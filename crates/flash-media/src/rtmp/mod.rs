//! RTMP (Adobe "Real-Time Messaging Protocol" 2012) with Enhanced RTMP codecs (H.265 `hvc1`,
//! Opus), as a server publishing into and playing from a [`Hub`].
//!
//! * [`handshake`]: the simple handshake and the Flash digest ("complex") one.
//! * [`chunk`]: the sans-IO chunk stream (all four header formats, extended timestamps, chunk
//!   size changes, aborts, aggregates).
//! * [`RtmpServer`]: an [`Acceptor`] answering `connect`, `releaseStream`, `FCPublish`,
//!   `createStream`, `publish`, `play`, `getStreamLength`, `FCUnpublish`, `deleteStream` and
//!   `closeStream`. A publish of `rtmp://host/app/name?query` reserves hub path `app/name`
//!   (a second publisher hears `NetStream.Publish.BadName` at once) and goes live once the
//!   metadata and sequence headers make the tracks known; the query reaches the hub's hooks in
//!   [`PeerInfo::query`]. Players start from the GOP cache with onMetaData and the sequence
//!   headers first; a player that falls behind has packets dropped ([`Dropper`], video to the
//!   next keyframe) and is disconnected past a second limit.
//!
//! RTMPS: put flash-tls in front of the server (an `Acceptor` with a TLS transport).
//! Not supported: RTMPE/RTMPT, shared objects, AMF3 replies (an AMF3 client gets AMF0 ones,
//! which every client takes), recorded streams, Enhanced RTMP multitrack.

pub mod chunk;
pub mod handshake;

use std::{fmt, sync::Arc, time::Duration};

use flash::{Acceptor, Conn, Handler};

use crate::{
    amf::{self, Value},
    av::Tracks,
    flv::{self, Decoder, Encoder, EncoderConfig, Event},
    hub::{
        Dropper, Hub, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription, Timeline,
    },
};

use chunk::{ChunkReader, Message};

/// A hook run on `connect`: `(app, tcUrl, peer)`; an `Err` rejects the connection.
pub type ConnectHook = Arc<dyn Fn(&str, &str, &PeerInfo) -> Result<(), String> + Send + Sync>;

/// Configures an [`RtmpServer`].
#[derive(Clone)]
#[non_exhaustive]
pub struct RtmpConfig {
    /// The chunk size the server sends with (it tells the client with Set Chunk Size).
    pub chunk_size: u32,
    /// The window acknowledgement size announced to clients.
    pub window_ack_size: u32,
    /// A player's queued bytes above which packets are dropped (video to the next keyframe).
    pub write_queue_limit: usize,
    /// A player's queued bytes above which it is disconnected.
    pub max_write_queue: usize,
    /// How long a player waits for a stream not published yet, or for the next publisher
    /// after its own left (`None`: play fails / ends without a publisher).
    pub play_wait: Option<Duration>,
    /// FLV encoding options for players (legacy H.265 codec id).
    pub encoder: EncoderConfig,
    /// Authorizes `connect`.
    pub on_connect: Option<ConnectHook>,
}

impl Default for RtmpConfig {
    fn default() -> Self {
        RtmpConfig {
            chunk_size: 4096,
            window_ack_size: 2_500_000,
            write_queue_limit: 2 << 20,
            max_write_queue: 16 << 20,
            play_wait: None,
            encoder: EncoderConfig::default(),
            on_connect: None,
        }
    }
}

impl fmt::Debug for RtmpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtmpConfig")
            .field("chunk_size", &self.chunk_size)
            .field("window_ack_size", &self.window_ack_size)
            .field("write_queue_limit", &self.write_queue_limit)
            .field("max_write_queue", &self.max_write_queue)
            .field("play_wait", &self.play_wait)
            .finish_non_exhaustive()
    }
}

struct Inner {
    hub: Hub,
    cfg: RtmpConfig,
}

/// The RTMP server: an [`Acceptor`] to serve on a TCP listener. Cheap to clone.
#[derive(Clone)]
pub struct RtmpServer(Arc<Inner>);

impl fmt::Debug for RtmpServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtmpServer")
            .field("cfg", &self.0.cfg)
            .finish_non_exhaustive()
    }
}

impl RtmpServer {
    /// A server publishing into and playing from `hub`.
    pub fn new(hub: Hub, cfg: RtmpConfig) -> RtmpServer {
        RtmpServer(Arc::new(Inner { hub, cfg }))
    }

    /// The hub.
    pub fn hub(&self) -> &Hub {
        &self.0.hub
    }
}

impl Acceptor for RtmpServer {
    type Handler = RtmpSession;

    fn on_open(&self, _c: &Conn<RtmpSession>) -> RtmpSession {
        RtmpSession {
            srv: self.0.clone(),
            st: State::C0C1,
            buf: Vec::new(),
            reader: ChunkReader::new(),
            peer_window: 0,
            acked: 0,
            app: String::new(),
            app_query: String::new(),
            tc_url: String::new(),
            publish: None,
            play: None,
        }
    }
}

enum State {
    C0C1,
    C2,
    Chunks,
}

struct Ingest {
    stream_id: u32,
    publisher: Publisher,
    decoder: Decoder,
}

/// One RTMP connection.
pub struct RtmpSession {
    srv: Arc<Inner>,
    st: State,
    buf: Vec<u8>,
    reader: ChunkReader,
    peer_window: u32,
    acked: u64,
    app: String,
    app_query: String,
    tc_url: String,
    publish: Option<Ingest>,
    play: Option<Subscription>,
}

impl fmt::Debug for RtmpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtmpSession")
            .field("app", &self.app)
            .field("publishing", &self.publish.is_some())
            .field("playing", &self.play.is_some())
            .finish_non_exhaustive()
    }
}

/// Splits `app` and a stream `name` (either may carry `?query`) into the hub path
/// `app/name` and the joined query.
pub fn stream_path(app: &str, name: &str) -> (String, String) {
    let (app, aq) = app.split_once('?').unwrap_or((app, ""));
    let (name, nq) = name.split_once('?').unwrap_or((name, ""));
    let app = app.trim_matches('/');
    let name = name.trim_matches('/');
    let mut q = nq.to_owned();
    if !aq.is_empty() {
        if !q.is_empty() {
            q.push('&');
        }
        q.push_str(aq);
    }
    let path = if app.is_empty() {
        name.to_owned()
    } else {
        format!("{app}/{name}")
    };
    (path, q)
}

fn status(level: &str, code: &str, desc: &str) -> Value {
    Value::object([
        ("level", Value::from(level)),
        ("code", Value::from(code)),
        ("description", Value::from(desc)),
    ])
}

impl Handler for RtmpSession {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        match self.st {
            State::C0C1 | State::C2 => {
                self.buf.extend_from_slice(data);
                if matches!(self.st, State::C0C1) {
                    if self.buf.len() < 1 + handshake::SIZE {
                        return;
                    }
                    match handshake::server_reply(&self.buf) {
                        Ok(s) => {
                            let _ = c.send_owned(s);
                        }
                        Err(_) => return c.close(),
                    }
                    self.buf.drain(..=handshake::SIZE);
                    self.st = State::C2;
                }
                if self.buf.len() < handshake::SIZE {
                    return;
                }
                self.buf.drain(..handshake::SIZE);
                self.st = State::Chunks;
                let rest = std::mem::take(&mut self.buf);
                if !rest.is_empty() {
                    self.chunks(c, &rest);
                }
            }
            State::Chunks => self.chunks(c, data),
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash::Error>) {
        self.publish = None;
        self.play = None;
    }
}

impl RtmpSession {
    fn send(&self, c: &Conn<Self>, m: &Message) {
        let mut out = Vec::with_capacity(m.payload.len() + 16);
        chunk::write_message(&mut out, m, self.srv.cfg.chunk_size as usize);
        if c.send_owned(out).is_err() {
            c.close();
        }
    }

    fn command(&self, c: &Conn<Self>, stream_id: u32, vals: &[Value]) {
        self.send(
            c,
            &Message::new(3, chunk::COMMAND_AMF0, stream_id, 0, amf::encode(vals)),
        );
    }

    fn on_status(&self, c: &Conn<Self>, stream_id: u32, level: &str, code: &str, desc: &str) {
        self.command(
            c,
            stream_id,
            &[
                Value::from("onStatus"),
                Value::Number(0.0),
                Value::Null,
                status(level, code, desc),
            ],
        );
    }

    fn chunks(&mut self, c: &Conn<Self>, data: &[u8]) {
        let Ok(msgs) = self.reader.feed(data) else {
            return c.close();
        };
        if self.peer_window > 0
            && self.reader.received() - self.acked >= u64::from(self.peer_window)
        {
            self.acked = self.reader.received();
            self.send(c, &chunk::control_u32(chunk::ACK, self.acked as u32));
        }
        for m in msgs {
            self.message(c, m);
            if !c.is_open() {
                return;
            }
        }
    }

    fn message(&mut self, c: &Conn<Self>, m: Message) {
        match m.msg_type {
            chunk::WINDOW_ACK_SIZE => {
                if let Some(x) = m.payload.get(..4) {
                    self.peer_window = u32::from_be_bytes([x[0], x[1], x[2], x[3]]);
                }
            }
            chunk::USER_CONTROL => {
                // PingRequest -> PingResponse.
                if m.payload.len() >= 6 && m.payload[..2] == [0, 6] {
                    let v = u32::from_be_bytes([
                        m.payload[2],
                        m.payload[3],
                        m.payload[4],
                        m.payload[5],
                    ]);
                    self.send(c, &chunk::user_control(7, v));
                }
            }
            chunk::COMMAND_AMF0 | chunk::COMMAND_AMF3 => {
                let body = if m.msg_type == chunk::COMMAND_AMF3 {
                    m.payload.get(1..).unwrap_or_default()
                } else {
                    &m.payload[..]
                };
                if let Ok(vals) = amf::decode_all(body) {
                    self.on_command(c, m.stream_id, &vals);
                }
            }
            chunk::AUDIO | chunk::VIDEO | chunk::DATA_AMF0 | chunk::DATA_AMF3 => self.media(&m),
            chunk::AGGREGATE => {
                for sub in chunk::split_aggregate(&m) {
                    self.media(&sub);
                }
            }
            _ => {}
        }
    }

    fn media(&mut self, m: &Message) {
        let Some(ing) = self.publish.as_mut() else {
            return;
        };
        if m.stream_id != ing.stream_id {
            return;
        }
        let (tag, body) = match m.msg_type {
            chunk::AUDIO => (flv::TAG_AUDIO, &m.payload[..]),
            chunk::VIDEO => (flv::TAG_VIDEO, &m.payload[..]),
            chunk::DATA_AMF3 => (flv::TAG_SCRIPT, m.payload.get(1..).unwrap_or_default()),
            _ => (flv::TAG_SCRIPT, &m.payload[..]),
        };
        for e in ing.decoder.write(tag, m.timestamp, body) {
            match e {
                Event::Tracks(t) => ing.publisher.set_tracks(t),
                Event::Packet(p) => ing.publisher.write(p),
            }
        }
    }

    fn peer(&self, c: &Conn<Self>, query: &str) -> PeerInfo {
        PeerInfo::new("rtmp", Some(c.peer_addr()), query)
    }

    fn on_command(&mut self, c: &Conn<Self>, stream_id: u32, vals: &[Value]) {
        let Some(name) = vals.first().and_then(Value::as_str) else {
            return;
        };
        let tx = vals.get(1).and_then(Value::as_f64).unwrap_or(0.0);
        match name {
            "connect" => {
                let obj = vals.get(2);
                let app = obj
                    .and_then(|o| o.get("app"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let (app, q) = app.split_once('?').unwrap_or((app, ""));
                self.app = app.trim_matches('/').to_owned();
                self.app_query = q.to_owned();
                self.tc_url = obj
                    .and_then(|o| o.get("tcUrl"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                if let Some(hook) = &self.srv.cfg.on_connect {
                    if let Err(reason) =
                        hook(&self.app, &self.tc_url, &self.peer(c, &self.app_query))
                    {
                        self.command(
                            c,
                            0,
                            &[
                                Value::from("_error"),
                                Value::Number(tx),
                                Value::Null,
                                status("error", "NetConnection.Connect.Rejected", &reason),
                            ],
                        );
                        c.close_after_send();
                        return;
                    }
                }
                let enc = obj
                    .and_then(|o| o.get("objectEncoding"))
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                self.send(
                    c,
                    &chunk::control_u32(chunk::WINDOW_ACK_SIZE, self.srv.cfg.window_ack_size),
                );
                self.send(c, &chunk::peer_bandwidth(self.srv.cfg.window_ack_size));
                // The Set Chunk Size goes out with the old (128) size: compute it by hand.
                let mut out = Vec::new();
                chunk::write_message(
                    &mut out,
                    &chunk::control_u32(chunk::SET_CHUNK_SIZE, self.srv.cfg.chunk_size),
                    128,
                );
                let _ = c.send_owned(out);
                let mut ok = status(
                    "status",
                    "NetConnection.Connect.Success",
                    "Connection succeeded.",
                );
                if let Value::Object(p) = &mut ok {
                    p.push(("objectEncoding".into(), Value::Number(enc)));
                }
                self.command(
                    c,
                    0,
                    &[
                        Value::from("_result"),
                        Value::Number(tx),
                        Value::object([
                            ("fmsVer", Value::from("FMS/3,0,1,123")),
                            ("capabilities", Value::Number(31.0)),
                        ]),
                        ok,
                    ],
                );
            }
            "createStream" => {
                self.command(
                    c,
                    0,
                    &[
                        Value::from("_result"),
                        Value::Number(tx),
                        Value::Null,
                        Value::Number(1.0),
                    ],
                );
            }
            "releaseStream" | "FCPublish" | "getStreamLength" => {
                if name == "FCPublish" {
                    let n = vals.get(3).and_then(Value::as_str).unwrap_or("");
                    self.command(
                        c,
                        0,
                        &[
                            Value::from("onFCPublish"),
                            Value::Number(0.0),
                            Value::Null,
                            status("status", "NetStream.Publish.Start", n),
                        ],
                    );
                }
                if tx != 0.0 {
                    // getStreamLength wants a number: 0, the length of a live stream.
                    let v = if name == "getStreamLength" {
                        Value::Number(0.0)
                    } else {
                        Value::Undefined
                    };
                    self.command(
                        c,
                        0,
                        &[Value::from("_result"), Value::Number(tx), Value::Null, v],
                    );
                }
            }
            "publish" => {
                let n = vals.get(3).and_then(Value::as_str).unwrap_or("");
                let (path, q) = stream_path(&format!("{}?{}", self.app, self.app_query), n);
                if path.is_empty() || n.is_empty() || self.publish.is_some() {
                    self.on_status(
                        c,
                        stream_id,
                        "error",
                        "NetStream.Publish.BadName",
                        "invalid stream name",
                    );
                    return;
                }
                match self.srv.hub.reserve(&path, self.peer(c, &q)) {
                    Ok(publisher) => {
                        self.publish = Some(Ingest {
                            stream_id,
                            publisher,
                            decoder: Decoder::new(),
                        });
                        self.send(c, &chunk::user_control(0, stream_id));
                        self.on_status(
                            c,
                            stream_id,
                            "status",
                            "NetStream.Publish.Start",
                            &format!("{path} is now published."),
                        );
                    }
                    Err(e) => {
                        let code = match e {
                            HubError::StreamBusy => "NetStream.Publish.BadName",
                            _ => "NetStream.Publish.Denied",
                        };
                        self.on_status(c, stream_id, "error", code, &e.to_string());
                        c.close_after_send();
                    }
                }
            }
            "play" => self.on_play(c, stream_id, vals),
            "FCUnpublish" | "deleteStream" | "closeStream" => {
                if self.publish.take().is_some() {
                    self.on_status(
                        c,
                        stream_id,
                        "status",
                        "NetStream.Unpublish.Success",
                        "unpublished",
                    );
                }
                self.play = None;
                if name == "FCUnpublish" && tx != 0.0 {
                    self.command(
                        c,
                        0,
                        &[
                            Value::from("_result"),
                            Value::Number(tx),
                            Value::Null,
                            Value::Undefined,
                        ],
                    );
                }
            }
            _ => {
                if tx != 0.0 && name != "_result" && name != "_error" && name != "onStatus" {
                    self.command(
                        c,
                        0,
                        &[
                            Value::from("_result"),
                            Value::Number(tx),
                            Value::Null,
                            Value::Undefined,
                        ],
                    );
                }
            }
        }
    }

    fn on_play(&mut self, c: &Conn<Self>, stream_id: u32, vals: &[Value]) {
        let n = vals.get(3).and_then(Value::as_str).unwrap_or("");
        let (path, q) = stream_path(&format!("{}?{}", self.app, self.app_query), n);
        if self.play.is_some() || path.is_empty() || n.is_empty() {
            self.on_status(
                c,
                stream_id,
                "error",
                "NetStream.Play.StreamNotFound",
                "invalid stream name",
            );
            return;
        }
        // StreamBegin and the play statuses go out before the subscription delivers the GOP.
        self.send(c, &chunk::user_control(0, stream_id));
        self.on_status(
            c,
            stream_id,
            "status",
            "NetStream.Play.Reset",
            &format!("Playing and resetting {path}."),
        );
        self.on_status(
            c,
            stream_id,
            "status",
            "NetStream.Play.Start",
            &format!("Started playing {path}."),
        );
        self.send(
            c,
            &Message::new(
                5,
                chunk::DATA_AMF0,
                stream_id,
                0,
                amf::encode(&[
                    Value::from("|RtmpSampleAccess"),
                    Value::Bool(true),
                    Value::Bool(true),
                ]),
            ),
        );
        let cfg = &self.srv.cfg;
        let egress = Egress {
            conn: c.clone(),
            stream_id,
            chunk_size: cfg.chunk_size as usize,
            enc: Encoder::new(cfg.encoder.clone()),
            started: false,
            timeline: Timeline::new(),
            max_queue: cfg.max_write_queue,
        };
        let backlog = c.clone();
        let mut opts = SubscribeOptions::new(self.peer(c, &q));
        opts.wait = cfg.play_wait;
        let sink = Dropper::new(
            egress,
            move || backlog.queued_bytes(),
            cfg.write_queue_limit,
        );
        match self.srv.hub.subscribe(&path, sink, opts) {
            Ok(sub) => self.play = Some(sub),
            Err(e) => {
                self.on_status(
                    c,
                    stream_id,
                    "error",
                    "NetStream.Play.StreamNotFound",
                    &e.to_string(),
                );
                c.close_after_send();
            }
        }
    }
}

/// A hub sink writing FLV tags as RTMP messages to one player.
struct Egress {
    conn: Conn<RtmpSession>,
    stream_id: u32,
    chunk_size: usize,
    enc: Encoder,
    started: bool,
    timeline: Timeline,
    max_queue: usize,
}

impl Egress {
    fn write(&self, msg_type: u8, ts: u32, body: Vec<u8>) {
        let csid = match msg_type {
            chunk::AUDIO => 4,
            chunk::VIDEO => 6,
            _ => 5,
        };
        let mut out = Vec::with_capacity(body.len() + 32);
        chunk::write_message(
            &mut out,
            &Message::new(csid, msg_type, self.stream_id, ts, body),
            self.chunk_size,
        );
        if self.conn.send_owned(out).is_err() {
            self.conn.close();
        }
    }
}

fn tag_msg_type(tag: u8) -> u8 {
    match tag {
        flv::TAG_AUDIO => chunk::AUDIO,
        flv::TAG_VIDEO => chunk::VIDEO,
        _ => chunk::DATA_AMF0,
    }
}

impl Sink for Egress {
    fn on_tracks(&mut self, tracks: &Tracks) {
        self.enc.set_tracks(tracks);
        if self.started {
            self.timeline.restart();
        }
        self.started = true;
        for (tag, body) in self.enc.headers() {
            let ts = match tag {
                flv::TAG_VIDEO => self.timeline.last_of(true),
                flv::TAG_AUDIO => self.timeline.last_of(false),
                _ => self.timeline.last(),
            };
            self.write(tag_msg_type(tag), flv::ms(ts) as u32, body);
        }
    }

    fn on_packet(&mut self, pkt: &Arc<crate::av::Packet>) {
        if self.conn.queued_bytes() > self.max_queue {
            self.conn.close();
            return;
        }
        let Some((tag, body)) = self.enc.packet(pkt) else {
            return;
        };
        let ts = self.timeline.stamp(tag == flv::TAG_VIDEO, pkt.dts);
        self.write(tag_msg_type(tag), flv::ms(ts) as u32, body);
    }

    fn on_close(&mut self, _err: HubError) {
        let mut b = Vec::new();
        chunk::write_message(
            &mut b,
            &chunk::user_control(1, self.stream_id),
            self.chunk_size,
        );
        let _ = self.conn.send_owned(b);
        self.conn.close_after_send();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(stream_path("live", "s"), ("live/s".into(), String::new()));
        assert_eq!(
            stream_path("live?a=1", "s?b=2"),
            ("live/s".into(), "b=2&a=1".into())
        );
        assert_eq!(
            stream_path("/live/", "/s"),
            ("live/s".into(), String::new())
        );
        assert_eq!(stream_path("", "s"), ("s".into(), String::new()));
    }
}
