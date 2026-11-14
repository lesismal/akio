//! RTSP 1.0 server (RFC 2326) on a `only` engine: plays the hub's streams to RTSP players and
//! records into the hub what RTSP publishers send. Media travels as RTP ([`crate::rtp`]),
//! interleaved on the RTSP connection (`RTP/AVP/TCP`) or over UDP unicast (`RTP/AVP`).
//!
//! `rtsp://host:port/live/cam` plays or records the hub stream `live/cam` (the query string
//! goes to the hub hooks in [`PeerInfo::query`]). The server answers OPTIONS, DESCRIBE (an SDP
//! of the stream's tracks), SETUP, PLAY (with `RTP-Info`), PAUSE, TEARDOWN, GET_PARAMETER and
//! SET_PARAMETER (keep-alives), and ANNOUNCE, SETUP with `mode=record` and RECORD for
//! publishers. ANNOUNCE reserves the path ([`Hub::reserve`]): a second publisher is refused at
//! once and the stream goes live when the parameter sets are known (from the SDP's
//! `sprop-*`, or in band).
//!
//! A player starts with the hub's cached GOP and gets RTCP sender reports; over TCP it is cut
//! back to keyframes ([`Dropper`]) when it falls behind and closed when it falls further.
//! Authentication is Digest or Basic through [`RtspConfig::credentials`]; the hub's
//! `on_publish` / `on_subscribe` hooks decide who may publish and play what.
//!
//! ```no_run
//! use only::{Engine, Listener};
//! use only_media::{Hub, rtsp::{RtspConfig, RtspServer}};
//!
//! let hub = Hub::default();
//! let srv = RtspServer::new(hub, RtspConfig::default());
//! srv.listen_udp("0.0.0.0:8000".parse().unwrap()).unwrap(); // optional: RTP/AVP over UDP
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("0.0.0.0:8554".parse().unwrap()).serve(srv))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! Left out: RTSP 2.0, RTSPS and HTTP tunnelling, multicast, seeking (every stream is live),
//! sessions that outlive their connection, and decode times for B-frame video recorded over
//! RTP (RTP carries presentation times only).

mod auth;
pub mod message;

use std::{
    collections::HashMap,
    fmt, io,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use only::{Acceptor, Conn, Handler};

use crate::{
    av::{Packet, Track, Tracks},
    hub::{
        Dropper, Hub, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription, Timeline,
    },
    rtp::{self, Depacketizer, Packetizer},
    sdp,
};

pub use message::{Frame, Parser, Request, Response, RtspError, Transport};

/// Looks up the password of a user.
pub type Credentials = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Configures an [`RtspServer`].
#[derive(Clone)]
#[non_exhaustive]
pub struct RtspConfig {
    /// When set, every request must authenticate (Digest or Basic) as a user whose password
    /// this returns.
    pub credentials: Option<Credentials>,
    /// The realm of the authentication challenge.
    pub realm: String,
    /// A TCP player's queued bytes above which packets are dropped (video to the next
    /// keyframe).
    pub write_queue_limit: usize,
    /// A TCP player's queued bytes above which it is disconnected.
    pub max_write_queue: usize,
    /// How long a player waits for a stream's publisher to come back (`None`: it ends with
    /// the publisher).
    pub play_wait: Option<Duration>,
    /// Interval of the RTCP sender reports to players.
    pub sender_report_interval: Duration,
}

impl Default for RtspConfig {
    fn default() -> Self {
        RtspConfig {
            credentials: None,
            realm: "only-media".to_owned(),
            write_queue_limit: 2 << 20,
            max_write_queue: 16 << 20,
            play_wait: None,
            sender_report_interval: Duration::from_secs(3),
        }
    }
}

impl fmt::Debug for RtspConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspConfig")
            .field("realm", &self.realm)
            .field("write_queue_limit", &self.write_queue_limit)
            .field("max_write_queue", &self.max_write_queue)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Where a UDP datagram from a client goes.
struct Route {
    rec: Weak<Mutex<Recorder>>,
    media: usize,
}

struct Udp {
    rtp: Arc<UdpSocket>,
    rtcp: Arc<UdpSocket>,
    ports: (u16, u16),
}

struct Inner {
    hub: Hub,
    cfg: RtspConfig,
    udp: Mutex<Option<Arc<Udp>>>,
    routes: Mutex<HashMap<SocketAddr, Route>>,
}

/// The RTSP server: an [`Acceptor`] to serve on a TCP listener. Cheap to clone.
#[derive(Clone)]
pub struct RtspServer(Arc<Inner>);

impl fmt::Debug for RtspServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspServer").finish_non_exhaustive()
    }
}

impl RtspServer {
    /// A server for `hub`.
    pub fn new(hub: Hub, cfg: RtspConfig) -> RtspServer {
        RtspServer(Arc::new(Inner {
            hub,
            cfg,
            udp: Mutex::new(None),
            routes: Mutex::new(HashMap::new()),
        }))
    }

    /// The hub.
    pub fn hub(&self) -> &Hub {
        &self.0.hub
    }

    /// Enables `RTP/AVP` over UDP: binds `rtp` and the next port (RTCP). Port 0 picks a free
    /// even pair. Returns the RTP and RTCP ports. The sockets are read by two threads that end
    /// when the server is dropped.
    pub fn listen_udp(&self, rtp: SocketAddr) -> io::Result<(u16, u16)> {
        let (a, b) = bind_pair(rtp)?;
        let ports = (a.local_addr()?.port(), b.local_addr()?.port());
        let udp = Arc::new(Udp {
            rtp: Arc::new(a),
            rtcp: Arc::new(b),
            ports,
        });
        for sock in [udp.rtp.clone(), udp.rtcp.clone()] {
            sock.set_read_timeout(Some(Duration::from_millis(200)))?;
            let weak = Arc::downgrade(&self.0);
            std::thread::Builder::new()
                .name("only-rtsp-udp".into())
                .spawn(move || read_udp(&sock, &weak))?;
        }
        *lock(&self.0.udp) = Some(udp);
        Ok(ports)
    }
}

fn bind_pair(addr: SocketAddr) -> io::Result<(UdpSocket, UdpSocket)> {
    if addr.port() != 0 {
        let mut b = addr;
        b.set_port(addr.port() + 1);
        return Ok((UdpSocket::bind(addr)?, UdpSocket::bind(b)?));
    }
    for _ in 0..64 {
        let a = UdpSocket::bind(addr)?;
        let port = a.local_addr()?.port();
        if port % 2 != 0 || port == u16::MAX {
            continue;
        }
        let mut b = addr;
        b.set_port(port + 1);
        if let Ok(b) = UdpSocket::bind(b) {
            return Ok((a, b));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no free UDP port pair",
    ))
}

fn read_udp(sock: &UdpSocket, server: &Weak<Inner>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let r = sock.recv_from(&mut buf);
        let Some(inner) = server.upgrade() else {
            return;
        };
        let Ok((n, from)) = r else { continue };
        let route = lock(&inner.routes)
            .get(&from)
            .map(|r| (r.rec.clone(), r.media));
        if let Some((rec, media)) = route {
            if let Some(rec) = rec.upgrade() {
                if !rtp::is_rtcp(&buf[..n]) {
                    lock(&rec).push(media, &buf[..n]);
                }
            }
        }
    }
}

impl Acceptor for RtspServer {
    type Handler = RtspSession;

    fn on_open(&self, _c: &Conn<RtspSession>) -> RtspSession {
        RtspSession {
            srv: self.0.clone(),
            parser: Parser::default(),
            id: random_hex(8),
            nonce: random_hex(16),
            path: None,
            query: String::new(),
            announced: Vec::new(),
            setups: HashMap::new(),
            recorder: None,
            sub: None,
            playing: false,
        }
    }
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// How a track's RTP travels.
#[derive(Debug, Clone, Copy)]
enum Path {
    Tcp { rtp: u8, rtcp: u8 },
    Udp { rtp: SocketAddr, rtcp: SocketAddr },
}

/// The ingest of a recording session.
struct Recorder {
    publisher: Publisher,
    /// Per announced media: its track, whether the hub carries it, its hub index.
    media: Vec<RecMedia>,
    tracks: Vec<Track>,
    live: bool,
    start: Instant,
    scratch: Vec<Packet>,
}

struct RecMedia {
    track: Option<Track>,
    hub_index: Option<usize>,
    depack: Option<Depacketizer>,
}

impl Recorder {
    fn push(&mut self, media: usize, data: &[u8]) {
        let start = self.start;
        let Some(m) = self.media.get_mut(media) else {
            return;
        };
        let (Some(track), Some(index)) = (m.track.as_ref(), m.hub_index) else {
            return;
        };
        let depack = m.depack.get_or_insert_with(|| {
            let off = i64::try_from(start.elapsed().as_nanos()).unwrap_or(0);
            Depacketizer::new(track).offset(off)
        });
        let mut out = std::mem::take(&mut self.scratch);
        if depack.push(data, &mut out).is_err() {
            self.scratch = out;
            return;
        }
        if let Some(cfg) = depack.take_config() {
            if self.tracks[index].config != cfg {
                let t = Track::video(self.tracks[index].codec, cfg);
                self.tracks[index] = t;
                if self.live {
                    self.publisher.set_tracks(Arc::from(self.tracks.clone()));
                }
            }
        }
        if !self.live
            && self
                .tracks
                .iter()
                .all(|t| !t.is_video() || !t.config.is_empty())
        {
            self.live = true;
            self.publisher.set_tracks(Arc::from(self.tracks.clone()));
        }
        for mut p in out.drain(..) {
            if self.live {
                p.track = index;
                self.publisher.write(p);
            }
        }
        self.scratch = out;
    }
}

/// One RTSP connection.
pub struct RtspSession {
    srv: Arc<Inner>,
    parser: Parser,
    id: String,
    nonce: String,
    path: Option<String>,
    query: String,
    /// ANNOUNCEd media: description and track.
    announced: Vec<sdp::Media>,
    /// Track (hub index for play, media index for record) -> transport.
    setups: HashMap<usize, Path>,
    recorder: Option<Arc<Mutex<Recorder>>>,
    sub: Option<Subscription>,
    playing: bool,
}

impl fmt::Debug for RtspSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspSession")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Splits an RTSP URL into the hub path (no slashes around it) and the query.
pub fn url_path(uri: &str) -> (String, String) {
    let rest = uri
        .split_once("://")
        .map_or(uri, |(_, r)| r.find('/').map_or("", |i| &r[i..]));
    let (p, q) = rest.split_once('?').unwrap_or((rest, ""));
    (p.trim_matches('/').to_owned(), q.to_owned())
}

/// The track number a SETUP URL's last segment names (`trackID=N`, `streamid=N`).
fn track_id(seg: &str) -> Option<usize> {
    let (k, v) = seg.split_once('=')?;
    matches!(
        k.to_ascii_lowercase().as_str(),
        "trackid" | "streamid" | "track"
    )
    .then(|| v.parse().ok())
    .flatten()
}

fn hub_status(e: &HubError) -> u16 {
    match e {
        HubError::NotFound | HubError::Unpublished => 404,
        HubError::StreamBusy => 453,
        HubError::Limit | HubError::Closed => 503,
        _ => 403,
    }
}

impl Handler for RtspSession {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let mut frames = Vec::new();
        if self.parser.feed(data, &mut frames).is_err() {
            let _ = c.send(&Response::new(400).encode(None));
            c.close_after_send();
            return;
        }
        for f in frames {
            match f {
                Frame::Request(req) => {
                    let resp = self.handle(c, &req);
                    let _ = c.send(&resp.encode(req.cseq()));
                    if req.method == "PLAY" && resp.status == 200 {
                        self.start_play(c);
                    }
                }
                Frame::Interleaved { channel, data } => self.interleaved(channel, &data),
                Frame::Response(_) => {}
            }
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        self.teardown();
    }
}

impl RtspSession {
    fn teardown(&mut self) {
        self.sub = None;
        self.playing = false;
        if let Some(rec) = self.recorder.take() {
            let weak = Arc::downgrade(&rec);
            lock(&self.srv.routes).retain(|_, r| !r.rec.ptr_eq(&weak));
            lock(&rec).publisher.close();
        }
        self.setups.clear();
    }

    fn interleaved(&self, channel: u8, data: &[u8]) {
        let Some(rec) = &self.recorder else { return };
        let media = self.setups.iter().find_map(|(&m, p)| match *p {
            Path::Tcp { rtp, .. } if rtp == channel => Some(m),
            _ => None,
        });
        if let Some(m) = media {
            lock(rec).push(m, data);
        }
    }

    fn peer(&self, c: &Conn<Self>) -> PeerInfo {
        PeerInfo::new("rtsp", Some(c.peer_addr()), self.query.clone())
    }

    fn handle(&mut self, c: &Conn<Self>, req: &Request) -> Response {
        if let Some(lookup) = self.srv.cfg.credentials.clone() {
            let ok = req.header("authorization").is_some_and(|h| {
                auth::verify(h, &req.method, &self.srv.cfg.realm, &self.nonce, &*lookup).is_some()
            });
            if !ok && req.method != "OPTIONS" {
                let [d, b] = auth::challenges(&self.srv.cfg.realm, &self.nonce);
                return Response::new(401)
                    .header("WWW-Authenticate", d)
                    .header("WWW-Authenticate", b);
            }
        }
        let session_hdr = format!("{};timeout=60", self.id);
        let session = || ("Session", session_hdr.clone());
        match req.method.as_str() {
            "OPTIONS" => Response::new(200).header(
                "Public",
                "OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, PAUSE, RECORD, TEARDOWN, GET_PARAMETER, SET_PARAMETER",
            ),
            "DESCRIBE" => self.describe(req),
            "ANNOUNCE" => self.announce(c, req),
            "SETUP" => self.setup(c, req),
            "PLAY" => {
                if self.recorder.is_some() || self.path.is_none() || self.setups.is_empty() {
                    return Response::new(455);
                }
                self.play_response()
            }
            "RECORD" => {
                if self.recorder.is_none() {
                    return Response::new(455);
                }
                let (s, v) = session();
                Response::new(200).header(s, v)
            }
            "PAUSE" => {
                self.sub = None;
                self.playing = false;
                let (s, v) = session();
                Response::new(200).header(s, v)
            }
            "TEARDOWN" => {
                self.teardown();
                let (s, v) = session();
                Response::new(200).header(s, v)
            }
            "GET_PARAMETER" | "SET_PARAMETER" => {
                let (s, v) = session();
                Response::new(200).header(s, v)
            }
            _ => Response::new(501),
        }
    }

    fn describe(&self, req: &Request) -> Response {
        let (path, _query) = url_path(&req.uri);
        let Some(info) = self.srv.hub.stream_info(&path).filter(|i| i.publishing) else {
            return Response::new(404);
        };
        let s = describe_sdp(&info.tracks);
        if s.media.is_empty() {
            return Response::new(415);
        }
        let base = req
            .uri
            .split('?')
            .next()
            .unwrap_or(&req.uri)
            .trim_end_matches('/');
        Response::new(200)
            .header("Content-Base", format!("{base}/"))
            .body("application/sdp", s.to_string().into_bytes())
    }

    fn announce(&mut self, c: &Conn<Self>, req: &Request) -> Response {
        if self.path.is_some() {
            return Response::new(455);
        }
        if !req
            .header("content-type")
            .is_some_and(|t| t.to_ascii_lowercase().starts_with("application/sdp"))
        {
            return Response::new(415);
        }
        let Ok(s) = sdp::Session::parse(&String::from_utf8_lossy(&req.body)) else {
            return Response::new(400);
        };
        let (path, query) = url_path(&req.uri);
        if path.is_empty() {
            return Response::new(400);
        }
        let mut media = Vec::new();
        let mut tracks = Vec::new();
        for m in &s.media {
            let t = sdp::media_track(m).map(|(t, _)| t);
            let hub_index = t.as_ref().map(|t| {
                tracks.push(t.clone());
                tracks.len() - 1
            });
            media.push(RecMedia {
                track: t,
                hub_index,
                depack: None,
            });
        }
        if tracks.is_empty() {
            return Response::new(415);
        }
        self.query = query;
        let publisher = match self.srv.hub.reserve(&path, self.peer(c)) {
            Ok(p) => p,
            Err(e) => return Response::new(hub_status(&e)),
        };
        self.announced = s.media;
        self.path = Some(path);
        self.recorder = Some(Arc::new(Mutex::new(Recorder {
            publisher,
            media,
            tracks,
            live: false,
            start: Instant::now(),
            scratch: Vec::new(),
        })));
        Response::new(200)
    }

    fn setup(&mut self, c: &Conn<Self>, req: &Request) -> Response {
        let Some(ts) = req.header("transport") else {
            return Response::new(461);
        };
        let Some(t) = Transport::parse_all(ts).into_iter().find(|t| !t.multicast) else {
            return Response::new(461);
        };
        let uri = req.uri.split('?').next().unwrap_or(&req.uri);
        let (full, query) = url_path(&req.uri);
        let last = full.rsplit('/').next().unwrap_or("");
        let index = if self.recorder.is_some() {
            // Match the media by its control (relative or absolute) or by a track id.
            let found = self.announced.iter().position(|m| {
                m.control().is_some_and(|ctl| {
                    ctl == uri || ctl == last || uri.ends_with(&format!("/{ctl}"))
                })
            });
            let Some(i) = found.or_else(|| track_id(last)) else {
                return Response::new(404);
            };
            i
        } else {
            let (i, path) = match track_id(last) {
                Some(i) => (i, full.rsplit_once('/').map_or("", |(p, _)| p).to_owned()),
                None => (0, full.clone()),
            };
            match &self.path {
                Some(p) if *p != path => return Response::new(455),
                Some(_) => {}
                None => {
                    self.path = Some(path.clone());
                    self.query = query;
                }
            }
            let ok = self
                .srv
                .hub
                .stream_info(&path)
                .is_some_and(|s| s.tracks.get(i).is_some_and(|t| rtp::supported(t.codec)));
            if !ok {
                return Response::new(404);
            }
            i
        };
        let mut reply = t.clone();
        let path = if t.tcp {
            let (a, b) = t
                .interleaved
                .unwrap_or((2 * index as u8, 2 * index as u8 + 1));
            reply.interleaved = Some((a, b));
            Path::Tcp { rtp: a, rtcp: b }
        } else {
            let Some(udp) = lock(&self.srv.udp).clone() else {
                return Response::new(461);
            };
            let Some((a, b)) = t.client_port else {
                return Response::new(461);
            };
            let ip = c.peer_addr().ip();
            let (rtp_addr, rtcp_addr) = (SocketAddr::new(ip, a), SocketAddr::new(ip, b));
            reply.server_port = Some(udp.ports);
            if let Some(rec) = &self.recorder {
                let mut routes = lock(&self.srv.routes);
                for addr in [rtp_addr, rtcp_addr] {
                    routes.insert(
                        addr,
                        Route {
                            rec: Arc::downgrade(rec),
                            media: index,
                        },
                    );
                }
            }
            Path::Udp {
                rtp: rtp_addr,
                rtcp: rtcp_addr,
            }
        };
        self.setups.insert(index, path);
        Response::new(200)
            .header("Transport", reply.to_string())
            .header("Session", format!("{};timeout=60", self.id))
    }

    fn play_response(&self) -> Response {
        Response::new(200)
            .header("Session", format!("{};timeout=60", self.id))
            .header("Range", "npt=0.000-")
    }

    fn start_play(&mut self, c: &Conn<Self>) {
        if self.playing {
            return;
        }
        let Some(path) = self.path.clone() else {
            return;
        };
        let udp = lock(&self.srv.udp).clone();
        let player = Player {
            conn: c.clone(),
            udp: udp.map(|u| (u.rtp.clone(), u.rtcp.clone())),
            setups: self.setups.clone(),
            tracks: HashMap::new(),
            timeline: Timeline::from_zero(),
            first: true,
            sr_every: self.srv.cfg.sender_report_interval,
            max_queue: self.srv.cfg.max_write_queue,
            video: Vec::new(),
        };
        let tcp = self.setups.values().any(|p| matches!(p, Path::Tcp { .. }));
        let conn = c.clone();
        let backlog = move || if tcp { conn.queued_bytes() } else { 0 };
        let mut opts = SubscribeOptions::new(self.peer(c));
        opts.wait = self.srv.cfg.play_wait;
        let sink = Dropper::new(player, backlog, self.srv.cfg.write_queue_limit);
        match self.srv.hub.subscribe(&path, sink, opts) {
            Ok(s) => {
                self.sub = Some(s);
                self.playing = true;
            }
            Err(_) => c.close_after_send(),
        }
    }
}

/// The SDP DESCRIBE answers for `tracks`: one media per track RTP carries, controlled by
/// `trackID=<hub index>`.
pub fn describe_sdp(tracks: &Tracks) -> sdp::Session {
    let mut s = sdp::Session::new("only-media");
    s.connection = Some("IN IP4 0.0.0.0".to_owned());
    s.attributes.push(sdp::Attribute::new("control", "*"));
    s.attributes.push(sdp::Attribute::new("range", "npt=0-"));
    for (i, t) in tracks.iter().enumerate() {
        if let Some(m) = sdp::track_media(t, 96 + i as u8, &format!("trackID={i}")) {
            s.media.push(m);
        }
    }
    s
}

struct PlayTrack {
    pack: Packetizer,
    track: Track,
    last_sr: Option<Instant>,
}

/// A hub sink sending RTP to one player.
struct Player {
    conn: Conn<RtspSession>,
    udp: Option<(Arc<UdpSocket>, Arc<UdpSocket>)>,
    setups: HashMap<usize, Path>,
    tracks: HashMap<usize, PlayTrack>,
    timeline: Timeline,
    first: bool,
    sr_every: Duration,
    max_queue: usize,
    video: Vec<bool>,
}

impl Player {
    fn send(&self, path: Path, rtcp: bool, data: &[u8]) {
        match path {
            Path::Tcp { rtp, rtcp: ch } => {
                let mut b = Vec::with_capacity(data.len() + 4);
                message::interleaved(if rtcp { ch } else { rtp }, data, &mut b);
                if self.conn.send_owned(b).is_err() {
                    self.conn.close();
                }
            }
            Path::Udp { rtp: a, rtcp: b } => {
                if let Some((s_rtp, s_rtcp)) = &self.udp {
                    let _ = if rtcp {
                        s_rtcp.send_to(data, b)
                    } else {
                        s_rtp.send_to(data, a)
                    };
                }
            }
        }
    }
}

impl Sink for Player {
    fn on_tracks(&mut self, tracks: &Tracks) {
        self.video = tracks.iter().map(Track::is_video).collect();
        if !self.first {
            self.timeline.restart();
        }
        self.first = false;
        for &i in self.setups.keys() {
            let Some(t) = tracks.get(i) else { continue };
            if !rtp::supported(t.codec) {
                continue;
            }
            // A new codec or configuration (republish) gets a new packetizer.
            if self.tracks.get(&i).is_none_or(|p| p.track != *t) {
                self.tracks.insert(
                    i,
                    PlayTrack {
                        pack: Packetizer::new(t, 96 + i as u8),
                        track: t.clone(),
                        last_sr: None,
                    },
                );
            }
        }
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        if self.conn.queued_bytes() > self.max_queue {
            self.conn.close();
            return;
        }
        let Some(&path) = self.setups.get(&pkt.track) else {
            return;
        };
        let video = self.video.get(pkt.track).copied().unwrap_or(false);
        let dts = self.timeline.stamp(video, pkt.dts);
        // RTP carries presentation times: keep them as published, on the timeline's clock.
        let pts = (pkt.pts + self.timeline.offset()).max(dts);
        let mut p = Packet::new(pkt.track, dts, pts, pkt.keyframe, Vec::new());
        let Some(t) = self.tracks.get_mut(&pkt.track) else {
            return;
        };
        p.data.clone_from(&pkt.data);
        let mut out = Vec::new();
        t.pack.packetize(&p, &mut out);
        let sr = match t.last_sr {
            Some(at) if at.elapsed() < self.sr_every => None,
            _ => {
                t.last_sr = Some(Instant::now());
                Some(
                    t.pack
                        .sender_report(rtp::ntp_now(), t.pack.last_timestamp()),
                )
            }
        };
        for r in &out {
            self.send(path, false, r);
        }
        if let Some(sr) = sr {
            self.send(path, true, &sr);
        }
    }

    fn on_close(&mut self, _err: HubError) {
        self.conn.close_after_send();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            url_path("rtsp://h:8554/live/s?token=1"),
            ("live/s".into(), "token=1".into())
        );
        assert_eq!(
            url_path("rtsp://h/live/s/"),
            ("live/s".into(), String::new())
        );
        assert_eq!(url_path("rtsp://h"), (String::new(), String::new()));
        assert_eq!(track_id("trackID=3"), Some(3));
        assert_eq!(track_id("streamid=1"), Some(1));
        assert_eq!(track_id("x=1"), None);
    }
}
