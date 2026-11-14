//! HTTP-FLV and WS-FLV playback of hub streams: `GET /app/name.flv` answers an FLV file that
//! never ends (chunked on HTTP/1.1, a stream on HTTP/2), or, when the request is a WebSocket
//! upgrade, the same bytes as binary messages (the FLV header first, then one message per tag),
//! as flv.js and mpegts.js play them.
//!
//! [`HttpFlv`] is a flash-http [`Service`]: mount it on a route with a wildcard
//! (`router.get("/*path", flv)`), or call it from another service for requests ending in
//! `.flv`. Players start from the GOP cache; a slow player has packets dropped ([`Dropper`]) and
//! is cut off past [`HttpFlvConfig::max_write_queue`].

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use flash_http::{
    Context, Headers, Service, WsOptions,
    ws::{Message as WsMessage, WsHandler, WsSender},
};

use crate::{
    av::{Packet, Tracks},
    flv::{self, Encoder, EncoderConfig},
    hub::{Dropper, Hub, HubError, PeerInfo, Sink, SubscribeOptions, Subscription, Timeline},
};

/// Configures [`HttpFlv`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpFlvConfig {
    /// A player's queued bytes above which packets are dropped (video to the next keyframe).
    pub write_queue_limit: usize,
    /// A player's queued bytes above which it is cut off.
    pub max_write_queue: usize,
    /// How long a player waits for a stream not published yet, or for the next publisher
    /// (`None`: 404 / end of the response without a publisher).
    pub play_wait: Option<Duration>,
    /// FLV encoding options (legacy H.265 codec id for older players).
    pub encoder: EncoderConfig,
    /// The `Access-Control-Allow-Origin` value sent (`None`: no CORS header).
    pub cors_origin: Option<String>,
}

impl Default for HttpFlvConfig {
    fn default() -> Self {
        HttpFlvConfig {
            write_queue_limit: 2 << 20,
            max_write_queue: 16 << 20,
            play_wait: None,
            encoder: EncoderConfig::default(),
            cors_origin: Some("*".to_owned()),
        }
    }
}

/// The HTTP-FLV / WS-FLV playback service.
#[derive(Clone)]
pub struct HttpFlv {
    hub: Hub,
    cfg: Arc<HttpFlvConfig>,
}

impl fmt::Debug for HttpFlv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpFlv")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

/// The hub path of a request path ending in `ext`: `/live/s.flv` -> `live/s`.
pub fn path_of(req_path: &str, ext: &str) -> Option<String> {
    let p = req_path.strip_suffix(ext)?.trim_start_matches('/');
    (!p.is_empty() && !p.contains("..")).then(|| p.to_owned())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl HttpFlv {
    /// A service playing streams of `hub`.
    pub fn new(hub: Hub, cfg: HttpFlvConfig) -> HttpFlv {
        HttpFlv {
            hub,
            cfg: Arc::new(cfg),
        }
    }

    fn options(&self, ctx: &Context, protocol: &'static str) -> SubscribeOptions {
        let info = PeerInfo::new(protocol, Some(ctx.peer()), ctx.req().query().unwrap_or(""));
        let mut o = SubscribeOptions::new(info);
        o.wait = self.cfg.play_wait;
        o
    }
}

impl Service for HttpFlv {
    fn call(&self, ctx: &mut Context) {
        let Some(path) = path_of(ctx.path(), ".flv") else {
            return ctx.text(404, "not found");
        };
        if ctx
            .header("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        {
            let h = WsFlv {
                hub: self.hub.clone(),
                cfg: self.cfg.clone(),
                path,
                opts: Some(self.options(ctx, "ws-flv")),
                sub: None,
            };
            ctx.upgrade_websocket(h, &WsOptions::default());
            return;
        }
        let opts = self.options(ctx, "http-flv");
        let mut h = Headers::new();
        h.set("Content-Type", "video/x-flv");
        h.set("Cache-Control", "no-cache");
        if let Some(o) = &self.cfg.cors_origin {
            h.set("Access-Control-Allow-Origin", o);
        }
        // The response starts once the subscription is accepted, so a refused or missing
        // stream gets a proper status instead of an empty 200.
        let Some(d) = ctx.detach() else { return };
        let out = Arc::new(Out {
            w: Mutex::new(Some(Writer::Pending(d, h))),
            sub: Mutex::new(None),
        });
        let sink = FlvSink::new(out.clone(), &self.cfg);
        let backlog = out.clone();
        let sink = Dropper::new(sink, move || backlog.queued(), self.cfg.write_queue_limit);
        match self.hub.subscribe(&path, sink, opts) {
            Ok(sub) => {
                out.start();
                out.keep(sub);
            }
            Err(e) => out.refuse(&e),
        }
    }
}

enum Writer {
    Pending(flash_http::Detached, Headers),
    Http(flash_http::BodyStream),
    Ws(WsSender),
}

/// Where a sink writes, and the subscription it keeps alive.
struct Out {
    w: Mutex<Option<Writer>>,
    sub: Mutex<Option<Subscription>>,
}

impl Out {
    fn queued(&self) -> usize {
        match &*lock(&self.w) {
            Some(Writer::Http(b)) => b.queued_bytes(),
            Some(Writer::Ws(s)) => s.queued_bytes(),
            Some(Writer::Pending(..)) | None => 0,
        }
    }

    /// Starts the HTTP response if it has not started yet.
    fn start(&self) {
        let mut g = lock(&self.w);
        if let Some(Writer::Pending(..)) = &*g {
            if let Some(Writer::Pending(d, h)) = g.take() {
                *g = d.stream_response(200, h).map(Writer::Http);
            }
        }
    }

    /// Answers a refused subscription.
    fn refuse(&self, e: &HubError) {
        let status = match e {
            HubError::NotFound | HubError::Unpublished => 404,
            HubError::Denied(_) => 403,
            _ => 503,
        };
        match lock(&self.w).take() {
            Some(Writer::Pending(d, _)) => {
                d.respond(flash_http::Response::text(status, e.to_string()))
            }
            Some(Writer::Http(b)) => b.finish(),
            Some(Writer::Ws(s)) => s.close(4000 + status, &e.to_string()),
            None => {}
        }
    }

    fn write(&self, data: &[u8]) -> bool {
        self.start();
        let ok = match &*lock(&self.w) {
            Some(Writer::Http(b)) => b.write(data).is_ok(),
            Some(Writer::Ws(s)) => s.send_binary(data).is_ok(),
            Some(Writer::Pending(..)) | None => false,
        };
        if !ok {
            self.finish();
        }
        ok
    }

    /// Keeps `sub` alive until the player is gone (or drops it if it already is).
    fn keep(&self, sub: Subscription) {
        if lock(&self.w).is_some() {
            *lock(&self.sub) = Some(sub);
        }
    }

    fn finish(&self) {
        let w = lock(&self.w).take();
        match w {
            Some(Writer::Http(b)) => b.finish(),
            Some(Writer::Ws(s)) => s.close(1000, ""),
            Some(Writer::Pending(d, _)) => {
                d.respond(flash_http::Response::text(404, "stream ended"))
            }
            None => {}
        }
        // Closing from inside a sink never blocks; the hub unlinks the subscription.
        if let Some(s) = lock(&self.sub).take() {
            s.close();
        }
    }
}

/// A hub sink writing an FLV stream.
struct FlvSink {
    out: Arc<Out>,
    enc: Encoder,
    timeline: Timeline,
    header_sent: bool,
    started: bool,
    max_queue: usize,
    buf: Vec<u8>,
}

impl FlvSink {
    fn new(out: Arc<Out>, cfg: &HttpFlvConfig) -> FlvSink {
        FlvSink {
            out,
            enc: Encoder::new(cfg.encoder.clone()),
            timeline: Timeline::from_zero(),
            header_sent: false,
            started: false,
            max_queue: cfg.max_write_queue,
            buf: Vec::new(),
        }
    }

    fn flush(&mut self) {
        if !self.buf.is_empty() {
            let b = std::mem::take(&mut self.buf);
            self.out.write(&b);
        }
    }
}

impl Sink for FlvSink {
    fn on_tracks(&mut self, tracks: &Tracks) {
        self.enc.set_tracks(tracks);
        if self.started {
            self.timeline.restart();
        }
        self.started = true;
        let (v, a) = self.enc.carried();
        if !self.header_sent {
            flv::write_header(&mut self.buf, v.is_some(), a.is_some());
            self.header_sent = true;
            // WS-FLV: the header is a message of its own.
            self.flush();
        }
        for (tag, body) in self.enc.headers() {
            let ts = match tag {
                flv::TAG_VIDEO => self.timeline.last_of(true),
                flv::TAG_AUDIO => self.timeline.last_of(false),
                _ => self.timeline.last(),
            };
            flv::write_tag(&mut self.buf, tag, flv::ms(ts) as u32, &body);
            self.flush();
        }
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        if self.out.queued() > self.max_queue {
            self.out.finish();
            return;
        }
        let Some((tag, body)) = self.enc.packet(pkt) else {
            return;
        };
        let ts = self.timeline.stamp(tag == flv::TAG_VIDEO, pkt.dts);
        flv::write_tag(&mut self.buf, tag, flv::ms(ts) as u32, &body);
        self.flush();
    }

    fn on_close(&mut self, _err: HubError) {
        self.out.finish();
    }
}

/// The WebSocket side: subscribes once the connection is open.
struct WsFlv {
    hub: Hub,
    cfg: Arc<HttpFlvConfig>,
    path: String,
    opts: Option<SubscribeOptions>,
    sub: Option<Arc<Out>>,
}

impl WsHandler for WsFlv {
    fn on_open(&mut self, ws: &WsSender) {
        let Some(opts) = self.opts.take() else { return };
        let out = Arc::new(Out {
            w: Mutex::new(Some(Writer::Ws(ws.clone()))),
            sub: Mutex::new(None),
        });
        let sink = FlvSink::new(out.clone(), &self.cfg);
        let backlog = out.clone();
        let sink = Dropper::new(sink, move || backlog.queued(), self.cfg.write_queue_limit);
        match self.hub.subscribe(&self.path, sink, opts) {
            Ok(sub) => {
                out.keep(sub);
                self.sub = Some(out);
            }
            Err(e) => out.refuse(&e),
        }
    }

    fn on_message(&mut self, _ws: &WsSender, _msg: WsMessage) {}

    fn on_close(&mut self, _code: Option<u16>, _reason: &str) {
        if let Some(out) = self.sub.take() {
            out.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_paths() {
        assert_eq!(path_of("/live/s.flv", ".flv").as_deref(), Some("live/s"));
        assert_eq!(path_of("/a/b/c.flv", ".flv").as_deref(), Some("a/b/c"));
        assert_eq!(path_of("/.flv", ".flv"), None);
        assert_eq!(path_of("/live/s.ts", ".flv"), None);
        assert_eq!(path_of("/../x.flv", ".flv"), None);
    }
}
