//! WHIP (RFC 9725, WebRTC-HTTP ingestion) and WHEP (WebRTC-HTTP egress) signalling as
//! only-http routes, in front of the [`Hub`].
//!
//! The HTTP side is complete: `POST` of an `application/sdp` offer to `/whip/<path>` (publish)
//! or `/whep/<path>` (play) answers `201 Created` with the answer SDP and a `Location` for the
//! session resource; `DELETE` on that resource ends the session; `PATCH` with
//! `application/trickle-ice-sdpfrag` passes trickled candidates (204) or answers 405 when the
//! engine does not take them; `OPTIONS` answers the CORS preflight with `Accept-Post`. Publishes
//! go through [`Hub::reserve`], so the hub's `on_publish` hook authorizes WHIP like every other
//! ingest (the `Authorization: Bearer` token is passed in [`PeerInfo::query`] as
//! `token=<value>` when the URL has no query).
//!
//! The media side (ICE, DTLS-SRTP, RTP) is a [`WebRtcEngine`]: the WebRTC crate implements it,
//! turning an offer into an answer and bridging media into the [`Publisher`] it is handed
//! (WHIP) or out of a hub subscription it makes itself (WHEP). [`NoMedia`] is the placeholder
//! engine: every offer gets `501 Not Implemented`.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use only_http::{Context, Method, Response, Router};

use crate::{
    hub::{Hub, HubError, PeerInfo, Publisher},
    sdp,
};

/// Why an offer or a session operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WhipError {
    /// The engine does not carry media (501).
    NotImplemented,
    /// The offer is unusable, with a reason (400).
    BadOffer(String),
    /// No codec of the offer is supported (406).
    Unsupported,
    /// The operation is not supported, such as trickle ICE (405).
    NotAllowed,
    /// The hub refused (busy path, hook, missing stream, limits).
    Hub(HubError),
    /// Anything else (500).
    Internal(String),
}

impl fmt::Display for WhipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WhipError::NotImplemented => f.write_str("WebRTC media is not available"),
            WhipError::BadOffer(r) => write!(f, "bad offer: {r}"),
            WhipError::Unsupported => f.write_str("no supported codec in the offer"),
            WhipError::NotAllowed => f.write_str("operation not allowed"),
            WhipError::Hub(e) => write!(f, "{e}"),
            WhipError::Internal(r) => write!(f, "internal error: {r}"),
        }
    }
}

impl std::error::Error for WhipError {}

impl WhipError {
    fn status(&self) -> u16 {
        match self {
            WhipError::NotImplemented => 501,
            WhipError::BadOffer(_) => 400,
            WhipError::Unsupported => 406,
            WhipError::NotAllowed => 405,
            WhipError::Hub(HubError::NotFound | HubError::Unpublished) => 404,
            WhipError::Hub(HubError::StreamBusy) => 409,
            WhipError::Hub(HubError::Denied(_)) => 403,
            WhipError::Hub(HubError::Limit | HubError::Closed) => 503,
            WhipError::Internal(_) => 500,
        }
    }
}

/// What a request to start a session carries besides the offer.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OfferInfo {
    /// The hub path (`live/cam` for `/whip/live/cam`).
    pub path: String,
    /// The peer, protocol `whip` or `whep`.
    pub peer: PeerInfo,
    /// The offer as received.
    pub offer_text: String,
    /// The offer parsed.
    pub offer: sdp::Session,
}

/// A live WebRTC session the engine runs; dropped (or [`close`](Self::close)d) when the
/// client `DELETE`s its resource or the server shuts it.
pub trait WebRtcSession: Send + 'static {
    /// A trickle-ICE SDP fragment (`PATCH`). The default refuses (405).
    fn trickle(&mut self, _fragment: &str) -> Result<(), WhipError> {
        Err(WhipError::NotAllowed)
    }
    /// Ends the session.
    fn close(&mut self) {}
}

/// An answer to an offer and the session it starts.
#[non_exhaustive]
pub struct Answer {
    /// The answer SDP.
    pub sdp: String,
    /// The session.
    pub session: Box<dyn WebRtcSession>,
}

impl Answer {
    /// An answer with `sdp` for `session`.
    pub fn new(sdp: impl Into<String>, session: Box<dyn WebRtcSession>) -> Answer {
        Answer {
            sdp: sdp.into(),
            session,
        }
    }
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer")
            .field("sdp", &self.sdp)
            .finish_non_exhaustive()
    }
}

/// The integration point for a WebRTC stack. Calls run on an HTTP connection's I/O thread
/// and must not block (gather host candidates at once, trickle the rest).
pub trait WebRtcEngine: Send + Sync + 'static {
    /// WHIP: answer `info.offer` and write what the peer sends into `publisher` (reserved for
    /// `info.path`: its first `set_tracks` makes the stream live, dropping it unpublishes).
    fn publish(&self, info: &OfferInfo, publisher: Publisher) -> Result<Answer, WhipError>;
    /// WHEP: answer `info.offer` and send the hub stream `info.path` to the peer (the engine
    /// subscribes to `hub` itself, typically through a [`crate::hub::Dropper`]).
    fn play(&self, info: &OfferInfo, hub: &Hub) -> Result<Answer, WhipError>;
}

/// The placeholder engine: every offer gets `501 Not Implemented`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMedia;

impl WebRtcEngine for NoMedia {
    fn publish(&self, _info: &OfferInfo, _publisher: Publisher) -> Result<Answer, WhipError> {
        Err(WhipError::NotImplemented)
    }
    fn play(&self, _info: &OfferInfo, _hub: &Hub) -> Result<Answer, WhipError> {
        Err(WhipError::NotImplemented)
    }
}

/// Configures a [`WhipServer`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WhipConfig {
    /// Prefix of WHIP endpoints (`/whip` serves `/whip/<path>`).
    pub whip_prefix: String,
    /// Prefix of WHEP endpoints.
    pub whep_prefix: String,
    /// Prefix of session resources (`Location`).
    pub resource_prefix: String,
    /// Most concurrent sessions; 0 is unlimited.
    pub max_sessions: usize,
    /// `Access-Control-Allow-Origin` value, `None` for no CORS headers.
    pub cors_origin: Option<String>,
    /// `Link` headers advertising ICE servers (RFC 9725 4.6), as full header values.
    pub ice_links: Vec<String>,
}

impl Default for WhipConfig {
    fn default() -> Self {
        WhipConfig {
            whip_prefix: "/whip".to_owned(),
            whep_prefix: "/whep".to_owned(),
            resource_prefix: "/webrtc/session".to_owned(),
            max_sessions: 0,
            cors_origin: Some("*".to_owned()),
            ice_links: Vec::new(),
        }
    }
}

struct Entry {
    session: Box<dyn WebRtcSession>,
}

struct Inner {
    hub: Hub,
    engine: Arc<dyn WebRtcEngine>,
    cfg: WhipConfig,
    sessions: Mutex<HashMap<String, Entry>>,
}

/// The WHIP/WHEP endpoints. Cheap to clone; mount with [`routes`](Self::routes).
#[derive(Clone)]
pub struct WhipServer(Arc<Inner>);

impl fmt::Debug for WhipServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WhipServer")
            .field("cfg", &self.0.cfg)
            .field("sessions", &self.sessions())
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    let _ = only_crypto::rand::fill_random(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Whip,
    Whep,
}

impl WhipServer {
    /// Endpoints for `hub` whose media `engine` carries.
    pub fn new(hub: Hub, engine: Arc<dyn WebRtcEngine>, cfg: WhipConfig) -> WhipServer {
        WhipServer(Arc::new(Inner {
            hub,
            engine,
            cfg,
            sessions: Mutex::new(HashMap::new()),
        }))
    }

    /// The number of live sessions.
    pub fn sessions(&self) -> usize {
        lock(&self.0.sessions).len()
    }

    /// Ends every session.
    pub fn close_all(&self) {
        let all: Vec<Entry> = lock(&self.0.sessions).drain().map(|(_, e)| e).collect();
        for mut e in all {
            e.session.close();
        }
    }

    /// Adds the endpoints to `router`.
    pub fn routes(&self, router: Router) -> Router {
        let c = &self.0.cfg;
        let mut r = router;
        for (prefix, kind) in [
            (c.whip_prefix.clone(), Kind::Whip),
            (c.whep_prefix.clone(), Kind::Whep),
        ] {
            let pattern = format!("{}/*path", prefix.trim_end_matches('/'));
            let me = self.clone();
            r = r.post(&pattern, move |ctx: &mut Context| me.offer(ctx, kind));
            let me = self.clone();
            r = r.options(&pattern, move |ctx: &mut Context| {
                me.preflight(ctx, "POST, OPTIONS");
            });
        }
        let res = format!("{}/:id", c.resource_prefix.trim_end_matches('/'));
        let me = self.clone();
        r = r.delete(&res, move |ctx: &mut Context| me.delete(ctx));
        let me = self.clone();
        r = r.patch(&res, move |ctx: &mut Context| me.patch(ctx));
        let me = self.clone();
        r = r.options(&res, move |ctx: &mut Context| {
            me.preflight(ctx, "PATCH, DELETE, OPTIONS");
        });
        r
    }

    fn cors(&self, mut resp: Response) -> Response {
        if let Some(o) = &self.0.cfg.cors_origin {
            resp = resp
                .header("Access-Control-Allow-Origin", o)
                .header("Access-Control-Expose-Headers", "Location, Link, ETag");
        }
        resp
    }

    fn preflight(&self, ctx: &mut Context, methods: &str) {
        let mut resp = Response::new(204)
            .header("Accept-Post", "application/sdp")
            .header("Allow", methods);
        if self.0.cfg.cors_origin.is_some() {
            resp = resp.header("Access-Control-Allow-Methods", methods).header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type, If-Match",
            );
        }
        for l in &self.0.cfg.ice_links {
            resp = resp.header("Link", l);
        }
        let resp = self.cors(resp);
        ctx.respond(resp);
    }

    fn error(&self, ctx: &mut Context, e: &WhipError) {
        let resp = self.cors(Response::text(e.status(), e.to_string()));
        ctx.respond(resp);
    }

    fn offer(&self, ctx: &mut Context, kind: Kind) {
        let ct = ctx
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if !ct.starts_with("application/sdp") {
            let resp = self.cors(Response::text(415, "offer must be application/sdp"));
            return ctx.respond(resp);
        }
        let path = ctx.param("path").unwrap_or("").trim_matches('/').to_owned();
        if path.is_empty() {
            return self.error(ctx, &WhipError::BadOffer("empty stream path".into()));
        }
        let max = self.0.cfg.max_sessions;
        if max > 0 && self.sessions() >= max {
            return self.error(ctx, &WhipError::Hub(HubError::Limit));
        }
        let offer_text = String::from_utf8_lossy(ctx.body()).into_owned();
        let offer = match sdp::Session::parse(&offer_text) {
            Ok(s) if !s.media.is_empty() => s,
            Ok(_) => return self.error(ctx, &WhipError::BadOffer("no media".into())),
            Err(e) => return self.error(ctx, &WhipError::BadOffer(e.to_string())),
        };
        let mut query = ctx.req().query().unwrap_or("").to_owned();
        if query.is_empty() {
            if let Some(t) = ctx.header("authorization").and_then(|h| {
                h.strip_prefix("Bearer ")
                    .or_else(|| h.strip_prefix("bearer "))
            }) {
                query = format!("token={}", t.trim());
            }
        }
        let protocol = if kind == Kind::Whip { "whip" } else { "whep" };
        let info = OfferInfo {
            path: path.clone(),
            peer: PeerInfo::new(protocol, Some(ctx.peer()), query),
            offer_text,
            offer,
        };
        let result = match kind {
            Kind::Whip => match self.0.hub.reserve(&path, info.peer.clone()) {
                Ok(p) => self.0.engine.publish(&info, p),
                Err(e) => Err(WhipError::Hub(e)),
            },
            Kind::Whep => {
                if self.0.hub.stream_info(&path).is_none_or(|s| !s.publishing) {
                    Err(WhipError::Hub(HubError::NotFound))
                } else {
                    self.0.engine.play(&info, &self.0.hub)
                }
            }
        };
        let answer = match result {
            Ok(a) => a,
            Err(e) => return self.error(ctx, &e),
        };
        let id = random_id();
        let location = format!("{}/{id}", self.0.cfg.resource_prefix.trim_end_matches('/'));
        lock(&self.0.sessions).insert(
            id.clone(),
            Entry {
                session: answer.session,
            },
        );
        let mut resp = Response::with_body(201, "application/sdp", answer.sdp.into_bytes())
            .header("Location", &location)
            .header("ETag", format!("\"{id}\""));
        for l in &self.0.cfg.ice_links {
            resp = resp.header("Link", l);
        }
        let resp = self.cors(resp);
        ctx.respond(resp);
    }

    fn delete(&self, ctx: &mut Context) {
        let id = ctx.param("id").unwrap_or("").to_owned();
        let entry = lock(&self.0.sessions).remove(&id);
        let resp = match entry {
            Some(mut e) => {
                e.session.close();
                Response::new(200)
            }
            None => Response::text(404, "no such session"),
        };
        let resp = self.cors(resp);
        ctx.respond(resp);
    }

    fn patch(&self, ctx: &mut Context) {
        let id = ctx.param("id").unwrap_or("").to_owned();
        let ct = ctx
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if !ct.starts_with("application/trickle-ice-sdpfrag") {
            let resp = self.cors(Response::text(
                415,
                "expected application/trickle-ice-sdpfrag",
            ));
            return ctx.respond(resp);
        }
        let frag = String::from_utf8_lossy(ctx.body()).into_owned();
        let r = match lock(&self.0.sessions).get_mut(&id) {
            Some(e) => e.session.trickle(&frag),
            None => Err(WhipError::Hub(HubError::NotFound)),
        };
        match r {
            Ok(()) => {
                let resp = self.cors(Response::new(204));
                ctx.respond(resp);
            }
            Err(e) => self.error(ctx, &e),
        }
    }
}

/// Whether `m` is a method the endpoints answer (for routers that dispatch by hand).
pub fn handles(m: &Method) -> bool {
    matches!(
        m,
        Method::Post | Method::Delete | Method::Patch | Method::Options
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpStream,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use only::{Engine, Listener};
    use only_http::serve;

    use crate::av::{Codec, Track};

    struct Echo {
        closed: Arc<AtomicUsize>,
    }

    struct EchoSession {
        closed: Arc<AtomicUsize>,
        _publisher: Option<Publisher>,
    }

    impl WebRtcSession for EchoSession {
        fn trickle(&mut self, frag: &str) -> Result<(), WhipError> {
            if frag.contains("candidate") {
                Ok(())
            } else {
                Err(WhipError::BadOffer("frag".into()))
            }
        }
        fn close(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl WebRtcEngine for Echo {
        fn publish(&self, info: &OfferInfo, p: Publisher) -> Result<Answer, WhipError> {
            p.set_tracks(Arc::from(vec![Track::new(Codec::Opus, vec![])]));
            Ok(Answer::new(
                format!("v=0\r\ns=answer-{}\r\n", info.path),
                Box::new(EchoSession {
                    closed: self.closed.clone(),
                    _publisher: Some(p),
                }),
            ))
        }
        fn play(&self, info: &OfferInfo, _hub: &Hub) -> Result<Answer, WhipError> {
            Ok(Answer::new(
                format!("v=0\r\ns=play-{}\r\n", info.path),
                Box::new(EchoSession {
                    closed: self.closed.clone(),
                    _publisher: None,
                }),
            ))
        }
    }

    fn http(addr: std::net::SocketAddr, req: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn post(addr: std::net::SocketAddr, path: &str, ct: &str, body: &str) -> String {
        http(
            addr,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: {ct}\r\nAuthorization: Bearer abc\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
    }

    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=rtpmap:111 opus/48000/2\r\n";

    #[test]
    fn whip_whep_http_plumbing() {
        let hub = Hub::default();
        let closed = Arc::new(AtomicUsize::new(0));
        let srv = WhipServer::new(
            hub.clone(),
            Arc::new(Echo {
                closed: closed.clone(),
            }),
            WhipConfig::default(),
        );
        let none = WhipServer::new(
            hub.clone(),
            Arc::new(NoMedia),
            WhipConfig {
                whip_prefix: "/n/whip".into(),
                whep_prefix: "/n/whep".into(),
                resource_prefix: "/n/res".into(),
                ..WhipConfig::default()
            },
        );
        let app = none.routes(srv.routes(Router::new()));
        let engine = Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .build()
            .unwrap();
        engine.start().unwrap();
        let addr = engine.local_addrs()[0];

        let r = post(addr, "/whip/live/a", "application/sdp", OFFER);
        assert!(r.starts_with("HTTP/1.1 201"), "{r}");
        assert!(r.contains("s=answer-live/a"));
        let loc = r
            .lines()
            .find_map(|l| l.strip_prefix("Location: "))
            .unwrap()
            .trim()
            .to_owned();
        assert!(loc.starts_with("/webrtc/session/"));
        assert!(hub.stream_info("live/a").unwrap().publishing);
        assert_eq!(
            hub.stream_info("live/a").unwrap().publisher.query,
            "token=abc"
        );
        // second publisher: busy
        assert!(post(addr, "/whip/live/a", "application/sdp", OFFER).starts_with("HTTP/1.1 409"));
        // WHEP of a live stream, of a missing one
        assert!(post(addr, "/whep/live/a", "application/sdp", OFFER).starts_with("HTTP/1.1 201"));
        assert!(
            post(addr, "/whep/live/none", "application/sdp", OFFER).starts_with("HTTP/1.1 404")
        );
        // wrong type, bad SDP
        assert!(post(addr, "/whip/live/b", "text/plain", OFFER).starts_with("HTTP/1.1 415"));
        assert!(
            post(addr, "/whip/live/b", "application/sdp", "nonsense").starts_with("HTTP/1.1 400")
        );
        // trickle
        let patch = |frag: &str| {
            http(
                addr,
                &format!(
                    "PATCH {loc} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/trickle-ice-sdpfrag\r\nContent-Length: {}\r\n\r\n{frag}",
                    frag.len()
                ),
            )
        };
        assert!(patch("a=candidate:1 1 udp 1 1.2.3.4 5 typ host").starts_with("HTTP/1.1 204"));
        assert!(patch("a=x").starts_with("HTTP/1.1 400"));
        // preflight
        let o = http(
            addr,
            "OPTIONS /whip/live/a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        assert!(
            o.starts_with("HTTP/1.1 204") && o.contains("Accept-Post: application/sdp"),
            "{o}"
        );
        // delete ends the session and unpublishes
        let d = http(
            addr,
            &format!("DELETE {loc} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
        );
        assert!(d.starts_with("HTTP/1.1 200"), "{d}");
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        assert!(hub.stream_info("live/a").is_none_or(|s| !s.publishing));
        assert!(
            http(
                addr,
                &format!("DELETE {loc} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            )
            .starts_with("HTTP/1.1 404")
        );
        // the placeholder engine
        assert!(post(addr, "/n/whip/live/c", "application/sdp", OFFER).starts_with("HTTP/1.1 501"));
        assert!(hub.stream_info("live/c").is_none());
        assert_eq!(srv.sessions(), 1);
        srv.close_all();
        assert_eq!(srv.sessions(), 0);
        assert!(handles(&Method::Post));
        engine.shutdown();
    }
}
