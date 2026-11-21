//! The RTMP client: [`push`] a hub stream to an RTMP server (publish), or [`pull`] one from an
//! RTMP server into a hub (play).
//!
//! Both dial `rtmp://host[:port]/app[/instance]/stream[?query]` ([`RtmpUrl`]) on an
//! [`Engine`], run the handshake (C0 C1 C2, the Flash digest one unless
//! [`RtmpClientConfig::simple_handshake`]), then the command exchange:
//!
//! * push: `connect`, `releaseStream`, `FCPublish`, `createStream`, `publish(name, "live")`;
//!   once the server answers `NetStream.Publish.Start` the client subscribes to the hub path
//!   and sends `@setDataFrame` onMetaData, the sequence headers and the media, written by
//!   [`flv::Encoder`] (Enhanced RTMP `hvc1` / `vp09` / `av01` / `vp08` / `Opus`; H.265 with
//!   the legacy codec id under [`EncoderConfig::legacy_hevc`]).
//!   A server that reads too slowly has packets dropped ([`Dropper`], video to the next
//!   keyframe) and is disconnected past [`RtmpClientConfig::max_write_queue`].
//! * pull: the hub path is reserved at once (a busy path fails [`pull`] right away), then
//!   `connect`, `createStream`, `play(name)` and Set Buffer Length; audio, video, data and
//!   aggregate messages are decoded by [`flv::Decoder`] into the hub publisher, which goes live
//!   with the first tracks.
//!
//! Both answer the server's Set Chunk Size, Window Acknowledgement Size (acknowledgements are
//! sent per window) and ping requests, and end with an error carrying the server's status code
//! when it refuses (`NetConnection.Connect.Rejected`, `NetStream.Publish.BadName`,
//! `NetStream.Play.StreamNotFound`...).
//!
//! Every wait is bounded ([`RtmpClientConfig`]): connecting, the handshake, each command's
//! answer, and while pulling, the time without any byte from the server. Received messages are
//! bounded by [`RtmpClientConfig::max_message_size`] (the [`ChunkReader`] limits).
//!
//! Not supported: `rtmps://` (TLS), RTMPE/RTMPT, AMF3 command encoding, Enhanced RTMP
//! multitrack.

use std::{
    fmt,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Acceptor, Conn, Engine, Handler};

use super::{
    chunk::{self, ChunkReader, Message},
    handshake,
};
use crate::{
    amf::{self, Value},
    av::{Packet, Tracks},
    flv::{self, Decoder, Encoder, EncoderConfig, Event},
    hub::{
        Dropper, Hub, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription, Timeline,
    },
};

/// The RTMP port used when the URL names none.
pub const DEFAULT_PORT: u16 = 1935;

/// Configures [`push`] and [`pull`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RtmpClientConfig {
    /// Connect to this address instead of resolving the URL's host (which then only names the
    /// server in `tcUrl`). Use it to keep [`push`] / [`pull`] from resolving a host name on the
    /// calling thread. Default `None`.
    pub addr: Option<SocketAddr>,
    /// Time to establish the TCP connection. Default 10 s; `Duration::ZERO` leaves it to the
    /// engine's `Config::connect_timeout`.
    pub connect_timeout: Duration,
    /// Time from the connection to the end of the handshake (S0 S1 S2 received). Default 10 s;
    /// `Duration::ZERO` disables it.
    pub handshake_timeout: Duration,
    /// Time the server has to answer each command (`connect`, `createStream`, `publish`,
    /// `play`). Default 10 s; `Duration::ZERO` disables it.
    pub response_timeout: Duration,
    /// While pulling, a server that sends nothing for this long is disconnected (a live stream
    /// sends media continuously). Not applied to a push, which only sends. Default 30 s;
    /// `Duration::ZERO` disables it.
    pub idle_timeout: Duration,
    /// The chunk size the client sends with (it tells the server with Set Chunk Size).
    /// Default 4096.
    pub chunk_size: u32,
    /// The window acknowledgement size announced to the server. Default 2 500 000.
    pub window_ack_size: u32,
    /// The largest message accepted from the server; unfinished messages over all chunk
    /// streams may hold twice this. A server going past it is disconnected. Default 16 MiB.
    pub max_message_size: usize,
    /// Push: bytes queued for the server above which packets are dropped (video to the next
    /// keyframe). Default 2 MiB.
    pub write_queue_limit: usize,
    /// Push: bytes queued for the server above which the connection is closed
    /// ([`ClientError::WriteQueueFull`]). Default 16 MiB.
    pub max_write_queue: usize,
    /// Push: how long to wait, once the server accepted the publish, for a publisher on the hub
    /// path (`None`: the path must be live then). The push ends when that publisher leaves.
    /// Default 10 s.
    pub source_wait: Option<Duration>,
    /// Pull: the buffer length sent with Set Buffer Length (User Control event 3). Default
    /// 1 s.
    pub buffer_length: Duration,
    /// Push: FLV encoding options (legacy H.265 codec id instead of Enhanced RTMP `hvc1`).
    pub encoder: EncoderConfig,
    /// The `flashVer` sent in `connect`; `None` sends `FMLE/3.0 (compatible; only)` when
    /// pushing and `LNX 9,0,124,2` when pulling.
    pub flash_ver: Option<String>,
    /// Use the simple handshake rather than the Flash digest one (some old servers only take
    /// the simple one; every server takes both in practice). Default `false`.
    pub simple_handshake: bool,
}

impl Default for RtmpClientConfig {
    fn default() -> Self {
        RtmpClientConfig {
            addr: None,
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            chunk_size: 4096,
            window_ack_size: 2_500_000,
            max_message_size: 16 << 20,
            write_queue_limit: 2 << 20,
            max_write_queue: 16 << 20,
            source_wait: Some(Duration::from_secs(10)),
            buffer_length: Duration::from_secs(1),
            encoder: EncoderConfig::default(),
            flash_ver: None,
            simple_handshake: false,
        }
    }
}

/// Why a [`push`] or [`pull`] failed or ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientError {
    /// The URL is not `rtmp://host[:port]/app/stream` (with the reason). `rtmps://` is not
    /// supported.
    BadUrl(String),
    /// The host name did not resolve.
    Resolve(String),
    /// The TCP connection failed.
    Connect(String),
    /// A wait passed its timeout: `"connect"`, `"handshake"`, `"connect response"`,
    /// `"createStream response"`, `"publish response"`, `"play response"` or `"data"` (the
    /// idle timeout while pulling).
    TimedOut(&'static str),
    /// The server's handshake was invalid (S0 is not version 3).
    Handshake,
    /// The server broke the chunk stream or the command exchange (with the reason), or sent a
    /// message over [`RtmpClientConfig::max_message_size`].
    Protocol(String),
    /// The server refused: `_error` to `connect` / `createStream`, or an error `onStatus`
    /// (`NetStream.Publish.BadName`, `NetStream.Publish.Denied`,
    /// `NetStream.Play.StreamNotFound`...).
    Rejected {
        /// The status code (`NetConnection.Connect.Rejected`...), empty when none was given.
        code: String,
        /// The server's description.
        description: String,
    },
    /// The hub refused or ended the stream: pull could not reserve the path
    /// ([`HubError::StreamBusy`]...), or a push found no publisher within
    /// [`RtmpClientConfig::source_wait`] ([`HubError::NotFound`]) or its publisher left
    /// ([`HubError::Unpublished`]).
    Hub(HubError),
    /// Push: the server read too slowly ([`RtmpClientConfig::max_write_queue`]).
    WriteQueueFull,
    /// Pull: the server ended the stream (`NetStream.Play.Stop`, `NetStream.Play.Complete`).
    Ended(String),
    /// The server closed the connection (which is how most servers end a stream too), or it
    /// failed; with the reason.
    Disconnected(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::BadUrl(r) => write!(f, "bad RTMP URL: {r}"),
            ClientError::Resolve(r) => write!(f, "cannot resolve the RTMP server: {r}"),
            ClientError::Connect(r) => write!(f, "cannot connect to the RTMP server: {r}"),
            ClientError::TimedOut(w) => write!(f, "RTMP client timed out waiting for {w}"),
            ClientError::Handshake => f.write_str("RTMP handshake failed"),
            ClientError::Protocol(r) => write!(f, "RTMP protocol error: {r}"),
            ClientError::Rejected { code, description } => {
                write!(f, "RTMP server refused: {code} {description}")
            }
            ClientError::Hub(e) => write!(f, "hub: {e}"),
            ClientError::WriteQueueFull => f.write_str("RTMP server reads too slowly"),
            ClientError::Ended(code) => write!(f, "RTMP stream ended: {code}"),
            ClientError::Disconnected(r) => write!(f, "RTMP connection closed: {r}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A parsed `rtmp://host[:port]/app[/instance]/stream[?query]`.
///
/// The stream name is the last path segment with the query; the application is everything
/// between the host and the stream name (`live`, or `live/instance`); `tcUrl` is the URL up to
/// the application, the way Flash and ffmpeg send it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtmpUrl {
    /// The host as written (an IPv6 literal without its brackets).
    pub host: String,
    /// The port, [`DEFAULT_PORT`] when the URL names none.
    pub port: u16,
    /// The application (`connect`'s `app`).
    pub app: String,
    /// The stream name with its query (`publish` / `play` argument).
    pub stream: String,
    /// `rtmp://host[:port]/app`.
    pub tc_url: String,
}

impl RtmpUrl {
    /// Parses `url`. Only `rtmp://` is accepted; the application and the stream name must not
    /// be empty.
    pub fn parse(url: &str) -> Result<RtmpUrl, ClientError> {
        let bad = |r: &str| ClientError::BadUrl(r.to_owned());
        let Some((scheme, rest)) = url.split_once("://") else {
            return Err(bad("no scheme"));
        };
        if !scheme.eq_ignore_ascii_case("rtmp") {
            return Err(bad("only rtmp:// is supported"));
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.contains('@') {
            return Err(bad("credentials in the URL are not supported"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let Some((h, after)) = v6.split_once(']') else {
                return Err(bad("unterminated IPv6 literal"));
            };
            let port = match after {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .ok_or_else(|| bad("junk after the host"))?,
                ),
            };
            (h, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err(bad("no host"));
        }
        let port = match port {
            None => DEFAULT_PORT,
            Some(p) => p.parse::<u16>().map_err(|_| bad("invalid port"))?,
        };
        // The query belongs to the stream name; a '/' inside it does not split the path.
        let (path_part, query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        let path_part = path_part.trim_matches('/');
        let Some((app, name)) = path_part.rsplit_once('/') else {
            return Err(bad("expected /app/stream"));
        };
        if app.is_empty() || name.is_empty() {
            return Err(bad("empty application or stream name"));
        }
        let stream = match query {
            Some(q) => format!("{name}?{q}"),
            None => name.to_owned(),
        };
        let host_part = &url[..url.len() - path.len()];
        let tc_url = format!("{}/{app}", host_part.trim_end_matches('/'));
        Ok(RtmpUrl {
            host: host.to_owned(),
            port,
            app: app.to_owned(),
            stream,
            tc_url,
        })
    }

    /// The query of the stream name (after `?`), empty when there is none.
    pub fn query(&self) -> &str {
        self.stream.split_once('?').map_or("", |(_, q)| q)
    }

    /// The server address: `host` when it is an IP literal, otherwise resolved with the
    /// system resolver, which **blocks** the calling thread (never call it on an I/O thread).
    pub fn resolve(&self) -> Result<SocketAddr, ClientError> {
        if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, self.port));
        }
        (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| ClientError::Resolve(e.to_string()))?
            .next()
            .ok_or_else(|| ClientError::Resolve(format!("no address for {}", self.host)))
    }
}

/// Where an [`RtmpClient`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientState {
    /// The TCP connection is being made.
    Connecting,
    /// The RTMP handshake is running.
    Handshaking,
    /// `connect`, `createStream` and `publish` / `play` are being exchanged.
    Negotiating,
    /// Media flows: the server accepted the publish (and the hub path is subscribed) or the
    /// play.
    Streaming,
    /// Over: [`RtmpClient::error`] says why, `None` after [`RtmpClient::close`].
    Closed,
}

/// A running [`push`] or [`pull`]. Dropping it closes the connection (like
/// [`Subscription`]); [`close`](Self::close) does so explicitly.
pub struct RtmpClient {
    shared: Arc<Shared>,
}

impl fmt::Debug for RtmpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtmpClient")
            .field("url", &self.shared.setup.url)
            .field("addr", &self.shared.setup.addr)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl RtmpClient {
    /// The URL dialed.
    pub fn url(&self) -> &RtmpUrl {
        &self.shared.setup.url
    }

    /// The server address dialed.
    pub fn addr(&self) -> SocketAddr {
        self.shared.setup.addr
    }

    /// The current state.
    pub fn state(&self) -> ClientState {
        self.shared.lock().state
    }

    /// Whether the client is over (closed, failed, or ended by the server or the hub).
    pub fn is_closed(&self) -> bool {
        self.state() == ClientState::Closed
    }

    /// The error that ended the client; `None` while it runs and after [`close`](Self::close).
    pub fn error(&self) -> Option<ClientError> {
        self.shared.lock().error.clone()
    }

    /// Ends the client: a push sends `FCUnpublish` and `deleteStream`, a pull `deleteStream`,
    /// then the connection closes once that is sent. A pull's hub path is free again when this
    /// returns. Never blocks; idempotent.
    pub fn close(&self) {
        let Some((conn, stream_id)) = self.shared.end(None) else {
            return;
        };
        if let Some(c) = conn {
            if let Some(sid) = stream_id {
                let setup = &self.shared.setup;
                let mut out = Vec::new();
                if setup.push.is_some() {
                    out.extend(command_bytes(
                        setup.chunk_size(),
                        0,
                        &[
                            Value::from("FCUnpublish"),
                            Value::Number(0.0),
                            Value::Null,
                            Value::from(setup.url.stream.as_str()),
                        ],
                    ));
                }
                out.extend(command_bytes(
                    setup.chunk_size(),
                    0,
                    &[
                        Value::from("deleteStream"),
                        Value::Number(0.0),
                        Value::Null,
                        Value::Number(f64::from(sid)),
                    ],
                ));
                let _ = c.send_owned(out);
            }
            c.close_after_send();
        }
    }
}

impl Drop for RtmpClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Pushes the hub stream at `path` to the RTMP server at `url` (an RTMP publish).
///
/// Returns once the connection is being made; the handshake, the commands and the stream run
/// on the engine's I/O threads ([`RtmpClient::state`], [`RtmpClient::error`]). Once the server
/// answers `NetStream.Publish.Start`, the client subscribes to `path`, waiting up to
/// [`RtmpClientConfig::source_wait`] for its publisher, and ends when that publisher leaves.
///
/// A host name in `url` is resolved here with the system resolver, which **blocks**: do not
/// call this on an I/O thread with a host name (pass an IP literal or set
/// [`RtmpClientConfig::addr`]). The engine must have been started and have TCP I/O threads.
pub fn push(
    engine: &Engine,
    url: &str,
    hub: &Hub,
    path: &str,
    cfg: RtmpClientConfig,
) -> Result<RtmpClient, ClientError> {
    let url = RtmpUrl::parse(url)?;
    let addr = match cfg.addr {
        Some(a) => a,
        None => url.resolve()?,
    };
    let setup = Setup {
        url,
        addr,
        cfg,
        push: Some((hub.clone(), path.to_owned())),
    };
    Ok(start(engine, setup, None))
}

/// Pulls the stream at `url` from an RTMP server (an RTMP play) and publishes it in `hub` at
/// `path`.
///
/// `path` is reserved at once: a path that already has a publisher fails here with
/// [`ClientError::Hub`]. It goes live when the first tracks arrive and is unpublished when the
/// client ends. Returns once the connection is being made (see [`push`] for how it runs, and
/// for the blocking resolution of a host name).
pub fn pull(
    engine: &Engine,
    url: &str,
    hub: &Hub,
    path: &str,
    cfg: RtmpClientConfig,
) -> Result<RtmpClient, ClientError> {
    let url = RtmpUrl::parse(url)?;
    let addr = match cfg.addr {
        Some(a) => a,
        None => url.resolve()?,
    };
    let publisher = hub
        .reserve(path, PeerInfo::new("rtmp", Some(addr), url.query()))
        .map_err(ClientError::Hub)?;
    let setup = Setup {
        url,
        addr,
        cfg,
        push: None,
    };
    Ok(start(engine, setup, Some(publisher)))
}

fn start(engine: &Engine, setup: Setup, publisher: Option<Publisher>) -> RtmpClient {
    let shared = Shared::new(setup, publisher);
    {
        let mut g = shared.lock();
        let t = shared.setup.cfg.connect_timeout;
        g.deadline = (!t.is_zero()).then(|| (Instant::now() + t, "connect"));
    }
    arm(Arc::downgrade(&shared));
    let on_err = Arc::downgrade(&shared);
    engine.dial(
        shared.setup.addr,
        Dialer {
            shared: shared.clone(),
        },
        move |e| {
            if let Some(s) = on_err.upgrade() {
                s.fail(
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        ClientError::TimedOut("connect")
                    } else {
                        ClientError::Connect(e.to_string())
                    },
                    false,
                );
            }
        },
    );
    RtmpClient { shared }
}

/// What a client was started with.
struct Setup {
    url: RtmpUrl,
    addr: SocketAddr,
    cfg: RtmpClientConfig,
    /// `Some((hub, path))` for a push.
    push: Option<(Hub, String)>,
}

impl Setup {
    fn chunk_size(&self) -> usize {
        self.cfg.chunk_size.clamp(1, chunk::MAX_CHUNK_SIZE) as usize
    }
}

struct Status {
    state: ClientState,
    error: Option<ClientError>,
    conn: Option<Conn<Session>>,
    /// The pending wait and its name.
    deadline: Option<(Instant, &'static str)>,
    /// A pull's publisher, shared with the session once the connection opens, so whoever
    /// ends the client can unpublish before the state says [`ClientState::Closed`].
    publisher: Option<Arc<Publisher>>,
    /// The stream id from `createStream`.
    stream_id: Option<u32>,
}

/// Shared by the handle, the connection's handler and the timer.
struct Shared {
    setup: Setup,
    start: Instant,
    /// Milliseconds since `start` of the last bytes received.
    last_rx: AtomicU64,
    st: Mutex<Status>,
}

impl Shared {
    fn new(setup: Setup, publisher: Option<Publisher>) -> Arc<Shared> {
        Arc::new(Shared {
            setup,
            start: Instant::now(),
            last_rx: AtomicU64::new(0),
            st: Mutex::new(Status {
                state: ClientState::Connecting,
                error: None,
                conn: None,
                deadline: None,
                publisher: publisher.map(Arc::new),
                stream_id: None,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Status> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn touch(&self) {
        self.last_rx
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Moves to `state` and arms the deadline `what` (none when `t` is zero).
    fn enter(&self, state: ClientState, wait: Option<(Duration, &'static str)>) {
        let mut g = self.lock();
        if g.state == ClientState::Closed {
            return;
        }
        g.state = state;
        g.deadline = wait
            .filter(|(t, _)| !t.is_zero())
            .map(|(t, what)| (Instant::now() + t, what));
    }

    /// Moves to [`ClientState::Closed`] with `err` (`None` unless it already ended), returning
    /// the connection and, if it was streaming, the stream id. A pull's hub path is freed
    /// first: once [`RtmpClient::is_closed`] says so, the path can be pulled again.
    fn end(&self, err: Option<ClientError>) -> Option<(Option<Conn<Session>>, Option<u32>)> {
        let publisher = {
            let g = self.lock();
            if g.state == ClientState::Closed {
                return None;
            }
            g.publisher.clone()
        };
        if let Some(p) = &publisher {
            p.close(); // idempotent; packets the session writes after it are dropped
        }
        let mut g = self.lock();
        if g.state == ClientState::Closed {
            return None;
        }
        let streaming = g.state == ClientState::Streaming;
        g.state = ClientState::Closed;
        g.deadline = None;
        g.error = err;
        let held = g.publisher.take();
        let out = (g.conn.take(), g.stream_id.filter(|_| streaming));
        drop(g);
        drop((held, publisher)); // the session may still hold the last reference
        Some(out)
    }

    /// Ends the client with `err` (unless it already ended). `graceful` lets queued output
    /// leave first.
    fn fail(&self, err: ClientError, graceful: bool) {
        let Some((conn, _)) = self.end(Some(err)) else {
            return;
        };
        if let Some(c) = conn {
            if graceful {
                c.close_after_send();
            } else {
                c.close();
            }
        }
    }

    /// One timer check: `false` once the client is over.
    fn check(&self) -> bool {
        let fire = {
            let g = self.lock();
            if g.state == ClientState::Closed {
                return false;
            }
            let now = Instant::now();
            match g.deadline {
                Some((at, what)) if now >= at => Some(what),
                _ => {
                    let idle = self.setup.cfg.idle_timeout;
                    let since = (self.start.elapsed().as_millis() as u64)
                        .saturating_sub(self.last_rx.load(Ordering::Relaxed));
                    (g.state == ClientState::Streaming
                        && self.setup.push.is_none()
                        && !idle.is_zero()
                        && since >= idle.as_millis() as u64)
                        .then_some("data")
                }
            }
        };
        match fire {
            Some(what) => {
                self.fail(ClientError::TimedOut(what), false);
                false
            }
            None => true,
        }
    }
}

/// The timer check period: a quarter of the shortest timeout (they fire up to 25 % late), at
/// least 10 ms; `None` when every timeout is disabled.
fn period(cfg: &RtmpClientConfig) -> Option<Duration> {
    [
        cfg.connect_timeout,
        cfg.handshake_timeout,
        cfg.response_timeout,
        cfg.idle_timeout,
    ]
    .into_iter()
    .filter(|t| !t.is_zero())
    .min()
    .map(|t| (t / 4).max(Duration::from_millis(10)))
}

fn arm(w: Weak<Shared>) {
    let Some(s) = w.upgrade() else { return };
    let Some(every) = period(&s.setup.cfg) else {
        return;
    };
    drop(s);
    crate::timer::after(every, move || {
        let Some(s) = w.upgrade() else { return };
        if s.check() {
            drop(s);
            arm(w);
        }
    });
}

/// The engine-side acceptor of the one dialed connection.
pub(crate) struct Dialer {
    shared: Arc<Shared>,
}

impl Acceptor for Dialer {
    type Handler = Session;

    fn on_open(&self, c: &Conn<Session>) -> Session {
        let sh = &self.shared;
        let publisher = {
            let mut g = sh.lock();
            if g.state == ClientState::Closed {
                // Timed out or closed before the connection was made.
                drop(g);
                c.close();
                return Session::new(sh.clone(), None, Phase::Dead);
            }
            g.conn = Some(c.clone());
            g.publisher.clone()
        };
        sh.touch();
        sh.enter(
            ClientState::Handshaking,
            Some((sh.setup.cfg.handshake_timeout, "handshake")),
        );
        if c.send_owned(handshake::client_hello(sh.setup.cfg.simple_handshake))
            .is_err()
        {
            sh.fail(ClientError::Disconnected("send failed".into()), false);
        }
        Session::new(sh.clone(), publisher, Phase::Handshake)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for S0 S1 S2.
    Handshake,
    /// Waiting for `connect`'s `_result`.
    Connect,
    /// Waiting for `createStream`'s `_result`.
    CreateStream,
    /// Waiting for `NetStream.Publish.Start` / `NetStream.Play.Start`.
    Start,
    /// Media flows.
    Streaming,
    /// Nothing more is done.
    Dead,
}

const TX_CONNECT: f64 = 1.0;
const TX_RELEASE: f64 = 2.0;
const TX_FCPUBLISH: f64 = 3.0;
const TX_CREATE_PUSH: f64 = 4.0;
const TX_PUBLISH: f64 = 5.0;
const TX_CREATE_PULL: f64 = 2.0;
const TX_PLAY: f64 = 3.0;

/// The connection's handler: the client's state machine. Sans-IO apart from the [`Conn`] it
/// writes to, so the fuzzer drives it with a detached connection.
pub(crate) struct Session {
    shared: Arc<Shared>,
    phase: Phase,
    /// S0 S1 S2 as they arrive (at most `1 + 2 * 1536` bytes).
    hs: Vec<u8>,
    reader: ChunkReader,
    peer_window: u32,
    acked: u64,
    stream_id: u32,
    /// Pull: the hub publisher (shared with [`Status`]) and the tag decoder.
    publisher: Option<Arc<Publisher>>,
    decoder: Decoder,
    /// Push: the hub subscription.
    sub: Option<Subscription>,
}

impl Session {
    fn new(shared: Arc<Shared>, publisher: Option<Arc<Publisher>>, phase: Phase) -> Session {
        let max = shared.setup.cfg.max_message_size;
        Session {
            shared,
            phase,
            hs: Vec::new(),
            reader: ChunkReader::with_limits(max, max.saturating_mul(2)),
            peer_window: 0,
            acked: 0,
            stream_id: 0,
            publisher,
            decoder: Decoder::new(),
            sub: None,
        }
    }

    fn setup(&self) -> &Setup {
        &self.shared.setup
    }

    fn fail(&mut self, c: &Conn<Self>, err: ClientError) {
        self.phase = Phase::Dead;
        self.shared.fail(err, false);
        c.close();
    }

    fn send(&mut self, c: &Conn<Self>, m: &Message) {
        let mut out = Vec::with_capacity(m.payload.len() + 16);
        chunk::write_message(&mut out, m, self.setup().chunk_size());
        if c.send_owned(out).is_err() {
            self.fail(c, ClientError::Disconnected("send failed".into()));
        }
    }

    fn command(&mut self, c: &Conn<Self>, stream_id: u32, vals: &[Value]) {
        self.send(
            c,
            &Message::new(3, chunk::COMMAND_AMF0, stream_id, 0, amf::encode(vals)),
        );
    }

    fn handshake(&mut self, c: &Conn<Self>, data: &[u8]) {
        let need = 1 + 2 * handshake::SIZE;
        let take = (need - self.hs.len()).min(data.len());
        self.hs.extend_from_slice(&data[..take]);
        if self.hs.len() < need {
            return;
        }
        let Ok(c2) = handshake::client_reply(&self.hs) else {
            return self.fail(c, ClientError::Handshake);
        };
        self.hs = Vec::new();
        let mut out = c2;
        // Set Chunk Size goes out with the initial size of 128.
        chunk::write_message(
            &mut out,
            &chunk::control_u32(chunk::SET_CHUNK_SIZE, self.setup().chunk_size() as u32),
            128,
        );
        if c.send_owned(out).is_err() {
            return self.fail(c, ClientError::Disconnected("send failed".into()));
        }
        self.send_connect(c);
        let rest = &data[take..];
        if !rest.is_empty() && c.is_open() {
            self.chunks(c, rest);
        }
    }

    fn send_connect(&mut self, c: &Conn<Self>) {
        let s = self.setup();
        let push = s.push.is_some();
        let flash_ver = s.cfg.flash_ver.clone().unwrap_or_else(|| {
            if push {
                "FMLE/3.0 (compatible; only)".into()
            } else {
                "LNX 9,0,124,2".into()
            }
        });
        let mut props = vec![
            ("app", Value::from(s.url.app.as_str())),
            ("flashVer", Value::from(flash_ver.as_str())),
            ("tcUrl", Value::from(s.url.tc_url.as_str())),
        ];
        if push {
            props.push(("type", Value::from("nonprivate")));
        } else {
            props.extend([
                ("fpad", Value::Bool(false)),
                ("capabilities", Value::Number(15.0)),
                ("audioCodecs", Value::Number(4071.0)),
                ("videoCodecs", Value::Number(252.0)),
                ("videoFunction", Value::Number(1.0)),
            ]);
        }
        // Enhanced RTMP: the FourCCs the client takes (pull) or may send (push).
        props.push((
            "fourCcList",
            Value::Array(
                ["hvc1", "vp09", "av01", "vp08", "Opus"]
                    .into_iter()
                    .map(Value::from)
                    .collect(),
            ),
        ));
        let vals = [
            Value::from("connect"),
            Value::Number(TX_CONNECT),
            Value::object(props),
        ];
        let resp = self.setup().cfg.response_timeout;
        self.phase = Phase::Connect;
        self.shared
            .enter(ClientState::Negotiating, Some((resp, "connect response")));
        self.command(c, 0, &vals);
    }

    fn chunks(&mut self, c: &Conn<Self>, data: &[u8]) {
        let msgs = match self.reader.feed(data) {
            Ok(m) => m,
            Err(e) => return self.fail(c, ClientError::Protocol(e.to_string())),
        };
        if self.peer_window > 0
            && self.reader.received() - self.acked >= u64::from(self.peer_window)
        {
            self.acked = self.reader.received();
            self.send(c, &chunk::control_u32(chunk::ACK, self.acked as u32));
        }
        for m in msgs {
            if self.phase == Phase::Dead || !c.is_open() {
                return;
            }
            self.message(c, m);
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
                    self.on_command(c, &vals);
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
        if !matches!(self.phase, Phase::Start | Phase::Streaming) {
            return;
        }
        let Some(publisher) = self.publisher.as_ref() else {
            return;
        };
        let (tag, body) = match m.msg_type {
            chunk::AUDIO => (flv::TAG_AUDIO, &m.payload[..]),
            chunk::VIDEO => (flv::TAG_VIDEO, &m.payload[..]),
            chunk::DATA_AMF3 => (flv::TAG_SCRIPT, m.payload.get(1..).unwrap_or_default()),
            _ => (flv::TAG_SCRIPT, &m.payload[..]),
        };
        for e in self.decoder.write(tag, m.timestamp, body) {
            match e {
                Event::Tracks(t) => publisher.set_tracks(t),
                Event::Packet(p) => publisher.write(p),
            }
        }
        if self.phase == Phase::Start {
            // Some servers send media before (or without) NetStream.Play.Start.
            self.phase = Phase::Streaming;
            self.shared.enter(ClientState::Streaming, None);
        }
    }

    fn on_command(&mut self, c: &Conn<Self>, vals: &[Value]) {
        let Some(name) = vals.first().and_then(Value::as_str) else {
            return;
        };
        let tx = vals.get(1).and_then(Value::as_f64).unwrap_or(0.0);
        // The information object: the first object after the transaction id.
        let info = vals.iter().skip(2).find(|v| {
            v.props()
                .is_some_and(|p| p.iter().any(|(k, _)| k == "code"))
        });
        let field = |k: &str| {
            info.and_then(|o| o.get(k))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        let rejected = || ClientError::Rejected {
            code: field("code"),
            description: field("description"),
        };
        let push = self.setup().push.is_some();
        match name {
            "_result" | "_error" => match self.phase {
                Phase::Connect if tx == TX_CONNECT => {
                    if name == "_error" || field("level") == "error" {
                        return self.fail(c, rejected());
                    }
                    let w = self.setup().cfg.window_ack_size;
                    self.send(c, &chunk::control_u32(chunk::WINDOW_ACK_SIZE, w));
                    let n = Value::from(self.setup().url.stream.as_str());
                    let create = if push {
                        self.command(
                            c,
                            0,
                            &[
                                Value::from("releaseStream"),
                                Value::Number(TX_RELEASE),
                                Value::Null,
                                n.clone(),
                            ],
                        );
                        self.command(
                            c,
                            0,
                            &[
                                Value::from("FCPublish"),
                                Value::Number(TX_FCPUBLISH),
                                Value::Null,
                                n,
                            ],
                        );
                        TX_CREATE_PUSH
                    } else {
                        TX_CREATE_PULL
                    };
                    self.phase = Phase::CreateStream;
                    let resp = self.setup().cfg.response_timeout;
                    self.shared.enter(
                        ClientState::Negotiating,
                        Some((resp, "createStream response")),
                    );
                    self.command(
                        c,
                        0,
                        &[
                            Value::from("createStream"),
                            Value::Number(create),
                            Value::Null,
                        ],
                    );
                }
                Phase::CreateStream if tx == if push { TX_CREATE_PUSH } else { TX_CREATE_PULL } => {
                    if name == "_error" {
                        return self.fail(c, rejected());
                    }
                    let id = vals
                        .iter()
                        .skip(2)
                        .find_map(Value::as_f64)
                        .filter(|v| v.is_finite() && *v >= 0.0 && *v <= f64::from(u32::MAX));
                    let Some(id) = id else {
                        return self.fail(
                            c,
                            ClientError::Protocol("createStream gave no stream id".into()),
                        );
                    };
                    self.stream_id = id as u32;
                    self.shared.lock().stream_id = Some(self.stream_id);
                    self.start_stream(c);
                }
                _ => {}
            },
            "onStatus" => {
                if field("level") == "error" {
                    return self.fail(c, rejected());
                }
                let code = field("code");
                match (self.phase, code.as_str()) {
                    (Phase::Start, "NetStream.Publish.Start") if push => self.start_push(c),
                    (Phase::Start, "NetStream.Play.Start") if !push => {
                        self.phase = Phase::Streaming;
                        self.shared.enter(ClientState::Streaming, None);
                    }
                    (
                        Phase::Start | Phase::Streaming,
                        "NetStream.Play.Stop" | "NetStream.Play.Complete",
                    ) if !push => {
                        self.phase = Phase::Dead;
                        self.shared.fail(ClientError::Ended(code), false);
                        c.close();
                    }
                    _ => {}
                }
            }
            "close" => self.fail(c, ClientError::Disconnected("the server sent close".into())),
            _ => {}
        }
    }

    /// After `createStream`: `publish` or `play`.
    fn start_stream(&mut self, c: &Conn<Self>) {
        let sid = self.stream_id;
        let s = self.setup();
        let n = Value::from(s.url.stream.as_str());
        let resp = s.cfg.response_timeout;
        let buffer = s.cfg.buffer_length.as_millis().min(u128::from(u32::MAX)) as u32;
        let push = s.push.is_some();
        self.phase = Phase::Start;
        if push {
            self.shared
                .enter(ClientState::Negotiating, Some((resp, "publish response")));
            self.command(
                c,
                sid,
                &[
                    Value::from("publish"),
                    Value::Number(TX_PUBLISH),
                    Value::Null,
                    n,
                    Value::from("live"),
                ],
            );
        } else {
            self.shared
                .enter(ClientState::Negotiating, Some((resp, "play response")));
            self.command(
                c,
                sid,
                &[
                    Value::from("play"),
                    Value::Number(TX_PLAY),
                    Value::Null,
                    n,
                    Value::Number(-2000.0),
                ],
            );
            // Set Buffer Length: event 3, stream id, milliseconds.
            let mut p = 3u16.to_be_bytes().to_vec();
            p.extend_from_slice(&sid.to_be_bytes());
            p.extend_from_slice(&buffer.to_be_bytes());
            self.send(c, &Message::new(2, chunk::USER_CONTROL, 0, 0, p));
        }
    }

    /// The server accepted the publish: subscribe to the hub path.
    fn start_push(&mut self, c: &Conn<Self>) {
        let Some((hub, path)) = self.setup().push.clone() else {
            return;
        };
        self.phase = Phase::Streaming;
        self.shared.enter(ClientState::Streaming, None);
        let cfg = &self.shared.setup.cfg;
        let egress = Egress {
            conn: c.clone(),
            shared: Arc::downgrade(&self.shared),
            stream_id: self.stream_id,
            chunk_size: self.shared.setup.chunk_size(),
            enc: Encoder::new(cfg.encoder.clone()),
            started: false,
            timeline: Timeline::new(),
            max_queue: cfg.max_write_queue,
            stream: self.shared.setup.url.stream.clone(),
        };
        let backlog = c.clone();
        let sink = Dropper::new(
            egress,
            move || backlog.queued_bytes(),
            cfg.write_queue_limit,
        );
        let mut opts = SubscribeOptions::new(PeerInfo::new("rtmp", Some(c.peer_addr()), ""));
        opts.start_wait = cfg.source_wait;
        match hub.subscribe(&path, sink, opts) {
            Ok(sub) => self.sub = Some(sub),
            Err(e) => self.fail(c, ClientError::Hub(e)),
        }
    }
}

impl Handler for Session {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.shared.touch();
        match self.phase {
            Phase::Dead => {}
            Phase::Handshake => self.handshake(c, data),
            _ => self.chunks(c, data),
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<only::Error>) {
        self.phase = Phase::Dead;
        self.sub = None;
        let publisher = self.publisher.take();
        self.shared.fail(
            ClientError::Disconnected(match err {
                Some(e) => e.to_string(),
                None => "closed by the server".into(),
            }),
            false,
        );
        drop(publisher);
    }
}

fn command_bytes(chunk_size: usize, stream_id: u32, vals: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    chunk::write_message(
        &mut out,
        &Message::new(3, chunk::COMMAND_AMF0, stream_id, 0, amf::encode(vals)),
        chunk_size,
    );
    out
}

/// A hub sink publishing to the server: FLV tag bodies as RTMP messages.
struct Egress {
    conn: Conn<Session>,
    shared: Weak<Shared>,
    stream_id: u32,
    chunk_size: usize,
    enc: Encoder,
    started: bool,
    timeline: Timeline,
    max_queue: usize,
    stream: String,
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
            self.end(ClientError::Disconnected("send failed".into()), false);
        }
    }

    fn end(&self, err: ClientError, graceful: bool) {
        match self.shared.upgrade() {
            Some(s) => s.fail(err, graceful),
            None => self.conn.close(),
        }
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
            let (msg_type, body) = match tag {
                flv::TAG_AUDIO => (chunk::AUDIO, body),
                flv::TAG_VIDEO => (chunk::VIDEO, body),
                _ => {
                    // A publisher's metadata goes through @setDataFrame.
                    let mut b = Vec::with_capacity(body.len() + 16);
                    amf::write_string(&mut b, "@setDataFrame");
                    b.extend_from_slice(&body);
                    (chunk::DATA_AMF0, b)
                }
            };
            self.write(msg_type, flv::ms(ts) as u32, body);
        }
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        if self.conn.queued_bytes() > self.max_queue {
            self.end(ClientError::WriteQueueFull, false);
            return;
        }
        let Some((tag, body)) = self.enc.packet(pkt) else {
            return;
        };
        let ts = self.timeline.stamp(tag == flv::TAG_VIDEO, pkt.dts);
        let msg_type = if tag == flv::TAG_AUDIO {
            chunk::AUDIO
        } else {
            chunk::VIDEO
        };
        self.write(msg_type, flv::ms(ts) as u32, body);
    }

    fn on_close(&mut self, err: HubError) {
        // The source left: unpublish, then close once that is sent.
        let mut out = command_bytes(
            self.chunk_size,
            0,
            &[
                Value::from("FCUnpublish"),
                Value::Number(0.0),
                Value::Null,
                Value::from(self.stream.as_str()),
            ],
        );
        out.extend(command_bytes(
            self.chunk_size,
            0,
            &[
                Value::from("deleteStream"),
                Value::Number(0.0),
                Value::Null,
                Value::Number(f64::from(self.stream_id)),
            ],
        ));
        let _ = self.conn.send_owned(out);
        self.end(ClientError::Hub(err), true);
    }
}

/// A client driven without an engine, for the fuzzer: the acceptor to open on a detached
/// connection and the handle (every timeout disabled; a push finds no source).
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn detached(push: bool, hub: &Hub) -> (Dialer, RtmpClient) {
    let cfg = RtmpClientConfig {
        connect_timeout: Duration::ZERO,
        handshake_timeout: Duration::ZERO,
        response_timeout: Duration::ZERO,
        idle_timeout: Duration::ZERO,
        source_wait: None,
        max_message_size: 1 << 20,
        ..RtmpClientConfig::default()
    };
    let url = RtmpUrl::parse("rtmp://127.0.0.1/live/s").unwrap_or_else(|_| unreachable!());
    let addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT));
    let (push_to, publisher) = if push {
        (Some((hub.clone(), "src".to_owned())), None)
    } else {
        (None, hub.reserve("pulled", PeerInfo::default()).ok())
    };
    let shared = Shared::new(
        Setup {
            url,
            addr,
            cfg,
            push: push_to,
        },
        publisher,
    );
    (
        Dialer {
            shared: shared.clone(),
        },
        RtmpClient { shared },
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{av::Codec, flv::Demuxer};
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::atomic::AtomicUsize,
    };

    const SAMPLE: &[u8] = include_bytes!("../../testdata/h264_aac.flv");

    #[test]
    fn urls() {
        let u = RtmpUrl::parse("rtmp://example.com/live/s").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.app.as_str(), u.stream.as_str()),
            ("example.com", 1935, "live", "s")
        );
        assert_eq!(u.tc_url, "rtmp://example.com/live");
        assert_eq!(u.query(), "");
        let u = RtmpUrl::parse("rtmp://10.0.0.1:1940/app/inst/name?token=a/b").unwrap();
        assert_eq!((u.port, u.app.as_str()), (1940, "app/inst"));
        assert_eq!(u.stream, "name?token=a/b");
        assert_eq!(u.query(), "token=a/b");
        assert_eq!(u.tc_url, "rtmp://10.0.0.1:1940/app/inst");
        assert_eq!(
            u.resolve().unwrap(),
            "10.0.0.1:1940".parse::<SocketAddr>().unwrap()
        );
        let u = RtmpUrl::parse("RTMP://[::1]:19350/live/s/").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 19350));
        assert_eq!(u.tc_url, "RTMP://[::1]:19350/live");
        assert_eq!(u.resolve().unwrap(), "[::1]:19350".parse().unwrap());
        for bad in [
            "rtmps://h/live/s",
            "http://h/live/s",
            "h/live/s",
            "rtmp://h/live",
            "rtmp://h/",
            "rtmp:///live/s",
            "rtmp://h:99999/live/s",
            "rtmp://h:x/live/s",
            "rtmp://[::1/live/s",
            "rtmp://u:p@h/live/s",
            "rtmp://h//s",
        ] {
            assert!(
                matches!(RtmpUrl::parse(bad), Err(ClientError::BadUrl(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn defaults_are_bounded() {
        let c = RtmpClientConfig::default();
        assert_eq!(c.connect_timeout, Duration::from_secs(10));
        assert_eq!(c.handshake_timeout, Duration::from_secs(10));
        assert_eq!(c.response_timeout, Duration::from_secs(10));
        assert_eq!(c.idle_timeout, Duration::from_secs(30));
        assert_eq!(c.max_message_size, 16 << 20);
        assert!(c.write_queue_limit < c.max_write_queue);
        assert_eq!(period(&c), Some(Duration::from_millis(2500)));
    }

    fn engine() -> Engine {
        let e = Engine::builder().client_threads(1).build().unwrap();
        e.start().unwrap();
        e
    }

    /// A scripted blocking RTMP server, one connection.
    struct Server {
        s: TcpStream,
        r: ChunkReader,
        pending: Vec<Message>,
        chunk_size: usize,
    }

    impl Server {
        fn accept(l: &TcpListener) -> Server {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut c0c1 = vec![0u8; 1 + handshake::SIZE];
            s.read_exact(&mut c0c1).unwrap();
            // The client's digest handshake, answered by the server side of it.
            s.write_all(&handshake::server_reply(&c0c1).unwrap())
                .unwrap();
            let mut c2 = vec![0u8; handshake::SIZE];
            s.read_exact(&mut c2).unwrap();
            Server {
                s,
                r: ChunkReader::new(),
                pending: Vec::new(),
                chunk_size: 128,
            }
        }

        fn next(&mut self) -> Option<Message> {
            loop {
                if !self.pending.is_empty() {
                    return Some(self.pending.remove(0));
                }
                let mut b = vec![0u8; 65536];
                let n = self.s.read(&mut b).ok()?;
                if n == 0 {
                    return None;
                }
                self.pending.extend(self.r.feed(&b[..n]).unwrap());
            }
        }

        /// The next command, skipping other messages.
        fn command(&mut self) -> (Message, Vec<Value>) {
            loop {
                let m = self.next().expect("closed");
                if m.msg_type == chunk::COMMAND_AMF0 {
                    let v = amf::decode_all(&m.payload).unwrap();
                    return (m, v);
                }
            }
        }

        fn send(&mut self, m: &Message) {
            let mut out = Vec::new();
            chunk::write_message(&mut out, m, self.chunk_size);
            self.s.write_all(&out).unwrap();
        }

        fn reply(&mut self, sid: u32, vals: &[Value]) {
            self.send(&Message::new(
                3,
                chunk::COMMAND_AMF0,
                sid,
                0,
                amf::encode(vals),
            ));
        }

        fn status(&mut self, sid: u32, level: &str, code: &str) {
            self.reply(
                sid,
                &[
                    Value::from("onStatus"),
                    Value::Number(0.0),
                    Value::Null,
                    Value::object([
                        ("level", Value::from(level)),
                        ("code", Value::from(code)),
                        ("description", Value::from("scripted")),
                    ]),
                ],
            );
        }

        /// Answers `connect` (checked by `check`) with Window Ack Size `window` (0: none), Set
        /// Chunk Size 8192 and success.
        fn connect(&mut self, window: u32, check: impl FnOnce(&Value)) {
            let (_, v) = self.command();
            assert_eq!(v[0].as_str(), Some("connect"));
            assert_eq!(v[1].as_f64(), Some(1.0));
            check(&v[2]);
            assert_eq!(self.r.chunk_size(), 4096, "client's Set Chunk Size");
            if window > 0 {
                self.send(&chunk::control_u32(chunk::WINDOW_ACK_SIZE, window));
            }
            self.send(&chunk::control_u32(chunk::SET_CHUNK_SIZE, 8192));
            self.chunk_size = 8192;
            self.reply(
                0,
                &[
                    Value::from("_result"),
                    Value::Number(1.0),
                    Value::object([("fmsVer", Value::from("FMS/3,0,1,123"))]),
                    Value::object([
                        ("level", Value::from("status")),
                        ("code", Value::from("NetConnection.Connect.Success")),
                    ]),
                ],
            );
        }

        /// Reads until `createStream` and answers stream id 1.
        fn create_stream(&mut self) {
            loop {
                let (_, v) = self.command();
                if v[0].as_str() == Some("createStream") {
                    self.reply(
                        0,
                        &[
                            Value::from("_result"),
                            v[1].clone(),
                            Value::Null,
                            Value::Number(1.0),
                        ],
                    );
                    return;
                }
            }
        }
    }

    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn listener() -> (TcpListener, String) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("rtmp://{}/live/s?k=v", l.local_addr().unwrap());
        (l, url)
    }

    /// Tracks and packets of the sample, through the FLV decoder.
    fn sample() -> (Tracks, Vec<Packet>) {
        let mut dec = Decoder::new();
        let mut tracks = None;
        let mut pkts = Vec::new();
        for t in Demuxer::new().feed(SAMPLE).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) => pkts.push(p),
                }
            }
        }
        (tracks.unwrap(), pkts)
    }

    #[test]
    fn push_runs_the_publish_sequence_and_sends_the_stream() {
        let (l, url) = listener();
        let hub = Hub::default();
        let e = engine();
        let client = push(&e, &url, &hub, "src", RtmpClientConfig::default()).unwrap();
        let mut srv = Server::accept(&l);
        let tc = url.rsplit_once('/').unwrap().0.to_owned();
        srv.connect(5000, |o| {
            assert_eq!(o.get("app").and_then(Value::as_str), Some("live"));
            assert_eq!(o.get("tcUrl").and_then(Value::as_str), Some(tc.as_str()));
            assert_eq!(o.get("type").and_then(Value::as_str), Some("nonprivate"));
            assert!(
                o.get("flashVer")
                    .and_then(Value::as_str)
                    .unwrap()
                    .starts_with("FMLE")
            );
        });
        let names: Vec<String> = (0..3)
            .map(|_| srv.command().1[0].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["releaseStream", "FCPublish", "createStream"]);
        srv.reply(
            0,
            &[
                Value::from("_result"),
                Value::Number(4.0),
                Value::Null,
                Value::Number(1.0),
            ],
        );
        let (m, v) = srv.command();
        assert_eq!(v[0].as_str(), Some("publish"));
        assert_eq!(m.stream_id, 1);
        assert_eq!(v[3].as_str(), Some("s?k=v"));
        assert_eq!(v[4].as_str(), Some("live"));
        assert_eq!(client.state(), ClientState::Negotiating);
        srv.status(1, "status", "NetStream.Publish.Start");
        wait_for("the hub subscription", || {
            hub.stream_info("src").is_some_and(|s| s.subscribers == 1)
        });
        assert_eq!(client.state(), ClientState::Streaming);

        // The source publishes the sample; a ping on the way.
        let (tracks, pkts) = sample();
        let videos = pkts.iter().filter(|p| p.track == 0).count();
        let p = hub.publish("src", tracks, PeerInfo::default()).unwrap();
        for pkt in pkts {
            p.write(pkt);
        }
        srv.send(&chunk::user_control(6, 1234));
        let mut seen = Vec::new();
        let mut video = 0;
        let mut pong = false;
        while video < videos + 1 || !pong {
            let m = srv.next().expect("closed early");
            match m.msg_type {
                chunk::VIDEO => {
                    video += 1;
                    assert_eq!(m.stream_id, 1);
                }
                chunk::USER_CONTROL => {
                    assert_eq!(m.payload, [0, 7, 0, 0, 0x04, 0xd2]);
                    pong = true;
                }
                _ => {}
            }
            if seen.len() < 3 && m.stream_id == 1 {
                seen.push(m);
            }
        }
        // @setDataFrame onMetaData, then the sequence headers.
        assert_eq!(seen[0].msg_type, chunk::DATA_AMF0);
        let meta = amf::decode_all(&seen[0].payload).unwrap();
        assert_eq!(meta[0].as_str(), Some("@setDataFrame"));
        assert_eq!(meta[1].as_str(), Some("onMetaData"));
        assert_eq!(seen[1].msg_type, chunk::VIDEO);
        assert_eq!(seen[2].msg_type, chunk::AUDIO);
        // The source leaves: FCUnpublish, deleteStream, then the client closes.
        drop(p);
        let mut cmds = Vec::new();
        while let Some(m) = srv.next() {
            if m.msg_type == chunk::COMMAND_AMF0 {
                let v = amf::decode_all(&m.payload).unwrap();
                cmds.push(v[0].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(cmds, ["FCUnpublish", "deleteStream"]);
        wait_for("close", || client.is_closed());
        assert_eq!(
            client.error(),
            Some(ClientError::Hub(HubError::Unpublished))
        );
        e.shutdown();
    }

    #[test]
    fn pull_plays_into_the_hub_and_acknowledges() {
        let (l, url) = listener();
        let hub = Hub::default();
        let e = engine();
        let client = pull(&e, &url, &hub, "pulled", RtmpClientConfig::default()).unwrap();
        // Reserved at once: a second pull of the path fails right away.
        assert_eq!(
            pull(&e, &url, &hub, "pulled", RtmpClientConfig::default()).unwrap_err(),
            ClientError::Hub(HubError::StreamBusy)
        );
        assert!(hub.stream_info("pulled").unwrap().reserved);
        let mut srv = Server::accept(&l);
        srv.connect(1000, |o| {
            assert!(o.get("type").is_none());
            assert_eq!(
                o.get("flashVer").and_then(Value::as_str),
                Some("LNX 9,0,124,2")
            );
        });
        srv.create_stream();
        let (m, v) = srv.command();
        assert_eq!(v[0].as_str(), Some("play"));
        assert_eq!((m.stream_id, v[3].as_str()), (1, Some("s?k=v")));
        // Set Buffer Length: event 3, stream 1, 1000 ms.
        let buf = loop {
            let m = srv.next().unwrap();
            if m.msg_type == chunk::USER_CONTROL {
                break m.payload;
            }
        };
        assert_eq!(buf, [0, 3, 0, 0, 0, 1, 0, 0, 0x03, 0xe8]);
        srv.send(&chunk::user_control(0, 1));
        srv.status(1, "status", "NetStream.Play.Reset");
        srv.status(1, "status", "NetStream.Play.Start");
        wait_for("streaming", || client.state() == ClientState::Streaming);

        let count = Arc::new(AtomicUsize::new(0));
        struct Count(Arc<AtomicUsize>);
        impl Sink for Count {
            fn on_tracks(&mut self, _t: &Tracks) {}
            fn on_packet(&mut self, p: &Arc<Packet>) {
                if p.track == 0 {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let _sub = hub
            .subscribe(
                "pulled",
                Count(count.clone()),
                SubscribeOptions::new(PeerInfo::default()).wait(Duration::from_secs(5)),
            )
            .unwrap();
        // The sample: the first tags one by one, the rest in aggregates of four.
        let tags = Demuxer::new().feed(SAMPLE).unwrap();
        let (single, rest) = tags.split_at(10);
        for t in single {
            let mt = match t.tag_type {
                8 => chunk::AUDIO,
                9 => chunk::VIDEO,
                _ => chunk::DATA_AMF0,
            };
            srv.send(&Message::new(4, mt, 1, t.ts, t.body.clone()));
        }
        for group in rest.chunks(4) {
            let mut agg = Vec::new();
            for t in group {
                flv::write_tag(&mut agg, t.tag_type, t.ts, &t.body);
            }
            srv.send(&Message::new(4, chunk::AGGREGATE, 1, group[0].ts, agg));
        }
        let videos = sample().1.iter().filter(|p| p.track == 0).count();
        let deadline = Instant::now() + Duration::from_secs(3);
        while count.load(Ordering::Relaxed) != videos && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(count.load(Ordering::Relaxed), videos);
        let info = hub.stream_info("pulled").unwrap();
        assert_eq!(info.tracks[0].codec, Codec::H264);
        assert_eq!(info.tracks[1].codec, Codec::Aac);
        // The window was 1000 bytes: the client acknowledged.
        let mut acked = false;
        srv.s
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        while let Some(m) = srv.next() {
            if m.msg_type == chunk::ACK {
                acked = true;
                break;
            }
        }
        assert!(acked);
        // The server ends the stream.
        srv.status(1, "status", "NetStream.Play.Stop");
        wait_for("end", || client.is_closed());
        assert_eq!(
            client.error(),
            Some(ClientError::Ended("NetStream.Play.Stop".into()))
        );
        assert!(
            hub.stream_info("pulled")
                .is_none_or(|s| !s.publishing && !s.reserved)
        );
        e.shutdown();
    }

    #[test]
    fn refusals_carry_the_status_code() {
        let (l, url) = listener();
        let hub = Hub::default();
        let e = engine();
        // An error onStatus to publish.
        let client = push(&e, &url, &hub, "src", RtmpClientConfig::default()).unwrap();
        let mut srv = Server::accept(&l);
        srv.connect(0, |_| {});
        srv.create_stream();
        srv.command();
        srv.status(1, "error", "NetStream.Publish.BadName");
        wait_for("refusal", || client.is_closed());
        assert_eq!(
            client.error(),
            Some(ClientError::Rejected {
                code: "NetStream.Publish.BadName".into(),
                description: "scripted".into()
            })
        );
        srv.s
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        while srv.next().is_some() {}
        // _error to connect.
        let client = pull(&e, &url, &hub, "p", RtmpClientConfig::default()).unwrap();
        let mut srv = Server::accept(&l);
        srv.command();
        srv.reply(
            0,
            &[
                Value::from("_error"),
                Value::Number(1.0),
                Value::Null,
                Value::object([
                    ("level", Value::from("error")),
                    ("code", Value::from("NetConnection.Connect.Rejected")),
                    ("description", Value::from("no")),
                ]),
            ],
        );
        wait_for("refusal", || client.is_closed());
        assert!(matches!(
            client.error(),
            Some(ClientError::Rejected { code, .. }) if code == "NetConnection.Connect.Rejected"
        ));
        // The reserved path is free again.
        assert!(hub.stream_info("p").is_none_or(|s| !s.reserved));
        e.shutdown();
    }

    fn short(ms: u64) -> RtmpClientConfig {
        RtmpClientConfig {
            connect_timeout: Duration::from_millis(ms),
            handshake_timeout: Duration::from_millis(ms),
            response_timeout: Duration::from_millis(ms),
            idle_timeout: Duration::from_millis(ms),
            ..RtmpClientConfig::default()
        }
    }

    #[test]
    fn silent_servers_time_out() {
        let (l, url) = listener();
        let hub = Hub::default();
        let e = engine();
        // Accepts, never answers the handshake.
        let t = Instant::now();
        let client = push(&e, &url, &hub, "src", short(300)).unwrap();
        let (_s, _) = l.accept().unwrap();
        wait_for("handshake timeout", || client.is_closed());
        assert!(t.elapsed() >= Duration::from_millis(280));
        assert_eq!(client.error(), Some(ClientError::TimedOut("handshake")));
        // Answers the handshake, never the connect.
        let client = push(&e, &url, &hub, "src", short(300)).unwrap();
        let _srv = Server::accept(&l);
        wait_for("connect timeout", || client.is_closed());
        assert_eq!(
            client.error(),
            Some(ClientError::TimedOut("connect response"))
        );
        // A pull that streams, then goes silent.
        let client = pull(&e, &url, &hub, "p", short(300)).unwrap();
        let mut srv = Server::accept(&l);
        srv.connect(0, |_| {});
        srv.create_stream();
        srv.command();
        srv.status(1, "status", "NetStream.Play.Start");
        wait_for("streaming", || client.state() == ClientState::Streaming);
        wait_for("idle timeout", || client.is_closed());
        assert_eq!(client.error(), Some(ClientError::TimedOut("data")));
        // Nothing listening: refused.
        drop(l);
        let client = pull(&e, &url, &hub, "q", short(2000)).unwrap();
        wait_for("refused", || client.is_closed());
        assert!(matches!(
            client.error(),
            Some(ClientError::Connect(_) | ClientError::TimedOut("connect"))
        ));
        e.shutdown();
    }

    #[test]
    fn oversized_messages_and_bad_handshakes_close() {
        let (l, url) = listener();
        let hub = Hub::default();
        let e = engine();
        let cfg = RtmpClientConfig {
            max_message_size: 64 << 10,
            ..RtmpClientConfig::default()
        };
        let client = pull(&e, &url, &hub, "p", cfg.clone()).unwrap();
        let mut srv = Server::accept(&l);
        // One byte over the limit is refused as soon as its header arrives.
        srv.s
            .write_all(&[0x04, 0, 0, 0, 0x01, 0x00, 0x01, chunk::VIDEO, 1, 0, 0, 0])
            .unwrap();
        wait_for("close", || client.is_closed());
        assert!(matches!(client.error(), Some(ClientError::Protocol(_))));
        // The path is free as soon as the client says it is closed.
        assert!(
            hub.stream_info("p")
                .is_none_or(|s| !s.reserved && !s.publishing)
        );
        // At the limit is fine.
        let client = pull(&e, &url, &hub, "p", cfg).unwrap();
        let mut srv = Server::accept(&l);
        srv.connect(0, |_| {});
        srv.create_stream();
        srv.command();
        srv.status(1, "status", "NetStream.Play.Start");
        srv.send(&Message::new(6, chunk::VIDEO, 1, 0, vec![0x17; 64 << 10]));
        srv.send(&chunk::user_control(6, 9));
        loop {
            let m = srv.next().expect("closed");
            if m.msg_type == chunk::USER_CONTROL && m.payload[..2] == [0, 7] {
                break;
            }
        }
        assert!(!client.is_closed());
        client.close();
        assert!(client.is_closed());
        assert_eq!(client.error(), None);
        assert!(
            hub.stream_info("p")
                .is_none_or(|s| !s.reserved && !s.publishing)
        );
        // S0 with another version.
        let client = push(&e, &url, &hub, "src", RtmpClientConfig::default()).unwrap();
        let (mut s, _) = l.accept().unwrap();
        let mut c0c1 = vec![0u8; 1 + handshake::SIZE];
        s.read_exact(&mut c0c1).unwrap();
        s.write_all(&[6u8; 1 + 2 * handshake::SIZE]).unwrap();
        wait_for("close", || client.is_closed());
        assert_eq!(client.error(), Some(ClientError::Handshake));
        e.shutdown();
    }

    #[test]
    fn dropping_the_handle_closes() {
        let (l, url) = listener();
        let hub = Hub::default();
        let e = engine();
        let client = pull(&e, &url, &hub, "p", RtmpClientConfig::default()).unwrap();
        let mut srv = Server::accept(&l);
        srv.connect(0, |_| {});
        drop(client);
        assert!(hub.stream_info("p").is_none_or(|s| !s.reserved));
        while srv.next().is_some() {}
        e.shutdown();
    }
}
