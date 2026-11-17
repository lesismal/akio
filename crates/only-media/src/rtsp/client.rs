//! RTSP 1.0 client (RFC 2326) on a `only` engine: [`pull`] plays a remote stream into the hub,
//! [`push`] records a hub stream to a remote server. Media travels as RTP ([`crate::rtp`]),
//! interleaved on the RTSP connection (`RTP/AVP/TCP`, [`RtspTransport::Tcp`], the default) or
//! over UDP unicast (`RTP/AVP`, [`RtspTransport::Udp`]).
//!
//! [`pull`] reserves the hub path at once ([`Hub::reserve`]), then sends OPTIONS, DESCRIBE,
//! one SETUP per track RTP carries here and PLAY; the stream goes live in the hub when the
//! parameter sets of its video tracks are known (from the SDP's `sprop-*`, or in band), as for
//! an RTSP publisher of [`RtspServer`](super::RtspServer). [`push`] waits for the hub stream's
//! tracks, then sends OPTIONS, ANNOUNCE (an SDP of the tracks), SETUP with `mode=record` and
//! RECORD, and sends the stream from its cached GOP on, with RTCP sender reports; over TCP it is
//! cut back to keyframes ([`Dropper`]) when the server reads too slowly and disconnected when it
//! falls further behind.
//!
//! `rtsp://user:pass@host:port/path` authenticates with Digest (MD5) or Basic, whichever the
//! server's `401` offers (Digest first). Sessions are kept alive with `GET_PARAMETER` (or
//! `OPTIONS` when the server does not list it), at half the session timeout the server
//! announces. Every exchange is bounded in time: the connect, each response (also a response
//! trickled a byte at a time), the whole handshake and, while playing, the media
//! ([`RtspClientConfig`]).
//!
//! ```no_run
//! use only::Engine;
//! use only_media::{Hub, rtsp::client::{self, RtspClientConfig}};
//!
//! // `udp_client_threads` is needed for `RtspTransport::Udp` only.
//! let engine = Engine::builder().client_threads(1).udp_client_threads(1).build().unwrap();
//! engine.start().unwrap();
//! let hub = Hub::default();
//! let cam = client::pull(&engine, "rtsp://admin:pw@192.0.2.10/stream1", &hub, "live/cam",
//!     RtspClientConfig::default()).unwrap();
//! let out = client::push(&engine, "rtsp://198.51.100.7:8554/cam", &hub, "live/cam",
//!     RtspClientConfig::default()).unwrap();
//! // ... `cam.close()` / `out.close()`, or drop them.
//! ```
//!
//! [`pull`] and [`push`] block their caller until the session plays or records (or fails):
//! call them from a thread of your own, never from an I/O thread callback. A host name in the
//! URL is resolved there with the system resolver (`ToSocketAddrs`); an IP literal, or
//! [`RtspClientConfig::addr`], needs no lookup.
//!
//! Left out: RTSPS and HTTP tunnelling, multicast, redirects, RTCP-based A/V sync (each track's
//! times start at its first packet's arrival, as for RTSP publishers) and reconnecting.

use std::{
    fmt,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Acceptor, Conn, Engine, Handler, UdpBinding};

use super::{
    Recorder,
    auth::Challenge,
    describe_sdp,
    message::{self, Frame, MAX_BODY, MAX_HEAD, Parser, Reply, Response, Transport},
};
use crate::{
    av::{Packet, Track, Tracks},
    hub::{Dropper, Hub, HubError, PeerInfo, Sink, SubscribeOptions, Subscription, Timeline},
    rtp::{self, Packetizer},
    sdp,
};

/// Most tracks a client sets up; media descriptions past it are ignored.
const MAX_TRACKS: usize = 16;
/// Longest session id taken from a server.
const MAX_SESSION_ID: usize = 256;

/// How RTP travels between an RTSP client and its server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RtspTransport {
    /// Interleaved on the RTSP connection (`RTP/AVP/TCP`): one connection, through any NAT or
    /// firewall that lets RTSP through. The default.
    #[default]
    Tcp,
    /// UDP unicast (`RTP/AVP`): a pair of UDP sockets per track, bound on the engine
    /// ([`Engine::bind_udp`], which needs `EngineBuilder::udp_client_threads` or a UDP
    /// listener), on the local address of the RTSP connection.
    Udp,
}

/// Configures an RTSP client ([`pull`], [`push`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RtspClientConfig {
    /// How RTP travels (default [`RtspTransport::Tcp`]).
    pub transport: RtspTransport,
    /// Connect here rather than to the URL's host (which then only names the server in the
    /// requests); skips the name lookup.
    pub addr: Option<SocketAddr>,
    /// Time allowed for the TCP connect. Default 10 s; `Duration::ZERO` leaves it to the
    /// engine's `Config::connect_timeout`.
    pub connect_timeout: Duration,
    /// Time allowed for each response, from its request (and for any message once its first
    /// byte arrived: a server trickling one is dropped). The whole handshake is bounded by
    /// `connect_timeout` plus 16 times this. Default 10 s; `Duration::ZERO` disables both.
    pub response_timeout: Duration,
    /// [`pull`]: a session that receives no RTP or RTCP for this long ends with
    /// [`ClientError::Timeout`]. Default 10 s; `Duration::ZERO` disables it.
    pub idle_timeout: Duration,
    /// Interval of the keep-alive requests (`GET_PARAMETER`, or `OPTIONS` when the server
    /// does not list `GET_PARAMETER`). `None` (the default): half the timeout of the server's
    /// `Session` header, else 30 s. At least one second.
    pub keepalive: Option<Duration>,
    /// Bound of a response head (default [`message::MAX_HEAD`], 16 KiB).
    pub max_head: usize,
    /// Bound of a response body, such as a DESCRIBE's SDP (default [`message::MAX_BODY`],
    /// 256 KiB).
    pub max_body: usize,
    /// [`push`] over TCP: queued bytes above which packets are dropped (video to the next
    /// keyframe). Default 2 MiB.
    pub write_queue_limit: usize,
    /// [`push`] over TCP: queued bytes above which the session ends with
    /// [`ClientError::WriteQueueFull`]. Default 16 MiB.
    pub max_write_queue: usize,
    /// [`push`]: interval of the RTCP sender reports (default 3 s).
    pub sender_report_interval: Duration,
    /// The `User-Agent` header (default `only-media`).
    pub user_agent: String,
    /// [`push`]: how long to wait for the hub stream to be live (default 10 s).
    pub push_wait: Duration,
}

impl Default for RtspClientConfig {
    fn default() -> Self {
        RtspClientConfig {
            transport: RtspTransport::Tcp,
            addr: None,
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            keepalive: None,
            max_head: MAX_HEAD,
            max_body: MAX_BODY,
            write_queue_limit: 2 << 20,
            max_write_queue: 16 << 20,
            sender_report_interval: Duration::from_secs(3),
            user_agent: "only-media".to_owned(),
            push_wait: Duration::from_secs(10),
        }
    }
}

/// Why an RTSP client could not start, or why its session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientError {
    /// The URL is malformed or not `rtsp://` (`rtsps://` is not supported).
    Url(String),
    /// The host name did not resolve.
    Resolve(String),
    /// The TCP connect failed.
    Connect(String),
    /// A local I/O error (binding the UDP sockets).
    Io(String),
    /// What timed out: `"connect"`, `"response"`, `"handshake"` or `"media"`.
    Timeout(&'static str),
    /// The server refused a request.
    Status {
        /// The request's method.
        method: &'static str,
        /// The status code.
        status: u16,
        /// The reason phrase.
        reason: String,
    },
    /// The server asks for credentials and the URL has none, or refused them.
    Unauthorized,
    /// The stream has no track RTP carries here ([`rtp::supported`]).
    NoTracks,
    /// The server broke the protocol (malformed message, unusable SDP or transport, oversized
    /// head or body), or the pushed stream changed its tracks.
    Protocol(String),
    /// [`push`] over TCP: the server read too slowly
    /// ([`RtspClientConfig::max_write_queue`]).
    WriteQueueFull,
    /// The hub refused the path, or the pushed stream ended.
    Hub(HubError),
    /// The connection closed.
    Closed,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Url(e) => write!(f, "bad RTSP URL: {e}"),
            ClientError::Resolve(e) => write!(f, "cannot resolve the RTSP server: {e}"),
            ClientError::Connect(e) => write!(f, "cannot connect to the RTSP server: {e}"),
            ClientError::Io(e) => write!(f, "RTSP client I/O error: {e}"),
            ClientError::Timeout(what) => write!(f, "RTSP {what} timed out"),
            ClientError::Status {
                method,
                status,
                reason,
            } => write!(f, "RTSP {method} refused: {status} {reason}"),
            ClientError::Unauthorized => f.write_str("RTSP authentication failed"),
            ClientError::NoTracks => f.write_str("no RTSP track this client can carry"),
            ClientError::Protocol(e) => write!(f, "RTSP protocol error: {e}"),
            ClientError::WriteQueueFull => f.write_str("RTSP server reads too slowly"),
            ClientError::Hub(e) => write!(f, "hub: {e}"),
            ClientError::Closed => f.write_str("RTSP connection closed"),
        }
    }
}

impl std::error::Error for ClientError {}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ---- URLs ----------------------------------------------------------------------------------

/// An `rtsp://` URL split for a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Url {
    /// The host, without the brackets of an IPv6 literal.
    pub(crate) host: String,
    /// The port (554 when absent).
    pub(crate) port: u16,
    /// The user of the userinfo, percent-decoded.
    pub(crate) user: Option<String>,
    /// The password of the userinfo, percent-decoded.
    pub(crate) pass: Option<String>,
    /// The URL requests name: without the userinfo.
    pub(crate) request: String,
}

fn pct_decode(s: &str) -> Result<String, ClientError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| ClientError::Url("bad percent-encoding".into()))?;
            out.push(h);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ClientError::Url("userinfo is not UTF-8".into()))
}

/// Whether `s` can go into a request line or header as is.
fn clean(s: &str) -> bool {
    !s.bytes().any(|b| b <= b' ' || b == 0x7f)
}

impl Url {
    pub(crate) fn parse(s: &str) -> Result<Url, ClientError> {
        let bad = |e: &str| ClientError::Url(e.to_owned());
        if !clean(s) {
            return Err(bad("spaces or control characters"));
        }
        let (scheme, rest) = s.split_once("://").ok_or_else(|| bad("no scheme"))?;
        match scheme.to_ascii_lowercase().as_str() {
            "rtsp" => {}
            "rtsps" => return Err(bad("rtsps:// is not supported")),
            _ => return Err(bad("not an rtsp:// URL")),
        }
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
            let (h, after) = r.split_once(']').ok_or_else(|| bad("unclosed '['"))?;
            h.parse::<std::net::Ipv6Addr>()
                .map_err(|_| bad("bad IPv6 address"))?;
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or_else(|| bad("bad port"))?),
            };
            (h, port)
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        if host.is_empty() {
            return Err(bad("no host"));
        }
        let port = match port {
            None | Some("") => 554,
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| bad("bad port"))?,
        };
        let (user, pass) = match userinfo {
            None => (None, None),
            Some(u) => match u.split_once(':') {
                Some((u, p)) => (Some(pct_decode(u)?), Some(pct_decode(p)?)),
                None => (Some(pct_decode(u)?), None),
            },
        };
        Ok(Url {
            host: host.to_owned(),
            port,
            user,
            pass,
            request: format!("rtsp://{hostport}{path}"),
        })
    }

    fn resolve(&self, cfg: &RtspClientConfig) -> Result<SocketAddr, ClientError> {
        if let Some(a) = cfg.addr {
            return Ok(a);
        }
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, self.port));
        }
        (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| ClientError::Resolve(e.to_string()))?
            .next()
            .ok_or_else(|| ClientError::Resolve(format!("{}: no address", self.host)))
    }
}

/// Resolves the control `control` of an SDP against `base` the way RTSP servers expect
/// (appended as a path segment, before any query; absolute controls as they are).
pub(crate) fn join(base: &str, control: &str) -> String {
    let lc = control.to_ascii_lowercase();
    if lc.starts_with("rtsp://") || lc.starts_with("rtsps://") {
        return control.to_owned();
    }
    if control.is_empty() || control == "*" {
        return base.to_owned();
    }
    let (b, q) = base
        .split_once('?')
        .map_or((base, None), |(b, q)| (b, Some(q)));
    let mut s = format!(
        "{}/{}",
        b.trim_end_matches('/'),
        control.trim_start_matches('/')
    );
    if let Some(q) = q {
        s.push('?');
        s.push_str(q);
    }
    s
}

// ---- the sans-IO session -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Options,
    Describe,
    Announce,
    /// Waiting for [`Machine::set_ports`].
    Ports,
    Setup,
    Play,
    Record,
    Live,
}

/// A track to set up.
#[derive(Debug, Clone)]
struct Plan {
    /// The SETUP URL.
    control: String,
    /// Play: the SDP media index. Record: the hub track index.
    media: usize,
    /// Interleaved RTP and RTCP channels.
    channels: (u8, u8),
    client_ports: Option<(u16, u16)>,
    server_ports: Option<(u16, u16)>,
}

#[derive(Debug)]
struct Pending {
    cseq: u32,
    method: &'static str,
    uri: String,
    headers: Vec<(&'static str, String)>,
    body: Option<Vec<u8>>,
    at: Instant,
}

/// What the session asks of its driver.
#[derive(Debug)]
pub(crate) enum Event {
    /// Bytes to write to the connection.
    Send(Vec<u8>),
    /// Play: the DESCRIBE's media descriptions (those not set up are emptied).
    Described(Vec<sdp::Media>),
    /// UDP: bind this many RTP/RTCP port pairs and call [`Machine::set_ports`].
    NeedPorts(usize),
    /// PLAY or RECORD succeeded.
    Live,
    /// An interleaved frame of a track (`media` as in [`Plan::media`]).
    Media {
        media: usize,
        rtcp: bool,
        data: Vec<u8>,
    },
    /// The session failed.
    Fail(ClientError),
}

/// The client's RTSP session, sans-IO: [`feed`](Self::feed) it what the connection reads; it
/// answers with [`Event`]s.
pub(crate) struct Machine {
    record: bool,
    tcp: bool,
    url: Url,
    user_agent: String,
    parser: Parser,
    cseq: u32,
    pending: Option<Pending>,
    step: Step,
    challenge: Option<Challenge>,
    nc: u32,
    auth_tries: u8,
    /// Aggregate URL (PLAY, RECORD, keep-alives, TEARDOWN).
    aggregate: String,
    plans: Vec<Plan>,
    next_setup: usize,
    session: Option<String>,
    session_timeout: Option<Duration>,
    get_parameter: bool,
    announce: Vec<u8>,
    /// Since when part of a message is buffered without a message completing.
    partial_since: Option<Instant>,
}

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Machine")
            .field("url", &self.url.request)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl Machine {
    fn new(url: Url, record: bool, cfg: &RtspClientConfig) -> Machine {
        Machine {
            record,
            tcp: cfg.transport == RtspTransport::Tcp,
            aggregate: url.request.clone(),
            url,
            user_agent: cfg.user_agent.replace(['\r', '\n'], ""),
            parser: Parser::client(cfg.max_head, cfg.max_body),
            cseq: 0,
            pending: None,
            step: Step::Options,
            challenge: None,
            nc: 0,
            auth_tries: 0,
            plans: Vec::new(),
            next_setup: 0,
            session: None,
            session_timeout: None,
            get_parameter: false,
            announce: Vec::new(),
            partial_since: None,
        }
    }

    /// A session playing `url`.
    pub(crate) fn play(url: Url, cfg: &RtspClientConfig) -> Machine {
        Machine::new(url, false, cfg)
    }

    /// A session recording `tracks` to `url`.
    pub(crate) fn record(
        url: Url,
        tracks: &Tracks,
        cfg: &RtspClientConfig,
    ) -> Result<Machine, ClientError> {
        let mut m = Machine::new(url, true, cfg);
        let s = describe_sdp(tracks);
        for (i, t) in tracks.iter().enumerate() {
            if m.plans.len() == MAX_TRACKS {
                break;
            }
            if rtp::supported(t.codec) && sdp::track_media(t, 0, "").is_some() {
                let k = m.plans.len() as u8;
                m.plans.push(Plan {
                    control: join(&m.url.request, &format!("trackID={i}")),
                    media: i,
                    channels: (2 * k, 2 * k + 1),
                    client_ports: None,
                    server_ports: None,
                });
            }
        }
        if m.plans.is_empty() {
            return Err(ClientError::NoTracks);
        }
        m.announce = s.to_string().into_bytes();
        Ok(m)
    }

    fn encode(&mut self, p: &Pending) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut s = format!(
            "{} {} RTSP/1.0\r\nCSeq: {}\r\nUser-Agent: {}\r\n",
            p.method, p.uri, p.cseq, self.user_agent
        );
        if let (Some(ch), Some(user)) = (&self.challenge, &self.url.user) {
            self.nc += 1;
            let pass = self.url.pass.as_deref().unwrap_or("");
            let _ = write!(
                s,
                "Authorization: {}\r\n",
                ch.authorization(user, pass, p.method, &p.uri, self.nc)
            );
        }
        if let Some(id) = &self.session {
            let _ = write!(s, "Session: {id}\r\n");
        }
        for (n, v) in &p.headers {
            let _ = write!(s, "{n}: {}\r\n", v.replace(['\r', '\n'], ""));
        }
        if let Some(b) = &p.body {
            let _ = write!(
                s,
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n",
                b.len()
            );
        }
        s.push_str("\r\n");
        let mut out = s.into_bytes();
        if let Some(b) = &p.body {
            out.extend_from_slice(b);
        }
        out
    }

    fn request(
        &mut self,
        method: &'static str,
        uri: String,
        headers: Vec<(&'static str, String)>,
        body: Option<Vec<u8>>,
        now: Instant,
        out: &mut Vec<Event>,
    ) {
        self.cseq += 1;
        let p = Pending {
            cseq: self.cseq,
            method,
            uri,
            headers,
            body,
            at: now,
        };
        out.push(Event::Send(self.encode(&p)));
        self.pending = Some(p);
    }

    /// Sends the first request (OPTIONS).
    pub(crate) fn start(&mut self, now: Instant, out: &mut Vec<Event>) {
        self.step = Step::Options;
        let uri = self.url.request.clone();
        self.request("OPTIONS", uri, Vec::new(), None, now, out);
    }

    /// The tracks being set up: (play: SDP media index, record: hub track index).
    pub(crate) fn plan_media(&self) -> Vec<usize> {
        self.plans.iter().map(|p| p.media).collect()
    }

    /// UDP: the RTP/RTCP ports bound for each track, in order; sends the first SETUP.
    pub(crate) fn set_ports(&mut self, ports: &[(u16, u16)], now: Instant, out: &mut Vec<Event>) {
        if self.step != Step::Ports || ports.len() != self.plans.len() {
            return;
        }
        for (p, &ports) in self.plans.iter_mut().zip(ports) {
            p.client_ports = Some(ports);
        }
        self.step = Step::Setup;
        self.setup(now, out);
    }

    fn setup(&mut self, now: Instant, out: &mut Vec<Event>) {
        let Some(p) = self.plans.get(self.next_setup) else {
            return;
        };
        let t = Transport {
            tcp: self.tcp,
            interleaved: self.tcp.then_some(p.channels),
            client_port: if self.tcp { None } else { p.client_ports },
            mode: self.record.then(|| "record".to_owned()),
            ..Transport::default()
        };
        let uri = p.control.clone();
        self.request(
            "SETUP",
            uri,
            vec![("Transport", t.to_string())],
            None,
            now,
            out,
        );
    }

    /// The session's keep-alive interval.
    pub(crate) fn keepalive_every(&self, cfg: &RtspClientConfig) -> Duration {
        cfg.keepalive
            .unwrap_or_else(|| {
                self.session_timeout
                    .map_or(Duration::from_secs(30), |t| t / 2)
            })
            .max(Duration::from_secs(1))
    }

    /// Sends a keep-alive when live and no request is outstanding.
    pub(crate) fn keepalive(&mut self, now: Instant, out: &mut Vec<Event>) {
        if self.step != Step::Live || self.pending.is_some() {
            return;
        }
        let method = if self.get_parameter {
            "GET_PARAMETER"
        } else {
            "OPTIONS"
        };
        let uri = self.aggregate.clone();
        self.request(method, uri, Vec::new(), None, now, out);
    }

    /// The TEARDOWN to send when closing a session the server knows.
    pub(crate) fn teardown(&mut self) -> Option<Vec<u8>> {
        self.session.as_ref()?;
        self.cseq += 1;
        let p = Pending {
            cseq: self.cseq,
            method: "TEARDOWN",
            uri: self.aggregate.clone(),
            headers: Vec::new(),
            body: None,
            at: Instant::now(),
        };
        Some(self.encode(&p))
    }

    /// A response or message overdue at `now`.
    pub(crate) fn check(&self, now: Instant, timeout: Duration) -> Option<ClientError> {
        if timeout.is_zero() {
            return None;
        }
        let late = |t: Instant| now.saturating_duration_since(t) >= timeout;
        (self.pending.as_ref().is_some_and(|p| late(p.at)) || self.partial_since.is_some_and(late))
            .then_some(ClientError::Timeout("response"))
    }

    /// UDP: the server's RTP and RTCP ports of each track, in order.
    pub(crate) fn server_ports(&self) -> Vec<Option<(u16, u16)>> {
        self.plans.iter().map(|p| p.server_ports).collect()
    }

    /// TCP: the interleaved channels of each track, in order.
    pub(crate) fn channels(&self) -> Vec<(u8, u8)> {
        self.plans.iter().map(|p| p.channels).collect()
    }

    /// Feeds what the connection read.
    pub(crate) fn feed(&mut self, data: &[u8], now: Instant, out: &mut Vec<Event>) {
        let mut frames = Vec::new();
        let res = self.parser.feed(data, &mut frames);
        let progressed = !frames.is_empty();
        for f in frames {
            match f {
                Frame::Reply(r) => self.reply(r, now, out),
                Frame::Interleaved { channel, data } => {
                    if let Some(p) = self
                        .plans
                        .iter()
                        .find(|p| p.channels.0 == channel || p.channels.1 == channel)
                    {
                        out.push(Event::Media {
                            media: p.media,
                            rtcp: channel == p.channels.1 && channel != p.channels.0,
                            data,
                        });
                    }
                }
                Frame::Request(req) => {
                    // A server's own request (keep-alive, announce of a change): acknowledge
                    // the harmless ones.
                    let st = match req.method.as_str() {
                        "OPTIONS" | "GET_PARAMETER" | "SET_PARAMETER" => 200,
                        _ => 501,
                    };
                    out.push(Event::Send(Response::new(st).encode(req.cseq())));
                }
                _ => {}
            }
        }
        if let Err(e) = res {
            out.push(Event::Fail(ClientError::Protocol(e.to_string())));
            return;
        }
        self.partial_since = if !self.parser.pending() {
            None
        } else if progressed || self.partial_since.is_none() {
            Some(now)
        } else {
            self.partial_since
        };
    }

    fn refused(&self, method: &'static str, r: &Reply) -> Event {
        Event::Fail(ClientError::Status {
            method,
            status: r.status,
            reason: r.reason.clone(),
        })
    }

    fn reply(&mut self, r: Reply, now: Instant, out: &mut Vec<Event>) {
        let Some(p) = self.pending.take() else {
            return;
        };
        if let Some(c) = r.cseq() {
            if c.trim().parse::<u32>().ok() != Some(p.cseq) {
                // A late answer to something else: still waiting.
                self.pending = Some(p);
                return;
            }
        }
        if r.status == 401 {
            let ch = Challenge::pick(r.headers_named("www-authenticate"));
            match ch {
                Some(ch) if self.url.user.is_some() && self.auth_tries < 2 => {
                    self.auth_tries += 1;
                    self.challenge = Some(ch);
                    self.nc = 0;
                    self.request(p.method, p.uri, p.headers, p.body, now, out);
                }
                _ => out.push(Event::Fail(ClientError::Unauthorized)),
            }
            return;
        }
        self.auth_tries = 0;
        let ok = (200..300).contains(&r.status);
        match self.step {
            Step::Options => {
                if let Some(public) = r.header("public") {
                    self.get_parameter = public
                        .split(',')
                        .any(|m| m.trim().eq_ignore_ascii_case("GET_PARAMETER"));
                }
                let uri = self.url.request.clone();
                if self.record {
                    self.step = Step::Announce;
                    let body = self.announce.clone();
                    self.request("ANNOUNCE", uri, Vec::new(), Some(body), now, out);
                } else {
                    self.step = Step::Describe;
                    let h = vec![("Accept", "application/sdp".to_owned())];
                    self.request("DESCRIBE", uri, h, None, now, out);
                }
            }
            Step::Describe => {
                if !ok {
                    out.push(self.refused("DESCRIBE", &r));
                    return;
                }
                self.described(&r, now, out);
            }
            Step::Announce => {
                if !ok {
                    out.push(self.refused("ANNOUNCE", &r));
                    return;
                }
                self.begin_setup(now, out);
            }
            Step::Setup => {
                if !ok {
                    out.push(self.refused("SETUP", &r));
                    return;
                }
                if let Err(e) = self.set_up(&r) {
                    out.push(Event::Fail(e));
                    return;
                }
                self.next_setup += 1;
                if self.next_setup < self.plans.len() {
                    self.setup(now, out);
                } else {
                    let (step, method) = if self.record {
                        (Step::Record, "RECORD")
                    } else {
                        (Step::Play, "PLAY")
                    };
                    self.step = step;
                    let uri = self.aggregate.clone();
                    let h = vec![("Range", "npt=0.000-".to_owned())];
                    self.request(method, uri, h, None, now, out);
                }
            }
            Step::Play | Step::Record => {
                if !ok {
                    let m = if self.record { "RECORD" } else { "PLAY" };
                    out.push(self.refused(m, &r));
                    return;
                }
                self.step = Step::Live;
                out.push(Event::Live);
            }
            Step::Live => {
                if r.status == 454 {
                    out.push(self.refused(p.method, &r));
                } else if !ok && p.method == "GET_PARAMETER" {
                    self.get_parameter = false;
                }
            }
            Step::Ports => {}
        }
    }

    fn begin_setup(&mut self, now: Instant, out: &mut Vec<Event>) {
        if self.tcp {
            self.step = Step::Setup;
            self.setup(now, out);
        } else {
            self.step = Step::Ports;
            out.push(Event::NeedPorts(self.plans.len()));
        }
    }

    fn described(&mut self, r: &Reply, now: Instant, out: &mut Vec<Event>) {
        let Ok(s) = sdp::Session::parse(&String::from_utf8_lossy(&r.body)) else {
            out.push(Event::Fail(ClientError::Protocol("malformed SDP".into())));
            return;
        };
        let base = ["content-base", "content-location"]
            .iter()
            .filter_map(|h| r.header(h))
            .find(|b| clean(b) && b.to_ascii_lowercase().starts_with("rtsp://"))
            .map_or_else(|| self.url.request.clone(), str::to_owned);
        if let Some(c) = s.attr("control").filter(|c| clean(c)) {
            self.aggregate = join(&base, c);
        } else {
            self.aggregate = base.clone();
        }
        let mut medias = s.media.clone();
        for (i, m) in s.media.iter().enumerate() {
            let usable = self.plans.len() < MAX_TRACKS
                && m.control().is_none_or(clean)
                && sdp::media_track(m).is_some_and(|(t, _)| rtp::supported(t.codec));
            if !usable {
                medias[i] = sdp::Media::default();
                continue;
            }
            let k = self.plans.len() as u8;
            self.plans.push(Plan {
                control: join(&base, m.control().unwrap_or("")),
                media: i,
                channels: (2 * k, 2 * k + 1),
                client_ports: None,
                server_ports: None,
            });
        }
        if self.plans.is_empty() {
            out.push(Event::Fail(ClientError::NoTracks));
            return;
        }
        out.push(Event::Described(medias));
        self.begin_setup(now, out);
    }

    fn set_up(&mut self, r: &Reply) -> Result<(), ClientError> {
        let bad = |e: &str| ClientError::Protocol(e.to_owned());
        if let Some(s) = r.header("session") {
            let mut it = s.split(';');
            let id = it.next().unwrap_or("").trim();
            if id.is_empty() || id.len() > MAX_SESSION_ID {
                return Err(bad("bad Session header"));
            }
            if self.session.is_none() {
                self.session = Some(id.to_owned());
                self.session_timeout = it.find_map(|p| {
                    let (k, v) = p.split_once('=')?;
                    k.trim()
                        .eq_ignore_ascii_case("timeout")
                        .then(|| v.trim().parse::<u64>().ok())
                        .flatten()
                        .filter(|&t| t > 0)
                        .map(Duration::from_secs)
                });
            }
        } else if self.session.is_none() {
            return Err(bad("SETUP answered without a Session"));
        }
        let t = r
            .header("transport")
            .and_then(|t| Transport::parse_all(t).into_iter().next())
            .ok_or_else(|| bad("SETUP answered without a usable Transport"))?;
        let tcp = self.tcp;
        let record = self.record;
        let p = &mut self.plans[self.next_setup];
        if t.tcp != tcp {
            return Err(bad("the server chose another transport"));
        }
        if tcp {
            if let Some(ch) = t.interleaved {
                p.channels = ch;
            }
        } else {
            p.server_ports = t.server_port;
            if record && p.server_ports.is_none() {
                return Err(bad("SETUP answered without server_port"));
            }
        }
        Ok(())
    }
}

// ---- the driver ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connecting,
    Handshake,
    NeedPorts(usize),
    Live,
    Done,
}

struct Inner {
    phase: Phase,
    conn: Option<Conn<ClientConn>>,
    m: Machine,
    /// Pull: the reserved path, until DESCRIBE answers.
    publisher: Option<crate::hub::Publisher>,
    recorder: Option<Arc<Mutex<Recorder>>>,
    sub: Option<Subscription>,
    /// UDP: RTP and RTCP sockets of each track, in order.
    udp: Vec<(Arc<UdpBinding>, Arc<UdpBinding>)>,
    error: Option<ClientError>,
    server_ip: Option<IpAddr>,
    local_ip: Option<IpAddr>,
    keepalive_at: Option<Instant>,
    rr_ssrc: u32,
}

/// What the connection, the timer and the caller share.
struct Shared {
    cfg: RtspClientConfig,
    path: String,
    record: bool,
    timers: bool,
    start: Instant,
    /// Milliseconds since `start` of the last media received.
    last_media: AtomicU64,
    closed: AtomicBool,
    inner: Mutex<Inner>,
    cond: Condvar,
}

impl Shared {
    fn new(
        cfg: RtspClientConfig,
        m: Machine,
        publisher: Option<crate::hub::Publisher>,
        path: &str,
        timers: bool,
    ) -> Arc<Shared> {
        let mut b = [0u8; 4];
        let _ = only_crypto::rand::fill_random(&mut b);
        Arc::new(Shared {
            record: m.record,
            cfg,
            path: path.to_owned(),
            timers,
            start: Instant::now(),
            last_media: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                phase: Phase::Connecting,
                conn: None,
                m,
                publisher,
                recorder: None,
                sub: None,
                udp: Vec::new(),
                error: None,
                server_ip: None,
                local_ip: None,
                keepalive_at: None,
                rr_ssrc: u32::from_be_bytes(b),
            }),
            cond: Condvar::new(),
        })
    }

    fn ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn touch(&self) {
        self.last_media.store(self.ms(), Ordering::Relaxed);
    }

    /// Acts on the session's control events under the lock; media and failures are returned
    /// to be handled without it.
    fn handle(
        &self,
        g: &mut Inner,
        events: Vec<Event>,
        media: &mut Vec<(usize, bool, Vec<u8>)>,
        fail: &mut Option<ClientError>,
    ) {
        for e in events {
            match e {
                Event::Send(b) => {
                    if let Some(c) = &g.conn {
                        if c.send_owned(b).is_err() {
                            fail.get_or_insert(ClientError::Closed);
                        }
                    }
                }
                Event::Described(medias) => {
                    let Some(p) = g.publisher.take() else {
                        continue;
                    };
                    match Recorder::new(p, &medias) {
                        Some(r) => g.recorder = Some(Arc::new(Mutex::new(r))),
                        None => {
                            fail.get_or_insert(ClientError::NoTracks);
                        }
                    }
                }
                Event::NeedPorts(n) => {
                    g.phase = Phase::NeedPorts(n);
                    self.cond.notify_all();
                }
                Event::Live => {
                    g.phase = Phase::Live;
                    self.touch();
                    g.keepalive_at = Some(Instant::now() + g.m.keepalive_every(&self.cfg));
                    self.cond.notify_all();
                }
                Event::Media {
                    media: m,
                    rtcp,
                    data,
                } => media.push((m, rtcp, data)),
                Event::Fail(e) => {
                    fail.get_or_insert(e);
                }
            }
        }
    }

    fn on_data(&self, data: &[u8]) {
        let mut events = Vec::new();
        let mut media = Vec::new();
        let mut fail = None;
        let rec = {
            let mut g = lock(&self.inner);
            if g.phase == Phase::Done {
                return;
            }
            g.m.feed(data, Instant::now(), &mut events);
            self.handle(&mut g, events, &mut media, &mut fail);
            g.recorder.clone()
        };
        if !media.is_empty() {
            self.touch();
            if let Some(rec) = rec {
                let mut r = lock(&rec);
                for (m, rtcp, d) in &media {
                    if !rtcp && !rtp::is_rtcp(d) {
                        r.push(*m, d);
                    }
                }
            }
        }
        if let Some(e) = fail {
            self.finish(Some(e));
        }
    }

    fn opened(&self, c: &Conn<ClientConn>) -> bool {
        let mut events = Vec::new();
        let mut media = Vec::new();
        let mut fail = None;
        {
            let mut g = lock(&self.inner);
            if g.phase != Phase::Connecting {
                return false;
            }
            g.conn = Some(c.clone());
            g.server_ip = Some(c.peer_addr().ip());
            g.local_ip = Some(c.local_addr().ip());
            g.phase = Phase::Handshake;
            g.m.start(Instant::now(), &mut events);
            self.handle(&mut g, events, &mut media, &mut fail);
        }
        if let Some(e) = fail {
            self.finish(Some(e));
        }
        true
    }

    /// Periodic checks: timeouts and keep-alives.
    fn tick(&self) {
        let now = Instant::now();
        let mut fail = None;
        let mut rr = Vec::new();
        {
            let mut g = lock(&self.inner);
            let resp = self.cfg.response_timeout;
            match g.phase {
                Phase::Done => return,
                Phase::Connecting => {
                    let t = self.cfg.connect_timeout;
                    if !t.is_zero() && self.start.elapsed() >= t {
                        fail = Some(ClientError::Timeout("connect"));
                    }
                }
                Phase::NeedPorts(_) => {}
                Phase::Handshake | Phase::Live => fail = g.m.check(now, resp),
            }
            if g.phase == Phase::Live && fail.is_none() {
                let idle = self.cfg.idle_timeout;
                let quiet = self
                    .ms()
                    .saturating_sub(self.last_media.load(Ordering::Relaxed));
                if !self.record && !idle.is_zero() && quiet >= idle.as_millis() as u64 {
                    fail = Some(ClientError::Timeout("media"));
                }
                if g.keepalive_at.is_some_and(|t| now >= t) {
                    g.keepalive_at = Some(now + g.m.keepalive_every(&self.cfg));
                    let mut events = Vec::new();
                    g.m.keepalive(now, &mut events);
                    let mut media = Vec::new();
                    self.handle(&mut g, events, &mut media, &mut fail);
                    if !self.record {
                        // UDP: an empty receiver report on each track's RTCP port keeps NAT
                        // bindings and servers that watch RTCP happy.
                        if let Some(ip) = g.server_ip {
                            let mut pkt = vec![0x80, 201, 0, 1];
                            pkt.extend_from_slice(&g.rr_ssrc.to_be_bytes());
                            for (sp, (_, rtcp)) in g.m.server_ports().into_iter().zip(&g.udp) {
                                if let Some((_, p)) = sp {
                                    rr.push((rtcp.clone(), SocketAddr::new(ip, p), pkt.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }
        for (sock, to, pkt) in rr {
            let _ = sock.send_to(&pkt, to);
        }
        if let Some(e) = fail {
            self.finish(Some(e));
        }
    }

    fn period(&self) -> Duration {
        let mut p = Duration::from_millis(500);
        for t in [
            self.cfg.connect_timeout,
            self.cfg.response_timeout,
            self.cfg.idle_timeout,
        ] {
            if !t.is_zero() {
                p = p.min(t / 4);
            }
        }
        p.max(Duration::from_millis(10))
    }

    /// Ends the session (idempotent): TEARDOWN when the server knows it, then the connection,
    /// the hub side and the UDP sockets are closed.
    fn finish(&self, err: Option<ClientError>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let (conn, bye, rec, publisher, sub, udp) = {
            let mut g = lock(&self.inner);
            if g.error.is_none() {
                g.error = err;
            }
            let bye = match g.phase {
                Phase::Handshake | Phase::NeedPorts(_) | Phase::Live => g.m.teardown(),
                _ => None,
            };
            g.phase = Phase::Done;
            (
                g.conn.take(),
                bye,
                g.recorder.take(),
                g.publisher.take(),
                g.sub.take(),
                std::mem::take(&mut g.udp),
            )
        };
        self.cond.notify_all();
        drop(sub);
        if let Some(r) = rec {
            lock(&r).close();
        }
        drop(publisher);
        for (a, b) in udp {
            a.close();
            b.close();
        }
        if let Some(c) = conn {
            if bye.is_some_and(|b| c.send_owned(b).is_ok()) {
                c.close_after_send();
            } else {
                c.close();
            }
        }
    }
}

fn arm(w: Weak<Shared>, every: Duration) {
    crate::timer::after(every, move || {
        let Some(s) = w.upgrade() else { return };
        if s.closed.load(Ordering::Acquire) {
            return;
        }
        s.tick();
        drop(s);
        arm(w, every);
    });
}

/// The RTSP connection's handler.
pub(crate) struct ClientConn(Arc<Shared>);

impl fmt::Debug for ClientConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConn")
            .field("path", &self.0.path)
            .finish_non_exhaustive()
    }
}

impl Handler for ClientConn {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        self.0.on_data(data);
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<only::Error>) {
        self.0.finish(Some(
            err.map_or(ClientError::Closed, |e| ClientError::Io(e.to_string())),
        ));
    }
}

struct ClientAcceptor(Arc<Shared>);

impl Acceptor for ClientAcceptor {
    type Handler = ClientConn;

    fn on_open(&self, c: &Conn<ClientConn>) -> ClientConn {
        if !self.0.opened(c) {
            c.close();
        }
        ClientConn(self.0.clone())
    }
}

/// The handler of one UDP socket of a track.
struct UdpRecv {
    shared: Weak<Shared>,
    rec: Weak<Mutex<Recorder>>,
    media: usize,
    rtcp: bool,
    /// Whether the datagrams come from the server (others are ignored).
    allowed: bool,
}

impl Handler for UdpRecv {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        if !self.allowed {
            return;
        }
        if let Some(s) = self.shared.upgrade() {
            s.touch();
        }
        if !self.rtcp && !rtp::is_rtcp(data) {
            if let Some(r) = self.rec.upgrade() {
                lock(&r).push(self.media, data);
            }
        }
    }
}

struct UdpAcceptor {
    shared: Weak<Shared>,
    rec: Weak<Mutex<Recorder>>,
    media: usize,
    rtcp: bool,
    server: Option<IpAddr>,
}

impl Acceptor for UdpAcceptor {
    type Handler = UdpRecv;

    fn on_open(&self, c: &Conn<UdpRecv>) -> UdpRecv {
        let allowed = self.server.is_none_or(|ip| ip == c.peer_addr().ip());
        if !allowed {
            c.close();
        }
        UdpRecv {
            shared: self.shared.clone(),
            rec: self.rec.clone(),
            media: self.media,
            rtcp: self.rtcp,
            allowed,
        }
    }
}

type UdpPair = (Arc<UdpBinding>, Arc<UdpBinding>);

/// Binds an RTP/RTCP pair for track `media` on `ip`, an even port and the next one when it
/// can.
fn bind_pair(
    engine: &Engine,
    ip: IpAddr,
    acc: impl Fn(bool) -> UdpAcceptor,
) -> Result<UdpPair, ClientError> {
    let io = |e: std::io::Error| ClientError::Io(e.to_string());
    for _ in 0..32 {
        let a = engine
            .bind_udp(SocketAddr::new(ip, 0), acc(false))
            .map_err(io)?;
        let port = a.local_addr().port();
        if port % 2 == 0 && port < u16::MAX {
            if let Ok(b) = engine.bind_udp(SocketAddr::new(ip, port + 1), acc(true)) {
                return Ok((Arc::new(a), Arc::new(b)));
            }
        }
        a.close();
    }
    let a = engine
        .bind_udp(SocketAddr::new(ip, 0), acc(false))
        .map_err(io)?;
    match engine.bind_udp(SocketAddr::new(ip, 0), acc(true)) {
        Ok(b) => Ok((Arc::new(a), Arc::new(b))),
        Err(e) => {
            a.close();
            Err(io(e))
        }
    }
}

/// Dials, then drives the handshake from the caller's thread until the session is live.
fn establish(engine: &Engine, addr: SocketAddr, s: &Arc<Shared>) -> Result<(), ClientError> {
    let s2 = s.clone();
    engine.dial(addr, ClientAcceptor(s.clone()), move |e| {
        let err = if e.kind() == std::io::ErrorKind::TimedOut {
            ClientError::Timeout("connect")
        } else {
            ClientError::Connect(e.to_string())
        };
        s2.finish(Some(err));
    });
    if s.timers {
        arm(Arc::downgrade(s), s.period());
    }
    let cfg = &s.cfg;
    let deadline = (!cfg.response_timeout.is_zero())
        .then(|| Instant::now() + cfg.connect_timeout + cfg.response_timeout * 16);
    let mut g = lock(&s.inner);
    loop {
        match g.phase {
            Phase::Live => return Ok(()),
            Phase::Done => return Err(g.error.clone().unwrap_or(ClientError::Closed)),
            Phase::NeedPorts(n) => {
                let ip = g.local_ip.unwrap_or_else(|| IpAddr::from([0, 0, 0, 0]));
                let server = g.server_ip;
                let medias = g.m.plan_media();
                let rec = g.recorder.as_ref().map_or_else(Weak::new, Arc::downgrade);
                drop(g);
                let mut pairs = Vec::with_capacity(n);
                let mut err = None;
                for &media in medias.iter().take(n) {
                    let acc = |rtcp| UdpAcceptor {
                        shared: Arc::downgrade(s),
                        rec: rec.clone(),
                        media,
                        rtcp,
                        server,
                    };
                    match bind_pair(engine, ip, acc) {
                        Ok(p) => pairs.push(p),
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                let mut fail = err;
                let mut events = Vec::new();
                let mut media = Vec::new();
                g = lock(&s.inner);
                if fail.is_none() && g.phase == Phase::NeedPorts(n) {
                    let ports: Vec<(u16, u16)> = pairs
                        .iter()
                        .map(|(a, b)| (a.local_addr().port(), b.local_addr().port()))
                        .collect();
                    g.udp = pairs;
                    g.phase = Phase::Handshake;
                    g.m.set_ports(&ports, Instant::now(), &mut events);
                    s.handle(&mut g, events, &mut media, &mut fail);
                } else {
                    for (a, b) in pairs {
                        a.close();
                        b.close();
                    }
                }
                if let Some(e) = fail {
                    drop(g);
                    s.finish(Some(e));
                    g = lock(&s.inner);
                }
                continue;
            }
            _ => {}
        }
        match deadline {
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    drop(g);
                    s.finish(Some(ClientError::Timeout("handshake")));
                    g = lock(&s.inner);
                    continue;
                }
                g = s
                    .cond
                    .wait_timeout(g, d - now)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
            None => g = s.cond.wait(g).unwrap_or_else(|p| p.into_inner()),
        }
    }
}

// ---- push: the hub sink --------------------------------------------------------------------

#[derive(Clone)]
enum Route {
    Tcp {
        rtp: u8,
        rtcp: u8,
    },
    Udp {
        rtp: Arc<UdpBinding>,
        rtcp: Arc<UdpBinding>,
        to_rtp: SocketAddr,
        to_rtcp: SocketAddr,
    },
}

struct PushTrack {
    route: Route,
    pack: Option<Packetizer>,
    track: Option<Track>,
    last_sr: Option<Instant>,
}

/// A hub sink recording one stream to the server.
struct Pusher {
    shared: Weak<Shared>,
    conn: Option<Conn<ClientConn>>,
    /// By hub track index.
    tracks: Vec<Option<PushTrack>>,
    codecs: Vec<crate::av::Codec>,
    timeline: Timeline,
    first: bool,
    video: Vec<bool>,
    sr_every: Duration,
    max_queue: usize,
}

impl Pusher {
    fn fail(&self, e: ClientError) {
        if let Some(s) = self.shared.upgrade() {
            s.finish(Some(e));
        }
    }
}

impl Sink for Pusher {
    fn on_tracks(&mut self, tracks: &Tracks) {
        if tracks.len() != self.codecs.len()
            || tracks.iter().zip(&self.codecs).any(|(t, c)| t.codec != *c)
        {
            self.fail(ClientError::Protocol(
                "the pushed stream changed its tracks".into(),
            ));
            return;
        }
        self.video = tracks.iter().map(Track::is_video).collect();
        if !self.first {
            self.timeline.restart();
        }
        self.first = false;
        for (i, t) in tracks.iter().enumerate() {
            let Some(Some(pt)) = self.tracks.get_mut(i) else {
                continue;
            };
            if pt.track.as_ref() != Some(t) {
                pt.pack = Some(Packetizer::new(t, 96 + i as u8));
                pt.track = Some(t.clone());
            }
        }
    }

    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        if let Some(c) = &self.conn {
            if c.queued_bytes() > self.max_queue {
                self.fail(ClientError::WriteQueueFull);
                return;
            }
        }
        let video = self.video.get(pkt.track).copied().unwrap_or(false);
        let Some(Some(t)) = self.tracks.get_mut(pkt.track) else {
            return;
        };
        let Some(pack) = t.pack.as_mut() else { return };
        let dts = self.timeline.stamp(video, pkt.dts);
        let pts = (pkt.pts + self.timeline.offset()).max(dts);
        let mut p = Packet::new(pkt.track, dts, pts, pkt.keyframe, Vec::new());
        p.data.clone_from(&pkt.data);
        let mut out = Vec::new();
        pack.packetize(&p, &mut out);
        let sr = match t.last_sr {
            Some(at) if at.elapsed() < self.sr_every => None,
            _ => {
                t.last_sr = Some(Instant::now());
                Some(pack.sender_report(rtp::ntp_now(), pack.last_timestamp()))
            }
        };
        match &t.route {
            Route::Tcp { rtp, rtcp } => {
                let Some(c) = &self.conn else { return };
                let n: usize = out.iter().map(|r| r.len() + 4).sum::<usize>() + 32;
                let mut b = Vec::with_capacity(n);
                for r in &out {
                    message::interleaved(*rtp, r, &mut b);
                }
                if let Some(sr) = &sr {
                    message::interleaved(*rtcp, sr, &mut b);
                }
                if c.send_owned(b).is_err() {
                    self.fail(ClientError::Closed);
                }
            }
            Route::Udp {
                rtp,
                rtcp,
                to_rtp,
                to_rtcp,
            } => {
                // UDP semantics: a datagram the socket cannot take now is lost.
                for r in &out {
                    let _ = rtp.send_to(r, *to_rtp);
                }
                if let Some(sr) = &sr {
                    let _ = rtcp.send_to(sr, *to_rtcp);
                }
            }
        }
    }

    fn on_close(&mut self, err: HubError) {
        self.fail(ClientError::Hub(err));
    }
}

/// Subscribes the live record session `s` to the hub stream.
fn start_push(
    s: &Arc<Shared>,
    hub: &Hub,
    tracks: &Tracks,
    remote: SocketAddr,
) -> Result<(), ClientError> {
    let (conn, routes) = {
        let g = lock(&s.inner);
        let medias = g.m.plan_media();
        let mut routes: Vec<Option<PushTrack>> = (0..tracks.len()).map(|_| None).collect();
        let tcp = s.cfg.transport == RtspTransport::Tcp;
        for (k, ((&hub_index, ch), sp)) in medias
            .iter()
            .zip(g.m.channels())
            .zip(g.m.server_ports())
            .enumerate()
        {
            let route = if tcp {
                Route::Tcp {
                    rtp: ch.0,
                    rtcp: ch.1,
                }
            } else {
                let (Some((a, b)), Some(ip), Some((rtp, rtcp))) = (sp, g.server_ip, g.udp.get(k))
                else {
                    continue;
                };
                Route::Udp {
                    rtp: rtp.clone(),
                    rtcp: rtcp.clone(),
                    to_rtp: SocketAddr::new(ip, a),
                    to_rtcp: SocketAddr::new(ip, b),
                }
            };
            if let Some(slot) = routes.get_mut(hub_index) {
                *slot = Some(PushTrack {
                    route,
                    pack: None,
                    track: None,
                    last_sr: None,
                });
            }
        }
        (g.conn.clone(), routes)
    };
    let tcp = s.cfg.transport == RtspTransport::Tcp;
    let pusher = Pusher {
        shared: Arc::downgrade(s),
        conn: if tcp { conn.clone() } else { None },
        tracks: routes,
        codecs: tracks.iter().map(|t| t.codec).collect(),
        timeline: Timeline::from_zero(),
        first: true,
        video: Vec::new(),
        sr_every: s.cfg.sender_report_interval,
        max_queue: s.cfg.max_write_queue,
    };
    let backlog = move || match (&conn, tcp) {
        (Some(c), true) => c.queued_bytes(),
        _ => 0,
    };
    let sink = Dropper::new(pusher, backlog, s.cfg.write_queue_limit);
    let opts = SubscribeOptions::new(PeerInfo::new("rtsp", Some(remote), ""));
    match hub.subscribe(&s.path, sink, opts) {
        Ok(sub) => {
            let mut g = lock(&s.inner);
            if g.phase == Phase::Done {
                drop(g);
                drop(sub);
                return Err(lock(&s.inner).error.clone().unwrap_or(ClientError::Closed));
            }
            g.sub = Some(sub);
            Ok(())
        }
        Err(e) => {
            s.finish(Some(ClientError::Hub(e.clone())));
            Err(ClientError::Hub(e))
        }
    }
}

// ---- the public API ------------------------------------------------------------------------

/// A running RTSP client session ([`pull`] or [`push`]). Dropping it closes the session, like
/// [`close`](Self::close).
pub struct RtspClient(Arc<Shared>);

impl fmt::Debug for RtspClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspClient")
            .field("path", &self.0.path)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl RtspClient {
    /// The hub path the session publishes to ([`pull`]) or reads from ([`push`]).
    pub fn path(&self) -> &str {
        &self.0.path
    }

    /// Ends the session: sends TEARDOWN (best effort, not waited for) and closes the
    /// connection, the UDP sockets and the hub side (a pulled stream is unpublished, a push
    /// unsubscribes). Idempotent; [`error`](Self::error) stays `None` if nothing failed first.
    pub fn close(&self) {
        self.0.finish(None);
    }

    /// Whether the session is over: closed, or ended by an error.
    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }

    /// The error that ended the session, if one did.
    pub fn error(&self) -> Option<ClientError> {
        lock(&self.0.inner).error.clone()
    }
}

impl Drop for RtspClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Plays `url` (RTSP PLAY) and publishes it in `hub` at `path`, which is reserved right away
/// (a second publisher is refused; the stream goes live once its tracks are known). Returns
/// once the server answered PLAY; afterwards the session runs on the engine's I/O threads
/// until [`RtspClient::close`], a drop, or an error ([`RtspClient::error`]): the connection
/// closing, no media for [`RtspClientConfig::idle_timeout`], or a keep-alive unanswered.
///
/// Dials with [`Engine::dial`] (the engine must be started); [`RtspTransport::Udp`] also needs
/// `EngineBuilder::udp_client_threads` (or a UDP listener). Blocks the caller for the
/// handshake and for the lookup of a host name: never call it from an I/O thread.
pub fn pull(
    engine: &Engine,
    url: &str,
    hub: &Hub,
    path: &str,
    cfg: RtspClientConfig,
) -> Result<RtspClient, ClientError> {
    let url = Url::parse(url)?;
    let addr = url.resolve(&cfg)?;
    let publisher = hub
        .reserve(path, PeerInfo::new("rtsp", Some(addr), ""))
        .map_err(ClientError::Hub)?;
    let m = Machine::play(url, &cfg);
    let s = Shared::new(cfg, m, Some(publisher), path, true);
    establish(engine, addr, &s)?;
    Ok(RtspClient(s))
}

/// Records the hub stream at `path` to `url` (RTSP ANNOUNCE and RECORD), from its cached GOP
/// on. Waits up to [`RtspClientConfig::push_wait`] for the stream to be live (its tracks go
/// into the ANNOUNCE's SDP), then returns once the server answered RECORD; afterwards the
/// session runs until [`RtspClient::close`], a drop, or an error ([`RtspClient::error`]): the
/// connection closing, the stream ending ([`ClientError::Hub`]) or changing its codecs, or the
/// server reading too slowly ([`ClientError::WriteQueueFull`]).
///
/// Dials with [`Engine::dial`] (the engine must be started); [`RtspTransport::Udp`] also needs
/// `EngineBuilder::udp_client_threads` (or a UDP listener). Blocks the caller while waiting
/// for the stream, for the handshake and for the lookup of a host name: never call it from an
/// I/O thread.
pub fn push(
    engine: &Engine,
    url: &str,
    hub: &Hub,
    path: &str,
    cfg: RtspClientConfig,
) -> Result<RtspClient, ClientError> {
    let url = Url::parse(url)?;
    let addr = url.resolve(&cfg)?;
    let deadline = Instant::now() + cfg.push_wait;
    let tracks = loop {
        if let Some(i) = hub
            .stream_info(path)
            .filter(|i| i.publishing && !i.tracks.is_empty())
        {
            break i.tracks;
        }
        if Instant::now() >= deadline {
            return Err(ClientError::Hub(HubError::NotFound));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let m = Machine::record(url, &tracks, &cfg)?;
    let s = Shared::new(cfg, m, None, path, true);
    establish(engine, addr, &s)?;
    start_push(&s, hub, &tracks, addr)?;
    Ok(RtspClient(s))
}

// ---- fuzzing -------------------------------------------------------------------------------

/// Drives a client session over a detached connection with `pieces` as what the server sends:
/// `record` picks push or pull, `udp` the transport (ports are made up, nothing is bound). A
/// push that goes live subscribes to a hub stream of H.264 and AAC fed a few packets.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn fuzz(record: bool, udp: bool, pieces: &[&[u8]]) {
    use crate::{av::Codec, codec::h264};
    let hub = Hub::default();
    let mut cfg = RtspClientConfig::default();
    if udp {
        cfg.transport = RtspTransport::Udp;
    }
    let Ok(url) = Url::parse("rtsp://user:pass@127.0.0.1:8554/live/s") else {
        return;
    };
    let tracks: Tracks = Arc::from(vec![
        Track::video(Codec::H264, Vec::new()),
        Track::aac(vec![0x12, 0x10]),
    ]);
    let src = if record {
        hub.publish("src", tracks.clone(), PeerInfo::default()).ok()
    } else {
        None
    };
    let s = if record {
        let Ok(m) = Machine::record(url, &tracks, &cfg) else {
            return;
        };
        Shared::new(cfg, m, None, "src", false)
    } else {
        let Ok(p) = hub.reserve("dst", PeerInfo::default()) else {
            return;
        };
        let m = Machine::play(url, &cfg);
        Shared::new(cfg, m, Some(p), "dst", false)
    };
    let c = only_core::fuzzing::conn::<ClientConn>();
    let mut h = ClientAcceptor(s.clone()).on_open(&c);
    let mut pushing = false;
    for p in pieces {
        h.on_data(&c, p);
        let phase = lock(&s.inner).phase;
        if let Phase::NeedPorts(n) = phase {
            let mut g = lock(&s.inner);
            g.phase = Phase::Handshake;
            let ports: Vec<(u16, u16)> = (0..n as u16)
                .map(|i| (5000 + 2 * i, 5001 + 2 * i))
                .collect();
            let mut events = Vec::new();
            g.m.set_ports(&ports, Instant::now(), &mut events);
            let (mut media, mut fail) = (Vec::new(), None);
            s.handle(&mut g, events, &mut media, &mut fail);
        }
        if record && !pushing && lock(&s.inner).phase == Phase::Live {
            pushing = true;
            let remote = SocketAddr::from(([127, 0, 0, 1], 8554));
            if start_push(&s, &hub, &tracks, remote).is_ok() {
                if let Some(src) = &src {
                    for i in 0..3i64 {
                        let nal = if i == 0 { 0x65 } else { 0x41 };
                        src.write(Packet::new(
                            0,
                            i * 40_000_000,
                            i * 40_000_000,
                            i == 0,
                            h264::to_avcc([&[nal, 1, 2, 3][..]]),
                        ));
                        src.write(Packet::new(
                            1,
                            i * 23_000_000,
                            i * 23_000_000,
                            true,
                            vec![0x21; 30],
                        ));
                    }
                }
            }
        }
    }
    h.on_close(&c, None);
    s.finish(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=x\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1; sprop-parameter-sets=Z2QADazZQUH7ARAAAAMAEAAAAwMg8UKZYA==,aOvjyyLA\r\na=control:trackID=0\r\nm=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\na=control:trackID=1\r\nm=audio 0 RTP/AVP 97\r\na=rtpmap:97 MPEG4-GENERIC/44100/2\r\na=fmtp:97 mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1210\r\na=control:rtsp://127.0.0.1/cam/audio\r\n";

    fn reply(cseq: u32, head: &str, body: &str) -> Vec<u8> {
        format!(
            "{head}\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The requests among `ev`, as text.
    fn sent(ev: &mut Vec<Event>) -> Vec<String> {
        ev.drain(..)
            .filter_map(|e| match e {
                Event::Send(b) => Some(String::from_utf8(b).unwrap()),
                _ => None,
            })
            .collect()
    }

    fn header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
        req.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}: ")))
    }

    #[test]
    fn urls() {
        let u = Url::parse("rtsp://ad%40min:p%3Ass@cam.local:8554/live/s?t=1").unwrap();
        assert_eq!(u.host, "cam.local");
        assert_eq!(u.port, 8554);
        assert_eq!(u.user.as_deref(), Some("ad@min"));
        assert_eq!(u.pass.as_deref(), Some("p:ss"));
        assert_eq!(u.request, "rtsp://cam.local:8554/live/s?t=1");
        let u = Url::parse("RTSP://[::1]/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 554));
        assert_eq!(u.request, "rtsp://[::1]/x");
        assert_eq!(
            u.resolve(&RtspClientConfig::default()).unwrap(),
            "[::1]:554".parse().unwrap()
        );
        let u = Url::parse("rtsp://user@10.0.0.1").unwrap();
        assert_eq!((u.user.as_deref(), u.pass.as_deref()), (Some("user"), None));
        assert_eq!(u.request, "rtsp://10.0.0.1");
        let cfg = RtspClientConfig {
            addr: Some("127.0.0.1:9".parse().unwrap()),
            ..RtspClientConfig::default()
        };
        assert_eq!(u.resolve(&cfg).unwrap(), "127.0.0.1:9".parse().unwrap());
        for bad in [
            "rtsps://h/s",
            "http://h/s",
            "h/s",
            "rtsp:///s",
            "rtsp://h:0/s",
            "rtsp://h:99999/s",
            "rtsp://[::1/s",
            "rtsp://[zz]/s",
            "rtsp://h/s x",
            "rtsp://h/s\r\nX: y",
            "rtsp://u%zz@h/s",
        ] {
            assert!(matches!(Url::parse(bad), Err(ClientError::Url(_))), "{bad}");
        }
        assert!(
            Url::parse("rtsps://h/s")
                .unwrap_err()
                .to_string()
                .contains("rtsps")
        );
    }

    #[test]
    fn control_urls() {
        assert_eq!(join("rtsp://h/s/", "trackID=0"), "rtsp://h/s/trackID=0");
        assert_eq!(join("rtsp://h/s", "trackID=0"), "rtsp://h/s/trackID=0");
        assert_eq!(
            join("rtsp://h/s?t=1", "trackID=0"),
            "rtsp://h/s/trackID=0?t=1"
        );
        assert_eq!(join("rtsp://h/s/", "rtsp://o/a"), "rtsp://o/a");
        assert_eq!(join("rtsp://h/s/", "*"), "rtsp://h/s/");
        assert_eq!(join("rtsp://h/s/", ""), "rtsp://h/s/");
    }

    #[test]
    fn play_over_tcp_with_digest() {
        let cfg = RtspClientConfig {
            user_agent: "test\r\nX: y".into(),
            ..RtspClientConfig::default()
        };
        let url = Url::parse("rtsp://admin:secret@127.0.0.1/cam").unwrap();
        let mut m = Machine::play(url, &cfg);
        let now = Instant::now();
        let mut ev = Vec::new();
        m.start(now, &mut ev);
        let r = sent(&mut ev);
        assert!(r[0].starts_with(
            "OPTIONS rtsp://127.0.0.1/cam RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: testX: y\r\n"
        ));
        m.feed(
            &reply(
                1,
                "RTSP/1.0 200 OK\r\nPublic: OPTIONS, DESCRIBE, GET_PARAMETER",
                "",
            ),
            now,
            &mut ev,
        );
        let r = sent(&mut ev);
        assert!(r[0].starts_with("DESCRIBE rtsp://127.0.0.1/cam RTSP/1.0\r\nCSeq: 2\r\n"));
        assert_eq!(header(&r[0], "Accept"), Some("application/sdp"));
        assert_eq!(header(&r[0], "Authorization"), None);
        // 401 with Digest: DESCRIBE again, answered.
        m.feed(
            &reply(
                2,
                "RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"only-media\"\r\nWWW-Authenticate: Digest realm=\"only-media\", nonce=\"n1\"",
                "",
            ),
            now,
            &mut ev,
        );
        let r = sent(&mut ev);
        assert!(r[0].starts_with("DESCRIBE rtsp://127.0.0.1/cam RTSP/1.0\r\nCSeq: 3\r\n"));
        let auth = header(&r[0], "Authorization").unwrap();
        let lookup = |u: &str| (u == "admin").then(|| "secret".to_owned());
        assert_eq!(
            super::super::auth::verify(auth, "DESCRIBE", "only-media", "n1", &lookup).as_deref(),
            Some("admin")
        );
        // The DESCRIBE, split anywhere, with an interleaved frame of nobody after it.
        let mut d = reply(
            3,
            "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\nContent-Base: rtsp://127.0.0.1/cam/",
            SDP,
        );
        d.extend_from_slice(b"$\x09\x00\x01x");
        for c in d.chunks(5) {
            m.feed(c, now, &mut ev);
        }
        let medias = ev
            .iter()
            .find_map(|e| match e {
                Event::Described(m) => Some(m.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(medias.len(), 3);
        assert!(medias[1].formats.is_empty(), "metadata is not set up");
        assert_eq!(m.plan_media(), vec![0, 2]);
        let r = sent(&mut ev);
        assert_eq!(r.len(), 1);
        assert!(r[0].starts_with("SETUP rtsp://127.0.0.1/cam/trackID=0 RTSP/1.0\r\nCSeq: 4\r\n"));
        assert_eq!(
            header(&r[0], "Transport"),
            Some("RTP/AVP/TCP;unicast;interleaved=0-1")
        );
        assert!(
            header(&r[0], "Authorization")
                .unwrap()
                .starts_with("Digest ")
        );
        assert_eq!(header(&r[0], "Session"), None);
        // The server moves the channels.
        m.feed(
            &reply(
                4,
                "RTSP/1.0 200 OK\r\nSession: abc;timeout=20\r\nTransport: RTP/AVP/TCP;unicast;interleaved=4-5",
                "",
            ),
            now,
            &mut ev,
        );
        let r = sent(&mut ev);
        assert!(r[0].starts_with("SETUP rtsp://127.0.0.1/cam/audio RTSP/1.0\r\nCSeq: 5\r\n"));
        assert_eq!(
            header(&r[0], "Transport"),
            Some("RTP/AVP/TCP;unicast;interleaved=2-3")
        );
        assert_eq!(header(&r[0], "Session"), Some("abc"));
        m.feed(
            &reply(
                5,
                "RTSP/1.0 200 OK\r\nSession: abc\r\nTransport: RTP/AVP/TCP;unicast;interleaved=2-3",
                "",
            ),
            now,
            &mut ev,
        );
        let r = sent(&mut ev);
        assert!(r[0].starts_with("PLAY rtsp://127.0.0.1/cam/ RTSP/1.0\r\nCSeq: 6\r\n"));
        assert_eq!(header(&r[0], "Range"), Some("npt=0.000-"));
        // A stale answer is ignored; the right one makes the session live.
        m.feed(&reply(2, "RTSP/1.0 200 OK", ""), now, &mut ev);
        assert!(ev.is_empty());
        m.feed(
            &reply(6, "RTSP/1.0 200 OK\r\nSession: abc", ""),
            now,
            &mut ev,
        );
        assert!(matches!(ev.as_slice(), [Event::Live]));
        ev.clear();
        assert_eq!(m.keepalive_every(&cfg), Duration::from_secs(10));
        m.feed(b"$\x04\x00\x02ab$\x05\x00\x01c$\x02\x00\x01d", now, &mut ev);
        let got: Vec<(usize, bool)> = ev
            .iter()
            .map(|e| match e {
                Event::Media { media, rtcp, .. } => (*media, *rtcp),
                _ => panic!(),
            })
            .collect();
        assert_eq!(got, vec![(0, false), (0, true), (2, false)]);
        ev.clear();
        m.keepalive(now, &mut ev);
        let r = sent(&mut ev);
        assert!(r[0].starts_with("GET_PARAMETER rtsp://127.0.0.1/cam/ RTSP/1.0\r\nCSeq: 7\r\n"));
        m.keepalive(now, &mut ev);
        assert!(ev.is_empty(), "one keep-alive at a time");
        let late = now + Duration::from_secs(11);
        assert_eq!(
            m.check(late, Duration::from_secs(10)),
            Some(ClientError::Timeout("response"))
        );
        m.feed(&reply(7, "RTSP/1.0 200 OK", ""), now, &mut ev);
        assert_eq!(m.check(late, Duration::from_secs(10)), None);
        let t = String::from_utf8(m.teardown().unwrap()).unwrap();
        assert!(t.starts_with("TEARDOWN rtsp://127.0.0.1/cam/ RTSP/1.0\r\nCSeq: 8\r\n"));
        assert_eq!(header(&t, "Session"), Some("abc"));
        // A server request is answered.
        m.feed(b"OPTIONS * RTSP/1.0\r\nCSeq: 44\r\n\r\n", now, &mut ev);
        assert!(sent(&mut ev)[0].starts_with("RTSP/1.0 200 OK\r\nCSeq: 44\r\n"));
    }

    #[test]
    fn record_over_udp() {
        let cfg = RtspClientConfig {
            transport: RtspTransport::Udp,
            ..RtspClientConfig::default()
        };
        let url = Url::parse("rtsp://127.0.0.1:8554/live/out").unwrap();
        let tracks: Tracks = Arc::from(vec![
            Track::video(crate::Codec::H264, Vec::new()),
            Track::audio(crate::Codec::Mp3, Vec::new(), 44100, 2),
            Track::aac(vec![0x12, 0x10]),
        ]);
        let mut m = Machine::record(url, &tracks, &cfg).unwrap();
        assert_eq!(m.plan_media(), vec![0, 2]);
        let now = Instant::now();
        let mut ev = Vec::new();
        m.start(now, &mut ev);
        sent(&mut ev);
        m.feed(&reply(1, "RTSP/1.0 200 OK", ""), now, &mut ev);
        let r = sent(&mut ev);
        assert!(
            r[0].starts_with("ANNOUNCE rtsp://127.0.0.1:8554/live/out RTSP/1.0\r\nCSeq: 2\r\n")
        );
        assert_eq!(header(&r[0], "Content-Type"), Some("application/sdp"));
        let body = r[0].split("\r\n\r\n").nth(1).unwrap();
        let s = sdp::Session::parse(body).unwrap();
        assert_eq!(s.media.len(), 2);
        assert_eq!(s.media[1].control(), Some("trackID=2"));
        m.feed(&reply(2, "RTSP/1.0 200 OK", ""), now, &mut ev);
        assert!(matches!(ev.as_slice(), [Event::NeedPorts(2)]));
        ev.clear();
        m.set_ports(&[(5000, 5001), (5002, 5003)], now, &mut ev);
        let r = sent(&mut ev);
        assert!(r[0].starts_with("SETUP rtsp://127.0.0.1:8554/live/out/trackID=0 RTSP/1.0\r\n"));
        assert_eq!(
            header(&r[0], "Transport"),
            Some("RTP/AVP;unicast;client_port=5000-5001;mode=record")
        );
        m.feed(
            &reply(
                3,
                "RTSP/1.0 200 OK\r\nSession: s1\r\nTransport: RTP/AVP;unicast;client_port=5000-5001;server_port=8000-8001",
                "",
            ),
            now,
            &mut ev,
        );
        let r = sent(&mut ev);
        assert!(r[0].starts_with("SETUP rtsp://127.0.0.1:8554/live/out/trackID=2 RTSP/1.0\r\n"));
        // Without server_port there is nowhere to send to.
        m.feed(
            &reply(
                4,
                "RTSP/1.0 200 OK\r\nSession: s1\r\nTransport: RTP/AVP;unicast;client_port=5002-5003",
                "",
            ),
            now,
            &mut ev,
        );
        assert!(matches!(
            ev.as_slice(),
            [Event::Fail(ClientError::Protocol(_))]
        ));
        assert_eq!(m.server_ports()[0], Some((8000, 8001)));
    }

    #[test]
    fn refusals_and_bad_input() {
        let cfg = RtspClientConfig::default();
        let now = Instant::now();
        let play = |url: &str| {
            let mut m = Machine::play(Url::parse(url).unwrap(), &cfg);
            let mut ev = Vec::new();
            m.start(now, &mut ev);
            m.feed(&reply(1, "RTSP/1.0 200 OK", ""), now, &mut ev);
            m
        };
        let fail = |m: &mut Machine, wire: &[u8]| {
            let mut ev = Vec::new();
            m.feed(wire, now, &mut ev);
            ev.into_iter().find_map(|e| match e {
                Event::Fail(e) => Some(e),
                _ => None,
            })
        };
        let mut m = play("rtsp://h/s");
        assert_eq!(
            fail(&mut m, &reply(2, "RTSP/1.0 404 Not Found", "")),
            Some(ClientError::Status {
                method: "DESCRIBE",
                status: 404,
                reason: "Not Found".into()
            })
        );
        // No credentials for a 401; and credentials refused again and again.
        let deny = "RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"r\"";
        let mut m = play("rtsp://h/s");
        assert_eq!(
            fail(&mut m, &reply(2, deny, "")),
            Some(ClientError::Unauthorized)
        );
        let mut m = play("rtsp://u:p@h/s");
        assert_eq!(fail(&mut m, &reply(2, deny, "")), None);
        assert_eq!(fail(&mut m, &reply(3, deny, "")), None);
        assert_eq!(
            fail(&mut m, &reply(4, deny, "")),
            Some(ClientError::Unauthorized)
        );
        let mut m = play("rtsp://h/s");
        let metadata =
            "v=0\r\nm=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\n";
        assert_eq!(
            fail(&mut m, &reply(2, "RTSP/1.0 200 OK", metadata)),
            Some(ClientError::NoTracks)
        );
        let mut m = play("rtsp://h/s");
        assert!(matches!(
            fail(
                &mut m,
                b"RTSP/1.0 200 OK\r\nContent-Length: 999999999\r\n\r\n"
            ),
            Some(ClientError::Protocol(_))
        ));
        let mut m = play("rtsp://h/s");
        assert!(matches!(
            fail(&mut m, &vec![b'x'; MAX_HEAD + 1]),
            Some(ClientError::Protocol(_))
        ));
        // A control that would inject into the request line is not used.
        let mut m = play("rtsp://h/s");
        let inject =
            "v=0\r\nm=audio 0 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=control:x RTSP/1.0\r\n";
        assert_eq!(
            fail(&mut m, &reply(2, "RTSP/1.0 200 OK", inject)),
            Some(ClientError::NoTracks)
        );
        // SETUP answered with another transport, or without a session.
        let mut m = play("rtsp://h/s");
        assert_eq!(fail(&mut m, &reply(2, "RTSP/1.0 200 OK", SDP)), None);
        assert!(matches!(
            fail(
                &mut m,
                &reply(
                    3,
                    "RTSP/1.0 200 OK\r\nSession: 1\r\nTransport: RTP/AVP;unicast;server_port=1-2",
                    ""
                )
            ),
            Some(ClientError::Protocol(_))
        ));
        let mut m = play("rtsp://h/s");
        assert_eq!(fail(&mut m, &reply(2, "RTSP/1.0 200 OK", SDP)), None);
        assert!(matches!(
            fail(
                &mut m,
                &reply(
                    3,
                    "RTSP/1.0 200 OK\r\nTransport: RTP/AVP/TCP;interleaved=0-1",
                    ""
                )
            ),
            Some(ClientError::Protocol(_))
        ));
        // A head trickled past the response timeout.
        let mut m = play("rtsp://h/s");
        let mut ev = Vec::new();
        m.feed(b"RTSP/1.0 200", now, &mut ev);
        m.pending = None;
        let second = Duration::from_secs(1);
        assert_eq!(m.check(now + Duration::from_millis(500), second), None);
        m.feed(b" O", now + Duration::from_millis(900), &mut ev);
        assert_eq!(
            m.check(now + Duration::from_millis(1000), second),
            Some(ClientError::Timeout("response"))
        );
        assert_eq!(m.check(now + Duration::from_secs(99), Duration::ZERO), None);
    }

    fn engine() -> Engine {
        let e = Engine::builder()
            .client_threads(1)
            .udp_client_threads(1)
            .build()
            .unwrap();
        e.start().unwrap();
        e
    }

    /// A server that accepts and never answers: the response timeout ends the handshake, and
    /// the reserved path is released.
    #[test]
    fn silent_server_times_out() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 1024];
            // Read until the client gives up.
            while matches!(std::io::Read::read(&mut s, &mut b), Ok(n) if n > 0) {}
        });
        let e = engine();
        let hub = Hub::default();
        let cfg = RtspClientConfig {
            response_timeout: Duration::from_millis(300),
            ..RtspClientConfig::default()
        };
        let at = Instant::now();
        let r = pull(&e, &format!("rtsp://{addr}/s"), &hub, "live/x", cfg);
        assert_eq!(r.unwrap_err(), ClientError::Timeout("response"));
        assert!(at.elapsed() < Duration::from_secs(3), "{:?}", at.elapsed());
        assert!(
            hub.reserve("live/x", PeerInfo::default()).is_ok(),
            "path released"
        );
        t.join().unwrap();
        // Nobody listening: a connect error, quickly.
        let url = format!("rtsp://{addr}/s");
        let r = pull(&e, &url, &hub, "live/y", RtspClientConfig::default());
        assert!(matches!(r.unwrap_err(), ClientError::Connect(_)));
        // A busy path is refused before dialing.
        let _p = hub.reserve("live/z", PeerInfo::default()).unwrap();
        let r = pull(&e, &url, &hub, "live/z", RtspClientConfig::default());
        assert_eq!(r.unwrap_err(), ClientError::Hub(HubError::StreamBusy));
        // push: no stream within the wait.
        let cfg = RtspClientConfig {
            push_wait: Duration::from_millis(50),
            ..RtspClientConfig::default()
        };
        let r = push(&e, &url, &hub, "live/none", cfg);
        assert_eq!(r.unwrap_err(), ClientError::Hub(HubError::NotFound));
        e.shutdown();
    }

    /// A server that answers OPTIONS, then trickles the DESCRIBE response a byte at a time.
    #[test]
    fn trickling_server_times_out() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b);
            let _ = s.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");
            let _ = s.read(&mut b);
            for c in b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
                if s.write_all(&[*c]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let e = engine();
        let hub = Hub::default();
        let cfg = RtspClientConfig {
            response_timeout: Duration::from_millis(400),
            ..RtspClientConfig::default()
        };
        let at = Instant::now();
        let r = pull(&e, &format!("rtsp://{addr}/s"), &hub, "live/x", cfg);
        assert_eq!(r.unwrap_err(), ClientError::Timeout("response"));
        assert!(at.elapsed() < Duration::from_secs(2), "{:?}", at.elapsed());
        e.shutdown();
    }
}
