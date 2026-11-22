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
//! URL is resolved there with the system resolver (`ToSocketAddrs`), and again for every later
//! session (a reconnect, a redirect), so a server that moved to another address under the same
//! name is found; an IP literal, or [`RtspClientConfig::addr`], needs no lookup.
//!
//! **A/V sync**: a pull lines its tracks up by the RTCP sender reports of the server
//! ([`RtspClientConfig::rtcp_sync`], on by default): each track's times start at its first
//! packet's arrival, then once a track has a sender report its RTP timestamps are mapped to
//! the server's NTP clock, relative to the first track synchronized, so audio and video
//! captured at the same instant carry the same time in the hub. Corrections only move a
//! track's times forward, and are made before the stream goes live when the server sends its
//! reports early (as ffmpeg and mediamtx do).
//!
//! **Reconnecting**: with [`RtspClientConfig::reconnect`] a session that ends with an error
//! another try may cure is followed by a new one, after a bounded backoff ([`Reconnect`]),
//! from a short-lived thread of its own (the handshake blocks). A pull keeps its hub path
//! reserved throughout and republishes the new session's tracks (a timeline restart for the
//! sinks); a push reads the hub stream's current tracks again (a stream that changed its
//! codecs is announced anew) and continues from the cached GOP. The first session must come
//! up: [`pull`] and [`push`] return its error.
//!
//! **Receiver reports**: a pull sends the server RTCP receiver reports (RFC 3550 6.4.2) on each
//! track's RTCP channel or port ([`RtspClientConfig::receiver_report_interval`]).
//!
//! **Redirects**: a redirect (300 to 303, 307, 308) with a `Location` answering any request
//! before PLAY or RECORD ends the connection and starts the handshake again at the location
//! (an `rtsp://` URL, or an absolute path on the same server), up to five in a row, then the
//! client fails with the last one's [`ClientError::Status`]. The URL's credentials go along to
//! the same host and port only, unless the location has its own;
//! [`RtspClientConfig::addr`] applies to the client's own URL only. A `301` is remembered for
//! later sessions; other redirects are followed again from the client's URL.
//!
//! **Server REDIRECT**: a server may move a live session with a `REDIRECT` request (RFC 2326
//! 10.15, such as [`RtspServer::redirect_session`](super::RtspServer::redirect_session)). The
//! client answers it, and when its `Range` start comes (a `clock=` UTC time, an `npt=` from
//! PLAY or RECORD; at once without) tears the session down and starts a new one at the
//! `Location` right away, without the backoff, on the [`RtspClientConfig::reconnect`] engine
//! (it counts as a reconnect; later reconnects start from the client's URL again). Without
//! `reconnect` the client ends with [`ClientError::Redirected`] and the location. A connection
//! that closes after the `REDIRECT` but before its time moves too.
//!
//! **Addresses**: every session dials the addresses its server's name has, in the resolver's
//! order, until one connects (a refused or timed-out connect tries the next).
//!
//! Left out: RTSPS and HTTP tunnelling, multicast.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use only::{Acceptor, Conn, Engine, Handler, UdpBinding};

use super::{
    Recorder,
    auth::Challenge,
    describe_sdp,
    message::{
        self, Frame, MAX_BODY, MAX_HEAD, Parser, RangeStart, Reply, Request, Response, Transport,
    },
};
pub use crate::reconnect::Reconnect;
use crate::{
    av::{Packet, Track, Tracks},
    hub::{
        Dropper, Hub, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription, Timeline,
    },
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
    /// requests); skips the name lookup. Not used for a redirect to another host or port.
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
    /// [`pull`]: line the tracks up by the server's RTCP sender reports (default `true`);
    /// `false` keeps each track's times from its first packet's arrival.
    pub rtcp_sync: bool,
    /// [`pull`]: interval of the RTCP receiver reports (RFC 3550 6.4.2) to the server, one
    /// per track on its RTCP channel or port (packets lost, highest sequence number, jitter,
    /// delay since the track's last sender report, with a CNAME), the first half an interval
    /// after the track's first packet. Default 5 s; `Duration::ZERO` sends none (over UDP an
    /// empty receiver report then goes to each RTCP port with every keep-alive, for NAT
    /// bindings).
    pub receiver_report_interval: Duration,
    /// Connect again when a session fails ([`Reconnect`]). Default `None`: the client ends
    /// with the first error.
    pub reconnect: Option<Reconnect>,
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
            rtcp_sync: true,
            receiver_report_interval: Duration::from_secs(5),
            reconnect: None,
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
    /// The server moved the session to this URL (its `REDIRECT` request) and the client does
    /// not reconnect ([`RtspClientConfig::reconnect`] unset, or its engine gone): pull or push
    /// from there.
    Redirected(String),
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
            ClientError::Redirected(to) => write!(f, "RTSP session moved to {to}"),
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

    fn resolve(&self, cfg: &RtspClientConfig) -> Result<Vec<SocketAddr>, ClientError> {
        if let Some(a) = cfg.addr {
            return Ok(vec![a]);
        }
        self.lookup()
    }

    /// The addresses of the host (an IP literal as it is, a name looked up with the system
    /// resolver, which blocks), in the resolver's order.
    fn lookup(&self) -> Result<Vec<SocketAddr>, ClientError> {
        crate::reconnect::lookup(&self.host, self.port).map_err(ClientError::Resolve)
    }

    /// Whether `other` names the same server (host, case-insensitively, and port).
    fn same_server(&self, other: &Url) -> bool {
        self.host.eq_ignore_ascii_case(&other.host) && self.port == other.port
    }

    /// The URL a redirect's `location` points to: absolute (`rtsp://`), or an absolute path
    /// on this server. The credentials go along to the same server only, unless the location
    /// has its own.
    pub(crate) fn follow(&self, location: &str) -> Result<Url, ClientError> {
        let location = location.trim();
        let abs = if location.starts_with('/') {
            let rest = self.request.split_once("://").map_or("", |(_, r)| r);
            let authority = &rest[..rest.find(['/', '?']).unwrap_or(rest.len())];
            format!("rtsp://{authority}{location}")
        } else {
            location.to_owned()
        };
        let mut u = Url::parse(&abs)?;
        if u.user.is_none() && self.same_server(&u) {
            u.user.clone_from(&self.user);
            u.pass.clone_from(&self.pass);
        }
        Ok(u)
    }
}

/// Redirects followed in a row before the client gives up with the last one's status.
const MAX_REDIRECTS: usize = 5;
/// The longest a server's `REDIRECT` is waited for (a `Range` further away is cut to it).
const MAX_MOVE_WAIT: Duration = Duration::from_secs(86_400);

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
    /// A redirect (300 to 303, 307, 308) with a `Location` before the session went live: the
    /// session ends and the client starts again there.
    Redirect {
        method: &'static str,
        status: u16,
        reason: String,
        location: String,
    },
    /// The server's `REDIRECT` request while live: the session moves to `url` at `at`.
    Moved { url: Url, at: Instant },
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
    /// When PLAY or RECORD was answered (where a `REDIRECT`'s `npt` range counts from).
    live_at: Option<Instant>,
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
            live_at: None,
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
                    // A server's own request: acknowledge the harmless ones (keep-alives),
                    // follow a REDIRECT.
                    let (st, moved) = match req.method.as_str() {
                        "OPTIONS" | "GET_PARAMETER" | "SET_PARAMETER" => (200, None),
                        "REDIRECT" => self.redirected(&req, now),
                        _ => (501, None),
                    };
                    let mut resp = Response::new(st);
                    if let Some(id) = self.session.as_ref().filter(|_| moved.is_some()) {
                        resp = resp.header("Session", id.clone());
                    }
                    out.push(Event::Send(resp.encode(req.cseq())));
                    out.extend(moved);
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

    /// A server's `REDIRECT` (RFC 2326 10.15): the status to answer and, when it is followed,
    /// where and when the session moves. Only a live session moves (455 before); the
    /// `Location` is needed (400 without, or when it is not an RTSP URL or absolute path); a
    /// `Session` that is not ours is 454. The `Range` start says when: `clock=` a UTC time,
    /// `npt=` counted from PLAY or RECORD; at once without (or when it passed).
    fn redirected(&self, req: &Request, now: Instant) -> (u16, Option<Event>) {
        if self.step != Step::Live {
            return (455, None);
        }
        if let (Some(theirs), Some(ours)) = (req.header("session"), &self.session) {
            if theirs.split(';').next().unwrap_or("").trim() != ours {
                return (454, None);
            }
        }
        let url = req
            .header("location")
            .map(str::trim)
            .filter(|l| clean(l))
            .and_then(|l| self.url.follow(l).ok());
        let Some(url) = url else {
            return (400, None);
        };
        let wait = match req.header("range").and_then(message::range_start) {
            Some(RangeStart::Clock(t)) => t.duration_since(SystemTime::now()).unwrap_or_default(),
            Some(RangeStart::Npt(d)) => {
                let since = now.saturating_duration_since(self.live_at.unwrap_or(now));
                d.saturating_sub(since)
            }
            None => Duration::ZERO,
        };
        let at = now + wait.min(MAX_MOVE_WAIT);
        (200, Some(Event::Moved { url, at }))
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
        // 304 (Not Modified) and 305 (Use Proxy: the location is a proxy) are not redirects.
        if matches!(r.status, 300..=303 | 307 | 308) && self.step != Step::Live {
            if let Some(loc) = r.header("location").filter(|l| clean(l.trim())) {
                out.push(Event::Redirect {
                    method: p.method,
                    status: r.status,
                    reason: r.reason.clone(),
                    location: loc.trim().to_owned(),
                });
                return;
            }
        }
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
                self.live_at = Some(now);
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
    /// Pull: the reserved path, until DESCRIBE answers (shared with the [`Client`], which
    /// keeps it across sessions).
    publisher: Option<Arc<Publisher>>,
    recorder: Option<Arc<Mutex<Recorder>>>,
    sub: Option<Subscription>,
    /// UDP: RTP and RTCP sockets of each track, in order.
    udp: Vec<(Arc<UdpBinding>, Arc<UdpBinding>)>,
    error: Option<ClientError>,
    server_ip: Option<IpAddr>,
    local_ip: Option<IpAddr>,
    keepalive_at: Option<Instant>,
    rr_ssrc: u32,
    /// Where the server redirected the session (a 3xx before it went live).
    redirect: Option<String>,
    /// Where and when the server moves the live session (its `REDIRECT`).
    moving: Option<(Url, Instant)>,
    /// Another address of the server is tried if this one does not connect (the client's
    /// [`session`](Client::session) loop does, not [`Client::ended`]); cleared once connected.
    next_addr: bool,
}

/// One session (one RTSP connection): what the connection, the timer and the caller share.
struct Shared {
    /// The client the session belongs to, told when it ends (none in the fuzzer, where the
    /// session closes the hub side itself).
    client: Weak<Client>,
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
        publisher: Option<Arc<Publisher>>,
        path: &str,
        timers: bool,
        client: Weak<Client>,
    ) -> Arc<Shared> {
        let mut b = [0u8; 4];
        let _ = only_crypto::rand::fill_random(&mut b);
        Arc::new(Shared {
            client,
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
                redirect: None,
                moving: None,
                next_addr: false,
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
                        Some(r) => {
                            let r = r
                                .sync(self.cfg.rtcp_sync)
                                .reports(self.cfg.receiver_report_interval, g.rr_ssrc);
                            g.recorder = Some(Arc::new(Mutex::new(r)));
                        }
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
                Event::Moved { url, at } => {
                    let due = at <= Instant::now();
                    if due {
                        fail.get_or_insert(ClientError::Redirected(url.request.clone()));
                    }
                    g.moving = Some((url, at));
                }
                Event::Redirect {
                    method,
                    status,
                    reason,
                    location,
                } => {
                    g.redirect = Some(location);
                    fail.get_or_insert(ClientError::Status {
                        method,
                        status,
                        reason,
                    });
                }
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
        let now = Instant::now();
        let rec = {
            let mut g = lock(&self.inner);
            if g.phase == Phase::Done {
                return;
            }
            g.m.feed(data, now, &mut events);
            self.handle(&mut g, events, &mut media, &mut fail);
            g.recorder.clone()
        };
        if !media.is_empty() {
            self.touch();
            if let Some(rec) = rec {
                let mut r = lock(&rec);
                for (m, rtcp, d) in &media {
                    if *rtcp || rtp::is_rtcp(d) {
                        r.rtcp(*m, d);
                    } else {
                        r.push(*m, d, now);
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
            g.next_addr = false;
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
        let mut reports = None;
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
                if let Some((url, _)) = g.moving.as_ref().filter(|(_, at)| now >= *at) {
                    fail = Some(ClientError::Redirected(url.request.clone()));
                }
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
                    if !self.record && self.cfg.receiver_report_interval.is_zero() {
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
                if let Some(rec) = g.recorder.clone() {
                    let due = lock(&rec).take_reports();
                    if !due.is_empty() {
                        reports = Some((due, self.report_routes(&g)));
                    }
                }
            }
        }
        for (sock, to, pkt) in rr {
            let _ = sock.send_to(&pkt, to);
        }
        if let Some((due, routes)) = reports {
            for (media, pkt) in due {
                match routes.iter().find(|r| r.0 == media) {
                    Some((_, ReportRoute::Tcp(c, ch))) => {
                        let mut b = Vec::with_capacity(pkt.len() + 4);
                        message::interleaved(*ch, &pkt, &mut b);
                        let _ = c.send_owned(b);
                    }
                    Some((_, ReportRoute::Udp(sock, to))) => {
                        let _ = sock.send_to(&pkt, *to);
                    }
                    None => {}
                }
            }
        }
        if let Some(e) = fail {
            self.finish(Some(e));
        }
    }

    /// Where each set-up media's receiver reports go: its interleaved RTCP channel, or the
    /// server's RTCP port from the track's RTCP socket.
    fn report_routes(&self, g: &Inner) -> Vec<(usize, ReportRoute)> {
        let media = g.m.plan_media();
        if self.cfg.transport == RtspTransport::Tcp {
            let Some(c) = &g.conn else { return Vec::new() };
            media
                .into_iter()
                .zip(g.m.channels())
                .map(|(m, (_, ch))| (m, ReportRoute::Tcp(c.clone(), ch)))
                .collect()
        } else {
            let Some(ip) = g.server_ip else {
                return Vec::new();
            };
            media
                .into_iter()
                .zip(g.m.server_ports())
                .zip(&g.udp)
                .filter_map(|((m, sp), (_, rtcp))| {
                    let (_, p) = sp?;
                    Some((m, ReportRoute::Udp(rtcp.clone(), SocketAddr::new(ip, p))))
                })
                .collect()
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
    /// the hub subscription and the UDP sockets are closed, and the client hears of it (it
    /// decides about the hub path and reconnecting).
    fn finish(&self, err: Option<ClientError>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let (conn, bye, rec, publisher, sub, udp, err) = {
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
                g.error.clone(),
            )
        };
        self.cond.notify_all();
        drop(sub);
        let client = self.client.upgrade();
        if client.is_none() {
            if let Some(r) = &rec {
                lock(r).close();
            }
        }
        drop((rec, publisher));
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
        if let Some(c) = client {
            c.ended(self, err);
        }
    }
}

/// Where a receiver report goes ([`Shared::report_routes`]).
enum ReportRoute {
    Tcp(Conn<ClientConn>, u8),
    Udp(Arc<UdpBinding>, SocketAddr),
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
        if let Some(r) = self.rec.upgrade() {
            if self.rtcp || rtp::is_rtcp(data) {
                lock(&r).rtcp(self.media, data);
            } else {
                let mut r = lock(&r);
                let at = if r.reports_on() {
                    Instant::now()
                } else {
                    r.start
                };
                r.push(self.media, data, at);
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

// ---- the client: sessions, reconnects -----------------------------------------------------

/// What a client keeps across its sessions.
struct Client {
    /// The URL the client was given.
    url: Url,
    cfg: RtspClientConfig,
    path: String,
    /// Push: the hub the stream is read from.
    hub: Option<Hub>,
    /// Pull: the reserved hub path, held across sessions.
    publisher: Option<Arc<Publisher>>,
    st: Mutex<ClientSt>,
    /// Over for good: set once the hub path is free again.
    closed: AtomicBool,
}

// `RtspClient` stays unwind safe (as it was before the client kept the hub and the publisher
// itself): its state is behind locks that ignore poisoning, and the hub and the publisher
// guard their own state the same way, so nothing is seen half updated after a panic.
impl std::panic::UnwindSafe for Client {}
impl std::panic::RefUnwindSafe for Client {}

#[derive(Default)]
struct ClientSt {
    /// The current session.
    session: Option<Arc<Shared>>,
    /// Closed, or ending for good: no new session starts.
    ending: bool,
    /// A session went live: later failures reconnect (the first session's error is returned
    /// by [`pull`] / [`push`] instead).
    established: bool,
    /// Tries since the last live session.
    attempts: u32,
    reconnects: u64,
    /// The error that ended the client.
    error: Option<ClientError>,
    /// The error that ended the last session.
    last_error: Option<ClientError>,
    /// Where a `301 Moved Permanently` sent the client: later sessions start there.
    moved: Option<Url>,
}

/// Why a session could not start: before it existed (a lookup, a redirect's URL, the hub;
/// the caller handles it), or the session failed (and the client heard of it through
/// [`Client::ended`]).
enum Failed {
    Before(ClientError),
    Session(ClientError),
}

impl Failed {
    fn error(self) -> ClientError {
        match self {
            Failed::Before(e) | Failed::Session(e) => e,
        }
    }
}

/// Whether a session that ended with `err` is worth trying again.
fn retryable(err: Option<&ClientError>) -> bool {
    // A lookup that fails on a reconnect is tried again (the name may come back); the first
    // session's failures go to the caller instead.
    match err {
        None
        | Some(
            ClientError::Url(_)
            | ClientError::Redirected(_)
            | ClientError::Unauthorized
            | ClientError::NoTracks
            | ClientError::Hub(_),
        ) => false,
        Some(ClientError::Status { status, .. }) => !matches!(status, 401 | 403),
        Some(_) => true,
    }
}

impl Client {
    /// The session machine of `url`: playing, or recording the hub stream's `tracks`.
    fn machine(&self, url: &Url, tracks: Option<&Tracks>) -> Result<Machine, ClientError> {
        Ok(match tracks {
            Some(t) => Machine::record(url.clone(), t, &self.cfg)?,
            None => Machine::play(url.clone(), &self.cfg),
        })
    }

    /// The address to dial for `url`: [`RtspClientConfig::addr`] for the URL the client was
    /// given, else the host looked up now (again for every session, so a server that moved
    /// to another address is found).
    fn address(&self, url: &Url) -> Result<Vec<SocketAddr>, ClientError> {
        match self.cfg.addr {
            Some(a) if self.url.same_server(url) => Ok(vec![a]),
            _ => url.lookup(),
        }
    }

    /// Starts a session on `engine` and drives it until it plays or records (a push
    /// subscribes to the hub stream, of `tracks`), following up to [`MAX_REDIRECTS`]
    /// redirects. `addrs`: the addresses of the client's URL, when just looked up; each
    /// session dials the addresses its server has in turn until one connects. `start`: the
    /// URL to start at (a server's `REDIRECT`), else the client's (or where a `301` sent it).
    /// A session's failures also reach [`ended`](Self::ended).
    fn session(
        self: &Arc<Self>,
        engine: &Engine,
        tracks: Option<&Tracks>,
        mut addrs: Option<Vec<SocketAddr>>,
        start: Option<Url>,
    ) -> Result<(), Failed> {
        let mut url = start.unwrap_or_else(|| {
            lock(&self.st)
                .moved
                .clone()
                .unwrap_or_else(|| self.url.clone())
        });
        let mut hops = 0;
        loop {
            let all = match addrs.take() {
                Some(a) => a,
                None => self.address(&url).map_err(Failed::Before)?,
            };
            let (s, to, res) = self.dial_any(engine, &url, tracks, &all)?;
            if let Err(e) = res {
                let Some(loc) = lock(&s.inner).redirect.take() else {
                    return Err(Failed::Session(e));
                };
                // Redirected: [`ended`](Self::ended) left it to this loop.
                if hops == MAX_REDIRECTS {
                    return Err(Failed::Before(e));
                }
                hops += 1;
                url = url.follow(&loc).map_err(Failed::Before)?;
                if matches!(e, ClientError::Status { status: 301, .. }) {
                    lock(&self.st).moved = Some(url.clone());
                }
                continue;
            }
            if let (Some(hub), Some(t)) = (&self.hub, tracks) {
                start_push(&s, hub, t, to).map_err(Failed::Session)?;
            }
            let mut g = lock(&self.st);
            if !g.session.as_ref().is_some_and(|x| Arc::ptr_eq(x, &s)) {
                // It ended right after going live: `ended` took it (and, after a first session,
                // scheduled the next try); the first one's error goes to the caller.
                drop(g);
                let e = lock(&s.inner).error.clone().unwrap_or(ClientError::Closed);
                return Err(Failed::Session(e));
            }
            if g.established {
                g.reconnects += 1;
            }
            g.established = true;
            g.attempts = 0;
            g.last_error = None;
            return Ok(());
        }
    }

    /// A session at `url` dialing `addrs` in turn: the first that connects carries it
    /// (another is tried only when the connect fails or times out). Returns the session,
    /// the address dialed and how it went.
    #[allow(clippy::type_complexity)]
    fn dial_any(
        self: &Arc<Self>,
        engine: &Engine,
        url: &Url,
        tracks: Option<&Tracks>,
        addrs: &[SocketAddr],
    ) -> Result<(Arc<Shared>, SocketAddr, Result<(), ClientError>), Failed> {
        let mut i = 0;
        loop {
            let to = addrs[i];
            let m = self.machine(url, tracks).map_err(Failed::Before)?;
            let s = Shared::new(
                self.cfg.clone(),
                m,
                self.publisher.clone(),
                &self.path,
                true,
                Arc::downgrade(self),
            );
            let more = i + 1 < addrs.len();
            lock(&s.inner).next_addr = more;
            {
                let mut g = lock(&self.st);
                if g.ending {
                    return Err(Failed::Before(ClientError::Closed));
                }
                g.session = Some(s.clone());
            }
            let res = establish(engine, to, &s);
            let unreached = matches!(
                res,
                Err(ClientError::Connect(_) | ClientError::Timeout("connect"))
            );
            if more && unreached && lock(&s.inner).next_addr {
                i += 1;
                continue;
            }
            return Ok((s, to, res));
        }
    }

    /// Session `s` ended with `err`: reconnect, or end the client.
    fn ended(self: &Arc<Self>, s: &Shared, err: Option<ClientError>) {
        let moved = {
            let mut g = lock(&s.inner);
            if g.redirect.is_some() || g.next_addr {
                return; // [`session`](Self::session) follows it, or dials the next address
            }
            g.moving.take().map(|(u, _)| u)
        };
        {
            let mut g = lock(&self.st);
            if !g
                .session
                .as_ref()
                .is_some_and(|x| std::ptr::eq(&raw const **x, s))
            {
                return; // replaced, or taken by close
            }
            g.session = None;
            if g.ending || !g.established {
                return;
            }
        }
        match moved {
            Some(url) => self.follow(url),
            None => self.failed(err),
        }
    }

    /// The server moved the live session to `url`: a new session there at once (no backoff,
    /// on a thread of its own), on the reconnect engine; without one the client ends with
    /// [`ClientError::Redirected`]. Later reconnects start from the client's URL again.
    fn follow(self: &Arc<Self>, url: Url) {
        let Some(engine) = self.cfg.reconnect.as_ref().and_then(Reconnect::engine) else {
            return self.end(Some(ClientError::Redirected(url.request)));
        };
        let c = self.clone();
        let spawned = std::thread::Builder::new()
            .name("only-rtsp-redirect".into())
            .spawn(move || c.attempt(&engine, Some(url)));
        if let Err(e) = spawned {
            self.end(Some(ClientError::Io(e.to_string())));
        }
    }

    /// A session (or a try before one existed) failed with `err`.
    fn failed(self: &Arc<Self>, err: Option<ClientError>) {
        let mut g = lock(&self.st);
        if g.ending {
            return;
        }
        g.last_error.clone_from(&err);
        let retry = self
            .cfg
            .reconnect
            .as_ref()
            .filter(|r| retryable(err.as_ref()) && r.allows(g.attempts));
        if let Some(r) = retry {
            let delay = r.delay(g.attempts);
            g.attempts += 1;
            drop(g);
            let w = Arc::downgrade(self);
            crate::timer::after(delay, move || {
                let Some(c) = w.upgrade() else { return };
                if lock(&c.st).ending {
                    return;
                }
                let Some(engine) = c.cfg.reconnect.as_ref().and_then(Reconnect::engine) else {
                    return c.end(Some(ClientError::Closed));
                };
                // The handshake blocks: a short-lived thread of its own, not the timer's.
                let c2 = c.clone();
                let spawned = std::thread::Builder::new()
                    .name("only-rtsp-reconnect".into())
                    .spawn(move || c2.attempt(&engine, None));
                if let Err(e) = spawned {
                    c.end(Some(ClientError::Io(e.to_string())));
                }
            });
            return;
        }
        drop(g);
        self.end(err);
    }

    /// One reconnect try (on its own thread), at `start` (a server's `REDIRECT`) or the
    /// client's URL.
    fn attempt(self: &Arc<Self>, engine: &Engine, start: Option<Url>) {
        let tracks = match &self.hub {
            Some(hub) => match wait_tracks(hub, &self.path, self.cfg.push_wait) {
                Ok(t) => Some(t),
                Err(e) => return self.failed(Some(e)),
            },
            None => None,
        };
        // A session's failures went through `ended`.
        if let Err(Failed::Before(e)) = self.session(engine, tracks.as_ref(), None, start) {
            self.failed(Some(e));
        }
    }

    /// Ends the client for good with `err`: the hub path is freed before it says so.
    fn end(&self, err: Option<ClientError>) {
        let session = {
            let mut g = lock(&self.st);
            if g.ending && self.closed.load(Ordering::Acquire) {
                return;
            }
            g.ending = true;
            if g.error.is_none() {
                g.error = err;
            }
            g.session.take()
        };
        if let Some(s) = session {
            s.finish(None);
        }
        if let Some(p) = &self.publisher {
            p.close();
        }
        self.closed.store(true, Ordering::Release);
    }
}

/// Waits up to `wait` for the hub stream at `path` to be live, returning its tracks.
fn wait_tracks(hub: &Hub, path: &str, wait: Duration) -> Result<Tracks, ClientError> {
    let deadline = Instant::now() + wait;
    loop {
        if let Some(i) = hub
            .stream_info(path)
            .filter(|i| i.publishing && !i.tracks.is_empty())
        {
            return Ok(i.tracks);
        }
        if Instant::now() >= deadline {
            return Err(ClientError::Hub(HubError::NotFound));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---- the public API ------------------------------------------------------------------------

/// A running RTSP client ([`pull`] or [`push`]): its session, and the ones that follow when it
/// reconnects. Dropping it closes the client, like [`close`](Self::close).
pub struct RtspClient(Arc<Client>);

impl fmt::Debug for RtspClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspClient")
            .field("path", &self.0.path)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl RtspClient {
    /// The hub path the client publishes to ([`pull`]) or reads from ([`push`]).
    pub fn path(&self) -> &str {
        &self.0.path
    }

    /// Ends the client: sends TEARDOWN (best effort, not waited for) and closes the
    /// connection, the UDP sockets and the hub side (a pulled stream is unpublished, a push
    /// unsubscribes); a pending reconnect is called off. A pull's hub path is free again when
    /// this returns. Idempotent; [`error`](Self::error) stays `None` if nothing failed first.
    pub fn close(&self) {
        self.0.end(None);
    }

    /// Whether the client is over: closed, or ended by an error it does not reconnect after.
    /// A pull's hub path is free once this says so.
    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }

    /// The error that ended the client; while it reconnects, the one that ended the last
    /// session.
    pub fn error(&self) -> Option<ClientError> {
        let g = lock(&self.0.st);
        g.error.clone().or_else(|| g.last_error.clone())
    }

    /// Sessions made after the first ([`RtspClientConfig::reconnect`]).
    pub fn reconnects(&self) -> u64 {
        lock(&self.0.st).reconnects
    }

    /// Whether a session currently plays or records (`false` while connecting again).
    pub fn is_live(&self) -> bool {
        let s = lock(&self.0.st).session.clone();
        s.is_some_and(|s| lock(&s.inner).phase == Phase::Live)
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
/// closing, no media for [`RtspClientConfig::idle_timeout`], or a keep-alive unanswered. With
/// [`RtspClientConfig::reconnect`] such an error starts a new session instead, the path kept.
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
    let addrs = url.resolve(&cfg)?;
    let publisher = hub
        .reserve(path, PeerInfo::new("rtsp", addrs.first().copied(), ""))
        .map_err(ClientError::Hub)?;
    let c = Arc::new(Client {
        url,
        cfg,
        path: path.to_owned(),
        hub: None,
        publisher: Some(Arc::new(publisher)),
        st: Mutex::new(ClientSt::default()),
        closed: AtomicBool::new(false),
    });
    match c.session(engine, None, Some(addrs), None) {
        Ok(()) => Ok(RtspClient(c)),
        Err(e) => {
            let e = e.error();
            c.end(Some(e.clone()));
            Err(e)
        }
    }
}

/// Records the hub stream at `path` to `url` (RTSP ANNOUNCE and RECORD), from its cached GOP
/// on. Waits up to [`RtspClientConfig::push_wait`] for the stream to be live (its tracks go
/// into the ANNOUNCE's SDP), then returns once the server answered RECORD; afterwards the
/// session runs until [`RtspClient::close`], a drop, or an error ([`RtspClient::error`]): the
/// connection closing, the stream ending ([`ClientError::Hub`]) or changing its codecs, or the
/// server reading too slowly ([`ClientError::WriteQueueFull`]). With
/// [`RtspClientConfig::reconnect`] such an error (but the stream ending) starts a new session
/// instead, announcing the stream's current tracks.
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
    let addrs = url.resolve(&cfg)?;
    let tracks = wait_tracks(hub, path, cfg.push_wait)?;
    let c = Arc::new(Client {
        url,
        cfg,
        path: path.to_owned(),
        hub: Some(hub.clone()),
        publisher: None,
        st: Mutex::new(ClientSt::default()),
        closed: AtomicBool::new(false),
    });
    match c.session(engine, Some(&tracks), Some(addrs), None) {
        Ok(()) => Ok(RtspClient(c)),
        Err(e) => {
            let e = e.error();
            c.end(Some(e.clone()));
            Err(e)
        }
    }
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
        Shared::new(cfg, m, None, "src", false, Weak::new())
    } else {
        let Ok(p) = hub.reserve("dst", PeerInfo::default()) else {
            return;
        };
        let m = Machine::play(url, &cfg);
        Shared::new(cfg, m, Some(Arc::new(p)), "dst", false, Weak::new())
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

    fn set_name(host: &str, addr: Option<SocketAddr>) {
        crate::reconnect::names::set(host, addr.as_slice());
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
            ["[::1]:554".parse().unwrap()]
        );
        let u = Url::parse("rtsp://user@10.0.0.1").unwrap();
        assert_eq!((u.user.as_deref(), u.pass.as_deref()), (Some("user"), None));
        assert_eq!(u.request, "rtsp://10.0.0.1");
        let cfg = RtspClientConfig {
            addr: Some("127.0.0.1:9".parse().unwrap()),
            ..RtspClientConfig::default()
        };
        assert_eq!(u.resolve(&cfg).unwrap(), ["127.0.0.1:9".parse().unwrap()]);
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

    #[test]
    fn redirect_urls() {
        let u = Url::parse("rtsp://u:p@cam.local:8554/live/s?t=1").unwrap();
        // Absolute path: same server, credentials kept.
        let r = u.follow("/other/x?y=2").unwrap();
        assert_eq!(r.request, "rtsp://cam.local:8554/other/x?y=2");
        assert_eq!(
            (r.user.as_deref(), r.pass.as_deref()),
            (Some("u"), Some("p"))
        );
        // The same server named in another case: kept too.
        let r = u.follow("rtsp://CAM.local:8554/a").unwrap();
        assert_eq!(r.user.as_deref(), Some("u"));
        // Another server (or port): dropped, unless the location has its own.
        assert_eq!(u.follow("rtsp://other:8554/a").unwrap().user, None);
        assert_eq!(u.follow("rtsp://cam.local:554/a").unwrap().user, None);
        let r = u.follow("rtsp://v:q@other/a").unwrap();
        assert_eq!(
            (r.user.as_deref(), r.pass.as_deref()),
            (Some("v"), Some("q"))
        );
        assert!(matches!(u.follow("http://x/y"), Err(ClientError::Url(_))));
        assert!(matches!(
            u.follow("relative/path"),
            Err(ClientError::Url(_))
        ));
    }

    /// A 3xx with a `Location` before the session is live is a redirect; without one, a
    /// refusal; a 3xx answering a keep-alive is not followed.
    #[test]
    fn redirects_in_the_machine() {
        let now = Instant::now();
        let cfg = RtspClientConfig::default();
        let mut m = Machine::play(Url::parse("rtsp://127.0.0.1/a").unwrap(), &cfg);
        let mut ev = Vec::new();
        m.start(now, &mut ev);
        ev.clear();
        m.feed(&reply(1, "RTSP/1.0 200 OK", ""), now, &mut ev);
        ev.clear();
        let r = b"RTSP/1.0 302 Found\r\nCSeq: 2\r\nLocation: rtsp://10.0.0.2/b\r\n\r\n";
        m.feed(r, now, &mut ev);
        assert!(matches!(
            &ev[..],
            [Event::Redirect { method: "DESCRIBE", status: 302, location, .. }]
                if location == "rtsp://10.0.0.2/b"
        ));
        let mut m = Machine::play(Url::parse("rtsp://127.0.0.1/a").unwrap(), &cfg);
        let mut ev = Vec::new();
        m.start(now, &mut ev);
        ev.clear();
        m.feed(b"RTSP/1.0 301 Moved\r\nCSeq: 1\r\n\r\n", now, &mut ev);
        // OPTIONS refused is not fatal (DESCRIBE follows); DESCRIBE without a location is.
        ev.clear();
        m.feed(b"RTSP/1.0 305 Use Proxy\r\nCSeq: 2\r\n\r\n", now, &mut ev);
        assert!(matches!(
            &ev[..],
            [Event::Fail(ClientError::Status { status: 305, .. })]
        ));
    }

    /// A server's `REDIRECT` while live: answered 200 with the session, a move to the
    /// location at the `Range` start (a clock time, an npt from RECORD, or at once); refused
    /// before the session is live, without a usable location, or naming another session.
    #[test]
    fn server_redirects_in_the_machine() {
        let cfg = RtspClientConfig::default();
        let tracks: Tracks = Arc::from(vec![Track::aac(vec![0x12, 0x10])]);
        let live = |now: Instant| {
            let url = Url::parse("rtsp://u:p@127.0.0.1:8554/live/out").unwrap();
            let mut m = Machine::record(url, &tracks, &cfg).unwrap();
            let mut ev = Vec::new();
            m.start(now, &mut ev);
            // Before it is live: 455.
            m.feed(
                b"REDIRECT rtsp://127.0.0.1:8554/live/out RTSP/1.0\r\nCSeq: 1\r\nLocation: rtsp://10.0.0.2/x\r\n\r\n",
                now,
                &mut ev,
            );
            let r = sent(&mut ev);
            assert!(r.iter().any(|r| r.starts_with("RTSP/1.0 455 ")), "{r:?}");
            for (cseq, head) in [
                (1, "RTSP/1.0 200 OK"),
                (2, "RTSP/1.0 200 OK"),
                (
                    3,
                    "RTSP/1.0 200 OK\r\nSession: s1;timeout=60\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1",
                ),
                (4, "RTSP/1.0 200 OK\r\nSession: s1"),
            ] {
                m.feed(&reply(cseq, head, ""), now, &mut ev);
            }
            assert!(ev.iter().any(|e| matches!(e, Event::Live)));
            ev.clear();
            m
        };
        let now = Instant::now();
        let redirect = |m: &mut Machine, extra: &str, at: Instant| {
            let mut ev = Vec::new();
            let req = format!(
                "REDIRECT rtsp://127.0.0.1:8554/live/out RTSP/1.0\r\nCSeq: 7\r\n{extra}\r\n"
            );
            m.feed(req.as_bytes(), at, &mut ev);
            ev
        };
        // At once, to an absolute path on the same server: the credentials go along.
        let mut m = live(now);
        let mut ev = redirect(&mut m, "Session: s1\r\nLocation: /live/other\r\n", now);
        match ev.as_slice() {
            [Event::Send(b), Event::Moved { url, at }] => {
                let r = String::from_utf8_lossy(b);
                assert!(
                    r.starts_with("RTSP/1.0 200 OK\r\nCSeq: 7\r\nSession: s1\r\n"),
                    "{r}"
                );
                assert_eq!(url.request, "rtsp://127.0.0.1:8554/live/other");
                assert_eq!(url.user.as_deref(), Some("u"));
                assert_eq!(*at, now);
            }
            e => panic!("{e:?}"),
        }
        ev.clear();
        // A clock time 30 s ahead, to another server (no credentials).
        let t = SystemTime::now() + Duration::from_secs(30);
        let ev = redirect(
            &mut m,
            &format!(
                "Location: rtsp://10.0.0.2:554/x\r\nRange: {}\r\n",
                message::clock_range(t)
            ),
            now,
        );
        match ev.as_slice() {
            [Event::Send(_), Event::Moved { url, at }] => {
                assert_eq!(url.request, "rtsp://10.0.0.2:554/x");
                assert_eq!(url.user, None);
                let wait = at.duration_since(now);
                assert!(
                    wait > Duration::from_secs(28) && wait <= Duration::from_secs(30),
                    "{wait:?}"
                );
            }
            e => panic!("{e:?}"),
        }
        // An npt counted from RECORD (2 s ago), a clock time passed: 3 s from now, at once.
        let ev = redirect(
            &mut m,
            "Location: rtsp://10.0.0.2/x\r\nRange: npt=5-\r\n",
            now + Duration::from_secs(2),
        );
        assert!(
            matches!(ev.as_slice(), [Event::Send(_), Event::Moved { at, .. }] if *at == now + Duration::from_secs(5))
        );
        let ev = redirect(
            &mut m,
            "Location: rtsp://10.0.0.2/x\r\nRange: clock=19960213T143205Z-\r\n",
            now,
        );
        assert!(matches!(ev.as_slice(), [Event::Send(_), Event::Moved { at, .. }] if *at == now));
        // Refusals.
        for (extra, status) in [
            ("", 400),
            ("Location: http://10.0.0.2/x\r\n", 400),
            ("Location: rtsps://10.0.0.2/x\r\n", 400),
            ("Session: other\r\nLocation: rtsp://10.0.0.2/x\r\n", 454),
        ] {
            let mut ev = redirect(&mut m, extra, now);
            let r = sent(&mut ev);
            assert_eq!(r.len(), 1);
            assert!(
                r[0].starts_with(&format!("RTSP/1.0 {status} ")),
                "{extra}: {}",
                r[0]
            );
            assert!(!r[0].contains("Session:"));
        }
    }

    /// One looped sample published at `path` in real time until the flag is set.
    fn feed_sample(hub: &Hub, path: &str) -> Arc<AtomicBool> {
        use crate::flv::{Decoder, Demuxer, Event as F};
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        let data = include_bytes!("../../testdata/h264_aac.flv");
        for t in Demuxer::new().feed(data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    F::Tracks(t) => tracks = Some(t),
                    F::Packet(p) => pkts.push(p),
                }
            }
        }
        let p = hub
            .publish(path, tracks.unwrap(), PeerInfo::default())
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        std::thread::spawn(move || {
            let span = pkts.iter().map(|p| p.dts).max().unwrap_or(0) + 40_000_000;
            let start = Instant::now();
            for round in 0.. {
                for pkt in &pkts {
                    if s.load(Ordering::Relaxed) {
                        p.close();
                        return;
                    }
                    let off = round * span;
                    let at = Duration::from_nanos((pkt.dts + off).max(0) as u64);
                    if let Some(d) = at.checked_sub(start.elapsed()) {
                        std::thread::sleep(d);
                    }
                    p.write(Packet::new(
                        pkt.track,
                        pkt.dts + off,
                        pkt.pts + off,
                        pkt.keyframe,
                        pkt.data.clone(),
                    ));
                }
            }
        });
        stop
    }

    /// An RTSP server of this crate with `src` published, on an engine that also dials.
    fn media_server() -> (Hub, Arc<Engine>, SocketAddr, Arc<AtomicBool>) {
        let hub = Hub::default();
        let srv = super::super::RtspServer::new(hub.clone(), super::super::RtspConfig::default());
        let e = Arc::new(
            Engine::builder()
                .listen(only::Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(srv))
                .client_threads(1)
                .udp_client_threads(1)
                .build()
                .unwrap(),
        );
        e.start().unwrap();
        let addr = e.local_addrs()[0];
        let stop = feed_sample(&hub, "src");
        (hub, e, addr, stop)
    }

    fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Packets of `path` arriving from now on.
    fn packets_after(hub: &Hub, path: &str) -> u64 {
        hub.stream_info(path)
            .filter(|i| i.publishing)
            .map_or(0, |i| i.packets_in)
    }

    /// A server answering every request but OPTIONS with `status` and the `Location` that
    /// `location` gives for the connection number; counts its connections.
    fn redirector(
        status: u16,
        location: impl Fn(usize) -> String + Send + 'static,
    ) -> (SocketAddr, Arc<AtomicU64>, Arc<AtomicBool>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let (conns, stop) = (
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
        );
        let (c2, s2) = (conns.clone(), stop.clone());
        std::thread::spawn(move || {
            while !s2.load(Ordering::Relaxed) {
                let Ok((mut s, _)) = l.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let n = c2.fetch_add(1, Ordering::SeqCst) as usize;
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                'conn: while let Ok(k) = s.read(&mut b) {
                    if k == 0 {
                        break;
                    }
                    buf.extend_from_slice(&b[..k]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        buf.drain(..end + 4);
                        let cseq = head
                            .lines()
                            .find_map(|l| l.strip_prefix("CSeq: "))
                            .unwrap_or("0")
                            .to_owned();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .map_or(0, |v| v.trim().parse().unwrap());
                        buf.drain(..len.min(buf.len()));
                        let r = if head.starts_with("OPTIONS") {
                            format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n\r\n")
                        } else {
                            format!(
                                "RTSP/1.0 {status} Moved\r\nCSeq: {cseq}\r\nLocation: {}\r\n\r\n",
                                location(n)
                            )
                        };
                        if s.write_all(r.as_bytes()).is_err() {
                            break 'conn;
                        }
                    }
                }
            }
        });
        (addr, conns, stop)
    }

    /// Pull and push follow 302s (two in a row) to the server that has the stream; a 301
    /// is remembered for the next session; a redirect loop ends after `MAX_REDIRECTS` with
    /// the last refusal.
    #[test]
    fn clients_follow_redirects() {
        let (hub, e, media, stop) = media_server();
        let (hop2, _, s2) = redirector(302, move |_| format!("rtsp://{media}/src"));
        let (hop1, _, s1) = redirector(302, move |_| format!("rtsp://{hop2}/src"));
        let pulled = pull(
            &e,
            &format!("rtsp://{hop1}/x"),
            &hub,
            "pulled",
            RtspClientConfig::default(),
        )
        .unwrap();
        wait_until("pulled live", 10, || packets_after(&hub, "pulled") > 20);
        drop(pulled);
        // Push: ANNOUNCE redirected.
        let (hop, _, s3) = redirector(307, move |_| format!("rtsp://{media}/pushed"));
        let pushed = push(
            &e,
            &format!("rtsp://{hop}/x"),
            &hub,
            "src",
            RtspClientConfig::default(),
        )
        .unwrap();
        wait_until("pushed live", 10, || packets_after(&hub, "pushed") > 20);
        drop(pushed);
        // A loop: the bound, with the last refusal.
        let (lp, conns, s4) = redirector(302, |_| "/again".to_owned());
        let r = pull(
            &e,
            &format!("rtsp://{lp}/x"),
            &hub,
            "loop",
            RtspClientConfig::default(),
        );
        assert!(matches!(
            r.unwrap_err(),
            ClientError::Status {
                method: "DESCRIBE",
                status: 302,
                ..
            }
        ));
        assert_eq!(conns.load(Ordering::SeqCst) as usize, MAX_REDIRECTS + 1);
        assert!(
            hub.reserve("loop", PeerInfo::default()).is_ok(),
            "path released"
        );
        // 301: reconnects go straight to the new place.
        let (moved, conns, s5) = redirector(301, move |_| format!("rtsp://{media}/src"));
        let cfg = RtspClientConfig {
            reconnect: Some(Reconnect::new(&e).initial_delay(Duration::from_millis(50))),
            ..RtspClientConfig::default()
        };
        let c = pull(&e, &format!("rtsp://{moved}/x"), &hub, "moved", cfg).unwrap();
        wait_until("moved live", 10, || packets_after(&hub, "moved") > 20);
        // Cut the session: the server drops its publisher and players.
        stop.store(true, Ordering::Relaxed);
        wait_until("moved session ends", 10, || !c.is_live());
        let stop = feed_sample(&hub, "src");
        wait_until("moved reconnected", 15, || {
            c.reconnects() >= 1 && c.is_live()
        });
        assert_eq!(conns.load(Ordering::SeqCst), 1, "the 301 was remembered");
        drop(c);
        for s in [s1, s2, s3, s4, s5, stop] {
            s.store(true, Ordering::Relaxed);
        }
        e.shutdown();
    }

    /// An RTSP server of this crate (its handle too) with `src` published.
    fn served() -> (
        Hub,
        super::super::RtspServer,
        Arc<Engine>,
        SocketAddr,
        Arc<AtomicBool>,
    ) {
        let hub = Hub::default();
        let srv = super::super::RtspServer::new(hub.clone(), super::super::RtspConfig::default());
        let e = Arc::new(
            Engine::builder()
                .listen(only::Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(srv.clone()))
                .client_threads(1)
                .udp_client_threads(1)
                .build()
                .unwrap(),
        );
        e.start().unwrap();
        srv.listen_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = e.local_addrs()[0];
        let stop = feed_sample(&hub, "src");
        (hub, srv, e, addr, stop)
    }

    /// A server moves its sessions with `REDIRECT`: a reconnecting pull and push (TCP and
    /// UDP) tear down and carry on at the other server (a push at the `Range` time, not
    /// before); a client that does not reconnect ends with the location; the moved sessions
    /// leave the first server's list.
    #[test]
    fn server_redirects_move_sessions() {
        use super::super::Redirect;
        let (hub_a, srv_a, e, a, stop_a) = served();
        let (hub_b, srv_b, e_b, b, stop_b) = served();
        let reconnecting = |t| RtspClientConfig {
            transport: t,
            reconnect: Some(Reconnect::new(&e).initial_delay(Duration::from_secs(30))),
            ..RtspClientConfig::default()
        };
        for t in [RtspTransport::Tcp, RtspTransport::Udp] {
            // Pull from a, moved to b's `src`.
            let pulled = pull(
                &e,
                &format!("rtsp://{a}/src"),
                &hub_a,
                "pulled",
                reconnecting(t),
            )
            .unwrap();
            wait_until("pulled live", 10, || packets_after(&hub_a, "pulled") > 20);
            let s = srv_a.sessions();
            assert_eq!(s.len(), 1, "{s:?}");
            assert_eq!(
                (s[0].path.as_str(), s[0].recording, s[0].redirected),
                ("src", false, false)
            );
            let n = srv_a.redirect_path("/src/", &Redirect::new(format!("rtsp://{b}/src")));
            assert_eq!(n, 1);
            wait_until("pull moved", 10, || {
                pulled.reconnects() == 1 && pulled.is_live() && srv_b.sessions().len() == 1
            });
            wait_until("a's session gone", 5, || srv_a.sessions().is_empty());
            let before = packets_after(&hub_a, "pulled");
            wait_until("pulled flows", 10, || {
                packets_after(&hub_a, "pulled") > before + 20
            });
            assert!(pulled.error().is_none(), "{:?}", pulled.error());
            drop(pulled);
            wait_until("b's session gone", 5, || srv_b.sessions().is_empty());
            // Push a's `src` to a's `pushed`, moved to b's `pushed` in 600 ms.
            let pushed = push(
                &e,
                &format!("rtsp://{a}/pushed"),
                &hub_a,
                "src",
                reconnecting(t),
            )
            .unwrap();
            wait_until("pushed live", 10, || packets_after(&hub_a, "pushed") > 20);
            let s = srv_a.sessions();
            let rec = s.iter().find(|s| s.recording).expect("recording session");
            assert_eq!(rec.path, "pushed");
            let at = SystemTime::now() + Duration::from_millis(600);
            let moved = Redirect::new(format!("rtsp://{b}/pushed")).at(at);
            assert!(srv_a.redirect_session(&rec.id, &moved));
            assert!(!srv_a.redirect_session("nope", &moved));
            assert!(srv_a.sessions()[0].redirected);
            std::thread::sleep(Duration::from_millis(300));
            assert_eq!(pushed.reconnects(), 0, "moved before its time");
            assert!(packets_after(&hub_b, "pushed") == 0);
            wait_until("push moved", 10, || {
                pushed.reconnects() == 1 && packets_after(&hub_b, "pushed") > 20
            });
            wait_until("a's pushed ends", 5, || {
                hub_a.stream_info("pushed").is_none_or(|i| !i.publishing)
            });
            drop(pushed);
            wait_until("b's session gone", 5, || srv_b.sessions().is_empty());
        }
        // Without reconnect: the client ends, with the location.
        let pulled = pull(
            &e,
            &format!("rtsp://{a}/src"),
            &hub_a,
            "once",
            RtspClientConfig::default(),
        )
        .unwrap();
        wait_until("once live", 10, || packets_after(&hub_a, "once") > 5);
        assert_eq!(
            srv_a.redirect_path("src", &Redirect::new(format!("rtsp://{b}/src"))),
            1
        );
        wait_until("once ends", 10, || pulled.is_closed());
        assert_eq!(
            pulled.error(),
            Some(ClientError::Redirected(format!("rtsp://{b}/src")))
        );
        assert!(
            hub_a.reserve("once", PeerInfo::default()).is_ok(),
            "path released"
        );
        wait_until("a's session gone", 5, || srv_a.sessions().is_empty());
        for s in [stop_a, stop_b] {
            s.store(true, Ordering::Relaxed);
        }
        e.shutdown();
        e_b.shutdown();
    }

    /// A client that ignores the `REDIRECT` is closed the grace after the move: the request
    /// it got names the session, the location and the time.
    #[test]
    fn unfollowed_redirects_close_after_the_grace() {
        use super::super::Redirect;
        use std::io::{Read, Write};
        let (_hub, srv, e, a, stop) = served();
        let mut c = std::net::TcpStream::connect(a).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let sdp = describe_sdp(&Arc::from(vec![Track::aac(vec![0x12, 0x10])])).to_string();
        let reqs = [
            format!(
                "ANNOUNCE rtsp://{a}/raw RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                sdp.len()
            ),
            format!(
                "SETUP rtsp://{a}/raw/trackID=0 RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=record\r\n\r\n"
            ),
        ];
        let mut b = [0u8; 4096];
        for r in &reqs {
            c.write_all(r.as_bytes()).unwrap();
            let n = c.read(&mut b).unwrap();
            assert!(b[..n].starts_with(b"RTSP/1.0 200 OK\r\n"));
        }
        let id = srv.sessions()[0].id.clone();
        // A time passed: the grace counts from now.
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        let started = Instant::now();
        let r = Redirect::new("rtsp://10.0.0.9/raw")
            .at(t)
            .grace(Duration::from_millis(300));
        assert!(srv.redirect_session(&id, &r));
        let mut text = Vec::new();
        loop {
            match c.read(&mut b) {
                Ok(0) => break,
                Ok(n) => text.extend_from_slice(&b[..n]),
                Err(e) => panic!("not closed: {e}"),
            }
        }
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(250) && waited < Duration::from_secs(3),
            "{waited:?}"
        );
        let text = String::from_utf8_lossy(&text);
        assert!(
            text.starts_with(&format!(
                "REDIRECT rtsp://{a}/raw RTSP/1.0\r\nCSeq: 1\r\nSession: {id}\r\n"
            )),
            "{text}"
        );
        assert!(text.contains("Location: rtsp://10.0.0.9/raw\r\n"), "{text}");
        assert!(
            text.contains("Range: clock=20260101T000000.000Z-\r\n"),
            "{text}"
        );
        assert!(srv.sessions().is_empty());
        stop.store(true, Ordering::Relaxed);
        e.shutdown();
    }

    /// A TCP forwarder to `to` that can be cut: its connections closed and its port freed.
    struct Forward {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        conns: Arc<Mutex<Vec<std::net::TcpStream>>>,
    }

    impl Forward {
        fn new(to: SocketAddr) -> Forward {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.set_nonblocking(true).unwrap();
            let addr = l.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let conns: Arc<Mutex<Vec<std::net::TcpStream>>> = Arc::default();
            let (s2, c2) = (stop.clone(), conns.clone());
            std::thread::spawn(move || {
                while !s2.load(Ordering::Relaxed) {
                    let Ok((a, _)) = l.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    let _ = a.set_nonblocking(false);
                    let Ok(b) = std::net::TcpStream::connect(to) else {
                        continue;
                    };
                    for (mut x, mut y) in [
                        (a.try_clone().unwrap(), b.try_clone().unwrap()),
                        (b.try_clone().unwrap(), a.try_clone().unwrap()),
                    ] {
                        std::thread::spawn(move || {
                            let _ = std::io::copy(&mut x, &mut y);
                            let _ = y.shutdown(std::net::Shutdown::Both);
                        });
                    }
                    lock(&c2).extend([a, b]);
                }
            });
            Forward { addr, stop, conns }
        }

        fn cut(&self) {
            self.stop.store(true, Ordering::Relaxed);
            for c in lock(&self.conns).drain(..) {
                let _ = c.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    /// Each reconnect looks the host name up again: the server's name moves to another
    /// address while the first one is gone, and the client finds it there (pull and push).
    /// A name that stops resolving is tried again, not the end of the client.
    #[test]
    fn reconnects_look_the_name_up_again() {
        let (hub, e, media, stop) = media_server();
        let a = Forward::new(media);
        set_name("cam-rr.test", Some(a.addr));
        let cfg = RtspClientConfig {
            reconnect: Some(Reconnect::new(&e).initial_delay(Duration::from_millis(50))),
            idle_timeout: Duration::from_secs(2),
            ..RtspClientConfig::default()
        };
        let pulled = pull(&e, "rtsp://cam-rr.test:9/src", &hub, "pulled", cfg.clone()).unwrap();
        let pushed = push(&e, "rtsp://cam-rr.test:9/pushed", &hub, "src", cfg).unwrap();
        wait_until("live", 10, || {
            packets_after(&hub, "pulled") > 20 && packets_after(&hub, "pushed") > 20
        });
        // The name stops resolving, the server goes away: the clients keep trying.
        set_name("cam-rr.test", None);
        a.cut();
        wait_until("sessions end", 10, || {
            !pulled.is_live() && !pushed.is_live()
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(!pulled.is_closed() && !pushed.is_closed());
        assert!(
            matches!(pulled.error(), Some(ClientError::Resolve(_))),
            "{:?}",
            pulled.error()
        );
        // The name comes back at another address.
        let b = Forward::new(media);
        set_name("cam-rr.test", Some(b.addr));
        wait_until("reconnected", 20, || {
            pulled.is_live()
                && pushed.is_live()
                && pulled.reconnects() >= 1
                && pushed.reconnects() >= 1
        });
        let before = packets_after(&hub, "pulled");
        wait_until("pulled flows again", 10, || {
            packets_after(&hub, "pulled") > before + 20
        });
        drop((pulled, pushed));
        b.cut();
        set_name("cam-rr.test", None);
        stop.store(true, Ordering::Relaxed);
        e.shutdown();
    }

    /// A name with several addresses: each session dials them in turn until one connects
    /// (the first refuses here), with or without reconnecting.
    #[test]
    fn sessions_walk_the_addresses_of_a_name() {
        let (hub, e, media, stop) = media_server();
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        crate::reconnect::names::set("cam-walk.test", &[dead, dead, media]);
        let pulled = pull(
            &e,
            "rtsp://cam-walk.test/src",
            &hub,
            "walked",
            RtspClientConfig::default(),
        )
        .unwrap();
        wait_until("walked live", 10, || packets_after(&hub, "walked") > 20);
        assert_eq!(pulled.reconnects(), 0);
        drop(pulled);
        crate::reconnect::names::set("cam-walk.test", &[dead]);
        let r = pull(
            &e,
            "rtsp://cam-walk.test/src",
            &hub,
            "walked",
            RtspClientConfig::default(),
        );
        assert!(matches!(r, Err(ClientError::Connect(_))), "{r:?}");
        crate::reconnect::names::set("cam-walk.test", &[]);
        stop.store(true, Ordering::Relaxed);
        e.shutdown();
    }

    /// A server that answers a pull's handshake (one H.264 track, TCP or UDP), then sends RTP
    /// with gaps after a sender report, and collects the RTCP the client sends back.
    type Collected = Arc<Mutex<Vec<Vec<u8>>>>;

    fn reporting_server(udp: bool) -> (SocketAddr, Collected, Arc<AtomicBool>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let got: Collected = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (g2, s2) = (got.clone(), stop.clone());
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            let rtp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let rtcp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            rtcp.set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            let ports = (
                rtp.local_addr().unwrap().port(),
                rtcp.local_addr().unwrap().port(),
            );
            let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=x\r\nt=0 0\r\na=control:*\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1; sprop-parameter-sets=Z2QADazZQUH7ARAAAAMAEAAAAwMg8UKZYA==,aOvjyyLA\r\na=control:trackID=0\r\n";
            let (mut buf, mut client_rtp, mut playing) = (Vec::new(), None, false);
            let (mut seq, mut sent) = (100u16, 0u32);
            let ssrc = 0x0bad_cafeu32;
            let mut b = [0u8; 4096];
            while !s2.load(Ordering::Relaxed) {
                match s.read(&mut b) {
                    Ok(0) => return,
                    Ok(k) => buf.extend_from_slice(&b[..k]),
                    Err(_) => {}
                }
                // Interleaved frames from the client.
                loop {
                    if buf.len() >= 4 && buf[0] == b'$' {
                        let n = 4 + usize::from(u16::from_be_bytes([buf[2], buf[3]]));
                        if buf.len() < n {
                            break;
                        }
                        if buf[1] == 1 {
                            lock(&g2).push(buf[4..n].to_vec());
                        }
                        buf.drain(..n);
                        continue;
                    }
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        break;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    buf.drain(..end + 4);
                    let cseq = head
                        .lines()
                        .find_map(|l| l.strip_prefix("CSeq: "))
                        .unwrap_or("0")
                        .to_owned();
                    let method = head.split(' ').next().unwrap_or("").to_owned();
                    let extra = match method.as_str() {
                        "DESCRIBE" => format!(
                            "Content-Base: rtsp://{addr}/cam/\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                            sdp.len()
                        ),
                        "SETUP" => {
                            let t = if udp {
                                let cp = head.split("client_port=").nth(1).unwrap();
                                let cp = cp.split([';', '\r']).next().unwrap();
                                let (a, _) = cp.split_once('-').unwrap();
                                client_rtp = Some(SocketAddr::new(addr.ip(), a.parse().unwrap()));
                                format!(
                                    "RTP/AVP;unicast;client_port={cp};server_port={}-{}",
                                    ports.0, ports.1
                                )
                            } else {
                                "RTP/AVP/TCP;unicast;interleaved=0-1".to_owned()
                            };
                            format!("Transport: {t}\r\nSession: 77;timeout=60\r\n\r\n")
                        }
                        "PLAY" => {
                            playing = true;
                            "Session: 77\r\n\r\n".to_owned()
                        }
                        _ => "Public: OPTIONS, DESCRIBE, SETUP, PLAY, GET_PARAMETER\r\n\r\n"
                            .to_owned(),
                    };
                    let r = format!("RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n{extra}");
                    s.write_all(r.as_bytes()).unwrap();
                    if method == "PLAY" {
                        // The sender report first.
                        let sr = rtp::sender_report(ssrc, 0xe000_0000_0001_0000, 0, 0, 0);
                        match client_rtp {
                            Some(to) => {
                                let to = SocketAddr::new(to.ip(), to.port() + 1);
                                rtp.send_to(&sr, to).unwrap();
                            }
                            None => {
                                let mut w = Vec::new();
                                message::interleaved(1, &sr, &mut w);
                                s.write_all(&w).unwrap();
                            }
                        }
                    }
                }
                if let Ok((k, _)) = rtcp.recv_from(&mut b) {
                    lock(&g2).push(b[..k].to_vec());
                }
                if playing {
                    // One packet per round (about 20 ms), every 10th sequence number skipped.
                    if seq % 10 == 5 {
                        seq = seq.wrapping_add(1);
                    }
                    let mut p = vec![0x80, 96];
                    p.extend_from_slice(&seq.to_be_bytes());
                    p.extend_from_slice(&(sent * 1800).to_be_bytes());
                    p.extend_from_slice(&ssrc.to_be_bytes());
                    p.extend_from_slice(&[0x41, 0x9a, 0x00, 0x11]);
                    seq = seq.wrapping_add(1);
                    sent += 1;
                    match client_rtp {
                        Some(to) => {
                            let _ = rtp.send_to(&p, to);
                        }
                        None => {
                            let mut w = Vec::new();
                            message::interleaved(0, &p, &mut w);
                            if s.write_all(&w).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });
        (addr, got, stop)
    }

    /// A pull sends the server receiver reports on the track's RTCP channel or port: the
    /// server's SSRC, its losses, the last sender report; none with the interval zero.
    #[test]
    fn pulls_send_receiver_reports() {
        let e = engine();
        for (udp, every) in [(false, 200), (true, 200), (false, 0)] {
            let (addr, got, stop) = reporting_server(udp);
            let hub = Hub::default();
            let cfg = RtspClientConfig {
                transport: if udp {
                    RtspTransport::Udp
                } else {
                    RtspTransport::Tcp
                },
                receiver_report_interval: Duration::from_millis(every),
                ..RtspClientConfig::default()
            };
            let c = pull(&e, &format!("rtsp://{addr}/cam"), &hub, "rr", cfg).unwrap();
            std::thread::sleep(Duration::from_millis(1500));
            drop(c);
            stop.store(true, Ordering::Relaxed);
            let got = lock(&got).clone();
            let rrs: Vec<&Vec<u8>> = got.iter().filter(|p| p.len() > 8 && p[1] == 201).collect();
            if every == 0 {
                assert!(rrs.iter().all(|p| p[0] & 31 == 0), "udp {udp}: {rrs:02x?}");
                continue;
            }
            assert!(
                rrs.len() >= 3,
                "udp {udp}: {} reports in {got:02x?}",
                rrs.len()
            );
            let last = rrs.last().unwrap();
            assert_eq!(last[0], 0x81, "one report block");
            let be = |i: usize| u32::from_be_bytes(last[i..i + 4].try_into().unwrap());
            assert_eq!(be(8), 0x0bad_cafe);
            let lost = be(12) & 0xff_ffff;
            assert!(lost >= 3, "udp {udp}: lost {lost}");
            assert_eq!(be(24), 0x0000_0001, "LSR");
            // The SDES with the CNAME follows.
            let sdes = &last[32..];
            assert_eq!((sdes[1], sdes[8]), (202, 1));
        }
        e.shutdown();
    }
}
