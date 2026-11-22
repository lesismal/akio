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
//! `sprop-*`, or in band; for VP8, VP9 and AV1, from the first keyframe). A recording's
//! tracks are lined up by the publisher's RTCP sender reports ([`RtspConfig::rtcp_sync`], on
//! by default), so audio and video keep the offset they were captured with rather than the
//! one their first packets arrived with. The publisher gets RTCP receiver reports
//! ([`RtspConfig::receiver_report_interval`]): losses, jitter and the delay since its last
//! sender report, per track.
//!
//! A player starts with the hub's cached GOP and gets RTCP sender reports; over TCP it is cut
//! back to keyframes ([`Dropper`]) when it falls behind and closed when it falls further.
//! Authentication is Digest or Basic through [`RtspConfig::credentials`]; the hub's
//! `on_publish` / `on_subscribe` hooks decide who may publish and play what.
//!
//! [`RtspServer::sessions`] lists the sessions; [`RtspServer::redirect_session`] and
//! [`RtspServer::redirect_path`] move them to another URL, for load shedding or maintenance,
//! with a `REDIRECT` request (RFC 2326 10.15; [`Redirect`]: the location, optionally when, as
//! `Range: clock=`). The session keeps playing or recording until its client tears it down
//! (then the server closes the connection), or until the redirect's grace passes after the
//! move (then the server closes it): clients that do not follow `REDIRECT` (ffmpeg answers
//! 501 and GStreamer 200, both carry on; mediamtx pulls the same URL again) are ended cleanly
//! all the same.
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
//! The [`client`] plays remote RTSP streams into the hub ([`client::pull`]) and records hub
//! streams to remote servers ([`client::push`]).
//!
//! Left out: RTSP 2.0, RTSPS and HTTP tunnelling, multicast, seeking (every stream is live),
//! sessions that outlive their connection, and decode times for B-frame video recorded over
//! RTP (RTP carries presentation times only).

mod auth;
pub mod client;
pub mod message;

use std::{
    collections::HashMap,
    fmt, io,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant, SystemTime},
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

pub use client::{ClientError, RtspClient, RtspClientConfig, RtspTransport};
pub use message::{Frame, Parser, Reply, Request, Response, RtspError, Transport};

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
    /// The session timeout advertised in `Session: <id>;timeout=<s>` (in whole seconds, one at
    /// least) and enforced: a connection that sends nothing (no request, no interleaved RTCP, and
    /// for UDP transports no datagram from the client's ports) for this long is torn down and
    /// closed. Clients keep sessions alive with RTCP receiver reports or `GET_PARAMETER`, as
    /// RFC 2326 section 12.37 asks. Default 60 s; `Duration::ZERO` disables enforcement (60
    /// is still advertised).
    pub session_timeout: Duration,
    /// Time allowed for the first request after accept, and for any request once its first
    /// byte arrived; a client trickling a request is closed. Default 10 s; `Duration::ZERO`
    /// disables it.
    pub request_timeout: Duration,
    /// Line a recording session's tracks up by the publisher's RTCP sender reports (over the
    /// interleaved RTCP channels, RTCP muxed on the RTP channel or port, and the UDP RTCP
    /// port): each track's times start at its first packet's arrival, then move to the
    /// publisher's NTP clock relative to the first track synchronized, forward only, before
    /// the stream goes live when the reports come first (as the RTSP client's
    /// [`RtspClientConfig::rtcp_sync`]). Corrections over 10 s and reports with no NTP time
    /// are ignored. Default `true`; `false` keeps arrival-based times.
    pub rtcp_sync: bool,
    /// Interval of the RTCP receiver reports (RFC 3550 6.4.2) a recording session sends its
    /// publisher, one per track on the track's RTCP channel or port: packets lost, the highest
    /// sequence number, the interarrival jitter and the delay since the track's last sender
    /// report, in a compound packet with the server's CNAME. A track's first report goes half
    /// an interval after its first packet. Default 5 s (RFC 3550's minimum);
    /// `Duration::ZERO` sends none.
    pub receiver_report_interval: Duration,
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
            session_timeout: Duration::from_secs(60),
            request_timeout: Duration::from_secs(10),
            rtcp_sync: true,
            receiver_report_interval: Duration::from_secs(5),
        }
    }
}

impl fmt::Debug for RtspConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtspConfig")
            .field("realm", &self.realm)
            .field("write_queue_limit", &self.write_queue_limit)
            .field("max_write_queue", &self.max_write_queue)
            .field("session_timeout", &self.session_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("rtcp_sync", &self.rtcp_sync)
            .field("receiver_report_interval", &self.receiver_report_interval)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Where a UDP datagram from a client goes.
struct Route {
    /// The recording session the datagram feeds (dangling for a player's ports).
    rec: Weak<Mutex<Recorder>>,
    media: usize,
    /// The client's RTCP port of the media (where receiver reports go).
    rtcp: SocketAddr,
    /// The session's deadlines: any datagram from its client keeps it alive.
    watch: Weak<crate::watch::Watch>,
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
    /// The sessions (set up or announced), by id.
    sessions: Mutex<HashMap<String, Live>>,
}

/// What the server's API sees of a session ([`RtspServer::sessions`],
/// [`RtspServer::redirect_session`]).
struct Live {
    conn: Conn<RtspSession>,
    path: String,
    /// The session's URL (the request URI of the server's requests).
    uri: String,
    recording: bool,
    /// The CSeq of the server's last request.
    cseq: u32,
    /// Redirects sent: a redirect's grace timer closes the connection only while it is the
    /// latest.
    redirects: u64,
}

/// A session of an [`RtspServer`] ([`RtspServer::sessions`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RtspSessionInfo {
    /// The session id (the `Session` header's).
    pub id: String,
    /// The hub path it plays or records.
    pub path: String,
    /// The client's address.
    pub peer: SocketAddr,
    /// Whether it records (ANNOUNCE and RECORD) rather than plays.
    pub recording: bool,
    /// Whether a `REDIRECT` was sent to it.
    pub redirected: bool,
}

/// Where and when [`RtspServer::redirect_session`] and [`RtspServer::redirect_path`] move a
/// session: the server sends the client a `REDIRECT` request (RFC 2326 10.15) with this
/// `Location` and, with [`at`](Self::at), a `Range: clock=` saying when the move takes effect.
/// The session keeps playing or recording meanwhile; a client that follows tears it down
/// (TEARDOWN) and sets up at the location, and the server closes the connection after its
/// TEARDOWN answer. One that does not is closed [`grace`](Self::grace) after the move.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Redirect {
    /// The URL the client should use from now on: `rtsp://host[:port]/path`, or an absolute
    /// path on this server.
    pub location: String,
    /// When the move takes effect (`None`: at once). Sent as `Range: clock=<UTC>-`.
    pub at: Option<SystemTime>,
    /// How long after the move takes effect the server closes a connection whose client has
    /// not torn the session down. Default 10 s.
    pub grace: Duration,
}

impl Redirect {
    /// A move to `location`, effective at once, with the default grace.
    pub fn new(location: impl Into<String>) -> Redirect {
        Redirect {
            location: location.into(),
            at: None,
            grace: Duration::from_secs(10),
        }
    }

    /// Sets [`at`](Self::at).
    #[must_use]
    pub fn at(mut self, t: SystemTime) -> Redirect {
        self.at = Some(t);
        self
    }

    /// Sets [`grace`](Self::grace).
    #[must_use]
    pub fn grace(mut self, d: Duration) -> Redirect {
        self.grace = d;
        self
    }
}

/// The longest a redirect's timer waits (a move far in the future is bounded by it).
const MAX_REDIRECT_WAIT: Duration = Duration::from_secs(86_400);

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
            sessions: Mutex::new(HashMap::new()),
        }))
    }

    /// The sessions: connections that set a stream up (SETUP to play, ANNOUNCE to record),
    /// until they tear it down or close.
    pub fn sessions(&self) -> Vec<RtspSessionInfo> {
        lock(&self.0.sessions)
            .iter()
            .map(|(id, l)| RtspSessionInfo {
                id: id.clone(),
                path: l.path.clone(),
                peer: l.conn.peer_addr(),
                recording: l.recording,
                redirected: l.redirects > 0,
            })
            .collect()
    }

    /// Moves the session `id` ([`RtspSessionInfo::id`]) to another URL, for load shedding
    /// or maintenance: sends its client a `REDIRECT` request ([`Redirect`]). Returns whether
    /// the session exists (and the request could be queued).
    pub fn redirect_session(&self, id: &str, r: &Redirect) -> bool {
        // Built under the lock, sent without it (a send that fails may close the connection,
        // whose handler takes the lock).
        let (conn, req, n) = {
            let mut g = lock(&self.0.sessions);
            let Some(l) = g.get_mut(id) else {
                return false;
            };
            l.cseq += 1;
            l.redirects += 1;
            let mut req = format!(
                "REDIRECT {} RTSP/1.0\r\nCSeq: {}\r\nSession: {id}\r\nLocation: {}\r\n",
                l.uri,
                l.cseq,
                r.location.replace(['\r', '\n'], "")
            );
            if let Some(t) = r.at {
                req.push_str("Range: ");
                req.push_str(&message::clock_range(t));
                req.push_str("\r\n");
            }
            req.push_str("Server: only-media\r\n\r\n");
            (l.conn.clone(), req, l.redirects)
        };
        if conn.send_owned(req.into_bytes()).is_err() {
            return false;
        }
        let wait =
            r.at.and_then(|t| t.duration_since(SystemTime::now()).ok())
                .unwrap_or_default()
                .saturating_add(r.grace)
                .min(MAX_REDIRECT_WAIT);
        let (srv, id) = (Arc::downgrade(&self.0), id.to_owned());
        crate::timer::after(wait, move || {
            // Still the latest redirect of a session not torn down: the client did not follow.
            let current = srv
                .upgrade()
                .is_some_and(|s| lock(&s.sessions).get(&id).is_some_and(|l| l.redirects == n));
            if current {
                conn.close();
            }
        });
        true
    }

    /// Moves every session of the hub path `path` (players and its publisher) to `r`'s
    /// location ([`redirect_session`](Self::redirect_session)). Returns how many were sent a
    /// `REDIRECT`.
    pub fn redirect_path(&self, path: &str, r: &Redirect) -> usize {
        let path = path.trim_matches('/');
        let ids: Vec<String> = lock(&self.0.sessions)
            .iter()
            .filter(|(_, l)| l.path == path)
            .map(|(id, _)| id.clone())
            .collect();
        ids.iter().filter(|id| self.redirect_session(id, r)).count()
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
        let route = lock(&inner.routes).get(&from).map(|r| {
            if let Some(w) = r.watch.upgrade() {
                w.touch();
            }
            (r.rec.clone(), r.media, r.rtcp)
        });
        if let Some((rec, media, to)) = route {
            if let Some(rec) = rec.upgrade() {
                // From the RTCP port, or muxed on the RTP port: sender reports sync the track.
                let reports = {
                    let mut r = lock(&rec);
                    if rtp::is_rtcp(&buf[..n]) {
                        r.rtcp(media, &buf[..n]);
                    } else {
                        let at = if r.reports_on() {
                            Instant::now()
                        } else {
                            r.start
                        };
                        r.push(media, &buf[..n], at);
                    }
                    r.take_reports()
                };
                if !reports.is_empty() {
                    let udp = lock(&inner.udp).clone();
                    if let Some(udp) = udp {
                        for (_, pkt) in reports {
                            let _ = udp.rtcp.send_to(&pkt, to);
                        }
                    }
                }
            }
        }
    }
}

impl Acceptor for RtspServer {
    type Handler = RtspSession;

    fn on_open(&self, c: &Conn<RtspSession>) -> RtspSession {
        let cfg = &self.0.cfg;
        let watch = crate::watch::watch(
            c.inner(),
            crate::watch::Deadlines {
                handshake: cfg.request_timeout,
                idle: cfg.session_timeout,
                message: cfg.request_timeout,
            },
        );
        let secs = if cfg.session_timeout.is_zero() {
            60
        } else {
            cfg.session_timeout.as_secs().max(1)
        };
        let id = random_hex(8);
        RtspSession {
            session_hdr: format!("{id};timeout={secs}"),
            id,
            registered: false,
            close_after: false,
            watch,
            srv: self.0.clone(),
            parser: Parser::default(),
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

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = only_crypto::rand::fill_random(&mut b);
    u32::from_be_bytes(b)
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    let _ = only_crypto::rand::fill_random(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// How a track's RTP travels.
#[derive(Debug, Clone, Copy)]
enum Path {
    Tcp { rtp: u8, rtcp: u8 },
    Udp { rtp: SocketAddr, rtcp: SocketAddr },
}

/// The ingest of a recording session (and of the RTSP client's play): depacketizes each
/// media's RTP into the publisher; the stream goes live once every video track's parameter
/// sets are known.
///
/// Each track's times start at its first packet's arrival. With [`sync`](Self::sync) the RTCP
/// sender reports of the tracks then line them up on the sender's NTP clock: once a track
/// has a report and a packet, its offset becomes the NTP time of its first RTP timestamp
/// relative to that of the first track synchronized. Offsets only move forward (when a track
/// would go back, those already synchronized move forward instead), so times keep
/// increasing; before the stream is live nothing of this is seen.
pub(crate) struct Recorder {
    publisher: Arc<Publisher>,
    /// Per announced media: its track, whether the hub carries it, its hub index.
    media: Vec<RecMedia>,
    tracks: Vec<Track>,
    live: bool,
    start: Instant,
    scratch: Vec<Packet>,
    /// RTCP sender reports line the tracks up.
    sync: bool,
    /// The NTP time (ns) that times count from, once a track is synchronized.
    ntp_ref: Option<i128>,
    /// RTCP receiver reports, when on ([`reports`](Self::reports)).
    rr: Option<Box<Reports>>,
}

/// The receiver reports of a session: what each media received, when its next report is due,
/// and the reports due ([`Recorder::take_reports`]).
struct Reports {
    every: Duration,
    ssrc: u32,
    cname: String,
    recv: Vec<rtp::Reception>,
    next: Vec<Option<Instant>>,
    out: Vec<(usize, Vec<u8>)>,
}

impl Reports {
    fn rtp(&mut self, media: usize, data: &[u8], now: Instant) {
        let (Some(r), Some(next)) = (self.recv.get_mut(media), self.next.get_mut(media)) else {
            return;
        };
        r.rtp(data, now);
        if !r.started() {
            return;
        }
        match *next {
            None => *next = Some(now + self.every / 2),
            Some(t) if now >= t => {
                *next = Some(now + self.every);
                if let Some(b) = r.block(now) {
                    let pkt = rtp::receiver_report(self.ssrc, &[b], &self.cname);
                    self.out.push((media, pkt));
                }
            }
            Some(_) => {}
        }
    }
}

struct RecMedia {
    track: Option<Track>,
    hub_index: Option<usize>,
    depack: Option<Depacketizer>,
    /// The newest sender report: NTP time and RTP timestamp.
    sr: Option<(u64, u32)>,
    synced: bool,
}

/// An NTP timestamp (RFC 5905, 32.32 fixed point) in nanoseconds.
fn ntp_ns(ntp: u64) -> i128 {
    i128::from(ntp >> 32) * 1_000_000_000 + ((i128::from(ntp & 0xffff_ffff) * 1_000_000_000) >> 32)
}

/// A larger correction than this means the reports' clocks do not agree (or the sender's
/// clock is not a clock): the track keeps its arrival-based times.
const MAX_SYNC_SHIFT: crate::av::Time = 10 * crate::av::SECOND;

/// The NTP and RTP timestamps of the first sender report of an RTCP compound packet.
fn sender_report(mut b: &[u8]) -> Option<(u64, u32)> {
    while b.len() >= 4 {
        if b[0] >> 6 != 2 {
            return None;
        }
        let len = (usize::from(u16::from_be_bytes([b[2], b[3]])) + 1) * 4;
        let pkt = b.get(..len)?;
        if pkt[1] == 200 && len >= 28 {
            let ntp = u64::from_be_bytes(pkt[8..16].try_into().ok()?);
            let rtp = u32::from_be_bytes(pkt[16..20].try_into().ok()?);
            return (ntp != 0).then_some((ntp, rtp));
        }
        b = &b[len..];
    }
    None
}

impl Recorder {
    /// The ingest of `media` (an SDP's media descriptions, in order) into `publisher`, or
    /// `None` when no media maps to a track. Media that map to none are ignored.
    pub(crate) fn new(publisher: Arc<Publisher>, medias: &[sdp::Media]) -> Option<Recorder> {
        let mut media = Vec::new();
        let mut tracks = Vec::new();
        for m in medias {
            let t = sdp::media_track(m)
                .map(|(t, _)| t)
                .filter(|t| rtp::supported(t.codec));
            let hub_index = t.as_ref().map(|t| {
                tracks.push(t.clone());
                tracks.len() - 1
            });
            media.push(RecMedia {
                track: t,
                hub_index,
                depack: None,
                sr: None,
                synced: false,
            });
        }
        if tracks.is_empty() {
            return None;
        }
        Some(Recorder {
            publisher,
            media,
            tracks,
            live: false,
            start: Instant::now(),
            scratch: Vec::new(),
            sync: false,
            ntp_ref: None,
            rr: None,
        })
    }

    /// Sends RTCP receiver reports from `ssrc` every `every` per media (none with
    /// `Duration::ZERO`); they are collected with [`take_reports`](Self::take_reports).
    pub(crate) fn reports(mut self, every: Duration, ssrc: u32) -> Recorder {
        if every.is_zero() {
            self.rr = None;
            return self;
        }
        let mut b = [0u8; 8];
        let _ = only_crypto::rand::fill_random(&mut b);
        let cname: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let epoch = Instant::now();
        let recv = self
            .media
            .iter()
            .map(|m| {
                let clock = m.track.as_ref().map_or(90_000, Track::clock_rate);
                rtp::Reception::new(clock, epoch)
            })
            .collect();
        self.rr = Some(Box::new(Reports {
            every,
            ssrc,
            cname: format!("only-media-{cname}"),
            recv,
            next: vec![None; self.media.len()],
            out: Vec::new(),
        }));
        self
    }

    /// Whether receiver reports are sent (and packets need their arrival time).
    pub(crate) fn reports_on(&self) -> bool {
        self.rr.is_some()
    }

    /// The receiver reports due since the last call: the media and the RTCP compound packet.
    pub(crate) fn take_reports(&mut self) -> Vec<(usize, Vec<u8>)> {
        self.rr
            .as_deref_mut()
            .map_or_else(Vec::new, |r| std::mem::take(&mut r.out))
    }

    /// Lines the tracks up by their RTCP sender reports ([`rtcp`](Self::rtcp)).
    pub(crate) fn sync(mut self, on: bool) -> Recorder {
        self.sync = on;
        self
    }

    /// Closes the publisher.
    pub(crate) fn close(&self) {
        self.publisher.close();
    }

    /// Feeds one RTCP packet of media `media`: its sender report, if any, synchronizes the
    /// track ([`sync`](Self::sync)).
    pub(crate) fn rtcp(&mut self, media: usize, data: &[u8]) {
        if !self.sync && self.rr.is_none() {
            return;
        }
        let Some(m) = self.media.get_mut(media) else {
            return;
        };
        let Some(sr) = sender_report(data) else {
            return;
        };
        if let Some(r) = self.rr.as_deref_mut().and_then(|r| r.recv.get_mut(media)) {
            r.sender_report(sr.0, Instant::now());
        }
        if self.sync {
            m.sr = Some(sr);
            self.resync(media);
        }
    }

    /// Synchronizes track `media` once it has a sender report and a packet.
    fn resync(&mut self, media: usize) {
        let Some(m) = self.media.get(media) else {
            return;
        };
        let (Some((ntp, rtp)), Some(d), false) = (m.sr, m.depack.as_ref(), m.synced) else {
            return;
        };
        let Some(rel) = d.rtp_time(rtp) else { return };
        // The NTP time of the track's first RTP timestamp.
        let base = ntp_ns(ntp) - i128::from(rel);
        let cur = d.current_offset();
        let Some(r) = self.ntp_ref else {
            self.ntp_ref = Some(base - i128::from(cur));
            self.media[media].synced = true;
            return;
        };
        let Ok(want) = crate::av::Time::try_from(base - r) else {
            return;
        };
        if (want - cur).abs() > MAX_SYNC_SHIFT {
            return;
        }
        if want >= cur {
            if let Some(d) = self.media[media].depack.as_mut() {
                d.set_offset(want);
            }
        } else {
            // Moving this track back would send its times backwards: move the others forward.
            let delta = cur - want;
            self.ntp_ref = Some(r - i128::from(delta));
            for o in self.media.iter_mut().filter(|o| o.synced) {
                if let Some(d) = o.depack.as_mut() {
                    d.set_offset(d.current_offset() + delta);
                }
            }
        }
        self.media[media].synced = true;
    }

    /// Feeds one RTP packet of media `media` that arrived at `now`.
    pub(crate) fn push(&mut self, media: usize, data: &[u8], now: Instant) {
        let start = self.start;
        let Some(m) = self.media.get_mut(media) else {
            return;
        };
        let (Some(track), Some(index)) = (m.track.as_ref(), m.hub_index) else {
            return;
        };
        if let Some(rr) = self.rr.as_deref_mut() {
            rr.rtp(media, data, now);
        }
        let first = m.depack.is_none();
        let depack = m.depack.get_or_insert_with(|| {
            let off = i64::try_from(start.elapsed().as_nanos()).unwrap_or(0);
            Depacketizer::new(track).offset(off)
        });
        let mut out = std::mem::take(&mut self.scratch);
        if depack.push(data, &mut out).is_err() {
            self.scratch = out;
            return;
        }
        if first && self.sync {
            // A report that came before the first packet (as ffmpeg sends them) applies to
            // the packets it completed too.
            let before = depack.current_offset();
            self.resync(media);
            let after = self.media[media]
                .depack
                .as_ref()
                .map_or(before, Depacketizer::current_offset);
            for p in &mut out {
                p.dts += after - before;
                p.pts += after - before;
            }
        }
        let Some(depack) = self.media[media].depack.as_mut() else {
            self.scratch = out;
            return;
        };
        if let Some(cfg) = depack.take_config() {
            let mut t = Track::video(self.tracks[index].codec, cfg);
            if t.width == 0 {
                // VP8 / VP9: the size comes from the keyframe, not the configuration.
                if let Some((w, h)) = depack.picture_size() {
                    (t.width, t.height) = (w, h);
                }
            }
            if self.tracks[index] != t {
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
    /// `Session` header value: the id and the advertised timeout.
    session_hdr: String,
    /// The session id.
    id: String,
    /// In the server's [`Inner::sessions`].
    registered: bool,
    /// Close the connection once the response being sent is out (a redirected session torn
    /// down).
    close_after: bool,
    watch: Arc<crate::watch::Watch>,
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
        self.watch.touch();
        // What one read brought arrived at once (the receiver reports' jitter): the clock is
        // read once, for the first RTP packet.
        let mut now = None;
        let mut frames = Vec::new();
        if self.parser.feed(data, &mut frames).is_err() {
            let _ = c.send(&Response::new(400).encode(None));
            c.close_after_send();
            return;
        }
        self.watch.set_partial(self.parser.pending());
        if frames
            .iter()
            .any(|f| matches!(f, Frame::Request(_) | Frame::Response(_) | Frame::Reply(_)))
        {
            self.watch.ready();
        }
        for f in frames {
            match f {
                Frame::Request(req) => {
                    let resp = self.handle(c, &req);
                    let _ = c.send(&resp.encode(req.cseq()));
                    if req.method == "PLAY" && resp.status == 200 {
                        self.start_play(c);
                    }
                    if self.close_after {
                        // Redirected and torn down: the client goes elsewhere.
                        c.close_after_send();
                        return;
                    }
                }
                Frame::Interleaved { channel, data } => {
                    self.interleaved(c, channel, &data, &mut now);
                }
                Frame::Response(_) | Frame::Reply(_) => {}
            }
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        self.teardown();
    }
}

impl RtspSession {
    /// Lists the session in the server's [`Inner::sessions`] once it has a stream.
    fn register(&mut self, c: &Conn<Self>, uri: String) {
        if self.registered {
            return;
        }
        let Some(path) = self.path.clone() else {
            return;
        };
        self.registered = true;
        lock(&self.srv.sessions).insert(
            self.id.clone(),
            Live {
                conn: c.clone(),
                path,
                uri,
                recording: self.recorder.is_some(),
                cseq: 0,
                redirects: 0,
            },
        );
    }

    /// Takes the session out of the server's list; whether it had been redirected.
    fn unregister(&mut self) -> bool {
        if !std::mem::take(&mut self.registered) {
            return false;
        }
        lock(&self.srv.sessions)
            .remove(&self.id)
            .is_some_and(|l| l.redirects > 0)
    }

    fn teardown(&mut self) {
        self.unregister();
        self.sub = None;
        self.playing = false;
        if let Some(rec) = self.recorder.take() {
            let weak = Arc::downgrade(&rec);
            lock(&self.srv.routes).retain(|_, r| !r.rec.ptr_eq(&weak));
            lock(&rec).publisher.close();
        }
        let w = Arc::downgrade(&self.watch);
        lock(&self.srv.routes).retain(|_, r| !r.watch.ptr_eq(&w));
        self.setups.clear();
    }

    fn interleaved(&self, c: &Conn<Self>, channel: u8, data: &[u8], now: &mut Option<Instant>) {
        let Some(rec) = &self.recorder else { return };
        let media = self.setups.iter().find_map(|(&m, p)| match *p {
            Path::Tcp { rtp, rtcp } if rtp == channel => Some((m, false, rtcp)),
            Path::Tcp { rtcp, .. } if rtcp == channel => Some((m, true, rtcp)),
            _ => None,
        });
        if let Some((m, is_rtcp, ch)) = media {
            // The RTCP channel, or RTCP muxed on the RTP one: sender reports sync the track.
            let reports = {
                let mut r = lock(rec);
                if is_rtcp || rtp::is_rtcp(data) {
                    r.rtcp(m, data);
                } else {
                    let at = if r.reports_on() {
                        *now.get_or_insert_with(Instant::now)
                    } else {
                        r.start
                    };
                    r.push(m, data, at);
                }
                r.take_reports()
            };
            for (_, pkt) in reports {
                let mut b = Vec::with_capacity(pkt.len() + 4);
                message::interleaved(ch, &pkt, &mut b);
                let _ = c.send_owned(b);
            }
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
        let session_hdr = self.session_hdr.clone();
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
                self.close_after = self.registered
                    && lock(&self.srv.sessions)
                        .get(&self.id)
                        .is_some_and(|l| l.redirects > 0);
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
        if !s
            .media
            .iter()
            .any(|m| sdp::media_track(m).is_some_and(|(t, _)| rtp::supported(t.codec)))
        {
            return Response::new(415);
        }
        self.query = query;
        let publisher = match self.srv.hub.reserve(&path, self.peer(c)) {
            Ok(p) => p,
            Err(e) => return Response::new(hub_status(&e)),
        };
        let Some(rec) = Recorder::new(Arc::new(publisher), &s.media) else {
            return Response::new(415);
        };
        let rec = rec
            .sync(self.srv.cfg.rtcp_sync)
            .reports(self.srv.cfg.receiver_report_interval, random_u32());
        self.announced = s.media;
        self.path = Some(path);
        self.recorder = Some(Arc::new(Mutex::new(rec)));
        let uri = req.uri.clone();
        self.register(c, uri);
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
            // Recording: datagrams feed the recorder. Playing: the client's RTCP receiver
            // reports only keep the session alive.
            let rec = self
                .recorder
                .as_ref()
                .map_or_else(Weak::new, Arc::downgrade);
            let mut routes = lock(&self.srv.routes);
            for addr in [rtp_addr, rtcp_addr] {
                routes.insert(
                    addr,
                    Route {
                        rec: rec.clone(),
                        media: index,
                        rtcp: rtcp_addr,
                        watch: Arc::downgrade(&self.watch),
                    },
                );
            }
            Path::Udp {
                rtp: rtp_addr,
                rtcp: rtcp_addr,
            }
        };
        self.setups.insert(index, path);
        // The session's URL: the SETUP's, without the track.
        let uri = match track_id(last) {
            Some(_) => uri.rsplit_once('/').map_or(uri, |(b, _)| b),
            None => uri,
        };
        self.register(c, uri.to_owned());
        Response::new(200)
            .header("Transport", reply.to_string())
            .header("Session", self.session_hdr.clone())
    }

    fn play_response(&self) -> Response {
        Response::new(200)
            .header("Session", self.session_hdr.clone())
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

    /// Packets of the H.264 + AAC sample.
    fn sample() -> (Tracks, Vec<Packet>) {
        use crate::flv::{Decoder, Demuxer, Event};
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        for t in Demuxer::new()
            .feed(include_bytes!("../../testdata/h264_aac.flv"))
            .expect("flv")
        {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    Event::Tracks(t) => tracks = Some(t),
                    Event::Packet(p) => pkts.push(p),
                }
            }
        }
        (tracks.expect("tracks"), pkts)
    }

    /// Collects what a hub subscriber hears: (track, pts) of every packet, and how many times
    /// it heard the tracks.
    #[derive(Clone, Default)]
    struct Collect(Arc<Mutex<Heard>>);

    /// (track, pts) of the packets, and the tracks announcements.
    type Heard = (Vec<(usize, crate::av::Time)>, usize);

    impl Sink for Collect {
        fn on_tracks(&mut self, _t: &Tracks) {
            lock(&self.0).1 += 1;
        }
        fn on_packet(&mut self, p: &Arc<Packet>) {
            lock(&self.0).0.push((p.track, p.pts));
        }
        fn on_close(&mut self, _e: HubError) {}
    }

    /// Two tracks whose packets arrive together but whose sender reports put audio 500 ms
    /// after video: with sync the hub's times follow the reports (whether they come before
    /// the first packets or after the stream is live, in which case times only move
    /// forward); without, they follow the arrival.
    #[test]
    fn rtcp_sender_reports_line_tracks_up() {
        use crate::av::{MILLISECOND, SECOND};
        let (tracks, pkts) = sample();
        let medias = describe_sdp(&tracks).media;
        // Media times of video and audio, from 0.
        let v0 = pkts.iter().find(|p| p.track == 0).map_or(0, |p| p.pts);
        let a0 = pkts.iter().find(|p| p.track == 1).map_or(0, |p| p.pts);
        let ntp = |t: crate::av::Time| -> u64 {
            let t = t + 3_900_000_000 * SECOND;
            let secs = (t / SECOND) as u64;
            let frac = (((t % SECOND) as u128) << 32) / SECOND as u128;
            (secs << 32) | frac as u64
        };
        for (sync, early) in [(true, true), (true, false), (false, true)] {
            let hub = Hub::default();
            let p = hub.reserve("s", PeerInfo::default()).expect("reserve");
            let mut rec = Recorder::new(Arc::new(p), &medias)
                .expect("recorder")
                .sync(sync);
            let got = Collect::default();
            let mut opts = SubscribeOptions::new(PeerInfo::default());
            opts.wait = Some(Duration::from_secs(5));
            let _sub = hub.subscribe("s", got.clone(), opts).expect("subscribe");
            let mut packers: Vec<Packetizer> = tracks
                .iter()
                .enumerate()
                .map(|(i, t)| Packetizer::new(t, 96 + i as u8))
                .collect();
            // The reports: video's first frame at NTP 0, audio's first frame at NTP 500 ms.
            let srs: Vec<Vec<u8>> = (0..2)
                .map(|i| {
                    let (first, at) = if i == 0 {
                        (v0, 0)
                    } else {
                        (a0, 500 * MILLISECOND)
                    };
                    let pk = &packers[i];
                    pk.sender_report(ntp(at), pk.timestamp(first))
                })
                .collect();
            if early {
                rec.rtcp(0, &srs[0]);
                rec.rtcp(1, &srs[1]);
            }
            let mut out = Vec::new();
            for (n, pkt) in pkts.iter().enumerate() {
                if !early && n == pkts.len() / 2 {
                    rec.rtcp(1, &srs[1]);
                    rec.rtcp(0, &srs[0]);
                }
                out.clear();
                packers[pkt.track].packetize(pkt, &mut out);
                for r in &out {
                    rec.push(pkt.track, r, Instant::now());
                }
            }
            let g = lock(&got.0);
            assert_eq!(g.1, 1, "went live once");
            let first = |t: usize, after: usize| {
                g.0.iter()
                    .skip(after)
                    .find(|(k, _)| *k == t)
                    .map(|(_, d)| *d)
                    .expect("packet")
            };
            // Audio times keep increasing.
            let d: Vec<_> =
                g.0.iter()
                    .filter(|(k, _)| *k == 1)
                    .map(|(_, d)| *d)
                    .collect();
            assert!(d.windows(2).all(|w| w[1] >= w[0]), "audio goes back");
            // Audio relative to video, at the same media time (the sample's own offset taken
            // out): the reports' 500 ms with sync, about nothing without.
            let skew = |after: usize| {
                let (v, a) = (first(0, after), first(1, after));
                (a - v) - (a0 - v0)
            };
            if !sync {
                assert!(skew(0).abs() < 50 * MILLISECOND, "{}", skew(0));
                continue;
            }
            if early {
                assert!(
                    (skew(0) - 500 * MILLISECOND).abs() < 30 * MILLISECOND,
                    "{}",
                    skew(0)
                );
            } else {
                // Late reports: the packets after them carry the offset.
                let n = g.0.len();
                let late: Vec<_> = g.0[n / 2..].to_vec();
                let v = late
                    .iter()
                    .find(|(k, _)| *k == 0)
                    .map(|x| x.1)
                    .expect("video");
                let src_v = pkts
                    .iter()
                    .filter(|p| p.track == 0)
                    .nth(g.0[..n / 2].iter().filter(|(k, _)| *k == 0).count());
                let src_a = pkts
                    .iter()
                    .filter(|p| p.track == 1)
                    .nth(g.0[..n / 2].iter().filter(|(k, _)| *k == 1).count());
                let a = late
                    .iter()
                    .find(|(k, _)| *k == 1)
                    .map(|x| x.1)
                    .expect("audio");
                let (sv, sa) = (src_v.expect("v").pts, src_a.expect("a").pts);
                let skew = (a - v) - (sa - sv);
                assert!(
                    (skew - 500 * MILLISECOND).abs() < 60 * MILLISECOND,
                    "{skew}"
                );
            }
        }
        assert_eq!(sender_report(&[0x80, 201, 0, 1, 0, 0, 0, 0]), None);
        assert_eq!(sender_report(&[0x80, 200, 0, 1]), None);
        assert_eq!(ntp_ns(1 << 32), 1_000_000_000);
        assert_eq!(ntp_ns(1 << 31), 500_000_000);
    }
}
