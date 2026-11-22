//! SRT on `akio` UDP: the server ([`SrtServer`], a UDP listener's acceptor) and the caller
//! ([`dial`], [`push`], [`pull`]), both driving a sans-IO [`Conn`] per peer from the I/O
//! thread that reads its datagrams and from the media timer thread.

use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use akio::{Acceptor, Conn as AkioConn, Engine, Handler, UdpBinding};
use akio_core::ConnInner;

use super::{
    conn::{Config, Conn, Event, RejectReason, SrtError, Stats, TS_PAYLOAD_SIZE},
    listener::{Listener, Mode, Request, StreamId, is_handshake},
};
use crate::{
    av::{Packet, Tracks},
    hub::{
        Dropper, Hub, HubError, PeerInfo, Publisher, Sink, SubscribeOptions, Subscription, Timeline,
    },
    mpegts::{
        Muxer,
        demux::{Demuxer, Event as TsEvent},
    },
};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Default bound of a player's unacknowledged bytes above which hub packets are dropped.
pub const DEFAULT_MAX_SEND_BACKLOG: usize = 2 << 20;

/// Authorizes a connection from its request and parsed stream ID.
pub type ConnectHook = Arc<dyn Fn(&Request, &StreamId) -> Result<(), RejectReason> + Send + Sync>;

/// Configures an [`SrtServer`].
#[derive(Clone)]
#[non_exhaustive]
pub struct SrtConfig {
    /// TSBPD latency (the larger of this and the peer's is used).
    pub latency: Duration,
    /// Requires encryption with this passphrase (10 to 79 bytes).
    pub passphrase: Option<String>,
    /// How long a player waits for a stream not published yet, and for the next publisher
    /// after its own leaves. `None`: an unknown stream is rejected (1404).
    pub play_wait: Option<Duration>,
    /// Players start from the hub's GOP cache (default) rather than the next keyframe.
    pub play_gop_cache: bool,
    /// Unacknowledged bytes above which a player's packets are dropped (video to the next
    /// keyframe).
    pub max_send_backlog: usize,
    /// Most connections; past it handshakes are rejected. Default 1024; 0 removes the limit.
    pub max_conns: usize,
    /// Receive buffer / flow window in packets.
    pub flow_window: usize,
    /// Silence after which a peer is dropped.
    pub peer_idle_timeout: Duration,
    /// Authorizes connections (after the stream ID parsed).
    pub on_connect: Option<ConnectHook>,
}

impl Default for SrtConfig {
    fn default() -> Self {
        let c = Config::default();
        SrtConfig {
            latency: c.latency,
            passphrase: None,
            play_wait: None,
            play_gop_cache: true,
            max_send_backlog: DEFAULT_MAX_SEND_BACKLOG,
            max_conns: 1024,
            flow_window: c.flow_window,
            peer_idle_timeout: c.peer_idle_timeout,
            on_connect: None,
        }
    }
}

impl fmt::Debug for SrtConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtConfig")
            .field("latency", &self.latency)
            .field("encrypted", &self.passphrase.is_some())
            .field("play_wait", &self.play_wait)
            .field("play_gop_cache", &self.play_gop_cache)
            .field("max_send_backlog", &self.max_send_backlog)
            .finish_non_exhaustive()
    }
}

impl SrtConfig {
    /// Sets the latency.
    #[must_use]
    pub fn latency(mut self, d: Duration) -> SrtConfig {
        self.latency = d;
        self
    }

    /// Requires encryption with `p`.
    #[must_use]
    pub fn passphrase(mut self, p: impl Into<String>) -> SrtConfig {
        self.passphrase = Some(p.into());
        self
    }

    /// Lets players wait up to `d` for a publisher.
    #[must_use]
    pub fn play_wait(mut self, d: Duration) -> SrtConfig {
        self.play_wait = Some(d);
        self
    }

    fn conn_config(&self) -> Config {
        Config {
            latency: self.latency,
            passphrase: self.passphrase.clone(),
            flow_window: self.flow_window,
            peer_idle_timeout: self.peer_idle_timeout,
            ..Config::default()
        }
    }
}

// ---- session -------------------------------------------------------------------------------

/// Receives what a raw session ([`dial`]) gets. Runs on the I/O or timer thread with the
/// session locked: do not block, and do not call the session's own methods (use the
/// [`SrtSession`] given only to stash a clone).
pub trait SrtHandler: Send + 'static {
    /// The handshake completed.
    fn on_connect(&mut self, _s: &SrtSession) {}
    /// A payload arrived (in order, at its delivery time).
    fn on_data(&mut self, data: Vec<u8>);
    /// The session ended.
    fn on_close(&mut self, _err: Option<SrtError>) {}
}

enum Role {
    /// Received payloads are MPEG-TS for the hub.
    Ingest {
        hub: Hub,
        path: String,
        info: PeerInfo,
        demux: Demuxer,
        publisher: Option<Publisher>,
    },
    /// The hub stream goes out as MPEG-TS.
    Play {
        sub: Option<Subscription>,
        muxer: Option<Muxer>,
        timeline: Timeline,
        video: Vec<bool>,
        buf: Vec<u8>,
    },
    /// Payloads go to a handler.
    Raw(Box<dyn SrtHandler>),
    /// Nothing (rejected or done).
    None,
}

/// Where a session's datagrams go.
enum Udp {
    /// A UDP connection of the engine (listener peer, caller).
    Conn(Arc<ConnInner>),
    /// A socket bound to a local port (rendezvous), sending to the peer.
    Bound(UdpBinding, SocketAddr),
}

impl Udp {
    fn send(&self, b: &[u8]) {
        match self {
            Udp::Conn(c) => {
                let _ = c.send(b);
            }
            Udp::Bound(u, to) => {
                let _ = u.send_to(b, *to);
            }
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        match self {
            Udp::Conn(c) => c.peer_addr(),
            Udp::Bound(_, to) => *to,
        }
    }

    fn close(&self) {
        match self {
            Udp::Conn(c) => c.close_after_send(),
            Udp::Bound(u, _) => u.close(),
        }
    }
}

struct Inner {
    conn: Conn,
    udp: Udp,
    role: Role,
    scheduled: Option<Instant>,
    closed: bool,
    connected: bool,
}

struct SessionShared {
    inner: Mutex<Inner>,
    backlog: AtomicUsize,
    remote: SocketAddr,
    stream_id: String,
    on_closed: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// A handle to an SRT session (cheap to clone, any thread).
#[derive(Clone)]
pub struct SrtSession(Arc<SessionShared>);

impl fmt::Debug for SrtSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtSession")
            .field("remote", &self.0.remote)
            .field("stream_id", &self.0.stream_id)
            .finish_non_exhaustive()
    }
}

impl SrtSession {
    fn new(conn: Conn, udp: Udp, role: Role) -> SrtSession {
        let remote = udp.peer_addr();
        let stream_id = conn.stream_id().to_owned();
        SrtSession(Arc::new(SessionShared {
            inner: Mutex::new(Inner {
                conn,
                udp,
                role,
                scheduled: None,
                closed: false,
                connected: false,
            }),
            backlog: AtomicUsize::new(0),
            remote,
            stream_id,
            on_closed: Mutex::new(None),
        }))
    }

    /// The peer's address.
    pub fn remote(&self) -> SocketAddr {
        self.0.remote
    }

    /// The stream ID (sent or received).
    pub fn stream_id(&self) -> &str {
        &self.0.stream_id
    }

    /// Sends a payload (at most 1456 bytes; 1316 for MPEG-TS). Fails when not connected,
    /// closed, or the send buffer is full.
    pub fn send(&self, payload: &[u8]) -> Result<(), SrtError> {
        let mut g = lock(&self.0.inner);
        let r = g.conn.write(payload, Instant::now());
        self.pump(&mut g);
        r
    }

    /// Unacknowledged payload bytes.
    pub fn send_backlog(&self) -> usize {
        self.0.backlog.load(Ordering::Relaxed)
    }

    /// The connection's counters.
    pub fn stats(&self) -> Stats {
        lock(&self.0.inner).conn.stats()
    }

    /// Whether the handshake completed and the session is not closed.
    pub fn is_connected(&self) -> bool {
        let g = lock(&self.0.inner);
        g.connected && !g.closed
    }

    /// Closes the session (SHUTDOWN to the peer).
    pub fn close(&self) {
        let mut g = lock(&self.0.inner);
        g.conn.close(Instant::now());
        self.pump(&mut g);
    }

    fn handle(&self, data: &[u8]) {
        let mut g = lock(&self.0.inner);
        g.conn.handle(data, Instant::now());
        self.pump(&mut g);
    }

    fn on_timer(&self, at: Instant) {
        let mut g = lock(&self.0.inner);
        if g.scheduled == Some(at) {
            g.scheduled = None;
        }
        g.conn.handle_timeout(Instant::now());
        self.pump(&mut g);
    }

    /// Sends the output, handles the events and arms the timer.
    fn pump(&self, g: &mut Inner) {
        loop {
            for b in g.conn.take_output() {
                g.udp.send(&b);
            }
            let Some(ev) = g.conn.poll_event() else { break };
            match ev {
                Event::Connected => {
                    g.connected = true;
                    if let Role::Raw(h) = &mut g.role {
                        h.on_connect(self);
                    }
                }
                Event::Data(d) => self.data(g, &d),
                Event::Closed(err) => self.closed(g, err),
            }
        }
        self.0
            .backlog
            .store(g.conn.send_backlog(), Ordering::Relaxed);
        if g.closed {
            return;
        }
        if let Some(t) = g.conn.next_timeout() {
            if g.scheduled.is_none_or(|s| t < s) {
                g.scheduled = Some(t);
                let weak = Arc::downgrade(&self.0);
                crate::timer::after(t.saturating_duration_since(Instant::now()), move || {
                    if let Some(s) = weak.upgrade() {
                        SrtSession(s).on_timer(t);
                    }
                });
            }
        }
    }

    fn data(&self, g: &mut Inner, d: &[u8]) {
        match &mut g.role {
            Role::Ingest {
                hub,
                path,
                info,
                demux,
                publisher,
            } => {
                let mut evs = Vec::new();
                let _ = demux.feed(d, &mut |e| evs.push(e));
                let mut refused = false;
                for e in evs {
                    match e {
                        TsEvent::Tracks(t) => match publisher {
                            Some(p) => p.set_tracks(t),
                            None => match hub.publish(path, t, info.clone()) {
                                Ok(p) => *publisher = Some(p),
                                Err(_) => refused = true,
                            },
                        },
                        TsEvent::Packet(p) => {
                            if let Some(pb) = publisher {
                                pb.write(p);
                            }
                        }
                    }
                }
                if refused {
                    g.conn.close(Instant::now());
                }
            }
            Role::Raw(h) => h.on_data(d.to_vec()),
            Role::Play { .. } | Role::None => {}
        }
    }

    fn closed(&self, g: &mut Inner, err: Option<SrtError>) {
        if g.closed {
            return;
        }
        g.closed = true;
        match std::mem::replace(&mut g.role, Role::None) {
            Role::Raw(mut h) => h.on_close(err),
            Role::Ingest { publisher, .. } => drop(publisher),
            Role::Play { sub, .. } => {
                if let Some(s) = sub {
                    s.close();
                }
            }
            Role::None => {}
        }
        g.udp.close();
        let f = lock(&self.0.on_closed).take();
        if let Some(f) = f {
            f();
        }
    }

    /// Feeds a hub packet into a playing session.
    fn play_tracks(&self, tracks: &Tracks) {
        let mut g = lock(&self.0.inner);
        if let Role::Play {
            muxer,
            timeline,
            video,
            buf,
            ..
        } = &mut g.role
        {
            let mut m = Muxer::new(tracks);
            m.write_tables(buf);
            *muxer = Some(m);
            *video = tracks.iter().map(|t| t.codec.is_video()).collect();
            timeline.restart();
        }
        self.flush_play(&mut g);
    }

    fn play_packet(&self, pkt: &Packet) {
        let mut g = lock(&self.0.inner);
        if let Role::Play {
            muxer: Some(m),
            timeline,
            video,
            buf,
            ..
        } = &mut g.role
        {
            if !m.carries(pkt.track) {
                return;
            }
            let v = video.get(pkt.track).copied().unwrap_or(false);
            if v && pkt.keyframe {
                m.write_tables(buf); // so a decoder joining at this keyframe finds the program
            }
            let dts = timeline.stamp(v, pkt.dts);
            let mut p = pkt.clone();
            p.pts = dts + pkt.cts();
            p.dts = dts;
            m.write_packet(&p, buf);
        }
        self.flush_play(&mut g);
    }

    fn flush_play(&self, g: &mut Inner) {
        let Role::Play { buf, .. } = &mut g.role else {
            return;
        };
        if !g.connected || g.closed {
            // Held until the handshake completes (a caller pushing); bounded.
            if buf.len() > 8 << 20 {
                buf.clear();
            }
            return;
        }
        let data = std::mem::take(buf);
        let now = Instant::now();
        for chunk in data.chunks(TS_PAYLOAD_SIZE) {
            if g.conn.write(chunk, now).is_err() {
                break;
            }
        }
        self.pump(g);
    }

    fn play_closed(&self) {
        let mut g = lock(&self.0.inner);
        g.conn.close(Instant::now());
        self.pump(&mut g);
    }
}

/// The hub sink of a playing session.
struct PlaySink(Weak<SessionShared>);

impl Sink for PlaySink {
    fn on_tracks(&mut self, tracks: &Tracks) {
        if let Some(s) = self.0.upgrade() {
            SrtSession(s).play_tracks(tracks);
        }
    }
    fn on_packet(&mut self, pkt: &Arc<Packet>) {
        if let Some(s) = self.0.upgrade() {
            SrtSession(s).play_packet(pkt);
        }
    }
    fn on_close(&mut self, _err: HubError) {
        if let Some(s) = self.0.upgrade() {
            SrtSession(s).play_closed();
        }
    }
}

fn play_role() -> Role {
    Role::Play {
        sub: None,
        muxer: None,
        timeline: Timeline::new(),
        video: Vec::new(),
        buf: Vec::new(),
    }
}

/// Subscribes a playing session to `path` (without its lock held: the hub delivers the
/// tracks and the GOP cache right away).
fn start_play(
    s: &SrtSession,
    hub: &Hub,
    path: &str,
    opts: SubscribeOptions,
    limit: usize,
) -> Result<(), HubError> {
    let shared = s.0.clone();
    let mut sub_slot = None;
    let res = (|| {
        let backlog_of = Arc::downgrade(&shared);
        let sink = Dropper::new(
            PlaySink(Arc::downgrade(&shared)),
            move || {
                backlog_of
                    .upgrade()
                    .map_or(0, |s| s.backlog.load(Ordering::Relaxed))
            },
            limit,
        );
        let mut sub = hub.subscribe(path, sink, opts)?;
        let _ = sub.drop_counter();
        sub_slot = Some(sub);
        Ok(())
    })();
    if let Some(sub) = sub_slot {
        let mut g = lock(&shared.inner);
        match &mut g.role {
            Role::Play { sub: slot, .. } => *slot = Some(sub),
            _ => sub.close(),
        }
    }
    res
}

// ---- server --------------------------------------------------------------------------------

struct ServerInner {
    cfg: SrtConfig,
    hub: Hub,
    listener: Mutex<Listener>,
    conns: Arc<AtomicUsize>,
}

/// An SRT server: the acceptor of a UDP listener (`Listener::udp(addr).serve(server)`).
/// Callers that publish (`m=publish`) are demuxed into the hub (the path is reserved during the
/// handshake, so a second publisher is rejected with 1409); callers that play (`m=request`,
/// the default) get the hub stream as MPEG-TS, 7 transport packets per SRT packet.
#[derive(Clone)]
pub struct SrtServer(Arc<ServerInner>);

impl fmt::Debug for SrtServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtServer")
            .field("cfg", &self.0.cfg)
            .field("conns", &self.0.conns.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SrtServer {
    /// A server publishing into and playing from `hub`.
    pub fn new(hub: Hub, cfg: SrtConfig) -> SrtServer {
        SrtServer(Arc::new(ServerInner {
            cfg,
            hub,
            listener: Mutex::new(Listener::new()),
            conns: Arc::new(AtomicUsize::new(0)),
        }))
    }

    /// Connected sessions.
    pub fn connections(&self) -> usize {
        self.0.conns.load(Ordering::Relaxed)
    }
}

/// One peer address of an [`SrtServer`].
pub struct SrtPeer {
    server: Arc<ServerInner>,
    session: Option<(SrtSession, u32)>,
}

impl fmt::Debug for SrtPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtPeer")
            .field("session", &self.session.as_ref().map(|s| &s.0))
            .finish_non_exhaustive()
    }
}

impl Acceptor for SrtServer {
    type Handler = SrtPeer;
    fn on_open(&self, _c: &AkioConn<SrtPeer>) -> SrtPeer {
        SrtPeer {
            server: self.0.clone(),
            session: None,
        }
    }
}

enum Accepted {
    Publish(Publisher, String, PeerInfo),
    Play(String, PeerInfo),
}

fn hub_reject(e: &HubError) -> RejectReason {
    match e {
        HubError::StreamBusy => RejectReason::CONFLICT,
        HubError::NotFound => RejectReason::NOT_FOUND,
        HubError::Limit => RejectReason::OVERLOAD,
        HubError::Closed => RejectReason::CLOSE,
        _ => RejectReason::FORBIDDEN,
    }
}

impl Handler for SrtPeer {
    fn on_data(&mut self, c: &AkioConn<Self>, data: &[u8]) {
        if let Some((s, peer_id)) = &self.session {
            match is_handshake(data) {
                Some((id, _)) if id != *peer_id => {
                    // The caller restarted: drop the old session, handshake anew.
                    s.close();
                    self.session = None;
                }
                _ => return s.handle(data),
            }
        }
        let srv = self.server.clone();
        let cfg = &srv.cfg;
        let mut out = Vec::new();
        let mut accepted = None;
        let conn =
            lock(&srv.listener).handle(data, c.peer_addr(), Instant::now(), &mut out, |req| {
                let id = StreamId::parse(&req.stream_id).ok_or(RejectReason::BAD_REQUEST)?;
                if let Some(hook) = &cfg.on_connect {
                    hook(req, &id)?;
                }
                if cfg.max_conns > 0 && srv.conns.load(Ordering::Relaxed) >= cfg.max_conns {
                    return Err(RejectReason::OVERLOAD);
                }
                let info = PeerInfo::new("srt", Some(req.remote), id.query.clone());
                match id.mode {
                    Mode::Publish => {
                        let p = srv
                            .hub
                            .reserve(&id.resource, info.clone())
                            .map_err(|e| hub_reject(&e))?;
                        accepted = Some(Accepted::Publish(p, id.resource, info));
                    }
                    Mode::Request => {
                        let live = srv
                            .hub
                            .stream_info(&id.resource)
                            .is_some_and(|s| s.publishing);
                        if !live && cfg.play_wait.is_none() {
                            return Err(RejectReason::NOT_FOUND);
                        }
                        accepted = Some(Accepted::Play(id.resource, info));
                    }
                    _ => return Err(RejectReason::BAD_MODE),
                }
                Ok(cfg.conn_config())
            });
        for b in out {
            let _ = c.send(&b);
        }
        let (Some(conn), Some(acc)) = (conn, accepted) else {
            return;
        };
        let peer_id = conn.peer_id;
        let (role, play) = match acc {
            Accepted::Publish(p, path, info) => (
                Role::Ingest {
                    hub: srv.hub.clone(),
                    path,
                    info,
                    demux: Demuxer::new(),
                    publisher: Some(p),
                },
                None,
            ),
            Accepted::Play(path, info) => (play_role(), Some((path, info))),
        };
        let s = SrtSession::new(conn, Udp::Conn(c.inner().clone()), role);
        srv.conns.fetch_add(1, Ordering::Relaxed);
        let conns = srv.conns.clone();
        *lock(&s.0.on_closed) = Some(Box::new(move || {
            conns.fetch_sub(1, Ordering::Relaxed);
        }));
        {
            let mut g = lock(&s.0.inner);
            s.pump(&mut g);
        }
        if let Some((path, info)) = play {
            let mut o = SubscribeOptions::new(info);
            o.wait = cfg.play_wait;
            o.no_gop_cache = !cfg.play_gop_cache;
            if start_play(&s, &srv.hub, &path, o, cfg.max_send_backlog).is_err() {
                s.close();
            }
        }
        self.session = Some((s, peer_id));
    }

    fn on_close(&mut self, _c: &AkioConn<Self>, err: Option<akio::Error>) {
        if let Some((s, _)) = self.session.take() {
            let mut g = lock(&s.0.inner);
            g.conn.close_with(Some(SrtError::Transport(
                err.map_or_else(|| "closed".to_owned(), |e| e.to_string()),
            )));
            s.pump(&mut g);
        }
    }
}

// ---- caller --------------------------------------------------------------------------------

/// Runs once a caller's UDP socket is open.
type AfterOpen = Box<dyn FnOnce(&SrtSession) + Send>;

struct CallerAcceptor {
    cfg: Config,
    role: Mutex<Option<Role>>,
    slot: Arc<Mutex<Option<SrtSession>>>,
    after: Mutex<Option<AfterOpen>>,
}

/// The UDP handler of a caller session.
struct CallerPeer(Option<SrtSession>);

impl Handler for CallerPeer {
    fn on_data(&mut self, _c: &AkioConn<Self>, data: &[u8]) {
        if let Some(s) = &self.0 {
            s.handle(data);
        }
    }
    fn on_close(&mut self, _c: &AkioConn<Self>, err: Option<akio::Error>) {
        if let Some(s) = self.0.take() {
            let mut g = lock(&s.0.inner);
            g.conn.close_with(Some(SrtError::Transport(
                err.map_or_else(|| "closed".to_owned(), |e| e.to_string()),
            )));
            s.pump(&mut g);
        }
    }
}

impl Acceptor for CallerAcceptor {
    type Handler = CallerPeer;
    fn on_open(&self, c: &AkioConn<CallerPeer>) -> CallerPeer {
        let role = lock(&self.role).take().unwrap_or(Role::None);
        let Ok(conn) = Conn::caller(self.cfg.clone(), Instant::now()) else {
            c.close();
            return CallerPeer(None);
        };
        let s = SrtSession::new(conn, Udp::Conn(c.inner().clone()), role);
        {
            let mut g = lock(&s.0.inner);
            s.pump(&mut g);
        }
        *lock(&self.slot) = Some(s.clone());
        let f = lock(&self.after).take();
        if let Some(f) = f {
            f(&s);
        }
        CallerPeer(Some(s))
    }
}

fn dial_role(
    engine: &Engine,
    addr: SocketAddr,
    mut cfg: Config,
    role: Role,
    after: Option<AfterOpen>,
) -> Result<SrtSession, SrtError> {
    cfg.check()?;
    let slot = Arc::new(Mutex::new(None));
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), SrtError>>();
    let acc = CallerAcceptor {
        cfg,
        role: Mutex::new(Some(role)),
        slot: slot.clone(),
        after: Mutex::new(after),
    };
    engine.dial_udp(addr, acc, move |e| {
        let _ = tx.send(Err(SrtError::Transport(e.to_string())));
    });
    // on_open runs on an I/O thread right away (UDP has no handshake): wait for it briefly.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let opened = lock(&slot).clone();
        if let Some(s) = opened {
            return Ok(s);
        }
        if let Ok(Err(e)) = rx.try_recv() {
            return Err(e);
        }
        if Instant::now() > deadline {
            return Err(SrtError::Transport("dial timed out".into()));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Dials an SRT listener at `addr` as a caller; `handler` hears the session's events. The
/// engine needs UDP client threads (`EngineBuilder::udp_client_threads`). Returns once the
/// UDP socket is open (the handshake goes on in the background: [`SrtSession::is_connected`]).
/// Do not call from an I/O thread callback (it waits briefly for the socket).
pub fn dial(
    engine: &Engine,
    addr: SocketAddr,
    cfg: Config,
    handler: impl SrtHandler,
) -> Result<SrtSession, SrtError> {
    dial_role(engine, addr, cfg, Role::Raw(Box::new(handler)), None)
}

/// Pushes the hub stream at `path` to the listener at `addr` (an SRT server with
/// `streamid=...m=publish` in `cfg.stream_id`, or ffmpeg with `mode=listener`), muxed into
/// MPEG-TS.
pub fn push(
    engine: &Engine,
    addr: SocketAddr,
    cfg: Config,
    hub: &Hub,
    path: &str,
) -> Result<SrtSession, SrtError> {
    let hub = hub.clone();
    let path = path.to_owned();
    let after: AfterOpen = Box::new(move |s| {
        let s = s.clone();
        // Subscribe off the I/O thread's session lock (the hub calls back right away).
        std::thread::spawn(move || {
            let mut o = SubscribeOptions::new(PeerInfo::new("srt", Some(s.remote()), ""));
            o.wait = Some(Duration::from_secs(10));
            if start_play(&s, &hub, &path, o, DEFAULT_MAX_SEND_BACKLOG).is_err() {
                s.close();
            }
        });
    });
    dial_role(engine, addr, cfg, play_role(), Some(after))
}

/// Pulls MPEG-TS from the listener at `addr` (`cfg.stream_id` names what to play) and
/// publishes it in `hub` at `path`, which is reserved right away.
pub fn pull(
    engine: &Engine,
    addr: SocketAddr,
    cfg: Config,
    hub: &Hub,
    path: &str,
) -> Result<SrtSession, SrtError> {
    let info = PeerInfo::new("srt", Some(addr), "");
    let publisher = hub
        .reserve(path, info.clone())
        .map_err(|e| SrtError::Rejected(hub_reject(&e)))?;
    let role = Role::Ingest {
        hub: hub.clone(),
        path: path.to_owned(),
        info,
        demux: Demuxer::new(),
        publisher: Some(publisher),
    };
    dial_role(engine, addr, cfg, role, None)
}

// ---- rendezvous ----------------------------------------------------------------------------

/// The acceptor of a rendezvous socket: datagrams from the peer go to the session, others are
/// ignored.
struct RdvAcceptor {
    remote: SocketAddr,
    slot: Arc<Mutex<Option<SrtSession>>>,
}

struct RdvPeer {
    from_peer: bool,
    slot: Arc<Mutex<Option<SrtSession>>>,
}

impl Acceptor for RdvAcceptor {
    type Handler = RdvPeer;
    fn on_open(&self, c: &AkioConn<RdvPeer>) -> RdvPeer {
        let from_peer = c.peer_addr() == self.remote;
        if !from_peer {
            c.close();
        }
        RdvPeer {
            from_peer,
            slot: self.slot.clone(),
        }
    }
}

impl Handler for RdvPeer {
    fn on_data(&mut self, _c: &AkioConn<Self>, data: &[u8]) {
        if !self.from_peer {
            return;
        }
        let s = lock(&self.slot).clone();
        if let Some(s) = s {
            s.handle(data);
        }
    }
    fn on_close(&mut self, _c: &AkioConn<Self>, err: Option<akio::Error>) {
        if !self.from_peer {
            return;
        }
        let s = lock(&self.slot).take();
        if let Some(s) = s {
            let mut g = lock(&s.0.inner);
            g.conn.close_with(Some(SrtError::Transport(
                err.map_or_else(|| "closed".to_owned(), |e| e.to_string()),
            )));
            s.pump(&mut g);
        }
    }
}

fn rendezvous_role(
    engine: &Engine,
    local: SocketAddr,
    remote: SocketAddr,
    cfg: Config,
    role: Role,
) -> Result<SrtSession, SrtError> {
    let conn = Conn::rendezvous(cfg, remote, Instant::now())?;
    let slot = Arc::new(Mutex::new(None));
    let binding = engine
        .bind_udp(
            local,
            RdvAcceptor {
                remote,
                slot: slot.clone(),
            },
        )
        .map_err(|e| SrtError::Transport(e.to_string()))?;
    let s = SrtSession::new(conn, Udp::Bound(binding, remote), role);
    *lock(&slot) = Some(s.clone());
    {
        let mut g = lock(&s.0.inner);
        s.pump(&mut g);
    }
    Ok(s)
}

/// Starts a rendezvous with the peer at `remote` from a UDP socket bound at `local` (the port
/// the peer sends to; both sides start at about the same time, e.g. through NATs that each
/// side punches); `handler` hears the session's events. The engine needs UDP client threads
/// (`EngineBuilder::udp_client_threads`). Returns once the socket is bound; the handshake goes
/// on in the background ([`SrtSession::is_connected`]) and gives up after ten times
/// [`Config::handshake_timeout`]. See [`Conn::rendezvous`] for the protocol.
pub fn rendezvous(
    engine: &Engine,
    local: SocketAddr,
    remote: SocketAddr,
    cfg: Config,
    handler: impl SrtHandler,
) -> Result<SrtSession, SrtError> {
    rendezvous_role(engine, local, remote, cfg, Role::Raw(Box::new(handler)))
}

/// [`push`] over a [`rendezvous`]: the hub stream at `path` goes to the peer at `remote` as
/// MPEG-TS once the handshake completes.
pub fn push_rendezvous(
    engine: &Engine,
    local: SocketAddr,
    remote: SocketAddr,
    cfg: Config,
    hub: &Hub,
    path: &str,
) -> Result<SrtSession, SrtError> {
    let s = rendezvous_role(engine, local, remote, cfg, play_role())?;
    let hub = hub.clone();
    let path = path.to_owned();
    let s2 = s.clone();
    // Subscribe off the caller's thread's session lock (the hub calls back right away).
    std::thread::spawn(move || {
        let mut o = SubscribeOptions::new(PeerInfo::new("srt", Some(s2.remote()), ""));
        o.wait = Some(Duration::from_secs(10));
        if start_play(&s2, &hub, &path, o, DEFAULT_MAX_SEND_BACKLOG).is_err() {
            s2.close();
        }
    });
    Ok(s)
}

/// [`pull`] over a [`rendezvous`]: MPEG-TS from the peer at `remote` is published in `hub` at
/// `path`, which is reserved right away.
pub fn pull_rendezvous(
    engine: &Engine,
    local: SocketAddr,
    remote: SocketAddr,
    cfg: Config,
    hub: &Hub,
    path: &str,
) -> Result<SrtSession, SrtError> {
    let info = PeerInfo::new("srt", Some(remote), "");
    let publisher = hub
        .reserve(path, info.clone())
        .map_err(|e| SrtError::Rejected(hub_reject(&e)))?;
    let role = Role::Ingest {
        hub: hub.clone(),
        path: path.to_owned(),
        info,
        demux: Demuxer::new(),
        publisher: Some(publisher),
    };
    rendezvous_role(engine, local, remote, cfg, role)
}
