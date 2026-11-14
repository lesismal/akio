#![forbid(unsafe_code)]
//! KCP for flash: reliable, ordered messages over UDP, wire-compatible with
//! [skywind3000/kcp](https://github.com/skywind3000/kcp) and with
//! [kcp-go](https://github.com/xtaci/kcp-go)'s FEC and encryption (so with kcptun and fib's kcp).
//!
//! A [`KcpServer`] is the acceptor of a UDP [`flash::Listener`]: each peer address that starts
//! a conversation gets a [`Session`] and a [`KcpHandler`] from the factory. [`dial`] starts a
//! client session on an engine with UDP client threads. A session's KCP is driven by the
//! datagrams its I/O thread reads, by a shared timer thread and by [`Session::send`]; the
//! handler's `on_message` runs on the I/O thread, one message at a time, in order.
//!
//! ```no_run
//! use flash::{Engine, Listener};
//! use flash_kcp::{Config, KcpHandler, KcpServer, Session};
//!
//! struct Echo;
//! impl KcpHandler for Echo {
//!     fn on_message(&mut self, s: &Session, msg: Vec<u8>) {
//!         let _ = s.send(&msg);
//!     }
//! }
//! let server = KcpServer::new(Config::fast(), |_s: &Session| Echo).unwrap();
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:4000".parse().unwrap()).serve(server))
//!     .build()
//!     .unwrap();
//! engine.start().unwrap();
//! ```
//!
//! Guide: [KCP](https://lesismal.github.io/flash/en/protocols/kcp.html)
//! (中文: [KCP](https://lesismal.github.io/flash/zh-CN/protocols/kcp.html)).
#![warn(clippy::unwrap_used)]

pub mod crypt;
mod fec;
mod frame;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod kcp;
mod rs;

use std::collections::BinaryHeap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use flash_core::{Acceptor, Conn, Handler};

pub use crypt::Crypt;
pub use kcp::{Kcp, KcpError};

use frame::Framer;

/// A session's settings; both sides should agree on the KCP knobs, and must on FEC and crypt.
#[derive(Debug, Clone)]
pub struct Config {
    /// KCP `nodelay`: 0 normal, 1 fast retransmission timing.
    pub nodelay: i32,
    /// Internal update interval in milliseconds (10..=5000; KCP's default is 100).
    pub interval: i32,
    /// Fast resend after this many duplicate ACKs (0 off).
    pub resend: i32,
    /// Turns congestion control off.
    pub no_congestion: bool,
    /// Send window in segments.
    pub send_window: i32,
    /// Receive window in segments.
    pub recv_window: i32,
    /// Largest datagram sent, framing included.
    pub mtu: usize,
    /// KCP stream mode: sends are packed into whole segments, so messages are not preserved.
    pub stream: bool,
    /// Transmissions of an unacknowledged segment before the session closes with
    /// [`CloseReason::DeadLink`].
    pub dead_link: u32,
    /// Datagram encryption, as kcp-go's crypt of the same name and key.
    pub crypt: Option<Arc<Crypt>>,
    /// kcp-go's forward error correction (kcptun default 10 data / 3 parity); either at zero
    /// turns it off.
    pub data_shards: usize,
    /// See `data_shards`.
    pub parity_shards: usize,
    /// [`Session::send`] fails with `KcpError::Full` once this many segments wait (0: twice
    /// the send window).
    pub write_queue: usize,
}

impl Default for Config {
    /// The reference implementation's normal mode.
    fn default() -> Config {
        Config {
            nodelay: 0,
            interval: 100,
            resend: 0,
            no_congestion: false,
            send_window: kcp::DEFAULT_WINDOW as i32,
            recv_window: kcp::DEFAULT_WINDOW as i32,
            mtu: kcp::DEFAULT_MTU as usize,
            stream: false,
            dead_link: 20,
            crypt: None,
            data_shards: 0,
            parity_shards: 0,
            write_queue: 0,
        }
    }
}

impl Config {
    /// kcptun's "fast3": nodelay, 10 ms interval, resend after 2, no congestion control.
    pub fn fast() -> Config {
        Config {
            nodelay: 1,
            interval: 10,
            resend: 2,
            no_congestion: true,
            ..Config::default()
        }
    }

    fn validate(&self) -> Result<(), String> {
        let fr = Framer::new(self.data_shards, self.parity_shards).ok_or("bad FEC shard counts")?;
        let ovh = fr.overhead(self.crypt.as_deref());
        if self.mtu < kcp::OVERHEAD + ovh + 1 || self.mtu > 1500 {
            return Err("MTU out of range for the framing".into());
        }
        Ok(())
    }
}

/// Why a session closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// [`Session::close`] closed it.
    Closed,
    /// A segment went unacknowledged through `Config::dead_link` transmissions.
    DeadLink,
    /// The peer started a new conversation from the same address.
    Replaced,
    /// The UDP connection under it closed (the engine's UDP idle timeout, an ICMP error, a
    /// shutdown) or could not be created.
    Transport,
}

/// The application side of a session.
pub trait KcpHandler: Send + 'static {
    /// A whole message (in stream mode, whatever bytes arrived), in order. It runs on the I/O
    /// thread that also reads the peer's ACKs, so it must not block waiting for
    /// [`Session::send`] to stop failing with `KcpError::Full`: queue or drop instead.
    fn on_message(&mut self, s: &Session, msg: Vec<u8>);
    /// The session closed; called once.
    fn on_close(&mut self, _s: &Session, _why: CloseReason) {}
}

/// Session statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Segments sent for the first time.
    pub sent: u64,
    /// Segments retransmitted on timeout.
    pub retransmitted: u64,
    /// Segments retransmitted fast (duplicate ACKs).
    pub fast_retransmitted: u64,
    /// Loss events.
    pub lost: u64,
    /// Packets the FEC recovered.
    pub recovered: u64,
}

struct State {
    kcp: Kcp,
    fr: Framer,
    conn: Option<Conn<Udp>>,
    out: Vec<Vec<u8>>,
    closed: Option<CloseReason>,
    armed: Option<Instant>,
}

struct Shared {
    cfg: Config,
    conv: u32,
    remote: SocketAddr,
    epoch: Instant,
    write_queue: usize,
    state: Mutex<State>,
    handler: Mutex<Option<Box<dyn KcpHandler>>>,
    owner: Option<Arc<ServerShared>>,
    client: bool,
}

/// A KCP conversation with one peer. Cheap to clone and usable from any thread.
#[derive(Clone)]
pub struct Session(Arc<Shared>);

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    fn new(
        cfg: &Config,
        conv: u32,
        remote: SocketAddr,
        owner: Option<Arc<ServerShared>>,
    ) -> Session {
        let fr = Framer::new(cfg.data_shards, cfg.parity_shards).expect("validated");
        let mut k = Kcp::new(conv);
        k.set_mtu(cfg.mtu - fr.overhead(cfg.crypt.as_deref()));
        k.nodelay(cfg.nodelay, cfg.interval, cfg.resend, cfg.no_congestion);
        k.set_window(cfg.send_window, cfg.recv_window);
        k.set_stream(cfg.stream);
        k.set_dead_link(cfg.dead_link);
        let write_queue = if cfg.write_queue == 0 {
            2 * cfg.send_window.max(1) as usize
        } else {
            cfg.write_queue
        };
        Session(Arc::new(Shared {
            cfg: cfg.clone(),
            conv,
            remote,
            epoch: Instant::now(),
            write_queue,
            state: Mutex::new(State {
                kcp: k,
                fr,
                conn: None,
                out: Vec::new(),
                closed: None,
                armed: None,
            }),
            handler: Mutex::new(None),
            client: owner.is_none(),
            owner,
        }))
    }

    /// The conversation id.
    pub fn conv(&self) -> u32 {
        self.0.conv
    }

    /// The peer's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.0.remote
    }

    /// Whether the session is still open.
    pub fn is_open(&self) -> bool {
        lock(&self.0.state).closed.is_none()
    }

    /// Segments queued or in flight.
    pub fn wait_send(&self) -> usize {
        lock(&self.0.state).kcp.wait_send()
    }

    /// Counters since the session started.
    pub fn stats(&self) -> Stats {
        let st = lock(&self.0.state);
        let s = st.kcp.stats;
        Stats {
            sent: s[0],
            retransmitted: s[1],
            fast_retransmitted: s[2],
            lost: s[3],
            recovered: st.fr.recovered,
        }
    }

    /// Queues a message and sends what KCP allows right away. Fails with `KcpError::Closed`
    /// once closed, `KcpError::Full` when `Config::write_queue` segments wait, or as KCP's send.
    pub fn send(&self, msg: &[u8]) -> Result<(), KcpError> {
        let mut st = lock(&self.0.state);
        if st.closed.is_some() {
            return Err(KcpError::Closed);
        }
        if st.kcp.wait_send() >= self.0.write_queue {
            return Err(KcpError::Full);
        }
        st.kcp.send(msg)?;
        let now = self.now_ms();
        self.flush_locked(&mut st, now);
        self.unlock(st);
        Ok(())
    }

    /// Closes the session: what is due goes out, the handler's `on_close` runs.
    pub fn close(&self) {
        self.close_with(CloseReason::Closed);
    }

    fn now_ms(&self) -> u32 {
        self.0.epoch.elapsed().as_millis() as u32
    }

    fn flush_locked(&self, st: &mut State, now: u32) {
        let State { kcp, fr, out, .. } = st;
        let crypt = self.0.cfg.crypt.as_deref();
        kcp.flush(now, &mut |p| {
            fr.encode(crypt, p, i64::from(now), &mut |d| out.push(d));
        });
    }

    /// Flushes what is due, checks for a dead link, rearms the timer, releases the lock and
    /// sends what was framed.
    fn unlock(&self, mut st: std::sync::MutexGuard<'_, State>) {
        let mut dead = false;
        if st.closed.is_none() {
            let now = self.now_ms();
            if st
                .kcp
                .next_flush(now)
                .is_some_and(|at| at.wrapping_sub(now) as i32 <= 0)
            {
                self.flush_locked(&mut st, now);
            }
            dead = st.kcp.is_dead();
            if !dead {
                self.rearm(&mut st, now);
            }
        }
        let conn = st.conn.clone();
        let out = if conn.is_some() {
            std::mem::take(&mut st.out)
        } else {
            Vec::new()
        };
        drop(st);
        if let Some(c) = conn {
            for d in out {
                let _ = c.send_owned(d);
            }
        }
        if dead {
            self.close_with(CloseReason::DeadLink);
        }
    }

    fn rearm(&self, st: &mut State, now: u32) {
        let Some(at) = st.kcp.next_flush(now) else {
            return;
        };
        let wait = (at.wrapping_sub(now) as i32).max(0) as u64;
        let when = Instant::now() + Duration::from_millis(wait);
        if st.armed.is_none_or(|a| when < a) {
            st.armed = Some(when);
            ticker().schedule(when, Arc::downgrade(&self.0));
        }
    }

    fn on_timer(&self, at: Instant) {
        let mut st = lock(&self.0.state);
        if st.armed != Some(at) || st.closed.is_some() {
            return;
        }
        st.armed = None;
        let now = self.now_ms();
        self.flush_locked(&mut st, now);
        self.unlock(st);
    }

    /// Feeds opened datagrams, then hands complete messages to the handler.
    fn input(&self, dgrams: &[Vec<u8>]) {
        let mut st = lock(&self.0.state);
        if st.closed.is_some() {
            return;
        }
        let now = self.now_ms();
        for d in dgrams {
            let State { kcp, fr, .. } = &mut *st;
            fr.decode(d, &mut |p| {
                let _ = kcp.input(p, now);
            });
        }
        let mut msgs = Vec::new();
        while let Some(m) = st.kcp.recv() {
            msgs.push(m);
        }
        self.unlock(st);
        if !msgs.is_empty() {
            self.deliver(msgs);
        }
    }

    fn deliver(&self, msgs: Vec<Vec<u8>>) {
        let Some(mut h) = lock(&self.0.handler).take() else {
            return;
        };
        for m in msgs {
            h.on_message(self, m);
        }
        *lock(&self.0.handler) = Some(h);
        // A close while the handler was out could not notify it.
        if lock(&self.0.state).closed.is_some() {
            self.notify_close();
        }
    }

    fn notify_close(&self) {
        let h = lock(&self.0.handler).take();
        if let Some(mut h) = h {
            let why = lock(&self.0.state)
                .closed
                .clone()
                .unwrap_or(CloseReason::Closed);
            h.on_close(self, why);
        }
    }

    fn close_with(&self, why: CloseReason) {
        let mut st = lock(&self.0.state);
        if st.closed.is_some() {
            return;
        }
        if why == CloseReason::Closed {
            let now = self.now_ms();
            self.flush_locked(&mut st, now);
        }
        st.closed = Some(why);
        st.armed = None;
        let conn = st.conn.take();
        let out = std::mem::take(&mut st.out);
        drop(st);
        if let Some(c) = conn {
            for d in out {
                let _ = c.send_owned(d);
            }
            if self.0.client {
                c.close_after_send();
            }
        }
        if let Some(o) = &self.0.owner {
            o.sessions.fetch_sub(1, Ordering::Relaxed);
        }
        self.notify_close();
    }

    fn attach(&self, conn: Conn<Udp>) {
        let mut st = lock(&self.0.state);
        if st.closed.is_some() {
            drop(st);
            conn.close();
            return;
        }
        st.conn = Some(conn);
        self.unlock(st);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- the timer thread shared by every session ----

struct Due {
    at: Instant,
    s: Weak<Shared>,
}

impl PartialEq for Due {
    fn eq(&self, o: &Due) -> bool {
        self.at == o.at
    }
}
impl Eq for Due {}
impl PartialOrd for Due {
    fn partial_cmp(&self, o: &Due) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Due {
    fn cmp(&self, o: &Due) -> std::cmp::Ordering {
        o.at.cmp(&self.at) // min-heap
    }
}

struct Ticker {
    heap: Mutex<BinaryHeap<Due>>,
    cv: Condvar,
}

impl Ticker {
    fn schedule(&self, at: Instant, s: Weak<Shared>) {
        let mut h = lock(&self.heap);
        let earliest = h.peek().is_none_or(|d| at < d.at);
        h.push(Due { at, s });
        drop(h);
        if earliest {
            self.cv.notify_one();
        }
    }

    fn run(&self) {
        let mut h = lock(&self.heap);
        loop {
            let now = Instant::now();
            match h.peek() {
                None => h = self.cv.wait(h).unwrap_or_else(|e| e.into_inner()),
                Some(d) if d.at > now => {
                    let wait = d.at - now;
                    h = self
                        .cv
                        .wait_timeout(h, wait)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                Some(_) => {
                    let d = h.pop().expect("peeked");
                    drop(h);
                    if let Some(s) = d.s.upgrade() {
                        Session(s).on_timer(d.at);
                    }
                    h = lock(&self.heap);
                }
            }
        }
    }
}

fn ticker() -> &'static Ticker {
    static T: OnceLock<&'static Ticker> = OnceLock::new();
    T.get_or_init(|| {
        let t: &'static Ticker = Box::leak(Box::new(Ticker {
            heap: Mutex::new(BinaryHeap::new()),
            cv: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("flash-kcp-timer".into())
            .spawn(move || t.run())
            .expect("spawn the KCP timer thread");
        t
    })
}

// ---- the UDP side ----

type Factory = dyn Fn(&Session) -> Box<dyn KcpHandler> + Send + Sync;

struct ServerShared {
    cfg: Config,
    factory: Box<Factory>,
    max_sessions: usize,
    sessions: AtomicUsize,
}

/// Serves KCP on a UDP listener: an [`Acceptor`] whose peers each get a session. A datagram
/// from a peer without one starts a session when its first segment opens a conversation (data
/// with sequence number 0); a peer opening another conversation that way replaces its session.
pub struct KcpServer(Arc<ServerShared>);

impl std::fmt::Debug for KcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpServer").finish_non_exhaustive()
    }
}

impl KcpServer {
    /// A server whose sessions get handlers from `factory`.
    pub fn new<H: KcpHandler, F>(cfg: Config, factory: F) -> Result<KcpServer, String>
    where
        F: Fn(&Session) -> H + Send + Sync + 'static,
    {
        cfg.validate()?;
        Ok(KcpServer(Arc::new(ServerShared {
            cfg,
            factory: Box::new(move |s| Box::new(factory(s))),
            max_sessions: 0,
            sessions: AtomicUsize::new(0),
        })))
    }

    /// Bounds the open sessions (0, the default, is unlimited).
    #[must_use]
    pub fn max_sessions(mut self, n: usize) -> KcpServer {
        if let Some(s) = Arc::get_mut(&mut self.0) {
            s.max_sessions = n;
        }
        self
    }

    /// Open sessions.
    pub fn sessions(&self) -> usize {
        self.0.sessions.load(Ordering::Relaxed)
    }
}

impl Acceptor for KcpServer {
    type Handler = Udp;
    fn on_open(&self, _c: &Conn<Udp>) -> Udp {
        Udp {
            server: Some(self.0.clone()),
            session: None,
        }
    }
}

/// The UDP connection handler under a session (internal).
#[doc(hidden)]
pub struct Udp {
    server: Option<Arc<ServerShared>>,
    session: Option<Session>,
}

impl std::fmt::Debug for Udp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Udp").finish_non_exhaustive()
    }
}

impl Udp {
    fn start(&self, c: &Conn<Udp>, conv: u32) -> Option<Session> {
        let srv = self.server.as_ref()?;
        if srv.max_sessions > 0 && srv.sessions.load(Ordering::Relaxed) >= srv.max_sessions {
            return None;
        }
        srv.sessions.fetch_add(1, Ordering::Relaxed);
        let s = Session::new(&srv.cfg, conv, c.peer_addr(), Some(srv.clone()));
        let h = (srv.factory)(&s);
        *lock(&s.0.handler) = Some(h);
        s.attach(c.clone());
        Some(s)
    }
}

impl Handler for Udp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (crypt, server) = match (&self.server, &self.session) {
            (Some(srv), _) => (srv.cfg.crypt.clone(), true),
            (None, Some(s)) => (s.0.cfg.crypt.clone(), false),
            (None, None) => return,
        };
        let Some(o) = frame::open(crypt.as_deref(), data) else {
            return;
        };
        if let Some(s) = &self.session {
            if !s.is_open() && server {
                self.session = None;
            }
        }
        let peek = frame::peek(&o);
        if let Some(s) = &self.session {
            if !server || peek.is_none_or(|(conv, _, _)| conv == s.conv()) {
                s.input(&[o]);
                return;
            }
        }
        let Some((conv, cmd, sn)) = peek else {
            return;
        };
        if cmd != 81 || sn != 0 {
            return; // not a conversation's start: the peer's session is gone
        }
        if let Some(old) = self.session.take() {
            old.close_with(CloseReason::Replaced);
        }
        self.session = self.start(c, conv);
        if let Some(s) = &self.session {
            s.input(&[o]);
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash_core::Error>) {
        if let Some(s) = self.session.take() {
            s.close_with(CloseReason::Transport);
        }
    }
}

struct Client(Session);

impl Acceptor for Client {
    type Handler = Udp;
    fn on_open(&self, c: &Conn<Udp>) -> Udp {
        self.0.attach(c.clone());
        Udp {
            server: None,
            session: Some(self.0.clone()),
        }
    }
}

/// Starts a client session to `addr` with a random conversation id. The engine needs UDP
/// client threads ([`flash::EngineBuilder::udp_client_threads`]) and must be started. Messages
/// may be sent right away; they go out once the socket is up.
pub fn dial<H: KcpHandler>(
    engine: &flash::Engine,
    addr: SocketAddr,
    cfg: Config,
    handler: H,
) -> Result<Session, String> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    dial_conv(engine, addr, u32::from_le_bytes(b), cfg, handler)
}

/// [`dial`] with a chosen conversation id.
pub fn dial_conv<H: KcpHandler>(
    engine: &flash::Engine,
    addr: SocketAddr,
    conv: u32,
    cfg: Config,
    handler: H,
) -> Result<Session, String> {
    cfg.validate()?;
    let s = Session::new(&cfg, conv, addr, None);
    *lock(&s.0.handler) = Some(Box::new(handler));
    let failed = s.clone();
    engine.dial_udp(addr, Client(s.clone()), move |_e| {
        failed.close_with(CloseReason::Transport);
    });
    Ok(s)
}
