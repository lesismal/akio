use std::{
    cell::Cell,
    io::{self, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use only_core::{
    Config, ConnInfo, ConnInner, DynAcceptor, DynHandler, Error, LoopLink, LoopStats, Pool, Task,
    telemetry::{LoopCmd, log_or_stderr},
};
use only_sys::{Event, Poller, Waker};
use only_timer::{TimerId, Wheel};

const WAKER: u64 = 0;
const LISTENER: u64 = 1;
const FIRST_CONN: u64 = 16;
const MAX_ACCEPT_PER_EVENT: usize = 64;
const MAX_READS_PER_EVENT: usize = 16;
/// After `accept` fails (EMFILE, ENFILE, ENOBUFS...), the listener is left alone this long.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(FIRST_CONN);
static NEXT_LOOP_UID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    /// Uid of the loop running on this thread (0 = not a loop thread).
    static CURRENT_LOOP: Cell<usize> = const { Cell::new(0) };
}

/// Marks the calling thread as the loop of `shared` (posts from it need no wake-up).
pub(crate) fn set_current_loop(shared: &LoopShared) {
    CURRENT_LOOP.with(|c| c.set(shared.uid));
}

pub(crate) enum Cmd {
    Wake(u64),
    Close(u64, Option<io::Error>),
    Task(u64, Task),
    Shutdown,
    /// From the engine's telemetry hub (connection table, live-settings reload).
    Core(LoopCmd),
    /// UDP only: a client connection with its own connected socket.
    DialUdp {
        sock: std::net::UdpSocket,
        acceptor: Arc<dyn DynAcceptor>,
    },
    /// UDP only: an unconnected socket bound at run time (`Engine::bind_udp`), served like a
    /// listener socket under poll token `id`.
    BindUdp {
        id: u64,
        sock: Arc<std::net::UdpSocket>,
        acceptor: Arc<dyn DynAcceptor>,
    },
    /// UDP only: closes the socket bound under `id` and its connections.
    Unbind(u64),
    /// UDP only: a peer of the server socket opened from this side.
    OpenPeer {
        peer: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    },
    Dial {
        stream: TcpStream,
        addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    },
}

/// The part of a loop other threads can reach: its command queue and waker.
pub(crate) struct LoopShared {
    uid: usize,
    waker: Waker,
    cmds: Mutex<Vec<Cmd>>,
    wake_pending: AtomicBool,
    pool: Arc<Pool>,
    pub(crate) stats: Arc<LoopStats>,
}

impl LoopShared {
    /// A loop's shared half, registered with `cfg`'s telemetry hub.
    pub(crate) fn new(
        poller: &Poller,
        pool: Arc<Pool>,
        cfg: &Config,
        meta: only_core::LoopMeta,
    ) -> io::Result<Arc<LoopShared>> {
        let sh = Arc::new(LoopShared {
            uid: NEXT_LOOP_UID.fetch_add(1, Ordering::Relaxed),
            waker: Waker::new(poller, WAKER)?,
            cmds: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
            pool,
            stats: Arc::new(LoopStats::new(meta)),
        });
        let weak = Arc::downgrade(&sh);
        cfg.telemetry.register_loop(
            sh.stats.clone(),
            Box::new(move |c| {
                if let Some(sh) = weak.upgrade() {
                    sh.post(Cmd::Core(c));
                }
            }),
        );
        Ok(sh)
    }

    pub(crate) fn post(&self, cmd: Cmd) {
        self.cmds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(cmd);
        // The loop drains its queue after every batch of events, so a post from the loop's own
        // thread needs no wakeup.
        if CURRENT_LOOP.with(Cell::get) != self.uid
            && !self.wake_pending.swap(true, Ordering::AcqRel)
        {
            self.waker.wake();
        }
    }

    pub(crate) fn waker(&self) -> &Waker {
        &self.waker
    }

    pub(crate) fn take(&self) -> Vec<Cmd> {
        self.wake_pending.store(false, Ordering::Release);
        std::mem::take(&mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

impl LoopLink for LoopShared {
    fn wake_conn(&self, id: u64) {
        self.post(Cmd::Wake(id));
    }
    fn close_conn(&self, id: u64, err: Option<io::Error>) {
        self.post(Cmd::Close(id, err));
    }
    fn post_task(&self, id: u64, task: Task) {
        self.post(Cmd::Task(id, task));
    }
    fn pool(&self) -> Option<&Pool> {
        Some(&self.pool)
    }
    fn stats(&self) -> Option<Arc<LoopStats>> {
        Some(self.stats.clone())
    }
}

/// Backend name for metrics labels.
pub(crate) const BACKEND: &str = if cfg!(target_os = "linux") {
    "epoll"
} else {
    "kqueue"
};

struct LoopConn {
    inner: Arc<ConnInner>,
    handler: Box<dyn DynHandler>,
    acceptor: Arc<dyn DynAcceptor>,
    reg_read: bool,
    reg_write: bool,
    /// Reads paused by backpressure (queue above the high watermark).
    bp: bool,
    /// Peer sent EOF; we are only draining output.
    eof: bool,
    /// Wheel tick of the last inbound data (idle timeout).
    last_active: u64,
    idle_timer: Option<TimerId>,
    /// Pending write-timeout check (`Config::write_timeout`), and the bytes written when it
    /// was armed.
    write_timer: Option<TimerId>,
    write_mark: u64,
    /// Wheel tick when it opened, and bytes read (connection table).
    opened: u64,
    bytes_in: u64,
}

enum Slot {
    Conn(LoopConn),
    Connecting {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Option<Box<dyn FnOnce(io::Error) + Send>>,
    },
}

pub(crate) struct Loop {
    poller: Poller,
    shared: Arc<LoopShared>,
    listener: Option<(TcpListener, Arc<dyn DynAcceptor>)>,
    slots: only_core::IdMap<Slot>,
    scratch: Vec<u8>,
    cfg: Arc<Config>,
    draining: Option<Instant>,
    /// The listener is out of the poller until then, after a failed `accept`.
    accept_paused_until: Option<Instant>,
    /// Idle-timeout timers (connection ids); empty unless `Config::idle_timeout` is set.
    wheel: Wheel<u64>,
    epoch: Instant,
    /// When the current batch of events started, or the last timed callback ended: the start of
    /// the next callback and the "now" of idle accounting, so a request costs one clock read
    /// instead of three. (A timed `on_data` therefore includes the `read` just before it.)
    clock: Instant,
}

/// Marks a wheel entry as a write-timeout check (connection ids never reach bit 63).
const WRITE_TIMER: u64 = 1 << 63;
/// Timer ids with this bit set are connect deadlines of pending dials (`Config::connect_timeout`).
const CONNECT_TIMER: u64 = 1 << 62;

fn panic_error() -> Error {
    Error::Io(io::Error::other("handler panicked"))
}

impl Loop {
    pub(crate) fn new(
        poller: Poller,
        shared: Arc<LoopShared>,
        listener: Option<(TcpListener, Arc<dyn DynAcceptor>)>,
        cfg: Arc<Config>,
    ) -> io::Result<Loop> {
        if let Some((l, _)) = &listener {
            l.set_nonblocking(true)?;
            poller.add(l.as_raw_fd(), LISTENER, true, false)?;
        }
        Ok(Loop {
            poller,
            shared,
            listener,
            slots: Default::default(),
            scratch: vec![0; cfg.read_buffer],
            cfg,
            draining: None,
            accept_paused_until: None,
            wheel: Wheel::new(0),
            epoch: Instant::now(),
            clock: Instant::now(),
        })
    }

    pub(crate) fn run(&mut self) {
        self.run_inner();
        self.shared.stats.set_running(false);
        // Pending telemetry requests are dropped, which answers them (as "nothing").
        drop(self.shared.take());
    }

    fn run_inner(&mut self) {
        CURRENT_LOOP.with(|c| c.set(self.shared.uid));
        let mut events: Vec<Event> = Vec::with_capacity(1024);
        loop {
            let mut timeout = self.draining.map(|_| Duration::from_millis(50));
            if let Some(next) = self.wheel.next_deadline() {
                // Round up: waking a hair late is fine, spinning on a not-yet-due tick is not.
                let wait = Duration::from_millis(next.saturating_sub(self.tick()) + 1);
                timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
            }
            if let Some(t) = self.accept_paused_until {
                let left = t.saturating_duration_since(Instant::now()) + Duration::from_millis(1);
                timeout = Some(timeout.map_or(left, |x| x.min(left)));
            }
            events.clear();
            if let Err(e) = self.poller.wait(&mut events, timeout) {
                log_or_stderr(only_log::Level::Error, format_args!("poller error: {e}"));
                break;
            }
            self.shared.stats.iterations.add_local(1);
            self.shared.stats.events.add_local(events.len() as u64);
            self.clock = Instant::now();
            for ev in &events {
                match ev.token {
                    WAKER => self.shared.waker.drain(),
                    LISTENER => self.accept(),
                    id => self.on_event(id, *ev),
                }
            }
            self.drain_cmds();
            self.fire_timers();
            self.resume_accept();
            if let Some(deadline) = self.draining {
                if self.slots.is_empty() {
                    break;
                }
                if Instant::now() >= deadline {
                    let ids: Vec<u64> = self.slots.keys().copied().collect();
                    for id in ids {
                        self.finalize(id, None);
                    }
                    break;
                }
            }
        }
    }

    // ---- callbacks ------------------------------------------------------------------------

    /// Accounts a callback (and reports it if it ran longer than the slow-callback threshold).
    fn check_slow(&self, kind: &'static str, id: u64, started: Option<Instant>) {
        self.cfg
            .telemetry
            .callback_done(&self.shared.stats, kind, id, started);
    }

    fn timing(&self) -> Option<Instant> {
        self.cfg.telemetry.timing()
    }

    /// Runs a `spawn_blocking` completion on the connection's handler.
    fn on_task(&mut self, id: u64, task: Task) {
        let t0 = self.timing();
        let mut failed = None;
        {
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                return; // connection closed meanwhile: the completion is dropped
            };
            lc.inner.set_corked(true);
            if catch_unwind(AssertUnwindSafe(|| lc.handler.run_task(task))).is_err() {
                failed = Some(panic_error());
            } else if let Err(e) = lc.inner.uncork_flush() {
                failed = Some(Error::Io(e));
            }
        }
        self.check_slow("spawn_blocking completion", id, t0);
        match failed {
            Some(e) => self.finalize(id, Some(e)),
            None => self.refresh(id),
        }
    }

    // ---- timers ---------------------------------------------------------------------------

    fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn arm_idle(&mut self, id: u64, at: u64) -> Option<TimerId> {
        if self.cfg.telemetry.live().idle_ms() == 0 {
            return None;
        }
        if self.wheel.is_empty() {
            // The wheel's clock stops while it is empty; catch it up so the next `advance`
            // does not replay the idle period tick by tick.
            self.wheel.advance(self.tick(), drop);
        }
        Some(self.wheel.schedule(at, id))
    }

    /// Arms the write-timeout check of a connection that has output queued (if the timeout is
    /// set and no check is pending). `now` comes from the cached loop clock.
    fn arm_write(&mut self, id: u64) {
        let Some(wt) = self.cfg.write_timeout else {
            return;
        };
        let now = self.clock.saturating_duration_since(self.epoch).as_millis() as u64;
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        if lc.write_timer.is_some() {
            return;
        }
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        lc.write_mark = lc.inner.debug_state().0;
        let at = now + (wt.as_millis() as u64).max(1);
        lc.write_timer = Some(self.wheel.schedule(at, id | WRITE_TIMER));
    }

    /// Arms the connect deadline of a pending dial (if `connect_timeout` is set). The timer is
    /// not cancelled when the dial completes: the connection then lives under a new id, and a
    /// stale deadline finds no pending dial.
    fn arm_connect(&mut self, id: u64) {
        let Some(ct) = self.cfg.connect_timeout else {
            return;
        };
        let now = self.tick();
        if self.wheel.is_empty() {
            self.wheel.advance(now, drop);
        }
        let at = now + (ct.as_millis() as u64).max(1);
        self.wheel.schedule(at, id | CONNECT_TIMER);
    }

    /// A dial's connect deadline is due: abandon it if it is still pending.
    fn on_connect_timer(&mut self, id: u64) {
        if !matches!(self.slots.get(&id), Some(Slot::Connecting { .. })) {
            return;
        }
        let Some(Slot::Connecting {
            stream, on_error, ..
        }) = self.slots.remove(&id)
        else {
            return;
        };
        self.poller.delete(stream.as_raw_fd());
        if let Some(f) = on_error {
            f(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
        }
    }

    /// A write-timeout check is due: close the connection if output is still queued and nothing
    /// was written since the last check, else check again later.
    fn on_write_timer(&mut self, id: u64, now: u64) {
        let Some(wt) = self.cfg.write_timeout else {
            return;
        };
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        lc.write_timer = None;
        let (sent, pending, ..) = lc.inner.debug_state();
        if pending == 0 {
            return; // drained: the next blocked write arms a new check
        }
        if sent != lc.write_mark {
            lc.write_mark = sent;
            let at = now + (wt.as_millis() as u64).max(1);
            lc.write_timer = Some(self.wheel.schedule(at, id | WRITE_TIMER));
            return;
        }
        self.shared.stats.write_timeouts.add_local(1);
        let e = io::Error::new(io::ErrorKind::TimedOut, "write timeout");
        self.finalize(id, Some(Error::Io(e)));
    }

    fn fire_timers(&mut self) {
        let idle = self.cfg.telemetry.live().idle_ms();
        if self.wheel.is_empty() {
            return;
        }
        let now = self.tick();
        let mut due = Vec::new();
        self.wheel.advance(now, |id| due.push(id));
        for id in due {
            if id & CONNECT_TIMER != 0 {
                self.on_connect_timer(id & !CONNECT_TIMER);
                continue;
            }
            if id & WRITE_TIMER != 0 {
                self.on_write_timer(id & !WRITE_TIMER, now);
                continue;
            }
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                continue;
            };
            lc.idle_timer = None;
            if idle == 0 {
                continue; // disabled at runtime: the timer is just dropped
            }
            let expires = lc.last_active + idle;
            if expires <= now {
                self.shared.stats.idle_timeouts.add_local(1);
                let e = io::Error::new(io::ErrorKind::TimedOut, "idle timeout");
                self.finalize(id, Some(Error::Io(e)));
            } else {
                // Traffic arrived since this timer was set: sleep until the new expiry.
                lc.idle_timer = Some(self.wheel.schedule(expires, id));
            }
        }
    }

    // ---- commands -------------------------------------------------------------------------

    fn drain_cmds(&mut self) {
        loop {
            let cmds = self.shared.take();
            if cmds.is_empty() {
                return;
            }
            for cmd in cmds {
                match cmd {
                    Cmd::Wake(id) => self.on_wake(id),
                    Cmd::Close(id, err) => self.finalize(id, err.map(Error::Io)),
                    Cmd::Task(id, task) => self.on_task(id, task),
                    Cmd::Shutdown => self.begin_shutdown(),
                    Cmd::Core(c) => self.on_core(c),
                    // Only UDP loops are sent these.
                    Cmd::DialUdp { .. } | Cmd::BindUdp { .. } | Cmd::Unbind(_) => {}
                    Cmd::OpenPeer { on_error, .. } => on_error(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "not a UDP listener",
                    )),
                    Cmd::Dial {
                        stream,
                        addr,
                        acceptor,
                        on_error,
                    } => self.begin_dial(stream, addr, acceptor, on_error),
                }
            }
        }
    }

    fn on_core(&mut self, c: LoopCmd) {
        match c {
            LoopCmd::Inspect(reply) => {
                let now = self.tick();
                let infos = self
                    .slots
                    .iter()
                    .filter_map(|(id, s)| match s {
                        Slot::Conn(lc) => Some(self.info(*id, lc, now)),
                        Slot::Connecting { .. } => None,
                    })
                    .collect();
                reply(infos);
            }
            LoopCmd::Reload => self.on_reload(),
        }
    }

    fn info(&self, id: u64, lc: &LoopConn, now: u64) -> ConnInfo {
        let mut ci = ConnInfo::new(id, &lc.inner, self.shared.stats.meta().clone());
        ci.age = Duration::from_millis(now.saturating_sub(lc.opened));
        ci.idle = Duration::from_millis(now.saturating_sub(lc.last_active));
        ci.bytes_in = lc.bytes_in;
        ci.backpressure = lc.bp;
        ci
    }

    /// Live settings changed: re-arm idle timers for the new timeout and re-evaluate
    /// backpressure against the new watermark.
    fn on_reload(&mut self) {
        let idle = self.cfg.telemetry.live().idle_ms();
        let ids: Vec<u64> = self.slots.keys().copied().collect();
        if self.wheel.is_empty() && idle != 0 {
            self.wheel.advance(self.tick(), drop);
        }
        for &id in &ids {
            if let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) {
                if let Some(t) = lc.idle_timer.take() {
                    self.wheel.cancel(t);
                }
                if idle != 0 {
                    lc.idle_timer = Some(self.wheel.schedule(lc.last_active + idle, id));
                }
            }
        }
        for id in ids {
            self.refresh(id);
        }
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg.telemetry.live().shutdown_timeout());
        if let Some((l, _)) = self.listener.take() {
            self.poller.delete(l.as_raw_fd());
        }
        let ids: Vec<u64> = self.slots.keys().copied().collect();
        for id in ids {
            match self.slots.get_mut(&id) {
                Some(Slot::Conn(lc)) => {
                    let (acc, inner) = (lc.acceptor.clone(), lc.inner.clone());
                    if catch_unwind(AssertUnwindSafe(|| acc.on_shutdown(&inner))).is_err() {
                        self.finalize(id, Some(panic_error()));
                    }
                }
                Some(Slot::Connecting { .. }) => {
                    if let Some(Slot::Connecting {
                        stream, on_error, ..
                    }) = self.slots.remove(&id)
                    {
                        self.poller.delete(stream.as_raw_fd());
                        if let Some(f) = on_error {
                            f(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "engine shutting down",
                            ));
                        }
                    }
                }
                None => {}
            }
        }
    }

    // ---- accept / dial --------------------------------------------------------------------

    fn accept(&mut self) {
        for _ in 0..MAX_ACCEPT_PER_EVENT {
            let Some((l, acceptor)) = &self.listener else {
                return;
            };
            match l.accept() {
                Ok((stream, peer)) => {
                    let acceptor = acceptor.clone();
                    self.open(stream, peer, acceptor, false);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    // e.g. EMFILE. The pending connection stays queued (on Linux) and the
                    // listener stays readable: polling it again right away would spin, so take
                    // it out of the poller for a moment (closing connections frees descriptors).
                    self.shared.stats.accept_errors.add_local(1);
                    log_or_stderr(
                        only_log::Level::Warn,
                        format_args!("accept: {e}; pausing accepts for {ACCEPT_BACKOFF:?}"),
                    );
                    self.poller.delete(l.as_raw_fd());
                    self.accept_paused_until = Some(Instant::now() + ACCEPT_BACKOFF);
                    return;
                }
            }
        }
    }

    /// Puts the listener back into the poller once an accept backoff is over.
    fn resume_accept(&mut self) {
        let Some(t) = self.accept_paused_until else {
            return;
        };
        if Instant::now() < t {
            return;
        }
        self.accept_paused_until = None;
        if let Some((l, _)) = &self.listener {
            if let Err(e) = self.poller.add(l.as_raw_fd(), LISTENER, true, false) {
                log_or_stderr(
                    only_log::Level::Warn,
                    format_args!("re-arming the listener: {e}"),
                );
                self.accept_paused_until = Some(Instant::now() + ACCEPT_BACKOFF);
            }
        }
    }

    fn open(
        &mut self,
        stream: TcpStream,
        peer: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        dialed: bool,
    ) {
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let _ = stream.set_nodelay(true);
        let Ok(local) = stream.local_addr() else {
            return;
        };
        let tel = self.cfg.telemetry.clone();
        if !tel.conn_opened(!dialed) {
            self.shared.stats.rejected.add_local(1);
            only_log::debug!(target: "only", peer:% = peer; "connection refused: max_connections reached");
            return; // dropping the stream closes it
        }
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let fd = stream.as_raw_fd();
        let inner = ConnInner::new(
            id,
            stream,
            local,
            peer,
            self.shared.clone(),
            self.cfg.clone(),
        );
        let Ok(handler) = catch_unwind(AssertUnwindSafe(|| acceptor.on_open(&inner))) else {
            inner.mark_closed();
            tel.conn_closed();
            return;
        };
        if self.poller.add(fd, id, true, false).is_err() {
            inner.mark_closed();
            tel.conn_closed();
            return;
        }
        let st = &self.shared.stats;
        if dialed { &st.dialed } else { &st.accepted }.add_local(1);
        only_log::trace!(target: "only", conn_id = id, peer:% = peer, local:% = local, dialed = dialed; "connection opened");
        let now = self.tick();
        let idle = self.cfg.telemetry.live().idle_ms();
        let idle_timer = self.arm_idle(id, now + idle);
        self.slots.insert(
            id,
            Slot::Conn(LoopConn {
                inner,
                handler,
                acceptor,
                reg_read: true,
                reg_write: false,
                bp: false,
                eof: false,
                last_active: now,
                idle_timer,
                write_timer: None,
                write_mark: 0,
                opened: now,
                bytes_in: 0,
            }),
        );
        // `on_open` may already have queued output or closed the connection.
        self.on_wake(id);
    }

    fn begin_dial(
        &mut self,
        stream: TcpStream,
        _addr: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    ) {
        if self.draining.is_some() {
            return on_error(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "engine shutting down",
            ));
        }
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = self.poller.add(stream.as_raw_fd(), id, false, true) {
            return on_error(e);
        }
        self.slots.insert(
            id,
            Slot::Connecting {
                stream,
                acceptor,
                on_error: Some(on_error),
            },
        );
        self.arm_connect(id);
    }

    fn finish_connect(&mut self, id: u64) {
        let Some(Slot::Connecting {
            stream,
            acceptor,
            on_error,
        }) = self.slots.remove(&id)
        else {
            return;
        };
        self.poller.delete(stream.as_raw_fd());
        let result = match stream.take_error() {
            Ok(None) => stream
                .peer_addr()
                .and_then(|p| stream.local_addr().map(|l| (l, p))),
            Ok(Some(e)) | Err(e) => Err(e),
        };
        match result {
            Ok((_, peer)) => {
                // `open` re-registers the stream under a fresh id.
                self.open(stream, peer, acceptor, true);
            }
            Err(e) => {
                if let Some(f) = on_error {
                    f(e);
                }
            }
        }
    }

    // ---- events ---------------------------------------------------------------------------

    fn on_event(&mut self, id: u64, ev: Event) {
        if matches!(self.slots.get(&id), Some(Slot::Connecting { .. })) {
            if ev.writable || ev.readable {
                self.finish_connect(id);
            }
            return;
        }
        if ev.writable {
            self.on_wake(id);
        }
        if ev.readable {
            self.on_readable(id);
        }
    }

    /// Flushes output, applies `close_after_send`, and refreshes interest.
    fn on_wake(&mut self, id: u64) {
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        match lc.inner.flush_queue() {
            Err(e) => self.finalize(id, Some(Error::Io(e))),
            Ok(empty) => {
                if empty && lc.inner.close_after_send_requested() {
                    self.finalize(id, None);
                } else {
                    self.refresh(id);
                }
            }
        }
    }

    fn on_readable(&mut self, id: u64) {
        enum Done {
            No,
            Eof,
            Err(io::Error),
            Panic,
        }
        let mut done = Done::No;
        let high = self.cfg.telemetry.live().write_high_watermark();
        let now = self.clock.saturating_duration_since(self.epoch).as_millis() as u64;
        let timed = self.cfg.telemetry.timing_enabled();
        {
            let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
                return;
            };
            if lc.eof || !lc.reg_read || !lc.inner.is_open() {
                return;
            }
            for _ in 0..MAX_READS_PER_EVENT {
                match lc.inner.stream().read(&mut self.scratch) {
                    Ok(0) => {
                        done = Done::Eof;
                        break;
                    }
                    Ok(n) => {
                        lc.last_active = now;
                        lc.bytes_in += n as u64;
                        let st = &self.shared.stats;
                        st.reads.add_local(1);
                        st.bytes_in.add_local(n as u64);
                        lc.inner.set_corked(true);
                        let r = catch_unwind(AssertUnwindSafe(|| {
                            lc.handler.on_data(&self.scratch[..n]);
                        }));
                        if timed {
                            self.clock = self
                                .cfg
                                .telemetry
                                .callback_done_at(st, "on_data", id, self.clock);
                        } else {
                            st.callbacks.add_local(1);
                        }
                        if r.is_err() {
                            done = Done::Panic;
                            break;
                        }
                        if let Err(e) = lc.inner.uncork_flush() {
                            done = Done::Err(e);
                            break;
                        }
                        // Stop early on a short read (socket drained), or if the handler asked to
                        // stop reading / close / the queue got long.
                        if n < self.scratch.len()
                            || !lc.inner.is_open()
                            || lc.inner.read_held()
                            || (lc.inner.write_backpressure() && lc.inner.queued_bytes() >= high)
                        {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        done = Done::Err(e);
                        break;
                    }
                }
            }
            if matches!(done, Done::Eof) {
                lc.eof = true;
                // Peer is done sending: finish writing what we owe, then close.
                lc.inner.close_after_responses();
            }
        }
        match done {
            Done::No => self.refresh(id),
            Done::Eof => self.on_wake(id),
            Done::Err(e) => self.finalize(id, Some(Error::Io(e))),
            Done::Panic => self.finalize(id, Some(panic_error())),
        }
    }

    /// Recomputes the poller interest of a connection from its queue and flags.
    fn refresh(&mut self, id: u64) {
        let high = self.cfg.telemetry.live().write_high_watermark();
        let Some(Slot::Conn(lc)) = self.slots.get_mut(&id) else {
            return;
        };
        let q = lc.inner.queued_bytes();
        if q >= high && lc.inner.write_backpressure() {
            if !lc.bp {
                self.shared.stats.backpressure.add_local(1);
            }
            lc.bp = true;
        } else if q <= high / 4 || !lc.inner.write_backpressure() {
            lc.bp = false;
        }
        let read = !lc.inner.read_held() && !lc.bp && !lc.eof;
        let write = q > 0;
        let arm = write && lc.write_timer.is_none() && self.cfg.write_timeout.is_some();
        if (read, write) != (lc.reg_read, lc.reg_write) {
            lc.reg_read = read;
            lc.reg_write = write;
            if let Err(e) = self
                .poller
                .modify(lc.inner.stream().as_raw_fd(), id, read, write)
            {
                self.finalize(id, Some(Error::Io(e)));
                return;
            }
        }
        if arm {
            self.arm_write(id);
        }
    }

    /// Removes a connection and runs `on_close` exactly once.
    fn finalize(&mut self, id: u64, err: Option<Error>) {
        let Some(Slot::Conn(mut lc)) = self.slots.remove(&id) else {
            // A dialing slot being closed by id is not possible: ids are not exposed before open.
            return;
        };
        if let Some(t) = lc.idle_timer.take() {
            self.wheel.cancel(t);
        }
        if let Some(t) = lc.write_timer.take() {
            self.wheel.cancel(t);
        }
        self.poller.delete(lc.inner.stream().as_raw_fd());
        lc.inner.mark_closed();
        let _ = lc.inner.stream().shutdown(std::net::Shutdown::Both);
        let t0 = self.timing();
        if only_log::log_enabled!(target: "only", only_log::Level::Trace) {
            only_log::trace!(target: "only", conn_id = id, peer:% = lc.inner.peer_addr(), error:? = err; "connection closed");
        }
        let _ = catch_unwind(AssertUnwindSafe(|| lc.handler.on_close(err)));
        self.check_slow("on_close", id, t0);
        self.shared.stats.closed.add_local(1);
        self.cfg.telemetry.conn_closed();
    }
}
