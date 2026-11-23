//! A poller of rounds scheduling (ADR-104): waits for readiness, accepts, and runs the control
//! path (dials, timers, telemetry, shutdown). It never reads, writes or runs handler code: a
//! readiness event becomes pending bits on the connection, served by a worker.

use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::{
    Config, ConnInfo, DynAcceptor, IdMap, LoopStats, Pool,
    telemetry::{LoopCmd, log_or_stderr},
};
use akio_sys::{Event, Poller, Registry, Waker};
use akio_timer::{TimerId, Wheel};

use super::conn::{HUP, RConn, READ, SHUTDOWN, WRITE};
use super::workers::Workers;

const WAKER: u64 = 0;
const LISTEN_BIT: u64 = 1 << 62;
const MAX_ACCEPT_PER_EVENT: usize = 64;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Timer ids: write-timeout checks, connect and handshake deadlines (else idle checks).
const WRITE_TIMER: u64 = 1 << 63;
const CONNECT_TIMER: u64 = 1 << 62;
const HANDSHAKE_TIMER: u64 = 1 << 61;

/// Connection ids, shared with the per-thread loops so ids stay unique per process.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1 << 40);

pub(crate) enum RCmd {
    /// A connection was finalized by its round: drop it.
    Remove(u64),
    /// Output is queued: arm a write-timeout check.
    ArmWrite(u64),
    /// `on_open` installed a transport with a handshake deadline.
    ArmHandshake(u64),
    Shutdown,
    Core(LoopCmd),
    Dial {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
    },
}

/// The part of a poller other threads reach.
pub(crate) struct PollerShared {
    waker: Waker,
    cmds: Mutex<Vec<RCmd>>,
    wake_pending: AtomicBool,
    pub(crate) registry: Registry,
    pub(crate) pool: Arc<Pool>,
    pub(crate) stats: Arc<LoopStats>,
    pub(crate) cfg: Arc<Config>,
    pub(crate) epoch: Instant,
}

impl PollerShared {
    pub(crate) fn new(
        poller: &Poller,
        pool: Arc<Pool>,
        cfg: Arc<Config>,
        stats: Arc<LoopStats>,
    ) -> io::Result<Arc<PollerShared>> {
        let sh = Arc::new(PollerShared {
            waker: Waker::new(poller, WAKER)?,
            cmds: Mutex::new(Vec::new()),
            wake_pending: AtomicBool::new(false),
            registry: poller.registry(),
            pool,
            stats,
            cfg,
            epoch: Instant::now(),
        });
        let weak = Arc::downgrade(&sh);
        sh.cfg.telemetry.register_loop(
            sh.stats.clone(),
            Box::new(move |c| {
                if let Some(sh) = weak.upgrade() {
                    sh.post(RCmd::Core(c));
                }
            }),
        );
        Ok(sh)
    }

    pub(crate) fn post(&self, cmd: RCmd) {
        self.cmds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(cmd);
        if !self.wake_pending.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    /// Interrupts a blocking poll of this poller (a worker waiting in it in driver mode).
    pub(crate) fn wake(&self) {
        if !self.wake_pending.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    fn take_into(&self, batch: &mut Vec<RCmd>) {
        self.wake_pending.store(false, Ordering::Release);
        std::mem::swap(
            &mut *self.cmds.lock().unwrap_or_else(|p| p.into_inner()),
            batch,
        );
    }
}

struct Connecting {
    stream: TcpStream,
    acceptor: Arc<dyn DynAcceptor>,
    on_error: Option<Box<dyn FnOnce(io::Error) + Send>>,
}

struct Timers {
    idle: Option<TimerId>,
    write: Option<TimerId>,
    write_mark: u64,
    hs: Option<TimerId>,
}

pub(crate) struct RLoop {
    poller: Poller,
    shared: Arc<PollerShared>,
    listeners: Vec<TcpListener>,
    acceptor: Option<Arc<dyn DynAcceptor>>,
    workers: Arc<Workers>,
    conns: IdMap<(Arc<RConn>, Timers)>,
    connecting: IdMap<Connecting>,
    wheel: Wheel<u64>,
    backlog: i32,
    draining: Option<Instant>,
    /// Remaining connections were told to close (the drain deadline passed).
    killed: bool,
    accept_paused_until: Option<Instant>,
    spare: Vec<RCmd>,
    events: Vec<Event>,
    finished: bool,
    /// Tracing: how long the last `wait` took.
    last_wait: Duration,
}

impl RLoop {
    pub(crate) fn new(
        poller: Poller,
        shared: Arc<PollerShared>,
        listeners: Vec<TcpListener>,
        acceptor: Option<Arc<dyn DynAcceptor>>,
        workers: Arc<Workers>,
    ) -> io::Result<RLoop> {
        for (i, l) in listeners.iter().enumerate() {
            l.set_nonblocking(true)?;
            poller.add(l.as_raw_fd(), LISTEN_BIT | i as u64, true, false)?;
        }
        let backlog = shared.cfg.telemetry.live().backlog();
        Ok(RLoop {
            poller,
            shared,
            listeners,
            acceptor,
            workers,
            conns: IdMap::default(),
            connecting: IdMap::default(),
            wheel: Wheel::new(0),
            backlog,
            draining: None,
            killed: false,
            accept_paused_until: None,
            spare: Vec::new(),
            events: Vec::with_capacity(1024),
            finished: false,
            last_wait: Duration::ZERO,
        })
    }

    fn tick(&self) -> u64 {
        self.shared.epoch.elapsed().as_millis() as u64
    }

    fn cfg(&self) -> &Arc<Config> {
        &self.shared.cfg
    }

    /// How long a blocking poll may wait: until the next timer, the end of an accept backoff, or
    /// a short tick while draining. `None`: until an event.
    pub(crate) fn next_timeout(&self) -> Option<Duration> {
        let mut timeout = self.draining.map(|_| Duration::from_millis(20));
        if let Some(next) = self.wheel.next_deadline() {
            let wait = Duration::from_millis(next.saturating_sub(self.tick()) + 1);
            timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
        }
        if let Some(t) = self.accept_paused_until {
            let left = t.saturating_duration_since(Instant::now()) + Duration::from_millis(1);
            timeout = Some(timeout.map_or(left, |x| x.min(left)));
        }
        timeout
    }

    /// Dedicated-poller mode: polls until the poller is done.
    pub(crate) fn run(&mut self) {
        loop {
            let t = self.next_timeout();
            if self.poll_once(t) {
                break;
            }
        }
        self.shared.stats.set_running(false);
    }

    /// One poll: waits up to `timeout` for readiness, hands the events to the connections, runs
    /// commands and timers. True once the poller has finished (shut down and drained). Called by
    /// the dedicated poller thread, or by a worker holding the driver (ADR-104, driver mode).
    pub(crate) fn poll_once(&mut self, timeout: Option<Duration>) -> bool {
        if self.finished {
            return true;
        }
        let mut events = std::mem::take(&mut self.events);
        events.clear();
        let t_wait = super::trace::on().then(Instant::now);
        if let Err(e) = self.poller.wait(&mut events, timeout) {
            log_or_stderr(akio_log::Level::Error, format_args!("poller error: {e}"));
            self.events = events;
            self.finished = true;
            return true;
        }
        if let Some(t0) = t_wait {
            self.last_wait = t0.elapsed();
        }
        let st = &self.shared.stats;
        st.iterations.add_local(1);
        st.events.add_local(events.len() as u64);
        for ev in &events {
            match ev.token {
                WAKER => self.shared.waker.drain(),
                t if t & LISTEN_BIT != 0 => self.accept((t & !LISTEN_BIT) as usize),
                id => self.on_event(id, *ev),
            }
        }
        let n_events = events.len();
        self.events = events;
        self.drain_cmds();
        self.fire_timers();
        self.resume_accept();
        if let Some(t0) = t_wait {
            // `busy`: from the end of the wait (approximated by the first event's handling)
            // to here; `waited`: the whole wait.
            let total = t0.elapsed();
            super::trace::polled(
                total.saturating_sub(self.last_wait),
                self.last_wait,
                n_events,
            );
        }
        if let Some(deadline) = self.draining {
            if self.conns.is_empty() && self.connecting.is_empty() {
                self.finished = true;
                return true;
            }
            let now = Instant::now();
            if now >= deadline && !self.killed {
                self.killed = true;
                for (c, _) in self.conns.values() {
                    c.close_with(None);
                }
                for (_, d) in self.connecting.drain() {
                    if let Some(f) = d.on_error {
                        f(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "engine shutting down",
                        ));
                    }
                }
            }
            if now >= deadline + Duration::from_secs(5) {
                self.finished = true; // rounds stuck in handlers: give up waiting for them
                return true;
            }
        }
        false
    }

    fn on_event(&mut self, id: u64, ev: Event) {
        if let Some((c, _)) = self.conns.get(&id) {
            let bits = if ev.readable { READ } else { 0 }
                | if ev.writable { WRITE } else { 0 }
                | if ev.hup { HUP } else { 0 };
            if bits != 0 {
                c.notify(bits);
            }
            return;
        }
        if self.connecting.contains_key(&id) && (ev.readable || ev.writable) {
            self.finish_connect(id);
        }
    }

    // ---- accept / open / dial ---------------------------------------------------------------

    fn accept(&mut self, idx: usize) {
        for _ in 0..MAX_ACCEPT_PER_EVENT {
            let (Some(l), Some(acceptor)) = (self.listeners.get(idx), &self.acceptor) else {
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
                    self.shared.stats.accept_errors.add_local(1);
                    log_or_stderr(
                        akio_log::Level::Warn,
                        format_args!("accept: {e}; pausing accepts for {ACCEPT_BACKOFF:?}"),
                    );
                    for l in &self.listeners {
                        self.poller.delete(l.as_raw_fd());
                    }
                    self.accept_paused_until = Some(Instant::now() + ACCEPT_BACKOFF);
                    return;
                }
            }
        }
    }

    fn resume_accept(&mut self) {
        let Some(t) = self.accept_paused_until else {
            return;
        };
        if Instant::now() < t || self.draining.is_some() {
            return;
        }
        self.accept_paused_until = None;
        for (i, l) in self.listeners.iter().enumerate() {
            if let Err(e) = self
                .poller
                .add(l.as_raw_fd(), LISTEN_BIT | i as u64, true, false)
            {
                log_or_stderr(
                    akio_log::Level::Warn,
                    format_args!("re-arming the listener: {e}"),
                );
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
        let tel = self.cfg().telemetry.clone();
        if !tel.conn_opened(!dialed) {
            self.shared.stats.rejected.add_local(1);
            akio_log::debug!(target: "akio", peer:% = peer; "connection refused: max_connections reached");
            return;
        }
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let fd = stream.as_raw_fd();
        let now = self.tick();
        let c = RConn::new(
            id,
            stream,
            local,
            peer,
            acceptor,
            self.shared.clone(),
            self.workers.clone(),
            now,
        );
        if self.shared.registry.add_edge(fd, id).is_err() {
            c.inner.mark_closed();
            tel.conn_closed();
            return;
        }
        let st = &self.shared.stats;
        if dialed { &st.dialed } else { &st.accepted }.add_local(1);
        akio_log::trace!(target: "akio", conn_id = id, peer:% = peer, local:% = local, dialed = dialed; "connection opened");
        let idle = self.cfg().telemetry.live().idle_ms();
        let idle_timer = (idle != 0).then(|| self.schedule(now + idle, id));
        self.conns.insert(
            id,
            (
                c.clone(),
                Timers {
                    idle: idle_timer,
                    write: None,
                    write_mark: 0,
                    hs: None,
                },
            ),
        );
        c.start();
    }

    fn begin_dial(
        &mut self,
        stream: TcpStream,
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
        self.connecting.insert(
            id,
            Connecting {
                stream,
                acceptor,
                on_error: Some(on_error),
            },
        );
        if let Some(ct) = self.cfg().connect_timeout {
            let at = self.tick() + (ct.as_millis() as u64).max(1);
            self.schedule(at, id | CONNECT_TIMER);
        }
    }

    fn finish_connect(&mut self, id: u64) {
        let Some(Connecting {
            stream,
            acceptor,
            on_error,
        }) = self.connecting.remove(&id)
        else {
            return;
        };
        self.poller.delete(stream.as_raw_fd());
        let result = match stream.take_error() {
            Ok(None) => stream.peer_addr(),
            Ok(Some(e)) | Err(e) => Err(e),
        };
        match result {
            Ok(peer) => self.open(stream, peer, acceptor, true),
            Err(e) => {
                if let Some(f) = on_error {
                    f(e);
                }
            }
        }
    }

    // ---- commands ---------------------------------------------------------------------------

    fn drain_cmds(&mut self) {
        let mut batch = std::mem::take(&mut self.spare);
        loop {
            self.shared.take_into(&mut batch);
            if batch.is_empty() {
                break;
            }
            for cmd in batch.drain(..) {
                self.on_cmd(cmd);
            }
        }
        if batch.capacity() <= 1024 {
            self.spare = batch;
        }
    }

    fn on_cmd(&mut self, cmd: RCmd) {
        match cmd {
            RCmd::Remove(id) => {
                if let Some((_, t)) = self.conns.remove(&id) {
                    for t in [t.idle, t.write, t.hs].into_iter().flatten() {
                        self.wheel.cancel(t);
                    }
                }
            }
            RCmd::ArmWrite(id) => {
                let Some(wt) = self.cfg().write_timeout else {
                    return;
                };
                let at = self.tick() + (wt.as_millis() as u64).max(1);
                if !self.conns.contains_key(&id) {
                    return;
                }
                let t = self.schedule(at, id | WRITE_TIMER);
                if let Some((c, tm)) = self.conns.get_mut(&id) {
                    tm.write_mark = c.inner.debug_state().0;
                    if let Some(old) = tm.write.replace(t) {
                        self.wheel.cancel(old);
                    }
                }
            }
            RCmd::ArmHandshake(id) => {
                let Some(d) = self
                    .conns
                    .get(&id)
                    .and_then(|(c, _)| c.inner.handshake_timeout())
                else {
                    return;
                };
                let at = self.tick() + (d.as_millis() as u64).max(1);
                let t = self.schedule(at, id | HANDSHAKE_TIMER);
                if let Some((_, tm)) = self.conns.get_mut(&id) {
                    tm.hs = Some(t);
                }
            }
            RCmd::Shutdown => self.begin_shutdown(),
            RCmd::Core(LoopCmd::Inspect(reply)) => {
                let now = self.tick();
                let meta = self.shared.stats.meta().clone();
                let infos = self
                    .conns
                    .iter()
                    .map(|(id, (c, _))| {
                        let mut ci = ConnInfo::new(*id, &c.inner, meta.clone());
                        ci.age = Duration::from_millis(now.saturating_sub(c.opened));
                        ci.idle = Duration::from_millis(
                            now.saturating_sub(c.last_active.load(Ordering::Relaxed)),
                        );
                        ci.bytes_in = c.bytes_in.load(Ordering::Relaxed);
                        ci.backpressure = c.bp_flag.load(Ordering::Relaxed);
                        ci
                    })
                    .collect();
                reply(infos);
            }
            RCmd::Core(LoopCmd::Reload) => self.on_reload(),
            RCmd::Dial {
                stream,
                acceptor,
                on_error,
            } => self.begin_dial(stream, acceptor, on_error),
        }
    }

    fn on_reload(&mut self) {
        let cfg = self.shared.cfg.clone();
        let live = cfg.telemetry.live();
        let backlog = live.backlog();
        if backlog != self.backlog {
            self.backlog = backlog;
            for l in &self.listeners {
                let _ = akio_sys::set_backlog(l, backlog);
            }
        }
        let idle = live.idle_ms();
        let ids: Vec<u64> = self.conns.keys().copied().collect();
        for id in ids {
            let Some((c, tm)) = self.conns.get_mut(&id) else {
                continue;
            };
            let last = c.last_active.load(Ordering::Relaxed);
            if let Some(t) = tm.idle.take() {
                self.wheel.cancel(t);
            }
            if idle != 0 {
                let t = self.schedule(last + idle, id);
                if let Some((_, tm)) = self.conns.get_mut(&id) {
                    tm.idle = Some(t);
                }
            }
            // Backpressure is re-evaluated by the connection's next round.
            if let Some((c, _)) = self.conns.get(&id) {
                c.notify(super::conn::WAKE);
            }
        }
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg().telemetry.live().shutdown_timeout());
        for l in std::mem::take(&mut self.listeners) {
            self.poller.delete(l.as_raw_fd());
        }
        for (c, _) in self.conns.values() {
            c.notify(SHUTDOWN);
        }
        for (_, d) in self.connecting.drain() {
            self.poller.delete(d.stream.as_raw_fd());
            if let Some(f) = d.on_error {
                f(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "engine shutting down",
                ));
            }
        }
    }

    // ---- timers -----------------------------------------------------------------------------

    fn schedule(&mut self, at: u64, id: u64) -> TimerId {
        if self.wheel.is_empty() {
            // The wheel's clock stops while it is empty; catch it up first.
            self.wheel.advance(self.tick(), drop);
        }
        self.wheel.schedule(at, id)
    }

    fn fire_timers(&mut self) {
        if self.wheel.is_empty() {
            return;
        }
        let now = self.tick();
        let mut due = Vec::new();
        self.wheel.advance(now, |id| due.push(id));
        let idle = self.cfg().telemetry.live().idle_ms();
        for id in due {
            if id & WRITE_TIMER != 0 {
                self.on_write_timer(id & !WRITE_TIMER, now);
            } else if id & CONNECT_TIMER != 0 {
                let id = id & !CONNECT_TIMER;
                if let Some(d) = self.connecting.remove(&id) {
                    self.poller.delete(d.stream.as_raw_fd());
                    if let Some(f) = d.on_error {
                        f(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
                    }
                }
            } else if id & HANDSHAKE_TIMER != 0 {
                let id = id & !HANDSHAKE_TIMER;
                if let Some((c, tm)) = self.conns.get_mut(&id) {
                    tm.hs = None;
                    if c.inner.transport_handshaking() {
                        c.inner.note_transport_error();
                        c.close_with(Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "handshake timeout",
                        )));
                    }
                }
            } else {
                let Some((c, tm)) = self.conns.get_mut(&id) else {
                    continue;
                };
                tm.idle = None;
                if idle == 0 {
                    continue;
                }
                let expires = c.last_active.load(Ordering::Relaxed) + idle;
                if expires <= now {
                    self.shared.stats.idle_timeouts.add_local(1);
                    c.close_with(Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "idle timeout",
                    )));
                } else {
                    let t = self.wheel.schedule(expires, id);
                    if let Some((_, tm)) = self.conns.get_mut(&id) {
                        tm.idle = Some(t);
                    }
                }
            }
        }
    }

    fn on_write_timer(&mut self, id: u64, now: u64) {
        let Some(wt) = self.cfg().write_timeout else {
            return;
        };
        let Some((c, tm)) = self.conns.get_mut(&id) else {
            return;
        };
        tm.write = None;
        let (sent, pending, ..) = c.inner.debug_state();
        if pending == 0 {
            c.write_armed.store(false, Ordering::Release);
            return;
        }
        if sent != tm.write_mark {
            tm.write_mark = sent;
            let t = self
                .wheel
                .schedule(now + (wt.as_millis() as u64).max(1), id | WRITE_TIMER);
            if let Some((_, tm)) = self.conns.get_mut(&id) {
                tm.write = Some(t);
            }
            return;
        }
        self.shared.stats.write_timeouts.add_local(1);
        c.close_with(Some(io::Error::new(
            io::ErrorKind::TimedOut,
            "write timeout",
        )));
    }
}

/// Posts a dial to `sh`'s poller.
pub(crate) fn post_dial(
    sh: &PollerShared,
    stream: TcpStream,
    acceptor: Arc<dyn DynAcceptor>,
    on_error: Box<dyn FnOnce(io::Error) + Send>,
) {
    sh.post(RCmd::Dial {
        stream,
        acceptor,
        on_error,
    });
}
