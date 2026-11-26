//! A poller of work-stealing scheduling (ADR-104): waits for readiness and runs the control
//! path (dials, telemetry, shutdown, timers). It never reads, writes, accepts or runs handler
//! code: a readiness event becomes pending bits on a connection, or an accept job for a
//! listener, both served by the workers.
//!
//! The connections a poller watches are in its [`ConnTable`]: sharded and behind locks, so the
//! workers add the connections they accept and remove the ones they close themselves, without
//! posting to the poller. The table also holds the connections' timers (idle, write, handshake);
//! the poller fires them.

use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, RawFd},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::{
    Config, ConnInfo, DynAcceptor, FilterCell, FilterView, IdMap, IdleCheck, IdleRule, LoopStats,
    Pool,
    telemetry::{LoopCmd, log_or_stderr},
};
use akio_sys::{Event, Poller, Registry, Waker};
use akio_timer::{TimerId, Wheel};

use super::conn::{HUP, RConn, READ, WAKE, WRITE};
use super::workers::{Job, WorkerCtx, Workers};

const WAKER: u64 = 0;
const LISTEN_BIT: u64 = 1 << 62;
const MAX_ACCEPT_PER_JOB: usize = 64;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Timer ids: write-timeout checks, connect and handshake deadlines (else idle checks).
const WRITE_TIMER: u64 = 1 << 63;
const CONNECT_TIMER: u64 = 1 << 62;
const HANDSHAKE_TIMER: u64 = 1 << 61;
/// `wait_until` while no blocking poll is in progress.
const NOT_WAITING: u64 = 0;

/// Connection ids, shared with the per-thread loops so ids stay unique per process.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1 << 40);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub(crate) enum RCmd {
    Shutdown,
    Core(LoopCmd),
    /// A listener was removed (ADR-099): listener `lid` of the group, or with `None` every one.
    /// Its sockets are already closed (by the group); its connections stay. With `drain` they
    /// get `on_shutdown` now and are closed at the deadline; with `exit` (`lid == None` only)
    /// the poller finishes once none is left.
    StopListening {
        lid: Option<usize>,
        drain: Option<Duration>,
        exit: bool,
    },
    /// A listening socket joins this poller (a listener added to a shared group, ADR-130).
    AddJob(Arc<ListenJob>),
    Dial {
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
        /// A Unix-domain socket (ADR-120): its addresses are `UNIX_ADDR`.
        unix: bool,
        /// The dial's own connect timeout (`DialOptions`, ADR-154); `None`: the engine's.
        timeout: Option<Duration>,
    },
}

struct Timers {
    idle: Option<TimerId>,
    /// The connection's own idle timeout, if it set one (ADR-155); else the engine's.
    rule: IdleRule,
    write: Option<TimerId>,
    write_mark: u64,
    hs: Option<TimerId>,
}

struct TableInner {
    conns: IdMap<(Arc<RConn>, Timers)>,
    wheel: Wheel<u64>,
}

impl TableInner {
    fn schedule(&mut self, at: u64, id: u64, now: u64) -> TimerId {
        if self.wheel.is_empty() {
            // The wheel's clock stops while it is empty; catch it up first.
            self.wheel.advance(now, drop);
        }
        self.wheel.schedule(at, id)
    }
}

struct TableShard {
    inner: Mutex<TableInner>,
    /// The earliest timer deadline in this shard (`u64::MAX`: none), readable without the lock.
    next: AtomicU64,
}

/// The connections of one poller and their timers, sharded by id so the workers that open and
/// close connections rarely meet on a lock.
pub(crate) struct ConnTable {
    shards: Box<[TableShard]>,
    mask: usize,
}

impl ConnTable {
    fn new(workers: usize) -> ConnTable {
        let n = (workers * 2).next_power_of_two().clamp(4, 64);
        ConnTable {
            shards: (0..n)
                .map(|_| TableShard {
                    inner: Mutex::new(TableInner {
                        conns: IdMap::default(),
                        wheel: Wheel::new(0),
                    }),
                    next: AtomicU64::new(u64::MAX),
                })
                .collect(),
            mask: n - 1,
        }
    }

    fn shard(&self, id: u64) -> &TableShard {
        &self.shards[id as usize & self.mask]
    }
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
    table: ConnTable,
    /// Shutting down: connections opened from now on are told so at once.
    draining: AtomicBool,
    /// The listener was removed and the poller finishes once its table is empty (ADR-099):
    /// a connection leaving the table wakes it, as while draining.
    exit_when_empty: AtomicBool,
    /// The tick a blocking poll in progress waits until (`u64::MAX`: no limit,
    /// [`NOT_WAITING`]: none in progress). A timer due earlier interrupts it.
    wait_until: AtomicU64,
}

impl PollerShared {
    pub(crate) fn new(
        poller: &Poller,
        pool: Arc<Pool>,
        cfg: Arc<Config>,
        stats: Arc<LoopStats>,
        workers: usize,
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
            table: ConnTable::new(workers),
            draining: AtomicBool::new(false),
            exit_when_empty: AtomicBool::new(false),
            wait_until: AtomicU64::new(NOT_WAITING),
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
        lock(&self.cmds).push(cmd);
        self.wake();
    }

    /// Interrupts a blocking poll of this poller (a worker waiting in it in driver mode).
    pub(crate) fn wake(&self) {
        if !self.wake_pending.swap(true, Ordering::AcqRel) {
            super::trace::count(&super::trace::C.driver_wakes);
            self.waker.wake();
        }
    }

    fn take_into(&self, batch: &mut Vec<RCmd>) {
        self.wake_pending.store(false, Ordering::Release);
        std::mem::swap(&mut *lock(&self.cmds), batch);
    }

    pub(crate) fn tick(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    // ---- the connection table ---------------------------------------------------------------

    /// After a change to `shard`'s timers: publishes its earliest deadline, and interrupts a
    /// blocking poll that would sleep past it.
    fn timers_changed(&self, shard: &TableShard, inner: &TableInner) {
        let next = inner.wheel.next_deadline().unwrap_or(u64::MAX);
        shard.next.store(next, Ordering::SeqCst);
        if next < self.wait_until.load(Ordering::SeqCst) {
            self.wake();
        }
    }

    /// Adds `bits` to the connection with this id, if it is still open. False if it is not in
    /// the table. Under the shard's lock, so no reference count changes hands; a worker's poll
    /// only queues the connection here (it wakes others after the poll).
    fn notify_conn(&self, id: u64, bits: u32) -> bool {
        let g = lock(&self.table.shard(id).inner);
        let Some((c, _)) = g.conns.get(&id) else {
            return false;
        };
        if bits != 0 {
            c.notify(bits);
        }
        true
    }

    /// Opens an accepted or connected socket: registers it (edge-triggered, once) and queues its
    /// first round. Runs on the worker that accepted it, or on the poller (dials).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        self: &Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        acceptor: Arc<dyn DynAcceptor>,
        dialed: bool,
        // The local address of a Unix-domain socket, which has none of its own (ADR-120).
        unix_local: Option<SocketAddr>,
        workers: &Arc<Workers>,
        // The listener it was accepted on (`NO_LISTENER` when dialed).
        lid: usize,
    ) {
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let local = match unix_local {
            Some(l) => l,
            None => {
                let _ = stream.set_nodelay(true);
                let Ok(l) = stream.local_addr() else {
                    return;
                };
                l
            }
        };
        let tel = &self.cfg.telemetry;
        if !tel.conn_opened(!dialed) {
            self.stats.rejected.add(1);
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
            self.clone(),
            workers.clone(),
            now,
            lid,
        );
        let idle = tel.live().idle_ms();
        // Into the table before the registration, so the first event finds it.
        {
            let shard = self.table.shard(id);
            let mut g = lock(&shard.inner);
            let idle_timer = (idle != 0).then(|| g.schedule(now + idle, id, now));
            g.conns.insert(
                id,
                (
                    c.clone(),
                    Timers {
                        idle: idle_timer,
                        rule: IdleRule::ENGINE,
                        write: None,
                        write_mark: 0,
                        hs: None,
                    },
                ),
            );
            if idle_timer.is_some() {
                self.timers_changed(shard, &g);
            }
        }
        if self.registry.add_edge(fd, id).is_err() {
            self.remove(id);
            c.inner.mark_closed();
            tel.conn_closed(!dialed);
            return;
        }
        if dialed {
            &self.stats.dialed
        } else {
            &self.stats.accepted
        }
        .add(1);
        akio_log::trace!(target: "akio", conn_id = id, peer:% = peer, local:% = local, dialed = dialed; "connection opened");
        #[cfg(test)]
        tests::open_hook();
        if self.draining.load(Ordering::SeqCst) {
            c.shutdown_notice();
        }
        c.start();
    }

    /// Drops a connection its round finalized, with its timers. With the last reference the
    /// socket closes.
    pub(crate) fn remove(&self, id: u64) {
        let shard = self.table.shard(id);
        let removed = {
            let mut g = lock(&shard.inner);
            let removed = g.conns.remove(&id);
            if let Some((_, t)) = &removed {
                for t in [t.idle, t.write, t.hs].into_iter().flatten() {
                    g.wheel.cancel(t);
                }
                shard.next.store(
                    g.wheel.next_deadline().unwrap_or(u64::MAX),
                    Ordering::SeqCst,
                );
            }
            removed
        };
        if removed.is_some()
            && (self.draining.load(Ordering::SeqCst) || self.exit_when_empty.load(Ordering::SeqCst))
        {
            // The poller finishes the drain (or the removed listener) once the table is empty.
            self.wake();
        }
    }

    /// Output is queued: arms a write-timeout check.
    pub(crate) fn arm_write(&self, id: u64) {
        let Some(wt) = self.cfg.telemetry.live().write_timeout() else {
            // Turned off since the round looked (ADR-108): a later value arms again.
            if let Some((c, _)) = lock(&self.table.shard(id).inner).conns.get(&id) {
                c.write_armed.store(false, Ordering::Release);
            }
            return;
        };
        let now = self.tick();
        let at = now + (wt.as_millis() as u64).max(1);
        let shard = self.table.shard(id);
        let mut g = lock(&shard.inner);
        let Some(mark) = g.conns.get(&id).map(|(c, _)| c.inner.debug_state().0) else {
            return;
        };
        let t = g.schedule(at, id | WRITE_TIMER, now);
        let old = g.conns.get_mut(&id).and_then(|(_, tm)| {
            tm.write_mark = mark;
            tm.write.replace(t)
        });
        if let Some(old) = old {
            g.wheel.cancel(old);
        }
        self.timers_changed(shard, &g);
    }

    /// `on_open` installed a transport with a handshake deadline: arms it.
    pub(crate) fn arm_handshake(&self, id: u64) {
        let shard = self.table.shard(id);
        let mut g = lock(&shard.inner);
        let Some(d) = g
            .conns
            .get(&id)
            .and_then(|(c, _)| c.inner.handshake_timeout())
        else {
            return;
        };
        let now = self.tick();
        let at = now + (d.as_millis() as u64).max(1);
        let t = g.schedule(at, id | HANDSHAKE_TIMER, now);
        if let Some((_, tm)) = g.conns.get_mut(&id) {
            tm.hs = Some(t);
        }
        self.timers_changed(shard, &g);
    }

    /// The earliest timer deadline of the table.
    fn next_deadline(&self) -> Option<u64> {
        let next = self
            .table
            .shards
            .iter()
            .map(|s| s.next.load(Ordering::SeqCst))
            .min()
            .unwrap_or(u64::MAX);
        (next != u64::MAX).then_some(next)
    }

    /// Drops whatever is left in the table (after the workers stopped): a connection holds its
    /// poller, so leftovers would keep both alive.
    pub(crate) fn clear_table(&self) {
        for s in &self.table.shards {
            let left = std::mem::take(&mut lock(&s.inner).conns);
            drop(left);
        }
    }

    fn table_is_empty(&self) -> bool {
        self.table
            .shards
            .iter()
            .all(|s| lock(&s.inner).conns.is_empty())
    }

    /// Runs `f` on every connection (under its shard's lock).
    fn each(&self, mut f: impl FnMut(u64, &Arc<RConn>)) {
        for s in &self.table.shards {
            for (id, (c, _)) in &lock(&s.inner).conns {
                f(*id, c);
            }
        }
    }

    /// Fires the table's due timers. `due` is scratch space.
    fn fire_timers(&self, due: &mut Vec<u64>) {
        let now = self.tick();
        let idle = self.cfg.telemetry.live().idle_ms();
        for shard in &self.table.shards {
            if shard.next.load(Ordering::SeqCst) > now {
                continue;
            }
            let mut g = lock(&shard.inner);
            due.clear();
            g.wheel.advance(now, |id| due.push(id));
            for &id in due.iter() {
                if id & WRITE_TIMER != 0 {
                    self.on_write_timer(&mut g, id & !WRITE_TIMER, now);
                } else if id & HANDSHAKE_TIMER != 0 {
                    let id = id & !HANDSHAKE_TIMER;
                    if let Some((c, tm)) = g.conns.get_mut(&id) {
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
                    let Some((c, tm)) = g.conns.get_mut(&id) else {
                        continue;
                    };
                    tm.idle = None;
                    let mut last = c.last_active.load(Ordering::Relaxed);
                    let before = last;
                    match tm.rule.check(idle, &mut last, now, &c.inner) {
                        IdleCheck::Off => {}
                        IdleCheck::Expired => {
                            self.stats.idle_timeouts.add(1);
                            c.close_with(Some(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "idle timeout",
                            )));
                        }
                        IdleCheck::At(at) => {
                            if last != before {
                                // Data sent counts (ADR-155); a read meanwhile may be newer.
                                c.last_active.fetch_max(last, Ordering::Relaxed);
                            }
                            let t = g.wheel.schedule(at, id);
                            if let Some((_, tm)) = g.conns.get_mut(&id) {
                                tm.idle = Some(t);
                            }
                        }
                    }
                }
            }
            shard.next.store(
                g.wheel.next_deadline().unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
        }
    }

    fn on_write_timer(&self, g: &mut TableInner, id: u64, now: u64) {
        let wt = self.cfg.telemetry.live().write_timeout();
        let Some((c, tm)) = g.conns.get_mut(&id) else {
            return;
        };
        tm.write = None;
        // Turned off at run time (`Live::set_write_timeout`, ADR-108): no more checks until it
        // is set again and a round that leaves output queued arms one.
        let Some(wt) = wt else {
            c.write_armed.store(false, Ordering::Release);
            return;
        };
        let (sent, pending, ..) = c.inner.debug_state();
        if pending == 0 {
            c.write_armed.store(false, Ordering::Release);
            return;
        }
        if sent != tm.write_mark {
            tm.write_mark = sent;
            let t = g
                .wheel
                .schedule(now + (wt.as_millis() as u64).max(1), id | WRITE_TIMER);
            if let Some((_, tm)) = g.conns.get_mut(&id) {
                tm.write = Some(t);
            }
            return;
        }
        self.stats.write_timeouts.add(1);
        c.close_with(Some(io::Error::new(
            io::ErrorKind::TimedOut,
            "write timeout",
        )));
    }

    /// Connection `id` set an idle timeout of its own (ADR-155): re-arms its timer from its
    /// last activity. From any thread (the shard's lock is not held by user code).
    pub(crate) fn retime(&self, id: u64) {
        let engine = self.cfg.telemetry.live().idle_ms();
        let now = self.tick();
        let shard = self.table.shard(id);
        let mut g = lock(&shard.inner);
        let TableInner { conns, wheel } = &mut *g;
        let Some((c, tm)) = conns.get_mut(&id) else {
            return;
        };
        tm.rule = IdleRule::of(&c.inner);
        if let Some(t) = tm.idle.take() {
            wheel.cancel(t);
        }
        let last = c.last_active.load(Ordering::Relaxed);
        if let Some(at) = tm.rule.first_check(engine, last, now) {
            if wheel.is_empty() {
                wheel.advance(now, drop);
            }
            tm.idle = Some(wheel.schedule(at, id));
        }
        self.timers_changed(shard, &g);
    }

    /// Re-applies the live idle timeout to every connection (a reload).
    fn reload_idle(&self, idle: u64) {
        let now = self.tick();
        for shard in &self.table.shards {
            let mut g = lock(&shard.inner);
            let g = &mut *g;
            for (id, (c, tm)) in &mut g.conns {
                if let Some(t) = tm.idle.take() {
                    g.wheel.cancel(t);
                }
                let last = c.last_active.load(Ordering::Relaxed);
                if let Some(at) = tm.rule.first_check(idle, last, now) {
                    if g.wheel.is_empty() {
                        g.wheel.advance(now, drop);
                    }
                    tm.idle = Some(g.wheel.schedule(at, *id));
                }
                // Backpressure is re-evaluated by the connection's next round.
                c.notify(WAKE);
            }
            self.timers_changed(shard, g);
        }
    }
}

/// A listening socket. Its readiness queues it on the workers like a connection: one worker at a
/// time accepts from it, opens what it accepted, and registers it with the poller.
pub(crate) struct ListenJob {
    /// Its listener in the group (ADR-130), and that listener's address (the connection
    /// table's `owner.listener`).
    lid: usize,
    addr: SocketAddr,
    /// A Unix-domain listener (ADR-121): connections are accepted without an address and get
    /// `UNIX_ADDR` for both.
    unix: bool,
    listener: Mutex<Accepting>,
    /// The listener's accept filter (ADR-099). Outside `listener`: the filter is user code, and
    /// one that removes its own listener closes this job, which locks `listener`. Only the
    /// accept job (one at a time) locks it.
    filter: Mutex<FilterView>,
    fd: RawFd,
    token: u64,
    acceptor: Arc<dyn DynAcceptor>,
    home: Arc<PollerShared>,
    pending: AtomicBool,
    scheduled: AtomicBool,
    /// Accepts paused after an error until this tick (0: not paused).
    paused_until: AtomicU64,
}

/// The part of a [`ListenJob`] an accept job holds while it runs.
struct Accepting {
    /// `None` once the listener was removed or the poller shut down (the socket is closed).
    listener: Option<TcpListener>,
}

/// No listener: a dialed connection's `RConn::lid`.
pub(crate) const NO_LISTENER: usize = usize::MAX;

impl ListenJob {
    /// The accept job of socket `l` of listener `lid`, polled by `home` under `token`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        l: TcpListener,
        lid: usize,
        addr: SocketAddr,
        unix: bool,
        token: u64,
        acceptor: Arc<dyn DynAcceptor>,
        filter: &Arc<FilterCell>,
        home: Arc<PollerShared>,
    ) -> io::Result<Arc<ListenJob>> {
        l.set_nonblocking(true)?;
        Ok(Arc::new(ListenJob {
            lid,
            addr,
            unix,
            filter: Mutex::new(FilterView::new(filter.clone())),
            fd: l.as_raw_fd(),
            listener: Mutex::new(Accepting { listener: Some(l) }),
            token: LISTEN_BIT | token,
            acceptor,
            home,
            pending: AtomicBool::new(false),
            scheduled: AtomicBool::new(false),
            paused_until: AtomicU64::new(0),
        }))
    }

    /// Readiness: queues an accept job unless one is queued or running.
    fn notify(self: &Arc<Self>, workers: &Workers) {
        self.pending.store(true, Ordering::SeqCst);
        if !self.scheduled.load(Ordering::SeqCst) && !self.scheduled.swap(true, Ordering::SeqCst) {
            workers.submit(Job::Accept(self.clone()));
        }
    }

    /// Runs on a worker: accepts until the backlog is empty (or the budget is spent, then it
    /// goes to the back of the queue).
    pub(crate) fn run(self: Arc<Self>, ctx: &WorkerCtx) {
        self.pending.store(false, Ordering::SeqCst);
        let mut again;
        {
            let mut g = lock(&self.listener);
            again = g.listener.is_some();
            for _ in 0..MAX_ACCEPT_PER_JOB {
                let Some(l) = g.listener.as_ref() else {
                    again = false; // closed while the filter ran
                    break;
                };
                let accepted = if self.unix {
                    akio_sys::accept_stream(l).map(|s| (s, akio_core::UNIX_ADDR))
                } else {
                    l.accept()
                };
                match accepted {
                    Ok((stream, peer)) => {
                        // The filter runs without the socket's lock: it is user code, and may
                        // remove this very listener (`close` takes the lock).
                        drop(g);
                        let allowed = lock(&self.filter).allows(&peer);
                        g = lock(&self.listener);
                        if !allowed {
                            self.home.stats.filtered.add(1);
                            akio_log::debug!(target: "akio", peer:% = peer; "connection refused by the accept filter");
                            continue; // dropping the stream closes it
                        }
                        if g.listener.is_none() {
                            // Closed meanwhile: the connection is dropped like one that
                            // arrived after the close.
                            again = false;
                            break;
                        }
                        self.home.open(
                            stream,
                            peer,
                            self.acceptor.clone(),
                            false,
                            self.unix.then_some(akio_core::UNIX_ADDR),
                            &ctx.workers,
                            self.lid,
                        );
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        again = false;
                        break;
                    }
                    // One connection failed before it was accepted: not the listener's fault.
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::ConnectionReset
                        ) => {}
                    Err(e) => {
                        again = false;
                        self.home.stats.accept_errors.add(1);
                        log_or_stderr(
                            akio_log::Level::Warn,
                            format_args!("accept: {e}; pausing accepts for {ACCEPT_BACKOFF:?}"),
                        );
                        self.home.registry.delete(self.fd);
                        let until = self.home.tick() + ACCEPT_BACKOFF.as_millis() as u64;
                        self.paused_until.store(until.max(1), Ordering::SeqCst);
                        // The poller re-arms it; let it compute its wait with this.
                        self.home.wake();
                        break;
                    }
                }
            }
        }
        self.scheduled.store(false, Ordering::SeqCst);
        if (again || self.pending.load(Ordering::SeqCst))
            && !self.scheduled.swap(true, Ordering::SeqCst)
        {
            ctx.workers.submit(Job::Accept(self));
        }
    }

    /// Closes the socket (shutdown, or the listener removed). Waits for an accept job in
    /// progress, so every connection it accepted is in the table afterwards (one whose filter
    /// check was running is dropped instead); an accept job that runs later finds no socket.
    /// Idempotent.
    pub(crate) fn close(&self) {
        let mut g = lock(&self.listener);
        // No pause to resume: the poller's wait must not count on it any more.
        self.paused_until.store(0, Ordering::SeqCst);
        if let Some(l) = g.listener.take() {
            self.home.registry.delete(l.as_raw_fd());
            drop(l);
        }
    }
}

struct Connecting {
    stream: TcpStream,
    acceptor: Arc<dyn DynAcceptor>,
    on_error: Option<Box<dyn FnOnce(io::Error) + Send>>,
    unix: bool,
}

pub(crate) struct RLoop {
    poller: Poller,
    shared: Arc<PollerShared>,
    jobs: Vec<Arc<ListenJob>>,
    workers: Arc<Workers>,
    connecting: IdMap<Connecting>,
    /// Connect deadlines (the connections' own timers are in the table).
    wheel: Wheel<u64>,
    backlog: i32,
    draining: Option<Instant>,
    /// Remaining connections were told to close (the drain deadline passed).
    killed: bool,
    /// Every listener was removed (`RCmd::StopListening` with no `lid`, ADR-099): with
    /// `unlisted_exit` the poller finishes once no connection is left, and at `unlisted_kill`
    /// (the drain deadline) the connections still open are closed and the dials aborted.
    unlisted: bool,
    unlisted_exit: bool,
    unlisted_kill: Option<Instant>,
    /// One listener's removal (ADR-130): its connections still open at the deadline are closed.
    listener_kills: Vec<(usize, Instant)>,
    /// The address of each listener whose sockets this poller got, by `lid`.
    listener_addrs: Vec<Option<SocketAddr>>,
    spare: Vec<RCmd>,
    due: Vec<u64>,
    events: Vec<Event>,
    finished: bool,
    /// Tracing: how long the last `wait` took.
    last_wait: Duration,
}

impl RLoop {
    pub(crate) fn new(
        poller: Poller,
        shared: Arc<PollerShared>,
        jobs: Vec<Arc<ListenJob>>,
        workers: Arc<Workers>,
    ) -> io::Result<RLoop> {
        for j in &jobs {
            shared.registry.add_edge(j.fd, j.token)?;
        }
        let backlog = shared.cfg.telemetry.live().backlog();
        Ok(RLoop {
            poller,
            shared,
            jobs,
            workers,
            connecting: IdMap::default(),
            wheel: Wheel::new(0),
            backlog,
            draining: None,
            killed: false,
            unlisted: false,
            unlisted_exit: false,
            unlisted_kill: None,
            listener_kills: Vec::new(),
            listener_addrs: Vec::new(),
            spare: Vec::new(),
            due: Vec::new(),
            events: Vec::with_capacity(1024),
            finished: false,
            last_wait: Duration::ZERO,
        })
    }

    fn tick(&self) -> u64 {
        self.shared.tick()
    }

    fn cfg(&self) -> &Arc<Config> {
        &self.shared.cfg
    }

    /// How long a blocking poll may wait: until the next timer, the end of an accept backoff, or
    /// a short tick while draining. `None`: until an event.
    pub(crate) fn next_timeout(&self) -> Option<Duration> {
        let mut timeout = self.draining.map(|_| Duration::from_millis(20));
        let now = self.tick();
        let mut next = self.wheel.next_deadline();
        if let Some(t) = self.shared.next_deadline() {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
        for j in &self.jobs {
            let p = j.paused_until.load(Ordering::SeqCst);
            if p != 0 {
                next = Some(next.map_or(p, |n| n.min(p)));
            }
        }
        if let Some(next) = next {
            let wait = Duration::from_millis(next.saturating_sub(now) + 1);
            timeout = Some(timeout.map_or(wait, |t| t.min(wait)));
        }
        let kills = self.listener_kills.iter().map(|(_, t)| *t);
        if let Some(kill) = self.unlisted_kill.into_iter().chain(kills).min() {
            let left = kill.saturating_duration_since(Instant::now()) + Duration::from_millis(1);
            timeout = Some(timeout.map_or(left, |t| t.min(left)));
        }
        timeout
    }

    /// Dedicated-poller mode: polls until the poller is done.
    pub(crate) fn run(&mut self) {
        loop {
            if self.poll_once(None) {
                break;
            }
        }
        self.shared.stats.set_running(false);
    }

    /// One poll: waits up to `limit` (and no longer than the next deadline of this poller) for
    /// readiness, hands the events to the connections and listeners, runs commands and timers.
    /// True once the poller has finished (shut down and drained). Called by the dedicated poller
    /// thread, or by a worker holding the driver (ADR-104, driver mode).
    pub(crate) fn poll_once(&mut self, limit: Option<Duration>) -> bool {
        if self.finished {
            return true;
        }
        let blocking = limit != Some(Duration::ZERO);
        let timeout = if blocking {
            // Announce the wait before reading the deadlines: a worker arming an earlier timer
            // meanwhile either is seen here or sees the announcement and interrupts the wait.
            self.shared.wait_until.store(u64::MAX, Ordering::SeqCst);
            let own = self.next_timeout();
            let t = match (own, limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if let Some(t) = t {
                let until = self.tick() + t.as_millis() as u64;
                self.shared.wait_until.store(until.max(1), Ordering::SeqCst);
            }
            t
        } else {
            limit
        };
        let mut events = std::mem::take(&mut self.events);
        events.clear();
        let t_wait = super::trace::on().then(Instant::now);
        let r = self.poller.wait(&mut events, timeout);
        if blocking {
            self.shared.wait_until.store(NOT_WAITING, Ordering::SeqCst);
        }
        if let Err(e) = r {
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
                t if t & LISTEN_BIT != 0 => {
                    if let Some(j) = self.jobs.iter().find(|j| j.token == t) {
                        j.notify(&self.workers);
                    }
                }
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
        if (self.unlisted || !self.listener_kills.is_empty())
            && self.draining.is_none()
            && self.unlisted_step()
        {
            self.finished = true;
            return true;
        }
        if let Some(deadline) = self.draining {
            if self.connecting.is_empty() && self.shared.table_is_empty() {
                self.finished = true;
                return true;
            }
            let now = Instant::now();
            if now >= deadline && !self.killed {
                self.killed = true;
                self.shared.each(|_, c| c.close_with(None));
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
        let bits = if ev.readable { READ } else { 0 }
            | if ev.writable { WRITE } else { 0 }
            | if ev.hup { HUP } else { 0 };
        if self.shared.notify_conn(id, bits) {
            return;
        }
        if self.connecting.contains_key(&id) && (ev.readable || ev.writable) {
            self.finish_connect(id);
        }
    }

    // ---- accept / dial ----------------------------------------------------------------------

    fn resume_accept(&self) {
        if self.draining.is_some() {
            return;
        }
        let now = self.tick();
        for j in &self.jobs {
            let p = j.paused_until.load(Ordering::SeqCst);
            if p == 0 || now < p {
                continue;
            }
            // Under the listener's lock, which an accept job holds while it pauses: so a pause
            // set meanwhile is seen here, and the socket is registered exactly when not paused.
            let g = lock(&j.listener);
            let p = j.paused_until.load(Ordering::SeqCst);
            if g.listener.is_none() || p == 0 || now < p {
                continue;
            }
            j.paused_until.store(0, Ordering::SeqCst);
            if let Err(e) = self.shared.registry.add_edge(j.fd, j.token) {
                log_or_stderr(
                    akio_log::Level::Warn,
                    format_args!("re-arming the listener: {e}"),
                );
                continue;
            }
            drop(g);
            // Edge-triggered: what queued up during the pause gives no new edge.
            j.notify(&self.workers);
        }
    }

    fn begin_dial(
        &mut self,
        stream: TcpStream,
        acceptor: Arc<dyn DynAcceptor>,
        on_error: Box<dyn FnOnce(io::Error) + Send>,
        unix: bool,
        timeout: Option<Duration>,
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
                unix,
            },
        );
        // The dial's own timeout (ADR-154), else the engine's.
        if let Some(ct) = timeout.or(self.cfg().connect_timeout) {
            let ct = ct.min(akio_core::timer::MAX_DELAY); // a deadline that cannot overflow
            let at = self.tick() + (ct.as_millis() as u64).max(1);
            if self.wheel.is_empty() {
                self.wheel.advance(self.tick(), drop);
            }
            self.wheel.schedule(at, id | CONNECT_TIMER);
        }
    }

    fn finish_connect(&mut self, id: u64) {
        let Some(Connecting {
            stream,
            acceptor,
            on_error,
            unix,
        }) = self.connecting.remove(&id)
        else {
            return;
        };
        self.poller.delete(stream.as_raw_fd());
        let result = match stream.take_error() {
            // A Unix-domain socket has no `SocketAddr`; both its addresses are `UNIX_ADDR`.
            Ok(None) if unix => Ok(akio_core::UNIX_ADDR),
            Ok(None) => stream.peer_addr(),
            Ok(Some(e)) | Err(e) => Err(e),
        };
        match result {
            Ok(peer) => self.shared.open(
                stream,
                peer,
                acceptor,
                true,
                unix.then_some(akio_core::UNIX_ADDR),
                &self.workers,
                NO_LISTENER,
            ),
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
            // The deepest batch, and one past the line to the pressure watcher.
            self.shared.stats.cmd_batch(batch.len());
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
            RCmd::Shutdown => self.begin_shutdown(),
            RCmd::Core(LoopCmd::Inspect(reply)) => {
                let now = self.tick();
                let meta = self.shared.stats.meta().clone();
                let mut infos = Vec::new();
                let addrs = &self.listener_addrs;
                self.shared.each(|id, c| {
                    let mut ci = ConnInfo::new(id, &c.inner, meta.clone());
                    // A shared group serves several listeners (ADR-130): name the connection's.
                    if let Some(a) = addrs.get(c.lid).copied().flatten() {
                        ci.owner.listener = Some(a);
                    }
                    ci.age = Duration::from_millis(now.saturating_sub(c.opened));
                    ci.idle = Duration::from_millis(
                        now.saturating_sub(c.last_active.load(Ordering::Relaxed)),
                    );
                    ci.bytes_in = c.bytes_in.load(Ordering::Relaxed);
                    ci.backpressure = c.bp_flag.load(Ordering::Relaxed);
                    infos.push(ci);
                });
                reply(infos);
            }
            RCmd::Core(LoopCmd::Reload) => self.on_reload(),
            RCmd::StopListening { lid, drain, exit } => self.stop_listening(lid, drain, exit),
            RCmd::AddJob(j) => self.add_job(j),
            RCmd::Dial {
                stream,
                acceptor,
                on_error,
                unix,
                timeout,
            } => self.begin_dial(stream, acceptor, on_error, unix, timeout),
        }
    }

    fn on_reload(&mut self) {
        let cfg = self.shared.cfg.clone();
        let live = cfg.telemetry.live();
        let backlog = live.backlog();
        if backlog != self.backlog {
            self.backlog = backlog;
            for j in &self.jobs {
                if let Some(l) = lock(&j.listener).listener.as_ref() {
                    let _ = akio_sys::set_backlog(l, backlog);
                }
            }
        }
        self.shared.reload_idle(live.idle_ms());
    }

    fn begin_shutdown(&mut self) {
        if self.draining.is_some() {
            return;
        }
        self.draining = Some(Instant::now() + self.cfg().telemetry.live().shutdown_timeout());
        self.shared.draining.store(true, Ordering::SeqCst);
        for j in std::mem::take(&mut self.jobs) {
            j.close();
        }
        // Every connection an accept job opened is in the table now (`close` waited for it);
        // later ones (none but in-flight dials) see `draining` themselves.
        self.shared.each(|_, c| c.shutdown_notice());
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

    // ---- removing a listener (ADR-099, ADR-130) -----------------------------------------------

    /// Listener `lid` (with `None`, every listener) was removed: its sockets are closed (the
    /// group closed them before posting this); the connections stay (see `RCmd::StopListening`).
    fn stop_listening(&mut self, lid: Option<usize>, drain: Option<Duration>, exit: bool) {
        if self.draining.is_some() {
            return; // the engine is shutting down anyway
        }
        let (gone, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.jobs)
            .into_iter()
            .partition(|j| lid.is_none_or(|l| j.lid == l));
        self.jobs = keep;
        for j in gone {
            j.close();
        }
        let at = drain.map(|d| Instant::now() + d);
        match lid {
            None => {
                self.unlisted = true;
                self.unlisted_exit |= exit;
                if exit {
                    self.shared.exit_when_empty.store(true, Ordering::SeqCst);
                }
                if let Some(at) = at {
                    self.unlisted_kill = Some(self.unlisted_kill.map_or(at, |t| t.min(at)));
                    self.shared.each(|_, c| c.shutdown_notice());
                }
            }
            Some(l) => {
                if let Some(at) = at {
                    self.listener_kills.push((l, at));
                    self.shared.each(|_, c| {
                        if c.lid == l {
                            c.shutdown_notice();
                        }
                    });
                }
            }
        }
    }

    /// A socket of a listener added to a shared group (ADR-130): polled from now on, and
    /// accepted from at once (connections may be queued already).
    fn add_job(&mut self, j: Arc<ListenJob>) {
        if self.draining.is_some() || lock(&j.listener).listener.is_none() {
            return; // shutting down, or the listener was removed meanwhile
        }
        if let Err(e) = self.shared.registry.add_edge(j.fd, j.token) {
            log_or_stderr(
                akio_log::Level::Warn,
                format_args!("adding a listening socket: {e}"),
            );
            return;
        }
        j.notify(&self.workers);
        if self.listener_addrs.len() <= j.lid {
            self.listener_addrs.resize(j.lid + 1, None);
        }
        self.listener_addrs[j.lid] = Some(j.addr);
        self.jobs.push(j);
    }

    /// Once per poll after a listener was removed: closes what is left at a drain deadline,
    /// and finishes the poller (true) once no connection is left, if it may.
    fn unlisted_step(&mut self) -> bool {
        let now = Instant::now();
        if self.unlisted_kill.is_some_and(|t| now >= t) {
            self.unlisted_kill = None;
            self.shared.each(|_, c| c.close_with(None));
            for (_, d) in self.connecting.drain() {
                self.poller.delete(d.stream.as_raw_fd());
                if let Some(f) = d.on_error {
                    f(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "listener shut down",
                    ));
                }
            }
        }
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.listener_kills)
            .into_iter()
            .partition(|(_, t)| now >= *t);
        self.listener_kills = later;
        for (l, _) in due {
            self.shared.each(|_, c| {
                if c.lid == l {
                    c.close_with(None);
                }
            });
        }
        self.unlisted_exit && self.connecting.is_empty() && self.shared.table_is_empty()
    }

    // ---- timers -----------------------------------------------------------------------------

    fn fire_timers(&mut self) {
        let mut due = std::mem::take(&mut self.due);
        self.shared.fire_timers(&mut due);
        if !self.wheel.is_empty() {
            due.clear();
            let now = self.tick();
            self.wheel.advance(now, |id| due.push(id));
            for &id in &due {
                let id = id & !CONNECT_TIMER;
                if let Some(d) = self.connecting.remove(&id) {
                    self.poller.delete(d.stream.as_raw_fd());
                    if let Some(f) = d.on_error {
                        f(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
                    }
                }
            }
        }
        due.clear();
        self.due = due;
    }
}

/// Posts a dial to `sh`'s poller; `unix` for a Unix-domain socket (ADR-120); `timeout`: its
/// own connect timeout (ADR-154), `None` for the engine's.
pub(crate) fn post_dial(
    sh: &PollerShared,
    stream: TcpStream,
    acceptor: Arc<dyn DynAcceptor>,
    on_error: Box<dyn FnOnce(io::Error) + Send>,
    unix: bool,
    timeout: Option<Duration>,
) {
    sh.post(RCmd::Dial {
        stream,
        acceptor,
        on_error,
        unix,
        timeout,
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        io::Write,
        net::TcpStream,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use akio_core::{
        Config, ConnInner, DynAcceptor, DynHandler, Error, Group, Pool, PoolConfig, Task,
    };

    use super::super::{WorkStealingConfig, WorkStealingGroup};

    /// A round was queued while the connection already was (the invariant broken).
    pub(crate) static DOUBLE_QUEUED: AtomicU64 = AtomicU64::new(0);
    /// Milliseconds `open` sleeps between registering a connection and queueing its first round.
    static OPEN_DELAY_MS: AtomicU64 = AtomicU64::new(0);
    static SERIAL: Mutex<()> = Mutex::new(());

    pub(crate) fn open_hook() {
        let ms = OPEN_DELAY_MS.load(Ordering::SeqCst);
        if ms > 0 {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }

    #[derive(Default)]
    struct Counts {
        opens: AtomicUsize,
        shutdowns: AtomicUsize,
        bytes: AtomicUsize,
        /// Milliseconds `on_open` / `on_data` take (to make rounds overlap with events).
        slow_open_ms: AtomicU64,
        slow_data_ms: AtomicU64,
    }

    fn nap(ms: &AtomicU64) {
        let ms = ms.load(Ordering::SeqCst);
        if ms > 0 {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }

    struct Acc(Arc<Counts>);
    struct H(Arc<Counts>);

    impl DynHandler for H {
        fn on_data(&mut self, data: &[u8]) {
            nap(&self.0.slow_data_ms);
            self.0.bytes.fetch_add(data.len(), Ordering::SeqCst);
        }
        fn on_close(&mut self, _err: Option<Error>) {}
        fn run_task(&mut self, _task: Task) {}
    }

    impl DynAcceptor for Acc {
        fn on_open(&self, _inner: &Arc<ConnInner>) -> Box<dyn DynHandler> {
            self.0.opens.fetch_add(1, Ordering::SeqCst);
            nap(&self.0.slow_open_ms);
            Box::new(H(self.0.clone()))
        }
        fn on_shutdown(&self, _inner: &Arc<ConnInner>) {
            // Not closing: a second notice would run it again (the drain deadline closes).
            self.0.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn group(counts: &Arc<Counts>) -> WorkStealingGroup {
        let mut cfg = Config::default();
        cfg.shutdown_timeout = Duration::from_millis(500);
        let g = WorkStealingGroup::bind(
            Some((
                "127.0.0.1:0".parse().expect("addr"),
                Arc::new(Acc(counts.clone())),
            )),
            WorkStealingConfig::new(1, 2),
            cfg,
            Pool::new(PoolConfig::default()),
        )
        .expect("bind");
        g.start().expect("start");
        g
    }

    fn wait_for(what: &str, f: impl Fn() -> bool) {
        let t0 = Instant::now();
        while !f() {
            assert!(t0.elapsed() < Duration::from_secs(5), "timed out: {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A readable socket's first edge reaches a worker polling the driver while the accepting
    /// worker is still between registration and `start`: the connection must be queued once.
    #[test]
    fn an_edge_before_the_first_round_does_not_queue_the_connection_twice() {
        let _s = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let counts = Arc::new(Counts::default());
        // The round the edge queued is still in `on_data` when the accepting worker reaches
        // `start` (100 ms later): a second queueing overlaps it.
        counts.slow_data_ms.store(300, Ordering::SeqCst);
        let g = group(&counts);
        let before = DOUBLE_QUEUED.load(Ordering::SeqCst);
        OPEN_DELAY_MS.store(100, Ordering::SeqCst);
        let mut c = TcpStream::connect(g.local_addr()).expect("connect");
        c.write_all(b"hello").expect("write");
        wait_for("data", || counts.bytes.load(Ordering::SeqCst) == 5);
        OPEN_DELAY_MS.store(0, Ordering::SeqCst);
        assert_eq!(DOUBLE_QUEUED.load(Ordering::SeqCst), before);
        assert_eq!(counts.opens.load(Ordering::SeqCst), 1);
        drop(c);
        g.shutdown();
        g.join();
    }

    /// A connection accepted while the shutdown waits for the accept job gets `on_shutdown`
    /// once, not once from the accept and once from the shutdown.
    #[test]
    fn a_connection_accepted_during_shutdown_gets_on_shutdown_once() {
        let _s = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let counts = Arc::new(Counts::default());
        // The shutdown's notice arrives while the first round is still in `on_open`.
        counts.slow_open_ms.store(100, Ordering::SeqCst);
        let g = group(&counts);
        OPEN_DELAY_MS.store(200, Ordering::SeqCst);
        let _c = TcpStream::connect(g.local_addr()).expect("connect");
        // The accept job is asleep in `open` now; the shutdown waits for it.
        std::thread::sleep(Duration::from_millis(50));
        g.shutdown();
        wait_for("on_shutdown", || {
            counts.shutdowns.load(Ordering::SeqCst) >= 1
        });
        std::thread::sleep(Duration::from_millis(100));
        OPEN_DELAY_MS.store(0, Ordering::SeqCst);
        g.join();
        assert_eq!(counts.shutdowns.load(Ordering::SeqCst), 1);
    }

    /// An accept filter that removes its own listener: the filter runs without the listening
    /// socket's lock, which `stop_listening` takes to close the socket (it used to deadlock).
    #[test]
    fn a_filter_may_stop_its_own_listener() {
        let _s = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let counts = Arc::new(Counts::default());
        let g = Arc::new(group(&counts));
        let me: Arc<std::sync::OnceLock<std::sync::Weak<WorkStealingGroup>>> = Arc::default();
        let _ = me.set(Arc::downgrade(&g));
        let stopped = Arc::new(AtomicUsize::new(0));
        let st = stopped.clone();
        g.set_filter(Some(Arc::new(move |_peer: &std::net::SocketAddr| {
            if let Some(g) = me.get().and_then(std::sync::Weak::upgrade) {
                g.stop_listening(None, false).expect("stop_listening");
                st.fetch_add(1, Ordering::SeqCst);
            }
            true
        })))
        .expect("set_filter");
        let _c = TcpStream::connect(g.local_addr()).expect("connect");
        let t0 = Instant::now();
        while stopped.load(Ordering::SeqCst) == 0 {
            if t0.elapsed() > Duration::from_secs(5) {
                // The worker is stuck: leave the group alone rather than wait for it.
                std::mem::forget(g);
                panic!("a filter stopping its own listener deadlocked");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // The listener was closed while the filter ran: the connection it allowed is dropped.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(counts.opens.load(Ordering::SeqCst), 0);
        g.shutdown();
        g.join();
    }

    /// Driver mode with fewer workers than pollers: the one worker must not stay blocked in
    /// the first driver while the second holds dials, their connections and their data.
    #[test]
    fn one_worker_polls_every_driver() {
        let _s = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        if std::env::var("AKIO_WORK_STEALING_POLLERS").as_deref() == Ok("dedicated") {
            return; // driver mode only
        }
        let counts = Arc::new(Counts::default());
        let mut cfg = Config::default();
        cfg.shutdown_timeout = Duration::from_millis(500);
        let g = WorkStealingGroup::bind(
            None,
            WorkStealingConfig::new(2, 1),
            cfg,
            Pool::new(PoolConfig::default()),
        )
        .expect("bind");
        g.start().expect("start");
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
        let addr = server.local_addr().expect("addr");
        const N: usize = 4;
        for _ in 0..N {
            g.dial(
                addr,
                Arc::new(Acc(counts.clone())),
                Box::new(|e| panic!("dial: {e}")),
            );
        }
        server.set_nonblocking(true).expect("nonblocking");
        let mut peers = Vec::new();
        let t0 = Instant::now();
        while peers.len() < N {
            match server.accept() {
                Ok((s, _)) => peers.push(s),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
            if t0.elapsed() > Duration::from_secs(5) {
                break;
            }
        }
        let opened = |counts: &Counts| counts.opens.load(Ordering::SeqCst);
        let t0 = Instant::now();
        while opened(&counts) < N && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let opens = opened(&counts);
        for p in &mut peers {
            p.write_all(b"hi").expect("write");
        }
        let t0 = Instant::now();
        while counts.bytes.load(Ordering::SeqCst) < 2 * N && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let bytes = counts.bytes.load(Ordering::SeqCst);
        if opens < N || bytes < 2 * N {
            // A driver is never polled: leave the group alone rather than wait for it.
            std::mem::forget(g);
            panic!(
                "{opens} of {N} dials opened, {bytes} of {} bytes read",
                2 * N
            );
        }
        drop(peers);
        g.shutdown();
        g.join();
    }
}
