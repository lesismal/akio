//! The worker pool of rounds scheduling (ADR-104): a fixed set of threads, each with its own
//! queue of connections whose round is due.
//!
//! Who waits for readiness depends on the mode:
//!
//! * **Dedicated pollers**: poller threads of their own wait in `epoll_wait` and spread the
//!   connections over the workers' queues in turn.
//! * **Driver mode** (as Tokio's multi-thread runtime): there are no poller threads. Each poller
//!   is a *driver* behind a lock; a worker with nothing to run takes a free driver and waits in
//!   its `epoll_wait`, and the connections it finds go to its own queue (the others steal). A
//!   busy worker polls the drivers without blocking every [`POLL_INTERVAL`] rounds, so under
//!   load events are picked up without any thread waking another.
//!
//! A worker that runs dry steals half of another's queue, spins a little, and parks. A poster
//! wakes a parked worker when the queue it pushed to belongs to one, or when no worker is
//! spinning (so some idle worker comes to steal the job instead of it waiting behind a busy one);
//! in driver mode, a worker blocked in a driver's `epoll_wait` is woken through the driver's
//! eventfd when no parked worker is left to wake. What a worker's own poll collects wakes no one
//! until the poll is over, and then only for the jobs it will not run next itself; a worker that
//! found work by searching wakes another if more is queued. One parked worker (the watch) wakes
//! every 10 ms to look at the drivers; the others sleep until woken.
//!
//! Jobs are rounds of connections and accept jobs of listening sockets ([`Job`]).

use std::{
    cell::Cell,
    collections::VecDeque,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{JoinHandle, Thread},
    time::Duration,
};

use akio_core::{Config, LoopMeta, LoopStats};

use super::conn::RConn;
use super::poller::{ListenJob, PollerShared, RLoop};

/// Empty passes over every queue before a worker parks.
const SPIN: usize = 64;
/// Driver mode: rounds a busy worker runs between two non-blocking polls of the drivers
/// (Tokio's `event_interval`).
const POLL_INTERVAL: u32 = 61;
/// Driver mode: how long the watch (one parked worker) sleeps before it looks at the drivers.
const WATCH: Duration = Duration::from_millis(10);

/// `SPIN`, or `AKIO_ROUNDS_SPIN` (diagnostic knob).
fn spin_limit() -> usize {
    std::env::var("AKIO_ROUNDS_SPIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SPIN)
}

/// `POLL_INTERVAL`, or `AKIO_ROUNDS_POLL_INTERVAL` (diagnostic knob).
fn poll_interval() -> u32 {
    std::env::var("AKIO_ROUNDS_POLL_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &u32| n > 0)
        .unwrap_or(POLL_INTERVAL)
}

static NEXT_POOL_UID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    /// `(pool uid, worker index)` of the worker running on this thread (uid 0: not a worker).
    static CURRENT: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    /// This worker is polling a driver: what the poll queues goes to its own queue without
    /// waking anyone; afterwards it wakes others only for what it cannot run itself next.
    static POLLING: Cell<bool> = const { Cell::new(false) };
}

/// What a worker runs.
pub(crate) enum Job {
    /// A round of a connection.
    Round(Arc<RConn>),
    /// Accepts on a listening socket.
    Accept(Arc<ListenJob>),
}

impl Job {
    fn run(self, ctx: &mut WorkerCtx) {
        match self {
            Job::Round(c) => c.run_round(ctx),
            Job::Accept(l) => l.run(ctx),
        }
    }
}

struct Shard {
    q: Mutex<VecDeque<Job>>,
    /// `q.len()`, readable without the lock (emptiness checks of stealers and parkers).
    len: AtomicUsize,
    /// The worker is parked (or about to): a poster that swaps it to false unparks it.
    parked: AtomicBool,
    thread: OnceLock<Thread>,
}

impl Shard {
    fn push(&self, c: Job) {
        let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
        q.push_back(c);
        self.len.store(q.len(), Ordering::SeqCst);
    }

    fn pop(&self) -> Option<Job> {
        if self.len.load(Ordering::SeqCst) == 0 {
            return None;
        }
        let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
        let c = q.pop_front();
        self.len.store(q.len(), Ordering::SeqCst);
        c
    }

    /// Takes half of the queue (at least one): the first to run now, the rest into `into`.
    fn steal_half(&self, into: &Shard) -> Option<Job> {
        if self.len.load(Ordering::SeqCst) == 0 {
            return None;
        }
        let mut taken = {
            let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
            let n = q.len().div_ceil(2);
            let taken: VecDeque<Job> = q.drain(..n).collect();
            self.len.store(q.len(), Ordering::SeqCst);
            taken
        };
        let first = taken.pop_front();
        if !taken.is_empty() {
            let mut q = into.q.lock().unwrap_or_else(|p| p.into_inner());
            q.extend(taken);
            into.len.store(q.len(), Ordering::SeqCst);
        }
        first
    }

    fn wake(&self) -> bool {
        if self.parked.swap(false, Ordering::SeqCst) {
            if let Some(t) = self.thread.get() {
                super::trace::count(&super::trace::C.unparks);
                t.unpark();
            }
            return true;
        }
        false
    }
}

/// A poller driven by the workers (driver mode).
pub(crate) struct Driver {
    /// `None` once the pool stopped: dropping the loop releases its sockets, its poller and
    /// the `Arc`s it holds back to this pool.
    pub(crate) lp: Mutex<Option<RLoop>>,
    pub(crate) shared: Arc<PollerShared>,
    /// Its loop finished (shut down and drained): nobody polls it any more.
    pub(crate) done: AtomicBool,
}

/// The pool. Built by the group, started with [`Workers::start`].
pub(crate) struct Workers {
    uid: usize,
    shards: Box<[Shard]>,
    rr: AtomicUsize,
    spinning: AtomicUsize,
    sleeping: AtomicUsize,
    /// Workers blocked in a driver's `epoll_wait`.
    in_poll: AtomicUsize,
    /// Driver mode: a parked worker keeps watch (parks with a timeout).
    watch: AtomicBool,
    stop: AtomicBool,
    handles: Mutex<Vec<JoinHandle<()>>>,
    stats: Vec<Arc<LoopStats>>,
    spin: usize,
    interval: u32,
    /// Driver mode: the pollers the workers drive (empty with dedicated pollers). Set once
    /// before the workers start, cleared when they stop (it holds `Arc`s back to this pool).
    drivers: Mutex<Vec<Arc<Driver>>>,
    driven: OnceLock<Vec<Arc<Driver>>>,
}

impl std::fmt::Debug for Workers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workers")
            .field("n", &self.shards.len())
            .finish_non_exhaustive()
    }
}

/// What a round needs from the worker running it.
pub(crate) struct WorkerCtx {
    pub(crate) scratch: Vec<u8>,
    pub(crate) stats: Arc<LoopStats>,
    pub(crate) workers: Arc<Workers>,
}

impl Workers {
    /// `n` workers (at least 1), counted in `cfg`'s telemetry as threads of `listener`.
    pub(crate) fn new(
        n: usize,
        cfg: &Config,
        listener: Option<std::net::SocketAddr>,
    ) -> Arc<Workers> {
        let n = n.max(1);
        let stats: Vec<Arc<LoopStats>> = (0..n)
            .map(|i| {
                let st = Arc::new(LoopStats::new(LoopMeta::new(super::BACKEND, listener, i)));
                // Workers own no connections: telemetry commands (connection table, reload)
                // are answered by the pollers, so a worker drops them (answering "nothing").
                cfg.telemetry.register_loop(st.clone(), Box::new(drop));
                st
            })
            .collect();
        Arc::new(Workers {
            uid: NEXT_POOL_UID.fetch_add(1, Ordering::Relaxed),
            shards: (0..n)
                .map(|_| Shard {
                    q: Mutex::new(VecDeque::new()),
                    len: AtomicUsize::new(0),
                    parked: AtomicBool::new(false),
                    thread: OnceLock::new(),
                })
                .collect(),
            rr: AtomicUsize::new(0),
            spinning: AtomicUsize::new(0),
            sleeping: AtomicUsize::new(0),
            in_poll: AtomicUsize::new(0),
            watch: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            handles: Mutex::new(Vec::new()),
            stats,
            spin: {
                let _ = super::trace::on();
                spin_limit()
            },
            interval: poll_interval(),
            drivers: Mutex::new(Vec::new()),
            driven: OnceLock::new(),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.shards.len()
    }

    /// Driver mode: the workers poll `drivers` themselves. Call before [`start`](Self::start).
    pub(crate) fn set_drivers(&self, drivers: Vec<Arc<Driver>>) {
        *self.drivers.lock().unwrap_or_else(|p| p.into_inner()) = drivers.clone();
        let _ = self.driven.set(drivers);
    }

    fn drivers(&self) -> &[Arc<Driver>] {
        self.driven.get().map_or(&[], Vec::as_slice)
    }

    /// Driver mode: every driver finished.
    pub(crate) fn drivers_done(&self) -> bool {
        self.drivers()
            .iter()
            .all(|d| d.done.load(Ordering::Acquire))
    }

    /// Spawns the threads (idempotent).
    pub(crate) fn start(self: &Arc<Self>, cfg: &Arc<Config>) -> std::io::Result<()> {
        let mut hs = self.handles.lock().unwrap_or_else(|p| p.into_inner());
        if !hs.is_empty() {
            return Ok(());
        }
        for i in 0..self.shards.len() {
            let me = self.clone();
            let cfg = cfg.clone();
            self.stats[i].set_running(true);
            let h = std::thread::Builder::new()
                .name(format!("akio-io-w{i}"))
                .spawn(move || me.run(i, &cfg))?;
            hs.push(h);
        }
        Ok(())
    }

    /// Stops the threads once their queues are empty and joins them.
    pub(crate) fn stop_and_join(&self) {
        self.stop.store(true, Ordering::SeqCst);
        for s in &self.shards {
            s.wake();
        }
        for d in self.drivers() {
            d.shared.wake();
        }
        let hs = std::mem::take(&mut *self.handles.lock().unwrap_or_else(|p| p.into_inner()));
        for h in hs {
            let _ = h.join();
        }
        for st in &self.stats {
            st.set_running(false);
        }
        // Connections still queued hold this pool (cycle pool -> queue -> connection -> pool).
        for sh in &self.shards {
            let q = std::mem::take(&mut *sh.q.lock().unwrap_or_else(|p| p.into_inner()));
            sh.len.store(0, Ordering::SeqCst);
            drop(q);
        }
        // Break the cycle drivers -> loops -> this pool: drop the loops (their sockets close).
        for d in self.drivers() {
            let lp = d.lp.lock().unwrap_or_else(|p| p.into_inner()).take();
            drop(lp);
        }
        self.drivers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Queues `job`: on the calling worker's own queue, else on the next in turn.
    pub(crate) fn submit(&self, job: Job) {
        if let Job::Round(c) = &job {
            c.queued_ns.store(super::trace::now_ns(), Ordering::Relaxed);
        }
        let (uid, me) = CURRENT.with(Cell::get);
        let own = uid == self.uid;
        let i = if own {
            me
        } else {
            self.rr.fetch_add(1, Ordering::Relaxed) % self.shards.len()
        };
        let shard = &self.shards[i];
        shard.push(job);
        if own && POLLING.with(Cell::get) {
            // Collected by this worker's poll: it decides once the poll is over.
            return;
        }
        if !own && shard.wake() {
            return;
        }
        self.kick(i, own);
    }

    /// Work was queued on `i`, whose owner is busy (or is us): get an idle worker to steal it,
    /// unless one is already spinning and will find it. True if one was woken.
    fn kick(&self, i: usize, own: bool) -> bool {
        if self.spinning.load(Ordering::SeqCst) != 0 {
            return false;
        }
        if self.sleeping.load(Ordering::SeqCst) > 0 && self.wake_one(i) {
            return true;
        }
        if !own && self.in_poll.load(Ordering::SeqCst) > 0 {
            // Driver mode with every idle worker in `epoll_wait`: interrupt one.
            if let Some(d) = self.drivers().first() {
                d.shared.wake();
            }
        }
        false
    }

    /// Wakes one parked worker, starting the search after `from`.
    fn wake_one(&self, from: usize) -> bool {
        let n = self.shards.len();
        for k in 1..=n {
            if self.shards[(from + k) % n].wake() {
                return true;
            }
        }
        false
    }

    /// The next job: from the own queue, else stolen (with half of the victim's queue). The
    /// flag says it was stolen.
    fn find(&self, me: usize) -> Option<(Job, bool)> {
        if let Some(c) = self.shards[me].pop() {
            return Some((c, false));
        }
        let n = self.shards.len();
        for k in 1..n {
            if let Some(c) = self.shards[(me + k) % n].steal_half(&self.shards[me]) {
                return Some((c, true));
            }
        }
        None
    }

    /// A worker that had to look for work found some: if more is queued, it wakes a parked
    /// worker for it (who does the same), so a burst spreads over the pool in a chain of
    /// wake-ups instead of waiting for the workers that hold it (Tokio's rule for searching
    /// workers).
    fn found_by_search(&self, me: usize) {
        if self.sleeping.load(Ordering::SeqCst) > 0 && self.any_queued() {
            self.kick(me, true);
        }
    }

    fn any_queued(&self) -> bool {
        self.shards
            .iter()
            .any(|s| s.len.load(Ordering::SeqCst) != 0)
    }

    /// Driver mode: polls a free driver. `block`: wait for events (an idle worker), else just
    /// collect what is ready. True if a driver was polled.
    fn poll_drivers(&self, me: usize, block: bool) -> bool {
        for d in self.drivers() {
            if d.done.load(Ordering::Acquire) {
                continue;
            }
            // A poisoned lock means a callback panicked inside a poll (a dial's `on_error`,
            // say); the loop's state is still consistent, so keep polling it.
            let mut g = match d.lp.try_lock() {
                Ok(g) => g,
                Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => continue,
            };
            let Some(lp) = g.as_mut() else {
                continue;
            };
            // The loop adds its own deadlines in `poll_once`; this bounds the wait by the
            // worker's loop timers (ADR-103).
            let timeout = if block {
                akio_core::timer::poll_timeout(None)
            } else {
                Some(Duration::ZERO)
            };
            if block {
                self.in_poll.fetch_add(1, Ordering::SeqCst);
            }
            POLLING.with(|p| p.set(true));
            let r =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lp.poll_once(timeout)));
            POLLING.with(|p| p.set(false));
            if block {
                self.in_poll.fetch_sub(1, Ordering::SeqCst);
            }
            drop(g);
            self.after_poll(me);
            let finished = r.unwrap_or_else(|_| {
                akio_core::telemetry::log_or_stderr(
                    akio_log::Level::Error,
                    format_args!("a callback panicked while a worker polled; polling goes on"),
                );
                false
            });
            if finished {
                d.done.store(true, Ordering::Release);
                d.shared.stats.set_running(false);
            }
            return true;
        }
        false
    }

    /// After a poll: wake parked workers for what it queued. When every other worker is
    /// parked (light load), the first job is this worker's to run next and wakes no one, so a
    /// poll that finds one connection costs no wake-up of another thread; it wakes one parked
    /// worker for each job after that (Tokio's rule). When other workers are busy, it wakes one
    /// for the first job too, so that a worker comes back to the driver while this one runs
    /// the round (closed-loop clients wait for exactly that).
    fn after_poll(&self, me: usize) {
        let queued = self.shards[me].len.load(Ordering::SeqCst);
        if queued == 0 {
            return;
        }
        let n = self.shards.len();
        let sleeping = self.sleeping.load(Ordering::SeqCst);
        let wakes = if sleeping + 1 < n { queued } else { queued - 1 };
        for _ in 0..wakes.min(n) {
            if self.sleeping.load(Ordering::SeqCst) == 0 || !self.kick(me, true) {
                break;
            }
        }
    }

    fn run(self: Arc<Self>, me: usize, cfg: &Arc<Config>) {
        CURRENT.with(|c| c.set((self.uid, me)));
        // Loop timers (ADR-103): a timer set from a round runs later on the same worker.
        akio_core::timer::install();
        let shard = &self.shards[me];
        let _ = shard.thread.set(std::thread::current());
        let mut ctx = WorkerCtx {
            scratch: vec![0; cfg.telemetry.live().read_buffer()],
            stats: self.stats[me].clone(),
            workers: self.clone(),
        };
        let driving = !self.drivers().is_empty();
        let mut since_poll = 0u32;
        loop {
            akio_core::timer::fire();
            if let Some((job, stolen)) = self.find(me) {
                if stolen {
                    self.found_by_search(me);
                }
                ctx.stats.iterations.add_local(1);
                job.run(&mut ctx);
                if driving {
                    since_poll += 1;
                    if since_poll >= self.interval {
                        since_poll = 0;
                        self.poll_drivers(me, false);
                    }
                }
                continue;
            }
            // Out of work: under load more events are likely ready, and a non-blocking poll
            // collects them without spinning first (and without counting as spinning, which
            // holds back other workers' wake-ups). Skipping it after a single round saved 0.6 µs
            // per request at 10k requests/s but cost 7% on echo with 64 connections (ADR-104).
            since_poll = 0;
            if driving
                && self.poll_drivers(me, false)
                && self.shards[me].len.load(Ordering::SeqCst) != 0
            {
                continue;
            }
            // Spin a little: under load, more work arrives within microseconds, and a park /
            // unpark pair costs more than that.
            self.spinning.fetch_add(1, Ordering::SeqCst);
            let mut found = None;
            for _ in 0..self.spin {
                if let Some((c, _)) = self.find(me) {
                    found = Some(c);
                    break;
                }
                std::hint::spin_loop();
            }
            self.spinning.fetch_sub(1, Ordering::SeqCst);
            if let Some(job) = found {
                self.found_by_search(me);
                ctx.stats.iterations.add_local(1);
                job.run(&mut ctx);
                since_poll += 1;
                continue;
            }
            // Nothing to run: wait for events in a free driver, if there is one.
            if driving && !self.drivers_done() && self.poll_drivers(me, true) {
                continue;
            }
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            // Park. Announce it first, then look once more: a poster either sees `parked` (and
            // wakes us) or pushed before our last look (and we see the job).
            self.sleeping.fetch_add(1, Ordering::SeqCst);
            shard.parked.store(true, Ordering::SeqCst);
            if self.any_queued() || self.stop.load(Ordering::SeqCst) {
                shard.parked.store(false, Ordering::SeqCst);
            }
            if driving {
                // Polls that find more than their worker runs wake parked workers, and an idle
                // worker takes a free driver before it parks, so a driver is not normally left
                // unpolled. One parked worker, the watch, wakes every 10 ms for the case where
                // the last poller went into a long round meanwhile; the others sleep until woken
                // (or until a loop timer of theirs is due), so an idle pool costs 100 wake-ups a
                // second, not 100 per worker.
                if shard.parked.load(Ordering::SeqCst) {
                    let watch = !self.watch.swap(true, Ordering::SeqCst);
                    let mut t = akio_core::timer::next_wait();
                    if watch {
                        t = Some(t.map_or(WATCH, |w| w.min(WATCH)));
                    }
                    super::trace::count(&super::trace::C.parks);
                    match t {
                        Some(t) => std::thread::park_timeout(t),
                        None => std::thread::park(),
                    }
                    if watch {
                        self.watch.store(false, Ordering::SeqCst);
                    }
                    shard.parked.store(false, Ordering::SeqCst);
                }
            } else {
                while shard.parked.load(Ordering::SeqCst) {
                    match akio_core::timer::next_wait() {
                        // A timer of this worker is due: wake for it.
                        Some(w) => {
                            std::thread::park_timeout(w);
                            if akio_core::timer::next_wait().is_some_and(|w| w.is_zero()) {
                                shard.parked.store(false, Ordering::SeqCst);
                            }
                        }
                        None => std::thread::park(),
                    }
                }
            }
            self.sleeping.fetch_sub(1, Ordering::SeqCst);
        }
        akio_core::timer::uninstall();
        CURRENT.with(|c| c.set((0, 0)));
    }
}
