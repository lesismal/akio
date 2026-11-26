#![forbid(unsafe_code)]
//! The logical (blocking-work) thread pool: a bounded queue served by threads that are spawned on
//! demand up to a maximum and retire after sitting idle.
//!
//! I/O threads never block; code that must block (databases, files, slow RPC) is handed to this
//! pool and its result is brought back to the connection's I/O thread by `akio-core`.
//!
//! Work comes in two lanes. New work ([`Pool::try_execute`]) is admitted while the queue has
//! room and refused past `queue_capacity`: that is where an overloaded process turns work away.
//! The next step of work already admitted ([`Pool::resume`]: the next piece of a file being
//! sent, the next message of an open call) is never refused while the pool runs, so nobody has
//! to try again later; threads take it before new work, so what was admitted finishes first. It
//! is bounded by its owners, not by the queue: each owner has at most one step queued or
//! running at a time.
//!
//! A pool task that waits for something only another task of the same pool can produce (a
//! handler on the pool calling a service of the same engine whose handlers run there too, then
//! waiting for the answer) would hang once every thread waits so. It wraps the wait in
//! [`blocking`], as the libraries' blocking clients do: while it waits, the pool may start a
//! thread in its place (up to [`PoolConfig::max_blocked_threads`] such threads), and the extra
//! thread leaves as soon as it is not needed.
//!
//! A pool under pressure says so. When a submission finds the queue more than half full (or is
//! refused, or finds work held up by the stand-in limit), the pool is handed to a process-wide
//! watcher thread, `akio-pool-watch`, started then: it samples the pool every 100 ms, logs
//! (target `akio-pool`) each time the backlog rises to 50, 75, 90 or 100% of `queue_capacity`,
//! and lets the pool go, with a summary, once the backlog has stayed under 40% for a second. With
//! no pool under pressure no watcher runs and no timer fires ([`PoolStats::warnings`],
//! [`PoolStats::watched`]).
//!
//! Guide: [Blocking work: the logical pool](https://lesismal.github.io/akio/en/concepts/blocking.html)
//! (中文: [阻塞任务：逻辑线程池](https://lesismal.github.io/akio/zh-CN/concepts/blocking.html)).
#![warn(clippy::unwrap_used)]

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

mod watch;

#[doc(hidden)]
pub use watch::{watch_list_has, watcher_running};

/// How long a thread that finds the queue empty keeps looking (without the lock) before it
/// sleeps: work arriving meanwhile costs no wake-up. Short, so an idle pool goes quiet at once
/// (under load the next job comes within microseconds; 10 us gave the same as 50 us on gpu51).
/// It yields the CPU between looks rather than spinning on it: the pool often has more threads
/// than the machine has CPUs, and a busy-spinning thread took a whole CPU from the I/O threads
/// (gpu51, 4 CPUs: h2c through the pool fell 4-12%; with yielding, and wake-ups counted per
/// new job, it gained 12-20%, docs/BENCHMARKS.md).
const SPIN: Duration = Duration::from_micros(10);

/// Threads that may look for work at once ([`SPIN`]).
const MAX_SPINNING: usize = 1;

/// After a look ([`SPIN`]) that found nothing, threads go straight to sleep, except one idle
/// pass in this many, which looks again: under light load looking costs CPU and saves nothing,
/// and a look that finds work turns it back on for every pass.
const SPIN_PROBE: u32 = 16;

thread_local! {
    /// The pool this thread works for, while it is a pool thread.
    static CURRENT: RefCell<Option<Weak<Pool>>> = const { RefCell::new(None) };
    /// How deep this thread is in [`blocking`] calls (only the outermost one counts).
    static BLOCKING: Cell<usize> = const { Cell::new(0) };
}

/// Whether the calling thread is a thread of an akio pool (any [`Pool`], the engine's logical
/// pool among them).
pub fn on_pool_thread() -> bool {
    CURRENT.with(|c| c.borrow().is_some())
}

/// Runs `f`, a wait, telling the pool of the calling thread that this thread is blocked
/// meanwhile, so that the pool may start a thread in its place.
///
/// A pool task that waits for a result only another task of the same pool can produce (a
/// handler on the logical pool calling, through a blocking client, a service of the same engine
/// whose handlers run on the pool too) would hang for good once every thread of the pool waits
/// so: the tasks they wait for sit in the queue with no thread to run them. Inside `blocking`,
/// the thread is counted as blocked ([`PoolStats::blocked`]): while it is, queued work that no
/// idle thread will take gets a new thread, up to `max_threads` plus one per blocked thread, at
/// most [`PoolConfig::max_blocked_threads`] more ([`PoolStats::compensated`] counts them,
/// [`PoolStats::blocked_at_ceiling`] the times that limit left work waiting). Once the waits
/// end, a thread above that allowance leaves after the job it is running, without waiting for
/// `keep_alive`.
///
/// The libraries' blocking calls (`ResponseFuture::wait`, `CallFuture::wait`, the gRPC
/// client's `unary`, the `*_blocking` dials and requests) do this already. Off a pool thread it
/// just runs `f`; nested calls count once; a panic in `f` ends the blocked state too. Wrap only
/// the wait, not work that uses the CPU.
///
/// ```
/// use std::sync::mpsc;
/// use std::time::Duration;
///
/// let mut cfg = akio_pool::PoolConfig::default();
/// cfg.max_threads = 1;
/// let pool = akio_pool::Pool::new(cfg);
/// let (done_tx, done_rx) = mpsc::channel();
/// let p = pool.clone();
/// pool.try_execute(Box::new(move || {
///     // On the pool's only thread: a sub-task, then a wait for it.
///     let (tx, rx) = mpsc::channel();
///     let _ = p.try_execute(Box::new(move || {
///         let _ = tx.send(2 + 2);
///     }));
///     let got = akio_pool::blocking(|| rx.recv_timeout(Duration::from_secs(5)));
///     let _ = done_tx.send(got);
/// }))
/// .ok()
/// .expect("queued");
/// assert_eq!(done_rx.recv_timeout(Duration::from_secs(5)), Ok(Ok(4)));
/// pool.shutdown();
/// pool.join();
/// ```
pub fn blocking<R>(f: impl FnOnce() -> R) -> R {
    let depth = BLOCKING.with(Cell::get);
    let pool = if depth == 0 {
        match CURRENT.with(|c| c.borrow().as_ref().and_then(Weak::upgrade)) {
            Some(p) => Some(p),
            None => return f(),
        }
    } else {
        None
    };
    BLOCKING.with(|d| d.set(depth + 1));
    if let Some(p) = &pool {
        p.enter_blocking();
    }
    // Dropped after `f`, also when it panics.
    let _blocked = Blocked(pool);
    f()
}

/// Ends a [`blocking`] call: the depth, and for the outermost call the pool's count.
struct Blocked(Option<Arc<Pool>>);

impl Drop for Blocked {
    fn drop(&mut self) {
        BLOCKING.with(|d| d.set(d.get().saturating_sub(1)));
        if let Some(p) = &self.0 {
            let mut st = p.lock();
            st.blocked = st.blocked.saturating_sub(1);
        }
    }
}

/// A unit of work.
pub type Job = Box<dyn FnOnce() + Send + 'static>;

/// Pool sizing and overload behaviour.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PoolConfig {
    /// Threads kept alive even when idle.
    pub min_threads: usize,
    /// Upper bound on threads; a new one is started when work is queued and none is idle.
    /// Threads waiting in [`blocking`] may be stood in for beyond it
    /// (`max_blocked_threads`).
    pub max_threads: usize,
    /// How many threads beyond `max_threads` may be started while pool threads wait in
    /// [`blocking`]: one per blocked thread, at most this many. 0 turns that off. Default: the
    /// default `max_threads`.
    pub max_blocked_threads: usize,
    /// Jobs that may wait, new work and resumed work together; beyond it [`Pool::try_execute`]
    /// rejects ([`Pool::resume`] does not). Past half of it the pool is watched and its pressure
    /// logged (see the [crate docs](crate)).
    pub queue_capacity: usize,
    /// How long a thread above `min_threads` may sit idle before it exits.
    pub keep_alive: Duration,
    /// Run by each pool thread when it starts, before any job (the engine's NUMA placement
    /// pins the thread here, ADR-088). `#[doc(hidden)]`: engine-facing.
    #[doc(hidden)]
    pub on_start: Option<ThreadHook>,
    /// The pool's name in the pressure logs (target `akio-pool`, field `pool`), so that a
    /// process with several pools tells which one is under pressure. Threads keep the name
    /// `akio-pool`. Default: `"akio-pool"`; the engine's logical pool is `"akio"`.
    pub name: String,
}

impl PoolConfig {
    /// The default [`name`](Self::name).
    pub const DEFAULT_NAME: &'static str = "akio-pool";
}

/// A function each pool thread runs when it starts ([`PoolConfig::on_start`]).
/// `#[doc(hidden)]`: engine-facing.
#[doc(hidden)]
#[derive(Clone)]
pub struct ThreadHook(pub Arc<dyn Fn() + Send + Sync + std::panic::RefUnwindSafe>);

impl std::fmt::Debug for ThreadHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ThreadHook")
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        let cores = thread::available_parallelism().map_or(4, |n| n.get());
        let max_threads = (cores * 8).max(8);
        PoolConfig {
            min_threads: 0,
            max_threads,
            max_blocked_threads: max_threads,
            queue_capacity: 65_536,
            keep_alive: Duration::from_secs(30),
            on_start: None,
            name: PoolConfig::DEFAULT_NAME.to_owned(),
        }
    }
}

/// Returned when the queue is full or the pool is shut down; carries the job back.
pub struct Rejected(pub Job);

impl std::fmt::Debug for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rejected(..)")
    }
}

/// A snapshot of pool counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolStats {
    /// Threads currently alive.
    pub threads: usize,
    /// Threads waiting for work.
    pub idle: usize,
    /// New jobs waiting ([`Pool::try_execute`]).
    pub queued: usize,
    /// Resumed jobs waiting ([`Pool::resume`]).
    pub resumes: usize,
    /// The most jobs that have waited at once, new and resumed together.
    pub max_queued: usize,
    /// Jobs that ran to completion or panicked.
    pub completed: u64,
    /// Jobs that panicked (also counted in `completed`).
    pub panicked: u64,
    /// Jobs refused because the queue was full or the pool was closed.
    pub rejected: u64,
    /// Threads waiting in [`blocking`] now.
    pub blocked: usize,
    /// Threads started beyond `max_threads` because threads were waiting in [`blocking`].
    pub compensated: u64,
    /// Times queued work was left with no thread to take it while more threads waited in
    /// [`blocking`] than `max_blocked_threads` stands in for: a sign that limit (or a wait in a
    /// pool task) is what holds the work up.
    pub blocked_at_ceiling: u64,
    /// Times the backlog (new and resumed jobs waiting) rose to 50, 75, 90 and 100% of
    /// `queue_capacity`, one count per rise at the highest level reached, whether or not the
    /// log line was held back by its rate limit. A refusal, or work held up by the stand-in
    /// limit (`blocked_at_ceiling`), between two samples counts as 100%.
    pub warnings: [u64; 4],
    /// Whether the pressure watcher watches the pool now: it passed half of `queue_capacity`
    /// (or refused work, or hit the stand-in limit) and has not stayed calm since.
    pub watched: bool,
}

struct State {
    /// New work ([`Pool::try_execute`]), bounded by `queue_capacity`.
    queue: VecDeque<Job>,
    /// Work already admitted, resumed ([`Pool::resume`]); taken first.
    resumes: VecDeque<Job>,
    /// The deepest `queue` and `resumes` have been together.
    max_queued: usize,
    threads: usize,
    /// Threads waiting on the condition variable, plus those just started ([`starting`]).
    idle: usize,
    /// Threads spawned that have not yet looked at the queue (counted in `idle` meanwhile).
    starting: usize,
    /// Threads waiting in [`blocking`].
    blocked: usize,
    /// Threads started beyond `max_threads` for blocked ones ([`PoolStats::compensated`]).
    compensated: u64,
    /// [`PoolStats::blocked_at_ceiling`].
    blocked_at_ceiling: u64,
    /// The pool is in the pressure watcher's list, or a submitter is putting it there. Set by
    /// submitters, cleared by the watcher, both under this lock (`watch` module).
    watched: bool,
    /// Refusals for a full queue since the watcher's last sample.
    refused_since: u64,
    /// `blocked_at_ceiling` events since the watcher's last sample.
    ceiling_since: u64,
    /// The watcher's per-pool memory (levels logged, rate limits), kept across episodes.
    watch: watch::PoolWatch,
    closed: bool,
    handles: Vec<JoinHandle<()>>,
}

/// What [`Pool::queued_locked`] asks of the caller once the lock is dropped.
#[derive(Default)]
struct Queued {
    /// Sleeping threads to wake.
    wake: usize,
    /// Register the pool with the pressure watcher.
    watch: bool,
}

/// What [`Pool::grow_locked`] did.
struct Grown {
    /// Threads started.
    started: usize,
    /// Register the pool with the pressure watcher.
    watch: bool,
}

/// The pool. Share it as an `Arc<Pool>`.
pub struct Pool {
    me: Weak<Pool>,
    cfg: PoolConfig,
    state: Mutex<State>,
    cv: Condvar,
    /// The queue's length, readable without the lock (for spinning threads).
    queued: AtomicUsize,
    /// Threads spinning for work ([`SPIN`]); a job they will take needs no wake-up.
    spinning: AtomicUsize,
    /// The last look for work found some ([`SPIN_PROBE`]).
    spin_pays: std::sync::atomic::AtomicBool,
    /// Idle passes that did not look, counted to probe now and then ([`SPIN_PROBE`]).
    spin_skipped: std::sync::atomic::AtomicU32,
    completed: AtomicU64,
    panicked: AtomicU64,
    rejected: AtomicU64,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool").finish_non_exhaustive()
    }
}

impl Pool {
    /// Creates a pool. No thread starts until work arrives (except `min_threads`, started here).
    pub fn new(mut cfg: PoolConfig) -> Arc<Pool> {
        cfg.max_threads = cfg.max_threads.max(1);
        cfg.min_threads = cfg.min_threads.min(cfg.max_threads);
        let pool = Arc::new_cyclic(|me| Pool {
            me: me.clone(),
            cfg,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                resumes: VecDeque::new(),
                max_queued: 0,
                threads: 0,
                idle: 0,
                starting: 0,
                blocked: 0,
                compensated: 0,
                blocked_at_ceiling: 0,
                watched: false,
                refused_since: 0,
                ceiling_since: 0,
                watch: watch::PoolWatch::default(),
                closed: false,
                handles: Vec::new(),
            }),
            cv: Condvar::new(),
            queued: AtomicUsize::new(0),
            spinning: AtomicUsize::new(0),
            spin_pays: std::sync::atomic::AtomicBool::new(true),
            spin_skipped: std::sync::atomic::AtomicU32::new(0),
            completed: AtomicU64::new(0),
            panicked: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        });
        {
            let mut st = pool.lock();
            for _ in 0..pool.cfg.min_threads {
                pool.spawn_locked(&mut st);
            }
        }
        pool
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queues `job` as new work, starting a thread if all are busy and the maximum allows.
    /// Never blocks. Refused when `queue_capacity` jobs (new and resumed) wait already, or the
    /// pool is shut down.
    pub fn try_execute(&self, job: Job) -> Result<(), Rejected> {
        let mut st = self.lock();
        if st.closed || st.queue.len() + st.resumes.len() >= self.cfg.queue_capacity {
            let watch = !st.closed && Self::refused_locked(&mut st, 1);
            drop(st);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            if watch {
                self.register_watch();
            }
            return Err(Rejected(job));
        }
        st.queue.push_back(job);
        let q = self.queued_locked(&mut st, 1);
        drop(st);
        self.after_queued(q);
        Ok(())
    }

    /// Wakes the threads [`queued_locked`](Self::queued_locked) asked for and, if it marked
    /// the pool watched, hands it to the pressure watcher (after the pool's lock is dropped).
    fn after_queued(&self, q: Queued) {
        for _ in 0..q.wake {
            self.cv.notify_one();
        }
        if q.watch {
            self.register_watch();
        }
    }

    /// Marks the pool watched (under the lock) if it is not yet; true when the caller is to
    /// register it with the watcher once the lock is dropped.
    fn watch_locked(st: &mut State) -> bool {
        if st.watched {
            return false;
        }
        st.watched = true;
        true
    }

    /// `n` submissions refused for a full queue (under the lock): counted for the watcher's
    /// next sample. True when the caller is to register the pool.
    fn refused_locked(st: &mut State, n: u64) -> bool {
        st.refused_since += n;
        Self::watch_locked(st)
    }

    /// Queues the jobs of `jobs` in one go (one lock, the wake-ups they need), as
    /// [`try_execute`](Self::try_execute) would one by one. What the queue has no room for (or
    /// everything, once the pool is shut down) is left in `jobs`, in order, unrun.
    pub fn try_execute_batch(&self, jobs: &mut Vec<Job>) {
        if jobs.is_empty() {
            return;
        }
        let mut st = self.lock();
        let room = if st.closed {
            0
        } else {
            self.cfg
                .queue_capacity
                .saturating_sub(st.queue.len() + st.resumes.len())
        };
        let n = room.min(jobs.len());
        st.queue.extend(jobs.drain(..n));
        let mut q = if n == 0 {
            Queued::default()
        } else {
            self.queued_locked(&mut st, n)
        };
        if !jobs.is_empty() && !st.closed {
            q.watch |= Self::refused_locked(&mut st, jobs.len() as u64);
        }
        drop(st);
        if !jobs.is_empty() {
            self.rejected
                .fetch_add(jobs.len() as u64, Ordering::Relaxed);
        }
        self.after_queued(q);
    }

    /// Queues `job` as the next step of work the pool admitted before (the next piece of a
    /// response under way, the next message of an open call), ahead of new work. Never blocks
    /// and, unlike [`try_execute`](Self::try_execute), is not refused for a full queue: work
    /// already admitted goes on rather than being cut or tried again later. `Err(job)` hands
    /// it back, unrun, only once the pool is shut down.
    ///
    /// The caller bounds it: each owner (a response, a call) keeps at most one step queued or
    /// running at a time, so what waits here is at most one job per piece of admitted work.
    pub fn resume(&self, job: Job) -> Result<(), Job> {
        let mut st = self.lock();
        if st.closed {
            return Err(job);
        }
        st.resumes.push_back(job);
        let q = self.queued_locked(&mut st, 1);
        drop(st);
        self.after_queued(q);
        Ok(())
    }

    /// The next job, resumed work first (under the lock).
    fn next_locked(&self, st: &mut State) -> Option<Job> {
        let job = st.resumes.pop_front().or_else(|| st.queue.pop_front())?;
        self.queued
            .store(st.queue.len() + st.resumes.len(), Ordering::SeqCst);
        Some(job)
    }

    /// After `added` jobs were queued (under the lock): starts threads if every live one is
    /// already spoken for and the maximum allows, and returns how many sleeping threads to wake
    /// for the new jobs: one each, except those a spinning thread not already claimed by the
    /// jobs queued before will take, and those a thread started here will. (Counting the whole
    /// queue instead woke again, for every new job, the sleepers already woken for the earlier
    /// ones: at 2k requests/s, one more context switch per request, 12% more CPU.) A thread
    /// busy with a job looks at the queue before it sleeps, so it is never woken.
    ///
    /// Also marks the pool watched when the backlog passes half of `queue_capacity` (or the
    /// stand-in limit held work up) and it is not watched yet: one comparison and a flag read
    /// on what the lock already guards, nothing more while the pool is calm or watched.
    fn queued_locked(&self, st: &mut State, added: usize) -> Queued {
        let len = st.queue.len() + st.resumes.len();
        self.queued.store(len, Ordering::SeqCst);
        st.max_queued = st.max_queued.max(len);
        // Read under the lock: a spinner stops counting itself before it takes the lock to look
        // at the queue, so either it is counted here or it sees these jobs.
        let spinning = self.spinning.load(Ordering::SeqCst);
        let grown = self.grow_locked(st, len, spinning);
        let free_spinners = spinning.saturating_sub(len - added);
        let wake = added
            .saturating_sub(free_spinners + grown.started)
            .min(st.idle - st.starting);
        let watch = grown.watch
            || (len.saturating_mul(2) > self.cfg.queue_capacity && Self::watch_locked(st));
        Queued { wake, watch }
    }

    /// How many threads may run (under the lock): `max_threads`, plus one for each thread
    /// waiting in [`blocking`], at most `max_blocked_threads` more.
    fn allowance(&self, st: &State) -> usize {
        self.cfg
            .max_threads
            .saturating_add(st.blocked.min(self.cfg.max_blocked_threads))
    }

    /// Starts threads (under the lock) while `len` queued jobs are more than the idle and
    /// `spinning` threads will take and the [`allowance`](Self::allowance) has room. Returns
    /// how many it started, and whether the caller is to register the pool with the watcher
    /// (work was held up by the stand-in limit and the pool was not watched).
    fn grow_locked(&self, st: &mut State, len: usize, spinning: usize) -> Grown {
        let allowance = self.allowance(st);
        let mut started = 0;
        while st.idle + spinning < len && st.threads < allowance {
            let before = st.threads;
            self.spawn_locked(st);
            if st.threads == before {
                break;
            }
            if before >= self.cfg.max_threads {
                st.compensated += 1;
            }
            // A new thread looks at the queue when it starts: count it as taking a job.
            st.idle += 1;
            st.starting += 1;
            started += 1;
        }
        if st.blocked > self.cfg.max_blocked_threads
            && st.idle + spinning < len
            && st.threads >= allowance
        {
            st.blocked_at_ceiling += 1;
            st.ceiling_since += 1;
            return Grown {
                started,
                watch: Self::watch_locked(st),
            };
        }
        Grown {
            started,
            watch: false,
        }
    }

    /// The calling pool thread starts waiting in [`blocking`]: counts it, and starts a thread
    /// in its place if queued work has none to take it.
    fn enter_blocking(&self) {
        let mut st = self.lock();
        st.blocked += 1;
        let len = st.queue.len() + st.resumes.len();
        if len > 0 {
            // Read under the lock, as in `queued_locked`. A thread started here looks at the
            // queue when it starts; sleeping ones were woken for the jobs when they came.
            let spinning = self.spinning.load(Ordering::SeqCst);
            let watch = self.grow_locked(&mut st, len, spinning).watch;
            drop(st);
            if watch {
                self.register_watch();
            }
        }
    }

    fn spawn_locked(&self, st: &mut State) {
        let Some(pool) = self.me.upgrade() else {
            return;
        };
        // Handles of threads that have exited are dropped, so the list holds live threads only.
        st.handles.retain(|h| !h.is_finished());
        let spawned = thread::Builder::new()
            .name("akio-pool".into())
            .spawn(move || pool.worker());
        match spawned {
            Ok(h) => {
                st.threads += 1;
                st.handles.push(h);
            }
            // Out of threads: the job stays queued for the existing ones.
            Err(e) => eprintln!("akio-pool: cannot spawn worker: {e}"),
        }
    }

    /// Whether an idle pass should look for work before sleeping ([`SPIN_PROBE`]).
    fn worth_spinning(&self) -> bool {
        self.spin_pays.load(Ordering::Relaxed)
            || self.spin_skipped.fetch_add(1, Ordering::Relaxed) % SPIN_PROBE == 0
    }

    /// Counts this thread as spinning if fewer than [`MAX_SPINNING`] do.
    fn start_spinning(&self) -> bool {
        if self.spinning.fetch_add(1, Ordering::SeqCst) < MAX_SPINNING {
            return true;
        }
        self.spinning.fetch_sub(1, Ordering::SeqCst);
        false
    }

    fn worker(self: Arc<Self>) {
        CURRENT.with(|c| *c.borrow_mut() = Some(Arc::downgrade(&self)));
        if let Some(h) = &self.cfg.on_start {
            (h.0)();
        }
        let mut st = self.lock();
        if st.starting > 0 {
            // Spawned for queued work ([`queued_locked`]): no longer counted as waiting.
            st.starting -= 1;
            st.idle -= 1;
        }
        let mut spun = false;
        // Leaving with jobs queued: a sleeping thread is woken to take this one's place.
        let mut hand_over = false;
        loop {
            if let Some(job) = self.next_locked(&mut st) {
                drop(st);
                if catch_unwind(AssertUnwindSafe(job)).is_err() {
                    self.panicked.fetch_add(1, Ordering::Relaxed);
                }
                self.completed.fetch_add(1, Ordering::Relaxed);
                spun = false;
                st = self.lock();
                // More threads than the allowance: one started for a thread that was blocked
                // and is no longer. It leaves now, not after `keep_alive`. (Threads above
                // `max_threads` exist only while the allowance was higher, so it is at most
                // `max_threads` plus the blocked ones: those that stay are enough.)
                if st.threads > self.allowance(&st) {
                    hand_over =
                        (!st.queue.is_empty() || !st.resumes.is_empty()) && st.idle > st.starting;
                    break;
                }
                continue;
            }
            if st.closed {
                break;
            }
            // Before sleeping, look for work a little longer without the lock (one thread at a
            // time): under load the next job usually comes within microseconds, and taking it
            // here saves the producer's wake-up and this thread's sleep.
            if !spun && self.worth_spinning() && self.start_spinning() {
                drop(st);
                let t0 = Instant::now();
                let mut n = 0u32;
                let mut found = true;
                while self.queued.load(Ordering::SeqCst) == 0 {
                    thread::yield_now();
                    n = n.wrapping_add(1);
                    if n % 8 == 0 && t0.elapsed() >= SPIN {
                        found = false;
                        break;
                    }
                }
                self.spin_pays.store(found, Ordering::Relaxed);
                // Stop counting as a spinner before looking at the queue (see `queued_locked`).
                self.spinning.fetch_sub(1, Ordering::SeqCst);
                spun = true;
                st = self.lock();
                continue;
            }
            st.idle += 1;
            let (guard, res) = self
                .cv
                .wait_timeout(st, self.cfg.keep_alive)
                .unwrap_or_else(|p| p.into_inner());
            st = guard;
            st.idle -= 1;
            spun = false;
            if res.timed_out()
                && st.queue.is_empty()
                && st.resumes.is_empty()
                && st.threads > self.cfg.min_threads
                && !st.closed
            {
                break;
            }
        }
        st.threads -= 1;
        drop(st);
        if hand_over {
            self.cv.notify_one();
        }
        CURRENT.with(|c| *c.borrow_mut() = None);
    }

    /// Current counters.
    pub fn stats(&self) -> PoolStats {
        let st = self.lock();
        PoolStats {
            threads: st.threads,
            idle: st.idle,
            queued: st.queue.len(),
            resumes: st.resumes.len(),
            max_queued: st.max_queued,
            completed: self.completed.load(Ordering::Relaxed),
            panicked: self.panicked.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            blocked: st.blocked,
            compensated: st.compensated,
            blocked_at_ceiling: st.blocked_at_ceiling,
            warnings: st.watch.warnings,
            watched: st.watched,
        }
    }

    /// The pool's name ([`PoolConfig::name`]).
    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    /// Whether the calling thread is one of this pool's threads.
    pub fn is_current(&self) -> bool {
        CURRENT.with(|c| {
            c.borrow()
                .as_ref()
                .is_some_and(|w| std::ptr::eq(w.as_ptr(), self))
        })
    }

    /// Stops accepting work; threads finish the queued jobs and exit.
    pub fn shutdown(&self) {
        self.lock().closed = true;
        self.cv.notify_all();
    }

    /// Waits for every thread to exit. Call after [`shutdown`](Self::shutdown).
    ///
    /// Called from one of the pool's own threads (a job that shuts the pool down and joins
    /// it), it waits for the other threads and not for the calling one, which cannot wait for
    /// itself: that thread exits on its own once its job returns. Its handle is kept, so a
    /// later `join` from outside the pool waits for it too.
    pub fn join(&self) {
        let me = thread::current().id();
        let handles = std::mem::take(&mut self.lock().handles);
        let mut own = None;
        for h in handles {
            if h.thread().id() == me {
                own = Some(h);
            } else {
                let _ = h.join();
            }
        }
        if let Some(h) = own {
            self.lock().handles.push(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use super::*;

    fn cfg(min: usize, max: usize, cap: usize) -> PoolConfig {
        PoolConfig {
            min_threads: min,
            max_threads: max,
            queue_capacity: cap,
            keep_alive: Duration::from_millis(100),
            max_blocked_threads: max,
            on_start: None,
            name: "test".to_owned(),
        }
    }

    #[test]
    fn on_start_runs_once_per_thread() {
        let started = Arc::new(AtomicUsize::new(0));
        let s = started.clone();
        let mut c = cfg(2, 2, 16);
        c.on_start = Some(ThreadHook(Arc::new(move || {
            s.fetch_add(1, Ordering::SeqCst);
        })));
        let pool = Pool::new(c);
        let done = Arc::new(AtomicUsize::new(0));
        for _ in 0..8 {
            let d = done.clone();
            pool.try_execute(Box::new(move || {
                d.fetch_add(1, Ordering::SeqCst);
            }))
            .ok()
            .unwrap();
        }
        wait_until(|| done.load(Ordering::SeqCst) == 8);
        assert_eq!(started.load(Ordering::SeqCst), 2);
        pool.shutdown();
        pool.join();
    }

    fn wait_until(mut c: impl FnMut() -> bool) {
        let t = Instant::now();
        while !c() {
            assert!(t.elapsed() < Duration::from_secs(10), "timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_job_that_shuts_down_and_joins_its_own_pool_does_not_join_itself() {
        // Two threads: the job's join waits for the other one and skips its own.
        let p = Pool::new(cfg(2, 2, 16));
        let joined = Arc::new(AtomicBool::new(false));
        let (p2, j) = (p.clone(), joined.clone());
        p.try_execute(Box::new(move || {
            p2.shutdown();
            p2.join();
            j.store(true, Ordering::SeqCst);
        }))
        .unwrap();
        wait_until(|| p.stats().completed == 1);
        assert!(joined.load(Ordering::SeqCst));
        assert_eq!(p.stats().panicked, 0);
        // The test thread's join waits for the job's thread too, which exits now.
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            p.join();
            let _ = tx.send(p.stats().threads);
        });
        let threads = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("join from outside the pool returns");
        assert_eq!(threads, 0);
    }

    #[test]
    fn runs_all_jobs() {
        let p = Pool::new(cfg(0, 4, 1000));
        let n = Arc::new(AtomicUsize::new(0));
        for _ in 0..500 {
            let n = n.clone();
            p.try_execute(Box::new(move || {
                n.fetch_add(1, Ordering::SeqCst);
            }))
            .unwrap();
        }
        // `completed` is bumped after the job returns, so wait on it, not on the job's own effect.
        wait_until(|| p.stats().completed == 500);
        assert_eq!(n.load(Ordering::SeqCst), 500);
        p.shutdown();
        p.join();
    }

    #[test]
    fn grows_to_max_for_blocking_jobs_then_shrinks() {
        let p = Pool::new(cfg(0, 6, 100));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        for _ in 0..6 {
            let g = gate.clone();
            p.try_execute(Box::new(move || {
                let (m, cv) = &*g;
                let _open = cv.wait_while(m.lock().unwrap(), |o| !*o).unwrap();
            }))
            .unwrap();
        }
        // All six block at once, so six threads must exist (not fewer).
        wait_until(|| p.stats().threads == 6);
        // A seventh job cannot get a thread beyond the max; it waits.
        p.try_execute(Box::new(|| {})).unwrap();
        assert_eq!(p.stats().threads, 6);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        wait_until(|| p.stats().completed == 7);
        // Idle threads retire after keep_alive down to min_threads (0).
        wait_until(|| p.stats().threads == 0);
        p.shutdown();
        p.join();
    }

    #[test]
    fn min_threads_survive_idle() {
        let p = Pool::new(cfg(2, 4, 10));
        thread::sleep(Duration::from_millis(350));
        assert_eq!(p.stats().threads, 2);
        p.shutdown();
        p.join();
        assert_eq!(p.stats().threads, 0);
    }

    #[test]
    fn rejects_when_queue_full_and_after_shutdown() {
        let p = Pool::new(cfg(0, 1, 2));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let g = gate.clone();
        p.try_execute(Box::new(move || {
            let (m, cv) = &*g;
            let _open = cv.wait_while(m.lock().unwrap(), |o| !*o).unwrap();
        }))
        .unwrap();
        wait_until(|| p.stats().queued == 0 && p.stats().threads == 1);
        p.try_execute(Box::new(|| {})).unwrap();
        p.try_execute(Box::new(|| {})).unwrap();
        assert!(
            p.try_execute(Box::new(|| {})).is_err(),
            "queue of 2 is full"
        );
        assert_eq!(p.stats().rejected, 1);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        wait_until(|| p.stats().completed == 3);
        p.shutdown();
        assert!(p.try_execute(Box::new(|| {})).is_err());
        p.join();
    }

    #[test]
    fn panicking_job_does_not_kill_the_worker() {
        let p = Pool::new(cfg(1, 1, 10));
        p.try_execute(Box::new(|| panic!("boom"))).unwrap();
        let ok = Arc::new(AtomicUsize::new(0));
        let o = ok.clone();
        p.try_execute(Box::new(move || {
            o.store(1, Ordering::SeqCst);
        }))
        .unwrap();
        wait_until(|| ok.load(Ordering::SeqCst) == 1);
        assert_eq!(p.stats().panicked, 1);
        assert_eq!(p.stats().threads, 1);
        p.shutdown();
        p.join();
    }

    #[test]
    fn a_batch_is_queued_at_once_and_what_does_not_fit_comes_back() {
        let p = Pool::new(cfg(0, 2, 4));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let done = Arc::new(AtomicUsize::new(0));
        let mut jobs: Vec<Job> = (0..6)
            .map(|i| -> Job {
                let (g, d) = (gate.clone(), done.clone());
                Box::new(move || {
                    let (m, cv) = &*g;
                    drop(cv.wait_while(m.lock().unwrap(), |o| !*o).unwrap());
                    d.fetch_add(i, Ordering::SeqCst);
                })
            })
            .collect();
        p.try_execute_batch(&mut jobs);
        // A queue of 4: the last 2 come back, unrun.
        assert_eq!(jobs.len(), 2);
        assert_eq!(p.stats().rejected, 2);
        // Two threads were started for the 4 (the maximum).
        wait_until(|| p.stats().threads == 2);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        wait_until(|| p.stats().completed == 4);
        assert_eq!(done.load(Ordering::SeqCst), 1 + 2 + 3);
        // The refused ones still run when given back to a pool with room.
        p.try_execute_batch(&mut jobs);
        assert!(jobs.is_empty());
        wait_until(|| p.stats().completed == 6);
        p.shutdown();
        let mut late: Vec<Job> = vec![Box::new(|| {})];
        p.try_execute_batch(&mut late);
        assert_eq!(late.len(), 1, "refused after shutdown");
        p.join();
    }

    /// A job that holds the pool's one thread until the gate opens.
    fn gate_job(gate: &Arc<(Mutex<bool>, Condvar)>) -> Job {
        let g = gate.clone();
        Box::new(move || {
            let (m, cv) = &*g;
            drop(cv.wait_while(m.lock().unwrap(), |o| !*o).unwrap());
        })
    }

    fn open(gate: &Arc<(Mutex<bool>, Condvar)>) {
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }

    /// A full queue refuses new work but not resumed work, which runs first; resumed work
    /// counts against the room left for new work.
    #[test]
    fn resumed_work_is_never_refused_and_runs_first() {
        let p = Pool::new(cfg(0, 1, 2));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        p.try_execute(gate_job(&gate)).unwrap();
        wait_until(|| p.stats().queued == 0 && p.stats().threads == 1);
        let order = Arc::new(Mutex::new(Vec::new()));
        let push = |tag: &'static str| -> Job {
            let o = order.clone();
            Box::new(move || o.lock().unwrap().push(tag))
        };
        p.try_execute(push("new1")).unwrap();
        p.try_execute(push("new2")).unwrap();
        assert!(p.try_execute(push("new3")).is_err(), "queue of 2 is full");
        for _ in 0..3 {
            p.resume(push("resumed")).ok().unwrap();
        }
        let s = p.stats();
        assert_eq!(
            (s.queued, s.resumes, s.max_queued, s.rejected),
            (2, 3, 5, 1)
        );
        open(&gate);
        wait_until(|| p.stats().completed == 6);
        assert_eq!(
            *order.lock().unwrap(),
            ["resumed", "resumed", "resumed", "new1", "new2"]
        );
        // Resumed work waiting leaves less room for new work.
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        p.try_execute(gate_job(&gate)).unwrap();
        wait_until(|| p.stats().queued == 0 && p.stats().completed == 6);
        wait_until(|| p.stats().idle == 0);
        p.resume(Box::new(|| {})).ok().unwrap();
        p.try_execute(Box::new(|| {})).unwrap();
        assert!(p.try_execute(Box::new(|| {})).is_err());
        open(&gate);
        wait_until(|| p.stats().completed == 9);
        p.shutdown();
        assert!(p.resume(Box::new(|| {})).is_err(), "refused after shutdown");
        p.join();
    }

    /// Runs `job` on `p` with a handle to `p`, and gives back what it returns (5 s at most).
    fn on_pool<R: Send + 'static>(
        p: &Arc<Pool>,
        job: impl FnOnce(&Arc<Pool>) -> R + Send + 'static,
    ) -> R {
        let (tx, rx) = std::sync::mpsc::channel();
        let q = p.clone();
        p.try_execute(Box::new(move || {
            let _ = tx.send(job(&q));
        }))
        .unwrap();
        rx.recv_timeout(Duration::from_secs(5)).expect("job ran")
    }

    /// A sub-task that sends 4, and the receiver its waiter waits on.
    fn sub_task(p: &Arc<Pool>) -> std::sync::mpsc::Receiver<i32> {
        let (tx, rx) = std::sync::mpsc::channel();
        p.try_execute(Box::new(move || {
            let _ = tx.send(4);
        }))
        .unwrap();
        rx
    }

    /// The pool's only thread waits (in `blocking`) for a task of the same pool: a thread is
    /// started for it, whether it was queued before the wait began or during it.
    #[test]
    fn a_task_waiting_for_the_same_pool_gets_a_thread() {
        let p = Pool::new(cfg(0, 1, 16));
        let got = on_pool(&p, |p| {
            let rx = sub_task(p);
            blocking(|| rx.recv_timeout(Duration::from_secs(5)))
        });
        assert_eq!(got, Ok(4));
        let s = p.stats();
        assert_eq!((s.compensated, s.blocked, s.blocked_at_ceiling), (1, 0, 0));
        // The sub-task queued while its waiter is blocked already.
        let got = on_pool(&p, |p| {
            blocking(|| {
                let rx = sub_task(p);
                rx.recv_timeout(Duration::from_secs(5))
            })
        });
        assert_eq!(got, Ok(4));
        p.shutdown();
        p.join();
    }

    #[test]
    fn nested_blocking_counts_once_and_only_on_a_pool_thread() {
        assert!(!on_pool_thread());
        assert_eq!(blocking(|| 7), 7, "off a pool thread it just runs");
        let p = Pool::new(cfg(0, 2, 16));
        assert!(!p.is_current());
        let other = Pool::new(cfg(0, 1, 16));
        let o = other.clone();
        let (on, mine, theirs, outer, inner, after) = on_pool(&p, move |p| {
            let (outer, inner) = blocking(|| (p.stats().blocked, blocking(|| p.stats().blocked)));
            (
                on_pool_thread(),
                p.is_current(),
                o.is_current(),
                outer,
                inner,
                p.stats().blocked,
            )
        });
        assert!(on && mine && !theirs);
        assert_eq!((outer, inner, after), (1, 1, 0));
        assert_eq!(p.stats().blocked, 0);
        for q in [p, other] {
            q.shutdown();
            q.join();
        }
    }

    /// A panic inside `blocking` ends the blocked state: the pool's count and the thread's
    /// depth (the next outermost call on that thread counts again).
    #[test]
    fn a_panic_in_blocking_restores_the_count() {
        let p = Pool::new(cfg(1, 1, 16));
        p.try_execute(Box::new(|| blocking(|| panic!("boom"))))
            .unwrap();
        wait_until(|| p.stats().completed == 1);
        let s = p.stats();
        assert_eq!((s.panicked, s.blocked), (1, 0));
        // The same (only) thread: a fresh outermost call counts again.
        assert_eq!(on_pool(&p, |p| blocking(|| p.stats().blocked)), 1);
        assert_eq!(p.stats().blocked, 0);
        p.shutdown();
        p.join();
    }

    /// With `max_blocked_threads = 0` nothing stands in for a blocked thread: the work it
    /// waits for is counted as held up by that limit, and runs once the wait gives up.
    #[test]
    fn no_stand_in_past_max_blocked_threads() {
        let mut c = cfg(0, 1, 16);
        c.max_blocked_threads = 0;
        let p = Pool::new(c);
        let got = on_pool(&p, |p| {
            let rx = sub_task(p);
            blocking(|| rx.recv_timeout(Duration::from_millis(200)))
        });
        assert!(got.is_err(), "no thread for the sub-task");
        let s = p.stats();
        assert_eq!(s.compensated, 0);
        assert!(s.blocked_at_ceiling >= 1);
        wait_until(|| p.stats().completed == 2);
        assert_eq!(p.stats().threads, 1);
        p.shutdown();
        p.join();
    }

    /// The thread started for a blocked one leaves once the wait is over, on the next job a
    /// thread finishes, not after `keep_alive`.
    #[test]
    fn the_extra_thread_leaves_without_waiting_for_keep_alive() {
        let mut c = cfg(0, 1, 16);
        c.keep_alive = Duration::from_secs(60);
        let p = Pool::new(c);
        let got = on_pool(&p, |p| {
            let rx = sub_task(p);
            let r = blocking(|| rx.recv_timeout(Duration::from_secs(5)));
            // Two threads while this one is blocked.
            (r, p.stats().threads)
        });
        assert_eq!(got, (Ok(4), 2));
        wait_until(|| p.stats().completed == 2);
        wait_until(|| p.stats().threads == 1);
        // More work runs on the one left.
        assert_eq!(on_pool(&p, |_| 5), 5);
        assert_eq!(p.stats().threads, 1);
        p.shutdown();
        p.join();
    }

    /// Many producers, few threads, jobs that finish at once: every job runs (no wake-up is
    /// lost between the spinning thread, the sleeping ones and the producers that skip a
    /// wake-up because a thread is spinning or busy).
    #[test]
    fn no_job_is_stranded_under_many_producers() {
        for max in [1, 2, 4] {
            let p = Pool::new(cfg(0, max, 1 << 20));
            let done = Arc::new(AtomicUsize::new(0));
            let producers: Vec<_> = (0..4)
                .map(|k| {
                    let (p, done) = (p.clone(), done.clone());
                    thread::spawn(move || {
                        for i in 0..20_000 {
                            let d = done.clone();
                            if (i + k) % 7 == 0 {
                                let mut b: Vec<Job> = (0..3)
                                    .map(|_| -> Job {
                                        let d = d.clone();
                                        Box::new(move || {
                                            d.fetch_add(1, Ordering::Relaxed);
                                        })
                                    })
                                    .collect();
                                p.try_execute_batch(&mut b);
                                assert!(b.is_empty());
                            } else {
                                p.try_execute(Box::new(move || {
                                    d.fetch_add(1, Ordering::Relaxed);
                                }))
                                .ok()
                                .unwrap();
                            }
                            if i % 1000 == 0 {
                                // Let the pool drain and its threads go to sleep now and then.
                                thread::sleep(Duration::from_micros(300));
                            }
                        }
                    })
                })
                .collect();
            let mut want = 0;
            for k in 0..4 {
                want += (0..20_000)
                    .map(|i| if (i + k) % 7 == 0 { 3 } else { 1 })
                    .sum::<usize>();
            }
            for h in producers {
                h.join().unwrap();
            }
            wait_until(|| done.load(Ordering::SeqCst) == want);
            assert!(p.stats().threads <= max);
            p.shutdown();
            p.join();
        }
    }
}
