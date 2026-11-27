//! Sampling the pools' backlogs: by the pressure watcher, one thread for the whole process,
//! `akio-pool-watch`, that runs only while some pool is under pressure (unless
//! [`set_auto_sample`] switches it off), and by hand ([`sample`], [`Pool::sample`]).
//!
//! A sample ([`observe`]) looks at a pool under its lock: it logs each rise of the backlog to
//! 50, 75, 90 and 100% of the capacity ([`LEVELS`]) since the sample before, the watcher's or
//! one by hand, which share the level reached and the rate limits ([`PoolWatch`]).
//!
//! No timer runs while every pool is calm, nor ever while automatic sampling is off. With it
//! on (the default), a submitter that finds the backlog (new and resumed jobs waiting) past half of
//! `queue_capacity`, or is refused for a full queue, or finds work held up by the stand-in limit
//! (`blocked_at_ceiling`), marks its pool watched under the pool's lock and, once that lock is
//! dropped, puts the pool in the watch list, starting the thread if none runs. The thread
//! samples the listed pools every [`sample_interval`] (500 ms unless [`set_sample_interval`]
//! says otherwise), and lets a pool go, with a summary, once its backlog has stayed under 40%
//! ([`LEVELS`]`[0]` less [`HYSTERESIS`]) for [`CALM`] with no refusal and no stand-in limit hit,
//! as samples at least that far apart found it (the summary is rate limited per pool as the
//! level lines are, [`LOG_EVERY`]). With the list empty the thread exits; the next
//! pool to pass the line starts another one. Switched off, the watcher lets every pool go at its
//! next pass, without a summary, and exits.
//!
//! The same thread watches the command queues of the I/O threads ([`DepthWatch`]), under the
//! same switch: a loop that takes a batch of more than [`DepthWatch::LINE`] commands reports it,
//! and the watcher logs each rise past 1024, 16384 and 131072 commands ([`DEPTH_LEVELS`]) until
//! no batch has passed the line for [`CALM`].
//!
//! Locks: a submitter takes the pool's lock, drops it, then takes [`WATCH`]; it never holds
//! both. Only the watcher holds both, and always [`WATCH`] first, so they cannot deadlock. The
//! watcher never drops a pool (the last `Arc` it upgraded) while holding [`WATCH`]: a pool's
//! drop drops its queued jobs, whose destructors may submit to a pool and register it. The
//! registry of pools ([`REGISTRY`]) is never held with another lock, and no pool is dropped
//! under it, for the same reason. The watcher waits out the interval on [`WATCH_CV`], with
//! [`WATCH`], so that [`set_sample_interval`] can wake it.

use std::{
    mem, ptr,
    sync::{
        Condvar, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use std::sync::Arc;

use super::{Ordering, Pool, PoolStats, State};

/// [`set_auto_sample`]'s switch, on unless switched off.
static AUTO_SAMPLE: AtomicBool = AtomicBool::new(true);

/// Switches automatic sampling on or off for every pool of the process, and for the I/O
/// threads' command lists ([`DepthWatch`]). On by default.
///
/// On, a pool whose backlog passes half of `queue_capacity` (or that refuses work, or hits the
/// stand-in limit) is watched by the pressure watcher thread, which samples it every
/// [`sample_interval`], logs its pressure and lets it go once it has stayed calm for 2 s (see
/// the [crate docs](crate)); no thread runs while every pool is calm. It takes effect at once:
/// switched off, the watcher lets every pool go at its next look, without a summary, and exits,
/// and a submission past the line reads the switch and nothing more; switched back on, a pool is
/// watched at its next submission past the line.
///
/// [`sample`] and [`Pool::sample`] sample by hand either way.
pub fn set_auto_sample(on: bool) {
    AUTO_SAMPLE.store(on, Ordering::Relaxed);
}

/// Whether automatic sampling is on (see [`set_auto_sample`]).
pub fn auto_sample() -> bool {
    AUTO_SAMPLE.load(Ordering::Relaxed)
}

/// How often the watcher samples the pools in its list unless [`set_sample_interval`] says
/// otherwise: often enough that a backlog left deep is logged within half a second, seldom
/// enough that watching it costs a process under pressure two wake-ups a second. A sample is
/// about time: the backlog is a level held over time, and the logs are rate limited in time.
pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

/// [`set_sample_interval`]'s, in nanoseconds.
static SAMPLE_INTERVAL: AtomicU64 = AtomicU64::new(DEFAULT_SAMPLE_INTERVAL.as_nanos() as u64);

/// Sets how often the pressure watcher samples the pools (and command lists) in its list, at
/// once: a watcher running is woken and starts the new interval from now. Zero sets
/// [`DEFAULT_SAMPLE_INTERVAL`] again. A longer interval costs a process under pressure fewer
/// wake-ups and logs later; a pool is let go no sooner than two samples apart, even when that
/// is longer than the 2 s of calm it otherwise takes. Samples taken by hand ([`sample`],
/// [`Pool::sample`]) follow no interval.
pub fn set_sample_interval(d: Duration) {
    let d = if d.is_zero() {
        DEFAULT_SAMPLE_INTERVAL
    } else {
        d
    };
    let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
    SAMPLE_INTERVAL.store(nanos, Ordering::Relaxed);
    let mut w = watch_lock();
    if w.running {
        w.interval_set = true;
        drop(w);
        WATCH_CV.notify_all();
    }
}

/// How often the pressure watcher samples the pools in its list (see [`set_sample_interval`]).
pub fn sample_interval() -> Duration {
    Duration::from_nanos(SAMPLE_INTERVAL.load(Ordering::Relaxed))
}

/// The levels, in percent of `queue_capacity`, whose rise is logged (warn, error at 100%).
const LEVELS: [usize; 4] = [50, 75, 90, 100];

/// A level is left only once the backlog falls this many points below it, so a backlog
/// hovering at a line does not log each crossing.
const HYSTERESIS: usize = 10;

/// How long a pool (or command list) must stay calm, from the first sample that found it calm
/// to a later one, before it leaves the list.
const CALM: Duration = Duration::from_secs(2);

/// Whether something calm since `since` (the first calm sample) has been calm long enough at
/// the sample taken `now`.
fn calm_enough(since: Option<Instant>, now: Instant) -> bool {
    since.is_some_and(|t| now.duration_since(t) >= CALM)
}

/// At most one log line per pool and level (and for the stand-in limit, and for the summary
/// of an episode) this often; the next one says how many were held back meanwhile.
const LOG_EVERY: Duration = Duration::from_secs(10);

/// The samples' memory of one pool, kept in the pool's state (under its lock) across episodes,
/// so a pool going in and out of pressure is still rate limited, and shared by the watcher and
/// the samples taken by hand, so a rise is counted and logged once whoever sees it.
#[derive(Default)]
pub(crate) struct PoolWatch {
    /// [`PoolStats::warnings`](crate::PoolStats::warnings).
    pub(crate) warnings: [u64; 4],
    /// 0, or `i + 1` while at [`LEVELS`]`[i]`.
    level: usize,
    /// `refused_full` and `blocked_at_ceiling` as the last sample saw them.
    refused_seen: u64,
    ceiling_seen: u64,
    /// When each level was last logged.
    last_log: [Option<Instant>; 4],
    /// Rises of each level not logged since it was last logged.
    held: [u64; 4],
    /// When the stand-in limit was last logged.
    ceiling_last_log: Option<Instant>,
    /// Samples with the stand-in limit hit not logged since it was last logged.
    ceiling_held: u64,
    /// When the summary of an episode ("pressure over") was last logged: a pool flapping
    /// around the line would otherwise log one about every second.
    over_last_log: Option<Instant>,
    /// Summaries not logged since the last one.
    over_held: u64,
}

/// Whether a line for something last logged at `last` may be logged `now`
/// ([`LOG_EVERY`]); if so, records `now`. Otherwise counts it in `held`.
fn may_log(last: &mut Option<Instant>, held: &mut u64, now: Instant) -> Option<u64> {
    if last.is_some_and(|t| now.duration_since(t) < LOG_EVERY) {
        *held += 1;
        return None;
    }
    *last = Some(now);
    Some(mem::take(held))
}

/// The tail of a rate-limited line: how many like it were held back since the last one.
fn held_back(n: u64) -> String {
    if n == 0 {
        String::new()
    } else {
        format!(" ({n} more since the last such line)")
    }
}

/// What the watcher watches: a pool, or a queue whose owner reports its depth.
enum Target {
    Pool(Weak<Pool>),
    Depth(Weak<DepthWatch>),
}

impl Target {
    /// Whether this is the object at `p`.
    fn is(&self, p: *const ()) -> bool {
        match self {
            Target::Pool(w) => ptr::eq(w.as_ptr().cast(), p),
            Target::Depth(w) => ptr::eq(w.as_ptr().cast(), p),
        }
    }

    fn addr(&self) -> *const () {
        match self {
            Target::Pool(w) => w.as_ptr().cast(),
            Target::Depth(w) => w.as_ptr().cast(),
        }
    }

    /// Clears its `watched` flag (the thread could not be started).
    fn unmark(&self) {
        match self {
            Target::Pool(w) => {
                if let Some(p) = w.upgrade() {
                    p.lock().watched = false;
                }
            }
            Target::Depth(w) => {
                if let Some(d) = w.upgrade() {
                    d.lock().watched = false;
                }
            }
        }
    }
}

/// The watch list and whether a thread serves it.
struct Watch {
    /// Pools and queues under pressure, each at most once.
    pools: Vec<Target>,
    /// A watcher thread serves the list: set by the registration that starts it, cleared by
    /// the thread itself, under this lock, when it finds the list empty and exits.
    running: bool,
    /// The last thread started.
    handle: Option<JoinHandle<()>>,
    /// [`set_sample_interval`] was called while a thread served the list: it starts the new
    /// interval from then. Cleared by the thread.
    interval_set: bool,
}

static WATCH: Mutex<Watch> = Mutex::new(Watch {
    pools: Vec::new(),
    running: false,
    handle: None,
    interval_set: false,
});

/// What the watcher waits on between two passes, with [`WATCH`]: [`set_sample_interval`]
/// wakes it.
static WATCH_CV: Condvar = Condvar::new();

/// The watcher thread could not be started once already (reported once).
static SPAWN_FAILED: AtomicBool = AtomicBool::new(false);

fn watch_lock() -> MutexGuard<'static, Watch> {
    WATCH.lock().unwrap_or_else(|p| p.into_inner())
}

/// Whether the pressure watcher thread runs (or is exiting). `#[doc(hidden)]`: for tests.
#[doc(hidden)]
pub fn watcher_running() -> bool {
    let w = watch_lock();
    w.running || w.handle.as_ref().is_some_and(|h| !h.is_finished())
}

/// Whether `pool` is in the pressure watcher's list. `#[doc(hidden)]`: for tests.
#[doc(hidden)]
pub fn watch_list_has(pool: &Pool) -> bool {
    let p: *const Pool = pool;
    watch_lock().pools.iter().any(|t| t.is(p.cast()))
}

impl Pool {
    /// Puts the pool in the watch list (a submitter marked it watched, then dropped the pool's
    /// lock) and starts the watcher thread if none runs.
    pub(crate) fn register_watch(&self) {
        register(Target::Pool(self.me.clone()));
    }
}

/// Puts `t` in the watch list (its owner marked it watched, then dropped its lock) and starts
/// the watcher thread if none runs.
fn register(t: Target) {
    let mut w = watch_lock();
    if !w.pools.iter().any(|q| q.is(t.addr())) {
        w.pools.push(t);
    }
    if w.running {
        return;
    }
    w.running = true;
    let spawned = thread::Builder::new()
        .name("akio-pool-watch".into())
        .spawn(watch_loop);
    match spawned {
        // The previous thread, if any, cleared `running` as its last step: its handle goes.
        Ok(h) => w.handle = Some(h),
        Err(e) => {
            // Nobody serves the list: empty it and unmark what it holds, so that the next
            // crossing of any of them registers it and tries again.
            w.running = false;
            let pools = mem::take(&mut w.pools);
            drop(w);
            if !SPAWN_FAILED.swap(true, Ordering::Relaxed) {
                akio_log::log_or_stderr(
                    akio_log::Level::Error,
                    "akio-pool",
                    format_args!(
                        "cannot start the pressure watcher thread ({e}): pools under pressure are not logged until it starts"
                    ),
                );
            }
            for t in pools {
                t.unmark();
            }
        }
    }
}

/// The pools created, for [`sample`], held weakly: a pool dropped is pruned at the next look,
/// or as pools are created ([`enroll`]). `live` is how many were alive at the last prune.
struct Registry {
    pools: Vec<Weak<Pool>>,
    live: usize,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    pools: Vec::new(),
    live: 0,
});

fn registry_lock() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|p| p.into_inner())
}

/// The next pool's [`Pool::id`].
pub(crate) fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Adds a pool just created to the registry, first pruning the dropped ones if they could be
/// half of it, so a process that creates pools and never samples them holds no more than
/// twice the live ones.
pub(crate) fn enroll(pool: &Weak<Pool>) {
    let mut r = registry_lock();
    if r.pools.len() >= 2 * r.live.max(64) {
        r.pools.retain(|p| p.strong_count() > 0);
        r.live = r.pools.len();
    }
    r.pools.push(pool.clone());
}

/// One pool, as [`sample`] found it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolSample {
    /// [`PoolConfig::name`](crate::PoolConfig::name).
    pub name: String,
    /// [`Pool::id`]: tells pools of the same name apart.
    pub id: u64,
    /// The `max_threads` the pool runs with.
    pub max_threads: usize,
    /// The `queue_capacity` the pool runs with: the backlog's levels are shares of it.
    pub queue_capacity: usize,
    /// The pool's counters, right after the sample ([`Pool::sample`]).
    pub stats: PoolStats,
}

/// Samples every pool of the process that is not dropped or shut down, the engine's logical
/// pool and the protocol crates' pools included, as [`Pool::sample`] does, and reports each, in
/// the order they were created.
///
/// It is for a process to call from its own status or metrics endpoint: each call is one
/// sample of every pool, so the warnings it counts and logs follow how often the endpoint is
/// asked. It works whether or not automatic sampling is on ([`set_auto_sample`]), and
/// does not disturb the watcher's timing.
pub fn sample() -> Vec<PoolSample> {
    let pools: Vec<Arc<Pool>> = {
        let mut r = registry_lock();
        let pools: Vec<Arc<Pool>> = r.pools.iter().filter_map(Weak::upgrade).collect();
        if pools.len() < r.pools.len() {
            r.pools.retain(|p| p.strong_count() > 0);
        }
        r.live = r.pools.len();
        pools
        // The pools are dropped, if this held the last `Arc`, after the lock.
    };
    pools
        .iter()
        .filter_map(|p| {
            let stats = p.sample_open()?;
            Some(PoolSample {
                name: p.cfg.name.clone(),
                id: p.id,
                max_threads: p.cfg.max_threads,
                queue_capacity: p.cfg.queue_capacity,
                stats,
            })
        })
        .collect()
}

impl Pool {
    /// Samples the pool once and reports its counters: logs (target `akio-pool`) and counts in
    /// [`PoolStats::warnings`] each rise of the backlog to 50, 75, 90 or 100% of
    /// `queue_capacity` since the sample before, by hand or by the watcher, as the watcher
    /// does. It does not hand the pool to the watcher, and works whether or not
    /// automatic sampling is on ([`set_auto_sample`]). [`sample`] samples every pool.
    pub fn sample(&self) -> PoolStats {
        self.sample_open().unwrap_or_else(|| self.stats())
    }

    /// [`sample`](Self::sample), `None` once the pool is shut down (nothing sampled).
    fn sample_open(&self) -> Option<PoolStats> {
        let look = {
            let mut st = self.lock();
            if st.closed {
                return None;
            }
            observe(self, &mut st, Instant::now())
        };
        log(&self.cfg.name, &look);
        Some(self.stats())
    }
}

/// The level a backlog of `n` reaches against `cap`: 0 under the first line, `i + 1` past
/// [`LEVELS`]`[i]` (50, 75 and 90% are passed when exceeded, 100% when the queue is full).
fn level_of(n: usize, cap: usize) -> usize {
    if n > 0 && n >= cap {
        return LEVELS.len();
    }
    (0..LEVELS.len() - 1)
        .rev()
        .find(|&i| n.saturating_mul(100) > LEVELS[i].saturating_mul(cap))
        .map_or(0, |i| i + 1)
}

/// Whether a backlog of `n` is under `pct`% of `cap`.
fn below(n: usize, cap: usize, pct: usize) -> bool {
    n == 0 || n.saturating_mul(100) < pct.saturating_mul(cap)
}

/// Calm: under the first line less the hysteresis (40%).
fn calm(n: usize, cap: usize) -> bool {
    below(n, cap, LEVELS[0] - HYSTERESIS)
}

/// What a sample found, to be logged once the pool's lock is dropped ([`log`]).
pub(crate) struct Look {
    /// The backlog sampled and the capacity.
    backlog: usize,
    capacity: usize,
    /// A rise to this level, and the rises held back before it.
    rise: Option<(usize, u64)>,
    /// The stand-in limit was hit: threads blocked, `blocked_at_ceiling`, lines held back.
    ceiling: Option<(usize, u64, u64)>,
}

/// One sample of a pool (under its lock), the watcher's or one taken by hand: counts a warning
/// at the highest level the backlog has risen to since the sample before (a refusal or a hit of
/// the stand-in limit since then counts as 100%: a burst the backlog may no longer show), and
/// lets a level go once the backlog has fallen [`HYSTERESIS`] points under it.
pub(crate) fn observe(p: &Pool, st: &mut State, now: Instant) -> Look {
    let capacity = p.cfg.queue_capacity;
    let backlog = st.queue.len() + st.resumes.len();
    let (refused_full, at_ceiling, blocked) = (st.refused_full, st.blocked_at_ceiling, st.blocked);
    let w = &mut st.watch;
    let refused = mem::replace(&mut w.refused_seen, refused_full) != refused_full;
    let ceiling = mem::replace(&mut w.ceiling_seen, at_ceiling) != at_ceiling;
    let reach = if refused || ceiling {
        LEVELS.len()
    } else {
        level_of(backlog, capacity)
    };
    let mut look = Look {
        backlog,
        capacity,
        rise: None,
        ceiling: None,
    };
    if reach > w.level {
        w.level = reach;
        let i = reach - 1;
        w.warnings[i] += 1;
        look.rise = may_log(&mut w.last_log[i], &mut w.held[i], now).map(|h| (i, h));
    } else {
        while w.level > 0 && below(backlog, capacity, LEVELS[w.level - 1] - HYSTERESIS) {
            w.level -= 1;
        }
    }
    if ceiling {
        look.ceiling = may_log(&mut w.ceiling_last_log, &mut w.ceiling_held, now)
            .map(|h| (blocked, at_ceiling, h));
    }
    look
}

/// Logs what a sample of pool `name` found.
pub(crate) fn log(name: &str, look: &Look) {
    let cap = look.capacity;
    if let Some((i, held)) = look.rise {
        let (level, backlog, more) = (LEVELS[i], look.backlog, held_back(held));
        if level == 100 {
            akio_log::error!(target: "akio-pool", pool:% = name, level = level, backlog = backlog, capacity = cap, held_back = held;
                "pool {name}: queue full ({backlog}/{cap} jobs waiting), new work is refused{more}");
        } else {
            akio_log::warn!(target: "akio-pool", pool:% = name, level = level, backlog = backlog, capacity = cap, held_back = held;
                "pool {name}: queue past {level}% ({backlog}/{cap} jobs waiting){more}");
        }
    }
    if let Some((blocked, total, held)) = look.ceiling {
        let more = held_back(held);
        akio_log::warn!(target: "akio-pool", pool:% = name, blocked = blocked, blocked_at_ceiling = total, held_back = held;
            "pool {name}: queued work waits for a thread while {blocked} threads are blocked in akio::blocking, past max_blocked_threads{more}");
    }
}

/// One pool's episode of pressure, as the watcher thread follows it.
struct Episode {
    pool: Weak<Pool>,
    /// Set on the first sample.
    started: bool,
    name: String,
    /// The first sample of the calm going on now, if it is calm.
    calm_since: Option<Instant>,
    start: Instant,
    /// The deepest backlog sampled, and the capacity.
    peak: usize,
    capacity: usize,
    /// `refused_full` when the episode began (as the sample before it saw it), for the
    /// summary.
    refused0: u64,
    /// `refused_full` and `blocked_at_ceiling` at this episode's last sample: a change since
    /// is not calm, whoever else sampled the pool meanwhile.
    refused_last: u64,
    ceiling_last: u64,
    /// `compensated` when the episode was first sampled.
    compensated0: u64,
}

impl Episode {
    fn new(pool: Weak<Pool>) -> Episode {
        Episode {
            pool,
            started: false,
            name: String::new(),
            calm_since: None,
            start: Instant::now(),
            peak: 0,
            capacity: 0,
            refused0: 0,
            refused_last: 0,
            ceiling_last: 0,
            compensated0: 0,
        }
    }

    /// Samples the pool. False when it is gone or shut down, or automatic sampling is off (to
    /// be removed).
    fn sample(&mut self, now: Instant) -> bool {
        if !auto_sample() {
            return false;
        }
        let Some(p) = self.pool.upgrade() else {
            return false;
        };
        let mut st = p.lock();
        if st.closed {
            return false;
        }
        if !self.started {
            self.started = true;
            self.name = p.cfg.name.clone();
            self.start = now;
            self.capacity = p.cfg.queue_capacity;
            self.compensated0 = st.compensated;
            // What happened since the sample before this episode is this episode's: the
            // refusal that started it, say.
            self.refused0 = st.watch.refused_seen;
            self.refused_last = st.watch.refused_seen;
            self.ceiling_last = st.watch.ceiling_seen;
        }
        let look = observe(&p, &mut st, now);
        let quiet =
            st.refused_full == self.refused_last && st.blocked_at_ceiling == self.ceiling_last;
        self.refused_last = st.refused_full;
        self.ceiling_last = st.blocked_at_ceiling;
        self.peak = self.peak.max(look.backlog);
        self.calm_since = if quiet && calm(look.backlog, look.capacity) {
            self.calm_since.or(Some(now))
        } else {
            None
        };
        drop(st);
        log(&self.name, &look);
        true
    }

    /// The pool has been calm long enough, or is gone or shut down, or automatic sampling is
    /// off: takes it off the list if it still is calm (or gone, shut down, or sampling off),
    /// re-checked under both locks. True when it left.
    ///
    /// Why no registration is lost: `watched` is set by submitters and cleared here, both
    /// under the pool's lock. A submission that put the backlog past the line before this
    /// takes that lock saw `watched` set and did not register, but then the re-check below
    /// sees its backlog (or its refusal) and the pool stays. One that comes after sees
    /// `watched` clear, sets it and registers once it has the [`WATCH`] lock, which this holds
    /// until the pool is off the list: so it puts the pool back in after. And the thread exits
    /// only when it finds the list empty under [`WATCH`], where a registration that finds no
    /// thread running starts one.
    fn try_leave(&mut self) -> bool {
        // Upgraded before `WATCH` is taken and dropped after it is released (see the module
        // docs): `w` is declared after `p`, so it is dropped first.
        let p = self.pool.upgrade();
        let mut w = watch_lock();
        // Read under `WATCH`: a submitter registers only after reading it on, and then waits
        // for `WATCH` to put the pool back.
        let off = !auto_sample();
        // `Some((compensated so far, refused so far, summaries held back))` when it leaves calm
        // and its summary is due, `None` when it is gone or shut down, sampling is off, or the
        // summary is held back.
        let summary = match &p {
            None => None,
            Some(p) => {
                let mut st = p.lock();
                let backlog = st.queue.len() + st.resumes.len();
                let calm = st.refused_full == self.refused_last
                    && st.blocked_at_ceiling == self.ceiling_last
                    && calm(backlog, p.cfg.queue_capacity);
                if !st.closed && !off && !calm {
                    drop(st);
                    self.calm_since = None;
                    return false;
                }
                st.watched = false;
                if st.closed || off || !self.started {
                    None
                } else {
                    // Rate limited per pool, as the level lines are.
                    let (compensated, refused) = (st.compensated, st.refused_full);
                    let w = &mut st.watch;
                    may_log(&mut w.over_last_log, &mut w.over_held, Instant::now())
                        .map(|held| (compensated, refused, held))
                }
            }
        };
        let me: *const Pool = self.pool.as_ptr();
        w.pools.retain(|t| !t.is(me.cast()));
        drop(w);
        if let Some((compensated, refused, held)) = summary {
            let compensated = compensated.saturating_sub(self.compensated0);
            let refused = refused.saturating_sub(self.refused0);
            let name = &self.name;
            let secs = self.start.elapsed().as_secs_f64();
            let (peak, cap) = (self.peak, self.capacity);
            let more = held_back(held);
            akio_log::info!(target: "akio-pool", pool:% = name, seconds = secs, peak = peak, capacity = cap, refused = refused, compensated = compensated, held_back = held;
                "pool {name}: pressure over after {secs:.1} s (peak {peak}/{cap} jobs waiting, {refused} refused, {compensated} threads started for blocked ones){more}");
        }
        true
    }
}

/// The watcher thread: samples the listed pools every [`sample_interval`] while the list is
/// not empty.
fn watch_loop() {
    let mut eps: Vec<Episode> = Vec::new();
    let mut deps: Vec<DepthEpisode> = Vec::new();
    loop {
        // Pools and queues registered since the last pass.
        {
            let w = watch_lock();
            for t in &w.pools {
                match t {
                    Target::Pool(p) => {
                        if !eps.iter().any(|e| e.pool.ptr_eq(p)) {
                            eps.push(Episode::new(p.clone()));
                        }
                    }
                    Target::Depth(d) => {
                        if !deps.iter().any(|e| e.queue.ptr_eq(d)) {
                            deps.push(DepthEpisode::new(d.clone()));
                        }
                    }
                }
            }
        }
        let now = Instant::now();
        eps.retain_mut(|e| {
            let alive = e.sample(now);
            !((!alive || calm_enough(e.calm_since, now)) && e.try_leave())
        });
        deps.retain_mut(|e| {
            let alive = e.sample(now);
            !((!alive || calm_enough(e.calm_since, now)) && e.try_leave())
        });
        let mut w = watch_lock();
        if w.pools.is_empty() {
            w.running = false;
            w.interval_set = false;
            return;
        }
        // The next pass one interval from now, or from when the interval is set again (`None`:
        // an interval past what an `Instant` holds, waited out as long as the wait goes).
        let from_now = || Instant::now().checked_add(sample_interval());
        let mut next = from_now();
        loop {
            if mem::take(&mut w.interval_set) {
                next = from_now();
            }
            let left = next.map_or(Duration::MAX, |t| {
                t.saturating_duration_since(Instant::now())
            });
            if left.is_zero() {
                break;
            }
            w = WATCH_CV
                .wait_timeout(w, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }
}

/// The depths, in commands, whose rise past is logged for a [`DepthWatch`] (warn, error past
/// the last).
const DEPTH_LEVELS: [usize; 3] = [DepthWatch::LINE, 16_384, 131_072];

/// The level a batch of `n` commands reaches: 0 at or under the line, `i + 1` past
/// [`DEPTH_LEVELS`]`[i]`.
fn depth_level_of(n: usize) -> usize {
    DEPTH_LEVELS
        .iter()
        .rposition(|&l| n > l)
        .map_or(0, |i| i + 1)
}

/// A queue that is not bounded by a capacity but whose owner reports the batches it takes
/// past [`LINE`](Self::LINE): an I/O thread's command list, which other threads post to and
/// the loop takes whole. The first report past the line puts it in the pressure watcher's
/// list; the watcher logs each rise past 1024, 16384 and 131072 commands and lets it go once
/// no batch has passed the line for 2 s. `#[doc(hidden)]`: backend-facing.
#[doc(hidden)]
pub struct DepthWatch {
    me: Weak<DepthWatch>,
    name: String,
    state: Mutex<DepthState>,
}

#[derive(Default)]
struct DepthState {
    /// In the watch list, or being put there; set by [`DepthWatch::report`], cleared by the
    /// watcher, under this lock (the same argument as a pool's, [`Episode::try_leave`]).
    watched: bool,
    /// The deepest batch reported since the last sample (0: none past the line).
    deepest: usize,
    /// Rises per level ([`DEPTH_LEVELS`]).
    warnings: [u64; 3],
    last_log: [Option<Instant>; 3],
    held: [u64; 3],
    /// The summary line of an episode, rate limited as the pool's is.
    over_last_log: Option<Instant>,
    over_held: u64,
}

impl std::fmt::Debug for DepthWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DepthWatch")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl DepthWatch {
    /// Batches deeper than this are reported.
    pub const LINE: usize = 1024;

    /// A queue named `name` in the logs (target `akio-pool`).
    pub fn new(name: String) -> Arc<DepthWatch> {
        Arc::new_cyclic(|me| DepthWatch {
            me: me.clone(),
            name,
            state: Mutex::new(DepthState::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, DepthState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The owner took a batch of `depth` commands, more than [`LINE`](Self::LINE) (smaller ones
    /// are ignored): recorded for the watcher's next sample, and the queue registered with it
    /// if it is not watched yet.
    /// Ignored while automatic sampling is off ([`set_auto_sample`]).
    #[cold]
    pub fn report(&self, depth: usize) {
        if depth <= Self::LINE || !auto_sample() {
            return;
        }
        let register_it = {
            let mut st = self.lock();
            st.deepest = st.deepest.max(depth);
            !mem::replace(&mut st.watched, true)
        };
        if register_it {
            register(Target::Depth(self.me.clone()));
        }
    }

    /// Times a batch rose past 1024, 16384 and 131072 commands (one count per rise, at the
    /// highest level passed).
    pub fn warnings(&self) -> [u64; 3] {
        self.lock().warnings
    }

    /// Whether the pressure watcher watches the queue now.
    pub fn watched(&self) -> bool {
        self.lock().watched
    }
}

/// One queue's episode of deep batches, as the watcher thread follows it.
struct DepthEpisode {
    queue: Weak<DepthWatch>,
    started: bool,
    name: String,
    level: usize,
    /// The first sample of the calm going on now, if it is calm.
    calm_since: Option<Instant>,
    start: Instant,
    peak: usize,
}

impl DepthEpisode {
    fn new(queue: Weak<DepthWatch>) -> DepthEpisode {
        DepthEpisode {
            queue,
            started: false,
            name: String::new(),
            level: 0,
            calm_since: None,
            start: Instant::now(),
            peak: 0,
        }
    }

    /// Samples the queue. False when it is gone, or automatic sampling is off.
    fn sample(&mut self, now: Instant) -> bool {
        if !auto_sample() {
            return false;
        }
        let Some(q) = self.queue.upgrade() else {
            return false;
        };
        let mut st = q.lock();
        let deepest = mem::take(&mut st.deepest);
        if !self.started {
            self.started = true;
            self.name = q.name.clone();
            self.start = now;
        }
        self.peak = self.peak.max(deepest);
        let reach = depth_level_of(deepest);
        let mut rise = None;
        if reach > self.level {
            self.level = reach;
            let i = reach - 1;
            st.warnings[i] += 1;
            let st = &mut *st;
            rise = may_log(&mut st.last_log[i], &mut st.held[i], now).map(|h| (i, h));
        } else {
            // A level is left 10% under it.
            while self.level > 0 && deepest * 10 < DEPTH_LEVELS[self.level - 1] * 9 {
                self.level -= 1;
            }
        }
        self.calm_since = if deepest == 0 {
            self.calm_since.or(Some(now))
        } else {
            None
        };
        drop(st);
        if let Some((i, held)) = rise {
            let name = &self.name;
            let (level, more) = (DEPTH_LEVELS[i], held_back(held));
            if i + 1 == DEPTH_LEVELS.len() {
                akio_log::error!(target: "akio-pool", queue:% = name, level = level, depth = deepest, held_back = held;
                    "{name}: {deepest} commands queued at once, past {level}{more}");
            } else {
                akio_log::warn!(target: "akio-pool", queue:% = name, level = level, depth = deepest, held_back = held;
                    "{name}: {deepest} commands queued at once, past {level}{more}");
            }
        }
        true
    }

    /// No batch past the line for long enough, or the queue is gone, or automatic sampling is
    /// off: takes it off the list if still so, re-checked under both locks
    /// ([`Episode::try_leave`] argues why no report is lost). True when it left.
    fn try_leave(&mut self) -> bool {
        let q = self.queue.upgrade();
        let mut w = watch_lock();
        let off = !auto_sample();
        let mut summary = None;
        if let Some(q) = &q {
            let mut st = q.lock();
            if st.deepest != 0 && !off {
                drop(st);
                self.calm_since = None;
                return false;
            }
            st.watched = false;
            st.deepest = 0;
            if self.started && !off {
                let st = &mut *st;
                summary = may_log(&mut st.over_last_log, &mut st.over_held, Instant::now());
            }
        }
        let me: *const DepthWatch = self.queue.as_ptr();
        w.pools.retain(|t| !t.is(me.cast()));
        drop(w);
        if let Some(held) = summary {
            let name = &self.name;
            let secs = self.start.elapsed().as_secs_f64();
            let (peak, more) = (self.peak, held_back(held));
            akio_log::info!(target: "akio-pool", queue:% = name, seconds = secs, peak = peak, held_back = held;
                "{name}: command batches back under {} after {secs:.1} s (deepest {peak}){more}", DepthWatch::LINE);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_and_hysteresis_lines() {
        assert_eq!(level_of(0, 100), 0);
        assert_eq!(level_of(50, 100), 0, "50% is reached when passed");
        assert_eq!(level_of(51, 100), 1);
        assert_eq!(level_of(76, 100), 2);
        assert_eq!(level_of(91, 100), 3);
        assert_eq!(level_of(99, 100), 3);
        assert_eq!(level_of(100, 100), 4);
        assert_eq!(
            level_of(250, 100),
            4,
            "resumed work may go past the capacity"
        );
        assert_eq!(level_of(0, 0), 0);
        assert_eq!(level_of(1, 0), 4);
        assert!(calm(39, 100) && !calm(40, 100));
        assert!(calm(0, 0) && !calm(1, 0));
        assert!(below(79, 100, 80) && !below(80, 100, 80));
    }

    #[test]
    fn depth_levels() {
        assert_eq!(depth_level_of(0), 0);
        assert_eq!(depth_level_of(1024), 0);
        assert_eq!(depth_level_of(1025), 1);
        assert_eq!(depth_level_of(16_385), 2);
        assert_eq!(depth_level_of(1 << 20), 3);
    }

    #[test]
    fn rate_limit_counts_what_it_holds_back() {
        let (mut last, mut held) = (None, 0);
        let t0 = Instant::now();
        assert_eq!(may_log(&mut last, &mut held, t0), Some(0));
        assert_eq!(
            may_log(&mut last, &mut held, t0 + Duration::from_secs(1)),
            None
        );
        assert_eq!(
            may_log(&mut last, &mut held, t0 + Duration::from_secs(2)),
            None
        );
        assert_eq!(may_log(&mut last, &mut held, t0 + LOG_EVERY), Some(2));
        assert_eq!(held, 0);
    }

    /// A pool flapping around the line leaves the list about once a second: its "pressure
    /// over" summary is logged at most once per [`LOG_EVERY`], and the next one counts those
    /// held back.
    #[test]
    fn pressure_over_summary_is_rate_limited() {
        // Never switched off in this binary: the two tests that need it on may overlap.
        set_auto_sample(true);
        let p = Pool::new(crate::PoolConfig {
            min_threads: 0,
            max_threads: 1,
            queue_capacity: 4,
            name: "flapping".into(),
            ..Default::default()
        });
        let leave = || {
            p.lock().watched = true;
            let mut e = Episode::new(Arc::downgrade(&p));
            assert!(e.sample(Instant::now()));
            assert!(e.try_leave(), "a calm pool leaves");
            assert!(!p.lock().watched);
        };
        let state = || {
            let st = p.lock();
            (st.watch.over_last_log, st.watch.over_held)
        };
        leave();
        let (first, held) = state();
        assert!(first.is_some(), "the first summary is logged");
        assert_eq!(held, 0);
        leave();
        leave();
        assert_eq!(state(), (first, 2), "two summaries held back within 10 s");
        // Ten seconds later the next one is logged, saying how many were held back.
        let back = Instant::now()
            .checked_sub(LOG_EVERY)
            .expect("an instant 10 s ago");
        p.lock().watch.over_last_log = Some(back);
        leave();
        let (last, held) = state();
        assert!(last.is_some_and(|t| t > back));
        assert_eq!(held, 0, "the held-back count went out with the summary");
        // A shut-down pool leaves with no summary.
        p.shutdown();
        let mut e = Episode::new(Arc::downgrade(&p));
        e.started = true;
        p.lock().watched = true;
        assert!(e.try_leave());
        assert_eq!(state(), (last, 0));
        p.join();
    }

    /// The same for a queue of deep command batches.
    #[test]
    fn depth_summary_is_rate_limited() {
        set_auto_sample(true);
        let q = DepthWatch::new("flapping-loop".into());
        let leave = || {
            q.lock().watched = true;
            let mut e = DepthEpisode::new(Arc::downgrade(&q));
            assert!(e.sample(Instant::now()));
            assert!(e.try_leave());
        };
        leave();
        leave();
        leave();
        let (first, held) = {
            let st = q.lock();
            (st.over_last_log, st.over_held)
        };
        assert!(first.is_some());
        assert_eq!(held, 2);
        q.lock().over_last_log = Instant::now().checked_sub(LOG_EVERY);
        leave();
        assert_eq!(q.lock().over_held, 0);
    }
}
