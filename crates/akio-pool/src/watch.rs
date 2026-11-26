//! The pressure watcher: one thread for the whole process, `akio-pool-watch`, that runs only
//! while some pool is under pressure.
//!
//! No timer runs while every pool is calm. A submitter that finds the backlog (new and resumed
//! jobs waiting) past half of `queue_capacity`, or is refused for a full queue, or finds work
//! held up by the stand-in limit (`blocked_at_ceiling`), marks its pool watched under the pool's
//! lock and, once that lock is dropped, puts the pool in the watch list, starting the thread if
//! none runs. The thread samples the listed pools every [`SAMPLE`]: it logs each rise of the
//! backlog to 50, 75, 90 and 100% of the capacity ([`LEVELS`]), and lets a pool go, with a
//! summary, once its backlog has stayed under 40% ([`LEVELS`]`[0]` less [`HYSTERESIS`]) for
//! [`CALM_SAMPLES`] samples in a row with no refusal and no stand-in limit hit. With the list
//! empty the thread exits; the next pool to pass the line starts another one.
//!
//! Locks: a submitter takes the pool's lock, drops it, then takes [`WATCH`]; it never holds
//! both. Only the watcher holds both, and always [`WATCH`] first, so they cannot deadlock. The
//! watcher never drops a pool (the last `Arc` it upgraded) while holding [`WATCH`]: a pool's
//! drop drops its queued jobs, whose destructors may submit to a pool and register it.

use std::{
    mem, ptr,
    sync::{Mutex, MutexGuard, Weak, atomic::AtomicBool},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use super::{Ordering, Pool};

/// How often the watcher samples the pools in its list. A sample is about time: the backlog is
/// a level held over time, and the logs are rate limited in time.
const SAMPLE: Duration = Duration::from_millis(100);

/// The levels, in percent of `queue_capacity`, whose rise is logged (warn, error at 100%).
const LEVELS: [usize; 4] = [50, 75, 90, 100];

/// A level is left only once the backlog falls this many points below it, so a backlog
/// hovering at a line does not log each crossing.
const HYSTERESIS: usize = 10;

/// Samples in a row (1 s) a pool must stay calm before it leaves the list.
const CALM_SAMPLES: u32 = 10;

/// At most one log line per pool and level (and for the stand-in limit) this often; the next
/// one says how many were held back meanwhile.
const LOG_EVERY: Duration = Duration::from_secs(10);

/// The watcher's memory of one pool, kept in the pool's state (under its lock) across episodes,
/// so a pool going in and out of pressure is still rate limited.
#[derive(Default)]
pub(crate) struct PoolWatch {
    /// [`PoolStats::warnings`](crate::PoolStats::warnings).
    pub(crate) warnings: [u64; 4],
    /// When each level was last logged.
    last_log: [Option<Instant>; 4],
    /// Rises of each level not logged since it was last logged.
    held: [u64; 4],
    /// When the stand-in limit was last logged.
    ceiling_last_log: Option<Instant>,
    /// Samples with the stand-in limit hit not logged since it was last logged.
    ceiling_held: u64,
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

/// The watch list and whether a thread serves it.
struct Watch {
    /// Pools under pressure, each at most once.
    pools: Vec<Weak<Pool>>,
    /// A watcher thread serves the list: set by the registration that starts it, cleared by
    /// the thread itself, under this lock, when it finds the list empty and exits.
    running: bool,
    /// The last thread started.
    handle: Option<JoinHandle<()>>,
}

static WATCH: Mutex<Watch> = Mutex::new(Watch {
    pools: Vec::new(),
    running: false,
    handle: None,
});

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
    watch_lock().pools.iter().any(|p| ptr::eq(p.as_ptr(), pool))
}

impl Pool {
    /// Puts the pool in the watch list (a submitter marked it watched, then dropped the pool's
    /// lock) and starts the watcher thread if none runs.
    pub(crate) fn register_watch(&self) {
        let mut w = watch_lock();
        if !w.pools.iter().any(|p| ptr::eq(p.as_ptr(), self)) {
            w.pools.push(self.me.clone());
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
                // Nobody serves the list: empty it and unmark its pools, so that the next
                // submission past the line of any of them registers it and tries again.
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
                for p in pools {
                    if let Some(p) = p.upgrade() {
                        p.lock().watched = false;
                    }
                }
            }
        }
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

/// One pool's episode of pressure, as the watcher thread follows it.
struct Episode {
    pool: Weak<Pool>,
    /// Set on the first sample.
    started: bool,
    name: String,
    /// 0, or `i + 1` while at [`LEVELS`]`[i]`.
    level: usize,
    /// Calm samples in a row.
    calm: u32,
    start: Instant,
    /// The deepest backlog sampled, and the capacity.
    peak: usize,
    capacity: usize,
    /// Refusals for a full queue seen in this episode.
    refusals: u64,
    /// `compensated` when the episode was first sampled.
    compensated0: u64,
}

/// What a sample found that is to be logged, once the pool's lock is dropped.
struct Logs {
    /// A rise to this level, the backlog then, and the rises held back before it.
    rise: Option<(usize, usize, u64)>,
    /// The stand-in limit was hit: threads blocked, `blocked_at_ceiling`, lines held back.
    ceiling: Option<(usize, u64, u64)>,
}

impl Episode {
    fn new(pool: Weak<Pool>) -> Episode {
        Episode {
            pool,
            started: false,
            name: String::new(),
            level: 0,
            calm: 0,
            start: Instant::now(),
            peak: 0,
            capacity: 0,
            refusals: 0,
            compensated0: 0,
        }
    }

    /// Samples the pool. False when it is gone or shut down (to be removed).
    fn sample(&mut self, now: Instant) -> bool {
        let Some(p) = self.pool.upgrade() else {
            return false;
        };
        let mut st = p.lock();
        if st.closed {
            return false;
        }
        let cap = p.cfg.queue_capacity;
        let backlog = st.queue.len() + st.resumes.len();
        let refused = mem::take(&mut st.refused_since);
        let ceiling = mem::take(&mut st.ceiling_since);
        if !self.started {
            self.started = true;
            self.name = p.cfg.name.clone();
            self.start = now;
            self.capacity = cap;
            self.compensated0 = st.compensated;
        }
        self.refusals += refused;
        self.peak = self.peak.max(backlog);
        // A refusal or the stand-in limit hit between two samples is a burst the backlog may
        // no longer show: it counts as 100%.
        let reach = if refused > 0 || ceiling > 0 {
            LEVELS.len()
        } else {
            level_of(backlog, cap)
        };
        let mut logs = Logs {
            rise: None,
            ceiling: None,
        };
        if reach > self.level {
            self.level = reach;
            let i = reach - 1;
            let w = &mut st.watch;
            w.warnings[i] += 1;
            logs.rise = may_log(&mut w.last_log[i], &mut w.held[i], now).map(|h| (i, backlog, h));
        } else {
            while self.level > 0 && below(backlog, cap, LEVELS[self.level - 1] - HYSTERESIS) {
                self.level -= 1;
            }
        }
        if ceiling > 0 {
            let (blocked, total) = (st.blocked, st.blocked_at_ceiling);
            let w = &mut st.watch;
            logs.ceiling = may_log(&mut w.ceiling_last_log, &mut w.ceiling_held, now)
                .map(|h| (blocked, total, h));
        }
        self.calm = if refused == 0 && ceiling == 0 && calm(backlog, cap) {
            self.calm + 1
        } else {
            0
        };
        drop(st);
        self.log(&logs, cap);
        true
    }

    fn log(&self, logs: &Logs, cap: usize) {
        let name = &self.name;
        if let Some((i, backlog, held)) = logs.rise {
            let level = LEVELS[i];
            let more = held_back(held);
            if level == 100 {
                akio_log::error!(target: "akio-pool", pool:% = name, level = level, backlog = backlog, capacity = cap, held_back = held;
                    "pool {name}: queue full ({backlog}/{cap} jobs waiting), new work is refused{more}");
            } else {
                akio_log::warn!(target: "akio-pool", pool:% = name, level = level, backlog = backlog, capacity = cap, held_back = held;
                    "pool {name}: queue past {level}% ({backlog}/{cap} jobs waiting){more}");
            }
        }
        if let Some((blocked, total, held)) = logs.ceiling {
            let more = held_back(held);
            akio_log::warn!(target: "akio-pool", pool:% = name, blocked = blocked, blocked_at_ceiling = total, held_back = held;
                "pool {name}: queued work waits for a thread while {blocked} threads are blocked in akio::blocking, past max_blocked_threads{more}");
        }
    }

    /// The pool has been calm long enough, or is gone or shut down: takes it off the list if
    /// it still is calm, re-checked under both locks. True when it left.
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
        // `Some(compensated so far)` when it leaves calm, `None` when it is gone or shut down.
        let summary = match &p {
            None => None,
            Some(p) => {
                let mut st = p.lock();
                let backlog = st.queue.len() + st.resumes.len();
                let calm = st.refused_since == 0
                    && st.ceiling_since == 0
                    && calm(backlog, p.cfg.queue_capacity);
                if !st.closed && !calm {
                    drop(st);
                    self.calm = 0;
                    return false;
                }
                st.watched = false;
                (!st.closed).then_some(st.compensated)
            }
        };
        w.pools.retain(|q| !q.ptr_eq(&self.pool));
        drop(w);
        if let (true, Some(compensated)) = (self.started, summary) {
            let compensated = compensated.saturating_sub(self.compensated0);
            let name = &self.name;
            let secs = self.start.elapsed().as_secs_f64();
            let (peak, cap, refused) = (self.peak, self.capacity, self.refusals);
            akio_log::info!(target: "akio-pool", pool:% = name, seconds = secs, peak = peak, capacity = cap, refused = refused, compensated = compensated;
                "pool {name}: pressure over after {secs:.1} s (peak {peak}/{cap} jobs waiting, {refused} refused, {compensated} threads started for blocked ones)");
        }
        true
    }
}

/// The watcher thread: samples the listed pools every [`SAMPLE`] while the list is not empty.
fn watch_loop() {
    let mut eps: Vec<Episode> = Vec::new();
    loop {
        // Pools registered since the last pass.
        {
            let w = watch_lock();
            for p in &w.pools {
                if !eps.iter().any(|e| e.pool.ptr_eq(p)) {
                    eps.push(Episode::new(p.clone()));
                }
            }
        }
        let now = Instant::now();
        eps.retain_mut(|e| {
            let alive = e.sample(now);
            !((!alive || e.calm >= CALM_SAMPLES) && e.try_leave())
        });
        {
            let mut w = watch_lock();
            if w.pools.is_empty() {
                w.running = false;
                return;
            }
        }
        thread::sleep(SAMPLE);
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
}
