#![forbid(unsafe_code)]
//! The logical (blocking-work) thread pool: a bounded queue served by threads that are spawned on
//! demand up to a maximum and retire after sitting idle.
//!
//! I/O threads never block; code that must block (databases, files, slow RPC) is handed to this
//! pool and its result is brought back to the connection's I/O thread by `akio-core`.
//!
//! Guide: [Blocking work: the logical pool](https://lesismal.github.io/akio/en/concepts/blocking.html)
//! (中文: [阻塞任务：逻辑线程池](https://lesismal.github.io/akio/zh-CN/concepts/blocking.html)).
#![warn(clippy::unwrap_used)]

use std::{
    collections::VecDeque,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

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

/// A unit of work.
pub type Job = Box<dyn FnOnce() + Send + 'static>;

/// Pool sizing and overload behaviour.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PoolConfig {
    /// Threads kept alive even when idle.
    pub min_threads: usize,
    /// Upper bound on threads; a new one is started when work is queued and none is idle.
    pub max_threads: usize,
    /// Jobs that may wait in the queue; beyond it [`Pool::try_execute`] rejects.
    pub queue_capacity: usize,
    /// How long a thread above `min_threads` may sit idle before it exits.
    pub keep_alive: Duration,
    /// Run by each pool thread when it starts, before any job (the engine's NUMA placement
    /// pins the thread here, ADR-088). `#[doc(hidden)]`: engine-facing.
    #[doc(hidden)]
    pub on_start: Option<ThreadHook>,
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
        PoolConfig {
            min_threads: 0,
            max_threads: (cores * 8).max(8),
            queue_capacity: 65_536,
            keep_alive: Duration::from_secs(30),
            on_start: None,
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
    /// Jobs waiting in the queue.
    pub queued: usize,
    /// Jobs that ran to completion or panicked.
    pub completed: u64,
    /// Jobs that panicked (also counted in `completed`).
    pub panicked: u64,
    /// Jobs refused because the queue was full or the pool was closed.
    pub rejected: u64,
}

struct State {
    queue: VecDeque<Job>,
    threads: usize,
    /// Threads waiting on the condition variable, plus those just started ([`starting`]).
    idle: usize,
    /// Threads spawned that have not yet looked at the queue (counted in `idle` meanwhile).
    starting: usize,
    closed: bool,
    handles: Vec<JoinHandle<()>>,
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
                threads: 0,
                idle: 0,
                starting: 0,
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

    /// Queues `job`, starting a thread if all are busy and the maximum allows. Never blocks.
    pub fn try_execute(&self, job: Job) -> Result<(), Rejected> {
        let mut st = self.lock();
        if st.closed || st.queue.len() >= self.cfg.queue_capacity {
            drop(st);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected(job));
        }
        st.queue.push_back(job);
        let wake = self.queued_locked(&mut st, 1);
        drop(st);
        for _ in 0..wake {
            self.cv.notify_one();
        }
        Ok(())
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
            self.cfg.queue_capacity.saturating_sub(st.queue.len())
        };
        let n = room.min(jobs.len());
        st.queue.extend(jobs.drain(..n));
        let wake = if n == 0 {
            0
        } else {
            self.queued_locked(&mut st, n)
        };
        drop(st);
        if !jobs.is_empty() {
            self.rejected
                .fetch_add(jobs.len() as u64, Ordering::Relaxed);
        }
        for _ in 0..wake {
            self.cv.notify_one();
        }
    }

    /// After `added` jobs were queued (under the lock): starts threads if every live one is
    /// already spoken for and the maximum allows, and returns how many sleeping threads to wake
    /// for the new jobs: one each, except those a spinning thread not already claimed by the
    /// jobs queued before will take, and those a thread started here will. (Counting the whole
    /// queue instead woke again, for every new job, the sleepers already woken for the earlier
    /// ones: at 2k requests/s, one more context switch per request, 12% more CPU.) A thread
    /// busy with a job looks at the queue before it sleeps, so it is never woken.
    fn queued_locked(&self, st: &mut State, added: usize) -> usize {
        let len = st.queue.len();
        self.queued.store(len, Ordering::SeqCst);
        // Read under the lock: a spinner stops counting itself before it takes the lock to look
        // at the queue, so either it is counted here or it sees these jobs.
        let spinning = self.spinning.load(Ordering::SeqCst);
        let mut started = 0;
        while st.idle + spinning < len && st.threads < self.cfg.max_threads {
            let before = st.threads;
            self.spawn_locked(st);
            if st.threads == before {
                break;
            }
            // A new thread looks at the queue when it starts: count it as taking a job.
            st.idle += 1;
            st.starting += 1;
            started += 1;
        }
        let free_spinners = spinning.saturating_sub(len - added);
        added
            .saturating_sub(free_spinners + started)
            .min(st.idle - st.starting)
    }

    fn spawn_locked(&self, st: &mut State) {
        let Some(pool) = self.me.upgrade() else {
            return;
        };
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
        loop {
            if let Some(job) = st.queue.pop_front() {
                self.queued.store(st.queue.len(), Ordering::SeqCst);
                drop(st);
                if catch_unwind(AssertUnwindSafe(job)).is_err() {
                    self.panicked.fetch_add(1, Ordering::Relaxed);
                }
                self.completed.fetch_add(1, Ordering::Relaxed);
                spun = false;
                st = self.lock();
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
                && st.threads > self.cfg.min_threads
                && !st.closed
            {
                break;
            }
        }
        st.threads -= 1;
    }

    /// Current counters.
    pub fn stats(&self) -> PoolStats {
        let st = self.lock();
        PoolStats {
            threads: st.threads,
            idle: st.idle,
            queued: st.queue.len(),
            completed: self.completed.load(Ordering::Relaxed),
            panicked: self.panicked.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }

    /// Stops accepting work; threads finish the queued jobs and exit.
    pub fn shutdown(&self) {
        self.lock().closed = true;
        self.cv.notify_all();
    }

    /// Waits for every thread to exit. Call after [`shutdown`](Self::shutdown).
    pub fn join(&self) {
        let handles = std::mem::take(&mut self.lock().handles);
        for h in handles {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    fn cfg(min: usize, max: usize, cap: usize) -> PoolConfig {
        PoolConfig {
            min_threads: min,
            max_threads: max,
            queue_capacity: cap,
            keep_alive: Duration::from_millis(100),
            on_start: None,
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
