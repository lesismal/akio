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
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

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
    idle: usize,
    closed: bool,
    handles: Vec<JoinHandle<()>>,
}

/// The pool. Share it as an `Arc<Pool>`.
pub struct Pool {
    me: Weak<Pool>,
    cfg: PoolConfig,
    state: Mutex<State>,
    cv: Condvar,
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
                closed: false,
                handles: Vec::new(),
            }),
            cv: Condvar::new(),
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
        // Start a thread only if every live thread is already spoken for by queued work.
        if st.idle < st.queue.len() && st.threads < self.cfg.max_threads {
            self.spawn_locked(&mut st);
        }
        drop(st);
        self.cv.notify_one();
        Ok(())
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

    fn worker(self: Arc<Self>) {
        if let Some(h) = &self.cfg.on_start {
            (h.0)();
        }
        let mut st = self.lock();
        loop {
            if let Some(job) = st.queue.pop_front() {
                drop(st);
                if catch_unwind(AssertUnwindSafe(job)).is_err() {
                    self.panicked.fetch_add(1, Ordering::Relaxed);
                }
                self.completed.fetch_add(1, Ordering::Relaxed);
                st = self.lock();
                continue;
            }
            if st.closed {
                break;
            }
            st.idle += 1;
            let (guard, res) = self
                .cv
                .wait_timeout(st, self.cfg.keep_alive)
                .unwrap_or_else(|p| p.into_inner());
            st = guard;
            st.idle -= 1;
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
        let t = std::time::Instant::now();
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
}
