//! The worker pool of rounds scheduling (ADR-102): a fixed set of threads, each with its own
//! queue of connections whose round is due. Pollers spread connections over the queues in turn;
//! a worker that runs dry steals from the others, spins a little, and parks. A poster wakes a
//! parked worker when the queue it pushed to belongs to one, or when no worker is spinning (so
//! some idle worker comes to steal the job instead of it waiting behind a busy one).

use std::{
    cell::Cell,
    collections::VecDeque,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{JoinHandle, Thread},
};

use akio_core::{Config, LoopMeta, LoopStats};

use super::conn::RConn;

/// Empty passes over every queue before a worker parks.
const SPIN: usize = 64;

static NEXT_POOL_UID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    /// `(pool uid, worker index)` of the worker running on this thread (uid 0: not a worker).
    static CURRENT: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

struct Shard {
    q: Mutex<VecDeque<Arc<RConn>>>,
    /// `q.len()`, readable without the lock (emptiness checks of stealers and parkers).
    len: AtomicUsize,
    /// The worker is parked (or about to): a poster that swaps it to false unparks it.
    parked: AtomicBool,
    thread: OnceLock<Thread>,
}

impl Shard {
    fn push(&self, c: Arc<RConn>) {
        let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
        q.push_back(c);
        self.len.store(q.len(), Ordering::SeqCst);
    }

    fn pop(&self) -> Option<Arc<RConn>> {
        if self.len.load(Ordering::SeqCst) == 0 {
            return None;
        }
        let mut q = self.q.lock().unwrap_or_else(|p| p.into_inner());
        let c = q.pop_front();
        self.len.store(q.len(), Ordering::SeqCst);
        c
    }

    fn wake(&self) -> bool {
        if self.parked.swap(false, Ordering::SeqCst) {
            if let Some(t) = self.thread.get() {
                t.unpark();
            }
            return true;
        }
        false
    }
}

/// The pool. Built by the group, started with [`Workers::start`].
pub(crate) struct Workers {
    uid: usize,
    shards: Box<[Shard]>,
    rr: AtomicUsize,
    spinning: AtomicUsize,
    sleeping: AtomicUsize,
    stop: AtomicBool,
    handles: Mutex<Vec<JoinHandle<()>>>,
    stats: Vec<Arc<LoopStats>>,
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
            stop: AtomicBool::new(false),
            handles: Mutex::new(Vec::new()),
            stats,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.shards.len()
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
        for s in self.shards.iter() {
            s.wake();
        }
        let hs = std::mem::take(&mut *self.handles.lock().unwrap_or_else(|p| p.into_inner()));
        for h in hs {
            let _ = h.join();
        }
        for st in &self.stats {
            st.set_running(false);
        }
    }

    /// Queues `c` for a round: on the calling worker's own queue, else on the next in turn.
    pub(crate) fn submit(&self, c: Arc<RConn>) {
        let (uid, me) = CURRENT.with(Cell::get);
        let own = uid == self.uid;
        let i = if own {
            me
        } else {
            self.rr.fetch_add(1, Ordering::Relaxed) % self.shards.len()
        };
        let shard = &self.shards[i];
        shard.push(c);
        if !own && shard.wake() {
            return;
        }
        // The queue's owner is busy (or is us): get an idle worker to steal, unless one is
        // already spinning and will find it.
        if self.spinning.load(Ordering::SeqCst) == 0 && self.sleeping.load(Ordering::SeqCst) > 0 {
            self.wake_one(i);
        }
    }

    /// Wakes one parked worker, starting the search after `from`.
    fn wake_one(&self, from: usize) {
        let n = self.shards.len();
        for k in 1..=n {
            if self.shards[(from + k) % n].wake() {
                return;
            }
        }
    }

    fn find(&self, me: usize) -> Option<Arc<RConn>> {
        if let Some(c) = self.shards[me].pop() {
            return Some(c);
        }
        let n = self.shards.len();
        for k in 1..n {
            if let Some(c) = self.shards[(me + k) % n].pop() {
                return Some(c);
            }
        }
        None
    }

    fn any_queued(&self) -> bool {
        self.shards
            .iter()
            .any(|s| s.len.load(Ordering::SeqCst) != 0)
    }

    fn run(self: Arc<Self>, me: usize, cfg: &Arc<Config>) {
        CURRENT.with(|c| c.set((self.uid, me)));
        let shard = &self.shards[me];
        let _ = shard.thread.set(std::thread::current());
        let mut ctx = WorkerCtx {
            scratch: vec![0; cfg.telemetry.live().read_buffer()],
            stats: self.stats[me].clone(),
            workers: self.clone(),
        };
        loop {
            if let Some(c) = self.find(me) {
                ctx.stats.iterations.add_local(1);
                c.run_round(&mut ctx);
                continue;
            }
            // Spin a little: under load, more work arrives within microseconds, and a park /
            // unpark pair costs more than that.
            self.spinning.fetch_add(1, Ordering::SeqCst);
            let mut found = None;
            for _ in 0..SPIN {
                if let Some(c) = self.find(me) {
                    found = Some(c);
                    break;
                }
                std::hint::spin_loop();
            }
            self.spinning.fetch_sub(1, Ordering::SeqCst);
            if let Some(c) = found {
                ctx.stats.iterations.add_local(1);
                c.run_round(&mut ctx);
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
            while shard.parked.load(Ordering::SeqCst) {
                std::thread::park();
            }
            self.sleeping.fetch_sub(1, Ordering::SeqCst);
        }
        CURRENT.with(|c| c.set((0, 0)));
    }
}
