//! The engine-wide budget of queued output, `Config::max_pending_bytes` (ADR-172).
//!
//! Every I/O thread already keeps the bytes its connections have queued for sending in a gauge
//! (`LoopStats::queued_bytes`). A watcher thread, running only while a budget is set, sums those
//! gauges every millisecond or so (every 10 ms while the sum is under half the budget) and
//! raises a flag when the sum reaches the budget and lowers it at three quarters of it. Nothing
//! on the write path changes: the per-thread gauges are what it already updated.
//!
//! While the flag is up, a connection asked whether its reads are held
//! ([`ConnInner::read_held`](crate::ConnInner::read_held), which every backend asks after each
//! read and when it re-arms reading) answers yes and is *parked*: its id and loop are recorded,
//! once per episode. Lowering the flag wakes every parked connection, so its loop re-arms its
//! reads, as `hold_reads(false)` does. A connection that reads nothing is never parked and costs
//! nothing; one that reads pauses after its current read.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::{LoopLink, LoopStats};

/// How often the watcher sums the threads' queues while the sum is near the budget (at or past
/// half of it) or over it.
const NEAR: Duration = Duration::from_millis(1);
/// How often it sums them while the sum is under half the budget.
const FAR: Duration = Duration::from_millis(10);

/// The budget's state, shared by the engine's telemetry, its connections and the watcher.
#[repr(align(128))] // `over` is read on every read check: keep it off busy lines
pub(crate) struct Budget {
    /// The sum reached the budget and has not fallen to three quarters of it yet.
    over: AtomicBool,
    /// Episodes so far (raised as `over` goes up): a connection parked in this one is in
    /// `parked`, one parked in an earlier one is not.
    epoch: AtomicU64,
    /// The budget in bytes; 0: none.
    max: AtomicUsize,
    /// A watcher thread runs.
    watching: AtomicBool,
    /// Connections parked in this episode, to wake when it ends.
    parked: Mutex<HashMap<u64, Arc<dyn LoopLink>>>,
    /// The I/O threads' counters, whose `queued_bytes` gauges are summed.
    loops: Mutex<Vec<Weak<LoopStats>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Default for Budget {
    fn default() -> Budget {
        Budget {
            over: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            max: AtomicUsize::new(0),
            watching: AtomicBool::new(false),
            parked: Mutex::new(HashMap::new()),
            loops: Mutex::new(Vec::new()),
        }
    }
}

impl Budget {
    /// The budget in bytes, `None` when there is none.
    pub(crate) fn max(&self) -> Option<usize> {
        match self.max.load(Ordering::Relaxed) {
            0 => None,
            n => Some(n),
        }
    }

    /// Sets the budget and starts the watcher if one is set and none runs. `Some(0)` is none.
    pub(crate) fn set_max(this: &Arc<Budget>, n: Option<usize>) {
        let n = n.unwrap_or(0);
        this.max.store(n, Ordering::Relaxed);
        if n != 0 && !this.watching.swap(true, Ordering::AcqRel) {
            let b = this.clone();
            let spawned = std::thread::Builder::new()
                .name("akio-budget".into())
                .spawn(move || b.watch());
            if let Err(e) = spawned {
                this.watching.store(false, Ordering::Release);
                akio_log::warn!(target: "akio", error:% = e; "max_pending_bytes: no watcher thread, the budget is not enforced");
            }
        }
    }

    /// Whether reads are paused by the budget (one relaxed load: the common answer is no).
    #[inline]
    pub(crate) fn is_over(&self) -> bool {
        self.over.load(Ordering::Relaxed)
    }

    /// Connection `id` (of `link`, its epoch slot `slot`) is asked whether its reads are held
    /// while the budget is over: parks it, once per episode, and answers whether it is held.
    #[cold]
    pub(crate) fn park(
        &self,
        id: u64,
        slot: &AtomicU64,
        link: &Arc<dyn LoopLink>,
        stats: Option<&LoopStats>,
    ) -> bool {
        if slot.load(Ordering::Acquire) == self.epoch.load(Ordering::Acquire) {
            return true; // parked in this episode already
        }
        let mut parked = lock(&self.parked);
        // Under the lock the release takes too: once the flag is down, no one parks.
        if !self.over.load(Ordering::Relaxed) {
            return false;
        }
        slot.store(self.epoch.load(Ordering::Relaxed), Ordering::Release);
        parked.insert(id, link.clone());
        if let Some(s) = stats {
            s.budget_pauses.add(1);
        }
        true
    }

    /// Connection `id` closes: forgets it if it is parked in this episode.
    #[inline]
    pub(crate) fn forget(&self, id: u64, slot: &AtomicU64) {
        if self.is_over() && slot.load(Ordering::Acquire) == self.epoch.load(Ordering::Acquire) {
            lock(&self.parked).remove(&id);
        }
    }

    /// Adds an I/O thread's counters to the sum.
    pub(crate) fn add_loop(&self, stats: &Arc<LoopStats>) {
        let mut loops = lock(&self.loops);
        loops.retain(|w| w.strong_count() > 0);
        if !loops
            .iter()
            .any(|w| std::ptr::eq(w.as_ptr(), Arc::as_ptr(stats)))
        {
            loops.push(Arc::downgrade(stats));
        }
    }

    /// Takes exited I/O threads' counters out of the sum.
    pub(crate) fn remove_loops(&self, gone: &[Arc<LoopStats>]) {
        lock(&self.loops).retain(|w| {
            w.strong_count() > 0
                && !gone
                    .iter()
                    .any(|s| std::ptr::eq(w.as_ptr(), Arc::as_ptr(s)))
        });
    }

    /// The bytes queued across the engine's I/O threads.
    pub(crate) fn total(&self) -> usize {
        let mut sum = 0u64;
        lock(&self.loops).retain(|w| match w.upgrade() {
            Some(s) => {
                sum = sum.saturating_add(s.queued_bytes.get());
                true
            }
            None => false,
        });
        usize::try_from(sum).unwrap_or(usize::MAX)
    }

    fn hold(&self) {
        let _parked = lock(&self.parked);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.over.store(true, Ordering::Release);
    }

    fn release(&self) {
        let woken = {
            let mut parked = lock(&self.parked);
            self.over.store(false, Ordering::Release);
            std::mem::take(&mut *parked)
        };
        for (id, link) in woken {
            link.wake_conn(id);
        }
    }

    /// The watcher thread: runs while a budget is set and the telemetry lives.
    fn watch(self: Arc<Budget>) {
        loop {
            // Only this thread holds it: the engine and its telemetry are gone.
            if Arc::strong_count(&self) == 1 {
                self.release();
                self.watching.store(false, Ordering::Release);
                return;
            }
            let Some(max) = self.max() else {
                if self.is_over() {
                    self.release();
                }
                self.watching.store(false, Ordering::Release);
                // A budget set again meanwhile found the watcher still running: carry on.
                if self.max().is_some() && !self.watching.swap(true, Ordering::AcqRel) {
                    continue;
                }
                return;
            };
            let total = self.total();
            let over = self.is_over();
            if !over && total >= max {
                self.hold();
            } else if over && total <= max - max / 4 {
                self.release();
            }
            let near = self.is_over() || total >= max / 2;
            std::thread::sleep(if near { NEAR } else { FAR });
        }
    }
}

impl std::fmt::Debug for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget")
            .field("max", &self.max())
            .field("over", &self.is_over())
            .finish_non_exhaustive()
    }
}
