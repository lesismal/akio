//! Cancellable deadlines: one background thread over sharded ordered maps.
//!
//! The engine exposes no per-connection timer that can be armed from any thread, so call
//! deadlines live here. A timer is an entry keyed by (millisecond tick, sequence number) in one
//! of [`SHARDS`] maps; the shard is picked per thread, so I/O threads scheduling deadlines do not
//! share a lock. Cancelling removes the entry and drops its callback at once: memory follows the
//! number of live timers, not the number ever scheduled. The thread sleeps until the earliest
//! deadline and is woken only when a new timer is due before that.
//!
//! The same module is in `akio-grpc` and `akio-arpc` (`src/deadline.rs`); keep them identical.

use std::{
    cell::Cell,
    collections::BTreeMap,
    sync::{
        Condvar, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

type TimerFn = Box<dyn FnOnce() + Send>;
type Key = (u64, u64);

const SHARDS: usize = 16;
/// Deadlines further out than this are clamped (about 292 million years: keeps tick arithmetic
/// in range).
const MAX_TICK: u64 = u64::MAX / 2;

/// A scheduled callback; [`Timer::cancel`] removes it. Dropping the handle does not cancel.
#[derive(Debug)]
pub(crate) struct Timer {
    shard: u8,
    key: Key,
}

impl Timer {
    /// Runs `f` on the timer thread at `at` (or soon after) unless cancelled first.
    pub(crate) fn at(at: Instant, f: impl FnOnce() + Send + 'static) -> Timer {
        service().schedule(at, Box::new(f))
    }

    /// Removes the timer and drops its callback; nothing if it already ran or was cancelled.
    pub(crate) fn cancel(&self) {
        service().cancel(self);
    }
}

/// Timers scheduled and not yet run or cancelled, in every shard.
#[cfg(test)]
pub(crate) fn pending() -> usize {
    service().len()
}

struct Service {
    base: Instant,
    shards: [Mutex<BTreeMap<Key, TimerFn>>; SHARDS],
    seq: AtomicU64,
    /// Tick the thread sleeps until (`u64::MAX`: while it scans, or with nothing pending, so
    /// any new timer wakes it).
    next_wake: AtomicU64,
    kicked: Mutex<bool>,
    cv: Condvar,
}

fn service() -> &'static Service {
    static S: OnceLock<&'static Service> = OnceLock::new();
    S.get_or_init(|| {
        let s: &'static Service = Box::leak(Box::new(Service::new()));
        std::thread::Builder::new()
            .name(concat!(env!("CARGO_PKG_NAME"), "-deadlines").into())
            .spawn(move || s.run())
            .expect("deadline thread");
        s
    })
}

fn shard_index() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static SHARD: Cell<usize> = const { Cell::new(usize::MAX) };
    }
    SHARD.with(|c| {
        let mut v = c.get();
        if v == usize::MAX {
            v = NEXT.fetch_add(1, Ordering::Relaxed) % SHARDS;
            c.set(v);
        }
        v
    })
}

impl Service {
    fn new() -> Service {
        Service {
            base: Instant::now(),
            shards: std::array::from_fn(|_| Mutex::new(BTreeMap::new())),
            seq: AtomicU64::new(0),
            next_wake: AtomicU64::new(u64::MAX),
            kicked: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    /// The tick (ms since `base`) at or after `at`: a timer never fires early.
    fn tick_of(&self, at: Instant) -> u64 {
        let ms = at
            .saturating_duration_since(self.base)
            .as_nanos()
            .div_ceil(1_000_000);
        u64::try_from(ms).unwrap_or(MAX_TICK).min(MAX_TICK)
    }

    fn now_tick(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(MAX_TICK)
    }

    fn schedule(&self, at: Instant, f: TimerFn) -> Timer {
        let tick = self.tick_of(at);
        let key = (tick, self.seq.fetch_add(1, Ordering::Relaxed));
        let shard = shard_index();
        self.shards[shard]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, f);
        // Wake the thread only when this timer is due before the one it sleeps for.
        if tick < self.next_wake.load(Ordering::SeqCst) {
            *self.kicked.lock().unwrap_or_else(|p| p.into_inner()) = true;
            self.cv.notify_one();
        }
        Timer {
            shard: shard as u8,
            key,
        }
    }

    fn cancel(&self, t: &Timer) {
        let f = self.shards[usize::from(t.shard)]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&t.key);
        drop(f); // outside the lock
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|p| p.into_inner()).len())
            .sum()
    }

    /// Takes every due callback into `due`; returns the earliest tick still pending.
    fn collect(&self, now: u64, due: &mut Vec<TimerFn>) -> u64 {
        let mut next = u64::MAX;
        for s in &self.shards {
            let mut g = s.lock().unwrap_or_else(|p| p.into_inner());
            while let Some(e) = g.first_entry() {
                if e.key().0 <= now {
                    due.push(e.remove());
                } else {
                    next = next.min(e.key().0);
                    break;
                }
            }
        }
        next
    }

    fn run(&self) {
        let mut due = Vec::new();
        loop {
            self.next_wake.store(u64::MAX, Ordering::SeqCst);
            let next = self.collect(self.now_tick(), &mut due);
            if !due.is_empty() {
                for f in due.drain(..) {
                    f();
                }
                continue;
            }
            let mut k = self.kicked.lock().unwrap_or_else(|p| p.into_inner());
            self.next_wake.store(next, Ordering::SeqCst);
            if !*k {
                k = if next == u64::MAX {
                    self.cv.wait(k).unwrap_or_else(|p| p.into_inner())
                } else {
                    let wait = Duration::from_millis(next.saturating_sub(self.now_tick()));
                    self.cv
                        .wait_timeout(k, wait)
                        .unwrap_or_else(|p| p.into_inner())
                        .0
                };
            }
            *k = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use super::*;

    #[test]
    fn fires_in_order_and_cancel_frees_the_entry() {
        let (tx, rx) = mpsc::channel();
        let now = Instant::now();
        for (i, ms) in [(2u8, 60u64), (1, 30), (3, 90)] {
            let tx = tx.clone();
            Timer::at(now + Duration::from_millis(ms), move || {
                let _ = tx.send((i, Instant::now()));
            });
        }
        let gone = Timer::at(now + Duration::from_millis(40), move || {
            let _ = tx.send((9, Instant::now()));
        });
        gone.cancel();
        gone.cancel(); // twice is harmless
        let got: Vec<_> = (0..3)
            .map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect();
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), [1, 2, 3]);
        assert!(got[0].1 >= now + Duration::from_millis(30), "never early");
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn earlier_timer_wakes_a_sleeping_thread() {
        let (tx, rx) = mpsc::channel();
        let far = Timer::at(Instant::now() + Duration::from_secs(3600), || {});
        std::thread::sleep(Duration::from_millis(20)); // let the thread sleep for `far`
        let t0 = Instant::now();
        Timer::at(t0 + Duration::from_millis(10), move || {
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(t0.elapsed() < Duration::from_secs(1));
        far.cancel();
    }

    /// A flood of long deadlines that are all cancelled leaves nothing behind (the callbacks,
    /// and what they hold, are dropped at cancel time).
    #[test]
    fn cancelled_flood_leaves_no_entries() {
        let s = Service::new(); // private instance: other tests share the global one
        let held = Arc::new(());
        let far = Instant::now() + Duration::from_secs(24 * 3600);
        for _ in 0..100_000 {
            let h = held.clone();
            let t = s.schedule(far, Box::new(move || drop(h)));
            s.cancel(&t);
        }
        assert_eq!(s.len(), 0);
        assert_eq!(Arc::strong_count(&held), 1, "callbacks dropped on cancel");
        // A deadline in the past fires on the next scan.
        let past = s.schedule(s.base, Box::new(|| {}));
        assert_eq!(past.key.0, 0);
        let mut due = Vec::new();
        assert_eq!(s.collect(s.now_tick(), &mut due), u64::MAX);
        assert_eq!(due.len(), 1);
    }
}
