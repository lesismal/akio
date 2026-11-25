//! Timers any thread may set: one process-wide timer thread (ADR-154, akit A45).
//!
//! [`after_send`](super::after_send) is for code that runs off the I/O threads (a control
//! plane: health probes and their deadlines, periodic sweeps, refreshes, lock expiries) and has
//! no loop of its own to set a [loop timer](super::after) on. The timers are kept in one ordered
//! map under one lock, served by one thread (`akio-timer`) started on first use and leaving
//! after [`IDLE`] with nothing pending. Setting and cancelling take the lock for a map insert or
//! removal; the thread takes it to pop what is due and runs the jobs outside it.

use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock},
    time::{Duration, Instant},
};

use crate::{Error, Result};

/// Timers pending at once across the process; past it [`after_send`](super::after_send)
/// returns [`Error::Overloaded`].
pub const MAX_SEND_TIMERS: usize = 1 << 20;

/// How long the timer thread waits with nothing pending before it exits (the next timer starts
/// it again).
pub(crate) const IDLE: Duration = Duration::from_secs(30);

/// Jobs taken off the map per lock hold, so a burst of due timers does not keep setters waiting.
const BATCH: usize = 256;

type Job = Box<dyn FnOnce() + Send>;

/// A timer set by [`after_send`](super::after_send). `Copy` and `Send`: cancel it from any
/// thread. Dropping it does **not** cancel the timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "dropping a SendTimer does not cancel it; bind it to `_` if that is intended"]
pub struct SendTimer {
    at: Instant,
    seq: u64,
}

impl SendTimer {
    /// Cancels the timer from any thread: its closure is dropped without running (on the
    /// calling thread). `true` if it was still pending; `false` if it already ran (or is
    /// running), or was cancelled.
    pub fn cancel(self) -> bool {
        global().cancel(self)
    }
}

struct State {
    timers: BTreeMap<(Instant, u64), Job>,
    seq: u64,
    /// Whether the thread is running (it clears this, under the lock, as it exits).
    running: bool,
}

/// One timer service: the process-wide one, or a test's own.
pub(crate) struct Service {
    state: Mutex<State>,
    ready: Condvar,
    cap: usize,
    name: &'static str,
    /// [`IDLE`], shorter in tests.
    idle: Duration,
}

fn global() -> &'static Arc<Service> {
    static S: OnceLock<Arc<Service>> = OnceLock::new();
    S.get_or_init(|| Service::new(MAX_SEND_TIMERS, "akio-timer"))
}

/// See [`after_send`](super::after_send).
pub(crate) fn after_send(delay: Duration, f: Job) -> Result<SendTimer> {
    Service::after(global(), delay, f)
}

impl Service {
    pub(crate) fn new(cap: usize, name: &'static str) -> Arc<Service> {
        Arc::new(Service {
            state: Mutex::new(State {
                timers: BTreeMap::new(),
                seq: 0,
                running: false,
            }),
            ready: Condvar::new(),
            cap,
            name,
            idle: IDLE,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn after(me: &Arc<Service>, delay: Duration, f: Job) -> Result<SendTimer> {
        let at = Instant::now() + delay.min(super::MAX_DELAY);
        let mut st = me.lock();
        if st.timers.len() >= me.cap {
            drop(st);
            drop(f); // outside the lock: its destructor may set or cancel timers
            return Err(Error::Overloaded);
        }
        if !st.running {
            let run = me.clone();
            let spawned = std::thread::Builder::new()
                .name(me.name.into())
                .spawn(move || run.run());
            if let Err(e) = spawned {
                drop(st);
                drop(f);
                return Err(Error::Io(e));
            }
            st.running = true;
        }
        st.seq += 1;
        let key = (at, st.seq);
        // Wake the thread only when this timer is due before everything it waits for.
        let first = st.timers.keys().next().is_none_or(|k| key < *k);
        st.timers.insert(key, f);
        drop(st);
        if first {
            me.ready.notify_one();
        }
        Ok(SendTimer {
            at: key.0,
            seq: key.1,
        })
    }

    pub(crate) fn cancel(&self, t: SendTimer) -> bool {
        let job = self.lock().timers.remove(&(t.at, t.seq));
        // Dropped outside the lock: its destructor may set or cancel timers.
        job.is_some()
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.lock().timers.len()
    }

    #[cfg(test)]
    pub(crate) fn running(&self) -> bool {
        self.lock().running
    }

    /// The thread: runs each job once it is due, outside the lock; exits after [`IDLE`] with
    /// nothing pending.
    fn run(&self) {
        let mut due: Vec<Job> = Vec::new();
        let mut st = self.lock();
        loop {
            let now = Instant::now();
            while due.len() < BATCH {
                match st.timers.first_entry() {
                    Some(e) if e.key().0 <= now => due.push(e.remove()),
                    _ => break,
                }
            }
            if !due.is_empty() {
                drop(st);
                for job in due.drain(..) {
                    if catch_unwind(AssertUnwindSafe(job)).is_err() {
                        crate::telemetry::log_or_stderr(
                            akio_log::Level::Error,
                            format_args!("a timer job panicked; the timer thread goes on"),
                        );
                    }
                }
                st = self.lock();
                continue;
            }
            match st.timers.keys().next() {
                Some(&(at, _)) => {
                    let wait = at.saturating_duration_since(now);
                    st = self
                        .ready
                        .wait_timeout(st, wait)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                None => {
                    let (g, r) = self
                        .ready
                        .wait_timeout(st, self.idle)
                        .unwrap_or_else(|p| p.into_inner());
                    st = g;
                    if r.timed_out() && st.timers.is_empty() {
                        st.running = false;
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    #[test]
    fn fires_once_never_early_in_order() {
        let s = Service::new(16, "akio-timer-test");
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        for (i, ms) in [60u64, 10, 30, 0].into_iter().enumerate() {
            let tx = tx.clone();
            let _ = Service::after(
                &s,
                Duration::from_millis(ms),
                Box::new(move || {
                    let _ = tx.send((i, start.elapsed() >= Duration::from_millis(ms)));
                }),
            )
            .unwrap();
        }
        let got: Vec<_> = (0..4)
            .map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect();
        assert_eq!(got, [(3, true), (1, true), (2, true), (0, true)]);
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(s.pending(), 0);
    }

    #[test]
    fn cancel_from_another_thread() {
        let s = Service::new(16, "akio-timer-test");
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let t = Service::after(
            &s,
            Duration::from_millis(50),
            Box::new(move || {
                h.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .unwrap();
        let s2 = s.clone();
        assert!(std::thread::spawn(move || s2.cancel(t)).join().unwrap());
        assert!(!s.cancel(t), "a second cancel finds nothing");
        // An earlier timer set after it still fires: the thread is not left waiting.
        let (tx, rx) = mpsc::channel();
        let _ = Service::after(
            &s,
            Duration::ZERO,
            Box::new(move || {
                let _ = tx.send(());
            }),
        )
        .unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        // Cancelling one that ran: false.
        let (tx, rx) = mpsc::channel();
        let t = Service::after(
            &s,
            Duration::ZERO,
            Box::new(move || {
                let _ = tx.send(());
            }),
        )
        .unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!s.cancel(t));
    }

    #[test]
    fn bounded_then_overloaded() {
        let s = Service::new(3, "akio-timer-test");
        let ts: Vec<_> = (0..3)
            .map(|_| Service::after(&s, Duration::from_secs(60), Box::new(|| {})).unwrap())
            .collect();
        assert!(matches!(
            Service::after(&s, Duration::from_secs(60), Box::new(|| {})),
            Err(Error::Overloaded)
        ));
        assert!(ts[0].cancel_in(&s));
        assert!(Service::after(&s, Duration::from_secs(60), Box::new(|| {})).is_ok());
        assert_eq!(s.pending(), 3);
    }

    #[test]
    fn the_thread_leaves_when_idle_and_comes_back() {
        let s = Arc::new(Service {
            idle: Duration::from_millis(50),
            ..Arc::into_inner(Service::new(4, "akio-timer-test")).unwrap()
        });
        let (tx, rx) = mpsc::channel();
        for _ in 0..2 {
            let tx = tx.clone();
            let _ = Service::after(
                &s,
                Duration::ZERO,
                Box::new(move || {
                    let _ = tx.send(());
                }),
            )
            .unwrap();
            rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let t0 = Instant::now();
            while s.running() {
                assert!(t0.elapsed() < Duration::from_secs(5), "the thread stays");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[test]
    fn a_panicking_job_does_not_stop_the_thread() {
        let s = Service::new(16, "akio-timer-test");
        let _ = Service::after(&s, Duration::ZERO, Box::new(|| panic!("boom"))).unwrap();
        let (tx, rx) = mpsc::channel();
        let _ = Service::after(
            &s,
            Duration::from_millis(5),
            Box::new(move || {
                let _ = tx.send(());
            }),
        )
        .unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(s.running());
    }

    impl SendTimer {
        fn cancel_in(self, s: &Service) -> bool {
            s.cancel(self)
        }
    }
}
