//! Timers that run on the I/O loop that set them (ADR-099).
//!
//! [`after`] schedules a closure on the **calling** I/O thread's own timer wheel: no lock, no
//! other thread, no wakeup. When it is due, the loop runs it on that same thread, between two
//! polls, like any other callback. A handler that wants to answer later ("reply in 10 ms", a
//! retry, a per-request deadline) sets one from its callback and sends from the timer, so the
//! response is written by the thread that owns the connection.
//!
//! The closure need not be `Send`: it never leaves the thread. Only I/O threads have a wheel;
//! anywhere else [`after`] returns [`Error::Closed`] (use the logical pool and a channel, or a
//! thread of your own, there).
//!
//! Timing: a timer never fires early; it fires on the first loop iteration at least `delay`
//! later, normally within a millisecond (the wheel counts milliseconds), later if the thread is
//! busy. Timers still pending when the loop exits are dropped without running.
//!
//! ```no_run
//! use std::time::Duration;
//! # fn demo(c: &akio_core::Conn<impl akio_core::Handler>) {
//! let c = c.clone();
//! let _ = akio_core::timer::after(Duration::from_millis(10), move || {
//!     let _ = c.send(b"later\n");
//! });
//! # }
//! ```
//!
//! Guide: [Timers](https://lesismal.github.io/akio/en/concepts/timers.html)
//! (中文: [定时器](https://lesismal.github.io/akio/zh-CN/concepts/timers.html)).

use std::{
    cell::{Cell, RefCell},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use akio_timer::{TimerId, Wheel};

use crate::{Error, Result};

/// Timers one loop may hold at once; past it [`after`] returns [`Error::Overloaded`].
pub const MAX_TIMERS_PER_LOOP: usize = 1 << 20;

/// The longest delay accepted (about 49 days); longer ones are clamped to it.
pub const MAX_DELAY: Duration = Duration::from_millis(u32::MAX as u64);

type Job = Box<dyn FnOnce()>;

/// A loop's wheel: ticks are milliseconds since `epoch`.
struct LoopTimers {
    /// Distinguishes this installation from any other (a loop that exited, another thread).
    uid: u64,
    epoch: Instant,
    wheel: Wheel<Job>,
    /// Jobs taken off the wheel and not run yet (kept to reuse the allocation).
    due: Vec<Job>,
}

static NEXT_UID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static TIMERS: RefCell<Option<LoopTimers>> = const { RefCell::new(None) };
    /// The uid of the wheel installed on this thread (0: none), readable without a borrow.
    static UID: Cell<u64> = const { Cell::new(0) };
}

/// A pending timer set by [`after`]. Dropping it does **not** cancel the timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "dropping a Timer does not cancel it; bind it to `_` if that is intended"]
pub struct Timer {
    uid: u64,
    id: TimerId,
}

impl Timer {
    /// Cancels the timer: its closure is dropped without running. `true` if it was still
    /// pending; `false` if it already ran, was cancelled, or this is not the thread that set it.
    pub fn cancel(self) -> bool {
        if UID.with(Cell::get) != self.uid {
            return false;
        }
        let job = TIMERS.with(|t| {
            let mut g = t.try_borrow_mut().ok()?;
            g.as_mut()?.wheel.cancel(self.id)
        });
        // Dropped outside the borrow: its destructor may set or cancel timers.
        job.is_some()
    }
}

/// Runs `f` on this I/O thread once `delay` has passed (see the [module docs](self)).
///
/// Returns [`Error::Closed`] when the calling thread is not an I/O thread (or its loop is
/// exiting), [`Error::Overloaded`] when the loop already holds [`MAX_TIMERS_PER_LOOP`] timers.
/// A delay over [`MAX_DELAY`] is clamped to it.
pub fn after(delay: Duration, f: impl FnOnce() + 'static) -> Result<Timer> {
    let job: Job = Box::new(f);
    // On failure the job comes back and is dropped here, outside the borrow: its destructor
    // may touch timers.
    TIMERS
        .with(|t| {
            let Ok(mut g) = t.try_borrow_mut() else {
                return Err((Error::Closed, job));
            };
            let Some(t) = g.as_mut() else {
                return Err((Error::Closed, job));
            };
            if t.wheel.len() >= MAX_TIMERS_PER_LOOP {
                return Err((Error::Overloaded, job));
            }
            let now = t.epoch.elapsed();
            if t.wheel.is_empty() {
                // An idle wheel's clock is not advanced; catch it up first, or the next
                // `advance` would step through every millisecond since it was last used.
                t.wheel.advance(now.as_millis() as u64, |_| {});
            }
            // The first tick at or after `now + delay`: never early.
            let at = now + delay.min(MAX_DELAY);
            let tick = at.as_millis() as u64 + u64::from(at.subsec_nanos() % 1_000_000 != 0);
            let id = t.wheel.schedule(tick, job);
            Ok(Timer { uid: t.uid, id })
        })
        .map_err(|(e, _job)| e)
}

/// Whether the calling thread is an I/O thread with a timer wheel ([`after`] works here).
pub fn on_loop() -> bool {
    UID.with(Cell::get) != 0
}

/// Backends: gives the calling loop thread its timer wheel (once, before its first poll).
#[doc(hidden)]
pub fn install() {
    let uid = NEXT_UID.fetch_add(1, Ordering::Relaxed);
    let old = TIMERS.with(|t| {
        t.borrow_mut().replace(LoopTimers {
            uid,
            epoch: Instant::now(),
            wheel: Wheel::new(0),
            due: Vec::new(),
        })
    });
    UID.with(|u| u.set(uid));
    drop(old);
}

/// Backends: removes the calling thread's wheel when its loop exits; pending timers are dropped
/// without running.
#[doc(hidden)]
pub fn uninstall() {
    UID.with(|u| u.set(0));
    let old = TIMERS.with(|t| t.borrow_mut().take());
    drop(old); // destructors run with the wheel already gone: `after` from them fails cleanly
}

/// Backends: how long the loop may sleep before the next timer is due (`None`: no timer).
/// Rounded up to whole milliseconds, so a poll never wakes before the tick it waits for.
#[doc(hidden)]
pub fn next_wait() -> Option<Duration> {
    if UID.with(Cell::get) == 0 {
        return None;
    }
    TIMERS.with(|t| {
        let t = t.try_borrow().ok()?;
        let t = t.as_ref()?;
        let next = t.wheel.next_deadline()?;
        let left = Duration::from_millis(next).saturating_sub(t.epoch.elapsed());
        Some(Duration::from_millis(
            left.as_millis() as u64 + u64::from(left.subsec_nanos() % 1_000_000 != 0),
        ))
    })
}

/// Backends: runs every timer that is due, on the calling loop thread; returns how many ran.
/// A timer's panic is caught and logged; the others still run.
#[doc(hidden)]
pub fn fire() -> usize {
    if UID.with(Cell::get) == 0 {
        return 0;
    }
    let mut due = TIMERS.with(|t| {
        let mut g = t.borrow_mut();
        let Some(t) = g.as_mut() else {
            return Vec::new();
        };
        if t.wheel.is_empty() {
            return Vec::new();
        }
        let mut due = std::mem::take(&mut t.due);
        let now = t.epoch.elapsed().as_millis() as u64;
        t.wheel.advance(now, |j| due.push(j));
        due
    });
    let n = due.len();
    if n == 0 {
        return 0;
    }
    // Run with the wheel released: a job may set or cancel timers.
    for job in due.drain(..) {
        if catch_unwind(AssertUnwindSafe(job)).is_err() {
            crate::telemetry::log_or_stderr(
                akio_log::Level::Error,
                format_args!("a loop timer panicked; the loop goes on"),
            );
        }
    }
    TIMERS.with(|t| {
        if let Some(t) = t.borrow_mut().as_mut() {
            if t.due.capacity() < due.capacity() && due.capacity() <= 4096 {
                t.due = due;
            }
        }
    });
    n
}

/// The timeout a loop should poll with: the shorter of its own `timeout` and [`next_wait`].
#[doc(hidden)]
pub fn poll_timeout(timeout: Option<Duration>) -> Option<Duration> {
    match (timeout, next_wait()) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    fn run_until(cond: impl Fn() -> bool, limit: Duration) {
        let start = Instant::now();
        while !cond() {
            assert!(start.elapsed() < limit, "timed out");
            std::thread::sleep(next_wait().unwrap_or(Duration::from_millis(1)));
            fire();
        }
    }

    #[test]
    fn not_on_a_loop() {
        std::thread::spawn(|| {
            assert!(!on_loop());
            assert!(matches!(after(Duration::ZERO, || {}), Err(Error::Closed)));
            assert_eq!(next_wait(), None);
            assert_eq!(fire(), 0);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn fires_in_order_and_never_early() {
        std::thread::spawn(|| {
            install();
            assert!(on_loop());
            let log = Rc::new(RefCell::new(Vec::new()));
            let start = Instant::now();
            for (i, ms) in [30u64, 5, 15, 0].into_iter().enumerate() {
                let log = log.clone();
                let _ = after(Duration::from_millis(ms), move || {
                    assert!(start.elapsed() >= Duration::from_millis(ms));
                    log.borrow_mut().push(i);
                })
                .unwrap();
            }
            run_until(|| log.borrow().len() == 4, Duration::from_secs(5));
            assert_eq!(*log.borrow(), [3, 1, 2, 0]);
            assert_eq!(next_wait(), None);
            uninstall();
            assert!(!on_loop());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn cancel_and_rearm_from_a_timer() {
        std::thread::spawn(|| {
            install();
            let hits = Rc::new(Cell::new(0));
            let h = hits.clone();
            let t = after(Duration::from_millis(1), move || h.set(h.get() + 100)).unwrap();
            assert!(t.cancel());
            assert!(!t.cancel());
            let h = hits.clone();
            let _ = after(Duration::from_millis(1), move || {
                h.set(h.get() + 1);
                // Set from inside a timer: runs on a later iteration.
                let _ = after(Duration::from_millis(1), move || h.set(h.get() + 1)).unwrap();
            })
            .unwrap();
            run_until(|| hits.get() == 2, Duration::from_secs(5));
            // A handle is only good on its own thread.
            let other = after(Duration::from_secs(60), || {}).unwrap();
            assert!(!std::thread::spawn(move || other.cancel()).join().unwrap());
            assert!(other.cancel());
            uninstall();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_panicking_timer_does_not_stop_the_others() {
        std::thread::spawn(|| {
            install();
            let ok = Rc::new(Cell::new(false));
            let o = ok.clone();
            let _ = after(Duration::ZERO, || panic!("boom")).unwrap();
            let _ = after(Duration::ZERO, move || o.set(true)).unwrap();
            run_until(|| ok.get(), Duration::from_secs(5));
            uninstall();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn pending_timers_are_dropped_at_exit_and_idle_wheel_catches_up() {
        std::thread::spawn(|| {
            install();
            struct Flag(Rc<Cell<bool>>);
            impl Drop for Flag {
                fn drop(&mut self) {
                    self.0.set(true);
                    // The wheel is gone by now: setting a timer fails, it does not panic.
                    assert!(after(Duration::ZERO, || {}).is_err());
                }
            }
            // Idle for a while, then a short timer still fires promptly.
            std::thread::sleep(Duration::from_millis(20));
            let hit = Rc::new(Cell::new(false));
            let h = hit.clone();
            let _ = after(Duration::from_millis(1), move || h.set(true)).unwrap();
            assert!(next_wait().unwrap() <= Duration::from_millis(2));
            run_until(|| hit.get(), Duration::from_secs(5));
            let dropped = Rc::new(Cell::new(false));
            let f = Flag(dropped.clone());
            let _ = after(Duration::from_secs(3600), move || drop(f)).unwrap();
            uninstall();
            assert!(dropped.get());
        })
        .join()
        .unwrap();
    }
}
