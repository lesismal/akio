//! Per-connection deadlines of the HTTP server (head read, keep-alive idle, body progress).
//!
//! `akio-core` keeps one timer wheel per I/O thread, but does not expose it to handlers. The
//! server's deadlines are coarse (seconds by default) and re-armed several times per request,
//! so they use a cheaper scheme of their own:
//!
//! * a connection registers one [`Watch`] when it opens (one sharded lock, once);
//! * arming is a relaxed store of `coarse_now + timeout` into the watch, disarming a store of 0,
//!   so the request path pays two atomic accesses and takes no lock;
//! * one sweeper thread per process ticks at a fraction of the shortest timeout in use (between
//!   5 ms and 1 s), advances the coarse clock and scans the registry. An expired watch is
//!   cleared and its handler's `on_deadline` is posted to the connection's own I/O thread (by way
//!   of the logical pool, the only route to a loop that `akio-core` offers); if the pool refuses,
//!   the connection is closed from the sweeper.
//!
//! A deadline fires between `timeout` and `timeout + 2 ticks` after it was armed; it never
//! fires early. The handler re-checks its state when the expiry reaches it, so a deadline
//! re-armed meanwhile is not acted on.

use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::{Conn, Handler};

/// The deadline was cleared (or never armed).
const NONE: u64 = 0;
/// The connection is gone: the sweeper drops the watch.
const GONE: u64 = u64::MAX;

const SHARDS: usize = 16;
const MIN_TICK_MS: u64 = 5;
const MAX_TICK_MS: u64 = 1000;

/// A handler whose deadlines are watched.
pub(crate) trait OnDeadline: Handler + Sized {
    /// A deadline armed on this connection passed. Runs on the connection's I/O thread.
    fn on_deadline(&mut self, c: &Conn<Self>);
}

/// One connection's deadline.
pub(crate) struct Watch<H> {
    deadline: AtomicU64,
    conn: Mutex<Option<Conn<H>>>,
}

impl<H: OnDeadline> Watch<H> {
    /// Registers a watch for `c`. `shortest` is the shortest timeout the connection may arm (it
    /// sets the sweeper's resolution).
    pub(crate) fn register(c: &Conn<H>, shortest: Duration) -> Arc<Watch<H>> {
        let w = Arc::new(Watch {
            deadline: AtomicU64::new(NONE),
            conn: Mutex::new(Some(c.clone())),
        });
        let reg = registry();
        let ms = u64::try_from(shortest.as_millis()).unwrap_or(u64::MAX);
        let tick = (ms / 8).clamp(MIN_TICK_MS, MAX_TICK_MS);
        if reg.tick.fetch_min(tick, Ordering::Relaxed) > tick {
            // A shorter tick: the sweeper may be asleep for the longer one, its clock as stale.
            // Bring the clock up to date now and wake it, so deadlines armed from here on count
            // from the time they are armed (ADR-108: a client's 300 ms header timeout armed
            // while the sweeper slept a server's 1 s tick fired about 100 ms after arming).
            reg.advance();
            if let Some(t) = reg.sweeper.get() {
                t.unpark();
            }
        }
        reg.shards[(c.id() as usize) % SHARDS]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(w.clone());
        reg.start();
        w
    }
}

impl<H> Watch<H> {
    /// Arms the deadline `t` from now (`None` clears it).
    #[inline]
    pub(crate) fn arm(&self, t: Option<Duration>) {
        let v = match t {
            None => NONE,
            Some(t) => {
                let reg = registry();
                // One tick of slack: the coarse clock may lag by up to one tick.
                let ms = u64::try_from(t.as_millis()).unwrap_or(u64::MAX / 4);
                reg.now
                    .load(Ordering::Relaxed)
                    .saturating_add(ms)
                    .saturating_add(reg.tick.load(Ordering::Relaxed))
                    .clamp(1, GONE - 1)
            }
        };
        self.deadline.store(v, Ordering::Relaxed);
    }

    /// Whether the deadline fired and was not re-armed since.
    #[inline]
    pub(crate) fn fired(&self) -> bool {
        self.deadline.load(Ordering::Relaxed) == NONE
    }

    /// The connection is closing: stop watching it (the sweeper drops the watch on its next
    /// pass) and release the connection handle.
    pub(crate) fn release(&self) {
        self.deadline.store(GONE, Ordering::Relaxed);
        self.conn.lock().unwrap_or_else(|p| p.into_inner()).take();
    }
}

/// What the sweeper sees of a watch.
trait Entry: Send + Sync {
    /// Checks the deadline against `now`; `false` drops the entry.
    fn poll(&self, now: u64) -> bool;
}

impl<H: OnDeadline> Entry for Watch<H> {
    fn poll(&self, now: u64) -> bool {
        let d = self.deadline.load(Ordering::Relaxed);
        if d == GONE {
            return false;
        }
        if d == NONE || d > now {
            return true;
        }
        // Expired: clear it (unless the loop re-armed it just now) and tell the handler.
        if self
            .deadline
            .compare_exchange(d, NONE, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return true;
        }
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(c) = conn else { return false };
        if c.run_on_loop(|h: &mut H, c| h.on_deadline(c)).is_err() {
            c.close();
        }
        true
    }
}

struct Registry {
    shards: [Mutex<Vec<Arc<dyn Entry>>>; SHARDS],
    /// Milliseconds since `epoch`, advanced by the sweeper once per tick.
    now: AtomicU64,
    tick: AtomicU64,
    epoch: Instant,
    started: AtomicBool,
    /// The sweeper thread, woken when the tick gets shorter.
    sweeper: OnceLock<std::thread::Thread>,
}

fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(|| Registry {
        shards: std::array::from_fn(|_| Mutex::new(Vec::new())),
        now: AtomicU64::new(1),
        tick: AtomicU64::new(MAX_TICK_MS),
        epoch: Instant::now(),
        started: AtomicBool::new(false),
        sweeper: OnceLock::new(),
    })
}

impl Registry {
    fn start(&'static self) {
        if self.started.load(Ordering::Acquire) || self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        self.advance();
        let spawned = std::thread::Builder::new()
            .name("akio-http-deadlines".into())
            .spawn(move || {
                let _ = self.sweeper.set(std::thread::current());
                loop {
                    // Woken early when a registration shortens the tick (and spuriously, which
                    // only makes a pass sooner).
                    std::thread::park_timeout(Duration::from_millis(
                        self.tick.load(Ordering::Relaxed),
                    ));
                    let now = self.advance();
                    for s in &self.shards {
                        // Polling never blocks (a pool submission at most), so holding the
                        // shard lock across the scan only delays registrations briefly.
                        s.lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .retain(|e| e.poll(now));
                    }
                }
            });
        if spawned.is_err() {
            // No thread: deadlines cannot fire; try again with the next registration.
            self.started.store(false, Ordering::Release);
        }
    }

    fn advance(&self) -> u64 {
        let now = u64::try_from(self.epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX / 2)
            .max(1);
        // Also advanced from registrations: never backwards.
        self.now.fetch_max(now, Ordering::Relaxed).max(now)
    }
}
