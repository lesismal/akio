//! One timer thread shared by every engine-driven TURN client
//! ([`TcpAllocation`](crate::client::TcpAllocation)): a min-heap of deadlines, each tied to a
//! weak reference; a stale entry (the client rearmed earlier, or went away) is skipped.

use std::collections::BinaryHeap;
use std::sync::{Condvar, Mutex, OnceLock, Weak};
use std::time::Instant;

pub(crate) trait Due: Send + Sync {
    fn fire(&self, at: Instant);
}

enum Target {
    Weak(Weak<dyn Due>),
    /// Runs once ([`Timer::defer`]).
    Once(Box<dyn FnOnce() + Send>),
}

struct Entry {
    at: Instant,
    target: Target,
}

impl PartialEq for Entry {
    fn eq(&self, o: &Entry) -> bool {
        self.at == o.at
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, o: &Entry) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Entry {
    fn cmp(&self, o: &Entry) -> std::cmp::Ordering {
        o.at.cmp(&self.at)
    }
}

pub(crate) struct Timer {
    heap: Mutex<BinaryHeap<Entry>>,
    cv: Condvar,
}

impl Timer {
    pub(crate) fn schedule(&self, at: Instant, target: Weak<dyn Due>) {
        let mut h = self.heap.lock().unwrap_or_else(|e| e.into_inner());
        let earliest = h.peek().is_none_or(|d| at < d.at);
        h.push(Entry {
            at,
            target: Target::Weak(target),
        });
        drop(h);
        if earliest {
            self.cv.notify_one();
        }
    }

    /// Runs `f` on the timer thread now: a callback that must not run under the caller's
    /// locks.
    pub(crate) fn defer(&self, f: Box<dyn FnOnce() + Send>) {
        let at = Instant::now();
        let mut h = self.heap.lock().unwrap_or_else(|e| e.into_inner());
        h.push(Entry {
            at,
            target: Target::Once(f),
        });
        drop(h);
        self.cv.notify_one();
    }

    fn run(&self) {
        let mut h = self.heap.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let now = Instant::now();
            match h.peek() {
                None => h = self.cv.wait(h).unwrap_or_else(|e| e.into_inner()),
                Some(d) if d.at > now => {
                    let wait = d.at - now;
                    h = self
                        .cv
                        .wait_timeout(h, wait)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                Some(_) => {
                    let d = h.pop().expect("peeked");
                    drop(h);
                    match d.target {
                        Target::Weak(t) => {
                            if let Some(t) = t.upgrade() {
                                t.fire(d.at);
                            }
                        }
                        Target::Once(f) => f(),
                    }
                    h = self.heap.lock().unwrap_or_else(|e| e.into_inner());
                }
            }
        }
    }
}

pub(crate) fn timer() -> &'static Timer {
    static T: OnceLock<&'static Timer> = OnceLock::new();
    T.get_or_init(|| {
        let t: &'static Timer = Box::leak(Box::new(Timer {
            heap: Mutex::new(BinaryHeap::new()),
            cv: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("akio-turn-timer".into())
            .spawn(move || t.run())
            .expect("spawn the TURN timer thread");
        t
    })
}
