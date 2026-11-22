//! One timer thread shared by every QUIC connection: a min-heap of deadlines, each tied to a
//! weak reference; a stale entry (the connection rearmed earlier, or went away) is skipped.

use std::collections::BinaryHeap;
use std::sync::{Condvar, Mutex, OnceLock, Weak};
use std::time::Instant;

pub(crate) trait Due: Send + Sync {
    fn fire(&self, at: Instant);
}

struct Entry {
    at: Instant,
    target: Weak<dyn Due>,
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
        h.push(Entry { at, target });
        drop(h);
        if earliest {
            self.cv.notify_one();
        }
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
                    if let Some(t) = d.target.upgrade() {
                        t.fire(d.at);
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
            .name("akio-quic-timer".into())
            .spawn(move || t.run())
            .expect("spawn the QUIC timer thread");
        t
    })
}
