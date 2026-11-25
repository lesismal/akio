//! One timer thread shared by every WebRTC peer: a min-heap of deadlines, each tied to a
//! weak reference; a stale entry (the peer rearmed earlier, or went away) is skipped.

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
    fn new() -> Timer {
        Timer {
            heap: Mutex::new(BinaryHeap::new()),
            cv: Condvar::new(),
        }
    }

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
                        // A panic in what `fire` reaches (a user callback) must not take the
                        // thread down: every later deadline of the process would never fire.
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            t.fire(d.at);
                        }));
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
        let t: &'static Timer = Box::leak(Box::new(Timer::new()));
        std::thread::Builder::new()
            .name("akio-webrtc-timer".into())
            .spawn(move || t.run())
            .expect("spawn the WebRTC timer thread");
        t
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    struct Boom;
    impl Due for Boom {
        fn fire(&self, _at: Instant) {
            panic!("a deadline's target panics");
        }
    }

    struct Ping(mpsc::Sender<()>);
    impl Due for Ping {
        fn fire(&self, _at: Instant) {
            let _ = self.0.send(());
        }
    }

    /// A target that panics does not stop the thread: later deadlines still fire.
    #[test]
    fn a_panicking_target_does_not_stop_the_timer() {
        let t: &'static Timer = Box::leak(Box::new(Timer::new()));
        std::thread::spawn(move || t.run());
        let boom: Arc<dyn Due> = Arc::new(Boom);
        t.schedule(Instant::now(), Arc::downgrade(&boom));
        let (tx, rx) = mpsc::channel();
        let ping: Arc<dyn Due> = Arc::new(Ping(tx));
        t.schedule(
            Instant::now() + Duration::from_millis(20),
            Arc::downgrade(&ping),
        );
        rx.recv_timeout(Duration::from_secs(5))
            .expect("a deadline after a panicking one fires");
    }
}
