//! A single lazily started thread that runs short deferred jobs (request timeouts of the
//! clients). Jobs must be quick: they only fail a request and close its connection.
//!
//! A job made per request is [`cancel`]led when its request ends (akit's A171): until then it
//! holds what it captured (a request's exchange, its stream's state), so leaving it to expire
//! kept every request of the last `timeout` alive, a proxy at 230k requests a second with a
//! 60s timeout holding gigabytes. Cancelled jobs are dropped at once; their heap entries are
//! compacted away once they outnumber the live ones.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, Sender},
    },
    time::{Duration, Instant},
};

type Job = Box<dyn FnOnce() + Send>;

enum Msg {
    Add(Instant, u64, Job),
    Cancel(u64),
}

/// A job [`after`] scheduled, for [`cancel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key(u64);

impl Key {
    /// The key as a number, never 0, to keep in an atomic.
    pub(crate) fn raw(self) -> u64 {
        self.0
    }

    /// The key [`Key::raw`] gave, or `None` for 0.
    pub(crate) fn from_raw(raw: u64) -> Option<Key> {
        (raw != 0).then_some(Key(raw))
    }
}

/// Heap entries of cancelled jobs are dropped once there are this many and they outnumber the
/// live jobs.
const COMPACT_FLOOR: usize = 4096;

fn sender() -> &'static Sender<Msg> {
    static TX: OnceLock<Sender<Msg>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Msg>();
        std::thread::Builder::new()
            .name("akio-http-timer".into())
            .spawn(move || {
                let mut heap: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();
                let mut jobs: HashMap<u64, Job> = HashMap::new();
                loop {
                    let now = Instant::now();
                    while let Some(&Reverse((at, id))) = heap.peek() {
                        if at > now {
                            break;
                        }
                        heap.pop();
                        if let Some(j) = jobs.remove(&id) {
                            j();
                        }
                    }
                    let msg = match heap.peek() {
                        Some(&Reverse((at, _))) => {
                            rx.recv_timeout(at.saturating_duration_since(Instant::now()))
                        }
                        None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                    };
                    match msg {
                        Ok(Msg::Add(at, id, job)) => {
                            heap.push(Reverse((at, id)));
                            jobs.insert(id, job);
                        }
                        Ok(Msg::Cancel(id)) => {
                            drop(jobs.remove(&id));
                            if heap.len() >= COMPACT_FLOOR && heap.len() > 2 * jobs.len() {
                                heap.retain(|Reverse((_, id))| jobs.contains_key(id));
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                }
            })
            .expect("spawn akio-http timer thread");
        tx
    })
}

/// Runs `job` on the timer thread after `delay`, unless [`cancel`]led first. A delay too long
/// to represent never runs it.
pub(crate) fn after(delay: Duration, job: impl FnOnce() + Send + 'static) -> Key {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let key = Key(NEXT.fetch_add(1, Ordering::Relaxed));
    if let Some(at) = Instant::now().checked_add(delay) {
        let _ = sender().send(Msg::Add(at, key.0, Box::new(job)));
    }
    key
}

/// Drops the job `key` names if it has not run: what it captured goes now, not when its delay
/// would have passed. Cancelling one that ran, or twice, does nothing.
pub(crate) fn cancel(key: Key) {
    let _ = sender().send(Msg::Cancel(key.0));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    /// A cancelled job never runs and what it captured is dropped long before its delay; one
    /// left alone runs.
    #[test]
    fn cancelled_jobs_drop_what_they_hold() {
        let held = Arc::new(());
        let ran = Arc::new(AtomicUsize::new(0));
        let mut keys = Vec::new();
        for _ in 0..10_000 {
            let (h, r) = (held.clone(), ran.clone());
            keys.push(after(Duration::from_secs(3600), move || {
                drop(h);
                r.fetch_add(1, Ordering::SeqCst);
            }));
        }
        assert_eq!(Arc::strong_count(&held), 10_001);
        for k in keys {
            cancel(k);
        }
        let (tx, rx) = mpsc::channel();
        after(Duration::from_millis(10), move || {
            let _ = tx.send(ran.load(Ordering::SeqCst));
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)), Ok(0));
        // The cancels were sent before the job above, so they were handled before it ran.
        assert_eq!(Arc::strong_count(&held), 1);
        assert_eq!(Key::from_raw(0), None);
        assert_eq!(Key::from_raw(7).map(Key::raw), Some(7));
    }
}
