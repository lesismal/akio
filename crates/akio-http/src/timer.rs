//! A single lazily started thread that runs short deferred jobs (request timeouts of the
//! clients). Jobs must be quick: they only fail a request and close its connection.
//!
//! A job made per request is [`cancel`]led when its request ends (akit's A171): until then it
//! holds what it captured (a request's exchange, its stream's state), so leaving it to expire
//! kept every request of the last `timeout` alive, a proxy at 230k requests a second with a
//! 60s timeout holding gigabytes. Cancelled jobs are dropped within [`LAZY`] (at once when the
//! thread was idle); their heap entries are compacted away once they outnumber the live ones.
//!
//! Scheduling and cancelling cost the calling thread no wake-up of the timer thread and no
//! lock or counter shared with other threads (rules §5.12): each thread queues its messages in
//! a queue of its own (its *shard*), takes its keys from a block of its own, and wakes the
//! timer thread only when a job is due before the thread's next wake-up, or when a cancel finds
//! it asleep with nothing in flight. While messages arrive the timer thread collects them every
//! [`LAZY`]; a cancel waits that long at most.

use std::{
    cell::Cell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::Thread,
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

/// How often the timer thread collects the queued messages while they keep coming: the longest
/// a cancelled job (and what it captured) outlives its cancel.
pub(crate) const LAZY: Duration = Duration::from_millis(10);

/// Keys a thread takes at once from the process-wide counter.
const KEY_BLOCK: u64 = 1 << 16;

/// One thread's queue of messages for the timer thread.
#[derive(Default)]
struct Shard(Mutex<Vec<Msg>>);

impl Shard {
    fn lock(&self) -> MutexGuard<'_, Vec<Msg>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

struct Shared {
    /// Every live thread's shard; the timer thread drops those whose thread exited.
    shards: Mutex<Vec<Arc<Shard>>>,
    /// The queue of threads whose own shard is gone (their thread-locals are being destroyed).
    orphans: Arc<Shard>,
    /// When the timer thread wakes up next, in nanoseconds since `epoch` (`u64::MAX`: only when
    /// woken). A job due earlier wakes it.
    next_wake: AtomicU64,
    /// The timer thread sleeps with no message in flight: a cancel wakes it.
    idle: AtomicBool,
    epoch: Instant,
    thread: Thread,
}

fn shared() -> &'static Shared {
    static SHARED: OnceLock<Shared> = OnceLock::new();
    SHARED.get_or_init(|| {
        let orphans = Arc::new(Shard::default());
        let thread = std::thread::Builder::new()
            .name("akio-http-timer".into())
            .spawn(|| run(shared()))
            .expect("spawn akio-http timer thread")
            .thread()
            .clone();
        Shared {
            shards: Mutex::new(vec![orphans.clone()]),
            orphans,
            next_wake: AtomicU64::new(u64::MAX),
            idle: AtomicBool::new(true),
            epoch: Instant::now(),
            thread,
        }
    })
}

/// A thread's own shard and block of keys.
struct Local {
    shard: Arc<Shard>,
    /// The next key of the block and the block's end.
    keys: Cell<(u64, u64)>,
}

thread_local! {
    static LOCAL: Local = {
        let shard = Arc::new(Shard::default());
        let sh = shared();
        sh.shards.lock().unwrap_or_else(|p| p.into_inner()).push(shard.clone());
        Local { shard, keys: Cell::new((0, 0)) }
    };
}

/// Keys come in blocks of [`KEY_BLOCK`] from here; 0 is never one.
static NEXT_BLOCK: AtomicU64 = AtomicU64::new(1);

/// Queues `msg` on the calling thread's shard (the orphans' once its thread-locals are gone)
/// and returns the key of an [`after`].
fn post(msg: impl FnOnce(u64) -> Msg) -> u64 {
    let mut msg = Some(msg);
    let local = LOCAL.try_with(|l| {
        let (mut next, mut end) = l.keys.get();
        if next == end {
            next = NEXT_BLOCK.fetch_add(KEY_BLOCK, Ordering::Relaxed);
            end = next + KEY_BLOCK;
        }
        l.keys.set((next + 1, end));
        if let Some(m) = msg.take() {
            l.shard.lock().push(m(next));
        }
        next
    });
    match (local, msg) {
        (Ok(key), _) => key,
        (Err(_), Some(m)) => {
            let key = NEXT_BLOCK.fetch_add(1, Ordering::Relaxed);
            shared().orphans.lock().push(m(key));
            key
        }
        (Err(_), None) => unreachable!("a message is queued once"),
    }
}

/// Collects every shard's messages (dropping the shards of exited threads) into `into`.
fn collect(sh: &Shared, into: &mut Vec<Msg>, spare: &mut Vec<Msg>) {
    let mut shards = sh.shards.lock().unwrap_or_else(|p| p.into_inner());
    shards.retain(|s| {
        // Only the list holds it: its thread exited, and nothing can queue on it any more (so
        // the drain below takes its last messages).
        let exited = Arc::strong_count(s) == 1 && !Arc::ptr_eq(s, &sh.orphans);
        {
            let mut q = s.lock();
            if !q.is_empty() {
                std::mem::swap(&mut *q, spare);
            }
        }
        into.append(spare);
        !exited
    });
}

fn run(sh: &'static Shared) {
    let mut heap: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();
    let mut jobs: HashMap<u64, Job> = HashMap::new();
    let (mut msgs, mut spare) = (Vec::new(), Vec::new());
    // Cancels of keys not added yet (the add was queued on another thread's shard, collected
    // after this one): tried once more after the next collection, which sees the add.
    let (mut early, mut retry, mut cancels) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        collect(sh, &mut msgs, &mut spare);
        let got = !msgs.is_empty() || !early.is_empty();
        std::mem::swap(&mut early, &mut retry);
        // Adds before cancels: a cancel always follows its add, but maybe on another shard.
        for m in msgs.drain(..) {
            match m {
                Msg::Add(at, id, job) => {
                    heap.push(Reverse((at, id)));
                    jobs.insert(id, job);
                }
                Msg::Cancel(id) => cancels.push(id),
            }
        }
        for id in cancels.drain(..) {
            if jobs.remove(&id).is_none() {
                early.push(id);
            }
        }
        for id in retry.drain(..) {
            drop(jobs.remove(&id));
        }
        if heap.len() >= COMPACT_FLOOR && heap.len() > 2 * jobs.len() {
            heap.retain(|Reverse((_, id))| jobs.contains_key(id));
        }
        let now = Instant::now();
        while let Some(&Reverse((at, id))) = heap.peek() {
            if at > now {
                break;
            }
            heap.pop();
            if let Some(j) = jobs.remove(&id) {
                // A panicking job (a user callback it reached) must not take the timer thread
                // down with it: every later job of the process would silently never run.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(j));
            }
        }
        // Messages are flowing: collect again within LAZY. Else sleep until the first job is
        // due; a job due earlier or a cancel wakes the thread.
        let flowing = got || !early.is_empty();
        let now = Instant::now();
        let mut wake = heap.peek().map(|&Reverse((at, _))| at);
        if flowing {
            wake = Some(wake.map_or(now + LAZY, |w| w.min(now + LAZY)));
        }
        let nanos = wake.map_or(u64::MAX, |w| {
            u64::try_from(w.saturating_duration_since(sh.epoch).as_nanos()).unwrap_or(u64::MAX)
        });
        sh.next_wake.store(nanos, Ordering::SeqCst);
        sh.idle.store(!flowing, Ordering::SeqCst);
        // A message queued before the stores above is collected now; one queued after them
        // reads them, and wakes this thread if it must (see `after` and `cancel`).
        if sh
            .shards
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|s| !s.lock().is_empty())
        {
            continue;
        }
        match wake {
            Some(w) => std::thread::park_timeout(w.saturating_duration_since(Instant::now())),
            None => std::thread::park(),
        }
    }
}

/// Runs `job` on the timer thread after `delay`, unless [`cancel`]led first. A delay too long
/// to represent never runs it.
pub(crate) fn after(delay: Duration, job: impl FnOnce() + Send + 'static) -> Key {
    let Some(at) = Instant::now().checked_add(delay) else {
        return Key(u64::MAX); // never runs; cancelling it does nothing
    };
    let sh = shared();
    let key = post(|key| Msg::Add(at, key, Box::new(job)));
    let due = u64::try_from(at.saturating_duration_since(sh.epoch).as_nanos()).unwrap_or(u64::MAX);
    if due < sh.next_wake.load(Ordering::SeqCst) {
        sh.thread.unpark();
    }
    Key(key)
}

/// Drops the job `key` names if it has not run: what it captured goes within [`LAZY`], not
/// when its delay would have passed. Cancelling one that ran, or twice, does nothing.
pub(crate) fn cancel(key: Key) {
    let sh = shared();
    post(|_| Msg::Cancel(key.0));
    if sh.idle.load(Ordering::SeqCst) && sh.idle.swap(false, Ordering::SeqCst) {
        sh.thread.unpark();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, mpsc};

    /// Waits up to 10 s for `cond`.
    fn eventually(cond: impl Fn() -> bool) -> bool {
        let start = Instant::now();
        while !cond() {
            if start.elapsed() > Duration::from_secs(10) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }

    /// A job cancelled on another thread than the one that scheduled it (its add and its cancel
    /// sit on different shards) is dropped all the same, long before its delay, and never runs;
    /// so is one cancelled while the timer thread sleeps with nothing in flight.
    #[test]
    fn cancels_from_other_threads_and_while_idle() {
        let held = Arc::new(());
        let ran = Arc::new(AtomicUsize::new(0));
        let mut keys = Vec::new();
        for _ in 0..1000 {
            let (h, r) = (held.clone(), ran.clone());
            keys.push(after(Duration::from_secs(3600), move || {
                drop(h);
                r.fetch_add(1, Ordering::SeqCst);
            }));
        }
        std::thread::spawn(move || keys.into_iter().for_each(cancel))
            .join()
            .unwrap();
        assert!(eventually(|| Arc::strong_count(&held) == 1));
        // Idle: the timer thread has collected everything and sleeps until 3600 s.
        let h = held.clone();
        let key = after(Duration::from_secs(3600), move || drop(h));
        std::thread::sleep(LAZY * 5);
        cancel(key);
        assert!(eventually(|| Arc::strong_count(&held) == 1));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }

    /// A job due before the timer thread's next wake-up wakes it; jobs scheduled by a thread
    /// that exited at once still run; keys are never repeated across threads.
    #[test]
    fn early_jobs_and_exited_threads() {
        let _late = after(Duration::from_secs(3600), || {});
        std::thread::sleep(LAZY * 5);
        let (tx, rx) = mpsc::channel();
        let t = Instant::now();
        let tx2 = tx.clone();
        after(Duration::from_millis(20), move || tx2.send(1).unwrap());
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(1));
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let keys: Vec<Vec<u64>> = (0..4)
            .map(|_| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut keys = Vec::new();
                    for _ in 0..100 {
                        let tx = tx.clone();
                        keys.push(
                            after(Duration::from_millis(5), move || tx.send(2).unwrap()).raw(),
                        );
                    }
                    keys
                })
            })
            .map(|t| t.join().unwrap())
            .collect();
        for _ in 0..400 {
            assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(2));
        }
        let mut all: Vec<u64> = keys.concat();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 400);
    }

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

    /// A job that panics does not stop the thread: later jobs still run.
    #[test]
    fn a_panicking_job_does_not_stop_the_timer() {
        after(Duration::ZERO, || panic!("a job panics"));
        let (tx, rx) = mpsc::channel();
        after(Duration::from_millis(20), move || tx.send(()).unwrap());
        rx.recv_timeout(Duration::from_secs(5))
            .expect("a job after a panicking one runs");
    }
}
