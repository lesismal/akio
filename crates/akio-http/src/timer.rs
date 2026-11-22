//! A single lazily started thread that runs short deferred jobs (request timeouts of the
//! clients). Jobs must be quick: they only fail a request and close its connection.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::{
        OnceLock,
        mpsc::{self, RecvTimeoutError, Sender},
    },
    time::{Duration, Instant},
};

type Job = Box<dyn FnOnce() + Send>;

fn sender() -> &'static Sender<(Instant, Job)> {
    static TX: OnceLock<Sender<(Instant, Job)>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<(Instant, Job)>();
        std::thread::Builder::new()
            .name("akio-http-timer".into())
            .spawn(move || {
                let mut heap: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();
                let mut jobs: HashMap<u64, Job> = HashMap::new();
                let mut seq = 0u64;
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
                        Ok((at, job)) => {
                            seq += 1;
                            heap.push(Reverse((at, seq)));
                            jobs.insert(seq, job);
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

/// Runs `job` on the timer thread after `delay`.
pub(crate) fn after(delay: Duration, job: impl FnOnce() + Send + 'static) {
    let _ = sender().send((Instant::now() + delay, Box::new(job)));
}
