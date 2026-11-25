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
            .spawn(move || run(&rx))
            .expect("spawn akio-http timer thread");
        tx
    })
}

fn run(rx: &mpsc::Receiver<(Instant, Job)>) {
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
                // A panicking job (a user callback it reached) must not take the timer thread
                // down with it: every later job of the process would silently never run.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(j));
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
}

/// Runs `job` on the timer thread after `delay`.
pub(crate) fn after(delay: Duration, job: impl FnOnce() + Send + 'static) {
    let _ = sender().send((Instant::now() + delay, Box::new(job)));
}

#[cfg(test)]
mod tests {
    use super::*;

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
