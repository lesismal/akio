//! A single lazily started thread that runs short deferred jobs: hub wait timeouts, SRT and
//! RTSP periodic work, HLS segment expiry. Jobs must be quick and must not block.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    sync::{
        Mutex, OnceLock,
        mpsc::{self, RecvTimeoutError, Sender},
    },
    time::{Duration, Instant},
};

type Job = Box<dyn FnOnce() + Send>;

fn sender() -> &'static Mutex<Sender<(Instant, Job)>> {
    static TX: OnceLock<Mutex<Sender<(Instant, Job)>>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<(Instant, Job)>();
        std::thread::Builder::new()
            .name("flash-media-timer".into())
            .spawn(move || run(&rx))
            .expect("spawn the flash-media timer thread");
        Mutex::new(tx)
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
                // A panicking job must not take the timer thread down with it.
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
    let tx = sender().lock().unwrap_or_else(|p| p.into_inner()).clone();
    let _ = tx.send((Instant::now() + delay, Box::new(job)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_run_in_deadline_order() {
        let (tx, rx) = mpsc::channel();
        let t2 = tx.clone();
        after(Duration::from_millis(40), move || t2.send(2).unwrap());
        after(Duration::from_millis(5), move || tx.send(1).unwrap());
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
    }
}
