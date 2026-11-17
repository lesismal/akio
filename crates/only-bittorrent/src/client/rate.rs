//! Token buckets for upload and download rate limits: one pair per torrent, one pair shared by
//! the client. A bucket refills at its rate, holds at most a fifth of a second's worth (but at
//! least one block), and may go into debt by one transfer: a block is sent or asked for while
//! any token is left, so a rate below a block a second still moves data.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::wire::BLOCK_SIZE;

#[derive(Debug)]
pub(crate) struct Bucket {
    rate: u64,
    tokens: i64,
    last: Instant,
}

impl Bucket {
    pub(crate) fn new(rate: Option<u64>) -> Bucket {
        let mut b = Bucket {
            rate: 0,
            tokens: 0,
            last: Instant::now(),
        };
        b.set_rate(rate);
        b
    }

    /// `None` or `Some(0)`: unlimited.
    pub(crate) fn set_rate(&mut self, rate: Option<u64>) {
        self.rate = rate.unwrap_or(0);
        self.tokens = self.cap();
        self.last = Instant::now();
    }

    pub(crate) fn rate(&self) -> Option<u64> {
        (self.rate > 0).then_some(self.rate)
    }

    fn cap(&self) -> i64 {
        (self.rate / 5)
            .max(u64::from(BLOCK_SIZE))
            .min(i64::MAX as u64) as i64
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last);
        let add = (u128::from(self.rate) * dt.as_micros() / 1_000_000).min(i64::MAX as u128) as i64;
        if add > 0 {
            self.tokens = self.tokens.saturating_add(add).min(self.cap());
            self.last = now;
        }
    }

    /// Whether a transfer may start now.
    pub(crate) fn ready(&mut self, now: Instant) -> bool {
        if self.rate == 0 {
            return true;
        }
        self.refill(now);
        self.tokens > 0
    }

    /// Counts a transfer of `n` bytes.
    pub(crate) fn take(&mut self, n: u64) {
        if self.rate > 0 {
            self.tokens = self.tokens.saturating_sub(n.min(i64::MAX as u64) as i64);
        }
    }
}

/// The client-wide buckets. Unlimited (the default) costs one relaxed load per check.
#[derive(Debug)]
pub(crate) struct GlobalRates {
    up_limited: AtomicBool,
    down_limited: AtomicBool,
    up: Mutex<Bucket>,
    down: Mutex<Bucket>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl GlobalRates {
    pub(crate) fn new(up: Option<u64>, down: Option<u64>) -> GlobalRates {
        let g = GlobalRates {
            up_limited: AtomicBool::new(false),
            down_limited: AtomicBool::new(false),
            up: Mutex::new(Bucket::new(None)),
            down: Mutex::new(Bucket::new(None)),
        };
        g.set(up, down);
        g
    }

    pub(crate) fn set(&self, up: Option<u64>, down: Option<u64>) {
        lock(&self.up).set_rate(up);
        lock(&self.down).set_rate(down);
        self.up_limited
            .store(up.is_some_and(|r| r > 0), Ordering::Relaxed);
        self.down_limited
            .store(down.is_some_and(|r| r > 0), Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> (Option<u64>, Option<u64>) {
        (lock(&self.up).rate(), lock(&self.down).rate())
    }

    pub(crate) fn up_ready(&self, now: Instant) -> bool {
        !self.up_limited.load(Ordering::Relaxed) || lock(&self.up).ready(now)
    }

    pub(crate) fn down_ready(&self, now: Instant) -> bool {
        !self.down_limited.load(Ordering::Relaxed) || lock(&self.down).ready(now)
    }

    pub(crate) fn up_take(&self, n: u64) {
        if self.up_limited.load(Ordering::Relaxed) {
            lock(&self.up).take(n);
        }
    }

    pub(crate) fn down_take(&self, n: u64) {
        if self.down_limited.load(Ordering::Relaxed) {
            lock(&self.down).take(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_rate() {
        let mut b = Bucket::new(Some(100_000));
        let t0 = Instant::now();
        let mut sent = 0u64;
        // Simulated clock: 2 s in 10 ms steps.
        for step in 0..200u64 {
            let now = t0 + Duration::from_millis(10 * step);
            while b.ready(now) {
                b.take(16384);
                sent += 16384;
            }
        }
        // 2 s at 100 kB/s plus the initial burst, give or take a block.
        assert!((180_000..=260_000).contains(&sent), "{sent}");
        let mut u = Bucket::new(None);
        assert!(u.ready(t0));
        u.take(u64::MAX);
        assert!(u.ready(t0));
    }
}
