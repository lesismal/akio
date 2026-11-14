//! Loss recovery building blocks (RFC 9002): the RTT estimator, NewReno and CUBIC (RFC 9438)
//! congestion controllers, and a pacer.

use std::time::{Duration, Instant};

/// Timer granularity (RFC 9002 kGranularity).
pub const GRANULARITY: Duration = Duration::from_millis(1);

/// Packet reordering threshold (kPacketThreshold).
pub const PACKET_THRESHOLD: u64 = 3;

/// Persistent congestion threshold (kPersistentCongestionThreshold).
pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// RTT estimation (RFC 9002 section 5).
#[derive(Clone, Debug)]
pub struct Rtt {
    pub latest: Duration,
    pub smoothed: Duration,
    pub var: Duration,
    pub min: Duration,
    /// Whether a sample was taken.
    pub sampled: bool,
}

impl Rtt {
    pub fn new(initial: Duration) -> Rtt {
        Rtt {
            latest: initial,
            smoothed: initial,
            var: initial / 2,
            min: initial,
            sampled: false,
        }
    }

    /// Adds a sample; `ack_delay` is already capped by the peer's max_ack_delay once the
    /// handshake is confirmed.
    pub fn update(&mut self, latest: Duration, ack_delay: Duration) {
        self.latest = latest;
        if !self.sampled {
            self.sampled = true;
            self.min = latest;
            self.smoothed = latest;
            self.var = latest / 2;
            return;
        }
        self.min = self.min.min(latest);
        let mut adjusted = latest;
        if latest >= self.min + ack_delay {
            adjusted = latest.saturating_sub(ack_delay);
        }
        let diff = self.smoothed.abs_diff(adjusted);
        self.var = (self.var * 3 + diff) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }

    /// The probe timeout without backoff, excluding max_ack_delay.
    pub fn pto_base(&self) -> Duration {
        self.smoothed + (self.var * 4).max(GRANULARITY)
    }

    /// The loss time threshold: 9/8 of the larger of smoothed and latest RTT.
    pub fn loss_delay(&self) -> Duration {
        (self.latest.max(self.smoothed) * 9 / 8).max(GRANULARITY)
    }
}

/// Which congestion controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CcKind {
    NewReno,
    Cubic,
}

/// A congestion controller in bytes (RFC 9002 section 7 and RFC 9438).
#[derive(Clone, Debug)]
pub struct Congestion {
    kind: CcKind,
    pub window: u64,
    pub ssthresh: u64,
    mtu: u64,
    /// Bytes acknowledged towards the next window increase (NewReno avoidance).
    acked: u64,
    /// Packets sent before this time do not cause a new reduction.
    recovery_start: Option<Instant>,
    pub events: u64,
    // CUBIC state.
    w_max: f64,
    k: f64,
    epoch: Option<Instant>,
    w_est: f64,
}

const BETA_CUBIC: f64 = 0.7;
const C_CUBIC: f64 = 0.4;

impl Congestion {
    pub fn new(kind: CcKind, mtu: u16) -> Congestion {
        let mtu = u64::from(mtu);
        let w = initial_window(mtu);
        Congestion {
            kind,
            window: w,
            ssthresh: u64::MAX,
            mtu,
            acked: 0,
            recovery_start: None,
            events: 0,
            w_max: 0.0,
            k: 0.0,
            epoch: None,
            w_est: 0.0,
        }
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = u64::from(mtu);
        self.window = self.window.max(self.min_window());
    }

    fn min_window(&self) -> u64 {
        2 * self.mtu
    }

    pub fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|r| sent <= r)
    }

    /// `bytes` of a packet sent at `sent` were acknowledged.
    pub fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        rtt: &Rtt,
        app_limited: bool,
    ) {
        if self.in_recovery(sent) || app_limited {
            return;
        }
        if self.window < self.ssthresh {
            self.window += bytes;
            return;
        }
        match self.kind {
            CcKind::NewReno => {
                self.acked += bytes;
                if self.acked >= self.window {
                    self.acked -= self.window;
                    self.window += self.mtu;
                }
            }
            CcKind::Cubic => self.cubic_ack(now, bytes, rtt),
        }
    }

    fn cubic_ack(&mut self, now: Instant, bytes: u64, rtt: &Rtt) {
        let mss = self.mtu as f64;
        // A new avoidance epoch starts now if none is running.
        let epoch = *self.epoch.get_or_insert(now);
        if self.w_max == 0.0 {
            self.w_max = self.window as f64 / mss;
            self.k = 0.0;
            self.w_est = self.window as f64 / mss;
        }
        let t = (now - epoch + rtt.smoothed).as_secs_f64();
        let w_cubic = C_CUBIC * (t - self.k).powi(3) + self.w_max;
        // The Reno-friendly estimate (RFC 9438 section 4.3).
        let cwnd = self.window as f64 / mss;
        let alpha = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);
        self.w_est += alpha * (bytes as f64 / mss) / cwnd;
        let target = if w_cubic < self.w_est {
            self.w_est
        } else {
            // Grow towards W_cubic(t + RTT), at most 1.5x per RTT.
            w_cubic.min(cwnd * 1.5)
        };
        if target > cwnd {
            let inc = (target - cwnd) / cwnd * (bytes as f64 / mss);
            self.window += (inc * mss) as u64;
        }
    }

    /// A packet sent at `sent` was lost (or ECN-CE marked).
    pub fn on_congestion(&mut self, now: Instant, sent: Instant) {
        if self.in_recovery(sent) {
            return;
        }
        self.events += 1;
        self.recovery_start = Some(now);
        match self.kind {
            CcKind::NewReno => {
                self.window = (self.window / 2).max(self.min_window());
            }
            CcKind::Cubic => {
                let mss = self.mtu as f64;
                let cwnd = self.window as f64 / mss;
                // Fast convergence (RFC 9438 section 4.7).
                self.w_max = if cwnd < self.w_max {
                    cwnd * (1.0 + BETA_CUBIC) / 2.0
                } else {
                    cwnd
                };
                self.window = ((self.window as f64 * BETA_CUBIC) as u64).max(self.min_window());
                self.k = (self.w_max * (1.0 - BETA_CUBIC) / C_CUBIC).cbrt();
                self.w_est = self.window as f64 / mss;
                self.epoch = Some(now);
            }
        }
        self.ssthresh = self.window;
        self.acked = 0;
    }

    /// Persistent congestion (RFC 9002 section 7.6): back to the minimum window.
    pub fn on_persistent_congestion(&mut self) {
        self.window = self.min_window();
        self.recovery_start = None;
        self.w_max = 0.0;
        self.epoch = None;
    }

    /// A new path: start over.
    pub fn reset(&mut self) {
        *self = Congestion::new(self.kind, self.mtu as u16);
    }
}

fn initial_window(mtu: u64) -> u64 {
    (10 * mtu).min((2 * mtu).max(14720))
}

/// A token-bucket pacer spreading a window over the RTT (RFC 9002 section 7.7).
#[derive(Clone, Debug)]
pub struct Pacer {
    tokens: u64,
    capacity: u64,
    last: Option<Instant>,
}

impl Pacer {
    pub fn new() -> Pacer {
        Pacer {
            tokens: u64::MAX,
            capacity: 0,
            last: None,
        }
    }

    /// When a packet of `size` bytes may be sent, or `None` for now.
    pub fn delay(
        &mut self,
        now: Instant,
        size: u64,
        mtu: u64,
        window: u64,
        rtt: Duration,
    ) -> Option<Instant> {
        // Bursts of up to ~2 ms worth of window, at least 10 packets.
        let rtt = rtt.max(Duration::from_millis(1));
        let cap = ((u128::from(window) * 2_000_000 / rtt.as_nanos().max(1)) as u64)
            .clamp(10 * mtu, 256 * mtu)
            .min(window.max(10 * mtu));
        if cap != self.capacity {
            self.capacity = cap;
            self.tokens = self.tokens.min(cap);
        }
        let last = *self.last.get_or_insert(now);
        // Refill at 1.25 * window / rtt.
        let elapsed = now.saturating_duration_since(last);
        let refill = (u128::from(window) * 5 / 4 * elapsed.as_nanos() / rtt.as_nanos()) as u64;
        if refill > 0 {
            self.tokens = self.tokens.saturating_add(refill).min(cap);
            self.last = Some(now);
        }
        if self.tokens >= size {
            return None;
        }
        let missing = size - self.tokens;
        let nanos =
            (u128::from(missing) * rtt.as_nanos() * 4 / (u128::from(window.max(1)) * 5)) as u64;
        Some(now + Duration::from_nanos(nanos.max(1)))
    }

    pub fn on_sent(&mut self, size: u64) {
        self.tokens = self.tokens.saturating_sub(size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_estimates() {
        let mut r = Rtt::new(Duration::from_millis(333));
        assert_eq!(r.pto_base(), Duration::from_millis(333 + 666));
        r.update(Duration::from_millis(100), Duration::ZERO);
        assert_eq!(
            (r.smoothed, r.var, r.min),
            (
                Duration::from_millis(100),
                Duration::from_millis(50),
                Duration::from_millis(100)
            )
        );
        r.update(Duration::from_millis(120), Duration::from_millis(10));
        assert_eq!(r.smoothed, Duration::from_micros(101_250));
        r.update(Duration::from_millis(50), Duration::from_millis(100));
        assert_eq!(r.min, Duration::from_millis(50));
        assert!(r.loss_delay() >= r.smoothed);
    }

    #[test]
    fn newreno_and_cubic_windows() {
        let now = Instant::now();
        let rtt = Rtt::new(Duration::from_millis(10));
        for kind in [CcKind::NewReno, CcKind::Cubic] {
            let mut c = Congestion::new(kind, 1200);
            assert_eq!(c.window, 12000);
            c.on_ack(now, now, 1200, &rtt, false);
            assert_eq!(c.window, 13200);
            c.on_ack(now, now, 1200, &rtt, true);
            assert_eq!(c.window, 13200);
            let t1 = now + Duration::from_millis(5);
            c.on_congestion(t1, now);
            let reduced = c.window;
            assert!(reduced < 13200 && c.events == 1);
            // A loss of a packet sent before recovery started does not reduce again.
            c.on_congestion(t1 + Duration::from_millis(1), now);
            assert_eq!((c.window, c.events), (reduced, 1));
            // Congestion avoidance grows slowly.
            let t2 = t1 + Duration::from_millis(10);
            for i in 0..200 {
                c.on_ack(t2 + Duration::from_millis(i), t2, 1200, &rtt, false);
            }
            assert!(c.window > reduced, "{kind:?}");
            c.on_persistent_congestion();
            assert_eq!(c.window, 2400);
            c.set_mtu(1400);
            assert_eq!(c.window, 2800);
            c.reset();
            assert_eq!(c.window, 14000);
        }
    }

    #[test]
    fn pacer_spreads_bursts() {
        let now = Instant::now();
        let mut p = Pacer::new();
        let rtt = Duration::from_millis(100);
        let window = 100 * 1200;
        let mut sent = 0;
        while p.delay(now, 1200, 1200, window, rtt).is_none() {
            p.on_sent(1200);
            sent += 1;
        }
        assert!((10..=20).contains(&sent), "{sent}");
        let at = p.delay(now, 1200, 1200, window, rtt).unwrap();
        assert!(at > now && at < now + Duration::from_millis(5));
        assert!(
            p.delay(at + Duration::from_millis(1), 1200, 1200, window, rtt)
                .is_none()
        );
    }
}
