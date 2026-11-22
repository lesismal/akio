//! Round-trip time estimation and retransmission timeout (RFC 6298), and congestion control:
//! NewReno (RFC 5681 / RFC 6582) and CUBIC (RFC 9438).

use std::time::{Duration, Instant};

/// Lower bound of the retransmission timeout (Linux's 200 ms rather than RFC 6298's 1 s: the
/// stack targets data-center and LAN paths).
pub(crate) const MIN_RTO: Duration = Duration::from_millis(200);
pub(crate) const MAX_RTO: Duration = Duration::from_secs(60);
pub(crate) const INITIAL_RTO: Duration = Duration::from_secs(1);

/// RFC 6298 estimator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rtt {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    /// Smallest sample seen (CUBIC's delay floor, diagnostics).
    pub(crate) min: Option<Duration>,
}

impl Default for Rtt {
    fn default() -> Rtt {
        Rtt {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
            min: None,
        }
    }
}

impl Rtt {
    pub(crate) fn sample(&mut self, r: Duration) {
        self.min = Some(self.min.map_or(r, |m| m.min(r)));
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                let diff = s.abs_diff(r);
                // rttvar = 3/4 rttvar + 1/4 |srtt - r|; srtt = 7/8 srtt + 1/8 r
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((s * 7 + r) / 8);
            }
        }
        let s = self.srtt.unwrap_or(r);
        // RFC 6298 with G = 1 ms.
        self.rto = (s + (self.rttvar * 4).max(Duration::from_millis(1))).clamp(MIN_RTO, MAX_RTO);
    }

    pub(crate) fn rto(&self) -> Duration {
        self.rto
    }

    pub(crate) fn srtt(&self) -> Option<Duration> {
        self.srtt
    }
}

/// Which congestion controller a connection uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum CcKind {
    NewReno,
    #[default]
    Cubic,
}

/// CUBIC constants (RFC 9438 section 4).
const C: f64 = 0.4;
const BETA: f64 = 0.7;

#[derive(Clone, Copy, Debug, Default)]
struct Cubic {
    /// Window before the last reduction, in segments.
    w_max: f64,
    /// Start of the current congestion-avoidance epoch.
    epoch: Option<Instant>,
    /// Time to reach `w_max` from the epoch start, seconds.
    k: f64,
    /// Reno-friendly estimate, segments.
    w_est: f64,
    /// Byte counter for sub-segment increments.
    acked: u64,
}

/// Congestion state: window, slow-start threshold and the controller's own state. Windows are in
/// bytes; `mss` is passed on each call (it can shrink with path MTU).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cc {
    pub(crate) kind: CcKind,
    pub(crate) cwnd: u32,
    pub(crate) ssthresh: u32,
    cubic: Cubic,
    /// Bytes acked in congestion avoidance (NewReno's appropriate byte counting).
    ca_acked: u32,
}

impl Cc {
    /// RFC 6928 initial window (10 segments, at most 14600 bytes... applied as 10 * mss).
    pub(crate) fn new(kind: CcKind, mss: u32) -> Cc {
        Cc {
            kind,
            cwnd: 10 * mss,
            ssthresh: u32::MAX,
            cubic: Cubic::default(),
            ca_acked: 0,
        }
    }

    pub(crate) fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// `acked` new bytes were acknowledged outside loss recovery.
    pub(crate) fn on_ack(&mut self, acked: u32, mss: u32, now: Instant, rtt: &Rtt) {
        if acked == 0 {
            return;
        }
        if self.in_slow_start() {
            // RFC 5681 / RFC 3465 byte counting, without the L limit: one ACK may cover a whole
            // receive burst (ACKs are coalesced per burst, like stretch ACKs under GRO).
            self.cwnd = self
                .cwnd
                .saturating_add(acked.min(self.ssthresh - self.cwnd).max(1));
            return;
        }
        match self.kind {
            CcKind::NewReno => {
                self.ca_acked = self.ca_acked.saturating_add(acked);
                if self.ca_acked >= self.cwnd {
                    self.ca_acked -= self.cwnd;
                    self.cwnd = self.cwnd.saturating_add(mss);
                }
            }
            CcKind::Cubic => self.cubic_ack(acked, mss, now, rtt),
        }
    }

    fn cubic_ack(&mut self, acked: u32, mss: u32, now: Instant, rtt: &Rtt) {
        let m = f64::from(mss.max(1));
        let cwnd = f64::from(self.cwnd) / m;
        let cu = &mut self.cubic;
        let epoch = *cu.epoch.get_or_insert_with(|| {
            // A new epoch (first ack in congestion avoidance after slow start or a reduction).
            if cu.w_max < cwnd {
                cu.k = 0.0;
                cu.w_max = cwnd;
            } else {
                cu.k = ((cu.w_max - cwnd) / C).cbrt();
            }
            cu.w_est = cwnd;
            cu.acked = 0;
            now
        });
        let rtt = rtt
            .srtt()
            .unwrap_or(Duration::from_millis(100))
            .as_secs_f64();
        let t = now.saturating_duration_since(epoch).as_secs_f64();
        let w_cubic = |t: f64| C * (t - cu.k).powi(3) + cu.w_max;
        // Reno-friendly region (RFC 9438 4.3): alpha = 3 (1 - beta) / (1 + beta).
        let alpha = 3.0 * (1.0 - BETA) / (1.0 + BETA);
        let segs = f64::from(acked) / m;
        cu.w_est += alpha * segs / cwnd;
        let target = w_cubic(t + rtt).clamp(cwnd, 1.5 * cwnd);
        let next = if w_cubic(t) < cu.w_est {
            cu.w_est.max(cwnd)
        } else {
            // Concave / convex region: grow by (target - cwnd) / cwnd segments per segment acked.
            cwnd + (target - cwnd) / cwnd * segs
        };
        // Accumulate fractional growth in bytes.
        let grow = ((next - cwnd) * m).max(0.0);
        cu.acked += grow as u64;
        let whole = cu.acked.min(u64::from(u32::MAX)) as u32;
        cu.acked -= u64::from(whole);
        self.cwnd = self.cwnd.saturating_add(whole);
    }

    /// Loss detected by duplicate ACKs / SACK (fast retransmit): returns the new ssthresh and
    /// sets cwnd to it (the caller enters recovery). `flight` is the bytes in flight.
    pub(crate) fn on_loss(&mut self, flight: u32, mss: u32) -> u32 {
        let ss = match self.kind {
            CcKind::NewReno => (flight / 2).max(2 * mss),
            CcKind::Cubic => {
                let m = f64::from(mss.max(1));
                let cwnd = f64::from(self.cwnd) / m;
                let cu = &mut self.cubic;
                // Fast convergence (RFC 9438 4.7).
                cu.w_max = if cwnd < cu.w_max {
                    cwnd * (1.0 + BETA) / 2.0
                } else {
                    cwnd
                };
                cu.epoch = None;
                ((f64::from(self.cwnd) * BETA) as u32).max(2 * mss)
            }
        };
        self.ssthresh = ss;
        self.cwnd = ss;
        self.ca_acked = 0;
        ss
    }

    /// Retransmission timeout: one segment, ssthresh halved (RFC 5681 / RFC 9438 4.8).
    pub(crate) fn on_rto(&mut self, flight: u32, mss: u32) {
        let before = self.cwnd;
        self.on_loss(flight, mss);
        if self.kind == CcKind::NewReno {
            self.ssthresh = (flight / 2).max(2 * mss);
        } else {
            self.ssthresh = ((f64::from(before) * BETA) as u32).max(2 * mss);
        }
        self.cwnd = mss;
    }

    /// Leaving fast recovery (RFC 6582): deflate to ssthresh.
    pub(crate) fn on_recovered(&mut self, flight: u32, mss: u32) {
        self.cwnd = self.ssthresh.min(flight.max(mss) + mss).max(2 * mss);
        if self.kind == CcKind::Cubic {
            self.cwnd = self.ssthresh.max(2 * mss);
        }
    }

    /// Restart after idle (RFC 5681 4.1 / RFC 7661 not applied: only when cwnd exceeds the
    /// restart window after an RTO-long pause).
    pub(crate) fn on_idle(&mut self, mss: u32) {
        let rw = 10 * mss;
        if self.cwnd > rw {
            self.cwnd = rw;
            self.cubic.epoch = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rto_follows_rfc6298() {
        let mut r = Rtt::default();
        assert_eq!(r.rto(), INITIAL_RTO);
        r.sample(Duration::from_millis(100));
        // srtt 100, rttvar 50: rto = 100 + 200 = 300 ms.
        assert_eq!(r.rto(), Duration::from_millis(300));
        for _ in 0..50 {
            r.sample(Duration::from_millis(10));
        }
        assert_eq!(r.rto(), MIN_RTO);
        r.sample(Duration::from_secs(1000));
        assert_eq!(r.rto(), MAX_RTO);
    }

    #[test]
    fn newreno_slow_start_and_avoidance() {
        let now = Instant::now();
        let rtt = Rtt::default();
        let mut c = Cc::new(CcKind::NewReno, 1000);
        assert_eq!(c.cwnd, 10_000);
        c.on_ack(1000, 1000, now, &rtt);
        assert_eq!(c.cwnd, 11_000);
        c.on_ack(5000, 1000, now, &rtt);
        assert_eq!(c.cwnd, 16_000);
        c.cwnd = 11_000;
        let ss = c.on_loss(20_000, 1000);
        assert_eq!(ss, 10_000);
        assert!(!c.in_slow_start());
        // One cwnd of acks grows cwnd by one segment.
        for _ in 0..10 {
            c.on_ack(1000, 1000, now, &rtt);
        }
        assert_eq!(c.cwnd, 11_000);
        c.on_rto(11_000, 1000);
        assert_eq!(c.cwnd, 1000);
        assert_eq!(c.ssthresh, 5500);
    }

    #[test]
    fn cubic_reduces_by_beta_and_regrows() {
        let t0 = Instant::now();
        let mut rtt = Rtt::default();
        rtt.sample(Duration::from_millis(100));
        let mut c = Cc::new(CcKind::Cubic, 1000);
        c.cwnd = 100_000;
        c.ssthresh = 100_000;
        c.on_loss(100_000, 1000);
        assert_eq!(c.cwnd, 70_000);
        // Ack a window per 100 ms RTT for 2 s: concave growth towards w_max (K = cbrt(30 / 0.4)
        // ~ 4.2 s), monotonic, not past it yet.
        let mut last = c.cwnd;
        for i in 1..=20u64 {
            let now = t0 + Duration::from_millis(100 * i);
            let w = c.cwnd;
            c.on_ack(w, 1000, now, &rtt);
            assert!(c.cwnd >= last);
            last = c.cwnd;
        }
        assert!(c.cwnd > 80_000 && c.cwnd < 100_000, "cwnd {}", c.cwnd);
        // After K the window exceeds w_max (convex region).
        for i in 21..=70u64 {
            let now = t0 + Duration::from_millis(100 * i);
            let w = c.cwnd;
            c.on_ack(w, 1000, now, &rtt);
        }
        assert!(c.cwnd > 105_000, "cwnd {}", c.cwnd);
        // At a short RTT the Reno-friendly estimate dominates (RFC 9438 4.3).
        let mut r = Rtt::default();
        r.sample(Duration::from_millis(1));
        let mut d = Cc::new(CcKind::Cubic, 1000);
        d.cwnd = 100_000;
        d.ssthresh = 100_000;
        d.on_loss(100_000, 1000);
        for i in 1..=1000u64 {
            let w = d.cwnd;
            d.on_ack(w, 1000, t0 + Duration::from_millis(i), &r);
        }
        assert!(d.cwnd > 300_000, "cwnd {}", d.cwnd);
    }
}
