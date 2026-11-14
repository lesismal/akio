//! A simple Google-congestion-control-like send-side bandwidth estimator
//! (draft-ietf-rmcat-gcc-02): a delay-gradient trendline detector driving an AIMD rate
//! controller, combined with loss-based control, capped by REMB and clamped to bounds.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::twcc::PacketResult;

/// Default lower bound of the estimate (bits per second).
pub const DEFAULT_MIN_BITRATE: u64 = 30_000;
/// Default upper bound of the estimate (bits per second).
pub const DEFAULT_MAX_BITRATE: u64 = 20_000_000;

/// Packets sent within this span form one group (a burst).
const BURST: Duration = Duration::from_millis(5);
/// Trendline regression window (groups).
const WINDOW: usize = 20;
const SMOOTHING: f64 = 0.9;
const THRESHOLD_GAIN: f64 = 4.0;
const K_UP: f64 = 0.0087;
const K_DOWN: f64 = 0.039;
const OVERUSE_TIME_MS: f64 = 10.0;
/// Multiplicative decrease factor on overuse.
const BETA: f64 = 0.85;
/// Window for the acknowledged (received) bitrate.
const ACK_WINDOW: Duration = Duration::from_millis(500);
/// Minimum interval between loss-based updates.
const LOSS_INTERVAL: Duration = Duration::from_millis(200);

/// The detector's view of the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthUsage {
    /// Queuing delay is stable.
    Normal,
    /// Queuing delay is growing: the link is over-used.
    Overusing,
    /// Queuing delay is shrinking (queues draining).
    Underusing,
}

#[derive(Debug, Clone, Copy)]
struct Group {
    first_sent: Instant,
    last_sent: Instant,
    last_recv: Instant,
}

/// Send-side bandwidth estimator fed with transport-wide feedback results.
///
/// - Delay-based: packets are grouped in 5 ms send bursts; the inter-group delay variation
///   (arrival spacing minus send spacing) is accumulated, smoothed and fitted with a
///   linear regression over 20 groups. The slope, scaled by the number of samples and a gain
///   of 4, is compared to an adaptive threshold (6..600 ms, starting at 12.5 ms): over it for
///   more than 10 ms is over-use, under its negative is under-use.
/// - Rate control: over-use cuts the rate to 0.85 x the acknowledged (received) bitrate;
///   normal use grows it 8 % per second, or additively (about one packet per RTT) once it
///   is near the rate of the last decrease; under-use holds. The rate never exceeds 1.5 x the
///   acknowledged bitrate + 10 kbps, so it does not run away while the sender is
///   application-limited.
/// - Loss-based: at most every 200 ms and per at least 20 results, loss above 10 % multiplies the loss-based
///   rate by `1 - loss / 2`, loss below 2 % grows it by 8 %.
/// - The estimate is the minimum of both and of the last REMB
///   ([`set_remote_estimate`](Self::set_remote_estimate)), clamped to
///   [`with_bounds`](Self::with_bounds) (default 30 kbps .. 20 Mbps).
#[derive(Debug)]
pub struct BandwidthEstimator {
    min: u64,
    max: u64,
    delay_rate: f64,
    loss_rate: f64,
    remote: Option<u64>,
    // trendline
    group: Option<Group>,
    prev_group: Option<Group>,
    first_arrival: Option<Instant>,
    accumulated: f64,
    smoothed: f64,
    samples: VecDeque<(f64, f64)>,
    num_deltas: usize,
    threshold: f64,
    last_threshold_update: Option<Instant>,
    prev_trend: f64,
    overuse_time: Option<f64>,
    overuse_count: u32,
    usage: BandwidthUsage,
    // rate control
    last_update: Option<Instant>,
    last_decrease: Option<Instant>,
    decrease_rate: Option<f64>,
    acked: VecDeque<(Instant, usize)>,
    // loss
    loss_lost: usize,
    loss_total: usize,
    last_loss_update: Option<Instant>,
}

impl BandwidthEstimator {
    /// An estimator starting at `initial_bps`.
    #[must_use]
    pub fn new(initial_bps: u64) -> BandwidthEstimator {
        let r = initial_bps as f64;
        BandwidthEstimator {
            min: DEFAULT_MIN_BITRATE,
            max: DEFAULT_MAX_BITRATE,
            delay_rate: r,
            loss_rate: r,
            remote: None,
            group: None,
            prev_group: None,
            first_arrival: None,
            accumulated: 0.0,
            smoothed: 0.0,
            samples: VecDeque::new(),
            num_deltas: 0,
            threshold: 12.5,
            last_threshold_update: None,
            prev_trend: 0.0,
            overuse_time: None,
            overuse_count: 0,
            usage: BandwidthUsage::Normal,
            last_update: None,
            last_decrease: None,
            decrease_rate: None,
            acked: VecDeque::new(),
            loss_lost: 0,
            loss_total: 0,
            last_loss_update: None,
        }
    }

    /// Sets the bounds of the estimate (bits per second).
    #[must_use]
    pub fn with_bounds(mut self, min_bps: u64, max_bps: u64) -> BandwidthEstimator {
        self.min = min_bps.min(max_bps);
        self.max = max_bps.max(min_bps);
        self
    }

    /// Caps the estimate at a receiver estimate (REMB); `0` removes the cap.
    pub fn set_remote_estimate(&mut self, bps: u64) {
        self.remote = (bps > 0).then_some(bps);
    }

    /// The current estimate in bits per second.
    #[must_use]
    pub fn estimate(&self) -> u64 {
        let mut e = self.delay_rate.min(self.loss_rate);
        if let Some(r) = self.remote {
            e = e.min(r as f64);
        }
        (e.max(0.0) as u64).clamp(self.min, self.max)
    }

    /// The delay detector's current state.
    #[must_use]
    pub fn usage(&self) -> BandwidthUsage {
        self.usage
    }

    /// The bitrate acknowledged as received over the last 500 ms, if known.
    #[must_use]
    pub fn acknowledged_bitrate(&self) -> Option<u64> {
        let (first, last) = (self.acked.front()?.0, self.acked.back()?.0);
        let span = last
            .saturating_duration_since(first)
            .max(Duration::from_millis(100));
        let bytes: usize = self.acked.iter().map(|&(_, s)| s).sum();
        Some((bytes as f64 * 8.0 / span.as_secs_f64()) as u64)
    }

    /// Feeds the results of one feedback ([`TwccSender::on_feedback`](crate::TwccSender::on_feedback)).
    pub fn on_packet_results(&mut self, now: Instant, results: &[PacketResult]) {
        let mut sorted: Vec<&PacketResult> = results.iter().collect();
        sorted.sort_by_key(|r| r.seq);
        for r in &sorted {
            self.loss_total += 1;
            match r.received {
                None => self.loss_lost += 1,
                Some(at) => {
                    self.acked.push_back((at, r.size));
                    self.on_arrival(r.sent, at);
                }
            }
        }
        while let (Some(&(f, _)), Some(&(l, _))) = (self.acked.front(), self.acked.back()) {
            if l.saturating_duration_since(f) > ACK_WINDOW {
                self.acked.pop_front();
            } else {
                break;
            }
        }
        self.update_rate(now);
        self.update_loss(now);
        self.clamp_rates();
    }

    fn clamp_rates(&mut self) {
        let (min, max) = (self.min as f64, self.max as f64);
        self.delay_rate = self.delay_rate.clamp(min, max);
        self.loss_rate = self.loss_rate.clamp(min, max);
    }

    fn on_arrival(&mut self, sent: Instant, recv: Instant) {
        let Some(g) = self.group.as_mut() else {
            self.group = Some(Group {
                first_sent: sent,
                last_sent: sent,
                last_recv: recv,
            });
            return;
        };
        if sent < g.first_sent {
            return; // reordered into an older group
        }
        if sent.saturating_duration_since(g.first_sent) <= BURST {
            g.last_sent = g.last_sent.max(sent);
            g.last_recv = g.last_recv.max(recv);
            return;
        }
        let done = *g;
        self.group = Some(Group {
            first_sent: sent,
            last_sent: sent,
            last_recv: recv,
        });
        if let Some(prev) = self.prev_group {
            let send_delta = ms(done.last_sent, prev.last_sent);
            let recv_delta = ms(done.last_recv, prev.last_recv);
            self.trendline(send_delta, recv_delta, done.last_recv);
        }
        self.prev_group = Some(done);
    }

    fn trendline(&mut self, send_delta: f64, recv_delta: f64, arrival: Instant) {
        let first = *self.first_arrival.get_or_insert(arrival);
        let d = recv_delta - send_delta;
        self.num_deltas = (self.num_deltas + 1).min(1000);
        self.accumulated += d;
        self.smoothed = SMOOTHING * self.smoothed + (1.0 - SMOOTHING) * self.accumulated;
        self.samples.push_back((ms(arrival, first), self.smoothed));
        if self.samples.len() > WINDOW {
            self.samples.pop_front();
        }
        let trend = if self.samples.len() == WINDOW {
            slope(&self.samples).unwrap_or(self.prev_trend)
        } else {
            self.prev_trend
        };
        self.detect(trend, send_delta, arrival);
    }

    fn detect(&mut self, trend: f64, send_delta: f64, now: Instant) {
        let modified = self.num_deltas.min(60) as f64 * trend * THRESHOLD_GAIN;
        if modified > self.threshold {
            let t = match self.overuse_time {
                None => send_delta / 2.0,
                Some(t) => t + send_delta,
            };
            self.overuse_time = Some(t);
            self.overuse_count += 1;
            if t > OVERUSE_TIME_MS && self.overuse_count > 1 && trend >= self.prev_trend {
                self.overuse_time = Some(0.0);
                self.overuse_count = 0;
                self.usage = BandwidthUsage::Overusing;
            }
        } else if modified < -self.threshold {
            self.overuse_time = None;
            self.overuse_count = 0;
            self.usage = BandwidthUsage::Underusing;
        } else {
            self.overuse_time = None;
            self.overuse_count = 0;
            self.usage = BandwidthUsage::Normal;
        }
        self.prev_trend = trend;
        // Adaptive threshold.
        let last = *self.last_threshold_update.get_or_insert(now);
        if modified.abs() <= self.threshold + 15.0 {
            let k = if modified.abs() < self.threshold {
                K_DOWN
            } else {
                K_UP
            };
            let dt = ms(now, last).min(100.0);
            self.threshold += k * (modified.abs() - self.threshold) * dt;
            self.threshold = self.threshold.clamp(6.0, 600.0);
        }
        self.last_threshold_update = Some(now);
    }

    fn update_rate(&mut self, now: Instant) {
        let last = self.last_update.replace(now);
        let dt = last.map_or(0.0, |l| {
            now.saturating_duration_since(l).as_secs_f64().min(1.0)
        });
        let acked = self.acknowledged_bitrate().map(|a| a as f64);
        match self.usage {
            BandwidthUsage::Overusing => {
                let recently = self
                    .last_decrease
                    .is_some_and(|t| now.saturating_duration_since(t) < Duration::from_millis(200));
                if !recently {
                    let base = acked.unwrap_or(self.delay_rate);
                    let new = (BETA * base).min(self.delay_rate);
                    self.delay_rate = new;
                    self.decrease_rate = Some(new);
                    self.last_decrease = Some(now);
                }
            }
            BandwidthUsage::Underusing => {}
            BandwidthUsage::Normal => {
                let before = self.delay_rate;
                let near = self
                    .decrease_rate
                    .is_some_and(|d| self.delay_rate < 1.3 * d / BETA);
                if near {
                    // About one 1200-byte packet per 200 ms "RTT", per second.
                    self.delay_rate += dt * 1200.0 * 8.0 * 5.0;
                } else {
                    self.decrease_rate = None;
                    self.delay_rate *= 1.08f64.powf(dt);
                }
                // Increases stop at 1.5 x acknowledged + 10 kbps (the cap never decreases).
                if let Some(a) = acked {
                    self.delay_rate = self.delay_rate.min((1.5 * a + 10_000.0).max(before));
                }
            }
        }
    }

    fn update_loss(&mut self, now: Instant) {
        let recent = self
            .last_loss_update
            .is_some_and(|t| now.saturating_duration_since(t) < LOSS_INTERVAL);
        if self.loss_total < 20 || recent {
            return;
        }
        self.last_loss_update = Some(now);
        let loss = self.loss_lost as f64 / self.loss_total as f64;
        self.loss_lost = 0;
        self.loss_total = 0;
        if loss > 0.10 {
            self.loss_rate = self.estimate() as f64 * (1.0 - 0.5 * loss);
        } else if loss < 0.02 {
            self.loss_rate = (self.loss_rate * 1.08).max(self.estimate() as f64);
        }
    }
}

fn ms(a: Instant, b: Instant) -> f64 {
    if a >= b {
        a.saturating_duration_since(b).as_secs_f64() * 1000.0
    } else {
        -(b.saturating_duration_since(a).as_secs_f64() * 1000.0)
    }
}

/// Least-squares slope of `(x, y)` points.
fn slope(points: &VecDeque<(f64, f64)>) -> Option<f64> {
    let n = points.len() as f64;
    let (sx, sy) = points
        .iter()
        .fold((0.0, 0.0), |(a, b), &(x, y)| (a + x, b + y));
    let (mx, my) = (sx / n, sy / n);
    let (num, den) = points.iter().fold((0.0, 0.0), |(n, d), &(x, y)| {
        (n + (x - mx) * (y - my), d + (x - mx) * (x - mx))
    });
    (den != 0.0).then(|| num / den)
}
