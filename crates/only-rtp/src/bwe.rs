//! A simple Google-congestion-control-like send-side bandwidth estimator
//! (draft-ietf-rmcat-gcc-02): a delay-gradient trendline detector driving an AIMD rate
//! controller, combined with loss-based control, capped by REMB and clamped to bounds.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::probe::{ProbeController, ProbePacket};
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
/// Network state estimate: probes go up to this multiple of it, and a further probe follows
/// only a result below the second multiple (libwebrtc's `network_state_scale` and
/// `further_probe_threshold`).
const NSE_SCALE: f64 = 1.0;
const NSE_FURTHER: f64 = 0.7;
/// Link capacity estimate (libwebrtc's `LinkCapacityEstimator`): smoothing of the acknowledged
/// rate at over-use and of probe results, and the bounds of the normalised deviation.
const LINK_ALPHA_OVERUSE: f64 = 0.05;
const LINK_ALPHA_PROBE: f64 = 0.5;
const LINK_DEV_MIN: f64 = 0.4;
const LINK_DEV_MAX: f64 = 2.5;

/// libwebrtc's `LinkCapacityEstimator`: an exponentially smoothed estimate of the link
/// capacity from the acknowledged rate at over-use and from probe results, with a deviation.
#[derive(Debug, Clone, Copy, Default)]
struct LinkCapacity {
    kbps: Option<f64>,
    dev: f64,
}

impl LinkCapacity {
    fn update(&mut self, sample_bps: f64, alpha: f64) {
        let sample = sample_bps / 1000.0;
        let est = match self.kbps {
            None => sample,
            Some(e) => (1.0 - alpha) * e + alpha * sample,
        };
        self.kbps = Some(est);
        let norm = est.max(1.0);
        let err = est - sample;
        self.dev =
            ((1.0 - alpha) * self.dev + alpha * err * err / norm).clamp(LINK_DEV_MIN, LINK_DEV_MAX);
    }

    /// (lower, upper) in bits per second: the estimate -/+ 3 deviations.
    fn bounds(&self) -> Option<(u64, u64)> {
        let e = self.kbps?;
        let d = (self.dev * e).sqrt();
        Some((
            ((e - 3.0 * d).max(0.0) * 1000.0) as u64,
            ((e + 3.0 * d) * 1000.0) as u64,
        ))
    }
}

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
/// - ECN (RFC 8888 feedback, [`PacketResult::ecn`]): a packet that arrived marked CE counts as
///   lost for the loss-based control, the classic ECN response (RFC 3168 §5).
/// - Probing (ADR-050, on unless [`with_probing(false)`](Self::with_probing)): short
///   clusters of probe packets paced at a target rate ([`poll_probe`](Self::poll_probe)) whose
///   feedback measures what the path delivers. It starts with probes at 3 and 6 times the start
///   rate and doubles while a result reaches 70 % of the last probe; it probes at twice the
///   estimate every 5 s while the sender is application-limited, and after a large drop of the
///   estimate (below 66 %) at up to 85 % of the earlier rate (when the queues have drained,
///   then every 3 s for 30 s); [`on_network_change`](Self::on_network_change) starts over. A
///   result raises both the delay-based and the loss-based rate unless the link is over-used.
///   Raising the maximum with [`set_bounds`](Self::set_bounds) probes at the new maximum
///   when the estimate is below it (libwebrtc's `SetBitrates`).
/// - Network state estimate (libwebrtc's `ProbeController` with a `NetworkStateEstimate`): with
///   one set ([`set_network_state_estimate`](Self::set_network_state_estimate), the upper
///   bound of the link capacity, from outside), probes never go above it (nor above the
///   estimate when that is higher), a further probe only follows a result below 70 % of it,
///   and it probes at twice the estimate (capped at it) every 5 s while the estimate is below
///   it, every 3 s while the delay-based rate holds the estimate below 70 % of it. Without
///   one, the estimator's own link capacity estimate ([`link_capacity`](Self::link_capacity):
///   the acknowledged rate at over-use and probe results, smoothed, plus three deviations)
///   drives the 3 s probes, without capping anything.
#[derive(Debug)]
pub struct BandwidthEstimator {
    initial: u64,
    probe: ProbeController,
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
    // network state
    link: LinkCapacity,
    network_estimate: Option<u64>,
    // ECN
    ect_received: u64,
    ce_received: u64,
}

impl BandwidthEstimator {
    /// An estimator starting at `initial_bps`.
    #[must_use]
    pub fn new(initial_bps: u64) -> BandwidthEstimator {
        let r = initial_bps as f64;
        BandwidthEstimator {
            initial: initial_bps,
            probe: ProbeController::new(true),
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
            link: LinkCapacity::default(),
            network_estimate: None,
            ect_received: 0,
            ce_received: 0,
        }
    }

    /// Sets the bounds of the estimate (bits per second).
    #[must_use]
    pub fn with_bounds(mut self, min_bps: u64, max_bps: u64) -> BandwidthEstimator {
        self.min = min_bps.min(max_bps);
        self.max = max_bps.max(min_bps);
        self
    }

    /// Changes the bounds at `now` (bits per second). A maximum raised above both the old one
    /// and the estimate starts a probe at the new maximum once the initial probing is over,
    /// as libwebrtc probes when the application allows more.
    pub fn set_bounds(&mut self, now: Instant, min_bps: u64, max_bps: u64) {
        let old_max = self.max;
        self.min = min_bps.min(max_bps);
        self.max = max_bps.max(min_bps);
        self.clamp_rates();
        if self.probe.enabled() && self.max > old_max {
            let e = self.estimate() as f64;
            let cap = self.max_probe();
            self.probe.on_max_raised(now, e, self.max as f64, cap);
        }
    }

    /// The bounds (min, max) in bits per second.
    #[must_use]
    pub fn bounds(&self) -> (u64, u64) {
        (self.min, self.max)
    }

    /// Sets (or with `None` removes) a network state estimate: the upper bound of the link
    /// capacity in bits per second, from a source outside the estimator (a remote estimate,
    /// a known access link). Probes stay below it and are sent toward it while the estimate is
    /// lower (see the type's documentation).
    pub fn set_network_state_estimate(&mut self, upper_bps: Option<u64>) {
        self.network_estimate = upper_bps;
        self.probe
            .set_further_limit(upper_bps.map_or(f64::INFINITY, |u| u as f64 * NSE_FURTHER));
    }

    /// The estimator's own link capacity estimate (lower, upper bound) in bits per second,
    /// once an over-use or a probe result gave one.
    #[must_use]
    pub fn link_capacity(&self) -> Option<(u64, u64)> {
        self.link.bounds()
    }

    /// Packets the feedback reported arriving ECN-capable (ECT(0), ECT(1) or CE), and those
    /// of them marked CE (congestion experienced), so far.
    #[must_use]
    pub fn ecn_counts(&self) -> (u64, u64) {
        (self.ect_received, self.ce_received)
    }

    /// Turns probing on (the default) or off. Without it the estimator only ever grows by its
    /// AIMD rules.
    #[must_use]
    pub fn with_probing(mut self, on: bool) -> BandwidthEstimator {
        self.probe = ProbeController::new(on);
        self
    }

    /// The probe packet to send at `now`, if one is due (call until `None`). The first call
    /// starts the initial probing. Send about `size` bytes (an RTX copy of recent media, or
    /// padding), log it with [`TwccSender::on_sent_probe`](crate::TwccSender::on_sent_probe)
    /// or [`CcfbSender::on_sent_probe`](crate::CcfbSender::on_sent_probe) and report it with
    /// [`on_probe_sent`](Self::on_probe_sent); a packet that cannot be sent is just not
    /// reported.
    pub fn poll_probe(&mut self, now: Instant) -> Option<ProbePacket> {
        if !self.probe.enabled() {
            return None;
        }
        let e = self.estimate() as f64;
        self.probe.start(now, e, self.max_probe());
        self.probe.poll(now)
    }

    /// When the next probe packet is due ([`poll_probe`](Self::poll_probe)).
    #[must_use]
    pub fn probe_timeout(&self) -> Option<Instant> {
        self.probe.timeout()
    }

    /// Drops the probe clusters waiting to be sent: the caller cannot send them now (no path,
    /// no stream to carry them), and [`probe_timeout`](Self::probe_timeout) must not stay due.
    pub fn cancel_probes(&mut self) {
        self.probe.cancel();
    }

    /// Reports a probe packet of `bytes` bytes of cluster `cluster` sent at `now`.
    pub fn on_probe_sent(&mut self, now: Instant, cluster: u32, bytes: usize) {
        self.probe.on_sent(now, cluster, bytes);
    }

    /// The path changed (a new ICE pair, an interface switch): the delay and loss state is
    /// dropped, the estimate goes back to the start rate and probing starts over.
    pub fn on_network_change(&mut self, now: Instant) {
        let fresh = BandwidthEstimator::new(self.initial).with_bounds(self.min, self.max);
        let remote = self.remote;
        let nse = self.network_estimate;
        let probe = std::mem::replace(&mut self.probe, ProbeController::new(false));
        *self = BandwidthEstimator { probe, ..fresh };
        self.remote = remote;
        self.probe.reset();
        self.set_network_state_estimate(nse);
        let e = self.estimate() as f64;
        self.probe.start(now, e, self.max_probe());
    }

    /// Whether the sender looks application-limited: the media it sent over the last 500 ms
    /// stays below about 60 % of the estimate (only tracked with probing on).
    #[must_use]
    pub fn application_limited(&self) -> bool {
        self.probe.alr()
    }

    fn max_probe(&self) -> f64 {
        let mut m = self.max as f64;
        if let Some(r) = self.remote {
            m = m.min(r as f64);
        }
        if let Some(n) = self.network_estimate {
            m = m.min((self.estimate() as f64).max(n as f64 * NSE_SCALE));
        }
        m
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
    /// Results of probe packets ([`PacketResult::probe`]) also measure their cluster's rate.
    pub fn on_packet_results(&mut self, now: Instant, results: &[PacketResult]) {
        let prev = self.estimate() as f64;
        let prev_usage = self.usage;
        let mut probed: Option<f64> = None;
        let mut sorted: Vec<&PacketResult> = results.iter().collect();
        sorted.sort_by_key(|r| r.seq);
        for r in &sorted {
            if r.probe.is_some() {
                if let Some(p) = self.probe.on_probe_result(now, r) {
                    probed = Some(p);
                }
            } else {
                self.probe.on_media_result(r);
            }
            self.loss_total += 1;
            match r.received {
                None => self.loss_lost += 1,
                Some(at) => {
                    if let Some(e @ 1..=3) = r.ecn {
                        self.ect_received += 1;
                        if e == 3 {
                            self.ce_received += 1;
                            self.loss_lost += 1;
                        }
                    }
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
        // A probe result lifts the estimate unless the link is over-used.
        if let Some(p) = probed.filter(|_| self.usage != BandwidthUsage::Overusing) {
            self.link.update(p, LINK_ALPHA_PROBE);
            let p = p.min(self.max_probe());
            if p > self.delay_rate {
                self.delay_rate = p;
                self.decrease_rate = None;
            }
            self.loss_rate = self.loss_rate.max(p);
        }
        self.update_loss(now);
        self.clamp_rates();
        if self.probe.enabled() {
            let e = self.estimate() as f64;
            let max = self.max_probe();
            let normal = self.usage == BandwidthUsage::Normal;
            let recovered = prev_usage == BandwidthUsage::Underusing && normal;
            self.probe.on_estimate(now, prev, e, max, normal, recovered);
            // Network state probing: from the estimate set from outside (periodic and when
            // low), else from the own link capacity estimate (when low).
            let delay_limited = self.delay_rate <= self.loss_rate;
            let (upper, external) = match self.network_estimate {
                Some(n) => (Some(n as f64), true),
                None => (self.link.bounds().map(|b| b.1 as f64), false),
            };
            if let Some(u) = upper.filter(|_| normal) {
                self.probe
                    .network_state_probe(now, e, u, external, delay_limited, max);
            }
        }
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
                    if let Some(a) = acked {
                        self.link.update(a, LINK_ALPHA_OVERUSE);
                    }
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
