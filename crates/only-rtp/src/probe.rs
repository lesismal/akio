//! Bandwidth probing for [`BandwidthEstimator`](crate::BandwidthEstimator) (ADR-050), after
//! libwebrtc's `ProbeController`, `BitrateProber` and `ProbeBitrateEstimator`: when to probe
//! and at what rate, how to pace a probe cluster, and what rate a cluster's feedback shows.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::twcc::PacketResult;

/// First initial probe, as a multiple of the start rate.
const FIRST_SCALE: f64 = 3.0;
/// Second initial probe.
const SECOND_SCALE: f64 = 6.0;
/// Further probes (after a result above [`FURTHER_THRESHOLD`] of the last probe).
const FURTHER_SCALE: f64 = 2.0;
const FURTHER_THRESHOLD: f64 = 0.7;
/// Probing stops when no result reaches the threshold within this time.
const WAIT_FOR_RESULT: Duration = Duration::from_secs(1);
/// Probes while application-limited.
const ALR_INTERVAL: Duration = Duration::from_secs(5);
const ALR_SCALE: f64 = 2.0;
/// A new estimate below this fraction of the previous one is a large drop.
const DROP_THRESHOLD: f64 = 0.66;
/// Recovery probes aim at this fraction of the rate before the drop.
const AFTER_DROP: f64 = 0.85;
/// Recovery probes are sent this long after a drop, at most every [`RECOVERY_INTERVAL`].
const RECOVERY_WINDOW: Duration = Duration::from_secs(30);
const RECOVERY_INTERVAL: Duration = Duration::from_secs(3);
/// The first recovery probe goes when the delay detector is back to normal (under-use turned
/// normal, or this long after the drop).
const RECOVERY_SETTLE: Duration = Duration::from_millis(500);
/// A cluster lasts at least this long and has at least [`MIN_PACKETS`] packets.
const MIN_DURATION: Duration = Duration::from_millis(15);
const MIN_PACKETS: u32 = 5;
/// Packets per cluster the prober aims at (more than [`MIN_PACKETS`], so that a lost packet
/// moves the result less), and the sizes it asks for.
const PACKETS_WANTED: usize = 10;
const MIN_PACKET: usize = 200;
const MAX_PACKET: usize = 1200;
/// Clusters waiting to be sent; an unstarted cluster older than [`CLUSTER_TIMEOUT`] is dropped.
const MAX_QUEUED: usize = 4;
const CLUSTER_TIMEOUT: Duration = Duration::from_secs(1);
/// Clusters whose feedback is evaluated; older ones are forgotten.
const MAX_TRACKED: usize = 16;
/// Probe packets measured per cluster.
const MAX_CLUSTER_PACKETS: usize = 256;
const CLUSTER_HISTORY: Duration = Duration::from_secs(1);
/// A result needs this fraction of the cluster's packets and bytes.
const MIN_RECEIVED: f64 = 0.8;
/// Receive / send rate above this: the measurement is broken.
const MAX_VALID_RATIO: f64 = 2.0;
/// Receive rate below this fraction of the send rate: the link is saturated.
const SATURATED_RATIO: f64 = 0.9;
/// A saturated cluster reports this fraction of its receive rate.
const TARGET_UTILIZATION: f64 = 0.95;
/// Application-limited: the media send rate stays below this fraction of the estimate
/// (enter), or goes above the second (leave).
const ALR_ENTER: f64 = 0.6;
const ALR_LEAVE: f64 = 0.7;
/// Window of the media send rate.
const SEND_WINDOW: Duration = Duration::from_millis(500);
/// Media packets kept for that window at most (about 40 Mbps of 1200-byte packets).
const MAX_MEDIA: usize = 2048;
const MIN_SEND_SPAN: Duration = Duration::from_millis(200);

/// One probe packet to send now: about `size` bytes (RTX of recent media or padding), logged
/// with [`TwccSender::on_sent_probe`](crate::TwccSender::on_sent_probe) (or
/// [`CcfbSender::on_sent_probe`](crate::CcfbSender::on_sent_probe)) under `cluster` and
/// reported with [`BandwidthEstimator::on_probe_sent`](crate::BandwidthEstimator::on_probe_sent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePacket {
    /// The probe cluster id.
    pub cluster: u32,
    /// Suggested size in bytes (any size works; the pacing follows what is reported sent).
    pub size: usize,
}

#[derive(Debug, Clone, Copy)]
struct Cluster {
    id: u32,
    bitrate: f64,
    min_bytes: usize,
    created: Instant,
    started: Option<Instant>,
    sent_bytes: usize,
    sent_packets: u32,
}

impl Cluster {
    fn done(&self) -> bool {
        self.sent_bytes >= self.min_bytes && self.sent_packets >= MIN_PACKETS
    }

    /// When the next packet is due: the bytes sent so far at the cluster's rate.
    fn due(&self) -> Instant {
        match self.started {
            None => self.created,
            Some(s) => s + Duration::from_secs_f64(self.sent_bytes as f64 * 8.0 / self.bitrate),
        }
    }
}

/// A received packet: (sent, received, size).
type Arrival = (Instant, Instant, usize);

/// The received probe packets of one cluster.
#[derive(Debug)]
struct Measure {
    id: u32,
    min_bytes: usize,
    created: Instant,
    probes: Vec<Arrival>,
}

/// What a set of received packets shows (libwebrtc's `ProbeBitrateEstimator`): the send rate
/// without the last packet sent, the receive rate without the first received, both over at
/// most a second; `None` when the intervals are empty or the receive rate is implausible.
fn measure(pkts: &[Arrival]) -> Option<f64> {
    let first_send = pkts.iter().map(|p| p.0).min()?;
    let (last_send, _, size_last_send) = *pkts.iter().max_by_key(|p| p.0)?;
    let (_, first_recv, size_first_recv) = *pkts.iter().min_by_key(|p| p.1)?;
    let last_recv = pkts.iter().map(|p| p.1).max()?;
    let total: usize = pkts.iter().map(|p| p.2).sum();
    let send = last_send.checked_duration_since(first_send)?;
    let recv = last_recv.checked_duration_since(first_recv)?;
    let ok = |d: Duration| !d.is_zero() && d <= Duration::from_secs(1);
    if !ok(send) || !ok(recv) {
        return None;
    }
    let send = (total - size_last_send) as f64 * 8.0 / send.as_secs_f64();
    let recv = (total - size_first_recv) as f64 * 8.0 / recv.as_secs_f64();
    if recv / send > MAX_VALID_RATIO {
        return None;
    }
    if recv < SATURATED_RATIO * send {
        Some(TARGET_UTILIZATION * recv)
    } else {
        Some(send.min(recv))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Not started yet.
    Init,
    /// Waiting for a result that is worth probing further from.
    Waiting,
    /// Nothing in flight.
    Complete,
}

/// Decides when to probe, paces the clusters and measures their feedback.
#[derive(Debug)]
pub(crate) struct ProbeController {
    enabled: bool,
    state: State,
    next_id: u32,
    queue: VecDeque<Cluster>,
    measures: VecDeque<Measure>,
    /// A result above this starts a further probe (while waiting).
    further_above: f64,
    last_probe: Option<Instant>,
    /// The last large drop: when, and the estimate before it.
    drop: Option<(Instant, f64)>,
    last_recovery: Option<Instant>,
    /// Media (non-probe) packets from feedback over the last 500 ms of sends: (sent,
    /// received, size), for application-limited detection and probe measurements.
    media: VecDeque<(Instant, Option<Instant>, usize)>,
    alr: bool,
}

impl ProbeController {
    pub(crate) fn new(enabled: bool) -> ProbeController {
        ProbeController {
            enabled,
            state: State::Init,
            next_id: 1,
            queue: VecDeque::new(),
            measures: VecDeque::new(),
            further_above: 0.0,
            last_probe: None,
            drop: None,
            last_recovery: None,
            media: VecDeque::new(),
            alr: false,
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn alr(&self) -> bool {
        self.alr
    }

    /// Forgets everything; the next [`start`](Self::start) probes from scratch.
    pub(crate) fn reset(&mut self) {
        let (enabled, next_id) = (self.enabled, self.next_id);
        *self = ProbeController::new(enabled);
        self.next_id = next_id;
    }

    /// The initial exponential probes at 3 and 6 times `estimate`, once.
    pub(crate) fn start(&mut self, now: Instant, estimate: f64, max: f64) {
        if !self.enabled || self.state != State::Init {
            return;
        }
        self.state = State::Complete;
        self.probe(
            now,
            &[FIRST_SCALE * estimate, SECOND_SCALE * estimate],
            max,
            true,
        );
    }

    /// Queues clusters at `rates` (capped at `max`); with `further`, a result above 70 % of
    /// the last one starts another probe at twice the estimate.
    fn probe(&mut self, now: Instant, rates: &[f64], max: f64, further: bool) {
        let mut last = 0.0;
        for &r in rates {
            let r = r.min(max);
            if r <= last {
                continue;
            }
            last = r;
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            let min_bytes = (r * MIN_DURATION.as_secs_f64() / 8.0) as usize;
            if self.queue.len() >= MAX_QUEUED {
                self.queue.pop_front();
            }
            self.queue.push_back(Cluster {
                id,
                bitrate: r,
                min_bytes,
                created: now,
                started: None,
                sent_bytes: 0,
                sent_packets: 0,
            });
            if self.measures.len() >= MAX_TRACKED {
                self.measures.pop_front();
            }
            self.measures.push_back(Measure {
                id,
                min_bytes,
                created: now,
                probes: Vec::new(),
            });
        }
        if last == 0.0 {
            return;
        }
        self.last_probe = Some(now);
        if further && last < max {
            self.state = State::Waiting;
            self.further_above = FURTHER_THRESHOLD * last;
        } else {
            self.state = State::Complete;
        }
    }

    fn prune(&mut self, now: Instant) {
        while self.queue.front().is_some_and(|c| {
            c.done()
                || (c.started.is_none()
                    && now.saturating_duration_since(c.created) > CLUSTER_TIMEOUT)
        }) {
            self.queue.pop_front();
        }
    }

    /// The probe packet due at `now`, if any.
    pub(crate) fn poll(&mut self, now: Instant) -> Option<ProbePacket> {
        self.prune(now);
        let c = self.queue.front()?;
        if c.due() > now {
            return None;
        }
        let size = (c.min_bytes / PACKETS_WANTED).clamp(MIN_PACKET, MAX_PACKET);
        Some(ProbePacket {
            cluster: c.id,
            size,
        })
    }

    pub(crate) fn cancel(&mut self) {
        self.queue.clear();
    }

    /// When the next probe packet is due.
    pub(crate) fn timeout(&self) -> Option<Instant> {
        self.queue.iter().find(|c| !c.done()).map(Cluster::due)
    }

    pub(crate) fn on_sent(&mut self, now: Instant, cluster: u32, bytes: usize) {
        if let Some(c) = self.queue.iter_mut().find(|c| c.id == cluster) {
            c.started.get_or_insert(now);
            c.sent_bytes += bytes;
            c.sent_packets += 1;
        }
        self.prune(now);
    }

    /// One feedback result of a probe packet: the cluster's rate once enough has arrived.
    pub(crate) fn on_probe_result(&mut self, now: Instant, r: &PacketResult) -> Option<f64> {
        let id = r.probe?;
        let at = r.received?;
        while self
            .measures
            .front()
            .is_some_and(|m| now.saturating_duration_since(m.created) > CLUSTER_HISTORY)
        {
            self.measures.pop_front();
        }
        let m = self.measures.iter_mut().find(|m| m.id == id)?;
        if m.probes.len() >= MAX_CLUSTER_PACKETS {
            return None;
        }
        m.probes.push((r.sent, at, r.size));
        let bytes: usize = m.probes.iter().map(|p| p.2).sum();
        if (m.probes.len() as f64) < f64::from(MIN_PACKETS) * MIN_RECEIVED
            || (bytes as f64) < m.min_bytes as f64 * MIN_RECEIVED
        {
            return None;
        }
        // The media sent during the cluster shared the path: it is part of the measurement,
        // as in libwebrtc, whose clusters carry media too.
        let first = m.probes.iter().map(|p| p.0).min()?;
        let last = m.probes.iter().map(|p| p.0).max()?;
        let mut all = m.probes.clone();
        all.extend(
            self.media
                .iter()
                .filter(|p| p.0 >= first && p.0 <= last)
                .filter_map(|&(s, r, n)| r.map(|r| (s, r, n))),
        );
        measure(&all)
    }

    /// One media (non-probe) send from feedback.
    pub(crate) fn on_media_result(&mut self, r: &PacketResult) {
        if !self.enabled {
            return;
        }
        let pos = self.media.partition_point(|p| p.0 <= r.sent);
        self.media.insert(pos, (r.sent, r.received, r.size));
        if let Some(&(last, _, _)) = self.media.back() {
            while self
                .media
                .front()
                .is_some_and(|p| last.saturating_duration_since(p.0) > SEND_WINDOW)
            {
                self.media.pop_front();
            }
        }
        if self.media.len() > MAX_MEDIA {
            self.media.pop_front();
        }
    }

    /// After an estimator update: application-limited detection, further / ALR / recovery
    /// probes. `usage_normal` and `recovered` (under-use turned normal) describe the delay
    /// detector.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_estimate(
        &mut self,
        now: Instant,
        prev: f64,
        estimate: f64,
        max: f64,
        usage_normal: bool,
        recovered: bool,
    ) {
        if !self.enabled {
            return;
        }
        self.update_alr(estimate);
        if self.state == State::Init {
            self.start(now, prev, max);
        }
        if estimate < DROP_THRESHOLD * prev {
            let before = match self.drop {
                Some((at, b)) if now.saturating_duration_since(at) < RECOVERY_WINDOW => b.max(prev),
                _ => prev,
            };
            self.drop = Some((now, before));
            self.last_recovery = None;
        }
        let since_probe = |t: Option<Instant>| t.map(|t| now.saturating_duration_since(t));
        if self.state == State::Waiting {
            if estimate > self.further_above {
                self.probe(now, &[FURTHER_SCALE * estimate], max, true);
            } else if since_probe(self.last_probe).is_some_and(|d| d > WAIT_FOR_RESULT) {
                self.state = State::Complete;
            }
        }
        if self.state != State::Complete || !usage_normal {
            return;
        }
        // Recovery after a large drop: first when the queues have drained, then every 3 s.
        if let Some((at, before)) = self.drop {
            let target = AFTER_DROP * before;
            if now.saturating_duration_since(at) > RECOVERY_WINDOW || estimate >= target {
                self.drop = None;
            } else if match self.last_recovery {
                None => recovered || now.saturating_duration_since(at) >= RECOVERY_SETTLE,
                Some(t) => now.saturating_duration_since(t) >= RECOVERY_INTERVAL,
            } {
                self.last_recovery = Some(now);
                let rate = target.min(FURTHER_SCALE * estimate);
                self.probe(now, &[rate], max, rate < target);
                return;
            }
        }
        if self.alr && since_probe(self.last_probe).is_none_or(|d| d >= ALR_INTERVAL) {
            self.probe(now, &[ALR_SCALE * estimate], max, true);
        }
    }

    fn update_alr(&mut self, estimate: f64) {
        let (Some(&(first, _, _)), Some(&(last, _, _))) = (self.media.front(), self.media.back())
        else {
            return;
        };
        let span = last.saturating_duration_since(first);
        if span < MIN_SEND_SPAN {
            return;
        }
        let bytes: usize = self.media.iter().map(|p| p.2).sum();
        let rate = bytes as f64 * 8.0 / span.as_secs_f64();
        if self.alr {
            self.alr = rate < ALR_LEAVE * estimate;
        } else {
            self.alr = rate < ALR_ENTER * estimate;
        }
    }
}
