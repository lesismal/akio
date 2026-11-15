//! BBR congestion control: a model of the path's bottleneck bandwidth and round-trip
//! propagation time, paced at a gain over the estimated bandwidth with a window of a few
//! bandwidth-delay products.
//!
//! The state machine is BBRv1's (draft-cardwell-iccrg-bbr-congestion-control-00): Startup
//! (gain 2/ln 2 until the bandwidth stops growing by 25% over three rounds), Drain, ProbeBW
//! (eight phases of pacing gain 1.25, 0.75, then six of 1.0, each one min RTT long) and
//! ProbeRTT (four packets in flight for 200 ms when the min RTT is ten seconds old). On top of
//! it, the loss and ECN response of BBRv2/v3 (draft-cardwell-ccwg-bbr): a round whose lost or
//! CE-marked bytes exceed 2% of its traffic ends Startup and caps the data in flight at the
//! larger of a bandwidth-delay product and 0.7 of the window then (`inflight_hi`); the cap grows
//! back by an eighth per clean round and is lifted once it no longer binds. BBRv1 alone ignores
//! loss and keeps a full queue's worth of losses on a shallow buffer; v3's bandwidth and inflight
//! lower bounds, its probing schedule and its DCTCP-style ECN fraction are left out.
//!
//! Bandwidth comes from delivery-rate samples (draft-cheng-iccrg-delivery-rate-estimation),
//! taken by the connection per acknowledgment ([`RateSample`]).

use std::time::{Duration, Instant};

/// Startup's pacing and window gain, 2/ln 2.
const STARTUP_GAIN: f64 = 2.885;
/// ProbeBW's window gain.
const CWND_GAIN: f64 = 2.0;
/// ProbeBW's pacing gains, one phase per min RTT.
const PROBE_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// Rounds the bandwidth filter keeps its maximum for.
const BW_ROUNDS: u64 = 10;
/// The min RTT is probed again when it is this old.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);
/// Time spent in ProbeRTT.
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
/// Lost (or CE-marked) bytes per round above this fraction mean the path is overloaded.
const LOSS_THRESH: f64 = 0.02;
/// The fraction of the window `inflight_hi` falls to on such a round.
const BETA: f64 = 0.7;
/// Packets of window at least.
const MIN_PACKETS: u64 = 4;

/// A delivery-rate sample of one acknowledgment.
#[derive(Clone, Copy, Debug)]
pub struct RateSample {
    /// Bytes delivered (acknowledged) in all, after this acknowledgment.
    pub total_delivered: u64,
    /// `total_delivered` when the newest packet acknowledged here was sent.
    pub prior_delivered: u64,
    /// Bytes delivered over the sample's interval.
    pub delivered: u64,
    /// The sample's interval: the longer of its send and acknowledgment intervals.
    pub interval: Duration,
    /// Bytes newly acknowledged by this acknowledgment.
    pub acked: u64,
    /// The newest packet acknowledged here was sent while the sender was application-limited.
    pub app_limited: bool,
    /// An RTT sample taken from this acknowledgment.
    pub rtt: Option<Duration>,
}

impl RateSample {
    /// The delivery rate in bytes per second, if the interval is long enough to trust (at
    /// least `min_rtt`, which rules out acknowledgment compression).
    fn rate(&self, min_rtt: Option<Duration>) -> Option<f64> {
        if self.delivered == 0 || self.interval.is_zero() {
            return None;
        }
        if min_rtt.is_some_and(|m| self.interval < m) {
            return None;
        }
        Some(self.delivered as f64 / self.interval.as_secs_f64())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// The windowed maximum of the bandwidth samples of the last [`BW_ROUNDS`] rounds.
#[derive(Clone, Debug, Default)]
struct MaxBw {
    /// (round, max of that round), indexed by round.
    slots: [(u64, f64); BW_ROUNDS as usize],
}

impl MaxBw {
    fn update(&mut self, round: u64, bw: f64) {
        let s = &mut self.slots[(round % BW_ROUNDS) as usize];
        if s.0 != round {
            *s = (round, bw);
        } else if bw > s.1 {
            s.1 = bw;
        }
    }

    fn get(&self, round: u64) -> f64 {
        self.slots
            .iter()
            .filter(|(r, _)| *r + BW_ROUNDS > round)
            .map(|(_, b)| *b)
            .fold(0.0, f64::max)
    }
}

/// The BBR state of a connection.
#[derive(Clone, Debug)]
pub struct Bbr {
    pub mode: Mode,
    mtu: u64,
    initial_window: u64,
    bw: MaxBw,
    min_rtt: Option<Duration>,
    min_rtt_stamp: Option<Instant>,
    /// Round-trip counting: a round ends when a packet sent after it began is acknowledged.
    round: u64,
    next_round_delivered: u64,
    // Startup's full-pipe detection.
    full_bw: f64,
    full_bw_rounds: u32,
    pub filled_pipe: bool,
    pacing_gain: f64,
    cwnd_gain: f64,
    cycle: usize,
    cycle_stamp: Option<Instant>,
    probe_rtt_done: Option<Instant>,
    probe_rtt_round_done: bool,
    prior_cwnd: u64,
    /// The congestion window, in bytes.
    pub cwnd: u64,
    /// Bytes per second.
    pacing_rate: f64,
    /// The cap on data in flight set by lossy rounds (`u64::MAX`: none).
    pub inflight_hi: u64,
    // This round's traffic and losses (or CE marks), for the loss rate.
    round_lost: u64,
    round_start_delivered: u64,
}

impl Bbr {
    pub fn new(mtu: u16, initial_window: u64, initial_rtt: Duration) -> Bbr {
        let mtu = u64::from(mtu);
        let rtt = initial_rtt.max(Duration::from_millis(1));
        Bbr {
            mode: Mode::Startup,
            mtu,
            initial_window,
            bw: MaxBw::default(),
            min_rtt: None,
            min_rtt_stamp: None,
            round: 0,
            next_round_delivered: 0,
            full_bw: 0.0,
            full_bw_rounds: 0,
            filled_pipe: false,
            pacing_gain: STARTUP_GAIN,
            cwnd_gain: STARTUP_GAIN,
            cycle: 0,
            cycle_stamp: None,
            probe_rtt_done: None,
            probe_rtt_round_done: false,
            prior_cwnd: 0,
            cwnd: initial_window,
            pacing_rate: STARTUP_GAIN * initial_window as f64 / rtt.as_secs_f64(),
            inflight_hi: u64::MAX,
            round_lost: 0,
            round_start_delivered: 0,
        }
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = u64::from(mtu);
        self.cwnd = self.cwnd.max(self.min_cwnd());
    }

    fn min_cwnd(&self) -> u64 {
        MIN_PACKETS * self.mtu
    }

    /// The estimated bottleneck bandwidth, in bytes per second.
    pub fn bandwidth(&self) -> f64 {
        self.bw.get(self.round)
    }

    /// The pacing rate, in bytes per second.
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate as u64
    }

    /// The bandwidth-delay product times `gain`, or the initial window before there is one.
    fn bdp(&self, gain: f64) -> u64 {
        let bw = self.bandwidth();
        match self.min_rtt {
            Some(rtt) if bw > 0.0 => (gain * bw * rtt.as_secs_f64()) as u64,
            _ => (gain * self.initial_window as f64) as u64,
        }
    }

    /// Bytes lost, or acknowledged CE-marked: the round's congestion signal.
    pub fn on_lost(&mut self, bytes: u64) {
        self.round_lost += bytes;
    }

    /// Persistent congestion: the window falls to its minimum.
    pub fn on_persistent_congestion(&mut self) {
        self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
        self.cwnd = self.min_cwnd();
    }

    /// One acknowledgment (frame) was processed; `inflight` is what is still in flight.
    pub fn on_ack(&mut self, now: Instant, rs: &RateSample, inflight: u64) {
        self.update_min_rtt(now, rs.rtt);
        // Rounds.
        let round_start = rs.prior_delivered >= self.next_round_delivered;
        if round_start {
            self.next_round_delivered = rs.total_delivered;
            self.round += 1;
        }
        // The bandwidth filter takes samples that are not application-limited, or that are
        // above the estimate anyway.
        if let Some(r) = rs.rate(self.min_rtt) {
            if !rs.app_limited || r >= self.bandwidth() {
                self.bw.update(self.round, r);
            }
        }
        if round_start {
            self.end_round(rs, inflight);
        }
        self.check_full_pipe(round_start, rs);
        self.update_mode(now, rs, inflight, round_start);
        self.set_pacing_rate();
        self.set_cwnd(rs);
    }

    fn update_min_rtt(&mut self, now: Instant, rtt: Option<Duration>) {
        let expired = self
            .min_rtt_stamp
            .is_some_and(|s| now.saturating_duration_since(s) > MIN_RTT_WINDOW);
        if let Some(r) = rtt {
            if self.min_rtt.is_none_or(|m| r <= m) || expired {
                self.min_rtt = Some(r);
                self.min_rtt_stamp = Some(now);
            }
        }
        if expired && self.mode != Mode::ProbeRtt {
            self.enter_probe_rtt();
        }
    }

    /// A round ended: its loss rate decides whether the path is overloaded.
    fn end_round(&mut self, rs: &RateSample, inflight: u64) {
        let delivered = rs
            .total_delivered
            .saturating_sub(self.round_start_delivered);
        let lost = self.round_lost;
        self.round_lost = 0;
        self.round_start_delivered = rs.total_delivered;
        let total = delivered + lost;
        let lossy = lost >= 3 * self.mtu && total > 0 && lost as f64 > LOSS_THRESH * total as f64;
        if lossy {
            let floor = self.bdp(1.0).max(self.min_cwnd());
            let cap = ((self.cwnd.min(inflight.max(self.cwnd / 2)) as f64) * BETA) as u64;
            self.inflight_hi = self.inflight_hi.min(cap.max(floor)).max(floor);
            if self.mode == Mode::Startup {
                // A full buffer: the pipe is as full as it gets.
                self.filled_pipe = true;
            }
            if self.mode == Mode::ProbeBw && self.pacing_gain > 1.0 {
                // Probing up overloaded the path: stop probing for this cycle.
                self.cycle = 1;
            }
        } else if self.inflight_hi != u64::MAX && self.mode == Mode::ProbeBw {
            // A clean round: let the cap grow back, and lift it once it no longer binds.
            self.inflight_hi += (self.inflight_hi / 8).max(self.mtu);
            if self.inflight_hi > 2 * self.bdp(CWND_GAIN).max(self.min_cwnd()) {
                self.inflight_hi = u64::MAX;
            }
        }
    }

    fn check_full_pipe(&mut self, round_start: bool, rs: &RateSample) {
        if self.filled_pipe || !round_start || rs.app_limited {
            return;
        }
        let bw = self.bandwidth();
        if bw >= self.full_bw * 1.25 {
            self.full_bw = bw;
            self.full_bw_rounds = 0;
            return;
        }
        self.full_bw_rounds += 1;
        if self.full_bw_rounds >= 3 {
            self.filled_pipe = true;
        }
    }

    fn update_mode(&mut self, now: Instant, rs: &RateSample, inflight: u64, round_start: bool) {
        if self.mode == Mode::Startup && self.filled_pipe {
            self.mode = Mode::Drain;
            self.pacing_gain = 1.0 / STARTUP_GAIN;
            self.cwnd_gain = STARTUP_GAIN;
        }
        if self.mode == Mode::Drain && inflight <= self.bdp(1.0) {
            self.enter_probe_bw(now);
        }
        if self.mode == Mode::ProbeBw {
            self.advance_cycle(now, inflight);
        }
        if self.mode == Mode::ProbeRtt {
            self.handle_probe_rtt(now, rs, inflight, round_start);
        }
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = CWND_GAIN;
        // Start in a cruising phase (BBR picks one at random; any but the draining one).
        self.cycle = 2;
        self.cycle_stamp = Some(now);
        self.pacing_gain = PROBE_GAINS[self.cycle];
    }

    fn advance_cycle(&mut self, now: Instant, inflight: u64) {
        let min_rtt = self.min_rtt.unwrap_or(Duration::from_millis(1));
        let in_phase = self
            .cycle_stamp
            .map_or(Duration::MAX, |s| now.saturating_duration_since(s));
        let elapsed = in_phase > min_rtt;
        let gain = self.pacing_gain;
        let next = if gain > 1.0 {
            // Probing up lasts a round trip and until the extra data is in flight (at most two
            // round trips: the sender may be limited by something else; a lossy round cuts it
            // short, see `end_round`).
            elapsed && (inflight >= self.bdp(gain) || in_phase > 2 * min_rtt)
        } else if gain < 1.0 {
            // Draining the probe's queue ends early once it is gone.
            elapsed || inflight <= self.bdp(1.0)
        } else {
            elapsed
        };
        if next {
            self.cycle = (self.cycle + 1) % PROBE_GAINS.len();
            self.cycle_stamp = Some(now);
            self.pacing_gain = PROBE_GAINS[self.cycle];
        }
    }

    fn enter_probe_rtt(&mut self) {
        self.mode = Mode::ProbeRtt;
        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
        self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
        self.probe_rtt_done = None;
        self.probe_rtt_round_done = false;
    }

    fn handle_probe_rtt(
        &mut self,
        now: Instant,
        rs: &RateSample,
        inflight: u64,
        round_start: bool,
    ) {
        match self.probe_rtt_done {
            None => {
                if inflight <= self.min_cwnd() {
                    // At least 200 ms and one round trip at the low window.
                    self.probe_rtt_done = Some(now + PROBE_RTT_TIME);
                    self.probe_rtt_round_done = false;
                    self.next_round_delivered = rs.total_delivered;
                }
            }
            Some(done) => {
                if round_start {
                    self.probe_rtt_round_done = true;
                }
                if self.probe_rtt_round_done && now >= done {
                    self.min_rtt_stamp = Some(now);
                    self.cwnd = self.cwnd.max(self.prior_cwnd);
                    self.prior_cwnd = 0;
                    if self.filled_pipe {
                        self.enter_probe_bw(now);
                    } else {
                        self.mode = Mode::Startup;
                        self.pacing_gain = STARTUP_GAIN;
                        self.cwnd_gain = STARTUP_GAIN;
                    }
                }
            }
        }
    }

    fn set_pacing_rate(&mut self) {
        let bw = self.bandwidth();
        if bw <= 0.0 {
            // No bandwidth sample yet: the initial window per measured RTT (the handshake's),
            // not per the configured initial RTT.
            if let Some(rtt) = self.min_rtt.filter(|r| !r.is_zero()) {
                self.pacing_rate = STARTUP_GAIN * self.initial_window as f64 / rtt.as_secs_f64();
            }
            return;
        }
        let rate = self.pacing_gain * bw;
        // Until the pipe is full the rate only goes up (a low early sample must not slow
        // Startup down).
        if self.filled_pipe || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    fn set_cwnd(&mut self, rs: &RateSample) {
        // The target: the gain times the BDP, plus room for acknowledgment aggregation.
        let target = self.bdp(self.cwnd_gain) + 3 * self.mtu;
        if self.filled_pipe {
            self.cwnd = (self.cwnd + rs.acked).min(target);
        } else if self.cwnd < target || rs.total_delivered < self.initial_window {
            self.cwnd += rs.acked;
        }
        self.cwnd = self.cwnd.max(self.min_cwnd());
        if self.mode == Mode::ProbeRtt {
            self.cwnd = self.cwnd.min(self.min_cwnd());
        }
        if self.inflight_hi != u64::MAX {
            self.cwnd = self.cwnd.min(self.inflight_hi.max(self.min_cwnd()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sender with an infinite backlog on a path of `bw` bytes/s and `rtt`, acknowledged
    /// one packet at a time, with no loss: returns the controller after `rounds` rounds.
    fn run(bw: f64, rtt: Duration, secs: f64) -> Bbr {
        let mtu = 1200u64;
        let mut b = Bbr::new(1200, 12_000, Duration::from_millis(333));
        let t0 = Instant::now();
        let mut now = t0;
        let mut delivered = 0u64;
        let step = Duration::from_secs_f64(mtu as f64 / bw);
        // Each acknowledgment delivers one packet sent one RTT (plus queueing) earlier, paced
        // at the bottleneck rate: the samples measure `bw`.
        while now - t0 < Duration::from_secs_f64(secs) {
            now += step;
            let prior = delivered.saturating_sub(b.cwnd.min(delivered));
            delivered += mtu;
            let rs = RateSample {
                total_delivered: delivered,
                prior_delivered: prior,
                delivered: delivered - prior,
                interval: rtt.max(step * ((delivered - prior) / mtu) as u32),
                acked: mtu,
                app_limited: false,
                rtt: Some(rtt),
            };
            let inflight = b.cwnd.min((bw * rtt.as_secs_f64()) as u64);
            b.on_ack(now, &rs, inflight);
        }
        b
    }

    #[test]
    fn converges_on_the_bottleneck() {
        let bw = 12_500_000.0; // 100 Mbit/s
        let rtt = Duration::from_millis(40);
        let b = run(bw, rtt, 3.0);
        assert!(b.filled_pipe);
        assert!(
            matches!(b.mode, Mode::ProbeBw | Mode::ProbeRtt),
            "{:?}",
            b.mode
        );
        let est = b.bandwidth();
        assert!(est > bw * 0.8 && est < bw * 1.3, "{est}");
        // The window is about two BDPs.
        let bdp = bw * rtt.as_secs_f64();
        assert!(
            (b.cwnd as f64) > 1.5 * bdp && (b.cwnd as f64) < 3.0 * bdp,
            "{}",
            b.cwnd
        );
        assert!(b.pacing_rate() as f64 > 0.7 * bw && (b.pacing_rate() as f64) < 1.4 * bw);
    }

    #[test]
    fn lossy_rounds_cap_inflight_and_probe_rtt_runs() {
        let rtt = Duration::from_millis(20);
        let mut b = run(2_500_000.0, rtt, 1.0);
        let before = b.cwnd;
        // A round with 10% loss.
        b.on_lost(b.cwnd / 10);
        let mut now = Instant::now() + Duration::from_secs(1);
        let d = b.next_round_delivered + 1;
        let rs = RateSample {
            total_delivered: d + 100_000,
            prior_delivered: d,
            delivered: 0,
            interval: Duration::ZERO,
            acked: 1200,
            app_limited: false,
            rtt: Some(rtt),
        };
        b.on_ack(now, &rs, before);
        assert!(
            b.inflight_hi < u64::MAX && b.cwnd <= before,
            "{} {}",
            b.cwnd,
            before
        );
        // Ten seconds later the min RTT is stale: ProbeRTT drains to four packets.
        now += Duration::from_secs(11);
        let rs = RateSample {
            rtt: Some(rtt * 2),
            ..rs
        };
        b.on_ack(now, &rs, before);
        assert_eq!(b.mode, Mode::ProbeRtt);
        assert_eq!(b.cwnd, 4 * 1200);
        b.on_ack(now, &rs, 1200);
        // A round later and 200 ms on, it is over.
        let rs2 = RateSample {
            total_delivered: rs.total_delivered + 10_000,
            prior_delivered: rs.total_delivered,
            ..rs
        };
        b.on_ack(now + Duration::from_millis(250), &rs2, 1200);
        assert_eq!(b.mode, Mode::ProbeBw);
        b.on_persistent_congestion();
        assert_eq!(b.cwnd, 4 * 1200);
        b.set_mtu(1400);
        assert_eq!(b.cwnd, 4 * 1400);
    }

    #[test]
    fn max_filter_forgets_old_rounds() {
        let mut f = MaxBw::default();
        f.update(1, 10.0);
        f.update(1, 5.0);
        f.update(2, 7.0);
        assert_eq!(f.get(2), 10.0);
        assert_eq!(f.get(11), 7.0);
        assert_eq!(f.get(12), 0.0);
    }
}
