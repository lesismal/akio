//! ECN-capable RTP (ADR-077): marking sent media ECT(0) or ECT(1) and checking, from RFC 8888
//! feedback, that the marks arrive (RFC 6679 §7.2-7.4 with RFC 8888 as the feedback).
//!
//! - **When.** [`RtcConfig::set_ecn_marking`](crate::RtcConfig::set_ecn_marking) asks for it;
//!   it happens on a path once RFC 8888 feedback is in use (it reports the codepoint each
//!   packet arrived with) and the bandwidth estimator runs (it is what responds to CE). Only
//!   RTP is marked: RTCP never (RFC 6679 §7.3.1 "SHALL NOT"), nor STUN, DTLS or SCTP.
//! - **Initiation** ([`Phase::Testing`]): one RTP packet in [`PROBE_EVERY`] is marked (RFC 6679
//!   §7.2.1: a small fraction while it is unknown whether marks get through). Once
//!   [`CONFIRM`] marked packets are reported received with their mark (or CE) and none
//!   otherwise, the path is ECN-capable (the unicast "provisional success") and every RTP
//!   packet is marked.
//! - **Failure** ([`Phase::Failed`], RFC 6679 §7.4): a marked packet reported received
//!   without its mark (bleached to Not-ECT, or re-marked to the other ECT) ends marking on the
//!   path; so does losing marked packets that are not getting through: [`CONFIRM`] of them
//!   lost and none received, or (with enough results) a marked loss rate above half and well
//!   above the unmarked one. While capable, heavy loss of marked packets goes back to
//!   initiation, which compares marked and unmarked losses again. A new path (ICE pair,
//!   latched address) starts over.
//! - **Other initiations** (ADR-086, RFC 6679 §7.2): with "leap of faith"
//!   ([`EcnInitiation::LeapOfFaith`](crate::EcnInitiation::LeapOfFaith), or negotiated `leap`)
//!   initiation marks every packet and judges them the same way; with RFC 6679's "ice"
//!   initiation negotiated, the path marks nothing ([`Phase::Verifying`]) until an ECN-marked
//!   STUN check on the selected pair comes back with its codepoint (then everything is
//!   marked) or not (failed). A path where checks cannot run falls back to probing.
//! - **Retrying** (RFC 6679 §7.4.1 option 1): a failed path tries initiation again (probing)
//!   after [`RETRY_FIRST`], doubling up to [`RETRY_MAX`], so a path that changes behind the
//!   same addresses gets ECN back. After [`MAX_FALLBACKS`] fallbacks from full marking (marks
//!   confirmed, then lost or cleared) it stays unmarked, as §7.4.1 recommends.
//! - **Bookkeeping.** Sent RTP packets are remembered by SSRC and sequence number (the last
//!   [`HISTORY`]) with their codepoint, and RFC 8888 report blocks (or the counter differences
//!   of RFC 6679 reports, [`super::ecn_fb`]) are matched against them before the estimator sees
//!   the results; CE marks reach the estimator, as loss for ECT(0) and to its scalable
//!   response for ECT(1) (ADR-082).
//! - **TCP paths** (ICE-TCP, TURN over TCP / TLS) carry no codepoint: ECN stays off there.

use std::collections::{HashMap, VecDeque};

use super::ecn_fb::Init;
use super::*;
use crate::types::{EcnInitiation, EcnMarking};

/// During initiation, one RTP packet in this many is marked.
pub(super) const PROBE_EVERY: u64 = 4;
/// Marked packets reported received with their mark before the path counts as capable (and
/// marked packets lost, with none received, before it counts as dropping them).
pub(super) const CONFIRM: u64 = 10;
/// Marked results looked at before comparing marked and unmarked losses.
const LOSS_SAMPLE: u64 = 16;
/// While capable: results per loss window, and the lost share of marked packets in it that
/// sends the path back to initiation.
const CAPABLE_WINDOW: u64 = 64;
const CAPABLE_LOSS: f64 = 0.5;
/// Sent packets remembered per path.
const HISTORY: usize = 2048;
/// A failed path tries again after this, doubling up to [`RETRY_MAX`] (ADR-086).
pub(super) const RETRY_FIRST: Duration = Duration::from_secs(10);
pub(super) const RETRY_MAX: Duration = Duration::from_secs(300);
/// Fallbacks from full marking after which a path is not tried again.
pub(super) const MAX_FALLBACKS: u32 = 3;

/// Where a path stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Phase {
    /// Not marking: ECN off, or no RFC 8888 feedback / estimator yet.
    #[default]
    Off,
    /// Marking a fraction of packets until the feedback shows the marks arrive.
    Testing,
    /// Marking every RTP packet.
    Capable,
    /// RFC 6679's "ice" initiation (ADR-086): not marking until an ECN-marked STUN check on the
    /// path comes back.
    Verifying,
    /// The marks do not get through: not marking on this path.
    Failed,
}

/// A sent packet: its codepoint and whether a report already counted it lost.
#[derive(Debug, Clone, Copy)]
struct Sent {
    ecn: u8,
    lost: bool,
}

/// The ECN state of one transport's path.
#[derive(Debug, Default)]
pub(super) struct EcnPath {
    pub(super) phase: Phase,
    /// The codepoint marked packets carry (1 = ECT(1), 2 = ECT(0)).
    mark: u8,
    /// The path the state is about.
    path: Option<(SocketAddr, SocketAddr)>,
    /// RTP packets sent while testing (to pick every [`PROBE_EVERY`]-th).
    counter: u64,
    sent: HashMap<(u32, u16), Sent>,
    order: VecDeque<(u32, u16)>,
    /// Initiation: marked packets received with their mark or CE, marked lost; unmarked
    /// results and lost.
    ok: u64,
    lost: u64,
    unmarked: u64,
    unmarked_lost: u64,
    /// While capable: marked results and lost in the current window.
    win: u64,
    win_lost: u64,
    /// Packets sent marked on this transport (statistics).
    pub(super) marked_sent: u64,
    /// Marked packets reported CE.
    pub(super) ce: u64,
    /// Paths given up on (statistics).
    pub(super) failures: u64,
    /// RFC 6679 (ADR-082): each source's last report (extended highest sequence number and
    /// counters).
    prev: HashMap<u32, (u32, only_rtp::EcnCounters)>,
    /// Initiation marks every packet (leap of faith, ADR-086).
    leap: bool,
    /// An "ice" initiation waits for its STUN check to be started.
    ice_wanted: bool,
    /// Retrying a failed path (ADR-086): when, how many retries so far, fallbacks from full
    /// marking on this path, and whether full marking was reached since the last start.
    retry_at: Option<Instant>,
    retries: u32,
    fallbacks: u32,
    reached: bool,
    /// Times a failed path was tried again (statistics).
    pub(super) retried: u64,
}

impl EcnPath {
    /// The codepoint of `cfg`'s marking (0: none).
    pub(super) fn codepoint(m: EcnMarking) -> u8 {
        match m {
            EcnMarking::Ect0 => 2,
            EcnMarking::Ect1 => 1,
            _ => 0,
        }
    }

    /// Starts (or restarts, on a new path) initiation with codepoint `mark`; `Off` when
    /// `mark` is 0.
    pub(super) fn start(&mut self, mark: u8, path: Option<(SocketAddr, SocketAddr)>) {
        self.start_with(mark, path, Init::Rtp);
    }

    /// [`start`](Self::start) with initiation `init` (ADR-086). Retry bookkeeping carries over
    /// on the same path.
    pub(super) fn start_with(
        &mut self,
        mark: u8,
        path: Option<(SocketAddr, SocketAddr)>,
        init: Init,
    ) {
        let (marked_sent, ce, failures, retried) =
            (self.marked_sent, self.ce, self.failures, self.retried);
        let (retries, fallbacks) = if path == self.path {
            (self.retries, self.fallbacks)
        } else {
            (0, 0)
        };
        *self = EcnPath {
            phase: match (mark, init) {
                (0, _) => Phase::Off,
                (_, Init::Ice) => Phase::Verifying,
                _ => Phase::Testing,
            },
            mark,
            path,
            marked_sent,
            ce,
            failures,
            retried,
            retries,
            fallbacks,
            leap: init == Init::Leap,
            ice_wanted: mark != 0 && init == Init::Ice,
            ..EcnPath::default()
        };
    }

    /// The codepoint marked packets carry (0: none).
    pub(super) fn mark(&self) -> u8 {
        self.mark
    }

    /// Whether an "ice" initiation waits for its STUN check to be started.
    pub(super) fn ice_wanted(&self) -> bool {
        self.ice_wanted
    }

    /// Whether an "ice" initiation waits for its STUN check; cleared by the call.
    pub(super) fn take_ice_wanted(&mut self) -> bool {
        std::mem::take(&mut self.ice_wanted)
    }

    /// The path packets go on now: a different one starts over (with `init`).
    pub(super) fn on_path(&mut self, path: Option<(SocketAddr, SocketAddr)>, init: Init) {
        if self.mark != 0 && path.is_some() && path != self.path {
            self.start_with(self.mark, path, init);
        }
    }

    /// A failed path tries again once its time comes (ADR-086): `true` when it restarted
    /// (probing, or `ice` for the "ice" initiation).
    pub(super) fn retry(&mut self, now: Instant, ice: bool) -> bool {
        if self.phase != Phase::Failed || self.fallbacks >= MAX_FALLBACKS {
            return false;
        }
        let Some(at) = self.retry_at else {
            let wait = RETRY_FIRST
                .saturating_mul(1u32 << self.retries.min(16))
                .min(RETRY_MAX);
            self.retry_at = Some(now + wait);
            return false;
        };
        if now < at {
            return false;
        }
        self.retries += 1;
        self.retried += 1;
        let init = if ice { Init::Ice } else { Init::Rtp };
        self.start_with(self.mark, self.path, init);
        true
    }

    /// The result of the "ice" initiation's check on `path`: the codepoint the remote saw.
    pub(super) fn on_ice_check(&mut self, path: (SocketAddr, SocketAddr), ecn: Option<u8>) {
        if self.phase != Phase::Verifying || self.path != Some(path) {
            return;
        }
        match ecn {
            Some(e) if e == self.mark || e == 3 => self.capable(),
            _ => self.fail(),
        }
    }

    /// The codepoint for the next RTP packet, `ssrc` / `seq`, sent now (0: Not-ECT); the
    /// packet is remembered for matching feedback.
    pub(super) fn on_send(&mut self, ssrc: u32, seq: u16) -> u8 {
        let ecn = match self.phase {
            Phase::Off | Phase::Failed | Phase::Verifying => return 0,
            Phase::Testing => {
                self.counter += 1;
                if self.leap || self.counter % PROBE_EVERY == 1 {
                    self.mark
                } else {
                    0
                }
            }
            Phase::Capable => self.mark,
        };
        if ecn != 0 {
            self.marked_sent += 1;
        }
        if self
            .sent
            .insert((ssrc, seq), Sent { ecn, lost: false })
            .is_none()
        {
            self.order.push_back((ssrc, seq));
        }
        while self.order.len() > HISTORY {
            if let Some(k) = self.order.pop_front() {
                self.sent.remove(&k);
            }
        }
        ecn
    }

    /// Whether RFC 8888 reports about `ssrc` concern packets this path sent.
    pub(super) fn wants(&self) -> bool {
        matches!(self.phase, Phase::Testing | Phase::Capable)
    }

    /// One RFC 8888 report entry: packet `ssrc` / `seq` arrived with `ecn`, or not
    /// (`None`).
    pub(super) fn on_report(&mut self, ssrc: u32, seq: u16, ecn: Option<u8>) {
        if !self.wants() {
            return;
        }
        let Some(s) = self.sent.get_mut(&(ssrc, seq)) else {
            return;
        };
        let marked = s.ecn != 0;
        match ecn {
            None => {
                if s.lost {
                    return;
                }
                s.lost = true;
                self.count(marked, true);
            }
            Some(got) => {
                let was_lost = s.lost;
                self.sent.remove(&(ssrc, seq));
                if marked && got != self.mark && got != 3 {
                    // Bleached to Not-ECT or re-marked: marks do not survive this path.
                    self.fail();
                    return;
                }
                if marked && got == 3 {
                    self.ce += 1;
                }
                if was_lost {
                    // Counted lost by an earlier report: it arrived after all.
                    self.uncount(marked);
                }
                self.count(marked, false);
            }
        }
    }

    /// An RFC 6679 report about `ssrc` (ADR-082): its extended highest sequence number
    /// `highest` and cumulative counters. Matched with the packets sent since the previous
    /// report; returns the ECN-capable and CE packets that arrived in between, for the
    /// estimator (`None` before a previous report, or when not marking).
    pub(super) fn on_counters(
        &mut self,
        ssrc: u32,
        highest: u32,
        c: &only_rtp::EcnCounters,
    ) -> Option<(u64, u64)> {
        if !self.wants() {
            return None;
        }
        let (ph, pc) = self.prev.insert(ssrc, (highest, *c))?;
        let n = highest.wrapping_sub(ph);
        if n == 0 || n > HISTORY as u32 {
            return None;
        }
        let d = c.since(&pc);
        let (mut marked, mut unmarked) = (0u64, 0u64);
        for i in 1..=n {
            let seq = ph.wrapping_add(i) as u16;
            if let Some(s) = self.sent.remove(&(ssrc, seq)) {
                if s.ecn != 0 {
                    marked += 1;
                } else {
                    unmarked += 1;
                }
            }
        }
        let (mine, other) = if self.mark == 1 {
            (d.ect1, d.ect0)
        } else {
            (d.ect0, d.ect1)
        };
        if other > 0 || (marked > 0 && mine + d.ce == 0 && d.not_ect >= unmarked + marked) {
            // Re-marked, or every marked packet arrived not-ECT.
            self.fail();
            return None;
        }
        self.ce += d.ce;
        let ok = (mine + d.ce).min(marked);
        let arrived_unmarked = d.not_ect.saturating_sub(d.duplicates).min(unmarked);
        for _ in 0..ok {
            self.count(true, false);
        }
        for _ in ok..marked {
            self.count(true, true);
        }
        for _ in 0..arrived_unmarked {
            self.count(false, false);
        }
        for _ in arrived_unmarked..unmarked {
            self.count(false, true);
        }
        Some((mine + other + d.ce, d.ce))
    }

    fn count(&mut self, marked: bool, lost: bool) {
        match self.phase {
            Phase::Testing => {
                if marked {
                    if lost {
                        self.lost += 1;
                    } else {
                        self.ok += 1;
                    }
                } else {
                    self.unmarked += 1;
                    if lost {
                        self.unmarked_lost += 1;
                    }
                }
                self.decide();
            }
            Phase::Capable if marked => {
                self.win += 1;
                if lost {
                    self.win_lost += 1;
                }
                if self.win >= CAPABLE_WINDOW {
                    if self.win_lost as f64 > CAPABLE_LOSS * self.win as f64 {
                        // Losing marked packets: initiation compares with unmarked ones.
                        let (mark, path) = (self.mark, self.path);
                        self.fallbacks += 1;
                        self.start(mark, path);
                        return;
                    }
                    self.win = 0;
                    self.win_lost = 0;
                }
            }
            _ => {}
        }
    }

    /// A packet counted lost arrived after all.
    fn uncount(&mut self, marked: bool) {
        match self.phase {
            Phase::Testing if marked => self.lost = self.lost.saturating_sub(1),
            Phase::Testing => self.unmarked_lost = self.unmarked_lost.saturating_sub(1),
            Phase::Capable if marked => {
                self.win = self.win.saturating_sub(1);
                self.win_lost = self.win_lost.saturating_sub(1);
            }
            _ => {}
        }
    }

    /// Initiation's verdict, once there is one.
    fn decide(&mut self) {
        if self.ok == 0 && self.lost >= CONFIRM {
            self.fail(); // marked packets do not get through
            return;
        }
        let marked = self.ok + self.lost;
        if marked >= LOSS_SAMPLE {
            let m = self.lost as f64 / marked as f64;
            let u = if self.unmarked == 0 {
                0.0
            } else {
                self.unmarked_lost as f64 / self.unmarked as f64
            };
            if m > 0.5 && m > 3.0 * u + 0.1 {
                self.fail();
                return;
            }
        }
        if self.ok >= CONFIRM && self.lost * 4 <= self.ok {
            self.capable();
        }
    }

    fn capable(&mut self) {
        self.phase = Phase::Capable;
        self.win = 0;
        self.win_lost = 0;
        if !self.reached {
            self.reached = true;
            self.retries = 0; // it worked: a later failure retries soon again
        }
    }

    fn fail(&mut self) {
        if self.phase == Phase::Capable {
            self.fallbacks += 1;
        }
        self.phase = Phase::Failed;
        self.failures += 1;
        self.retry_at = None;
        self.sent.clear();
        self.order.clear();
    }
}

impl Rtc {
    /// Whether ECN marking may run: asked for, RFC 8888 feedback in use or RFC 6679 toward
    /// a remote that reads and reports ECN (ADR-082), the estimator on.
    pub(super) fn ecn_enabled(&self) -> bool {
        self.cfg.ecn != EcnMarking::Off && (self.ccfb || self.ecn6679.tx) && self.bwe.is_some()
    }

    /// Paths from local address `addr` carry no ECN codepoint (a TURN allocation over TCP or
    /// TLS; ICE-TCP candidates are recognised on their own): ECN stays off there.
    pub(crate) fn set_no_ecn(&mut self, addr: SocketAddr) {
        if !self.no_ecn.contains(&addr) {
            self.no_ecn.push(addr);
        }
    }

    /// Whether the current path marks ECT(1), whose CE marks the estimator answers scalably
    /// (L4S): the pacer then sends smoothly.
    pub(super) fn ecn_scalable(&self) -> bool {
        self.ecn_codepoint() == 1
            && matches!(self.ecn.phase, Phase::Testing | Phase::Capable)
            && self.ecn_enabled()
    }

    /// The codepoint marked packets carry: the configured one, or the one a remote that
    /// negotiated RFC 6679 asks for with `ect=` (ADR-086; "random" leaves ours).
    pub(super) fn ecn_codepoint(&self) -> u8 {
        if self.cfg.ecn == EcnMarking::Off {
            return 0;
        }
        self.ecn6679
            .ect
            .filter(|_| self.ecn6679.init.is_some())
            .unwrap_or_else(|| EcnPath::codepoint(self.cfg.ecn))
    }

    /// How a new path starts marking (ADR-086): the RFC 6679 initiation negotiated, else
    /// the configured one.
    fn ecn_init(&self) -> Init {
        match self.ecn6679.init {
            Some(i) => i,
            None if self.cfg.ecn_init == EcnInitiation::LeapOfFaith => Init::Leap,
            None => Init::Rtp,
        }
    }

    /// The codepoint for RTP packet `raw` about to leave at `now` on the current transport's
    /// path `path` (0 when not marking).
    pub(super) fn ecn_mark(
        &mut self,
        now: Instant,
        raw: &[u8],
        path: (SocketAddr, SocketAddr),
    ) -> u8 {
        if raw.len() < 12 {
            return 0;
        }
        if !self.ecn_enabled() || self.no_ecn.contains(&path.0) {
            // Off, or a path over TCP: ECN is TCP's own business there (RFC 6544), and a
            // TURN server reached over TCP or TLS has no codepoint to copy (RFC 8656 §12).
            if self.ecn.phase != Phase::Off {
                self.ecn.start(0, None);
            }
            return 0;
        }
        let mark = self.ecn_codepoint();
        let init = self.ecn_init();
        if self.ecn.phase == Phase::Off || self.ecn.mark() != mark {
            // A first path, or a renegotiation that changed the codepoint.
            self.ecn.start_with(mark, Some(path), init);
        } else {
            self.ecn.on_path(Some(path), init);
            self.ecn.retry(now, init == Init::Ice);
        }
        if self.ecn.ice_wanted() {
            // RFC 6679 §7.2.2: an ECN-marked check once the path is ICE's selected pair
            // (unmarked until then); where none can run (fixed pairs, a lite agent), probing.
            if self.ice.is_fixed() || self.lite {
                self.ecn.start_with(mark, Some(path), Init::Rtp);
            } else if self.ice.selected_pair() == Some(path) {
                self.ecn.take_ice_wanted();
                if !self.ice.check_ecn(now, mark) {
                    self.ecn.start_with(mark, Some(path), Init::Rtp);
                }
            }
        }
        let seq = u16::from_be_bytes([raw[2], raw[3]]);
        let ssrc = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        self.ecn.on_send(ssrc, seq)
    }

    /// The ECN entries of RFC 8888 feedback about streams the current transport sends.
    pub(super) fn ecn_feedback(&mut self, fb: &only_rtp::CcfbFeedback) {
        if !self.ecn.wants() {
            return;
        }
        for st in &fb.streams {
            for (i, r) in st.reports.iter().enumerate() {
                let seq = st.begin_seq.wrapping_add(i as u16);
                self.ecn.on_report(st.ssrc, seq, r.map(|m| m.ecn & 3));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> Option<(SocketAddr, SocketAddr)> {
        Some((
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
        ))
    }

    /// Sends `n` packets from `seq0`; returns the codepoints.
    fn send(e: &mut EcnPath, seq0: u16, n: u16) -> Vec<u8> {
        (0..n).map(|i| e.on_send(7, seq0 + i)).collect()
    }

    #[test]
    fn initiation_marks_a_fraction_then_everything() {
        let mut e = EcnPath::default();
        e.start(1, path());
        let marks = send(&mut e, 0, 40);
        assert_eq!(marks.iter().filter(|m| **m == 1).count(), 10);
        assert!(marks.iter().all(|m| *m == 0 || *m == 1));
        for (i, m) in marks.iter().enumerate() {
            e.on_report(7, i as u16, Some(*m));
        }
        assert_eq!(e.phase, Phase::Capable);
        assert!(send(&mut e, 40, 10).iter().all(|m| *m == 1));
    }

    #[test]
    fn bleaching_and_remarking_fail() {
        for got in [0u8, 2] {
            let mut e = EcnPath::default();
            e.start(1, path());
            let marks = send(&mut e, 0, 8);
            // Unmarked packets arriving Not-ECT are fine; a marked one is not.
            e.on_report(7, 1, Some(0));
            assert_eq!(e.phase, Phase::Testing);
            assert_eq!(marks[0], 1);
            e.on_report(7, 0, Some(got));
            assert_eq!(e.phase, Phase::Failed);
            assert!(send(&mut e, 8, 8).iter().all(|m| *m == 0));
        }
        // CE on a marked packet is a congestion signal, not a failure.
        let mut e = EcnPath::default();
        e.start(2, path());
        send(&mut e, 0, 1);
        e.on_report(7, 0, Some(3));
        assert_eq!((e.phase, e.ce), (Phase::Testing, 1));
    }

    #[test]
    fn dropped_marks_fail() {
        let mut e = EcnPath::default();
        e.start(1, path());
        let marks = send(&mut e, 0, 80);
        for (i, m) in marks.iter().enumerate() {
            e.on_report(7, i as u16, if *m != 0 { None } else { Some(0) });
        }
        assert_eq!(e.phase, Phase::Failed);
        assert_eq!(e.failures, 1);
    }

    #[test]
    fn late_arrival_and_path_change() {
        let mut e = EcnPath::default();
        e.start(1, path());
        let marks = send(&mut e, 0, 40);
        // Reported lost, then received: counts as received.
        for (i, m) in marks.iter().enumerate() {
            e.on_report(7, i as u16, None);
            e.on_report(7, i as u16, Some(*m));
        }
        assert_eq!(e.phase, Phase::Capable);
        // A new path starts over; the same path does not.
        e.on_path(path(), Init::Rtp);
        assert_eq!(e.phase, Phase::Capable);
        e.on_path(
            Some((
                "10.0.0.1:1000".parse().unwrap(),
                "10.0.0.3:2000".parse().unwrap(),
            )),
            Init::Rtp,
        );
        assert_eq!(e.phase, Phase::Testing);
        e.fail();
        e.on_path(path(), Init::Rtp);
        assert_eq!(e.phase, Phase::Testing);
    }

    #[test]
    fn heavy_loss_while_capable_goes_back_to_testing() {
        let mut e = EcnPath::default();
        e.start(1, path());
        let marks = send(&mut e, 0, 40);
        for (i, m) in marks.iter().enumerate() {
            e.on_report(7, i as u16, Some(*m));
        }
        assert_eq!(e.phase, Phase::Capable);
        send(&mut e, 40, 64);
        for i in 40..104u16 {
            e.on_report(7, i, if i % 4 == 0 { Some(1) } else { None });
        }
        assert_eq!(e.phase, Phase::Testing);
    }

    #[test]
    fn leap_of_faith_marks_everything_and_still_fails() {
        let mut e = EcnPath::default();
        e.start_with(2, path(), Init::Leap);
        let marks = send(&mut e, 0, 12);
        assert!(marks.iter().all(|m| *m == 2));
        for i in 0..12u16 {
            e.on_report(7, i, Some(2));
        }
        assert_eq!(e.phase, Phase::Capable);
        // Cleared marks fail it like any other path.
        let mut e = EcnPath::default();
        e.start_with(2, path(), Init::Leap);
        send(&mut e, 0, 4);
        e.on_report(7, 0, Some(0));
        assert_eq!(e.phase, Phase::Failed);
    }

    #[test]
    fn ice_initiation_waits_for_its_check() {
        let mut e = EcnPath::default();
        e.start_with(1, path(), Init::Ice);
        assert!(e.take_ice_wanted() && !e.take_ice_wanted());
        assert_eq!(e.phase, Phase::Verifying);
        assert!(send(&mut e, 0, 8).iter().all(|m| *m == 0));
        // Another pair's result changes nothing; this one's does.
        let other = (
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.9:9".parse().unwrap(),
        );
        e.on_ice_check(other, Some(1));
        assert_eq!(e.phase, Phase::Verifying);
        e.on_ice_check(path().unwrap(), Some(1));
        assert_eq!(e.phase, Phase::Capable);
        assert!(send(&mut e, 8, 8).iter().all(|m| *m == 1));
        for (ecn, phase) in [
            (Some(3), Phase::Capable),
            (Some(0), Phase::Failed),
            (Some(2), Phase::Failed),
            (None, Phase::Failed),
        ] {
            e.start_with(1, path(), Init::Ice);
            e.on_ice_check(path().unwrap(), ecn);
            assert_eq!(e.phase, phase, "{ecn:?}");
        }
    }

    #[test]
    fn failed_paths_retry_with_backoff_until_fallbacks_pile_up() {
        let now = Instant::now();
        let mut e = EcnPath::default();
        e.start(1, path());
        let mut t = now;
        let mut waits = Vec::new();
        for _ in 0..7 {
            e.fail();
            assert!(!e.retry(t, false), "the first call sets the time");
            let at = e.retry_at.unwrap();
            waits.push(at - t);
            assert!(!e.retry(at - Duration::from_millis(1), false));
            assert!(e.retry(at, false));
            assert_eq!(e.phase, Phase::Testing);
            t = at;
        }
        let s = |n| Duration::from_secs(n);
        assert_eq!(
            waits,
            vec![s(10), s(20), s(40), s(80), s(160), s(300), s(300)]
        );
        assert_eq!(e.retried, 7);
        // Reaching full marking resets the backoff; falling back from it counts.
        for i in 0..MAX_FALLBACKS {
            e.start(1, path());
            e.capable();
            e.fail();
            assert_eq!(e.fallbacks, i + 1);
            assert!(!e.retry(t, false));
            if i + 1 < MAX_FALLBACKS {
                assert_eq!(e.retry_at, Some(t + s(10)));
            }
        }
        assert!(!e.retry(t + s(1000), false), "given up on this path");
        // A new path starts afresh.
        let other = Some((
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.9:9".parse().unwrap(),
        ));
        e.on_path(other, Init::Rtp);
        e.fail();
        assert!(!e.retry(t, false));
        assert!(e.retry(t + s(10), false));
    }
}
