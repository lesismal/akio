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
//!   initiation, which compares marked and unmarked losses again. A failed path stays
//!   unmarked; a new path (ICE pair, latched address) starts over.
//! - **Bookkeeping.** Sent RTP packets are remembered by SSRC and sequence number (the last
//!   [`HISTORY`]) with their codepoint, and RFC 8888 report blocks are matched against them
//!   before the estimator sees the results; CE marks reach the estimator as loss (ADR-073).

use std::collections::{HashMap, VecDeque};

use super::*;
use crate::types::EcnMarking;

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
        let (marked_sent, ce, failures) = (self.marked_sent, self.ce, self.failures);
        *self = EcnPath {
            phase: if mark == 0 {
                Phase::Off
            } else {
                Phase::Testing
            },
            mark,
            path,
            marked_sent,
            ce,
            failures,
            ..EcnPath::default()
        };
    }

    /// The path packets go on now: a different one starts over.
    pub(super) fn on_path(&mut self, path: Option<(SocketAddr, SocketAddr)>) {
        if self.mark != 0 && path.is_some() && path != self.path {
            self.start(self.mark, path);
        }
    }

    /// The codepoint for the next RTP packet, `ssrc` / `seq`, sent now (0: Not-ECT); the
    /// packet is remembered for matching feedback.
    pub(super) fn on_send(&mut self, ssrc: u32, seq: u16) -> u8 {
        let ecn = match self.phase {
            Phase::Off | Phase::Failed => return 0,
            Phase::Testing => {
                self.counter += 1;
                if self.counter % PROBE_EVERY == 1 {
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
            self.phase = Phase::Capable;
            self.win = 0;
            self.win_lost = 0;
        }
    }

    fn fail(&mut self) {
        self.phase = Phase::Failed;
        self.failures += 1;
        self.sent.clear();
        self.order.clear();
    }
}

impl Rtc {
    /// Whether ECN marking may run: asked for, RFC 8888 feedback in use, the estimator on.
    pub(super) fn ecn_enabled(&self) -> bool {
        self.cfg.ecn != EcnMarking::Off && self.ccfb && self.bwe.is_some()
    }

    /// The codepoint for RTP packet `raw` about to leave on the current transport's path
    /// `path` (0 when not marking).
    pub(super) fn ecn_mark(&mut self, raw: &[u8], path: (SocketAddr, SocketAddr)) -> u8 {
        if raw.len() < 12 {
            return 0;
        }
        if !self.ecn_enabled() {
            if self.ecn.phase != Phase::Off {
                self.ecn.start(0, None);
            }
            return 0;
        }
        if self.ecn.phase == Phase::Off {
            self.ecn.start(EcnPath::codepoint(self.cfg.ecn), Some(path));
        } else {
            self.ecn.on_path(Some(path));
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
        e.on_path(path());
        assert_eq!(e.phase, Phase::Capable);
        e.on_path(Some((
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.3:2000".parse().unwrap(),
        )));
        assert_eq!(e.phase, Phase::Testing);
        e.fail();
        e.on_path(path());
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
}
