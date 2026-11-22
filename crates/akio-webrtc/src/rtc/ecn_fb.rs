//! RFC 6679's own signalling for ECN-capable RTP (ADR-082), for remotes without RFC 8888:
//! `a=ecn-capable-rtp` per media section, the RTCP ECN feedback message (`a=rtcp-fb:<pt>
//! nack ecn`) and the XR ECN summary report (`a=rtcp-xr:ecn-sum`).
//!
//! - **Offer / answer.** With [`RtcConfig::set_ecn_marking`](crate::RtcConfig::set_ecn_marking)
//!   on, every audio and video section offers `a=ecn-capable-rtp:ice,rtp mode=setread; ect=N`
//!   (`N` the configured codepoint), `nack ecn` on its payload types and `ecn-sum` in
//!   `a=rtcp-xr`. The initiation methods (ADR-086), in our order of preference: "ice" (§7.2.2:
//!   an ECN-marked STUN check whose answer echoes the codepoint, only with ICE and a full
//!   agent; `a=ice-options` then carries `rtp+ecn`, §6.4), "rtp" (§7.2.1: a fraction of the
//!   packets marked until feedback confirms them) and "leap" (§7.2.3: every packet marked at
//!   once; offered, first, only with [`EcnInitiation::LeapOfFaith`]). An offer is answered
//!   with the first method of that order it lists; sections without the attribute, or with
//!   none of these methods, use no RFC 6679 (§6.1.1).
//! - **`ect=`** is the receiver's preference (§6.1: "0" when absent): toward a remote that
//!   negotiated RFC 6679, the path marks the codepoint it asks for ("random" leaves ours), and
//!   the estimator responds to CE as that codepoint says (scalably for ECT(1)).
//! - **Receiving** (any negotiated section): each source's packets are counted by codepoint,
//!   with losses and duplicates ([`akio_rtp::EcnReceiver`]). Unless RFC 8888 is in use (its
//!   reports carry every packet's codepoint), feedback messages go out when a source's first
//!   ECN-capable packet or a CE mark arrives (at most every [`EARLY_GAP`]) and with every
//!   regular report, and each section's compound report carries an ECN summary of its
//!   sources when `ecn-sum` was negotiated.
//! - **Sending.** A remote that reads ECN (`mode=setread` or `readonly`) and reports it
//!   (feedback messages or summaries) lets the path mark without RFC 8888, as long as the
//!   estimator runs (fed by transport-wide feedback). The differences between a source's
//!   reports are matched with the packets sent in between (by sequence number): marks that
//!   arrived as the other ECT fail the path, as do marked packets of which none arrived
//!   ECN-capable while the not-ECT count covers them (cleared); the rest is counted as
//!   received or lost for initiation, as with RFC 8888 ([`super::ecn`]). CE differences go
//!   to the estimator ([`akio_rtp::BandwidthEstimator::on_ecn_counts`]).

use super::*;
use crate::types::{EcnInitiation, EcnMarking};
use akio_rtp::{EcnCounters, EcnFeedback, EcnReceiver, EcnSummary};

/// `a=rtcp-xr` token of the ECN summary (RFC 6679 §6.3).
pub(super) const XR_ECN_SUM: &str = "ecn-sum";
/// Early feedback messages are this far apart at least.
pub(super) const EARLY_GAP: Duration = Duration::from_millis(20);

/// An RFC 6679 initiation method (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Init {
    /// A fraction of the packets marked until feedback confirms them (§7.2.1).
    #[default]
    Rtp,
    /// An ECN-marked STUN check on the selected pair (§7.2.2).
    Ice,
    /// Every packet marked from the start (§7.2.3).
    Leap,
}

impl Init {
    fn token(self) -> &'static str {
        match self {
            Init::Rtp => "rtp",
            Init::Ice => "ice",
            Init::Leap => "leap",
        }
    }

    /// Our order of preference: `ice` only where checks run, `leap` first when configured
    /// (and only accepted otherwise).
    fn preference(cfg: &ConfigInner, ice: bool) -> Vec<Init> {
        let mut v = Vec::with_capacity(3);
        let leap = cfg.ecn_init == EcnInitiation::LeapOfFaith;
        if leap {
            v.push(Init::Leap);
        }
        if ice {
            v.push(Init::Ice);
        }
        v.push(Init::Rtp);
        if !leap {
            v.push(Init::Leap);
        }
        v
    }
}

/// RFC 6679 as negotiated for a media section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LineEcn {
    /// The remote reads ECN (`mode=setread` or `readonly`): marking toward it may work.
    pub(super) remote_reads: bool,
    /// Both listed `ecn-sum`.
    pub(super) sum: bool,
    /// The initiation method.
    pub(super) init: Init,
    /// The codepoint the remote prefers to receive (`ect=`: 2 for ECT(0), its default, 1 for
    /// ECT(1); `None` for "random").
    pub(super) ect: Option<u8>,
}

/// The session's RFC 6679 state.
#[derive(Debug, Default)]
pub(super) struct Session {
    /// A section negotiated it: count what arrives and report it.
    pub(super) rx: bool,
    /// A section toward a remote that reads and reports ECN: marking may rely on it.
    pub(super) tx: bool,
    pub(super) receiver: EcnReceiver,
    last_early: Option<Instant>,
    /// The negotiated initiation method and the remote's `ect=` preference (first section that
    /// negotiated RFC 6679; `None` without one).
    pub(super) init: Option<Init>,
    pub(super) ect: Option<u8>,
}

/// What the remote section `m` negotiates (`None`: no RFC 6679 there); `ice`: the "ice"
/// initiation can run (ICE with a full agent here).
pub(super) fn remote_line(cfg: &ConfigInner, m: &Media, ice: bool) -> Option<LineEcn> {
    if cfg.ecn == EcnMarking::Off {
        return None;
    }
    let v = m.get("ecn-capable-rtp")?;
    let mut parts = v.trim().splitn(2, ' ');
    let methods: Vec<&str> = parts.next()?.split(',').map(str::trim).collect();
    let init = Init::preference(cfg, ice)
        .into_iter()
        .find(|i| methods.contains(&i.token()))?;
    let mut remote_reads = true;
    let mut ect = Some(2);
    for p in parts.next().unwrap_or("").split(';') {
        let p = p.trim();
        if let Some(mode) = p.strip_prefix("mode=") {
            remote_reads = mode.trim() != "setonly";
        } else if let Some(e) = p.strip_prefix("ect=") {
            ect = match e.trim() {
                "1" => Some(1),
                "random" => None,
                _ => Some(2),
            };
        }
    }
    let sum = m
        .all("rtcp-xr")
        .any(|x| x.split_ascii_whitespace().any(|t| t == XR_ECN_SUM));
    Some(LineEcn {
        remote_reads,
        sum,
        init,
        ect,
    })
}

/// The `a=ecn-capable-rtp` value of a section we describe, and whether `ecn-sum` goes in
/// its `a=rtcp-xr`; `ice` as for [`remote_line`].
pub(super) fn local_line(
    cfg: &ConfigInner,
    offer: bool,
    neg: Option<LineEcn>,
    ice: bool,
) -> Option<(String, bool)> {
    let ect = match cfg.ecn {
        EcnMarking::Ect0 => 0,
        EcnMarking::Ect1 => 1,
        _ => return None,
    };
    let (methods, sum) = if offer {
        let mut p = Init::preference(cfg, ice);
        if cfg.ecn_init != EcnInitiation::LeapOfFaith {
            p.retain(|i| *i != Init::Leap); // answered when offered, not offered
        }
        let m: Vec<&str> = p.iter().map(|i| i.token()).collect();
        (m.join(","), true)
    } else {
        let n = neg?;
        (n.init.token().to_owned(), n.sum)
    };
    Some((format!("{methods} mode=setread; ect={ect}"), sum))
}

impl MediaLine {
    /// Whether the line's payload types negotiated the ECN feedback message.
    fn ecn_feedback(&self) -> bool {
        self.codecs.iter().any(|c| c.fb.iter().any(|f| f == FB_ECN))
    }
}

impl Rtc {
    /// Recomputes the session's RFC 6679 state after a negotiation.
    pub(super) fn ecn6679_apply(&mut self) {
        let lines = || {
            self.media
                .iter()
                .filter(|l| !l.stopped)
                .filter_map(|l| l.ecn6679.map(|e| (l, e)))
        };
        self.ecn6679.rx = lines().next().is_some();
        self.ecn6679.tx = lines().any(|(l, e)| e.remote_reads && (e.sum || l.ecn_feedback()));
        let first = lines().next().map(|(_, e)| e);
        self.ecn6679.init = first.map(|e| e.init);
        self.ecn6679.ect = first.and_then(|e| e.ect);
        // The estimator responds to CE as the codepoint marked says (RFC 9331 §4.3).
        let scalable = self.ecn_codepoint() == 1;
        if let Some(b) = self.bwe.as_mut() {
            b.set_ecn_response(if scalable {
                akio_rtp::EcnResponse::Scalable
            } else {
                akio_rtp::EcnResponse::Classic
            });
        }
    }

    /// Whether this side can run RFC 6679's "ice" initiation: ICE, with a full agent.
    pub(super) fn ecn_ice_capable(&self) -> bool {
        !self.xt.plain && !self.lite
    }

    /// Whether a section negotiated the "ice" initiation (`a=ice-options:rtp+ecn`, §6.4).
    pub(super) fn ecn_ice_negotiated(&self) -> bool {
        self.media
            .iter()
            .any(|l| !l.stopped && l.ecn6679.is_some_and(|e| e.init == Init::Ice))
    }

    /// Sends feedback messages about the sources heard from since the last ones: early
    /// (`regular` false: news arrived) at most every [`EARLY_GAP`], else with the regular
    /// reports. Each goes from, and on the transport of, the line receiving the source.
    pub(super) fn send_ecn6679(&mut self, now: Instant, regular: bool) {
        if !regular
            && self
                .ecn6679
                .last_early
                .is_some_and(|t| now.saturating_duration_since(t) < EARLY_GAP)
        {
            return;
        }
        if !self.media.iter().any(|l| !l.stopped && l.ecn_feedback()) {
            return;
        }
        if !regular {
            self.ecn6679.last_early = Some(now);
        }
        for fb in self.ecn6679.receiver.feedback(0, false) {
            let line = self.recv.get(&fb.media_ssrc).map_or(0, |r| r.line);
            let Some(l) = self.media.get(line) else {
                continue;
            };
            if !l.ecn_feedback() {
                continue;
            }
            let p = EcnFeedback {
                sender_ssrc: l.send.ssrc(),
                ..fb
            }
            .to_rtcp();
            let k = self.tp_of_line(line);
            self.with_tp(k, |s| s.send_rtcp(std::slice::from_ref(&p)));
        }
    }

    /// The XR ECN summary for line `i`'s compound report (sent from `ssrc`) about the
    /// sources it receives, when negotiated (and RFC 8888 is not in use).
    pub(super) fn ecn6679_summary(&self, i: usize, ssrc: u32) -> Option<Rtcp> {
        if !self.ecn6679.rx || self.ccfb {
            return None;
        }
        let l = self.media.get(i)?;
        if !l.ecn6679?.sum {
            return None;
        }
        let mut sums: Vec<EcnSummary> = self
            .recv
            .iter()
            .filter(|(_, r)| r.line == i)
            .filter_map(|(s, _)| self.ecn6679.receiver.summary(*s))
            .collect();
        if sums.is_empty() {
            return None;
        }
        sums.sort_by_key(|s| s.ssrc);
        Some(Rtcp::ExtendedReport {
            ssrc,
            blocks: vec![EcnSummary::to_xr(&sums)],
        })
    }

    /// RFC 6679 reports in a received compound: feedback messages, and summaries matched
    /// with the report block about the same source.
    pub(super) fn ecn6679_input(&mut self, now: Instant, pkts: &[Rtcp]) {
        if self.ccfb {
            return; // RFC 8888 reports every packet's codepoint
        }
        let mut found: Vec<(u32, u32, EcnCounters)> = Vec::new();
        let mut highest: Vec<(u32, u32)> = Vec::new();
        for p in pkts {
            match p {
                Rtcp::SenderReport { reports, .. } | Rtcp::ReceiverReport { reports, .. } => {
                    highest.extend(reports.iter().map(|b| (b.ssrc, b.extended_highest_seq)));
                }
                _ => {}
            }
        }
        for p in pkts {
            match p {
                Rtcp::Unknown { .. } => {
                    if let Some(fb) = EcnFeedback::from_rtcp(p) {
                        found.push((fb.media_ssrc, fb.extended_highest_seq, fb.counters));
                    }
                }
                Rtcp::ExtendedReport { blocks, .. } => {
                    for b in blocks {
                        for s in EcnSummary::from_xr(b).unwrap_or_default() {
                            if let Some(&(_, h)) = highest.iter().find(|(x, _)| *x == s.ssrc) {
                                found.push((s.ssrc, h, s.counters));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        for (ssrc, h, c) in found {
            let k = self
                .media
                .iter()
                .position(|l| l.sends_ssrc(ssrc))
                .map_or(self.xt.cur, |i| self.tp_of_line(i));
            let counts = self.with_tp(k, |s| s.ecn.on_counters(ssrc, h, &c));
            if let (Some((ect, ce)), Some(b)) = (counts, self.bwe.as_mut()) {
                b.on_ecn_counts(now, ect, ce);
            }
        }
        self.bwe_event();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn media(attrs: &[(&str, &str)]) -> Media {
        Media {
            kind: "audio".into(),
            port: 9,
            proto: "UDP/TLS/RTP/SAVPF".into(),
            fmts: vec!["111".into()],
            attrs: attrs.iter().map(|(k, v)| Attr::kv(k, *v)).collect(),
        }
    }

    #[test]
    fn negotiation() {
        let mut cfg = ConfigInner::default();
        let m = media(&[
            ("ecn-capable-rtp", "leap,rtp mode=readonly; ect=0"),
            ("rtcp-xr", "rcvr-rtt=all ecn-sum"),
        ]);
        assert_eq!(remote_line(&cfg, &m, true), None, "off");
        assert_eq!(local_line(&cfg, true, None, true), None);
        cfg.ecn = EcnMarking::Ect1;
        let e = remote_line(&cfg, &m, true).unwrap();
        assert_eq!(
            e,
            LineEcn {
                remote_reads: true,
                sum: true,
                init: Init::Rtp,
                ect: Some(2),
            }
        );
        assert_eq!(
            local_line(&cfg, false, Some(e), true),
            Some(("rtp mode=setread; ect=1".into(), true))
        );
        assert_eq!(
            local_line(&cfg, true, None, true),
            Some(("ice,rtp mode=setread; ect=1".into(), true))
        );
        assert_eq!(
            local_line(&cfg, true, None, false),
            Some(("rtp mode=setread; ect=1".into(), true))
        );
        // Methods: ours first ("ice" only with ICE), then "leap" when it is all there is.
        let line = |cfg: &ConfigInner, v: &str, ice: bool| {
            remote_line(cfg, &media(&[("ecn-capable-rtp", v)]), ice)
        };
        assert_eq!(line(&cfg, "leap,rtp,ice", true).unwrap().init, Init::Ice);
        assert_eq!(line(&cfg, "leap,rtp,ice", false).unwrap().init, Init::Rtp);
        assert_eq!(line(&cfg, "leap", false).unwrap().init, Init::Leap);
        assert_eq!(line(&cfg, "ice", false), None);
        assert_eq!(line(&cfg, "zrtp,foo", true), None);
        // ect=: the remote's preference.
        assert_eq!(
            line(&cfg, "rtp mode=setread; ect=1", false).unwrap().ect,
            Some(1)
        );
        assert_eq!(line(&cfg, "rtp ect=random", false).unwrap().ect, None);
        assert_eq!(line(&cfg, "rtp", false).unwrap().ect, Some(2));
        // setonly: the remote does not read.
        let e = line(&cfg, "rtp mode=setonly", false).unwrap();
        assert!(!e.remote_reads && !e.sum);
        assert_eq!(local_line(&cfg, false, None, false), None);
        // Leap of faith: offered first.
        cfg.ecn_init = EcnInitiation::LeapOfFaith;
        assert_eq!(
            local_line(&cfg, true, None, true),
            Some(("leap,ice,rtp mode=setread; ect=1".into(), true))
        );
        assert_eq!(line(&cfg, "rtp,leap", true).unwrap().init, Init::Leap);
    }
}
