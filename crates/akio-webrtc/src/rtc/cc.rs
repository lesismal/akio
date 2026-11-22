//! Transport-wide congestion control across the transports of a session without BUNDLE
//! (ADR-077): one bandwidth estimator and one pacer over the feedback of every transport.
//!
//! - **Negotiated as with BUNDLE.** transport-cc and RFC 8888 (`ack ccfb`) stay on every
//!   line of a session that is not bundled (ADR-072 removed them).
//! - **RFC 8888** reports per SSRC, so there is nothing transport-wide to number: each
//!   transport has its own receiver (its report goes out on it, about the streams it
//!   carries), the sender log is the session's, and reports from any transport are split by
//!   the transport of each SSRC (ECN is checked per path).
//! - **Transport-wide sequence numbers** have two conventions. The draft numbers packets per
//!   transport; libwebrtc (Chrome, Firefox) numbers them per peer connection, one space over
//!   every transport, and runs one feedback generator over all of them. Mixing the two
//!   breaks feedback both ways (a per-transport receiver sees the other transports' numbers
//!   as losses; a per-connection one sees two spaces collide). So the numbering follows the
//!   remote's, read from what it sends ([`Spaces`]): until the remote shows separate spaces
//!   the session numbers in one space and acknowledges every transport's packets with one
//!   receiver (what libwebrtc sends and expects); once it does (the same numbers on two
//!   transports, or numbers far apart), every transport gets its own sender and receiver,
//!   swapped in with its state ([`Rtc::with_tp`]), feedback per transport on it.
//! - **One estimator over several spaces** ([`Merge`]): results from separate spaces carry
//!   arrival times on separate clock anchors and come in per transport, out of send order.
//!   They are aligned (each transport's arrival times are taken relative to its smallest
//!   one-way delay, so queueing delay is comparable across transports on one bottleneck),
//!   held until every transport with packets in flight has reported up to their send time
//!   (at most [`HOLD`]), then handed to the estimator in send order. RFC 8888 results share
//!   the remote's report clock and are only ordered.

use std::collections::VecDeque;

use super::*;
use akio_rtp::PacketResult;

/// Results wait at most this long for the other transports' feedback.
const HOLD: Duration = Duration::from_millis(300);
/// Recent transport-wide numbers kept per transport for reading the remote's numbering, and
/// how old they may be.
const RECENT: usize = 64;
const RECENT_AGE: Duration = Duration::from_secs(1);
/// Numbers further than this from every recent number of another transport are another
/// space.
const FAR: i32 = 1024;
/// Evidence needed for a verdict on the remote's numbering.
const SHARED_EVIDENCE: u32 = 8;
const SPLIT_EVIDENCE: u32 = 4;

/// How the remote numbers transport-wide sequence numbers across our transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Spaces {
    /// Not known yet: treated as [`Spaces::Shared`].
    #[default]
    Unknown,
    /// One space over all transports (libwebrtc).
    Shared,
    /// A space per transport (the draft's transport-wide numbering).
    PerTransport,
}

/// The session-wide congestion control state of an unbundled session.
#[derive(Debug, Default)]
pub(super) struct UnbundledCc {
    pub(super) spaces: Spaces,
    /// A verdict reached while a transport was swapped in, applied at the top level.
    pending: Option<Spaces>,
    /// Recent transport-wide numbers per transport, with their arrival.
    recent: Vec<VecDeque<(u16, Instant)>>,
    shared_ev: u32,
    split_ev: u32,
    pub(super) merge: Merge,
}

impl UnbundledCc {
    /// Whether transport-wide CC state is per transport (swapped with the transport).
    pub(super) fn per_transport(&self) -> bool {
        self.spaces == Spaces::PerTransport
    }

    /// A packet with transport-wide number `seq` arrived on transport `k` at `now`.
    pub(super) fn observe(&mut self, k: usize, seq: u16, now: Instant) {
        if self.spaces != Spaces::Unknown || self.pending.is_some() {
            return;
        }
        if self.recent.len() <= k {
            self.recent.resize_with(k + 1, VecDeque::new);
        }
        let mut dmin = i32::MAX;
        let mut pred = false;
        let mut others = false;
        for (j, r) in self.recent.iter().enumerate() {
            if j == k {
                continue;
            }
            for &(x, at) in r {
                if now.saturating_duration_since(at) > RECENT_AGE {
                    continue;
                }
                others = true;
                let d = i32::from(seq.wrapping_sub(x) as i16);
                dmin = dmin.min(d.abs());
                pred |= d == 1;
            }
        }
        let own_pred = self.recent[k]
            .iter()
            .any(|&(x, _)| x == seq.wrapping_sub(1));
        if others {
            if dmin == 0 || dmin > FAR {
                self.split_ev += 1;
            } else if pred && !own_pred {
                self.shared_ev += 1;
            }
        }
        let r = &mut self.recent[k];
        r.push_back((seq, now));
        if r.len() > RECENT {
            r.pop_front();
        }
        if self.split_ev >= SPLIT_EVIDENCE && self.split_ev >= 2 * self.shared_ev {
            self.pending = Some(Spaces::PerTransport);
        } else if self.shared_ev >= SHARED_EVIDENCE && self.shared_ev >= 4 * self.split_ev {
            self.pending = Some(Spaces::Shared);
        }
    }
}

/// Feedback results of several transports, merged for one estimator.
#[derive(Debug, Default)]
pub(super) struct Merge {
    /// Results waiting, with the time they came in.
    buf: Vec<(PacketResult, Instant)>,
    /// Per transport: the smallest one-way delay seen (ns, received minus sent; anchors are
    /// arbitrary, so it may be negative), the latest send time its feedback covered, and
    /// when it last sent a packet that feedback will cover.
    base: Vec<Option<i128>>,
    covered: Vec<Option<Instant>>,
    last_sent: Vec<Option<Instant>>,
    /// The next send-order index handed to the estimator.
    next: u64,
}

/// `b - a` in nanoseconds.
fn nanos(a: Instant, b: Instant) -> i128 {
    if b >= a {
        b.duration_since(a).as_nanos() as i128
    } else {
        -(a.duration_since(b).as_nanos() as i128)
    }
}

impl Merge {
    fn grow(&mut self, k: usize) {
        if self.base.len() <= k {
            self.base.resize(k + 1, None);
            self.covered.resize(k + 1, None);
            self.last_sent.resize(k + 1, None);
        }
    }

    /// Transport `k` sent a packet feedback will cover.
    pub(super) fn on_sent(&mut self, k: usize, now: Instant) {
        self.grow(k);
        self.last_sent[k] = Some(now);
    }

    /// Results of feedback that came in on transport `k` (`align`: their arrival times are
    /// on the transport's own anchor).
    pub(super) fn push(&mut self, k: usize, now: Instant, results: Vec<PacketResult>, align: bool) {
        self.grow(k);
        for mut r in results {
            if self.covered[k].is_none_or(|c| r.sent > c) {
                self.covered[k] = Some(r.sent);
            }
            if align {
                if let Some(at) = r.received {
                    let owd = nanos(r.sent, at);
                    let base = *self.base[k].get_or_insert(owd);
                    let base = if owd < base {
                        self.base[k] = Some(owd);
                        owd
                    } else {
                        base
                    };
                    // Arrival relative to the transport's smallest delay: queueing only.
                    let q = (owd - base).max(0) as u64;
                    r.received = r.sent.checked_add(Duration::from_nanos(q)).or(Some(at));
                }
            }
            self.buf.push((r, now));
        }
    }

    /// The results every transport with packets in flight has reported up to (or that
    /// waited [`HOLD`]), in send order and numbered so.
    pub(super) fn pop(&mut self, now: Instant) -> Vec<PacketResult> {
        if self.buf.is_empty() {
            return Vec::new();
        }
        // A transport holds results back while it sent after what its feedback covered.
        let mark = (0..self.last_sent.len())
            .filter(|&k| {
                self.last_sent[k].is_some_and(|s| {
                    self.covered[k].is_none_or(|c| s > c) && now.saturating_duration_since(s) < HOLD
                })
            })
            .map(|k| self.covered[k])
            .min();
        let mut out = Vec::new();
        let mut keep = Vec::new();
        for (r, at) in self.buf.drain(..) {
            let ready = match mark {
                None => true,
                Some(None) => false,
                Some(Some(m)) => r.sent <= m,
            };
            if ready || now.saturating_duration_since(at) >= HOLD {
                out.push(r);
            } else {
                keep.push((r, at));
            }
        }
        self.buf = keep;
        out.sort_by_key(|r| r.sent);
        for r in &mut out {
            r.seq = self.next;
            self.next += 1;
        }
        out
    }

    /// Whether results are waiting (their hold ends by [`HOLD`]).
    pub(super) fn waiting(&self) -> Option<Instant> {
        self.buf.iter().map(|(_, at)| *at + HOLD).min()
    }
}

impl Rtc {
    /// Whether feedback results go through the merge: a session with several transports (no
    /// BUNDLE) using RFC 8888, or transport-wide numbering per transport.
    pub(super) fn cc_merged(&self) -> bool {
        !self.xt.tps.is_empty() && (self.ccfb || self.xt.cc.per_transport())
    }

    /// A packet feedback will cover left on the current transport.
    pub(super) fn cc_on_sent(&mut self, now: Instant) {
        if !self.xt.tps.is_empty() {
            let k = self.xt.cur;
            self.xt.cc.merge.on_sent(k, now);
        }
    }

    /// Hands results to the estimator: directly, or through the merge in an unbundled
    /// session (`align`: transport-wide results on the current transport's anchor).
    pub(super) fn cc_results(&mut self, now: Instant, res: Vec<PacketResult>, align: bool) {
        let res = if self.cc_merged() {
            let k = self.xt.cur;
            self.xt.cc.merge.push(k, now, res, align);
            self.xt.cc.merge.pop(now)
        } else {
            res
        };
        if res.is_empty() {
            return;
        }
        if let Some(b) = self.bwe.as_mut() {
            b.on_packet_results(now, &res);
        }
        self.bwe_event();
    }

    /// Results whose hold ran out (from the timers).
    pub(super) fn cc_flush(&mut self, now: Instant) {
        if self.xt.cc.merge.waiting().is_some_and(|t| t <= now) {
            let res = self.xt.cc.merge.pop(now);
            if !res.is_empty() {
                if let Some(b) = self.bwe.as_mut() {
                    b.on_packet_results(now, &res);
                }
                self.bwe_event();
            }
        }
    }

    /// RFC 8888 feedback (on any transport): split by the transport of each reported SSRC,
    /// ECN checked on that transport's path, results to the estimator.
    pub(super) fn cc_ccfb(&mut self, now: Instant, fb: &akio_rtp::CcfbFeedback) {
        if self.xt.tps.is_empty() {
            self.ecn_feedback(fb);
            let res = self.ccfb_tx.on_feedback(now, fb);
            if self.ccfb {
                self.cc_results(now, res, false);
            }
            return;
        }
        let mut parts: Vec<(usize, akio_rtp::CcfbFeedback)> = Vec::new();
        for st in &fb.streams {
            let k = self
                .media
                .iter()
                .position(|l| l.sends_ssrc(st.ssrc))
                .map_or(self.xt.cur, |i| self.tp_of_line(i));
            match parts.iter_mut().find(|(j, _)| *j == k) {
                Some((_, p)) => p.streams.push(st.clone()),
                None => parts.push((
                    k,
                    akio_rtp::CcfbFeedback {
                        sender_ssrc: fb.sender_ssrc,
                        streams: vec![st.clone()],
                        report_timestamp: fb.report_timestamp,
                    },
                )),
            }
        }
        for (k, part) in parts {
            self.with_tp(k, |s| {
                s.ecn_feedback(&part);
                let res = s.ccfb_tx.on_feedback(now, &part);
                if s.ccfb {
                    s.cc_results(now, res, false);
                }
            });
        }
    }

    /// Transport-wide feedback on the current transport: to the session's sender, or the
    /// transport's own when the numbering is per transport.
    pub(super) fn cc_twcc(&mut self, now: Instant, fb: &akio_rtp::TwccFeedback) {
        let res = self.twcc_tx.on_feedback(now, fb);
        // With RFC 8888 negotiated its feedback drives the estimator.
        if !self.ccfb {
            let align = self.xt.cc.per_transport();
            self.cc_results(now, res, align);
        }
    }

    /// A received packet's transport-wide number (`seq`, from stream `ssrc`).
    pub(super) fn cc_received(&mut self, now: Instant, seq: u16, ssrc: u32) {
        if self.xt.split && self.xt.cc.spaces == Spaces::Unknown {
            let k = self.xt.cur;
            self.xt.cc.observe(k, seq, now);
        }
        self.twcc_rx.on_received(seq, now);
        self.twcc_media_ssrc = ssrc;
    }

    /// Applies a verdict on the remote's numbering reached during the last call (with the
    /// primary current).
    pub(super) fn cc_apply(&mut self) {
        if self.xt.cur != 0 {
            return;
        }
        let Some(s) = self.xt.cc.pending.take() else {
            return;
        };
        akio_log::debug!(target: "akio_webrtc", "transport-wide numbering of the remote: {s:?}");
        if s == Spaces::PerTransport {
            // What the shared receiver gathered mixes the spaces: start over per transport.
            self.twcc_rx = TwccReceiver::new();
            self.xt.cc.merge = Merge::default();
            // Every transport numbers on from where the shared space stopped: the remote's
            // receivers must not see numbers go back (they would ignore them as old).
            let next = self.twcc_tx.next_seq();
            for (_, t) in &mut self.xt.tps {
                t.skip_twcc(next);
            }
        }
        self.xt.cc.spaces = s;
    }

    /// The SSRC our feedback about transport `k`'s streams is sent from: a line on it.
    fn cc_sender(&self, k: usize) -> Option<u32> {
        self.media
            .iter()
            .enumerate()
            .find(|(i, l)| !l.stopped && self.tp_of_line(*i) == k)
            .map(|(_, l)| l.send.ssrc())
    }

    /// Congestion control feedback due at `now`: RFC 8888 when negotiated, else
    /// transport-wide; per transport (on it) when the session is not bundled and the state
    /// is per transport.
    pub(super) fn send_cc_feedback(&mut self, now: Instant) {
        let per_tp = !self.xt.tps.is_empty() && (self.ccfb || self.xt.cc.per_transport());
        if !per_tp {
            let sender = self.media.first().map_or(1, |l| l.send.ssrc());
            self.poll_cc_feedback(now, sender);
            return;
        }
        for k in 0..=self.xt.tps.len() {
            if let Some(sender) = self.cc_sender(k) {
                self.with_tp(k, |s| s.poll_cc_feedback(now, sender));
            }
        }
    }

    /// The current transport's (or the session's) feedback due at `now`, sent from
    /// `sender`.
    fn poll_cc_feedback(&mut self, now: Instant, sender: u32) {
        let mut out = Vec::new();
        if self.ccfb {
            let ntp = self.ntp(now);
            while let Some(fb) = self.ccfb_rx.poll_feedback(now, ntp, sender) {
                out.push(fb);
                if out.len() > 32 {
                    break;
                }
            }
        } else {
            while let Some(fb) = self
                .twcc_rx
                .poll_feedback(now, sender, self.twcc_media_ssrc)
            {
                out.push(fb);
                if out.len() > 32 {
                    break;
                }
            }
        }
        for p in out {
            self.send_rtcp(std::slice::from_ref(&p));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_numbering_is_recognised() {
        let now = Instant::now();
        let mut cc = UnbundledCc::default();
        // libwebrtc: one counter, audio every 5th packet, video the rest.
        for s in 0..200u16 {
            let k = usize::from(s % 5 == 0);
            cc.observe(k, s, now);
        }
        assert_eq!(cc.pending, Some(Spaces::Shared));
    }

    #[test]
    fn per_transport_numbering_is_recognised() {
        let now = Instant::now();
        // Spaces starting together: the same numbers on both transports.
        let mut cc = UnbundledCc::default();
        let (mut a, mut v) = (0u16, 0u16);
        for i in 0..200 {
            if i % 5 == 0 {
                cc.observe(1, a, now);
                a += 1;
            } else {
                cc.observe(0, v, now);
                v += 1;
            }
        }
        assert_eq!(cc.pending, Some(Spaces::PerTransport));
        // Spaces far apart.
        let mut cc = UnbundledCc::default();
        let (mut a, mut v) = (40_000u16, 7u16);
        for i in 0..200 {
            if i % 5 == 0 {
                cc.observe(1, a, now);
                a += 1;
            } else {
                cc.observe(0, v, now);
                v += 1;
            }
        }
        assert_eq!(cc.pending, Some(Spaces::PerTransport));
        // One transport alone says nothing.
        let mut cc = UnbundledCc::default();
        for s in 0..500u16 {
            cc.observe(0, s, now);
        }
        assert_eq!(cc.pending, None);
    }

    fn result(sent: Instant, recv: Option<Instant>) -> PacketResult {
        PacketResult {
            seq: 0,
            sent,
            size: 1000,
            received: recv,
            probe: None,
            ecn: None,
        }
    }

    #[test]
    fn merge_orders_aligns_and_holds() {
        let t0 = Instant::now();
        let ms = |n: u64| t0 + Duration::from_millis(n);
        let mut m = Merge::default();
        for i in 0..10 {
            m.on_sent(0, ms(i * 10));
            m.on_sent(1, ms(i * 10 + 5));
        }
        // Transport 1's feedback first, on an anchor 500 ms off; transport 0 has not
        // reported: held.
        let r1: Vec<_> = (0..10)
            .map(|i| result(ms(i * 10 + 5), Some(ms(i * 10 + 5 + 520))))
            .collect();
        m.push(1, ms(100), r1, true);
        assert!(m.pop(ms(100)).is_empty());
        let r0: Vec<_> = (0..10)
            .map(|i| result(ms(i * 10), Some(ms(i * 10 + 30))))
            .collect();
        m.push(0, ms(101), r0, true);
        let out = m.pop(ms(101));
        assert_eq!(out.len(), 20);
        assert!(
            out.windows(2)
                .all(|w| w[0].sent <= w[1].sent && w[0].seq + 1 == w[1].seq)
        );
        // Aligned: every packet arrives its queueing delay (0 here) after it was sent.
        assert!(out.iter().all(|r| r.received == Some(r.sent)));
        // A transport that never reports holds results back for HOLD at most.
        m.on_sent(1, ms(200));
        m.push(0, ms(210), vec![result(ms(195), Some(ms(225)))], true);
        assert!(m.pop(ms(210)).is_empty());
        assert_eq!(m.waiting(), Some(ms(210) + HOLD));
        assert_eq!(m.pop(ms(210) + HOLD).len(), 1);
    }
}
