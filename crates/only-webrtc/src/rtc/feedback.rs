//! RTCP beyond reports and NACK: RFC 8888 feedback bookkeeping, XR receiver reference
//! times (RFC 3611), TMMBR / TMMBN (RFC 5104), and the caps they put on the bandwidth
//! estimate (ADR-039).

use super::*;
use only_rtp::{TmmbItem, XrBlock};

/// Per-packet overhead announced in our TMMBRs: IPv4 + UDP + RTP fixed headers.
const TMMBR_OVERHEAD: u16 = 40;

/// The TMMBR asking the remote sender(s) of line `line` for at most `bitrate` (0
/// withdraws), or `None` before any remote stream is known.
pub(super) fn tmmbr_request(
    l: &MediaLine,
    line: usize,
    recv: &HashMap<u32, Recv>,
    routes: &HashMap<u32, Route>,
    bitrate: u64,
) -> Option<Rtcp> {
    let mut targets: Vec<u32> = recv
        .iter()
        .filter(|(s, r)| r.line == line && routes.get(s).is_none_or(|x| x.repairs.is_none()))
        .map(|(s, _)| *s)
        .collect();
    if targets.is_empty() {
        targets = l
            .remote_ssrcs
            .iter()
            .copied()
            .filter(|s| !l.remote_rtx.contains_key(s) && !l.remote_fec.contains_key(s))
            .collect();
    }
    targets.sort_unstable();
    if targets.is_empty() {
        return None;
    }
    Some(Rtcp::Tmmbr {
        sender_ssrc: l.send.ssrc(),
        entries: targets
            .into_iter()
            .map(|ssrc| TmmbItem {
                ssrc,
                bitrate,
                overhead: TMMBR_OVERHEAD,
            })
            .collect(),
    })
}

impl Rtc {
    /// A sent RTP packet (media, RTX or FEC): logged for RFC 8888 feedback.
    pub(super) fn note_sent(&mut self, now: Instant, raw: &[u8]) {
        if self.ccfb && raw.len() >= 12 {
            let seq = u16::from_be_bytes([raw[2], raw[3]]);
            let ssrc = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
            self.ccfb_tx.on_sent(ssrc, seq, now, raw.len());
        }
    }

    /// Caps the bandwidth estimate at the lowest of REMB and the TMMBR bounds.
    pub(super) fn apply_remote_caps(&mut self) {
        let tmmbr = self.tmmbr.values().filter_map(|t| t.bound).min();
        let cap = match (self.remb, tmmbr) {
            (Some(a), Some(b)) => a.min(b),
            (a, b) => a.or(b).unwrap_or(0),
        };
        if let Some(b) = self.bwe.as_mut() {
            b.set_remote_estimate(cap);
        }
        self.bwe_event();
    }

    /// A TMMBR from `sender`: each entry about a stream we send updates its bounding set;
    /// every request is answered with a TMMBN (RFC 5104 §3.5.4.2).
    pub(super) fn handle_tmmbr(&mut self, now: Instant, sender: u32, entries: &[TmmbItem]) {
        let mut answers = Vec::new();
        for e in entries {
            if !self.media.iter().any(|l| l.sends_ssrc(e.ssrc)) {
                continue;
            }
            if !self.tmmbr.contains_key(&e.ssrc) && self.tmmbr.len() >= MAX_TMMBR_STREAMS {
                continue;
            }
            let st = self.tmmbr.entry(e.ssrc).or_insert_with(|| TmmbrState {
                handler: TmmbrHandler::new(e.ssrc),
                bound: None,
                packets: 0,
                at: now,
                pps: 0.0,
            });
            st.handler.on_tmmbr(now, sender, std::slice::from_ref(e));
            answers.push(st.handler.tmmbn(now));
        }
        if !answers.is_empty() {
            self.send_rtcp(&answers);
            self.refresh_tmmbr(now);
        }
    }

    /// Re-evaluates the TMMBR bounds (requests time out, the packet rate changes) and
    /// reports changes.
    pub(super) fn refresh_tmmbr(&mut self, now: Instant) {
        if self.tmmbr.is_empty() {
            return;
        }
        let mut changed = false;
        let mut gone = Vec::new();
        for (&ssrc, st) in &mut self.tmmbr {
            let Some((li, enc)) = self
                .media
                .iter()
                .enumerate()
                .find_map(|(i, l)| l.send_of(ssrc).map(|e| (i, e)))
            else {
                gone.push(ssrc);
                continue;
            };
            let l = &self.media[li];
            let sent = match enc {
                Some(i) => l.sim[i].send.packets_sent(),
                None => l.send.packets_sent(),
            };
            let dt = now.saturating_duration_since(st.at).as_secs_f64();
            if dt >= 0.5 {
                st.pps = sent.saturating_sub(st.packets) as f64 / dt;
                st.packets = sent;
                st.at = now;
            }
            let bound = st.handler.max_bitrate(now, st.pps);
            if bound != st.bound {
                st.bound = bound;
                changed = true;
                self.events
                    .push_back(RtcEvent::Other(Other::MaxBitrateRequest {
                        mid: l.mid,
                        ssrc,
                        bitrate: bound,
                    }));
            }
            if bound.is_none() && st.handler.bounding_set(now).is_empty() {
                gone.push(ssrc);
            }
        }
        for s in gone {
            self.tmmbr.remove(&s);
        }
        if changed {
            self.apply_remote_caps();
        }
    }

    /// An extended report from `ssrc`: receiver reference times are remembered for our
    /// DLRR, DLRR blocks about our SSRCs give the receiver-side RTT.
    pub(super) fn handle_xr(&mut self, now: Instant, ntp: u64, ssrc: u32, blocks: &[XrBlock]) {
        for b in blocks {
            match b {
                XrBlock::ReceiverReferenceTime { ntp: t } => self.rrtr.on_rrtr(now, ssrc, *t),
                XrBlock::Dlrr(items) => {
                    for it in items {
                        if !self.media.iter().any(|l| l.send.ssrc() == it.ssrc) {
                            continue;
                        }
                        if let Some(rtt) = only_rtp::rtt_from_dlrr(ntp, it) {
                            self.xr_rtt = Some(rtt);
                            for r in self.recv.values_mut() {
                                r.stream.set_rtt(rtt);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Asks the remote sender of `mid` for at most `bitrate` bits per second with TMMBR
    /// (repeated with every report while set), or withdraws the request (`None`). `false`:
    /// no such line.
    pub(crate) fn request_max_bitrate(&mut self, mid: Mid, bitrate: Option<u64>) -> bool {
        let Some(idx) = self.media.iter().position(|l| l.mid == mid) else {
            return false;
        };
        self.media[idx].tmmbr_req = bitrate.filter(|b| *b > 0);
        let l = &self.media[idx];
        if let Some(t) = tmmbr_request(l, idx, &self.recv, &self.routes, bitrate.unwrap_or(0)) {
            self.send_rtcp(&[t]);
        }
        true
    }
}
