//! Per-SSRC send and receive state: sequence numbering, retransmission history and RTX
//! (RFC 4588), sender / receiver reports (RFC 3550 §6.4, Appendix A.3 and A.8), NACK
//! generation (RFC 4585 §6.2.1).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::packet::{ExtensionMap, ExtensionValues, RtpHeader};
use crate::rtcp::{ReportBlock, SenderInfo, compact_ntp};
use crate::xr::{DlrrItem, JitterStats, StatisticsSummary, rtt_from_dlrr};

/// Packets kept for retransmission.
pub const SEND_HISTORY_PACKETS: usize = 1024;
/// Age after which packets leave the retransmission history.
pub const SEND_HISTORY_AGE: Duration = Duration::from_secs(2);
/// A packet is resent at most once per this interval.
const RESEND_MIN_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone)]
struct Sent {
    seq: u16,
    pt: u8,
    marker: bool,
    timestamp: u32,
    payload: Vec<u8>,
    ext: ExtensionValues,
    at: Instant,
    resent: Option<Instant>,
}

/// The sending side of one RTP stream (one SSRC, optionally with an RTX SSRC).
#[derive(Debug)]
pub struct SendStream {
    ssrc: u32,
    clock_rate: u32,
    rtx_ssrc: Option<u32>,
    next_seq: u16,
    next_rtx_seq: u16,
    history: VecDeque<Sent>,
    packets: u64,
    octets: u64,
    rtx_packets: u64,
    rtx_octets: u64,
    last: Option<(u32, Instant)>,
    rtt: Option<Duration>,
    remote: Option<ReportBlock>,
}

impl SendStream {
    /// A stream for `ssrc` with RTP clock rate `clock_rate` (Hz), an optional RTX SSRC, and
    /// the first sequence number (random, chosen by the caller). The RTX stream's sequence
    /// numbers start at `initial_seq ^ 0x8000`.
    #[must_use]
    pub fn new(ssrc: u32, clock_rate: u32, rtx_ssrc: Option<u32>, initial_seq: u16) -> SendStream {
        SendStream {
            ssrc,
            clock_rate: clock_rate.max(1),
            rtx_ssrc,
            next_seq: initial_seq,
            next_rtx_seq: initial_seq ^ 0x8000,
            history: VecDeque::new(),
            packets: 0,
            octets: 0,
            rtx_packets: 0,
            rtx_octets: 0,
            last: None,
            rtt: None,
            remote: None,
        }
    }

    /// The media SSRC.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The RTX SSRC.
    #[must_use]
    pub fn rtx_ssrc(&self) -> Option<u32> {
        self.rtx_ssrc
    }

    /// The sequence number the next [`write`](Self::write) uses.
    #[must_use]
    pub fn next_seq(&self) -> u16 {
        self.next_seq
    }

    /// Round-trip time from the last report block with an LSR.
    #[must_use]
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Media packets sent (excluding retransmissions).
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets
    }

    /// Media payload octets sent (excluding retransmissions).
    #[must_use]
    pub fn octets_sent(&self) -> u64 {
        self.octets
    }

    /// Packets retransmitted (RTX or plain).
    #[must_use]
    pub fn packets_resent(&self) -> u64 {
        self.rtx_packets
    }

    /// Payload octets retransmitted.
    #[must_use]
    pub fn octets_resent(&self) -> u64 {
        self.rtx_octets
    }

    /// The last report block received about this stream.
    #[must_use]
    pub fn remote_report(&self) -> Option<&ReportBlock> {
        self.remote.as_ref()
    }

    fn prune(&mut self, now: Instant) {
        while self.history.len() > SEND_HISTORY_PACKETS
            || self
                .history
                .front()
                .is_some_and(|s| now.saturating_duration_since(s.at) > SEND_HISTORY_AGE)
        {
            self.history.pop_front();
        }
    }

    /// Serializes a media packet with the next sequence number, keeps it for retransmission
    /// (the last [`SEND_HISTORY_PACKETS`] packets, at most [`SEND_HISTORY_AGE`] old) and
    /// updates the counters and the RTP timestamp / wallclock pair used by
    /// [`sender_report`](Self::sender_report).
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &mut self,
        now: Instant,
        pt: u8,
        marker: bool,
        timestamp: u32,
        payload: &[u8],
        ext: &ExtensionValues,
        map: &ExtensionMap,
    ) -> Vec<u8> {
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        let h = RtpHeader {
            marker,
            payload_type: pt,
            sequence_number: seq,
            timestamp,
            ssrc: self.ssrc,
            ext: ext.clone(),
            ..RtpHeader::default()
        };
        let out = h.write(map, payload);
        self.packets += 1;
        self.octets += payload.len() as u64;
        self.last = Some((timestamp, now));
        self.history.push_back(Sent {
            seq,
            pt,
            marker,
            timestamp,
            payload: payload.to_vec(),
            ext: ext.clone(),
            at: now,
            resent: None,
        });
        self.prune(now);
        out
    }

    /// Answers a NACK: for each sequence number still in the history and not resent in the
    /// last 10 ms, an RTX packet (RFC 4588: the RTX SSRC and its own sequence number, payload
    /// type `rtx_pt`, payload = 2-byte original sequence number + original payload, same
    /// timestamp, marker and extensions) when `rtx_pt` is given and the stream has an RTX
    /// SSRC, otherwise the original packet again. Unknown sequence numbers are skipped.
    ///
    /// The header extensions are repeated as sent, including the transport-wide sequence
    /// number; use [`resend_with`](Self::resend_with) to give retransmissions fresh ones.
    pub fn resend(
        &mut self,
        now: Instant,
        seqs: &[u16],
        rtx_pt: Option<u8>,
        map: &ExtensionMap,
    ) -> Vec<Vec<u8>> {
        self.resend_with(now, seqs, rtx_pt, map, |_| {})
    }

    /// [`resend`](Self::resend) that lets `f` adjust each retransmission's extension values
    /// (for example set `transport_cc` from
    /// [`TwccSender::next_seq`](crate::TwccSender::next_seq)).
    pub fn resend_with(
        &mut self,
        now: Instant,
        seqs: &[u16],
        rtx_pt: Option<u8>,
        map: &ExtensionMap,
        mut f: impl FnMut(&mut ExtensionValues),
    ) -> Vec<Vec<u8>> {
        self.prune(now);
        let mut out = Vec::new();
        let Some(first) = self.history.front().map(|s| s.seq) else {
            return out;
        };
        for &seq in seqs {
            let i = usize::from(seq.wrapping_sub(first));
            let Some(s) = self.history.get_mut(i) else {
                continue;
            };
            if s.seq != seq
                || s.resent
                    .is_some_and(|t| now.saturating_duration_since(t) < RESEND_MIN_INTERVAL)
            {
                continue;
            }
            s.resent = Some(now);
            let mut ext = s.ext.clone();
            f(&mut ext);
            let mut h = RtpHeader {
                marker: s.marker,
                payload_type: s.pt,
                sequence_number: s.seq,
                timestamp: s.timestamp,
                ssrc: self.ssrc,
                ext,
                ..RtpHeader::default()
            };
            let pkt = match (rtx_pt, self.rtx_ssrc) {
                (Some(pt), Some(rtx)) => {
                    h.payload_type = pt;
                    h.ssrc = rtx;
                    h.sequence_number = self.next_rtx_seq;
                    self.next_rtx_seq = self.next_rtx_seq.wrapping_add(1);
                    let mut p = Vec::with_capacity(2 + s.payload.len());
                    p.extend_from_slice(&s.seq.to_be_bytes());
                    p.extend_from_slice(&s.payload);
                    h.write(map, &p)
                }
                _ => h.write(map, &s.payload),
            };
            self.rtx_packets += 1;
            self.rtx_octets += s.payload.len() as u64;
            out.push(pkt);
        }
        out
    }

    /// The sender information for an SR at `now` (`ntp_now` = [`ntp_time`](crate::ntp_time)
    /// of the same instant), or `None` before anything was sent. The RTP time is the last
    /// packet's timestamp advanced by the elapsed time at the clock rate.
    #[must_use]
    pub fn sender_report(&self, now: Instant, ntp_now: u64) -> Option<SenderInfo> {
        let (ts, at) = self.last?;
        let elapsed = now.saturating_duration_since(at);
        let ticks = elapsed.as_micros() * u128::from(self.clock_rate) / 1_000_000;
        Some(SenderInfo {
            ntp_time: ntp_now,
            rtp_time: ts.wrapping_add(ticks as u32),
            packet_count: self.packets as u32,
            octet_count: self.octets as u32,
        })
    }

    /// Handles a report block about this stream (from an RR or SR of the remote): keeps it
    /// ([`remote_report`](Self::remote_report)) and computes the RTT as
    /// `now - LSR - DLSR` (RFC 3550 §6.4.1) when it carries an LSR.
    pub fn handle_report_block(&mut self, _now: Instant, ntp_now: u64, block: &ReportBlock) {
        self.remote = Some(*block);
        if block.last_sr == 0 {
            return;
        }
        let rtt = compact_ntp(ntp_now)
            .wrapping_sub(block.last_sr)
            .wrapping_sub(block.delay_since_last_sr);
        // Negative (clock skew or bogus fields) or more than a minute: ignore.
        if rtt < 60 << 16 {
            self.rtt = Some(Duration::from_micros((u64::from(rtt) * 1_000_000) >> 16));
        }
    }
}

/// Sequence numbers tracked for duplicate detection and reordering.
const RECV_WINDOW: u64 = 2048;
/// Missing packets tracked for NACK.
const MAX_NACK_TRACKED: usize = 1000;
/// Sequence numbers in one NACK.
const MAX_NACK_PER_POLL: usize = 400;
/// NACK attempts per packet.
const MAX_NACK_TRIES: u8 = 10;
/// Missing packets are given up after this.
const NACK_GIVE_UP: Duration = Duration::from_secs(1);
/// Forward jumps larger than this are treated as a sequence discontinuity (no NACKs).
const MAX_DROPOUT: u64 = 3000;
const DEFAULT_RTT: Duration = Duration::from_millis(100);

/// Per-interval counters of the XR statistics summary.
#[derive(Debug, Clone, Copy, Default)]
struct Summary {
    begin: Option<u64>,
    received: u64,
    dups: u64,
    jitter_n: u64,
    jitter_min: f64,
    jitter_max: f64,
    jitter_sum: f64,
    jitter_sq: f64,
}

#[derive(Debug, Clone, Copy)]
struct Missing {
    since: Instant,
    last_nack: Option<Instant>,
    tries: u8,
}

/// The receiving side of one RTP stream: sequence number unwrapping, duplicate detection,
/// loss / jitter statistics for receiver reports, and NACK scheduling.
#[derive(Debug)]
pub struct RecvStream {
    ssrc: u32,
    clock_rate: u32,
    nack: bool,
    epoch: Option<Instant>,
    base: u64,
    max: Option<u64>,
    seen: Vec<u64>,
    received: u64,
    expected_prior: u64,
    received_prior: u64,
    jitter: f64,
    last_transit: Option<i64>,
    last_sr: Option<(SenderInfo, Instant)>,
    rtt: Option<Duration>,
    missing: BTreeMap<u64, Missing>,
    duplicates: u64,
    summary: Summary,
}

impl RecvStream {
    /// A receive stream for `ssrc` at RTP clock rate `clock_rate` (Hz); `nack` enables
    /// [`poll_nack`](Self::poll_nack).
    #[must_use]
    pub fn new(ssrc: u32, clock_rate: u32, nack: bool) -> RecvStream {
        RecvStream {
            ssrc,
            clock_rate: clock_rate.max(1),
            nack,
            epoch: None,
            base: 0,
            max: None,
            seen: vec![0; (RECV_WINDOW / 64) as usize],
            received: 0,
            expected_prior: 0,
            received_prior: 0,
            jitter: 0.0,
            last_transit: None,
            last_sr: None,
            rtt: None,
            missing: BTreeMap::new(),
            duplicates: 0,
            summary: Summary::default(),
        }
    }

    /// The SSRC.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Sets the round-trip time used to pace NACKs (default 100 ms).
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
    }

    /// The round-trip time set with [`set_rtt`](Self::set_rtt) or measured by
    /// [`handle_dlrr`](Self::handle_dlrr).
    #[must_use]
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Handles a DLRR sub-block answering this receiver's receiver reference time (RFC
    /// 3611 §4.5; the caller checks that `item.ssrc` is its own SSRC) received at NTP time
    /// `ntp_now`: the RTT it gives (see [`rtt_from_dlrr`](crate::rtt_from_dlrr)) also paces
    /// NACKs.
    pub fn handle_dlrr(&mut self, ntp_now: u64, item: &DlrrItem) -> Option<Duration> {
        let rtt = rtt_from_dlrr(ntp_now, item)?;
        self.rtt = Some(rtt);
        Some(rtt)
    }

    /// Duplicate packets received.
    #[must_use]
    pub fn duplicates(&self) -> u64 {
        self.duplicates
    }

    /// Distinct packets received.
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.received
    }

    /// Highest extended sequence number received.
    #[must_use]
    pub fn extended_highest_seq(&self) -> Option<u64> {
        self.max
    }

    /// Interarrival jitter in timestamp units (RFC 3550 A.8).
    #[must_use]
    pub fn jitter(&self) -> u32 {
        self.jitter as u32
    }

    /// The last sender report and when it arrived (for lip sync: NTP time <-> RTP time).
    #[must_use]
    pub fn last_sender_report(&self) -> Option<(SenderInfo, Instant)> {
        self.last_sr
    }

    /// Packets currently considered missing and tracked for NACK.
    #[must_use]
    pub fn missing_count(&self) -> usize {
        self.missing.len()
    }

    fn bit(&self, ext: u64) -> (usize, u64) {
        let pos = ext % RECV_WINDOW;
        ((pos / 64) as usize, 1 << (pos % 64))
    }

    fn is_seen(&self, ext: u64) -> bool {
        let (w, b) = self.bit(ext);
        self.seen.get(w).is_some_and(|x| x & b != 0)
    }

    fn mark(&mut self, ext: u64, on: bool) {
        let (w, b) = self.bit(ext);
        if let Some(x) = self.seen.get_mut(w) {
            if on {
                *x |= b;
            } else {
                *x &= !b;
            }
        }
    }

    /// Records a received packet. Returns its extended (rollover-corrected) sequence number,
    /// or `None` for a duplicate or a packet more than 2048 sequence numbers older than the
    /// highest one (or from before the first packet's cycle).
    pub fn receive(&mut self, now: Instant, seq: u16, timestamp: u32) -> Option<u64> {
        let epoch = *self.epoch.get_or_insert(now);
        let Some(max) = self.max else {
            let ext = u64::from(seq);
            self.base = ext;
            self.max = Some(ext);
            self.mark(ext, true);
            self.received = 1;
            self.summary.received += 1;
            self.update_jitter(now, epoch, timestamp);
            return Some(ext);
        };
        // The candidate in the cycle of `max` closest to it.
        let delta = seq.wrapping_sub(max as u16) as i16;
        let ext = u64::try_from(max as i64 + i64::from(delta)).ok()?;
        if ext > max {
            let jump = ext - max;
            // Clear the bits the window slides over.
            for e in (max + 1..=ext).take(RECV_WINDOW as usize) {
                self.mark(e, false);
            }
            if self.nack {
                if jump > MAX_DROPOUT {
                    self.missing.clear();
                } else {
                    for e in max + 1..ext {
                        self.missing.insert(
                            e,
                            Missing {
                                since: now,
                                last_nack: None,
                                tries: 0,
                            },
                        );
                    }
                    while self.missing.len() > MAX_NACK_TRACKED {
                        self.missing.pop_first();
                    }
                }
            }
            if jump > MAX_DROPOUT {
                // Restart the statistics after a discontinuity.
                self.base = ext;
                self.received = 0;
                self.expected_prior = 0;
                self.received_prior = 0;
                self.summary = Summary::default();
            }
            self.max = Some(ext);
            self.mark(ext, true);
            self.received += 1;
            self.summary.received += 1;
            self.update_jitter(now, epoch, timestamp);
            return Some(ext);
        }
        if max - ext >= RECV_WINDOW {
            return None;
        }
        if self.is_seen(ext) {
            self.duplicates += 1;
            self.summary.dups += 1;
            return None;
        }
        self.mark(ext, true);
        self.missing.remove(&ext);
        if ext < self.base {
            self.base = ext;
        }
        self.received += 1;
        self.summary.received += 1;
        Some(ext)
    }

    fn update_jitter(&mut self, now: Instant, epoch: Instant, timestamp: u32) {
        let arrival = now.saturating_duration_since(epoch).as_micros()
            * u128::from(self.clock_rate)
            / 1_000_000;
        let transit = (arrival as u32).wrapping_sub(timestamp) as i32;
        if let Some(last) = self.last_transit {
            let d = f64::from(transit.wrapping_sub(last as i32)).abs();
            self.jitter += (d - self.jitter) / 16.0;
            let s = &mut self.summary;
            if s.jitter_n == 0 {
                (s.jitter_min, s.jitter_max) = (d, d);
            } else {
                s.jitter_min = s.jitter_min.min(d);
                s.jitter_max = s.jitter_max.max(d);
            }
            s.jitter_n += 1;
            s.jitter_sum += d;
            s.jitter_sq += d * d;
        }
        self.last_transit = Some(i64::from(transit));
    }

    /// Records a sender report from this source (for LSR / DLSR in report blocks).
    pub fn handle_sender_report(&mut self, now: Instant, info: &SenderInfo) {
        self.last_sr = Some((*info, now));
    }

    /// A report block about this stream at `now`, or `None` before the first packet:
    /// fraction lost since the previous call, cumulative lost, extended highest sequence
    /// number, jitter (RFC 3550 A.3, A.8), and LSR / DLSR from the last sender report.
    pub fn report_block(&mut self, now: Instant) -> Option<ReportBlock> {
        let max = self.max?;
        let expected = max - self.base + 1;
        let lost = expected as i64 - self.received as i64;
        let exp_int = expected.saturating_sub(self.expected_prior);
        let rec_int = self.received.saturating_sub(self.received_prior);
        self.expected_prior = expected;
        self.received_prior = self.received;
        let lost_int = exp_int as i64 - rec_int as i64;
        let fraction_lost = if exp_int == 0 || lost_int <= 0 {
            0
        } else {
            ((lost_int << 8) / exp_int as i64).min(255) as u8
        };
        let (last_sr, delay_since_last_sr) = match self.last_sr {
            Some((info, at)) => {
                let d = now.saturating_duration_since(at);
                let dlsr = (d.as_micros() << 16) / 1_000_000;
                (
                    compact_ntp(info.ntp_time),
                    dlsr.min(u128::from(u32::MAX)) as u32,
                )
            }
            None => (0, 0),
        };
        Some(ReportBlock {
            ssrc: self.ssrc,
            fraction_lost,
            cumulative_lost: lost.clamp(-0x80_0000, 0x7f_ffff) as i32,
            extended_highest_seq: max as u32,
            jitter: self.jitter as u32,
            last_sr,
            delay_since_last_sr,
        })
    }

    /// An XR statistics summary (RFC 3611 §4.6) of the packets since the previous call (or
    /// the first packet): the sequence interval up to the highest received, packets lost
    /// and duplicated in it, and the minimum / maximum / mean / standard deviation of the
    /// per-packet transit time differences (timestamp units). TTLs are not known at this
    /// layer. `None` before the first packet or when nothing new arrived.
    pub fn statistics_summary(&mut self) -> Option<StatisticsSummary> {
        let max = self.max?;
        let s = self.summary;
        let begin = s.begin.unwrap_or(self.base).max(self.base);
        if begin > max && s.dups == 0 {
            return None;
        }
        let expected = (max + 1).saturating_sub(begin);
        let lost = expected.saturating_sub(s.received);
        let jitter = (s.jitter_n > 0).then(|| {
            let n = s.jitter_n as f64;
            let mean = s.jitter_sum / n;
            let dev = (s.jitter_sq / n - mean * mean).max(0.0).sqrt();
            JitterStats {
                min: s.jitter_min as u32,
                max: s.jitter_max as u32,
                mean: mean.round() as u32,
                dev: dev.round() as u32,
            }
        });
        self.summary = Summary {
            begin: Some(max + 1),
            ..Summary::default()
        };
        Some(StatisticsSummary {
            ssrc: self.ssrc,
            begin_seq: begin as u16,
            end_seq: (max + 1) as u16,
            lost_packets: Some(lost.min(u64::from(u32::MAX)) as u32),
            dup_packets: Some(s.dups.min(u64::from(u32::MAX)) as u32),
            jitter,
            ttl: None,
        })
    }

    fn nack_wait(&self) -> (Duration, Duration) {
        let rtt = self.rtt.unwrap_or(DEFAULT_RTT);
        // First NACK after a short reordering allowance, re-NACK every RTT.
        let first = (rtt / 4).clamp(Duration::from_millis(5), Duration::from_millis(20));
        let again = rtt.max(Duration::from_millis(10));
        (first, again)
    }

    /// Missing sequence numbers due for a NACK at `now`: first after a short reordering wait
    /// (a quarter of the RTT, 5..=20 ms), then again every RTT (default 100 ms), at most 10
    /// times and for at most 1 s per packet. At most 1000 missing packets are tracked and 400
    /// returned per call. `None` when NACK is disabled or nothing is due.
    pub fn poll_nack(&mut self, now: Instant) -> Option<Vec<u16>> {
        if !self.nack {
            return None;
        }
        let (first, again) = self.nack_wait();
        let mut out = Vec::new();
        self.missing.retain(|&ext, m| {
            if m.tries >= MAX_NACK_TRIES || now.saturating_duration_since(m.since) > NACK_GIVE_UP {
                return false;
            }
            let due = match m.last_nack {
                None => now.saturating_duration_since(m.since) >= first,
                Some(t) => now.saturating_duration_since(t) >= again,
            };
            if due && out.len() < MAX_NACK_PER_POLL {
                m.last_nack = Some(now);
                m.tries += 1;
                out.push(ext as u16);
            }
            true
        });
        (!out.is_empty()).then_some(out)
    }

    /// When [`poll_nack`](Self::poll_nack) next has something to do (a NACK or a give-up).
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        if !self.nack {
            return None;
        }
        let (first, again) = self.nack_wait();
        self.missing
            .values()
            .filter_map(|m| match m.last_nack {
                None => m.since.checked_add(first),
                Some(t) => t.checked_add(again),
            })
            .min()
    }
}
