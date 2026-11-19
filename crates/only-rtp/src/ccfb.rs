//! RTP congestion control feedback (RFC 8888): the receiver's report generator and the
//! sender's matching of reports onto sent packets.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::rtcp::{
    CCFB_ATO_OVERRANGE, CCFB_ATO_UNAVAILABLE, CcfbFeedback, CcfbMetric, CcfbStream, Rtcp,
    compact_ntp,
};
use crate::twcc::PacketResult;

/// Extends a 16-bit sequence number to the 64-bit one closest to `last`.
fn unwrap16(last: u64, seq: u16) -> Option<u64> {
    let delta = i64::from(seq.wrapping_sub(last as u16) as i16);
    u64::try_from(last as i64 + delta).ok()
}

/// Default feedback interval of [`CcfbReceiver`].
pub const CCFB_FEEDBACK_INTERVAL: Duration = Duration::from_millis(50);
/// Pending packets that trigger feedback before the interval elapses.
const FEEDBACK_PACKETS: usize = 100;
/// Packet reports per feedback packet (with the 8-byte stream headers this stays well
/// inside an MTU).
const MAX_REPORTS_PER_FEEDBACK: u64 = 500;
/// Arrivals kept per stream before the oldest are dropped.
const MAX_PENDING: usize = 16_384;
/// Streams tracked.
const MAX_STREAMS: usize = 64;

#[derive(Debug, Default)]
struct RxStream {
    /// Arrival (µs since the receiver's epoch) and ECN by extended sequence number.
    pending: BTreeMap<u64, (i64, u8)>,
    /// First sequence number of the next report.
    next_begin: Option<u64>,
    last_seq: Option<u64>,
    reported: bool,
}

/// The receiving side of RFC 8888: records arrivals per media SSRC and builds
/// [`Rtcp::CongestionControl`] feedback every [`CCFB_FEEDBACK_INTERVAL`] (or when 100
/// packets are pending). Each packet is reported once; a packet that arrives after a report
/// already covered it as lost is not reported again.
#[derive(Debug)]
pub struct CcfbReceiver {
    epoch: Option<Instant>,
    streams: BTreeMap<u32, RxStream>,
    interval: Duration,
    last_feedback: Option<Instant>,
    more: bool,
}

impl Default for CcfbReceiver {
    fn default() -> CcfbReceiver {
        CcfbReceiver::new()
    }
}

impl CcfbReceiver {
    /// An empty receiver.
    #[must_use]
    pub fn new() -> CcfbReceiver {
        CcfbReceiver {
            epoch: None,
            streams: BTreeMap::new(),
            interval: CCFB_FEEDBACK_INTERVAL,
            last_feedback: None,
            more: false,
        }
    }

    /// Sets the feedback interval (RFC 8888 suggests about one per video frame or RTT).
    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    /// Records the arrival of packet `seq` of `ssrc` at `now` with the ECN bits `ecn` (0 if
    /// unknown). Duplicates and packets already reported are ignored; at most 64 streams
    /// are tracked.
    pub fn on_received(&mut self, ssrc: u32, seq: u16, now: Instant, ecn: u8) {
        let epoch = *self.epoch.get_or_insert(now);
        if !self.streams.contains_key(&ssrc) && self.streams.len() >= MAX_STREAMS {
            return;
        }
        let s = self.streams.entry(ssrc).or_default();
        let ext = match s.last_seq {
            None => (1 << 32) + u64::from(seq),
            Some(last) => match unwrap16(last, seq) {
                Some(e) => e,
                None => return,
            },
        };
        if s.last_seq.is_none_or(|l| ext > l) {
            s.last_seq = Some(ext);
        }
        match s.next_begin {
            Some(b) if ext < b => {
                if s.reported || b - ext > MAX_REPORTS_PER_FEEDBACK {
                    return;
                }
                s.next_begin = Some(ext);
            }
            None => s.next_begin = Some(ext),
            _ => {}
        }
        let us = now.saturating_duration_since(epoch).as_micros() as i64;
        s.pending.entry(ext).or_insert((us, ecn & 3));
        while s.pending.len() > MAX_PENDING {
            if let Some((k, _)) = s.pending.pop_first() {
                s.next_begin = Some(k + 1);
            }
        }
    }

    /// Feedback due at `now` (`ntp_now` = [`ntp_time`](crate::ntp_time) of the same
    /// instant, for the report timestamp), or `None`. A long backlog is split over several
    /// calls of at most 500 packet reports each.
    pub fn poll_feedback(&mut self, now: Instant, ntp_now: u64, sender_ssrc: u32) -> Option<Rtcp> {
        if self.streams.values().all(|s| s.pending.is_empty()) {
            return None;
        }
        let due = self.more
            || self
                .streams
                .values()
                .map(|s| s.pending.len())
                .sum::<usize>()
                >= FEEDBACK_PACKETS
            || self
                .last_feedback
                .is_none_or(|t| now.saturating_duration_since(t) >= self.interval);
        if !due {
            return None;
        }
        let epoch = self.epoch?;
        let now_us = now.saturating_duration_since(epoch).as_micros() as i64;
        let mut budget = MAX_REPORTS_PER_FEEDBACK;
        let mut streams = Vec::new();
        for (&ssrc, s) in &mut self.streams {
            if budget == 0 {
                break;
            }
            let (Some(begin), Some((&last, _))) = (s.next_begin, s.pending.last_key_value()) else {
                continue;
            };
            let end = last.min(begin + budget - 1);
            let mut reports = Vec::with_capacity((end + 1 - begin) as usize);
            for seq in begin..=end {
                reports.push(s.pending.remove(&seq).map(|(us, ecn)| {
                    let ato = now_us - us;
                    let arrival_offset = if ato < 0 {
                        CCFB_ATO_UNAVAILABLE
                    } else {
                        ((ato * 1024) / 1_000_000).min(i64::from(CCFB_ATO_OVERRANGE)) as u16
                    };
                    CcfbMetric {
                        ecn,
                        arrival_offset,
                    }
                }));
            }
            budget -= end + 1 - begin;
            s.next_begin = Some(end + 1);
            s.reported = true;
            streams.push(CcfbStream {
                ssrc,
                begin_seq: begin as u16,
                reports,
            });
        }
        self.more = self.streams.values().any(|s| !s.pending.is_empty());
        self.last_feedback = Some(now);
        Some(Rtcp::CongestionControl(CcfbFeedback {
            sender_ssrc,
            streams,
            report_timestamp: compact_ntp(ntp_now),
        }))
    }
}

/// Sent packets remembered per stream.
const SENDER_HISTORY: u64 = 8192;

#[derive(Debug, Clone, Copy)]
struct Sent {
    index: u64,
    at: Instant,
    size: usize,
    probe: Option<u32>,
}

#[derive(Debug, Default)]
struct TxStream {
    last: Option<u64>,
    sent: BTreeMap<u64, Sent>,
}

/// The sending side of RFC 8888: logs sent packets per SSRC and turns
/// [`CcfbFeedback`] into [`PacketResult`]s for a
/// [`BandwidthEstimator`](crate::BandwidthEstimator). `PacketResult::seq` is a send-order
/// index across all streams.
#[derive(Debug, Default)]
pub struct CcfbSender {
    next_index: u64,
    streams: BTreeMap<u32, TxStream>,
    /// Extended report timestamp (1/65536 s) of the last feedback, for unwrapping.
    last_ts: Option<i64>,
    /// `(local instant, remote µs)` anchor mapping remote arrival times onto `Instant`s.
    anchor: Option<(Instant, i64)>,
}

impl CcfbSender {
    /// An empty sender.
    #[must_use]
    pub fn new() -> CcfbSender {
        CcfbSender::default()
    }

    /// Logs that packet `seq` of `ssrc`, `size` bytes, left at `now`. The last 8192
    /// packets per stream are remembered.
    pub fn on_sent(&mut self, ssrc: u32, seq: u16, now: Instant, size: usize) {
        self.log(ssrc, seq, now, size, None);
    }

    /// [`on_sent`](Self::on_sent) for a probe packet of cluster `cluster`
    /// ([`BandwidthEstimator::poll_probe`](crate::BandwidthEstimator::poll_probe)).
    pub fn on_sent_probe(&mut self, ssrc: u32, seq: u16, now: Instant, size: usize, cluster: u32) {
        self.log(ssrc, seq, now, size, Some(cluster));
    }

    fn log(&mut self, ssrc: u32, seq: u16, now: Instant, size: usize, probe: Option<u32>) {
        let s = self.streams.entry(ssrc).or_default();
        let ext = match s.last {
            None => (1 << 32) + u64::from(seq),
            Some(l) => match unwrap16(l, seq) {
                Some(e) => e,
                None => return,
            },
        };
        if s.last.is_none_or(|l| ext > l) {
            s.last = Some(ext);
        }
        s.sent.insert(
            ext,
            Sent {
                index: self.next_index,
                at: now,
                size,
                probe,
            },
        );
        self.next_index += 1;
        let top = s.last.unwrap_or(ext);
        while s
            .sent
            .first_key_value()
            .is_some_and(|(&k, _)| k + SENDER_HISTORY <= top)
        {
            s.sent.pop_first();
        }
    }

    /// Matches feedback against the send log: one result per reported packet still in the
    /// log, in send order (a packet reported more than once counts as received if any report
    /// says so). Packets reported received leave the log, lost ones stay (a later report may
    /// cover them again). Packets received with an unavailable or over-range
    /// arrival offset leave the log without a result.
    pub fn on_feedback(&mut self, now: Instant, fb: &CcfbFeedback) -> Vec<PacketResult> {
        // Unwrap the 32-bit report timestamp (1/65536 s).
        let ts = i64::from(fb.report_timestamp);
        let ts = match self.last_ts {
            None => ts,
            Some(last) => {
                let d = (ts - last).rem_euclid(1 << 32);
                last + if d >= 1 << 31 { d - (1 << 32) } else { d }
            }
        };
        self.last_ts = Some(ts);
        let report_us = (i128::from(ts) * 1_000_000 / 65_536) as i64;
        let mut out = BTreeMap::new();
        for st in &fb.streams {
            let Some(s) = self.streams.get_mut(&st.ssrc) else {
                continue;
            };
            let Some(base) = s.last.and_then(|l| unwrap16(l, st.begin_seq)) else {
                continue;
            };
            for (i, r) in st.reports.iter().enumerate() {
                let ext = base + i as u64;
                let Some(p) = s.sent.get(&ext).copied() else {
                    continue;
                };
                let received = match r {
                    None => None,
                    Some(m) if m.arrival_offset >= CCFB_ATO_OVERRANGE => {
                        s.sent.remove(&ext);
                        out.remove(&p.index);
                        continue;
                    }
                    Some(m) => {
                        s.sent.remove(&ext);
                        let t = report_us - i64::from(m.arrival_offset) * 1_000_000 / 1024;
                        let (a_inst, a_us) = *self.anchor.get_or_insert((now, t));
                        let off = t - a_us;
                        Some(
                            if off >= 0 {
                                a_inst.checked_add(Duration::from_micros(off as u64))
                            } else {
                                a_inst.checked_sub(Duration::from_micros(off.unsigned_abs()))
                            }
                            .unwrap_or(now),
                        )
                    }
                };
                let res = PacketResult {
                    seq: p.index,
                    sent: p.at,
                    size: p.size,
                    received,
                    probe: p.probe,
                };
                if received.is_some() {
                    out.insert(p.index, res);
                } else {
                    out.entry(p.index).or_insert(res);
                }
            }
        }
        out.into_values().collect()
    }
}
