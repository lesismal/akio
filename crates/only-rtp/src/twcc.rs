//! Transport-wide congestion control (draft-holmer-rmcat-transport-wide-cc-extensions-01):
//! the sender's packet log and the receiver's feedback generator.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::rtcp::{Rtcp, TwccFeedback};

/// Extends a 16-bit sequence number to the 64-bit one closest to `last` (`None` below 0).
fn unwrap16(last: u64, seq: u16) -> Option<u64> {
    let delta = i64::from(seq.wrapping_sub(last as u16) as i16);
    u64::try_from(last as i64 + delta).ok()
}

/// Sent packets remembered for feedback.
const SENDER_HISTORY: u64 = 8192;

/// The fate of one sent packet, from transport-wide feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketResult {
    /// Extended transport-wide sequence number.
    pub seq: u64,
    /// When it was sent ([`TwccSender::on_sent`]).
    pub sent: Instant,
    /// Its size in bytes as given to [`TwccSender::on_sent`].
    pub size: usize,
    /// Its arrival time on the remote clock mapped onto local `Instant`s (only differences
    /// between arrivals are meaningful), or `None` if reported lost.
    pub received: Option<Instant>,
    /// The probe cluster it belonged to ([`TwccSender::on_sent_probe`],
    /// [`CcfbSender::on_sent_probe`](crate::CcfbSender::on_sent_probe)), if any.
    pub probe: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct SentPacket {
    at: Instant,
    size: usize,
    probe: Option<u32>,
}

/// The sending side of transport-wide CC: assigns transport-wide sequence numbers, logs
/// sends, and turns [`TwccFeedback`] into [`PacketResult`]s for a
/// [`BandwidthEstimator`](crate::BandwidthEstimator).
#[derive(Debug)]
pub struct TwccSender {
    next: u64,
    sent: BTreeMap<u64, SentPacket>,
    /// Extended reference time (64 ms units) of the last feedback, for unwrapping.
    last_ref: Option<i64>,
    /// `(local instant, remote µs)` anchor mapping remote arrival times onto `Instant`s.
    anchor: Option<(Instant, i64)>,
}

impl Default for TwccSender {
    fn default() -> TwccSender {
        TwccSender::new()
    }
}

impl TwccSender {
    /// A sender starting at transport-wide sequence number 0.
    #[must_use]
    pub fn new() -> TwccSender {
        TwccSender {
            next: 0,
            sent: BTreeMap::new(),
            last_ref: None,
            anchor: None,
        }
    }

    /// The next transport-wide sequence number (put it in
    /// [`ExtensionValues::transport_cc`](crate::ExtensionValues::transport_cc)).
    pub fn next_seq(&mut self) -> u16 {
        let s = self.next as u16;
        self.next += 1;
        s
    }

    /// Logs that the packet with transport-wide sequence number `seq` and `size` bytes left
    /// at `now`. The last 8192 packets are remembered.
    pub fn on_sent(&mut self, seq: u16, now: Instant, size: usize) {
        self.log(seq, now, size, None);
    }

    /// [`on_sent`](Self::on_sent) for a probe packet of cluster `cluster`
    /// ([`BandwidthEstimator::poll_probe`](crate::BandwidthEstimator::poll_probe)).
    pub fn on_sent_probe(&mut self, seq: u16, now: Instant, size: usize, cluster: u32) {
        self.log(seq, now, size, Some(cluster));
    }

    fn log(&mut self, seq: u16, now: Instant, size: usize, probe: Option<u32>) {
        let last = self.next.saturating_sub(1);
        let Some(ext) = unwrap16(last, seq) else {
            return;
        };
        if ext >= self.next {
            self.next = ext + 1;
        }
        self.sent.insert(
            ext,
            SentPacket {
                at: now,
                size,
                probe,
            },
        );
        while self
            .sent
            .first_key_value()
            .is_some_and(|(&k, _)| k + SENDER_HISTORY < self.next)
        {
            self.sent.pop_first();
        }
    }

    /// Matches feedback against the send log. Returns one result per reported packet that
    /// is still in the log, in sequence order; packets reported received leave the log, lost
    /// ones stay (a later feedback may report them received).
    pub fn on_feedback(&mut self, now: Instant, fb: &TwccFeedback) -> Vec<PacketResult> {
        let mut out = Vec::new();
        let Some(base) = unwrap16(self.next.saturating_sub(1), fb.base_seq) else {
            return out;
        };
        // Unwrap the 24-bit reference time.
        let r = i64::from(fb.reference_time & 0x00ff_ffff);
        let ref_ext = match self.last_ref {
            None => r,
            Some(last) => {
                let d = (r - last).rem_euclid(1 << 24);
                let d = if d >= 1 << 23 { d - (1 << 24) } else { d };
                last + d
            }
        };
        self.last_ref = Some(ref_ext);
        let mut t_us = ref_ext * 64_000;
        for (i, &(_, delta)) in fb.packets.iter().enumerate() {
            let ext = base + i as u64;
            let received = delta.map(|d| {
                t_us += d * 250;
                let (a_inst, a_us) = *self.anchor.get_or_insert((now, t_us));
                let off = t_us - a_us;
                if off >= 0 {
                    a_inst.checked_add(Duration::from_micros(off as u64))
                } else {
                    a_inst.checked_sub(Duration::from_micros(off.unsigned_abs()))
                }
            });
            let Some(p) = self.sent.get(&ext).copied() else {
                continue;
            };
            let received = match received {
                Some(Some(t)) => Some(t),
                Some(None) => Some(now),
                None => None,
            };
            if received.is_some() {
                self.sent.remove(&ext);
            }
            out.push(PacketResult {
                seq: ext,
                sent: p.at,
                size: p.size,
                received,
                probe: p.probe,
            });
        }
        out
    }
}

/// Feedback interval of [`TwccReceiver`].
pub const TWCC_FEEDBACK_INTERVAL: Duration = Duration::from_millis(100);
/// Pending packets that trigger feedback before the interval elapses.
const FEEDBACK_PACKETS: usize = 100;
/// Packets (statuses) per feedback, so it fits an MTU.
const MAX_FEEDBACK_STATUSES: u64 = 400;
/// Arrivals kept before the oldest are dropped.
const MAX_PENDING: usize = 16_384;

/// The receiving side of transport-wide CC: records arrivals and builds
/// [`Rtcp::TransportCc`] feedback (every 100 ms, or once 100 packets are pending), with the
/// same delta rounding and chunk packing as libwebrtc and pion.
#[derive(Debug)]
pub struct TwccReceiver {
    epoch: Option<Instant>,
    /// Arrival times (µs since `epoch`) by extended sequence number.
    pending: BTreeMap<u64, i64>,
    /// First sequence number of the next feedback.
    next_base: Option<u64>,
    last_seq: Option<u64>,
    last_feedback: Option<Instant>,
    more: bool,
    fb_count: u8,
}

impl Default for TwccReceiver {
    fn default() -> TwccReceiver {
        TwccReceiver::new()
    }
}

impl TwccReceiver {
    /// An empty receiver.
    #[must_use]
    pub fn new() -> TwccReceiver {
        TwccReceiver {
            epoch: None,
            pending: BTreeMap::new(),
            next_base: None,
            last_seq: None,
            last_feedback: None,
            more: false,
            fb_count: 0,
        }
    }

    /// Records the arrival of the packet with transport-wide sequence number `seq` at `now`.
    /// Duplicates and packets older than the last feedback are ignored.
    pub fn on_received(&mut self, seq: u16, now: Instant) {
        let epoch = *self.epoch.get_or_insert(now);
        let ext = match self.last_seq {
            // Start in the middle of the 64-bit space so early reordering stays positive.
            None => (1 << 32) + u64::from(seq),
            Some(last) => match unwrap16(last, seq) {
                Some(e) => e,
                None => return,
            },
        };
        if self.last_seq.is_none_or(|l| ext > l) {
            self.last_seq = Some(ext);
        }
        match self.next_base {
            Some(b) if ext < b => {
                // Already reported (as lost) unless nothing was reported yet.
                if self.last_feedback.is_some() || b - ext > MAX_FEEDBACK_STATUSES {
                    return;
                }
                self.next_base = Some(ext);
            }
            None => self.next_base = Some(ext),
            _ => {}
        }
        let us = now.saturating_duration_since(epoch).as_micros() as i64;
        self.pending.entry(ext).or_insert(us);
        while self.pending.len() > MAX_PENDING {
            if let Some((k, _)) = self.pending.pop_first() {
                self.next_base = Some(k + 1);
            }
        }
    }

    /// Feedback due at `now`, or `None` (nothing pending, or neither the interval elapsed
    /// nor 100 packets are waiting). Call repeatedly: a long backlog is split into several
    /// feedback packets of at most 400 statuses.
    pub fn poll_feedback(
        &mut self,
        now: Instant,
        sender_ssrc: u32,
        media_ssrc: u32,
    ) -> Option<Rtcp> {
        if self.pending.is_empty() {
            return None;
        }
        let due = self.more
            || self.pending.len() >= FEEDBACK_PACKETS
            || self
                .last_feedback
                .is_none_or(|t| now.saturating_duration_since(t) >= TWCC_FEEDBACK_INTERVAL);
        if !due {
            return None;
        }
        let base = self.next_base?;
        let (&first, &first_us) = self.pending.first_key_value()?;
        let base = base.max(first.saturating_sub(0x7ffe));
        let reference = first_us.div_euclid(64_000);
        let mut last_us = reference * 64_000;
        let mut packets = Vec::new();
        let mut next = base;
        let mut taken = Vec::new();
        for (&seq, &us) in &self.pending {
            if seq - base >= MAX_FEEDBACK_STATUSES {
                break;
            }
            let d = us - last_us;
            let d250 = if d >= 0 {
                (d + 125) / 250
            } else {
                (d - 125) / 250
            };
            if d250 < i64::from(i16::MIN) || d250 > i64::from(i16::MAX) {
                break;
            }
            while next < seq {
                packets.push((next as u16, None));
                next += 1;
            }
            packets.push((seq as u16, Some(d250)));
            last_us += d250 * 250;
            next = seq + 1;
            taken.push(seq);
        }
        if taken.is_empty() {
            // Cannot happen with a non-empty map, but never loop forever.
            self.pending.clear();
            return None;
        }
        for s in &taken {
            self.pending.remove(s);
        }
        self.next_base = Some(next);
        self.more = !self.pending.is_empty();
        self.last_feedback = Some(now);
        let fb = TwccFeedback {
            sender_ssrc,
            media_ssrc,
            base_seq: base as u16,
            reference_time: (reference & 0x00ff_ffff) as u32,
            fb_count: self.fb_count,
            packets,
        };
        self.fb_count = self.fb_count.wrapping_add(1);
        Some(Rtcp::TransportCc(fb))
    }
}
