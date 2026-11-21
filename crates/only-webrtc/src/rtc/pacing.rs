//! The send path's pacing and probing (ADR-050, ADR-073).
//!
//! - **Pacer** (libwebrtc's `PacingController`): with the bandwidth estimator on, video, FEC
//!   and retransmissions leave through a queue drained at 2.5 times the estimate, with a
//!   burst allowance of 40 ms worth of bytes (a frame that fits leaves at once, a keyframe is
//!   spread out); retransmissions go before new media; audio is never queued (it is sent at
//!   once and counted against the budget, as libwebrtc does); the debt is capped at 500 ms;
//!   a queue older than 2 s raises the rate so that it drains in time. Transport-wide
//!   sequence numbers and abs-send-time are written when a packet leaves, so feedback measures
//!   the paced send times. Padding (RTX copies of recent media, or padding-only packets) fills
//!   the configured padding rate while the queue is empty.
//! - **Probing**: the estimator's probe clusters go out at their own pace; queued media goes
//!   out in a probe's slot before padding is made for it (libwebrtc's clusters carry media
//!   too). A new ICE pair restarts the estimate.

use super::*;

/// Probe packets sent per call (a 15 ms cluster at 20 Mbps is about 30 packets).
const MAX_PROBES_PER_CALL: usize = 64;
/// The pacing rate is this multiple of the estimate (libwebrtc's `kDefaultPaceMultiplier`).
const PACING_FACTOR: f64 = 2.5;
/// Bytes may leave at once up to this long at the pacing rate (`kDefaultBurstInterval`).
const BURST: Duration = Duration::from_millis(40);
/// The debt never exceeds this long at the pacing rate (`kMaxDebtInTime`).
const MAX_DEBT: Duration = Duration::from_millis(500);
/// Queued packets drain within this time at least (`kMaxExpectedQueueLength`).
const QUEUE_TIME_LIMIT: Duration = Duration::from_secs(2);
/// Elapsed time credited at once at most (`kMaxElapsedTime`).
const MAX_ELAPSED: Duration = Duration::from_secs(2);
/// Queued packets and bytes at most; past them the oldest media is dropped.
const MAX_QUEUED_PACKETS: usize = 8192;
const MAX_QUEUED_BYTES: usize = 8 << 20;
/// Padding packets per call, and their size.
const MAX_PADDING_PER_CALL: usize = 16;
const PADDING_SIZE: usize = 1000;
/// Bytes of slack in the budget comparisons.
const SLACK: f64 = 1.0;

/// A packet waiting in the pacer: the plain RTP packet (before SRTP) and the header extension
/// ids to fill when it leaves.
#[derive(Debug)]
pub(super) struct Queued {
    pub(super) raw: Vec<u8>,
    /// transport-wide-cc: a sequence number is taken when the packet leaves.
    pub(super) twcc: Option<u8>,
    /// abs-send-time, written when it leaves.
    pub(super) ast: Option<u8>,
    pub(super) fec: bool,
    pub(super) at: Instant,
}

/// What a sent packet is to the pacer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Class {
    /// Not queued; counted against the budget.
    Audio,
    /// Queued ahead of media.
    Retransmission,
    /// Video media and FEC.
    Media,
}

/// The pacer's queues and budget.
#[derive(Debug, Default)]
pub(super) struct Pacer {
    /// 0: retransmissions, 1: media and FEC.
    queues: [VecDeque<Queued>; 2],
    bytes: usize,
    /// Pacing and padding rates, bytes per second (0: not pacing / no padding).
    rate: f64,
    padding_rate: f64,
    /// Bytes sent beyond the budget, and padding beyond the padding budget.
    debt: f64,
    padding_debt: f64,
    last: Option<Instant>,
    /// Media packets dropped because the queue was full.
    pub(super) dropped: u64,
}

impl Pacer {
    pub(super) fn is_empty(&self) -> bool {
        self.bytes == 0 && self.queues.iter().all(VecDeque::is_empty)
    }

    /// Pacing at 2.5 times `estimate` (bits per second), padding up to `padding` of it.
    pub(super) fn set_rates(&mut self, estimate: u64, padding: u64) {
        self.rate = estimate as f64 * PACING_FACTOR / 8.0;
        self.padding_rate = padding.min(estimate) as f64 / 8.0;
    }

    /// The rate the queue drains at: the pacing rate, or faster if the queue would otherwise
    /// take longer than 2 s from its oldest packet.
    fn drain_rate(&self, now: Instant) -> f64 {
        let oldest = self
            .queues
            .iter()
            .filter_map(|q| q.front())
            .map(|q| q.at)
            .min();
        match oldest {
            Some(at) => {
                let left = QUEUE_TIME_LIMIT
                    .saturating_sub(now.saturating_duration_since(at))
                    .max(Duration::from_millis(10));
                self.rate.max(self.bytes as f64 / left.as_secs_f64())
            }
            None => self.rate,
        }
    }

    /// Credits the time since the last call.
    pub(super) fn advance(&mut self, now: Instant) {
        let elapsed = match self.last {
            Some(l) if now > l => now.saturating_duration_since(l).min(MAX_ELAPSED),
            Some(_) => return,
            None => Duration::ZERO,
        };
        self.last = Some(now);
        let s = elapsed.as_secs_f64();
        self.debt = (self.debt - self.drain_rate(now) * s).max(0.0);
        self.padding_debt = (self.padding_debt - self.padding_rate * s).max(0.0);
    }

    /// Whether a queued packet may leave now (the debt is within the burst allowance, with a
    /// byte of slack so that [`next_send`](Self::next_send) and this agree despite rounding).
    pub(super) fn can_send(&self, now: Instant) -> bool {
        self.debt <= self.drain_rate(now) * BURST.as_secs_f64() + SLACK
    }

    pub(super) fn push(&mut self, class: Class, q: Queued) {
        let i = usize::from(class != Class::Retransmission);
        self.bytes += q.raw.len();
        self.queues[i].push_back(q);
        while self.queues.iter().map(VecDeque::len).sum::<usize>() > MAX_QUEUED_PACKETS
            || self.bytes > MAX_QUEUED_BYTES
        {
            let Some(old) = self.queues[1]
                .pop_front()
                .or_else(|| self.queues[0].pop_front())
            else {
                break;
            };
            self.bytes -= old.raw.len();
            self.dropped += 1;
        }
    }

    /// The next packet to send: retransmissions first.
    pub(super) fn pop(&mut self) -> Option<Queued> {
        let q = self.queues[0]
            .pop_front()
            .or_else(|| self.queues[1].pop_front())?;
        self.bytes -= q.raw.len();
        Some(q)
    }

    /// `bytes` were sent (queued, audio or probe packets).
    pub(super) fn on_sent(&mut self, bytes: usize) {
        let cap = self.rate * MAX_DEBT.as_secs_f64();
        self.debt = (self.debt + bytes as f64).min(cap.max(bytes as f64));
    }

    /// Padding of `bytes` was sent.
    pub(super) fn on_padding(&mut self, bytes: usize) {
        self.on_sent(bytes);
        let cap = self.padding_rate * MAX_DEBT.as_secs_f64();
        self.padding_debt = (self.padding_debt + bytes as f64).min(cap.max(bytes as f64));
    }

    /// The size of a padding packet due now, if any: the queue is empty and both budgets
    /// allow it.
    pub(super) fn padding_due(&self, now: Instant) -> Option<usize> {
        (self.padding_rate > 0.0
            && self.is_empty()
            && self.can_send(now)
            && self.padding_debt <= 0.0)
            .then_some(PADDING_SIZE)
    }

    /// When the next packet may leave (a queued one, or padding).
    pub(super) fn next_send(&self, now: Instant) -> Option<Instant> {
        let last = self.last.unwrap_or(now);
        if !self.is_empty() {
            let rate = self.drain_rate(now);
            if rate <= 0.0 {
                return None;
            }
            let over = self.debt - rate * BURST.as_secs_f64() - SLACK;
            return Some(if over <= 0.0 {
                now
            } else {
                last + Duration::from_secs_f64(over / rate)
            });
        }
        if self.padding_rate > 0.0 && self.rate > 0.0 {
            let media = (self.debt - self.rate * BURST.as_secs_f64()).max(0.0) / self.rate;
            let pad = self.padding_debt / self.padding_rate;
            return Some(last + Duration::from_secs_f64(media.max(pad).max(0.001)));
        }
        None
    }
}

/// Overwrites the value of header extension element `id` of an RTP packet (RFC 8285 one- or
/// two-byte form) with `val`; `false` if the element is absent or of another length.
pub(super) fn patch_ext(p: &mut [u8], id: u8, val: &[u8]) -> bool {
    if p.len() < 12 || p[0] & 0x10 == 0 {
        return false;
    }
    let i = 12 + 4 * usize::from(p[0] & 0x0f);
    let Some(h) = p.get(i..i + 4) else {
        return false;
    };
    let profile = u16::from_be_bytes([h[0], h[1]]);
    let end = i + 4 + 4 * usize::from(u16::from_be_bytes([h[2], h[3]]));
    if end > p.len() {
        return false;
    }
    let mut j = i + 4;
    if profile == 0xbede {
        while j < end {
            let b = p[j];
            if b == 0 {
                j += 1;
                continue;
            }
            let (eid, len) = (b >> 4, usize::from(b & 0x0f) + 1);
            if eid == 15 || j + 1 + len > end {
                return false;
            }
            if eid == id {
                if len != val.len() {
                    return false;
                }
                p[j + 1..j + 1 + len].copy_from_slice(val);
                return true;
            }
            j += 1 + len;
        }
    } else if profile & 0xfff0 == 0x1000 {
        while j + 1 < end {
            let eid = p[j];
            if eid == 0 {
                j += 1;
                continue;
            }
            let len = usize::from(p[j + 1]);
            if j + 2 + len > end {
                return false;
            }
            if eid == id {
                if len != val.len() {
                    return false;
                }
                p[j + 2..j + 2 + len].copy_from_slice(val);
                return true;
            }
            j += 2 + len;
        }
    }
    false
}

impl Rtc {
    /// Whether media is paced: the estimator is on and pacing is not turned off.
    pub(super) fn pacing(&self) -> bool {
        self.bwe.is_some() && self.cfg.pacing
    }

    /// Sends `q` now (or queues it while paced, `class` deciding how): sequence numbers of
    /// transport-wide feedback and abs-send-time are written as it leaves.
    pub(super) fn send_rtp(&mut self, now: Instant, class: Class, q: Queued) {
        if self.pacing() && class != Class::Audio {
            self.pacer.push(class, q);
            self.pace(now);
            return;
        }
        let n = self.release(now, q, None);
        if self.pacing() {
            self.pacer.on_sent(n);
        }
    }

    /// Fills in the send-time extensions of `q`, logs it for feedback (in probe cluster
    /// `probe`), protects and transmits it; returns its size before SRTP (0 if it could not be
    /// sent).
    pub(super) fn release(&mut self, now: Instant, mut q: Queued, probe: Option<u32>) -> usize {
        let (Some(_), Some((src, dest))) = (self.srtp_tx.as_ref(), self.ice.send_pair()) else {
            return 0;
        };
        let mut tw = None;
        if let Some(id) = q.twcc {
            let s = self.twcc_tx.next_seq();
            if patch_ext(&mut q.raw, id, &s.to_be_bytes()) {
                tw = Some(s);
            }
        }
        if let Some(id) = q.ast {
            patch_ext(&mut q.raw, id, &abs_send_time_now().to_be_bytes()[1..]);
        }
        let raw = &q.raw;
        match (tw, probe) {
            (Some(s), None) => self.twcc_tx.on_sent(s, now, raw.len()),
            (Some(s), Some(c)) => self.twcc_tx.on_sent_probe(s, now, raw.len(), c),
            (None, Some(c)) if self.ccfb && raw.len() >= 12 => {
                let seq = u16::from_be_bytes([raw[2], raw[3]]);
                let ssrc = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
                self.ccfb_tx.on_sent_probe(ssrc, seq, now, raw.len(), c);
            }
            _ => {}
        }
        if probe.is_none() {
            self.note_sent(now, raw);
        }
        if q.fec {
            self.stats.fec_sent += 1;
        }
        let Some(tx) = self.srtp_tx.as_mut() else {
            return 0;
        };
        match tx.protect_rtp(raw) {
            Ok(o) => {
                self.stats.bytes_sent += o.len() as u64;
                self.stats.packets_sent += 1;
                self.transmits.push_back((src, dest, o));
                raw.len()
            }
            Err(_) => 0,
        }
    }

    /// Releases what the pacer lets out at `now`, then padding.
    pub(super) fn pace(&mut self, now: Instant) {
        if !self.pacing() {
            return;
        }
        let estimate = self.bwe.as_ref().map_or(0, BandwidthEstimator::estimate);
        self.pacer.set_rates(estimate, self.cfg.padding_rate);
        self.pacer.advance(now);
        while self.pacer.can_send(now) {
            let Some(q) = self.pacer.pop() else {
                break;
            };
            let n = self.release(now, q, None);
            self.pacer.on_sent(n);
        }
        for _ in 0..MAX_PADDING_PER_CALL {
            let Some(size) = self.pacer.padding_due(now) else {
                break;
            };
            match self.send_padding(now, size, None) {
                Some(n) => self.pacer.on_padding(n),
                None => break,
            }
        }
    }

    /// When the pacer has something to send next.
    pub(super) fn pacer_timeout(&self, now: Instant) -> Option<Instant> {
        if !self.pacing() {
            return None;
        }
        self.pacer.next_send(now)
    }

    /// The stream padding and probes go on: the one that sent the most media among the lines
    /// with congestion control feedback (line, simulcast encoding).
    fn padding_stream(&self) -> Option<(usize, Option<usize>)> {
        let ccfb = self.ccfb;
        self.media
            .iter()
            .enumerate()
            .filter(|(_, l)| !l.stopped && (ccfb || l.ext.id_of(Extension::TransportCc).is_some()))
            .flat_map(|(i, l)| {
                let sim = l.sim.iter().enumerate();
                std::iter::once((i, None, l.send.octets_sent()))
                    .chain(sim.map(move |(j, e)| (i, Some(j), e.send.octets_sent())))
            })
            .filter(|c| c.2 > 0)
            .max_by_key(|c| c.2)
            .map(|(i, e, _)| (i, e))
    }

    /// Sends a padding packet of about `size` bytes (an RTX copy of recent media, or
    /// padding) on the stream that sent the most media among the lines with congestion
    /// control feedback, logged under probe cluster `cluster`; the bytes sent, `None` if no
    /// stream can carry it (nothing sent yet, no path).
    fn send_padding(&mut self, now: Instant, size: usize, cluster: Option<u32>) -> Option<usize> {
        let (true, Some((src, dest))) = (self.srtp_tx.is_some(), self.ice.send_pair()) else {
            return None;
        };
        let (li, enc) = self.padding_stream()?;
        let line = &mut self.media[li];
        let rtx_pt = match line.last_pt {
            Some(p) if line.fec_pts.red == Some(p) => line.fec_pts.red_rtx,
            p => p.and_then(|p| line.codec(p)).and_then(|c| c.rtx),
        };
        let has_twcc = line.ext.id_of(Extension::TransportCc).is_some();
        let has_rrid = line.ext.id_of(Extension::RepairedRtpStreamId).is_some();
        let has_ast = line.ext.id_of(Extension::AbsSendTime).is_some();
        let MediaLine {
            ext: map,
            send,
            sim,
            ..
        } = line;
        let stream = match enc {
            Some(j) => &mut sim[j].send,
            None => send,
        };
        let on_rtx = rtx_pt.is_some() && stream.rtx_ssrc().is_some();
        let twcc = &mut self.twcc_tx;
        let mut tw = None;
        let raw = stream.padding(now, size, rtx_pt, map, |e| {
            e.transport_cc = has_twcc.then(|| twcc.next_seq());
            tw = e.transport_cc;
            if has_ast {
                e.abs_send_time = Some(abs_send_time_now());
            }
            // An RTX stream names the encoding it repairs (RFC 8852).
            if on_rtx {
                let rid = e.rid.take();
                if has_rrid {
                    e.rrid = rid;
                }
            }
        })?;
        match (tw, cluster) {
            (Some(s), Some(c)) => twcc.on_sent_probe(s, now, raw.len(), c),
            (Some(s), None) => twcc.on_sent(s, now, raw.len()),
            (None, _) if raw.len() >= 12 => {
                let seq = u16::from_be_bytes([raw[2], raw[3]]);
                let ssrc = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
                match cluster {
                    Some(c) => self.ccfb_tx.on_sent_probe(ssrc, seq, now, raw.len(), c),
                    None => self.ccfb_tx.on_sent(ssrc, seq, now, raw.len()),
                }
            }
            (None, _) => {}
        }
        let tx = self.srtp_tx.as_mut()?;
        let o = tx.protect_rtp(&raw).ok()?;
        self.stats.bytes_sent += o.len() as u64;
        self.stats.packets_sent += 1;
        self.transmits.push_back((src, dest, o));
        Some(raw.len())
    }

    /// Sends the probe packets due at `now`: queued media first, else padding on the stream
    /// that sent the most media among the lines with congestion control feedback. Nothing
    /// before media was sent; clusters that cannot be sent (no path, no such stream) are
    /// dropped, so the probe timeout never stays due.
    pub(super) fn send_probes(&mut self, now: Instant) {
        if self.bwe.is_none() {
            return;
        }
        // Nothing before media was sent (the first poll starts the initial probing).
        if self.srtp_tx.is_none()
            || self.ice.send_pair().is_none()
            || self.padding_stream().is_none()
        {
            if let Some(b) = self.bwe.as_mut() {
                b.cancel_probes();
            }
            return;
        }
        let pacing = self.pacing();
        for _ in 0..MAX_PROBES_PER_CALL {
            let Some(p) = self.bwe.as_mut().and_then(|b| b.poll_probe(now)) else {
                break;
            };
            let queued = if pacing { self.pacer.pop() } else { None };
            let sent = match queued {
                Some(q) => Some(self.release(now, q, Some(p.cluster))),
                None => self.send_padding(now, p.size, Some(p.cluster)),
            };
            let Some(n) = sent.filter(|n| *n > 0) else {
                if let Some(b) = self.bwe.as_mut() {
                    b.cancel_probes();
                }
                break;
            };
            if pacing {
                self.pacer.on_sent(n);
            }
            if let Some(b) = self.bwe.as_mut() {
                b.on_probe_sent(now, p.cluster, n);
            }
        }
    }

    /// New bounds of the estimate (a raised maximum is probed), sent out at once.
    pub(crate) fn set_bitrate_bounds(&mut self, now: Instant, min: u64, max: u64) {
        if let Some(b) = self.bwe.as_mut() {
            b.set_bounds(now, min, max);
        }
        self.bwe_event();
        self.send_probes(now);
    }

    /// ICE selected `(local, remote)`: a change of path restarts the estimate and probing.
    pub(super) fn on_selected_pair(&mut self, now: Instant, local: SocketAddr, remote: SocketAddr) {
        let changed = self.probe_pair.is_some_and(|p| p != (local, remote));
        self.probe_pair = Some((local, remote));
        if changed {
            if let Some(b) = self.bwe.as_mut() {
                b.on_network_change(now);
            }
            self.bwe_event();
        }
    }
}
