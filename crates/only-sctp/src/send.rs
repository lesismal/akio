//! The sending half: message fragmentation, TSN / SSN assignment, the retransmission queue,
//! congestion control (RFC 9260 §6-7), RTO (§6.3) and partial reliability (RFC 3758).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::packet::{
    DATA_HEADER_LEN, Data, FLAG_BEGIN, FLAG_END, FLAG_UNORDERED, ForwardTsn, PacketWriter, Sack,
    pad4,
};

/// `a` is before `b` in serial-number arithmetic (RFC 1982).
pub(crate) fn lt32(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

pub(crate) fn le32(a: u32, b: u32) -> bool {
    a == b || lt32(a, b)
}

pub(crate) fn le16(a: u16, b: u16) -> bool {
    b.wrapping_sub(a) < 0x8000
}

/// Partial reliability of one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Policy {
    Reliable,
    MaxRetransmits(u16),
    Deadline(Instant),
}

/// One fragment of a message, before or after it gets its TSN.
#[derive(Debug)]
struct Frag {
    stream: u16,
    ppid: u32,
    unordered: bool,
    begin: bool,
    end: bool,
    data: Vec<u8>,
    msg_id: u64,
    policy: Policy,
    /// Counted in the stream's buffered amount (user messages, not DCEP).
    counted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FState {
    /// Sent, waiting for an ack.
    InFlight,
    /// Gap-acked.
    Acked,
    /// Waiting for retransmission.
    Rtx,
    /// Given up (RFC 3758).
    Abandoned,
}

#[derive(Debug)]
struct Entry {
    frag: Frag,
    ssn: u16,
    state: FState,
    tx_count: u32,
    sent_at: Instant,
    misses: u8,
    fast_rtxed: bool,
}

#[derive(Debug, Default)]
struct Buffered {
    amount: usize,
    threshold: usize,
    above: bool,
}

/// RTO and congestion constants (RFC 9260 §16).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timing {
    pub(crate) rto_initial: Duration,
    pub(crate) rto_min: Duration,
    pub(crate) rto_max: Duration,
}

#[derive(Debug)]
pub(crate) struct Sender {
    mtu: usize,
    timing: Timing,
    pending: VecDeque<Frag>,
    pending_per_stream: HashMap<u16, usize>,
    inflight: VecDeque<Entry>,
    /// TSN of `inflight[0]` (the cumulative ack point plus one).
    front_tsn: u32,
    next_tsn: u32,
    next_ssn: HashMap<u16, u16>,
    next_msg_id: u64,
    flight_bytes: usize,
    rtx_marked: usize,
    cwnd: usize,
    ssthresh: usize,
    partial_bytes_acked: usize,
    peer_a_rwnd: usize,
    peer_rwnd: usize,
    fast_recovery: Option<u32>,
    fast_rtx_pending: bool,
    srtt: Option<Duration>,
    rttvar: Duration,
    pub(crate) rto: Duration,
    pub(crate) t3: Option<Instant>,
    pub(crate) error_count: u32,
    pub(crate) fwd_tsn_needed: bool,
    pub(crate) pr_enabled: bool,
    buffered: HashMap<u16, Buffered>,
}

impl Sender {
    pub(crate) fn new(mtu: usize, timing: Timing, initial_tsn: u32) -> Sender {
        Sender {
            mtu,
            timing,
            pending: VecDeque::new(),
            pending_per_stream: HashMap::new(),
            inflight: VecDeque::new(),
            front_tsn: initial_tsn,
            next_tsn: initial_tsn,
            next_ssn: HashMap::new(),
            next_msg_id: 0,
            flight_bytes: 0,
            rtx_marked: 0,
            cwnd: (4 * mtu).min((2 * mtu).max(4380)),
            ssthresh: usize::MAX,
            partial_bytes_acked: 0,
            peer_a_rwnd: 0,
            peer_rwnd: 0,
            fast_recovery: None,
            fast_rtx_pending: false,
            srtt: None,
            rttvar: Duration::ZERO,
            rto: timing.rto_initial,
            t3: None,
            error_count: 0,
            fwd_tsn_needed: false,
            pr_enabled: false,
            buffered: HashMap::new(),
        }
    }

    /// Applies the peer's INIT / INIT ACK parameters.
    pub(crate) fn start(&mut self, peer_a_rwnd: u32, forward_tsn: bool) {
        let w = peer_a_rwnd as usize;
        self.peer_a_rwnd = w;
        self.peer_rwnd = w;
        self.ssthresh = w.max(4 * self.mtu);
        self.pr_enabled = forward_tsn;
    }

    fn max_payload(&self) -> usize {
        // Common header + DATA chunk header; rounded down to 4 so padding never overflows.
        (self.mtu.saturating_sub(12 + DATA_HEADER_LEN) & !3).max(4)
    }

    /// The last TSN assigned (RFC 6525 "Sender's Last Assigned TSN").
    pub(crate) fn last_assigned_tsn(&self) -> u32 {
        self.next_tsn.wrapping_sub(1)
    }

    pub(crate) fn cum_ack_point(&self) -> u32 {
        self.front_tsn.wrapping_sub(1)
    }

    /// Queues a message, fragmented to the MTU.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn enqueue(
        &mut self,
        stream: u16,
        ppid: u32,
        data: &[u8],
        unordered: bool,
        policy: Policy,
        counted: bool,
    ) {
        let max = self.max_payload();
        let msg_id = self.next_msg_id;
        self.next_msg_id += 1;
        let n = data.len().div_ceil(max).max(1);
        for (i, part) in data.chunks(max).enumerate() {
            self.pending.push_back(Frag {
                stream,
                ppid,
                unordered,
                begin: i == 0,
                end: i + 1 == n,
                data: part.to_vec(),
                msg_id,
                policy,
                counted,
            });
        }
        *self.pending_per_stream.entry(stream).or_insert(0) += n;
        if counted {
            let b = self.buffered.entry(stream).or_default();
            b.amount += data.len();
            if b.amount > b.threshold {
                b.above = true;
            }
        }
    }

    pub(crate) fn buffered_amount(&self, stream: u16) -> usize {
        self.buffered.get(&stream).map_or(0, |b| b.amount)
    }

    pub(crate) fn set_threshold(&mut self, stream: u16, bytes: usize) {
        let b = self.buffered.entry(stream).or_default();
        b.threshold = bytes;
        b.above = b.amount > bytes;
    }

    /// Forgets a closed stream's buffered-amount record.
    pub(crate) fn forget_stream(&mut self, stream: u16) {
        self.buffered.remove(&stream);
        self.next_ssn.remove(&stream);
    }

    /// Resets the outgoing SSN of `stream` (stream reset performed, RFC 6525 §5.2.2).
    pub(crate) fn reset_ssn(&mut self, stream: u16) {
        self.next_ssn.remove(&stream);
    }

    /// Fragments of `stream` still waiting for a TSN.
    pub(crate) fn pending_on(&self, stream: u16) -> usize {
        self.pending_per_stream.get(&stream).copied().unwrap_or(0)
    }

    /// Drops the not-yet-sent fragments of `stream` (channel closed before the association
    /// came up).
    pub(crate) fn drop_pending_stream(&mut self, stream: u16) {
        self.pending.retain(|f| f.stream != stream);
        self.pending_per_stream.remove(&stream);
        self.buffered.remove(&stream);
    }

    pub(crate) fn all_acked(&self) -> bool {
        self.pending.is_empty() && self.inflight.is_empty()
    }

    pub(crate) fn has_sendable(&self) -> bool {
        self.rtx_marked > 0 || !self.pending.is_empty()
    }

    fn dec_buffered(&mut self, frag: &mut Frag, low: &mut Vec<u16>) {
        if frag.counted {
            frag.counted = false;
            self.dec_buf(frag.stream, frag.data.len(), low);
        }
    }

    fn dec_buf(&mut self, stream: u16, len: usize, low: &mut Vec<u16>) {
        if let Some(b) = self.buffered.get_mut(&stream) {
            b.amount = b.amount.saturating_sub(len);
            if b.above && b.amount <= b.threshold {
                b.above = false;
                low.push(stream);
            }
        }
    }

    fn dec_pending(&mut self, stream: u16) {
        if let Some(n) = self.pending_per_stream.get_mut(&stream) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.pending_per_stream.remove(&stream);
            }
        }
    }

    /// Gives up the message of `inflight[idx]`: all its sent fragments are abandoned and its
    /// unsent ones dropped (RFC 3758 §3.5 A1-A3).
    fn abandon_at(&mut self, idx: usize, low: &mut Vec<u16>) {
        let Some(msg_id) = self.inflight.get(idx).map(|e| e.frag.msg_id) else {
            return;
        };
        let mut start = idx;
        while start > 0 && self.inflight[start - 1].frag.msg_id == msg_id {
            start -= 1;
        }
        let mut i = start;
        while i < self.inflight.len() && self.inflight[i].frag.msg_id == msg_id {
            let e = &mut self.inflight[i];
            match e.state {
                FState::InFlight => self.flight_bytes -= e.frag.data.len(),
                FState::Rtx => self.rtx_marked -= 1,
                FState::Acked | FState::Abandoned => {}
            }
            e.state = FState::Abandoned;
            let (stream, len, counted) = (e.frag.stream, e.frag.data.len(), e.frag.counted);
            e.frag.counted = false;
            e.frag.data = Vec::new();
            if counted {
                self.dec_buf(stream, len, low);
            }
            i += 1;
        }
        // The rest of the message has not been sent: it is at the front of the queue. Its
        // last fragment still takes a TSN (never transmitted) so that the FORWARD TSN covers
        // the whole message and the peer drops the fragments it has (as usrsctp does).
        let Some((ssn, sent_at)) = self.inflight.get(i - 1).map(|e| (e.ssn, e.sent_at)) else {
            return;
        };
        let mut last: Option<Frag> = None;
        while self.pending.front().is_some_and(|f| f.msg_id == msg_id) {
            if let Some(mut f) = self.pending.pop_front() {
                self.dec_pending(f.stream);
                self.dec_buffered(&mut f, low);
                f.data = Vec::new();
                last = Some(f);
            }
        }
        if let Some(mut f) = last {
            f.begin = false;
            self.next_tsn = self.next_tsn.wrapping_add(1);
            self.inflight.push_back(Entry {
                frag: f,
                ssn,
                state: FState::Abandoned,
                tx_count: 0,
                sent_at,
                misses: 0,
                fast_rtxed: false,
            });
        }
    }

    /// Whether `e` should be abandoned instead of retransmitted.
    fn exhausted(&self, e: &Entry, now: Instant) -> bool {
        if !self.pr_enabled {
            return false;
        }
        match e.frag.policy {
            Policy::Reliable => false,
            Policy::MaxRetransmits(n) => e.tx_count > u32::from(n),
            Policy::Deadline(d) => now >= d,
        }
    }

    /// Advances the Advanced.Peer.Ack.Point over abandoned chunks; flags a FORWARD TSN when
    /// it is ahead of the cumulative ack point (RFC 3758 §3.5 C2-C3).
    fn update_fwd_tsn(&mut self) {
        if self
            .inflight
            .front()
            .is_some_and(|e| e.state == FState::Abandoned)
        {
            self.fwd_tsn_needed = true;
        }
    }

    /// The FORWARD TSN to send, if the advanced ack point is ahead of the cumulative one.
    /// At most `max_streams` stream / SSN pairs: the new cumulative TSN then stops before
    /// the first chunk of a stream that does not fit (messages never straddle it).
    pub(crate) fn forward_tsn(&self, max_streams: usize) -> Option<ForwardTsn> {
        let mut n = 0u32;
        let mut streams: Vec<(u16, u16)> = Vec::new();
        for e in &self.inflight {
            if e.state != FState::Abandoned {
                break;
            }
            if !e.frag.unordered {
                let room = streams.len() < max_streams.max(1);
                match streams.iter_mut().find(|(s, _)| *s == e.frag.stream) {
                    Some(x) => {
                        if le16(x.1, e.ssn) {
                            x.1 = e.ssn;
                        }
                    }
                    None if room => streams.push((e.frag.stream, e.ssn)),
                    None => break,
                }
            }
            n += 1;
        }
        if n == 0 {
            return None;
        }
        Some(ForwardTsn {
            new_cum_tsn: self.cum_ack_point().wrapping_add(n),
            streams,
        })
    }

    /// Fills `w` with retransmissions and then new DATA, within cwnd and the peer's window.
    pub(crate) fn fill(
        &mut self,
        now: Instant,
        w: &mut PacketWriter,
        allow_new: bool,
        low: &mut Vec<u16>,
    ) {
        let mut sent_any = false;
        if self.rtx_marked > 0 {
            let fast = std::mem::take(&mut self.fast_rtx_pending);
            let mut i = 0;
            while i < self.inflight.len() && self.rtx_marked > 0 {
                if self.inflight[i].state != FState::Rtx {
                    i += 1;
                    continue;
                }
                if self.exhausted(&self.inflight[i], now) {
                    self.abandon_at(i, low);
                    self.update_fwd_tsn();
                    i += 1;
                    continue;
                }
                if !fast && self.flight_bytes >= self.cwnd {
                    break;
                }
                let len = self.inflight[i].frag.data.len();
                if pad4(DATA_HEADER_LEN + len) > w.remaining() {
                    break;
                }
                let tsn = self.front_tsn.wrapping_add(i as u32);
                let e = &mut self.inflight[i];
                w.push_data(&data_of(e, tsn));
                e.state = FState::InFlight;
                e.tx_count += 1;
                e.sent_at = now;
                e.misses = 0;
                self.flight_bytes += len;
                self.rtx_marked -= 1;
                sent_any = true;
                i += 1;
            }
            if self.rtx_marked > 0 {
                // More to retransmit: no new data yet.
                if sent_any && self.t3.is_none() {
                    self.t3 = Some(now + self.rto);
                }
                return;
            }
        }
        while let Some(f) = self.pending.front().filter(|_| allow_new) {
            if f.begin && self.pr_enabled {
                if let Policy::Deadline(d) = f.policy {
                    if now >= d {
                        // Expired before its first transmission: drop it without a TSN.
                        let id = f.msg_id;
                        while self.pending.front().is_some_and(|f| f.msg_id == id) {
                            if let Some(mut f) = self.pending.pop_front() {
                                self.dec_pending(f.stream);
                                self.dec_buffered(&mut f, low);
                            }
                        }
                        continue;
                    }
                }
            }
            let len = f.data.len();
            if self.flight_bytes >= self.cwnd
                || (len > self.peer_rwnd && self.flight_bytes > 0)
                || pad4(DATA_HEADER_LEN + len) > w.remaining()
            {
                break;
            }
            let Some(frag) = self.pending.pop_front() else {
                break;
            };
            self.dec_pending(frag.stream);
            let ssn = if frag.unordered {
                0
            } else {
                let next = self.next_ssn.entry(frag.stream).or_insert(0);
                if frag.begin {
                    let s = *next;
                    *next = next.wrapping_add(1);
                    s
                } else {
                    next.wrapping_sub(1)
                }
            };
            let tsn = self.next_tsn;
            self.next_tsn = self.next_tsn.wrapping_add(1);
            let e = Entry {
                frag,
                ssn,
                state: FState::InFlight,
                tx_count: 1,
                sent_at: now,
                misses: 0,
                fast_rtxed: false,
            };
            w.push_data(&data_of(&e, tsn));
            self.inflight.push_back(e);
            self.flight_bytes += len;
            self.peer_rwnd = self.peer_rwnd.saturating_sub(len);
            sent_any = true;
        }
        if sent_any && self.t3.is_none() {
            self.t3 = Some(now + self.rto);
        }
    }

    fn update_rto(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(r);
                self.rttvar = self.rttvar * 3 / 4 + diff / 4;
                self.srtt = Some(srtt * 7 / 8 + r / 8);
            }
        }
        let srtt = self.srtt.unwrap_or(r);
        self.rto = (srtt + 4 * self.rttvar).clamp(self.timing.rto_min, self.timing.rto_max);
    }

    /// Processes a SACK (RFC 9260 §6.2.1, §7.2). Streams whose buffered amount crossed the
    /// low threshold are pushed to `low`.
    pub(crate) fn on_sack(&mut self, now: Instant, sack: &Sack, low: &mut Vec<u16>) {
        let cum_point = self.cum_ack_point();
        if lt32(sack.cum_tsn, cum_point) {
            return; // stale
        }
        let n = sack.cum_tsn.wrapping_sub(cum_point) as usize;
        if n > self.inflight.len() {
            return; // acks a TSN we never sent
        }
        let flight_before = self.flight_bytes;
        let mut newly = 0usize;
        let mut htna: Option<u32> = None;
        let mut rtt: Option<Duration> = None;
        for _ in 0..n {
            let Some(mut e) = self.inflight.pop_front() else {
                break;
            };
            let tsn = self.front_tsn;
            self.front_tsn = self.front_tsn.wrapping_add(1);
            match e.state {
                FState::InFlight => {
                    self.flight_bytes -= e.frag.data.len();
                    newly += e.frag.data.len();
                    htna = Some(tsn);
                    if e.tx_count == 1 {
                        rtt = Some(now.saturating_duration_since(e.sent_at));
                    }
                }
                FState::Rtx => {
                    self.rtx_marked -= 1;
                    newly += e.frag.data.len();
                    htna = Some(tsn);
                }
                FState::Acked | FState::Abandoned => {}
            }
            self.dec_buffered(&mut e.frag, low);
        }
        let cum_advanced = n > 0;

        // Gap ack blocks: offsets from the new cumulative TSN.
        let mut gaps: Vec<(usize, usize)> = sack
            .gaps
            .iter()
            .filter(|(s, e)| *s >= 1 && s <= e)
            .map(|&(s, e)| (usize::from(s), usize::from(e)))
            .collect();
        gaps.sort_unstable();
        let max_end = gaps
            .iter()
            .map(|g| g.1)
            .max()
            .unwrap_or(0)
            .min(self.inflight.len());
        let mut g = 0;
        for i in 0..max_end {
            let off = i + 1;
            while g < gaps.len() && gaps[g].1 < off {
                g += 1;
            }
            let covered = g < gaps.len() && gaps[g].0 <= off;
            let tsn = self.front_tsn.wrapping_add(i as u32);
            let e = &mut self.inflight[i];
            if covered {
                match e.state {
                    FState::InFlight => {
                        self.flight_bytes -= e.frag.data.len();
                        newly += e.frag.data.len();
                        htna = Some(tsn);
                        e.state = FState::Acked;
                        // Karn: only chunks sent once give an RTT sample, taken when first
                        // acknowledged (a later cumulative ack would overstate it).
                        if e.tx_count == 1 {
                            rtt = Some(now.saturating_duration_since(e.sent_at));
                        }
                    }
                    FState::Rtx => {
                        self.rtx_marked -= 1;
                        newly += e.frag.data.len();
                        htna = Some(tsn);
                        e.state = FState::Acked;
                    }
                    FState::Acked | FState::Abandoned => {}
                }
            } else if e.state == FState::Acked {
                // Reneged (RFC 9260 §6.2.1): send it again.
                e.state = FState::Rtx;
                self.rtx_marked += 1;
            }
        }

        // Fast retransmit (RFC 9260 §7.2.4).
        let mut any_fast = false;
        if let Some(h) = htna {
            let mut i = 0;
            while i < self.inflight.len() {
                let tsn = self.front_tsn.wrapping_add(i as u32);
                if !lt32(tsn, h) {
                    break;
                }
                let e = &mut self.inflight[i];
                if e.state == FState::InFlight && !e.fast_rtxed {
                    e.misses = e.misses.saturating_add(1);
                    if e.misses >= 3 {
                        e.fast_rtxed = true;
                        if self.exhausted(&self.inflight[i], now) {
                            self.abandon_at(i, low);
                        } else {
                            let e = &mut self.inflight[i];
                            e.state = FState::Rtx;
                            self.flight_bytes -= e.frag.data.len();
                            self.rtx_marked += 1;
                            any_fast = true;
                        }
                    }
                }
                i += 1;
            }
        }
        if any_fast {
            if self.fast_recovery.is_none() {
                self.ssthresh = (self.cwnd / 2).max(4 * self.mtu);
                self.cwnd = self.ssthresh;
                self.partial_bytes_acked = 0;
                self.fast_recovery = Some(self.last_assigned_tsn());
            }
            self.fast_rtx_pending = true;
        }

        // Congestion window (RFC 9260 §7.2.1-2).
        if cum_advanced && self.fast_recovery.is_none() {
            if self.cwnd <= self.ssthresh {
                if flight_before + self.mtu >= self.cwnd {
                    self.cwnd += newly.min(self.mtu);
                }
            } else {
                self.partial_bytes_acked += newly;
                if self.partial_bytes_acked >= self.cwnd && flight_before >= self.cwnd {
                    self.partial_bytes_acked -= self.cwnd;
                    self.cwnd += self.mtu;
                }
            }
        }
        if let Some(r) = self.fast_recovery {
            if le32(r, sack.cum_tsn) {
                self.fast_recovery = None;
            }
        }
        if let Some(r) = rtt {
            self.update_rto(r);
        }
        if cum_advanced {
            self.error_count = 0;
        }
        self.peer_a_rwnd = sack.a_rwnd as usize;
        self.peer_rwnd = self.peer_a_rwnd.saturating_sub(self.flight_bytes);
        if self.inflight.is_empty() {
            self.t3 = None;
        } else if cum_advanced {
            self.t3 = Some(now + self.rto);
        }
        self.update_fwd_tsn();
    }

    /// A cumulative ack from a SHUTDOWN chunk.
    pub(crate) fn on_cum_ack(&mut self, now: Instant, cum: u32, low: &mut Vec<u16>) {
        let sack = Sack {
            cum_tsn: cum,
            a_rwnd: u32::try_from(self.peer_a_rwnd).unwrap_or(u32::MAX),
            gaps: Vec::new(),
            dups: Vec::new(),
        };
        self.on_sack(now, &sack, low);
    }

    /// T3-rtx expiry (RFC 9260 §6.3.3). Returns `false` when the association failed.
    pub(crate) fn on_t3(&mut self, now: Instant, max_retrans: u32, low: &mut Vec<u16>) -> bool {
        self.error_count += 1;
        if self.error_count > max_retrans {
            return false;
        }
        self.ssthresh = (self.cwnd / 2).max(4 * self.mtu);
        self.cwnd = self.mtu;
        self.partial_bytes_acked = 0;
        self.fast_recovery = None;
        self.rto = (self.rto * 2).min(self.timing.rto_max);
        let mut i = 0;
        while i < self.inflight.len() {
            if self.inflight[i].state == FState::InFlight {
                if self.exhausted(&self.inflight[i], now) {
                    self.abandon_at(i, low);
                } else {
                    let e = &mut self.inflight[i];
                    e.state = FState::Rtx;
                    self.flight_bytes -= e.frag.data.len();
                    self.rtx_marked += 1;
                }
            }
            i += 1;
        }
        self.update_fwd_tsn();
        self.t3 = if self.inflight.is_empty() {
            None
        } else {
            Some(now + self.rto)
        };
        true
    }
}

fn data_of(e: &Entry, tsn: u32) -> Data<'_> {
    let mut flags = 0;
    if e.frag.begin {
        flags |= FLAG_BEGIN;
    }
    if e.frag.end {
        flags |= FLAG_END;
    }
    if e.frag.unordered {
        flags |= FLAG_UNORDERED;
    }
    Data {
        flags,
        tsn,
        stream: e.frag.stream,
        ssn: e.ssn,
        ppid: e.frag.ppid,
        payload: &e.frag.data,
    }
}
