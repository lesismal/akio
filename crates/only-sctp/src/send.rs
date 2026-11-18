//! The sending half: per-stream queues and the stream scheduler (RFC 8260 §3), message
//! fragmentation into DATA or I-DATA chunks, TSN / SSN / MID assignment, the retransmission
//! queue, congestion control (RFC 9260 §6-7), RTO (§6.3) and partial reliability (RFC 3758,
//! RFC 8260 §2.3).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Scheduler;
use crate::packet::{
    DATA_HEADER_LEN, Data, FLAG_BEGIN, FLAG_END, FLAG_UNORDERED, ForwardTsn, IDATA_HEADER_LEN,
    IData, IForwardTsn, PacketWriter, Sack, pad4,
};
use crate::sched::{DEFAULT_PRIORITY, Sched, SchedState, StreamMap};

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

/// `stream`'s started message is finished or gone (see `Sender::started`).
fn unstart(started: &mut Vec<(u16, usize)>, bytes: &mut usize, stream: u16) {
    if let Some(i) = started.iter().position(|&(s, _)| s == stream) {
        *bytes -= started.swap_remove(i).1;
    }
}

/// Partial reliability of one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Policy {
    Reliable,
    MaxRetransmits(u16),
    Deadline(Instant),
}

/// A queued message. Fragments are cut when they get their TSN, so that the fragment size
/// follows the chunk type negotiated (DATA or I-DATA) and fragments share one buffer.
#[derive(Debug)]
struct OutMsg {
    data: Arc<[u8]>,
    /// Bytes already given TSNs.
    off: usize,
    ppid: u32,
    unordered: bool,
    policy: Policy,
    /// Counted in the stream's buffered amount (user messages, not DCEP).
    counted: bool,
    msg_id: u64,
    /// SSN (DATA) or MID (I-DATA), assigned with the first fragment.
    seq: u32,
    /// Next fragment sequence number (I-DATA).
    fsn: u32,
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

/// One fragment with its TSN (the TSN is implied by the position in `Sender::inflight`).
#[derive(Debug)]
struct Entry {
    stream: u16,
    ppid: u32,
    unordered: bool,
    begin: bool,
    end: bool,
    data: Arc<[u8]>,
    off: usize,
    /// Payload length; 0 once abandoned.
    len: usize,
    msg_id: u64,
    policy: Policy,
    counted: bool,
    /// SSN (DATA) or MID (I-DATA).
    seq: u32,
    fsn: u32,
    state: FState,
    tx_count: u32,
    sent_at: Instant,
    misses: u8,
    fast_rtxed: bool,
}

impl Entry {
    fn payload(&self) -> &[u8] {
        &self.data[self.off..self.off + self.len]
    }

    fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.begin {
            flags |= FLAG_BEGIN;
        }
        if self.end {
            flags |= FLAG_END;
        }
        if self.unordered {
            flags |= FLAG_UNORDERED;
        }
        flags
    }
}

#[derive(Debug, Default)]
struct Buffered {
    amount: usize,
    threshold: usize,
    above: bool,
}

/// Outgoing state of one stream.
#[derive(Debug, Default)]
struct OutStream {
    queue: VecDeque<OutMsg>,
    next_ssn: u16,
    /// I-DATA MIDs: ordered, unordered (RFC 8260 §2.1: separate sequences).
    next_mid: [u32; 2],
    buffered: Buffered,
    sched: SchedState,
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
    streams: StreamMap<OutStream>,
    sched: Sched,
    /// Messages queued on all streams.
    queued: usize,
    /// Without I-DATA: the stream whose message is half sent (its fragments need
    /// consecutive TSNs, so nothing else goes out before it ends).
    current: Option<u16>,
    inflight: VecDeque<Entry>,
    /// TSN of `inflight[0]` (the cumulative ack point plus one).
    front_tsn: u32,
    next_tsn: u32,
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
    /// I-DATA / I-FORWARD-TSN negotiated (RFC 8260).
    pub(crate) idata: bool,
    /// With I-DATA: streams whose first message is started but not all sent, with its size.
    /// The peer holds such messages whole until they complete, so their total is kept within
    /// `start_limit` (new messages wait) lest the peer's window fill with messages none of
    /// which can finish.
    started: Vec<(u16, usize)>,
    started_bytes: usize,
    start_limit: usize,
}

impl Sender {
    pub(crate) fn new(
        mtu: usize,
        timing: Timing,
        initial_tsn: u32,
        scheduler: Scheduler,
    ) -> Sender {
        Sender {
            mtu,
            timing,
            streams: StreamMap::default(),
            sched: Sched::new(scheduler),
            queued: 0,
            current: None,
            inflight: VecDeque::new(),
            front_tsn: initial_tsn,
            next_tsn: initial_tsn,
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
            idata: false,
            started: Vec::new(),
            started_bytes: 0,
            start_limit: usize::MAX,
        }
    }

    /// Applies the peer's INIT / INIT ACK parameters.
    pub(crate) fn start(&mut self, peer_a_rwnd: u32, forward_tsn: bool, idata: bool) {
        let w = peer_a_rwnd as usize;
        self.peer_a_rwnd = w;
        self.peer_rwnd = w;
        self.ssthresh = w.max(4 * self.mtu);
        self.start_limit = (w / 2).max(self.mtu);
        self.pr_enabled = forward_tsn;
        self.idata = idata;
    }

    fn header_len(&self) -> usize {
        if self.idata {
            IDATA_HEADER_LEN
        } else {
            DATA_HEADER_LEN
        }
    }

    fn max_payload(&self) -> usize {
        // Common header + chunk header; rounded down to 4 so padding never overflows.
        (self.mtu.saturating_sub(12 + self.header_len()) & !3).max(4)
    }

    /// The last TSN assigned (RFC 6525 "Sender's Last Assigned TSN").
    pub(crate) fn last_assigned_tsn(&self) -> u32 {
        self.next_tsn.wrapping_sub(1)
    }

    pub(crate) fn cum_ack_point(&self) -> u32 {
        self.front_tsn.wrapping_sub(1)
    }

    /// Queues a message on its stream.
    pub(crate) fn enqueue(
        &mut self,
        stream: u16,
        ppid: u32,
        data: &[u8],
        unordered: bool,
        policy: Policy,
        counted: bool,
    ) {
        let msg_id = self.next_msg_id;
        self.next_msg_id += 1;
        let st = self.streams.entry(stream).or_default();
        let was_idle = st.queue.is_empty();
        st.queue.push_back(OutMsg {
            data: Arc::from(data),
            off: 0,
            ppid,
            unordered,
            policy,
            counted,
            msg_id,
            seq: 0,
            fsn: 0,
        });
        self.queued += 1;
        if counted {
            let b = &mut st.buffered;
            b.amount += data.len();
            if b.amount > b.threshold {
                b.above = true;
            }
        }
        self.sched.on_enqueue(stream, msg_id, was_idle, st.sched);
    }

    pub(crate) fn buffered_amount(&self, stream: u16) -> usize {
        self.streams.get(&stream).map_or(0, |s| s.buffered.amount)
    }

    pub(crate) fn set_threshold(&mut self, stream: u16, bytes: usize) {
        let b = &mut self.streams.entry(stream).or_default().buffered;
        b.threshold = bytes;
        b.above = b.amount > bytes;
    }

    /// Sets the stream's scheduling priority (RFC 8832 semantics: higher goes first). 0 is
    /// not a WebRTC priority (pion sends it when none is set): it schedules as the default.
    pub(crate) fn set_priority(&mut self, stream: u16, priority: u16) {
        let priority = if priority == 0 {
            DEFAULT_PRIORITY
        } else {
            priority
        };
        self.streams.entry(stream).or_default().sched.priority = priority;
        self.sched.set_priority(stream, priority);
    }

    /// Forgets a stream: its buffered-amount record, sequence numbers, priority and any
    /// queued messages.
    pub(crate) fn forget_stream(&mut self, stream: u16) {
        if let Some(st) = self.streams.remove(&stream) {
            self.queued -= st.queue.len();
            unstart(&mut self.started, &mut self.started_bytes, stream);
            self.sched.remove(stream);
            if self.current == Some(stream) {
                self.current = None;
            }
        }
    }

    /// Resets the outgoing SSN / MIDs of `stream` (stream reset performed, RFC 6525 §5.2.2,
    /// RFC 8260 §2.3.2).
    pub(crate) fn reset_ssn(&mut self, stream: u16) {
        if let Some(st) = self.streams.get_mut(&stream) {
            st.next_ssn = 0;
            st.next_mid = [0, 0];
        }
    }

    /// Resets the outgoing SSNs / MIDs of every stream (SSN/TSN reset, RFC 6525 §5.2.4 G5).
    pub(crate) fn reset_all_ssn(&mut self) {
        for st in self.streams.values_mut() {
            st.next_ssn = 0;
            st.next_mid = [0, 0];
        }
    }

    /// Nothing in flight and no message partly given TSNs: an SSN/TSN reset can be
    /// performed without losing data.
    pub(crate) fn quiescent(&self) -> bool {
        self.inflight.is_empty()
            && self.current.is_none()
            && self.started.is_empty()
            && self
                .streams
                .values()
                .all(|s| s.queue.front().is_none_or(|m| m.off == 0))
    }

    /// The TSN the next new DATA chunk gets.
    pub(crate) fn next_tsn(&self) -> u32 {
        self.next_tsn
    }

    /// The smoothed round-trip time, once measured.
    pub(crate) fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Messages of `stream` not completely given TSNs yet.
    pub(crate) fn pending_on(&self, stream: u16) -> usize {
        self.streams.get(&stream).map_or(0, |s| s.queue.len())
    }

    /// Drops the queued messages of `stream` (channel closed before the association came
    /// up) and its buffered-amount record.
    pub(crate) fn drop_pending_stream(&mut self, stream: u16) {
        self.forget_stream(stream);
    }

    pub(crate) fn all_acked(&self) -> bool {
        self.queued == 0 && self.inflight.is_empty()
    }

    pub(crate) fn has_sendable(&self) -> bool {
        self.rtx_marked > 0 || self.queued > 0
    }

    fn dec_counted(&mut self, idx: usize, low: &mut Vec<u16>) {
        let e = &mut self.inflight[idx];
        if e.counted {
            e.counted = false;
            let (stream, len) = (e.stream, e.len);
            self.dec_buf(stream, len, low);
        }
    }

    fn dec_buf(&mut self, stream: u16, len: usize, low: &mut Vec<u16>) {
        if let Some(b) = self.streams.get_mut(&stream).map(|s| &mut s.buffered) {
            b.amount = b.amount.saturating_sub(len);
            if b.above && b.amount <= b.threshold {
                b.above = false;
                low.push(stream);
            }
        }
    }

    /// Removes the first queued message of `stream` (sent, expired or abandoned).
    fn pop_message(&mut self, stream: u16) -> Option<OutMsg> {
        let st = self.streams.get_mut(&stream)?;
        let m = st.queue.pop_front()?;
        self.queued -= 1;
        if m.off > 0 {
            unstart(&mut self.started, &mut self.started_bytes, stream);
        }
        if st.queue.is_empty() {
            if let Some(kept) = self.sched.remove(stream) {
                st.sched = kept;
            }
        }
        if self.current == Some(stream) {
            self.current = None;
        }
        Some(m)
    }

    /// Gives up the message of `inflight[idx]`: all its sent fragments are abandoned and its
    /// unsent rest dropped (RFC 3758 §3.5 A1-A3).
    fn abandon_at(&mut self, idx: usize, low: &mut Vec<u16>) {
        let Some((msg_id, stream)) = self.inflight.get(idx).map(|e| (e.msg_id, e.stream)) else {
            return;
        };
        // Without I-DATA the fragments are consecutive; with it they may be interleaved with
        // other streams' fragments.
        let mut last: Option<(usize, u32, Instant)> = None;
        for i in 0..self.inflight.len() {
            if self.inflight[i].msg_id != msg_id {
                continue;
            }
            let e = &mut self.inflight[i];
            match e.state {
                FState::InFlight => self.flight_bytes -= e.len,
                FState::Rtx => self.rtx_marked -= 1,
                FState::Acked | FState::Abandoned => {}
            }
            e.state = FState::Abandoned;
            last = Some((i, e.seq, e.sent_at));
            self.dec_counted(i, low);
            self.inflight[i].len = 0;
        }
        let Some((_, seq, sent_at)) = last else {
            return;
        };
        // The rest of the message has not been sent: it is at the front of its stream's
        // queue. Its last fragment still takes a TSN (never transmitted), so that the peer's
        // cumulative TSN cannot pass the message before a FORWARD TSN / I-FORWARD-TSN covers
        // it, even if every fragment sent arrives, and the peer drops the fragments it has
        // (as usrsctp does).
        let started = self
            .streams
            .get(&stream)
            .and_then(|s| s.queue.front())
            .is_some_and(|m| m.msg_id == msg_id);
        if !started {
            return;
        }
        let Some(m) = self.pop_message(stream) else {
            return;
        };
        if m.counted {
            self.dec_buf(stream, m.data.len() - m.off, low);
        }
        self.next_tsn = self.next_tsn.wrapping_add(1);
        self.inflight.push_back(Entry {
            stream,
            ppid: m.ppid,
            unordered: m.unordered,
            begin: false,
            end: true,
            data: m.data,
            off: 0,
            len: 0,
            msg_id,
            policy: m.policy,
            counted: false,
            seq,
            fsn: m.fsn,
            state: FState::Abandoned,
            tx_count: 0,
            sent_at,
            misses: 0,
            fast_rtxed: false,
        });
    }

    /// Whether `e` should be abandoned instead of retransmitted.
    fn exhausted(&self, e: &Entry, now: Instant) -> bool {
        if !self.pr_enabled {
            return false;
        }
        match e.policy {
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
            if !e.unordered {
                let room = streams.len() < max_streams.max(1);
                let ssn = e.seq as u16;
                match streams.iter_mut().find(|(s, _)| *s == e.stream) {
                    Some(x) => {
                        if le16(x.1, ssn) {
                            x.1 = ssn;
                        }
                    }
                    None if room => streams.push((e.stream, ssn)),
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

    /// The I-FORWARD-TSN to send (RFC 8260 §2.3.1): like [`Self::forward_tsn`], with the
    /// highest skipped MID per ordered stream and every skipped unordered message.
    pub(crate) fn iforward_tsn(&self, max_entries: usize) -> Option<IForwardTsn> {
        let mut n = 0u32;
        let mut streams: Vec<(u16, bool, u32)> = Vec::new();
        for e in &self.inflight {
            if e.state != FState::Abandoned {
                break;
            }
            let room = streams.len() < max_entries.max(1);
            let found = streams
                .iter_mut()
                .find(|(s, u, m)| *s == e.stream && *u == e.unordered && (!*u || *m == e.seq));
            match found {
                Some(x) => {
                    if le32(x.2, e.seq) {
                        x.2 = e.seq;
                    }
                }
                None if room => streams.push((e.stream, e.unordered, e.seq)),
                None => break,
            }
            n += 1;
        }
        if n == 0 {
            return None;
        }
        Some(IForwardTsn {
            new_cum_tsn: self.cum_ack_point().wrapping_add(n),
            streams,
        })
    }

    fn write(&self, w: &mut PacketWriter, e: &Entry, tsn: u32) {
        if self.idata {
            w.push_idata(&IData {
                flags: e.flags(),
                tsn,
                stream: e.stream,
                mid: e.seq,
                ppid: e.ppid,
                fsn: e.fsn,
                payload: e.payload(),
            });
        } else {
            w.push_data(&Data {
                flags: e.flags(),
                tsn,
                stream: e.stream,
                ssn: e.seq as u16,
                ppid: e.ppid,
                payload: e.payload(),
            });
        }
    }

    /// Fills `w` with retransmissions and then new DATA, within cwnd and the peer's window.
    pub(crate) fn fill(
        &mut self,
        now: Instant,
        w: &mut PacketWriter,
        allow_new: bool,
        low: &mut Vec<u16>,
    ) {
        let hdr = self.header_len();
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
                let len = self.inflight[i].len;
                if pad4(hdr + len) > w.remaining() {
                    break;
                }
                let tsn = self.front_tsn.wrapping_add(i as u32);
                self.write(w, &self.inflight[i], tsn);
                let e = &mut self.inflight[i];
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
        if allow_new && self.queued > 0 {
            self.sched.new_packet();
            let max = self.max_payload();
            while self.fill_one(now, w, hdr, max, low) {
                sent_any = true;
            }
        }
        if sent_any && self.t3.is_none() {
            self.t3 = Some(now + self.rto);
        }
    }

    /// Sends the next chunk the scheduler picks; `false` when nothing more fits or is
    /// queued.
    fn fill_one(
        &mut self,
        now: Instant,
        w: &mut PacketWriter,
        hdr: usize,
        max: usize,
        low: &mut Vec<u16>,
    ) -> bool {
        let mut forced: Option<u16> = None;
        loop {
            let stream = match forced.take().or(self.current) {
                Some(s) => s,
                None => {
                    let streams = &self.streams;
                    let head = |s: u16| {
                        streams
                            .get(&s)
                            .and_then(|st| st.queue.front())
                            .map(|m| m.msg_id)
                    };
                    match self.sched.select(head) {
                        Some(s) => s,
                        None => return false,
                    }
                }
            };
            let Some(st) = self.streams.get_mut(&stream) else {
                // Stale scheduler entry.
                self.sched.remove(stream);
                self.current = None;
                if self.queued == 0 {
                    return false;
                }
                continue;
            };
            let Some(m) = st.queue.front_mut() else {
                st.sched = self.sched.remove(stream).unwrap_or(st.sched);
                self.current = None;
                if self.queued == 0 {
                    return false;
                }
                continue;
            };
            if m.off == 0 && self.pr_enabled && matches!(m.policy, Policy::Deadline(d) if now >= d)
            {
                // Expired before its first transmission: dropped without a TSN.
                if let Some(m) = self.pop_message(stream) {
                    if m.counted {
                        self.dec_buf(stream, m.data.len(), low);
                    }
                }
                continue;
            }
            if m.off == 0
                && !self.started.is_empty()
                && self.started_bytes + m.data.len() > self.start_limit
            {
                // Finish started messages before starting another.
                forced = Some(self.started[(m.msg_id as usize) % self.started.len()].0);
                continue;
            }
            let len = (m.data.len() - m.off).min(max);
            if self.flight_bytes >= self.cwnd
                || (len > self.peer_rwnd && self.flight_bytes > 0)
                || pad4(hdr + len) > w.remaining()
            {
                return false;
            }
            let idata = self.idata;
            let begin = m.off == 0;
            if begin {
                m.fsn = 0;
                m.seq = if idata {
                    let n = &mut st.next_mid[usize::from(m.unordered)];
                    let mid = *n;
                    *n = n.wrapping_add(1);
                    mid
                } else if m.unordered {
                    0
                } else {
                    let ssn = st.next_ssn;
                    st.next_ssn = ssn.wrapping_add(1);
                    u32::from(ssn)
                };
            }
            let end = m.off + len == m.data.len();
            let e = Entry {
                stream,
                ppid: m.ppid,
                unordered: m.unordered,
                begin,
                end,
                data: Arc::clone(&m.data),
                off: m.off,
                len,
                msg_id: m.msg_id,
                policy: m.policy,
                counted: m.counted,
                seq: m.seq,
                fsn: m.fsn,
                state: FState::InFlight,
                tx_count: 1,
                sent_at: now,
                misses: 0,
                fast_rtxed: false,
            };
            let size = m.data.len();
            m.off += len;
            m.fsn = m.fsn.wrapping_add(1);
            if end {
                st.queue.pop_front();
                self.queued -= 1;
                self.current = None;
            } else if !idata {
                self.current = Some(stream);
            }
            if idata && begin && !end {
                self.started.push((stream, size));
                self.started_bytes += size;
            } else if idata && end && !begin {
                unstart(&mut self.started, &mut self.started_bytes, stream);
            }
            let emptied = st.queue.is_empty();
            if let Some(kept) = self.sched.served(stream, len, end || idata, emptied) {
                st.sched = kept;
            }
            let tsn = self.next_tsn;
            self.next_tsn = self.next_tsn.wrapping_add(1);
            self.write(w, &e, tsn);
            self.inflight.push_back(e);
            self.flight_bytes += len;
            self.peer_rwnd = self.peer_rwnd.saturating_sub(len);
            return true;
        }
    }

    /// Takes an RTT measurement (from a SACK or a HEARTBEAT ACK, RFC 9260 §6.3.1).
    pub(crate) fn update_rto(&mut self, r: Duration) {
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
            let Some(e) = self.inflight.pop_front() else {
                break;
            };
            let tsn = self.front_tsn;
            self.front_tsn = self.front_tsn.wrapping_add(1);
            match e.state {
                FState::InFlight => {
                    self.flight_bytes -= e.len;
                    newly += e.len;
                    htna = Some(tsn);
                    if e.tx_count == 1 {
                        rtt = Some(now.saturating_duration_since(e.sent_at));
                    }
                }
                FState::Rtx => {
                    self.rtx_marked -= 1;
                    newly += e.len;
                    htna = Some(tsn);
                }
                FState::Acked | FState::Abandoned => {}
            }
            if e.counted {
                self.dec_buf(e.stream, e.len, low);
            }
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
                        self.flight_bytes -= e.len;
                        newly += e.len;
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
                        newly += e.len;
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
                            self.flight_bytes -= e.len;
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
                    self.flight_bytes -= e.len;
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
