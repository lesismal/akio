//! Jitter-free frame assembly: reorder by sequence number, emit complete frames in order.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use super::{CodecKind, Depacketizer, MAX_FRAME_SIZE, depacketizer};

/// Packets buffered beyond `max_packets` before the oldest are evicted (a frame of up to
/// [`MAX_FRAME_SIZE`] in flight fits).
const MAX_EXTRA_PACKETS: usize = 8192;
/// Buffered payload bytes before the oldest packets are evicted.
const MAX_BUFFERED_BYTES: usize = 2 * MAX_FRAME_SIZE;
/// Sequence numbers marked with [`FrameAssembler::skip`] kept at most.
const MAX_SKIPPED: usize = 1024;

/// One reassembled media frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Extended RTP timestamp (rollover-corrected; starts at the first packet's timestamp).
    pub timestamp: u64,
    /// The depacketized frame (Annex-B for H.264/H.265, OBUs with size fields for AV1).
    pub data: Vec<u8>,
    /// Arrival time of the earliest-arriving packet of the frame.
    pub first_arrival: Instant,
    /// No packet is missing between the previous emitted frame and this one (always `true` for
    /// the first frame unless its leading packets were dropped).
    pub contiguous: bool,
    /// Extended sequence number of the first packet.
    pub first_seq: u64,
    /// Extended sequence number of the last packet.
    pub last_seq: u64,
    /// Best effort keyframe flag ([`Depacketizer::is_keyframe`] of any packet; always `true`
    /// for audio).
    pub keyframe: bool,
    /// A packet of the frame was only rebuilt in part ([`FrameAssembler::push_partial`]): its
    /// payload is the start of the original one, so the frame may be truncated or corrupt.
    pub partial: bool,
}

#[derive(Debug)]
struct Pkt {
    ts: u64,
    start: bool,
    end: bool,
    payload: Vec<u8>,
    arrival: Instant,
    partial: bool,
}

/// What is known about the packet before the head of the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prev {
    /// It ended a frame (or nothing came before).
    Aligned,
    /// It belonged to an unfinished frame with this timestamp: only a frame-start packet with a
    /// different timestamp begins the next frame.
    Partial(u64),
}

impl Prev {
    fn allows(self, ts: u64) -> bool {
        match self {
            Prev::Aligned => true,
            Prev::Partial(t) => t != ts,
        }
    }

    fn after(p: &Pkt) -> Prev {
        if p.end {
            Prev::Aligned
        } else {
            Prev::Partial(p.ts)
        }
    }
}

/// Resumable completeness scan of the frame at the head.
#[derive(Debug, Clone, Copy)]
struct Scan {
    head: u64,
    seq: u64,
    bytes: usize,
}

/// Reorders RTP packets by extended sequence number and emits complete frames in order.
///
/// A video frame is the run of packets from a frame-start packet to a frame-end packet (marker
/// or [`Depacketizer::is_frame_end`], or the last packet before a timestamp change) with no
/// sequence gap and one timestamp; audio and [`CodecKind::Other`] frames are single packets.
/// [`FrameAssembler::pop`] emits a frame as soon as it is complete and every earlier frame was
/// emitted or given up; it never waits on time. A gap is given up when more than
/// `max_packets` packets have arrived after it: the assembler skips to the next frame start
/// and marks the next frame `contiguous = false`. Frames over [`MAX_FRAME_SIZE`] and frames
/// that fail to depacketize are dropped the same way. A caller that keeps time gives a gap up
/// sooner: [`blocked`](Self::blocked) names the frame waiting behind it,
/// [`give_up_hole`](Self::give_up_hole) gives it up (a playout buffer does so at that frame's
/// playout deadline, [`VideoPlayout::hole_deadline`](crate::VideoPlayout::hole_deadline)).
#[derive(Debug)]
pub struct FrameAssembler {
    kind: CodecKind,
    depack: Box<dyn Depacketizer>,
    max_packets: usize,
    buf: BTreeMap<u64, Pkt>,
    bytes: usize,
    /// Next sequence number to emit; `None` until the first frame is emitted or dropped.
    next: Option<u64>,
    prev: Prev,
    /// Packets were lost or dropped since the last emitted frame.
    gap: bool,
    last_ts: Option<u64>,
    /// `(ext_seq, ext_ts)` of the highest sequence number seen, the rollover reference.
    ts_ref: Option<(u64, u64)>,
    scan: Option<Scan>,
    /// Sequence numbers without media (FEC, padding) that are not gaps.
    skipped: BTreeSet<u64>,
}

enum Step {
    Emit(u64),
    Wait,
    Retry,
}

impl FrameAssembler {
    /// An assembler for `kind` that gives up on a gap once more than `max_packets` packets
    /// arrived after it (for example 15 for audio, 30 for video; 0 is treated as 1).
    #[must_use]
    pub fn new(kind: CodecKind, max_packets: usize) -> FrameAssembler {
        FrameAssembler {
            kind,
            depack: depacketizer(kind),
            max_packets: max_packets.max(1),
            buf: BTreeMap::new(),
            bytes: 0,
            next: None,
            prev: Prev::Aligned,
            gap: false,
            last_ts: None,
            ts_ref: None,
            scan: None,
            skipped: BTreeSet::new(),
        }
    }

    /// The codec this assembler was created for.
    #[must_use]
    pub fn kind(&self) -> CodecKind {
        self.kind
    }

    /// Number of buffered packets.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Adds a packet. Duplicates, packets older than what was already emitted or given up, and
    /// sequence numbers above `u64::MAX / 2` (never produced by RTP sequence extension) are
    /// ignored.
    pub fn push(
        &mut self,
        ext_seq: u64,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
        arrival: Instant,
    ) {
        self.insert(ext_seq, timestamp, marker, payload, arrival, false);
    }

    /// Adds a packet of which only the start of the payload is known (FEC rebuilt it in part,
    /// [`FecDecoder::take_partials`](crate::fec::FecDecoder::take_partials)) in place of a
    /// lost one: its frame is emitted with [`Frame::partial`] instead of being given up (if
    /// the depacketizer accepts the truncated payload).
    pub fn push_partial(
        &mut self,
        ext_seq: u64,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
        arrival: Instant,
    ) {
        self.insert(ext_seq, timestamp, marker, payload, arrival, true);
    }

    fn insert(
        &mut self,
        ext_seq: u64,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
        arrival: Instant,
        partial: bool,
    ) {
        if self.next.is_some_and(|n| ext_seq < n)
            || ext_seq > u64::MAX / 2
            || self.buf.contains_key(&ext_seq)
            || payload.len() > MAX_FRAME_SIZE
        {
            return;
        }
        let ts = self.extend_ts(ext_seq, timestamp);
        let single = self.kind.is_single_packet();
        let pkt = Pkt {
            ts,
            start: single || self.depack.is_frame_start(payload),
            end: single || self.depack.is_frame_end(payload, marker),
            payload: payload.to_vec(),
            arrival,
            partial,
        };
        self.bytes += pkt.payload.len();
        self.buf.insert(ext_seq, pkt);
        while self.buf.len() > self.max_packets + MAX_EXTRA_PACKETS
            || self.bytes > MAX_BUFFERED_BYTES
        {
            let Some((seq, p)) = self.buf.pop_first() else {
                break;
            };
            self.bytes -= p.payload.len();
            self.next = Some(seq + 1);
            self.prev = self.after(&p);
            self.gap = true;
        }
    }

    /// Marks `ext_seq` as a sequence number of this stream that carries no media (a ULPFEC
    /// packet in RED, a padding-only packet): frames on either side of it are not separated
    /// by a gap. At most 1024 pending ones are kept.
    pub fn skip(&mut self, ext_seq: u64) {
        if self.next.is_some_and(|n| ext_seq < n)
            || ext_seq > u64::MAX / 2
            || self.buf.contains_key(&ext_seq)
        {
            return;
        }
        self.skipped.insert(ext_seq);
        while self.skipped.len() > MAX_SKIPPED {
            self.skipped.pop_first();
        }
    }

    fn extend_ts(&mut self, ext_seq: u64, ts: u32) -> u64 {
        let ext = match self.ts_ref {
            None => u64::from(ts),
            Some((_, r)) => {
                let diff = i64::from(ts.wrapping_sub(r as u32) as i32);
                let v = r as i64 + diff;
                if v < 0 { u64::from(ts) } else { v as u64 }
            }
        };
        if self.ts_ref.is_none_or(|(s, _)| ext_seq > s) {
            self.ts_ref = Some((ext_seq, ext));
        }
        ext
    }

    fn after(&self, p: &Pkt) -> Prev {
        if self.kind.is_single_packet() {
            Prev::Aligned
        } else {
            Prev::after(p)
        }
    }

    /// The next complete frame in order, if any.
    pub fn pop(&mut self) -> Option<Frame> {
        loop {
            if let Some(n) = self.next {
                while self.skipped.first().is_some_and(|&s| s < n) {
                    self.skipped.pop_first();
                }
            }
            let (&first, _) = self.buf.first_key_value()?;
            let head = self.next.unwrap_or(first);
            let Some(p) = self.buf.get(&head) else {
                if self.skipped.remove(&head) {
                    self.next = Some(head + 1);
                    continue;
                }
                // Lost (or not yet arrived) head.
                if self.buf.len() > self.max_packets {
                    self.give_up(head, head);
                    continue;
                }
                return None;
            };
            if !(p.start && self.prev.allows(p.ts)) {
                if self.next.is_none() && self.buf.len() <= self.max_packets {
                    // Joined mid-frame, or the first packets are still on their way: treat it as
                    // a gap before the head.
                    return None;
                }
                self.drop_head(head);
                continue;
            }
            match self.scan_frame(head) {
                Step::Emit(end) => {
                    if let Some(f) = self.emit(head, end) {
                        return Some(f);
                    }
                }
                Step::Retry => {}
                Step::Wait => return None,
            }
        }
    }

    fn drop_head(&mut self, head: u64) {
        if let Some(p) = self.buf.remove(&head) {
            self.bytes -= p.payload.len();
            self.prev = self.after(&p);
        }
        self.next = Some(head + 1);
        self.gap = true;
    }

    /// More than `max_packets` packets arrived after the hole at `m` (all of `head..m` are
    /// buffered and nothing below `head` is).
    fn over_capacity(&self, head: u64, m: u64) -> bool {
        let before = usize::try_from(m - head).unwrap_or(usize::MAX);
        self.buf.len().saturating_sub(before) > self.max_packets
    }

    fn scan_frame(&mut self, head: u64) -> Step {
        let (mut seq, mut bytes) = match self.scan {
            Some(s) if s.head == head => (s.seq, s.bytes),
            _ => (head, 0),
        };
        let Some(head_ts) = self.buf.get(&head).map(|p| p.ts) else {
            return Step::Wait;
        };
        loop {
            let Some(q) = self.buf.get(&seq) else {
                if self.skipped.contains(&seq) {
                    seq += 1;
                    continue;
                }
                self.scan = Some(Scan { head, seq, bytes });
                if self.over_capacity(head, seq) {
                    self.give_up(head, seq);
                    return Step::Retry;
                }
                return Step::Wait;
            };
            if seq != head && q.ts != head_ts {
                return Step::Emit(seq - 1);
            }
            bytes += q.payload.len();
            if bytes > MAX_FRAME_SIZE {
                // Too large: drop what we have; the rest of the frame is dropped as partial.
                let st = self.after(q);
                self.remove_below(seq + 1);
                self.prev = st;
                self.next = Some(seq + 1);
                self.gap = true;
                return Step::Retry;
            }
            if q.end {
                return Step::Emit(seq);
            }
            seq += 1;
        }
    }

    /// Removes every packet below `seq`.
    fn remove_below(&mut self, seq: u64) {
        let keep = self.buf.split_off(&seq);
        let dropped = std::mem::replace(&mut self.buf, keep);
        self.bytes -= dropped.values().map(|p| p.payload.len()).sum::<usize>();
    }

    /// Whether [`push`](Self::push) would buffer `ext_seq`: it is not a duplicate, nor older
    /// than what was already emitted or given up.
    #[must_use]
    pub fn accepts(&self, ext_seq: u64) -> bool {
        !(self.next.is_some_and(|n| ext_seq < n)
            || ext_seq > u64::MAX / 2
            || self.buf.contains_key(&ext_seq))
    }

    /// The first missing sequence number the head waits on, with `head`, while packets of a
    /// later frame are buffered behind it: `None` when nothing waits behind a hole (the head
    /// frame is still arriving, or nothing is buffered).
    fn hole(&self) -> Option<(u64, u64)> {
        let (&first, fp) = self.buf.first_key_value()?;
        let (_, lp) = self.buf.last_key_value()?;
        let head = self.next.unwrap_or(first);
        let Some(p) = self.buf.get(&head) else {
            return Some((head, head));
        };
        if fp.ts == lp.ts && p.start {
            // One frame, still arriving.
            return None;
        }
        if !(p.start && self.prev.allows(p.ts)) {
            return Some((head, head));
        }
        let mut m = head;
        while self.buf.contains_key(&m) || self.skipped.contains(&m) {
            m += 1;
        }
        Some((head, m))
    }

    /// When [`pop`](Self::pop) returns `None` because a packet is missing and a later frame
    /// is buffered behind it: the extended RTP timestamp of the frame that giving the packet
    /// up would release next. `None` when no frame waits behind a hole. A playout buffer
    /// gives the packet up ([`give_up_hole`](Self::give_up_hole)) when that frame is due
    /// ([`VideoPlayout::hole_deadline`](crate::VideoPlayout::hole_deadline)).
    #[must_use]
    pub fn blocked(&self) -> Option<u64> {
        let (head, m) = self.hole()?;
        let (found, _) = self.resume_point(head, m);
        found.and_then(|s| self.buf.get(&s)).map(|p| p.ts)
    }

    /// Gives up the packet [`blocked`](Self::blocked) says the next frame waits on, as the
    /// packet count would: the frame it belongs to is dropped and the next one is marked
    /// `contiguous = false`. `false` when nothing waits behind a hole. Call
    /// [`pop`](Self::pop) afterwards.
    pub fn give_up_hole(&mut self) -> bool {
        if self.blocked().is_none() {
            return false;
        }
        let Some((head, m)) = self.hole() else {
            return false;
        };
        self.give_up(head, m);
        true
    }

    /// Where giving up the hole at `m` (`head <= m`) resumes: the next frame start after it
    /// (`None`: none buffered), and what is known of the packet before that one.
    fn resume_point(&self, head: u64, m: u64) -> (Option<u64>, Prev) {
        let mut st = if self.kind.is_single_packet() {
            Prev::Aligned
        } else if m > head {
            self.buf.get(&(m - 1)).map_or(self.prev, |p| self.after(p))
        } else {
            match (self.prev, self.last_ts) {
                (Prev::Aligned, Some(t)) => Prev::Partial(t),
                (p, _) => p,
            }
        };
        for (&seq, q) in self.buf.range(m + 1..) {
            if q.start && st.allows(q.ts) {
                return (Some(seq), st);
            }
            st = self.after(q);
        }
        (None, st)
    }

    /// Gives up the hole at `m` (`head <= m`): skips to the next frame start after it.
    fn give_up(&mut self, head: u64, m: u64) {
        let (found, st) = self.resume_point(head, m);
        let to = match found {
            Some(s) => s,
            None => self.buf.last_key_value().map_or(m + 1, |(&s, _)| s + 1),
        };
        self.remove_below(to);
        self.next = Some(to);
        self.prev = st;
        self.gap = true;
    }

    fn emit(&mut self, head: u64, end: u64) -> Option<Frame> {
        let rest = self.buf.split_off(&(end + 1));
        let pkts = std::mem::replace(&mut self.buf, rest);
        self.next = Some(end + 1);
        self.prev = Prev::Aligned;
        self.depack.reset();
        let mut data = Vec::new();
        let mut keyframe = false;
        let mut partial = false;
        let mut ok = true;
        let mut first_arrival: Option<Instant> = None;
        let mut ts = 0;
        for (i, p) in pkts.values().enumerate() {
            self.bytes -= p.payload.len();
            if i == 0 {
                ts = p.ts;
            }
            first_arrival = Some(first_arrival.map_or(p.arrival, |a| a.min(p.arrival)));
            partial |= p.partial;
            if ok {
                keyframe |= self.depack.is_keyframe(&p.payload);
                ok = self.depack.depacketize(&p.payload, &mut data).is_ok()
                    && data.len() <= MAX_FRAME_SIZE;
            }
        }
        self.depack.reset();
        if !ok {
            self.gap = true;
            return None;
        }
        let contiguous = !self.gap;
        self.gap = false;
        self.last_ts = Some(ts);
        Some(Frame {
            timestamp: ts,
            data,
            first_arrival: first_arrival?,
            contiguous,
            first_seq: head,
            last_seq: end,
            keyframe,
            partial,
        })
    }
}
