//! The receiving half: TSN tracking, SACK generation (RFC 9260 §6.2), reassembly of DATA
//! (by TSN) or I-DATA (by stream, MID and FSN, RFC 8260 §2.1) chunks, per-stream ordered
//! delivery, FORWARD TSN (RFC 3758 §3.6) or I-FORWARD-TSN (RFC 8260 §2.3) and incoming stream
//! resets.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::packet::{Data, FLAG_BEGIN, FLAG_END, FLAG_IMMEDIATE, FLAG_UNORDERED, IData, Sack};
use crate::sched::StreamMap;
use crate::send::{le16, le32};

/// Delayed SACK timer (RFC 9260 §6.2: at most 500 ms; 200 ms is customary).
pub(crate) const SACK_DELAY: Duration = Duration::from_millis(200);
/// Bookkeeping cost charged per buffered chunk against the memory cap, so that tiny chunks
/// cannot make us hold millions of map entries.
const CHUNK_OVERHEAD: usize = 64;
/// TSNs further than this ahead of the cumulative TSN are dropped.
const MAX_TSN_AHEAD: u64 = 1 << 16;
const MAX_DUPS: usize = 32;

/// A complete message handed up.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) stream: u16,
    pub(crate) ppid: u32,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug)]
struct RChunk {
    stream: u16,
    ssn: u16,
    ppid: u32,
    flags: u8,
    data: Vec<u8>,
}

impl RChunk {
    fn unordered(&self) -> bool {
        self.flags & FLAG_UNORDERED != 0
    }

    /// Same message as `other` could be (consecutive TSNs of one message share these).
    fn same_message(&self, other: &RChunk) -> bool {
        self.stream == other.stream
            && self.unordered() == other.unordered()
            && (self.unordered() || self.ssn == other.ssn)
    }
}

#[derive(Debug, Default)]
struct InStream {
    /// Next SSN (DATA, 16 bits) or MID (I-DATA) to deliver.
    next: u32,
    ready: BTreeMap<u32, Message>,
}

/// An I-DATA message being reassembled: fragments that arrive in FSN order are appended to
/// `data` directly, the others wait in `later`.
#[derive(Debug, Default)]
struct Partial {
    /// Fragments 0 .. `next`, concatenated.
    data: Vec<u8>,
    next: u32,
    later: BTreeMap<u32, Vec<u8>>,
    ppid: u32,
    last: Option<u32>,
    /// Payload bytes and fragments held (charged).
    size: usize,
    frags: usize,
}

/// The message exceeded the receive limit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TooLarge;

#[derive(Debug)]
pub(crate) struct Receiver {
    /// Cumulative TSN, extended to 64 bits (starts at 2^32 + initial TSN - 1).
    cum: u64,
    /// Received TSNs above `cum`.
    received: BTreeSet<u64>,
    /// Received DATA fragments not yet assembled, by extended TSN.
    chunks: BTreeMap<u64, RChunk>,
    /// I-DATA mode (RFC 8260): fragments are reassembled by message instead.
    idata: bool,
    /// Received I-DATA fragments by (stream, unordered, MID).
    reasm: BTreeMap<(u16, bool, u32), Partial>,
    streams: StreamMap<InStream>,
    /// Payload bytes held (fragments plus complete messages waiting for their SSN).
    held: usize,
    /// `held` plus per-chunk overhead, checked against the caps.
    charged: usize,
    dups: Vec<u32>,
    window: usize,
    max_message: usize,
    soft_cap: usize,
    hard_cap: usize,
    packets_unacked: u32,
    sack_now: bool,
    pub(crate) sack_deadline: Option<Instant>,
}

impl Receiver {
    pub(crate) fn new(
        peer_initial_tsn: u32,
        window: u32,
        max_message: usize,
        mtu: usize,
        idata: bool,
    ) -> Receiver {
        let window = window as usize;
        let soft_cap = window.max(max_message).saturating_add(4 * mtu);
        Receiver {
            cum: (1u64 << 32) + u64::from(peer_initial_tsn) - 1,
            received: BTreeSet::new(),
            chunks: BTreeMap::new(),
            idata,
            reasm: BTreeMap::new(),
            streams: StreamMap::default(),
            held: 0,
            charged: 0,
            dups: Vec::new(),
            window,
            max_message,
            soft_cap,
            hard_cap: soft_cap.saturating_mul(2),
            packets_unacked: 0,
            sack_now: false,
            sack_deadline: None,
        }
    }

    pub(crate) fn cum_tsn(&self) -> u32 {
        self.cum as u32
    }

    fn extend(&self, tsn: u32) -> u64 {
        let diff = i64::from(tsn.wrapping_sub(self.cum as u32) as i32);
        // `cum` is at least 2^32 - 1, so this never goes negative.
        (self.cum as i64 + diff) as u64
    }

    fn advance_cum(&mut self) {
        while self.received.first() == Some(&(self.cum + 1)) {
            self.received.pop_first();
            self.cum += 1;
        }
    }

    /// Advertised receiver window.
    pub(crate) fn a_rwnd(&self) -> u32 {
        u32::try_from(self.window.saturating_sub(self.held)).unwrap_or(u32::MAX)
    }

    /// Call once per received packet that carried DATA (RFC 9260 §6.2: ack at least every
    /// second packet, or within the delay).
    pub(crate) fn packet_done(&mut self, now: Instant) {
        self.packets_unacked += 1;
        if self.packets_unacked >= 2 || !self.received.is_empty() || !self.dups.is_empty() {
            self.sack_now = true;
        } else if self.sack_deadline.is_none() {
            self.sack_deadline = Some(now + SACK_DELAY);
        }
    }

    pub(crate) fn on_sack_timer(&mut self) {
        self.sack_deadline = None;
        self.sack_now = true;
    }

    pub(crate) fn sack_due(&self) -> bool {
        self.sack_now
    }

    pub(crate) fn sack_pending(&self) -> bool {
        self.sack_now || self.sack_deadline.is_some()
    }

    /// Builds a SACK that fits in `room` bytes and resets the SACK state.
    pub(crate) fn make_sack(&mut self, room: usize) -> Sack {
        let dups: Vec<u32> = std::mem::take(&mut self.dups);
        let max_dups = room.saturating_sub(16) / 4;
        let dups: Vec<u32> = dups.into_iter().take(max_dups).collect();
        let max_gaps = room.saturating_sub(16 + 4 * dups.len()) / 4;
        let mut gaps: Vec<(u16, u16)> = Vec::new();
        let mut cur: Option<(u64, u64)> = None;
        for &t in &self.received {
            let off = t - self.cum;
            if off > u64::from(u16::MAX) {
                break;
            }
            cur = match cur {
                Some((s, e)) if off == e + 1 => Some((s, off)),
                Some((s, e)) => {
                    if gaps.len() == max_gaps {
                        cur = None;
                        break;
                    }
                    gaps.push((s as u16, e as u16));
                    Some((off, off))
                }
                None => Some((off, off)),
            };
        }
        if let Some((s, e)) = cur {
            if gaps.len() < max_gaps {
                gaps.push((s as u16, e as u16));
            }
        }
        self.sack_now = false;
        self.sack_deadline = None;
        self.packets_unacked = 0;
        Sack {
            cum_tsn: self.cum_tsn(),
            a_rwnd: self.a_rwnd(),
            gaps,
            dups,
        }
    }

    /// Whether a chunk with this TSN and payload size is taken: not a duplicate, not too far
    /// ahead and within the memory caps. Records the TSN as received when it is.
    /// `continues`: an I-DATA fragment of a message already started, which gets the larger
    /// cap so that started messages can always complete.
    fn accept(&mut self, flags: u8, tsn: u32, len: usize, continues: bool) -> Option<u64> {
        if flags & FLAG_IMMEDIATE != 0 {
            self.sack_now = true;
        }
        if len == 0 {
            return None; // RFC 9260 §6.2: no user data; ignored
        }
        let t = self.extend(tsn);
        if t <= self.cum || self.received.contains(&t) {
            if self.dups.len() < MAX_DUPS {
                self.dups.push(tsn);
            }
            self.sack_now = true;
            return None;
        }
        if t - self.cum > MAX_TSN_AHEAD {
            return None;
        }
        let cost = len + CHUNK_OVERHEAD;
        let limit = if t == self.cum + 1 || continues {
            self.hard_cap
        } else {
            self.soft_cap
        };
        if self.charged + cost > limit {
            return None; // no room: the peer retransmits
        }
        self.received.insert(t);
        self.advance_cum();
        Some(t)
    }

    /// Takes one DATA chunk; complete messages are appended to `out`.
    pub(crate) fn on_data(&mut self, d: &Data<'_>, out: &mut Vec<Message>) -> Result<(), TooLarge> {
        let Some(t) = self.accept(d.flags, d.tsn, d.payload.len(), false) else {
            return Ok(());
        };
        if d.flags & (FLAG_BEGIN | FLAG_END) == FLAG_BEGIN | FLAG_END {
            // A whole message in one chunk: no reassembly.
            return self.whole(d.stream, d.ppid, d.flags, u32::from(d.ssn), d.payload, out);
        }
        self.held += d.payload.len();
        self.charged += d.payload.len() + CHUNK_OVERHEAD;
        let end = d.flags & FLAG_END != 0;
        self.chunks.insert(
            t,
            RChunk {
                stream: d.stream,
                ssn: d.ssn,
                ppid: d.ppid,
                flags: d.flags,
                data: d.payload.to_vec(),
            },
        );
        // A message can only be complete when this chunk ends it or its successor is here.
        if end || self.chunks.contains_key(&(t + 1)) {
            self.try_assemble(t, out)?;
        }
        Ok(())
    }

    fn try_assemble(&mut self, t: u64, out: &mut Vec<Message>) -> Result<(), TooLarge> {
        let Some(c) = self.chunks.get(&t) else {
            return Ok(());
        };
        // Walk back to the first fragment, then forward to the last.
        let mut first = t;
        let mut cur = c;
        while cur.flags & FLAG_BEGIN == 0 {
            match self.chunks.get(&(first - 1)) {
                Some(p) if p.same_message(cur) && p.flags & FLAG_END == 0 => {
                    first -= 1;
                    cur = p;
                }
                _ => return Ok(()),
            }
        }
        let mut last = first;
        let mut size = cur.data.len();
        while cur.flags & FLAG_END == 0 {
            match self.chunks.get(&(last + 1)) {
                Some(n) if n.same_message(cur) && n.flags & FLAG_BEGIN == 0 => {
                    last += 1;
                    size += n.data.len();
                    cur = n;
                }
                _ => return Ok(()),
            }
        }
        if size > self.max_message {
            return Err(TooLarge);
        }
        let mut data = Vec::with_capacity(size);
        let mut head = None;
        for k in first..=last {
            if let Some(c) = self.chunks.remove(&k) {
                self.charged -= c.data.len() + CHUNK_OVERHEAD;
                data.extend_from_slice(&c.data);
                if head.is_none() {
                    head = Some((c.stream, c.ssn, c.ppid, c.unordered()));
                }
            }
        }
        let Some((stream, ssn, ppid, unordered)) = head else {
            return Ok(());
        };
        // Charge the complete message as one buffered item until delivered.
        self.charged += CHUNK_OVERHEAD;
        let msg = Message { stream, ppid, data };
        if unordered {
            self.deliver(msg, out);
        } else {
            self.in_order(u32::from(ssn), msg, out);
        }
        Ok(())
    }

    /// A message in a single chunk (B and E set): delivered or held without reassembly.
    fn whole(
        &mut self,
        stream: u16,
        ppid: u32,
        flags: u8,
        seq: u32,
        payload: &[u8],
        out: &mut Vec<Message>,
    ) -> Result<(), TooLarge> {
        if payload.len() > self.max_message {
            return Err(TooLarge);
        }
        // Charged as a complete message waiting for delivery (see `try_assemble`).
        self.held += payload.len();
        self.charged += CHUNK_OVERHEAD;
        let msg = Message {
            stream,
            ppid,
            data: payload.to_vec(),
        };
        if flags & FLAG_UNORDERED != 0 {
            self.deliver(msg, out);
        } else {
            self.in_order(seq, msg, out);
        }
        Ok(())
    }

    /// `a` is at or before `b` in the sequence space of SSNs (16 bits) or MIDs (32 bits).
    fn seq_le(&self, a: u32, b: u32) -> bool {
        if self.idata {
            le32(a, b)
        } else {
            le16(a as u16, b as u16)
        }
    }

    fn seq_next(&self, a: u32) -> u32 {
        if self.idata {
            a.wrapping_add(1)
        } else {
            u32::from((a as u16).wrapping_add(1))
        }
    }

    /// A complete ordered message (charged as one buffered item): delivered now if it is
    /// the stream's next, else held until it is.
    fn in_order(&mut self, seq: u32, msg: Message, out: &mut Vec<Message>) {
        let stream = msg.stream;
        let next = self.streams.entry(stream).or_default().next;
        if seq == next {
            let n = self.seq_next(seq);
            if let Some(st) = self.streams.get_mut(&stream) {
                st.next = n;
            }
            self.deliver(msg, out);
            self.drain_stream(stream, out);
        } else if self.seq_le(next, seq) {
            if let Some(st) = self.streams.get_mut(&stream) {
                st.ready.insert(seq, msg);
            }
        } else {
            // An old SSN / MID (duplicate after a reset or forward): drop.
            self.held -= msg.data.len();
            self.charged -= CHUNK_OVERHEAD;
        }
    }

    /// Takes one I-DATA chunk (RFC 8260 §2.1); complete messages are appended to `out`.
    pub(crate) fn on_idata(
        &mut self,
        d: &IData<'_>,
        out: &mut Vec<Message>,
    ) -> Result<(), TooLarge> {
        let continues = d.flags & FLAG_BEGIN == 0
            && self
                .reasm
                .contains_key(&(d.stream, d.flags & FLAG_UNORDERED != 0, d.mid));
        if self
            .accept(d.flags, d.tsn, d.payload.len(), continues)
            .is_none()
        {
            return Ok(());
        }
        let begin = d.flags & FLAG_BEGIN != 0;
        let unordered = d.flags & FLAG_UNORDERED != 0;
        if !begin && d.fsn == 0 {
            return Ok(()); // FSN 0 is the first fragment's: malformed, dropped (but acked)
        }
        if !unordered {
            let next = self.streams.get(&d.stream).map_or(0, |s| s.next);
            if !le32(next, d.mid) {
                return Ok(()); // a message already delivered or skipped
            }
        }
        if begin && d.flags & FLAG_END != 0 {
            return self.whole(d.stream, d.ppid, d.flags, d.mid, d.payload, out);
        }
        let key = (d.stream, unordered, d.mid);
        let p = self.reasm.entry(key).or_default();
        if d.fsn < p.next || p.later.contains_key(&d.fsn) {
            return Ok(()); // the same fragment under another TSN
        }
        if begin {
            p.ppid = d.ppid;
        }
        if d.flags & FLAG_END != 0 && p.last.is_none() {
            p.last = Some(d.fsn);
        }
        if d.fsn == p.next {
            p.data.extend_from_slice(d.payload);
            p.next = p.next.wrapping_add(1);
            while let Some(f) = p.later.remove(&p.next) {
                p.data.extend_from_slice(&f);
                p.next = p.next.wrapping_add(1);
            }
        } else {
            p.later.insert(d.fsn, d.payload.to_vec());
        }
        p.size += d.payload.len();
        p.frags += 1;
        let size = p.size;
        let complete = p.last.is_some_and(|l| p.next == l.wrapping_add(1));
        self.held += d.payload.len();
        self.charged += d.payload.len() + CHUNK_OVERHEAD;
        if size > self.max_message {
            return Err(TooLarge);
        }
        if !complete {
            return Ok(());
        }
        let Some(p) = self.reasm.remove(&key) else {
            return Ok(());
        };
        // Fragments past the last one (malformed) are dropped with it.
        let stray: usize = p.later.values().map(Vec::len).sum();
        self.held -= stray;
        self.charged -= p.size + p.frags * CHUNK_OVERHEAD;
        self.charged += CHUNK_OVERHEAD;
        let msg = Message {
            stream: d.stream,
            ppid: p.ppid,
            data: p.data,
        };
        if unordered {
            self.deliver(msg, out);
        } else {
            self.in_order(d.mid, msg, out);
        }
        Ok(())
    }

    /// Drops an I-DATA message being reassembled.
    fn drop_partial(&mut self, key: (u16, bool, u32)) {
        if let Some(p) = self.reasm.remove(&key) {
            self.held -= p.size;
            self.charged -= p.size + p.frags * CHUNK_OVERHEAD;
        }
    }

    fn deliver(&mut self, msg: Message, out: &mut Vec<Message>) {
        self.held -= msg.data.len();
        self.charged -= CHUNK_OVERHEAD;
        out.push(msg);
    }

    fn drain_stream(&mut self, stream: u16, out: &mut Vec<Message>) {
        loop {
            let Some(st) = self.streams.get_mut(&stream) else {
                return;
            };
            let next = st.next;
            let Some(m) = st.ready.remove(&next) else {
                return;
            };
            st.next = if self.idata {
                next.wrapping_add(1)
            } else {
                u32::from((next as u16).wrapping_add(1))
            };
            self.deliver(m, out);
        }
    }

    /// FORWARD TSN (RFC 3758 §3.6): skips to `new_cum`, drops the partial messages up to it
    /// and moves the given streams past the given SSNs.
    pub(crate) fn on_forward_tsn(
        &mut self,
        new_cum: u32,
        streams: &[(u16, u16)],
        out: &mut Vec<Message>,
    ) {
        self.sack_now = true;
        let t = self.extend(new_cum);
        if t > self.cum && t - self.cum <= MAX_TSN_AHEAD {
            let keep = self.chunks.split_off(&(t + 1));
            for c in std::mem::replace(&mut self.chunks, keep).into_values() {
                self.held -= c.data.len();
                self.charged -= c.data.len() + CHUNK_OVERHEAD;
            }
            self.received = self.received.split_off(&(t + 1));
            self.cum = t;
            self.advance_cum();
            // Continuation fragments whose start was skipped can never complete.
            let mut k = t + 1;
            while self
                .chunks
                .get(&k)
                .is_some_and(|c| c.flags & FLAG_BEGIN == 0)
            {
                if let Some(c) = self.chunks.remove(&k) {
                    self.held -= c.data.len();
                    self.charged -= c.data.len() + CHUNK_OVERHEAD;
                }
                k += 1;
            }
        }
        for &(stream, ssn) in streams {
            self.skip_to(stream, u32::from(ssn), out);
        }
    }

    /// Delivers what is complete on `stream` up to `seq` in order, then moves past it.
    fn skip_to(&mut self, stream: u16, seq: u32, out: &mut Vec<Message>) {
        let idata = self.idata;
        let le = move |a: u32, b: u32| {
            if idata {
                le32(a, b)
            } else {
                le16(a as u16, b as u16)
            }
        };
        let after = self.seq_next(seq);
        let st = self.streams.entry(stream).or_default();
        if !le(st.next, seq) {
            return;
        }
        let base = st.next;
        let ready: Vec<u32> = st
            .ready
            .keys()
            .copied()
            .filter(|&s| le(s, seq) && le(base, s))
            .collect();
        let mut msgs: Vec<(u32, Message)> = ready
            .into_iter()
            .filter_map(|s| st.ready.remove(&s).map(|m| (s, m)))
            .collect();
        msgs.sort_by_key(|(s, _)| s.wrapping_sub(base) & if idata { u32::MAX } else { 0xffff });
        st.next = after;
        for (_, m) in msgs {
            self.deliver(m, out);
        }
        self.drain_stream(stream, out);
    }

    /// I-FORWARD-TSN (RFC 8260 §2.3.1): skips to `new_cum`; for each ordered entry drops
    /// the partial messages up to its MID and moves the stream past it, for each unordered
    /// one drops that message. Fragments are not dropped by TSN: with interleaving, those
    /// below `new_cum` may belong to messages that still complete.
    pub(crate) fn on_iforward_tsn(
        &mut self,
        new_cum: u32,
        entries: &[(u16, bool, u32)],
        out: &mut Vec<Message>,
    ) {
        self.sack_now = true;
        let t = self.extend(new_cum);
        if t > self.cum && t - self.cum <= MAX_TSN_AHEAD {
            self.received = self.received.split_off(&(t + 1));
            self.cum = t;
            self.advance_cum();
        }
        for &(stream, unordered, mid) in entries {
            if unordered {
                self.drop_partial((stream, true, mid));
                continue;
            }
            let next = self.streams.get(&stream).map_or(0, |s| s.next);
            if !le32(next, mid) {
                continue;
            }
            // Partial messages next ..= mid (serial order: one or two key ranges).
            let ranges = if next <= mid {
                [(next, mid), (1, 0)]
            } else {
                [(next, u32::MAX), (0, mid)]
            };
            let mut stale: Vec<(u16, bool, u32)> = Vec::new();
            for (lo, hi) in ranges {
                if lo <= hi {
                    stale.extend(
                        self.reasm
                            .range((stream, false, lo)..=(stream, false, hi))
                            .map(|(k, _)| *k),
                    );
                }
            }
            for k in stale {
                self.drop_partial(k);
            }
            self.skip_to(stream, mid, out);
        }
    }

    /// Incoming stream reset performed (RFC 6525 §5.2.2): the stream's SSN restarts at 0.
    pub(crate) fn reset_stream(&mut self, stream: u16) {
        if let Some(st) = self.streams.remove(&stream) {
            for m in st.ready.into_values() {
                self.held -= m.data.len();
                self.charged -= CHUNK_OVERHEAD;
            }
        }
    }

    /// Resets every incoming stream.
    pub(crate) fn reset_all_streams(&mut self) {
        let ids: Vec<u16> = self.streams.keys().copied().collect();
        for s in ids {
            self.reset_stream(s);
        }
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(tsn: u32, stream: u16, ssn: u16, flags: u8, payload: &[u8]) -> Data<'_> {
        Data {
            flags,
            tsn,
            stream,
            ssn,
            ppid: 51,
            payload,
        }
    }

    const BE: u8 = FLAG_BEGIN | FLAG_END;

    #[test]
    fn ordered_out_of_order_and_gaps() {
        let mut r = Receiver::new(u32::MAX - 1, 1 << 20, 1 << 20, 1200, false);
        let mut out = Vec::new();
        // TSNs wrap: MAX-1, MAX, 0, 1.
        r.on_data(&data(0, 1, 2, BE, b"c"), &mut out).unwrap();
        r.on_data(&data(u32::MAX, 1, 1, BE, b"b"), &mut out)
            .unwrap();
        assert!(out.is_empty());
        let s = r.make_sack(1000);
        assert_eq!(s.cum_tsn, u32::MAX - 2);
        assert_eq!(s.gaps, vec![(2, 3)]);
        r.on_data(&data(u32::MAX - 1, 1, 0, BE, b"a"), &mut out)
            .unwrap();
        let got: Vec<&[u8]> = out.iter().map(|m| &m.data[..]).collect();
        assert_eq!(got, vec![&b"a"[..], b"b", b"c"]);
        assert_eq!(r.cum_tsn(), 0);
        // Duplicate.
        r.on_data(&data(0, 1, 2, BE, b"c"), &mut out).unwrap();
        assert_eq!(r.make_sack(1000).dups, vec![0]);
        assert_eq!(r.held(), 0);
    }

    #[test]
    fn fragments_and_limit() {
        let mut r = Receiver::new(1, 1 << 20, 5, 1200, false);
        let mut out = Vec::new();
        r.on_data(&data(3, 0, 0, FLAG_END, b"cc"), &mut out)
            .unwrap();
        r.on_data(&data(1, 0, 0, FLAG_BEGIN, b"a"), &mut out)
            .unwrap();
        r.on_data(&data(2, 0, 0, 0, b"bb"), &mut out).unwrap();
        assert_eq!(out[0].data, b"abbcc");
        assert_eq!(
            r.on_data(&data(4, 0, 1, FLAG_BEGIN, b"xxx"), &mut out),
            Ok(())
        );
        assert_eq!(
            r.on_data(&data(5, 0, 1, FLAG_END, b"yyy"), &mut out),
            Err(TooLarge)
        );
    }

    #[test]
    fn forward_tsn_skips() {
        let mut r = Receiver::new(10, 1 << 20, 1 << 20, 1200, false);
        let mut out = Vec::new();
        // SSN 0 lost (TSN 10), SSN 1 partial (TSN 11 begin, 12 lost), SSN 2 complete (13).
        r.on_data(&data(11, 0, 1, FLAG_BEGIN, b"x"), &mut out)
            .unwrap();
        r.on_data(&data(13, 0, 2, BE, b"z"), &mut out).unwrap();
        assert!(out.is_empty());
        r.on_forward_tsn(12, &[(0, 1)], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data, b"z");
        assert_eq!(r.cum_tsn(), 13);
        assert_eq!(r.held(), 0);
    }

    fn idata(tsn: u32, stream: u16, mid: u32, fsn: u32, flags: u8, payload: &[u8]) -> IData<'_> {
        IData {
            flags,
            tsn,
            stream,
            mid,
            ppid: if flags & FLAG_BEGIN != 0 { 53 } else { 0 },
            fsn,
            payload,
        }
    }

    #[test]
    fn idata_interleaved_reassembly() {
        let mut r = Receiver::new(u32::MAX - 2, 1 << 20, 1 << 20, 1200, true);
        let mut out = Vec::new();
        // Stream 1 MID 0 "abc" (3 fragments) interleaved with stream 2 MID 0 "xy" and stream
        // 1 MID 1 "z"; fragments arrive out of order across the TSN wrap.
        let t = |i: u32| (u32::MAX - 2).wrapping_add(i);
        r.on_idata(&idata(t(4), 1, 1, 0, BE, b"z"), &mut out)
            .unwrap();
        r.on_idata(&idata(t(3), 1, 0, 2, FLAG_END, b"c"), &mut out)
            .unwrap();
        r.on_idata(&idata(t(1), 2, 0, 0, FLAG_BEGIN, b"x"), &mut out)
            .unwrap();
        r.on_idata(&idata(t(0), 1, 0, 0, FLAG_BEGIN, b"a"), &mut out)
            .unwrap();
        assert!(out.is_empty());
        r.on_idata(&idata(t(5), 2, 0, 1, FLAG_END, b"y"), &mut out)
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out[0].stream, out[0].ppid, &out[0].data[..]),
            (2, 53, &b"xy"[..])
        );
        r.on_idata(&idata(t(2), 1, 0, 1, 0, b"b"), &mut out)
            .unwrap();
        let got: Vec<(u16, &[u8])> = out.iter().map(|m| (m.stream, &m.data[..])).collect();
        assert_eq!(got, vec![(2, &b"xy"[..]), (1, b"abc"), (1, b"z")]);
        assert_eq!(r.cum_tsn(), t(5));
        // Duplicates and an old MID are dropped.
        r.on_idata(&idata(t(5), 2, 0, 1, FLAG_END, b"y"), &mut out)
            .unwrap();
        r.on_idata(&idata(t(6), 1, 0, 0, BE, b"old"), &mut out)
            .unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(r.held(), 0);
        assert_eq!(r.make_sack(1000).dups, vec![t(5)]);
    }

    #[test]
    fn idata_malformed_and_limit() {
        let mut r = Receiver::new(1, 1 << 20, 6, 1200, true);
        let mut out = Vec::new();
        // FSN 0 without the B bit is malformed: acked, dropped.
        r.on_idata(&idata(1, 0, 0, 0, FLAG_END, b"bad"), &mut out)
            .unwrap();
        assert_eq!((r.cum_tsn(), r.held()), (1, 0));
        // The same fragment under another TSN is ignored.
        r.on_idata(&idata(2, 0, 0, 0, FLAG_BEGIN, b"ab"), &mut out)
            .unwrap();
        r.on_idata(&idata(3, 0, 0, 0, FLAG_BEGIN, b"ab"), &mut out)
            .unwrap();
        assert_eq!(r.held(), 2);
        assert_eq!(
            r.on_idata(&idata(4, 0, 0, 1, 0, b"cdefg"), &mut out),
            Err(TooLarge)
        );
        assert!(out.is_empty());
    }

    #[test]
    fn iforward_tsn_skips_by_mid() {
        let mut r = Receiver::new(10, 1 << 20, 1 << 20, 1200, true);
        let mut out = Vec::new();
        // Stream 0: MID 0 partial (TSN 10), MID 1 lost, MID 2 complete (13). Stream 3,
        // unordered: MID 5 partial (12) and MID 6 partial (14).
        r.on_idata(&idata(10, 0, 0, 0, FLAG_BEGIN, b"p"), &mut out)
            .unwrap();
        r.on_idata(
            &idata(12, 3, 5, 0, FLAG_BEGIN | FLAG_UNORDERED, b"u"),
            &mut out,
        )
        .unwrap();
        r.on_idata(&idata(13, 0, 2, 0, BE, b"two"), &mut out)
            .unwrap();
        r.on_idata(
            &idata(14, 3, 6, 0, FLAG_BEGIN | FLAG_UNORDERED, b"v"),
            &mut out,
        )
        .unwrap();
        assert!(out.is_empty());
        r.on_iforward_tsn(11, &[(0, false, 1), (3, true, 5)], &mut out);
        let got: Vec<&[u8]> = out.iter().map(|m| &m.data[..]).collect();
        assert_eq!(got, vec![&b"two"[..]]);
        assert_eq!(r.cum_tsn(), 14);
        // Only the unordered message named is dropped; MID 6 still completes.
        assert_eq!(r.held(), 1);
        r.on_idata(
            &idata(15, 3, 6, 1, FLAG_END | FLAG_UNORDERED, b"w"),
            &mut out,
        )
        .unwrap();
        assert_eq!(out[1].data, b"vw");
        // Stale or far-off forwards change nothing.
        r.on_iforward_tsn(3, &[(0, false, 0)], &mut out);
        assert_eq!((r.cum_tsn(), out.len()), (15, 2));
        assert_eq!(r.held(), 0);
    }
}
