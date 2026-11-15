//! Stream (and CRYPTO) data buffers: what is sent, acknowledged and lost on the send side;
//! reassembly of out-of-order data on the receive side (RFC 9000 sections 2 and 3).

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;

use super::frame::{TransportError, code};
use super::ranges::RangeSet;
use crate::Bytes;

/// Written chunks in order, the first one held inline: a request or response written in one
/// piece (the usual HTTP/3 case) costs no queue allocation.
#[derive(Debug, Default)]
struct Chunks {
    /// The first chunk; `None` only when `rest` is empty too.
    front: Option<Bytes>,
    rest: VecDeque<Bytes>,
}

impl Chunks {
    fn push_back(&mut self, b: Bytes) {
        if self.front.is_none() {
            self.front = Some(b);
        } else {
            self.rest.push_back(b);
        }
    }

    fn front_mut(&mut self) -> Option<&mut Bytes> {
        self.front.as_mut()
    }

    fn pop_front(&mut self) {
        self.front = self.rest.pop_front();
    }

    fn iter(&self) -> impl Iterator<Item = &Bytes> {
        self.front.iter().chain(&self.rest)
    }

    fn clear(&mut self) {
        self.front = None;
        self.rest.clear();
    }
}

/// The send side of a stream: written bytes until acknowledged.
#[derive(Debug, Default)]
pub struct SendBuf {
    chunks: Chunks,
    /// Offset of the first byte of `chunks`.
    base: u64,
    /// Total bytes written.
    end: u64,
    /// Next new byte to send.
    sent: u64,
    acked: RangeSet,
    lost: RangeSet,
    pub fin: bool,
    pub fin_sent: bool,
    pub fin_acked: bool,
    fin_lost: bool,
}

impl SendBuf {
    pub fn write(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        self.end += data.len() as u64;
        self.chunks.push_back(data);
    }

    /// Total bytes written.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// The offset up to which new data was sent.
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Bytes written but never sent.
    pub fn unsent(&self) -> u64 {
        self.end - self.sent
    }

    /// Something to retransmit.
    pub fn has_lost(&self) -> bool {
        !self.lost.is_empty() || self.fin_lost
    }

    /// Whether anything can go out given the flow control limit `max` on new offsets.
    pub fn wants_send(&self, max: u64) -> bool {
        self.has_lost()
            || (self.sent < self.end && self.sent < max)
            || (self.fin && !self.fin_sent && self.sent == self.end)
    }

    /// Whether new data is blocked by flow control at `max`.
    pub fn blocked_at(&self, max: u64) -> bool {
        self.sent < self.end && self.sent >= max
    }

    /// The next range to send (retransmissions first), at most `max_len` bytes, new data below
    /// `max_offset`. Returns the range and whether it carries FIN. An empty range with FIN is a
    /// bare FIN.
    pub fn next(&mut self, max_len: usize, max_offset: u64) -> Option<(Range<u64>, bool)> {
        if let Some(r) = self.lost.pop_first(max_len as u64) {
            let fin = self.fin && r.end == self.end && self.fin_lost;
            if fin {
                self.fin_lost = false;
            }
            return Some((r, fin));
        }
        if self.fin_lost && self.sent == self.end {
            self.fin_lost = false;
            return Some((self.end..self.end, true));
        }
        let limit = self.end.min(max_offset).min(self.sent + max_len as u64);
        if limit > self.sent {
            let r = self.sent..limit;
            self.sent = limit;
            let fin = self.fin && limit == self.end;
            if fin {
                self.fin_sent = true;
            }
            return Some((r, fin));
        }
        if self.fin && !self.fin_sent && self.sent == self.end {
            self.fin_sent = true;
            return Some((self.end..self.end, true));
        }
        None
    }

    /// Copies the bytes of `r` (not yet acknowledged) to `out`.
    pub fn copy(&self, r: Range<u64>, out: &mut Vec<u8>) {
        let mut off = self.base;
        let mut need = r.start;
        for c in self.chunks.iter() {
            let cend = off + c.len() as u64;
            if cend > need {
                let from = (need - off) as usize;
                let to = (r.end.min(cend) - off) as usize;
                out.extend_from_slice(&c[from..to]);
                need = off + to as u64;
                if need >= r.end {
                    return;
                }
            }
            off = cend;
        }
    }

    /// Bytes sent but not acknowledged from the front.
    pub fn unacked(&self) -> u64 {
        self.sent - self.base.min(self.sent)
    }

    /// Records an acknowledgment; returns how far the acknowledged front moved.
    pub fn on_ack(&mut self, r: Range<u64>, fin: bool) -> u64 {
        let old_base = self.base;
        if fin {
            self.fin_acked = true;
            self.fin_lost = false;
        }
        if r.start >= r.end {
            return 0;
        }
        self.lost.remove(r.clone());
        if r.start <= self.base && self.acked.is_empty() {
            // In order (the usual case): move the front without a round trip through `acked`
            // (a tree node allocated and freed per acknowledgment).
            self.drop_front(r.end);
            return self.base - old_base;
        }
        self.acked.insert(r);
        // Drop what is acknowledged from the front.
        while let Some(f) = self.acked.first() {
            if f.start > self.base {
                break;
            }
            self.acked.pop_first(u64::MAX);
            self.drop_front(f.end);
        }
        self.base - old_base
    }

    /// Drops the chunks (and part of a chunk) below `upto`.
    fn drop_front(&mut self, upto: u64) {
        while self.base < upto {
            let Some(front) = self.chunks.front_mut() else {
                break;
            };
            let n = front.len() as u64;
            if self.base + n <= upto {
                self.base += n;
                self.chunks.pop_front();
            } else {
                front.advance((upto - self.base) as usize);
                self.base = upto;
            }
        }
    }

    pub fn on_lost(&mut self, r: Range<u64>, fin: bool) {
        if fin && !self.fin_acked {
            self.fin_lost = true;
        }
        let r = r.start.max(self.base)..r.end;
        for part in self.acked_gaps(r) {
            self.lost.insert(part);
        }
    }

    /// The parts of `r` not yet acknowledged.
    fn acked_gaps(&self, r: Range<u64>) -> Vec<Range<u64>> {
        if r.start >= r.end {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut at = r.start;
        for a in self.acked.overlapping(r.clone()) {
            if a.start > at {
                out.push(at..a.start);
            }
            at = a.end;
        }
        if at < r.end {
            out.push(at..r.end);
        }
        out
    }

    /// Everything written, FIN included, is acknowledged.
    pub fn all_acked(&self) -> bool {
        self.fin && self.fin_acked && self.base == self.end
    }

    /// Drops all data (after a reset); returns the bytes that were sent but not acknowledged.
    pub fn clear(&mut self) -> u64 {
        let unacked = self.unacked();
        self.chunks.clear();
        self.base = self.end;
        self.sent = self.end;
        self.acked.clear();
        self.lost.clear();
        self.fin_lost = false;
        unacked
    }
}

/// The receive side: reassembles data into order.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Next offset to deliver.
    read: u64,
    pending: BTreeMap<u64, Bytes>,
    /// An in-order chunk taken without reassembly, not popped yet (already counted in `read`).
    ready: Option<Bytes>,
    buffered: u64,
    pub final_size: Option<u64>,
    /// The highest offset received.
    pub max_seen: u64,
}

impl RecvBuf {
    pub fn read_offset(&self) -> u64 {
        self.read
    }

    /// Bytes held out of order.
    pub fn buffered(&self) -> u64 {
        self.buffered
    }

    /// Adds data at `offset`; checks the final size rules (RFC 9000 section 4.5).
    pub fn insert(
        &mut self,
        offset: u64,
        mut data: Bytes,
        fin: bool,
    ) -> Result<(), TransportError> {
        let end = offset + data.len() as u64;
        if let Some(f) = self.final_size {
            if end > f || (fin && end != f) {
                return Err(TransportError::new(
                    code::FINAL_SIZE_ERROR,
                    "data beyond the final size",
                ));
            }
        }
        if fin {
            if end < self.max_seen {
                return Err(TransportError::new(
                    code::FINAL_SIZE_ERROR,
                    "final size below received data",
                ));
            }
            self.final_size = Some(end);
        }
        self.max_seen = self.max_seen.max(end);
        if end <= self.read {
            return Ok(());
        }
        let mut offset = offset;
        if offset < self.read {
            data.advance((self.read - offset) as usize);
            offset = self.read;
        }
        if data.is_empty() {
            return Ok(());
        }
        if offset == self.read && self.pending.is_empty() && self.ready.is_none() {
            // In order with nothing buffered (the common case): no reassembly needed.
            self.read += data.len() as u64;
            self.ready = Some(data);
            return Ok(());
        }
        match self.pending.get(&offset) {
            Some(old) if old.len() >= data.len() => {}
            Some(old) => {
                self.buffered += (data.len() - old.len()) as u64;
                self.pending.insert(offset, data);
            }
            None => {
                self.buffered += data.len() as u64;
                self.pending.insert(offset, data);
            }
        }
        Ok(())
    }

    /// The next in-order chunk.
    pub fn pop(&mut self) -> Option<Bytes> {
        if let Some(d) = self.ready.take() {
            return Some(d);
        }
        loop {
            let (&off, _) = self.pending.iter().next()?;
            if off > self.read {
                return None;
            }
            let mut d = self.pending.remove(&off)?;
            self.buffered -= d.len() as u64;
            let skip = self.read - off;
            if skip >= d.len() as u64 {
                continue;
            }
            d.advance(skip as usize);
            self.read += d.len() as u64;
            return Some(d);
        }
    }

    /// All data up to the final size was delivered.
    pub fn finished(&self) -> bool {
        self.final_size == Some(self.read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_retransmits_and_acks() {
        let mut s = SendBuf::default();
        s.write(Bytes::from_static(b"hello "));
        s.write(Bytes::from_static(b"world"));
        s.write(Bytes::new());
        assert_eq!((s.end(), s.unsent()), (11, 11));
        assert!(s.wants_send(100) && !s.wants_send(0));
        assert!(s.blocked_at(0));
        let (r1, fin) = s.next(4, 100).unwrap();
        assert_eq!((r1.clone(), fin), (0..4, false));
        let (r2, _) = s.next(100, 8).unwrap();
        assert_eq!(r2, 4..8);
        s.fin = true;
        let (r3, fin) = s.next(100, 100).unwrap();
        assert_eq!((r3.clone(), fin), (8..11, true));
        assert!(s.next(100, 100).is_none());
        let mut out = Vec::new();
        s.copy(r2.clone(), &mut out);
        assert_eq!(out, b"o wo");
        // The middle range is lost and resent; the rest acknowledged.
        s.on_lost(r2, false);
        s.on_ack(r1, false);
        s.on_ack(r3, true);
        assert!(s.has_lost() && !s.all_acked());
        let (again, fin) = s.next(2, 100).unwrap();
        assert_eq!((again.clone(), fin), (4..6, false));
        out.clear();
        s.copy(again, &mut out);
        assert_eq!(out, b"o ");
        s.on_ack(4..8, false);
        assert!(s.all_acked());
        assert!(!s.has_lost());
        // Lost after acknowledged: nothing to resend.
        s.on_lost(4..8, false);
        assert!(!s.has_lost());
    }

    #[test]
    fn bare_fin_and_lost_fin() {
        let mut s = SendBuf {
            fin: true,
            ..SendBuf::default()
        };
        assert_eq!(s.next(10, 10), Some((0..0, true)));
        assert!(s.next(10, 10).is_none());
        s.on_lost(0..0, true);
        assert_eq!(s.next(10, 10), Some((0..0, true)));
        s.on_ack(0..0, true);
        assert!(s.all_acked());
        let mut s = SendBuf::default();
        s.write(Bytes::from_static(b"ab"));
        s.next(10, 10);
        s.clear();
        assert_eq!(s.unsent(), 0);
    }

    #[test]
    fn recv_reassembles() {
        let mut r = RecvBuf::default();
        r.insert(5, Bytes::from_static(b"fgh"), false).unwrap();
        r.insert(5, Bytes::from_static(b"f"), false).unwrap();
        assert_eq!(r.pop(), None);
        assert_eq!(r.buffered(), 3);
        r.insert(0, Bytes::from_static(b"abcdef"), false).unwrap();
        assert_eq!(r.pop().unwrap(), "abcdef");
        assert_eq!(r.pop().unwrap(), "gh");
        assert_eq!(r.read_offset(), 8);
        r.insert(2, Bytes::from_static(b"cd"), false).unwrap();
        assert_eq!(r.pop(), None);
        r.insert(8, Bytes::from_static(b"ij"), true).unwrap();
        assert_eq!(r.pop().unwrap(), "ij");
        assert!(r.finished());
        assert!(r.insert(9, Bytes::from_static(b"zz"), false).is_err());
        assert!(r.insert(0, Bytes::new(), true).is_err());
        let mut r = RecvBuf::default();
        r.insert(0, Bytes::from_static(b"abc"), false).unwrap();
        assert!(r.insert(0, Bytes::from_static(b"a"), true).is_err());
        r.insert(5, Bytes::from_static(b"xy"), false).unwrap();
        r.insert(5, Bytes::from_static(b"xyz"), false).unwrap();
        // "abc" arrived in order and waits outside the reassembly buffer.
        assert_eq!(r.buffered(), 3);
        assert_eq!(r.pop().unwrap(), "abc");
        assert_eq!(r.pop(), None);
        r.insert(3, Bytes::from_static(b"de"), false).unwrap();
        assert_eq!(r.pop().unwrap(), "de");
        assert_eq!(r.pop().unwrap(), "xyz");
    }
}
