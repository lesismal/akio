//! Byte buffers of a TCP connection: a fixed-capacity ring (send and receive buffers) and the
//! assembler tracking out-of-order data written ahead of the readable part of the receive ring.

/// A fixed-capacity byte ring. Data is appended at the tail and consumed at the head; data can
/// also be written at an offset past the tail (out-of-order receive) and later committed.
#[derive(Debug)]
pub(crate) struct Ring {
    buf: Box<[u8]>,
    head: usize,
    len: usize,
}

impl Ring {
    pub(crate) fn new(cap: usize) -> Ring {
        Ring {
            buf: vec![0; cap].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    pub(crate) fn cap(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn free(&self) -> usize {
        self.buf.len() - self.len
    }

    /// Appends as much of `data` as fits; returns the bytes taken.
    pub(crate) fn push(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.free());
        self.write_at(self.len, &data[..n]);
        self.len += n;
        n
    }

    /// Writes `data` at `off` bytes past the head (`off + data.len() <= cap`), without changing
    /// the length.
    pub(crate) fn write_at(&mut self, off: usize, data: &[u8]) {
        let cap = self.buf.len();
        debug_assert!(off + data.len() <= cap);
        let start = (self.head + off) % cap.max(1);
        let first = data.len().min(cap - start);
        self.buf[start..start + first].copy_from_slice(&data[..first]);
        self.buf[..data.len() - first].copy_from_slice(&data[first..]);
    }

    /// Makes `n` more bytes past the tail (written with `write_at`) part of the data.
    pub(crate) fn commit(&mut self, n: usize) {
        debug_assert!(self.len + n <= self.buf.len());
        self.len += n;
    }

    /// The `n` bytes starting `off` bytes past the head, as one or two slices.
    pub(crate) fn slices(&self, off: usize, n: usize) -> (&[u8], &[u8]) {
        debug_assert!(off + n <= self.len);
        let cap = self.buf.len();
        if n == 0 {
            return (&[], &[]);
        }
        let start = (self.head + off) % cap;
        let first = n.min(cap - start);
        (&self.buf[start..start + first], &self.buf[..n - first])
    }

    /// Drops `n` bytes from the head.
    pub(crate) fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.len -= n;
        // The head moves even when the ring empties: data written past the tail (out of order)
        // stays where it is.
        if n > 0 {
            self.head = (self.head + n) % self.buf.len();
        }
    }

    /// Copies up to `out.len()` bytes from the head into `out` and consumes them.
    pub(crate) fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        let (a, b) = self.slices(0, n);
        out[..a.len()].copy_from_slice(a);
        out[a.len()..n].copy_from_slice(b);
        self.consume(n);
        n
    }
}

/// Out-of-order ranges received past the in-order point, as `(start, end)` byte offsets
/// relative to it, sorted and disjoint (never adjacent).
#[derive(Debug, Default)]
pub(crate) struct Assembler {
    ranges: Vec<(u32, u32)>,
    /// The range holding the most recently received segment (first SACK block, RFC 2018).
    last: Option<(u32, u32)>,
}

/// Most disjoint out-of-order ranges kept; a segment that would need more is dropped (the
/// peer retransmits it).
pub(crate) const MAX_RANGES: usize = 32;

impl Assembler {
    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub(crate) fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }

    /// Records `[start, end)`. Returns `false` (nothing recorded) if that would exceed
    /// [`MAX_RANGES`].
    pub(crate) fn add(&mut self, start: u32, end: u32) -> bool {
        if start >= end {
            return true;
        }
        // First range ending at or after `start` (touching counts: merge adjacent ranges).
        let i = self.ranges.partition_point(|&(_, e)| e < start);
        // Ranges [i, j) overlap or touch the new one.
        let mut j = i;
        while j < self.ranges.len() && self.ranges[j].0 <= end {
            j += 1;
        }
        if i == j {
            if self.ranges.len() >= MAX_RANGES {
                return false;
            }
            self.ranges.insert(i, (start, end));
            self.last = Some((start, end));
            return true;
        }
        let s = start.min(self.ranges[i].0);
        let e = end.max(self.ranges[j - 1].1);
        self.ranges.drain(i + 1..j);
        self.ranges[i] = (s, e);
        self.last = Some((s, e));
        true
    }

    /// The in-order point moves forward by `n` bytes (data up to there is now readable):
    /// returns how many contiguous bytes from offset 0 are available beyond `n` and rebases the
    /// ranges. Call with `n` = the length of in-order data just written at offset 0.
    pub(crate) fn advance(&mut self, n: u32) -> u32 {
        // Ranges starting at or before `n` are now contiguous with the in-order data.
        let mut extra = 0;
        let mut k = 0;
        while k < self.ranges.len() && self.ranges[k].0 <= n {
            extra = extra.max(self.ranges[k].1.saturating_sub(n));
            k += 1;
        }
        self.ranges.drain(..k);
        let shift = n + extra;
        for r in &mut self.ranges {
            r.0 -= shift;
            r.1 -= shift;
        }
        self.last = self.last.and_then(|(s, e)| {
            if e <= shift {
                None
            } else {
                Some((s.saturating_sub(shift), e - shift))
            }
        });
        extra
    }

    /// The range holding the most recent out-of-order segment, if still out of order.
    pub(crate) fn last(&self) -> Option<(u32, u32)> {
        self.last
            .filter(|&(s, e)| self.ranges.iter().any(|&(a, b)| a <= s && e <= b))
    }

    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_wraps() {
        let mut r = Ring::new(8);
        assert_eq!(r.push(b"abcdef"), 6);
        let mut out = [0u8; 4];
        assert_eq!(r.read(&mut out), 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(r.push(b"ghijklmn"), 6); // only 6 free
        let (a, b) = r.slices(0, 8);
        let all: Vec<u8> = a.iter().chain(b).copied().collect();
        assert_eq!(all, b"efghijkl");
        r.consume(3);
        let (a, b) = r.slices(1, 3);
        let s: Vec<u8> = a.iter().chain(b).copied().collect();
        assert_eq!(s, b"ijk");
        assert_eq!(r.free(), 3);
    }

    #[test]
    fn ring_write_ahead() {
        let mut r = Ring::new(10);
        r.push(b"ab");
        r.write_at(5, b"xyz"); // out of order, 3 bytes past the tail
        r.write_at(2, b"cde");
        r.commit(6);
        let mut out = [0u8; 10];
        let n = r.read(&mut out);
        assert_eq!(&out[..n], b"abcdexyz");
    }

    #[test]
    fn assembler_merges() {
        let mut a = Assembler::default();
        assert!(a.add(10, 20));
        assert!(a.add(30, 40));
        assert!(a.add(20, 30)); // bridges both
        assert_eq!(a.ranges(), &[(10, 40)]);
        assert!(a.add(50, 60));
        assert_eq!(a.last(), Some((50, 60)));
        // 10 in-order bytes arrive: [10, 40) becomes contiguous.
        assert_eq!(a.advance(10), 30);
        assert_eq!(a.ranges(), &[(10, 20)]);
        assert_eq!(a.advance(5), 0);
        assert_eq!(a.ranges(), &[(5, 15)]);
        // Overlapping range starting before 0 after rebase cannot happen; covering everything:
        assert_eq!(a.advance(20), 0);
        assert!(a.is_empty());
    }

    #[test]
    fn assembler_limit() {
        let mut a = Assembler::default();
        for i in 0..MAX_RANGES as u32 {
            assert!(a.add(i * 10 + 1, i * 10 + 2));
        }
        assert!(!a.add(1000, 1001));
        assert!(a.add(1, 3)); // merging is always possible
    }
}
