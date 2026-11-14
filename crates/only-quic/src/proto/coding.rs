//! Wire coding: variable-length integers (RFC 9000 section 16) and a bounds-checked reader.

/// The largest value a variable-length integer holds.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Bytes `v` takes as a variable-length integer.
pub fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Appends `v` (clamped to [`VARINT_MAX`]) as a variable-length integer.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    let v = v.min(VARINT_MAX);
    match varint_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Writes `v` as a 2-byte variable-length integer at `at` (`v` < 16384).
pub fn patch_varint2(buf: &mut [u8], at: usize, v: usize) {
    debug_assert!(v < 1 << 14);
    let b = ((v as u16) | 0x4000).to_be_bytes();
    buf[at] = b[0];
    buf[at + 1] = b[1];
}

/// A cursor over received bytes; every read is bounds-checked and returns `None` past the end.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Some(a)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos.min(self.buf.len())..];
        self.pos = self.buf.len();
        s
    }

    pub fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut v = u64::from(first & 0x3f);
        for _ in 1..len {
            v = (v << 8) | u64::from(self.u8()?);
        }
        Some(v)
    }

    /// A varint-length-prefixed byte string.
    pub fn vbytes(&mut self) -> Option<&'a [u8]> {
        let n = self.varint()?;
        self.bytes(usize::try_from(n).ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip() {
        // RFC 9000 Appendix A.1 examples.
        let cases: [(&[u8], u64); 4] = [
            (&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c], 151_288_809_941_952_652),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (wire, v) in cases {
            assert_eq!(Reader::new(wire).varint(), Some(v));
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out, wire);
            assert_eq!(varint_len(v), wire.len());
        }
        // A two-byte encoding of 37 still decodes.
        assert_eq!(Reader::new(&[0x40, 0x25]).varint(), Some(37));
        assert_eq!(Reader::new(&[0x40]).varint(), None);
        let mut out = Vec::new();
        put_varint(&mut out, u64::MAX);
        assert_eq!(Reader::new(&out).varint(), Some(VARINT_MAX));
        let mut b = [0u8; 3];
        patch_varint2(&mut b, 1, 300);
        assert_eq!(Reader::new(&b[1..]).varint(), Some(300));
    }

    #[test]
    fn reader_bounds() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.peek(), Some(2));
        assert_eq!(r.u16(), Some(0x0203));
        assert_eq!(r.array::<2>(), Some([4, 5]));
        assert_eq!(r.u32(), None);
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.pos(), 5);
        assert_eq!(r.rest(), &[6, 7]);
        assert!(r.is_empty());
        assert_eq!(r.bytes(usize::MAX), None);
        assert_eq!(Reader::new(&[2, 9, 8]).vbytes(), Some(&[9, 8][..]));
        assert_eq!(Reader::new(&[3, 9]).vbytes(), None);
    }
}
