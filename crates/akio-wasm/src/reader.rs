//! A cursor over a module's bytes: LEB128 integers, floats, names, with the specification's
//! checks (no overlong integers, no unused bits set, UTF-8 names).

use crate::error::{Result, malformed};

#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Offset of `data[0]` in the module, for errors.
    base: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8], base: usize) -> Self {
        Self { data, pos: 0, base }
    }

    /// Offset of the next byte in the module.
    pub(crate) const fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// All the bytes this reader covers, read or not.
    pub(crate) const fn data(&self) -> &'a [u8] {
        self.data
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| malformed(self.offset(), "unexpected end"))?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(malformed(self.offset(), "unexpected end"));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// A sub-reader over the next `n` bytes (a section or a function body).
    pub(crate) fn sub(&mut self, n: usize) -> Result<Self> {
        let base = self.offset();
        if n > self.remaining() {
            // The specification's wording for a section or body running past its container.
            return Err(malformed(base, "unexpected end of section or function"));
        }
        Ok(Self::new(self.bytes(n)?, base))
    }

    /// An unsigned LEB128 integer of at most `bits` bits.
    fn uleb(&mut self, bits: u32) -> Result<u64> {
        let start = self.offset();
        let max_bytes = bits.div_ceil(7);
        let mut result = 0u64;
        let mut shift = 0u32;
        for i in 0..max_bytes {
            let b = self.u8()?;
            let low = u64::from(b & 0x7f);
            if i == max_bytes - 1 {
                // The last byte: no continuation, and no bits past `bits`.
                if b & 0x80 != 0 {
                    return Err(malformed(start, "integer representation too long"));
                }
                let used = bits - shift;
                if used < 7 && low >> used != 0 {
                    return Err(malformed(start, "integer too large"));
                }
            }
            result |= low << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
        unreachable!("the last byte returns")
    }

    /// A signed LEB128 integer of at most `bits` bits.
    fn sleb(&mut self, bits: u32) -> Result<i64> {
        let start = self.offset();
        let max_bytes = bits.div_ceil(7);
        let mut result = 0i64;
        let mut shift = 0u32;
        for i in 0..max_bytes {
            let b = self.u8()?;
            let low = i64::from(b & 0x7f);
            if i == max_bytes - 1 {
                if b & 0x80 != 0 {
                    return Err(malformed(start, "integer representation too long"));
                }
                // The bits past `bits`, sign bit included, must all equal the sign bit.
                let used = bits - shift; // bits of the value this byte carries, 1..=7
                if used < 7 {
                    let sign_and_rest = (b & 0x7f) >> (used - 1);
                    let all = (1u8 << (8 - used)) - 1;
                    if sign_and_rest != 0 && sign_and_rest != all {
                        return Err(malformed(start, "integer too large"));
                    }
                }
            }
            result |= low << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
        }
        unreachable!("the last byte returns")
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        // At most 32 bits by construction.
        self.uleb(32).map(|v| v as u32)
    }

    pub(crate) fn s32(&mut self) -> Result<i32> {
        self.sleb(32).map(|v| v as i32)
    }

    pub(crate) fn s33(&mut self) -> Result<i64> {
        self.sleb(33)
    }

    pub(crate) fn s64(&mut self) -> Result<i64> {
        self.sleb(64)
    }

    pub(crate) fn f32_bits(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn f64_bits(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A length-prefixed UTF-8 name.
    pub(crate) fn name(&mut self) -> Result<&'a str> {
        let n = self.u32()? as usize;
        let at = self.offset();
        let b = self.bytes(n)?;
        std::str::from_utf8(b).map_err(|_| malformed(at, "malformed UTF-8 encoding"))
    }

    /// A vector's length, refused if it cannot fit in what is left (each element takes at least
    /// `min_size` bytes), so nothing is allocated for a count the bytes cannot hold.
    pub(crate) fn count(&mut self, min_size: usize) -> Result<u32> {
        let at = self.offset();
        let n = self.u32()?;
        if (n as usize).saturating_mul(min_size) > self.remaining() {
            return Err(malformed(at, "unexpected end"));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;

    fn u32_of(b: &[u8]) -> Result<u32, &'static str> {
        Reader::new(b, 0).u32().map_err(|e| e.message())
    }

    fn s32_of(b: &[u8]) -> Result<i32, &'static str> {
        Reader::new(b, 0).s32().map_err(|e| e.message())
    }

    fn s64_of(b: &[u8]) -> Result<i64, &'static str> {
        Reader::new(b, 0).s64().map_err(|e| e.message())
    }

    #[test]
    fn unsigned() {
        assert_eq!(u32_of(&[0]), Ok(0));
        assert_eq!(u32_of(&[0x80, 0]), Ok(0));
        assert_eq!(u32_of(&[0xe5, 0x8e, 0x26]), Ok(624_485));
        assert_eq!(u32_of(&[0xff, 0xff, 0xff, 0xff, 0x0f]), Ok(u32::MAX));
        assert_eq!(
            u32_of(&[0xff, 0xff, 0xff, 0xff, 0x1f]),
            Err("integer too large")
        );
        assert_eq!(
            u32_of(&[0x80, 0x80, 0x80, 0x80, 0x80, 0]),
            Err("integer representation too long")
        );
        assert_eq!(u32_of(&[0x80]), Err("unexpected end"));
    }

    #[test]
    fn signed() {
        assert_eq!(s32_of(&[0x7f]), Ok(-1));
        assert_eq!(s32_of(&[0x3f]), Ok(63));
        assert_eq!(s32_of(&[0xc0, 0x00]), Ok(64));
        assert_eq!(s32_of(&[0x80, 0x80, 0x80, 0x80, 0x78]), Ok(i32::MIN));
        assert_eq!(s32_of(&[0xff, 0xff, 0xff, 0xff, 0x07]), Ok(i32::MAX));
        assert_eq!(
            s32_of(&[0xff, 0xff, 0xff, 0xff, 0x0f]),
            Err("integer too large")
        );
        assert_eq!(
            s32_of(&[0x80, 0x80, 0x80, 0x80, 0x70]),
            Err("integer too large")
        );
        assert_eq!(s32_of(&[0xff, 0xff, 0xff, 0xff, 0x7f]), Ok(-1));
        assert_eq!(
            s64_of(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f]),
            Ok(i64::MIN)
        );
        assert_eq!(
            s64_of(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]),
            Ok(i64::MAX)
        );
        assert_eq!(
            s64_of(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
            Err("integer too large")
        );
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0).s33(),
            Ok(0xffff_ffff)
        );
    }
}
