//! Bit-level reading and writing (MSB first) with Exp-Golomb codes, for codec headers.

/// Reads bits MSB first from a byte slice.
#[derive(Debug, Clone)]
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader { data, pos: 0 }
    }

    pub(crate) fn bit(&mut self) -> Option<u32> {
        let byte = *self.data.get(self.pos / 8)?;
        let b = (byte >> (7 - (self.pos % 8))) & 1;
        self.pos += 1;
        Some(u32::from(b))
    }

    pub(crate) fn flag(&mut self) -> Option<bool> {
        self.bit().map(|b| b == 1)
    }

    /// Reads `n <= 32` bits.
    pub(crate) fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Some(v)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        if self.pos + n > self.data.len() * 8 {
            return None;
        }
        self.pos += n;
        Some(())
    }

    /// Unsigned Exp-Golomb.
    pub(crate) fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        while self.bit()? == 0 {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        if zeros == 0 {
            return Some(0);
        }
        let rest = self.bits(zeros)?;
        Some(((1u64 << zeros) - 1 + u64::from(rest)).min(u64::from(u32::MAX)) as u32)
    }

    /// Signed Exp-Golomb.
    pub(crate) fn se(&mut self) -> Option<i32> {
        let k = i64::from(self.ue()?);
        let v = if k & 1 == 1 { (k + 1) / 2 } else { -(k / 2) };
        i32::try_from(v).ok()
    }

    #[allow(dead_code)]
    pub(crate) fn bits_left(&self) -> usize {
        (self.data.len() * 8).saturating_sub(self.pos)
    }
}

/// Writes bits MSB first.
#[derive(Debug, Default)]
pub(crate) struct BitWriter {
    pub(crate) out: Vec<u8>,
    n: u32,
}

impl BitWriter {
    pub(crate) fn put(&mut self, v: u32, bits: u32) {
        for i in (0..bits).rev() {
            if self.n % 8 == 0 {
                self.out.push(0);
            }
            let b = ((v >> i) & 1) as u8;
            if let Some(last) = self.out.last_mut() {
                *last |= b << (7 - (self.n % 8));
            }
            self.n += 1;
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Removes emulation prevention bytes (`00 00 03` -> `00 00`) from a NAL unit payload.
pub(crate) fn unescape_rbsp(nal: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nal.len());
    let mut zeros = 0;
    for &b in nal {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        if b == 0 {
            zeros += 1;
        } else {
            zeros = 0;
        }
        out.push(b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp_golomb() {
        // 1 | 010 | 011 | 00100 | 00101 -> 0, 1, 2, 3, 4
        let mut w = BitWriter::default();
        for (v, n) in [(1, 1), (2, 3), (3, 3), (4, 5), (5, 5)] {
            w.put(v, n);
        }
        let data = w.finish();
        let mut r = BitReader::new(&data);
        assert_eq!(r.ue(), Some(0));
        assert_eq!(r.ue(), Some(1));
        assert_eq!(r.ue(), Some(2));
        let mut r2 = BitReader::new(&data);
        r2.skip(4).unwrap();
        assert_eq!(r2.se(), Some(-1));
        assert_eq!(r2.ue(), Some(3));
        assert_eq!(r2.ue(), Some(4));
        assert!(r2.bits_left() < 8);
        assert_eq!(BitReader::new(&[0, 0, 0, 0, 0]).ue(), None);
        assert_eq!(unescape_rbsp(&[0, 0, 3, 1, 0, 0, 3]), vec![0, 0, 1, 0, 0]);
    }
}
