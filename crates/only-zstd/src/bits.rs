//! Bit streams: the backward reader of the decoder (Huffman and FSE streams are read from their
//! last byte towards their first) and the forward writer of the encoder.

/// Reads a stream backwards, the way libzstd's `BIT_DStream_t` does: a 64-bit container holding
/// the 8 bytes at `ptr`, of which the top `consumed` bits are used. Bits before the start of the
/// stream read as zeros; reading past them is detected by [`BackReader::overflowed`] and
/// [`BackReader::finished`].
pub(crate) struct BackReader<'a> {
    data: &'a [u8],
    ptr: usize,
    container: u64,
    consumed: u32,
}

impl<'a> BackReader<'a> {
    /// Starts at the end mark (the highest set bit of the last byte). `None` when the stream is
    /// empty or its last byte is zero.
    pub(crate) fn new(data: &'a [u8]) -> Option<Self> {
        let &last = data.last()?;
        if last == 0 {
            return None;
        }
        let mark = 8 - (31 - u32::from(last).leading_zeros());
        Some(if data.len() >= 8 {
            let ptr = data.len() - 8;
            BackReader {
                data,
                ptr,
                container: Self::load(data, ptr),
                consumed: mark,
            }
        } else {
            let mut b = [0u8; 8];
            b[..data.len()].copy_from_slice(data);
            BackReader {
                data,
                ptr: 0,
                container: u64::from_le_bytes(b),
                consumed: mark + (8 - data.len() as u32) * 8,
            }
        })
    }

    #[inline]
    fn load(data: &[u8], ptr: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[ptr..ptr + 8]);
        u64::from_le_bytes(b)
    }

    /// The next `n` bits (1..=57 after a reload) without consuming them.
    #[inline]
    pub(crate) fn peek(&self, n: u32) -> u64 {
        if self.consumed >= 64 || n == 0 {
            return 0;
        }
        (self.container << self.consumed) >> (64 - n)
    }

    #[inline]
    pub(crate) fn consume(&mut self, n: u32) {
        self.consumed += n;
    }

    /// Reads `n` bits (0..=57 after a reload).
    #[inline]
    pub(crate) fn read(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        let v = self.peek(n);
        self.consumed += n;
        v
    }

    /// Refills the container so that at least 57 bits are available, or all that remain.
    #[inline]
    pub(crate) fn reload(&mut self) {
        if self.consumed > 64 {
            return; // overflowed: stays so
        }
        if self.ptr >= 8 {
            self.ptr -= (self.consumed >> 3) as usize;
            self.consumed &= 7;
        } else if self.ptr > 0 {
            let n = ((self.consumed >> 3) as usize).min(self.ptr);
            self.ptr -= n;
            self.consumed -= n as u32 * 8;
        } else {
            return;
        }
        self.container = Self::load(self.data, self.ptr);
    }

    /// More bits were read than the stream holds. Exact only right after a reload or when the
    /// reads since the last reload stayed within 57 bits.
    #[inline]
    pub(crate) fn overflowed(&self) -> bool {
        self.consumed > 64
    }

    /// Every bit of the stream was read, and no more.
    #[inline]
    pub(crate) fn finished(&self) -> bool {
        self.ptr == 0 && self.consumed == 64
    }
}

/// Writes bits forwards, least significant first (libzstd's `BIT_CStream_t`).
pub(crate) struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    acc: u64,
    n: u32,
}

impl<'a> BitWriter<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        BitWriter { out, acc: 0, n: 0 }
    }

    /// Appends the low `bits` bits of `v` (`bits` ≤ 32).
    #[inline]
    pub(crate) fn put(&mut self, v: u64, bits: u32) {
        debug_assert!(bits <= 32);
        if bits == 0 {
            return;
        }
        self.acc |= (v & ((1u64 << bits) - 1)) << self.n;
        self.n += bits;
        if self.n >= 32 {
            self.out.extend_from_slice(&(self.acc as u32).to_le_bytes());
            self.acc >>= 32;
            self.n -= 32;
        }
    }

    /// Writes what is left, padding the last byte with zeros.
    pub(crate) fn flush(self) {
        let bytes = self.n.div_ceil(8) as usize;
        self.out.extend_from_slice(&self.acc.to_le_bytes()[..bytes]);
    }

    /// Ends a backward-read stream: the end mark (a 1 bit), then the padding.
    pub(crate) fn close(mut self) {
        self.put(1, 1);
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_backwards() {
        let mut out = Vec::new();
        let mut w = BitWriter::new(&mut out);
        let fields: Vec<(u64, u32)> = (0..200u64)
            .map(|i| (i * 7919 % 1000, 10 + (i % 7) as u32))
            .collect();
        for &(v, n) in &fields {
            w.put(v, n);
        }
        w.close();
        let mut r = BackReader::new(&out).unwrap();
        for &(v, n) in fields.iter().rev() {
            r.reload();
            assert_eq!(r.read(n), v & ((1 << n) - 1));
        }
        r.reload();
        assert!(r.finished());
        assert!(BackReader::new(&[]).is_none());
        assert!(BackReader::new(&[1, 0]).is_none());
        // One byte holding only the end mark: an empty stream.
        let r = BackReader::new(&[1]).unwrap();
        assert!(r.finished());
        let mut r = BackReader::new(&[0b11]).unwrap();
        assert_eq!(r.read(1), 1);
        assert!(r.finished());
        r.read(1);
        assert!(r.overflowed() && !r.finished());
    }
}
