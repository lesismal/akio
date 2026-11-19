//! Bit input and output, least significant bit first (RFC 7932 section 2).

/// Reads bits from a byte slice, 64 bits of look-ahead at a time.
///
/// Past the end of the input it supplies zero bits and counts them; [`BitReader::overrun`]
/// tells whether any of them were consumed, which the decoder checks at least once per command
/// (a truncated stream then fails with `Truncated` instead of decoding zeros for ever).
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    /// Next byte to load.
    pos: usize,
    /// Loaded, unconsumed bits (the low `nbits`); the bits above are the stream's next ones
    /// (as far as they were loaded) or zero.
    bits: u64,
    nbits: u32,
    /// Zero bits loaded past the end of the input (the top `phantom` of `nbits`, or more if
    /// some were consumed).
    phantom: u64,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            bits: 0,
            nbits: 0,
            phantom: 0,
        }
    }

    /// Makes at least 57 bits available. Without a branch on the bits left: the 8 bytes at
    /// `pos` are ORed in above the loaded bits (bits past the 64th fall off), `pos` moves on
    /// by the whole bytes that fitted. Bits above `nbits` are therefore not zero but the next
    /// bits of the stream (or zero past its end), and ORing them in again changes nothing.
    #[inline(always)]
    pub(crate) fn refill(&mut self) {
        if let Some(chunk) = self.data.get(self.pos..self.pos + 8) {
            let v = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            self.bits |= v << self.nbits;
            self.pos += ((63 - self.nbits) >> 3) as usize;
            self.nbits |= 56;
        } else {
            self.refill_slow();
        }
    }

    #[cold]
    fn refill_slow(&mut self) {
        while self.nbits <= 56 {
            if let Some(&b) = self.data.get(self.pos) {
                self.bits |= u64::from(b) << self.nbits;
                self.pos += 1;
            } else {
                self.phantom = self.phantom.saturating_add(8);
            }
            self.nbits += 8;
        }
    }

    /// The next 64 bits (only the low `nbits` are meaningful: mask what is used); call
    /// [`BitReader::refill`] first.
    #[inline(always)]
    pub(crate) fn peek(&self) -> u64 {
        self.bits
    }

    /// Drops `n` bits (at most the available ones; call [`BitReader::refill`] first).
    #[inline(always)]
    pub(crate) fn consume(&mut self, n: u32) {
        let n = n.min(self.nbits);
        self.bits >>= n;
        self.nbits -= n;
    }

    /// Drops `n` bits, which must be loaded (after [`BitReader::refill`], up to 57 bits in
    /// all before the next refill).
    #[inline(always)]
    pub(crate) fn consume_loaded(&mut self, n: u32) {
        debug_assert!(n <= self.nbits);
        self.bits >>= n;
        self.nbits -= n;
    }

    /// Reads `n` bits, `n` <= 32.
    #[inline(always)]
    pub(crate) fn read(&mut self, n: u32) -> u32 {
        self.refill();
        let v = (self.bits & ((1u64 << n) - 1)) as u32;
        self.consume(n);
        v
    }

    /// Whether bits past the end of the input have been consumed.
    #[inline(always)]
    pub(crate) fn overrun(&self) -> bool {
        self.phantom > u64::from(self.nbits)
    }

    /// Skips to the next byte boundary; returns false if a skipped bit is set.
    pub(crate) fn align(&mut self) -> bool {
        let r = self.nbits % 8;
        let ok = self.bits & ((1u64 << r) - 1) == 0;
        self.consume(r);
        ok
    }

    /// The position of the next unread byte, after [`BitReader::align`]; `None` if bits past
    /// the end were consumed.
    pub(crate) fn byte_pos(&self) -> Option<usize> {
        let real = u64::from(self.nbits).checked_sub(self.phantom)?;
        Some(self.pos - (real / 8) as usize)
    }

    /// Takes the next `n` whole bytes, after [`BitReader::align`]; `None` if the input ends
    /// first.
    pub(crate) fn take_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let p = self.byte_pos()?;
        let s = self.data.get(p..p.checked_add(n)?)?;
        self.pos = p + n;
        self.bits = 0;
        self.nbits = 0;
        self.phantom = 0;
        Some(s)
    }
}

/// Writes bits into a byte vector.
pub(crate) struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

/// A position of a [`BitWriter`] to roll back to.
#[derive(Clone, Copy)]
pub(crate) struct Mark(usize, u64, u32);

impl BitWriter {
    pub(crate) fn with_capacity(n: usize) -> Self {
        BitWriter {
            out: Vec::with_capacity(n),
            acc: 0,
            n: 0,
        }
    }

    /// Writes the low `n` bits of `v`, `n` <= 32.
    #[inline(always)]
    pub(crate) fn bits(&mut self, n: u32, v: u64) {
        debug_assert!(n <= 32 && (n == 32 || v >> n == 0));
        self.acc |= v << self.n;
        self.n += n;
        if self.n >= 32 {
            self.out.extend_from_slice(&(self.acc as u32).to_le_bytes());
            self.acc >>= 32;
            self.n -= 32;
        }
    }

    /// The number of bits written so far.
    pub(crate) fn bit_len(&self) -> usize {
        self.out.len() * 8 + self.n as usize
    }

    /// Pads with zero bits to a byte boundary.
    pub(crate) fn align(&mut self) {
        while self.n > 0 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n = self.n.saturating_sub(8);
        }
        self.acc = 0;
    }

    /// Writes whole bytes; call [`BitWriter::align`] first.
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.align();
        self.out.extend_from_slice(b);
    }

    pub(crate) fn mark(&self) -> Mark {
        Mark(self.out.len(), self.acc, self.n)
    }

    pub(crate) fn rollback(&mut self, m: Mark) {
        self.out.truncate(m.0);
        self.acc = m.1;
        self.n = m.2;
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.align();
        self.out
    }
}
