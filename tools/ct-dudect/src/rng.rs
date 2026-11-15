//! A small fast generator (xoshiro256**, seeded through SplitMix64) for the class sequence and
//! the random secrets. Statistical quality is all the test needs; the secrets are test values.

/// xoshiro256**.
#[derive(Clone, Debug)]
pub(crate) struct Rng {
    s: [u64; 4],
}

impl Rng {
    /// A generator from a 64-bit seed.
    pub(crate) fn new(seed: u64) -> Self {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Self {
            s: [next(), next(), next(), next()],
        }
    }

    /// The next 64 random bits.
    pub(crate) fn next_u64(&mut self) -> u64 {
        let r = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        r
    }

    /// Fills `buf` with random bytes.
    pub(crate) fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    /// `N` random bytes.
    pub(crate) fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }

    /// A random class, 0 or 1.
    pub(crate) fn class(&mut self) -> u8 {
        u8::from(self.next_u64() >> 63 == 1)
    }
}
