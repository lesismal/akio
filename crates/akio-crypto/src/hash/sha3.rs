//! SHAKE128 and SHAKE256 (FIPS 202): the Keccak-f[1600] sponge as an extendable-output
//! function. Ed448 (RFC 8032) hashes with SHAKE256.

/// The Keccak-f[1600] round constants.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets of the ρ step, in the order the π step visits the lanes.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane indices of the π step's cycle starting at lane 1.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation (24 rounds) on 25 little-endian lanes.
pub(crate) fn keccak_f(a: &mut [u64; 25]) {
    for rc in RC {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // ρ and π
        let mut last = a[1];
        for i in 0..24 {
            let j = PI[i];
            let t = a[j];
            a[j] = last.rotate_left(RHO[i]);
            last = t;
        }
        // χ
        for y in 0..5 {
            let row = [
                a[5 * y],
                a[5 * y + 1],
                a[5 * y + 2],
                a[5 * y + 3],
                a[5 * y + 4],
            ];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // ι
        a[0] ^= rc;
    }
}

/// A Keccak sponge with a rate of `RATE` bytes and the SHAKE domain padding (`0x1f`).
#[derive(Clone)]
struct Sponge<const RATE: usize> {
    state: [u64; 25],
    /// Bytes absorbed into the current block (absorbing) or squeezed from it (squeezing).
    pos: usize,
    squeezing: bool,
}

impl<const RATE: usize> Sponge<RATE> {
    const fn new() -> Self {
        Sponge {
            state: [0; 25],
            pos: 0,
            squeezing: false,
        }
    }

    fn xor_byte(&mut self, i: usize, b: u8) {
        self.state[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    fn absorb(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "SHAKE: update after the output was read");
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == RATE {
                keccak_f(&mut self.state);
                self.pos = 0;
            }
        }
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.xor_byte(self.pos, 0x1f);
            self.xor_byte(RATE - 1, 0x80);
            keccak_f(&mut self.state);
            self.squeezing = true;
            self.pos = 0;
        }
        for o in out {
            if self.pos == RATE {
                keccak_f(&mut self.state);
                self.pos = 0;
            }
            *o = (self.state[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
            self.pos += 1;
        }
    }
}

macro_rules! shake {
    ($t:ident, $rate:expr, $name:literal) => {
        #[doc = concat!($name, " (FIPS 202): absorb with [`update`](Self::update), then read any")]
        /// amount of output with [`squeeze`](Self::squeeze) (repeated calls continue the
        /// output stream; no `update` after the first `squeeze`).
        #[derive(Clone)]
        pub struct $t(Sponge<$rate>);

        impl $t {
            /// An empty state.
            #[must_use]
            pub const fn new() -> Self {
                $t(Sponge::new())
            }

            /// Absorbs `data`.
            ///
            /// # Panics
            ///
            /// After [`squeeze`](Self::squeeze).
            pub fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            /// Fills `out` with the next output bytes.
            pub fn squeeze(&mut self, out: &mut [u8]) {
                self.0.squeeze(out);
            }

            /// The first `N` output bytes for `data`.
            #[must_use]
            pub fn digest<const N: usize>(data: &[u8]) -> [u8; N] {
                let mut h = Self::new();
                h.update(data);
                let mut out = [0u8; N];
                h.squeeze(&mut out);
                out
            }
        }

        impl Default for $t {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($t)).finish_non_exhaustive()
            }
        }
    };
}

shake!(Shake128, 168, "SHAKE128");
shake!(Shake256, 136, "SHAKE256");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hex;

    #[test]
    fn empty() {
        assert_eq!(
            hex(&Shake128::digest::<32>(b"")),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        assert_eq!(
            hex(&Shake256::digest::<64>(b"")),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }

    #[test]
    fn long_and_split() {
        // 200 bytes of 0xa3 (the FIPS 202 example message), squeezed past one block.
        let msg = [0xa3u8; 200];
        let one: [u8; 300] = Shake256::digest(&msg);
        let mut h = Shake256::new();
        for c in msg.chunks(7) {
            h.update(c);
        }
        let mut two = [0u8; 300];
        let (a, b) = two.split_at_mut(13);
        h.squeeze(a);
        h.squeeze(b);
        assert_eq!(one, two);
        assert_eq!(
            hex(&one[..32]),
            "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"
        );
        let s128: [u8; 32] = Shake128::digest(&msg);
        assert_eq!(
            hex(&s128),
            "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037"
        );
    }
}
