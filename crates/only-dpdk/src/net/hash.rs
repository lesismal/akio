//! The keyed hasher of the stack's per-packet tables.

use std::hash::{BuildHasher, Hasher, RandomState};

/// A keyed, fast hasher for the connection table and the neighbour caches (randomized per
/// interface so remote peers cannot aim collisions; a multiply-rotate mix per word instead of
/// SipHash, which these per-packet lookups cannot afford).
#[derive(Clone, Debug)]
pub(crate) struct KeyedHash(pub(crate) u64);

impl KeyedHash {
    /// A randomly keyed hasher.
    pub(crate) fn random() -> KeyedHash {
        KeyedHash(RandomState::new().hash_one(0x6b65_7965_645f_6831u64))
    }
}

impl BuildHasher for KeyedHash {
    type Hasher = MixHasher;
    fn build_hasher(&self) -> MixHasher {
        MixHasher(self.0)
    }
}

#[derive(Debug)]
pub(crate) struct MixHasher(u64);

impl Hasher for MixHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut c = bytes.chunks_exact(8);
        for w in &mut c {
            let mut a = [0u8; 8];
            a.copy_from_slice(w);
            self.write_u64(u64::from_le_bytes(a));
        }
        let rest = c.remainder();
        if !rest.is_empty() {
            let mut a = [0u8; 8];
            a[..rest.len()].copy_from_slice(rest);
            self.write_u64(u64::from_le_bytes(a) ^ ((rest.len() as u64) << 56));
        }
    }
    fn write_u16(&mut self, n: u16) {
        self.write_u64(u64::from(n));
    }
    fn write_u32(&mut self, n: u32) {
        self.write_u64(u64::from(n));
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0 ^ n)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(29);
    }
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
    fn finish(&self) -> u64 {
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}
