//! Keyed hashing for tables whose keys a peer chooses (backend-facing, `#[doc(hidden)]`).

/// A map whose keys a peer chooses or influences: QUIC connection IDs (akio-quic's routing
/// tables) and peer addresses (the UDP loops' peer tables, akio-quic's sockets). Hashed by
/// [`KeyedHash`] instead of SipHash, which was ~2% of a receiving thread.
pub type KeyedMap<K, V> = std::collections::HashMap<K, V, KeyedHash>;
/// A set hashed by [`KeyedHash`].
pub type KeyedSet<K> = std::collections::HashSet<K, KeyedHash>;

/// A `BuildHasher` keyed with three random words per table, hashing a word at a time with a
/// folded 64×64→128-bit multiply and a keyed final fold (the construction of foldhash and
/// aHash's fallback).
///
/// HashDoS: a client picks the destination connection ID of its first Initial, which keys the
/// endpoint's `initial` table, and lookups take any connection ID or address an attacker
/// sends. With an unkeyed (or process-wide, guessable) hash it could precompute IDs that share
/// a bucket and turn each insert and lookup into a long probe. Here every table draws its own
/// key from the OS-seeded generator, the key enters both operands of every multiply, and hash
/// values never leave the process, so colliding inputs cannot be found offline and timing
/// probes against one table say nothing about another or about a later run. This is not a PRF
/// like SipHash, but it is the same keyed-multiply defence `std`'s alternatives use, at a
/// fraction of the cost. The tables are bounded besides: routes hold connection IDs we issue
/// ourselves (random, never peer-chosen), and `initial` gains an entry only for a full-size
/// Initial, with Retry above `RETRY_THRESHOLD` handshakes.
#[derive(Clone, Copy, Debug)]
pub struct KeyedHash {
    k0: u64,
    k1: u64,
    k2: u64,
}

impl KeyedHash {
    /// A hasher keyed with three random words (`k1` and `k2` are made odd).
    pub fn from_keys(k0: u64, k1: u64, k2: u64) -> KeyedHash {
        KeyedHash {
            k0,
            k1: k1 | 1,
            k2: k2 | 1,
        }
    }
}

impl Default for KeyedHash {
    /// Keyed from `std`'s per-table random state (itself seeded from the OS).
    fn default() -> KeyedHash {
        use std::hash::BuildHasher;
        let s = std::collections::hash_map::RandomState::new();
        KeyedHash {
            k0: s.hash_one(0x6b30u64),
            k1: s.hash_one(0x6b31u64) | 1,
            k2: s.hash_one(0x6b32u64) | 1,
        }
    }
}

impl std::hash::BuildHasher for KeyedHash {
    type Hasher = KeyedHasher;
    fn build_hasher(&self) -> KeyedHasher {
        KeyedHasher {
            acc: self.k0,
            k1: self.k1,
            k2: self.k2,
        }
    }
}

/// The hasher of [`KeyedHash`].
#[derive(Debug)]
pub struct KeyedHasher {
    acc: u64,
    k1: u64,
    k2: u64,
}

/// The high and low halves of `a × b` folded together.
#[inline]
fn folded_mul(a: u64, b: u64) -> u64 {
    let p = u128::from(a) * u128::from(b);
    (p as u64) ^ ((p >> 64) as u64)
}

impl std::hash::Hasher for KeyedHasher {
    #[inline]
    /// One more fold, with its own key: a word whose changes are all in its high bits would
    /// otherwise reach the low bits (the bucket index) only through the carry.
    fn finish(&self) -> u64 {
        folded_mul(self.acc, self.k2)
    }
    /// Eight bytes at a time; a short tail is zero-padded (the `Hash` impls that call this
    /// write a length first, so padding cannot make two keys equal).
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            let mut w = [0u8; 8];
            w.copy_from_slice(c);
            self.write_u64(u64::from_le_bytes(w));
        }
        let tail = chunks.remainder();
        if !tail.is_empty() {
            let mut w = [0u8; 8];
            w[..tail.len()].copy_from_slice(tail);
            self.write_u64(u64::from_le_bytes(w));
        }
    }
    #[inline]
    fn write_u8(&mut self, n: u8) {
        self.write_u64(u64::from(n));
    }
    #[inline]
    fn write_u16(&mut self, n: u16) {
        self.write_u64(u64::from(n));
    }
    #[inline]
    fn write_u32(&mut self, n: u32) {
        self.write_u64(u64::from(n));
    }
    #[inline]
    fn write_u64(&mut self, n: u64) {
        self.acc = folded_mul(self.acc ^ n, self.k1);
    }
    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::BuildHasher;

    #[test]
    fn keyed_hash() {
        let (a, b) = (KeyedHash::from_keys(1, 2, 3), KeyedHash::from_keys(4, 5, 6));
        let addr: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");
        // Deterministic per key, different across keys.
        assert_eq!(a.hash_one(addr), a.hash_one(addr));
        assert_ne!(a.hash_one(addr), b.hash_one(addr));
        // The length takes part: a zero-padded prefix is another key.
        assert_ne!(
            a.hash_one(&[1u8, 2, 3][..]),
            a.hash_one(&[1u8, 2, 3, 0][..])
        );
        // Sequential ports spread over the low bits (the bucket index).
        let mut seen = std::collections::HashSet::new();
        for p in 0u16..4096 {
            let s = std::net::SocketAddr::from(([10, 0, 0, 1], p));
            seen.insert(a.hash_one(s) & 0xfff);
        }
        assert!(seen.len() > 2400, "{}", seen.len());
        let d = KeyedHash::default();
        assert_eq!(d.hash_one(addr), d.hash_one(addr));
        assert_ne!(d.hash_one(addr), KeyedHash::default().hash_one(addr));
        let mut m: KeyedMap<std::net::SocketAddr, u32> = KeyedMap::default();
        m.insert(addr, 1);
        assert_eq!(m.get(&addr), Some(&1));
    }
}
