//! The QUIC v1 protocol core (RFC 9000, 9001, 9002, 9221), sans-io: no sockets, no threads, no
//! clocks of its own. The I/O layer (`crate::Ep` and friends) feeds it datagrams and the time,
//! and sends what it produces.
#![allow(unreachable_pub)]

pub(crate) mod bbr;
pub(crate) mod cid;
pub(crate) mod coding;
pub(crate) mod conn;
pub(crate) mod crypto;
pub(crate) mod endpoint;
pub(crate) mod frame;
pub(crate) mod packet;
pub(crate) mod params;
pub(crate) mod ranges;
pub(crate) mod recovery;
pub(crate) mod stream;

#[cfg(test)]
mod sim;

pub(crate) use conn::{ConnConfig, Connection, EndpointEvent, Event, Transmit};
pub(crate) use endpoint::{ConnHandle, DatagramEvent, Endpoint, ServerSetup};

/// A map keyed by stream ID (or another `u64` the peer only partly chooses: stream IDs are
/// bounded by the stream limits we grant), hashed by a multiply-rotate with a per-process
/// random key instead of SipHash, which showed up in bulk transfer profiles.
pub(crate) type IdMap<V> = std::collections::HashMap<u64, V, IdHash>;
/// A set of stream IDs (see [`IdMap`]).
pub(crate) type IdSet = std::collections::HashSet<u64, IdHash>;

/// The `BuildHasher` of [`IdMap`] and [`IdSet`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct IdHash(u64);

impl Default for IdHash {
    fn default() -> IdHash {
        use std::hash::BuildHasher;
        static KEY: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        IdHash(
            *KEY.get_or_init(|| std::collections::hash_map::RandomState::new().hash_one(0u64) | 1),
        )
    }
}

impl std::hash::BuildHasher for IdHash {
    type Hasher = IdHasher;
    fn build_hasher(&self) -> IdHasher {
        IdHasher(self.0, 0)
    }
}

/// The hasher of [`IdHash`] (meant for single `u64` keys).
#[derive(Debug)]
pub(crate) struct IdHasher(u64, u64);

impl std::hash::Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.1
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u64(&mut self, v: u64) {
        let x = (self.1.rotate_left(5) ^ v ^ self.0).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.1 = x ^ (x >> 29);
    }
}

/// A map whose keys a peer chooses or influences: connection IDs (the endpoint's routing
/// tables) and peer addresses. Hashed by [`KeyedHash`] instead of SipHash, which was ~2% of a
/// receiving thread.
pub(crate) type KeyedMap<K, V> = std::collections::HashMap<K, V, KeyedHash>;
/// A set hashed by [`KeyedHash`].
pub(crate) type KeyedSet<K> = std::collections::HashSet<K, KeyedHash>;

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
pub(crate) struct KeyedHash {
    k0: u64,
    k1: u64,
    k2: u64,
}

impl KeyedHash {
    /// A hasher keyed from `rng`.
    pub(crate) fn from_rng(rng: &mut only_crypto::rand::ChaChaRng) -> KeyedHash {
        KeyedHash {
            k0: rng.next_u64(),
            k1: rng.next_u64() | 1,
            k2: rng.next_u64() | 1,
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
pub(crate) struct KeyedHasher {
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
mod keyed_tests {
    use super::*;
    use std::hash::BuildHasher;

    #[test]
    fn keyed_hash() {
        let mut rng = only_crypto::rand::ChaChaRng::from_seed([7; 32]);
        let (a, b) = (KeyedHash::from_rng(&mut rng), KeyedHash::from_rng(&mut rng));
        let cid = cid::ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        // Deterministic per key, different across keys.
        assert_eq!(a.hash_one(cid), a.hash_one(cid));
        assert_ne!(a.hash_one(cid), b.hash_one(cid));
        // The length takes part: a zero-padded prefix is another key.
        let short = cid::ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
        let padded = cid::ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 0]).unwrap();
        assert_ne!(a.hash_one(short), a.hash_one(padded));
        // Sequential IDs spread over the low bits (the bucket index).
        let mut seen = std::collections::HashSet::new();
        for i in 0u64..4096 {
            let c = cid::ConnectionId::new(&i.to_be_bytes()).unwrap();
            seen.insert(a.hash_one(c) & 0xfff);
        }
        assert!(seen.len() > 2400, "{}", seen.len());
        let d = KeyedHash::default();
        let addr: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert_eq!(d.hash_one(addr), d.hash_one(addr));
        let mut m: KeyedMap<cid::ConnectionId, u32> = KeyedMap::with_hasher(a);
        m.insert(cid, 1);
        assert_eq!(m.get(&cid), Some(&1));
        assert_eq!(m.get(&short), None);
    }
}
