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

pub(crate) use cid::ConnectionId;
pub(crate) use conn::{ClientToken, ConnConfig, Connection, EndpointEvent, Event, Transmit};
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

/// Tables keyed by peer-chosen values (connection IDs, addresses), hashed with the keyed
/// folded multiply of `akio_core::hash` instead of SipHash (see [`KeyedHash`] for the HashDoS
/// argument).
pub(crate) use akio_core::hash::{KeyedHash, KeyedMap, KeyedSet};

/// A [`KeyedHash`] keyed from `rng` (each routing table draws its own key).
pub(crate) fn keyed_from_rng(rng: &mut akio_crypto::rand::ChaChaRng) -> KeyedHash {
    KeyedHash::from_keys(rng.next_u64(), rng.next_u64(), rng.next_u64())
}

#[cfg(test)]
mod keyed_tests {
    use super::*;
    use std::hash::BuildHasher;

    #[test]
    fn keyed_hash() {
        let mut rng = akio_crypto::rand::ChaChaRng::from_seed([7; 32]);
        let (a, b) = (keyed_from_rng(&mut rng), keyed_from_rng(&mut rng));
        let cid = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        // Deterministic per key, different across keys.
        assert_eq!(a.hash_one(cid), a.hash_one(cid));
        assert_ne!(a.hash_one(cid), b.hash_one(cid));
        // The length takes part: a zero-padded prefix is another key.
        let short = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
        let padded = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 0]).unwrap();
        assert_ne!(a.hash_one(short), a.hash_one(padded));
        // Sequential IDs spread over the low bits (the bucket index).
        let mut seen = std::collections::HashSet::new();
        for i in 0u64..4096 {
            let c = ConnectionId::new(&i.to_be_bytes()).unwrap();
            seen.insert(a.hash_one(c) & 0xfff);
        }
        assert!(seen.len() > 2400, "{}", seen.len());
        let d = KeyedHash::default();
        let addr: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert_eq!(d.hash_one(addr), d.hash_one(addr));
        let mut m: KeyedMap<ConnectionId, u32> = KeyedMap::with_hasher(a);
        m.insert(cid, 1);
        assert_eq!(m.get(&cid), Some(&1));
        assert_eq!(m.get(&short), None);
    }
}
