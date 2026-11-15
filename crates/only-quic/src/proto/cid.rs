//! Connection IDs (RFC 9000 section 5.1) and stateless reset tokens (section 10.3).

use std::fmt;

use only_crypto::hash::Sha256;
use only_crypto::mac::Hmac;
use only_crypto::rand::ChaChaRng;

/// The longest connection ID QUIC v1 allows.
pub const MAX_CID_LEN: usize = 20;

/// The length of the connection IDs this implementation issues.
pub const LOCAL_CID_LEN: usize = 8;

/// A connection ID of 0 to 20 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; MAX_CID_LEN],
}

impl ConnectionId {
    /// `None` if longer than 20 bytes.
    pub fn new(b: &[u8]) -> Option<ConnectionId> {
        if b.len() > MAX_CID_LEN {
            return None;
        }
        let mut bytes = [0u8; MAX_CID_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Some(ConnectionId {
            len: b.len() as u8,
            bytes,
        })
    }

    pub fn random(rng: &mut ChaChaRng, len: usize) -> ConnectionId {
        let mut bytes = [0u8; MAX_CID_LEN];
        rng.fill(&mut bytes[..len]);
        ConnectionId {
            len: len as u8,
            bytes,
        }
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Hashes the length and the used bytes only (two words for an 8-byte ID instead of all 20).
impl std::hash::Hash for ConnectionId {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        h.write_u8(self.len);
        h.write(self);
    }
}

impl std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.iter() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A stateless reset token.
pub type ResetToken = [u8; 16];

/// Derives the stateless reset token of `cid` from the endpoint's secret key, so a restarted
/// endpoint with the same key (or any endpoint instance) can produce it without state.
pub fn reset_token(key: &[u8; 32], cid: &[u8]) -> ResetToken {
    let mac = Hmac::<Sha256>::mac(key, cid);
    let mut t = [0u8; 16];
    t.copy_from_slice(&mac[..16]);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_tokens() {
        let c = ConnectionId::new(&[1, 2, 3]).unwrap();
        assert_eq!(&c[..], &[1, 2, 3]);
        assert_eq!(format!("{c:?}"), "010203");
        assert!(ConnectionId::new(&[0; 21]).is_none());
        assert!(ConnectionId::default().is_empty());
        let mut rng = ChaChaRng::from_seed([7; 32]);
        let a = ConnectionId::random(&mut rng, 8);
        let b = ConnectionId::random(&mut rng, 8);
        assert_ne!(a, b);
        assert_eq!(a.len(), 8);
        let k = [3u8; 32];
        assert_eq!(reset_token(&k, &a), reset_token(&k, &a));
        assert_ne!(reset_token(&k, &a), reset_token(&k, &b));
    }
}
