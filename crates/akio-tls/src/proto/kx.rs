//! Key exchange groups (RFC 8446 section 4.2.7, RFC 8422) and ephemeral key shares.

use akio_crypto::{p256, p384, p521, x448, x25519};

use super::alert::{Alert, Fatal};

/// A named group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// X25519.
    X25519,
    /// secp256r1 (P-256).
    Secp256r1,
    /// secp384r1 (P-384).
    Secp384r1,
    /// X448 (RFC 7748; offered after the 256- and 384-bit groups by default).
    X448,
    /// secp521r1 (P-521; offered last by default, ADR-049).
    Secp521r1,
}

impl Group {
    /// The IANA code.
    pub fn id(self) -> u16 {
        match self {
            Group::X25519 => 0x001d,
            Group::Secp256r1 => 0x0017,
            Group::Secp384r1 => 0x0018,
            Group::X448 => 0x001e,
            Group::Secp521r1 => 0x0019,
        }
    }

    /// From the IANA code.
    pub fn from_id(id: u16) -> Option<Group> {
        match id {
            0x001d => Some(Group::X25519),
            0x0017 => Some(Group::Secp256r1),
            0x0018 => Some(Group::Secp384r1),
            0x001e => Some(Group::X448),
            0x0019 => Some(Group::Secp521r1),
            _ => None,
        }
    }

    /// Generates an ephemeral key pair.
    pub(crate) fn generate(self) -> Result<KeyShare, Fatal> {
        let err = |_| Fatal::new(Alert::InternalError, "no randomness for a key share");
        Ok(match self {
            Group::X25519 => KeyShare::X25519(x25519::PrivateKey::generate().map_err(err)?),
            Group::Secp256r1 => KeyShare::P256(p256::SecretKey::generate().map_err(err)?),
            Group::Secp384r1 => KeyShare::P384(p384::SecretKey::generate().map_err(err)?),
            Group::X448 => KeyShare::X448(x448::PrivateKey::generate().map_err(err)?),
            Group::Secp521r1 => KeyShare::P521(p521::SecretKey::generate().map_err(err)?),
        })
    }
}

/// Default groups, in preference order.
pub(crate) const DEFAULT_GROUPS: &[Group] = &[
    Group::X25519,
    Group::Secp256r1,
    Group::Secp384r1,
    Group::X448,
    Group::Secp521r1,
];

/// An ephemeral private key.
pub(crate) enum KeyShare {
    X25519(x25519::PrivateKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    X448(x448::PrivateKey),
    P521(p521::SecretKey),
}

impl KeyShare {
    pub(crate) fn group(&self) -> Group {
        match self {
            KeyShare::X25519(_) => Group::X25519,
            KeyShare::P256(_) => Group::Secp256r1,
            KeyShare::P384(_) => Group::Secp384r1,
            KeyShare::X448(_) => Group::X448,
            KeyShare::P521(_) => Group::Secp521r1,
        }
    }

    /// The public value as sent on the wire (raw X25519 / X448, uncompressed SEC1 points).
    pub(crate) fn public(&self) -> Vec<u8> {
        match self {
            KeyShare::X25519(k) => k.public_key().to_vec(),
            KeyShare::P256(k) => k.public_key().to_uncompressed(),
            KeyShare::P384(k) => k.public_key().to_uncompressed(),
            KeyShare::X448(k) => k.public_key().to_vec(),
            KeyShare::P521(k) => k.public_key().to_uncompressed(),
        }
    }

    /// The shared secret with the peer's public value; a malformed or invalid value is an
    /// `illegal_parameter`.
    pub(crate) fn agree(&self, peer: &[u8]) -> Result<Vec<u8>, Fatal> {
        let bad = || Fatal::new(Alert::IllegalParameter, "invalid key share");
        match self {
            KeyShare::X25519(k) => {
                let p: [u8; 32] = peer.try_into().map_err(|_| bad())?;
                k.diffie_hellman(&p).map(|s| s.to_vec()).map_err(|_| bad())
            }
            KeyShare::P256(k) => {
                if peer.len() != 65 || peer[0] != 4 {
                    return Err(bad());
                }
                let p = p256::PublicKey::from_sec1(peer).map_err(|_| bad())?;
                Ok(k.diffie_hellman(&p).to_vec())
            }
            KeyShare::P384(k) => {
                if peer.len() != 97 || peer[0] != 4 {
                    return Err(bad());
                }
                let p = p384::PublicKey::from_sec1(peer).map_err(|_| bad())?;
                Ok(k.diffie_hellman(&p).to_vec())
            }
            KeyShare::X448(k) => {
                let p: [u8; 56] = peer.try_into().map_err(|_| bad())?;
                k.diffie_hellman(&p).map(|s| s.to_vec()).map_err(|_| bad())
            }
            KeyShare::P521(k) => {
                if peer.len() != 133 || peer[0] != 4 {
                    return Err(bad());
                }
                let p = p521::PublicKey::from_sec1(peer).map_err(|_| bad())?;
                Ok(k.diffie_hellman(&p).to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreement() {
        for g in DEFAULT_GROUPS {
            assert_eq!(Group::from_id(g.id()), Some(*g));
            let a = g.generate().unwrap();
            let b = g.generate().unwrap();
            assert_eq!(a.group(), *g);
            assert_eq!(a.agree(&b.public()).unwrap(), b.agree(&a.public()).unwrap());
            assert!(a.agree(&[]).is_err());
            let mut bad = b.public();
            bad[0] ^= 0xff;
            if !matches!(*g, Group::X25519 | Group::X448) {
                assert!(a.agree(&bad).is_err());
            }
        }
        // The all-zero X25519 point gives a zero shared secret: refused.
        let a = Group::X25519.generate().unwrap();
        assert!(a.agree(&[0; 32]).is_err());
        let a = Group::X448.generate().unwrap();
        assert!(a.agree(&[0; 56]).is_err());
        assert!(a.agree(&[0; 32]).is_err());
        assert!(Group::from_id(0x001a).is_none());
        // A compressed P-521 point is refused (TLS 1.3 key shares are uncompressed).
        let a = Group::Secp521r1.generate().unwrap();
        let b = p521::SecretKey::generate().unwrap().public_key();
        assert!(a.agree(&b.to_compressed()).is_err());
        assert_eq!(a.agree(&b.to_uncompressed()).unwrap().len(), 66);
    }
}
