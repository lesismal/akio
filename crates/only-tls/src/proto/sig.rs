//! Signature schemes (RFC 8446 section 4.2.3): mapping to `only_crypto::pkey`, choosing one for
//! a key and verifying handshake signatures.

use only_crypto::pkey::{PrivateKey, PublicKey, SignatureAlgorithm as A};

use super::alert::{Alert, Fatal};

pub(crate) const ECDSA_P256_SHA256: u16 = 0x0403;
pub(crate) const ECDSA_P384_SHA384: u16 = 0x0503;
pub(crate) const ECDSA_P521_SHA512: u16 = 0x0603;
pub(crate) const ED25519: u16 = 0x0807;
pub(crate) const ED448: u16 = 0x0808;
pub(crate) const PSS_SHA256: u16 = 0x0804;
pub(crate) const PSS_SHA384: u16 = 0x0805;
pub(crate) const PSS_SHA512: u16 = 0x0806;
pub(crate) const PKCS1_SHA256: u16 = 0x0401;
pub(crate) const PKCS1_SHA384: u16 = 0x0501;
pub(crate) const PKCS1_SHA512: u16 = 0x0601;

/// What we offer and accept, in preference order (`signature_algorithms`). The PKCS#1 v1.5
/// schemes are for certificates and TLS 1.2 only.
pub(crate) const SUPPORTED: &[u16] = &[
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    ED448,
    PSS_SHA256,
    PSS_SHA384,
    PSS_SHA512,
    PKCS1_SHA256,
    PKCS1_SHA384,
    PKCS1_SHA512,
];

fn algorithm(scheme: u16) -> Option<A> {
    Some(match scheme {
        ECDSA_P256_SHA256 => A::EcdsaSha256,
        ECDSA_P384_SHA384 => A::EcdsaSha384,
        ECDSA_P521_SHA512 => A::EcdsaSha512,
        ED25519 => A::Ed25519,
        ED448 => A::Ed448,
        PSS_SHA256 => A::RsaPssSha256,
        PSS_SHA384 => A::RsaPssSha384,
        PSS_SHA512 => A::RsaPssSha512,
        PKCS1_SHA256 => A::RsaPkcs1Sha256,
        PKCS1_SHA384 => A::RsaPkcs1Sha384,
        PKCS1_SHA512 => A::RsaPkcs1Sha512,
        _ => return None,
    })
}

/// A key's type, as far as signature schemes care.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ed25519,
    Ed448,
    P256,
    P384,
    Rsa,
    Other,
}

fn public_kind(key: &PublicKey) -> Kind {
    match key {
        PublicKey::Ed25519(_) => Kind::Ed25519,
        PublicKey::Ed448(_) => Kind::Ed448,
        PublicKey::P256(_) => Kind::P256,
        PublicKey::P384(_) => Kind::P384,
        PublicKey::Rsa(_) => Kind::Rsa,
        _ => Kind::Other,
    }
}

/// Without deriving the public key (a scalar multiplication for the curves).
fn private_kind(key: &PrivateKey) -> Kind {
    match key {
        PrivateKey::Ed25519(_) => Kind::Ed25519,
        PrivateKey::Ed448(_) => Kind::Ed448,
        PrivateKey::P256(_) => Kind::P256,
        PrivateKey::P384(_) => Kind::P384,
        PrivateKey::Rsa(_) => Kind::Rsa,
        _ => Kind::Other,
    }
}

/// Whether a private key is RSA (TLS 1.2 suite selection).
pub(crate) fn is_rsa(key: &PrivateKey) -> bool {
    private_kind(key) == Kind::Rsa
}

/// Whether `scheme` fits a key of `kind` (in TLS 1.3 the ECDSA curve is part of the scheme).
fn fits(scheme: u16, kind: Kind, tls13: bool) -> bool {
    match kind {
        Kind::Ed25519 => scheme == ED25519,
        Kind::Ed448 => scheme == ED448,
        Kind::P256 => scheme == ECDSA_P256_SHA256 || (!tls13 && scheme == ECDSA_P384_SHA384),
        Kind::P384 => scheme == ECDSA_P384_SHA384 || (!tls13 && scheme == ECDSA_P256_SHA256),
        Kind::Rsa => {
            matches!(scheme, PSS_SHA256 | PSS_SHA384 | PSS_SHA512)
                || (!tls13 && matches!(scheme, PKCS1_SHA256 | PKCS1_SHA384 | PKCS1_SHA512))
        }
        Kind::Other => false,
    }
}

/// The scheme to sign with `key`, among those the peer `offered`.
pub(crate) fn choose(key: &PrivateKey, offered: &[u16], tls13: bool) -> Option<u16> {
    let kind = private_kind(key);
    SUPPORTED
        .iter()
        .copied()
        .find(|s| offered.contains(s) && fits(*s, kind, tls13))
}

/// Signs `msg` with `key` under `scheme`.
pub(crate) fn sign(key: &PrivateKey, scheme: u16, msg: &[u8]) -> Result<Vec<u8>, Fatal> {
    let alg = algorithm(scheme).ok_or_else(|| Fatal::new(Alert::InternalError, "bad scheme"))?;
    key.sign(alg, msg)
        .map_err(|_| Fatal::new(Alert::InternalError, "signing failed"))
}

/// Verifies a handshake signature: `scheme` must be one we offered (`SUPPORTED`), fit the
/// certificate key, and the signature must verify.
pub(crate) fn verify(
    key: &PublicKey,
    scheme: u16,
    msg: &[u8],
    signature: &[u8],
    tls13: bool,
) -> Result<(), Fatal> {
    if !SUPPORTED.contains(&scheme) || !fits(scheme, public_kind(key), tls13) {
        return Err(Fatal::new(
            Alert::IllegalParameter,
            "signature scheme not offered or does not fit the key",
        ));
    }
    let alg = algorithm(scheme).ok_or_else(|| Fatal::new(Alert::IllegalParameter, "scheme"))?;
    key.verify(alg, msg, signature)
        .map_err(|_| Fatal::new(Alert::DecryptError, "bad handshake signature"))
}

/// The content a TLS 1.3 CertificateVerify signs (RFC 8446 section 4.4.3).
pub(crate) fn tls13_content(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let mut m = vec![0x20u8; 64];
    m.extend_from_slice(if server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    });
    m.push(0);
    m.extend_from_slice(transcript_hash);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_crypto::{ed448, ed25519, p256, p384};

    #[test]
    fn choose_sign_verify() {
        let keys = [
            PrivateKey::Ed25519(ed25519::SigningKey::from_seed(&[1; 32])),
            PrivateKey::Ed448(ed448::SigningKey::from_seed(&[1; 57])),
            PrivateKey::P256(p256::SecretKey::generate().unwrap()),
            PrivateKey::P384(p384::SecretKey::generate().unwrap()),
        ];
        for k in &keys {
            for tls13 in [true, false] {
                let s = choose(k, SUPPORTED, tls13).unwrap();
                let sig = sign(k, s, b"msg").unwrap();
                verify(&k.public_key(), s, b"msg", &sig, tls13).unwrap();
                assert!(verify(&k.public_key(), s, b"msX", &sig, tls13).is_err());
                assert!(verify(&k.public_key(), PKCS1_SHA256, b"msg", &sig, tls13).is_err());
            }
            assert!(choose(k, &[0x0201], true).is_none());
        }
        // TLS 1.3 binds the curve: a P-256 key cannot use the P-384 scheme.
        assert_eq!(choose(&keys[2], &[ECDSA_P384_SHA384], true), None);
        assert_eq!(
            choose(&keys[2], &[ECDSA_P384_SHA384], false),
            Some(ECDSA_P384_SHA384)
        );
        assert_eq!(tls13_content(true, b"h").len(), 64 + 33 + 1 + 1);
    }
}
