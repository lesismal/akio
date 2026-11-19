//! NIST P-521 (secp521r1): ECDH and ECDSA (SHA-512 by default; deterministic nonces, RFC 6979).
//!
//! The API is the same as [`p256`](crate::p256)'s, with 66-byte scalars and coordinates. The
//! base field `GF(2⁵²¹ - 1)` uses nine unsaturated limbs (58 bits, the top one 57) and the
//! Mersenne reduction; points use the complete formulas of Renes, Costello and Batina, so the
//! secret-scalar multiplications (a signed 5-bit Booth window for ECDH, a signed 4-bit comb of
//! the base point for key generation and signing) have no exceptional cases. Secret-key
//! operations are constant time (see the crate documentation); keys decoded from SEC1 are
//! validated (on the curve, not the identity). Portable Rust only.
//!
//! ```
//! use only_crypto::p521::{SecretKey, Signature};
//!
//! let k = SecretKey::generate().unwrap();
//! let sig = k.sign(b"message");
//! k.public_key().verify(b"message", &Signature::from_der(&sig.to_der()).unwrap()).unwrap();
//!
//! let peer = SecretKey::generate().unwrap();
//! assert_eq!(k.diffie_hellman(&peer.public_key()), peer.diffie_hellman(&k.public_key()));
//! ```

mod field;
mod group;

use group::{Point, Scalar, Sig};

use crate::Error;
use crate::hash::{Hash, Sha512};

/// The length of a scalar, a coordinate and each half of a fixed-width signature.
pub const SCALAR_LEN: usize = group::LEN;

/// A P-521 private key: a scalar in `[1, n)`, for ECDH and ECDSA.
#[derive(Clone)]
pub struct SecretKey {
    d: Scalar,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P-521 SecretKey(..)")
    }
}

impl SecretKey {
    /// A new key from the operating system's randomness (rejection sampling over 521 bits).
    pub fn generate() -> Result<SecretKey, Error> {
        loop {
            let mut b: [u8; SCALAR_LEN] = crate::random_array()?;
            b[0] &= 1;
            if let Ok(k) = Self::from_bytes(&b) {
                return Ok(k);
            }
        }
    }

    /// From the big-endian scalar; fails with [`Error::InvalidKey`] unless it is in `[1, n)`
    /// and exactly 66 bytes long.
    pub fn from_bytes(b: &[u8]) -> Result<SecretKey, Error> {
        let d = group::scalar_from_bytes(b).ok_or(Error::InvalidKey)?;
        if d.is_zero() != 0 {
            return Err(Error::InvalidKey);
        }
        Ok(SecretKey { d })
    }

    /// The big-endian scalar.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SCALAR_LEN] {
        group::scalar_to_bytes(&self.d)
    }

    /// The public key `d·G`.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            q: Point::mul_base_ct(&self.d),
        }
    }

    /// ECDH (SEC1 §3.3.1): the x-coordinate of `d·Q`. The peer key was validated when it was
    /// decoded, and the group has prime order, so the result is never the identity.
    #[must_use]
    pub fn diffie_hellman(&self, peer: &PublicKey) -> [u8; SCALAR_LEN] {
        peer.q
            .mul_ct(&self.d)
            .to_affine_x()
            .map_or([0; SCALAR_LEN], |x| x.to_be_bytes())
    }

    /// Signs `msg` hashed with SHA-512 (deterministic nonce, RFC 6979).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sign_with::<Sha512>(msg)
    }

    /// Signs `msg` hashed with `H` (RFC 6979 nonce with HMAC-`H`).
    #[must_use]
    pub fn sign_with<H: Hash>(&self, msg: &[u8]) -> Signature {
        self.sign_prehash::<H>(H::digest(msg).as_ref())
    }

    /// Signs a precomputed digest; `H` is the hash used for the RFC 6979 nonce (it should be
    /// the one that produced `digest`).
    #[must_use]
    pub fn sign_prehash<H: Hash>(&self, digest: &[u8]) -> Signature {
        Signature(group::sign::<H>(&self.d, digest))
    }
}

/// A P-521 public key: a point on the curve other than the identity.
#[derive(Clone)]
pub struct PublicKey {
    q: Point,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P-521 PublicKey(")?;
        for b in self.to_uncompressed() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, o: &Self) -> bool {
        self.to_uncompressed() == o.to_uncompressed()
    }
}
impl Eq for PublicKey {}

impl PublicKey {
    /// Decodes a SEC1 point, uncompressed (`04 || x || y`) or compressed (`02`/`03 || x`).
    /// Coordinates must be below `p` and the point on the curve; the identity is rejected.
    pub fn from_sec1(b: &[u8]) -> Result<PublicKey, Error> {
        Point::from_sec1(b)
            .map(|q| PublicKey { q })
            .ok_or(Error::InvalidKey)
    }

    /// The uncompressed SEC1 encoding, `04 || x || y` (133 bytes).
    #[must_use]
    pub fn to_uncompressed(&self) -> Vec<u8> {
        self.q.to_uncompressed().unwrap_or_default()
    }

    /// The compressed SEC1 encoding, `02`/`03 || x` (67 bytes).
    #[must_use]
    pub fn to_compressed(&self) -> Vec<u8> {
        let mut u = self.to_uncompressed();
        let odd = u.last().map_or(0, |b| b & 1);
        u.truncate(1 + SCALAR_LEN);
        u[0] = 2 | odd;
        u
    }

    /// Verifies `sig` on `msg` hashed with SHA-512.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        self.verify_with::<Sha512>(msg, sig)
    }

    /// Verifies `sig` on `msg` hashed with `H`.
    pub fn verify_with<H: Hash>(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        self.verify_prehash(H::digest(msg).as_ref(), sig)
    }

    /// Verifies `sig` on a precomputed digest (its leftmost 521 bits, as ECDSA specifies).
    /// High-`s` signatures are accepted.
    pub fn verify_prehash(&self, digest: &[u8], sig: &Signature) -> Result<(), Error> {
        group::verify(&self.q, digest, &sig.0)
    }
}

/// An ECDSA signature `(r, s)` with `1 <= r, s < n`.
#[derive(Clone)]
pub struct Signature(Sig);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P-521 Signature(")?;
        for b in self.to_fixed() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl PartialEq for Signature {
    fn eq(&self, o: &Self) -> bool {
        self.to_fixed() == o.to_fixed()
    }
}
impl Eq for Signature {}

impl Signature {
    /// From the DER `ECDSA-Sig-Value` (TLS, X.509), strictly: minimal positive INTEGERs, no
    /// trailing data. Fails with [`Error::Encoding`] or, for values out of range,
    /// [`Error::Verification`].
    pub fn from_der(b: &[u8]) -> Result<Signature, Error> {
        group::sig_from_der(b).map(Signature)
    }

    /// From the fixed-width `r || s` form (132 bytes: IEEE P1363, JWS).
    pub fn from_fixed(b: &[u8]) -> Result<Signature, Error> {
        group::sig_from_fixed(b).map(Signature)
    }

    /// The DER encoding.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        group::sig_to_der(&self.0)
    }

    /// The fixed-width `r || s` encoding.
    #[must_use]
    pub fn to_fixed(&self) -> Vec<u8> {
        let mut v = group::scalar_to_bytes(&self.0.r).to_vec();
        v.extend_from_slice(&group::scalar_to_bytes(&self.0.s));
        v
    }
}
