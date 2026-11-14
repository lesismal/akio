//! Ed25519 signatures (RFC 8032, "pure" Ed25519 without context or prehash).
//!
//! Signing is constant time (fixed-window table scan for `[r]B` and `[a]B`, Montgomery scalar
//! arithmetic). Verification is variable time on public data and follows these rules (the same
//! as ring and the strict mode of ed25519-dalek, minus the small-order key check):
//!
//! - `S` must be canonical (`S < ℓ`), otherwise the signature is malleable;
//! - the public key `A` must decode: `y < p`, a square root exists, and `x = 0` does not carry
//!   the sign bit;
//! - the check is the cofactorless equation `[S]B - [k]A == R` compared on the *encoding* of
//!   `R`, so a non-canonical `R` never verifies.
//!
//! Small-order public keys are accepted by verification (as RFC 8032 and ring do) but can be
//! detected with [`VerifyingKey::is_weak`].
//!
//! ```
//! use only_crypto::ed25519::SigningKey;
//!
//! let k = SigningKey::from_seed(&[7; 32]);
//! let sig = k.sign(b"hello");
//! k.verifying_key().verify(b"hello", &sig).unwrap();
//! assert!(k.verifying_key().verify(b"hellO", &sig).is_err());
//! ```

use crate::Error;
use crate::curve25519::{Point, Scalar, scalar_from_hash};
use crate::hash::Sha512;

/// The length of a signature.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 private key: the 32-byte seed, with the expanded scalar and prefix cached.
#[derive(Clone)]
pub struct SigningKey {
    seed: [u8; 32],
    scalar: Scalar,
    prefix: [u8; 32],
    public: VerifyingKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ed25519::SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// The key derived from a 32-byte seed (the RFC 8032 private key).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        let h = Sha512::digest(seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        let public = Point::mul_base(&a).compress();
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&a);
        SigningKey {
            seed: *seed,
            scalar: scalar_from_hash(&wide),
            prefix,
            public: VerifyingKey {
                bytes: public,
                point: None,
            },
        }
    }

    /// A new key from the operating system's randomness.
    pub fn generate() -> Result<SigningKey, Error> {
        Ok(Self::from_seed(&crate::random_array()?))
    }

    /// The seed.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.public.clone()
    }

    /// The signature of `msg`: `R || S`.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        let mut h = Sha512::new();
        h.update(&self.prefix);
        h.update(msg);
        let r = scalar_from_hash(&h.finalize());
        let mut rb = [0u8; 32];
        r.write_le(&mut rb);
        let big_r = Point::mul_base(&rb).compress();
        let mut h = Sha512::new();
        h.update(&big_r);
        h.update(&self.public.bytes);
        h.update(msg);
        let k = scalar_from_hash(&h.finalize());
        let s = r.add(&k.mul(&self.scalar));
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        s.write_le(&mut sig[32..]);
        sig
    }
}

/// An Ed25519 public key (32 bytes).
#[derive(Clone)]
pub struct VerifyingKey {
    bytes: [u8; 32],
    /// The decoded point; `None` for a key derived from a signing key (decoded on first use).
    point: Option<Point>,
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ed25519::VerifyingKey(")?;
        for b in &self.bytes {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, o: &Self) -> bool {
        self.bytes == o.bytes
    }
}
impl Eq for VerifyingKey {}

impl VerifyingKey {
    /// Decodes a public key; fails with [`Error::InvalidKey`] if it is not a valid encoding of
    /// a curve point.
    pub fn from_bytes(b: &[u8]) -> Result<VerifyingKey, Error> {
        let bytes: [u8; 32] = b.try_into().map_err(|_| Error::InvalidLength)?;
        let point = Point::decompress(&bytes).ok_or(Error::InvalidKey)?;
        Ok(VerifyingKey {
            bytes,
            point: Some(point),
        })
    }

    /// The 32-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    fn point(&self) -> Result<Point, Error> {
        match self.point {
            Some(p) => Ok(p),
            None => Point::decompress(&self.bytes).ok_or(Error::InvalidKey),
        }
    }

    /// Whether the key is a point of small order (it would verify signatures on many
    /// messages); protocols that need strong binding can reject such keys.
    #[must_use]
    pub fn is_weak(&self) -> bool {
        self.point().is_ok_and(|p| p.is_small_order())
    }

    /// Verifies `sig` on `msg` (rules in the module documentation); fails with
    /// [`Error::Verification`].
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        if sig.len() != SIGNATURE_LEN {
            return Err(Error::Verification);
        }
        let a = self.point().map_err(|_| Error::Verification)?;
        let s = Scalar::from_le_bytes(&sig[32..]).ok_or(Error::Verification)?;
        let mut h = Sha512::new();
        h.update(&sig[..32]);
        h.update(&self.bytes);
        h.update(msg);
        let k = scalar_from_hash(&h.finalize());
        let (mut sb, mut kb) = ([0u8; 32], [0u8; 32]);
        s.write_le(&mut sb);
        k.write_le(&mut kb);
        let r = Point::mul_base(&sb).add(&a.neg().mul_vartime(&kb));
        if r.compress()[..] == sig[..32] {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hex;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8032() {
        // §7.1 TEST 1, 2, 3.
        for (sk, pk, msg, sig) in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ] {
            let k = SigningKey::from_seed(&unhex(sk).try_into().unwrap());
            assert_eq!(hex(k.verifying_key().as_bytes()), pk);
            let s = k.sign(&unhex(msg));
            assert_eq!(hex(&s), sig);
            let vk = VerifyingKey::from_bytes(&unhex(pk)).unwrap();
            vk.verify(&unhex(msg), &s).unwrap();
            let mut bad = s;
            bad[5] ^= 1;
            assert!(vk.verify(&unhex(msg), &bad).is_err());
        }
    }
}
