//! Ed448 signatures (RFC 8032 §5.2, "pure" Ed448 with an empty context), as X.509 (RFC 8410)
//! and TLS 1.3 (`ed448`) use them.
//!
//! Signing is constant time: fixed 4-bit windows with masked table scans for `[r]B` and `[s]B`,
//! Montgomery scalar arithmetic, SHAKE256. Verification is variable time on public data and
//! strict in the same way as [`ed25519`](crate::ed25519):
//!
//! - `S` must be canonical (`S < ℓ`, top byte zero);
//! - the public key must decode (`y < p`, unused bits zero, a square root exists, no sign bit
//!   on `x = 0`);
//! - the check is the cofactorless `[S]B - [k]A == R`, compared on the encoding of `R`.
//!
//! ```
//! use akio_crypto::ed448::SigningKey;
//!
//! let k = SigningKey::from_seed(&[7; 57]);
//! let sig = k.sign(b"hello");
//! k.verifying_key().verify(b"hello", &sig).unwrap();
//! assert!(k.verifying_key().verify(b"hellO", &sig).is_err());
//! ```

use crate::Error;
use crate::curve448::{Point, Scalar, scalar_from_hash};
use crate::field::le_to_limbs;
use crate::hash::Shake256;

/// The length of a signature.
pub const SIGNATURE_LEN: usize = 114;
/// The length of a public key and of a seed.
pub const KEY_LEN: usize = 57;

/// `dom4(0, "")`: the domain separation prefix of pure Ed448 without context.
const DOM4: &[u8] = b"SigEd448\x00\x00";

fn hash(parts: &[&[u8]]) -> Scalar {
    let mut h = Shake256::new();
    h.update(DOM4);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 114];
    h.squeeze(&mut out);
    scalar_from_hash(&out)
}

/// An Ed448 private key: the 57-byte seed, with the expanded scalar and prefix cached.
#[derive(Clone)]
pub struct SigningKey {
    seed: [u8; KEY_LEN],
    scalar: Scalar,
    prefix: [u8; 57],
    public: VerifyingKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ed448::SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// The key derived from a 57-byte seed (the RFC 8032 private key).
    #[must_use]
    pub fn from_seed(seed: &[u8; KEY_LEN]) -> SigningKey {
        let h: [u8; 114] = Shake256::digest(seed);
        let mut a = [0u8; 56];
        a.copy_from_slice(&h[..56]);
        // Clamp: the two low bits cleared, the top bit of the 448-bit string set (the 57th
        // byte is zero).
        a[0] &= 0xfc;
        a[55] |= 0x80;
        let mut prefix = [0u8; 57];
        prefix.copy_from_slice(&h[57..]);
        let scalar = Scalar::from_limbs_reduce(&le_to_limbs(&a).unwrap_or([0; 7]));
        let public = Point::mul_base(&scalar.to_limbs()).compress();
        SigningKey {
            seed: *seed,
            scalar,
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
    pub fn seed(&self) -> &[u8; KEY_LEN] {
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
        let r = hash(&[&self.prefix, msg]);
        let big_r = Point::mul_base(&r.to_limbs()).compress();
        let k = hash(&[&big_r, &self.public.bytes, msg]);
        let s = r.add(&k.mul(&self.scalar));
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..57].copy_from_slice(&big_r);
        s.write_le(&mut sig[57..113]);
        sig
    }
}

/// An Ed448 public key (57 bytes).
#[derive(Clone)]
pub struct VerifyingKey {
    bytes: [u8; KEY_LEN],
    /// The decoded point; `None` for a key derived from a signing key (decoded on first use).
    point: Option<Point>,
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ed448::VerifyingKey(")?;
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
        let bytes: [u8; KEY_LEN] = b.try_into().map_err(|_| Error::InvalidLength)?;
        let point = Point::decompress(&bytes).ok_or(Error::InvalidKey)?;
        Ok(VerifyingKey {
            bytes,
            point: Some(point),
        })
    }

    /// The 57-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    fn point(&self) -> Result<Point, Error> {
        match self.point {
            Some(p) => Ok(p),
            None => Point::decompress(&self.bytes).ok_or(Error::InvalidKey),
        }
    }

    /// Whether the key is a point of small order.
    #[must_use]
    pub fn is_weak(&self) -> bool {
        self.point().is_ok_and(|p| p.is_small_order())
    }

    /// Verifies `sig` on `msg` (rules in the module documentation); fails with
    /// [`Error::Verification`].
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        if sig.len() != SIGNATURE_LEN || sig[113] != 0 {
            return Err(Error::Verification);
        }
        let a = self.point().map_err(|_| Error::Verification)?;
        let s = Scalar::from_le_bytes(&sig[57..113]).ok_or(Error::Verification)?;
        let k = hash(&[&sig[..57], &self.bytes, msg]);
        let r = a.neg().mul_add_base_vartime(&s.to_limbs(), &k.to_limbs());
        if r.compress()[..] == sig[..57] {
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
        // §7.4 "Blank" and "1 octet".
        for (sk, pk, msg, sig) in [
            (
                "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
                "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
                "",
                "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
            ),
            (
                "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
                "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
                "03",
                "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
            ),
        ] {
            let k = SigningKey::from_seed(&unhex(sk).try_into().unwrap());
            assert_eq!(hex(k.verifying_key().as_bytes()), pk);
            let s = k.sign(&unhex(msg));
            assert_eq!(hex(&s), sig);
            let vk = VerifyingKey::from_bytes(&unhex(pk)).unwrap();
            vk.verify(&unhex(msg), &s).unwrap();
            for i in [0, 56, 60, 112] {
                let mut bad = s;
                bad[i] ^= 1;
                assert!(vk.verify(&unhex(msg), &bad).is_err(), "byte {i}");
            }
            assert!(vk.verify(b"x", &s).is_err());
        }
    }

    #[test]
    fn strictness() {
        let k = SigningKey::from_seed(&[1; 57]);
        let sig = k.sign(b"m");
        let vk = k.verifying_key();
        // S + ℓ (non-canonical) fails.
        let mut s = Scalar::from_le_bytes(&sig[57..113]).unwrap().to_limbs();
        let l = <crate::curve448::L448 as crate::field::Modulus<7>>::P;
        let s0 = s;
        crate::ct::add_limbs(&mut s, &s0, &l);
        let mut bad = sig;
        for (i, w) in s.iter().enumerate() {
            bad[57 + 8 * i..65 + 8 * i].copy_from_slice(&w.to_le_bytes());
        }
        assert!(vk.verify(b"m", &bad).is_err());
        // Unused bits of the last key byte.
        let mut pk = *vk.as_bytes();
        pk[56] |= 1;
        assert!(VerifyingKey::from_bytes(&pk).is_err());
        // y = p is rejected.
        let mut pk = [0xffu8; 57];
        pk[28] = 0xfe;
        pk[56] = 0;
        assert!(VerifyingKey::from_bytes(&pk).is_err());
        // The identity (y = 1) is weak; x = 0 with the sign bit is invalid.
        let mut id = [0u8; 57];
        id[0] = 1;
        assert!(VerifyingKey::from_bytes(&id).unwrap().is_weak());
        id[56] = 0x80;
        assert!(VerifyingKey::from_bytes(&id).is_err());
        assert!(!vk.is_weak());
        assert!(vk.verify(b"m", &sig[..113]).is_err());
    }
}
