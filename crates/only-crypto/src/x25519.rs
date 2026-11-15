//! X25519 key agreement (RFC 7748): the Montgomery ladder on Curve25519, constant time. Public
//! keys (the fixed base point) come from the Ed25519 base point table instead: `[k]B` on the
//! birationally equivalent edwards25519 curve, mapped to `u = (1 + y)/(1 - y)`, about three
//! times cheaper than the ladder.
//!
//! ```
//! use only_crypto::x25519::PrivateKey;
//!
//! let a = PrivateKey::generate().unwrap();
//! let b = PrivateKey::generate().unwrap();
//! let s1 = a.diffie_hellman(&b.public_key()).unwrap();
//! let s2 = b.diffie_hellman(&a.public_key()).unwrap();
//! assert_eq!(s1, s2);
//! ```

use crate::Error;
use crate::ct;
use crate::curve25519::Point;
use crate::curve25519::fe::Fe;

/// The u-coordinate of the base point.
pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// The X25519 function: `scalar · u` (the scalar is clamped, the top bit of `u` ignored, as
/// RFC 7748 specifies). Constant time in both inputs.
#[must_use]
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    #[cfg(target_arch = "x86_64")]
    if crate::curve25519::hw::enabled() {
        return crate::curve25519::hw::ladder(&clamp(scalar), u);
    }
    #[cfg(target_arch = "aarch64")]
    if crate::curve25519::hw_aarch64::enabled() {
        return crate::curve25519::hw_aarch64::ladder(&clamp(scalar), u);
    }
    x25519_portable(scalar, u)
}

/// The scalar as RFC 7748 §5 decodes it: the low three bits and the top bit cleared, bit 254 set.
fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// [`x25519`] on the portable field (radix 2⁵¹): the fallback, and the reference for the
/// assembly ladders (`curve25519::hw` on BMI2 + ADX, `curve25519::hw_aarch64`).
pub(crate) fn x25519_portable(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let k = clamp(scalar);
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= kt;
        let m = ct::mask(swap);
        Fe::cswap(m, &mut x2, &mut x3);
        Fe::cswap(m, &mut z2, &mut z3);
        swap = kt;
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(121_665)));
    }
    let m = ct::mask(swap);
    Fe::cswap(m, &mut x2, &mut x3);
    Fe::cswap(m, &mut z2, &mut z3);
    x2.mul(&z2.invert()).to_bytes()
}

/// An X25519 private key (32 random bytes; clamped when used).
#[derive(Clone)]
pub struct PrivateKey([u8; 32]);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("x25519::PrivateKey(..)")
    }
}

impl PrivateKey {
    /// A new key from the operating system's randomness.
    pub fn generate() -> Result<PrivateKey, Error> {
        Ok(PrivateKey(crate::random_array()?))
    }

    /// The key with these 32 bytes.
    #[must_use]
    pub fn from_bytes(b: [u8; 32]) -> PrivateKey {
        PrivateKey(b)
    }

    /// The key's bytes (unclamped, as given).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The public key, `x25519(self, 9)`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        let k = clamp(&self.0);
        // u = 9 is the image of the Ed25519 base point B, so x25519(k, 9) = u([k]B); the clamped
        // k is below 2²⁵⁵ as `mul_base` needs.
        Point::mul_base(&k).to_montgomery_u()
    }

    /// The shared secret with the peer's public key. Fails with
    /// [`Error::ZeroSharedSecret`] for the all-zero result (a low-order peer key), which TLS 1.3
    /// requires peers to reject (RFC 8446 §7.4.2).
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32], Error> {
        let s = x25519(&self.0, peer);
        if crate::ct_eq(&s, &[0; 32]) {
            return Err(Error::ZeroSharedSecret);
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hex;

    fn h32(s: &str) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..32 {
            b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        b
    }

    #[test]
    fn rfc7748() {
        // §5.2 test vectors.
        let k = h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            hex(&x25519(&k, &u)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
        let k = h32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = h32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            hex(&x25519(&k, &u)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
        // Iterated: 1000 rounds.
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for i in 1..=1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    hex(&k),
                    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
                );
            }
        }
        assert_eq!(
            hex(&k),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        );
        // §6.1 Diffie-Hellman.
        let a = PrivateKey::from_bytes(h32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = PrivateKey::from_bytes(h32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            hex(&a.public_key()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        let s = a.diffie_hellman(&b.public_key()).unwrap();
        assert_eq!(
            hex(&s),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
        assert_eq!(a.diffie_hellman(&[0; 32]), Err(Error::ZeroSharedSecret));
        assert_eq!(
            hex(&b.public_key()),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
    }

    /// RFC 7748 §5.2, 1,000,000 iterations (minutes in debug builds: `--ignored`, or
    /// `--release`), on whichever ladder `x25519` dispatches to.
    #[test]
    #[ignore = "slow: 1,000,000 ladders"]
    fn rfc7748_million() {
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for _ in 0..1_000_000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
        }
        assert_eq!(
            hex(&k),
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
        );
    }

    /// Public keys from the Edwards base point table match the ladder on u = 9.
    #[test]
    fn public_key_matches_ladder() {
        let mut rng = crate::rand::ChaChaRng::from_seed([0x25; 32]);
        let mut keys = vec![[0u8; 32], [0xff; 32]];
        for _ in 0..200 {
            let mut k = [0u8; 32];
            rng.fill(&mut k);
            keys.push(k);
        }
        for k in keys {
            assert_eq!(
                PrivateKey::from_bytes(k).public_key(),
                x25519(&k, &BASEPOINT),
                "{}",
                hex(&k)
            );
        }
    }
}
