//! X448 key agreement (RFC 7748): the Montgomery ladder on Curve448, constant time (masked
//! swaps, Montgomery field arithmetic, inversion by a fixed exponent).
//!
//! ```
//! use akio_crypto::x448::PrivateKey;
//!
//! let a = PrivateKey::generate().unwrap();
//! let b = PrivateKey::generate().unwrap();
//! let s1 = a.diffie_hellman(&b.public_key()).unwrap();
//! let s2 = b.diffie_hellman(&a.public_key()).unwrap();
//! assert_eq!(s1, s2);
//! ```

use crate::Error;
use crate::ct;
use crate::curve448::{A24, Fp};
use crate::field::le_to_limbs;

/// The length of keys and shared secrets.
pub const KEY_LEN: usize = 56;

/// The u-coordinate of the base point (5).
pub const BASEPOINT: [u8; KEY_LEN] = {
    let mut b = [0u8; KEY_LEN];
    b[0] = 5;
    b
};

/// The X448 function: `scalar · u` (the scalar clamped as RFC 7748 §5 specifies, `u` reduced
/// modulo p). Constant time in both inputs.
#[must_use]
pub fn x448(scalar: &[u8; KEY_LEN], u: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut k = *scalar;
    k[0] &= 252;
    k[55] |= 128;
    // u < 2⁴⁴⁸ = R, so the Montgomery conversion reduces any encoding.
    let x1 = Fp::from_limbs_reduce(&le_to_limbs(u).unwrap_or([0; 7]));
    let mut x2 = Fp::ONE;
    let mut z2 = Fp::ZERO;
    let mut x3 = x1;
    let mut z3 = Fp::ONE;
    let mut swap = 0u64;
    for t in (0..448).rev() {
        let kt = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= kt;
        let m = ct::mask(swap);
        ct::swap(m, &mut x2.l, &mut x3.l);
        ct::swap(m, &mut z2.l, &mut z3.l);
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
        z2 = e.mul(&aa.add(&A24.mul(&e)));
    }
    let m = ct::mask(swap);
    ct::swap(m, &mut x2.l, &mut x3.l);
    ct::swap(m, &mut z2.l, &mut z3.l);
    let mut out = [0u8; KEY_LEN];
    x2.mul(&z2.invert()).write_le(&mut out);
    out
}

/// An X448 private key (56 random bytes; clamped when used).
#[derive(Clone)]
pub struct PrivateKey([u8; KEY_LEN]);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("x448::PrivateKey(..)")
    }
}

impl PrivateKey {
    /// A new key from the operating system's randomness.
    pub fn generate() -> Result<PrivateKey, Error> {
        Ok(PrivateKey(crate::random_array()?))
    }

    /// The key with these 56 bytes.
    #[must_use]
    pub fn from_bytes(b: [u8; KEY_LEN]) -> PrivateKey {
        PrivateKey(b)
    }

    /// The key's bytes (unclamped, as given).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// The public key, `x448(self, 5)`.
    #[must_use]
    pub fn public_key(&self) -> [u8; KEY_LEN] {
        x448(&self.0, &BASEPOINT)
    }

    /// The shared secret with the peer's public key. Fails with [`Error::ZeroSharedSecret`]
    /// for the all-zero result (a low-order peer key), which TLS 1.3 requires peers to reject.
    pub fn diffie_hellman(&self, peer: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], Error> {
        let s = x448(&self.0, peer);
        if crate::ct_eq(&s, &[0; KEY_LEN]) {
            return Err(Error::ZeroSharedSecret);
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hex;

    fn h56(s: &str) -> [u8; 56] {
        let mut b = [0u8; 56];
        for i in 0..56 {
            b[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        b
    }

    #[test]
    fn rfc7748() {
        // §5.2 test vectors.
        let k = h56(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let u = h56(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        assert_eq!(
            hex(&x448(&k, &u)),
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
        );
        let k = h56(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        );
        let u = h56(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        );
        assert_eq!(
            hex(&x448(&k, &u)),
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
        );
        // Iterated.
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for i in 1..=1000 {
            let r = x448(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    hex(&k),
                    "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
                );
            }
        }
        assert_eq!(
            hex(&k),
            "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"
        );
        // §6.2 Diffie-Hellman.
        let a = PrivateKey::from_bytes(h56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        ));
        let b = PrivateKey::from_bytes(h56(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        ));
        assert_eq!(
            hex(&a.public_key()),
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        );
        assert_eq!(
            hex(&b.public_key()),
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        );
        assert_eq!(
            hex(&a.diffie_hellman(&b.public_key()).unwrap()),
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        );
        assert_eq!(a.diffie_hellman(&[0; 56]), Err(Error::ZeroSharedSecret));
        // u = p + 1 ≡ 1 (a non-canonical encoding of a low-order point) also gives zero.
        let mut p1 = [0xffu8; 56];
        p1[..28].fill(0);
        assert_eq!(a.diffie_hellman(&p1), Err(Error::ZeroSharedSecret));
    }
}
