//! Arithmetic modulo the Mersenne prime `p = 2⁵²¹ - 1`, in nine unsaturated limbs.
//!
//! Limb `i` has weight `2^(58i)`: eight limbs of 58 bits and a top limb of 57 bits make 521
//! bits. Because `2⁵²¹ ≡ 1 (mod p)`, a product term of weight `2^(58k)` with `k ≥ 9` folds onto
//! weight `2^(58(k-9))` times `2^522 / 2^521 = 2`: multiplication is the schoolbook product with
//! the wrapped terms doubled, then one carry chain whose carry out of the top limb re-enters at
//! the bottom. No step branches on or indexes by a value, so everything here is constant time
//! (the canonical encoding included).
//!
//! Bounds. An element is *loose*: limbs 0–7 below `2⁵⁸ + 2¹⁰`, limb 8 below `2⁵⁷ + 2¹⁰`; it
//! represents its value modulo `p` (not necessarily below `p`). Every operation takes loose
//! inputs and returns loose outputs:
//!
//! - multiplication: products below `2^118.1`, at most nine per output limb with the wrapped
//!   ones doubled, sums below `2^123`: no overflow of `u128`; the carry chain (carries below
//!   `2⁶⁶`) leaves limbs 0, 2–7 below `2⁵⁸`, limb 8 below `2⁵⁷` and limb 1 below `2⁵⁸ + 2⁹`;
//! - addition: limb sums below `2^59.1`, then one parallel carry step (each limb keeps its low
//!   bits and receives the carry, at most 2, of the limb below; limb 0 that of limb 8);
//!   subtraction adds `2p` (limbs `2⁵⁹ - 2`, top `2⁵⁸ - 2`, each at least the subtrahend's
//!   limb) before subtracting, so no limb goes negative; multiplication by `k ≤ 16` gives
//!   carries of at most 16.

// Limb arithmetic reads clearest with the limb indices spelled out.
#![allow(clippy::needless_range_loop)]

use crate::ct;

const M58: u64 = (1 << 58) - 1;
const M57: u64 = (1 << 57) - 1;

/// An element of `GF(2⁵²¹ - 1)` (loose limbs, see the module documentation).
#[derive(Clone, Copy)]
pub(crate) struct Fe(pub(crate) [u64; 9]);

impl std::fmt::Debug for Fe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fe(..)")
    }
}

/// One carry step done for every limb at once (no chain: every limb's carry is computed from
/// the input, so the steps run in parallel): limbs below `2⁶²` become loose (each below its
/// width plus the carry from the limb below, at most 16 here).
#[inline(always)]
fn carry(c: [u64; 9]) -> [u64; 9] {
    let mut out = [0u64; 9];
    out[0] = (c[0] & M58) + (c[8] >> 57);
    for i in 1..8 {
        out[i] = (c[i] & M58) + (c[i - 1] >> 58);
    }
    out[8] = (c[8] & M57) + (c[7] >> 58);
    out
}

/// One full carry chain over limbs below `2⁶³` (top limb included): every limb below its
/// width except limb 1, which may exceed it by the wrapped carry.
#[inline(always)]
fn carry_chain(mut c: [u64; 9]) -> [u64; 9] {
    for i in 0..8 {
        c[i + 1] += c[i] >> 58;
        c[i] &= M58;
    }
    c[0] += c[8] >> 57;
    c[8] &= M57;
    c[1] += c[0] >> 58;
    c[0] &= M58;
    c
}

/// The carry chain of a product: `c[k]` below `2^123`.
#[inline(always)]
fn carry_wide(c: [u128; 9]) -> Fe {
    let mut out = [0u64; 9];
    let mut k: u128 = 0;
    for i in 0..8 {
        let v = c[i] + k;
        out[i] = (v as u64) & M58;
        k = v >> 58;
    }
    let v = c[8] + k;
    out[8] = (v as u64) & M57;
    // Weight 2⁵²¹ ≡ 1: the carry (below 2⁶⁷) re-enters at limb 0.
    let v = u128::from(out[0]) + (v >> 57);
    out[0] = (v as u64) & M58;
    out[1] += (v >> 58) as u64;
    Fe(out)
}

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 9]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// From canonical 58-bit limbs (constants).
    pub(crate) const fn from_limbs(l: [u64; 9]) -> Fe {
        Fe(l)
    }

    #[inline]
    pub(crate) fn add(&self, b: &Fe) -> Fe {
        let mut c = [0u64; 9];
        for i in 0..9 {
            c[i] = self.0[i] + b.0[i];
        }
        Fe(carry(c))
    }

    #[inline]
    pub(crate) fn sub(&self, b: &Fe) -> Fe {
        let mut c = [0u64; 9];
        for i in 0..8 {
            c[i] = self.0[i] + ((M58 << 1) - b.0[i]);
        }
        c[8] = self.0[8] + ((M57 << 1) - b.0[8]);
        Fe(carry(c))
    }

    #[inline]
    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// `k·self` for a small `k` (at most 16).
    #[inline]
    pub(crate) fn mul_small(&self, k: u64) -> Fe {
        let mut c = [0u64; 9];
        for i in 0..9 {
            c[i] = self.0[i] * k;
        }
        Fe(carry(c))
    }

    #[inline]
    pub(crate) fn mul(&self, b: &Fe) -> Fe {
        let a = &self.0;
        let b = &b.0;
        let mut b2 = [0u64; 9];
        for i in 0..9 {
            b2[i] = b[i] << 1;
        }
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let mut c = [0u128; 9];
        for i in 0..9 {
            for j in 0..9 {
                // Both indices are constants once the loops are unrolled.
                if i + j < 9 {
                    c[i + j] += m(a[i], b[j]);
                } else {
                    c[i + j - 9] += m(a[i], b2[j]);
                }
            }
        }
        carry_wide(c)
    }

    #[inline]
    pub(crate) fn square(&self) -> Fe {
        let a = &self.0;
        let mut a2 = [0u64; 9];
        for i in 0..9 {
            a2[i] = a[i] << 1;
        }
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let mut c = [0u128; 9];
        for i in 0..9 {
            // The square term, doubled when it folds.
            if 2 * i < 9 {
                c[2 * i] += m(a[i], a[i]);
            } else {
                c[2 * i - 9] += m(a[i], a2[i]);
            }
            // Each cross term twice, four times when it folds.
            for j in i + 1..9 {
                if i + j < 9 {
                    c[i + j] += m(a2[i], a[j]);
                } else {
                    c[i + j - 9] += m(a2[i], a2[j]);
                }
            }
        }
        carry_wide(c)
    }

    /// `self^(2ⁿ)`.
    #[inline]
    pub(crate) fn square_n(&self, n: usize) -> Fe {
        let mut r = *self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// `self^(2ᵏ - 1)` chain pieces: `(x^(2^a - 1))^(2^b) · x^(2^b - 1) = x^(2^(a+b) - 1)`.
    #[inline]
    fn chain(xa: &Fe, b: usize, xb: &Fe) -> Fe {
        xa.square_n(b).mul(xb)
    }

    /// `self^(2⁵¹⁹ - 1)`: 518 squarings and 12 multiplications.
    fn pow_2_519_m1(&self) -> Fe {
        let x1 = *self;
        let x2 = Self::chain(&x1, 1, &x1);
        let x3 = Self::chain(&x2, 1, &x1);
        let x4 = Self::chain(&x2, 2, &x2);
        let x7 = Self::chain(&x4, 3, &x3);
        let x8 = Self::chain(&x4, 4, &x4);
        let x16 = Self::chain(&x8, 8, &x8);
        let x32 = Self::chain(&x16, 16, &x16);
        let x64 = Self::chain(&x32, 32, &x32);
        let x128 = Self::chain(&x64, 64, &x64);
        let x256 = Self::chain(&x128, 128, &x128);
        let x512 = Self::chain(&x256, 256, &x256);
        Self::chain(&x512, 7, &x7)
    }

    /// `self⁻¹` (0 maps to 0): `self^(p-2)`, `p - 2 = (2⁵¹⁹ - 1)·4 + 1`. Constant time.
    pub(crate) fn invert(&self) -> Fe {
        self.pow_2_519_m1().square_n(2).mul(self)
    }

    /// A square root if `self` is a square (`p ≡ 3 mod 4`: `self^((p+1)/4) = self^(2⁵¹⁹)`).
    pub(crate) fn sqrt(&self) -> Option<Fe> {
        let r = self.square_n(519);
        (r.square().ct_eq(self) != 0).then_some(r)
    }

    /// The canonical limbs (each below its width, the value below `p`).
    pub(crate) fn canonical(&self) -> [u64; 9] {
        // Two chains make every limb strict (the second one's wrap-around carry can only
        // reach limb 1 if limbs 1–8 were all ones, which it zeroes); the value is then at most
        // 2⁵²¹ - 1 = p, which maps to 0.
        let mut c = carry_chain(carry_chain(self.0));
        let mut all = c[8] ^ M57;
        for &l in &c[..8] {
            all |= l ^ M58;
        }
        let is_p = ct::is_zero(all);
        for l in &mut c {
            *l &= !is_p;
        }
        c
    }

    /// `u64::MAX` if zero (modulo `p`).
    pub(crate) fn is_zero(&self) -> u64 {
        ct::is_zero_limbs(&self.canonical())
    }

    /// `u64::MAX` if equal modulo `p`.
    pub(crate) fn ct_eq(&self, b: &Fe) -> u64 {
        self.sub(b).is_zero()
    }

    /// `a` where `m` is all ones, else `b`.
    #[inline]
    pub(crate) fn select(m: u64, a: &Fe, b: &Fe) -> Fe {
        let mut l = b.0;
        ct::assign(m, &mut l, &a.0);
        Fe(l)
    }

    /// The low bit of the canonical value.
    pub(crate) fn is_odd(&self) -> u64 {
        self.canonical()[0] & 1
    }

    /// From 66 big-endian bytes, if below `p`.
    pub(crate) fn from_be_bytes(b: &[u8]) -> Option<Fe> {
        let w = bytes_to_words(b)?;
        let l = words_to_limbs(&w);
        // Below p: at most 521 bits and not all ones.
        if w[8] >> 9 != 0 {
            return None;
        }
        let mut all = l[8] ^ M57;
        for &x in &l[..8] {
            all |= x ^ M58;
        }
        (all != 0).then_some(Fe(l))
    }

    /// The canonical 66-byte big-endian encoding.
    pub(crate) fn to_be_bytes(self) -> [u8; 66] {
        words_to_bytes(&limbs_to_words(&self.canonical()))
    }
}

/// 66 big-endian bytes as nine little-endian 64-bit words (the top word holds 16 bits).
pub(crate) fn bytes_to_words(b: &[u8]) -> Option<[u64; 9]> {
    if b.len() != 66 {
        return None;
    }
    let mut buf = [0u8; 72];
    buf[6..].copy_from_slice(b);
    let mut w = [0u64; 9];
    for (i, c) in buf.rchunks_exact(8).enumerate() {
        let mut a = [0u8; 8];
        a.copy_from_slice(c);
        w[i] = u64::from_be_bytes(a);
    }
    Some(w)
}

/// Nine little-endian words (below 2⁵²⁸) as 66 big-endian bytes.
pub(crate) fn words_to_bytes(w: &[u64; 9]) -> [u8; 66] {
    let mut buf = [0u8; 72];
    for (i, c) in buf.rchunks_exact_mut(8).enumerate() {
        c.copy_from_slice(&w[i].to_be_bytes());
    }
    let mut out = [0u8; 66];
    out.copy_from_slice(&buf[6..]);
    out
}

/// The low 521 bits of 64-bit words as 58-bit limbs.
fn words_to_limbs(w: &[u64; 9]) -> [u64; 9] {
    let mut l = [0u64; 9];
    for (i, x) in l.iter_mut().enumerate() {
        let bit = 58 * i;
        let (j, off) = (bit / 64, bit % 64);
        let mut v = w[j] >> off;
        if off > 6 && j + 1 < 9 {
            v |= w[j + 1] << (64 - off);
        }
        *x = v & if i == 8 { M57 } else { M58 };
    }
    l
}

/// Strict 58-bit limbs as 64-bit words.
fn limbs_to_words(l: &[u64; 9]) -> [u64; 9] {
    let mut w = [0u64; 9];
    for (i, &x) in l.iter().enumerate() {
        let bit = 58 * i;
        let (j, off) = (bit / 64, bit % 64);
        w[j] |= x << off;
        if off > 6 && j + 1 < 9 {
            w[j + 1] |= x >> (64 - off);
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_fe(rng: &mut crate::rand::ChaChaRng) -> Fe {
        let mut b = [0u8; 66];
        rng.fill(&mut b);
        b[0] &= 1;
        Fe::from_be_bytes(&b).unwrap_or(Fe::ONE)
    }

    /// Bytes round trip, field laws, inversion and square roots on random and edge values.
    #[test]
    fn field_laws() {
        let mut rng = crate::rand::ChaChaRng::from_seed([0x52; 32]);
        let mut p_minus_1 = [0xffu8; 66];
        p_minus_1[0] = 1;
        p_minus_1[65] = 0xfe;
        let pm1 = Fe::from_be_bytes(&p_minus_1).unwrap();
        let mut p = p_minus_1;
        p[65] = 0xff;
        assert!(Fe::from_be_bytes(&p).is_none());
        let mut big = p;
        big[0] = 2;
        assert!(Fe::from_be_bytes(&big).is_none());
        assert_eq!(pm1.to_be_bytes(), p_minus_1);
        assert_eq!(pm1.add(&Fe::ONE).is_zero(), u64::MAX);
        assert_eq!(pm1.mul(&pm1).to_be_bytes(), Fe::ONE.to_be_bytes());
        assert_eq!(pm1.square().to_be_bytes(), Fe::ONE.to_be_bytes());
        let mut vals = vec![Fe::ONE, pm1, Fe::ZERO.sub(&Fe::ONE)];
        for _ in 0..200 {
            vals.push(rand_fe(&mut rng));
        }
        for w in vals.windows(3) {
            let (a, b, c) = (w[0], w[1], w[2]);
            assert_eq!(
                Fe::from_be_bytes(&a.to_be_bytes()).unwrap().0,
                a.canonical()
            );
            assert_eq!(a.square().to_be_bytes(), a.mul(&a).to_be_bytes());
            assert_eq!(a.mul(&b).to_be_bytes(), b.mul(&a).to_be_bytes());
            assert_eq!(
                a.mul(&b.add(&c)).to_be_bytes(),
                a.mul(&b).add(&a.mul(&c)).to_be_bytes()
            );
            assert_eq!(a.sub(&b).add(&b).to_be_bytes(), a.to_be_bytes());
            assert_eq!(
                a.mul_small(3).to_be_bytes(),
                a.add(&a).add(&a).to_be_bytes()
            );
            if a.is_zero() == 0 {
                assert_eq!(a.mul(&a.invert()).to_be_bytes(), Fe::ONE.to_be_bytes());
            }
            let sq = a.square();
            let r = sq.sqrt().unwrap();
            assert_eq!(r.square().to_be_bytes(), sq.to_be_bytes());
            // -1 is not a square (p ≡ 3 mod 4), so -a² is not either.
            if a.is_zero() == 0 {
                assert!(sq.neg().sqrt().is_none());
            }
        }
        // Long chains of lazy operations stay within the bounds (checked by debug overflow
        // checks) and agree with the reduced values.
        let mut x = vals[5];
        for v in &vals {
            let y = x.add(v);
            let y = y.add(&y).sub(&x.mul(v)).neg().mul_small(16).add(&y);
            assert!(y.0[..8].iter().all(|&l| l < (1 << 58) + (1 << 10)));
            assert!(y.0[8] < (1 << 57) + (1 << 10));
            x = y.square();
            assert!(x.0[..8].iter().all(|&l| l < (1 << 58) + (1 << 10)));
            assert!(x.0[8] < (1 << 57) + (1 << 10));
        }
        assert_eq!(Fe::ZERO.invert().is_zero(), u64::MAX);
    }
}
