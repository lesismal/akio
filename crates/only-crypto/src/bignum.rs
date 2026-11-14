//! Run-time-sized unsigned integers (little-endian `u64` limbs) and Montgomery arithmetic
//! modulo an odd modulus, for RSA.
//!
//! The modular operations used with secrets ([`Mont::mul`], [`Mont::pow`], [`Mont::reduce`],
//! the constant computation in [`Mont::new`]) take time that depends only on the limb counts:
//! CIOS Montgomery multiplication with a masked final subtraction, fixed 4-bit exponent windows
//! with full-table lookups. Functions named `_vartime` are for public values only.

use crate::ct;
use crate::field::{mont_mul_cios, neg_inv64, redc, sqr_wide};

/// The largest modulus: 8192 bits.
pub(crate) const MAX_LIMBS: usize = 128;

/// Big-endian bytes as `k` little-endian limbs; `None` if the value needs more.
pub(crate) fn from_be(b: &[u8], k: usize) -> Option<Vec<u64>> {
    let skip = b.iter().take_while(|&&x| x == 0).count();
    let b = &b[skip..];
    if b.len() > 8 * k {
        return None;
    }
    let mut l = vec![0u64; k];
    for (i, &byte) in b.iter().rev().enumerate() {
        l[i / 8] |= u64::from(byte) << (8 * (i % 8));
    }
    Some(l)
}

/// Limbs as exactly `len` big-endian bytes (the value must fit).
pub(crate) fn to_be(l: &[u64], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for i in 0..len {
        let limb = i / 8;
        if limb < l.len() {
            out[len - 1 - i] = (l[limb] >> (8 * (i % 8))) as u8;
        }
    }
    out
}

/// The number of significant bits (variable time: public values).
pub(crate) fn bit_len_vartime(l: &[u64]) -> usize {
    for i in (0..l.len()).rev() {
        if l[i] != 0 {
            return 64 * i + 64 - l[i].leading_zeros() as usize;
        }
    }
    0
}

/// `a < b` for equal-length limbs (variable time: public values).
pub(crate) fn lt_vartime(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a · b` (schoolbook), `a.len() + b.len()` limbs.
pub(crate) fn mul_plain(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut r = vec![0u64; a.len() + b.len()];
    for (i, &ai) in a.iter().enumerate() {
        let mut c = 0u64;
        for (j, &bj) in b.iter().enumerate() {
            let x = u128::from(r[i + j]) + u128::from(ai) * u128::from(bj) + u128::from(c);
            r[i + j] = x as u64;
            c = (x >> 64) as u64;
        }
        r[i + b.len()] = c;
    }
    r
}

/// `a` zero-extended or truncated to `k` limbs.
pub(crate) fn resize(a: &[u64], k: usize) -> Vec<u64> {
    let mut v = a.to_vec();
    v.resize(k, 0);
    v
}

/// The first `N` limbs of `a` as an array (callers pass at least `N`).
#[inline(always)]
fn arr<const N: usize>(a: &[u64]) -> &[u64; N] {
    a[..N].try_into().unwrap_or_else(|_| unreachable!())
}

/// Montgomery context for an odd modulus `m` of `k` limbs, `R = 2^(64k)`.
#[derive(Clone, Debug)]
pub(crate) struct Mont {
    pub(crate) m: Vec<u64>,
    n0: u64,
    /// `R² mod m`.
    r2: Vec<u64>,
    /// `R mod m` (Montgomery 1).
    r1: Vec<u64>,
}

impl Mont {
    /// The context for `m` (odd, > 1, at most [`MAX_LIMBS`] limbs). Constant time in `m`'s
    /// value (it may be a secret prime).
    pub(crate) fn new(m: &[u64]) -> Option<Mont> {
        let k = m.len();
        if k == 0 || k > MAX_LIMBS || m[0] & 1 == 0 || (k == 1 && m[0] == 1) {
            return None;
        }
        let mut x = vec![0u64; k];
        x[0] = 1;
        let mut t = vec![0u64; k];
        let mut r1 = Vec::new();
        for i in 0..128 * k {
            // x = 2x mod m.
            let mut carry = 0;
            for l in &mut x {
                let v = *l;
                *l = (v << 1) | carry;
                carry = v >> 63;
            }
            let borrow = ct::sub_limbs(&mut t, &x, m);
            // Keep t (= 2x - m) when the doubling carried out or the subtraction did not borrow.
            let take = ct::mask(carry | (1 ^ borrow));
            ct::assign(take, &mut x, &t);
            if i + 1 == 64 * k {
                r1 = x.clone();
            }
        }
        Some(Mont {
            m: m.to_vec(),
            n0: neg_inv64(m[0]),
            r2: x,
            r1,
        })
    }

    pub(crate) fn limbs(&self) -> usize {
        self.m.len()
    }

    /// The Montgomery form of 1.
    pub(crate) fn one(&self) -> Vec<u64> {
        self.r1.clone()
    }

    /// `out = a·b·R⁻¹ mod m` for `a < R`, `b < m` (CIOS; fixed-size code for the limb counts
    /// of 2048- to 8192-bit RSA and their CRT halves).
    pub(crate) fn mul_into(&self, out: &mut [u64], a: &[u64], b: &[u64]) {
        macro_rules! fixed {
            ($($n:literal),*) => {
                match self.m.len() {
                    $($n => {
                        let r = mont_mul_cios::<$n>(arr(a), arr(b), arr(&self.m), self.n0);
                        out[..$n].copy_from_slice(&r);
                        return;
                    })*
                    _ => {}
                }
            };
        }
        fixed!(16, 24, 32, 48, 64);
        self.mul_into_generic(out, a, b);
    }

    /// `out = a²·R⁻¹ mod m` for `a < m`: a half-size product plus Montgomery reduction for the
    /// common limb counts, else [`mul_into`](Self::mul_into).
    pub(crate) fn sqr_into(&self, out: &mut [u64], a: &[u64]) {
        macro_rules! fixed {
            ($(($n:literal, $w:literal)),*) => {
                match self.m.len() {
                    $($n => {
                        let r = redc::<$n, $w>(sqr_wide::<$n, $w>(arr(a)), arr(&self.m), self.n0);
                        out[..$n].copy_from_slice(&r);
                        return;
                    })*
                    _ => {}
                }
            };
        }
        fixed!((16, 32), (24, 48), (32, 64), (48, 96), (64, 128));
        self.mul_into_generic(out, a, a);
    }

    /// CIOS for any limb count.
    fn mul_into_generic(&self, out: &mut [u64], a: &[u64], b: &[u64]) {
        let k = self.m.len();
        let m = &self.m;
        let mut t = [0u64; MAX_LIMBS + 2];
        for &bi in &b[..k] {
            let mut c = 0u64;
            for j in 0..k {
                let x = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + u128::from(c);
                t[j] = x as u64;
                c = (x >> 64) as u64;
            }
            let x = u128::from(t[k]) + u128::from(c);
            t[k] = x as u64;
            t[k + 1] = (x >> 64) as u64;
            let q = t[0].wrapping_mul(self.n0);
            let x = u128::from(t[0]) + u128::from(q) * u128::from(m[0]);
            let mut c = (x >> 64) as u64;
            for j in 1..k {
                let x = u128::from(t[j]) + u128::from(q) * u128::from(m[j]) + u128::from(c);
                t[j - 1] = x as u64;
                c = (x >> 64) as u64;
            }
            let x = u128::from(t[k]) + u128::from(c);
            t[k - 1] = x as u64;
            t[k] = t[k + 1] + (x >> 64) as u64;
        }
        let borrow = ct::sub_limbs(&mut out[..k], &t[..k], m);
        let keep_t = ct::mask(borrow & (1 ^ (t[k] & 1)));
        ct::assign(keep_t, &mut out[..k], &t[..k]);
    }

    pub(crate) fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut out = vec![0u64; self.m.len()];
        self.mul_into(&mut out, a, b);
        out
    }

    /// Into Montgomery form (`a < R`).
    pub(crate) fn to_mont(&self, a: &[u64]) -> Vec<u64> {
        self.mul(a, &self.r2)
    }

    /// Out of Montgomery form.
    pub(crate) fn out_of_mont(&self, a: &[u64]) -> Vec<u64> {
        let mut one = vec![0u64; self.m.len()];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// `x mod m` (normal form) for `x < m·R`, given in at most `2k` limbs.
    pub(crate) fn reduce(&self, x: &[u64]) -> Vec<u64> {
        let k = self.m.len();
        let x = resize(x, 2 * k);
        // x = lo + hi·R: lo mod m = REDC(lo·R²)·1, and hi·R mod m = REDC(hi·R²).
        let lo = self.out_of_mont(&self.mul(&x[..k], &self.r2));
        let hi_r = self.mul(&x[k..], &self.r2);
        self.add(&lo, &hi_r)
    }

    /// `x mod m` (normal form) for any `x`: Horner's rule over `k`-limb chunks, from the top,
    /// each step a [`reduce`](Self::reduce) of `acc·R + chunk < m·R`.
    pub(crate) fn reduce_any(&self, x: &[u64]) -> Vec<u64> {
        let k = self.m.len();
        let chunks = x.len().div_ceil(k).max(1);
        let x = resize(x, chunks * k);
        let mut acc = vec![0u64; k];
        for c in (0..chunks).rev() {
            let mut wide = x[c * k..(c + 1) * k].to_vec();
            wide.extend_from_slice(&acc);
            acc = self.reduce(&wide);
        }
        acc
    }

    /// `a + b mod m` for `a, b < m`.
    pub(crate) fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let k = self.m.len();
        let mut s = vec![0u64; k];
        let carry = ct::add_limbs(&mut s, a, b);
        let mut r = vec![0u64; k];
        let borrow = ct::sub_limbs(&mut r, &s, &self.m);
        ct::assign(ct::mask(borrow & (1 ^ carry)), &mut r, &s);
        r
    }

    /// `a - b mod m` for `a, b < m`.
    pub(crate) fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let k = self.m.len();
        let mut d = vec![0u64; k];
        let borrow = ct::sub_limbs(&mut d, a, b);
        let mask = ct::mask(borrow);
        let pm: Vec<u64> = self.m.iter().map(|&x| x & mask).collect();
        let mut r = vec![0u64; k];
        ct::add_limbs(&mut r, &d, &pm);
        r
    }

    /// `base^e` (Montgomery form in and out), constant time in `base` and `e`'s value: 4-bit
    /// windows over all of `e`'s limbs, each table entry read on every lookup.
    pub(crate) fn pow(&self, base: &[u64], e: &[u64]) -> Vec<u64> {
        let k = self.m.len();
        let mut table = vec![self.one(); 16];
        for j in 1..16 {
            table[j] = self.mul(&table[j - 1], base);
        }
        let mut r = self.one();
        let mut tmp = vec![0u64; k];
        let mut sel = vec![0u64; k];
        for i in (0..16 * e.len()).rev() {
            for _ in 0..4 {
                self.sqr_into(&mut tmp, &r);
                r.copy_from_slice(&tmp);
            }
            let nib = (e[i / 16] >> (4 * (i % 16))) & 15;
            sel.fill(0);
            for (j, entry) in table.iter().enumerate() {
                ct::assign(ct::eq(j as u64, nib), &mut sel, entry);
            }
            self.mul_into(&mut tmp, &r, &sel);
            r.copy_from_slice(&tmp);
        }
        r
    }

    /// `base^e` (Montgomery form) for a public exponent, square-and-multiply.
    pub(crate) fn pow_vartime(&self, base: &[u64], e: &[u64]) -> Vec<u64> {
        let mut r = self.one();
        let bits = bit_len_vartime(e);
        let mut tmp = vec![0u64; self.m.len()];
        for i in (0..bits).rev() {
            self.sqr_into(&mut tmp, &r);
            r.copy_from_slice(&tmp);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.mul(&r, base);
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed-size multiplication and squaring agree with the generic CIOS.
    #[test]
    fn fixed_sizes() {
        let mut rng = crate::rand::ChaChaRng::from_seed([16; 32]);
        for k in [16usize, 24, 32, 48, 64] {
            let mut m = vec![0u64; k];
            for x in &mut m {
                *x = rng.next_u64();
            }
            m[0] |= 1;
            m[k - 1] |= 1 << 63;
            let mont = Mont::new(&m).unwrap();
            let mut a = vec![0u64; k];
            let mut b = vec![0u64; k];
            for (x, y) in a.iter_mut().zip(b.iter_mut()) {
                *x = rng.next_u64();
                *y = rng.next_u64();
            }
            a[k - 1] >>= 1; // below m
            b[k - 1] >>= 1;
            let (mut f, mut g) = (vec![0u64; k], vec![0u64; k]);
            mont.mul_into(&mut f, &a, &b);
            mont.mul_into_generic(&mut g, &a, &b);
            assert_eq!(f, g, "mul {k}");
            mont.sqr_into(&mut f, &a);
            mont.mul_into_generic(&mut g, &a, &a);
            assert_eq!(f, g, "sqr {k}");
        }
    }

    #[test]
    fn small_modulus() {
        // m = 2^64 + 13 (two limbs).
        let m = Mont::new(&[13, 1]).unwrap();
        let a = m.to_mont(&[5, 0]);
        let b = m.to_mont(&[7, 0]);
        assert_eq!(m.out_of_mont(&m.mul(&a, &b)), vec![35, 0]);
        // 3^(m-1) = 1 if m is prime; check pow and pow_vartime agree anyway.
        let three = m.to_mont(&[3, 0]);
        let e = [12, 1];
        assert_eq!(m.pow(&three, &e), m.pow_vartime(&three, &e));
        // reduce: (2^128 + 5) mod m.
        let r = m.reduce(&[5, 0, 1, 0]);
        // 2^64 ≡ -13, 2^128 ≡ 169.
        assert_eq!(r, vec![174, 0]);
        assert_eq!(m.sub(&[1, 0], &[2, 0]), vec![12, 1]);
        assert_eq!(m.add(&[12, 1], &[2, 0]), vec![1, 0]);
        assert_eq!(
            from_be(&[1, 0, 0, 0, 0, 0, 0, 0, 2], 2).unwrap(),
            vec![2, 1]
        );
        assert_eq!(to_be(&[2, 1], 9), vec![1, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(mul_plain(&[u64::MAX], &[u64::MAX]), vec![1, u64::MAX - 1]);
    }
}
