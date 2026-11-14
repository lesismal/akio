//! Fixed-width arithmetic modulo an odd prime in Montgomery form, generic over the number of
//! 64-bit limbs: the P-256 and P-384 base fields and the scalar fields of P-256, P-384 and
//! Ed25519.
//!
//! Every operation runs in time independent of the values: Montgomery multiplication (CIOS)
//! with a final masked subtraction, masked additions and subtractions, inversion and square
//! roots by exponentiation with a fixed public exponent. The constants a modulus needs (`R mod
//! p`, `R² mod p`, `R³ mod p`, `-p⁻¹ mod 2⁶⁴`, the exponents) are computed at compile time from
//! the modulus alone.

use std::marker::PhantomData;

use crate::ct;

/// An odd modulus of `N` limbs (little-endian), with its derived Montgomery constants.
pub(crate) trait Modulus<const N: usize>: Copy + Send + Sync + 'static {
    /// The modulus.
    const P: [u64; N];
    /// `-P⁻¹ mod 2⁶⁴`.
    const N0: u64 = neg_inv64(Self::P[0]);
    /// `R mod P` (the Montgomery form of 1), `R = 2^(64N)`.
    const R1: [u64; N] = pow2_mod(&Self::P, 64 * N);
    /// `R² mod P`.
    const R2: [u64; N] = pow2_mod(&Self::P, 128 * N);
    /// `R³ mod P`.
    const R3: [u64; N] = pow2_mod(&Self::P, 192 * N);
    /// `P - 2`: the inversion exponent.
    const P_MINUS_2: [u64; N] = sub_small(&Self::P, 2);
}

/// `-a⁻¹ mod 2⁶⁴` for odd `a` (Newton iteration).
pub(crate) const fn neg_inv64(a: u64) -> u64 {
    let mut x = 1u64;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg()
}

/// `2^k mod p` by repeated doubling (compile time only).
const fn pow2_mod<const N: usize>(p: &[u64; N], k: usize) -> [u64; N] {
    // Start from 1 (p > 1).
    let mut x = [0u64; N];
    x[0] = 1;
    mul_pow2_mod(x, p, k)
}

/// `x · 2^k mod p` for `x < p` by repeated doubling (compile time only).
pub(crate) const fn mul_pow2_mod<const N: usize>(
    mut x: [u64; N],
    p: &[u64; N],
    k: usize,
) -> [u64; N] {
    let mut i = 0;
    while i < k {
        // x = 2x mod p, with x < p.
        let mut carry = 0u64;
        let mut j = 0;
        while j < N {
            let v = x[j];
            x[j] = (v << 1) | carry;
            carry = v >> 63;
            j += 1;
        }
        // Subtract p if x >= p (or the doubling carried out).
        let mut t = [0u64; N];
        let mut borrow = 0u64;
        j = 0;
        while j < N {
            let (d, b1) = x[j].overflowing_sub(p[j]);
            let (d, b2) = d.overflowing_sub(borrow);
            t[j] = d;
            borrow = (b1 | b2) as u64;
            j += 1;
        }
        if carry == 1 || borrow == 0 {
            x = t;
        }
        i += 1;
    }
    x
}

/// `a - s` for a small `s` with `a >= s` (compile time only).
pub(crate) const fn sub_small<const N: usize>(a: &[u64; N], s: u64) -> [u64; N] {
    let mut r = *a;
    let mut borrow = s;
    let mut i = 0;
    while i < N {
        let (d, b) = r[i].overflowing_sub(borrow);
        r[i] = d;
        borrow = b as u64;
        i += 1;
    }
    r
}

/// `(a + s) >> shift` for a small `s` and `shift < 64` (compile time only; no overflow out of
/// the top limb for the moduli used here).
pub(crate) const fn add_small_shr<const N: usize>(a: &[u64; N], s: u64, shift: u32) -> [u64; N] {
    let mut r = *a;
    let mut carry = s;
    let mut i = 0;
    while i < N {
        let (v, c) = r[i].overflowing_add(carry);
        r[i] = v;
        carry = c as u64;
        i += 1;
    }
    let mut out = [0u64; N];
    i = 0;
    while i < N {
        let hi = if i + 1 < N { r[i + 1] } else { carry };
        out[i] = (r[i] >> shift) | if shift == 0 { 0 } else { hi << (64 - shift) };
        i += 1;
    }
    out
}

/// An element of `Z/P` in Montgomery form (`a·R mod P`), always fully reduced.
pub(crate) struct Fe<M: Modulus<N>, const N: usize> {
    pub(crate) l: [u64; N],
    _m: PhantomData<M>,
}

impl<M: Modulus<N>, const N: usize> Clone for Fe<M, N> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<M: Modulus<N>, const N: usize> Copy for Fe<M, N> {}

impl<M: Modulus<N>, const N: usize> std::fmt::Debug for Fe<M, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fe(..)")
    }
}

impl<M: Modulus<N>, const N: usize> Fe<M, N> {
    const fn raw(l: [u64; N]) -> Self {
        Fe { l, _m: PhantomData }
    }

    pub(crate) const ZERO: Self = Self::raw([0; N]);

    /// The element with canonical limbs `a < P`, converted at compile time (`a·R` by doubling).
    pub(crate) const fn from_canonical_const(a: [u64; N]) -> Self {
        Self::raw(mul_pow2_mod(a, &M::P, 64 * N))
    }
    pub(crate) const ONE: Self = Self::raw(M::R1);

    /// Montgomery multiplication `a·b·R⁻¹ mod P` (CIOS). Needs `a < R`, `b < P`.
    #[inline]
    fn mont_mul(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let p = &M::P;
        let mut t = [0u64; N];
        let mut t_n = 0u64;
        for &bi in b {
            let mut c = 0u64;
            for j in 0..N {
                let x = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + u128::from(c);
                t[j] = x as u64;
                c = (x >> 64) as u64;
            }
            let x = u128::from(t_n) + u128::from(c);
            t_n = x as u64;
            let t_n1 = (x >> 64) as u64;

            let m = t[0].wrapping_mul(M::N0);
            let x = u128::from(t[0]) + u128::from(m) * u128::from(p[0]);
            let mut c = (x >> 64) as u64;
            for j in 1..N {
                let x = u128::from(t[j]) + u128::from(m) * u128::from(p[j]) + u128::from(c);
                t[j - 1] = x as u64;
                c = (x >> 64) as u64;
            }
            let x = u128::from(t_n) + u128::from(c);
            t[N - 1] = x as u64;
            t_n = t_n1 + (x >> 64) as u64;
        }
        // t < 2P: subtract P unless that borrows (and nothing carried out).
        let mut r = [0u64; N];
        let borrow = ct::sub_limbs(&mut r, &t, p);
        let keep_t = ct::mask(borrow & (1 ^ (t_n & 1)));
        ct::assign(keep_t, &mut r, &t);
        r
    }

    #[inline]
    pub(crate) fn mul(&self, b: &Self) -> Self {
        Self::raw(Self::mont_mul(&self.l, &b.l))
    }

    #[inline]
    pub(crate) fn square(&self) -> Self {
        self.mul(self)
    }

    #[inline]
    pub(crate) fn add(&self, b: &Self) -> Self {
        let mut s = [0u64; N];
        let carry = ct::add_limbs(&mut s, &self.l, &b.l);
        let mut r = [0u64; N];
        let borrow = ct::sub_limbs(&mut r, &s, &M::P);
        // Keep s when s < P, i.e. the subtraction borrowed and the addition did not carry.
        ct::assign(ct::mask(borrow & (1 ^ carry)), &mut r, &s);
        Self::raw(r)
    }

    #[inline]
    pub(crate) fn sub(&self, b: &Self) -> Self {
        let mut d = [0u64; N];
        let borrow = ct::sub_limbs(&mut d, &self.l, &b.l);
        let m = ct::mask(borrow);
        let mut pm = [0u64; N];
        for (x, &p) in pm.iter_mut().zip(M::P.iter()) {
            *x = p & m;
        }
        let mut r = [0u64; N];
        ct::add_limbs(&mut r, &d, &pm);
        Self::raw(r)
    }

    #[inline]
    pub(crate) fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    #[inline]
    pub(crate) fn double(&self) -> Self {
        self.add(self)
    }

    /// `u64::MAX` if zero.
    #[inline]
    pub(crate) fn is_zero(&self) -> u64 {
        ct::is_zero_limbs(&self.l)
    }

    /// `u64::MAX` if equal.
    #[inline]
    pub(crate) fn ct_eq(&self, b: &Self) -> u64 {
        let mut acc = 0;
        for i in 0..N {
            acc |= self.l[i] ^ b.l[i];
        }
        ct::is_zero(acc)
    }

    /// `a` where `m` is all ones, else `b`.
    #[inline]
    pub(crate) fn select(m: u64, a: &Self, b: &Self) -> Self {
        let mut l = b.l;
        ct::assign(m, &mut l, &a.l);
        Self::raw(l)
    }

    /// `self^e` for a public exponent `e` (little-endian limbs), most significant bit first.
    /// The sequence of operations depends only on `e`.
    pub(crate) fn pow_vartime_exp(&self, e: &[u64; N]) -> Self {
        let mut r = Self::ONE;
        for i in (0..N).rev() {
            for bit in (0..64).rev() {
                r = r.square();
                if (e[i] >> bit) & 1 == 1 {
                    r = r.mul(self);
                }
            }
        }
        r
    }

    /// `self⁻¹` (0 maps to 0), by Fermat's little theorem: constant time.
    pub(crate) fn invert(&self) -> Self {
        self.pow_vartime_exp(&M::P_MINUS_2)
    }

    /// The Montgomery form of the integer with little-endian limbs `a` (any value below `R`).
    #[inline]
    pub(crate) fn from_limbs_reduce(a: &[u64; N]) -> Self {
        Self::raw(Self::mont_mul(a, &M::R2))
    }

    /// The element `lo + hi·R mod P` for arbitrary `lo`, `hi < R`: reduces a double-width
    /// integer (a 512-bit hash for Ed25519 scalars).
    pub(crate) fn from_wide(lo: &[u64; N], hi: &[u64; N]) -> Self {
        let a = Self::raw(Self::mont_mul(lo, &M::R2));
        let b = Self::raw(Self::mont_mul(hi, &M::R3));
        a.add(&b)
    }

    /// The canonical integer as little-endian limbs.
    #[inline]
    pub(crate) fn to_limbs(self) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        Self::mont_mul(&self.l, &one)
    }

    /// From a little-endian limb integer, if it is below `P`; the check takes constant time
    /// (the result's `Option`-ness is public).
    pub(crate) fn from_limbs_canonical(a: &[u64; N]) -> Option<Self> {
        if ct::lt_limbs(a, &M::P) == 0 {
            return None;
        }
        Some(Self::from_limbs_reduce(a))
    }

    /// From `8N` big-endian bytes, if below `P`.
    pub(crate) fn from_be_bytes(b: &[u8]) -> Option<Self> {
        Self::from_limbs_canonical(&be_to_limbs(b)?)
    }

    /// From `8N` big-endian bytes, reduced modulo `P` (any value).
    pub(crate) fn from_be_bytes_reduce(b: &[u8]) -> Option<Self> {
        Some(Self::from_limbs_reduce(&be_to_limbs(b)?))
    }

    /// The canonical big-endian encoding (`8N` bytes) into `out`.
    pub(crate) fn write_be(&self, out: &mut [u8]) {
        limbs_to_be(&self.to_limbs(), out);
    }

    /// From `8N` little-endian bytes, if below `P`.
    pub(crate) fn from_le_bytes(b: &[u8]) -> Option<Self> {
        Self::from_limbs_canonical(&le_to_limbs(b)?)
    }

    /// The canonical little-endian encoding (`8N` bytes) into `out`.
    pub(crate) fn write_le(&self, out: &mut [u8]) {
        for (i, l) in self.to_limbs().iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&l.to_le_bytes());
        }
    }
}

/// `8N` big-endian bytes as little-endian limbs.
pub(crate) fn be_to_limbs<const N: usize>(b: &[u8]) -> Option<[u64; N]> {
    if b.len() != 8 * N {
        return None;
    }
    let mut l = [0u64; N];
    for (i, c) in b.rchunks_exact(8).enumerate() {
        l[i] = u64::from_be_bytes(c.try_into().ok()?);
    }
    Some(l)
}

/// `8N` little-endian bytes as little-endian limbs.
pub(crate) fn le_to_limbs<const N: usize>(b: &[u8]) -> Option<[u64; N]> {
    if b.len() != 8 * N {
        return None;
    }
    let mut l = [0u64; N];
    for (i, c) in b.chunks_exact(8).enumerate() {
        l[i] = u64::from_le_bytes(c.try_into().ok()?);
    }
    Some(l)
}

/// Little-endian limbs as `8N` big-endian bytes.
pub(crate) fn limbs_to_be<const N: usize>(l: &[u64; N], out: &mut [u8]) {
    for (i, c) in out.rchunks_exact_mut(8).enumerate() {
        c.copy_from_slice(&l[i].to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct P256;
    impl Modulus<4> for P256 {
        const P: [u64; 4] = [
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_ffff,
            0x0000_0000_0000_0000,
            0xffff_ffff_0000_0001,
        ];
    }
    type F = Fe<P256, 4>;

    #[test]
    fn constants() {
        assert_eq!(P256::N0.wrapping_mul(P256::P[0]), u64::MAX); // -1
        // R mod p for P-256 is 2^256 - p.
        let mut r1 = [0u64; 4];
        ct::sub_limbs(&mut r1, &[0; 4], &P256::P);
        assert_eq!(P256::R1, r1);
    }

    #[test]
    fn arithmetic() {
        let a = F::from_limbs_reduce(&[5, 0, 0, 0]);
        let b = F::from_limbs_reduce(&[7, 0, 0, 0]);
        assert_eq!(a.mul(&b).to_limbs(), [35, 0, 0, 0]);
        assert_eq!(a.add(&b).to_limbs(), [12, 0, 0, 0]);
        assert_eq!(b.sub(&a).to_limbs(), [2, 0, 0, 0]);
        let m = a.sub(&b); // -2
        assert_eq!(m.add(&b).to_limbs(), [5, 0, 0, 0]);
        assert_eq!(a.invert().mul(&a).to_limbs(), [1, 0, 0, 0]);
        assert_eq!(F::ZERO.invert().to_limbs(), [0; 4]);
        let pm1 = sub_small(&P256::P, 1);
        let x = F::from_limbs_canonical(&pm1).unwrap();
        assert_eq!(x.square().to_limbs(), [1, 0, 0, 0]);
        assert!(F::from_limbs_canonical(&P256::P).is_none());
        // from_wide: (lo + hi*R) mod p with hi = 1, lo = 0 is R mod p.
        let w = F::from_wide(&[0; 4], &[1, 0, 0, 0]);
        assert_eq!(w.to_limbs(), P256::R1);
        let w = F::from_wide(&[u64::MAX; 4], &[0; 4]);
        let mut e = [0u64; 4];
        ct::sub_limbs(&mut e, &[u64::MAX; 4], &P256::P);
        assert_eq!(w.to_limbs(), e);
    }

    #[test]
    fn shr() {
        assert_eq!(add_small_shr(&[3, 0], 1, 2), [1, 0]);
        assert_eq!(add_small_shr(&[u64::MAX, u64::MAX], 1, 2), [0, 1 << 62]);
    }
}
