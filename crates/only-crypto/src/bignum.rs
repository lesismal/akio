//! Run-time-sized unsigned integers (little-endian `u64` limbs) and Montgomery arithmetic
//! modulo an odd modulus, for RSA.
//!
//! The modular operations used with secrets ([`Mont::mul`], [`Mont::pow`], [`Mont::reduce`],
//! the constant computation in [`Mont::new`]) take time that depends only on the limb counts:
//! Montgomery multiplication with a masked final subtraction (BMI2 + ADX assembly in `hw`,
//! portable CIOS otherwise), fixed 5-bit exponent windows with full-table lookups (on AVX-512
//! IFMA in radix 2⁵², `ifma`). Functions named `_vartime` are for public values only.

use crate::ct;
use crate::field::{mont_mul_cios, neg_inv64, redc, sqr_wide};

#[cfg(all(target_arch = "x86_64", not(miri)))]
mod hw;
#[cfg(all(target_arch = "x86_64", not(miri)))]
mod ifma;

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

/// `x mod d` (Knuth's algorithm D, variable time: public values only), `d.len()` limbs; the
/// top limb of `d` must be nonzero.
pub(crate) fn rem_vartime(x: &[u64], d: &[u64]) -> Vec<u64> {
    let k = d.len();
    debug_assert!(k > 0 && d[k - 1] != 0);
    if x.len() < k {
        return resize(x, k);
    }
    if k == 1 {
        let mut r = 0u128;
        for &l in x.iter().rev() {
            r = ((r << 64) | u128::from(l)) % u128::from(d[0]);
        }
        return vec![r as u64];
    }
    // Normalize so that the divisor's top bit is set.
    let s = d[k - 1].leading_zeros();
    let shl = |v: &[u64], extra: usize| -> Vec<u64> {
        let mut out = vec![0u64; v.len() + extra];
        for (i, &l) in v.iter().enumerate() {
            out[i] |= l << s;
            if s > 0 {
                out[i + 1] |= l >> (64 - s);
            }
        }
        out
    };
    let dn = &shl(d, 1)[..k];
    let mut un = shl(x, 1);
    let (dt, ds) = (u128::from(dn[k - 1]), u128::from(dn[k - 2]));
    for j in (0..un.len() - k).rev() {
        let top = (u128::from(un[j + k]) << 64) | u128::from(un[j + k - 1]);
        let mut qhat = top / dt;
        let mut rhat = top % dt;
        while qhat >> 64 != 0 || qhat * ds > ((rhat << 64) | u128::from(un[j + k - 2])) {
            qhat -= 1;
            rhat += dt;
            if rhat >> 64 != 0 {
                break;
            }
        }
        // un[j..=j+k] -= qhat·dn.
        let mut borrow = 0u128;
        let mut carry = 0u128;
        for i in 0..k {
            let p = qhat * u128::from(dn[i]) + carry;
            carry = p >> 64;
            let t = u128::from(un[i + j])
                .wrapping_sub(p & u128::from(u64::MAX))
                .wrapping_sub(borrow);
            un[i + j] = t as u64;
            borrow = (t >> 64) & 1;
        }
        let t = u128::from(un[j + k])
            .wrapping_sub(carry)
            .wrapping_sub(borrow);
        un[j + k] = t as u64;
        if (t >> 64) & 1 != 0 {
            // qhat was one too large: add dn back.
            let mut c = 0u128;
            for i in 0..k {
                let t = u128::from(un[i + j]) + u128::from(dn[i]) + c;
                un[i + j] = t as u64;
                c = t >> 64;
            }
            un[j + k] = un[j + k].wrapping_add(c as u64);
        }
    }
    // Unnormalize the remainder.
    (0..k)
        .map(|i| {
            let hi = if s > 0 { un[i + 1] << (64 - s) } else { 0 };
            (un[i] >> s) | hi
        })
        .collect()
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

/// The first `N` limbs of `a` as a mutable array (callers pass at least `N`).
#[cfg(all(target_arch = "x86_64", not(miri)))]
#[inline(always)]
fn arr_mut<const N: usize>(a: &mut [u64]) -> &mut [u64; N] {
    (&mut a[..N]).try_into().unwrap_or_else(|_| unreachable!())
}

/// The window of [`Mont::pow`] in bits (`2^WINDOW` table entries).
const WINDOW: usize = 5;

/// `out = table[idx]` for a table of `k`-limb entries, reading every entry (constant time in
/// `idx`): AVX2 masks on x86_64 when the limb count is a multiple of 4, else masks of [`ct`].
fn lookup(out: &mut [u64], table: &[u64], k: usize, idx: u64) {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    if k % 4 == 0 && hw::avx2_enabled() {
        hw::lookup(out, table, k, idx);
        return;
    }
    out.fill(0);
    for (j, entry) in table.chunks_exact(k).enumerate() {
        let m = ct::eq(j as u64, idx);
        for (o, &x) in out.iter_mut().zip(entry) {
            *o |= x & m;
        }
    }
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
    /// The context for `m` (odd, > 1, at most [`MAX_LIMBS`] limbs, the top limb nonzero).
    /// Constant time in `m`'s value (it may be a secret prime).
    ///
    /// `R mod m` comes from doubling `2^(64(k-1)) < m` 64 times modulo `m`, and `R² mod m` from
    /// `k` more doublings (`2ᵏ` in Montgomery form) and six Montgomery squarings
    /// (`(2ᵏ)^64 = R`): `64 + k` doublings instead of `128k`.
    pub(crate) fn new(m: &[u64]) -> Option<Mont> {
        let k = m.len();
        if k == 0 || k > MAX_LIMBS || m[0] & 1 == 0 || m[k - 1] == 0 || (k == 1 && m[0] == 1) {
            return None;
        }
        let mut x = vec![0u64; k];
        x[k - 1] = 1; // 2^(64(k-1)) < m (with k = 1: 1 < m)
        let mut t = vec![0u64; k];
        let mut r1 = Vec::new();
        for i in 0..64 + k {
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
            if i + 1 == 64 {
                r1 = x.clone();
            }
        }
        let mut mont = Mont {
            m: m.to_vec(),
            n0: neg_inv64(m[0]),
            r2: Vec::new(),
            r1,
        };
        for _ in 0..6 {
            mont.sqr_into(&mut t, &x);
            x.copy_from_slice(&t);
        }
        mont.r2 = x;
        Some(mont)
    }

    /// The context for a public `m` (as [`new`](Self::new)), faster and in variable time:
    /// `R² mod m` by one long division.
    pub(crate) fn new_public(m: &[u64]) -> Option<Mont> {
        let k = m.len();
        if k == 0 || k > MAX_LIMBS || m[0] & 1 == 0 || m[k - 1] == 0 || (k == 1 && m[0] == 1) {
            return None;
        }
        let mut r2_in = vec![0u64; 2 * k + 1];
        r2_in[2 * k] = 1;
        let r2 = rem_vartime(&r2_in, m);
        let mut mont = Mont {
            m: m.to_vec(),
            n0: neg_inv64(m[0]),
            r2,
            r1: Vec::new(),
        };
        let mut one = vec![0u64; k];
        one[0] = 1;
        mont.r1 = mont.mul(&mont.r2, &one);
        Some(mont)
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
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        if hw::enabled() {
            macro_rules! asm_sizes {
                ($(($n:literal, $w:literal)),*) => {
                    match self.m.len() {
                        $($n => {
                            hw::mont_mul::<$n, $w>(arr_mut(out), arr(a), arr(b), arr(&self.m), self.n0);
                            return;
                        })*
                        _ => {}
                    }
                };
            }
            asm_sizes!((16, 32), (24, 48), (32, 64), (48, 96), (64, 128));
        }
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
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        if hw::enabled() {
            macro_rules! asm_sizes {
                ($(($n:literal, $w:literal)),*) => {
                    match self.m.len() {
                        $($n => {
                            hw::mont_sqr::<$n, $w>(arr_mut(out), arr(a), arr(&self.m), self.n0);
                            return;
                        })*
                        _ => {}
                    }
                };
            }
            asm_sizes!((16, 32), (24, 48), (32, 64));
            if matches!(self.m.len(), 48 | 64) {
                self.mul_into(out, a, a);
                return;
            }
        }
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

    /// The Montgomery form of `x mod m` for any `x` of at most `2k` limbs:
    /// `x_lo·R + x_hi·R²`, three multiplications.
    pub(crate) fn to_mont_wide(&self, x: &[u64]) -> Vec<u64> {
        let k = self.m.len();
        let x = resize(x, 2 * k);
        let lo = self.mul(&x[..k], &self.r2);
        let hi = self.mul(&self.mul(&x[k..], &self.r2), &self.r2);
        self.add(&lo, &hi)
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

    /// `base^e` (Montgomery form in and out), constant time in `base` and `e`'s value: fixed
    /// [`WINDOW`]-bit windows over all of `e`'s limbs, every table entry read on every lookup
    /// ([`lookup`]).
    pub(crate) fn pow(&self, base: &[u64], e: &[u64]) -> Vec<u64> {
        let k = self.m.len();
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        if ifma::enabled() && ifma::digits(k).is_some() && hw::avx2_enabled() {
            return ifma::pow(self, base, e, WINDOW);
        }
        let entries = 1 << WINDOW;
        // table[j] = base^j: even entries by squaring, odd ones by one multiplication.
        let mut table = vec![0u64; entries * k];
        table[..k].copy_from_slice(&self.r1);
        table[k..2 * k].copy_from_slice(base);
        for j in 2..entries {
            let (done, rest) = table.split_at_mut(j * k);
            let out = &mut rest[..k];
            if j % 2 == 0 {
                self.sqr_into(out, &done[j / 2 * k..(j / 2 + 1) * k]);
            } else {
                self.mul_into(out, &done[(j - 1) * k..j * k], base);
            }
        }
        // The window digits from the top; their positions depend only on e's length.
        let bits = 64 * e.len();
        let windows = bits.div_ceil(WINDOW);
        let digit = |w: usize| -> u64 {
            let lo = w * WINDOW;
            let (limb, shift) = (lo / 64, lo % 64);
            let mut d = e[limb] >> shift;
            if shift + WINDOW > 64 && limb + 1 < e.len() {
                d |= e[limb + 1] << (64 - shift);
            }
            d & (entries as u64 - 1)
        };
        let mut r = vec![0u64; k];
        lookup(&mut r, &table, k, digit(windows - 1));
        let mut tmp = vec![0u64; k];
        let mut sel = vec![0u64; k];
        for w in (0..windows - 1).rev() {
            for _ in 0..WINDOW {
                self.sqr_into(&mut tmp, &r);
                r.copy_from_slice(&tmp);
            }
            lookup(&mut sel, &table, k, digit(w));
            self.mul_into(&mut tmp, &r, &sel);
            r.copy_from_slice(&tmp);
        }
        r
    }

    /// `(bp^ep, bq^eq)` in the Montgomery forms of `p` and `q`, as two [`pow`](Self::pow)
    /// calls: the CRT halves of an RSA key. On AVX-512 IFMA, when both moduli have the same
    /// supported size and the exponents the same length, the two run interleaved in one
    /// multiplication loop (their reduction chains overlap).
    pub(crate) fn pow2(
        p: &Self,
        bp: &[u64],
        ep: &[u64],
        q: &Self,
        bq: &[u64],
        eq: &[u64],
    ) -> (Vec<u64>, Vec<u64>) {
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        {
            let k = p.limbs();
            if k == q.limbs()
                && ep.len() == eq.len()
                && ifma::enabled()
                && ifma::digits(k).is_some()
                && hw::avx2_enabled()
            {
                return ifma::pow_x2(p, bp, ep, q, bq, eq, WINDOW);
            }
        }
        (p.pow(bp, ep), q.pow(bq, eq))
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

    /// The assembly (x86_64 with BMI2 + ADX) against the generic CIOS, at every size it
    /// covers, on random values and the edges: 0, 1, m - 1, m - 2, R - 1 and R - m (the first
    /// operand of a multiplication may be anything below R), for moduli with a full and a
    /// short top limb.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn asm_matches_generic() {
        if !crate::cpu::cpu_has(crate::cpu::Feature::Adx) {
            return;
        }
        let mut rng = crate::rand::ChaChaRng::from_seed([17; 32]);
        let mut rand_limbs = |k: usize| (0..k).map(|_| rng.next_u64()).collect::<Vec<u64>>();
        for k in [16usize, 24, 32, 48, 64] {
            for top in [u64::MAX, 1 << 63, 0x8000_0000_0000_0001, 3] {
                let mut m = rand_limbs(k);
                m[0] |= 1;
                m[k - 1] = top | (m[k - 1] & (top >> 1));
                let mont = Mont::new(&m).unwrap();
                let one = {
                    let mut v = vec![0u64; k];
                    v[0] = 1;
                    v
                };
                let mut m1 = m.clone();
                m1[0] -= 1;
                let mut m2 = m.clone();
                m2[0] -= 2;
                let mut r_m = vec![0u64; k];
                ct::sub_limbs(&mut r_m, &vec![0u64; k], &m); // R - m
                let below_m = |v: Vec<u64>| -> Vec<u64> { mont.reduce(&v) };
                let mut below = vec![vec![0u64; k], one, m1, m2];
                let mut any = vec![vec![u64::MAX; k], r_m];
                for _ in 0..8 {
                    below.push(below_m(rand_limbs(k)));
                    any.push(rand_limbs(k));
                }
                any.extend(below.iter().cloned());
                let (mut f, mut g) = (vec![0u64; k], vec![0u64; k]);
                for a in &any {
                    for b in &below {
                        mont.mul_into(&mut f, a, b);
                        mont.mul_into_generic(&mut g, a, b);
                        assert_eq!(f, g, "mul k={k} top={top:x}");
                    }
                }
                for a in &below {
                    mont.sqr_into(&mut f, a);
                    mont.mul_into_generic(&mut g, a, a);
                    assert_eq!(f, g, "sqr k={k} top={top:x}");
                }
                // A chain of squarings and products, as in an exponentiation.
                let mut x = below[5].clone();
                let mut y = x.clone();
                for i in 0..200 {
                    if i % 5 == 4 {
                        mont.mul_into(&mut f, &x, &below[6]);
                        mont.mul_into_generic(&mut g, &y, &below[6]);
                    } else {
                        mont.sqr_into(&mut f, &x);
                        mont.mul_into_generic(&mut g, &y, &y);
                    }
                    x.copy_from_slice(&f);
                    y.copy_from_slice(&g);
                    assert_eq!(x, y, "chain k={k} step {i}");
                }
            }
        }
    }

    /// The IFMA exponentiation against square-and-multiply, at each size it covers, with edge
    /// bases (0, 1, m - 1, R mod m) and exponents (0, 1, all ones), moduli with a full and a
    /// short top limb.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn ifma_pow_matches() {
        if !crate::cpu::cpu_has(crate::cpu::Feature::Ifma)
            || !crate::cpu::cpu_has(crate::cpu::Feature::Avx2)
        {
            return;
        }
        let mut rng = crate::rand::ChaChaRng::from_seed([20; 32]);
        let mut rand_limbs = |k: usize| (0..k).map(|_| rng.next_u64()).collect::<Vec<u64>>();
        for k in [16usize, 24, 32] {
            for top in [u64::MAX, 1 << 63, 5] {
                let mut m = rand_limbs(k);
                m[0] |= 1;
                m[k - 1] = top;
                let mont = Mont::new(&m).unwrap();
                let mut m1 = m.clone();
                m1[0] -= 1;
                let bases = [
                    vec![0u64; k],
                    mont.one(),
                    mont.to_mont(&m1),
                    mont.reduce(&rand_limbs(k)),
                    mont.reduce(&rand_limbs(k)),
                ];
                let mut exps = vec![vec![0u64; k], vec![u64::MAX; k], rand_limbs(k)];
                exps.push({
                    let mut e = vec![0u64; k];
                    e[0] = 1;
                    e
                });
                for b in &bases {
                    for e in &exps {
                        assert_eq!(
                            ifma::pow(&mont, b, e, WINDOW),
                            mont.pow_vartime(b, e),
                            "k={k} top={top:x}"
                        );
                    }
                }
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn ifma_pow_x2_matches() {
        if !crate::cpu::cpu_has(crate::cpu::Feature::Ifma)
            || !crate::cpu::cpu_has(crate::cpu::Feature::Avx2)
        {
            return;
        }
        let mut rng = crate::rand::ChaChaRng::from_seed([22; 32]);
        let mut rand_limbs = |k: usize| (0..k).map(|_| rng.next_u64()).collect::<Vec<u64>>();
        for k in [16usize, 24, 32] {
            for (top_p, top_q) in [(u64::MAX, 1 << 63), (5, u64::MAX), (1 << 63, 5)] {
                let mut mp = rand_limbs(k);
                mp[0] |= 1;
                mp[k - 1] = top_p;
                let mut mq = rand_limbs(k);
                mq[0] |= 1;
                mq[k - 1] = top_q;
                let (p, q) = (Mont::new(&mp).unwrap(), Mont::new(&mq).unwrap());
                let edge = |m: &Mont, raw: &[u64]| {
                    let mut m1 = raw.to_vec();
                    m1[0] -= 1;
                    m.to_mont(&m1)
                };
                let bases = [
                    (vec![0u64; k], q.one()),
                    (p.one(), edge(&q, &mq)),
                    (edge(&p, &mp), vec![0u64; k]),
                    (p.reduce(&rand_limbs(k)), q.reduce(&rand_limbs(k))),
                ];
                let mut one = vec![0u64; k];
                one[0] = 1;
                let exps = [
                    (vec![0u64; k], vec![u64::MAX; k]),
                    (rand_limbs(k), rand_limbs(k)),
                    (one.clone(), rand_limbs(k)),
                    (vec![u64::MAX; k], one),
                ];
                for (bp, bq) in &bases {
                    for (ep, eq) in &exps {
                        assert_eq!(
                            ifma::pow_x2(&p, bp, ep, &q, bq, eq, WINDOW),
                            (p.pow_vartime(bp, ep), q.pow_vartime(bq, eq)),
                            "k={k} top={top_p:x}/{top_q:x}"
                        );
                    }
                }
            }
        }
    }

    /// Time per Montgomery multiplication and squaring at each fixed size (the path in use:
    /// assembly, or portable with `ONLY_CRYPTO_PORTABLE=1`):
    /// `cargo test --release -p only-crypto --lib bignum::tests::timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing, run by hand"]
    fn timing() {
        let mut rng = crate::rand::ChaChaRng::from_seed([18; 32]);
        for k in [16usize, 24, 32, 48, 64] {
            let mut m: Vec<u64> = (0..k).map(|_| rng.next_u64()).collect();
            m[0] |= 1;
            m[k - 1] |= 1 << 63;
            let mont = Mont::new(&m).unwrap();
            let a = mont.reduce(&(0..k).map(|_| rng.next_u64()).collect::<Vec<u64>>());
            let mut x = a.clone();
            let mut y = vec![0u64; k];
            let iters = 2_000_000 / k;
            let t = std::time::Instant::now();
            for _ in 0..iters {
                mont.mul_into(&mut y, &x, &a);
                mont.mul_into(&mut x, &y, &a);
            }
            let mul = t.elapsed().as_nanos() as f64 / (2 * iters) as f64;
            let t = std::time::Instant::now();
            for _ in 0..iters {
                mont.sqr_into(&mut y, &x);
                mont.sqr_into(&mut x, &y);
            }
            let sqr = t.elapsed().as_nanos() as f64 / (2 * iters) as f64;
            std::hint::black_box(&x);
            println!("{:>5} bits: mul {mul:8.1} ns  sqr {sqr:8.1} ns", 64 * k);
        }
    }

    /// `new_public` (long division) and `new` (doublings and squarings) agree, and match
    /// plain doubling, for several sizes and top limbs.
    #[test]
    fn r2_constructions() {
        let mut rng = crate::rand::ChaChaRng::from_seed([19; 32]);
        for k in [1usize, 2, 3, 5, 16, 24, 32, 33, 48, 64] {
            for top in [u64::MAX, 1 << 63, 1, 0x1234_5678] {
                let mut m: Vec<u64> = (0..k).map(|_| rng.next_u64()).collect();
                m[0] |= 1;
                m[k - 1] = if k == 1 { m[0] | 3 } else { top };
                let a = Mont::new(&m).unwrap();
                let b = Mont::new_public(&m).unwrap();
                // Reference: 2^(128k) mod m by plain doubling (variable time is fine here).
                let mut x = vec![0u64; k];
                x[0] = 1;
                let mut r1 = Vec::new();
                for i in 0..128 * k {
                    let mut carry = 0;
                    for l in &mut x {
                        let v = *l;
                        *l = (v << 1) | carry;
                        carry = v >> 63;
                    }
                    if carry == 1 || !lt_vartime(&x, &m) {
                        let mut t = vec![0u64; k];
                        ct::sub_limbs(&mut t, &x, &m);
                        x = t;
                    }
                    if i + 1 == 64 * k {
                        r1 = x.clone();
                    }
                }
                assert_eq!(a.r2, x, "new r2 k={k}");
                assert_eq!(b.r2, x, "new_public r2 k={k}");
                assert_eq!(a.r1, r1, "new r1 k={k}");
                assert_eq!(b.r1, r1, "new_public r1 k={k}");
                assert_eq!(a.n0, b.n0);
            }
        }
        // rem_vartime against u128 arithmetic.
        for _ in 0..1000 {
            let x = [rng.next_u64(), rng.next_u64()];
            let d = rng.next_u64() >> (rng.next_u64() % 64) | 1;
            let want = ((u128::from(x[1]) << 64) | u128::from(x[0])) % u128::from(d);
            assert_eq!(rem_vartime(&x, &[d]), vec![want as u64]);
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
