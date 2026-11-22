//! Constant-time modular inversion for moduli below `2²⁵⁶` by Bernstein–Yang divsteps
//! ("Fast constant-time gcd computation and modular inversion", 2019), in the half-delta form
//! and signed 62-bit limbs that libsecp256k1's `modinv64` uses: ten batches of 59 divsteps
//! (590, enough for any input below a modulus under `2²⁵⁶`), each batch run on the low bits
//! of `f` and `g` as a 2×2 transition matrix, then applied to the full `f`, `g` and to the
//! Bézout coefficients `d`, `e` (kept in `(-2m, m)` by adding multiples of `m` that clear
//! their low 62 bits).
//!
//! Constant time: every batch runs the same 59 steps, the conditions of a step (the sign of
//! `ζ`, the low bit of `g`) become masks through [`ct::mask`] (a `black_box` barrier, so the
//! optimizer cannot turn them back into branches), and the rest is straight-line arithmetic on
//! fixed-size limbs. About a third of the cost of a Fermat inversion (255 squarings) modulo the
//! P-256 prime or order.

use std::marker::PhantomData;

use crate::ct;
use crate::field::Modulus;

/// `2⁶² - 1`.
const M62: u64 = u64::MAX >> 2;

/// A signed integer as five limbs `v₀ + v₁·2⁶² + … + v₄·2²⁴⁸` (limbs 0–3 in `[0, 2⁶²)` once
/// normalized, the top limb signed).
type S62 = [i64; 5];

/// The 2×2 transition matrix of one batch of divsteps, scaled by `2⁶²`.
pub(crate) struct Trans {
    pub(crate) u: i64,
    pub(crate) v: i64,
    pub(crate) q: i64,
    pub(crate) r: i64,
}

/// A batch of 59 divsteps: `(ζ, f₀, g₀) → (ζ', t)` ([`divsteps_59`] or an assembly twin).
pub(crate) type Divsteps = fn(i64, u64, u64) -> (i64, Trans);

/// An odd modulus below `2²⁵⁶`: its signed-62 limbs and its inverse modulo `2⁶²`.
pub(crate) struct Modulus256 {
    m: S62,
    inv62: u64,
}

impl Modulus256 {
    /// From little-endian 64-bit limbs (`m` odd).
    pub(crate) const fn new(m: &[u64; 4]) -> Self {
        // m·x ≡ 1 (mod 2⁶⁴) by Newton iteration.
        let mut x = 1u64;
        let mut i = 0;
        while i < 6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(x)));
            i += 1;
        }
        Modulus256 {
            m: to_s62(m),
            inv62: x & M62,
        }
    }
}

const fn to_s62(a: &[u64; 4]) -> S62 {
    [
        (a[0] & M62) as i64,
        ((a[0] >> 62 | a[1] << 2) & M62) as i64,
        ((a[1] >> 60 | a[2] << 4) & M62) as i64,
        ((a[2] >> 58 | a[3] << 6) & M62) as i64,
        (a[3] >> 56) as i64,
    ]
}

/// The limbs of a normalized value in `[0, 2²⁵⁶)`.
fn from_s62(v: &S62) -> [u64; 4] {
    let v = v.map(|x| x as u64);
    [
        v[0] | v[1] << 62,
        v[1] >> 2 | v[2] << 60,
        v[2] >> 4 | v[3] << 58,
        v[3] >> 6 | v[4] << 56,
    ]
}

/// 59 divsteps on the low 64 bits of `f` and `g` (`f` odd), from `ζ = -(δ + 1/2)`: returns the
/// new `ζ` and the transition matrix (times `2⁶²`; it starts at `8·I` so that 59 steps of
/// doubling `u`, `v` end at `2⁶²`).
pub(crate) fn divsteps_59(mut zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    for _ in 3..62 {
        // c1: δ > 0 (ζ < 0); c2: g odd.
        let c1 = ct::mask((zeta as u64) >> 63);
        let c2 = ct::mask(g & 1);
        // If c1, (f, u, v) are negated for the subtraction below and swapped in after it.
        let x = (f ^ c1).wrapping_sub(c1);
        let y = (u ^ c1).wrapping_sub(c1);
        let z = (v ^ c1).wrapping_sub(c1);
        // g odd: g += ±f (and the matrix rows alike).
        g = g.wrapping_add(x & c2);
        q = q.wrapping_add(y & c2);
        r = r.wrapping_add(z & c2);
        // Both: δ ← 1 - δ and f ← f + (g - f) = old g (the rows alike).
        let c3 = c1 & c2;
        zeta = (zeta ^ c3 as i64).wrapping_sub(1);
        f = f.wrapping_add(g & c3);
        u = u.wrapping_add(q & c3);
        v = v.wrapping_add(r & c3);
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    (
        zeta,
        Trans {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// `(d, e) ← (t·(d, e) + m·(md, me)) / 2⁶²`, with `md`, `me` chosen to clear the low 62 bits
/// and to keep the results in `(-2m, m)` (given inputs there).
#[inline]
fn update_de(d: &mut S62, e: &mut S62, t: &Trans, md_: &Modulus256) {
    let m = &md_.m;
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let sd = d[4] >> 63;
    let se = e[4] >> 63;
    // Negative inputs get m added (through the matrix entries' signs).
    let mut md = (u & sd).wrapping_add(v & se);
    let mut me = (q & sd).wrapping_add(r & se);
    let mut cd = i128::from(u) * i128::from(d[0]) + i128::from(v) * i128::from(e[0]);
    let mut ce = i128::from(q) * i128::from(d[0]) + i128::from(r) * i128::from(e[0]);
    // md, me so that the low 62 bits of t·(d, e) + m·(md, me) are zero.
    md = md.wrapping_sub((md_.inv62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64);
    me = me.wrapping_sub((md_.inv62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64);
    cd += i128::from(m[0]) * i128::from(md);
    ce += i128::from(m[0]) * i128::from(me);
    debug_assert_eq!(cd as u64 & M62, 0);
    debug_assert_eq!(ce as u64 & M62, 0);
    cd >>= 62;
    ce >>= 62;
    for i in 1..5 {
        cd += i128::from(u) * i128::from(d[i])
            + i128::from(v) * i128::from(e[i])
            + i128::from(m[i]) * i128::from(md);
        ce += i128::from(q) * i128::from(d[i])
            + i128::from(r) * i128::from(e[i])
            + i128::from(m[i]) * i128::from(me);
        d[i - 1] = (cd as u64 & M62) as i64;
        e[i - 1] = (ce as u64 & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    d[4] = cd as i64;
    e[4] = ce as i64;
}

/// `(f, g) ← t·(f, g) / 2⁶²` (exact: the batch cleared the low 62 bits).
#[inline]
fn update_fg(f: &mut S62, g: &mut S62, t: &Trans) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut cf = i128::from(u) * i128::from(f[0]) + i128::from(v) * i128::from(g[0]);
    let mut cg = i128::from(q) * i128::from(f[0]) + i128::from(r) * i128::from(g[0]);
    debug_assert_eq!(cf as u64 & M62, 0);
    debug_assert_eq!(cg as u64 & M62, 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..5 {
        cf += i128::from(u) * i128::from(f[i]) + i128::from(v) * i128::from(g[i]);
        cg += i128::from(q) * i128::from(f[i]) + i128::from(r) * i128::from(g[i]);
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[4] = cf as i64;
    g[4] = cg as i64;
}

/// `r` from `(-2m, m)` to `[0, m)`, negated first when `sign < 0`.
fn normalize(r: &mut S62, sign: i64, md: &Modulus256) {
    let m = &md.m;
    let add = ct::mask((r[4] as u64) >> 63) as i64;
    for (x, &mi) in r.iter_mut().zip(m) {
        *x = x.wrapping_add(mi & add);
    }
    let neg = ct::mask((sign as u64) >> 63) as i64;
    for x in r.iter_mut() {
        *x = (*x ^ neg).wrapping_sub(neg);
    }
    carry(r);
    let add = ct::mask((r[4] as u64) >> 63) as i64;
    for (x, &mi) in r.iter_mut().zip(m) {
        *x = x.wrapping_add(mi & add);
    }
    carry(r);
}

/// Limbs 0–3 back into `[0, 2⁶²)`, the carries into the top limb.
#[inline]
fn carry(r: &mut S62) {
    for i in 0..4 {
        r[i + 1] = r[i + 1].wrapping_add(r[i] >> 62);
        r[i] &= M62 as i64;
    }
}

/// `a⁻¹·R mod P` from the Montgomery form `a·R` of a 4-limb modulus (`0` maps to `0`): the
/// integer inverse `(aR)⁻¹ = a⁻¹R⁻¹` here, then one Montgomery multiplication by `R³`.
#[inline]
pub(crate) fn mont_inv<M: Modulus<4>>(a: &[u64; 4]) -> [u64; 4] {
    mont_inv_with::<M>(a, divsteps_59)
}

/// [`mont_inv`] with the given batch of divsteps.
#[inline]
pub(crate) fn mont_inv_with<M: Modulus<4>>(a: &[u64; 4], divsteps: Divsteps) -> [u64; 4] {
    struct Md<M>(PhantomData<M>);
    impl<M: Modulus<4>> Md<M> {
        const MD: Modulus256 = Modulus256::new(&M::P);
    }
    M::mont_mul(&inv_with(a, &Md::<M>::MD, divsteps), &M::R3)
}

/// `a⁻¹ mod m` for `a < m` (`0` maps to `0`), in constant time (portable divsteps).
#[cfg(test)]
pub(crate) fn inv(a: &[u64; 4], md: &Modulus256) -> [u64; 4] {
    inv_with(a, md, divsteps_59)
}

/// [`inv`] with the given batch of divsteps (the same contract as [`divsteps_59`]).
#[inline]
pub(crate) fn inv_with(a: &[u64; 4], md: &Modulus256, divsteps: Divsteps) -> [u64; 4] {
    let mut d: S62 = [0; 5];
    let mut e: S62 = [1, 0, 0, 0, 0];
    let mut f = md.m;
    let mut g = to_s62(a);
    let mut zeta = -1i64;
    for _ in 0..10 {
        let (z, t) = divsteps(zeta, f[0] as u64, g[0] as u64);
        zeta = z;
        update_de(&mut d, &mut e, &t, md);
        update_fg(&mut f, &mut g, &t);
    }
    // g = 0 and f = ±1 now (±gcd); d = ±a⁻¹.
    debug_assert!(g.iter().all(|&x| x == 0));
    normalize(&mut d, f[4], md);
    from_s62(&d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves::{P256N, P256P};

    /// Against `a^(m-2)` for random and edge inputs, modulo the P-256 prime and order.
    #[test]
    fn matches_fermat() {
        fn check<M: Modulus<4>>() {
            let md = Modulus256::new(&M::P);
            let mut rng = crate::rand::ChaChaRng::from_seed([0x62; 32]);
            let mut vals = vec![
                [0u64; 4],
                [1, 0, 0, 0],
                [2, 0, 0, 0],
                crate::field::sub_small(&M::P, 1),
                crate::field::sub_small(&M::P, 2),
                [u64::MAX, 0, 0, 0],
                [0, 0, 0, 1 << 63],
            ];
            for _ in 0..2000 {
                let mut b = [0u8; 32];
                rng.fill(&mut b);
                let mut l = crate::field::be_to_limbs::<4>(&b).unwrap();
                if ct::lt_limbs(&l, &M::P) == 0 {
                    l[3] >>= 1;
                }
                vals.push(l);
                // Small and sparse values.
                vals.push([l[0] & 0xffff, 0, 0, 0]);
                vals.push([0, 0, l[2], 0]);
            }
            for a in vals {
                let x = crate::field::Fe::<M, 4>::from_limbs_reduce(&a);
                let want = x.pow_vartime_exp(&M::P_MINUS_2).to_limbs();
                assert_eq!(inv(&a, &md), want, "{a:x?}");
            }
        }
        check::<P256P>();
        check::<P256N>();
    }
}
