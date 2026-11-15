//! NIST P-256 and P-384 parameters (FIPS 186-4 / SEC 2).

use std::sync::OnceLock;

use super::{BaseTables, Curve, Point, Scalar, Sig};
#[cfg(target_arch = "x86_64")]
use super::{Fp, Jac};
use crate::Error;
use crate::field::{Modulus, mont_mul_cios, mul_wide, redc, sqr_wide, sub_if_ge};
use crate::hash::Hash;

#[derive(Clone, Copy, Debug)]
pub(crate) struct P256;
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256P;
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256N;

impl Modulus<4> for P256P {
    const P: [u64; 4] = [
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ];

    #[inline]
    fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        p256_redc(&mul_wide::<4, 8>(a, b))
    }

    #[inline]
    fn mont_sqr(a: &[u64; 4]) -> [u64; 4] {
        p256_redc(&sqr_wide::<4, 8>(a))
    }

    // Inversions also happen outside the twin's operations (encoding a public key): one check
    // chooses the assembly divsteps and multiplication. Both are safegcd (`crate::safegcd`).
    fn mont_inv(a: &[u64; 4]) -> Option<[u64; 4]> {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return Some(super::hw::mont_inv_safegcd::<super::hw::P256Px>(a));
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return Some(crate::safegcd::mont_inv::<super::hw_aarch64::P256Pa>(a));
        }
        Some(crate::safegcd::mont_inv::<Self>(a))
    }
}

/// Montgomery reduction modulo the P-256 prime `p = 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1` of an 8-limb
/// `t < p·2²⁵⁶`. `-p⁻¹ mod 2⁶⁴ = 1`, so each step's multiplier is the low limb `m` itself, and
/// `m·p` needs one multiplication: adding `m·(2⁹⁶ - 1)` clears the low limb and adds `m·2⁹⁶`
/// (two shifted words); only `m·p₃` (`p₃ = 2⁶⁴ - 2³² + 1`) is a real product. Constant time.
#[inline(always)]
fn p256_redc(t: &[u64; 8]) -> [u64; 4] {
    const P3: u64 = 0xffff_ffff_0000_0001;
    let mut t = *t;
    let mut carry = 0u64;
    for i in 0..4 {
        let m = t[i];
        let x = u128::from(t[i + 1]) + u128::from(m << 32);
        t[i + 1] = x as u64;
        let x = u128::from(t[i + 2]) + u128::from(m >> 32) + (x >> 64);
        t[i + 2] = x as u64;
        let mp = u128::from(m) * u128::from(P3);
        let x = u128::from(t[i + 3]) + u128::from(mp as u64) + (x >> 64);
        t[i + 3] = x as u64;
        let x = u128::from(t[i + 4]) + (mp >> 64) + (x >> 64) + u128::from(carry);
        t[i + 4] = x as u64;
        carry = (x >> 64) as u64;
    }
    sub_if_ge([t[4], t[5], t[6], t[7]], carry, &P256P::P)
}

/// `a^(p-2)` (Montgomery form) by the addition chain of mmcloughlin/addchain for P-256 (255
/// squarings, 12 multiplications; the same as Go's `p256Invert`): constant time. Generic over
/// the implementation of the P-256 prime (portable or `hw`). The reference for the safegcd
/// inversion in tests.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
#[cfg(test)]
pub(crate) fn p256_inv<M: Modulus<4>>(a: &[u64; 4]) -> [u64; 4] {
    let mul = |x: &[u64; 4], y: &[u64; 4]| M::mont_mul(x, y);
    let sqn = |x: &[u64; 4], n: usize| {
        let mut r = *x;
        for _ in 0..n {
            r = M::mont_sqr(&r);
        }
        r
    };
    let z = a;
    let t10 = sqn(z, 1);
    let t11 = mul(z, &t10);
    let t110 = sqn(&t11, 1);
    let t111 = mul(z, &t110);
    let t111000 = sqn(&t111, 3);
    let t111111 = mul(&t111, &t111000);
    let x12 = mul(&sqn(&t111111, 6), &t111111);
    let x15 = mul(&sqn(&x12, 3), &t111);
    let x16 = mul(&sqn(&x15, 1), z);
    let x32 = mul(&sqn(&x16, 16), &x16);
    let i53 = sqn(&x32, 15);
    let x47 = mul(&x15, &i53);
    let i263 = sqn(&mul(&sqn(&mul(&sqn(&i53, 17), z), 143), &x47), 47);
    mul(&sqn(&mul(&x47, &i263), 2), z)
}
impl Modulus<4> for P256N {
    const P: [u64; 4] = [
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
    ];

    // Scalar operations are few outside the inversion: one check per operation chooses the
    // BMI2 + ADX code (`hw`), the inversion checks once.
    #[inline]
    fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return super::hw::ord_mul(a, b);
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return super::hw_aarch64::ord_mul(a, b);
        }
        mont_mul_cios(a, b, &Self::P, Self::N0)
    }

    #[inline]
    fn mont_sqr(a: &[u64; 4]) -> [u64; 4] {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return super::hw::ord_sqr(a);
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return super::hw_aarch64::ord_sqr(a);
        }
        redc::<4, 8>(sqr_wide::<4, 8>(a), &Self::P, Self::N0)
    }

    fn mont_inv(a: &[u64; 4]) -> Option<[u64; 4]> {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return Some(super::hw::mont_inv_safegcd::<super::hw::P256Nx>(a));
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return Some(crate::safegcd::mont_inv::<super::hw_aarch64::P256Na>(a));
        }
        Some(crate::safegcd::mont_inv::<Self>(a))
    }
}

/// `a^(n-2)` modulo the P-256 group order (Montgomery form): `n - 2` is
/// `ffffffff 00000000 ffffffff ffffffff` followed by 128 irregular bits. The top half comes from
/// `a^(2³² - 1)` (31 squarings, 5 multiplications) shifted into place, the bottom half from
/// sliding windows of up to 4 bits over `a, a³, …, a¹⁵`: 255 squarings and 40 multiplications
/// (the generic 4-bit windows need 78). Every branch depends on the public exponent
/// only, so the sequence of operations is the same for every `a`: constant time. The reference
/// for the safegcd inversion in tests.
#[cfg(test)]
pub(crate) fn p256n_inv<M: Modulus<4>>(a: &[u64; 4]) -> [u64; 4] {
    const LOW: [u64; 2] = [0xf3b9_cac2_fc63_254f, 0xbce6_faad_a717_9e84];
    let mul = |x: &[u64; 4], y: &[u64; 4]| M::mont_mul(x, y);
    let sqn = |x: &[u64; 4], n: usize| {
        let mut r = *x;
        for _ in 0..n {
            r = M::mont_sqr(&r);
        }
        r
    };
    // odd[i] = a^(2i + 1).
    let a2 = M::mont_sqr(a);
    let mut odd = [*a; 8];
    for i in 1..8 {
        odd[i] = mul(&odd[i - 1], &a2);
    }
    let x2 = odd[1];
    let x4 = mul(&sqn(&x2, 2), &x2);
    let x8 = mul(&sqn(&x4, 4), &x4);
    let x16 = mul(&sqn(&x8, 8), &x8);
    let x32 = mul(&sqn(&x16, 16), &x16);
    let mut t = mul(&sqn(&x32, 64), &x32);
    t = mul(&sqn(&t, 32), &x32);
    let bit = |i: usize| (LOW[i / 64] >> (i % 64)) & 1;
    let mut i = 128usize;
    while i > 0 {
        if bit(i - 1) == 0 {
            t = M::mont_sqr(&t);
            i -= 1;
            continue;
        }
        // The window: bits i-1 down to j, at most 4 of them, ending in a one.
        let mut j = i.saturating_sub(4);
        while bit(j) == 0 {
            j += 1;
        }
        let mut w = 0usize;
        for b in (j..i).rev() {
            w = (w << 1) | bit(b) as usize;
        }
        t = mul(&sqn(&t, i - j), &odd[w >> 1]);
        i = j;
    }
    t
}
impl Curve<4> for P256 {
    type Fp = P256P;
    type Fq = P256N;
    const B: [u64; 4] = [
        0x3bce_3c3e_27d2_604b,
        0x651d_06b0_cc53_b0f6,
        0xb3eb_bd55_7698_86bc,
        0x5ac6_35d8_aa3a_93e7,
    ];
    const GX: [u64; 4] = [
        0xf4a1_3945_d898_c296,
        0x7703_7d81_2deb_33a0,
        0xf8bc_e6e5_63a4_40f2,
        0x6b17_d1f2_e12c_4247,
    ];
    const GY: [u64; 4] = [
        0xcbb6_4068_37bf_51f5,
        0x2bce_3357_6b31_5ece,
        0x8ee7_eb4a_7c0f_9e16,
        0x4fe3_42e2_fe1a_7f9b,
    ];
    fn tables() -> &'static BaseTables<4> {
        static T: OnceLock<BaseTables<4>> = OnceLock::new();
        T.get_or_init(BaseTables::build::<P256>)
    }

    #[inline]
    fn base_mul(d: &Scalar<Self, 4>) -> Point<Self, 4> {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return super::base_mul_impl::<P256X, 4>(d).cast();
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return super::base_mul_impl::<super::hw_aarch64::P256A, 4>(d).cast();
        }
        super::base_mul_impl::<Self, 4>(d)
    }

    #[inline]
    fn ecdh_x(d: &Scalar<Self, 4>, q: &Point<Self, 4>, out: &mut [u8]) -> bool {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return super::ecdh_x_impl::<P256X, 4>(d, &q.cast(), out);
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return super::ecdh_x_impl::<super::hw_aarch64::P256A, 4>(d, &q.cast(), out);
        }
        super::ecdh_x_impl::<Self, 4>(d, q, out)
    }

    #[inline]
    fn sign_digest<H: Hash>(d: &Scalar<Self, 4>, h: &[u8]) -> Sig<Self, 4> {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return super::sign_impl::<P256X, H, 4>(d, h).cast();
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return super::sign_impl::<super::hw_aarch64::P256A, H, 4>(d, h).cast();
        }
        super::sign_impl::<Self, H, 4>(d, h)
    }

    #[inline]
    fn verify_digest(q: &Point<Self, 4>, h: &[u8], sig: &Sig<Self, 4>) -> Result<(), Error> {
        #[cfg(target_arch = "x86_64")]
        if super::hw::enabled() {
            return super::verify_impl::<P256X, 4>(&q.cast(), h, &sig.cast());
        }
        #[cfg(target_arch = "aarch64")]
        if super::hw_aarch64::enabled() {
            return super::verify_impl::<super::hw_aarch64::P256A, 4>(&q.cast(), h, &sig.cast());
        }
        super::verify_impl::<Self, 4>(q, h, sig)
    }
}

/// P-256 with the base field on BMI2 + ADX (`hw`): the twin `P256` dispatches its operations to
/// when `hw::enabled()`. Same constants, same scalar field, same tables.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256X;

#[cfg(target_arch = "x86_64")]
impl Curve<4> for P256X {
    type Fp = super::hw::P256Px;
    type Fq = P256N;
    const B: [u64; 4] = P256::B;
    const GX: [u64; 4] = P256::GX;
    const GY: [u64; 4] = P256::GY;
    fn tables() -> &'static BaseTables<4> {
        P256::tables()
    }

    // Whole point operations in assembly (`hw`), same formulas as the portable defaults.
    #[inline]
    fn jac_double(p: &Jac<Self, 4>) -> Jac<Self, 4> {
        Jac::from_raw(super::hw::point_double(&p.raw()))
    }

    #[inline]
    fn jac_double_n(p: &Jac<Self, 4>, n: usize) -> Jac<Self, 4> {
        Jac::from_raw(super::hw::point_double_n(&p.raw(), n))
    }

    #[inline]
    fn jac_add_core(p: &Jac<Self, 4>, q: &Jac<Self, 4>) -> Jac<Self, 4> {
        Jac::from_raw(super::hw::point_add(&p.raw(), &q.raw()))
    }

    #[inline]
    fn jac_madd_core(p: &Jac<Self, 4>, x2: &Fp<Self, 4>, y2: &Fp<Self, 4>) -> Jac<Self, 4> {
        Jac::from_raw(super::hw::point_add_affine(&p.raw(), &x2.l, &y2.l))
    }

    #[inline]
    fn jac_lookup(table: &[Jac<Self, 4>; 16], d: u64) -> Jac<Self, 4> {
        super::hw::lookup_jac(table, d)
    }

    #[inline]
    fn jac_mul_base(k: &Scalar<Self, 4>) -> Jac<Self, 4> {
        super::hw::mul_base(k)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct P384;
#[derive(Clone, Copy, Debug)]
pub(crate) struct P384P;
#[derive(Clone, Copy, Debug)]
pub(crate) struct P384N;

impl Modulus<6> for P384P {
    const P: [u64; 6] = [
        0x0000_0000_ffff_ffff,
        0xffff_ffff_0000_0000,
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ];
}
impl Modulus<6> for P384N {
    const P: [u64; 6] = [
        0xecec_196a_ccc5_2973,
        0x581a_0db2_48b0_a77a,
        0xc763_4d81_f437_2ddf,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ];
}
impl Curve<6> for P384 {
    type Fp = P384P;
    type Fq = P384N;
    const B: [u64; 6] = [
        0x2a85_c8ed_d3ec_2aef,
        0xc656_398d_8a2e_d19d,
        0x0314_088f_5013_875a,
        0x181d_9c6e_fe81_4112,
        0x988e_056b_e3f8_2d19,
        0xb331_2fa7_e23e_e7e4,
    ];
    const GX: [u64; 6] = [
        0x3a54_5e38_7276_0ab7,
        0x5502_f25d_bf55_296c,
        0x59f7_41e0_8254_2a38,
        0x6e1d_3b62_8ba7_9b98,
        0x8eb1_c71e_f320_ad74,
        0xaa87_ca22_be8b_0537,
    ];
    const GY: [u64; 6] = [
        0x7a43_1d7c_90ea_0e5f,
        0x0a60_b1ce_1d7e_819d,
        0xe9da_3113_b5f0_b8c0,
        0xf8f4_1dbd_289a_147c,
        0x5d9e_98bf_9292_dc29,
        0x3617_de4a_9626_2c6f,
    ];
    fn tables() -> &'static BaseTables<6> {
        static T: OnceLock<BaseTables<6>> = OnceLock::new();
        T.get_or_init(BaseTables::build::<P384>)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Jac, Point, Scalar};
    use super::*;
    use crate::field::sub_small;

    fn enc<C: Curve<L>, const L: usize>(j: Jac<C, L>) -> Option<Vec<u8>> {
        let (x, y) = j.to_affine()?;
        Point::<C, L>::from_affine(x, y)?.to_uncompressed()
    }

    fn scalar<C: Curve<L>, const L: usize>(l: &[u64; L]) -> Scalar<C, L> {
        Scalar::<C, L>::from_limbs_canonical(l).expect("scalar below n")
    }

    /// Scalars that stress the digit recodings: the ends of `[1, n)`, `n - 2|d|` for every
    /// Booth digit, carries into the comb's top row, runs of 8s, 9s and 16s.
    fn edge_scalars<C: Curve<L>, const L: usize>() -> Vec<Scalar<C, L>> {
        let n = <C::Fq as Modulus<L>>::P;
        let mut v = Vec::new();
        for s in 1..=40 {
            v.push(scalar::<C, L>(&sub_small(&n, s)));
            let mut small = [0u64; L];
            small[0] = s;
            v.push(scalar::<C, L>(&small));
        }
        for pat in [
            0x8888_8888_8888_8888u64,
            0x9999_9999_9999_9999,
            0x1010_1010_1010_1010,
        ] {
            let mut l = [pat; L];
            l[L - 1] &= 0x7fff_ffff_ffff_ffff;
            v.push(scalar::<C, L>(&l));
            l[L - 1] = 0x8000_0000_0000_0000;
            v.push(scalar::<C, L>(&l));
        }
        let mut top = [0u64; L];
        top[L - 1] = 1 << 63;
        v.push(scalar::<C, L>(&top));
        top[0] = 0xf;
        v.push(scalar::<C, L>(&top));
        // The top window of the wide comb: D·2^(64L-3), D·2^(64L-4) and n minus them, with
        // and without low bits (every top digit, both signs of the window below).
        for d in 1..16u64 {
            for shift in [3u32, 4] {
                if d >> shift != 0 {
                    continue;
                }
                let mut l = [0u64; L];
                l[L - 1] = d << (64 - shift);
                if let Some(s) = Scalar::<C, L>::from_limbs_canonical(&l) {
                    v.push(s);
                    let mut nl = [0u64; L];
                    crate::ct::sub_limbs(&mut nl, &n, &l);
                    v.push(scalar::<C, L>(&nl));
                    l[0] = 0x5555;
                    v.push(scalar::<C, L>(&l));
                }
            }
        }
        v
    }

    fn check<C: Curve<L>, const L: usize>() {
        // The Booth argument of `Jac::mul_ct` needs n mod 32 ∉ [1, 16].
        assert!(<C::Fq as Modulus<L>>::P[0] & 31 >= 17);
        let g = Point::<C, L>::generator();
        assert!(Point::<C, L>::from_affine(g.x, g.y).is_some());
        // (n-1)·G = -G, via both multiplications.
        let nm1 =
            Scalar::<C, L>::from_limbs_canonical(&sub_small(&<C::Fq as Modulus<L>>::P, 1)).unwrap();
        let a = Point::<C, L>::mul_base_ref(&nm1).to_uncompressed().unwrap();
        let b = g.mul_ref(&nm1).to_uncompressed().unwrap();
        let c = g.neg().to_uncompressed().unwrap();
        assert_eq!(a, c);
        assert_eq!(b, c);
        assert_eq!(enc(Jac::<C, L>::mul_base_ct(&nm1)).unwrap(), c);
        assert_eq!(enc(C::jac_mul_base(&nm1)).unwrap(), c);
        assert_eq!(enc(Jac::<C, L>::mul_ct(&g, &nm1)).unwrap(), c);
        // G + (n-1)G = identity, 2G = G + G.
        assert!(g.add(&g.neg()).to_affine().is_none());
        assert_eq!(g.double().to_uncompressed(), g.add(&g).to_uncompressed());
        let two = Scalar::<C, L>::ONE.add(&Scalar::<C, L>::ONE);
        assert_eq!(
            g.mul_add_base_vartime(&Scalar::<C, L>::ONE, &Scalar::<C, L>::ONE)
                .to_uncompressed(),
            Point::<C, L>::mul_base_ref(&two).to_uncompressed()
        );
        // Mixed addition matches full addition, also from the identity; wNAF verification math
        // on random scalars matches the constant-time multiplications.
        let (gx, gy) = g.to_affine().unwrap();
        let g3 = g.double().add(&g);
        assert_eq!(
            g3.add_affine(&gx, &gy).to_uncompressed(),
            g3.add(&g).to_uncompressed()
        );
        assert_eq!(
            Point::<C, L>::identity()
                .add_affine(&gx, &gy)
                .to_uncompressed(),
            g.to_uncompressed()
        );
        // The Jacobian multiplications against the complete-formula references: random
        // scalars and points, then the edge scalars on G and on a random point.
        let mut rng = crate::rand::ChaChaRng::from_seed([L as u8; 32]);
        let mut q = g;
        for _ in 0..20 {
            let mut b = vec![0u8; 8 * L];
            rng.fill(&mut b);
            let a = Scalar::<C, L>::from_be_bytes_reduce(&b).unwrap();
            rng.fill(&mut b);
            let k = Scalar::<C, L>::from_be_bytes_reduce(&b).unwrap();
            q = Point::<C, L>::mul_base_ref(&k);
            let want = Point::<C, L>::mul_base_ref(&a).to_uncompressed();
            assert_eq!(want, g.mul_ref(&a).to_uncompressed());
            assert_eq!(enc(Jac::<C, L>::mul_base_ct(&a)), want);
            assert_eq!(enc(C::jac_mul_base(&a)), want);
            assert_eq!(
                enc(Jac::<C, L>::mul_ct(&q, &a)),
                q.mul_ref(&a).to_uncompressed()
            );
            let want = Point::<C, L>::mul_base_ref(&a).add(&q.mul_ref(&k));
            assert_eq!(
                q.mul_add_base_vartime(&a, &k).to_uncompressed(),
                want.to_uncompressed()
            );
        }
        for k in edge_scalars::<C, L>() {
            let want = g.mul_ref(&k).to_uncompressed();
            assert_eq!(Point::<C, L>::mul_base_ref(&k).to_uncompressed(), want);
            assert_eq!(enc(Jac::<C, L>::mul_base_ct(&k)), want);
            assert_eq!(enc(C::jac_mul_base(&k)), want);
            assert_eq!(enc(Jac::<C, L>::mul_ct(&g, &k)), want);
            assert_eq!(
                enc(Jac::<C, L>::mul_ct(&q, &k)),
                q.mul_ref(&k).to_uncompressed()
            );
        }
        // A point with Z ≠ 1 enters the variable-base multiplication correctly.
        let q3 = q.double().add(&q);
        let k = edge_scalars::<C, L>()[5];
        assert_eq!(
            enc(Jac::<C, L>::mul_ct(&q3, &k)),
            q3.mul_ref(&k).to_uncompressed()
        );
        // Digits that carry into the top row: n - 2 has top nibble f.
        let top =
            Scalar::<C, L>::from_limbs_canonical(&sub_small(&<C::Fq as Modulus<L>>::P, 2)).unwrap();
        assert_eq!(
            Point::<C, L>::mul_base_ref(&top).to_uncompressed(),
            g.mul_ref(&top).to_uncompressed()
        );
        // Compressed round trip.
        let u = g.double().to_uncompressed().unwrap();
        let mut comp = u[..=8 * L].to_vec();
        comp[0] = 2 | (u[u.len() - 1] & 1);
        assert_eq!(
            Point::<C, L>::from_sec1(&comp)
                .unwrap()
                .to_uncompressed()
                .unwrap(),
            u
        );
    }

    /// The dedicated scalar inversion chain matches the generic exponentiation by `n - 2`.
    #[test]
    fn scalar_inverse() {
        let mut rng = crate::rand::ChaChaRng::from_seed([0x4e; 32]);
        let mut vals = vec![[1u64, 0, 0, 0], sub_small(&P256N::P, 1), [0; 4]];
        for _ in 0..100 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            vals.push(Scalar::<P256, 4>::from_be_bytes_reduce(&b).unwrap().l);
        }
        for a in vals {
            let x = Scalar::<P256, 4>::from_mont(a);
            let want = x.pow_vartime_exp(&P256N::P_MINUS_2);
            assert_eq!(p256n_inv::<P256N>(&a), want.l);
            assert_eq!(x.invert().l, want.l);
            #[cfg(target_arch = "x86_64")]
            if crate::cpu::cpu_has(crate::cpu::Feature::Adx) {
                assert_eq!(p256n_inv::<crate::ec::hw::P256Nx>(&a), want.l);
            }
        }
    }

    #[test]
    fn group_laws() {
        check::<P256, 4>();
        check::<P384, 6>();
        #[cfg(target_arch = "x86_64")]
        if crate::cpu::cpu_has(crate::cpu::Feature::Adx) {
            check::<P256X, 4>();
        }
        #[cfg(target_arch = "aarch64")]
        if crate::cpu::cpu_has(crate::cpu::Feature::Umulh) {
            check::<crate::ec::hw_aarch64::P256A, 4>();
        }
    }

    /// The hardware twin and the portable curve agree on every operation, through the public
    /// API's dispatch (the portable path forced by `set_portable` for the comparison).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn twin_matches_portable() {
        use crate::hash::Sha256;
        if !crate::cpu::cpu_has(crate::cpu::Feature::Adx) {
            return;
        }
        let mut rng = crate::rand::ChaChaRng::from_seed([0x77; 32]);
        for _ in 0..50 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let d = Scalar::<P256, 4>::from_be_bytes_reduce(&b).unwrap();
            rng.fill(&mut b);
            let e = Scalar::<P256, 4>::from_be_bytes_reduce(&b).unwrap();
            let q = super::super::base_mul_impl::<P256, 4>(&e);
            let qx = super::super::base_mul_impl::<P256X, 4>(&e).cast::<P256>();
            assert_eq!(q.to_uncompressed(), qx.to_uncompressed());
            let (mut o1, mut o2) = ([0u8; 32], [0u8; 32]);
            assert!(super::super::ecdh_x_impl::<P256, 4>(&d, &q, &mut o1));
            assert!(super::super::ecdh_x_impl::<P256X, 4>(
                &d,
                &q.cast(),
                &mut o2
            ));
            assert_eq!(o1, o2);
            let s1 = super::super::sign_impl::<P256, Sha256, 4>(&d, &b);
            let s2 = super::super::sign_impl::<P256X, Sha256, 4>(&d, &b);
            assert_eq!((s1.r.l, s1.s.l), (s2.r.l, s2.s.l));
            let pd = super::super::base_mul_impl::<P256, 4>(&d);
            assert!(super::super::verify_impl::<P256, 4>(&pd, &b, &s1).is_ok());
            assert!(super::super::verify_impl::<P256X, 4>(&pd.cast(), &b, &s2.cast()).is_ok());
            b[0] ^= 1;
            assert!(super::super::verify_impl::<P256X, 4>(&pd.cast(), &b, &s2.cast()).is_err());
        }
    }
}
