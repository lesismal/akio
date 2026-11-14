//! NIST P-256 and P-384 parameters (FIPS 186-4 / SEC 2).

use std::sync::OnceLock;

use super::{BaseTables, Curve};
use crate::field::{Modulus, mul_wide, sqr_wide, sub_if_ge};

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

    fn mont_inv(a: &[u64; 4]) -> Option<[u64; 4]> {
        Some(p256_inv(a))
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
/// squarings, 12 multiplications; the same as Go's `p256Invert`): constant time.
fn p256_inv(a: &[u64; 4]) -> [u64; 4] {
    let mul = |x: &[u64; 4], y: &[u64; 4]| P256P::mont_mul(x, y);
    let sqn = |x: &[u64; 4], n: usize| {
        let mut r = *x;
        for _ in 0..n {
            r = P256P::mont_sqr(&r);
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
    fn tables() -> &'static BaseTables<Self, 4> {
        static T: OnceLock<BaseTables<P256, 4>> = OnceLock::new();
        T.get_or_init(BaseTables::build)
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
    fn tables() -> &'static BaseTables<Self, 6> {
        static T: OnceLock<BaseTables<P384, 6>> = OnceLock::new();
        T.get_or_init(BaseTables::build)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Point, Scalar};
    use super::*;
    use crate::field::sub_small;

    fn check<C: Curve<L>, const L: usize>() {
        let g = Point::<C, L>::generator();
        assert!(Point::<C, L>::from_affine(g.x, g.y).is_some());
        // (n-1)·G = -G, via both multiplications.
        let nm1 =
            Scalar::<C, L>::from_limbs_canonical(&sub_small(&<C::Fq as Modulus<L>>::P, 1)).unwrap();
        let a = Point::<C, L>::mul_base(&nm1).to_uncompressed().unwrap();
        let b = g.mul(&nm1).to_uncompressed().unwrap();
        let c = g.neg().to_uncompressed().unwrap();
        assert_eq!(a, c);
        assert_eq!(b, c);
        // G + (n-1)G = identity, 2G = G + G.
        assert!(g.add(&g.neg()).to_affine().is_none());
        assert_eq!(g.double().to_uncompressed(), g.add(&g).to_uncompressed());
        let two = Scalar::<C, L>::ONE.add(&Scalar::<C, L>::ONE);
        assert_eq!(
            g.mul_add_base_vartime(&Scalar::<C, L>::ONE, &Scalar::<C, L>::ONE)
                .to_uncompressed(),
            Point::<C, L>::mul_base(&two).to_uncompressed()
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
        let mut rng = crate::rand::ChaChaRng::from_seed([L as u8; 32]);
        for _ in 0..20 {
            let mut b = vec![0u8; 8 * L];
            rng.fill(&mut b);
            let a = Scalar::<C, L>::from_be_bytes_reduce(&b).unwrap();
            rng.fill(&mut b);
            let k = Scalar::<C, L>::from_be_bytes_reduce(&b).unwrap();
            let q = Point::<C, L>::mul_base(&k);
            assert_eq!(
                Point::<C, L>::mul_base(&a).to_uncompressed(),
                g.mul(&a).to_uncompressed()
            );
            let want = Point::<C, L>::mul_base(&a).add(&q.mul(&k));
            assert_eq!(
                q.mul_add_base_vartime(&a, &k).to_uncompressed(),
                want.to_uncompressed()
            );
        }
        // Digits that carry into the top row: n - 1 has top nibble f.
        let top =
            Scalar::<C, L>::from_limbs_canonical(&sub_small(&<C::Fq as Modulus<L>>::P, 2)).unwrap();
        assert_eq!(
            Point::<C, L>::mul_base(&top).to_uncompressed(),
            g.mul(&top).to_uncompressed()
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

    #[test]
    fn group_laws() {
        check::<P256, 4>();
        check::<P384, 6>();
    }
}
