//! NIST P-256 and P-384 parameters (FIPS 186-4 / SEC 2).

use std::sync::OnceLock;

use super::{Curve, Point};
use crate::field::Modulus;

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
    fn base_table() -> &'static [[Point<Self, 4>; 16]] {
        static T: OnceLock<Vec<[Point<P256, 4>; 16]>> = OnceLock::new();
        T.get_or_init(Point::build_base_table)
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
    fn base_table() -> &'static [[Point<Self, 6>; 16]] {
        static T: OnceLock<Vec<[Point<P384, 6>; 16]>> = OnceLock::new();
        T.get_or_init(Point::build_base_table)
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
