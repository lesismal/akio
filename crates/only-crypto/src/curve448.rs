//! Curve448 arithmetic for Ed448 and X448: the field `GF(2⁴⁴⁸ - 2²²⁴ - 1)` and the scalar field
//! modulo the prime group order `ℓ = 2⁴⁴⁶ - 13818066809895115352007386748515426880336692474882178609894547503885`,
//! both on the generic Montgomery code of [`crate::field`] (seven 64-bit limbs, constant time),
//! and the untwisted Edwards curve edwards448 `x² + y² = 1 + d·x²·y²`, `d = -39081`, in
//! projective coordinates with the complete formulas of RFC 8032 §5.2.4 (`d` is not a square,
//! so addition has no exceptional cases).
//!
//! Secret scalars are multiplied with fixed 4-bit windows: every window does four doublings and
//! one addition of a table entry chosen by a masked scan of all sixteen entries, so the
//! sequence of operations and memory accesses depends only on the window position. Inversion is
//! Fermat's (a fixed public exponent). Verification ([`Point::mul_add_base_vartime`]) and point
//! decoding run in variable time on public data.

use crate::ct;
use crate::field::{Fe, Modulus, add_small_shr, le_to_limbs, sub_small};

/// The field prime `p = 2⁴⁴⁸ - 2²²⁴ - 1`.
#[derive(Clone, Copy)]
pub(crate) struct P448;
impl Modulus<7> for P448 {
    const P: [u64; 7] = [
        u64::MAX,
        u64::MAX,
        u64::MAX,
        0xffff_fffe_ffff_ffff,
        u64::MAX,
        u64::MAX,
        u64::MAX,
    ];
}

/// The group order `ℓ`.
#[derive(Clone, Copy)]
pub(crate) struct L448;
impl Modulus<7> for L448 {
    const P: [u64; 7] = [
        0x2378_c292_ab58_44f3,
        0x216c_c272_8dc5_8f55,
        0xc44e_db49_aed6_3690,
        0xffff_ffff_7cca_23e9,
        u64::MAX,
        u64::MAX,
        0x3fff_ffff_ffff_ffff,
    ];
}

/// A field element.
pub(crate) type Fp = Fe<P448, 7>;
/// A scalar modulo `ℓ`.
pub(crate) type Scalar = Fe<L448, 7>;

/// `(p - 3) / 4`: the exponent of the square root `u³v·(u⁵v³)^((p-3)/4)`.
const SQRT_EXP: [u64; 7] = add_small_shr(&sub_small(&P448::P, 3), 0, 2);

/// `d = -39081 = p - 39081`.
const D: Fp = Fp::from_canonical_const(sub_small(&P448::P, 39081));

/// A field element from a small constant.
const fn small(v: u64) -> Fp {
    Fp::from_canonical_const([v, 0, 0, 0, 0, 0, 0])
}

/// The X448 ladder constant `a24 = (A - 2) / 4 = 39081` (RFC 7748 §5).
pub(crate) const A24: Fp = small(39081);

/// A point in projective coordinates `(X : Y : Z)`, `x = X/Z`, `y = Y/Z`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    x: Fp,
    y: Fp,
    z: Fp,
}

impl Point {
    pub(crate) const IDENTITY: Point = Point {
        x: Fp::ZERO,
        y: Fp::ONE,
        z: Fp::ONE,
    };

    /// The base point `B` of RFC 8032 §5.2.
    pub(crate) const BASE: Point = Point {
        x: Fp::from_canonical_const([
            0x2626_a82b_c70c_c05e,
            0x433b_80e1_8b00_938e,
            0x12ae_1af7_2ab6_6511,
            0xea6d_e324_a3d3_a464,
            0x9e14_6570_470f_1767,
            0x221d_15a6_22bf_36da,
            0x4f19_70c6_6bed_0ded,
        ]),
        y: Fp::from_canonical_const([
            0x9808_795b_f230_fa14,
            0xfdbd_132c_4ed7_c8ad,
            0x3ad3_ff1c_e67c_39c4,
            0x8778_9c1e_05a0_c2d7,
            0x4bea_7373_6ca3_9840,
            0x8876_2037_56c9_c762,
            0x693f_4671_6eb6_bc24,
        ]),
        z: Fp::ONE,
    };

    /// `self + o` (complete).
    pub(crate) fn add(&self, o: &Point) -> Point {
        let a = self.z.mul(&o.z);
        let b = a.square();
        let c = self.x.mul(&o.x);
        let d = self.y.mul(&o.y);
        let e = D.mul(&c).mul(&d);
        let f = b.sub(&e);
        let g = b.add(&e);
        let h = self.x.add(&self.y).mul(&o.x.add(&o.y));
        Point {
            x: a.mul(&f).mul(&h.sub(&c).sub(&d)),
            y: a.mul(&g).mul(&d.sub(&c)),
            z: f.mul(&g),
        }
    }

    /// `2·self`.
    pub(crate) fn double(&self) -> Point {
        let b = self.x.add(&self.y).square();
        let c = self.x.square();
        let d = self.y.square();
        let e = c.add(&d);
        let h = self.z.square();
        let j = e.sub(&h.double());
        Point {
            x: b.sub(&e).mul(&j),
            y: e.mul(&c.sub(&d)),
            z: e.mul(&j),
        }
    }

    /// `-self`.
    pub(crate) fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            ..*self
        }
    }

    /// `a` where `m` is all ones, else `b`.
    fn select(m: u64, a: &Point, b: &Point) -> Point {
        Point {
            x: Fp::select(m, &a.x, &b.x),
            y: Fp::select(m, &a.y, &b.y),
            z: Fp::select(m, &a.z, &b.z),
        }
    }

    /// `0·P, 1·P, …, 15·P`.
    fn table(&self) -> [Point; 16] {
        let mut t = [Point::IDENTITY; 16];
        t[1] = *self;
        for i in 2..16 {
            t[i] = if i % 2 == 0 {
                t[i / 2].double()
            } else {
                t[i - 1].add(self)
            };
        }
        t
    }

    /// `[k]·self` for a secret scalar `k < 2⁴⁴⁸` (little-endian limbs), constant time: 112
    /// fixed 4-bit windows from the top, each four doublings and the addition of a table entry
    /// read by a masked scan of the whole table.
    pub(crate) fn mul_ct(&self, k: &[u64; 7]) -> Point {
        let t = self.table();
        let mut r = Point::IDENTITY;
        for i in (0..112).rev() {
            r = r.double().double().double().double();
            let d = (k[i / 16] >> (4 * (i % 16))) & 15;
            let mut e = Point::IDENTITY;
            for (j, tj) in t.iter().enumerate() {
                e = Point::select(ct::eq(j as u64, d), tj, &e);
            }
            r = r.add(&e);
        }
        r
    }

    /// `[k]B` for a secret scalar (constant time).
    pub(crate) fn mul_base(k: &[u64; 7]) -> Point {
        Point::BASE.mul_ct(k)
    }

    /// `[a]B + [b]·self` in variable time (public scalars: signature verification), with
    /// interleaved 4-bit windows.
    pub(crate) fn mul_add_base_vartime(&self, a: &[u64; 7], b: &[u64; 7]) -> Point {
        let tb = Point::BASE.table();
        let tp = self.table();
        let mut r = Point::IDENTITY;
        for i in (0..112).rev() {
            r = r.double().double().double().double();
            let da = ((a[i / 16] >> (4 * (i % 16))) & 15) as usize;
            let db = ((b[i / 16] >> (4 * (i % 16))) & 15) as usize;
            if da != 0 {
                r = r.add(&tb[da]);
            }
            if db != 0 {
                r = r.add(&tp[db]);
            }
        }
        r
    }

    /// The 57-byte encoding (RFC 8032 §5.2.2): `y` little-endian, the low bit of `x` in the
    /// top bit of the last byte.
    pub(crate) fn compress(&self) -> [u8; 57] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi);
        let y = self.y.mul(&zi);
        let mut out = [0u8; 57];
        y.write_le(&mut out[..56]);
        out[56] = ((x.to_limbs()[0] & 1) as u8) << 7;
        out
    }

    /// Decodes a 57-byte encoding (RFC 8032 §5.2.3), strictly: `y < p`, the unused bits of the
    /// last byte zero, a square root exists, and `x = 0` does not carry the sign bit.
    pub(crate) fn decompress(b: &[u8; 57]) -> Option<Point> {
        if b[56] & 0x7f != 0 {
            return None;
        }
        let y = Fp::from_le_bytes(&b[..56])?;
        let sign = u64::from(b[56] >> 7);
        let yy = y.square();
        let u = yy.sub(&Fp::ONE);
        let v = D.mul(&yy).sub(&Fp::ONE);
        // x = u³v · (u⁵v³)^((p-3)/4)
        let u2 = u.square();
        let u3v = u2.mul(&u).mul(&v);
        let u5v3 = u3v.mul(&u2).mul(&v.square());
        let mut x = u3v.mul(&u5v3.pow_vartime_exp(&SQRT_EXP));
        if v.mul(&x.square()).ct_eq(&u) == 0 {
            return None;
        }
        let x0 = x.to_limbs()[0] & 1;
        if x.is_zero() != 0 && sign == 1 {
            return None;
        }
        if x0 != sign {
            x = x.neg();
        }
        Some(Point { x, y, z: Fp::ONE })
    }

    /// Whether `[4]·self` is the identity (a point of small order).
    pub(crate) fn is_small_order(&self) -> bool {
        let q = self.double().double();
        q.x.is_zero() != 0 && q.y.ct_eq(&q.z) != 0
    }
}

/// The scalar `h mod ℓ` of a 114-byte hash read little-endian (`h = lo + mid·2⁴⁴⁸ +
/// hi·2⁸⁹⁶`, `R = 2⁴⁴⁸` being the Montgomery radix).
pub(crate) fn scalar_from_hash(h: &[u8; 114]) -> Scalar {
    let mut wide = [0u8; 120];
    wide[..114].copy_from_slice(h);
    let lo: [u64; 7] = le_to_limbs(&wide[..56]).unwrap_or([0; 7]);
    let mid: [u64; 7] = le_to_limbs(&wide[56..112]).unwrap_or([0; 7]);
    let mut hi = [0u64; 7];
    hi[0] = u64::from_le_bytes(wide[112..120].try_into().unwrap_or([0; 8]));
    // `from_mont(R³)` is the element `R²`.
    let r2 = Scalar::from_mont(L448::R3);
    Scalar::from_wide(&lo, &mid).add(&Scalar::from_limbs_reduce(&hi).mul(&r2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point() {
        // On the curve, of order ℓ, and its encoding round-trips.
        let b = Point::BASE;
        let lhs = b.x.square().add(&b.y.square());
        let rhs = Fp::ONE.add(&D.mul(&b.x.square()).mul(&b.y.square()));
        assert_eq!(lhs.ct_eq(&rhs), u64::MAX);
        let e = Point::mul_base(&L448::P);
        assert_eq!(e.compress(), Point::IDENTITY.compress());
        let one = Point::mul_base(&[1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(one.compress(), b.compress());
        let back = Point::decompress(&b.compress()).unwrap();
        assert_eq!(back.compress(), b.compress());
        assert!(!b.is_small_order());
        assert!(Point::IDENTITY.is_small_order());
        // Doubling agrees with addition.
        assert_eq!(b.double().compress(), b.add(&b).compress());
    }

    #[test]
    fn hash_reduction() {
        // 2⁹¹² - 1 mod ℓ against 2-step reduction by the generic code.
        let h = [0xffu8; 114];
        let s = scalar_from_hash(&h);
        // (2⁹¹² - 1) = (2⁴⁵⁶ - 1)·2⁴⁵⁶ + (2⁴⁵⁶ - 1)
        let mut a = [0u8; 120];
        a[..57].fill(0xff);
        let lo = Scalar::from_wide(
            &le_to_limbs(&a[..56]).unwrap(),
            &le_to_limbs(&a[56..112]).unwrap(),
        );
        let mut t = [0u64; 7];
        t[0] = 1 << 8; // 2⁴⁵⁶ = 2⁴⁴⁸·2⁸
        let shift = Scalar::from_wide(&[0; 7], &t);
        assert_eq!(s.ct_eq(&lo.mul(&shift).add(&lo)), u64::MAX);
    }
}
