//! Curve25519 internals: the field (radix 2⁵¹), the twisted Edwards group of Ed25519 and its
//! scalars modulo the group order `ℓ`.

pub(crate) mod fe;

use std::sync::OnceLock;

use crate::ct;
use crate::field::{self, Modulus};
use fe::Fe;

/// The order of the Ed25519 base point, `ℓ = 2²⁵² + 27742317777372353535851937790883648493`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct L;
impl Modulus<4> for L {
    const P: [u64; 4] = [
        0x5812_631a_5cf5_d3ed,
        0x14de_f9de_a2f7_9cd6,
        0,
        0x1000_0000_0000_0000,
    ];
}
/// A scalar modulo `ℓ`.
pub(crate) type Scalar = field::Fe<L, 4>;

/// The scalar `(lo + hi·2²⁵⁶) mod ℓ` of a 64-byte little-endian hash.
pub(crate) fn scalar_from_hash(h: &[u8; 64]) -> Scalar {
    let lo = field::le_to_limbs::<4>(&h[..32]).unwrap_or([0; 4]);
    let hi = field::le_to_limbs::<4>(&h[32..]).unwrap_or([0; 4]);
    Scalar::from_wide(&lo, &hi)
}

/// Curve constants computed once: `d`, `2d`, `√-1` and the base point table.
pub(crate) struct Consts {
    pub(crate) d: Fe,
    pub(crate) d2: Fe,
    pub(crate) sqrt_m1: Fe,
    /// `table[i][j] = j·16ⁱ·B`.
    base: Vec<[Point; 16]>,
}

pub(crate) fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| {
        let d = Fe::from_u64(121_665)
            .neg()
            .mul(&Fe::from_u64(121_666).invert());
        let two = Fe::from_u64(2);
        // √-1 = 2^((p-1)/4) = (2^((p-5)/8))² · 2.
        let sqrt_m1 = two.pow_p58().square().mul(&two);
        let mut c = Consts {
            d,
            d2: d.add(&d),
            sqrt_m1,
            base: Vec::new(),
        };
        // B: y = 4/5, x even.
        let mut by = [0u8; 32];
        let y = Fe::from_u64(4).mul(&Fe::from_u64(5).invert());
        by.copy_from_slice(&y.to_bytes());
        let b = Point::decompress_with(&by, &c).unwrap_or(Point::IDENTITY);
        let mut base = Vec::with_capacity(64);
        let mut p16 = b; // 16^i B
        for _ in 0..64 {
            let mut row = [Point::IDENTITY; 16];
            for j in 1..16 {
                row[j] = row[j - 1].add_with(&p16, &c);
            }
            p16 = row[15].add_with(&p16, &c);
            base.push(row);
        }
        c.base = base;
        c
    })
}

/// A point in extended twisted Edwards coordinates `(X:Y:Z:T)`, `x = X/Z`, `y = Y/Z`,
/// `xy = T/Z`, on `-x² + y² = 1 + d·x²y²`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    pub(crate) const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Decodes a point (RFC 8032 §5.1.3), rejecting non-canonical `y` (≥ p), `x = 0` with the
    /// sign bit set, and `y` values that are not on the curve. Variable time (public inputs).
    pub(crate) fn decompress(b: &[u8; 32]) -> Option<Point> {
        Self::decompress_with(b, consts())
    }

    fn decompress_with(b: &[u8; 32], c: &Consts) -> Option<Point> {
        let sign = u64::from(b[31] >> 7);
        let y = Fe::from_bytes(b);
        let mut yb = *b;
        yb[31] &= 0x7f;
        if y.to_bytes() != yb {
            return None; // y >= p
        }
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul(&c.d).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let vxx = v.mul(&x.square());
        if vxx.ct_eq(&u) == 0 {
            if vxx.ct_eq(&u.neg()) == 0 {
                return None;
            }
            x = x.mul(&c.sqrt_m1);
        }
        if x.is_zero() != 0 && sign == 1 {
            return None;
        }
        if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }

    /// The 32-byte encoding.
    pub(crate) fn compress(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi);
        let y = self.y.mul(&zi);
        let mut b = y.to_bytes();
        b[31] |= (x.is_negative() as u8) << 7;
        b
    }

    pub(crate) fn add(&self, q: &Point) -> Point {
        self.add_with(q, consts())
    }

    /// Unified addition (add-2008-hwcd-3, complete on edwards25519).
    fn add_with(&self, q: &Point, c: &Consts) -> Point {
        let a = self.y.sub(&self.x).mul(&q.y.sub(&q.x));
        let b = self.y.add(&self.x).mul(&q.y.add(&q.x));
        let cc = self.t.mul(&c.d2).mul(&q.t);
        let d = self.z.add(&self.z).mul(&q.z);
        let e = b.sub(&a);
        let f = d.sub(&cc);
        let g = d.add(&cc);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Doubling (dbl-2008-hwcd with a = -1).
    pub(crate) fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().mul_small(2);
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    pub(crate) fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn select(m: u64, a: &Point, b: &Point) -> Point {
        Point {
            x: Fe::select(m, &a.x, &b.x),
            y: Fe::select(m, &a.y, &b.y),
            z: Fe::select(m, &a.z, &b.z),
            t: Fe::select(m, &a.t, &b.t),
        }
    }

    /// `[s]B` for a 32-byte little-endian scalar below 2²⁵⁶, in constant time: one addition
    /// per 4-bit digit from the precomputed table, each entry chosen by scanning the whole row.
    pub(crate) fn mul_base(s: &[u8; 32]) -> Point {
        let c = consts();
        let mut r = Point::IDENTITY;
        for (i, row) in c.base.iter().enumerate() {
            let nib = u64::from((s[i / 2] >> (4 * (i & 1))) & 15);
            let mut e = Point::IDENTITY;
            for (j, p) in row.iter().enumerate() {
                e = Point::select(ct::eq(j as u64, nib), p, &e);
            }
            r = r.add_with(&e, c);
        }
        r
    }

    /// `[s]P` in variable time (public scalars only: signature verification).
    pub(crate) fn mul_vartime(&self, s: &[u8; 32]) -> Point {
        let c = consts();
        let mut table = [Point::IDENTITY; 16];
        for j in 1..16 {
            table[j] = table[j - 1].add_with(self, c);
        }
        let mut r = Point::IDENTITY;
        for i in (0..64).rev() {
            r = r.double().double().double().double();
            let nib = usize::from((s[i / 2] >> (4 * (i & 1))) & 15);
            if nib != 0 {
                r = r.add_with(&table[nib], c);
            }
        }
        r
    }

    /// `[8]P == identity`: the point has small order.
    pub(crate) fn is_small_order(&self) -> bool {
        let p = self.double().double().double();
        p.x.is_zero() != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point() {
        let b = Point::mul_base(&{
            let mut s = [0u8; 32];
            s[0] = 1;
            s
        });
        let enc = b.compress();
        let mut want = [0x66u8; 32];
        want[0] = 0x58;
        assert_eq!(enc, want);
        // ℓ·B = identity.
        let mut l = [0u8; 32];
        L::P.iter()
            .enumerate()
            .for_each(|(i, x)| l[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes()));
        assert_eq!(Point::mul_base(&l).compress(), Point::IDENTITY.compress());
        let bb = Point::decompress(&enc).unwrap();
        assert_eq!(bb.mul_vartime(&l).compress(), Point::IDENTITY.compress());
        assert_eq!(bb.double().compress(), bb.add(&bb).compress());
        assert!(!bb.is_small_order());
        assert!(Point::IDENTITY.is_small_order());
    }
}
