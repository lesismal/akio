//! Curve25519 internals: the field (radix 2⁵¹), the twisted Edwards group of Ed25519 and its
//! scalars modulo the group order `ℓ`.

pub(crate) mod fe;
#[cfg(target_arch = "x86_64")]
pub(crate) mod hw;

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
    /// `base[i][j - 1] = j·16ⁱ·B` for `1 ≤ j ≤ 8`, affine Niels form (signed 4-bit digits).
    base: Vec<[Niels; 8]>,
    /// `(2i + 1)·B` for `0 ≤ i < 32` in affine Niels form (width-7 wNAF, verification).
    base_odd: Vec<Niels>,
}

/// An affine point as `(y + x, y - x, 2d·x·y)` (Niels form), for mixed additions.
#[derive(Clone, Copy, Debug)]
struct Niels {
    ypx: Fe,
    ymx: Fe,
    xy2d: Fe,
}

impl Niels {
    /// The identity, `(1, 1, 0)`: adding it is a no-op (the formulas are complete).
    const IDENTITY: Niels = Niels {
        ypx: Fe::ONE,
        ymx: Fe::ONE,
        xy2d: Fe::ZERO,
    };

    /// The Niels form of the affine point `(x, y)`.
    fn from_affine(x: &Fe, y: &Fe, c: &Consts) -> Niels {
        Niels {
            ypx: y.add(x),
            ymx: y.sub(x),
            xy2d: x.mul(y).mul(&c.d2),
        }
    }

    /// `a` where `m` is all ones, else `b`.
    fn select(m: u64, a: &Niels, b: &Niels) -> Niels {
        Niels {
            ypx: Fe::select(m, &a.ypx, &b.ypx),
            ymx: Fe::select(m, &a.ymx, &b.ymx),
            xy2d: Fe::select(m, &a.xy2d, &b.xy2d),
        }
    }

    /// `-self` where `m` is all ones (`-(x, y) = (-x, y)`: swap `y ± x`, negate `2d·x·y`).
    fn cneg(&self, m: u64) -> Niels {
        let mut r = *self;
        Fe::cswap(m, &mut r.ypx, &mut r.ymx);
        r.xy2d = Fe::select(m, &self.xy2d.neg(), &self.xy2d);
        r
    }
}

/// A point as `(Y + X, Y - X, Z, 2d·T)`, for additions with a variable second operand.
#[derive(Clone, Copy, Debug)]
struct Cached {
    ypx: Fe,
    ymx: Fe,
    z: Fe,
    t2d: Fe,
}

/// A "completed" point `((X:Z), (Y:T))`: the output of additions and doublings before
/// conversion (ref10's `p1p1`).
#[derive(Clone, Copy, Debug)]
struct Completed {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Completed {
    /// To extended coordinates (4M).
    fn to_point(self) -> Point {
        Point {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
            t: self.x.mul(&self.y),
        }
    }

    /// To projective `(X:Y:Z)` (3M; `t` of the result is not maintained).
    fn to_projective(self) -> Point {
        Point {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
            t: Fe::ZERO,
        }
    }
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
            base_odd: Vec::new(),
        };
        // B: y = 4/5, x even.
        let mut by = [0u8; 32];
        let y = Fe::from_u64(4).mul(&Fe::from_u64(5).invert());
        by.copy_from_slice(&y.to_bytes());
        let b = Point::decompress_with(&by, &c).unwrap_or(Point::IDENTITY);
        // j·16ⁱ·B for 1 ≤ j ≤ 8, then all to affine with one inversion (Montgomery's trick).
        let mut pts = Vec::with_capacity(64 * 8);
        let mut p16 = b; // 16^i B
        for _ in 0..64 {
            let mut q = p16;
            for _ in 0..8 {
                pts.push(q);
                q = q.add_with(&p16, &c);
            }
            // 16·16ⁱ·B = 8·16ⁱ·B doubled.
            p16 = pts[pts.len() - 1].double();
        }
        let mut acc = Vec::with_capacity(pts.len());
        let mut a = Fe::ONE;
        for p in &pts {
            acc.push(a);
            a = a.mul(&p.z);
        }
        let mut inv = a.invert();
        let mut base = vec![[Niels::IDENTITY; 8]; 64];
        for (i, p) in pts.iter().enumerate().rev() {
            let zi = inv.mul(&acc[i]);
            inv = inv.mul(&p.z);
            base[i / 8][i % 8] = Niels::from_affine(&p.x.mul(&zi), &p.y.mul(&zi), &c);
        }
        c.base = base;
        let b2 = b.add_with(&b, &c);
        let mut q = b;
        let mut odd = Vec::with_capacity(32);
        for _ in 0..32 {
            let zi = q.z.invert();
            let (x, y) = (q.x.mul(&zi), q.y.mul(&zi));
            odd.push(Niels::from_affine(&x, &y, &c));
            q = q.add_with(&b2, &c);
        }
        c.base_odd = odd;
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

    #[cfg(test)]
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

    /// `[s]B` for a 32-byte little-endian scalar below 2²⁵⁵ (clamped scalars, scalars reduced
    /// modulo `ℓ`), in constant time: signed 4-bit digits `s = Σ dᵢ·16ⁱ`, `dᵢ ∈ [-7, 8]`, one
    /// mixed addition (7M) per digit with the entry `|dᵢ|·16ⁱ·B` found by scanning the whole row
    /// and negated by masked selects; a zero digit adds the identity (the formulas are
    /// complete). Below 2²⁵⁵ the top digit is at most 8, so no carry leaves the last row.
    pub(crate) fn mul_base(s: &[u8; 32]) -> Point {
        debug_assert!(s[31] < 0x80, "mul_base needs a scalar below 2^255");
        let c = consts();
        let mut r = Point::IDENTITY;
        let mut carry = 0u64;
        for (i, row) in c.base.iter().enumerate() {
            let nib = u64::from((s[i / 2] >> (4 * (i & 1))) & 15);
            let (abs, neg, cy) = crate::ec::comb_digit(nib, carry);
            carry = cy;
            let mut e = Niels::IDENTITY;
            for (j, p) in row.iter().enumerate() {
                e = Niels::select(ct::eq(j as u64 + 1, abs), p, &e);
            }
            r = r.add_niels(&e.cneg(neg), false).to_point();
        }
        r
    }

    /// The X25519 (Montgomery) u-coordinate `(1 + y)/(1 - y) = (Z + Y)/(Z - Y)` of this point,
    /// encoded (RFC 7748 §4.1); 0 for the identity. Constant time.
    pub(crate) fn to_montgomery_u(self) -> [u8; 32] {
        self.z
            .add(&self.y)
            .mul(&self.z.sub(&self.y).invert())
            .to_bytes()
    }

    /// `[s]P` in variable time (public scalars only: signature verification).
    #[cfg(test)]
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

    fn cached(&self, c: &Consts) -> Cached {
        Cached {
            ypx: self.y.add(&self.x),
            ymx: self.y.sub(&self.x),
            z: self.z,
            t2d: self.t.mul(&c.d2),
        }
    }

    /// Doubling of a projective point (ref10 `ge_p2_dbl`: 4S; `t` is not read).
    fn double_completed(&self) -> Completed {
        let xx = self.x.square();
        let yy = self.y.square();
        let b = self.z.square().mul_small(2);
        let a = self.x.add(&self.y).square();
        let y3 = yy.add(&xx);
        let z3 = yy.sub(&xx);
        Completed {
            x: a.sub(&y3),
            y: y3,
            z: z3,
            t: b.sub(&z3),
        }
    }

    /// `self ± q` for an affine `q` (ref10 `ge_madd` / `ge_msub`: 3M).
    fn add_niels(&self, q: &Niels, negate: bool) -> Completed {
        let (qp, qm) = if negate {
            (&q.ymx, &q.ypx)
        } else {
            (&q.ypx, &q.ymx)
        };
        let a = self.y.add(&self.x).mul(qp);
        let b = self.y.sub(&self.x).mul(qm);
        let c = q.xy2d.mul(&self.t);
        let d = self.z.add(&self.z);
        let (z, t) = if negate {
            (d.sub(&c), d.add(&c))
        } else {
            (d.add(&c), d.sub(&c))
        };
        Completed {
            x: a.sub(&b),
            y: a.add(&b),
            z,
            t,
        }
    }

    /// `self ± q` (ref10 `ge_add` / `ge_sub`: 4M).
    fn add_cached(&self, q: &Cached, negate: bool) -> Completed {
        let (qp, qm) = if negate {
            (&q.ymx, &q.ypx)
        } else {
            (&q.ypx, &q.ymx)
        };
        let a = self.y.add(&self.x).mul(qp);
        let b = self.y.sub(&self.x).mul(qm);
        let c = q.t2d.mul(&self.t);
        let d = self.z.mul(&q.z);
        let d = d.add(&d);
        let (z, t) = if negate {
            (d.sub(&c), d.add(&c))
        } else {
            (d.add(&c), d.sub(&c))
        };
        Completed {
            x: a.sub(&b),
            y: a.add(&b),
            z,
            t,
        }
    }

    /// `[s]B + [k]self` in variable time (public scalars: verification): width-7 wNAF of `s`
    /// over the precomputed odd multiples of `B`, width-5 wNAF of `k` over `self, 3·self, …,
    /// 15·self`, one shared chain of doublings in projective coordinates.
    pub(crate) fn mul_add_base_vartime(&self, s: &[u8; 32], k: &[u8; 32]) -> Point {
        let c = consts();
        let ws = crate::ec::wnaf(&field::le_to_limbs::<4>(s).unwrap_or([0; 4]), 7);
        let wk = crate::ec::wnaf(&field::le_to_limbs::<4>(k).unwrap_or([0; 4]), 5);
        let mut table = [self.cached(c); 8];
        let p2 = self.double();
        let mut q = *self;
        for e in table.iter_mut().skip(1) {
            q = q.add_with(&p2, c);
            *e = q.cached(c);
        }
        let n = ws.len().max(wk.len());
        let mut r = Point::IDENTITY;
        for i in (0..n).rev() {
            let mut t = r.double_completed();
            let ds = ws.get(i).copied().unwrap_or(0);
            let dk = wk.get(i).copied().unwrap_or(0);
            if ds != 0 {
                let u = t.to_point();
                t = u.add_niels(&c.base_odd[usize::from(ds.unsigned_abs() >> 1)], ds < 0);
            }
            if dk != 0 {
                let u = t.to_point();
                t = u.add_cached(&table[usize::from(dk.unsigned_abs() >> 1)], dk < 0);
            }
            r = if i == 0 {
                t.to_point()
            } else {
                t.to_projective()
            };
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

    /// The interleaved wNAF double multiplication matches the separate ones.
    #[test]
    fn mul_add_base() {
        let mut rng = crate::rand::ChaChaRng::from_seed([25; 32]);
        let a = Point::mul_base(&[7; 32]);
        for i in 0..30 {
            let (mut s, mut k) = ([0u8; 32], [0u8; 32]);
            rng.fill(&mut s);
            rng.fill(&mut k);
            s[31] &= 0x1f;
            k[31] &= 0x1f;
            if i == 0 {
                s = [0; 32];
            }
            if i == 1 {
                k = [0; 32];
            }
            let want = Point::mul_base(&s).add(&a.mul_vartime(&k));
            assert_eq!(a.mul_add_base_vartime(&s, &k).compress(), want.compress());
        }
        assert_eq!(
            a.mul_add_base_vartime(&[0; 32], &[0; 32]).compress(),
            Point::IDENTITY.compress()
        );
    }
}
