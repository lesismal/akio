//! The P-521 group (`y² = x³ - 3x + b` over `GF(2⁵²¹ - 1)`, prime order `n`): points in
//! homogeneous projective coordinates with the complete formulas of Renes, Costello and Batina
//! (2016, algorithms 4, 5 and 6 for `a = -3`), scalar multiplication, ECDSA.
//!
//! Every addition is complete (correct for equal operands and for the identity), so the
//! secret-scalar multiplications need no argument about exceptional cases:
//!
//! - variable base (ECDH): Booth-recoded signed 5-bit windows (105 of them) over a table
//!   `0·P … 16·P` read in full for every digit, the entry negated by a masked select; five
//!   doublings and one addition per window;
//! - fixed base (key generation, signing): a comb of affine points `j·16ⁱ·G` (`1 ≤ j ≤ 8`, 131
//!   rows) indexed by signed 4-bit digits, the whole row read for every digit, one mixed
//!   addition per digit (computed and discarded by a masked select for a zero digit). A scalar
//!   below `n < 2⁵²¹` has a top nibble of at most 1, so the last digit never carries out.
//!
//! Verification (public inputs) interleaves width-7 wNAF over a table of odd multiples of `G`
//! with width-5 wNAF over the public key, and compares `x(R) ≡ r` projectively. Its branches
//! depend on public data only.

use std::sync::OnceLock;

use super::field::Fe;
use crate::Error;
use crate::ct;
use crate::field::{Fe as ModFe, Modulus};
use crate::hash::Hash;
use crate::mac::Hmac;

/// The group order `n`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct P521N;

impl Modulus<9> for P521N {
    const P: [u64; 9] = [
        0xbb6f_b71e_9138_6409,
        0x3bb5_c9b8_899c_47ae,
        0x7fcc_0148_f709_a5d0,
        0x5186_8783_bf2f_966b,
        0xffff_ffff_ffff_fffa,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x0000_0000_0000_01ff,
    ];
}

/// A scalar modulo `n` (Montgomery form, nine 64-bit limbs).
pub(crate) type Scalar = ModFe<P521N, 9>;

/// The byte length of a coordinate or a scalar.
pub(crate) const LEN: usize = 66;

const B: Fe = Fe::from_limbs([
    0x0345_1fd4_6b50_3f00,
    0x00f7_e20f_4b0d_3c7b,
    0x000b_d3bb_1bf0_7357,
    0x0147_b1fa_4dec_594b,
    0x018e_f109_e156_1939,
    0x026c_c57c_ee2d_2264,
    0x0054_0eea_2da7_25b9,
    0x0268_7e4a_6886_82da,
    0x0051_953e_b961_8e1c,
]);
const GX: Fe = Fe::from_limbs([
    0x017e_7e31_c2e5_bd66,
    0x022c_f061_5a90_a6fe,
    0x0012_7a2f_fa8d_e334,
    0x01df_bf9d_64a3_f877,
    0x006b_4d3d_baa1_4b5e,
    0x014f_ed48_7e0a_2bd8,
    0x015b_4429_c648_1390,
    0x03a7_3678_fb2d_988e,
    0x00c6_858e_06b7_0404,
]);
const GY: Fe = Fe::from_limbs([
    0x00be_9476_9fd1_6650,
    0x031c_21a8_9cb0_9022,
    0x0390_13fa_d076_1353,
    0x0265_7bd0_9903_1542,
    0x0327_3e66_2c97_ee72,
    0x01e6_d11a_05eb_ef45,
    0x03d1_bd99_8f54_4495,
    0x0300_1172_297e_d0b1,
    0x0118_3929_6a78_9a3b,
]);

/// A projective point `(X:Y:Z)`, affine `(X/Z, Y/Z)`; the identity is `(0:1:0)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// Comb rows: 4-bit digits of a 521-bit scalar.
const COMB_ROWS: usize = 131;
/// Booth windows of 5 bits: the top window's sign bit (bit 524) lies above the scalar.
const WINDOWS: usize = 105;

struct Tables {
    /// `comb[i][j - 1] = j·16ⁱ·G`, affine.
    comb: Vec<[[Fe; 2]; 8]>,
    /// `wnaf[i] = (2i + 1)·G`, affine, `0 ≤ i < 32`.
    wnaf: Vec<[Fe; 2]>,
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut pts = Vec::with_capacity(COMB_ROWS * 8 + 32);
        let mut p = Point::generator();
        for _ in 0..COMB_ROWS {
            let mut q = p;
            for _ in 0..8 {
                pts.push(q);
                q = q.add(&p);
            }
            p = pts[pts.len() - 1].double();
        }
        let g = Point::generator();
        let g2 = g.double();
        let mut q = g;
        for _ in 0..32 {
            pts.push(q);
            q = q.add(&g2);
        }
        let aff = Point::batch_to_affine(&pts);
        let n = COMB_ROWS * 8;
        Tables {
            comb: aff[..n]
                .chunks_exact(8)
                .map(|c| {
                    let mut row = [c[0]; 8];
                    row.copy_from_slice(c);
                    row
                })
                .collect(),
            wnaf: aff[n..].to_vec(),
        }
    })
}

impl Point {
    pub(crate) const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ZERO,
    };

    pub(crate) fn generator() -> Point {
        Point {
            x: GX,
            y: GY,
            z: Fe::ONE,
        }
    }

    /// `u64::MAX` for the identity.
    pub(crate) fn is_identity(&self) -> u64 {
        self.z.is_zero()
    }

    fn select(m: u64, a: &Point, b: &Point) -> Point {
        Point {
            x: Fe::select(m, &a.x, &b.x),
            y: Fe::select(m, &a.y, &b.y),
            z: Fe::select(m, &a.z, &b.z),
        }
    }

    pub(crate) fn neg(&self) -> Point {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Complete addition (RCB16 algorithm 4, `a = -3`).
    pub(crate) fn add(&self, q: &Point) -> Point {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&q.x, &q.y, &q.z);
        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t2 = z1.mul(z2);
        let mut t3 = x1.add(y1);
        let mut t4 = x2.add(y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = y1.add(z1);
        let mut x3 = y2.add(z2);
        t4 = t4.mul(&x3);
        x3 = t1.add(&t2);
        t4 = t4.sub(&x3);
        x3 = x1.add(z1);
        let mut y3 = x2.add(z2);
        x3 = x3.mul(&y3);
        y3 = t0.add(&t2);
        y3 = x3.sub(&y3);
        let mut z3 = B.mul(&t2);
        x3 = y3.sub(&z3);
        z3 = x3.add(&x3);
        x3 = x3.add(&z3);
        z3 = t1.sub(&x3);
        x3 = t1.add(&x3);
        y3 = B.mul(&y3);
        t1 = t2.add(&t2);
        t2 = t1.add(&t2);
        y3 = y3.sub(&t2);
        y3 = y3.sub(&t0);
        t1 = y3.add(&y3);
        y3 = t1.add(&y3);
        t1 = t0.add(&t0);
        t0 = t1.add(&t0);
        t0 = t0.sub(&t2);
        t1 = t4.mul(&y3);
        t2 = t0.mul(&y3);
        y3 = x3.mul(&z3);
        y3 = y3.add(&t2);
        x3 = t3.mul(&x3);
        x3 = x3.sub(&t1);
        z3 = t4.mul(&z3);
        t1 = t3.mul(&t0);
        z3 = z3.add(&t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete mixed addition `self + (x2, y2)` (RCB16 algorithm 5, `a = -3`): correct for
    /// every `self`; `(x2, y2)` must be on the curve.
    pub(crate) fn add_affine(&self, x2: &Fe, y2: &Fe) -> Point {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t3 = x2.add(y2);
        let mut t4 = x1.add(y1);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);
        t4 = y2.mul(z1);
        t4 = t4.add(y1);
        let mut y3 = x2.mul(z1);
        y3 = y3.add(x1);
        let mut z3 = B.mul(z1);
        let mut x3 = y3.sub(&z3);
        z3 = x3.add(&x3);
        x3 = x3.add(&z3);
        z3 = t1.sub(&x3);
        x3 = t1.add(&x3);
        y3 = B.mul(&y3);
        t1 = z1.add(z1);
        let mut t2 = t1.add(z1);
        y3 = y3.sub(&t2);
        y3 = y3.sub(&t0);
        t1 = y3.add(&y3);
        y3 = t1.add(&y3);
        t1 = t0.add(&t0);
        t0 = t1.add(&t0);
        t0 = t0.sub(&t2);
        t1 = t4.mul(&y3);
        t2 = t0.mul(&y3);
        y3 = x3.mul(&z3);
        y3 = y3.add(&t2);
        x3 = t3.mul(&x3);
        x3 = x3.sub(&t1);
        z3 = t4.mul(&z3);
        t1 = t3.mul(&t0);
        z3 = z3.add(&t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Doubling (RCB16 algorithm 6, `a = -3`).
    pub(crate) fn double(&self) -> Point {
        let (x, y, z) = (&self.x, &self.y, &self.z);
        let mut t0 = x.square();
        let t1 = y.square();
        let mut t2 = z.square();
        let mut t3 = x.mul(y);
        t3 = t3.add(&t3);
        let mut z3 = x.mul(z);
        z3 = z3.add(&z3);
        let mut y3 = B.mul(&t2);
        y3 = y3.sub(&z3);
        let mut x3 = y3.add(&y3);
        y3 = x3.add(&y3);
        x3 = t1.sub(&y3);
        y3 = t1.add(&y3);
        y3 = x3.mul(&y3);
        x3 = x3.mul(&t3);
        t3 = t2.add(&t2);
        t2 = t2.add(&t3);
        z3 = B.mul(&z3);
        z3 = z3.sub(&t2);
        z3 = z3.sub(&t0);
        t3 = z3.add(&z3);
        z3 = z3.add(&t3);
        t3 = t0.add(&t0);
        t0 = t3.add(&t0);
        t0 = t0.sub(&t2);
        t0 = t0.mul(&z3);
        y3 = y3.add(&t0);
        t0 = y.mul(z);
        t0 = t0.add(&t0);
        z3 = t0.mul(&z3);
        x3 = x3.sub(&z3);
        z3 = t0.mul(&t1);
        z3 = z3.add(&z3);
        z3 = z3.add(&z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Affine coordinates (one constant-time inversion); `None` for the identity.
    pub(crate) fn to_affine(self) -> Option<(Fe, Fe)> {
        if self.is_identity() != 0 {
            return None;
        }
        let zi = self.z.invert();
        Some((self.x.mul(&zi), self.y.mul(&zi)))
    }

    /// The affine x-coordinate (one constant-time inversion); `None` for the identity.
    pub(crate) fn to_affine_x(self) -> Option<Fe> {
        if self.is_identity() != 0 {
            return None;
        }
        Some(self.x.mul(&self.z.invert()))
    }

    /// Affine forms of many points with one inversion; the identity maps to `(0, 0)`.
    fn batch_to_affine(pts: &[Point]) -> Vec<[Fe; 2]> {
        let mut acc = Vec::with_capacity(pts.len());
        let mut a = Fe::ONE;
        for p in pts {
            acc.push(a);
            if p.is_identity() == 0 {
                a = a.mul(&p.z);
            }
        }
        let mut inv = a.invert();
        let mut out = vec![[Fe::ZERO, Fe::ZERO]; pts.len()];
        for (i, p) in pts.iter().enumerate().rev() {
            if p.is_identity() != 0 {
                continue;
            }
            let zi = inv.mul(&acc[i]);
            inv = inv.mul(&p.z);
            out[i] = [p.x.mul(&zi), p.y.mul(&zi)];
        }
        out
    }

    fn rhs(x: &Fe) -> Fe {
        x.square().mul(x).sub(&x.mul_small(3)).add(&B)
    }

    /// From affine coordinates on the curve (checked).
    pub(crate) fn from_affine(x: Fe, y: Fe) -> Option<Point> {
        if y.square().ct_eq(&Self::rhs(&x)) == 0 {
            return None;
        }
        Some(Point { x, y, z: Fe::ONE })
    }

    /// Decodes a SEC1 point: uncompressed (`04 || x || y`, 133 bytes) or compressed
    /// (`02`/`03 || x`, 67 bytes). The identity and points off the curve are rejected.
    pub(crate) fn from_sec1(b: &[u8]) -> Option<Point> {
        match b.first()? {
            4 if b.len() == 1 + 2 * LEN => {
                let x = Fe::from_be_bytes(&b[1..=LEN])?;
                let y = Fe::from_be_bytes(&b[1 + LEN..])?;
                Self::from_affine(x, y)
            }
            t @ (2 | 3) if b.len() == 1 + LEN => {
                let x = Fe::from_be_bytes(&b[1..])?;
                let mut y = Self::rhs(&x).sqrt()?;
                if y.is_odd() != u64::from(t & 1) {
                    y = y.neg();
                }
                Self::from_affine(x, y)
            }
            _ => None,
        }
    }

    /// The uncompressed SEC1 encoding; `None` for the identity.
    pub(crate) fn to_uncompressed(self) -> Option<Vec<u8>> {
        let (x, y) = self.to_affine()?;
        let mut v = Vec::with_capacity(1 + 2 * LEN);
        v.push(4);
        v.extend_from_slice(&x.to_be_bytes());
        v.extend_from_slice(&y.to_be_bytes());
        Some(v)
    }

    /// `[k]self` for a secret `k`, constant time: Booth-recoded signed 5-bit windows over
    /// `0·P … 16·P`. The doublings run in Jacobian coordinates ([`Jac::double`], cheaper than
    /// the complete doubling and also without exceptional cases), the additions with the
    /// complete formula after a conversion.
    pub(crate) fn mul_ct(&self, k: &Scalar) -> Point {
        let k = k.to_limbs();
        let mut table = [Point::IDENTITY; 17];
        table[1] = *self;
        for j in 2..17 {
            table[j] = if j % 2 == 0 {
                table[j / 2].double()
            } else {
                table[j - 1].add(self)
            };
        }
        let mut r = Point::IDENTITY;
        for i in (0..WINDOWS).rev() {
            if i != WINDOWS - 1 {
                let mut j = Jac::from_point(&r);
                for _ in 0..5 {
                    j = j.double();
                }
                r = j.to_point();
            }
            let (d, neg) = crate::ec::booth::<9, 5>(&k, i);
            let mut t = Point::IDENTITY;
            for (j, e) in table.iter().enumerate() {
                t = Point::select(ct::eq(j as u64, d), e, &t);
            }
            t.y = Fe::select(neg, &t.y.neg(), &t.y);
            r = r.add(&t);
        }
        r
    }

    /// `[k]G` for a secret `k`, constant time, from the comb.
    pub(crate) fn mul_base_ct(k: &Scalar) -> Point {
        let k = k.to_limbs();
        let comb = &tables().comb;
        let mut r = Point::IDENTITY;
        let mut carry = 0u64;
        for (i, row) in comb.iter().enumerate() {
            let nib = (k[i / 16] >> (4 * (i % 16))) & 15;
            let (abs, neg, c) = crate::ec::comb_digit(nib, carry);
            carry = c;
            let (mut x, mut y) = (Fe::ZERO, Fe::ZERO);
            for (j, e) in row.iter().enumerate() {
                let m = ct::eq(j as u64 + 1, abs);
                x = Fe::select(m, &e[0], &x);
                y = Fe::select(m, &e[1], &y);
            }
            y = Fe::select(neg, &y.neg(), &y);
            // abs = 0 selected (0, 0), off the curve: the sum is discarded.
            let sum = r.add_affine(&x, &y);
            r = Point::select(ct::is_zero(abs) ^ u64::MAX, &sum, &r);
        }
        debug_assert_eq!(carry, 0);
        r
    }

    /// `[a]G + [b]self` in variable time (public scalars: verification).
    pub(crate) fn mul_add_vartime(&self, a: &Scalar, b: &Scalar) -> Point {
        let wa = crate::ec::wnaf(&a.to_limbs(), 7);
        let wb = crate::ec::wnaf(&b.to_limbs(), 5);
        let gt = &tables().wnaf;
        let mut qt = [*self; 8];
        let q2 = self.double();
        for i in 1..8 {
            qt[i] = qt[i - 1].add(&q2);
        }
        let mut r = Point::IDENTITY;
        // Doublings are batched (in Jacobian coordinates) up to the next addition.
        let mut pending = 0;
        for i in (0..wa.len().max(wb.len())).rev() {
            pending += 1;
            let (da, db) = (
                wa.get(i).copied().unwrap_or(0),
                wb.get(i).copied().unwrap_or(0),
            );
            if da == 0 && db == 0 {
                continue;
            }
            r = r.double_n(pending);
            pending = 0;
            match da {
                0 => {}
                d if d > 0 => {
                    let e = &gt[(d as usize) >> 1];
                    r = r.add_affine(&e[0], &e[1]);
                }
                d => {
                    let e = &gt[((-d) as usize) >> 1];
                    r = r.add_affine(&e[0], &e[1].neg());
                }
            }
            match db {
                0 => {}
                d if d > 0 => r = r.add(&qt[(d as usize) >> 1]),
                d => r = r.add(&qt[((-d) as usize) >> 1].neg()),
            }
        }
        r.double_n(pending)
    }

    /// `2ⁿ·self` through Jacobian doublings.
    fn double_n(&self, n: usize) -> Point {
        let mut j = Jac::from_point(self);
        for _ in 0..n {
            j = j.double();
        }
        j.to_point()
    }
}

/// A point in Jacobian coordinates `(X:Y:Z)`, affine `(X/Z², Y/Z³)`; the identity is
/// `(1:1:0)`. Used for runs of doublings only.
#[derive(Clone, Copy)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Jac {
    /// `(X·Z : Y·Z² : Z)`; the projective identity (`Z = 0`) becomes `(1:1:0)` by a masked
    /// select. Constant time.
    fn from_point(p: &Point) -> Jac {
        let id = p.z.is_zero();
        Jac {
            x: Fe::select(id, &Fe::ONE, &p.x.mul(&p.z)),
            y: Fe::select(id, &Fe::ONE, &p.y.mul(&p.z.square())),
            z: p.z,
        }
    }

    /// `(X·Z : Y : Z³)`; `(1:1:0)` becomes `(0:1:0)`.
    fn to_point(self) -> Point {
        Point {
            x: self.x.mul(&self.z),
            y: self.y,
            z: self.z.square().mul(&self.z),
        }
    }

    /// Doubling for `a = -3` (dbl-2001-b: 3M + 5S), constant time. It has no exceptional case
    /// on a curve of prime order: the identity `(1:1:0)` maps to itself (`α = 3`, `β = 1`,
    /// `X₃ = 1`, `Y₃ = 3·3 - 8 = 1`, `Z₃ = 0`), and no other point has `Y = 0`.
    fn double(&self) -> Jac {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);
        let alpha = self.x.sub(&delta).mul(&self.x.add(&delta)).mul_small(3);
        let beta4 = beta.mul_small(4);
        let x3 = alpha.square().sub(&beta4.mul_small(2));
        let z3 = self.y.add(&self.z).square().sub(&gamma).sub(&delta);
        let y3 = alpha.mul(&beta4.sub(&x3)).sub(&gamma.square().mul_small(8));
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// `bits2int(h)` (RFC 6979 §2.3.2): the leftmost 521 bits of `h` as 66 big-endian bytes.
fn bits2int(h: &[u8]) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    if h.len() < LEN {
        out[LEN - h.len()..].copy_from_slice(h);
        return out;
    }
    // 66 bytes or more: the first 528 bits shifted right by 7.
    let mut prev = 0u8;
    for (o, &b) in out.iter_mut().zip(&h[..LEN]) {
        *o = (prev << 1) | (b >> 7);
        prev = b;
    }
    out
}

/// A 66-byte big-endian value below 2⁵²¹ as a scalar, reduced modulo `n`.
fn scalar_reduce(b: &[u8; LEN]) -> Scalar {
    let mut wide = [0u8; 72];
    wide[6..].copy_from_slice(b);
    Scalar::from_be_bytes_reduce(&wide).unwrap_or(Scalar::ZERO)
}

/// A 66-byte big-endian value as a scalar, if below `n`.
pub(crate) fn scalar_from_bytes(b: &[u8]) -> Option<Scalar> {
    if b.len() != LEN {
        return None;
    }
    let mut wide = [0u8; 72];
    wide[6..].copy_from_slice(b);
    Scalar::from_be_bytes(&wide)
}

/// The canonical 66-byte big-endian encoding of a scalar.
pub(crate) fn scalar_to_bytes(s: &Scalar) -> [u8; LEN] {
    let mut wide = [0u8; 72];
    s.write_be(&mut wide);
    let mut out = [0u8; LEN];
    out.copy_from_slice(&wide[6..]);
    out
}

/// The RFC 6979 nonce for private key `x` and message digest `h`, with HMAC over `H`.
fn rfc6979_nonce<H: Hash>(x: &Scalar, h: &[u8]) -> Scalar {
    let xb = scalar_to_bytes(x);
    let hb = scalar_to_bytes(&scalar_reduce(&bits2int(h)));
    let hl = H::OUTPUT_LEN;
    let mut v = vec![1u8; hl];
    let mut k = vec![0u8; hl];
    for round in [0u8, 1] {
        let mut m = Hmac::<H>::new(&k);
        m.update(&v);
        m.update(&[round]);
        m.update(&xb);
        m.update(&hb);
        k = m.finalize().as_ref().to_vec();
        v = Hmac::<H>::mac(&k, &v).as_ref().to_vec();
    }
    loop {
        let mut t = Vec::with_capacity(LEN + hl);
        while t.len() < LEN {
            v = Hmac::<H>::mac(&k, &v).as_ref().to_vec();
            t.extend_from_slice(&v);
        }
        if let Some(s) = scalar_from_bytes(&bits2int(&t)) {
            if s.is_zero() == 0 {
                return s;
            }
        }
        let mut m = Hmac::<H>::new(&k);
        m.update(&v);
        m.update(&[0]);
        k = m.finalize().as_ref().to_vec();
        v = Hmac::<H>::mac(&k, &v).as_ref().to_vec();
    }
}

/// An ECDSA signature `(r, s)` with both in `[1, n)`.
#[derive(Clone, Copy)]
pub(crate) struct Sig {
    pub(crate) r: Scalar,
    pub(crate) s: Scalar,
}

/// Signs digest `h` with private key `d` (RFC 6979 nonce over `H`).
pub(crate) fn sign<H: Hash>(d: &Scalar, h: &[u8]) -> Sig {
    let e = scalar_reduce(&bits2int(h));
    loop {
        let k = rfc6979_nonce::<H>(d, h);
        let Some(x) = Point::mul_base_ct(&k).to_affine_x() else {
            continue; // unreachable: 0 < k < n
        };
        // r = x mod n (x < p < 2n).
        let r = scalar_reduce(&x.to_be_bytes());
        let s = k.invert().mul(&e.add(&r.mul(d)));
        if r.is_zero() == 0 && s.is_zero() == 0 {
            return Sig { r, s };
        }
    }
}

/// Verifies `sig` on digest `h` under public key `q`.
pub(crate) fn verify(q: &Point, h: &[u8], sig: &Sig) -> Result<(), Error> {
    let e = scalar_reduce(&bits2int(h));
    let w = sig.s.invert_vartime();
    let u1 = e.mul(&w);
    let u2 = sig.r.mul(&w);
    let rp = q.mul_add_vartime(&u1, &u2);
    if rp.is_identity() != 0 {
        return Err(Error::Verification);
    }
    // x(R) = X/Z < p and x(R) mod n == r: X == r·Z, or X == (r + n)·Z when r + n < p.
    let r = scalar_to_bytes(&sig.r);
    let rx = Fe::from_be_bytes(&r).ok_or(Error::Verification)?;
    if rx.mul(&rp.z).ct_eq(&rp.x) != 0 {
        return Ok(());
    }
    let rl = sig.r.to_limbs();
    let mut rn = [0u64; 9];
    ct::add_limbs(&mut rn, &rl, &P521N::P);
    let mut wide = [0u8; 72];
    crate::field::limbs_to_be(&rn, &mut wide);
    if wide[..6].iter().all(|&b| b == 0) {
        if let Some(rnx) = Fe::from_be_bytes(&wide[6..]) {
            if rnx.mul(&rp.z).ct_eq(&rp.x) != 0 {
                return Ok(());
            }
        }
    }
    Err(Error::Verification)
}

/// Parses a fixed-width `r || s` signature (132 bytes), requiring `1 <= r, s < n`.
pub(crate) fn sig_from_fixed(b: &[u8]) -> Result<Sig, Error> {
    if b.len() != 2 * LEN {
        return Err(Error::Encoding);
    }
    let r = scalar_from_bytes(&b[..LEN]).ok_or(Error::Verification)?;
    let s = scalar_from_bytes(&b[LEN..]).ok_or(Error::Verification)?;
    if r.is_zero() != 0 || s.is_zero() != 0 {
        return Err(Error::Verification);
    }
    Ok(Sig { r, s })
}

/// Parses a DER `ECDSA-Sig-Value`, strictly.
pub(crate) fn sig_from_der(b: &[u8]) -> Result<Sig, Error> {
    let mut r = crate::der::Reader::new(b);
    let mut seq = r.sequence()?;
    let ri = seq.read_uint()?;
    let si = seq.read_uint()?;
    seq.finish()?;
    r.finish()?;
    if ri.len() > LEN || si.len() > LEN {
        return Err(Error::Verification);
    }
    let mut fixed = [0u8; 2 * LEN];
    fixed[LEN - ri.len()..LEN].copy_from_slice(ri);
    fixed[2 * LEN - si.len()..].copy_from_slice(si);
    sig_from_fixed(&fixed)
}

/// The DER encoding of a signature.
pub(crate) fn sig_to_der(sig: &Sig) -> Vec<u8> {
    let mut w = crate::der::Writer::new();
    w.sequence(|w| {
        w.uint(&scalar_to_bytes(&sig.r));
        w.uint(&scalar_to_bytes(&sig.s));
    });
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::sub_small;

    fn enc(p: Point) -> Option<Vec<u8>> {
        p.to_uncompressed()
    }

    /// `[k]P` by double-and-add over the bits, complete formulas: the reference.
    fn mul_ref(p: &Point, k: &Scalar) -> Point {
        let k = k.to_limbs();
        let mut r = Point::IDENTITY;
        for i in (0..576).rev() {
            r = r.double();
            if (k[i / 64] >> (i % 64)) & 1 == 1 {
                r = r.add(p);
            }
        }
        r
    }

    fn scalar(l: &[u64; 9]) -> Scalar {
        Scalar::from_limbs_canonical(l).expect("below n")
    }

    #[test]
    fn group_laws() {
        let g = Point::generator();
        assert!(Point::from_affine(GX, GY).is_some());
        let nm1 = scalar(&sub_small(&P521N::P, 1));
        let neg_g = enc(g.neg());
        assert_eq!(enc(Point::mul_base_ct(&nm1)), neg_g);
        assert_eq!(enc(g.mul_ct(&nm1)), neg_g);
        assert_eq!(enc(mul_ref(&g, &nm1)), neg_g);
        // n·G is the identity.
        assert!(mul_ref(&g, &nm1).add(&g).to_affine().is_none());
        assert!(g.add(&g.neg()).to_affine().is_none());
        assert_eq!(enc(g.double()), enc(g.add(&g)));
        assert_eq!(enc(Point::IDENTITY.add(&g)), enc(g));
        let (gx, gy) = g.double().to_affine().unwrap();
        assert_eq!(enc(Point::IDENTITY.add_affine(&gx, &gy)), enc(g.double()));
        let mut rng = crate::rand::ChaChaRng::from_seed([0x21; 32]);
        let mut ks = Vec::new();
        for s in 1..=20u64 {
            let mut l = [0u64; 9];
            l[0] = s;
            ks.push(scalar(&l));
            ks.push(scalar(&sub_small(&P521N::P, s)));
        }
        let mut top = [0u64; 9];
        top[8] = 0x100;
        ks.push(scalar(&top));
        for _ in 0..12 {
            let mut b = [0u8; LEN];
            rng.fill(&mut b);
            b[0] &= 1;
            ks.push(scalar_reduce(&b));
        }
        let q = g.mul_ct(&ks[ks.len() - 1]);
        for k in &ks {
            let want = enc(mul_ref(&g, k));
            assert_eq!(enc(Point::mul_base_ct(k)), want);
            assert_eq!(enc(g.mul_ct(k)), want);
            assert_eq!(enc(q.mul_ct(k)), enc(mul_ref(&q, k)));
            let k2 = k.add(&Scalar::ONE);
            assert_eq!(
                enc(q.mul_add_vartime(k, &k2)),
                enc(mul_ref(&g, k).add(&mul_ref(&q, &k2)))
            );
        }
        // SEC1 round trips, compressed both parities.
        for p in [g, q, g.double()] {
            let u = enc(p).unwrap();
            assert_eq!(enc(Point::from_sec1(&u).unwrap()).unwrap(), u);
            let mut c = u[..=LEN].to_vec();
            c[0] = 2 | (u[u.len() - 1] & 1);
            assert_eq!(enc(Point::from_sec1(&c).unwrap()).unwrap(), u);
            c[0] ^= 1;
            assert_eq!(enc(Point::from_sec1(&c).unwrap().neg()).unwrap(), u);
        }
        let mut bad = enc(g).unwrap();
        bad[100] ^= 1;
        assert!(Point::from_sec1(&bad).is_none());
    }

    #[test]
    fn bits2int_truncates() {
        let h = [0xffu8; 70];
        let b = bits2int(&h);
        assert_eq!(b[0], 1);
        assert!(b[1..].iter().all(|&x| x == 0xff));
        let h = [0xabu8; 64];
        assert_eq!(&bits2int(&h)[2..], &h[..]);
    }
}
