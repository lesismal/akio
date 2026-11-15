//! Short Weierstrass curves `y² = x³ - 3x + b` over prime fields (P-256, P-384), ECDH and ECDSA.
//!
//! Scalar multiplication works in Jacobian coordinates with the `a = -3` formulas
//! (dbl-2001-b: 3M + 5S; add-2007-bl: 11M + 5S; madd-2007-bl: 7M + 4S).
//!
//! Secret scalars, constant time (always the same sequence of field operations and memory
//! accesses):
//!
//! - variable base (ECDH): Booth-recoded signed 5-bit windows (digits in `[-16, 16]`, 52 windows
//!   for P-256) over a table of `1·P … 16·P`, read in full for every digit and negated by a
//!   masked select; five doublings and one addition per window;
//! - fixed base (key generation, signing): a precomputed comb of affine points `j·16ⁱ·G`
//!   (`1 ≤ j ≤ 8`) indexed by signed 4-bit digits, one mixed addition per digit, the whole row
//!   read for every digit.
//!
//! The Jacobian addition formulas are not complete: they fail when an operand is the identity
//! and when both operands are equal. The identity cases are handled by masked selects (an
//! accumulator still at the identity, a zero digit). Equal operands cannot occur for scalars in
//! `[1, n)` on a prime-order curve, as [`Jac::mul_ct`] and [`Jac::mul_base_ct`] prove; the
//! sum of a point and its negation correctly comes out as `Z = 0`. Points enter as validated
//! affine points (`Z = 1`) and leave through one inversion.
//!
//! Verification (public inputs) interleaves width-5 wNAF over the public key with width-7 wNAF
//! over a precomputed table of odd multiples of `G`, sharing one chain of doublings; it compares
//! `x(R) ≡ r` projectively, without an inversion. Its branches depend on public data only.
//!
//! Decoding, validation and the table construction use projective coordinates with the complete
//! formulas of Renes, Costello and Batina (2016, algorithms 4 and 6 for `a = -3`).
//!
//! A curve can route the high-level operations to a twin whose base field uses CPU instructions
//! (P-256 on x86_64 with BMI2 + ADX: `hw`); the twin shares the Montgomery representation and the
//! base point tables.

pub(crate) mod api;
pub(crate) mod curves;
#[cfg(target_arch = "x86_64")]
pub(crate) mod hw;

use std::marker::PhantomData;

use crate::Error;
use crate::ct;
use crate::field::{Fe, Modulus, add_small_shr};
use crate::hash::Hash;
use crate::mac::Hmac;

/// Curve parameters for a curve over an `L`-limb field.
pub(crate) trait Curve<const L: usize>: Copy + Send + Sync + 'static {
    /// The base field modulus.
    type Fp: Modulus<L>;
    /// The group order.
    type Fq: Modulus<L>;
    /// `b`, canonical little-endian limbs.
    const B: [u64; L];
    /// The base point.
    const GX: [u64; L];
    const GY: [u64; L];
    /// The base point tables, built once (with [`BaseTables::build`]).
    fn tables() -> &'static BaseTables<L>;

    /// `d·G` for a secret `d`, as a projective point (no inversion: the affine form is computed,
    /// in constant time, when the point is encoded). A curve with a hardware twin overrides the
    /// four operations here to dispatch to it.
    #[inline]
    fn base_mul(d: &Scalar<Self, L>) -> Point<Self, L> {
        base_mul_impl::<Self, L>(d)
    }

    /// The big-endian x-coordinate of `d·q` into `out` (`8L` bytes) for a secret `d`; `false`
    /// (nothing written) for the identity.
    #[inline]
    fn ecdh_x(d: &Scalar<Self, L>, q: &Point<Self, L>, out: &mut [u8]) -> bool {
        ecdh_x_impl::<Self, L>(d, q, out)
    }

    /// ECDSA signature of digest `h` under `d` (RFC 6979 nonce over `H`).
    #[inline]
    fn sign_digest<H: Hash>(d: &Scalar<Self, L>, h: &[u8]) -> Sig<Self, L> {
        sign_impl::<Self, H, L>(d, h)
    }

    /// ECDSA verification of `sig` on digest `h` under `q`.
    #[inline]
    fn verify_digest(q: &Point<Self, L>, h: &[u8], sig: &Sig<Self, L>) -> Result<(), Error> {
        verify_impl::<Self, L>(q, h, sig)
    }
}

/// An affine point `(x, y)` (never the identity).
pub(crate) type Affine<C, const L: usize> = (Fp<C, L>, Fp<C, L>);

/// An affine point as the Montgomery-form limbs of `x` and `y` (shared by a curve and its
/// hardware twin).
type RawAffine<const L: usize> = [[u64; L]; 2];

/// Precomputed multiples of the base point.
pub(crate) struct BaseTables<const L: usize> {
    /// `comb[i][j - 1] = j·16ⁱ·G` for `1 ≤ j ≤ 8`, `16L + 1` rows (signed digits carry into the
    /// last one).
    comb: Vec<[RawAffine<L>; 8]>,
    /// `wnaf[i] = (2i + 1)·G`, `0 ≤ i < 32` (width-7 wNAF digits).
    wnaf: Vec<RawAffine<L>>,
}

/// The point behind a table entry.
#[inline]
fn raw_affine<C: Curve<L>, const L: usize>(e: &RawAffine<L>) -> Affine<C, L> {
    (Fe::from_mont(e[0]), Fe::from_mont(e[1]))
}

impl<const L: usize> BaseTables<L> {
    /// Computes the tables (projective arithmetic, then one batched inversion).
    pub(crate) fn build<C: Curve<L>>() -> Self {
        let mut pts = Vec::with_capacity((16 * L + 1) * 8 + 32);
        let mut p = Point::<C, L>::generator();
        for _ in 0..=16 * L {
            let mut q = p;
            for _ in 0..8 {
                pts.push(q);
                q = q.add(&p);
            }
            // 16·16ⁱ·G = 8·16ⁱ·G doubled.
            p = pts[pts.len() - 1].double();
        }
        let g = Point::<C, L>::generator();
        let g2 = g.double();
        let mut q = g;
        for _ in 0..32 {
            pts.push(q);
            q = q.add(&g2);
        }
        let aff: Vec<RawAffine<L>> = Point::batch_to_affine(&pts)
            .iter()
            .map(|(x, y)| [x.l, y.l])
            .collect();
        let n = (16 * L + 1) * 8;
        let comb = aff[..n]
            .chunks_exact(8)
            .map(|c| {
                let mut row = [c[0]; 8];
                row.copy_from_slice(c);
                row
            })
            .collect();
        BaseTables {
            comb,
            wnaf: aff[n..].to_vec(),
        }
    }
}

pub(crate) type Fp<C, const L: usize> = Fe<<C as Curve<L>>::Fp, L>;
pub(crate) type Scalar<C, const L: usize> = Fe<<C as Curve<L>>::Fq, L>;

/// A projective point `(X:Y:Z)`, affine `(X/Z, Y/Z)`; the identity is `(0:1:0)`.
pub(crate) struct Point<C: Curve<L>, const L: usize> {
    x: Fp<C, L>,
    y: Fp<C, L>,
    z: Fp<C, L>,
    _c: PhantomData<C>,
}

impl<C: Curve<L>, const L: usize> Clone for Point<C, L> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Curve<L>, const L: usize> Copy for Point<C, L> {}

impl<C: Curve<L>, const L: usize> std::fmt::Debug for Point<C, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Point(..)")
    }
}

fn curve_b<C: Curve<L>, const L: usize>() -> Fp<C, L> {
    struct B<C, const L: usize>(PhantomData<C>);
    impl<C: Curve<L>, const L: usize> B<C, L> {
        const MONT: Fp<C, L> = Fp::<C, L>::from_canonical_const(C::B);
    }
    B::<C, L>::MONT
}

impl<C: Curve<L>, const L: usize> Point<C, L> {
    pub(crate) const LEN: usize = 8 * L;

    #[cfg(test)]
    pub(crate) fn identity() -> Self {
        Point {
            x: Fp::<C, L>::ZERO,
            y: Fp::<C, L>::ONE,
            z: Fp::<C, L>::ZERO,
            _c: PhantomData,
        }
    }

    pub(crate) fn generator() -> Self {
        Point {
            x: Fp::<C, L>::from_limbs_reduce(&C::GX),
            y: Fp::<C, L>::from_limbs_reduce(&C::GY),
            z: Fp::<C, L>::ONE,
            _c: PhantomData,
        }
    }

    /// `u64::MAX` for the identity.
    pub(crate) fn is_identity(&self) -> u64 {
        self.z.is_zero()
    }

    /// Complete addition (RCB16 algorithm 4, a = -3).
    pub(crate) fn add(&self, q: &Self) -> Self {
        let b = curve_b::<C, L>();
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
        let mut z3 = b.mul(&t2);
        x3 = y3.sub(&z3);
        z3 = x3.add(&x3);
        x3 = x3.add(&z3);
        z3 = t1.sub(&x3);
        x3 = t1.add(&x3);
        y3 = b.mul(&y3);
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
            _c: PhantomData,
        }
    }

    /// Doubling (RCB16 algorithm 6, a = -3).
    pub(crate) fn double(&self) -> Self {
        let b = curve_b::<C, L>();
        let (x, y, z) = (&self.x, &self.y, &self.z);
        let mut t0 = x.square();
        let t1 = y.square();
        let mut t2 = z.square();
        let mut t3 = x.mul(y);
        t3 = t3.add(&t3);
        let mut z3 = x.mul(z);
        z3 = z3.add(&z3);
        let mut y3 = b.mul(&t2);
        y3 = y3.sub(&z3);
        let mut x3 = y3.add(&y3);
        y3 = x3.add(&y3);
        x3 = t1.sub(&y3);
        y3 = t1.add(&y3);
        y3 = x3.mul(&y3);
        x3 = x3.mul(&t3);
        t3 = t2.add(&t2);
        t2 = t2.add(&t3);
        z3 = b.mul(&z3);
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
            _c: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn neg(&self) -> Self {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
            _c: PhantomData,
        }
    }

    /// The same point on a twin curve (same base field modulus and Montgomery form).
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    #[inline]
    pub(crate) fn cast<D: Curve<L>>(&self) -> Point<D, L> {
        debug_assert_eq!(
            <C::Fp as Modulus<L>>::P,
            <D::Fp as Modulus<L>>::P,
            "not a twin"
        );
        Point {
            x: Fe::from_mont(self.x.l),
            y: Fe::from_mont(self.y.l),
            z: Fe::from_mont(self.z.l),
            _c: PhantomData,
        }
    }

    #[cfg(test)]
    fn select(m: u64, a: &Self, b: &Self) -> Self {
        Point {
            x: Fe::select(m, &a.x, &b.x),
            y: Fe::select(m, &a.y, &b.y),
            z: Fe::select(m, &a.z, &b.z),
            _c: PhantomData,
        }
    }

    /// `table[idx]`, reading every entry.
    #[cfg(test)]
    fn lookup(table: &[Self; 16], idx: u64) -> Self {
        let mut r = Self::identity();
        for (j, p) in table.iter().enumerate() {
            r = Self::select(ct::eq(j as u64, idx), p, &r);
        }
        r
    }

    /// `[k]self` with the complete formulas (fixed 4-bit windows, full-table lookups): the
    /// reference for the Jacobian multiplications in tests.
    #[cfg(test)]
    pub(crate) fn mul_ref(&self, k: &Scalar<C, L>) -> Self {
        let k = k.to_limbs();
        let mut table = [Self::identity(); 16];
        for j in 1..16 {
            table[j] = table[j - 1].add(self);
        }
        let mut r = Self::identity();
        for i in (0..16 * L).rev() {
            r = r.double().double().double().double();
            r = r.add(&Self::lookup(&table, nibble(&k, i)));
        }
        r
    }

    /// Complete mixed addition `self + (x2, y2)` (RCB16 algorithm 5, a = -3): correct for every
    /// `self`, including the identity; `(x2, y2)` must be a point on the curve (not the
    /// identity, which has no affine form). Constant time.
    #[cfg(test)]
    pub(crate) fn add_affine(&self, x2: &Fp<C, L>, y2: &Fp<C, L>) -> Self {
        let b = curve_b::<C, L>();
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
        let mut z3 = b.mul(z1);
        let mut x3 = y3.sub(&z3);
        z3 = x3.add(&x3);
        x3 = x3.add(&z3);
        z3 = t1.sub(&x3);
        x3 = t1.add(&x3);
        y3 = b.mul(&y3);
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
            _c: PhantomData,
        }
    }

    /// `[k]G` from the comb with the complete mixed addition: the reference for
    /// [`Jac::mul_base_ct`] in tests.
    #[cfg(test)]
    pub(crate) fn mul_base_ref(k: &Scalar<C, L>) -> Self {
        let k = k.to_limbs();
        let comb = &C::tables().comb;
        let mut r = Self::identity();
        let mut carry = 0u64;
        for (i, row) in comb.iter().enumerate().take(16 * L) {
            let (abs, neg, c) = comb_digit(nibble(&k, i), carry);
            carry = c;
            let (mut x, mut y) = (Fp::<C, L>::ZERO, Fp::<C, L>::ZERO);
            for (j, e) in row.iter().enumerate() {
                let m = ct::eq(j as u64 + 1, abs);
                let (px, py) = raw_affine::<C, L>(e);
                x = Fe::select(m, &px, &x);
                y = Fe::select(m, &py, &y);
            }
            y = Fe::select(neg, &y.neg(), &y);
            let sum = r.add_affine(&x, &y);
            r = Self::select(ct::is_zero(abs) ^ u64::MAX, &sum, &r);
        }
        let (x, y) = raw_affine::<C, L>(&comb[16 * L][0]);
        let sum = r.add_affine(&x, &y);
        Self::select(ct::mask(carry), &sum, &r)
    }

    /// Affine forms of many points with one inversion (Montgomery's trick); the identity maps
    /// to `(0, 0)`. For public points (tables).
    pub(crate) fn batch_to_affine(pts: &[Self]) -> Vec<Affine<C, L>> {
        let mut acc = Vec::with_capacity(pts.len());
        let mut a = Fp::<C, L>::ONE;
        for p in pts {
            acc.push(a);
            if p.is_identity() == 0 {
                a = a.mul(&p.z);
            }
        }
        let mut inv = a.invert();
        let mut out = vec![(Fp::<C, L>::ZERO, Fp::<C, L>::ZERO); pts.len()];
        for (i, p) in pts.iter().enumerate().rev() {
            if p.is_identity() != 0 {
                continue;
            }
            let zi = inv.mul(&acc[i]);
            inv = inv.mul(&p.z);
            out[i] = (p.x.mul(&zi), p.y.mul(&zi));
        }
        out
    }

    /// `[a]G + [b]self` in variable time (public scalars: verification), as a projective
    /// point.
    #[cfg(test)]
    pub(crate) fn mul_add_base_vartime(&self, a: &Scalar<C, L>, b: &Scalar<C, L>) -> Self {
        let j = Jac::<C, L>::mul_add_vartime(self, a, b);
        if j.is_identity() {
            return Self::identity();
        }
        // Jacobian (X:Y:Z) is projective (X·Z : Y : Z³).
        Point {
            x: j.x.mul(&j.z),
            y: j.y,
            z: j.z.square().mul(&j.z),
            _c: PhantomData,
        }
    }

    /// Affine coordinates of a public point, skipping the inversion when `Z = 1` (decoded
    /// points); `None` for the identity. Variable time.
    fn to_affine_vartime(self) -> Option<Affine<C, L>> {
        if self.is_identity() != 0 {
            return None;
        }
        if self.z.ct_eq(&Fp::<C, L>::ONE) != 0 {
            return Some((self.x, self.y));
        }
        self.to_affine()
    }

    /// Affine coordinates; `None` for the identity.
    pub(crate) fn to_affine(self) -> Option<(Fp<C, L>, Fp<C, L>)> {
        if self.is_identity() != 0 {
            return None;
        }
        let zi = self.z.invert();
        Some((self.x.mul(&zi), self.y.mul(&zi)))
    }

    /// From affine coordinates on the curve (checked).
    pub(crate) fn from_affine(x: Fp<C, L>, y: Fp<C, L>) -> Option<Self> {
        // y² = x³ - 3x + b
        let rhs = x
            .square()
            .mul(&x)
            .sub(&x.double().add(&x))
            .add(&curve_b::<C, L>());
        if y.square().ct_eq(&rhs) == 0 {
            return None;
        }
        Some(Point {
            x,
            y,
            z: Fp::<C, L>::ONE,
            _c: PhantomData,
        })
    }

    /// Decodes a SEC1 point: uncompressed (`04 || x || y`) or compressed (`02`/`03 || x`).
    /// The identity (`00`) and points off the curve are rejected.
    pub(crate) fn from_sec1(b: &[u8]) -> Option<Self> {
        let n = Self::LEN;
        match b.first()? {
            4 if b.len() == 1 + 2 * n => {
                let x = Fp::<C, L>::from_be_bytes(&b[1..=n])?;
                let y = Fp::<C, L>::from_be_bytes(&b[1 + n..])?;
                Self::from_affine(x, y)
            }
            t @ (2 | 3) if b.len() == 1 + n => {
                let x = Fp::<C, L>::from_be_bytes(&b[1..])?;
                let rhs = x
                    .square()
                    .mul(&x)
                    .sub(&x.double().add(&x))
                    .add(&curve_b::<C, L>());
                // p ≡ 3 (mod 4): √a = a^((p+1)/4).
                let e = add_small_shr(&<C::Fp as Modulus<L>>::P, 1, 2);
                let mut y = rhs.pow_vartime_exp(&e);
                if y.square().ct_eq(&rhs) == 0 {
                    return None;
                }
                let odd = y.to_limbs()[0] & 1;
                if odd != u64::from(t & 1) {
                    y = y.neg();
                }
                Self::from_affine(x, y)
            }
            _ => None,
        }
    }

    /// The uncompressed SEC1 encoding (`04 || x || y`); `None` for the identity. Variable time
    /// (public points: the inversion is skipped for `Z = 1`).
    pub(crate) fn to_uncompressed(self) -> Option<Vec<u8>> {
        let (x, y) = self.to_affine_vartime()?;
        let n = Self::LEN;
        let mut v = vec![0u8; 1 + 2 * n];
        v[0] = 4;
        x.write_be(&mut v[1..=n]);
        y.write_be(&mut v[1 + n..]);
        Some(v)
    }
}

/// The 4-bit digit `i` (from the least significant) of little-endian limbs.
#[inline]
fn nibble<const L: usize>(k: &[u64; L], i: usize) -> u64 {
    (k[i / 16] >> (4 * (i % 16))) & 15
}

/// One signed comb digit: the nibble plus the incoming carry, `d ∈ [0, 16]`, becomes
/// `d - 16` with an outgoing carry when `d ≥ 9`. Returns `(|digit|, negative mask, carry)`,
/// without branches.
#[inline]
pub(crate) fn comb_digit(nib: u64, carry: u64) -> (u64, u64, u64) {
    let d = nib + carry;
    let c = (d + 7) >> 4;
    let sd = d.wrapping_sub(c << 4); // two's complement of d - 16·c
    let neg = ct::mask(sd >> 63);
    let abs = (sd ^ neg).wrapping_sub(neg);
    (abs, neg, c)
}

/// The number of signed 5-bit windows of an `L`-limb scalar: the top window's sign bit (bit
/// `5w - 1`) lies above the scalar, so the top digit is not negative.
const fn booth_windows(l: usize) -> usize {
    (64 * l + 5) / 5
}

/// The Booth digit of window `i` of `k`: bits `5i - 1 ..= 5i + 4` (bit -1 is 0) recoded to
/// `|d| ∈ [0, 16]` and a mask set when `d < 0`, so that `k = Σ dᵢ·32ⁱ` (OpenSSL's
/// `booth_recode_w5`). The bit positions are public; the digit is computed without branches.
#[inline]
fn booth5<const L: usize>(k: &[u64; L], i: usize) -> (u64, u64) {
    let w = if i == 0 {
        (k[0] << 1) & 63
    } else {
        let pos = 5 * i - 1;
        let (limb, off) = (pos / 64, pos % 64);
        let lo = k.get(limb).copied().unwrap_or(0) >> off;
        let hi = if off > 58 {
            k.get(limb + 1).copied().unwrap_or(0) << (64 - off)
        } else {
            0
        };
        (lo | hi) & 63
    };
    let s = ct::mask(w >> 5);
    let d = ((63 - w) & s) | (w & !s);
    ((d >> 1) + (d & 1), s)
}

/// A point in Jacobian coordinates `(X:Y:Z)`, affine `(X/Z², Y/Z³)`, `Z = 0` for the identity.
/// The `*_ct` operations and the doubling are constant time (secret scalars); the others branch
/// on their inputs (verification: public points and scalars).
pub(crate) struct Jac<C: Curve<L>, const L: usize> {
    x: Fp<C, L>,
    y: Fp<C, L>,
    z: Fp<C, L>,
}

impl<C: Curve<L>, const L: usize> Clone for Jac<C, L> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: Curve<L>, const L: usize> Copy for Jac<C, L> {}

/// Constant-time Jacobian arithmetic for secret scalars.
impl<C: Curve<L>, const L: usize> Jac<C, L> {
    fn select(m: u64, a: &Self, b: &Self) -> Self {
        Jac {
            x: Fe::select(m, &a.x, &b.x),
            y: Fe::select(m, &a.y, &b.y),
            z: Fe::select(m, &a.z, &b.z),
        }
    }

    /// The Jacobian form `(X·Z : Y·Z² : Z)` of a projective point.
    fn from_point(p: &Point<C, L>) -> Self {
        Jac {
            x: p.x.mul(&p.z),
            y: p.y.mul(&p.z.square()),
            z: p.z,
        }
    }

    /// `self + q` (add-2007-bl: 11M + 5S) without special cases: correct when neither operand
    /// is the identity and `self ≠ q`; `self = -q` gives `Z = 0`, the identity.
    fn add_core(&self, q: &Self) -> Self {
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = q.x.mul(&z1z1);
        let s1 = self.y.mul(&q.z).mul(&z2z2);
        let s2 = q.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let r = s2.sub(&s1).double();
        let i = h.double().square();
        let j = h.mul(&i);
        let v = u1.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).double());
        let z3 = self.z.add(&q.z).square().sub(&z1z1).sub(&z2z2).mul(&h);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + (x2, y2)` (madd-2007-bl: 7M + 4S) without special cases: correct when `self`
    /// is not the identity and not `(x2, y2)`; `self = -(x2, y2)` gives `Z = 0`.
    fn madd_core(&self, x2: &Fp<C, L>, y2: &Fp<C, L>) -> Self {
        let z1z1 = self.z.square();
        let u2 = x2.mul(&z1z1);
        let s2 = y2.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let hh = h.square();
        let i = hh.mul_pow2(2);
        let j = h.mul(&i);
        let r = s2.sub(&self.y).double();
        let v = self.x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&j).double());
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + q` in constant time, correct when either operand is the identity (masked
    /// selects); `self ≠ q` otherwise (the caller's invariant).
    fn add_ct(&self, q: &Self) -> Self {
        let s = self.add_core(q);
        let s = Self::select(q.z.is_zero(), self, &s);
        Self::select(self.z.is_zero(), q, &s)
    }

    /// `self + (x2, y2)` in constant time, correct when `self` is the identity (masked select);
    /// `self ≠ (x2, y2)` otherwise (the caller's invariant).
    fn madd_ct(&self, x2: &Fp<C, L>, y2: &Fp<C, L>) -> Self {
        let s = self.madd_core(x2, y2);
        let q = Jac {
            x: *x2,
            y: *y2,
            z: Fp::<C, L>::ONE,
        };
        Self::select(self.z.is_zero(), &q, &s)
    }

    /// `table[d - 1]` for `d ∈ [1, 16]`, the identity for `d = 0`, reading every entry.
    #[inline]
    fn lookup(table: &[Self; 16], d: u64) -> Self {
        let mut r = Self::identity();
        for (j, p) in table.iter().enumerate() {
            r = Self::select(ct::eq(j as u64 + 1, d), p, &r);
        }
        r
    }

    /// `[k]p` for a secret `k`, in constant time; `p` must have order `n` (every point other
    /// than the identity: P-256 and P-384 have prime order) and `k ∈ [1, n)` (a `Scalar` is
    /// reduced; `k = 0` gives the identity, possibly with a wrong `X`, `Y`).
    ///
    /// Booth-recoded signed 5-bit windows `k = Σ dᵢ·32ⁱ`, `dᵢ ∈ [-16, 16]`, from the top: five
    /// doublings, then the addition of `table[|dᵢ|]` (read in full, negated by a masked select).
    ///
    /// The addition never meets equal operands. Write `Mⱼ = Σ_{i≥j} dᵢ·32^(i-j)`: the accumulator
    /// before adding `dⱼ` is `A = 32·Mⱼ₊₁` (times `p`), and `A + dⱼ = Mⱼ`. The lower digits sum to
    /// less than `32ʲ/1.9` in absolute value, so `0 ≤ Mⱼ < n` for `j ≥ 1` and `0 ≤ A < n`.
    /// Equal operands mean `A ≡ dⱼ (mod n)`. For `j ≥ 1` both sides are below `n` in absolute
    /// value, so `A = dⱼ`; as `32 | A` and `|dⱼ| ≤ 16`, `A = dⱼ = 0`: both operands are the
    /// identity, which the masked selects handle. For `j = 0`, `A - d₀ = k - 2d₀ ≡ 0` needs
    /// `k = 2d₀` (then `A = d₀ = 0`, `k = 0`, excluded) or `k = n - 2|d₀|` with `A = n - |d₀|`, a
    /// multiple of 32: `n ≡ |d₀| (mod 32)`, impossible as `n mod 32 ≥ 17` for both curves
    /// (checked in the tests). `A ≡ -dⱼ` is the sum `Mⱼ ≡ 0`, the identity, which the formula
    /// yields as `Z = 0` (and `j = 0` would need `k ≡ 0`).
    pub(crate) fn mul_ct(p: &Point<C, L>, k: &Scalar<C, L>) -> Self {
        let k = k.to_limbs();
        let p1 = Self::from_point(p);
        // table[j] = (j + 1)·p: no addition here meets equal operands (jP ≠ ±P for 2 ≤ j ≤ 15).
        let mut table = [p1; 16];
        for j in 1..16 {
            table[j] = if j % 2 == 1 {
                table[j / 2].double()
            } else {
                table[j - 1].add_core(&p1)
            };
        }
        let w = booth_windows(L);
        let mut r = Self::identity();
        for i in (0..w).rev() {
            if i != w - 1 {
                r = r.double().double().double().double().double();
            }
            let (d, neg) = booth5(&k, i);
            let mut t = Self::lookup(&table, d);
            t.y = Fe::select(neg, &t.y.neg(), &t.y);
            r = r.add_ct(&t);
        }
        r
    }

    /// `[k]G` for a secret `k`, in constant time, from the comb: `k = Σ dᵢ·16ⁱ` with signed
    /// digits `dᵢ ∈ [-7, 8]` (a carry into the extra top row), one mixed addition per digit.
    /// Each digit's entry is found by reading the whole row with masked selects, negated by a
    /// masked select; the addition of a zero digit is computed and discarded by a masked
    /// select, and an accumulator still at the identity takes the entry by a masked select.
    ///
    /// The addition never meets equal operands: before row `j` the accumulator is
    /// `Sⱼ = Σ_{i<j} dᵢ·16ⁱ` (times `G`) with `|Sⱼ| ≤ 8·(16ʲ - 1)/15 < 0.54·16ʲ`, and the entry
    /// is `±dⱼ·16ʲ` with `dⱼ ≠ 0`, so `0 < |Sⱼ ∓ dⱼ·16ʲ| < 8.54·16ʲ`, below `n` for every
    /// regular row (`8.54·2^(64L-4) < 2^(64L-0.9) < n`): never `≡ 0 (mod n)`. The top row adds
    /// `2^(64L)·G` only when the last digit carried, which needs `k ≥ 2^(64L-1)`; equality
    /// there means `k ≡ 2^(64L+1) (mod n)` (or `k ≡ 0`), and that residue is
    /// `2^(64L+1) - 2n < 2^(64L-30)`, far smaller.
    pub(crate) fn mul_base_ct(k: &Scalar<C, L>) -> Self {
        let k = k.to_limbs();
        let comb = &C::tables().comb;
        let mut r = Self::identity();
        let mut carry = 0u64;
        for (i, row) in comb.iter().enumerate().take(16 * L) {
            let (abs, neg, c) = comb_digit(nibble(&k, i), carry);
            carry = c;
            let mut e = [[0u64; L]; 2];
            for (j, entry) in row.iter().enumerate() {
                let m = ct::eq(j as u64 + 1, abs);
                ct::assign(m, &mut e[0], &entry[0]);
                ct::assign(m, &mut e[1], &entry[1]);
            }
            let (x, y) = raw_affine::<C, L>(&e);
            let y = Fe::select(neg, &y.neg(), &y);
            // abs = 0 selected (0, 0), off the curve: the sum is discarded.
            let sum = r.madd_ct(&x, &y);
            r = Self::select(ct::is_zero(abs) ^ u64::MAX, &sum, &r);
        }
        let (x, y) = raw_affine::<C, L>(&comb[16 * L][0]);
        let sum = r.madd_ct(&x, &y);
        Self::select(ct::mask(carry), &sum, &r)
    }

    /// The affine x-coordinate (one constant-time inversion); `None` for the identity.
    fn to_affine_x(self) -> Option<Fp<C, L>> {
        if self.z.is_zero() != 0 {
            return None;
        }
        Some(self.x.mul(&self.z.invert().square()))
    }

    /// The projective form `(X·Z : Y : Z³)` (no inversion; the identity stays `Z = 0`).
    fn to_projective(self) -> Point<C, L> {
        Point {
            x: self.x.mul(&self.z),
            y: self.y,
            z: self.z.square().mul(&self.z),
            _c: PhantomData,
        }
    }

    /// The affine coordinates (one constant-time inversion); `None` for the identity.
    #[cfg(test)]
    fn to_affine(self) -> Option<Affine<C, L>> {
        if self.z.is_zero() != 0 {
            return None;
        }
        let zi = self.z.invert();
        let zi2 = zi.square();
        Some((self.x.mul(&zi2), self.y.mul(&zi2).mul(&zi)))
    }
}

impl<C: Curve<L>, const L: usize> Jac<C, L> {
    fn identity() -> Self {
        Jac {
            x: Fp::<C, L>::ONE,
            y: Fp::<C, L>::ONE,
            z: Fp::<C, L>::ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        self.z.is_zero() != 0
    }

    fn from_affine((x, y): &Affine<C, L>) -> Self {
        Jac {
            x: *x,
            y: *y,
            z: Fp::<C, L>::ONE,
        }
    }

    fn neg(&self) -> Self {
        Jac {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Doubling for a = -3 (dbl-2001-b with `Z₃ = 2·Y·Z`: 4M + 4S), constant time; the
    /// identity (`Z = 0`) stays the identity.
    fn double(&self) -> Self {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);
        let alpha = self.x.sub(&delta).mul(&self.x.add(&delta)).mul3();
        let beta4 = beta.mul_pow2(2);
        let x3 = alpha.square().sub(&beta4.double());
        let z3 = self.y.mul(&self.z).double();
        let y3 = alpha.mul(&beta4.sub(&x3)).sub(&gamma.square().mul_pow2(3));
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + (x2, y2)` (madd-2007-bl: 7M + 4S), with the special cases handled by branches.
    fn add_affine(&self, q: &Affine<C, L>) -> Self {
        if self.is_identity() {
            return Self::from_affine(q);
        }
        let (x2, y2) = q;
        let z1z1 = self.z.square();
        let u2 = x2.mul(&z1z1);
        let s2 = y2.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let r = s2.sub(&self.y).double();
        if h.is_zero() != 0 {
            return if r.is_zero() != 0 {
                self.double()
            } else {
                Self::identity()
            };
        }
        let hh = h.square();
        let i = hh.double().double();
        let j = h.mul(&i);
        let v = self.x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&j).double());
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `self + q` (add-2007-bl: 11M + 5S), with the special cases handled by branches.
    fn add(&self, q: &Self) -> Self {
        if self.is_identity() {
            return *q;
        }
        if q.is_identity() {
            return *self;
        }
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = q.x.mul(&z1z1);
        let s1 = self.y.mul(&q.z).mul(&z2z2);
        let s2 = q.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let r = s2.sub(&s1).double();
        if h.is_zero() != 0 {
            return if r.is_zero() != 0 {
                self.double()
            } else {
                Self::identity()
            };
        }
        let i = h.double().square();
        let j = h.mul(&i);
        let v = u1.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).double());
        let z3 = self.z.add(&q.z).square().sub(&z1z1).sub(&z2z2).mul(&h);
        Jac {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `[a]G + [b]q`: width-7 wNAF of `a` over the precomputed odd multiples of `G`, width-5
    /// wNAF of `b` over `q, 3q, …, 15q`, one shared chain of doublings.
    fn mul_add_vartime(q: &Point<C, L>, a: &Scalar<C, L>, b: &Scalar<C, L>) -> Self {
        let wa = wnaf(&a.to_limbs(), 7);
        let wb = wnaf(&b.to_limbs(), 5);
        let gt = &C::tables().wnaf;
        let mut qt = [Self::identity(); 8];
        // Projective to Jacobian without an inversion (keys from `public_key()` have `Z ≠ 1`).
        if q.is_identity() == 0 {
            qt[0] = Self::from_point(q);
            let q2 = qt[0].double();
            for i in 1..8 {
                qt[i] = qt[i - 1].add(&q2);
            }
        }
        let mut r = Self::identity();
        for i in (0..wa.len().max(wb.len())).rev() {
            r = r.double();
            match wa.get(i).copied().unwrap_or(0) {
                0 => {}
                d if d > 0 => r = r.add_affine(&raw_affine::<C, L>(&gt[(d as usize) >> 1])),
                d => {
                    let (x, y) = raw_affine::<C, L>(&gt[((-d) as usize) >> 1]);
                    r = r.add_affine(&(x, y.neg()));
                }
            }
            match wb.get(i).copied().unwrap_or(0) {
                0 => {}
                d if d > 0 => r = r.add(&qt[(d as usize) >> 1]),
                d => r = r.add(&qt[((-d) as usize) >> 1].neg()),
            }
        }
        r
    }
}

/// The width-`w` NAF of `k` (little-endian limbs): digits zero or odd in
/// `(-2^(w-1), 2^(w-1))`, least significant first, trailing zeros trimmed. Variable time.
pub(crate) fn wnaf<const L: usize>(k: &[u64; L], w: u32) -> Vec<i8> {
    // One extra limb: subtracting a negative digit adds to k.
    let mut k: Vec<u64> = k.iter().copied().chain([0]).collect();
    let mut out = Vec::with_capacity(64 * L + 1);
    let full = 1u64 << w;
    let half = 1u64 << (w - 1);
    while k.iter().any(|&x| x != 0) {
        let mut d = 0i64;
        if k[0] & 1 == 1 {
            let m = k[0] & (full - 1);
            if m >= half {
                d = m as i64 - full as i64;
                // k += |d|
                let mut c = (-d) as u64;
                for x in &mut k {
                    let (v, o) = x.overflowing_add(c);
                    *x = v;
                    c = u64::from(o);
                }
            } else {
                d = m as i64;
                k[0] -= m; // the low w bits are m: no borrow
            }
        }
        out.push(d as i8);
        // k >>= 1
        for i in 0..k.len() {
            let hi = k.get(i + 1).copied().unwrap_or(0);
            k[i] = (k[i] >> 1) | (hi << 63);
        }
    }
    out
}

/// `bits2int(h) mod n` (RFC 6979 §2.3.2 / SEC1 §4.1.3 step 5): the leftmost `8L·8` bits of the
/// digest, reduced.
pub(crate) fn digest_scalar<C: Curve<L>, const L: usize>(digest: &[u8]) -> Scalar<C, L> {
    let n = 8 * L;
    let mut buf = vec![0u8; n];
    if digest.len() >= n {
        buf.copy_from_slice(&digest[..n]);
    } else {
        buf[n - digest.len()..].copy_from_slice(digest);
    }
    // Below 2^(64L) < 2n, so one reduction suffices; from_be_bytes_reduce handles any value.
    Scalar::<C, L>::from_be_bytes_reduce(&buf).unwrap_or(Scalar::<C, L>::ZERO)
}

/// The RFC 6979 nonce for private key `x` and message digest `h`, with HMAC over `H`.
pub(crate) fn rfc6979_nonce<C: Curve<L>, H: Hash, const L: usize>(
    x: &Scalar<C, L>,
    h: &[u8],
) -> Scalar<C, L> {
    let n = 8 * L;
    let mut xb = vec![0u8; n];
    x.write_be(&mut xb);
    let mut hb = vec![0u8; n];
    digest_scalar::<C, L>(h).write_be(&mut hb);
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
        let mut t = Vec::with_capacity(n + hl);
        while t.len() < n {
            v = Hmac::<H>::mac(&k, &v).as_ref().to_vec();
            t.extend_from_slice(&v);
        }
        t.truncate(n);
        if let Some(s) = Scalar::<C, L>::from_be_bytes(&t) {
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

/// An ECDSA signature `(r, s)`; both in `[1, n)` once constructed through the parsers.
pub(crate) struct Sig<C: Curve<L>, const L: usize> {
    pub(crate) r: Scalar<C, L>,
    pub(crate) s: Scalar<C, L>,
}

impl<C: Curve<L>, const L: usize> Sig<C, L> {
    /// The same signature on a twin curve (same scalar field).
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    #[inline]
    pub(crate) fn cast<D: Curve<L, Fq = C::Fq>>(&self) -> Sig<D, L> {
        Sig {
            r: self.r,
            s: self.s,
        }
    }
}

/// `d·G` as a projective point, constant time.
pub(crate) fn base_mul_impl<C: Curve<L>, const L: usize>(d: &Scalar<C, L>) -> Point<C, L> {
    Jac::<C, L>::mul_base_ct(d).to_projective()
}

/// The big-endian x-coordinate of `d·q` into `out`, constant time; `false` for the identity.
pub(crate) fn ecdh_x_impl<C: Curve<L>, const L: usize>(
    d: &Scalar<C, L>,
    q: &Point<C, L>,
    out: &mut [u8],
) -> bool {
    match Jac::<C, L>::mul_ct(q, d).to_affine_x() {
        Some(x) => {
            x.write_be(out);
            true
        }
        None => false,
    }
}

/// Signs digest `h` with private key `d` (RFC 6979 nonce over `H`).
pub(crate) fn sign_impl<C: Curve<L>, H: Hash, const L: usize>(
    d: &Scalar<C, L>,
    h: &[u8],
) -> Sig<C, L> {
    let e = digest_scalar::<C, L>(h);
    loop {
        let k = rfc6979_nonce::<C, H, L>(d, h);
        let Some(x) = Jac::<C, L>::mul_base_ct(&k).to_affine_x() else {
            continue; // unreachable: 0 < k < n
        };
        // r = x mod n (x < p < 2n).
        let r = Scalar::<C, L>::from_limbs_reduce(&x.to_limbs());
        let s = k.invert().mul(&e.add(&r.mul(d)));
        if r.is_zero() == 0 && s.is_zero() == 0 {
            return Sig { r, s };
        }
    }
}

/// Verifies `(r, s)` (already range-checked) on digest `h` under public key `q`.
pub(crate) fn verify_impl<C: Curve<L>, const L: usize>(
    q: &Point<C, L>,
    h: &[u8],
    sig: &Sig<C, L>,
) -> Result<(), Error> {
    let e = digest_scalar::<C, L>(h);
    let w = sig.s.invert_vartime();
    let u1 = e.mul(&w);
    let u2 = sig.r.mul(&w);
    let rj = Jac::<C, L>::mul_add_vartime(q, &u1, &u2);
    if rj.is_identity() {
        return Err(Error::Verification);
    }
    // x(R) mod n == r, where x(R) = X/Z² < p: compare X with r·Z², and with (r + n)·Z² when
    // r + n < p (x(R) ≥ n). No inversion; all values public.
    let z2 = rj.z.square();
    let r = sig.r.to_limbs();
    let rx = Fp::<C, L>::from_limbs_canonical(&r).ok_or(Error::Verification)?;
    if rx.mul(&z2).ct_eq(&rj.x) != 0 {
        return Ok(());
    }
    let mut rn = [0u64; L];
    let carry = ct::add_limbs(&mut rn, &r, &<C::Fq as Modulus<L>>::P);
    if carry == 0 {
        if let Some(rnx) = Fp::<C, L>::from_limbs_canonical(&rn) {
            if rnx.mul(&z2).ct_eq(&rj.x) != 0 {
                return Ok(());
            }
        }
    }
    Err(Error::Verification)
}

/// Parses a fixed-width `r || s` signature, requiring `1 <= r, s < n`.
pub(crate) fn sig_from_fixed<C: Curve<L>, const L: usize>(b: &[u8]) -> Result<Sig<C, L>, Error> {
    let n = 8 * L;
    if b.len() != 2 * n {
        return Err(Error::Encoding);
    }
    let r = Scalar::<C, L>::from_be_bytes(&b[..n]).ok_or(Error::Verification)?;
    let s = Scalar::<C, L>::from_be_bytes(&b[n..]).ok_or(Error::Verification)?;
    if r.is_zero() != 0 || s.is_zero() != 0 {
        return Err(Error::Verification);
    }
    Ok(Sig { r, s })
}

/// Parses a DER `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`), strictly.
pub(crate) fn sig_from_der<C: Curve<L>, const L: usize>(b: &[u8]) -> Result<Sig<C, L>, Error> {
    let n = 8 * L;
    let mut r = crate::der::Reader::new(b);
    let mut seq = r.sequence()?;
    let ri = seq.read_uint()?;
    let si = seq.read_uint()?;
    seq.finish()?;
    r.finish()?;
    if ri.len() > n || si.len() > n {
        return Err(Error::Verification);
    }
    let mut fixed = vec![0u8; 2 * n];
    fixed[n - ri.len()..n].copy_from_slice(ri);
    fixed[2 * n - si.len()..].copy_from_slice(si);
    sig_from_fixed(&fixed)
}

/// The DER encoding of a signature.
pub(crate) fn sig_to_der<C: Curve<L>, const L: usize>(sig: &Sig<C, L>) -> Vec<u8> {
    let n = 8 * L;
    let mut rb = vec![0u8; n];
    let mut sb = vec![0u8; n];
    sig.r.write_be(&mut rb);
    sig.s.write_be(&mut sb);
    let mut w = crate::der::Writer::new();
    w.sequence(|w| {
        w.uint(&rb);
        w.uint(&sb);
    });
    w.into_vec()
}
