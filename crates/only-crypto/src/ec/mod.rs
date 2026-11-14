//! Short Weierstrass curves `y² = x³ - 3x + b` over prime fields (P-256, P-384): points in
//! projective coordinates with the complete addition formulas of Renes, Costello and Batina
//! (2016, algorithms 4 and 6 for `a = -3`), so there are no exceptional cases and no
//! data-dependent branches; ECDH and ECDSA on top.
//!
//! Secret-scalar multiplication uses fixed 4-bit windows with a table lookup that reads every
//! entry (variable base) or a precomputed comb table of `j·16ⁱ·G` (fixed base), always the same
//! sequence of field operations. Verification (public inputs) uses the same code without the
//! secret-handling discipline where that is faster.

pub(crate) mod api;
pub(crate) mod curves;

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
    /// The comb table of the base point, built once.
    fn base_table() -> &'static [[Point<Self, L>; 16]];
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

    fn select(m: u64, a: &Self, b: &Self) -> Self {
        Point {
            x: Fe::select(m, &a.x, &b.x),
            y: Fe::select(m, &a.y, &b.y),
            z: Fe::select(m, &a.z, &b.z),
            _c: PhantomData,
        }
    }

    /// `table[idx]`, reading every entry.
    fn lookup(table: &[Self; 16], idx: u64) -> Self {
        let mut r = Self::identity();
        for (j, p) in table.iter().enumerate() {
            r = Self::select(ct::eq(j as u64, idx), p, &r);
        }
        r
    }

    /// The 4-bit digit `i` (from the least significant) of little-endian limbs.
    fn nibble(k: &[u64; L], i: usize) -> u64 {
        (k[i / 16] >> (4 * (i % 16))) & 15
    }

    /// `[k]self` in constant time (fixed 4-bit windows, full-table lookups).
    pub(crate) fn mul(&self, k: &Scalar<C, L>) -> Self {
        let k = k.to_limbs();
        let mut table = [Self::identity(); 16];
        for j in 1..16 {
            table[j] = table[j - 1].add(self);
        }
        let mut r = Self::identity();
        for i in (0..16 * L).rev() {
            r = r.double().double().double().double();
            r = r.add(&Self::lookup(&table, Self::nibble(&k, i)));
        }
        r
    }

    /// `[k]G` in constant time from the comb table: one addition per 4-bit digit.
    pub(crate) fn mul_base(k: &Scalar<C, L>) -> Self {
        let k = k.to_limbs();
        let mut r = Self::identity();
        for (i, row) in C::base_table().iter().enumerate() {
            r = r.add(&Self::lookup(row, Self::nibble(&k, i)));
        }
        r
    }

    /// `[a]G + [b]self` in variable time (public scalars: verification).
    pub(crate) fn mul_add_base_vartime(&self, a: &Scalar<C, L>, b: &Scalar<C, L>) -> Self {
        let (a, b) = (a.to_limbs(), b.to_limbs());
        let mut table = [Self::identity(); 16];
        for j in 1..16 {
            table[j] = table[j - 1].add(self);
        }
        let mut r = Self::identity();
        for i in (0..16 * L).rev() {
            r = r.double().double().double().double();
            let n = Self::nibble(&b, i) as usize;
            if n != 0 {
                r = r.add(&table[n]);
            }
        }
        for (i, row) in C::base_table().iter().enumerate() {
            let n = Self::nibble(&a, i) as usize;
            if n != 0 {
                r = r.add(&row[n]);
            }
        }
        r
    }

    /// Builds the comb table `table[i][j] = j·16ⁱ·G` (for [`Curve::base_table`]).
    pub(crate) fn build_base_table() -> Vec<[Self; 16]> {
        let mut out = Vec::with_capacity(16 * L);
        let mut p = Self::generator();
        for _ in 0..16 * L {
            let mut row = [Self::identity(); 16];
            for j in 1..16 {
                row[j] = row[j - 1].add(&p);
            }
            p = row[15].add(&p);
            out.push(row);
        }
        out
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

    /// The uncompressed SEC1 encoding (`04 || x || y`); `None` for the identity.
    pub(crate) fn to_uncompressed(self) -> Option<Vec<u8>> {
        let (x, y) = self.to_affine()?;
        let n = Self::LEN;
        let mut v = vec![0u8; 1 + 2 * n];
        v[0] = 4;
        x.write_be(&mut v[1..=n]);
        y.write_be(&mut v[1 + n..]);
        Some(v)
    }
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

/// Signs digest `h` with private key `d` (RFC 6979 nonce over `H`).
pub(crate) fn sign<C: Curve<L>, H: Hash, const L: usize>(d: &Scalar<C, L>, h: &[u8]) -> Sig<C, L> {
    let e = digest_scalar::<C, L>(h);
    loop {
        let k = rfc6979_nonce::<C, H, L>(d, h);
        let Some((x, _)) = Point::<C, L>::mul_base(&k).to_affine() else {
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
pub(crate) fn verify<C: Curve<L>, const L: usize>(
    q: &Point<C, L>,
    h: &[u8],
    sig: &Sig<C, L>,
) -> Result<(), Error> {
    let e = digest_scalar::<C, L>(h);
    let w = sig.s.invert();
    let u1 = e.mul(&w);
    let u2 = sig.r.mul(&w);
    let (x, _) = q
        .mul_add_base_vartime(&u1, &u2)
        .to_affine()
        .ok_or(Error::Verification)?;
    let xr = Scalar::<C, L>::from_limbs_reduce(&x.to_limbs());
    if xr.ct_eq(&sig.r) != 0 {
        Ok(())
    } else {
        Err(Error::Verification)
    }
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
