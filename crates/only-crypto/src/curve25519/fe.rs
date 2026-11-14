//! Arithmetic modulo `p = 2²⁵⁵ - 19` in radix 2⁵¹ (five 64-bit limbs, products in `u128`),
//! after curve25519-donna-64 / ref10. Every operation takes constant time; limbs stay below
//! 2⁵² between operations (loosely reduced), [`Fe::to_bytes`] reduces fully.

use crate::ct;

const MASK51: u64 = (1 << 51) - 1;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    pub(crate) const fn from_u64(x: u64) -> Fe {
        Fe([x & MASK51, x >> 51, 0, 0, 0])
    }

    /// From 32 little-endian bytes; the top bit is ignored (RFC 7748). Values in `[p, 2²⁵⁵)`
    /// are accepted and reduced.
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(w)
        };
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51,
        ])
    }

    /// The canonical (fully reduced) 32-byte little-endian encoding.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut t = self.carry().carry().0;
        // t < 2^255 + small; compute q = 1 if t >= p, via t + 19 overflowing 2^255.
        let mut q = (t[0] + 19) >> 51;
        q = (t[1] + q) >> 51;
        q = (t[2] + q) >> 51;
        q = (t[3] + q) >> 51;
        q = (t[4] + q) >> 51;
        t[0] += 19 * q;
        t[1] += t[0] >> 51;
        t[0] &= MASK51;
        t[2] += t[1] >> 51;
        t[1] &= MASK51;
        t[3] += t[2] >> 51;
        t[2] &= MASK51;
        t[4] += t[3] >> 51;
        t[3] &= MASK51;
        t[4] &= MASK51;
        let mut out = [0u8; 32];
        let words = [
            t[0] | (t[1] << 51),
            (t[1] >> 13) | (t[2] << 38),
            (t[2] >> 26) | (t[3] << 25),
            (t[3] >> 39) | (t[4] << 12),
        ];
        for (i, w) in words.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    #[inline]
    fn carry(self) -> Fe {
        let mut t = self.0;
        let c = t[0] >> 51;
        t[0] &= MASK51;
        t[1] += c;
        let c = t[1] >> 51;
        t[1] &= MASK51;
        t[2] += c;
        let c = t[2] >> 51;
        t[2] &= MASK51;
        t[3] += c;
        let c = t[3] >> 51;
        t[3] &= MASK51;
        t[4] += c;
        let c = t[4] >> 51;
        t[4] &= MASK51;
        t[0] += c * 19;
        Fe(t)
    }

    #[inline]
    pub(crate) fn add(&self, b: &Fe) -> Fe {
        let a = &self.0;
        Fe([
            a[0] + b.0[0],
            a[1] + b.0[1],
            a[2] + b.0[2],
            a[3] + b.0[3],
            a[4] + b.0[4],
        ])
        .carry()
    }

    #[inline]
    pub(crate) fn sub(&self, b: &Fe) -> Fe {
        // Add 4p to keep limbs positive (inputs below 2^52 each).
        let a = &self.0;
        Fe([
            (a[0] + 0x1f_ffff_ffff_ffb4) - b.0[0],
            (a[1] + 0x1f_ffff_ffff_fffc) - b.0[1],
            (a[2] + 0x1f_ffff_ffff_fffc) - b.0[2],
            (a[3] + 0x1f_ffff_ffff_fffc) - b.0[3],
            (a[4] + 0x1f_ffff_ffff_fffc) - b.0[4],
        ])
        .carry()
    }

    #[inline]
    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    #[inline]
    pub(crate) fn mul(&self, b: &Fe) -> Fe {
        let a = &self.0;
        let b = &b.0;
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let b1 = b[1] * 19;
        let b2 = b[2] * 19;
        let b3 = b[3] * 19;
        let b4 = b[4] * 19;
        let c0 = m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1);
        let c1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2);
        let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3);
        let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4);
        let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        Self::reduce_wide([c0, c1, c2, c3, c4])
    }

    #[inline]
    fn reduce_wide(c: [u128; 5]) -> Fe {
        let mask = u128::from(MASK51);
        let mut r = [0u64; 5];
        let c1 = c[1] + (c[0] >> 51);
        r[0] = (c[0] & mask) as u64;
        let c2 = c[2] + (c1 >> 51);
        r[1] = (c1 & mask) as u64;
        let c3 = c[3] + (c2 >> 51);
        r[2] = (c2 & mask) as u64;
        let c4 = c[4] + (c3 >> 51);
        r[3] = (c3 & mask) as u64;
        r[4] = (c4 & mask) as u64;
        let r0 = u128::from(r[0]) + (c4 >> 51) * 19;
        r[0] = (r0 & mask) as u64;
        r[1] += (r0 >> 51) as u64;
        Fe(r)
    }

    #[inline]
    pub(crate) fn square(&self) -> Fe {
        self.mul(self)
    }

    fn square_n(&self, n: u32) -> Fe {
        let mut r = *self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// Multiplication by a small constant (below 2¹³).
    #[inline]
    pub(crate) fn mul_small(&self, k: u64) -> Fe {
        let a = &self.0;
        let m = |x: u64| u128::from(x) * u128::from(k);
        Self::reduce_wide([m(a[0]), m(a[1]), m(a[2]), m(a[3]), m(a[4])])
    }

    /// `(self^(2²⁵⁰ - 1), self^11)`, the shared prefix of the inversion and square-root chains.
    fn pow250(&self) -> (Fe, Fe) {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square().mul(&z9); // 2^5 - 1
        let z_10_0 = z_5_0.square_n(5).mul(&z_5_0);
        let z_20_0 = z_10_0.square_n(10).mul(&z_10_0);
        let z_40_0 = z_20_0.square_n(20).mul(&z_20_0);
        let z_50_0 = z_40_0.square_n(10).mul(&z_10_0);
        let z_100_0 = z_50_0.square_n(50).mul(&z_50_0);
        let z_200_0 = z_100_0.square_n(100).mul(&z_100_0);
        let z_250_0 = z_200_0.square_n(50).mul(&z_50_0);
        (z_250_0, z11)
    }

    /// `self⁻¹ = self^(p-2)` (0 maps to 0).
    pub(crate) fn invert(&self) -> Fe {
        let (z_250_0, z11) = self.pow250();
        z_250_0.square_n(5).mul(&z11)
    }

    /// `self^((p-5)/8) = self^(2²⁵² - 3)`.
    pub(crate) fn pow_p58(&self) -> Fe {
        let (z_250_0, _) = self.pow250();
        z_250_0.square_n(2).mul(self)
    }

    /// `u64::MAX` if zero (after full reduction).
    pub(crate) fn is_zero(&self) -> u64 {
        let b = self.to_bytes();
        let mut acc = 0u64;
        for x in b {
            acc |= u64::from(x);
        }
        ct::is_zero(acc)
    }

    /// `u64::MAX` if equal.
    pub(crate) fn ct_eq(&self, b: &Fe) -> u64 {
        self.sub(b).is_zero()
    }

    /// The low bit of the canonical encoding ("negative" in RFC 8032).
    pub(crate) fn is_negative(&self) -> u64 {
        u64::from(self.to_bytes()[0] & 1)
    }

    pub(crate) fn select(m: u64, a: &Fe, b: &Fe) -> Fe {
        let mut r = b.0;
        ct::assign(m, &mut r, &a.0);
        Fe(r)
    }

    pub(crate) fn cswap(m: u64, a: &mut Fe, b: &mut Fe) {
        ct::swap(m, &mut a.0, &mut b.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_inverse() {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i * 7 + 3) as u8;
        }
        b[31] &= 0x7f;
        let x = Fe::from_bytes(&b);
        assert_eq!(x.to_bytes(), b);
        assert_eq!(x.mul(&x.invert()).to_bytes(), Fe::ONE.to_bytes());
        // p itself encodes to zero; p + 1 to one.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0; 32]);
        p[0] = 0xee;
        assert_eq!(Fe::from_bytes(&p).to_bytes(), Fe::ONE.to_bytes());
        assert_eq!(
            Fe::ONE.sub(&Fe::from_u64(2)).add(&Fe::ONE).is_zero(),
            u64::MAX
        );
        assert_eq!(
            x.mul_small(121_666).to_bytes(),
            x.mul(&Fe::from_u64(121_666)).to_bytes()
        );
    }
}
