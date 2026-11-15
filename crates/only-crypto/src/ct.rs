//! Constant-time building blocks shared by the public-key code: masks, selection and
//! comparison on machine words without secret-dependent branches.
//!
//! A *mask* is `0` or `u64::MAX`. Every mask goes through [`std::hint::black_box`] so that the
//! optimizer cannot see that it has only two values and turn the selection that uses it back
//! into a branch. This matters in practice: without the barrier, LLVM compiles the masked
//! corrections of the modular additions and subtractions (`d + (P & m)`, selects between two
//! limb arrays) into conditional jumps for some moduli (seen on x86_64 for P-384 and, depending
//! on the formulation, P-256), although it costs a round trip through memory per mask.
//!
//! The inline assembly of `ec::hw` and `curve25519::hw` (P-256 and Curve25519 arithmetic on
//! x86_64 with BMI2 + ADX) and of `ec::hw_aarch64` and `curve25519::hw_aarch64` (the same on
//! aarch64) does not need the barrier: the compiler cannot rewrite it, and its corrections are
//! `cmov` or `sbb` masks (x86_64), `CSEL` on the carry flag or an `SBC` mask (aarch64). None of
//! the templates contains a branch instruction. The Rust code around it (Jacobian formulas, table
//! scans, the ladder's swaps, digit recoding) still uses the masks here.
//!
//! How this is checked: `objdump -d` of a release build (`--example pk_bench`), listing every
//! conditional branch in the secret-scalar paths: `Jac::{double, add_core, madd_ct}` and the
//! inlined `mul_ct`/`mul_base_ct`/`lookup`/`booth5` inside `ecdh_x_impl`/`base_mul_impl`
//! (portable `P256`/`P384` and the `P256X` twin), the field multiplication, squaring and
//! inversion chains (`p256_inv`, `p256n_inv`, `Fe::invert`), `Point::mul_base` / `add_niels` /
//! `Completed::to_point` (edwards25519) and `x25519` (both ladders inlined). On x86_64 (with
//! the assembly) and aarch64 (with the aarch64 assembly: the `P256A` twin's functions,
//! `p256_inv::<P256Pa>`, `curve25519::hw_aarch64::ladder`; and portable) the only conditional
//! branches there are loop counters,
//! public bounds and indices (window positions, table rows), the public exponent bits of the
//! inversion chains, the CPU-feature checks, `OnceLock` initialization, and the final
//! "result is the identity" test, which a valid secret scalar never reaches.
//!
//! The aarch64 assembly paths, as listed on macOS (Apple silicon, `objdump -d` of the release
//! `pk_bench`): `curve25519::hw_aarch64::ladder` has 4 conditional branches (the 255-step ladder
//! counter, three `sqn` loop counters of the inversion chain), `x25519` 5 (the CPU-feature and
//! portable-switch checks, the portable ladder's counter), `p256_inv::<P256Pa>` 1 (a squaring
//! loop counter), `Jac::<P256A>::{double, madd_ct, add_core}` none, `Jac::<P256A>::mul_base_ct`
//! 4 (`OnceLock` state, the digit loop, a table bound), `ecdh_x_impl::<P256A>` 14 (building the
//! 16-entry table, the 52 windows and their public bit positions, the full table scan, the
//! identity test, the byte loop of the public-length output).

use std::hint::black_box;

/// `u64::MAX` if `bit` is 1, else 0 (`bit` must be 0 or 1).
#[inline]
pub(crate) fn mask(bit: u64) -> u64 {
    black_box(bit).wrapping_neg()
}

/// `u64::MAX` if `x == 0`, else 0.
#[inline]
pub(crate) fn is_zero(x: u64) -> u64 {
    // (x | -x) has its top bit set exactly when x != 0.
    mask(1 ^ ((x | x.wrapping_neg()) >> 63))
}

/// `u64::MAX` if `a == b`, else 0.
#[inline]
pub(crate) fn eq(a: u64, b: u64) -> u64 {
    is_zero(a ^ b)
}

/// `a` where `m` is all ones, `b` where it is zero.
#[inline]
pub(crate) fn select(m: u64, a: u64, b: u64) -> u64 {
    b ^ (m & (a ^ b))
}

/// `u64::MAX` if every limb of `a` is zero.
#[inline]
pub(crate) fn is_zero_limbs(a: &[u64]) -> u64 {
    let mut acc = 0;
    for &x in a {
        acc |= x;
    }
    is_zero(acc)
}

/// Overwrites `dst` with `src` where `m` is all ones.
#[inline]
pub(crate) fn assign(m: u64, dst: &mut [u64], src: &[u64]) {
    for (d, &s) in dst.iter_mut().zip(src) {
        *d = select(m, s, *d);
    }
}

/// Swaps `a` and `b` where `m` is all ones.
#[inline]
pub(crate) fn swap(m: u64, a: &mut [u64], b: &mut [u64]) {
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = m & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// `a - b` over little-endian limbs into `out`, returning the borrow (0 or 1).
#[inline]
pub(crate) fn sub_limbs(out: &mut [u64], a: &[u64], b: &[u64]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..out.len() {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = u64::from(b1 | b2);
    }
    borrow
}

/// `a + b` over little-endian limbs into `out`, returning the carry (0 or 1).
#[inline]
pub(crate) fn add_limbs(out: &mut [u64], a: &[u64], b: &[u64]) -> u64 {
    let mut carry = 0u64;
    for i in 0..out.len() {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        out[i] = s;
        carry = u64::from(c1 | c2);
    }
    carry
}

/// `u64::MAX` if `a < b` (little-endian limbs of equal length), in constant time.
#[inline]
pub(crate) fn lt_limbs(a: &[u64], b: &[u64]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (_, b2) = d.overflowing_sub(borrow);
        borrow = u64::from(b1 | b2);
    }
    mask(borrow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(is_zero(0), u64::MAX);
        assert_eq!(is_zero(1), 0);
        assert_eq!(is_zero(u64::MAX), 0);
        assert_eq!(is_zero(1 << 63), 0);
        assert_eq!(eq(5, 5), u64::MAX);
        assert_eq!(eq(5, 6), 0);
        assert_eq!(select(u64::MAX, 1, 2), 1);
        assert_eq!(select(0, 1, 2), 2);
        assert_eq!(lt_limbs(&[1, 0], &[2, 0]), u64::MAX);
        assert_eq!(lt_limbs(&[3, 1], &[2, 1]), 0);
        assert_eq!(lt_limbs(&[2, 1], &[2, 1]), 0);
        assert_eq!(lt_limbs(&[u64::MAX, 0], &[0, 1]), u64::MAX);
        let (mut a, mut b) = ([1, 2], [3, 4]);
        swap(u64::MAX, &mut a, &mut b);
        assert_eq!((a, b), ([3, 4], [1, 2]));
        swap(0, &mut a, &mut b);
        assert_eq!((a, b), ([3, 4], [1, 2]));
    }
}
