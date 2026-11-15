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
//! x86_64 with BMI2 + ADX: field routines, whole Jacobian doublings and additions, the safegcd
//! divsteps) does not need the barrier: the compiler cannot rewrite it, and its corrections are
//! `cmov`, `sbb` or `sar`/`neg` masks. The AVX2 table scans of `ec::hw` select with `vpcmpeqq`
//! masks. The Rust code around them (the masked selects of the scalar multiplications, the
//! ladder's swaps, digit recoding, the portable safegcd) still uses the masks here.
//!
//! RSA works the same way: on x86_64 the Montgomery multiplication and squaring of
//! `bignum::hw` (BMI2 + ADX) and the almost Montgomery multiplication of `bignum::ifma`
//! (AVX-512 IFMA) are `asm!` blocks whose only branches are row and digit counters; the final
//! subtraction is a `cmovnz` on an `sbb` mask, the IFMA carry normalization uses opmask merges
//! from a generate / propagate word. The exponentiation's table scans use `vpcmpeqq` masks (AVX2)
//! or the masks here; the portable Montgomery code, `Mont::new`'s doublings, the conversion into
//! the IFMA radix (`shl_mod`) and the final reductions use the masks here.
//!
//! How this is checked: `objdump -d` of a release build (`--example pk_bench`), listing every
//! conditional branch in the secret-scalar paths: `Jac::{double, add_core, madd_ct}` and the
//! inlined `mul_ct`/`mul_base_ct`/`lookup`/`booth`/`booth5` inside `ecdh_x_impl`/`base_mul_impl`
//! (portable `P256`/`P384` and the `P256X` twin with its whole-point assembly), `ec::hw::mul_base`
//! (the wide comb), `ec::hw::lookup_jac_avx2` / `lookup_affine_avx2`, the field multiplication,
//! squaring and inversion (`Fe::invert`, `P256P`/`P256N::mont_inv`, `safegcd::inv_with` and both
//! `divsteps_59`), `Point::mul_base` / `add_niels` / `Completed::to_point` (edwards25519) and
//! `x25519` (both ladders inlined). On x86_64 (with the assembly) and aarch64 (portable) the only
//! conditional branches there are loop counters, public bounds and indices (window positions,
//! limb and bit offsets of a digit, table rows), the public exponent bits of the remaining
//! Fermat chains (P-384, Ed25519), the CPU-feature checks, `OnceLock` initialization, the length
//! of the output encoding, and the final "result is the identity" test, which a valid secret
//! scalar never reaches. Last checked on Zen 4 for the point-formula pass (`ecp_nistz256`
//! additions, the doubling from `2Y` with a modular halving): no conditional branch at all in the
//! point routines, the table scans, `divsteps_59` (assembly: one, the loop counter) and
//! `Fe::invert`; `ecdh_x_impl` for the `P256X` twin has 17, all of the kinds above (the
//! table-building loop and its public index parity, the window loop and the public bit offset
//! and limb bound of each digit, the AVX2 feature check and the scalar-scan fallback's loop, the
//! final identity test and the length of the output encoding), the same set as before the pass.
//!
//! RSA, checked on Zen 4 for the RSA pass (`--example pk_bench`, release): the conditional branches
//! of `Mont::mul_into` (61) and `Mont::sqr_into` (72; both with the BMI2 + ADX blocks for every
//! size inlined, and the portable fixed-size code), `ifma::amm` (17, the three IFMA blocks),
//! `ifma::pow` (77), `ifma::shl_mod` (37), `Mont::pow` (48), `hw::lookup` (22) and
//! `hw::lookup_avx2::<V>` (3 each), `Mont::new` (23), `crt_combine` (19) and `private_op` (120)
//! are all of these kinds: the CPU-feature checks, the dispatch on the public limb or digit
//! count, slice-bound and allocation checks (panic and out-of-memory paths), deallocation of
//! empty vectors, loop counters (the assembly's `dec ecx; jnz` over rows and digits, Rust loops
//! over limbs, windows and table entries), the public bit offset of a window digit and the parity
//! of a table index, vectorization alias checks, the `Mutex` and the cached-blinding `Option`,
//! the `Result` of a fresh blinding, `Mont::new`'s checks of the public modulus shape (odd, top
//! limb nonzero) and the final fault check (`sᵉ = m`). None reads a limb of a secret value, an
//! exponent bit or a table index. The blinding's rejection of a non-invertible `r` (probability
//! about 2⁻¹⁰²⁴) is the one data-dependent branch, on a random value.

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
