//! ChaCha20 and Poly1305 on x86_64 vector instructions, chosen at run time:
//!
//! - ChaCha20 eight blocks at a time with AVX2 (this file): word `j` of the eight blocks shares
//!   one 256-bit register; after the rounds an 8×8 transpose turns the registers back into
//!   blocks.
//! - ChaCha20 sixteen (zmm), eight (ymm) or four (one row per zmm register) blocks at a time with
//!   AVX-512 (`avx512`, `asm!`).
//! - Poly1305 eight blocks at a time with AVX-512 IFMA (`ifma`, `asm!`).
//!
//! Additions, XORs, rotations and multiplications only: constant time like the portable code.
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the
//! `#[target_feature]` function and its intrinsics and for the `asm!` kernels, each called after
//! its feature was detected, and for recording what the AVX-512 kernel wrote out of place into a
//! possibly uninitialised `Fill` (`Fill::assume_written`).
#![allow(unsafe_code)]
// The intrinsics are `unsafe fn` at the MSRV (1.85) and safe inside `#[target_feature]` functions
// on newer compilers.
#![allow(unused_unsafe)]

use crate::cpu::{self, Feature};
use crate::fill::Fill;

#[cfg(target_arch = "x86_64")]
mod avx512;
#[cfg(target_arch = "x86_64")]
use avx512::Width;
#[cfg(target_arch = "x86_64")]
mod ifma;

/// Powers of `r` for the IFMA kernel: for each of `r0, r1, r2, 20·r1, 20·r2` (in that order),
/// eight lanes, lane `i` from `r⁸⁻ⁱ`.
pub(super) type Powers = [u64; 40];

/// Bytes the IFMA kernel absorbs per iteration (eight blocks).
pub(super) const POLY_CHUNK: usize = 128;

/// Whether to use the AVX-512 ChaCha20 kernels (detected and not switched off).
#[inline]
pub(super) fn wide_enabled() -> bool {
    cpu::has(Feature::Avx512)
}

/// Whether to use the AVX-512 IFMA Poly1305 kernel (detected and not switched off).
#[inline]
pub(super) fn ifma_enabled() -> bool {
    cpu::has(Feature::Ifma)
}

/// The relative cost of [`xor_wide`] over `len` bytes (a multiple of 64 or the end of a
/// message), from the kernel times on Zen 4 (ChaCha20 alone, call overhead excluded: about 63 ns
/// for a four-block row group, 83 for an eight-block ymm group, 140 for a sixteen-block zmm
/// group), for choosing how many blocks the head of an AEAD message takes.
pub(super) const fn wide_cost(len: usize) -> usize {
    let rest = len % 1024;
    let last = match rest {
        0 => 0,
        1..=256 => 63,
        257..=512 => 83,
        _ => 140,
    };
    len / 1024 * 140 + last
}

/// XORs the keystream starting at block `state[12]` into `dst` in place. The counter must not
/// wrap within the `dst.len().div_ceil(64)` blocks. `false` (nothing done) without AVX-512.
#[cfg_attr(not(target_arch = "x86_64"), allow(clippy::needless_pass_by_ref_mut))]
pub(super) fn xor_wide(state: &[u32; 16], dst: &mut [u8]) -> bool {
    if !cpu::cpu_has(Feature::Avx512) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let len = dst.len();
        // Sixteen blocks at a time, then one group for the rest (see `Width::last`), under byte
        // masks when it does not fill the group.
        let whole = len / Width::Z.bytes();
        let mut st = *state;
        if whole > 0 {
            let to = dst.as_mut_ptr();
            // SAFETY: `cpu_has` confirmed AVX-512 F/BW/VL and the OS ZMM state; `whole >= 1`
            // groups of 1024 bytes fit in `dst`, worked on in place.
            unsafe { avx512::xor(&st, to.cast_const(), to, whole, Width::Z) };
            st[12] = st[12].wrapping_add(16 * whole as u32);
        }
        let done = whole * Width::Z.bytes();
        let rest = len - done;
        if rest > 0 {
            let w = Width::last(rest);
            let to = dst[done..].as_mut_ptr();
            // SAFETY: as above, one group of `rest` bytes (at most `w.bytes()`) in place from
            // offset `done`, under byte masks when it is not whole.
            unsafe { avx512::xor_masked(&st, to.cast_const(), to, rest, w) };
        }
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (state, dst);
        false
    }
}

/// Writes the keystream starting at block `state[12]` XOR `src` to the next `src.len()` bytes
/// of `out` (which may be uninitialised: they are only written), as [`xor_wide`] does in place.
/// The counter must not wrap within the `src.len().div_ceil(64)` blocks. `false` (nothing done)
/// without AVX-512.
#[cfg_attr(not(target_arch = "x86_64"), allow(clippy::needless_pass_by_ref_mut))]
pub(super) fn xor_wide_into(state: &[u32; 16], src: &[u8], out: &mut Fill<'_>) -> bool {
    if !cpu::cpu_has(Feature::Avx512) {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let len = src.len();
        let whole = len / Width::Z.bytes();
        let mut st = *state;
        if whole > 0 {
            let n = whole * Width::Z.bytes();
            let to = out.next_ptr(n);
            // SAFETY: `cpu_has` confirmed AVX-512 F/BW/VL and the OS ZMM state; `whole >= 1`
            // groups of 1024 bytes fit in `src` (readable) and at `to` (`next_ptr(n)`,
            // writable; the kernel only writes there); `src` is a shared slice and `out` holds a
            // unique borrow, so they do not overlap.
            unsafe { avx512::xor(&st, src.as_ptr(), to, whole, Width::Z) };
            // SAFETY: the kernel stored all `n` bytes at `next_ptr(n)`.
            unsafe { out.assume_written(n) };
            st[12] = st[12].wrapping_add(16 * whole as u32);
        }
        let done = whole * Width::Z.bytes();
        let rest = len - done;
        if rest > 0 {
            let w = Width::last(rest);
            let to = out.next_ptr(rest);
            // SAFETY: as above, one group of `rest` bytes (at most `w.bytes()`) from
            // `src[done..]` to `next_ptr(rest)`, under byte masks when it is not whole.
            unsafe { avx512::xor_masked(&st, src[done..].as_ptr(), to, rest, w) };
            // SAFETY: the kernel stored all `rest` bytes at `next_ptr(rest)`.
            unsafe { out.assume_written(rest) };
        }
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (state, src, out);
        false
    }
}

/// Absorbs the full blocks of `m` (a nonzero multiple of [`POLY_CHUNK`] bytes) into `h`
/// (44/44/42-bit limbs, partially reduced as the scalar code leaves them, so below 2⁴⁵) with the
/// powers `pw` of `r`; `false` (nothing done) without AVX-512 IFMA.
#[cfg_attr(not(target_arch = "x86_64"), allow(clippy::needless_pass_by_ref_mut))]
pub(super) fn poly_blocks(h: &mut [u64; 3], pw: &Powers, m: &[u8]) -> bool {
    if !cpu::cpu_has(Feature::Ifma) {
        return false;
    }
    assert!(
        !m.is_empty() && m.len() % POLY_CHUNK == 0,
        "Poly1305: whole groups"
    );
    #[cfg(target_arch = "x86_64")]
    {
        let mut acc = [0u64; 24];
        acc[0] = h[0];
        acc[8] = h[1];
        acc[16] = h[2];
        // SAFETY: `cpu_has` confirmed AVX-512 F + IFMA and the OS ZMM state; `m` holds
        // `m.len() / 128 >= 1` whole groups; `h` comes from the scalar code (limbs below 2⁴⁵)
        // and `pw` from `Poly1305::powers` (limbs below 2⁵⁰).
        unsafe { ifma::blocks(&mut acc, pw, m.as_ptr(), m.len() / POLY_CHUNK) };
        for (l, h) in h.iter_mut().enumerate() {
            *h = acc[8 * l..8 * l + 8].iter().sum();
        }
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (h, pw);
        false
    }
}

/// Whether to use the AVX2 path (detected and not switched off).
#[inline]
pub(super) fn enabled() -> bool {
    cpu::has(Feature::Avx2)
}

/// XORs the keystream of the eight blocks starting at `state` (counter `state[12]`, which must
/// not wrap within the eight) into `data`; `false` (nothing done) without AVX2.
#[inline]
#[cfg_attr(not(target_arch = "x86_64"), allow(clippy::needless_pass_by_ref_mut))]
pub(super) fn xor8(state: &[u32; 16], data: &mut [u8; 512]) -> bool {
    if !cpu::cpu_has(Feature::Avx2) {
        return false;
    }
    debug_assert!(state[12] <= u32::MAX - 8);
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `cpu_has` confirmed AVX2.
        unsafe { imp::xor8(state, data) };
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = data;
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use std::arch::x86_64::*;

    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor8(state: &[u32; 16], data: &mut [u8; 512]) {
        // SAFETY: the caller guarantees AVX2; loads and stores are 32-byte pieces of `data`
        // (unaligned), every other intrinsic works on registers.
        unsafe {
            let rot16 = _mm256_set_epi8(
                13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10,
                5, 4, 7, 6, 1, 0, 3, 2,
            );
            let rot8 = _mm256_set_epi8(
                14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11,
                6, 5, 4, 7, 2, 1, 0, 3,
            );
            let mut init = [_mm256_setzero_si256(); 16];
            for (v, &w) in init.iter_mut().zip(state) {
                *v = _mm256_set1_epi32(w as i32);
            }
            init[12] = _mm256_add_epi32(init[12], _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0));
            let mut x = init;
            macro_rules! qr {
                ($a:expr, $b:expr, $c:expr, $d:expr) => {
                    x[$a] = _mm256_add_epi32(x[$a], x[$b]);
                    x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[$d], x[$a]), rot16);
                    x[$c] = _mm256_add_epi32(x[$c], x[$d]);
                    let t = _mm256_xor_si256(x[$b], x[$c]);
                    x[$b] = _mm256_or_si256(_mm256_slli_epi32::<12>(t), _mm256_srli_epi32::<20>(t));
                    x[$a] = _mm256_add_epi32(x[$a], x[$b]);
                    x[$d] = _mm256_shuffle_epi8(_mm256_xor_si256(x[$d], x[$a]), rot8);
                    x[$c] = _mm256_add_epi32(x[$c], x[$d]);
                    let t = _mm256_xor_si256(x[$b], x[$c]);
                    x[$b] = _mm256_or_si256(_mm256_slli_epi32::<7>(t), _mm256_srli_epi32::<25>(t));
                };
            }
            for _ in 0..10 {
                qr!(0, 4, 8, 12);
                qr!(1, 5, 9, 13);
                qr!(2, 6, 10, 14);
                qr!(3, 7, 11, 15);
                qr!(0, 5, 10, 15);
                qr!(1, 6, 11, 12);
                qr!(2, 7, 8, 13);
                qr!(3, 4, 9, 14);
            }
            for (x, i) in x.iter_mut().zip(&init) {
                *x = _mm256_add_epi32(*x, *i);
            }
            // Transpose each half (words 0-7, words 8-15): row j = word j of blocks 0..7 becomes
            // column b = words of block b.
            for half in 0..2 {
                let r = &x[8 * half..8 * half + 8];
                let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
                let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
                let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
                let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
                let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
                let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
                let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
                let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
                let u0 = _mm256_unpacklo_epi64(t0, t2);
                let u1 = _mm256_unpackhi_epi64(t0, t2);
                let u2 = _mm256_unpacklo_epi64(t1, t3);
                let u3 = _mm256_unpackhi_epi64(t1, t3);
                let u4 = _mm256_unpacklo_epi64(t4, t6);
                let u5 = _mm256_unpackhi_epi64(t4, t6);
                let u6 = _mm256_unpacklo_epi64(t5, t7);
                let u7 = _mm256_unpackhi_epi64(t5, t7);
                let cols = [
                    _mm256_permute2x128_si256::<0x20>(u0, u4),
                    _mm256_permute2x128_si256::<0x20>(u1, u5),
                    _mm256_permute2x128_si256::<0x20>(u2, u6),
                    _mm256_permute2x128_si256::<0x20>(u3, u7),
                    _mm256_permute2x128_si256::<0x31>(u0, u4),
                    _mm256_permute2x128_si256::<0x31>(u1, u5),
                    _mm256_permute2x128_si256::<0x31>(u2, u6),
                    _mm256_permute2x128_si256::<0x31>(u3, u7),
                ];
                for (b, col) in cols.iter().enumerate() {
                    let o = 64 * b + 32 * half;
                    let p = data[o..o + 32].as_mut_ptr().cast::<__m256i>();
                    _mm256_storeu_si256(p, _mm256_xor_si256(_mm256_loadu_si256(p), *col));
                }
            }
        }
    }
}
