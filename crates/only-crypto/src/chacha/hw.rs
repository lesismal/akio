//! ChaCha20 eight blocks at a time with AVX2 (x86_64), chosen at run time. Word `j` of the eight
//! blocks shares one 256-bit register; after the rounds an 8×8 transpose turns the registers back
//! into blocks. Additions, XORs and rotations only: constant time like the portable code.
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the
//! `#[target_feature]` function and its intrinsics, called after the feature was detected.
#![allow(unsafe_code)]
// The intrinsics are `unsafe fn` at the MSRV (1.85) and safe inside `#[target_feature]` functions
// on newer compilers.
#![allow(unused_unsafe)]

use crate::cpu::{self, Feature};

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
