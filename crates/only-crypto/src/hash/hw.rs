//! SHA-1 and SHA-256 compression on the CPU's SHA instructions: SHA-NI on x86_64, the ARMv8
//! SHA1/SHA2 instructions on aarch64. Chosen at run time when the CPU has them; the message
//! schedule and rounds are the instructions' own, so the result is bit-for-bit the FIPS 180-4
//! compression of the portable code (hashes have no secret-dependent control flow either way).
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the
//! `#[target_feature]` functions and their intrinsics, called after the feature was detected.
#![allow(unsafe_code)]
// The intrinsics are `unsafe fn` at the MSRV (1.85) and safe inside `#[target_feature]` functions
// on newer compilers.
#![allow(unused_unsafe)]

use crate::cpu::{self, Feature};

/// Whether to use the SHA instructions (detected and not switched off).
#[inline]
pub(super) fn enabled() -> bool {
    cpu::has(Feature::Sha)
}

/// SHA-1 compression of every 64-byte block of `blocks` into `state`, if the CPU has the SHA
/// instructions; `false` (nothing done) otherwise.
#[inline]
pub(super) fn sha1(state: &mut [u32; 5], blocks: &[u8]) -> bool {
    debug_assert_eq!(blocks.len() % 64, 0);
    if !cpu::cpu_has(Feature::Sha) {
        return false;
    }
    // SAFETY: `cpu_has` confirmed the features `imp::sha1` is compiled for.
    unsafe { imp::sha1(state, blocks) };
    true
}

/// SHA-256 compression of every 64-byte block of `blocks` into `state`, if the CPU has the SHA
/// instructions; `false` (nothing done) otherwise.
#[inline]
pub(super) fn sha256(state: &mut [u32; 8], blocks: &[u8]) -> bool {
    debug_assert_eq!(blocks.len() % 64, 0);
    if !cpu::cpu_has(Feature::Sha) {
        return false;
    }
    // SAFETY: `cpu_has` confirmed the features `imp::sha256` is compiled for.
    unsafe { imp::sha256(state, blocks) };
    true
}

/// The SHA-256 round constants, four per group.
const K32X4: [[u32; 4]; 16] = {
    let k = super::sha256::K;
    let mut out = [[0u32; 4]; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = [k[4 * i], k[4 * i + 1], k[4 * i + 2], k[4 * i + 3]];
        i += 1;
    }
    out
};

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::K32X4;
    use std::arch::x86_64::*;

    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection; `p`
    /// points to 16 readable bytes.
    #[inline(always)]
    unsafe fn load(p: *const u8, mask: __m128i) -> __m128i {
        // SAFETY: the caller guarantees 16 readable bytes at `p` (unaligned load) and SSSE3.
        unsafe { _mm_shuffle_epi8(_mm_loadu_si128(p.cast()), mask) }
    }

    /// # Safety
    ///
    /// The CPU must support SHA, SSE2, SSSE3 and SSE4.1; `blocks.len()` is a multiple of 64.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn sha1(state: &mut [u32; 5], blocks: &[u8]) {
        // SAFETY: the caller guarantees the features; loads read 16-byte pieces of 64-byte
        // chunks of `blocks`.
        unsafe {
            // Byte-reverse the whole register: big-endian words, W0 in the top lane.
            let mask = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0a0b_0c0d_0e0f);
            let mut abcd = _mm_set_epi32(
                state[0] as i32,
                state[1] as i32,
                state[2] as i32,
                state[3] as i32,
            );
            let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);
            for b in blocks.chunks_exact(64) {
                let (abcd_save, e_save) = (abcd, e0);
                let p = b.as_ptr();
                let mut w = [
                    load(p, mask),
                    load(p.add(16), mask),
                    load(p.add(32), mask),
                    load(p.add(48), mask),
                ];
                // `prev` is ABCD four rounds back: SHA1NEXTE derives E from its A.
                let mut prev = abcd;
                abcd = _mm_sha1rnds4_epu32::<0>(abcd, _mm_add_epi32(e0, w[0]));
                macro_rules! step {
                    ($f:literal, $wk:expr) => {{
                        let e = _mm_sha1nexte_epu32(prev, $wk);
                        prev = abcd;
                        abcd = _mm_sha1rnds4_epu32::<$f>(abcd, e);
                    }};
                }
                macro_rules! sched {
                    () => {{
                        let n = _mm_sha1msg2_epu32(
                            _mm_xor_si128(_mm_sha1msg1_epu32(w[0], w[1]), w[2]),
                            w[3],
                        );
                        w = [w[1], w[2], w[3], n];
                        n
                    }};
                }
                step!(0, w[1]);
                step!(0, w[2]);
                step!(0, w[3]);
                step!(0, sched!());
                for _ in 0..5 {
                    step!(1, sched!());
                }
                for _ in 0..5 {
                    step!(2, sched!());
                }
                for _ in 0..5 {
                    step!(3, sched!());
                }
                abcd = _mm_add_epi32(abcd, abcd_save);
                e0 = _mm_sha1nexte_epu32(prev, e_save);
            }
            let mut out = [0u32; 4];
            _mm_storeu_si128(out.as_mut_ptr().cast(), abcd);
            state[..4].copy_from_slice(&[out[3], out[2], out[1], out[0]]);
            state[4] = _mm_extract_epi32::<3>(e0) as u32;
        }
    }

    /// # Safety
    ///
    /// The CPU must support SHA, SSE2, SSSE3 and SSE4.1; `blocks.len()` is a multiple of 64.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn sha256(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: the caller guarantees the features; loads read 16-byte pieces of 64-byte
        // chunks of `blocks` and of `state` / `K32X4`, stores write `state`.
        unsafe {
            // Byte-swap each 32-bit word: W0 in the low lane.
            let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
            let dcba = _mm_loadu_si128(state.as_ptr().cast());
            let hgfe = _mm_loadu_si128(state.as_ptr().add(4).cast());
            let cdab = _mm_shuffle_epi32::<0xb1>(dcba);
            let efgh = _mm_shuffle_epi32::<0x1b>(hgfe);
            let mut abef = _mm_alignr_epi8::<8>(cdab, efgh);
            let mut cdgh = _mm_blend_epi16::<0xf0>(efgh, cdab);
            for b in blocks.chunks_exact(64) {
                let (abef_save, cdgh_save) = (abef, cdgh);
                let p = b.as_ptr();
                let mut w = [
                    load(p, mask),
                    load(p.add(16), mask),
                    load(p.add(32), mask),
                    load(p.add(48), mask),
                ];
                macro_rules! rounds4 {
                    ($w:expr, $k:expr) => {{
                        let k = _mm_loadu_si128($k.as_ptr().cast());
                        let t = _mm_add_epi32($w, k);
                        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, t);
                        abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32::<0x0e>(t));
                    }};
                }
                rounds4!(w[0], K32X4[0]);
                rounds4!(w[1], K32X4[1]);
                rounds4!(w[2], K32X4[2]);
                rounds4!(w[3], K32X4[3]);
                for k in &K32X4[4..] {
                    let t = _mm_add_epi32(
                        _mm_sha256msg1_epu32(w[0], w[1]),
                        _mm_alignr_epi8::<4>(w[3], w[2]),
                    );
                    let n = _mm_sha256msg2_epu32(t, w[3]);
                    w = [w[1], w[2], w[3], n];
                    rounds4!(n, k);
                }
                abef = _mm_add_epi32(abef, abef_save);
                cdgh = _mm_add_epi32(cdgh, cdgh_save);
            }
            let feba = _mm_shuffle_epi32::<0x1b>(abef);
            let dchg = _mm_shuffle_epi32::<0xb1>(cdgh);
            let dcba = _mm_blend_epi16::<0xf0>(feba, dchg);
            let hgfe = _mm_alignr_epi8::<8>(dchg, feba);
            _mm_storeu_si128(state.as_mut_ptr().cast(), dcba);
            _mm_storeu_si128(state.as_mut_ptr().add(4).cast(), hgfe);
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::K32X4;
    use std::arch::aarch64::*;

    /// Four big-endian message words.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection; `p`
    /// points to 16 readable bytes.
    #[inline(always)]
    unsafe fn load(p: *const u8) -> uint32x4_t {
        // SAFETY: the caller guarantees 16 readable bytes at `p`.
        unsafe { vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))) }
    }

    /// # Safety
    ///
    /// The CPU must support the `sha2` feature (which includes the SHA-1 instructions);
    /// `blocks.len()` is a multiple of 64.
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn sha1(state: &mut [u32; 5], blocks: &[u8]) {
        // SAFETY: the caller guarantees the feature; loads read 16-byte pieces of 64-byte chunks
        // of `blocks` and of `state`, the store writes `state[..4]`.
        unsafe {
            let k = [
                vdupq_n_u32(0x5a82_7999),
                vdupq_n_u32(0x6ed9_eba1),
                vdupq_n_u32(0x8f1b_bcdc),
                vdupq_n_u32(0xca62_c1d6),
            ];
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut e0 = state[4];
            for b in blocks.chunks_exact(64) {
                let (abcd_save, e_save) = (abcd, e0);
                let p = b.as_ptr();
                let mut w = [load(p), load(p.add(16)), load(p.add(32)), load(p.add(48))];
                for s in 0..20 {
                    let wk = if s < 4 {
                        w[s]
                    } else {
                        let n = vsha1su1q_u32(vsha1su0q_u32(w[0], w[1], w[2]), w[3]);
                        w = [w[1], w[2], w[3], n];
                        n
                    };
                    let t = vaddq_u32(wk, k[s / 5]);
                    let e_next = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
                    abcd = match s / 5 {
                        0 => vsha1cq_u32(abcd, e0, t),
                        2 => vsha1mq_u32(abcd, e0, t),
                        _ => vsha1pq_u32(abcd, e0, t),
                    };
                    e0 = e_next;
                }
                abcd = vaddq_u32(abcd, abcd_save);
                e0 = e0.wrapping_add(e_save);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            state[4] = e0;
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `sha2` feature; `blocks.len()` is a multiple of 64.
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn sha256(state: &mut [u32; 8], blocks: &[u8]) {
        // SAFETY: the caller guarantees the feature; loads read 16-byte pieces of 64-byte chunks
        // of `blocks`, of `state` and of `K32X4`, stores write `state`.
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut efgh = vld1q_u32(state.as_ptr().add(4));
            for b in blocks.chunks_exact(64) {
                let (abcd_save, efgh_save) = (abcd, efgh);
                let p = b.as_ptr();
                let mut w = [load(p), load(p.add(16)), load(p.add(32)), load(p.add(48))];
                for (i, k) in K32X4.iter().enumerate() {
                    let wk = if i < 4 {
                        w[i]
                    } else {
                        let n = vsha256su1q_u32(vsha256su0q_u32(w[0], w[1]), w[2], w[3]);
                        w = [w[1], w[2], w[3], n];
                        n
                    };
                    let t = vaddq_u32(wk, vld1q_u32(k.as_ptr()));
                    let abcd_prev = abcd;
                    abcd = vsha256hq_u32(abcd, efgh, t);
                    efgh = vsha256h2q_u32(efgh, abcd_prev, t);
                }
                abcd = vaddq_u32(abcd, abcd_save);
                efgh = vaddq_u32(efgh, efgh_save);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            vst1q_u32(state.as_mut_ptr().add(4), efgh);
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod imp {
    /// # Safety
    ///
    /// Never called: the SHA feature is never detected on this architecture.
    pub(super) unsafe fn sha1(_: &mut [u32; 5], _: &[u8]) {
        unreachable!("no SHA instructions on this architecture")
    }
    /// # Safety
    ///
    /// Never called: the SHA feature is never detected on this architecture.
    pub(super) unsafe fn sha256(_: &mut [u32; 8], _: &[u8]) {
        unreachable!("no SHA instructions on this architecture")
    }
}
