//! GHASH on the CPU's carry-less multiplication (PCLMULQDQ on x86_64, PMULL on aarch64) and, with
//! AES instructions too, AES-GCM encryption and decryption fused into one pass: each 128-byte
//! group is encrypted eight counter blocks at a time and hashed in the same loop iteration, so
//! the AES and carry-less multiplication units work in parallel. Chosen at run time when the CPU
//! has the instructions; they take constant time.
//!
//! Blocks use the layout of the portable GHASH (`super::Ghash`): a block is the 128-bit integer
//! whose most significant bit is the first bit of the block (the coefficient of `x⁰`), split into
//! `[lo, hi]` 64-bit halves. Up to eight blocks are aggregated per reduction:
//! `Y' = (Y ⊕ X₁)·Hⁿ ⊕ X₂·Hⁿ⁻¹ ⊕ … ⊕ Xₙ·H`, with Karatsuba products accumulated unreduced and a
//! single shift-and-reduce (the same steps as the portable path, on the four product words) per
//! group. `Hⁱ` are precomputed with the portable constant-time multiplication.
//!
//! On x86_64 with VAES and VPCLMULQDQ the kernels of `vaes` take over: with AVX-512 the whole
//! message (AAD up to 256 bytes, every data byte, the tag) in one call
//! ([`Powers::crypt_all`]), with AVX2 only whole 256-byte groups (this module handles the rest).
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the
//! `#[target_feature]` functions and their intrinsics and for the `asm!` kernels of `vaes`,
//! called after the features were detected.
#![allow(unsafe_code)]
// The intrinsics are `unsafe fn` at the MSRV (1.85) and safe inside `#[target_feature]` functions
// on newer compilers.
#![allow(unused_unsafe)]

use crate::cpu::{self, Feature};

#[cfg(target_arch = "x86_64")]
mod vaes;

/// Which kernels a key may use: the widest the CPU has, at most the VAES-AVX2 one, or only the
/// 128-bit one (the last two for tests and benchmarks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Best,
    Avx2,
    Narrow,
}

/// The VAES kernel a key uses (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wide {
    /// VAES + VPCLMULQDQ + AVX-512: the whole message per call.
    Avx512,
    /// VAES + VPCLMULQDQ + AVX2: whole 256-byte groups.
    Avx2,
}

/// `H¹ … H⁸` as `[lo, hi, lo ^ hi]` (the last word for Karatsuba), and on x86_64 with VAES the
/// sixteen powers of the wide kernels (`vaes`) and which kernel to use.
#[derive(Clone)]
pub(super) struct Powers {
    k: [[u64; 3]; 8],
    #[cfg(target_arch = "x86_64")]
    wide: Option<(vaes::WidePowers, Wide)>,
}

/// AES round keys from `aes::hw`: the encryption keys and the round count.
pub(super) type RoundKeys<'a> = (&'a [[u8; 16]; 15], usize);

/// Whether this CPU has carry-less multiplication (the condition for every call into `imp`).
fn available() -> bool {
    cpu::cpu_has(Feature::Clmul)
}

/// Whether this CPU has what the AVX2 kernel needs (the condition for every call into
/// `vaes::crypt256`): AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ and AVX2 with the OS saving the YMM
/// state.
#[cfg(target_arch = "x86_64")]
fn avx2_available() -> bool {
    cpu::cpu_has(Feature::Aes) && cpu::cpu_has(Feature::Clmul) && cpu::cpu_has(Feature::Vaes)
}

/// Whether this CPU has what the AVX-512 kernel needs (the condition for every call into
/// `vaes::crypt512`): the AVX2 kernel's features and AVX-512 F/BW/VL with the OS saving the ZMM
/// and opmask state.
#[cfg(target_arch = "x86_64")]
fn wide_available() -> bool {
    avx2_available() && cpu::cpu_has(Feature::Avx512)
}

/// The counter block `n` blocks after `ctr` (32-bit big-endian counter, wrapping).
fn advance(ctr: &[u8; 16], n: usize) -> [u8; 16] {
    let mut c = *ctr;
    let v = u32::from_be_bytes([c[12], c[13], c[14], c[15]]).wrapping_add(n as u32);
    c[12..].copy_from_slice(&v.to_be_bytes());
    c
}

impl Powers {
    /// The powers of `h` (`[lo, hi]`), or `None` without carry-less multiplication (or when the
    /// portable path is forced). On x86_64 with VAES (and a `mode` that allows it, the CPU
    /// features not switched off) also the powers of the wide kernels.
    pub(super) fn new(h: [u64; 2], mode: Mode) -> Option<Powers> {
        if !cpu::has(Feature::Clmul) || !available() {
            return None;
        }
        let mut p = [[0u64; 3]; 8];
        let mut x = h;
        for e in &mut p {
            *e = [x[0], x[1], x[0] ^ x[1]];
            x = super::gf_mul(x, h);
        }
        #[cfg(target_arch = "x86_64")]
        let wide = {
            let vaes = cpu::has(Feature::Aes) && cpu::has(Feature::Vaes) && avx2_available();
            let avx512 = vaes && cpu::has(Feature::Avx512) && wide_available();
            let kind = match mode {
                Mode::Best if avx512 => Some(Wide::Avx512),
                Mode::Best | Mode::Avx2 if vaes => Some(Wide::Avx2),
                _ => None,
            };
            kind.map(|k| {
                // `x` is H⁹ here.
                let mut all = [[0u64; 2]; 16];
                for (a, e) in all.iter_mut().zip(&p) {
                    *a = [e[0], e[1]];
                }
                for a in &mut all[8..] {
                    *a = x;
                    x = super::gf_mul(x, h);
                }
                (vaes::WidePowers::new(&all), k)
            })
        };
        #[cfg(not(target_arch = "x86_64"))]
        let _ = mode;
        Some(Powers {
            k: p,
            #[cfg(target_arch = "x86_64")]
            wide,
        })
    }

    /// The kernel AES-GCM runs on: `"vaes-avx512"`, `"vaes-avx2"` or `"clmul"` (the 128-bit
    /// one).
    pub(super) fn kernel(&self) -> &'static str {
        #[cfg(target_arch = "x86_64")]
        match self.wide {
            Some((_, Wide::Avx512)) => return "vaes-avx512",
            Some((_, Wide::Avx2)) => return "vaes-avx2",
            None => {}
        }
        "clmul"
    }

    /// Whether [`crypt_all`](Self::crypt_all) does whole messages (the AVX-512 kernel).
    pub(super) fn whole_message(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        return matches!(self.wide, Some((_, Wide::Avx512)));
        #[cfg(not(target_arch = "x86_64"))]
        false
    }

    /// Absorbs `data` (whole 16-byte blocks) into the GHASH state `y`.
    pub(super) fn update(&self, y: &mut [u64; 2], data: &[u8]) {
        debug_assert_eq!(data.len() % 16, 0);
        if !available() {
            unreachable!("Powers exist only with carry-less multiplication");
        }
        // SAFETY: `available()` confirmed the CPU features `imp::ghash` is compiled for.
        unsafe { imp::ghash(self, y, data) }
    }

    /// CTR-encrypts (`open == false`) or decrypts (`open == true`) the whole 128-byte groups at
    /// the start of `data` with the AES round keys `rk`, starting at the counter block `ctr`
    /// (32-bit big-endian counter in the last four bytes, wrapping), and absorbs the ciphertext
    /// into `y`. Returns the number of bytes processed (a multiple of 128): whole 256-byte groups
    /// on the wide kernel when there is one, then 128-byte groups.
    ///
    /// With `src` (at most `data.len()` bytes), the input is `src` followed by
    /// `data[src.len()..]`: the wide kernel reads its groups from `src` and writes them to
    /// `data`, the rest of `src` is copied into `data` and processed in place.
    pub(super) fn crypt(
        &self,
        rk: RoundKeys<'_>,
        ctr: &[u8; 16],
        y: &mut [u64; 2],
        src: Option<&[u8]>,
        data: &mut [u8],
        open: bool,
    ) -> usize {
        if !available() || !cpu::cpu_has(Feature::Aes) {
            unreachable!("round keys and Powers exist only with AES and carry-less multiplication");
        }
        assert!(src.is_none_or(|s| s.len() <= data.len()));
        #[allow(unused_mut)]
        let mut done = 0;
        #[cfg(target_arch = "x86_64")]
        if let Some((w, kind)) = &self.wide {
            let chunk = match kind {
                Wide::Avx512 => vaes::CHUNK,
                Wide::Avx2 => vaes::CHUNK2,
            };
            let n = src.map_or(data.len(), <[u8]>::len) / chunk * chunk;
            if n > 0 {
                let dst = data.as_mut_ptr();
                let from = src.map_or_else(|| dst.cast_const(), <[u8]>::as_ptr);
                match kind {
                    Wide::Avx512 => {
                        if !wide_available() {
                            unreachable!("AVX-512 powers exist only with VAES and AVX-512");
                        }
                        let mut a = vaes::Args::new(ctr, *y);
                        // SAFETY: `wide_available()` confirmed every CPU and OS feature the
                        // kernel needs; the `n / CHUNK` whole groups lie within `data` and
                        // within `src` (when given); `a` has no tail and no AAD, so nothing
                        // else is read or written; `src` is a shared slice and `data` a unique
                        // one, so they do not overlap, and without `src` the kernel works in
                        // place on `data`; `rk` comes from `aes::hw` (round count 10, 12, 14).
                        unsafe { vaes::crypt512(w, rk, &mut a, from, dst, n / chunk, open) };
                        *y = a.y();
                    }
                    Wide::Avx2 => {
                        if !avx2_available() {
                            unreachable!("AVX2 wide powers exist only with VAES");
                        }
                        // SAFETY: `avx2_available()` confirmed every CPU and OS feature the
                        // kernel needs; `n` is a nonzero multiple of `CHUNK2` and at most the
                        // length of `data` and of `src` (when given); `src` is a shared slice
                        // and `data` a unique one, so they do not overlap, and without `src`
                        // the kernel works in place on `data`; `rk` comes from `aes::hw`.
                        unsafe { vaes::crypt256(w, rk, ctr, y, from, dst, n, open) };
                    }
                }
                done = n;
            }
        }
        if let Some(s) = src {
            data[done..s.len()].copy_from_slice(&s[done..]);
        }
        let rest = &mut data[done..];
        let n = rest.len() & !127;
        if n > 0 {
            let c = advance(ctr, done / 16);
            // SAFETY: `cpu_has` confirmed AES and carry-less multiplication (and, on x86_64,
            // the SSE levels `Feature::Clmul` includes); `n` is a multiple of 128.
            unsafe { imp::crypt(self, rk, &c, y, &mut rest[..n], open) };
        }
        done + n
    }

    /// All of AES-GCM after the key schedule on the AVX-512 kernel, when this key has it (else
    /// `None`, nothing done): `aad` (the whole AAD of `aad_len` bytes when that is at most 256
    /// bytes, else empty with its GHASH already in `y`) is hashed, `data` encrypted
    /// (`open == false`) or decrypted in place, or with `src` (at most `data.len()` bytes) from
    /// `src` followed by `data[src.len()..]`, and the tag over the ciphertext returned.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn crypt_all(
        &self,
        rk: RoundKeys<'_>,
        j0: &[u8; 16],
        y: [u64; 2],
        aad: &[u8],
        aad_len: usize,
        src: Option<&[u8]>,
        data: &mut [u8],
        open: bool,
    ) -> Option<[u8; 16]> {
        #[cfg(target_arch = "x86_64")]
        if let Some((w, Wide::Avx512)) = &self.wide {
            if !wide_available() {
                unreachable!("AVX-512 powers exist only with VAES and AVX-512");
            }
            assert!(src.is_none_or(|s| s.len() <= data.len()) && aad.len() <= vaes::CHUNK);
            let len = data.len();
            let ctr = advance(j0, 1);
            let mut a = vaes::Args::new(&ctr, y);
            a.aad(w, aad);
            // Input partly in `src`, partly in `data`: the whole groups of `src` first (out of
            // place), then the rest of `src` copied over and everything after it in place.
            let mut at = 0;
            let mut from = None;
            match src {
                Some(s) if s.len() < len => {
                    let first = s.len() / vaes::CHUNK * vaes::CHUNK;
                    if first > 0 {
                        // SAFETY: `wide_available()` confirmed every CPU and OS feature the
                        // kernel needs; the `first / CHUNK` whole groups lie within `s` and
                        // `data`, a shared and a unique slice that do not overlap; `a` has no
                        // tail, and its AAD was set by `Args::aad` from the live slice `aad`
                        // with the powers `w`; `rk` comes from `aes::hw` (round count 10, 12 or
                        // 14).
                        unsafe {
                            vaes::crypt512(
                                w,
                                rk,
                                &mut a,
                                s.as_ptr(),
                                data.as_mut_ptr(),
                                first / vaes::CHUNK,
                                open,
                            );
                        }
                        a = vaes::Args::new(&advance(&ctr, first / 16), a.y());
                    }
                    data[first..s.len()].copy_from_slice(&s[first..]);
                    at = first;
                }
                Some(s) => from = Some(s),
                None => {}
            }
            let rest = &mut data[at..];
            let groups = rest.len() / vaes::CHUNK;
            let tail = rest.len() - groups * vaes::CHUNK;
            // The tail is read from where the groups are, just after them.
            let tail_src = match from {
                Some(s) => s[groups * vaes::CHUNK..].as_ptr(),
                None => rest[groups * vaes::CHUNK..].as_ptr(),
            };
            let dst = rest.as_mut_ptr();
            let from = from.map_or_else(|| dst.cast_const(), <[u8]>::as_ptr);
            a.tail(w, tail_src, tail);
            a.finish(j0, aad_len, len);
            if groups == 0 {
                a.short(w);
            }
            // SAFETY: `wide_available()` confirmed every CPU and OS feature the kernel needs;
            // `rest` (at `dst`) holds `groups` whole groups and then the `tail` bytes, and the
            // input is either `rest` itself (in place, the tail source then exactly
            // `dst + 256 * groups`) or all of `src`, a shared slice of the same length that does
            // not overlap `data` (the tail source then inside it, after the groups); the AAD of
            // `a` was set by `Args::aad` from the live slice `aad` (or is none) with the powers
            // `w`, the tail by `Args::tail` with `w` (both moved by `Args::short` within `w`);
            // `rk` comes from `aes::hw`.
            unsafe { vaes::crypt512(w, rk, &mut a, from, dst, groups, open) };
            return Some(a.tag());
        }
        let _ = (rk, j0, y, aad, aad_len, src, data, open);
        None
    }
}

/// The GHASH product of the 256-bit unreduced product `v` (least significant word first):
/// shift left by one (bit-reflected operands) and reduce modulo `x¹²⁸ + x⁷ + x² + x + 1`, as in
/// the portable `Ghash::block`. Returns `[lo, hi]`.
#[inline(always)]
fn reduce(v: [u64; 4]) -> [u64; 2] {
    let [mut v0, mut v1, mut v2, mut v3] = v;
    v3 = (v3 << 1) | (v2 >> 63);
    v2 = (v2 << 1) | (v1 >> 63);
    v1 = (v1 << 1) | (v0 >> 63);
    v0 <<= 1;
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    [v2, v3]
}

/// The four product words from the accumulated Karatsuba terms (`lo`, `hi`: 128-bit products of
/// the low and high halves; `mid`: of the half sums).
#[inline(always)]
fn combine(lo: [u64; 2], hi: [u64; 2], mid: [u64; 2]) -> [u64; 4] {
    let m0 = mid[0] ^ lo[0] ^ hi[0];
    let m1 = mid[1] ^ lo[1] ^ hi[1];
    [lo[0], lo[1] ^ m0, hi[0] ^ m1, hi[1]]
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::{Powers, RoundKeys, combine, reduce};
    use std::arch::x86_64::*;

    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection.
    #[inline(always)]
    unsafe fn words(v: __m128i) -> [u64; 2] {
        // SAFETY: SSE2/SSE4.1 lane extraction, no memory access.
        unsafe {
            [
                _mm_cvtsi128_si64(v) as u64,
                _mm_extract_epi64::<1>(v) as u64,
            ]
        }
    }

    /// A block, byte-reversed into the `[lo, hi]` lane layout.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection; `b` has
    /// at least 16 bytes.
    #[inline(always)]
    unsafe fn load(b: &[u8], rev: __m128i) -> __m128i {
        debug_assert!(b.len() >= 16);
        // SAFETY: reads 16 bytes of `b` (callers pass slices of at least 16 bytes), unaligned.
        unsafe { _mm_shuffle_epi8(_mm_loadu_si128(b.as_ptr().cast()), rev) }
    }

    /// One block's Karatsuba terms into the accumulators.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection.
    #[inline(always)]
    unsafe fn mul_acc(x: __m128i, h: __m128i, hx: __m128i, acc: &mut [__m128i; 3]) {
        // SAFETY: register-only intrinsics; the caller guarantees PCLMULQDQ and SSE2.
        unsafe {
            let xx = _mm_xor_si128(x, _mm_shuffle_epi32::<0x4e>(x));
            acc[0] = _mm_xor_si128(acc[0], _mm_clmulepi64_si128::<0x00>(x, h));
            acc[1] = _mm_xor_si128(acc[1], _mm_clmulepi64_si128::<0x11>(x, h));
            acc[2] = _mm_xor_si128(acc[2], _mm_clmulepi64_si128::<0x00>(xx, hx));
        }
    }

    /// The powers as vectors: `([H¹ … H⁸], [Karatsuba words])`.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection.
    #[inline(always)]
    unsafe fn powers(p: &Powers) -> ([__m128i; 8], [__m128i; 8]) {
        // SAFETY: register-only intrinsics.
        unsafe {
            let mut h = [_mm_setzero_si128(); 8];
            let mut hx = [_mm_setzero_si128(); 8];
            for ((h, hx), w) in h.iter_mut().zip(hx.iter_mut()).zip(&p.k) {
                *h = _mm_set_epi64x(w[1] as i64, w[0] as i64);
                *hx = _mm_set_epi64x(0, w[2] as i64);
            }
            (h, hx)
        }
    }

    /// Absorbs the `n = blocks.len() / 16` (1 to 8) blocks of `blocks` into `y` with one
    /// reduction.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection;
    /// `blocks.len()` is 16 to 128 and a multiple of 16.
    #[inline(always)]
    unsafe fn ghash_group(
        h: &[__m128i; 8],
        hx: &[__m128i; 8],
        y: [u64; 2],
        blocks: &[u8],
        rev: __m128i,
    ) -> [u64; 2] {
        // SAFETY: every load reads 16 bytes inside `blocks`.
        unsafe {
            let n = blocks.len() / 16;
            let mut acc = [_mm_setzero_si128(); 3];
            let x0 = _mm_xor_si128(
                load(&blocks[..16], rev),
                _mm_set_epi64x(y[1] as i64, y[0] as i64),
            );
            mul_acc(x0, h[n - 1], hx[n - 1], &mut acc);
            for i in 1..n {
                mul_acc(
                    load(&blocks[16 * i..], rev),
                    h[n - 1 - i],
                    hx[n - 1 - i],
                    &mut acc,
                );
            }
            reduce(combine(words(acc[0]), words(acc[1]), words(acc[2])))
        }
    }

    /// # Safety
    ///
    /// The CPU must support PCLMULQDQ, SSE2, SSSE3 and SSE4.1; `data.len()` is a multiple of 16.
    #[target_feature(enable = "pclmulqdq,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn ghash(p: &Powers, y: &mut [u64; 2], data: &[u8]) {
        // SAFETY: the caller guarantees the features; `ghash_group` gets 16 to 128 bytes, a
        // multiple of 16.
        unsafe {
            let rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let (h, hx) = powers(p);
            let mut acc_y = *y;
            for c in data.chunks(128) {
                acc_y = ghash_group(&h, &hx, acc_y, c, rev);
            }
            *y = acc_y;
        }
    }

    /// # Safety
    ///
    /// The CPU must support AES, PCLMULQDQ, SSE2, SSSE3 and SSE4.1; `data.len()` is a multiple of
    /// 128; `rk.1` is 10, 12 or 14.
    #[target_feature(enable = "aes,pclmulqdq,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn crypt(
        p: &Powers,
        rk: RoundKeys<'_>,
        ctr: &[u8; 16],
        y: &mut [u64; 2],
        data: &mut [u8],
        open: bool,
    ) {
        // SAFETY: as in `crypt_r`.
        unsafe {
            match (rk.1, open) {
                (10, false) => crypt_r::<10, false>(p, rk.0, ctr, y, data),
                (12, false) => crypt_r::<12, false>(p, rk.0, ctr, y, data),
                (_, false) => crypt_r::<14, false>(p, rk.0, ctr, y, data),
                (10, true) => crypt_r::<10, true>(p, rk.0, ctr, y, data),
                (12, true) => crypt_r::<12, true>(p, rk.0, ctr, y, data),
                (_, true) => crypt_r::<14, true>(p, rk.0, ctr, y, data),
            }
        }
    }

    /// `crypt` with the round count and direction known at compile time.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection;
    /// `data.len()` is a multiple of 128.
    #[inline(always)]
    unsafe fn crypt_r<const R: usize, const OPEN: bool>(
        p: &Powers,
        rk: &[[u8; 16]; 15],
        ctr: &[u8; 16],
        y: &mut [u64; 2],
        data: &mut [u8],
    ) {
        // SAFETY: loads and stores are 16-byte pieces of the 128-byte chunks of `data` or whole
        // 16-byte arrays; `ghash_group` gets exactly 128 bytes.
        unsafe {
            let rev = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            let (h, hx) = powers(p);
            let mut k = [_mm_setzero_si128(); 15];
            for (k, r) in k.iter_mut().zip(rk.iter()).take(R + 1) {
                *k = _mm_loadu_si128(r.as_ptr().cast());
            }
            let base = _mm_loadu_si128(ctr.as_ptr().cast());
            let c0 = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
            let mut acc_y = *y;
            for (g, chunk) in data.chunks_exact_mut(128).enumerate() {
                let c = c0.wrapping_add(8 * g as u32);
                let mut s = [k[0]; 8];
                for (i, s) in s.iter_mut().enumerate() {
                    let cb =
                        _mm_insert_epi32::<3>(base, c.wrapping_add(i as u32).swap_bytes() as i32);
                    *s = _mm_xor_si128(cb, k[0]);
                }
                if OPEN {
                    acc_y = ghash_group(&h, &hx, acc_y, chunk, rev);
                }
                for rk in &k[1..R] {
                    for s in &mut s {
                        *s = _mm_aesenc_si128(*s, *rk);
                    }
                }
                for (s, d) in s.iter().zip(chunk.chunks_exact_mut(16)) {
                    let ptr = d.as_mut_ptr().cast::<__m128i>();
                    let v = _mm_xor_si128(_mm_aesenclast_si128(*s, k[R]), _mm_loadu_si128(ptr));
                    _mm_storeu_si128(ptr, v);
                }
                if !OPEN {
                    acc_y = ghash_group(&h, &hx, acc_y, chunk, rev);
                }
            }
            *y = acc_y;
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::{Powers, RoundKeys, combine, reduce};
    use std::arch::aarch64::*;

    /// A block as `[lo, hi]`: the big-endian halves, swapped.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection; `b` has
    /// at least 16 bytes.
    #[inline(always)]
    unsafe fn load(b: &[u8]) -> [u64; 2] {
        debug_assert!(b.len() >= 16);
        // SAFETY: reads 16 bytes of `b` (callers pass slices of at least 16 bytes).
        unsafe {
            let v = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(b.as_ptr())));
            [vgetq_lane_u64::<1>(v), vgetq_lane_u64::<0>(v)]
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature (PMULL).
    #[inline(always)]
    unsafe fn clmul(a: u64, b: u64) -> [u64; 2] {
        // SAFETY: register-only intrinsic; the caller guarantees the feature.
        let p = unsafe { vmull_p64(a, b) };
        [p as u64, (p >> 64) as u64]
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature (PMULL).
    #[inline(always)]
    unsafe fn mul_acc(x: [u64; 2], h: &[u64; 3], acc: &mut [[u64; 2]; 3]) {
        // SAFETY: the caller guarantees the feature.
        unsafe {
            let lo = clmul(x[0], h[0]);
            let hi = clmul(x[1], h[1]);
            let mid = clmul(x[0] ^ x[1], h[2]);
            for (a, t) in acc.iter_mut().zip([lo, hi, mid]) {
                a[0] ^= t[0];
                a[1] ^= t[1];
            }
        }
    }

    /// Absorbs the `n = blocks.len() / 16` (1 to 8) blocks of `blocks` into `y` with one
    /// reduction.
    ///
    /// # Safety
    ///
    /// The CPU must support the `aes` feature (PMULL); `blocks.len()` is 16 to 128 and a
    /// multiple of 16.
    #[inline(always)]
    unsafe fn ghash_group(p: &Powers, y: [u64; 2], blocks: &[u8]) -> [u64; 2] {
        // SAFETY: every load reads 16 bytes inside `blocks`.
        unsafe {
            let h = &p.k;
            let n = blocks.len() / 16;
            let mut acc = [[0u64; 2]; 3];
            let x = load(&blocks[..16]);
            mul_acc([x[0] ^ y[0], x[1] ^ y[1]], &h[n - 1], &mut acc);
            for i in 1..n {
                mul_acc(load(&blocks[16 * i..]), &h[n - 1 - i], &mut acc);
            }
            reduce(combine(acc[0], acc[1], acc[2]))
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature (PMULL; NEON is baseline); `data.len()` is a
    /// multiple of 16.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn ghash(p: &Powers, y: &mut [u64; 2], data: &[u8]) {
        // SAFETY: the caller guarantees the feature; `ghash_group` gets 16 to 128 bytes, a
        // multiple of 16.
        unsafe {
            let mut acc_y = *y;
            for c in data.chunks(128) {
                acc_y = ghash_group(p, acc_y, c);
            }
            *y = acc_y;
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature; `data.len()` is a multiple of 128; `rk.1` is 10,
    /// 12 or 14.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn crypt(
        p: &Powers,
        rk: RoundKeys<'_>,
        ctr: &[u8; 16],
        y: &mut [u64; 2],
        data: &mut [u8],
        open: bool,
    ) {
        // SAFETY: as in `crypt_r`.
        unsafe {
            match (rk.1, open) {
                (10, false) => crypt_r::<10, false>(p, rk.0, ctr, y, data),
                (12, false) => crypt_r::<12, false>(p, rk.0, ctr, y, data),
                (_, false) => crypt_r::<14, false>(p, rk.0, ctr, y, data),
                (10, true) => crypt_r::<10, true>(p, rk.0, ctr, y, data),
                (12, true) => crypt_r::<12, true>(p, rk.0, ctr, y, data),
                (_, true) => crypt_r::<14, true>(p, rk.0, ctr, y, data),
            }
        }
    }

    /// `crypt` with the round count and direction known at compile time.
    ///
    /// # Safety
    ///
    /// The CPU must support the `aes` feature; `data.len()` is a multiple of 128.
    #[inline(always)]
    unsafe fn crypt_r<const R: usize, const OPEN: bool>(
        p: &Powers,
        rk: &[[u8; 16]; 15],
        ctr: &[u8; 16],
        y: &mut [u64; 2],
        data: &mut [u8],
    ) {
        // SAFETY: loads and stores are 16-byte pieces of the 128-byte chunks of `data` or whole
        // 16-byte arrays; `ghash_group` gets exactly 128 bytes.
        unsafe {
            let mut k = [vdupq_n_u8(0); 15];
            for (k, r) in k.iter_mut().zip(rk.iter()).take(R + 1) {
                *k = vld1q_u8(r.as_ptr());
            }
            let base = vreinterpretq_u32_u8(vld1q_u8(ctr.as_ptr()));
            let c0 = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
            let mut acc_y = *y;
            for (g, chunk) in data.chunks_exact_mut(128).enumerate() {
                let c = c0.wrapping_add(8 * g as u32);
                let mut s = [k[0]; 8];
                for (i, s) in s.iter_mut().enumerate() {
                    let cb = vsetq_lane_u32::<3>(c.wrapping_add(i as u32).swap_bytes(), base);
                    *s = vreinterpretq_u8_u32(cb);
                }
                if OPEN {
                    acc_y = ghash_group(p, acc_y, chunk);
                }
                for rk in &k[..R - 1] {
                    for s in &mut s {
                        *s = vaesmcq_u8(vaeseq_u8(*s, *rk));
                    }
                }
                for (s, d) in s.iter().zip(chunk.chunks_exact_mut(16)) {
                    let ptr = d.as_mut_ptr();
                    let v = veorq_u8(veorq_u8(vaeseq_u8(*s, k[R - 1]), k[R]), vld1q_u8(ptr));
                    vst1q_u8(ptr, v);
                }
                if !OPEN {
                    acc_y = ghash_group(p, acc_y, chunk);
                }
            }
            *y = acc_y;
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod imp {
    use super::{Powers, RoundKeys};

    /// # Safety
    ///
    /// Never called: no `Powers` can exist on this architecture.
    pub(super) unsafe fn ghash(_: &Powers, _: &mut [u64; 2], _: &[u8]) {
        unreachable!("no carry-less multiplication on this architecture")
    }

    /// # Safety
    ///
    /// Never called: no `Powers` can exist on this architecture.
    pub(super) unsafe fn crypt(
        _: &Powers,
        _: RoundKeys<'_>,
        _: &[u8; 16],
        _: &mut [u64; 2],
        _: &mut [u8],
        _: bool,
    ) {
        unreachable!("no AES or carry-less multiplication on this architecture")
    }
}
