//! CRC-32 and CRC-32C on CPU instructions, chosen at run time:
//!
//! - x86_64: both polynomials fold 64 bytes per step with PCLMULQDQ (four independent 128-bit
//!   accumulators, Intel's "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ"
//!   method) down to one 128-bit value congruent to the input modulo the polynomial; its 16 bytes
//!   and the tail go through the table (CRC-32) or the SSE4.2 `crc32` instruction (CRC-32C,
//!   which also handles short inputs).
//! - aarch64: the ARMv8 CRC32 instructions (`crc32x` / `crc32cx`, eight bytes per instruction).
//!
//! Folding works on the register state (`!crc`, as in `super::update`): XORing the state into the
//! first four bytes and starting from zero gives the same CRC, and a 128-bit block `X` followed
//! by `128·m` bits is replaced by `X_lo·(x^(128m+63) mod P) ⊕ X_hi·(x^(128m-1) mod P)` (bit
//! reflected), which has the same remainder. The fold constants are computed at compile time
//! from the polynomial.
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the
//! `#[target_feature]` functions and their intrinsics, called after the feature was detected.
#![allow(unsafe_code)]
// The intrinsics are `unsafe fn` at the MSRV (1.85) and safe inside `#[target_feature]` functions
// on newer compilers.
#![allow(unused_unsafe)]

#[cfg(target_arch = "x86_64")]
use crate::cpu::cpu_has;
use crate::cpu::{Feature, has};

/// Which CRC.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Poly {
    /// IEEE 802.3, `0x04C11DB7` (reflected `0xEDB88320`).
    Ieee,
    /// Castagnoli, `0x1EDC6F41` (reflected `0x82F63B78`).
    Castagnoli,
}

/// `x^n mod P` for the degree-32 polynomial `x³² + poly` (normal bit order, compile time).
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const fn xpow_mod(n: u32, poly: u32) -> u32 {
    let mut r: u64 = 1;
    let mut i = 0;
    while i < n {
        r <<= 1;
        if r & (1 << 32) != 0 {
            r ^= (1 << 32) | poly as u64;
        }
        i += 1;
    }
    r as u32
}

/// A fold constant `x^n mod P`, bit reflected into the top 32 bits of a 64-bit lane.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const fn k(n: u32, poly: u32) -> u64 {
    (xpow_mod(n, poly).reverse_bits() as u64) << 32
}

/// Fold constants `[lo-lane multiplier, hi-lane multiplier]` for a distance of `m` 128-bit
/// blocks.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const fn fold(m: u32, poly: u32) -> [u64; 2] {
    [k(128 * m + 63, poly), k(128 * m - 1, poly)]
}

/// The constants for one polynomial: distances 4, 3, 2 and 1 blocks.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
struct Consts {
    k4: [u64; 2],
    k3: [u64; 2],
    k2: [u64; 2],
    k1: [u64; 2],
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const fn consts(poly: u32) -> Consts {
    Consts {
        k4: fold(4, poly),
        k3: fold(3, poly),
        k2: fold(2, poly),
        k1: fold(1, poly),
    }
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
static IEEE_K: Consts = consts(0x04c1_1db7);
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
static CASTAGNOLI_K: Consts = consts(0x1edc_6f41);

/// Inputs shorter than this stay on the table / `crc32` instruction path on x86_64.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const FOLD_MIN: usize = 64;

/// Updates the register state `crc` (already inverted) with `data` on CPU instructions, or
/// `None` when this CPU (or the portable switch) leaves it to the table. `table` finishes the
/// folded remainder where no instruction covers it.
#[inline]
pub(super) fn update(
    poly: Poly,
    crc: u32,
    data: &[u8],
    table: fn(u32, &[u8]) -> u32,
) -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        let crc32c = poly == Poly::Castagnoli && has(Feature::Crc) && cpu_has(Feature::Crc);
        if data.len() >= FOLD_MIN && has(Feature::Clmul) && cpu_has(Feature::Clmul) {
            let k = match poly {
                Poly::Ieee => &IEEE_K,
                Poly::Castagnoli => &CASTAGNOLI_K,
            };
            // SAFETY: `cpu_has` confirmed PCLMULQDQ, SSE2, SSSE3 and SSE4.1; `data` has at
            // least 64 bytes.
            let (rem, used) = unsafe { imp::fold(k, crc, data) };
            let tail = &data[used..];
            return Some(if crc32c {
                // SAFETY: `cpu_has` confirmed SSE4.2.
                unsafe { imp::crc32c(imp::crc32c(0, &rem), tail) }
            } else {
                table(table(0, &rem), tail)
            });
        }
        if crc32c {
            // SAFETY: `cpu_has` confirmed SSE4.2.
            return Some(unsafe { imp::crc32c(crc, data) });
        }
        let _ = table;
        None
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = table;
        if !has(Feature::Crc) || !crate::cpu::cpu_has(Feature::Crc) {
            return None;
        }
        // SAFETY: `cpu_has` confirmed the CRC32 instructions.
        Some(unsafe {
            match poly {
                Poly::Ieee => imp::crc32(crc, data),
                Poly::Castagnoli => imp::crc32c(crc, data),
            }
        })
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (poly, crc, data, table, has(Feature::Crc));
        None
    }
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::Consts;
    use std::arch::x86_64::*;

    /// # Safety
    ///
    /// Only called from functions compiled with the needed features, after detection; `p`
    /// points to 16 readable bytes.
    #[inline(always)]
    unsafe fn load(p: *const u8) -> __m128i {
        // SAFETY: the caller guarantees 16 readable bytes at `p` (unaligned load).
        unsafe { _mm_loadu_si128(p.cast()) }
    }

    /// `x` moved `k`'s distance forward: `x_lo·k[0] ⊕ x_hi·k[1]`.
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with PCLMULQDQ, after detection.
    #[inline(always)]
    unsafe fn fold_by(x: __m128i, k: __m128i) -> __m128i {
        // SAFETY: register-only intrinsics; the caller guarantees the feature.
        unsafe {
            _mm_xor_si128(
                _mm_clmulepi64_si128::<0x00>(x, k),
                _mm_clmulepi64_si128::<0x11>(x, k),
            )
        }
    }

    /// # Safety
    ///
    /// Only called from functions compiled with SSE2, after detection.
    #[inline(always)]
    unsafe fn kv(k: [u64; 2]) -> __m128i {
        // SAFETY: register-only intrinsic.
        unsafe { _mm_set_epi64x(k[1] as i64, k[0] as i64) }
    }

    /// Folds the longest prefix of `data` that is a multiple of 16 bytes (at least 64) into 16
    /// bytes with the same CRC from a zero state, the register state `crc` included. Returns them
    /// and the prefix length.
    ///
    /// # Safety
    ///
    /// The CPU must support PCLMULQDQ, SSE2, SSSE3 and SSE4.1; `data.len() >= 64`.
    #[target_feature(enable = "pclmulqdq,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn fold(k: &Consts, crc: u32, data: &[u8]) -> ([u8; 16], usize) {
        debug_assert!(data.len() >= 64);
        // SAFETY: the caller guarantees the features and 64 bytes; every load reads 16 bytes at
        // an offset `o` with `o + 16 <= data.len()` (the loops check it).
        unsafe {
            let p = data.as_ptr();
            let mut x = [
                _mm_xor_si128(load(p), _mm_cvtsi32_si128(crc as i32)),
                load(p.add(16)),
                load(p.add(32)),
                load(p.add(48)),
            ];
            let mut o = 64;
            let k4 = kv(k.k4);
            while o + 64 <= data.len() {
                for (i, x) in x.iter_mut().enumerate() {
                    *x = _mm_xor_si128(fold_by(*x, k4), load(p.add(o + 16 * i)));
                }
                o += 64;
            }
            let mut r = _mm_xor_si128(
                _mm_xor_si128(fold_by(x[0], kv(k.k3)), fold_by(x[1], kv(k.k2))),
                _mm_xor_si128(fold_by(x[2], kv(k.k1)), x[3]),
            );
            let k1 = kv(k.k1);
            while o + 16 <= data.len() {
                r = _mm_xor_si128(fold_by(r, k1), load(p.add(o)));
                o += 16;
            }
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr().cast(), r);
            (out, o)
        }
    }

    /// CRC-32C register update with the SSE4.2 `crc32` instruction.
    ///
    /// # Safety
    ///
    /// The CPU must support SSE4.2.
    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn crc32c(crc: u32, data: &[u8]) -> u32 {
        // SAFETY: the caller guarantees the feature; register-only intrinsics.
        unsafe {
            let mut c = u64::from(crc);
            let mut chunks = data.chunks_exact(8);
            for w in &mut chunks {
                c = _mm_crc32_u64(c, u64::from_le_bytes(w.try_into().unwrap_or_default()));
            }
            let mut c = c as u32;
            for &b in chunks.remainder() {
                c = _mm_crc32_u8(c, b);
            }
            c
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use std::arch::aarch64::*;

    /// CRC-32 register update with the CRC32 instructions.
    ///
    /// # Safety
    ///
    /// The CPU must support the `crc` feature.
    #[target_feature(enable = "crc")]
    pub(super) unsafe fn crc32(mut c: u32, data: &[u8]) -> u32 {
        // SAFETY: the caller guarantees the feature; register-only intrinsics.
        unsafe {
            let mut chunks = data.chunks_exact(8);
            for w in &mut chunks {
                c = __crc32d(c, u64::from_le_bytes(w.try_into().unwrap_or_default()));
            }
            for &b in chunks.remainder() {
                c = __crc32b(c, b);
            }
            c
        }
    }

    /// CRC-32C register update with the CRC32 instructions.
    ///
    /// # Safety
    ///
    /// The CPU must support the `crc` feature.
    #[target_feature(enable = "crc")]
    pub(super) unsafe fn crc32c(mut c: u32, data: &[u8]) -> u32 {
        // SAFETY: the caller guarantees the feature; register-only intrinsics.
        unsafe {
            let mut chunks = data.chunks_exact(8);
            for w in &mut chunks {
                c = __crc32cd(c, u64::from_le_bytes(w.try_into().unwrap_or_default()));
            }
            for &b in chunks.remainder() {
                c = __crc32cb(c, b);
            }
            c
        }
    }
}
