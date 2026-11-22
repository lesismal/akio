//! AES with the CPU's AES instructions: AES-NI on x86_64, the ARMv8 Cryptography Extension on
//! aarch64. Chosen at run time by [`Keys::new`] when the CPU has them; the instructions are
//! constant time, like the fixsliced fallback.
//!
//! The key schedule is the FIPS 197 one, with `SubWord` computed by the AES instruction itself
//! (a word replicated into all four columns is unaffected by `ShiftRows`), so no S-box table is
//! indexed with key material. Decryption uses the equivalent inverse cipher (round keys through
//! `InvMixColumns`).
//!
//! CTR mode runs eight blocks at a time so that the pipelined AES units stay busy.
//!
//! One of the crate's hardware modules (with `hash::hw`, `gcm::hw`, `crc::hw`, `chacha::hw`), the
//! only places with `unsafe`: calls to `#[target_feature]` functions and intrinsics, made only
//! after the feature was detected (docs/unsafe-review.md).
#![allow(unsafe_code)]
// The intrinsics are `unsafe fn` at the MSRV (1.85) and safe inside `#[target_feature]` functions
// on newer compilers.
#![allow(unused_unsafe)]

/// Round keys for the hardware path: encryption keys `enc[0..=rounds]` and the equivalent
/// inverse cipher's keys `dec[0..=rounds]`.
#[derive(Clone)]
pub(super) struct Keys {
    enc: [[u8; 16]; 15],
    dec: [[u8; 16]; 15],
    rounds: usize,
}

/// Whether this CPU has the AES instructions (the condition for every call into `imp`).
fn available() -> bool {
    crate::cpu::cpu_has(crate::cpu::Feature::Aes)
}

impl Keys {
    /// The schedule of a 16-, 24- or 32-byte key, or `None` without AES instructions.
    pub(super) fn new(key: &[u8]) -> Option<Keys> {
        if !crate::cpu::has(crate::cpu::Feature::Aes)
            || !available()
            || !matches!(key.len(), 16 | 24 | 32)
        {
            return None;
        }
        // SAFETY: `available()` confirmed the CPU features `imp` is compiled for.
        Some(unsafe { imp::schedule(key) })
    }

    /// The encryption round keys and the round count (for the fused AES-GCM kernel).
    pub(super) fn enc_keys(&self) -> (&[[u8; 16]; 15], usize) {
        (&self.enc, self.rounds)
    }

    pub(super) fn encrypt4(&self, b: &mut [[u8; 16]; 4]) {
        // SAFETY: a `Keys` exists only if `available()` returned true (see `new`).
        unsafe { imp::encrypt4(self, b) }
    }

    pub(super) fn decrypt4(&self, b: &mut [[u8; 16]; 4]) {
        // SAFETY: as in `encrypt4`.
        unsafe { imp::decrypt4(self, b) }
    }

    pub(super) fn encrypt1(&self, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe { imp::encrypt1(self, b) }
    }

    pub(super) fn decrypt1(&self, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe { imp::decrypt1(self, b) }
    }

    /// XORs `data` with the CTR keystream of the counter blocks `next()` returns, eight blocks
    /// per round trip through the pipeline.
    #[inline]
    pub(super) fn ctr(&self, data: &mut [u8], mut next: impl FnMut() -> [u8; 16]) {
        let mut chunks = data.chunks_exact_mut(128);
        for c in &mut chunks {
            let mut b = [[0u8; 16]; 8];
            for b in &mut b {
                *b = next();
            }
            let c: &mut [u8; 128] = c.try_into().unwrap_or_else(|_| unreachable!());
            self.ctr8_xor(&b, c);
        }
        let rest = chunks.into_remainder();
        if !rest.is_empty() {
            let mut b = [[0u8; 16]; 8];
            for b in b.iter_mut().take(rest.len().div_ceil(16)) {
                *b = next();
            }
            let mut ks = [0u8; 128];
            self.ctr8_xor(&b, &mut ks);
            for (d, k) in rest.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
    }

    /// Encrypts the eight blocks `ctr` and XORs them into `data` (the AES-GCM tail: the last
    /// counter blocks and `J0` in one pass through the pipeline).
    #[inline]
    pub(super) fn ctr8_xor(&self, ctr: &[[u8; 16]; 8], data: &mut [u8; 128]) {
        // SAFETY: a `Keys` exists only if `available()` returned true (see `new`).
        unsafe { imp::ctr8_xor(self, ctr, data) }
    }
}

/// The FIPS 197 key expansion, with `sub_word` and `inv_mix_columns` supplied by the platform.
fn expand(
    key: &[u8],
    sub_word: impl Fn(u32) -> u32,
    inv_mix: impl Fn([u8; 16]) -> [u8; 16],
) -> Keys {
    const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let nk = key.len() / 4;
    let rounds = nk + 6;
    let total = 4 * (rounds + 1);
    let mut w = [0u32; 60];
    for (w, k) in w.iter_mut().zip(key.chunks_exact(4)) {
        // Little-endian words: byte 0 of the FIPS word is the low byte.
        *w = u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
    }
    for i in nk..total {
        let mut t = w[i - 1];
        if i % nk == 0 {
            t = sub_word(t.rotate_right(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }
        w[i] = w[i - nk] ^ t;
    }
    let mut enc = [[0u8; 16]; 15];
    for (r, rk) in enc.iter_mut().enumerate().take(rounds + 1) {
        for j in 0..4 {
            rk[4 * j..4 * j + 4].copy_from_slice(&w[4 * r + j].to_le_bytes());
        }
    }
    let mut dec = [[0u8; 16]; 15];
    dec[0] = enc[rounds];
    for r in 1..rounds {
        dec[r] = inv_mix(enc[rounds - r]);
    }
    dec[rounds] = enc[0];
    Keys { enc, dec, rounds }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::{Keys, expand};
    use std::arch::aarch64::*;

    /// # Safety
    ///
    /// The CPU must support the `aes` feature.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn schedule(key: &[u8]) -> Keys {
        // SAFETY: the caller guarantees the `aes` feature (NEON is baseline on aarch64); every
        // pointer comes from a live 16-byte array.
        unsafe {
            expand(
                key,
                |w| {
                    // AESE with a zero key is SubBytes(ShiftRows(x)); a word in all four columns is
                    // unaffected by ShiftRows.
                    let v = vreinterpretq_u8_u32(vdupq_n_u32(w));
                    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(vaeseq_u8(v, vdupq_n_u8(0))))
                },
                |k| {
                    let mut out = [0u8; 16];
                    vst1q_u8(out.as_mut_ptr(), vaesimcq_u8(vld1q_u8(k.as_ptr())));
                    out
                },
            )
        }
    }

    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection.
    #[inline(always)]
    unsafe fn load(b: &[u8; 16]) -> uint8x16_t {
        // SAFETY: `b` is 16 readable bytes.
        unsafe { vld1q_u8(b.as_ptr()) }
    }

    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection.
    #[inline(always)]
    unsafe fn store(b: &mut [u8; 16], v: uint8x16_t) {
        // SAFETY: `b` is 16 writable bytes.
        unsafe { vst1q_u8(b.as_mut_ptr(), v) }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn encrypt4(k: &Keys, b: &mut [[u8; 16]; 4]) {
        // SAFETY: the caller guarantees the feature; loads and stores stay within the arrays.
        unsafe {
            let mut s = [load(&b[0]), load(&b[1]), load(&b[2]), load(&b[3])];
            for rk in &k.enc[..k.rounds - 1] {
                let rk = load(rk);
                for s in &mut s {
                    *s = vaesmcq_u8(vaeseq_u8(*s, rk));
                }
            }
            let a = load(&k.enc[k.rounds - 1]);
            let z = load(&k.enc[k.rounds]);
            for (s, out) in s.iter().zip(b.iter_mut()) {
                store(out, veorq_u8(vaeseq_u8(*s, a), z));
            }
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn decrypt4(k: &Keys, b: &mut [[u8; 16]; 4]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            let mut s = [load(&b[0]), load(&b[1]), load(&b[2]), load(&b[3])];
            for rk in &k.dec[..k.rounds - 1] {
                let rk = load(rk);
                for s in &mut s {
                    *s = vaesimcq_u8(vaesdq_u8(*s, rk));
                }
            }
            let a = load(&k.dec[k.rounds - 1]);
            let z = load(&k.dec[k.rounds]);
            for (s, out) in s.iter().zip(b.iter_mut()) {
                store(out, veorq_u8(vaesdq_u8(*s, a), z));
            }
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn encrypt1(k: &Keys, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            match k.rounds {
                10 => encrypt1_r::<10>(k, b),
                12 => encrypt1_r::<12>(k, b),
                _ => encrypt1_r::<14>(k, b),
            }
        }
    }

    /// `encrypt1` with the round count known at compile time (unrolled).
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection;
    /// `R == k.rounds`.
    #[inline(always)]
    unsafe fn encrypt1_r<const R: usize>(k: &Keys, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            let mut s = load(b);
            for rk in &k.enc[..R - 1] {
                s = vaesmcq_u8(vaeseq_u8(s, load(rk)));
            }
            s = vaeseq_u8(s, load(&k.enc[R - 1]));
            store(b, veorq_u8(s, load(&k.enc[R])));
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` feature.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn decrypt1(k: &Keys, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            let mut s = load(b);
            for rk in &k.dec[..k.rounds - 1] {
                s = vaesimcq_u8(vaesdq_u8(s, load(rk)));
            }
            s = vaesdq_u8(s, load(&k.dec[k.rounds - 1]));
            store(b, veorq_u8(s, load(&k.dec[k.rounds])));
        }
    }

    /// Encrypts the eight counter blocks `ctr` and XORs the keystream into `data`.
    ///
    /// # Safety
    ///
    /// The CPU must support the `aes` feature.
    #[target_feature(enable = "aes")]
    pub(super) unsafe fn ctr8_xor(k: &Keys, ctr: &[[u8; 16]; 8], data: &mut [u8; 128]) {
        // SAFETY: as in `ctr8_xor_r`.
        unsafe {
            match k.rounds {
                10 => ctr8_xor_r::<10>(k, ctr, data),
                12 => ctr8_xor_r::<12>(k, ctr, data),
                _ => ctr8_xor_r::<14>(k, ctr, data),
            }
        }
    }

    /// `ctr8_xor` with the round count known at compile time (unrolled).
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection;
    /// `R == k.rounds`.
    #[inline(always)]
    unsafe fn ctr8_xor_r<const R: usize>(k: &Keys, ctr: &[[u8; 16]; 8], data: &mut [u8; 128]) {
        // SAFETY: the caller guarantees the feature; every load and store is a whole 16-byte
        // array or a 16-byte chunk of `data`.
        unsafe {
            let mut s = [vdupq_n_u8(0); 8];
            for (s, c) in s.iter_mut().zip(ctr) {
                *s = load(c);
            }
            for rk in &k.enc[..R - 1] {
                let rk = load(rk);
                for s in &mut s {
                    *s = vaesmcq_u8(vaeseq_u8(*s, rk));
                }
            }
            let a = load(&k.enc[R - 1]);
            let z = load(&k.enc[R]);
            for (s, d) in s.iter().zip(data.chunks_exact_mut(16)) {
                let p = d.as_mut_ptr();
                let v = veorq_u8(veorq_u8(vaeseq_u8(*s, a), z), vld1q_u8(p));
                vst1q_u8(p, v);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::{Keys, expand};
    use std::arch::x86_64::*;

    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection.
    #[inline(always)]
    unsafe fn load(b: &[u8; 16]) -> __m128i {
        // SAFETY: `b` is 16 readable bytes; the load is unaligned.
        unsafe { _mm_loadu_si128(b.as_ptr().cast()) }
    }

    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection.
    #[inline(always)]
    unsafe fn store(b: &mut [u8; 16], v: __m128i) {
        // SAFETY: `b` is 16 writable bytes; the store is unaligned.
        unsafe { _mm_storeu_si128(b.as_mut_ptr().cast(), v) }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` and `sse2` features.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn schedule(key: &[u8]) -> Keys {
        // SAFETY: the caller guarantees the features; every pointer comes from a live 16-byte
        // array.
        unsafe {
            expand(
                key,
                |w| {
                    // AESENCLAST with a zero key is SubBytes(ShiftRows(x)); a word in all four
                    // columns is unaffected by ShiftRows.
                    let v = _mm_set1_epi32(w as i32);
                    _mm_cvtsi128_si32(_mm_aesenclast_si128(v, _mm_setzero_si128())) as u32
                },
                |k| {
                    let mut out = [0u8; 16];
                    store(&mut out, _mm_aesimc_si128(load(&k)));
                    out
                },
            )
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` and `sse2` features.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn encrypt4(k: &Keys, b: &mut [[u8; 16]; 4]) {
        // SAFETY: the caller guarantees the features; loads and stores stay within the arrays.
        unsafe {
            let k0 = load(&k.enc[0]);
            let mut s = [
                _mm_xor_si128(load(&b[0]), k0),
                _mm_xor_si128(load(&b[1]), k0),
                _mm_xor_si128(load(&b[2]), k0),
                _mm_xor_si128(load(&b[3]), k0),
            ];
            for rk in &k.enc[1..k.rounds] {
                let rk = load(rk);
                for s in &mut s {
                    *s = _mm_aesenc_si128(*s, rk);
                }
            }
            let z = load(&k.enc[k.rounds]);
            for (s, out) in s.iter().zip(b.iter_mut()) {
                store(out, _mm_aesenclast_si128(*s, z));
            }
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` and `sse2` features.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn decrypt4(k: &Keys, b: &mut [[u8; 16]; 4]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            let k0 = load(&k.dec[0]);
            let mut s = [
                _mm_xor_si128(load(&b[0]), k0),
                _mm_xor_si128(load(&b[1]), k0),
                _mm_xor_si128(load(&b[2]), k0),
                _mm_xor_si128(load(&b[3]), k0),
            ];
            for rk in &k.dec[1..k.rounds] {
                let rk = load(rk);
                for s in &mut s {
                    *s = _mm_aesdec_si128(*s, rk);
                }
            }
            let z = load(&k.dec[k.rounds]);
            for (s, out) in s.iter().zip(b.iter_mut()) {
                store(out, _mm_aesdeclast_si128(*s, z));
            }
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` and `sse2` features.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn encrypt1(k: &Keys, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            match k.rounds {
                10 => encrypt1_r::<10>(k, b),
                12 => encrypt1_r::<12>(k, b),
                _ => encrypt1_r::<14>(k, b),
            }
        }
    }

    /// `encrypt1` with the round count known at compile time (unrolled).
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection;
    /// `R == k.rounds`.
    #[inline(always)]
    unsafe fn encrypt1_r<const R: usize>(k: &Keys, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            let mut s = _mm_xor_si128(load(b), load(&k.enc[0]));
            for rk in &k.enc[1..R] {
                s = _mm_aesenc_si128(s, load(rk));
            }
            store(b, _mm_aesenclast_si128(s, load(&k.enc[R])));
        }
    }

    /// # Safety
    ///
    /// The CPU must support the `aes` and `sse2` features.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn decrypt1(k: &Keys, b: &mut [u8; 16]) {
        // SAFETY: as in `encrypt4`.
        unsafe {
            let mut s = _mm_xor_si128(load(b), load(&k.dec[0]));
            for rk in &k.dec[1..k.rounds] {
                s = _mm_aesdec_si128(s, load(rk));
            }
            store(b, _mm_aesdeclast_si128(s, load(&k.dec[k.rounds])));
        }
    }

    /// Encrypts the eight counter blocks `ctr` and XORs the keystream into `data`.
    ///
    /// # Safety
    ///
    /// The CPU must support the `aes` and `sse2` features.
    #[target_feature(enable = "aes,sse2")]
    pub(super) unsafe fn ctr8_xor(k: &Keys, ctr: &[[u8; 16]; 8], data: &mut [u8; 128]) {
        // SAFETY: as in `ctr8_xor_r`.
        unsafe {
            match k.rounds {
                10 => ctr8_xor_r::<10>(k, ctr, data),
                12 => ctr8_xor_r::<12>(k, ctr, data),
                _ => ctr8_xor_r::<14>(k, ctr, data),
            }
        }
    }

    /// `ctr8_xor` with the round count known at compile time (unrolled).
    ///
    /// # Safety
    ///
    /// Only called from functions compiled with the AES feature, after detection;
    /// `R == k.rounds`.
    #[inline(always)]
    unsafe fn ctr8_xor_r<const R: usize>(k: &Keys, ctr: &[[u8; 16]; 8], data: &mut [u8; 128]) {
        // SAFETY: the caller guarantees the features; every load and store is a whole 16-byte
        // array or a 16-byte chunk of `data` (unaligned accesses).
        unsafe {
            let k0 = load(&k.enc[0]);
            let mut s = [k0; 8];
            for (s, c) in s.iter_mut().zip(ctr) {
                *s = _mm_xor_si128(load(c), k0);
            }
            for rk in &k.enc[1..R] {
                let rk = load(rk);
                for s in &mut s {
                    *s = _mm_aesenc_si128(*s, rk);
                }
            }
            let z = load(&k.enc[R]);
            for (s, d) in s.iter().zip(data.chunks_exact_mut(16)) {
                let p = d.as_mut_ptr().cast::<__m128i>();
                let v = _mm_xor_si128(_mm_aesenclast_si128(*s, z), _mm_loadu_si128(p));
                _mm_storeu_si128(p, v);
            }
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod imp {
    use super::Keys;

    /// # Safety
    ///
    /// Never called: `available()` is false on this architecture.
    pub(super) unsafe fn schedule(_: &[u8]) -> Keys {
        unreachable!("no AES instructions on this architecture")
    }
    /// # Safety
    ///
    /// Never called (no `Keys` can exist).
    pub(super) unsafe fn encrypt4(_: &Keys, _: &mut [[u8; 16]; 4]) {}
    /// # Safety
    ///
    /// Never called (no `Keys` can exist).
    pub(super) unsafe fn decrypt4(_: &Keys, _: &mut [[u8; 16]; 4]) {}
    /// # Safety
    ///
    /// Never called (no `Keys` can exist).
    pub(super) unsafe fn encrypt1(_: &Keys, _: &mut [u8; 16]) {}
    /// # Safety
    ///
    /// Never called (no `Keys` can exist).
    pub(super) unsafe fn decrypt1(_: &Keys, _: &mut [u8; 16]) {}
    /// # Safety
    ///
    /// Never called (no `Keys` can exist).
    pub(super) unsafe fn ctr8_xor(_: &Keys, _: &[[u8; 16]; 8], _: &mut [u8; 128]) {}
}
