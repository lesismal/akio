//! Run-time CPU feature detection for the hardware paths (`aes::hw`, `hash::hw`, `gcm::hw`,
//! `crc::hw`, `chacha::hw`), detected once and cached.
//!
//! A feature reported here is one the CPU has *and* that has not been switched off: the
//! environment variable `ONLY_CRYPTO_PORTABLE` (set to anything but `0` or the empty string when
//! the first primitive is used) or [`set_portable`] force the portable implementations, for
//! tests and benchmarks. Switching off never makes a hardware path reachable on a CPU without the
//! instructions: the hardware modules check the real detection result before every `unsafe`
//! call (key schedules made while the hardware path was enabled keep using it). Under Miri
//! nothing is detected, so `cargo miri test` runs the portable code.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Bit set of detected features; `INIT` marks a filled cache.
static DETECTED: AtomicU32 = AtomicU32::new(0);
/// Hardware paths switched off ([`set_portable`] or the environment variable).
static PORTABLE: AtomicBool = AtomicBool::new(false);

const INIT: u32 = 1 << 31;

/// A CPU feature some hardware path needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum Feature {
    /// AES rounds: AES-NI (x86_64), the ARMv8 AES instructions (aarch64).
    Aes = 1 << 0,
    /// Carry-less multiplication: PCLMULQDQ (x86_64, with SSSE3 for byte shuffles), PMULL
    /// (aarch64, part of the AES extension).
    Clmul = 1 << 1,
    /// SHA-1 and SHA-256 rounds: SHA-NI (x86_64, with SSSE3 and SSE4.1), the ARMv8 SHA1/SHA2
    /// instructions (aarch64).
    Sha = 1 << 2,
    /// CRC-32C (x86_64 SSE4.2 `crc32`) or CRC-32 and CRC-32C (aarch64 CRC32 instructions).
    Crc = 1 << 3,
    /// 256-bit integer vectors: AVX2 (x86_64).
    Avx2 = 1 << 4,
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
fn detect() -> u32 {
    use std::arch::is_x86_feature_detected as has;
    let mut f = 0;
    if has!("aes") && has!("sse2") {
        f |= Feature::Aes as u32;
    }
    if has!("pclmulqdq") && has!("ssse3") && has!("sse4.1") {
        f |= Feature::Clmul as u32;
    }
    if has!("sha") && has!("ssse3") && has!("sse4.1") {
        f |= Feature::Sha as u32;
    }
    if has!("sse4.2") {
        f |= Feature::Crc as u32;
    }
    if has!("avx2") {
        f |= Feature::Avx2 as u32;
    }
    f
}

#[cfg(all(target_arch = "aarch64", not(miri)))]
fn detect() -> u32 {
    use std::arch::is_aarch64_feature_detected as has;
    let mut f = 0;
    if has!("aes") {
        f |= Feature::Aes as u32 | Feature::Clmul as u32;
    }
    if has!("sha2") {
        f |= Feature::Sha as u32;
    }
    if has!("crc") {
        f |= Feature::Crc as u32;
    }
    f
}

/// Other architectures, and Miri (which does not interpret the SIMD intrinsics): portable code
/// only.
#[cfg(any(miri, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn detect() -> u32 {
    0
}

/// The detected feature bits (ignoring the portable switch).
#[inline]
fn detected() -> u32 {
    let d = DETECTED.load(Ordering::Relaxed);
    if d & INIT != 0 {
        return d;
    }
    init()
}

#[cold]
fn init() -> u32 {
    let forced =
        std::env::var_os("ONLY_CRYPTO_PORTABLE").is_some_and(|v| !v.is_empty() && v != "0");
    if forced {
        PORTABLE.store(true, Ordering::Relaxed);
    }
    let d = detect() | INIT;
    DETECTED.store(d, Ordering::Relaxed);
    d
}

/// Whether the CPU has `f`, regardless of the portable switch: the condition checked before
/// every call into a hardware module.
#[inline]
pub(crate) fn cpu_has(f: Feature) -> bool {
    detected() & f as u32 != 0
}

/// Whether to use the hardware path for `f`: the CPU has it and the portable implementations are
/// not forced.
#[inline]
pub(crate) fn has(f: Feature) -> bool {
    let d = detected();
    d & f as u32 != 0 && !PORTABLE.load(Ordering::Relaxed)
}

/// Forces (`true`) or stops forcing (`false`) the portable implementations for everything created
/// or called afterwards, as the environment variable `ONLY_CRYPTO_PORTABLE=1` does at start-up.
/// For tests and benchmarks; existing AES / AES-GCM keys keep the path they were made with.
#[doc(hidden)]
pub fn set_portable(portable: bool) {
    let _ = detected();
    PORTABLE.store(portable, Ordering::Relaxed);
}

/// Whether the portable implementations are forced ([`set_portable`] or `ONLY_CRYPTO_PORTABLE`).
#[doc(hidden)]
#[must_use]
pub fn is_portable() -> bool {
    let _ = detected();
    PORTABLE.load(Ordering::Relaxed)
}

/// The hardware paths this CPU uses now, for diagnostics and benchmark labels (for example
/// `"aes clmul sha crc avx2"`; empty when everything is portable).
#[doc(hidden)]
#[must_use]
pub fn hardware_features() -> String {
    let names = [
        (Feature::Aes, "aes"),
        (Feature::Clmul, "clmul"),
        (Feature::Sha, "sha"),
        (Feature::Crc, "crc"),
        (Feature::Avx2, "avx2"),
    ];
    names
        .iter()
        .filter(|(f, _)| has(*f))
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn report() {
        println!("hardware: [{}]", super::hardware_features());
        println!("portable forced: {}", super::is_portable());
    }
}
