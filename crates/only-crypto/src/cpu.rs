//! Run-time CPU feature detection for the hardware paths (`aes::hw`, `hash::hw`, `gcm::hw`,
//! `crc::hw`, `chacha::hw`, `ec::hw`), detected once and cached.
//!
//! A feature reported here is one the CPU has *and* that has not been switched off: the
//! environment variable `ONLY_CRYPTO_PORTABLE` (set to anything but `0` or the empty string when
//! the first primitive is used) or [`set_portable`] force the portable implementations, for
//! tests and benchmarks. Switching off never makes a hardware path reachable on a CPU without the
//! instructions: the hardware modules check the real detection result before every `unsafe`
//! call (key schedules made while the hardware path was enabled keep using it). Under Miri
//! nothing is detected, so `cargo miri test` runs the portable code (and never the `asm!` of the
//! wide AES-GCM kernel).
//!
//! VAES, VPCLMULQDQ, AVX-512 (and its IFMA extension), BMI2 and ADX are read from CPUID (and XCR0 for the vector state)
//! directly (`hw`), independent of the feature names `is_x86_feature_detected!` accepts at the
//! MSRV.

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
    /// Vector AES and carry-less multiplication: VAES and VPCLMULQDQ with AVX2 and the OS
    /// saving the YMM state (x86_64, read from CPUID and XCR0).
    Vaes = 1 << 5,
    /// AVX-512 F, BW and VL with the OS saving the opmask and ZMM state (x86_64, read from
    /// CPUID and XCR0).
    Avx512 = 1 << 6,
    /// Wide multiplication with two independent carry chains: BMI2 `mulx` and ADX
    /// `adcx`/`adox` (x86_64, read from CPUID).
    Adx = 1 << 7,
    /// 52-bit integer multiply-add: AVX-512 IFMA with [`Avx512`](Feature::Avx512) (x86_64, read
    /// from CPUID).
    Ifma = 1 << 8,
}

/// CPUID and XCR0, for the features `is_x86_feature_detected!` cannot name at the MSRV (VAES,
/// VPCLMULQDQ, AVX-512) and for BMI2 + ADX (read the same way, so every leaf-7 feature has one
/// source): the one `unsafe` of this file.
#[cfg(all(target_arch = "x86_64", not(miri)))]
// `__cpuid_count` is an `unsafe fn` at the MSRV (1.85) and safe on newer compilers.
#[allow(unsafe_code, unused_unsafe)]
mod hw {
    use std::arch::x86_64::{__cpuid_count, _xgetbv};

    /// The leaf-7 features as defined by `super::Feature`.
    pub(super) struct Leaf7 {
        pub(super) vaes: bool,
        pub(super) avx512: bool,
        pub(super) adx: bool,
        pub(super) ifma: bool,
    }

    /// `Vaes`, `Avx512`, `Adx` and `Ifma` as defined by `super::Feature`.
    pub(super) fn leaf7() -> Leaf7 {
        let none = Leaf7 {
            vaes: false,
            avx512: false,
            adx: false,
            ifma: false,
        };
        // SAFETY: CPUID exists on every x86_64 CPU; leaf 0 reports the highest leaf.
        let max = unsafe { __cpuid_count(0, 0) }.eax;
        if max < 7 {
            return none;
        }
        // SAFETY: leaf 7 is within `max`.
        let l7 = unsafe { __cpuid_count(7, 0) };
        // BMI2 (`mulx`) and ADX (`adcx`/`adox`) are general-purpose instructions: no OS state.
        let adx = l7.ebx & (1 << 8) != 0 && l7.ebx & (1 << 19) != 0;
        // SAFETY: as above, leaf 1 is within `max`.
        let l1 = unsafe { __cpuid_count(1, 0) };
        // OSXSAVE: the OS enabled XSAVE, so XGETBV is available and XCR0 tells which register
        // state the OS saves.
        if l1.ecx & (1 << 27) == 0 {
            return Leaf7 { adx, ..none };
        }
        // SAFETY: OSXSAVE is set, so XGETBV with XCR0 (index 0) does not fault.
        let xcr0 = unsafe { xcr0() };
        let avx = l1.ecx & (1 << 28) != 0;
        let ymm_os = xcr0 & 0x6 == 0x6;
        let zmm_os = xcr0 & 0xe6 == 0xe6;
        let avx2 = l7.ebx & (1 << 5) != 0;
        let vaes = l7.ecx & (1 << 9) != 0;
        let vpclmulqdq = l7.ecx & (1 << 10) != 0;
        let avx512 = l7.ebx & (1 << 16) != 0 && l7.ebx & (1 << 30) != 0 && l7.ebx & (1 << 31) != 0;
        let v = avx && ymm_os && avx2 && vaes && vpclmulqdq;
        let ifma = l7.ebx & (1 << 21) != 0;
        Leaf7 {
            vaes: v,
            avx512: v && zmm_os && avx512,
            adx,
            ifma: v && zmm_os && avx512 && ifma,
        }
    }

    /// # Safety
    ///
    /// The CPU must support XSAVE and the OS must have enabled it (CPUID.1:ECX.OSXSAVE).
    #[target_feature(enable = "xsave")]
    unsafe fn xcr0() -> u64 {
        // SAFETY: the caller guarantees OSXSAVE; XCR0 always exists then.
        unsafe { _xgetbv(0) }
    }
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
fn detect() -> u32 {
    use std::arch::is_x86_feature_detected as has;
    let mut f = 0;
    let l7 = hw::leaf7();
    if l7.vaes {
        f |= Feature::Vaes as u32;
    }
    if l7.avx512 {
        f |= Feature::Avx512 as u32;
    }
    if l7.adx {
        f |= Feature::Adx as u32;
    }
    if l7.ifma {
        f |= Feature::Ifma as u32;
    }
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
/// `"aes clmul sha crc avx2 vaes avx512 adx ifma"`; empty when everything is portable).
#[doc(hidden)]
#[must_use]
pub fn hardware_features() -> String {
    let names = [
        (Feature::Aes, "aes"),
        (Feature::Clmul, "clmul"),
        (Feature::Sha, "sha"),
        (Feature::Crc, "crc"),
        (Feature::Avx2, "avx2"),
        (Feature::Vaes, "vaes"),
        (Feature::Avx512, "avx512"),
        (Feature::Adx, "adx"),
        (Feature::Ifma, "ifma"),
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
