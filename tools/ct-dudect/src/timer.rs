//! The cycle counter read around each measured call: `rdtsc` fenced by `lfence` on x86_64, the
//! virtual counter `cntvct_el0` after an `isb` on aarch64, else [`std::time::Instant`] in
//! nanoseconds. The only `unsafe` of this crate (two `asm!` reads of a counter register).
//!
//! `rdtsc` counts at a constant rate on every CPU this runs on in CI and on the bench host (an
//! invariant TSC: reference cycles, not core clock cycles); `cntvct_el0` counts at the generic
//! timer's frequency (24 MHz on Apple silicon, 25 MHz to 1 GHz on Linux servers), so on aarch64
//! one measurement is coarse and a difference shows only as a shift of the tick distribution
//! over many measurements.

/// What [`now`] reads, for the report.
pub(crate) const NAME: &str = if cfg!(target_arch = "x86_64") {
    "rdtsc"
} else if cfg!(target_arch = "aarch64") {
    "cntvct_el0"
} else {
    "Instant (ns)"
};

/// The current counter value.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[inline(always)]
pub(crate) fn now() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `lfence` and `rdtsc` exist on every x86_64 CPU (SSE2 is baseline) and only write
    // the declared output registers (`eax`, `edx`); no memory is touched and the stack is not
    // used. The fences keep the read from moving before earlier or after later instructions.
    unsafe {
        std::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// The current counter value.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline(always)]
pub(crate) fn now() -> u64 {
    let v: u64;
    // SAFETY: `cntvct_el0` is readable from EL0 on Linux and macOS (the kernels enable
    // CNTKCTL_EL1.EL0VCTEN); `isb` orders the read after the preceding instructions. Only the
    // declared output register is written; no memory, no stack.
    unsafe {
        std::arch::asm!(
            "isb",
            "mrs {v}, cntvct_el0",
            v = out(reg) v,
            options(nostack, preserves_flags),
        );
    }
    v
}

/// The current counter value (nanoseconds since the first call).
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub(crate) fn now() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #[test]
    fn advances() {
        let a = super::now();
        let mut x = 0u64;
        for i in 0..1_000_000u64 {
            x = std::hint::black_box(x.wrapping_add(i));
        }
        let b = super::now();
        assert!(b > a, "{} {a} {b} {x}", super::NAME);
    }
}
