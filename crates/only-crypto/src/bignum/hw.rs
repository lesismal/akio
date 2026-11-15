//! Montgomery multiplication and squaring for RSA on x86_64 with BMI2 (`mulx`) and ADX
//! (`adcx`/`adox`), in inline assembly, for the even limb counts of [`super::Mont`]'s fixed
//! sizes (16, 24, 32, 48 and 64 limbs: 2048- to 4096-bit moduli and their CRT halves).
//!
//! Each operation is one `asm!` block in three phases over a `2N`-limb scratch buffer `t`:
//!
//! 1. the product: `a·b` row by row (operand scanning), or for squaring the cross products
//!    `a[i]·a[j]` (`i < j`) once, then doubled with the squares `a[i]²` added in one pass;
//! 2. the Montgomery reduction: `N` rows of `t += (t[i]·n0 mod 2⁶⁴)·m·2⁶⁴ⁱ`, the carry out of
//!    each row added into `t[i + N]` with a running top bit;
//! 3. the final conditional subtraction of `m`, selected with `cmovnz` on a mask.
//!
//! Every product row is two carry chains at once: `mulx` leaves the flags alone, `adcx` adds the
//! low halves (and the row being accumulated) on the carry flag and `adox` the high halves of the
//! previous column on the overflow flag. The rows are unrolled with the assembler's `.rept`
//! (`.set` symbols give the displacements); the loops over rows count with `dec`/`jnz` between
//! rows, where both chains have been flushed.
//!
//! Constant time: no branch and no memory address depends on the values; the only branches
//! are the two row-loop counters (the limb count is public). The final selection is `cmovnz`
//! from a mask made with `sbb`. (`black_box` is not needed: the compiler cannot rewrite the
//! assembly.)
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the `asm!`
//! blocks, which read the `N`-limb arrays behind `a`, `b` and `m`, write the `N`-limb output and
//! the `2N`-limb scratch buffer (a local), and nothing else. Their instructions need BMI2 and
//! ADX: they are reached only from `Mont::mul_into` / `Mont::sqr_into` after
//! [`enabled`] (`cpu::has(Feature::Adx)`), and every function here debug-asserts it.
#![allow(unsafe_code)]

use std::arch::asm;
use std::arch::x86_64::{
    __m256i, _mm256_and_si256, _mm256_cmpeq_epi64, _mm256_loadu_si256, _mm256_or_si256,
    _mm256_set1_epi64x, _mm256_setzero_si256, _mm256_storeu_si256,
};
use std::mem::MaybeUninit;

use crate::cpu::{self, Feature};

/// Whether to use this module: the CPU has BMI2 and ADX, and the portable code is not forced.
#[inline]
pub(crate) fn enabled() -> bool {
    cpu::has(Feature::Adx)
}

/// Whether [`lookup`] may run: the CPU has AVX2, and the portable code is not forced.
#[inline]
pub(crate) fn avx2_enabled() -> bool {
    cpu::has(Feature::Avx2)
}

/// `out = table[idx]` for a table of `k`-limb entries (`k` a multiple of 4, `out` at least `k`
/// limbs), reading every entry: AVX2 `vpcmpeqq` masks, no branch or address that depends on
/// `idx`. Callers check [`avx2_enabled`] first.
pub(crate) fn lookup(out: &mut [u64], table: &[u64], k: usize, idx: u64) {
    assert!(k % 4 == 0 && out.len() >= k && cpu::cpu_has(Feature::Avx2));
    // SAFETY: the CPU has AVX2 (asserted above).
    unsafe { lookup_avx2(out, table, k, idx) }
}

/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
// The intrinsics are `unsafe fn`s at the MSRV (1.85) and safe inside `avx2` code on newer
// compilers.
#[allow(unused_unsafe)]
unsafe fn lookup_avx2(out: &mut [u64], table: &[u64], k: usize, idx: u64) {
    // SAFETY: AVX2 (the caller's contract); register-only intrinsics plus unaligned 32-byte
    // loads from 4-limb chunks of live table entries and stores into 4-limb chunks of `out`.
    unsafe {
        let idx = _mm256_set1_epi64x(idx as i64);
        // Blocks of up to 16 limbs (four accumulators), each scanned over all entries.
        for base in (0..k).step_by(16) {
            let width = (k - base).min(16);
            let mut acc = [_mm256_setzero_si256(); 4];
            for (j, entry) in table.chunks_exact(k).enumerate() {
                let m = _mm256_cmpeq_epi64(_mm256_set1_epi64x(j as i64), idx);
                for (a, c) in acc
                    .iter_mut()
                    .zip(entry[base..base + width].chunks_exact(4))
                {
                    let v = _mm256_loadu_si256(c.as_ptr().cast::<__m256i>());
                    *a = _mm256_or_si256(*a, _mm256_and_si256(m, v));
                }
            }
            for (a, o) in acc.iter().zip(out[base..base + width].chunks_exact_mut(4)) {
                _mm256_storeu_si256(o.as_mut_ptr().cast::<__m256i>(), *a);
            }
        }
    }
}

/// One row `t[0..N] += rdx · v[0..N]`, the carry out (a full limb) stored to `t[N]`, which the
/// caller has not written yet. `t` and `v` are register operands; clobbers `rax`, `r8`–`r11`
/// and the flags.
macro_rules! row_add {
    ($v:literal) => {
        concat!(
            "xor r9d, r9d\n",
            ".set only_oj, 0\n",
            ".rept {half}\n",
            "mulx r11, r10, qword ptr [",
            $v,
            " + only_oj]\n",
            "adcx r10, qword ptr [{t} + only_oj]\n",
            "adox r10, r9\n",
            "mov qword ptr [{t} + only_oj], r10\n",
            "mulx r9, r8, qword ptr [",
            $v,
            " + only_oj + 8]\n",
            "adcx r8, qword ptr [{t} + only_oj + 8]\n",
            "adox r8, r11\n",
            "mov qword ptr [{t} + only_oj + 8], r8\n",
            ".set only_oj, only_oj + 16\n",
            ".endr\n",
            "mov eax, 0\n",
            "adcx r9, rax\n",
            "adox r9, rax\n",
        )
    };
}

/// The Montgomery reduction of the `2N`-limb `t` (at `{t}`, moved past the low half) and the
/// final subtraction into `{out}`. `$top` is a free register (the running top bit: 0 or all
/// ones; the caller passes the dead `{a}` pointer), `$q` another one (the next row's factor),
/// `rcx` the row counter.
macro_rules! redc_final {
    ($top:literal, $top32:literal, $q:literal) => {
        concat!(
            "xor ",
            $top32,
            ", ",
            $top32,
            "\n",
            "mov ecx, {n}\n",
            "mov ",
            $q,
            ", qword ptr [{t}]\n",
            "imul ",
            $q,
            ", {n0}\n",
            "3:\n",
            // Row i: t += q·m·2^(64i) with q = t[i]·n0, from the previous row's limb i (kept in
            // a register: no round trip through memory on the critical path).
            "mov rdx, ",
            $q,
            "\n",
            "xor r9d, r9d\n",
            "mulx r11, r10, qword ptr [{m}]\n",
            "adcx r10, qword ptr [{t}]\n",
            "adox r10, r9\n",
            "mulx r9, r8, qword ptr [{m} + 8]\n",
            "adcx r8, qword ptr [{t} + 8]\n",
            "adox r8, r11\n",
            "mov qword ptr [{t} + 8], r8\n",
            "mov ",
            $q,
            ", r8\n",
            ".set only_oj, 16\n",
            ".rept {half} - 1\n",
            "mulx r11, r10, qword ptr [{m} + only_oj]\n",
            "adcx r10, qword ptr [{t} + only_oj]\n",
            "adox r10, r9\n",
            "mov qword ptr [{t} + only_oj], r10\n",
            "mulx r9, r8, qword ptr [{m} + only_oj + 8]\n",
            "adcx r8, qword ptr [{t} + only_oj + 8]\n",
            "adox r8, r11\n",
            "mov qword ptr [{t} + only_oj + 8], r8\n",
            ".set only_oj, only_oj + 16\n",
            ".endr\n",
            "mov eax, 0\n",
            "adcx r9, rax\n",
            "adox r9, rax\n",
            // `imul` changes the flags: after the chains. Out of order, it still runs as soon
            // as limb i + 1 is known.
            "imul ",
            $q,
            ", {n0}\n",
            // t[i + N] += carry word + top bit; the carry out becomes the next top bit.
            "neg ",
            $top,
            "\n",
            "adc r9, qword ptr [{t} + only_oj]\n",
            "mov qword ptr [{t} + only_oj], r9\n",
            "sbb ",
            $top,
            ", ",
            $top,
            "\n",
            "lea {t}, [{t} + 8]\n",
            "dec ecx\n",
            "jnz 3b\n",
            // {t} is the high half now: out = t - m, kept unless it borrowed and the top bit
            // is clear.
            "mov rax, qword ptr [{t}]\n",
            "sub rax, qword ptr [{m}]\n",
            "mov qword ptr [{out}], rax\n",
            ".set only_oj, 8\n",
            ".rept {n} - 1\n",
            "mov rax, qword ptr [{t} + only_oj]\n",
            "sbb rax, qword ptr [{m} + only_oj]\n",
            "mov qword ptr [{out} + only_oj], rax\n",
            ".set only_oj, only_oj + 8\n",
            ".endr\n",
            "sbb rax, rax\n",
            "not ",
            $top,
            "\n",
            "and rax, ",
            $top,
            "\n",
            "test rax, rax\n",
            ".set only_oj, 0\n",
            ".rept {n}\n",
            "mov rcx, qword ptr [{out} + only_oj]\n",
            "cmovnz rcx, qword ptr [{t} + only_oj]\n",
            "mov qword ptr [{out} + only_oj], rcx\n",
            ".set only_oj, only_oj + 8\n",
            ".endr\n",
        )
    };
}

/// `out = a·b·2^(-64N) mod m`, fully reduced, for `a·b < m·2^(64N)` (any `a < 2^(64N)` with
/// `b < m`); `n0 = -m⁻¹ mod 2⁶⁴`. `W` must be `2N`, `N` even and at least 4.
#[inline]
pub(crate) fn mont_mul<const N: usize, const W: usize>(
    out: &mut [u64; N],
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    n0: u64,
) {
    const { assert!(W == 2 * N && N % 2 == 0 && N >= 4) };
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let mut t = MaybeUninit::<[u64; W]>::uninit();
    // SAFETY: reads the N limbs behind `a`, `b` and `m` (live arrays), writes the N limbs behind
    // `out` (an exclusive borrow, so it aliases none of the inputs) and the 2N limbs of the
    // local scratch `t`, each limb of which is written before it is read (row 0 stores
    // t[0..=N], row i reads t[i..i+N] and stores t[i+N]); every displacement is below 8·2N.
    // No stack use; `rbx`/`rbp` untouched. `mulx`, `adcx` and `adox` need BMI2 and ADX: this
    // is reached only after `enabled()` (asserted in debug builds above).
    unsafe {
        asm!(
            // Row 0: t[0..=N] = a·b[0], one carry chain.
            "mov rdx, qword ptr [{b}]",
            "xor r9d, r9d",
            ".set only_oj, 0",
            ".rept {half}",
            "mulx r11, r10, qword ptr [{a} + only_oj]",
            "adcx r10, r9",
            "mov qword ptr [{t} + only_oj], r10",
            "mulx r9, r8, qword ptr [{a} + only_oj + 8]",
            "adcx r8, r11",
            "mov qword ptr [{t} + only_oj + 8], r8",
            ".set only_oj, only_oj + 16",
            ".endr",
            "mov eax, 0",
            "adcx r9, rax",
            "mov qword ptr [{t} + only_oj], r9",
            // Rows 1..N: t[i..=i+N] += a·b[i].
            "mov ecx, {n} - 1",
            "2:",
            "lea {b}, [{b} + 8]",
            "lea {t}, [{t} + 8]",
            "mov rdx, qword ptr [{b}]",
            row_add!("{a}"),
            "mov qword ptr [{t} + only_oj], r9",
            "dec ecx",
            "jnz 2b",
            "sub {t}, 8 * ({n} - 1)",
            redc_final!("{a}", "{a:e}", "{b}"),
            a = inout(reg) a.as_ptr() => _,
            b = inout(reg) b.as_ptr() => _,
            t = inout(reg) t.as_mut_ptr().cast::<u64>() => _,
            m = in(reg) m.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            n0 = in(reg) n0,
            n = const N,
            half = const N / 2,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack),
        );
    }
}

/// `out = a²·2^(-64N) mod m`, fully reduced, for `a < m`; `n0 = -m⁻¹ mod 2⁶⁴`. `W` must be
/// `2N`, `N` even and at least 4. The cross products are unrolled completely (`N(N-1)/2`
/// of them), so [`super::Mont`] uses this up to 32 limbs and [`mont_mul`] above that.
#[inline]
pub(crate) fn mont_sqr<const N: usize, const W: usize>(
    out: &mut [u64; N],
    a: &[u64; N],
    m: &[u64; N],
    n0: u64,
) {
    const { assert!(W == 2 * N && N % 2 == 0 && N >= 4) };
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let mut t = MaybeUninit::<[u64; W]>::uninit();
    // SAFETY: reads the N limbs behind `a` and `m` (live arrays), writes the N limbs behind
    // `out` (an exclusive borrow) and the 2N limbs of the local scratch `t`, zeroed first;
    // every displacement is below 8·2N. No stack use; `rbx`/`rbp` untouched. BMI2 and ADX as
    // for `mont_mul`: reached only after `enabled()` (asserted in debug builds above).
    unsafe {
        asm!(
            // t = 0.
            "xor eax, eax",
            ".set only_oj, 0",
            ".rept 2 * {n}",
            "mov qword ptr [{t} + only_oj], rax",
            ".set only_oj, only_oj + 8",
            ".endr",
            // Cross products: row i adds a[i]·a[i+1..N] at t[2i+1..], its carry to t[i+N].
            ".set only_oi, 0",
            ".rept {n} - 1",
            "mov rdx, qword ptr [{a} + 8 * only_oi]",
            "xor r9d, r9d",
            ".set only_oj, only_oi + 1",
            ".rept {n} - 1 - only_oi",
            "mulx r11, r10, qword ptr [{a} + 8 * only_oj]",
            "adcx r10, qword ptr [{t} + 8 * (only_oi + only_oj)]",
            "adox r10, r9",
            "mov qword ptr [{t} + 8 * (only_oi + only_oj)], r10",
            "mov r9, r11",
            ".set only_oj, only_oj + 1",
            ".endr",
            "mov eax, 0",
            "adcx r9, rax",
            "adox r9, rax",
            "mov qword ptr [{t} + 8 * (only_oi + {n})], r9",
            ".set only_oi, only_oi + 1",
            ".endr",
            // t = 2t + Σ a[i]²·2^(128i): doubling on the carry chain, squares on the other.
            "xor eax, eax",
            ".set only_oi, 0",
            ".rept {n}",
            "mov rdx, qword ptr [{a} + 8 * only_oi]",
            "mulx r9, r8, rdx",
            "mov r10, qword ptr [{t} + 16 * only_oi]",
            "mov r11, qword ptr [{t} + 16 * only_oi + 8]",
            "adcx r10, r10",
            "adox r10, r8",
            "adcx r11, r11",
            "adox r11, r9",
            "mov qword ptr [{t} + 16 * only_oi], r10",
            "mov qword ptr [{t} + 16 * only_oi + 8], r11",
            ".set only_oi, only_oi + 1",
            ".endr",
            redc_final!("{a}", "{a:e}", "{q}"),
            a = inout(reg) a.as_ptr() => _,
            t = inout(reg) t.as_mut_ptr().cast::<u64>() => _,
            m = in(reg) m.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            n0 = in(reg) n0,
            q = out(reg) _,
            n = const N,
            half = const N / 2,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack),
        );
    }
}
