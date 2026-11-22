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
//! Squaring at 48 and 64 limbs (3072- and 4096-bit moduli, whose fully unrolled squaring would
//! be too large) is one level of Karatsuba ([`mont_sqr_kara`]): three half-size squarings
//! ([`sqr_wide`], phase 1 alone), the middle term combined in Rust with masked carries, then the
//! reduction ([`redc`], phases 2 and 3 alone): about 30% fewer `mulx` than a multiplication.
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
//! the `2N`-limb scratch buffer (a local), and nothing else (the Karatsuba pieces: the `N`- or
//! `2N`-limb arrays behind their references). Their instructions need BMI2 and
//! ADX: they are reached only from `Mont::mul_into` / `Mont::sqr_into` after
//! [`enabled`] (`cpu::has(Feature::Adx)`), and every function here debug-asserts it.
#![allow(unsafe_code)]

use std::arch::asm;
use std::arch::x86_64::{
    __m256i, _mm256_add_epi64, _mm256_and_si256, _mm256_cmpeq_epi64, _mm256_loadu_si256,
    _mm256_or_si256, _mm256_set1_epi64x, _mm256_setzero_si256, _mm256_storeu_si256,
};
use std::mem::MaybeUninit;

use crate::cpu::{self, Feature};
use crate::ct;

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
    macro_rules! sizes {
        ($($v:literal),*) => {
            match k / 4 {
                // SAFETY: the CPU has AVX2 (asserted above).
                $($v => unsafe { lookup_avx2::<$v>(out, table, idx) },)*
                _ => {
                    for (o, base) in out[..k].chunks_exact_mut(4).zip((0..k).step_by(4)) {
                        let col: Vec<u64> = table
                            .chunks_exact(k)
                            .flat_map(|e| e[base..base + 4].iter().copied())
                            .collect();
                        // SAFETY: as above.
                        unsafe { lookup_avx2::<1>(o, &col, idx) }
                    }
                }
            }
        };
    }
    sizes!(4, 5, 6, 8, 10, 12, 16);
}

/// `out[..4V] = table[idx]` for entries of `4V` limbs: one pass over the table with `V`
/// accumulators.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
// The intrinsics are `unsafe fn`s at the MSRV (1.85) and safe inside `avx2` code on newer
// compilers.
#[allow(unused_unsafe)]
unsafe fn lookup_avx2<const V: usize>(out: &mut [u64], table: &[u64], idx: u64) {
    // SAFETY: AVX2 (the caller's contract); register-only intrinsics plus unaligned 32-byte
    // loads from 4-limb chunks of live table entries and stores into 4-limb chunks of `out`.
    unsafe {
        let idx = _mm256_set1_epi64x(idx as i64);
        let one = _mm256_set1_epi64x(1);
        let mut j = _mm256_setzero_si256();
        let mut acc = [_mm256_setzero_si256(); V];
        for entry in table.chunks_exact(4 * V) {
            let m = _mm256_cmpeq_epi64(j, idx);
            j = _mm256_add_epi64(j, one);
            for (a, c) in acc.iter_mut().zip(entry.chunks_exact(4)) {
                let v = _mm256_loadu_si256(c.as_ptr().cast::<__m256i>());
                *a = _mm256_or_si256(*a, _mm256_and_si256(m, v));
            }
        }
        for (a, o) in acc.iter().zip(out.chunks_exact_mut(4)) {
            _mm256_storeu_si256(o.as_mut_ptr().cast::<__m256i>(), *a);
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
            ".set akio_oj, 0\n",
            ".rept {half}\n",
            "mulx r11, r10, qword ptr [",
            $v,
            " + akio_oj]\n",
            "adcx r10, qword ptr [{t} + akio_oj]\n",
            "adox r10, r9\n",
            "mov qword ptr [{t} + akio_oj], r10\n",
            "mulx r9, r8, qword ptr [",
            $v,
            " + akio_oj + 8]\n",
            "adcx r8, qword ptr [{t} + akio_oj + 8]\n",
            "adox r8, r11\n",
            "mov qword ptr [{t} + akio_oj + 8], r8\n",
            ".set akio_oj, akio_oj + 16\n",
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
            ".set akio_oj, 16\n",
            ".rept {half} - 1\n",
            "mulx r11, r10, qword ptr [{m} + akio_oj]\n",
            "adcx r10, qword ptr [{t} + akio_oj]\n",
            "adox r10, r9\n",
            "mov qword ptr [{t} + akio_oj], r10\n",
            "mulx r9, r8, qword ptr [{m} + akio_oj + 8]\n",
            "adcx r8, qword ptr [{t} + akio_oj + 8]\n",
            "adox r8, r11\n",
            "mov qword ptr [{t} + akio_oj + 8], r8\n",
            ".set akio_oj, akio_oj + 16\n",
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
            "adc r9, qword ptr [{t} + akio_oj]\n",
            "mov qword ptr [{t} + akio_oj], r9\n",
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
            ".set akio_oj, 8\n",
            ".rept {n} - 1\n",
            "mov rax, qword ptr [{t} + akio_oj]\n",
            "sbb rax, qword ptr [{m} + akio_oj]\n",
            "mov qword ptr [{out} + akio_oj], rax\n",
            ".set akio_oj, akio_oj + 8\n",
            ".endr\n",
            "sbb rax, rax\n",
            "not ",
            $top,
            "\n",
            "and rax, ",
            $top,
            "\n",
            "test rax, rax\n",
            ".set akio_oj, 0\n",
            ".rept {n}\n",
            "mov rcx, qword ptr [{out} + akio_oj]\n",
            "cmovnz rcx, qword ptr [{t} + akio_oj]\n",
            "mov qword ptr [{out} + akio_oj], rcx\n",
            ".set akio_oj, akio_oj + 8\n",
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
            ".set akio_oj, 0",
            ".rept {half}",
            "mulx r11, r10, qword ptr [{a} + akio_oj]",
            "adcx r10, r9",
            "mov qword ptr [{t} + akio_oj], r10",
            "mulx r9, r8, qword ptr [{a} + akio_oj + 8]",
            "adcx r8, r11",
            "mov qword ptr [{t} + akio_oj + 8], r8",
            ".set akio_oj, akio_oj + 16",
            ".endr",
            "mov eax, 0",
            "adcx r9, rax",
            "mov qword ptr [{t} + akio_oj], r9",
            // Rows 1..N: t[i..=i+N] += a·b[i].
            "mov ecx, {n} - 1",
            "2:",
            "lea {b}, [{b} + 8]",
            "lea {t}, [{t} + 8]",
            "mov rdx, qword ptr [{b}]",
            row_add!("{a}"),
            "mov qword ptr [{t} + akio_oj], r9",
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
/// of them), so [`super::Mont`] uses this up to 32 limbs and [`mont_sqr_kara`] above that.
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
            ".set akio_oj, 0",
            ".rept 2 * {n}",
            "mov qword ptr [{t} + akio_oj], rax",
            ".set akio_oj, akio_oj + 8",
            ".endr",
            // Cross products: row i adds a[i]·a[i+1..N] at t[2i+1..], its carry to t[i+N].
            ".set akio_oi, 0",
            ".rept {n} - 1",
            "mov rdx, qword ptr [{a} + 8 * akio_oi]",
            "xor r9d, r9d",
            ".set akio_oj, akio_oi + 1",
            ".rept {n} - 1 - akio_oi",
            "mulx r11, r10, qword ptr [{a} + 8 * akio_oj]",
            "adcx r10, qword ptr [{t} + 8 * (akio_oi + akio_oj)]",
            "adox r10, r9",
            "mov qword ptr [{t} + 8 * (akio_oi + akio_oj)], r10",
            "mov r9, r11",
            ".set akio_oj, akio_oj + 1",
            ".endr",
            "mov eax, 0",
            "adcx r9, rax",
            "adox r9, rax",
            "mov qword ptr [{t} + 8 * (akio_oi + {n})], r9",
            ".set akio_oi, akio_oi + 1",
            ".endr",
            // t = 2t + Σ a[i]²·2^(128i): doubling on the carry chain, squares on the other.
            "xor eax, eax",
            ".set akio_oi, 0",
            ".rept {n}",
            "mov rdx, qword ptr [{a} + 8 * akio_oi]",
            "mulx r9, r8, rdx",
            "mov r10, qword ptr [{t} + 16 * akio_oi]",
            "mov r11, qword ptr [{t} + 16 * akio_oi + 8]",
            "adcx r10, r10",
            "adox r10, r8",
            "adcx r11, r11",
            "adox r11, r9",
            "mov qword ptr [{t} + 16 * akio_oi], r10",
            "mov qword ptr [{t} + 16 * akio_oi + 8], r11",
            ".set akio_oi, akio_oi + 1",
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

/// `t = a²` (all `2N` limbs): the product phase of [`mont_sqr`] alone, for [`mont_sqr_kara`].
/// `W` must be `2N`, `N` even and at least 4.
#[inline]
fn sqr_wide<const N: usize, const W: usize>(t: &mut [u64; W], a: &[u64; N]) {
    const { assert!(W == 2 * N && N % 2 == 0 && N >= 4) };
    debug_assert!(cpu::cpu_has(Feature::Adx));
    // SAFETY: reads the N limbs behind `a` (a live array) and writes the 2N limbs of `t` (an
    // exclusive borrow), zeroed first, as in `mont_sqr`; every displacement is below 8·2N. No
    // stack use; `rbx`/`rbp` untouched. BMI2 and ADX: reached only after `enabled()`.
    unsafe {
        asm!(
            "xor eax, eax",
            ".set akio_oj, 0",
            ".rept 2 * {n}",
            "mov qword ptr [{t} + akio_oj], rax",
            ".set akio_oj, akio_oj + 8",
            ".endr",
            ".set akio_oi, 0",
            ".rept {n} - 1",
            "mov rdx, qword ptr [{a} + 8 * akio_oi]",
            "xor r9d, r9d",
            ".set akio_oj, akio_oi + 1",
            ".rept {n} - 1 - akio_oi",
            "mulx r11, r10, qword ptr [{a} + 8 * akio_oj]",
            "adcx r10, qword ptr [{t} + 8 * (akio_oi + akio_oj)]",
            "adox r10, r9",
            "mov qword ptr [{t} + 8 * (akio_oi + akio_oj)], r10",
            "mov r9, r11",
            ".set akio_oj, akio_oj + 1",
            ".endr",
            "mov eax, 0",
            "adcx r9, rax",
            "adox r9, rax",
            "mov qword ptr [{t} + 8 * (akio_oi + {n})], r9",
            ".set akio_oi, akio_oi + 1",
            ".endr",
            "xor eax, eax",
            ".set akio_oi, 0",
            ".rept {n}",
            "mov rdx, qword ptr [{a} + 8 * akio_oi]",
            "mulx r9, r8, rdx",
            "mov r10, qword ptr [{t} + 16 * akio_oi]",
            "mov r11, qword ptr [{t} + 16 * akio_oi + 8]",
            "adcx r10, r10",
            "adox r10, r8",
            "adcx r11, r11",
            "adox r11, r9",
            "mov qword ptr [{t} + 16 * akio_oi], r10",
            "mov qword ptr [{t} + 16 * akio_oi + 8], r11",
            ".set akio_oi, akio_oi + 1",
            ".endr",
            a = in(reg) a.as_ptr(),
            t = in(reg) t.as_mut_ptr(),
            n = const N,
            out("rax") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack),
        );
    }
}

/// `out = t·2^(-64N) mod m`, fully reduced, for `t < m·2^(64N)` (`2N` limbs, used as scratch):
/// the reduction and final subtraction of [`mont_mul`] alone. `W` must be `2N`, `N` even and at
/// least 4.
#[inline]
fn redc<const N: usize, const W: usize>(
    out: &mut [u64; N],
    t: &mut [u64; W],
    m: &[u64; N],
    n0: u64,
) {
    const { assert!(W == 2 * N && N % 2 == 0 && N >= 4) };
    debug_assert!(cpu::cpu_has(Feature::Adx));
    // SAFETY: reads the N limbs behind `m` (a live array), reads and writes the 2N limbs of `t`
    // (an exclusive borrow) and writes the N limbs behind `out` (an exclusive borrow, aliasing
    // neither), as the reduction phase of `mont_mul` does; every displacement is below 8·2N.
    // No stack use; `rbx`/`rbp` untouched. BMI2 and ADX: reached only after `enabled()`.
    unsafe {
        asm!(
            redc_final!("{top}", "{top:e}", "{q}"),
            t = inout(reg) t.as_mut_ptr() => _,
            m = in(reg) m.as_ptr(),
            out = in(reg) out.as_mut_ptr(),
            n0 = in(reg) n0,
            top = out(reg) _,
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

/// `|x - y|` into `d` and a mask set when `x < y`, in constant time.
#[inline(always)]
fn abs_diff(d: &mut [u64], x: &[u64], y: &[u64]) -> u64 {
    let neg = ct::mask(ct::sub_limbs(d, x, y));
    let mut c = neg & 1;
    for l in d.iter_mut() {
        let (v, o) = (*l ^ neg).overflowing_add(c);
        *l = v;
        c = u64::from(o);
    }
    neg
}

/// Adds `x` (`N + 1` limbs: `N` plus a top word) into `t` at limb `H`, carrying to the end of
/// `t`, in constant time (every limb is visited).
#[inline(always)]
fn add_middle(t: &mut [u64], at: usize, x: &[u64], top: u64) {
    let mut c = 0u64;
    for (i, l) in t[at..].iter_mut().enumerate() {
        let v = if i < x.len() {
            x[i]
        } else if i == x.len() {
            top
        } else {
            0
        };
        let (s, c1) = l.overflowing_add(v);
        let (s, c2) = s.overflowing_add(c);
        *l = s;
        c = u64::from(c1 | c2);
    }
}

/// [`mont_sqr`] for `N = 2H` limbs by one level of Karatsuba: with `a = a₁·B + a₀`
/// (`B = 2^(64H)`), `a² = a₁²·B² + (a₀² + a₁² - (a₀ - a₁)²)·B + a₀²`, three `H`-limb squarings
/// ([`sqr_wide`]) instead of the `N²` products of [`mont_mul`]`(a, a)`, then [`redc`]. For
/// `a < m`; constant time (the sign of `a₀ - a₁` only selects by masks). `W` must be `2N`.
pub(crate) fn mont_sqr_kara<const N: usize, const H: usize, const W: usize>(
    out: &mut [u64; N],
    a: &[u64; N],
    m: &[u64; N],
    n0: u64,
) {
    const { assert!(N == 2 * H && W == 2 * N && H % 2 == 0 && H >= 4) };
    let mut t = [0u64; W];
    let (a0, a1) = a.split_at(H);
    let (a0, a1): (&[u64; H], &[u64; H]) =
        (a0.try_into().expect("half"), a1.try_into().expect("half"));
    {
        let (lo, hi) = t.split_at_mut(N);
        sqr_wide::<H, N>(lo.try_into().expect("half"), a0);
        sqr_wide::<H, N>(hi.try_into().expect("half"), a1);
    }
    let mut d = [0u64; H];
    abs_diff(&mut d, a0, a1);
    let mut dd = [0u64; N];
    sqr_wide::<H, N>(&mut dd, &d);
    // mid = a₀² + a₁² - d² = 2·a₀·a₁ ≥ 0, below 2^(64N + 1).
    let mut mid = [0u64; N];
    let c = ct::add_limbs(&mut mid, &t[..N], &t[N..]);
    let mut mid2 = [0u64; N];
    let b = ct::sub_limbs(&mut mid2, &mid, &dd);
    add_middle(&mut t, H, &mid2, c.wrapping_sub(b));
    redc::<N, W>(out, &mut t, m, n0);
}
