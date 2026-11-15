//! P-256 arithmetic on x86_64 with BMI2 (`mulx`) and ADX (`adcx`/`adox`), in inline assembly:
//!
//! - modulo the prime `p = 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1` ([`P256Px`]): Montgomery multiplication
//!   and squaring (`R = 2²⁵⁶`), addition, subtraction. It is the base field of the `P256X` twin
//!   of the `P256` curve (`curves.rs`), which `P256` dispatches its operations to when
//!   [`enabled`] says so; both share the Montgomery representation, so points and tables convert
//!   by copying limbs;
//! - modulo the group order `n` ([`ord_mul`], [`ord_sqr`], [`P256Nx`]): Montgomery
//!   multiplication and squaring, which the portable `P256N` scalar field calls when
//!   [`enabled`] (one check per operation; the inversion checks once).
//!
//! Constant time: straight-line code, no branches and no memory accesses that depend on the
//! values; the final corrections use `cmovc`/`cmovnc` or masks from `sbb`. (`black_box` is not
//! needed here: the compiler cannot rewrite the assembly.)
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the `asm!`
//! blocks, which read the 32-byte limb arrays behind their pointer operands and write nothing but
//! their register outputs. Their instructions need BMI2 and ADX: they are only reached after
//! `cpu::has(Feature::Adx)` (the twin curve's dispatch in `curves.rs`, the scalar field's checks),
//! and every function here debug-asserts it.
#![allow(unsafe_code)]

use std::arch::asm;
use std::arch::x86_64::{
    _mm256_add_epi64, _mm256_and_si256, _mm256_cmpeq_epi64, _mm256_loadu_si256, _mm256_or_si256,
    _mm256_set1_epi64x, _mm256_setzero_si256, _mm256_storeu_si256,
};
use std::sync::OnceLock;

use super::curves::P256X;
use super::{Jac, Point, Scalar};
use crate::cpu::{self, Feature};
use crate::ct;
use crate::field::{Fe, Modulus};

/// Whether to use this module: the CPU has BMI2 and ADX, and the portable code is not forced.
#[inline]
pub(crate) fn enabled() -> bool {
    cpu::has(Feature::Adx)
}

/// `p₃`, the top limb of `p`.
const P3: u64 = 0xffff_ffff_0000_0001;

/// The P-256 base field on BMI2 + ADX.
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256Px;

impl Modulus<4> for P256Px {
    const P: [u64; 4] = [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0, P3];

    #[inline]
    fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        mul(a, b)
    }

    #[inline]
    fn mont_sqr(a: &[u64; 4]) -> [u64; 4] {
        sqr(a)
    }

    #[inline]
    fn mod_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        add(a, b)
    }

    #[inline]
    fn mod_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        sub(a, b)
    }

    #[inline]
    fn mod_mul3(a: &[u64; 4]) -> [u64; 4] {
        mul3(a)
    }

    #[inline]
    fn mod_mul_pow2(a: &[u64; 4], k: u32) -> [u64; 4] {
        if k == 0 {
            return *a;
        }
        let mut r = mul_pow2(a, k.min(3));
        for _ in 3..k {
            r = mul_pow2(&r, 1);
        }
        r
    }

    fn mont_inv(a: &[u64; 4]) -> Option<[u64; 4]> {
        Some(mont_inv_safegcd::<Self>(a))
    }
}

/// The P-256 group order on BMI2 + ADX, for the scalar inversion chain (addition and subtraction
/// stay portable: the chain uses none).
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256Nx;

impl Modulus<4> for P256Nx {
    const P: [u64; 4] = [N0, N1, N2, N3];

    #[inline]
    fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        ord_mul(a, b)
    }

    #[inline]
    fn mont_sqr(a: &[u64; 4]) -> [u64; 4] {
        ord_sqr(a)
    }
}

/// The limbs of `n` and `-n⁻¹ mod 2⁶⁴`.
const N0: u64 = 0xf3b9_cac2_fc63_2551;
const N1: u64 = 0xbce6_faad_a717_9e84;
const N2: u64 = 0xffff_ffff_ffff_ffff;
const N3: u64 = 0xffff_ffff_0000_0000;
#[cfg(test)]
const NINV: u64 = 0xccd1_c8aa_ee00_bc4f;

/// The 512-bit product `a·b` into `z0..z7` = `r8..r15` (pointers in `{a}`, `{b}`; clobbers `rax`,
/// `rcx`, `rdx`): one row per limb of `b`, the low halves of `a·bᵢ` on the CF chain (`adcx`), the
/// high halves on the OF chain (`adox`). Each row's top limb is `hi(a₃·bᵢ)` plus the two pending
/// carries, which cannot overflow (the partial product fits its limbs).
macro_rules! mul_rows {
    () => {
        mul_rows!("{a}", "{b}")
    };
    ($a:literal, $b:literal) => {
        concat!(
            "mov rdx, [",
            $b,
            "]\n",
            "mulx r9, r8, [",
            $a,
            "]\n",
            "mulx r10, rax, [",
            $a,
            " + 8]\n",
            "add r9, rax\n",
            "mulx r11, rax, [",
            $a,
            " + 16]\n",
            "adc r10, rax\n",
            "mulx r12, rax, [",
            $a,
            " + 24]\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            //
            "mov rdx, [",
            $b,
            " + 8]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [",
            $a,
            "]\n",
            "adcx r9, rax\n",
            "adox r10, rcx\n",
            "mulx rcx, rax, [",
            $a,
            " + 8]\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx rcx, rax, [",
            $a,
            " + 16]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx r13, rax, [",
            $a,
            " + 24]\n",
            "adcx r12, rax\n",
            "mov eax, 0\n",
            "adox r13, rax\n",
            "adcx r13, rax\n",
            //
            "mov rdx, [",
            $b,
            " + 16]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [",
            $a,
            "]\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx rcx, rax, [",
            $a,
            " + 8]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx rcx, rax, [",
            $a,
            " + 16]\n",
            "adcx r12, rax\n",
            "adox r13, rcx\n",
            "mulx r14, rax, [",
            $a,
            " + 24]\n",
            "adcx r13, rax\n",
            "mov eax, 0\n",
            "adox r14, rax\n",
            "adcx r14, rax\n",
            //
            "mov rdx, [",
            $b,
            " + 24]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [",
            $a,
            "]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx rcx, rax, [",
            $a,
            " + 8]\n",
            "adcx r12, rax\n",
            "adox r13, rcx\n",
            "mulx rcx, rax, [",
            $a,
            " + 16]\n",
            "adcx r13, rax\n",
            "adox r14, rcx\n",
            "mulx r15, rax, [",
            $a,
            " + 24]\n",
            "adcx r14, rax\n",
            "mov eax, 0\n",
            "adox r15, rax\n",
            "adcx r15, rax\n",
        )
    };
}

/// The 512-bit square `a²` into `z0..z7` = `r8..r15` (pointer in `{a}`; clobbers `rax`, `rcx`,
/// `rdx`): the six cross products once, doubled, plus the four squares.
macro_rules! sqr_rows {
    () => {
        sqr_rows!("{a}")
    };
    ($a:literal) => {
        concat!(
            // Cross products aᵢ·aⱼ (i < j) into limbs 1..6 (r9..r14).
            "mov rdx, [",
            $a,
            "]\n",
            "mulx r10, r9, [",
            $a,
            " + 8]\n",
            "mulx r11, rax, [",
            $a,
            " + 16]\n",
            "add r10, rax\n",
            "mulx r12, rax, [",
            $a,
            " + 24]\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            "mov rdx, [",
            $a,
            " + 8]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [",
            $a,
            " + 16]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx r13, rax, [",
            $a,
            " + 24]\n",
            "adcx r12, rax\n",
            "mov eax, 0\n",
            "adox r13, rax\n",
            "adcx r13, rax\n",
            "mov rdx, [",
            $a,
            " + 16]\n",
            "mulx r14, rax, [",
            $a,
            " + 24]\n",
            "add r13, rax\n",
            "adc r14, 0\n",
            // Doubled into limbs 1..7.
            "xor r15d, r15d\n",
            "add r9, r9\n",
            "adc r10, r10\n",
            "adc r11, r11\n",
            "adc r12, r12\n",
            "adc r13, r13\n",
            "adc r14, r14\n",
            "adc r15, 0\n",
            // Plus the squares aᵢ² at limbs 2i, 2i + 1.
            "mov rdx, [",
            $a,
            "]\n",
            "mulx rcx, r8, rdx\n",
            "add r9, rcx\n",
            "mov rdx, [",
            $a,
            " + 8]\n",
            "mulx rcx, rax, rdx\n",
            "adc r10, rax\n",
            "adc r11, rcx\n",
            "mov rdx, [",
            $a,
            " + 16]\n",
            "mulx rcx, rax, rdx\n",
            "adc r12, rax\n",
            "adc r13, rcx\n",
            "mov rdx, [",
            $a,
            " + 24]\n",
            "mulx rcx, rax, rdx\n",
            "adc r14, rax\n",
            "adc r15, rcx\n",
        )
    };
}

// The X25519 ladder (`curve25519::hw`) shares the 512-bit products.
pub(crate) use {mul_rows, sqr_rows};

/// One step of [`reduce_p`]: `m = zᵢ`, `z += m·p`, with the previous carry in `$c`.
macro_rules! reduce_p_step {
    ($zi:literal, $z1:literal, $z2:literal, $z3:literal, $z4:literal, $p3:literal, $c:literal, $ce:literal) => {
        concat!(
            "mov rdx, ",
            $zi,
            "\n",
            "mulx rcx, ",
            $zi,
            ", ",
            $p3,
            "\n",
            "mov rax, rdx\n",
            "shl rax, 32\n",
            "shr rdx, 32\n",
            "add ",
            $z1,
            ", rax\n",
            "adc ",
            $z2,
            ", rdx\n",
            "adc ",
            $z3,
            ", ",
            $zi,
            "\n",
            "adc rcx, ",
            $c,
            "\n",
            "add ",
            $z4,
            ", rcx\n",
            "mov ",
            $ce,
            ", 0\n",
            "adc ",
            $ce,
            ", 0\n",
        )
    };
}

/// The Montgomery reduction modulo `p` of the 512-bit `z0..z7` in `r8..r15`, given the operands
/// holding `p₃` and a zeroed carry register (as `$p3`, `$c` and its 32-bit name `$ce`), leaving
/// `t·2⁻²⁵⁶ mod p` fully reduced in `rax, rcx, r8, r9`.
///
/// `-p⁻¹ mod 2⁶⁴ = 1`, so each step's multiplier `m` is the low limb itself, and adding `m·p`
/// clears it and adds `m·2⁹⁶` (two shifted words) and `m·p₃·2¹⁹²` (one `mulx`), as the portable
/// `p256_redc`. The carry out of step `i` belongs to limb `i + 5`; it rides in `$c` into the next
/// step's top addition (`hi(m·p₃) ≤ 2⁶⁴ - 2³²`, so adding it and a carry cannot overflow).
/// The input is below `p·2²⁵⁶`, so the result before the final subtraction is below `2p`.
macro_rules! reduce_p {
    ($p3:literal, $c:literal, $ce:literal) => {
        concat!(
            reduce_p_step!("r8", "r9", "r10", "r11", "r12", $p3, $c, $ce),
            reduce_p_step!("r9", "r10", "r11", "r12", "r13", $p3, $c, $ce),
            reduce_p_step!("r10", "r11", "r12", "r13", "r14", $p3, $c, $ce),
            reduce_p_step!("r11", "r12", "r13", "r14", "r15", $p3, $c, $ce),
            // t = c·2²⁵⁶ + (r12..r15) < 2p: subtract p, keep t where that borrows.
            "mov edx, 0xffffffff\n",
            "mov rax, r12\n",
            "sub rax, -1\n",
            "mov rcx, r13\n",
            "sbb rcx, rdx\n",
            "mov r8, r14\n",
            "sbb r8, 0\n",
            "mov r9, r15\n",
            "sbb r9, ",
            $p3,
            "\n",
            "sbb ",
            $c,
            ", 0\n",
            "cmovc rax, r12\n",
            "cmovc rcx, r13\n",
            "cmovc r8, r14\n",
            "cmovc r9, r15\n",
        )
    };
}

/// One step of [`reduce_n`]: `m = zᵢ·(-n⁻¹) mod 2⁶⁴`, `z += m·n` (constants through `$k`), with
/// the previous carry in `$c`. The top limb gets `hi(m·n₃) + c + OF + CF`, which cannot overflow
/// (`n₃ = 2⁶⁴ - 2³²`, so `hi(m·n₃) < 2⁶⁴ - 2³²`).
macro_rules! reduce_n_step {
    ($zi:literal, $z1:literal, $z2:literal, $z3:literal, $z4:literal, $k:literal, $c:literal, $ce:literal) => {
        concat!(
            "mov rdx, ",
            $zi,
            "\n",
            "mov ",
            $k,
            ", 0xccd1c8aaee00bc4f\n",
            "imul rdx, ",
            $k,
            "\n",
            "xor eax, eax\n",
            "mov ",
            $k,
            ", 0xf3b9cac2fc632551\n",
            "mulx rcx, rax, ",
            $k,
            "\n",
            "adcx ",
            $zi,
            ", rax\n",
            "adox ",
            $z1,
            ", rcx\n",
            "mov ",
            $k,
            ", 0xbce6faada7179e84\n",
            "mulx rcx, rax, ",
            $k,
            "\n",
            "adcx ",
            $z1,
            ", rax\n",
            "adox ",
            $z2,
            ", rcx\n",
            "mov ",
            $k,
            ", -1\n",
            "mulx rcx, rax, ",
            $k,
            "\n",
            "adcx ",
            $z2,
            ", rax\n",
            "adox ",
            $z3,
            ", rcx\n",
            "mov ",
            $k,
            ", 0xffffffff00000000\n",
            "mulx rcx, rax, ",
            $k,
            "\n",
            "adcx ",
            $z3,
            ", rax\n",
            "adox rcx, ",
            $c,
            "\n",
            "mov eax, 0\n",
            "adcx rcx, rax\n",
            "add ",
            $z4,
            ", rcx\n",
            "mov ",
            $ce,
            ", 0\n",
            "adc ",
            $ce,
            ", 0\n",
        )
    };
}

/// The Montgomery reduction modulo `n` of the 512-bit `z0..z7` in `r8..r15` (a scratch register
/// `$k` and a zeroed carry register `$c`/`$ce`), leaving `t·2⁻²⁵⁶ mod n` fully reduced in `rax,
/// rcx, rdx, r8`. The input is below `n·2²⁵⁶`, so the result before the final subtraction is
/// below `2n`.
macro_rules! reduce_n {
    ($k:literal, $c:literal, $ce:literal) => {
        concat!(
            reduce_n_step!("r8", "r9", "r10", "r11", "r12", $k, $c, $ce),
            reduce_n_step!("r9", "r10", "r11", "r12", "r13", $k, $c, $ce),
            reduce_n_step!("r10", "r11", "r12", "r13", "r14", $k, $c, $ce),
            reduce_n_step!("r11", "r12", "r13", "r14", "r15", $k, $c, $ce),
            // t = c·2²⁵⁶ + (r12..r15) < 2n: subtract n, keep t where that borrows.
            "mov rax, r12\n",
            "mov ",
            $k,
            ", 0xf3b9cac2fc632551\n",
            "sub rax, ",
            $k,
            "\n",
            "mov rcx, r13\n",
            "mov ",
            $k,
            ", 0xbce6faada7179e84\n",
            "sbb rcx, ",
            $k,
            "\n",
            "mov rdx, r14\n",
            "sbb rdx, -1\n",
            "mov r8, r15\n",
            "mov ",
            $k,
            ", 0xffffffff00000000\n",
            "sbb r8, ",
            $k,
            "\n",
            "sbb ",
            $c,
            ", 0\n",
            "cmovc rax, r12\n",
            "cmovc rcx, r13\n",
            "cmovc rdx, r14\n",
            "cmovc r8, r15\n",
        )
    };
}

/// Montgomery multiplication `a·b·2⁻²⁵⁶ mod p`, fully reduced, for `a·b < p·2²⁵⁶` (any `a < 2²⁵⁶`
/// with `b < p`).
#[inline]
pub(crate) fn mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind each of `a` and `b` (live, 32-byte arrays), writes only
    // the declared registers (no stack). `mulx`, `adcx` and `adox` need BMI2 and ADX: this is
    // only reached through the `P256X` twin, entered after `cpu::has(Feature::Adx)` (asserted in
    // debug builds above).
    unsafe {
        asm!(
            mul_rows!(),
            // The pointers are dead: {b} holds p₃, {a} the reduction's carry.
            "mov {b}, 0xffffffff00000001",
            "xor {a:e}, {a:e}",
            reduce_p!("{b}", "{a}", "{a:e}"),
            a = inout(reg) a.as_ptr() => _,
            b = inout(reg) b.as_ptr() => _,
            out("rax") r0,
            out("rcx") r1,
            out("rdx") _,
            out("r8") r2,
            out("r9") r3,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// Montgomery squaring `a²·2⁻²⁵⁶ mod p`, fully reduced, for `a < p`.
#[inline]
pub(crate) fn sqr(a: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind `a` (a live 32-byte array), writes only the declared
    // registers (no stack). BMI2 and ADX: only reached through the `P256X` twin, entered after
    // `cpu::has(Feature::Adx)` (asserted in debug builds above).
    unsafe {
        asm!(
            sqr_rows!(),
            // The pointer is dead: {a} becomes the reduction's carry.
            "xor {a:e}, {a:e}",
            reduce_p!("{p3}", "{a}", "{a:e}"),
            a = inout(reg) a.as_ptr() => _,
            p3 = in(reg) P3,
            out("rax") r0,
            out("rcx") r1,
            out("rdx") _,
            out("r8") r2,
            out("r9") r3,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// Montgomery multiplication `a·b·2⁻²⁵⁶ mod n` (the group order), fully reduced, for
/// `a·b < n·2²⁵⁶`.
#[inline]
pub(crate) fn ord_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind each of `a` and `b` (live 32-byte arrays), writes only the
    // declared registers (no stack). BMI2 and ADX: callers check `enabled()` first (asserted in
    // debug builds above).
    unsafe {
        asm!(
            mul_rows!(),
            // The pointers are dead: {b} is scratch for the constants, {a} the carry.
            "xor {a:e}, {a:e}",
            reduce_n!("{b}", "{a}", "{a:e}"),
            a = inout(reg) a.as_ptr() => _,
            b = inout(reg) b.as_ptr() => _,
            out("rax") r0,
            out("rcx") r1,
            out("rdx") r2,
            out("r8") r3,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// Montgomery squaring `a²·2⁻²⁵⁶ mod n` (the group order), fully reduced, for `a < n`.
#[inline]
pub(crate) fn ord_sqr(a: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind `a` (a live 32-byte array), writes only the declared
    // registers (no stack). BMI2 and ADX: callers check `enabled()` first (asserted in debug
    // builds above).
    unsafe {
        asm!(
            sqr_rows!(),
            "xor {a:e}, {a:e}",
            reduce_n!("{k}", "{a}", "{a:e}"),
            a = inout(reg) a.as_ptr() => _,
            k = out(reg) _,
            out("rax") r0,
            out("rcx") r1,
            out("rdx") r2,
            out("r8") r3,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `s - p` unless that borrows, for `s = {c}·2²⁵⁶ + ({r0}..{r3}) < 2p`, into `{r0}..{r3}`
/// (`{t0}..{t3}` scratch, `{p1}`, `{p3}` the limbs of `p`).
macro_rules! cond_sub_p {
    () => {
        concat!(
            "mov {t0}, {r0}\n",
            "sub {t0}, -1\n",
            "mov {t1}, {r1}\n",
            "sbb {t1}, {p1}\n",
            "mov {t2}, {r2}\n",
            "sbb {t2}, 0\n",
            "mov {t3}, {r3}\n",
            "sbb {t3}, {p3}\n",
            "sbb {c}, 0\n",
            "cmovnc {r0}, {t0}\n",
            "cmovnc {r1}, {t1}\n",
            "cmovnc {r2}, {t2}\n",
            "cmovnc {r3}, {t3}\n",
        )
    };
}

/// `2·({r0}..{r3}) mod p` in place.
macro_rules! dbl_p {
    () => {
        concat!(
            "xor {c:e}, {c:e}\n",
            "add {r0}, {r0}\n",
            "adc {r1}, {r1}\n",
            "adc {r2}, {r2}\n",
            "adc {r3}, {r3}\n",
            "adc {c}, 0\n",
            cond_sub_p!(),
        )
    };
}

/// `a + b mod p` for `a, b < p`. The operands travel in registers.
#[inline]
pub(crate) fn add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: registers only. Base x86_64 instructions only (`cmov` included).
    unsafe {
        asm!(
            "xor {c:e}, {c:e}",
            "add {r0}, {t0}",
            "adc {r1}, {t1}",
            "adc {r2}, {t2}",
            "adc {r3}, {t3}",
            "adc {c}, 0",
            cond_sub_p!(),
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            t0 = inout(reg) b[0] => _,
            t1 = inout(reg) b[1] => _,
            t2 = inout(reg) b[2] => _,
            t3 = inout(reg) b[3] => _,
            c = out(reg) _,
            p1 = in(reg) 0xffff_ffffu64,
            p3 = in(reg) P3,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a - b mod p` for `a, b < p`. The operands travel in registers.
#[inline]
pub(crate) fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: registers only. Base x86_64 instructions only.
    unsafe {
        asm!(
            "sub {r0}, {b0}",
            "sbb {r1}, {b1}",
            "sbb {r2}, {b2}",
            "sbb {r3}, {b3}",
            // m = -borrow; add p & m (p₀ = 2⁶⁴ - 1, p₁ = 2³² - 1, p₂ = 0).
            "sbb {b0}, {b0}",
            "mov {b1}, {b0}",
            "shr {b1}, 32",
            "mov {b3}, 0xffffffff00000001",
            "and {b3}, {b0}",
            "add {r0}, {b0}",
            "adc {r1}, {b1}",
            "adc {r2}, 0",
            "adc {r3}, {b3}",
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            b0 = inout(reg) b[0] => _,
            b1 = inout(reg) b[1] => _,
            b2 = in(reg) b[2],
            b3 = inout(reg) b[3] => _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `2ᵏ·a mod p` for `a < p`, `k ∈ {1, 2, 3}` (the doublings of the point formulas fused, in
/// registers).
#[inline]
pub(crate) fn mul_pow2(a: &[u64; 4], k: u32) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    debug_assert!((1..=3).contains(&k));
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    macro_rules! go {
        ($($step:expr),+) => {
            // SAFETY: registers only. Base x86_64 instructions only (`cmov` included).
            unsafe {
                asm!(
                    $($step,)+
                    r0 = inout(reg) r0,
                    r1 = inout(reg) r1,
                    r2 = inout(reg) r2,
                    r3 = inout(reg) r3,
                    t0 = out(reg) _,
                    t1 = out(reg) _,
                    t2 = out(reg) _,
                    t3 = out(reg) _,
                    c = out(reg) _,
                    p1 = in(reg) 0xffff_ffffu64,
                    p3 = in(reg) P3,
                    options(pure, nomem, nostack),
                );
            }
        };
    }
    match k {
        1 => go!(dbl_p!()),
        2 => go!(dbl_p!(), dbl_p!()),
        _ => go!(dbl_p!(), dbl_p!(), dbl_p!()),
    }
    [r0, r1, r2, r3]
}

/// `3·a mod p` for `a < p` (the second addition reads `a` from memory).
#[inline]
pub(crate) fn mul3(a: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: reads the 4 limbs behind `a` (a live 32-byte array), writes only the declared
    // registers. Base x86_64 instructions only (`cmov` included).
    unsafe {
        asm!(
            dbl_p!(),
            "xor {c:e}, {c:e}",
            "add {r0}, [{a}]",
            "adc {r1}, [{a} + 8]",
            "adc {r2}, [{a} + 16]",
            "adc {r3}, [{a} + 24]",
            "adc {c}, 0",
            cond_sub_p!(),
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            a = in(reg) a.as_ptr(),
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            c = out(reg) _,
            p1 = in(reg) 0xffff_ffffu64,
            p3 = in(reg) P3,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

// Whole point operations: each one `asm!` block over a frame of 32-byte field elements addressed
// from `rdi` (`[rdi]` holds `p₃`, the elements start at `rdi + 32`). A product or square leaves
// its reduced result in the accumulator `r12..r15`; the additions, subtractions and doublings
// work on the accumulator in place, with the other operand in the frame, so a chain of them costs
// no stores; the accumulator goes to the frame only where a later product reads it. `rsi`
// carries the reductions' and additions' top bits, `rax`, `rcx`, `rdx`, `r8..r11` are scratch.

/// `R = (r12..r15) ← a·b·2⁻²⁵⁶ mod p` for frame addresses `a`, `b` (holding values below `p`).
macro_rules! f_mul {
    ($a:literal, $b:literal) => {
        concat!(mul_rows!($a, $b), f_redc!())
    };
}

/// `R ← a²·2⁻²⁵⁶ mod p`.
macro_rules! f_sqr {
    ($a:literal) => {
        concat!(sqr_rows!($a), f_redc!())
    };
}

/// One step of [`f_redc`] on the low half `L = ($m, $z1, $z2, $z3)`: `L ← (L + m·p)/2⁶⁴` with
/// `m` the low limb, the result in `($z1, $z2, $z3, $m)`. As in [`reduce_p`], `m·p` adds `m·2⁹⁶`
/// (two shifted words) and `m·p₃·2¹⁹²`; the top limb of the result is `hi(m·p₃)` plus a carry,
/// which cannot overflow (`hi(m·p₃) ≤ 2⁶⁴ - 2³²`), and `(L + m·p)/2⁶⁴ < 2¹⁹² + p < 2²⁵⁶`.
macro_rules! f_redc_step {
    ($m:literal, $z1:literal, $z2:literal, $z3:literal) => {
        concat!(
            "mov rdx, ",
            $m,
            "\n",
            "mov rax, ",
            $m,
            "\n",
            "shl rax, 32\n",
            "mov rcx, ",
            $m,
            "\n",
            "shr rcx, 32\n",
            "mulx ",
            $m,
            ", rsi, [rdi]\n",
            "add ",
            $z1,
            ", rax\n",
            "adc ",
            $z2,
            ", rcx\n",
            "adc ",
            $z3,
            ", rsi\n",
            "adc ",
            $m,
            ", 0\n",
        )
    };
}

/// The Montgomery reduction `t·2⁻²⁵⁶ mod p` of `t = H·2²⁵⁶ + L` in `r8..r15` (`t < p·2²⁵⁶`) into
/// `R`, `p₃` read from `[rdi]`: four steps reduce the low half alone to `L' = (L + M·p)/2²⁵⁶ ≤
/// p` (in `r8..r11` again after the rotation), then `R = H + L' < 2p` with the carry in `rsi`,
/// and one conditional subtraction.
macro_rules! f_redc {
    () => {
        concat!(
            f_redc_step!("r8", "r9", "r10", "r11"),
            f_redc_step!("r9", "r10", "r11", "r8"),
            f_redc_step!("r10", "r11", "r8", "r9"),
            f_redc_step!("r11", "r8", "r9", "r10"),
            "xor esi, esi\n",
            "add r12, r8\n",
            "adc r13, r9\n",
            "adc r14, r10\n",
            "adc r15, r11\n",
            "adc rsi, 0\n",
            f_csub!(),
        )
    };
}

/// `R ← s - p` unless that borrows, for `s = rsi·2²⁵⁶ + R < 2p`: the result is below `p`.
macro_rules! f_csub {
    () => {
        concat!(
            "mov edx, 0xffffffff\n",
            "mov rax, r12\n",
            "sub rax, -1\n",
            "mov rcx, r13\n",
            "sbb rcx, rdx\n",
            "mov r8, r14\n",
            "sbb r8, 0\n",
            "mov r9, r15\n",
            "sbb r9, [rdi]\n",
            "sbb rsi, 0\n",
            "cmovnc r12, rax\n",
            "cmovnc r13, rcx\n",
            "cmovnc r14, r8\n",
            "cmovnc r15, r9\n",
        )
    };
}

/// `R ← R + m mod p` (`m` a frame address).
macro_rules! f_add {
    ($m:literal) => {
        concat!(
            "xor esi, esi\n",
            "add r12, [",
            $m,
            "]\n",
            "adc r13, [",
            $m,
            " + 8]\n",
            "adc r14, [",
            $m,
            " + 16]\n",
            "adc r15, [",
            $m,
            " + 24]\n",
            "adc rsi, 0\n",
            f_csub!(),
        )
    };
}

/// `R ← 2·R mod p`.
macro_rules! f_dbl {
    () => {
        concat!(
            "xor esi, esi\n",
            "add r12, r12\n",
            "adc r13, r13\n",
            "adc r14, r14\n",
            "adc r15, r15\n",
            "adc rsi, 0\n",
            f_csub!(),
        )
    };
}

/// `R ← R - m mod p`: on a borrow, add `p` (its limbs masked from the borrow).
macro_rules! f_sub {
    ($m:literal) => {
        concat!(
            "sub r12, [",
            $m,
            "]\n",
            "sbb r13, [",
            $m,
            " + 8]\n",
            "sbb r14, [",
            $m,
            " + 16]\n",
            "sbb r15, [",
            $m,
            " + 24]\n",
            "sbb rax, rax\n",
            "mov rcx, rax\n",
            "shr rcx, 32\n",
            "mov rdx, [rdi]\n",
            "and rdx, rax\n",
            "add r12, rax\n",
            "adc r13, rcx\n",
            "adc r14, 0\n",
            "adc r15, rdx\n",
        )
    };
}

/// `R ← m`.
macro_rules! f_ld {
    ($m:literal) => {
        concat!(
            "mov r12, [",
            $m,
            "]\n",
            "mov r13, [",
            $m,
            " + 8]\n",
            "mov r14, [",
            $m,
            " + 16]\n",
            "mov r15, [",
            $m,
            " + 24]\n",
        )
    };
}

/// `m ← R`.
macro_rules! f_st {
    ($m:literal) => {
        concat!(
            "mov [",
            $m,
            "], r12\n",
            "mov [",
            $m,
            " + 8], r13\n",
            "mov [",
            $m,
            " + 16], r14\n",
            "mov [",
            $m,
            " + 24], r15\n",
        )
    };
}

/// A Jacobian point `[X, Y, Z]` as the Montgomery-form limbs of its coordinates.
pub(crate) type JacLimbs = [[u64; 4]; 3];

/// Runs one point routine on `frame`: `frame[0] = p₃`, the coordinates from `frame[4]` on.
macro_rules! point_asm {
    ($frame:expr, $($code:expr),+ $(,)?) => {{
        let f: &mut [u64] = $frame;
        f[0] = P3;
        // SAFETY: the block reads and writes only the frame behind `rdi` (a live, exclusively
        // borrowed array; every address is `rdi` plus a constant inside it, checked against the
        // frame length by the callers' array types), and the declared registers; no stack, no
        // branches. `mulx`, `adcx` and `adox` need BMI2 and ADX: only reached through the
        // `P256X` twin, entered after `cpu::has(Feature::Adx)` (debug-asserted by the callers).
        unsafe {
            asm!(
                $($code,)+
                in("rdi") f.as_mut_ptr(),
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("rsi") _,
                out("r8") _,
                out("r9") _,
                out("r10") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(nostack),
            );
        }
    }};
}

/// Copies `p` into the frame from limb 4 on.
#[inline(always)]
fn load_point(f: &mut [u64], at: usize, p: &JacLimbs) {
    for (i, c) in p.iter().enumerate() {
        f[at + 4 * i..at + 4 * i + 4].copy_from_slice(c);
    }
}

/// The point at limb 4 of the frame.
#[inline(always)]
fn store_point(f: &[u64]) -> JacLimbs {
    let mut p = [[0u64; 4]; 3];
    for (i, c) in p.iter_mut().enumerate() {
        c.copy_from_slice(&f[4 + 4 * i..8 + 4 * i]);
    }
    p
}

/// Jacobian doubling for `a = -3` (dbl-2001-b with `Z₃ = 2·Y·Z`, 4M + 4S), as the portable
/// `Jac::double`: `δ = Z²`, `γ = Y²`, `β = X·γ`, `α = 3·(X - δ)·(X + δ)`, `X₃ = α² - 8β`,
/// `Y₃ = α·(4β - X₃) - 8γ²`. The identity (`Z = 0`) stays the identity. Constant time.
#[inline]
pub(crate) fn point_double(p: &JacLimbs) -> JacLimbs {
    point_double_n(p, 1)
}

/// `2ⁿ·p`: [`point_double`] `n` times on one frame (no copies between the doublings; `n` is
/// public).
#[inline]
pub(crate) fn point_double_n(p: &JacLimbs, n: usize) -> JacLimbs {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    // X 32, Y 64, Z 96 (in place); δ 128, γ 192, 4β 224, α 256, 3(X - δ) 288, 8γ² 320.
    // The order puts each output where the next doubling needs it first: Z₃ early (the next
    // δ), the products off the critical path δ → α → α² → X₃ → Y₃ between its steps.
    let mut f = [0u64; 44];
    load_point(&mut f, 4, p);
    for _ in 0..n {
        point_asm!(
            &mut f,
            f_sqr!("rdi + 96"),
            f_st!("rdi + 128"),
            f_sqr!("rdi + 64"),
            f_st!("rdi + 192"),
            f_ld!("rdi + 32"),
            f_add!("rdi + 128"),
            f_st!("rdi + 256"),
            f_ld!("rdi + 32"),
            f_sub!("rdi + 128"),
            f_st!("rdi + 288"),
            f_dbl!(),
            f_add!("rdi + 288"),
            f_st!("rdi + 288"),
            f_mul!("rdi + 32", "rdi + 192"),
            f_dbl!(),
            f_dbl!(),
            f_st!("rdi + 224"),
            f_mul!("rdi + 256", "rdi + 288"),
            f_st!("rdi + 256"),
            // Z₃ = 2·Y·Z (Z is not read again).
            f_mul!("rdi + 64", "rdi + 96"),
            f_dbl!(),
            f_st!("rdi + 96"),
            // X₃ = α² - 2·4β (X is not read again).
            f_sqr!("rdi + 256"),
            f_sub!("rdi + 224"),
            f_sub!("rdi + 224"),
            f_st!("rdi + 32"),
            f_sqr!("rdi + 192"),
            f_dbl!(),
            f_dbl!(),
            f_dbl!(),
            f_st!("rdi + 320"),
            f_ld!("rdi + 224"),
            f_sub!("rdi + 32"),
            f_st!("rdi + 288"),
            // Y₃ = α·(4β - X₃) - 8γ² (Y is not read again).
            f_mul!("rdi + 256", "rdi + 288"),
            f_sub!("rdi + 320"),
            f_st!("rdi + 64"),
        );
    }
    store_point(&f)
}

/// `p + q` (add-2007-bl, 11M + 5S) without special cases, as the portable `Jac::add_core`:
/// correct when neither operand is the identity and `p ≠ q`; `p = -q` gives `Z = 0`. Constant
/// time.
#[inline]
pub(crate) fn point_add(p: &JacLimbs, q: &JacLimbs) -> JacLimbs {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    // X₁ 32, Y₁ 64, Z₁ 96, X₂ 128, Y₂ 160, Z₂ 192; Z₁Z₁ 224, Z₂Z₂ 256, U₁ 288, H 320, S₁ 352,
    // r 384, scratch 416.
    let mut f = [0u64; 56];
    load_point(&mut f, 4, p);
    load_point(&mut f, 16, q);
    point_asm!(
        &mut f,
        f_sqr!("rdi + 96"),
        f_st!("rdi + 224"),
        f_sqr!("rdi + 192"),
        f_st!("rdi + 256"),
        f_mul!("rdi + 32", "rdi + 256"),
        f_st!("rdi + 288"),
        // H = U₂ - U₁.
        f_mul!("rdi + 128", "rdi + 224"),
        f_sub!("rdi + 288"),
        f_st!("rdi + 320"),
        f_mul!("rdi + 64", "rdi + 192"),
        f_st!("rdi + 352"),
        f_mul!("rdi + 352", "rdi + 256"),
        f_st!("rdi + 352"),
        // r = 2·(S₂ - S₁).
        f_mul!("rdi + 160", "rdi + 96"),
        f_st!("rdi + 384"),
        f_mul!("rdi + 384", "rdi + 224"),
        f_sub!("rdi + 352"),
        f_dbl!(),
        f_st!("rdi + 384"),
        // Z₃ = ((Z₁ + Z₂)² - Z₁Z₁ - Z₂Z₂)·H (Z₁ is not read again).
        f_ld!("rdi + 96"),
        f_add!("rdi + 192"),
        f_st!("rdi + 416"),
        f_sqr!("rdi + 416"),
        f_sub!("rdi + 224"),
        f_sub!("rdi + 256"),
        f_st!("rdi + 416"),
        f_mul!("rdi + 416", "rdi + 320"),
        f_st!("rdi + 96"),
        // I = (2H)² over Z₁Z₁, J = H·I over Z₂Z₂, V = U₁·I over U₁.
        f_ld!("rdi + 320"),
        f_dbl!(),
        f_st!("rdi + 224"),
        f_sqr!("rdi + 224"),
        f_st!("rdi + 224"),
        f_mul!("rdi + 320", "rdi + 224"),
        f_st!("rdi + 256"),
        f_mul!("rdi + 288", "rdi + 224"),
        f_st!("rdi + 288"),
        // X₃ = r² - J - 2V.
        f_sqr!("rdi + 384"),
        f_sub!("rdi + 256"),
        f_sub!("rdi + 288"),
        f_sub!("rdi + 288"),
        f_st!("rdi + 32"),
        f_mul!("rdi + 352", "rdi + 256"),
        f_dbl!(),
        f_st!("rdi + 352"),
        // Y₃ = r·(V - X₃) - 2·S₁·J.
        f_ld!("rdi + 288"),
        f_sub!("rdi + 32"),
        f_st!("rdi + 288"),
        f_mul!("rdi + 384", "rdi + 288"),
        f_sub!("rdi + 352"),
        f_st!("rdi + 64"),
    );
    store_point(&f)
}

/// `p + (x₂, y₂)` (madd-2007-bl, 7M + 4S) without special cases, as the portable
/// `Jac::madd_core`: correct when `p` is not the identity and not `(x₂, y₂)`; `p = -(x₂, y₂)`
/// gives `Z = 0`. Constant time.
#[inline]
pub(crate) fn point_add_affine(p: &JacLimbs, x2: &[u64; 4], y2: &[u64; 4]) -> JacLimbs {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    // X₁ 32, Y₁ 64, Z₁ 96, x₂ 128, y₂ 160; Z₁Z₁ 192, H 224, scratch 256, r 288, HH 320,
    // I then J 352, V 384.
    let mut f = [0u64; 52];
    load_point(&mut f, 4, p);
    f[16..20].copy_from_slice(x2);
    f[20..24].copy_from_slice(y2);
    point_asm!(
        &mut f,
        f_sqr!("rdi + 96"),
        f_st!("rdi + 192"),
        // H = x₂·Z₁Z₁ - X₁.
        f_mul!("rdi + 128", "rdi + 192"),
        f_sub!("rdi + 32"),
        f_st!("rdi + 224"),
        // r = 2·(y₂·Z₁·Z₁Z₁ - Y₁).
        f_mul!("rdi + 160", "rdi + 96"),
        f_st!("rdi + 256"),
        f_mul!("rdi + 256", "rdi + 192"),
        f_sub!("rdi + 64"),
        f_dbl!(),
        f_st!("rdi + 288"),
        // HH = H², I = 4·HH, V = X₁·I, J = H·I.
        f_sqr!("rdi + 224"),
        f_st!("rdi + 320"),
        f_dbl!(),
        f_dbl!(),
        f_st!("rdi + 352"),
        f_mul!("rdi + 32", "rdi + 352"),
        f_st!("rdi + 384"),
        f_mul!("rdi + 224", "rdi + 352"),
        f_st!("rdi + 352"),
        // Z₃ = (Z₁ + H)² - Z₁Z₁ - HH.
        f_ld!("rdi + 96"),
        f_add!("rdi + 224"),
        f_st!("rdi + 256"),
        f_sqr!("rdi + 256"),
        f_sub!("rdi + 192"),
        f_sub!("rdi + 320"),
        f_st!("rdi + 96"),
        // X₃ = r² - J - 2V.
        f_sqr!("rdi + 288"),
        f_sub!("rdi + 352"),
        f_sub!("rdi + 384"),
        f_sub!("rdi + 384"),
        f_st!("rdi + 32"),
        f_mul!("rdi + 64", "rdi + 352"),
        f_dbl!(),
        f_st!("rdi + 192"),
        // Y₃ = r·(V - X₃) - 2·Y₁·J.
        f_ld!("rdi + 384"),
        f_sub!("rdi + 32"),
        f_st!("rdi + 384"),
        f_mul!("rdi + 288", "rdi + 384"),
        f_sub!("rdi + 192"),
        f_st!("rdi + 64"),
    );
    store_point(&f)
}

/// 59 Bernstein–Yang divsteps in assembly: [`crate::safegcd::divsteps_59`] step for step, the
/// conditions turned into masks by `sar`/`neg` (no `black_box` round trip through memory), so
/// constant time by construction; the only branch is the loop counter. Base x86_64
/// instructions only.
pub(crate) fn divsteps_59(zeta: i64, f0: u64, g0: u64) -> (i64, crate::safegcd::Trans) {
    let (mut zeta, mut f, mut g) = (zeta as u64, f0, g0);
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    // SAFETY: registers only (no memory, no stack); base x86_64 instructions.
    unsafe {
        asm!(
            "mov ecx, 59",
            "2:",
            // c1 = δ > 0 (ζ < 0), c2 = g odd.
            "mov {c1}, {zeta}",
            "sar {c1}, 63",
            "mov {c2}, {g}",
            "and {c2}, 1",
            "neg {c2}",
            // (x, y, z) = ±(f, u, v); g, q, r += them where g is odd.
            "mov {x}, {f}",
            "xor {x}, {c1}",
            "sub {x}, {c1}",
            "mov {y}, {u}",
            "xor {y}, {c1}",
            "sub {y}, {c1}",
            "mov {z}, {v}",
            "xor {z}, {c1}",
            "sub {z}, {c1}",
            "and {x}, {c2}",
            "add {g}, {x}",
            "and {y}, {c2}",
            "add {q}, {y}",
            "and {z}, {c2}",
            "add {r}, {z}",
            // Both: ζ ← -ζ - 2 (δ ← 1 - δ) and f, u, v ← old g, q, r.
            "and {c1}, {c2}",
            "xor {zeta}, {c1}",
            "sub {zeta}, 1",
            "mov {x}, {g}",
            "and {x}, {c1}",
            "add {f}, {x}",
            "mov {y}, {q}",
            "and {y}, {c1}",
            "add {u}, {y}",
            "mov {z}, {r}",
            "and {z}, {c1}",
            "add {v}, {z}",
            "shr {g}, 1",
            "shl {u}, 1",
            "shl {v}, 1",
            "dec ecx",
            "jnz 2b",
            zeta = inout(reg) zeta,
            f = inout(reg) f,
            g = inout(reg) g,
            u = inout(reg) u,
            v = inout(reg) v,
            q = inout(reg) q,
            r = inout(reg) r,
            c1 = out(reg) _,
            c2 = out(reg) _,
            x = out(reg) _,
            y = out(reg) _,
            z = out(reg) _,
            out("rcx") _,
            options(pure, nomem, nostack),
        );
    }
    let _ = (f, g);
    (
        zeta as i64,
        crate::safegcd::Trans {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

/// `a⁻¹·R` from the Montgomery form `a·R` (`0` maps to `0`) by safegcd with the assembly
/// divsteps: the integer inverse `(aR)⁻¹ = a⁻¹R⁻¹`, then one Montgomery multiplication by `R³`.
#[inline]
pub(crate) fn mont_inv_safegcd<M: Modulus<4>>(a: &[u64; 4]) -> [u64; 4] {
    crate::safegcd::mont_inv_with::<M>(a, divsteps_59)
}

// Table scans with AVX2: every entry is read with 256-bit loads and kept or dropped by a mask
// from `vpcmpeqq` of its (public) index against the broadcast secret digit, then OR-ed into the
// result; no branch and no address depends on the digit.

/// `table[d - 1]` for `d ∈ [1, 16]`, the point `(0, 0, 0)` (`Z = 0`, the identity) for
/// `d = 0`, reading every entry: [`Jac::lookup_scan`] with AVX2 when the CPU has it.
#[inline]
pub(crate) fn lookup_jac(table: &[Jac<P256X, 4>; 16], d: u64) -> Jac<P256X, 4> {
    if cpu::cpu_has(Feature::Avx2) {
        // SAFETY: the CPU has AVX2 (checked just above).
        return Jac::from_raw(unsafe { lookup_jac_avx2(table, d) });
    }
    Jac::lookup_scan(table, d)
}

/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
// The intrinsics are `unsafe fn`s at the MSRV (1.85) and safe inside `avx2` code on newer
// compilers.
#[allow(unused_unsafe)]
unsafe fn lookup_jac_avx2(table: &[Jac<P256X, 4>; 16], d: u64) -> JacLimbs {
    // SAFETY: AVX2 (the caller's contract); register-only intrinsics plus unaligned 32-byte
    // loads from the 4-limb arrays of live table entries and stores into the local result.
    unsafe {
        let idx = _mm256_set1_epi64x(d as i64);
        let mut acc = [_mm256_setzero_si256(); 3];
        for (j, e) in table.iter().enumerate() {
            let m = _mm256_cmpeq_epi64(_mm256_set1_epi64x(j as i64 + 1), idx);
            for (a, c) in acc.iter_mut().zip([&e.x.l, &e.y.l, &e.z.l]) {
                let v = _mm256_loadu_si256(c.as_ptr().cast());
                *a = _mm256_or_si256(*a, _mm256_and_si256(m, v));
            }
        }
        let mut out = [[0u64; 4]; 3];
        for (o, a) in out.iter_mut().zip(acc) {
            _mm256_storeu_si256(o.as_mut_ptr().cast(), a);
        }
        out
    }
}

/// `row[d - 1]` for `d ∈ [1, E]`, `(0, 0)` for `d = 0`, reading every entry with AVX2.
///
/// # Safety
///
/// The CPU must support AVX2.
#[target_feature(enable = "avx2")]
#[allow(unused_unsafe)]
unsafe fn lookup_affine_avx2<const E: usize>(row: &[[[u64; 4]; 2]; E], d: u64) -> [[u64; 4]; 2] {
    // SAFETY: as in `lookup_jac_avx2`, over the entries of `row`.
    unsafe {
        let idx = _mm256_set1_epi64x(d as i64);
        let one = _mm256_set1_epi64x(1);
        let mut j = _mm256_setzero_si256();
        let (mut x, mut y) = (_mm256_setzero_si256(), _mm256_setzero_si256());
        for e in row {
            j = _mm256_add_epi64(j, one);
            let m = _mm256_cmpeq_epi64(j, idx);
            x = _mm256_or_si256(
                x,
                _mm256_and_si256(m, _mm256_loadu_si256(e[0].as_ptr().cast())),
            );
            y = _mm256_or_si256(
                y,
                _mm256_and_si256(m, _mm256_loadu_si256(e[1].as_ptr().cast())),
            );
        }
        let mut out = [[0u64; 4]; 2];
        _mm256_storeu_si256(out[0].as_mut_ptr().cast(), x);
        _mm256_storeu_si256(out[1].as_mut_ptr().cast(), y);
        out
    }
}

/// The window width of the wide fixed-base comb.
pub(crate) const COMB_W: usize = 6;
/// Entries per window, `2^(W-1)`.
const COMB_E: usize = 1 << (COMB_W - 1);
/// Windows over a 256-bit scalar (the top one's sign bit above the scalar).
const COMB_ROWS: usize = super::booth_windows(4, COMB_W);

/// One window of the wide comb: `row[j - 1] = j·2^(W·i)·G` for `1 ≤ j ≤ E`, affine,
/// Montgomery-form limbs.
type CombRow = [[[u64; 4]; 2]; COMB_E];

/// The wide comb (`COMB_ROWS · COMB_E` points, 64 bytes each), built once: projective
/// multiples, then one batched inversion.
fn comb() -> &'static [CombRow] {
    static T: OnceLock<Vec<CombRow>> = OnceLock::new();
    T.get_or_init(|| {
        let mut pts = Vec::with_capacity(COMB_ROWS * COMB_E);
        let mut p = Point::<P256X, 4>::generator();
        for _ in 0..COMB_ROWS {
            let mut q = p;
            for _ in 0..COMB_E {
                pts.push(q);
                q = q.add(&p);
            }
            // 2^W·p = (E·p) doubled.
            p = pts[pts.len() - 1].double();
        }
        let aff = Point::batch_to_affine(&pts);
        aff.chunks_exact(COMB_E)
            .map(|c| {
                let mut row = [[[0u64; 4]; 2]; COMB_E];
                for (r, (x, y)) in row.iter_mut().zip(c) {
                    *r = [x.l, y.l];
                }
                row
            })
            .collect()
    })
}

/// `[k]G` for a secret `k`, in constant time, from the wide comb: Booth-recoded signed
/// `W`-bit digits `k = Σ dᵢ·2^(W·i)`, `dᵢ ∈ [-2^(W-1), 2^(W-1)]` (37 windows for `W = 7`), one
/// mixed addition per window and no doublings (ring's and OpenSSL's `ecp_nistz256` layout).
/// Each window's row is read in full with AVX2 masks, the entry negated by a masked select;
/// the addition of a zero digit is computed and discarded by a masked select, and an
/// accumulator still at the identity takes the entry by a masked select (`Jac::madd_ct`).
///
/// The addition never meets equal operands. Before window `j` the accumulator is
/// `Sⱼ = Σ_{i<j} dᵢ·2^(Wi)` (times `G`) with `|Sⱼ| ≤ 2^(W-1)·(2^(Wj) - 1)/(2^W - 1) <
/// 0.51·2^(Wj)`; it is the identity exactly when every lower digit is zero (the masked case).
/// The entry is `±dⱼ·2^(Wj)` with `1 ≤ |dⱼ| ≤ 2^(W-1)`, so `0 < |Sⱼ ∓ dⱼ·2^(Wj)| <
/// (2^(W-1) + 0.51)·2^(Wj)`, below `2^252 < n` for every window but the last (`W·j ≤ 245`):
/// never `≡ 0 (mod n)`. In the last window (`W·j = 252`, digit `D ∈ [0, 16]`, `Sⱼ = k - D·2^252`)
/// equality means `k ≡ D·2^253 (mod n)`: for `D ≤ 7` that is `k = D·2^253`, whose top digit is
/// `2D ≠ D`; for `8 ≤ D ≤ 15`, `k = D·2^253 - n = (2D - 16)·2^252 + (2^256 - n)` (and
/// `2^256 - n < 2^224`), top digit `2D - 16 ≠ D`; for `D = 16`, `k = 2^257 - 2n < 2^225`, top
/// digit 0. So no scalar meets equal operands; `Sⱼ ≡ -dⱼ·2^(Wj)` would need `k ≡ 0`.
///
/// Without AVX2 this is [`Jac::mul_base_ct`] (the 4-bit comb with scalar scans).
pub(crate) fn mul_base(k: &Scalar<P256X, 4>) -> Jac<P256X, 4> {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    if !cpu::cpu_has(Feature::Avx2) {
        return Jac::mul_base_ct(k);
    }
    let k = k.to_limbs();
    let mut r = Jac::<P256X, 4>::identity();
    for (i, row) in comb().iter().enumerate() {
        let (d, neg) = super::booth::<4, COMB_W>(&k, i);
        // SAFETY: the CPU has AVX2 (checked above).
        let e = unsafe { lookup_affine_avx2(row, d) };
        let x = Fe::from_mont(e[0]);
        let y = Fe::from_mont(e[1]);
        let y = Fe::select(neg, &y.neg(), &y);
        // d = 0 selected (0, 0), off the curve: the sum is discarded.
        let sum = r.madd_ct(&x, &y);
        r = Jac::select(ct::is_zero(d) ^ u64::MAX, &sum, &r);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves::{P256N, P256P};

    /// Random values below `m` plus the edges (0, 1, m - 1, m - 2, limbs of all ones or zeros).
    fn values(m: &[u64; 4]) -> Vec<[u64; 4]> {
        let mut vals: Vec<[u64; 4]> = vec![
            [0; 4],
            [1, 0, 0, 0],
            crate::field::sub_small(m, 1),
            crate::field::sub_small(m, 2),
            [u64::MAX, 0, 0, 0],
            [0, 0, 0, m[3] - 1],
            [u64::MAX, 0xffff_ffff, 0, 0],
            [0, 0xffff_ffff, u64::MAX, m[3] - 1],
            [u64::MAX, u64::MAX, u64::MAX, m[3] - 1],
        ];
        let mut rng = crate::rand::ChaChaRng::from_seed([0x5a; 32]);
        for _ in 0..2000 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let mut l = crate::field::be_to_limbs::<4>(&b).unwrap_or([0; 4]);
            if ct::lt_limbs(&l, m) == 0 {
                l[3] &= 0x7fff_ffff_ffff_ffff;
            }
            vals.push(l);
        }
        vals
    }

    /// Against the portable arithmetic.
    #[test]
    fn matches_portable() {
        if !cpu::cpu_has(Feature::Adx) {
            return;
        }
        let vals = values(&P256P::P);
        for (i, a) in vals.iter().enumerate() {
            let b = &vals[(i * 7 + 3) % vals.len()];
            for (x, y) in [(a, b), (b, a), (a, a)] {
                assert_eq!(mul(x, y), P256P::mont_mul(x, y), "mul {x:x?} {y:x?}");
                assert_eq!(add(x, y), P256P::mod_add(x, y), "add {x:x?} {y:x?}");
                assert_eq!(sub(x, y), P256P::mod_sub(x, y), "sub {x:x?} {y:x?}");
            }
            assert_eq!(mul3(a), P256P::mod_mul3(a), "mul3 {a:x?}");
            for k in 0..6 {
                assert_eq!(
                    P256Px::mod_mul_pow2(a, k),
                    P256P::mod_mul_pow2(a, k),
                    "2^{k} {a:x?}"
                );
            }
            assert_eq!(sqr(a), P256P::mont_sqr(a), "sqr {a:x?}");
            // P256P::mont_inv itself dispatches here: compare with the portable chain.
            assert_eq!(
                P256Px::mont_inv(a),
                Some(crate::ec::curves::p256_inv::<P256P>(a)),
                "inv {a:x?} (Montgomery form)"
            );
        }
        // Unreduced first operand below 2²⁵⁶ (from_limbs_reduce multiplies by R² < p).
        let big = [u64::MAX; 4];
        assert_eq!(mul(&big, &P256P::R2), P256P::mont_mul(&big, &P256P::R2));

        assert_eq!(NINV, P256N::N0);
        assert_eq!(P256Nx::P, P256N::P);
        let vals = values(&P256N::P);
        let generic =
            |x: &[u64; 4], y: &[u64; 4]| crate::field::mont_mul_cios(x, y, &P256N::P, P256N::N0);
        for (i, a) in vals.iter().enumerate() {
            let b = &vals[(i * 5 + 1) % vals.len()];
            for (x, y) in [(a, b), (b, a), (a, a)] {
                assert_eq!(ord_mul(x, y), generic(x, y), "ord_mul {x:x?} {y:x?}");
            }
            assert_eq!(ord_sqr(a), generic(a, a), "ord_sqr {a:x?}");
        }
        assert_eq!(ord_mul(&big, &P256N::R2), generic(&big, &P256N::R2));
    }

    use crate::ec::curves::{P256, P256X};
    use crate::ec::{Jac, Point, Scalar};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Jacobian points for the differential tests: random multiples of `G` with random `Z`
    /// (scaled by `λ²`, `λ³`, `λ`), every valid public key of Wycheproof's P-256 ECDH vectors
    /// (`Z = 1`), the identity in two forms, and `G` with `Z = 1`.
    fn jac_points() -> Vec<Jac<P256, 4>> {
        let mut rng = crate::rand::ChaChaRng::from_seed([0x3c; 32]);
        let mut scalar = || {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            Scalar::<P256, 4>::from_be_bytes_reduce(&b).unwrap()
        };
        let mut pts = vec![
            Jac::identity(),
            Jac::from_raw([[0; 4]; 3]),
            Jac::from_point(&Point::<P256, 4>::generator()),
        ];
        for _ in 0..64 {
            let k = scalar();
            let lambda = Fe::<P256P, 4>::from_mont(scalar().l);
            let j = Jac::from_point(&Point::<P256, 4>::mul_base_ref(&k));
            let l2 = lambda.square();
            pts.push(Jac {
                x: j.x.mul(&l2),
                y: j.y.mul(&l2).mul(&lambda),
                z: j.z.mul(&lambda),
            });
        }
        let json = include_str!("../../tests/data/wycheproof_ecdh_secp256r1_ecpoint.json");
        for part in json.split("\"public\":\"").skip(1) {
            let hex = &part[..part.find('"').unwrap()];
            if let Some(p) = Point::<P256, 4>::from_sec1(&unhex(hex)) {
                pts.push(Jac::from_point(&p));
            }
        }
        pts
    }

    /// The whole-point routines against the portable formulas, limb for limb (both are the
    /// same formulas over fully reduced values): random points, Wycheproof points, `P + P`,
    /// `P + (-P)` and the identity on either side.
    #[test]
    fn points_match_portable() {
        if !cpu::cpu_has(Feature::Adx) {
            return;
        }
        let pts = jac_points();
        assert!(pts.len() > 64 + 3 + 20, "{} points", pts.len());
        for (i, p) in pts.iter().enumerate() {
            assert_eq!(point_double(&p.raw()), p.double_formula().raw(), "2P {i}");
            let mut p5 = *p;
            for _ in 0..5 {
                p5 = p5.double_formula();
            }
            assert_eq!(point_double_n(&p.raw(), 5), p5.raw(), "32P {i}");
            let neg = Jac::<P256, 4> {
                x: p.x,
                y: p.y.neg(),
                z: p.z,
            };
            let q = pts[(i * 7 + 5) % pts.len()];
            for q in [q, *p, neg, Jac::identity()] {
                assert_eq!(
                    point_add(&p.raw(), &q.raw()),
                    p.add_core_formula(&q).raw(),
                    "P + Q {i}"
                );
                assert_eq!(
                    point_add(&q.raw(), &p.raw()),
                    q.add_core_formula(p).raw(),
                    "Q + P {i}"
                );
                if let Some((x, y)) = q.to_affine() {
                    assert_eq!(
                        point_add_affine(&p.raw(), &x.l, &y.l),
                        p.madd_core_formula(&x, &y).raw(),
                        "P + affine Q {i}"
                    );
                }
            }
            if p.z.is_zero() == 0 {
                let s = point_add(&p.raw(), &neg.raw());
                assert_eq!(s[2], [0; 4], "P + (-P) has Z = 0");
                let (x, y) = p.to_affine().unwrap();
                let s = point_add_affine(&neg.raw(), &x.l, &y.l);
                assert_eq!(s[2], [0; 4], "-P + affine P has Z = 0");
            }
        }
    }

    /// Nanoseconds per operation, the whole-point routines against the previous formulas over
    /// the assembly field (`P256X`'s portable formulas): `cargo test --release -p only-crypto
    /// --lib ec::hw::tests::timings -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing report"]
    fn timings() {
        use std::hint::black_box;
        use std::time::Instant;
        if !cpu::has(Feature::Adx) {
            return;
        }
        let only = std::env::var("ONLY_TIMING").ok();
        let reps: u32 = std::env::var("ONLY_TIMING_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let time = |name: &str, n: u32, mut f: &mut dyn FnMut()| {
            if let Some(o) = &only {
                if o != name {
                    return;
                }
                for _ in 0..reps {
                    f();
                }
                return;
            }
            time(name, n, &mut f);
        };
        fn time(name: &str, n: u32, f: &mut dyn FnMut()) {
            for _ in 0..n / 10 {
                f();
            }
            let mut best = f64::MAX;
            for _ in 0..5 {
                let t = Instant::now();
                for _ in 0..n {
                    f();
                }
                best = best.min(t.elapsed().as_nanos() as f64 / f64::from(n));
            }
            println!("{name:<32} {best:>10.1} ns");
        }
        let pts: Vec<Jac<P256X, 4>> = jac_points()
            .iter()
            .map(|p| Jac::from_raw(p.raw()))
            .collect();
        let (p, q) = (pts[5], pts[9]);
        let (x2, y2) = q.to_affine().unwrap();
        time("double (formula)", 200_000, &mut || {
            black_box(black_box(&p).double_formula());
        });
        time("double (asm)", 200_000, &mut || {
            black_box(point_double(&black_box(&p).raw()));
        });
        let mut r = p;
        time("double chain (formula)", 200_000, &mut || {
            r = r.double_formula();
        });
        let mut r = p.raw();
        time("double chain (asm)", 200_000, &mut || {
            r = point_double(&r);
        });
        let mut r = p.raw();
        time("double x5 (asm)", 40_000, &mut || {
            r = point_double_n(&r, 5);
        });
        let mut r = p;
        time("add chain (formula)", 200_000, &mut || {
            r = r.add_core_formula(&q);
        });
        let mut r = p.raw();
        time("add chain (asm)", 200_000, &mut || {
            r = point_add(&r, &q.raw());
        });
        black_box(r);
        time("add_core (formula)", 200_000, &mut || {
            black_box(black_box(&p).add_core_formula(&q));
        });
        time("add_core (asm)", 200_000, &mut || {
            black_box(point_add(&black_box(&p).raw(), &q.raw()));
        });
        time("madd_core (formula)", 200_000, &mut || {
            black_box(black_box(&p).madd_core_formula(&x2, &y2));
        });
        time("madd_core (asm)", 200_000, &mut || {
            black_box(point_add_affine(&black_box(&p).raw(), &x2.l, &y2.l));
        });
        let mut b = [0x5au8; 32];
        b[0] = 0x7f;
        let k = Scalar::<P256X, 4>::from_be_bytes_reduce(&b).unwrap();
        let g = Point::<P256X, 4>::generator();
        time("mul_base_ct", 20_000, &mut || {
            black_box(Jac::<P256X, 4>::mul_base_ct(black_box(&k)));
        });
        time("jac_mul_base", 20_000, &mut || {
            black_box(<P256X as crate::ec::Curve<4>>::jac_mul_base(black_box(&k)));
        });
        time("mul_ct", 5_000, &mut || {
            black_box(Jac::<P256X, 4>::mul_ct(&g, black_box(&k)));
        });
        time("scalar invert", 20_000, &mut || {
            black_box(black_box(k).invert());
        });
        time("scalar mul", 1_000_000, &mut || {
            black_box(black_box(k).mul(&k));
        });
        time("scalar square", 1_000_000, &mut || {
            black_box(black_box(k).square());
        });
        let nmod = crate::safegcd::Modulus256::new(&P256Nx::P);
        time("scalar invert (safegcd)", 20_000, &mut || {
            black_box(crate::safegcd::inv(&black_box(k).l, &nmod));
        });
        let pmod = crate::safegcd::Modulus256::new(&P256Px::P);
        time("field invert (safegcd)", 20_000, &mut || {
            black_box(crate::safegcd::inv(&black_box(q.z).l, &pmod));
        });
        let z = q.z;
        time("field invert", 20_000, &mut || {
            black_box(black_box(z).invert());
        });
        time("field square", 1_000_000, &mut || {
            black_box(black_box(z).square());
        });
    }
}
