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

use crate::cpu::{self, Feature};
use crate::field::Modulus;

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

    fn mont_inv(a: &[u64; 4]) -> Option<[u64; 4]> {
        Some(super::curves::p256_inv::<Self>(a))
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
const NINV: u64 = 0xccd1_c8aa_ee00_bc4f;

/// The 512-bit product `a·b` into `z0..z7` = `r8..r15` (pointers in `{a}`, `{b}`; clobbers `rax`,
/// `rcx`, `rdx`): one row per limb of `b`, the low halves of `a·bᵢ` on the CF chain (`adcx`), the
/// high halves on the OF chain (`adox`). Each row's top limb is `hi(a₃·bᵢ)` plus the two pending
/// carries, which cannot overflow (the partial product fits its limbs).
macro_rules! mul_rows {
    () => {
        concat!(
            "mov rdx, [{b}]\n",
            "mulx r9, r8, [{a}]\n",
            "mulx r10, rax, [{a} + 8]\n",
            "add r9, rax\n",
            "mulx r11, rax, [{a} + 16]\n",
            "adc r10, rax\n",
            "mulx r12, rax, [{a} + 24]\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            //
            "mov rdx, [{b} + 8]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [{a}]\n",
            "adcx r9, rax\n",
            "adox r10, rcx\n",
            "mulx rcx, rax, [{a} + 8]\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx rcx, rax, [{a} + 16]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx r13, rax, [{a} + 24]\n",
            "adcx r12, rax\n",
            "mov eax, 0\n",
            "adox r13, rax\n",
            "adcx r13, rax\n",
            //
            "mov rdx, [{b} + 16]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [{a}]\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx rcx, rax, [{a} + 8]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx rcx, rax, [{a} + 16]\n",
            "adcx r12, rax\n",
            "adox r13, rcx\n",
            "mulx r14, rax, [{a} + 24]\n",
            "adcx r13, rax\n",
            "mov eax, 0\n",
            "adox r14, rax\n",
            "adcx r14, rax\n",
            //
            "mov rdx, [{b} + 24]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [{a}]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx rcx, rax, [{a} + 8]\n",
            "adcx r12, rax\n",
            "adox r13, rcx\n",
            "mulx rcx, rax, [{a} + 16]\n",
            "adcx r13, rax\n",
            "adox r14, rcx\n",
            "mulx r15, rax, [{a} + 24]\n",
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
        concat!(
            // Cross products aᵢ·aⱼ (i < j) into limbs 1..6 (r9..r14).
            "mov rdx, [{a}]\n",
            "mulx r10, r9, [{a} + 8]\n",
            "mulx r11, rax, [{a} + 16]\n",
            "add r10, rax\n",
            "mulx r12, rax, [{a} + 24]\n",
            "adc r11, rax\n",
            "adc r12, 0\n",
            "mov rdx, [{a} + 8]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, [{a} + 16]\n",
            "adcx r11, rax\n",
            "adox r12, rcx\n",
            "mulx r13, rax, [{a} + 24]\n",
            "adcx r12, rax\n",
            "mov eax, 0\n",
            "adox r13, rax\n",
            "adcx r13, rax\n",
            "mov rdx, [{a} + 16]\n",
            "mulx r14, rax, [{a} + 24]\n",
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
            "mov rdx, [{a}]\n",
            "mulx rcx, r8, rdx\n",
            "add r9, rcx\n",
            "mov rdx, [{a} + 8]\n",
            "mulx rcx, rax, rdx\n",
            "adc r10, rax\n",
            "adc r11, rcx\n",
            "mov rdx, [{a} + 16]\n",
            "mulx rcx, rax, rdx\n",
            "adc r12, rax\n",
            "adc r13, rcx\n",
            "mov rdx, [{a} + 24]\n",
            "mulx rcx, rax, rdx\n",
            "adc r14, rax\n",
            "adc r15, rcx\n",
        )
    };
}

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

/// `a + b mod p` for `a, b < p`.
#[inline]
pub(crate) fn add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind each of `a` and `b` (live 32-byte arrays), writes only the
    // declared registers. Base x86_64 instructions only (`cmov` included).
    unsafe {
        asm!(
            "mov {r0}, [{a}]",
            "mov {r1}, [{a} + 8]",
            "mov {r2}, [{a} + 16]",
            "mov {r3}, [{a} + 24]",
            "xor {c:e}, {c:e}",
            "add {r0}, [{b}]",
            "adc {r1}, [{b} + 8]",
            "adc {r2}, [{b} + 16]",
            "adc {r3}, [{b} + 24]",
            "adc {c}, 0",
            // s = c·2²⁵⁶ + r < 2p: take s - p unless that borrows. {a}, {b} hold p₁ and p₃.
            "mov {a:e}, 0xffffffff",
            "mov {b}, 0xffffffff00000001",
            "mov {t0}, {r0}",
            "sub {t0}, -1",
            "mov {t1}, {r1}",
            "sbb {t1}, {a}",
            "mov {t2}, {r2}",
            "sbb {t2}, 0",
            "mov {t3}, {r3}",
            "sbb {t3}, {b}",
            "sbb {c}, 0",
            "cmovnc {r0}, {t0}",
            "cmovnc {r1}, {t1}",
            "cmovnc {r2}, {t2}",
            "cmovnc {r3}, {t3}",
            a = inout(reg) a.as_ptr() => _,
            b = inout(reg) b.as_ptr() => _,
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            c = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a - b mod p` for `a, b < p`.
#[inline]
pub(crate) fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind each of `a` and `b` (live 32-byte arrays), writes only the
    // declared registers. Base x86_64 instructions only.
    unsafe {
        asm!(
            "mov {r0}, [{a}]",
            "mov {r1}, [{a} + 8]",
            "mov {r2}, [{a} + 16]",
            "mov {r3}, [{a} + 24]",
            "sub {r0}, [{b}]",
            "sbb {r1}, [{b} + 8]",
            "sbb {r2}, [{b} + 16]",
            "sbb {r3}, [{b} + 24]",
            // m = -borrow; add p & m (p₀ = 2⁶⁴ - 1, p₁ = 2³² - 1, p₂ = 0).
            "sbb {m}, {m}",
            "mov {t1}, {m}",
            "shr {t1}, 32",
            "mov {t3}, 0xffffffff00000001",
            "and {t3}, {m}",
            "add {r0}, {m}",
            "adc {r1}, {t1}",
            "adc {r2}, 0",
            "adc {r3}, {t3}",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            m = out(reg) _,
            t1 = out(reg) _,
            t3 = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
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
            if crate::ct::lt_limbs(&l, m) == 0 {
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
            assert_eq!(sqr(a), P256P::mont_sqr(a), "sqr {a:x?}");
            assert_eq!(
                P256Px::mont_inv(a),
                P256P::mont_inv(a),
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
}
