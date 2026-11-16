//! Modular exponentiation for RSA on x86_64 with AVX-512 IFMA (`vpmadd52luq`/`vpmadd52huq` on
//! 256-bit registers), for the CRT halves of 2048-, 3072- and 4096-bit keys (moduli of 16, 24
//! and 32 limbs), one modulus at a time or both halves interleaved in one loop.
//!
//! Numbers are vectors of `D` digits of 52 bits in 64-bit lanes (`D` = 20, 32, 40: four digits
//! per `ymm` register). The core is the almost Montgomery multiplication `AMM(a, b) = a·b·2^(-52D)
//! mod m`, with the result below `2m` instead of `m` (inputs below `2m`, `4m < 2^(52D)`), so the
//! exponentiation never subtracts conditionally; one reduction at the end. Per digit `bᵢ` of `b`:
//! the low halves of `a·bᵢ` and `m·yᵢ` are added lane by lane, the lanes shift down one digit,
//! the high halves are added; the lowest digit and `yᵢ = digit₀·(-m⁻¹) mod 2⁵²` are tracked in a
//! general-purpose register (`mulx`). After the `D` steps the lanes are normalized back to 52
//! bits: one shift-and-add of the carries, then the rare second carry through a generate /
//! propagate mask computed with one scalar addition (no branch). The scheme is the one of
//! OpenSSL's `rsaz-2k-avx512` (Drucker and Gueron); the code here is new.
//!
//! The IFMA instructions are not stable intrinsics at the MSRV (1.85), so each multiplication is
//! one `asm!` block with fixed registers (`clobber_abi("C")` declares all vector and mask
//! registers clobbered). Constant time: straight-line vector code, the only branch is the loop
//! counter over the digits of `b`; the carry masks are applied with `{k}` merge masking.
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the `asm!`
//! blocks, which read the `D`-digit arrays behind `a`, `b` and `m` and write the `D`-digit
//! output. Their instructions need AVX-512 F + VL + IFMA with the OS saving the ZMM and opmask
//! state: they are reached only from [`pow`] and [`pow_x2`] (the two CRT halves interleaved)
//! after [`enabled`] (`cpu::has(Feature::Ifma)`), and every multiplication debug-asserts it.
#![allow(unsafe_code)]

use std::arch::asm;

use super::{Mont, lookup};
use crate::cpu::{self, Feature};
use crate::ct;

/// Whether to use this module: the CPU has AVX-512 IFMA (with F, BW, VL and the OS state), and
/// the portable code is not forced.
#[inline]
pub(crate) fn enabled() -> bool {
    cpu::has(Feature::Ifma)
}

const MASK52: u64 = (1 << 52) - 1;

// Register use. Zen 4 runs `vpmadd52*` on two pipes for `ymm` registers and on both at once for
// `zmm`, but only on one with a memory operand, so `a` and `m` are loaded into registers; the
// lane shifts (`valignq`) share those pipes. Each multiply-add depends on the previous value of
// its accumulator register (four cycles), so the shapes below trade registers for shorter
// chains:
//
// - 20 digits (`amm20`): `ymm`, two accumulators: ymm0-4 the products with `a`, ymm16-20 those
//   with `m` (each register takes two dependent multiply-adds per step instead of four; they are
//   added before the normalization, which then uses ymm16-20 for the carries); `a` in ymm5-9,
//   `m` in ymm10-14.
// - 32 digits (`amm32`): `ymm`, one accumulator ymm0-7, `a` in ymm8-15 (the carries of the
//   normalization), `m` in ymm16-23.
// - 40 digits (`amm40`): `zmm`, one accumulator zmm0-4, `a` in zmm8-12 (the carries), `m` in
//   zmm16-20.
// - All: register 26 the broadcast digit bᵢ, 27 the broadcast yᵢ, 28 zero, 29 the 52-bit mask, 30
//   ones, ymm15 scratch where free (`vpextrq` reaches only registers 0-15 without AVX512DQ),
//   xmm31 the output pointer during the loop. GPRs: rsi a, rdi b (advancing), r8 m, r9 out
//   (scratch in the loop), r10 k0, rax the low digit, rcx the digit counter, rdx and r11-r13,
//   r15 scratch, r14 the 52-bit mask.
//
// The low digit of the next step comes from GPRs alone: `(acc + a₀bᵢ + m₀yᵢ) >> 52`, plus digit 1
// read at the start of the step and the low halves of `a₁bᵢ` and `m₁yᵢ`, so the chain from one
// yᵢ to the next does not pass through the vector unit.

/// The scalar part of one step: broadcasts bᵢ (register 26 of width `$v`) and yᵢ (27) and leaves
/// the next low digit in rax. `$digit1` puts digit 1 (lane 1 of the accumulator) into r15.
macro_rules! amm_scalar {
    ($v:literal, $digit1:literal) => {
        concat!(
            "mov r13, qword ptr [rdi]\n",
            "vpbroadcastq ",
            $v,
            "26, r13\n",
            // Digit 1 as the step starts, plus lo(a₁·bᵢ): both off the yᵢ chain.
            $digit1,
            "mov rdx, qword ptr [rsi + 8]\n",
            "mulx r11, r9, r13\n",
            "and r9, r14\n",
            "add r15, r9\n",
            // acc += a₀·bᵢ (r12: the high half and carry), yᵢ = acc·k0 mod 2⁵².
            "mov rdx, qword ptr [rsi]\n",
            "mulx r12, r13, r13\n",
            "add rax, r13\n",
            "adc r12, 0\n",
            "mov rdx, r10\n",
            "imul rdx, rax\n",
            "and rdx, r14\n",
            "vpbroadcastq ",
            $v,
            "27, rdx\n",
            // acc = (acc + m₀·yᵢ) >> 52 + digit 1 + lo(a₁·bᵢ) + lo(m₁·yᵢ).
            "mulx r11, r13, qword ptr [r8]\n",
            "mulx rdx, r9, qword ptr [r8 + 8]\n",
            "add rax, r13\n",
            "adc r12, r11\n",
            "shr rax, 52\n",
            "shl r12, 12\n",
            "or rax, r12\n",
            "and r9, r14\n",
            "add rax, r15\n",
            "add rax, r9\n",
        )
    };
}

/// The constants, the output pointer in xmm31, the low digit and the digit counter.
macro_rules! amm_setup {
    ($v:literal, $d:literal) => {
        concat!(
            "vmovq xmm31, r9\n",
            "mov r14, {mask}\n",
            "vpbroadcastq ",
            $v,
            "29, r14\n",
            "mov eax, 1\n",
            "vpbroadcastq ",
            $v,
            "30, rax\n",
            "vpxorq ",
            $v,
            "28, ",
            $v,
            "28, ",
            $v,
            "28\n",
            "xor eax, eax\n",
            "mov ecx, ",
            $d,
            "\n",
        )
    };
}

/// After the loop: lane 0 of the accumulator := the low digit; the first carry pass is the
/// caller's. Then (`$load` puts the output pointer into r9) the second carry where a lane exceeds 2⁵² - 1, rippling through lanes equal to
/// it (generate G, propagate P, carries in = ((G << 1) + P) ^ P, `$bits` bits per register), and
/// the stores.
macro_rules! amm_ripple {
    (
        $v:literal, $bits:literal, $load:literal, [$($rv:literal),*],
        [$(($r:literal, $off:literal)),*]
    ) => {
        concat!(
            "xor r12d, r12d\n",
            "xor r13d, r13d\n",
            $(
                "vpcmpuq k1, ", $v, $rv, ", ", $v, "29, 6\n",
                "vpcmpuq k2, ", $v, $rv, ", ", $v, "29, 0\n",
                "kmovw r11d, k1\n",
                "shl r12, ", $bits, "\n",
                "or r12, r11\n",
                "kmovw r11d, k2\n",
                "shl r13, ", $bits, "\n",
                "or r13, r11\n",
            )*
            "add r12, r12\n",
            "add r12, r13\n",
            "xor r12, r13\n",
            $load,
            $(
                "kmovw k1, r12d\n",
                "vpaddq ", $v, $r, " {{k1}}, ", $v, $r, ", ", $v, "30\n",
                "vpandq ", $v, $r, ", ", $v, $r, ", ", $v, "29\n",
                "shr r12, ", $bits, "\n",
                "vmovdqu64 ", $v, "word ptr [r9 + ", $off, "], ", $v, $r, "\n",
            )*
        )
    };
}

/// The operands of every AMM block.
macro_rules! amm_asm {
    ($out:ident, $a:ident, $b:ident, $m:ident, $k0:expr, $($t:expr),* $(,)?) => {
        asm!(
            $($t,)*
            mask = const MASK52,
            inout("rsi") $a.as_ptr() => _,
            inout("rdi") $b.as_ptr() => _,
            inout("r8") $m.as_ptr() => _,
            inout("r9") $out.as_mut_ptr() => _,
            inout("r10") $k0 => _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            clobber_abi("C"),
            options(nostack),
        )
    };
}

/// `AMM(a, b)` with two accumulators in `ymm` registers. Per register: the `a`-product
/// accumulator, the `m`-product accumulator (the carries in the normalization), the `a` and `m`
/// registers, the byte offset; then the neighbours of the one-lane shifts down (both
/// accumulators) and up (the carries), and the `a`-product registers from the top.
macro_rules! amm_dual {
    (
        $name:ident, $d:literal,
        [$(($r:literal, $c:literal, $ra:literal, $rm:literal, $off:literal)),*],
        shift: [$(($s:literal, $sn:literal)),*], last: [$($last:literal),*],
        carry: [$(($cu:literal, $cl:literal)),*], first: $first:literal,
        rev: [$($rv:literal),*]
    ) => {
        /// `out = a·b·2^(-52D) mod m`, below `2m`, digits below `2⁵²`, for `a, b < 2m` with
        /// digits below `2⁵²`, `4m < 2^(52D)` and `k0 = -m⁻¹ mod 2⁵²`.
        fn $name(out: &mut [u64; $d], a: &[u64; $d], b: &[u64; $d], m: &[u64; $d], k0: u64) {
            debug_assert!(cpu::cpu_has(Feature::Ifma));
            // SAFETY: reads the D digits behind `a`, `b` and `m` (live arrays; `b` one digit at a
            // time, the counter stops after D) and writes the D digits behind `out` (an
            // exclusive borrow), all with unaligned accesses; no stack. The vector and mask
            // registers and the caller-saved GPRs are declared clobbered (`clobber_abi("C")`),
            // r11-r15 explicitly. AVX-512 F/VL/IFMA with the OS state: reached only after
            // `enabled()` (asserted in debug builds above).
            unsafe {
                amm_asm!(
                    out, a, b, m, k0,
                    amm_setup!("ymm", $d),
                    $(concat!("vmovdqu64 ymm", $ra, ", ymmword ptr [rsi + ", $off, "]"),)*
                    $(concat!("vmovdqu64 ymm", $rm, ", ymmword ptr [r8 + ", $off, "]"),)*
                    $(concat!("vpxorq ymm", $r, ", ymm", $r, ", ymm", $r),)*
                    $(concat!("vpxorq ymm", $c, ", ymm", $c, ", ymm", $c),)*
                    "2:",
                    amm_scalar!("ymm", "vpaddq ymm15, ymm0, ymm16\nvpextrq r15, xmm15, 1\n"),
                    // Low halves into lane j.
                    $(concat!("vpmadd52luq ymm", $r, ", ymm26, ymm", $ra),)*
                    $(concat!("vpmadd52luq ymm", $c, ", ymm27, ymm", $rm),)*
                    // Divide by 2⁵²: every lane down by one.
                    $(concat!("valignq ymm", $s, ", ymm", $sn, ", ymm", $s, ", 1"),)*
                    $(concat!("valignq ymm", $last, ", ymm28, ymm", $last, ", 1"),)*
                    // High halves into lane j (digit j + 1 before the shift).
                    $(concat!("vpmadd52huq ymm", $r, ", ymm26, ymm", $ra),)*
                    $(concat!("vpmadd52huq ymm", $c, ", ymm27, ymm", $rm),)*
                    "lea rdi, [rdi + 8]",
                    "dec ecx",
                    "jnz 2b",
                    // One accumulator; lane 0 is the low digit.
                    $(concat!("vpaddq ymm", $r, ", ymm", $r, ", ymm", $c),)*
                    "mov r11d, 1",
                    "kmovw k1, r11d",
                    "vpbroadcastq ymm0 {{k1}}, rax",
                    // Normalize: carries up one lane, then the ripple.
                    $(concat!("vpsrlq ymm", $c, ", ymm", $r, ", 52"),)*
                    $(concat!("vpandq ymm", $r, ", ymm", $r, ", ymm29"),)*
                    $(concat!("valignq ymm", $cu, ", ymm", $cu, ", ymm", $cl, ", 3"),)*
                    concat!("valignq ymm", $first, ", ymm", $first, ", ymm28, 3"),
                    $(concat!("vpaddq ymm", $r, ", ymm", $r, ", ymm", $c),)*
                    amm_ripple!("ymm", "4", "vmovq r9, xmm31\n", [$($rv),*], [$(($r, $off)),*]),
                    "vzeroupper",
                )
            }
        }
    };
}

/// `AMM(a, b)` with one accumulator in `$v` registers (`$up` the lanes per register minus one,
/// `$bits` the lanes per register). Per register: the accumulator, the `a` register (the carries
/// in the normalization), the `m` register, the byte offset; then the shift neighbours as for
/// `amm_dual`.
macro_rules! amm_single {
    (
        $name:ident, $d:literal, $v:literal, $up:literal, $bits:literal,
        [$(($r:literal, $ra:literal, $rm:literal, $off:literal)),*],
        shift: [$(($s:literal, $sn:literal)),*], last: $last:literal,
        carry: [$(($cu:literal, $cl:literal)),*], first: $first:literal,
        rev: [$($rv:literal),*]
    ) => {
        /// `out = a·b·2^(-52D) mod m`, below `2m`, digits below `2⁵²`, for `a, b < 2m` with
        /// digits below `2⁵²`, `4m < 2^(52D)` and `k0 = -m⁻¹ mod 2⁵²`.
        fn $name(out: &mut [u64; $d], a: &[u64; $d], b: &[u64; $d], m: &[u64; $d], k0: u64) {
            debug_assert!(cpu::cpu_has(Feature::Ifma));
            // SAFETY: as for `amm20`: reads the D digits behind `a`, `b` and `m`, writes the D
            // digits behind `out`; no stack; every register used is declared clobbered; reached
            // only after `enabled()`.
            unsafe {
                amm_asm!(
                    out, a, b, m, k0,
                    amm_setup!($v, $d),
                    $(concat!("vmovdqu64 ", $v, $ra, ", ", $v, "word ptr [rsi + ", $off, "]"),)*
                    $(concat!("vmovdqu64 ", $v, $rm, ", ", $v, "word ptr [r8 + ", $off, "]"),)*
                    $(concat!("vpxorq ", $v, $r, ", ", $v, $r, ", ", $v, $r),)*
                    "2:",
                    amm_scalar!($v, "vpextrq r15, xmm0, 1\n"),
                    $(concat!("vpmadd52luq ", $v, $r, ", ", $v, "26, ", $v, $ra),)*
                    $(concat!("vpmadd52luq ", $v, $r, ", ", $v, "27, ", $v, $rm),)*
                    $(concat!("valignq ", $v, $s, ", ", $v, $sn, ", ", $v, $s, ", 1"),)*
                    concat!("valignq ", $v, $last, ", ", $v, "28, ", $v, $last, ", 1"),
                    $(concat!("vpmadd52huq ", $v, $r, ", ", $v, "26, ", $v, $ra),)*
                    $(concat!("vpmadd52huq ", $v, $r, ", ", $v, "27, ", $v, $rm),)*
                    "lea rdi, [rdi + 8]",
                    "dec ecx",
                    "jnz 2b",
                    "mov r11d, 1",
                    "kmovw k1, r11d",
                    concat!("vpbroadcastq ", $v, "0 {{k1}}, rax"),
                    $(concat!("vpsrlq ", $v, $ra, ", ", $v, $r, ", 52"),)*
                    $(concat!("vpandq ", $v, $r, ", ", $v, $r, ", ", $v, "29"),)*
                    $(concat!("valignq ", $v, $cu, ", ", $v, $cu, ", ", $v, $cl, ", ", $up),)*
                    concat!("valignq ", $v, $first, ", ", $v, $first, ", ", $v, "28, ", $up),
                    $(concat!("vpaddq ", $v, $r, ", ", $v, $r, ", ", $v, $ra),)*
                    amm_ripple!($v, $bits, "vmovq r9, xmm31\n", [$($rv),*], [$(($r, $off)),*]),
                    "vzeroupper",
                )
            }
        }
    };
}

amm_dual!(
    amm20, 20,
    [
        ("0", "16", "5", "10", "0"), ("1", "17", "6", "11", "32"), ("2", "18", "7", "12", "64"),
        ("3", "19", "8", "13", "96"), ("4", "20", "9", "14", "128")
    ],
    shift: [
        ("0", "1"), ("1", "2"), ("2", "3"), ("3", "4"),
        ("16", "17"), ("17", "18"), ("18", "19"), ("19", "20")
    ],
    last: ["4", "20"],
    carry: [("20", "19"), ("19", "18"), ("18", "17"), ("17", "16")], first: "16",
    rev: ["4", "3", "2", "1", "0"]
);

amm_single!(
    amm32, 32, "ymm", "3", "4",
    [
        ("0", "8", "16", "0"), ("1", "9", "17", "32"), ("2", "10", "18", "64"),
        ("3", "11", "19", "96"), ("4", "12", "20", "128"), ("5", "13", "21", "160"),
        ("6", "14", "22", "192"), ("7", "15", "23", "224")
    ],
    shift: [("0", "1"), ("1", "2"), ("2", "3"), ("3", "4"), ("4", "5"), ("5", "6"), ("6", "7")],
    last: "7",
    carry: [
        ("15", "14"), ("14", "13"), ("13", "12"), ("12", "11"), ("11", "10"), ("10", "9"),
        ("9", "8")
    ],
    first: "8",
    rev: ["7", "6", "5", "4", "3", "2", "1", "0"]
);

amm_single!(
    amm40, 40, "zmm", "7", "8",
    [
        ("0", "8", "16", "0"), ("1", "9", "17", "64"), ("2", "10", "18", "128"),
        ("3", "11", "19", "192"), ("4", "12", "20", "256")
    ],
    shift: [("0", "1"), ("1", "2"), ("2", "3"), ("3", "4")], last: "4",
    carry: [("12", "11"), ("11", "10"), ("10", "9"), ("9", "8")], first: "8",
    rev: ["4", "3", "2", "1", "0"]
);

// Two independent AMMs in one loop (`amm*_x2`), for the two CRT halves of an RSA private key:
// each step runs the scalar part and the vector part of half 1, then those of half 2. The `yᵢ`
// chains of the two halves are independent, so the out-of-order core overlaps them; one AMM
// alone waits on its chain (about 21 cycles per digit at 20 digits, for 14 cycles of vector
// work). Operands are `[half 1 | half 2]`, `m` followed by both `k0`, read from memory by the
// scalar part (r10 is the low digit of half 2). Registers, the same at every size (`$v` = ymm
// for 20 digits, zmm for 32 and 40; 5, 4 and 5 registers per number): accumulators 0-4 and 5-9
// (below 16 for `vpextrq`), `a` in 10-14 and 16-20, `m` in 21-25 and 26-30, 15 the broadcast
// bᵢ, 31 the broadcast yᵢ (shared by the halves; renaming keeps them apart). With no register
// left for zero, the top register shifts in zero lanes by zero-masking (k3). The output pointer
// waits in k7. After the loop `a` holds the carries and 28-30 the constants, as for one AMM.

/// The scalar part of one step of the half at byte offset `$o` (`$o8` = `$o` + 8), with the low
/// digit in `$acc` and its `k0` at `[r8 + $k0]`; `$digit1` puts digit 1 into r15.
macro_rules! amm_scalar_x2 {
    ($v:literal, $acc:literal, $digit1:literal, $o:literal, $o8:literal, $k0:literal) => {
        concat!(
            "mov r13, qword ptr [rdi + ",
            $o,
            "]\n",
            "vpbroadcastq ",
            $v,
            "15, r13\n",
            $digit1,
            "mov rdx, qword ptr [rsi + ",
            $o8,
            "]\n",
            "mulx r11, r9, r13\n",
            "and r9, r14\n",
            "add r15, r9\n",
            "mov rdx, qword ptr [rsi + ",
            $o,
            "]\n",
            "mulx r12, r13, r13\n",
            "add ",
            $acc,
            ", r13\n",
            "adc r12, 0\n",
            "mov rdx, qword ptr [r8 + ",
            $k0,
            "]\n",
            "imul rdx, ",
            $acc,
            "\n",
            "and rdx, r14\n",
            "vpbroadcastq ",
            $v,
            "31, rdx\n",
            "mulx r11, r13, qword ptr [r8 + ",
            $o,
            "]\n",
            "mulx rdx, r9, qword ptr [r8 + ",
            $o8,
            "]\n",
            "add ",
            $acc,
            ", r13\n",
            "adc r12, r11\n",
            "shr ",
            $acc,
            ", 52\n",
            "shl r12, 12\n",
            "or ",
            $acc,
            ", r12\n",
            "and r9, r14\n",
            "add ",
            $acc,
            ", r15\n",
            "add ",
            $acc,
            ", r9\n",
        )
    };
}

/// Two AMMs, one per half (see above). Per half: the scalar offsets, the registers (accumulator,
/// `a` = the carries afterwards, `m`, byte offset of the store), the shift neighbours, the top
/// register, the carry neighbours, the first carry register, the registers from the top.
macro_rules! amm_x2 {
    (
        $name:ident, $v:literal, $d:literal, $d2:literal, $dm:literal, $up:literal,
        $bits:literal, $lastmask:literal, k0: ($k0a:literal, $k0b:literal),
        h1: {
            o: ($o1:literal, $o18:literal), acc0: $acc1:literal, digit1: $dg1:literal,
            [$(($r1:literal, $ra1:literal, $rm1:literal, $off1:literal)),*],
            shift: [$(($s1:literal, $sn1:literal)),*], last: $last1:literal,
            carry: [$(($cu1:literal, $cl1:literal)),*], first: $first1:literal,
            rev: [$($rv1:literal),*]
        },
        h2: {
            o: ($o2:literal, $o28:literal), acc0: $acc2:literal, digit1: $dg2:literal,
            [$(($r2:literal, $ra2:literal, $rm2:literal, $off2:literal)),*],
            shift: [$(($s2:literal, $sn2:literal)),*], last: $last2:literal,
            carry: [$(($cu2:literal, $cl2:literal)),*], first: $first2:literal,
            rev: [$($rv2:literal),*]
        }
    ) => {
        /// `out = [AMM(a₁, b₁) mod m₁ | AMM(a₂, b₂) mod m₂]` for `a = [a₁ | a₂]`, `b`, `m`
        /// likewise, `m` followed by `k0₁, k0₂`; each half as for the one-AMM functions.
        fn $name(out: &mut [u64; $d2], a: &[u64; $d2], b: &[u64; $d2], m: &[u64; $dm]) {
            debug_assert!(cpu::cpu_has(Feature::Ifma));
            // SAFETY: reads the 2D digits behind `a`, `b` (one digit of each half per step, the
            // counter stops after D) and the 2D + 2 words behind `m`, writes the 2D digits
            // behind `out` (an exclusive borrow), all unaligned; no stack. The vector and mask
            // registers and the caller-saved GPRs are declared clobbered (`clobber_abi("C")`),
            // r11-r15 explicitly. AVX-512 F/BW/VL/IFMA with the OS state: reached only after
            // `enabled()` (asserted in debug builds above).
            unsafe {
                amm_asm!(
                    out, a, b, m, 0u64,
                    "kmovq k7, r9",
                    "mov r14, {mask}",
                    concat!("mov r11d, ", $lastmask),
                    "kmovw k3, r11d",
                    "xor eax, eax",
                    "xor r10d, r10d",
                    concat!("mov ecx, ", $d),
                    $(concat!("vmovdqu64 ", $v, $ra1, ", ", $v, "word ptr [rsi + ", $off1, "]"),)*
                    $(concat!("vmovdqu64 ", $v, $ra2, ", ", $v, "word ptr [rsi + ", $off2, "]"),)*
                    $(concat!("vmovdqu64 ", $v, $rm1, ", ", $v, "word ptr [r8 + ", $off1, "]"),)*
                    $(concat!("vmovdqu64 ", $v, $rm2, ", ", $v, "word ptr [r8 + ", $off2, "]"),)*
                    $(concat!("vpxorq ", $v, $r1, ", ", $v, $r1, ", ", $v, $r1),)*
                    $(concat!("vpxorq ", $v, $r2, ", ", $v, $r2, ", ", $v, $r2),)*
                    "2:",
                    amm_scalar_x2!($v, "rax", $dg1, $o1, $o18, $k0a),
                    $(concat!("vpmadd52luq ", $v, $r1, ", ", $v, "15, ", $v, $ra1),)*
                    $(concat!("vpmadd52luq ", $v, $r1, ", ", $v, "31, ", $v, $rm1),)*
                    $(concat!("valignq ", $v, $s1, ", ", $v, $sn1, ", ", $v, $s1, ", 1"),)*
                    concat!(
                        "valignq ", $v, $last1, " {{k3}}{{z}}, ", $v, $last1, ", ", $v, $last1,
                        ", 1"
                    ),
                    $(concat!("vpmadd52huq ", $v, $r1, ", ", $v, "15, ", $v, $ra1),)*
                    $(concat!("vpmadd52huq ", $v, $r1, ", ", $v, "31, ", $v, $rm1),)*
                    amm_scalar_x2!($v, "r10", $dg2, $o2, $o28, $k0b),
                    $(concat!("vpmadd52luq ", $v, $r2, ", ", $v, "15, ", $v, $ra2),)*
                    $(concat!("vpmadd52luq ", $v, $r2, ", ", $v, "31, ", $v, $rm2),)*
                    $(concat!("valignq ", $v, $s2, ", ", $v, $sn2, ", ", $v, $s2, ", 1"),)*
                    concat!(
                        "valignq ", $v, $last2, " {{k3}}{{z}}, ", $v, $last2, ", ", $v, $last2,
                        ", 1"
                    ),
                    $(concat!("vpmadd52huq ", $v, $r2, ", ", $v, "15, ", $v, $ra2),)*
                    $(concat!("vpmadd52huq ", $v, $r2, ", ", $v, "31, ", $v, $rm2),)*
                    "lea rdi, [rdi + 8]",
                    "dec ecx",
                    "jnz 2b",
                    // The constants of the normalization, in registers `m` no longer needs.
                    concat!("vpxorq ", $v, "28, ", $v, "28, ", $v, "28"),
                    concat!("vpbroadcastq ", $v, "29, r14"),
                    "mov r11d, 1",
                    concat!("vpbroadcastq ", $v, "30, r11"),
                    "kmovw k1, r11d",
                    concat!("vpbroadcastq ", $v, $acc1, " {{k1}}, rax"),
                    concat!("vpbroadcastq ", $v, $acc2, " {{k1}}, r10"),
                    $(concat!("vpsrlq ", $v, $ra1, ", ", $v, $r1, ", 52"),)*
                    $(concat!("vpandq ", $v, $r1, ", ", $v, $r1, ", ", $v, "29"),)*
                    $(concat!("valignq ", $v, $cu1, ", ", $v, $cu1, ", ", $v, $cl1, ", ", $up),)*
                    concat!("valignq ", $v, $first1, ", ", $v, $first1, ", ", $v, "28, ", $up),
                    $(concat!("vpaddq ", $v, $r1, ", ", $v, $r1, ", ", $v, $ra1),)*
                    $(concat!("vpsrlq ", $v, $ra2, ", ", $v, $r2, ", 52"),)*
                    $(concat!("vpandq ", $v, $r2, ", ", $v, $r2, ", ", $v, "29"),)*
                    $(concat!("valignq ", $v, $cu2, ", ", $v, $cu2, ", ", $v, $cl2, ", ", $up),)*
                    concat!("valignq ", $v, $first2, ", ", $v, $first2, ", ", $v, "28, ", $up),
                    $(concat!("vpaddq ", $v, $r2, ", ", $v, $r2, ", ", $v, $ra2),)*
                    amm_ripple!($v, $bits, "kmovq r9, k7\n", [$($rv1),*], [$(($r1, $off1)),*]),
                    amm_ripple!($v, $bits, "", [$($rv2),*], [$(($r2, $off2)),*]),
                    "vzeroupper",
                )
            }
        }
    };
}

amm_x2!(
    amm20_x2, "ymm", 20, 40, 42, "3", "4", "7", k0: ("320", "328"),
    h1: {
        o: ("0", "8"), acc0: "0", digit1: "vpextrq r15, xmm0, 1\n",
        [
            ("0", "10", "21", "0"), ("1", "11", "22", "32"), ("2", "12", "23", "64"),
            ("3", "13", "24", "96"), ("4", "14", "25", "128")
        ],
        shift: [("0", "1"), ("1", "2"), ("2", "3"), ("3", "4")], last: "4",
        carry: [("14", "13"), ("13", "12"), ("12", "11"), ("11", "10")], first: "10",
        rev: ["4", "3", "2", "1", "0"]
    },
    h2: {
        o: ("160", "168"), acc0: "5", digit1: "vpextrq r15, xmm5, 1\n",
        [
            ("5", "16", "26", "160"), ("6", "17", "27", "192"), ("7", "18", "28", "224"),
            ("8", "19", "29", "256"), ("9", "20", "30", "288")
        ],
        shift: [("5", "6"), ("6", "7"), ("7", "8"), ("8", "9")], last: "9",
        carry: [("20", "19"), ("19", "18"), ("18", "17"), ("17", "16")], first: "16",
        rev: ["9", "8", "7", "6", "5"]
    }
);

amm_x2!(
    amm32_x2, "zmm", 32, 64, 66, "7", "8", "127", k0: ("512", "520"),
    h1: {
        o: ("0", "8"), acc0: "0", digit1: "vpextrq r15, xmm0, 1\n",
        [
            ("0", "10", "21", "0"), ("1", "11", "22", "64"), ("2", "12", "23", "128"),
            ("3", "13", "24", "192")
        ],
        shift: [("0", "1"), ("1", "2"), ("2", "3")], last: "3",
        carry: [("13", "12"), ("12", "11"), ("11", "10")], first: "10",
        rev: ["3", "2", "1", "0"]
    },
    h2: {
        o: ("256", "264"), acc0: "5", digit1: "vpextrq r15, xmm5, 1\n",
        [
            ("5", "16", "26", "256"), ("6", "17", "27", "320"), ("7", "18", "28", "384"),
            ("8", "19", "29", "448")
        ],
        shift: [("5", "6"), ("6", "7"), ("7", "8")], last: "8",
        carry: [("19", "18"), ("18", "17"), ("17", "16")], first: "16",
        rev: ["8", "7", "6", "5"]
    }
);

amm_x2!(
    amm40_x2, "zmm", 40, 80, 82, "7", "8", "127", k0: ("640", "648"),
    h1: {
        o: ("0", "8"), acc0: "0", digit1: "vpextrq r15, xmm0, 1\n",
        [
            ("0", "10", "21", "0"), ("1", "11", "22", "64"), ("2", "12", "23", "128"),
            ("3", "13", "24", "192"), ("4", "14", "25", "256")
        ],
        shift: [("0", "1"), ("1", "2"), ("2", "3"), ("3", "4")], last: "4",
        carry: [("14", "13"), ("13", "12"), ("12", "11"), ("11", "10")], first: "10",
        rev: ["4", "3", "2", "1", "0"]
    },
    h2: {
        o: ("320", "328"), acc0: "5", digit1: "vpextrq r15, xmm5, 1\n",
        [
            ("5", "16", "26", "320"), ("6", "17", "27", "384"), ("7", "18", "28", "448"),
            ("8", "19", "29", "512"), ("9", "20", "30", "576")
        ],
        shift: [("5", "6"), ("6", "7"), ("7", "8"), ("8", "9")], last: "9",
        carry: [("20", "19"), ("19", "18"), ("18", "17"), ("17", "16")], first: "16",
        rev: ["9", "8", "7", "6", "5"]
    }
);

/// `k` limbs as `d` digits of 52 bits (the value must fit).
fn to_digits(l: &[u64], d: usize) -> Vec<u64> {
    (0..d)
        .map(|j| {
            let bit = 52 * j;
            let (i, s) = (bit / 64, bit % 64);
            let lo = l.get(i).map_or(0, |&x| x >> s);
            let hi = if s > 12 {
                l.get(i + 1).map_or(0, |&x| x << (64 - s))
            } else {
                0
            };
            (lo | hi) & MASK52
        })
        .collect()
}

/// `d` digits of 52 bits as `k` limbs (the value must fit).
fn from_digits(dg: &[u64], k: usize) -> Vec<u64> {
    let mut l = vec![0u64; k + 1];
    for (j, &x) in dg.iter().enumerate() {
        let bit = 52 * j;
        let (i, s) = (bit / 64, bit % 64);
        if i < l.len() {
            l[i] |= x << s;
        }
        if s > 12 && i + 1 < l.len() {
            l[i + 1] |= x >> (64 - s);
        }
    }
    l.truncate(k);
    l
}

/// `x·2ˢ mod m` for `x < m` (constant time: `s` doublings with masked subtractions).
fn shl_mod(mont: &Mont, x: &[u64], s: usize) -> Vec<u64> {
    let mut x = x.to_vec();
    let mut t = vec![0u64; x.len()];
    for _ in 0..s {
        let mut carry = 0;
        for l in &mut x {
            let v = *l;
            *l = (v << 1) | carry;
            carry = v >> 63;
        }
        let borrow = ct::sub_limbs(&mut t, &x, &mont.m);
        ct::assign(ct::mask(carry | (1 ^ borrow)), &mut x, &t);
    }
    x
}

/// One AMM at the digit count `d` (20, 32 or 40).
fn amm(d: usize, out: &mut [u64], a: &[u64], b: &[u64], m: &[u64], k0: u64) {
    macro_rules! go {
        ($f:ident, $n:literal) => {
            $f(
                (&mut out[..$n])
                    .try_into()
                    .unwrap_or_else(|_| unreachable!()),
                a[..$n].try_into().unwrap_or_else(|_| unreachable!()),
                b[..$n].try_into().unwrap_or_else(|_| unreachable!()),
                m[..$n].try_into().unwrap_or_else(|_| unreachable!()),
                k0,
            )
        };
    }
    match d {
        20 => go!(amm20, 20),
        32 => go!(amm32, 32),
        _ => go!(amm40, 40),
    }
}

/// The digit count for a modulus of `k` limbs, if this module handles it.
pub(crate) fn digits(k: usize) -> Option<usize> {
    match k {
        16 => Some(20),
        24 => Some(32),
        32 => Some(40),
        _ => None,
    }
}

/// [`Mont::pow`] on IFMA: `base^e` with `base` and the result in the 64-bit Montgomery form of
/// `mont` (fully reduced), for the limb counts of [`digits`]; the same fixed windows and table
/// scans, constant time in `base` and `e`'s value.
pub(crate) fn pow(mont: &Mont, base: &[u64], e: &[u64], window: usize) -> Vec<u64> {
    let k = mont.limbs();
    let d = digits(k).unwrap_or_else(|| unreachable!());
    // From R = 2^(64k) to R' = 2^(52d): x·R' = x·R·2^s.
    let s = 52 * d - 64 * k;
    let m = to_digits(&mont.m, d);
    let k0 = mont.n0 & MASK52;
    let entries = 1 << window;
    let mut table = vec![0u64; entries * d];
    table[..d].copy_from_slice(&to_digits(&shl_mod(mont, &mont.r1, s), d));
    table[d..2 * d].copy_from_slice(&to_digits(&shl_mod(mont, base, s), d));
    // table[j] = base^j: even entries by squaring, odd ones by one multiplication.
    for j in 2..entries {
        let (done, rest) = table.split_at_mut(j * d);
        let (x, y) = if j % 2 == 0 {
            let h = &done[j / 2 * d..(j / 2 + 1) * d];
            (h, h)
        } else {
            (&done[(j - 1) * d..j * d], &done[d..2 * d])
        };
        amm(d, &mut rest[..d], x, y, &m, k0);
    }
    let bits = 64 * e.len();
    let windows = bits.div_ceil(window);
    let digit = |w: usize| window_digit(e, window, w);
    let mut r = vec![0u64; d];
    lookup(&mut r, &table, d, digit(windows - 1));
    let mut tmp = vec![0u64; d];
    let mut sel = vec![0u64; d];
    for w in (0..windows - 1).rev() {
        for _ in 0..window {
            amm(d, &mut tmp, &r, &r, &m, k0);
            std::mem::swap(&mut r, &mut tmp);
        }
        lookup(&mut sel, &table, d, digit(w));
        amm(d, &mut tmp, &r, &sel, &m, k0);
        std::mem::swap(&mut r, &mut tmp);
    }
    // Back to the 64-bit form: AMM(r, R mod m) = r·R·R'⁻¹, below 2m.
    amm(d, &mut tmp, &r, &to_digits(&mont.r1, d), &m, k0);
    finish(mont, &tmp)
}

/// A result below `2m` in digits, fully reduced, in limbs (one masked subtraction).
fn finish(mont: &Mont, dg: &[u64]) -> Vec<u64> {
    let k = mont.limbs();
    let v = from_digits(dg, k + 1);
    let mut out = vec![0u64; k + 1];
    let mut mm = mont.m.clone();
    mm.push(0);
    let borrow = ct::sub_limbs(&mut out, &v, &mm);
    ct::assign(ct::mask(borrow), &mut out, &v);
    out.truncate(k);
    out
}

/// Two AMMs at the digit count `d` in one block: operands `[half 1 | half 2]` of `2d` digits,
/// `m` followed by both `k0`.
fn amm_x2(d: usize, out: &mut [u64], a: &[u64], b: &[u64], m: &[u64]) {
    macro_rules! go {
        ($f:ident, $n:literal, $nm:literal) => {
            $f(
                (&mut out[..$n])
                    .try_into()
                    .unwrap_or_else(|_| unreachable!()),
                a[..$n].try_into().unwrap_or_else(|_| unreachable!()),
                b[..$n].try_into().unwrap_or_else(|_| unreachable!()),
                m[..$nm].try_into().unwrap_or_else(|_| unreachable!()),
            )
        };
    }
    match d {
        20 => go!(amm20_x2, 40, 42),
        32 => go!(amm32_x2, 64, 66),
        _ => go!(amm40_x2, 80, 82),
    }
}

/// The `window`-bit digit `w` of `e` (digit positions depend only on `e`'s length).
fn window_digit(e: &[u64], window: usize, w: usize) -> u64 {
    let lo = w * window;
    let (limb, shift) = (lo / 64, lo % 64);
    let mut v = e[limb] >> shift;
    if shift + window > 64 && limb + 1 < e.len() {
        v |= e[limb + 1] << (64 - shift);
    }
    v & ((1 << window) - 1)
}

/// [`pow`] for two moduli at once, `(bp^ep mod p, bq^eq mod q)`, interleaved in the `_x2`
/// blocks: for the CRT halves of an RSA key. `p` and `q` have the same limb count (one of
/// [`digits`]) and `ep`, `eq` the same length; constant time in the bases and the exponents'
/// values, as [`pow`].
pub(crate) fn pow_x2(
    p: &Mont,
    bp: &[u64],
    ep: &[u64],
    q: &Mont,
    bq: &[u64],
    eq: &[u64],
    window: usize,
) -> (Vec<u64>, Vec<u64>) {
    let k = p.limbs();
    debug_assert!(q.limbs() == k && ep.len() == eq.len());
    let d = digits(k).unwrap_or_else(|| unreachable!());
    let d2 = 2 * d;
    let s = 52 * d - 64 * k;
    let pair = |x: Vec<u64>, y: Vec<u64>| -> Vec<u64> { [x, y].concat() };
    let mut m = pair(to_digits(&p.m, d), to_digits(&q.m, d));
    m.push(p.n0 & MASK52);
    m.push(q.n0 & MASK52);
    // table[j] = [bp^j | bq^j], built in pairs; then split for the two lookups.
    let entries = 1 << window;
    let mut table = vec![0u64; entries * d2];
    table[..d2].copy_from_slice(&pair(
        to_digits(&shl_mod(p, &p.r1, s), d),
        to_digits(&shl_mod(q, &q.r1, s), d),
    ));
    table[d2..2 * d2].copy_from_slice(&pair(
        to_digits(&shl_mod(p, bp, s), d),
        to_digits(&shl_mod(q, bq, s), d),
    ));
    for j in 2..entries {
        let (done, rest) = table.split_at_mut(j * d2);
        let (x, y) = if j % 2 == 0 {
            let h = &done[j / 2 * d2..(j / 2 + 1) * d2];
            (h, h)
        } else {
            (&done[(j - 1) * d2..j * d2], &done[d2..2 * d2])
        };
        amm_x2(d, &mut rest[..d2], x, y, &m);
    }
    let (mut tp, mut tq) = (
        Vec::with_capacity(entries * d),
        Vec::with_capacity(entries * d),
    );
    for e in table.chunks_exact(d2) {
        tp.extend_from_slice(&e[..d]);
        tq.extend_from_slice(&e[d..]);
    }
    let windows = (64 * ep.len()).div_ceil(window);
    let mut r = vec![0u64; d2];
    let mut tmp = vec![0u64; d2];
    let mut sel = vec![0u64; d2];
    let pick = |sel: &mut [u64], w: usize| {
        let (sp, sq) = sel.split_at_mut(d);
        lookup(sp, &tp, d, window_digit(ep, window, w));
        lookup(sq, &tq, d, window_digit(eq, window, w));
    };
    pick(&mut r, windows - 1);
    for w in (0..windows - 1).rev() {
        for _ in 0..window {
            amm_x2(d, &mut tmp, &r, &r, &m);
            std::mem::swap(&mut r, &mut tmp);
        }
        pick(&mut sel, w);
        amm_x2(d, &mut tmp, &r, &sel, &m);
        std::mem::swap(&mut r, &mut tmp);
    }
    let one = pair(to_digits(&p.r1, d), to_digits(&q.r1, d));
    amm_x2(d, &mut tmp, &r, &one, &m);
    (finish(p, &tmp[..d]), finish(q, &tmp[d..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Time per AMM at each digit count:
    /// `cargo test --release -p only-crypto --lib bignum::ifma::tests::timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing, run by hand"]
    fn timing() {
        if !enabled() {
            return;
        }
        let mut rng = crate::rand::ChaChaRng::from_seed([21; 32]);
        for k in [16usize, 24, 32] {
            let d = digits(k).unwrap();
            let mut m: Vec<u64> = (0..k).map(|_| rng.next_u64()).collect();
            m[0] |= 1;
            m[k - 1] |= 1 << 63;
            let mont = Mont::new(&m).unwrap();
            let md = to_digits(&m, d);
            let k0 = mont.n0 & MASK52;
            let mut x = to_digits(
                &mont.reduce(&(0..k).map(|_| rng.next_u64()).collect::<Vec<_>>()),
                d,
            );
            let mut y = vec![0u64; d];
            let iters = 4_000_000 / k;
            let t = std::time::Instant::now();
            for _ in 0..iters {
                amm(d, &mut y, &x, &x, &md, k0);
                amm(d, &mut x, &y, &y, &md, k0);
            }
            let ns = t.elapsed().as_nanos() as f64 / (2 * iters) as f64;
            std::hint::black_box(&x);
            let base = mont.reduce(&(0..k).map(|_| rng.next_u64()).collect::<Vec<_>>());
            let e: Vec<u64> = (0..k).map(|_| rng.next_u64()).collect();
            let iters = 4000 / k;
            let t = std::time::Instant::now();
            for _ in 0..iters {
                std::hint::black_box(pow(&mont, &base, &e, crate::bignum::WINDOW));
            }
            let us = t.elapsed().as_nanos() as f64 / iters as f64 / 1000.0;
            // The interleaved pair, per half.
            let mut x2 = x.repeat(2);
            let mut y2 = vec![0u64; 2 * d];
            let mut m2 = md.repeat(2);
            m2.extend([k0, k0]);
            let iters2 = 4_000_000 / k;
            let t = std::time::Instant::now();
            for _ in 0..iters2 {
                amm_x2(d, &mut y2, &x2, &x2, &m2);
                amm_x2(d, &mut x2, &y2, &y2, &m2);
            }
            let ns2 = t.elapsed().as_nanos() as f64 / (4 * iters2) as f64;
            std::hint::black_box(&x2);
            let t = std::time::Instant::now();
            for _ in 0..iters {
                std::hint::black_box(pow_x2(
                    &mont,
                    &base,
                    &e,
                    &mont,
                    &base,
                    &e,
                    crate::bignum::WINDOW,
                ));
            }
            let us2 = t.elapsed().as_nanos() as f64 / (2 * iters) as f64 / 1000.0;
            println!(
                "{:>5} bits ({d} digits): amm {ns:8.1} ns  pow {us:8.1} us  \
                 x2 per half: amm {ns2:8.1} ns  pow {us2:8.1} us",
                64 * k
            );
        }
    }
}
