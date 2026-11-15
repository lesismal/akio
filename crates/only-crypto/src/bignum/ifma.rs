//! Modular exponentiation for RSA on x86_64 with AVX-512 IFMA (`vpmadd52luq`/`vpmadd52huq` on
//! 256-bit registers), for the CRT halves of 2048-, 3072- and 4096-bit keys (moduli of 16, 24
//! and 32 limbs).
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
//! state: they are reached only from [`pow`] after [`enabled`] (`cpu::has(Feature::Ifma)`), and
//! every multiplication debug-asserts it.
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
/// caller's. Then the second carry where a lane exceeds 2⁵² - 1, rippling through lanes equal to
/// it (generate G, propagate P, carries in = ((G << 1) + P) ^ P, `$bits` bits per register), and
/// the stores.
macro_rules! amm_ripple {
    ($v:literal, $bits:literal, [$($rv:literal),*], [$(($r:literal, $off:literal)),*]) => {
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
            "vmovq r9, xmm31\n",
            $(
                "kmovw k1, r12d\n",
                "vpaddq ", $v, $r, " {{k1}}, ", $v, $r, ", ", $v, "30\n",
                "vpandq ", $v, $r, ", ", $v, $r, ", ", $v, "29\n",
                "shr r12, ", $bits, "\n",
                "vmovdqu64 ", $v, "word ptr [r9 + ", $off, "], ", $v, $r, "\n",
            )*
            "vzeroupper\n",
        )
    };
}

/// The operands of every AMM block.
macro_rules! amm_asm {
    ($out:ident, $a:ident, $b:ident, $m:ident, $k0:ident, $($t:expr),* $(,)?) => {
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
                    amm_ripple!("ymm", "4", [$($rv),*], [$(($r, $off)),*]),
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
                    amm_ripple!($v, $bits, [$($rv),*], [$(($r, $off)),*]),
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
    let digit = |w: usize| -> u64 {
        let lo = w * window;
        let (limb, shift) = (lo / 64, lo % 64);
        let mut v = e[limb] >> shift;
        if shift + window > 64 && limb + 1 < e.len() {
            v |= e[limb + 1] << (64 - shift);
        }
        v & (entries as u64 - 1)
    };
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
    // Back to the 64-bit form: AMM(r, R mod m) = r·R·R'⁻¹, below 2m; then one masked
    // subtraction.
    amm(d, &mut tmp, &r, &to_digits(&mont.r1, d), &m, k0);
    let v = from_digits(&tmp, k + 1);
    let mut out = vec![0u64; k + 1];
    let mut mm = mont.m.clone();
    mm.push(0);
    let borrow = ct::sub_limbs(&mut out, &v, &mm);
    ct::assign(ct::mask(borrow), &mut out, &v);
    out.truncate(k);
    out
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
            println!(
                "{:>5} bits ({d} digits): amm {ns:8.1} ns  pow {us:8.1} us",
                64 * k
            );
        }
    }
}
