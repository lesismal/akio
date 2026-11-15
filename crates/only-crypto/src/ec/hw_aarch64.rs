//! P-256 arithmetic on aarch64 in inline assembly (`MUL`/`UMULH` for the 64×64-bit products,
//! `ADDS`/`ADCS`/`SUBS`/`SBCS` carry chains, `CSEL` for the final corrections), the counterpart
//! of the x86_64 BMI2 + ADX module `ec::hw`, with the same function set and semantics:
//!
//! - modulo the prime `p = 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1` ([`P256Pa`]): Montgomery multiplication
//!   and squaring (`R = 2²⁵⁶`), addition, subtraction, `2ᵏ·a`, `3·a`. It is the base field of
//!   the [`P256A`] twin of the `P256` curve, which `P256` dispatches its operations to when
//!   [`enabled`] says so; both share the Montgomery representation, so points and tables convert
//!   by copying limbs;
//! - modulo the group order `n` ([`ord_mul`], [`ord_sqr`], [`P256Na`]): Montgomery
//!   multiplication and squaring, which the portable `P256N` scalar field calls when [`enabled`].
//!
//! Inversions modulo `p` and `n` are safegcd (`crate::safegcd`, portable divsteps) with the final
//! Montgomery multiplication in this module. The twin keeps the portable defaults of the
//! `Curve::jac_*` hooks (point formulas, table scans, the 4-bit comb), which run on this field;
//! the x86_64 twin's whole-point assembly, AVX2 scans and 6-bit comb have no aarch64 counterpart
//! yet.
//!
//! The instructions are in every ARMv8.0-A CPU, so there is nothing to detect: [`enabled`] is
//! `cpu::has(Feature::Umulh)`, which is set on every aarch64 target outside Miri and cleared by
//! `ONLY_CRYPTO_PORTABLE=1` / `set_portable(true)`.
//!
//! Design (not benchmarked yet; the choices follow OpenSSL's `ecp_nistz256-armv8` and the
//! instruction counts): the 512-bit product is formed row by row (4 `MUL` + 4 `UMULH` per row,
//! the low halves on one carry chain, the high halves on a second), the square from the six
//! cross products doubled plus the four squares (10 `MUL` + 10 `UMULH` instead of 16 + 16). The
//! reduction modulo `p` needs no multiplication at all: `-p⁻¹ mod 2⁶⁴ = 1`, so each step's
//! multiplier `m` is the low limb, and `m·p₃` (`p₃ = 2⁶⁴ - 2³² + 1`) is two shifts and a
//! subtraction. Modulo `n`, `m·n₂` and `m·n₃` (`n₂ = 2⁶⁴ - 1`, `n₃ = 2⁶⁴ - 2³²`) are shifts and
//! subtractions too; only `m·n₀` and `m·n₁` are real products.
//!
//! Constant time: straight-line code, no branches and no memory accesses that depend on the
//! values; the final corrections use `CSEL` on the carry flag, the subtraction's correction a
//! mask from `SBC`. (`black_box` is not needed here: the compiler cannot rewrite the assembly.)
//! `MUL`, `UMULH`, the flag-setting additions and `CSEL` take data-independent time on ARMv8
//! cores (Arm's DIT list includes them).
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the `asm!`
//! blocks, which take their operands in registers and write nothing but their register outputs
//! (`pure`, `nomem`, `nostack`).
#![allow(unsafe_code)]

use std::arch::asm;

use super::curves::{P256, P256N};
use super::{BaseTables, Curve};
use crate::cpu::{self, Feature};
use crate::field::Modulus;

/// Whether to use this module: aarch64 outside Miri, and the portable code is not forced.
#[inline]
pub(crate) fn enabled() -> bool {
    cpu::has(Feature::Umulh)
}

/// `p₃`, the top limb of `p`.
const P3: u64 = 0xffff_ffff_0000_0001;

/// The P-256 base field in aarch64 assembly.
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256Pa;

impl Modulus<4> for P256Pa {
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

    // safegcd (portable divsteps), then the final Montgomery multiplication here.
    fn mont_inv(a: &[u64; 4]) -> Option<[u64; 4]> {
        Some(crate::safegcd::mont_inv::<Self>(a))
    }
}

/// The P-256 group order in aarch64 assembly, for the scalar inversion chain (addition and
/// subtraction stay portable: the chain uses none).
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256Na;

impl Modulus<4> for P256Na {
    const P: [u64; 4] = [N0, N1, u64::MAX, N3];

    #[inline]
    fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        ord_mul(a, b)
    }

    #[inline]
    fn mont_sqr(a: &[u64; 4]) -> [u64; 4] {
        ord_sqr(a)
    }
}

/// P-256 with the base field in aarch64 assembly ([`P256Pa`]): the twin `P256` dispatches its
/// operations to when [`enabled`]. Same constants, same scalar field, same tables.
#[derive(Clone, Copy, Debug)]
pub(crate) struct P256A;

impl Curve<4> for P256A {
    type Fp = P256Pa;
    type Fq = P256N;
    const B: [u64; 4] = P256::B;
    const GX: [u64; 4] = P256::GX;
    const GY: [u64; 4] = P256::GY;
    fn tables() -> &'static BaseTables<4> {
        P256::tables()
    }
}

/// The limbs of `n` (`n₂ = 2⁶⁴ - 1`) and `-n⁻¹ mod 2⁶⁴`.
const N0: u64 = 0xf3b9_cac2_fc63_2551;
const N1: u64 = 0xbce6_faad_a717_9e84;
const N3: u64 = 0xffff_ffff_0000_0000;
const NINV: u64 = 0xccd1_c8aa_ee00_bc4f;

/// One row `i ≥ 1` of `mul_rows!`: `z[i..i+5] += a·bᵢ` (`z[i+4]` is new), the low halves on the
/// first carry chain, the high halves on the second. The partial product fits its limbs, so the
/// last `ADC` cannot overflow.
macro_rules! mul_row {
    ($bi:literal, $z0:literal, $z1:literal, $z2:literal, $z3:literal, $z4:literal) => {
        concat!(
            "mul {t0}, {a0}, ",
            $bi,
            "\n",
            "mul {t1}, {a1}, ",
            $bi,
            "\n",
            "mul {t2}, {a2}, ",
            $bi,
            "\n",
            "mul {t3}, {a3}, ",
            $bi,
            "\n",
            "adds ",
            $z0,
            ", ",
            $z0,
            ", {t0}\n",
            "adcs ",
            $z1,
            ", ",
            $z1,
            ", {t1}\n",
            "adcs ",
            $z2,
            ", ",
            $z2,
            ", {t2}\n",
            "adcs ",
            $z3,
            ", ",
            $z3,
            ", {t3}\n",
            "cset ",
            $z4,
            ", cs\n",
            "umulh {t0}, {a0}, ",
            $bi,
            "\n",
            "umulh {t1}, {a1}, ",
            $bi,
            "\n",
            "umulh {t2}, {a2}, ",
            $bi,
            "\n",
            "umulh {t3}, {a3}, ",
            $bi,
            "\n",
            "adds ",
            $z1,
            ", ",
            $z1,
            ", {t0}\n",
            "adcs ",
            $z2,
            ", ",
            $z2,
            ", {t1}\n",
            "adcs ",
            $z3,
            ", ",
            $z3,
            ", {t2}\n",
            "adc ",
            $z4,
            ", ",
            $z4,
            ", {t3}\n",
        )
    };
}

/// The 512-bit product `a·b` of `{a0}..{a3}` and `{b0}..{b3}` into `{z0}..{z7}` (scratch
/// `{t0}..{t3}`): one row per limb of `b`. (`MUL`/`UMULH` leave the flags alone.)
macro_rules! mul_rows {
    () => {
        concat!(
            "mul {z0}, {a0}, {b0}\n",
            "mul {z1}, {a1}, {b0}\n",
            "mul {z2}, {a2}, {b0}\n",
            "mul {z3}, {a3}, {b0}\n",
            "umulh {t0}, {a0}, {b0}\n",
            "umulh {t1}, {a1}, {b0}\n",
            "umulh {t2}, {a2}, {b0}\n",
            "umulh {z4}, {a3}, {b0}\n",
            "adds {z1}, {z1}, {t0}\n",
            "adcs {z2}, {z2}, {t1}\n",
            "adcs {z3}, {z3}, {t2}\n",
            "adc {z4}, {z4}, xzr\n",
            mul_row!("{b1}", "{z1}", "{z2}", "{z3}", "{z4}", "{z5}"),
            mul_row!("{b2}", "{z2}", "{z3}", "{z4}", "{z5}", "{z6}"),
            mul_row!("{b3}", "{z3}", "{z4}", "{z5}", "{z6}", "{z7}"),
        )
    };
}

/// The 512-bit square of `{a0}..{a3}` into `{z0}..{z7}` (scratch `{t0}..{t3}`): the six cross
/// products once, doubled, plus the four squares.
macro_rules! sqr_rows {
    () => {
        concat!(
            // a₀·(a₁, a₂, a₃) into limbs 1..4.
            "mul {z1}, {a0}, {a1}\n",
            "mul {z2}, {a0}, {a2}\n",
            "mul {z3}, {a0}, {a3}\n",
            "umulh {t0}, {a0}, {a1}\n",
            "umulh {t1}, {a0}, {a2}\n",
            "umulh {z4}, {a0}, {a3}\n",
            "adds {z2}, {z2}, {t0}\n",
            "adcs {z3}, {z3}, {t1}\n",
            "adc {z4}, {z4}, xzr\n",
            // a₁·(a₂, a₃) into limbs 3..5.
            "mul {t0}, {a1}, {a2}\n",
            "mul {t1}, {a1}, {a3}\n",
            "umulh {t2}, {a1}, {a2}\n",
            "umulh {z5}, {a1}, {a3}\n",
            "adds {z3}, {z3}, {t0}\n",
            "adcs {z4}, {z4}, {t1}\n",
            "adc {z5}, {z5}, xzr\n",
            "adds {z4}, {z4}, {t2}\n",
            "adc {z5}, {z5}, xzr\n",
            // a₂·a₃ into limbs 5..6.
            "mul {t0}, {a2}, {a3}\n",
            "umulh {z6}, {a2}, {a3}\n",
            "adds {z5}, {z5}, {t0}\n",
            "adc {z6}, {z6}, xzr\n",
            // Doubled into limbs 1..7.
            "adds {z1}, {z1}, {z1}\n",
            "adcs {z2}, {z2}, {z2}\n",
            "adcs {z3}, {z3}, {z3}\n",
            "adcs {z4}, {z4}, {z4}\n",
            "adcs {z5}, {z5}, {z5}\n",
            "adcs {z6}, {z6}, {z6}\n",
            "cset {z7}, cs\n",
            // Plus the squares aᵢ² at limbs 2i, 2i + 1.
            "mul {z0}, {a0}, {a0}\n",
            "umulh {t0}, {a0}, {a0}\n",
            "mul {t1}, {a1}, {a1}\n",
            "umulh {t2}, {a1}, {a1}\n",
            "mul {t3}, {a2}, {a2}\n",
            "adds {z1}, {z1}, {t0}\n",
            "adcs {z2}, {z2}, {t1}\n",
            "adcs {z3}, {z3}, {t2}\n",
            "adcs {z4}, {z4}, {t3}\n",
            "umulh {t0}, {a2}, {a2}\n",
            "mul {t1}, {a3}, {a3}\n",
            "umulh {t2}, {a3}, {a3}\n",
            "adcs {z5}, {z5}, {t0}\n",
            "adcs {z6}, {z6}, {t1}\n",
            "adc {z7}, {z7}, {t2}\n",
        )
    };
}

// The X25519 ladder (`curve25519::hw_aarch64`) shares the 512-bit products.
pub(crate) use {mul_row, mul_rows, sqr_rows};

/// One step of `reduce_p!`: `m = zᵢ`, `z += m·p`, the carry into limb `i + 5` in `$c` (read and
/// replaced). `m·(2⁹⁶ - 1)` clears limb `i` and adds `m·2⁹⁶` (two shifted words);
/// `m·p₃ = m·2⁶⁴ - m·2³² + m` is `(m - (m >> 32) - borrow)·2⁶⁴ + (m - (m << 32))`. The top word
/// `hi(m·p₃) + c + CF` cannot overflow (`hi(m·p₃) < 2⁶⁴ - 2³²`).
macro_rules! reduce_p_step {
    ($zi:literal, $z1:literal, $z2:literal, $z3:literal, $z4:literal, $c:literal) => {
        concat!(
            "lsl {t0}, ",
            $zi,
            ", #32\n",
            "lsr {t1}, ",
            $zi,
            ", #32\n",
            "subs {t2}, ",
            $zi,
            ", {t0}\n",
            "sbc {t3}, ",
            $zi,
            ", {t1}\n",
            "adds ",
            $z1,
            ", ",
            $z1,
            ", {t0}\n",
            "adcs ",
            $z2,
            ", ",
            $z2,
            ", {t1}\n",
            "adcs ",
            $z3,
            ", ",
            $z3,
            ", {t2}\n",
            "adc {t3}, {t3}, ",
            $c,
            "\n",
            "adds ",
            $z4,
            ", ",
            $z4,
            ", {t3}\n",
            "cset ",
            $c,
            ", cs\n",
        )
    };
}

/// The Montgomery reduction modulo `p` of the 512-bit `{z0}..{z7}`, leaving `t·2⁻²⁵⁶ mod p`
/// fully reduced in `{z4}..{z7}` (scratch `{t0}..{t3}` and `$c`, `$p1`, `$p3` free registers).
/// The input is below `p·2²⁵⁶`, so the result before the final subtraction is below `2p`.
macro_rules! reduce_p {
    ($c:literal, $p1:literal, $p3:literal) => {
        concat!(
            "mov ", $c, ", xzr\n",
            reduce_p_step!("{z0}", "{z1}", "{z2}", "{z3}", "{z4}", $c),
            reduce_p_step!("{z1}", "{z2}", "{z3}", "{z4}", "{z5}", $c),
            reduce_p_step!("{z2}", "{z3}", "{z4}", "{z5}", "{z6}", $c),
            reduce_p_step!("{z3}", "{z4}", "{z5}", "{z6}", "{z7}", $c),
            // t = c·2²⁵⁶ + z4..z7 < 2p: subtract p (z4 - (2⁶⁴ - 1) is z4 + 1 with the same
            // carry-out), keep t where that borrows (carry clear).
            "mov ", $p1, ", #0xffffffff\n",
            "mov ", $p3, ", #0xffffffff00000001\n",
            "adds {t0}, {z4}, #1\n",
            "sbcs {t1}, {z5}, ", $p1, "\n",
            "sbcs {t2}, {z6}, xzr\n",
            "sbcs {t3}, {z7}, ", $p3, "\n",
            "sbcs xzr, ", $c, ", xzr\n",
            "csel {z4}, {z4}, {t0}, cc\n",
            "csel {z5}, {z5}, {t1}, cc\n",
            "csel {z6}, {z6}, {t2}, cc\n",
            "csel {z7}, {z7}, {t3}, cc\n",
        )
    };
}

/// One step of `reduce_n!`: `m = zᵢ·(-n⁻¹) mod 2⁶⁴`, `z += m·n`, the carry into limb `i + 5`
/// in `$c`. `m·n₂ = (m - 1 + [m = 0])·2⁶⁴ + (-m)` and `m·n₃ = m·2⁶⁴ - m·2³²` come from
/// subtractions; `$l*` take the low halves, `{t0}..{t3}` the high ones. The top word
/// `hi(m·n₃) + c + CF` cannot overflow (`hi(m·n₃) < 2⁶⁴ - 2³²`).
macro_rules! reduce_n_step {
    ($zi:literal, $z1:literal, $z2:literal, $z3:literal, $z4:literal,
     $m:literal, $c:literal, $l0:literal, $l1:literal, $l2:literal, $l3:literal) => {
        concat!(
            "mul ",
            $m,
            ", ",
            $zi,
            ", {ninv}\n",
            "mul ",
            $l0,
            ", ",
            $m,
            ", {n0}\n",
            "umulh {t0}, ",
            $m,
            ", {n0}\n",
            "mul ",
            $l1,
            ", ",
            $m,
            ", {n1}\n",
            "umulh {t1}, ",
            $m,
            ", {n1}\n",
            "subs ",
            $l2,
            ", xzr, ",
            $m,
            "\n",
            "sbc {t2}, ",
            $m,
            ", xzr\n",
            "lsl ",
            $l3,
            ", ",
            $m,
            ", #32\n",
            "lsr {t3}, ",
            $m,
            ", #32\n",
            "subs ",
            $l3,
            ", xzr, ",
            $l3,
            "\n",
            "sbc {t3}, ",
            $m,
            ", {t3}\n",
            "adds ",
            $zi,
            ", ",
            $zi,
            ", ",
            $l0,
            "\n",
            "adcs ",
            $z1,
            ", ",
            $z1,
            ", ",
            $l1,
            "\n",
            "adcs ",
            $z2,
            ", ",
            $z2,
            ", ",
            $l2,
            "\n",
            "adcs ",
            $z3,
            ", ",
            $z3,
            ", ",
            $l3,
            "\n",
            "adc {t3}, {t3}, ",
            $c,
            "\n",
            "adds ",
            $z1,
            ", ",
            $z1,
            ", {t0}\n",
            "adcs ",
            $z2,
            ", ",
            $z2,
            ", {t1}\n",
            "adcs ",
            $z3,
            ", ",
            $z3,
            ", {t2}\n",
            "adcs ",
            $z4,
            ", ",
            $z4,
            ", {t3}\n",
            "cset ",
            $c,
            ", cs\n",
        )
    };
}

/// The Montgomery reduction modulo `n` of the 512-bit `{z0}..{z7}` (constants in `{ninv}`,
/// `{n0}`, `{n1}`; scratch `{t0}..{t3}` and the free registers `$m`, `$c`, `$l0..$l3`), leaving
/// `t·2⁻²⁵⁶ mod n` fully reduced in `{z4}..{z7}`. The input is below `n·2²⁵⁶`, so the result
/// before the final subtraction is below `2n`.
macro_rules! reduce_n {
    ($m:literal, $c:literal, $l0:literal, $l1:literal, $l2:literal, $l3:literal) => {
        concat!(
            "mov ", $c, ", xzr\n",
            reduce_n_step!("{z0}", "{z1}", "{z2}", "{z3}", "{z4}", $m, $c, $l0, $l1, $l2, $l3),
            reduce_n_step!("{z1}", "{z2}", "{z3}", "{z4}", "{z5}", $m, $c, $l0, $l1, $l2, $l3),
            reduce_n_step!("{z2}", "{z3}", "{z4}", "{z5}", "{z6}", $m, $c, $l0, $l1, $l2, $l3),
            reduce_n_step!("{z3}", "{z4}", "{z5}", "{z6}", "{z7}", $m, $c, $l0, $l1, $l2, $l3),
            // t = c·2²⁵⁶ + z4..z7 < 2n: subtract n (z6 - (2⁶⁴ - 1) - borrow is z6 + carry with
            // the same carry-out), keep t where that borrows (carry clear).
            "mov ", $m, ", #0xffffffff00000000\n",
            "subs {t0}, {z4}, {n0}\n",
            "sbcs {t1}, {z5}, {n1}\n",
            "adcs {t2}, {z6}, xzr\n",
            "sbcs {t3}, {z7}, ", $m, "\n",
            "sbcs xzr, ", $c, ", xzr\n",
            "csel {z4}, {z4}, {t0}, cc\n",
            "csel {z5}, {z5}, {t1}, cc\n",
            "csel {z6}, {z6}, {t2}, cc\n",
            "csel {z7}, {z7}, {t3}, cc\n",
        )
    };
}

/// Montgomery multiplication `a·b·2⁻²⁵⁶ mod p`, fully reduced, for `a·b < p·2²⁵⁶` (any `a < 2²⁵⁶`
/// with `b < p`).
#[inline]
pub(crate) fn mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: registers only (no memory, no stack); base ARMv8.0-A instructions, present on every
    // aarch64 CPU.
    unsafe {
        asm!(
            mul_rows!(),
            // a and b are dead: {b0} is the carry, {b1}/{b2} hold p₁/p₃.
            reduce_p!("{b0}", "{b1}", "{b2}"),
            a0 = inout(reg) a[0] => _,
            a1 = inout(reg) a[1] => _,
            a2 = inout(reg) a[2] => _,
            a3 = inout(reg) a[3] => _,
            b0 = inout(reg) b[0] => _,
            b1 = inout(reg) b[1] => _,
            b2 = inout(reg) b[2] => _,
            b3 = inout(reg) b[3] => _,
            z0 = out(reg) _,
            z1 = out(reg) _,
            z2 = out(reg) _,
            z3 = out(reg) _,
            z4 = out(reg) r0,
            z5 = out(reg) r1,
            z6 = out(reg) r2,
            z7 = out(reg) r3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// Montgomery squaring `a²·2⁻²⁵⁶ mod p`, fully reduced, for `a < p`.
#[inline]
pub(crate) fn sqr(a: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: registers only (no memory, no stack); base ARMv8.0-A instructions.
    unsafe {
        asm!(
            sqr_rows!(),
            reduce_p!("{a0}", "{a1}", "{a2}"),
            a0 = inout(reg) a[0] => _,
            a1 = inout(reg) a[1] => _,
            a2 = inout(reg) a[2] => _,
            a3 = inout(reg) a[3] => _,
            z0 = out(reg) _,
            z1 = out(reg) _,
            z2 = out(reg) _,
            z3 = out(reg) _,
            z4 = out(reg) r0,
            z5 = out(reg) r1,
            z6 = out(reg) r2,
            z7 = out(reg) r3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// Montgomery multiplication `a·b·2⁻²⁵⁶ mod n` (the group order), fully reduced, for
/// `a·b < n·2²⁵⁶`.
#[inline]
pub(crate) fn ord_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: registers only (no memory, no stack); base ARMv8.0-A instructions.
    unsafe {
        asm!(
            mul_rows!(),
            reduce_n!("{b0}", "{b1}", "{a0}", "{a1}", "{a2}", "{a3}"),
            a0 = inout(reg) a[0] => _,
            a1 = inout(reg) a[1] => _,
            a2 = inout(reg) a[2] => _,
            a3 = inout(reg) a[3] => _,
            b0 = inout(reg) b[0] => _,
            b1 = inout(reg) b[1] => _,
            b2 = inout(reg) b[2] => _,
            b3 = inout(reg) b[3] => _,
            z0 = out(reg) _,
            z1 = out(reg) _,
            z2 = out(reg) _,
            z3 = out(reg) _,
            z4 = out(reg) r0,
            z5 = out(reg) r1,
            z6 = out(reg) r2,
            z7 = out(reg) r3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            ninv = in(reg) NINV,
            n0 = in(reg) N0,
            n1 = in(reg) N1,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// Montgomery squaring `a²·2⁻²⁵⁶ mod n` (the group order), fully reduced, for `a < n`.
#[inline]
pub(crate) fn ord_sqr(a: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: registers only (no memory, no stack); base ARMv8.0-A instructions.
    unsafe {
        asm!(
            sqr_rows!(),
            reduce_n!("{m}", "{c}", "{a0}", "{a1}", "{a2}", "{a3}"),
            a0 = inout(reg) a[0] => _,
            a1 = inout(reg) a[1] => _,
            a2 = inout(reg) a[2] => _,
            a3 = inout(reg) a[3] => _,
            z0 = out(reg) _,
            z1 = out(reg) _,
            z2 = out(reg) _,
            z3 = out(reg) _,
            z4 = out(reg) r0,
            z5 = out(reg) r1,
            z6 = out(reg) r2,
            z7 = out(reg) r3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            m = out(reg) _,
            c = out(reg) _,
            ninv = in(reg) NINV,
            n0 = in(reg) N0,
            n1 = in(reg) N1,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `s - p` unless that borrows, for `s = {c}·2²⁵⁶ + ({r0}..{r3}) < 2p`, into `{r0}..{r3}`
/// (`{t0}..{t3}` scratch, `{p1}`, `{p3}` the limbs of `p`).
macro_rules! cond_sub_p {
    () => {
        concat!(
            "adds {t0}, {r0}, #1\n",
            "sbcs {t1}, {r1}, {p1}\n",
            "sbcs {t2}, {r2}, xzr\n",
            "sbcs {t3}, {r3}, {p3}\n",
            "sbcs xzr, {c}, xzr\n",
            "csel {r0}, {t0}, {r0}, cs\n",
            "csel {r1}, {t1}, {r1}, cs\n",
            "csel {r2}, {t2}, {r2}, cs\n",
            "csel {r3}, {t3}, {r3}, cs\n",
        )
    };
}

/// `2·({r0}..{r3}) mod p` in place.
macro_rules! dbl_p {
    () => {
        concat!(
            "adds {r0}, {r0}, {r0}\n",
            "adcs {r1}, {r1}, {r1}\n",
            "adcs {r2}, {r2}, {r2}\n",
            "adcs {r3}, {r3}, {r3}\n",
            "cset {c}, cs\n",
            cond_sub_p!(),
        )
    };
}

/// `a + b mod p` for `a, b < p`.
#[inline]
pub(crate) fn add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: registers only; base ARMv8.0-A instructions.
    unsafe {
        asm!(
            "adds {r0}, {r0}, {t0}",
            "adcs {r1}, {r1}, {t1}",
            "adcs {r2}, {r2}, {t2}",
            "adcs {r3}, {r3}, {t3}",
            "cset {c}, cs",
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

/// `a - b mod p` for `a, b < p`.
#[inline]
pub(crate) fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: registers only; base ARMv8.0-A instructions.
    unsafe {
        asm!(
            "subs {r0}, {r0}, {b0}",
            "sbcs {r1}, {r1}, {b1}",
            "sbcs {r2}, {r2}, {b2}",
            "sbcs {r3}, {r3}, {b3}",
            // m = -borrow; add p & m (p₀ = 2⁶⁴ - 1, p₁ = 2³² - 1, p₂ = 0).
            "sbc {b0}, xzr, xzr",
            "lsr {b1}, {b0}, #32",
            "and {b3}, {b0}, #0xffffffff00000001",
            "adds {r0}, {r0}, {b0}",
            "adcs {r1}, {r1}, {b1}",
            "adcs {r2}, {r2}, xzr",
            "adc {r3}, {r3}, {b3}",
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
    debug_assert!((1..=3).contains(&k));
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    macro_rules! go {
        ($($step:expr),+) => {
            // SAFETY: registers only; base ARMv8.0-A instructions.
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

/// `3·a mod p` for `a < p`.
#[inline]
pub(crate) fn mul3(a: &[u64; 4]) -> [u64; 4] {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: registers only; base ARMv8.0-A instructions.
    unsafe {
        asm!(
            dbl_p!(),
            "adds {r0}, {r0}, {a0}",
            "adcs {r1}, {r1}, {a1}",
            "adcs {r2}, {r2}, {a2}",
            "adcs {r3}, {r3}, {a3}",
            "cset {c}, cs",
            cond_sub_p!(),
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            a0 = in(reg) a[0],
            a1 = in(reg) a[1],
            a2 = in(reg) a[2],
            a3 = in(reg) a[3],
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
    [r0, r1, r2, r3]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves::P256P;

    /// Random values below `m` plus the edges (0, 1, m - 1, m - 2, limbs of all ones or zeros).
    fn values(m: &[u64; 4]) -> Vec<[u64; 4]> {
        let mut vals: Vec<[u64; 4]> = vec![
            [0; 4],
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            crate::field::sub_small(m, 1),
            crate::field::sub_small(m, 2),
            [u64::MAX, 0, 0, 0],
            [0, 0, 0, m[3] - 1],
            [u64::MAX, 0xffff_ffff, 0, 0],
            [0, 0xffff_ffff, u64::MAX, m[3] - 1],
            [u64::MAX, u64::MAX, u64::MAX, m[3] - 1],
            [0, u64::MAX, 0, 0],
            [0, 0, u64::MAX, 0],
            [u64::MAX, u64::MAX, u64::MAX, 0],
            [0xffff_ffff, 0, 0, 0],
            [0xffff_ffff_0000_0000, 0, 0, 0],
        ];
        let mut rng = crate::rand::ChaChaRng::from_seed([0xa6; 32]);
        for _ in 0..3000 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let mut l = crate::field::be_to_limbs::<4>(&b).unwrap_or([0; 4]);
            if crate::ct::lt_limbs(&l, m) == 0 {
                l[3] &= 0x7fff_ffff_ffff_ffff;
            }
            vals.push(l);
        }
        // Sparse values: single bits and single 32-bit halves.
        for i in 0..256 {
            let mut l = [0u64; 4];
            l[i / 64] = 1 << (i % 64);
            if crate::ct::lt_limbs(&l, m) != 0 {
                vals.push(l);
            }
        }
        vals
    }

    fn generic_n(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
        crate::field::mont_mul_cios(x, y, &P256N::P, P256N::N0)
    }

    /// Against the portable arithmetic, on random and edge values.
    #[test]
    fn matches_portable() {
        if !cpu::cpu_has(Feature::Umulh) {
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
                    P256Pa::mod_mul_pow2(a, k),
                    P256P::mod_mul_pow2(a, k),
                    "2^{k} {a:x?}"
                );
            }
            assert_eq!(sqr(a), P256P::mont_sqr(a), "sqr {a:x?}");
            assert_eq!(
                P256Pa::mont_inv(a),
                Some(crate::ec::curves::p256_inv::<P256P>(a)),
                "inv {a:x?} (Montgomery form)"
            );
        }
        // Unreduced first operands below 2²⁵⁶ (from_limbs_reduce multiplies by R² < p), all-ones
        // limbs and values just at or above p.
        for big in [
            [u64::MAX; 4],
            P256P::P,
            [0, 0, 0, u64::MAX],
            [u64::MAX, u64::MAX, 0, u64::MAX],
        ] {
            for b in [
                P256P::R2,
                crate::field::sub_small(&P256P::P, 1),
                [1, 0, 0, 0],
            ] {
                assert_eq!(mul(&big, &b), P256P::mont_mul(&big, &b), "{big:x?}");
            }
        }

        assert_eq!(NINV, P256N::N0);
        assert_eq!(P256Na::P, P256N::P);
        let vals = values(&P256N::P);
        for (i, a) in vals.iter().enumerate() {
            let b = &vals[(i * 5 + 1) % vals.len()];
            for (x, y) in [(a, b), (b, a), (a, a)] {
                assert_eq!(ord_mul(x, y), generic_n(x, y), "ord_mul {x:x?} {y:x?}");
            }
            assert_eq!(ord_sqr(a), generic_n(a, a), "ord_sqr {a:x?}");
        }
        for big in [[u64::MAX; 4], P256N::P] {
            for b in [P256N::R2, crate::field::sub_small(&P256N::P, 1)] {
                assert_eq!(ord_mul(&big, &b), generic_n(&big, &b), "{big:x?}");
            }
        }
    }

    /// Long chains: every result feeds the next operation, so values from deep inside the
    /// arithmetic (not just fresh random ones) reach the assembly.
    #[test]
    fn chains_match_portable() {
        if !cpu::cpu_has(Feature::Umulh) {
            return;
        }
        let (mut x, mut y) = ([3u64, 5, 7, 11], [u64::MAX, 1, 0, 0xffff_ffff_0000_0000]);
        let (mut px, mut py) = (x, y);
        for i in 0..20_000 {
            let (t, pt) = match i % 6 {
                0 => (mul(&x, &y), P256P::mont_mul(&px, &py)),
                1 => (sqr(&x), P256P::mont_sqr(&px)),
                2 => (add(&x, &y), P256P::mod_add(&px, &py)),
                3 => (sub(&x, &y), P256P::mod_sub(&px, &py)),
                4 => (mul3(&x), P256P::mod_mul3(&px)),
                _ => (mul_pow2(&x, 1 + (i % 3) as u32), {
                    P256P::mod_mul_pow2(&px, 1 + (i % 3) as u32)
                }),
            };
            assert_eq!(t, pt, "step {i}");
            (x, y, px, py) = (t, x, pt, px);
        }
        let (mut x, mut y) = ([1u64, 2, 3, 4], P256N::R2);
        for i in 0..20_000 {
            let t = if i % 2 == 0 {
                ord_mul(&x, &y)
            } else {
                ord_sqr(&x)
            };
            let pt = generic_n(&x, if i % 2 == 0 { &y } else { &x });
            assert_eq!(t, pt, "ord step {i}");
            (x, y) = (t, x);
        }
    }

    /// The inversions on the assembly (Fermat chains and safegcd) match the portable chains.
    #[test]
    fn inverses() {
        if !cpu::cpu_has(Feature::Umulh) {
            return;
        }
        for a in values(&P256N::P).iter().take(200) {
            let want = crate::ec::curves::p256n_inv::<P256N>(a);
            assert_eq!(crate::ec::curves::p256n_inv::<P256Na>(a), want, "{a:x?}");
            assert_eq!(crate::safegcd::mont_inv::<P256Na>(a), want, "{a:x?}");
        }
        for a in values(&P256P::P).iter().take(200) {
            let want = crate::ec::curves::p256_inv::<P256P>(a);
            assert_eq!(crate::safegcd::mont_inv::<P256Pa>(a), want, "{a:x?}");
        }
    }

    /// The twin and the portable curve agree on every operation (the portable path called
    /// directly for the comparison).
    #[test]
    fn twin_matches_portable() {
        use super::super::{Scalar, base_mul_impl, ecdh_x_impl, sign_impl, verify_impl};
        use crate::hash::Sha256;
        if !cpu::cpu_has(Feature::Umulh) {
            return;
        }
        let mut rng = crate::rand::ChaChaRng::from_seed([0x78; 32]);
        for _ in 0..50 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let d = Scalar::<P256, 4>::from_be_bytes_reduce(&b).unwrap();
            rng.fill(&mut b);
            let e = Scalar::<P256, 4>::from_be_bytes_reduce(&b).unwrap();
            let q = base_mul_impl::<P256, 4>(&e);
            let qa = base_mul_impl::<P256A, 4>(&e).cast::<P256>();
            assert_eq!(q.to_uncompressed(), qa.to_uncompressed());
            let (mut o1, mut o2) = ([0u8; 32], [0u8; 32]);
            assert!(ecdh_x_impl::<P256, 4>(&d, &q, &mut o1));
            assert!(ecdh_x_impl::<P256A, 4>(&d, &q.cast(), &mut o2));
            assert_eq!(o1, o2);
            let s1 = sign_impl::<P256, Sha256, 4>(&d, &b);
            let s2 = sign_impl::<P256A, Sha256, 4>(&d, &b);
            assert_eq!((s1.r.l, s1.s.l), (s2.r.l, s2.s.l));
            let pd = base_mul_impl::<P256, 4>(&d);
            assert!(verify_impl::<P256, 4>(&pd, &b, &s1).is_ok());
            assert!(verify_impl::<P256A, 4>(&pd.cast(), &b, &s2.cast()).is_ok());
            b[0] ^= 1;
            assert!(verify_impl::<P256A, 4>(&pd.cast(), &b, &s2.cast()).is_err());
        }
    }
}
