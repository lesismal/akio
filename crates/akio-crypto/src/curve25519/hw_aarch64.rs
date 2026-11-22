//! The X25519 Montgomery ladder on aarch64: arithmetic modulo `p = 2²⁵⁵ - 19` on four 64-bit
//! limbs in inline assembly (`MUL`/`UMULH`, `ADDS`/`ADCS` carry chains, `CSEL`), the ladder itself
//! in safe Rust; the counterpart of the x86_64 BMI2 + ADX module `curve25519::hw`. Chosen by
//! `x25519::x25519` when [`enabled`]; the portable ladder (radix 2⁵¹) is the reference and the
//! fallback.
//!
//! Why four 64-bit limbs (the choice follows the instruction counts; 1.18× the portable radix-2⁵¹
//! ladder on an Apple M4 Pro, docs/BENCHMARKS.md): a
//! product is 16 `MUL` + 16 `UMULH` (a square 10 + 10) plus the fold by 38, against 25 128-bit
//! products (50 instructions) and the carry propagation of radix 2⁵¹; aarch64 has no
//! 64×64 → 128-bit instruction, so the halves cost the same either way.
//!
//! Elements are kept below `2²⁵⁶` (not fully reduced): a product folds its high half back with
//! `2²⁵⁶ ≡ 38 (mod p)`, additions and subtractions fold their carry or borrow the same way, and
//! only the final encoding reduces fully. Constant time: the assembly is straight-line (the
//! folds pick 38 or 0 with `CSEL` on the carry flag), the ladder swaps with masks (`ct::swap`),
//! and the inversion is a fixed addition chain.
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the `asm!`
//! blocks, which take their operands in registers and write nothing but their register outputs
//! (`pure`, `nomem`, `nostack`). Base ARMv8.0-A instructions only; [`enabled`] is
//! `cpu::has(Feature::Umulh)`, set on every aarch64 target outside Miri and cleared by
//! `AKIO_CRYPTO_PORTABLE=1` / `set_portable(true)`.
#![allow(unsafe_code)]

use std::arch::asm;

use crate::cpu::{self, Feature};
use crate::ct;
use crate::ec::hw_aarch64::{mul_row, mul_rows, sqr_rows};

/// Whether to use this module: aarch64 outside Miri, and the portable code is not forced.
#[inline]
pub(crate) fn enabled() -> bool {
    cpu::has(Feature::Umulh)
}

type Fe = [u64; 4];

/// `{z0}..{z7}` reduced to four limbs below `2²⁵⁶` in `{z0}..{z3}`, with `$k` a free register
/// and `$l0..$l3`, `{t0}..{t3}` scratch: the high half times 38 added to the low half (the top
/// word `hi(38·z₇) + carries ≤ 39`), then that word times 38 added to limb 0, then 38 once more
/// if that carried (the sum is then tiny, so no further carry).
macro_rules! reduce_38 {
    ($k:literal, $l0:literal, $l1:literal, $l2:literal, $l3:literal) => {
        concat!(
            "mov ",
            $k,
            ", #38\n",
            "mul ",
            $l0,
            ", {z4}, ",
            $k,
            "\n",
            "mul ",
            $l1,
            ", {z5}, ",
            $k,
            "\n",
            "mul ",
            $l2,
            ", {z6}, ",
            $k,
            "\n",
            "mul ",
            $l3,
            ", {z7}, ",
            $k,
            "\n",
            "umulh {t0}, {z4}, ",
            $k,
            "\n",
            "umulh {t1}, {z5}, ",
            $k,
            "\n",
            "umulh {t2}, {z6}, ",
            $k,
            "\n",
            "umulh {t3}, {z7}, ",
            $k,
            "\n",
            "adds {z0}, {z0}, ",
            $l0,
            "\n",
            "adcs {z1}, {z1}, ",
            $l1,
            "\n",
            "adcs {z2}, {z2}, ",
            $l2,
            "\n",
            "adcs {z3}, {z3}, ",
            $l3,
            "\n",
            "adc {t3}, {t3}, xzr\n",
            "adds {z1}, {z1}, {t0}\n",
            "adcs {z2}, {z2}, {t1}\n",
            "adcs {z3}, {z3}, {t2}\n",
            "adc {t3}, {t3}, xzr\n",
            "mul {t3}, {t3}, ",
            $k,
            "\n",
            "adds {z0}, {z0}, {t3}\n",
            "adcs {z1}, {z1}, xzr\n",
            "adcs {z2}, {z2}, xzr\n",
            "adcs {z3}, {z3}, xzr\n",
            "csel {t3}, ",
            $k,
            ", xzr, cs\n",
            "add {z0}, {z0}, {t3}\n",
        )
    };
}

/// `a·b mod p`, below `2²⁵⁶`.
#[inline]
fn mul(a: &Fe, b: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: registers only (no memory, no stack); base ARMv8.0-A instructions.
    unsafe {
        asm!(
            mul_rows!(),
            // a and b are dead: scratch for the fold.
            reduce_38!("{b0}", "{a0}", "{a1}", "{a2}", "{a3}"),
            a0 = inout(reg) a[0] => _,
            a1 = inout(reg) a[1] => _,
            a2 = inout(reg) a[2] => _,
            a3 = inout(reg) a[3] => _,
            b0 = inout(reg) b[0] => _,
            b1 = inout(reg) b[1] => _,
            b2 = inout(reg) b[2] => _,
            b3 = inout(reg) b[3] => _,
            z0 = out(reg) r0,
            z1 = out(reg) r1,
            z2 = out(reg) r2,
            z3 = out(reg) r3,
            z4 = out(reg) _,
            z5 = out(reg) _,
            z6 = out(reg) _,
            z7 = out(reg) _,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a² mod p`, below `2²⁵⁶`.
#[inline]
fn sqr(a: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: registers only (no memory, no stack); base ARMv8.0-A instructions.
    unsafe {
        asm!(
            sqr_rows!(),
            reduce_38!("{k}", "{a0}", "{a1}", "{a2}", "{a3}"),
            a0 = inout(reg) a[0] => _,
            a1 = inout(reg) a[1] => _,
            a2 = inout(reg) a[2] => _,
            a3 = inout(reg) a[3] => _,
            z0 = out(reg) r0,
            z1 = out(reg) r1,
            z2 = out(reg) r2,
            z3 = out(reg) r3,
            z4 = out(reg) _,
            z5 = out(reg) _,
            z6 = out(reg) _,
            z7 = out(reg) _,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            k = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `121665·a mod p` (the ladder's `(A - 2)/4`), below `2²⁵⁶`.
#[inline]
fn mul_a24(a: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: registers only; base ARMv8.0-A instructions.
    unsafe {
        asm!(
            // k = 121665 = 0x1db41.
            "movz {k}, #0xdb41",
            "movk {k}, #0x1, lsl #16",
            "mul {r0}, {a0}, {k}",
            "mul {r1}, {a1}, {k}",
            "mul {r2}, {a2}, {k}",
            "mul {r3}, {a3}, {k}",
            "umulh {a0}, {a0}, {k}",
            "umulh {a1}, {a1}, {k}",
            "umulh {a2}, {a2}, {k}",
            "umulh {a3}, {a3}, {k}",
            "adds {r1}, {r1}, {a0}",
            "adcs {r2}, {r2}, {a1}",
            "adcs {r3}, {r3}, {a2}",
            "adc {a3}, {a3}, xzr",
            // The top word (below 2¹⁷) times 38 into limb 0, then 38 once more on a carry.
            "mov {k}, #38",
            "mul {a3}, {a3}, {k}",
            "adds {r0}, {r0}, {a3}",
            "adcs {r1}, {r1}, xzr",
            "adcs {r2}, {r2}, xzr",
            "adcs {r3}, {r3}, xzr",
            "csel {a3}, {k}, xzr, cs",
            "add {r0}, {r0}, {a3}",
            a0 = inout(reg) a[0] => _,
            a1 = inout(reg) a[1] => _,
            a2 = inout(reg) a[2] => _,
            a3 = inout(reg) a[3] => _,
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            k = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a + b mod p`, below `2²⁵⁶`.
#[inline]
fn add(a: &Fe, b: &Fe) -> Fe {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: registers only; base ARMv8.0-A instructions.
    unsafe {
        asm!(
            "mov {k}, #38",
            "adds {r0}, {r0}, {b0}",
            "adcs {r1}, {r1}, {b1}",
            "adcs {r2}, {r2}, {b2}",
            "adcs {r3}, {r3}, {b3}",
            // 2²⁵⁶ ≡ 38: fold the carry, then the (only possible, tiny) second one.
            "csel {b0}, {k}, xzr, cs",
            "adds {r0}, {r0}, {b0}",
            "adcs {r1}, {r1}, xzr",
            "adcs {r2}, {r2}, xzr",
            "adcs {r3}, {r3}, xzr",
            "csel {b0}, {k}, xzr, cs",
            "add {r0}, {r0}, {b0}",
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            b0 = inout(reg) b[0] => _,
            b1 = in(reg) b[1],
            b2 = in(reg) b[2],
            b3 = in(reg) b[3],
            k = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a - b mod p`, below `2²⁵⁶`.
#[inline]
fn sub(a: &Fe, b: &Fe) -> Fe {
    let [mut r0, mut r1, mut r2, mut r3] = *a;
    // SAFETY: registers only; base ARMv8.0-A instructions.
    unsafe {
        asm!(
            "mov {k}, #38",
            "subs {r0}, {r0}, {b0}",
            "sbcs {r1}, {r1}, {b1}",
            "sbcs {r2}, {r2}, {b2}",
            "sbcs {r3}, {r3}, {b3}",
            // A borrow (carry clear) wrapped by 2²⁵⁶ ≡ 38: take 38 off, then once more if that
            // borrowed (the value is then just below 2²⁵⁶, so no further borrow).
            "csel {b0}, {k}, xzr, cc",
            "subs {r0}, {r0}, {b0}",
            "sbcs {r1}, {r1}, xzr",
            "sbcs {r2}, {r2}, xzr",
            "sbcs {r3}, {r3}, xzr",
            "csel {b0}, {k}, xzr, cc",
            "sub {r0}, {r0}, {b0}",
            r0 = inout(reg) r0,
            r1 = inout(reg) r1,
            r2 = inout(reg) r2,
            r3 = inout(reg) r3,
            b0 = inout(reg) b[0] => _,
            b1 = in(reg) b[1],
            b2 = in(reg) b[2],
            b3 = in(reg) b[3],
            k = out(reg) _,
            options(pure, nomem, nostack),
        );
    }
    [r0, r1, r2, r3]
}

fn sqn(a: &Fe, n: usize) -> Fe {
    let mut r = *a;
    for _ in 0..n {
        r = sqr(&r);
    }
    r
}

/// `a^(p-2)`, the inverse (0 for 0): the ref10 addition chain (254 squarings, 11 multiplications).
fn invert(z: &Fe) -> Fe {
    let z2 = sqr(z);
    let z9 = mul(&sqn(&z2, 2), z);
    let z11 = mul(&z9, &z2);
    let z_5_0 = mul(&sqr(&z11), &z9);
    let z_10_0 = mul(&sqn(&z_5_0, 5), &z_5_0);
    let z_20_0 = mul(&sqn(&z_10_0, 10), &z_10_0);
    let z_40_0 = mul(&sqn(&z_20_0, 20), &z_20_0);
    let z_50_0 = mul(&sqn(&z_40_0, 10), &z_10_0);
    let z_100_0 = mul(&sqn(&z_50_0, 50), &z_50_0);
    let z_200_0 = mul(&sqn(&z_100_0, 100), &z_100_0);
    let z_250_0 = mul(&sqn(&z_200_0, 50), &z_50_0);
    mul(&sqn(&z_250_0, 5), &z11)
}

/// The canonical 32-byte encoding of `a < 2²⁵⁶`, without branches: fold bit 255 (`2²⁵⁵ ≡ 19`),
/// then subtract `p` where the value is at least `p` (`a + 19` reaches bit 255).
fn to_bytes(a: &Fe) -> [u8; 32] {
    let mut r = *a;
    let top = r[3] >> 63;
    r[3] &= u64::MAX >> 1;
    let mut c = u128::from(19 * top);
    for x in &mut r {
        c += u128::from(*x);
        *x = c as u64;
        c >>= 64;
    }
    // Now r < 2²⁵⁵ + 19. t = r + 19 - 2²⁵⁵ when that is non-negative, i.e. r ≥ p.
    let mut t = [0u64; 4];
    let mut c = 19u128;
    for (d, &x) in t.iter_mut().zip(&r) {
        c += u128::from(x);
        *d = c as u64;
        c >>= 64;
    }
    let ge = ct::mask(t[3] >> 63);
    t[3] &= u64::MAX >> 1;
    ct::assign(ge, &mut r, &t);
    let mut out = [0u8; 32];
    for (i, x) in r.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// X25519 for a clamped scalar `k` and the u-coordinate `u` (top bit ignored): the Montgomery
/// ladder of RFC 7748 §5 with masked swaps, then one inversion. Callers check [`enabled`].
pub(crate) fn ladder(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut x1 = [0u64; 4];
    for (i, x) in x1.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&u[8 * i..8 * i + 8]);
        *x = u64::from_le_bytes(w);
    }
    x1[3] &= u64::MAX >> 1;
    let mut x2: Fe = [1, 0, 0, 0];
    let mut z2: Fe = [0; 4];
    let mut x3 = x1;
    let mut z3: Fe = [1, 0, 0, 0];
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= kt;
        let m = ct::mask(swap);
        ct::swap(m, &mut x2, &mut x3);
        ct::swap(m, &mut z2, &mut z3);
        swap = kt;
        let a = add(&x2, &z2);
        let aa = sqr(&a);
        let b = sub(&x2, &z2);
        let bb = sqr(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = sqr(&add(&da, &cb));
        z3 = mul(&x1, &sqr(&sub(&da, &cb)));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&aa, &mul_a24(&e)));
    }
    let m = ct::mask(swap);
    ct::swap(m, &mut x2, &mut x3);
    ct::swap(m, &mut z2, &mut z3);
    to_bytes(&mul(&x2, &invert(&z2)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve25519::fe;

    /// The portable element for `a < 2²⁵⁶`: `a mod 2²⁵⁵` plus 19 for bit 255 (`2²⁵⁵ ≡ 19`).
    fn to_fe(a: &Fe) -> fe::Fe {
        let mut b = [0u8; 32];
        for (i, x) in a.iter().enumerate() {
            b[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes());
        }
        let lo = fe::Fe::from_bytes(&b); // ignores bit 255
        if a[3] >> 63 == 1 {
            lo.add(&fe::Fe::from_u64(19))
        } else {
            lo
        }
    }

    fn le(a: &Fe) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (j, x) in a.iter().enumerate() {
            b[8 * j..8 * j + 8].copy_from_slice(&x.to_le_bytes());
        }
        b
    }

    const P: Fe = [
        0xffff_ffff_ffff_ffed,
        u64::MAX,
        u64::MAX,
        0x7fff_ffff_ffff_ffff,
    ];

    /// Edge values (0, 1, p - 1, p, p + 1, 2p - 1, 2p, 2²⁵⁵ - 1, 2²⁵⁶ - 1 and neighbours, all-ones
    /// limbs) and random ones.
    fn values() -> Vec<Fe> {
        let mut vals: Vec<Fe> = vec![
            [0; 4],
            [1, 0, 0, 0],
            [P[0] - 1, P[1], P[2], P[3]],
            P,
            [P[0] + 1, P[1], P[2], P[3]],
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1],
            [u64::MAX; 4],
            [u64::MAX - 37, u64::MAX, u64::MAX, u64::MAX],
            [u64::MAX - 38, u64::MAX, u64::MAX, u64::MAX],
            [0xffff_ffff_ffff_ffda, u64::MAX, u64::MAX, u64::MAX],
            [0xffff_ffff_ffff_ffdb, u64::MAX, u64::MAX, u64::MAX],
            [37, 0, 0, 0],
            [38, 0, 0, 0],
            [39, 0, 0, 0],
            [0, 0, 0, 1 << 63],
            [u64::MAX, 0, 0, 0],
            [0, u64::MAX, 0, 0],
            [0, 0, u64::MAX, 0],
            [0, 0, 0, u64::MAX],
        ];
        let mut rng = crate::rand::ChaChaRng::from_seed([0x1a; 32]);
        for _ in 0..2000 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            let mut l = [0u64; 4];
            for (i, x) in l.iter_mut().enumerate() {
                let mut w = [0u8; 8];
                w.copy_from_slice(&b[8 * i..8 * i + 8]);
                *x = u64::from_le_bytes(w);
            }
            vals.push(l);
        }
        vals
    }

    /// Field operations and the ladder against the portable code, on random and edge values.
    #[test]
    fn matches_portable() {
        if !cpu::cpu_has(Feature::Umulh) {
            return;
        }
        let vals = values();
        for (i, a) in vals.iter().enumerate() {
            let b = &vals[(i * 7 + 3) % vals.len()];
            let (fa, fb) = (to_fe(a), to_fe(b));
            for (x, y, fx, fy) in [(a, b, &fa, &fb), (b, a, &fb, &fa), (a, a, &fa, &fa)] {
                assert_eq!(
                    to_bytes(&mul(x, y)),
                    fx.mul(fy).to_bytes(),
                    "mul {x:x?} {y:x?}"
                );
                assert_eq!(
                    to_bytes(&add(x, y)),
                    fx.add(fy).to_bytes(),
                    "add {x:x?} {y:x?}"
                );
                assert_eq!(
                    to_bytes(&sub(x, y)),
                    fx.sub(fy).to_bytes(),
                    "sub {x:x?} {y:x?}"
                );
            }
            assert_eq!(to_bytes(&sqr(a)), fa.square().to_bytes(), "sqr {a:x?}");
            assert_eq!(
                to_bytes(&mul_a24(a)),
                fa.mul_small(121_665).to_bytes(),
                "a24 {a:x?}"
            );
            assert_eq!(to_bytes(a), fa.to_bytes(), "to_bytes {a:x?}");
            if i < 300 {
                assert_eq!(to_bytes(&invert(a)), fa.invert().to_bytes(), "inv {a:x?}");
            }
        }
        // The ladder on random scalars and points, including u ≥ p and the top bit set.
        let mut rng = crate::rand::ChaChaRng::from_seed([0x25; 32]);
        for (i, u) in vals.iter().enumerate().take(300) {
            let mut k = [0u8; 32];
            rng.fill(&mut k);
            if i == 0 {
                k = [0xff; 32];
            }
            if i == 1 {
                k = [0; 32];
            }
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
            assert_eq!(
                ladder(&k, &le(u)),
                crate::x25519::x25519_portable(&k, &le(u))
            );
        }
    }

    /// Long chains: every result feeds the next operation, so unreduced values from deep inside
    /// the arithmetic (not just fresh random ones) reach the assembly.
    #[test]
    fn chains_match_portable() {
        if !cpu::cpu_has(Feature::Umulh) {
            return;
        }
        let (mut x, mut y): (Fe, Fe) = ([u64::MAX; 4], [9, 0, 0, 0]);
        let (mut fx, mut fy) = (to_fe(&x), to_fe(&y));
        for i in 0..50_000 {
            let (t, ft) = match i % 5 {
                0 => (mul(&x, &y), fx.mul(&fy)),
                1 => (sqr(&x), fx.square()),
                2 => (add(&x, &y), fx.add(&fy)),
                3 => (sub(&x, &y), fx.sub(&fy)),
                _ => (mul_a24(&x), fx.mul_small(121_665)),
            };
            assert_eq!(to_bytes(&t), ft.to_bytes(), "step {i}");
            (x, y, fx, fy) = (t, x, ft, fx);
        }
    }
}
