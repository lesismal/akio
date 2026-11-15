//! The X25519 Montgomery ladder on x86_64 with BMI2 (`mulx`) and ADX (`adcx`/`adox`): arithmetic
//! modulo `p = 2²⁵⁵ - 19` on four 64-bit limbs in inline assembly, the ladder itself in safe
//! Rust. Chosen by `x25519::x25519` when [`enabled`]; the portable ladder (radix 2⁵¹) is the
//! reference and the fallback.
//!
//! Elements are kept below `2²⁵⁶` (not fully reduced): a product folds its high half back with
//! `2²⁵⁶ ≡ 38 (mod p)`, additions and subtractions fold their carry or borrow the same way, and
//! only the final encoding reduces fully. Constant time: the assembly is straight-line (the
//! folds use `sbb` masks), the ladder swaps with masks (`ct::swap`), and the inversion is a fixed
//! addition chain.
//!
//! One of the crate's hardware modules (docs/unsafe-review.md): `unsafe` only for the `asm!`
//! blocks, which read the 32-byte limb arrays behind their pointer operands and write nothing but
//! their register outputs. `mulx`, `adcx` and `adox` need BMI2 and ADX: [`ladder`] is only
//! called after [`enabled`] (`cpu::has(Feature::Adx)`), and every function here debug-asserts
//! it.
#![allow(unsafe_code)]

use std::arch::asm;

use crate::cpu::{self, Feature};
use crate::ct;
use crate::ec::hw::{mul_rows, sqr_rows};

/// Whether to use this module: the CPU has BMI2 and ADX, and the portable code is not forced.
#[inline]
pub(crate) fn enabled() -> bool {
    cpu::has(Feature::Adx)
}

type Fe = [u64; 4];

/// `z0..z7` (`r8..r15`) reduced to four limbs below `2²⁵⁶` in `r8..r11`, with `$zero` a register
/// holding 0 (set before the flags were last cleared): the high half times 38 added to the low
/// half (`rdx = 38`; the top word `hi(38·z₇) + carries ≤ 39`), then that word times 38 added to
/// limb 0, then 38 once more if that carried (the sum is then tiny, so no further carry).
macro_rules! reduce_38 {
    ($zero:literal) => {
        concat!(
            "mov edx, 38\n",
            "mulx rcx, rax, r12\n",
            "adcx r8, rax\n",
            "adox r9, rcx\n",
            "mulx rcx, rax, r13\n",
            "adcx r9, rax\n",
            "adox r10, rcx\n",
            "mulx rcx, rax, r14\n",
            "adcx r10, rax\n",
            "adox r11, rcx\n",
            "mulx rcx, rax, r15\n",
            "adcx r11, rax\n",
            "adox rcx, ",
            $zero,
            "\n",
            "adcx rcx, ",
            $zero,
            "\n",
            "imul rcx, rcx, 38\n",
            "add r8, rcx\n",
            "adc r9, 0\n",
            "adc r10, 0\n",
            "adc r11, 0\n",
            "sbb rcx, rcx\n",
            "and rcx, 38\n",
            "add r8, rcx\n",
        )
    };
}

/// `a·b mod p`, below `2²⁵⁶`.
#[inline]
fn mul(a: &Fe, b: &Fe) -> Fe {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind each of `a` and `b` (live 32-byte arrays), writes only the
    // declared registers (no stack). BMI2 and ADX: only reached from `ladder`, called after
    // `enabled()` (asserted in debug builds above).
    unsafe {
        asm!(
            mul_rows!(),
            // {a} is dead: zero (this also clears CF and OF for the fold).
            "xor {a:e}, {a:e}",
            reduce_38!("{a}"),
            a = inout(reg) a.as_ptr() => _,
            b = in(reg) b.as_ptr(),
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") r0,
            out("r9") r1,
            out("r10") r2,
            out("r11") r3,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a² mod p`, below `2²⁵⁶`.
#[inline]
fn sqr(a: &Fe) -> Fe {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind `a` (a live 32-byte array), writes only the declared
    // registers (no stack). BMI2 and ADX: only reached from `ladder`, called after `enabled()`
    // (asserted in debug builds above).
    unsafe {
        asm!(
            sqr_rows!(),
            "xor {a:e}, {a:e}",
            reduce_38!("{a}"),
            a = inout(reg) a.as_ptr() => _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r8") r0,
            out("r9") r1,
            out("r10") r2,
            out("r11") r3,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `121665·a mod p` (the ladder's `(A - 2)/4`), below `2²⁵⁶`.
#[inline]
fn mul_a24(a: &Fe) -> Fe {
    debug_assert!(cpu::cpu_has(Feature::Adx));
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind `a` (a live 32-byte array), writes only the declared
    // registers. BMI2 (`mulx`): only reached from `ladder`, called after `enabled()`.
    unsafe {
        asm!(
            "mov edx, 121665",
            "mulx {r1}, {r0}, [{a}]",
            "mulx {r2}, {t}, [{a} + 8]",
            "add {r1}, {t}",
            "mulx {r3}, {t}, [{a} + 16]",
            "adc {r2}, {t}",
            "mulx {h}, {t}, [{a} + 24]",
            "adc {r3}, {t}",
            "adc {h}, 0",
            "imul {h}, {h}, 38",
            "add {r0}, {h}",
            "adc {r1}, 0",
            "adc {r2}, 0",
            "adc {r3}, 0",
            "sbb {h}, {h}",
            "and {h}, 38",
            "add {r0}, {h}",
            a = in(reg) a.as_ptr(),
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            t = out(reg) _,
            h = out(reg) _,
            out("rdx") _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a + b mod p`, below `2²⁵⁶`.
#[inline]
fn add(a: &Fe, b: &Fe) -> Fe {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: reads the 4 limbs behind each of `a` and `b` (live 32-byte arrays), writes only the
    // declared registers. Base x86_64 instructions only.
    unsafe {
        asm!(
            "mov {r0}, [{a}]",
            "mov {r1}, [{a} + 8]",
            "mov {r2}, [{a} + 16]",
            "mov {r3}, [{a} + 24]",
            "add {r0}, [{b}]",
            "adc {r1}, [{b} + 8]",
            "adc {r2}, [{b} + 16]",
            "adc {r3}, [{b} + 24]",
            // 2²⁵⁶ ≡ 38: fold the carry, then the (only possible, tiny) second one.
            "sbb {t}, {t}",
            "and {t}, 38",
            "add {r0}, {t}",
            "adc {r1}, 0",
            "adc {r2}, 0",
            "adc {r3}, 0",
            "sbb {t}, {t}",
            "and {t}, 38",
            "add {r0}, {t}",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            t = out(reg) _,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a - b mod p`, below `2²⁵⁶`.
#[inline]
fn sub(a: &Fe, b: &Fe) -> Fe {
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
            // A borrow wrapped by 2²⁵⁶ ≡ 38: take 38 off, then once more if that borrowed (the
            // value is then just below 2²⁵⁶, so no further borrow).
            "sbb {t}, {t}",
            "and {t}, 38",
            "sub {r0}, {t}",
            "sbb {r1}, 0",
            "sbb {r2}, 0",
            "sbb {r3}, 0",
            "sbb {t}, {t}",
            "and {t}, 38",
            "sub {r0}, {t}",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            r0 = out(reg) r0,
            r1 = out(reg) r1,
            r2 = out(reg) r2,
            r3 = out(reg) r3,
            t = out(reg) _,
            options(pure, readonly, nostack),
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

    /// Field operations and the ladder against the portable code, on random and edge values
    /// (0, 1, p - 1, p, p + 1, 2²⁵⁵ - 1, 2²⁵⁶ - 1 and neighbours).
    #[test]
    fn matches_portable() {
        if !cpu::cpu_has(Feature::Adx) {
            return;
        }
        let p: Fe = [
            0xffff_ffff_ffff_ffed,
            u64::MAX,
            u64::MAX,
            0x7fff_ffff_ffff_ffff,
        ];
        let mut vals: Vec<Fe> = vec![
            [0; 4],
            [1, 0, 0, 0],
            [p[0] - 1, p[1], p[2], p[3]],
            p,
            [p[0] + 1, p[1], p[2], p[3]],
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1],
            [u64::MAX; 4],
            [u64::MAX - 37, u64::MAX, u64::MAX, u64::MAX],
            [37, 0, 0, 0],
            [38, 0, 0, 0],
            [0, 0, 0, 1 << 63],
        ];
        let mut rng = crate::rand::ChaChaRng::from_seed([0x19; 32]);
        for _ in 0..1000 {
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
        for (i, a) in vals.iter().enumerate() {
            let b = &vals[(i * 7 + 3) % vals.len()];
            let (fa, fb) = (to_fe(a), to_fe(b));
            assert_eq!(
                to_bytes(&mul(a, b)),
                fa.mul(&fb).to_bytes(),
                "mul {a:x?} {b:x?}"
            );
            assert_eq!(
                to_bytes(&add(a, b)),
                fa.add(&fb).to_bytes(),
                "add {a:x?} {b:x?}"
            );
            assert_eq!(
                to_bytes(&sub(a, b)),
                fa.sub(&fb).to_bytes(),
                "sub {a:x?} {b:x?}"
            );
            assert_eq!(to_bytes(&sqr(a)), fa.square().to_bytes(), "sqr {a:x?}");
            assert_eq!(
                to_bytes(&mul_a24(a)),
                fa.mul_small(121_665).to_bytes(),
                "a24 {a:x?}"
            );
            assert_eq!(to_bytes(&invert(a)), fa.invert().to_bytes(), "inv {a:x?}");
        }
        // The ladder on random scalars and points, including u ≥ p and the top bit set.
        for (i, u) in vals.iter().enumerate().take(300) {
            let mut ub = [0u8; 32];
            for (j, x) in u.iter().enumerate() {
                ub[8 * j..8 * j + 8].copy_from_slice(&x.to_le_bytes());
            }
            let mut k = [0u8; 32];
            rng.fill(&mut k);
            if i == 0 {
                k = [0xff; 32];
            }
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
            assert_eq!(ladder(&k, &ub), crate::x25519::x25519_portable(&k, &ub));
        }
    }
}
