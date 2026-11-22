//! Poly1305 on AVX-512 IFMA (x86_64): eight blocks per iteration, one per 64-bit lane, in the
//! 44/44/42-bit limbs of the scalar code. Lane `i` accumulates blocks `i, 8 + i, 16 + i, …` and
//! is multiplied by `r⁸` per iteration; at the end lane `i` is multiplied by `r⁸⁻ⁱ` and the lanes
//! are summed (by the caller). A product of two limbs (each below 2⁵²) is
//! `vpmadd52luq` (its low 52 bits) plus `vpmadd52huq` (the high ones, worth 2⁵²): the carry out
//! of a 44-bit limb is the low sum shifted right by 44 plus the high sum shifted left by 8 (by 10
//! for the 42-bit top limb, folded back through `2¹³⁰ ≡ 5`). The design follows OpenSSL's
//! `poly1305_blocks_vpmadd52` (Andy Polyakov); the code here is new.
//!
//! AVX-512 IFMA is not stable at the MSRV (1.85), so the kernel is one `asm!` block with fixed
//! registers, entered only after `cpu::cpu_has(Feature::Ifma)` (CPUID, with the OS saving the ZMM
//! state in XCR0). Multiplications, additions, shifts and masks only: constant time.

/// `vpermi2q` indices gathering the low (offset 0) and the high (64) 64-bit halves of eight
/// consecutive blocks from two vectors of four.
#[repr(C, align(64))]
struct Consts {
    lo: [u64; 8],
    hi: [u64; 8],
}

static CONSTS: Consts = Consts {
    lo: [0, 2, 4, 6, 8, 10, 12, 14],
    hi: [1, 3, 5, 7, 9, 11, 13, 15],
};

// Lane 0 of the powers is `r⁸`, the per-iteration multiplier.
use super::Powers;

/// `H = H·R` and the carry back to 44/44/42-bit limbs; `H` in zmm0-2, the multiplier limbs
/// `r0 r1 r2 s1 s2` in the five registers given, products in zmm3-8, masks in zmm14/15, zmm21
/// scratch.
macro_rules! mul {
    ($r0:literal, $r1:literal, $r2:literal, $s1:literal, $s2:literal) => {
        concat!(
            "vpxorq zmm3, zmm3, zmm3\n",
            "vpxorq zmm4, zmm4, zmm4\n",
            "vpxorq zmm5, zmm5, zmm5\n",
            "vpxorq zmm6, zmm6, zmm6\n",
            "vpxorq zmm7, zmm7, zmm7\n",
            "vpxorq zmm8, zmm8, zmm8\n",
            "vpmadd52luq zmm3, zmm2, zmm",
            $s1,
            "\n",
            "vpmadd52huq zmm4, zmm2, zmm",
            $s1,
            "\n",
            "vpmadd52luq zmm5, zmm2, zmm",
            $s2,
            "\n",
            "vpmadd52huq zmm6, zmm2, zmm",
            $s2,
            "\n",
            "vpmadd52luq zmm7, zmm2, zmm",
            $r0,
            "\n",
            "vpmadd52huq zmm8, zmm2, zmm",
            $r0,
            "\n",
            "vpmadd52luq zmm3, zmm1, zmm",
            $s2,
            "\n",
            "vpmadd52huq zmm4, zmm1, zmm",
            $s2,
            "\n",
            "vpmadd52luq zmm5, zmm1, zmm",
            $r0,
            "\n",
            "vpmadd52huq zmm6, zmm1, zmm",
            $r0,
            "\n",
            "vpmadd52luq zmm7, zmm1, zmm",
            $r1,
            "\n",
            "vpmadd52huq zmm8, zmm1, zmm",
            $r1,
            "\n",
            "vpmadd52luq zmm3, zmm0, zmm",
            $r0,
            "\n",
            "vpmadd52huq zmm4, zmm0, zmm",
            $r0,
            "\n",
            "vpmadd52luq zmm5, zmm0, zmm",
            $r1,
            "\n",
            "vpmadd52huq zmm6, zmm0, zmm",
            $r1,
            "\n",
            "vpmadd52luq zmm7, zmm0, zmm",
            $r2,
            "\n",
            "vpmadd52huq zmm8, zmm0, zmm",
            $r2,
            "\n",
            // d0 → h0, carry into d1.
            "vpsrlq zmm21, zmm3, 44\n",
            "vpsllq zmm4, zmm4, 8\n",
            "vpandq zmm0, zmm3, zmm14\n",
            "vpaddq zmm4, zmm4, zmm21\n",
            "vpaddq zmm5, zmm5, zmm4\n",
            // d1 → h1, carry into d2.
            "vpsrlq zmm21, zmm5, 44\n",
            "vpsllq zmm6, zmm6, 8\n",
            "vpandq zmm1, zmm5, zmm14\n",
            "vpaddq zmm6, zmm6, zmm21\n",
            "vpaddq zmm7, zmm7, zmm6\n",
            // d2 → h2, the carry past 2^130 times 5 into h0, then h0's carry into h1.
            "vpsrlq zmm21, zmm7, 42\n",
            "vpsllq zmm8, zmm8, 10\n",
            "vpandq zmm2, zmm7, zmm15\n",
            "vpaddq zmm8, zmm8, zmm21\n",
            "vpaddq zmm0, zmm0, zmm8\n",
            "vpsllq zmm8, zmm8, 2\n",
            "vpaddq zmm0, zmm0, zmm8\n",
            "vpsrlq zmm21, zmm0, 44\n",
            "vpandq zmm0, zmm0, zmm14\n",
            "vpaddq zmm1, zmm1, zmm21\n",
        )
    };
}

/// Adds the eight blocks at `rsi` (with the 2¹²⁸ bit, zmm16) to `H`.
macro_rules! add_blocks {
    () => {
        concat!(
            "vmovdqu64 zmm17, zmmword ptr [rsi]\n",
            "vmovdqu64 zmm18, zmmword ptr [rsi + 64]\n",
            "vmovdqa64 zmm19, zmm22\n",
            "vpermi2q zmm19, zmm17, zmm18\n",
            "vmovdqa64 zmm20, zmm23\n",
            "vpermi2q zmm20, zmm17, zmm18\n",
            "vpandq zmm21, zmm19, zmm14\n",
            "vpaddq zmm0, zmm0, zmm21\n",
            "vpsrlq zmm19, zmm19, 44\n",
            "vpsllq zmm21, zmm20, 20\n",
            "vporq zmm19, zmm19, zmm21\n",
            "vpandq zmm19, zmm19, zmm14\n",
            "vpaddq zmm1, zmm1, zmm19\n",
            "vpsrlq zmm20, zmm20, 24\n",
            "vporq zmm20, zmm20, zmm16\n",
            "vpaddq zmm2, zmm2, zmm20\n",
            "add rsi, 128\n",
        )
    };
}

/// Absorbs `n` groups of eight full blocks at `m` into the lane accumulators `acc` (three limbs
/// of eight lanes: the caller puts its `h` in lane 0 and zeros elsewhere) and leaves in `acc` the
/// lanes multiplied by their powers (`pw`), each limb below 2⁴⁵: the new `h` is the sum of the
/// lanes.
///
/// # Safety
///
/// The CPU must support AVX-512 F and IFMA with the OS saving the ZMM state; `n >= 1`; `m` must be
/// readable for `n * 128` bytes. The limbs of `acc` must be below 2⁴⁵ and those of `pw` below
/// 2⁵² (as `r` and its powers are, partially reduced, with `20·r1`, `20·r2` below 2⁵⁰).
pub(super) unsafe fn blocks(acc: &mut [u64; 24], pw: &Powers, m: *const u8, n: usize) {
    debug_assert!(n >= 1);
    // SAFETY: the caller guarantees the CPU and OS features and the `m` range. The kernel reads
    // `acc` (192 bytes), `pw` (320 bytes), the constants and `n * 128` bytes from `m`, writes
    // `acc`, uses no stack and clobbers only the registers declared here (all vector registers
    // through `clobber_abi("C")`, the flags), ending with `vzeroupper`.
    unsafe {
        core::arch::asm!(
            "mov rax, 0xfffffffffff\n",
            "vpbroadcastq zmm14, rax\n",
            "mov rax, 0x3ffffffffff\n",
            "vpbroadcastq zmm15, rax\n",
            "mov rax, 0x10000000000\n",
            "vpbroadcastq zmm16, rax\n",
            "vmovdqa64 zmm22, zmmword ptr [{c}]\n",
            "vmovdqa64 zmm23, zmmword ptr [{c} + 64]\n",
            "vpbroadcastq zmm9, qword ptr [{p}]\n",
            "vpbroadcastq zmm10, qword ptr [{p} + 64]\n",
            "vpbroadcastq zmm11, qword ptr [{p} + 128]\n",
            "vpbroadcastq zmm12, qword ptr [{p} + 192]\n",
            "vpbroadcastq zmm13, qword ptr [{p} + 256]\n",
            "vmovdqu64 zmm0, zmmword ptr [{h}]\n",
            "vmovdqu64 zmm1, zmmword ptr [{h} + 64]\n",
            "vmovdqu64 zmm2, zmmword ptr [{h} + 128]\n",
            add_blocks!(),
            "dec rcx\n",
            "jz 3f\n",
            "2:\n",
            mul!("9", "10", "11", "12", "13"),
            add_blocks!(),
            "dec rcx\n",
            "jnz 2b\n",
            "3:\n",
            "vmovdqu64 zmm24, zmmword ptr [{p}]\n",
            "vmovdqu64 zmm25, zmmword ptr [{p} + 64]\n",
            "vmovdqu64 zmm26, zmmword ptr [{p} + 128]\n",
            "vmovdqu64 zmm27, zmmword ptr [{p} + 192]\n",
            "vmovdqu64 zmm28, zmmword ptr [{p} + 256]\n",
            mul!("24", "25", "26", "27", "28"),
            "vmovdqu64 zmmword ptr [{h}], zmm0\n",
            "vmovdqu64 zmmword ptr [{h} + 64], zmm1\n",
            "vmovdqu64 zmmword ptr [{h} + 128], zmm2\n",
            "vzeroupper\n",
            h = in(reg) acc.as_mut_ptr(),
            p = in(reg) pw.as_ptr(),
            c = in(reg) &raw const CONSTS,
            inout("rsi") m => _,
            inout("rcx") n => _,
            out("rax") _,
            clobber_abi("C"),
            options(nostack),
        );
    }
}
