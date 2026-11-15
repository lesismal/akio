//! AES-GCM on VAES + VPCLMULQDQ with AVX-512 (x86_64): sixteen blocks per loop iteration in
//! four 512-bit vectors of four blocks each, the AES rounds of one group interleaved with the
//! GHASH of the previous ciphertext group (sealing) or of the same group (opening), one GHASH
//! reduction per sixteen blocks. The design follows the `aes-gcm-avx10-x86_64` kernels of
//! BoringSSL and Linux (Eric Biggers); the code here is new.
//!
//! The VAES, VPCLMULQDQ and AVX-512 target features and intrinsics are not stable at the MSRV
//! (1.85), so the kernel is one `asm!` block per direction with fixed registers (all 32 vector
//! registers; `clobber_abi("C")` declares them clobbered) and is only entered after
//! `cpu::cpu_has(Feature::Vaes)` and `cpu::cpu_has(Feature::Avx512)` (CPUID, with the OS saving
//! the ZMM state in XCR0). On Zen 4 this 512-bit kernel was faster at every message size than
//! the same kernel on 256-bit registers (eight blocks per iteration), so only it is kept.
//!
//! GHASH runs on byte-reflected blocks (the layout of the other GHASH paths: `[lo, hi]` of the
//! block read as a big-endian integer), where a carry-less product of two field elements is
//! their GHASH product times `x¹²⁷` modulo the reflected polynomial
//! `G = x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1`. The key powers are stored premultiplied by `x`
//! ([`WidePowers::new`]), and each accumulated 256-bit product is reduced by `x¹²⁸` in two
//! Montgomery steps of one carry-less multiplication each (by `x⁶³ + x⁶² + x⁵⁷`), so the result
//! is the GHASH product in the same layout. AES and carry-less multiplication take constant time.

use super::RoundKeys;

/// Bytes per loop iteration: sixteen blocks, four vectors of four blocks.
pub(super) const CHUNK: usize = 256;

/// `H¹⁶ … H¹` (the first entry is `H¹⁶`), byte-reflected and multiplied by `x` modulo `G`, as
/// `[lo, hi]`: entry `i` multiplies the `i`-th block of a sixteen-block group.
#[derive(Clone)]
#[repr(C, align(64))]
pub(super) struct WidePowers([[u64; 2]; 16]);

impl WidePowers {
    /// From `H¹ … H¹⁶` in the GHASH layout (`[lo, hi]`, as the portable GHASH has them).
    pub(super) fn new(h: &[[u64; 2]; 16]) -> WidePowers {
        let mut p = [[0u64; 2]; 16];
        for (i, e) in p.iter_mut().enumerate() {
            let x = h[15 - i];
            let n = (u128::from(x[1]) << 64) | u128::from(x[0]);
            // Times `x` modulo G, branch-free: the bit shifted out selects the reduction.
            let carry = 0u128.wrapping_sub(n >> 127);
            let m = (n << 1) ^ (carry & ((0xc2u128 << 120) | 1));
            *e = [m as u64, (m >> 64) as u64];
        }
        WidePowers(p)
    }
}

/// Byte shuffles and constants of the kernel, at fixed offsets: `BSWAP` (0, reverses the bytes
/// of each 128-bit lane), `POLY` (64, `x⁶³ + x⁶² + x⁵⁷` in the high half of each lane), `LANES`
/// (128, lane `i` holds `i` in its low 32 bits: the counter offsets of one vector) and `INC`
/// (192, 4 in the low 32 bits of each lane: the counter step from one vector to the next).
#[repr(C, align(64))]
struct Consts {
    bswap: [u8; 64],
    poly: [u64; 8],
    lanes: [u32; 16],
    inc: [u32; 16],
}

const fn consts() -> Consts {
    let mut c = Consts {
        bswap: [0; 64],
        poly: [0; 8],
        lanes: [0; 16],
        inc: [0; 16],
    };
    let mut i = 0;
    while i < 64 {
        c.bswap[i] = 15 - (i % 16) as u8;
        i += 1;
    }
    let mut l = 0;
    while l < 4 {
        c.poly[2 * l] = 1;
        c.poly[2 * l + 1] = 0xc200_0000_0000_0000;
        c.lanes[4 * l] = l as u32;
        c.inc[4 * l] = 4;
        l += 1;
    }
    c
}

static CONSTS: Consts = consts();

// The kernel text. Vector registers (zmm): 0-3 AES states, 4-7 the byte-reflected ciphertext
// being hashed, 8-10 the LO/MI/HI product accumulators, 11-13 temporaries, 14 the GHASH state
// (low 128 bits), 15 the counter step, 16 round key 0, 17-20 the extra first round keys of
// AES-192/256, 21-29 the nine middle round keys before the last, 30 the last round key, 31 the
// next counters (byte-reflected, so the 32-bit counter is the low dword of each lane and wraps as
// GCM's inc32 does). GPR operands: `rk` round keys, `r` round count, `pw` powers, `c` constants,
// `ctr` first counter block, `y` GHASH state; fixed: rsi input, rdi output, rcx 256-byte groups
// left, rax scratch (outputs need explicit registers next to `clobber_abi`).

/// `op dst, src1, src2` on three zmm registers.
macro_rules! z3 {
    ($op:literal, $a:literal, $b:literal, $c:literal) => {
        concat!($op, " zmm", $a, ", zmm", $b, ", zmm", $c, "\n")
    };
}

/// One AES round (`vaesenc` with round key register `k`) on the four state vectors.
macro_rules! round4 {
    ($k:literal) => {
        concat!(
            z3!("vaesenc", "0", "0", $k),
            z3!("vaesenc", "1", "1", $k),
            z3!("vaesenc", "2", "2", $k),
            z3!("vaesenc", "3", "3", $k),
        )
    };
}

/// Broadcasts the round key `off` bytes below the last one (`t` points at it) to zmm `reg`.
macro_rules! bkey {
    ($reg:literal, $off:literal) => {
        concat!(
            "vbroadcasti32x4 zmm",
            $reg,
            ", xmmword ptr [rax - ",
            $off,
            "]\n"
        )
    };
}

/// Loads the round keys, the first counters, the counter step and the GHASH state.
macro_rules! setup {
    () => {
        concat!(
            "mov rax, {r}\n",
            "shl rax, 4\n",
            "add rax, {rk}\n",
            "vbroadcasti32x4 zmm16, xmmword ptr [{rk}]\n",
            "vbroadcasti32x4 zmm30, xmmword ptr [rax]\n",
            bkey!("21", "144"),
            bkey!("22", "128"),
            bkey!("23", "112"),
            bkey!("24", "96"),
            bkey!("25", "80"),
            bkey!("26", "64"),
            bkey!("27", "48"),
            bkey!("28", "32"),
            bkey!("29", "16"),
            "cmp {r}, 12\n",
            "jb 6f\n",
            bkey!("19", "176"),
            bkey!("20", "160"),
            "je 6f\n",
            bkey!("17", "208"),
            bkey!("18", "192"),
            "6:\n",
            "vbroadcasti32x4 zmm31, xmmword ptr [{ctr}]\n",
            "vpshufb zmm31, zmm31, zmmword ptr [{c}]\n",
            "vpaddd zmm31, zmm31, zmmword ptr [{c} + 128]\n",
            "vmovdqu64 zmm15, zmmword ptr [{c} + 192]\n",
            "vmovdqu xmm14, xmmword ptr [{y}]\n",
        )
    };
}

/// The next sixteen counter blocks, XORed with round key 0, into zmm0-3.
macro_rules! ctr4 {
    () => {
        concat!(
            "vpshufb zmm0, zmm31, zmmword ptr [{c}]\n",
            z3!("vpaddd", "31", "31", "15"),
            "vpshufb zmm1, zmm31, zmmword ptr [{c}]\n",
            z3!("vpaddd", "31", "31", "15"),
            "vpshufb zmm2, zmm31, zmmword ptr [{c}]\n",
            z3!("vpaddd", "31", "31", "15"),
            "vpshufb zmm3, zmm31, zmmword ptr [{c}]\n",
            z3!("vpaddd", "31", "31", "15"),
            z3!("vpxord", "0", "0", "16"),
            z3!("vpxord", "1", "1", "16"),
            z3!("vpxord", "2", "2", "16"),
            z3!("vpxord", "3", "3", "16"),
        )
    };
}

/// The rounds AES-192 (two) and AES-256 (four) have before the common last ten.
macro_rules! extra {
    () => {
        concat!(
            "cmp {r}, 12\n",
            "jb 5f\n",
            "je 4f\n",
            round4!("17"),
            round4!("18"),
            "4:\n",
            round4!("19"),
            round4!("20"),
            "5:\n",
        )
    };
}

/// The first GHASH vector (zmm4, the GHASH state already XORed into its first block) times
/// `H¹⁶ … H¹³`: starts the accumulators.
macro_rules! ghash0 {
    () => {
        concat!(
            "vpclmulqdq zmm8, zmm4, zmmword ptr [{pw}], 0x00\n",
            "vpclmulqdq zmm11, zmm4, zmmword ptr [{pw}], 0x01\n",
            "vpclmulqdq zmm12, zmm4, zmmword ptr [{pw}], 0x10\n",
            "vpclmulqdq zmm10, zmm4, zmmword ptr [{pw}], 0x11\n",
            z3!("vpxord", "9", "11", "12"),
        )
    };
}

/// GHASH vector `g` (zmm5-7) times the powers at byte offset `off`, into the accumulators.
macro_rules! ghash {
    ($g:literal, $off:literal) => {
        concat!(
            "vpclmulqdq zmm11, zmm",
            $g,
            ", zmmword ptr [{pw} + ",
            $off,
            "], 0x00\n",
            "vpclmulqdq zmm12, zmm",
            $g,
            ", zmmword ptr [{pw} + ",
            $off,
            "], 0x01\n",
            "vpclmulqdq zmm13, zmm",
            $g,
            ", zmmword ptr [{pw} + ",
            $off,
            "], 0x10\n",
            z3!("vpxord", "8", "8", "11"),
            "vpternlogd zmm9, zmm12, zmm13, 0x96\n",
            "vpclmulqdq zmm11, zmm",
            $g,
            ", zmmword ptr [{pw} + ",
            $off,
            "], 0x11\n",
            z3!("vpxord", "10", "10", "11"),
        )
    };
}

/// XORs the four 128-bit lanes of each accumulator into its low lane.
macro_rules! fold {
    () => {
        concat!(
            "vextracti64x4 ymm11, zmm8, 1\n",
            "vextracti64x4 ymm12, zmm9, 1\n",
            "vextracti64x4 ymm13, zmm10, 1\n",
            "vpxor ymm8, ymm8, ymm11\n",
            "vpxor ymm9, ymm9, ymm12\n",
            "vpxor ymm10, ymm10, ymm13\n",
            "vextracti128 xmm11, ymm8, 1\n",
            "vextracti128 xmm12, ymm9, 1\n",
            "vextracti128 xmm13, ymm10, 1\n",
            "vpxor xmm8, xmm8, xmm11\n",
            "vpxor xmm9, xmm9, xmm12\n",
            "vpxor xmm10, xmm10, xmm13\n",
        )
    };
}

/// First Montgomery step: the low 64 bits of LO times the polynomial, folded with LO's swapped
/// halves into MI.
macro_rules! reduce1 {
    () => {
        concat!(
            "vpclmulqdq xmm11, xmm8, xmmword ptr [{c} + 64], 0x10\n",
            "vpshufd xmm8, xmm8, 0x4e\n",
            "vpternlogd xmm9, xmm8, xmm11, 0x96\n",
        )
    };
}

/// Second step: the same with MI folded into HI; the result is the new GHASH state (xmm14,
/// upper lanes zero).
macro_rules! reduce2 {
    () => {
        concat!(
            "vpclmulqdq xmm11, xmm9, xmmword ptr [{c} + 64], 0x10\n",
            "vpshufd xmm9, xmm9, 0x4e\n",
            "vpternlogd xmm10, xmm9, xmm11, 0x96\n",
            "vmovdqa xmm14, xmm10\n",
        )
    };
}

/// The last AES round with the data XORed into the round key (`vaesenclast` then yields
/// keystream ⊕ data), stored back over the data.
macro_rules! last4 {
    () => {
        concat!(
            "vpxord zmm11, zmm30, zmmword ptr [rsi]\n",
            "vaesenclast zmm0, zmm0, zmm11\n",
            "vpxord zmm12, zmm30, zmmword ptr [rsi + 64]\n",
            "vaesenclast zmm1, zmm1, zmm12\n",
            "vpxord zmm13, zmm30, zmmword ptr [rsi + 128]\n",
            "vaesenclast zmm2, zmm2, zmm13\n",
            "vpxord zmm11, zmm30, zmmword ptr [rsi + 192]\n",
            "vaesenclast zmm3, zmm3, zmm11\n",
            "vmovdqu64 zmmword ptr [rdi], zmm0\n",
            "vmovdqu64 zmmword ptr [rdi + 64], zmm1\n",
            "vmovdqu64 zmmword ptr [rdi + 128], zmm2\n",
            "vmovdqu64 zmmword ptr [rdi + 192], zmm3\n",
        )
    };
}

/// One group's AES rounds interleaved with the GHASH of zmm4-7 (the state XORed in first).
macro_rules! rounds_ghash {
    () => {
        concat!(
            z3!("vpxord", "4", "4", "14"),
            extra!(),
            round4!("21"),
            ghash0!(),
            round4!("22"),
            ghash!("5", "64"),
            round4!("23"),
            ghash!("6", "128"),
            round4!("24"),
            ghash!("7", "192"),
            round4!("25"),
            fold!(),
            round4!("26"),
            reduce1!(),
            round4!("27"),
            reduce2!(),
            round4!("28"),
            round4!("29"),
            last4!(),
        )
    };
}

/// zmm4-7 = the group just written, byte-reflected (sealing hashes the ciphertext it made).
macro_rules! keep_ct {
    () => {
        concat!(
            "vpshufb zmm4, zmm0, zmmword ptr [{c}]\n",
            "vpshufb zmm5, zmm1, zmmword ptr [{c}]\n",
            "vpshufb zmm6, zmm2, zmmword ptr [{c}]\n",
            "vpshufb zmm7, zmm3, zmmword ptr [{c}]\n",
        )
    };
}

/// zmm4-7 = the group about to be decrypted, byte-reflected (opening hashes its input).
macro_rules! load_ct {
    () => {
        concat!(
            "vmovdqu64 zmm4, zmmword ptr [rsi]\n",
            "vmovdqu64 zmm5, zmmword ptr [rsi + 64]\n",
            "vmovdqu64 zmm6, zmmword ptr [rsi + 128]\n",
            "vmovdqu64 zmm7, zmmword ptr [rsi + 192]\n",
            "vpshufb zmm4, zmm4, zmmword ptr [{c}]\n",
            "vpshufb zmm5, zmm5, zmmword ptr [{c}]\n",
            "vpshufb zmm6, zmm6, zmmword ptr [{c}]\n",
            "vpshufb zmm7, zmm7, zmmword ptr [{c}]\n",
        )
    };
}

/// Sealing: the first group is only encrypted, each later one is encrypted while the previous
/// ciphertext group is hashed, and the last ciphertext group is hashed after the loop.
macro_rules! seal_kernel {
    () => {
        concat!(
            setup!(),
            ctr4!(),
            extra!(),
            round4!("21"),
            round4!("22"),
            round4!("23"),
            round4!("24"),
            round4!("25"),
            round4!("26"),
            round4!("27"),
            round4!("28"),
            round4!("29"),
            last4!(),
            keep_ct!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jz 3f\n",
            "2:\n",
            ctr4!(),
            rounds_ghash!(),
            keep_ct!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jnz 2b\n",
            "3:\n",
            z3!("vpxord", "4", "4", "14"),
            ghash0!(),
            ghash!("5", "64"),
            ghash!("6", "128"),
            ghash!("7", "192"),
            fold!(),
            reduce1!(),
            reduce2!(),
            "vmovdqu xmmword ptr [{y}], xmm14\n",
            "vzeroupper\n",
        )
    };
}

/// Opening: each group is hashed while it is decrypted.
macro_rules! open_kernel {
    () => {
        concat!(
            setup!(),
            "2:\n",
            load_ct!(),
            ctr4!(),
            rounds_ghash!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jnz 2b\n",
            "vmovdqu xmmword ptr [{y}], xmm14\n",
            "vzeroupper\n",
        )
    };
}

/// CTR-encrypts (`open == false`) or decrypts the `len` bytes at `src` into `dst` with the AES
/// round keys `rk`, starting at the counter block `ctr` (32-bit big-endian counter in the last
/// four bytes, wrapping), and absorbs the ciphertext into the GHASH state `y`. `src == dst`
/// works in place: each 256-byte group is read before it is written.
///
/// # Safety
///
/// The CPU must support AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ, AVX2 and AVX-512 F/BW/VL, and the
/// OS must save the YMM and ZMM state (`Feature::Vaes` and `Feature::Avx512` of `cpu.rs`);
/// `len` is a nonzero multiple of [`CHUNK`]; `src` is valid for reading and `dst` for writing
/// `len` bytes, and the two ranges are the same or do not overlap; `rk.1` is 10, 12 or 14.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn crypt(
    p: &WidePowers,
    rk: RoundKeys<'_>,
    ctr: &[u8; 16],
    y: &mut [u64; 2],
    src: *const u8,
    dst: *mut u8,
    len: usize,
    open: bool,
) {
    let n = len / CHUNK;
    debug_assert!(n > 0 && len % CHUNK == 0);
    debug_assert!(matches!(rk.1, 10 | 12 | 14));
    if open {
        // SAFETY: the caller guarantees the CPU and OS features and the `src` / `dst` ranges.
        // The kernel reads the round keys `rk.0[0]` and `rk.0[r - 13 ..= r]` (only those with
        // index >= 1 for r = 12, 14; `r <= 14` so all lie in the 15-entry array), the 256 bytes
        // of `p`, the 256 bytes of `CONSTS`, 16 bytes of `ctr` and of `y`, `n * 256` bytes at
        // `src`, and writes `n * 256` bytes at `dst` (`n >= 1`; each group is loaded before it
        // is stored) and 16 bytes of `y`, all unaligned. It uses no stack and clobbers only
        // registers declared here (all vector registers through `clobber_abi("C")`, the flags),
        // ending with `vzeroupper`.
        unsafe {
            core::arch::asm!(
                open_kernel!(),
                rk = in(reg) rk.0.as_ptr(),
                r = in(reg) rk.1,
                pw = in(reg) p.0.as_ptr(),
                c = in(reg) &raw const CONSTS,
                ctr = in(reg) ctr.as_ptr(),
                y = in(reg) y.as_mut_ptr(),
                inout("rsi") src => _,
                inout("rdi") dst => _,
                inout("rcx") n => _,
                out("rax") _,
                clobber_abi("C"),
                options(nostack),
            );
        }
    } else {
        // SAFETY: as above (the same reads and writes).
        unsafe {
            core::arch::asm!(
                seal_kernel!(),
                rk = in(reg) rk.0.as_ptr(),
                r = in(reg) rk.1,
                pw = in(reg) p.0.as_ptr(),
                c = in(reg) &raw const CONSTS,
                ctr = in(reg) ctr.as_ptr(),
                y = in(reg) y.as_mut_ptr(),
                inout("rsi") src => _,
                inout("rdi") dst => _,
                inout("rcx") n => _,
                out("rax") _,
                clobber_abi("C"),
                options(nostack),
            );
        }
    }
}
