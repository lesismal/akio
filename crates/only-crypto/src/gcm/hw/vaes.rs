//! AES-GCM on VAES + VPCLMULQDQ (x86_64), two kernels:
//!
//! - **AVX-512** ([`crypt512`]): sixteen blocks per loop iteration in four 512-bit vectors of
//!   four blocks each, the AES rounds of one group interleaved with the GHASH of the previous
//!   ciphertext group (sealing) or of the same group (opening), one GHASH reduction per sixteen
//!   blocks. The whole message runs in one call: the AAD (up to 256 bytes) is hashed first, the
//!   last partial group (1 to 255 bytes) is loaded and stored with AVX-512 byte masks and hashed
//!   with the powers of its length, and the length block and `E(J0)` give the tag.
//! - **AVX2** ([`crypt256`]), for CPUs with VAES and VPCLMULQDQ but no AVX-512 (Zen 3, Alder
//!   Lake): sixteen blocks per iteration in eight 256-bit vectors, one reduction per sixteen
//!   blocks, only the sixteen VEX registers (the round keys and constants come from memory);
//!   whole 256-byte groups only, the rest goes through the 128-bit path.
//!
//! The design follows the `aes-gcm-avx10-x86_64` and `aes-gcm-vaes-avx2` kernels of BoringSSL
//! and Linux (Eric Biggers); the code here is new.
//!
//! The VAES, VPCLMULQDQ and AVX-512 target features and intrinsics are not stable at the MSRV
//! (1.85), so each kernel is one `asm!` block per direction with fixed registers
//! (`clobber_abi("C")` declares every vector and mask register clobbered), entered only after
//! `cpu::cpu_has(Feature::Vaes)` (CPUID, with the OS saving the YMM state in XCR0) and, for
//! the 512-bit one, `cpu::cpu_has(Feature::Avx512)` (the ZMM and opmask state too).
//!
//! GHASH runs on byte-reflected blocks (the layout of the other GHASH paths: `[lo, hi]` of the
//! block read as a big-endian integer), where a carry-less product of two field elements is
//! their GHASH product times `x¹²⁷` modulo the reflected polynomial
//! `G = x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1`. The key powers are stored premultiplied by `x`
//! ([`WidePowers::new`]), and each accumulated 256-bit product is reduced by `x¹²⁸` in two
//! Montgomery steps of one carry-less multiplication each (by `x⁶³ + x⁶² + x⁵⁷`), so the result
//! is the GHASH product in the same layout. AES and carry-less multiplication take constant
//! time; the byte masks depend only on the (public) lengths.

use super::RoundKeys;

/// Bytes per loop iteration of the AVX-512 kernel: sixteen blocks, four vectors of four blocks.
pub(super) const CHUNK: usize = 256;
/// Bytes per loop iteration of the AVX2 kernel: sixteen blocks, eight vectors of two blocks.
pub(super) const CHUNK2: usize = 256;

/// `H¹⁶ … H¹` (the first entry is `H¹⁶`), byte-reflected and multiplied by `x` modulo `G`, as
/// `[lo, hi]`, then sixteen zero entries: entry `i` multiplies the `i`-th block of a
/// sixteen-block group, and a group of `n < 16` blocks starts at entry `16 - n` (its missing
/// blocks are zero and meet the zero entries).
#[derive(Clone)]
#[repr(C, align(64))]
pub(super) struct WidePowers([[u64; 2]; 32]);

impl WidePowers {
    /// From `H¹ … H¹⁶` in the GHASH layout (`[lo, hi]`, as the portable GHASH has them).
    pub(super) fn new(h: &[[u64; 2]; 16]) -> WidePowers {
        let mut p = [[0u64; 2]; 32];
        for (i, e) in p.iter_mut().take(16).enumerate() {
            let x = h[15 - i];
            let n = (u128::from(x[1]) << 64) | u128::from(x[0]);
            // Times `x` modulo G, branch-free: the bit shifted out selects the reduction.
            let carry = 0u128.wrapping_sub(n >> 127);
            let m = (n << 1) ^ (carry & ((0xc2u128 << 120) | 1));
            *e = [m as u64, (m >> 64) as u64];
        }
        WidePowers(p)
    }

    /// The powers for a group of `bytes` (1 to 256) bytes: from entry `16 - ⌈bytes / 16⌉`.
    fn for_len(&self, bytes: usize) -> *const u8 {
        debug_assert!((1..=CHUNK).contains(&bytes));
        self.0[16 - bytes.div_ceil(16)..].as_ptr().cast()
    }
}

/// Byte shuffles and constants of the kernels, at fixed offsets: `BSWAP` (0, reverses the bytes
/// of each 128-bit lane), `POLY` (64, `x⁶³ + x⁶² + x⁵⁷` in the high half of each lane), `LANES`
/// (128, lane `i` holds `i` in its low 32 bits: the counter offsets of one vector), `INC`
/// (192, 4 in the low 32 bits of each lane: the counter step from one 512-bit vector to the
/// next) and `INC2` (256, 2 in the low 32 bits of the two lanes of a 256-bit vector).
#[repr(C, align(64))]
struct Consts {
    bswap: [u8; 64],
    poly: [u64; 8],
    lanes: [u32; 16],
    inc: [u32; 16],
    inc2: [u32; 16],
}

const fn consts() -> Consts {
    let mut c = Consts {
        bswap: [0; 64],
        poly: [0; 8],
        lanes: [0; 16],
        inc: [0; 16],
        inc2: [0; 16],
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
    c.inc2[0] = 2;
    c.inc2[4] = 2;
    c
}

static CONSTS: Consts = consts();

/// The memory operand of one call of the AVX-512 kernel, at the fixed offsets the kernel text
/// uses (checked below).
#[repr(C, align(64))]
pub(super) struct Args {
    /// Byte masks of the four vectors of the last partial group (all zero: none).
    tail_mask: [u64; 4],
    /// Byte masks of the four vectors of the AAD hashed first (all zero: none).
    aad_mask: [u64; 4],
    /// The length block in the GHASH layout.
    lens: [u64; 2],
    /// `J0`.
    j0: [u8; 16],
    /// The counter block of the first data byte.
    ctr: [u8; 16],
    /// The GHASH state, in and out.
    y: [u64; 2],
    /// `E(J0)`, and with `fin` the tag.
    tag: [u8; 16],
    /// The powers for the tail ([`WidePowers::for_len`]).
    tail_pow: *const u8,
    /// Where the tail is read from.
    tail_src: *const u8,
    /// The AAD.
    aad: *const u8,
    /// The powers for the AAD.
    aad_pow: *const u8,
    /// Nonzero: hash the length block and make the tag.
    fin: u64,
    /// The short path ([`Args::short`]): 0 none, 1 with one vector each for the AAD and the
    /// data, 4 with four.
    short: u64,
}

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(Args, tail_mask) == 0);
    assert!(offset_of!(Args, aad_mask) == 32);
    assert!(offset_of!(Args, lens) == 64);
    assert!(offset_of!(Args, j0) == 80);
    assert!(offset_of!(Args, ctr) == 96);
    assert!(offset_of!(Args, y) == 112);
    assert!(offset_of!(Args, tag) == 128);
    assert!(offset_of!(Args, tail_pow) == 144);
    assert!(offset_of!(Args, tail_src) == 152);
    assert!(offset_of!(Args, aad) == 160);
    assert!(offset_of!(Args, aad_pow) == 168);
    assert!(offset_of!(Args, fin) == 176);
    assert!(offset_of!(Args, short) == 184);
    assert!(offset_of!(Consts, poly) == 64);
    assert!(offset_of!(Consts, lanes) == 128);
    assert!(offset_of!(Consts, inc) == 192);
    assert!(offset_of!(Consts, inc2) == 256);
};

/// The bytes four masks select.
fn ones(m: &[u64; 4]) -> usize {
    m.iter().map(|m| m.count_ones() as usize).sum()
}

/// The byte masks of `len` (at most 256) bytes spread over four 64-byte vectors.
fn masks(len: usize) -> [u64; 4] {
    debug_assert!(len <= CHUNK);
    let mut m = [0u64; 4];
    for (i, m) in m.iter_mut().enumerate() {
        let b = len.saturating_sub(64 * i).min(64);
        *m = if b == 64 { u64::MAX } else { (1u64 << b) - 1 };
    }
    m
}

impl Args {
    /// Whole groups only, from the counter block `ctr` and the GHASH state `y`.
    pub(super) fn new(ctr: &[u8; 16], y: [u64; 2]) -> Args {
        Args {
            tail_mask: [0; 4],
            aad_mask: [0; 4],
            lens: [0; 2],
            j0: [0; 16],
            ctr: *ctr,
            y,
            tag: [0; 16],
            tail_pow: core::ptr::null(),
            tail_src: core::ptr::null(),
            aad: core::ptr::null(),
            aad_pow: core::ptr::null(),
            fin: 0,
            short: 0,
        }
    }

    /// Hashes `aad` (at most 256 bytes, zero-padded to whole blocks) before the data.
    pub(super) fn aad(&mut self, p: &WidePowers, aad: &[u8]) {
        assert!(aad.len() <= CHUNK);
        if !aad.is_empty() {
            self.aad_mask = masks(aad.len());
            self.aad = aad.as_ptr();
            self.aad_pow = p.for_len(aad.len());
        }
    }

    /// The `tail_len` (under 256) bytes after the whole groups, read from `src` (valid for
    /// `tail_len` bytes, checked by the caller of [`crypt512`]).
    pub(super) fn tail(&mut self, p: &WidePowers, src: *const u8, tail_len: usize) {
        assert!(tail_len < CHUNK);
        if tail_len > 0 {
            self.tail_mask = masks(tail_len);
            self.tail_src = src;
            self.tail_pow = p.for_len(tail_len);
        }
    }

    /// Ends the message: the length block of `aad_len` and `ct_len` bytes is hashed and the tag
    /// made with `J0`.
    pub(super) fn finish(&mut self, j0: &[u8; 16], aad_len: usize, ct_len: usize) {
        self.j0 = *j0;
        self.lens = [(ct_len as u64) << 3, (aad_len as u64) << 3];
        self.fin = 1;
    }

    /// Takes the short path when it can (called after [`aad`](Self::aad),
    /// [`tail`](Self::tail) and [`finish`](Self::finish), with no whole groups, the GHASH state
    /// still zero and a tail): the AAD, the tail and the length block, `T` blocks in all, are
    /// multiplied by `Hᵀ … H¹` and reduced once, instead of one reduction each.
    pub(super) fn short(&mut self, p: &WidePowers) {
        let (aad, tail) = (ones(&self.aad_mask), self.tail_len());
        let (na, nb) = (aad.div_ceil(16), tail.div_ceil(16));
        if self.fin == 0 || self.y != [0, 0] || tail == 0 || na + nb + 1 > 16 {
            return;
        }
        self.aad_pow = p.0[16 - (na + nb + 1)..].as_ptr().cast();
        self.tail_pow = p.0[15 - nb..].as_ptr().cast();
        if aad == 0 {
            // Never read (the AAD masks are zero), but a valid pointer all the same.
            self.aad = self.aad_pow;
        }
        self.short = if aad <= 64 && tail <= 64 { 1 } else { 4 };
    }

    /// The tail length in bytes (from the masks).
    fn tail_len(&self) -> usize {
        ones(&self.tail_mask)
    }

    /// The GHASH state after the call.
    pub(super) fn y(&self) -> [u64; 2] {
        self.y
    }

    /// The tag after a call with [`finish`](Self::finish).
    pub(super) fn tag(&self) -> [u8; 16] {
        self.tag
    }
}

// ---- The AVX-512 kernel ----
//
// Vector registers (zmm): 0-3 AES states, 4-7 the byte-reflected ciphertext being hashed, 8-10
// the LO/MI/HI product accumulators, 11-13 temporaries, 14 the GHASH state (low 128 bits), 15
// the counter step, 16 round key 0, 17-20 the extra first round keys of AES-192/256, 21-29 the
// nine middle round keys before the last, 30 the last round key, 31 the next counters
// (byte-reflected, so the 32-bit counter is the low dword of each lane and wraps as GCM's inc32
// does). Mask registers k1-k4: the byte masks of the AAD, then of the tail. GPR operands: `rk`
// round keys, `r` round count, `pw` powers, `c` constants, `a` the `Args`; fixed: rsi input,
// rdi output, rcx 256-byte groups, rax scratch (outputs need explicit registers next to
// `clobber_abi`). Local labels: 2/3 loop, 4/5 round count, 6 key setup, 7-9 and 12-14 the
// tail, AAD and final paths (no labels of only 0 and 1 digits).

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

/// Broadcasts the round key `off` bytes below the last one (`rax` points at it) to zmm `reg`.
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
            "vbroadcasti32x4 zmm31, xmmword ptr [{a} + 96]\n",
            "vpshufb zmm31, zmm31, zmmword ptr [{c}]\n",
            "vpaddd zmm31, zmm31, zmmword ptr [{c} + 128]\n",
            "vmovdqu64 zmm15, zmmword ptr [{c} + 192]\n",
            "vmovdqu xmm14, xmmword ptr [{a} + 112]\n",
        )
    };
}

/// `E(J0)` on one lane (stored for the tag; independent of everything else, so it overlaps
/// with the first group).
macro_rules! ej0 {
    () => {
        concat!(
            "vmovdqu xmm0, xmmword ptr [{a} + 80]\n",
            "vpxord xmm0, xmm0, xmm16\n",
            "cmp {r}, 12\n",
            "jb 5f\n",
            "je 4f\n",
            "vaesenc xmm0, xmm0, xmm17\n",
            "vaesenc xmm0, xmm0, xmm18\n",
            "4:\n",
            "vaesenc xmm0, xmm0, xmm19\n",
            "vaesenc xmm0, xmm0, xmm20\n",
            "5:\n",
            "vaesenc xmm0, xmm0, xmm21\n",
            "vaesenc xmm0, xmm0, xmm22\n",
            "vaesenc xmm0, xmm0, xmm23\n",
            "vaesenc xmm0, xmm0, xmm24\n",
            "vaesenc xmm0, xmm0, xmm25\n",
            "vaesenc xmm0, xmm0, xmm26\n",
            "vaesenc xmm0, xmm0, xmm27\n",
            "vaesenc xmm0, xmm0, xmm28\n",
            "vaesenc xmm0, xmm0, xmm29\n",
            "vaesenclast xmm0, xmm0, xmm30\n",
            "vmovdqu xmmword ptr [{a} + 128], xmm0\n",
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

/// All AES rounds but the last on zmm0-3, without GHASH.
macro_rules! rounds {
    () => {
        concat!(
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
        )
    };
}

/// The first GHASH vector (zmm4, the GHASH state already XORed into its first block) times
/// the four powers at `[p]`: starts the accumulators.
macro_rules! ghash0 {
    ($p:literal) => {
        concat!(
            "vpclmulqdq zmm8, zmm4, zmmword ptr [",
            $p,
            "], 0x00\n",
            "vpclmulqdq zmm11, zmm4, zmmword ptr [",
            $p,
            "], 0x01\n",
            "vpclmulqdq zmm12, zmm4, zmmword ptr [",
            $p,
            "], 0x10\n",
            "vpclmulqdq zmm10, zmm4, zmmword ptr [",
            $p,
            "], 0x11\n",
            z3!("vpxord", "9", "11", "12"),
        )
    };
}

/// GHASH vector `g` (zmm5-7) times the powers at `[p + off]`, into the accumulators.
macro_rules! ghash {
    ($g:literal, $p:literal, $off:literal) => {
        concat!(
            "vpclmulqdq zmm11, zmm",
            $g,
            ", zmmword ptr [",
            $p,
            " + ",
            $off,
            "], 0x00\n",
            "vpclmulqdq zmm12, zmm",
            $g,
            ", zmmword ptr [",
            $p,
            " + ",
            $off,
            "], 0x01\n",
            "vpclmulqdq zmm13, zmm",
            $g,
            ", zmmword ptr [",
            $p,
            " + ",
            $off,
            "], 0x10\n",
            z3!("vpxord", "8", "8", "11"),
            "vpternlogd zmm9, zmm12, zmm13, 0x96\n",
            "vpclmulqdq zmm11, zmm",
            $g,
            ", zmmword ptr [",
            $p,
            " + ",
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

/// zmm4-7 (a whole or masked group, byte-reflected) hashed into the state with the powers at
/// `[p]`, reduced.
macro_rules! ghash_all {
    ($p:literal) => {
        concat!(
            z3!("vpxord", "4", "4", "14"),
            ghash0!($p),
            ghash!("5", $p, "64"),
            ghash!("6", $p, "128"),
            ghash!("7", $p, "192"),
            fold!(),
            reduce1!(),
            reduce2!(),
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

/// [`last4`] on the tail: the data loaded and the result stored under the byte masks k1-k4
/// (masked-off bytes are neither read nor written, and load as zero).
macro_rules! last4m {
    () => {
        concat!(
            "vmovdqu8 zmm11 {{k1}} {{z}}, zmmword ptr [rsi]\n",
            "vpxord zmm11, zmm11, zmm30\n",
            "vaesenclast zmm0, zmm0, zmm11\n",
            "vmovdqu8 zmm12 {{k2}} {{z}}, zmmword ptr [rsi + 64]\n",
            "vpxord zmm12, zmm12, zmm30\n",
            "vaesenclast zmm1, zmm1, zmm12\n",
            "vmovdqu8 zmm13 {{k3}} {{z}}, zmmword ptr [rsi + 128]\n",
            "vpxord zmm13, zmm13, zmm30\n",
            "vaesenclast zmm2, zmm2, zmm13\n",
            "vmovdqu8 zmm11 {{k4}} {{z}}, zmmword ptr [rsi + 192]\n",
            "vpxord zmm11, zmm11, zmm30\n",
            "vaesenclast zmm3, zmm3, zmm11\n",
            "vmovdqu8 zmmword ptr [rdi] {{k1}}, zmm0\n",
            "vmovdqu8 zmmword ptr [rdi + 64] {{k2}}, zmm1\n",
            "vmovdqu8 zmmword ptr [rdi + 128] {{k3}}, zmm2\n",
            "vmovdqu8 zmmword ptr [rdi + 192] {{k4}}, zmm3\n",
        )
    };
}

/// One group's AES rounds but the last, interleaved with the GHASH of zmm4-7 (the state XORed
/// in first) with the powers at `[p]`.
macro_rules! rounds_ghash {
    ($p:literal) => {
        concat!(
            z3!("vpxord", "4", "4", "14"),
            extra!(),
            round4!("21"),
            ghash0!($p),
            round4!("22"),
            ghash!("5", $p, "64"),
            round4!("23"),
            ghash!("6", $p, "128"),
            round4!("24"),
            ghash!("7", $p, "192"),
            round4!("25"),
            fold!(),
            round4!("26"),
            reduce1!(),
            round4!("27"),
            reduce2!(),
            round4!("28"),
            round4!("29"),
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

/// [`keep_ct`] of the tail: the bytes past its end (keystream) zeroed first.
macro_rules! keep_ctm {
    () => {
        concat!(
            "vmovdqu8 zmm0 {{k1}} {{z}}, zmm0\n",
            "vmovdqu8 zmm1 {{k2}} {{z}}, zmm1\n",
            "vmovdqu8 zmm2 {{k3}} {{z}}, zmm2\n",
            "vmovdqu8 zmm3 {{k4}} {{z}}, zmm3\n",
            keep_ct!(),
        )
    };
}

/// zmm4-7 = the group at `[b]`, byte-reflected (opening hashes its input).
macro_rules! load_ct {
    ($b:literal) => {
        concat!(
            "vmovdqu64 zmm4, zmmword ptr [",
            $b,
            "]\n",
            "vmovdqu64 zmm5, zmmword ptr [",
            $b,
            " + 64]\n",
            "vmovdqu64 zmm6, zmmword ptr [",
            $b,
            " + 128]\n",
            "vmovdqu64 zmm7, zmmword ptr [",
            $b,
            " + 192]\n",
            "vpshufb zmm4, zmm4, zmmword ptr [{c}]\n",
            "vpshufb zmm5, zmm5, zmmword ptr [{c}]\n",
            "vpshufb zmm6, zmm6, zmmword ptr [{c}]\n",
            "vpshufb zmm7, zmm7, zmmword ptr [{c}]\n",
        )
    };
}

/// [`load_ct`] under the byte masks k1-k4 (zero past the end).
macro_rules! load_ctm {
    ($b:literal) => {
        concat!(
            "vmovdqu8 zmm4 {{k1}} {{z}}, zmmword ptr [",
            $b,
            "]\n",
            "vmovdqu8 zmm5 {{k2}} {{z}}, zmmword ptr [",
            $b,
            " + 64]\n",
            "vmovdqu8 zmm6 {{k3}} {{z}}, zmmword ptr [",
            $b,
            " + 128]\n",
            "vmovdqu8 zmm7 {{k4}} {{z}}, zmmword ptr [",
            $b,
            " + 192]\n",
            "vpshufb zmm4, zmm4, zmmword ptr [{c}]\n",
            "vpshufb zmm5, zmm5, zmmword ptr [{c}]\n",
            "vpshufb zmm6, zmm6, zmmword ptr [{c}]\n",
            "vpshufb zmm7, zmm7, zmmword ptr [{c}]\n",
        )
    };
}

/// The byte masks at `[a + off]` into k1-k4.
macro_rules! kmasks {
    ($off:literal) => {
        concat!(
            "kmovq k1, qword ptr [{a} + ",
            $off,
            "]\n",
            "kmovq k2, qword ptr [{a} + ",
            $off,
            " + 8]\n",
            "kmovq k3, qword ptr [{a} + ",
            $off,
            " + 16]\n",
            "kmovq k4, qword ptr [{a} + ",
            $off,
            " + 24]\n",
        )
    };
}

/// Hashes the AAD (when its masks are not zero) into the state.
macro_rules! aad512 {
    () => {
        concat!(
            kmasks!("32"),
            "kortestq k1, k1\n",
            "jz 12f\n",
            "mov rax, qword ptr [{a} + 160]\n",
            load_ctm!("rax"),
            "mov rax, qword ptr [{a} + 168]\n",
            ghash_all!("rax"),
            "12:\n",
        )
    };
}

/// With `fin`: the length block hashed (times `H¹`, the last entry of the powers) and the tag
/// (the byte-swapped state XOR `E(J0)`) stored. Then the state.
macro_rules! final512 {
    () => {
        concat!(
            "cmp qword ptr [{a} + 176], 0\n",
            "je 14f\n",
            "vmovdqu xmm4, xmmword ptr [{a} + 64]\n",
            "vpxor xmm4, xmm4, xmm14\n",
            "vpclmulqdq xmm8, xmm4, xmmword ptr [{pw} + 240], 0x00\n",
            "vpclmulqdq xmm11, xmm4, xmmword ptr [{pw} + 240], 0x01\n",
            "vpclmulqdq xmm12, xmm4, xmmword ptr [{pw} + 240], 0x10\n",
            "vpclmulqdq xmm10, xmm4, xmmword ptr [{pw} + 240], 0x11\n",
            "vpxor xmm9, xmm11, xmm12\n",
            reduce1!(),
            reduce2!(),
            "vpshufb xmm11, xmm14, xmmword ptr [{c}]\n",
            "vpxor xmm11, xmm11, xmmword ptr [{a} + 128]\n",
            "vmovdqu xmmword ptr [{a} + 128], xmm11\n",
            "14:\n",
            "vmovdqu xmmword ptr [{a} + 112], xmm14\n",
        )
    };
}

/// The next four counter blocks, XORed with round key 0, into zmm0 (the short path).
macro_rules! ctr1 {
    () => {
        concat!(
            "vpshufb zmm0, zmm31, zmmword ptr [{c}]\n",
            z3!("vpxord", "0", "0", "16"),
        )
    };
}

/// All AES rounds but the last on zmm0.
macro_rules! rounds1 {
    () => {
        concat!(
            "cmp {r}, 12\n",
            "jb 5f\n",
            "je 4f\n",
            z3!("vaesenc", "0", "0", "17"),
            z3!("vaesenc", "0", "0", "18"),
            "4:\n",
            z3!("vaesenc", "0", "0", "19"),
            z3!("vaesenc", "0", "0", "20"),
            "5:\n",
            z3!("vaesenc", "0", "0", "21"),
            z3!("vaesenc", "0", "0", "22"),
            z3!("vaesenc", "0", "0", "23"),
            z3!("vaesenc", "0", "0", "24"),
            z3!("vaesenc", "0", "0", "25"),
            z3!("vaesenc", "0", "0", "26"),
            z3!("vaesenc", "0", "0", "27"),
            z3!("vaesenc", "0", "0", "28"),
            z3!("vaesenc", "0", "0", "29"),
        )
    };
}

/// [`last4m`] on zmm0 alone (mask k1).
macro_rules! last1m {
    () => {
        concat!(
            "vmovdqu8 zmm11 {{k1}} {{z}}, zmmword ptr [rsi]\n",
            "vpxord zmm11, zmm11, zmm30\n",
            "vaesenclast zmm0, zmm0, zmm11\n",
            "vmovdqu8 zmmword ptr [rdi] {{k1}}, zmm0\n",
        )
    };
}

/// The short path's end: the length block times `H¹` into the accumulators, one reduction,
/// the tag and the state stored.
macro_rules! short_end {
    () => {
        concat!(
            "18:\n",
            "vmovdqu xmm4, xmmword ptr [{a} + 64]\n",
            "vpclmulqdq xmm11, xmm4, xmmword ptr [{pw} + 240], 0x00\n",
            z3!("vpxord", "8", "8", "11"),
            "vpclmulqdq xmm12, xmm4, xmmword ptr [{pw} + 240], 0x01\n",
            "vpclmulqdq xmm13, xmm4, xmmword ptr [{pw} + 240], 0x10\n",
            "vpternlogd zmm9, zmm12, zmm13, 0x96\n",
            "vpclmulqdq xmm11, xmm4, xmmword ptr [{pw} + 240], 0x11\n",
            z3!("vpxord", "10", "10", "11"),
            fold!(),
            reduce1!(),
            reduce2!(),
            "vpshufb xmm11, xmm14, xmmword ptr [{c}]\n",
            "vpxor xmm11, xmm11, xmmword ptr [{a} + 128]\n",
            "vmovdqu xmmword ptr [{a} + 128], xmm11\n",
            "vmovdqu xmmword ptr [{a} + 112], xmm14\n",
        )
    };
}

/// Sealing a short message (`short` 1 or 4): the AAD times its powers starts the accumulators
/// (independent of the AES rounds, so the two overlap), the tail is encrypted and its
/// ciphertext times its powers added, then [`short_end`].
macro_rules! short_seal {
    () => {
        concat!(
            "15:\n",
            "mov rax, qword ptr [{a} + 168]\n",
            "mov rsi, qword ptr [{a} + 160]\n",
            "cmp qword ptr [{a} + 184], 1\n",
            "jne 17f\n",
            "kmovq k1, qword ptr [{a} + 32]\n",
            "vmovdqu8 zmm4 {{k1}} {{z}}, zmmword ptr [rsi]\n",
            "vpshufb zmm4, zmm4, zmmword ptr [{c}]\n",
            ctr1!(),
            ghash0!("rax"),
            rounds1!(),
            "kmovq k1, qword ptr [{a}]\n",
            "mov rsi, qword ptr [{a} + 152]\n",
            "mov rax, qword ptr [{a} + 144]\n",
            last1m!(),
            "vmovdqu8 zmm0 {{k1}} {{z}}, zmm0\n",
            "vpshufb zmm4, zmm0, zmmword ptr [{c}]\n",
            ghash!("4", "rax", "0"),
            "jmp 18f\n",
            "17:\n",
            kmasks!("32"),
            load_ctm!("rsi"),
            ctr4!(),
            ghash0!("rax"),
            ghash!("5", "rax", "64"),
            ghash!("6", "rax", "128"),
            ghash!("7", "rax", "192"),
            rounds!(),
            kmasks!("0"),
            "mov rsi, qword ptr [{a} + 152]\n",
            "mov rax, qword ptr [{a} + 144]\n",
            last4m!(),
            keep_ctm!(),
            ghash!("4", "rax", "0"),
            ghash!("5", "rax", "64"),
            ghash!("6", "rax", "128"),
            ghash!("7", "rax", "192"),
            short_end!(),
        )
    };
}

/// Opening a short message: the AAD and the ciphertext times their powers (both known up
/// front, so the GHASH overlaps the AES rounds), the tail decrypted, then [`short_end`].
macro_rules! short_open {
    () => {
        concat!(
            "15:\n",
            "mov rax, qword ptr [{a} + 168]\n",
            "mov rsi, qword ptr [{a} + 160]\n",
            "cmp qword ptr [{a} + 184], 1\n",
            "jne 17f\n",
            "kmovq k1, qword ptr [{a} + 32]\n",
            "vmovdqu8 zmm4 {{k1}} {{z}}, zmmword ptr [rsi]\n",
            "vpshufb zmm4, zmm4, zmmword ptr [{c}]\n",
            ghash0!("rax"),
            "kmovq k1, qword ptr [{a}]\n",
            "mov rsi, qword ptr [{a} + 152]\n",
            "mov rax, qword ptr [{a} + 144]\n",
            "vmovdqu8 zmm4 {{k1}} {{z}}, zmmword ptr [rsi]\n",
            "vpshufb zmm4, zmm4, zmmword ptr [{c}]\n",
            ghash!("4", "rax", "0"),
            ctr1!(),
            rounds1!(),
            last1m!(),
            "jmp 18f\n",
            "17:\n",
            kmasks!("32"),
            load_ctm!("rsi"),
            ghash0!("rax"),
            ghash!("5", "rax", "64"),
            ghash!("6", "rax", "128"),
            ghash!("7", "rax", "192"),
            kmasks!("0"),
            "mov rsi, qword ptr [{a} + 152]\n",
            "mov rax, qword ptr [{a} + 144]\n",
            load_ctm!("rsi"),
            ghash!("4", "rax", "0"),
            ghash!("5", "rax", "64"),
            ghash!("6", "rax", "128"),
            ghash!("7", "rax", "192"),
            ctr4!(),
            rounds!(),
            last4m!(),
            short_end!(),
        )
    };
}

/// Sealing: the first group is only encrypted, each later one is encrypted while the previous
/// ciphertext group is hashed; the tail is encrypted while the last whole group is hashed and
/// then hashed itself.
macro_rules! seal512 {
    () => {
        concat!(
            setup!(),
            ej0!(),
            "cmp qword ptr [{a} + 184], 0\n",
            "jne 15f\n",
            aad512!(),
            "test rcx, rcx\n",
            "jz 7f\n",
            ctr4!(),
            rounds!(),
            last4!(),
            keep_ct!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jz 3f\n",
            "2:\n",
            ctr4!(),
            rounds_ghash!("{pw}"),
            last4!(),
            keep_ct!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jnz 2b\n",
            "3:\n",
            kmasks!("0"),
            "kortestq k1, k1\n",
            "jz 8f\n",
            "mov rsi, qword ptr [{a} + 152]\n",
            ctr4!(),
            rounds_ghash!("{pw}"),
            last4m!(),
            keep_ctm!(),
            "jmp 9f\n",
            "8:\n",
            ghash_all!("{pw}"),
            "jmp 13f\n",
            "7:\n",
            kmasks!("0"),
            "kortestq k1, k1\n",
            "jz 13f\n",
            "mov rsi, qword ptr [{a} + 152]\n",
            ctr4!(),
            rounds!(),
            last4m!(),
            keep_ctm!(),
            "9:\n",
            "mov rax, qword ptr [{a} + 144]\n",
            ghash_all!("rax"),
            "13:\n",
            final512!(),
            "jmp 16f\n",
            short_seal!(),
            "16:\n",
            "vzeroupper\n",
        )
    };
}

/// Opening: each group, and the tail, is hashed while it is decrypted.
macro_rules! open512 {
    () => {
        concat!(
            setup!(),
            ej0!(),
            "cmp qword ptr [{a} + 184], 0\n",
            "jne 15f\n",
            aad512!(),
            "test rcx, rcx\n",
            "jz 7f\n",
            "2:\n",
            load_ct!("rsi"),
            ctr4!(),
            rounds_ghash!("{pw}"),
            last4!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jnz 2b\n",
            "7:\n",
            kmasks!("0"),
            "kortestq k1, k1\n",
            "jz 13f\n",
            "mov rsi, qword ptr [{a} + 152]\n",
            "mov rax, qword ptr [{a} + 144]\n",
            load_ctm!("rsi"),
            ctr4!(),
            rounds_ghash!("rax"),
            last4m!(),
            "13:\n",
            final512!(),
            "jmp 16f\n",
            short_open!(),
            "16:\n",
            "vzeroupper\n",
        )
    };
}

/// CTR-encrypts (`open == false`) or decrypts the `groups` 256-byte groups at `src` into `dst`
/// and then the tail of `a` (read from its `tail_src`, written after the groups), with the AES
/// round keys `rk`, starting at the counter block in `a` (32-bit big-endian counter in the
/// last four bytes, wrapping); the AAD of `a` and the ciphertext are absorbed into the GHASH
/// state in `a`, and with `fin` the length block too, and the tag is left in `a`. `src == dst`
/// works in place (each group, and the tail, is read before it is written), as does a
/// `tail_src` equal to `dst + 256 * groups`.
///
/// # Safety
///
/// The CPU must support AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ, AVX2 and AVX-512 F/BW/VL, and the
/// OS must save the YMM, ZMM and opmask state (`Feature::Vaes` and `Feature::Avx512` of
/// `cpu.rs`); `src` is valid for reading and `dst` for writing `256 * groups + t` bytes where
/// `t` is the tail length of `a` (only `256 * groups` of them are read from `src`), and the two
/// ranges are the same or do not overlap; `a`'s tail source is valid for reading `t` bytes and
/// its AAD for the bytes its masks select, and neither overlaps the output except a tail source
/// at exactly `dst + 256 * groups`; the AAD and tail powers of `a` point into `p` as
/// [`Args::aad`], [`Args::tail`] and [`Args::short`] set them (from `p`); `rk.1` is 10, 12 or
/// 14.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn crypt512(
    p: &WidePowers,
    rk: RoundKeys<'_>,
    a: &mut Args,
    src: *const u8,
    dst: *mut u8,
    groups: usize,
    open: bool,
) {
    debug_assert!(matches!(rk.1, 10 | 12 | 14));
    debug_assert!(a.tail_len() < CHUNK);
    if open {
        // SAFETY: the caller guarantees the CPU and OS features and the memory ranges. The
        // kernel reads the round keys `rk.0[0]` and `rk.0[r - 13 ..= r]` (only those with index
        // >= 1 for r = 12, 14; `r <= 14` so all lie in the 15-entry array), the powers at `pw`
        // (entry 15 for the length block; the AAD and tail powers at most 256 bytes from an
        // entry <= 15 of the 32-entry table, also on the short path), the 320 bytes of `CONSTS`, `a`, `256 * groups`
        // bytes at `src` and the masked bytes of the AAD and the tail source; it writes
        // `256 * groups` bytes at `dst`, then the masked tail bytes after them (each group and
        // the tail is loaded before it is stored), and `a.y` and `a.tag`, all unaligned. It
        // uses no stack and clobbers only registers declared here (every vector and mask
        // register through `clobber_abi("C")`, the flags), ending with `vzeroupper`.
        unsafe {
            core::arch::asm!(
                open512!(),
                rk = in(reg) rk.0.as_ptr(),
                r = in(reg) rk.1,
                pw = in(reg) p.0.as_ptr(),
                c = in(reg) &raw const CONSTS,
                a = in(reg) &raw mut *a,
                inout("rsi") src => _,
                inout("rdi") dst => _,
                inout("rcx") groups => _,
                out("rax") _,
                clobber_abi("C"),
                options(nostack),
            );
        }
    } else {
        // SAFETY: as above (the same reads and writes).
        unsafe {
            core::arch::asm!(
                seal512!(),
                rk = in(reg) rk.0.as_ptr(),
                r = in(reg) rk.1,
                pw = in(reg) p.0.as_ptr(),
                c = in(reg) &raw const CONSTS,
                a = in(reg) &raw mut *a,
                inout("rsi") src => _,
                inout("rdi") dst => _,
                inout("rcx") groups => _,
                out("rax") _,
                clobber_abi("C"),
                options(nostack),
            );
        }
    }
}

// ---- The AVX2 kernel ----
//
// Vector registers (ymm, VEX only: 0-15): 0-7 AES states (sixteen blocks), 8 the round key of
// the current round (broadcast from memory), 9-11 the LO/MI/HI accumulators, 12-13
// temporaries, 14 the GHASH state (low 128 bits), 15 the next counters (byte-reflected). The
// constants are memory operands. GPRs as in the AVX-512 kernel, with `ctr` and `y` pointers
// instead of `a`, and rax at the last round key throughout.

/// One AES round on ymm0-7 with the round key `off` bytes below the last one.
macro_rules! yround {
    ($off:literal) => {
        concat!(
            "vbroadcasti128 ymm8, xmmword ptr [rax - ",
            $off,
            "]\n",
            "vaesenc ymm0, ymm0, ymm8\n",
            "vaesenc ymm1, ymm1, ymm8\n",
            "vaesenc ymm2, ymm2, ymm8\n",
            "vaesenc ymm3, ymm3, ymm8\n",
            "vaesenc ymm4, ymm4, ymm8\n",
            "vaesenc ymm5, ymm5, ymm8\n",
            "vaesenc ymm6, ymm6, ymm8\n",
            "vaesenc ymm7, ymm7, ymm8\n",
        )
    };
}

/// The pointer to the last round key, the first counters and the GHASH state.
macro_rules! ysetup {
    () => {
        concat!(
            "mov rax, {r}\n",
            "shl rax, 4\n",
            "add rax, {rk}\n",
            "vbroadcasti128 ymm15, xmmword ptr [{ctr}]\n",
            "vpshufb ymm15, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 128]\n",
            "vmovdqu xmm14, xmmword ptr [{y}]\n",
        )
    };
}

/// The next sixteen counter blocks, XORed with round key 0, into ymm0-7.
macro_rules! yctr {
    () => {
        concat!(
            "vpshufb ymm0, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vpshufb ymm1, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vpshufb ymm2, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vpshufb ymm3, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vpshufb ymm4, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vpshufb ymm5, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vpshufb ymm6, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vpshufb ymm7, ymm15, ymmword ptr [{c}]\n",
            "vpaddd ymm15, ymm15, ymmword ptr [{c} + 256]\n",
            "vbroadcasti128 ymm8, xmmword ptr [{rk}]\n",
            "vpxor ymm0, ymm0, ymm8\n",
            "vpxor ymm1, ymm1, ymm8\n",
            "vpxor ymm2, ymm2, ymm8\n",
            "vpxor ymm3, ymm3, ymm8\n",
            "vpxor ymm4, ymm4, ymm8\n",
            "vpxor ymm5, ymm5, ymm8\n",
            "vpxor ymm6, ymm6, ymm8\n",
            "vpxor ymm7, ymm7, ymm8\n",
        )
    };
}

/// The rounds AES-192 (two) and AES-256 (four) have before the common last ten.
macro_rules! yextra {
    () => {
        concat!(
            "cmp {r}, 12\n",
            "jb 5f\n",
            "je 4f\n",
            yround!("208"),
            yround!("192"),
            "4:\n",
            yround!("176"),
            yround!("160"),
            "5:\n",
        )
    };
}

/// The last AES round with the data XORed into the round key, stored.
macro_rules! ylast {
    () => {
        concat!(
            "vbroadcasti128 ymm8, xmmword ptr [rax]\n",
            "vpxor ymm12, ymm8, ymmword ptr [rsi]\n",
            "vaesenclast ymm0, ymm0, ymm12\n",
            "vpxor ymm13, ymm8, ymmword ptr [rsi + 32]\n",
            "vaesenclast ymm1, ymm1, ymm13\n",
            "vpxor ymm12, ymm8, ymmword ptr [rsi + 64]\n",
            "vaesenclast ymm2, ymm2, ymm12\n",
            "vpxor ymm13, ymm8, ymmword ptr [rsi + 96]\n",
            "vaesenclast ymm3, ymm3, ymm13\n",
            "vpxor ymm12, ymm8, ymmword ptr [rsi + 128]\n",
            "vaesenclast ymm4, ymm4, ymm12\n",
            "vpxor ymm13, ymm8, ymmword ptr [rsi + 160]\n",
            "vaesenclast ymm5, ymm5, ymm13\n",
            "vpxor ymm12, ymm8, ymmword ptr [rsi + 192]\n",
            "vaesenclast ymm6, ymm6, ymm12\n",
            "vpxor ymm13, ymm8, ymmword ptr [rsi + 224]\n",
            "vaesenclast ymm7, ymm7, ymm13\n",
            "vmovdqu ymmword ptr [rdi], ymm0\n",
            "vmovdqu ymmword ptr [rdi + 32], ymm1\n",
            "vmovdqu ymmword ptr [rdi + 64], ymm2\n",
            "vmovdqu ymmword ptr [rdi + 96], ymm3\n",
            "vmovdqu ymmword ptr [rdi + 128], ymm4\n",
            "vmovdqu ymmword ptr [rdi + 160], ymm5\n",
            "vmovdqu ymmword ptr [rdi + 192], ymm6\n",
            "vmovdqu ymmword ptr [rdi + 224], ymm7\n",
        )
    };
}

/// The first two blocks at `[m]`, byte-reflected, with the state XORed in, times `H¹⁶, H¹⁵`:
/// starts the accumulators.
macro_rules! yghash0 {
    ($m:literal) => {
        concat!(
            "vmovdqu ymm12, ymmword ptr [",
            $m,
            "]\n",
            "vpshufb ymm12, ymm12, ymmword ptr [{c}]\n",
            "vpxor ymm12, ymm12, ymm14\n",
            "vpclmulqdq ymm9, ymm12, ymmword ptr [{pw}], 0x00\n",
            "vpclmulqdq ymm10, ymm12, ymmword ptr [{pw}], 0x01\n",
            "vpclmulqdq ymm13, ymm12, ymmword ptr [{pw}], 0x10\n",
            "vpxor ymm10, ymm10, ymm13\n",
            "vpclmulqdq ymm11, ymm12, ymmword ptr [{pw}], 0x11\n",
        )
    };
}

/// The two blocks at `[m]`, byte-reflected, times the powers at `[pw + off]`, into the
/// accumulators.
macro_rules! yghash {
    ($m:literal, $off:literal) => {
        concat!(
            "vmovdqu ymm12, ymmword ptr [",
            $m,
            "]\n",
            "vpshufb ymm12, ymm12, ymmword ptr [{c}]\n",
            "vpclmulqdq ymm13, ymm12, ymmword ptr [{pw} + ",
            $off,
            "], 0x00\n",
            "vpxor ymm9, ymm9, ymm13\n",
            "vpclmulqdq ymm13, ymm12, ymmword ptr [{pw} + ",
            $off,
            "], 0x01\n",
            "vpxor ymm10, ymm10, ymm13\n",
            "vpclmulqdq ymm13, ymm12, ymmword ptr [{pw} + ",
            $off,
            "], 0x10\n",
            "vpxor ymm10, ymm10, ymm13\n",
            "vpclmulqdq ymm13, ymm12, ymmword ptr [{pw} + ",
            $off,
            "], 0x11\n",
            "vpxor ymm11, ymm11, ymm13\n",
        )
    };
}

/// XORs the two lanes of each accumulator into the low one.
macro_rules! yfold {
    () => {
        concat!(
            "vextracti128 xmm12, ymm9, 1\n",
            "vpxor xmm9, xmm9, xmm12\n",
            "vextracti128 xmm12, ymm10, 1\n",
            "vpxor xmm10, xmm10, xmm12\n",
            "vextracti128 xmm12, ymm11, 1\n",
            "vpxor xmm11, xmm11, xmm12\n",
        )
    };
}

/// The two Montgomery steps of [`reduce1`] and [`reduce2`] without `vpternlogd`; the result is
/// the new state (xmm14, upper lane zero).
macro_rules! yreduce {
    () => {
        concat!(
            "vpclmulqdq xmm12, xmm9, xmmword ptr [{c} + 64], 0x10\n",
            "vpshufd xmm9, xmm9, 0x4e\n",
            "vpxor xmm10, xmm10, xmm9\n",
            "vpxor xmm10, xmm10, xmm12\n",
            "vpclmulqdq xmm12, xmm10, xmmword ptr [{c} + 64], 0x10\n",
            "vpshufd xmm10, xmm10, 0x4e\n",
            "vpxor xmm11, xmm11, xmm10\n",
            "vpxor xmm14, xmm11, xmm12\n",
        )
    };
}

/// One group's AES rounds but the last, interleaved with the GHASH of the eight ciphertext
/// vectors at `[m0]` … `[m7]`.
macro_rules! yrounds_ghash {
    ($m0:literal, $m1:literal, $m2:literal, $m3:literal, $m4:literal, $m5:literal, $m6:literal, $m7:literal) => {
        concat!(
            yextra!(),
            yround!("144"),
            yghash0!($m0),
            yround!("128"),
            yghash!($m1, "32"),
            yround!("112"),
            yghash!($m2, "64"),
            yround!("96"),
            yghash!($m3, "96"),
            yround!("80"),
            yghash!($m4, "128"),
            yround!("64"),
            yghash!($m5, "160"),
            yround!("48"),
            yghash!($m6, "192"),
            yround!("32"),
            yghash!($m7, "224"),
            yfold!(),
            yround!("16"),
            yreduce!(),
        )
    };
}

/// Sealing: the first group is only encrypted, each later one is encrypted while the previous
/// ciphertext group (the 256 bytes before `rdi`) is hashed, and the last one is hashed after
/// the loop.
macro_rules! seal256 {
    () => {
        concat!(
            ysetup!(),
            yctr!(),
            yextra!(),
            yround!("144"),
            yround!("128"),
            yround!("112"),
            yround!("96"),
            yround!("80"),
            yround!("64"),
            yround!("48"),
            yround!("32"),
            yround!("16"),
            ylast!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jz 3f\n",
            "2:\n",
            yctr!(),
            yrounds_ghash!(
                "rdi - 256",
                "rdi - 224",
                "rdi - 192",
                "rdi - 160",
                "rdi - 128",
                "rdi - 96",
                "rdi - 64",
                "rdi - 32"
            ),
            ylast!(),
            "add rdi, 256\n",
            "add rsi, 256\n",
            "dec rcx\n",
            "jnz 2b\n",
            "3:\n",
            yghash0!("rdi - 256"),
            yghash!("rdi - 224", "32"),
            yghash!("rdi - 192", "64"),
            yghash!("rdi - 160", "96"),
            yghash!("rdi - 128", "128"),
            yghash!("rdi - 96", "160"),
            yghash!("rdi - 64", "192"),
            yghash!("rdi - 32", "224"),
            yfold!(),
            yreduce!(),
            "vmovdqu xmmword ptr [{y}], xmm14\n",
            "vzeroupper\n",
        )
    };
}

/// Opening: each group is hashed while it is decrypted.
macro_rules! open256 {
    () => {
        concat!(
            ysetup!(),
            "2:\n",
            yctr!(),
            yrounds_ghash!(
                "rsi",
                "rsi + 32",
                "rsi + 64",
                "rsi + 96",
                "rsi + 128",
                "rsi + 160",
                "rsi + 192",
                "rsi + 224"
            ),
            ylast!(),
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
/// four bytes, wrapping), and absorbs the ciphertext into the GHASH state `y`, on 256-bit
/// vectors. `src == dst` works in place: each 256-byte group is read before it is written.
///
/// # Safety
///
/// The CPU must support AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ and AVX2, and the OS must save the
/// YMM state (`Feature::Vaes` of `cpu.rs`); `len` is a nonzero multiple of [`CHUNK2`]; `src` is
/// valid for reading and `dst` for writing `len` bytes, and the two ranges are the same or do
/// not overlap; `rk.1` is 10, 12 or 14.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn crypt256(
    p: &WidePowers,
    rk: RoundKeys<'_>,
    ctr: &[u8; 16],
    y: &mut [u64; 2],
    src: *const u8,
    dst: *mut u8,
    len: usize,
    open: bool,
) {
    let n = len / CHUNK2;
    debug_assert!(n > 0 && len % CHUNK2 == 0);
    debug_assert!(matches!(rk.1, 10 | 12 | 14));
    if open {
        // SAFETY: the caller guarantees the CPU and OS features and the `src` / `dst` ranges.
        // The kernel reads the round keys `rk.0[0]` and `rk.0[r - 13 ..= r]` (as in
        // `crypt512`), the 256 bytes of entries 0-15 of `p`, 288 bytes of `CONSTS`, 16 bytes of
        // `ctr` and of `y`, `n * 256` bytes at `src`, and writes `n * 256` bytes at `dst`
        // (`n >= 1`; each group is loaded, for the GHASH and the last round, before it is
        // stored) and 16 bytes of `y`, all unaligned. It uses no stack and clobbers only
        // registers declared here (all vector registers through `clobber_abi("C")`, the flags),
        // ending with `vzeroupper`.
        unsafe {
            core::arch::asm!(
                open256!(),
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
        // SAFETY: as above (the same reads and writes; sealing hashes the 256 bytes it just
        // wrote at `dst`).
        unsafe {
            core::arch::asm!(
                seal256!(),
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
