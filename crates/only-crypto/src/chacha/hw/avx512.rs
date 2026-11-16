//! ChaCha20 on AVX-512 (x86_64): sixteen blocks per iteration in zmm registers or eight in ymm
//! registers, word `j` of the blocks in register `j` as in the AVX2 code; four blocks with one
//! row of each block per register (`row_kernel`) for short messages and tails. The rotations are
//! single `vprold` instructions, and with 32 vector registers the state, the counters and the
//! transpose temporaries all stay in registers. After the rounds of the word-sliced kernels, a
//! 4×4 dword transpose inside each 128-bit lane, then a transpose of the lanes with
//! `vshufi32x4`, turns the registers back into blocks. A last partial group is read and written
//! under byte masks (`xor_masked`, AVX-512 BW `vmovdqu8`), with no buffer.
//!
//! The AVX-512 target features and intrinsics are not stable at the MSRV (1.85), so each kernel is
//! one `asm!` block with fixed registers (`clobber_abi("C")` declares the vector registers
//! clobbered), entered only after `cpu::cpu_has(Feature::Avx512)` (CPUID, with the OS saving the
//! ZMM state in XCR0). Additions, XORs and rotations only: constant time.

/// The register width of a kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Width {
    /// Sixteen blocks (1024 bytes) per iteration in zmm registers.
    Z,
    /// Eight blocks (512 bytes) per iteration in ymm registers.
    Y,
    /// Four blocks (256 bytes) per iteration, one row per zmm register.
    X,
}

impl Width {
    /// Bytes per iteration.
    pub(super) const fn bytes(self) -> usize {
        match self {
            Width::Z => 1024,
            Width::Y => 512,
            Width::X => 256,
        }
    }

    /// The width for one last group of `rest` bytes (under 1024): the narrowest that covers it
    /// (on Zen 4, ChaCha20 alone: about 63 ns for a row group, 83 for a ymm group, 140 for a
    /// zmm group, so one wider group beats two narrower ones).
    pub(super) const fn last(rest: usize) -> Width {
        match rest {
            513.. => Width::Z,
            257.. => Width::Y,
            _ => Width::X,
        }
    }
}

/// Counter offsets and steps at fixed offsets: `lanes` (0, lane `i` holds `i`), `inc16` (64, the
/// step of the zmm kernel), `inc8` (72, the ymm kernel), `row` (128, dword `4i` holds `i`: the
/// counters of the row kernel's four blocks) and `row_inc` (192, 4 in every dword `4i`: its step).
#[repr(C, align(64))]
struct Consts {
    lanes: [u32; 16],
    inc16: u32,
    _unused: u32,
    inc8: u32,
    _pad: [u32; 13],
    row: [u32; 16],
    row_inc: [u32; 16],
}

const fn consts() -> Consts {
    let mut c = Consts {
        lanes: [0; 16],
        inc16: 16,
        _unused: 0,
        inc8: 8,
        _pad: [0; 13],
        row: [0; 16],
        row_inc: [0; 16],
    };
    let mut i = 0;
    while i < 16 {
        c.lanes[i] = i as u32;
        i += 1;
    }
    let mut i = 0;
    while i < 4 {
        c.row[4 * i] = i as u32;
        c.row_inc[4 * i] = 4;
        i += 1;
    }
    c
}

static CONSTS: Consts = consts();

/// `op w$a, w$b, w$c` on three registers of width prefix `w` (`"zmm"`, `"xmm"`).
macro_rules! op3 {
    ($op:literal, $w:literal, $a:literal, $b:literal, $c:literal) => {
        concat!($op, " ", $w, $a, ", ", $w, $b, ", ", $w, $c, "\n")
    };
}

/// Rotates register `a` left by `n` bits.
macro_rules! rol {
    ($w:literal, $a:literal, $n:literal) => {
        concat!("vprold ", $w, $a, ", ", $w, $a, ", ", $n, "\n")
    };
}

/// Four quarter rounds side by side, step by step.
macro_rules! qr4 {
    ($w:literal, $($a:literal $b:literal $c:literal $d:literal)|*) => {
        concat!(
            $(op3!("vpaddd", $w, $a, $a, $b),)*
            $(op3!("vpxord", $w, $d, $d, $a),)*
            $(rol!($w, $d, "16"),)*
            $(op3!("vpaddd", $w, $c, $c, $d),)*
            $(op3!("vpxord", $w, $b, $b, $c),)*
            $(rol!($w, $b, "12"),)*
            $(op3!("vpaddd", $w, $a, $a, $b),)*
            $(op3!("vpxord", $w, $d, $d, $a),)*
            $(rol!($w, $d, "8"),)*
            $(op3!("vpaddd", $w, $c, $c, $d),)*
            $(op3!("vpxord", $w, $b, $b, $c),)*
            $(rol!($w, $b, "7"),)*
        )
    };
}

/// A column round and a diagonal round on registers 0-15.
macro_rules! double_round {
    ($w:literal) => {
        concat!(
            qr4!($w, "0" "4" "8" "12" | "1" "5" "9" "13" | "2" "6" "10" "14" | "3" "7" "11" "15"),
            qr4!($w, "0" "5" "10" "15" | "1" "6" "11" "12" | "2" "7" "8" "13" | "3" "4" "9" "14"),
        )
    };
}

/// Broadcasts state word `j` (at byte offset `o` of `{s}`) to register `j`.
macro_rules! load {
    ($w:literal, $j:literal, $o:literal) => {
        concat!("vpbroadcastd ", $w, $j, ", dword ptr [{s} + ", $o, "]\n")
    };
}

/// Adds state word `j` (at byte offset `o` of `{s}`, broadcast `bc`) to register `j`.
macro_rules! feed {
    ($w:literal, $bc:literal, $j:literal, $o:literal) => {
        concat!(
            "vpaddd ",
            $w,
            $j,
            ", ",
            $w,
            $j,
            ", dword ptr [{s} + ",
            $o,
            "]{{",
            $bc,
            "}}\n"
        )
    };
}

/// Loads the state words (`{s}`) into registers 0-15, the counters from register 16; then the
/// ten double rounds (eax counts) and the feed-forward addition.
macro_rules! rounds {
    ($w:literal, $bc:literal) => {
        concat!(
            load!($w, "0", "0"),
            load!($w, "1", "4"),
            load!($w, "2", "8"),
            load!($w, "3", "12"),
            load!($w, "4", "16"),
            load!($w, "5", "20"),
            load!($w, "6", "24"),
            load!($w, "7", "28"),
            load!($w, "8", "32"),
            load!($w, "9", "36"),
            load!($w, "10", "40"),
            load!($w, "11", "44"),
            "vmovdqa64 ",
            $w,
            "12, ",
            $w,
            "16\n",
            load!($w, "13", "52"),
            load!($w, "14", "56"),
            load!($w, "15", "60"),
            "mov eax, 10\n",
            "3:\n",
            double_round!($w),
            "dec eax\n",
            "jnz 3b\n",
            feed!($w, $bc, "0", "0"),
            feed!($w, $bc, "1", "4"),
            feed!($w, $bc, "2", "8"),
            feed!($w, $bc, "3", "12"),
            feed!($w, $bc, "4", "16"),
            feed!($w, $bc, "5", "20"),
            feed!($w, $bc, "6", "24"),
            feed!($w, $bc, "7", "28"),
            feed!($w, $bc, "8", "32"),
            feed!($w, $bc, "9", "36"),
            feed!($w, $bc, "10", "40"),
            feed!($w, $bc, "11", "44"),
            op3!("vpaddd", $w, "12", "12", "16"),
            feed!($w, $bc, "13", "52"),
            feed!($w, $bc, "14", "56"),
            feed!($w, $bc, "15", "60"),
        )
    };
}
/// 4×4 dword transpose inside each 128-bit lane of registers `p q r t` (temporaries 18-21):
/// afterwards register `i` of the four holds dword `i` of each.
macro_rules! tr4 {
    ($w:literal, $p:literal, $q:literal, $r:literal, $t:literal) => {
        concat!(
            op3!("vpunpckldq", $w, "18", $p, $q),
            op3!("vpunpckhdq", $w, "19", $p, $q),
            op3!("vpunpckldq", $w, "20", $r, $t),
            op3!("vpunpckhdq", $w, "21", $r, $t),
            op3!("vpunpcklqdq", $w, $p, "18", "20"),
            op3!("vpunpckhqdq", $w, $q, "18", "20"),
            op3!("vpunpcklqdq", $w, $r, "19", "21"),
            op3!("vpunpckhqdq", $w, $t, "19", "21"),
        )
    };
}

/// XORs register `r` with the input at `off` and stores it to the output at `off` (`$m`, the
/// offset of its mask for [`xor_masked`], is unused).
macro_rules! xs {
    ($w:literal, $size:literal, $r:literal, $off:literal, $m:literal) => {
        concat!(
            "vpxord ",
            $w,
            $r,
            ", ",
            $w,
            $r,
            ", ",
            $size,
            " ptr [rsi + ",
            $off,
            "]\n",
            "vmovdqu64 ",
            $size,
            " ptr [rdi + ",
            $off,
            "], ",
            $w,
            $r,
            "\n",
        )
    };
}

/// [`xs`] under a byte mask: the bytes of the mask at offset `m` of `{m}` (`off / 8`: 64 bits
/// for a zmm store, 32 for a ymm one) select the bytes read and written; the others are neither
/// read (no fault) nor written. A full mask takes the plain [`xs`] and an empty one skips the
/// store (branches on the public length): on Zen 4 a masked load or store that crosses a cache
/// line costs tens of cycles, so only the one partial block of a message pays for it.
macro_rules! xm {
    ("zmm", $size:literal, $r:literal, $off:literal, $m:literal) => {
        xm!(@ "zmm", "kmovq k1, qword", "kortestq", $size, $r, $off, $m)
    };
    ("ymm", $size:literal, $r:literal, $off:literal, $m:literal) => {
        xm!(@ "ymm", "kmovd k1, dword", "kortestd", $size, $r, $off, $m)
    };
    (@ $w:literal, $k:literal, $kt:literal, $size:literal, $r:literal, $off:literal, $m:literal) => {
        concat!(
            $k, " ptr [{m} + ", $m, "]\n",
            $kt, " k1, k1\n",
            "jz 5f\n",
            "jc 4f\n",
            "vmovdqu8 ", $w, "30{{k1}}{{z}}, ", $size, " ptr [rsi + ", $off, "]\n",
            "vpxord ", $w, $r, ", ", $w, $r, ", ", $w, "30\n",
            "vmovdqu8 ", $size, " ptr [rdi + ", $off, "]{{k1}}, ", $w, $r, "\n",
            "jmp 5f\n",
            "4:\n",
            xs!($w, $size, $r, $off, $m),
            "5:\n",
        )
    };
}

/// After `tr4` on every group of four registers, lane `L` of register `4g + i` holds words
/// `4g..4g+4` of block `4L + i`: transposes the lanes of registers `i, 4+i, 8+i, 12+i` (into
/// 22-29) and writes blocks `i, 4+i, 8+i, 12+i` (output offsets `o0..o3`).
macro_rules! lanes4 {
    ($st:ident, $a:literal, $b:literal, $c:literal, $d:literal, $o0:literal, $o1:literal, $o2:literal, $o3:literal,
     $m0:literal, $m1:literal, $m2:literal, $m3:literal) => {
        concat!(
            "vshufi32x4 zmm22, zmm",
            $a,
            ", zmm",
            $b,
            ", 0x44\n",
            "vshufi32x4 zmm23, zmm",
            $a,
            ", zmm",
            $b,
            ", 0xee\n",
            "vshufi32x4 zmm24, zmm",
            $c,
            ", zmm",
            $d,
            ", 0x44\n",
            "vshufi32x4 zmm25, zmm",
            $c,
            ", zmm",
            $d,
            ", 0xee\n",
            "vshufi32x4 zmm26, zmm22, zmm24, 0x88\n",
            "vshufi32x4 zmm27, zmm22, zmm24, 0xdd\n",
            "vshufi32x4 zmm28, zmm23, zmm25, 0x88\n",
            "vshufi32x4 zmm29, zmm23, zmm25, 0xdd\n",
            $st!("zmm", "zmmword", "26", $o0, $m0),
            $st!("zmm", "zmmword", "27", $o1, $m1),
            $st!("zmm", "zmmword", "28", $o2, $m2),
            $st!("zmm", "zmmword", "29", $o3, $m3),
        )
    };
}

/// The zmm kernel: `rcx` groups of sixteen blocks from `rsi` to `rdi`, stored with `st`.
macro_rules! wide_kernel {
    ($st:ident) => {
        concat!(
            "vpbroadcastd zmm16, dword ptr [{s} + 48]\n",
            "vpaddd zmm16, zmm16, zmmword ptr [{c}]\n",
            "vpbroadcastd zmm17, dword ptr [{c} + 64]\n",
            "2:\n",
            rounds!("zmm", "1to16"),
            tr4!("zmm", "0", "1", "2", "3"),
            tr4!("zmm", "4", "5", "6", "7"),
            tr4!("zmm", "8", "9", "10", "11"),
            tr4!("zmm", "12", "13", "14", "15"),
            lanes4!(
                $st, "0", "4", "8", "12", "0", "256", "512", "768", "0", "32", "64", "96"
            ),
            lanes4!(
                $st, "1", "5", "9", "13", "64", "320", "576", "832", "8", "40", "72", "104"
            ),
            lanes4!(
                $st, "2", "6", "10", "14", "128", "384", "640", "896", "16", "48", "80", "112"
            ),
            lanes4!(
                $st, "3", "7", "11", "15", "192", "448", "704", "960", "24", "56", "88", "120"
            ),
            op3!("vpaddd", "zmm", "16", "16", "17"),
            "add rsi, 1024\n",
            "add rdi, 1024\n",
            "dec rcx\n",
            "jnz 2b\n",
            "vzeroupper\n",
        )
    };
}

/// After `tr4`, lane `L` of register `4g + i` holds words `4g..4g+4` of block `4L + i`: writes
/// blocks `i` (offset `o0`) and `4 + i` (`o1`) from registers `a b c d` = `i, 4+i, 8+i, 12+i`.
macro_rules! lanes2 {
    ($st:ident, $a:literal, $b:literal, $c:literal, $d:literal, $o0:literal, $o0h:literal, $o1:literal, $o1h:literal,
     $m0:literal, $m0h:literal, $m1:literal, $m1h:literal) => {
        concat!(
            "vshufi32x4 ymm22, ymm",
            $a,
            ", ymm",
            $b,
            ", 0x0\n",
            "vshufi32x4 ymm23, ymm",
            $c,
            ", ymm",
            $d,
            ", 0x0\n",
            "vshufi32x4 ymm24, ymm",
            $a,
            ", ymm",
            $b,
            ", 0x3\n",
            "vshufi32x4 ymm25, ymm",
            $c,
            ", ymm",
            $d,
            ", 0x3\n",
            $st!("ymm", "ymmword", "22", $o0, $m0),
            $st!("ymm", "ymmword", "23", $o0h, $m0h),
            $st!("ymm", "ymmword", "24", $o1, $m1),
            $st!("ymm", "ymmword", "25", $o1h, $m1h),
        )
    };
}

/// The ymm kernel: `rcx` groups of eight blocks from `rsi` to `rdi`, stored with `st`.
macro_rules! mid_kernel {
    ($st:ident) => {
        concat!(
            "vpbroadcastd ymm16, dword ptr [{s} + 48]\n",
            "vpaddd ymm16, ymm16, ymmword ptr [{c}]\n",
            "vpbroadcastd ymm17, dword ptr [{c} + 72]\n",
            "2:\n",
            rounds!("ymm", "1to8"),
            tr4!("ymm", "0", "1", "2", "3"),
            tr4!("ymm", "4", "5", "6", "7"),
            tr4!("ymm", "8", "9", "10", "11"),
            tr4!("ymm", "12", "13", "14", "15"),
            lanes2!(
                $st, "0", "4", "8", "12", "0", "32", "256", "288", "0", "4", "32", "36"
            ),
            lanes2!(
                $st, "1", "5", "9", "13", "64", "96", "320", "352", "8", "12", "40", "44"
            ),
            lanes2!(
                $st, "2", "6", "10", "14", "128", "160", "384", "416", "16", "20", "48", "52"
            ),
            lanes2!(
                $st, "3", "7", "11", "15", "192", "224", "448", "480", "24", "28", "56", "60"
            ),
            op3!("vpaddd", "ymm", "16", "16", "17"),
            "add rsi, 512\n",
            "add rdi, 512\n",
            "dec rcx\n",
            "jnz 2b\n",
            "vzeroupper\n",
        )
    };
}

/// Rotates the words of rows `b c d` within each block by `ib`, `ic` and `id` (`vpshufd`
/// immediates) in each set of row registers, the `b` rows first: they are what the next step
/// waits for.
macro_rules! row_shuffle {
    ($ib:literal, $ic:literal, $id:literal, $($b:literal $c:literal $d:literal)|*) => {
        concat!(
            $("vpshufd zmm", $b, ", zmm", $b, ", ", $ib, "\n",)*
            $("vpshufd zmm", $c, ", zmm", $c, ", ", $ic, "\n",)*
            $("vpshufd zmm", $d, ", zmm", $d, ", ", $id, "\n",)*
        )
    };
}

/// The row kernel: `rcx` groups of four blocks from `rsi` to `rdi`, stored with `st`. Each zmm
/// register holds one row (four words) of each of four blocks, so a double round is two quarter
/// rounds with the diagonal turned into a column by word rotations in between (OpenSSL's
/// layout): a quarter of the instructions of four blocks word by word in xmm registers, and the
/// dependency chain of a round is about as long. For short messages, which wait for it.
macro_rules! row_kernel {
    ($st:ident) => {
        concat!(
            "vbroadcasti32x4 zmm4, xmmword ptr [{s}]\n",
            "vbroadcasti32x4 zmm5, xmmword ptr [{s} + 16]\n",
            "vbroadcasti32x4 zmm6, xmmword ptr [{s} + 32]\n",
            "vbroadcasti32x4 zmm7, xmmword ptr [{s} + 48]\n",
            "vpaddd zmm7, zmm7, zmmword ptr [{c} + 128]\n",
            "vmovdqa64 zmm8, zmmword ptr [{c} + 192]\n",
            "2:\n",
            "vmovdqa64 zmm0, zmm4\n",
            "vmovdqa64 zmm1, zmm5\n",
            "vmovdqa64 zmm2, zmm6\n",
            "vmovdqa64 zmm3, zmm7\n",
            "mov eax, 10\n",
            "3:\n",
            qr4!("zmm", "0" "1" "2" "3"),
            row_shuffle!("0x39", "0x4e", "0x93", "1" "2" "3"),
            qr4!("zmm", "0" "1" "2" "3"),
            row_shuffle!("0x93", "0x4e", "0x39", "1" "2" "3"),
            "dec eax\n",
            "jnz 3b\n",
            op3!("vpaddd", "zmm", "0", "0", "4"),
            op3!("vpaddd", "zmm", "1", "1", "5"),
            op3!("vpaddd", "zmm", "2", "2", "6"),
            op3!("vpaddd", "zmm", "3", "3", "7"),
            // Lane `L` of registers 0-3 holds the rows of block `L`.
            lanes4!($st, "0", "1", "2", "3", "0", "64", "128", "192", "0", "8", "16", "24"),
            op3!("vpaddd", "zmm", "7", "7", "8"),
            "add rsi, 256\n",
            "add rdi, 256\n",
            "dec rcx\n",
            "jnz 2b\n",
            "vzeroupper\n",
        )
    };
}

/// XORs the keystream of `n` groups of `w.bytes() / 64` blocks, starting at block `state[12]`,
/// into the bytes at `src` and writes them to `dst` (`src == dst` works in place). Counters past
/// `2³² - 1` wrap within the 32-bit word (the row kernel carries no further either: its four
/// blocks have their own counter words).
///
/// # Safety
///
/// The CPU must support AVX-512 F and VL with the OS saving the ZMM state; `n >= 1`; `src` must
/// be readable and `dst` writable for `n * w.bytes()` bytes, and the two ranges must either be the
/// same or not overlap.
pub(super) unsafe fn xor(state: &[u32; 16], src: *const u8, dst: *mut u8, n: usize, w: Width) {
    debug_assert!(n >= 1);
    macro_rules! kernel {
        ($k:ident) => {
            // SAFETY: the caller guarantees the CPU and OS features and the `src` / `dst`
            // ranges. The kernel reads the 64-byte state, the constants and `n * w.bytes()`
            // bytes from `src`, writes `n * w.bytes()` bytes to `dst` (each 64-byte block is
            // loaded before it is stored, so `src == dst` works), uses no stack and clobbers
            // only the registers declared here (all vector registers through
            // `clobber_abi("C")`, the flags), ending with `vzeroupper`.
            unsafe {
                core::arch::asm!(
                    $k!(xs),
                    s = in(reg) state.as_ptr(),
                    c = in(reg) &raw const CONSTS,
                    inout("rsi") src => _,
                    inout("rdi") dst => _,
                    inout("rcx") n => _,
                    out("rax") _,
                    clobber_abi("C"),
                    options(nostack),
                )
            }
        };
    }
    match w {
        Width::Z => kernel!(wide_kernel),
        Width::Y => kernel!(mid_kernel),
        Width::X => kernel!(row_kernel),
    }
}

/// [`xor`] of one group of width `w` of which only the first `len` bytes (`0 < len <=
/// w.bytes()`) exist: each 64-byte block is read and written under a byte mask, so nothing
/// outside `src[..len]` is read and nothing outside `dst[..len]` written (no buffer).
///
/// # Safety
///
/// As for [`xor`] with `n = 1`, for `len` bytes instead of `w.bytes()`.
pub(super) unsafe fn xor_masked(
    state: &[u32; 16],
    src: *const u8,
    dst: *mut u8,
    len: usize,
    w: Width,
) {
    debug_assert!(len > 0 && len <= w.bytes());
    // The byte mask of each block (bit `i` for byte `i`); the ymm stores read 32-bit halves.
    let mut masks = [0u64; 16];
    for (i, m) in masks.iter_mut().enumerate() {
        let have = len.saturating_sub(64 * i);
        *m = if have >= 64 { !0 } else { (1u64 << have) - 1 };
    }
    macro_rules! kernel {
        ($k:ident) => {
            // SAFETY: as in `xor` with one group, except that each block of `src` / `dst` is
            // read and written whole only when its mask from `masks` is all ones (the block is
            // below `len`), skipped when it is zero (above `len`), and otherwise through a
            // `vmovdqu8` under the mask, which neither reads nor writes (nor faults on) the
            // masked-off bytes: the kernel touches only `src[..len]` and `dst[..len]`. It also reads `masks` (128 bytes on the stack of the caller) and
            // clobbers `k1` (through `clobber_abi("C")`).
            unsafe {
                core::arch::asm!(
                    $k!(xm),
                    s = in(reg) state.as_ptr(),
                    c = in(reg) &raw const CONSTS,
                    m = in(reg) masks.as_ptr(),
                    inout("rsi") src => _,
                    inout("rdi") dst => _,
                    inout("rcx") 1usize => _,
                    out("rax") _,
                    clobber_abi("C"),
                    options(nostack),
                )
            }
        };
    }
    match w {
        Width::Z => kernel!(wide_kernel),
        Width::Y => kernel!(mid_kernel),
        Width::X => kernel!(row_kernel),
    }
}
