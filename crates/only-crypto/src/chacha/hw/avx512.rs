//! ChaCha20 on AVX-512 (x86_64): sixteen blocks per iteration in zmm registers, or four in xmm
//! registers (for the tail of a message and for short ones), word `j` of the blocks in register
//! `j` as in the AVX2 code. The rotations are single `vprold` instructions, and with 32 vector
//! registers the state, the counters and the transpose temporaries all stay in registers.
//! After the rounds, a 4×4 dword transpose inside each 128-bit lane (and, for sixteen blocks, a
//! 4×4 transpose of the lanes with `vshufi32x4`) turns the registers back into blocks.
//!
//! The AVX-512 target features and intrinsics are not stable at the MSRV (1.85), so each kernel is
//! one `asm!` block with fixed registers (`clobber_abi("C")` declares the vector registers
//! clobbered), entered only after `cpu::cpu_has(Feature::Avx512)` (CPUID, with the OS saving the
//! ZMM state in XCR0). Additions, XORs and rotations only: constant time.

/// Bytes per iteration of the zmm kernel (sixteen blocks).
pub(super) const WIDE: usize = 1024;
/// Bytes per iteration of the xmm kernel (four blocks).
pub(super) const NARROW: usize = 256;

/// Counter offsets and steps at fixed offsets: `lanes` (0, lane `i` holds `i`), `inc16` (64, the
/// step of the zmm kernel) and `inc4` (68, the step of the xmm kernel).
#[repr(C, align(64))]
struct Consts {
    lanes: [u32; 16],
    inc16: u32,
    inc4: u32,
}

const fn consts() -> Consts {
    let mut c = Consts {
        lanes: [0; 16],
        inc16: 16,
        inc4: 4,
    };
    let mut i = 0;
    while i < 16 {
        c.lanes[i] = i as u32;
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

/// Loads the state words (`{s}`) into registers 0-15, the counters from register 16; then the
/// ten double rounds (eax counts) and the feed-forward addition.
macro_rules! rounds {
    ($w:literal, $bc:literal) => {
        concat!(
            "vpbroadcastd ", $w, "0, dword ptr [{s}]\n",
            "vpbroadcastd ", $w, "1, dword ptr [{s} + 4]\n",
            "vpbroadcastd ", $w, "2, dword ptr [{s} + 8]\n",
            "vpbroadcastd ", $w, "3, dword ptr [{s} + 12]\n",
            "vpbroadcastd ", $w, "4, dword ptr [{s} + 16]\n",
            "vpbroadcastd ", $w, "5, dword ptr [{s} + 20]\n",
            "vpbroadcastd ", $w, "6, dword ptr [{s} + 24]\n",
            "vpbroadcastd ", $w, "7, dword ptr [{s} + 28]\n",
            "vpbroadcastd ", $w, "8, dword ptr [{s} + 32]\n",
            "vpbroadcastd ", $w, "9, dword ptr [{s} + 36]\n",
            "vpbroadcastd ", $w, "10, dword ptr [{s} + 40]\n",
            "vpbroadcastd ", $w, "11, dword ptr [{s} + 44]\n",
            "vmovdqa64 ", $w, "12, ", $w, "16\n",
            "vpbroadcastd ", $w, "13, dword ptr [{s} + 52]\n",
            "vpbroadcastd ", $w, "14, dword ptr [{s} + 56]\n",
            "vpbroadcastd ", $w, "15, dword ptr [{s} + 60]\n",
            "mov eax, 10\n",
            "3:\n",
            double_round!($w),
            "dec eax\n",
            "jnz 3b\n",
            "vpaddd ", $w, "0, ", $w, "0, dword ptr [{s}]{{", $bc, "}}\n",
            "vpaddd ", $w, "1, ", $w, "1, dword ptr [{s} + 4]{{", $bc, "}}\n",
            "vpaddd ", $w, "2, ", $w, "2, dword ptr [{s} + 8]{{", $bc, "}}\n",
            "vpaddd ", $w, "3, ", $w, "3, dword ptr [{s} + 12]{{", $bc, "}}\n",
            "vpaddd ", $w, "4, ", $w, "4, dword ptr [{s} + 16]{{", $bc, "}}\n",
            "vpaddd ", $w, "5, ", $w, "5, dword ptr [{s} + 20]{{", $bc, "}}\n",
            "vpaddd ", $w, "6, ", $w, "6, dword ptr [{s} + 24]{{", $bc, "}}\n",
            "vpaddd ", $w, "7, ", $w, "7, dword ptr [{s} + 28]{{", $bc, "}}\n",
            "vpaddd ", $w, "8, ", $w, "8, dword ptr [{s} + 32]{{", $bc, "}}\n",
            "vpaddd ", $w, "9, ", $w, "9, dword ptr [{s} + 36]{{", $bc, "}}\n",
            "vpaddd ", $w, "10, ", $w, "10, dword ptr [{s} + 40]{{", $bc, "}}\n",
            "vpaddd ", $w, "11, ", $w, "11, dword ptr [{s} + 44]{{", $bc, "}}\n",
            op3!("vpaddd", $w, "12", "12", "16"),
            "vpaddd ", $w, "13, ", $w, "13, dword ptr [{s} + 52]{{", $bc, "}}\n",
            "vpaddd ", $w, "14, ", $w, "14, dword ptr [{s} + 56]{{", $bc, "}}\n",
            "vpaddd ", $w, "15, ", $w, "15, dword ptr [{s} + 60]{{", $bc, "}}\n",
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

/// XORs register `r` with the input at `off` and stores it to the output at `off`.
macro_rules! xor_store {
    ($w:literal, $size:literal, $r:literal, $off:literal) => {
        concat!(
            "vpxord ", $w, $r, ", ", $w, $r, ", ", $size, " ptr [rsi + ", $off, "]\n",
            "vmovdqu64 ", $size, " ptr [rdi + ", $off, "], ", $w, $r, "\n",
        )
    };
}

/// After `tr4` on every group of four registers, lane `L` of register `4g + i` holds words
/// `4g..4g+4` of block `4L + i`: transposes the lanes of registers `i, 4+i, 8+i, 12+i` (into
/// 22-29) and writes blocks `i, 4+i, 8+i, 12+i` (output offsets `o0..o3`).
macro_rules! lanes4 {
    ($a:literal, $b:literal, $c:literal, $d:literal, $o0:literal, $o1:literal, $o2:literal, $o3:literal) => {
        concat!(
            "vshufi32x4 zmm22, zmm", $a, ", zmm", $b, ", 0x44\n",
            "vshufi32x4 zmm23, zmm", $a, ", zmm", $b, ", 0xee\n",
            "vshufi32x4 zmm24, zmm", $c, ", zmm", $d, ", 0x44\n",
            "vshufi32x4 zmm25, zmm", $c, ", zmm", $d, ", 0xee\n",
            "vshufi32x4 zmm26, zmm22, zmm24, 0x88\n",
            "vshufi32x4 zmm27, zmm22, zmm24, 0xdd\n",
            "vshufi32x4 zmm28, zmm23, zmm25, 0x88\n",
            "vshufi32x4 zmm29, zmm23, zmm25, 0xdd\n",
            xor_store!("zmm", "zmmword", "26", $o0),
            xor_store!("zmm", "zmmword", "27", $o1),
            xor_store!("zmm", "zmmword", "28", $o2),
            xor_store!("zmm", "zmmword", "29", $o3),
        )
    };
}

/// The zmm kernel: `rcx` groups of sixteen blocks from `rsi` to `rdi`.
macro_rules! wide_kernel {
    () => {
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
            lanes4!("0", "4", "8", "12", "0", "256", "512", "768"),
            lanes4!("1", "5", "9", "13", "64", "320", "576", "832"),
            lanes4!("2", "6", "10", "14", "128", "384", "640", "896"),
            lanes4!("3", "7", "11", "15", "192", "448", "704", "960"),
            op3!("vpaddd", "zmm", "16", "16", "17"),
            "add rsi, 1024\n",
            "add rdi, 1024\n",
            "dec rcx\n",
            "jnz 2b\n",
            "vzeroupper\n",
        )
    };
}

/// The xmm kernel: `rcx` groups of four blocks from `rsi` to `rdi`.
macro_rules! narrow_kernel {
    () => {
        concat!(
            "vpbroadcastd xmm16, dword ptr [{s} + 48]\n",
            "vpaddd xmm16, xmm16, xmmword ptr [{c}]\n",
            "vpbroadcastd xmm17, dword ptr [{c} + 68]\n",
            "2:\n",
            rounds!("xmm", "1to4"),
            tr4!("xmm", "0", "1", "2", "3"),
            tr4!("xmm", "4", "5", "6", "7"),
            tr4!("xmm", "8", "9", "10", "11"),
            tr4!("xmm", "12", "13", "14", "15"),
            xor_store!("xmm", "xmmword", "0", "0"),
            xor_store!("xmm", "xmmword", "4", "16"),
            xor_store!("xmm", "xmmword", "8", "32"),
            xor_store!("xmm", "xmmword", "12", "48"),
            xor_store!("xmm", "xmmword", "1", "64"),
            xor_store!("xmm", "xmmword", "5", "80"),
            xor_store!("xmm", "xmmword", "9", "96"),
            xor_store!("xmm", "xmmword", "13", "112"),
            xor_store!("xmm", "xmmword", "2", "128"),
            xor_store!("xmm", "xmmword", "6", "144"),
            xor_store!("xmm", "xmmword", "10", "160"),
            xor_store!("xmm", "xmmword", "14", "176"),
            xor_store!("xmm", "xmmword", "3", "192"),
            xor_store!("xmm", "xmmword", "7", "208"),
            xor_store!("xmm", "xmmword", "11", "224"),
            xor_store!("xmm", "xmmword", "15", "240"),
            op3!("vpaddd", "xmm", "16", "16", "17"),
            "add rsi, 256\n",
            "add rdi, 256\n",
            "dec rcx\n",
            "jnz 2b\n",
            "vzeroupper\n",
        )
    };
}

/// XORs the keystream of `n` groups of sixteen (`wide`) or four blocks, starting at block
/// `state[12]`, into the bytes at `src` and writes them to `dst` (`src == dst` works in place).
/// Counters past `2³² - 1` wrap within the 32-bit word.
///
/// # Safety
///
/// The CPU must support AVX-512 F and VL with the OS saving the ZMM state; `n >= 1`; `src` must
/// be readable and `dst` writable for `n * WIDE` (`wide`) or `n * NARROW` bytes, and the two ranges
/// must either be the same or not overlap.
pub(super) unsafe fn xor(state: &[u32; 16], src: *const u8, dst: *mut u8, n: usize, wide: bool) {
    debug_assert!(n >= 1);
    if wide {
        // SAFETY: the caller guarantees the CPU and OS features and the `src` / `dst` ranges.
        // The kernel reads the 64-byte state and constants and `n * 1024` bytes from `src`,
        // writes `n * 1024` bytes to `dst` (each 64-byte block is loaded before it is stored, so
        // `src == dst` works), uses no stack and clobbers only the registers declared here (all
        // vector registers through `clobber_abi("C")`, the flags), ending with `vzeroupper`.
        unsafe {
            core::arch::asm!(
                wide_kernel!(),
                s = in(reg) state.as_ptr(),
                c = in(reg) &raw const CONSTS,
                inout("rsi") src => _,
                inout("rdi") dst => _,
                inout("rcx") n => _,
                out("rax") _,
                clobber_abi("C"),
                options(nostack),
            );
        }
    } else {
        // SAFETY: as above, with `n * 256` bytes and xmm registers.
        unsafe {
            core::arch::asm!(
                narrow_kernel!(),
                s = in(reg) state.as_ptr(),
                c = in(reg) &raw const CONSTS,
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
