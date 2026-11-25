//! eBPF: a tiny assembler (with labels) and the programs `akio` loads.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::steer::{HashKey, SEED, SLOTS, fin_consts, mix_prime};

/// One eBPF instruction (`struct bpf_insn`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Insn {
    pub(crate) code: u8,
    regs: u8,
    pub(crate) off: i16,
    pub(crate) imm: i32,
}

#[cfg(any(test, feature = "fuzzing"))]
impl Insn {
    pub(crate) fn dst(&self) -> u8 {
        #[cfg(target_endian = "little")]
        return self.regs & 0x0f;
        #[cfg(target_endian = "big")]
        return self.regs >> 4;
    }

    pub(crate) fn src(&self) -> u8 {
        #[cfg(target_endian = "little")]
        return self.regs >> 4;
        #[cfg(target_endian = "big")]
        return self.regs & 0x0f;
    }
}

pub(crate) const R0: u8 = 0;
pub(crate) const R1: u8 = 1;
pub(crate) const R2: u8 = 2;
pub(crate) const R3: u8 = 3;
pub(crate) const R4: u8 = 4;
pub(crate) const R5: u8 = 5;
pub(crate) const R6: u8 = 6;
pub(crate) const R7: u8 = 7;
pub(crate) const R8: u8 = 8;
pub(crate) const R9: u8 = 9;
pub(crate) const R10: u8 = 10;

// Opcodes (linux/bpf.h, linux/bpf_common.h).
pub(crate) const ALU64_ADD_K: u8 = 0x07;
pub(crate) const ALU64_ADD_X: u8 = 0x0f;
pub(crate) const ALU64_SUB_X: u8 = 0x1f;
pub(crate) const ALU64_AND_K: u8 = 0x57;
pub(crate) const ALU64_LSH_K: u8 = 0x67;
pub(crate) const ALU64_RSH_K: u8 = 0x77;
pub(crate) const ALU64_MOV_K: u8 = 0xb7;
pub(crate) const ALU64_MOV_X: u8 = 0xbf;
pub(crate) const ALU_MUL_K: u8 = 0x24;
pub(crate) const ALU_RSH_K: u8 = 0x74;
pub(crate) const ALU_MOD_K: u8 = 0x94;
pub(crate) const ALU_XOR_K: u8 = 0xa4;
pub(crate) const ALU_XOR_X: u8 = 0xac;
pub(crate) const ALU_MOV_X: u8 = 0xbc;
/// `BPF_ALU | BPF_END | BPF_TO_BE`: host to big endian (`imm` = 16, 32 or 64 bits).
pub(crate) const ALU_TO_BE: u8 = 0xdc;
pub(crate) const LDX_MEM_W: u8 = 0x61;
pub(crate) const LDX_MEM_H: u8 = 0x69;
pub(crate) const LDX_MEM_B: u8 = 0x71;
pub(crate) const LDX_MEM_DW: u8 = 0x79;
pub(crate) const ST_MEM_W: u8 = 0x62;
pub(crate) const ST_MEM_DW: u8 = 0x7a;
pub(crate) const STX_MEM_W: u8 = 0x63;
pub(crate) const STX_MEM_DW: u8 = 0x7b;
pub(crate) const LD_IMM64: u8 = 0x18;
pub(crate) const JMP_JA: u8 = 0x05;
pub(crate) const JMP_JEQ_K: u8 = 0x15;
pub(crate) const JMP_JGT_X: u8 = 0x2d;
pub(crate) const JMP_JGE_X: u8 = 0x3d;
pub(crate) const JMP_JNE_K: u8 = 0x55;
pub(crate) const JMP_JLT_K: u8 = 0xa5;
pub(crate) const JMP_JLT_X: u8 = 0xad;
pub(crate) const JMP_JLE_X: u8 = 0xbd;
pub(crate) const CALL: u8 = 0x85;
pub(crate) const EXIT: u8 = 0x95;
/// `src_reg` of a `LD_IMM64` whose immediate is a map fd.
pub(crate) const PSEUDO_MAP_FD: u8 = 1;

// Helper function ids.
pub(crate) const FN_MAP_LOOKUP_ELEM: i32 = 1;
pub(crate) const FN_MAP_UPDATE_ELEM: i32 = 2;
pub(crate) const FN_KTIME_GET_NS: i32 = 5;
pub(crate) const FN_GET_SMP_PROCESSOR_ID: i32 = 8;
pub(crate) const FN_GET_SOCKET_COOKIE: i32 = 46;
pub(crate) const FN_REDIRECT_MAP: i32 = 51;
pub(crate) const FN_SKB_LOAD_BYTES_RELATIVE: i32 = 68;
pub(crate) const FN_SK_REDIRECT_HASH: i32 = 72;
pub(crate) const FN_SK_SELECT_REUSEPORT: i32 = 82;

/// `BPF_HDR_START_NET` (`bpf_skb_load_bytes_relative`).
pub(crate) const HDR_START_NET: i32 = 1;

pub(crate) const SK_PASS: i32 = 1;
pub(crate) const XDP_DROP: i32 = 1;
pub(crate) const XDP_PASS: i32 = 2;

pub(crate) fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    #[cfg(target_endian = "little")]
    let regs = dst | (src << 4);
    #[cfg(target_endian = "big")]
    let regs = (dst << 4) | src;
    Insn {
        code,
        regs,
        off,
        imm,
    }
}

fn mov_x(dst: u8, src: u8) -> Insn {
    ins(ALU64_MOV_X, dst, src, 0, 0)
}

fn mov_k(dst: u8, imm: i32) -> Insn {
    ins(ALU64_MOV_K, dst, 0, 0, imm)
}

fn call(f: i32) -> Insn {
    ins(CALL, 0, 0, 0, f)
}

fn ld_map_fd(dst: u8, fd: i32) -> [Insn; 2] {
    [ins(LD_IMM64, dst, PSEUDO_MAP_FD, 0, fd), ins(0, 0, 0, 0, 0)]
}

/// A jump target of [`Asm`].
#[derive(Clone, Copy)]
pub(crate) struct Label(usize);

/// Appends instructions, resolving forward jumps to labels in [`Asm::finish`].
#[derive(Default)]
pub(crate) struct Asm {
    p: Vec<Insn>,
    /// (instruction index, label) of every jump to patch.
    fixups: Vec<(usize, usize)>,
    labels: Vec<Option<usize>>,
}

impl Asm {
    pub(crate) fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    /// Places `l` at the next instruction.
    pub(crate) fn bind(&mut self, l: Label) {
        self.labels[l.0] = Some(self.p.len());
    }

    pub(crate) fn i(&mut self, i: Insn) -> &mut Self {
        self.p.push(i);
        self
    }

    pub(crate) fn op(&mut self, code: u8, dst: u8, src: u8, off: i16, imm: i32) -> &mut Self {
        self.i(ins(code, dst, src, off, imm))
    }

    /// A conditional (or, with [`JMP_JA`], unconditional) jump to `to`.
    pub(crate) fn jmp(&mut self, code: u8, dst: u8, src: u8, imm: i32, to: Label) -> &mut Self {
        self.fixups.push((self.p.len(), to.0));
        self.i(ins(code, dst, src, 0, imm))
    }

    pub(crate) fn goto(&mut self, to: Label) -> &mut Self {
        self.jmp(JMP_JA, 0, 0, 0, to)
    }

    pub(crate) fn ld_imm64(&mut self, dst: u8, v: u64) -> &mut Self {
        self.i(ins(LD_IMM64, dst, 0, 0, v as u32 as i32));
        self.i(ins(0, 0, 0, 0, (v >> 32) as u32 as i32))
    }

    pub(crate) fn ld_map(&mut self, dst: u8, fd: i32) -> &mut Self {
        self.p.extend(ld_map_fd(dst, fd));
        self
    }

    pub(crate) fn call(&mut self, f: i32) -> &mut Self {
        self.i(call(f))
    }

    pub(crate) fn exit_with(&mut self, r0: i32) -> &mut Self {
        self.i(mov_k(R0, r0));
        self.i(ins(EXIT, 0, 0, 0, 0))
    }

    pub(crate) fn finish(mut self) -> Vec<Insn> {
        for (at, l) in self.fixups {
            let to = self.labels[l].expect("jump to an unbound label");
            self.p[at].off = i16::try_from(to as isize - at as isize - 1).expect("jump too long");
        }
        self.p
    }
}

/// `BPF_PROG_TYPE_SK_REUSEPORT`: select `sockarray[cpu % n]`. If the slot is empty the
/// selection fails and returning `SK_PASS` lets the kernel fall back to its own hash.
pub(crate) fn reuseport_cpu(sockarray: i32, n: u32) -> Vec<Insn> {
    let mut p = vec![
        mov_x(R6, R1),
        call(FN_GET_SMP_PROCESSOR_ID),
        ins(ALU_MOD_K, R0, 0, 0, n.max(1) as i32),
        ins(STX_MEM_W, R10, R0, -4, 0),
    ];
    p.extend(ld_map_fd(R2, sockarray));
    p.extend([
        mov_x(R1, R6),
        mov_x(R3, R10),
        ins(ALU64_ADD_K, R3, 0, 0, -4),
        mov_k(R4, 0),
        call(FN_SK_SELECT_REUSEPORT),
        mov_k(R0, SK_PASS),
        ins(EXIT, 0, 0, 0, 0),
    ]);
    p
}

/// Loads `len` bytes at `off` (from the network header) to the stack at `fp + to`; jumps to
/// `fail` when the packet is too short. `off_reg`: take the offset from that register instead.
fn load_net(a: &mut Asm, off: i32, off_reg: Option<u8>, to: i16, len: i32, fail: Label) {
    a.i(mov_x(R1, R6));
    match off_reg {
        Some(r) => a.i(mov_x(R2, r)),
        None => a.i(mov_k(R2, off)),
    };
    a.i(mov_x(R3, R10))
        .op(ALU64_ADD_K, R3, 0, 0, i32::from(to))
        .i(mov_k(R4, len))
        .i(mov_k(R5, HDR_START_NET))
        .call(FN_SKB_LOAD_BYTES_RELATIVE)
        .jmp(JMP_JNE_K, R0, 0, 0, fail);
}

/// Mixes the big-endian word at `fp + at` into the hash in `R7` (`h = (h ^ w) * P`, 32 bits;
/// the first word seeds it).
fn mix(a: &mut Asm, at: i16, first: bool) {
    a.op(LDX_MEM_W, R1, R10, at, 0).op(ALU_TO_BE, R1, 0, 0, 32);
    if first {
        a.op(ALU_MOV_X, R7, R1, 0, 0)
            .op(ALU_XOR_K, R7, 0, 0, SEED as i32);
    } else {
        a.op(ALU_XOR_X, R7, R1, 0, 0);
    }
    a.op(ALU_MUL_K, R7, 0, 0, mix_prime() as i32);
}

/// `BPF_PROG_TYPE_SK_REUSEPORT`: the eBPF tier of [`Steering::Hash`](crate::Steering::Hash).
/// Computes exactly the classic BPF program's hash (and so [`crate::expected_index`]), looks
/// the slot up in `slots` (`ARRAY`, slot -> thread index) and selects that thread's socket from
/// `sockarray`. A packet it cannot parse, or an empty socket slot, leaves the choice to the
/// kernel's own hash.
pub(crate) fn reuseport_hash(sockarray: i32, slots: i32, key: HashKey) -> Vec<Insn> {
    let ports = key == HashKey::SrcIpPort;
    let mut a = Asm::default();
    let (pass, v4, fin) = (a.label(), a.label(), a.label());
    // fp-48..-28: header bytes; fp-24: ports; fp-8: thread index; fp-4: slot.
    a.i(mov_x(R6, R1));
    load_net(&mut a, 0, None, -48, 1, pass);
    a.op(LDX_MEM_B, R1, R10, -48, 0)
        .op(ALU64_RSH_K, R1, 0, 0, 4)
        .jmp(JMP_JEQ_K, R1, 0, 4, v4)
        .jmp(JMP_JNE_K, R1, 0, 6, pass);
    // IPv6: the source address, then the ports right after the fixed header.
    load_net(&mut a, 8, None, -48, 16, pass);
    for k in 0..4 {
        mix(&mut a, -48 + 4 * k, k == 0);
    }
    if ports {
        load_net(&mut a, 40, None, -24, 4, pass);
        mix(&mut a, -24, false);
    }
    a.goto(fin);
    // IPv4: the source address, then the ports after the header's IHL words.
    a.bind(v4);
    load_net(&mut a, 0, None, -48, 20, pass);
    mix(&mut a, -36, true);
    if ports {
        a.op(LDX_MEM_B, R8, R10, -48, 0)
            .op(ALU64_AND_K, R8, 0, 0, 0xf)
            .op(ALU64_LSH_K, R8, 0, 0, 2);
        load_net(&mut a, 0, Some(R8), -24, 4, pass);
        mix(&mut a, -24, false);
    }
    // lowbias32, then the slot.
    a.bind(fin);
    let (c1, c2) = fin_consts();
    for (shift, mul) in [(16, Some(c1)), (15, Some(c2)), (16, None)] {
        a.op(ALU_MOV_X, R1, R7, 0, 0)
            .op(ALU_RSH_K, R1, 0, 0, shift)
            .op(ALU_XOR_X, R7, R1, 0, 0);
        if let Some(m) = mul {
            a.op(ALU_MUL_K, R7, 0, 0, m as i32);
        }
    }
    a.op(ALU_MOD_K, R7, 0, 0, SLOTS as i32)
        .op(STX_MEM_W, R10, R7, -4, 0)
        .ld_map(R1, slots)
        .i(mov_x(R2, R10))
        .op(ALU64_ADD_K, R2, 0, 0, -4)
        .call(FN_MAP_LOOKUP_ELEM)
        .jmp(JMP_JEQ_K, R0, 0, 0, pass)
        .op(LDX_MEM_W, R1, R0, 0, 0)
        .op(STX_MEM_W, R10, R1, -8, 0)
        .i(mov_x(R1, R6))
        .ld_map(R2, sockarray)
        .i(mov_x(R3, R10))
        .op(ALU64_ADD_K, R3, 0, 0, -8)
        .i(mov_k(R4, 0))
        .call(FN_SK_SELECT_REUSEPORT);
    a.bind(pass);
    a.exit_with(SK_PASS);
    a.finish()
}

/// `struct sk_reuseport_md`: offsets of `hash` and `migrating_sk` (Linux 5.14+).
const MD_HASH: i16 = 32;
const MD_MIGRATING_SK: i16 = 48;

/// `BPF_PROG_TYPE_SK_REUSEPORT` for a group shared by several processes (pinned in bpffs):
/// `n` sockets in `sockarray`, chosen by [`reuseport_cpu`] or [`reuseport_hash`] (`slots`
/// is only read by the latter). With `migrate` the program is loaded for
/// `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`: when the kernel moves a request or an accepted-queue
/// connection off a closing listener (`migrating_sk` set), it selects
/// `sockarray[hash % n]`, the slot's current socket, which after a process replaced its sockets is the new
/// process's; an empty slot leaves the choice to the kernel (a random live listener).
pub(crate) fn reuseport_shared(
    sockarray: i32,
    slots: i32,
    n: u32,
    steering: crate::Steering,
    migrate: bool,
) -> Vec<Insn> {
    let body = match steering {
        crate::Steering::Hash(key) => reuseport_hash(sockarray, slots, key),
        _ => reuseport_cpu(sockarray, n),
    };
    if !migrate {
        return body;
    }
    let mut a = Asm::default();
    let skip = a.label();
    a.op(LDX_MEM_DW, R2, R1, MD_MIGRATING_SK, 0)
        .jmp(JMP_JEQ_K, R2, 0, 0, skip)
        .i(mov_x(R6, R1))
        .op(LDX_MEM_W, R0, R1, MD_HASH, 0)
        .op(ALU_MOD_K, R0, 0, 0, n.max(1) as i32)
        .op(STX_MEM_W, R10, R0, -4, 0)
        .ld_map(R2, sockarray)
        .i(mov_x(R1, R6))
        .i(mov_x(R3, R10))
        .op(ALU64_ADD_K, R3, 0, 0, -4)
        .i(mov_k(R4, 0))
        .call(FN_SK_SELECT_REUSEPORT)
        .exit_with(SK_PASS);
    a.bind(skip);
    let mut p = a.finish();
    p.extend(body);
    p
}

/// `BPF_PROG_TYPE_XDP` for AF_XDP: redirects every frame of an RX queue to the AF_XDP socket
/// stored for that queue in `xskmap` (`XSKMAP`); a queue without a socket passes its frames to
/// the kernel (the `XDP_PASS` default action of `bpf_redirect_map`, Linux 5.3+).
pub(crate) fn xdp_redirect_xsk(xskmap: i32) -> Vec<Insn> {
    let mut p = vec![ins(LDX_MEM_W, R2, R1, 16, 0)]; // xdp_md.rx_queue_index
    p.extend(ld_map_fd(R1, xskmap));
    p.extend([
        mov_k(R3, XDP_PASS),
        call(FN_REDIRECT_MAP),
        ins(EXIT, 0, 0, 0, 0),
    ]);
    p
}

/// Indexes of the rate limiter's counters (`PERCPU_ARRAY` of `u64`).
pub(crate) const CTR_DROPPED: i32 = 0;
pub(crate) const CTR_PASSED: i32 = 1;
pub(crate) const CTR_NEW: i32 = 2;
pub(crate) const COUNTERS: u32 = 3;

/// Parameters of [`xdp_rate_limit`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct LimitProg {
    /// `LRU_PERCPU_HASH`: 16-byte source address (IPv4 mapped to IPv6) -> [`Bucket`].
    pub(crate) sources: i32,
    /// `PERCPU_ARRAY` of [`COUNTERS`] `u64`s.
    pub(crate) counters: i32,
    /// Nanoseconds of credit one packet costs (`1e9 / rate`).
    pub(crate) cost: u64,
    /// Credit a source can save up (`cost * burst`).
    pub(crate) cap: u64,
    /// Count only TCP SYNs (without ACK); everything else passes untouched.
    pub(crate) syn_only: bool,
}

/// The value of the rate limiter's source map: a token bucket kept as nanoseconds of credit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Bucket {
    pub(crate) credit: u64,
    pub(crate) last: u64,
}

/// `::ffff:0:0/96` in the third word of the key, as stored by a 32-bit store.
const MAPPED: i32 = i32::from_ne_bytes([0, 0, 0xff, 0xff]);

/// `BPF_PROG_TYPE_XDP`: per-source token buckets. Every counted packet (all IPv4/IPv6 ones, or
/// with `syn_only` only TCP SYNs) costs `cost` ns of credit from its source's bucket, which
/// refills at one nanosecond per nanosecond up to `cap`; a packet without enough credit is
/// dropped. The bucket is per CPU (the map is per-CPU), so no atomics are needed. Packets that
/// are not counted (other EtherTypes, VLAN-tagged frames, non-first IPv4 fragments, IPv6 with
/// extension headers before TCP when `syn_only`) pass.
pub(crate) fn xdp_rate_limit(p: LimitProg) -> Vec<Insn> {
    let mut a = Asm::default();
    let (pass, v4, limit, newsrc, full, have, drop, count, ret) = (
        a.label(),
        a.label(),
        a.label(),
        a.label(),
        a.label(),
        a.label(),
        a.label(),
        a.label(),
        a.label(),
    );
    // r6 = data, r7 = data_end.
    a.op(LDX_MEM_W, R6, R1, 0, 0)
        .op(LDX_MEM_W, R7, R1, 4, 0)
        .i(mov_x(R2, R6))
        .op(ALU64_ADD_K, R2, 0, 0, 14)
        .jmp(JMP_JGT_X, R2, R7, 0, pass)
        .op(LDX_MEM_H, R3, R6, 12, 0)
        .op(ALU_TO_BE, R3, 0, 0, 16)
        .jmp(JMP_JEQ_K, R3, 0, 0x0800, v4)
        .jmp(JMP_JNE_K, R3, 0, 0x86dd, pass);
    // IPv6: key = source address.
    a.i(mov_x(R2, R6))
        .op(ALU64_ADD_K, R2, 0, 0, 54)
        .jmp(JMP_JGT_X, R2, R7, 0, pass);
    for k in 0..4 {
        a.op(LDX_MEM_W, R3, R6, 22 + 4 * k, 0)
            .op(STX_MEM_W, R10, R3, -16 + 4 * k, 0);
    }
    if p.syn_only {
        a.op(LDX_MEM_B, R3, R6, 20, 0)
            .jmp(JMP_JNE_K, R3, 0, 6, pass)
            .i(mov_x(R2, R6))
            .op(ALU64_ADD_K, R2, 0, 0, 68)
            .jmp(JMP_JGT_X, R2, R7, 0, pass)
            .op(LDX_MEM_B, R3, R6, 67, 0)
            .op(ALU64_AND_K, R3, 0, 0, 0x12)
            .jmp(JMP_JNE_K, R3, 0, 0x02, pass);
    }
    a.goto(limit);
    // IPv4: key = ::ffff:source.
    a.bind(v4);
    a.i(mov_x(R2, R6))
        .op(ALU64_ADD_K, R2, 0, 0, 34)
        .jmp(JMP_JGT_X, R2, R7, 0, pass)
        .op(ST_MEM_DW, R10, 0, -16, 0)
        .op(ST_MEM_W, R10, 0, -8, MAPPED)
        .op(LDX_MEM_W, R3, R6, 26, 0)
        .op(STX_MEM_W, R10, R3, -4, 0);
    if p.syn_only {
        a.op(LDX_MEM_B, R3, R6, 23, 0)
            .jmp(JMP_JNE_K, R3, 0, 6, pass)
            // Non-first fragments carry no TCP header.
            .op(LDX_MEM_H, R3, R6, 20, 0)
            .op(ALU_TO_BE, R3, 0, 0, 16)
            .op(ALU64_AND_K, R3, 0, 0, 0x1fff)
            .jmp(JMP_JNE_K, R3, 0, 0, pass)
            .op(LDX_MEM_B, R3, R6, 14, 0)
            .op(ALU64_AND_K, R3, 0, 0, 0xf)
            .op(ALU64_LSH_K, R3, 0, 0, 2)
            .jmp(JMP_JLT_K, R3, 0, 20, pass)
            .i(mov_x(R2, R6))
            .op(ALU64_ADD_X, R2, R3, 0, 0)
            .i(mov_x(R4, R2))
            .op(ALU64_ADD_K, R4, 0, 0, 28)
            .jmp(JMP_JGT_X, R4, R7, 0, pass)
            .op(LDX_MEM_B, R3, R2, 27, 0)
            .op(ALU64_AND_K, R3, 0, 0, 0x12)
            .jmp(JMP_JNE_K, R3, 0, 0x02, pass);
    }
    // The bucket: r9 = this CPU's value.
    a.bind(limit);
    a.ld_map(R1, p.sources)
        .i(mov_x(R2, R10))
        .op(ALU64_ADD_K, R2, 0, 0, -16)
        .call(FN_MAP_LOOKUP_ELEM)
        .jmp(JMP_JEQ_K, R0, 0, 0, newsrc)
        .i(mov_x(R9, R0))
        .call(FN_KTIME_GET_NS)
        // r0 = elapsed since the last packet; last = now.
        .op(LDX_MEM_DW, R1, R9, 8, 0)
        .op(STX_MEM_DW, R9, R0, 8, 0)
        .op(ALU64_SUB_X, R0, R1, 0, 0)
        // r2 = min(cap, credit + elapsed), without overflowing.
        .op(LDX_MEM_DW, R2, R9, 0, 0)
        .ld_imm64(R3, p.cap)
        .jmp(JMP_JGE_X, R0, R3, 0, full)
        .op(ALU64_ADD_X, R2, R0, 0, 0)
        .jmp(JMP_JLE_X, R2, R3, 0, have);
    a.bind(full);
    a.i(mov_x(R2, R3));
    a.bind(have);
    a.ld_imm64(R4, p.cost)
        .jmp(JMP_JLT_X, R2, R4, 0, drop)
        .op(ALU64_SUB_X, R2, R4, 0, 0)
        .op(STX_MEM_DW, R9, R2, 0, 0)
        .i(mov_k(R8, CTR_PASSED))
        .i(mov_k(R6, XDP_PASS))
        .goto(count);
    a.bind(drop);
    a.op(STX_MEM_DW, R9, R2, 0, 0)
        .i(mov_k(R8, CTR_DROPPED))
        .i(mov_k(R6, XDP_DROP))
        .goto(count);
    // First packet of a source (on this CPU): a full bucket minus this packet.
    a.bind(newsrc);
    a.call(FN_KTIME_GET_NS)
        .op(STX_MEM_DW, R10, R0, -24, 0)
        .ld_imm64(R1, p.cap.saturating_sub(p.cost))
        .op(STX_MEM_DW, R10, R1, -32, 0)
        .ld_map(R1, p.sources)
        .i(mov_x(R2, R10))
        .op(ALU64_ADD_K, R2, 0, 0, -16)
        .i(mov_x(R3, R10))
        .op(ALU64_ADD_K, R3, 0, 0, -32)
        .i(mov_k(R4, 0))
        .call(FN_MAP_UPDATE_ELEM)
        .i(mov_k(R8, CTR_NEW))
        .i(mov_k(R6, XDP_PASS));
    // counters[r8] += 1; return r6.
    a.bind(count);
    a.op(STX_MEM_W, R10, R8, -36, 0)
        .ld_map(R1, p.counters)
        .i(mov_x(R2, R10))
        .op(ALU64_ADD_K, R2, 0, 0, -36)
        .call(FN_MAP_LOOKUP_ELEM)
        .jmp(JMP_JEQ_K, R0, 0, 0, ret)
        .op(LDX_MEM_DW, R1, R0, 0, 0)
        .op(ALU64_ADD_K, R1, 0, 0, 1)
        .op(STX_MEM_DW, R0, R1, 0, 0);
    a.bind(ret);
    a.i(mov_x(R0, R6)).op(EXIT, 0, 0, 0, 0);
    a.bind(pass);
    a.exit_with(XDP_PASS);
    a.finish()
}

/// `BPF_PROG_TYPE_SK_SKB` stream verdict: redirect the data to the egress of the socket stored
/// in `sockhash` under this socket's cookie (its relay peer); when there is none, pass it to
/// the socket's own receive queue (userspace).
pub(crate) fn relay_verdict(sockhash: i32) -> Vec<Insn> {
    let mut p = vec![
        mov_x(R6, R1),
        call(FN_GET_SOCKET_COOKIE),
        ins(STX_MEM_DW, R10, R0, -8, 0),
        mov_x(R1, R6),
    ];
    p.extend(ld_map_fd(R2, sockhash));
    p.extend([
        mov_x(R3, R10),
        ins(ALU64_ADD_K, R3, 0, 0, -8),
        mov_k(R4, 0), // flags 0: egress of the peer
        call(FN_SK_REDIRECT_HASH),
        ins(JMP_JNE_K, R0, 0, 1, 0), // SK_DROP (0) means "no peer"
        mov_k(R0, SK_PASS),
        ins(EXIT, 0, 0, 0, 0),
    ]);
    p
}

#[cfg(target_os = "linux")]
fn sockarray(fds: &[i32]) -> std::io::Result<crate::sys::Map<u32, u64>> {
    use crate::sys;
    let map = sys::Map::<u32, u64>::create(sys::MAP_REUSEPORT_SOCKARRAY, fds.len() as u32)?;
    for (i, &fd) in fds.iter().enumerate() {
        map.update(&(i as u32), &(fd as u64))?;
    }
    Ok(map)
}

#[cfg(target_os = "linux")]
pub(crate) fn attach_cpu_reuseport(fds: &[i32]) -> std::io::Result<()> {
    use crate::sys;
    use std::os::fd::AsRawFd;
    let map = sockarray(fds)?;
    let prog = sys::prog_load(
        sys::PROG_SK_REUSEPORT,
        sys::ATTACH_SK_REUSEPORT_SELECT,
        &reuseport_cpu(map.fd(), fds.len() as u32),
        "akio_steer_cpu",
    )?;
    // The group holds the program and the program the map: both fds can be closed now.
    sys::attach_reuseport_ebpf(fds[0], prog.as_raw_fd())
}

#[cfg(target_os = "linux")]
pub(crate) fn attach_hash_reuseport(fds: &[i32], key: HashKey) -> std::io::Result<()> {
    use crate::sys;
    use std::os::fd::AsRawFd;
    let socks = sockarray(fds)?;
    let slots = sys::Map::<u32, u32>::create(sys::MAP_ARRAY, SLOTS as u32)?;
    for (s, &i) in crate::steer::slot_table(fds.len()).iter().enumerate() {
        slots.update(&(s as u32), &u32::from(i))?;
    }
    let prog = sys::prog_load(
        sys::PROG_SK_REUSEPORT,
        sys::ATTACH_SK_REUSEPORT_SELECT,
        &reuseport_hash(socks.fd(), slots.fd(), key),
        "akio_steer_hash",
    )?;
    sys::attach_reuseport_ebpf(fds[0], prog.as_raw_fd())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programs_have_the_expected_shape() {
        let p = reuseport_cpu(7, 4);
        assert_eq!(p.len(), 13);
        assert_eq!(p[2].imm, 4);
        assert_eq!(p[4].code, LD_IMM64);
        assert_eq!(p[4].imm, 7);
        assert_eq!(p.last().unwrap().code, EXIT);
        let v = relay_verdict(9);
        assert_eq!(v.len(), 13);
        assert_eq!(v[4].imm, 9);
        assert_eq!(size_of::<Insn>(), 8);
    }

    #[test]
    fn jumps_stay_inside_and_go_forward() {
        let progs = [
            reuseport_hash(3, 4, HashKey::SrcIp),
            reuseport_hash(3, 4, HashKey::SrcIpPort),
            xdp_rate_limit(LimitProg {
                sources: 3,
                counters: 4,
                cost: 1000,
                cap: 10_000,
                syn_only: false,
            }),
            reuseport_shared(3, 4, 6, crate::Steering::Cpu, true),
            reuseport_shared(3, 4, 6, crate::Steering::Hash(HashKey::SrcIp), true),
            reuseport_shared(3, 4, 6, crate::Steering::Hash(HashKey::SrcIpPort), false),
            xdp_redirect_xsk(5),
            xdp_rate_limit(LimitProg {
                sources: 3,
                counters: 4,
                cost: 1000,
                cap: 10_000,
                syn_only: true,
            }),
        ];
        for p in progs {
            assert!(p.len() < 400);
            assert_eq!(p.last().unwrap().code, EXIT);
            for (i, x) in p.iter().enumerate() {
                if x.code & 0x07 == 0x05 && x.code != CALL && x.code != EXIT {
                    assert!(x.off >= 0, "backward jump at {i}");
                    assert!(i + 1 + (x.off as usize) < p.len(), "jump out at {i}");
                }
            }
        }
    }
}
