//! eBPF: a tiny assembler and the two programs flash loads.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// One eBPF instruction (`struct bpf_insn`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R6: u8 = 6;
const R10: u8 = 10;

// Opcodes (linux/bpf.h).
const ALU64_MOV_X: u8 = 0xbf;
const ALU64_MOV_K: u8 = 0xb7;
const ALU64_ADD_K: u8 = 0x07;
const ALU_MOD_K: u8 = 0x94;
const STX_MEM_W: u8 = 0x63;
const STX_MEM_DW: u8 = 0x7b;
const LD_IMM64: u8 = 0x18;
const JMP_JNE_K: u8 = 0x55;
const CALL: u8 = 0x85;
const EXIT: u8 = 0x95;
/// `src_reg` of a `LD_IMM64` whose immediate is a map fd.
const PSEUDO_MAP_FD: u8 = 1;

// Helper function ids.
const FN_GET_SMP_PROCESSOR_ID: i32 = 8;
const FN_GET_SOCKET_COOKIE: i32 = 46;
const FN_SK_REDIRECT_HASH: i32 = 72;
const FN_SK_SELECT_REUSEPORT: i32 = 82;

const SK_PASS: i32 = 1;

fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
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
pub(crate) fn attach_cpu_reuseport(fds: &[i32]) -> std::io::Result<()> {
    use crate::sys;
    use std::os::fd::AsRawFd;
    let n = fds.len() as u32;
    let map = sys::Map::<u32, u64>::create(sys::MAP_REUSEPORT_SOCKARRAY, n)?;
    for (i, &fd) in fds.iter().enumerate() {
        map.update(&(i as u32), &(fd as u64))?;
    }
    let prog = sys::prog_load(
        sys::PROG_SK_REUSEPORT,
        sys::ATTACH_SK_REUSEPORT_SELECT,
        &reuseport_cpu(map.fd(), n),
        "flash_steer_cpu",
    )?;
    // The group holds the program and the program the map: both fds can be closed now.
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
        assert_eq!(std::mem::size_of::<Insn>(), 8);
    }
}
