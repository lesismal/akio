//! Classic BPF: the instruction format, the `SO_ATTACH_REUSEPORT_CBPF` selection programs, and
//! (for tests) a small interpreter of the subset those programs use.
//!
//! A reuseport program runs on the packet that created the connection (the TCP SYN, or the UDP
//! datagram); its return value is the index of the socket in the reuseport group, i.e. the
//! I/O thread. Classic BPF needs no privileges, which makes it the always-available tier.

use crate::steer::{HashKey, SEED, SLOTS, Steering, fin_consts, mix_prime, slot_table};

/// One classic BPF instruction (`struct sock_filter`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// Opcode.
    pub code: u16,
    /// Jump offset when the condition holds.
    pub jt: u8,
    /// Jump offset when it does not.
    pub jf: u8,
    /// Constant operand.
    pub k: u32,
}

// Instruction classes, sizes, modes and operations (linux/filter.h).
const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ST: u16 = 0x02;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const B: u16 = 0x10;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const MEM: u16 = 0x60;
const MSH: u16 = 0xa0;
const MUL: u16 = 0x20;
const AND: u16 = 0x50;
const RSH: u16 = 0x70;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;
const K: u16 = 0x00;
const X: u16 = 0x08;
const JA: u16 = 0x00;
const JEQ: u16 = 0x10;
const JGE: u16 = 0x30;
const RET_A: u16 = 0x10;
const TAX: u16 = 0x00;

/// Offset base of loads relative to the network header (`SKF_NET_OFF`).
const NET: u32 = (-0x100000i32) as u32;
/// `SKF_AD_OFF + SKF_AD_CPU`: loads the CPU number.
const AD_CPU: u32 = (-0x1000i32 + 36) as u32;

fn op(code: u16, k: u32) -> Insn {
    Insn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jmp(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code, jt, jf, k }
}

/// The selection program for `steering` over `n` sockets.
pub fn program(steering: Steering, n: usize) -> Vec<Insn> {
    let n = n.max(1) as u32;
    match steering {
        // A = cpu % n
        Steering::Cpu => vec![
            op(LD | W | ABS, AD_CPU),
            op(ALU | MOD | K, n),
            op(RET | RET_A, 0),
        ],
        Steering::Hash(key) => hash_program(key, n as usize),
    }
}

/// `h = (h ^ A) * P`, with `h` kept in scratch slot 0. The first word seeds `h`.
fn mix_word(p: &mut Vec<Insn>, first: bool) {
    if first {
        p.push(op(ALU | XOR | K, SEED));
    } else {
        p.push(op(MISC | TAX, 0));
        p.push(op(LD | W | MEM, 0));
        p.push(op(ALU | XOR | X, 0));
    }
    p.push(op(ALU | MUL | K, mix_prime()));
    p.push(op(ST, 0));
}

fn hash_program(key: HashKey, n: usize) -> Vec<Insn> {
    let ports = matches!(key, HashKey::SrcIpPort);
    // IPv4 block.
    let mut v4 = vec![op(LD | W | ABS, NET.wrapping_add(12))];
    mix_word(&mut v4, true);
    if ports {
        v4.push(op(LDX | B | MSH, NET)); // X = 4 * (ihl)
        v4.push(op(LD | W | IND, NET)); // A = sport << 16 | dport
        mix_word(&mut v4, false);
    }
    // IPv6 block (no extension headers before TCP/UDP).
    let mut v6 = Vec::new();
    for (i, off) in [8u32, 12, 16, 20].into_iter().enumerate() {
        v6.push(op(LD | W | ABS, NET.wrapping_add(off)));
        mix_word(&mut v6, i == 0);
    }
    if ports {
        v6.push(op(LD | W | ABS, NET.wrapping_add(40)));
        mix_word(&mut v6, false);
    }

    let mut p = vec![
        op(LD | B | ABS, NET),
        op(ALU | RSH | K, 4),
        jmp(JMP | JEQ | K, 6, 0, 1),
        op(JMP | JA, v4.len() as u32 + 1), // to the IPv6 block
    ];
    p.extend(v4);
    p.push(op(JMP | JA, v6.len() as u32)); // over it
    p.extend(v6);
    // Finalize (lowbias32) and take the slot.
    let (c1, c2) = fin_consts();
    p.push(op(LD | W | MEM, 0));
    for (shift, mul) in [(16, Some(c1)), (15, Some(c2)), (16, None)] {
        p.push(op(MISC | TAX, 0));
        p.push(op(ALU | RSH | K, shift));
        p.push(op(ALU | XOR | X, 0));
        if let Some(m) = mul {
            p.push(op(ALU | MUL | K, m));
        }
    }
    p.push(op(ALU | MOD | K, SLOTS as u32));
    p.extend(slot_tree(&runs(&slot_table(n))));
    p
}

/// Runs of equal thread index in the slot table: `(first_slot, index)`.
fn runs(table: &[u8]) -> Vec<(u32, u32)> {
    let mut r: Vec<(u32, u32)> = Vec::new();
    for (s, &i) in table.iter().enumerate() {
        if r.last().is_none_or(|&(_, last)| last != u32::from(i)) {
            r.push((s as u32, u32::from(i)));
        }
    }
    r
}

/// A binary search over the runs on A (the slot), ending in `ret #index`. Conditional jumps
/// only ever skip one instruction; long distances use `ja`, whose offset is 32 bits.
fn slot_tree(runs: &[(u32, u32)]) -> Vec<Insn> {
    if runs.len() == 1 {
        return vec![op(RET | K, runs[0].1)];
    }
    let mid = runs.len() / 2;
    let left = slot_tree(&runs[..mid]);
    let right = slot_tree(&runs[mid..]);
    let mut p = Vec::with_capacity(2 + left.len() + right.len());
    // if A >= first slot of the right half: take the `ja` to it, else fall into the left half.
    p.push(jmp(JMP | JGE | K, runs[mid].0, 0, 1));
    p.push(op(JMP | JA, left.len() as u32));
    p.extend(left);
    p.extend(right);
    p
}

/// Interprets `prog` the way the kernel runs a reuseport program: `net` is the packet from its
/// network header on, `cpu` the CPU it was received on. Returns the program's result (0 when a
/// load is out of bounds, as in the kernel). Only the instructions used above are supported.
pub fn run(prog: &[Insn], net: &[u8], cpu: u32) -> u32 {
    let load = |off: u32, size: usize| -> Option<u32> {
        if off == AD_CPU {
            return Some(cpu);
        }
        let rel = off.wrapping_sub(NET) as usize;
        let b = net.get(rel..rel + size)?;
        Some(b.iter().fold(0u32, |v, &x| (v << 8) | u32::from(x)))
    };
    let (mut a, mut x, mut mem) = (0u32, 0u32, [0u32; 16]);
    let mut pc = 0usize;
    while let Some(i) = prog.get(pc) {
        pc += 1;
        let size = match i.code & 0x18 {
            0x00 => 4,
            0x08 => 2,
            _ => 1,
        };
        match i.code & 0x07 {
            LD => match i.code & 0xe0 {
                ABS => match load(i.k, size) {
                    Some(v) => a = v,
                    None => return 0,
                },
                IND => match load(x.wrapping_add(i.k), size) {
                    Some(v) => a = v,
                    None => return 0,
                },
                MEM => a = mem[i.k as usize & 15],
                m => panic!("unsupported ld mode {m:#x}"),
            },
            LDX => match load(i.k, 1) {
                Some(v) => x = 4 * (v & 0xf),
                None => return 0,
            },
            ST => mem[i.k as usize & 15] = a,
            ALU => {
                let v = if i.code & X != 0 { x } else { i.k };
                a = match i.code & 0xf0 {
                    MUL => a.wrapping_mul(v),
                    AND => a & v,
                    RSH => a.wrapping_shr(v),
                    MOD => a % v,
                    XOR => a ^ v,
                    o => panic!("unsupported alu op {o:#x}"),
                };
            }
            JMP => match i.code & 0xf0 {
                JA => pc += i.k as usize,
                JEQ => pc += if a == i.k { i.jt } else { i.jf } as usize,
                JGE => pc += if a >= i.k { i.jt } else { i.jf } as usize,
                o => panic!("unsupported jump {o:#x}"),
            },
            RET => return if i.code & RET_A != 0 { a } else { i.k },
            MISC => x = a,
            c => panic!("unsupported class {c:#x}"),
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::steer::expected_index;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    /// A minimal IPv4 or IPv6 + TCP header from `src` to `dst`.
    fn packet(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let mut p = Vec::new();
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                p.extend([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]);
                p.extend(s.octets());
                p.extend(d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                p.extend([0x60, 0, 0, 0, 0, 20, 6, 64]);
                p.extend(s.octets());
                p.extend(d.octets());
            }
            _ => unreachable!(),
        }
        p.extend(src.port().to_be_bytes());
        p.extend(dst.port().to_be_bytes());
        p.extend([0u8; 16]);
        p
    }

    #[test]
    fn cpu_program_is_cpu_mod_n() {
        let p = program(Steering::Cpu, 3);
        for cpu in 0..10 {
            assert_eq!(run(&p, &[], cpu), cpu % 3);
        }
    }

    #[test]
    fn hash_programs_match_the_userspace_hash() {
        let local4: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let local6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        for key in [HashKey::SrcIp, HashKey::SrcIpPort] {
            for n in [1usize, 2, 3, 4, 7, 16, 64, SLOTS] {
                let p = program(Steering::Hash(key), n);
                assert!(p.len() < 4096, "program too long: {}", p.len());
                for i in 0..300u32 {
                    let port = 1024 + (i * 7919 % 60000) as u16;
                    let src4 = SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(
                            0x0a00_0000u32.wrapping_add(i.wrapping_mul(2654435761)),
                        )),
                        port,
                    );
                    let src6 = SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(
                            u128::from(i).wrapping_mul(0x9e3779b97f4a7c15_f39cc0605cedc835),
                        )),
                        port,
                    );
                    for (src, local) in [(src4, local4), (src6, local6)] {
                        let got = run(&p, &packet(src, local), 0) as usize;
                        let want = expected_index(Steering::Hash(key), n, src, local).unwrap();
                        assert_eq!(got, want, "{key:?} n={n} {src}");
                        assert!(got < n);
                    }
                }
            }
        }
    }

    #[test]
    fn src_ip_ignores_the_port() {
        let local: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let p = program(Steering::Hash(HashKey::SrcIp), 8);
        let a = run(&p, &packet("10.1.2.3:1000".parse().unwrap(), local), 0);
        let b = run(&p, &packet("10.1.2.3:2000".parse().unwrap(), local), 0);
        assert_eq!(a, b);
    }
}
