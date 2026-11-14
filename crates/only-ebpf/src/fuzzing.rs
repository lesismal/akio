//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::cbpf::{Insn, program, run};
use crate::{HashKey, SLOTS, Steering, expected_index};

/// Every jump of `p` lands on an instruction and the last instruction returns.
fn check_jumps(p: &[Insn]) {
    for (i, ins) in p.iter().enumerate() {
        if ins.code & 0x07 == 0x05 {
            let next = i + 1;
            let targets = if ins.code & 0xf0 == 0 {
                vec![next + ins.k as usize]
            } else {
                vec![next + usize::from(ins.jt), next + usize::from(ins.jf)]
            };
            for t in targets {
                assert!(t < p.len(), "jump out of the program at {i}");
            }
        }
    }
    assert_eq!(
        p.last().map(|l| l.code & 0x07),
        Some(0x06),
        "must end in ret"
    );
}

/// The flow a packet (from its network header) describes, if it is long enough to be one.
fn flow(pkt: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0xf) * 4;
            let ports = pkt.get(ihl..ihl + 4)?;
            let b = pkt.get(..20)?;
            let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
            let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
            Some((
                SocketAddr::new(IpAddr::V4(src), u16::from_be_bytes([ports[0], ports[1]])),
                SocketAddr::new(IpAddr::V4(dst), u16::from_be_bytes([ports[2], ports[3]])),
            ))
        }
        6 => {
            let b = pkt.get(..44)?;
            let src: [u8; 16] = b[8..24].try_into().ok()?;
            let dst: [u8; 16] = b[24..40].try_into().ok()?;
            Some((
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(src)),
                    u16::from_be_bytes([b[40], b[41]]),
                ),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(dst)),
                    u16::from_be_bytes([b[42], b[43]]),
                ),
            ))
        }
        _ => None,
    }
}

/// `cbpf_steer`: the generated `SO_ATTACH_REUSEPORT_CBPF` selection programs, run by the
/// interpreter on arbitrary packets. `data[0..2]`: thread count (1..=SLOTS), `data[2]`: the
/// steering, `data[3]`: the CPU; the rest is the packet. Programs must be well formed, return a
/// valid thread index, and agree with the userspace hash on well-formed packets.
pub fn cbpf_steer(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let n = usize::from(u16::from_le_bytes([data[0], data[1]])) % SLOTS + 1;
    let steering = match data[2] % 3 {
        0 => Steering::Cpu,
        1 => Steering::Hash(HashKey::SrcIp),
        _ => Steering::Hash(HashKey::SrcIpPort),
    };
    let cpu = u32::from(data[3]);
    let pkt = &data[4..];
    let p = program(steering, n);
    check_jumps(&p);
    let got = run(&p, pkt, cpu) as usize;
    assert!(got < n, "index {got} out of {n}");
    // An IPv6 packet from an IPv4-mapped address is hashed as IPv6 by the program but as the
    // IPv4 peer a dual-stack socket reports by `expected_index`; such packets are not routable.
    let flow = flow(pkt).filter(|(src, _)| match src.ip() {
        IpAddr::V6(a) => a.to_ipv4_mapped().is_none(),
        IpAddr::V4(_) => true,
    });
    if let (Steering::Hash(_), Some((src, dst))) = (steering, flow) {
        assert_eq!(Some(got), expected_index(steering, n, src, dst));
    }
    if steering == Steering::Cpu {
        assert_eq!(got, cpu as usize % n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn seeds() -> Vec<Vec<u8>> {
        let v4: &[u8] = &[
            0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 1, 2, 3, 10, 0, 0, 1, 0x30, 0x39, 1, 187,
        ];
        let v4opts: &[u8] = &[
            0x46, 0, 0, 44, 0, 0, 0, 0, 64, 17, 0, 0, 192, 168, 1, 9, 10, 0, 0, 1, 1, 2, 3, 4,
            0x30, 0x39, 0, 53,
        ];
        let mut v6 = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
        v6.extend((0..32).map(|i| i as u8));
        v6.extend([0x30, 0x39, 1, 187]);
        let mut v = Vec::new();
        for (n, s) in [(4u16, 0u8), (7, 1), (64, 2), (1, 2)] {
            for pkt in [v4, v4opts, &v6[..], &[]] {
                v.push([&n.to_le_bytes()[..], &[s, 3][..], pkt].concat());
            }
        }
        v
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "cbpf_steer", cbpf_steer) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            cbpf_steer(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p only-ebpf --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "cbpf_steer", &seeds());
    }
}
