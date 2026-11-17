//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::cbpf::{Insn, program, run};
use crate::ebpf::{self, LimitProg};
use crate::steer::slot_table;
use crate::vm::{SimMap, Vm};
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
    let routable = flow(pkt).filter(|(src, _)| match src.ip() {
        IpAddr::V6(a) => a.to_ipv4_mapped().is_none(),
        IpAddr::V4(_) => true,
    });
    if let (Steering::Hash(_), Some((src, dst))) = (steering, routable) {
        assert_eq!(Some(got), expected_index(steering, n, src, dst));
    }
    if steering == Steering::Cpu {
        assert_eq!(got, cpu as usize % n);
    }
    // The eBPF tier computes the same hash; it leaves packets it cannot parse to the kernel.
    if let Steering::Hash(key) = steering {
        let mut vm = Vm::new();
        vm.add_map(3, SimMap::hash(4, 8, n));
        vm.add_map(4, SimMap::hash(4, 4, SLOTS));
        for (s, &i) in slot_table(n).iter().enumerate() {
            vm.update(4, &(s as u32).to_ne_bytes(), &u32::from(i).to_ne_bytes())
                .expect("slot");
        }
        let (ret, fx) = vm
            .run(&ebpf::reuseport_hash(3, 4, key), pkt)
            .unwrap_or_else(|e| panic!("eBPF hash program: {e}"));
        assert_eq!(ret, 1, "SK_PASS");
        if let Some(sel) = fx.selected {
            assert_eq!(sel as usize, got, "eBPF and classic BPF disagree");
        } else {
            assert!(
                flow(pkt).is_none(),
                "a parsable packet was left to the kernel"
            );
        }
    }
}

/// The source key the rate limiter counts `frame` under, if it counts it.
fn counted(frame: &[u8], syn_only: bool) -> Option<[u8; 16]> {
    let ethertype = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    let ip = &frame[14..];
    let mut key = [0u8; 16];
    match ethertype {
        0x0800 => {
            let h = ip.get(..20)?;
            key[10] = 0xff;
            key[11] = 0xff;
            key[12..].copy_from_slice(&h[12..16]);
            if syn_only {
                let ihl = usize::from(h[0] & 0xf) * 4;
                let frag = u16::from_be_bytes([h[6], h[7]]) & 0x1fff;
                if h[9] != 6 || frag != 0 || ihl < 20 || *ip.get(ihl + 13)? & 0x12 != 0x02 {
                    return None;
                }
            }
        }
        0x86dd => {
            let h = ip.get(..40)?;
            key.copy_from_slice(&h[8..24]);
            if syn_only && (h[6] != 6 || *ip.get(53)? & 0x12 != 0x02) {
                return None;
            }
        }
        _ => return None,
    }
    Some(key)
}

/// `xdp_rate_limit`: the XDP rate limiter, run by the interpreter on a sequence of frames.
/// `data[0]`: bit 0 = SYN-only, bits 1..: burst; `data[1]`: rate; then frames, each a length
/// byte, a clock step byte (ms) and the frame. The program must never fault, return only
/// `XDP_PASS`/`XDP_DROP`, count exactly the frames the reference parser counts, and drop only
/// counted frames.
pub fn xdp_rate_limit(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let syn_only = data[0] & 1 != 0;
    let burst = u64::from(data[0] >> 1) + 1;
    let rate = u64::from(data[1]) + 1;
    let cost = 1_000_000_000 / rate;
    let prog = ebpf::xdp_rate_limit(LimitProg {
        sources: 5,
        counters: 6,
        cost,
        cap: cost * burst,
        syn_only,
    });
    let mut vm = Vm::new();
    vm.add_map(5, SimMap::hash(16, 16, 8));
    vm.add_map(6, SimMap::hash(4, 8, ebpf::COUNTERS as usize));
    for c in 0..ebpf::COUNTERS {
        vm.update(6, &c.to_ne_bytes(), &0u64.to_ne_bytes())
            .expect("counter");
    }
    vm.now = 1 << 40;
    let mut rest = &data[2..];
    let mut tracked = 0usize;
    while rest.len() >= 2 {
        let (len, step) = (usize::from(rest[0]), u64::from(rest[1]));
        let frame = &rest[2..(2 + len).min(rest.len())];
        rest = &rest[(2 + len).min(rest.len())..];
        vm.now += step * 1_000_000;
        let (ret, _) = vm
            .run(&prog, frame)
            .unwrap_or_else(|e| panic!("XDP program: {e}"));
        assert!(ret == 1 || ret == 2, "verdict {ret}");
        match counted(frame, syn_only) {
            Some(key) => assert!(vm.lookup(5, &key).is_some(), "source not tracked"),
            None => assert_eq!(ret, 2, "an uncounted frame was dropped"),
        }
        let now_tracked = vm.entries(5);
        assert!(now_tracked >= tracked.min(8));
        tracked = now_tracked;
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

    /// Frames for `xdp_rate_limit`: IPv4/IPv6 SYNs and ACKs, UDP, a fragment, junk.
    fn xdp_seeds() -> Vec<Vec<u8>> {
        let eth = |t: u16| [&[0u8; 12][..], &t.to_be_bytes()].concat();
        let v4 = |proto: u8, flags: u8, frag: u8| {
            let mut f = eth(0x0800);
            f.extend([
                0x45, 0, 0, 40, 0, 0, frag, 0, 64, proto, 0, 0, 10, 1, 2, 3, 10, 0, 0, 1,
            ]);
            f.extend([
                0x30, 0x39, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff,
            ]);
            f.extend([0u8; 4]);
            f
        };
        let mut v6 = eth(0x86dd);
        v6.extend([0x60, 0, 0, 0, 0, 20, 6, 64]);
        v6.extend((0..32).map(|i| i as u8));
        v6.extend([
            0x30, 0x39, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        let frames = [
            v4(6, 0x02, 0),
            v4(6, 0x12, 0),
            v4(6, 0x10, 0),
            v4(17, 0, 0),
            v4(6, 0x02, 0x20),
            v6,
            eth(0x0806),
            vec![1, 2, 3],
        ];
        let mut out = Vec::new();
        for (head, steps) in [
            ([1u8, 0], [0u8, 0, 0]),
            ([8, 9], [0, 50, 200]),
            ([3, 255], [1, 1, 1]),
        ] {
            let mut d = head.to_vec();
            for (i, f) in frames.iter().enumerate() {
                for &st in &steps {
                    d.push(f.len() as u8);
                    d.push(st.wrapping_add(i as u8));
                    d.extend(f);
                }
            }
            out.push(d);
        }
        out
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "cbpf_steer", cbpf_steer) > 0);
        assert!(replay(DIR, "xdp_rate_limit", xdp_rate_limit) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            cbpf_steer(s);
        }
        for s in &xdp_seeds() {
            xdp_rate_limit(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p only-ebpf --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "cbpf_steer", &seeds());
        write_target_seeds(DIR, "xdp_rate_limit", &xdp_seeds());
    }
}
