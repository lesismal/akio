//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.
//!
//! The parser targets check that no input panics and that what parses also writes back to the
//! same fields; [`dpdk_stack`] feeds frames to a whole dual-stack userspace stack (a listener,
//! a UDP port, fragment reassembly, ARP and NDP), with time passing between frames.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use crate::net::{
    self, CcKind, Event, Iface, Params, Tx,
    frag::Reassembler,
    wire::{self, Arp, Eth, Icmp, Ipv4, Tcp, TcpOpts, Udp},
    wire6::{self, Icmp6, Ipv6, Nd},
};

const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SRC6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const DST6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

/// Splits `data` into length-prefixed frames (`u16` little endian; a truncated last one is
/// taken as it is).
pub fn frames(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let n = usize::from(u16::from_le_bytes([data[0], data[1]])).min(data.len() - 2);
        out.push(&data[2..2 + n]);
        data = &data[2 + n..];
    }
    out
}

/// Prefixes each frame with its length (the inverse of [`frames`]).
pub fn join(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    for f in frames {
        v.extend_from_slice(&(f.len().min(0xffff) as u16).to_le_bytes());
        v.extend_from_slice(&f[..f.len().min(0xffff)]);
    }
    v
}

/// `dpdk_ethernet`: an Ethernet frame through every parser it reaches.
pub fn dpdk_ethernet(data: &[u8]) {
    let Some(eth) = Eth::parse(data) else { return };
    match eth.ethertype {
        wire::ETHERTYPE_ARP => dpdk_arp(eth.payload),
        wire::ETHERTYPE_IPV4 => {
            for verify in [false, true] {
                let Some(ip) = Ipv4::parse(eth.payload, verify) else {
                    continue;
                };
                match ip.proto {
                    wire::PROTO_TCP => {
                        let _ = Tcp::parse(ip.payload, ip.src.into(), ip.dst.into(), verify);
                    }
                    wire::PROTO_UDP => {
                        let _ = Udp::parse(ip.payload, ip.src.into(), ip.dst.into(), verify);
                    }
                    wire::PROTO_ICMP => {
                        if let Some(m) = Icmp::parse(ip.payload, verify) {
                            let _ = m.quoted();
                        }
                    }
                    _ => {}
                }
            }
        }
        wire::ETHERTYPE_IPV6 => dpdk_ipv6(eth.payload),
        _ => {}
    }
}

/// `dpdk_arp`: an ARP packet; what parses writes back identically.
pub fn dpdk_arp(data: &[u8]) {
    if let Some(a) = Arp::parse(data) {
        let mut b = [0u8; wire::ARP_LEN];
        a.write(&mut b);
        assert_eq!(&b[..], &data[..wire::ARP_LEN]);
        assert_eq!(Arp::parse(&b), Some(a));
    }
}

/// `dpdk_ipv4`: an IPv4 packet (both checksum modes), and as a sequence of fragments through
/// the reassembler.
pub fn dpdk_ipv4(data: &[u8]) {
    let _ = Ipv4::parse(data, true);
    let mut r = Reassembler::default();
    let t0 = Instant::now();
    for (i, f) in frames(data).into_iter().enumerate() {
        let Some(ip) = Ipv4::parse(f, false) else {
            continue;
        };
        let now = t0 + Duration::from_secs(i as u64);
        if let Some(d) = r.add(
            ip.src.into(),
            ip.dst.into(),
            ip.proto,
            u32::from(ip.id),
            ip.frag_offset(),
            ip.more_fragments(),
            ip.payload,
            now,
        ) {
            assert!(d.payload.len() <= 65535);
        }
    }
}

/// `dpdk_ipv6`: an IPv6 packet: the fixed header, the extension-header chain (and, past a
/// fragment header, the rest of the chain), the upper layer; and the input as a sequence of
/// packets whose fragments go through the reassembler.
pub fn dpdk_ipv6(data: &[u8]) {
    ipv6_packet(data);
    let mut r = Reassembler::default();
    let t0 = Instant::now();
    for (i, f) in frames(data).into_iter().enumerate() {
        let Some(ip) = Ipv6::parse(f) else { continue };
        let Ok(up) = wire6::walk(ip.next, ip.payload, wire6::IPV6_HDR, true) else {
            continue;
        };
        assert!(up.offset <= ip.payload.len());
        let Some(fr) = up.frag else { continue };
        let now = t0 + Duration::from_secs(i as u64);
        let (src, dst) = (IpAddr::V6(ip.src), IpAddr::V6(ip.dst));
        let part = &ip.payload[fr.data..];
        if let Some(d) = r.add(src, dst, fr.next, fr.id, fr.offset, fr.more, part, now) {
            assert!(d.payload.len() <= 65535);
            let _ = wire6::walk(d.proto, &d.payload, wire6::IPV6_HDR, false);
        }
    }
}

fn ipv6_packet(data: &[u8]) {
    let Some(ip) = Ipv6::parse(data) else { return };
    assert!(ip.payload.len() + wire6::IPV6_HDR <= data.len());
    let Ok(up) = wire6::walk(ip.next, ip.payload, wire6::IPV6_HDR, true) else {
        return;
    };
    let (mut proto, mut upper) = (up.proto, &ip.payload[up.offset..]);
    if let Some(f) = up.frag {
        let rest = &ip.payload[f.data..];
        match wire6::walk(f.next, rest, wire6::IPV6_HDR + f.data, false) {
            Ok(u) => (proto, upper) = (u.proto, &rest[u.offset..]),
            Err(_) => return,
        }
    }
    let (src, dst) = (IpAddr::V6(ip.src), IpAddr::V6(ip.dst));
    match proto {
        wire::PROTO_TCP => {
            let _ = Tcp::parse(upper, src, dst, true);
        }
        wire::PROTO_UDP => {
            let _ = Udp::parse(upper, src, dst, true);
        }
        wire::PROTO_ICMPV6 => {
            if let Some(m) = Icmp6::parse(upper, ip.src, ip.dst, false) {
                let _ = m.quoted();
                let _ = Nd::parse(&m, ip.src, ip.dst, ip.hop_limit);
            }
        }
        _ => {}
    }
}

/// `dpdk_icmpv6`: an ICMPv6 message (from `SRC6` to `DST6`): checksum, the packet an error
/// quotes (through its extension headers), and neighbor discovery validation.
pub fn dpdk_icmpv6(data: &[u8]) {
    let _ = Icmp6::parse(data, SRC6, DST6, true);
    let Some(m) = Icmp6::parse(data, SRC6, DST6, false) else {
        return;
    };
    if let Some(q) = m.quoted() {
        assert!(q.src.is_ipv6() && q.dst.is_ipv6());
    }
    let _ = Nd::parse(&m, SRC6, DST6, 255);
}

/// `dpdk_ndp`: a neighbor solicitation or advertisement; what validates writes back to a
/// message that validates to the same fields. `data[0]` picks the destination (unicast,
/// solicited-node or all-nodes) and whether the source is unspecified.
pub fn dpdk_ndp(data: &[u8]) {
    let Some((&sel, msg)) = data.split_first() else {
        return;
    };
    let src = if sel & 4 != 0 {
        Ipv6Addr::UNSPECIFIED
    } else {
        SRC6
    };
    let target = msg
        .get(8..24)
        .and_then(|t| <[u8; 16]>::try_from(t).ok())
        .map_or(DST6, Ipv6Addr::from);
    let dst = match sel & 3 {
        0 => DST6,
        1 => wire6::solicited_node(target),
        _ => wire6::ALL_NODES,
    };
    let Some(m) = Icmp6::parse(msg, src, dst, false) else {
        return;
    };
    let Some(nd) = Nd::parse(&m, src, dst, 255) else {
        return;
    };
    let mut b = [0u8; wire6::ND_MSG];
    let len = if nd.kind == wire6::ND_NEIGHBOR_SOLICIT {
        wire6::write_ns(&mut b, src, dst, nd.target, nd.lla);
        if nd.lla.is_some() {
            wire6::ND_MSG
        } else {
            wire6::ND_LEN
        }
    } else {
        let Some(mac) = nd.lla else { return };
        wire6::write_na(&mut b, src, dst, nd.flags, nd.target, mac);
        wire6::ND_MSG
    };
    let back = Icmp6::parse(&b[..len], src, dst, true).expect("checksum written");
    assert_eq!(Nd::parse(&back, src, dst, 255), Some(nd));
}

/// `dpdk_tcp`: a TCP segment; its options write back to the same options.
pub fn dpdk_tcp(data: &[u8]) {
    let (src, dst) = (IpAddr::V4(SRC), IpAddr::V4(DST));
    let _ = Tcp::parse(data, src, dst, true);
    let Some(t) = Tcp::parse(data, src, dst, false) else {
        return;
    };
    let _ = t.seg_len();
    let o = t.opts;
    if o.len() <= 40 {
        let mut b = [0u8; 40];
        let n = o.write(&mut b);
        assert_eq!(n, o.len());
        let back = TcpOpts::parse(&b[..n]);
        assert_eq!(back.mss, o.mss);
        assert_eq!(back.wscale, o.wscale);
        assert_eq!(back.ts, o.ts);
        assert_eq!(back.sacks(), o.sacks());
    }
}

/// `dpdk_udp`: a UDP datagram.
pub fn dpdk_udp(data: &[u8]) {
    let (src, dst) = (IpAddr::V4(SRC), IpAddr::V4(DST));
    let _ = Udp::parse(data, src, dst, true);
    if let Some(u) = Udp::parse(data, src, dst, false) {
        assert!(u.payload.len() + wire::UDP_HDR <= data.len());
    }
}

/// `dpdk_icmp`: an ICMP message and the datagram an error quotes.
pub fn dpdk_icmp(data: &[u8]) {
    let _ = Icmp::parse(data, true);
    if let Some(m) = Icmp::parse(data, false) {
        let _ = m.quoted();
    }
}

/// Discards transmitted frames (but builds them, so the output path runs).
struct Sink(Vec<u8>, usize);

impl Tx for Sink {
    fn buffer(&mut self, len: usize) -> &mut [u8] {
        self.0.clear();
        self.0.resize(len, 0);
        &mut self.0
    }
    fn commit(&mut self) {
        self.1 += 1;
    }
}

fn stack(now: Instant) -> Iface {
    let p = Params {
        mss: 1460,
        rx_buf: 16 << 10,
        tx_buf: 16 << 10,
        cc: CcKind::Cubic,
        keepalive: Some(Duration::from_secs(5)),
        time_wait: Duration::from_secs(10),
        wscale: true,
        timestamps: true,
        sack: true,
        ecn: true,
        pacing: true,
    };
    let cfg = net::Config {
        mac: MAC,
        ip: DST,
        prefix_len: 24,
        gateway: Some(Ipv4Addr::new(10, 0, 0, 254)),
        ip6: Some(DST6),
        prefix_len6: 64,
        gateway6: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        mtu: 1500,
        tcp: p,
        backlog: 4,
        syn_cookies: true,
        udp_queue: 64 << 10,
        verify_checksums: false,
        queue: 0,
        queues: 2,
        dial_first: 49152,
        seed: Some(7),
    };
    let mut s = Iface::new(cfg, now);
    s.tcp_listen(80);
    s.udp_bind(53);
    s
}

/// `dpdk_stack`: length-prefixed Ethernet frames fed to a dual-stack stack with a TCP listener
/// on 80, a UDP port 53 and dialed connections over both families; TCP / UDP checksums are not
/// verified, so the fuzzer reaches the protocol logic. `data[0]`: bit 0 fixes up each frame's
/// destination MAC and IPv4 / IPv6 address to the stack's, the other bits the clock step
/// between frames.
pub fn dpdk_stack(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let t0 = Instant::now();
    let mut now = t0;
    let mut s = stack(now);
    let mut tx = Sink(Vec::new(), 0);
    let dialed = s
        .tcp_connect(50000, SocketAddr::new(SRC.into(), 80), now)
        .ok();
    let dialed6 = s
        .tcp_connect(50001, SocketAddr::new(SRC6.into(), 80), now)
        .ok();
    let mut events = Vec::new();
    let mut buf = vec![0u8; 4096];
    let step = Duration::from_millis(u64::from(cfg >> 1) * 37);
    for f in frames(rest) {
        let mut f = f.to_vec();
        if cfg & 1 != 0 && f.len() >= wire::ETH_HDR {
            f[..6].copy_from_slice(&MAC);
            if f.len() >= wire::ETH_HDR + 20 && f[12..14] == [0x08, 0x00] {
                f[wire::ETH_HDR + 16..wire::ETH_HDR + 20].copy_from_slice(&DST.octets());
            }
            if f.len() >= wire::ETH_HDR + 40 && f[12..14] == [0x86, 0xdd] {
                f[wire::ETH_HDR + 24..wire::ETH_HDR + 40].copy_from_slice(&DST6.octets());
            }
        }
        s.receive(now, &f, &mut tx);
        s.take_events(&mut events);
        for e in events.drain(..) {
            match e {
                Event::Accepted { h, .. } | Event::Readable(h) | Event::Connected(h) => {
                    while s.tcp_recv(h, &mut buf) > 0 {}
                    let _ = s.tcp_send(h, b"response data");
                    if s.tcp_eof(h) {
                        s.tcp_close(h, now);
                    }
                }
                _ => {}
            }
        }
        while s.udp_recv_ecn(&mut buf).is_some() {}
        let _ = s.take_forward();
        now += step;
        s.poll(now, &mut tx);
    }
    // Let every timer run out: retransmissions, keepalive, TIME-WAIT, reassembly expiry.
    for _ in 0..64 {
        match s.next_deadline() {
            Some(t) => now = now.max(t),
            None => break,
        }
        s.poll(now, &mut tx);
        s.take_events(&mut events);
        events.clear();
    }
    for h in [dialed, dialed6].into_iter().flatten() {
        s.tcp_abort(h, now, &mut tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        let n = replay(DIR, "dpdk_ethernet", dpdk_ethernet)
            + replay(DIR, "dpdk_arp", dpdk_arp)
            + replay(DIR, "dpdk_ipv4", dpdk_ipv4)
            + replay(DIR, "dpdk_tcp", dpdk_tcp)
            + replay(DIR, "dpdk_udp", dpdk_udp)
            + replay(DIR, "dpdk_icmp", dpdk_icmp)
            + replay(DIR, "dpdk_ipv6", dpdk_ipv6)
            + replay(DIR, "dpdk_icmpv6", dpdk_icmpv6)
            + replay(DIR, "dpdk_ndp", dpdk_ndp)
            + replay(DIR, "dpdk_stack", dpdk_stack);
        assert!(n > 0);
    }

    fn seeds() -> Vec<(&'static str, Vec<Vec<u8>>)> {
        let (ab, ba) = net::sim::capture();
        let (ab6, ba6) = net::sim::capture6();
        let all: Vec<Vec<u8>> = ab.iter().chain(&ba).cloned().collect();
        let all6: Vec<Vec<u8>> = ab6.iter().chain(&ba6).cloned().collect();
        let ipv6: Vec<Vec<u8>> = all6
            .iter()
            .filter_map(|f| Eth::parse(f))
            .filter(|e| e.ethertype == wire::ETHERTYPE_IPV6)
            .map(|e| e.payload.to_vec())
            .collect();
        // ICMPv6 messages (ND, echo, errors), rewritten as if from SRC6 to DST6 (the
        // checksum is not verified on the parse the target exercises beyond the first).
        let icmp6: Vec<Vec<u8>> = ipv6
            .iter()
            .filter_map(|p| Ipv6::parse(p))
            .filter(|ip| ip.next == wire::PROTO_ICMPV6)
            .map(|ip| ip.payload.to_vec())
            .collect();
        let nd: Vec<Vec<u8>> = ipv6
            .iter()
            .filter_map(|p| Ipv6::parse(p))
            .filter(|ip| ip.next == wire::PROTO_ICMPV6)
            .filter_map(|ip| {
                let m = Icmp6::parse(ip.payload, ip.src, ip.dst, true)?;
                let nd = Nd::parse(&m, ip.src, ip.dst, ip.hop_limit)?;
                // Re-target to what dpdk_ndp checks against.
                let mut b = [0u8; wire6::ND_MSG];
                let (sel, src) = if ip.src.is_unspecified() {
                    (4u8, Ipv6Addr::UNSPECIFIED)
                } else {
                    (0, SRC6)
                };
                let (sel, dst) = if ip.dst.is_multicast() && nd.kind == wire6::ND_NEIGHBOR_SOLICIT {
                    (sel | 1, wire6::solicited_node(nd.target))
                } else {
                    (sel, DST6)
                };
                if nd.kind == wire6::ND_NEIGHBOR_SOLICIT {
                    wire6::write_ns(&mut b, src, dst, nd.target, nd.lla);
                } else {
                    wire6::write_na(&mut b, src, dst, nd.flags, nd.target, nd.lla?);
                }
                Some([&[sel][..], &b[..]].concat())
            })
            .collect();
        let l3 = |p: u16| -> Vec<Vec<u8>> {
            all.iter()
                .filter_map(|f| Eth::parse(f))
                .filter(|e| e.ethertype == p)
                .map(|e| e.payload.to_vec())
                .collect()
        };
        let ipv4 = l3(wire::ETHERTYPE_IPV4);
        let l4 = |proto: u8| -> Vec<Vec<u8>> {
            ipv4.iter()
                .filter_map(|p| Ipv4::parse(p, false))
                .filter(|ip| ip.proto == proto && !ip.is_fragment())
                .map(|ip| ip.payload.to_vec())
                .collect()
        };
        let fragments: Vec<Vec<u8>> = ipv4
            .iter()
            .filter(|p| Ipv4::parse(p, false).is_some_and(|ip| ip.is_fragment()))
            .cloned()
            .collect();
        let mut stack_seeds = vec![
            [&[1u8][..], &join(&ba)].concat(),
            [&[3u8][..], &join(&ba[..ba.len().min(8)])].concat(),
        ];
        for chunk in ba.chunks(6) {
            stack_seeds.push([&[0x21u8][..], &join(chunk)].concat());
        }
        let mut icmp = l4(wire::PROTO_ICMP);
        icmp.truncate(8);
        stack_seeds.push([&[1u8][..], &join(&ba6)].concat());
        for chunk in ba6.chunks(6) {
            stack_seeds.push([&[0x21u8][..], &join(chunk)].concat());
        }
        let frag6: Vec<Vec<u8>> = ipv6
            .iter()
            .filter(|p| Ipv6::parse(p).is_some_and(|ip| ip.next == wire6::NH_FRAGMENT))
            .cloned()
            .collect();
        vec![
            ("dpdk_ethernet", all.iter().take(40).cloned().collect()),
            ("dpdk_arp", l3(wire::ETHERTYPE_ARP)),
            ("dpdk_ipv4", {
                let mut v: Vec<Vec<u8>> = ipv4.iter().take(10).cloned().collect();
                v.push(join(&fragments));
                v
            }),
            (
                "dpdk_tcp",
                l4(wire::PROTO_TCP).into_iter().take(30).collect(),
            ),
            ("dpdk_udp", l4(wire::PROTO_UDP)),
            ("dpdk_icmp", icmp),
            ("dpdk_stack", stack_seeds),
            ("dpdk_ipv6", {
                let mut v: Vec<Vec<u8>> = ipv6.iter().take(20).cloned().collect();
                v.push(join(&frag6));
                v.extend(net::sim::ext_header_packets());
                v
            }),
            ("dpdk_icmpv6", icmp6.into_iter().take(16).collect()),
            ("dpdk_ndp", nd),
        ]
    }

    #[test]
    fn seeds_run_clean() {
        for (target, seeds) in seeds() {
            assert!(!seeds.is_empty(), "{target}: no seeds");
            for s in &seeds {
                match target {
                    "dpdk_ethernet" => dpdk_ethernet(s),
                    "dpdk_arp" => dpdk_arp(s),
                    "dpdk_ipv4" => dpdk_ipv4(s),
                    "dpdk_tcp" => dpdk_tcp(s),
                    "dpdk_udp" => dpdk_udp(s),
                    "dpdk_icmp" => dpdk_icmp(s),
                    "dpdk_ipv6" => dpdk_ipv6(s),
                    "dpdk_icmpv6" => dpdk_icmpv6(s),
                    "dpdk_ndp" => dpdk_ndp(s),
                    _ => dpdk_stack(s),
                }
            }
        }
    }

    /// Regenerates the seed files: `cargo test -p only-dpdk --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        for (target, seeds) in seeds() {
            write_target_seeds(DIR, target, &seeds);
        }
    }
}
