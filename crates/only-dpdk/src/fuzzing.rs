//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.
//!
//! The parser targets check that no input panics and that what parses also writes back to the
//! same fields; [`dpdk_stack`] feeds frames to a whole userspace stack (a listener, a UDP port,
//! fragment reassembly, ARP), with time passing between frames.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use crate::net::{
    self, CcKind, Event, Iface, Params, Tx,
    frag::Reassembler,
    wire::{self, Arp, Eth, Icmp, Ipv4, Tcp, TcpOpts, Udp},
};

const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
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
                        let _ = Tcp::parse(ip.payload, ip.src, ip.dst, verify);
                    }
                    wire::PROTO_UDP => {
                        let _ = Udp::parse(ip.payload, ip.src, ip.dst, verify);
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
            ip.src,
            ip.dst,
            ip.proto,
            ip.id,
            ip.frag_offset(),
            ip.more_fragments(),
            ip.payload,
            now,
        ) {
            assert!(d.payload.len() <= 65535);
        }
    }
}

/// `dpdk_tcp`: a TCP segment; its options write back to the same options.
pub fn dpdk_tcp(data: &[u8]) {
    let _ = Tcp::parse(data, SRC, DST, true);
    let Some(t) = Tcp::parse(data, SRC, DST, false) else {
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
    let _ = Udp::parse(data, SRC, DST, true);
    if let Some(u) = Udp::parse(data, SRC, DST, false) {
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
    };
    let cfg = net::Config {
        mac: MAC,
        ip: DST,
        prefix_len: 24,
        gateway: Some(Ipv4Addr::new(10, 0, 0, 254)),
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

/// `dpdk_stack`: length-prefixed Ethernet frames fed to a stack with a TCP listener on 80, a
/// UDP port 53 and a dialed connection; checksums are not verified, so the fuzzer reaches the
/// protocol logic. `data[0]`: bit 0 fixes up each frame's destination MAC and IPv4 address to
/// the stack's, the other bits the clock step between frames.
pub fn dpdk_stack(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let t0 = Instant::now();
    let mut now = t0;
    let mut s = stack(now);
    let mut tx = Sink(Vec::new(), 0);
    let dialed = s.tcp_connect(50000, SocketAddrV4::new(SRC, 80), now).ok();
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
        while s.udp_recv(&mut buf).is_some() {}
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
    if let Some(h) = dialed {
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
            + replay(DIR, "dpdk_stack", dpdk_stack);
        assert!(n > 0);
    }

    fn seeds() -> Vec<(&'static str, Vec<Vec<u8>>)> {
        let (ab, ba) = net::sim::capture();
        let all: Vec<Vec<u8>> = ab.iter().chain(&ba).cloned().collect();
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
