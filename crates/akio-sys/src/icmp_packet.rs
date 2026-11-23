//! Parsing ICMP error messages about UDP datagrams, as an ICMP socket receives them (macOS:
//! IPv4 with the outer IP header, ICMPv6 without). Safe code only: the bytes come from the
//! network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// An ICMP error about a UDP datagram, read from an ICMP message ([`parse_icmp_error`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct IcmpPacket {
    /// Where the datagram that drew the error came from (a local socket's address and port).
    pub source: SocketAddr,
    /// Where it was going (address and port).
    pub dest: SocketAddr,
    /// An ICMPv6 message (else ICMPv4).
    pub v6: bool,
    /// The ICMP type: ICMPv4 3 (destination unreachable), 11 (time exceeded) or 12 (parameter
    /// problem); ICMPv6 1 (destination unreachable), 2 (packet too big), 3 (time exceeded) or 4
    /// (parameter problem).
    pub icmp_type: u8,
    /// The ICMP code.
    pub code: u8,
    /// The next-hop MTU of an ICMPv4 "fragmentation needed" (type 3, code 4) or an ICMPv6
    /// "packet too big", else 0.
    pub mtu: u32,
}

const UDP: u8 = 17;

/// Parses an ICMP error message about a UDP datagram: with `v6`, an ICMPv6 message (from its
/// ICMPv6 header on); else an IPv4 packet carrying an ICMPv4 message (from the outer IP header
/// on, as a BSD raw or ICMP socket delivers it). The quoted datagram must be UDP over IP of the
/// same version, with at least its ports quoted (RFC 792 / RFC 4443 quote at least that much);
/// IPv6 extension headers in the quoted packet are not followed. `None` for anything else:
/// other ICMP types (echo replies, redirects, ...), truncated or malformed messages.
pub fn parse_icmp_error(data: &[u8], v6: bool) -> Option<IcmpPacket> {
    if v6 { parse_v6(data) } else { parse_v4(data) }
}

/// The header length of the IPv4 packet starting at `p`, if it is one (version 4, a header of
/// 20 to 60 bytes that fits), and its protocol.
fn ipv4_header(p: &[u8]) -> Option<(usize, u8)> {
    let first = *p.first()?;
    let ihl = usize::from(first & 0x0f) * 4;
    (first >> 4 == 4 && ihl >= 20 && p.len() >= ihl).then(|| (ihl, p[9]))
}

fn port(p: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(at)?, *p.get(at + 1)?]))
}

fn parse_v4(data: &[u8]) -> Option<IcmpPacket> {
    let (outer, proto) = ipv4_header(data)?;
    if proto != 1 {
        return None;
    }
    let icmp = &data[outer..];
    if icmp.len() < 8 {
        return None;
    }
    let (icmp_type, code) = (icmp[0], icmp[1]);
    if !matches!(icmp_type, 3 | 11 | 12) {
        return None;
    }
    let mtu = if icmp_type == 3 && code == 4 {
        u32::from(u16::from_be_bytes([icmp[6], icmp[7]]))
    } else {
        0
    };
    let inner = &icmp[8..];
    let (ihl, proto) = ipv4_header(inner)?;
    if proto != UDP {
        return None;
    }
    let src = Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]);
    let dst = Ipv4Addr::new(inner[16], inner[17], inner[18], inner[19]);
    let (sport, dport) = (port(inner, ihl)?, port(inner, ihl + 2)?);
    Some(IcmpPacket {
        source: SocketAddr::new(IpAddr::V4(src), sport),
        dest: SocketAddr::new(IpAddr::V4(dst), dport),
        v6: false,
        icmp_type,
        code,
        mtu,
    })
}

fn parse_v6(icmp: &[u8]) -> Option<IcmpPacket> {
    if icmp.len() < 8 {
        return None;
    }
    let (icmp_type, code) = (icmp[0], icmp[1]);
    if !matches!(icmp_type, 1..=4) {
        return None;
    }
    let mtu = if icmp_type == 2 {
        u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]])
    } else {
        0
    };
    let inner = &icmp[8..];
    if inner.len() < 44 || inner[0] >> 4 != 6 || inner[6] != UDP {
        return None;
    }
    let addr = |at: usize| {
        let mut o = [0u8; 16];
        o.copy_from_slice(&inner[at..at + 16]);
        Ipv6Addr::from(o)
    };
    let (src, dst) = (addr(8), addr(24));
    let (sport, dport) = (port(inner, 40)?, port(inner, 42)?);
    Some(IcmpPacket {
        source: SocketAddr::new(IpAddr::V6(src), sport),
        dest: SocketAddr::new(IpAddr::V6(dst), dport),
        v6: true,
        icmp_type,
        code,
        mtu,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What macOS delivered for a datagram from 127.0.0.1:62292 to the closed port 9.
    const PORT_UNREACHABLE_V4: &str = "4500240030840000400100007f0000017f0000010303c7180000000045002100bf430000401100007f0000017f000001f3540009000d0000";
    /// And for one from [::1]:65397 to port 9 (the ICMPv6 socket gets no IPv6 header).
    const PORT_UNREACHABLE_V6: &str = "01043fd00000000060050a00000d11400000000000000000000000000000000100000000000000000000000000000001ff750009000d000068656c6c6f";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn port_unreachable_as_macos_delivers_it() {
        let p = parse_icmp_error(&hex(PORT_UNREACHABLE_V4), false).expect("v4");
        assert_eq!(p.source, "127.0.0.1:62292".parse().expect("addr"));
        assert_eq!(p.dest, "127.0.0.1:9".parse().expect("addr"));
        assert_eq!((p.v6, p.icmp_type, p.code, p.mtu), (false, 3, 3, 0));
        let p = parse_icmp_error(&hex(PORT_UNREACHABLE_V6), true).expect("v6");
        assert_eq!(p.source, "[::1]:65397".parse().expect("addr"));
        assert_eq!(p.dest, "[::1]:9".parse().expect("addr"));
        assert_eq!((p.v6, p.icmp_type, p.code, p.mtu), (true, 1, 4, 0));
    }

    #[test]
    fn mtu_of_too_big_messages() {
        let mut v4 = hex(PORT_UNREACHABLE_V4);
        v4[21] = 4; // code 4: fragmentation needed
        v4[26..28].copy_from_slice(&1400u16.to_be_bytes());
        assert_eq!(parse_icmp_error(&v4, false).expect("v4").mtu, 1400);
        let mut v6 = hex(PORT_UNREACHABLE_V6);
        v6[0] = 2; // packet too big
        v6[1] = 0;
        v6[4..8].copy_from_slice(&1280u32.to_be_bytes());
        let p = parse_icmp_error(&v6, true).expect("v6");
        assert_eq!((p.icmp_type, p.mtu), (2, 1280));
    }

    #[test]
    fn rejects_what_is_not_a_udp_error() {
        let v4 = hex(PORT_UNREACHABLE_V4);
        let v6 = hex(PORT_UNREACHABLE_V6);
        // Every truncation.
        for n in 0..v4.len() {
            if n < 52 {
                assert_eq!(parse_icmp_error(&v4[..n], false), None, "v4 cut at {n}");
            }
        }
        for n in 0..52 {
            assert_eq!(parse_icmp_error(&v6[..n], true), None, "v6 cut at {n}");
        }
        // An echo reply, a redirect; a quoted TCP segment; the wrong family.
        for (at, v) in [(20, 0u8), (20, 5), (37, 6)] {
            let mut m = v4.clone();
            m[at] = v;
            assert_eq!(parse_icmp_error(&m, false), None, "v4 byte {at} = {v}");
        }
        for (at, v) in [(0, 129u8), (0, 137), (14, 6), (8, 0x45)] {
            let mut m = v6.clone();
            m[at] = v;
            assert_eq!(parse_icmp_error(&m, true), None, "v6 byte {at} = {v}");
        }
        assert_eq!(parse_icmp_error(&v4, true), None);
        assert_eq!(parse_icmp_error(&v6, false), None);
        // An outer header length past the end.
        let mut m = v4;
        m[0] = 0x4f;
        assert_eq!(parse_icmp_error(&m[..50], false), None);
    }
}
