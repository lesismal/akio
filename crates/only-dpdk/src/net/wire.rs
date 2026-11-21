//! Frame formats: parsing (bounds-checked views over received bytes) and writing (into a
//! caller-provided buffer) of Ethernet II, ARP, IPv4, ICMPv4, UDP and TCP, plus the Internet
//! checksum. UDP and TCP are carried over IPv4 or IPv6 (the pseudo-header follows the address
//! family); IPv6, ICMPv6 and NDP are in `wire6`. Parsers never panic on any input (fuzzed:
//! `fuzz/fuzz_targets/dpdk_*.rs`).

use std::net::{IpAddr, Ipv4Addr};

pub(crate) type Mac = [u8; 6];

pub(crate) const BROADCAST: Mac = [0xff; 6];
pub(crate) const ETH_HDR: usize = 14;
pub(crate) const ETHERTYPE_IPV4: u16 = 0x0800;
pub(crate) const ETHERTYPE_ARP: u16 = 0x0806;
pub(crate) const ETHERTYPE_IPV6: u16 = 0x86dd;
pub(crate) const IPV4_HDR: usize = 20;
pub(crate) const UDP_HDR: usize = 8;
pub(crate) const TCP_HDR: usize = 20;
pub(crate) const ICMP_HDR: usize = 8;
pub(crate) const ARP_LEN: usize = 28;

pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_ICMPV6: u8 = 58;

/// ECN codepoints (RFC 3168 5), the low two bits of the IPv4 TOS / IPv6 traffic class.
pub(crate) const ECN_MASK: u8 = 0x03;
pub(crate) const ECT0: u8 = 0x02;
pub(crate) const ECT1: u8 = 0x01;
pub(crate) const ECN_CE: u8 = 0x03;

pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

pub(crate) fn mac_at(b: &[u8], at: usize) -> Mac {
    let mut m = [0u8; 6];
    m.copy_from_slice(&b[at..at + 6]);
    m
}

// ---- checksum -------------------------------------------------------------------------------

/// Adds `data` to a running one's-complement sum (not yet folded). `data` is summed as
/// big-endian 16-bit words, a trailing odd byte padded with zero.
#[inline]
pub(crate) fn sum(data: &[u8], mut acc: u64) -> u64 {
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        acc += u64::from(u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
        acc += u64::from(u32::from_be_bytes([c[4], c[5], c[6], c[7]]));
    }
    let rest = chunks.remainder();
    let mut words = rest.chunks_exact(2);
    for w in &mut words {
        acc += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [b] = words.remainder() {
        acc += u64::from(u16::from_be_bytes([*b, 0]));
    }
    acc
}

/// Folds a running sum into the 16-bit one's-complement checksum field value.
#[inline]
pub(crate) fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The pseudo-header sum for an upper-layer checksum: IPv4 (RFC 793) or IPv6 (RFC 8200 8.1),
/// by the family of the addresses (mixed families never occur: both come from one packet).
#[inline]
pub(crate) fn pseudo(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u64 {
    Pseudo::of(src, dst).with(proto, len)
}

/// The address part of a pseudo-header sum, computed once per packet (an IPv4 pair is four
/// 16-bit words, without a dispatch on the address family per checksum).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pseudo(u64);

impl Pseudo {
    #[inline]
    pub(crate) fn of(src: IpAddr, dst: IpAddr) -> Pseudo {
        Pseudo(addr_sum(src) + addr_sum(dst))
    }

    #[inline]
    pub(crate) fn v4(src: Ipv4Addr, dst: Ipv4Addr) -> Pseudo {
        let (s, d) = (u32::from(src), u32::from(dst));
        Pseudo(
            u64::from(s >> 16) + u64::from(s & 0xffff) + u64::from(d >> 16) + u64::from(d & 0xffff),
        )
    }

    #[inline]
    pub(crate) fn with(self, proto: u8, len: usize) -> u64 {
        self.0 + u64::from(proto) + len as u64
    }
}

/// An address's 16-bit words, summed (an IPv4 address: its two words, without loading 16
/// bytes).
#[inline]
fn addr_sum(a: IpAddr) -> u64 {
    match a {
        IpAddr::V4(a) => {
            let x = u32::from(a);
            u64::from(x >> 16) + u64::from(x & 0xffff)
        }
        IpAddr::V6(a) => {
            let x = u128::from(a);
            let hi = (x >> 64) as u64;
            let lo = x as u64;
            let words = |w: u64| (w & 0xffff) + (w >> 16 & 0xffff) + (w >> 32 & 0xffff) + (w >> 48);
            words(hi) + words(lo)
        }
    }
}

/// Checksum of `data` (a header or a whole ICMP message).
pub(crate) fn checksum(data: &[u8]) -> u16 {
    fold(sum(data, 0))
}

// ---- Ethernet -------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Eth<'a> {
    pub(crate) dst: Mac,
    pub(crate) src: Mac,
    pub(crate) ethertype: u16,
    pub(crate) payload: &'a [u8],
}

impl Eth<'_> {
    pub(crate) fn parse(b: &[u8]) -> Option<Eth<'_>> {
        if b.len() < ETH_HDR {
            return None;
        }
        Some(Eth {
            dst: mac_at(b, 0),
            src: mac_at(b, 6),
            ethertype: be16(b, 12),
            payload: &b[ETH_HDR..],
        })
    }
}

pub(crate) fn write_eth(b: &mut [u8], dst: Mac, src: Mac, ethertype: u16) {
    b[0..6].copy_from_slice(&dst);
    b[6..12].copy_from_slice(&src);
    b[12..14].copy_from_slice(&ethertype.to_be_bytes());
}

// ---- ARP ------------------------------------------------------------------------------------

pub(crate) const ARP_REQUEST: u16 = 1;
pub(crate) const ARP_REPLY: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Arp {
    pub(crate) op: u16,
    pub(crate) sha: Mac,
    pub(crate) spa: Ipv4Addr,
    pub(crate) tha: Mac,
    pub(crate) tpa: Ipv4Addr,
}

impl Arp {
    /// Parses an Ethernet/IPv4 ARP packet; anything else is `None`.
    pub(crate) fn parse(b: &[u8]) -> Option<Arp> {
        if b.len() < ARP_LEN || be16(b, 0) != 1 || be16(b, 2) != ETHERTYPE_IPV4 {
            return None;
        }
        if b[4] != 6 || b[5] != 4 {
            return None;
        }
        Some(Arp {
            op: be16(b, 6),
            sha: mac_at(b, 8),
            spa: ip_at(b, 14),
            tha: mac_at(b, 18),
            tpa: ip_at(b, 24),
        })
    }

    pub(crate) fn write(&self, b: &mut [u8]) {
        b[0..2].copy_from_slice(&1u16.to_be_bytes());
        b[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        b[4] = 6;
        b[5] = 4;
        b[6..8].copy_from_slice(&self.op.to_be_bytes());
        b[8..14].copy_from_slice(&self.sha);
        b[14..18].copy_from_slice(&self.spa.octets());
        b[18..24].copy_from_slice(&self.tha);
        b[24..28].copy_from_slice(&self.tpa.octets());
    }
}

// ---- IPv4 -----------------------------------------------------------------------------------

pub(crate) const IP_DF: u16 = 0x4000;
pub(crate) const IP_MF: u16 = 0x2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ipv4<'a> {
    pub(crate) src: Ipv4Addr,
    pub(crate) dst: Ipv4Addr,
    pub(crate) proto: u8,
    pub(crate) ttl: u8,
    /// TOS byte (DSCP and ECN).
    pub(crate) tos: u8,
    pub(crate) id: u16,
    /// Flags (DF, MF) and the fragment offset in 8-byte units, as on the wire.
    pub(crate) frag: u16,
    pub(crate) hdr_len: usize,
    /// The whole header (options included), for ICMP errors quoting it.
    pub(crate) header: &'a [u8],
    /// The payload, trimmed to the total length (Ethernet padding removed).
    pub(crate) payload: &'a [u8],
}

impl Ipv4<'_> {
    /// Parses an IPv4 header; `verify` checks the header checksum.
    pub(crate) fn parse(b: &[u8], verify: bool) -> Option<Ipv4<'_>> {
        if b.len() < IPV4_HDR || b[0] >> 4 != 4 {
            return None;
        }
        let hdr_len = usize::from(b[0] & 0x0f) * 4;
        let total = usize::from(be16(b, 2));
        if hdr_len < IPV4_HDR || total < hdr_len || total > b.len() {
            return None;
        }
        if verify && checksum(&b[..hdr_len]) != 0 {
            return None;
        }
        Some(Ipv4 {
            src: ip_at(b, 12),
            dst: ip_at(b, 16),
            proto: b[9],
            ttl: b[8],
            tos: b[1],
            id: be16(b, 4),
            frag: be16(b, 6),
            hdr_len,
            header: &b[..hdr_len],
            payload: &b[hdr_len..total],
        })
    }

    /// More-fragments flag set or a non-zero offset.
    pub(crate) fn is_fragment(&self) -> bool {
        self.frag & (IP_MF | 0x1fff) != 0
    }

    pub(crate) fn frag_offset(&self) -> usize {
        usize::from(self.frag & 0x1fff) * 8
    }

    pub(crate) fn more_fragments(&self) -> bool {
        self.frag & IP_MF != 0
    }
}

/// Writes a 20-byte IPv4 header (no options) for a `payload_len`-byte payload; `tos` is the
/// whole TOS byte (DSCP and ECN).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_ipv4(
    b: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    frag: u16,
    ttl: u8,
    tos: u8,
    payload_len: usize,
) {
    b[0] = 0x45;
    b[1] = tos;
    let total = (IPV4_HDR + payload_len) as u16;
    b[2..4].copy_from_slice(&total.to_be_bytes());
    b[4..6].copy_from_slice(&id.to_be_bytes());
    b[6..8].copy_from_slice(&frag.to_be_bytes());
    b[8] = ttl;
    b[9] = proto;
    b[10..12].copy_from_slice(&[0, 0]);
    b[12..16].copy_from_slice(&src.octets());
    b[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&b[..IPV4_HDR]);
    b[10..12].copy_from_slice(&c.to_be_bytes());
}

// ---- ICMPv4 ---------------------------------------------------------------------------------

pub(crate) const ICMP_ECHO_REPLY: u8 = 0;
pub(crate) const ICMP_UNREACHABLE: u8 = 3;
pub(crate) const ICMP_ECHO_REQUEST: u8 = 8;
/// Destination-unreachable codes.
pub(crate) const UNREACH_NET: u8 = 0;
pub(crate) const UNREACH_HOST: u8 = 1;
pub(crate) const UNREACH_PROTO: u8 = 2;
pub(crate) const UNREACH_PORT: u8 = 3;
pub(crate) const UNREACH_FRAG_NEEDED: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Icmp<'a> {
    pub(crate) kind: u8,
    pub(crate) code: u8,
    /// Bytes 4..8 (echo id/sequence, next-hop MTU, ...).
    pub(crate) rest: [u8; 4],
    pub(crate) body: &'a [u8],
}

impl Icmp<'_> {
    pub(crate) fn parse(b: &[u8], verify: bool) -> Option<Icmp<'_>> {
        if b.len() < ICMP_HDR || (verify && checksum(b) != 0) {
            return None;
        }
        Some(Icmp {
            kind: b[0],
            code: b[1],
            rest: [b[4], b[5], b[6], b[7]],
            body: &b[ICMP_HDR..],
        })
    }

    /// For an error message (unreachable, time exceeded): the quoted datagram's addresses,
    /// protocol and first 8 bytes of its transport header (the ports).
    pub(crate) fn quoted(&self) -> Option<Quoted> {
        let b = self.body;
        if b.len() < IPV4_HDR || b[0] >> 4 != 4 {
            return None;
        }
        let hl = usize::from(b[0] & 0x0f) * 4;
        if hl < IPV4_HDR || b.len() < hl + 8 {
            return None;
        }
        Some(Quoted {
            src: IpAddr::V4(ip_at(b, 12)),
            dst: IpAddr::V4(ip_at(b, 16)),
            proto: b[9],
            src_port: be16(b, hl),
            dst_port: be16(b, hl + 2),
            seq: be32(b, hl + 4),
        })
    }
}

/// What an ICMP error quotes of the datagram that caused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Quoted {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) proto: u8,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    /// TCP: the sequence number of the quoted segment.
    pub(crate) seq: u32,
}

/// Writes an ICMP message: header (`kind`, `code`, `rest`) followed by `body`, checksummed.
/// `b` must be `ICMP_HDR + body.len()` bytes.
pub(crate) fn write_icmp(b: &mut [u8], kind: u8, code: u8, rest: [u8; 4], body: &[u8]) {
    b[0] = kind;
    b[1] = code;
    b[2..4].copy_from_slice(&[0, 0]);
    b[4..8].copy_from_slice(&rest);
    b[ICMP_HDR..ICMP_HDR + body.len()].copy_from_slice(body);
    let c = checksum(&b[..ICMP_HDR + body.len()]);
    b[2..4].copy_from_slice(&c.to_be_bytes());
}

// ---- UDP ------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Udp<'a> {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) payload: &'a [u8],
}

impl Udp<'_> {
    /// Parses a UDP datagram carried in an IP packet from `src` to `dst`; `verify` checks a
    /// non-zero checksum. Over IPv6 a zero checksum is invalid (RFC 8200 8.1) and refused.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn parse(b: &[u8], src: IpAddr, dst: IpAddr, verify: bool) -> Option<Udp<'_>> {
        Udp::parse_with(b, Pseudo::of(src, dst), src.is_ipv6(), verify)
    }

    /// [`Udp::parse`] with the pseudo-header's address sum already computed (`v6`: carried by
    /// IPv6, where a zero checksum is invalid).
    #[inline]
    pub(crate) fn parse_with(b: &[u8], ps: Pseudo, v6: bool, verify: bool) -> Option<Udp<'_>> {
        if b.len() < UDP_HDR {
            return None;
        }
        let len = usize::from(be16(b, 4));
        if len < UDP_HDR || len > b.len() {
            return None;
        }
        let b = &b[..len];
        if be16(b, 6) == 0 {
            if v6 {
                return None;
            }
        } else if verify && fold(sum(b, ps.with(PROTO_UDP, len))) != 0 {
            return None;
        }
        Some(Udp {
            src_port: be16(b, 0),
            dst_port: be16(b, 2),
            payload: &b[UDP_HDR..],
        })
    }
}

/// Writes a UDP header for `payload_len` bytes already at `b[UDP_HDR..]`, with its checksum.
pub(crate) fn write_udp(
    b: &mut [u8],
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
) {
    let len = UDP_HDR + payload_len;
    b[0..2].copy_from_slice(&src_port.to_be_bytes());
    b[2..4].copy_from_slice(&dst_port.to_be_bytes());
    b[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    b[6..8].copy_from_slice(&[0, 0]);
    let mut c = fold(sum(&b[..len], pseudo(src, dst, PROTO_UDP, len)));
    if c == 0 {
        c = 0xffff;
    }
    b[6..8].copy_from_slice(&c.to_be_bytes());
}

// ---- TCP ------------------------------------------------------------------------------------

pub(crate) const FIN: u8 = 0x01;
pub(crate) const SYN: u8 = 0x02;
pub(crate) const RST: u8 = 0x04;
pub(crate) const PSH: u8 = 0x08;
pub(crate) const ACK: u8 = 0x10;
/// ECN-Echo and Congestion Window Reduced (RFC 3168 6.1).
pub(crate) const ECE: u8 = 0x40;
pub(crate) const CWR: u8 = 0x80;

/// Most SACK blocks carried (4 without timestamps, 3 with).
pub(crate) const MAX_SACK: usize = 4;

/// AccECN option kinds (RFC 9768 3.2.3): order 0 carries EE0B, ECEB, EE1B; order 1 the
/// reverse.
pub(crate) const OPT_ACCECN0: u8 = 172;
pub(crate) const OPT_ACCECN1: u8 = 174;

/// An AccECN option: the first `n` (0 to 3) of its three 24-bit byte counters, in wire order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AccOpt {
    /// Order 1 (kind 174: EE1B, ECEB, EE0B) rather than order 0 (kind 172).
    pub(crate) order1: bool,
    pub(crate) n: u8,
    pub(crate) fields: [u32; 3],
}

impl AccOpt {
    /// An order-0 option with the low 24 bits of the first `n` of (e0b, ceb, e1b).
    pub(crate) fn order0(n: u8, e0b: u32, ceb: u32, e1b: u32) -> AccOpt {
        let n = n.min(3);
        let mut fields = [e0b & 0xff_ffff, ceb & 0xff_ffff, e1b & 0xff_ffff];
        fields[usize::from(n)..].fill(0); // what is not sent (parsing gives the same)
        AccOpt {
            order1: false,
            n,
            fields,
        }
    }

    fn field(&self, i: usize) -> Option<u32> {
        (i < usize::from(self.n)).then(|| self.fields[i])
    }

    /// EE0B: bytes received ECT(0), modulo 2^24.
    pub(crate) fn e0b(&self) -> Option<u32> {
        self.field(if self.order1 { 2 } else { 0 })
    }

    /// ECEB: bytes received CE, modulo 2^24.
    pub(crate) fn ceb(&self) -> Option<u32> {
        self.field(1)
    }

    /// EE1B: bytes received ECT(1), modulo 2^24.
    pub(crate) fn e1b(&self) -> Option<u32> {
        self.field(if self.order1 { 0 } else { 2 })
    }

    /// Option length (2 + 3 per field).
    fn wire_len(&self) -> usize {
        2 + 3 * usize::from(self.n)
    }

    /// Bytes on the wire, NOP-padded to 4.
    fn padded_len(&self) -> usize {
        (self.wire_len() + 3) & !3
    }
}

/// TCP options this stack understands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TcpOpts {
    pub(crate) mss: Option<u16>,
    pub(crate) wscale: Option<u8>,
    pub(crate) sack_perm: bool,
    /// (TSval, TSecr).
    pub(crate) ts: Option<(u32, u32)>,
    pub(crate) sack: [(u32, u32); MAX_SACK],
    pub(crate) sack_n: usize,
    /// AccECN option (RFC 9768).
    pub(crate) acc: Option<AccOpt>,
}

impl TcpOpts {
    pub(crate) fn sacks(&self) -> &[(u32, u32)] {
        &self.sack[..self.sack_n]
    }

    /// Parses the options area; malformed options end parsing (what was read so far is kept).
    pub(crate) fn parse(mut b: &[u8]) -> TcpOpts {
        let mut o = TcpOpts::default();
        while let Some(&kind) = b.first() {
            match kind {
                0 => break,
                1 => {
                    b = &b[1..];
                    continue;
                }
                _ => {}
            }
            let Some(&len) = b.get(1) else { break };
            let len = usize::from(len);
            if len < 2 || len > b.len() {
                break;
            }
            let v = &b[2..len];
            match (kind, v.len()) {
                (2, 2) => o.mss = Some(be16(v, 0)),
                (3, 1) => o.wscale = Some(v[0].min(14)),
                (4, 0) => o.sack_perm = true,
                (5, n) if n > 0 && n % 8 == 0 => {
                    for blk in v.chunks_exact(8).take(MAX_SACK) {
                        o.sack[o.sack_n] = (be32(blk, 0), be32(blk, 4));
                        o.sack_n += 1;
                    }
                }
                (8, 8) => o.ts = Some((be32(v, 0), be32(v, 4))),
                (OPT_ACCECN0 | OPT_ACCECN1, n) => {
                    // Whole 3-byte fields; the rest is padding (3.2.3, forward compatibility).
                    let n = (n / 3).min(3);
                    let mut f = [0u32; 3];
                    for (i, x) in f.iter_mut().enumerate().take(n) {
                        *x = u32::from_be_bytes([0, v[3 * i], v[3 * i + 1], v[3 * i + 2]]);
                    }
                    o.acc = Some(AccOpt {
                        order1: kind == OPT_ACCECN1,
                        n: n as u8,
                        fields: f,
                    });
                }
                _ => {}
            }
            b = &b[len..];
        }
        o
    }

    /// Bytes these options take on the wire (padded to 4).
    pub(crate) fn len(&self) -> usize {
        let mut n = 0;
        if self.mss.is_some() {
            n += 4;
        }
        if self.wscale.is_some() {
            n += 4; // NOP + 3
        }
        if self.ts.is_some() {
            n += 12; // NOP NOP + 10 (or SACK-permitted + 10)
        } else if self.sack_perm {
            n += 4; // NOP NOP + 2
        }
        if self.sack_n > 0 {
            n += 4 + 8 * self.sack_n; // NOP NOP + 2 + 8n
        }
        if let Some(a) = self.acc {
            n += a.padded_len();
        }
        n
    }

    /// Writes the options (exactly `self.len()` bytes).
    pub(crate) fn write(&self, b: &mut [u8]) -> usize {
        let mut i = 0;
        if let Some(mss) = self.mss {
            b[i..i + 4].copy_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
            i += 4;
        }
        if let Some(ws) = self.wscale {
            b[i..i + 4].copy_from_slice(&[1, 3, 3, ws]);
            i += 4;
        }
        match (self.ts, self.sack_perm) {
            (Some((val, ecr)), sp) => {
                if sp {
                    b[i..i + 2].copy_from_slice(&[4, 2]);
                } else {
                    b[i..i + 2].copy_from_slice(&[1, 1]);
                }
                b[i + 2] = 8;
                b[i + 3] = 10;
                b[i + 4..i + 8].copy_from_slice(&val.to_be_bytes());
                b[i + 8..i + 12].copy_from_slice(&ecr.to_be_bytes());
                i += 12;
            }
            (None, true) => {
                b[i..i + 4].copy_from_slice(&[1, 1, 4, 2]);
                i += 4;
            }
            (None, false) => {}
        }
        if self.sack_n > 0 {
            b[i..i + 4].copy_from_slice(&[1, 1, 5, (2 + 8 * self.sack_n) as u8]);
            i += 4;
            for &(l, r) in self.sacks() {
                b[i..i + 4].copy_from_slice(&l.to_be_bytes());
                b[i + 4..i + 8].copy_from_slice(&r.to_be_bytes());
                i += 8;
            }
        }
        if let Some(a) = self.acc {
            let pad = a.padded_len() - a.wire_len();
            b[i..i + pad].fill(1); // NOPs
            i += pad;
            b[i] = if a.order1 { OPT_ACCECN1 } else { OPT_ACCECN0 };
            b[i + 1] = a.wire_len() as u8;
            for k in 0..usize::from(a.n) {
                b[i + 2 + 3 * k..i + 5 + 3 * k].copy_from_slice(&a.fields[k].to_be_bytes()[1..]);
            }
            i += a.wire_len();
        }
        i
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tcp<'a> {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) window: u16,
    pub(crate) opts: TcpOpts,
    pub(crate) payload: &'a [u8],
    /// ECN codepoint of the IP packet that carried it (set by the interface).
    pub(crate) ecn: u8,
    /// The AE flag (RFC 9768: the former NS bit; with CWR and ECE the ACE field).
    pub(crate) ae: bool,
}

impl Tcp<'_> {
    /// Parses a TCP segment carried from `src` to `dst`; `verify` checks the checksum.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn parse(b: &[u8], src: IpAddr, dst: IpAddr, verify: bool) -> Option<Tcp<'_>> {
        Tcp::parse_with(b, Pseudo::of(src, dst), verify)
    }

    /// [`Tcp::parse`] with the pseudo-header's address sum already computed.
    #[inline]
    pub(crate) fn parse_with(b: &[u8], ps: Pseudo, verify: bool) -> Option<Tcp<'_>> {
        if b.len() < TCP_HDR {
            return None;
        }
        let off = usize::from(b[12] >> 4) * 4;
        if off < TCP_HDR || off > b.len() {
            return None;
        }
        if verify && fold(sum(b, ps.with(PROTO_TCP, b.len()))) != 0 {
            return None;
        }
        Some(Tcp {
            src_port: be16(b, 0),
            dst_port: be16(b, 2),
            seq: be32(b, 4),
            ack: be32(b, 8),
            flags: b[13],
            window: be16(b, 14),
            opts: TcpOpts::parse(&b[TCP_HDR..off]),
            payload: &b[off..],
            ecn: 0,
            ae: b[12] & 1 != 0,
        })
    }

    /// Sequence space the segment occupies (payload plus one for SYN and FIN each).
    pub(crate) fn seg_len(&self) -> u32 {
        self.payload.len() as u32
            + u32::from(self.flags & SYN != 0)
            + u32::from(self.flags & FIN != 0)
    }
}

/// The header fields of a segment to send.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TcpOut {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) window: u16,
    pub(crate) opts: TcpOpts,
    /// Send the segment ECN-capable (ECT(0) in the IP header).
    pub(crate) ect: bool,
    /// The AE flag (AccECN).
    pub(crate) ae: bool,
}

impl TcpOut {
    pub(crate) fn header_len(&self) -> usize {
        TCP_HDR + self.opts.len()
    }

    /// Writes the header into `b` (whose length is header + payload, the payload already in
    /// place after the header) and the checksum over everything.
    #[cfg(test)]
    pub(crate) fn write(&self, b: &mut [u8], src: IpAddr, dst: IpAddr) {
        self.write_with(b, Pseudo::of(src, dst));
    }

    /// [`TcpOut::write`] with the pseudo-header's address sum already computed.
    #[inline]
    pub(crate) fn write_with(&self, b: &mut [u8], ps: Pseudo) {
        let hl = self.header_len();
        b[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        b[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        b[4..8].copy_from_slice(&self.seq.to_be_bytes());
        b[8..12].copy_from_slice(&self.ack.to_be_bytes());
        b[12] = ((hl / 4) as u8) << 4 | u8::from(self.ae);
        b[13] = self.flags;
        b[14..16].copy_from_slice(&self.window.to_be_bytes());
        b[16..20].copy_from_slice(&[0, 0, 0, 0]);
        self.opts.write(&mut b[TCP_HDR..hl]);
        let c = fold(sum(b, ps.with(PROTO_TCP, b.len())));
        b[16..18].copy_from_slice(&c.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const B4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const A: IpAddr = IpAddr::V4(A4);
    const B: IpAddr = IpAddr::V4(B4);

    #[test]
    fn checksum_known_answer() {
        // RFC 1071's example words.
        let d = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(fold(sum(&d, 0)), !0xddf2);
        // A real IPv4 header (from a capture): its checksum verifies.
        let h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&h), 0);
        // Odd length.
        assert_eq!(fold(sum(&[0xab], 0)), !0xab00);
    }

    #[test]
    fn pseudo_header_sums_match_bytewise() {
        let addrs: [IpAddr; 4] = [
            A,
            IpAddr::V4(Ipv4Addr::new(255, 254, 1, 0)),
            "fd00::1:ffff:fe12:3456".parse().unwrap(),
            "ffff:fffe:fdfc:8000:1:2:3:ffff".parse().unwrap(),
        ];
        for a in addrs {
            let bytes = match a {
                IpAddr::V4(x) => sum(&x.octets(), 0),
                IpAddr::V6(x) => sum(&x.octets(), 0),
            };
            // `sum` adds 32-bit words: the accumulators differ, the folded checksums do not.
            assert_eq!(fold(addr_sum(a)), fold(bytes), "{a}");
            assert_eq!(fold(addr_sum(a) + 0x1234), fold(bytes + 0x1234), "{a}");
        }
    }

    #[test]
    fn arp_roundtrip() {
        let a = Arp {
            op: ARP_REQUEST,
            sha: [2, 0, 0, 0, 0, 1],
            spa: A4,
            tha: [0; 6],
            tpa: B4,
        };
        let mut b = [0u8; ARP_LEN];
        a.write(&mut b);
        assert_eq!(Arp::parse(&b), Some(a));
        assert_eq!(Arp::parse(&b[..27]), None);
    }

    #[test]
    fn ipv4_udp_roundtrip() {
        let mut b = vec![0u8; IPV4_HDR + UDP_HDR + 5];
        b[IPV4_HDR + UDP_HDR..].copy_from_slice(b"hello");
        write_udp(&mut b[IPV4_HDR..], A, B, 1000, 2000, 5);
        write_ipv4(&mut b, A4, B4, PROTO_UDP, 7, IP_DF, 64, ECT0, UDP_HDR + 5);
        let ip = Ipv4::parse(&b, true).unwrap();
        assert_eq!((ip.src, ip.dst, ip.proto, ip.id), (A4, B4, PROTO_UDP, 7));
        assert_eq!(ip.tos & ECN_MASK, ECT0);
        assert!(!ip.is_fragment());
        let u = Udp::parse(ip.payload, A, B, true).unwrap();
        assert_eq!(
            (u.src_port, u.dst_port, u.payload),
            (1000, 2000, &b"hello"[..])
        );
        // A flipped bit fails the checksums.
        let mut bad = b.clone();
        bad[IPV4_HDR + UDP_HDR] ^= 1;
        assert!(Udp::parse(&bad[IPV4_HDR..], A, B, true).is_none());
        bad[3] ^= 1;
        assert!(Ipv4::parse(&bad, true).is_none());
    }

    #[test]
    fn tcp_options_roundtrip() {
        let mut o = TcpOpts {
            mss: Some(1460),
            wscale: Some(7),
            sack_perm: true,
            ts: Some((123, 456)),
            ..TcpOpts::default()
        };
        o.sack[0] = (10, 20);
        o.sack[1] = (30, 40);
        o.sack_n = 2;
        let out = TcpOut {
            src_port: 1,
            dst_port: 2,
            seq: 3,
            ack: 4,
            flags: SYN | ACK,
            window: 5,
            opts: o,
            ect: false,
            ae: true,
        };
        let hl = out.header_len();
        assert_eq!(hl % 4, 0);
        let mut b = vec![0u8; hl + 3];
        b[hl..].copy_from_slice(b"abc");
        out.write(&mut b, A, B);
        let t = Tcp::parse(&b, A, B, true).unwrap();
        assert_eq!(t.opts, o);
        assert_eq!((t.seq, t.ack, t.flags, t.window), (3, 4, SYN | ACK, 5));
        assert!(t.ae);
        assert_eq!(t.payload, b"abc");
        assert_eq!(t.seg_len(), 4);
    }

    #[test]
    fn linux_syn_options() {
        // Options of a SYN from Linux 6.x: MSS 1460, SACK-permitted, timestamps, NOP, wscale 7.
        let opts = [
            2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
        ];
        let o = TcpOpts::parse(&opts);
        assert_eq!(o.mss, Some(1460));
        assert!(o.sack_perm);
        assert_eq!(o.ts, Some((1, 0)));
        assert_eq!(o.wscale, Some(7));
        // Truncated / malformed options never panic.
        for n in 0..opts.len() {
            let _ = TcpOpts::parse(&opts[..n]);
        }
        let _ = TcpOpts::parse(&[5, 1]);
        let _ = TcpOpts::parse(&[5, 255, 0]);
    }

    #[test]
    fn icmp_quote() {
        let mut dgram = vec![0u8; IPV4_HDR + UDP_HDR];
        write_udp(&mut dgram[IPV4_HDR..], A, B, 1111, 2222, 0);
        write_ipv4(&mut dgram, A4, B4, PROTO_UDP, 1, 0, 64, 0, UDP_HDR);
        let mut m = vec![0u8; ICMP_HDR + dgram.len()];
        write_icmp(&mut m, ICMP_UNREACHABLE, UNREACH_PORT, [0; 4], &dgram);
        let i = Icmp::parse(&m, true).unwrap();
        let q = i.quoted().unwrap();
        assert_eq!(
            (q.src, q.dst, q.proto, q.src_port, q.dst_port),
            (A, B, PROTO_UDP, 1111, 2222)
        );
    }
}
