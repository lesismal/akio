//! IPv6 frame formats: the fixed header (RFC 8200 3) and the extension-header chain (hop-by-hop
//! and destination options, routing, fragment) walked with limits, ICMPv6 (RFC 4443), Neighbor
//! Discovery (RFC 4861: neighbor solicitation and advertisement with their link-layer address
//! options, router solicitation, router advertisements with their prefix-information, MTU and
//! link-layer options; the RFC 3971 nonce option of RFC 7527 duplicate address detection) and
//! MLDv2 reports (RFC 3810 5.2, so MLD-snooping switches forward our
//! solicited-node multicast). Like `wire`, parsers are bounds-checked views that never panic
//! (fuzzed: `dpdk_ipv6`, `dpdk_icmpv6`, `dpdk_ndp`).

use std::net::{IpAddr, Ipv6Addr};

use super::wire::{Mac, PROTO_ICMPV6, Quoted, be16, be32, fold, mac_at, pseudo, sum};

pub(crate) const IPV6_HDR: usize = 40;
pub(crate) const FRAG_HDR: usize = 8;
/// Smallest MTU every IPv6 link supports (RFC 8200 5).
pub(crate) const MIN_MTU: usize = 1280;

pub(crate) const NH_HOPOPT: u8 = 0;
pub(crate) const NH_ROUTING: u8 = 43;
pub(crate) const NH_FRAGMENT: u8 = 44;
pub(crate) const NH_NONE: u8 = 59;
pub(crate) const NH_DSTOPTS: u8 = 60;

/// Most extension headers walked before the packet is dropped (a long chain is either an
/// attack or nothing a host must accept, RFC 8504 5.3).
pub(crate) const MAX_EXT_HEADERS: usize = 8;
/// Most options in one hop-by-hop or destination options header.
const MAX_OPTIONS: usize = 16;

// ICMPv6 types (RFC 4443, RFC 4861, RFC 3810).
pub(crate) const ICMP6_UNREACHABLE: u8 = 1;
pub(crate) const ICMP6_PACKET_TOO_BIG: u8 = 2;
pub(crate) const ICMP6_PARAM_PROBLEM: u8 = 4;
pub(crate) const ICMP6_ECHO_REQUEST: u8 = 128;
pub(crate) const ICMP6_ECHO_REPLY: u8 = 129;
pub(crate) const MLD_QUERY: u8 = 130;
pub(crate) const MLD2_REPORT: u8 = 143;
pub(crate) const ND_ROUTER_SOLICIT: u8 = 133;
pub(crate) const ND_ROUTER_ADVERT: u8 = 134;
pub(crate) const ND_NEIGHBOR_SOLICIT: u8 = 135;
pub(crate) const ND_NEIGHBOR_ADVERT: u8 = 136;

/// Destination-unreachable codes.
pub(crate) const UNREACH6_NO_ROUTE: u8 = 0;
pub(crate) const UNREACH6_ADMIN: u8 = 1;
pub(crate) const UNREACH6_ADDR: u8 = 3;
pub(crate) const UNREACH6_PORT: u8 = 4;
/// Parameter-problem codes.
pub(crate) const PARAM_HEADER: u8 = 0;
pub(crate) const PARAM_NEXT_HEADER: u8 = 1;
pub(crate) const PARAM_OPTION: u8 = 2;

pub(crate) const ICMP6_HDR: usize = 8;
/// Neighbor solicitation / advertisement: ICMPv6 header + target address.
pub(crate) const ND_LEN: usize = ICMP6_HDR + 16;
/// A link-layer address option for Ethernet.
pub(crate) const LLA_OPT: usize = 8;
const OPT_SOURCE_LLA: u8 = 1;
const OPT_TARGET_LLA: u8 = 2;
const OPT_PREFIX_INFO: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_NONCE: u8 = 14;
/// A nonce option with a 6-byte nonce (RFC 3971 5.3.2, as RFC 7527 uses it).
pub(crate) const NONCE_OPT: usize = 8;
/// Most prefix-information options of one router advertisement that are looked at.
pub(crate) const MAX_RA_PREFIXES: usize = 8;

/// Neighbor advertisement flags (first byte of the reserved word).
pub(crate) const NA_ROUTER: u8 = 0x80;
pub(crate) const NA_SOLICITED: u8 = 0x40;
pub(crate) const NA_OVERRIDE: u8 = 0x20;

pub(crate) const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
pub(crate) const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
pub(crate) const ALL_MLDV2_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);

fn ip6_at(b: &[u8], at: usize) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&b[at..at + 16]);
    Ipv6Addr::from(o)
}

// ---- addresses ------------------------------------------------------------------------------

/// The solicited-node multicast address of `a` (RFC 4291 2.7.1): `ff02::1:ffXX:XXXX`.
pub(crate) fn solicited_node(a: Ipv6Addr) -> Ipv6Addr {
    let o = a.octets();
    Ipv6Addr::from([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, o[13], o[14], o[15],
    ])
}

/// The Ethernet multicast address an IPv6 multicast address maps to (RFC 2464 7):
/// `33:33` and the address's last 32 bits.
pub(crate) fn multicast_mac(a: Ipv6Addr) -> Mac {
    let o = a.octets();
    [0x33, 0x33, o[12], o[13], o[14], o[15]]
}

/// The link-local address of an interface with MAC `mac` (RFC 4291 2.5.6 / RFC 2464 4,
/// modified EUI-64): `fe80::` + the MAC with the universal/local bit flipped and `ff:fe` in the
/// middle.
pub(crate) fn link_local(mac: Mac) -> Ipv6Addr {
    Ipv6Addr::from([
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ])
}

/// `fe80::/10`.
pub(crate) fn is_link_local(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

// ---- IPv6 header ----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ipv6<'a> {
    pub(crate) src: Ipv6Addr,
    pub(crate) dst: Ipv6Addr,
    /// Traffic class (DSCP and ECN).
    pub(crate) tclass: u8,
    pub(crate) hop_limit: u8,
    /// The fixed header's Next Header.
    pub(crate) next: u8,
    /// The fixed header, for ICMPv6 errors quoting it.
    pub(crate) header: &'a [u8],
    /// Everything after the fixed header, trimmed to the payload length (Ethernet padding
    /// removed).
    pub(crate) payload: &'a [u8],
}

impl Ipv6<'_> {
    /// Parses the fixed header. Jumbograms (payload length 0 with a hop-by-hop jumbo option,
    /// RFC 2675) are not supported: a zero payload length is taken literally.
    pub(crate) fn parse(b: &[u8]) -> Option<Ipv6<'_>> {
        if b.len() < IPV6_HDR || b[0] >> 4 != 6 {
            return None;
        }
        let len = usize::from(be16(b, 4));
        if IPV6_HDR + len > b.len() {
            return None;
        }
        Some(Ipv6 {
            src: ip6_at(b, 8),
            dst: ip6_at(b, 24),
            tclass: (b[0] << 4) | (b[1] >> 4),
            hop_limit: b[7],
            next: b[6],
            header: &b[..IPV6_HDR],
            payload: &b[IPV6_HDR..IPV6_HDR + len],
        })
    }
}

/// Writes a 40-byte IPv6 header (flow label 0) for a `payload_len`-byte payload.
pub(crate) fn write_ipv6(
    b: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next: u8,
    hop_limit: u8,
    tclass: u8,
    payload_len: usize,
) {
    b[0] = 0x60 | (tclass >> 4);
    b[1] = tclass << 4;
    b[2] = 0;
    b[3] = 0;
    b[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    b[6] = next;
    b[7] = hop_limit;
    b[8..24].copy_from_slice(&src.octets());
    b[24..40].copy_from_slice(&dst.octets());
}

/// Writes a fragment header: `offset` bytes into the fragmentable part (a multiple of 8),
/// `more` = the M flag.
pub(crate) fn write_frag(b: &mut [u8], next: u8, offset: usize, more: bool, id: u32) {
    b[0] = next;
    b[1] = 0;
    let off = ((offset as u16) & !7) | u16::from(more);
    b[2..4].copy_from_slice(&off.to_be_bytes());
    b[4..8].copy_from_slice(&id.to_be_bytes());
}

// ---- extension headers ----------------------------------------------------------------------

/// A fragment header found in the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Frag {
    pub(crate) id: u32,
    /// Byte offset of this fragment's data in the fragmentable part.
    pub(crate) offset: usize,
    pub(crate) more: bool,
    /// Next Header of the fragment header (meaningful in the first fragment).
    pub(crate) next: u8,
    /// Where the fragment's data starts (offset into the walked bytes).
    pub(crate) data: usize,
}

/// The end of the extension-header chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Upper {
    /// The upper-layer protocol (or the fragment header's next header when `frag` is set).
    pub(crate) proto: u8,
    /// Where the upper-layer data starts (offset into the walked bytes).
    pub(crate) offset: usize,
    /// Offset of the Next Header field naming `proto`, counted from the start of the IPv6
    /// header (the pointer of a "next header unrecognized" parameter problem).
    pub(crate) nh_field: usize,
    /// The chain reached a fragment header (`offset`/`proto` describe what follows it).
    pub(crate) frag: Option<Frag>,
}

/// Why a chain was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtError {
    /// Drop silently.
    Drop,
    /// Drop and answer with an ICMPv6 parameter problem (`code`, `pointer` from the start of
    /// the IPv6 header) — unless the destination was multicast and `always` is false.
    Problem {
        code: u8,
        pointer: usize,
        always: bool,
    },
}

/// Walks the extension headers of `b` (the bytes after the fixed header, or a reassembled
/// fragmentable part) starting with Next Header `next`. `base` is where `b` starts relative to
/// the IPv6 header (40 for a received packet), for parameter-problem pointers; `first` is true
/// when `b` follows the fixed header directly (only there may hop-by-hop options appear).
///
/// Stops at the first upper-layer header, at a fragment header (returned in `frag`, the caller
/// reassembles and walks the rest), or at No Next Header (dropped). Unknown options are
/// handled by their action bits (RFC 8200 4.2); a routing header with segments left is
/// refused (we are a host, not a router: RFC 8200 4.4).
pub(crate) fn walk(mut next: u8, b: &[u8], base: usize, first: bool) -> Result<Upper, ExtError> {
    let mut off = 0usize;
    let mut nh_field = if first { 6 } else { base.saturating_sub(8) };
    for i in 0..=MAX_EXT_HEADERS {
        match next {
            NH_HOPOPT | NH_DSTOPTS | NH_ROUTING => {
                if next == NH_HOPOPT && !(first && i == 0) {
                    return Err(ExtError::Problem {
                        code: PARAM_NEXT_HEADER,
                        pointer: nh_field,
                        always: false,
                    });
                }
                if i == MAX_EXT_HEADERS || b.len() < off + 8 {
                    return Err(ExtError::Drop);
                }
                let len = (usize::from(b[off + 1]) + 1) * 8;
                if b.len() < off + len {
                    return Err(ExtError::Drop);
                }
                let h = &b[off..off + len];
                if next == NH_ROUTING {
                    if h[3] != 0 {
                        return Err(ExtError::Problem {
                            code: PARAM_HEADER,
                            pointer: base + off + 3,
                            always: false,
                        });
                    }
                } else {
                    options(&h[2..], base + off + 2)?;
                }
                nh_field = base + off;
                next = h[0];
                off += len;
            }
            NH_FRAGMENT => {
                if i == MAX_EXT_HEADERS || b.len() < off + FRAG_HDR {
                    return Err(ExtError::Drop);
                }
                let h = &b[off..off + FRAG_HDR];
                let fo = be16(h, 2);
                let frag = Frag {
                    id: be32(h, 4),
                    offset: usize::from(fo & !7),
                    more: fo & 1 != 0,
                    next: h[0],
                    data: off + FRAG_HDR,
                };
                return Ok(Upper {
                    proto: h[0],
                    offset: off + FRAG_HDR,
                    nh_field: base + off,
                    frag: Some(frag),
                });
            }
            NH_NONE => return Err(ExtError::Drop),
            proto => {
                return Ok(Upper {
                    proto,
                    offset: off,
                    nh_field,
                    frag: None,
                });
            }
        }
    }
    Err(ExtError::Drop)
}

/// The TLV options of a hop-by-hop or destination options header (`b` after its first two
/// bytes; `at` is `b`'s offset from the IPv6 header).
fn options(b: &[u8], at: usize) -> Result<(), ExtError> {
    let mut i = 0;
    let mut n = 0;
    while i < b.len() {
        let kind = b[i];
        if kind == 0 {
            i += 1; // Pad1
            continue;
        }
        n += 1;
        if n > MAX_OPTIONS || i + 2 > b.len() {
            return Err(ExtError::Drop);
        }
        let len = usize::from(b[i + 1]);
        if i + 2 + len > b.len() {
            return Err(ExtError::Drop);
        }
        match kind {
            1 => {}    // PadN
            0x05 => {} // Router Alert (RFC 2711): for routers; a host ignores it
            _ => match kind >> 6 {
                0 => {}
                1 => return Err(ExtError::Drop),
                a => {
                    return Err(ExtError::Problem {
                        code: PARAM_OPTION,
                        pointer: at + i,
                        always: a == 2,
                    });
                }
            },
        }
        i += 2 + len;
    }
    Ok(())
}

// ---- ICMPv6 ---------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Icmp6<'a> {
    pub(crate) kind: u8,
    pub(crate) code: u8,
    /// Bytes 4..8 (echo id/sequence, MTU, pointer, NA flags, ...).
    pub(crate) rest: [u8; 4],
    pub(crate) body: &'a [u8],
}

impl Icmp6<'_> {
    /// Parses an ICMPv6 message from `src` to `dst`; `verify` checks the checksum (which
    /// covers the IPv6 pseudo-header).
    pub(crate) fn parse(b: &[u8], src: Ipv6Addr, dst: Ipv6Addr, verify: bool) -> Option<Icmp6<'_>> {
        if b.len() < ICMP6_HDR {
            return None;
        }
        if verify
            && fold(sum(
                b,
                pseudo(IpAddr::V6(src), IpAddr::V6(dst), PROTO_ICMPV6, b.len()),
            )) != 0
        {
            return None;
        }
        Some(Icmp6 {
            kind: b[0],
            code: b[1],
            rest: [b[4], b[5], b[6], b[7]],
            body: &b[ICMP6_HDR..],
        })
    }

    /// For an error message: the quoted packet's addresses, upper-layer protocol and ports
    /// (extension headers skipped; a non-first fragment quotes no ports and gives `None`).
    pub(crate) fn quoted(&self) -> Option<Quoted> {
        let ip = Ipv6::parse_quoted(self.body)?;
        let up = walk(ip.next, ip.payload, IPV6_HDR, true).ok()?;
        if up.frag.is_some_and(|f| f.offset != 0) {
            return None;
        }
        let t = ip.payload.get(up.offset..)?;
        if t.len() < 8 {
            return None;
        }
        Some(Quoted {
            src: IpAddr::V6(ip.src),
            dst: IpAddr::V6(ip.dst),
            proto: up.proto,
            src_port: be16(t, 0),
            dst_port: be16(t, 2),
            seq: be32(t, 4),
        })
    }
}

impl Ipv6<'_> {
    /// A quoted header: the payload is whatever was quoted (the payload length field is not
    /// checked against it, the quote is usually truncated).
    fn parse_quoted(b: &[u8]) -> Option<Ipv6<'_>> {
        if b.len() < IPV6_HDR || b[0] >> 4 != 6 {
            return None;
        }
        let len = usize::from(be16(b, 4)).min(b.len() - IPV6_HDR);
        Some(Ipv6 {
            src: ip6_at(b, 8),
            dst: ip6_at(b, 24),
            tclass: (b[0] << 4) | (b[1] >> 4),
            hop_limit: b[7],
            next: b[6],
            header: &b[..IPV6_HDR],
            payload: &b[IPV6_HDR..IPV6_HDR + len],
        })
    }
}

/// Fills in the checksum of the ICMPv6 message `b` (its checksum field is overwritten).
pub(crate) fn icmp6_checksum(b: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr) {
    b[2] = 0;
    b[3] = 0;
    let c = fold(sum(
        b,
        pseudo(IpAddr::V6(src), IpAddr::V6(dst), PROTO_ICMPV6, b.len()),
    ));
    b[2..4].copy_from_slice(&c.to_be_bytes());
}

/// Writes an ICMPv6 message: header (`kind`, `code`, `rest`) followed by `body`, checksummed.
/// `b` must be `ICMP6_HDR + body.len()` bytes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_icmp6(
    b: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    kind: u8,
    code: u8,
    rest: [u8; 4],
    body: &[u8],
) {
    b[0] = kind;
    b[1] = code;
    b[4..8].copy_from_slice(&rest);
    b[ICMP6_HDR..ICMP6_HDR + body.len()].copy_from_slice(body);
    icmp6_checksum(&mut b[..ICMP6_HDR + body.len()], src, dst);
}

// ---- Neighbor Discovery ---------------------------------------------------------------------

/// A neighbor solicitation or advertisement (RFC 4861 4.3 / 4.4), validated per 7.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nd {
    /// `ND_NEIGHBOR_SOLICIT` or `ND_NEIGHBOR_ADVERT`.
    pub(crate) kind: u8,
    /// NA flags (`NA_*`); 0 for a solicitation.
    pub(crate) flags: u8,
    pub(crate) target: Ipv6Addr,
    /// Source (NS) or target (NA) link-layer address option.
    pub(crate) lla: Option<Mac>,
    /// Nonce option (a duplicate address detection probe, RFC 7527).
    pub(crate) nonce: Option<[u8; 6]>,
}

impl Nd {
    /// Validates a neighbor solicitation / advertisement received from `src` to `dst` with
    /// `hop_limit` (`m` is the parsed, checksum-verified ICMPv6 message).
    pub(crate) fn parse(m: &Icmp6<'_>, src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8) -> Option<Nd> {
        if !(m.kind == ND_NEIGHBOR_SOLICIT || m.kind == ND_NEIGHBOR_ADVERT)
            || hop_limit != 255
            || m.code != 0
            || m.body.len() < 16
        {
            return None;
        }
        let target = ip6_at(m.body, 0);
        if target.is_multicast() {
            return None;
        }
        let mut lla = None;
        let mut nonce = None;
        let mut o = &m.body[16..];
        let want = if m.kind == ND_NEIGHBOR_SOLICIT {
            OPT_SOURCE_LLA
        } else {
            OPT_TARGET_LLA
        };
        while !o.is_empty() {
            if o.len() < 2 {
                return None;
            }
            let len = usize::from(o[1]) * 8;
            if len == 0 || len > o.len() {
                return None; // 7.1.1: every option has a non-zero length
            }
            if o[0] == want && len == LLA_OPT {
                lla = Some(mac_at(o, 2));
            }
            if o[0] == OPT_NONCE && len == NONCE_OPT {
                let mut n = [0u8; 6];
                n.copy_from_slice(&o[2..8]);
                nonce = Some(n);
            }
            o = &o[len..];
        }
        let flags = if m.kind == ND_NEIGHBOR_ADVERT {
            m.rest[0] & (NA_ROUTER | NA_SOLICITED | NA_OVERRIDE)
        } else {
            0
        };
        if m.kind == ND_NEIGHBOR_SOLICIT && src.is_unspecified() {
            // Duplicate address detection: to the solicited-node address, no source LLA.
            if dst != solicited_node(target) || lla.is_some() {
                return None;
            }
        }
        if m.kind == ND_NEIGHBOR_ADVERT && dst.is_multicast() && flags & NA_SOLICITED != 0 {
            return None;
        }
        Some(Nd {
            kind: m.kind,
            flags,
            target,
            lla,
            nonce,
        })
    }
}

/// Length of a neighbor solicitation / advertisement with a link-layer address option.
pub(crate) const ND_MSG: usize = ND_LEN + LLA_OPT;

/// Writes a neighbor solicitation for `target` with our link-layer address `mac` (omitted when
/// `mac` is `None`), from `src` to `dst`. `b` is `ND_LEN` (+ `LLA_OPT` with a MAC) bytes.
pub(crate) fn write_ns(
    b: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    target: Ipv6Addr,
    mac: Option<Mac>,
) {
    write_nd(
        b,
        src,
        dst,
        ND_NEIGHBOR_SOLICIT,
        0,
        target,
        OPT_SOURCE_LLA,
        mac,
    );
}

/// Writes a neighbor advertisement for `target` (flags `NA_*`) carrying `mac` as the target
/// link-layer address.
pub(crate) fn write_na(
    b: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    flags: u8,
    target: Ipv6Addr,
    mac: Mac,
) {
    write_nd(
        b,
        src,
        dst,
        ND_NEIGHBOR_ADVERT,
        flags,
        target,
        OPT_TARGET_LLA,
        Some(mac),
    );
}

#[allow(clippy::too_many_arguments)]
fn write_nd(
    b: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    kind: u8,
    flags: u8,
    target: Ipv6Addr,
    opt: u8,
    mac: Option<Mac>,
) {
    b[0] = kind;
    b[1] = 0;
    b[4..8].copy_from_slice(&[flags, 0, 0, 0]);
    b[8..24].copy_from_slice(&target.octets());
    let len = if let Some(m) = mac {
        b[24] = opt;
        b[25] = 1;
        b[26..32].copy_from_slice(&m);
        ND_MSG
    } else {
        ND_LEN
    };
    icmp6_checksum(&mut b[..len], src, dst);
}

/// Length of a duplicate address detection probe: a neighbor solicitation with a nonce option.
pub(crate) const DAD_NS: usize = ND_LEN + NONCE_OPT;

/// Writes a duplicate address detection probe for `target` (RFC 4862 5.4.2): from the
/// unspecified address to `target`'s solicited-node group, no link-layer option, with `nonce`
/// (RFC 7527: our own probe looped back is recognised by it). `b` is `DAD_NS` bytes.
pub(crate) fn write_dad_ns(b: &mut [u8], target: Ipv6Addr, nonce: [u8; 6]) {
    b[0] = ND_NEIGHBOR_SOLICIT;
    b[1] = 0;
    b[4..8].copy_from_slice(&[0; 4]);
    b[8..24].copy_from_slice(&target.octets());
    b[24] = OPT_NONCE;
    b[25] = 1;
    b[26..32].copy_from_slice(&nonce);
    icmp6_checksum(
        &mut b[..DAD_NS],
        Ipv6Addr::UNSPECIFIED,
        solicited_node(target),
    );
}

/// Length of a router solicitation, with a source link-layer option when `lla`.
pub(crate) fn rs_len(lla: bool) -> usize {
    ICMP6_HDR + if lla { LLA_OPT } else { 0 }
}

/// Writes a router solicitation (RFC 4861 4.1) from `src` to all-routers; the source
/// link-layer option is included when `mac` is given (never from the unspecified address).
/// `b` is `rs_len(mac.is_some())` bytes.
pub(crate) fn write_rs(b: &mut [u8], src: Ipv6Addr, mac: Option<Mac>) {
    b[0] = ND_ROUTER_SOLICIT;
    b[1] = 0;
    b[4..8].copy_from_slice(&[0; 4]);
    let mut len = ICMP6_HDR;
    if let Some(m) = mac {
        b[8] = OPT_SOURCE_LLA;
        b[9] = 1;
        b[10..16].copy_from_slice(&m);
        len += LLA_OPT;
    }
    icmp6_checksum(&mut b[..len], src, ALL_ROUTERS);
}

/// A prefix-information option (RFC 4861 4.6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrefixInfo {
    pub(crate) prefix: Ipv6Addr,
    pub(crate) len: u8,
    /// L: the prefix is on the link.
    pub(crate) on_link: bool,
    /// A: addresses may be formed from it (SLAAC).
    pub(crate) autonomous: bool,
    /// Seconds; `u32::MAX` is infinite.
    pub(crate) valid: u32,
    pub(crate) preferred: u32,
}

/// A router advertisement (RFC 4861 4.2), validated per 6.1.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ra {
    /// Hop limit for our packets (0: unspecified).
    pub(crate) hop_limit: u8,
    /// Seconds the router is a default router (0: it is not).
    pub(crate) lifetime: u16,
    /// Source link-layer address option.
    pub(crate) lla: Option<Mac>,
    /// MTU option.
    pub(crate) mtu: Option<u32>,
    /// The first `MAX_RA_PREFIXES` prefix-information options.
    pub(crate) prefixes: [Option<PrefixInfo>; MAX_RA_PREFIXES],
}

impl Ra {
    /// Validates a router advertisement received from `src` with `hop_limit` (`m` is the
    /// parsed, checksum-verified ICMPv6 message): from a link-local address, hop limit 255,
    /// code 0, at least 16 bytes, every option of non-zero length.
    pub(crate) fn parse(m: &Icmp6<'_>, src: Ipv6Addr, hop_limit: u8) -> Option<Ra> {
        if m.kind != ND_ROUTER_ADVERT
            || hop_limit != 255
            || m.code != 0
            || !is_link_local(src)
            || m.body.len() < 8
        {
            return None;
        }
        let mut ra = Ra {
            hop_limit: m.rest[0],
            lifetime: u16::from_be_bytes([m.rest[2], m.rest[3]]),
            lla: None,
            mtu: None,
            prefixes: [None; MAX_RA_PREFIXES],
        };
        let mut n = 0;
        let mut o = &m.body[8..];
        while !o.is_empty() {
            if o.len() < 2 {
                return None;
            }
            let len = usize::from(o[1]) * 8;
            if len == 0 || len > o.len() {
                return None;
            }
            match (o[0], len) {
                (OPT_SOURCE_LLA, LLA_OPT) => ra.lla = Some(mac_at(o, 2)),
                (OPT_MTU, 8) => ra.mtu = Some(be32(o, 4)),
                (OPT_PREFIX_INFO, 32) if n < MAX_RA_PREFIXES => {
                    ra.prefixes[n] = Some(PrefixInfo {
                        prefix: ip6_at(o, 16),
                        len: o[2],
                        on_link: o[3] & 0x80 != 0,
                        autonomous: o[3] & 0x40 != 0,
                        valid: be32(o, 4),
                        preferred: be32(o, 8),
                    });
                    n += 1;
                }
                _ => {}
            }
            o = &o[len..];
        }
        Some(ra)
    }
}

// ---- MLDv2 ----------------------------------------------------------------------------------

/// Hop-by-hop options header with a Router Alert (MLD) and padding: 8 bytes.
pub(crate) const HBH_ROUTER_ALERT: [u8; 8] = [PROTO_ICMPV6, 0, 0x05, 0x02, 0, 0, 0x01, 0x00];

/// Bytes of an MLDv2 report joining `groups` (ICMPv6 part only).
pub(crate) fn mld2_report_len(groups: usize) -> usize {
    ICMP6_HDR + groups * 20
}

/// Writes an MLDv2 report (RFC 3810 5.2) with one `CHANGE_TO_EXCLUDE_MODE` record (exclude
/// nothing: join) per group. `b` is `mld2_report_len(groups.len())` bytes.
pub(crate) fn write_mld2_report(b: &mut [u8], src: Ipv6Addr, groups: &[Ipv6Addr]) {
    b[0] = MLD2_REPORT;
    b[1] = 0;
    b[4..6].copy_from_slice(&[0, 0]);
    b[6..8].copy_from_slice(&(groups.len() as u16).to_be_bytes());
    for (i, g) in groups.iter().enumerate() {
        let r = &mut b[ICMP6_HDR + i * 20..ICMP6_HDR + (i + 1) * 20];
        r[0] = 4; // CHANGE_TO_EXCLUDE_MODE
        r[1] = 0;
        r[2..4].copy_from_slice(&[0, 0]);
        r[4..20].copy_from_slice(&g.octets());
    }
    icmp6_checksum(b, src, ALL_MLDV2_ROUTERS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wire::{self, PROTO_TCP, PROTO_UDP, UDP_HDR, write_udp};

    const A: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const B: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    fn packet(next: u8, ext: &[u8], upper: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; IPV6_HDR + ext.len() + upper.len()];
        write_ipv6(&mut b, A, B, next, 64, 0, ext.len() + upper.len());
        b[IPV6_HDR..IPV6_HDR + ext.len()].copy_from_slice(ext);
        b[IPV6_HDR + ext.len()..].copy_from_slice(upper);
        b
    }

    #[test]
    fn addresses() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        assert_eq!(
            link_local(mac),
            "fe80::5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            solicited_node("2001:db8::1:2:3".parse().unwrap()),
            "ff02::1:ff02:3".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(multicast_mac(ALL_NODES), [0x33, 0x33, 0, 0, 0, 1]);
        assert!(is_link_local(link_local(mac)));
        assert!(!is_link_local(A));
    }

    #[test]
    fn header_roundtrip_and_tclass() {
        let mut b = vec![0u8; IPV6_HDR + 3 + 5];
        write_ipv6(&mut b, A, B, PROTO_UDP, 64, 0xb6, 3);
        let ip = Ipv6::parse(&b).unwrap();
        assert_eq!(
            (ip.src, ip.dst, ip.next, ip.hop_limit),
            (A, B, PROTO_UDP, 64)
        );
        assert_eq!(ip.tclass, 0xb6);
        assert_eq!(ip.payload.len(), 3); // Ethernet padding trimmed
        assert!(Ipv6::parse(&b[..IPV6_HDR + 2]).is_none());
        b[0] = 0x45;
        assert!(Ipv6::parse(&b).is_none());
    }

    #[test]
    fn extension_chain() {
        // HBH (PadN) -> DstOpts (Pad1 x6) -> UDP.
        let hbh = [NH_DSTOPTS, 0, 1, 4, 0, 0, 0, 0];
        let dst = [PROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
        let ext = [&hbh[..], &dst[..]].concat();
        let p = packet(NH_HOPOPT, &ext, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let ip = Ipv6::parse(&p).unwrap();
        let up = walk(ip.next, ip.payload, IPV6_HDR, true).unwrap();
        assert_eq!((up.proto, up.offset, up.frag), (PROTO_UDP, 16, None));
        assert_eq!(up.nh_field, IPV6_HDR + 8);
        // HBH not first: next header problem.
        let ext = [&dst[..1], &[0u8; 7][..]].concat();
        let mut e2 = ext;
        e2[0] = NH_HOPOPT;
        let p = packet(NH_DSTOPTS, &[e2, hbh.to_vec()].concat(), &[]);
        let ip = Ipv6::parse(&p).unwrap();
        assert!(matches!(
            walk(ip.next, ip.payload, IPV6_HDR, true),
            Err(ExtError::Problem {
                code: PARAM_NEXT_HEADER,
                pointer: 40,
                ..
            })
        ));
        // Unknown option with action 10: problem pointing at it.
        let bad = [PROTO_UDP, 0, 0x87, 2, 0, 0, 0, 0];
        let p = packet(NH_DSTOPTS, &bad, &[0; 8]);
        let ip = Ipv6::parse(&p).unwrap();
        assert_eq!(
            walk(ip.next, ip.payload, IPV6_HDR, true),
            Err(ExtError::Problem {
                code: PARAM_OPTION,
                pointer: 42,
                always: true
            })
        );
        // Action 01: silent drop; 00: skipped.
        let p = packet(NH_DSTOPTS, &[PROTO_UDP, 0, 0x47, 2, 0, 0, 0, 0], &[0; 8]);
        let ip = Ipv6::parse(&p).unwrap();
        assert_eq!(walk(ip.next, ip.payload, 40, true), Err(ExtError::Drop));
        let p = packet(NH_DSTOPTS, &[PROTO_UDP, 0, 0x07, 2, 0, 0, 0, 0], &[0; 8]);
        let ip = Ipv6::parse(&p).unwrap();
        assert!(walk(ip.next, ip.payload, 40, true).is_ok());
        // Routing header with segments left: problem at its segments-left field.
        let rh = [PROTO_UDP, 0, 4, 1, 0, 0, 0, 0];
        let p = packet(NH_ROUTING, &rh, &[0; 8]);
        let ip = Ipv6::parse(&p).unwrap();
        assert!(matches!(
            walk(ip.next, ip.payload, 40, true),
            Err(ExtError::Problem {
                code: PARAM_HEADER,
                pointer: 43,
                ..
            })
        ));
        // Routing header with nothing left is skipped.
        let rh = [PROTO_TCP, 0, 4, 0, 0, 0, 0, 0];
        let p = packet(NH_ROUTING, &rh, &[0; 8]);
        let ip = Ipv6::parse(&p).unwrap();
        assert_eq!(
            walk(ip.next, ip.payload, 40, true).unwrap().proto,
            PROTO_TCP
        );
        // No next header, and a chain longer than the limit, are dropped.
        let p = packet(NH_NONE, &[], &[0; 8]);
        let ip = Ipv6::parse(&p).unwrap();
        assert_eq!(walk(ip.next, ip.payload, 40, true), Err(ExtError::Drop));
        let mut long = Vec::new();
        for _ in 0..=MAX_EXT_HEADERS {
            long.extend_from_slice(&[NH_DSTOPTS, 0, 0, 0, 0, 0, 0, 0]);
        }
        let p = packet(NH_DSTOPTS, &long, &[0; 8]);
        let ip = Ipv6::parse(&p).unwrap();
        assert_eq!(walk(ip.next, ip.payload, 40, true), Err(ExtError::Drop));
        // Truncated headers never panic.
        for n in 0..p.len() {
            if let Some(ip) = Ipv6::parse(&p[..n]) {
                let _ = walk(ip.next, ip.payload, 40, true);
            }
        }
    }

    #[test]
    fn fragment_header() {
        let mut fh = [0u8; FRAG_HDR];
        write_frag(&mut fh, PROTO_UDP, 1232, true, 0xdead_beef);
        let p = packet(NH_FRAGMENT, &fh, &[9; 16]);
        let ip = Ipv6::parse(&p).unwrap();
        let up = walk(ip.next, ip.payload, 40, true).unwrap();
        let f = up.frag.unwrap();
        assert_eq!(
            (f.id, f.offset, f.more, f.next, f.data),
            (0xdead_beef, 1232, true, PROTO_UDP, 8)
        );
    }

    #[test]
    fn udp_and_icmp_checksums() {
        let (a, b) = (IpAddr::V6(A), IpAddr::V6(B));
        let mut u = vec![0u8; UDP_HDR + 4];
        u[UDP_HDR..].copy_from_slice(b"ping");
        write_udp(&mut u, a, b, 1, 2, 4);
        assert!(wire::Udp::parse(&u, a, b, true).is_some());
        // A zero UDP checksum is invalid over IPv6.
        let mut z = u.clone();
        z[6] = 0;
        z[7] = 0;
        assert!(wire::Udp::parse(&z, a, b, false).is_none());
        let mut m = vec![0u8; ICMP6_HDR + 4];
        write_icmp6(&mut m, A, B, ICMP6_ECHO_REQUEST, 0, [0, 1, 0, 2], b"data");
        let i = Icmp6::parse(&m, A, B, true).unwrap();
        assert_eq!(
            (i.kind, i.rest, i.body),
            (ICMP6_ECHO_REQUEST, [0, 1, 0, 2], &b"data"[..])
        );
        // The checksum covers the pseudo-header: other addresses fail it.
        let c: Ipv6Addr = "fd00::3".parse().unwrap();
        assert!(Icmp6::parse(&m, A, c, true).is_none());
    }

    #[test]
    fn neighbor_discovery() {
        let mac = [2, 0, 0, 0, 0, 1];
        let sn = solicited_node(B);
        let mut b = [0u8; ND_MSG];
        write_ns(&mut b, A, sn, B, Some(mac));
        let m = Icmp6::parse(&b, A, sn, true).unwrap();
        let nd = Nd::parse(&m, A, sn, 255).unwrap();
        assert_eq!(
            (nd.kind, nd.target, nd.lla),
            (ND_NEIGHBOR_SOLICIT, B, Some(mac))
        );
        // Hop limit other than 255: forged off-link, refused.
        assert!(Nd::parse(&m, A, sn, 64).is_none());
        // DAD probe: unspecified source, no option.
        let mut d = [0u8; ND_LEN];
        write_ns(&mut d, Ipv6Addr::UNSPECIFIED, sn, B, None);
        let m = Icmp6::parse(&d, Ipv6Addr::UNSPECIFIED, sn, true).unwrap();
        assert!(Nd::parse(&m, Ipv6Addr::UNSPECIFIED, sn, 255).is_some());
        // ... but not to a unicast address.
        assert!(Nd::parse(&m, Ipv6Addr::UNSPECIFIED, B, 255).is_none());
        let mut na = [0u8; ND_MSG];
        write_na(&mut na, B, A, NA_SOLICITED | NA_OVERRIDE, B, mac);
        let m = Icmp6::parse(&na, B, A, true).unwrap();
        let nd = Nd::parse(&m, B, A, 255).unwrap();
        assert_eq!(nd.flags, NA_SOLICITED | NA_OVERRIDE);
        assert_eq!(nd.lla, Some(mac));
        // Solicited flag on a multicast advertisement is invalid.
        assert!(Nd::parse(&m, B, ALL_NODES, 255).is_none());
        // A zero-length option is invalid.
        let mut bad = na;
        bad[25] = 0;
        icmp6_checksum(&mut bad, B, A);
        let m = Icmp6::parse(&bad, B, A, true).unwrap();
        assert!(Nd::parse(&m, B, A, 255).is_none());
    }

    #[test]
    fn quoted_through_extension_headers() {
        let (a, b) = (IpAddr::V6(A), IpAddr::V6(B));
        let mut u = vec![0u8; UDP_HDR];
        write_udp(&mut u, a, b, 1111, 2222, 0);
        let p = packet(NH_DSTOPTS, &[PROTO_UDP, 0, 1, 4, 0, 0, 0, 0], &u);
        let mut m = vec![0u8; ICMP6_HDR + p.len()];
        write_icmp6(&mut m, B, A, ICMP6_UNREACHABLE, UNREACH6_PORT, [0; 4], &p);
        let i = Icmp6::parse(&m, B, A, true).unwrap();
        let q = i.quoted().unwrap();
        assert_eq!(
            (q.src, q.dst, q.proto, q.src_port, q.dst_port),
            (a, b, PROTO_UDP, 1111, 2222)
        );
    }

    #[test]
    fn mld_report() {
        let ll = link_local([2, 0, 0, 0, 0, 1]);
        let groups = [solicited_node(ll), solicited_node(A)];
        let mut b = vec![0u8; mld2_report_len(2)];
        write_mld2_report(&mut b, ll, &groups);
        let m = Icmp6::parse(&b, ll, ALL_MLDV2_ROUTERS, true).unwrap();
        assert_eq!((m.kind, m.rest[3]), (MLD2_REPORT, 2));
    }

    #[test]
    fn router_discovery_messages() {
        let ll = link_local([2, 0, 0, 0, 0, 9]);
        let mac = [2, 0, 0, 0, 0, 9];
        // Router solicitation with and without the link-layer option.
        let mut b = [0u8; ICMP6_HDR + LLA_OPT];
        write_rs(&mut b, ll, Some(mac));
        let m = Icmp6::parse(&b, ll, ALL_ROUTERS, true).unwrap();
        assert_eq!(
            (m.kind, m.body),
            (ND_ROUTER_SOLICIT, &[1, 1, 2, 0, 0, 0, 0, 9][..])
        );
        write_rs(&mut b[..rs_len(false)], Ipv6Addr::UNSPECIFIED, None);
        assert!(Icmp6::parse(&b[..ICMP6_HDR], Ipv6Addr::UNSPECIFIED, ALL_ROUTERS, true).is_some());
        // A DAD probe carries its nonce and no link-layer option.
        let mut ns = [0u8; DAD_NS];
        write_dad_ns(&mut ns, A, [1, 2, 3, 4, 5, 6]);
        let sn = solicited_node(A);
        let m = Icmp6::parse(&ns, Ipv6Addr::UNSPECIFIED, sn, true).unwrap();
        let nd = Nd::parse(&m, Ipv6Addr::UNSPECIFIED, sn, 255).unwrap();
        assert_eq!(
            (nd.target, nd.lla, nd.nonce),
            (A, None, Some([1, 2, 3, 4, 5, 6]))
        );
        // Router advertisement: hop limit 64, lifetime 1800, LLA, MTU 1480, one prefix.
        let mut body = vec![0u8; 8];
        body.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 9, 5, 1, 0, 0, 0, 0, 0x05, 0xc8]);
        body.extend_from_slice(&[
            3, 4, 64, 0xc0, 0, 0, 0x0e, 0x10, 0, 0, 0x07, 0x08, 0, 0, 0, 0,
        ]);
        body.extend_from_slice(&A.octets());
        let mut m = vec![0u8; ICMP6_HDR + body.len()];
        write_icmp6(
            &mut m,
            ll,
            ALL_NODES,
            ND_ROUTER_ADVERT,
            0,
            [64, 0, 0x07, 0x08],
            &body,
        );
        let i = Icmp6::parse(&m, ll, ALL_NODES, true).unwrap();
        let ra = Ra::parse(&i, ll, 255).unwrap();
        assert_eq!(
            (ra.hop_limit, ra.lifetime, ra.lla, ra.mtu),
            (64, 1800, Some(mac), Some(1480))
        );
        assert_eq!(
            ra.prefixes[0],
            Some(PrefixInfo {
                prefix: A,
                len: 64,
                on_link: true,
                autonomous: true,
                valid: 3600,
                preferred: 1800,
            })
        );
        // Not from a link-local source, a forwarded one, a zero-length option, truncated.
        assert!(Ra::parse(&i, A, 255).is_none());
        assert!(Ra::parse(&i, ll, 254).is_none());
        let mut bad = m.clone();
        bad[ICMP6_HDR + 9] = 0;
        assert!(Ra::parse(&Icmp6::parse(&bad, ll, ALL_NODES, false).unwrap(), ll, 255).is_none());
        for n in ICMP6_HDR..m.len() {
            if let Some(i) = Icmp6::parse(&m[..n], ll, ALL_NODES, false) {
                let _ = Ra::parse(&i, ll, 255);
            }
        }
    }
}
