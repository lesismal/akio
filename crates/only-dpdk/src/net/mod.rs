//! The userspace TCP/IP stack: Ethernet II, ARP, IPv4 (with fragmentation and reassembly),
//! ICMPv4, IPv6 (extension headers, fragmentation and reassembly, path MTU), ICMPv6, NDP with
//! duplicate address detection and SLAAC from router advertisements, MLDv2 reports, UDP and
//! TCP over both, in safe Rust with no dependencies. One [`Iface`] per device queue, owned by
//! that queue's I/O thread; it is driven with received frames, a clock and a
//! transmit sink, and reports what the owner must act on as [`Event`]s.
//!
//! Layout: `wire` / `wire6` (frame formats), `arp` (ARP and NDP neighbour caches), `frag`
//! (IPv4 and IPv6 reassembly), `buf`
//! (TCP byte rings and the out-of-order assembler), `cc` (RTT / RTO, NewReno, CUBIC), `tcp`
//! (the connection state machine, ECN, pacing), `iface` (demultiplexing, listeners, timers, IP
//! output).
#![forbid(unsafe_code)]

pub(crate) mod arp;
pub(crate) mod buf;
pub(crate) mod cc;
pub(crate) mod frag;
pub(crate) mod hash;
pub(crate) mod iface;
pub(crate) mod tcp;
pub(crate) mod wire;
pub(crate) mod wire6;

#[cfg(test)]
pub(crate) mod sim;

pub(crate) use cc::CcKind;
pub(crate) use iface::{CallError, Config, Event, Iface, TcpHandle, Tx};
pub(crate) use tcp::{Params, TcpError};
pub(crate) use wire6::link_local;

/// An ARP frame, or an IPv6 neighbor solicitation / advertisement or router advertisement
/// without extension headers (NDP messages never have them: hop limit 255, RFC 4861): what
/// every queue's stack must see.
pub(crate) fn is_neighbor_frame(f: &[u8]) -> bool {
    const ICMP6_TYPE: usize = wire::ETH_HDR + wire6::IPV6_HDR;
    match f.get(12..14) {
        Some([0x08, 0x06]) => true,
        Some([0x86, 0xdd]) => {
            f.len() > ICMP6_TYPE
                && f[wire::ETH_HDR + 6] == wire::PROTO_ICMPV6
                && matches!(
                    f[ICMP6_TYPE],
                    wire6::ND_NEIGHBOR_SOLICIT
                        | wire6::ND_NEIGHBOR_ADVERT
                        | wire6::ND_ROUTER_ADVERT
                )
        }
        _ => false,
    }
}
