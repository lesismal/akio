//! One stack instance (one per device queue): Ethernet / ARP / IPv4 / ICMP and IPv6 / ICMPv6 /
//! NDP demultiplexing, UDP and TCP over both families, the TCP connection table and listeners
//! (dual-stack: a listener on a port accepts IPv4 and IPv6), timers, and the output path
//! (routing, ARP / NDP resolution with a pending queue, fragmentation, IPv6 path MTU).
//!
//! The interface never reads a clock or touches a device: the caller passes `now`, hands it
//! received frames ([`Iface::receive`]), runs [`Iface::poll`] for timers and queued output, and
//! provides a [`Tx`] for the frames it sends. That keeps it deterministic for the simulated-link
//! tests.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    hash::{BuildHasher, Hash, Hasher, RandomState},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use super::{
    arp::{ArpCache, Lookup, NdpCache},
    frag::Reassembler,
    hash::KeyedHash,
    tcp::{Clock, Endpoints, IcmpError, Notes, Params, SegOut, State, SynOpts, Tcb, TcpError},
    wire::{
        self, ACK, ARP_LEN, ARP_REPLY, ARP_REQUEST, Arp, BROADCAST, ECN_MASK, ECT0, ETH_HDR,
        ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Eth, ICMP_HDR, IP_DF, IP_MF, IPV4_HDR, Icmp,
        Ipv4, Mac, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, RST, SYN, Tcp, TcpOpts, TcpOut,
        UDP_HDR, Udp,
    },
    wire6::{self, ExtError, FRAG_HDR, ICMP6_HDR, IPV6_HDR, Icmp6, Ipv6, ND_MSG, Nd},
};

/// Where frames go: a device queue. A frame is built in the buffer `buffer` returns and sent by
/// `commit`.
pub(crate) trait Tx {
    /// A writable buffer of exactly `len` bytes for the next frame.
    fn buffer(&mut self, len: usize) -> &mut [u8];
    /// Sends the frame last built with `buffer`.
    fn commit(&mut self);
}

/// Configuration of one interface.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) mac: Mac,
    pub(crate) ip: Ipv4Addr,
    pub(crate) prefix_len: u8,
    pub(crate) gateway: Option<Ipv4Addr>,
    /// The global (or unique local) IPv6 address: IPv6 is on when set (with a link-local
    /// address derived from the MAC next to it).
    pub(crate) ip6: Option<Ipv6Addr>,
    pub(crate) prefix_len6: u8,
    /// IPv6 default router (often a link-local address).
    pub(crate) gateway6: Option<Ipv6Addr>,
    /// IP MTU.
    pub(crate) mtu: usize,
    pub(crate) tcp: Params,
    /// Half-open connections per listener before SYN cookies (or drops) take over.
    pub(crate) backlog: usize,
    pub(crate) syn_cookies: bool,
    /// Bytes of received UDP datagrams queued per bound port.
    pub(crate) udp_queue: usize,
    /// Verify received checksums (off for AF_PACKET, which sees the local kernel's partial
    /// checksums).
    pub(crate) verify_checksums: bool,
    /// This interface's queue index and the number of queues of the device (multi-queue
    /// steering of dialed connections, see [`Iface::dial_port_owner`]).
    pub(crate) queue: usize,
    pub(crate) queues: usize,
    /// First port of the range dialed connections use.
    pub(crate) dial_first: u16,
    /// Seed for ISNs, SYN cookies and the timestamp clock (tests pass a fixed one).
    pub(crate) seed: Option<u64>,
}

/// A TCP connection of this interface. Stale after the connection is freed (every call on it
/// then does nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TcpHandle {
    idx: u32,
    ver: u32,
}

/// What the interface tells its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// A connection to listener `port` completed its handshake.
    Accepted {
        port: u16,
        h: TcpHandle,
    },
    Connected(TcpHandle),
    ConnectFailed(TcpHandle, TcpError),
    /// New data (or the peer's FIN) to read.
    Readable(TcpHandle),
    /// Send-buffer space freed after a short `tcp_send`.
    Writable(TcpHandle),
    /// A connection the owner holds ended without the owner closing it (reset, timeout, or
    /// the closing exchange finished). The handle is stale afterwards.
    Closed(TcpHandle, Option<TcpError>),
    /// ICMP port / host unreachable for a datagram sent from `port` to `remote` (boxed: the
    /// address would triple the size of every event).
    UdpUnreachable {
        port: u16,
        remote: Box<SocketAddr>,
    },
}

#[derive(Debug)]
struct Slot {
    ver: u32,
    tcb: Option<Box<Tcb>>,
    dirty: bool,
    /// The owner knows the connection (dialed, or announced by `Accepted`).
    known: bool,
    /// `Connected` / `Accepted` was emitted.
    announced: bool,
    /// `Closed` / `ConnectFailed` was emitted.
    reported: bool,
    /// Send a RST with the next `poll` (accepted for a listener that is gone).
    abort: bool,
    /// Counted in its listener's half-open connections.
    half_open: Option<u16>,
}

#[derive(Debug)]
struct Listener {
    half_open: usize,
}

#[derive(Debug)]
struct Datagram {
    port: u16,
    from: SocketAddr,
    /// ECN codepoint it arrived with (of the last fragment when reassembled).
    ecn: u8,
    data: Vec<u8>,
}

/// Errors of the owner-facing calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallError {
    AddrInUse,
    TooBig,
    Unreachable,
}

/// A connection-table key: (local port, remote address), packed in 20 bytes whatever the
/// family (an IPv4 address as its IPv4-mapped IPv6 form): the remote address's four words, then
/// both ports. Hashed as two words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key([u32; 5]);

impl Key {
    fn new(local_port: u16, remote: SocketAddr) -> Key {
        let ip = match remote.ip() {
            IpAddr::V4(a) => [0, 0, 0xffff, u32::from(a)],
            IpAddr::V6(a) => words(IpAddr::V6(a)),
        };
        let ports = (u32::from(local_port) << 16) | u32::from(remote.port());
        Key([ip[0], ip[1], ip[2], ip[3], ports])
    }
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, h: &mut H) {
        let w = &self.0;
        h.write_u64((u64::from(w[3]) << 32 | u64::from(w[4])) ^ u64::from(w[2]));
        h.write_u64(u64::from(w[0]) << 32 | u64::from(w[1]));
    }
}

/// An address as words for the keyed hashes (ISNs, SYN cookies).
fn words(a: IpAddr) -> [u32; 4] {
    match a {
        IpAddr::V4(a) => [u32::from(a), 0, 0, 0],
        IpAddr::V6(a) => {
            let o = u128::from(a);
            [
                (o >> 96) as u32,
                (o >> 64) as u32,
                (o >> 32) as u32,
                o as u32,
            ]
        }
    }
}

/// A received IP packet, either family, as the transport layer sees it.
#[derive(Clone, Copy, Debug)]
struct Pkt<'a> {
    src: IpAddr,
    dst: IpAddr,
    /// Upper-layer protocol.
    proto: u8,
    /// ECN codepoint.
    ecn: u8,
    /// Hop limit / TTL.
    hops: u8,
    /// Sent to a broadcast or multicast address.
    bcast: bool,
    /// The upper-layer data.
    payload: &'a [u8],
    /// The whole packet from its IP header (what an ICMP error quotes).
    raw: &'a [u8],
    /// IPv4: the header length. IPv6: offset of the Next Header field naming `proto`.
    hdr: usize,
    /// The sender's MAC (NDP answers to a solicitation without a link-layer option).
    src_mac: Mac,
    /// The pseudo-header's address sum (TCP / UDP checksums).
    ps: wire::Pseudo,
}

/// What an ICMP error about a received packet says, in both families' terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unreach {
    Port,
    /// Unknown protocol (IPv6: parameter problem "next header", pointing at it).
    Proto,
}

/// How long a SYN cookie stays valid (two 64 s counter periods).
const COOKIE_LIFE: Duration = Duration::from_secs(128);
/// SYN-cookie MSS table (3 bits).
const COOKIE_MSS: [u16; 8] = [536, 1200, 1360, 1400, 1440, 1460, 4312, 8960];
/// ICMP error budget: tokens, refilled one per `ICMP_REFILL`.
const ICMP_BURST: u32 = 50;
const ICMP_REFILL: Duration = Duration::from_millis(10);
const TTL: u8 = 64;
/// Most destinations with a learned path MTU (IPv6 packet-too-big); the oldest goes first.
const PMTU_ENTRIES: usize = 1024;
/// A learned path MTU is forgotten after this (RFC 8201 4: at least 5 minutes, 10 suggested).
const PMTU_LIFE: Duration = Duration::from_secs(600);
/// Bytes of the invoking packet an ICMPv6 error quotes: as much as fits in the minimum MTU.
const ICMP6_QUOTE: usize = wire6::MIN_MTU - IPV6_HDR - ICMP6_HDR;

/// What one IP packet to send looks like (the payload is written by a callback).
#[derive(Clone, Copy, Debug)]
struct IpOut {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    /// Payload bytes.
    len: usize,
    /// Never fragment (TCP: segments are sized to the path MTU instead).
    df: bool,
    /// TOS / traffic class byte.
    tos: u8,
}

impl IpOut {
    fn body(&self) -> Body {
        Body {
            proto: self.proto,
            len: self.len,
            df: self.df,
            tos: self.tos,
        }
    }
}

/// The family-independent part of [`IpOut`] (what the per-family senders take, in registers).
#[derive(Clone, Copy, Debug)]
struct Body {
    proto: u8,
    len: usize,
    df: bool,
    tos: u8,
}

/// IPv6 addressing and neighbour state.
#[derive(Debug)]
struct Net6 {
    /// Link-local address (from the MAC).
    ll: Ipv6Addr,
    global: Option<Ipv6Addr>,
    /// Prefix of `global`'s subnet, as a mask.
    mask: u128,
    gateway: Option<Ipv6Addr>,
    ndp: NdpCache,
    frag_id: u32,
    /// Path MTUs learned from packet-too-big messages: destination -> (MTU, expiry).
    pmtu: HashMap<Ipv6Addr, (usize, Instant)>,
    /// Ethernet multicast addresses we receive (all-nodes, our solicited-node groups).
    mcast_macs: Vec<Mac>,
    /// When to send an MLDv2 report (at start, and after a query).
    mld_at: Option<Instant>,
}

impl Net6 {
    fn ours(&self, a: Ipv6Addr) -> bool {
        a == self.ll || Some(a) == self.global
    }

    /// A multicast group we listen to.
    fn listening(&self, a: Ipv6Addr) -> bool {
        a == wire6::ALL_NODES
            || a == wire6::solicited_node(self.ll)
            || self.global.is_some_and(|g| a == wire6::solicited_node(g))
    }

    fn on_link(&self, dst: Ipv6Addr) -> bool {
        wire6::is_link_local(dst)
            || self
                .global
                .is_some_and(|g| u128::from(dst) & self.mask == u128::from(g) & self.mask)
    }

    fn next_hop(&self, dst: Ipv6Addr) -> Option<Ipv6Addr> {
        if self.on_link(dst) || dst.is_multicast() {
            Some(dst)
        } else {
            self.gateway
        }
    }

    /// Source address for a packet to `dst` (RFC 6724, reduced to two candidates: the
    /// link-local address for link-local and multicast-link-scope destinations, the global one
    /// otherwise).
    fn src_for(&self, dst: Ipv6Addr) -> Ipv6Addr {
        let link_scope =
            wire6::is_link_local(dst) || (dst.is_multicast() && dst.segments()[0] & 0x000f <= 2);
        match self.global {
            Some(g) if !link_scope => g,
            _ => self.ll,
        }
    }

    fn path_mtu(&self, dst: Ipv6Addr, link: usize, now: Instant) -> usize {
        match self.pmtu.get(&dst) {
            Some(&(m, exp)) if now < exp => m.min(link),
            _ => link,
        }
    }

    fn learn_pmtu(&mut self, dst: Ipv6Addr, mtu: usize, link: usize, now: Instant) {
        let mtu = mtu.clamp(wire6::MIN_MTU, link);
        if mtu >= link {
            return;
        }
        if self.pmtu.len() >= PMTU_ENTRIES && !self.pmtu.contains_key(&dst) {
            self.pmtu.retain(|_, (_, exp)| *exp > now);
            if self.pmtu.len() >= PMTU_ENTRIES {
                let oldest = self
                    .pmtu
                    .iter()
                    .min_by_key(|(_, (_, e))| *e)
                    .map(|(a, _)| *a);
                if let Some(a) = oldest {
                    self.pmtu.remove(&a);
                }
            }
        }
        let e = self.pmtu.entry(dst).or_insert((mtu, now + PMTU_LIFE));
        if mtu <= e.0 {
            *e = (mtu, now + PMTU_LIFE);
        }
    }
}

/// IP output: addresses, routing, ARP / NDP, fragmentation.
#[derive(Debug)]
struct Net {
    mac: Mac,
    ip: Ipv4Addr,
    mask: u32,
    gateway: Option<Ipv4Addr>,
    mtu: usize,
    ip_id: u16,
    arp: ArpCache,
    v6: Option<Net6>,
    scratch: Vec<u8>,
    icmp_tokens: u32,
    icmp_refill: Instant,
}

impl Net {
    fn on_link(&self, dst: Ipv4Addr) -> bool {
        u32::from(dst) & self.mask == u32::from(self.ip) & self.mask
    }

    fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) | !self.mask)
    }

    fn next_hop(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        if self.on_link(dst) || dst.is_broadcast() {
            Some(dst)
        } else {
            self.gateway
        }
    }

    /// `dst` can be routed (a dial's precondition).
    fn routable(&self, dst: IpAddr) -> bool {
        match dst {
            IpAddr::V4(d) => self.next_hop(d).is_some(),
            IpAddr::V6(d) => self.v6.as_ref().is_some_and(|v| v.next_hop(d).is_some()),
        }
    }

    /// Our source address for a packet to `dst`.
    fn src_for(&self, dst: IpAddr) -> IpAddr {
        match (dst, &self.v6) {
            (IpAddr::V6(d), Some(v)) => IpAddr::V6(v.src_for(d)),
            (IpAddr::V6(_), None) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            (IpAddr::V4(_), _) => IpAddr::V4(self.ip),
        }
    }

    fn send_arp(&self, tx: &mut dyn Tx, op: u16, dst_mac: Mac, tha: Mac, tpa: Ipv4Addr) {
        let b = tx.buffer(ETH_HDR + ARP_LEN);
        wire::write_eth(b, dst_mac, self.mac, ETHERTYPE_ARP);
        Arp {
            op,
            sha: self.mac,
            spa: self.ip,
            tha,
            tpa,
        }
        .write(&mut b[ETH_HDR..]);
        tx.commit();
    }

    /// Sends an IP packet whose `o.len`-byte payload `write` fills in (over IPv4 or IPv6, by
    /// the destination). Packets larger than the (path) MTU are fragmented (unless `o.df`, then
    /// dropped). Returns `false` if the packet could not be sent or queued.
    #[inline]
    fn send_ip(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        o: IpOut,
        write: &mut dyn FnMut(&mut [u8]),
    ) -> bool {
        match (o.src, o.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => self.send_ip4(now, tx, src, dst, o.body(), write),
            (IpAddr::V6(src), IpAddr::V6(dst)) => self.send_ip6(now, tx, src, dst, o.body(), write),
            _ => false,
        }
    }

    fn send_ip4(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        o: Body,
        write: &mut dyn FnMut(&mut [u8]),
    ) -> bool {
        let Some(hop) = self.next_hop(dst) else {
            return false;
        };
        let (proto, len, tos) = (o.proto, o.len, o.tos);
        let mac = if dst.is_broadcast() || dst == self.broadcast() {
            Some(BROADCAST)
        } else {
            match self.arp.lookup(hop, now) {
                Lookup::Mac { mac, refresh } => {
                    if refresh {
                        self.send_arp(tx, ARP_REQUEST, mac, [0; 6], hop);
                    }
                    Some(mac)
                }
                Lookup::Pending { request } => {
                    if request {
                        self.send_arp(tx, ARP_REQUEST, BROADCAST, [0; 6], hop);
                    }
                    None
                }
            }
        };
        self.ip_id = self.ip_id.wrapping_add(1);
        let id = self.ip_id;
        if IPV4_HDR + len <= self.mtu {
            let frag = if o.df { IP_DF } else { 0 };
            match mac {
                Some(mac) => {
                    let b = tx.buffer(ETH_HDR + IPV4_HDR + len);
                    wire::write_eth(b, mac, self.mac, ETHERTYPE_IPV4);
                    write(&mut b[ETH_HDR + IPV4_HDR..]);
                    wire::write_ipv4(&mut b[ETH_HDR..], src, dst, proto, id, frag, TTL, tos, len);
                    tx.commit();
                    true
                }
                None => {
                    let mut p = vec![0u8; IPV4_HDR + len];
                    write(&mut p[IPV4_HDR..]);
                    wire::write_ipv4(&mut p, src, dst, proto, id, frag, TTL, tos, len);
                    self.arp.queue_packet(hop, p)
                }
            }
        } else {
            if o.df {
                return false;
            }
            // Fragment: payload into scratch, then 8-byte aligned pieces.
            let mut payload = std::mem::take(&mut self.scratch);
            payload.clear();
            payload.resize(len, 0);
            write(&mut payload);
            let max = (self.mtu - IPV4_HDR) & !7;
            let mut ok = true;
            let mut off = 0;
            while off < len {
                let n = max.min(len - off);
                let more = off + n < len;
                let frag = ((off / 8) as u16) | if more { IP_MF } else { 0 };
                let piece = &payload[off..off + n];
                match mac {
                    Some(mac) => {
                        let b = tx.buffer(ETH_HDR + IPV4_HDR + n);
                        wire::write_eth(b, mac, self.mac, ETHERTYPE_IPV4);
                        b[ETH_HDR + IPV4_HDR..].copy_from_slice(piece);
                        wire::write_ipv4(&mut b[ETH_HDR..], src, dst, proto, id, frag, TTL, tos, n);
                        tx.commit();
                    }
                    None => {
                        let mut p = vec![0u8; IPV4_HDR + n];
                        p[IPV4_HDR..].copy_from_slice(piece);
                        wire::write_ipv4(&mut p, src, dst, proto, id, frag, TTL, tos, n);
                        ok &= self.arp.queue_packet(hop, p);
                    }
                }
                off += n;
            }
            self.scratch = payload;
            ok
        }
    }

    /// Resolves an IPv6 next hop: its MAC, or `None` with the packet to be queued (a neighbor
    /// solicitation went out when needed).
    fn resolve6(&mut self, now: Instant, tx: &mut dyn Tx, hop: Ipv6Addr) -> Option<Mac> {
        if hop.is_multicast() {
            return Some(wire6::multicast_mac(hop));
        }
        let v6 = self.v6.as_mut()?;
        match v6.ndp.lookup(hop, now) {
            Lookup::Mac { mac, refresh } => {
                if refresh {
                    // NUD probe: unicast solicitation (RFC 4861 7.3.3, PROBE).
                    self.send_ns(tx, hop, Some(mac));
                }
                Some(mac)
            }
            Lookup::Pending { request } => {
                if request {
                    self.send_ns(tx, hop, None);
                }
                None
            }
        }
    }

    /// A neighbor solicitation for `target`: to its solicited-node group, or unicast to
    /// `known` (reachability confirmation).
    fn send_ns(&self, tx: &mut dyn Tx, target: Ipv6Addr, known: Option<Mac>) {
        let Some(v6) = &self.v6 else { return };
        let src = v6.src_for(target);
        let (dst, dmac) = match known {
            Some(m) => (target, m),
            None => {
                let sn = wire6::solicited_node(target);
                (sn, wire6::multicast_mac(sn))
            }
        };
        let b = tx.buffer(ETH_HDR + IPV6_HDR + ND_MSG);
        wire::write_eth(b, dmac, self.mac, ETHERTYPE_IPV6);
        wire6::write_ipv6(&mut b[ETH_HDR..], src, dst, PROTO_ICMPV6, 255, 0, ND_MSG);
        wire6::write_ns(
            &mut b[ETH_HDR + IPV6_HDR..],
            src,
            dst,
            target,
            Some(self.mac),
        );
        tx.commit();
    }

    /// A neighbor advertisement for our `target`, to `dst` at `dmac`.
    fn send_na(&self, tx: &mut dyn Tx, target: Ipv6Addr, dst: Ipv6Addr, dmac: Mac, flags: u8) {
        let b = tx.buffer(ETH_HDR + IPV6_HDR + ND_MSG);
        wire::write_eth(b, dmac, self.mac, ETHERTYPE_IPV6);
        wire6::write_ipv6(&mut b[ETH_HDR..], target, dst, PROTO_ICMPV6, 255, 0, ND_MSG);
        wire6::write_na(
            &mut b[ETH_HDR + IPV6_HDR..],
            target,
            dst,
            flags,
            target,
            self.mac,
        );
        tx.commit();
    }

    /// An MLDv2 report joining our solicited-node groups (RFC 3810 5.2: from the link-local
    /// address, hop limit 1, with a router alert).
    fn send_mld_report(&self, tx: &mut dyn Tx) {
        let Some(v6) = &self.v6 else { return };
        let mut groups = vec![wire6::solicited_node(v6.ll)];
        if let Some(g) = v6.global.map(wire6::solicited_node) {
            if !groups.contains(&g) {
                groups.push(g);
            }
        }
        let mlen = wire6::mld2_report_len(groups.len());
        let hbh = wire6::HBH_ROUTER_ALERT.len();
        let dst = wire6::ALL_MLDV2_ROUTERS;
        let b = tx.buffer(ETH_HDR + IPV6_HDR + hbh + mlen);
        wire::write_eth(b, wire6::multicast_mac(dst), self.mac, ETHERTYPE_IPV6);
        wire6::write_ipv6(
            &mut b[ETH_HDR..],
            v6.ll,
            dst,
            wire6::NH_HOPOPT,
            1,
            0,
            hbh + mlen,
        );
        let at = ETH_HDR + IPV6_HDR;
        b[at..at + hbh].copy_from_slice(&wire6::HBH_ROUTER_ALERT);
        wire6::write_mld2_report(&mut b[at + hbh..], v6.ll, &groups);
        tx.commit();
    }

    fn send_ip6(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        o: Body,
        write: &mut dyn FnMut(&mut [u8]),
    ) -> bool {
        let Some(v6) = &self.v6 else { return false };
        let Some(hop) = v6.next_hop(dst) else {
            return false;
        };
        let mtu = v6.path_mtu(dst, self.mtu, now);
        let mac = self.resolve6(now, tx, hop);
        let (proto, len, tos) = (o.proto, o.len, o.tos);
        if IPV6_HDR + len <= mtu {
            match mac {
                Some(mac) => {
                    let b = tx.buffer(ETH_HDR + IPV6_HDR + len);
                    wire::write_eth(b, mac, self.mac, ETHERTYPE_IPV6);
                    write(&mut b[ETH_HDR + IPV6_HDR..]);
                    wire6::write_ipv6(&mut b[ETH_HDR..], src, dst, proto, TTL, tos, len);
                    tx.commit();
                    true
                }
                None => {
                    let mut p = vec![0u8; IPV6_HDR + len];
                    write(&mut p[IPV6_HDR..]);
                    wire6::write_ipv6(&mut p, src, dst, proto, TTL, tos, len);
                    self.v6.as_mut().is_some_and(|v| v.ndp.queue_packet(hop, p))
                }
            }
        } else {
            // Only the source fragments in IPv6 (RFC 8200 4.5); TCP sizes its segments instead.
            if o.df || len + FRAG_HDR > 65535 {
                return false;
            }
            let Some(v6) = self.v6.as_mut() else {
                return false;
            };
            v6.frag_id = v6.frag_id.wrapping_add(1);
            let id = v6.frag_id;
            let mut payload = std::mem::take(&mut self.scratch);
            payload.clear();
            payload.resize(len, 0);
            write(&mut payload);
            let max = (mtu - IPV6_HDR - FRAG_HDR) & !7;
            let mut ok = true;
            let mut off = 0;
            while off < len {
                let n = max.min(len - off);
                let more = off + n < len;
                let piece = &payload[off..off + n];
                let plen = FRAG_HDR + n;
                let fill = |p: &mut [u8]| {
                    wire6::write_ipv6(p, src, dst, wire6::NH_FRAGMENT, TTL, tos, plen);
                    wire6::write_frag(&mut p[IPV6_HDR..], proto, off, more, id);
                    p[IPV6_HDR + FRAG_HDR..].copy_from_slice(piece);
                };
                match mac {
                    Some(mac) => {
                        let b = tx.buffer(ETH_HDR + IPV6_HDR + plen);
                        wire::write_eth(b, mac, self.mac, ETHERTYPE_IPV6);
                        fill(&mut b[ETH_HDR..]);
                        tx.commit();
                    }
                    None => {
                        let mut p = vec![0u8; IPV6_HDR + plen];
                        fill(&mut p);
                        ok &= self.v6.as_mut().is_some_and(|v| v.ndp.queue_packet(hop, p));
                    }
                }
                off += n;
            }
            self.scratch = payload;
            ok
        }
    }

    /// Sends the IP packets that waited for `mac`.
    fn release(&self, tx: &mut dyn Tx, mac: Mac, ethertype: u16, packets: VecDeque<Vec<u8>>) {
        for p in packets {
            let b = tx.buffer(ETH_HDR + p.len());
            wire::write_eth(b, mac, self.mac, ethertype);
            b[ETH_HDR..].copy_from_slice(&p);
            tx.commit();
        }
    }

    fn icmp_allowed(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.icmp_refill);
        let add = (elapsed.as_micros() / ICMP_REFILL.as_micros()) as u32;
        if add > 0 {
            self.icmp_tokens = (self.icmp_tokens + add).min(ICMP_BURST);
            self.icmp_refill = now;
        }
        if self.icmp_tokens == 0 {
            return false;
        }
        self.icmp_tokens -= 1;
        true
    }

    /// ICMP / ICMPv6 error about a received packet, rate limited.
    fn send_unreach(&mut self, now: Instant, tx: &mut dyn Tx, why: Unreach, p: &Pkt<'_>) {
        match p.src {
            IpAddr::V4(_) => {
                let code = match why {
                    Unreach::Port => wire::UNREACH_PORT,
                    Unreach::Proto => wire::UNREACH_PROTO,
                };
                self.send_icmp4_error(now, tx, wire::ICMP_UNREACHABLE, code, p);
            }
            IpAddr::V6(_) => {
                let (kind, code, rest) = match why {
                    Unreach::Port => (wire6::ICMP6_UNREACHABLE, wire6::UNREACH6_PORT, 0),
                    Unreach::Proto => (
                        wire6::ICMP6_PARAM_PROBLEM,
                        wire6::PARAM_NEXT_HEADER,
                        p.hdr as u32,
                    ),
                };
                self.send_icmp6_error(now, tx, kind, code, rest, p.raw, p.bcast);
            }
        }
    }

    /// ICMPv4 error about a received datagram, rate limited.
    fn send_icmp4_error(&mut self, now: Instant, tx: &mut dyn Tx, kind: u8, code: u8, p: &Pkt<'_>) {
        let IpAddr::V4(src) = p.src else { return };
        if !self.icmp_allowed(now) {
            return;
        }
        // RFC 1812 4.3.2.3: quote as much as fits in 576 bytes.
        let hl = p.hdr;
        let quote = (p.raw.len() - hl).min(576 - IPV4_HDR - ICMP_HDR - hl);
        let body = &p.raw[..hl + quote];
        let o = IpOut {
            src: IpAddr::V4(self.ip),
            dst: IpAddr::V4(src),
            proto: PROTO_ICMP,
            len: ICMP_HDR + body.len(),
            df: false,
            tos: 0,
        };
        self.send_ip(now, tx, o, &mut |b| {
            wire::write_icmp(b, kind, code, [0; 4], body);
        });
    }

    /// ICMPv6 error (RFC 4443 2.4): rate limited, never about a packet from an unspecified or
    /// multicast source, nor (except `always`) about one sent to a multicast address.
    #[allow(clippy::too_many_arguments)]
    fn send_icmp6_error(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        kind: u8,
        code: u8,
        rest: u32,
        raw: &[u8],
        to_multicast: bool,
    ) {
        let Some(ip) = Ipv6::parse(raw) else {
            return;
        };
        let always = kind == wire6::ICMP6_PACKET_TOO_BIG
            || (kind == wire6::ICMP6_PARAM_PROBLEM && code == wire6::PARAM_OPTION);
        if ip.src.is_unspecified() || ip.src.is_multicast() || (to_multicast && !always) {
            return;
        }
        let Some(v6) = &self.v6 else { return };
        let src = if v6.ours(ip.dst) {
            ip.dst
        } else {
            v6.src_for(ip.src)
        };
        if !self.icmp_allowed(now) {
            return;
        }
        let body = &raw[..raw.len().min(ICMP6_QUOTE)];
        let (s, d) = (src, ip.src);
        let o = IpOut {
            src: IpAddr::V6(s),
            dst: IpAddr::V6(d),
            proto: PROTO_ICMPV6,
            len: ICMP6_HDR + body.len(),
            df: false,
            tos: 0,
        };
        self.send_ip(now, tx, o, &mut |b| {
            wire6::write_icmp6(b, s, d, kind, code, rest.to_be_bytes(), body);
        });
    }
}

/// `SegOut` over the IP output path.
struct NetOut<'a> {
    net: &'a mut Net,
    tx: &'a mut dyn Tx,
    now: Instant,
}

impl SegOut for NetOut<'_> {
    #[inline]
    fn segment(&mut self, ep: &Endpoints, hdr: &TcpOut, payload: (&[u8], &[u8])) {
        let hl = hdr.header_len();
        let len = hl + payload.0.len() + payload.1.len();
        let tos = if hdr.ect { ECT0 } else { 0 };
        let fill = |b: &mut [u8], ps: wire::Pseudo| {
            b[hl..hl + payload.0.len()].copy_from_slice(payload.0);
            b[hl + payload.0.len()..].copy_from_slice(payload.1);
            hdr.write_with(b, ps);
        };
        match ep {
            // IPv4 first and without the family dispatch of `send_ip`.
            Endpoints::V4(l, r) => {
                let (src, dst) = (*l.ip(), *r.ip());
                let o = Body {
                    proto: PROTO_TCP,
                    len,
                    df: true,
                    tos,
                };
                let ps = wire::Pseudo::v4(src, dst);
                self.net
                    .send_ip4(self.now, self.tx, src, dst, o, &mut |b| fill(b, ps));
            }
            Endpoints::V6(a) => {
                let (src, dst) = (*a.0.ip(), *a.1.ip());
                let o = Body {
                    proto: PROTO_TCP,
                    len,
                    df: true,
                    tos,
                };
                let ps = wire::Pseudo::of(IpAddr::V6(src), IpAddr::V6(dst));
                self.net
                    .send_ip6(self.now, self.tx, src, dst, o, &mut |b| fill(b, ps));
            }
        }
    }
}

/// One userspace TCP/IP stack instance.
#[derive(Debug)]
pub(crate) struct Iface {
    cfg: Config,
    net: Net,
    slots: Vec<Slot>,
    free: Vec<u32>,
    table: HashMap<Key, u32, KeyedHash>,
    listeners: HashMap<u16, Listener>,
    udp_ports: HashSet<u16>,
    udp_q: VecDeque<Datagram>,
    udp_bytes: usize,
    udp_pool: Vec<Vec<u8>>,
    timers: BinaryHeap<Reverse<(Instant, u32, u32)>>,
    dirty: Vec<u32>,
    events: Vec<Event>,
    reasm: Reassembler,
    /// Frames for other queues (multi-queue steering): (queue, frame).
    forward: Vec<(usize, Vec<u8>)>,
    epoch: Instant,
    ts_offset: u32,
    secret: RandomState,
    seed: u64,
    arp_retry: Vec<Ipv4Addr>,
    arp_failed: Vec<Ipv4Addr>,
    nd_retry: Vec<Ipv6Addr>,
    nd_failed: Vec<Ipv6Addr>,
    /// When a SYN cookie was last sent.
    cookie_sent: Option<Instant>,
}

impl Iface {
    pub(crate) fn new(cfg: Config, now: Instant) -> Iface {
        let seed = cfg
            .seed
            .unwrap_or_else(|| RandomState::new().hash_one(cfg.queue));
        let mask = if cfg.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(cfg.prefix_len.min(32)))
        };
        let mtu = cfg.mtu.clamp(576, 65535);
        let v6 = cfg.ip6.filter(|_| mtu >= wire6::MIN_MTU).map(|global| {
            let ll = wire6::link_local(cfg.mac);
            let plen = u32::from(cfg.prefix_len6.min(128));
            let mask = if plen == 0 {
                0
            } else {
                u128::MAX << (128 - plen)
            };
            let global = (!global.is_unspecified() && global != ll).then_some(global);
            let mut mcast_macs = vec![wire6::multicast_mac(wire6::ALL_NODES)];
            for a in std::iter::once(ll).chain(global) {
                let m = wire6::multicast_mac(wire6::solicited_node(a));
                if !mcast_macs.contains(&m) {
                    mcast_macs.push(m);
                }
            }
            Net6 {
                ll,
                global,
                mask,
                gateway: cfg.gateway6,
                ndp: NdpCache::default(),
                frag_id: (seed >> 16) as u32,
                pmtu: HashMap::new(),
                mcast_macs,
                // One report for the device (queue 0); any queue answers a query.
                mld_at: (cfg.queue == 0).then_some(now),
            }
        });
        let net = Net {
            mac: cfg.mac,
            ip: cfg.ip,
            mask,
            gateway: cfg.gateway,
            mtu,
            ip_id: seed as u16,
            arp: ArpCache::default(),
            v6,
            scratch: Vec::new(),
            icmp_tokens: ICMP_BURST,
            icmp_refill: now,
        };
        Iface {
            net,
            slots: Vec::new(),
            free: Vec::new(),
            table: HashMap::with_hasher(KeyedHash(seed ^ 0x5851_f42d_4c95_7f2d)),
            listeners: HashMap::new(),
            udp_ports: HashSet::new(),
            udp_q: VecDeque::new(),
            udp_bytes: 0,
            udp_pool: Vec::new(),
            timers: BinaryHeap::new(),
            dirty: Vec::new(),
            events: Vec::new(),
            reasm: Reassembler::default(),
            forward: Vec::new(),
            epoch: now,
            ts_offset: (seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32) as u32 | 1,
            secret: RandomState::new(),
            seed,
            arp_retry: Vec::new(),
            arp_failed: Vec::new(),
            nd_retry: Vec::new(),
            nd_failed: Vec::new(),
            cookie_sent: None,
            cfg,
        }
    }

    fn clock(&self, now: Instant) -> Clock {
        let ms = now.saturating_duration_since(self.epoch).as_millis() as u32;
        Clock {
            now,
            ts: ms.wrapping_add(self.ts_offset),
        }
    }

    fn keyed(&self, words: &[u32]) -> u32 {
        let mut h = self.secret.build_hasher();
        self.seed.hash(&mut h);
        words.hash(&mut h);
        h.finish() as u32
    }

    /// RFC 6528 initial sequence number: a keyed hash of the connection plus a 4 µs clock.
    fn isn(&self, local: SocketAddr, remote: SocketAddr, now: Instant) -> u32 {
        let t = (now.saturating_duration_since(self.epoch).as_micros() / 4) as u32;
        let (lp, rp) = (u32::from(local.port()), u32::from(remote.port()));
        let h = match (local.ip(), remote.ip()) {
            // IPv4 hashes the four words it always did.
            (IpAddr::V4(l), IpAddr::V4(r)) => self.keyed(&[u32::from(l), lp, u32::from(r), rp]),
            (l, r) => {
                let (l, r) = (words(l), words(r));
                self.keyed(&[l[0], l[1], l[2], l[3], lp, r[0], r[1], r[2], r[3], rp])
            }
        };
        h.wrapping_add(t)
    }

    /// Frames waiting to be handed to other queues.
    pub(crate) fn take_forward(&mut self) -> Vec<(usize, Vec<u8>)> {
        std::mem::take(&mut self.forward)
    }

    pub(crate) fn take_events(&mut self, out: &mut Vec<Event>) {
        out.append(&mut self.events);
    }

    pub(crate) fn has_events(&self) -> bool {
        !self.events.is_empty() || !self.udp_q.is_empty()
    }

    /// The earliest time `poll` has work (timers, ARP retries, reassembly expiry).
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let t = self.timers.peek().map(|Reverse((t, _, _))| *t);
        let (nd, mld) = self
            .net
            .v6
            .as_ref()
            .map_or((None, None), |v| (v.ndp.next_deadline(), v.mld_at));
        [
            t,
            self.net.arp.next_deadline(),
            self.reasm.next_deadline(),
            nd,
            mld,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Output is queued (`poll` should run now).
    pub(crate) fn has_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    // ---- slots ----------------------------------------------------------------------------

    fn alloc(&mut self, tcb: Tcb) -> u32 {
        let key = Key::new(tcb.local().port(), tcb.remote());
        let idx = match self.free.pop() {
            Some(i) => {
                let s = &mut self.slots[i as usize];
                s.tcb = Some(Box::new(tcb));
                s.dirty = false;
                s.known = false;
                s.announced = false;
                s.reported = false;
                s.abort = false;
                s.half_open = None;
                i
            }
            None => {
                self.slots.push(Slot {
                    ver: 0,
                    tcb: Some(Box::new(tcb)),
                    dirty: false,
                    known: false,
                    announced: false,
                    reported: false,
                    abort: false,
                    half_open: None,
                });
                (self.slots.len() - 1) as u32
            }
        };
        self.table.insert(key, idx);
        idx
    }

    fn handle(&self, idx: u32) -> TcpHandle {
        TcpHandle {
            idx,
            ver: self.slots[idx as usize].ver,
        }
    }

    fn slot(&self, h: TcpHandle) -> Option<&Tcb> {
        let s = self.slots.get(h.idx as usize)?;
        if s.ver != h.ver {
            return None;
        }
        s.tcb.as_deref()
    }

    fn slot_mut(&mut self, h: TcpHandle) -> Option<&mut Tcb> {
        let s = self.slots.get_mut(h.idx as usize)?;
        if s.ver != h.ver {
            return None;
        }
        s.tcb.as_deref_mut()
    }

    fn mark_dirty(&mut self, idx: u32) {
        let s = &mut self.slots[idx as usize];
        if !s.dirty && s.tcb.is_some() {
            s.dirty = true;
            self.dirty.push(idx);
        }
    }

    /// After anything touched connection `idx`: turn its notes into events, keep the
    /// listener's half-open count and the timer heap up to date, free it if it is finished.
    fn settle(&mut self, idx: u32) {
        let h = self.handle(idx);
        let slot = &mut self.slots[idx as usize];
        let Some(tcb) = slot.tcb.as_deref_mut() else {
            return;
        };
        let notes = tcb.take_notes();
        if slot.half_open.is_some() && tcb.state != State::SynReceived {
            if let Some(l) = slot
                .half_open
                .take()
                .and_then(|p| self.listeners.get_mut(&p))
            {
                l.half_open = l.half_open.saturating_sub(1);
            }
        }
        if !notes.is_empty() && !tcb.orphan {
            if notes.has(Notes::ESTABLISHED) {
                match tcb.listener {
                    Some(port) if self.listeners.contains_key(&port) => {
                        slot.known = true;
                        slot.announced = true;
                        self.events.push(Event::Accepted { port, h });
                    }
                    Some(_) => {
                        // The listener is gone: refuse the connection.
                        tcb.orphan = true;
                        slot.abort = true;
                        if !slot.dirty {
                            slot.dirty = true;
                            self.dirty.push(idx);
                        }
                    }
                    None => {
                        slot.announced = true;
                        self.events.push(Event::Connected(h));
                    }
                }
            }
            if slot.known && !tcb.orphan {
                if notes.has(Notes::READABLE) {
                    self.events.push(Event::Readable(h));
                }
                if notes.has(Notes::WRITABLE) {
                    self.events.push(Event::Writable(h));
                }
            }
        }
        let gone = notes.has(Notes::CLOSED) || tcb.is_dead();
        if gone && slot.known && !tcb.orphan && !slot.reported {
            slot.reported = true;
            if slot.announced {
                self.events.push(Event::Closed(h, tcb.error));
            } else {
                self.events.push(Event::ConnectFailed(
                    h,
                    tcb.error.unwrap_or(TcpError::Reset),
                ));
            }
        }
        if tcb.is_dead() {
            let key = Key::new(tcb.local().port(), tcb.remote());
            if let Some(p) = slot.half_open.take() {
                if let Some(l) = self.listeners.get_mut(&p) {
                    l.half_open = l.half_open.saturating_sub(1);
                }
            }
            slot.tcb = None;
            slot.ver = slot.ver.wrapping_add(1);
            slot.dirty = false;
            if self.table.get(&key) == Some(&idx) {
                self.table.remove(&key);
            }
            self.free.push(idx);
            return;
        }
        if let Some(t) = tcb.next_timer() {
            if tcb.scheduled.is_none_or(|s| t < s) {
                tcb.scheduled = Some(t);
                self.timers.push(Reverse((t, idx, slot.ver)));
            }
        }
    }

    // ---- owner calls: TCP -----------------------------------------------------------------

    pub(crate) fn tcp_listen(&mut self, port: u16) {
        self.listeners
            .entry(port)
            .or_insert(Listener { half_open: 0 });
    }

    pub(crate) fn tcp_unlisten(&mut self, port: u16) {
        self.listeners.remove(&port);
    }

    /// Opens a connection from local `port` to `remote` (IPv4 or IPv6); the SYN goes out with
    /// the next `poll`.
    pub(crate) fn tcp_connect(
        &mut self,
        port: u16,
        remote: SocketAddr,
        now: Instant,
    ) -> Result<TcpHandle, CallError> {
        let remote = SocketAddr::new(remote.ip(), remote.port()); // no scope id / flow label
        if !self.net.routable(remote.ip()) {
            return Err(CallError::Unreachable);
        }
        if let Some(&idx) = self.table.get(&Key::new(port, remote)) {
            // TIME-WAIT reuse for a new connection (its ISN is larger: the clock moved on).
            match self.slots[idx as usize].tcb.as_deref() {
                Some(t) if t.state == State::TimeWait => {
                    let s = &mut self.slots[idx as usize];
                    s.tcb = None;
                    s.ver = s.ver.wrapping_add(1);
                    self.table.remove(&Key::new(port, remote));
                    self.free.push(idx);
                }
                _ => return Err(CallError::AddrInUse),
            }
        }
        let local = SocketAddr::new(self.net.src_for(remote.ip()), port);
        let iss = self.isn(local, remote, now);
        let tcb = Tcb::connect(self.cfg.tcp, local, remote, iss, self.clock(now));
        let idx = self.alloc(tcb);
        self.slots[idx as usize].known = true;
        self.mark_dirty(idx);
        Ok(self.handle(idx))
    }

    /// Whether a connection exists for `(port, remote)` (dial port selection).
    pub(crate) fn tcp_in_use(&self, port: u16, remote: SocketAddr) -> bool {
        let remote = SocketAddr::new(remote.ip(), remote.port());
        self.table
            .get(&Key::new(port, remote))
            .and_then(|&i| self.slots[i as usize].tcb.as_deref())
            .is_some_and(|t| t.state != State::TimeWait)
    }

    pub(crate) fn tcp_peer(&self, h: TcpHandle) -> Option<SocketAddr> {
        self.slot(h).map(|t| t.remote())
    }

    pub(crate) fn tcp_local(&self, h: TcpHandle) -> Option<SocketAddr> {
        self.slot(h).map(|t| t.local())
    }

    /// The stack has an address of `a`'s family.
    pub(crate) fn has_family(&self, a: IpAddr) -> bool {
        a.is_ipv4() || self.net.v6.is_some()
    }

    /// Our address for traffic with `remote`.
    pub(crate) fn local_for(&self, remote: IpAddr) -> IpAddr {
        self.net.src_for(remote)
    }

    /// Queues data; returns the bytes taken (sent with the next `poll`).
    pub(crate) fn tcp_send(&mut self, h: TcpHandle, data: &[u8]) -> usize {
        let Some(t) = self.slot_mut(h) else { return 0 };
        let n = t.send(data);
        if n > 0 {
            self.mark_dirty(h.idx);
        }
        n
    }

    pub(crate) fn tcp_recv(&mut self, h: TcpHandle, out: &mut [u8]) -> usize {
        let Some(t) = self.slot_mut(h) else { return 0 };
        let n = t.recv(out);
        if n > 0 {
            self.mark_dirty(h.idx);
        }
        n
    }

    pub(crate) fn tcp_readable(&self, h: TcpHandle) -> usize {
        self.slot(h).map_or(0, Tcb::readable)
    }

    /// The peer closed its side and everything was read (or the connection is gone).
    pub(crate) fn tcp_eof(&self, h: TcpHandle) -> bool {
        self.slot(h).is_none_or(Tcb::eof)
    }

    #[cfg(test)]
    pub(crate) fn tcp_state(&self, h: TcpHandle) -> Option<State> {
        self.slot(h).map(|t| t.state)
    }

    #[cfg(test)]
    pub(crate) fn tcb(&self, h: TcpHandle) -> Option<&Tcb> {
        self.slot(h)
    }

    /// Orderly close (FIN after queued data); the owner is done with the handle.
    pub(crate) fn tcp_close(&mut self, h: TcpHandle, now: Instant) {
        let clock = self.clock(now);
        let Some(t) = self.slot_mut(h) else { return };
        t.close(true, clock);
        self.mark_dirty(h.idx);
        self.settle(h.idx);
    }

    /// Abort (RST); the owner is done with the handle.
    pub(crate) fn tcp_abort(&mut self, h: TcpHandle, now: Instant, tx: &mut dyn Tx) {
        let s = match self.slots.get_mut(h.idx as usize) {
            Some(s) if s.ver == h.ver && s.tcb.is_some() => s,
            _ => return,
        };
        if let Some(t) = s.tcb.as_deref_mut() {
            let mut out = NetOut {
                net: &mut self.net,
                tx,
                now,
            };
            t.abort(&mut out);
        }
        self.settle(h.idx);
    }

    // ---- owner calls: UDP -----------------------------------------------------------------

    pub(crate) fn udp_bind(&mut self, port: u16) -> bool {
        self.udp_ports.insert(port)
    }

    pub(crate) fn udp_unbind(&mut self, port: u16) {
        self.udp_ports.remove(&port);
        let mut freed = 0;
        self.udp_q.retain(|d| {
            if d.port == port {
                freed += d.data.len();
                false
            } else {
                true
            }
        });
        self.udp_bytes -= freed;
    }

    /// Sends a datagram from local `port` (fragmented if larger than the (path) MTU).
    #[cfg(test)]
    pub(crate) fn udp_send(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        port: u16,
        remote: SocketAddr,
        data: &[u8],
    ) -> Result<(), CallError> {
        self.udp_send_ecn(now, tx, port, remote, data, 0)
    }

    /// Sends a datagram from local `port` (fragmented if larger than the (path) MTU) with ECN
    /// codepoint `ecn` (its low two bits) in the IP header's TOS / traffic class.
    pub(crate) fn udp_send_ecn(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        port: u16,
        remote: SocketAddr,
        data: &[u8],
        ecn: u8,
    ) -> Result<(), CallError> {
        let max = if remote.is_ipv6() {
            65535 - FRAG_HDR - UDP_HDR
        } else {
            65535 - IPV4_HDR - UDP_HDR
        };
        if data.len() > max {
            return Err(CallError::TooBig);
        }
        let dst = remote.ip();
        let src = self.net.src_for(dst);
        let o = IpOut {
            src,
            dst,
            proto: PROTO_UDP,
            len: UDP_HDR + data.len(),
            df: false,
            tos: ecn & ECN_MASK,
        };
        let ok = self.net.send_ip(now, tx, o, &mut |b| {
            b[UDP_HDR..].copy_from_slice(data);
            wire::write_udp(b, src, dst, port, remote.port(), data.len());
        });
        if ok {
            Ok(())
        } else {
            Err(CallError::Unreachable)
        }
    }

    /// The next received datagram: (local port, sender, length copied into `out`).
    #[cfg(test)]
    pub(crate) fn udp_recv(&mut self, out: &mut [u8]) -> Option<(u16, SocketAddr, usize)> {
        self.udp_recv_ecn(out).map(|(p, f, n, _)| (p, f, n))
    }

    /// The next received datagram: (local port, sender, length copied into `out`, ECN
    /// codepoint).
    pub(crate) fn udp_recv_ecn(&mut self, out: &mut [u8]) -> Option<(u16, SocketAddr, usize, u8)> {
        let d = self.udp_q.pop_front()?;
        self.udp_bytes -= d.data.len();
        let n = d.data.len().min(out.len());
        out[..n].copy_from_slice(&d.data[..n]);
        if self.udp_pool.len() < 256 {
            self.udp_pool.push(d.data);
        }
        Some((d.port, d.from, n, d.ecn))
    }

    // ---- receive path ---------------------------------------------------------------------

    /// The queue a dialed connection's port belongs to (multi-queue: dial ports are spread
    /// over the queues by `port % queues`, and frames the NIC's RSS put on the wrong queue are
    /// handed to the right one). `None`: this queue.
    fn dial_port_owner(&self, proto: u8, port: u16) -> Option<usize> {
        if self.cfg.queues <= 1 || port < self.cfg.dial_first {
            return None;
        }
        let bound = match proto {
            PROTO_TCP => self.listeners.contains_key(&port),
            _ => self.udp_ports.contains(&port),
        };
        if bound {
            return None;
        }
        let q = usize::from(port) % self.cfg.queues;
        (q != self.cfg.queue).then_some(q)
    }

    /// Processes one received Ethernet frame.
    pub(crate) fn receive(&mut self, now: Instant, frame: &[u8], tx: &mut dyn Tx) {
        let Some(eth) = Eth::parse(frame) else { return };
        if eth.dst != self.cfg.mac
            && eth.dst != BROADCAST
            && !self
                .net
                .v6
                .as_ref()
                .is_some_and(|v| v.mcast_macs.contains(&eth.dst))
        {
            return;
        }
        match eth.ethertype {
            ETHERTYPE_ARP => self.on_arp(now, eth.payload, tx),
            ETHERTYPE_IPV4 => self.on_ipv4(now, frame, eth.payload, tx),
            ETHERTYPE_IPV6 if self.net.v6.is_some() => {
                self.on_ipv6(now, frame, eth.src, eth.payload, tx);
            }
            _ => {}
        }
    }

    fn on_arp(&mut self, now: Instant, b: &[u8], tx: &mut dyn Tx) {
        let Some(a) = Arp::parse(b) else { return };
        if a.spa == self.cfg.ip {
            return; // our own (fanned out) or a conflicting announcement
        }
        let for_us = a.tpa == self.cfg.ip;
        // RFC 826: update an existing entry; create one when the packet is aimed at us.
        if let Some(q) = self.net.arp.learn(a.spa, a.sha, now, for_us) {
            self.net.release(tx, a.sha, ETHERTYPE_IPV4, q);
        }
        if for_us && a.op == ARP_REQUEST {
            self.net.send_arp(tx, ARP_REPLY, a.sha, a.sha, a.spa);
        }
    }

    fn on_ipv4(&mut self, now: Instant, frame: &[u8], b: &[u8], tx: &mut dyn Tx) {
        let verify = self.cfg.verify_checksums;
        let Some(ip) = Ipv4::parse(b, verify) else {
            return;
        };
        let bcast = ip.dst.is_broadcast() || ip.dst == self.net.broadcast();
        if ip.dst != self.cfg.ip && !bcast {
            return;
        }
        let src_mac = wire::mac_at(frame, 6);
        if ip.is_fragment() {
            let Some(d) = self.reasm.add(
                IpAddr::V4(ip.src),
                IpAddr::V4(ip.dst),
                ip.proto,
                u32::from(ip.id),
                ip.frag_offset(),
                ip.more_fragments(),
                ip.payload,
                now,
            ) else {
                return;
            };
            // Rebuild a whole packet so the rest of the path (and steering) sees one.
            let mut pkt = vec![0u8; IPV4_HDR + d.payload.len()];
            pkt[IPV4_HDR..].copy_from_slice(&d.payload);
            if pkt.len() > 65535 {
                return;
            }
            wire::write_ipv4(
                &mut pkt,
                ip.src,
                ip.dst,
                d.proto,
                ip.id,
                0,
                ip.ttl,
                ip.tos,
                d.payload.len(),
            );
            if let Some(q) =
                Self::dst_port(d.proto, &d.payload).and_then(|p| self.dial_port_owner(d.proto, p))
            {
                let mut f = Vec::with_capacity(ETH_HDR + pkt.len());
                f.extend_from_slice(&frame[..ETH_HDR]);
                f.extend_from_slice(&pkt);
                self.forward.push((q, f));
                return;
            }
            let Some(whole) = Ipv4::parse(&pkt, false) else {
                return;
            };
            self.on_packet(now, &Self::pkt4(&whole, &pkt, bcast, src_mac), false, tx);
            return;
        }
        if let Some(q) =
            Self::dst_port(ip.proto, ip.payload).and_then(|p| self.dial_port_owner(ip.proto, p))
        {
            self.forward.push((q, frame.to_vec()));
            return;
        }
        let raw = &b[..ip.hdr_len + ip.payload.len()];
        let p = Self::pkt4(&ip, raw, bcast, src_mac);
        if ip.proto == PROTO_TCP && !bcast {
            // The common case, without the protocol dispatch.
            return self.on_tcp(now, &p, verify, tx);
        }
        self.on_packet(now, &p, verify, tx);
    }

    fn pkt4<'a>(ip: &Ipv4<'a>, raw: &'a [u8], bcast: bool, src_mac: Mac) -> Pkt<'a> {
        Pkt {
            src: IpAddr::V4(ip.src),
            dst: IpAddr::V4(ip.dst),
            proto: ip.proto,
            ecn: ip.tos & ECN_MASK,
            hops: ip.ttl,
            bcast,
            payload: ip.payload,
            raw,
            hdr: ip.hdr_len,
            src_mac,
            ps: wire::Pseudo::v4(ip.src, ip.dst),
        }
    }

    fn on_ipv6(&mut self, now: Instant, frame: &[u8], src_mac: Mac, b: &[u8], tx: &mut dyn Tx) {
        let Some(ip) = Ipv6::parse(b) else { return };
        let Some(v6) = &self.net.v6 else { return };
        let mcast = ip.dst.is_multicast();
        if !(v6.ours(ip.dst) || (mcast && v6.listening(ip.dst))) || ip.src.is_multicast() {
            return;
        }
        let raw = &b[..IPV6_HDR + ip.payload.len()];
        let up = match wire6::walk(ip.next, ip.payload, IPV6_HDR, true) {
            Ok(up) => up,
            Err(ExtError::Drop) => return,
            Err(ExtError::Problem {
                code,
                pointer,
                always,
            }) => {
                if !mcast || always {
                    self.net.send_icmp6_error(
                        now,
                        tx,
                        wire6::ICMP6_PARAM_PROBLEM,
                        code,
                        pointer as u32,
                        raw,
                        mcast,
                    );
                }
                return;
            }
        };
        let verify = self.cfg.verify_checksums;
        let Some(f) = up.frag else {
            let p = Self::pkt6(
                &ip,
                up.proto,
                &ip.payload[up.offset..],
                raw,
                up.nh_field,
                src_mac,
            );
            if let Some(q) = Self::dst_port(p.proto, p.payload)
                .and_then(|port| self.dial_port_owner(p.proto, port))
            {
                self.forward.push((q, frame.to_vec()));
                return;
            }
            return self.on_packet(now, &p, verify, tx);
        };
        let data = &ip.payload[f.data..];
        if f.offset == 0 && !f.more {
            // An atomic fragment (RFC 6946): processed as is, never reassembled.
            let base = IPV6_HDR + f.data;
            match wire6::walk(f.next, data, base, false) {
                Ok(u) if u.frag.is_none() => {
                    let p = Self::pkt6(&ip, u.proto, &data[u.offset..], raw, u.nh_field, src_mac);
                    self.on_packet(now, &p, verify, tx);
                }
                _ => {}
            }
            return;
        }
        let Some(d) = self.reasm.add(
            IpAddr::V6(ip.src),
            IpAddr::V6(ip.dst),
            f.next,
            f.id,
            f.offset,
            f.more,
            data,
            now,
        ) else {
            return;
        };
        // The rest of the chain follows the fragment header in the reassembled part.
        let Ok(u) = wire6::walk(d.proto, &d.payload, IPV6_HDR, false) else {
            return;
        };
        if u.frag.is_some() {
            return; // a fragment inside a fragment
        }
        let upper = &d.payload[u.offset..];
        // Rebuild a whole packet without extension headers so the rest of the path (and
        // steering) sees one.
        let mut pkt = vec![0u8; IPV6_HDR + upper.len()];
        if upper.len() > 65535 {
            return;
        }
        wire6::write_ipv6(
            &mut pkt,
            ip.src,
            ip.dst,
            u.proto,
            ip.hop_limit,
            ip.tclass,
            upper.len(),
        );
        pkt[IPV6_HDR..].copy_from_slice(upper);
        if let Some(q) =
            Self::dst_port(u.proto, upper).and_then(|p| self.dial_port_owner(u.proto, p))
        {
            let mut fr = Vec::with_capacity(ETH_HDR + pkt.len());
            fr.extend_from_slice(&frame[..ETH_HDR]);
            fr.extend_from_slice(&pkt);
            self.forward.push((q, fr));
            return;
        }
        let Some(whole) = Ipv6::parse(&pkt) else {
            return;
        };
        let p = Self::pkt6(&whole, u.proto, whole.payload, &pkt, 6, src_mac);
        self.on_packet(now, &p, verify, tx);
    }

    fn pkt6<'a>(
        ip: &Ipv6<'a>,
        proto: u8,
        payload: &'a [u8],
        raw: &'a [u8],
        nh_field: usize,
        src_mac: Mac,
    ) -> Pkt<'a> {
        Pkt {
            src: IpAddr::V6(ip.src),
            dst: IpAddr::V6(ip.dst),
            proto,
            ecn: ip.tclass & ECN_MASK,
            hops: ip.hop_limit,
            bcast: ip.dst.is_multicast(),
            payload,
            raw,
            hdr: nh_field,
            src_mac,
            ps: wire::Pseudo::of(IpAddr::V6(ip.src), IpAddr::V6(ip.dst)),
        }
    }

    fn dst_port(proto: u8, payload: &[u8]) -> Option<u16> {
        if !(proto == PROTO_TCP || proto == PROTO_UDP) || payload.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([payload[2], payload[3]]))
    }

    fn on_packet(&mut self, now: Instant, p: &Pkt<'_>, verify: bool, tx: &mut dyn Tx) {
        match p.proto {
            PROTO_ICMP if p.src.is_ipv4() && !p.bcast => self.on_icmp(now, p, verify, tx),
            PROTO_ICMPV6 if p.src.is_ipv6() => self.on_icmp6(now, p, verify, tx),
            PROTO_UDP => self.on_udp(now, p, verify, tx),
            PROTO_TCP if !p.bcast => self.on_tcp(now, p, verify, tx),
            PROTO_ICMP | PROTO_ICMPV6 | PROTO_TCP => {}
            _ if !p.bcast => self.net.send_unreach(now, tx, Unreach::Proto, p),
            _ => {}
        }
    }

    /// An ICMP / ICMPv6 error quoting one of our datagrams or segments.
    fn on_icmp_error(&mut self, q: wire::Quoted, err: IcmpError, udp_hard: bool) {
        if q.src != self.net.src_for(q.dst) && !self.is_ours(q.src) {
            return;
        }
        let remote = SocketAddr::new(q.dst, q.dst_port);
        match q.proto {
            PROTO_UDP => {
                if udp_hard && self.udp_ports.contains(&q.src_port) {
                    self.events.push(Event::UdpUnreachable {
                        port: q.src_port,
                        remote: Box::new(remote),
                    });
                }
            }
            PROTO_TCP => {
                let Some(&idx) = self.table.get(&Key::new(q.src_port, remote)) else {
                    return;
                };
                if let Some(t) = self.slots[idx as usize].tcb.as_deref_mut() {
                    t.on_icmp_error(err, q.seq);
                }
                self.mark_dirty(idx);
                self.settle(idx);
            }
            _ => {}
        }
    }

    fn is_ours(&self, a: IpAddr) -> bool {
        match a {
            IpAddr::V4(a) => a == self.cfg.ip,
            IpAddr::V6(a) => self.net.v6.as_ref().is_some_and(|v| v.ours(a)),
        }
    }

    fn on_icmp(&mut self, now: Instant, p: &Pkt<'_>, verify: bool, tx: &mut dyn Tx) {
        let Some(m) = Icmp::parse(p.payload, verify) else {
            return;
        };
        match m.kind {
            wire::ICMP_ECHO_REQUEST if m.code == 0 => {
                let (rest, body) = (m.rest, m.body);
                let o = IpOut {
                    src: p.dst,
                    dst: p.src,
                    proto: PROTO_ICMP,
                    len: ICMP_HDR + body.len(),
                    df: false,
                    tos: 0,
                };
                self.net.send_ip(now, tx, o, &mut |b| {
                    wire::write_icmp(b, wire::ICMP_ECHO_REPLY, 0, rest, body);
                });
            }
            wire::ICMP_UNREACHABLE => {
                let Some(q) = m.quoted() else { return };
                let err = if m.code == wire::UNREACH_FRAG_NEEDED {
                    IcmpError::TooBig(u32::from(u16::from_be_bytes([m.rest[2], m.rest[3]])))
                } else {
                    IcmpError::Unreachable
                };
                let hard = matches!(
                    m.code,
                    wire::UNREACH_NET
                        | wire::UNREACH_HOST
                        | wire::UNREACH_PROTO
                        | wire::UNREACH_PORT
                );
                self.on_icmp_error(q, err, hard);
            }
            _ => {}
        }
    }

    fn on_icmp6(&mut self, now: Instant, p: &Pkt<'_>, verify: bool, tx: &mut dyn Tx) {
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (p.src, p.dst) else {
            return;
        };
        // ICMPv6 checksums are always verified: unlike TCP / UDP, the kernel next to an
        // AF_PACKET socket fills them in before the frame reaches us.
        let _ = verify;
        let Some(m) = Icmp6::parse(p.payload, src, dst, true) else {
            return;
        };
        match m.kind {
            wire6::ICMP6_ECHO_REQUEST if m.code == 0 => {
                if p.bcast && !self.net.icmp_allowed(now) {
                    return;
                }
                let Some(v6) = &self.net.v6 else { return };
                let from = if p.bcast { v6.src_for(src) } else { dst };
                let (rest, body) = (m.rest, m.body);
                let o = IpOut {
                    src: IpAddr::V6(from),
                    dst: IpAddr::V6(src),
                    proto: PROTO_ICMPV6,
                    len: ICMP6_HDR + body.len(),
                    df: false,
                    tos: 0,
                };
                self.net.send_ip(now, tx, o, &mut |b| {
                    wire6::write_icmp6(b, from, src, wire6::ICMP6_ECHO_REPLY, 0, rest, body);
                });
            }
            wire6::ND_NEIGHBOR_SOLICIT => self.on_ns(now, p, src, dst, &m, tx),
            wire6::ND_NEIGHBOR_ADVERT => {
                let Some(nd) = Nd::parse(&m, src, dst, p.hops) else {
                    return;
                };
                let Some(v6) = self.net.v6.as_mut() else {
                    return;
                };
                if v6.ours(nd.target) {
                    return; // someone else claims our address: we keep it (no DAD)
                }
                // RFC 4861 7.2.5: only updates an entry that exists (pending or resolved).
                if let Some(mac) = nd.lla {
                    if let Some(q) = v6.ndp.learn(nd.target, mac, now, false) {
                        self.net.release(tx, mac, ETHERTYPE_IPV6, q);
                    }
                }
            }
            wire6::ICMP6_PACKET_TOO_BIG => {
                let mtu = u32::from_be_bytes(m.rest);
                let Some(q) = m.quoted() else { return };
                let link = self.net.mtu;
                if let (Some(v6), IpAddr::V6(d)) = (self.net.v6.as_mut(), q.dst) {
                    v6.learn_pmtu(d, mtu as usize, link, now);
                }
                let mtu = mtu.max(wire6::MIN_MTU as u32);
                self.on_icmp_error(q, IcmpError::TooBig(mtu), false);
            }
            wire6::ICMP6_UNREACHABLE => {
                let Some(q) = m.quoted() else { return };
                let hard = matches!(
                    m.code,
                    wire6::UNREACH6_NO_ROUTE
                        | wire6::UNREACH6_ADMIN
                        | wire6::UNREACH6_ADDR
                        | wire6::UNREACH6_PORT
                );
                self.on_icmp_error(q, IcmpError::Unreachable, hard);
            }
            wire6::ICMP6_PARAM_PROBLEM if m.code == wire6::PARAM_NEXT_HEADER => {
                // The peer does not know the protocol: like IPv4's protocol unreachable.
                let Some(q) = m.quoted() else { return };
                self.on_icmp_error(q, IcmpError::Unreachable, true);
            }
            wire6::MLD_QUERY => {
                // Answer queries for all groups or ours (RFC 3810 6.2; no random delay: one
                // host, few groups).
                if let Some(v6) = self.net.v6.as_mut() {
                    v6.mld_at = Some(now);
                }
            }
            _ => {}
        }
    }

    /// Neighbor solicitation (RFC 4861 7.2.3): learn the sender, advertise our address.
    fn on_ns(
        &mut self,
        now: Instant,
        p: &Pkt<'_>,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        m: &Icmp6<'_>,
        tx: &mut dyn Tx,
    ) {
        let Some(nd) = Nd::parse(m, src, dst, p.hops) else {
            return;
        };
        let Some(v6) = self.net.v6.as_mut() else {
            return;
        };
        if !v6.ours(nd.target) {
            return;
        }
        if src.is_unspecified() {
            // Another node's duplicate address detection for our address: defend it with an
            // advertisement to all nodes (RFC 4862 5.4.3).
            let dmac = wire6::multicast_mac(wire6::ALL_NODES);
            self.net
                .send_na(tx, nd.target, wire6::ALL_NODES, dmac, wire6::NA_OVERRIDE);
            return;
        }
        if let Some(mac) = nd.lla {
            if let Some(q) = v6.ndp.learn(src, mac, now, true) {
                self.net.release(tx, mac, ETHERTYPE_IPV6, q);
            }
        }
        // Unicast reply to the sender (its link-layer option, or the frame's source for a
        // reachability probe without one).
        let dmac = nd.lla.unwrap_or(p.src_mac);
        self.net.send_na(
            tx,
            nd.target,
            src,
            dmac,
            wire6::NA_SOLICITED | wire6::NA_OVERRIDE,
        );
    }

    fn on_udp(&mut self, now: Instant, p: &Pkt<'_>, verify: bool, tx: &mut dyn Tx) {
        let Some(u) = Udp::parse_with(p.payload, p.ps, p.src.is_ipv6(), verify) else {
            return;
        };
        if !self.udp_ports.contains(&u.dst_port) {
            if !p.bcast {
                self.net.send_unreach(now, tx, Unreach::Port, p);
            }
            return;
        }
        let budget = self
            .cfg
            .udp_queue
            .saturating_mul(self.udp_ports.len().max(1));
        if self.udp_bytes + u.payload.len() > budget {
            return; // queue full: dropped, like a full socket buffer
        }
        let mut data = self.udp_pool.pop().unwrap_or_default();
        data.clear();
        data.extend_from_slice(u.payload);
        self.udp_bytes += data.len();
        self.udp_q.push_back(Datagram {
            port: u.dst_port,
            from: SocketAddr::new(p.src, u.src_port),
            ecn: p.ecn,
            data,
        });
    }

    fn send_rst_for(&mut self, now: Instant, tx: &mut dyn Tx, p: &Pkt<'_>, seg: &Tcp<'_>) {
        if seg.flags & RST != 0 {
            return;
        }
        let hdr = if seg.flags & ACK != 0 {
            TcpOut {
                src_port: seg.dst_port,
                dst_port: seg.src_port,
                seq: seg.ack,
                flags: RST,
                ..TcpOut::default()
            }
        } else {
            TcpOut {
                src_port: seg.dst_port,
                dst_port: seg.src_port,
                seq: 0,
                ack: seg.seq.wrapping_add(seg.seg_len()),
                flags: RST | ACK,
                ..TcpOut::default()
            }
        };
        let mut out = NetOut {
            net: &mut self.net,
            tx,
            now,
        };
        let ep = Endpoints::new(
            SocketAddr::new(p.dst, seg.dst_port),
            SocketAddr::new(p.src, seg.src_port),
        );
        out.segment(&ep, &hdr, (&[], &[]));
    }

    fn on_tcp(&mut self, now: Instant, p: &Pkt<'_>, verify: bool, tx: &mut dyn Tx) {
        let Some(mut seg) = Tcp::parse_with(p.payload, p.ps, verify) else {
            return;
        };
        seg.ecn = p.ecn;

        let remote = SocketAddr::new(p.src, seg.src_port);
        let key = Key::new(seg.dst_port, remote);
        let clock = self.clock(now);
        if let Some(&idx) = self.table.get(&key) {
            let slot = &mut self.slots[idx as usize];
            let tw_reopen = slot.tcb.as_deref().is_some_and(|t| {
                t.state == State::TimeWait
                    && seg.flags & (SYN | ACK | RST) == SYN
                    && self.listeners.contains_key(&seg.dst_port)
            });
            if tw_reopen {
                // RFC 6191 / RFC 1122 4.2.2.13: a new SYN for a TIME-WAIT connection reopens it.
                slot.tcb = None;
                slot.ver = slot.ver.wrapping_add(1);
                slot.dirty = false;
                self.table.remove(&key);
                self.free.push(idx);
            } else {
                if let Some(t) = slot.tcb.as_deref_mut() {
                    let mut out = NetOut {
                        net: &mut self.net,
                        tx,
                        now,
                    };
                    t.on_segment(&seg, clock, &mut out);
                }
                self.mark_dirty(idx);
                self.settle(idx);
                return;
            }
        }
        let Some(listener) = self.listeners.get(&seg.dst_port) else {
            self.send_rst_for(now, tx, p, &seg);
            return;
        };
        let local = SocketAddr::new(p.dst, seg.dst_port);
        if seg.flags & RST != 0 {
            return;
        }
        if seg.flags & ACK != 0 {
            // An ACK for no connection: a SYN-cookie handshake completing, or stale.
            if self.cfg.syn_cookies && seg.flags & SYN == 0 {
                if let Some(opts) = self.check_cookie(local, remote, &seg, clock) {
                    let iss = seg.ack.wrapping_sub(1);
                    let irs = seg.seq.wrapping_sub(1);
                    let mut tcb =
                        Tcb::from_cookie(self.cfg.tcp, local, remote, iss, irs, opts, &seg, clock);
                    tcb.listener = Some(seg.dst_port);
                    let idx = self.alloc(tcb);
                    if !seg.payload.is_empty() || seg.flags & wire::FIN != 0 {
                        if let Some(t) = self.slots[idx as usize].tcb.as_deref_mut() {
                            let mut out = NetOut {
                                net: &mut self.net,
                                tx,
                                now,
                            };
                            t.on_segment(&seg, clock, &mut out);
                        }
                    }
                    self.mark_dirty(idx);
                    self.settle(idx);
                    return;
                }
            }
            // A data segment that fails the cookie check while cookies are in use is most likely
            // a later segment of a cookie handshake whose ACK (and first data) was lost: drop it
            // (the peer retransmits the earlier one, which validates) rather than reset.
            let cookies_recent = self
                .cookie_sent
                .is_some_and(|t| now.saturating_duration_since(t) < COOKIE_LIFE);
            if !(cookies_recent && !seg.payload.is_empty()) {
                self.send_rst_for(now, tx, p, &seg);
            }
            return;
        }
        if seg.flags & SYN == 0 {
            return;
        }
        if listener.half_open >= self.cfg.backlog {
            if self.cfg.syn_cookies {
                self.send_cookie(now, tx, local, remote, &seg, clock);
            }
            return;
        }
        let iss = self.isn(local, remote, now);
        let mut tcb = Tcb::accept(self.cfg.tcp, local, remote, iss, &seg, clock);
        tcb.listener = Some(seg.dst_port);
        let idx = self.alloc(tcb);
        self.slots[idx as usize].half_open = Some(seg.dst_port);
        if let Some(l) = self.listeners.get_mut(&seg.dst_port) {
            l.half_open += 1;
        }
        self.mark_dirty(idx);
        self.settle(idx);
    }

    // ---- SYN cookies ----------------------------------------------------------------------

    fn cookie_hash(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        client_isn: u32,
        count: u32,
        mss_idx: u32,
    ) -> u32 {
        let (lp, rp) = (u32::from(local.port()), u32::from(remote.port()));
        let h = match (local.ip(), remote.ip()) {
            (IpAddr::V4(l), IpAddr::V4(r)) => self.keyed(&[
                u32::from(l),
                lp,
                u32::from(r),
                rp,
                client_isn,
                count,
                mss_idx,
                0x0c00_c1e5,
            ]),
            (l, r) => {
                let (l, r) = (words(l), words(r));
                self.keyed(&[
                    l[0],
                    l[1],
                    l[2],
                    l[3],
                    lp,
                    r[0],
                    r[1],
                    r[2],
                    r[3],
                    rp,
                    client_isn,
                    count,
                    mss_idx,
                    0x0c00_c1e5,
                ])
            }
        };
        h & 0x00ff_ffff
    }

    fn cookie_count(&self, now: Instant) -> u32 {
        ((now.saturating_duration_since(self.epoch).as_secs() / 64) & 31) as u32
    }

    /// A stateless SYN-ACK whose ISN encodes the handshake (RFC 4987 3.6): 5 bits of time,
    /// 3 bits of MSS, 24 bits of keyed hash; window scale and SACK ride in the low bits of our
    /// TSval when the peer offered timestamps.
    fn send_cookie(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        local: SocketAddr,
        remote: SocketAddr,
        syn: &Tcp<'_>,
        clock: Clock,
    ) {
        let peer_mss = syn.opts.mss.unwrap_or(536);
        let mss_idx = COOKIE_MSS.iter().rposition(|&m| m <= peer_mss).unwrap_or(0) as u32;
        let count = self.cookie_count(now);
        let h = self.cookie_hash(local, remote, syn.seq, count, mss_idx);
        let iss = (count << 27) | (mss_idx << 24) | h;
        self.cookie_sent = Some(now);
        let p = self.cfg.tcp;
        let mss = if remote.is_ipv6() {
            p.mss.saturating_sub(20)
        } else {
            p.mss
        };
        let mut opts = TcpOpts {
            mss: Some(mss),
            ..TcpOpts::default()
        };
        let mut window = 0xffffu32.min(p.rx_buf as u32);
        if let (true, Some(tsval)) = (p.timestamps, syn.opts.ts) {
            let ws = match (p.wscale, syn.opts.wscale) {
                (true, Some(w)) => u32::from(w.min(14)),
                _ => 15,
            };
            let sack = u32::from(p.sack && syn.opts.sack_perm);
            let mut ours = (clock.ts & !0x3f) | 0x20 | (sack << 4) | ws;
            if crate::net::tcp::seq_gt(ours, clock.ts) {
                // Never ahead of the clock: later segments' TSvals must not look older (PAWS).
                ours = ours.wrapping_sub(64);
            }
            opts.ts = Some((ours, tsval.0));
            opts.sack_perm = sack == 1;
            if ws != 15 {
                let mut s = 0u8;
                while s < 14 && (p.rx_buf >> s) > 0xffff {
                    s += 1;
                }
                opts.wscale = Some(s);
            }
        } else {
            window = window.min(0xffff);
        }
        let hdr = TcpOut {
            src_port: local.port(),
            dst_port: remote.port(),
            seq: iss,
            ack: syn.seq.wrapping_add(1),
            flags: SYN | ACK,
            window: window as u16,
            opts,
            ect: false,
        };
        let mut out = NetOut {
            net: &mut self.net,
            tx,
            now,
        };
        out.segment(&Endpoints::new(local, remote), &hdr, (&[], &[]));
    }

    fn check_cookie(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        ack: &Tcp<'_>,
        clock: Clock,
    ) -> Option<SynOpts> {
        let iss = ack.ack.wrapping_sub(1);
        let client_isn = ack.seq.wrapping_sub(1);
        let count = iss >> 27;
        let mss_idx = (iss >> 24) & 7;
        let now_count = self.cookie_count(clock.now);
        let age = now_count.wrapping_sub(count) & 31;
        if age > 1 {
            return None;
        }
        if self.cookie_hash(local, remote, client_isn, count, mss_idx) != iss & 0x00ff_ffff {
            return None;
        }
        let mut o = SynOpts {
            mss: Some(COOKIE_MSS[mss_idx as usize]),
            ..SynOpts::default()
        };
        if let Some((val, ecr)) = ack.opts.ts {
            if ecr & 0x20 != 0 {
                let ws = ecr & 0xf;
                o.wscale = (ws != 15).then_some(ws as u8);
                o.sack = ecr & 0x10 != 0;
                o.ts = Some(val);
            }
        }
        Some(o)
    }

    // ---- timers and output ----------------------------------------------------------------

    /// Runs due timers, sends queued output (data the owner queued, ACKs owed after a receive
    /// burst, window updates), retries ARP requests and expires reassembly.
    pub(crate) fn poll(&mut self, now: Instant, tx: &mut dyn Tx) {
        let clock = self.clock(now);
        while let Some(&Reverse((t, idx, ver))) = self.timers.peek() {
            if t > now {
                break;
            }
            self.timers.pop();
            let slot = &mut self.slots[idx as usize];
            if slot.ver != ver {
                continue;
            }
            let Some(tcb) = slot.tcb.as_deref_mut() else {
                continue;
            };
            if tcb.scheduled != Some(t) {
                continue; // superseded by an earlier entry
            }
            tcb.scheduled = None;
            let mut out = NetOut {
                net: &mut self.net,
                tx,
                now,
            };
            tcb.on_timer(clock, &mut out);
            slot.dirty = false;
            self.settle(idx);
        }
        let mut dirty = std::mem::take(&mut self.dirty);
        for &idx in &dirty {
            let slot = &mut self.slots[idx as usize];
            if !slot.dirty {
                continue;
            }
            slot.dirty = false;
            let Some(tcb) = slot.tcb.as_deref_mut() else {
                continue;
            };
            if std::mem::take(&mut slot.abort) {
                let mut out = NetOut {
                    net: &mut self.net,
                    tx,
                    now,
                };
                tcb.abort(&mut out);
            } else {
                let mut out = NetOut {
                    net: &mut self.net,
                    tx,
                    now,
                };
                tcb.output(clock, &mut out);
            }
            self.settle(idx);
        }
        dirty.clear();
        if self.dirty.is_empty() {
            self.dirty = dirty;
        }
        if self.net.arp.next_deadline().is_some_and(|t| now >= t) {
            let mut retry = std::mem::take(&mut self.arp_retry);
            let mut failed = std::mem::take(&mut self.arp_failed);
            self.net.arp.poll(now, &mut retry, &mut failed);
            for ip in retry.drain(..) {
                self.net.send_arp(tx, ARP_REQUEST, BROADCAST, [0; 6], ip);
            }
            failed.clear();
            self.arp_retry = retry;
            self.arp_failed = failed;
        }
        if self.net.v6.is_some() {
            self.poll6(now, tx);
        }
        self.reasm.expire(now);
    }

    /// The IPv6 part of `poll`: neighbor solicitation retries, the MLD report.
    #[inline(never)]
    fn poll6(&mut self, now: Instant, tx: &mut dyn Tx) {
        if let Some(v6) = self.net.v6.as_mut() {
            if v6.ndp.next_deadline().is_some_and(|t| now >= t) {
                let mut retry = std::mem::take(&mut self.nd_retry);
                let mut failed = std::mem::take(&mut self.nd_failed);
                v6.ndp.poll(now, &mut retry, &mut failed);
                for ip in retry.drain(..) {
                    self.net.send_ns(tx, ip, None);
                }
                failed.clear();
                self.nd_retry = retry;
                self.nd_failed = failed;
            }
        }
        if let Some(v6) = self.net.v6.as_mut() {
            if v6.mld_at.is_some_and(|t| now >= t) {
                v6.mld_at = None;
                self.net.send_mld_report(tx);
            }
        }
    }

    /// Connections in the table (tests, stats).
    #[cfg(test)]
    pub(crate) fn tcp_count(&self) -> usize {
        self.table.len()
    }
}
