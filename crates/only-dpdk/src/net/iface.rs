//! One stack instance (one per device queue): Ethernet / ARP / IPv4 / ICMP / UDP demultiplexing,
//! the TCP connection table and listeners, timers, and the IPv4 output path (routing, ARP
//! resolution with a pending queue, fragmentation).
//!
//! The interface never reads a clock or touches a device: the caller passes `now`, hands it
//! received frames ([`Iface::receive`]), runs [`Iface::poll`] for timers and queued output, and
//! provides a [`Tx`] for the frames it sends. That keeps it deterministic for the simulated-link
//! tests.

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    hash::{BuildHasher, Hash, Hasher, RandomState},
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use super::{
    arp::{ArpCache, Lookup},
    frag::Reassembler,
    tcp::{Clock, Notes, Params, SegOut, State, SynOpts, Tcb, TcpError},
    wire::{
        self, ACK, ARP_LEN, ARP_REPLY, ARP_REQUEST, Arp, BROADCAST, ETH_HDR, ETHERTYPE_ARP,
        ETHERTYPE_IPV4, Eth, ICMP_HDR, IP_DF, IP_MF, IPV4_HDR, Icmp, Ipv4, Mac, PROTO_ICMP,
        PROTO_TCP, PROTO_UDP, RST, SYN, Tcp, TcpOpts, TcpOut, UDP_HDR, Udp,
    },
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// ICMP port / host unreachable for a datagram sent from `port` to `remote`.
    UdpUnreachable {
        port: u16,
        remote: SocketAddrV4,
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
    from: SocketAddrV4,
    data: Vec<u8>,
}

/// Errors of the owner-facing calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallError {
    AddrInUse,
    TooBig,
    Unreachable,
}

/// A keyed, fast hasher for the connection table (randomized per interface so remote peers
/// cannot aim collisions).
#[derive(Clone, Debug)]
struct KeyedHash(u64);

impl BuildHasher for KeyedHash {
    type Hasher = MixHasher;
    fn build_hasher(&self) -> MixHasher {
        MixHasher(self.0)
    }
}

#[derive(Debug)]
struct MixHasher(u64);

impl Hasher for MixHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u16(&mut self, n: u16) {
        self.write_u64(u64::from(n));
    }
    fn write_u32(&mut self, n: u32) {
        self.write_u64(u64::from(n));
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0 ^ n)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(29);
    }
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
    fn finish(&self) -> u64 {
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

type Key = (u16, SocketAddrV4);

/// How long a SYN cookie stays valid (two 64 s counter periods).
const COOKIE_LIFE: Duration = Duration::from_secs(128);
/// SYN-cookie MSS table (3 bits).
const COOKIE_MSS: [u16; 8] = [536, 1200, 1360, 1400, 1440, 1460, 4312, 8960];
/// ICMP error budget: tokens, refilled one per `ICMP_REFILL`.
const ICMP_BURST: u32 = 50;
const ICMP_REFILL: Duration = Duration::from_millis(10);
const TTL: u8 = 64;

/// IPv4 output: addresses, routing, ARP, fragmentation.
#[derive(Debug)]
struct Net {
    mac: Mac,
    ip: Ipv4Addr,
    mask: u32,
    gateway: Option<Ipv4Addr>,
    mtu: usize,
    ip_id: u16,
    arp: ArpCache,
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

    #[allow(clippy::too_many_arguments)]
    /// Sends an IPv4 packet to `dst` whose `len`-byte payload `write` fills in. Packets larger
    /// than the MTU are fragmented (unless `df`, then dropped). Returns `false` if the packet
    /// could not be sent or queued.
    fn send_ip(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        dst: Ipv4Addr,
        proto: u8,
        len: usize,
        df: bool,
        write: &mut dyn FnMut(&mut [u8]),
    ) -> bool {
        let Some(hop) = self.next_hop(dst) else {
            return false;
        };
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
            let frag = if df { IP_DF } else { 0 };
            match mac {
                Some(mac) => {
                    let b = tx.buffer(ETH_HDR + IPV4_HDR + len);
                    wire::write_eth(b, mac, self.mac, ETHERTYPE_IPV4);
                    write(&mut b[ETH_HDR + IPV4_HDR..]);
                    wire::write_ipv4(&mut b[ETH_HDR..], self.ip, dst, proto, id, frag, TTL, len);
                    tx.commit();
                    true
                }
                None => {
                    let mut p = vec![0u8; IPV4_HDR + len];
                    write(&mut p[IPV4_HDR..]);
                    wire::write_ipv4(&mut p, self.ip, dst, proto, id, frag, TTL, len);
                    self.arp.queue_packet(hop, p)
                }
            }
        } else {
            if df {
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
                        wire::write_ipv4(&mut b[ETH_HDR..], self.ip, dst, proto, id, frag, TTL, n);
                        tx.commit();
                    }
                    None => {
                        let mut p = vec![0u8; IPV4_HDR + n];
                        p[IPV4_HDR..].copy_from_slice(piece);
                        wire::write_ipv4(&mut p, self.ip, dst, proto, id, frag, TTL, n);
                        ok &= self.arp.queue_packet(hop, p);
                    }
                }
                off += n;
            }
            self.scratch = payload;
            ok
        }
    }

    /// Sends the IP packets that waited for `mac`.
    fn release(&self, tx: &mut dyn Tx, mac: Mac, packets: VecDeque<Vec<u8>>) {
        for p in packets {
            let b = tx.buffer(ETH_HDR + p.len());
            wire::write_eth(b, mac, self.mac, ETHERTYPE_IPV4);
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

    /// ICMP error about a received datagram (`ip_header` + its payload), rate limited.
    fn send_icmp_error(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        kind: u8,
        code: u8,
        ip: &Ipv4<'_>,
    ) {
        if !self.icmp_allowed(now) {
            return;
        }
        // RFC 1812 4.3.2.3: quote as much as fits in 576 bytes.
        let quote = (ip.payload.len()).min(576 - IPV4_HDR - ICMP_HDR - ip.hdr_len);
        let body_len = ip.hdr_len + quote;
        let (hdr, payload) = (ip.header, &ip.payload[..quote]);
        self.send_ip(
            now,
            tx,
            ip.src,
            PROTO_ICMP,
            ICMP_HDR + body_len,
            false,
            &mut |b| {
                b[ICMP_HDR..ICMP_HDR + hdr.len()].copy_from_slice(hdr);
                b[ICMP_HDR + hdr.len()..ICMP_HDR + body_len].copy_from_slice(payload);
                b[0] = kind;
                b[1] = code;
                b[2..8].copy_from_slice(&[0; 6]);
                let c = wire::checksum(b);
                b[2..4].copy_from_slice(&c.to_be_bytes());
            },
        );
    }
}

/// `SegOut` over the IPv4 output path.
struct NetOut<'a> {
    net: &'a mut Net,
    tx: &'a mut dyn Tx,
    now: Instant,
}

impl SegOut for NetOut<'_> {
    fn segment(
        &mut self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        hdr: &TcpOut,
        payload: (&[u8], &[u8]),
    ) {
        let hl = hdr.header_len();
        let len = hl + payload.0.len() + payload.1.len();
        let (src, dst) = (*local.ip(), *remote.ip());
        self.net
            .send_ip(self.now, self.tx, dst, PROTO_TCP, len, true, &mut |b| {
                b[hl..hl + payload.0.len()].copy_from_slice(payload.0);
                b[hl + payload.0.len()..].copy_from_slice(payload.1);
                hdr.write(b, src, dst);
            });
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
        let net = Net {
            mac: cfg.mac,
            ip: cfg.ip,
            mask,
            gateway: cfg.gateway,
            mtu: cfg.mtu.clamp(576, 65535),
            ip_id: seed as u16,
            arp: ArpCache::default(),
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
    fn isn(&self, local: SocketAddrV4, remote: SocketAddrV4, now: Instant) -> u32 {
        let t = (now.saturating_duration_since(self.epoch).as_micros() / 4) as u32;
        self.keyed(&[
            u32::from(*local.ip()),
            u32::from(local.port()),
            u32::from(*remote.ip()),
            u32::from(remote.port()),
        ])
        .wrapping_add(t)
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
        [t, self.net.arp.next_deadline(), self.reasm.next_deadline()]
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
        let key = (tcb.local.port(), tcb.remote);
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
            let key = (tcb.local.port(), tcb.remote);
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

    /// Opens a connection from local `port` to `remote`; the SYN goes out with the next `poll`.
    pub(crate) fn tcp_connect(
        &mut self,
        port: u16,
        remote: SocketAddrV4,
        now: Instant,
    ) -> Result<TcpHandle, CallError> {
        if self.net.next_hop(*remote.ip()).is_none() {
            return Err(CallError::Unreachable);
        }
        if let Some(&idx) = self.table.get(&(port, remote)) {
            // TIME-WAIT reuse for a new connection (its ISN is larger: the clock moved on).
            match self.slots[idx as usize].tcb.as_deref() {
                Some(t) if t.state == State::TimeWait => {
                    let s = &mut self.slots[idx as usize];
                    s.tcb = None;
                    s.ver = s.ver.wrapping_add(1);
                    self.table.remove(&(port, remote));
                    self.free.push(idx);
                }
                _ => return Err(CallError::AddrInUse),
            }
        }
        let local = SocketAddrV4::new(self.cfg.ip, port);
        let iss = self.isn(local, remote, now);
        let tcb = Tcb::connect(self.cfg.tcp, local, remote, iss, self.clock(now));
        let idx = self.alloc(tcb);
        self.slots[idx as usize].known = true;
        self.mark_dirty(idx);
        Ok(self.handle(idx))
    }

    /// Whether a connection exists for `(port, remote)` (dial port selection).
    pub(crate) fn tcp_in_use(&self, port: u16, remote: SocketAddrV4) -> bool {
        self.table
            .get(&(port, remote))
            .and_then(|&i| self.slots[i as usize].tcb.as_deref())
            .is_some_and(|t| t.state != State::TimeWait)
    }

    pub(crate) fn tcp_peer(&self, h: TcpHandle) -> Option<SocketAddrV4> {
        self.slot(h).map(|t| t.remote)
    }

    pub(crate) fn tcp_local_port(&self, h: TcpHandle) -> Option<u16> {
        self.slot(h).map(|t| t.local.port())
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

    /// Sends a datagram from local `port` (fragmented if larger than the MTU).
    pub(crate) fn udp_send(
        &mut self,
        now: Instant,
        tx: &mut dyn Tx,
        port: u16,
        remote: SocketAddrV4,
        data: &[u8],
    ) -> Result<(), CallError> {
        if data.len() > 65535 - IPV4_HDR - UDP_HDR {
            return Err(CallError::TooBig);
        }
        let (src, dst) = (self.cfg.ip, *remote.ip());
        let len = UDP_HDR + data.len();
        let ok = self
            .net
            .send_ip(now, tx, dst, PROTO_UDP, len, false, &mut |b| {
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
    pub(crate) fn udp_recv(&mut self, out: &mut [u8]) -> Option<(u16, SocketAddrV4, usize)> {
        let d = self.udp_q.pop_front()?;
        self.udp_bytes -= d.data.len();
        let n = d.data.len().min(out.len());
        out[..n].copy_from_slice(&d.data[..n]);
        if self.udp_pool.len() < 256 {
            self.udp_pool.push(d.data);
        }
        Some((d.port, d.from, n))
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
        if eth.dst != self.cfg.mac && eth.dst != BROADCAST {
            return;
        }
        match eth.ethertype {
            ETHERTYPE_ARP => self.on_arp(now, eth.payload, tx),
            ETHERTYPE_IPV4 => self.on_ipv4(now, frame, eth.payload, tx),
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
            self.net.release(tx, a.sha, q);
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
        if ip.is_fragment() {
            let Some(d) = self.reasm.add(
                ip.src,
                ip.dst,
                ip.proto,
                ip.id,
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
                d.src,
                d.dst,
                d.proto,
                ip.id,
                0,
                ip.ttl,
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
            self.on_packet(now, &whole, bcast, false, tx);
            return;
        }
        if let Some(q) =
            Self::dst_port(ip.proto, ip.payload).and_then(|p| self.dial_port_owner(ip.proto, p))
        {
            self.forward.push((q, frame.to_vec()));
            return;
        }
        self.on_packet(now, &ip, bcast, verify, tx);
    }

    fn dst_port(proto: u8, payload: &[u8]) -> Option<u16> {
        if !(proto == PROTO_TCP || proto == PROTO_UDP) || payload.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([payload[2], payload[3]]))
    }

    fn on_packet(
        &mut self,
        now: Instant,
        ip: &Ipv4<'_>,
        bcast: bool,
        verify: bool,
        tx: &mut dyn Tx,
    ) {
        match ip.proto {
            PROTO_ICMP if !bcast => self.on_icmp(now, ip, verify, tx),
            PROTO_UDP => self.on_udp(now, ip, bcast, verify, tx),
            PROTO_TCP if !bcast => self.on_tcp(now, ip, verify, tx),
            PROTO_ICMP | PROTO_TCP => {}
            _ if !bcast => {
                self.net
                    .send_icmp_error(now, tx, wire::ICMP_UNREACHABLE, wire::UNREACH_PROTO, ip);
            }
            _ => {}
        }
    }

    fn on_icmp(&mut self, now: Instant, ip: &Ipv4<'_>, verify: bool, tx: &mut dyn Tx) {
        let Some(m) = Icmp::parse(ip.payload, verify) else {
            return;
        };
        match m.kind {
            wire::ICMP_ECHO_REQUEST if m.code == 0 => {
                let (rest, body) = (m.rest, m.body);
                self.net.send_ip(
                    now,
                    tx,
                    ip.src,
                    PROTO_ICMP,
                    ICMP_HDR + body.len(),
                    false,
                    &mut |b| {
                        wire::write_icmp(b, wire::ICMP_ECHO_REPLY, 0, rest, body);
                    },
                );
            }
            wire::ICMP_UNREACHABLE => {
                let Some(q) = m.quoted() else { return };
                if q.src != self.cfg.ip {
                    return;
                }
                let remote = SocketAddrV4::new(q.dst, q.dst_port);
                match q.proto {
                    PROTO_UDP => {
                        if matches!(
                            m.code,
                            wire::UNREACH_NET
                                | wire::UNREACH_HOST
                                | wire::UNREACH_PROTO
                                | wire::UNREACH_PORT
                        ) && self.udp_ports.contains(&q.src_port)
                        {
                            self.events.push(Event::UdpUnreachable {
                                port: q.src_port,
                                remote,
                            });
                        }
                    }
                    PROTO_TCP => {
                        let Some(&idx) = self.table.get(&(q.src_port, remote)) else {
                            return;
                        };
                        let next_mtu = u16::from_be_bytes([m.rest[2], m.rest[3]]);
                        if let Some(t) = self.slots[idx as usize].tcb.as_deref_mut() {
                            t.on_icmp_unreachable(m.code, next_mtu, q.seq);
                        }
                        self.mark_dirty(idx);
                        self.settle(idx);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn on_udp(&mut self, now: Instant, ip: &Ipv4<'_>, bcast: bool, verify: bool, tx: &mut dyn Tx) {
        let Some(u) = Udp::parse(ip.payload, ip.src, ip.dst, verify) else {
            return;
        };
        if !self.udp_ports.contains(&u.dst_port) {
            if !bcast {
                self.net
                    .send_icmp_error(now, tx, wire::ICMP_UNREACHABLE, wire::UNREACH_PORT, ip);
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
            from: SocketAddrV4::new(ip.src, u.src_port),
            data,
        });
    }

    fn send_rst_for(&mut self, now: Instant, tx: &mut dyn Tx, ip: &Ipv4<'_>, seg: &Tcp<'_>) {
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
        out.segment(
            SocketAddrV4::new(ip.dst, seg.dst_port),
            SocketAddrV4::new(ip.src, seg.src_port),
            &hdr,
            (&[], &[]),
        );
    }

    fn on_tcp(&mut self, now: Instant, ip: &Ipv4<'_>, verify: bool, tx: &mut dyn Tx) {
        let Some(seg) = Tcp::parse(ip.payload, ip.src, ip.dst, verify) else {
            return;
        };

        let remote = SocketAddrV4::new(ip.src, seg.src_port);
        let key = (seg.dst_port, remote);
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
            self.send_rst_for(now, tx, ip, &seg);
            return;
        };
        let local = SocketAddrV4::new(self.cfg.ip, seg.dst_port);
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
                self.send_rst_for(now, tx, ip, &seg);
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
        local: SocketAddrV4,
        remote: SocketAddrV4,
        client_isn: u32,
        count: u32,
        mss_idx: u32,
    ) -> u32 {
        self.keyed(&[
            u32::from(*local.ip()),
            u32::from(local.port()),
            u32::from(*remote.ip()),
            u32::from(remote.port()),
            client_isn,
            count,
            mss_idx,
            0x0c00_c1e5,
        ]) & 0x00ff_ffff
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
        local: SocketAddrV4,
        remote: SocketAddrV4,
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
        let mut opts = TcpOpts {
            mss: Some(p.mss),
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
        };
        let mut out = NetOut {
            net: &mut self.net,
            tx,
            now,
        };
        out.segment(local, remote, &hdr, (&[], &[]));
    }

    fn check_cookie(
        &self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
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
        self.reasm.expire(now);
    }

    /// Connections in the table (tests, stats).
    #[cfg(test)]
    pub(crate) fn tcp_count(&self) -> usize {
        self.table.len()
    }
}
