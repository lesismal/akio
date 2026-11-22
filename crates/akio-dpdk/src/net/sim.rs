//! Two interfaces over a simulated Ethernet link in virtual time: propagation delay, a
//! bandwidth-limited drop-tail bottleneck queue, random loss and reordering. Deterministic
//! (seeded PRNG), so TCP correctness and throughput are tested reproducibly.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use super::{
    CcKind, Config, Event, Iface, Params, TcpError, TcpHandle, Tx,
    tcp::State,
    wire::{self, ETH_HDR, Eth, Ipv4, Tcp},
    wire6,
};

pub(super) const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub(super) const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub(super) const A6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
pub(super) const B6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

/// A socket address of either family.
pub(super) fn sa(ip: impl Into<IpAddr>, port: u16) -> SocketAddr {
    SocketAddr::new(ip.into(), port)
}
const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];

/// Collects transmitted frames.
#[derive(Default)]
struct Cap(Vec<Vec<u8>>);

impl Tx for Cap {
    fn buffer(&mut self, len: usize) -> &mut [u8] {
        self.0.push(vec![0; len]);
        self.0.last_mut().expect("just pushed")
    }
    fn commit(&mut self) {}
}

/// xorshift64*.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn chance(&mut self, p: f64) -> bool {
        p > 0.0 && (self.next() >> 11) as f64 / (1u64 << 53) as f64 <= p
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LinkCfg {
    pub(super) delay: Duration,
    /// Bytes per second (0: unlimited).
    pub(super) rate: u64,
    /// Frames the bottleneck queue holds (drop-tail).
    pub(super) queue: usize,
    pub(super) loss: f64,
    /// Probability a frame is delayed by up to `reorder_by` extra (reordering).
    pub(super) reorder: f64,
    pub(super) reorder_by: Duration,
    /// ECN: mark ECN-capable frames CE instead of queueing them past this many frames
    /// (0: no marking), like a RED / CoDel AQM.
    pub(super) ce_mark: usize,
}

impl Default for LinkCfg {
    fn default() -> LinkCfg {
        LinkCfg {
            delay: Duration::from_millis(1),
            rate: 0,
            queue: 1000,
            loss: 0.0,
            reorder: 0.0,
            reorder_by: Duration::ZERO,
            ce_mark: 0,
        }
    }
}

/// Drops the frames it returns true for.
type Filter = Box<dyn FnMut(&[u8]) -> bool>;

/// One direction of the link.
struct Dir {
    cfg: LinkCfg,
    /// (deliver at, sequence, frame).
    flight: BinaryHeap<Reverse<(Instant, u64, Vec<u8>)>>,
    busy_until: Instant,
    queued: Vec<Instant>,
    pub(super) dropped: u64,
    pub(super) sent: u64,
    /// Frames marked CE.
    pub(super) marked: u64,
    /// Drop the frames for which this returns true (targeted loss).
    filter: Option<Filter>,
    /// Every frame sent, when capturing.
    log: Option<Vec<Vec<u8>>>,
}

impl Dir {
    fn new(cfg: LinkCfg, now: Instant) -> Dir {
        Dir {
            cfg,
            flight: BinaryHeap::new(),
            busy_until: now,
            queued: Vec::new(),
            dropped: 0,
            sent: 0,
            marked: 0,
            filter: None,
            log: None,
        }
    }

    fn push(&mut self, now: Instant, mut frame: Vec<u8>, rng: &mut Rng, seq: u64) {
        self.sent += 1;
        if let Some(l) = &mut self.log {
            l.push(frame.clone());
        }
        if let Some(f) = &mut self.filter {
            if f(&frame) {
                self.dropped += 1;
                return;
            }
        }
        if rng.chance(self.cfg.loss) {
            self.dropped += 1;
            return;
        }
        let mut at = now;
        if let Some(per_byte) = 1_000_000_000u64.checked_div(self.cfg.rate) {
            self.queued.retain(|&t| t > now);
            if self.queued.len() >= self.cfg.queue {
                self.dropped += 1;
                return;
            }
            if self.cfg.ce_mark > 0 && self.queued.len() >= self.cfg.ce_mark && mark_ce(&mut frame)
            {
                self.marked += 1;
            }
            let tx_time = Duration::from_nanos(frame.len() as u64 * per_byte);
            let start = self.busy_until.max(now);
            self.busy_until = start + tx_time;
            self.queued.push(self.busy_until);
            at = self.busy_until;
        }
        at += self.cfg.delay;
        if rng.chance(self.cfg.reorder) {
            let extra = self.cfg.reorder_by.as_nanos() as u64;
            at += Duration::from_nanos(rng.next() % extra.max(1));
        }
        self.flight.push(Reverse((at, seq, frame)));
    }
}

/// Sets CE on an ECN-capable IP frame (fixing the IPv4 header checksum); `false` if the frame
/// is not ECN-capable.
fn mark_ce(f: &mut [u8]) -> bool {
    let Some(eth) = Eth::parse(f) else {
        return false;
    };
    match eth.ethertype {
        wire::ETHERTYPE_IPV4 if f.len() >= ETH_HDR + 20 => {
            let tos = f[ETH_HDR + 1];
            if tos & wire::ECN_MASK == 0 {
                return false;
            }
            f[ETH_HDR + 1] = tos | wire::ECN_CE;
            f[ETH_HDR + 10] = 0;
            f[ETH_HDR + 11] = 0;
            let hl = usize::from(f[ETH_HDR] & 0x0f) * 4;
            let c = wire::checksum(&f[ETH_HDR..ETH_HDR + hl]);
            f[ETH_HDR + 10..ETH_HDR + 12].copy_from_slice(&c.to_be_bytes());
            true
        }
        wire::ETHERTYPE_IPV6 if f.len() >= ETH_HDR + 40 => {
            // Traffic class: low nibble of byte 0, high nibble of byte 1; ECN is its low 2 bits.
            if (f[ETH_HDR + 1] >> 4) & wire::ECN_MASK == 0 {
                return false;
            }
            f[ETH_HDR + 1] |= wire::ECN_CE << 4;
            true
        }
        _ => false,
    }
}

pub(super) struct Sim {
    pub(super) now: Instant,
    pub(super) a: Iface,
    pub(super) b: Iface,
    ab: Dir,
    ba: Dir,
    rng: Rng,
    seq: u64,
    pub(super) ev_a: Vec<Event>,
    pub(super) ev_b: Vec<Event>,
}

pub(super) fn params() -> Params {
    Params {
        mss: 1460,
        rx_buf: 64 << 10,
        tx_buf: 64 << 10,
        cc: CcKind::Cubic,
        keepalive: None,
        time_wait: Duration::from_secs(60),
        wscale: true,
        timestamps: true,
        sack: true,
        ecn: false,
        accecn: false,
        pacing: false,
    }
}

pub(super) fn config(ip: Ipv4Addr, mac: [u8; 6], p: Params) -> Config {
    Config {
        mac,
        ip,
        prefix_len: 24,
        gateway: None,
        ip6: None,
        prefix_len6: 64,
        gateway6: None,
        slaac: false,
        dad: false,
        mtu: 1500,
        tcp: p,
        backlog: 64,
        syn_cookies: true,
        udp_queue: 1 << 20,
        verify_checksums: true,
        queue: 0,
        queues: 1,
        dial_first: 49152,
        seed: Some(u64::from(mac[5])),
    }
}

impl Sim {
    pub(super) fn new(link: LinkCfg, pa: Params, pb: Params) -> Sim {
        Sim::with(link, config(A, MAC_A, pa), config(B, MAC_B, pb))
    }

    /// Both ends dual-stack (`A6` / `B6` in `fd00::/64`, plus link-local addresses).
    pub(super) fn new6(link: LinkCfg, pa: Params, pb: Params) -> Sim {
        let mut ca = config(A, MAC_A, pa);
        let mut cb = config(B, MAC_B, pb);
        ca.ip6 = Some(A6);
        cb.ip6 = Some(B6);
        Sim::with(link, ca, cb)
    }

    pub(super) fn with(link: LinkCfg, ca: Config, cb: Config) -> Sim {
        let now = Instant::now();
        Sim {
            now,
            a: Iface::new(ca, now),
            b: Iface::new(cb, now),
            ab: Dir::new(link, now),
            ba: Dir::new(link, now),
            rng: Rng(0x1234_5678_9abc_def1),
            seq: 0,
            ev_a: Vec::new(),
            ev_b: Vec::new(),
        }
    }

    /// Drops frames from A to B matching `f`.
    pub(super) fn filter_ab(&mut self, f: impl FnMut(&[u8]) -> bool + 'static) {
        self.ab.filter = Some(Box::new(f));
    }

    /// Drops frames from B to A matching `f`.
    pub(super) fn filter_ba(&mut self, f: impl FnMut(&[u8]) -> bool + 'static) {
        self.ba.filter = Some(Box::new(f));
    }

    pub(super) fn dropped(&self) -> (u64, u64) {
        (self.ab.dropped, self.ba.dropped)
    }

    /// Frames A sent, and of them marked CE.
    pub(super) fn ab_stats(&self) -> (u64, u64) {
        (self.ab.sent, self.ab.marked)
    }

    /// Puts frames A transmitted outside `poll` on the link.
    fn out_a(&mut self, cap: Cap) {
        for f in cap.0 {
            self.seq += 1;
            self.ab.push(self.now, f, &mut self.rng, self.seq);
        }
    }

    /// Puts frames B transmitted outside `poll` on the link.
    fn out_b(&mut self, cap: Cap) {
        for f in cap.0 {
            self.seq += 1;
            self.ba.push(self.now, f, &mut self.rng, self.seq);
        }
    }

    /// Runs `poll` on both sides and moves their frames onto the link.
    fn flush(&mut self) {
        let mut cap = Cap::default();
        self.a.poll(self.now, &mut cap);
        for f in cap.0.drain(..) {
            self.seq += 1;
            self.ab.push(self.now, f, &mut self.rng, self.seq);
        }
        self.b.poll(self.now, &mut cap);
        for f in cap.0.drain(..) {
            self.seq += 1;
            self.ba.push(self.now, f, &mut self.rng, self.seq);
        }
        self.a.take_events(&mut self.ev_a);
        self.b.take_events(&mut self.ev_b);
    }

    /// Advances to the next thing that happens (a frame arriving, a timer), at most `max`
    /// ahead; delivers due frames; polls both sides. Returns false if nothing is pending.
    pub(super) fn step(&mut self, max: Duration) -> bool {
        self.flush();
        let next = [
            self.ab.flight.peek().map(|Reverse((t, _, _))| *t),
            self.ba.flight.peek().map(|Reverse((t, _, _))| *t),
            self.a.next_deadline(),
            self.b.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        let limit = self.now + max;
        let Some(next) = next else {
            self.now = limit;
            return false;
        };
        self.now = next.min(limit).max(self.now);
        let mut cap = Cap::default();
        while self
            .ab
            .flight
            .peek()
            .is_some_and(|Reverse((t, _, _))| *t <= self.now)
        {
            let Reverse((_, _, f)) = self.ab.flight.pop().expect("peeked");
            self.b.receive(self.now, &f, &mut cap);
        }
        for f in cap.0.drain(..) {
            self.seq += 1;
            self.ba.push(self.now, f, &mut self.rng, self.seq);
        }
        while self
            .ba
            .flight
            .peek()
            .is_some_and(|Reverse((t, _, _))| *t <= self.now)
        {
            let Reverse((_, _, f)) = self.ba.flight.pop().expect("peeked");
            self.a.receive(self.now, &f, &mut cap);
        }
        for f in cap.0.drain(..) {
            self.seq += 1;
            self.ab.push(self.now, f, &mut self.rng, self.seq);
        }
        self.flush();
        true
    }

    /// Steps until `done` holds or `limit` of virtual time passed; returns whether it held.
    pub(super) fn run_until(
        &mut self,
        limit: Duration,
        mut done: impl FnMut(&mut Sim) -> bool,
    ) -> bool {
        let end = self.now + limit;
        while self.now < end {
            if done(self) {
                return true;
            }
            self.step(Duration::from_millis(50));
        }
        done(self)
    }

    /// A connects to B's listener on `port`; returns (A's handle, B's handle).
    pub(super) fn connect(&mut self, port: u16, local: u16) -> (TcpHandle, TcpHandle) {
        self.connect_to(IpAddr::V4(B), port, local)
    }

    /// A connects to B at `to` (either family) on `port`.
    pub(super) fn connect_to(
        &mut self,
        to: IpAddr,
        port: u16,
        local: u16,
    ) -> (TcpHandle, TcpHandle) {
        self.b.tcp_listen(port);
        let ha = self
            .a
            .tcp_connect(local, sa(to, port), self.now)
            .expect("connect");
        let mut hb = None;
        let mut up = false;
        let ok = self.run_until(Duration::from_secs(10), |s| {
            for e in s.ev_b.drain(..) {
                if let Event::Accepted { h, .. } = e {
                    hb = Some(h);
                }
            }
            for e in s.ev_a.drain(..) {
                if e == Event::Connected(ha) {
                    up = true;
                }
            }
            up && hb.is_some()
        });
        assert!(ok, "handshake did not complete");
        (ha, hb.expect("accepted"))
    }

    /// Moves `data` from A (`ha`) to B (`hb`); returns the virtual time it took.
    pub(super) fn transfer(
        &mut self,
        ha: TcpHandle,
        hb: TcpHandle,
        data: &[u8],
        limit: Duration,
    ) -> Duration {
        let t0 = self.now;
        let mut sent = 0;
        let mut got = Vec::with_capacity(data.len());
        let mut buf = vec![0u8; 64 << 10];
        let ok = self.run_until(limit, |s| {
            if sent < data.len() {
                sent += s.a.tcp_send(ha, &data[sent..]);
            }
            loop {
                let n = s.b.tcp_recv(hb, &mut buf);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            s.ev_a.clear();
            s.ev_b.clear();
            got.len() >= data.len()
        });
        assert!(
            ok,
            "transfer stalled: {} of {} bytes after {:?}",
            got.len(),
            data.len(),
            limit
        );
        assert!(got == data, "data corrupted");
        let took = self.now - t0;
        eprintln!(
            "transfer: {} bytes in {took:?} ({:.1} MB/s), link drops {:?}",
            data.len(),
            data.len() as f64 / took.as_secs_f64().max(1e-9) / 1e6,
            self.dropped()
        );
        took
    }
}

/// A capture of a whole exchange (ARP, handshake with options, data with loss so SACK blocks
/// appear, a fragmented UDP datagram, ICMP port unreachable, orderly close), as (A -> B,
/// B -> A) frames: the fuzz seeds.
pub(crate) fn capture() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let link = LinkCfg {
        loss: 0.03,
        ..LinkCfg::default()
    };
    let mut s = Sim::new(link, params(), params());
    s.ab.log = Some(Vec::new());
    s.ba.log = Some(Vec::new());
    let (ha, hb) = s.connect(80, 50000);
    s.transfer(ha, hb, &pattern(64 << 10), Duration::from_secs(30));
    s.a.udp_bind(5000);
    s.b.udp_bind(53);
    let mut cap = Cap::default();
    let _ =
        s.a.udp_send(s.now, &mut cap, 5000, sa(B, 53), &pattern(3000));
    let _ =
        s.a.udp_send(s.now, &mut cap, 5000, sa(B, 54), b"closed port");
    s.out_a(cap);
    s.run_until(Duration::from_millis(100), |_| false);
    s.a.tcp_close(ha, s.now);
    s.b.tcp_close(hb, s.now);
    s.run_until(Duration::from_secs(1), |_| false);
    (
        s.ab.log.take().unwrap_or_default(),
        s.ba.log.take().unwrap_or_default(),
    )
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// TCP segments of a frame (either family): (flags, seq, payload length).
fn tcp_of(frame: &[u8]) -> Option<(u8, u32, usize)> {
    let eth = Eth::parse(frame)?;
    let (src, dst, payload) = match eth.ethertype {
        wire::ETHERTYPE_IPV4 => {
            let ip = Ipv4::parse(eth.payload, false)?;
            if ip.proto != wire::PROTO_TCP {
                return None;
            }
            (IpAddr::V4(ip.src), IpAddr::V4(ip.dst), ip.payload)
        }
        wire::ETHERTYPE_IPV6 => {
            let ip = wire6::Ipv6::parse(eth.payload)?;
            if ip.next != wire::PROTO_TCP {
                return None;
            }
            (IpAddr::V6(ip.src), IpAddr::V6(ip.dst), ip.payload)
        }
        _ => return None,
    };
    let t = Tcp::parse(payload, src, dst, false)?;
    Some((t.flags, t.seq, t.payload.len()))
}

#[test]
fn handshake_without_arp_delay() {
    // The first SYN waits in the ARP queue instead of being dropped: the connection is up in
    // about two round trips (ARP + handshake), not after a 1 s SYN retransmission.
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    let t0 = s.now;
    let (ha, hb) = s.connect(80, 50000);
    let took = s.now - t0;
    assert!(took < Duration::from_millis(10), "handshake took {took:?}");
    let (_, _, sack, ts, ws) = s.a.tcb(ha).unwrap().snapshot();
    assert!(sack && ts && ws, "options negotiated (client)");
    let (_, _, sack, ts, ws) = s.b.tcb(hb).unwrap().snapshot();
    assert!(sack && ts && ws, "options negotiated (server)");
}

#[test]
fn bulk_transfer_clean_link() {
    let link = LinkCfg {
        delay: Duration::from_millis(1),
        rate: 125_000_000, // 1 Gbit/s
        queue: 200,
        ..LinkCfg::default()
    };
    let mut s = Sim::new(link, params(), params());
    let (ha, hb) = s.connect(80, 50000);
    let data = pattern(8 << 20);
    let took = s.transfer(ha, hb, &data, Duration::from_secs(60));
    // 64 KiB window over a 2 ms RTT bounds throughput at ~32 MB/s.
    let mbps = data.len() as f64 / took.as_secs_f64() / 1e6;
    assert!(mbps > 20.0, "{mbps:.1} MB/s in {took:?}");
}

#[test]
fn window_scaling_fills_a_long_fat_pipe() {
    let link = LinkCfg {
        delay: Duration::from_millis(25), // 50 ms RTT
        rate: 12_500_000,                 // 100 Mbit/s
        queue: 1000,
        ..LinkCfg::default()
    };
    let mut p = params();
    p.rx_buf = 4 << 20;
    p.tx_buf = 4 << 20;
    let mut s = Sim::new(link, p, p);
    let (ha, hb) = s.connect(80, 50000);
    let tcb = s.a.tcb(ha).unwrap();
    assert!(tcb.snapshot().4);
    let data = pattern(32 << 20);
    let took = s.transfer(ha, hb, &data, Duration::from_secs(120));
    let mbps = data.len() as f64 / took.as_secs_f64() / 1e6;
    // Without window scaling this would be capped at 64 KiB / 50 ms = 1.3 MB/s.
    assert!(mbps > 8.0, "{mbps:.1} MB/s in {took:?}");
}

fn lossy(loss: f64, sack: bool, cc: CcKind) -> (f64, (u64, u64)) {
    let link = LinkCfg {
        delay: Duration::from_millis(5),
        rate: 12_500_000,
        queue: 100,
        loss,
        reorder: 0.02,
        reorder_by: Duration::from_millis(3),
        ..LinkCfg::default()
    };
    let mut p = params();
    p.sack = sack;
    p.cc = cc;
    p.rx_buf = 512 << 10;
    p.tx_buf = 512 << 10;
    let mut s = Sim::new(link, p, p);
    let (ha, hb) = s.connect(80, 50000);
    let data = pattern(4 << 20);
    let took = s.transfer(ha, hb, &data, Duration::from_secs(300));
    (data.len() as f64 / took.as_secs_f64() / 1e6, s.dropped())
}

#[test]
fn lossy_reordering_link_sack_cubic() {
    let (mbps, dropped) = lossy(0.02, true, CcKind::Cubic);
    assert!(dropped.0 > 50, "the link dropped {dropped:?}");
    assert!(mbps > 0.5, "{mbps:.2} MB/s");
}

#[test]
fn lossy_reordering_link_newreno_without_sack() {
    let (mbps, dropped) = lossy(0.02, false, CcKind::NewReno);
    assert!(dropped.0 > 50);
    assert!(mbps > 0.2, "{mbps:.2} MB/s");
}

#[test]
fn lossy_link_both_directions_heavy() {
    // 10% loss each way, data and ACKs: still correct, just slow.
    let link = LinkCfg {
        delay: Duration::from_millis(2),
        loss: 0.10,
        reorder: 0.1,
        reorder_by: Duration::from_millis(5),
        ..LinkCfg::default()
    };
    let mut s = Sim::new(link, params(), params());
    let (ha, hb) = s.connect(80, 50000);
    let data = pattern(512 << 10);
    s.transfer(ha, hb, &data, Duration::from_secs(600));
}

#[test]
fn sack_recovers_a_burst_loss_in_one_round_trip() {
    let link = LinkCfg {
        delay: Duration::from_millis(10),
        ..LinkCfg::default()
    };
    let mut p = params();
    p.rx_buf = 1 << 20;
    p.tx_buf = 1 << 20;
    let mut s = Sim::new(link, p, p);
    let (ha, hb) = s.connect(80, 50000);
    // Grow cwnd first.
    s.transfer(ha, hb, &pattern(2 << 20), Duration::from_secs(30));
    // Drop three non-adjacent data segments of the next flight, once each.
    let mut seen = 0u32;
    let mut dropped = Vec::new();
    s.filter_ab(move |f| {
        if let Some((_, seq, len)) = tcp_of(f) {
            if len > 0 {
                seen += 1;
                if matches!(seen, 5 | 9 | 13) && !dropped.contains(&seq) {
                    dropped.push(seq);
                    return true;
                }
            }
        }
        false
    });
    let took = s.transfer(ha, hb, &pattern(256 << 10), Duration::from_secs(30));
    // No retransmission timeout (>= 200 ms): SACK repaired all three holes.
    assert!(took < Duration::from_millis(150), "took {took:?}");
    assert_eq!(s.dropped().0, 3);
    let st = s.a.tcb(ha).unwrap().snapshot();
    assert!(st.1 < u32::MAX, "entered recovery (ssthresh {})", st.1);
}

#[test]
fn rto_recovers_a_lost_tail() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    let (ha, hb) = s.connect(80, 50000);
    // Lose the only segment of a short message once: only the timer can repair it.
    let mut first = true;
    s.filter_ab(move |f| {
        if let Some((_, _, len)) = tcp_of(f) {
            if len > 0 && first {
                first = false;
                return true;
            }
        }
        false
    });
    let took = s.transfer(ha, hb, b"tail", Duration::from_secs(10));
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_secs(2),
        "{took:?}"
    );
}

#[test]
fn orderly_close_and_time_wait() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    let (ha, hb) = s.connect(80, 50000);
    s.transfer(ha, hb, b"bye", Duration::from_secs(1));
    s.a.tcp_close(ha, s.now);
    let ok = s.run_until(Duration::from_secs(1), |s| s.b.tcp_eof(hb));
    assert!(ok, "B saw the FIN");
    assert_eq!(s.b.tcp_state(hb), Some(State::CloseWait));
    s.b.tcp_close(hb, s.now);
    s.run_until(Duration::from_secs(1), |s| s.b.tcp_count() == 0);
    assert_eq!(s.b.tcp_count(), 0, "LAST-ACK finished");
    // A is in TIME-WAIT (its handle was released at close) until 2 MSL.
    assert_eq!(s.a.tcp_count(), 1);
    s.run_until(Duration::from_secs(61), |s| s.a.tcp_count() == 0);
    assert_eq!(s.a.tcp_count(), 0);
}

#[test]
fn simultaneous_close() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    let (ha, hb) = s.connect(80, 50000);
    s.a.tcp_close(ha, s.now);
    s.b.tcp_close(hb, s.now);
    s.run_until(Duration::from_secs(1), |_| false);
    // Both went through CLOSING to TIME-WAIT.
    assert_eq!((s.a.tcp_count(), s.b.tcp_count()), (1, 1));
    s.run_until(Duration::from_secs(61), |_| false);
    assert_eq!((s.a.tcp_count(), s.b.tcp_count()), (0, 0));
}

#[test]
fn refused_and_reset() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    let h = s.a.tcp_connect(50000, sa(B, 81), s.now).unwrap();
    let mut failed = None;
    s.run_until(Duration::from_secs(2), |s| {
        for e in s.ev_a.drain(..) {
            if let Event::ConnectFailed(x, err) = e {
                assert_eq!(x, h);
                failed = Some(err);
            }
        }
        failed.is_some()
    });
    assert_eq!(failed, Some(TcpError::Refused));
    // An abort resets the peer.
    let (ha, hb) = s.connect(80, 50001);
    let mut cap = Cap::default();
    s.a.tcp_abort(ha, s.now, &mut cap);
    assert_eq!(cap.0.len(), 1);
    s.out_a(cap);
    let mut closed = None;
    s.run_until(Duration::from_secs(1), |s| {
        for e in s.ev_b.drain(..) {
            if let Event::Closed(h, err) = e {
                assert_eq!(h, hb);
                closed = Some(err);
            }
        }
        closed.is_some()
    });
    assert_eq!(closed, Some(Some(TcpError::Reset)));
    assert_eq!(s.a.tcp_state(ha), None, "the aborted handle is stale");
}

#[test]
fn syn_cookies_when_the_backlog_is_full() {
    let mut cb = config(B, MAC_B, params());
    cb.backlog = 0; // every handshake goes through a cookie
    let mut s = Sim::with(LinkCfg::default(), config(A, MAC_A, params()), cb);
    s.b.tcp_listen(80);
    let hs: Vec<TcpHandle> = (0..20)
        .map(|i| s.a.tcp_connect(50000 + i, sa(B, 80), s.now).unwrap())
        .collect();
    let mut accepted = Vec::new();
    let mut connected = 0;
    s.run_until(Duration::from_secs(5), |s| {
        for e in s.ev_b.drain(..) {
            if let Event::Accepted { h, .. } = e {
                accepted.push(h);
            }
        }
        for e in s.ev_a.drain(..) {
            if matches!(e, Event::Connected(_)) {
                connected += 1;
            }
        }
        accepted.len() == 20 && connected == 20
    });
    assert_eq!((accepted.len(), connected), (20, 20));
    // Options survive the cookie (timestamps carry wscale and SACK).
    let (_, _, sack, ts, ws) = s.b.tcb(accepted[0]).unwrap().snapshot();
    assert!(sack && ts && ws);
    // Data flows both ways on a cookie connection.
    let data = pattern(300 << 10);
    s.transfer(hs[3], accepted[3], &data, Duration::from_secs(10));
    let back = pattern(100 << 10);
    // B -> A
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 65536];
    let (ha, hb) = (hs[3], accepted[3]);
    s.run_until(Duration::from_secs(10), |s| {
        sent += s.b.tcp_send(hb, &back[sent..]);
        loop {
            let n = s.a.tcp_recv(ha, &mut buf);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got.len() == back.len()
    });
    assert!(got == back);
}

#[test]
fn zero_window_and_persist() {
    let mut p = params();
    p.rx_buf = 8 << 10;
    let mut s = Sim::new(LinkCfg::default(), params(), p);
    let (ha, hb) = s.connect(80, 50000);
    let data = pattern(64 << 10);
    let mut sent = s.a.tcp_send(ha, &data);
    // B does not read for 3 s: the window closes, A probes.
    s.run_until(Duration::from_secs(3), |_| false);
    assert_eq!(s.b.tcp_readable(hb), 8 << 10);
    assert_eq!(s.a.tcb(ha).unwrap().snd_wnd(), 0);
    let mut got = Vec::new();
    let mut buf = vec![0u8; 4096];
    let ok = s.run_until(Duration::from_secs(10), |s| {
        if sent < data.len() {
            sent += s.a.tcp_send(ha, &data[sent..]);
        }
        loop {
            let n = s.b.tcp_recv(hb, &mut buf);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got.len() == data.len()
    });
    assert!(ok && got == data, "{} bytes", got.len());
}

#[test]
fn keepalive_detects_a_dead_peer() {
    let mut p = params();
    p.keepalive = Some(Duration::from_secs(10));
    let mut s = Sim::new(LinkCfg::default(), p, params());
    let (ha, _hb) = s.connect(80, 50000);
    // Keepalives are answered while B is up.
    s.run_until(Duration::from_secs(60), |_| false);
    assert_eq!(s.a.tcp_state(ha), Some(State::Established));
    // B vanishes.
    s.filter_ab(|_| true);
    let mut closed = None;
    s.run_until(Duration::from_secs(800), |s| {
        for e in s.ev_a.drain(..) {
            if let Event::Closed(_, err) = e {
                closed = Some(err);
            }
        }
        closed.is_some()
    });
    assert_eq!(closed, Some(Some(TcpError::TimedOut)));
}

#[test]
fn many_connections_with_timers() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    s.b.tcp_listen(80);
    let n = 2000u16;
    let hs: Vec<TcpHandle> = (0..n)
        .map(|i| s.a.tcp_connect(20000 + i, sa(B, 80), s.now).unwrap())
        .collect();
    let mut acc = Vec::new();
    s.run_until(Duration::from_secs(10), |s| {
        for e in s.ev_b.drain(..) {
            if let Event::Accepted { h, .. } = e {
                acc.push(h);
            }
        }
        s.ev_a.clear();
        acc.len() == usize::from(n)
    });
    assert_eq!(acc.len(), usize::from(n));
    for &h in &hs {
        assert_eq!(s.a.tcp_send(h, b"ping"), 4);
    }
    let mut buf = [0u8; 16];
    let mut got = 0;
    s.run_until(Duration::from_secs(10), |s| {
        for &h in &acc {
            got += s.b.tcp_recv(h, &mut buf);
        }
        got == usize::from(n) * 4
    });
    assert_eq!(got, usize::from(n) * 4);
    // Idle connections hold no timers that keep firing: the heap drains.
    s.run_until(Duration::from_secs(5), |_| false);
    assert!(s.a.next_deadline().is_none(), "{:?}", s.a.next_deadline());
}

#[test]
fn udp_ecn_codepoints_both_ways() {
    for v6 in [false, true] {
        let (mut s, a, b) = if v6 {
            (
                Sim::new6(LinkCfg::default(), params(), params()),
                IpAddr::from(A6),
                IpAddr::from(B6),
            )
        } else {
            (
                Sim::new(LinkCfg::default(), params(), params()),
                IpAddr::from(A),
                IpAddr::from(B),
            )
        };
        s.a.udp_bind(5000);
        s.b.udp_bind(6000);
        let mut cap = Cap::default();
        for (i, ecn) in [2u8, 1, 3, 0, 0b110].into_iter().enumerate() {
            s.a.udp_send_ecn(s.now, &mut cap, 5000, sa(b, 6000), &[i as u8; 100], ecn)
                .unwrap();
        }
        s.out_a(std::mem::take(&mut cap));
        let mut buf = vec![0u8; 2048];
        let mut got = Vec::new();
        s.run_until(Duration::from_secs(1), |s| {
            while let Some((port, from, n, ecn)) = s.b.udp_recv_ecn(&mut buf) {
                assert_eq!((port, from, n), (6000, sa(a, 5000), 100));
                got.push((buf[0], ecn));
            }
            got.len() == 5
        });
        // Only the low two bits are sent.
        assert_eq!(got, [(0, 2), (1, 1), (2, 3), (3, 0), (4, 2)], "v6={v6}");
        // And back, through the plain call: not ECN-capable.
        s.b.udp_send(s.now, &mut cap, 6000, sa(a, 5000), b"x")
            .unwrap();
        s.out_b(std::mem::take(&mut cap));
        let mut back = None;
        s.run_until(Duration::from_secs(1), |s| {
            back = s.a.udp_recv_ecn(&mut buf).map(|r| r.3);
            back.is_some()
        });
        assert_eq!(back, Some(0));
    }
}

#[test]
fn udp_fragmentation_and_port_unreachable() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    s.a.udp_bind(5000);
    s.b.udp_bind(6000);
    let big = pattern(20_000);
    let mut cap = Cap::default();
    s.a.udp_send(s.now, &mut cap, 5000, sa(B, 6000), &big)
        .unwrap();
    s.out_a(std::mem::take(&mut cap));
    let mut buf = vec![0u8; 65536];
    let mut got = None;
    s.run_until(Duration::from_secs(2), |s| {
        if let Some((port, from, n)) = s.b.udp_recv(&mut buf) {
            got = Some((port, from, buf[..n].to_vec()));
        }
        got.is_some()
    });
    let (port, from, data) = got.expect("datagram");
    assert_eq!((port, from), (6000, sa(A, 5000)));
    assert!(data == big);
    // To a closed port: ICMP port unreachable comes back as an event.
    s.a.udp_send(s.now, &mut cap, 5000, sa(B, 6001), b"x")
        .unwrap();
    s.out_a(cap);
    let mut unreachable = false;
    s.run_until(Duration::from_secs(1), |s| {
        unreachable |= s.ev_a.contains(&Event::UdpUnreachable {
            port: 5000,
            remote: Box::new(sa(B, 6001)),
        });
        unreachable
    });
    assert!(unreachable);
}

#[test]
fn ping() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    // Resolve ARP first via a UDP datagram.
    s.b.udp_bind(1);
    let mut cap = Cap::default();
    s.a.udp_send(s.now, &mut cap, 1, sa(B, 1), b"x").unwrap();
    s.out_a(cap);
    s.run_until(Duration::from_millis(100), |_| false);
    // Inject an echo request from A's MAC to B.
    let body = b"abcdefgh";
    let mut f = vec![0u8; ETH_HDR + 20 + 8 + body.len()];
    wire::write_eth(&mut f, MAC_B, MAC_A, wire::ETHERTYPE_IPV4);
    wire::write_icmp(
        &mut f[ETH_HDR + 20..],
        wire::ICMP_ECHO_REQUEST,
        0,
        [0, 1, 0, 2],
        body,
    );
    wire::write_ipv4(
        &mut f[ETH_HDR..],
        A,
        B,
        wire::PROTO_ICMP,
        9,
        0,
        64,
        0,
        8 + body.len(),
    );
    let mut out = Cap::default();
    s.b.receive(s.now, &f, &mut out);
    assert_eq!(out.0.len(), 1);
    let eth = Eth::parse(&out.0[0]).unwrap();
    let ip = Ipv4::parse(eth.payload, true).unwrap();
    let m = wire::Icmp::parse(ip.payload, true).unwrap();
    assert_eq!(
        (m.kind, m.rest, m.body),
        (wire::ICMP_ECHO_REPLY, [0, 1, 0, 2], &body[..])
    );
    assert!(tcp_of(&out.0[0]).is_none());
}

#[test]
fn time_wait_reuse_by_a_new_dial() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    let (ha, hb) = s.connect(80, 50000);
    s.a.tcp_close(ha, s.now);
    s.b.tcp_close(hb, s.now);
    s.run_until(Duration::from_secs(1), |s| s.b.tcp_count() == 0);
    assert_eq!(s.a.tcp_count(), 1); // TIME-WAIT
    // Same 4-tuple again right away.
    let (ha2, hb2) = s.connect(80, 50000);
    s.transfer(ha2, hb2, b"again", Duration::from_secs(1));
}

#[test]
fn many_connections_echo_through_cookies_and_loss() {
    // More simultaneous handshakes than the backlog (SYN cookies), a lossy link, every
    // connection echoing data: all complete.
    let link = LinkCfg {
        delay: Duration::from_millis(1),
        rate: 50_000_000,
        queue: 300,
        loss: 0.01,
        ..LinkCfg::default()
    };
    let mut cb = config(B, MAC_B, params());
    cb.backlog = 16;
    let mut s = Sim::with(link, config(A, MAC_A, params()), cb);
    s.b.tcp_listen(80);
    let n = 300usize;
    let size = 32 << 10;
    let hs: Vec<TcpHandle> = (0..n)
        .map(|i| s.a.tcp_connect(30000 + i as u16, sa(B, 80), s.now).unwrap())
        .collect();
    let data = pattern(size);
    let mut sent = vec![0usize; n];
    let mut got = vec![Vec::new(); n];
    let mut server: Vec<TcpHandle> = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut failed = Vec::new();
    let ok = s.run_until(Duration::from_secs(120), |s| {
        for e in s.ev_b.drain(..) {
            if let Event::Accepted { h, .. } = e {
                server.push(h);
            }
        }
        for e in s.ev_a.drain(..) {
            if let Event::ConnectFailed(h, err) | Event::Closed(h, Some(err)) = e {
                failed.push((h, err));
            }
        }
        for &h in &server {
            loop {
                let n = s.b.tcp_recv(h, &mut buf);
                if n == 0 {
                    break;
                }
                let w = s.b.tcp_send(h, &buf[..n]);
                assert_eq!(w, n, "echo send buffer full");
            }
        }
        for (i, &h) in hs.iter().enumerate() {
            if sent[i] < size {
                sent[i] += s.a.tcp_send(h, &data[sent[i]..]);
            }
            loop {
                let k = s.a.tcp_recv(h, &mut buf);
                if k == 0 {
                    break;
                }
                got[i].extend_from_slice(&buf[..k]);
            }
        }
        got.iter().all(|g| g.len() == size)
    });
    let done = got.iter().filter(|g| g.len() == size).count();
    assert!(failed.is_empty(), "{failed:?}");
    assert!(
        ok,
        "{done} of {n} connections completed; {} accepted",
        server.len()
    );
    assert!(got.iter().all(|g| *g == data));
}

// ---- IPv6 ---------------------------------------------------------------------------------

/// The IPv6 counterpart of [`capture`]: neighbor discovery, MLD, a handshake and data with
/// loss, a fragmented UDP datagram, port unreachable, an echo, a close.
pub(crate) fn capture6() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let link = LinkCfg {
        loss: 0.03,
        ..LinkCfg::default()
    };
    let mut s = Sim::new6(link, params(), params());
    s.ab.log = Some(Vec::new());
    s.ba.log = Some(Vec::new());
    let (ha, hb) = s.connect_to(IpAddr::V6(B6), 80, 50000);
    s.transfer(ha, hb, &pattern(32 << 10), Duration::from_secs(30));
    s.a.udp_bind(5000);
    s.b.udp_bind(53);
    let mut cap = Cap::default();
    let _ =
        s.a.udp_send(s.now, &mut cap, 5000, sa(B6, 53), &pattern(3000));
    let _ =
        s.a.udp_send(s.now, &mut cap, 5000, sa(B6, 54), b"closed port");
    s.out_a(cap);
    let echo = echo6(MAC_A, MAC_B, A6, B6, b"ping6");
    if let Some(l) = s.ab.log.as_mut() {
        l.push(echo.clone());
    }
    let mut cap = Cap::default();
    s.b.receive(s.now, &echo, &mut cap);
    for f in cap.0 {
        s.seq += 1;
        s.ba.push(s.now, f, &mut s.rng, s.seq);
    }
    s.run_until(Duration::from_millis(100), |_| false);
    s.a.tcp_close(ha, s.now);
    s.b.tcp_close(hb, s.now);
    s.run_until(Duration::from_secs(1), |_| false);
    (
        s.ab.log.take().unwrap_or_default(),
        s.ba.log.take().unwrap_or_default(),
    )
}

/// An Ethernet frame carrying an IPv6 packet from `src` to `dst` with `next` and `payload`.
fn frame6(
    smac: [u8; 6],
    dmac: [u8; 6],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next: u8,
    hops: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = vec![0u8; ETH_HDR + wire6::IPV6_HDR + payload.len()];
    wire::write_eth(&mut f, dmac, smac, wire::ETHERTYPE_IPV6);
    wire6::write_ipv6(&mut f[ETH_HDR..], src, dst, next, hops, 0, payload.len());
    f[ETH_HDR + wire6::IPV6_HDR..].copy_from_slice(payload);
    f
}

fn echo6(smac: [u8; 6], dmac: [u8; 6], src: Ipv6Addr, dst: Ipv6Addr, body: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8; wire6::ICMP6_HDR + body.len()];
    wire6::write_icmp6(
        &mut m,
        src,
        dst,
        wire6::ICMP6_ECHO_REQUEST,
        0,
        [0, 7, 0, 1],
        body,
    );
    frame6(smac, dmac, src, dst, wire::PROTO_ICMPV6, 64, &m)
}

/// A UDP datagram from `src`:1000 to `dst`:`port`, behind the extension headers `ext` (whose
/// first byte chain must end in UDP).
fn udp6_with(
    ext_first: u8,
    ext: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    port: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut u = vec![0u8; wire::UDP_HDR + data.len()];
    u[wire::UDP_HDR..].copy_from_slice(data);
    wire::write_udp(&mut u, src.into(), dst.into(), 1000, port, data.len());
    let p = [ext, &u[..]].concat();
    frame6(MAC_A, MAC_B, src, dst, ext_first, 64, &p)
}

/// IPv6 packets with extension headers (fuzz seeds): options (skipped, unknown with each
/// action), a routing header with and without segments left, a long chain.
pub(crate) fn ext_header_packets() -> Vec<Vec<u8>> {
    use wire6::{NH_DSTOPTS, NH_HOPOPT, NH_ROUTING};
    let u = wire::PROTO_UDP;
    let cases: Vec<(u8, Vec<u8>)> = vec![
        (
            NH_HOPOPT,
            vec![NH_DSTOPTS, 0, 1, 4, 0, 0, 0, 0, u, 0, 0x05, 2, 0, 0, 1, 0],
        ),
        (NH_DSTOPTS, vec![u, 0, 0x07, 2, 0, 0, 0, 0]),
        (NH_DSTOPTS, vec![u, 0, 0x47, 2, 0, 0, 0, 0]),
        (NH_DSTOPTS, vec![u, 0, 0x87, 2, 0, 0, 0, 0]),
        (NH_DSTOPTS, vec![u, 0, 0xc7, 2, 0, 0, 0, 0]),
        (NH_ROUTING, vec![u, 0, 4, 0, 0, 0, 0, 0]),
        (NH_ROUTING, vec![u, 0, 4, 2, 0, 0, 0, 0]),
        (NH_DSTOPTS, [NH_DSTOPTS, 0, 0, 0, 0, 0, 0, 0].repeat(9)),
        (99, vec![]),
    ];
    cases
        .into_iter()
        .map(|(first, ext)| udp6_with(first, &ext, A6, B6, 53, b"seed")[ETH_HDR..].to_vec())
        .collect()
}

/// The first frame in `frames` that is an ICMPv6 message of `kind`, as (IPv6 header fields,
/// message).
fn find_icmp6(frames: &[Vec<u8>], kind: u8) -> Option<(Ipv6Addr, Ipv6Addr, u8, Vec<u8>)> {
    frames.iter().find_map(|f| {
        let eth = Eth::parse(f)?;
        let ip = wire6::Ipv6::parse(eth.payload)?;
        let up = wire6::walk(ip.next, ip.payload, wire6::IPV6_HDR, true).ok()?;
        if up.proto != wire::PROTO_ICMPV6 {
            return None;
        }
        let m = &ip.payload[up.offset..];
        let i = wire6::Icmp6::parse(m, ip.src, ip.dst, true)?;
        (i.kind == kind).then(|| (ip.src, ip.dst, ip.hop_limit, m.to_vec()))
    })
}

#[test]
fn ipv6_handshake_resolves_neighbors_without_delay() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    let t0 = s.now;
    let (ha, hb) = s.connect_to(IpAddr::V6(B6), 80, 50000);
    assert!(
        s.now - t0 < Duration::from_millis(10),
        "the SYN waited in the NDP queue"
    );
    assert_eq!(s.a.tcp_peer(ha), Some(sa(B6, 80)));
    assert_eq!(s.b.tcp_peer(hb), Some(sa(A6, 50000)));
    assert_eq!(s.b.tcp_local(hb), Some(sa(B6, 80)));
    let (_, _, sack, ts, ws) = s.b.tcb(hb).unwrap().snapshot();
    assert!(sack && ts && ws);
    // The IPv6 MSS is 20 bytes less (1500 - 60, less 12 for timestamps).
    assert_eq!(s.a.tcb(ha).unwrap().mss(), 1500 - 60 - 12);
    let data = pattern(200_000);
    s.transfer(ha, hb, &data, Duration::from_secs(10));
}

#[test]
fn ipv6_bulk_transfer_lossy_reordering_link() {
    let link = LinkCfg {
        delay: Duration::from_millis(5),
        rate: 12_500_000,
        queue: 100,
        loss: 0.02,
        reorder: 0.02,
        reorder_by: Duration::from_millis(3),
        ..LinkCfg::default()
    };
    let mut s = Sim::new6(link, params(), params());
    let (ha, hb) = s.connect_to(IpAddr::V6(B6), 80, 50000);
    let data = pattern(2 << 20);
    s.transfer(ha, hb, &data, Duration::from_secs(120));
    assert!(s.dropped().0 > 0, "the link dropped segments");
    // And the other direction over the same connection.
    let back = pattern(300_000);
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = vec![0u8; 65536];
    let ok = s.run_until(Duration::from_secs(60), |s| {
        sent += s.b.tcp_send(hb, &back[sent..]);
        loop {
            let n = s.a.tcp_recv(ha, &mut buf);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got.len() == back.len()
    });
    assert!(ok && got == back);
}

#[test]
fn ipv6_link_local_and_dual_stack_listener() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    let ll_b = wire6::link_local(MAC_B);
    let (ha, hb) = s.connect_to(IpAddr::V6(ll_b), 80, 50000);
    // Link-local destination: link-local source.
    assert_eq!(s.b.tcp_peer(hb), Some(sa(wire6::link_local(MAC_A), 50000)));
    s.transfer(ha, hb, &pattern(10_000), Duration::from_secs(5));
    // The same listener takes IPv4.
    let (ha4, hb4) = s.connect_to(IpAddr::V4(B), 80, 50001);
    assert_eq!(s.b.tcp_peer(hb4), Some(sa(A, 50001)));
    s.transfer(ha4, hb4, &pattern(10_000), Duration::from_secs(5));
}

#[test]
fn ipv6_udp_fragments_and_port_unreachable() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    s.a.udp_bind(5000);
    s.b.udp_bind(6000);
    let big = pattern(20_000);
    let mut cap = Cap::default();
    s.a.udp_send(s.now, &mut cap, 5000, sa(B6, 6000), &big)
        .unwrap();
    s.out_a(cap);
    let mut buf = vec![0u8; 65536];
    let mut got = None;
    s.run_until(Duration::from_secs(1), |s| {
        got = s.b.udp_recv(&mut buf);
        got.is_some()
    });
    let (port, from, n) = got.expect("reassembled");
    assert_eq!((port, from), (6000, sa(A6, 5000)));
    assert_eq!(&buf[..n], &big[..]);
    // Largest datagram: the UDP length field less the fragment header.
    let mut cap = Cap::default();
    let max = 65535 - 16;
    assert!(
        s.a.udp_send(s.now, &mut cap, 5000, sa(B6, 6000), &pattern(max))
            .is_ok()
    );
    assert_eq!(
        s.a.udp_send(s.now, &mut cap, 5000, sa(B6, 6000), &pattern(max + 1)),
        Err(super::CallError::TooBig)
    );
    s.out_a(cap);
    s.run_until(Duration::from_secs(1), |s| s.b.udp_recv(&mut buf).is_some());
    let mut cap = Cap::default();
    s.a.udp_send(s.now, &mut cap, 5000, sa(B6, 6001), b"x")
        .unwrap();
    s.out_a(cap);
    let mut unreachable = false;
    s.run_until(Duration::from_secs(1), |s| {
        unreachable |= s.ev_a.contains(&Event::UdpUnreachable {
            port: 5000,
            remote: Box::new(sa(B6, 6001)),
        });
        unreachable
    });
    assert!(unreachable);
}

#[test]
fn ipv6_overlapping_fragments_are_discarded() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    s.b.udp_bind(53);
    let mut u = vec![0u8; wire::UDP_HDR + 24];
    wire::write_udp(&mut u, A6.into(), B6.into(), 1000, 53, 24);
    let frag = |id: u32, off: usize, more: bool, data: &[u8]| {
        let mut p = vec![0u8; wire6::FRAG_HDR + data.len()];
        wire6::write_frag(&mut p, wire::PROTO_UDP, off, more, id);
        p[wire6::FRAG_HDR..].copy_from_slice(data);
        frame6(MAC_A, MAC_B, A6, B6, wire6::NH_FRAGMENT, 64, &p)
    };
    let mut cap = Cap::default();
    s.b.receive(s.now, &frag(77, 0, true, &u[..16]), &mut cap);
    s.b.receive(s.now, &frag(77, 8, true, &u[8..24]), &mut cap); // overlaps
    s.b.receive(s.now, &frag(77, 24, false, &u[24..]), &mut cap);
    let mut buf = [0u8; 64];
    assert!(s.b.udp_recv(&mut buf).is_none());
    // The same fragments without the overlap reassemble.
    let mut cap = Cap::default();
    s.b.receive(s.now, &frag(78, 0, true, &u[..16]), &mut cap);
    s.b.receive(s.now, &frag(78, 16, false, &u[16..]), &mut cap);
    assert_eq!(s.b.udp_recv(&mut buf).map(|r| r.2), Some(24));
    // An atomic fragment is delivered as is.
    let mut cap = Cap::default();
    s.b.receive(s.now, &frag(79, 0, false, &u), &mut cap);
    assert_eq!(s.b.udp_recv(&mut buf).map(|r| r.2), Some(24));
}

#[test]
fn ipv6_ping_ndp_and_dad_defense() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    // Echo to the global and the all-nodes address.
    for dst in [B6, wire6::ALL_NODES] {
        let mut out = Cap::default();
        let dmac = if dst.is_multicast() {
            wire6::multicast_mac(dst)
        } else {
            MAC_B
        };
        s.b.receive(s.now, &echo6(MAC_A, dmac, A6, dst, b"abc"), &mut out);
        // The reply waits for A's address: B solicits it first.
        let (src, ndst, hops, m) = find_icmp6(&out.0, wire6::ND_NEIGHBOR_SOLICIT).expect("NS");
        assert_eq!((src, ndst, hops), (B6, wire6::solicited_node(A6), 255));
        let i = wire6::Icmp6::parse(&m, src, ndst, true).unwrap();
        assert_eq!(wire6::Nd::parse(&i, src, ndst, 255).unwrap().target, A6);
        // A answers; the queued reply goes out.
        let mut cap = Cap::default();
        for f in &out.0 {
            s.a.receive(s.now, f, &mut cap);
        }
        let (_, _, _, na) = find_icmp6(&cap.0, wire6::ND_NEIGHBOR_ADVERT).expect("NA");
        assert_eq!(na[4] & wire6::NA_SOLICITED, wire6::NA_SOLICITED);
        let mut out = Cap::default();
        for f in &cap.0 {
            s.b.receive(s.now, f, &mut out);
        }
        let (src, rdst, _, m) = find_icmp6(&out.0, wire6::ICMP6_ECHO_REPLY).expect("reply");
        assert_eq!((src, rdst), (B6, A6));
        assert_eq!(&m[wire6::ICMP6_HDR..], b"abc");
        // Forget A so the next round solicits again.
        s.b = Iface::new(
            {
                let mut c = config(B, MAC_B, params());
                c.ip6 = Some(B6);
                c
            },
            s.now,
        );
    }
    // A DAD probe for B's address is answered with an advertisement to all nodes.
    let sn = wire6::solicited_node(B6);
    let mut ns = [0u8; wire6::ND_LEN];
    wire6::write_ns(&mut ns, Ipv6Addr::UNSPECIFIED, sn, B6, None);
    let f = frame6(
        MAC_A,
        wire6::multicast_mac(sn),
        Ipv6Addr::UNSPECIFIED,
        sn,
        wire::PROTO_ICMPV6,
        255,
        &ns,
    );
    let mut out = Cap::default();
    s.b.receive(s.now, &f, &mut out);
    let (src, dst, _, na) = find_icmp6(&out.0, wire6::ND_NEIGHBOR_ADVERT).expect("defended");
    assert_eq!((src, dst), (B6, wire6::ALL_NODES));
    assert_eq!(na[4] & wire6::NA_SOLICITED, 0);
    // A solicitation with a forged hop limit is ignored.
    let mut ns = [0u8; wire6::ND_MSG];
    wire6::write_ns(&mut ns, A6, sn, B6, Some(MAC_A));
    let f = frame6(
        MAC_A,
        wire6::multicast_mac(sn),
        A6,
        sn,
        wire::PROTO_ICMPV6,
        64,
        &ns,
    );
    let mut out = Cap::default();
    s.b.receive(s.now, &f, &mut out);
    assert!(out.0.is_empty());
}

#[test]
fn ipv6_mld_report_at_start() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    let mut cap = Cap::default();
    s.a.poll(s.now, &mut cap);
    let (src, dst, hops, m) = find_icmp6(&cap.0, wire6::MLD2_REPORT).expect("report");
    assert_eq!(
        (src, dst, hops),
        (wire6::link_local(MAC_A), wire6::ALL_MLDV2_ROUTERS, 1)
    );
    // fe80::...:1 and fd00::1 share their solicited-node group: reported once.
    assert_eq!(m[7], 1);
    let groups: Vec<Ipv6Addr> = vec![wire6::solicited_node(A6)];
    assert_eq!(
        &m[wire6::ICMP6_HDR + 4..wire6::ICMP6_HDR + 20],
        &groups[0].octets()
    );
    // Once.
    let mut cap = Cap::default();
    s.a.poll(s.now, &mut cap);
    assert!(find_icmp6(&cap.0, wire6::MLD2_REPORT).is_none());
}

#[test]
fn ipv6_extension_headers_and_unknown_protocols() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    s.b.udp_bind(53);
    // Prime B's neighbor cache with A (errors go out at once).
    let mut ns = [0u8; wire6::ND_MSG];
    let sn = wire6::solicited_node(B6);
    wire6::write_ns(&mut ns, A6, sn, B6, Some(MAC_A));
    let mut cap = Cap::default();
    s.b.receive(
        s.now,
        &frame6(
            MAC_A,
            wire6::multicast_mac(sn),
            A6,
            sn,
            wire::PROTO_ICMPV6,
            255,
            &ns,
        ),
        &mut cap,
    );
    let mut buf = [0u8; 64];
    let packets = ext_header_packets();
    /// (UDP bytes delivered, parameter problem (type, code, pointer) sent).
    type Outcome = (Option<usize>, Option<(u8, u8, u32)>);
    let expect: [Outcome; 9] = [
        (Some(4), None),                                   // HBH + DstOpts + router alert
        (Some(4), None),                                   // unknown option, skip
        (None, None),                                      // discard silently
        (None, Some((wire6::ICMP6_PARAM_PROBLEM, 2, 42))), // discard + problem
        (None, Some((wire6::ICMP6_PARAM_PROBLEM, 2, 42))), // discard + problem (unicast)
        (Some(4), None),                                   // routing header, nothing left
        (None, Some((wire6::ICMP6_PARAM_PROBLEM, 0, 43))), // segments left
        (None, None),                                      // chain too long
        (None, Some((wire6::ICMP6_PARAM_PROBLEM, 1, 6))),  // unknown next header
    ];
    for (i, (p, (delivered, error))) in packets.iter().zip(expect).enumerate() {
        let mut f = vec![0u8; ETH_HDR];
        wire::write_eth(&mut f, MAC_B, MAC_A, wire::ETHERTYPE_IPV6);
        f.extend_from_slice(p);
        let mut out = Cap::default();
        s.now += Duration::from_millis(20); // ICMP rate limit
        s.b.receive(s.now, &f, &mut out);
        assert_eq!(s.b.udp_recv(&mut buf).map(|r| r.2), delivered, "case {i}");
        let got = find_icmp6(&out.0, wire6::ICMP6_PARAM_PROBLEM)
            .map(|(_, _, _, m)| (m[0], m[1], u32::from_be_bytes([m[4], m[5], m[6], m[7]])));
        assert_eq!(got, error, "case {i}");
    }
}

#[test]
fn ipv6_packet_too_big_lowers_mss_and_fragments_udp() {
    let mut s = Sim::new6(LinkCfg::default(), params(), params());
    let (ha, hb) = s.connect_to(IpAddr::V6(B6), 80, 50000);
    let before = s.a.tcb(ha).unwrap().mss();
    // B's segment in flight is quoted in a packet-too-big (MTU 1400) from a router.
    s.b.tcp_send(hb, &pattern(10_000));
    let mut cap = Cap::default();
    s.b.poll(s.now, &mut cap);
    let seg = cap
        .0
        .iter()
        .find(|f| tcp_of(f).is_some_and(|t| t.2 > 0))
        .expect("data")
        .clone();
    let quoted = &seg[ETH_HDR..];
    let mut m = vec![0u8; wire6::ICMP6_HDR + quoted.len().min(1232)];
    let router: Ipv6Addr = "fd00::fe".parse().unwrap();
    wire6::write_icmp6(
        &mut m,
        router,
        B6,
        wire6::ICMP6_PACKET_TOO_BIG,
        0,
        1400u32.to_be_bytes(),
        &quoted[..quoted.len().min(1232)],
    );
    let mut out = Cap::default();
    s.b.receive(
        s.now,
        &frame6(MAC_A, MAC_B, router, B6, wire::PROTO_ICMPV6, 64, &m),
        &mut out,
    );
    assert_eq!(s.b.tcb(hb).unwrap().mss(), 1400 - 60 - 12);
    assert_eq!(before, 1500 - 60 - 12);
    // UDP to the same destination is fragmented to the path MTU.
    s.b.udp_bind(7);
    let mut cap = Cap::default();
    s.b.udp_send(s.now, &mut cap, 7, sa(A6, 7), &pattern(3000))
        .unwrap();
    let frags: Vec<usize> = cap
        .0
        .iter()
        .filter(|f| {
            wire6::Ipv6::parse(&f[ETH_HDR..]).is_some_and(|ip| ip.next == wire6::NH_FRAGMENT)
        })
        .map(Vec::len)
        .collect();
    assert!(
        frags.len() >= 3 && frags.iter().all(|&n| n - ETH_HDR <= 1400),
        "{frags:?}"
    );
    // A packet-too-big below the minimum MTU is taken as 1280.
    let mut m2 = m.clone();
    m2[4..8].copy_from_slice(&500u32.to_be_bytes());
    wire6::icmp6_checksum(&mut m2, router, B6);
    s.b.receive(
        s.now,
        &frame6(MAC_A, MAC_B, router, B6, wire::PROTO_ICMPV6, 64, &m2),
        &mut out,
    );
    assert_eq!(s.b.tcb(hb).unwrap().mss(), 1280 - 60 - 12);
    // The connection still delivers everything.
    let mut got = 0;
    let mut buf = vec![0u8; 65536];
    s.run_until(Duration::from_secs(10), |s| {
        got += s.a.tcp_recv(ha, &mut buf);
        got == 10_000
    });
    assert_eq!(got, 10_000);
}

// ---- ECN and pacing --------------------------------------------------------------------------

fn params_with(ecn: bool, pacing: bool) -> Params {
    Params {
        ecn,
        pacing,
        ..params()
    }
}

/// A 1 MB transfer through a 20 Mbit/s bottleneck whose queue (20 frames) is shallower than
/// the window beyond the path's BDP (about 17 frames): (drops, CE marks, retransmitted
/// segments seen, time).
fn bottleneck(v6: bool, ecn: bool, pacing: bool) -> (u64, u64, usize, Duration) {
    let link = LinkCfg {
        delay: Duration::from_millis(5),
        rate: 2_500_000,
        queue: 20,
        ce_mark: if ecn { 8 } else { 0 },
        ..LinkCfg::default()
    };
    let p = params_with(ecn, pacing);
    let mut s = if v6 {
        Sim::new6(link, p, p)
    } else {
        Sim::new(link, p, p)
    };
    s.ab.log = Some(Vec::new());
    let to = if v6 { IpAddr::V6(B6) } else { IpAddr::V4(B) };
    let (ha, hb) = s.connect_to(to, 80, 50000);
    let took = s.transfer(ha, hb, &pattern(1 << 20), Duration::from_secs(60));
    let log = s.ab.log.take().unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    let rexmits = log
        .iter()
        .filter_map(|f| tcp_of(f))
        .filter(|&(_, _, n)| n > 0)
        .filter(|&(_, seq, _)| !seen.insert(seq))
        .count();
    (s.dropped().0, s.ab_stats().1, rexmits, took)
}

#[test]
fn ecn_negotiation() {
    for (a, b, want) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
    ] {
        let mut s = Sim::new6(
            LinkCfg::default(),
            params_with(a, false),
            params_with(b, false),
        );
        s.ab.log = Some(Vec::new());
        let (ha, hb) = s.connect_to(IpAddr::V6(B6), 80, 50000);
        s.transfer(ha, hb, &pattern(20_000), Duration::from_secs(5));
        let log = s.ab.log.take().unwrap_or_default();
        let syn = log
            .iter()
            .filter_map(|f| tcp_of(f))
            .find(|t| t.0 & wire::SYN != 0)
            .unwrap();
        assert_eq!(syn.0 & (wire::ECE | wire::CWR) != 0, a, "ECN-setup SYN");
        // Data is ECT exactly when both agreed.
        let ect = log.iter().any(|f| {
            tcp_of(f).is_some_and(|t| t.2 > 0)
                && wire6::Ipv6::parse(&f[ETH_HDR..])
                    .is_some_and(|ip| ip.tclass & wire::ECN_MASK == wire::ECT0)
        });
        assert_eq!(ect, want, "ecn a={a} b={b}");
    }
}

#[test]
fn ecn_marks_instead_of_drops() {
    for v6 in [false, true] {
        let (drops, _, rx_plain, t_plain) = bottleneck(v6, false, false);
        let (drops_ecn, marks, rx_ecn, t_ecn) = bottleneck(v6, true, false);
        eprintln!(
            "v6={v6}: plain {drops} drops {rx_plain} rexmits {t_plain:?}; ecn {drops_ecn} drops {marks} marks {rx_ecn} rexmits {t_ecn:?}"
        );
        assert!(marks > 0, "the AQM marked");
        assert!(drops > 0, "without ECN the shallow queue overflows");
        assert!(
            drops_ecn < drops,
            "ECN avoids drops ({drops_ecn} vs {drops})"
        );
        assert!(rx_ecn < rx_plain);
    }
}

#[test]
fn pacing_smooths_bursts() {
    for v6 in [false, true] {
        let (drops, _, _, t_plain) = bottleneck(v6, false, false);
        let (drops_paced, _, _, t_paced) = bottleneck(v6, false, true);
        eprintln!(
            "v6={v6}: unpaced {drops} drops {t_plain:?}; paced {drops_paced} drops {t_paced:?}"
        );
        assert!(
            drops_paced <= drops,
            "pacing does not add drops ({drops_paced} vs {drops})"
        );
        assert!(t_paced < t_plain * 2, "pacing keeps the link busy");
    }
}

#[test]
fn ecn_and_pacing_through_loss_and_cookies() {
    // Both features on, a lossy link, every handshake through a SYN cookie (no ECN then).
    let p = params_with(true, true);
    let mut cb = config(B, MAC_B, p);
    cb.backlog = 0;
    cb.ip6 = Some(B6);
    let mut ca = config(A, MAC_A, p);
    ca.ip6 = Some(A6);
    let link = LinkCfg {
        loss: 0.02,
        ce_mark: 20,
        rate: 12_500_000,
        queue: 60,
        ..LinkCfg::default()
    };
    let mut s = Sim::with(link, ca, cb);
    let (ha, hb) = s.connect_to(IpAddr::V6(B6), 80, 50000);
    s.transfer(ha, hb, &pattern(500_000), Duration::from_secs(60));
}

/// Stack-only cost of a small request/response (64 bytes each way plus the ACK) between two
/// interfaces, without threads or a link model: `cargo test --release -p akio-dpdk --lib
/// bench_request_response -- --ignored --nocapture`. `AKIO_RR_N` sets the round trips.
#[test]
#[ignore]
fn bench_request_response() {
    let link = LinkCfg {
        delay: Duration::ZERO,
        ..LinkCfg::default()
    };
    let mut s = Sim::new(link, params(), params());
    let (ha, hb) = s.connect(80, 50000);
    let n: u32 = std::env::var("AKIO_RR_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000);
    let req = [7u8; 64];
    let mut buf = [0u8; 4096];
    let mut now = s.now;
    let (mut ca, mut cb) = (Cap::default(), Cap::default());
    let mut ev = Vec::new();
    let t0 = Instant::now();
    for _ in 0..n {
        s.a.tcp_send(ha, &req);
        s.a.poll(now, &mut ca);
        for f in ca.0.drain(..) {
            s.b.receive(now, &f, &mut cb);
        }
        while s.b.tcp_recv(hb, &mut buf) > 0 {}
        s.b.tcp_send(hb, &req);
        s.b.poll(now, &mut cb);
        for f in cb.0.drain(..) {
            s.a.receive(now, &f, &mut ca);
        }
        while s.a.tcp_recv(ha, &mut buf) > 0 {}
        s.a.poll(now, &mut ca);
        for f in ca.0.drain(..) {
            s.b.receive(now, &f, &mut cb);
        }
        cb.0.clear();
        s.a.take_events(&mut ev);
        s.b.take_events(&mut ev);
        ev.clear();
        now += Duration::from_micros(10);
    }
    let el = t0.elapsed();
    eprintln!(
        "RR {n} round trips: {:.1} ns each",
        el.as_nanos() as f64 / f64::from(n)
    );
}

/// Stack-only cost of a short connection (handshake, 64-byte request and response, close by
/// the client, the server's FIN), like `stack-bench`'s sequential connections:
/// `cargo test --release -p akio-dpdk --lib bench_connection_cycle -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench_connection_cycle() {
    let link = LinkCfg {
        delay: Duration::ZERO,
        ..LinkCfg::default()
    };
    let mut s = Sim::new(link, params(), params());
    s.b.tcp_listen(80);
    let n: u16 = std::env::var("AKIO_CC_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let req = [7u8; 64];
    let mut buf = [0u8; 4096];
    let mut now = s.now;
    let (mut ca, mut cb) = (Cap::default(), Cap::default());
    let mut ev = Vec::new();
    // Moves frames both ways until nothing is left to send.
    fn pump(s: &mut Sim, now: Instant, ca: &mut Cap, cb: &mut Cap) {
        for _ in 0..8 {
            s.a.poll(now, ca);
            for f in ca.0.drain(..) {
                s.b.receive(now, &f, cb);
            }
            s.b.poll(now, cb);
            if cb.0.is_empty() {
                break;
            }
            for f in cb.0.drain(..) {
                s.a.receive(now, &f, ca);
            }
        }
    }
    let t0 = Instant::now();
    for i in 0..n {
        let ha = s.a.tcp_connect(20000 + i, sa(B, 80), now).expect("connect");
        pump(&mut s, now, &mut ca, &mut cb);
        s.b.take_events(&mut ev);
        let hb = ev
            .iter()
            .find_map(|e| match e {
                Event::Accepted { h, .. } => Some(*h),
                _ => None,
            })
            .expect("accepted");
        ev.clear();
        s.a.tcp_send(ha, &req);
        pump(&mut s, now, &mut ca, &mut cb);
        while s.b.tcp_recv(hb, &mut buf) > 0 {}
        s.b.tcp_send(hb, &req);
        pump(&mut s, now, &mut ca, &mut cb);
        while s.a.tcp_recv(ha, &mut buf) > 0 {}
        s.a.tcp_close(ha, now);
        pump(&mut s, now, &mut ca, &mut cb);
        s.b.tcp_close(hb, now);
        pump(&mut s, now, &mut ca, &mut cb);
        s.a.take_events(&mut ev);
        s.b.take_events(&mut ev);
        ev.clear();
        now += Duration::from_micros(10);
    }
    let el = t0.elapsed();
    eprintln!(
        "CC {n} connections: {:.1} ns each",
        el.as_nanos() as f64 / f64::from(n)
    );
}

// ---- IPv6 autoconfiguration (RFC 4861 / RFC 4862) -------------------------------------------

const MAC_R: [u8; 6] = [2, 0, 0, 0, 0, 0x99];

/// A router advertisement from the router `fe80::99` (MAC `MAC_R`) to all nodes: `lifetime`
/// seconds as a default router, hop limit `hops`, an MTU option when `mtu` is non-zero, its
/// link-layer address, and the prefix-information options `prefixes`
/// (prefix, length, flags, valid, preferred).
fn ra_frame(
    lifetime: u16,
    hops: u8,
    mtu: u32,
    prefixes: &[(Ipv6Addr, u8, u8, u32, u32)],
) -> Vec<u8> {
    let src = wire6::link_local(MAC_R);
    let dst = wire6::ALL_NODES;
    let mut body = vec![0u8; 8]; // reachable time, retrans timer
    body.extend_from_slice(&[1, 1]);
    body.extend_from_slice(&MAC_R);
    if mtu != 0 {
        body.extend_from_slice(&[5, 1, 0, 0]);
        body.extend_from_slice(&mtu.to_be_bytes());
    }
    for &(p, len, flags, valid, preferred) in prefixes {
        body.extend_from_slice(&[3, 4, len, flags]);
        body.extend_from_slice(&valid.to_be_bytes());
        body.extend_from_slice(&preferred.to_be_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&p.octets());
    }
    let lt = lifetime.to_be_bytes();
    let mut m = vec![0u8; wire6::ICMP6_HDR + body.len()];
    wire6::write_icmp6(
        &mut m,
        src,
        dst,
        wire6::ND_ROUTER_ADVERT,
        0,
        [hops, 0, lt[0], lt[1]],
        &body,
    );
    frame6(
        MAC_R,
        wire6::multicast_mac(dst),
        src,
        dst,
        wire::PROTO_ICMPV6,
        255,
        &m,
    )
}

const PFX: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0);

/// Autoconfiguration frames (fuzz seeds): a router advertisement with prefix, MTU and
/// link-layer options, and a duplicate address detection probe.
pub(crate) fn autoconf_frames() -> Vec<Vec<u8>> {
    let mut ns = [0u8; wire6::DAD_NS];
    let target = slaac_addr(PFX, MAC_B);
    wire6::write_dad_ns(&mut ns, target, [1, 2, 3, 4, 5, 6]);
    let sn = wire6::solicited_node(target);
    vec![
        ra_frame(1800, 64, 1500, &[(PFX, 64, 0xc0, 86400, 14400)]),
        frame6(
            MAC_A,
            wire6::multicast_mac(sn),
            Ipv6Addr::UNSPECIFIED,
            sn,
            wire::PROTO_ICMPV6,
            255,
            &ns,
        ),
    ]
}

/// `prefix` (a /64) with `mac`'s modified EUI-64 interface identifier.
fn slaac_addr(prefix: Ipv6Addr, mac: [u8; 6]) -> Ipv6Addr {
    let iid = u128::from(wire6::link_local(mac)) & u128::from(u64::MAX);
    Ipv6Addr::from(u128::from(prefix) | iid)
}

fn auto_config(mac: [u8; 6], slaac: bool, dad: bool, ip6: Option<Ipv6Addr>) -> Config {
    let mut c = config(B, mac, params());
    c.slaac = slaac;
    c.dad = dad;
    c.ip6 = ip6;
    c
}

/// Polls `i` at `now`, returning what it sent.
fn poll_at(i: &mut Iface, now: Instant) -> Vec<Vec<u8>> {
    let mut cap = Cap::default();
    i.poll(now, &mut cap);
    cap.0
}

#[test]
fn ipv6_slaac_from_router_advertisements() {
    let t0 = Instant::now();
    let mut i = Iface::new(auto_config(MAC_B, true, false, None), t0);
    let ll = wire6::link_local(MAC_B);
    assert_eq!(i.ipv6_changed(), Some(vec![ll]));
    // A router solicitation within MAX_RTR_SOLICITATION_DELAY, from the link-local address with
    // our link-layer address.
    let mut rs = None;
    let mut t = t0;
    while t < t0 + Duration::from_millis(1100) && rs.is_none() {
        rs = find_icmp6(&poll_at(&mut i, t), wire6::ND_ROUTER_SOLICIT);
        t += Duration::from_millis(10);
    }
    let (src, dst, hops, m) = rs.expect("router solicitation");
    assert_eq!((src, dst, hops), (ll, wire6::ALL_ROUTERS, 255));
    assert_eq!(&m[8..16], &[1, 1, 2, 0, 0, 0, 0, 2]);
    // Nothing off the link is reachable yet.
    let far = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 5);
    assert!(i.tcp_connect(50000, sa(far, 80), t).is_err());
    // A router advertisement: a /64 to autoconfigure, an on-link-only /48 (no address: our
    // identifier is 64 bits), MTU 1400, hop limit 32, 600 s as default router.
    let onlink48 = Ipv6Addr::new(0x2001, 0xdb8, 0x77, 0, 0, 0, 0, 0);
    let ra = ra_frame(
        600,
        32,
        1400,
        &[
            (PFX, 64, 0xc0, 3600, 1800),
            (onlink48, 48, 0xc0, 3600, 1800),
        ],
    );
    let mut out = Cap::default();
    i.receive(t, &ra, &mut out);
    let me = slaac_addr(PFX, MAC_B);
    assert_eq!(i.ipv6_changed(), Some(vec![ll, me]));
    assert!(i.ipv6_changed().is_none());
    // The router answered: no more solicitations.
    for k in 1..20 {
        let f = poll_at(&mut i, t + Duration::from_secs(k));
        assert!(find_icmp6(&f, wire6::ND_ROUTER_SOLICIT).is_none());
    }
    // An off-link dial goes to the router's MAC (learned from the advertisement), from the
    // SLAAC address, with the advertised hop limit and an MSS for MTU 1400.
    let h = i.tcp_connect(50000, sa(far, 80), t).expect("routable");
    assert_eq!(i.tcp_local(h).map(|a| a.ip()), Some(IpAddr::V6(me)));
    let f = poll_at(&mut i, t);
    let syn = f
        .iter()
        .find(|f| Eth::parse(f).is_some_and(|e| e.dst == MAC_R))
        .expect("SYN to the router");
    let ip = wire6::Ipv6::parse(&syn[ETH_HDR..]).unwrap();
    assert_eq!((ip.src, ip.dst, ip.hop_limit), (me, far, 32));
    let seg = Tcp::parse(ip.payload, me.into(), far.into(), true).unwrap();
    assert_eq!(seg.opts.mss, Some(1400 - 60));
    // The /48 is on the link: no router for it.
    let near = Ipv6Addr::new(0x2001, 0xdb8, 0x77, 1, 0, 0, 0, 9);
    let _ = i.tcp_connect(50001, sa(near, 80), t).expect("on link");
    let f = poll_at(&mut i, t);
    let (_, _, _, m) = find_icmp6(&f, wire6::ND_NEIGHBOR_SOLICIT).expect("resolves it");
    assert_eq!(&m[8..24], &near.octets());
    // An advertisement cutting the valid lifetime to 60 s is ignored for it (RFC 4862 5.5.3 e:
    // the remaining hour is under two hours), the preferred lifetime follows it.
    i.receive(
        t,
        &ra_frame(600, 32, 0, &[(PFX, 64, 0x40, 60, 30)]),
        &mut out,
    );
    let t1 = t + Duration::from_secs(100);
    poll_at(&mut i, t1);
    // Deprecated (past 30 s preferred) but still ours, and still the only global source.
    assert_eq!(i.ipv6_changed(), None);
    let h = i.tcp_connect(50003, sa(far, 81), t1).expect("routable");
    assert_eq!(i.tcp_local(h).map(|a| a.ip()), Some(IpAddr::V6(me)));
    // Past the router's 600 s: off-link is unreachable again; past the hour: the address goes.
    let t2 = t + Duration::from_secs(601);
    poll_at(&mut i, t2);
    assert!(i.tcp_connect(50002, sa(far, 80), t2).is_err());
    let t3 = t + Duration::from_secs(3601);
    poll_at(&mut i, t3);
    assert_eq!(i.ipv6_changed(), Some(vec![ll]));
    // Invalid advertisements are ignored: hop limit below 255, a global source.
    let mut bad = ra_frame(600, 64, 0, &[(PFX, 64, 0xc0, 3600, 1800)]);
    bad[ETH_HDR + 7] = 64;
    i.receive(t3, &bad, &mut out);
    assert!(i.ipv6_changed().is_none());
}

#[test]
fn ipv6_slaac_off_ignores_advertisements() {
    let t = Instant::now();
    let mut i = Iface::new(auto_config(MAC_B, false, false, Some(B6)), t);
    let f = poll_at(&mut i, t + Duration::from_secs(2));
    assert!(find_icmp6(&f, wire6::ND_ROUTER_SOLICIT).is_none());
    let _ = i.ipv6_changed();
    let mut out = Cap::default();
    i.receive(
        t,
        &ra_frame(600, 32, 0, &[(PFX, 64, 0xc0, 3600, 1800)]),
        &mut out,
    );
    assert!(i.ipv6_changed().is_none());
    let far = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 5);
    assert!(i.tcp_connect(50000, sa(far, 80), t).is_err());
}

/// The duplicate address detection probes in `frames`: (target, nonce).
fn dad_probes(frames: &[Vec<u8>]) -> Vec<(Ipv6Addr, Option<[u8; 6]>)> {
    frames
        .iter()
        .filter_map(|f| {
            let eth = Eth::parse(f)?;
            let ip = wire6::Ipv6::parse(eth.payload)?;
            let m = wire6::Icmp6::parse(ip.payload, ip.src, ip.dst, true)?;
            let nd = wire6::Nd::parse(&m, ip.src, ip.dst, ip.hop_limit)?;
            (ip.src.is_unspecified() && nd.kind == wire6::ND_NEIGHBOR_SOLICIT)
                .then_some((nd.target, nd.nonce))
        })
        .collect()
}

#[test]
fn ipv6_dad_before_use() {
    let t0 = Instant::now();
    let mut i = Iface::new(auto_config(MAC_B, false, true, Some(B6)), t0);
    let ll = wire6::link_local(MAC_B);
    // Nothing usable while tentative: the MLD report comes from `::`, dials fail, and packets
    // to the tentative address are dropped.
    assert_eq!(i.ipv6_changed(), Some(vec![]));
    let f = poll_at(&mut i, t0);
    let (src, _, _, _) = find_icmp6(&f, wire6::MLD2_REPORT).expect("report");
    assert!(src.is_unspecified());
    assert!(i.tcp_connect(50000, sa(A6, 80), t0).is_err());
    let mut out = Cap::default();
    i.receive(t0, &echo6(MAC_A, MAC_B, A6, B6, b"x"), &mut out);
    assert!(out.0.is_empty());
    // One probe per address, from `::` with our nonce, within a second.
    let mut probes = Vec::new();
    let mut t = t0;
    while probes.len() < 2 && t < t0 + Duration::from_millis(1100) {
        probes.extend(dad_probes(&poll_at(&mut i, t)));
        t += Duration::from_millis(10);
    }
    let targets: Vec<Ipv6Addr> = probes.iter().map(|p| p.0).collect();
    assert_eq!(targets, vec![ll, B6]);
    assert!(probes.iter().all(|p| p.1.is_some()));
    // Our own probe looped back is not a conflict.
    let mut ns = [0u8; wire6::DAD_NS];
    wire6::write_dad_ns(&mut ns, B6, probes[1].1.unwrap());
    let sn = wire6::solicited_node(B6);
    let looped = frame6(
        MAC_B,
        wire6::multicast_mac(sn),
        Ipv6Addr::UNSPECIFIED,
        sn,
        wire::PROTO_ICMPV6,
        255,
        &ns,
    );
    i.receive(t, &looped, &mut out);
    // A second later both are ours.
    poll_at(&mut i, t + Duration::from_millis(1100));
    assert_eq!(i.dad_failures(), 0);
    assert_eq!(i.ipv6_changed(), Some(vec![ll, B6]));
    let mut out = Cap::default();
    i.receive(t, &echo6(MAC_A, MAC_B, A6, B6, b"x"), &mut out);
    assert!(find_icmp6(&out.0, wire6::ND_NEIGHBOR_SOLICIT).is_some());
}

#[test]
fn ipv6_dad_conflicts() {
    // B owns B6; C comes up with B6 too, and probes first: B defends, C gives it up.
    let mut ca = auto_config(MAC_A, false, true, Some(B6));
    ca.ip = A;
    let cb = auto_config(MAC_B, false, false, Some(B6));
    let mut s = Sim::with(LinkCfg::default(), ca, cb);
    for _ in 0..400 {
        s.step(Duration::from_millis(20));
    }
    assert_eq!(s.a.dad_failures(), 1);
    assert_eq!(s.a.ipv6_changed(), Some(vec![wire6::link_local(MAC_A)]));
    // Another node's probe for our tentative address (no nonce of ours) is a conflict too, and
    // a duplicate link-local address turns IPv6 off.
    let t = Instant::now();
    let mut i = Iface::new(auto_config(MAC_B, true, true, None), t);
    let ll = wire6::link_local(MAC_B);
    let sn = wire6::solicited_node(ll);
    let mut ns = [0u8; wire6::DAD_NS];
    wire6::write_dad_ns(&mut ns, ll, [9; 6]);
    let probe = frame6(
        MAC_A,
        wire6::multicast_mac(sn),
        Ipv6Addr::UNSPECIFIED,
        sn,
        wire::PROTO_ICMPV6,
        255,
        &ns,
    );
    let mut out = Cap::default();
    i.receive(t, &probe, &mut out);
    assert_eq!(i.dad_failures(), 1);
    assert_eq!(i.ipv6_changed(), Some(vec![]));
    // Off: no solicitations, no reports, advertisements ignored.
    let f = poll_at(&mut i, t + Duration::from_secs(5));
    assert!(f.is_empty(), "{f:?}");
    i.receive(
        t,
        &ra_frame(600, 32, 0, &[(PFX, 64, 0xc0, 3600, 1800)]),
        &mut out,
    );
    assert!(i.ipv6_changed().is_none());
    // A SLAAC address found duplicate by an advertisement is dropped, the rest stays.
    let mut i = Iface::new(auto_config(MAC_B, true, true, None), t);
    poll_at(&mut i, t + Duration::from_secs(3));
    i.receive(
        t + Duration::from_secs(3),
        &ra_frame(600, 64, 0, &[(PFX, 64, 0xc0, 3600, 1800)]),
        &mut out,
    );
    let me = slaac_addr(PFX, MAC_B);
    let f = poll_at(&mut i, t + Duration::from_secs(3));
    assert_eq!(dad_probes(&f).first().map(|p| p.0), Some(me));
    let mut na = [0u8; wire6::ND_MSG];
    wire6::write_na(&mut na, me, wire6::ALL_NODES, wire6::NA_OVERRIDE, me, MAC_A);
    let claim = frame6(
        MAC_A,
        wire6::multicast_mac(wire6::ALL_NODES),
        me,
        wire6::ALL_NODES,
        wire::PROTO_ICMPV6,
        255,
        &na,
    );
    i.receive(t + Duration::from_secs(3), &claim, &mut out);
    poll_at(&mut i, t + Duration::from_secs(5));
    assert_eq!(i.dad_failures(), 1);
    assert_eq!(i.ipv6_changed(), Some(vec![ll]));
}

#[test]
fn ipv6_autoconf_only_queue_zero_speaks() {
    let t = Instant::now();
    let mut c = auto_config(MAC_B, true, true, None);
    c.queue = 1;
    c.queues = 2;
    let mut i = Iface::new(c, t);
    let mut sent = Vec::new();
    for k in 0..300 {
        sent.extend(poll_at(&mut i, t + Duration::from_millis(10 * k)));
    }
    assert!(sent.is_empty(), "queue 1 transmitted {} frames", sent.len());
    // It follows the same timeline: the link-local address is ours after the probe's wait.
    assert_eq!(i.ipv6_changed(), Some(vec![wire6::link_local(MAC_B)]));
    // And acts on advertisements.
    let mut out = Cap::default();
    let now = t + Duration::from_secs(3);
    i.receive(
        now,
        &ra_frame(600, 64, 0, &[(PFX, 64, 0xc0, 3600, 1800)]),
        &mut out,
    );
    assert!(poll_at(&mut i, now).is_empty());
    assert_eq!(i.ipv6_changed(), None); // tentative
    assert!(poll_at(&mut i, now + Duration::from_millis(1100)).is_empty());
    assert_eq!(
        i.ipv6_changed(),
        Some(vec![wire6::link_local(MAC_B), slaac_addr(PFX, MAC_B)])
    );
    assert!(super::is_neighbor_frame(&ra_frame(600, 64, 0, &[])));
}

/// Multi-queue: an ICMP / ICMPv6 error quoting a dialed connection's datagram or segment goes
/// to the queue owning its port, like the connection's own packets (RSS hashes an ICMP error by
/// its addresses only, so it lands on any queue).
#[test]
fn icmp_errors_for_dialed_ports_go_to_their_queue() {
    let t = Instant::now();
    let mut c = config(B, MAC_B, params());
    c.ip6 = Some(B6);
    c.queues = 2;
    let mut i = Iface::new(c, t);
    let mut out = Cap::default();
    // Port 49153 belongs to queue 1, 49152 to queue 0 (this one).
    for (proto, port, owner) in [
        (wire::PROTO_UDP, 49153u16, Some(1usize)),
        (wire::PROTO_TCP, 49153, Some(1)),
        (wire::PROTO_UDP, 49152, None),
    ] {
        let mut quoted = vec![0u8; wire::IPV4_HDR + 8];
        wire::write_ipv4(&mut quoted, B, A, proto, 1, 0, 64, 0, 8);
        quoted[wire::IPV4_HDR..wire::IPV4_HDR + 2].copy_from_slice(&port.to_be_bytes());
        quoted[wire::IPV4_HDR + 2..wire::IPV4_HDR + 4].copy_from_slice(&9003u16.to_be_bytes());
        let mut m = vec![0u8; wire::ICMP_HDR + quoted.len()];
        wire::write_icmp(&mut m, wire::ICMP_UNREACHABLE, 3, [0; 4], &quoted);
        let mut f = vec![0u8; ETH_HDR + wire::IPV4_HDR + m.len()];
        wire::write_eth(&mut f, MAC_B, MAC_A, wire::ETHERTYPE_IPV4);
        wire::write_ipv4(
            &mut f[ETH_HDR..],
            A,
            B,
            wire::PROTO_ICMP,
            2,
            0,
            64,
            0,
            m.len(),
        );
        f[ETH_HDR + wire::IPV4_HDR..].copy_from_slice(&m);
        i.receive(t, &f, &mut out);
        let want: Vec<_> = owner.map(|q| (q, f.clone())).into_iter().collect();
        assert_eq!(i.take_forward(), want, "ICMP, {proto} port {port}");

        let mut quoted = vec![0u8; wire6::IPV6_HDR + 8];
        wire6::write_ipv6(&mut quoted, B6, A6, proto, 64, 0, 8);
        quoted[wire6::IPV6_HDR..wire6::IPV6_HDR + 2].copy_from_slice(&port.to_be_bytes());
        for (kind, rest) in [
            (wire6::ICMP6_UNREACHABLE, [0; 4]),
            (wire6::ICMP6_PACKET_TOO_BIG, 1280u32.to_be_bytes()),
        ] {
            let mut m = vec![0u8; wire6::ICMP6_HDR + quoted.len()];
            wire6::write_icmp6(&mut m, A6, B6, kind, 4, rest, &quoted);
            let f = frame6(MAC_A, MAC_B, A6, B6, wire::PROTO_ICMPV6, 64, &m);
            i.receive(t, &f, &mut out);
            let want: Vec<_> = owner.map(|q| (q, f.clone())).into_iter().collect();
            assert_eq!(i.take_forward(), want, "ICMPv6 {kind}, {proto} port {port}");
        }
    }
}

// ---- Accurate ECN (RFC 9768) -----------------------------------------------------------------

fn params_acc(accecn: bool, ecn: bool) -> Params {
    Params {
        accecn,
        ecn,
        ..params()
    }
}

/// A TCP segment's (flags, ACE field as AE/CWR/ECE, AccECN option, payload length, IP ECN).
fn seg_of(frame: &[u8]) -> Option<(u8, u8, Option<wire::AccOpt>, usize, u8)> {
    let eth = Eth::parse(frame)?;
    let (src, dst, payload, ecn) = match eth.ethertype {
        wire::ETHERTYPE_IPV4 => {
            let ip = Ipv4::parse(eth.payload, false)?;
            (
                IpAddr::V4(ip.src),
                IpAddr::V4(ip.dst),
                ip.payload,
                ip.tos & 3,
            )
        }
        wire::ETHERTYPE_IPV6 => {
            let ip = wire6::Ipv6::parse(eth.payload)?;
            (
                IpAddr::V6(ip.src),
                IpAddr::V6(ip.dst),
                ip.payload,
                ip.tclass & 3,
            )
        }
        _ => return None,
    };
    let t = Tcp::parse(payload, src, dst, false)?;
    let ace = (u8::from(t.ae) << 2) | ((t.flags >> 6) & 3);
    Some((t.flags, ace, t.opts.acc, t.payload.len(), ecn))
}

#[test]
fn accecn_negotiation() {
    // (A accecn, A ecn, B accecn, B ecn) -> mode on both ends (Some(true): AccECN,
    // Some(false): RFC 3168, None: no ECN).
    for (aa, ae, ba, be, want) in [
        (true, false, true, false, Some(true)),
        (true, false, false, true, Some(false)),
        (false, true, true, false, Some(false)),
        (true, false, false, false, None),
        (false, false, true, false, None),
    ] {
        let mut s = Sim::new(LinkCfg::default(), params_acc(aa, ae), params_acc(ba, be));
        s.ab.log = Some(Vec::new());
        s.ba.log = Some(Vec::new());
        let (ha, hb) = s.connect(80, 50000);
        s.transfer(ha, hb, &pattern(30_000), Duration::from_secs(5));
        s.run_until(Duration::from_millis(200), |_| false); // the last (delayed) ACK
        let ma = s.a.tcb(ha).unwrap().ecn_mode();
        let mb = s.b.tcb(hb).unwrap().ecn_mode();
        assert_eq!((ma, mb), (want, want), "a=({aa},{ae}) b=({ba},{be})");
        let ab: Vec<_> =
            s.ab.log
                .take()
                .unwrap()
                .iter()
                .filter_map(|f| seg_of(f))
                .collect();
        let ba_: Vec<_> =
            s.ba.log
                .take()
                .unwrap()
                .iter()
                .filter_map(|f| seg_of(f))
                .collect();
        let syn = ab.iter().find(|t| t.0 & wire::SYN != 0).unwrap();
        if aa {
            assert_eq!(syn.1, 0b111, "AccECN SYN");
        }
        // Data is ECT(0) exactly when ECN is on.
        assert_eq!(
            ab.iter().any(|t| t.3 > 0 && t.4 == wire::ECT0),
            want.is_some()
        );
        if want == Some(true) {
            // The SYN-ACK feeds back the SYN's Not-ECT (0,1,0) with a full option; the first
            // ACK feeds back the SYN-ACK's Not-ECT in the handshake encoding with an option;
            // later ACE fields carry r.cep = 5.
            let synack = ba_.iter().find(|t| t.0 & wire::SYN != 0).unwrap();
            assert_eq!(synack.1, 0b010);
            assert_eq!(
                synack.2.map(|o| (o.n, o.e0b(), o.ceb(), o.e1b())),
                Some((3, Some(1), Some(0), Some(1)))
            );
            let first_ack = ab.iter().find(|t| t.0 & wire::SYN == 0).unwrap();
            assert_eq!((first_ack.1, first_ack.3), (0b010, 0));
            assert!(first_ack.2.is_some());
            assert!(
                ab.iter()
                    .filter(|t| t.0 & wire::SYN == 0)
                    .skip(1)
                    .all(|t| t.1 == 0b101)
            );
            // B's ACKs report the ECT(0) bytes it received.
            let last = ba_
                .iter()
                .rev()
                .find_map(|t| t.2.and_then(|o| o.e0b()))
                .unwrap();
            assert_eq!(last, 1 + 30_000);
            let (c, ect) = s.a.tcb(ha).unwrap().acc_counters().unwrap();
            assert!(ect);
            assert_eq!(c[5], 1 + 30_000, "s.e0b");
        }
    }
}

/// `bottleneck` with AccECN on both ends: (drops, CE marks, sender s.cep - 5, receiver
/// r.cep - 5, sender s.ceb, receiver r.ceb).
fn bottleneck_acc(v6: bool, ack_loss: f64, ce_mark: usize) -> (u64, u64, u32, u32, u32, u32) {
    let link = LinkCfg {
        delay: Duration::from_millis(5),
        rate: 2_500_000,
        queue: 20,
        ce_mark,
        ..LinkCfg::default()
    };
    let p = params_acc(true, false);
    let mut s = if v6 {
        Sim::new6(link, p, p)
    } else {
        Sim::new(link, p, p)
    };
    let to = if v6 { IpAddr::V6(B6) } else { IpAddr::V4(B) };
    let (ha, hb) = s.connect_to(to, 80, 50000);
    if ack_loss > 0.0 {
        let mut rng = Rng(77);
        s.filter_ba(move |_| rng.chance(ack_loss));
    }
    s.transfer(ha, hb, &pattern(1 << 20), Duration::from_secs(60));
    // Let the last ACKs arrive.
    s.filter_ba(|_| false);
    s.run_until(Duration::from_millis(500), |_| false);
    let (sa_, ect) = s.a.tcb(ha).unwrap().acc_counters().unwrap();
    let (sb, _) = s.b.tcb(hb).unwrap().acc_counters().unwrap();
    assert!(ect, "no false mangling verdict");
    (
        s.dropped().0,
        s.ab_stats().1,
        sa_[3] - 5,
        sb[0] - 5,
        sa_[4],
        sb[1],
    )
}

#[test]
fn accecn_marks_are_fed_back_exactly() {
    for v6 in [false, true] {
        let (drops_plain, _, _, _) = bottleneck(v6, false, false);
        let (drops, marks, s_cep, r_cep, s_ceb, r_ceb) = bottleneck_acc(v6, 0.0, 8);
        eprintln!(
            "v6={v6}: plain {drops_plain} drops; accecn {drops} drops {marks} marks, r.cep {r_cep} s.cep {s_cep}, r.ceb {r_ceb} s.ceb {s_ceb}"
        );
        assert!(marks > 0);
        assert!(
            drops < drops_plain,
            "AccECN avoids drops ({drops} vs {drops_plain})"
        );
        // Every CE mark the receiver saw (data and the odd control packet) reached the sender.
        assert_eq!(u64::from(r_cep), marks);
        assert_eq!(s_cep, r_cep);
        assert_eq!(s_ceb, r_ceb);
    }
}

#[test]
fn accecn_survives_ack_loss() {
    // A fifth of the ACKs lost while nearly every queued packet is marked (hundreds of
    // marks): the byte counters of the option stay exact, the 3-bit packet counter never
    // falls behind (a possible wrap is counted, A.2.2), and no ACK of a retransmission (which
    // carries no option) passes for mangled feedback.
    let (_, marks, s_cep, r_cep, s_ceb, r_ceb) = bottleneck_acc(false, 0.2, 1);
    eprintln!("ack loss: {marks} marks, r.cep {r_cep} s.cep {s_cep}, r.ceb {r_ceb} s.ceb {s_ceb}");
    assert!(marks > 100);
    assert_eq!(s_ceb, r_ceb);
    assert!(s_cep >= r_cep);
}

#[test]
fn accecn_syn_cookies() {
    let mut cb = config(B, MAC_B, params_acc(true, false));
    cb.backlog = 0;
    let mut s = Sim::with(
        LinkCfg::default(),
        config(A, MAC_A, params_acc(true, false)),
        cb,
    );
    let (ha, hb) = s.connect(80, 50000);
    assert_eq!(s.a.tcb(ha).unwrap().ecn_mode(), Some(true));
    assert_eq!(s.b.tcb(hb).unwrap().ecn_mode(), Some(true));
    s.transfer(ha, hb, &pattern(50_000), Duration::from_secs(5));
    // A cookie server without AccECN gives no ECN.
    let mut cb = config(B, MAC_B, params());
    cb.backlog = 0;
    let mut s = Sim::with(
        LinkCfg::default(),
        config(A, MAC_A, params_acc(true, false)),
        cb,
    );
    let (ha, hb) = s.connect(80, 50000);
    assert_eq!(s.a.tcb(ha).unwrap().ecn_mode(), None);
    assert_eq!(s.b.tcb(hb).unwrap().ecn_mode(), None);
}

#[test]
fn accecn_handshake_fallbacks() {
    // Two lost SYNs: the third goes without AE/CWR/ECE (RFC 9768 3.1.4.1), no ECN.
    let mut s = Sim::new(
        LinkCfg::default(),
        params_acc(true, false),
        params_acc(true, false),
    );
    let mut syns = 0;
    s.filter_ab(move |f| {
        let syn = seg_of(f).is_some_and(|t| t.0 & wire::SYN != 0);
        syns += u32::from(syn);
        syn && syns <= 2
    });
    let (ha, hb) = s.connect(80, 50000);
    assert_eq!(s.a.tcb(ha).unwrap().ecn_mode(), None);
    assert_eq!(s.b.tcb(hb).unwrap().ecn_mode(), None);
    // Two lost SYN-ACKs: the server stays in AccECN mode but its third SYN-ACK has no AccECN
    // flags, so the client has no ECN and the server sends nothing ECN-capable (3.1.5).
    let mut s = Sim::new(
        LinkCfg::default(),
        params_acc(true, false),
        params_acc(true, false),
    );
    let mut synacks = 0;
    s.filter_ba(move |f| {
        let synack = seg_of(f).is_some_and(|t| t.0 & wire::SYN != 0);
        synacks += u32::from(synack);
        synack && synacks <= 2
    });
    s.ba.log = Some(Vec::new());
    let (ha, hb) = s.connect(80, 50000);
    assert_eq!(s.a.tcb(ha).unwrap().ecn_mode(), None);
    let (_, ect) = s.b.tcb(hb).unwrap().acc_counters().unwrap();
    assert!(!ect);
    // B -> A data is Not-ECT.
    let data = pattern(20_000);
    let mut sent = 0;
    let mut got = 0;
    let mut buf = vec![0u8; 65536];
    s.run_until(Duration::from_secs(5), |s| {
        sent += s.b.tcp_send(hb, &data[sent..]);
        got += s.a.tcp_recv(ha, &mut buf);
        got == data.len()
    });
    let log = s.ba.log.take().unwrap();
    assert!(
        log.iter()
            .filter_map(|f| seg_of(f))
            .filter(|t| t.3 > 0)
            .all(|t| t.4 == 0)
    );
    let synacks: Vec<u8> = log
        .iter()
        .filter_map(|f| seg_of(f))
        .filter(|t| t.0 & wire::SYN != 0)
        .map(|t| t.1)
        .collect();
    assert_eq!(synacks, vec![0b010, 0b010, 0]);
}

#[test]
fn accecn_option_wire_format() {
    let o = wire::AccOpt::order0(2, 0x0102_0304, 7, 9);
    let mut opts = wire::TcpOpts {
        ts: Some((1, 2)),
        acc: Some(o),
        ..wire::TcpOpts::default()
    };
    let mut b = [0u8; 40];
    let n = opts.write(&mut b);
    assert_eq!(n, opts.len());
    assert_eq!(n % 4, 0);
    let back = wire::TcpOpts::parse(&b[..n]);
    assert_eq!(back.acc, Some(o));
    assert_eq!(
        (o.e0b(), o.ceb(), o.e1b()),
        (Some(0x02_0304), Some(7), None)
    );
    // Order 1 and odd lengths (whole fields only).
    let order1 = [174u8, 11, 0, 0, 1, 0, 0, 2, 0, 0, 3];
    let a = wire::TcpOpts::parse(&order1).acc.unwrap();
    assert_eq!((a.e1b(), a.ceb(), a.e0b()), (Some(1), Some(2), Some(3)));
    let odd = [172u8, 7, 0, 0, 5, 9, 9];
    let a = wire::TcpOpts::parse(&odd).acc.unwrap();
    assert_eq!((a.n, a.e0b(), a.ceb()), (1, Some(5), None));
    assert_eq!(a, wire::AccOpt::order0(1, 5, 0, 0));
    opts.acc = Some(wire::AccOpt::order0(0, 0, 0, 0));
    let n = opts.write(&mut b);
    assert_eq!(wire::TcpOpts::parse(&b[..n]).acc.map(|a| a.n), Some(0));
}
