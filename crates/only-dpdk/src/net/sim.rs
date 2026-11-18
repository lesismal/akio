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
/// interfaces, without threads or a link model: `cargo test --release -p only-dpdk --lib
/// bench_request_response -- --ignored --nocapture`. `ONLY_RR_N` sets the round trips.
#[test]
#[ignore]
fn bench_request_response() {
    let link = LinkCfg {
        delay: Duration::ZERO,
        ..LinkCfg::default()
    };
    let mut s = Sim::new(link, params(), params());
    let (ha, hb) = s.connect(80, 50000);
    let n: u32 = std::env::var("ONLY_RR_N")
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
/// `cargo test --release -p only-dpdk --lib bench_connection_cycle -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench_connection_cycle() {
    let link = LinkCfg {
        delay: Duration::ZERO,
        ..LinkCfg::default()
    };
    let mut s = Sim::new(link, params(), params());
    s.b.tcp_listen(80);
    let n: u16 = std::env::var("ONLY_CC_N")
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
