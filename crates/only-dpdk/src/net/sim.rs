//! Two interfaces over a simulated Ethernet link in virtual time: propagation delay, a
//! bandwidth-limited drop-tail bottleneck queue, random loss and reordering. Deterministic
//! (seeded PRNG), so TCP correctness and throughput are tested reproducibly.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};

use super::{
    CcKind, Config, Event, Iface, Params, TcpError, TcpHandle, Tx,
    tcp::State,
    wire::{self, ETH_HDR, Eth, Ipv4, Tcp},
};

pub(super) const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub(super) const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
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
            filter: None,
            log: None,
        }
    }

    fn push(&mut self, now: Instant, frame: Vec<u8>, rng: &mut Rng, seq: u64) {
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
    }
}

pub(super) fn config(ip: Ipv4Addr, mac: [u8; 6], p: Params) -> Config {
    Config {
        mac,
        ip,
        prefix_len: 24,
        gateway: None,
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

    /// Puts frames A transmitted outside `poll` on the link.
    fn out_a(&mut self, cap: Cap) {
        for f in cap.0 {
            self.seq += 1;
            self.ab.push(self.now, f, &mut self.rng, self.seq);
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
        self.b.tcp_listen(port);
        let ha = self
            .a
            .tcp_connect(local, SocketAddrV4::new(B, port), self.now)
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
    let _ = s.a.udp_send(
        s.now,
        &mut cap,
        5000,
        SocketAddrV4::new(B, 53),
        &pattern(3000),
    );
    let _ = s.a.udp_send(
        s.now,
        &mut cap,
        5000,
        SocketAddrV4::new(B, 54),
        b"closed port",
    );
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

/// TCP segments of a frame: (flags, seq, payload length).
fn tcp_of(frame: &[u8]) -> Option<(u8, u32, usize)> {
    let eth = Eth::parse(frame)?;
    let ip = Ipv4::parse(eth.payload, false)?;
    if ip.proto != wire::PROTO_TCP {
        return None;
    }
    let t = Tcp::parse(ip.payload, ip.src, ip.dst, false)?;
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
    let h =
        s.a.tcp_connect(50000, SocketAddrV4::new(B, 81), s.now)
            .unwrap();
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
        .map(|i| {
            s.a.tcp_connect(50000 + i, SocketAddrV4::new(B, 80), s.now)
                .unwrap()
        })
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
        .map(|i| {
            s.a.tcp_connect(20000 + i, SocketAddrV4::new(B, 80), s.now)
                .unwrap()
        })
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
fn udp_fragmentation_and_port_unreachable() {
    let mut s = Sim::new(LinkCfg::default(), params(), params());
    s.a.udp_bind(5000);
    s.b.udp_bind(6000);
    let big = pattern(20_000);
    let mut cap = Cap::default();
    s.a.udp_send(s.now, &mut cap, 5000, SocketAddrV4::new(B, 6000), &big)
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
    assert_eq!((port, from), (6000, SocketAddrV4::new(A, 5000)));
    assert!(data == big);
    // To a closed port: ICMP port unreachable comes back as an event.
    s.a.udp_send(s.now, &mut cap, 5000, SocketAddrV4::new(B, 6001), b"x")
        .unwrap();
    s.out_a(cap);
    let mut unreachable = false;
    s.run_until(Duration::from_secs(1), |s| {
        unreachable |= s.ev_a.contains(&Event::UdpUnreachable {
            port: 5000,
            remote: SocketAddrV4::new(B, 6001),
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
    s.a.udp_send(s.now, &mut cap, 1, SocketAddrV4::new(B, 1), b"x")
        .unwrap();
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
        .map(|i| {
            s.a.tcp_connect(30000 + i as u16, SocketAddrV4::new(B, 80), s.now)
                .unwrap()
        })
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
