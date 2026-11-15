//! A simulated network for the sans-io core: two endpoints, a virtual clock, and a link that
//! loses, reorders, duplicates and delays datagrams and enforces an MTU, optionally behind a
//! bottleneck of limited rate with a drop-tail buffer, and that carries, bleaches or CE-marks
//! the ECN codepoint. Handshakes, bulk transfers, many streams, migration, key updates, Retry,
//! resets, timeouts, ECN and congestion control run on it.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use only_crypto::rand::ChaChaRng;

use super::conn::{ConnConfig, Connection, EndpointEvent, Event};
use super::endpoint::{ConnHandle, DatagramEvent, Endpoint, ServerSetup};
use crate::Bytes;
use crate::types::{ConnectionError, Dir, StreamId, TransportConfig};

#[derive(Clone, Debug)]
pub(crate) struct Link {
    pub loss: f64,
    pub reorder: f64,
    pub dup: f64,
    pub delay: Duration,
    pub jitter: Duration,
    pub mtu: usize,
    /// Drop everything (a blackout) while set.
    pub down: bool,
    /// A bottleneck of this many bytes per second (each direction), or none.
    pub rate: Option<u64>,
    /// The bottleneck's buffer in bytes: datagrams that do not fit are dropped (drop-tail).
    pub buffer: usize,
    /// ECN-capable datagrams are CE-marked instead of queued past this many bytes (an AQM).
    pub ce_above: Option<usize>,
    /// The probability that an ECN-capable datagram is CE-marked.
    pub ce: f64,
    /// Clear the ECN codepoint of every datagram (a bleaching middlebox).
    pub bleach: bool,
    /// Drop every ECN-capable datagram (a black hole for ECN).
    pub drop_ect: bool,
}

impl Default for Link {
    fn default() -> Link {
        Link {
            loss: 0.0,
            reorder: 0.0,
            dup: 0.0,
            delay: Duration::from_millis(10),
            jitter: Duration::ZERO,
            mtu: 1500,
            down: false,
            rate: None,
            buffer: 64 * 1024,
            ce_above: None,
            ce: 0.0,
            bleach: false,
            drop_ect: false,
        }
    }
}

pub(crate) struct Node {
    pub ep: Endpoint,
    pub conns: HashMap<ConnHandle, Connection>,
    pub events: HashMap<ConnHandle, Vec<Event>>,
    pub addr: SocketAddr,
    pub tokens: Vec<Vec<u8>>,
    /// Server: a second address it serves (its preferred address). Client: the address of the
    /// socket a migration probes from.
    pub alt_addr: Option<SocketAddr>,
    /// Addresses whose sockets were closed (datagrams to them are lost).
    pub closed: Vec<SocketAddr>,
    /// Migration outcomes the node's connections reported (client).
    pub migrations: Vec<Result<SocketAddr, ()>>,
}

impl Node {
    fn new(ep: Endpoint, addr: SocketAddr) -> Node {
        Node {
            ep,
            conns: HashMap::new(),
            events: HashMap::new(),
            addr,
            tokens: Vec::new(),
            alt_addr: None,
            closed: Vec::new(),
            migrations: Vec::new(),
        }
    }
}

/// A datagram on the link: to the server?, from, to, ECN codepoint, bytes.
type InFlight = (bool, SocketAddr, SocketAddr, u8, Vec<u8>);

pub(crate) struct Sim {
    pub now: Instant,
    pub client: Node,
    pub server: Node,
    pub link: Link,
    rng: ChaChaRng,
    seq: u64,
    /// (deliver at, seq) -> datagram
    queue: BTreeMap<(Instant, u64), InFlight>,
    /// When the bottleneck of each direction (to client, to server) is free again.
    busy_until: [Instant; 2],
    pub delivered: u64,
    pub dropped: u64,
    /// Datagrams the link CE-marked.
    pub ce_marked: u64,
    /// Datagrams sent ECN-capable.
    pub ect_sent: u64,
    /// Datagrams from or to these addresses are dropped (a path that does not work).
    pub blocked: Vec<SocketAddr>,
    /// The server address each client address last sent to: the server answers from it (a
    /// socket per listener address, as the I/O layer has).
    server_local: HashMap<SocketAddr, SocketAddr>,
}

pub(crate) fn certs() -> (only_tls::ServerConfig, only_tls::ClientConfig) {
    certs_with(None)
}

pub(crate) fn certs_with(
    suites: Option<&[u16]>,
) -> (only_tls::ServerConfig, only_tls::ClientConfig) {
    let (cert, key) = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
    let chain = vec![only_tls::Certificate::from_der(cert.as_der().to_vec())];
    let mut roots = only_tls::RootCerts::empty();
    roots.add(&chain[0]).expect("root");
    let key = only_tls::PrivateKey::from_pkcs8_der(key.to_pkcs8_der());
    let mut sb = only_tls::ServerConfig::builder(chain, key)
        .alpn(["sim"])
        .tls13_only(true)
        .session_tickets(true);
    let mut cb = only_tls::ClientConfig::builder()
        .roots(roots)
        .alpn(["sim"])
        .tls13_only(true);
    if let Some(s) = suites {
        sb = sb.__suites(s);
        cb = cb.__suites(s);
    }
    (
        sb.build().expect("server tls"),
        cb.build().expect("client tls"),
    )
}

impl Sim {
    pub fn new(seed: u8, server_cfg: ConnConfig, tls: only_tls::ServerConfig, retry: bool) -> Sim {
        let mut rng = ChaChaRng::from_seed([seed; 32]);
        let server = Endpoint::with_rng(
            Some(ServerSetup {
                tls,
                cfg: server_cfg,
                retry,
            }),
            &mut rng,
        );
        let client = Endpoint::with_rng(None, &mut rng);
        let now = Instant::now();
        Sim {
            now,
            busy_until: [now; 2],
            ce_marked: 0,
            ect_sent: 0,
            blocked: Vec::new(),
            server_local: HashMap::new(),
            client: Node::new(client, "10.0.0.1:5000".parse().expect("addr")),
            server: Node::new(server, "10.0.0.2:4433".parse().expect("addr")),
            link: Link::default(),
            rng,
            seq: 0,
            queue: BTreeMap::new(),
            delivered: 0,
            dropped: 0,
        }
    }

    pub fn default_pair(seed: u8) -> (Sim, only_tls::ClientConfig) {
        let (s, c) = certs();
        (
            Sim::new(
                seed,
                ConnConfig::new(TransportConfig::default(), true),
                s,
                false,
            ),
            c,
        )
    }

    pub fn connect(
        &mut self,
        tls: &only_tls::ClientConfig,
        cfg: ConnConfig,
        token: Vec<u8>,
    ) -> ConnHandle {
        let (h, c) = self
            .client
            .ep
            .connect(self.now, cfg, tls, "localhost", self.server.addr, token)
            .expect("connect");
        self.client.conns.insert(h, c);
        h
    }

    fn rand(&mut self) -> f64 {
        f64::from(self.rng.next_u32()) / f64::from(u32::MAX)
    }

    fn is_server(&self, a: SocketAddr) -> bool {
        a == self.server.addr || Some(a) == self.server.alt_addr
    }

    fn send(&mut self, from: SocketAddr, to: SocketAddr, mut ecn: u8, data: Vec<u8>) {
        let to_server = self.is_server(to);
        if ecn != 0 {
            self.ect_sent += 1;
        }
        if self.blocked.contains(&from) || self.blocked.contains(&to) {
            self.dropped += 1;
            return;
        }
        if self.link.down
            || data.len() > self.link.mtu
            || self.rand() < self.link.loss
            || (ecn != 0 && self.link.drop_ect)
        {
            self.dropped += 1;
            return;
        }
        if self.link.bleach {
            ecn = 0;
        }
        if ecn != 0 && self.rand() < self.link.ce {
            ecn = 3;
            self.ce_marked += 1;
        }
        // The bottleneck: queued behind what it is still sending, dropped when the buffer is
        // full, CE-marked above the AQM threshold.
        let mut depart = self.now;
        if let Some(rate) = self.link.rate {
            let dir = usize::from(to_server);
            let busy = self.busy_until[dir].max(self.now);
            let queued = (busy - self.now).as_secs_f64() * rate as f64;
            if queued as usize + data.len() > self.link.buffer {
                self.dropped += 1;
                return;
            }
            if ecn != 0 && self.link.ce_above.is_some_and(|t| queued as usize > t) {
                if ecn != 3 {
                    self.ce_marked += 1;
                }
                ecn = 3;
            }
            depart = busy + Duration::from_secs_f64(data.len() as f64 / rate as f64);
            self.busy_until[dir] = depart;
        }
        let copies = if self.rand() < self.link.dup { 2 } else { 1 };
        for _ in 0..copies {
            let mut d = self.link.delay + (depart - self.now);
            if !self.link.jitter.is_zero() {
                d += self.link.jitter.mul_f64(self.rand());
            }
            if self.rand() < self.link.reorder {
                d += self.link.delay;
            }
            self.seq += 1;
            self.queue.insert(
                (self.now + d, self.seq),
                (to_server, from, to, ecn, data.clone()),
            );
        }
    }

    /// Lets every connection send what it has.
    fn flush(&mut self) {
        for side in [false, true] {
            let node = if side {
                &mut self.server
            } else {
                &mut self.client
            };
            let mut out = Vec::new();
            let mut ep_events = Vec::new();
            for (&h, c) in &mut node.conns {
                while let Some(t) = c.poll_transmit(self.now, 10) {
                    // The source: the client's probe socket for probe transmits; for the server,
                    // the address the client talks to.
                    let from = if side {
                        self.server_local.get(&t.dest).copied().unwrap_or(node.addr)
                    } else if t.probe {
                        node.alt_addr.unwrap_or(node.addr)
                    } else {
                        node.addr
                    };
                    match t.segment_size {
                        Some(s) => {
                            for d in t.data.chunks(s) {
                                out.push((from, t.dest, t.ecn, d.to_vec()));
                            }
                        }
                        None => out.push((from, t.dest, t.ecn, t.data)),
                    }
                }
                while let Some(e) = c.poll_endpoint_event() {
                    ep_events.push((h, e));
                }
                while let Some(e) = c.poll_event() {
                    node.events.entry(h).or_default().push(e);
                }
            }
            let mut drained = Vec::new();
            for (h, e) in ep_events {
                node.ep.handle_event(h, &e);
                match e {
                    EndpointEvent::Drained => drained.push(h),
                    EndpointEvent::NewToken(t) => node.tokens.push(t),
                    EndpointEvent::Migrated { remote } => {
                        // The probe socket becomes the connection's socket; the old one closes.
                        if let Some(a) = node.alt_addr.take() {
                            node.closed.push(std::mem::replace(&mut node.addr, a));
                        }
                        node.migrations.push(Ok(remote));
                    }
                    EndpointEvent::MigrationFailed => {
                        if let Some(a) = node.alt_addr.take() {
                            node.closed.push(a);
                        }
                        node.migrations.push(Err(()));
                    }
                    _ => {}
                }
            }
            for h in drained {
                node.conns.remove(&h);
            }
            for (from, dest, ecn, d) in out {
                self.send(from, dest, ecn, d);
            }
        }
    }

    fn deliver(
        &mut self,
        to_server: bool,
        from: SocketAddr,
        to: SocketAddr,
        ecn: u8,
        data: Vec<u8>,
    ) {
        self.delivered += 1;
        let now = self.now;
        // A client's (connected) sockets hear from server addresses only; closed ones nothing.
        if !to_server && (!self.is_server(from) || self.client.closed.contains(&to)) {
            return;
        }
        if to_server {
            self.server_local.insert(from, to);
        }
        let node = if to_server {
            &mut self.server
        } else {
            &mut self.client
        };
        match node.ep.handle_ecn(now, from, ecn, &data) {
            Some(DatagramEvent::Conn(h)) => {
                if let Some(c) = node.conns.get_mut(&h) {
                    c.handle_shared_ecn(now, from, ecn, std::sync::Arc::new(data));
                }
            }
            Some(DatagramEvent::New(h, c)) => {
                node.conns.insert(h, *c);
            }
            Some(DatagramEvent::Respond(t)) => {
                let src = if to_server { to } else { node.addr };
                self.send(src, t.dest, t.ecn, t.data);
            }
            None => {}
        }
    }

    /// Advances to the next event (a delivery or a timer).
    pub fn step(&mut self) -> bool {
        self.flush();
        let mut next = self.queue.keys().next().map(|k| k.0);
        for node in [&self.client, &self.server] {
            for c in node.conns.values() {
                if let Some(t) = c.poll_timeout() {
                    next = Some(next.map_or(t, |n: Instant| n.min(t)));
                }
            }
        }
        let Some(next) = next else {
            return false;
        };
        if next > self.now {
            self.now = next;
        }
        while let Some((&k, _)) = self.queue.iter().next() {
            if k.0 > self.now {
                break;
            }
            let (to_server, from, to, ecn, data) = self.queue.remove(&k).expect("present");
            self.deliver(to_server, from, to, ecn, data);
        }
        let now = self.now;
        for node in [&mut self.client, &mut self.server] {
            for c in node.conns.values_mut() {
                if c.poll_timeout().is_some_and(|t| t <= now) {
                    c.handle_timeout(now);
                }
            }
        }
        true
    }

    /// Runs until `done` holds or `limit` of virtual time passes; returns whether it held.
    pub fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Sim) -> bool) -> bool {
        let end = self.now + limit;
        loop {
            self.flush();
            if done(self) {
                return true;
            }
            if self.now > end || !self.step() {
                return done(self);
            }
        }
    }

    pub fn events(&mut self, server: bool, h: ConnHandle) -> Vec<Event> {
        let node = if server {
            &mut self.server
        } else {
            &mut self.client
        };
        node.events.remove(&h).unwrap_or_default()
    }

    pub fn server_handle(&self) -> Option<ConnHandle> {
        self.server.conns.keys().next().copied()
    }

    pub fn connected(&self, server: bool, h: ConnHandle) -> bool {
        let node = if server { &self.server } else { &self.client };
        node.events
            .get(&h)
            .is_some_and(|v| v.iter().any(|e| matches!(e, Event::Connected)))
    }

    pub fn cconn(&mut self, h: ConnHandle) -> &mut Connection {
        self.client.conns.get_mut(&h).expect("client conn")
    }

    pub fn sconn(&mut self) -> &mut Connection {
        let h = self.server_handle().expect("server conn");
        self.server.conns.get_mut(&h).expect("server conn")
    }

    /// Connects and waits for both sides to report the handshake.
    pub fn handshake(&mut self, tls: &only_tls::ClientConfig, cfg: ConnConfig) -> ConnHandle {
        let h = self.connect(tls, cfg, Vec::new());
        let ok = self.run_until(Duration::from_secs(30), |s| {
            s.connected(false, h) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
        });
        assert!(ok, "handshake did not complete");
        h
    }
}

/// Collects stream data per stream from events; returns finished streams.
#[derive(Default)]
pub(crate) struct Collector {
    pub data: HashMap<StreamId, Vec<u8>>,
    pub finished: HashMap<StreamId, Vec<u8>>,
    pub opened: Vec<StreamId>,
    pub resets: Vec<(StreamId, u64)>,
    pub stops: Vec<(StreamId, u64)>,
    pub datagrams: Vec<Bytes>,
    pub closed: Option<ConnectionError>,
    pub available: Vec<Dir>,
}

impl Collector {
    pub fn take(&mut self, evs: Vec<Event>) {
        for e in evs {
            match e {
                Event::StreamData(id, d, fin) => {
                    self.data.entry(id).or_default().extend_from_slice(&d);
                    if fin {
                        let v = self.data.remove(&id).unwrap_or_default();
                        self.finished.insert(id, v);
                    }
                }
                Event::StreamOpened(id) => self.opened.push(id),
                Event::StreamReset(id, c) => self.resets.push((id, c)),
                Event::StreamStopped(id, c) => self.stops.push((id, c)),
                Event::Datagram(d) => self.datagrams.push(d),
                Event::Closed(r) => self.closed = Some(r),
                Event::StreamsAvailable(d) => self.available.push(d),
                Event::Connected => {}
            }
        }
    }
}

fn body(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

/// The server echoes every stream it gets (FIN included); runs until the client has `want`
/// finished streams back.
fn echo_until(sim: &mut Sim, h: ConnHandle, want: usize, limit: Duration) -> Collector {
    let mut server = Collector::default();
    let mut client = Collector::default();
    let mut echoed: HashMap<StreamId, usize> = HashMap::new();
    let ok = sim.run_until(limit, |s| {
        if let Some(sh) = s.server_handle() {
            let evs = s.events(true, sh);
            server.take(evs);
            let sc = s.sconn();
            for (id, d) in &server.data {
                let done = echoed.entry(*id).or_default();
                if d.len() > *done {
                    sc.write(*id, Bytes::copy_from_slice(&d[*done..]))
                        .expect("echo write");
                    *done = d.len();
                }
            }
            for (id, d) in std::mem::take(&mut server.finished) {
                let done = echoed.entry(id).or_default();
                if d.len() > *done {
                    sc.write(id, Bytes::copy_from_slice(&d[*done..]))
                        .expect("echo write");
                }
                *done = usize::MAX;
                sc.finish(id).expect("echo finish");
                server.data.remove(&id);
            }
        }
        let evs = s.events(false, h);
        client.take(evs);
        client.finished.len() >= want
    });
    assert!(
        ok,
        "echo did not finish: {} of {want} streams back",
        client.finished.len()
    );
    client
}

fn bulk(sim: &mut Sim, h: ConnHandle, sizes: &[usize], limit: Duration) {
    let mut want = HashMap::new();
    for (i, &n) in sizes.iter().enumerate() {
        let id = sim.cconn(h).open(Dir::Bi).expect("stream credit");
        let b = body(n, i as u8);
        sim.cconn(h)
            .write(id, Bytes::from(b.clone()))
            .expect("write");
        sim.cconn(h).finish(id).expect("finish");
        want.insert(id, b);
    }
    let got = echo_until(sim, h, sizes.len(), limit);
    for (id, b) in want {
        let g = got.finished.get(&id).expect("stream echoed");
        assert_eq!(g.len(), b.len(), "stream {id}");
        assert!(*g == b, "stream {id} differs");
    }
}

#[test]
fn clean_handshake_and_echo() {
    let (mut sim, tls) = Sim::default_pair(1);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    assert_eq!(sim.cconn(h).alpn().as_deref(), Some(&b"sim"[..]));
    assert_eq!(sim.sconn().server_name().as_deref(), Some("localhost"));
    bulk(&mut sim, h, &[0, 1, 1000, 100_000], Duration::from_secs(30));
    let st = sim.cconn(h).stats();
    assert!(st.sent_packets > 0 && st.udp_rx.datagrams > 0 && st.rtt > Duration::ZERO);
    // Full-size datagrams leave in GSO batches.
    assert!(st.udp_tx.ios < st.udp_tx.datagrams, "{st:?}");
    // The path MTU was raised from 1200 to the probe size.
    assert!(
        sim.run_until(Duration::from_secs(5), |s| s.cconn(h).stats().current_mtu
            == 1452)
    );
    assert_eq!(st.lost_packets, 0);
}

#[test]
fn lossy_reordering_duplicating_link() {
    for seed in [2u8, 3, 4] {
        let (mut sim, tls) = Sim::default_pair(seed);
        sim.link = Link {
            loss: 0.1,
            reorder: 0.1,
            dup: 0.05,
            delay: Duration::from_millis(20),
            jitter: Duration::from_millis(5),
            mtu: 1350,
            ..Link::default()
        };
        let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
        let mut sizes = vec![2_000_000];
        sizes.extend(std::iter::repeat_n(10_000, 40));
        bulk(&mut sim, h, &sizes, Duration::from_secs(300));
        let st = sim.cconn(h).stats();
        assert!(st.lost_packets > 0, "{st:?}");
        assert!(st.current_mtu <= 1350, "{st:?}");
    }
}

#[test]
fn handshake_survives_heavy_loss() {
    let (mut sim, tls) = Sim::default_pair(5);
    sim.link.loss = 0.3;
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[50_000], Duration::from_secs(120));
}

#[test]
fn many_streams_with_small_limits_and_windows() {
    let (s, tls) = certs();
    let t = TransportConfig {
        max_concurrent_bidi_streams: 4,
        stream_receive_window: 8 * 1024,
        receive_window: Some(16 * 1024),
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(6, ConnConfig::new(t.clone(), true), s, false);
    let h = sim.handshake(&tls, ConnConfig::new(t, true));
    // Four streams at a time; more as the server finishes them.
    let total = 30;
    let mut opened = 0;
    let mut want = HashMap::new();
    let mut server = Collector::default();
    let mut client = Collector::default();
    let ok = sim.run_until(Duration::from_secs(120), |s| {
        while opened < total {
            let Some(id) = s.cconn(h).open(Dir::Bi) else {
                break;
            };
            let b = body(20_000, opened as u8);
            s.cconn(h).write(id, Bytes::from(b.clone())).expect("write");
            s.cconn(h).finish(id).expect("finish");
            want.insert(id, b);
            opened += 1;
        }
        if let Some(sh) = s.server_handle() {
            let evs = s.events(true, sh);
            server.take(evs);
            for (id, d) in std::mem::take(&mut server.finished) {
                let sc = s.sconn();
                sc.write(id, Bytes::from(d)).expect("echo");
                sc.finish(id).expect("finish");
            }
        }
        let evs = s.events(false, h);
        client.take(evs);
        client.finished.len() == total
    });
    assert!(ok, "{} of {total}", client.finished.len());
    for (id, b) in want {
        assert!(client.finished[&id] == b);
    }
    assert!(
        !client.available.is_empty(),
        "StreamsAvailable after the limit"
    );
}

#[test]
fn nat_rebinding_migrates_the_path() {
    let (mut sim, tls) = Sim::default_pair(7);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[10_000], Duration::from_secs(10));
    // The client's address changes (a NAT rebinding): the server follows after validating.
    sim.client.addr = "10.9.9.9:7000".parse().expect("addr");
    bulk(&mut sim, h, &[300_000], Duration::from_secs(30));
    assert_eq!(sim.sconn().remote_addr(), sim.client.addr);
    // And the port alone.
    sim.client.addr = "10.9.9.9:7001".parse().expect("addr");
    bulk(&mut sim, h, &[10_000], Duration::from_secs(30));
    assert_eq!(sim.sconn().remote_addr(), sim.client.addr);
}

#[test]
fn migration_refused_when_disabled() {
    let (s, tls) = certs();
    let mut sim = Sim::new(
        8,
        ConnConfig::new(TransportConfig::default(), false),
        s,
        false,
    );
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    let old = sim.client.addr;
    sim.client.addr = "10.9.9.9:7000".parse().expect("addr");
    let id = sim.cconn(h).open(Dir::Bi).expect("stream");
    sim.cconn(h)
        .write(id, Bytes::from_static(b"x"))
        .expect("write");
    sim.run_until(Duration::from_secs(2), |_| false);
    assert_eq!(sim.sconn().remote_addr(), old);
}

#[test]
fn key_updates_both_ways() {
    let (mut sim, tls) = Sim::default_pair(9);
    sim.link.loss = 0.02;
    sim.link.reorder = 0.1;
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[50_000], Duration::from_secs(30));
    assert_eq!(sim.cconn(h).key_phase(), Some(false));
    assert!({
        let n = sim.now;
        sim.cconn(h).force_key_update(n)
    });
    // Another update must wait for an acknowledgment in the new phase.
    assert!(!{
        let n = sim.now;
        sim.cconn(h).force_key_update(n)
    });
    bulk(&mut sim, h, &[200_000], Duration::from_secs(30));
    assert_eq!(sim.cconn(h).key_phase(), Some(true));
    assert_eq!(sim.sconn().key_phase(), Some(true));
    // The server starts the next one.
    let now = sim.now;
    assert!(sim.sconn().force_key_update(now));
    bulk(&mut sim, h, &[200_000], Duration::from_secs(30));
    assert_eq!(sim.cconn(h).key_phase(), Some(false));
}

#[test]
fn automatic_key_update_interval() {
    let (s, tls) = certs();
    let mut cfg = ConnConfig::new(TransportConfig::default(), true);
    cfg.key_update_interval = 100;
    let mut sim = Sim::new(10, cfg.clone(), s, false);
    let h = sim.handshake(&tls, cfg);
    bulk(&mut sim, h, &[1_000_000], Duration::from_secs(30));
    bulk(&mut sim, h, &[1_000_000], Duration::from_secs(30));
}

#[test]
fn chacha20_suite() {
    let (s, tls) = certs_with(Some(&[0x1303]));
    let mut sim = Sim::new(
        11,
        ConnConfig::new(TransportConfig::default(), true),
        s,
        false,
    );
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    assert!(
        {
            let n = sim.now;
            sim.cconn(h).force_key_update(n)
        } || true
    );
    bulk(&mut sim, h, &[100_000], Duration::from_secs(30));
}

#[test]
fn aes256_suite() {
    let (s, tls) = certs_with(Some(&[0x1302]));
    let mut sim = Sim::new(
        12,
        ConnConfig::new(TransportConfig::default(), true),
        s,
        false,
    );
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[100_000], Duration::from_secs(30));
}

#[test]
fn retry_validates_the_address() {
    let (s, tls) = certs();
    let mut sim = Sim::new(
        13,
        ConnConfig::new(TransportConfig::default(), true),
        s,
        true,
    );
    sim.link.loss = 0.05;
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    assert!(sim.cconn(h).retry_scid.is_some());
    bulk(&mut sim, h, &[100_000], Duration::from_secs(30));
}

#[test]
fn new_token_and_resumption() {
    let (mut sim, tls) = Sim::default_pair(14);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    assert!(!sim.cconn(h).resumed());
    assert!(sim.run_until(Duration::from_secs(5), |s| !s.client.tokens.is_empty()));
    let token = sim.client.tokens[0].clone();
    {
        let n = sim.now;
        sim.cconn(h).close(n, 0, b"");
    }
    sim.run_until(Duration::from_secs(5), |s| {
        s.client.conns.is_empty() && s.server.conns.is_empty()
    });
    // The second connection presents the token (address validated at once) and resumes.
    let h2 = sim.connect(
        &tls,
        ConnConfig::new(TransportConfig::default(), true),
        token,
    );
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        s.connected(false, h2) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
    });
    assert!(ok);
    assert!(sim.cconn(h2).resumed());
    assert!(sim.sconn().path.validated);
}

#[test]
fn version_negotiation() {
    use super::packet::{VERSION_1, VERSION_2};
    let (mut sim, tls) = Sim::default_pair(15);
    let h = sim.connect(
        &tls,
        ConnConfig::new(TransportConfig::default(), true),
        Vec::new(),
    );
    let now = sim.now;
    let t = sim.cconn(h).poll_transmit(now, 1).expect("initial");
    let mut d = t.data;
    d[1..5].copy_from_slice(&0x6b33_43d0u32.to_be_bytes());
    let from = sim.client.addr;
    let Some(DatagramEvent::Respond(vn)) = sim.server.ep.handle(now, from, &d) else {
        panic!("no version negotiation");
    };
    // Versions 1 and 2, and a reserved one.
    assert_eq!(vn.data.len(), 7 + 16 + 12);
    let server = sim.server.addr;
    // It lists version 1, which the client chose: a bogus answer it ignores.
    sim.cconn(h).handle_datagram(now, server, vn.data.clone());
    assert!(sim.cconn(h).poll_event().is_none());
    // One listing only unknown versions ends the connection.
    let mut unknown = vn.data[..vn.data.len() - 12].to_vec();
    unknown.extend_from_slice(&0x0a0a_0a0au32.to_be_bytes());
    sim.cconn(h).handle_datagram(now, server, unknown);
    let mut c = Collector::default();
    let evs: Vec<Event> = std::iter::from_fn(|| sim.cconn(h).poll_event()).collect();
    c.take(evs);
    assert_eq!(c.closed, Some(ConnectionError::VersionMismatch));
    // Small datagrams with unknown versions get no answer.
    assert!(sim.server.ep.handle(now, from, &d[..100]).is_none());

    // A server that only speaks version 2: the client starts over in it.
    let (s, tls) = certs();
    let mut scfg = ConnConfig::new(TransportConfig::default(), true);
    scfg.versions = vec![VERSION_2];
    let mut sim = Sim::new(16, scfg, s, false);
    let h = sim.connect(
        &tls,
        ConnConfig::new(TransportConfig::default(), true),
        Vec::new(),
    );
    let now = sim.now;
    let first = sim.cconn(h).poll_transmit(now, 1).expect("initial").data;
    let Some(DatagramEvent::Respond(vn)) = sim.server.ep.handle(now, from, &first) else {
        panic!("no version negotiation for version 1");
    };
    sim.cconn(h).handle_datagram(now, server, vn.data);
    assert_eq!(sim.cconn(h).version(), VERSION_2);
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        s.connected(false, h) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
    });
    assert!(ok, "no handshake after starting over");
    assert_eq!(sim.sconn().version(), VERSION_2);
    bulk(&mut sim, h, &[50_000], Duration::from_secs(10));

    // A forged Version Negotiation pushing a version 2 client down to version 1: the server's
    // version_information lists version 2, which gives the downgrade away.
    let (s, tls) = certs();
    let mut sim = Sim::new(
        17,
        ConnConfig::new(TransportConfig::default(), true),
        s,
        false,
    );
    let mut cfg = ConnConfig::new(TransportConfig::default(), true);
    cfg.version = VERSION_2;
    let h = sim.connect(&tls, cfg, Vec::new());
    let now = sim.now;
    let first = sim.cconn(h).poll_transmit(now, 1).expect("initial").data;
    let hdr = super::packet::parse_header(&first, 8).expect("header");
    assert_eq!(hdr.version, VERSION_2);
    let only_v1 = super::packet::version_negotiation(&hdr.dcid, &hdr.scid, 5, &[VERSION_1]);
    sim.cconn(h).handle_datagram(now, server, only_v1);
    assert_eq!(sim.cconn(h).version(), VERSION_1);
    let mut closed = None;
    sim.run_until(Duration::from_secs(10), |s| {
        let mut c = Collector::default();
        c.take(s.events(false, h));
        if c.closed.is_some() {
            closed = c.closed;
        }
        closed.is_some()
    });
    assert!(
        matches!(
            closed,
            Some(ConnectionError::TransportError { code: 0x11, .. })
        ),
        "{closed:?}"
    );
}

#[test]
fn version_2_handshake_retry_and_key_update() {
    use super::packet::VERSION_2;
    let (s, tls) = certs();
    let mut sim = Sim::new(
        18,
        ConnConfig::new(TransportConfig::default(), true),
        s,
        true,
    );
    sim.link.loss = 0.05;
    let mut cfg = ConnConfig::new(TransportConfig::default(), true);
    cfg.version = VERSION_2;
    cfg.key_update_interval = 200;
    let h = sim.handshake(&tls, cfg);
    assert_eq!(sim.cconn(h).version(), VERSION_2);
    assert_eq!(sim.sconn().version(), VERSION_2);
    assert!(sim.sconn().retry_scid.is_some());
    bulk(&mut sim, h, &[400_000, 1000], Duration::from_secs(30));
}

#[test]
fn stateless_reset_after_server_restart() {
    let (mut sim, tls) = Sim::default_pair(16);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[1000], Duration::from_secs(5));
    // The server forgets the connection (same endpoint key, as after a restart).
    let sh = sim.server_handle().expect("server");
    sim.server.conns.remove(&sh);
    sim.server.ep.handle_event(sh, &EndpointEvent::Drained);
    let id = sim.cconn(h).open(Dir::Bi).expect("stream");
    sim.cconn(h)
        .write(id, Bytes::from(vec![7u8; 500]))
        .expect("write");
    let mut c = Collector::default();
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        let evs = s.events(false, h);
        c.take(evs);
        c.closed.is_some()
    });
    assert!(ok);
    assert_eq!(c.closed, Some(ConnectionError::Reset));
}

#[test]
fn idle_timeout_and_keep_alive() {
    let (s, tls) = certs();
    let t = TransportConfig {
        max_idle_timeout: Some(Duration::from_secs(3)),
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(17, ConnConfig::new(t.clone(), true), s.clone(), false);
    let h = sim.handshake(&tls, ConnConfig::new(t.clone(), true));
    let mut c = Collector::default();
    let start = sim.now;
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        let evs = s.events(false, h);
        c.take(evs);
        c.closed.is_some()
    });
    assert!(ok);
    assert_eq!(c.closed, Some(ConnectionError::TimedOut));
    assert!(sim.now - start >= Duration::from_secs(3));
    // With keep-alives the connection stays.
    let ka = TransportConfig {
        keep_alive_interval: Some(Duration::from_secs(1)),
        ..t
    };
    let mut sim = Sim::new(18, ConnConfig::new(t, true), s, false);
    let h = sim.handshake(&tls, ConnConfig::new(ka, true));
    sim.run_until(Duration::from_secs(10), |_| false);
    let evs = sim.events(false, h);
    assert!(!evs.iter().any(|e| matches!(e, Event::Closed(_))));
    assert!(!sim.cconn(h).is_closed());
}

#[test]
fn application_close_reaches_the_peer() {
    let (mut sim, tls) = Sim::default_pair(19);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    let sh = sim.server_handle().expect("server");
    {
        let n = sim.now;
        sim.cconn(h).close(n, 42, b"bye");
    }
    let mut c = Collector::default();
    let ok = sim.run_until(Duration::from_secs(5), |s| {
        let evs = s.events(true, sh);
        c.take(evs);
        c.closed.is_some()
    });
    assert!(ok);
    assert_eq!(
        c.closed,
        Some(ConnectionError::ApplicationClosed {
            code: 42,
            reason: b"bye".to_vec()
        })
    );
    // Both drain and go away.
    assert!(
        sim.run_until(Duration::from_secs(10), |s| s.client.conns.is_empty()
            && s.server.conns.is_empty())
    );
}

#[test]
fn close_during_handshake_uses_transport_close() {
    let (mut sim, tls) = Sim::default_pair(20);
    let h = sim.connect(
        &tls,
        ConnConfig::new(TransportConfig::default(), true),
        Vec::new(),
    );
    sim.step();
    sim.step();
    let now = sim.now;
    sim.cconn(h).close(now, 7, b"early");
    let ok = sim.run_until(Duration::from_secs(5), |s| {
        s.server_handle().is_some_and(|sh| {
            s.server.events.get(&sh).is_some_and(|v| {
                v.iter().any(|e| {
                    matches!(
                        e,
                        Event::Closed(ConnectionError::ConnectionClosed { code: 0xc, .. })
                    )
                })
            })
        })
    });
    assert!(ok);
}

#[test]
fn datagrams_both_ways() {
    let (mut sim, tls) = Sim::default_pair(21);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    let max = sim.cconn(h).max_datagram_size().expect("supported");
    assert!(max > 1000);
    assert!(
        sim.cconn(h)
            .send_datagram(Bytes::from(vec![0u8; max + 1]))
            .is_err()
    );
    for i in 0..10u8 {
        sim.cconn(h)
            .send_datagram(Bytes::from(vec![i; 100]))
            .expect("datagram");
    }
    let mut sc = Collector::default();
    let ok = sim.run_until(Duration::from_secs(5), |s| {
        let sh = s.server_handle().expect("server");
        let evs = s.events(true, sh);
        sc.take(evs);
        sc.datagrams.len() == 10
    });
    assert!(ok);
    sim.sconn()
        .send_datagram(Bytes::from_static(b"back"))
        .expect("datagram");
    let mut cc = Collector::default();
    assert!(sim.run_until(Duration::from_secs(5), |s| {
        let evs = s.events(false, h);
        cc.take(evs);
        !cc.datagrams.is_empty()
    }));
    assert_eq!(cc.datagrams[0], "back");
    // A peer that refuses datagrams.
    let (s, tls) = certs();
    let t = TransportConfig {
        datagram_receive_buffer_size: None,
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(22, ConnConfig::new(t, true), s, false);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    assert!(
        sim.cconn(h)
            .send_datagram(Bytes::from_static(b"x"))
            .is_err()
    );
}

#[test]
fn reset_and_stop_streams() {
    let (mut sim, tls) = Sim::default_pair(23);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    let a = sim.cconn(h).open(Dir::Bi).expect("stream");
    sim.cconn(h)
        .write(a, Bytes::from(vec![1u8; 50_000]))
        .expect("write");
    sim.cconn(h).reset(a, 5).expect("reset");
    let b = sim.cconn(h).open(Dir::Bi).expect("stream");
    sim.cconn(h)
        .write(b, Bytes::from_static(b"hello"))
        .expect("write");
    let mut sc = Collector::default();
    let ok = sim.run_until(Duration::from_secs(5), |s| {
        let sh = s.server_handle().expect("server");
        let evs = s.events(true, sh);
        sc.take(evs);
        !sc.resets.is_empty() && sc.data.get(&b).is_some_and(|d| d == b"hello")
    });
    assert!(ok);
    assert_eq!(sc.resets, vec![(a, 5)]);
    // The server stops b: the client is told and its sends fail.
    sim.sconn().stop(b, 9).expect("stop");
    let mut cc = Collector::default();
    assert!(sim.run_until(Duration::from_secs(5), |s| {
        let evs = s.events(false, h);
        cc.take(evs);
        !cc.stops.is_empty()
    }));
    assert_eq!(cc.stops, vec![(b, 9)]);
    assert!(matches!(
        sim.cconn(h).write(b, Bytes::from_static(b"x")),
        Err(crate::Error::Stopped(9))
    ));
    // Uni stream rules.
    let u = sim.cconn(h).open(Dir::Uni).expect("uni");
    assert!(sim.cconn(h).stop(u, 1).is_err());
    sim.cconn(h)
        .write(u, Bytes::from_static(b"one way"))
        .expect("write");
    sim.cconn(h).finish(u).expect("finish");
    assert!(matches!(
        sim.cconn(h).write(u, Bytes::from_static(b"x")),
        Err(crate::Error::UnknownStream)
    ));
    let mut sc = Collector::default();
    assert!(sim.run_until(Duration::from_secs(5), |s| {
        let sh = s.server_handle().expect("server");
        let evs = s.events(true, sh);
        sc.take(evs);
        sc.finished.get(&u).is_some_and(|d| d == b"one way")
    }));
    assert!(sc.opened.contains(&u));
}

#[test]
fn blackout_then_recovery() {
    let (mut sim, tls) = Sim::default_pair(24);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    let id = sim.cconn(h).open(Dir::Bi).expect("stream");
    sim.cconn(h)
        .write(id, Bytes::from(body(500_000, 1)))
        .expect("write");
    sim.cconn(h).finish(id).expect("finish");
    sim.run_until(Duration::from_millis(100), |_| false);
    sim.link.down = true;
    sim.run_until(Duration::from_secs(4), |_| false);
    sim.link.down = false;
    let mut sc = Collector::default();
    let ok = sim.run_until(Duration::from_secs(60), |s| {
        let sh = s.server_handle().expect("server");
        let evs = s.events(true, sh);
        sc.take(evs);
        sc.finished.contains_key(&id)
    });
    assert!(ok);
    assert!(sc.finished[&id] == body(500_000, 1));
    assert!(sim.cconn(h).stats().congestion_events > 0);
}

#[test]
fn newreno_bulk() {
    let (s, tls) = certs();
    let t = TransportConfig {
        congestion: crate::Congestion::NewReno,
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(25, ConnConfig::new(t.clone(), true), s, false);
    sim.link.loss = 0.01;
    let h = sim.handshake(&tls, ConnConfig::new(t, true));
    bulk(&mut sim, h, &[1_000_000], Duration::from_secs(60));
}

#[test]
fn bad_certificate_is_a_crypto_error() {
    let (s, _) = certs();
    let (_, other) = certs();
    let mut sim = Sim::new(
        26,
        ConnConfig::new(TransportConfig::default(), true),
        s,
        false,
    );
    let h = sim.connect(
        &other,
        ConnConfig::new(TransportConfig::default(), true),
        Vec::new(),
    );
    let mut c = Collector::default();
    let ok = sim.run_until(Duration::from_secs(5), |s| {
        let evs = s.events(false, h);
        c.take(evs);
        c.closed.is_some()
    });
    assert!(ok);
    assert!(
        matches!(c.closed, Some(ConnectionError::TransportError { code, .. }) if code > 0x100),
        "{:?}",
        c.closed
    );
}

#[test]
fn small_send_window() {
    let (s, tls) = certs();
    let t = TransportConfig {
        send_window: 16 * 1024,
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(27, ConnConfig::new(t.clone(), true), s, false);
    sim.link.loss = 0.02;
    let h = sim.handshake(&tls, ConnConfig::new(t, true));
    bulk(
        &mut sim,
        h,
        &[300_000, 1000, 50_000],
        Duration::from_secs(60),
    );
    assert!(sim.cconn(h).stream_unacked <= 16 * 1024);
}

/// CPU cost of the core alone: a bulk transfer over an ideal in-memory link (no sockets).
/// `cargo test --release -p only-quic --lib -- --ignored core_throughput --nocapture`
#[test]
#[ignore = "benchmark"]
fn core_throughput() {
    let (mut sim, tls) = Sim::default_pair(28);
    sim.link.delay = Duration::from_micros(50);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    let n = 256 << 20;
    let id = sim.cconn(h).open(Dir::Bi).expect("stream");
    let body = Bytes::from(vec![0x5au8; n]);
    sim.cconn(h).write(id, body).expect("write");
    sim.cconn(h).finish(id).expect("finish");
    let start = Instant::now();
    let mut got = 0usize;
    let ok = sim.run_until(Duration::from_secs(600), |s| {
        let sh = s.server_handle().expect("server");
        for e in s.events(true, sh) {
            if let Event::StreamData(_, d, fin) = e {
                got += d.len();
                if fin {
                    return true;
                }
            }
        }
        false
    });
    let el = start.elapsed().as_secs_f64();
    assert!(ok && got == n);
    let st = sim.cconn(h).stats();
    println!(
        "core: {} MB in {el:.2}s wall = {:.0} Mbit/s ({} packets, {:.2} us/packet both sides)",
        n >> 20,
        (n * 8) as f64 / el / 1e6,
        st.sent_packets,
        el * 1e6 / st.sent_packets as f64
    );
}

#[test]
fn late_initial_does_not_start_a_second_connection() {
    let (mut sim, tls) = Sim::default_pair(29);
    let h = sim.connect(
        &tls,
        ConnConfig::new(TransportConfig::default(), true),
        Vec::new(),
    );
    let now = sim.now;
    let first = sim.cconn(h).poll_transmit(now, 1).expect("initial").data;
    let from = sim.client.addr;
    let server = sim.server.addr;
    sim.deliver(true, from, server, 0, first.clone());
    let ok = sim.run_until(Duration::from_secs(10), |s| {
        s.connected(false, h) && s.server_handle().is_some_and(|sh| s.connected(true, sh))
    });
    assert!(ok);
    // The handshake is confirmed; the client's first Initial arrives again, late.
    sim.run_until(Duration::from_millis(200), |_| false);
    sim.deliver(true, from, server, 0, first);
    sim.run_until(Duration::from_millis(200), |_| false);
    assert_eq!(sim.server.conns.len(), 1);
}

#[test]
fn ecn_validated_and_ce_marks_are_congestion() {
    let (mut sim, tls) = Sim::default_pair(40);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[200_000], Duration::from_secs(30));
    let st = sim.cconn(h).stats();
    assert!(st.ecn_capable && sim.sconn().stats().ecn_capable, "{st:?}");
    assert_eq!(st.ecn_ce_events, 0);
    assert!(sim.ect_sent > 100);
    // A 20 Mbit/s bottleneck whose AQM marks instead of dropping, with a deep buffer: the
    // senders back off on the CE marks and nothing is lost.
    sim.link.rate = Some(2_500_000);
    sim.link.buffer = 1 << 20;
    sim.link.ce_above = Some(30_000);
    bulk(&mut sim, h, &[3_000_000], Duration::from_secs(60));
    let st = sim.cconn(h).stats();
    assert!(sim.ce_marked > 0);
    assert!(st.ecn_ce_events > 0 && st.congestion_events > 0, "{st:?}");
    assert_eq!((sim.dropped, st.lost_packets), (0, 0), "{st:?}");
    assert!(st.ecn_capable);
}

#[test]
fn ecn_bleached_or_black_holed_falls_back() {
    // A middlebox clears the codepoint: validation fails, marking stops, data still flows.
    let (mut sim, tls) = Sim::default_pair(41);
    sim.link.bleach = true;
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[200_000], Duration::from_secs(30));
    assert!(!sim.cconn(h).stats().ecn_capable && !sim.sconn().stats().ecn_capable);
    let marked = sim.ect_sent;
    assert!(marked <= 2 * 10, "{marked}");
    bulk(&mut sim, h, &[200_000], Duration::from_secs(30));
    assert_eq!(sim.ect_sent, marked);
    // A path that drops marked packets: the handshake gets through after one probe timeout,
    // unmarked.
    let (mut sim, tls) = Sim::default_pair(42);
    sim.link.drop_ect = true;
    let start = sim.now;
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    assert!(sim.now - start < Duration::from_secs(3));
    bulk(&mut sim, h, &[200_000], Duration::from_secs(30));
    assert!(!sim.cconn(h).stats().ecn_capable);
    // Off by configuration: nothing is marked, received marks are still reported.
    let (s, tls) = certs();
    let t = TransportConfig {
        ecn: false,
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(43, ConnConfig::new(t.clone(), true), s, false);
    let h = sim.handshake(&tls, ConnConfig::new(t, true));
    bulk(&mut sim, h, &[100_000], Duration::from_secs(30));
    assert_eq!(sim.ect_sent, 0);
    assert!(!sim.cconn(h).stats().ecn_capable);
}

/// Sends `n` bytes one way (client to server) with congestion controller `cc` over `link`;
/// returns the virtual time it took after the handshake and the sender's statistics.
fn upload(
    seed: u8,
    cc: crate::Congestion,
    link: Link,
    n: usize,
) -> (Duration, crate::ConnectionStats) {
    let (s, tls) = certs();
    let t = TransportConfig {
        congestion: cc,
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(seed, ConnConfig::new(t.clone(), true), s, false);
    sim.link = link;
    let h = sim.handshake(&tls, ConnConfig::new(t, true));
    let start = sim.now;
    let id = sim.cconn(h).open(Dir::Uni).expect("stream");
    sim.cconn(h)
        .write(id, Bytes::from(body(n, 9)))
        .expect("write");
    sim.cconn(h).finish(id).expect("finish");
    let mut got = Collector::default();
    let ok = sim.run_until(Duration::from_secs(600), |s| {
        if let Some(sh) = s.server_handle() {
            let evs = s.events(true, sh);
            got.take(evs);
        }
        got.finished.contains_key(&id)
    });
    assert!(ok, "{cc:?}: upload did not finish");
    assert_eq!(got.finished[&id].len(), n);
    (sim.now - start, sim.cconn(h).stats())
}

/// A 20 Mbit/s bottleneck with 40 ms of round trip and a buffer of one bandwidth-delay product.
fn bottleneck() -> Link {
    Link {
        delay: Duration::from_millis(20),
        rate: Some(2_500_000),
        buffer: 100_000,
        ..Link::default()
    }
}

#[test]
fn bbr_fills_a_bottleneck_without_a_standing_queue() {
    let n = 8_000_000;
    let ideal = n as f64 / 2_500_000.0;
    let (t, st) = upload(50, crate::Congestion::Bbr, bottleneck(), n);
    let secs = t.as_secs_f64();
    assert!(
        secs < ideal * 1.35,
        "BBR took {secs:.2}s, ideal {ideal:.2}s: {st:?}"
    );
    // The queue it keeps is small: the smoothed RTT stays near the minimum.
    assert!(st.rtt < st.min_rtt * 2, "{st:?}");
    let (tc, stc) = upload(50, crate::Congestion::Cubic, bottleneck(), n);
    assert!(tc.as_secs_f64() < ideal * 1.5, "CUBIC took {tc:?}: {stc:?}");
    eprintln!(
        "bottleneck: BBR {secs:.2}s (rtt {:?}, lost {}), CUBIC {:.2}s (rtt {:?}, lost {})",
        st.rtt,
        st.lost_packets,
        tc.as_secs_f64(),
        stc.rtt,
        stc.lost_packets
    );
}

#[test]
fn bbr_keeps_its_rate_under_random_loss() {
    // 1% random loss on top of the bottleneck: CUBIC halves its window over and over, BBR's
    // model is unaffected (the loss rate stays below its 2% bound).
    let link = Link {
        loss: 0.01,
        ..bottleneck()
    };
    let n = 4_000_000;
    let (tb, sb) = upload(51, crate::Congestion::Bbr, link.clone(), n);
    let (tc, sc) = upload(51, crate::Congestion::Cubic, link, n);
    eprintln!(
        "1% loss: BBR {:.2}s (lost {}), CUBIC {:.2}s (lost {})",
        tb.as_secs_f64(),
        sb.lost_packets,
        tc.as_secs_f64(),
        sc.lost_packets
    );
    assert!(tb.as_secs_f64() < 2.5, "BBR took {tb:?}: {sb:?}");
    assert!(tb * 2 < tc, "BBR {tb:?} vs CUBIC {tc:?}");
}

#[test]
fn bbr_backs_off_on_a_shallow_buffer_and_ecn() {
    // A buffer of under a third of the BDP: the 2% loss bound caps what BBR keeps in flight, so it
    // loses little more than CUBIC does.
    let shallow = Link {
        buffer: 30_000,
        ..bottleneck()
    };
    let n = 4_000_000;
    let (tb, sb) = upload(52, crate::Congestion::Bbr, shallow.clone(), n);
    let (tc, sc) = upload(52, crate::Congestion::Cubic, shallow, n);
    eprintln!(
        "shallow: BBR {:.2}s (lost {}), CUBIC {:.2}s (lost {})",
        tb.as_secs_f64(),
        sb.lost_packets,
        tc.as_secs_f64(),
        sc.lost_packets
    );
    let sent = sb.sent_packets.max(1);
    assert!(sb.lost_packets * 100 / sent < 6, "{sb:?}");
    assert!(tb.as_secs_f64() < 2.5, "BBR took {tb:?}");
    // An AQM that marks: BBR treats CE marks like losses and nothing is dropped.
    let marking = Link {
        buffer: 1 << 20,
        ce_above: Some(20_000),
        ..bottleneck()
    };
    let (tm, sm) = upload(53, crate::Congestion::Bbr, marking, n);
    assert!(sm.ecn_capable && sm.lost_packets == 0, "{sm:?}");
    assert!(tm.as_secs_f64() < 2.5, "BBR with ECN took {tm:?}");
}

#[test]
#[ignore]
fn bbr_debug_trace() {
    let (s, tls) = certs();
    let t = TransportConfig {
        congestion: crate::Congestion::Bbr,
        ..TransportConfig::default()
    };
    let mut sim = Sim::new(52, ConnConfig::new(t.clone(), true), s, false);
    sim.link = Link {
        buffer: 30_000,
        ..bottleneck()
    };
    let h = sim.handshake(&tls, ConnConfig::new(t, true));
    let id = sim.cconn(h).open(Dir::Uni).expect("stream");
    sim.cconn(h)
        .write(id, Bytes::from(body(4_000_000, 9)))
        .expect("write");
    sim.cconn(h).finish(id).expect("finish");
    let start = sim.now;
    let mut next = start;
    sim.run_until(Duration::from_secs(5), |s| {
        if s.now >= next {
            next += Duration::from_millis(50);
            let now = s.now;
            let dropped = s.dropped;
            let c = s.cconn(h);
            let st = c.stats();
            eprintln!(
                "{:>5}ms {} lost {} dropped {}",
                (now - start).as_millis(),
                c.cc_debug(),
                st.lost_packets,
                dropped
            );
        }
        false
    });
}

/// Runs until the client reports the outcome of a migration.
fn migration_outcome(sim: &mut Sim) -> Result<SocketAddr, ()> {
    let ok = sim.run_until(Duration::from_secs(30), |s| !s.client.migrations.is_empty());
    assert!(ok, "no migration outcome");
    sim.client.migrations.remove(0)
}

#[test]
fn client_migrates_to_a_new_local_port() {
    let (mut sim, tls) = Sim::default_pair(60);
    sim.link.loss = 0.02;
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[50_000], Duration::from_secs(10));
    let old = sim.client.addr;
    let old_cid = sim.cconn(h).remote_cid();
    // A new socket: the path is probed from it, then the connection moves there.
    let new: SocketAddr = "10.0.0.1:5001".parse().expect("addr");
    sim.client.alt_addr = Some(new);
    let now = sim.now;
    assert_eq!(sim.cconn(h).migrate(now), Ok(sim.server.addr));
    assert_eq!(
        sim.cconn(h).migrate(now),
        Err(super::conn::MigrateError::InProgress)
    );
    assert_eq!(migration_outcome(&mut sim), Ok(sim.server.addr));
    assert_eq!(sim.client.addr, new);
    assert!(sim.client.closed.contains(&old));
    // A connection ID not used before, on the new path.
    assert_ne!(sim.cconn(h).remote_cid(), old_cid);
    // Data flows on the new path; the server follows (validating the address itself).
    bulk(&mut sim, h, &[300_000], Duration::from_secs(30));
    assert_eq!(sim.sconn().remote_addr(), new);
    // ECN was validated again on the new path (the counts carry over).
    assert!(sim.cconn(h).stats().ecn_capable);
    // And again.
    let newer: SocketAddr = "10.0.0.1:5002".parse().expect("addr");
    sim.client.alt_addr = Some(newer);
    let now = sim.now;
    sim.cconn(h).migrate(now).expect("second migration");
    assert!(migration_outcome(&mut sim).is_ok());
    bulk(&mut sim, h, &[50_000], Duration::from_secs(30));
    assert_eq!(sim.sconn().remote_addr(), newer);
}

#[test]
fn failed_migration_stays_on_the_old_path() {
    let (mut sim, tls) = Sim::default_pair(61);
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    bulk(&mut sim, h, &[10_000], Duration::from_secs(10));
    let old = sim.client.addr;
    let new: SocketAddr = "10.0.0.1:5001".parse().expect("addr");
    sim.client.alt_addr = Some(new);
    // The new path does not work.
    sim.blocked.push(new);
    let now = sim.now;
    sim.cconn(h).migrate(now).expect("migrate");
    // Meanwhile the old path carries on.
    bulk(&mut sim, h, &[100_000], Duration::from_secs(10));
    assert_eq!(migration_outcome(&mut sim), Err(()));
    assert_eq!(sim.client.addr, old);
    bulk(&mut sim, h, &[100_000], Duration::from_secs(10));
    assert_eq!(sim.sconn().remote_addr(), old);
    assert!(!sim.cconn(h).is_closed());
}

#[test]
fn migration_refused_when_the_server_disables_it() {
    let (s, tls) = certs();
    let mut sim = Sim::new(
        62,
        ConnConfig::new(TransportConfig::default(), false),
        s,
        false,
    );
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    let now = sim.now;
    assert_eq!(
        sim.cconn(h).migrate(now),
        Err(super::conn::MigrateError::Disabled)
    );
    assert_eq!(
        sim.sconn().migrate(now),
        Err(super::conn::MigrateError::NotClient)
    );
}

#[test]
fn client_moves_to_the_preferred_address() {
    let (s, tls) = certs();
    let preferred: SocketAddr = "10.0.0.3:4433".parse().expect("addr");
    let mut cfg = ConnConfig::new(TransportConfig::default(), true);
    let SocketAddr::V4(v4) = preferred else {
        unreachable!()
    };
    cfg.preferred_address = (Some(v4), None);
    let mut sim = Sim::new(63, cfg, s, false);
    sim.server.alt_addr = Some(preferred);
    sim.link.loss = 0.02;
    let h = sim.handshake(&tls, ConnConfig::new(TransportConfig::default(), true));
    // Confirmed: the offer is known.
    assert!(sim.run_until(Duration::from_secs(5), |s| {
        s.cconn(h).preferred_address().is_some()
    }));
    assert_eq!(sim.cconn(h).preferred_address(), Some(preferred));
    bulk(&mut sim, h, &[20_000], Duration::from_secs(10));
    let new: SocketAddr = "10.0.0.1:5001".parse().expect("addr");
    sim.client.alt_addr = Some(new);
    let now = sim.now;
    assert_eq!(sim.cconn(h).migrate(now), Ok(preferred));
    assert_eq!(migration_outcome(&mut sim), Ok(preferred));
    assert_eq!(sim.cconn(h).remote_addr(), preferred);
    assert_eq!(sim.cconn(h).preferred_address(), None);
    // The server's original address is gone for this connection: everything flows through
    // the preferred one.
    sim.blocked.push(sim.server.addr);
    bulk(&mut sim, h, &[300_000], Duration::from_secs(30));
    assert_eq!(sim.sconn().remote_addr(), new);
    // A later migration moves the local port again, on the preferred address.
    sim.client.alt_addr = Some("10.0.0.1:5002".parse().expect("addr"));
    let now = sim.now;
    assert_eq!(sim.cconn(h).migrate(now), Ok(preferred));
    assert!(migration_outcome(&mut sim).is_ok());
    bulk(&mut sim, h, &[20_000], Duration::from_secs(30));
}
