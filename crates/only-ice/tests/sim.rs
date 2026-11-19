//! Deterministic simulated-network tests: agents exchange datagrams over an in-memory network
//! with configurable loss, duplication, reordering, dead addresses and NATs, in simulated time.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use only_ice::{
    Candidate, Credentials, IceAgent, IceConfig, IceEvent, IceState, TcpType, Transmit,
};
use only_turn::stun::{self, Class, Message, MessageBuilder, Method, attr};

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A port-restricted cone NAT for one private IP.
struct Nat {
    internal: IpAddr,
    external: IpAddr,
    map: HashMap<SocketAddr, SocketAddr>,
    back: HashMap<SocketAddr, SocketAddr>,
    allowed: HashSet<(SocketAddr, SocketAddr)>,
    next_port: u16,
}

impl Nat {
    fn new(internal: &str, external: &str) -> Nat {
        Nat {
            internal: internal.parse().unwrap(),
            external: external.parse().unwrap(),
            map: HashMap::new(),
            back: HashMap::new(),
            allowed: HashSet::new(),
            next_port: 40000,
        }
    }

    fn mapping(&mut self, inside: SocketAddr) -> SocketAddr {
        if let Some(m) = self.map.get(&inside) {
            return *m;
        }
        let m = SocketAddr::new(self.external, self.next_port);
        self.next_port += 1;
        self.map.insert(inside, m);
        self.back.insert(m, inside);
        m
    }
}

struct Packet {
    at: Instant,
    seq: u64,
    src: SocketAddr,
    dst: SocketAddr,
    data: Vec<u8>,
}

type Rewrite = Box<dyn FnMut(&mut Packet)>;

struct Net {
    queue: Vec<Packet>,
    seq: u64,
    rng: u64,
    delay: Duration,
    jitter_ms: u64,
    loss_pct: u64,
    dup_pct: u64,
    dead: HashSet<SocketAddr>,
    down: bool,
    nats: Vec<Nat>,
    /// Rewrites the source of matching packets (spoofing tests).
    rewrite: Option<Rewrite>,
}

impl Net {
    fn new(seed: u64) -> Net {
        Net {
            queue: Vec::new(),
            seq: 0,
            rng: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
            delay: Duration::from_millis(10),
            jitter_ms: 0,
            loss_pct: 0,
            dup_pct: 0,
            dead: HashSet::new(),
            down: false,
            nats: Vec::new(),
            rewrite: None,
        }
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn send(&mut self, now: Instant, t: Transmit) {
        if self.down || self.dead.contains(&t.source) || self.dead.contains(&t.destination) {
            return;
        }
        let mut src = t.source;
        for nat in &mut self.nats {
            if nat.internal == src.ip() {
                src = nat.mapping(src);
                nat.allowed.insert((src, t.destination));
            }
        }
        let copies = if self.rand() % 100 < self.dup_pct {
            2
        } else {
            1
        };
        for _ in 0..copies {
            if self.rand() % 100 < self.loss_pct {
                continue;
            }
            let jitter = if self.jitter_ms > 0 {
                self.rand() % self.jitter_ms
            } else {
                0
            };
            self.seq += 1;
            let mut p = Packet {
                at: now + self.delay + Duration::from_millis(jitter),
                seq: self.seq,
                src,
                dst: t.destination,
                data: t.contents.clone(),
            };
            if let Some(f) = self.rewrite.as_mut() {
                f(&mut p);
            }
            self.queue.push(p);
        }
    }

    fn next_at(&self) -> Option<Instant> {
        self.queue.iter().map(|p| p.at).min()
    }

    /// Pops the due packets in delivery order, after inbound NAT translation (dropped when
    /// no permission or mapping).
    fn due(&mut self, now: Instant) -> Vec<Packet> {
        let mut out: Vec<Packet> = Vec::new();
        let mut keep = Vec::new();
        for p in self.queue.drain(..) {
            if p.at <= now {
                out.push(p);
            } else {
                keep.push(p);
            }
        }
        self.queue = keep;
        out.sort_by_key(|p| (p.at, p.seq));
        let mut res = Vec::new();
        for mut p in out {
            if self.down {
                continue;
            }
            let mut ok = true;
            for nat in &self.nats {
                if nat.external == p.dst.ip() {
                    match nat.back.get(&p.dst) {
                        Some(inside) if nat.allowed.contains(&(p.dst, p.src)) => p.dst = *inside,
                        _ => ok = false,
                    }
                }
            }
            if ok {
                res.push(p);
            }
        }
        res
    }
}

struct Peer {
    agent: IceAgent,
    addrs: Vec<SocketAddr>,
    events: Vec<IceEvent>,
    app: usize,
}

impl Peer {
    fn new(config: IceConfig, now: Instant, addrs: &[&str]) -> Peer {
        let mut agent = IceAgent::new(config, now);
        let addrs: Vec<SocketAddr> = addrs.iter().map(|s| a(s)).collect();
        for &ad in &addrs {
            assert!(agent.add_local_candidate(Candidate::host(ad)));
        }
        Peer {
            agent,
            addrs,
            events: Vec::new(),
            app: 0,
        }
    }

    fn states(&self) -> Vec<IceState> {
        self.events
            .iter()
            .filter_map(|e| match e {
                IceEvent::StateChanged(s) => Some(*s),
                _ => None,
            })
            .collect()
    }

    fn selections(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                IceEvent::SelectedPair { local, remote } => Some((*local, *remote)),
                _ => None,
            })
            .collect()
    }
}

struct Sim {
    now: Instant,
    start: Instant,
    net: Net,
    peers: Vec<Peer>,
    /// Send application data on `send_pair` every tick once there is one.
    app_data: bool,
    next_app: Instant,
}

impl Sim {
    fn new(seed: u64, a_peer: Peer, b_peer: Peer, now: Instant) -> Sim {
        Sim {
            now,
            start: now,
            net: Net::new(seed),
            peers: vec![a_peer, b_peer],
            app_data: false,
            next_app: now,
        }
    }

    fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    /// Signals credentials and every local candidate both ways.
    fn signal(&mut self) {
        let ca = self.peers[0].agent.local_credentials().clone();
        let cb = self.peers[1].agent.local_credentials().clone();
        self.peers[0].agent.set_remote_credentials(cb);
        self.peers[1].agent.set_remote_credentials(ca);
        self.signal_candidates(0);
        self.signal_candidates(1);
    }

    fn signal_candidates(&mut self, from: usize) {
        let cands: Vec<Candidate> = self.peers[from].agent.local_candidates().to_vec();
        for c in cands {
            let parsed = Candidate::parse(&format!("a={}", c.to_sdp())).unwrap();
            self.peers[1 - from].agent.add_remote_candidate(parsed);
        }
    }

    fn flush(&mut self) {
        for i in 0..self.peers.len() {
            while let Some(t) = self.peers[i].agent.poll_transmit() {
                assert!(
                    self.peers[i].addrs.contains(&t.source),
                    "transmit from a foreign address {t:?}"
                );
                assert!(stun::is_stun(&t.contents));
                self.net.send(self.now, t);
            }
            while let Some(e) = self.peers[i].agent.poll_event() {
                self.peers[i].events.push(e);
            }
        }
    }

    /// One step: flush, advance to the next event, deliver, fire timers. `false` if nothing
    /// is scheduled before `limit`.
    fn step(&mut self, limit: Instant) -> bool {
        self.flush();
        if self.app_data && self.now >= self.next_app {
            self.next_app = self.now + Duration::from_millis(100);
            for i in 0..self.peers.len() {
                if let Some((src, dst)) = self.peers[i].agent.send_pair() {
                    self.net.send(
                        self.now,
                        Transmit {
                            source: src,
                            destination: dst,
                            contents: b"app".to_vec(),
                        },
                    );
                }
            }
        }
        let mut next = self.net.next_at();
        for p in &self.peers {
            if let Some(t) = p.agent.poll_timeout() {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        if self.app_data {
            let tick = self.next_app.max(self.now);
            next = Some(next.map_or(tick, |n| n.min(tick)));
        }
        let Some(next) = next else {
            return false;
        };
        if next > limit {
            self.now = limit;
            return false;
        }
        self.now = self.now.max(next);
        let now = self.now;
        for p in self.net.due(now) {
            if let Some(peer) = self.peers.iter_mut().find(|x| x.addrs.contains(&p.dst)) {
                if !peer.agent.handle_receive(now, p.src, p.dst, &p.data) {
                    assert_eq!(p.data, b"app");
                    peer.app += 1;
                }
            }
        }
        for p in &mut self.peers {
            if p.agent.poll_timeout().is_some_and(|t| t <= now) {
                p.agent.handle_timeout(now);
            }
        }
        true
    }

    fn run_for(&mut self, d: Duration) {
        let limit = self.now + d;
        let mut n = 0;
        while self.step(limit) {
            n += 1;
            assert!(n < 1_000_000, "simulation does not progress");
        }
        self.flush();
    }

    fn run_until(&mut self, max: Duration, mut f: impl FnMut(&Sim) -> bool) -> bool {
        let limit = self.now + max;
        let mut n = 0;
        loop {
            self.flush();
            if f(self) {
                return true;
            }
            if !self.step(limit) {
                self.flush();
                return f(self);
            }
            n += 1;
            assert!(n < 1_000_000, "simulation does not progress");
        }
    }

    fn both(&self, s: IceState) -> bool {
        self.peers.iter().all(|p| p.agent.state() == s)
    }

    fn assert_connected_pair(&self) {
        let (l0, r0) = self.peers[0].agent.selected_pair().expect("A selected");
        let (l1, r1) = self.peers[1].agent.selected_pair().expect("B selected");
        assert!(self.peers[0].addrs.contains(&l0));
        assert!(self.peers[1].addrs.contains(&l1));
        // Without NAT, the pairs mirror each other.
        if self.net.nats.is_empty() {
            assert_eq!((l0, r0), (r1, l1));
        }
    }
}

fn full(controlling: bool) -> IceConfig {
    IceConfig::new(false, controlling)
}

fn lite() -> IceConfig {
    IceConfig::new(true, false)
}

fn basic(seed: u64, ca: IceConfig, aa: &[&str], cb: IceConfig, ba: &[&str]) -> Sim {
    let now = Instant::now();
    Sim::new(seed, Peer::new(ca, now, aa), Peer::new(cb, now, ba), now)
}

const NORMAL_STATES: [IceState; 3] = [IceState::Checking, IceState::Connected, IceState::Completed];

#[test]
fn full_full_host_both_orders() {
    for controlling_first in [true, false] {
        let mut sim = basic(
            1,
            full(controlling_first),
            &["10.0.0.1:1000"],
            full(!controlling_first),
            &["10.0.0.2:2000"],
        );
        assert_eq!(sim.peers[0].agent.state(), IceState::New);
        sim.signal();
        assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
        assert!(
            sim.elapsed() < Duration::from_millis(500),
            "{:?}",
            sim.elapsed()
        );
        sim.assert_connected_pair();
        for p in &sim.peers {
            assert_eq!(p.states(), NORMAL_STATES);
            assert_eq!(p.selections().len(), 1);
            assert_eq!(p.agent.send_pair(), p.agent.selected_pair());
        }
        assert_eq!(sim.peers[0].agent.controlling(), controlling_first);
        // Stays up for a long time thanks to consent.
        sim.app_data = true;
        sim.run_for(Duration::from_secs(120));
        assert!(sim.both(IceState::Completed));
        assert_eq!(sim.peers[0].states().len(), 3);
        assert!(sim.peers[0].app > 100 && sim.peers[1].app > 100);
    }
}

#[test]
fn full_lite_both_ways() {
    // Full controlling agent, lite remote.
    for full_first in [true, false] {
        let (ca, cb) = if full_first {
            (full(false), lite())
        } else {
            (lite(), full(false))
        };
        let mut sim = basic(2, ca, &["10.0.0.1:1000"], cb, &["10.0.0.2:2000"]);
        let fi = usize::from(!full_first);
        sim.peers[fi].agent.set_remote_lite(true);
        assert!(sim.peers[fi].agent.controlling());
        assert!(sim.peers[1 - fi].agent.is_lite());
        sim.signal();
        assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
        sim.assert_connected_pair();
        assert_eq!(sim.peers[fi].states(), NORMAL_STATES);
        assert_eq!(sim.peers[1 - fi].states(), NORMAL_STATES);
        sim.run_for(Duration::from_secs(100));
        assert!(sim.both(IceState::Completed));
    }
}

#[test]
fn lite_without_remote_credentials_and_disconnect() {
    let now = Instant::now();
    let mut f = Peer::new(full(true), now, &["10.0.0.1:1000"]);
    let l = Peer::new(lite(), now, &["10.0.0.2:2000"]);
    f.agent.set_remote_lite(true);
    let mut sim = Sim::new(3, f, l, now);
    // The lite side never learns the full side's credentials or candidates.
    let cl = sim.peers[1].agent.local_credentials().clone();
    sim.peers[0].agent.set_remote_credentials(cl);
    sim.signal_candidates(1);
    assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
    assert_eq!(
        sim.peers[1].agent.send_pair(),
        Some((a("10.0.0.2:2000"), a("10.0.0.1:1000")))
    );
    sim.net.down = true;
    let t0 = sim.now;
    assert!(sim.run_until(Duration::from_secs(60), |s| {
        s.peers[1].agent.state() == IceState::Disconnected
    }));
    let lag = sim.now - t0;
    assert!(
        lag > Duration::from_secs(24) && lag <= Duration::from_secs(31),
        "{lag:?}"
    );
    sim.net.down = false;
    assert!(sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)));
}

#[test]
fn srflx_behind_nat() {
    let now = Instant::now();
    let mut pa = Peer::new(full(true), now, &["10.0.0.1:1000"]);
    let pb = Peer::new(full(false), now, &["203.0.113.2:2000"]);
    let mut nat = Nat::new("10.0.0.1", "198.51.100.1");
    // The STUN server taught A its mapping.
    let mapped = nat.mapping(a("10.0.0.1:1000"));
    assert!(
        pa.agent
            .add_local_candidate(Candidate::server_reflexive(mapped, a("10.0.0.1:1000")))
    );
    // Redundant.
    assert!(
        !pa.agent
            .add_local_candidate(Candidate::server_reflexive(mapped, a("10.0.0.1:1000")))
    );
    let mut sim = Sim::new(4, pa, pb, now);
    sim.net.nats.push(nat);
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)));
    assert_eq!(
        sim.peers[0].agent.selected_pair(),
        Some((a("10.0.0.1:1000"), a("203.0.113.2:2000")))
    );
    assert_eq!(
        sim.peers[1].agent.selected_pair(),
        Some((a("203.0.113.2:2000"), mapped))
    );
    sim.run_for(Duration::from_secs(60));
    assert!(sim.both(IceState::Completed));
}

#[test]
fn prflx_through_nat() {
    // B only knows A's private host address; A's checks through the NAT reveal a
    // peer-reflexive candidate to B, and B's response reveals a peer-reflexive local one to A.
    for controlling in [true, false] {
        let now = Instant::now();
        let pa = Peer::new(full(controlling), now, &["10.0.0.1:1000"]);
        let pb = Peer::new(full(!controlling), now, &["203.0.113.2:2000"]);
        let mut sim = Sim::new(5, pa, pb, now);
        sim.net.nats.push(Nat::new("10.0.0.1", "198.51.100.1"));
        sim.signal();
        assert!(sim.run_until(Duration::from_secs(15), |s| s.both(IceState::Completed)));
        let mapped = a("198.51.100.1:40000");
        assert_eq!(
            sim.peers[1].agent.selected_pair(),
            Some((a("203.0.113.2:2000"), mapped))
        );
        assert!(
            sim.peers[1]
                .agent
                .remote_candidates()
                .iter()
                .any(|c| c.addr() == mapped && c.kind() == only_ice::CandidateKind::PeerReflexive)
        );
        assert!(
            sim.peers[0]
                .agent
                .local_candidates()
                .iter()
                .any(|c| c.addr() == mapped
                    && c.kind() == only_ice::CandidateKind::PeerReflexive
                    && c.base() == a("10.0.0.1:1000"))
        );
    }
}

#[test]
fn some_candidates_unreachable() {
    let mut sim = basic(
        6,
        full(true),
        &["10.0.0.1:1000", "192.168.9.1:1001", "172.16.0.1:1002"],
        full(false),
        &["10.0.0.2:2000", "192.168.9.2:2001"],
    );
    sim.net.dead.insert(a("10.0.0.1:1000"));
    sim.net.dead.insert(a("192.168.9.2:2001"));
    sim.signal();
    assert!(
        sim.run_until(Duration::from_secs(20), |s| s.both(IceState::Connected)
            || s.both(IceState::Completed))
    );
    let (l, r) = sim.peers[0].agent.selected_pair().unwrap();
    assert_ne!(l, a("10.0.0.1:1000"));
    assert_eq!(r, a("10.0.0.2:2000"));
    sim.assert_connected_pair();
    assert!(sim.run_until(Duration::from_secs(20), |s| s.both(IceState::Completed)));
}

#[test]
fn ipv4_ipv6_mix() {
    let mut sim = basic(
        7,
        full(true),
        &["10.0.0.1:1000", "[2001:db8::1]:1000"],
        full(false),
        &["10.0.0.2:2000", "[2001:db8::2]:2000"],
    );
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
    assert_eq!(
        sim.peers[0].agent.selected_pair(),
        Some((a("[2001:db8::1]:1000"), a("[2001:db8::2]:2000")))
    );
    // IPv6 broken: IPv4 wins after the IPv6 pair fails (nomination waits briefly).
    let mut sim = basic(
        8,
        full(true),
        &["10.0.0.1:1000", "[2001:db8::1]:1000"],
        full(false),
        &["10.0.0.2:2000", "[2001:db8::2]:2000"],
    );
    sim.net.dead.insert(a("[2001:db8::2]:2000"));
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(20), |s| s.both(IceState::Completed)));
    assert_eq!(
        sim.peers[1].agent.selected_pair(),
        Some((a("10.0.0.2:2000"), a("10.0.0.1:1000")))
    );
    // B is IPv4-only: no cross-family pairs.
    let mut sim = basic(
        9,
        full(true),
        &["[2001:db8::1]:1000", "10.0.0.1:1000"],
        full(false),
        &["10.0.0.2:2000"],
    );
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
    assert_eq!(
        sim.peers[0].agent.selected_pair(),
        Some((a("10.0.0.1:1000"), a("10.0.0.2:2000")))
    );
}

#[test]
fn lossy_link() {
    for seed in 0..24u64 {
        let controlling = seed % 2 == 0;
        let (ca, cb) = if seed % 3 == 0 {
            (full(true), lite())
        } else {
            (full(controlling), full(!controlling))
        };
        let lite_remote = seed % 3 == 0;
        let mut sim = basic(
            100 + seed,
            ca,
            &["10.0.0.1:1000", "[2001:db8::1]:1000"],
            cb,
            &["10.0.0.2:2000", "[2001:db8::2]:2000"],
        );
        if lite_remote {
            sim.peers[0].agent.set_remote_lite(true);
        }
        sim.net.loss_pct = 25;
        sim.net.dup_pct = 10;
        sim.net.jitter_ms = 300;
        sim.signal();
        assert!(
            sim.run_until(Duration::from_secs(30), |s| s.both(IceState::Completed)),
            "seed {seed}: {:?} {:?}",
            sim.peers[0].agent.state(),
            sim.peers[1].agent.state()
        );
        sim.assert_connected_pair();
        sim.app_data = true;
        sim.run_for(Duration::from_secs(90));
        for p in &sim.peers {
            assert_eq!(p.agent.state(), IceState::Completed, "seed {seed}");
            assert!(!p.states().contains(&IceState::Disconnected), "seed {seed}");
            assert!(!p.states().contains(&IceState::Failed), "seed {seed}");
            assert_eq!(p.selections().len(), 1, "seed {seed}");
        }
        assert!(sim.peers[0].app > 0 && sim.peers[1].app > 0);
    }
}

#[test]
fn trickle_after_start() {
    let mut sim = basic(10, full(true), &["10.0.0.1:1000"], full(false), &[]);
    let ca = sim.peers[0].agent.local_credentials().clone();
    let cb = sim.peers[1].agent.local_credentials().clone();
    sim.peers[0].agent.set_remote_credentials(cb);
    sim.peers[1].agent.set_remote_credentials(ca);
    sim.run_for(Duration::from_secs(1));
    assert_eq!(sim.peers[0].agent.state(), IceState::New);
    // B gathers late and trickles; A trickles its candidate too.
    sim.peers[1].addrs.push(a("10.0.0.2:2000"));
    assert!(
        sim.peers[1]
            .agent
            .add_local_candidate(Candidate::host(a("10.0.0.2:2000")))
    );
    sim.signal_candidates(1);
    sim.run_for(Duration::from_millis(300));
    sim.signal_candidates(0);
    assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
    sim.assert_connected_pair();
    // End-of-candidates after success changes nothing.
    sim.peers[0].agent.end_of_remote_candidates();
    sim.peers[1].agent.end_of_remote_candidates();
    sim.run_for(Duration::from_secs(10));
    assert!(sim.both(IceState::Completed));
}

#[test]
fn checks_before_remote_credentials() {
    for answerer_controlling in [false, true] {
        // A (offerer) learns B's credentials only after B's checks arrive.
        let mut sim = basic(
            11,
            full(!answerer_controlling),
            &["10.0.0.1:1000"],
            full(answerer_controlling),
            &["10.0.0.2:2000"],
        );
        let ca = sim.peers[0].agent.local_credentials().clone();
        sim.peers[1].agent.set_remote_credentials(ca);
        sim.signal_candidates(0);
        sim.run_for(Duration::from_secs(2));
        // A answered: B has a valid pair, A has a peer-reflexive remote candidate.
        assert_eq!(
            sim.peers[1].agent.send_pair(),
            Some((a("10.0.0.2:2000"), a("10.0.0.1:1000")))
        );
        assert_eq!(sim.peers[0].agent.remote_candidates().len(), 1);
        assert!(sim.peers[0].agent.remote_credentials().is_none());
        let cb = sim.peers[1].agent.local_credentials().clone();
        sim.peers[0].agent.set_remote_credentials(cb);
        sim.signal_candidates(1);
        assert!(sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)));
        sim.assert_connected_pair();
        // The signaled candidate replaced the peer-reflexive one.
        assert_eq!(sim.peers[0].agent.remote_candidates().len(), 1);
        assert_eq!(
            sim.peers[0].agent.remote_candidates()[0].kind(),
            only_ice::CandidateKind::Host
        );
    }
}

#[test]
fn role_conflicts() {
    for controlling in [true, false] {
        let mut sim = basic(
            12,
            full(controlling),
            &["10.0.0.1:1000"],
            full(controlling),
            &["10.0.0.2:2000"],
        );
        sim.signal();
        assert!(sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)));
        sim.assert_connected_pair();
        assert_ne!(
            sim.peers[0].agent.controlling(),
            sim.peers[1].agent.controlling()
        );
        sim.run_for(Duration::from_secs(30));
        assert!(sim.both(IceState::Completed));
    }
}

#[test]
fn consent_loss_and_recovery() {
    let mut sim = basic(
        13,
        full(true),
        &["10.0.0.1:1000"],
        full(false),
        &["10.0.0.2:2000"],
    );
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
    sim.run_for(Duration::from_secs(20));
    sim.net.down = true;
    let t0 = sim.now;
    assert!(sim.run_until(Duration::from_secs(60), |s| s.both(IceState::Disconnected)));
    let lag = sim.now - t0;
    assert!(
        lag > Duration::from_secs(23) && lag <= Duration::from_secs(31),
        "{lag:?}"
    );
    assert!(sim.peers[0].agent.selected_pair().is_some());
    sim.run_for(Duration::from_secs(60));
    assert!(sim.both(IceState::Disconnected));
    sim.net.down = false;
    assert!(sim.run_until(Duration::from_secs(8), |s| s.both(IceState::Completed)));
    for p in &sim.peers {
        assert_eq!(
            p.states(),
            [
                IceState::Checking,
                IceState::Connected,
                IceState::Completed,
                IceState::Disconnected,
                IceState::Completed
            ]
        );
        assert_eq!(p.selections().len(), 1);
    }
}

fn restart(sim: &mut Sim, who: usize, keep: bool) {
    let other = 1 - who;
    // Offer from `who`, answer from the other side (which restarts too).
    let new = Credentials::random();
    sim.peers[who].agent.restart(new.clone(), keep);
    if !keep {
        for &ad in &sim.peers[who].addrs.clone() {
            assert!(
                sim.peers[who]
                    .agent
                    .add_local_candidate(Candidate::host(ad))
            );
        }
    }
    sim.peers[other].agent.set_remote_credentials(new);
    sim.signal_candidates(who);
    let ans = Credentials::random();
    sim.peers[other].agent.restart(ans.clone(), true);
    sim.peers[who].agent.set_remote_credentials(ans);
    sim.signal_candidates(other);
}

#[test]
fn ice_restart_either_side() {
    for (who, keep) in [(0, true), (1, true), (0, false), (1, false)] {
        let mut sim = basic(
            14,
            full(true),
            &["10.0.0.1:1000", "10.1.0.1:1001"],
            full(false),
            &["10.0.0.2:2000"],
        );
        sim.signal();
        assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
        let before = sim.peers[0].agent.selected_pair();
        sim.run_for(Duration::from_secs(7));
        restart(&mut sim, who, keep);
        for p in &sim.peers {
            assert_eq!(p.agent.send_pair(), p.agent.selected_pair());
            assert!(p.agent.send_pair().is_some());
        }
        assert!(
            sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)
                && s.peers.iter().all(|p| p.selections().len() == 2))
        );
        sim.assert_connected_pair();
        assert_eq!(sim.peers[0].agent.selected_pair(), before);
        sim.run_for(Duration::from_secs(60));
        assert!(sim.both(IceState::Completed));
    }
}

#[test]
fn ice_restart_moves_to_new_path() {
    // The old path dies right after the restart; the new generation finds the other one.
    let mut sim = basic(
        15,
        full(true),
        &["10.0.0.1:1000"],
        full(false),
        &["10.0.0.2:2000"],
    );
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(5), |s| s.both(IceState::Completed)));
    sim.net.dead.insert(a("10.0.0.1:1000"));
    sim.peers[0].addrs.push(a("10.9.0.1:1500"));
    let new = Credentials::random();
    sim.peers[0].agent.restart(new.clone(), false);
    assert!(
        sim.peers[0]
            .agent
            .add_local_candidate(Candidate::host(a("10.9.0.1:1500")))
    );
    // Old path still the send pair until the new nomination.
    assert_eq!(
        sim.peers[0].agent.send_pair(),
        Some((a("10.0.0.1:1000"), a("10.0.0.2:2000")))
    );
    sim.peers[1].agent.set_remote_credentials(new);
    sim.signal_candidates(0);
    let ans = Credentials::random();
    sim.peers[1].agent.restart(ans.clone(), true);
    sim.peers[0].agent.set_remote_credentials(ans);
    sim.signal_candidates(1);
    assert!(
        sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)
            && s.peers[0].agent.selected_pair()
                == Some((a("10.9.0.1:1500"), a("10.0.0.2:2000"))))
    );
    sim.assert_connected_pair();
}

#[test]
fn failed_after_end_of_candidates() {
    let mut sim = basic(
        16,
        full(true),
        &["10.0.0.1:1000"],
        full(false),
        &["10.0.0.2:2000"],
    );
    sim.net.down = true;
    sim.signal();
    sim.peers[0].agent.end_of_remote_candidates();
    sim.peers[1].agent.end_of_remote_candidates();
    assert!(sim.run_until(Duration::from_secs(20), |s| s.both(IceState::Failed)));
    let t = sim.elapsed();
    assert!(
        t > Duration::from_secs(6) && t < Duration::from_secs(10),
        "{t:?}"
    );
    assert_eq!(
        sim.peers[0].states(),
        [IceState::Checking, IceState::Failed]
    );
    // Nothing more scheduled.
    sim.run_for(Duration::from_secs(60));
    assert!(sim.peers.iter().all(|p| p.agent.poll_timeout().is_none()));

    // Without end-of-candidates: the failed timeout.
    let mut sim = basic(
        17,
        full(true),
        &["10.0.0.1:1000"],
        full(false),
        &["10.0.0.2:2000"],
    );
    sim.net.down = true;
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(60), |s| s.both(IceState::Failed)));
    let t = sim.elapsed();
    assert!(
        t >= Duration::from_secs(30) && t < Duration::from_secs(31),
        "{t:?}"
    );
}

#[test]
fn response_from_wrong_address_fails_check() {
    let now = Instant::now();
    let mut ca = full(true);
    ca.check_max_sends = 1; // no retransmission: the forged path is the only one
    let mut sim = Sim::new(
        18,
        Peer::new(ca, now, &["10.0.0.1:1000"]),
        Peer::new(full(false), now, &["10.0.0.2:2000"]),
        now,
    );
    // Responses from B appear to come from another address (a reflecting middlebox).
    sim.net.rewrite = Some(Box::new(|p: &mut Packet| {
        if let Ok(m) = Message::parse(&p.data) {
            if m.class() == Class::Success && p.src == a("10.0.0.2:2000") {
                p.src = a("10.0.0.3:2000");
            }
        }
    }));
    // Only A checks (B never learns A's credentials, so it only answers).
    let cb = sim.peers[1].agent.local_credentials().clone();
    sim.peers[0].agent.set_remote_credentials(cb);
    sim.signal_candidates(1);
    sim.peers[0].agent.end_of_remote_candidates();
    assert!(
        sim.run_until(Duration::from_secs(5), |s| s.peers[0].agent.state()
            == IceState::Failed)
    );
    assert!(sim.peers[0].agent.send_pair().is_none());
}

/// Runs A's first check through B by hand; returns (request transmit, B's response).
fn one_exchange() -> (IceAgent, IceAgent, Transmit, Transmit, Instant) {
    let now = Instant::now();
    let mut x = IceAgent::new(full(true), now);
    let mut y = IceAgent::new(full(false), now);
    x.add_local_candidate(Candidate::host(a("10.0.0.1:1000")));
    y.add_local_candidate(Candidate::host(a("10.0.0.2:2000")));
    x.set_remote_credentials(y.local_credentials().clone());
    x.add_remote_candidate(Candidate::host(a("10.0.0.2:2000")));
    x.handle_timeout(now);
    let req = x.poll_transmit().unwrap();
    assert_eq!(req.source, a("10.0.0.1:1000"));
    assert_eq!(req.destination, a("10.0.0.2:2000"));
    assert!(y.handle_receive(now, req.source, req.destination, &req.contents));
    let resp = y.poll_transmit().unwrap();
    (x, y, req, resp, now)
}

#[test]
fn request_and_response_format() {
    let (x, y, req, resp, _) = one_exchange();
    let m = Message::parse(&req.contents).unwrap();
    assert_eq!(m.method(), Method::BINDING);
    assert_eq!(m.class(), Class::Request);
    assert_eq!(
        m.get_str(attr::USERNAME).unwrap(),
        format!(
            "{}:{}",
            y.local_credentials().ufrag,
            x.local_credentials().ufrag
        )
    );
    assert_eq!(m.get_u32(attr::PRIORITY).unwrap() >> 24, 110);
    assert_eq!(m.get(attr::ICE_CONTROLLING).unwrap().len(), 8);
    assert!(!m.has(attr::ICE_CONTROLLED));
    assert!(!m.has(attr::USE_CANDIDATE));
    assert!(m.check_integrity(y.local_credentials().pwd.as_bytes()));
    assert!(m.check_fingerprint());
    let r = Message::parse(&resp.contents).unwrap();
    assert_eq!(r.class(), Class::Success);
    assert_eq!(r.transaction_id(), m.transaction_id());
    assert_eq!(
        r.get_xor_addr(attr::XOR_MAPPED_ADDRESS),
        Some(a("10.0.0.1:1000"))
    );
    assert!(r.check_integrity(y.local_credentials().pwd.as_bytes()));
    assert!(r.check_fingerprint());
    assert_eq!(
        (resp.source, resp.destination),
        (req.destination, req.source)
    );
}

#[test]
fn bad_integrity_ignored() {
    let (mut x, mut y, req, resp, now) = one_exchange();
    // A forged response (wrong key) is consumed but ignored; the genuine one still counts.
    let m = Message::parse(&resp.contents).unwrap();
    let forged = MessageBuilder::response(&m, Class::Success)
        .xor_addr(attr::XOR_MAPPED_ADDRESS, a("6.6.6.6:6"))
        .integrity(b"not the password")
        .fingerprint()
        .build();
    assert!(x.handle_receive(now, resp.source, resp.destination, &forged));
    assert!(x.send_pair().is_none());
    // A corrupted fingerprint is not even consumed.
    let mut bad = resp.contents.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(!x.handle_receive(now, resp.source, resp.destination, &bad));
    assert!(x.send_pair().is_none());
    assert!(x.handle_receive(now, resp.source, resp.destination, &resp.contents));
    assert_eq!(
        x.send_pair(),
        Some((a("10.0.0.1:1000"), a("10.0.0.2:2000")))
    );
    assert!(
        x.local_candidates().len() == 1,
        "no prflx from the forged response"
    );
    // A late duplicate is still consumed, and changes nothing.
    assert!(x.handle_receive(now, resp.source, resp.destination, &resp.contents));
    assert_eq!(
        x.send_pair(),
        Some((a("10.0.0.1:1000"), a("10.0.0.2:2000")))
    );

    // A request with a bad MESSAGE-INTEGRITY gets 401 and creates nothing.
    let mreq = Message::parse(&req.contents).unwrap();
    let tid = [7u8; 12];
    let forged_req = MessageBuilder::new(Method::BINDING, Class::Request, tid)
        .attr(attr::USERNAME, mreq.get(attr::USERNAME).unwrap())
        .u32(attr::PRIORITY, 1)
        .attr(attr::ICE_CONTROLLING, &[1; 8])
        .integrity(b"wrong")
        .fingerprint()
        .build();
    while y.poll_transmit().is_some() {}
    assert!(y.handle_receive(now, a("10.0.0.9:9"), a("10.0.0.2:2000"), &forged_req));
    let e = y.poll_transmit().unwrap();
    assert_eq!(
        Message::parse(&e.contents).unwrap().error_code().unwrap().0,
        401
    );
    assert!(
        y.remote_candidates()
            .iter()
            .all(|c| c.addr() != a("10.0.0.9:9"))
    );
    // Wrong ufrag: 401. Missing attributes: 400. No fingerprint: not ours.
    let wrong_user = MessageBuilder::new(Method::BINDING, Class::Request, tid)
        .attr(attr::USERNAME, b"nope:x")
        .u32(attr::PRIORITY, 1)
        .integrity(y.local_credentials().pwd.as_bytes())
        .fingerprint()
        .build();
    assert!(y.handle_receive(now, a("10.0.0.9:9"), a("10.0.0.2:2000"), &wrong_user));
    let e = y.poll_transmit().unwrap();
    assert_eq!(
        Message::parse(&e.contents).unwrap().error_code().unwrap().0,
        401
    );
    let user = format!("{}:x", y.local_credentials().ufrag);
    let no_prio = MessageBuilder::new(Method::BINDING, Class::Request, tid)
        .attr(attr::USERNAME, user.as_bytes())
        .integrity(y.local_credentials().pwd.as_bytes())
        .fingerprint()
        .build();
    assert!(y.handle_receive(now, a("10.0.0.9:9"), a("10.0.0.2:2000"), &no_prio));
    let e = y.poll_transmit().unwrap();
    assert_eq!(
        Message::parse(&e.contents).unwrap().error_code().unwrap().0,
        400
    );
    let no_user = MessageBuilder::new(Method::BINDING, Class::Request, tid)
        .fingerprint()
        .build();
    assert!(y.handle_receive(now, a("10.0.0.9:9"), a("10.0.0.2:2000"), &no_user));
    let e = y.poll_transmit().unwrap();
    assert_eq!(
        Message::parse(&e.contents).unwrap().error_code().unwrap().0,
        400
    );
    let no_fp = MessageBuilder::new(Method::BINDING, Class::Request, tid)
        .attr(attr::USERNAME, user.as_bytes())
        .u32(attr::PRIORITY, 1)
        .integrity(y.local_credentials().pwd.as_bytes())
        .build();
    assert!(!y.handle_receive(now, a("10.0.0.9:9"), a("10.0.0.2:2000"), &no_fp));
    assert!(y.poll_transmit().is_none());
    // Non-STUN and non-Binding STUN are not consumed.
    assert!(!y.handle_receive(now, a("10.0.0.9:9"), a("10.0.0.2:2000"), b"\x16\xfe\xfd"));
    let alloc = MessageBuilder::new(Method::ALLOCATE, Class::Request, tid)
        .fingerprint()
        .build();
    assert!(!y.handle_receive(now, a("10.0.0.9:9"), a("10.0.0.2:2000"), &alloc));
}

#[test]
fn role_conflict_responses() {
    let now = Instant::now();
    let mut y = IceAgent::new(full(true), now);
    y.add_local_candidate(Candidate::host(a("10.0.0.2:2000")));
    let user = format!("{}:x", y.local_credentials().ufrag);
    let pwd = y.local_credentials().pwd.clone();
    let req = |role: u16, tb: u64| {
        MessageBuilder::new(Method::BINDING, Class::Request, [3; 12])
            .attr(attr::USERNAME, user.as_bytes())
            .u32(attr::PRIORITY, 1000)
            .attr(role, &tb.to_be_bytes())
            .integrity(pwd.as_bytes())
            .fingerprint()
            .build()
    };
    let src = a("10.0.0.1:1000");
    let dst = a("10.0.0.2:2000");
    // Both controlling, ours is larger (u64::MAX can't lose): 487 and we stay controlling.
    // Tie-breakers are random, so use the extremes.
    assert!(y.handle_receive(now, src, dst, &req(attr::ICE_CONTROLLING, 0)));
    let r = y.poll_transmit().unwrap();
    let m = Message::parse(&r.contents).unwrap();
    assert_eq!(m.error_code().unwrap().0, 487);
    assert!(m.check_integrity(pwd.as_bytes()));
    assert!(y.controlling());
    // Remote larger: we switch to controlled and answer with success.
    assert!(y.handle_receive(now, src, dst, &req(attr::ICE_CONTROLLING, u64::MAX)));
    let r = y.poll_transmit().unwrap();
    assert_eq!(Message::parse(&r.contents).unwrap().class(), Class::Success);
    assert!(!y.controlling());
    // Both controlled, remote larger: 487. Remote smaller: we switch to controlling.
    assert!(y.handle_receive(now, src, dst, &req(attr::ICE_CONTROLLED, u64::MAX)));
    let r = y.poll_transmit().unwrap();
    assert_eq!(
        Message::parse(&r.contents).unwrap().error_code().unwrap().0,
        487
    );
    assert!(!y.controlling());
    assert!(y.handle_receive(now, src, dst, &req(attr::ICE_CONTROLLED, 0)));
    let r = y.poll_transmit().unwrap();
    assert_eq!(Message::parse(&r.contents).unwrap().class(), Class::Success);
    assert!(y.controlling());
}

#[test]
fn closed_agent_is_inert() {
    let (mut x, _y, _req, resp, now) = one_exchange();
    x.close();
    assert!(x.poll_timeout().is_none());
    assert!(!x.handle_receive(now, resp.source, resp.destination, &resp.contents));
    x.handle_timeout(now + Duration::from_secs(10));
    assert!(x.poll_transmit().is_none());
}

#[test]
fn candidate_lists() {
    let now = Instant::now();
    let mut x = IceAgent::new(full(true), now);
    assert!(x.add_local_candidate(Candidate::host(a("10.0.0.1:1000"))));
    assert!(!x.add_local_candidate(Candidate::host(a("10.0.0.1:1000"))));
    assert_eq!(x.local_candidates().len(), 1);
    x.set_remote_credentials(Credentials::new("abcd", "0123456789012345678901"));
    // Another generation's candidate, another component, a duplicate: ignored.
    x.add_remote_candidate(
        Candidate::parse("candidate:1 1 udp 2122260223 10.0.0.2 5 typ host ufrag zzzz").unwrap(),
    );
    x.add_remote_candidate(
        Candidate::parse("candidate:1 2 udp 2122260223 10.0.0.2 6 typ host").unwrap(),
    );
    x.add_remote_candidate(
        Candidate::parse("candidate:1 1 udp 2122260223 10.0.0.2 7 typ host ufrag abcd").unwrap(),
    );
    x.add_remote_candidate(
        Candidate::parse("candidate:1 1 udp 2122260223 10.0.0.2 7 typ host").unwrap(),
    );
    assert_eq!(x.remote_candidates().len(), 1);
    assert_eq!(x.state(), IceState::Checking);
    // A remote restart drops remote candidates.
    x.set_remote_credentials(Credentials::new("efgh", "0123456789012345678901"));
    assert!(x.remote_candidates().is_empty());
    assert_eq!(x.remote_credentials().unwrap().ufrag, "efgh");
    // A lite agent is never controlling.
    let mut l = IceAgent::new(IceConfig::new(true, true), now);
    assert!(!l.controlling());
    l.set_controlling(true);
    assert!(!l.controlling());
    assert!(l.poll_timeout().is_none());
}

// RFC 5769 test vectors through only_turn::stun.
const RFC5769_REQ: &[u8] = b"\x00\x01\x00\x58\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x10STUN test client\x00\x24\x00\x04\x6e\x00\x01\xff\x80\x29\x00\x08\x93\x2f\xf9\xb1\x51\x26\x3b\x36\x00\x06\x00\x09\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20\x00\x08\x00\x14\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2\x80\x28\x00\x04\xe5\x7a\x3b\xcf";
const RFC5769_V4: &[u8] = b"\x01\x01\x00\x3c\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\x00\x20\x00\x08\x00\x01\xa1\x47\xe1\x12\xa6\x43\x00\x08\x00\x14\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7\x80\x28\x00\x04\xc0\x7d\x4c\x96";
const RFC5769_V6: &[u8] = b"\x01\x01\x00\x48\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\x00\x20\x00\x14\x00\x02\xa1\x47\x01\x13\xa9\xfa\xa5\xd3\xf1\x79\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9\x00\x08\x00\x14\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c\x82\x92\xc2\x75\xbf\xe3\xed\x41\x80\x28\x00\x04\xc8\xfb\x0b\x4c";
const RFC5769_KEY: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";

#[test]
fn rfc5769_vectors() {
    let m = Message::parse(RFC5769_REQ).unwrap();
    assert_eq!(m.class(), Class::Request);
    assert_eq!(m.get_str(attr::USERNAME), Some("evtj:h6vY"));
    assert_eq!(m.get_u32(attr::PRIORITY), Some(0x6e00_01ff));
    assert_eq!(
        m.get(attr::ICE_CONTROLLED),
        Some(&[0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36][..])
    );
    assert!(m.check_integrity(RFC5769_KEY));
    assert!(m.check_fingerprint());
    for (raw, want) in [
        (RFC5769_V4, a("192.0.2.1:32853")),
        (
            RFC5769_V6,
            a("[2001:db8:1234:5678:11:2233:4455:6677]:32853"),
        ),
    ] {
        let m = Message::parse(raw).unwrap();
        assert_eq!(m.class(), Class::Success);
        assert_eq!(m.get_str(attr::SOFTWARE), Some("test vector"));
        assert_eq!(m.get_xor_addr(attr::XOR_MAPPED_ADDRESS), Some(want));
        assert!(m.check_integrity(RFC5769_KEY));
        assert!(!m.check_integrity(b"VOkJxbRl1RmTxUk/WvJxBu"));
        assert!(m.check_fingerprint());
    }
    // The RFC request reaches an agent whose credentials match it ("evtj" local, password
    // the vector key): it has every ICE attribute, so the agent answers it.
    let now = Instant::now();
    let mut cfg = full(true);
    cfg.local = Credentials::new("evtj", std::str::from_utf8(RFC5769_KEY).unwrap());
    let mut y = IceAgent::new(cfg, now);
    y.add_local_candidate(Candidate::host(a("10.0.0.2:2000")));
    assert!(y.handle_receive(now, a("192.0.2.1:32853"), a("10.0.0.2:2000"), RFC5769_REQ));
    let r = y.poll_transmit().unwrap();
    let m = Message::parse(&r.contents).unwrap();
    assert_eq!(m.class(), Class::Success);
    assert_eq!(
        m.get_xor_addr(attr::XOR_MAPPED_ADDRESS),
        Some(a("192.0.2.1:32853"))
    );
    assert!(m.check_integrity(RFC5769_KEY));
    assert!(m.check_fingerprint());
    assert_eq!(y.remote_candidates()[0].priority(), 0x6e00_01ff);
}

// ---- ICE-TCP (RFC 6544) ----

/// A peer with UDP host candidates and TCP host candidates of the given types. The simulated
/// network carries TCP checks like datagrams (as an RFC 4571 framed connection would deliver
/// them); an active candidate's address stands for its connection's local address.
fn tcp_peer(cfg: IceConfig, now: Instant, udp: &[&str], tcp: &[(&str, TcpType)]) -> Peer {
    let mut p = Peer::new(cfg, now, udp);
    for (ad, t) in tcp {
        assert!(p.agent.add_local_candidate(Candidate::host_tcp(a(ad), *t)));
        p.addrs.push(a(ad));
    }
    p
}

#[test]
fn ice_tcp_passive_with_an_active_remote() {
    for (seed, controlling, loss) in [(1, true, 0), (2, false, 0), (3, true, 20), (4, false, 20)] {
        let now = Instant::now();
        // A: UDP and passive TCP. B: active TCP only (no UDP path).
        let pa = tcp_peer(
            full(controlling),
            now,
            &["10.0.0.1:1000"],
            &[("10.0.0.1:1001", TcpType::Passive)],
        );
        let pb = tcp_peer(
            full(!controlling),
            now,
            &[],
            &[("10.0.0.2:50000", TcpType::Active)],
        );
        let mut sim = Sim::new(seed, pa, pb, now);
        sim.net.loss_pct = loss;
        sim.signal();
        // A signals the passive port; B signals port 9 and A never checks it.
        assert!(sim.peers[0].agent.remote_candidates()[0].addr().port() == 9);
        assert!(sim.run_until(Duration::from_secs(20), |s| s.both(IceState::Completed)));
        sim.assert_connected_pair();
        assert_eq!(
            sim.peers[0].agent.selected_pair(),
            Some((a("10.0.0.1:1001"), a("10.0.0.2:50000")))
        );
        sim.app_data = true;
        sim.run_for(Duration::from_secs(60));
        assert!(sim.both(IceState::Completed), "seed {seed}");
        assert!(sim.peers.iter().all(|p| p.app > 100));
    }
}

#[test]
fn ice_tcp_loses_to_udp() {
    let now = Instant::now();
    let pa = tcp_peer(
        full(true),
        now,
        &["10.0.0.1:1000"],
        &[("10.0.0.1:1001", TcpType::Passive)],
    );
    let pb = tcp_peer(
        full(false),
        now,
        &["10.0.0.2:2000"],
        &[("10.0.0.2:50000", TcpType::Active)],
    );
    let mut sim = Sim::new(5, pa, pb, now);
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)));
    assert_eq!(
        sim.peers[0].agent.selected_pair(),
        Some((a("10.0.0.1:1000"), a("10.0.0.2:2000")))
    );
}

#[test]
fn ice_tcp_passive_alone_never_checks() {
    // Only passive TCP on one side and UDP on the other: nothing pairs, nothing is sent.
    let now = Instant::now();
    let pa = tcp_peer(full(true), now, &[], &[("10.0.0.1:1001", TcpType::Passive)]);
    let pb = Peer::new(full(false), now, &["10.0.0.2:2000"]);
    let mut sim = Sim::new(6, pa, pb, now);
    sim.signal();
    sim.peers[0].agent.end_of_remote_candidates();
    sim.peers[1].agent.end_of_remote_candidates();
    sim.run_for(Duration::from_secs(5));
    assert!(sim.net.queue.is_empty());
    assert_ne!(sim.peers[0].agent.state(), IceState::Connected);
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Nomination {
    Regular,
    Aggressive,
    Renomination,
}

fn nominating(mode: Nomination, controlling: bool) -> IceConfig {
    let mut c = full(controlling);
    c.aggressive_nomination = mode == Nomination::Aggressive;
    c.renomination = mode == Nomination::Renomination;
    c
}

/// Counts the requests carrying USE-CANDIDATE and NOMINATION (0xC001) in the queue.
fn nominations(sim: &Sim) -> (usize, usize) {
    let mut n = (0, 0);
    for p in &sim.net.queue {
        if let Ok(m) = Message::parse(&p.data) {
            if m.class() == Class::Request && m.has(attr::USE_CANDIDATE) {
                n.0 += 1;
                n.1 += usize::from(m.has(0xC001));
            }
        }
    }
    n
}

#[test]
fn better_pair_after_nomination() {
    // A (controlling) has IPv4 and IPv6; B only IPv4 at first, so the IPv4 pair is selected.
    // B then trickles an IPv6 candidate: a better pair. Regular nomination keeps the first
    // selection; aggressive nomination and renomination move both sides to the new pair.
    for mode in [
        Nomination::Regular,
        Nomination::Aggressive,
        Nomination::Renomination,
    ] {
        for seed in [1, 2] {
            let mut sim = basic(
                seed,
                nominating(mode, true),
                &["10.0.0.1:1000", "[2001:db8::1]:1000"],
                nominating(mode, false),
                &["10.0.0.2:2000"],
            );
            sim.net.loss_pct = if seed == 2 { 10 } else { 0 };
            for p in &mut sim.peers {
                p.agent
                    .set_remote_renomination(mode == Nomination::Renomination);
            }
            sim.signal();
            assert!(
                sim.run_until(Duration::from_secs(20), |s| s.both(IceState::Completed)),
                "{mode:?}"
            );
            let v4 = (a("10.0.0.1:1000"), a("10.0.0.2:2000"));
            assert_eq!(sim.peers[0].agent.selected_pair(), Some(v4), "{mode:?}");
            let mut uses = 0;
            sim.peers[1].addrs.push(a("[2001:db8::2]:2000"));
            assert!(
                sim.peers[1]
                    .agent
                    .add_local_candidate(Candidate::host(a("[2001:db8::2]:2000")))
            );
            sim.signal_candidates(1);
            let limit = sim.now + Duration::from_secs(15);
            while sim.step(limit) {
                let (u, n) = nominations(&sim);
                uses += u;
                if mode != Nomination::Renomination {
                    assert_eq!(n, 0, "NOMINATION only with renomination");
                }
            }
            let v6 = (a("[2001:db8::1]:1000"), a("[2001:db8::2]:2000"));
            let want = if mode == Nomination::Regular { v4 } else { v6 };
            assert_eq!(sim.peers[0].agent.selected_pair(), Some(want), "{mode:?}");
            sim.assert_connected_pair();
            assert!(sim.both(IceState::Completed), "{mode:?}");
            let switches = if mode == Nomination::Regular { 1 } else { 2 };
            for p in &sim.peers {
                assert_eq!(p.selections().len(), switches, "{mode:?}");
            }
            if mode == Nomination::Regular {
                assert_eq!(uses, 0, "no USE-CANDIDATE after nomination");
            }
            // Still up on the new pair.
            sim.app_data = true;
            sim.run_for(Duration::from_secs(40));
            assert!(sim.both(IceState::Completed), "{mode:?}");
        }
    }
}

#[test]
fn aggressive_nomination_selects_the_best_pair() {
    // Every check of the controlling side carries USE-CANDIDATE; both sides end on the
    // highest-priority pair (IPv6 here) even though several pairs were nominated.
    let mut sim = basic(
        3,
        nominating(Nomination::Aggressive, true),
        &["10.0.0.1:1000", "[2001:db8::1]:1000"],
        full(false),
        &["10.0.0.2:2000", "[2001:db8::2]:2000"],
    );
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)));
    assert_eq!(
        sim.peers[0].agent.selected_pair(),
        Some((a("[2001:db8::1]:1000"), a("[2001:db8::2]:2000")))
    );
    sim.assert_connected_pair();
}

/// A Binding request from `from` (controlling, tie-breaker `tb`) to `to`'s agent, nominating
/// with `nomination` (USE-CANDIDATE and, if given, NOMINATION).
fn nominate_request(remote: &Credentials, local_ufrag: &str, nomination: Option<u32>) -> Vec<u8> {
    let mut b = MessageBuilder::new(Method::BINDING, Class::Request, stun::transaction_id())
        .attr(
            attr::USERNAME,
            format!("{}:{}", remote.ufrag, local_ufrag).as_bytes(),
        )
        .u32(attr::PRIORITY, 1_853_824_767)
        .attr(attr::ICE_CONTROLLING, &u64::MAX.to_be_bytes())
        .attr(attr::USE_CANDIDATE, &[]);
    if let Some(n) = nomination {
        b = b.u32(0xC001, n);
    }
    b.integrity(remote.pwd.as_bytes()).fingerprint().build()
}

#[test]
fn controlled_follows_the_highest_nomination() {
    // B (controlled) has two valid pairs to A; A nominates with NOMINATION values: the
    // highest value wins, an older (lower) one later changes nothing.
    let mut sim = basic(
        4,
        full(true),
        &["10.0.0.1:1000", "10.0.0.1:1001"],
        full(false),
        &["10.0.0.2:2000"],
    );
    sim.signal();
    assert!(sim.run_until(Duration::from_secs(10), |s| s.both(IceState::Completed)));
    let first = sim.peers[1].agent.selected_pair().unwrap();
    let other = if first.1 == a("10.0.0.1:1000") {
        a("10.0.0.1:1001")
    } else {
        a("10.0.0.1:1000")
    };
    let b_addr = a("10.0.0.2:2000");
    let bc = sim.peers[1].agent.local_credentials().clone();
    let au = sim.peers[0].agent.local_credentials().ufrag.clone();
    // The forged requests' responses would reach A, which never sent them: drop them.
    let inject = |sim: &mut Sim, from: SocketAddr, r: &[u8]| {
        let now = sim.now;
        assert!(sim.peers[1].agent.handle_receive(now, from, b_addr, r));
        while let Some(t) = sim.peers[1].agent.poll_transmit() {
            if Message::parse(&t.contents).unwrap().class() == Class::Request {
                sim.net.send(now, t);
            }
        }
    };
    // Make sure B's pair to `other` is valid: its check of it went out when A's arrived.
    inject(&mut sim, other, &nominate_request(&bc, &au, None));
    sim.run_for(Duration::from_secs(2));
    let send = |sim: &mut Sim, from: SocketAddr, n: u32| {
        inject(sim, from, &nominate_request(&bc, &au, Some(n)));
        sim.run_for(Duration::from_millis(500));
    };
    send(&mut sim, other, 5);
    assert_eq!(sim.peers[1].agent.selected_pair(), Some((b_addr, other)));
    send(&mut sim, first.1, 3);
    assert_eq!(sim.peers[1].agent.selected_pair(), Some((b_addr, other)));
    send(&mut sim, first.1, 6);
    assert_eq!(sim.peers[1].agent.selected_pair(), Some((b_addr, first.1)));
}
