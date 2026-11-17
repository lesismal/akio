//! The mainline DHT (BEP 5) as a node without I/O: KRPC messages ([`Msg`]), a routing table
//! of k-buckets (K = 8), the four queries (ping, find_node, get_peers, announce_peer, with
//! `implied_port`) answered with tokens bound to the asker's IP (valid 5 to 10 minutes), and
//! Kademlia's iterative lookups with 3 queries in flight: [`Node::bootstrap`],
//! [`Node::get_peers`] (optionally announcing to the 8 closest nodes that gave a token).
//!
//! A [`Node`] takes datagrams ([`Node::handle`]) and the clock ([`Node::tick`]), and queues the
//! datagrams it wants sent ([`Node::take_outgoing`]) and what it learned ([`Node::take_events`]).
//! Only nodes that answered a query of ours enter the routing table.
//!
//! IPv6 (BEP 32): IPv4 and IPv6 nodes live in separate routing tables; queries are answered with
//! `nodes` and/or `nodes6` as the asker's `want` says (by default its own family), and stored
//! peers of the asker's family. A node on a dual-stack socket ([`Node::set_ipv6`]) also asks for
//! `n6` and walks lookups through nodes of both families.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::bencode::{self, Value};
use crate::metainfo::{InfoHash, sha1};
use crate::wire::{compact_peers, parse_compact_peers};

/// Nodes per bucket, and the nodes a lookup converges on.
pub const K: usize = 8;
/// Queries in flight per lookup.
pub const ALPHA: usize = 3;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const TOKEN_ROTATE: Duration = Duration::from_secs(300);
const PEER_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_PEERS_PER_TORRENT: usize = 200;
const MAX_TORRENTS: usize = 10_000;
const QUESTIONABLE: Duration = Duration::from_secs(15 * 60);
const REFRESH: Duration = Duration::from_secs(5 * 60);

/// A 160-bit node ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct NodeId(pub [u8; 20]);

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", crate::metainfo::hex(&self.0[..4]))
    }
}

impl NodeId {
    /// A random ID.
    pub fn random() -> NodeId {
        let mut b = [0u8; 20];
        crate::rand_fill(&mut b);
        NodeId(b)
    }

    /// XOR distance.
    pub fn distance(&self, other: &[u8; 20]) -> [u8; 20] {
        let mut d = [0u8; 20];
        for (i, o) in d.iter_mut().enumerate() {
            *o = self.0[i] ^ other[i];
        }
        d
    }

    /// Leading bits shared with `other` (160 when equal).
    pub fn common_prefix(&self, other: &NodeId) -> usize {
        for (i, (a, b)) in self.0.iter().zip(other.0.iter()).enumerate() {
            let x = a ^ b;
            if x != 0 {
                return i * 8 + x.leading_zeros() as usize;
            }
        }
        160
    }
}

/// A node: ID and address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NodeInfo {
    /// Its ID.
    pub id: NodeId,
    /// Its address.
    pub addr: SocketAddr,
}

/// Compact node info: 26 bytes per IPv4 node.
pub fn compact_nodes(nodes: &[NodeInfo]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 26);
    for n in nodes {
        if let SocketAddr::V4(a) = n.addr {
            out.extend_from_slice(&n.id.0);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out
}

/// Decodes compact node info.
pub fn parse_compact_nodes(b: &[u8]) -> Vec<NodeInfo> {
    b.chunks_exact(26)
        .map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            NodeInfo {
                id: NodeId(id),
                addr: SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(c[20], c[21], c[22], c[23]),
                    u16::from_be_bytes([c[24], c[25]]),
                )),
            }
        })
        .collect()
}

/// Compact IPv6 node info (BEP 32): 38 bytes per node.
pub fn compact_nodes6(nodes: &[NodeInfo]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 38);
    for n in nodes {
        if let SocketAddr::V6(a) = n.addr {
            out.extend_from_slice(&n.id.0);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out
}

/// Decodes compact IPv6 node info.
pub fn parse_compact_nodes6(b: &[u8]) -> Vec<NodeInfo> {
    b.chunks_exact(38)
        .map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&c[20..36]);
            NodeInfo {
                id: NodeId(id),
                addr: SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    u16::from_be_bytes([c[36], c[37]]),
                    0,
                    0,
                )),
            }
        })
        .collect()
}

/// A KRPC message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Msg {
    /// `y = q`
    Query {
        /// Transaction ID.
        t: Vec<u8>,
        /// Method name.
        q: String,
        /// Arguments (a dictionary).
        a: Value,
        /// BEP 43 `ro`: the sender is read-only (do not add it to routing tables).
        ro: bool,
    },
    /// `y = r`
    Response {
        /// Transaction ID.
        t: Vec<u8>,
        /// Return values (a dictionary).
        r: Value,
    },
    /// `y = e`
    Error {
        /// Transaction ID.
        t: Vec<u8>,
        /// Error code.
        code: i64,
        /// Message.
        msg: String,
    },
}

impl Msg {
    /// Parses a datagram.
    pub fn parse(b: &[u8]) -> Option<Msg> {
        let v = bencode::decode(b).ok()?;
        let t = v.bytes_at("t")?.to_vec();
        match v.bytes_at("y")? {
            b"q" => Some(Msg::Query {
                t,
                q: v.str_at("q")?.to_owned(),
                a: v.get("a").filter(|a| a.as_dict().is_some())?.clone(),
                ro: v.int("ro") == Some(1),
            }),
            b"r" => Some(Msg::Response {
                t,
                r: v.get("r").filter(|a| a.as_dict().is_some())?.clone(),
            }),
            b"e" => {
                let e = v.get("e")?.as_list()?;
                Some(Msg::Error {
                    t,
                    code: e.first().and_then(Value::as_int).unwrap_or(0),
                    msg: e.get(1).and_then(Value::as_str).unwrap_or("").to_owned(),
                })
            }
            _ => None,
        }
    }

    /// Encodes it.
    pub fn encode(&self) -> Vec<u8> {
        let v = match self {
            Msg::Query { t, q, a, ro } => {
                let v = Value::dict()
                    .with("t", t.clone())
                    .with("y", "q")
                    .with("q", q.as_str())
                    .with("a", a.clone());
                if *ro { v.with("ro", 1) } else { v }
            }
            Msg::Response { t, r } => Value::dict()
                .with("t", t.clone())
                .with("y", "r")
                .with("r", r.clone()),
            Msg::Error { t, code, msg } => Value::dict()
                .with("t", t.clone())
                .with("y", "e")
                .with("e", vec![Value::Int(*code), Value::from(msg.as_str())]),
        };
        bencode::encode(&v)
    }
}

#[derive(Clone, Debug)]
struct Entry {
    info: NodeInfo,
    last_seen: Instant,
    fails: u32,
}

/// The routing table: bucket `i` holds nodes sharing exactly `i` leading bits with our ID.
#[derive(Debug)]
struct Table {
    own: NodeId,
    buckets: Vec<Vec<Entry>>,
    ips: HashSet<IpAddr>,
}

impl Table {
    fn new(own: NodeId) -> Table {
        Table {
            own,
            buckets: vec![Vec::new(); 160],
            ips: HashSet::new(),
        }
    }

    fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    fn heard(&mut self, info: NodeInfo, now: Instant) {
        if info.id == self.own {
            return;
        }
        let b = &mut self.buckets[self.own.common_prefix(&info.id).min(159)];
        if let Some(e) = b.iter_mut().find(|e| e.info.id == info.id) {
            e.last_seen = now;
            e.fails = 0;
            e.info.addr = info.addr;
            return;
        }
        // One node per IP (BEP 42's spirit), except loopback, where tests run whole networks.
        if !info.addr.ip().is_loopback() && self.ips.contains(&info.addr.ip()) {
            return;
        }
        if b.len() >= K {
            // Replace a node that failed or has been quiet for 15 minutes.
            let Some(i) = b
                .iter()
                .position(|e| e.fails >= 2 || now.duration_since(e.last_seen) > QUESTIONABLE)
            else {
                return;
            };
            let old = b.remove(i);
            self.ips.remove(&old.info.addr.ip());
        }
        b.push(Entry {
            info,
            last_seen: now,
            fails: 0,
        });
        self.ips.insert(info.addr.ip());
    }

    /// Whether `id` is new and its bucket has room.
    fn wants(&self, id: &NodeId) -> bool {
        if *id == self.own {
            return false;
        }
        let b = &self.buckets[self.own.common_prefix(id).min(159)];
        b.len() < K && !b.iter().any(|e| e.info.id == *id)
    }

    fn failed(&mut self, addr: SocketAddr) {
        for b in &mut self.buckets {
            if let Some(i) = b.iter().position(|e| e.info.addr == addr) {
                b[i].fails += 1;
                if b[i].fails >= 5 {
                    let old = b.remove(i);
                    self.ips.remove(&old.info.addr.ip());
                }
                return;
            }
        }
    }

    fn closest(&self, target: &[u8; 20], n: usize) -> Vec<NodeInfo> {
        let mut all: Vec<&Entry> = self
            .buckets
            .iter()
            .flatten()
            .filter(|e| e.fails < 2)
            .collect();
        all.sort_by_key(|e| NodeId(*target).distance(&e.info.id.0));
        all.into_iter().take(n).map(|e| e.info).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandState {
    New,
    Asked,
    Answered,
    Failed,
}

#[derive(Debug)]
struct Candidate {
    info: NodeInfo,
    state: CandState,
    token: Option<Vec<u8>>,
}

#[derive(Debug)]
struct Lookup {
    target: [u8; 20],
    get_peers: bool,
    announce_port: Option<u16>,
    candidates: BTreeMap<[u8; 20], Candidate>,
    in_flight: usize,
    peers_found: usize,
}

#[derive(Debug)]
struct Pending {
    to: SocketAddr,
    sent: Instant,
    lookup: Option<u64>,
}

/// What a [`Node`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DhtEvent {
    /// Peers of a torrent, found by a [`Node::get_peers`] lookup.
    Peers {
        /// The torrent.
        info_hash: InfoHash,
        /// Peers (compact values, IPv4 and, from IPv6 nodes, IPv6).
        peers: Vec<SocketAddr>,
    },
    /// A lookup ended.
    LookupDone {
        /// The lookup's ID ([`Node::get_peers`], [`Node::bootstrap`]).
        id: u64,
        /// Peers found (get_peers).
        peers: usize,
        /// Nodes announced to.
        announced: usize,
    },
    /// Another node announced a peer for a torrent to us.
    Announced {
        /// The torrent.
        info_hash: InfoHash,
        /// The peer.
        peer: SocketAddr,
    },
}

/// A DHT node without I/O.
#[derive(Debug)]
pub struct Node {
    id: NodeId,
    table: Table,
    table6: Table,
    ipv6: bool,
    secrets: [[u8; 16]; 2],
    rotated: Instant,
    refreshed: Instant,
    storage: HashMap<InfoHash, Vec<(SocketAddr, Instant)>>,
    pending: HashMap<Vec<u8>, Pending>,
    lookups: HashMap<u64, Lookup>,
    next_tid: u16,
    next_lookup: u64,
    out: Vec<(SocketAddr, Vec<u8>)>,
    events: Vec<DhtEvent>,
    routers: Vec<SocketAddr>,
    read_only: bool,
}

fn now() -> Instant {
    Instant::now()
}

impl Node {
    /// A node with ID `id`.
    pub fn new(id: NodeId) -> Node {
        let mut secrets = [[0u8; 16]; 2];
        crate::rand_fill(&mut secrets[0]);
        crate::rand_fill(&mut secrets[1]);
        let t = now();
        Node {
            id,
            table: Table::new(id),
            table6: Table::new(id),
            ipv6: false,
            secrets,
            rotated: t,
            refreshed: t,
            storage: HashMap::new(),
            pending: HashMap::new(),
            lookups: HashMap::new(),
            next_tid: crate::rand_u32() as u16,
            next_lookup: 1,
            out: Vec::new(),
            events: Vec::new(),
            routers: Vec::new(),
            read_only: false,
        }
    }

    /// Reaches IPv6 nodes too (a dual-stack socket): queries ask for `nodes6` as well as
    /// `nodes`, and lookups walk nodes of both families (BEP 32). Off by default.
    pub fn set_ipv6(&mut self, on: bool) {
        self.ipv6 = on;
    }

    fn table_for(&mut self, addr: &SocketAddr) -> &mut Table {
        if addr.is_ipv6() {
            &mut self.table6
        } else {
            &mut self.table
        }
    }

    /// The `n` closest of both tables (IPv6 only with [`Node::set_ipv6`]).
    fn closest_any(&self, target: &[u8; 20], n: usize) -> Vec<NodeInfo> {
        let mut all = self.table.closest(target, n);
        if self.ipv6 {
            all.extend(self.table6.closest(target, n));
            all.sort_by_key(|i| NodeId(*target).distance(&i.id.0));
            all.truncate(n);
        }
        all
    }

    fn want_both(&self, a: Value) -> Value {
        if self.ipv6 {
            a.with("want", vec![Value::from("n4"), Value::from("n6")])
        } else {
            a
        }
    }

    /// Queries without answering (BEP 43): other nodes leave us out of their tables.
    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    /// Our ID.
    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Nodes in the routing tables (IPv4 and IPv6).
    pub fn table_len(&self) -> usize {
        self.table.len() + self.table6.len()
    }

    /// IPv6 nodes in the routing table.
    pub fn table6_len(&self) -> usize {
        self.table6.len()
    }

    /// The `n` known nodes closest to `target`, of both families.
    pub fn closest(&self, target: &[u8; 20], n: usize) -> Vec<NodeInfo> {
        let mut all = self.table.closest(target, n);
        all.extend(self.table6.closest(target, n));
        all.sort_by_key(|i| NodeId(*target).distance(&i.id.0));
        all.truncate(n);
        all
    }

    /// Datagrams to send.
    pub fn take_outgoing(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut self.out)
    }

    /// What happened since the last call.
    pub fn take_events(&mut self) -> Vec<DhtEvent> {
        std::mem::take(&mut self.events)
    }

    /// Peers stored for `info_hash` (announced to us).
    pub fn stored_peers(&self, info_hash: &InfoHash) -> Vec<SocketAddr> {
        self.storage
            .get(info_hash)
            .map(|v| v.iter().map(|(a, _)| *a).collect())
            .unwrap_or_default()
    }

    fn token(&self, ip: IpAddr, secret: usize) -> Vec<u8> {
        let mut b = self.secrets[secret].to_vec();
        match ip {
            IpAddr::V4(a) => b.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => b.extend_from_slice(&a.octets()),
        }
        sha1(&b)[..8].to_vec()
    }

    fn query(&mut self, to: SocketAddr, q: &str, mut a: Value, lookup: Option<u64>) {
        let t = self.next_tid.to_be_bytes().to_vec();
        self.next_tid = self.next_tid.wrapping_add(1);
        a.insert("id", self.id.0.to_vec());
        let m = Msg::Query {
            t: t.clone(),
            q: q.to_owned(),
            a,
            ro: self.read_only,
        }
        .encode();
        self.out.push((to, m));
        self.pending.insert(
            t,
            Pending {
                to,
                sent: now(),
                lookup,
            },
        );
    }

    /// Pings `addr` (a node that answers enters the routing table).
    pub fn ping(&mut self, addr: SocketAddr) {
        self.query(addr, "ping", Value::dict(), None);
    }

    /// Starts filling the routing table from `routers` (well-known nodes, or the nodes of a
    /// torrent): a lookup of our own ID. Kept, to start again when the table empties.
    pub fn bootstrap(&mut self, routers: &[SocketAddr]) -> u64 {
        for r in routers {
            if !self.routers.contains(r) {
                self.routers.push(*r);
            }
        }
        let target = self.id.0;
        self.start_lookup(target, false, None, routers)
    }

    /// Looks for peers of `info_hash`; with `announce_port` (`Some(0)`: implied port, the
    /// port the queries leave from), announces this peer to the closest nodes once done.
    pub fn get_peers(&mut self, info_hash: InfoHash, announce_port: Option<u16>) -> u64 {
        let routers = self.routers.clone();
        self.start_lookup(info_hash.0, true, announce_port, &routers)
    }

    fn start_lookup(
        &mut self,
        target: [u8; 20],
        get_peers: bool,
        announce_port: Option<u16>,
        extra: &[SocketAddr],
    ) -> u64 {
        let id = self.next_lookup;
        self.next_lookup += 1;
        let mut l = Lookup {
            target,
            get_peers,
            announce_port,
            candidates: BTreeMap::new(),
            in_flight: 0,
            peers_found: 0,
        };
        for n in self.closest_any(&target, K * 2) {
            l.candidates.insert(
                NodeId(target).distance(&n.id.0),
                Candidate {
                    info: n,
                    state: CandState::New,
                    token: None,
                },
            );
        }
        self.lookups.insert(id, l);
        // Routers have no known ID: ask them directly, outside the candidate set.
        for &r in extra {
            if r.is_ipv6() && !self.ipv6 {
                continue;
            }
            let a = self.want_both(if get_peers {
                Value::dict().with("info_hash", target.to_vec())
            } else {
                Value::dict().with("target", target.to_vec())
            });
            self.query(
                r,
                if get_peers { "get_peers" } else { "find_node" },
                a,
                Some(id),
            );
            if let Some(l) = self.lookups.get_mut(&id) {
                l.in_flight += 1;
            }
        }
        self.advance(id);
        id
    }

    fn advance(&mut self, id: u64) {
        let Some(l) = self.lookups.get_mut(&id) else {
            return;
        };
        let mut to_ask = Vec::new();
        // Ask the closest unasked among the K closest still alive.
        let mut alive = 0;
        for c in l.candidates.values_mut() {
            if alive >= K {
                break;
            }
            match c.state {
                CandState::Failed => continue,
                CandState::New if l.in_flight + to_ask.len() < ALPHA => {
                    c.state = CandState::Asked;
                    to_ask.push(c.info.addr);
                }
                _ => {}
            }
            alive += 1;
        }
        let (target, gp) = (l.target, l.get_peers);
        l.in_flight += to_ask.len();
        let done = l.in_flight == 0;
        for addr in to_ask {
            let a = self.want_both(if gp {
                Value::dict().with("info_hash", target.to_vec())
            } else {
                Value::dict().with("target", target.to_vec())
            });
            self.query(
                addr,
                if gp { "get_peers" } else { "find_node" },
                a,
                Some(id),
            );
        }
        if done {
            self.finish(id);
        }
    }

    fn finish(&mut self, id: u64) {
        let Some(l) = self.lookups.remove(&id) else {
            return;
        };
        let mut announced = 0;
        if let Some(port) = l.announce_port {
            let ih = l.target.to_vec();
            let targets: Vec<(SocketAddr, Vec<u8>)> = l
                .candidates
                .values()
                .filter(|c| c.state == CandState::Answered)
                .filter_map(|c| c.token.clone().map(|t| (c.info.addr, t)))
                .take(K)
                .collect();
            for (addr, token) in targets {
                let a = Value::dict()
                    .with("info_hash", ih.clone())
                    .with("port", i64::from(port))
                    .with("implied_port", i64::from(port == 0))
                    .with("token", token);
                self.query(addr, "announce_peer", a, None);
                announced += 1;
            }
        }
        self.events.push(DhtEvent::LookupDone {
            id,
            peers: l.peers_found,
            announced,
        });
    }

    /// Takes a datagram from `from`; `false` if it is not KRPC.
    pub fn handle(&mut self, from: SocketAddr, data: &[u8]) -> bool {
        let Some(m) = Msg::parse(data) else {
            return false;
        };
        match m {
            Msg::Query { t, q, a, ro } => {
                if !self.read_only {
                    self.answer(from, t, &q, &a);
                    // A node that queries us, not read-only and new to us, is pinged: if it
                    // answers, it enters the table (where it fits).
                    if let Some(id) = a.bytes_at("id").and_then(|b| <[u8; 20]>::try_from(b).ok()) {
                        let id = NodeId(id);
                        if !ro
                            && (from.is_ipv4() || self.ipv6)
                            && self.table_for(&from).wants(&id)
                            && !self.pending.values().any(|p| p.to == from)
                        {
                            self.ping(from);
                        }
                    }
                }
            }
            Msg::Response { t, r } => self.on_response(from, &t, &r),
            Msg::Error { t, .. } => {
                if let Some(p) = self.pending.remove(&t) {
                    if let Some(id) = p.lookup {
                        self.lookup_failed(id, p.to);
                    }
                }
            }
        }
        true
    }

    fn answer(&mut self, from: SocketAddr, t: Vec<u8>, q: &str, a: &Value) {
        let err = |code: i64, msg: &str| {
            Msg::Error {
                t: t.clone(),
                code,
                msg: msg.to_owned(),
            }
            .encode()
        };
        if a.bytes_at("id").map(<[u8]>::len) != Some(20) {
            self.out.push((from, err(203, "bad id")));
            return;
        }
        let mut r = Value::dict().with("id", self.id.0.to_vec());
        // BEP 32: `want` lists the families to return nodes of; by default the asker's own.
        let want = a.get("want").and_then(Value::as_list);
        let (n4, n6) = match want {
            Some(w) => (
                w.iter().any(|x| x.as_bytes() == Some(b"n4")),
                w.iter().any(|x| x.as_bytes() == Some(b"n6")),
            ),
            None => (from.is_ipv4(), from.is_ipv6()),
        };
        let nodes = |me: &Node, r: &mut Value, target: &[u8; 20]| {
            if n4 {
                r.insert("nodes", compact_nodes(&me.table.closest(target, K)));
            }
            if n6 {
                r.insert("nodes6", compact_nodes6(&me.table6.closest(target, K)));
            }
        };
        match q {
            "ping" => {}
            "find_node" => {
                let Some(target) = a
                    .bytes_at("target")
                    .and_then(|b| <[u8; 20]>::try_from(b).ok())
                else {
                    self.out.push((from, err(203, "bad target")));
                    return;
                };
                nodes(self, &mut r, &target);
            }
            "get_peers" => {
                let Some(ih) = a
                    .bytes_at("info_hash")
                    .and_then(|b| <[u8; 20]>::try_from(b).ok())
                else {
                    self.out.push((from, err(203, "bad info_hash")));
                    return;
                };
                r.insert("token", self.token(from.ip(), 0));
                // Peers of the asker's family (BEP 32).
                let v6 = from.is_ipv6();
                let values: Vec<Value> = self
                    .stored_peers(&InfoHash(ih))
                    .iter()
                    .filter(|p| p.is_ipv6() == v6)
                    .take(50)
                    .map(|p| Value::Bytes(compact_peers(std::slice::from_ref(p), v6)))
                    .collect();
                if !values.is_empty() {
                    r.insert("values", values);
                }
                nodes(self, &mut r, &ih);
            }
            "announce_peer" => {
                let Some(ih) = a
                    .bytes_at("info_hash")
                    .and_then(|b| <[u8; 20]>::try_from(b).ok())
                else {
                    self.out.push((from, err(203, "bad info_hash")));
                    return;
                };
                let token = a.bytes_at("token").unwrap_or_default();
                if token != self.token(from.ip(), 0).as_slice()
                    && token != self.token(from.ip(), 1).as_slice()
                {
                    self.out.push((from, err(203, "bad token")));
                    return;
                }
                let port = if a.int("implied_port") == Some(1) {
                    from.port()
                } else {
                    match a.int("port").and_then(|p| u16::try_from(p).ok()) {
                        Some(p) if p != 0 => p,
                        _ => {
                            self.out.push((from, err(203, "bad port")));
                            return;
                        }
                    }
                };
                let peer = SocketAddr::new(from.ip(), port);
                let ih = InfoHash(ih);
                if self.storage.len() < MAX_TORRENTS || self.storage.contains_key(&ih) {
                    let list = self.storage.entry(ih).or_default();
                    list.retain(|(p, _)| *p != peer);
                    if list.len() < MAX_PEERS_PER_TORRENT {
                        list.push((peer, now()));
                    }
                }
                self.events.push(DhtEvent::Announced {
                    info_hash: ih,
                    peer,
                });
            }
            _ => {
                self.out.push((from, err(204, "method unknown")));
                return;
            }
        }
        self.out.push((from, Msg::Response { t, r }.encode()));
    }

    fn on_response(&mut self, from: SocketAddr, t: &[u8], r: &Value) {
        let Some(p) = self.pending.remove(t) else {
            return;
        };
        if p.to != from {
            self.pending.insert(t.to_vec(), p);
            return;
        }
        let Some(id) = r
            .bytes_at("id")
            .and_then(|b| <[u8; 20]>::try_from(b).ok())
            .map(NodeId)
        else {
            return;
        };
        if from.is_ipv4() || self.ipv6 {
            self.table_for(&from)
                .heard(NodeInfo { id, addr: from }, now());
        }
        let ipv6 = self.ipv6;
        let Some(lid) = p.lookup else { return };
        let Some(l) = self.lookups.get_mut(&lid) else {
            return;
        };
        l.in_flight = l.in_flight.saturating_sub(1);
        let target = l.target;
        let dist = NodeId(target).distance(&id.0);
        let token = r.bytes_at("token").map(<[u8]>::to_vec);
        match l.candidates.get_mut(&dist) {
            Some(c) => {
                c.state = CandState::Answered;
                c.token = token;
                c.info.addr = from;
            }
            None => {
                l.candidates.insert(
                    dist,
                    Candidate {
                        info: NodeInfo { id, addr: from },
                        state: CandState::Answered,
                        token,
                    },
                );
            }
        }
        let mut found = parse_compact_nodes(r.bytes_at("nodes").unwrap_or_default());
        if ipv6 {
            found.extend(parse_compact_nodes6(
                r.bytes_at("nodes6").unwrap_or_default(),
            ));
        }
        for n in found {
            if n.id == self.id || n.addr.port() == 0 {
                continue;
            }
            l.candidates
                .entry(NodeId(target).distance(&n.id.0))
                .or_insert(Candidate {
                    info: n,
                    state: CandState::New,
                    token: None,
                });
        }
        // Keep the candidate set bounded.
        while l.candidates.len() > 8 * K {
            let last = *l.candidates.keys().next_back().unwrap_or(&[0; 20]);
            l.candidates.remove(&last);
        }
        if l.get_peers {
            let mut peers = Vec::new();
            for v in r.get("values").and_then(Value::as_list).unwrap_or_default() {
                if let Some(b) = v.as_bytes() {
                    match b.len() {
                        6 => peers.extend(parse_compact_peers(b, false)),
                        18 => peers.extend(parse_compact_peers(b, true)),
                        _ => {}
                    }
                }
            }
            if !peers.is_empty() {
                l.peers_found += peers.len();
                self.events.push(DhtEvent::Peers {
                    info_hash: InfoHash(target),
                    peers,
                });
            }
        }
        self.advance(lid);
    }

    fn lookup_failed(&mut self, id: u64, addr: SocketAddr) {
        if let Some(l) = self.lookups.get_mut(&id) {
            l.in_flight = l.in_flight.saturating_sub(1);
            for c in l.candidates.values_mut() {
                if c.info.addr == addr && c.state == CandState::Asked {
                    c.state = CandState::Failed;
                }
            }
            self.advance(id);
        }
    }

    /// Times queries out, rotates token secrets, expires stored peers and refreshes the table.
    /// Call about once a second.
    pub fn tick(&mut self) {
        let t = now();
        let expired: Vec<Vec<u8>> = self
            .pending
            .iter()
            .filter(|(_, p)| t.duration_since(p.sent) > QUERY_TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            if let Some(p) = self.pending.remove(&k) {
                self.table_for(&p.to).failed(p.to);
                if let Some(id) = p.lookup {
                    self.lookup_failed(id, p.to);
                }
            }
        }
        if t.duration_since(self.rotated) > TOKEN_ROTATE {
            self.secrets[1] = self.secrets[0];
            crate::rand_fill(&mut self.secrets[0]);
            self.rotated = t;
        }
        for list in self.storage.values_mut() {
            list.retain(|(_, at)| t.duration_since(*at) < PEER_TTL);
        }
        self.storage.retain(|_, l| !l.is_empty());
        let empty = self.table_len() < K && !self.routers.is_empty();
        if t.duration_since(self.refreshed) > REFRESH
            || (empty && t.duration_since(self.refreshed) > Duration::from_secs(30))
        {
            self.refreshed = t;
            let routers = if empty {
                self.routers.clone()
            } else {
                Vec::new()
            };
            let target = self.id.0;
            self.start_lookup(target, false, None, &routers);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory network of nodes on 127.0.0.1:(base + i).
    fn deliver(nodes: &mut [Node], base: u16, rounds: usize) -> Vec<Vec<DhtEvent>> {
        deliver_at(nodes, base, rounds, |p| {
            SocketAddr::from(([127, 0, 0, 1], p))
        })
    }

    /// The same on any address family: node `i` is at `at(base + i)`.
    fn deliver_at(
        nodes: &mut [Node],
        base: u16,
        rounds: usize,
        at: impl Fn(u16) -> SocketAddr,
    ) -> Vec<Vec<DhtEvent>> {
        let mut events = vec![Vec::new(); nodes.len()];
        for _ in 0..rounds {
            let mut moved = false;
            let mut batch = Vec::new();
            for (i, n) in nodes.iter_mut().enumerate() {
                for (to, b) in n.take_outgoing() {
                    batch.push((i, to, b));
                }
            }
            for (from, to, b) in batch {
                let j = usize::from(to.port() - base);
                if j < nodes.len() {
                    moved = true;
                    let from = at(base + from as u16);
                    assert!(nodes[j].handle(from, &b));
                }
            }
            for (i, n) in nodes.iter_mut().enumerate() {
                events[i].extend(n.take_events());
            }
            if !moved {
                break;
            }
        }
        events
    }

    #[test]
    fn krpc_codec() {
        let q = Msg::Query {
            t: b"aa".to_vec(),
            q: "ping".into(),
            a: Value::dict().with("id", vec![1u8; 20]),
            ro: true,
        };
        assert_eq!(Msg::parse(&q.encode()), Some(q));
        let e = Msg::Error {
            t: b"x".to_vec(),
            code: 201,
            msg: "generic".into(),
        };
        assert_eq!(Msg::parse(&e.encode()), Some(e));
        assert_eq!(Msg::parse(b"d1:y1:qe"), None);
        let n = vec![NodeInfo {
            id: NodeId([3; 20]),
            addr: "1.2.3.4:5".parse().unwrap(),
        }];
        assert_eq!(parse_compact_nodes(&compact_nodes(&n)), n);
    }

    #[test]
    fn network_bootstrap_announce_get_peers() {
        let base = 40000;
        let mut nodes: Vec<Node> = (0..40).map(|_| Node::new(NodeId::random())).collect();
        let router = SocketAddr::from(([127, 0, 0, 1], base));
        for n in nodes.iter_mut().skip(1) {
            n.bootstrap(&[router]);
        }
        deliver(&mut nodes, base, 200);
        // A second round so later nodes learn of each other.
        for n in nodes.iter_mut().skip(1) {
            n.bootstrap(&[]);
        }
        deliver(&mut nodes, base, 200);
        assert!(
            nodes.iter().skip(1).all(|n| n.table_len() >= 5),
            "{:?}",
            nodes.iter().map(Node::table_len).collect::<Vec<_>>()
        );
        let ih = InfoHash::of(b"some torrent");
        nodes[7].get_peers(ih, Some(6881));
        let ev = deliver(&mut nodes, base, 200);
        let announced = ev[7].iter().find_map(|e| match e {
            DhtEvent::LookupDone { announced, .. } => Some(*announced),
            _ => None,
        });
        assert!(announced.unwrap_or(0) >= 3, "{:?}", ev[7]);
        // Another node finds the announced peer (node 7's address, port 6881).
        nodes[23].get_peers(ih, None);
        let ev = deliver(&mut nodes, base, 200);
        let found: Vec<SocketAddr> = ev[23]
            .iter()
            .filter_map(|e| match e {
                DhtEvent::Peers { peers, .. } => Some(peers.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            found.contains(&SocketAddr::from(([127, 0, 0, 1], 6881))),
            "{:?}",
            ev[23]
        );
    }

    #[test]
    fn ipv6_network() {
        let base = 41000;
        let v6 = |p: u16| SocketAddr::from((Ipv6Addr::LOCALHOST, p));
        let mut nodes: Vec<Node> = (0..20)
            .map(|_| {
                let mut n = Node::new(NodeId::random());
                n.set_ipv6(true);
                n
            })
            .collect();
        for n in nodes.iter_mut().skip(1) {
            n.bootstrap(&[v6(base)]);
        }
        deliver_at(&mut nodes, base, 200, v6);
        for n in nodes.iter_mut().skip(1) {
            n.bootstrap(&[]);
        }
        deliver_at(&mut nodes, base, 200, v6);
        assert!(
            nodes
                .iter()
                .skip(1)
                .all(|n| n.table6_len() >= 5 && n.table_len() == n.table6_len())
        );
        let ih = InfoHash::of(b"v6 torrent");
        nodes[3].get_peers(ih, Some(6881));
        deliver_at(&mut nodes, base, 200, v6);
        nodes[11].get_peers(ih, None);
        let ev = deliver_at(&mut nodes, base, 200, v6);
        let found: Vec<SocketAddr> = ev[11]
            .iter()
            .filter_map(|e| match e {
                DhtEvent::Peers { peers, .. } => Some(peers.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(found.contains(&v6(6881)), "{:?}", ev[11]);
        let n6 = vec![NodeInfo {
            id: NodeId([4; 20]),
            addr: v6(9),
        }];
        assert_eq!(parse_compact_nodes6(&compact_nodes6(&n6)), n6);
    }

    #[test]
    fn want_and_families() {
        let mut n = Node::new(NodeId::random());
        n.set_ipv6(true);
        let a4: SocketAddr = "10.0.0.2:1000".parse().unwrap();
        let a6: SocketAddr = "[2001:db8::2]:1000".parse().unwrap();
        // Fill both tables through answered pings.
        for (i, a) in [a4, a6].into_iter().enumerate() {
            n.ping(a);
            let (_, q) = n.take_outgoing().pop().unwrap();
            let Some(Msg::Query { t, .. }) = Msg::parse(&q) else {
                panic!()
            };
            let r = Msg::Response {
                t,
                r: Value::dict().with("id", vec![i as u8 + 1; 20]),
            };
            n.handle(a, &r.encode());
        }
        assert_eq!((n.table_len(), n.table6_len()), (2, 1));
        let ask = |n: &mut Node, from: SocketAddr, want: Option<Vec<&str>>| {
            let mut a = Value::dict()
                .with("id", vec![9u8; 20])
                .with("target", vec![0u8; 20]);
            if let Some(w) = want {
                a.insert("want", w.into_iter().map(Value::from).collect::<Vec<_>>());
            }
            let q = Msg::Query {
                t: b"x".to_vec(),
                q: "find_node".into(),
                a,
                ro: true,
            };
            n.handle(from, &q.encode());
            let out = n.take_outgoing();
            let Some(Msg::Response { r, .. }) = Msg::parse(&out[0].1) else {
                panic!()
            };
            (
                r.bytes_at("nodes").map(<[u8]>::len),
                r.bytes_at("nodes6").map(<[u8]>::len),
            )
        };
        assert_eq!(ask(&mut n, a4, None), (Some(26), None));
        assert_eq!(ask(&mut n, a6, None), (None, Some(38)));
        assert_eq!(
            ask(&mut n, a4, Some(vec!["n4", "n6"])),
            (Some(26), Some(38))
        );
    }

    #[test]
    fn bad_token_and_unknown_method() {
        let mut n = Node::new(NodeId::random());
        let from: SocketAddr = "10.0.0.2:1000".parse().unwrap();
        let q = Msg::Query {
            ro: false,
            t: b"t1".to_vec(),
            q: "announce_peer".into(),
            a: Value::dict()
                .with("id", vec![1u8; 20])
                .with("info_hash", vec![2u8; 20])
                .with("port", 5)
                .with("token", "nope"),
        };
        assert!(n.handle(from, &q.encode()));
        let out = n.take_outgoing();
        assert!(matches!(
            Msg::parse(&out[0].1),
            Some(Msg::Error { code: 203, .. })
        ));
        let q = Msg::Query {
            t: b"t2".to_vec(),
            q: "vote".into(),
            a: Value::dict().with("id", vec![1u8; 20]),
            ro: true,
        };
        n.handle(from, &q.encode());
        assert!(matches!(
            Msg::parse(&n.take_outgoing()[0].1),
            Some(Msg::Error { code: 204, .. })
        ));
        assert!(!n.handle(from, b"not krpc"));
    }
}
