//! mDNS for ICE candidates (RFC 6762, draft-ietf-mmusic-mdns-ice-candidates): resolving the
//! `.local` names browsers write instead of their host addresses, and answering queries for
//! the names an [`Endpoint`](crate::Endpoint) conceals its own host addresses behind.
//!
//! One socket per address family and endpoint, served by an engine I/O thread (nothing here
//! blocks): normally the shared mDNS port (`0.0.0.0:5353` member of `224.0.0.251`, and
//! `[::]:5353` member of `ff02::fb`, with `SO_REUSEADDR`/`SO_REUSEPORT`, next to the system's
//! responder), where queries go to the group and the answers come back by multicast; if that
//! port cannot be bound, an ephemeral port, from which queries are "legacy unicast" one-shot
//! queries (RFC 6762 §6.7: responders answer to the source port) and nothing can be concealed
//! over that family (names are still answered over the other one: an IPv6-only link, where
//! `224.0.0.251` has no route, conceals over `ff02::fb`). A host without IPv6 runs IPv4 only.
//!
//! IPv6 multicast is link-scoped: a query goes to `ff02::fb` on each interface the endpoint
//! knows (the scope ids of its link-local IPv6 host candidates, and the default multicast
//! interface), an answer goes back to the interface its query came from, and a link-local
//! address resolved from an answer is reached through the interface the answer came from
//! (the endpoint keeps that scope id for the address: SDP carries none). Either family's
//! answers may carry `A` and `AAAA` records; a name resolves to the addresses of both.
//!
//! A name being resolved is queried at once, again after 1 and 2 seconds, then every 2
//! seconds until the timeout; answers, solicited or not (browsers announce their names), are
//! cached for their TTL (at most 2 minutes, 256 names). When it
//! resolves, each waiting peer gets the candidate line with the address (one candidate per
//! address family the name has), unless that peer's remote ICE credentials changed meanwhile.
//!
//! A concealed name is claimed as RFC 6762 §8 asks of unique records, without holding up the
//! candidate (the name is a random UUID, used in descriptions at once and answered from the
//! start): after a random 0-250 ms, three probes 250 ms apart (§8.1: `ANY` with the QU bit,
//! the proposed record in the authority section), then two announcements 1 s apart (§8.3, unsolicited responses with the
//! cache-flush bit). A conflict (another host answers the name with another address, or
//! probes it with a record that wins the §8.2 tiebreak while ours is still being probed)
//! gives the name up: it is no longer answered and the address gets a fresh name for the
//! peers made after. A link-local IPv6 address is probed, announced and answered on its own
//! link only (§6.2: it is of no use on another; other addresses go out on every link, and
//! IPv4 has the default interface only). Closing the endpoint sends goodbyes (§10.1, TTL 0)
//! for its names. Every
//! response leaves with TTL / hop limit 255 (§11), unicast ones included.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Engine, Handler, UdpBinding};
use akio_ice::mdns::{self, Message, Question, Record};

use crate::{Hub, lock, timer};

/// Names being resolved at once (more are dropped).
const MAX_QUERIES: usize = 64;
/// Peers waiting on one name.
const MAX_WAITERS: usize = 16;
/// Cached answers.
const MAX_CACHE: usize = 256;
/// Concealed local addresses.
const MAX_OWN: usize = 32;
/// Longest a cached answer is kept.
const MAX_TTL: Duration = Duration::from_secs(120);
/// TTL of our answers (RFC 6762 §10: 120 s for host address records), and of legacy
/// unicast ones (§6.7: at most 10 s).
const OWN_TTL: u32 = 120;
const LEGACY_TTL: u32 = 10;
/// Probes per claimed name and their spacing (RFC 6762 §8.1), then announcements and their
/// spacing (§8.3).
const PROBES: u32 = 3;
const PROBE_GAP: Duration = Duration::from_millis(250);
const ANNOUNCEMENTS: u32 = 2;
const ANNOUNCE_GAP: Duration = Duration::from_secs(1);

/// A concealed name being claimed: probes and announcements sent so far, the next one due.
struct Claim {
    sends: u32,
    next: Instant,
}

struct Waiter {
    peer: u64,
    /// The remote ufrag when the candidate arrived.
    ufrag: String,
    /// The candidate line with the name.
    line: String,
}

struct Query {
    waiters: Vec<Waiter>,
    deadline: Instant,
    next: Instant,
    sends: u32,
}

#[derive(Default)]
struct State {
    queries: HashMap<String, Query>,
    cache: HashMap<String, (Vec<IpAddr>, Instant)>,
    /// Our concealed names: address -> name, and back.
    own: HashMap<IpAddr, String>,
    own_names: HashMap<String, IpAddr>,
    /// Our names for link-local IPv6 addresses, and the link (scope id) each is on: probed,
    /// announced and answered on that link only (RFC 6762 §6.2).
    link: HashMap<String, u32>,
    /// Our names still being probed or announced.
    claims: HashMap<String, Claim>,
    /// The earliest timer armed.
    armed: Option<Instant>,
}

/// The group of `v6`'s family on interface `scope` (IPv4 has no scope).
fn group(v6: bool, scope: u32) -> SocketAddr {
    if v6 {
        mdns::multicast_v6_on(scope)
    } else {
        mdns::MULTICAST_V4
    }
}

/// Whether `ip` is an IPv6 link-local unicast address (`fe80::/10`), which needs a scope id.
pub(crate) fn is_link_local(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// The interfaces with an IPv6 link-local address (their indexes, the scope ids): on Linux
/// from `/proc/net/if_inet6`, elsewhere by asking the kernel for a route to `ff02::fb` on
/// each of the first indexes (a UDP connect, nothing sent). Sorted, at most 64.
pub(crate) fn ipv6_interfaces() -> Vec<u32> {
    const MAX: usize = 64;
    let mut out = Vec::new();
    if let Ok(t) = std::fs::read_to_string("/proc/net/if_inet6") {
        // `<addr hex> <ifindex hex> <prefix> <scope hex> <flags> <name>`; scope 0x20: link.
        for l in t.lines() {
            let f: Vec<&str> = l.split_ascii_whitespace().collect();
            if f.len() >= 6 && f[3] == "20" {
                if let Ok(i) = u32::from_str_radix(f[1], 16) {
                    if !out.contains(&i) && out.len() < MAX {
                        out.push(i);
                    }
                }
            }
        }
    } else {
        for i in 1..=MAX as u32 {
            let Ok(s) = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
                break;
            };
            let up = s.connect(group(true, i)).is_ok()
                && matches!(s.local_addr(), Ok(SocketAddr::V6(a)) if is_link_local(a.ip()));
            if up {
                out.push(i);
            }
        }
    }
    out.sort_unstable();
    out
}

/// One mDNS socket.
struct Sock {
    binding: UdpBinding,
    v6: bool,
    /// Bound to the shared mDNS port (multicast); else an ephemeral port (legacy unicast).
    shared: bool,
}

pub(crate) struct Mdns {
    me: Weak<Mdns>,
    hub: Weak<Hub>,
    /// The IPv4 socket, then the IPv6 one when the host has IPv6.
    socks: OnceLock<Vec<Sock>>,
    /// The interfaces the IPv6 socket joined `ff02::fb` on (empty: the default one).
    ifaces: Vec<u32>,
    timeout: Duration,
    state: Mutex<State>,
}

struct MdnsAcceptor(Weak<Mdns>, bool);

impl Acceptor for MdnsAcceptor {
    type Handler = MdnsUdp;
    fn on_open(&self, _c: &Conn<MdnsUdp>) -> MdnsUdp {
        MdnsUdp(self.0.clone(), self.1)
    }
}

/// An mDNS socket's handler (and whether it is the IPv6 one).
pub(crate) struct MdnsUdp(Weak<Mdns>, bool);

impl std::fmt::Debug for MdnsUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsUdp")
            .field("v6", &self.1)
            .finish_non_exhaustive()
    }
}

impl Handler for MdnsUdp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let src = c.peer_addr();
        // The dual-stack IPv6 socket may also see IPv4 datagrams (as mapped addresses): the
        // IPv4 socket has them.
        if self.1 && matches!(src, SocketAddr::V6(a) if a.ip().to_ipv4_mapped().is_some()) {
            return;
        }
        if let Some(m) = self.0.upgrade() {
            m.on_datagram(src, data);
        }
    }
}

impl Mdns {
    /// Binds the mDNS sockets on `engine`: IPv4 (the shared port, else an ephemeral one),
    /// then IPv6 the same way when the host has IPv6 (its failure is not an error), member
    /// of `ff02::fb` on every interface with a link-local address.
    pub(crate) fn new(
        hub: &Arc<Hub>,
        engine: &Engine,
        timeout: Duration,
    ) -> std::io::Result<Arc<Mdns>> {
        let m = Arc::new_cyclic(|me| Mdns {
            me: me.clone(),
            hub: Arc::downgrade(hub),
            socks: OnceLock::new(),
            ifaces: ipv6_interfaces(),
            timeout,
            state: Mutex::new(State::default()),
        });
        let bind = |v6: bool| -> std::io::Result<Sock> {
            let acc = || MdnsAcceptor(m.me.clone(), v6);
            // IPv4 joins the default interface; IPv6 every link-local one (else the default).
            let ifaces: &[u32] = if v6 && !m.ifaces.is_empty() {
                &m.ifaces
            } else {
                &[0]
            };
            match engine.bind_udp_multicast_on(group(v6, 0), ifaces, acc()) {
                Ok(binding) => {
                    // Unicast answers (QU, legacy unicast) leave with 255 too, as multicast
                    // ones do (RFC 6762 §11).
                    if let Err(e) = binding.set_unicast_hops(255) {
                        akio_log::debug!(target: "akio_webrtc", "mdns: unicast hop limit 255 refused over IPv{} ({e})", if v6 { 6 } else { 4 });
                    }
                    Ok(Sock {
                        binding,
                        v6,
                        shared: true,
                    })
                }
                Err(e) => {
                    akio_log::debug!(target: "akio_webrtc", "mdns: port {} unavailable over IPv{} ({e}); one-shot unicast queries", mdns::PORT, if v6 { 6 } else { 4 });
                    let any: IpAddr = if v6 {
                        Ipv6Addr::UNSPECIFIED.into()
                    } else {
                        Ipv4Addr::UNSPECIFIED.into()
                    };
                    Ok(Sock {
                        binding: engine.bind_udp(SocketAddr::new(any, 0), acc())?,
                        v6,
                        shared: false,
                    })
                }
            }
        };
        let mut socks = vec![bind(false)?];
        match bind(true) {
            Ok(s) => socks.push(s),
            Err(e) => akio_log::debug!(target: "akio_webrtc", "mdns: no IPv6 ({e}); IPv4 only"),
        }
        let _ = m.socks.set(socks);
        Ok(m)
    }

    fn socks(&self) -> &[Sock] {
        self.socks.get().map_or(&[], Vec::as_slice)
    }

    /// Whether names can be answered: a socket of either family is on the shared mDNS port
    /// (on an IPv6-only link the IPv4 one is not, and answers go over IPv6 only).
    pub(crate) fn can_respond(&self) -> bool {
        self.socks().iter().any(|s| s.shared)
    }

    /// Sends goodbyes for our names (RFC 6762 §10.1), then closes the sockets.
    pub(crate) fn close(&self) {
        let names: Vec<(String, IpAddr, Option<u32>)> = {
            let mut st = lock(&self.state);
            st.claims.clear();
            let link = std::mem::take(&mut st.link);
            st.own_names
                .drain()
                .map(|(n, ip)| {
                    let l = link.get(&n).copied();
                    (n, ip, l)
                })
                .collect()
        };
        for (name, ip, link) in names {
            let r = own_record(&name, ip, 0, false);
            self.send_all(&Message::response(0, &[], &[r]), link);
        }
        for s in self.socks() {
            s.binding.close();
        }
    }

    /// Sends `packet` to the mDNS group over each socket on the shared port (IPv6: on every
    /// link queries go out on), or only to `ff02::fb` on `link` (a record of a link-local
    /// IPv6 address, which is of no use on another link: RFC 6762 §6.2).
    fn send_all(&self, packet: &[u8], link: Option<u32>) {
        let scopes = match link {
            Some(l) => vec![l],
            None if self.socks().iter().any(|s| s.v6 && s.shared) => self.scopes(),
            None => Vec::new(),
        };
        for s in self
            .socks()
            .iter()
            .filter(|s| s.shared && (s.v6 || link.is_none()))
        {
            if s.v6 {
                for &i in &scopes {
                    let _ = s.binding.send_to(packet, group(true, i));
                }
            } else {
                let _ = s.binding.send_to(packet, mdns::MULTICAST_V4);
            }
        }
    }

    /// Gives up our name `name` after a conflict: no longer answered, no longer claimed, and
    /// its address gets a fresh name next time.
    fn give_up(st: &mut State, name: &str, why: &str) {
        if let Some(ip) = st.own_names.remove(name) {
            st.own.remove(&ip);
            st.claims.remove(name);
            st.link.remove(name);
            akio_log::warn!(target: "akio_webrtc", "mdns: {name} given up ({why}); {ip} gets a new name for new peers");
        }
    }

    /// The interfaces IPv6 queries go out on: those the group was joined on (or the default
    /// one, 0) and those of the endpoint's link-local IPv6 host candidates.
    fn scopes(&self) -> Vec<u32> {
        let mut out = if self.ifaces.is_empty() {
            vec![0]
        } else {
            self.ifaces.clone()
        };
        if let Some(hub) = self.hub.upgrade() {
            for c in lock(&hub.candidates).iter() {
                if let SocketAddr::V6(a) = c.addr() {
                    if a.scope_id() != 0 && !out.contains(&a.scope_id()) {
                        out.push(a.scope_id());
                    }
                }
            }
        }
        out
    }

    /// The name concealing local address `addr` (made on first use; a link-local IPv6
    /// address keeps its scope id: the link it is claimed and answered on); `None` past
    /// [`MAX_OWN`] addresses.
    pub(crate) fn name_for(&self, addr: SocketAddr) -> Option<String> {
        let ip = addr.ip();
        let mut st = lock(&self.state);
        if let Some(n) = st.own.get(&ip) {
            return Some(n.clone());
        }
        if st.own.len() >= MAX_OWN {
            return None;
        }
        let n = mdns::random_name();
        st.own.insert(ip, n.clone());
        st.own_names.insert(n.clone(), ip);
        if let SocketAddr::V6(a) = addr {
            if is_link_local(a.ip()) && a.scope_id() != 0 {
                st.link.insert(n.clone(), a.scope_id());
            }
        }
        if !self.can_respond() {
            return Some(n);
        }
        // §8.1: the first probe after a random 0-250 ms, so hosts starting together do not
        // probe in lock step.
        let now = Instant::now();
        st.claims.insert(
            n.clone(),
            Claim {
                sends: 0,
                next: now + probe_delay(),
            },
        );
        drop(st);
        self.tick(now);
        Some(n)
    }

    /// Resolves `name` for peer `peer` (whose remote ufrag is `ufrag`): the peer gets the
    /// candidate `line` with the address once it is known.
    pub(crate) fn resolve(&self, peer: u64, ufrag: &str, name: String, line: String) {
        let now = Instant::now();
        let w = Waiter {
            peer,
            ufrag: ufrag.to_owned(),
            line,
        };
        let cached = {
            let mut st = lock(&self.state);
            st.cache.retain(|_, (_, exp)| *exp > now);
            if let Some((ips, _)) = st.cache.get(&name) {
                akio_log::debug!(target: "akio_webrtc", "mdns: {name} is {ips:?} (cached)");
                Some((ips.clone(), w))
            } else if let Some(q) = st.queries.get_mut(&name) {
                if q.waiters.len() < MAX_WAITERS {
                    q.waiters.push(w);
                }
                return;
            } else {
                if st.queries.len() >= MAX_QUERIES {
                    akio_log::debug!(target: "akio_webrtc", "mdns: too many names being resolved, {name} dropped");
                    return;
                }
                st.queries.insert(
                    name.clone(),
                    Query {
                        waiters: vec![w],
                        deadline: now + self.timeout,
                        next: now,
                        sends: 0,
                    },
                );
                None
            }
        };
        match cached {
            Some((ips, w)) => {
                if let Some(hub) = self.hub.upgrade() {
                    deliver(&hub, &ips, vec![(name, w)]);
                }
            }
            None => self.tick(now),
        }
    }

    /// Sends the queries, probes and announcements that are due, drops the expired queries,
    /// arms the timer.
    fn tick(&self, now: Instant) {
        let mut send = Vec::new();
        let mut claims = Vec::new();
        let next = {
            let mut st = lock(&self.state);
            let State {
                claims: c,
                own_names,
                link,
                ..
            } = &mut *st;
            c.retain(|name, cl| {
                let Some(&ip) = own_names.get(name) else {
                    return false;
                };
                if cl.next > now {
                    return true;
                }
                let l = link.get(name).copied();
                claims.push((name.clone(), ip, l, cl.sends < PROBES));
                cl.sends += 1;
                // §8.1: the claim is won 250 ms after the last probe, then announced.
                cl.next = now
                    + if cl.sends <= PROBES {
                        PROBE_GAP
                    } else {
                        ANNOUNCE_GAP
                    };
                cl.sends < PROBES + ANNOUNCEMENTS
            });
            st.queries.retain(|name, q| {
                if q.deadline <= now {
                    akio_log::debug!(target: "akio_webrtc", "mdns: {name} not resolved in time");
                    return false;
                }
                if q.next <= now {
                    send.push(name.clone());
                    q.sends += 1;
                    let gap = Duration::from_secs(u64::from(q.sends.min(2)));
                    q.next = now + gap;
                }
                true
            });
            let next = st
                .queries
                .values()
                .map(|q| q.next.min(q.deadline))
                .chain(st.claims.values().map(|c| c.next))
                .min();
            match next {
                Some(n) if st.armed.is_none_or(|a| n < a) => {
                    st.armed = Some(n);
                    Some(n)
                }
                _ => None,
            }
        };
        self.send_queries(&send);
        for (name, ip, link, probe) in claims {
            if probe {
                if let Some(p) = Message::probe(&name, &[own_record(&name, ip, OWN_TTL, false)]) {
                    self.send_all(&p, link);
                }
            } else {
                let r = own_record(&name, ip, OWN_TTL, true);
                self.send_all(&Message::response(0, &[], &[r]), link);
            }
        }
        if let Some(n) = next {
            let target: Weak<dyn timer::Due> = self.me.clone();
            timer::timer().schedule(n, target);
        }
    }

    fn send_queries(&self, names: &[String]) {
        let scopes = if self.socks().iter().any(|s| s.v6) {
            self.scopes()
        } else {
            Vec::new()
        };
        for s in self.socks() {
            let dests: Vec<SocketAddr> = if s.v6 {
                scopes.iter().map(|&i| group(true, i)).collect()
            } else {
                vec![mdns::MULTICAST_V4]
            };
            for n in names {
                // Over the shared port, a multicast query; otherwise a legacy unicast one (the
                // QU bit is set too, which the RFC asks of one-shot queriers on another port).
                // One question per message (Chromium's responder ignores several).
                for t in [mdns::TYPE_A, mdns::TYPE_AAAA] {
                    if let Some(q) = Message::query(n, t, !s.shared) {
                        for d in &dests {
                            let _ = s.binding.send_to(&q, *d);
                        }
                    }
                }
            }
        }
    }

    fn on_datagram(&self, src: SocketAddr, data: &[u8]) {
        let Ok(m) = Message::parse(data) else { return };
        if m.response {
            // RFC 6762 §6: answers come from the mDNS port (also to legacy unicast queriers).
            if src.port() == mdns::PORT {
                self.on_response(src, &m.records);
            }
        } else if !m.questions.is_empty()
            && self
                .socks()
                .iter()
                .any(|s| s.v6 == src.is_ipv6() && s.shared)
        {
            self.on_query(src, &m);
        }
    }

    fn on_response(&self, src: SocketAddr, records: &[Record]) {
        // Another host answering one of our names with another address is a conflict
        // (RFC 6762 §9); our own answers come back by multicast loopback with our address.
        {
            let mut st = lock(&self.state);
            if !st.own_names.is_empty() {
                let lost: Vec<String> = records
                    .iter()
                    .filter(|r| r.ttl > 0)
                    .filter(|r| st.own_names.get(&r.name).is_some_and(|ip| *ip != r.addr))
                    .map(|r| r.name.clone())
                    .collect();
                for n in lost {
                    Self::give_up(
                        &mut st,
                        &n,
                        &format!("{src} answers it with another address"),
                    );
                }
            }
        }
        // A link-local address is reached through the interface its answer came from.
        if let (SocketAddr::V6(s), Some(hub)) = (src, self.hub.upgrade()) {
            if s.scope_id() != 0 {
                for r in records {
                    if let IpAddr::V6(ip) = r.addr {
                        if is_link_local(&ip) && r.ttl > 0 {
                            hub.learn_scope(ip, s.scope_id());
                        }
                    }
                }
            }
        }
        let now = Instant::now();
        let mut done = Vec::new();
        {
            let mut st = lock(&self.state);
            let mut by_name: HashMap<&str, (Vec<IpAddr>, u32)> = HashMap::new();
            for r in records.iter().filter(|r| r.ttl > 0) {
                let e = by_name.entry(&r.name).or_insert((Vec::new(), r.ttl));
                if !e.0.contains(&r.addr) && e.0.len() < 4 {
                    e.0.push(r.addr);
                }
                e.1 = e.1.min(r.ttl);
            }
            st.cache.retain(|_, (_, exp)| *exp > now);
            for (name, (ips, ttl)) in by_name {
                // Unsolicited answers are cached too: a browser announces its names when it
                // makes them (RFC 6762 §8.3), just before its description arrives, and then
                // does not answer the same record again within a second (§6).
                if !mdns::is_mdns_name(name) {
                    continue;
                }
                if st.cache.len() < MAX_CACHE || st.cache.contains_key(name) {
                    let ttl = Duration::from_secs(u64::from(ttl)).min(MAX_TTL);
                    st.cache.insert(name.to_owned(), (ips.clone(), now + ttl));
                }
                let Some(q) = st.queries.remove(name) else {
                    continue;
                };
                akio_log::debug!(target: "akio_webrtc", "mdns: {name} is {ips:?} (from {src})");
                done.push((ips, q.waiters, name.to_owned()));
            }
        }
        let Some(hub) = self.hub.upgrade() else {
            return;
        };
        for (ips, waiters, name) in done {
            let ws = waiters.into_iter().map(|w| (name.clone(), w)).collect();
            deliver(&hub, &ips, ws);
        }
    }

    fn on_query(&self, src: SocketAddr, m: &Message) {
        let (answers, questions) = {
            let mut st = lock(&self.state);
            if st.own_names.is_empty() {
                return;
            }
            let mut answers = Vec::new();
            let mut questions = Vec::new();
            for q in &m.questions {
                let Some(&ip) = st.own_names.get(&q.name) else {
                    continue;
                };
                // A link-local IPv6 address is answered on its own link only (§6.2): a query
                // that arrived over IPv6 on another link is not answered with it (over IPv4 the
                // link is not known, and the answer goes out).
                if let (Some(&l), SocketAddr::V6(a)) = (st.link.get(&q.name), src) {
                    if a.scope_id() != 0 && a.scope_id() != l {
                        continue;
                    }
                }
                // A probe for the name (RFC 6762 §8.2): ours coming back by loopback (or an
                // identical claim) needs no answer; another host's, while ours is still being
                // probed, is a simultaneous probe settled by the tiebreak; after that, it is
                // answered (defended) below.
                let proposed: Vec<&Record> =
                    m.authority.iter().filter(|r| r.name == q.name).collect();
                if !proposed.is_empty() {
                    let mine = own_record(&q.name, ip, OWN_TTL, false);
                    if proposed.iter().all(|r| r.addr == ip) {
                        continue;
                    }
                    let probing = st.claims.get(&q.name).is_some_and(|c| c.sends <= PROBES);
                    if probing {
                        let theirs = proposed
                            .iter()
                            .max_by(|a, b| a.tiebreak(b))
                            .map(|r| mine.tiebreak(r));
                        if theirs == Some(std::cmp::Ordering::Less) {
                            Self::give_up(
                                &mut st,
                                &q.name,
                                &format!("{src} probes it and wins the tiebreak"),
                            );
                        }
                        continue;
                    }
                }
                let fits = match q.qtype {
                    mdns::TYPE_A => ip.is_ipv4(),
                    mdns::TYPE_AAAA => ip.is_ipv6(),
                    mdns::TYPE_ANY => true,
                    _ => false,
                };
                if fits && !answers.iter().any(|r: &Record| r.name == q.name) {
                    answers.push(Record {
                        name: q.name.clone(),
                        addr: ip,
                        ttl: OWN_TTL,
                        cache_flush: true,
                    });
                    questions.push(q.clone());
                }
            }
            (answers, questions)
        };
        if answers.is_empty() {
            return;
        }
        akio_log::debug!(target: "akio_webrtc", "mdns: answering {src} for {}", answers[0].name);
        let Some(b) = self
            .socks()
            .iter()
            .find(|s| s.v6 == src.is_ipv6())
            .map(|s| &s.binding)
        else {
            return;
        };
        if src.port() != mdns::PORT {
            // Legacy unicast (RFC 6762 §6.7): the query's id and questions, no cache flush,
            // a short TTL, to the querier's port.
            let answers: Vec<Record> = answers
                .into_iter()
                .map(|r| Record {
                    ttl: LEGACY_TTL,
                    cache_flush: false,
                    ..r
                })
                .collect();
            let _ = b.send_to(&Message::response(m.id, &questions, &answers), src);
            return;
        }
        let unicast = questions.iter().all(|q: &Question| q.unicast_response);
        // Multicast answers go to the group on the link the query came from.
        let scope = match src {
            SocketAddr::V6(a) => a.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        let dest = if unicast {
            src
        } else {
            group(src.is_ipv6(), scope)
        };
        let _ = b.send_to(&Message::response(0, &[], &answers), dest);
    }
}

impl timer::Due for Mdns {
    fn fire(&self, at: Instant) {
        {
            let mut st = lock(&self.state);
            if st.armed == Some(at) {
                st.armed = None;
            }
        }
        self.tick(Instant::now());
    }
}

/// A random delay of 0 to 250 ms before a name's first probe (RFC 6762 §8.1).
fn probe_delay() -> Duration {
    let mut b = [0u8; 2];
    let _ = akio_sys::fill_random(&mut b);
    Duration::from_millis(u64::from(u16::from_le_bytes(b)) % 251)
}

/// The address record of our name `name` for `ip`.
fn own_record(name: &str, ip: IpAddr, ttl: u32, cache_flush: bool) -> Record {
    Record {
        name: name.to_owned(),
        addr: ip,
        ttl,
        cache_flush,
    }
}

/// Gives each waiting peer its candidate line with the addresses `ips`.
fn deliver(hub: &Hub, ips: &[IpAddr], waiters: Vec<(String, Waiter)>) {
    for (name, w) in waiters {
        let Some(p) = hub.peer(w.peer) else { continue };
        for &ip in ips {
            let c = akio_ice::Candidate::parse_resolved(&w.line, |n| (n == name).then_some(ip));
            if let Ok(c) = c {
                let ufrag = w.ufrag.clone();
                let _ = p.with_rtc_inner(|rtc| rtc.add_resolved_candidate(c, &ufrag));
            }
        }
    }
}
