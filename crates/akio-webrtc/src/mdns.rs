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
//! Both families run on every interface (`getifaddrs`, read when resolving starts): IPv6
//! joins `ff02::fb` on each interface with a link-local address, IPv4 joins `224.0.0.251` on
//! each multicast-capable interface with an IPv4 address (loopback aside; the default
//! interface when there is none). A query goes to the group on each of them (IPv6 names the
//! link in the destination's scope id, IPv4 in an `IP_PKTINFO` control message), an answer
//! goes back to the interface its query came from (the source's scope id, else the interface
//! whose subnet holds the source), and a link-local address resolved from an answer is
//! reached through the interface the answer came from (the endpoint keeps that scope id for
//! the address: SDP carries none). Either family's answers may carry `A` and `AAAA` records; a
//! name resolves to the addresses of both.
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
//! peers made after. Each address is probed, announced and answered on the interface that
//! holds it only, over both families (§6.2: an address record is of no use on another link; a
//! link-local IPv6 address's interface is its scope id). Loopback addresses, addresses on no
//! interface the endpoint knows, and queries from a source on no known subnet keep the old
//! behaviour: every link. Closing the endpoint sends goodbyes (§10.1, TTL 0) for its names.
//! Every
//! response leaves with TTL / hop limit 255 (§11), unicast ones included.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Engine, Handler, UdpBinding};
use akio_ice::mdns::{self, Message, Question, Record};
use akio_sys::Interface;

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
    /// Our names whose address is on a known interface, and that interface (the scope id of a
    /// link-local IPv6 address, else the interface holding the address): probed, announced and
    /// answered on that link only (RFC 6762 §6.2).
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

/// The interfaces that are up and have an IPv6 link-local address (their indexes, the scope
/// ids): where `ff02::fb` is joined. Sorted, at most 64.
pub(crate) fn ipv6_interfaces(all: &[Interface]) -> Vec<u32> {
    all.iter()
        .filter(|i| i.flags.is_up() && i.index != 0)
        .filter(|i| {
            i.addrs
                .iter()
                .any(|a| matches!(a.ip, IpAddr::V6(ip) if is_link_local(&ip)))
        })
        .map(|i| i.index)
        .take(64)
        .collect()
}

/// The interfaces that are up, multicast-capable, not loopback (a scoped multicast send on
/// macOS's `lo0` is refused; this host's own listeners get the copies looped back from the
/// others) and have an IPv4 address: where `224.0.0.251` is joined and sent to. Sorted, at
/// most 20 (Linux's default limit of IPv4 memberships per socket).
pub(crate) fn ipv4_interfaces(all: &[Interface]) -> Vec<u32> {
    all.iter()
        .filter(|i| i.flags.is_up() && i.flags.is_multicast() && !i.flags.is_loopback())
        .filter(|i| i.index != 0 && i.ipv4().is_some())
        .map(|i| i.index)
        .take(20)
        .collect()
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
    /// The interfaces the IPv4 socket joined `224.0.0.251` on and sends on (empty: the
    /// default one, whose link is not known).
    ifaces_v4: Vec<u32>,
    /// The host's interfaces and addresses: which link an address of ours is on, and which a
    /// query came from (re-read when an address to conceal is on none of them).
    links: Mutex<Vec<Interface>>,
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
        let links = akio_sys::interfaces().unwrap_or_else(|e| {
            akio_log::debug!(target: "akio_webrtc", "mdns: no interface list ({e}); default interfaces, records on every link");
            Vec::new()
        });
        let ifaces_v4 = ipv4_interfaces(&links);
        let m = Arc::new_cyclic(|me| Mdns {
            me: me.clone(),
            hub: Arc::downgrade(hub),
            socks: OnceLock::new(),
            ifaces: ipv6_interfaces(&links),
            ifaces_v4,
            links: Mutex::new(links),
            timeout,
            state: Mutex::new(State::default()),
        });
        let bind = |v6: bool| -> std::io::Result<Sock> {
            let acc = || MdnsAcceptor(m.me.clone(), v6);
            // Each family joins its interfaces (else the default one).
            let list = if v6 { &m.ifaces } else { &m.ifaces_v4 };
            let ifaces: &[u32] = if list.is_empty() { &[0] } else { list };
            let joined = engine
                .bind_udp_multicast_on(group(v6, 0), ifaces, acc())
                .or_else(|e| {
                    if ifaces == [0] {
                        return Err(e);
                    }
                    akio_log::debug!(target: "akio_webrtc", "mdns: IPv{} group refused on {ifaces:?} ({e}); default interface", if v6 { 6 } else { 4 });
                    engine.bind_udp_multicast_on(group(v6, 0), &[0], acc())
                });
            match joined {
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

    /// Sends `packet` to the mDNS group over each socket on the shared port, on every link
    /// queries go out on, or only on `link` (a record of an address on that interface, which
    /// is of no use on another link: RFC 6762 §6.2).
    fn send_all(&self, packet: &[u8], link: Option<u32>) {
        for s in self.socks().iter().filter(|s| s.shared) {
            for (dest, via) in self.dests(s.v6, link) {
                let _ = s.binding.send_to_on(packet, dest, via);
            }
        }
    }

    /// Where a multicast message of family `v6` goes: the group on every link (`link` `None`)
    /// or on `link` only, with the interface to send it out of (0: named by the destination's
    /// scope id, or the default one).
    fn dests(&self, v6: bool, link: Option<u32>) -> Vec<(SocketAddr, u32)> {
        if v6 {
            let scopes = link.map_or_else(|| self.scopes(), |l| vec![l]);
            return scopes.into_iter().map(|i| (group(true, i), 0)).collect();
        }
        match link {
            // Joined on the default interface only: its link is not known.
            _ if self.ifaces_v4.is_empty() => match link {
                None => vec![(mdns::MULTICAST_V4, 0)],
                Some(_) => Vec::new(),
            },
            None => self
                .ifaces_v4
                .iter()
                .map(|&i| (mdns::MULTICAST_V4, i))
                .collect(),
            Some(l) if self.ifaces_v4.contains(&l) => vec![(mdns::MULTICAST_V4, l)],
            Some(_) => Vec::new(),
        }
    }

    /// The interface our address `addr` is on: a link-local IPv6 address's scope id, else the
    /// interface that holds it (the list is re-read once if none does). `None` for loopback
    /// addresses (of use to this host's own queriers, which may ask on any link) and addresses
    /// on no interface.
    fn link_of_own(&self, addr: SocketAddr) -> Option<u32> {
        let ip = addr.ip();
        if let SocketAddr::V6(a) = addr {
            if is_link_local(a.ip()) {
                return (a.scope_id() != 0).then_some(a.scope_id());
            }
        }
        if ip.is_loopback() || ip.is_unspecified() {
            return None;
        }
        let find = |all: &[Interface]| {
            all.iter()
                .find(|i| i.index != 0 && !i.flags.is_loopback() && i.has_addr(ip))
                .map(|i| i.index)
        };
        let known = find(&lock(&self.links));
        if known.is_some() {
            return known;
        }
        let all = akio_sys::interfaces().ok()?;
        let i = find(&all);
        *lock(&self.links) = all;
        i
    }

    /// Whether our address `ip`, on interface `l`, is of use to a querier on interface `f`
    /// (RFC 6762 §6.2): the same interface, or, unless `ip` is IPv6 link-local (whose link is
    /// its scope id), an interface with a subnet that holds `ip`: two interfaces on one link
    /// with the same prefix (two NICs on one LAN, the two ends of a veth pair). Without a
    /// scope id the interface a query arrived on is inferred from its source, which on such a
    /// link may name the other one.
    fn usable_on(&self, ip: IpAddr, l: u32, f: u32) -> bool {
        if l == f {
            return true;
        }
        if matches!(ip, IpAddr::V6(v6) if is_link_local(&v6)) {
            return false;
        }
        lock(&self.links)
            .iter()
            .any(|i| i.index == f && i.contains(ip))
    }

    /// The interface a datagram from `src` came from: its scope id, else the interface that
    /// holds the address or whose subnet does (the longest prefix). `None` when unknown, or a
    /// loopback source.
    fn link_of_src(&self, src: SocketAddr) -> Option<u32> {
        if let SocketAddr::V6(a) = src {
            if a.scope_id() != 0 {
                return Some(a.scope_id());
            }
        }
        let ip = src.ip();
        if ip.is_loopback() {
            return None;
        }
        let all = lock(&self.links);
        let usable = || {
            all.iter()
                .filter(|i| i.index != 0 && !i.flags.is_loopback())
        };
        if let Some(i) = usable().find(|i| i.has_addr(ip)) {
            return Some(i.index);
        }
        usable()
            .flat_map(|i| i.addrs.iter().map(move |a| (i.index, a)))
            .filter(|(_, a)| a.contains(ip))
            .max_by_key(|(_, a)| a.prefix_len)
            .map(|(i, _)| i)
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

    /// The name concealing local address `addr` (made on first use, with the interface it is
    /// claimed and answered on: see [`link_of_own`](Self::link_of_own)); `None` past
    /// [`MAX_OWN`] addresses.
    pub(crate) fn name_for(&self, addr: SocketAddr) -> Option<String> {
        let ip = addr.ip();
        if let Some(n) = lock(&self.state).own.get(&ip) {
            return Some(n.clone());
        }
        let link = self.link_of_own(addr);
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
        if let Some(l) = link {
            st.link.insert(n.clone(), l);
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
        for s in self.socks() {
            let dests = self.dests(s.v6, None);
            for n in names {
                // Over the shared port, a multicast query; otherwise a legacy unicast one (the
                // QU bit is set too, which the RFC asks of one-shot queriers on another port).
                // One question per message (Chromium's responder ignores several).
                for t in [mdns::TYPE_A, mdns::TYPE_AAAA] {
                    if let Some(q) = Message::query(n, t, !s.shared) {
                        for &(d, via) in &dests {
                            let _ = s.binding.send_to_on(&q, d, via);
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
        let from = self.link_of_src(src);
        akio_log::trace!(target: "akio_webrtc", "mdns: query from {src} (interface {from:?})");
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
                // An address is answered on the link of its interface only (§6.2): a query
                // from another link is not answered with it (from an unknown one, it is).
                // (`usable_on` takes the interface list's lock inside the state lock; nothing
                // takes them the other way round.)
                if let (Some(&l), Some(f)) = (st.link.get(&q.name), from) {
                    if !self.usable_on(ip, l, f) {
                        akio_log::debug!(target: "akio_webrtc", "mdns: {} not answered to {src}: {ip} is on interface {l}, the query came from {f}", q.name);
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
        let reply = Message::response(0, &[], &answers);
        if unicast {
            let _ = b.send_to(&reply, src);
            return;
        }
        // Multicast answers go to the group on the link the query came from (IPv6: in the
        // scope id; IPv4: out of that interface, when it is one the group was joined on).
        let (dest, via) = match (src, from) {
            (SocketAddr::V6(_), f) => (group(true, f.unwrap_or(0)), 0),
            (SocketAddr::V4(_), Some(f)) if self.ifaces_v4.contains(&f) => (mdns::MULTICAST_V4, f),
            (SocketAddr::V4(_), _) => (mdns::MULTICAST_V4, 0),
        };
        let _ = b.send_to_on(&reply, dest, via);
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
