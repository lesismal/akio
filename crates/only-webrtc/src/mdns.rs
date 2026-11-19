//! mDNS for ICE candidates (RFC 6762, draft-ietf-mmusic-mdns-ice-candidates): resolving the
//! `.local` names browsers write instead of their host addresses, and answering queries for
//! the names an [`Endpoint`](crate::Endpoint) conceals its own host addresses behind.
//!
//! One socket per endpoint, served by an engine I/O thread (nothing here blocks): normally
//! the shared mDNS port (`0.0.0.0:5353` with `SO_REUSEADDR`/`SO_REUSEPORT`, member of
//! `224.0.0.251`, next to the system's responder), where queries go to the group and the
//! answers come back by multicast; if that port cannot be bound, an ephemeral port, from which
//! queries are "legacy unicast" one-shot queries (RFC 6762 §6.7: responders answer to the
//! source port) and nothing can be concealed.
//!
//! A name being resolved is queried at once, again after 1 and 2 seconds, then every 2
//! seconds until the timeout; answers, solicited or not (browsers announce their names), are
//! cached for their TTL (at most 2 minutes, 256 names). When it
//! resolves, each waiting peer gets the candidate line with the address (one candidate per
//! address family the name has), unless that peer's remote ICE credentials changed meanwhile.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use only::{Acceptor, Conn, Engine, Handler, UdpBinding};
use only_ice::mdns::{self, Message, Question, Record};

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
    /// The earliest timer armed.
    armed: Option<Instant>,
}

pub(crate) struct Mdns {
    me: Weak<Mdns>,
    hub: Weak<Hub>,
    binding: OnceLock<UdpBinding>,
    /// Bound to the shared mDNS port (multicast); else an ephemeral port (legacy unicast).
    shared: bool,
    timeout: Duration,
    state: Mutex<State>,
}

struct MdnsAcceptor(Weak<Mdns>);

impl Acceptor for MdnsAcceptor {
    type Handler = MdnsUdp;
    fn on_open(&self, _c: &Conn<MdnsUdp>) -> MdnsUdp {
        MdnsUdp(self.0.clone())
    }
}

/// The mDNS socket's handler.
pub(crate) struct MdnsUdp(Weak<Mdns>);

impl std::fmt::Debug for MdnsUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsUdp").finish_non_exhaustive()
    }
}

impl Handler for MdnsUdp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(m) = self.0.upgrade() {
            m.on_datagram(c.peer_addr(), data);
        }
    }
}

impl Mdns {
    /// Binds the mDNS socket on `engine` (the shared port, else an ephemeral one).
    pub(crate) fn new(
        hub: &Arc<Hub>,
        engine: &Engine,
        timeout: Duration,
    ) -> std::io::Result<Arc<Mdns>> {
        let make = |shared: bool| {
            Arc::new_cyclic(|me| Mdns {
                me: me.clone(),
                hub: Arc::downgrade(hub),
                binding: OnceLock::new(),
                shared,
                timeout,
                state: Mutex::new(State::default()),
            })
        };
        let m = make(true);
        let b = match engine.bind_udp_multicast(mdns::MULTICAST_V4, MdnsAcceptor(m.me.clone())) {
            Ok(b) => (m, b),
            Err(e) => {
                only_log::debug!(target: "only_webrtc", "mdns: port {} unavailable ({e}); one-shot unicast queries", mdns::PORT);
                let m = make(false);
                let b = engine.bind_udp(
                    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                    MdnsAcceptor(m.me.clone()),
                )?;
                (m, b)
            }
        };
        let (m, b) = b;
        let _ = m.binding.set(b);
        Ok(m)
    }

    /// Whether this socket can answer queries (it is on the shared mDNS port).
    pub(crate) fn can_respond(&self) -> bool {
        self.shared
    }

    pub(crate) fn close(&self) {
        if let Some(b) = self.binding.get() {
            b.close();
        }
    }

    /// The name concealing local address `ip` (made on first use); `None` past
    /// [`MAX_OWN`] addresses.
    pub(crate) fn name_for(&self, ip: IpAddr) -> Option<String> {
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
                only_log::debug!(target: "only_webrtc", "mdns: {name} is {ips:?} (cached)");
                Some((ips.clone(), w))
            } else if let Some(q) = st.queries.get_mut(&name) {
                if q.waiters.len() < MAX_WAITERS {
                    q.waiters.push(w);
                }
                return;
            } else {
                if st.queries.len() >= MAX_QUERIES {
                    only_log::debug!(target: "only_webrtc", "mdns: too many names being resolved, {name} dropped");
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

    /// Sends the queries that are due, drops the expired ones, arms the timer.
    fn tick(&self, now: Instant) {
        let mut send = Vec::new();
        let next = {
            let mut st = lock(&self.state);
            st.queries.retain(|name, q| {
                if q.deadline <= now {
                    only_log::debug!(target: "only_webrtc", "mdns: {name} not resolved in time");
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
            let next = st.queries.values().map(|q| q.next.min(q.deadline)).min();
            match next {
                Some(n) if st.armed.is_none_or(|a| n < a) => {
                    st.armed = Some(n);
                    Some(n)
                }
                _ => None,
            }
        };
        self.send_queries(&send);
        if let Some(n) = next {
            let target: Weak<dyn timer::Due> = self.me.clone();
            timer::timer().schedule(n, target);
        }
    }

    fn send_queries(&self, names: &[String]) {
        let Some(b) = self.binding.get() else { return };
        for n in names {
            // Over the shared port, a multicast query; otherwise a legacy unicast one (the
            // QU bit is set too, which the RFC asks of one-shot queriers on another port).
            // One question per message (Chromium's responder ignores several).
            for t in [mdns::TYPE_A, mdns::TYPE_AAAA] {
                if let Some(q) = Message::query(n, t, !self.shared) {
                    let _ = b.send_to(&q, mdns::MULTICAST_V4);
                }
            }
        }
    }

    fn on_datagram(&self, src: SocketAddr, data: &[u8]) {
        let Ok(m) = Message::parse(data) else { return };
        if m.response {
            // RFC 6762 §6: answers come from the mDNS port (also to legacy unicast queriers).
            if src.port() == mdns::PORT {
                self.on_response(&m.records);
            }
        } else if self.shared && !m.questions.is_empty() {
            self.on_query(src, &m);
        }
    }

    fn on_response(&self, records: &[Record]) {
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
                only_log::debug!(target: "only_webrtc", "mdns: {name} is {ips:?}");
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
            let st = lock(&self.state);
            if st.own_names.is_empty() {
                return;
            }
            let mut answers = Vec::new();
            let mut questions = Vec::new();
            for q in &m.questions {
                let Some(&ip) = st.own_names.get(&q.name) else {
                    continue;
                };
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
        only_log::debug!(target: "only_webrtc", "mdns: answering {src} for {}", answers[0].name);
        let Some(b) = self.binding.get() else { return };
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
        let dest = if unicast { src } else { mdns::MULTICAST_V4 };
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

/// Gives each waiting peer its candidate line with the addresses `ips`.
fn deliver(hub: &Hub, ips: &[IpAddr], waiters: Vec<(String, Waiter)>) {
    for (name, w) in waiters {
        let Some(p) = hub.peer(w.peer) else { continue };
        for &ip in ips {
            let c = only_ice::Candidate::parse_resolved(&w.line, |n| (n == name).then_some(ip));
            if let Ok(c) = c {
                let ufrag = w.ufrag.clone();
                let _ = p.with_rtc_inner(|rtc| rtc.add_resolved_candidate(c, &ufrag));
            }
        }
    }
}
