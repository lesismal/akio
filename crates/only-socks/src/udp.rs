//! SOCKS5 UDP ASSOCIATE (RFC 1928 section 7): one UDP socket per association, bound through
//! [`only::Engine::bind_udp`], relaying between the client and the destinations it names.
//!
//! Rules applied:
//! - only datagrams from the client's IP (the control connection's peer) count as the client's,
//!   and once its first datagram fixes the source port (or the request named one), only that
//!   address; anything else from that IP is a remote host;
//! - fragmented datagrams (non-zero FRAG) are reassembled in order, one sequence at a time,
//!   bounded in size and time ([`crate::frag`]), and relayed as one datagram once complete;
//! - every destination goes through the access-control hook ([`Command::UdpDatagram`]),
//!   decided once per destination and association;
//! - datagrams from remote hosts are relayed to the client only from addresses the client has
//!   sent to (endpoint-dependent filtering), so the relay is not an open inbound port; with
//!   [`Socks::udp_fragment_size`](crate::Socks::udp_fragment_size) set, larger ones go in
//!   fragments of that size (ADR-059);
//! - the association ends with the control TCP connection, or after the idle timeout without
//!   a datagram either way (the sweeper closes the control connection);
//! - over GSS-API with per-message protection (RFC 1961 §5), every datagram between the client
//!   and the relay is one encapsulated-data message wrapped with the control connection's
//!   context; datagrams that do not unwrap are dropped.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Acceptor, Conn, Handler, UdpBinding};
use only_core::ConnInner;

use crate::{
    Allow, Command, Dest, Destinations, Request,
    frag::{Frag, Reassembly},
    gssapi::DatagramGss,
};

/// Remote addresses remembered per association (for filtering their answers).
const MAX_SENT_TO: usize = 4096;
/// Hook decisions and name resolutions cached per association.
const MAX_CACHE: usize = 256;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// An IPv4-mapped IPv6 address as IPv4, anything else unchanged.
pub(crate) fn canon(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        IpAddr::V4(_) => a,
    }
}

/// Parses the UDP request header: `RSV(2) FRAG ATYP DST.ADDR DST.PORT`, returning the
/// fragment number, the destination and the header length.
pub(crate) fn parse_header(d: &[u8]) -> Option<(u8, Dest, usize)> {
    if d.len() < 4 {
        return None;
    }
    let frag = d[2];
    let (dest, n) = crate::parse_addr(d[3], &d[4..])?;
    Some((frag, dest, 4 + n))
}

/// Writes the UDP reply header for a datagram from `from`.
pub(crate) fn push_header(out: &mut Vec<u8>, from: SocketAddr) {
    out.extend_from_slice(&[0, 0, 0]);
    crate::push_addr(out, from);
}

/// The sweeper shared by the associations of one [`Socks`](crate::Socks): one thread, started
/// with the first association, that ends idle ones. It exits when the server and all its
/// sessions are gone.
pub(crate) struct Sweeper {
    epoch: Instant,
    assocs: Mutex<Vec<Weak<Assoc>>>,
    started: AtomicBool,
}

impl Sweeper {
    pub(crate) fn new() -> Arc<Sweeper> {
        Arc::new(Sweeper {
            epoch: Instant::now(),
            assocs: Mutex::new(Vec::new()),
            started: AtomicBool::new(false),
        })
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn add(self: &Arc<Sweeper>, a: &Arc<Assoc>) {
        lock(&self.assocs).push(Arc::downgrade(a));
        if !self.started.swap(true, Ordering::AcqRel) {
            let weak = Arc::downgrade(self);
            let _ = std::thread::Builder::new()
                .name("only-socks-udp-sweep".into())
                .spawn(move || {
                    loop {
                        std::thread::sleep(Duration::from_millis(250));
                        let Some(s) = weak.upgrade() else { return };
                        s.sweep();
                    }
                });
        }
    }

    fn sweep(&self) {
        let now = self.now_ms();
        let mut expired = Vec::new();
        lock(&self.assocs).retain(|w| match w.upgrade() {
            Some(a) if a.closed.load(Ordering::Acquire) => false,
            Some(a) => {
                if now.saturating_sub(a.last.load(Ordering::Relaxed)) >= a.idle_ms {
                    expired.push(a);
                    false
                } else {
                    true
                }
            }
            None => false,
        });
        for a in expired {
            a.control.close();
            a.close();
        }
    }
}

/// One UDP association.
pub(crate) struct Assoc {
    /// The control TCP connection: the association lives as long as it.
    control: Arc<ConnInner>,
    /// The client's TCP address (for the access-control hook).
    client_tcp: SocketAddr,
    user: Option<String>,
    allow: Option<Allow>,
    /// Which addresses datagrams may be sent to (checked after resolution).
    destinations: Destinations,
    /// Port the request said the client sends from (0: learn it from the first datagram).
    declared_port: u16,
    /// The client's UDP address, once known.
    client: Mutex<Option<SocketAddr>>,
    binding: OnceLock<UdpBinding>,
    sent_to: Mutex<HashSet<SocketAddr>>,
    decisions: Mutex<HashMap<Dest, bool>>,
    resolved: Mutex<HashMap<(String, u16), SocketAddr>>,
    sweeper: Arc<Sweeper>,
    last: AtomicU64,
    idle_ms: u64,
    closed: AtomicBool,
    /// Datagrams to the client larger than this go in fragments.
    frag_size: Option<usize>,
    /// GSS-API per-message protection of the client's datagrams.
    gss: Option<DatagramGss>,
}

impl Assoc {
    /// The address replies go to the client from (the bound socket), after binding it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        engine: &only::Engine,
        control: Arc<ConnInner>,
        user: Option<String>,
        allow: Option<Allow>,
        declared: Option<SocketAddr>,
        destinations: Destinations,
        sweeper: &Arc<Sweeper>,
        idle: Duration,
        frag_size: Option<usize>,
        gss: Option<DatagramGss>,
    ) -> std::io::Result<(Arc<Assoc>, SocketAddr)> {
        let client_tcp = canon(control.peer_addr());
        // The client's declared address only counts when it is its own IP (behind NAT it
        // often sends 0.0.0.0:0 or a private address): the port is what helps.
        let declared_port = declared
            .map(canon)
            .filter(|d| d.ip().is_unspecified() || d.ip() == client_tcp.ip())
            .map_or(0, |d| d.port());
        let local = SocketAddr::new(canon(control.local_addr()).ip(), 0);
        let a = Arc::new(Assoc {
            control,
            client_tcp,
            user,
            allow,
            destinations,
            declared_port,
            client: Mutex::new(None),
            binding: OnceLock::new(),
            sent_to: Mutex::new(HashSet::new()),
            decisions: Mutex::new(HashMap::new()),
            resolved: Mutex::new(HashMap::new()),
            sweeper: sweeper.clone(),
            last: AtomicU64::new(sweeper.now_ms()),
            idle_ms: idle.as_millis().max(1) as u64,
            closed: AtomicBool::new(false),
            frag_size,
            gss,
        });
        let b = engine.bind_udp(local, RelayAcceptor(a.clone()))?;
        let bound = canon(b.local_addr());
        let _ = a.binding.set(b);
        sweeper.add(&a);
        Ok((a, bound))
    }

    /// Closes the relay socket. Idempotent.
    pub(crate) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            if let Some(b) = self.binding.get() {
                b.close();
            }
        }
    }

    fn touch(&self) {
        self.last.store(self.sweeper.now_ms(), Ordering::Relaxed);
    }

    /// Whether `peer` is the client (learning its port from its first datagram).
    fn is_client(&self, peer: SocketAddr) -> bool {
        let mut c = lock(&self.client);
        match *c {
            Some(a) => a == peer,
            None if peer.ip() == self.client_tcp.ip()
                && (self.declared_port == 0 || self.declared_port == peer.port()) =>
            {
                *c = Some(peer);
                true
            }
            None => false,
        }
    }

    fn allowed(&self, dest: &Dest) -> bool {
        let Some(f) = &self.allow else { return true };
        if let Some(&d) = lock(&self.decisions).get(dest) {
            return d;
        }
        let ok = f(&Request {
            version: 5,
            client: self.client_tcp,
            user: self.user.as_deref(),
            command: Command::UdpDatagram,
            dest,
        });
        let mut m = lock(&self.decisions);
        if m.len() < MAX_CACHE {
            m.insert(dest.clone(), ok);
        }
        ok
    }

    /// Sends `payload` to `to` from the relay socket, remembering `to` for its answers.
    fn send_out(&self, to: SocketAddr, payload: &[u8]) {
        let Some(b) = self.binding.get() else { return };
        let to = canon(to);
        // The destination policy, on the address actually used (after name resolution).
        if !self.destinations.allows(to) {
            return;
        }
        // The socket's family decides how the address is written.
        let wire = match (b.local_addr(), to.ip()) {
            (SocketAddr::V6(_), IpAddr::V4(v4)) => {
                SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), to.port())
            }
            (SocketAddr::V4(_), IpAddr::V6(_)) => return, // unreachable from this socket
            _ => to,
        };
        {
            let mut s = lock(&self.sent_to);
            if s.len() >= MAX_SENT_TO && !s.contains(&to) {
                s.clear();
            }
            s.insert(to);
        }
        let _ = b.send_to(payload, wire);
    }

    fn relay_from_client(&self, c: &Conn<RelayPeer>, reasm: &mut Reassembly, data: &[u8]) {
        let opened;
        let data = match &self.gss {
            Some(g) => match g.open(data) {
                Ok(d) => {
                    opened = d;
                    &opened[..]
                }
                Err(_) => return,
            },
            None => data,
        };
        let Some((frag, dest, n)) = parse_header(data) else {
            return;
        };
        if !self.allowed(&dest) {
            return;
        }
        let payload = &data[n..];
        if frag == 0 {
            reasm.reset();
            return self.relay_to(c, dest, payload);
        }
        if let Frag::Complete(dest, whole) = reasm.push(Instant::now(), frag, &dest, payload) {
            self.relay_to(c, dest, &whole);
        }
    }

    /// Relays one (whole or reassembled) datagram from the client to `dest`.
    fn relay_to(&self, c: &Conn<RelayPeer>, dest: Dest, payload: &[u8]) {
        match dest {
            Dest::Addr(a) => self.send_out(a, payload),
            Dest::Name(host, port) => {
                let cached = lock(&self.resolved).get(&(host.clone(), port)).copied();
                if let Some(a) = cached {
                    return self.send_out(a, payload);
                }
                // Resolution blocks: on the logical pool, then sent from there.
                let payload = payload.to_vec();
                let _ = c.spawn_blocking(
                    move || {
                        (host.as_str(), port)
                            .to_socket_addrs()
                            .ok()
                            .and_then(|mut a| a.next())
                            .map(|a| (host, port, a))
                    },
                    move |me: &mut RelayPeer, _c, res| {
                        if let Some((host, port, a)) = res {
                            let mut m = lock(&me.0.resolved);
                            if m.len() < MAX_CACHE {
                                m.insert((host, port), a);
                            }
                            drop(m);
                            me.0.send_out(a, &payload);
                        }
                    },
                );
            }
        }
    }

    /// Relays a datagram from a remote host to the client, if the client has sent to that
    /// host. Returns whether it did.
    fn relay_from_remote(&self, peer: SocketAddr, data: &[u8]) -> bool {
        if !lock(&self.sent_to).contains(&peer) {
            return false;
        }
        let (Some(client), Some(b)) = (*lock(&self.client), self.binding.get()) else {
            return false;
        };
        if let Some(max) = self.frag_size.filter(|&m| data.len() > m) {
            let Ok(parts) = crate::frag::split(data, max) else {
                return true; // larger than a datagram: cannot be expressed
            };
            let mut out = Vec::with_capacity(max + 22);
            for (frag, piece) in parts {
                out.clear();
                push_header(&mut out, peer);
                out[2] = frag;
                out.extend_from_slice(piece);
                self.to_client(b, &out, client);
            }
            return true;
        }
        let mut out = Vec::with_capacity(data.len() + 22);
        push_header(&mut out, peer);
        out.extend_from_slice(data);
        self.to_client(b, &out, client);
        true
    }

    /// Sends one datagram (header included) to the client, wrapped under GSS-API protection.
    fn to_client(&self, b: &UdpBinding, d: &[u8], client: SocketAddr) {
        match &self.gss {
            // Too large to wrap within the 16-bit length: cannot be expressed.
            Some(g) => {
                if let Ok(w) = g.seal(d) {
                    let _ = b.send_to(&w, client);
                }
            }
            None => {
                let _ = b.send_to(d, client);
            }
        }
    }
}

struct RelayAcceptor(Arc<Assoc>);

impl Acceptor for RelayAcceptor {
    type Handler = RelayPeer;
    fn on_open(&self, _c: &Conn<RelayPeer>) -> RelayPeer {
        RelayPeer(self.0.clone(), Reassembly::default())
    }
}

/// One peer address of an association's relay socket (the client's peer reassembles its
/// fragments: the client sends from one address).
pub(crate) struct RelayPeer(Arc<Assoc>, Reassembly);

impl std::fmt::Debug for RelayPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayPeer").finish_non_exhaustive()
    }
}

impl Handler for RelayPeer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let a = &self.0;
        if a.closed.load(Ordering::Acquire) {
            return;
        }
        let peer = canon(c.peer_addr());
        if a.is_client(peer) {
            a.touch();
            a.relay_from_client(c, &mut self.1, data);
        } else if a.relay_from_remote(peer, data) {
            a.touch();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        let mut h = Vec::new();
        push_header(&mut h, "10.1.2.3:53".parse().unwrap());
        assert_eq!(h, [0, 0, 0, 1, 10, 1, 2, 3, 0, 53]);
        h.extend_from_slice(b"payload");
        let (frag, dest, n) = parse_header(&h).unwrap();
        assert_eq!((frag, n), (0, 10));
        assert_eq!(dest, Dest::Addr("10.1.2.3:53".parse().unwrap()));
        assert_eq!(&h[n..], b"payload");
        let named = b"\x00\x00\x01\x03\x0bexample.com\x00\x35x";
        let (frag, dest, n) = parse_header(named).unwrap();
        assert_eq!((frag, n), (1, 18));
        assert_eq!(dest, Dest::Name("example.com".into(), 53));
        let mut h6 = Vec::new();
        push_header(&mut h6, "[::1]:9".parse().unwrap());
        assert_eq!((h6[3], h6.len()), (4, 22));
        assert!(parse_header(&[0, 0, 0]).is_none());
        assert!(parse_header(&[0, 0, 0, 1, 1, 2]).is_none());
        assert!(parse_header(&[0, 0, 0, 9, 1, 2, 3, 4, 0, 1]).is_none());
        assert_eq!(
            canon("[::ffff:1.2.3.4]:5".parse().unwrap()),
            "1.2.3.4:5".parse().unwrap()
        );
    }
}
