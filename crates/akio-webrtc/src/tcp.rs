//! ICE-TCP (RFC 6544): passive TCP candidates of an [`Endpoint`](crate::Endpoint) (a listening
//! socket of its own) and of an [`RtcServer`](crate::RtcServer) (a TCP listener of the engine,
//! [`RtcTcp`]), and the active TCP candidate of an endpoint (connections it dials).
//!
//! Every connection carries RFC 4571 frames.
//!
//! - **Passive**: an endpoint's dedicated thread accepts connections (blocking `accept`, never
//!   an I/O thread) and hands them to the engine ([`akio::Engine::adopt_tcp`]); a server's
//!   arrive through its listener. A connection's first frame must be a connectivity check
//!   naming one of the peers by ufrag, within [`FIRST_CHECK_TIMEOUT`]; from then on its frames
//!   go to that peer as datagrams from the connection's remote address to the candidate's
//!   address, and what the peer sends from the candidate's address to that remote address
//!   goes back framed on the connection.
//! - **Active**: the candidate's address is the primary IP with port 9 (the SDP says 9 for an
//!   active candidate). A check the agent sends from it to a remote passive candidate opens a
//!   connection for that peer and remote address (one per pair, RFC 6544 §5.1), queued until
//!   it is up; other datagrams to a remote without a connection are dropped. What arrives on it
//!   goes to that peer as datagrams from the remote address to the active candidate's address.
//!   A connection that fails or closes is forgotten: the agent's next check opens another.
//! - **Simultaneous open** (`tcptype so`): the candidate's port listens (accepted connections
//!   are handled as passive ones) and checks to a remote `so` candidate are dialed from that
//!   same port ([`akio::Engine::dial_from`], `SO_REUSEPORT`), unless a connection with that
//!   remote was accepted already. When both sides' connects cross, TCP simultaneous open makes
//!   one connection that each side uses as its dialed one; when one arrives first, the other
//!   side's listener accepts it and that side's checks then go over it.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Engine, Handler};
use akio_ice::tcp::{FrameReader, frame};
use akio_turn::stun;

use crate::{Hub, lock, timer};

/// Connections of an endpoint at once (more are refused).
pub(crate) const MAX_CONNS: usize = 256;
/// A passive connection whose first check has not arrived this long after it was accepted is
/// closed.
pub(crate) const FIRST_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// Datagrams for a connection with more than this queued are dropped (they keep datagram
/// semantics: DTLS, SCTP and RTP recover).
const MAX_QUEUED: usize = 1 << 20;
/// Bytes queued for an active connection that is still being dialed.
const MAX_DIALING: usize = 64 * 1024;
/// How long frames of a failed simultaneous-open dial wait for the remote's connection.
const ORPHAN_TTL: Duration = Duration::from_secs(2);

/// A connection, and the peer it belongs to once known.
struct Entry {
    conn: Conn<IceTcp>,
    peer: Option<u64>,
}

enum Active {
    Dialing(Vec<Vec<u8>>, usize),
    Open(Conn<IceTcp>),
}

#[derive(Default)]
struct Conns {
    /// Passive connections by remote address.
    passive: HashMap<SocketAddr, Entry>,
    /// Active connections by peer and remote passive candidate.
    active: HashMap<(u64, SocketAddr), Active>,
    /// Simultaneous open: frames queued for a dial that failed because the remote's own
    /// connect is being accepted, by remote address, for that connection (at most
    /// [`MAX_CONNS`], kept [`ORPHAN_TTL`]).
    orphans: HashMap<SocketAddr, (Instant, Vec<Vec<u8>>)>,
}

impl Conns {
    fn len(&self) -> usize {
        self.passive.len() + self.active.len()
    }
}

/// The TCP side of an endpoint or a server.
pub(crate) struct TcpSide {
    /// Passive candidates' addresses (what peers send from and what arrives "on").
    passive: Mutex<Vec<SocketAddr>>,
    /// The active candidate's address (IP and port 9).
    active: OnceLock<SocketAddr>,
    /// The engine active connections are dialed on.
    engine: OnceLock<Weak<Engine>>,
    /// The address an endpoint's listener is bound to (to wake its thread on close).
    bound: OnceLock<SocketAddr>,
    /// The simultaneous-open candidate's address (what its connections are dialed from) and
    /// the address its listener is bound to.
    so: OnceLock<(SocketAddr, SocketAddr)>,
    conns: Mutex<Conns>,
    /// A server's side: the bound follows its peer limit.
    server: bool,
    stop: AtomicBool,
    hub: Weak<Hub>,
    me: Weak<TcpSide>,
}

impl TcpSide {
    pub(crate) fn new(hub: &Arc<Hub>, server: bool) -> Arc<TcpSide> {
        Arc::new_cyclic(|me| TcpSide {
            passive: Mutex::new(Vec::new()),
            active: OnceLock::new(),
            engine: OnceLock::new(),
            bound: OnceLock::new(),
            so: OnceLock::new(),
            conns: Mutex::new(Conns::default()),
            server,
            stop: AtomicBool::new(false),
            hub: Arc::downgrade(hub),
            me: me.clone(),
        })
    }

    /// Most connections at once: [`MAX_CONNS`] for an endpoint; for a server twice its peer
    /// limit, at least [`MAX_CONNS`], 4096 without a limit.
    fn max_conns(&self) -> usize {
        if !self.server {
            return MAX_CONNS;
        }
        match self
            .hub
            .upgrade()
            .map(|h| h.max_peers.load(Ordering::Relaxed))
        {
            Some(0) | None => 4096,
            Some(n) => n.saturating_mul(2).max(MAX_CONNS),
        }
    }

    /// Whether an endpoint's listener runs.
    pub(crate) fn is_listening(&self) -> bool {
        self.bound.get().is_some()
    }

    /// Adds passive candidate addresses (a server's).
    pub(crate) fn add_passive(&self, addrs: &[SocketAddr]) {
        lock(&self.passive).extend_from_slice(addrs);
    }

    /// Starts accepting on `listener` (an endpoint's); `local` is the address advertised in
    /// the candidate. Once.
    pub(crate) fn listen(
        &self,
        engine: &Arc<Engine>,
        listener: TcpListener,
        local: SocketAddr,
    ) -> io::Result<()> {
        let bound = listener.local_addr()?;
        if self.bound.set(bound).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the endpoint listens on TCP already",
            ));
        }
        self.add_passive(&[local]);
        let (engine, me) = (Arc::downgrade(engine), self.me.clone());
        std::thread::Builder::new()
            .name("akio-webrtc-ice-tcp".into())
            .spawn(move || accept_loop(&listener, &engine, &me))?;
        Ok(())
    }

    /// Starts the simultaneous-open candidate `local` on `listener` (bound with
    /// `SO_REUSEPORT` to that port), dialing from `local` on `engine`. Once.
    pub(crate) fn listen_so(
        &self,
        engine: &Arc<Engine>,
        listener: TcpListener,
        local: SocketAddr,
    ) -> io::Result<()> {
        let bound = listener.local_addr()?;
        if self.so.set((local, bound)).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the endpoint has a simultaneous-open TCP candidate already",
            ));
        }
        let _ = self.engine.set(Arc::downgrade(engine));
        self.add_passive(&[local]);
        let (engine, me) = (Arc::downgrade(engine), self.me.clone());
        std::thread::Builder::new()
            .name("akio-webrtc-ice-tcp-so".into())
            .spawn(move || accept_loop(&listener, &engine, &me))?;
        Ok(())
    }

    /// Enables the active candidate `addr` (IP and port 9), dialing on `engine`. Once.
    pub(crate) fn set_active(&self, engine: &Arc<Engine>, addr: SocketAddr) -> bool {
        let _ = self.engine.set(Arc::downgrade(engine));
        self.active.set(addr).is_ok()
    }

    /// Whether `src` is the active or the simultaneous-open candidate's address (lock-free:
    /// on every transmit), whose datagrams go over connections.
    pub(crate) fn is_active(&self, src: SocketAddr) -> bool {
        self.active.get() == Some(&src) || self.so.get().is_some_and(|s| s.0 == src)
    }

    /// The candidate address a passive connection with local address `local` arrived on.
    fn candidate_of(&self, local: SocketAddr) -> SocketAddr {
        let p = lock(&self.passive);
        p.iter()
            .find(|a| **a == local)
            .or_else(|| {
                p.iter()
                    .find(|a| a.port() == local.port() && a.is_ipv4() == local.is_ipv4())
            })
            .copied()
            .unwrap_or(local)
    }

    /// Sends a datagram of peer `id` from candidate `src` to `dest`.
    pub(crate) fn send(&self, id: u64, src: SocketAddr, dest: SocketAddr, data: &[u8]) {
        let Some(f) = frame(data) else { return };
        if self.active.get() == Some(&src) {
            self.send_active(id, dest, data, f, None);
            return;
        }
        let c = lock(&self.conns).passive.get(&dest).map(|e| e.conn.clone());
        if let Some(c) = c {
            send_frame(&c, f);
        } else if let Some(&(so, _)) = self.so.get().filter(|s| s.0 == src) {
            // Simultaneous open: no connection from that remote was accepted, dial it.
            self.send_active(id, dest, data, f, Some(so));
        }
    }

    /// Sends on the dialed connection of peer `id` to `dest` (dialing it, from `from` when
    /// given, if `data` is a check).
    fn send_active(
        &self,
        id: u64,
        dest: SocketAddr,
        data: &[u8],
        f: Vec<u8>,
        from: Option<SocketAddr>,
    ) {
        let key = (id, dest);
        {
            let mut conns = lock(&self.conns);
            let full = conns.len() >= self.max_conns();
            match conns.active.get_mut(&key) {
                Some(Active::Open(c)) => {
                    let c = c.clone();
                    drop(conns);
                    send_frame(&c, f);
                    return;
                }
                Some(Active::Dialing(q, n)) => {
                    if *n + f.len() <= MAX_DIALING {
                        *n += f.len();
                        q.push(f);
                    }
                    return;
                }
                // Only a check opens a connection.
                None if full || !is_binding_request(data) || self.stop.load(Ordering::Acquire) => {
                    return;
                }
                None => {
                    let n = f.len();
                    conns.active.insert(key, Active::Dialing(vec![f], n));
                }
            }
        }
        // Dial outside the lock: a failure may be reported at once.
        let Some(engine) = self.engine.get().and_then(Weak::upgrade) else {
            lock(&self.conns).active.remove(&key);
            return;
        };
        let acc = TcpAcceptor {
            side: self.me.clone(),
            active: Some(key),
            local: from,
        };
        let me = self.me.clone();
        let failed = move |e: io::Error| {
            akio_log::debug!(target: "akio_webrtc", "ice-tcp: connect {dest}: {e}");
            let Some(s) = me.upgrade() else { return };
            let (queued, accepted) = {
                let mut conns = lock(&s.conns);
                let q = match conns.active.get(&key) {
                    Some(Active::Dialing(..)) => match conns.active.remove(&key) {
                        Some(Active::Dialing(q, _)) => q,
                        _ => Vec::new(),
                    },
                    _ => Vec::new(),
                };
                (q, conns.passive.get(&dest).map(|e| e.conn.clone()))
            };
            // Simultaneous open: the remote's connect reached our listener first (ours then
            // fails, the 4-tuple being taken): what was queued goes over that connection, or
            // waits for it if it is still being accepted.
            if from.is_none() || queued.is_empty() {
                return;
            }
            match accepted {
                Some(c) => queued.into_iter().for_each(|f| send_frame(&c, f)),
                None => {
                    let mut conns = lock(&s.conns);
                    let now = Instant::now();
                    conns.orphans.retain(|_, (t, _)| now < *t + ORPHAN_TTL);
                    if conns.orphans.len() < MAX_CONNS {
                        conns.orphans.insert(dest, (now, queued));
                    }
                }
            }
        };
        match from {
            Some(local) => engine.dial_from(local, dest, acc, failed),
            None => engine.dial(dest, acc, failed),
        }
    }

    /// Closes the connections of peer `id`.
    pub(crate) fn close_peer(&self, id: u64) {
        let conns: Vec<Conn<IceTcp>> = {
            let mut cs = lock(&self.conns);
            let mut v: Vec<Conn<IceTcp>> = cs
                .passive
                .values()
                .filter(|e| e.peer == Some(id))
                .map(|e| e.conn.clone())
                .collect();
            cs.active.retain(|(p, _), a| {
                if *p != id {
                    return true;
                }
                if let Active::Open(c) = a {
                    v.push(c.clone());
                }
                false
            });
            v
        };
        // After what the peer sent last (its SCTP ABORT and DTLS close_notify).
        for c in conns {
            c.close_after_send();
        }
    }

    /// Stops accepting and dialing, and closes every connection.
    pub(crate) fn close(&self) {
        self.stop.store(true, Ordering::Release);
        // The accept threads are woken from a thread of their own: this may run on an I/O
        // thread (the engine's shutdown), where even a loopback connect must not block.
        let bound: Vec<SocketAddr> = self
            .bound
            .get()
            .copied()
            .into_iter()
            .chain(self.so.get().map(|&(_, b)| b))
            .collect();
        if !bound.is_empty() {
            let _ = std::thread::Builder::new()
                .name("akio-webrtc-tcp-wake".into())
                .spawn(move || bound.into_iter().for_each(wake));
        }
        let conns: Vec<Conn<IceTcp>> = {
            let mut cs = lock(&self.conns);
            let mut v: Vec<Conn<IceTcp>> = cs.passive.values().map(|e| e.conn.clone()).collect();
            for (_, a) in cs.active.drain() {
                if let Active::Open(c) = a {
                    v.push(c);
                }
            }
            v
        };
        for c in conns {
            c.close_after_send();
        }
    }

    /// A passive connection opened (accepted).
    fn passive_open(&self, c: &Conn<IceTcp>) -> bool {
        if self.stop.load(Ordering::Acquire) {
            return false;
        }
        let (old, orphans) = {
            let mut cs = lock(&self.conns);
            if cs.len() >= self.max_conns() && !cs.passive.contains_key(&c.peer_addr()) {
                return false;
            }
            let old = cs.passive.insert(
                c.peer_addr(),
                Entry {
                    conn: c.clone(),
                    peer: None,
                },
            );
            let orphans = cs
                .orphans
                .remove(&c.peer_addr())
                .filter(|(t, _)| t.elapsed() < ORPHAN_TTL);
            (old, orphans)
        };
        if let Some(old) = old {
            old.conn.close();
        }
        for f in orphans.map(|o| o.1).unwrap_or_default() {
            send_frame(c, f);
        }
        true
    }

    /// An active connection opened: what was queued goes out.
    fn active_open(&self, key: (u64, SocketAddr), c: &Conn<IceTcp>) -> bool {
        let q = {
            let mut cs = lock(&self.conns);
            match cs.active.get_mut(&key) {
                Some(a @ Active::Dialing(..)) => {
                    match std::mem::replace(a, Active::Open(c.clone())) {
                        Active::Dialing(q, _) => q,
                        Active::Open(_) => Vec::new(),
                    }
                }
                _ => return false,
            }
        };
        for f in q {
            let _ = c.send_owned(f);
        }
        true
    }

    fn closed(&self, c: &Conn<IceTcp>, active: Option<(u64, SocketAddr)>) {
        let mut cs = lock(&self.conns);
        match active {
            Some(key) => {
                if matches!(cs.active.get(&key), Some(Active::Open(x)) if x.id() == c.id()) {
                    cs.active.remove(&key);
                }
            }
            None => {
                if cs
                    .passive
                    .get(&c.peer_addr())
                    .is_some_and(|e| e.conn.id() == c.id())
                {
                    cs.passive.remove(&c.peer_addr());
                }
            }
        }
    }
}

/// Connects to a listener bound at `bound` so that its blocking `accept` returns.
fn wake(bound: SocketAddr) {
    let mut wake = bound;
    if wake.ip().is_unspecified() {
        wake.set_ip(if wake.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    let _ = TcpStream::connect_timeout(&wake, Duration::from_millis(200));
}

fn send_frame(c: &Conn<IceTcp>, f: Vec<u8>) {
    if c.queued_bytes() > MAX_QUEUED {
        return;
    }
    let _ = c.send_owned(f);
}

fn is_binding_request(data: &[u8]) -> bool {
    stun::is_stun(data)
        && stun::Message::parse(data)
            .is_ok_and(|m| m.method() == stun::Method::BINDING && m.class() == stun::Class::Request)
}

fn accept_loop(listener: &TcpListener, engine: &Weak<Engine>, side: &Weak<TcpSide>) {
    loop {
        let Ok((s, _)) = listener.accept() else {
            std::thread::sleep(Duration::from_millis(50)); // EMFILE and the like
            continue;
        };
        let (Some(side), Some(engine)) = (side.upgrade(), engine.upgrade()) else {
            return;
        };
        if side.stop.load(Ordering::Acquire) {
            return;
        }
        if lock(&side.conns).len() >= side.max_conns() {
            continue; // dropped: refused
        }
        let _ = s.set_nodelay(true);
        engine.adopt_tcp(
            s,
            TcpAcceptor {
                side: Arc::downgrade(&side),
                active: None,
                local: None,
            },
            |_| {},
        );
    }
}

/// The acceptor of an [`RtcServer`](crate::RtcServer)'s TCP listener: passive ICE-TCP
/// ([`RtcServer::tcp`](crate::RtcServer::tcp)).
#[derive(Clone)]
pub struct RtcTcp(pub(crate) Weak<TcpSide>);

impl std::fmt::Debug for RtcTcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtcTcp").finish_non_exhaustive()
    }
}

impl Acceptor for RtcTcp {
    type Handler = IceTcp;
    fn on_open(&self, c: &Conn<IceTcp>) -> IceTcp {
        TcpAcceptor {
            side: self.0.clone(),
            active: None,
            local: None,
        }
        .on_open(c)
    }

    fn on_shutdown(&self, _c: &Conn<IceTcp>) {
        shutdown(&self.0);
    }
}

/// The engine shuts down: the endpoint or server closes ([`crate::engine_shutdown`]), and
/// with it this connection, once its peer's goodbye is written.
fn shutdown(side: &Weak<TcpSide>) {
    if let Some(s) = side.upgrade() {
        crate::engine_shutdown(&s.hub);
    }
}

struct TcpAcceptor {
    side: Weak<TcpSide>,
    /// The peer and remote of an active (dialed) connection.
    active: Option<(u64, SocketAddr)>,
    /// The candidate a dialed connection belongs to: the simultaneous-open one, or (`None`)
    /// the active one.
    local: Option<SocketAddr>,
}

impl Acceptor for TcpAcceptor {
    type Handler = IceTcp;
    fn on_open(&self, c: &Conn<IceTcp>) -> IceTcp {
        let side = self.side.upgrade();
        let hub = side.as_ref().map_or_else(Weak::new, |s| s.hub.clone());
        let guard = Arc::new(Guard {
            side: self.side.clone(),
            conn: c.clone(),
        });
        let (ok, local) = match (&side, self.active) {
            (Some(s), Some(key)) => (
                s.active_open(key, c),
                self.local
                    .or_else(|| s.active.get().copied())
                    .unwrap_or_else(|| c.local_addr()),
            ),
            (Some(s), None) => {
                let ok = s.passive_open(c);
                if ok {
                    let target: Weak<dyn timer::Due> =
                        Arc::downgrade(&guard) as Weak<dyn timer::Due>;
                    timer::timer().schedule(Instant::now() + FIRST_CHECK_TIMEOUT, target);
                }
                (ok, s.candidate_of(c.local_addr()))
            }
            (None, _) => (false, c.local_addr()),
        };
        if !ok {
            c.close();
        }
        IceTcp {
            hub,
            side: self.side.clone(),
            reader: FrameReader::new(),
            peer: self.active.map(|(p, _)| p),
            target: None,
            active: self.active,
            local,
            _guard: guard,
        }
    }

    fn on_shutdown(&self, _c: &Conn<IceTcp>) {
        shutdown(&self.side);
    }
}

/// Closes a passive connection that was not identified in time.
struct Guard {
    side: Weak<TcpSide>,
    conn: Conn<IceTcp>,
}

impl timer::Due for Guard {
    fn fire(&self, _at: Instant) {
        let Some(side) = self.side.upgrade() else {
            return;
        };
        let unknown = lock(&side.conns)
            .passive
            .get(&self.conn.peer_addr())
            .is_some_and(|e| e.conn.id() == self.conn.id() && e.peer.is_none());
        if unknown {
            self.conn.close();
        }
    }
}

/// One ICE-TCP connection of an [`Endpoint`](crate::Endpoint) or an
/// [`RtcServer`](crate::RtcServer) (internal).
#[doc(hidden)]
pub struct IceTcp {
    hub: Weak<Hub>,
    side: Weak<TcpSide>,
    reader: FrameReader,
    peer: Option<u64>,
    /// The peer, once identified (it closes this connection when it closes).
    target: Option<crate::Peer>,
    active: Option<(u64, SocketAddr)>,
    /// The candidate address frames arrive "on".
    local: SocketAddr,
    _guard: Arc<Guard>,
}

impl std::fmt::Debug for IceTcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceTcp")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// The peer a connection's first frame names (a Binding request with our ufrag first).
fn identify(hub: &Hub, data: &[u8]) -> Option<u64> {
    if !stun::is_stun(data) {
        return None;
    }
    let m = stun::Message::parse(data).ok()?;
    if m.method() != stun::Method::BINDING || m.class() != stun::Class::Request {
        return None;
    }
    let u = m.get_str(stun::attr::USERNAME)?;
    hub.peer_by_ufrag(u.split(':').next().unwrap_or(""))
}

impl Handler for IceTcp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (Some(hub), Some(side)) = (self.hub.upgrade(), self.side.upgrade()) else {
            c.close();
            return;
        };
        let source = c.peer_addr();
        let local = self.local;
        let (peer, target) = (&mut self.peer, &mut self.target);
        let mut close = false;
        self.reader.push(data, |f| {
            if target.is_none() {
                let id = match *peer {
                    Some(id) => id,
                    None => match identify(&hub, f) {
                        Some(id) => {
                            *peer = Some(id);
                            if let Some(e) = lock(&side.conns).passive.get_mut(&source) {
                                e.peer = Some(id);
                            }
                            id
                        }
                        None => {
                            close = true;
                            return false;
                        }
                    },
                };
                // Looked up once: frames then go straight to the peer.
                *target = hub.peer(id);
            }
            match target {
                Some(p) if !p.is_closed() => {
                    p.input(source, local, f, true, 0);
                    true
                }
                _ => {
                    close = true;
                    false
                }
            }
        });
        if close {
            c.close();
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<akio::Error>) {
        if let Some(side) = self.side.upgrade() {
            side.closed(c, self.active);
        }
    }
}
