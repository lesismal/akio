//! TCP allocations of a [`TurnServer`](crate::TurnServer) (RFC 6062) over `akio`: the
//! listening sockets on relayed addresses, connections to and from peers, client data
//! connections, and the relay between the two.
//!
//! - A relayed address is a non-blocking TCP listener bound with `SO_REUSEPORT`, so that
//!   connections to peers can leave from the same address. One thread per server
//!   ("akio-turn-tcp-accept") polls every listener ([`akio_sys::Poller`]) and hands accepted
//!   connections to the engine ([`akio::Engine::adopt_tcp`]): no thread per allocation, and no
//!   I/O thread ever waits on `accept`.
//! - The connection of a Connect is opened by that thread too: a non-blocking connect from the
//!   relayed address ([`akio_sys::connect_nonblocking_from`]), polled until it is writable, then
//!   adopted by the engine. The engine's `Config::connect_timeout` does not apply: the core's
//!   `TurnConfig::tcp_connect_timeout` decides when it fails, and an attempt whose connection
//!   the core has given up on is abandoned within a second.
//! - Each connection of an allocation is a [`Link`] in a server-wide table keyed by its
//!   `CONNECTION-ID`: the allocation's client and shard (a ConnectionBind arrives on another
//!   connection, which lives in another shard), and the [`Pair`] of `akio` connections.
//! - Until it is bound, what the peer sends is held, up to `TurnConfig::tcp_relay_buffer`
//!   bytes; reading the peer then pauses, which closes its TCP window (RFC 6062 section 5.2).
//! - Once bound, bytes go from one connection straight to the other, never through a shard
//!   lock: when one side's send queue passes `tcp_relay_buffer`, reading the other side pauses
//!   (`hold_reads`) until it drains (`on_drain`). Both connections are marked relayed
//!   ([`Conn::set_relayed`]) so that the engine's own write backpressure cannot deadlock them.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use akio::{Acceptor, Conn, Handler};
use akio_sys::{Event, Poller, Waker};

use crate::{Inner, TurnStreamClient, lock};

/// Pending connections a relayed address's listener queues.
const BACKLOG: i32 = 64;
/// Binds of a relay listener whose port turned out to be another relay's (with `SO_REUSEPORT`
/// the kernel may hand out a port twice) before giving up.
const BIND_TRIES: usize = 16;

/// The TCP side of a server: listeners, connections, the accept thread.
#[derive(Default)]
pub(crate) struct TcpRelays {
    /// Listeners by bound address: the shard of their allocation and their accept-loop token.
    listeners: Mutex<HashMap<SocketAddr, (usize, u64)>>,
    /// Connections by id.
    links: Mutex<HashMap<u32, Link>>,
    accept: OnceLock<Option<Arc<AcceptLoop>>>,
    next_token: AtomicU64,
}

/// A connection of a TCP allocation.
pub(crate) struct Link {
    /// The allocation's client (its control connection's address) and its shard.
    pub(crate) client: SocketAddr,
    pub(crate) shard: usize,
    pub(crate) pair: Arc<Pair>,
}

/// The two `akio` connections of a TCP relay connection.
#[derive(Default)]
pub(crate) struct Pair(Mutex<PairState>);

#[derive(Default)]
struct PairState {
    /// The connection with the peer, once open.
    peer: Option<Conn<TcpPeer>>,
    /// The client's data connection, once bound.
    data: Option<Conn<TurnStreamClient>>,
    /// The peer's bytes waiting for the bind.
    early: Vec<u8>,
    /// Reading the peer is paused until the bind.
    held: bool,
    /// The peer's connection closed.
    closed: bool,
}

impl Pair {
    fn with_peer(c: Conn<TcpPeer>) -> Arc<Pair> {
        Arc::new(Pair(Mutex::new(PairState {
            peer: Some(c),
            ..PairState::default()
        })))
    }

    fn close(&self) {
        let p = lock(&self.0);
        if let Some(c) = &p.peer {
            c.close();
        }
        if let Some(c) = &p.data {
            c.close();
        }
    }
}

impl TcpRelays {
    /// Opens a relay listener on `addr` for an allocation in `shard`.
    pub(crate) fn open(
        &self,
        inner: &Inner,
        addr: SocketAddr,
        shard: usize,
    ) -> io::Result<SocketAddr> {
        let Some(accept) = self.accept_loop(inner) else {
            return Err(io::Error::other("no accept thread"));
        };
        for _ in 0..BIND_TRIES {
            let l = akio_sys::listen(addr, true, BACKLOG)?;
            let bound = l.local_addr()?;
            let token = self.next_token.fetch_add(1, Ordering::Relaxed) + 1;
            {
                let mut ls = lock(&self.listeners);
                if ls.contains_key(&bound) {
                    continue; // another relay's port: try again
                }
                ls.insert(bound, (shard, token));
            }
            lock(&accept.cmds).push(Cmd::Add(token, l, bound));
            accept.waker.wake();
            return Ok(bound);
        }
        Err(io::ErrorKind::AddrInUse.into())
    }

    /// Closes the relay listener bound at `relay`.
    pub(crate) fn close(&self, relay: SocketAddr) {
        let Some((_, token)) = lock(&self.listeners).remove(&relay) else {
            return;
        };
        if let Some(Some(a)) = self.accept.get() {
            lock(&a.cmds).push(Cmd::Remove(token));
            a.waker.wake();
        }
    }

    /// Hands a connect in progress (connection `id` of a Connect) to the accept thread.
    fn connecting(&self, inner: &Inner, s: TcpStream, id: u32) -> io::Result<()> {
        let Some(accept) = self.accept_loop(inner) else {
            return Err(io::Error::other("no accept thread"));
        };
        let token = self.next_token.fetch_add(1, Ordering::Relaxed) + 1;
        lock(&accept.cmds).push(Cmd::Connect(token, s, id));
        accept.waker.wake();
        Ok(())
    }

    pub(crate) fn link(&self, id: u32) -> Option<(SocketAddr, usize, Arc<Pair>)> {
        lock(&self.links)
            .get(&id)
            .map(|l| (l.client, l.shard, l.pair.clone()))
    }

    pub(crate) fn insert(&self, id: u32, link: Link) {
        lock(&self.links).insert(id, link);
    }

    /// Forgets connection `id` and closes both of its connections.
    pub(crate) fn close_link(&self, id: u32) {
        let l = lock(&self.links).remove(&id);
        if let Some(l) = l {
            l.pair.close();
        }
    }

    fn accept_loop(&self, inner: &Inner) -> Option<&Arc<AcceptLoop>> {
        self.accept
            .get_or_init(|| AcceptLoop::start(inner.me.clone()).ok())
            .as_ref()
    }
}

enum Cmd {
    Add(u64, TcpListener, SocketAddr),
    Remove(u64),
    /// A connect in progress for connection id `.2`.
    Connect(u64, TcpStream, u32),
}

/// The thread accepting connections on every relay listener of a server.
struct AcceptLoop {
    cmds: Mutex<Vec<Cmd>>,
    waker: Waker,
}

impl AcceptLoop {
    fn start(inner: Weak<Inner>) -> io::Result<Arc<AcceptLoop>> {
        let mut poller = Poller::new()?;
        let waker = Waker::new(&poller, 0)?;
        let al = Arc::new(AcceptLoop {
            cmds: Mutex::new(Vec::new()),
            waker,
        });
        let me = al.clone();
        std::thread::Builder::new()
            .name("akio-turn-tcp-accept".into())
            .spawn(move || me.run(&mut poller, &inner))?;
        Ok(al)
    }

    fn run(&self, poller: &mut Poller, inner: &Weak<Inner>) {
        let mut listeners: HashMap<u64, (TcpListener, SocketAddr)> = HashMap::new();
        // Connects in progress: the socket and the connection id.
        let mut connecting: HashMap<u64, (TcpStream, u32)> = HashMap::new();
        let mut events: Vec<Event> = Vec::new();
        let mut swept = Instant::now();
        loop {
            events.clear(); // `wait` appends
            let _ = poller.wait(&mut events, Some(Duration::from_secs(1)));
            let Some(inner) = inner.upgrade() else {
                return; // the server is gone: its listeners close with this thread
            };
            let cmds = std::mem::take(&mut *lock(&self.cmds));
            for cmd in cmds {
                match cmd {
                    Cmd::Add(token, l, relay) => {
                        if poller.add(l.as_raw_fd(), token, true, false).is_ok() {
                            listeners.insert(token, (l, relay));
                        }
                    }
                    Cmd::Remove(token) => {
                        if let Some((l, _)) = listeners.remove(&token) {
                            poller.delete(l.as_raw_fd());
                        }
                    }
                    Cmd::Connect(token, s, id) => {
                        if poller.add(s.as_raw_fd(), token, false, true).is_ok() {
                            connecting.insert(token, (s, id));
                        } else {
                            connect_failed(&inner, id);
                        }
                    }
                }
            }
            for ev in &events {
                if ev.token == 0 {
                    self.waker.drain();
                    continue;
                }
                if let Some((s, id)) = connecting.remove(&ev.token) {
                    poller.delete(s.as_raw_fd());
                    connected(&inner, s, id);
                    continue;
                }
                let Some((l, relay)) = listeners.get(&ev.token) else {
                    continue;
                };
                loop {
                    match l.accept() {
                        Ok((s, _)) => accepted(&inner, s, *relay),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => {
                            // Out of descriptors and the like: let the backlog wait.
                            std::thread::sleep(Duration::from_millis(10));
                            break;
                        }
                    }
                }
            }
            // Attempts the core gave up on (`tcp_connect_timeout`) or whose allocation went.
            if !connecting.is_empty() && swept.elapsed() >= Duration::from_secs(1) {
                swept = Instant::now();
                let links = lock(&inner.tcp.links);
                connecting.retain(|_, (s, id)| {
                    let wanted = links.contains_key(id);
                    if !wanted {
                        poller.delete(s.as_raw_fd());
                    }
                    wanted
                });
            }
        }
    }
}

/// A connection accepted on relay `relay`: served by the engine, checked on its I/O thread.
fn accepted(inner: &Arc<Inner>, s: TcpStream, relay: SocketAddr) {
    let Ok(engine) = inner.engine() else {
        return;
    };
    let _ = s.set_nodelay(true);
    let acceptor = PeerAcceptor {
        inner: inner.me.clone(),
        how: How::Accepted(relay),
    };
    engine.adopt_tcp(s, acceptor, |_| {});
}

/// Starts the connection from `relay` to `peer` of a Connect (link `id` is registered): a
/// non-blocking connect the accept thread watches, with no deadline but the core's.
pub(crate) fn dial(inner: &Arc<Inner>, relay: SocketAddr, peer: SocketAddr, id: u32) {
    let started = inner.engine().and_then(|_| {
        let s = akio_sys::connect_nonblocking_from(relay, peer)?;
        inner.tcp.connecting(inner, s, id)
    });
    if started.is_err() {
        connect_failed(inner, id);
    }
}

/// The connect of connection `id` finished (the socket turned writable): the engine serves it
/// when it succeeded.
fn connected(inner: &Arc<Inner>, s: TcpStream, id: u32) {
    let ok = matches!(s.take_error(), Ok(None)) && s.peer_addr().is_ok();
    let engine = inner.engine();
    let (true, Ok(engine)) = (ok, engine) else {
        connect_failed(inner, id);
        return;
    };
    let _ = s.set_nodelay(true);
    let acceptor = PeerAcceptor {
        inner: inner.me.clone(),
        how: How::Dialed(id),
    };
    let weak = inner.me.clone();
    engine.adopt_tcp(s, acceptor, move |_| {
        if let Some(inner) = weak.upgrade() {
            connect_failed(&inner, id);
        }
    });
}

fn connect_failed(inner: &Inner, id: u32) {
    let l = lock(&inner.tcp.links).remove(&id);
    if let Some(l) = l {
        inner.with_shard(l.shard, Vec::new(), |core, env| {
            core.tcp_connected(Instant::now(), l.client, id, false, env);
        });
    }
}

enum How {
    /// The connection of a Connect.
    Dialed(u32),
    /// A connection accepted on this relay.
    Accepted(SocketAddr),
}

struct PeerAcceptor {
    inner: Weak<Inner>,
    how: How,
}

impl Acceptor for PeerAcceptor {
    type Handler = TcpPeer;

    fn on_open(&self, c: &Conn<TcpPeer>) -> TcpPeer {
        c.set_relayed(true);
        let dead = || TcpPeer {
            inner: Weak::new(),
            id: 0,
            pair: Arc::default(),
            data: None,
            limit: 0,
        };
        let Some(inner) = self.inner.upgrade() else {
            c.close();
            return dead();
        };
        let limit = inner.shared.config().tcp_relay_buffer;
        let now = Instant::now();
        match self.how {
            How::Dialed(id) => {
                let Some((client, shard, pair)) = inner.tcp.link(id) else {
                    c.close(); // given up on meanwhile
                    return dead();
                };
                lock(&pair.0).peer = Some(c.clone());
                let ok = inner.with_shard(shard, Vec::new(), |core, env| {
                    core.tcp_connected(now, client, id, true, env)
                });
                if !ok {
                    inner.tcp.close_link(id);
                    c.close();
                }
                TcpPeer {
                    inner: self.inner.clone(),
                    id,
                    pair,
                    data: None,
                    limit,
                }
            }
            How::Accepted(relay) => {
                let shard = lock(&inner.tcp.listeners).get(&relay).map(|x| x.0);
                let Some(shard) = shard else {
                    c.close();
                    return dead();
                };
                let pair = Pair::with_peer(c.clone());
                let id = inner.with_shard(shard, Vec::new(), |core, env| {
                    env.incoming = Some(pair.clone());
                    core.tcp_incoming(now, relay, c.peer_addr(), env)
                });
                match id {
                    Some(id) => TcpPeer {
                        inner: self.inner.clone(),
                        id,
                        pair,
                        data: None,
                        limit,
                    },
                    None => {
                        // No permission for this peer (or no room): closed right away.
                        c.close();
                        dead()
                    }
                }
            }
        }
    }

    fn on_shutdown(&self, c: &Conn<TcpPeer>) {
        c.close();
    }
}

/// The server's connection with a peer of a TCP allocation (internal).
#[doc(hidden)]
pub struct TcpPeer {
    inner: Weak<Inner>,
    id: u32,
    pair: Arc<Pair>,
    /// The client's data connection, once bound (copied out of the pair once).
    data: Option<Conn<TurnStreamClient>>,
    limit: usize,
}

impl std::fmt::Debug for TcpPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpPeer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Handler for TcpPeer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(d) = &self.data {
            forward(c, d, data, self.limit);
            return;
        }
        let mut p = lock(&self.pair.0);
        match p.data.clone() {
            Some(d) => {
                drop(p);
                forward(c, &d, data, self.limit);
                self.data = Some(d);
            }
            None => {
                // Held for the bind; past the mark, the peer waits (RFC 6062 section 5.2).
                p.early.extend_from_slice(data);
                if p.early.len() >= self.limit {
                    p.held = true;
                    c.hold_reads(true);
                }
            }
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        let data = {
            let mut p = lock(&self.pair.0);
            p.closed = true;
            p.data.clone()
        };
        if let Some(d) = data {
            d.close(); // RFC 6062 section 5.5
        }
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let l = lock(&inner.tcp.links).remove(&self.id);
        if let Some(l) = l {
            inner.with_shard(l.shard, Vec::new(), |core, env| {
                core.tcp_closed(l.client, self.id, env);
            });
        }
    }
}

/// Binds the client data connection `c` to connection `pair`: what the peer sent meanwhile
/// goes first (after `response`, the ConnectionBind success). The peer's connection, or `None`
/// when it is gone (`c` is closed then).
pub(crate) fn bind(
    pair: &Pair,
    c: &Conn<TurnStreamClient>,
    response: Vec<u8>,
) -> Option<Conn<TcpPeer>> {
    let mut p = lock(&pair.0);
    let peer = p.peer.clone().filter(|_| !p.closed);
    let _ = c.send_owned(response);
    let Some(peer) = peer else {
        c.close_after_send();
        return None;
    };
    c.set_relayed(true);
    p.data = Some(c.clone());
    let early = std::mem::take(&mut p.early);
    if !early.is_empty() {
        let _ = c.send_owned(early);
    }
    if std::mem::take(&mut p.held) {
        peer.hold_reads(false);
    }
    Some(peer)
}

/// Relays `data` read from `from` to `to`; while `to` has more than `limit` bytes queued,
/// reading `from` pauses (resumed when `to` drains or closes).
pub(crate) fn forward<A: 'static, B>(from: &Conn<A>, to: &Conn<B>, data: &[u8], limit: usize) {
    if to.send(data).is_err() {
        from.close();
        return;
    }
    if to.queued_bytes() > limit {
        from.hold_reads(true);
        let f = from.clone();
        to.on_drain(move || f.hold_reads(false));
    }
}
