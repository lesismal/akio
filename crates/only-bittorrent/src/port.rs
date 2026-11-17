//! One UDP port shared by uTP, the DHT and anything else: a [`UdpPort`] is the acceptor of a
//! `only` UDP [`Listener`](only::Listener). It sorts each datagram by its first byte (uTP
//! packets to their [`UtpStream`]s, everything else, such as the DHT's bencoded `d...`, to the
//! function [`UdpPort::on_datagram`] sets) and sends from the listener's own port, opening a
//! peer on the listener socket ([`only::Engine::dial_udp_from`]) for an address that has not
//! written first, so a DHT node and uTP connections are reachable at the port they announce.
//!
//! On a dual-stack listener (`[::]:port`) IPv4 peers are reported by their plain IPv4 address
//! (not `::ffff:a.b.c.d`), and datagrams to an IPv4 address leave mapped.
//!
//! ```no_run
//! use std::sync::Arc;
//! use only::{Engine, Listener};
//! use only_bittorrent::port::UdpPort;
//! let port = UdpPort::new();
//! let engine = Arc::new(
//!     Engine::builder()
//!         .listen(Listener::udp("0.0.0.0:6881".parse().unwrap()).serve(port.acceptor()))
//!         .build()
//!         .unwrap(),
//! );
//! engine.start().unwrap();
//! port.attach(&engine, engine.local_addrs()[0]);
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use only::{Engine, EngineRef};
use only_core::{Acceptor, Conn, ConnInner, Handler};

use crate::utp::{self, Connection, Event, Header};

/// Callbacks of one uTP stream. They run on an I/O thread or the port's timer thread, one at a
/// time per stream, and may write to any stream.
pub trait StreamHandler: Send + 'static {
    /// The handshake completed (a dialed stream), or the stream was accepted.
    fn on_connect(&mut self, _s: &UtpStream) {}
    /// Bytes arrived, in order.
    fn on_data(&mut self, s: &UtpStream, data: &[u8]);
    /// The peer finished sending. The default closes this side too.
    fn on_eof(&mut self, s: &UtpStream) {
        s.close();
    }
    /// The stream is gone (`None`: an orderly close); called once.
    fn on_close(&mut self, _s: &UtpStream, _err: Option<io::ErrorKind>) {}
}

type Shared = Arc<Mutex<Box<dyn StreamHandler>>>;
type AcceptFn = Arc<dyn Fn(&UtpStream) -> Option<Box<dyn StreamHandler>> + Send + Sync>;
type DatagramFn = Arc<dyn Fn(SocketAddr, &[u8]) + Send + Sync>;

#[derive(Default)]
struct Route {
    conn: Option<Arc<ConnInner>>,
    pending: Vec<Vec<u8>>,
    opening: bool,
}

struct Entry {
    conn: Connection,
    handler: Shared,
    /// Accepted from a SYN (counted against [`UdpPort::set_max_inbound`]).
    inbound: bool,
}

#[derive(Default)]
struct State {
    routes: HashMap<SocketAddr, Route>,
    utp: HashMap<(SocketAddr, u16), Entry>,
    /// Entries of `utp` with `inbound` set.
    inbound: usize,
}

impl State {
    fn remove_utp(&mut self, k: &(SocketAddr, u16)) -> Option<Entry> {
        let e = self.utp.remove(k)?;
        if e.inbound {
            self.inbound -= 1;
        }
        Some(e)
    }
}

/// Default [`UdpPort::set_max_inbound`].
pub const DEFAULT_MAX_INBOUND_UTP: usize = 1024;

struct Inner {
    engine: EngineRef,
    local: Mutex<Option<SocketAddr>>,
    state: Mutex<State>,
    on_accept: Mutex<Option<AcceptFn>>,
    on_datagram: Mutex<Option<DatagramFn>>,
    epoch: Instant,
    max_inbound: AtomicUsize,
}

/// A UDP port shared by uTP and other datagram protocols. Cheap to clone.
#[derive(Clone)]
pub struct UdpPort {
    inner: Arc<Inner>,
}

impl fmt::Debug for UdpPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPort").finish_non_exhaustive()
    }
}

/// A uTP connection on a [`UdpPort`]. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct UtpStream {
    inner: Weak<Inner>,
    peer: SocketAddr,
    id: u16,
}

impl fmt::Debug for UtpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UtpStream({}, {})", self.peer, self.id)
    }
}

enum Delivery {
    Connect,
    Event(Event),
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Default for UdpPort {
    fn default() -> Self {
        UdpPort::new()
    }
}

impl UdpPort {
    /// A port with nothing attached. Starts its timer thread (10 ms), which ends when the last
    /// clone is dropped.
    pub fn new() -> UdpPort {
        let inner = Arc::new(Inner {
            engine: EngineRef::new(),
            local: Mutex::new(None),
            state: Mutex::new(State::default()),
            on_accept: Mutex::new(None),
            on_datagram: Mutex::new(None),
            epoch: Instant::now(),
            max_inbound: AtomicUsize::new(DEFAULT_MAX_INBOUND_UTP),
        });
        let weak = Arc::downgrade(&inner);
        let _ = std::thread::Builder::new()
            .name("only-bt-utp".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(10));
                    let Some(inner) = weak.upgrade() else { return };
                    tick(&inner);
                }
            });
        UdpPort { inner }
    }

    /// The acceptor to serve the UDP listener with.
    pub fn acceptor(&self) -> PortAcceptor {
        PortAcceptor {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Ties the port to its started engine and the bound address of the UDP listener it serves
    /// (as [`Engine::local_addrs`] reports it): needed to send to an address that has not
    /// written first.
    pub fn attach(&self, engine: &Arc<Engine>, local: SocketAddr) {
        self.inner.engine.set(engine);
        *lock(&self.inner.local) = Some(local);
    }

    /// The listener's address, once set.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *lock(&self.inner.local)
    }

    /// Accepts incoming uTP connections: `f` returns the stream's handler, or `None` to refuse.
    /// It runs with the port locked: it must not use any stream (do that in `on_connect`).
    pub fn on_accept(
        &self,
        f: impl Fn(&UtpStream) -> Option<Box<dyn StreamHandler>> + Send + Sync + 'static,
    ) {
        *lock(&self.inner.on_accept) = Some(Arc::new(f));
    }

    /// Most incoming uTP connections at once (default 1024). A SYN beyond it is dropped without
    /// an answer or an `on_accept` call: a SYN costs its sender nothing and may come from a
    /// spoofed address, so without a cap a flood would fill the table (each accepted stream
    /// lives until its idle timeout). Outgoing connections are not counted.
    pub fn set_max_inbound(&self, n: usize) {
        self.inner.max_inbound.store(n, Ordering::Relaxed);
    }

    /// Receives every datagram that is not uTP (on an I/O thread; `data` valid during the call).
    pub fn on_datagram(&self, f: impl Fn(SocketAddr, &[u8]) + Send + Sync + 'static) {
        *lock(&self.inner.on_datagram) = Some(Arc::new(f));
    }

    /// Sends a datagram from the port to `to`.
    pub fn send_to(&self, to: SocketAddr, data: Vec<u8>) {
        send_all(&self.inner, to, vec![data]);
    }

    /// Starts a uTP connection to `to`; `handler` hears `on_connect` once it is up, or
    /// `on_close` with an error.
    pub fn connect(&self, to: SocketAddr, handler: impl StreamHandler) -> UtpStream {
        let to = canonical(to);
        let now = micros(&self.inner);
        let mut out = Vec::new();
        let id;
        {
            let mut st = lock(&self.inner.state);
            let mut r = crate::rand_u32() as u16;
            while st.utp.contains_key(&(to, r)) || st.utp.contains_key(&(to, r.wrapping_add(1))) {
                r = r.wrapping_add(2);
            }
            id = r;
            let conn = Connection::connect(id, now, &mut out);
            st.utp.insert(
                (to, id),
                Entry {
                    conn,
                    handler: Arc::new(Mutex::new(Box::new(handler))),
                    inbound: false,
                },
            );
        }
        send_all(&self.inner, to, out);
        UtpStream {
            inner: Arc::downgrade(&self.inner),
            peer: to,
            id,
        }
    }

    /// uTP connections open.
    pub fn utp_connections(&self) -> usize {
        lock(&self.inner.state).utp.len()
    }
}

/// `::ffff:a.b.c.d` as `a.b.c.d`.
pub(crate) fn canonical(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

/// The address to send to `to` at from a socket bound at `local`: IPv4 mapped on a dual-stack
/// socket; `None` for IPv6 from an IPv4 socket.
fn wire_addr(local: SocketAddr, to: SocketAddr) -> Option<SocketAddr> {
    match (local, to) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => Some(SocketAddr::new(
            std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()),
            v4.port(),
        )),
        (SocketAddr::V4(_), SocketAddr::V6(_)) => None,
        _ => Some(to),
    }
}

fn micros(inner: &Inner) -> u64 {
    inner.epoch.elapsed().as_micros() as u64
}

/// Sends `pkts` to `to` through its route, opening one if needed.
fn send_all(inner: &Arc<Inner>, to: SocketAddr, pkts: Vec<Vec<u8>>) {
    if pkts.is_empty() {
        return;
    }
    let to = canonical(to);
    let open = {
        let mut st = lock(&inner.state);
        let r = st.routes.entry(to).or_default();
        if let Some(c) = &r.conn {
            for p in pkts {
                let _ = c.send_owned(p);
            }
            return;
        }
        if r.pending.len() < 256 {
            r.pending.extend(pkts);
        }
        let open = !r.opening;
        r.opening = true;
        open
    };
    if !open {
        return;
    }
    let (Some(engine), Some(local)) = (inner.engine.get(), *lock(&inner.local)) else {
        lock(&inner.state).routes.remove(&to);
        return;
    };
    let Some(dest) = wire_addr(local, to) else {
        lock(&inner.state).routes.remove(&to);
        return;
    };
    let weak = Arc::downgrade(inner);
    let weak2 = weak.clone();
    engine.dial_udp_from(local, dest, PortAcceptor { inner: weak }, move |e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            return; // the listener's own peer registers and flushes
        }
        if let Some(inner) = weak2.upgrade() {
            let mut st = lock(&inner.state);
            if st.routes.get(&to).is_some_and(|r| r.conn.is_none()) {
                st.routes.remove(&to);
            }
        }
    });
}

/// Hands the effects of a uTP step to their peers and handlers.
fn deliver(
    inner: &Arc<Inner>,
    peer: SocketAddr,
    id: u16,
    sends: Vec<Vec<u8>>,
    events: Vec<(Shared, Delivery)>,
) {
    send_all(inner, peer, sends);
    let s = UtpStream {
        inner: Arc::downgrade(inner),
        peer,
        id,
    };
    for (h, d) in events {
        let mut h = lock(&h);
        match d {
            Delivery::Connect => h.on_connect(&s),
            Delivery::Event(Event::Connected) => h.on_connect(&s),
            Delivery::Event(Event::Data(d)) => h.on_data(&s, &d),
            Delivery::Event(Event::Eof) => h.on_eof(&s),
            Delivery::Event(Event::Closed(e)) => h.on_close(&s, e),
        }
    }
}

fn tick(inner: &Arc<Inner>) {
    let now = micros(inner);
    let mut work = Vec::new();
    {
        let mut st = lock(&inner.state);
        let mut gone = Vec::new();
        for (&(peer, id), e) in &mut st.utp {
            let mut sends = Vec::new();
            let mut evs = Vec::new();
            e.conn.on_tick(now, &mut sends, &mut evs);
            if e.conn.is_closed() {
                gone.push((peer, id));
            }
            if !sends.is_empty() || !evs.is_empty() {
                let evs = evs
                    .into_iter()
                    .map(|ev| (e.handler.clone(), Delivery::Event(ev)))
                    .collect();
                work.push((peer, id, sends, evs));
            }
        }
        for k in gone {
            st.remove_utp(&k);
        }
    }
    for (peer, id, sends, evs) in work {
        deliver(inner, peer, id, sends, evs);
    }
}

fn on_utp(inner: &Arc<Inner>, peer: SocketAddr, data: &[u8]) {
    let Some((h, sack, payload)) = Header::parse(data) else {
        return;
    };
    let now = micros(inner);
    let mut sends = Vec::new();
    let mut evs = Vec::new();
    let mut id = h.conn_id;
    {
        let mut st = lock(&inner.state);
        if h.typ == utp::ST_SYN {
            id = h.conn_id.wrapping_add(1);
            if let Some(e) = st.utp.get_mut(&(peer, id)) {
                let mut ev = Vec::new();
                e.conn
                    .on_packet(&h, sack, payload, now, &mut sends, &mut ev);
            } else {
                if st.inbound >= inner.max_inbound.load(Ordering::Relaxed) {
                    return;
                }
                let accept = lock(&inner.on_accept).clone();
                let Some(accept) = accept else { return };
                let stream = UtpStream {
                    inner: Arc::downgrade(inner),
                    peer,
                    id,
                };
                let Some(handler) = accept(&stream) else {
                    return;
                };
                let conn = Connection::accept(&h, now, &mut sends);
                let handler: Shared = Arc::new(Mutex::new(handler));
                evs.push((handler.clone(), Delivery::Connect));
                st.utp.insert(
                    (peer, id),
                    Entry {
                        conn,
                        handler,
                        inbound: true,
                    },
                );
                st.inbound += 1;
            }
        } else if let Some(e) = st.utp.get_mut(&(peer, id)) {
            let mut ev = Vec::new();
            e.conn
                .on_packet(&h, sack, payload, now, &mut sends, &mut ev);
            evs.extend(
                ev.into_iter()
                    .map(|x| (e.handler.clone(), Delivery::Event(x))),
            );
            if e.conn.is_closed() {
                st.remove_utp(&(peer, id));
            }
        } else if h.typ != utp::ST_RESET {
            sends.push(utp::reset_for(&h, now));
        }
    }
    deliver(inner, peer, id, sends, evs);
}

impl UtpStream {
    /// The peer's address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn with<R>(&self, f: impl FnOnce(&mut Connection, u64, &mut Vec<Vec<u8>>) -> R) -> Option<R> {
        let inner = self.inner.upgrade()?;
        let now = micros(&inner);
        let mut sends = Vec::new();
        let r = {
            let mut st = lock(&inner.state);
            let e = st.utp.get_mut(&(self.peer, self.id))?;
            f(&mut e.conn, now, &mut sends)
        };
        send_all(&inner, self.peer, sends);
        Some(r)
    }

    /// Queues bytes (never blocks); fails once the stream is closed.
    pub fn write(&self, data: &[u8]) -> io::Result<()> {
        self.with(|c, now, out| c.write(data, now, out))
            .unwrap_or_else(|| Err(io::ErrorKind::NotConnected.into()))
    }

    /// Bytes written and not yet acknowledged (for pacing).
    pub fn buffered(&self) -> usize {
        self.with(|c, _, _| c.buffered()).unwrap_or(0)
    }

    /// Closes after what is queued is delivered (FIN).
    pub fn close(&self) {
        self.with(|c, now, out| c.close(now, out));
    }

    /// Drops the connection at once (RESET); the handler hears `on_close` with an error.
    pub fn abort(&self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let now = micros(&inner);
        let mut sends = Vec::new();
        let handler = {
            let mut st = lock(&inner.state);
            st.remove_utp(&(self.peer, self.id)).map(|mut e| {
                e.conn.abort(now, &mut sends);
                e.handler
            })
        };
        send_all(&inner, self.peer, sends);
        if let Some(h) = handler {
            lock(&h).on_close(self, Some(io::ErrorKind::ConnectionAborted));
        }
    }

    /// Whether the stream is still open.
    pub fn is_open(&self) -> bool {
        self.with(|c, _, _| !c.is_closed()).unwrap_or(false)
    }

    /// Smoothed round-trip time.
    pub fn rtt(&self) -> Duration {
        Duration::from_micros(self.with(|c, _, _| c.rtt_us()).unwrap_or(0))
    }
}

/// The acceptor of the UDP listener a [`UdpPort`] serves.
#[derive(Clone)]
pub struct PortAcceptor {
    inner: Weak<Inner>,
}

impl fmt::Debug for PortAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PortAcceptor")
    }
}

/// One peer address of the port's listener.
#[derive(Debug)]
pub struct PortPeer {
    inner: Weak<Inner>,
    id: u64,
}

impl Acceptor for PortAcceptor {
    type Handler = PortPeer;
    fn on_open(&self, c: &Conn<PortPeer>) -> PortPeer {
        if let Some(inner) = self.inner.upgrade() {
            let mut st = lock(&inner.state);
            let r = st.routes.entry(canonical(c.peer_addr())).or_default();
            r.conn = Some(c.inner().clone());
            r.opening = false;
            for p in std::mem::take(&mut r.pending) {
                let _ = c.send_owned(p);
            }
        }
        PortPeer {
            inner: self.inner.clone(),
            id: c.id(),
        }
    }
}

impl Handler for PortPeer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let peer = canonical(c.peer_addr());
        if utp::is_utp(data) {
            on_utp(&inner, peer, data);
        } else {
            let f = lock(&inner.on_datagram).clone();
            if let Some(f) = f {
                f(peer, data);
            }
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only_core::Error>) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut st = lock(&inner.state);
        let peer = canonical(c.peer_addr());
        if st
            .routes
            .get(&peer)
            .is_some_and(|r| r.conn.as_ref().is_some_and(|x| x.id() == self.id))
        {
            st.routes.remove(&peer);
        }
    }
}
