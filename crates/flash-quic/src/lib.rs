//! QUIC for flash, on the sans-io [`quinn-proto`](https://docs.rs/quinn-proto) state machine.
//!
//! A [`QuicServer`] is the acceptor of a UDP [`flash::Listener`]: every datagram goes through one
//! `quinn_proto::Endpoint`, which routes it to its connection by connection id (so a peer that
//! migrates to another address keeps its connection). Each connection gets a [`QuicHandler`]
//! from the server's factory; [`dial`] starts a client connection on an engine with UDP client
//! threads. A connection's callbacks run one at a time, in order, on the I/O thread that read
//! the datagram or on the shared timer thread; they must not block.
//!
//! Writes never block: [`Connection::send`] hands quinn what flow control allows and keeps the
//! rest until the peer grants more credit ([`Connection::queued_bytes`] paces a producer).
//!
//! ```no_run
//! use bytes::Bytes;
//! use flash::{Engine, Listener};
//! use flash_quic::{Connection, QuicHandler, QuicServer, StreamId};
//!
//! struct Echo;
//! impl QuicHandler for Echo {
//!     fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
//!         let _ = c.send(id, data);
//!         if fin {
//!             let _ = c.finish(id);
//!         }
//!     }
//! }
//! # let (certs, key) = (vec![], rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()));
//! let cfg = flash_quic::server_config(certs, key, &[b"echo"]).unwrap();
//! let server = QuicServer::new(cfg, |_c: &Connection| Echo);
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:4433".parse().unwrap()).serve(server))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! Guide: [QUIC and HTTP/3](https://lesismal.github.io/flash/en/protocols/quic-h3.html)
//! (中文: [QUIC 与 HTTP/3](https://lesismal.github.io/flash/zh-CN/protocols/quic-h3.html)).
#![warn(clippy::unwrap_used)]

mod timer;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use flash_core::{Acceptor, Conn, Handler};
use quinn_proto as qp;

pub use qp::{ConnectionError, Dir, StreamId, TransportConfig, VarInt};
pub use quinn_proto as proto;
pub use rustls;

/// Errors of [`Connection`] calls and of the config helpers.
#[derive(Debug)]
pub enum Error {
    /// The connection is closed.
    Closed,
    /// No such stream, or not one this side can write (a peer's unidirectional stream) or read.
    UnknownStream,
    /// The peer stopped the stream (`STOP_SENDING`) with this code.
    Stopped(u64),
    /// The peer does not accept datagrams, or this one is too large.
    Datagram(String),
    /// Could not start a connection.
    Connect(qp::ConnectError),
    /// A TLS or QUIC configuration problem.
    Config(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Closed => f.write_str("quic: connection closed"),
            Error::UnknownStream => f.write_str("quic: unknown stream"),
            Error::Stopped(c) => write!(f, "quic: stream stopped by peer (code {c})"),
            Error::Datagram(e) => write!(f, "quic: datagram: {e}"),
            Error::Connect(e) => write!(f, "quic: connect: {e}"),
            Error::Config(e) => write!(f, "quic: config: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// The application side of a connection. Every method has a default except `on_stream_data`.
pub trait QuicHandler: Send + 'static {
    /// The handshake completed.
    fn on_connected(&mut self, _c: &Connection) {}
    /// The peer opened a stream (its data follows in `on_stream_data`).
    fn on_stream_opened(&mut self, _c: &Connection, _id: StreamId) {}
    /// Bytes of a stream, in order; `fin` marks its end (possibly with no bytes).
    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool);
    /// The peer abandoned sending on a stream (`RESET_STREAM`).
    fn on_stream_reset(&mut self, _c: &Connection, _id: StreamId, _code: u64) {}
    /// The peer asked us to stop sending on a stream (`STOP_SENDING`); queued data is dropped.
    fn on_stream_stopped(&mut self, _c: &Connection, _id: StreamId, _code: u64) {}
    /// More streams of `dir` may be opened (after `open_*` returned `None`).
    fn on_streams_available(&mut self, _c: &Connection, _dir: Dir) {}
    /// An unreliable datagram (RFC 9221).
    fn on_datagram(&mut self, _c: &Connection, _data: Bytes) {}
    /// The connection is over; called once, last.
    fn on_close(&mut self, _c: &Connection, _reason: ConnectionError) {}
}

enum Ev {
    Connected,
    Opened(StreamId),
    Data(StreamId, Bytes, bool),
    Reset(StreamId, u64),
    Stopped(StreamId, u64),
    Available(Dir),
    Datagram(Bytes),
    Closed(ConnectionError),
}

#[derive(Default)]
struct Pending {
    chunks: VecDeque<Bytes>,
    bytes: usize,
    fin: bool,
}

struct State {
    conn: qp::Connection,
    pending: HashMap<StreamId, Pending>,
    armed: Option<Instant>,
    lost: bool,
    buf: Vec<u8>,
}

struct Shared {
    h: qp::ConnectionHandle,
    ep: Arc<Ep>,
    me: Weak<Shared>,
    state: Mutex<State>,
    events: Mutex<VecDeque<Ev>>,
    handler: Mutex<Option<Box<dyn QuicHandler>>>,
    done: AtomicBool,
}

/// A QUIC connection. Cheap to clone and usable from any thread.
#[derive(Clone)]
pub struct Connection(Arc<Shared>);

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("remote", &self.remote_addr())
            .finish()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Connection {
    fn new(h: qp::ConnectionHandle, conn: qp::Connection, ep: Arc<Ep>) -> Connection {
        Connection(Arc::new_cyclic(|me| Shared {
            h,
            ep,
            me: me.clone(),
            state: Mutex::new(State {
                conn,
                pending: HashMap::new(),
                armed: None,
                lost: false,
                buf: Vec::new(),
            }),
            events: Mutex::new(VecDeque::new()),
            handler: Mutex::new(None),
            done: AtomicBool::new(false),
        }))
    }

    /// The peer's current address.
    pub fn remote_addr(&self) -> SocketAddr {
        lock(&self.0.state).conn.remote_address()
    }

    /// The negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<Vec<u8>> {
        let st = lock(&self.0.state);
        let hd = st.conn.crypto_session().handshake_data()?;
        hd.downcast::<qp::crypto::rustls::HandshakeData>()
            .ok()?
            .protocol
    }

    /// The SNI the client asked for (server side).
    pub fn server_name(&self) -> Option<String> {
        let st = lock(&self.0.state);
        let hd = st.conn.crypto_session().handshake_data()?;
        hd.downcast::<qp::crypto::rustls::HandshakeData>()
            .ok()?
            .server_name
    }

    /// The smoothed round-trip time.
    pub fn rtt(&self) -> Duration {
        lock(&self.0.state).conn.rtt()
    }

    /// quinn's connection statistics.
    pub fn stats(&self) -> qp::ConnectionStats {
        lock(&self.0.state).conn.stats()
    }

    /// Whether the connection is closed or closing.
    pub fn is_closed(&self) -> bool {
        lock(&self.0.state).conn.is_closed()
    }

    /// Opens a bidirectional stream; `None` while the peer's stream limit is reached (see
    /// [`QuicHandler::on_streams_available`]), which includes before the handshake completes
    /// (open streams from [`QuicHandler::on_connected`]).
    pub fn open_bi(&self) -> Option<StreamId> {
        lock(&self.0.state).conn.streams().open(Dir::Bi)
    }

    /// Opens a unidirectional stream; `None` while the peer's stream limit is reached.
    pub fn open_uni(&self) -> Option<StreamId> {
        lock(&self.0.state).conn.streams().open(Dir::Uni)
    }

    /// Queues bytes on a stream; what flow control allows goes out now, the rest as credit
    /// arrives.
    pub fn send(&self, id: StreamId, data: impl Into<Bytes>) -> Result<(), Error> {
        let data = data.into();
        let mut st = lock(&self.0.state);
        if st.conn.is_closed() {
            return Err(Error::Closed);
        }
        let State { conn, pending, .. } = &mut *st;
        if !can_send(conn, id) {
            return Err(Error::UnknownStream);
        }
        let p = pending.entry(id).or_default();
        if p.fin {
            return Err(Error::UnknownStream);
        }
        if !data.is_empty() {
            p.bytes += data.len();
            p.chunks.push_back(data);
        }
        let r = flush_stream(conn, id, p);
        if r.is_err() || (p.chunks.is_empty() && !p.fin) {
            pending.remove(&id);
        }
        drop(st);
        self.drive();
        r
    }

    /// Ends a stream once its queued bytes are out.
    pub fn finish(&self, id: StreamId) -> Result<(), Error> {
        let mut st = lock(&self.0.state);
        let State { conn, pending, .. } = &mut *st;
        if !can_send(conn, id) {
            return Err(Error::UnknownStream);
        }
        let p = pending.entry(id).or_default();
        p.fin = true;
        let r = flush_stream(conn, id, p);
        if r.is_err() || p.chunks.is_empty() {
            pending.remove(&id);
        }
        drop(st);
        self.drive();
        r
    }

    /// Abandons sending on a stream (`RESET_STREAM`), dropping what is queued.
    pub fn reset(&self, id: StreamId, code: u32) -> Result<(), Error> {
        let mut st = lock(&self.0.state);
        if !can_send(&st.conn, id) {
            return Err(Error::UnknownStream);
        }
        st.pending.remove(&id);
        let r = st
            .conn
            .send_stream(id)
            .reset(VarInt::from_u32(code))
            .map_err(|_| Error::UnknownStream);
        drop(st);
        self.drive();
        r
    }

    /// Asks the peer to stop sending on a stream (`STOP_SENDING`).
    pub fn stop(&self, id: StreamId, code: u32) -> Result<(), Error> {
        let mut st = lock(&self.0.state);
        if !can_recv(&st.conn, id) {
            return Err(Error::UnknownStream);
        }
        let r = st
            .conn
            .recv_stream(id)
            .stop(VarInt::from_u32(code))
            .map_err(|_| Error::UnknownStream);
        drop(st);
        self.drive();
        r
    }

    /// Bytes queued on a stream that quinn has not taken yet.
    pub fn queued_bytes(&self, id: StreamId) -> usize {
        lock(&self.0.state).pending.get(&id).map_or(0, |p| p.bytes)
    }

    /// Sends an unreliable datagram (needs the peer's support, RFC 9221).
    pub fn send_datagram(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        let mut st = lock(&self.0.state);
        let r = st
            .conn
            .datagrams()
            .send(data.into(), true)
            .map_err(|e| Error::Datagram(e.to_string()));
        drop(st);
        self.drive();
        r
    }

    /// Closes the connection with an application error code and reason; `on_close` gets
    /// `LocallyClosed`.
    pub fn close(&self, code: u32, reason: &[u8]) {
        let mut st = lock(&self.0.state);
        if st.conn.is_closed() {
            return;
        }
        st.conn.close(
            Instant::now(),
            VarInt::from_u32(code),
            Bytes::copy_from_slice(reason),
        );
        st.pending.clear();
        let first = !std::mem::replace(&mut st.lost, true);
        drop(st);
        if first {
            lock(&self.0.events).push_back(Ev::Closed(ConnectionError::LocallyClosed));
        }
        self.drive();
    }

    /// Polls quinn until it is quiet: app events, datagrams to send, endpoint events, the timer.
    fn drive(&self) {
        let ep = &self.0.ep;
        loop {
            let mut tx = Vec::new();
            let mut ep_events = Vec::new();
            let mut evs = Vec::new();
            let drained;
            {
                let mut st = lock(&self.0.state);
                let now = Instant::now();
                let State {
                    conn,
                    pending,
                    armed,
                    lost,
                    buf,
                } = &mut *st;
                while let Some(e) = conn.poll() {
                    match e {
                        qp::Event::HandshakeDataReady => {}
                        qp::Event::Connected => evs.push(Ev::Connected),
                        qp::Event::ConnectionLost { reason } => {
                            pending.clear();
                            if !std::mem::replace(lost, true) {
                                evs.push(Ev::Closed(reason));
                            }
                        }
                        qp::Event::Stream(se) => on_stream_event(conn, pending, se, &mut evs),
                        qp::Event::DatagramReceived => {
                            while let Some(d) = conn.datagrams().recv() {
                                evs.push(Ev::Datagram(d));
                            }
                        }
                        qp::Event::DatagramsUnblocked => {}
                    }
                }
                loop {
                    buf.clear();
                    match conn.poll_transmit(now, MAX_DATAGRAMS, buf) {
                        Some(t) => tx.push((t.destination, t.segment_size, buf[..t.size].to_vec())),
                        None => break,
                    }
                }
                while let Some(e) = conn.poll_endpoint_events() {
                    ep_events.push(e);
                }
                if let Some(t) = conn.poll_timeout() {
                    if armed.is_none_or(|a| t < a) {
                        *armed = Some(t);
                        let target: Weak<dyn timer::Due> = self.0.me.clone();
                        timer::timer().schedule(t, target);
                    }
                }
                drained = conn.is_drained();
                if drained && !std::mem::replace(lost, true) {
                    evs.push(Ev::Closed(ConnectionError::LocallyClosed));
                }
            }
            for (dest, seg, data) in tx {
                ep.transmit(dest, seg, data);
            }
            let mut again = false;
            for e in ep_events {
                let ce = lock(&ep.endpoint).handle_event(self.0.h, e);
                if let Some(ce) = ce {
                    lock(&self.0.state).conn.handle_event(ce);
                    again = true;
                }
            }
            if drained {
                lock(&ep.conns).remove(&self.0.h);
            }
            if !evs.is_empty() {
                lock(&self.0.events).extend(evs);
            }
            self.deliver();
            if !again {
                return;
            }
        }
    }

    /// Runs queued events through the handler, one deliverer at a time (a nested or concurrent
    /// call finds the handler taken and leaves its events to the one running).
    fn deliver(&self) {
        loop {
            if lock(&self.0.events).is_empty() {
                return;
            }
            let Some(mut h) = lock(&self.0.handler).take() else {
                if self.0.done.load(Ordering::Acquire) {
                    lock(&self.0.events).clear();
                }
                return;
            };
            let mut closed = false;
            loop {
                let ev = lock(&self.0.events).pop_front();
                let Some(ev) = ev else { break };
                match ev {
                    Ev::Connected => h.on_connected(self),
                    Ev::Opened(id) => h.on_stream_opened(self, id),
                    Ev::Data(id, d, fin) => h.on_stream_data(self, id, d, fin),
                    Ev::Reset(id, c) => h.on_stream_reset(self, id, c),
                    Ev::Stopped(id, c) => h.on_stream_stopped(self, id, c),
                    Ev::Available(d) => h.on_streams_available(self, d),
                    Ev::Datagram(d) => h.on_datagram(self, d),
                    Ev::Closed(r) => {
                        self.0.done.store(true, Ordering::Release);
                        h.on_close(self, r);
                        closed = true;
                        break;
                    }
                }
            }
            if closed {
                lock(&self.0.events).clear();
                return;
            }
            *lock(&self.0.handler) = Some(h);
        }
    }
}

impl timer::Due for Shared {
    fn fire(&self, at: Instant) {
        let Some(me) = self.me.upgrade() else { return };
        {
            let mut st = lock(&self.state);
            if st.armed != Some(at) {
                return;
            }
            st.armed = None;
            st.conn.handle_timeout(Instant::now());
        }
        Connection(me).drive();
    }
}

/// Whether `id` has a send side here (quinn panics on a peer's unidirectional stream).
fn can_send(conn: &qp::Connection, id: StreamId) -> bool {
    id.dir() == Dir::Bi || id.initiator() == conn.side()
}

/// Whether `id` has a receive side here (not one of our own unidirectional streams).
fn can_recv(conn: &qp::Connection, id: StreamId) -> bool {
    id.dir() == Dir::Bi || id.initiator() != conn.side()
}

/// Hands a stream's queued bytes to quinn; finishes it when they are all taken and `fin` is
/// set.
fn flush_stream(conn: &mut qp::Connection, id: StreamId, p: &mut Pending) -> Result<(), Error> {
    let mut s = conn.send_stream(id);
    while let Some(front) = p.chunks.front_mut() {
        match s.write(front) {
            Ok(n) => {
                p.bytes -= n;
                if n == front.len() {
                    p.chunks.pop_front();
                } else {
                    let _ = front.split_to(n);
                }
            }
            Err(qp::WriteError::Blocked) => return Ok(()),
            Err(qp::WriteError::Stopped(c)) => {
                p.chunks.clear();
                p.bytes = 0;
                return Err(Error::Stopped(c.into_inner()));
            }
            Err(qp::WriteError::ClosedStream) => {
                p.chunks.clear();
                p.bytes = 0;
                return Err(Error::UnknownStream);
            }
        }
    }
    if p.fin {
        return s.finish().map_err(|_| Error::UnknownStream);
    }
    Ok(())
}

fn read_stream(conn: &mut qp::Connection, id: StreamId, evs: &mut Vec<Ev>) {
    let mut rs = conn.recv_stream(id);
    let Ok(mut chunks) = rs.read(true) else {
        return;
    };
    let mut got: Vec<Bytes> = Vec::new();
    let mut fin = false;
    let mut reset = None;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(c)) => got.push(c.bytes),
            Ok(None) => {
                fin = true;
                break;
            }
            Err(qp::ReadError::Blocked) => break,
            Err(qp::ReadError::Reset(c)) => {
                reset = Some(c.into_inner());
                break;
            }
        }
    }
    let _ = chunks.finalize();
    let n = got.len();
    for (i, d) in got.into_iter().enumerate() {
        evs.push(Ev::Data(id, d, fin && i + 1 == n));
    }
    if fin && n == 0 {
        evs.push(Ev::Data(id, Bytes::new(), true));
    }
    if let Some(c) = reset {
        evs.push(Ev::Reset(id, c));
    }
}

fn on_stream_event(
    conn: &mut qp::Connection,
    pending: &mut HashMap<StreamId, Pending>,
    se: qp::StreamEvent,
    evs: &mut Vec<Ev>,
) {
    match se {
        qp::StreamEvent::Opened { dir } => {
            while let Some(id) = conn.streams().accept(dir) {
                evs.push(Ev::Opened(id));
                read_stream(conn, id, evs);
            }
        }
        qp::StreamEvent::Readable { id } => read_stream(conn, id, evs),
        qp::StreamEvent::Writable { id } => {
            if let Some(p) = pending.get_mut(&id) {
                let r = flush_stream(conn, id, p);
                if r.is_err() || p.chunks.is_empty() {
                    pending.remove(&id);
                }
            }
        }
        qp::StreamEvent::Finished { id } => {
            pending.remove(&id);
        }
        qp::StreamEvent::Stopped { id, error_code } => {
            pending.remove(&id);
            evs.push(Ev::Stopped(id, error_code.into_inner()));
        }
        qp::StreamEvent::Available { dir } => evs.push(Ev::Available(dir)),
    }
}

// ---- the endpoint and its UDP side ----

type Factory = dyn Fn(&Connection) -> Box<dyn QuicHandler> + Send + Sync;

struct Ep {
    endpoint: Mutex<qp::Endpoint>,
    conns: Mutex<HashMap<qp::ConnectionHandle, Connection>>,
    socks: Mutex<HashMap<SocketAddr, Conn<Udp>>>,
    /// A client's datagrams from before its socket was up.
    backlog: Mutex<Vec<Outgoing>>,
    factory: Option<Box<Factory>>,
    server_config: Option<Arc<qp::ServerConfig>>,
}

impl Ep {
    fn new(server_config: Option<Arc<qp::ServerConfig>>, factory: Option<Box<Factory>>) -> Ep {
        Ep {
            endpoint: Mutex::new(qp::Endpoint::new(
                Arc::new(qp::EndpointConfig::default()),
                server_config.clone(),
                false,
                None,
            )),
            conns: Mutex::new(HashMap::new()),
            socks: Mutex::new(HashMap::new()),
            backlog: Mutex::new(Vec::new()),
            factory,
            server_config,
        }
    }

    fn transmit(&self, dest: SocketAddr, seg: Option<usize>, data: Vec<u8>) {
        let sock = lock(&self.socks).get(&dest).cloned();
        let Some(sock) = sock else {
            if self.server_config.is_none() {
                lock(&self.backlog).push((dest, seg, data));
            }
            return;
        };
        // Several datagrams of `s` bytes: one GSO send where Linux supports it (else one
        // sendmmsg, else one by one); the boundaries survive either way.
        let _ = match seg {
            Some(s) => sock.send_segments(data, s),
            None => sock.send_owned(data),
        };
    }

    fn on_datagram(self: &Arc<Ep>, peer: SocketAddr, data: &[u8]) {
        let now = Instant::now();
        let mut buf = Vec::new();
        let ev = lock(&self.endpoint).handle(now, peer, None, None, BytesMut::from(data), &mut buf);
        match ev {
            None => {}
            Some(qp::DatagramEvent::Response(t)) => {
                self.transmit(t.destination, t.segment_size, buf[..t.size].to_vec());
            }
            Some(qp::DatagramEvent::ConnectionEvent(h, ce)) => {
                let c = lock(&self.conns).get(&h).cloned();
                if let Some(c) = c {
                    lock(&c.0.state).conn.handle_event(ce);
                    c.drive();
                }
            }
            Some(qp::DatagramEvent::NewConnection(incoming)) => {
                let r = lock(&self.endpoint).accept(incoming, now, &mut buf, None);
                match r {
                    Ok((h, conn)) => {
                        let c = Connection::new(h, conn, self.clone());
                        lock(&self.conns).insert(h, c.clone());
                        if let Some(f) = &self.factory {
                            let handler = f(&c);
                            *lock(&c.0.handler) = Some(handler);
                        }
                        c.drive();
                    }
                    Err(e) => {
                        if let Some(t) = e.response {
                            self.transmit(t.destination, t.segment_size, buf[..t.size].to_vec());
                        }
                    }
                }
            }
        }
    }
}

/// Serves QUIC on a UDP listener: an [`Acceptor`] giving each new connection a handler from
/// the factory.
pub struct QuicServer(Arc<Ep>);

impl QuicServer {
    /// A server with `config` (see [`server_config`]) whose connections get handlers from
    /// `factory`.
    pub fn new<H: QuicHandler, F>(config: qp::ServerConfig, factory: F) -> QuicServer
    where
        F: Fn(&Connection) -> H + Send + Sync + 'static,
    {
        QuicServer(Arc::new(Ep::new(
            Some(Arc::new(config)),
            Some(Box::new(move |c| Box::new(factory(c)))),
        )))
    }

    /// Open connections.
    pub fn connections(&self) -> usize {
        lock(&self.0.conns).len()
    }

    /// Closes every connection with `code` and `reason`.
    pub fn close_all(&self, code: u32, reason: &[u8]) {
        let all: Vec<Connection> = lock(&self.0.conns).values().cloned().collect();
        for c in all {
            c.close(code, reason);
        }
    }
}

impl Acceptor for QuicServer {
    type Handler = Udp;
    fn on_open(&self, c: &Conn<Udp>) -> Udp {
        lock(&self.0.socks).insert(c.peer_addr(), c.clone());
        Udp {
            ep: self.0.clone(),
            client: false,
        }
    }
}

/// The UDP connection handler under an endpoint (internal).
#[doc(hidden)]
pub struct Udp {
    ep: Arc<Ep>,
    client: bool,
}

impl Handler for Udp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.ep.on_datagram(c.peer_addr(), data);
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<flash_core::Error>) {
        {
            let mut socks = lock(&self.ep.socks);
            if socks.get(&c.peer_addr()).is_some_and(|s| s.id() == c.id()) {
                socks.remove(&c.peer_addr());
            }
        }
        if self.client {
            // The socket is gone: so is every connection on it.
            let all: Vec<Connection> = lock(&self.ep.conns).drain().map(|(_, c)| c).collect();
            for c in all {
                c.fail();
            }
        }
    }
}

impl Connection {
    /// The socket under a client connection failed.
    fn fail(&self) {
        let first = !std::mem::replace(&mut lock(&self.0.state).lost, true);
        if first {
            lock(&self.0.events).push_back(Ev::Closed(ConnectionError::TimedOut));
            self.deliver();
        }
    }
}

/// A transmit: destination, segment size (several datagrams), bytes.
type Outgoing = (SocketAddr, Option<usize>, Vec<u8>);

/// Datagrams one `poll_transmit` may return in a single [`Conn::send_segments`] (as quinn does,
/// up to 10).
const MAX_DATAGRAMS: usize = 10;

struct ClientAcceptor(Arc<Ep>);

impl Acceptor for ClientAcceptor {
    type Handler = Udp;
    fn on_open(&self, c: &Conn<Udp>) -> Udp {
        lock(&self.0.socks).insert(c.peer_addr(), c.clone());
        let backlog = std::mem::take(&mut *lock(&self.0.backlog));
        for (dest, seg, d) in backlog {
            self.0.transmit(dest, seg, d);
        }
        Udp {
            ep: self.0.clone(),
            client: true,
        }
    }
}

/// Connects to `addr`, verifying the server as `server_name`, with `config` (see
/// [`client_config`]). The connection uses a UDP socket of its own; the engine needs UDP
/// client threads ([`flash::EngineBuilder::udp_client_threads`]) and must be started. Streams
/// can be opened once the handshake completes ([`QuicHandler::on_connected`]).
pub fn dial<H: QuicHandler>(
    engine: &flash::Engine,
    addr: SocketAddr,
    server_name: &str,
    config: qp::ClientConfig,
    handler: H,
) -> Result<Connection, Error> {
    let ep = Arc::new(Ep::new(None, None));
    let (h, conn) = lock(&ep.endpoint)
        .connect(Instant::now(), config, addr, server_name)
        .map_err(Error::Connect)?;
    let c = Connection::new(h, conn, ep.clone());
    *lock(&c.0.handler) = Some(Box::new(handler));
    lock(&ep.conns).insert(h, c.clone());
    let failed = c.clone();
    engine.dial_udp(addr, ClientAcceptor(ep), move |_e| failed.fail());
    c.drive();
    Ok(c)
}

// ---- configuration helpers ----

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A server config for a certificate chain and key, offering the ALPN protocols `alpn`.
pub fn server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    alpn: &[&[u8]],
) -> Result<qp::ServerConfig, Error> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Config(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(e.to_string()))?;
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tls.max_early_data_size = u32::MAX;
    server_config_from(tls)
}

/// A server config from a rustls config (TLS 1.3, with the ALPN protocols set).
pub fn server_config_from(tls: rustls::ServerConfig) -> Result<qp::ServerConfig, Error> {
    let q = qp::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| Error::Config(e.to_string()))?;
    Ok(qp::ServerConfig::with_crypto(Arc::new(q)))
}

/// A client config trusting `roots`, asking for the ALPN protocols `alpn`.
pub fn client_config(
    roots: rustls::RootCertStore,
    alpn: &[&[u8]],
) -> Result<qp::ClientConfig, Error> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Config(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    client_config_from(tls)
}

/// A client config from a rustls config.
pub fn client_config_from(tls: rustls::ClientConfig) -> Result<qp::ClientConfig, Error> {
    let q = qp::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| Error::Config(e.to_string()))?;
    Ok(qp::ClientConfig::new(Arc::new(q)))
}

/// A client config that accepts any server certificate: for tests and interop runs only.
pub fn client_config_insecure(alpn: &[&[u8]]) -> Result<qp::ClientConfig, Error> {
    let p = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
        .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    client_config_from(tls)
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
