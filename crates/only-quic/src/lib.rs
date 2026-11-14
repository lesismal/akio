#![forbid(unsafe_code)]
//! QUIC v1 (RFC 9000, 9001, 9002) with unreliable datagrams (RFC 9221) for `only`, implemented
//! in this crate on `only-tls` and `only-crypto`, with no third-party dependency.
//!
//! A [`QuicServer`] is the acceptor of a UDP [`only::Listener`]: every datagram goes through one
//! endpoint, which routes it to its connection by connection ID (so a peer that migrates to
//! another address keeps its connection). Each connection gets a [`QuicHandler`] from the
//! server's factory; [`dial`] starts a client connection on an engine with UDP client threads.
//! A connection's callbacks run one at a time, in order, on the I/O thread that read the
//! datagram or on the shared timer thread; they must not block.
//!
//! Writes never block: [`Connection::send`] queues the bytes, and they go out as flow and
//! congestion control allow ([`Connection::queued_bytes`] paces a producer).
//!
//! The protocol core is sans-io (no sockets, threads or clocks of its own): packets and
//! header protection, all RFC 9000 frames, streams with flow control, loss detection and
//! congestion control (NewReno, CUBIC) with pacing, connection IDs, Retry and NEW_TOKEN
//! address validation, path validation and migration, key updates, stateless resets and
//! version negotiation. Full-size datagrams leave in batches for one GSO send.
//!
//! ```no_run
//! use only::{Engine, Listener};
//! use only_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};
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
//! # fn pem() -> (Vec<u8>, Vec<u8>) { unimplemented!() }
//! use only::tls::{Certificate, PrivateKey};
//! let (cert_pem, key_pem) = pem();
//! let certs = Certificate::from_pem(&cert_pem).unwrap();
//! let key = PrivateKey::from_pem(&key_pem).unwrap();
//! let cfg = only_quic::server_config(certs, key, &[b"echo"]).unwrap();
//! let server = QuicServer::new(cfg, |_c: &Connection| Echo);
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:4433".parse().unwrap()).serve(server))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! Guide: [QUIC and HTTP/3](https://lesismal.github.io/only/en/protocols/quic-h3.html)
//! (中文: [QUIC 与 HTTP/3](https://lesismal.github.io/only/zh-CN/protocols/quic-h3.html)).
#![warn(clippy::unwrap_used)]

mod bytes;
mod proto;
mod timer;
mod types;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Instant;

use only::tls;
use only_core::{Acceptor, Conn, Handler};

pub use crate::bytes::Bytes;
pub use types::{
    ClientConfig, Congestion, ConnectionError, ConnectionStats, Dir, ServerConfig, Side, StreamId,
    TransportConfig, UdpStats,
};
use types::{TokenStore, config_err};

/// Errors of [`Connection`] calls and of the config helpers.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The connection is closed.
    Closed,
    /// No such stream, or not one this side can write (a peer's unidirectional stream) or read.
    UnknownStream,
    /// The peer stopped the stream (`STOP_SENDING`) with this code.
    Stopped(u64),
    /// The peer does not accept datagrams, or this one is too large.
    Datagram(String),
    /// Could not start a connection (bad server name, endpoint stopping ...).
    Connect(String),
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

struct State {
    conn: proto::Connection,
    armed: Option<Instant>,
    lost: bool,
}

struct Shared {
    h: proto::ConnHandle,
    ep: Arc<Ep>,
    me: Weak<Shared>,
    state: Mutex<State>,
    events: Mutex<VecDeque<proto::Event>>,
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
    fn new(h: proto::ConnHandle, conn: proto::Connection, ep: Arc<Ep>) -> Connection {
        Connection(Arc::new_cyclic(|me| Shared {
            h,
            ep,
            me: me.clone(),
            state: Mutex::new(State {
                conn,
                armed: None,
                lost: false,
            }),
            events: Mutex::new(VecDeque::new()),
            handler: Mutex::new(None),
            done: AtomicBool::new(false),
        }))
    }

    /// The peer's current address.
    pub fn remote_addr(&self) -> SocketAddr {
        lock(&self.0.state).conn.remote_addr()
    }

    /// The negotiated ALPN protocol.
    pub fn alpn(&self) -> Option<Vec<u8>> {
        lock(&self.0.state).conn.alpn()
    }

    /// The SNI the client asked for (server side).
    pub fn server_name(&self) -> Option<String> {
        lock(&self.0.state).conn.server_name()
    }

    /// The smoothed round-trip time.
    pub fn rtt(&self) -> std::time::Duration {
        lock(&self.0.state).conn.rtt()
    }

    /// Connection statistics.
    pub fn stats(&self) -> ConnectionStats {
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
        let id = lock(&self.0.state).conn.open(Dir::Bi);
        self.drive();
        id
    }

    /// Opens a unidirectional stream; `None` while the peer's stream limit is reached.
    pub fn open_uni(&self) -> Option<StreamId> {
        let id = lock(&self.0.state).conn.open(Dir::Uni);
        self.drive();
        id
    }

    /// Queues bytes on a stream; they go out as flow and congestion control allow.
    pub fn send(&self, id: StreamId, data: impl Into<Bytes>) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.write(id, data.into());
        self.drive();
        r
    }

    /// Ends a stream once its queued bytes are out.
    pub fn finish(&self, id: StreamId) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.finish(id);
        self.drive();
        r
    }

    /// Abandons sending on a stream (`RESET_STREAM`), dropping what is queued.
    pub fn reset(&self, id: StreamId, code: u32) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.reset(id, u64::from(code));
        self.drive();
        r
    }

    /// Asks the peer to stop sending on a stream (`STOP_SENDING`).
    pub fn stop(&self, id: StreamId, code: u32) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.stop(id, u64::from(code));
        self.drive();
        r
    }

    /// Bytes queued on a stream that were not sent yet.
    pub fn queued_bytes(&self, id: StreamId) -> usize {
        lock(&self.0.state).conn.queued_bytes(id)
    }

    /// Sends an unreliable datagram (needs the peer's support, RFC 9221).
    pub fn send_datagram(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.send_datagram(data.into());
        self.drive();
        r
    }

    /// Closes the connection with an application error code and reason; `on_close` gets
    /// `LocallyClosed`.
    pub fn close(&self, code: u32, reason: &[u8]) {
        lock(&self.0.state)
            .conn
            .close(Instant::now(), u64::from(code), reason);
        self.drive();
    }

    /// Runs the state machine until it is quiet: app events, datagrams to send, endpoint
    /// events, the timer.
    fn drive(&self) {
        let ep = &self.0.ep;
        let mut tx = Vec::new();
        let mut ep_events = Vec::new();
        let mut evs = Vec::new();
        let drained;
        {
            let mut st = lock(&self.0.state);
            let now = Instant::now();
            let State { conn, armed, lost } = &mut *st;
            while let Some(t) = conn.poll_transmit(now, MAX_DATAGRAMS) {
                tx.push(t);
            }
            while let Some(e) = conn.poll_event() {
                if let proto::Event::Closed(_) = e {
                    if std::mem::replace(lost, true) {
                        continue;
                    }
                }
                evs.push(e);
            }
            while let Some(e) = conn.poll_endpoint_event() {
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
                evs.push(proto::Event::Closed(ConnectionError::LocallyClosed));
            }
        }
        for t in tx {
            ep.transmit(t.dest, t.segment_size, t.data);
        }
        if !ep_events.is_empty() {
            let mut e = lock(&ep.endpoint);
            for ev in &ep_events {
                e.handle_event(self.0.h, ev);
            }
            drop(e);
            for ev in ep_events {
                if let proto::EndpointEvent::NewToken(t) = ev {
                    if let Some((store, name)) = &ep.tokens {
                        lock(store).insert(name.clone(), t);
                    }
                }
            }
        }
        if drained {
            lock(&ep.conns).remove(&self.0.h);
        }
        if !evs.is_empty() {
            lock(&self.0.events).extend(evs);
        }
        self.deliver();
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
                    proto::Event::Connected => h.on_connected(self),
                    proto::Event::StreamOpened(id) => h.on_stream_opened(self, id),
                    proto::Event::StreamData(id, d, fin) => h.on_stream_data(self, id, d, fin),
                    proto::Event::StreamReset(id, c) => h.on_stream_reset(self, id, c),
                    proto::Event::StreamStopped(id, c) => h.on_stream_stopped(self, id, c),
                    proto::Event::StreamsAvailable(d) => h.on_streams_available(self, d),
                    proto::Event::Datagram(d) => h.on_datagram(self, d),
                    proto::Event::Closed(r) => {
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

    /// The socket under a client connection failed.
    fn fail(&self) {
        let first = !std::mem::replace(&mut lock(&self.0.state).lost, true);
        if first {
            lock(&self.0.events).push_back(proto::Event::Closed(ConnectionError::TimedOut));
            self.deliver();
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

// ---- the endpoint and its UDP side ----

type Factory = dyn Fn(&Connection) -> Box<dyn QuicHandler> + Send + Sync;

struct Ep {
    endpoint: Mutex<proto::Endpoint>,
    conns: Mutex<HashMap<proto::ConnHandle, Connection>>,
    socks: Mutex<HashMap<SocketAddr, Conn<Udp>>>,
    /// A client's datagrams from before its socket was up.
    backlog: Mutex<Vec<Outgoing>>,
    factory: Option<Box<Factory>>,
    /// A client's token store and the server name its tokens are kept under.
    tokens: Option<(TokenStore, String)>,
}

impl Ep {
    fn new(
        endpoint: proto::Endpoint,
        factory: Option<Box<Factory>>,
        tokens: Option<(TokenStore, String)>,
    ) -> Ep {
        Ep {
            endpoint: Mutex::new(endpoint),
            conns: Mutex::new(HashMap::new()),
            socks: Mutex::new(HashMap::new()),
            backlog: Mutex::new(Vec::new()),
            factory,
            tokens,
        }
    }

    fn transmit(&self, dest: SocketAddr, seg: Option<usize>, data: Vec<u8>) {
        let sock = lock(&self.socks).get(&dest).cloned();
        let Some(sock) = sock else {
            if self.factory.is_none() {
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
        let ev = lock(&self.endpoint).handle(now, peer, data);
        match ev {
            None => {}
            Some(proto::DatagramEvent::Respond(t)) => self.transmit(t.dest, None, t.data),
            Some(proto::DatagramEvent::Conn(h)) => {
                let c = lock(&self.conns).get(&h).cloned();
                if let Some(c) = c {
                    lock(&c.0.state)
                        .conn
                        .handle_datagram(now, peer, data.to_vec());
                    c.drive();
                }
            }
            Some(proto::DatagramEvent::New(h, conn)) => {
                let c = Connection::new(h, *conn, self.clone());
                lock(&self.conns).insert(h, c.clone());
                if let Some(f) = &self.factory {
                    let handler = f(&c);
                    *lock(&c.0.handler) = Some(handler);
                }
                c.drive();
            }
        }
    }
}

/// Serves QUIC on a UDP listener: an [`Acceptor`] giving each new connection a handler from
/// the factory.
pub struct QuicServer(Arc<Ep>);

impl fmt::Debug for QuicServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicServer").finish_non_exhaustive()
    }
}

impl QuicServer {
    /// A server with `config` (see [`server_config`]) whose connections get handlers from
    /// `factory`.
    pub fn new<H: QuicHandler, F>(config: ServerConfig, factory: F) -> QuicServer
    where
        F: Fn(&Connection) -> H + Send + Sync + 'static,
    {
        let setup = proto::ServerSetup {
            tls: config.tls,
            cfg: proto::ConnConfig::new(config.transport, config.migration),
            retry: config.retry,
        };
        QuicServer(Arc::new(Ep::new(
            proto::Endpoint::new(Some(setup)),
            Some(Box::new(move |c| Box::new(factory(c)))),
            None,
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

impl fmt::Debug for Udp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Udp").finish_non_exhaustive()
    }
}

impl Handler for Udp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.ep.on_datagram(c.peer_addr(), data);
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only_core::Error>) {
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

/// A transmit: destination, segment size (several datagrams), bytes.
type Outgoing = (SocketAddr, Option<usize>, Vec<u8>);

/// Datagrams one `poll_transmit` may return in a single [`Conn::send_segments`].
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
/// client threads ([`only::EngineBuilder::udp_client_threads`]) and must be started. Streams
/// can be opened once the handshake completes ([`QuicHandler::on_connected`]).
pub fn dial<H: QuicHandler>(
    engine: &only::Engine,
    addr: SocketAddr,
    server_name: &str,
    config: ClientConfig,
    handler: H,
) -> Result<Connection, Error> {
    let token = lock(&config.tokens)
        .get(server_name)
        .cloned()
        .unwrap_or_default();
    let mut endpoint = proto::Endpoint::new(None);
    let (h, conn) = endpoint.connect(
        Instant::now(),
        proto::ConnConfig::new(config.transport.clone(), true),
        &config.tls,
        server_name,
        addr,
        token,
    )?;
    let ep = Arc::new(Ep::new(
        endpoint,
        None,
        Some((config.tokens.clone(), server_name.to_string())),
    ));
    let c = Connection::new(h, conn, ep.clone());
    *lock(&c.0.handler) = Some(Box::new(handler));
    lock(&ep.conns).insert(h, c.clone());
    let failed = c.clone();
    engine.dial_udp(addr, ClientAcceptor(ep), move |_e| failed.fail());
    c.drive();
    Ok(c)
}

// ---- configuration helpers ----

/// A server config for a certificate chain (leaf first) and key, offering the ALPN protocols
/// `alpn` (TLS 1.3 with session tickets for resumption).
pub fn server_config(
    certs: Vec<tls::Certificate>,
    key: tls::PrivateKey,
    alpn: &[&[u8]],
) -> Result<ServerConfig, Error> {
    let tls = tls::ServerConfig::builder(certs, key)
        .alpn(alpn)
        .tls13_only(true)
        .session_tickets(true)
        .build()
        .map_err(config_err)?;
    Ok(ServerConfig::new(tls))
}

/// A server config from a TLS configuration (its certificates, ALPN protocols, client
/// authentication; QUIC always runs TLS 1.3).
pub fn server_config_from(tls: &tls::ServerConfig) -> Result<ServerConfig, Error> {
    Ok(ServerConfig::new(tls.clone()))
}

/// A client config trusting `roots`, asking for the ALPN protocols `alpn`.
pub fn client_config(roots: tls::RootCerts, alpn: &[&[u8]]) -> Result<ClientConfig, Error> {
    let tls = tls::ClientConfig::builder()
        .roots(roots)
        .alpn(alpn)
        .tls13_only(true)
        .build()
        .map_err(config_err)?;
    client_config_from(&tls)
}

/// A client config from a TLS configuration (roots, ALPN protocols, client certificate).
pub fn client_config_from(tls: &tls::ClientConfig) -> Result<ClientConfig, Error> {
    Ok(ClientConfig::new(tls.clone()))
}

/// A client config that accepts any server certificate: for tests and interop runs only.
pub fn client_config_insecure(alpn: &[&[u8]]) -> Result<ClientConfig, Error> {
    let tls = tls::ClientConfig::builder()
        .insecure_skip_verify()
        .alpn(alpn)
        .tls13_only(true)
        .build()
        .map_err(config_err)?;
    client_config_from(&tls)
}
