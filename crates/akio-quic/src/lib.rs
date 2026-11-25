#![forbid(unsafe_code)]
//! QUIC v1 (RFC 9000, 9001, 9002) with unreliable datagrams (RFC 9221) for `akio`, implemented
//! in this crate on `akio-tls` and `akio-crypto`, with no third-party dependency.
//!
//! A [`QuicServer`] is the acceptor of a UDP [`akio::Listener`]: every datagram goes through one
//! endpoint, which routes it to its connection by connection ID (so a peer that migrates to
//! another address keeps its connection). Each connection gets a [`QuicHandler`] from the
//! server's factory; [`dial`] starts a client connection on an engine with UDP client threads.
//! A connection's callbacks run one at a time, in order, on the I/O thread that read the
//! datagram or on the shared timer thread; they must not block.
//!
//! Writes never block: [`Connection::send`] queues the bytes, and they go out as flow and
//! congestion control allow. Send buffers are bounded per stream and per connection
//! ([`TransportConfig::stream_send_buffer`], [`TransportConfig::send_buffer`]): past them `send`
//! fails with [`Error::Overloaded`] and [`QuicHandler::on_stream_writable`] says when to go on.
//! A server holds at most [`ServerConfig::max_connections`] connections.
//!
//! The protocol core is sans-io (no sockets, threads or clocks of its own): packets and
//! header protection, all RFC 9000 frames, streams with flow control, loss detection and
//! congestion control (NewReno, CUBIC) with pacing, connection IDs, Retry and NEW_TOKEN
//! address validation, path validation and migration, key updates, stateless resets, QUIC
//! version 2 and version negotiation (Version Negotiation packets, and compatible negotiation
//! within the handshake with [`ServerConfig::prefer_version`], RFC 9368). Full-size datagrams
//! leave in batches for one GSO send.
//!
//! ```no_run
//! use akio::{Engine, Listener};
//! use akio_quic::{Bytes, Connection, QuicHandler, QuicServer, StreamId};
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
//! use akio::tls::{Certificate, PrivateKey};
//! let (cert_pem, key_pem) = pem();
//! let certs = Certificate::from_pem(&cert_pem).unwrap();
//! let key = PrivateKey::from_pem(&key_pem).unwrap();
//! let cfg = akio_quic::server_config(certs, key, &[b"echo"]).unwrap();
//! let server = QuicServer::new(cfg, |_c: &Connection| Echo);
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:4433".parse().unwrap()).serve(server))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! Guide: [QUIC and HTTP/3](https://lesismal.github.io/akio/en/protocols/quic-h3.html)
//! (中文: [QUIC 与 HTTP/3](https://lesismal.github.io/akio/zh-CN/protocols/quic-h3.html)).
#![warn(clippy::unwrap_used)]

mod bytes;
mod proto;
mod timer;
mod types;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

/// Hooks that force thread interleavings in tests; not a public API.
#[cfg(feature = "testing")]
#[doc(hidden)]
pub mod testing {
    use std::sync::atomic::{AtomicU8, Ordering};

    use crate::Side;

    /// 0: off; 1: server connections; 2: client connections.
    static DEFER: AtomicU8 = AtomicU8::new(0);

    std::thread_local! {
        /// This thread drives a connection from an API call made outside its handler.
        pub(crate) static KICKING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// While `Some(side)`, that side's connections (in this process) run their handler only
    /// from API calls made outside it (`send`, `reset`, ...): what the I/O and timer threads
    /// receive waits for such a call, which then runs it on the calling thread. Forces the
    /// interleaving where an application thread's call runs the handler. Process-wide: keep
    /// tests that use it in a test binary of their own.
    pub fn defer_delivery(side: Option<Side>) {
        let v = match side {
            None => 0,
            Some(Side::Server) => 1,
            Some(Side::Client) => 2,
        };
        DEFER.store(v, Ordering::SeqCst);
    }

    /// Whether a connection of this side leaves its events for an API call to run.
    pub(crate) fn deferred(server: bool) -> bool {
        let v = DEFER.load(Ordering::SeqCst);
        v != 0 && (v == 1) == server && !KICKING.with(std::cell::Cell::get)
    }
}

use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Instant;

use akio::tls;
use akio_core::{
    Acceptor, Conn, Handler,
    metrics::{Collector, Families},
};

pub use crate::bytes::Bytes;
pub use types::{
    ClientConfig, Congestion, ConnectionError, ConnectionStats, DEFAULT_MAX_CONNECTIONS, Dir,
    ServerConfig, Side, StreamId, TransportConfig, UdpStats, Version,
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
    /// Could not start a migration (see [`Connection::migrate`]).
    Migration(String),
    /// A TLS or QUIC configuration problem.
    Config(String),
    /// The stream's or the connection's send buffer is full
    /// ([`TransportConfig::stream_send_buffer`], [`TransportConfig::send_buffer`]): wait for
    /// [`QuicHandler::on_stream_writable`]. For [`Connection::spawn_blocking`]: the engine's
    /// logical pool is full.
    Overloaded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Closed => f.write_str("quic: connection closed"),
            Error::UnknownStream => f.write_str("quic: unknown stream"),
            Error::Stopped(c) => write!(f, "quic: stream stopped by peer (code {c})"),
            Error::Datagram(e) => write!(f, "quic: datagram: {e}"),
            Error::Connect(e) => write!(f, "quic: connect: {e}"),
            Error::Migration(e) => write!(f, "quic: migration: {e}"),
            Error::Config(e) => write!(f, "quic: config: {e}"),
            Error::Overloaded => f.write_str("quic: overloaded"),
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
    /// A stream whose write was refused with [`Error::Overloaded`] (or whose
    /// [`send_capacity`](Connection::send_capacity) was zero) has room again: its send buffer
    /// and the connection's are down to three quarters of their limits. Called once per refusal.
    fn on_stream_writable(&mut self, _c: &Connection, _id: StreamId) {}
    /// An unreliable datagram (RFC 9221).
    fn on_datagram(&mut self, _c: &Connection, _data: Bytes) {}
    /// The connection is over; called once, last.
    fn on_close(&mut self, _c: &Connection, _reason: ConnectionError) {}
    /// Server: the UDP socket the connection's peer talks to is going away (its listener is
    /// removed with a drain, `akio::Engine::shutdown_listener`; its bound socket drains,
    /// `UdpBinding::shutdown`; or the engine shuts down), as `Acceptor::on_shutdown` says it
    /// of the peer (ADR-155). Finish what is in flight, take nothing new and close: akio-h3
    /// sends `GOAWAY`. Called at most once. The default does nothing: the connection ends with
    /// the socket's drain deadline or its idle timeout.
    fn on_shutdown(&mut self, _c: &Connection) {}
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
    /// Datagrams to send, in the order the state machine produced them; queued under the
    /// state lock, sent outside it by one thread at a time (`sending`).
    outq: Mutex<VecDeque<proto::Transmit>>,
    sending: AtomicBool,
    /// The UDP socket (peer) the last datagram went out on (server): the next one to the same
    /// address uses it without the endpoint's shared socket table. Used by the sender only.
    tx_sock: Mutex<Option<Conn<Udp>>>,
    /// A call made in [`Connection::without_driving`] left the driving to the timer thread,
    /// which has not driven the connection since.
    woken: AtomicBool,
    /// `QuicHandler::on_shutdown` is due (ADR-155); `shut` once it was asked for.
    shutdown: AtomicBool,
    shut: AtomicBool,
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

thread_local! {
    /// The connection whose handler this thread is running (its address), if any.
    static DELIVERING: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The connection this thread calls in [`Connection::without_driving`] (its address).
    static QUIET: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Connection {
    fn new(h: proto::ConnHandle, mut conn: proto::Connection, ep: Arc<Ep>) -> Connection {
        Connection(Arc::new_cyclic(|me: &Weak<Shared>| {
            // A handshake suspended for an asynchronous anti-replay answer (ADR-062) is driven
            // again, from the thread that answers, once it is in.
            let wake = me.clone();
            conn.set_tls_waker(Arc::new(move || {
                if let Some(s) = wake.upgrade() {
                    Connection(s).drive();
                }
            }));
            Shared {
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
                outq: Mutex::new(VecDeque::new()),
                sending: AtomicBool::new(false),
                tx_sock: Mutex::new(None),
                woken: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                shut: AtomicBool::new(false),
            }
        }))
    }

    /// Server: the peer's socket goes away; the handler hears of it (`on_shutdown`) once.
    fn shut_down(&self) {
        if !self.0.shut.swap(true, Ordering::AcqRel) {
            self.0.shutdown.store(true, Ordering::Release);
            self.kick();
        }
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

    /// The certificate chain the peer sent and the handshake verified (DER, leaf first), as
    /// `akio_tls::TlsInfo::peer_certificates` describes it: on a server, the client's, which it
    /// sends only when the server's TLS configuration asks for one. Empty when it sent none;
    /// `None` while the handshake is under way (data sent in 0-RTT comes before it).
    pub fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
        lock(&self.0.state).conn.peer_certificates()
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
    /// (open streams from [`QuicHandler::on_connected`]) unless the client resumes with 0-RTT
    /// ([`ClientConfig::zero_rtt`]): then streams open right after [`dial`], under the limits
    /// the server gave last time, and their data goes out in 0-RTT packets.
    pub fn open_bi(&self) -> Option<StreamId> {
        // No callbacks run here (callers may hold their own locks); anything the opening
        // queued goes out with the next write.
        lock(&self.0.state).conn.open(Dir::Bi)
    }

    /// Opens a unidirectional stream; `None` while the peer's stream limit is reached.
    pub fn open_uni(&self) -> Option<StreamId> {
        // No callbacks run here (callers may hold their own locks); anything the opening
        // queued goes out with the next write.
        lock(&self.0.state).conn.open(Dir::Uni)
    }

    /// Queues bytes on a stream; they go out as flow and congestion control allow. Fails with
    /// [`Error::Overloaded`] while the stream's or the connection's send buffer is full
    /// ([`TransportConfig::stream_send_buffer`], [`TransportConfig::send_buffer`]): the data
    /// is not queued, and [`QuicHandler::on_stream_writable`] follows once there is room.
    pub fn send(&self, id: StreamId, data: impl Into<Bytes>) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.write(id, data.into());
        if r.is_ok() {
            self.kick();
        }
        r
    }

    /// Bytes [`send`](Self::send) would take on a stream now before refusing writes (the
    /// smaller of the stream's and the connection's room). When it is zero,
    /// [`QuicHandler::on_stream_writable`] follows once there is room, so a producer can check
    /// before it reads or builds the next piece.
    pub fn send_capacity(&self, id: StreamId) -> Result<usize, Error> {
        lock(&self.0.state)
            .conn
            .send_capacity(id)
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
    }

    /// Runs `work` on the engine's logical pool, off the I/O threads: for what may block (disk
    /// reads, DNS) on behalf of this connection. `work` may use the connection (it is usable
    /// from any thread). Fails with [`Error::Overloaded`] when the pool's queue is full and
    /// [`Error::Closed`] when the connection or its socket is gone.
    pub fn spawn_blocking(&self, work: impl FnOnce() + Send + 'static) -> Result<(), Error> {
        let sock = self.pool_socket().ok_or(Error::Closed)?;
        sock.spawn_blocking(work, |_: &mut Udp, _, ()| {})
            .map_err(|e| match e {
                akio_core::Error::Overloaded => Error::Overloaded,
                _ => Error::Closed,
            })
    }

    /// [`spawn_blocking`](Self::spawn_blocking) that hands `job` back, unrun, when it cannot
    /// be queued (the pool's queue is full, or the connection's socket is gone), so the caller
    /// can still answer for it.
    pub fn execute(&self, job: akio_core::Job) -> Result<(), akio_core::Job> {
        match self.pool_socket() {
            Some(sock) => sock.inner().execute(job),
            None => Err(job),
        }
    }

    /// The socket this connection's pool work is posted through: the one its peer is on.
    fn pool_socket(&self) -> Option<Conn<Udp>> {
        let addr = self.remote_addr();
        let socks = lock(&self.0.ep.socks);
        socks
            .get(&addr)
            .cloned()
            .or_else(|| socks.values().next().cloned())
    }

    /// Ends a stream once its queued bytes are out.
    pub fn finish(&self, id: StreamId) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.finish(id);
        self.kick();
        r
    }

    /// Abandons sending on a stream (`RESET_STREAM`), dropping what is queued.
    pub fn reset(&self, id: StreamId, code: u32) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.reset(id, u64::from(code));
        self.kick();
        r
    }

    /// Asks the peer to stop sending on a stream (`STOP_SENDING`).
    pub fn stop(&self, id: StreamId, code: u32) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.stop(id, u64::from(code));
        self.kick();
        r
    }

    /// Holds (`true`) or resumes (`false`) delivering a stream's data to
    /// [`QuicHandler::on_stream_data`]: while held, what arrives stays in the stream's receive
    /// buffer and its flow control window is not extended, so the peer stops sending once the
    /// window ([`TransportConfig::stream_receive_window`]) is used; held bytes also count
    /// against the connection's window. Resuming delivers what arrived (in later callbacks) and
    /// extends the window. Data already handed to the handler's queue may still arrive after
    /// holding. Holding a stream that was finished, reset or stopped does nothing;
    /// [`stop`](Self::stop) drops what is held.
    pub fn hold_reads(&self, id: StreamId, hold: bool) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.hold_reads(id, hold);
        if !hold {
            self.kick();
        }
        r
    }

    /// Bytes queued on a stream that were not sent yet.
    pub fn queued_bytes(&self, id: StreamId) -> usize {
        lock(&self.0.state).conn.queued_bytes(id)
    }

    /// Sends an unreliable datagram (needs the peer's support, RFC 9221).
    pub fn send_datagram(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        let r = lock(&self.0.state).conn.send_datagram(data.into());
        self.kick();
        r
    }

    /// What happened to 0-RTT on this connection (see [`ClientConfig::zero_rtt`] and
    /// [`ServerConfig::zero_rtt`]). A client knows `Accepted` or `Rejected` once the handshake
    /// completes; data sent in rejected 0-RTT packets is sent again in 1-RTT packets.
    pub fn early_data(&self) -> tls::EarlyData {
        lock(&self.0.state).conn.early_data()
    }

    /// Whether data of stream `id` arrived in 0-RTT packets (server): it was sent before the
    /// handshake and may be a **replay** of another connection's, so only act on requests that
    /// are safe to repeat (HTTP: answer others with `425 Too Early`, RFC 8470). `false` once
    /// the stream is gone.
    pub fn is_early(&self, id: StreamId) -> bool {
        lock(&self.0.state).conn.is_early(id)
    }

    /// The QUIC version in use.
    pub fn version(&self) -> Version {
        Version::from_wire(lock(&self.0.state).conn.version())
    }

    /// The server's preferred address (RFC 9000 section 9.6), on a client whose server offered
    /// one in the family of the current path and that does not use it yet (see
    /// [`migrate`](Self::migrate)). Known once the handshake completes.
    pub fn preferred_address(&self) -> Option<SocketAddr> {
        lock(&self.0.state).conn.preferred_address()
    }

    /// Moves this client connection to a new network path (RFC 9000 section 9): to the
    /// server's [preferred address](Self::preferred_address) if there is one, else to the same
    /// server address from a new UDP socket, so a new local port (what a client does when its
    /// network changes, or to shed a NAT binding). The new path is probed first with
    /// PATH_CHALLENGE under a connection ID not used before; the connection moves to it once
    /// the server answers (resetting its congestion state, ECN validation and, for a new server
    /// address, its RTT estimate), and the old socket closes. Without an answer within three
    /// probe timeouts it stays where it was and the new socket closes. Before the handshake is
    /// confirmed, or until the server provides a spare connection ID, the probe waits.
    ///
    /// Fails on a server's connection, a closed one, during another migration, and when the
    /// server disabled active migration (`disable_active_migration`, which does not cover its
    /// preferred address). `engine` opens the new socket (it needs UDP client threads).
    pub fn migrate(&self, engine: &akio::Engine) -> Result<(), Error> {
        let dest = lock(&self.0.state)
            .conn
            .migrate(Instant::now())
            .map_err(|e| Error::Migration(e.to_string()))?;
        let ep = self.0.ep.clone();
        lock(&ep.probe_backlog).clear();
        engine.dial_udp(dest, ProbeAcceptor(ep), |_e| {
            // The probe goes unanswered and the migration fails by itself.
        });
        self.drive();
        Ok(())
    }

    /// Closes the connection with an application error code and reason; `on_close` gets
    /// `LocallyClosed`.
    pub fn close(&self, code: u32, reason: &[u8]) {
        lock(&self.0.state)
            .conn
            .close(Instant::now(), u64::from(code), reason);
        self.kick();
    }

    /// Runs `f`, in which this connection's calls (`send`, `finish`, `reset`, `stop`, resuming
    /// reads, `close`) leave driving the connection to its timer thread, which does it at once,
    /// instead of driving it on this thread.
    ///
    /// A call from outside the connection's handler normally drives the connection on the
    /// calling thread: it sends what the call queued and runs the handler for whatever is
    /// pending (data received, a stream reset), there and then. A caller holding a lock the
    /// handler also takes would wait on itself; inside `f` it does not, at the cost of a thread
    /// hand-off. Calls from the handler itself never drive the connection (it is driven once
    /// the callback returns), with or without this.
    pub fn without_driving<R>(&self, f: impl FnOnce() -> R) -> R {
        let me = Arc::as_ptr(&self.0) as usize;
        let prev = QUIET.with(|q| q.replace(me));
        let r = f();
        QUIET.with(|q| q.set(prev));
        r
    }

    /// The timer thread drives the connection at once (for [`without_driving`]).
    ///
    /// [`without_driving`]: Self::without_driving
    fn wake(&self) {
        if !self.0.woken.swap(true, Ordering::AcqRel) {
            let target: Weak<dyn timer::Due> = self.0.me.clone();
            timer::timer().schedule(Instant::now(), target);
        }
    }

    /// After an API call: runs the state machine, unless the call came from this connection's
    /// own handler, whose delivering `drive` sends everything once the callback returns (so a
    /// response, its FIN and the acknowledgments share packets), or from
    /// [`without_driving`](Self::without_driving), which leaves it to the timer thread.
    fn kick(&self) {
        let me = Arc::as_ptr(&self.0) as usize;
        if DELIVERING.with(std::cell::Cell::get) == me {
            return;
        }
        if QUIET.with(std::cell::Cell::get) == me {
            return self.wake();
        }
        {
            #[cfg(feature = "testing")]
            let prev = testing::KICKING.with(|k| k.replace(true));
            self.drive();
            #[cfg(feature = "testing")]
            testing::KICKING.with(|k| k.set(prev));
        }
    }

    /// Runs the state machine until it is quiet: handler events first, then datagrams to send,
    /// endpoint events and the timer.
    fn drive(&self) {
        self.drive_at(None);
    }

    /// [`Connection::drive`] whose first round uses `now` (the time a datagram was just
    /// handled at) instead of reading the clock twice more.
    fn drive_at(&self, mut now: Option<Instant>) {
        // The timer is armed by the last round, which always runs.
        self.collect(false, false, now);
        loop {
            self.deliver();
            if !self.collect(true, true, now.take()) {
                return;
            }
        }
    }

    /// After a datagram that is part of a receive batch: runs the handler on what it brought,
    /// and sends right away only if there is more than an acknowledgment to send (data, a
    /// handler's reply); acknowledgments wait for the end of the batch (`Udp::on_batch_end`).
    fn drive_received(&self, now: Instant) {
        // The timer is armed at the end of the batch, when the connection is driven again.
        self.collect(false, false, Some(now));
        loop {
            self.deliver();
            if !self.collect(false, false, Some(now)) {
                break;
            }
        }
        if lock(&self.0.state).conn.wants_transmit() {
            self.drive_at(Some(now));
        }
    }

    /// Takes what the state machine produced: datagrams (when `transmit`), events, endpoint
    /// events, the timer (when `arm`). Returns whether new handler events were queued.
    fn collect(&self, transmit: bool, arm: bool, now: Option<Instant>) -> bool {
        let ep = &self.0.ep;
        let mut ep_events = Vec::new();
        let drained;
        let mut final_stats = None;
        let mut queued = false;
        {
            // Everything that must keep its order (datagrams on the wire, events for the
            // handler) is handed on while the state is still locked: another thread driving
            // the same connection cannot slip its batch in between.
            let mut st = lock(&self.0.state);
            let now = now.unwrap_or_else(Instant::now);
            let State { conn, armed, lost } = &mut *st;
            if transmit {
                let mut q = lock(&self.0.outq);
                while let Some(t) = conn.poll_transmit(now, MAX_DATAGRAMS) {
                    q.push_back(t);
                }
            }
            let mut evs = lock(&self.0.events);
            while let Some(e) = conn.poll_event() {
                if let proto::Event::Closed(_) = e {
                    if std::mem::replace(lost, true) {
                        continue;
                    }
                }
                evs.push_back(e);
                queued = true;
            }
            while let Some(e) = conn.poll_endpoint_event() {
                ep_events.push(e);
            }
            if let Some(t) = arm.then(|| conn.poll_timeout()).flatten() {
                if armed.is_none_or(|a| t < a) {
                    *armed = Some(t);
                    let target: Weak<dyn timer::Due> = self.0.me.clone();
                    timer::timer().schedule(t, target);
                }
            }
            drained = conn.is_drained();
            if drained {
                final_stats = Some(conn.stats());
            }
            if drained && !std::mem::replace(lost, true) {
                evs.push_back(proto::Event::Closed(ConnectionError::LocallyClosed));
                queued = true;
            }
        }
        if !ep_events.is_empty() {
            let mut e = lock(&ep.endpoint);
            for ev in &ep_events {
                e.handle_event(self.0.h, ev);
            }
            drop(e);
            if ep_events.iter().any(|ev| {
                matches!(
                    ev,
                    proto::EndpointEvent::RetireCid(_) | proto::EndpointEvent::Drained
                )
            }) {
                ep.routes_gen.fetch_add(1, Ordering::AcqRel);
            }
            for ev in ep_events {
                match ev {
                    proto::EndpointEvent::NewToken(t) => {
                        if let Some((store, name)) = &ep.tokens {
                            lock(store).insert(name.clone(), t);
                        }
                    }
                    proto::EndpointEvent::Migrated { .. } => ep.on_migrated(),
                    proto::EndpointEvent::MigrationFailed => ep.on_migration_failed(),
                    _ => {}
                }
            }
        }
        if transmit {
            self.send_queued();
        }
        if drained {
            let empty = {
                let mut conns = lock(&ep.conns);
                ep.routes_gen.fetch_add(1, Ordering::AcqRel);
                if conns.remove(&self.0.h).is_some() {
                    if let Some(st) = final_stats {
                        ep.closed.fetch_add(1, Ordering::Relaxed);
                        add_stats(&mut lock(&ep.closed_stats), &st);
                    }
                }
                conns.is_empty()
            };
            if empty && ep.factory.is_none() {
                // A client endpoint's only connection is gone: so is its UDP socket.
                let socks: Vec<Conn<Udp>> = lock(&ep.socks).values().cloned().collect();
                for s in socks {
                    s.close();
                }
            }
        }
        queued
    }

    /// Sends the queued datagrams; if another thread is already sending them, it sends ours
    /// too (the queue keeps the wire order without holding the state lock over syscalls).
    fn send_queued(&self) {
        loop {
            if self.0.sending.swap(true, Ordering::AcqRel) {
                return;
            }
            {
                let mut sock = lock(&self.0.tx_sock);
                loop {
                    let t = lock(&self.0.outq).pop_front();
                    let Some(t) = t else { break };
                    if t.probe {
                        self.0
                            .ep
                            .transmit_probe((t.dest, t.segment_size, t.data, t.ecn));
                    } else {
                        self.0
                            .ep
                            .transmit_via(&mut sock, t.dest, t.segment_size, t.data, t.ecn);
                    }
                }
            }
            self.0.sending.store(false, Ordering::Release);
            if lock(&self.0.outq).is_empty() {
                return;
            }
        }
    }

    /// Runs queued events through the handler, one deliverer at a time (a nested or concurrent
    /// call finds the handler taken and leaves its events to the one running).
    fn deliver(&self) {
        #[cfg(feature = "testing")]
        if testing::deferred(self.0.ep.factory.is_some()) {
            return;
        }
        loop {
            if lock(&self.0.events).is_empty() && !self.0.shutdown.load(Ordering::Acquire) {
                return;
            }
            let Some(mut h) = lock(&self.0.handler).take() else {
                if self.0.done.load(Ordering::Acquire) {
                    lock(&self.0.events).clear();
                }
                return;
            };
            let mut closed = false;
            let prev = DELIVERING.with(|d| d.replace(Arc::as_ptr(&self.0) as usize));
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
                    proto::Event::StreamWritable(id) => h.on_stream_writable(self, id),
                    proto::Event::Datagram(d) => h.on_datagram(self, d),
                    proto::Event::Closed(r) => {
                        self.0.done.store(true, Ordering::Release);
                        h.on_close(self, r);
                        closed = true;
                        break;
                    }
                }
            }
            if !closed && self.0.shutdown.swap(false, Ordering::AcqRel) {
                h.on_shutdown(self);
            }
            DELIVERING.with(|d| d.set(prev));
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
        // Asked to drive (`Connection::wake`): any entry of this connection's does it.
        let woken = self.woken.swap(false, Ordering::AcqRel);
        {
            let mut st = lock(&self.state);
            if st.armed == Some(at) {
                st.armed = None;
                st.conn.handle_timeout(Instant::now());
            } else if !woken {
                return;
            }
        }
        Connection(me).drive();
    }
}

// ---- the endpoint and its UDP side ----

type Factory = dyn Fn(&Connection) -> Box<dyn QuicHandler> + Send + Sync;

struct Ep {
    endpoint: Mutex<proto::Endpoint>,
    conns: Mutex<proto::KeyedMap<proto::ConnHandle, Connection>>,
    /// Client sockets by peer address, looked up for every datagram sent.
    socks: Mutex<proto::KeyedMap<SocketAddr, Conn<Udp>>>,
    /// A client's datagrams from before its socket was up.
    backlog: Mutex<Vec<Outgoing>>,
    /// A client's socket for the path a migration probes, once open, and the probe's datagrams
    /// from before that.
    probe: Mutex<Option<Conn<Udp>>>,
    probe_backlog: Mutex<Vec<Outgoing>>,
    factory: Option<Box<Factory>>,
    /// A client's token store and the server name its tokens are kept under.
    tokens: Option<(TokenStore, String)>,
    /// Connections accepted and closed, and the summed statistics of the closed ones (so the
    /// totals a scrape reports never go down).
    accepted: AtomicU64,
    closed: AtomicU64,
    closed_stats: Mutex<ConnectionStats>,
    /// Bumped whenever the endpoint removes a route (a retired connection ID, a drained
    /// connection): the routes the UDP handlers remember (`Route`) are valid while it is
    /// unchanged.
    routes_gen: AtomicU64,
}

/// Adds the counters of `b` to `a` (gauges such as RTT and the window are left alone).
fn add_stats(a: &mut ConnectionStats, b: &ConnectionStats) {
    for (x, y) in [(&mut a.udp_tx, &b.udp_tx), (&mut a.udp_rx, &b.udp_rx)] {
        x.datagrams = x.datagrams.wrapping_add(y.datagrams);
        x.bytes = x.bytes.wrapping_add(y.bytes);
        x.ios = x.ios.wrapping_add(y.ios);
    }
    a.sent_packets = a.sent_packets.wrapping_add(b.sent_packets);
    a.lost_packets = a.lost_packets.wrapping_add(b.lost_packets);
    a.lost_bytes = a.lost_bytes.wrapping_add(b.lost_bytes);
    a.congestion_events = a.congestion_events.wrapping_add(b.congestion_events);
    a.ecn_ce_events = a.ecn_ce_events.wrapping_add(b.ecn_ce_events);
}

impl Ep {
    fn new(
        endpoint: proto::Endpoint,
        factory: Option<Box<Factory>>,
        tokens: Option<(TokenStore, String)>,
    ) -> Ep {
        Ep {
            endpoint: Mutex::new(endpoint),
            conns: Mutex::new(proto::KeyedMap::default()),
            socks: Mutex::new(proto::KeyedMap::default()),
            backlog: Mutex::new(Vec::new()),
            probe: Mutex::new(None),
            probe_backlog: Mutex::new(Vec::new()),
            factory,
            tokens,
            accepted: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            closed_stats: Mutex::new(ConnectionStats::default()),
            routes_gen: AtomicU64::new(0),
        }
    }

    fn transmit(&self, dest: SocketAddr, seg: Option<usize>, data: Vec<u8>, ecn: u8) {
        let sock = lock(&self.socks).get(&dest).cloned();
        let sock = match sock {
            Some(sock) => sock,
            None => {
                // The socket is not up: the datagram waits in the backlog, unless the socket
                // came up meanwhile. `ClientAcceptor::on_open` flushes the backlog and then
                // publishes the socket under the backlog's lock, so nothing is sent ahead of
                // what waits there (a resumed client's 0-RTT ahead of its Initial, which the
                // server drops) and nothing is queued after the last flush.
                let mut backlog = lock(&self.backlog);
                let Some(sock) = lock(&self.socks).get(&dest).cloned() else {
                    if self.factory.is_none() {
                        backlog.push((dest, seg, data, ecn));
                    }
                    return;
                };
                sock
            }
        };
        send_out(&sock, seg, data, ecn);
    }

    /// [`Ep::transmit`] through `cache`, the connection's last socket (server): reused while it
    /// is open and has the same peer address, else looked up and remembered.
    fn transmit_via(
        &self,
        cache: &mut Option<Conn<Udp>>,
        dest: SocketAddr,
        seg: Option<usize>,
        data: Vec<u8>,
        ecn: u8,
    ) {
        if self.factory.is_none() {
            // A client has one socket (or two while migrating): no table worth skipping.
            return self.transmit(dest, seg, data, ecn);
        }
        if let Some(s) = cache.as_ref() {
            if s.peer_addr() == dest && s.is_open() {
                send_out(s, seg, data, ecn);
                return;
            }
        }
        let sock = lock(&self.socks).get(&dest).cloned();
        *cache = sock;
        match cache.as_ref() {
            Some(s) => send_out(s, seg, data, ecn),
            None => self.transmit(dest, seg, data, ecn),
        }
    }

    /// A datagram of the path a migration probes (client).
    fn transmit_probe(&self, t: Outgoing) {
        let sock = lock(&self.probe).clone();
        let sock = match sock {
            Some(sock) => sock,
            None => {
                // As in `transmit`: `ProbeAcceptor::on_open` flushes, then publishes.
                let mut backlog = lock(&self.probe_backlog);
                let Some(sock) = lock(&self.probe).clone() else {
                    backlog.push(t);
                    return;
                };
                sock
            }
        };
        let (_, seg, data, ecn) = t;
        let _ = sock.send_segments_ecn(data, seg.unwrap_or(0), ecn);
    }

    /// The probed path was validated: its socket becomes the client's socket, the others close.
    fn on_migrated(&self) {
        let Some(new) = lock(&self.probe).take() else {
            return;
        };
        let old: Vec<Conn<Udp>> = {
            let mut socks = lock(&self.socks);
            let old = socks
                .values()
                .filter(|s| s.id() != new.id())
                .cloned()
                .collect();
            socks.clear();
            socks.insert(new.peer_addr(), new);
            old
        };
        for s in old {
            s.close();
        }
    }

    /// The probed path did not answer: its socket closes.
    fn on_migration_failed(&self) {
        lock(&self.probe_backlog).clear();
        let probe = lock(&self.probe).take();
        if let Some(s) = probe {
            s.close();
        }
    }

    /// A datagram from `peer`. With `batch`, the connection it went to runs its handler and sends
    /// data now, but leaves its acknowledgment for the end of the receive batch (it is added to
    /// `batch` once and driven then): one ACK per batch instead of one per two packets.
    ///
    /// `route` is the peer's remembered route (its UDP handler's, so one I/O thread's): a
    /// short-header datagram to the same connection ID goes straight to that connection,
    /// without the endpoint's and the connection table's locks, which every I/O thread shares.
    fn on_datagram(
        self: &Arc<Ep>,
        peer: SocketAddr,
        ecn: u8,
        data: Rx<'_>,
        batch: Option<&mut Vec<Connection>>,
        route: &mut Option<Route>,
    ) {
        let now = Instant::now();
        if let Some(r) = route.as_ref() {
            if r.matches(&data) && r.epoch == self.routes_gen.load(Ordering::Acquire) {
                Ep::to_conn(&r.conn, now, peer, ecn, data, batch);
                return;
            }
        }
        // Read before the lookup: a route removed after it bumps the generation past this.
        let epoch = self.routes_gen.load(Ordering::Acquire);
        let ev = {
            let mut e = lock(&self.endpoint);
            match e.route_short(&data) {
                Some((cid, h)) => Ok((cid, h)),
                None => Err(e.handle_ecn(now, peer, ecn, &data)),
            }
        };
        let ev = match ev {
            Ok((cid, h)) => {
                let c = lock(&self.conns).get(&h).cloned();
                if let Some(c) = c {
                    Ep::to_conn(&c, now, peer, ecn, data, batch);
                    *route = Some(Route {
                        cid,
                        conn: c,
                        epoch,
                    });
                }
                return;
            }
            Err(ev) => ev,
        };
        match ev {
            None => {}
            Some(proto::DatagramEvent::Respond(t)) => self.transmit(t.dest, None, t.data, t.ecn),
            Some(proto::DatagramEvent::Conn(h)) => {
                let c = lock(&self.conns).get(&h).cloned();
                if let Some(c) = c {
                    Ep::to_conn(&c, now, peer, ecn, data, batch);
                }
            }
            Some(proto::DatagramEvent::New(h, conn)) => {
                let c = Connection::new(h, *conn, self.clone());
                lock(&self.conns).insert(h, c.clone());
                self.accepted.fetch_add(1, Ordering::Relaxed);
                if let Some(f) = &self.factory {
                    let handler = f(&c);
                    *lock(&c.0.handler) = Some(handler);
                }
                c.drive();
            }
        }
    }

    /// Hands a datagram to its connection (see [`Ep::on_datagram`]).
    fn to_conn(
        c: &Connection,
        now: Instant,
        peer: SocketAddr,
        ecn: u8,
        data: Rx<'_>,
        batch: Option<&mut Vec<Connection>>,
    ) {
        lock(&c.0.state)
            .conn
            .handle_shared_ecn(now, peer, ecn, data.into_pkt());
        match batch {
            Some(b) => {
                c.drive_received(now);
                if !b.iter().any(|x| Arc::ptr_eq(&x.0, &c.0)) {
                    b.push(c.clone());
                }
            }
            None => c.drive_at(Some(now)),
        }
    }
}

/// A peer's remembered route (see [`Ep::on_datagram`]): short-header datagrams to `cid` go to
/// `conn` while the endpoint's route generation is still `epoch`.
struct Route {
    cid: proto::ConnectionId,
    conn: Connection,
    epoch: u64,
}

impl Route {
    /// Whether `data` is a short-header packet to this route's connection ID.
    fn matches(&self, data: &[u8]) -> bool {
        let n = self.cid.len();
        data.first().is_some_and(|b| b & 0x80 == 0)
            && data.get(1..1 + n).is_some_and(|d| d == &self.cid[..])
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
        let config = config.0;
        let mut cfg = proto::ConnConfig::new(config.transport, config.migration);
        if let Some(n) = config.key_update {
            cfg.key_update_interval = n;
        }
        cfg.ecn_io = ecn_platform();
        cfg.preferred_address = config.preferred;
        cfg.versions = config.versions;
        cfg.prefer_version = config.prefer_version;
        cfg.zero_rtt = config.zero_rtt;
        let setup = proto::ServerSetup {
            tls: config.tls,
            cfg,
            retry: config.retry,
            max_connections: config.max_connections,
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

    /// New connections refused since the server started because it held
    /// [`max_connections`](ServerConfig::max_connections).
    pub fn refused_connections(&self) -> u64 {
        lock(&self.0.endpoint).refused()
    }

    /// Closes every connection with `code` and `reason`.
    pub fn close_all(&self, code: u32, reason: &[u8]) {
        let all: Vec<Connection> = lock(&self.0.conns).values().cloned().collect();
        for c in all {
            c.close(code, reason);
        }
    }
}

/// Reports the server's connections (ADR-015): `akio_quic_connections_open` (gauge),
/// `akio_quic_connections_accepted_total`, `akio_quic_connections_closed_total`,
/// `akio_quic_datagrams_total{dir}`, `akio_quic_bytes_total{dir}`, `akio_quic_packets_sent_total`,
/// `akio_quic_packets_lost_total`, `akio_quic_lost_bytes_total`,
/// `akio_quic_congestion_events_total` and `akio_quic_ecn_ce_events_total`. Totals cover open
/// connections and the ones that already closed. Register it with
/// `Telemetry::register_collector` (with a label telling servers apart if there are several).
impl Collector for QuicServer {
    fn collect(&self, out: &mut Families) {
        let ep = &self.0;
        let open: Vec<Connection> = lock(&ep.conns).values().cloned().collect();
        let mut t = *lock(&ep.closed_stats);
        for c in &open {
            add_stats(&mut t, &c.stats());
        }
        out.gauge(
            "akio_quic_connections_open",
            "QUIC connections open now.",
            &[],
            open.len() as f64,
        );
        type Row<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], u64);
        let counters: [Row<'_>; 11] = [
            (
                "akio_quic_connections_accepted_total",
                "QUIC connections accepted.",
                &[],
                ep.accepted.load(Ordering::Relaxed),
            ),
            (
                "akio_quic_connections_closed_total",
                "QUIC connections closed.",
                &[],
                ep.closed.load(Ordering::Relaxed),
            ),
            (
                "akio_quic_datagrams_total",
                "UDP datagrams of QUIC connections.",
                &[("dir", "rx")],
                t.udp_rx.datagrams,
            ),
            (
                "akio_quic_datagrams_total",
                "UDP datagrams of QUIC connections.",
                &[("dir", "tx")],
                t.udp_tx.datagrams,
            ),
            (
                "akio_quic_bytes_total",
                "UDP payload bytes of QUIC connections.",
                &[("dir", "rx")],
                t.udp_rx.bytes,
            ),
            (
                "akio_quic_bytes_total",
                "UDP payload bytes of QUIC connections.",
                &[("dir", "tx")],
                t.udp_tx.bytes,
            ),
            (
                "akio_quic_packets_sent_total",
                "QUIC packets sent.",
                &[],
                t.sent_packets,
            ),
            (
                "akio_quic_packets_lost_total",
                "QUIC packets declared lost.",
                &[],
                t.lost_packets,
            ),
            (
                "akio_quic_lost_bytes_total",
                "Bytes in QUIC packets declared lost.",
                &[],
                t.lost_bytes,
            ),
            (
                "akio_quic_congestion_events_total",
                "QUIC congestion events.",
                &[],
                t.congestion_events,
            ),
            (
                "akio_quic_ecn_ce_events_total",
                "QUIC congestion events signalled by ECN-CE.",
                &[],
                t.ecn_ce_events,
            ),
        ];
        for (name, help, labels, v) in counters {
            out.counter(name, help, labels, v as f64);
        }
    }
}

impl Clone for QuicServer {
    /// The same server (connections, configuration): serve it on several listeners, such as
    /// its [preferred address](ServerConfig::preferred_address).
    fn clone(&self) -> QuicServer {
        QuicServer(self.0.clone())
    }
}

impl Acceptor for QuicServer {
    type Handler = Udp;
    fn on_open(&self, c: &Conn<Udp>) -> Udp {
        lock(&self.0.socks).insert(c.peer_addr(), c.clone());
        Udp::new(self.0.clone(), false)
    }

    /// The peer's socket goes away (a drained listener or bound socket, or engine shutdown):
    /// each connection of this server from that address hears of it
    /// ([`QuicHandler::on_shutdown`]).
    fn on_shutdown(&self, c: &Conn<Udp>) {
        let peer = c.peer_addr();
        let conns: Vec<Connection> = lock(&self.0.conns).values().cloned().collect();
        for q in conns {
            if q.remote_addr() == peer {
                q.shut_down();
            }
        }
    }
}

/// The UDP connection handler under an endpoint (internal).
#[doc(hidden)]
pub struct Udp {
    ep: Arc<Ep>,
    client: bool,
    /// The I/O loop reports the end of receive batches (it called `on_batch_end` once): the
    /// connections a batch reached acknowledge then, once (see `Ep::on_datagram`). Until then
    /// (and on backends without the hook) every datagram is driven on its own.
    batched: bool,
    /// Connections that got datagrams in the current batch.
    pending: Vec<Connection>,
    /// The connection this peer's datagrams went to last (see `Ep::on_datagram`).
    route: Option<Route>,
}

impl Udp {
    fn new(ep: Arc<Ep>, client: bool) -> Udp {
        Udp {
            ep,
            client,
            batched: false,
            pending: Vec::new(),
            route: None,
        }
    }
}

impl fmt::Debug for Udp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Udp").finish_non_exhaustive()
    }
}

/// A datagram from the UDP layer: borrowed (copied into a pooled buffer if it reaches a
/// connection), or owned, cut off the receive slab, and then decrypted where it was received.
enum Rx<'a> {
    Slice(&'a [u8]),
    Owned(akio_buf::slab::ChunkMut),
}

impl Rx<'_> {
    fn into_pkt(self) -> bytes::PktBuf {
        match self {
            Rx::Slice(d) => bytes::PktBuf::Vec(bytes::pool::copy(d)),
            Rx::Owned(c) => bytes::PktBuf::Chunk(c),
        }
    }
}

impl std::ops::Deref for Rx<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Rx::Slice(d) => d,
            Rx::Owned(c) => c,
        }
    }
}

impl Handler for Udp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let batch = self.batched.then_some(&mut self.pending);
        self.ep.on_datagram(
            c.peer_addr(),
            c.rx_ecn(),
            Rx::Slice(data),
            batch,
            &mut self.route,
        );
    }

    /// Datagrams arrive as their own range of the receive slab: decrypted in place there, and
    /// their frames' `Bytes` share it (no copy at all, ADR-024).
    const OWNED_DATA: bool = true;

    fn on_data_owned(&mut self, c: &Conn<Self>, data: akio_buf::slab::ChunkMut) {
        let batch = self.batched.then_some(&mut self.pending);
        self.ep.on_datagram(
            c.peer_addr(),
            c.rx_ecn(),
            Rx::Owned(data),
            batch,
            &mut self.route,
        );
    }

    fn on_batch_end(&mut self, _c: &Conn<Self>) {
        self.batched = true;
        if self.pending.is_empty() {
            return;
        }
        let now = Instant::now();
        for c in self.pending.drain(..) {
            c.drive_at(Some(now));
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<akio_core::Error>) {
        // Whatever arrived before the close is handled (a batch cut short by it).
        for p in std::mem::take(&mut self.pending) {
            p.drive();
        }
        let current = {
            let mut socks = lock(&self.ep.socks);
            let current = socks.get(&c.peer_addr()).is_some_and(|s| s.id() == c.id());
            if current {
                socks.remove(&c.peer_addr());
            }
            current
        };
        {
            let mut probe = lock(&self.ep.probe);
            if probe.as_ref().is_some_and(|s| s.id() == c.id()) {
                *probe = None;
            }
        }
        // A client's sockets left behind by a migration (or a failed probe's) close quietly.
        if self.client && current {
            // The socket is gone: so is every connection on it.
            let all: Vec<Connection> = lock(&self.ep.conns).drain().map(|(_, c)| c).collect();
            for c in all {
                c.fail();
            }
        }
    }
}

/// A transmit: destination, segment size (several datagrams), bytes, ECN codepoint.
type Outgoing = (SocketAddr, Option<usize>, Vec<u8>, u8);

/// Sends `data` on `sock`: several datagrams of `seg` bytes as one GSO send where Linux
/// supports it (else one sendmmsg, else one by one); the boundaries survive either way.
fn send_out(sock: &Conn<Udp>, seg: Option<usize>, data: Vec<u8>, ecn: u8) {
    let _ = match (seg, ecn) {
        (Some(s), _) => sock.send_segments_ecn(data, s, ecn),
        (None, 0) => sock.send_owned(data),
        (None, _) => sock.send_segments_ecn(data, 0, ecn),
    };
}

/// Whether the UDP layer can mark datagrams ECT(0) (Linux and macOS, unless `AKIO_UDP_ECN=0`);
/// elsewhere connections do not try (validation would only fail).
fn ecn_platform() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
        && std::env::var("AKIO_UDP_ECN")
            .map_or(true, |v| v != "0" && !v.eq_ignore_ascii_case("off"))
}

/// Datagrams one `poll_transmit` may return in a single [`Conn::send_segments`].
const MAX_DATAGRAMS: usize = 10;

struct ClientAcceptor(Arc<Ep>);

/// Opens the socket of the path a client migration probes.
struct ProbeAcceptor(Arc<Ep>);

impl Acceptor for ProbeAcceptor {
    type Handler = Udp;
    fn on_open(&self, c: &Conn<Udp>) -> Udp {
        // The waiting datagrams first, then the socket is published (see `Ep::transmit`).
        let mut backlog = lock(&self.0.probe_backlog);
        for (_, seg, data, ecn) in backlog.drain(..) {
            let _ = c.send_segments_ecn(data, seg.unwrap_or(0), ecn);
        }
        *lock(&self.0.probe) = Some(c.clone());
        drop(backlog);
        Udp::new(self.0.clone(), true)
    }
}

impl Acceptor for ClientAcceptor {
    type Handler = Udp;
    fn on_open(&self, c: &Conn<Udp>) -> Udp {
        // The waiting datagrams first, in order, then the socket is published: under the
        // backlog's lock, so no other thread sends ahead of them (see `Ep::transmit`).
        let peer = c.peer_addr();
        let mut backlog = lock(&self.0.backlog);
        for (dest, seg, data, ecn) in backlog.drain(..) {
            if dest == peer {
                send_out(c, seg, data, ecn);
            }
        }
        lock(&self.0.socks).insert(peer, c.clone());
        drop(backlog);
        Udp::new(self.0.clone(), true)
    }
}

/// Connects to `addr`, verifying the server as `server_name`, with `config` (see
/// [`client_config`]). The connection uses a UDP socket of its own; the engine needs UDP
/// client threads ([`akio::EngineBuilder::udp_client_threads`]) and must be started. Streams
/// can be opened once the handshake completes ([`QuicHandler::on_connected`]), or right away
/// when the connection resumes with 0-RTT ([`ClientConfig::zero_rtt`]; check
/// [`Connection::open_bi`]'s result).
pub fn dial<H: QuicHandler>(
    engine: &akio::Engine,
    addr: SocketAddr,
    server_name: &str,
    config: ClientConfig,
    handler: H,
) -> Result<Connection, Error> {
    let config = config.0;
    let token = lock(&config.tokens).get(server_name).cloned();
    let mut endpoint = proto::Endpoint::new(None);
    let mut cfg = proto::ConnConfig::new(config.transport.clone(), true);
    if let Some(n) = config.key_update {
        cfg.key_update_interval = n;
    }
    cfg.ecn_io = ecn_platform();
    cfg.version = config.version.wire();
    cfg.zero_rtt = config.zero_rtt;
    let (h, conn) = endpoint.connect(Instant::now(), cfg, &config.tls, server_name, addr, token)?;
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
