//! TCP allocations (RFC 6062) driven by an `akio` engine: [`TcpAllocation`].
//!
//! The control connection is a connection of the engine (TCP, or TLS with
//! [`ServerTransport::Tls`]); its messages are cut by [`FrameReader`] and fed to a [`Client`],
//! whose timers run on one thread shared by every allocation of the process
//! ("akio-turn-timer"). Data connections are connections of the engine too: each carries a
//! [`Transport`] layer (under TLS's, when there is one) that sends the ConnectionBind first,
//! holds what the application sends until the success response, and then passes bytes through
//! both ways, so the application's handler sees nothing but the peer's bytes. A failed bind
//! closes the connection with an error, as a failed TLS handshake does.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use akio::tls::{self, Tls};
use akio::{Acceptor, Conn, Engine, Handler, Transport};

use super::{
    Client, ClientConfig, ClientError, ClientEvent, ClientState, DataConnection, DataState,
};
use crate::framing::FrameReader;
use crate::timer;

/// Bytes the control connection holds while it is being dialed (the Allocate and a few
/// requests); more is dropped (and retried by the client's own timeouts).
const MAX_CONNECTING: usize = 64 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// How a [`TcpAllocation`] reaches its TURN server.
#[derive(Clone)]
#[non_exhaustive]
pub enum ServerTransport {
    /// Plain TCP.
    Tcp,
    /// TLS (`turns:`): the client configuration and the server name verified and sent as SNI.
    Tls(tls::ClientConfig, String),
}

impl fmt::Debug for ServerTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerTransport::Tcp => f.write_str("Tcp"),
            ServerTransport::Tls(_, name) => f.debug_tuple("Tls").field(name).finish(),
        }
    }
}

/// What happened to a [`TcpAllocation`], given to its event callback.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllocationEvent {
    /// The allocation exists.
    Allocated {
        /// The relayed transport address (a TCP one).
        relayed: SocketAddr,
        /// The client's address as the server saw it, when the response said.
        mapped: Option<SocketAddr>,
        /// The lifetime granted (the allocation is refreshed before it runs out).
        lifetime: Duration,
    },
    /// A peer holding a permission ([`TcpAllocation::create_permission`]) connected to the
    /// relayed address: take it with [`TcpAllocation::accept`] within 30 seconds, or let the
    /// server close it.
    ConnectionAttempt {
        /// The peer.
        peer: SocketAddr,
        /// Its `CONNECTION-ID`.
        id: u32,
    },
    /// The server refused a permission for this peer.
    PeerFailed(SocketAddr, ClientError),
    /// The allocation could not be made, or it is lost (a refresh failed, the control
    /// connection closed): the allocation is done, and so are its data connections (the
    /// server closes them).
    Failed(ClientError),
    /// [`TcpAllocation::close`] finished.
    Closed,
}

type OnEvent = dyn Fn(&TcpAllocation, AllocationEvent) + Send + Sync;
/// The `on_error` of a data connection, called at most once: by the dial's failure or by the
/// bind's.
type OnError = Arc<Mutex<Option<Box<dyn FnOnce(ClientError) + Send>>>>;

fn report(on_error: &OnError, e: ClientError) {
    let f = lock(on_error).take();
    if let Some(f) = f {
        f(e);
    }
}
/// What a [`TcpAllocation::connect`] does once the server answered: bind, or report failure.
type OnConnect = Box<dyn FnOnce(&TcpAllocation, Result<u32, ClientError>) + Send>;

/// A TCP allocation (RFC 6062) on a TURN server, driven by an `akio` [`Engine`]: nothing
/// blocks, and the connections to peers are ordinary engine connections served by the
/// application's own [`Acceptor`]. Clone it to share it; dropping the last clone closes the
/// control connection, which ends the allocation and its connections on the server.
///
/// - [`open`](Self::open) dials the server and allocates; the event callback reports
///   [`AllocationEvent::Allocated`] (or `Failed`). Refreshes are automatic.
/// - [`connect`](Self::connect) asks the server for a connection to a peer (a Connect, no
///   permission needed); once it is up, a new connection to the server is dialed and bound to
///   it, and the acceptor's `on_open` runs for it like for any dialed connection: what the
///   handler sends goes to the peer and `on_data` gets what the peer sends.
/// - [`create_permission`](Self::create_permission) lets a peer connect to the relayed
///   address; each that does is reported as [`AllocationEvent::ConnectionAttempt`] and taken
///   with [`accept`](Self::accept), the same way.
///
/// A data connection opens (`on_open`) when its TCP (and TLS) connection to the server is up;
/// what the handler sends meanwhile waits for the ConnectionBind's success. Everything that
/// keeps it from carrying the peer's bytes goes to the `on_error` given with the call, at most
/// once: the Connect refused, the dial failing, the bind refused or timing out, TLS failing. A
/// connection that opened and then failed to bind is also closed (`on_close` follows, without
/// the reason). `on_error` never runs once the bind succeeded.
///
/// The engine needs TCP I/O threads ([`akio::EngineBuilder::client_threads`] or a TCP
/// listener). Callbacks run on I/O threads or the shared timer thread, with no lock held: they
/// may call back into the allocation but must not block.
///
/// Connect requests time out after [`ClientConfig::timeout`] (39.5 s; servers give up after
/// 30 s, RFC 6062 section 5.2) and ConnectionBinds as well.
#[derive(Clone)]
pub struct TcpAllocation(Arc<Shared>);

impl fmt::Debug for TcpAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st = lock(&self.0.state);
        f.debug_struct("TcpAllocation")
            .field("server", &self.0.cfg.server)
            .field("transport", &self.0.transport)
            .field("state", &st.client.state())
            .field("relayed", &st.client.relayed_addr())
            .finish_non_exhaustive()
    }
}

struct Shared {
    cfg: ClientConfig,
    transport: ServerTransport,
    engine: Weak<Engine>,
    on_event: Box<OnEvent>,
    state: Mutex<State>,
    me: Weak<Shared>,
}

enum Link {
    /// Dialing: what the client sent meanwhile.
    Connecting(Vec<Vec<u8>>),
    Open(Conn<Control>),
    /// Closed (or never opened): the client is done.
    Down,
}

enum Deferred {
    Event(AllocationEvent),
    Connect(OnConnect, Result<u32, ClientError>),
    Close(Conn<Control>),
}

struct State {
    client: Client,
    link: Link,
    armed: Option<Instant>,
    /// Connects waiting for the server's answer, by peer.
    connects: HashMap<SocketAddr, OnConnect>,
    deferred: Vec<Deferred>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        let st = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        if let Link::Open(c) = mem::replace(&mut st.link, Link::Down) {
            c.close();
        }
    }
}

impl TcpAllocation {
    /// Dials `cfg.server` over `transport` on `engine` and allocates (`cfg` is used with
    /// [`ClientConfig::tcp_allocation`] set). `on_event` gets what happens to the allocation;
    /// it receives the allocation itself, so it can [`accept`](Self::accept) connection
    /// attempts. The engine must have been started.
    pub fn open(
        engine: &Arc<Engine>,
        cfg: ClientConfig,
        transport: ServerTransport,
        on_event: impl Fn(&TcpAllocation, AllocationEvent) + Send + Sync + 'static,
    ) -> TcpAllocation {
        let cfg = cfg.tcp_allocation(true);
        let shared = Arc::new_cyclic(|me| Shared {
            state: Mutex::new(State {
                client: Client::new(cfg.clone(), Instant::now()),
                link: Link::Connecting(Vec::new()),
                armed: None,
                connects: HashMap::new(),
                deferred: Vec::new(),
            }),
            cfg,
            transport,
            engine: Arc::downgrade(engine),
            on_event: Box::new(on_event),
            me: me.clone(),
        });
        let a = TcpAllocation(shared);
        a.dial_control(engine);
        a.with(|_| ());
        a
    }

    /// The client's settings.
    pub fn config(&self) -> &ClientConfig {
        &self.0.cfg
    }

    /// The state of the allocation.
    pub fn state(&self) -> ClientState {
        lock(&self.0.state).client.state()
    }

    /// The relayed address, once allocated.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        lock(&self.0.state).client.relayed_addr()
    }

    /// The client's address as the server saw it, once allocated.
    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        lock(&self.0.state).client.mapped_addr()
    }

    /// Lets `peer`'s IP address connect to the relayed address (a permission, kept refreshed
    /// until the allocation closes). `false`: not allocated yet, or too many peers. A refusal
    /// is reported as [`AllocationEvent::PeerFailed`].
    pub fn create_permission(&self, peer: SocketAddr) -> bool {
        self.with(|st| st.client.create_permission(Instant::now(), peer))
    }

    /// Asks the server to connect to `peer` from the relayed address (a Connect); when it has,
    /// a new connection to the server is dialed, bound to that connection and served by
    /// `acceptor` (see the type's docs). `on_error` is called instead if the server refuses
    /// (447: the peer could not be reached; 446: a connection with it exists) or the data
    /// connection cannot be dialed. `false` (and neither is called): not allocated, or a
    /// Connect to `peer` is in flight already.
    pub fn connect<A: Acceptor>(
        &self,
        peer: SocketAddr,
        acceptor: A,
        on_error: impl FnOnce(ClientError) + Send + 'static,
    ) -> bool {
        let then: OnConnect = Box::new(move |a: &TcpAllocation, r| match r {
            Ok(id) => a.accept(id, acceptor, on_error),
            Err(e) => on_error(e),
        });
        self.with(|st| {
            if !st.client.connect(Instant::now(), peer) {
                return false;
            }
            st.connects.insert(peer, then);
            true
        })
    }

    /// Takes connection `id` (from [`AllocationEvent::ConnectionAttempt`]): dials a new
    /// connection to the server, binds it to `id` and serves it with `acceptor` (see the
    /// type's docs). `on_error`: the allocation has no credentials yet (not allocated), or the
    /// dial failed.
    pub fn accept<A: Acceptor>(
        &self,
        id: u32,
        acceptor: A,
        on_error: impl FnOnce(ClientError) + Send + 'static,
    ) {
        let bind = lock(&self.0.state)
            .client
            .data_connection(Instant::now(), id);
        let Some(bind) = bind else {
            return on_error(ClientError::Protocol("not allocated"));
        };
        let Some(engine) = self.0.engine.upgrade() else {
            return on_error(io_error(&io::Error::other("the engine is gone")));
        };
        let timeout = self.0.cfg.timeout;
        let inner = match &self.0.transport {
            ServerTransport::Tcp => Layer::Plain(acceptor),
            ServerTransport::Tls(cfg, name) => match Tls::client(cfg.clone(), name, acceptor) {
                Ok(t) => Layer::Tls(t),
                Err(e) => return on_error(io_error(&e)),
            },
        };
        let on_error: OnError = Arc::new(Mutex::new(Some(Box::new(on_error))));
        let acc = BindAcceptor {
            inner,
            bind: Mutex::new(Some(bind)),
            on_error: on_error.clone(),
            timeout,
        };
        engine.dial(self.0.cfg.server, acc, move |e| {
            report(&on_error, io_error(&e));
        });
    }

    /// Deletes the allocation (a Refresh with lifetime 0), then closes the control connection;
    /// [`AllocationEvent::Closed`] follows. Data connections end with the allocation.
    pub fn close(&self) {
        self.with(|st| {
            st.client.close(Instant::now());
            if st.client.state() == ClientState::Closed {
                // Closed before it was made: nothing to delete.
                if let Link::Open(c) = mem::replace(&mut st.link, Link::Down) {
                    st.deferred.push(Deferred::Close(c));
                }
            }
        });
    }

    // ---- driving the client ----

    /// Runs `f` on the state, then sends what the client produced, collects its events, arms
    /// the timer, releases the lock and runs the callbacks.
    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let (r, d) = {
            let mut st = lock(&self.0.state);
            let r = f(&mut st);
            self.after(&mut st);
            (r, mem::take(&mut st.deferred))
        };
        for d in d {
            match d {
                Deferred::Event(e) => (self.0.on_event)(self, e),
                Deferred::Connect(then, r) => then(self, r),
                Deferred::Close(c) => c.close(),
            }
        }
        r
    }

    fn after(&self, st: &mut State) {
        while let Some(m) = st.client.poll_transmit() {
            match &mut st.link {
                Link::Connecting(q) => {
                    if q.iter().map(Vec::len).sum::<usize>() + m.len() <= MAX_CONNECTING {
                        q.push(m);
                    }
                }
                Link::Open(c) => {
                    let _ = c.send_owned(m);
                }
                Link::Down => {}
            }
        }
        while let Some(e) = st.client.poll_event() {
            let ev = match e {
                ClientEvent::Allocated {
                    relayed,
                    mapped,
                    lifetime,
                } => AllocationEvent::Allocated {
                    relayed,
                    mapped,
                    lifetime,
                },
                ClientEvent::ConnectionAttempt { peer, id } => {
                    AllocationEvent::ConnectionAttempt { peer, id }
                }
                ClientEvent::PeerFailed(p, e) => AllocationEvent::PeerFailed(p, e),
                ClientEvent::Connected { peer, id } => {
                    if let Some(then) = st.connects.remove(&peer) {
                        st.deferred.push(Deferred::Connect(then, Ok(id)));
                    }
                    continue;
                }
                ClientEvent::ConnectFailed(peer, e) => {
                    if let Some(then) = st.connects.remove(&peer) {
                        st.deferred.push(Deferred::Connect(then, Err(e)));
                    }
                    continue;
                }
                ClientEvent::Failed(e) => {
                    self.done(st, Some(&e));
                    AllocationEvent::Failed(e)
                }
                ClientEvent::Closed => {
                    self.done(st, None);
                    AllocationEvent::Closed
                }
            };
            st.deferred.push(Deferred::Event(ev));
        }
        if let Some(t) = st.client.poll_timeout() {
            if st.armed.is_none_or(|a| t < a) {
                st.armed = Some(t);
                let target: Weak<dyn timer::Due> = self.0.me.clone();
                timer::timer().schedule(t, target);
            }
        }
    }

    /// The client is done: pending Connects fail, the control connection closes.
    fn done(&self, st: &mut State, e: Option<&ClientError>) {
        let e = e
            .cloned()
            .unwrap_or(ClientError::Protocol("allocation closed"));
        for (_, then) in st.connects.drain() {
            st.deferred.push(Deferred::Connect(then, Err(e.clone())));
        }
        if let Link::Open(c) = mem::replace(&mut st.link, Link::Down) {
            st.deferred.push(Deferred::Close(c));
        }
    }

    fn dial_control(&self, engine: &Arc<Engine>) {
        let acc = ControlAcceptor(self.0.me.clone());
        let me = self.0.me.clone();
        let on_error = move |e: io::Error| {
            if let Some(s) = me.upgrade() {
                TcpAllocation(s).link_down(&io_error(&e));
            }
        };
        match &self.0.transport {
            ServerTransport::Tcp => engine.dial(self.0.cfg.server, acc, on_error),
            ServerTransport::Tls(cfg, name) => match Tls::client(cfg.clone(), name, acc) {
                Ok(t) => engine.dial(self.0.cfg.server, t, on_error),
                Err(e) => on_error(e),
            },
        }
    }

    /// The control connection (or its dial) ended.
    fn link_down(&self, e: &ClientError) {
        self.with(|st| {
            if matches!(st.link, Link::Down) {
                return;
            }
            st.link = Link::Down;
            match st.client.state() {
                ClientState::Allocating | ClientState::Allocated => {
                    // The server deletes an allocation whose control connection closes.
                    st.client.fail_with(e.clone());
                }
                ClientState::Closing => st.client.fail_with(ClientError::Timeout),
                ClientState::Failed | ClientState::Closed => {}
            }
        });
    }

    fn link_up(&self, c: &Conn<Control>) -> bool {
        self.with(
            |st| match mem::replace(&mut st.link, Link::Open(c.clone())) {
                Link::Connecting(q) => {
                    for m in q {
                        let _ = c.send_owned(m);
                    }
                    true
                }
                other => {
                    st.link = other;
                    false
                }
            },
        )
    }
}

impl timer::Due for Shared {
    fn fire(&self, at: Instant) {
        let Some(me) = self.me.upgrade() else { return };
        TcpAllocation(me).with(|st| {
            if st.armed != Some(at) {
                return;
            }
            st.armed = None;
            st.client.handle_timeout(Instant::now());
        });
    }
}

fn io_error(e: &io::Error) -> ClientError {
    ClientError::Io(e.kind(), e.to_string())
}

/// Opens the control connection.
struct ControlAcceptor(Weak<Shared>);

impl Acceptor for ControlAcceptor {
    type Handler = Control;

    fn on_open(&self, c: &Conn<Control>) -> Control {
        let up = self
            .0
            .upgrade()
            .is_some_and(|s| TcpAllocation(s).link_up(c));
        if !up {
            c.close();
        }
        Control {
            shared: self.0.clone(),
            reader: FrameReader::new(),
        }
    }
}

/// The control connection of a [`TcpAllocation`].
struct Control {
    shared: Weak<Shared>,
    reader: FrameReader,
}

impl fmt::Debug for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Control").finish_non_exhaustive()
    }
}

impl Handler for Control {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let Some(s) = self.shared.upgrade() else {
            c.close();
            return;
        };
        let a = TcpAllocation(s);
        let mut msgs = Vec::new();
        if self.reader.push(data, |m| msgs.push(m.to_vec())).is_err() {
            c.close();
            return;
        }
        if !msgs.is_empty() {
            a.with(|st| {
                let now = Instant::now();
                for m in &msgs {
                    let _ = st.client.handle_input(now, m);
                }
            });
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<akio::Error>) {
        if let Some(s) = self.shared.upgrade() {
            let why = err.map_or_else(
                || "the control connection closed".to_owned(),
                |e| format!("the control connection closed: {e}"),
            );
            TcpAllocation(s).link_down(&ClientError::Io(io::ErrorKind::ConnectionAborted, why));
        }
    }
}

// ---- data connections ----

enum Layer<A: Acceptor> {
    Plain(A),
    Tls(Tls<A>),
}

/// Serves a data connection with the application's acceptor, under a [`BindTransport`].
struct BindAcceptor<A: Acceptor> {
    inner: Layer<A>,
    bind: Mutex<Option<DataConnection>>,
    on_error: OnError,
    timeout: Duration,
}

impl<A: Acceptor> Acceptor for BindAcceptor<A> {
    type Handler = A::Handler;

    fn on_open(&self, c: &Conn<A::Handler>) -> A::Handler {
        match &self.inner {
            Layer::Plain(a) => a.on_open(c),
            Layer::Tls(t) => t.on_open(c),
        }
    }

    fn on_shutdown(&self, c: &Conn<A::Handler>) {
        match &self.inner {
            Layer::Plain(a) => a.on_shutdown(c),
            Layer::Tls(t) => t.on_shutdown(c),
        }
    }

    fn transport(&self) -> Option<Box<dyn Transport>> {
        let bind = lock(&self.bind).take()?;
        let tls = match &self.inner {
            Layer::Plain(_) => None,
            Layer::Tls(t) => t.transport(),
        };
        Some(Box::new(BindTransport {
            tls,
            bind,
            bound: false,
            held: Vec::new(),
            on_error: Some(self.on_error.clone()),
            timeout: self.timeout,
        }))
    }
}

/// The ConnectionBind of a data connection as a byte-stream layer (over TLS's, if any): the
/// request goes first, the application's bytes wait for the success response, then bytes pass
/// through as they are.
struct BindTransport {
    tls: Option<Box<dyn Transport>>,
    bind: DataConnection,
    bound: bool,
    /// What the application sent before the bind.
    held: Vec<u8>,
    /// Told why the bind failed (dropped once bound).
    on_error: Option<OnError>,
    timeout: Duration,
}

impl BindTransport {
    /// Reports a failed bind on the timer thread: this runs under the connection's lock.
    fn failed(&mut self, e: ClientError) {
        if let Some(on_error) = self.on_error.take() {
            timer::timer().defer(Box::new(move || report(&on_error, e)));
        }
    }

    fn seal_below(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match &mut self.tls {
            Some(t) => t.seal(data, out),
            None => {
                out.extend_from_slice(data);
                Ok(())
            }
        }
    }
}

impl Drop for BindTransport {
    /// The connection ended before the bind was answered (closed, the deadline, TLS failed).
    fn drop(&mut self) {
        if !self.bound {
            self.failed(ClientError::Io(
                io::ErrorKind::ConnectionAborted,
                "the data connection closed before its ConnectionBind was answered".into(),
            ));
        }
    }
}

impl Transport for BindTransport {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        let mut decoded = Vec::new();
        let data: &[u8] = match &mut self.tls {
            Some(t) => match t.recv(cipher, &mut decoded, out) {
                Ok(()) => &decoded,
                Err(e) => {
                    self.failed(io_error(&e));
                    return Err(e);
                }
            },
            None => cipher,
        };
        if self.bound {
            plain.extend_from_slice(data);
            return Ok(());
        }
        let used = self.bind.handle_input(data);
        while let Some(m) = self.bind.poll_transmit() {
            self.seal_below(&m, out)?;
        }
        match self.bind.state().clone() {
            DataState::Binding => Ok(()),
            DataState::Bound => {
                self.bound = true;
                self.on_error = None;
                plain.extend_from_slice(&data[used..]);
                let held = mem::take(&mut self.held);
                if held.is_empty() {
                    Ok(())
                } else {
                    self.seal_below(&held, out)
                }
            }
            DataState::Failed(e) => {
                let err = io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("ConnectionBind: {e}"),
                );
                self.failed(e);
                Err(err)
            }
        }
    }

    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if self.bound {
            self.seal_below(plain, out)
        } else {
            self.held.extend_from_slice(plain);
            Ok(())
        }
    }

    fn shutdown(&mut self, out: &mut Vec<u8>) {
        if let Some(t) = &mut self.tls {
            t.shutdown(out);
        }
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn name(&self) -> &'static str {
        if self.tls.is_some() {
            "turn-tls"
        } else {
            "turn"
        }
    }

    fn handshaking(&self) -> bool {
        !self.bound
    }

    fn handshake_timeout(&self) -> Option<Duration> {
        Some(self.timeout)
    }

    fn set_waker(&mut self, waker: akio_core::TransportWaker) {
        if let Some(t) = &mut self.tls {
            t.set_waker(waker);
        }
    }
}
