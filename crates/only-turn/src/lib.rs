#![forbid(unsafe_code)]
//! STUN and TURN for `only`: servers over `only` UDP, TCP and TLS listeners, and a sans-io client.
//!
//! - [`stun`]: the STUN message codec (RFC 8489) with the TURN (RFC 8656) and ICE attributes,
//!   `MESSAGE-INTEGRITY` and `FINGERPRINT`; also used by `only-webrtc`.
//! - [`StunServer`]: answers Binding requests on a [`only::Listener::udp`] (clients learn their
//!   server-reflexive address).
//! - [`TurnServer`]: a TURN relay over UDP: allocations with long-term credentials
//!   ([`static_auth`], [`ephemeral_auth`]), permissions, channels, Send/Data indications,
//!   refreshes and lifetimes, quotas and a peer policy that refuses relaying into private
//!   networks by default. Relay sockets are bound at run time with
//!   [`only::Engine::bind_udp`]. It also answers Binding requests, so it is a STUN server too.
//! - [`TurnStream`] ([`TurnServer::stream`]): the same server for TCP listeners, and for TLS
//!   ones through [`only::tls::Tls`] (`turns:`, RFC 8656 section 3.1): STUN and ChannelData
//!   framed on the stream ([`framing`]). An allocation lives as long as its connection. Its
//!   relay is UDP, or TCP when the client asks for it (RFC 6062, `TurnConfig::tcp_relays`):
//!   a listening socket on the relayed address, Connect requests opening connections to peers
//!   from it, ConnectionAttempt indications for peers with a permission connecting to it, and
//!   ConnectionBind requests on new client connections, after which bytes are relayed as they
//!   are, with backpressure linking both sides.
//! - [`TurnDtls`] ([`TurnServer::dtls`]): the same server for UDP listeners whose clients talk
//!   DTLS (RFC 7350, `turns:` with `transport=udp`), on `only-dtls`: stateless cookies, DTLS
//!   1.3 with fallback to 1.2, one STUN or ChannelData message per record. An allocation lives
//!   as long as its DTLS association.
//! - [`client::Client`]: a sans-io TURN client (allocate, refresh, permissions, channels) over
//!   UDP or a stream, and TCP allocations ([`client::ClientConfig::tcp_allocation`],
//!   [`client::Client::connect`], [`client::DataConnection`]).
//! - [`TurnCore`]: the same server as a sans-io state machine.
//!
//! Callbacks run on the I/O thread that read the datagram (the listener's or a relay's) and
//! lock only the shard of the allocation concerned; expiry is swept shard by shard by one
//! background thread per server.
//!
//! ```no_run
//! use std::sync::Arc;
//! use only::{Engine, Listener};
//! use only_turn::{TurnConfig, TurnServer, static_auth};
//!
//! let auth = static_auth("example.org", [("alice", "secret")]);
//! let turn = TurnServer::new(TurnConfig::new("example.org", auth, "203.0.113.7".parse().unwrap()));
//! let engine = Arc::new(
//!     Engine::builder()
//!         .listen(Listener::udp("0.0.0.0:3478".parse().unwrap()).serve(turn.clone()))
//!         .build()
//!         .unwrap(),
//! );
//! turn.set_engine(&engine); // relays are bound through it
//! engine.run().unwrap();
//! ```
//!
//! Guide: [WebRTC, STUN and TURN](https://lesismal.github.io/only/en/protocols/webrtc.html)
//! (中文: [WebRTC、STUN 与 TURN](https://lesismal.github.io/only/zh-CN/protocols/webrtc.html)).
#![warn(clippy::unwrap_used)]

mod auth;
pub mod client;
mod core;
mod dtls;
pub mod framing;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod stun;
mod tcp;

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use only::{Acceptor, Conn, Engine, Handler, UdpBinding};

pub use crate::auth::{AuthFn, ephemeral_auth, ephemeral_credentials, static_auth};
use crate::core::Shared;
pub use crate::core::{PeerFilter, TurnConfig, TurnCore, TurnEnv, TurnStats, denied_by_default};
#[doc(hidden)]
pub use crate::tcp::TcpPeer;

pub(crate) fn fill_random(buf: &mut [u8]) {
    if only_crypto::rand::fill_random(buf).is_err() {
        // No OS randomness: fall back to a time-seeded mix (never expected in practice).
        let mut x = Instant::now().elapsed().as_nanos() as u64 ^ 0x9e37_79b9_7f4a_7c15;
        for b in buf {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- STUN server ----

/// Answers STUN Binding requests on a UDP listener with the sender's address
/// (`XOR-MAPPED-ADDRESS`); everything else is ignored.
#[derive(Clone, Debug, Default)]
pub struct StunServer {
    software: Option<String>,
}

impl StunServer {
    /// A server sending no `SOFTWARE`.
    pub fn new() -> StunServer {
        StunServer::default()
    }

    /// Sends `SOFTWARE` with this value.
    #[must_use]
    pub fn software(mut self, s: &str) -> Self {
        self.software = Some(s.to_owned());
        self
    }
}

impl Acceptor for StunServer {
    type Handler = StunPeer;
    fn on_open(&self, _c: &Conn<StunPeer>) -> StunPeer {
        StunPeer(self.software.clone())
    }
}

/// One client of a [`StunServer`] (internal).
#[doc(hidden)]
#[derive(Debug)]
pub struct StunPeer(Option<String>);

impl Handler for StunPeer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(r) = stun::binding_response(data, c.peer_addr(), self.0.as_deref()) {
            let _ = c.send_owned(r);
        }
    }
}

// ---- TURN server ----

/// The connection a client reaches the server on.
enum ClientConn {
    /// A UDP 5-tuple of the listener.
    Udp(Conn<TurnClient>),
    /// A TCP or TLS connection, and when it was accepted.
    Stream(Conn<TurnStreamClient>, Instant),
    /// A UDP 5-tuple of a DTLS listener and its DTLS association.
    Dtls(Conn<TurnDtlsClient>, Arc<Mutex<dtls::DtlsSession>>),
}

/// The transport a client reaches the server over; each has its own third of the shards, so
/// the same address on two transports names two clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    Udp = 0,
    Stream = 1,
    Dtls = 2,
}

/// One shard of a server: the allocations of the clients whose address hashes to it, and their
/// listener connections. A datagram locks only its own shard. UDP, stream and DTLS clients
/// live in separate shards (thirds of the table, see [`Wire`]).
struct Shard {
    core: TurnCore,
    clients: HashMap<SocketAddr, ClientConn>,
}

/// A relay socket and the shard its allocation lives in (an `EVEN-PORT` reservation can be
/// claimed from another shard, which moves it).
struct Relay {
    binding: UdpBinding,
    route: Arc<AtomicUsize>,
}

struct Inner {
    shared: Arc<Shared>,
    shards: Box<[Mutex<Shard>]>,
    /// Relay sockets by bound address, sharded by that address.
    relays: Box<[Mutex<HashMap<SocketAddr, Relay>>]>,
    /// Keyed per server, so clients cannot choose to crowd into one shard.
    hasher: RandomState,
    engine: OnceLock<Weak<Engine>>,
    /// TCP allocations' listeners and connections (RFC 6062).
    tcp: tcp::TcpRelays,
    me: Weak<Inner>,
}

impl Inner {
    /// The shard of a client on `wire`.
    fn shard_of(&self, addr: SocketAddr, wire: Wire) -> usize {
        let third = self.shards.len() / 3;
        let i = (self.hasher.hash_one(addr) as usize) & (third - 1);
        wire as usize * third + i
    }

    fn relays_of(&self, relay: SocketAddr) -> &Mutex<HashMap<SocketAddr, Relay>> {
        &self.relays[(self.hasher.hash_one(relay) as usize) & (self.relays.len() - 1)]
    }

    fn engine(&self) -> io::Result<Arc<Engine>> {
        self.engine
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| io::Error::other("TurnServer::set_engine was not called"))
    }

    /// Binds a relay socket whose peers' datagrams go to shard `route`.
    fn bind_relay(
        &self,
        addr: SocketAddr,
        route: usize,
    ) -> io::Result<(UdpBinding, Arc<AtomicUsize>)> {
        let route = Arc::new(AtomicUsize::new(route));
        let b = self
            .engine()?
            .bind_udp(addr, RelayAcceptor(self.me.clone(), route.clone()))?;
        Ok((b, route))
    }

    /// Runs `f` on shard `i`'s state machine with the `only` environment.
    fn with_shard<R>(
        &self,
        i: usize,
        prebound: Option<(UdpBinding, Arc<AtomicUsize>)>,
        f: impl FnOnce(&mut TurnCore, &mut Env<'_>) -> R,
    ) -> R {
        let mut g = lock(&self.shards[i]);
        let Shard { core, clients } = &mut *g;
        let mut env = Env {
            inner: self,
            shard: i,
            clients,
            prebound,
            incoming: None,
            dials: Vec::new(),
        };
        let r = f(core, &mut env);
        let unused = env.prebound.take();
        let dials = std::mem::take(&mut env.dials);
        drop(g);
        if let Some((b, _)) = unused {
            b.close();
        }
        // Started without the lock: a dial may fail at once, and its failure locks the shard.
        if !dials.is_empty() {
            if let Some(me) = self.me.upgrade() {
                for (relay, peer, id) in dials {
                    tcp::dial(&me, relay, peer, id);
                }
            }
        }
        r
    }
}

/// Shards for each transport (UDP, streams, DTLS): about four per CPU.
fn shard_count() -> usize {
    let cpus = std::thread::available_parallelism().map_or(4, usize::from);
    (cpus * 4).next_power_of_two().clamp(8, 256)
}

/// The `only` side of [`TurnEnv`] for one shard: its listener connections for clients, the
/// relay table for relays.
struct Env<'a> {
    inner: &'a Inner,
    shard: usize,
    clients: &'a mut HashMap<SocketAddr, ClientConn>,
    /// A relay bound before the shard was locked, for an authenticated Allocate.
    prebound: Option<(UdpBinding, Arc<AtomicUsize>)>,
    /// The connections of a peer just accepted on a TCP relay, for `accept_peer`.
    incoming: Option<Arc<tcp::Pair>>,
    /// Connections to peers to start once the shard is unlocked: relay, peer, id.
    dials: Vec<(SocketAddr, SocketAddr, u32)>,
}

impl TurnEnv for Env<'_> {
    fn send_to_client(&mut self, client: SocketAddr, data: &[u8]) {
        match self.clients.get(&client) {
            Some(ClientConn::Udp(c)) => {
                let _ = c.send(data);
            }
            Some(ClientConn::Stream(c, _)) => {
                // Relayed data keeps datagram semantics: dropped rather than queued behind a
                // slow reader. Responses always go.
                let relayed = stun::is_channel_data(data) || data.starts_with(&[0x00, 0x17]);
                if relayed && c.queued_bytes() > self.inner.shared.config().max_stream_queue {
                    return;
                }
                let _ = c.send(data);
            }
            Some(ClientConn::Dtls(c, s)) => {
                let mut out = Vec::new();
                lock(s).seal(data, &mut out);
                for d in out {
                    let _ = c.send_owned(d);
                }
            }
            None => {}
        }
    }

    fn pads_channel_data(&self, client: SocketAddr) -> bool {
        matches!(self.clients.get(&client), Some(ClientConn::Stream(..)))
    }

    fn send_to_peer(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8]) {
        if let Some(r) = lock(self.inner.relays_of(relay)).get(&relay) {
            let _ = r.binding.send_to(data, peer);
        }
    }

    fn open_relay(&mut self, _client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        let any_port = addr.port() == 0 && addr.ip() == self.inner.shared.config().relay_ip;
        let (binding, route) = match self.prebound.take() {
            Some(p) if any_port => p,
            other => {
                self.prebound = other;
                // EVEN-PORT allocations (a given port, or retries until an even one) still
                // bind here, under the shard's lock: they are rare.
                self.inner.bind_relay(addr, self.shard)?
            }
        };
        route.store(self.shard, Ordering::Relaxed);
        let bound = binding.local_addr();
        lock(self.inner.relays_of(bound)).insert(bound, Relay { binding, route });
        Ok(bound)
    }

    fn close_relay(&mut self, relay: SocketAddr) {
        let r = lock(self.inner.relays_of(relay)).remove(&relay);
        if let Some(r) = r {
            r.binding.close();
        }
    }

    fn adopt_relay(&mut self, relay: SocketAddr) {
        if let Some(r) = lock(self.inner.relays_of(relay)).get(&relay) {
            r.route.store(self.shard, Ordering::Relaxed);
        }
    }

    fn open_tcp_relay(&mut self, _client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.inner.engine()?;
        self.inner.tcp.open(self.inner, addr, self.shard)
    }

    fn close_tcp_relay(&mut self, relay: SocketAddr) {
        self.inner.tcp.close(relay);
    }

    fn connect_peer(&mut self, client: SocketAddr, relay: SocketAddr, peer: SocketAddr, id: u32) {
        let link = tcp::Link {
            client,
            shard: self.shard,
            pair: Arc::default(),
        };
        self.inner.tcp.insert(id, link);
        self.dials.push((relay, peer, id));
    }

    fn accept_peer(&mut self, client: SocketAddr, _relay: SocketAddr, _peer: SocketAddr, id: u32) {
        if let Some(pair) = self.incoming.take() {
            let link = tcp::Link {
                client,
                shard: self.shard,
                pair,
            };
            self.inner.tcp.insert(id, link);
        }
    }

    fn close_connection(&mut self, id: u32) {
        self.inner.tcp.close_link(id);
    }
}

/// A TURN server (and STUN server) for a [`only::Listener::udp`]. Clone it to keep a handle.
///
/// The engine serving it must be handed over with [`set_engine`](Self::set_engine) once built:
/// relay sockets are bound through [`Engine::bind_udp`]. A client that stays silent longer than
/// `Config::udp_idle_timeout` loses its listener connection, and data from peers is dropped
/// until it sends again (a refresh, a permission, data): keep that timeout above the
/// permission refresh interval (the default 60s is fine for clients refreshing every 5
/// minutes only if they also send keepalives; raise it for receive-only clients).
///
/// Allocations are split into shards by client address (about four per CPU), each with its own
/// lock: datagrams of different allocations do not contend, the expiry sweep holds one shard at
/// a time, and the relay socket of an authenticated Allocate is bound before any lock is taken.
///
/// [`stream`](Self::stream) serves TCP and TLS listeners with the same allocations, quotas and
/// credentials.
#[derive(Clone)]
pub struct TurnServer(Arc<Inner>);

impl fmt::Debug for TurnServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnServer")
            .field("allocations", &self.stats().allocations)
            .finish_non_exhaustive()
    }
}

impl TurnServer {
    /// A server with `cfg`.
    pub fn new(cfg: TurnConfig) -> TurnServer {
        let shared = Arc::new(Shared::new(cfg));
        let n = shard_count();
        let inner = Arc::new_cyclic(|me| Inner {
            shards: (0..3 * n)
                .map(|_| {
                    Mutex::new(Shard {
                        core: TurnCore::shard(shared.clone()),
                        clients: HashMap::new(),
                    })
                })
                .collect(),
            relays: (0..n).map(|_| Mutex::new(HashMap::new())).collect(),
            shared,
            hasher: RandomState::new(),
            engine: OnceLock::new(),
            tcp: tcp::TcpRelays::default(),
            me: me.clone(),
        });
        let weak = Arc::downgrade(&inner);
        let _ = std::thread::Builder::new()
            .name("only-turn-sweep".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(500));
                    let Some(inner) = weak.upgrade() else { return };
                    // One shard at a time: datagrams of the others go on meanwhile.
                    let wait = inner.shared.config().stream_allocate_timeout;
                    for i in 0..inner.shards.len() {
                        inner.with_shard(i, None, |core, env| {
                            let now = Instant::now();
                            core.handle_timeout(now, env);
                            // Stream connections that never allocated.
                            for c in env.clients.iter().filter_map(|(a, c)| match c {
                                ClientConn::Stream(c, since)
                                    if *since + wait <= now && core.relay_of(*a).is_none() =>
                                {
                                    Some(c)
                                }
                                _ => None,
                            }) {
                                c.close();
                            }
                            // DTLS retransmissions and handshake deadlines.
                            for c in env.clients.values() {
                                if let ClientConn::Dtls(c, s) = c {
                                    let mut out = dtls::DtlsOutput::default();
                                    lock(s).handle_timeout(now, &mut out);
                                    for d in out.transmit {
                                        let _ = c.send_owned(d);
                                    }
                                    if out.closed {
                                        c.close();
                                    }
                                }
                            }
                        });
                    }
                }
            });
        TurnServer(inner)
    }

    /// Hands over the engine serving this server's listener: relay sockets are bound on it.
    /// Held weakly (no reference cycle); later calls are ignored.
    pub fn set_engine(&self, engine: &Arc<Engine>) {
        let _ = self.0.engine.set(Arc::downgrade(engine));
    }

    /// Counters (allocations open, datagrams relayed, authentication failures), summed over
    /// the shards.
    pub fn stats(&self) -> TurnStats {
        let mut t = TurnStats::default();
        for s in &self.0.shards {
            let st = lock(s).core.stats();
            t.allocations += st.allocations;
            t.to_peer += st.to_peer;
            t.to_client += st.to_client;
            t.auth_failures += st.auth_failures;
            t.tcp_connections += st.tcp_connections;
        }
        t
    }

    /// The relayed address of `client`'s allocation (a UDP client).
    pub fn relay_of(&self, client: SocketAddr) -> Option<SocketAddr> {
        lock(&self.0.shards[self.0.shard_of(client, Wire::Udp)])
            .core
            .relay_of(client)
    }

    /// The relayed address of the allocation of the TCP or TLS client at `client` (a UDP
    /// relay, or a TCP one for a TCP allocation).
    pub fn stream_relay_of(&self, client: SocketAddr) -> Option<SocketAddr> {
        lock(&self.0.shards[self.0.shard_of(client, Wire::Stream)])
            .core
            .relay_of(client)
    }

    /// The relayed address of the allocation of the DTLS client at `client`.
    pub fn dtls_relay_of(&self, client: SocketAddr) -> Option<SocketAddr> {
        lock(&self.0.shards[self.0.shard_of(client, Wire::Dtls)])
            .core
            .relay_of(client)
    }

    /// The acceptor for UDP listeners of this server whose clients talk DTLS (TURN over
    /// DTLS, RFC 7350: `turns:<host>:<port>?transport=udp`, port 5349 by convention), with the
    /// certificate and key of `tls` (its default chain; client certificates only if it asks
    /// for them): same allocations, quotas and credentials as the plain UDP listener. DTLS 1.3
    /// is offered with fallback to 1.2 (only 1.3 if `tls` is TLS 1.3 only). ClientHellos are
    /// answered with stateless cookies; each STUN or ChannelData message travels in its own
    /// record, unpadded. An allocation lives as long as its DTLS association (close_notify, a
    /// fatal alert, a new handshake from the same address, or `Config::udp_idle_timeout` of
    /// silence ends it), so keep that timeout above the client's refresh interval. Clients
    /// are asked for 8-byte connection IDs (RFC 9146, RFC 9147 §9; negotiated, so clients
    /// without them are unaffected): a client whose address changes (NAT rebinding) keeps its
    /// association and allocation, and its path moves to the new address once a record from
    /// it authenticates ([`dtls_with_connection_ids`](Self::dtls_with_connection_ids) sets
    /// another length or none). Fails when the key or certificate cannot be used.
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use only::{Engine, Listener, tls};
    /// # use only_turn::{TurnConfig, TurnServer, static_auth};
    /// # fn f(turn: TurnServer, tls_cfg: tls::ServerConfig) -> std::io::Result<()> {
    /// let engine = Arc::new(
    ///     Engine::builder()
    ///         .listen(Listener::udp("0.0.0.0:3478".parse().unwrap()).serve(turn.clone()))
    ///         .listen(Listener::udp("0.0.0.0:5349".parse().unwrap()).serve(turn.dtls(&tls_cfg)?))
    ///         .build()?,
    /// );
    /// turn.set_engine(&engine);
    /// # Ok(()) }
    /// ```
    pub fn dtls(&self, tls: &only::tls::ServerConfig) -> io::Result<TurnDtls> {
        self.dtls_with_connection_ids(tls, Some(dtls::CID_LEN))
    }

    /// [`dtls`](Self::dtls) asking clients for connection IDs of `len` bytes (1 to 255;
    /// `None` or `Some(0)`: no connection IDs, every client is its 5-tuple).
    pub fn dtls_with_connection_ids(
        &self,
        tls: &only::tls::ServerConfig,
        len: Option<u8>,
    ) -> io::Result<TurnDtls> {
        Ok(TurnDtls(
            self.0.clone(),
            Arc::new(dtls::DtlsShared::new(tls, len)?),
        ))
    }

    /// The acceptor for TCP listeners (and TLS ones, wrapped in [`only::tls::Tls`]) of this
    /// server: same allocations, quotas and credentials as its UDP listener. Several
    /// listeners may share it.
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use only::{Engine, Listener, tls};
    /// # use only_turn::{TurnConfig, TurnServer, static_auth};
    /// # fn f(turn: TurnServer, tls_cfg: tls::ServerConfig) {
    /// let engine = Arc::new(
    ///     Engine::builder()
    ///         .listen(Listener::udp("0.0.0.0:3478".parse().unwrap()).serve(turn.clone()))
    ///         .listen(Listener::tcp("0.0.0.0:3478".parse().unwrap()).serve(turn.stream()))
    ///         .listen(
    ///             Listener::tcp("0.0.0.0:5349".parse().unwrap())
    ///                 .serve(tls::Tls::server(tls_cfg, turn.stream())),
    ///         )
    ///         .build()
    ///         .unwrap(),
    /// );
    /// turn.set_engine(&engine);
    /// # }
    /// ```
    pub fn stream(&self) -> TurnStream {
        TurnStream(self.0.clone())
    }

    /// Frees every allocation and closes the relay sockets.
    pub fn close_all(&self) {
        for i in 0..self.0.shards.len() {
            self.0.with_shard(i, None, |core, env| core.close_all(env));
        }
    }
}

impl Acceptor for TurnServer {
    type Handler = TurnClient;
    fn on_open(&self, c: &Conn<TurnClient>) -> TurnClient {
        let shard = self.0.shard_of(c.peer_addr(), Wire::Udp);
        lock(&self.0.shards[shard])
            .clients
            .insert(c.peer_addr(), ClientConn::Udp(c.clone()));
        TurnClient {
            inner: self.0.clone(),
            shard,
        }
    }

    fn on_shutdown(&self, _c: &Conn<TurnClient>) {
        self.close_all();
    }
}

/// One client 5-tuple of a [`TurnServer`] (internal).
#[doc(hidden)]
pub struct TurnClient {
    inner: Arc<Inner>,
    shard: usize,
}

impl fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnClient").finish_non_exhaustive()
    }
}

impl Handler for TurnClient {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let inner = &self.inner;
        let now = Instant::now();
        let client = c.peer_addr();
        // An authenticated Allocate gets its relay socket bound before the shard is locked.
        let prebound = if inner.shared.authenticated_allocate(now, client, data) {
            inner
                .bind_relay(
                    SocketAddr::new(inner.shared.config().relay_ip, 0),
                    self.shard,
                )
                .ok()
        } else {
            None
        };
        inner.with_shard(self.shard, prebound, |core, env| {
            core.handle_client(now, client, data, env);
        });
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        let mut shard = lock(&self.inner.shards[self.shard]);
        if matches!(shard.clients.get(&c.peer_addr()), Some(ClientConn::Udp(x)) if x.id() == c.id())
        {
            shard.clients.remove(&c.peer_addr());
        }
    }
}

// ---- TURN over TCP and TLS ----

/// The [`TurnServer`] acceptor for TCP and TLS listeners ([`TurnServer::stream`]).
#[derive(Clone)]
pub struct TurnStream(Arc<Inner>);

impl fmt::Debug for TurnStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnStream").finish_non_exhaustive()
    }
}

impl Acceptor for TurnStream {
    type Handler = TurnStreamClient;
    fn on_open(&self, c: &Conn<TurnStreamClient>) -> TurnStreamClient {
        let shard = self.0.shard_of(c.peer_addr(), Wire::Stream);
        let old = lock(&self.0.shards[shard])
            .clients
            .insert(c.peer_addr(), ClientConn::Stream(c.clone(), Instant::now()));
        if let Some(ClientConn::Stream(old, _)) = old {
            old.close(); // a stale connection from the same address and port
        }
        TurnStreamClient {
            inner: self.0.clone(),
            shard,
            reader: framing::FrameReader::new(),
            peer: None,
        }
    }

    fn on_shutdown(&self, _c: &Conn<TurnStreamClient>) {
        TurnServer(self.0.clone()).close_all();
    }
}

/// One TCP or TLS client connection of a [`TurnServer`] (internal).
#[doc(hidden)]
pub struct TurnStreamClient {
    inner: Arc<Inner>,
    shard: usize,
    reader: framing::FrameReader,
    /// A client data connection of a TCP allocation (RFC 6062), once bound: the peer's
    /// connection, which its bytes go to as they are.
    peer: Option<Conn<TcpPeer>>,
}

impl fmt::Debug for TurnStreamClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnStreamClient").finish_non_exhaustive()
    }
}

impl Handler for TurnStreamClient {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(p) = &self.peer {
            tcp::forward(c, p, data, self.inner.shared.config().tcp_relay_buffer);
            return;
        }
        let inner = self.inner.clone();
        let shard = self.shard;
        let client = c.peer_addr();
        let mut reader = std::mem::take(&mut self.reader);
        let mut peer = None;
        let r = reader.push_until(data, |msg| {
            let now = Instant::now();
            if is_connection_bind(msg) {
                peer = self.connection_bind(c, now, msg);
                return peer.is_none(); // bound: what follows is the client's data
            }
            let prebound = if inner.shared.authenticated_allocate(now, client, msg) {
                inner
                    .bind_relay(SocketAddr::new(inner.shared.config().relay_ip, 0), shard)
                    .ok()
            } else {
                None
            };
            inner.with_shard(shard, prebound, |core, env| {
                core.handle_client(now, client, msg, env);
            });
            true
        });
        self.reader = reader;
        match r {
            Ok(rest) => {
                if let Some(p) = peer {
                    if !rest.is_empty() {
                        tcp::forward(c, &p, rest, inner.shared.config().tcp_relay_buffer);
                    }
                    self.peer = Some(p);
                }
            }
            Err(_) => c.close(),
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        if let Some(p) = &self.peer {
            p.close(); // RFC 6062 section 5.5: the peer's connection goes with it
            return;
        }
        let client = c.peer_addr();
        self.inner.with_shard(self.shard, None, |core, env| {
            if matches!(env.clients.get(&client), Some(ClientConn::Stream(x, _)) if x.id() == c.id())
            {
                env.clients.remove(&client);
                // The allocation lives as long as its connection (RFC 8656 section 3.1).
                core.remove_client(client, env);
            }
        });
    }
}

/// Whether `msg` is a ConnectionBind request (RFC 6062).
fn is_connection_bind(msg: &[u8]) -> bool {
    stun::is_stun(msg)
        && stun::Message::parse(msg).is_ok_and(|m| {
            m.method() == stun::Method::CONNECTION_BIND && m.class() == stun::Class::Request
        })
}

impl TurnStreamClient {
    /// A ConnectionBind request on this connection: answered by the shard of the allocation
    /// holding the connection id. Returns the peer's connection when this connection is now
    /// bound to it.
    fn connection_bind(&self, c: &Conn<Self>, now: Instant, msg: &[u8]) -> Option<Conn<TcpPeer>> {
        let m = stun::Message::parse(msg).ok()?;
        let client = c.peer_addr();
        let id = m
            .get(stun::attr::CONNECTION_ID)
            .and_then(|v| <[u8; 4]>::try_from(v).ok())
            .map(u32::from_be_bytes);
        let link = id.and_then(|id| self.inner.tcp.link(id));
        let shard = link.as_ref().map_or(self.shard, |l| l.1);
        let owner = link.as_ref().map(|l| l.0);
        let (out, bound) = self.inner.with_shard(shard, None, |core, _| {
            core.connection_bind(now, client, &m, owner, true)
        })?;
        let (Some(_), Some((_, _, pair))) = (bound, link) else {
            let _ = c.send_owned(out);
            return None;
        };
        let peer = tcp::bind(&pair, c, out)?;
        // A data connection now: no allocation of its own, out of the client table (and of
        // the sweep of connections that never allocate).
        self.inner.with_shard(self.shard, None, |_, env| {
            if matches!(env.clients.get(&client), Some(ClientConn::Stream(x, _)) if x.id() == c.id())
            {
                env.clients.remove(&client);
            }
        });
        Some(peer)
    }
}

// ---- TURN over DTLS ----

/// The [`TurnServer`] acceptor for UDP listeners whose clients talk DTLS
/// ([`TurnServer::dtls`]).
#[derive(Clone)]
pub struct TurnDtls(Arc<Inner>, Arc<dtls::DtlsShared>);

impl fmt::Debug for TurnDtls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnDtls").finish_non_exhaustive()
    }
}

impl Acceptor for TurnDtls {
    type Handler = TurnDtlsClient;
    fn on_open(&self, c: &Conn<TurnDtlsClient>) -> TurnDtlsClient {
        let shard = self.0.shard_of(c.peer_addr(), Wire::Dtls);
        let session = self.1.session(c.peer_addr());
        lock(&self.0.shards[shard])
            .clients
            .insert(c.peer_addr(), ClientConn::Dtls(c.clone(), session.clone()));
        TurnDtlsClient {
            inner: self.0.clone(),
            dtls: self.1.clone(),
            shard,
            client: c.peer_addr(),
            session,
        }
    }

    fn on_shutdown(&self, c: &Conn<TurnDtlsClient>) {
        let shard = self.0.shard_of(c.peer_addr(), Wire::Dtls);
        let session = match lock(&self.0.shards[shard]).clients.get(&c.peer_addr()) {
            Some(ClientConn::Dtls(x, s)) if x.id() == c.id() => Some(s.clone()),
            _ => None,
        };
        if let Some(s) = session {
            let mut out = Vec::new();
            lock(&s).close(&mut out); // close_notify
            for d in out {
                let _ = c.send_owned(d);
            }
        }
        TurnServer(self.0.clone()).close_all();
    }
}

/// One DTLS client 5-tuple of a [`TurnServer`] (internal).
#[doc(hidden)]
pub struct TurnDtlsClient {
    inner: Arc<Inner>,
    dtls: Arc<dtls::DtlsShared>,
    shard: usize,
    /// The client's identity: this 5-tuple's address, or, once a connection ID moved an
    /// association here, the address that association started from (its allocation's key).
    client: SocketAddr,
    session: Arc<Mutex<dtls::DtlsSession>>,
}

impl fmt::Debug for TurnDtlsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnDtlsClient").finish_non_exhaustive()
    }
}

impl Handler for TurnDtlsClient {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let now = Instant::now();
        let mut out = dtls::DtlsOutput::default();
        // A 5-tuple without an association of its own whose datagram carries the CID of
        // another one: the client moved (RFC 9146 §6), if a record of it authenticates.
        let moved = self.client == c.peer_addr()
            && self.dtls.cid_len.is_some()
            && !lock(&self.session).has_connection();
        if let Some((first, session)) = moved.then(|| self.dtls.by_cid(data)).flatten() {
            lock(&session).input(now, data, &mut out);
            if out.messages.is_empty() {
                return; // nothing authenticated: the path stays
            }
            let own = c.peer_addr();
            self.inner.with_shard(self.shard, None, |_, env| {
                if matches!(env.clients.get(&own), Some(ClientConn::Dtls(x, _)) if x.id() == c.id())
                {
                    env.clients.remove(&own);
                }
            });
            self.client = first;
            self.shard = self.inner.shard_of(first, Wire::Dtls);
            self.session = session;
        } else {
            lock(&self.session).input(now, data, &mut out);
        }
        let inner = &self.inner;
        let shard = self.shard;
        let client = self.client;
        if self.dtls.cid_len.is_some() {
            let (moved, cids) = lock(&self.session).after_input(c.id(), !out.messages.is_empty());
            if moved {
                // The path goes where the latest authenticated record came from.
                let session = &self.session;
                inner.with_shard(shard, None, |_, env| match env.clients.get(&client) {
                    Some(ClientConn::Dtls(x, _)) if x.id() == c.id() => {}
                    Some(ClientConn::Dtls(..)) | None => {
                        env.clients
                            .insert(client, ClientConn::Dtls(c.clone(), session.clone()));
                    }
                    Some(_) => {}
                });
            }
            if cids || out.closed {
                self.dtls.sync_cids(client, &self.session, out.closed);
            }
        }
        for d in out.transmit {
            let _ = c.send_owned(d);
        }
        if out.restarted {
            // The client started over: its old allocation goes with the old association.
            inner.with_shard(shard, None, |core, env| core.remove_client(client, env));
        }
        for msg in &out.messages {
            let prebound = if inner.shared.authenticated_allocate(now, client, msg) {
                inner
                    .bind_relay(SocketAddr::new(inner.shared.config().relay_ip, 0), shard)
                    .ok()
            } else {
                None
            };
            inner.with_shard(shard, prebound, |core, env| {
                core.handle_client(now, client, msg, env);
            });
        }
        if out.closed {
            c.close();
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        let client = self.client;
        let owned = self.inner.with_shard(self.shard, None, |core, env| {
            if matches!(env.clients.get(&client), Some(ClientConn::Dtls(x, _)) if x.id() == c.id())
            {
                env.clients.remove(&client);
                // The allocation lives as long as its DTLS association.
                core.remove_client(client, env);
                true
            } else {
                false
            }
        });
        if owned {
            self.dtls.sync_cids(client, &self.session, true);
        }
    }
}

struct RelayAcceptor(Weak<Inner>, Arc<AtomicUsize>);

impl Acceptor for RelayAcceptor {
    type Handler = RelayPeer;
    fn on_open(&self, c: &Conn<RelayPeer>) -> RelayPeer {
        RelayPeer {
            inner: self.0.clone(),
            relay: c.local_addr(),
            route: self.1.clone(),
        }
    }
}

/// A peer talking to a relay socket (internal).
#[doc(hidden)]
pub struct RelayPeer {
    inner: Weak<Inner>,
    relay: SocketAddr,
    /// The shard of the allocation this relay belongs to.
    route: Arc<AtomicUsize>,
}

impl fmt::Debug for RelayPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayPeer")
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

impl Handler for RelayPeer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let shard = self.route.load(Ordering::Relaxed);
        inner.with_shard(shard, None, |core, env| {
            core.handle_peer(Instant::now(), self.relay, c.peer_addr(), data, env);
        });
    }
}
