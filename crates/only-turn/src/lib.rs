#![forbid(unsafe_code)]
//! STUN and TURN servers for `only`, over `only` UDP sockets.
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
mod core;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod stun;

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

/// One shard of a server: the allocations of the clients whose address hashes to it, and their
/// listener connections. A datagram locks only its own shard.
struct Shard {
    core: TurnCore,
    clients: HashMap<SocketAddr, Conn<TurnClient>>,
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
    me: Weak<Inner>,
}

impl Inner {
    fn shard_of(&self, addr: SocketAddr) -> usize {
        (self.hasher.hash_one(addr) as usize) & (self.shards.len() - 1)
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
        };
        let r = f(core, &mut env);
        let unused = env.prebound.take();
        drop(g);
        if let Some((b, _)) = unused {
            b.close();
        }
        r
    }
}

fn shard_count() -> usize {
    let cpus = std::thread::available_parallelism().map_or(4, usize::from);
    (cpus * 4).next_power_of_two().clamp(8, 256)
}

/// The `only` side of [`TurnEnv`] for one shard: its listener connections for clients, the
/// relay table for relays.
struct Env<'a> {
    inner: &'a Inner,
    shard: usize,
    clients: &'a mut HashMap<SocketAddr, Conn<TurnClient>>,
    /// A relay bound before the shard was locked, for an authenticated Allocate.
    prebound: Option<(UdpBinding, Arc<AtomicUsize>)>,
}

impl TurnEnv for Env<'_> {
    fn send_to_client(&mut self, client: SocketAddr, data: &[u8]) {
        if let Some(c) = self.clients.get(&client) {
            let _ = c.send(data);
        }
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
            shards: (0..n)
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
                    for i in 0..inner.shards.len() {
                        inner.with_shard(i, None, |core, env| {
                            core.handle_timeout(Instant::now(), env);
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
        }
        t
    }

    /// The relayed address of `client`'s allocation.
    pub fn relay_of(&self, client: SocketAddr) -> Option<SocketAddr> {
        lock(&self.0.shards[self.0.shard_of(client)])
            .core
            .relay_of(client)
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
        let shard = self.0.shard_of(c.peer_addr());
        lock(&self.0.shards[shard])
            .clients
            .insert(c.peer_addr(), c.clone());
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
        if shard
            .clients
            .get(&c.peer_addr())
            .is_some_and(|x| x.id() == c.id())
        {
            shard.clients.remove(&c.peer_addr());
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
