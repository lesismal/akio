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
//! Callbacks run on the I/O thread that read the datagram (the listener's or a relay's);
//! expiry is swept by one background thread per server.
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
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use only::{Acceptor, Conn, Engine, Handler, UdpBinding};

pub use crate::auth::{AuthFn, ephemeral_auth, ephemeral_credentials, static_auth};
pub use crate::core::{PeerFilter, TurnConfig, TurnCore, TurnEnv, TurnStats, denied_by_default};

pub(crate) fn fill_random(buf: &mut [u8]) {
    if getrandom::getrandom(buf).is_err() {
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

struct Inner {
    core: Mutex<TurnCore>,
    clients: Mutex<HashMap<SocketAddr, Conn<TurnClient>>>,
    relays: Mutex<HashMap<SocketAddr, UdpBinding>>,
    engine: OnceLock<Weak<Engine>>,
    me: Weak<Inner>,
}

/// The `only` side of [`TurnEnv`]: listener connections for clients, bound sockets for relays.
struct Env<'a>(&'a Inner);

impl TurnEnv for Env<'_> {
    fn send_to_client(&mut self, client: SocketAddr, data: &[u8]) {
        let c = lock(&self.0.clients).get(&client).cloned();
        if let Some(c) = c {
            let _ = c.send(data);
        }
    }

    fn send_to_peer(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8]) {
        let b = lock(&self.0.relays).get(&relay).cloned();
        if let Some(b) = b {
            let _ = b.send_to(data, peer);
        }
    }

    fn open_relay(&mut self, _client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        let engine = self
            .0
            .engine
            .get()
            .and_then(Weak::upgrade)
            .ok_or_else(|| io::Error::other("TurnServer::set_engine was not called"))?;
        let b = engine.bind_udp(addr, RelayAcceptor(self.0.me.clone()))?;
        let addr = b.local_addr();
        lock(&self.0.relays).insert(addr, b);
        Ok(addr)
    }

    fn close_relay(&mut self, relay: SocketAddr) {
        let b = lock(&self.0.relays).remove(&relay);
        if let Some(b) = b {
            b.close();
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
        let inner = Arc::new_cyclic(|me| Inner {
            core: Mutex::new(TurnCore::new(cfg)),
            clients: Mutex::new(HashMap::new()),
            relays: Mutex::new(HashMap::new()),
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
                    lock(&inner.core).handle_timeout(Instant::now(), &mut Env(&inner));
                }
            });
        TurnServer(inner)
    }

    /// Hands over the engine serving this server's listener: relay sockets are bound on it.
    /// Held weakly (no reference cycle); later calls are ignored.
    pub fn set_engine(&self, engine: &Arc<Engine>) {
        let _ = self.0.engine.set(Arc::downgrade(engine));
    }

    /// Counters (allocations open, datagrams relayed, authentication failures).
    pub fn stats(&self) -> TurnStats {
        lock(&self.0.core).stats()
    }

    /// The relayed address of `client`'s allocation.
    pub fn relay_of(&self, client: SocketAddr) -> Option<SocketAddr> {
        lock(&self.0.core).relay_of(client)
    }

    /// Frees every allocation and closes the relay sockets.
    pub fn close_all(&self) {
        lock(&self.0.core).close_all(&mut Env(&self.0));
    }
}

impl Acceptor for TurnServer {
    type Handler = TurnClient;
    fn on_open(&self, c: &Conn<TurnClient>) -> TurnClient {
        lock(&self.0.clients).insert(c.peer_addr(), c.clone());
        TurnClient(self.0.clone())
    }

    fn on_shutdown(&self, _c: &Conn<TurnClient>) {
        self.close_all();
    }
}

/// One client 5-tuple of a [`TurnServer`] (internal).
#[doc(hidden)]
pub struct TurnClient(Arc<Inner>);

impl fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnClient").finish_non_exhaustive()
    }
}

impl Handler for TurnClient {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let inner = &self.0;
        lock(&inner.core).handle_client(Instant::now(), c.peer_addr(), data, &mut Env(inner));
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        let mut clients = lock(&self.0.clients);
        if clients
            .get(&c.peer_addr())
            .is_some_and(|x| x.id() == c.id())
        {
            clients.remove(&c.peer_addr());
        }
    }
}

struct RelayAcceptor(Weak<Inner>);

impl Acceptor for RelayAcceptor {
    type Handler = RelayPeer;
    fn on_open(&self, c: &Conn<RelayPeer>) -> RelayPeer {
        RelayPeer {
            inner: self.0.clone(),
            relay: c.local_addr(),
        }
    }
}

/// A peer talking to a relay socket (internal).
#[doc(hidden)]
pub struct RelayPeer {
    inner: Weak<Inner>,
    relay: SocketAddr,
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
        lock(&inner.core).handle_peer(
            Instant::now(),
            self.relay,
            c.peer_addr(),
            data,
            &mut Env(&inner),
        );
    }
}
