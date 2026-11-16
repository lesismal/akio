//! The TURN server state machine (RFC 8656 over UDP), free of I/O: [`TurnCore`] takes datagrams
//! and the time, and acts through a [`TurnEnv`] (send to a client, send to a peer, open or close
//! a relay socket). [`TurnServer`](crate::TurnServer) drives it over `only` sockets; tests and
//! fuzzers drive it directly.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use only_crypto::hash::Sha1;
use only_crypto::mac::Hmac;

use crate::auth::AuthFn;
use crate::stun::{Class, Message, MessageBuilder, Method, attr, is_channel_data, is_stun};

/// What a [`TurnCore`] does to the outside world.
pub trait TurnEnv {
    /// Sends `data` to the client at `client` (from the address it reached the server at).
    fn send_to_client(&mut self, client: SocketAddr, data: &[u8]);
    /// Sends `data` from the relay socket bound at `relay` to `peer`.
    fn send_to_peer(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8]);
    /// Opens a relay socket for `client` bound on `addr` (port 0: any free port), returning
    /// its bound address.
    fn open_relay(&mut self, client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr>;
    /// Closes the relay socket bound at `relay`.
    fn close_relay(&mut self, relay: SocketAddr);
    /// The relay bound at `relay`, opened earlier (possibly through another `TurnEnv` of the
    /// same server, see `EVEN-PORT`) and set aside, now belongs to an allocation of this one.
    fn adopt_relay(&mut self, relay: SocketAddr) {
        let _ = relay;
    }
}

/// Decides which peers clients may relay to (see [`TurnConfig::peer_allowed`]).
pub type PeerFilter = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

/// TURN server settings.
#[derive(Clone)]
#[non_exhaustive]
pub struct TurnConfig {
    /// The realm of the long-term credentials.
    pub realm: String,
    /// Finds a user's key ([`static_auth`](crate::static_auth),
    /// [`ephemeral_auth`](crate::ephemeral_auth)).
    pub auth: AuthFn,
    /// Relay sockets are bound on this address (any free port).
    pub relay_ip: IpAddr,
    /// The address clients are told their relay is at, when it differs from `relay_ip` (a
    /// server behind a 1:1 NAT). Default: `relay_ip`.
    pub public_ip: Option<IpAddr>,
    /// Sent as `SOFTWARE` in responses, if set.
    pub software: Option<String>,
    /// Lifetime of an allocation whose client asks for none or for less (600s).
    pub default_lifetime: Duration,
    /// The longest lifetime a client may ask for (3600s).
    pub max_lifetime: Duration,
    /// Lifetime of a permission (300s, RFC 8656).
    pub permission_lifetime: Duration,
    /// Lifetime of a channel binding (600s, RFC 8656).
    pub channel_lifetime: Duration,
    /// How long a nonce is accepted before `438 Stale Nonce` (600s). Nonces are stateless: an
    /// expiry plus an HMAC of it and the client's address.
    pub nonce_lifetime: Duration,
    /// Allocations the server holds in all (`508` beyond).
    pub max_allocations: usize,
    /// Allocations of one username (`486` beyond).
    pub max_allocations_per_user: usize,
    /// Permissions of one allocation (`508` beyond).
    pub max_permissions: usize,
    /// Channels of one allocation (`508` beyond).
    pub max_channels: usize,
    /// Which peers may be relayed to; `None` applies [`denied_by_default`] (no loopback,
    /// private, link-local, multicast or reserved addresses: a relay into the server's own
    /// network would be an SSRF hole) unless `allow_private_peers` is set.
    pub peer_allowed: Option<PeerFilter>,
    /// Allows every peer address under the default policy (tests, private deployments).
    pub allow_private_peers: bool,
}

impl fmt::Debug for TurnConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnConfig")
            .field("realm", &self.realm)
            .field("relay_ip", &self.relay_ip)
            .field("public_ip", &self.public_ip)
            .field("default_lifetime", &self.default_lifetime)
            .field("max_allocations", &self.max_allocations)
            .finish_non_exhaustive()
    }
}

impl TurnConfig {
    /// Settings for `realm`, authenticating with `auth`, relaying from `relay_ip`.
    pub fn new(realm: &str, auth: AuthFn, relay_ip: IpAddr) -> TurnConfig {
        TurnConfig {
            realm: realm.to_owned(),
            auth,
            relay_ip,
            public_ip: None,
            software: Some(concat!("only-turn ", env!("CARGO_PKG_VERSION")).to_owned()),
            default_lifetime: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
            permission_lifetime: Duration::from_secs(300),
            channel_lifetime: Duration::from_secs(600),
            nonce_lifetime: Duration::from_secs(600),
            max_allocations: 16384,
            max_allocations_per_user: 1024,
            max_permissions: 256,
            max_channels: 256,
            peer_allowed: None,
            allow_private_peers: false,
        }
    }

    /// Sets [`public_ip`](Self::public_ip).
    #[must_use]
    pub fn public_ip(mut self, ip: IpAddr) -> Self {
        self.public_ip = Some(ip);
        self
    }

    /// Sets [`allow_private_peers`](Self::allow_private_peers).
    #[must_use]
    pub fn allow_private_peers(mut self, yes: bool) -> Self {
        self.allow_private_peers = yes;
        self
    }

    /// Sets [`peer_allowed`](Self::peer_allowed).
    #[must_use]
    pub fn peer_allowed(mut self, f: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        self.peer_allowed = Some(Arc::new(f));
        self
    }

    /// Sets the default and maximum allocation lifetimes.
    #[must_use]
    pub fn lifetimes(mut self, default: Duration, max: Duration) -> Self {
        self.default_lifetime = default;
        self.max_lifetime = max.max(default);
        self
    }
}

/// Whether the default peer policy refuses `ip`: unspecified, loopback, private (RFC 1918,
/// unique local), link-local, multicast, shared (RFC 6598), benchmarking, reserved, and the
/// IPv6 prefixes embedding IPv4 (NAT64, 6to4), as Go's fib does.
pub fn denied_by_default(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_unspecified()
                || v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_unspecified()
                || v.is_loopback()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x64 && s[1] == 0xff9b)
                || s[0] == 0x2002
                || (s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        }
    }
}

struct Allocation {
    relay: SocketAddr,
    public: SocketAddr,
    user: String,
    key: [u8; 16],
    expires: Instant,
    created_tid: [u8; 12],
    perms: HashMap<IpAddr, Instant>,
    chans: HashMap<u16, (SocketAddr, Instant)>,
    chan_of: HashMap<SocketAddr, u16>,
}

/// Counters a [`TurnCore`] keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TurnStats {
    /// Allocations open now.
    pub allocations: usize,
    /// Datagrams relayed client to peer.
    pub to_peer: u64,
    /// Datagrams relayed peer to client.
    pub to_client: u64,
    /// Requests refused for bad or missing credentials (401/438).
    pub auth_failures: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the shards of one server share: the immutable settings and nonce key (read without a
/// lock), and the server-wide quotas and `EVEN-PORT` reservations (locked only by Allocate,
/// allocation removal and the sweep, never per datagram).
pub(crate) struct Shared {
    cfg: TurnConfig,
    nonce_key: [u8; 32],
    epoch: Instant,
    /// Allocations open in all shards.
    allocations: AtomicUsize,
    /// Allocations open per username (only users with at least one).
    per_user: Mutex<HashMap<String, usize>>,
    /// Relays set aside by `EVEN-PORT` with the R bit, by `RESERVATION-TOKEN`: the token may
    /// come from another 5-tuple, which may live in another shard.
    reservations: Mutex<HashMap<[u8; 8], (SocketAddr, Instant)>>,
}

impl Shared {
    pub(crate) fn new(cfg: TurnConfig) -> Shared {
        let mut nonce_key = [0u8; 32];
        crate::fill_random(&mut nonce_key);
        Shared {
            cfg,
            nonce_key,
            epoch: Instant::now(),
            allocations: AtomicUsize::new(0),
            per_user: Mutex::new(HashMap::new()),
            reservations: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn config(&self) -> &TurnConfig {
        &self.cfg
    }

    /// Takes one allocation of the server-wide and per-user quotas.
    fn reserve(&self, user: &str) -> Result<(), Reject> {
        let mut users = lock(&self.per_user);
        if self.allocations.load(Ordering::Relaxed) >= self.cfg.max_allocations {
            return Err(Reject(508, "Insufficient Capacity"));
        }
        let n = users.get(user).copied().unwrap_or(0);
        if n >= self.cfg.max_allocations_per_user {
            return Err(Reject(486, "Allocation Quota Reached"));
        }
        users.insert(user.to_owned(), n + 1);
        self.allocations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Gives back what [`reserve`](Self::reserve) took.
    fn release(&self, user: &str) {
        let mut users = lock(&self.per_user);
        if let Some(n) = users.get_mut(user) {
            *n -= 1;
            if *n == 0 {
                users.remove(user);
            }
        }
        self.allocations.fetch_sub(1, Ordering::Relaxed);
    }

    fn nonce(&self, now: Instant, client: SocketAddr) -> String {
        let exp = (now + self.cfg.nonce_lifetime)
            .saturating_duration_since(self.epoch)
            .as_secs();
        format!("{exp:016x}{}", self.nonce_mac(exp, client))
    }

    fn nonce_mac(&self, exp: u64, client: SocketAddr) -> String {
        let mut mac = Hmac::<Sha1>::new(&self.nonce_key);
        mac.update(&exp.to_be_bytes());
        mac.update(client.to_string().as_bytes());
        mac.finalize()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn nonce_valid(&self, now: Instant, client: SocketAddr, nonce: &str) -> bool {
        if nonce.len() != 32 || !nonce.is_ascii() {
            return false;
        }
        let Ok(exp) = u64::from_str_radix(&nonce[..16], 16) else {
            return false;
        };
        let now_s = now.saturating_duration_since(self.epoch).as_secs();
        exp >= now_s && nonce[16..] == self.nonce_mac(exp, client)
    }

    /// Whether `data` is an authenticated Allocate that asks for a relay on any port (no
    /// `EVEN-PORT`, no `RESERVATION-TOKEN`): the server binds that relay socket before taking
    /// the shard's lock. Only a client holding valid credentials and a nonce issued to its own
    /// address passes, so this cannot be used to make the server bind sockets for free.
    pub(crate) fn authenticated_allocate(
        &self,
        now: Instant,
        client: SocketAddr,
        data: &[u8],
    ) -> bool {
        if !is_stun(data) {
            return false;
        }
        let Ok(m) = Message::parse(data) else {
            return false;
        };
        if m.class() != Class::Request
            || m.method() != Method::ALLOCATE
            || m.has(attr::EVEN_PORT)
            || m.has(attr::RESERVATION_TOKEN)
            || !m
                .get(attr::REQUESTED_TRANSPORT)
                .is_some_and(|t| t.len() == 4 && t[0] == 17)
        {
            return false;
        }
        let (Some(user), Some(realm), Some(nonce)) = (
            m.get_str(attr::USERNAME),
            m.get_str(attr::REALM),
            m.get_str(attr::NONCE),
        ) else {
            return false;
        };
        realm == self.cfg.realm
            && self.nonce_valid(now, client, nonce)
            && (self.cfg.auth)(user, realm).is_some_and(|k| m.check_integrity(&k))
    }
}

/// The TURN server state machine (see the module docs).
pub struct TurnCore {
    shared: Arc<Shared>,
    allocs: HashMap<SocketAddr, Allocation>,
    by_relay: HashMap<SocketAddr, SocketAddr>,
    stats: TurnStats,
}

impl fmt::Debug for TurnCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnCore")
            .field("allocations", &self.allocs.len())
            .finish_non_exhaustive()
    }
}

struct Reject(u16, &'static str);

/// How long a port reserved by `EVEN-PORT` waits for its `RESERVATION-TOKEN` (RFC 8656: about
/// 30 seconds).
const RESERVATION_LIFETIME: Duration = Duration::from_secs(30);

impl TurnCore {
    /// A server with `cfg`.
    pub fn new(cfg: TurnConfig) -> TurnCore {
        TurnCore::shard(Arc::new(Shared::new(cfg)))
    }

    /// One shard of a server whose shards share `shared` (quotas, nonce key, reservations).
    pub(crate) fn shard(shared: Arc<Shared>) -> TurnCore {
        TurnCore {
            shared,
            allocs: HashMap::new(),
            by_relay: HashMap::new(),
            stats: TurnStats::default(),
        }
    }

    /// The settings.
    pub fn config(&self) -> &TurnConfig {
        &self.shared.cfg
    }

    /// Counters.
    pub fn stats(&self) -> TurnStats {
        let mut s = self.stats;
        s.allocations = self.allocs.len();
        s
    }

    /// The relayed address (as told to the client) of `client`'s allocation.
    pub fn relay_of(&self, client: SocketAddr) -> Option<SocketAddr> {
        self.allocs.get(&client).map(|a| a.public)
    }

    fn peer_ok(&self, peer: SocketAddr) -> bool {
        let cfg = &self.shared.cfg;
        if let Some(f) = &cfg.peer_allowed {
            return f(peer);
        }
        cfg.allow_private_peers || !denied_by_default(peer.ip())
    }

    fn nonce(&self, now: Instant, client: SocketAddr) -> String {
        self.shared.nonce(now, client)
    }

    fn nonce_valid(&self, now: Instant, client: SocketAddr, nonce: &str) -> bool {
        self.shared.nonce_valid(now, client, nonce)
    }

    /// A datagram from `client` on the listening socket: a STUN request or indication, or
    /// ChannelData. Anything else is dropped.
    pub fn handle_client(
        &mut self,
        now: Instant,
        client: SocketAddr,
        data: &[u8],
        env: &mut dyn TurnEnv,
    ) {
        if is_channel_data(data) {
            self.channel_data(now, client, data, env);
            return;
        }
        if !is_stun(data) {
            return;
        }
        let Ok(m) = Message::parse(data) else {
            return;
        };
        match m.class() {
            Class::Request => self.request(now, client, &m, env),
            Class::Indication if m.method() == Method::SEND => {
                self.send_indication(now, client, &m, env);
            }
            _ => {}
        }
    }

    fn channel_data(
        &mut self,
        now: Instant,
        client: SocketAddr,
        data: &[u8],
        env: &mut dyn TurnEnv,
    ) {
        let ch = u16::from_be_bytes([data[0], data[1]]);
        let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        if data.len() < 4 + len {
            return;
        }
        let Some(a) = self.allocs.get(&client) else {
            return;
        };
        if a.expires <= now {
            return;
        }
        let Some(&(peer, exp)) = a.chans.get(&ch) else {
            return;
        };
        if exp <= now || !self.peer_ok(peer) {
            return;
        }
        let relay = a.relay;
        self.stats.to_peer += 1;
        env.send_to_peer(relay, peer, &data[4..4 + len]);
    }

    fn send_indication(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        env: &mut dyn TurnEnv,
    ) {
        let (Some(peer), Some(payload)) =
            (m.get_xor_addr(attr::XOR_PEER_ADDRESS), m.get(attr::DATA))
        else {
            return;
        };
        let Some(a) = self.allocs.get(&client) else {
            return;
        };
        if a.expires <= now || !a.perms.get(&peer.ip()).is_some_and(|&e| e > now) {
            return;
        }
        if !self.peer_ok(peer) {
            return;
        }
        let relay = a.relay;
        self.stats.to_peer += 1;
        env.send_to_peer(relay, peer, payload);
    }

    /// A datagram from `peer` on the relay socket bound at `relay`: relayed to the allocation's
    /// client as ChannelData (when a channel is bound to `peer`) or a Data indication, if a
    /// permission for `peer`'s address is installed.
    pub fn handle_peer(
        &mut self,
        now: Instant,
        relay: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
        env: &mut dyn TurnEnv,
    ) {
        let Some(&client) = self.by_relay.get(&relay) else {
            return;
        };
        let Some(a) = self.allocs.get(&client) else {
            return;
        };
        if a.expires <= now || !a.perms.get(&peer.ip()).is_some_and(|&e| e > now) {
            return;
        }
        if !self.peer_ok(peer) || data.len() > usize::from(u16::MAX) {
            return;
        }
        let ch = a
            .chan_of
            .get(&peer)
            .copied()
            .filter(|c| a.chans.get(c).is_some_and(|&(_, e)| e > now));
        self.stats.to_client += 1;
        match ch {
            Some(ch) => {
                let mut out = Vec::with_capacity(4 + data.len() + 3);
                out.extend_from_slice(&ch.to_be_bytes());
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(data);
                // UDP: padding is optional; it is not sent (RFC 8656 section 12.5).
                env.send_to_client(client, &out);
            }
            None => {
                let msg = MessageBuilder::new(
                    Method::DATA,
                    Class::Indication,
                    crate::stun::transaction_id(),
                )
                .xor_addr(attr::XOR_PEER_ADDRESS, peer)
                .attr(attr::DATA, data)
                .build();
                env.send_to_client(client, &msg);
            }
        }
    }

    /// Frees expired allocations (closing their relays), permissions and channels. Call it
    /// about once a second.
    pub fn handle_timeout(&mut self, now: Instant, env: &mut dyn TurnEnv) {
        let stale: Vec<SocketAddr> = {
            let mut res = lock(&self.shared.reservations);
            let mut out = Vec::new();
            res.retain(|_, (r, e)| {
                if *e <= now {
                    out.push(*r);
                    false
                } else {
                    true
                }
            });
            out
        };
        for r in stale {
            env.close_relay(r);
        }
        let dead: Vec<SocketAddr> = self
            .allocs
            .iter()
            .filter(|(_, a)| a.expires <= now)
            .map(|(c, _)| *c)
            .collect();
        for c in dead {
            self.remove(c, env);
        }
        for a in self.allocs.values_mut() {
            a.perms.retain(|_, e| *e > now);
            let gone: Vec<u16> = a
                .chans
                .iter()
                .filter(|(_, (_, e))| *e <= now)
                .map(|(c, _)| *c)
                .collect();
            for c in gone {
                if let Some((p, _)) = a.chans.remove(&c) {
                    a.chan_of.remove(&p);
                }
            }
        }
    }

    /// Removes every allocation (closing the relays): server shutdown.
    pub fn close_all(&mut self, env: &mut dyn TurnEnv) {
        let res: Vec<SocketAddr> = lock(&self.shared.reservations)
            .drain()
            .map(|(_, (r, _))| r)
            .collect();
        for r in res {
            env.close_relay(r);
        }
        let all: Vec<SocketAddr> = self.allocs.keys().copied().collect();
        for c in all {
            self.remove(c, env);
        }
    }

    fn remove(&mut self, client: SocketAddr, env: &mut dyn TurnEnv) {
        if let Some(a) = self.allocs.remove(&client) {
            self.by_relay.remove(&a.relay);
            self.shared.release(&a.user);
            env.close_relay(a.relay);
        }
    }

    fn base(&self, m: &Message<'_>, class: Class) -> MessageBuilder {
        let mut b = MessageBuilder::response(m, class);
        if let Some(s) = &self.shared.cfg.software {
            b = b.attr(attr::SOFTWARE, s.as_bytes());
        }
        b
    }

    fn finish(b: MessageBuilder, m: &Message<'_>, key: Option<&[u8; 16]>) -> Vec<u8> {
        let mut b = b;
        if let Some(k) = key {
            b = b.integrity(k);
        }
        if m.has(attr::FINGERPRINT) {
            b = b.fingerprint();
        }
        b.build()
    }

    fn error(&self, m: &Message<'_>, r: &Reject, key: Option<&[u8; 16]>) -> Vec<u8> {
        Self::finish(self.base(m, Class::Error).error(r.0, r.1), m, key)
    }

    fn challenge(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        code: u16,
        reason: &str,
    ) -> Vec<u8> {
        self.stats.auth_failures += 1;
        let b = self
            .base(m, Class::Error)
            .error(code, reason)
            .attr(attr::REALM, self.shared.cfg.realm.as_bytes())
            .attr(attr::NONCE, self.nonce(now, client).as_bytes());
        Self::finish(b, m, None)
    }

    fn request(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        env: &mut dyn TurnEnv,
    ) {
        if m.has(attr::FINGERPRINT) && !m.check_fingerprint() {
            return;
        }
        if m.method() == Method::BINDING {
            let b = self
                .base(m, Class::Success)
                .xor_addr(attr::XOR_MAPPED_ADDRESS, client);
            env.send_to_client(client, &Self::finish(b, m, None));
            return;
        }
        if !matches!(
            m.method(),
            Method::ALLOCATE | Method::REFRESH | Method::CREATE_PERMISSION | Method::CHANNEL_BIND
        ) {
            let r = Reject(400, "Bad Request");
            env.send_to_client(client, &self.error(m, &r, None));
            return;
        }
        // Long-term credentials (RFC 8489 section 9.2).
        if !m.has(attr::MESSAGE_INTEGRITY) {
            let out = self.challenge(now, client, m, 401, "Unauthorized");
            env.send_to_client(client, &out);
            return;
        }
        let (Some(user), Some(realm), Some(nonce)) = (
            m.get_str(attr::USERNAME),
            m.get_str(attr::REALM),
            m.get_str(attr::NONCE),
        ) else {
            env.send_to_client(client, &self.error(m, &Reject(400, "Bad Request"), None));
            return;
        };
        if !self.nonce_valid(now, client, nonce) {
            let out = self.challenge(now, client, m, 438, "Stale Nonce");
            env.send_to_client(client, &out);
            return;
        }
        let key = (self.shared.cfg.auth)(user, realm);
        let Some(key) = key.filter(|k| realm == self.shared.cfg.realm && m.check_integrity(k))
        else {
            let out = self.challenge(now, client, m, 401, "Unauthorized");
            env.send_to_client(client, &out);
            return;
        };
        if let Some(unknown) = unknown_required(m) {
            let b = self
                .base(m, Class::Error)
                .error(420, "Unknown Attribute")
                .attr(attr::UNKNOWN_ATTRIBUTES, &unknown);
            env.send_to_client(client, &Self::finish(b, m, Some(&key)));
            return;
        }
        if let Some(a) = self.allocs.get(&client) {
            if a.user != user {
                env.send_to_client(
                    client,
                    &self.error(m, &Reject(441, "Wrong Credentials"), Some(&key)),
                );
                return;
            }
        }
        let out = match m.method() {
            Method::ALLOCATE => self.allocate(now, client, m, user, key, env),
            Method::REFRESH => self.refresh(now, client, m, env),
            Method::CREATE_PERMISSION => self.create_permission(now, client, m),
            _ => self.channel_bind(now, client, m),
        };
        let out = match out {
            Ok(b) => Self::finish(b, m, Some(&key)),
            Err(r) => self.error(m, &r, Some(&key)),
        };
        env.send_to_client(client, &out);
    }

    fn allocate(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        user: &str,
        key: [u8; 16],
        env: &mut dyn TurnEnv,
    ) -> Result<MessageBuilder, Reject> {
        if let Some(a) = self.allocs.get(&client) {
            // A retransmission of the request that created it gets the same answer.
            if a.created_tid == m.transaction_id() {
                let left = a.expires.saturating_duration_since(now).as_secs() as u32;
                return Ok(self
                    .base(m, Class::Success)
                    .xor_addr(attr::XOR_RELAYED_ADDRESS, a.public)
                    .u32(attr::LIFETIME, left)
                    .xor_addr(attr::XOR_MAPPED_ADDRESS, client));
            }
            return Err(Reject(437, "Allocation Mismatch"));
        }
        let Some(t) = m.get(attr::REQUESTED_TRANSPORT) else {
            return Err(Reject(400, "Bad Request"));
        };
        if t.len() != 4 || t[0] != 17 {
            return Err(Reject(442, "Unsupported Transport Protocol"));
        }
        let token = m.get(attr::RESERVATION_TOKEN);
        let even = m.get(attr::EVEN_PORT);
        if token.is_some() && (even.is_some() || m.has(attr::REQUESTED_ADDRESS_FAMILY)) {
            return Err(Reject(400, "Bad Request"));
        }
        if let Some(f) = m.get(attr::REQUESTED_ADDRESS_FAMILY) {
            let want_v6 = match f.first() {
                Some(1) => false,
                Some(2) => true,
                _ => return Err(Reject(440, "Address Family not Supported")),
            };
            if want_v6 != self.shared.cfg.relay_ip.is_ipv6() {
                return Err(Reject(440, "Address Family not Supported"));
            }
        }
        let token: Option<[u8; 8]> = match token {
            Some(t) => Some(t.try_into().map_err(|_| Reject(400, "Bad Request"))?),
            None => None,
        };
        // Server-wide and per-user quotas: O(1), shared by every shard.
        self.shared.reserve(user)?;
        match self.open_for(now, client, token, even, env) {
            Ok((relay, reserved)) => Ok(self.allocated(now, client, m, user, key, relay, reserved)),
            Err(r) => {
                self.shared.release(user);
                Err(r)
            }
        }
    }

    /// The relay socket of a new allocation, and the token of the port set aside with it.
    fn open_for(
        &self,
        now: Instant,
        client: SocketAddr,
        token: Option<[u8; 8]>,
        even: Option<&[u8]>,
        env: &mut dyn TurnEnv,
    ) -> Result<(SocketAddr, Option<[u8; 8]>), Reject> {
        let full = || Reject(508, "Insufficient Capacity");
        match (token, even) {
            // The port an earlier EVEN-PORT allocation set aside.
            (Some(t), _) => {
                let taken = lock(&self.shared.reservations).remove(&t);
                match taken {
                    Some((r, exp)) if exp > now => {
                        env.adopt_relay(r);
                        Ok((r, None))
                    }
                    Some((r, _)) => {
                        env.close_relay(r);
                        Err(full())
                    }
                    None => Err(full()),
                }
            }
            (None, Some(e)) => {
                let reserve = e.first().is_some_and(|b| b & 0x80 != 0);
                let (r, next) = self.open_even(client, reserve, env).ok_or_else(full)?;
                let mut reserved = None;
                if let Some(next) = next {
                    let mut t = [0u8; 8];
                    crate::fill_random(&mut t);
                    lock(&self.shared.reservations).insert(t, (next, now + RESERVATION_LIFETIME));
                    reserved = Some(t);
                }
                Ok((r, reserved))
            }
            (None, None) => env
                .open_relay(client, SocketAddr::new(self.shared.cfg.relay_ip, 0))
                .map(|r| (r, None))
                .map_err(|_| full()),
        }
    }

    /// Records a new allocation on `relay` and builds its success response.
    #[allow(clippy::too_many_arguments)]
    fn allocated(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        user: &str,
        key: [u8; 16],
        relay: SocketAddr,
        reserved: Option<[u8; 8]>,
    ) -> MessageBuilder {
        let public = SocketAddr::new(
            self.shared.cfg.public_ip.unwrap_or_else(|| relay.ip()),
            relay.port(),
        );
        let life = self.lifetime(m);
        self.allocs.insert(
            client,
            Allocation {
                relay,
                public,
                user: user.to_owned(),
                key,
                expires: now + life,
                created_tid: m.transaction_id(),
                perms: HashMap::new(),
                chans: HashMap::new(),
                chan_of: HashMap::new(),
            },
        );
        self.by_relay.insert(relay, client);
        let mut b = self
            .base(m, Class::Success)
            .xor_addr(attr::XOR_RELAYED_ADDRESS, public)
            .u32(attr::LIFETIME, life.as_secs() as u32)
            .xor_addr(attr::XOR_MAPPED_ADDRESS, client);
        if let Some(t) = reserved {
            b = b.attr(attr::RESERVATION_TOKEN, &t);
        }
        b
    }

    /// Opens a relay on an even port and, with `reserve`, the odd port above it too (RFC 8656
    /// section 7.2, `EVEN-PORT`). Gives up after a few tries.
    fn open_even(
        &self,
        client: SocketAddr,
        reserve: bool,
        env: &mut dyn TurnEnv,
    ) -> Option<(SocketAddr, Option<SocketAddr>)> {
        for _ in 0..32 {
            let r = env
                .open_relay(client, SocketAddr::new(self.shared.cfg.relay_ip, 0))
                .ok()?;
            if r.port() % 2 != 0 || r.port() == u16::MAX {
                env.close_relay(r);
                continue;
            }
            if !reserve {
                return Some((r, None));
            }
            match env.open_relay(client, SocketAddr::new(r.ip(), r.port() + 1)) {
                Ok(next) => return Some((r, Some(next))),
                Err(_) => env.close_relay(r),
            }
        }
        None
    }

    fn lifetime(&self, m: &Message<'_>) -> Duration {
        match m.get_u32(attr::LIFETIME) {
            Some(s) => Duration::from_secs(u64::from(s))
                .max(self.shared.cfg.default_lifetime)
                .min(self.shared.cfg.max_lifetime),
            None => self.shared.cfg.default_lifetime,
        }
    }

    fn refresh(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        env: &mut dyn TurnEnv,
    ) -> Result<MessageBuilder, Reject> {
        if !self.allocs.contains_key(&client) {
            return Err(Reject(437, "Allocation Mismatch"));
        }
        if m.get_u32(attr::LIFETIME) == Some(0) {
            self.remove(client, env);
            return Ok(self.base(m, Class::Success).u32(attr::LIFETIME, 0));
        }
        let life = self.lifetime(m);
        if let Some(a) = self.allocs.get_mut(&client) {
            a.expires = now + life;
        }
        Ok(self
            .base(m, Class::Success)
            .u32(attr::LIFETIME, life.as_secs() as u32))
    }

    fn create_permission(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
    ) -> Result<MessageBuilder, Reject> {
        let peers = m.get_xor_addrs(attr::XOR_PEER_ADDRESS);
        if peers.is_empty() || peers.iter().any(Option::is_none) {
            return Err(Reject(400, "Bad Request"));
        }
        let peers: Vec<SocketAddr> = peers.into_iter().flatten().collect();
        let v6 = self.shared.cfg.relay_ip.is_ipv6();
        if peers.iter().any(|p| p.is_ipv6() != v6) {
            return Err(Reject(443, "Peer Address Family Mismatch"));
        }
        if peers
            .iter()
            .any(|p| !self.peer_ok(SocketAddr::new(p.ip(), 0)) && !self.peer_ok(*p))
        {
            return Err(Reject(403, "Forbidden"));
        }
        let cfg = &self.shared.cfg;
        let (max, life) = (cfg.max_permissions, cfg.permission_lifetime);
        let Some(a) = self.allocs.get_mut(&client) else {
            return Err(Reject(437, "Allocation Mismatch"));
        };
        a.perms.retain(|_, e| *e > now);
        let new = peers
            .iter()
            .filter(|p| !a.perms.contains_key(&p.ip()))
            .count();
        if a.perms.len() + new > max {
            return Err(Reject(508, "Insufficient Capacity"));
        }
        for p in peers {
            a.perms.insert(p.ip(), now + life);
        }
        Ok(self.base(m, Class::Success))
    }

    fn channel_bind(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
    ) -> Result<MessageBuilder, Reject> {
        let ch = match m.get(attr::CHANNEL_NUMBER) {
            Some(v) if v.len() == 4 => u16::from_be_bytes([v[0], v[1]]),
            _ => return Err(Reject(400, "Bad Request")),
        };
        if !(0x4000..=0x7ffe).contains(&ch) {
            return Err(Reject(400, "Bad Request"));
        }
        let Some(peer) = m.get_xor_addr(attr::XOR_PEER_ADDRESS) else {
            return Err(Reject(400, "Bad Request"));
        };
        if peer.is_ipv6() != self.shared.cfg.relay_ip.is_ipv6() {
            return Err(Reject(443, "Peer Address Family Mismatch"));
        }
        if !self.peer_ok(peer) {
            return Err(Reject(403, "Forbidden"));
        }
        let cfg = &self.shared.cfg;
        let (maxc, maxp) = (cfg.max_channels, cfg.max_permissions);
        let (cl, pl) = (cfg.channel_lifetime, cfg.permission_lifetime);
        let Some(a) = self.allocs.get_mut(&client) else {
            return Err(Reject(437, "Allocation Mismatch"));
        };
        if let Some(&(p, e)) = a.chans.get(&ch) {
            if p != peer && e > now {
                return Err(Reject(400, "Bad Request"));
            }
        }
        if let Some(&c) = a.chan_of.get(&peer) {
            if c != ch && a.chans.get(&c).is_some_and(|&(_, e)| e > now) {
                return Err(Reject(400, "Bad Request"));
            }
        }
        if !a.chans.contains_key(&ch) && a.chans.len() >= maxc {
            return Err(Reject(508, "Insufficient Capacity"));
        }
        if !a.perms.contains_key(&peer.ip()) && a.perms.len() >= maxp {
            return Err(Reject(508, "Insufficient Capacity"));
        }
        if let Some((old, _)) = a.chans.insert(ch, (peer, now + cl)) {
            a.chan_of.remove(&old);
        }
        a.chan_of.insert(peer, ch);
        let pe = a.perms.entry(peer.ip()).or_insert(now);
        *pe = (*pe).max(now + pl);
        Ok(self.base(m, Class::Success))
    }

    /// The key of `client`'s allocation (for tests).
    #[doc(hidden)]
    pub fn key_of(&self, client: SocketAddr) -> Option<[u8; 16]> {
        self.allocs.get(&client).map(|a| a.key)
    }
}

#[cfg(any(test, feature = "fuzzing"))]
impl TurnCore {
    /// Fixed nonce key and clock origin, so fuzz seeds can carry valid nonces.
    pub(crate) fn fuzz_reset(&mut self, start: Instant) {
        let mut sh = Shared::new(self.shared.cfg.clone());
        sh.nonce_key = [0x42; 32];
        sh.epoch = start;
        self.shared = Arc::new(sh);
    }

    #[cfg(test)]
    pub(crate) fn fuzz_nonce(&self, now: Instant, client: SocketAddr) -> String {
        self.nonce(now, client)
    }
}

/// Comprehension-required attributes this server does not understand, encoded for
/// `UNKNOWN-ATTRIBUTES`.
fn unknown_required(m: &Message<'_>) -> Option<Vec<u8>> {
    const KNOWN: &[u16] = &[
        attr::MAPPED_ADDRESS,
        attr::USERNAME,
        attr::MESSAGE_INTEGRITY,
        attr::ERROR_CODE,
        attr::UNKNOWN_ATTRIBUTES,
        attr::CHANNEL_NUMBER,
        attr::LIFETIME,
        attr::XOR_PEER_ADDRESS,
        attr::DATA,
        attr::REALM,
        attr::NONCE,
        attr::XOR_RELAYED_ADDRESS,
        attr::REQUESTED_ADDRESS_FAMILY,
        attr::EVEN_PORT,
        attr::REQUESTED_TRANSPORT,
        attr::DONT_FRAGMENT,
        attr::XOR_MAPPED_ADDRESS,
        attr::RESERVATION_TOKEN,
    ];
    let unknown: Vec<u8> = m
        .attr_types()
        .filter(|t| *t < 0x8000 && !KNOWN.contains(t))
        .flat_map(u16::to_be_bytes)
        .collect();
    (!unknown.is_empty()).then_some(unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzing::{CLIENT, REALM, USER, turn_core};
    use crate::stun::{long_term_key, transaction_id};

    fn allocate(core: &TurnCore, now: Instant, password: &str, nonce: Option<&str>) -> Vec<u8> {
        let mut b = MessageBuilder::new(Method::ALLOCATE, Class::Request, transaction_id())
            .u32(attr::REQUESTED_TRANSPORT, 17 << 24)
            .attr(attr::USERNAME, USER.0.as_bytes())
            .attr(attr::REALM, REALM.as_bytes());
        let n = nonce.map_or_else(|| core.fuzz_nonce(now, CLIENT), str::to_owned);
        b = b.attr(attr::NONCE, n.as_bytes());
        b.integrity(&long_term_key(USER.0, REALM, password)).build()
    }

    /// Only an Allocate with a valid nonce for its own address and valid credentials gets a
    /// relay bound before the shard is locked.
    #[test]
    fn prebind_needs_authentication() {
        let now = Instant::now();
        let core = turn_core(now);
        let sh = &core.shared;
        assert!(sh.authenticated_allocate(now, CLIENT, &allocate(&core, now, USER.1, None)));
        assert!(!sh.authenticated_allocate(now, CLIENT, &allocate(&core, now, "nope", None)));
        let forged = "0".repeat(32);
        assert!(!sh.authenticated_allocate(
            now,
            CLIENT,
            &allocate(&core, now, USER.1, Some(&forged))
        ));
        // A nonce issued to another address.
        let other: SocketAddr = "10.9.9.9:1".parse().unwrap();
        assert!(!sh.authenticated_allocate(now, other, &allocate(&core, now, USER.1, None)));
        // Expired nonce.
        let later = now + Duration::from_secs(3600);
        assert!(!sh.authenticated_allocate(later, CLIENT, &allocate(&core, now, USER.1, None)));
        // Not an Allocate.
        let b = MessageBuilder::new(Method::REFRESH, Class::Request, transaction_id()).build();
        assert!(!sh.authenticated_allocate(now, CLIENT, &b));
        assert!(!sh.authenticated_allocate(now, CLIENT, b"\x40\x00\x00\x00"));
    }

    /// The per-user count is kept in a map (not by scanning allocations): taken at, refused over
    /// the limit, and given back.
    #[test]
    fn quota_accounting() {
        let mut cfg = TurnConfig::new(
            REALM,
            crate::static_auth(REALM, [USER]),
            "192.0.2.1".parse().unwrap(),
        );
        cfg.max_allocations_per_user = 2;
        let sh = Shared::new(cfg);
        assert!(sh.reserve("u").is_ok());
        assert!(sh.reserve("u").is_ok());
        assert_eq!(sh.reserve("u").err().map(|r| r.0), Some(486));
        assert!(sh.reserve("v").is_ok());
        sh.release("u");
        assert!(sh.reserve("u").is_ok());
        sh.release("u");
        sh.release("u");
        sh.release("v");
        assert!(lock(&sh.per_user).is_empty());
        assert_eq!(sh.allocations.load(Ordering::Relaxed), 0);
    }
}

