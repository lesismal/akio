//! A sans-io TURN client (RFC 8656): one allocation on one server, over UDP or a stream (TCP,
//! TLS: [`ClientConfig::stream`]).
//!
//! [`Client`] owns no socket or clock. The caller sends what [`Client::poll_transmit`] returns
//! to the server, passes every datagram (or, on a stream, every message cut by
//! [`FrameReader`](crate::framing::FrameReader)) from the server to [`Client::handle_input`],
//! and calls [`Client::handle_timeout`] at [`Client::poll_timeout`].
//!
//! - Allocation with long-term credentials: the first Allocate is unauthenticated, the 401
//!   challenge gives the realm and nonce, `438 Stale Nonce` renews the nonce; every later
//!   request is authenticated and every success response must carry a valid
//!   `MESSAGE-INTEGRITY`.
//! - Refreshes before the lifetime runs out ([`ClientConfig::lifetime`]); [`Client::close`]
//!   deletes the allocation (a Refresh with lifetime 0).
//! - [`Client::send_to`] installs what a peer needs on first use: a channel (ChannelBind, which
//!   also installs the permission), or, when channels are off or the server refuses one, a
//!   permission and Send indications. Data for a peer waits (bounded) until that is done, and
//!   each binding is refreshed every 4 minutes while the peer is in use (permissions last 5,
//!   channels 10).
//! - Transactions are retransmitted over UDP (from [`ClientConfig::rto`], doubling, at most
//!   [`ClientConfig::max_sends`] sends) and time out after [`ClientConfig::timeout`] on a
//!   stream.
//! - Bounds: [`ClientConfig::max_peers`] peers, [`ClientConfig::max_pending`] bytes waiting.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::framing::channel_data_padding;
use crate::stun::{
    Class, Message, MessageBuilder, Method, attr, is_channel_data, is_stun, long_term_key,
    transaction_id,
};

/// How often a channel binding or permission in use is refreshed (permissions last 5 minutes).
const BINDING_REFRESH: Duration = Duration::from_secs(240);
/// A peer not sent to for this long is forgotten (its bindings are left to expire).
const PEER_IDLE: Duration = Duration::from_secs(600);
/// After a permission failed, data to that peer is dropped this long before trying again.
const PEER_RETRY: Duration = Duration::from_secs(30);
/// Datagrams waiting for one peer's binding.
const PENDING_PER_PEER: usize = 16;
/// Authentication retries (401 then 438) of one request.
const AUTH_RETRIES: u8 = 3;
/// Lowest and highest channel numbers (RFC 8656 section 12).
const CHANNEL_MIN: u16 = 0x4000;
const CHANNEL_MAX: u16 = 0x4fff;

/// Settings of a [`Client`]. [`ClientConfig::new`] fills in the defaults.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// The server's address (where datagrams go; informational on a stream).
    pub server: SocketAddr,
    /// Long-term credentials: username.
    pub username: String,
    /// Long-term credentials: password.
    pub password: String,
    /// The client talks to the server over a TCP or TLS stream: ChannelData is padded and
    /// requests are not retransmitted.
    pub stream: bool,
    /// The allocation lifetime asked for (600s; the server may grant less or more).
    pub lifetime: Duration,
    /// First retransmission timeout over UDP (500 ms), doubling.
    pub rto: Duration,
    /// Sends of one request over UDP before it fails (7, RFC 8489 `Rc`).
    pub max_sends: u32,
    /// A transaction fails this long after its first send (39.5 s, RFC 8489 `Ti`).
    pub timeout: Duration,
    /// Peers with a binding at once (64): data for more is dropped.
    pub max_peers: usize,
    /// Bytes waiting for bindings, all peers together (64 KiB): more is dropped.
    pub max_pending: usize,
    /// Bind a channel to each peer (4 bytes of overhead per datagram instead of 36); else
    /// permissions and Send indications (true).
    pub use_channels: bool,
    /// Sent as `SOFTWARE`, if set.
    pub software: Option<String>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("stream", &self.stream)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    /// Defaults for an allocation on `server` with these credentials, over UDP.
    pub fn new(server: SocketAddr, username: &str, password: &str) -> ClientConfig {
        ClientConfig {
            server,
            username: username.to_owned(),
            password: password.to_owned(),
            stream: false,
            lifetime: Duration::from_secs(600),
            rto: Duration::from_millis(500),
            max_sends: 7,
            timeout: Duration::from_millis(39_500),
            max_peers: 64,
            max_pending: 64 * 1024,
            use_channels: true,
            software: None,
        }
    }

    /// Sets [`stream`](Self::stream).
    #[must_use]
    pub fn stream(mut self, yes: bool) -> Self {
        self.stream = yes;
        self
    }

    /// Sets [`use_channels`](Self::use_channels).
    #[must_use]
    pub fn use_channels(mut self, yes: bool) -> Self {
        self.use_channels = yes;
        self
    }

    /// Sets [`lifetime`](Self::lifetime).
    #[must_use]
    pub fn lifetime(mut self, d: Duration) -> Self {
        self.lifetime = d;
        self
    }
}

/// Why an allocation failed or was lost.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientError {
    /// The server did not answer in time.
    Timeout,
    /// The server refused with this error code and reason (`401` after the credentials were
    /// sent: wrong credentials).
    Rejected(u16, String),
    /// A response was malformed (no relayed address in an Allocate success, say).
    Protocol(&'static str),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Timeout => f.write_str("turn: no answer from the server"),
            ClientError::Rejected(c, r) => write!(f, "turn: refused: {c} {r}"),
            ClientError::Protocol(w) => write!(f, "turn: bad response: {w}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// What happened, from [`Client::poll_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientEvent {
    /// The allocation exists: the relayed address peers send to, the client's address as the
    /// server saw it (server-reflexive), and the lifetime granted.
    Allocated {
        /// The relayed transport address.
        relayed: SocketAddr,
        /// `XOR-MAPPED-ADDRESS` of the response, when present.
        mapped: Option<SocketAddr>,
        /// The lifetime granted.
        lifetime: Duration,
    },
    /// The allocation could not be made, or a refresh failed and it is gone: the client is
    /// done ([`ClientState::Failed`]).
    Failed(ClientError),
    /// The server refused a permission or channel for this peer; its data is dropped for a
    /// while.
    PeerFailed(SocketAddr, ClientError),
    /// [`Client::close`] finished (the deletion was answered or timed out).
    Closed,
}

/// The state of a [`Client`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    /// The Allocate is in progress.
    Allocating,
    /// The allocation exists.
    Allocated,
    /// [`Client::close`] was called; the deletion is in progress.
    Closing,
    /// The allocation failed or was lost.
    Failed,
    /// Closed.
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Allocate,
    Refresh(u32),
    ChannelBind(SocketAddr, u16),
    Permission(SocketAddr),
}

struct Tx {
    kind: Kind,
    packet: Vec<u8>,
    sends: u32,
    next: Instant,
    rto: Duration,
    deadline: Instant,
    auth_tries: u8,
}

#[derive(Default)]
struct Peer {
    /// The channel bound (or being bound) to this peer.
    channel: Option<u16>,
    /// The binding (channel or permission) is installed.
    ready: bool,
    /// A ChannelBind or CreatePermission is in flight.
    busy: bool,
    /// The server refused channels for this peer: permissions and Send indications.
    no_channel: bool,
    refresh_at: Option<Instant>,
    last_used: Option<Instant>,
    failed_until: Option<Instant>,
    pending: VecDeque<Vec<u8>>,
}

/// A TURN client: one allocation (see the module docs).
pub struct Client {
    cfg: ClientConfig,
    state: ClientState,
    realm: Option<String>,
    nonce: Option<String>,
    key: Option<[u8; 16]>,
    relayed: Option<SocketAddr>,
    mapped: Option<SocketAddr>,
    refresh_at: Option<Instant>,
    txs: HashMap<[u8; 12], Tx>,
    peers: HashMap<SocketAddr, Peer>,
    by_channel: HashMap<u16, SocketAddr>,
    next_channel: u16,
    pending_bytes: usize,
    transmits: VecDeque<Vec<u8>>,
    events: VecDeque<ClientEvent>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("server", &self.cfg.server)
            .field("state", &self.state)
            .field("relayed", &self.relayed)
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client that starts allocating now (the Allocate is the first transmit).
    pub fn new(cfg: ClientConfig, now: Instant) -> Client {
        let mut c = Client {
            cfg,
            state: ClientState::Allocating,
            realm: None,
            nonce: None,
            key: None,
            relayed: None,
            mapped: None,
            refresh_at: None,
            txs: HashMap::new(),
            peers: HashMap::new(),
            by_channel: HashMap::new(),
            next_channel: CHANNEL_MIN,
            pending_bytes: 0,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        };
        c.start(now, Kind::Allocate, 0);
        c
    }

    /// The settings.
    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    /// The state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// The relayed address, once allocated.
    pub fn relayed_addr(&self) -> Option<SocketAddr> {
        self.relayed
    }

    /// The client's address as the server saw it, once allocated.
    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        self.mapped
    }

    /// Bytes waiting for peer bindings.
    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    // ---- requests ----

    fn build(&self, kind: &Kind, tid: [u8; 12]) -> Vec<u8> {
        let method = match kind {
            Kind::Allocate => Method::ALLOCATE,
            Kind::Refresh(_) => Method::REFRESH,
            Kind::ChannelBind(..) => Method::CHANNEL_BIND,
            Kind::Permission(_) => Method::CREATE_PERMISSION,
        };
        let mut b = MessageBuilder::new(method, Class::Request, tid);
        if let Some(s) = &self.cfg.software {
            b = b.attr(attr::SOFTWARE, s.as_bytes());
        }
        match kind {
            Kind::Allocate => {
                b = b.u32(attr::REQUESTED_TRANSPORT, 17 << 24);
                b = b.u32(attr::LIFETIME, self.cfg.lifetime.as_secs() as u32);
            }
            Kind::Refresh(l) => b = b.u32(attr::LIFETIME, *l),
            Kind::ChannelBind(peer, ch) => {
                b = b
                    .attr(attr::CHANNEL_NUMBER, &[(ch >> 8) as u8, *ch as u8, 0, 0])
                    .xor_addr(attr::XOR_PEER_ADDRESS, *peer);
            }
            Kind::Permission(peer) => b = b.xor_addr(attr::XOR_PEER_ADDRESS, *peer),
        }
        if let (Some(realm), Some(nonce), Some(key)) = (&self.realm, &self.nonce, &self.key) {
            b = b
                .attr(attr::USERNAME, self.cfg.username.as_bytes())
                .attr(attr::REALM, realm.as_bytes())
                .attr(attr::NONCE, nonce.as_bytes())
                .integrity(key);
        }
        b.fingerprint().build()
    }

    fn start(&mut self, now: Instant, kind: Kind, auth_tries: u8) {
        let tid = transaction_id();
        let packet = self.build(&kind, tid);
        self.transmits.push_back(packet.clone());
        self.txs.insert(
            tid,
            Tx {
                kind,
                packet,
                sends: 1,
                next: now + self.cfg.rto,
                rto: self.cfg.rto,
                deadline: now + self.cfg.timeout,
                auth_tries,
            },
        );
    }

    fn fail(&mut self, e: ClientError) {
        if matches!(self.state, ClientState::Failed | ClientState::Closed) {
            return;
        }
        let closing = self.state == ClientState::Closing;
        self.state = if closing {
            ClientState::Closed
        } else {
            ClientState::Failed
        };
        self.txs.clear();
        self.peers.clear();
        self.by_channel.clear();
        self.pending_bytes = 0;
        self.refresh_at = None;
        self.events.push_back(if closing {
            ClientEvent::Closed
        } else {
            ClientEvent::Failed(e)
        });
    }

    /// Deletes the allocation (a Refresh with lifetime 0); [`ClientEvent::Closed`] follows.
    pub fn close(&mut self, now: Instant) {
        match self.state {
            ClientState::Allocated => {
                self.state = ClientState::Closing;
                self.txs.clear();
                self.peers.clear();
                self.by_channel.clear();
                self.pending_bytes = 0;
                self.refresh_at = None;
                self.start(now, Kind::Refresh(0), 0);
            }
            ClientState::Allocating => {
                self.state = ClientState::Closed;
                self.txs.clear();
                self.events.push_back(ClientEvent::Closed);
            }
            _ => {}
        }
    }

    // ---- data ----

    /// Sends `data` to `peer` through the relay. `false`: dropped (not allocated, too many
    /// peers, too much waiting, or the peer was refused recently). The first datagrams to a
    /// peer wait for its binding.
    pub fn send_to(&mut self, now: Instant, peer: SocketAddr, data: &[u8]) -> bool {
        if self.state != ClientState::Allocated || data.len() > 0xffff {
            return false;
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= self.cfg.max_peers {
            self.forget_idle(now);
            if self.peers.len() >= self.cfg.max_peers {
                return false;
            }
        }
        let p = self.peers.entry(peer).or_default();
        p.last_used = Some(now);
        if p.failed_until.is_some_and(|t| t > now) {
            return false;
        }
        if p.ready {
            let out = match p.channel.filter(|_| !p.no_channel) {
                Some(ch) => channel_data(ch, data, self.cfg.stream),
                None => MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
                    .xor_addr(attr::XOR_PEER_ADDRESS, peer)
                    .attr(attr::DATA, data)
                    .build(),
            };
            self.transmits.push_back(out);
            return true;
        }
        if p.pending.len() >= PENDING_PER_PEER
            || self.pending_bytes + data.len() > self.cfg.max_pending
        {
            return false;
        }
        p.pending.push_back(data.to_vec());
        self.pending_bytes += data.len();
        if !p.busy {
            self.bind_peer(now, peer);
        }
        true
    }

    /// Starts (or refreshes) the binding of `peer`: a channel if possible, else a permission.
    fn bind_peer(&mut self, now: Instant, peer: SocketAddr) {
        let use_channels = self.cfg.use_channels;
        let next = self.next_channel;
        let Some(p) = self.peers.get_mut(&peer) else {
            return;
        };
        p.busy = true;
        let kind = if use_channels && !p.no_channel {
            let ch = match p.channel {
                Some(c) => Some(c),
                None if next <= CHANNEL_MAX => {
                    p.channel = Some(next);
                    self.next_channel += 1;
                    self.by_channel.insert(next, peer);
                    Some(next)
                }
                None => None,
            };
            match ch {
                Some(c) => Kind::ChannelBind(peer, c),
                None => {
                    p.no_channel = true;
                    Kind::Permission(peer)
                }
            }
        } else {
            Kind::Permission(peer)
        };
        self.start(now, kind, 0);
    }

    fn forget_idle(&mut self, now: Instant) {
        let idle: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| !p.busy && p.last_used.is_none_or(|t| t + PEER_IDLE <= now))
            .map(|(a, _)| *a)
            .collect();
        for a in idle {
            self.drop_peer(a);
        }
    }

    fn drop_peer(&mut self, peer: SocketAddr) {
        if let Some(p) = self.peers.remove(&peer) {
            self.pending_bytes -= p.pending.iter().map(Vec::len).sum::<usize>();
            if let Some(c) = p.channel {
                self.by_channel.remove(&c);
            }
        }
    }

    fn flush_peer(&mut self, peer: SocketAddr) {
        let Some(p) = self.peers.get_mut(&peer) else {
            return;
        };
        let ch = p.channel.filter(|_| !p.no_channel);
        let pending = std::mem::take(&mut p.pending);
        for d in pending {
            self.pending_bytes -= d.len();
            let out = match ch {
                Some(ch) => channel_data(ch, &d, self.cfg.stream),
                None => MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
                    .xor_addr(attr::XOR_PEER_ADDRESS, peer)
                    .attr(attr::DATA, &d)
                    .build(),
            };
            self.transmits.push_back(out);
        }
    }

    // ---- input ----

    /// A datagram (or stream message) from the server. Returns the peer and payload of relayed
    /// data (ChannelData or a Data indication); responses are consumed; anything else is
    /// ignored.
    pub fn handle_input<'a>(
        &mut self,
        now: Instant,
        data: &'a [u8],
    ) -> Option<(SocketAddr, &'a [u8])> {
        if matches!(self.state, ClientState::Failed | ClientState::Closed) {
            return None;
        }
        if is_channel_data(data) {
            let ch = u16::from_be_bytes([data[0], data[1]]);
            let len = usize::from(u16::from_be_bytes([data[2], data[3]]));
            let payload = data.get(4..4 + len)?;
            let peer = *self.by_channel.get(&ch)?;
            return self
                .peers
                .get(&peer)
                .is_some_and(|p| p.ready && !p.no_channel)
                .then_some((peer, payload));
        }
        if !is_stun(data) {
            return None;
        }
        let m = Message::parse(data).ok()?;
        match m.class() {
            Class::Indication if m.method() == Method::DATA => {
                let peer = m.get_xor_addr(attr::XOR_PEER_ADDRESS)?;
                let payload = m.get(attr::DATA)?;
                // Only peers we installed a permission for (the server checks too).
                self.peers.contains_key(&peer).then_some((peer, payload))
            }
            Class::Success | Class::Error => {
                self.on_response(now, &m);
                None
            }
            _ => None,
        }
    }

    fn on_response(&mut self, now: Instant, m: &Message<'_>) {
        let tid = m.transaction_id();
        let Some(tx) = self.txs.get(&tid) else {
            return;
        };
        if m.has(attr::FINGERPRINT) && !m.check_fingerprint() {
            return;
        }
        let authed = self.key.is_some() && tx.packet_authed();
        if authed {
            // Responses to authenticated requests are authenticated (RFC 8489 section
            // 9.2.5); 401 and 438 challenges may not be.
            let challenge =
                m.class() == Class::Error && matches!(m.error_code().map(|e| e.0), Some(401 | 438));
            let ok = self.key.is_some_and(|k| m.check_integrity(&k));
            if !ok && !challenge {
                return;
            }
        }
        let Some(tx) = self.txs.remove(&tid) else {
            return;
        };
        if m.class() == Class::Error {
            let (code, reason) = m.error_code().unwrap_or((0, ""));
            if matches!(code, 401 | 438) && tx.auth_tries < AUTH_RETRIES {
                let fresh_challenge = code == 438 || !authed;
                if let (Some(realm), Some(nonce)) = (m.get_str(attr::REALM), m.get_str(attr::NONCE))
                {
                    if fresh_challenge {
                        if self.realm.as_deref() != Some(realm) || self.key.is_none() {
                            self.key =
                                Some(long_term_key(&self.cfg.username, realm, &self.cfg.password));
                            self.realm = Some(realm.to_owned());
                        }
                        self.nonce = Some(nonce.to_owned());
                        self.start(now, tx.kind, tx.auth_tries + 1);
                        return;
                    }
                }
            }
            self.on_error(now, tx.kind, ClientError::Rejected(code, reason.to_owned()));
            return;
        }
        self.on_success(now, tx.kind, m);
    }

    fn on_error(&mut self, now: Instant, kind: Kind, e: ClientError) {
        match kind {
            Kind::Allocate | Kind::Refresh(_) => self.fail(e),
            Kind::ChannelBind(peer, ch) => {
                // Fall back to a permission and Send indications.
                self.by_channel.remove(&ch);
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.no_channel = true;
                    p.ready = false;
                    p.busy = false;
                }
                if self.state == ClientState::Allocated {
                    self.bind_peer(now, peer);
                }
            }
            Kind::Permission(peer) => {
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.busy = false;
                    p.ready = false;
                    p.refresh_at = None;
                    p.failed_until = Some(now + PEER_RETRY);
                    self.pending_bytes -= p.pending.iter().map(Vec::len).sum::<usize>();
                    p.pending.clear();
                }
                self.events.push_back(ClientEvent::PeerFailed(peer, e));
            }
        }
    }

    fn on_success(&mut self, now: Instant, kind: Kind, m: &Message<'_>) {
        match kind {
            Kind::Allocate => {
                let Some(relayed) = m.get_xor_addr(attr::XOR_RELAYED_ADDRESS) else {
                    self.fail(ClientError::Protocol("no XOR-RELAYED-ADDRESS"));
                    return;
                };
                let life = Duration::from_secs(u64::from(m.get_u32(attr::LIFETIME).unwrap_or(600)));
                self.relayed = Some(relayed);
                self.mapped = m.get_xor_addr(attr::XOR_MAPPED_ADDRESS);
                if self.state == ClientState::Allocating {
                    self.state = ClientState::Allocated;
                    self.events.push_back(ClientEvent::Allocated {
                        relayed,
                        mapped: self.mapped,
                        lifetime: life,
                    });
                }
                self.schedule_refresh(now, life);
            }
            Kind::Refresh(0) => {
                if self.state == ClientState::Closing {
                    self.state = ClientState::Closed;
                    self.events.push_back(ClientEvent::Closed);
                }
            }
            Kind::Refresh(_) => {
                let life = Duration::from_secs(u64::from(m.get_u32(attr::LIFETIME).unwrap_or(600)));
                self.schedule_refresh(now, life);
            }
            Kind::ChannelBind(peer, _) | Kind::Permission(peer) => {
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.ready = true;
                    p.busy = false;
                    p.refresh_at = Some(now + BINDING_REFRESH);
                }
                self.flush_peer(peer);
            }
        }
    }

    fn schedule_refresh(&mut self, now: Instant, life: Duration) {
        // A minute before it runs out, or halfway for short lifetimes.
        let before = life.saturating_sub(Duration::from_secs(60)).max(life / 2);
        self.refresh_at = Some(now + before.max(Duration::from_secs(1)));
    }

    // ---- time ----

    /// Drives retransmissions, timeouts and refreshes.
    pub fn handle_timeout(&mut self, now: Instant) {
        let stream = self.cfg.stream;
        let max_sends = self.cfg.max_sends;
        let mut dead = Vec::new();
        for (tid, tx) in &mut self.txs {
            if tx.deadline <= now {
                dead.push(*tid);
                continue;
            }
            if !stream && tx.next <= now {
                if tx.sends >= max_sends {
                    // RFC 8489: after the last send, wait 16 RTOs (bounded by the deadline).
                    tx.next = tx.deadline;
                    continue;
                }
                tx.sends += 1;
                tx.rto *= 2;
                tx.next = now + tx.rto;
                self.transmits.push_back(tx.packet.clone());
            }
        }
        for tid in dead {
            if let Some(tx) = self.txs.remove(&tid) {
                match tx.kind {
                    Kind::Refresh(0) => {
                        if self.state == ClientState::Closing {
                            self.state = ClientState::Closed;
                            self.events.push_back(ClientEvent::Closed);
                        }
                    }
                    k => self.on_error(now, k, ClientError::Timeout),
                }
            }
        }
        if self.state != ClientState::Allocated {
            return;
        }
        if self.refresh_at.is_some_and(|t| t <= now) {
            self.refresh_at = None;
            let life = self.cfg.lifetime.as_secs() as u32;
            self.start(now, Kind::Refresh(life.max(1)), 0);
        }
        let due: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| !p.busy && p.refresh_at.is_some_and(|t| t <= now))
            .map(|(a, _)| *a)
            .collect();
        for peer in due {
            let idle = self
                .peers
                .get(&peer)
                .is_none_or(|p| p.last_used.is_none_or(|t| t + PEER_IDLE <= now));
            if idle {
                self.drop_peer(peer);
            } else {
                self.bind_peer(now, peer);
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.refresh_at = None;
                }
            }
        }
    }

    /// When [`handle_timeout`](Self::handle_timeout) wants to run next.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut t: Option<Instant> = None;
        let mut at = |x: Instant| t = Some(t.map_or(x, |t| t.min(x)));
        for tx in self.txs.values() {
            at(tx.deadline);
            if !self.cfg.stream && tx.sends < self.cfg.max_sends {
                at(tx.next);
            }
        }
        if self.state == ClientState::Allocated {
            if let Some(r) = self.refresh_at {
                at(r);
            }
            for p in self.peers.values() {
                if let Some(r) = p.refresh_at.filter(|_| !p.busy) {
                    at(r);
                }
            }
        }
        t
    }

    /// The next message for the server.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.transmits.pop_front()
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop_front()
    }
}

impl Tx {
    /// Whether this request carried credentials.
    fn packet_authed(&self) -> bool {
        Message::parse(&self.packet).is_ok_and(|m| m.has(attr::MESSAGE_INTEGRITY))
    }
}

fn channel_data(ch: u16, data: &[u8], pad: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len() + 3);
    out.extend_from_slice(&ch.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    if pad {
        out.resize(out.len() + channel_data_padding(out.len()), 0);
    }
    out
}

#[cfg(test)]
mod tests;
