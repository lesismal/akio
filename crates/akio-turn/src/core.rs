//! The TURN server state machine (RFC 8656 over UDP), free of I/O: [`TurnCore`] takes datagrams
//! and the time, and acts through a [`TurnEnv`] (send to a client, send to a peer, open or close
//! a relay socket). [`TurnServer`](crate::TurnServer) drives it over `akio` sockets; tests and
//! fuzzers drive it directly.
//!
//! TCP allocations (RFC 6062) are decided here too: the Allocate, Connect and ConnectionBind
//! requests, permissions for connections from peers, ConnectionAttempt indications, the
//! deadlines of connections waiting for a ConnectionBind. The connections themselves belong to
//! the [`TurnEnv`] ([`TurnEnv::open_tcp_relay`], [`TurnEnv::connect_peer`],
//! [`TurnEnv::accept_peer`], [`TurnEnv::close_connection`]), which reports back with
//! [`TurnCore::tcp_connected`], [`TurnCore::tcp_incoming`] and [`TurnCore::tcp_closed`]; the
//! bytes of a bound connection never pass through the state machine.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use akio_crypto::hash::Sha1;
use akio_crypto::mac::Hmac;

use crate::auth::AuthFn;
use crate::stun::{Class, Message, MessageBuilder, Method, attr, is_channel_data, is_stun};

/// The IP header fields a relayed datagram carries across the server, UDP to UDP (RFC 8656
/// section 14; RFC 5766 section 12 for the TTL): those it came in with (`handle_*_ip`), and
/// those the datagram relayed goes out with ([`TurnEnv::send_to_peer_ip`],
/// [`TurnEnv::send_to_client_ip`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct IpFields {
    /// The traffic class byte (IPv4 TOS / IPv6 traffic class: DSCP in the upper six bits, ECN
    /// in the low two); 0 when unknown, or unmarked.
    pub tos: u8,
    /// The TTL (IPv4) or hop limit (IPv6); 0 when unknown coming in, the socket's default going
    /// out.
    pub ttl: u8,
    /// Going out to a peer only: send the datagram with the "don't fragment" bit set (a Send
    /// indication with `DONT-FRAGMENT`, RFC 8656 sections 14 and 15); every other datagram goes
    /// with it clear.
    pub dont_fragment: bool,
}

impl IpFields {
    /// Fields of a datagram that came in with traffic class byte `tos` and TTL `ttl`.
    pub const fn new(tos: u8, ttl: u8) -> IpFields {
        IpFields {
            tos,
            ttl,
            dont_fragment: false,
        }
    }
}

/// What a [`TurnCore`] does to the outside world.
pub trait TurnEnv {
    /// Sends `data` to the client at `client` (from the address it reached the server at).
    fn send_to_client(&mut self, client: SocketAddr, data: &[u8]);
    /// Sends `data` from the relay socket bound at `relay` to `peer`.
    fn send_to_peer(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8]);
    /// Relayed data for the client at `client` (ChannelData or a Data indication) whose
    /// datagram from the peer arrived with ECN codepoint `ecn` (RFC 3168: 2 = ECT(0), 1 =
    /// ECT(1), 3 = CE, 0 = not ECN-capable or unknown): RFC 8656 section 14 prefers it copied
    /// onto the datagram to a UDP client. Default: [`send_to_client`](Self::send_to_client),
    /// the codepoint dropped.
    fn send_to_client_ecn(&mut self, client: SocketAddr, data: &[u8], ecn: u8) {
        let _ = ecn;
        self.send_to_client(client, data);
    }
    /// Relayed data for `peer` whose datagram from the client arrived with ECN codepoint
    /// `ecn` (see [`send_to_client_ecn`](Self::send_to_client_ecn)), to copy onto the datagram
    /// to the peer. Default: [`send_to_peer`](Self::send_to_peer), the codepoint dropped.
    fn send_to_peer_ecn(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8], ecn: u8) {
        let _ = ecn;
        self.send_to_peer(relay, peer, data);
    }
    /// [`send_to_client_ecn`](Self::send_to_client_ecn) with the whole traffic class byte
    /// `tos` the peer's datagram arrived with (IPv4 TOS / IPv6 traffic class: DSCP in the upper
    /// six bits, ECN in the low two), to copy onto the datagram to a UDP client (RFC 8656
    /// section 14). Its DSCP is 0 when [`TurnConfig::copy_dscp`] is off. Default:
    /// `send_to_client_ecn` with the ECN bits.
    fn send_to_client_tos(&mut self, client: SocketAddr, data: &[u8], tos: u8) {
        self.send_to_client_ecn(client, data, tos & 3);
    }
    /// [`send_to_peer_ecn`](Self::send_to_peer_ecn) with the whole traffic class byte `tos` of
    /// the client's datagram (see [`send_to_client_tos`](Self::send_to_client_tos)). Default:
    /// `send_to_peer_ecn` with the ECN bits.
    fn send_to_peer_tos(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8], tos: u8) {
        self.send_to_peer_ecn(relay, peer, data, tos & 3);
    }
    /// [`send_to_client_tos`](Self::send_to_client_tos) with all the fields relayed: the
    /// traffic class byte, and the TTL / hop limit the peer's datagram arrived with minus one
    /// (0: the socket's default; see [`TurnConfig::copy_ttl`]). Default: `send_to_client_tos`
    /// with `ip.tos`.
    fn send_to_client_ip(&mut self, client: SocketAddr, data: &[u8], ip: IpFields) {
        self.send_to_client_tos(client, data, ip.tos);
    }
    /// [`send_to_peer_tos`](Self::send_to_peer_tos) with all the fields relayed: the traffic
    /// class byte, the TTL / hop limit of the client's datagram minus one, and whether to set
    /// the "don't fragment" bit (only ever when
    /// [`sets_dont_fragment`](Self::sets_dont_fragment)). Default: `send_to_peer_tos` with
    /// `ip.tos`.
    fn send_to_peer_ip(&mut self, relay: SocketAddr, peer: SocketAddr, data: &[u8], ip: IpFields) {
        self.send_to_peer_tos(relay, peer, data, ip.tos);
    }
    /// Whether datagrams to peers can be sent with the "don't fragment" bit
    /// ([`IpFields::dont_fragment`] in [`send_to_peer_ip`](Self::send_to_peer_ip)). When not,
    /// a `DONT-FRAGMENT` attribute is treated as an unknown comprehension-required one (RFC
    /// 8656 sections 7.2 and 11.2): an Allocate carrying it is answered 420 and a Send
    /// indication carrying it is dropped. Default: no.
    fn sets_dont_fragment(&self) -> bool {
        false
    }
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
    /// Whether ChannelData to `client` must be padded to a multiple of four bytes: a client on a
    /// TCP or TLS stream (RFC 8656 section 12.5). Default: no (UDP). This is also how the core
    /// tells a stream client: only those may ask for TCP allocations or bind connections.
    fn pads_channel_data(&self, client: SocketAddr) -> bool {
        let _ = client;
        false
    }

    /// TCP allocations (RFC 6062): opens a listening TCP socket for `client` bound on `addr`
    /// (port 0: any free port), the relayed transport address, returning its bound address.
    /// Connections it accepts go to [`TurnCore::tcp_incoming`]; connections to peers
    /// ([`connect_peer`](Self::connect_peer)) leave from the same address. Default:
    /// [`io::ErrorKind::Unsupported`], and TCP allocations are refused with 442.
    fn open_tcp_relay(&mut self, client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        let _ = (client, addr);
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Closes the TCP listener bound at `relay` (its connections are closed one by one with
    /// [`close_connection`](Self::close_connection) first).
    fn close_tcp_relay(&mut self, relay: SocketAddr) {
        let _ = relay;
    }

    /// A Connect request of `client`: open a TCP connection from `relay` to `peer`, connection
    /// `id`, and report the outcome with [`TurnCore::tcp_connected`] (not from inside this
    /// call). The data the peer sends before the connection is bound is held (bounded). The
    /// core answers 447 and calls [`close_connection`](Self::close_connection) itself when no
    /// outcome came within [`TurnConfig::tcp_connect_timeout`]: the environment may abandon the
    /// attempt then.
    fn connect_peer(&mut self, client: SocketAddr, relay: SocketAddr, peer: SocketAddr, id: u32) {
        let _ = (client, relay, peer, id);
    }

    /// The connection from `peer` accepted on `relay` (being handled by
    /// [`TurnCore::tcp_incoming`]) is connection `id` of `client`'s allocation. Called before
    /// the client hears of it in a ConnectionAttempt, so a ConnectionBind cannot outrun it.
    fn accept_peer(&mut self, client: SocketAddr, relay: SocketAddr, peer: SocketAddr, id: u32) {
        let _ = (client, relay, peer, id);
    }

    /// The stream client at `data_client` bound connection `id` with a ConnectionBind (the
    /// success response was just sent to it): from now on its bytes and the peer's are relayed
    /// as they are. Called only when the request reached [`TurnCore::handle_client`].
    fn connection_bound(&mut self, data_client: SocketAddr, id: u32) {
        let _ = (data_client, id);
    }

    /// Closes connection `id`: the peer's connection and the client's data connection, if
    /// bound. Called when its allocation goes, when it waited too long for a ConnectionBind,
    /// and from [`TurnCore::tcp_closed`]; may be called for a connection already closed.
    fn close_connection(&mut self, id: u32) {
        let _ = id;
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
    /// Relay sockets of the other address family than `relay_ip` are bound on this address
    /// (RFC 8656: an IPv6 relay next to an IPv4 one, or the reverse). Clients then get that
    /// family with `REQUESTED-ADDRESS-FAMILY`, and both in one allocation with
    /// `ADDITIONAL-ADDRESS-FAMILY` (a dual allocation). `None` (the default), or an address of
    /// `relay_ip`'s own family: one family only, and dual allocations get theirs with an
    /// `ADDRESS-ERROR-CODE` 440 for the other.
    pub additional_relay_ip: Option<IpAddr>,
    /// What `public_ip` is to `relay_ip`, for `additional_relay_ip`.
    pub additional_public_ip: Option<IpAddr>,
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
    /// A TCP or TLS client connection that has not created an allocation this long after it
    /// was accepted is closed (30s).
    pub stream_allocate_timeout: Duration,
    /// Relayed data (ChannelData, Data indications) for a TCP or TLS client is dropped while
    /// that connection has more than this many bytes queued (256 KiB): relayed traffic keeps
    /// its datagram semantics instead of piling up behind a slow reader.
    pub max_stream_queue: usize,
    /// Offers TCP allocations (RFC 6062) to TCP and TLS clients (true): `REQUESTED-TRANSPORT`
    /// TCP gets a TCP relayed address; when false it is refused with 442. Peers are checked
    /// against the same policy as UDP ones.
    pub tcp_relays: bool,
    /// Connections of one TCP allocation, connecting, waiting for a ConnectionBind or bound
    /// (64): Connect beyond is refused with 508, peers' connections beyond are closed.
    pub max_tcp_connections: usize,
    /// Bytes a TCP relay holds per direction (64 KiB): a peer's data waiting for the client's
    /// ConnectionBind (reading the peer pauses at this mark, which closes its TCP window), and
    /// the send queue of one side at which reading the other side pauses until it drains.
    pub tcp_relay_buffer: usize,
    /// How long a Connect waits for the server's connection to the peer before it is answered
    /// 447 (30 s, the least RFC 6062 section 5.2 allows). The core keeps this deadline itself
    /// (in [`TurnCore::handle_timeout`]), whatever the environment does; [`TurnServer`]
    /// connects without the engine's `Config::connect_timeout`, so this setting alone decides.
    ///
    /// [`TurnServer`]: crate::TurnServer
    pub tcp_connect_timeout: Duration,
    /// Relayed datagrams keep the DSCP of the datagram they came in (true), as RFC 8656
    /// section 14 prefers for UDP to UDP, both ways; the ECN codepoint is always kept. Off:
    /// they go out with DSCP 0 (best effort), for a server that should not let clients and
    /// peers pick their traffic class. Platforms that do not report the traffic class (or
    /// streams, sections 15 and 16) give 0 either way.
    pub copy_dscp: bool,
    /// Relayed datagrams go out with the TTL (IPv4) or hop limit (IPv6) they came in with
    /// minus one (true), as RFC 5766 section 12 prefers UDP to UDP and RFC 8656 section 13 for
    /// a relay between IPv6 and either family: a datagram that loops through relays dies once
    /// its TTL runs out, as it would through routers, and one that arrives with 1 is dropped.
    /// Off: they go out with the socket's default (the alternative both allow). Needs the
    /// incoming TTL: [`TurnServer`] asks its sockets for it; Linux sends it on both families,
    /// macOS on IPv6 only (XNU ignores a per-datagram IPv4 TTL). Stream clients have none
    /// (sections 15 and 16).
    ///
    /// [`TurnServer`]: crate::TurnServer
    pub copy_ttl: bool,
    /// ICMP errors drawn by datagrams relayed to peers go back to the client as Data
    /// indications with an `ICMP` attribute (true, RFC 8656 section 11.5). [`TurnServer`]
    /// reads them on Linux and macOS (`akio::Engine::bind_udp_icmp`); elsewhere there are
    /// none. The server's own errors go the same way and are turned off with it: time
    /// exceeded for a client's datagram dropped at TTL 1 (see [`copy_ttl`](Self::copy_ttl);
    /// at most one per allocation per 100 ms), and, from [`TurnServer`], "fragmentation
    /// needed" / "packet too big" with the path MTU for a `DONT-FRAGMENT` datagram the kernel
    /// refuses as too large (RFC 8656 sections 13.2 and 14; at most one per relay per 100 ms).
    ///
    /// [`TurnServer`]: crate::TurnServer
    pub relay_icmp: bool,
}

impl fmt::Debug for TurnConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnConfig")
            .field("realm", &self.realm)
            .field("relay_ip", &self.relay_ip)
            .field("public_ip", &self.public_ip)
            .field("additional_relay_ip", &self.additional_relay_ip)
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
            additional_relay_ip: None,
            additional_public_ip: None,
            software: Some(concat!("akio-turn ", env!("CARGO_PKG_VERSION")).to_owned()),
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
            stream_allocate_timeout: Duration::from_secs(30),
            max_stream_queue: 256 * 1024,
            tcp_relays: true,
            max_tcp_connections: 64,
            tcp_relay_buffer: 64 * 1024,
            tcp_connect_timeout: Duration::from_secs(30),
            copy_dscp: true,
            copy_ttl: true,
            relay_icmp: true,
        }
    }

    /// Sets [`public_ip`](Self::public_ip).
    #[must_use]
    pub fn public_ip(mut self, ip: IpAddr) -> Self {
        self.public_ip = Some(ip);
        self
    }

    /// Sets [`additional_relay_ip`](Self::additional_relay_ip): relays of that address's
    /// family too, and dual allocations.
    #[must_use]
    pub fn additional_relay_ip(mut self, ip: IpAddr) -> Self {
        self.additional_relay_ip = Some(ip);
        self
    }

    /// Sets [`additional_public_ip`](Self::additional_public_ip).
    #[must_use]
    pub fn additional_public_ip(mut self, ip: IpAddr) -> Self {
        self.additional_public_ip = Some(ip);
        self
    }

    /// Where relays of the IPv6 (`v6`) or IPv4 family are bound, if that family is offered.
    pub(crate) fn relay_ip_for(&self, v6: bool) -> Option<IpAddr> {
        if self.relay_ip.is_ipv6() == v6 {
            Some(self.relay_ip)
        } else {
            self.additional_relay_ip.filter(|ip| ip.is_ipv6() == v6)
        }
    }

    /// The family of an allocation that names none: IPv4 when offered (RFC 8656 section 7.2),
    /// else `relay_ip`'s.
    pub(crate) fn default_v6(&self) -> bool {
        self.relay_ip_for(false).is_none()
    }

    /// The address clients are told of for the relay bound at `relay`.
    fn public_of(&self, relay: SocketAddr) -> SocketAddr {
        let public = if relay.is_ipv6() == self.relay_ip.is_ipv6() {
            self.public_ip
        } else {
            self.additional_public_ip
        };
        SocketAddr::new(public.unwrap_or_else(|| relay.ip()), relay.port())
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

    /// Sets [`tcp_relays`](Self::tcp_relays).
    #[must_use]
    pub fn tcp_relays(mut self, yes: bool) -> Self {
        self.tcp_relays = yes;
        self
    }

    /// Sets [`tcp_connect_timeout`](Self::tcp_connect_timeout).
    #[must_use]
    pub fn tcp_connect_timeout(mut self, d: Duration) -> Self {
        self.tcp_connect_timeout = d;
        self
    }

    /// Sets [`copy_ttl`](Self::copy_ttl).
    #[must_use]
    pub fn copy_ttl(mut self, yes: bool) -> Self {
        self.copy_ttl = yes;
        self
    }

    /// Sets [`copy_dscp`](Self::copy_dscp).
    #[must_use]
    pub fn copy_dscp(mut self, yes: bool) -> Self {
        self.copy_dscp = yes;
        self
    }

    /// Sets [`relay_icmp`](Self::relay_icmp).
    #[must_use]
    pub fn relay_icmp(mut self, yes: bool) -> Self {
        self.relay_icmp = yes;
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

/// One relayed transport address of an allocation.
#[derive(Clone, Copy)]
struct RelayAddr {
    /// Where its socket is bound.
    relay: SocketAddr,
    /// What the client is told.
    public: SocketAddr,
    expires: Instant,
}

struct Allocation {
    /// One relayed address, or two of different families (a dual allocation, RFC 8656
    /// `ADDITIONAL-ADDRESS-FAMILY`), each with its own lifetime: refreshed or deleted alone
    /// with `REQUESTED-ADDRESS-FAMILY`. The allocation goes with the last one. A TCP
    /// allocation has one, its listener.
    relays: Vec<RelayAddr>,
    user: String,
    key: [u8; 16],
    created_tid: [u8; 12],
    /// The `ADDRESS-ERROR-CODE` of a dual allocation that got one family (family, code), for
    /// retransmissions of the Allocate.
    addr_error: Option<(u8, u16)>,
    perms: HashMap<IpAddr, Instant>,
    chans: HashMap<u16, (SocketAddr, Instant)>,
    chan_of: HashMap<SocketAddr, u16>,
    /// A TCP allocation (RFC 6062): its connections. `relay` is then its listener.
    tcp: Option<Box<TcpAlloc>>,
    /// When the client was last told of a datagram of its dropped at TTL 1 (ICMP time
    /// exceeded), to tell it at most once per [`TTL_ICMP_GAP`].
    ttl_icmp_at: Option<Instant>,
}

/// The least time between two "time exceeded" indications to one client: one tells it what
/// happened; a stream of them would cost a message per dropped datagram.
const TTL_ICMP_GAP: Duration = Duration::from_millis(100);

impl Allocation {
    /// Whether any relayed address is still alive.
    fn alive(&self, now: Instant) -> bool {
        self.relays.iter().any(|r| r.expires > now)
    }

    /// The live relayed address of `peer`'s family.
    fn relay_for(&self, peer: SocketAddr, now: Instant) -> Option<&RelayAddr> {
        self.relays
            .iter()
            .find(|r| r.relay.is_ipv6() == peer.is_ipv6() && r.expires > now)
    }

    /// Whether the allocation has a relayed address of `peer`'s family.
    fn has_family(&self, peer: SocketAddr) -> bool {
        self.relays
            .iter()
            .any(|r| r.relay.is_ipv6() == peer.is_ipv6())
    }

    /// Forgets the permissions and channels of the IPv6 (`v6`) or IPv4 family: its relayed
    /// address is gone (RFC 8656 section 8.1: the other family's stay).
    fn drop_family(&mut self, v6: bool) {
        self.perms.retain(|ip, _| ip.is_ipv6() != v6);
        let chans = &mut self.chans;
        self.chan_of.retain(|p, c| {
            let keep = p.is_ipv6() != v6;
            if !keep {
                chans.remove(c);
            }
            keep
        });
        self.chans.retain(|_, (p, _)| p.is_ipv6() != v6);
    }
}

/// The connections of a TCP allocation.
#[derive(Default)]
struct TcpAlloc {
    /// Connections by id.
    conns: HashMap<u32, TcpConn>,
    /// Connection ids by peer transport address: one connection per peer (RFC 6062 section 3).
    by_peer: HashMap<SocketAddr, u32>,
}

struct TcpConn {
    peer: SocketAddr,
    state: TcpState,
}

enum TcpState {
    /// A Connect request waiting for its outgoing connection: the request's transaction id,
    /// whether it carried `FINGERPRINT`, and when it fails (`TurnConfig::tcp_connect_timeout`).
    Connecting([u8; 12], bool, Instant),
    /// Connected or accepted, waiting for a ConnectionBind until then.
    Pending(Instant),
    /// Bound to a client data connection.
    Bound,
}

/// How long a peer connection waits for its ConnectionBind (RFC 6062 sections 5.2 and 5.3).
pub(crate) const TCP_BIND_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// Connections of TCP allocations open now (RFC 6062: connecting, waiting for a
    /// ConnectionBind, or bound).
    pub tcp_connections: usize,
    /// ICMP errors relayed to clients (Data indications with an `ICMP` attribute).
    pub icmp: u64,
    /// Datagrams not relayed because they arrived with a TTL / hop limit of 1, with nothing
    /// left for the hop through the server ([`TurnConfig::copy_ttl`]).
    pub ttl_expired: u64,
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
    /// The next `CONNECTION-ID` (from a random start, never 0), server-wide.
    next_conn: AtomicU32,
}

impl Shared {
    pub(crate) fn new(cfg: TurnConfig) -> Shared {
        let mut nonce_key = [0u8; 32];
        crate::fill_random(&mut nonce_key);
        let mut start = [0u8; 4];
        crate::fill_random(&mut start);
        Shared {
            cfg,
            nonce_key,
            epoch: Instant::now(),
            allocations: AtomicUsize::new(0),
            per_user: Mutex::new(HashMap::new()),
            reservations: Mutex::new(HashMap::new()),
            next_conn: AtomicU32::new(u32::from_be_bytes(start)),
        }
    }

    /// A new `CONNECTION-ID`: unique among the server's connections until 2^32 more were made.
    fn connection_id(&self) -> u32 {
        loop {
            let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
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

    /// The addresses to bind relays on (any port) for `data` when it is an authenticated
    /// Allocate of a UDP relay without `EVEN-PORT` or `RESERVATION-TOKEN`: the server binds
    /// those sockets before taking the shard's lock. One address, or two for a dual allocation
    /// the server can meet; none for anything else (the request is then handled, and maybe
    /// refused, under the lock). Only a client holding valid credentials and a nonce issued to
    /// its own address gets any, so this cannot be used to make the server bind sockets for
    /// free.
    pub(crate) fn prebind_ips(&self, now: Instant, client: SocketAddr, data: &[u8]) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        if !is_stun(data) {
            return ips;
        }
        let Ok(m) = Message::parse(data) else {
            return ips;
        };
        if m.class() != Class::Request
            || m.method() != Method::ALLOCATE
            || m.has(attr::EVEN_PORT)
            || m.has(attr::RESERVATION_TOKEN)
            || !m
                .get(attr::REQUESTED_TRANSPORT)
                .is_some_and(|t| t.len() == 4 && t[0] == 17)
        {
            return ips;
        }
        let Ok(Families { v6, additional }) = families(&self.cfg, &m) else {
            return ips;
        };
        let (Some(user), Some(realm), Some(nonce)) = (
            m.get_str(attr::USERNAME),
            m.get_str(attr::REALM),
            m.get_str(attr::NONCE),
        ) else {
            return ips;
        };
        let ok = realm == self.cfg.realm
            && self.nonce_valid(now, client, nonce)
            && (self.cfg.auth)(user, realm).is_some_and(|k| m.check_integrity(&k));
        if ok {
            ips.extend(self.cfg.relay_ip_for(v6));
            if additional {
                ips.extend(self.cfg.relay_ip_for(true));
            }
        }
        ips
    }
}

/// The address families an Allocate asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Families {
    /// The first relayed address is IPv6.
    v6: bool,
    /// `ADDITIONAL-ADDRESS-FAMILY` IPv6 too (a dual allocation; the first is then IPv4).
    additional: bool,
}

/// The families an Allocate asks for (RFC 8656 section 7.2, steps 6, 7 and 9): 400 for both
/// `REQUESTED-ADDRESS-FAMILY` and `ADDITIONAL-ADDRESS-FAMILY`, or for an additional family
/// other than IPv6; 440 for a requested family the server does not relay, an unknown one,
/// or no IPv4 for a dual allocation. Without either, IPv4 when offered, else `relay_ip`'s.
fn families(cfg: &TurnConfig, m: &Message<'_>) -> Result<Families, Reject> {
    let family = |v: &[u8]| match v.first() {
        Some(1) => Some(false),
        Some(2) => Some(true),
        _ => None,
    };
    let unsupported = || Reject(440, "Address Family not Supported");
    match (m.get(attr::REQUESTED_ADDRESS_FAMILY), additional_family(m)) {
        (Some(_), Some(_)) => Err(Reject(400, "Bad Request")),
        (Some(r), None) => {
            let v6 = family(r).ok_or_else(unsupported)?;
            cfg.relay_ip_for(v6).ok_or_else(unsupported)?;
            Ok(Families {
                v6,
                additional: false,
            })
        }
        (None, Some(a)) => {
            if family(a) != Some(true) {
                return Err(Reject(400, "Bad Request"));
            }
            cfg.relay_ip_for(false).ok_or_else(unsupported)?;
            Ok(Families {
                v6: false,
                additional: true,
            })
        }
        (None, None) => Ok(Families {
            v6: cfg.default_v6(),
            additional: false,
        }),
    }
}

/// `ADDITIONAL-ADDRESS-FAMILY`, by its RFC 8656 codepoint or the draft one coturn 4.6 uses.
fn additional_family<'a>(m: &Message<'a>) -> Option<&'a [u8]> {
    m.get(attr::ADDITIONAL_ADDRESS_FAMILY)
        .or_else(|| m.get(attr::ADDITIONAL_ADDRESS_FAMILY_DRAFT))
}

/// Adds `ADDRESS-ERROR-CODE` for `family` and `code` to a response to `m`: by its RFC 8656
/// codepoint, and by the draft one too when `m` asked with the draft's attribute (coturn 4.6
/// reads only that).
fn with_address_error(b: MessageBuilder, m: &Message<'_>, family: u8, code: u16) -> MessageBuilder {
    let b = b.address_error(family, code, reason(code));
    if !m.has(attr::ADDITIONAL_ADDRESS_FAMILY_DRAFT) {
        return b;
    }
    let mut v = vec![family, 0, (code / 100) as u8, (code % 100) as u8];
    v.extend_from_slice(reason(code).as_bytes());
    b.attr(attr::ADDRESS_ERROR_CODE_DRAFT, &v)
}

/// The TURN server state machine (see the module docs).
pub struct TurnCore {
    shared: Arc<Shared>,
    allocs: HashMap<SocketAddr, Allocation>,
    by_relay: HashMap<SocketAddr, SocketAddr>,
    /// Clients of TCP allocations by their listener's address.
    by_tcp_relay: HashMap<SocketAddr, SocketAddr>,
    /// Clients of TCP allocations by connection id.
    by_conn: HashMap<u32, SocketAddr>,
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
            by_tcp_relay: HashMap::new(),
            by_conn: HashMap::new(),
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
        s.tcp_connections = self.by_conn.len();
        s
    }

    /// The relayed address (as told to the client) of `client`'s allocation: the first one of
    /// a dual allocation (IPv4).
    pub fn relay_of(&self, client: SocketAddr) -> Option<SocketAddr> {
        self.allocs
            .get(&client)
            .and_then(|a| a.relays.first())
            .map(|r| r.public)
    }

    /// The relayed addresses (as told to the client) of `client`'s allocation: one, or two of
    /// a dual allocation (IPv4 first); empty without an allocation.
    pub fn relays_of(&self, client: SocketAddr) -> Vec<SocketAddr> {
        self.allocs
            .get(&client)
            .map(|a| a.relays.iter().map(|r| r.public).collect())
            .unwrap_or_default()
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
        self.handle_client_ecn(now, client, data, 0, env);
    }

    /// [`handle_client`](Self::handle_client) for a datagram that arrived with ECN codepoint
    /// `ecn`: relayed data goes to the peer with [`TurnEnv::send_to_peer_ecn`] and that
    /// codepoint (RFC 8656 section 14).
    pub fn handle_client_ecn(
        &mut self,
        now: Instant,
        client: SocketAddr,
        data: &[u8],
        ecn: u8,
        env: &mut dyn TurnEnv,
    ) {
        self.handle_client_tos(now, client, data, ecn & 3, env);
    }

    /// [`handle_client`](Self::handle_client) for a datagram that arrived with traffic class
    /// byte `tos` (IPv4 TOS / IPv6 traffic class: DSCP and ECN): relayed data goes to the peer
    /// with [`TurnEnv::send_to_peer_tos`] and that byte, its DSCP cleared unless
    /// [`TurnConfig::copy_dscp`] (RFC 8656 section 14).
    pub fn handle_client_tos(
        &mut self,
        now: Instant,
        client: SocketAddr,
        data: &[u8],
        tos: u8,
        env: &mut dyn TurnEnv,
    ) {
        self.handle_client_ip(now, client, data, IpFields::new(tos, 0), env);
    }

    /// [`handle_client`](Self::handle_client) for a datagram that arrived with IP header
    /// fields `ip` (traffic class byte and TTL / hop limit): relayed data goes to the peer
    /// with [`TurnEnv::send_to_peer_ip`] and those fields, the DSCP cleared unless
    /// [`TurnConfig::copy_dscp`], the TTL one less unless [`TurnConfig::copy_ttl`] is off
    /// (dropped when it came in as 1), and the "don't fragment" bit for a Send indication with
    /// `DONT-FRAGMENT` (RFC 8656 sections 14 and 15).
    pub fn handle_client_ip(
        &mut self,
        now: Instant,
        client: SocketAddr,
        data: &[u8],
        ip: IpFields,
        env: &mut dyn TurnEnv,
    ) {
        if is_channel_data(data) {
            self.channel_data(now, client, data, ip, env);
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
                self.send_indication(now, client, &m, ip, env);
            }
            _ => {}
        }
    }

    fn channel_data(
        &mut self,
        now: Instant,
        client: SocketAddr,
        data: &[u8],
        ip: IpFields,
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
        if a.tcp.is_some() {
            return;
        }
        let Some(&(peer, exp)) = a.chans.get(&ch) else {
            return;
        };
        let Some(r) = a.relay_for(peer, now) else {
            return;
        };
        if exp <= now || !self.peer_ok(peer) {
            return;
        }
        let relay = r.relay;
        let Some(out) = self.relayed(ip) else {
            self.ttl_exceeded(now, client, relay, peer, env);
            return;
        };
        self.stats.to_peer += 1;
        env.send_to_peer_ip(relay, peer, &data[4..4 + len], out);
    }

    fn send_indication(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        ip: IpFields,
        env: &mut dyn TurnEnv,
    ) {
        let (Some(peer), Some(payload)) =
            (m.get_xor_addr(attr::XOR_PEER_ADDRESS), m.get(attr::DATA))
        else {
            return;
        };
        // Section 11.2: a server that cannot set DF treats the attribute as unknown and
        // comprehension-required, which drops the indication.
        let df = m.has(attr::DONT_FRAGMENT);
        if df && !env.sets_dont_fragment() {
            return;
        }
        let Some(a) = self.allocs.get(&client) else {
            return;
        };
        if a.tcp.is_some() || !a.perms.get(&peer.ip()).is_some_and(|&e| e > now) {
            return;
        }
        let Some(r) = a.relay_for(peer, now) else {
            return;
        };
        if !self.peer_ok(peer) {
            return;
        }
        let relay = r.relay;
        let Some(mut out) = self.relayed(ip) else {
            self.ttl_exceeded(now, client, relay, peer, env);
            return;
        };
        // DF applies IPv4 to IPv4 over UDP (section 14; translations to or from IPv6 ignore
        // the attribute, section 13), and to everything from a stream client (section 15).
        let v4 = |a: SocketAddr| a.ip().to_canonical().is_ipv4();
        out.dont_fragment =
            df && (env.pads_channel_data(client) || (v4(client) && v4(peer) && relay.is_ipv4()));
        self.stats.to_peer += 1;
        env.send_to_peer_ip(relay, peer, payload, out);
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
        self.handle_peer_ecn(now, relay, peer, data, 0, env);
    }

    /// [`handle_peer`](Self::handle_peer) for a datagram that arrived with ECN codepoint
    /// `ecn`: it goes to the client with [`TurnEnv::send_to_client_ecn`] and that codepoint
    /// (RFC 8656 section 14).
    pub fn handle_peer_ecn(
        &mut self,
        now: Instant,
        relay: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
        ecn: u8,
        env: &mut dyn TurnEnv,
    ) {
        self.handle_peer_tos(now, relay, peer, data, ecn & 3, env);
    }

    /// [`handle_peer`](Self::handle_peer) for a datagram that arrived with traffic class byte
    /// `tos` (DSCP and ECN): it goes to the client with [`TurnEnv::send_to_client_tos`] and that
    /// byte, its DSCP cleared unless [`TurnConfig::copy_dscp`] (RFC 8656 section 14).
    pub fn handle_peer_tos(
        &mut self,
        now: Instant,
        relay: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
        tos: u8,
        env: &mut dyn TurnEnv,
    ) {
        self.handle_peer_ip(now, relay, peer, data, IpFields::new(tos, 0), env);
    }

    /// [`handle_peer`](Self::handle_peer) for a datagram that arrived with IP header fields
    /// `ip` (traffic class byte and TTL / hop limit): it goes to the client with
    /// [`TurnEnv::send_to_client_ip`] and those fields, the DSCP cleared unless
    /// [`TurnConfig::copy_dscp`], the TTL one less unless [`TurnConfig::copy_ttl`] is off
    /// (dropped when it came in as 1, unless the client is on a stream: no hop of the
    /// datagram's own follows there, RFC 8656 section 16).
    pub fn handle_peer_ip(
        &mut self,
        now: Instant,
        relay: SocketAddr,
        peer: SocketAddr,
        data: &[u8],
        ip: IpFields,
        env: &mut dyn TurnEnv,
    ) {
        let Some(&client) = self.by_relay.get(&relay) else {
            return;
        };
        let Some(a) = self.allocs.get(&client) else {
            return;
        };
        // The relayed address it arrived on, alive, and of the peer's family.
        let live = a
            .relays
            .iter()
            .any(|r| r.relay == relay && r.expires > now && r.relay.is_ipv6() == peer.is_ipv6());
        if !live || !a.perms.get(&peer.ip()).is_some_and(|&e| e > now) {
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
        let out = if env.pads_channel_data(client) {
            IpFields::default()
        } else {
            match self.relayed(ip) {
                Some(out) => out,
                None => return,
            }
        };
        self.stats.to_client += 1;
        match ch {
            Some(ch) => {
                let mut buf = Vec::with_capacity(4 + data.len() + 3);
                buf.extend_from_slice(&ch.to_be_bytes());
                buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
                buf.extend_from_slice(data);
                // UDP: padding is optional; it is not sent. Streams need it (RFC 8656 section
                // 12.5).
                if env.pads_channel_data(client) {
                    let pad = crate::framing::channel_data_padding(buf.len());
                    buf.resize(buf.len() + pad, 0);
                }
                env.send_to_client_ip(client, &buf, out);
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
                env.send_to_client_ip(client, &msg, out);
            }
        }
    }

    /// The fields a datagram that came in with `ip` is relayed with: the ECN codepoint, the
    /// DSCP when [`TurnConfig::copy_dscp`], the TTL one less when [`TurnConfig::copy_ttl`]
    /// (unknown, 0, stays 0: the socket's). `None` (counted) when it came in with a TTL of 1:
    /// one more hop would take it to 0, where a router drops it.
    fn relayed(&mut self, ip: IpFields) -> Option<IpFields> {
        let cfg = &self.shared.cfg;
        let tos = if cfg.copy_dscp { ip.tos } else { ip.tos & 3 };
        let ttl = match ip.ttl {
            _ if !cfg.copy_ttl => 0,
            0 => 0,
            1 => {
                self.stats.ttl_expired += 1;
                return None;
            }
            t => t - 1,
        };
        Some(IpFields::new(tos, ttl))
    }

    /// A datagram from `client` to `peer` through `relay` was dropped at TTL 1: the client
    /// hears of it as a router's sender would (RFC 8656 section 13.2: the server "acts as a
    /// regular router", ICMP error included), in a Data indication with `ICMP` time exceeded
    /// (ICMPv4 11/0, ICMPv6 3/0 by the relay's family), at most once per [`TTL_ICMP_GAP`].
    /// Through [`handle_icmp`](Self::handle_icmp): `relay_icmp`, the permission and the peer
    /// policy apply. A peer's datagram dropped so draws nothing: telling a peer takes a real
    /// ICMP message, which an unprivileged process cannot send.
    fn ttl_exceeded(
        &mut self,
        now: Instant,
        client: SocketAddr,
        relay: SocketAddr,
        peer: SocketAddr,
        env: &mut dyn TurnEnv,
    ) {
        if !self.shared.cfg.relay_icmp {
            return;
        }
        let Some(a) = self.allocs.get_mut(&client) else {
            return;
        };
        if a.ttl_icmp_at
            .is_some_and(|t| now.saturating_duration_since(t) < TTL_ICMP_GAP)
        {
            return;
        }
        a.ttl_icmp_at = Some(now);
        let (ty, code) = if relay.is_ipv6() { (3, 0) } else { (11, 0) };
        self.handle_icmp(now, relay, peer, ty, code, 0, env);
    }

    /// An ICMP error (type `icmp_type`, code `code`) that a datagram sent from the relay
    /// socket bound at `relay` to `peer` drew (RFC 8656 section 11.5). `peer`'s port is the
    /// datagram's destination port, or 0 when the platform does not tell it; `mtu` is the
    /// next-hop MTU an ICMPv4 "fragmentation needed" or ICMPv6 "packet too big" carries (else
    /// ignored). ICMPv4 or ICMPv6 follows from `relay`'s family.
    ///
    /// Only destination unreachable and time exceeded (ICMPv4 types 3 and 11; ICMPv6 1, 2 and
    /// 3) are relayed, and only to an allocation whose relayed address of that family is alive
    /// and has a permission for `peer`'s IP address: the client gets a Data indication with
    /// `XOR-PEER-ADDRESS` and `ICMP`, and no `DATA`. Anything else is dropped, as is everything
    /// when [`TurnConfig::relay_icmp`] is off.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_icmp(
        &mut self,
        now: Instant,
        relay: SocketAddr,
        peer: SocketAddr,
        icmp_type: u8,
        code: u8,
        mtu: u32,
        env: &mut dyn TurnEnv,
    ) {
        if !self.shared.cfg.relay_icmp || relay.is_ipv6() != peer.is_ipv6() {
            return;
        }
        let v6 = relay.is_ipv6();
        let relayed = if v6 {
            matches!(icmp_type, 1..=3)
        } else {
            matches!(icmp_type, 3 | 11)
        };
        if !relayed {
            return;
        }
        let Some(&client) = self.by_relay.get(&relay) else {
            return;
        };
        let Some(a) = self.allocs.get(&client) else {
            return;
        };
        let live = a.relays.iter().any(|r| r.relay == relay && r.expires > now);
        if !live || !a.perms.get(&peer.ip()).is_some_and(|&e| e > now) {
            return;
        }
        if !self.peer_ok(peer) {
            return;
        }
        // Section 18.13: the MTU for "packet too big" and "fragmentation needed", else 0.
        let too_big = if v6 {
            icmp_type == 2
        } else {
            icmp_type == 3 && code == 4
        };
        let data = if too_big { mtu } else { 0 };
        self.stats.icmp += 1;
        let msg = MessageBuilder::new(
            Method::DATA,
            Class::Indication,
            crate::stun::transaction_id(),
        )
        .xor_addr(attr::XOR_PEER_ADDRESS, peer)
        .icmp(icmp_type, code, data)
        .build();
        env.send_to_client(client, &msg);
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
            .filter(|(_, a)| a.relays.iter().any(|r| r.expires <= now))
            .map(|(c, _)| *c)
            .collect();
        for c in dead {
            // One family of a dual allocation may outlive the other.
            let gone: Vec<bool> = self.allocs.get(&c).map_or_else(Vec::new, |a| {
                a.relays
                    .iter()
                    .filter(|r| r.expires <= now)
                    .map(|r| r.relay.is_ipv6())
                    .collect()
            });
            for v6 in gone {
                self.remove_family(c, v6, env);
            }
        }
        self.tcp_timeouts(now, env);
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

    /// Frees `client`'s allocation, if any (closing its relay): the client's TCP or TLS
    /// connection closed (RFC 8656 section 3.1: an allocation over a stream lives as long as
    /// the connection).
    pub fn remove_client(&mut self, client: SocketAddr, env: &mut dyn TurnEnv) {
        self.remove(client, env);
    }

    fn remove(&mut self, client: SocketAddr, env: &mut dyn TurnEnv) {
        if let Some(a) = self.allocs.remove(&client) {
            self.shared.release(&a.user);
            match a.tcp {
                Some(tcp) => {
                    // RFC 6062 section 5.5: the data connections go with the allocation.
                    for id in tcp.conns.keys() {
                        self.by_conn.remove(id);
                        env.close_connection(*id);
                    }
                    for r in &a.relays {
                        self.by_tcp_relay.remove(&r.relay);
                        env.close_tcp_relay(r.relay);
                    }
                }
                None => {
                    for r in &a.relays {
                        self.by_relay.remove(&r.relay);
                        env.close_relay(r.relay);
                    }
                }
            }
        }
    }

    /// Frees the relayed address of the IPv6 (`v6`) or IPv4 family of `client`'s allocation,
    /// with its permissions and channels; the allocation goes with its last one.
    fn remove_family(&mut self, client: SocketAddr, v6: bool, env: &mut dyn TurnEnv) {
        let Some(a) = self.allocs.get_mut(&client) else {
            return;
        };
        if a.tcp.is_some() || a.relays.iter().all(|r| r.relay.is_ipv6() == v6) {
            self.remove(client, env);
            return;
        }
        let Some(i) = a.relays.iter().position(|r| r.relay.is_ipv6() == v6) else {
            return;
        };
        let r = a.relays.remove(i);
        a.drop_family(v6);
        self.by_relay.remove(&r.relay);
        env.close_relay(r.relay);
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
        if m.method() == Method::CONNECTION_BIND {
            // On a new connection of the client, with the credentials of its control
            // connection (RFC 6062 section 5.4).
            let stream = env.pads_channel_data(client);
            if let Some((out, bound)) = self.connection_bind(now, client, m, None, stream) {
                env.send_to_client(client, &out);
                if let Some(id) = bound {
                    env.connection_bound(client, id);
                }
            }
            return;
        }
        if !matches!(
            m.method(),
            Method::ALLOCATE
                | Method::REFRESH
                | Method::CREATE_PERMISSION
                | Method::CHANNEL_BIND
                | Method::CONNECT
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
        // Section 7.2: a server that cannot set DF treats an Allocate's DONT-FRAGMENT as
        // unknown and comprehension-required.
        let df_known = m.method() != Method::ALLOCATE || env.sets_dont_fragment();
        if let Some(unknown) = unknown_required(m, df_known) {
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
            Method::CONNECT => match self.connect(now, client, m, env) {
                // Answered once the connection is up or has failed (`tcp_connected`).
                Ok(()) => return,
                Err(r) => Err(r),
            },
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
                let left = a
                    .relays
                    .iter()
                    .map(|r| r.expires.saturating_duration_since(now))
                    .max()
                    .unwrap_or_default()
                    .as_secs() as u32;
                let mut b = self.base(m, Class::Success);
                for r in &a.relays {
                    b = b.xor_addr(attr::XOR_RELAYED_ADDRESS, r.public);
                }
                b = b
                    .u32(attr::LIFETIME, left)
                    .xor_addr(attr::XOR_MAPPED_ADDRESS, client);
                if let Some((family, code)) = a.addr_error {
                    b = with_address_error(b, m, family, code);
                }
                return Ok(b);
            }
            return Err(Reject(437, "Allocation Mismatch"));
        }
        let Some(t) = m.get(attr::REQUESTED_TRANSPORT) else {
            return Err(Reject(400, "Bad Request"));
        };
        let unsupported = || Reject(442, "Unsupported Transport Protocol");
        if t.len() != 4 || !matches!(t[0], 6 | 17) {
            return Err(unsupported());
        }
        if t[0] == 6 {
            return self.allocate_tcp(now, client, m, user, key, env);
        }
        let token = m.get(attr::RESERVATION_TOKEN);
        let even = m.get(attr::EVEN_PORT);
        if token.is_some()
            && (even.is_some()
                || m.has(attr::REQUESTED_ADDRESS_FAMILY)
                || additional_family(m).is_some())
        {
            return Err(Reject(400, "Bad Request"));
        }
        let fam = families(&self.shared.cfg, m)?;
        // EVEN-PORT with the R bit and a dual allocation would need two tokens (step 8).
        if fam.additional && even.is_some_and(|e| e.first().is_some_and(|b| b & 0x80 != 0)) {
            return Err(Reject(400, "Bad Request"));
        }
        let token: Option<[u8; 8]> = match token {
            Some(t) => Some(t.try_into().map_err(|_| Reject(400, "Bad Request"))?),
            None => None,
        };
        let Some(ip) = self.shared.cfg.relay_ip_for(fam.v6) else {
            return Err(Reject(440, "Address Family not Supported"));
        };
        // Server-wide and per-user quotas: O(1), shared by every shard. A dual allocation is
        // one allocation.
        self.shared.reserve(user)?;
        let (relay, reserved) = match self.open_for(now, client, ip, token, even, env) {
            Ok(r) => r,
            Err(r) => {
                self.shared.release(user);
                return Err(r);
            }
        };
        let mut relays = vec![relay];
        let mut addr_error = None;
        if fam.additional {
            // The IPv6 one, or the reason it is missing (step 9: a partial success).
            match self.shared.cfg.relay_ip_for(true) {
                None => addr_error = Some((2, 440)),
                Some(ip6) => match self.open_for(now, client, ip6, None, even, env) {
                    Ok((r6, _)) => relays.push(r6),
                    Err(_) => addr_error = Some((2, 508)),
                },
            }
        }
        Ok(self.allocated(
            now, client, m, user, key, &relays, reserved, addr_error, false,
        ))
    }

    /// An Allocate for a TCP relayed address (RFC 6062 section 5.1).
    fn allocate_tcp(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        user: &str,
        key: [u8; 16],
        env: &mut dyn TurnEnv,
    ) -> Result<MessageBuilder, Reject> {
        let unsupported = || Reject(442, "Unsupported Transport Protocol");
        if !self.shared.cfg.tcp_relays {
            return Err(unsupported());
        }
        // Only over TCP or TLS, and without the UDP-only attributes.
        if !env.pads_channel_data(client)
            || m.has(attr::DONT_FRAGMENT)
            || m.has(attr::EVEN_PORT)
            || m.has(attr::RESERVATION_TOKEN)
        {
            return Err(Reject(400, "Bad Request"));
        }
        let fam = families(&self.shared.cfg, m)?;
        let Some(ip) = self.shared.cfg.relay_ip_for(fam.v6) else {
            return Err(Reject(440, "Address Family not Supported"));
        };
        // RFC 6062 knows one relayed address: a dual request gets the IPv4 one, and says so.
        let addr_error = fam.additional.then_some((2, 440));
        self.shared.reserve(user)?;
        match env.open_tcp_relay(client, SocketAddr::new(ip, 0)) {
            Ok(relay) => {
                Ok(self.allocated(now, client, m, user, key, &[relay], None, addr_error, true))
            }
            Err(e) => {
                self.shared.release(user);
                Err(if e.kind() == io::ErrorKind::Unsupported {
                    unsupported()
                } else {
                    Reject(508, "Insufficient Capacity")
                })
            }
        }
    }

    /// A relay socket of a new allocation on `ip`, and the token of the port set aside with it.
    fn open_for(
        &self,
        now: Instant,
        client: SocketAddr,
        ip: IpAddr,
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
                let (r, next) = self.open_even(client, ip, reserve, env).ok_or_else(full)?;
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
                .open_relay(client, SocketAddr::new(ip, 0))
                .map(|r| (r, None))
                .map_err(|_| full()),
        }
    }

    /// Records a new allocation on `relays` (one, or two of different families) and builds
    /// its success response.
    #[allow(clippy::too_many_arguments)]
    fn allocated(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        user: &str,
        key: [u8; 16],
        relays: &[SocketAddr],
        reserved: Option<[u8; 8]>,
        addr_error: Option<(u8, u16)>,
        tcp: bool,
    ) -> MessageBuilder {
        let life = self.lifetime(m);
        let relays: Vec<RelayAddr> = relays
            .iter()
            .map(|&relay| RelayAddr {
                relay,
                public: self.shared.cfg.public_of(relay),
                expires: now + life,
            })
            .collect();
        let mut b = self.base(m, Class::Success);
        for r in &relays {
            if tcp {
                self.by_tcp_relay.insert(r.relay, client);
            } else {
                self.by_relay.insert(r.relay, client);
            }
            b = b.xor_addr(attr::XOR_RELAYED_ADDRESS, r.public);
        }
        b = b
            .u32(attr::LIFETIME, life.as_secs() as u32)
            .xor_addr(attr::XOR_MAPPED_ADDRESS, client);
        if let Some(t) = reserved {
            b = b.attr(attr::RESERVATION_TOKEN, &t);
        }
        if let Some((family, code)) = addr_error {
            b = with_address_error(b, m, family, code);
        }
        self.allocs.insert(
            client,
            Allocation {
                relays,
                user: user.to_owned(),
                key,
                created_tid: m.transaction_id(),
                addr_error,
                perms: HashMap::new(),
                chans: HashMap::new(),
                chan_of: HashMap::new(),
                tcp: tcp.then(Box::default),
                ttl_icmp_at: None,
            },
        );
        b
    }

    /// Opens a relay on an even port and, with `reserve`, the odd port above it too (RFC 8656
    /// section 7.2, `EVEN-PORT`). Gives up after a few tries.
    fn open_even(
        &self,
        client: SocketAddr,
        ip: IpAddr,
        reserve: bool,
        env: &mut dyn TurnEnv,
    ) -> Option<(SocketAddr, Option<SocketAddr>)> {
        for _ in 0..32 {
            let r = env.open_relay(client, SocketAddr::new(ip, 0)).ok()?;
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
        let Some(a) = self.allocs.get(&client) else {
            return Err(Reject(437, "Allocation Mismatch"));
        };
        // RFC 8656 sections 8.1 and 8.2: REQUESTED-ADDRESS-FAMILY picks one relayed address of
        // a dual allocation (443 for a family it does not have); without it, all of them.
        let family = match m.get(attr::REQUESTED_ADDRESS_FAMILY) {
            None => None,
            Some(f) => match f.first() {
                Some(1) => Some(false),
                Some(2) => Some(true),
                _ => return Err(Reject(400, "Bad Request")),
            },
        };
        if let Some(v6) = family {
            if !a.relays.iter().any(|r| r.relay.is_ipv6() == v6) {
                return Err(Reject(443, "Peer Address Family Mismatch"));
            }
        }
        if m.get_u32(attr::LIFETIME) == Some(0) {
            match family {
                Some(v6) => self.remove_family(client, v6, env),
                None => self.remove(client, env),
            }
            return Ok(self.base(m, Class::Success).u32(attr::LIFETIME, 0));
        }
        let life = self.lifetime(m);
        if let Some(a) = self.allocs.get_mut(&client) {
            for r in &mut a.relays {
                if family.is_none_or(|v6| r.relay.is_ipv6() == v6) {
                    r.expires = now + life;
                }
            }
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
        // Each peer needs a relayed address of its family (both, in a dual allocation).
        let Some(a) = self.allocs.get(&client) else {
            return Err(Reject(437, "Allocation Mismatch"));
        };
        if peers.iter().any(|p| !a.has_family(*p)) {
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
        if !self.allocs.get(&client).is_none_or(|a| a.has_family(peer)) {
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
        if a.tcp.is_some() {
            return Err(Reject(400, "Bad Request")); // no channels on a TCP allocation
        }
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

    // ---- TCP allocations (RFC 6062) ----

    /// A Connect request (RFC 6062 section 5.2): the connection is opened by the environment
    /// and the request answered by [`tcp_connected`](Self::tcp_connected).
    fn connect(
        &mut self,
        now: Instant,
        client: SocketAddr,
        m: &Message<'_>,
        env: &mut dyn TurnEnv,
    ) -> Result<(), Reject> {
        let max = self.shared.cfg.max_tcp_connections;
        let Some(a) = self.allocs.get(&client) else {
            return Err(Reject(437, "Allocation Mismatch"));
        };
        let Some(peer) = m.get_xor_addr(attr::XOR_PEER_ADDRESS) else {
            return Err(Reject(400, "Bad Request"));
        };
        if !a.has_family(peer) {
            return Err(Reject(443, "Peer Address Family Mismatch"));
        }
        if !self.peer_ok(peer) || peer.port() == 0 {
            return Err(Reject(403, "Forbidden"));
        }
        let id = self.shared.connection_id();
        let Some(a) = self.allocs.get_mut(&client) else {
            return Err(Reject(437, "Allocation Mismatch"));
        };
        let Some(relay) = a.relays.first().map(|r| r.relay) else {
            return Err(Reject(437, "Allocation Mismatch"));
        };
        let Some(tcp) = a.tcp.as_mut() else {
            return Err(Reject(400, "Bad Request")); // a UDP allocation
        };
        if tcp.by_peer.contains_key(&peer) {
            return Err(Reject(446, "Connection Already Exists"));
        }
        if tcp.conns.len() >= max {
            return Err(Reject(508, "Insufficient Capacity"));
        }
        let state = TcpState::Connecting(
            m.transaction_id(),
            m.has(attr::FINGERPRINT),
            now + self.shared.cfg.tcp_connect_timeout,
        );
        tcp.conns.insert(id, TcpConn { peer, state });
        tcp.by_peer.insert(peer, id);
        self.by_conn.insert(id, client);
        env.connect_peer(client, relay, peer, id);
        Ok(())
    }

    /// The outcome of [`TurnEnv::connect_peer`] for connection `id` of `client`'s allocation:
    /// the Connect is answered (with its `CONNECTION-ID`, or 447 Connection Timeout or
    /// Failure). Returns whether the connection is wanted: false when it failed, its
    /// allocation is gone or it was given up on; the environment then closes it.
    pub fn tcp_connected(
        &mut self,
        now: Instant,
        client: SocketAddr,
        id: u32,
        ok: bool,
        env: &mut dyn TurnEnv,
    ) -> bool {
        let Some(a) = self.allocs.get_mut(&client) else {
            return false;
        };
        let key = a.key;
        let alive = a.alive(now);
        let Some(tcp) = a.tcp.as_mut() else {
            return false;
        };
        let Some(c) = tcp.conns.get_mut(&id) else {
            return false;
        };
        let TcpState::Connecting(tid, fingerprint, _) = c.state else {
            return false;
        };
        let b = if ok && alive {
            c.state = TcpState::Pending(now + TCP_BIND_TIMEOUT);
            self.reply(Method::CONNECT, Class::Success, tid)
                .u32(attr::CONNECTION_ID, id)
        } else {
            let peer = c.peer;
            tcp.conns.remove(&id);
            tcp.by_peer.remove(&peer);
            self.by_conn.remove(&id);
            self.reply(Method::CONNECT, Class::Error, tid)
                .error(447, "Connection Timeout or Failure")
        };
        env.send_to_client(client, &Self::seal(b, &key, fingerprint));
        ok && self.by_conn.contains_key(&id)
    }

    /// A TCP connection from `peer` was accepted on the TCP relay bound at `relay` (RFC 6062
    /// section 5.3). With a permission for the peer's address (and room), it becomes a
    /// connection of the allocation: [`TurnEnv::accept_peer`] hears of it, then the client a
    /// ConnectionAttempt, and its id is returned. `None`: close it.
    pub fn tcp_incoming(
        &mut self,
        now: Instant,
        relay: SocketAddr,
        peer: SocketAddr,
        env: &mut dyn TurnEnv,
    ) -> Option<u32> {
        let client = *self.by_tcp_relay.get(&relay)?;
        let max = self.shared.cfg.max_tcp_connections;
        if !self.peer_ok(peer) {
            return None;
        }
        let id = self.shared.connection_id();
        let a = self.allocs.get_mut(&client)?;
        if !a.alive(now) || !a.perms.get(&peer.ip()).is_some_and(|&e| e > now) {
            return None;
        }
        let tcp = a.tcp.as_mut()?;
        if tcp.by_peer.contains_key(&peer) || tcp.conns.len() >= max {
            return None;
        }
        let state = TcpState::Pending(now + TCP_BIND_TIMEOUT);
        tcp.conns.insert(id, TcpConn { peer, state });
        tcp.by_peer.insert(peer, id);
        self.by_conn.insert(id, client);
        env.accept_peer(client, relay, peer, id);
        let ind = MessageBuilder::new(
            Method::CONNECTION_ATTEMPT,
            Class::Indication,
            crate::stun::transaction_id(),
        )
        .xor_addr(attr::XOR_PEER_ADDRESS, peer)
        .u32(attr::CONNECTION_ID, id)
        .build();
        env.send_to_client(client, &ind);
        Some(id)
    }

    /// Connection `id` of `client`'s allocation closed (the peer's connection or the client's
    /// data connection ended): it is forgotten, and [`TurnEnv::close_connection`] closes the
    /// other side.
    pub fn tcp_closed(&mut self, client: SocketAddr, id: u32, env: &mut dyn TurnEnv) {
        if self.by_conn.get(&id) != Some(&client) {
            return;
        }
        self.by_conn.remove(&id);
        if let Some(tcp) = self.allocs.get_mut(&client).and_then(|a| a.tcp.as_mut()) {
            if let Some(c) = tcp.conns.remove(&id) {
                tcp.by_peer.remove(&c.peer);
            }
        }
        env.close_connection(id);
    }

    /// A ConnectionBind request from the stream client at `data_client` (RFC 6062 section
    /// 5.4): the response for that connection, and the connection id when it is now bound.
    /// `alloc` names the client whose allocation holds the id, when the caller knows (the
    /// sharded server looks it up across shards); else this core's own allocations are
    /// searched. `stream`: the request came over TCP or TLS (else 400). The nonce may be one
    /// issued to the data connection or to the allocation's control connection (clients reuse
    /// the latter). `None`: not answered (not a ConnectionBind request, or a bad
    /// `FINGERPRINT`).
    pub(crate) fn connection_bind(
        &mut self,
        now: Instant,
        data_client: SocketAddr,
        m: &Message<'_>,
        alloc: Option<SocketAddr>,
        stream: bool,
    ) -> Option<(Vec<u8>, Option<u32>)> {
        if m.class() != Class::Request || m.method() != Method::CONNECTION_BIND {
            return None;
        }
        if m.has(attr::FINGERPRINT) && !m.check_fingerprint() {
            return None;
        }
        if !stream {
            return Some((self.error(m, &Reject(400, "Bad Request"), None), None));
        }
        if !m.has(attr::MESSAGE_INTEGRITY) {
            return Some((
                self.challenge(now, data_client, m, 401, "Unauthorized"),
                None,
            ));
        }
        let (Some(user), Some(realm), Some(nonce)) = (
            m.get_str(attr::USERNAME),
            m.get_str(attr::REALM),
            m.get_str(attr::NONCE),
        ) else {
            return Some((self.error(m, &Reject(400, "Bad Request"), None), None));
        };
        let id = m
            .get(attr::CONNECTION_ID)
            .and_then(|v| <[u8; 4]>::try_from(v).ok())
            .map(u32::from_be_bytes);
        let owner = alloc.or_else(|| id.and_then(|id| self.by_conn.get(&id).copied()));
        if !self.nonce_valid(now, data_client, nonce)
            && !owner.is_some_and(|o| self.nonce_valid(now, o, nonce))
        {
            return Some((
                self.challenge(now, data_client, m, 438, "Stale Nonce"),
                None,
            ));
        }
        let key = (self.shared.cfg.auth)(user, realm);
        let Some(key) = key.filter(|k| realm == self.shared.cfg.realm && m.check_integrity(k))
        else {
            return Some((
                self.challenge(now, data_client, m, 401, "Unauthorized"),
                None,
            ));
        };
        let bad =
            |core: &Self| Some((core.error(m, &Reject(400, "Bad Request"), Some(&key)), None));
        let (Some(id), Some(owner)) = (id, owner) else {
            return bad(self);
        };
        // A data connection is a new one: never a control connection (it would lose its
        // allocation's client).
        if self.allocs.contains_key(&data_client) {
            return bad(self);
        }
        if self.by_conn.get(&id) != Some(&owner) {
            return bad(self);
        }
        let Some(a) = self.allocs.get_mut(&owner) else {
            return bad(self);
        };
        if a.user != user || !a.alive(now) {
            return bad(self);
        }
        let Some(c) = a.tcp.as_mut().and_then(|t| t.conns.get_mut(&id)) else {
            return bad(self);
        };
        if !matches!(c.state, TcpState::Pending(_)) {
            return bad(self);
        }
        c.state = TcpState::Bound;
        let out = Self::finish(self.base(m, Class::Success), m, Some(&key));
        Some((out, Some(id)))
    }

    /// Connections past their deadline: waiting for a ConnectionBind too long (closed), or a
    /// Connect the environment never answered (447).
    fn tcp_timeouts(&mut self, now: Instant, env: &mut dyn TurnEnv) {
        let mut late: Vec<(SocketAddr, u32)> = Vec::new();
        for (client, a) in &self.allocs {
            let Some(tcp) = &a.tcp else { continue };
            for (id, c) in &tcp.conns {
                if matches!(c.state, TcpState::Pending(t) | TcpState::Connecting(_, _, t) if t <= now)
                {
                    late.push((*client, *id));
                }
            }
        }
        for (client, id) in late {
            let connecting = self
                .allocs
                .get(&client)
                .and_then(|a| a.tcp.as_ref())
                .and_then(|t| t.conns.get(&id))
                .is_some_and(|c| matches!(c.state, TcpState::Connecting(..)));
            if connecting {
                self.tcp_connected(now, client, id, false, env);
                env.close_connection(id);
            } else {
                self.tcp_closed(client, id, env);
            }
        }
    }

    /// A message of `method` and `class` answering transaction `tid` (`SOFTWARE` added).
    fn reply(&self, method: Method, class: Class, tid: [u8; 12]) -> MessageBuilder {
        let mut b = MessageBuilder::new(method, class, tid);
        if let Some(s) = &self.shared.cfg.software {
            b = b.attr(attr::SOFTWARE, s.as_bytes());
        }
        b
    }

    /// Integrity with `key`, and a `FINGERPRINT` if the request had one.
    fn seal(b: MessageBuilder, key: &[u8; 16], fingerprint: bool) -> Vec<u8> {
        let b = b.integrity(key);
        if fingerprint {
            b.fingerprint().build()
        } else {
            b.build()
        }
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
        sh.next_conn = AtomicU32::new(1);
        self.shared = Arc::new(sh);
    }

    #[cfg(test)]
    pub(crate) fn fuzz_nonce(&self, now: Instant, client: SocketAddr) -> String {
        self.nonce(now, client)
    }
}

/// Comprehension-required attributes this server does not understand, encoded for
/// `UNKNOWN-ATTRIBUTES`.
/// The reason phrase of an `ADDRESS-ERROR-CODE` (RFC 8656 section 19).
fn reason(code: u16) -> &'static str {
    match code {
        440 => "Address Family not Supported",
        _ => "Insufficient Capacity",
    }
}

fn unknown_required(m: &Message<'_>, df_known: bool) -> Option<Vec<u8>> {
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
        attr::CONNECTION_ID,
    ];
    let unknown: Vec<u8> = m
        .attr_types()
        .filter(|t| {
            let known = KNOWN.contains(t) && (*t != attr::DONT_FRAGMENT || df_known);
            *t < 0x8000 && !known
        })
        .flat_map(u16::to_be_bytes)
        .collect();
    (!unknown.is_empty()).then_some(unknown)
}

#[cfg(test)]
mod tests_dual;

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
        assert!(
            !sh.prebind_ips(now, CLIENT, &allocate(&core, now, USER.1, None))
                .is_empty()
        );
        assert!(
            sh.prebind_ips(now, CLIENT, &allocate(&core, now, "nope", None))
                .is_empty()
        );
        let forged = "0".repeat(32);
        assert!(
            sh.prebind_ips(now, CLIENT, &allocate(&core, now, USER.1, Some(&forged)))
                .is_empty()
        );
        // A nonce issued to another address.
        let other: SocketAddr = "10.9.9.9:1".parse().unwrap();
        assert!(
            sh.prebind_ips(now, other, &allocate(&core, now, USER.1, None))
                .is_empty()
        );
        // Expired nonce.
        let later = now + Duration::from_secs(3600);
        assert!(
            sh.prebind_ips(later, CLIENT, &allocate(&core, now, USER.1, None))
                .is_empty()
        );
        // Not an Allocate.
        let b = MessageBuilder::new(Method::REFRESH, Class::Request, transaction_id()).build();
        assert!(sh.prebind_ips(now, CLIENT, &b).is_empty());
        assert!(sh.prebind_ips(now, CLIENT, b"\x40\x00\x00\x00").is_empty());
    }

    /// What the TCP side of the core asks of its environment.
    #[derive(Default)]
    struct TcpEnv {
        sent: Vec<(SocketAddr, Vec<u8>)>,
        dials: Vec<(SocketAddr, SocketAddr, u32)>,
        accepted: Vec<u32>,
        closed: Vec<u32>,
        relays: Vec<SocketAddr>,
        bound: Vec<(SocketAddr, u32)>,
    }

    impl TurnEnv for TcpEnv {
        fn send_to_client(&mut self, client: SocketAddr, data: &[u8]) {
            self.sent.push((client, data.to_vec()));
        }
        fn send_to_peer(&mut self, _: SocketAddr, _: SocketAddr, _: &[u8]) {}
        fn open_relay(&mut self, _: SocketAddr, _: SocketAddr) -> io::Result<SocketAddr> {
            Err(io::Error::other("udp"))
        }
        fn close_relay(&mut self, _: SocketAddr) {}
        fn pads_channel_data(&self, _: SocketAddr) -> bool {
            true
        }
        fn sets_dont_fragment(&self) -> bool {
            true
        }
        fn open_tcp_relay(&mut self, _: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
            let r = SocketAddr::new(addr.ip(), 40000 + self.relays.len() as u16);
            self.relays.push(r);
            Ok(r)
        }
        fn close_tcp_relay(&mut self, relay: SocketAddr) {
            self.relays.retain(|r| *r != relay);
        }
        fn connect_peer(&mut self, _: SocketAddr, relay: SocketAddr, peer: SocketAddr, id: u32) {
            self.dials.push((relay, peer, id));
        }
        fn accept_peer(&mut self, _: SocketAddr, _: SocketAddr, _: SocketAddr, id: u32) {
            self.accepted.push(id);
        }
        fn connection_bound(&mut self, data_client: SocketAddr, id: u32) {
            self.bound.push((data_client, id));
        }
        fn close_connection(&mut self, id: u32) {
            self.closed.push(id);
        }
    }

    impl TcpEnv {
        /// The last message sent, parsed: method, class, error code, CONNECTION-ID.
        fn last(&self) -> (Method, Class, Option<u16>, Option<u32>) {
            let m = Message::parse(&self.sent.last().expect("sent").1).expect("stun");
            let id = m.get_u32(attr::CONNECTION_ID);
            (m.method(), m.class(), m.error_code().map(|e| e.0), id)
        }
    }

    fn authed(core: &TurnCore, now: Instant, from: SocketAddr, b: MessageBuilder) -> Vec<u8> {
        b.attr(attr::USERNAME, USER.0.as_bytes())
            .attr(attr::REALM, REALM.as_bytes())
            .attr(attr::NONCE, core.fuzz_nonce(now, from).as_bytes())
            .integrity(&long_term_key(USER.0, REALM, USER.1))
            .fingerprint()
            .build()
    }

    fn req(m: Method) -> MessageBuilder {
        MessageBuilder::new(m, Class::Request, transaction_id())
    }

    fn tcp_allocated(now: Instant) -> (TurnCore, TcpEnv, SocketAddr) {
        let mut core = turn_core(now);
        let mut env = TcpEnv::default();
        let a = authed(
            &core,
            now,
            CLIENT,
            req(Method::ALLOCATE).u32(attr::REQUESTED_TRANSPORT, 6 << 24),
        );
        core.handle_client(now, CLIENT, &a, &mut env);
        assert_eq!(env.last().1, Class::Success);
        let relay = env.relays[0];
        assert_eq!(core.by_tcp_relay.get(&relay), Some(&CLIENT));
        (core, env, relay)
    }

    /// Connect: answered when the environment reports; one connection per peer; 447 on
    /// failure; the ConnectionBind deadline closes connections nobody binds.
    #[test]
    fn tcp_connect_lifecycle() {
        let now = Instant::now();
        let (mut core, mut env, relay) = tcp_allocated(now);
        let peer: SocketAddr = "10.1.1.1:80".parse().unwrap();
        let c = authed(
            &core,
            now,
            CLIENT,
            req(Method::CONNECT).xor_addr(attr::XOR_PEER_ADDRESS, peer),
        );
        let n = env.sent.len();
        core.handle_client(now, CLIENT, &c, &mut env);
        assert_eq!(env.sent.len(), n, "answered only once connected");
        let (r, p, id) = env.dials[0];
        assert_eq!((r, p), (relay, peer));
        // The same peer again while connecting: 446.
        core.handle_client(now, CLIENT, &c, &mut env);
        assert_eq!(env.last().2, Some(446));
        assert!(core.tcp_connected(now, CLIENT, id, true, &mut env));
        assert_eq!(
            env.last(),
            (Method::CONNECT, Class::Success, None, Some(id))
        );
        assert!(
            !core.tcp_connected(now, CLIENT, id, true, &mut env),
            "answered once"
        );
        assert_eq!(core.stats().tcp_connections, 1);
        // Nobody binds it: closed after 30 s.
        core.handle_timeout(now + Duration::from_secs(29), &mut env);
        assert!(env.closed.is_empty());
        core.handle_timeout(now + TCP_BIND_TIMEOUT, &mut env);
        assert_eq!(env.closed, vec![id]);
        assert_eq!(core.stats().tcp_connections, 0);
        // A failed connect: 447, and the peer is free again.
        let c = authed(
            &core,
            now,
            CLIENT,
            req(Method::CONNECT).xor_addr(attr::XOR_PEER_ADDRESS, peer),
        );
        core.handle_client(now, CLIENT, &c, &mut env);
        let id2 = env.dials[1].2;
        assert_ne!(id2, id);
        assert!(!core.tcp_connected(now, CLIENT, id2, false, &mut env));
        assert_eq!(env.last().2, Some(447));
        // A connect the environment never reports on: 447 at `tcp_connect_timeout`, not before.
        core.handle_client(now, CLIENT, &c, &mut env);
        let id3 = env.dials[2].2;
        let t = core.config().tcp_connect_timeout;
        assert_eq!(t, Duration::from_secs(30));
        core.handle_timeout(now + Duration::from_millis(29_999), &mut env);
        assert!(!env.closed.contains(&id3));
        core.handle_timeout(now + t, &mut env);
        assert_eq!(env.last().2, Some(447));
        assert!(env.closed.contains(&id3));
        assert_eq!(core.stats().tcp_connections, 0);
        // Port 0 is 403; a ChannelBind on a TCP allocation is 400.
        let zero: SocketAddr = "10.1.1.1:0".parse().unwrap();
        let c = authed(
            &core,
            now,
            CLIENT,
            req(Method::CONNECT).xor_addr(attr::XOR_PEER_ADDRESS, zero),
        );
        core.handle_client(now, CLIENT, &c, &mut env);
        assert_eq!(env.last().2, Some(403));
        let cb = authed(
            &core,
            now,
            CLIENT,
            req(Method::CHANNEL_BIND)
                .u32(attr::CHANNEL_NUMBER, 0x4000 << 16)
                .xor_addr(attr::XOR_PEER_ADDRESS, peer),
        );
        core.handle_client(now, CLIENT, &cb, &mut env);
        assert_eq!(env.last().2, Some(400));
        // Deleting the allocation closes the listener.
        let r0 = authed(
            &core,
            now,
            CLIENT,
            req(Method::REFRESH).u32(attr::LIFETIME, 0),
        );
        core.handle_client(now, CLIENT, &r0, &mut env);
        assert!(env.relays.is_empty());
    }

    /// Peers connecting to the relayed address need a permission; each gets a
    /// ConnectionAttempt; the connection limit holds; ConnectionBind takes the control
    /// connection's nonce or one of its own, and only the allocation's user.
    #[test]
    fn tcp_incoming_and_bind() {
        let now = Instant::now();
        let (mut core, mut env, relay) = tcp_allocated(now);
        let peer: SocketAddr = "10.1.1.2:5555".parse().unwrap();
        assert_eq!(core.tcp_incoming(now, relay, peer, &mut env), None);
        let other: SocketAddr = "192.0.2.99:1".parse().unwrap();
        assert_eq!(
            core.tcp_incoming(now, other, peer, &mut env),
            None,
            "not a relay"
        );
        let cp = authed(
            &core,
            now,
            CLIENT,
            req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, peer),
        );
        core.handle_client(now, CLIENT, &cp, &mut env);
        let id = core.tcp_incoming(now, relay, peer, &mut env).unwrap();
        assert_eq!(env.accepted, vec![id]);
        let (m, c, _, cid) = env.last();
        assert_eq!(
            (m, c, cid),
            (Method::CONNECTION_ATTEMPT, Class::Indication, Some(id))
        );
        // One connection per peer address; another port of the same host is fine.
        assert_eq!(core.tcp_incoming(now, relay, peer, &mut env), None);
        let peer2: SocketAddr = "10.1.1.2:5556".parse().unwrap();
        let id2 = core.tcp_incoming(now, relay, peer2, &mut env).unwrap();
        // ConnectionBind from a new connection, with the control connection's nonce.
        let data: SocketAddr = "10.0.0.1:4001".parse().unwrap();
        let bind = |core: &TurnCore, from, id: u32| {
            authed(
                core,
                now,
                from,
                req(Method::CONNECTION_BIND).u32(attr::CONNECTION_ID, id),
            )
        };
        let b = bind(&core, CLIENT, id);
        core.handle_client(now, data, &b, &mut env);
        assert_eq!(env.last().1, Class::Success);
        assert_eq!(env.bound, vec![(data, id)]);
        // Not on the control connection itself.
        let id9 = core.tcp_incoming(now, relay, "10.1.1.2:5559".parse().unwrap(), &mut env);
        let b = bind(&core, CLIENT, id9.unwrap());
        core.handle_client(now, CLIENT, &b, &mut env);
        assert_eq!(env.last().2, Some(400));
        core.tcp_closed(CLIENT, id9.unwrap(), &mut env);
        // Bound already: 400. A nonce of its own works too.
        let b = bind(&core, data, id);
        core.handle_client(now, data, &b, &mut env);
        assert_eq!(env.last().2, Some(400));
        let data2: SocketAddr = "10.0.0.1:4002".parse().unwrap();
        let b = bind(&core, data2, id2);
        core.handle_client(now, data2, &b, &mut env);
        assert_eq!(env.last().1, Class::Success);
        // A nonce of a third address: 438; none at all: 401; unknown id: 400.
        let b = bind(&core, "10.0.0.9:1".parse().unwrap(), id2);
        core.handle_client(now, data2, &b, &mut env);
        assert_eq!(env.last().2, Some(438));
        let b = req(Method::CONNECTION_BIND)
            .u32(attr::CONNECTION_ID, id2)
            .build();
        core.handle_client(now, data2, &b, &mut env);
        assert_eq!(env.last().2, Some(401));
        // An unknown id cannot vouch for the control connection's nonce (438); with a nonce
        // of its own, 400.
        let b = bind(&core, CLIENT, id ^ 1);
        core.handle_client(now, data2, &b, &mut env);
        assert_eq!(env.last().2, Some(438));
        let b = bind(&core, data2, id ^ 1);
        core.handle_client(now, data2, &b, &mut env);
        assert_eq!(env.last().2, Some(400));
        // Another user with valid credentials cannot take it.
        let mut cfg = core.shared.cfg.clone();
        cfg.auth = crate::static_auth(REALM, [USER, ("v", "w")]);
        let mut sh = Shared::new(cfg);
        sh.nonce_key = core.shared.nonce_key;
        sh.epoch = core.shared.epoch;
        core.shared = Arc::new(sh);
        let peer3: SocketAddr = "10.1.1.2:5557".parse().unwrap();
        let id3 = core.tcp_incoming(now, relay, peer3, &mut env).unwrap();
        let b = req(Method::CONNECTION_BIND)
            .u32(attr::CONNECTION_ID, id3)
            .attr(attr::USERNAME, b"v")
            .attr(attr::REALM, REALM.as_bytes())
            .attr(attr::NONCE, core.fuzz_nonce(now, CLIENT).as_bytes())
            .integrity(&long_term_key("v", REALM, "w"))
            .build();
        core.handle_client(now, data2, &b, &mut env);
        assert_eq!(env.last().2, Some(400));
        assert_eq!(core.stats().tcp_connections, 3);
        // A closed connection is forgotten (and its other side closed).
        core.tcp_closed(CLIENT, id, &mut env);
        assert!(env.closed.contains(&id));
        assert_eq!(core.stats().tcp_connections, 2);
        // The connection limit.
        let mut cfg = core.shared.cfg.clone();
        cfg.max_tcp_connections = 2;
        let mut sh = Shared::new(cfg);
        sh.nonce_key = core.shared.nonce_key;
        sh.epoch = core.shared.epoch;
        core.shared = Arc::new(sh);
        assert_eq!(
            core.tcp_incoming(now, relay, "10.1.1.2:1".parse().unwrap(), &mut env),
            None
        );
        // The allocation going closes everything.
        core.remove_client(CLIENT, &mut env);
        assert!(env.closed.contains(&id2) && env.closed.contains(&id3));
        assert_eq!(core.stats().tcp_connections, 0);
        assert!(env.relays.is_empty());
        // No permission expiry race: an expired permission refuses peers again.
        let (mut core, mut env, relay) = tcp_allocated(now);
        let cp = authed(
            &core,
            now,
            CLIENT,
            req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, peer),
        );
        core.handle_client(now, CLIENT, &cp, &mut env);
        let later = now + Duration::from_secs(301);
        assert_eq!(core.tcp_incoming(later, relay, peer, &mut env), None);
    }

    /// TCP allocations need a stream client, no UDP-only attributes, and the setting.
    #[test]
    fn tcp_allocate_rules() {
        struct Udp(TcpEnv);
        impl TurnEnv for Udp {
            fn send_to_client(&mut self, c: SocketAddr, d: &[u8]) {
                self.0.send_to_client(c, d);
            }
            fn send_to_peer(&mut self, _: SocketAddr, _: SocketAddr, _: &[u8]) {}
            fn open_relay(&mut self, _: SocketAddr, a: SocketAddr) -> io::Result<SocketAddr> {
                Ok(a)
            }
            fn close_relay(&mut self, _: SocketAddr) {}
        }
        let now = Instant::now();
        let mut core = turn_core(now);
        let tcp = || req(Method::ALLOCATE).u32(attr::REQUESTED_TRANSPORT, 6 << 24);
        let mut udp = Udp(TcpEnv::default());
        core.handle_client(now, CLIENT, &authed(&core, now, CLIENT, tcp()), &mut udp);
        assert_eq!(udp.0.last().2, Some(400));
        let mut env = TcpEnv::default();
        for extra in [
            attr::EVEN_PORT,
            attr::RESERVATION_TOKEN,
            attr::DONT_FRAGMENT,
        ] {
            let a = authed(&core, now, CLIENT, tcp().attr(extra, &[0; 8]));
            core.handle_client(now, CLIENT, &a, &mut env);
            assert_eq!(env.last().2, Some(400), "{extra:#x}");
        }
        let a = authed(
            &core,
            now,
            CLIENT,
            tcp().attr(attr::REQUESTED_ADDRESS_FAMILY, &[3, 0, 0, 0]),
        );
        core.handle_client(now, CLIENT, &a, &mut env);
        assert_eq!(env.last().2, Some(440)); // no such family
        // An environment without TCP support: 442, and the quota is given back.
        struct NoTcp(TcpEnv);
        impl TurnEnv for NoTcp {
            fn send_to_client(&mut self, c: SocketAddr, d: &[u8]) {
                self.0.send_to_client(c, d);
            }
            fn send_to_peer(&mut self, _: SocketAddr, _: SocketAddr, _: &[u8]) {}
            fn open_relay(&mut self, _: SocketAddr, a: SocketAddr) -> io::Result<SocketAddr> {
                Ok(a)
            }
            fn close_relay(&mut self, _: SocketAddr) {}
            fn pads_channel_data(&self, _: SocketAddr) -> bool {
                true
            }
        }
        let mut no = NoTcp(TcpEnv::default());
        core.handle_client(now, CLIENT, &authed(&core, now, CLIENT, tcp()), &mut no);
        assert_eq!(no.0.last().2, Some(442));
        assert_eq!(core.shared.allocations.load(Ordering::Relaxed), 0);
        // The setting off: 442.
        let mut cfg = core.shared.cfg.clone();
        cfg.tcp_relays = false;
        let mut sh = Shared::new(cfg);
        sh.nonce_key = core.shared.nonce_key;
        sh.epoch = core.shared.epoch;
        core.shared = Arc::new(sh);
        core.handle_client(now, CLIENT, &authed(&core, now, CLIENT, tcp()), &mut env);
        assert_eq!(env.last().2, Some(442));
        // Connect on no allocation: 437; on a UDP allocation: 400.
        let peer: SocketAddr = "10.1.1.1:80".parse().unwrap();
        let c = authed(
            &core,
            now,
            CLIENT,
            req(Method::CONNECT).xor_addr(attr::XOR_PEER_ADDRESS, peer),
        );
        core.handle_client(now, CLIENT, &c, &mut env);
        assert_eq!(env.last().2, Some(437));
        let mut udp = Udp(TcpEnv::default());
        let a = authed(
            &core,
            now,
            CLIENT,
            req(Method::ALLOCATE).u32(attr::REQUESTED_TRANSPORT, 17 << 24),
        );
        core.handle_client(now, CLIENT, &a, &mut udp);
        assert_eq!(udp.0.last().1, Class::Success);
        core.handle_client(now, CLIENT, &c, &mut udp);
        assert_eq!(udp.0.last().2, Some(400));
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
