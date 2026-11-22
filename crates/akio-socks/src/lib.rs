#![forbid(unsafe_code)]
//! Proxies on `akio`: a SOCKS5 / SOCKS4 / SOCKS4a server ([`Socks`]) and an HTTP `CONNECT`
//! proxy ([`connect_proxy`]), both relaying callback to callback with backpressure in both
//! directions: when one side cannot keep up, reading from the other pauses until it drains;
//! and a SOCKS client ([`SocksClient`]).
//!
//! Server: SOCKS5 `CONNECT`, `BIND` and `UDP ASSOCIATE` (RFC 1928; the last two opt-in,
//! [`Socks::bind`], [`Socks::udp_associate`]) with no authentication or username/password
//! (RFC 1929), IPv4, IPv6 and domain names (resolved on the logical pool), UDP fragments
//! reassembled; SOCKS4 and 4a `CONNECT` and `BIND`; HTTP `CONNECT host:port`; an
//! access-control hook over every request ([`Socks::allow`]).
//!
//! Client ([`SocksClient`], ADR-019): SOCKS5 `CONNECT`, `BIND` and `UDP ASSOCIATE`, SOCKS4 and
//! 4a `CONNECT` and `BIND`, on the engine or blocking. The HTTP and WebSocket clients take SOCKS
//! proxies through `akio_ws::proxy::Proxy` (`socks5h://…`) with the same handshake.
//!
//! GSS-API authentication (RFC 1961, method 1; ADR-071), server and client, with the
//! per-message protection levels (integrity, confidentiality) or none: the GSS-API mechanism
//! (Kerberos through the system library, SSPI, ...) is the application's, behind the
//! [`gssapi::GssContext`] trait. With protection, `UDP ASSOCIATE` datagrams are wrapped too
//! (RFC 1961 §5, with the control connection's context), on both sides; the client's blocking
//! `CONNECT` / `BIND` helpers need level none.
//!
//! Linux fast path (opt-in, [`ProxyConfig::sockmap`]): `CONNECT` tunnels (SOCKS and HTTP) are
//! spliced in the kernel with `akio::ebpf::Relay` once the upstream is connected, so their bytes
//! no longer pass through userspace; wherever that is unavailable or unsafe the tunnel relays
//! in userspace as usual.
//!
//! Safe defaults ([`ProxyConfig`]): a handshake must complete (upstream connected) within 10 s,
//! a tunnel with no byte in either direction for 5 minutes is closed, at most 256 KiB of early
//! data is held while the upstream connects, and only public destinations are dialled
//! ([`Destinations::PublicOnly`]): a proxy reachable by others must not become a way into the
//! loopback, link-local (cloud metadata) or private networks behind it.
//!
//! Guide: [SOCKS and HTTP CONNECT proxies](https://lesismal.github.io/akio/en/protocols/socks.html)
//! (中文: [SOCKS 与 HTTP CONNECT 代理](https://lesismal.github.io/akio/zh-CN/protocols/socks.html)).
#![warn(clippy::unwrap_used)]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

mod guard;
use guard::Watch;
pub mod gssapi;
mod splice;
use splice::SpliceCtl;
pub use splice::spliced_tunnels;

use akio::{Acceptor, Conn, EngineRef, Handler};
use akio_core::ConnInner;
use akio_http::{
    Context, Method, Response, Service,
    raw::{RawConn, RawHandler},
};

/// Largest handshake (greeting, authentication or request) buffered before the client is cut
/// off. The largest valid SOCKS5 message is 513 bytes; SOCKS4's user id and 4a's host name are
/// NUL-terminated, so without a bound a client could make the buffer grow forever.
const MAX_HANDSHAKE: usize = 4096;

/// The same while GSS-API tokens are exchanged: one message (64 KiB token) and a little.
const MAX_GSS_HANDSHAKE: usize = 4 + 65_535 + 4096;

/// Queue size on the outgoing side above which reading from the incoming side pauses; also the
/// most early data (sent before the upstream is connected) held for the upstream.
const HIGH_WATER: usize = 256 << 10;

/// Default [`ProxyConfig::handshake_timeout`].
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default [`ProxyConfig::idle_timeout`].
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Which upstream addresses a proxy may dial. Checked on every address, after name resolution
/// (a host name that resolves to a denied address is denied too).
#[derive(Clone, Default)]
#[non_exhaustive]
pub enum Destinations {
    /// Only globally routable unicast addresses: loopback, private (RFC 1918, IPv6 ULA),
    /// carrier-grade NAT, link-local (including the `169.254.169.254` cloud metadata service),
    /// unspecified, multicast, broadcast, documentation and other reserved ranges are denied,
    /// as are IPv4-mapped, 6to4 and NAT64 IPv6 forms of them. The default.
    #[default]
    PublicOnly,
    /// Any address. Use it for a proxy that exists to reach a private network (a bastion), and
    /// restrict who may use it ([`Socks::auth`], a listener bound to a trusted interface).
    Any,
    /// Your own rule: `true` allows the address.
    Custom(Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>),
}

impl std::fmt::Debug for Destinations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Destinations::PublicOnly => f.write_str("PublicOnly"),
            Destinations::Any => f.write_str("Any"),
            Destinations::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

impl Destinations {
    /// Whether a proxy may dial `addr`.
    pub fn allows(&self, addr: SocketAddr) -> bool {
        match self {
            Destinations::PublicOnly => is_public(addr.ip()),
            Destinations::Any => true,
            Destinations::Custom(f) => f(addr),
        }
    }
}

/// Whether `ip` is a globally routable unicast address ([`Destinations::PublicOnly`]).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            // NAT64 well-known prefix 64:ff9b::/96 embeds the IPv4 address in the last 32 bits.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return is_public_v4(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])));
            }
            // 6to4 2002::/16 embeds it in bits 16..48.
            if s[0] == 0x2002 {
                return is_public_v4(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])));
            }
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || s[..6] == [0; 6] // IPv4-compatible (deprecated) and ::/96
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // site-local fec0::/10 (deprecated)
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0100 && s[1..4] == [0; 3])) // discard-only 100::/64
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(o[0] == 0 // "this network", unspecified
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // carrier-grade NAT 100.64/10
        || (o[0] == 169 && o[1] == 254) // link-local, cloud metadata
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // documentation
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18/15
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224) // multicast, reserved, broadcast
}

/// Limits and policy of a proxy ([`Socks::config`], [`connect_proxy_with`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// Longest time from accepting the client until its upstream is connected (SOCKS greeting,
    /// authentication, request, name resolution and connect; for `CONNECT`, resolution and
    /// connect). Past it the client is closed. Default 10 s; `None` disables it.
    pub handshake_timeout: Option<Duration>,
    /// A tunnel that moved no byte in either direction for this long is closed (both ends).
    /// Default 5 minutes; `None` disables it. Stalled readers are also bounded by the engine's
    /// `Config::write_timeout`.
    pub idle_timeout: Option<Duration>,
    /// Which addresses may be dialled. Default [`Destinations::PublicOnly`].
    pub destinations: Destinations,
    /// Splice `CONNECT` tunnels in the kernel with this sockmap relay (Linux, privileged, 6.15+
    /// by default; see `akio::ebpf::Relay::new`). Default `None`: userspace relaying. A tunnel
    /// is spliced right after its upstream connects, as its success reply is written, unless
    /// the client already sent data behind its request, the client connection has TLS, or
    /// splicing fails; those relay in userspace. Spliced bytes bypass the engine's write
    /// watermarks; the idle timeout and closing keep working (from the sockets' TCP counters).
    pub sockmap: Option<akio::ebpf::Relay>,
}

impl Default for ProxyConfig {
    fn default() -> ProxyConfig {
        ProxyConfig {
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            destinations: Destinations::PublicOnly,
            sockmap: None,
        }
    }
}

/// Forwards `data` read from `from` to `to`, pausing `from` while `to` is backed up.
///
/// Both ends are [relayed](ConnInner::set_relayed): this pacing replaces the engine's own write
/// backpressure, which would stop reading the upstream while it has client data queued for it.
/// An upstream that only reads once its writes go through (an echo server) then waits on us
/// while we wait on it, and the tunnel hangs.
fn forward(from: &Arc<ConnInner>, to: &Arc<ConnInner>, data: &[u8]) {
    if to.send(data).is_err() {
        from.close_after_send();
        return;
    }
    if to.queued_bytes() > HIGH_WATER {
        from.hold_reads(true);
        let from = from.clone();
        to.on_drain(Box::new(move || from.hold_reads(false)));
    }
}

/// How long a spliced side may make no forwarding progress after the other closed.
fn stall(cfg: &ProxyConfig) -> Duration {
    cfg.idle_timeout.unwrap_or(DEFAULT_IDLE_TIMEOUT)
}

/// Payload read in userspace from a side of a spliced tunnel (`from`; `to` is the other side):
/// `true` when it must not be forwarded. While both sides are open it can only be bytes read
/// before the splice took over (an io_uring read completing late), which the kernel may already
/// have overtaken: the tunnel is closed rather than reordered. Once `to` closed, the kernel
/// passes `from`'s data to userspace, where it has nowhere to go.
fn spliced_payload(splice: Option<&SpliceCtl>, from: &Arc<ConnInner>, to: &Arc<ConnInner>) -> bool {
    if !splice.is_some_and(SpliceCtl::is_spliced) {
        return false;
    }
    if to.is_open() {
        from.close();
        to.close();
    }
    true
}

/// Sends the success `reply` to the client, splicing the tunnel first if the fast path is on
/// and safe (its idle timeout then follows the sockets' counters, as no byte reaches the
/// handlers any more).
fn reply_and_splice(
    splice: Option<&SpliceCtl>,
    watch: Option<&Watch>,
    client: &Arc<ConnInner>,
    up: &Arc<ConnInner>,
    reply: &[u8],
) {
    let written = splice.map_or(0, |s| s.try_splice(client, up, reply));
    if written == reply.len() {
        if let Some(w) = watch {
            let (c, u) = (client.clone(), up.clone());
            w.set_probe(Box::new(move || SpliceCtl::activity(&c, &u)));
        }
    } else {
        let _ = client.send(&reply[written..]);
    }
}

/// The far side of a tunnel: its data goes back to the client.
type UpstreamSlot = Arc<Mutex<Option<Arc<ConnInner>>>>;

struct Upstream {
    client: Arc<ConnInner>,
    watch: Option<Arc<Watch>>,
    splice: Option<Arc<SpliceCtl>>,
    stall: Duration,
}

impl Handler for Upstream {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if spliced_payload(self.splice.as_deref(), c.inner(), &self.client) {
            return;
        }
        if let Some(w) = &self.watch {
            w.touch();
        }
        forward(c.inner(), &self.client, data);
    }
    fn on_close(&mut self, c: &Conn<Self>, _err: Option<akio::Error>) {
        match &self.splice {
            Some(s) if s.is_spliced() => {
                s.close_after_forward(c.inner(), false, self.client.clone(), self.stall);
            }
            _ => self.client.close_after_send(),
        }
    }
}

/// Runs when the upstream connection is established (on its I/O thread).
type OnUp = Box<dyn FnOnce(&Arc<ConnInner>) + Send>;

struct UpstreamAcceptor {
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    on_up: Arc<Mutex<Option<OnUp>>>,
    watch: Option<Arc<Watch>>,
    splice: Option<Arc<SpliceCtl>>,
    stall: Duration,
}

impl Acceptor for UpstreamAcceptor {
    type Handler = Upstream;
    fn on_open(&self, c: &Conn<Upstream>) -> Upstream {
        c.inner().set_relayed(true);
        *self.slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(c.inner().clone());
        let taken = self.on_up.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(w) = &self.watch {
            w.established();
        }
        if let Some(f) = taken {
            f(c.inner());
        }
        Upstream {
            client: self.client.clone(),
            watch: self.watch.clone(),
            splice: self.splice.clone(),
            stall: self.stall,
        }
    }
}

type OnFail = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// What one session needs to dial its upstream.
#[derive(Clone)]
struct DialCtx {
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    watch: Option<Arc<Watch>>,
    splice: Option<Arc<SpliceCtl>>,
    /// How long a spliced side may make no progress forwarding before it is closed anyway.
    stall: Duration,
}

/// Dials the addresses in order for `client`; `on_up` runs on the first that connects,
/// `on_fail` when none does.
fn dial(
    engine: &EngineRef,
    addrs: Vec<SocketAddr>,
    ctx: DialCtx,
    on_up: OnUp,
    on_fail: Box<dyn FnOnce() + Send>,
) {
    let up = Arc::new(Mutex::new(Some(on_up)));
    let fail: OnFail = Arc::new(Mutex::new(Some(on_fail)));
    try_dial(engine.get(), Arc::new(addrs), 0, ctx, up, fail);
}

fn try_dial(
    engine: Option<Arc<akio::Engine>>,
    addrs: Arc<Vec<SocketAddr>>,
    i: usize,
    ctx: DialCtx,
    up: Arc<Mutex<Option<OnUp>>>,
    fail: OnFail,
) {
    if !ctx.client.is_open() {
        return; // the client gave up (or timed out) while we were dialling
    }
    let (Some(e), Some(&addr)) = (engine, addrs.get(i)) else {
        let taken = fail.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(f) = taken {
            f();
        }
        return;
    };
    let acceptor = UpstreamAcceptor {
        client: ctx.client.clone(),
        slot: ctx.slot.clone(),
        on_up: up.clone(),
        watch: ctx.watch.clone(),
        splice: ctx.splice.clone(),
        stall: ctx.stall,
    };
    let e2 = e.clone();
    e.dial(addr, acceptor, move |_err| {
        try_dial(Some(e2), addrs, i + 1, ctx, up, fail);
    });
}

mod client;
mod frag;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
mod udp;

pub use client::{
    BlockingBind, BlockingUdp, DEFAULT_BIND_TIMEOUT, DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
    ProxyRefused, SocksClient, UdpAssociation, Version,
};

// ---- SOCKS ---------------------------------------------------------------------------------

/// Username/password check for SOCKS5.
pub type Auth = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Access-control hook: whether a [`Request`] may proceed.
pub type Allow = Arc<dyn Fn(&Request<'_>) -> bool + Send + Sync>;

/// GSS-API settings of a server.
struct GssServer {
    factory: gssapi::ServerFactory,
    min: gssapi::Protection,
    max: gssapi::Protection,
}

/// What a SOCKS client asks for, as the access-control hook ([`Socks::allow`]) sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Command {
    /// `CONNECT` (SOCKS5, SOCKS4, 4a): a TCP connection to the destination.
    Connect,
    /// `BIND` (SOCKS5, SOCKS4, 4a): accept one TCP connection from the destination (the
    /// address the client expects it from).
    Bind,
    /// SOCKS5 `UDP ASSOCIATE`: open a UDP relay. The destination is the address the client
    /// says it will send from (often `0.0.0.0:0`).
    UdpAssociate,
    /// One destination of a UDP association's datagrams: asked once per destination and
    /// association, before the first datagram to it is relayed.
    UdpDatagram,
}

/// A destination: an address, or a host name the server resolves.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Dest {
    /// An IPv4 or IPv6 address and port.
    Addr(SocketAddr),
    /// A host name (not resolved yet) and port.
    Name(String, u16),
}

impl Dest {
    /// The port.
    pub fn port(&self) -> u16 {
        match self {
            Dest::Addr(a) => a.port(),
            Dest::Name(_, p) => *p,
        }
    }
}

impl From<SocketAddr> for Dest {
    fn from(a: SocketAddr) -> Dest {
        Dest::Addr(a)
    }
}

impl std::fmt::Display for Dest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dest::Addr(a) => write!(f, "{a}"),
            Dest::Name(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

/// A request checked by the access-control hook ([`Socks::allow`]).
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    version: u8,
    client: SocketAddr,
    user: Option<&'a str>,
    command: Command,
    dest: &'a Dest,
}

impl<'a> Request<'a> {
    /// The SOCKS version: 5, or 4 (SOCKS4 and 4a).
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The client's address (its TCP control connection).
    pub fn client(&self) -> SocketAddr {
        self.client
    }

    /// The SOCKS5 user name, when authentication is on ([`Socks::auth`]), or the GSS-API
    /// peer's name ([`gssapi::GssContext::peer_name`]); the SOCKS4 user id otherwise, if not
    /// empty.
    pub fn user(&self) -> Option<&'a str> {
        self.user
    }

    /// What is asked.
    pub fn command(&self) -> Command {
        self.command
    }

    /// The destination (see [`Command`] for what it is per command).
    pub fn dest(&self) -> &'a Dest {
        self.dest
    }
}

/// A SOCKS5/4/4a server. Serve it on a listener (`Listener::tcp(..).serve(socks)`); set the
/// [`EngineRef`] once the engine is built so it can dial upstream.
///
/// `CONNECT` is always available; SOCKS5 `BIND` ([`bind`](Self::bind)) and `UDP ASSOCIATE`
/// ([`udp_associate`](Self::udp_associate)) are off until enabled, and every command goes
/// through the access-control hook ([`allow`](Self::allow)) when one is set.
pub struct Socks {
    engine: EngineRef,
    auth: Option<Auth>,
    gss: Option<Arc<GssServer>>,
    allow: Option<Allow>,
    allow_socks4: bool,
    cfg: Arc<ProxyConfig>,
    bind: bool,
    udp: bool,
    bind_timeout: Duration,
    udp_idle: Duration,
    udp_frag: Option<usize>,
    sweeper: Arc<udp::Sweeper>,
}

impl std::fmt::Debug for Socks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks")
            .field("bind", &self.bind)
            .field("udp_associate", &self.udp)
            .finish_non_exhaustive()
    }
}

impl Socks {
    /// A server that dials through `engine`.
    pub fn new(engine: EngineRef) -> Socks {
        Socks {
            engine,
            auth: None,
            gss: None,
            allow: None,
            allow_socks4: true,
            cfg: Arc::new(ProxyConfig::default()),
            bind: false,
            udp: false,
            bind_timeout: Duration::from_secs(60),
            udp_idle: Duration::from_secs(120),
            udp_frag: None,
            sweeper: udp::Sweeper::new(),
        }
    }

    /// Replaces the limits and destination policy (default [`ProxyConfig::default`]).
    #[must_use]
    pub fn config(mut self, cfg: ProxyConfig) -> Socks {
        self.cfg = Arc::new(cfg);
        self
    }

    /// Sets [`ProxyConfig::destinations`].
    #[must_use]
    pub fn destinations(mut self, d: Destinations) -> Socks {
        Arc::make_mut(&mut self.cfg).destinations = d;
        self
    }

    /// Sets [`ProxyConfig::sockmap`]: splice `CONNECT` tunnels in the kernel with `relay`.
    #[must_use]
    pub fn sockmap(mut self, relay: akio::ebpf::Relay) -> Socks {
        Arc::make_mut(&mut self.cfg).sockmap = Some(relay);
        self
    }

    /// Requires SOCKS5 username/password authentication (and turns SOCKS4, which has none, off).
    #[must_use]
    pub fn auth(mut self, check: impl Fn(&str, &str) -> bool + Send + Sync + 'static) -> Socks {
        self.auth = Some(Arc::new(check));
        self.allow_socks4 = false;
        self
    }

    /// Accepts GSS-API authentication (RFC 1961, method 1) and turns SOCKS4 off. `factory` makes
    /// the acceptor's security context of each connection, on the logical pool (it may load a
    /// keytab); `levels` are the per-message protection levels granted: a client asking for
    /// less than the lowest gets the lowest, one asking for more than the highest gets the
    /// highest (`Protection::None..=Protection::Confidentiality` grants what is asked; a range
    /// whose end is below its start grants the start). With [`auth`](Self::auth) as well,
    /// a client may use either; without, no-authentication is no longer accepted. The
    /// context's [`peer_name`](gssapi::GssContext::peer_name) is the [`Request::user`] the
    /// access-control hook sees.
    ///
    /// Protection levels other than none need the session's own transport: serve the server
    /// on a plain TCP listener (not inside TLS), else such clients are refused. At those
    /// levels a `UDP ASSOCIATE` relay wraps and unwraps every datagram exchanged with the
    /// client (RFC 1961 §5; one encapsulated-data message per datagram, the control
    /// connection's context; datagrams that do not unwrap are dropped), and the `sockmap` fast
    /// path does not apply to their tunnels.
    #[must_use]
    pub fn gssapi(
        mut self,
        factory: impl Fn() -> std::io::Result<Box<dyn gssapi::GssContext>> + Send + Sync + 'static,
        levels: std::ops::RangeInclusive<gssapi::Protection>,
    ) -> Socks {
        let (min, max) = levels.into_inner();
        self.gss = Some(Arc::new(GssServer {
            factory: Arc::new(factory),
            min,
            max: max.max(min),
        }));
        self.allow_socks4 = false;
        self
    }

    /// Access control: `check` decides whether each request may proceed, after
    /// authentication and before anything is dialed, bound or resolved. A refused SOCKS5
    /// request gets reply 2 ("connection not allowed by ruleset"), a refused SOCKS4 one 0x5b,
    /// and a refused UDP destination has its datagrams dropped. Destinations given as host
    /// names are checked as names ([`Dest::Name`]); resolve them in the hook to check
    /// addresses.
    ///
    /// ```
    /// use akio_socks::{Command, Dest, Socks};
    /// let socks = Socks::new(akio::EngineRef::new())
    ///     .udp_associate(true)
    ///     .allow(|r| match r.dest() {
    ///         // No proxied traffic to the loopback interface, except UDP ASSOCIATE's
    ///         // own client address.
    ///         Dest::Addr(a) => r.command() == Command::UdpAssociate || !a.ip().is_loopback(),
    ///         Dest::Name(host, _) => host != "localhost",
    ///     });
    /// # let _ = socks;
    /// ```
    #[must_use]
    pub fn allow(mut self, check: impl Fn(&Request<'_>) -> bool + Send + Sync + 'static) -> Socks {
        self.allow = Some(Arc::new(check));
        self
    }

    /// Enables `BIND`, SOCKS5 and SOCKS4/4a (off by default): the server listens on a new port
    /// of the address the client reached it on, replies with it, accepts one connection (from
    /// the requested address's IP, unless that is unspecified or a host name), replies again
    /// with the peer's address and relays. Gives up after [`bind_timeout`](Self::bind_timeout).
    /// SOCKS4 replies carry IPv4 only: a SOCKS4 `BIND` reaching the server over IPv6 is
    /// refused.
    #[must_use]
    pub fn bind(mut self, enabled: bool) -> Socks {
        self.bind = enabled;
        self
    }

    /// How long a `BIND` waits for the incoming connection (default 60 s).
    #[must_use]
    pub fn bind_timeout(mut self, timeout: Duration) -> Socks {
        self.bind_timeout = timeout;
        self
    }

    /// Enables SOCKS5 `UDP ASSOCIATE` (off by default): each association gets its own UDP
    /// socket on the address the client reached the server on. The engine needs UDP I/O
    /// threads (`EngineBuilder::udp_client_threads`, or a UDP listener); without them the
    /// request fails with reply 1. Fragmented datagrams (non-zero `FRAG`) are reassembled:
    /// in order, one sequence per association, at most 65,507 bytes, within 5 s.
    #[must_use]
    pub fn udp_associate(mut self, enabled: bool) -> Socks {
        self.udp = enabled;
        self
    }

    /// How long a UDP association lasts without a datagram in either direction (default
    /// 120 s); it then ends with its control connection. Checked every 250 ms.
    #[must_use]
    pub fn udp_idle_timeout(mut self, timeout: Duration) -> Socks {
        self.udp_idle = timeout;
        self
    }

    /// Sends datagrams from remote hosts to the client in fragments (RFC 1928 `FRAG`) when
    /// they are larger than `size` bytes, for paths whose MTU the client knows to be small.
    /// `None` (the default) sends every datagram whole, which every client understands; not
    /// all clients reassemble fragments. Raised to 516 bytes when smaller, so that any
    /// datagram fits in the 127 fragments a sequence may have.
    #[must_use]
    pub fn udp_fragment_size(mut self, size: Option<usize>) -> Socks {
        self.udp_frag = size.map(|s| s.max(frag::MIN_FRAGMENT));
        self
    }
}

enum St {
    Greeting,
    Auth,
    /// GSS-API: waiting for the client's next establishment token.
    GssAuth,
    /// GSS-API: an establishment step runs on the pool.
    GssWait,
    /// GSS-API: waiting for the protection-level message.
    GssProt,
    Request,
    Socks4,
    /// Waiting for the upstream connection.
    Connecting,
    /// `BIND`: waiting for the incoming connection.
    Binding,
    /// `UDP ASSOCIATE`: the control connection only waits to be closed.
    Associated,
    Relaying,
}

/// One client of the SOCKS server.
pub struct SocksSession {
    engine: EngineRef,
    auth: Option<Auth>,
    gss: Option<Arc<GssServer>>,
    /// In a mutex only to keep the session `Sync`; reached through `&mut self` (`get_mut`).
    gss_ctx: Mutex<Option<Box<dyn gssapi::GssContext>>>,
    /// The protection agreed over GSS-API (none otherwise).
    protection: gssapi::Protection,
    allow: Option<Allow>,
    allow_socks4: bool,
    bind: bool,
    udp: bool,
    bind_timeout: Duration,
    udp_idle: Duration,
    udp_frag: Option<usize>,
    sweeper: Arc<udp::Sweeper>,
    user: Option<String>,
    st: St,
    buf: Vec<u8>,
    upstream: UpstreamSlot,
    cfg: Arc<ProxyConfig>,
    watch: Option<Arc<Watch>>,
    assoc: Option<Arc<udp::Assoc>>,
    bind_cancel: Option<Arc<AtomicBool>>,
    splice: Option<Arc<SpliceCtl>>,
}

impl std::fmt::Debug for SocksSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksSession").finish_non_exhaustive()
    }
}

impl Acceptor for Socks {
    type Handler = SocksSession;
    fn on_open(&self, c: &Conn<SocksSession>) -> SocksSession {
        let upstream: UpstreamSlot = Arc::new(Mutex::new(None));
        let watch = Watch::start(
            c.inner(),
            &upstream,
            self.cfg.handshake_timeout,
            self.cfg.idle_timeout,
        );
        SocksSession {
            engine: self.engine.clone(),
            auth: self.auth.clone(),
            gss: self.gss.clone(),
            gss_ctx: Mutex::new(None),
            protection: gssapi::Protection::None,
            allow: self.allow.clone(),
            allow_socks4: self.allow_socks4,
            bind: self.bind,
            udp: self.udp,
            bind_timeout: self.bind_timeout,
            udp_idle: self.udp_idle,
            udp_frag: self.udp_frag,
            sweeper: self.sweeper.clone(),
            user: None,
            st: St::Greeting,
            buf: Vec::new(),
            upstream,
            cfg: self.cfg.clone(),
            watch,
            assoc: None,
            bind_cancel: None,
            splice: SpliceCtl::new(self.cfg.sockmap.as_ref()),
        }
    }

    fn transport(&self) -> Option<Box<dyn akio::Transport>> {
        // Pass-through until a GSS-API client agrees on per-message protection.
        self.gss
            .as_ref()
            .map(|_| Box::new(gssapi::GssLayer::passthrough()) as Box<dyn akio::Transport>)
    }
}

/// SOCKS5 reply codes.
const REP_OK: u8 = 0;
const REP_FAILURE: u8 = 1;
const REP_NOT_ALLOWED: u8 = 2;
const REP_UNREACHABLE: u8 = 4;
const REP_REFUSED: u8 = 5;
const REP_CMD: u8 = 7;
const REP_ATYP: u8 = 8;

/// SOCKS4 "rejected or failed".
const SOCKS4_FAIL: [u8; 8] = [0, 0x5b, 0, 0, 0, 0, 0, 0];

/// Appends `ATYP ADDR PORT` for `a`.
pub(crate) fn push_addr(out: &mut Vec<u8>, a: SocketAddr) {
    match a {
        SocketAddr::V6(a) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V4(a) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&a.port().to_be_bytes());
}

/// Parses `ADDR PORT` of address type `atyp` from `b`: the destination and the bytes used.
/// `None` when `b` is too short or `atyp` unknown.
pub(crate) fn parse_addr(atyp: u8, b: &[u8]) -> Option<(Dest, usize)> {
    match atyp {
        1 => {
            let b: &[u8; 6] = b.get(..6)?.try_into().ok()?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Some((Dest::Addr(SocketAddr::new(IpAddr::V4(ip), port)), 6))
        }
        4 => {
            let b: &[u8; 18] = b.get(..18)?.try_into().ok()?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            let port = u16::from_be_bytes([b[16], b[17]]);
            Some((
                Dest::Addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port)),
                18,
            ))
        }
        3 => {
            let l = *b.first()? as usize;
            let rest = b.get(1..3 + l)?;
            let host = String::from_utf8_lossy(&rest[..l]).into_owned();
            let port = u16::from_be_bytes([rest[l], rest[l + 1]]);
            Some((Dest::Name(host, port), 3 + l))
        }
        _ => None,
    }
}

/// A `BIND` reply: success with `addr`, or a failure (`REP_FAILURE` / SOCKS4 0x5b; `denied`:
/// `REP_NOT_ALLOWED`).
fn bind_reply(v5: bool, addr: Option<SocketAddr>, denied: bool) -> Vec<u8> {
    match (v5, addr) {
        (true, Some(a)) => socks5_reply(REP_OK, Some(a)),
        (true, None) => socks5_reply(if denied { REP_NOT_ALLOWED } else { REP_FAILURE }, None),
        (false, Some(SocketAddr::V4(a))) => {
            let mut r = vec![0, 0x5a];
            r.extend_from_slice(&a.port().to_be_bytes());
            r.extend_from_slice(&a.ip().octets());
            r
        }
        (false, _) => SOCKS4_FAIL.to_vec(),
    }
}

fn socks5_reply(code: u8, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut r = vec![5, code, 0];
    match bound {
        Some(a) => push_addr(&mut r, a),
        None => r.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
    }
    r
}

impl SocksSession {
    fn fail(&mut self, c: &Conn<Self>, reply: Vec<u8>) {
        let _ = c.send_owned(reply);
        c.close_after_send();
        self.st = St::Relaying; // ignore anything else
    }

    /// Asks the access-control hook.
    fn allowed(&self, c: &Conn<Self>, version: u8, command: Command, dest: &Dest) -> bool {
        self.allow.as_ref().is_none_or(|f| {
            f(&Request {
                version,
                client: udp::canon(c.peer_addr()),
                user: self.user.as_deref(),
                command,
                dest,
            })
        })
    }

    fn connect(&mut self, c: &Conn<Self>, target: Dest, v5: bool) {
        let denied = move || {
            if v5 {
                socks5_reply(REP_NOT_ALLOWED, None)
            } else {
                SOCKS4_FAIL.to_vec()
            }
        };
        if let Dest::Addr(a) = target
            && !self.cfg.destinations.allows(a)
        {
            return self.fail(c, denied());
        }
        self.st = St::Connecting;
        c.inner().set_relayed(true);
        c.hold_reads(true);
        let engine = self.engine.clone();
        if let Some(s) = &self.splice
            && !self.buf.is_empty()
        {
            s.mark_early(); // bytes behind the request go through userspace
        }
        let ctx = DialCtx {
            client: c.inner().clone(),
            slot: self.upstream.clone(),
            watch: self.watch.clone(),
            splice: self.splice.clone(),
            stall: stall(&self.cfg),
        };
        let client = c.inner().clone();
        let (splice, watch) = (self.splice.clone(), self.watch.clone());
        let ok_reply = move |up: &Arc<ConnInner>| {
            let reply = if v5 {
                socks5_reply(REP_OK, Some(up.local_addr()))
            } else {
                vec![0, 0x5a, 0, 0, 0, 0, 0, 0]
            };
            reply_and_splice(splice.as_deref(), watch.as_deref(), &client, up, &reply);
            client.hold_reads(false);
        };
        let client2 = c.inner().clone();
        let fail = move || {
            let reply = if v5 {
                socks5_reply(REP_REFUSED, None)
            } else {
                SOCKS4_FAIL.to_vec()
            };
            let _ = client2.send_owned(reply);
            client2.close_after_send();
        };
        match target {
            Dest::Addr(a) => dial(&engine, vec![a], ctx, Box::new(ok_reply), Box::new(fail)),
            Dest::Name(host, port) => {
                // Name resolution blocks: do it on the logical pool.
                let r = c.spawn_blocking(
                    move || {
                        (host.as_str(), port)
                            .to_socket_addrs()
                            .map(|a| a.collect::<Vec<_>>())
                    },
                    move |me: &mut SocksSession, c, res| match res {
                        Ok(addrs) if !addrs.is_empty() => {
                            let allowed: Vec<SocketAddr> = addrs
                                .into_iter()
                                .filter(|a| me.cfg.destinations.allows(*a))
                                .collect();
                            if allowed.is_empty() {
                                me.fail(c, denied());
                                return;
                            }
                            dial(&engine, allowed, ctx, Box::new(ok_reply), Box::new(fail));
                        }
                        _ => {
                            let reply = if v5 {
                                socks5_reply(REP_UNREACHABLE, None)
                            } else {
                                SOCKS4_FAIL.to_vec()
                            };
                            let _ = c.send_owned(reply);
                            c.close_after_send();
                        }
                    },
                );
                if r.is_err() {
                    c.close();
                }
            }
        }
    }

    /// `BIND` (SOCKS5, or SOCKS4 when `!v5`): listen, reply with the port, accept one
    /// connection (on a thread of its own, polling so that it notices the client leaving),
    /// adopt it into the engine, reply with the peer and relay.
    fn bind(&mut self, c: &Conn<Self>, expected: Dest, v5: bool) {
        // The destination policy applies to the peer BIND waits for: a stated address must be
        // allowed, and a connection from a denied address is never taken.
        if let Dest::Addr(a) = expected
            && !a.ip().is_unspecified()
            && !self.cfg.destinations.allows(a)
        {
            return self.fail(c, bind_reply(v5, None, true));
        }
        let Some(engine) = self.engine.get() else {
            return self.fail(c, bind_reply(v5, None, false));
        };
        let local = SocketAddr::new(udp::canon(c.local_addr()).ip(), 0);
        // SOCKS4 replies carry IPv4 addresses only.
        if !v5 && !local.is_ipv4() {
            return self.fail(c, bind_reply(v5, None, false));
        }
        let listener = match std::net::TcpListener::bind(local) {
            Ok(l) if l.set_nonblocking(true).is_ok() => l,
            _ => return self.fail(c, bind_reply(v5, None, false)),
        };
        let Ok(bound) = listener.local_addr() else {
            return self.fail(c, bind_reply(v5, None, false));
        };
        self.st = St::Binding;
        c.inner().set_relayed(true);
        let _ = c.send_owned(bind_reply(v5, Some(udp::canon(bound)), false));
        // The handshake is over; `bind_timeout` bounds the wait, the idle timeout what follows.
        if let Some(w) = &self.watch {
            w.established();
        }
        let destinations = self.cfg.destinations.clone();
        let watch = self.watch.clone();
        // Only a connection from the expected IP is taken (any, when it is unspecified or a
        // name: the client usually does not know where the peer connects from).
        let want_ip = match expected {
            Dest::Addr(a) if !a.ip().is_unspecified() => Some(udp::canon(a).ip()),
            _ => None,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        self.bind_cancel = Some(cancel.clone());
        let client = c.inner().clone();
        let slot = self.upstream.clone();
        let deadline = Instant::now() + self.bind_timeout;
        let spawned = std::thread::Builder::new()
            .name("akio-socks-bind".into())
            .spawn(move || {
                let stream = loop {
                    if cancel.load(Ordering::Acquire) {
                        return;
                    }
                    match listener.accept() {
                        Ok((s, peer))
                            if want_ip.is_none_or(|ip| udp::canon(peer).ip() == ip)
                                && destinations.allows(udp::canon(peer)) =>
                        {
                            break s;
                        }
                        Ok(_) => {} // someone else: dropped
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                let _ = client.send_owned(bind_reply(v5, None, false));
                                return client.close_after_send();
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => {
                            let _ = client.send_owned(bind_reply(v5, None, false));
                            return client.close_after_send();
                        }
                    }
                };
                drop(listener);
                let client_up = client.clone();
                let acceptor = UpstreamAcceptor {
                    client: client.clone(),
                    slot,
                    watch,
                    splice: None,
                    stall: Duration::ZERO,
                    on_up: Arc::new(Mutex::new(Some(Box::new(move |up: &Arc<ConnInner>| {
                        if !client_up.is_open() {
                            return up.close();
                        }
                        let peer = udp::canon(up.peer_addr());
                        let _ = client_up.send_owned(bind_reply(v5, Some(peer), false));
                    }) as OnUp))),
                };
                engine.adopt_tcp(stream, acceptor, move |_e| {
                    let _ = client.send_owned(bind_reply(v5, None, false));
                    client.close_after_send();
                });
            });
        if spawned.is_err() {
            self.fail(c, bind_reply(v5, None, false));
        }
    }

    /// SOCKS5 `UDP ASSOCIATE`: bind the relay socket and reply with its address.
    fn associate(&mut self, c: &Conn<Self>, declared: Dest) {
        let Some(engine) = self.engine.get() else {
            return self.fail(c, socks5_reply(REP_FAILURE, None));
        };
        let declared = match declared {
            Dest::Addr(a) => Some(a),
            Dest::Name(..) => None,
        };
        // RFC 1961 §5: with per-message protection the datagrams are wrapped too, with the
        // control connection's context.
        let gss = if self.protection == gssapi::Protection::None {
            None
        } else {
            let d = c
                .with_transport(|t| {
                    t.as_any()
                        .downcast_mut::<gssapi::GssLayer>()
                        .and_then(|l| l.datagrams())
                })
                .flatten();
            if d.is_none() {
                return self.fail(c, socks5_reply(REP_FAILURE, None));
            }
            d
        };
        match udp::Assoc::open(
            &engine,
            c.inner().clone(),
            self.user.clone(),
            self.allow.clone(),
            declared,
            self.cfg.destinations.clone(),
            &self.sweeper,
            self.udp_idle,
            self.udp_frag,
            gss,
        ) {
            Ok((a, bound)) => {
                // The association has its own idle timeout (its datagrams never touch the
                // control connection), so the session's timeouts stop here.
                if let Some(w) = &self.watch {
                    w.disarm();
                }
                self.assoc = Some(a);
                self.st = St::Associated;
                let _ = c.send_owned(socks5_reply(REP_OK, Some(bound)));
            }
            Err(_) => self.fail(c, socks5_reply(REP_FAILURE, None)),
        }
    }

    /// Handles as much of the handshake as is buffered.
    fn step(&mut self, c: &Conn<Self>) {
        loop {
            let b = &self.buf;
            match self.st {
                St::Greeting => {
                    let Some(&ver) = b.first() else { return };
                    if ver == 4 {
                        if !self.allow_socks4 {
                            return self.fail(c, SOCKS4_FAIL.to_vec());
                        }
                        self.st = St::Socks4;
                        continue;
                    }
                    if ver != 5 {
                        c.close();
                        self.st = St::Relaying;
                        return;
                    }
                    if b.len() < 2 || b.len() < 2 + b[1] as usize {
                        return;
                    }
                    let methods = &b[2..2 + b[1] as usize];
                    let n = 2 + b[1] as usize;
                    // GSS-API first, then username/password; none only when neither is on.
                    let want = [
                        (self.gss.is_some(), 1),
                        (self.auth.is_some(), 2),
                        (self.gss.is_none() && self.auth.is_none(), 0),
                    ]
                    .into_iter()
                    .find(|(on, m)| *on && methods.contains(m))
                    .map(|(_, m)| m);
                    let Some(want) = want else {
                        return self.fail(c, vec![5, 0xff]);
                    };
                    let _ = c.send(&[5, want]);
                    self.buf.drain(..n);
                    self.st = match want {
                        1 => St::GssAuth,
                        2 => St::Auth,
                        _ => St::Request,
                    };
                }
                St::GssWait => return,
                St::GssAuth => {
                    let msg = match gssapi::parse_msg(b) {
                        Ok(Some(m)) => m,
                        Ok(None) => return,
                        Err(_) => return self.gss_abort(c),
                    };
                    let (gssapi::MTYP_AUTH, token, n) = msg else {
                        return self.gss_abort(c);
                    };
                    let token = token.to_vec();
                    self.buf.drain(..n);
                    return self.gss_step(c, token);
                }
                St::GssProt => {
                    let msg = match gssapi::parse_msg(b) {
                        Ok(Some(m)) => m,
                        Ok(None) => return,
                        Err(_) => return self.gss_abort(c),
                    };
                    let (gssapi::MTYP_PROTECTION, token, n) = msg else {
                        return self.gss_abort(c);
                    };
                    let token = token.to_vec();
                    self.buf.drain(..n);
                    if !self.gss_protection(c, &token) {
                        return;
                    }
                }
                St::Auth => {
                    // RFC 1929: VER=1 ULEN UNAME PLEN PASSWD
                    if b.len() < 2 {
                        return;
                    }
                    let ul = b[1] as usize;
                    if b.len() < 3 + ul || b.len() < 3 + ul + b[2 + ul] as usize {
                        return;
                    }
                    let pl = b[2 + ul] as usize;
                    let user = String::from_utf8_lossy(&b[2..2 + ul]).into_owned();
                    let pass = String::from_utf8_lossy(&b[3 + ul..3 + ul + pl]).into_owned();
                    let n = 3 + ul + pl;
                    let ok = self.auth.as_ref().is_some_and(|f| f(&user, &pass));
                    if !ok {
                        return self.fail(c, vec![1, 1]);
                    }
                    let _ = c.send(&[1, 0]);
                    self.buf.drain(..n);
                    self.user = Some(user);
                    self.st = St::Request;
                }
                St::Request => {
                    if b.len() < 4 {
                        return;
                    }
                    let (cmd, atyp) = (b[1], b[3]);
                    if !matches!(atyp, 1 | 3 | 4) {
                        return self.fail(c, socks5_reply(REP_ATYP, None));
                    }
                    let Some((target, n)) = parse_addr(atyp, &b[4..]) else {
                        return;
                    };
                    let command = match cmd {
                        1 => Command::Connect,
                        2 if self.bind => Command::Bind,
                        3 if self.udp => Command::UdpAssociate,
                        _ => return self.fail(c, socks5_reply(REP_CMD, None)),
                    };
                    self.buf.drain(..4 + n);
                    if !self.allowed(c, 5, command, &target) {
                        return self.fail(c, socks5_reply(REP_NOT_ALLOWED, None));
                    }
                    return match command {
                        Command::Bind => self.bind(c, target, true),
                        Command::UdpAssociate => self.associate(c, target),
                        _ => self.connect(c, target, true),
                    };
                }
                St::Socks4 => {
                    // VN CD DSTPORT DSTIP USERID NUL [DOMAIN NUL]
                    if b.len() < 9 {
                        return;
                    }
                    let Some(uend) = b[8..].iter().position(|x| *x == 0).map(|p| p + 8) else {
                        return;
                    };
                    let command = match b[1] {
                        1 => Command::Connect,
                        2 if self.bind => Command::Bind,
                        _ => return self.fail(c, SOCKS4_FAIL.to_vec()),
                    };
                    let port = u16::from_be_bytes([b[2], b[3]]);
                    let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
                    let user = String::from_utf8_lossy(&b[8..uend]).into_owned();
                    let (target, n) = if b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] != 0 {
                        // 4a: a domain name follows the user id.
                        let Some(dend) = b[uend + 1..]
                            .iter()
                            .position(|x| *x == 0)
                            .map(|p| p + uend + 1)
                        else {
                            return;
                        };
                        let host = String::from_utf8_lossy(&b[uend + 1..dend]).into_owned();
                        (Dest::Name(host, port), dend + 1)
                    } else {
                        (Dest::Addr(SocketAddr::new(IpAddr::V4(ip), port)), uend + 1)
                    };
                    self.buf.drain(..n);
                    self.user = (!user.is_empty()).then_some(user);
                    if !self.allowed(c, 4, command, &target) {
                        return self.fail(c, SOCKS4_FAIL.to_vec());
                    }
                    return match command {
                        Command::Bind => self.bind(c, target, false),
                        _ => self.connect(c, target, false),
                    };
                }
                St::Connecting | St::Binding | St::Associated | St::Relaying => return,
            }
        }
    }

    /// The GSS-API context slot.
    fn ctx(&mut self) -> &mut Option<Box<dyn gssapi::GssContext>> {
        self.gss_ctx
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// RFC 1961: an establishment failure gets `VER = 1, MTYP = 0xff`, then the close.
    fn gss_abort(&mut self, c: &Conn<Self>) {
        *self.ctx() = None;
        self.fail(c, gssapi::ABORT.to_vec());
    }

    /// Runs one establishment step on the logical pool (it may block: keytab, replay cache).
    fn gss_step(&mut self, c: &Conn<Self>, token: Vec<u8>) {
        let Some(gss) = self.gss.clone() else {
            return self.gss_abort(c);
        };
        let ctx = self.ctx().take();
        self.st = St::GssWait;
        let r = c.spawn_blocking(
            move || {
                let mut ctx = match ctx {
                    Some(ctx) => ctx,
                    None => match (gss.factory)() {
                        Ok(ctx) => ctx,
                        Err(e) => return (None, Err(e)),
                    },
                };
                let r = ctx.step(&token);
                (Some(ctx), r)
            },
            |me: &mut SocksSession, c, (ctx, r)| {
                if !matches!(me.st, St::GssWait) {
                    return; // closed meanwhile
                }
                *me.ctx() = ctx;
                let Ok(step) = r else {
                    return me.gss_abort(c);
                };
                let mut out = Vec::new();
                let (token, done) = match step {
                    gssapi::GssStep::Continue(t) => (t, false),
                    gssapi::GssStep::Complete(t) => (t, true),
                };
                if (!done || !token.is_empty())
                    && gssapi::push_msg(&mut out, gssapi::MTYP_AUTH, &token).is_err()
                {
                    return me.gss_abort(c);
                }
                let _ = c.send_owned(out);
                if done {
                    me.user = me.ctx().as_ref().and_then(|x| x.peer_name());
                    me.st = St::GssProt;
                } else {
                    me.st = St::GssAuth;
                }
                // Go on with what came meanwhile.
                me.step(c);
            },
        );
        if r.is_err() {
            c.close();
        }
    }

    /// The protection-level message: answers with the level and, unless it is none, turns
    /// the session's transport on. `false` when the session failed.
    fn gss_protection(&mut self, c: &Conn<Self>, token: &[u8]) -> bool {
        let (Some(ctx), Some(gss)) = (
            self.gss_ctx
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut(),
            self.gss.as_ref(),
        ) else {
            self.gss_abort(c);
            return false;
        };
        let Ok(asked) = gssapi::protection_of(ctx.as_mut(), token) else {
            self.gss_abort(c);
            return false;
        };
        let level = asked.clamp(gss.min, gss.max);
        let mut out = Vec::new();
        if gssapi::protection_msg(ctx.as_mut(), level, &mut out).is_err() {
            self.gss_abort(c);
            return false;
        }
        let _ = c.send_owned(out);
        self.st = St::Request;
        if level == gssapi::Protection::None {
            *self.ctx() = None;
            return true;
        }
        // What follows, in this read and later ones, is wrapped.
        let Some(ctx) = self.ctx().take() else {
            return false;
        };
        let pending = std::mem::take(&mut self.buf);
        let mut plain = Vec::new();
        let activated = c.with_transport(|t| {
            t.as_any()
                .downcast_mut::<gssapi::GssLayer>()
                .map(|l| l.activate(ctx, level, &pending, &mut plain))
        });
        match activated {
            Some(Some(Ok(()))) => {
                self.protection = level;
                self.buf = plain;
                // The kernel cannot wrap: these tunnels stay in userspace.
                self.splice = None;
                true
            }
            _ => {
                // No GSS-API layer under the session (served inside TLS), or the pending
                // bytes did not unwrap.
                c.close();
                self.st = St::Relaying;
                false
            }
        }
    }
}

impl Handler for SocksSession {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let St::Associated = self.st {
            // RFC 1928: the control connection carries nothing more; its close ends the
            // association.
            return;
        }
        if let St::Relaying | St::Connecting | St::Binding = self.st {
            let up = {
                let g = self.upstream.lock().unwrap_or_else(|p| p.into_inner());
                if g.is_none()
                    && let Some(s) = &self.splice
                {
                    s.mark_early(); // held for the upstream: no splicing
                }
                g.clone()
            };
            match up {
                Some(up) => {
                    if spliced_payload(self.splice.as_deref(), c.inner(), &up) {
                        return;
                    }
                    if let Some(w) = &self.watch {
                        w.touch();
                    }
                    // Bytes buffered behind the request go first.
                    if !self.buf.is_empty() {
                        let pending = std::mem::take(&mut self.buf);
                        forward(c.inner(), &up, &pending);
                    }
                    forward(c.inner(), &up, data);
                    self.st = St::Relaying;
                }
                // Early data while the upstream connects is kept for it, up to the relay's high
                // water mark (reads are held meanwhile, so only a client that pushed past what
                // was already read gets here); after a failure (the session is closing) there is
                // nobody to give it to.
                None if matches!(self.st, St::Connecting) => {
                    if self.buf.len() + data.len() > HIGH_WATER {
                        self.buf = Vec::new();
                        self.st = St::Relaying;
                        c.close();
                        return;
                    }
                    self.buf.extend_from_slice(data);
                }
                // A BIND client must wait for the second reply.
                None if matches!(self.st, St::Binding) => {
                    self.st = St::Relaying;
                    c.close();
                }
                None => {}
            }
            return;
        }
        self.buf.extend_from_slice(data);
        self.step(c);
        let limit = if matches!(self.st, St::GssAuth | St::GssWait | St::GssProt) {
            MAX_GSS_HANDSHAKE
        } else {
            MAX_HANDSHAKE
        };
        if matches!(
            self.st,
            St::Greeting
                | St::Auth
                | St::Request
                | St::Socks4
                | St::GssAuth
                | St::GssWait
                | St::GssProt
        ) && self.buf.len() > limit
        {
            self.buf = Vec::new();
            self.st = St::Relaying; // ignore anything else
            c.close();
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<akio::Error>) {
        if let Some(cancel) = self.bind_cancel.take() {
            cancel.store(true, Ordering::Release);
        }
        if let Some(a) = self.assoc.take() {
            a.close();
        }
        let taken = self
            .upstream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(up) = taken {
            match &self.splice {
                Some(s) if s.is_spliced() => {
                    s.close_after_forward(c.inner(), true, up, stall(&self.cfg));
                }
                _ => up.close_after_send(),
            }
        }
    }
}

// ---- HTTP CONNECT --------------------------------------------------------------------------

/// An HTTP proxy service for `CONNECT host:port` tunnels (use it as a `akio-http` service, or
/// mount it in a router's fallback). Other methods get 405.
pub fn connect_proxy(engine: EngineRef) -> impl Service {
    connect_proxy_with(engine, ProxyConfig::default())
}

/// [`connect_proxy`] with explicit limits and destination policy. A denied destination gets
/// 403, an unresolvable one or a failed connect 502, and 503 when the resolver queue is full.
pub fn connect_proxy_with(engine: EngineRef, cfg: ProxyConfig) -> impl Service {
    let cfg = Arc::new(cfg);
    move |ctx: &mut Context| {
        if *ctx.method() != Method::Connect {
            return ctx.respond(
                Response::text(405, "only CONNECT is proxied").header("Allow", "CONNECT"),
            );
        }
        let target = ctx.req().target.clone();
        let Some((host, port)) = target.rsplit_once(':').and_then(|(h, p)| {
            Some((
                h.trim_matches(['[', ']']).to_owned(),
                p.parse::<u16>().ok()?,
            ))
        }) else {
            return ctx.text(400, "CONNECT needs host:port");
        };
        // A literal address is checked before anything is set up.
        if let Ok(ip) = host.parse::<IpAddr>()
            && !cfg.destinations.allows(SocketAddr::new(ip, port))
        {
            return ctx.text(403, "destination not allowed");
        }
        ctx.upgrade_raw(Tunnel {
            engine: engine.clone(),
            host: Some((host, port)),
            upstream: Arc::new(Mutex::new(None)),
            pending: Vec::new(),
            splice: SpliceCtl::new(cfg.sockmap.as_ref()),
            cfg: cfg.clone(),
            watch: None,
            client: None,
        });
    }
}

struct Tunnel {
    engine: EngineRef,
    host: Option<(String, u16)>,
    upstream: UpstreamSlot,
    pending: Vec<u8>,
    cfg: Arc<ProxyConfig>,
    watch: Option<Arc<Watch>>,
    splice: Option<Arc<SpliceCtl>>,
    /// The client connection (for closing a spliced tunnel).
    client: Option<Arc<ConnInner>>,
}

const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const UNAVAILABLE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

impl RawHandler for Tunnel {
    fn on_open(&mut self, conn: &RawConn) {
        conn.inner().set_relayed(true);
        conn.hold_reads(true);
        let (host, port) = self.host.take().expect("opened once");
        self.watch = Watch::start(
            conn.inner(),
            &self.upstream,
            self.cfg.handshake_timeout,
            self.cfg.idle_timeout,
        );
        let engine = self.engine.clone();
        self.client = Some(conn.inner().clone());
        let ctx = DialCtx {
            client: conn.inner().clone(),
            slot: self.upstream.clone(),
            watch: self.watch.clone(),
            splice: self.splice.clone(),
            stall: stall(&self.cfg),
        };
        let (splice, watch) = (self.splice.clone(), self.watch.clone());
        let cfg = self.cfg.clone();
        // Resolution may block: it runs on the proxy's resolver threads (a raw connection has
        // no typed handle for the logical pool), never on the I/O thread.
        let queued = guard::resolve(
            host,
            port,
            Box::new(move |res| {
                let client = ctx.client.clone();
                if !client.is_open() {
                    return;
                }
                let addrs: Vec<SocketAddr> = res.unwrap_or_default();
                if addrs.is_empty() {
                    let _ = client.send(BAD_GATEWAY);
                    return client.close_after_send();
                }
                let allowed: Vec<SocketAddr> = addrs
                    .into_iter()
                    .filter(|a| cfg.destinations.allows(*a))
                    .collect();
                if allowed.is_empty() {
                    let _ = client.send(FORBIDDEN);
                    return client.close_after_send();
                }
                let (c_ok, c_fail) = (client.clone(), client);
                dial(
                    &engine,
                    allowed,
                    ctx,
                    Box::new(move |up| {
                        const OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                        reply_and_splice(splice.as_deref(), watch.as_deref(), &c_ok, up, OK);
                        c_ok.hold_reads(false);
                    }),
                    Box::new(move || {
                        let _ = c_fail.send(BAD_GATEWAY);
                        c_fail.close_after_send();
                    }),
                );
            }),
        );
        if queued.is_err() {
            let _ = conn.send(UNAVAILABLE);
            conn.close_after_send();
        }
    }

    fn on_data(&mut self, conn: &RawConn, data: &[u8]) {
        let up = {
            let g = self.upstream.lock().unwrap_or_else(|p| p.into_inner());
            if g.is_none()
                && let Some(s) = &self.splice
            {
                s.mark_early();
            }
            g.clone()
        };
        match up {
            Some(up) => {
                if spliced_payload(self.splice.as_deref(), conn.inner(), &up) {
                    return;
                }
                if let Some(w) = &self.watch {
                    w.touch();
                }
                if !self.pending.is_empty() {
                    let p = std::mem::take(&mut self.pending);
                    forward(conn.inner(), &up, &p);
                }
                forward(conn.inner(), &up, data);
            }
            // Early data, bounded like the SOCKS session's.
            None if self.pending.len() + data.len() > HIGH_WATER => {
                self.pending = Vec::new();
                conn.close();
            }
            None => self.pending.extend_from_slice(data),
        }
    }

    fn on_close(&mut self) {
        let taken = self
            .upstream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(up) = taken {
            match (&self.splice, &self.client) {
                (Some(s), Some(client)) if s.is_spliced() => {
                    s.close_after_forward(client, true, up, stall(&self.cfg));
                }
                _ => up.close_after_send(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a SOCKS4 request whose user id never ends used to be buffered without limit.
    #[test]
    fn endless_socks4_user_id_is_cut_off() {
        let c = akio_core::fuzzing::conn();
        let mut s = Socks::new(EngineRef::new()).on_open(&c);
        s.on_data(&c, &[4, 1, 0, 80, 127, 0, 0, 1]);
        for _ in 0..100 {
            s.on_data(&c, &[b'u'; 1000]);
        }
        assert!(s.buf.len() <= MAX_HANDSHAKE);
        assert!(!c.is_open());
    }

    /// Early data sent while the upstream connects is held up to the relay's high water mark,
    /// and the client is cut off past it.
    #[test]
    fn early_data_is_bounded() {
        let c = akio_core::fuzzing::conn();
        let mut s = Socks::new(EngineRef::new()).on_open(&c);
        s.st = St::Connecting;
        s.on_data(&c, &vec![1; HIGH_WATER - 10]);
        s.on_data(&c, &[2; 10]); // at the limit: kept
        assert!(c.is_open());
        assert_eq!(s.buf.len(), HIGH_WATER);
        s.on_data(&c, &[3]); // over
        assert!(!c.is_open());
        assert!(s.buf.is_empty());
    }

    #[test]
    fn public_addresses() {
        let p = |s: &str| is_public(s.parse().unwrap());
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.0.1",
            "172.32.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(p(a), "{a} is public");
        }
        for a in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "::127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!p(a), "{a} is not public");
        }
        let any = Destinations::Any;
        assert!(any.allows("127.0.0.1:1".parse().unwrap()));
        let only_80 = Destinations::Custom(Arc::new(|a: SocketAddr| a.port() == 80));
        assert!(only_80.allows("10.0.0.1:80".parse().unwrap()));
        assert!(!only_80.allows("8.8.8.8:81".parse().unwrap()));
    }

    #[test]
    fn socks5_replies() {
        assert_eq!(
            socks5_reply(REP_OK, Some("1.2.3.4:80".parse().unwrap())),
            vec![5, 0, 0, 1, 1, 2, 3, 4, 0, 80]
        );
        assert_eq!(socks5_reply(REP_REFUSED, None)[..4], [5, 5, 0, 1]);
        let r = socks5_reply(REP_OK, Some("[::1]:443".parse().unwrap()));
        assert_eq!((r[3], r.len()), (4, 22));
    }
}
