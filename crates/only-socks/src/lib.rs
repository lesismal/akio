#![forbid(unsafe_code)]
//! Proxies on `only`: a SOCKS5 / SOCKS4 / SOCKS4a server ([`Socks`]) and an HTTP `CONNECT`
//! proxy ([`connect_proxy`]), both relaying callback to callback with backpressure in both
//! directions: when one side cannot keep up, reading from the other pauses until it drains.
//!
//! Supported: SOCKS5 `CONNECT`, `BIND` and `UDP ASSOCIATE` (RFC 1928; the last two opt-in,
//! [`Socks::bind`], [`Socks::udp_associate`]) with no authentication or username/password
//! (RFC 1929), IPv4, IPv6 and domain names (resolved on the logical pool); SOCKS4 and 4a
//! `CONNECT`; HTTP `CONNECT host:port`; an access-control hook over every request
//! ([`Socks::allow`]). Not supported: UDP fragment reassembly (fragments are dropped, as RFC
//! 1928 allows), SOCKS4 `BIND`, GSSAPI authentication, a Linux `splice` path.
//!
//! Guide: [SOCKS and HTTP CONNECT proxies](https://lesismal.github.io/only/en/protocols/socks.html)
//! (中文: [SOCKS 与 HTTP CONNECT 代理](https://lesismal.github.io/only/zh-CN/protocols/socks.html)).
#![warn(clippy::unwrap_used)]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Acceptor, Conn, EngineRef, Handler};
use only_core::ConnInner;
use only_http::{
    Context, Method, Response, Service,
    raw::{RawConn, RawHandler},
};

/// Largest handshake (greeting, authentication or request) buffered before the client is cut
/// off. The largest valid SOCKS5 message is 513 bytes; SOCKS4's user id and 4a's host name are
/// NUL-terminated, so without a bound a client could make the buffer grow forever.
const MAX_HANDSHAKE: usize = 4096;

/// Queue size on the outgoing side above which reading from the incoming side pauses.
const HIGH_WATER: usize = 256 << 10;

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

/// The far side of a tunnel: its data goes back to the client.
type UpstreamSlot = Arc<Mutex<Option<Arc<ConnInner>>>>;

struct Upstream {
    client: Arc<ConnInner>,
}

impl Handler for Upstream {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        forward(c.inner(), &self.client, data);
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        self.client.close_after_send();
    }
}

/// Runs when the upstream connection is established (on its I/O thread).
type OnUp = Box<dyn FnOnce(&Arc<ConnInner>) + Send>;

struct UpstreamAcceptor {
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    on_up: Arc<Mutex<Option<OnUp>>>,
}

impl Acceptor for UpstreamAcceptor {
    type Handler = Upstream;
    fn on_open(&self, c: &Conn<Upstream>) -> Upstream {
        c.inner().set_relayed(true);
        *self.slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(c.inner().clone());
        let taken = self.on_up.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(f) = taken {
            f(c.inner());
        }
        Upstream {
            client: self.client.clone(),
        }
    }
}

type OnFail = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// Dials the addresses in order for `client`; `on_up` runs on the first that connects,
/// `on_fail` when none does.
fn dial(
    engine: &EngineRef,
    addrs: Vec<SocketAddr>,
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    on_up: OnUp,
    on_fail: Box<dyn FnOnce() + Send>,
) {
    let up = Arc::new(Mutex::new(Some(on_up)));
    let fail: OnFail = Arc::new(Mutex::new(Some(on_fail)));
    try_dial(engine.get(), Arc::new(addrs), 0, client, slot, up, fail);
}

fn try_dial(
    engine: Option<Arc<only::Engine>>,
    addrs: Arc<Vec<SocketAddr>>,
    i: usize,
    client: Arc<ConnInner>,
    slot: UpstreamSlot,
    up: Arc<Mutex<Option<OnUp>>>,
    fail: OnFail,
) {
    let (Some(e), Some(&addr)) = (engine, addrs.get(i)) else {
        let taken = fail.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(f) = taken {
            f();
        }
        return;
    };
    let acceptor = UpstreamAcceptor {
        client: client.clone(),
        slot: slot.clone(),
        on_up: up.clone(),
    };
    let e2 = e.clone();
    e.dial(addr, acceptor, move |_err| {
        try_dial(Some(e2), addrs, i + 1, client, slot, up, fail);
    });
}

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
mod udp;

// ---- SOCKS ---------------------------------------------------------------------------------

/// Username/password check for SOCKS5.
pub type Auth = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Access-control hook: whether a [`Request`] may proceed.
pub type Allow = Arc<dyn Fn(&Request<'_>) -> bool + Send + Sync>;

/// What a SOCKS client asks for, as the access-control hook ([`Socks::allow`]) sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Command {
    /// `CONNECT` (SOCKS5, SOCKS4, 4a): a TCP connection to the destination.
    Connect,
    /// SOCKS5 `BIND`: accept one TCP connection from the destination (the address the
    /// client expects it from).
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

    /// The SOCKS5 user name, when authentication is on ([`Socks::auth`]); the SOCKS4 user id
    /// otherwise, if not empty.
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
    allow: Option<Allow>,
    allow_socks4: bool,
    bind: bool,
    udp: bool,
    bind_timeout: Duration,
    udp_idle: Duration,
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
            allow: None,
            allow_socks4: true,
            bind: false,
            udp: false,
            bind_timeout: Duration::from_secs(60),
            udp_idle: Duration::from_secs(120),
            sweeper: udp::Sweeper::new(),
        }
    }

    /// Requires SOCKS5 username/password authentication (and turns SOCKS4, which has none, off).
    #[must_use]
    pub fn auth(mut self, check: impl Fn(&str, &str) -> bool + Send + Sync + 'static) -> Socks {
        self.auth = Some(Arc::new(check));
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
    /// use only_socks::{Command, Dest, Socks};
    /// let socks = Socks::new(only::EngineRef::new())
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

    /// Enables SOCKS5 `BIND` (off by default): the server listens on a new port of the
    /// address the client reached it on, replies with it, accepts one connection (from the
    /// requested address's IP, unless that is unspecified), replies again with the peer's
    /// address and relays. Gives up after [`bind_timeout`](Self::bind_timeout).
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
    /// request fails with reply 1. Datagrams with a non-zero fragment number are dropped.
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
}

enum St {
    Greeting,
    Auth,
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
    allow: Option<Allow>,
    allow_socks4: bool,
    bind: bool,
    udp: bool,
    bind_timeout: Duration,
    udp_idle: Duration,
    sweeper: Arc<udp::Sweeper>,
    user: Option<String>,
    st: St,
    buf: Vec<u8>,
    upstream: UpstreamSlot,
    assoc: Option<Arc<udp::Assoc>>,
    bind_cancel: Option<Arc<AtomicBool>>,
}

impl std::fmt::Debug for SocksSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksSession").finish_non_exhaustive()
    }
}

impl Acceptor for Socks {
    type Handler = SocksSession;
    fn on_open(&self, _c: &Conn<SocksSession>) -> SocksSession {
        SocksSession {
            engine: self.engine.clone(),
            auth: self.auth.clone(),
            allow: self.allow.clone(),
            allow_socks4: self.allow_socks4,
            bind: self.bind,
            udp: self.udp,
            bind_timeout: self.bind_timeout,
            udp_idle: self.udp_idle,
            sweeper: self.sweeper.clone(),
            user: None,
            st: St::Greeting,
            buf: Vec::new(),
            upstream: Arc::new(Mutex::new(None)),
            assoc: None,
            bind_cancel: None,
        }
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
        self.st = St::Connecting;
        c.inner().set_relayed(true);
        c.hold_reads(true);
        let engine = self.engine.clone();
        let slot = self.upstream.clone();
        let client = c.inner().clone();
        let ok_reply = move |up: &Arc<ConnInner>| {
            let reply = if v5 {
                socks5_reply(REP_OK, Some(up.local_addr()))
            } else {
                vec![0, 0x5a, 0, 0, 0, 0, 0, 0]
            };
            let _ = client.send_owned(reply);
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
        let client3 = c.inner().clone();
        match target {
            Dest::Addr(a) => dial(
                &engine,
                vec![a],
                client3,
                slot,
                Box::new(ok_reply),
                Box::new(fail),
            ),
            Dest::Name(host, port) => {
                // Name resolution blocks: do it on the logical pool.
                let r = c.spawn_blocking(
                    move || {
                        (host.as_str(), port)
                            .to_socket_addrs()
                            .map(|a| a.collect::<Vec<_>>())
                    },
                    move |_me: &mut SocksSession, c, res| match res {
                        Ok(addrs) if !addrs.is_empty() => dial(
                            &engine,
                            addrs,
                            c.inner().clone(),
                            slot,
                            Box::new(ok_reply),
                            Box::new(fail),
                        ),
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

    /// SOCKS5 `BIND`: listen, reply with the port, accept one connection (on a thread of its
    /// own, polling so that it notices the client leaving), adopt it into the engine, reply
    /// with the peer and relay.
    fn bind(&mut self, c: &Conn<Self>, expected: Dest) {
        let Some(engine) = self.engine.get() else {
            return self.fail(c, socks5_reply(REP_FAILURE, None));
        };
        let local = SocketAddr::new(udp::canon(c.local_addr()).ip(), 0);
        let listener = match std::net::TcpListener::bind(local) {
            Ok(l) if l.set_nonblocking(true).is_ok() => l,
            _ => return self.fail(c, socks5_reply(REP_FAILURE, None)),
        };
        let Ok(bound) = listener.local_addr() else {
            return self.fail(c, socks5_reply(REP_FAILURE, None));
        };
        self.st = St::Binding;
        c.inner().set_relayed(true);
        let _ = c.send_owned(socks5_reply(REP_OK, Some(udp::canon(bound))));
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
            .name("only-socks-bind".into())
            .spawn(move || {
                let stream = loop {
                    if cancel.load(Ordering::Acquire) {
                        return;
                    }
                    match listener.accept() {
                        Ok((s, peer)) if want_ip.is_none_or(|ip| udp::canon(peer).ip() == ip) => {
                            break s;
                        }
                        Ok(_) => {} // someone else: dropped
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                let _ = client.send_owned(socks5_reply(REP_FAILURE, None));
                                return client.close_after_send();
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => {
                            let _ = client.send_owned(socks5_reply(REP_FAILURE, None));
                            return client.close_after_send();
                        }
                    }
                };
                drop(listener);
                let client_up = client.clone();
                let acceptor = UpstreamAcceptor {
                    client: client.clone(),
                    slot,
                    on_up: Arc::new(Mutex::new(Some(Box::new(move |up: &Arc<ConnInner>| {
                        if !client_up.is_open() {
                            return up.close();
                        }
                        let _ = client_up
                            .send_owned(socks5_reply(REP_OK, Some(udp::canon(up.peer_addr()))));
                    }) as OnUp))),
                };
                engine.adopt_tcp(stream, acceptor, move |_e| {
                    let _ = client.send_owned(socks5_reply(REP_FAILURE, None));
                    client.close_after_send();
                });
            });
        if spawned.is_err() {
            self.fail(c, socks5_reply(REP_FAILURE, None));
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
        match udp::Assoc::open(
            &engine,
            c.inner().clone(),
            self.user.clone(),
            self.allow.clone(),
            declared,
            &self.sweeper,
            self.udp_idle,
        ) {
            Ok((a, bound)) => {
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
                    let want = if self.auth.is_some() { 2 } else { 0 };
                    let n = 2 + b[1] as usize;
                    if !methods.contains(&want) {
                        return self.fail(c, vec![5, 0xff]);
                    }
                    let _ = c.send(&[5, want]);
                    self.buf.drain(..n);
                    self.st = if want == 2 { St::Auth } else { St::Request };
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
                        Command::Bind => self.bind(c, target),
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
                    if b[1] != 1 {
                        return self.fail(c, SOCKS4_FAIL.to_vec());
                    }
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
                    if !self.allowed(c, 4, Command::Connect, &target) {
                        return self.fail(c, SOCKS4_FAIL.to_vec());
                    }
                    return self.connect(c, target, false);
                }
                St::Connecting | St::Binding | St::Associated | St::Relaying => return,
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
            let up = self
                .upstream
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            match up {
                Some(up) => {
                    // Bytes buffered behind the request go first.
                    if !self.buf.is_empty() {
                        let pending = std::mem::take(&mut self.buf);
                        forward(c.inner(), &up, &pending);
                    }
                    forward(c.inner(), &up, data);
                    self.st = St::Relaying;
                }
                // Early data while the upstream connects is kept for it; after a failure (the
                // session is closing) there is nobody to give it to.
                None if matches!(self.st, St::Connecting) => self.buf.extend_from_slice(data),
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
        if matches!(self.st, St::Greeting | St::Auth | St::Request | St::Socks4)
            && self.buf.len() > MAX_HANDSHAKE
        {
            self.buf = Vec::new();
            self.st = St::Relaying; // ignore anything else
            c.close();
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
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
            up.close_after_send();
        }
    }
}

// ---- HTTP CONNECT --------------------------------------------------------------------------

/// An HTTP proxy service for `CONNECT host:port` tunnels (use it as a `only-http` service, or
/// mount it in a router's fallback). Other methods get 405.
pub fn connect_proxy(engine: EngineRef) -> impl Service {
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
        ctx.upgrade_raw(Tunnel {
            engine: engine.clone(),
            host: Some((host, port)),
            upstream: Arc::new(Mutex::new(None)),
            pending: Vec::new(),
        });
    }
}

struct Tunnel {
    engine: EngineRef,
    host: Option<(String, u16)>,
    upstream: UpstreamSlot,
    pending: Vec<u8>,
}

impl RawHandler for Tunnel {
    fn on_open(&mut self, conn: &RawConn) {
        conn.inner().set_relayed(true);
        conn.hold_reads(true);
        let (host, port) = self.host.take().expect("opened once");
        let engine = self.engine.clone();
        let slot = self.upstream.clone();
        let client = conn.inner().clone();
        // Resolution may block: a short-lived thread keeps it off the I/O thread (a raw
        // connection has no typed handle for the logical pool).
        std::thread::spawn(move || {
            let addrs: Vec<SocketAddr> = (host.as_str(), port)
                .to_socket_addrs()
                .map(|a| a.collect())
                .unwrap_or_default();
            let c_ok = client.clone();
            let c_fail = client.clone();
            if addrs.is_empty() {
                let _ = client.send(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                return client.close_after_send();
            }
            dial(
                &engine,
                addrs,
                client,
                slot,
                Box::new(move |_up| {
                    let _ = c_ok.send(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    c_ok.hold_reads(false);
                }),
                Box::new(move || {
                    let _ = c_fail.send(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    c_fail.close_after_send();
                }),
            );
        });
    }

    fn on_data(&mut self, conn: &RawConn, data: &[u8]) {
        let up = self
            .upstream
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match up {
            Some(up) => {
                if !self.pending.is_empty() {
                    let p = std::mem::take(&mut self.pending);
                    forward(conn.inner(), &up, &p);
                }
                forward(conn.inner(), &up, data);
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
            up.close_after_send();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a SOCKS4 request whose user id never ends used to be buffered without limit.
    #[test]
    fn endless_socks4_user_id_is_cut_off() {
        let c = only_core::fuzzing::conn();
        let mut s = Socks::new(EngineRef::new()).on_open(&c);
        s.on_data(&c, &[4, 1, 0, 80, 127, 0, 0, 1]);
        for _ in 0..100 {
            s.on_data(&c, &[b'u'; 1000]);
        }
        assert!(s.buf.len() <= MAX_HANDSHAKE);
        assert!(!c.is_open());
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
