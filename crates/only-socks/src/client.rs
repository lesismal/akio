//! The SOCKS client (ADR-019): SOCKS5 `CONNECT`, `BIND` and `UDP ASSOCIATE` with no
//! authentication or username/password, SOCKS4 and SOCKS4a `CONNECT` and `BIND`, on the engine
//! (non-blocking, callbacks on the I/O threads) and as blocking helpers over `std::net`.
//! ADR-059 adds TLS to the proxy ([`SocksClient::tls`], engine methods) and sending UDP
//! datagrams in fragments ([`UdpAssociation::send_fragmented`]).
//!
//! The handshake itself is the sans-io one the HTTP and WebSocket clients use for their
//! `socks5://` / `socks4a://` proxies (`only_ws::proxy`), so a refusal is reported the same
//! way: an `io::Error` carrying [`ProxyRefused`] ([`ProxyRefused::socks_reply`] has the code).

use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use only::{
    Acceptor, Conn, Engine, Handler, Transport, UdpBinding,
    tls::{ClientConfig as TlsClientConfig, Tls},
};
use only_core::ConnInner;
use only_ws::{
    proxy::{Connect, OnBound, Refusal},
    socks::{Cmd, Handshake, Target},
};

pub use only_ws::proxy::ProxyRefused;

use crate::{
    Dest, UpstreamSlot,
    frag::{Frag, Reassembly},
    guard::Watch,
    udp::canon,
};

/// Default [`SocksClient::handshake_timeout`].
pub const DEFAULT_CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default [`SocksClient::bind_timeout`].
pub const DEFAULT_BIND_TIMEOUT: Duration = Duration::from_secs(60);

/// The protocol a [`SocksClient`] speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Version {
    /// SOCKS5 (RFC 1928): IPv4, IPv6 and host names, username/password authentication,
    /// `CONNECT`, `BIND` and `UDP ASSOCIATE`.
    Socks5,
    /// SOCKS4: IPv4 only (host names are resolved by the client first), `CONNECT` and `BIND`;
    /// the user name, if set, is sent as the user id.
    Socks4,
    /// SOCKS4a: SOCKS4 with host names resolved by the proxy.
    Socks4a,
}

impl Version {
    fn wire(self) -> only_ws::socks::Version {
        match self {
            Version::Socks5 => only_ws::socks::Version::Socks5,
            Version::Socks4 => only_ws::socks::Version::Socks4,
            Version::Socks4a => only_ws::socks::Version::Socks4a,
        }
    }
}

fn target(d: &Dest) -> Target {
    match d {
        Dest::Addr(a) => Target::Addr(*a),
        Dest::Name(h, p) => Target::Name(h.clone(), *p),
    }
}

/// The address a reply names, with "the proxy's own address" (unspecified, or a host name)
/// replaced by the address the proxy was reached at.
fn reply_addr(t: &Target, proxy: SocketAddr) -> SocketAddr {
    match t {
        Target::Addr(a) if !a.ip().is_unspecified() => canon(*a),
        Target::Addr(a) => SocketAddr::new(canon(proxy).ip(), a.port()),
        Target::Name(_, port) => SocketAddr::new(canon(proxy).ip(), *port),
    }
}

/// A SOCKS client: which proxy, which protocol, which credentials and timeouts. Cheap to clone.
///
/// ```no_run
/// use only_socks::{Dest, SocksClient};
/// let client = SocksClient::from_url("socks5h://alice:secret@proxy.internal:1080")?;
/// // Blocking: a connected TcpStream through the proxy.
/// let s = client.dial_blocking(&Dest::Name("example.com".into(), 80))?;
/// # drop(s);
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone)]
pub struct SocksClient {
    host: String,
    port: u16,
    version: Version,
    auth: Option<(String, String)>,
    handshake_timeout: Option<Duration>,
    bind_timeout: Option<Duration>,
    /// TLS to the proxy: the configuration and the name to verify (the proxy's host if none).
    tls: Option<(TlsClientConfig, Option<String>)>,
}

impl std::fmt::Debug for SocksClient {
    // Without the credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksClient")
            .field("proxy", &format_args!("{}:{}", self.host, self.port))
            .field("version", &self.version)
            .field("auth", &self.auth.is_some())
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl SocksClient {
    /// A client of the proxy at `proxy` speaking `version`, without credentials.
    pub fn new(version: Version, proxy: SocketAddr) -> SocksClient {
        SocksClient::with_host(version, &proxy.ip().to_string(), proxy.port())
    }

    /// A client of the proxy at `host:port` (a name is resolved when dialling: off the I/O
    /// threads by the engine methods, on the calling thread by the blocking ones).
    pub fn with_host(version: Version, host: &str, port: u16) -> SocksClient {
        SocksClient {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port,
            version,
            auth: None,
            handshake_timeout: Some(DEFAULT_CLIENT_HANDSHAKE_TIMEOUT),
            bind_timeout: Some(DEFAULT_BIND_TIMEOUT),
            tls: None,
        }
    }

    /// From a proxy URL: `socks5://`, `socks5h://` (the same here: a [`Dest::Name`] is always
    /// sent to a SOCKS5 proxy as a name), `socks4://` or `socks4a://`, with optional
    /// percent-encoded `user:password@` and port (1080 by default).
    pub fn from_url(url: &str) -> io::Result<SocksClient> {
        use only_ws::proxy::{ProxyKind, ProxyServer};
        let s = ProxyServer::parse(url)?;
        let version = match s.kind {
            ProxyKind::Socks { version, .. } => match version {
                only_ws::socks::Version::Socks5 => Version::Socks5,
                only_ws::socks::Version::Socks4 => Version::Socks4,
                only_ws::socks::Version::Socks4a => Version::Socks4a,
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a SOCKS URL (socks5://, socks5h://, socks4://, socks4a://)",
                ));
            }
        };
        let mut c = SocksClient::with_host(version, &s.host, s.port);
        c.auth = s.credentials;
        Ok(c)
    }

    /// Username/password authentication (SOCKS5, RFC 1929: offered next to "no
    /// authentication", the proxy chooses; each 1 to 255 bytes). For SOCKS4 the user name is
    /// the user id and the password is ignored.
    #[must_use]
    pub fn auth(mut self, user: &str, password: &str) -> SocksClient {
        self.auth = Some((user.to_owned(), password.to_owned()));
        self
    }

    /// Longest time from starting to connect to the proxy until its (last) reply for `CONNECT`
    /// and `UDP ASSOCIATE`, and until its first reply for `BIND`. Default 10 s; `None`: no
    /// limit. On the engine it bounds the inner transport's handshake too (TLS through the
    /// tunnel), like any `Transport::handshake_timeout`.
    #[must_use]
    pub fn handshake_timeout(mut self, d: Option<Duration>) -> SocksClient {
        self.handshake_timeout = d;
        self
    }

    /// How long a `BIND` waits for the peer to connect (the proxy's second reply) after the
    /// first reply. Default 60 s; `None`: no limit.
    #[must_use]
    pub fn bind_timeout(mut self, d: Option<Duration>) -> SocksClient {
        self.bind_timeout = d;
        self
    }

    /// Speaks to the proxy over TLS (a SOCKS server behind TLS, such as only-socks' [`Socks`]
    /// wrapped in `Tls::server`), verifying its certificate with `cfg` for `server_name`, or
    /// for the proxy's host when `None`. Applies to the engine methods ([`dial`](Self::dial),
    /// [`bind`](Self::bind), and the control connection of
    /// [`udp_associate`](Self::udp_associate); the datagrams themselves stay plain UDP, as
    /// RFC 1928 has them); the blocking helpers return a `TcpStream` and refuse with
    /// `Unsupported`. A `Tls` acceptor given to `dial` then runs TLS inside this one.
    ///
    /// [`Socks`]: crate::Socks
    #[must_use]
    pub fn tls(mut self, cfg: TlsClientConfig, server_name: Option<&str>) -> SocksClient {
        self.tls = Some((cfg, server_name.map(str::to_owned)));
        self
    }

    /// The TLS configuration and name to reach the proxy with, if any.
    fn proxy_tls(&self) -> Option<(TlsClientConfig, String)> {
        self.tls
            .as_ref()
            .map(|(c, n)| (c.clone(), n.clone().unwrap_or_else(|| self.host.clone())))
    }

    fn no_blocking_tls(&self) -> io::Result<()> {
        if self.tls.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS to the proxy needs the engine methods (the blocking ones return a TcpStream)",
            ));
        }
        Ok(())
    }

    /// The protocol.
    pub fn version(&self) -> Version {
        self.version
    }

    fn creds(&self) -> Option<(&str, &str)> {
        self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))
    }

    fn handshake(&self, cmd: Cmd, to: &Dest) -> io::Result<Handshake> {
        Handshake::new(self.version.wire(), cmd, target(to), self.creds())
    }

    /// Whether `to` must be resolved here before asking (a name over SOCKS4).
    fn local_name<'a>(&self, to: &'a Dest) -> Option<(&'a str, u16)> {
        match to {
            Dest::Name(h, p) if self.version == Version::Socks4 => Some((h.as_str(), *p)),
            _ => None,
        }
    }

    // ---- on the engine ---------------------------------------------------------------------

    /// Opens a `CONNECT` tunnel to `to` and serves it with `acceptor`, without blocking.
    ///
    /// The proxy's name (and for SOCKS4 a target name) is resolved off the calling thread, the
    /// proxy dialled (each of its addresses in turn), then `acceptor.on_open` runs on an I/O
    /// thread as soon as the TCP connection to the proxy is up, as for a TLS dial: anything the
    /// handler sends waits until the tunnel is open, and the handler's `on_data` sees the
    /// target's bytes only. `acceptor` may be a `Tls` acceptor: TLS then runs inside the
    /// tunnel. Failing to resolve or reach the proxy calls `on_error`; a refusal, a proxy that
    /// does not speak SOCKS or the [`handshake_timeout`](Self::handshake_timeout) closes the
    /// connection with that error (`on_close`; a refusal carries [`ProxyRefused`]).
    pub fn dial<A: Acceptor>(
        &self,
        engine: &Arc<Engine>,
        to: Dest,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        self.tunnel(engine, Cmd::Connect, to, None, acceptor, Box::new(on_error));
    }

    /// `BIND`: asks the proxy to accept one connection from `from` (the peer's address as far
    /// as known; `0.0.0.0:0` for any), then serves that connection with `acceptor`, without
    /// blocking.
    ///
    /// `on_bound` gets where the proxy listens (its first reply; an unspecified address is
    /// replaced by the proxy's), to tell the peer. It runs on the I/O thread in the middle of
    /// the handshake: it must not use the connection being set up (it may send on others).
    /// `acceptor.on_open` runs when the TCP connection to the proxy is up; the handler's data
    /// flows once the peer has connected (the second reply). The whole exchange is bounded by
    /// [`handshake_timeout`](Self::handshake_timeout) plus
    /// [`bind_timeout`](Self::bind_timeout). Errors as for [`dial`](Self::dial).
    pub fn bind<A: Acceptor>(
        &self,
        engine: &Arc<Engine>,
        from: Dest,
        on_bound: impl FnOnce(SocketAddr) + Send + 'static,
        acceptor: A,
        on_error: impl FnOnce(io::Error) + Send + 'static,
    ) {
        let on_bound: BoundCb = Box::new(on_bound);
        self.tunnel(
            engine,
            Cmd::Bind,
            from,
            Some(on_bound),
            acceptor,
            Box::new(on_error),
        );
    }

    fn tunnel<A: Acceptor>(
        &self,
        engine: &Arc<Engine>,
        cmd: Cmd,
        to: Dest,
        on_bound: Option<BoundCb>,
        acceptor: A,
        on_error: ErrCb,
    ) {
        let me = self.clone();
        let engine = engine.clone();
        let start = move |to: io::Result<Dest>| {
            let hs = match to.and_then(|to| me.handshake(cmd, &to)) {
                Ok(h) => h,
                Err(e) => return on_error(e),
            };
            let timeout = match cmd {
                Cmd::Bind => me
                    .handshake_timeout
                    .zip(me.bind_timeout)
                    .map(|(a, b)| a + b),
                _ => me.handshake_timeout,
            };
            let plan = Arc::new(TunnelPlan {
                hs,
                acceptor: Arc::new(acceptor),
                tls: me.proxy_tls(),
                timeout,
                on_bound: Mutex::new(on_bound),
                on_error: Mutex::new(Some(on_error)),
            });
            let (host, port) = (me.host.clone(), me.port);
            only::dns::resolve(&host, port, move |r| match r {
                Ok(addrs) => dial_tunnel(engine, plan, Arc::new(addrs), 0),
                Err(e) => plan.fail(e),
            });
        };
        match self.local_name(&to) {
            Some((h, p)) => resolve_v4(h, p, move |r| start(r.map(Dest::Addr))),
            None => start(Ok(to)),
        }
    }

    /// `UDP ASSOCIATE` (SOCKS5): opens a UDP relay on the proxy, without blocking.
    ///
    /// A UDP socket is bound on the engine (it needs UDP I/O threads:
    /// `EngineBuilder::udp_client_threads`) and announced to the proxy; `done` gets the
    /// [`UdpAssociation`] once the proxy replies (or the error: unreachable proxy, refusal,
    /// [`handshake_timeout`](Self::handshake_timeout)). `on_datagram` runs on an I/O thread for
    /// every datagram the relay forwards, with the address it came from; fragmented ones are
    /// reassembled first (in order, bounded, RFC 1928's 5 s timer). Datagrams from anywhere but
    /// the relay are dropped. The association lasts until [`UdpAssociation::close`] or until
    /// the proxy closes the control connection.
    pub fn udp_associate(
        &self,
        engine: &Arc<Engine>,
        on_datagram: impl Fn(&UdpAssociation, Dest, &[u8]) + Send + Sync + 'static,
        done: impl FnOnce(io::Result<UdpAssociation>) + Send + 'static,
    ) {
        if self.version != Version::Socks5 {
            return done(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP ASSOCIATE needs SOCKS5",
            )));
        }
        let me = self.clone();
        let engine = engine.clone();
        let on_datagram: OnDatagram = Arc::new(on_datagram);
        let done: DoneCb = Box::new(done);
        only::dns::resolve(&me.host.clone(), me.port, move |r| match r {
            Ok(addrs) if !addrs.is_empty() => udp_open(me, engine, addrs, 0, on_datagram, done),
            Ok(_) => done(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "proxy has no address",
            ))),
            Err(e) => done(Err(e)),
        });
    }

    // ---- blocking --------------------------------------------------------------------------

    /// Connects to the proxy (each of its addresses in turn) and runs the handshake, all
    /// within [`handshake_timeout`](Self::handshake_timeout).
    fn open_blocking(&self, cmd: Cmd, to: &Dest) -> io::Result<(TcpStream, Handshake, Deadline)> {
        self.no_blocking_tls()?;
        let dl = Deadline::new(self.handshake_timeout);
        let resolved;
        let to = match self.local_name(to) {
            Some((h, p)) => {
                resolved = Dest::Addr(first_v4((h, p).to_socket_addrs()?)?);
                &resolved
            }
            None => to,
        };
        let mut hs = self.handshake(cmd, to)?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "proxy has no address");
        for addr in (self.host.as_str(), self.port).to_socket_addrs()? {
            let r = match dl.left()? {
                Some(t) => TcpStream::connect_timeout(&addr, t),
                None => TcpStream::connect(addr),
            };
            match r {
                Ok(s) => {
                    s.set_nodelay(true)?;
                    let mut out = Vec::new();
                    hs.start(&mut out);
                    dl.write(&s, &out)?;
                    return Ok((s, hs, dl));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// A `CONNECT` tunnel to `to` through the proxy, blocking: the returned stream is
    /// connected to the target (its timeouts cleared).
    pub fn dial_blocking(&self, to: &Dest) -> io::Result<TcpStream> {
        let (s, mut hs, dl) = self.open_blocking(Cmd::Connect, to)?;
        read_reply(&s, &mut hs, &dl)?;
        dl.clear(&s)?;
        Ok(s)
    }

    /// `BIND`, blocking: returns once the proxy listens ([`BlockingBind::bound_addr`]); then
    /// [`BlockingBind::accept`] waits for the peer.
    pub fn bind_blocking(&self, from: &Dest) -> io::Result<BlockingBind> {
        let (s, mut hs, dl) = self.open_blocking(Cmd::Bind, from)?;
        let first = read_reply(&s, &mut hs, &dl)?;
        let proxy = s.peer_addr()?;
        Ok(BlockingBind {
            bound: reply_addr(&first.addr, proxy),
            stream: s,
            hs,
            proxy,
            timeout: self.bind_timeout,
        })
    }

    /// `UDP ASSOCIATE` (SOCKS5), blocking: binds a UDP socket on the unspecified address of
    /// the proxy's family, announces it and returns the association.
    pub fn udp_associate_blocking(&self) -> io::Result<BlockingUdp> {
        self.no_blocking_tls()?;
        if self.version != Version::Socks5 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP ASSOCIATE needs SOCKS5",
            ));
        }
        let dl = Deadline::new(self.handshake_timeout);
        let mut last = io::Error::new(io::ErrorKind::NotFound, "proxy has no address");
        for addr in (self.host.as_str(), self.port).to_socket_addrs()? {
            let s = match dl.left()? {
                Some(t) => TcpStream::connect_timeout(&addr, t),
                None => TcpStream::connect(addr),
            };
            let s = match s {
                Ok(s) => s,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let sock = UdpSocket::bind(unspecified(addr))?;
            let declared = unspecified_port(addr, sock.local_addr()?.port());
            let mut hs = Handshake::new(
                only_ws::socks::Version::Socks5,
                Cmd::UdpAssociate,
                Target::Addr(declared),
                self.creds(),
            )?;
            let mut out = Vec::new();
            hs.start(&mut out);
            dl.write(&s, &out)?;
            let r = read_reply(&s, &mut hs, &dl)?;
            dl.clear(&s)?;
            let relay = reply_addr(&r.addr, addr);
            return Ok(BlockingUdp {
                control: s,
                sock,
                relay,
                rx: Mutex::new((Reassembly::default(), vec![0u8; 65_536])),
            });
        }
        Err(last)
    }
}

type BoundCb = Box<dyn FnOnce(SocketAddr) + Send>;
type ErrCb = Box<dyn FnOnce(io::Error) + Send>;
type DoneCb = Box<dyn FnOnce(io::Result<UdpAssociation>) + Send>;
type OnDatagram = Arc<dyn Fn(&UdpAssociation, Dest, &[u8]) + Send + Sync>;

/// Resolves `host:port` off the calling thread to its first IPv4 address (SOCKS4).
fn resolve_v4(host: &str, port: u16, done: impl FnOnce(io::Result<SocketAddr>) + Send + 'static) {
    only::dns::resolve(host, port, move |r| done(r.and_then(first_v4)));
}

fn first_v4(addrs: impl IntoIterator<Item = SocketAddr>) -> io::Result<SocketAddr> {
    addrs
        .into_iter()
        .map(canon)
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no IPv4 address (SOCKS4 carries IPv4 only)",
            )
        })
}

/// What one engine tunnel (`dial` / `bind`) needs across its attempts.
struct TunnelPlan<A> {
    hs: Handshake,
    acceptor: Arc<A>,
    tls: Option<(TlsClientConfig, String)>,
    timeout: Option<Duration>,
    on_bound: Mutex<Option<BoundCb>>,
    on_error: Mutex<Option<ErrCb>>,
}

impl<A> TunnelPlan<A> {
    fn fail(&self, e: io::Error) {
        let cb = self
            .on_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(cb) = cb {
            cb(e);
        }
    }
}

/// The acceptor of one attempt: the dial's own, plus the handshake deadline.
struct Shared<A>(Arc<TunnelPlan<A>>, AttemptWatch);

/// The deadline of one attempt, once its connection is open.
type AttemptWatch = Arc<Mutex<Option<Arc<Watch>>>>;

impl<A: Acceptor> Acceptor for Shared<A> {
    type Handler = A::Handler;
    fn on_open(&self, c: &Conn<A::Handler>) -> A::Handler {
        let slot: UpstreamSlot = Arc::new(Mutex::new(None));
        if let Some(w) = Watch::start(c.inner(), &slot, self.0.timeout, None) {
            let plan = self.0.clone();
            w.on_fire(Box::new(move || {
                plan.fail(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS handshake timed out",
                ));
            }));
            *self.1.lock().unwrap_or_else(|p| p.into_inner()) = Some(w);
        }
        self.0.acceptor.on_open(c)
    }
    fn on_shutdown(&self, c: &Conn<A::Handler>) {
        self.0.acceptor.on_shutdown(c);
    }
    fn transport(&self) -> Option<Box<dyn Transport>> {
        self.0.acceptor.transport()
    }
}

fn dial_tunnel<A: Acceptor>(
    engine: Arc<Engine>,
    plan: Arc<TunnelPlan<A>>,
    addrs: Arc<Vec<SocketAddr>>,
    i: usize,
) {
    let Some(&addr) = addrs.get(i) else {
        return plan.fail(io::Error::new(
            io::ErrorKind::NotFound,
            "proxy has no address",
        ));
    };
    let watch: AttemptWatch = Arc::default();
    let (p1, w1) = (plan.clone(), watch.clone());
    let mut c = Connect::socks(
        Ok(plan.hs.clone()),
        Refusal::default(),
        Shared(plan.clone(), watch),
    )
    .on_fail(Box::new(move |e| p1.fail(e)))
    // The tunnel is up: the deadline no longer applies (the inner transport, TLS, has its
    // own).
    .on_open(Box::new(move || {
        if let Some(w) = w1.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            w.disarm();
        }
    }));
    let on_bound = plan
        .on_bound
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take();
    if let Some(cb) = on_bound {
        let f: OnBound = Box::new(move |r| cb(reply_addr(&r.addr, addr)));
        c = c.on_bound(f);
    }
    if let Some((cfg, name)) = &plan.tls {
        c = match c.over_tls(cfg.clone(), name) {
            Ok(c) => c,
            Err(e) => return plan.fail(e),
        };
    }
    let e2 = engine.clone();
    engine.dial(addr, c, move |e| {
        if i + 1 < addrs.len() {
            dial_tunnel(e2, plan, addrs, i + 1);
        } else {
            plan.fail(e);
        }
    });
}

// ---- UDP on the engine -------------------------------------------------------------------

struct UdpShared {
    binding: UdpBinding,
    relay: OnceLock<SocketAddr>,
    control: OnceLock<Arc<ConnInner>>,
    closed: AtomicBool,
}

/// A SOCKS5 UDP association on the engine ([`SocksClient::udp_associate`]). Cheap to clone;
/// dropping the handles does not end it, [`close`](Self::close) does.
#[derive(Clone)]
pub struct UdpAssociation(Arc<UdpShared>);

impl std::fmt::Debug for UdpAssociation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpAssociation")
            .field("local", &self.local_addr())
            .field("relay", &self.0.relay.get())
            .finish_non_exhaustive()
    }
}

/// Appends the UDP request header for `to` (`RSV FRAG=0 ATYP DST.ADDR DST.PORT`).
fn udp_header(out: &mut Vec<u8>, to: &Dest) -> io::Result<()> {
    udp_header_frag(out, to, 0)
}

/// Sends `payload` to `to` in fragments of at most `max` bytes through `send`, which gets each
/// datagram (header included).
fn send_fragments(
    payload: &[u8],
    to: &Dest,
    max: usize,
    mut send: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let parts = crate::frag::split(payload, max)?;
    let mut d = Vec::with_capacity(max.min(payload.len()) + 262);
    for (frag, piece) in parts {
        d.clear();
        udp_header_frag(&mut d, to, frag)?;
        d.extend_from_slice(piece);
        send(&d)?;
    }
    Ok(())
}

/// The UDP request header with a `FRAG` value.
fn udp_header_frag(out: &mut Vec<u8>, to: &Dest, frag: u8) -> io::Result<()> {
    if matches!(to, Dest::Name(h, _) if h.is_empty() || h.len() > 255) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 host names are 1 to 255 bytes",
        ));
    }
    out.extend_from_slice(&[0, 0, frag]);
    only_ws::socks::push_addr(out, &target(to));
    Ok(())
}

impl UdpAssociation {
    /// Sends `payload` to `to` through the relay (one datagram; a [`Dest::Name`] is resolved
    /// by the proxy). Like any UDP send it may be dropped (`WouldBlock` when the socket's
    /// buffer is full).
    pub fn send_to(&self, payload: &[u8], to: &Dest) -> io::Result<()> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "association closed",
            ));
        }
        let relay = *self.0.relay.get().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "association not established")
        })?;
        let mut d = Vec::with_capacity(payload.len() + 22);
        udp_header(&mut d, to)?;
        d.extend_from_slice(payload);
        self.0.binding.send_to(&d, relay)
    }

    /// Sends `payload` to `to` in fragments of at most `max` bytes each (RFC 1928 `FRAG`
    /// 1, 2, ..., the last with the high bit set), for a path whose MTU is known to be small;
    /// as one datagram when it fits. The proxy must reassemble fragments (only-socks does;
    /// many proxies drop them). `InvalidInput` when it would take more than 127 fragments
    /// (`max` below `payload.len() / 127`), `max` is 0 or `payload` is larger than 65,507
    /// bytes.
    pub fn send_fragmented(&self, payload: &[u8], to: &Dest, max: usize) -> io::Result<()> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "association closed",
            ));
        }
        let relay = *self.0.relay.get().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "association not established")
        })?;
        send_fragments(payload, to, max, |d| self.0.binding.send_to(d, relay))
    }

    /// The proxy's relay address datagrams go to.
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.0.relay.get().copied()
    }

    /// The local UDP socket's address.
    pub fn local_addr(&self) -> SocketAddr {
        self.0.binding.local_addr()
    }

    /// Whether the association is still open.
    pub fn is_open(&self) -> bool {
        !self.0.closed.load(Ordering::Acquire)
    }

    /// Ends the association: closes the control connection and the UDP socket. Idempotent.
    pub fn close(&self) {
        if !self.0.closed.swap(true, Ordering::AcqRel) {
            if let Some(c) = self.0.control.get() {
                c.close();
            }
            self.0.binding.close();
        }
    }
}

fn unspecified(proxy: SocketAddr) -> SocketAddr {
    match proxy {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn unspecified_port(proxy: SocketAddr, port: u16) -> SocketAddr {
    SocketAddr::new(unspecified(proxy).ip(), port)
}

/// Opens the association through the proxy's address `addrs[i]`; when it cannot be reached,
/// through the next one.
fn udp_open(
    client: SocksClient,
    engine: Arc<Engine>,
    addrs: Vec<SocketAddr>,
    i: usize,
    on_datagram: OnDatagram,
    done: DoneCb,
) {
    let proxy = addrs[i];
    let slot: Arc<OnceLock<UdpAssociation>> = Arc::new(OnceLock::new());
    let binding = match engine.bind_udp(
        unspecified(proxy),
        RelayIn {
            assoc: slot.clone(),
            on_datagram: on_datagram.clone(),
        },
    ) {
        Ok(b) => b,
        Err(e) => return done(Err(e)),
    };
    let declared = unspecified_port(proxy, binding.local_addr().port());
    let hs = match Handshake::new(
        only_ws::socks::Version::Socks5,
        Cmd::UdpAssociate,
        Target::Addr(declared),
        client.creds(),
    ) {
        Ok(h) => h,
        Err(e) => {
            binding.close();
            return done(Err(e));
        }
    };
    let assoc = UdpAssociation(Arc::new(UdpShared {
        binding,
        relay: OnceLock::new(),
        control: OnceLock::new(),
        closed: AtomicBool::new(false),
    }));
    let _ = slot.set(assoc.clone());
    let done = Arc::new(Mutex::new(Some(done)));
    let acceptor = ControlAcceptor {
        hs,
        assoc: assoc.clone(),
        proxy,
        done: done.clone(),
        timeout: client.handshake_timeout,
    };
    let tls = client.proxy_tls();
    let e2 = engine.clone();
    let on_err = move |e| {
        assoc.close();
        let cb = done.lock().unwrap_or_else(|p| p.into_inner()).take();
        let Some(cb) = cb else { return };
        if i + 1 < addrs.len() {
            // Not reachable there (`localhost` is often ::1 first): the next address.
            udp_open(client, e2, addrs, i + 1, on_datagram, cb);
        } else {
            cb(Err(e));
        }
    };
    match tls {
        Some((cfg, name)) => match Tls::client(cfg, &name, acceptor) {
            Ok(a) => engine.dial(proxy, a, on_err),
            Err(e) => on_err(e),
        },
        None => engine.dial(proxy, acceptor, on_err),
    }
}

struct ControlAcceptor {
    hs: Handshake,
    assoc: UdpAssociation,
    proxy: SocketAddr,
    done: Arc<Mutex<Option<DoneCb>>>,
    timeout: Option<Duration>,
}

impl Acceptor for ControlAcceptor {
    type Handler = Control;
    fn on_open(&self, c: &Conn<Control>) -> Control {
        let _ = self.assoc.0.control.set(c.inner().clone());
        let mut hs = self.hs.clone();
        let mut out = Vec::new();
        hs.start(&mut out);
        let _ = c.send_owned(out);
        let slot: UpstreamSlot = Arc::new(Mutex::new(None));
        Control {
            hs,
            assoc: self.assoc.clone(),
            proxy: self.proxy,
            done: self.done.clone(),
            err: None,
            watch: Watch::start(c.inner(), &slot, self.timeout, None),
        }
    }
}

/// The TCP control connection of a UDP association.
struct Control {
    hs: Handshake,
    assoc: UdpAssociation,
    proxy: SocketAddr,
    done: Arc<Mutex<Option<DoneCb>>>,
    err: Option<io::Error>,
    watch: Option<Arc<Watch>>,
}

impl Control {
    fn finish(&self, r: io::Result<UdpAssociation>) {
        let cb = self.done.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(cb) = cb {
            cb(r);
        }
    }
}

impl Handler for Control {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if self.hs.is_done() {
            return; // RFC 1928: nothing more comes on the control connection
        }
        let mut out = Vec::new();
        match self.hs.feed(data, &mut out) {
            Ok((_, Some(r))) => {
                if let Some(w) = &self.watch {
                    w.disarm();
                }
                let _ = self.assoc.0.relay.set(reply_addr(&r.addr, self.proxy));
                self.finish(Ok(self.assoc.clone()));
            }
            Ok((_, None)) => {
                if !out.is_empty() {
                    let _ = c.send_owned(out);
                }
            }
            Err(e) => {
                self.err = Some(e);
                c.close();
            }
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<only::Error>) {
        self.assoc.close();
        let e = self.err.take().unwrap_or_else(|| match err {
            Some(only::Error::Io(e)) => e,
            _ => io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "proxy closed the control connection",
            ),
        });
        self.finish(Err(e));
    }
}

struct RelayIn {
    assoc: Arc<OnceLock<UdpAssociation>>,
    on_datagram: OnDatagram,
}

impl Acceptor for RelayIn {
    type Handler = RelayPeer;
    fn on_open(&self, _c: &Conn<RelayPeer>) -> RelayPeer {
        RelayPeer {
            assoc: self.assoc.clone(),
            on_datagram: self.on_datagram.clone(),
            reasm: Reassembly::default(),
        }
    }
}

/// One peer of the client's UDP socket: only the relay's datagrams are taken.
struct RelayPeer {
    assoc: Arc<OnceLock<UdpAssociation>>,
    on_datagram: OnDatagram,
    reasm: Reassembly,
}

impl Handler for RelayPeer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let Some(a) = self.assoc.get() else { return };
        if a.0.relay.get() != Some(&canon(c.peer_addr())) || !a.is_open() {
            return;
        }
        let Some((frag, from, n)) = crate::udp::parse_header(data) else {
            return;
        };
        let payload = &data[n..];
        if frag == 0 {
            self.reasm.reset();
            return (self.on_datagram)(a, from, payload);
        }
        if let Frag::Complete(from, whole) = self.reasm.push(Instant::now(), frag, &from, payload) {
            (self.on_datagram)(a, from, &whole);
        }
    }
}

// ---- blocking helpers ----------------------------------------------------------------------

/// A handshake deadline for the blocking helpers.
struct Deadline(Option<Instant>);

impl Deadline {
    fn new(d: Option<Duration>) -> Deadline {
        Deadline(d.map(|d| Instant::now() + d))
    }

    /// Time left (`None`: no limit); `TimedOut` once past.
    fn left(&self) -> io::Result<Option<Duration>> {
        match self.0 {
            None => Ok(None),
            Some(t) => {
                let left = t.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "SOCKS handshake timed out",
                    ))
                } else {
                    Ok(Some(left))
                }
            }
        }
    }

    // macOS refuses `setsockopt` with EINVAL once the peer has closed the connection: a
    // failure to set a timeout is ignored, the read or write that follows reports the state.
    fn write(&self, mut s: &TcpStream, b: &[u8]) -> io::Result<()> {
        let _ = s.set_write_timeout(self.left()?);
        s.write_all(b)
    }

    fn clear(&self, s: &TcpStream) -> io::Result<()> {
        let _ = s.set_read_timeout(None);
        let _ = s.set_write_timeout(None);
        Ok(())
    }
}

/// Reads byte by byte (so that nothing past the reply is consumed: it belongs to the caller)
/// until the handshake yields a reply.
fn read_reply(
    mut s: &TcpStream,
    hs: &mut Handshake,
    dl: &Deadline,
) -> io::Result<only_ws::socks::Reply> {
    let mut b = [0u8; 1];
    let _ = s.set_read_timeout(dl.left()?);
    loop {
        dl.left()?;
        match s.read(&mut b) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "proxy closed the connection during the SOCKS handshake",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS handshake timed out",
                ));
            }
            Err(e) => return Err(e),
        }
        let mut out = Vec::new();
        let (_, reply) = hs.feed(&b, &mut out)?;
        if !out.is_empty() {
            dl.write(s, &out)?;
        }
        if let Some(r) = reply {
            return Ok(r);
        }
    }
}

/// A blocking `BIND` whose first reply came ([`SocksClient::bind_blocking`]).
#[derive(Debug)]
pub struct BlockingBind {
    stream: TcpStream,
    hs: Handshake,
    bound: SocketAddr,
    proxy: SocketAddr,
    timeout: Option<Duration>,
}

impl BlockingBind {
    /// Where the proxy listens for the peer (an unspecified address in the reply is replaced
    /// by the proxy's).
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound
    }

    /// Waits (up to [`SocksClient::bind_timeout`]) for the peer to connect: returns the stream,
    /// now relayed to the peer, and the peer's address as the proxy reports it.
    pub fn accept(mut self) -> io::Result<(TcpStream, SocketAddr)> {
        let dl = Deadline::new(self.timeout);
        let r = read_reply(&self.stream, &mut self.hs, &dl)?;
        dl.clear(&self.stream)?;
        Ok((self.stream, reply_addr(&r.addr, self.proxy)))
    }
}

/// A blocking SOCKS5 UDP association ([`SocksClient::udp_associate_blocking`]); it ends when
/// dropped (the control connection closes).
#[derive(Debug)]
pub struct BlockingUdp {
    control: TcpStream,
    sock: UdpSocket,
    relay: SocketAddr,
    /// Reassembly queue and receive buffer.
    rx: Mutex<(Reassembly, Vec<u8>)>,
}

impl BlockingUdp {
    /// Sends `payload` to `to` through the relay (one datagram).
    pub fn send_to(&self, payload: &[u8], to: &Dest) -> io::Result<()> {
        let mut d = Vec::with_capacity(payload.len() + 22);
        udp_header(&mut d, to)?;
        d.extend_from_slice(payload);
        self.sock.send_to(&d, self.relay).map(|_| ())
    }

    /// [`UdpAssociation::send_fragmented`], blocking.
    pub fn send_fragmented(&self, payload: &[u8], to: &Dest, max: usize) -> io::Result<()> {
        send_fragments(payload, to, max, |d| {
            self.sock.send_to(d, self.relay).map(|_| ())
        })
    }

    /// Receives the next datagram the relay forwards: its length (cut to `buf`, as UDP does)
    /// and where it came from. Fragmented datagrams are reassembled; datagrams from anywhere
    /// but the relay are skipped. Honours [`set_read_timeout`](Self::set_read_timeout) per
    /// datagram received.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Dest)> {
        let mut rx = self.rx.lock().unwrap_or_else(|p| p.into_inner());
        let (reasm, tmp) = &mut *rx;
        loop {
            let (n, peer) = self.sock.recv_from(tmp)?;
            if canon(peer) != self.relay {
                continue;
            }
            let Some((frag, from, h)) = crate::udp::parse_header(&tmp[..n]) else {
                continue;
            };
            let copy = |buf: &mut [u8], p: &[u8]| {
                let k = p.len().min(buf.len());
                buf[..k].copy_from_slice(&p[..k]);
                k
            };
            if frag == 0 {
                reasm.reset();
                return Ok((copy(buf, &tmp[h..n]), from));
            }
            if let Frag::Complete(from, whole) = reasm.push(Instant::now(), frag, &from, &tmp[h..n])
            {
                return Ok((copy(buf, &whole), from));
            }
        }
    }

    /// Timeout of [`recv_from`](Self::recv_from) (`None`: block).
    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(d)
    }

    /// The proxy's relay address.
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    /// The local UDP socket's address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    /// Whether the proxy still holds the association: `false` once it closed the control
    /// connection (checked without blocking).
    pub fn is_open(&self) -> bool {
        let mut b = [0u8; 1];
        if self.control.set_nonblocking(true).is_err() {
            return false;
        }
        let open = match (&self.control).read(&mut b) {
            Ok(0) => false,
            Ok(_) => true,
            Err(e) => e.kind() == io::ErrorKind::WouldBlock,
        };
        let _ = self.control.set_nonblocking(false);
        open
    }
}
