//! The WebSocket client: dial `ws://` and `wss://` URLs on a `akio` [`Engine`].
//!
//! [`dial`] resolves the host (on a resolver thread, [`akio::dns`]), connects without blocking
//! (trying every resolved address in turn, through a [`Proxy`] with `CONNECT` when one applies),
//! runs TLS through `akio::tls` for `wss://` (the system's CAs unless [`DialOptions::tls`] says
//! otherwise), performs the opening handshake (following redirects when
//! [`DialOptions::max_redirects`] allows) and then serves the connection with the same
//! [`WsHandler`] model the server uses: callbacks on the connection's I/O thread, [`WsSender`] to
//! send from any thread. Frames are masked, `permessage-deflate` is offered when
//! [`WsConfig::permessage_deflate`] is set. When the engine shuts down gracefully, open
//! connections are closed with status 1001 (going away). [`dial_blocking`] is the blocking
//! convenience that waits for the handshake.
//!
//! ```no_run
//! use std::sync::Arc;
//! use akio::Engine;
//! use akio_ws::{Message, WsHandler, WsSender, client::{self, DialOptions}};
//!
//! struct Print;
//! impl WsHandler for Print {
//!     fn on_message(&mut self, _ws: &WsSender, msg: Message) {
//!         println!("{msg:?}");
//!     }
//! }
//!
//! let engine = Arc::new(Engine::builder().client_threads(1).build().unwrap());
//! engine.start().unwrap();
//! let ws = client::dial_blocking(&engine, "ws://127.0.0.1:8080/ws", &DialOptions::default(), Print).unwrap();
//! ws.send_text("hello").unwrap();
//! ```

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak, mpsc},
    time::{Duration, Instant},
};

use akio::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, RootCerts, Tls},
};
use akio_core::ConnInner;

use crate::{
    Message, WsConfig, WsHandler, WsSender, WsSession, accept_key,
    deflate::PmdOffer,
    http1,
    proxy::{Connect, Proxy, Refusal},
};

/// How to dial.
#[derive(Clone)]
#[non_exhaustive]
pub struct DialOptions {
    /// Message limits and compression; `permessage_deflate` decides whether it is offered.
    pub config: WsConfig,
    /// What the `permessage-deflate` offer asks for.
    pub pmd: PmdOffer,
    /// Subprotocols to offer, in order of preference (`Sec-WebSocket-Protocol`). The server's
    /// choice is available from [`WsSender::subprotocol`].
    pub protocols: Vec<String>,
    /// `Origin` header, for servers that check it.
    pub origin: Option<String>,
    /// Extra request header fields (e.g. `Authorization`, cookies). Fields the handshake itself
    /// sets (`Host`, `Upgrade`, `Connection`, `Sec-WebSocket-*`) are ignored here.
    pub headers: Vec<(String, String)>,
    /// TLS client configuration for `wss://` (roots, client certificate, ALPN...); do not offer
    /// `h2` in its ALPN list. `None`: the system's trusted CAs ([`RootCerts::system`]).
    pub tls: Option<TlsClientConfig>,
    /// Name for certificate verification and SNI; the URL's host by default.
    pub server_name: Option<String>,
    /// Limit for connecting plus the TLS and WebSocket handshakes.
    pub handshake_timeout: Duration,
    /// After the close handshake, how long to wait for the server to close the TCP connection
    /// before closing it from this side.
    pub close_timeout: Duration,
    /// HTTP proxy: every connection it applies to is tunnelled with `CONNECT`. None by default;
    /// [`Proxy::from_env`] reads the usual environment variables.
    pub proxy: Proxy,
    /// How many redirects (301, 302, 303, 307, 308 with a `Location`) the handshake may follow;
    /// 0 (the default) reports them as [`WsClientError::Status`]. `http`/`https` locations
    /// become `ws`/`wss`; a `wss://` handshake never follows a redirect to `ws://`; a redirect
    /// to another origin drops `Authorization`, `Cookie` and `Proxy-Authorization` from
    /// [`headers`](Self::headers). The [`handshake_timeout`](Self::handshake_timeout) covers the
    /// whole chain.
    pub max_redirects: u32,
    /// How the addresses of the server (or the proxy) are raced (RFC 8305: IPv6 and IPv4
    /// interleaved, a new attempt every 250 ms by default).
    pub happy_eyeballs: akio::dns::HappyEyeballs,
}

impl Default for DialOptions {
    fn default() -> Self {
        DialOptions {
            config: WsConfig::default(),
            pmd: PmdOffer::default(),
            protocols: Vec::new(),
            origin: None,
            headers: Vec::new(),
            tls: None,
            server_name: None,
            handshake_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(3),
            proxy: Proxy::none(),
            max_redirects: 0,
            happy_eyeballs: akio::dns::HappyEyeballs::default(),
        }
    }
}

impl std::fmt::Debug for DialOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialOptions")
            .field("config", &self.config)
            .field("pmd", &self.pmd)
            .field("protocols", &self.protocols)
            .field("origin", &self.origin)
            .field("headers", &self.headers)
            .field("tls", &self.tls.is_some())
            .field("server_name", &self.server_name)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("close_timeout", &self.close_timeout)
            .field("proxy", &self.proxy)
            .field("max_redirects", &self.max_redirects)
            .finish()
    }
}

/// Why a dial failed (before `on_open`).
#[derive(Debug)]
#[non_exhaustive]
pub enum WsClientError {
    /// The URL is not a usable `ws://` or `wss://` URL.
    InvalidUrl(String),
    /// Resolving, connecting, TLS or the connection itself failed.
    Io(io::Error),
    /// The server answered with something other than `101 Switching Protocols`.
    Status(u16, String),
    /// The server's `101` answer is not a valid WebSocket handshake.
    Handshake(&'static str),
    /// [`DialOptions::handshake_timeout`] passed.
    Timeout,
    /// The connection closed before the handshake completed.
    Closed,
    /// More redirects than [`DialOptions::max_redirects`] allows (or a redirect loop).
    TooManyRedirects,
}

impl std::fmt::Display for WsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsClientError::InvalidUrl(u) => write!(f, "invalid WebSocket url: {u}"),
            WsClientError::Io(e) => write!(f, "io: {e}"),
            WsClientError::Status(s, r) => write!(f, "handshake refused: {s} {r}"),
            WsClientError::Handshake(m) => write!(f, "bad handshake: {m}"),
            WsClientError::Timeout => f.write_str("handshake timed out"),
            WsClientError::Closed => f.write_str("connection closed during the handshake"),
            WsClientError::TooManyRedirects => f.write_str("too many redirects"),
        }
    }
}

impl std::error::Error for WsClientError {}

/// A parsed `ws://` / `wss://` URL.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WsUrl {
    tls: bool,
    host: String,
    port: u16,
    target: String,
    host_header: String,
}

pub(crate) fn parse_url(url: &str) -> Result<WsUrl, WsClientError> {
    let bad = || WsClientError::InvalidUrl(url.to_owned());
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "ws" => false,
        "wss" => true,
        _ => return Err(bad()),
    };
    if rest.contains('#') {
        return Err(bad()); // RFC 6455 3: fragments are not allowed
    }
    let (authority, target) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_owned()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    let default_port = if tls { 443 } else { 80 };
    let (host_part, port) = if let Some(after) = authority.strip_prefix('[') {
        let (h, tail) = after.split_once(']').ok_or_else(bad)?;
        let port = match tail {
            "" => default_port,
            t => t
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .ok_or_else(bad)?,
        };
        (h, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| bad())?),
            None => (authority, default_port),
        }
    };
    if host_part.is_empty() {
        return Err(bad());
    }
    let shown = if authority.starts_with('[') {
        format!("[{host_part}]")
    } else {
        host_part.to_owned()
    };
    let host_header = if port == default_port {
        shown
    } else {
        format!("{shown}:{port}")
    };
    Ok(WsUrl {
        tls,
        host: host_part.to_owned(),
        port,
        target,
        host_header,
    })
}

type ErrCb = Box<dyn FnOnce(WsClientError) + Send>;

/// What one dial still owns until it resolves (opens or fails).
struct Pending {
    handler: Option<Box<dyn WsHandler>>,
    on_error: Option<ErrCb>,
    /// The connection being handshaken, for the timeout to close.
    conn: Option<Weak<ConnInner>>,
    timed_out: bool,
}

impl Pending {
    fn resolved(&self) -> bool {
        self.on_error.is_none()
    }
}

/// Everything a dial needs, shared by its address attempts.
struct Plan {
    engine: Arc<Engine>,
    /// The URL this handshake goes to (after any redirects).
    url: String,
    secure: bool,
    host: String,
    port: u16,
    opts: DialOptions,
    /// Redirects still allowed.
    redirects_left: u32,
    deadline: Instant,
    /// The resolved addresses (of the target, or of the proxy).
    addrs: OnceLock<Vec<SocketAddr>>,
    /// The proxy this dial goes through, if any.
    proxy: Option<crate::proxy::ProxyServer>,
    /// The target as the tunnel names it: the host, or its address when the proxy wants
    /// addresses (`socks5://`, `socks4://`); set before dialling.
    tunnel_host: OnceLock<String>,
    /// Where the current attempt's tunnel records a refusal.
    refusal: Mutex<Option<Refusal>>,
    tls: Option<(TlsClientConfig, String)>,
    request: Vec<u8>,
    expected_accept: String,
    config: WsConfig,
    pmd: Option<PmdOffer>,
    protocols: Vec<String>,
    close_timeout: Duration,
    pending: Mutex<Pending>,
}

impl Plan {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reports `e` unless the dial already resolved.
    fn fail(&self, e: WsClientError) {
        let cb = {
            let mut p = self.lock();
            p.handler = None;
            p.on_error.take()
        };
        if let Some(cb) = cb {
            cb(e);
        }
    }

    /// The proxy's refusal of the current tunnel, as the error to report.
    fn refused(&self) -> Option<WsClientError> {
        let slot = self.refusal.lock().unwrap_or_else(|p| p.into_inner());
        let r = slot.as_ref()?.lock().unwrap_or_else(|p| p.into_inner());
        r.as_ref().map(|r| WsClientError::Io(r.to_io()))
    }
}

/// The system's CAs as a client configuration.
fn system_tls() -> io::Result<TlsClientConfig> {
    RootCerts::system()
        .and_then(|r| TlsClientConfig::builder().roots(r).build())
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))
}

/// Dials `url` and serves the connection with `handler` once the handshake succeeds
/// (`on_open` runs then, on an I/O thread). On failure before that, `on_error` is called once
/// instead (on an I/O thread, a resolver thread when the name does not resolve, the calling
/// thread for an invalid URL, or the timer thread when the handshake times out while
/// connecting); the handler is dropped unused.
///
/// The engine must be started; connections run on its client threads
/// ([`EngineBuilder::client_threads`](akio::EngineBuilder::client_threads)) when it has them.
/// Names are resolved off the calling thread ([`akio::dns::resolve`]).
pub fn dial(
    engine: &Arc<Engine>,
    url: &str,
    opts: &DialOptions,
    handler: impl WsHandler,
    on_error: impl FnOnce(WsClientError) + Send + 'static,
) {
    start(
        engine.clone(),
        url.to_owned(),
        opts.clone(),
        opts.max_redirects,
        Instant::now() + opts.handshake_timeout,
        Box::new(handler),
        Box::new(on_error),
    );
}

/// One handshake attempt (the first, or one after a redirect).
fn start(
    engine: Arc<Engine>,
    url: String,
    opts: DialOptions,
    redirects_left: u32,
    deadline: Instant,
    handler: Box<dyn WsHandler>,
    on_error: ErrCb,
) {
    let u = match parse_url(&url) {
        Ok(u) => u,
        Err(e) => return on_error(e),
    };
    let tls = if u.tls {
        let cfg = match opts.tls.clone().map_or_else(system_tls, Ok) {
            Ok(c) => c,
            Err(e) => return on_error(WsClientError::Io(e)),
        };
        Some((
            cfg,
            opts.server_name.clone().unwrap_or_else(|| u.host.clone()),
        ))
    } else {
        None
    };
    let key = new_key();
    let pmd = opts.config.permessage_deflate.then_some(opts.pmd);
    let request = build_request(&u, &key, &opts, pmd.as_ref());
    let proxy = opts.proxy.select(u.tls, &u.host, u.port).cloned();
    let (dial_host, dial_port) = match &proxy {
        Some(p) => (p.host.clone(), p.port),
        None => (u.host.clone(), u.port),
    };
    let plan = Arc::new(Plan {
        engine,
        url,
        secure: u.tls,
        host: u.host,
        port: u.port,
        redirects_left,
        deadline,
        addrs: OnceLock::new(),
        tunnel_host: OnceLock::new(),
        proxy,
        refusal: Mutex::new(None),
        tls,
        request,
        expected_accept: accept_key(&key),
        config: opts.config.clone(),
        pmd,
        protocols: opts.protocols.clone(),
        close_timeout: opts.close_timeout,
        opts,
        pending: Mutex::new(Pending {
            handler: Some(handler),
            on_error: Some(on_error),
            conn: None,
            timed_out: false,
        }),
    });
    let weak = Arc::downgrade(&plan);
    crate::timer::after(
        deadline.saturating_duration_since(Instant::now()),
        move || {
            let Some(plan) = weak.upgrade() else { return };
            let conn = {
                let mut p = plan.lock();
                if p.resolved() {
                    return;
                }
                p.timed_out = true;
                p.conn.as_ref().map(Weak::upgrade)
            };
            match conn {
                // Handshaking: closing it reports the timeout from the I/O thread.
                Some(Some(c)) => c.close(),
                // Resolving, connecting (or the connection is already gone): report it now.
                _ => plan.fail(WsClientError::Timeout),
            }
        },
    );
    let resolve_dial = move |plan: Arc<Plan>| {
        akio::dns::resolve(&dial_host, dial_port, move |r| match r {
            Ok(addrs) => {
                let _ = plan.addrs.set(addrs);
                dial_addrs(plan);
            }
            Err(e) => plan.fail(WsClientError::Io(e)),
        });
    };
    let local = plan.proxy.as_ref().is_some_and(|p| p.resolves_locally())
        && plan.host.parse::<std::net::IpAddr>().is_err();
    if !local {
        let _ = plan.tunnel_host.set(plan.host.clone());
        return resolve_dial(plan);
    }
    // A SOCKS proxy that takes addresses only: resolve the target here first.
    akio::dns::resolve(&plan.host.clone(), plan.port, move |r| {
        let socks4 = plan.proxy.as_ref().is_some_and(|p| p.is_socks4());
        match r.and_then(|a| crate::proxy::pick_target(a, socks4)) {
            Ok(a) => {
                let _ = plan.tunnel_host.set(a.ip().to_string());
                resolve_dial(plan);
            }
            Err(e) => plan.fail(WsClientError::Io(e)),
        }
    });
}

/// Runs the tunnel over TLS to the proxy when it is an `https://` one.
fn over_proxy_tls<A: Acceptor>(
    c: Connect<A>,
    tls: &Option<(TlsClientConfig, String)>,
) -> io::Result<Connect<A>> {
    match tls {
        Some((cfg, name)) => c.over_tls(cfg.clone(), name),
        None => Ok(c),
    }
}

fn dial_addrs(plan: Arc<Plan>) {
    if plan.lock().resolved() {
        return; // timed out while resolving
    }
    let addrs = plan.addrs.get().cloned().unwrap_or_default();
    let acceptor = ClientAcceptor { plan: plan.clone() };
    let on_err = {
        let plan = plan.clone();
        move |e: io::Error| plan.fail(WsClientError::Io(e))
    };
    let engine = plan.engine.clone();
    let he = plan.opts.happy_eyeballs;
    let tunnel_host = plan.tunnel_host.get().unwrap_or(&plan.host).clone();
    let tunnel = || {
        let r = Refusal::default();
        *plan.refusal.lock().unwrap_or_else(|p| p.into_inner()) = Some(r.clone());
        r
    };
    // TLS to the proxy itself (`https://` proxies), checked with the same configuration.
    let proxy_tls = match &plan.proxy {
        Some(p) if p.tls => {
            let cfg = match &plan.tls {
                Some((cfg, _)) => Ok(cfg.clone()),
                None => plan.opts.tls.clone().map_or_else(system_tls, Ok),
            };
            match cfg {
                Ok(c) => Some((c, p.host.clone())),
                Err(e) => return plan.fail(WsClientError::Io(e)),
            }
        }
        _ => None,
    };
    let r = match (&plan.tls, &plan.proxy) {
        (Some((cfg, name)), proxy) => Tls::client(cfg.clone(), name, acceptor).and_then(|a| {
            match proxy {
                Some(p) => {
                    let c = Connect::new(&tunnel_host, plan.port, p, tunnel(), a);
                    let c = over_proxy_tls(c, &proxy_tls)?;
                    he.dial(&engine, addrs, c, on_err);
                }
                None => he.dial(&engine, addrs, a, on_err),
            }
            Ok(())
        }),
        (None, Some(p)) => {
            let c = Connect::new(&tunnel_host, plan.port, p, tunnel(), acceptor);
            over_proxy_tls(c, &proxy_tls).map(|c| he.dial(&engine, addrs, c, on_err))
        }
        (None, None) => {
            he.dial(&engine, addrs, acceptor, on_err);
            Ok(())
        }
    };
    if let Err(e) = r {
        plan.fail(WsClientError::Io(e));
    }
}

/// Where a redirect response sends the handshake: `Ok(None)` when it is not one to follow.
fn redirect_target(plan: &Plan, buf: &[u8]) -> Result<Option<String>, WsClientError> {
    let mut storage = [http1::Header::EMPTY; 64];
    let Ok(http1::Status::Complete(r)) =
        http1::parse_response(buf, &mut storage, &mut http1::Resume::default())
    else {
        return Ok(None);
    };
    if plan.opts.max_redirects == 0 || !matches!(r.code, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let Some(loc) = r
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("location"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
    else {
        return Ok(None);
    };
    if plan.redirects_left == 0 {
        return Err(WsClientError::TooManyRedirects);
    }
    let next = crate::url::resolve(&plan.url, loc)
        .ok_or_else(|| WsClientError::InvalidUrl(loc.to_owned()))?;
    let next = match next.split_once("://") {
        Some(("http", rest)) => format!("ws://{rest}"),
        Some(("https", rest)) => format!("wss://{rest}"),
        Some(("ws" | "wss", _)) => next,
        _ => return Err(WsClientError::InvalidUrl(next)),
    };
    if plan.secure && next.starts_with("ws://") {
        return Ok(None); // never downgrade from TLS
    }
    Ok(Some(next))
}

/// Like [`dial`], blocking until the handshake completes; returns the connection's sender.
/// `handler.on_open` has been called (or is about to be) when this returns. Do not call it on
/// an I/O thread of the same engine.
pub fn dial_blocking(
    engine: &Arc<Engine>,
    url: &str,
    opts: &DialOptions,
    handler: impl WsHandler,
) -> Result<WsSender, WsClientError> {
    let (tx, rx) = mpsc::channel();
    let tx2 = tx.clone();
    dial(
        engine,
        url,
        opts,
        Notify {
            inner: Box::new(handler),
            tx: Some(tx),
        },
        move |e| {
            let _ = tx2.send(Err(e));
        },
    );
    // The handshake timeout always resolves the dial; the margin only guards against a bug.
    rx.recv_timeout(opts.handshake_timeout + Duration::from_secs(5))
        .unwrap_or(Err(WsClientError::Timeout))
}

/// Forwards to the application's handler, reporting the open to [`dial_blocking`].
struct Notify {
    inner: Box<dyn WsHandler>,
    tx: Option<mpsc::Sender<Result<WsSender, WsClientError>>>,
}

impl WsHandler for Notify {
    fn on_open(&mut self, ws: &WsSender) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Ok(ws.clone()));
        }
        self.inner.on_open(ws);
    }
    fn on_message(&mut self, ws: &WsSender, msg: Message) {
        self.inner.on_message(ws, msg);
    }
    fn on_pong(&mut self, ws: &WsSender, payload: &[u8]) {
        self.inner.on_pong(ws, payload);
    }
    fn on_close(&mut self, code: Option<u16>, reason: &str) {
        self.inner.on_close(code, reason);
    }
}

fn new_key() -> String {
    let mut k = [0u8; 16];
    if akio_crypto::rand::fill_random(&mut k).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        k = t.to_le_bytes();
    }
    akio_crypto::base64::STANDARD.encode(k)
}

fn build_request(u: &WsUrl, key: &str, opts: &DialOptions, pmd: Option<&PmdOffer>) -> Vec<u8> {
    let clean = |v: &str| v.replace(['\r', '\n'], "");
    let mut r = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
        u.target, u.host_header
    );
    if !opts.protocols.is_empty() {
        r.push_str(&format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            clean(&opts.protocols.join(", "))
        ));
    }
    if let Some(o) = pmd {
        r.push_str(&format!("Sec-WebSocket-Extensions: {}\r\n", o.header()));
    }
    if let Some(origin) = &opts.origin {
        r.push_str(&format!("Origin: {}\r\n", clean(origin)));
    }
    let mut ua = false;
    for (n, v) in &opts.headers {
        let lower = n.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "upgrade" | "connection" | "origin")
            || lower.starts_with("sec-websocket-")
            || n.contains([':', '\r', '\n'])
        {
            continue;
        }
        ua |= lower == "user-agent";
        r.push_str(&format!("{n}: {}\r\n", clean(v)));
    }
    if !ua {
        r.push_str("User-Agent: akio-ws\r\n");
    }
    r.push_str("\r\n");
    r.into_bytes()
}

struct ClientAcceptor {
    plan: Arc<Plan>,
}

impl Acceptor for ClientAcceptor {
    type Handler = ClientConn;

    fn on_open(&self, c: &Conn<ClientConn>) -> ClientConn {
        let resolved = {
            let mut p = self.plan.lock();
            p.conn = Some(Arc::downgrade(c.inner()));
            p.resolved()
        };
        if resolved {
            c.close(); // timed out while connecting
        } else if c.send(&self.plan.request).is_err() {
            c.close();
        }
        ClientConn {
            plan: Some(self.plan.clone()),
            buf: Vec::new(),
            ws: None,
        }
    }

    // A graceful engine shutdown closes open WebSocket connections with 1001 (going away) and
    // the close handshake; a connection still handshaking is dropped.
    fn on_shutdown(&self, c: &Conn<ClientConn>) {
        let queued = c.spawn_blocking(
            || (),
            |h: &mut ClientConn, c, ()| match &h.ws {
                Some(ws) => ws.going_away(),
                None => c.close(),
            },
        );
        if queued.is_err() {
            c.close();
        }
    }
}

/// The connection handler of a dialed WebSocket: handshake, then the session.
struct ClientConn {
    plan: Option<Arc<Plan>>,
    buf: Vec<u8>,
    ws: Option<WsSession>,
}

/// Largest response head accepted.
const MAX_HEAD: usize = 16 << 10;

impl ClientConn {
    fn handshake(&mut self, c: &Conn<Self>) {
        let Some(plan) = self.plan.clone() else {
            return;
        };
        match check_response(
            &plan.expected_accept,
            &plan.protocols,
            plan.pmd.as_ref(),
            &self.buf,
        ) {
            Ok(None) => {
                if self.buf.len() > MAX_HEAD {
                    self.plan = None;
                    plan.fail(WsClientError::Handshake("response head too large"));
                    c.close();
                }
            }
            Err(e) => {
                self.plan = None;
                c.close();
                if let WsClientError::Status(..) = e {
                    match redirect_target(&plan, &self.buf) {
                        Ok(Some(next)) => return follow(&plan, next),
                        Ok(None) => {}
                        Err(e) => return plan.fail(e),
                    }
                }
                plan.fail(e);
            }
            Ok(Some(ok)) => {
                self.plan = None;
                let handler = {
                    let mut p = plan.lock();
                    p.on_error = None;
                    p.conn = None;
                    p.handler.take()
                };
                let Some(handler) = handler else {
                    c.close();
                    return;
                };
                let rest = self.buf.split_off(ok.head_len);
                self.buf = Vec::new();
                let mut ws = WsSession::client(
                    c.inner().clone(),
                    &plan.config,
                    ok.pmd,
                    handler,
                    ok.protocol,
                    plan.close_timeout,
                );
                ws.open();
                if !rest.is_empty() {
                    ws.on_data(&rest);
                }
                self.ws = Some(ws);
            }
        }
    }
}

/// Starts the handshake again at `next`, moving the handler and error callback over.
fn follow(plan: &Plan, next: String) {
    let (handler, on_error) = {
        let mut p = plan.lock();
        (p.handler.take(), p.on_error.take())
    };
    let (Some(handler), Some(on_error)) = (handler, on_error) else {
        return; // timed out meanwhile
    };
    let mut opts = plan.opts.clone();
    let same_origin = parse_url(&next).is_ok_and(|u| {
        u.tls == plan.secure && u.host.eq_ignore_ascii_case(&plan.host) && u.port == plan.port
    });
    if !same_origin {
        opts.headers.retain(|(n, _)| {
            !["authorization", "cookie", "proxy-authorization"]
                .iter()
                .any(|s| n.eq_ignore_ascii_case(s))
        });
        // The server name given for the first host does not apply to another one.
        opts.server_name = None;
    }
    start(
        plan.engine.clone(),
        next,
        opts,
        plan.redirects_left - 1,
        plan.deadline,
        handler,
        on_error,
    );
}

pub(crate) struct Accepted {
    pub(crate) head_len: usize,
    pmd: Option<crate::deflate::PmdParams>,
    protocol: Option<String>,
}

/// Validates the server's handshake response; `Ok(None)` while it is incomplete.
pub(crate) fn check_response(
    expected_accept: &str,
    protocols: &[String],
    pmd: Option<&PmdOffer>,
    buf: &[u8],
) -> Result<Option<Accepted>, WsClientError> {
    let mut storage = [http1::Header::EMPTY; 64];
    let r = match http1::parse_response(buf, &mut storage, &mut http1::Resume::default()) {
        Ok(http1::Status::Complete(r)) => r,
        Ok(http1::Status::Partial) => return Ok(None),
        Err(_) => return Err(WsClientError::Handshake("malformed response head")),
    };
    let head_len = r.len;
    let status = r.code;
    if status != 101 {
        return Err(WsClientError::Status(status, r.reason.to_owned()));
    }
    let values = |name: &'static str| {
        r.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .filter_map(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    let has_token = |name: &'static str, token: &str| {
        values(name).any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    if !has_token("upgrade", "websocket") {
        return Err(WsClientError::Handshake("missing Upgrade: websocket"));
    }
    if !has_token("connection", "upgrade") {
        return Err(WsClientError::Handshake("missing Connection: Upgrade"));
    }
    let mut accept = values("sec-websocket-accept");
    if accept.next() != Some(expected_accept) || accept.next().is_some() {
        return Err(WsClientError::Handshake("wrong Sec-WebSocket-Accept"));
    }
    let mut protos = values("sec-websocket-protocol");
    let protocol = match (protos.next(), protos.next()) {
        (None, _) => None,
        (Some(p), None) if protocols.iter().any(|o| o == p) => Some(p.to_owned()),
        _ => {
            return Err(WsClientError::Handshake(
                "server selected a subprotocol that was not offered",
            ));
        }
    };
    let pmd = match pmd {
        Some(offer) => offer
            .accept_response(values("sec-websocket-extensions"))
            .map_err(WsClientError::Handshake)?,
        None => {
            if values("sec-websocket-extensions").any(|v| !v.is_empty()) {
                return Err(WsClientError::Handshake(
                    "server accepted an extension that was not offered",
                ));
            }
            None
        }
    };
    Ok(Some(Accepted {
        head_len,
        pmd,
        protocol,
    }))
}

impl Handler for ClientConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(ws) = self.ws.as_mut() {
            ws.on_data(data);
            return;
        }
        if self.plan.is_none() {
            return; // failed handshake, closing
        }
        self.buf.extend_from_slice(data);
        self.handshake(c);
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<akio::Error>) {
        if let Some(ws) = self.ws.as_mut() {
            ws.on_transport_closed();
            return;
        }
        if let Some(plan) = self.plan.take() {
            let timed_out = plan.lock().timed_out;
            let refused = plan.refused();
            plan.fail(match (err, refused) {
                _ if timed_out => WsClientError::Timeout,
                (_, Some(r)) => r,
                (Some(akio::Error::Io(e)), None) => WsClientError::Io(e),
                (Some(e), None) => WsClientError::Io(io::Error::other(e.to_string())),
                (None, None) => WsClientError::Closed,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("ws://example.com/chat?x=1").unwrap();
        assert_eq!(
            u,
            WsUrl {
                tls: false,
                host: "example.com".into(),
                port: 80,
                target: "/chat?x=1".into(),
                host_header: "example.com".into(),
            }
        );
        let u = parse_url("WSS://example.com:8443").unwrap();
        assert!(u.tls);
        assert_eq!((u.port, u.target.as_str()), (8443, "/"));
        assert_eq!(u.host_header, "example.com:8443");
        let u = parse_url("wss://example.com:443/").unwrap();
        assert_eq!(u.host_header, "example.com");
        let u = parse_url("ws://h?q").unwrap();
        assert_eq!(u.target, "/?q");
        let u = parse_url("ws://[::1]:9000/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 9000));
        assert_eq!(u.host_header, "[::1]:9000");
        let u = parse_url("ws://[::1]/").unwrap();
        assert_eq!((u.port, u.host_header.as_str()), (80, "[::1]"));
        for bad in [
            "http://x/",
            "example.com",
            "ws:///x",
            "ws://u@h/",
            "ws://h:port/",
            "ws://h/#frag",
            "ws://[::1/",
            "ws://[::1]x/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn request_has_the_handshake_fields() {
        let u = parse_url("ws://example.com:9000/ws").unwrap();
        let opts = DialOptions {
            protocols: vec!["chat".into(), "v2".into()],
            origin: Some("http://example.com".into()),
            headers: vec![
                ("Authorization".into(), "Bearer x\r\nEvil: 1".into()),
                ("Host".into(), "ignored".into()),
                ("Sec-WebSocket-Key".into(), "ignored".into()),
            ],
            ..DialOptions::default()
        };
        let r = String::from_utf8(build_request(
            &u,
            "dGhlIHNhbXBsZSBub25jZQ==",
            &opts,
            Some(&PmdOffer::default()),
        ))
        .unwrap();
        assert!(
            r.starts_with("GET /ws HTTP/1.1\r\nHost: example.com:9000\r\n"),
            "{r}"
        );
        assert!(r.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(r.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(r.contains("Sec-WebSocket-Protocol: chat, v2\r\n"));
        assert!(
            r.contains("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n")
        );
        assert!(r.contains("Origin: http://example.com\r\n"));
        assert!(r.contains("Authorization: Bearer xEvil: 1\r\n"));
        assert!(r.contains("User-Agent: akio-ws\r\n"));
        assert_eq!(r.matches("Host:").count(), 1);
        assert_eq!(r.matches("Sec-WebSocket-Key:").count(), 1);
        assert!(r.ends_with("\r\n\r\n"));
        // Keys are fresh, valid base64 of 16 bytes.
        let (a, b) = (new_key(), new_key());
        assert_ne!(a, b);
        assert!(crate::valid_key(&a));
    }
}
