//! Proxies for the clients (ADR-010, SOCKS in ADR-019): which proxy a URL goes through, and the
//! tunnel through it.
//!
//! A [`Proxy`] holds one proxy for `http://` / `ws://` targets and one for `https://` /
//! `wss://` targets, plus `NO_PROXY`-style exceptions. Nothing reads the environment unless
//! asked: [`Proxy::from_env`] is the opt-in. The WebSocket client tunnels every connection with
//! `CONNECT host:port`; only-http's client tunnels `https://` the same way and sends `http://`
//! requests to the proxy in absolute form.
//!
//! Proxy URLs:
//! - `http://[user:password@]host[:port]` (port 80): an HTTP proxy; credentials become
//!   `Proxy-Authorization: Basic`.
//! - `https://[user:password@]host[:port]` (port 443): an HTTP proxy reached over TLS (ADR-059;
//!   the certificate is checked against the proxy's host name with the client's TLS
//!   configuration, the system's CAs by default). An `https://` target then runs TLS inside
//!   TLS: one session with the proxy, one with the target through the tunnel.
//! - `socks5://` and `socks5h://` (port 1080): SOCKS5 (RFC 1928), with username/password
//!   authentication (RFC 1929) when the URL has credentials. `socks5h` sends host names to the
//!   proxy, `socks5` resolves them first (curl's convention); every request, `http://` ones
//!   included, goes through a tunnel to the target.
//! - `socks4://` and `socks4a://` (port 1080): SOCKS4 (IPv4 targets, resolved here) and SOCKS4a
//!   (host names resolved by the proxy); the URL's user name is the SOCKS4 user id.
//!
//! A SOCKS refusal is reported like an HTTP one, as a [`ProxyRefused`] with the closest HTTP
//! status ([`ProxyRefused::socks_reply`] has the SOCKS code).
//!
//! ```
//! use only_ws::proxy::Proxy;
//! let p = Proxy::all("http://proxy.internal:3128").unwrap().no_proxy("localhost, .corp.example");
//! assert!(p.applies(false, "example.com", 80));
//! assert!(!p.applies(true, "api.corp.example", 443));
//! ```

use std::{
    any::Any,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use only::{Acceptor, Conn, Transport};

use crate::http1;

/// Which proxy to use for which target. The default uses none.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Proxy {
    http: Option<ProxyServer>,
    https: Option<ProxyServer>,
    no_proxy: Vec<NoProxy>,
}

impl std::fmt::Debug for Proxy {
    // Without the credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let show = |s: &Option<ProxyServer>| s.as_ref().map(|s| format!("{}:{}", s.host, s.port));
        f.debug_struct("Proxy")
            .field("http", &show(&self.http))
            .field("https", &show(&self.https))
            .field("no_proxy", &self.no_proxy.len())
            .finish()
    }
}

impl Proxy {
    /// No proxy (same as `Proxy::default()`).
    pub fn none() -> Proxy {
        Proxy::default()
    }

    /// `url` (`http://[user:password@]host[:port]`, port 80 by default; `host:port` alone also
    /// works; or a SOCKS URL, see the [module docs](self)) for every target.
    pub fn all(url: &str) -> io::Result<Proxy> {
        let s = ProxyServer::parse(url)?;
        Ok(Proxy {
            http: Some(s.clone()),
            https: Some(s),
            no_proxy: Vec::new(),
        })
    }

    /// Uses `url` for `http://` and `ws://` targets.
    pub fn http(mut self, url: &str) -> io::Result<Proxy> {
        self.http = Some(ProxyServer::parse(url)?);
        Ok(self)
    }

    /// Uses `url` for `https://` and `wss://` targets (tunnelled with `CONNECT`).
    pub fn https(mut self, url: &str) -> io::Result<Proxy> {
        self.https = Some(ProxyServer::parse(url)?);
        Ok(self)
    }

    /// Adds exceptions in `NO_PROXY` syntax: comma-separated host names (matching the name and
    /// its subdomains; a leading `.` or `*.` is optional), IP addresses, CIDR blocks
    /// (`10.0.0.0/8`), any of them with `:port`, or `*` for every target.
    #[must_use]
    pub fn no_proxy(mut self, list: &str) -> Proxy {
        self.no_proxy.extend(
            list.split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .filter_map(NoProxy::parse),
        );
        self
    }

    /// The proxies the environment names: `http_proxy` / `HTTP_PROXY`, `https_proxy` /
    /// `HTTPS_PROXY`, `all_proxy` / `ALL_PROXY` for targets neither names (typically
    /// `socks5h://…`) and `no_proxy` / `NO_PROXY` (lower case first). `HTTP_PROXY` is ignored
    /// when `REQUEST_METHOD` is set (a CGI request could set it through a `Proxy:` header,
    /// "httpoxy"). Empty when none is set; an error when a value is not a usable proxy URL, so
    /// that a misconfigured proxy is not silently bypassed.
    pub fn from_env() -> io::Result<Proxy> {
        Proxy::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> io::Result<Proxy> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let cgi = get("REQUEST_METHOD").is_some();
        let mut p = Proxy::none();
        let http = get("http_proxy").or_else(|| if cgi { None } else { get("HTTP_PROXY") });
        if let Some(u) = http {
            p = p.http(u.trim())?;
        }
        if let Some(u) = get("https_proxy").or_else(|| get("HTTPS_PROXY")) {
            p = p.https(u.trim())?;
        }
        if let Some(u) = get("all_proxy").or_else(|| get("ALL_PROXY")) {
            let s = ProxyServer::parse(u.trim())?;
            p.http.get_or_insert_with(|| s.clone());
            p.https.get_or_insert(s);
        }
        if let Some(l) = get("no_proxy").or_else(|| get("NO_PROXY")) {
            p = p.no_proxy(&l);
        }
        Ok(p)
    }

    /// Whether no proxy is configured.
    pub fn is_empty(&self) -> bool {
        self.http.is_none() && self.https.is_none()
    }

    /// Whether a connection to `host:port` (`secure`: `https://` / `wss://`) goes through a
    /// proxy.
    pub fn applies(&self, secure: bool, host: &str, port: u16) -> bool {
        self.select(secure, host, port).is_some()
    }

    /// The proxy for a target, if any. Not public API.
    #[doc(hidden)]
    pub fn select(&self, secure: bool, host: &str, port: u16) -> Option<&ProxyServer> {
        let s = if secure { &self.https } else { &self.http }.as_ref()?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let ip = host.parse::<IpAddr>().ok();
        if self.no_proxy.iter().any(|n| n.matches(&host, ip, port)) {
            return None;
        }
        Some(s)
    }
}

/// One proxy server. Not public API (reached through [`Proxy::select`]).
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyServer {
    /// Host name or IP address (no brackets).
    pub host: String,
    /// Port.
    pub port: u16,
    /// `Proxy-Authorization` value, from credentials in the URL (HTTP proxies).
    pub authorization: Option<String>,
    /// What the proxy speaks.
    pub kind: ProxyKind,
    /// TLS to the proxy itself (`https://` proxy URLs).
    pub tls: bool,
    /// User name and password from the URL (SOCKS proxies; SOCKS4 uses the name as user id).
    pub credentials: Option<(String, String)>,
}

/// What a proxy speaks. Not public API.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    /// HTTP: `CONNECT`, or absolute-form requests.
    Http,
    /// SOCKS; `remote_dns`: host names go to the proxy (`socks5h`, `socks4a`), else the client
    /// resolves them first (`socks5`, `socks4`).
    Socks {
        /// The protocol.
        version: crate::socks::Version,
        /// Whether the proxy resolves host names.
        remote_dns: bool,
    },
}

impl std::fmt::Debug for ProxyServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProxyServer({:?}{} {}:{})",
            self.kind,
            if self.tls { " over TLS" } else { "" },
            self.host,
            self.port
        )
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl ProxyServer {
    /// Whether this is an HTTP proxy (`http://` requests go to it in absolute form).
    pub fn is_http(&self) -> bool {
        self.kind == ProxyKind::Http
    }

    /// Whether a target's host name must be resolved before the tunnel is asked for
    /// (`socks5://`, `socks4://`).
    pub fn resolves_locally(&self) -> bool {
        matches!(
            self.kind,
            ProxyKind::Socks {
                remote_dns: false,
                ..
            }
        )
    }

    /// Whether this is a SOCKS4 proxy (IPv4 targets only).
    pub fn is_socks4(&self) -> bool {
        matches!(
            self.kind,
            ProxyKind::Socks {
                version: crate::socks::Version::Socks4,
                ..
            }
        )
    }

    /// Parses a proxy URL (see the [module docs](self)).
    pub fn parse(url: &str) -> io::Result<ProxyServer> {
        let bad = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unusable proxy url ({why})"),
            )
        };
        use crate::socks::Version;
        let socks = |version, remote_dns| ProxyKind::Socks {
            version,
            remote_dns,
        };
        let mut tls = false;
        let (kind, rest) = match url.split_once("://") {
            Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
                "http" => (ProxyKind::Http, rest),
                "https" => {
                    tls = true;
                    (ProxyKind::Http, rest)
                }
                "socks5" => (socks(Version::Socks5, false), rest),
                "socks5h" => (socks(Version::Socks5, true), rest),
                "socks4" => (socks(Version::Socks4, false), rest),
                "socks4a" => (socks(Version::Socks4a, true), rest),
                _ => {
                    return Err(bad(
                        "supported proxies: http://, https://, socks5://, socks5h://, socks4://, socks4a://",
                    ));
                }
            },
            None => (ProxyKind::Http, url),
        };
        let default_port = match kind {
            ProxyKind::Http if tls => 443,
            ProxyKind::Http => 80,
            ProxyKind::Socks { .. } => 1080,
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (host, port) = if let Some(after) = hostport.strip_prefix('[') {
            let (h, tail) = after.split_once(']').ok_or_else(|| bad("bad IPv6 host"))?;
            let port = match tail {
                "" => default_port,
                t => t
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| bad("bad port"))?,
            };
            (h, port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h, p.parse().map_err(|_| bad("bad port"))?),
                None => (hostport, default_port),
            }
        };
        if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err(bad("no host"));
        }
        let credentials = userinfo.map(|u| {
            let (user, pass) = u.split_once(':').unwrap_or((u, ""));
            (percent_decode(user), percent_decode(pass))
        });
        let (authorization, credentials) = match kind {
            ProxyKind::Http => (
                credentials.map(|(u, p)| {
                    let cred = format!("{u}:{p}");
                    format!("Basic {}", only_crypto::base64::STANDARD.encode(cred))
                }),
                None,
            ),
            ProxyKind::Socks { .. } => (None, credentials),
        };
        Ok(ProxyServer {
            host: host.to_owned(),
            port,
            authorization,
            kind,
            tls,
            credentials,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NoProxy {
    All,
    /// Lower-case domain without a leading dot, optional port.
    Domain(String, Option<u16>),
    /// An address or a CIDR block (prefix length), optional port.
    Net(IpAddr, u8, Option<u16>),
}

impl NoProxy {
    fn parse(e: &str) -> Option<NoProxy> {
        if e == "*" {
            return Some(NoProxy::All);
        }
        // CIDR first (`::/0` contains colons but no port).
        if let Some((a, len)) = e.split_once('/') {
            let ip: IpAddr = a.trim_matches(['[', ']']).parse().ok()?;
            let len: u8 = len.parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            return (len <= max).then_some(NoProxy::Net(ip, len, None));
        }
        if let Ok(ip) = e.parse::<IpAddr>() {
            let full = if ip.is_ipv4() { 32 } else { 128 };
            return Some(NoProxy::Net(ip, full, None));
        }
        let (host, port) = if let Some(after) = e.strip_prefix('[') {
            let (h, tail) = after.split_once(']')?;
            (h, tail.strip_prefix(':').and_then(|p| p.parse().ok()))
        } else {
            match e.rsplit_once(':') {
                Some((h, p)) => (h, Some(p.parse().ok()?)),
                None => (e, None),
            }
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            let full = if ip.is_ipv4() { 32 } else { 128 };
            return Some(NoProxy::Net(ip, full, port));
        }
        let d = host
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        (!d.is_empty()).then_some(NoProxy::Domain(d, port))
    }

    fn matches(&self, host: &str, ip: Option<IpAddr>, port: u16) -> bool {
        let port_ok = |p: &Option<u16>| p.is_none_or(|p| p == port);
        match self {
            NoProxy::All => true,
            NoProxy::Domain(d, p) => {
                port_ok(p)
                    && (host == d
                        || (host.len() > d.len()
                            && host.ends_with(d.as_str())
                            && host.as_bytes()[host.len() - d.len() - 1] == b'.'))
            }
            NoProxy::Net(net, len, p) => {
                port_ok(p)
                    && ip.is_some_and(|ip| match (ip, net) {
                        (IpAddr::V4(a), IpAddr::V4(n)) => prefix_eq(&a.octets(), &n.octets(), *len),
                        (IpAddr::V6(a), IpAddr::V6(n)) => prefix_eq(&a.octets(), &n.octets(), *len),
                        _ => false,
                    })
            }
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let (whole, rest) = (usize::from(bits / 8), bits % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[whole] & mask == b[whole] & mask
}

/// The address a SOCKS proxy that takes addresses only (`socks5://`, `socks4://`) is asked
/// for, from a target's resolved addresses: the first IPv4 one (the tunnel gets one address,
/// and `localhost` and dual-stack names often list `::1` or an IPv6 address first that the
/// target does not listen on), else the first; IPv4 only for SOCKS4. Not public API.
#[doc(hidden)]
pub fn pick_target(
    addrs: Vec<std::net::SocketAddr>,
    socks4: bool,
) -> io::Result<std::net::SocketAddr> {
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| if socks4 { None } else { addrs.first() })
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no usable address for the proxy"))
}

/// The proxy answered `CONNECT` with something other than 2xx. Carried inside the
/// `io::Error` a client reports (`std::io::Error::get_ref` + `downcast_ref`).
///
/// A SOCKS proxy's refusal is reported the same way: [`status`](Self::status) is the closest
/// HTTP status (407 for failed or missing authentication, 403 for "not allowed", 502 for
/// failures to reach the target, 501 for unsupported requests, 504 for an expired TTL),
/// [`reason`](Self::reason) the SOCKS meaning and [`socks_reply`](Self::socks_reply) the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRefused {
    status: u16,
    reason: String,
    /// SOCKS version label and reply code.
    socks: Option<(&'static str, u8)>,
}

impl ProxyRefused {
    /// A SOCKS refusal. Not public API.
    #[doc(hidden)]
    pub fn socks(version: &'static str, code: u8, status: u16, reason: &str) -> ProxyRefused {
        ProxyRefused {
            status,
            reason: reason.to_owned(),
            socks: Some((version, code)),
        }
    }

    /// The proxy's status code (`407`: it wants credentials); for a SOCKS proxy the closest
    /// HTTP status.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The proxy's reason phrase (for a SOCKS proxy, what its reply code means).
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// For a SOCKS proxy, its reply code (SOCKS5 `REP`, SOCKS4 `CD`; 0xff when no
    /// authentication method was acceptable or authentication failed); `None` for an HTTP
    /// proxy.
    pub fn socks_reply(&self) -> Option<u8> {
        self.socks.map(|(_, c)| c)
    }

    /// As an `io::Error` (`PermissionDenied` for 401/403/407, `ConnectionRefused` otherwise).
    #[doc(hidden)]
    pub fn to_io(&self) -> io::Error {
        let kind = if matches!(self.status, 401 | 403 | 407) {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::ConnectionRefused
        };
        io::Error::new(kind, self.clone())
    }
}

impl std::fmt::Display for ProxyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.socks {
            Some((v, code)) => write!(f, "{v} proxy refused: {} (reply {code:#04x})", self.reason),
            None => write!(f, "proxy refused CONNECT: {} {}", self.status, self.reason),
        }
    }
}

impl std::error::Error for ProxyRefused {}

/// Where a tunnel records a refusal, for the client to report it when the connection closes.
#[doc(hidden)]
pub type Refusal = Arc<Mutex<Option<ProxyRefused>>>;

/// Called with a `BIND`'s first reply (where the proxy listens), on the I/O thread in the
/// middle of the handshake: it must not use the connection being set up.
#[doc(hidden)]
pub type OnBound = Box<dyn FnOnce(&crate::socks::Reply) + Send>;

/// Called once when the tunnel fails before it opens (the proxy refused, answered garbage, or
/// the request could not be expressed), on the I/O thread: it must not use the connection.
#[doc(hidden)]
pub type OnFail = Box<dyn FnOnce(io::Error) + Send>;

/// Called once when the tunnel opens, on the I/O thread: it must not use the connection.
#[doc(hidden)]
pub type OnOpen = Box<dyn FnOnce() + Send>;

/// The callbacks of one tunnel.
#[derive(Default)]
struct Hooks {
    bound: Mutex<Option<OnBound>>,
    fail: Mutex<Option<OnFail>>,
    open: Mutex<Option<OnOpen>>,
    /// The tunnel is open (failures no longer go to `fail`).
    opened: std::sync::atomic::AtomicBool,
}

fn take<T>(m: &Mutex<Option<T>>) -> Option<T> {
    m.lock().unwrap_or_else(|p| p.into_inner()).take()
}

enum Mode {
    /// The `CONNECT` request.
    Http(Vec<u8>),
    /// The SOCKS handshake to run (cloned per connection; an error to report instead when the
    /// request cannot be expressed).
    Socks(Result<crate::socks::Handshake, (io::ErrorKind, String)>),
}

/// Wraps an acceptor (plain, or `Tls<A>`) so that its connection, dialed to the proxy, first
/// opens a tunnel to `host:port` (HTTP `CONNECT`, or a SOCKS handshake); the inner acceptor's
/// transport (TLS) runs inside it. Not public API.
#[doc(hidden)]
pub struct Connect<A> {
    mode: Mode,
    refusal: Refusal,
    hooks: Arc<Hooks>,
    timeout: Option<std::time::Duration>,
    /// TLS to the proxy, under the tunnel.
    outer: Option<only::tls::Tls<Nop>>,
    inner: A,
}

impl<A> std::fmt::Debug for Connect<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connect").finish_non_exhaustive()
    }
}

impl<A: Acceptor> Connect<A> {
    /// A tunnel to `host:port` through `proxy`; a refusal is recorded in `refusal`. For a
    /// SOCKS proxy that does not resolve names (`socks5://`, `socks4://`), `host` should
    /// already be an address.
    pub fn new(
        host: &str,
        port: u16,
        proxy: &ProxyServer,
        refusal: Refusal,
        inner: A,
    ) -> Connect<A> {
        use crate::socks::{Cmd, Handshake, Target};
        if let ProxyKind::Socks { version, .. } = proxy.kind {
            let auth = proxy
                .credentials
                .as_ref()
                .map(|(u, p)| (u.as_str(), p.as_str()));
            let hs = Handshake::new(version, Cmd::Connect, Target::parse(host, port), auth);
            return Connect::socks(hs, refusal, inner);
        }
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut r = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(a) = &proxy.authorization {
            r.push_str(&format!("Proxy-Authorization: {a}\r\n"));
        }
        r.push_str("\r\n");
        Connect {
            mode: Mode::Http(r.into_bytes()),
            refusal,
            hooks: Arc::default(),
            timeout: None,
            outer: None,
            inner,
        }
    }

    /// A tunnel opened by the SOCKS handshake `hs` (an error from building it is reported when
    /// the connection opens); a refusal is recorded in `refusal`.
    pub fn socks(
        hs: io::Result<crate::socks::Handshake>,
        refusal: Refusal,
        inner: A,
    ) -> Connect<A> {
        Connect {
            mode: Mode::Socks(hs.map_err(|e| (e.kind(), e.to_string()))),
            refusal,
            hooks: Arc::default(),
            timeout: None,
            outer: None,
            inner,
        }
    }

    /// Runs `f` with a `BIND`'s first reply.
    #[must_use]
    pub fn on_bound(self, f: OnBound) -> Connect<A> {
        *self.hooks.bound.lock().unwrap_or_else(|p| p.into_inner()) = Some(f);
        self
    }

    /// Runs `f` with the error when the tunnel fails before it opens (the connection then
    /// closes; its handler's `on_close` gets no error, the engine does not pass transport
    /// errors on).
    #[must_use]
    pub fn on_fail(self, f: OnFail) -> Connect<A> {
        *self.hooks.fail.lock().unwrap_or_else(|p| p.into_inner()) = Some(f);
        self
    }

    /// Runs `f` when the tunnel opens.
    #[must_use]
    pub fn on_open(self, f: OnOpen) -> Connect<A> {
        *self.hooks.open.lock().unwrap_or_else(|p| p.into_inner()) = Some(f);
        self
    }

    /// Runs the tunnel over TLS to the proxy (`https://` proxies, SOCKS over TLS), checking its
    /// certificate for `server_name` with `cfg`.
    pub fn over_tls(
        mut self,
        cfg: only::tls::ClientConfig,
        server_name: &str,
    ) -> io::Result<Connect<A>> {
        self.outer = Some(only::tls::Tls::client(cfg, server_name, Nop)?);
        Ok(self)
    }

    /// Closes the connection when the tunnel (and the inner transport's handshake) is not up
    /// within `d` ([`Transport::handshake_timeout`]).
    #[must_use]
    pub fn handshake_timeout(mut self, d: Option<std::time::Duration>) -> Connect<A> {
        self.timeout = d;
        self
    }
}

impl<A: Acceptor> Acceptor for Connect<A> {
    type Handler = A::Handler;

    fn on_open(&self, c: &Conn<A::Handler>) -> A::Handler {
        self.inner.on_open(c)
    }

    fn on_shutdown(&self, c: &Conn<A::Handler>) {
        self.inner.on_shutdown(c);
    }

    fn transport(&self) -> Option<Box<dyn Transport>> {
        let inner = self.inner.transport();
        let (request, socks) = match &self.mode {
            Mode::Http(r) => (Some(r.clone()), None),
            Mode::Socks(hs) => (None, Some(hs.clone())),
        };
        let tunnel = Box::new(Tunnel {
            request,
            socks,
            hooks: self.hooks.clone(),
            timeout: self.timeout,
            started: false,
            head: Vec::new(),
            open: false,
            held: Vec::new(),
            inner,
            refusal: self.refusal.clone(),
            waker: None,
            gss: Arc::default(),
            gss_running: false,
        });
        match self.outer.as_ref().and_then(Acceptor::transport) {
            Some(outer) => {
                let mut l = Layered::new(outer, tunnel);
                l.hooks = Some(self.hooks.clone());
                Some(Box::new(l))
            }
            None => Some(tunnel),
        }
    }
}

/// An acceptor that only lends its TLS transport ([`Connect::over_tls`]); never opens.
#[doc(hidden)]
#[derive(Debug)]
pub struct Nop;

#[doc(hidden)]
#[derive(Debug)]
pub struct NopHandler;

impl only::Handler for NopHandler {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
}

impl Acceptor for Nop {
    type Handler = NopHandler;
    fn on_open(&self, _c: &Conn<NopHandler>) -> NopHandler {
        NopHandler
    }
}

/// One transport over another: `outer` (TLS to the proxy) carries what `inner` (the tunnel,
/// and the target's transport inside it) puts on the wire. Not public API.
#[doc(hidden)]
pub struct Layered {
    outer: Box<dyn Transport>,
    inner: Box<dyn Transport>,
    /// The outer transport's plaintext (the inner one's wire bytes, in).
    down: Vec<u8>,
    /// The inner transport's wire bytes, out.
    up: Vec<u8>,
    /// The tunnel's hooks: a failure of the outer transport before the tunnel opened goes to
    /// its `on_fail`.
    hooks: Option<Arc<Hooks>>,
}

impl std::fmt::Debug for Layered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layered")
            .field("outer", &self.outer.name())
            .field("inner", &self.inner.name())
            .finish()
    }
}

impl Layered {
    /// `inner` over `outer`.
    pub fn new(outer: Box<dyn Transport>, inner: Box<dyn Transport>) -> Layered {
        Layered {
            outer,
            inner,
            down: Vec::new(),
            up: Vec::new(),
            hooks: None,
        }
    }

    fn send_up(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.up.is_empty() {
            return Ok(());
        }
        let r = self.outer.seal(&self.up, out);
        self.up.clear();
        r
    }
}

impl Transport for Layered {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        self.down.clear();
        if let Err(e) = self.outer.recv(cipher, &mut self.down, out) {
            if let Some(h) = &self.hooks {
                if !h.opened.load(std::sync::atomic::Ordering::Acquire) {
                    if let Some(f) = take(&h.fail) {
                        f(copy_err(&e));
                    }
                }
            }
            return Err(e);
        }
        // Also with nothing new: lets the inner transport produce its first flight.
        let down = std::mem::take(&mut self.down);
        let r = self.inner.recv(&down, plain, &mut self.up);
        self.down = down;
        self.send_up(out)?;
        r
    }

    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.inner.seal(plain, &mut self.up)?;
        self.send_up(out)
    }

    fn shutdown(&mut self, out: &mut Vec<u8>) {
        self.inner.shutdown(&mut self.up);
        let _ = self.send_up(out);
        self.outer.shutdown(out);
    }

    fn as_any(&mut self) -> &mut dyn Any {
        // `only::tls::tls_info` reports the target's session, as without the outer layer.
        self.inner.as_any()
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn handshaking(&self) -> bool {
        self.outer.handshaking() || self.inner.handshaking()
    }

    fn set_waker(&mut self, waker: only_core::TransportWaker) {
        self.outer.set_waker(waker.clone());
        self.inner.set_waker(waker);
    }

    fn handshake_timeout(&self) -> Option<std::time::Duration> {
        self.inner
            .handshake_timeout()
            .or_else(|| self.outer.handshake_timeout())
    }
}

/// Largest proxy response head accepted.
const MAX_HEAD: usize = 16 << 10;

struct Tunnel {
    /// The `CONNECT` request, until sent.
    request: Option<Vec<u8>>,
    /// The SOCKS handshake instead, if this is a SOCKS proxy.
    socks: Option<Result<crate::socks::Handshake, (io::ErrorKind, String)>>,
    hooks: Arc<Hooks>,
    timeout: Option<std::time::Duration>,
    /// Whether the SOCKS greeting has been sent.
    started: bool,
    /// The proxy's answer so far.
    head: Vec<u8>,
    open: bool,
    /// Bytes for the target (the inner transport's first flight, early application bytes),
    /// sent once the tunnel is open.
    held: Vec<u8>,
    inner: Option<Box<dyn Transport>>,
    refusal: Refusal,
    /// Resumes the tunnel when a GSS-API step finishes on its thread.
    waker: Option<only_core::TransportWaker>,
    /// The finished GSS-API step.
    gss: Arc<Mutex<Option<crate::socks::GssDone>>>,
    gss_running: bool,
}

impl Tunnel {
    /// Runs the handshake's pending GSS-API step on a thread of its own (it may block on the
    /// KDC), resuming through the waker; inline when there is no waker (no engine).
    fn run_gss(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        let Some(Ok(hs)) = self.socks.as_mut() else {
            return Ok(false);
        };
        let Some(job) = hs.take_gss_job() else {
            return Ok(false);
        };
        let Some(waker) = self.waker.clone() else {
            hs.gss_done(job.run(), out)?;
            return Ok(true);
        };
        let slot = self.gss.clone();
        self.gss_running = true;
        std::thread::Builder::new()
            .name("only-socks-gss".into())
            .spawn(move || {
                let d = job.run();
                *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(d);
                waker.wake();
            })
            .map_err(|e| io::Error::other(format!("GSS-API worker thread: {e}")))?;
        Ok(false)
    }

    fn pass(&mut self, data: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        match &mut self.inner {
            Some(t) => t.recv(data, plain, out),
            None => {
                plain.extend_from_slice(data);
                Ok(())
            }
        }
    }
}

impl Tunnel {
    /// Lets the inner transport produce its first flight; it waits in `held`.
    fn first_flight(&mut self) -> io::Result<()> {
        if let Some(t) = &mut self.inner {
            let mut early = Vec::new();
            t.recv(&[], &mut early, &mut self.held)?;
        }
        Ok(())
    }

    fn recv_socks(
        &mut self,
        mut data: &[u8],
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        let hs = match self.socks.as_mut() {
            Some(Ok(hs)) => hs,
            Some(Err((kind, msg))) => return Err(io::Error::new(*kind, msg.clone())),
            None => return Ok(()),
        };
        if !self.started {
            self.started = true;
            hs.start(out);
            self.first_flight()?;
        }
        let mut resumed = false;
        if self.gss_running {
            let done = take(&self.gss);
            match done {
                Some(d) => {
                    self.gss_running = false;
                    resumed = true;
                    if let Some(Ok(hs)) = self.socks.as_mut() {
                        let r = hs.gss_done(d, out);
                        self.note_refusal(r)?;
                    }
                }
                // Still running: keep what came for later.
                None => {
                    if let Some(Ok(hs)) = self.socks.as_mut() {
                        hs.feed(data, out)?;
                    }
                    return Ok(());
                }
            }
        }
        if data.is_empty() && !resumed {
            return Ok(());
        }
        loop {
            let Some(Ok(hs)) = self.socks.as_mut() else {
                return Ok(());
            };
            let fed = hs.feed(data, out);
            let (used, reply) = match fed {
                Ok(v) => v,
                Err(e) => {
                    if let Some(r) = e.get_ref().and_then(|r| r.downcast_ref::<ProxyRefused>()) {
                        *self.refusal.lock().unwrap_or_else(|p| p.into_inner()) = Some(r.clone());
                    }
                    return Err(e);
                }
            };
            data = &data[used..];
            if self.run_gss(out)? {
                continue; // run inline: go on with what is buffered
            }
            if self.gss_running {
                return Ok(());
            }
            let Some(Ok(hs)) = self.socks.as_mut() else {
                return Ok(());
            };
            let done = hs.is_done();
            if let Some(r) = reply {
                if !done {
                    if let Some(f) = take(&self.hooks.bound) {
                        f(&r);
                    }
                    continue;
                }
            }
            if !done {
                return Ok(());
            }
            let protection = hs.take_protection();
            self.opened();
            let Some((ctx, level, leftover)) = protection else {
                out.append(&mut self.held);
                return if data.is_empty() {
                    Ok(())
                } else {
                    self.pass(data, plain, out)
                };
            };
            // GSS-API per-message protection: everything from here on is wrapped, the target's
            // transport (and what it already sealed) inside.
            let mut layer = crate::gss::GssLayer::new(ctx, level, self.inner.take());
            layer.wrap_raw(&std::mem::take(&mut self.held), out)?;
            layer.recv_unwrapped(&leftover, plain, out)?;
            self.inner = Some(Box::new(layer));
            return if data.is_empty() {
                Ok(())
            } else {
                self.pass(data, plain, out)
            };
        }
    }

    /// Records a refusal for the client to report.
    fn note_refusal<T>(&self, r: io::Result<T>) -> io::Result<T> {
        if let Err(e) = &r {
            if let Some(p) = e.get_ref().and_then(|r| r.downcast_ref::<ProxyRefused>()) {
                *self.refusal.lock().unwrap_or_else(|p| p.into_inner()) = Some(p.clone());
            }
        }
        r
    }
}

impl Tunnel {
    fn recv_http(
        &mut self,
        cipher: &[u8],
        plain: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        if let Some(r) = self.request.take() {
            out.extend_from_slice(&r);
            // Let the inner transport produce its first flight now; it waits in `held`.
            if let Some(t) = &mut self.inner {
                let mut early = Vec::new();
                t.recv(&[], &mut early, &mut self.held)?;
            }
        }
        self.head.extend_from_slice(cipher);
        loop {
            let mut storage = [http1::Header::EMPTY; 64];
            let r = match http1::parse_response(
                &self.head,
                &mut storage,
                &mut http1::Resume::default(),
            ) {
                Ok(http1::Status::Complete(r)) => r,
                Ok(http1::Status::Partial) if self.head.len() <= MAX_HEAD => return Ok(()),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed proxy response to CONNECT",
                    ));
                }
            };
            let (len, code) = (r.len, r.code);
            if (100..200).contains(&code) {
                self.head.drain(..len);
                continue;
            }
            if !(200..300).contains(&code) {
                let refused = ProxyRefused {
                    status: code,
                    reason: r.reason.to_owned(),
                    socks: None,
                };
                let e = refused.to_io();
                *self.refusal.lock().unwrap_or_else(|p| p.into_inner()) = Some(refused);
                return Err(e);
            }
            self.opened();
            let rest = self.head.split_off(len);
            self.head = Vec::new();
            out.append(&mut self.held);
            return if rest.is_empty() {
                Ok(())
            } else {
                self.pass(&rest, plain, out)
            };
        }
    }

    fn opened(&mut self) {
        self.open = true;
        self.hooks
            .opened
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(f) = take(&self.hooks.open) {
            f();
        }
    }

    /// Reports a failure before the tunnel opened to the `on_fail` hook, once.
    fn failed(&self, e: io::Error) -> io::Error {
        if self.open {
            return e;
        }
        if let Some(f) = take(&self.hooks.fail) {
            f(copy_err(&e));
        }
        e
    }
}

/// Copies an `io::Error`: its kind, and its `ProxyRefused` payload or its message.
fn copy_err(e: &io::Error) -> io::Error {
    match e.get_ref().and_then(|r| r.downcast_ref::<ProxyRefused>()) {
        Some(r) => io::Error::new(e.kind(), r.clone()),
        None => io::Error::new(e.kind(), e.to_string()),
    }
}

impl Transport for Tunnel {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        if self.open {
            return self.pass(cipher, plain, out);
        }
        if self.socks.is_some() {
            return self
                .recv_socks(cipher, plain, out)
                .map_err(|e| self.failed(e));
        }
        self.recv_http(cipher, plain, out)
            .map_err(|e| self.failed(e))
    }

    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let out = if self.open { out } else { &mut self.held };
        match &mut self.inner {
            Some(t) => t.seal(plain, out),
            None => {
                out.extend_from_slice(plain);
                Ok(())
            }
        }
    }

    fn shutdown(&mut self, out: &mut Vec<u8>) {
        if self.open {
            if let Some(t) = &mut self.inner {
                t.shutdown(out);
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        // `only::tls::tls_info` downcasts to the TLS transport: hand out the inner one.
        if self.inner.is_none() {
            return self;
        }
        self.inner.as_mut().expect("checked above").as_any()
    }

    fn name(&self) -> &'static str {
        match &self.inner {
            Some(t) if self.open => t.name(),
            _ if self.socks.is_some() => "socks",
            _ => "connect",
        }
    }

    fn handshaking(&self) -> bool {
        !self.open || self.inner.as_ref().is_some_and(|t| t.handshaking())
    }

    fn set_waker(&mut self, waker: only_core::TransportWaker) {
        if let Some(t) = &mut self.inner {
            t.set_waker(waker.clone());
        }
        self.waker = Some(waker);
    }

    fn handshake_timeout(&self) -> Option<std::time::Duration> {
        self.timeout
            .or_else(|| self.inner.as_ref().and_then(|t| t.handshake_timeout()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn proxy_urls() {
        let s = ProxyServer::parse("http://u%40x:p%3As@proxy:3128/").unwrap();
        assert_eq!((s.host.as_str(), s.port), ("proxy", 3128));
        assert_eq!(
            s.authorization.as_deref(),
            Some(format!("Basic {}", only_crypto::base64::STANDARD.encode("u@x:p:s")).as_str())
        );
        let s = ProxyServer::parse("10.0.0.1:8080").unwrap();
        assert_eq!(
            (s.host.as_str(), s.port, s.authorization),
            ("10.0.0.1", 8080, None)
        );
        let s = ProxyServer::parse("HTTP://[::1]").unwrap();
        assert_eq!((s.host.as_str(), s.port), ("::1", 80));
        let s = ProxyServer::parse("https://u:p@proxy.example").unwrap();
        assert_eq!(
            (s.host.as_str(), s.port, s.tls),
            ("proxy.example", 443, true)
        );
        assert!(s.is_http() && s.authorization.is_some());
        assert!(!ProxyServer::parse("http://p").unwrap().tls);
        for bad in [
            "httpx://p:1",
            "ftp://p:1",
            "http://:1",
            "http://p:x",
            "http://[::1",
        ] {
            assert!(ProxyServer::parse(bad).is_err(), "{bad}");
        }
        // Credentials stay out of Debug.
        let p = Proxy::all("http://user:secret@p:1").unwrap();
        assert!(!format!("{p:?}").contains("secret"));
    }

    #[test]
    fn no_proxy_rules() {
        let p = Proxy::all("http://p:1")
            .unwrap()
            .no_proxy("localhost, .corp.example,*.svc, 10.0.0.0/8, ::1, [fd00::]:8443, x.test:81");
        let via = |h: &str, port: u16| p.applies(false, h, port);
        assert!(!via("localhost", 80));
        assert!(!via("LOCALHOST.", 80));
        assert!(!via("corp.example", 80));
        assert!(!via("a.b.corp.example", 80));
        assert!(via("notcorp.example", 80));
        assert!(!via("api.svc", 80));
        assert!(!via("10.200.0.1", 80));
        assert!(via("11.0.0.1", 80));
        assert!(!via("::1", 80));
        assert!(!via("[::1]", 80));
        assert!(!via("fd00::", 8443));
        assert!(via("fd00::", 443));
        assert!(!via("x.test", 81));
        assert!(via("x.test", 80));
        assert!(via("example.com", 80));
        let all = Proxy::all("http://p:1").unwrap().no_proxy("*");
        assert!(!all.applies(true, "example.com", 443));
        assert!(!Proxy::none().applies(false, "example.com", 80));
        assert!(prefix_eq(&[192, 168, 1, 7], &[192, 168, 0, 0], 16));
        assert!(!prefix_eq(&[192, 169, 1, 7], &[192, 168, 0, 0], 16));
        assert!(prefix_eq(&[192, 168, 1, 7], &[192, 168, 1, 0], 25));
        assert!(!prefix_eq(&[192, 168, 1, 200], &[192, 168, 1, 0], 25));
    }

    #[test]
    fn environment() {
        let p = Proxy::from_lookup(env(&[
            ("HTTP_PROXY", "http://h:1"),
            ("https_proxy", "s:2"),
            ("HTTPS_PROXY", "ignored:3"),
            ("NO_PROXY", "internal"),
        ]))
        .unwrap();
        assert_eq!(p.select(false, "a", 80).map(|s| s.port), Some(1));
        assert_eq!(p.select(true, "a", 443).map(|s| s.port), Some(2));
        assert!(p.select(true, "x.internal", 443).is_none());
        // httpoxy: a CGI request's HTTP_PROXY is not trusted.
        let p = Proxy::from_lookup(env(&[
            ("HTTP_PROXY", "http://h:1"),
            ("REQUEST_METHOD", "GET"),
        ]))
        .unwrap();
        assert!(p.is_empty());
        assert!(Proxy::from_lookup(env(&[("http_proxy", "ftp://x:1")])).is_err());
        // ALL_PROXY fills in what the others leave out.
        let p = Proxy::from_lookup(env(&[
            ("https_proxy", "s:2"),
            ("ALL_PROXY", "socks5h://u:p%40w@sock"),
        ]))
        .unwrap();
        let s = p.select(false, "a", 80).unwrap();
        assert_eq!(
            (s.host.as_str(), s.port, s.is_http()),
            ("sock", 1080, false)
        );
        assert_eq!(s.credentials, Some(("u".into(), "p@w".into())));
        assert!(!s.resolves_locally());
        assert_eq!(p.select(true, "a", 443).map(|s| s.port), Some(2));
        assert!(
            Proxy::from_lookup(env(&[("http_proxy", "  ")]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn tunnel_holds_bytes_until_the_proxy_answers() {
        let s = ProxyServer::parse("http://u:p@proxy:1").unwrap();
        let refusal = Refusal::default();
        let c = Connect::new(
            "::1",
            443,
            &s,
            refusal.clone(),
            only::fn_acceptor(|_c: &Conn<Nop>| Nop),
        );
        let mut t = c.transport().unwrap();
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        t.recv(&[], &mut plain, &mut out).unwrap();
        let req = String::from_utf8(out.clone()).unwrap();
        assert!(
            req.starts_with("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n"),
            "{req}"
        );
        assert!(req.contains("Proxy-Authorization: Basic dTpw\r\n"));
        assert!(t.handshaking());
        out.clear();
        t.seal(b"early", &mut out).unwrap();
        assert!(out.is_empty(), "held until the tunnel is open");
        t.recv(
            b"HTTP/1.1 200 Connection established\r\n\r\nhi",
            &mut plain,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, b"early");
        assert_eq!(plain, b"hi");
        assert!(!t.handshaking());
        assert!(refusal.lock().unwrap().is_none());

        let refusal = Refusal::default();
        let c = Connect::new(
            "h",
            80,
            &s,
            refusal.clone(),
            only::fn_acceptor(|_c: &Conn<Nop>| Nop),
        );
        let mut t = c.transport().unwrap();
        out.clear();
        t.recv(&[], &mut plain, &mut out).unwrap();
        let e = t
            .recv(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
                &mut plain,
                &mut out,
            )
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        let r = e.get_ref().unwrap().downcast_ref::<ProxyRefused>().unwrap();
        assert_eq!(r.status(), 407);
        assert_eq!(refusal.lock().unwrap().as_ref(), Some(r));
    }

    #[test]
    fn socks_tunnel_holds_bytes_until_the_proxy_answers() {
        let s = ProxyServer::parse("socks5h://u:p@proxy").unwrap();
        assert_eq!((s.port, s.authorization.as_deref()), (1080, None));
        let c = Connect::new(
            "example.com",
            443,
            &s,
            Refusal::default(),
            only::fn_acceptor(|_c: &Conn<Nop>| Nop),
        )
        .handshake_timeout(Some(std::time::Duration::from_secs(3)));
        let mut t = c.transport().unwrap();
        assert_eq!(
            t.handshake_timeout(),
            Some(std::time::Duration::from_secs(3))
        );
        let (mut plain, mut out) = (Vec::new(), Vec::new());
        t.recv(&[], &mut plain, &mut out).unwrap();
        assert_eq!(out, [5, 2, 0, 2]);
        assert_eq!(t.name(), "socks");
        out.clear();
        t.seal(b"early", &mut out).unwrap();
        assert!(out.is_empty());
        t.recv(&[5, 2], &mut plain, &mut out).unwrap();
        assert_eq!(out, b"\x01\x01u\x01p");
        out.clear();
        t.recv(&[1, 0], &mut plain, &mut out).unwrap();
        assert_eq!(&out[..5], &[5, 1, 0, 3, 11]);
        out.clear();
        // Reply and the target's first bytes in one read.
        t.recv(
            &[5, 0, 0, 1, 1, 2, 3, 4, 0, 1, b'h', b'i'],
            &mut plain,
            &mut out,
        )
        .unwrap();
        assert_eq!(
            (out.as_slice(), plain.as_slice()),
            (&b"early"[..], &b"hi"[..])
        );
        assert!(!t.handshaking());

        // A refusal is recorded for the client to report.
        let s = ProxyServer::parse("socks4a://ident@proxy:9").unwrap();
        assert_eq!(s.credentials, Some(("ident".into(), String::new())));
        let refusal = Refusal::default();
        let c = Connect::new(
            "h",
            80,
            &s,
            refusal.clone(),
            only::fn_acceptor(|_c: &Conn<Nop>| Nop),
        );
        let mut t = c.transport().unwrap();
        out.clear();
        t.recv(&[], &mut plain, &mut out).unwrap();
        assert_eq!(out, b"\x04\x01\x00\x50\x00\x00\x00\x01ident\x00h\x00");
        let e = t
            .recv(&[0, 0x5b, 0, 0, 0, 0, 0, 0], &mut plain, &mut out)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        let r = refusal.lock().unwrap().clone().unwrap();
        assert_eq!((r.status(), r.socks_reply()), (502, Some(0x5b)));
        // socks4:// with a host name cannot be expressed: reported on open.
        let s = ProxyServer::parse("socks4://proxy").unwrap();
        assert!(s.resolves_locally() && s.is_socks4());
        let c = Connect::new(
            "h",
            80,
            &s,
            Refusal::default(),
            only::fn_acceptor(|_c: &Conn<Nop>| Nop),
        );
        let mut t = c.transport().unwrap();
        assert!(t.recv(&[], &mut plain, &mut out).is_err());
    }

    struct Nop;
    impl only::Handler for Nop {
        fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
    }
}
