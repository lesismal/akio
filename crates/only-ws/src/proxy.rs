//! HTTP proxies for the clients (ADR-010): which proxy a URL goes through, and the `CONNECT`
//! tunnel.
//!
//! A [`Proxy`] holds one proxy for `http://` / `ws://` targets and one for `https://` /
//! `wss://` targets, plus `NO_PROXY`-style exceptions. Nothing reads the environment unless
//! asked: [`Proxy::from_env`] is the opt-in. The WebSocket client tunnels every connection with
//! `CONNECT host:port`; only-http's client tunnels `https://` the same way and sends `http://`
//! requests to the proxy in absolute form.
//!
//! Only plain-HTTP proxies are supported (`http://proxy:port`, credentials in the URL become
//! `Proxy-Authorization: Basic`); TLS to the proxy itself and SOCKS (see `only-socks`) are not.
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
    /// works) for every target.
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
    /// `HTTPS_PROXY` and `no_proxy` / `NO_PROXY` (lower case first). `HTTP_PROXY` is ignored
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
    /// `Proxy-Authorization` value, from credentials in the URL.
    pub authorization: Option<String>,
}

impl std::fmt::Debug for ProxyServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxyServer({}:{})", self.host, self.port)
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
    fn parse(url: &str) -> io::Result<ProxyServer> {
        let bad = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unusable proxy url ({why})"),
            )
        };
        let rest = match url.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
            Some(_) => return Err(bad("only http:// proxies are supported")),
            None => url,
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (host, port) = if let Some(after) = hostport.strip_prefix('[') {
            let (h, tail) = after.split_once(']').ok_or_else(|| bad("bad IPv6 host"))?;
            let port = match tail {
                "" => 80,
                t => t
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| bad("bad port"))?,
            };
            (h, port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h, p.parse().map_err(|_| bad("bad port"))?),
                None => (hostport, 80),
            }
        };
        if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c.is_control()) {
            return Err(bad("no host"));
        }
        let authorization = userinfo.map(|u| {
            let (user, pass) = u.split_once(':').unwrap_or((u, ""));
            let cred = format!("{}:{}", percent_decode(user), percent_decode(pass));
            format!("Basic {}", only_crypto::base64::STANDARD.encode(cred))
        });
        Ok(ProxyServer {
            host: host.to_owned(),
            port,
            authorization,
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

/// The proxy answered `CONNECT` with something other than 2xx. Carried inside the
/// `io::Error` a client reports (`std::io::Error::get_ref` + `downcast_ref`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRefused {
    status: u16,
    reason: String,
}

impl ProxyRefused {
    /// The proxy's status code (`407`: it wants credentials).
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The proxy's reason phrase.
    pub fn reason(&self) -> &str {
        &self.reason
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
        write!(f, "proxy refused CONNECT: {} {}", self.status, self.reason)
    }
}

impl std::error::Error for ProxyRefused {}

/// Where a tunnel records a refusal, for the client to report it when the connection closes.
#[doc(hidden)]
pub type Refusal = Arc<Mutex<Option<ProxyRefused>>>;

/// Wraps an acceptor (plain, or `Tls<A>`) so that its connection, dialed to the proxy, first
/// opens a `CONNECT` tunnel to `authority`; the inner acceptor's transport (TLS) runs inside it.
/// Not public API.
#[doc(hidden)]
pub struct Connect<A> {
    request: Vec<u8>,
    refusal: Refusal,
    inner: A,
}

impl<A> std::fmt::Debug for Connect<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connect").finish_non_exhaustive()
    }
}

impl<A: Acceptor> Connect<A> {
    /// A tunnel to `host:port` through `proxy`; a refusal is recorded in `refusal`.
    pub fn new(
        host: &str,
        port: u16,
        proxy: &ProxyServer,
        refusal: Refusal,
        inner: A,
    ) -> Connect<A> {
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
            request: r.into_bytes(),
            refusal,
            inner,
        }
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
        Some(Box::new(Tunnel {
            request: Some(self.request.clone()),
            head: Vec::new(),
            open: false,
            held: Vec::new(),
            inner: self.inner.transport(),
            refusal: self.refusal.clone(),
        }))
    }
}

/// Largest proxy response head accepted.
const MAX_HEAD: usize = 16 << 10;

struct Tunnel {
    /// The `CONNECT` request, until sent.
    request: Option<Vec<u8>>,
    /// The proxy's answer so far.
    head: Vec<u8>,
    open: bool,
    /// Bytes for the target (the inner transport's first flight, early application bytes),
    /// sent once the tunnel is open.
    held: Vec<u8>,
    inner: Option<Box<dyn Transport>>,
    refusal: Refusal,
}

impl Tunnel {
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

impl Transport for Tunnel {
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()> {
        if self.open {
            return self.pass(cipher, plain, out);
        }
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
                };
                let e = refused.to_io();
                *self.refusal.lock().unwrap_or_else(|p| p.into_inner()) = Some(refused);
                return Err(e);
            }
            self.open = true;
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
            _ => "connect",
        }
    }

    fn handshaking(&self) -> bool {
        !self.open || self.inner.as_ref().is_some_and(|t| t.handshaking())
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
        for bad in [
            "https://p:1",
            "socks5://p:1",
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
        assert!(Proxy::from_lookup(env(&[("http_proxy", "socks5://x:1")])).is_err());
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

    struct Nop;
    impl only::Handler for Nop {
        fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
    }
}
