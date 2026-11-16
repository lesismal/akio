//! An asynchronous HTTP/1.1 client on `only`'s engine: callbacks or a waitable/awaitable result,
//! keep-alive connection reuse per host, chunked and close-delimited bodies, HTTPS through
//! `only::tls` (the system's CAs by default), opt-in redirects ([`RedirectPolicy`]), per-request
//! timeouts, HTTP proxies ([`Proxy`]) and name resolution off the calling thread
//! ([`only::dns`]). See ADR-010 for the rules.
//!
//! ```no_run
//! # use std::{sync::Arc, time::Duration};
//! use only::Engine;
//! use only_http::client::{Client, ClientRequest, Proxy, RedirectPolicy};
//!
//! let engine = Arc::new(Engine::builder().client_threads(1).build().unwrap());
//! engine.start().unwrap();
//! let client = Client::new(engine)
//!     .with_redirects(RedirectPolicy::limit(10))
//!     .with_timeout(Duration::from_secs(30))
//!     .with_proxy(Proxy::from_env().unwrap());
//! let r = client.send(ClientRequest::get("https://example.com/")).wait().unwrap();
//! println!("{} from {}", r.status, r.url);
//! ```
//!
//! Callbacks run on an I/O thread (a resolver thread when a name does not resolve, the timer
//! thread on a timeout, the calling thread for an invalid URL) and must not block.

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context as TaskContext, Poll, Waker},
    time::Duration,
};

use only::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, RootCerts, Tls},
};
use only_core::ConnInner;
pub use only_ws::proxy::{Proxy, ProxyRefused};
use only_ws::{
    http1,
    proxy::{Connect, ProxyServer, Refusal},
};

use crate::{
    message::{Headers, Method, Version},
    parse::ChunkDecoder,
};

/// A request to send.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ClientRequest {
    /// Method.
    pub method: Method,
    /// An absolute `http://` or `https://` URL.
    pub url: String,
    /// Extra header fields (`Host`, `Content-Length` and `Connection` are added).
    pub headers: Headers,
    /// Request body.
    pub body: Vec<u8>,
    /// Limit for this request from start to the complete response, redirects included; `None`
    /// uses the client's ([`Client::with_timeout`]). On expiry the request fails with
    /// [`ClientError::Timeout`] and its connection is closed.
    pub timeout: Option<Duration>,
}

impl ClientRequest {
    /// A request with `method` to `url`, no headers and an empty body.
    pub fn new(method: Method, url: &str) -> ClientRequest {
        ClientRequest {
            method,
            url: url.to_owned(),
            headers: Headers::new(),
            body: Vec::new(),
            timeout: None,
        }
    }

    /// A `GET` request.
    pub fn get(url: &str) -> ClientRequest {
        ClientRequest::new(Method::Get, url)
    }

    /// A `POST` request with a body.
    pub fn post(url: &str, body: Vec<u8>) -> ClientRequest {
        ClientRequest::new(Method::Post, url).body(body)
    }

    /// Replaces the body.
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> ClientRequest {
        self.body = body;
        self
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> ClientRequest {
        self.headers.append(name, value);
        self
    }

    /// Sets this request's timeout ([`timeout`](Self::timeout)).
    #[must_use]
    pub fn timeout(mut self, d: Duration) -> ClientRequest {
        self.timeout = Some(d);
        self
    }
}

/// A received response.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ClientResponse {
    /// Status code.
    pub status: u16,
    /// Reason phrase as sent.
    pub reason: String,
    /// Header fields.
    pub headers: Headers,
    /// Body (decoded if chunked).
    pub body: Vec<u8>,
    /// Trailer fields of a chunked body.
    pub trailers: Headers,
    /// Responses the server pushed with this one (HTTP/2 only; empty otherwise).
    pub pushed: Vec<(String, ClientResponse)>,
    /// The URL that answered: the request's, or the last redirect's target (HTTP/1 client).
    pub url: String,
}

/// Why a request failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// The URL could not be used.
    InvalidUrl(String),
    /// Resolving, connecting or the connection itself failed.
    Io(io::Error),
    /// The server's response was malformed.
    Protocol(&'static str),
    /// The connection closed before a complete response arrived.
    Closed,
    /// The request's timeout passed ([`ClientRequest::timeout`], [`Client::with_timeout`]).
    Timeout,
    /// More redirects than the [`RedirectPolicy`] allows (or a redirect loop).
    TooManyRedirects,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidUrl(u) => write!(f, "invalid url: {u}"),
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Protocol(m) => write!(f, "protocol: {m}"),
            ClientError::Closed => f.write_str("connection closed before a complete response"),
            ClientError::Timeout => f.write_str("request timed out"),
            ClientError::TooManyRedirects => f.write_str("too many redirects"),
        }
    }
}

impl std::error::Error for ClientError {}

type Callback = Box<dyn FnOnce(Result<ClientResponse, ClientError>) + Send>;

/// The result of [`Client::send`]: wait for it, or `.await` it.
pub struct ResponseFuture {
    pub(crate) shared: Arc<FutureShared>,
}

impl std::fmt::Debug for ResponseFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseFuture").finish_non_exhaustive()
    }
}

pub(crate) type Outcome = Result<ClientResponse, ClientError>;

pub(crate) struct FutureShared {
    slot: Mutex<(Option<Outcome>, Option<Waker>)>,
    cv: Condvar,
}

impl FutureShared {
    pub(crate) fn new() -> Arc<FutureShared> {
        Arc::new(FutureShared {
            slot: Mutex::new((None, None)),
            cv: Condvar::new(),
        })
    }

    pub(crate) fn complete(&self, r: Outcome) {
        let mut g = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        g.0 = Some(r);
        if let Some(w) = g.1.take() {
            w.wake();
        }
        self.cv.notify_all();
    }
}

impl ResponseFuture {
    /// Blocks until the response (or an error) is there.
    pub fn wait(self) -> Result<ClientResponse, ClientError> {
        let mut g = self.shared.slot.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(r) = g.0.take() {
                return r;
            }
            g = self.shared.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Like [`wait`](Self::wait) with a limit; `None` on timeout.
    pub fn wait_timeout(self, d: Duration) -> Option<Result<ClientResponse, ClientError>> {
        let deadline = std::time::Instant::now() + d;
        let mut g = self.shared.slot.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(r) = g.0.take() {
                return Some(r);
            }
            let left = deadline.checked_duration_since(std::time::Instant::now())?;
            g = self
                .shared
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }
}

impl Future for ResponseFuture {
    type Output = Result<ClientResponse, ClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut g = self.shared.slot.lock().unwrap_or_else(|p| p.into_inner());
        match g.0.take() {
            Some(r) => Poll::Ready(r),
            None => {
                g.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: bool,
    /// The proxy the connection goes through (connections are pooled per route).
    pub(crate) proxy: Option<(String, u16)>,
}

pub(crate) struct ParsedUrl {
    pub(crate) key: Key,
    pub(crate) target: String,
    pub(crate) host_header: String,
}

pub(crate) fn parse_url(url: &str) -> Result<ParsedUrl, ClientError> {
    let bad = || ClientError::InvalidUrl(url.to_owned());
    let (tls, rest) = if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        return Err(bad());
    };
    let (authority, target) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_owned()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (
            h.trim_matches(['[', ']']).to_owned(),
            p.parse().map_err(|_| bad())?,
        ),
        _ => (
            authority.trim_matches(['[', ']']).to_owned(),
            if tls { 443 } else { 80 },
        ),
    };
    if host.is_empty() {
        return Err(bad());
    }
    let default_port = if tls { 443 } else { 80 };
    let host_header = if port == default_port {
        authority
            .rsplit_once(':')
            .map_or(authority, |(h, _)| h)
            .to_owned()
    } else {
        authority.to_owned()
    };
    Ok(ParsedUrl {
        key: Key {
            host,
            port,
            tls,
            proxy: None,
        },
        target,
        host_header,
    })
}

/// Which redirects [`Client`] follows (ADR-010). The default follows none: a 3xx response is
/// returned as it is.
///
/// With a limit, 301, 302, 303, 307 and 308 responses that carry a `Location` are followed
/// (relative references resolved against the request URL), per RFC 9110 section 15.4:
/// 303 turns any method but `HEAD` into `GET` without a body, 301 and 302 turn `POST` into `GET`
/// without a body, everything else keeps its method and body. A redirect to another origin
/// (scheme, host or port) drops `Authorization`, `Cookie` and `Proxy-Authorization`; from
/// `https` to `http` is not followed unless [`allow_https_downgrade`](Self::allow_https_downgrade)
/// (the 3xx response is returned instead). One redirect more than the limit (a loop ends there)
/// fails with [`ClientError::TooManyRedirects`]. 300, 304 and 305 are never followed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RedirectPolicy {
    max: u32,
    downgrade: bool,
}

impl RedirectPolicy {
    /// Follows no redirect (the default).
    pub fn none() -> RedirectPolicy {
        RedirectPolicy::default()
    }

    /// Follows up to `max` redirects per request (browsers allow 20, curl 50, Go 10).
    pub fn limit(max: u32) -> RedirectPolicy {
        RedirectPolicy {
            max,
            downgrade: false,
        }
    }

    /// Also follows redirects from `https://` to `http://` (off by default).
    #[must_use]
    pub fn allow_https_downgrade(mut self, yes: bool) -> RedirectPolicy {
        self.downgrade = yes;
        self
    }

    /// The limit (0: none followed).
    pub fn max(&self) -> u32 {
        self.max
    }
}

/// Header fields that describe a request body, dropped when a redirect drops the body.
const BODY_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "content-language",
    "content-location",
    "transfer-encoding",
];

/// Header fields that carry credentials, dropped on a redirect to another origin.
const CREDENTIAL_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];

/// The request a redirect leads to: `Ok(None)` when `resp` is not one to follow (it is then the
/// answer), an error when the policy's limit is passed or the target is unusable.
fn redirect(
    policy: RedirectPolicy,
    hops: u32,
    req: &ClientRequest,
    resp: &ClientResponse,
) -> Result<Option<ClientRequest>, ClientError> {
    let status = resp.status;
    if policy.max == 0 || !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let Some(loc) = resp.headers.get("location") else {
        return Ok(None);
    };
    if hops >= policy.max {
        return Err(ClientError::TooManyRedirects);
    }
    let url = only_ws::url::resolve(&req.url, loc)
        .ok_or_else(|| ClientError::InvalidUrl(loc.to_owned()))?;
    let (from, to) = (parse_url(&req.url)?, parse_url(&url)?);
    if from.key.tls && !to.key.tls && !policy.downgrade {
        return Ok(None);
    }
    let mut next = req.clone();
    next.url = url;
    let drop_body = match status {
        303 => req.method != Method::Head,
        301 | 302 => req.method == Method::Post,
        _ => false,
    };
    if drop_body {
        next.method = Method::Get;
        next.body = Vec::new();
        for h in BODY_HEADERS {
            next.headers.remove(h);
        }
    }
    let same_origin = from.key.tls == to.key.tls
        && from.key.host.eq_ignore_ascii_case(&to.key.host)
        && from.key.port == to.key.port;
    if !same_origin {
        for h in CREDENTIAL_HEADERS {
            next.headers.remove(h);
        }
    }
    Ok(Some(next))
}

/// One logical request across its attempts (retries, redirects): delivers the outcome once and
/// carries the timeout.
struct Exchange {
    done: Mutex<Option<Callback>>,
    /// The connection serving the current attempt, for the timeout to close.
    conn: Mutex<Option<Weak<ConnInner>>>,
    expired: AtomicBool,
    hops: AtomicU32,
}

impl Exchange {
    fn finish(&self, r: Outcome) {
        let cb = self.done.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(cb) = cb {
            cb(r);
        }
    }

    fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }

    /// The timeout passed: fail the request and close its connection.
    fn expire(&self) {
        let cb = self.done.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(cb) = cb else { return };
        self.expired.store(true, Ordering::Release);
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .and_then(|w| w.upgrade());
        if let Some(c) = conn {
            c.close();
        }
        cb(Err(ClientError::Timeout));
    }
}

struct Pending {
    bytes: Vec<u8>,
    head_only: bool,
    retryable: bool,
    key: Key,
    /// The proxy to dial (instead of the target), if any.
    proxy: Option<ProxyServer>,
    /// Every resolved address, tried in order until one connects (empty until resolved).
    addrs: Vec<SocketAddr>,
    ex: Arc<Exchange>,
    cb: Callback,
}

#[derive(Clone, Default)]
struct Settings {
    tls: Option<TlsClientConfig>,
    redirects: RedirectPolicy,
    timeout: Option<Duration>,
    proxy: Proxy,
}

struct Inner {
    engine: Arc<Engine>,
    settings: Settings,
    /// The system's CAs, built on first `https://` use without [`Client::with_tls`].
    system_tls: OnceLock<Result<TlsClientConfig, String>>,
    idle: Mutex<HashMap<Key, Vec<Conn<ClientConn>>>>,
    /// The engine started a graceful shutdown: connections close once their response is in
    /// instead of going back to `idle`.
    shutting_down: AtomicBool,
}

/// The HTTP client. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// A client that runs its connections on `engine` (built with `client_threads(n)`, or with a
    /// listener whose threads may host them). The engine must be started.
    pub fn new(engine: Arc<Engine>) -> Client {
        Client::with_settings(engine, Settings::default())
    }

    fn with_settings(engine: Arc<Engine>, settings: Settings) -> Client {
        Client {
            inner: Arc::new(Inner {
                engine,
                settings,
                system_tls: OnceLock::new(),
                idle: Mutex::new(HashMap::new()),
                shutting_down: AtomicBool::new(false),
            }),
        }
    }

    /// A client with the same settings but `change` applied (and its own connections).
    fn rebuild(self, change: impl FnOnce(&mut Settings)) -> Client {
        let mut s = self.inner.settings.clone();
        change(&mut s);
        Client::with_settings(self.inner.engine.clone(), s)
    }

    /// Uses `cfg` for `https://` instead of the system's CAs ([`RootCerts::system`]).
    #[must_use]
    pub fn with_tls(self, cfg: TlsClientConfig) -> Client {
        self.rebuild(|s| s.tls = Some(cfg))
    }

    /// Follows redirects as `policy` says (none by default).
    #[must_use]
    pub fn with_redirects(self, policy: RedirectPolicy) -> Client {
        self.rebuild(|s| s.redirects = policy)
    }

    /// Default limit for each request, from start to the complete response, redirects included
    /// (none by default); [`ClientRequest::timeout`] overrides it.
    #[must_use]
    pub fn with_timeout(self, d: Duration) -> Client {
        self.rebuild(|s| s.timeout = Some(d))
    }

    /// Sends requests through `proxy` where it applies: `https://` through a `CONNECT` tunnel,
    /// `http://` as absolute-form requests to the proxy. None by default; the environment is
    /// only read through [`Proxy::from_env`].
    #[must_use]
    pub fn with_proxy(self, proxy: Proxy) -> Client {
        self.rebuild(|s| s.proxy = proxy)
    }

    /// Sends `req`; `done` is called once with the outcome (on an I/O thread, or as the module
    /// documentation says).
    pub fn request(
        &self,
        req: ClientRequest,
        done: impl FnOnce(Result<ClientResponse, ClientError>) + Send + 'static,
    ) {
        let ex = Arc::new(Exchange {
            done: Mutex::new(Some(Box::new(done))),
            conn: Mutex::new(None),
            expired: AtomicBool::new(false),
            hops: AtomicU32::new(0),
        });
        if let Some(d) = req.timeout.or(self.inner.settings.timeout) {
            let weak = Arc::downgrade(&ex);
            crate::timer::after(d, move || {
                if let Some(ex) = weak.upgrade() {
                    ex.expire();
                }
            });
        }
        self.attempt(ex, req);
    }

    /// Sends `req` (the first one, or a redirect's) as part of `ex`.
    fn attempt(&self, ex: Arc<Exchange>, req: ClientRequest) {
        let pu = match parse_url(&req.url) {
            Ok(p) => p,
            Err(e) => return ex.finish(Err(e)),
        };
        let proxy = self
            .inner
            .settings
            .proxy
            .select(pu.key.tls, &pu.key.host, pu.key.port)
            .cloned();
        let absolute = proxy.as_ref().filter(|_| !pu.key.tls);
        let mut bytes = Vec::with_capacity(160 + req.body.len());
        let scheme_host = match absolute {
            Some(_) => format!("http://{}", pu.host_header),
            None => String::new(),
        };
        bytes.extend_from_slice(
            format!(
                "{} {scheme_host}{} HTTP/1.1\r\nHost: {}\r\n",
                req.method.as_str(),
                pu.target,
                pu.host_header
            )
            .as_bytes(),
        );
        if let Some(auth) = absolute.and_then(|p| p.authorization.as_deref()) {
            bytes.extend_from_slice(format!("Proxy-Authorization: {auth}\r\n").as_bytes());
        }
        for (n, v) in req.headers.iter() {
            if !n.eq_ignore_ascii_case("host") && !n.eq_ignore_ascii_case("content-length") {
                bytes.extend_from_slice(
                    format!("{n}: {}\r\n", v.replace(['\r', '\n'], "")).as_bytes(),
                );
            }
        }
        if req.headers.get("user-agent").is_none() {
            bytes.extend_from_slice(b"User-Agent: only-http\r\n");
        }
        if !req.body.is_empty() || matches!(req.method, Method::Post | Method::Put | Method::Patch)
        {
            bytes.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&req.body);
        let mut key = pu.key;
        key.proxy = proxy.as_ref().map(|p| (p.host.clone(), p.port));
        let head_only = req.method == Method::Head;
        let retryable = matches!(req.method, Method::Get | Method::Head | Method::Options);
        // The request is kept only when a redirect may need it again.
        let policy = self.inner.settings.redirects;
        let (url, saved) = if policy.max > 0 {
            (req.url.clone(), Some(req))
        } else {
            (req.url, None)
        };
        let (me, ex2) = (self.clone(), ex.clone());
        let cb: Callback = Box::new(move |r| match r {
            Ok(mut resp) => {
                if let Some(req) = saved {
                    let hops = ex2.hops.load(Ordering::Relaxed);
                    match redirect(policy, hops, &req, &resp) {
                        Ok(Some(next)) => {
                            ex2.hops.store(hops + 1, Ordering::Relaxed);
                            if !ex2.expired() {
                                me.attempt(ex2, next);
                            }
                            return;
                        }
                        Ok(None) => {}
                        Err(e) => return ex2.finish(Err(e)),
                    }
                }
                resp.url = url;
                ex2.finish(Ok(resp));
            }
            Err(e) => ex2.finish(Err(e)),
        });
        self.dispatch(Pending {
            bytes,
            head_only,
            retryable,
            key,
            proxy,
            addrs: Vec::new(),
            ex,
            cb,
        });
    }

    /// Sends `req` and returns a handle to wait on or await.
    pub fn send(&self, req: ClientRequest) -> ResponseFuture {
        let shared = FutureShared::new();
        let s = shared.clone();
        self.request(req, move |r| s.complete(r));
        ResponseFuture { shared }
    }

    /// Reuses an idle keep-alive connection when there is one, else dials.
    fn dispatch(&self, p: Pending) {
        let idle = self
            .inner
            .idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&p.key)
            .and_then(Vec::pop);
        match idle {
            Some(conn) if conn.is_open() => {
                let slot = Arc::new(Mutex::new(Some(p)));
                let s2 = slot.clone();
                let me = self.clone();
                let ok = conn.spawn_blocking(
                    || (),
                    move |h: &mut ClientConn, c, ()| {
                        let taken = s2.lock().unwrap_or_else(|e| e.into_inner()).take();
                        if let Some(p) = taken {
                            h.begin(c, p, me, true);
                        }
                    },
                );
                if ok.is_err() {
                    // The pool refused (or the connection just closed): start over on a new one.
                    let taken = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(p) = taken {
                        self.dial(p);
                    }
                }
            }
            Some(_) => self.dispatch(p), // closed meanwhile: try the next idle one
            None => self.dial(p),
        }
    }

    /// The TLS configuration for `https://`.
    fn tls(&self) -> io::Result<TlsClientConfig> {
        if let Some(c) = &self.inner.settings.tls {
            return Ok(c.clone());
        }
        self.inner
            .system_tls
            .get_or_init(|| {
                RootCerts::system()
                    .and_then(|r| TlsClientConfig::builder().roots(r).build())
                    .map_err(|e| e.to_string())
            })
            .clone()
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))
    }

    fn dial(&self, mut p: Pending) {
        if p.ex.expired() {
            return;
        }
        if p.addrs.is_empty() {
            // Resolve the proxy (when there is one) or the target, off this thread.
            let (host, port) = match &p.proxy {
                Some(s) => (s.host.clone(), s.port),
                None => (p.key.host.clone(), p.key.port),
            };
            let me = self.clone();
            return only::dns::resolve(&host, port, move |r| match r {
                Ok(a) => {
                    p.addrs = a;
                    me.dial(p);
                }
                Err(e) => (p.cb)(Err(ClientError::Io(e))),
            });
        }
        let key = p.key.clone();
        let addr = p.addrs[0];
        let tunnel = key.tls.then(|| p.proxy.clone()).flatten();
        let slot = Arc::new(Mutex::new(Some(p)));
        let refusal = tunnel.as_ref().map(|_| Refusal::default());
        let acceptor = DialAcceptor {
            pending: slot.clone(),
            client: self.clone(),
            refusal: refusal.clone(),
        };
        let fail = {
            let (slot, me) = (slot, self.clone());
            move |e: io::Error| {
                let taken = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(mut p) = taken {
                    if p.addrs.len() > 1 {
                        // Next address (`localhost` is often ::1 first, then 127.0.0.1).
                        p.addrs.remove(0);
                        me.dial(p);
                    } else {
                        (p.cb)(Err(ClientError::Io(e)));
                    }
                }
            }
        };
        if key.tls {
            let cfg = match self.tls() {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            match (Tls::client(cfg, &key.host, acceptor), tunnel, refusal) {
                (Ok(a), Some(proxy), Some(r)) => {
                    let a = Connect::new(&key.host, key.port, &proxy, r, a);
                    self.inner.engine.dial(addr, a, fail);
                }
                (Ok(a), _, _) => self.inner.engine.dial(addr, a, fail),
                (Err(e), _, _) => fail(e),
            }
        } else {
            self.inner.engine.dial(addr, acceptor, fail);
        }
    }
}

struct DialAcceptor {
    pending: Arc<Mutex<Option<Pending>>>,
    client: Client,
    refusal: Option<Refusal>,
}

impl Acceptor for DialAcceptor {
    type Handler = ClientConn;

    fn on_open(&self, c: &Conn<ClientConn>) -> ClientConn {
        let mut h = ClientConn::new();
        h.refusal = self.refusal.clone();
        let taken = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(p) = taken {
            h.begin(c, p, self.client.clone(), false);
        }
        h
    }

    // Without this, idle keep-alive connections stayed open through the engine's graceful
    // shutdown, so `Engine::wait` sat out the whole `shutdown_timeout` (10 s by default).
    // An idle connection closes now; one with a request in flight closes after its response
    // (`ClientConn::complete`).
    fn on_shutdown(&self, c: &Conn<ClientConn>) {
        let inner = &self.client.inner;
        inner.shutting_down.store(true, Ordering::Relaxed);
        let mut idle = inner.idle.lock().unwrap_or_else(|e| e.into_inner());
        let mut was_idle = false;
        for v in idle.values_mut() {
            let n = v.len();
            v.retain(|x| x.id() != c.id());
            was_idle |= v.len() != n;
        }
        idle.retain(|_, v| !v.is_empty());
        drop(idle);
        if was_idle {
            c.close();
        }
    }
}

enum RState {
    /// No request in flight (idle or fresh).
    Idle,
    Head,
    Body {
        left: usize,
    },
    Chunked(Box<ChunkDecoder>),
    UntilClose,
}

struct Active {
    cb: Callback,
    head_only: bool,
    retry: Option<Pending>,
    resp: Option<ClientResponse>,
    version: Version,
}

/// The per-connection client handler.
pub struct ClientConn {
    state: RState,
    buf: Vec<u8>,
    active: Option<Active>,
    client: Option<Client>,
    key: Option<Key>,
    received_any: bool,
    /// Progress on the response head being received.
    head: http1::Resume,
    /// The exchange of the request in flight (its timeout closes this connection).
    ex: Option<Arc<Exchange>>,
    /// Where the proxy tunnel (if any) records a refusal.
    refusal: Option<Refusal>,
}

impl std::fmt::Debug for ClientConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConn").finish_non_exhaustive()
    }
}

impl ClientConn {
    fn new() -> ClientConn {
        ClientConn {
            state: RState::Idle,
            buf: Vec::new(),
            active: None,
            client: None,
            key: None,
            received_any: false,
            head: http1::Resume::default(),
            ex: None,
            refusal: None,
        }
    }

    /// Starts `p` on this connection: remember the callback, write the request.
    fn begin(&mut self, c: &Conn<Self>, p: Pending, client: Client, reused: bool) {
        let Pending {
            bytes,
            head_only,
            retryable,
            key,
            proxy,
            addrs,
            ex,
            cb,
        } = p;
        {
            let mut slot = ex.conn.lock().unwrap_or_else(|e| e.into_inner());
            if ex.expired() {
                // Timed out while this connection was being set up: nobody waits any more.
                drop(slot);
                c.close();
                return;
            }
            *slot = Some(Arc::downgrade(c.inner()));
        }
        // Kept so a reused connection that turns out dead can be retried on a fresh one.
        let retry = (reused && retryable).then(|| Pending {
            bytes: bytes.clone(),
            head_only,
            retryable,
            key: key.clone(),
            proxy,
            addrs,
            ex: ex.clone(),
            cb: Box::new(|_| {}),
        });
        self.ex = Some(ex);
        self.state = RState::Head;
        self.buf.clear();
        self.head = http1::Resume::default();
        self.received_any = false;
        self.client = Some(client);
        self.key = Some(key);
        self.active = Some(Active {
            cb,
            head_only,
            retry,
            resp: None,
            version: Version::Http11,
        });
        if c.send_owned(bytes).is_err() {
            self.fail(c, ClientError::Closed);
        }
    }

    fn fail(&mut self, c: &Conn<Self>, e: ClientError) {
        self.state = RState::Idle;
        // A proxy that refused the tunnel says why.
        let refused = self.refusal.as_ref().and_then(|r| {
            r.lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(ProxyRefused::to_io)
        });
        let e = match refused {
            Some(io) => ClientError::Io(io),
            None => e,
        };
        let expired = self.ex.as_ref().is_some_and(|x| x.expired());
        if let Some(a) = self.active.take() {
            // A reused connection the server had already closed: one retry on a fresh one.
            if let (Some(mut p), Some(client), false, false) =
                (a.retry, self.client.clone(), self.received_any, expired)
            {
                if matches!(e, ClientError::Closed | ClientError::Io(_)) {
                    p.cb = a.cb;
                    client.dial(p);
                    c.close();
                    return;
                }
            }
            (a.cb)(Err(e));
        }
        c.close();
    }

    /// Finishes the response in flight.
    fn complete(&mut self, c: &Conn<Self>, keep_alive: bool) {
        self.state = RState::Idle;
        let Some(a) = self.active.take() else { return };
        let resp = a.resp.expect("response head parsed");
        let shutting_down = self
            .client
            .as_ref()
            .is_some_and(|cl| cl.inner.shutting_down.load(Ordering::Relaxed));
        let reusable = keep_alive
            && !shutting_down
            && a.version == Version::Http11
            && !resp.headers.has_token("connection", "close");
        if reusable {
            if let (Some(client), Some(key)) = (&self.client, &self.key) {
                client
                    .inner
                    .idle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(key.clone())
                    .or_default()
                    .push(c.clone());
            }
        } else {
            c.close();
        }
        (a.cb)(Ok(resp));
    }

    /// Parses what is buffered. Returns once more bytes are needed.
    fn advance(&mut self, c: &Conn<Self>) {
        loop {
            match &mut self.state {
                RState::Idle => {
                    if !self.buf.is_empty() {
                        // Bytes nobody asked for: the connection is not trustworthy.
                        self.buf.clear();
                        c.close();
                    }
                    return;
                }
                RState::Head => {
                    let mut storage = [http1::Header::EMPTY; 100];
                    let r = match http1::parse_response(&self.buf, &mut storage, &mut self.head) {
                        Ok(http1::Status::Complete(r)) => r,
                        Ok(http1::Status::Partial) => return,
                        Err(_) => return self.fail(c, ClientError::Protocol("bad response head")),
                    };
                    let (n, status) = (r.len, r.code);
                    let mut headers = Headers::with_capacity(r.headers.len(), 0);
                    for h in r.headers {
                        let Ok(v) = std::str::from_utf8(h.value) else {
                            return self.fail(c, ClientError::Protocol("non-UTF-8 header"));
                        };
                        headers.append(h.name, v);
                    }
                    let version = if r.minor == 0 {
                        Version::Http10
                    } else {
                        Version::Http11
                    };
                    let reason = r.reason.to_owned();
                    self.buf.drain(..n);
                    if (100..200).contains(&status) && status != 101 {
                        continue; // interim response: the real one follows
                    }
                    let head_only = self.active.as_ref().is_some_and(|a| a.head_only);
                    let no_body = head_only || status == 204 || status == 304 || status == 101;
                    let te_chunked = headers.has_token("transfer-encoding", "chunked");
                    let cl = headers.get("content-length").map(str::parse::<usize>);
                    let next = if no_body {
                        None
                    } else if te_chunked {
                        Some(RState::Chunked(Box::new(ChunkDecoder::new())))
                    } else {
                        match cl {
                            Some(Ok(0)) => None,
                            Some(Ok(n)) => Some(RState::Body { left: n }),
                            Some(Err(_)) => {
                                return self.fail(c, ClientError::Protocol("bad Content-Length"));
                            }
                            None => Some(RState::UntilClose),
                        }
                    };
                    if let Some(a) = &mut self.active {
                        a.version = version;
                        a.resp = Some(ClientResponse {
                            status,
                            reason,
                            headers,
                            body: Vec::new(),
                            trailers: Headers::new(),
                            pushed: Vec::new(),
                            url: String::new(),
                        });
                    }
                    match next {
                        None => self.complete(c, true),
                        Some(s) => self.state = s,
                    }
                }
                RState::Body { left } => {
                    if self.buf.is_empty() {
                        return;
                    }
                    let n = self.buf.len().min(*left);
                    *left -= n;
                    let done = *left == 0;
                    let chunk: Vec<u8> = self.buf.drain(..n).collect();
                    if let Some(r) = self.active.as_mut().and_then(|a| a.resp.as_mut()) {
                        r.body.extend_from_slice(&chunk);
                    }
                    if done {
                        self.complete(c, true);
                    }
                }
                RState::Chunked(dec) => {
                    if self.buf.is_empty() {
                        return;
                    }
                    let mut out = Vec::new();
                    match dec.feed(&self.buf, &mut out, usize::MAX) {
                        Ok(n) => {
                            self.buf.drain(..n);
                            let done = dec.is_done();
                            let trailers = if done { dec.trailers() } else { Headers::new() };
                            if let Some(r) = self.active.as_mut().and_then(|a| a.resp.as_mut()) {
                                r.body.extend_from_slice(&out);
                                if done {
                                    r.trailers = trailers;
                                }
                            }
                            if done {
                                self.complete(c, true);
                            }
                        }
                        Err(_) => return self.fail(c, ClientError::Protocol("bad chunked body")),
                    }
                }
                RState::UntilClose => {
                    let chunk = std::mem::take(&mut self.buf);
                    if let Some(r) = self.active.as_mut().and_then(|a| a.resp.as_mut()) {
                        r.body.extend_from_slice(&chunk);
                    }
                    return;
                }
            }
        }
    }
}

/// Fuzzing: feeds `pieces` as the responses to requests on one connection (re-armed after each
/// complete response, as a keep-alive client would before its next request).
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn fuzz_responses(pieces: &[&[u8]], head_only: bool) {
    let c: Conn<ClientConn> = only_core::fuzzing::conn();
    let mut h = ClientConn::new();
    let arm = |h: &mut ClientConn| {
        h.state = RState::Head;
        h.active = Some(Active {
            cb: Box::new(|_| {}),
            head_only,
            retry: None,
            resp: None,
            version: Version::Http11,
        });
    };
    for p in pieces {
        if matches!(h.state, RState::Idle) && c.is_open() {
            arm(&mut h);
        }
        h.on_data(&c, p);
    }
    h.on_close(&c, None);
}

impl Handler for ClientConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.received_any = true;
        self.buf.extend_from_slice(data);
        self.advance(c);
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        match self.state {
            RState::UntilClose => self.complete(c, false),
            RState::Idle => {
                // Closed while idle: it may sit in the pool; `is_open` filters it out there.
            }
            _ => self.fail(c, ClientError::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, location: &str) -> ClientResponse {
        let mut headers = Headers::new();
        headers.append("Location", location);
        ClientResponse {
            status,
            reason: String::new(),
            headers,
            body: Vec::new(),
            trailers: Headers::new(),
            pushed: Vec::new(),
            url: String::new(),
        }
    }

    #[test]
    fn redirect_rules() {
        let p = RedirectPolicy::limit(2);
        let req = ClientRequest::post("https://a.example/x/y", b"b".to_vec())
            .header("Authorization", "t")
            .header("Cookie", "c")
            .header("Content-Type", "text/plain")
            .header("X-Keep", "1");
        // Relative, same origin: everything kept but the body (302 POST -> GET).
        let n = redirect(p, 0, &req, &resp(302, "z")).unwrap().unwrap();
        assert_eq!(n.url, "https://a.example/x/z");
        assert_eq!((n.method, n.body.len()), (Method::Get, 0));
        assert_eq!(n.headers.get("authorization"), Some("t"));
        assert_eq!(n.headers.get("content-type"), None);
        // Another host, scheme or port: credentials dropped, other fields kept.
        for loc in [
            "https://b.example/",
            "https://a.example:444/",
            "//b.example/",
        ] {
            let n = redirect(p, 0, &req, &resp(307, loc)).unwrap().unwrap();
            assert_eq!(n.headers.get("authorization"), None, "{loc}");
            assert_eq!(n.headers.get("cookie"), None, "{loc}");
            assert_eq!(n.headers.get("x-keep"), Some("1"), "{loc}");
            assert_eq!((n.method, n.body.len()), (Method::Post, 1), "{loc}");
        }
        // Host names compare without case.
        let n = redirect(p, 0, &req, &resp(308, "https://A.EXAMPLE/q"))
            .unwrap()
            .unwrap();
        assert_eq!(n.headers.get("authorization"), Some("t"));
        // https -> http: returned as is unless allowed.
        assert!(
            redirect(p, 0, &req, &resp(301, "http://a.example/"))
                .unwrap()
                .is_none()
        );
        let n = redirect(
            p.allow_https_downgrade(true),
            0,
            &req,
            &resp(301, "http://a.example/"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(n.headers.get("authorization"), None);
        // Not followed: other codes, no policy; the limit.
        for code in [300, 304, 305, 306, 200] {
            assert!(redirect(p, 0, &req, &resp(code, "/")).unwrap().is_none());
        }
        assert!(
            redirect(RedirectPolicy::none(), 0, &req, &resp(302, "/"))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            redirect(p, 2, &req, &resp(302, "/")),
            Err(ClientError::TooManyRedirects)
        ));
    }

    #[test]
    fn url_parsing() {
        let p = parse_url("http://example.com/a/b?x=1").unwrap();
        assert_eq!(
            (p.key.host.as_str(), p.key.port, p.key.tls),
            ("example.com", 80, false)
        );
        assert_eq!(
            (p.target.as_str(), p.host_header.as_str()),
            ("/a/b?x=1", "example.com")
        );
        let p = parse_url("https://example.com:8443").unwrap();
        assert_eq!(
            (p.key.port, p.key.tls, p.target.as_str()),
            (8443, true, "/")
        );
        assert_eq!(p.host_header, "example.com:8443");
        let p = parse_url("http://example.com?q=1").unwrap();
        assert_eq!(p.target, "/?q=1");
        let p = parse_url("http://[::1]:9000/x").unwrap();
        assert_eq!((p.key.host.as_str(), p.key.port), ("::1", 9000));
        assert_eq!(p.host_header, "[::1]:9000");
        for bad in [
            "ftp://x/",
            "example.com",
            "http:///x",
            "http://u@h/",
            "http://h:notaport/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }
}
