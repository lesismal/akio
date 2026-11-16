//! An asynchronous HTTP/1.1 client on `only`'s engine: callbacks or a waitable/awaitable result,
//! keep-alive connection reuse per host, chunked and close-delimited bodies, HTTPS through
//! `only::tls`.
//!
//! Callbacks run on an I/O thread and must not block. Name resolution and building the request
//! happen on the calling thread (resolution may block). Redirects are not followed.
//!
//! Every request is bounded by [`ClientOptions`]: the response head (64 KiB) and body (64 MiB)
//! sizes, a total request timeout (30 s), and the idle pool (32 connections per host, 256 in
//! all, closed after 90 s unused).

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

use only::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, Tls},
};
use only_ws::http1;

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
    /// Total time allowed for this request, overriding the client's
    /// [`ClientOptions::request_timeout`] (for an HTTP/2 [`open`](crate::h2client::H2Client::open)
    /// stream, the only timeout). `None`: the client's default.
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

    /// Sets the total time allowed for this request (see [`timeout`](Self#structfield.timeout)).
    #[must_use]
    pub fn timeout(mut self, d: Duration) -> ClientRequest {
        self.timeout = Some(d);
        self
    }
}

/// Limits of a [`Client`]. Every one has a safe default; raise them where a peer is trusted.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ClientOptions {
    /// Largest response head (status line and header fields, interim 1xx responses included).
    /// Past it the request fails with [`ClientError::TooLarge`]. Default 64 KiB.
    pub max_head_bytes: usize,
    /// Largest response body, whatever its framing (`Content-Length`, chunked or close
    /// delimited); a `Content-Length` over it fails at once, other bodies once they pass it,
    /// with [`ClientError::TooLarge`]. `usize::MAX` opts out. Default 64 MiB.
    pub max_body_bytes: usize,
    /// Total time from [`Client::request`] to the complete response (connecting, sending,
    /// waiting and receiving). Past it the request fails with [`ClientError::TimedOut`] and its
    /// connection is closed. [`ClientRequest::timeout`] overrides it per request; `None` opts
    /// out. Default 30 s.
    pub request_timeout: Option<Duration>,
    /// Keep-alive connections unused for this long are closed. `None` keeps them until the
    /// server closes them. Default 90 s (Go's `IdleConnTimeout`).
    pub idle_timeout: Option<Duration>,
    /// Idle keep-alive connections kept per host (`host`, `port`, scheme); a connection that
    /// would exceed it is closed instead. 0 disables reuse. Default 32.
    pub max_idle_per_host: usize,
    /// Idle keep-alive connections kept in all. Default 256.
    pub max_idle: usize,
}

impl Default for ClientOptions {
    fn default() -> ClientOptions {
        ClientOptions {
            max_head_bytes: 64 << 10,
            max_body_bytes: 64 << 20,
            request_timeout: Some(Duration::from_secs(30)),
            idle_timeout: Some(Duration::from_secs(90)),
            max_idle_per_host: 32,
            max_idle: 256,
        }
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
    /// No complete response within the request timeout
    /// ([`ClientOptions::request_timeout`], [`ClientRequest::timeout`]).
    TimedOut,
    /// The response passed a size limit (which one).
    TooLarge(&'static str),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidUrl(u) => write!(f, "invalid url: {u}"),
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Protocol(m) => write!(f, "protocol: {m}"),
            ClientError::Closed => f.write_str("connection closed before a complete response"),
            ClientError::TimedOut => f.write_str("request timed out"),
            ClientError::TooLarge(what) => write!(f, "too large: {what}"),
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
        let deadline = Instant::now() + d;
        let mut g = self.shared.slot.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(r) = g.0.take() {
                return Some(r);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
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
        key: Key { host, port, tls },
        target,
        host_header,
    })
}

struct Pending {
    bytes: Vec<u8>,
    head_only: bool,
    retryable: bool,
    key: Key,
    /// Every resolved address, tried in order until one connects.
    addrs: Vec<SocketAddr>,
    /// When the whole request times out (set when it was made, so it covers dialing too).
    deadline: Option<Instant>,
    cb: Callback,
}

/// Idle keep-alive connections, newest last per host, with when each became idle.
#[derive(Default)]
struct Pool {
    hosts: HashMap<Key, Vec<(Conn<ClientConn>, Instant)>>,
    total: usize,
    /// A sweep of expired connections is scheduled.
    sweep_armed: bool,
}

impl Pool {
    /// Removes the connection `id` wherever it is; whether it was there.
    fn remove(&mut self, id: u64) -> bool {
        let mut found = false;
        self.hosts.retain(|_, v| {
            let n = v.len();
            v.retain(|(x, _)| x.id() != id);
            found |= v.len() != n;
            !v.is_empty()
        });
        if found {
            self.total -= 1;
        }
        found
    }

    /// Takes every connection idle since before `cutoff` out of the pool.
    fn expire(&mut self, cutoff: Instant, out: &mut Vec<Conn<ClientConn>>) {
        self.hosts.retain(|_, v| {
            // Oldest first: the expired ones are a prefix.
            let n = v.iter().take_while(|(_, t)| *t <= cutoff).count();
            out.extend(v.drain(..n).map(|(c, _)| c));
            !v.is_empty()
        });
        self.total -= out.len();
    }
}

struct Inner {
    engine: Arc<Engine>,
    tls: Option<TlsClientConfig>,
    opts: ClientOptions,
    idle: Mutex<Pool>,
    /// The engine started a graceful shutdown: connections close once their response is in
    /// instead of going back to `idle`.
    shutting_down: std::sync::atomic::AtomicBool,
}

impl Inner {
    fn pool(&self) -> std::sync::MutexGuard<'_, Pool> {
        self.idle.lock().unwrap_or_else(|e| e.into_inner())
    }
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
        Client::build(engine, None, ClientOptions::default())
    }

    fn build(engine: Arc<Engine>, tls: Option<TlsClientConfig>, opts: ClientOptions) -> Client {
        Client {
            inner: Arc::new(Inner {
                engine,
                tls,
                opts,
                idle: Mutex::new(Pool::default()),
                shutting_down: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// Enables `https://` with the given TLS client configuration (a new client: connections
    /// are not shared with `self`).
    #[must_use]
    pub fn with_tls(self, cfg: TlsClientConfig) -> Client {
        Client::build(
            self.inner.engine.clone(),
            Some(cfg),
            self.inner.opts.clone(),
        )
    }

    /// Replaces the limits (a new client: connections are not shared with `self`).
    #[must_use]
    pub fn with_options(self, opts: ClientOptions) -> Client {
        Client::build(self.inner.engine.clone(), self.inner.tls.clone(), opts)
    }

    /// The limits in force.
    pub fn options(&self) -> &ClientOptions {
        &self.inner.opts
    }

    /// Sends `req`; `done` is called once, on an I/O thread, with the outcome.
    pub fn request(
        &self,
        req: ClientRequest,
        done: impl FnOnce(Result<ClientResponse, ClientError>) + Send + 'static,
    ) {
        let cb: Callback = Box::new(done);
        let pu = match parse_url(&req.url) {
            Ok(p) => p,
            Err(e) => return cb(Err(e)),
        };
        let addrs: Vec<SocketAddr> = match (pu.key.host.as_str(), pu.key.port)
            .to_socket_addrs()
            .map_err(ClientError::Io)
        {
            Ok(a) => a.collect(),
            Err(e) => return cb(Err(e)),
        };
        if addrs.is_empty() {
            return cb(Err(ClientError::Protocol("host did not resolve")));
        }
        let mut bytes = Vec::with_capacity(160 + req.body.len());
        bytes.extend_from_slice(
            format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\n",
                req.method.as_str(),
                pu.target,
                pu.host_header
            )
            .as_bytes(),
        );
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
        let deadline = req
            .timeout
            .or(self.inner.opts.request_timeout)
            .map(|d| Instant::now() + d);
        let pending = Pending {
            bytes,
            head_only: req.method == Method::Head,
            retryable: matches!(req.method, Method::Get | Method::Head | Method::Options),
            key: pu.key,
            addrs,
            deadline,
            cb,
        };
        self.dispatch(pending);
    }

    /// Sends `req` and returns a handle to wait on or await.
    pub fn send(&self, req: ClientRequest) -> ResponseFuture {
        let shared = Arc::new(FutureShared {
            slot: Mutex::new((None, None)),
            cv: Condvar::new(),
        });
        let s = shared.clone();
        self.request(req, move |r| {
            let mut g = s.slot.lock().unwrap_or_else(|p| p.into_inner());
            g.0 = Some(r);
            if let Some(w) = g.1.take() {
                w.wake();
            }
            s.cv.notify_all();
        });
        ResponseFuture { shared }
    }

    /// Reuses an idle keep-alive connection when there is one, else dials.
    fn dispatch(&self, p: Pending) {
        let mut expired = Vec::new();
        let idle = {
            let mut pool = self.inner.pool();
            let cutoff = self
                .inner
                .opts
                .idle_timeout
                .and_then(|d| Instant::now().checked_sub(d));
            let taken = pool.hosts.get_mut(&p.key).and_then(|v| {
                let (c, since) = v.pop()?;
                if cutoff.is_some_and(|t| since <= t) {
                    // The newest is stale, so are the older ones: drop them all.
                    expired.push(c);
                    expired.extend(v.drain(..).map(|(c, _)| c));
                    None
                } else {
                    Some(c)
                }
            });
            pool.total -= expired.len() + usize::from(taken.is_some());
            if pool.hosts.get(&p.key).is_some_and(Vec::is_empty) {
                pool.hosts.remove(&p.key);
            }
            taken
        };
        for c in expired {
            c.close();
        }
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

    /// Puts a connection whose response is complete back into the pool, unless the pool is
    /// full; whether it was kept (the caller closes it otherwise).
    fn put_idle(&self, key: &Key, c: &Conn<ClientConn>) -> bool {
        let opts = &self.inner.opts;
        let arm = {
            let mut pool = self.inner.pool();
            let total = pool.total;
            let v = pool.hosts.entry(key.clone()).or_default();
            if v.len() >= opts.max_idle_per_host || total >= opts.max_idle {
                if v.is_empty() {
                    pool.hosts.remove(key);
                }
                return false;
            }
            v.push((c.clone(), Instant::now()));
            pool.total += 1;
            let arm = opts.idle_timeout.is_some() && !pool.sweep_armed;
            pool.sweep_armed |= arm;
            arm
        };
        if arm {
            Client::arm_sweep(
                Arc::downgrade(&self.inner),
                Instant::now() + opts.idle_timeout.unwrap_or_default(),
            );
        }
        true
    }

    /// Schedules a sweep of expired idle connections at `at`. The sweep holds the client weakly
    /// and re-arms itself while connections are idle, so an unused client still lets its idle
    /// connections go.
    fn arm_sweep(inner: std::sync::Weak<Inner>, at: Instant) {
        timer::at(at, move || {
            let Some(inner) = inner.upgrade() else { return };
            let Some(d) = inner.opts.idle_timeout else {
                return;
            };
            let now = Instant::now();
            let mut expired = Vec::new();
            let next = {
                let mut pool = inner.pool();
                if let Some(cutoff) = now.checked_sub(d) {
                    pool.expire(cutoff, &mut expired);
                }
                let oldest = pool
                    .hosts
                    .values()
                    .filter_map(|v| v.first())
                    .map(|x| x.1)
                    .min();
                pool.sweep_armed = oldest.is_some();
                oldest
            };
            for c in expired {
                c.close();
            }
            if let Some(t) = next {
                // A little slack batches connections that went idle together.
                Client::arm_sweep(
                    Arc::downgrade(&inner),
                    (t + d).max(now + Duration::from_millis(100)),
                );
            }
        });
    }

    fn dial(&self, p: Pending) {
        let slot = Arc::new(Mutex::new(Some(p)));
        let (key, addr) = {
            let g = slot.lock().unwrap_or_else(|e| e.into_inner());
            let p = g.as_ref().expect("just stored");
            (p.key.clone(), p.addrs[0])
        };
        let acceptor = DialAcceptor {
            pending: slot.clone(),
            client: self.clone(),
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
            let Some(cfg) = self.inner.tls.clone() else {
                return fail(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "https needs Client::with_tls",
                ));
            };
            match Tls::client(cfg, &key.host, acceptor) {
                Ok(a) => self.inner.engine.dial(addr, a, fail),
                Err(e) => fail(e),
            }
        } else {
            self.inner.engine.dial(addr, acceptor, fail);
        }
    }
}

struct DialAcceptor {
    pending: Arc<Mutex<Option<Pending>>>,
    client: Client,
}

impl Acceptor for DialAcceptor {
    type Handler = ClientConn;

    fn on_open(&self, c: &Conn<ClientConn>) -> ClientConn {
        let mut h = ClientConn::new();
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
        inner
            .shutting_down
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let was_idle = inner.pool().remove(c.id());
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
    /// Head bytes of interim (1xx) responses already received for the request in flight.
    head_seen: usize,
    /// When the request in flight times out (`timer::ms`), 0 when none.
    deadline: u64,
    /// The connection's one deadline timer, re-armed lazily (no timer message per request).
    watch: Arc<timer::Watch>,
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
            head_seen: 0,
            deadline: 0,
            watch: timer::Watch::new(),
        }
    }

    fn opts(&self) -> Option<&ClientOptions> {
        self.client.as_ref().map(|c| &c.inner.opts)
    }

    fn disarm(&mut self) {
        self.deadline = 0;
        self.watch.set(0);
    }

    /// Arms the connection's watch for `self.deadline`.
    fn arm(&self, c: &Conn<Self>) {
        self.watch.set(self.deadline);
        let conn = c.clone();
        self.watch.ensure_armed(move || {
            let hop = conn.spawn_blocking(|| (), move |h: &mut ClientConn, c, ()| h.on_deadline(c));
            if hop.is_err() && conn.is_open() {
                // The pool refused the hop: closing still ends the request (as `Closed`).
                conn.close();
            }
        });
    }

    /// The watch fired: fail the request in flight if its deadline passed (and drop the
    /// connection, its state is unknown), else re-arm for the current one.
    fn on_deadline(&mut self, c: &Conn<Self>) {
        if self.active.is_none() || self.deadline == 0 {
            return;
        }
        if self.deadline <= timer::now_ms() {
            self.fail(c, ClientError::TimedOut);
        } else {
            self.arm(c);
        }
    }

    /// Starts `p` on this connection: remember the callback, write the request.
    fn begin(&mut self, c: &Conn<Self>, p: Pending, client: Client, reused: bool) {
        let Pending {
            bytes,
            head_only,
            retryable,
            key,
            addrs,
            deadline,
            cb,
        } = p;
        // Kept so a reused connection that turns out dead can be retried on a fresh one.
        let retry = (reused && retryable).then(|| Pending {
            bytes: bytes.clone(),
            head_only,
            retryable,
            key: key.clone(),
            addrs,
            deadline,
            cb: Box::new(|_| {}),
        });
        self.state = RState::Head;
        self.buf.clear();
        self.head = http1::Resume::default();
        self.head_seen = 0;
        self.received_any = false;
        self.disarm();
        self.client = Some(client);
        self.key = Some(key);
        self.active = Some(Active {
            cb,
            head_only,
            retry,
            resp: None,
            version: Version::Http11,
        });
        if let Some(at) = deadline {
            if at <= Instant::now() {
                // Spent dialing (the engine's connect timeout may be longer).
                return self.fail(c, ClientError::TimedOut);
            }
            self.deadline = timer::ms(at);
            self.arm(c);
        }
        if c.send_owned(bytes).is_err() {
            self.fail(c, ClientError::Closed);
        }
    }

    fn fail(&mut self, c: &Conn<Self>, e: ClientError) {
        self.state = RState::Idle;
        self.disarm();
        if let Some(a) = self.active.take() {
            // A reused connection the server had already closed: one retry on a fresh one.
            if let (Some(mut p), Some(client), false) =
                (a.retry, self.client.clone(), self.received_any)
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
        self.disarm();
        let Some(a) = self.active.take() else { return };
        let resp = a.resp.expect("response head parsed");
        let shutting_down = self.client.as_ref().is_some_and(|cl| {
            cl.inner
                .shutting_down
                .load(std::sync::atomic::Ordering::Relaxed)
        });
        let reusable = keep_alive
            && !shutting_down
            && a.version == Version::Http11
            && !resp.headers.has_token("connection", "close");
        let kept = reusable
            && match (&self.client, &self.key) {
                (Some(client), Some(key)) => client.put_idle(key, c),
                _ => false,
            };
        if !kept {
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
                    let max_head = self.opts().map_or(usize::MAX, |o| o.max_head_bytes);
                    let mut storage = [http1::Header::EMPTY; 100];
                    let r = match http1::parse_response(&self.buf, &mut storage, &mut self.head) {
                        Ok(http1::Status::Complete(r)) => r,
                        Ok(http1::Status::Partial) => {
                            if self.head_seen + self.buf.len() > max_head {
                                return self
                                    .fail(c, ClientError::TooLarge("response head too large"));
                            }
                            return;
                        }
                        Err(_) => return self.fail(c, ClientError::Protocol("bad response head")),
                    };
                    let (n, status) = (r.len, r.code);
                    if self.head_seen + n > max_head {
                        return self.fail(c, ClientError::TooLarge("response head too large"));
                    }
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
                        // Interim response: the real one follows (all heads count toward the
                        // head limit, so endless 1xx responses end too).
                        self.head_seen += n;
                        self.head = http1::Resume::default();
                        continue;
                    }
                    let head_only = self.active.as_ref().is_some_and(|a| a.head_only);
                    let no_body = head_only || status == 204 || status == 304 || status == 101;
                    let te_chunked = headers.has_token("transfer-encoding", "chunked");
                    let cl = headers.get("content-length").map(str::parse::<usize>);
                    let max_body = self.opts().map_or(usize::MAX, |o| o.max_body_bytes);
                    let next = if no_body {
                        None
                    } else if te_chunked {
                        Some(RState::Chunked(Box::new(ChunkDecoder::new())))
                    } else {
                        match cl {
                            Some(Ok(0)) => None,
                            Some(Ok(n)) if n > max_body => {
                                return self
                                    .fail(c, ClientError::TooLarge("response body too large"));
                            }
                            Some(Ok(n)) => Some(RState::Body { left: n }),
                            Some(Err(_)) => {
                                return self.fail(c, ClientError::Protocol("bad Content-Length"));
                            }
                            None => Some(RState::UntilClose),
                        }
                    };
                    if let Some(a) = &mut self.active {
                        a.version = version;
                        let reserve = match &next {
                            Some(RState::Body { left }) => (*left).min(1 << 20),
                            _ => 0,
                        };
                        a.resp = Some(ClientResponse {
                            status,
                            reason,
                            headers,
                            body: Vec::with_capacity(reserve),
                            trailers: Headers::new(),
                            pushed: Vec::new(),
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
                    if let Some(r) = self.active.as_mut().and_then(|a| a.resp.as_mut()) {
                        r.body.extend_from_slice(&self.buf[..n]);
                    }
                    self.buf.drain(..n);
                    if done {
                        self.complete(c, true);
                    }
                }
                RState::Chunked(dec) => {
                    if self.buf.is_empty() {
                        return;
                    }
                    let max_body = self
                        .client
                        .as_ref()
                        .map_or(usize::MAX, |c| c.inner.opts.max_body_bytes);
                    let have = self
                        .active
                        .as_ref()
                        .and_then(|a| a.resp.as_ref())
                        .map_or(0, |r| r.body.len());
                    let mut out = Vec::new();
                    match dec.feed(&self.buf, &mut out, max_body.saturating_sub(have)) {
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
                        Err(crate::parse::ChunkError::TooLarge) => {
                            return self.fail(c, ClientError::TooLarge("response body too large"));
                        }
                        Err(_) => return self.fail(c, ClientError::Protocol("bad chunked body")),
                    }
                }
                RState::UntilClose => {
                    let max_body = self
                        .client
                        .as_ref()
                        .map_or(usize::MAX, |c| c.inner.opts.max_body_bytes);
                    let mut over = false;
                    if let Some(r) = self.active.as_mut().and_then(|a| a.resp.as_mut()) {
                        over = r.body.len() + self.buf.len() > max_body;
                        if !over {
                            r.body.extend_from_slice(&self.buf);
                        }
                    }
                    self.buf.clear();
                    if over {
                        return self.fail(c, ClientError::TooLarge("response body too large"));
                    }
                    return;
                }
            }
        }
    }
}

/// Request and idle deadlines of the HTTP clients: one lazily started thread with a heap,
/// fed through a channel (no lock shared by the I/O threads). Jobs must be quick: they only hand
/// work to a connection's I/O thread or close connections.
pub(crate) mod timer {
    use std::{
        cmp::Reverse,
        collections::BinaryHeap,
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
            mpsc::{self, RecvTimeoutError, Sender},
        },
        time::Instant,
    };

    type Job = Box<dyn FnOnce() + Send>;

    /// A job in the heap, ordered by when it runs (then by arrival).
    struct Entry(Instant, u64, Job);

    impl PartialEq for Entry {
        fn eq(&self, o: &Entry) -> bool {
            (self.0, self.1) == (o.0, o.1)
        }
    }
    impl Eq for Entry {}
    impl PartialOrd for Entry {
        fn partial_cmp(&self, o: &Entry) -> Option<std::cmp::Ordering> {
            Some(self.cmp(o))
        }
    }
    impl Ord for Entry {
        fn cmp(&self, o: &Entry) -> std::cmp::Ordering {
            (self.0, self.1).cmp(&(o.0, o.1))
        }
    }

    fn sender() -> &'static Sender<(Instant, Job)> {
        static TX: OnceLock<Sender<(Instant, Job)>> = OnceLock::new();
        TX.get_or_init(|| {
            let (tx, rx) = mpsc::channel::<(Instant, Job)>();
            std::thread::Builder::new()
                .name("only-http-timer".into())
                .spawn(move || run(&rx))
                .expect("spawn only-http timer thread");
            tx
        })
    }

    fn run(rx: &mpsc::Receiver<(Instant, Job)>) {
        let mut heap: BinaryHeap<Reverse<Entry>> = BinaryHeap::new();
        let mut seq = 0u64;
        loop {
            let now = Instant::now();
            while heap.peek().is_some_and(|Reverse(e)| e.0 <= now) {
                let Reverse(Entry(_, _, job)) = heap.pop().expect("peeked");
                job();
            }
            let msg = match heap.peek() {
                Some(Reverse(e)) => rx.recv_timeout(e.0.saturating_duration_since(Instant::now())),
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match msg {
                Ok((at, job)) => {
                    seq += 1;
                    heap.push(Reverse(Entry(at, seq, job)));
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    /// Runs `job` on the timer thread at `at`. Callers keep this off the per-request path:
    /// request deadlines go through a [`Watch`].
    pub(crate) fn at(at: Instant, job: impl FnOnce() + Send + 'static) {
        let _ = sender().send((at, Box::new(job)));
    }

    fn epoch() -> Instant {
        static E: OnceLock<Instant> = OnceLock::new();
        *E.get_or_init(Instant::now)
    }

    /// `t` in whole milliseconds (rounded up) since a process epoch, never 0.
    pub(crate) fn ms(t: Instant) -> u64 {
        let d = t.saturating_duration_since(epoch());
        (d.as_nanos().div_ceil(1_000_000) as u64) + 1
    }

    pub(crate) fn now_ms() -> u64 {
        ms(Instant::now())
    }

    fn instant(ms: u64) -> Instant {
        epoch() + std::time::Duration::from_millis(ms.saturating_sub(1))
    }

    /// One owner's deadline (a connection's): at most one timer job is pending for it. Moving
    /// the deadline is an atomic store; the job, when it fires, re-arms itself for a later
    /// deadline, stops on 0, and calls back only once the deadline passed. A request costs no
    /// timer message unless the watch was idle.
    pub(crate) struct Watch {
        at: AtomicU64,
        /// When the pending job runs (`ms`), 0 when none is pending.
        armed_at: AtomicU64,
    }

    impl Watch {
        pub(crate) fn new() -> std::sync::Arc<Watch> {
            std::sync::Arc::new(Watch {
                at: AtomicU64::new(0),
                armed_at: AtomicU64::new(0),
            })
        }

        /// Sets the deadline (`ms`), 0 for none.
        pub(crate) fn set(&self, at: u64) {
            self.at.store(at, Ordering::SeqCst);
        }

        /// Makes sure a job is pending no later than the deadline; `due` runs on the timer
        /// thread once the deadline passed (it must be quick and decide again on its owner's
        /// thread). An earlier deadline than the pending job's gets a job of its own; the
        /// superseded one then does nothing.
        pub(crate) fn ensure_armed<F: Fn() + Clone + Send + 'static>(
            self: &std::sync::Arc<Self>,
            due: F,
        ) {
            let at = self.at.load(Ordering::SeqCst);
            if at == 0 {
                return;
            }
            let mut cur = self.armed_at.load(Ordering::SeqCst);
            loop {
                if cur != 0 && cur <= at {
                    return;
                }
                match self
                    .armed_at
                    .compare_exchange(cur, at, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => break,
                    Err(now) => cur = now,
                }
            }
            let w = self.clone();
            self::at(instant(at), move || {
                if w.armed_at
                    .compare_exchange(at, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    return; // superseded by an earlier job
                }
                let deadline = w.at.load(Ordering::SeqCst);
                if deadline == 0 {
                    return;
                }
                if deadline > now_ms() {
                    w.ensure_armed(due);
                } else {
                    due();
                }
            });
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
                // Closed while idle (by the server, or expired): leave the pool.
                self.disarm();
                if let Some(cl) = &self.client {
                    cl.inner.pool().remove(c.id());
                }
            }
            _ => self.fail(c, ClientError::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
