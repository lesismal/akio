//! An asynchronous HTTP/1.1 client on flash's engine: callbacks or a waitable/awaitable result,
//! keep-alive connection reuse per host, chunked and close-delimited bodies, HTTPS through
//! `flash::tls`.
//!
//! Callbacks run on an I/O thread and must not block. Name resolution and building the request
//! happen on the calling thread (resolution may block). Redirects are not followed and there is
//! no per-request timeout beyond the engine's `idle_timeout` and [`ResponseFuture::wait_timeout`].

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::{Context as TaskContext, Poll, Waker},
    time::Duration,
};

use flash::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, Tls},
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
}

impl ClientRequest {
    /// A request with `method` to `url`, no headers and an empty body.
    pub fn new(method: Method, url: &str) -> ClientRequest {
        ClientRequest {
            method,
            url: url.to_owned(),
            headers: Headers::new(),
            body: Vec::new(),
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
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidUrl(u) => write!(f, "invalid url: {u}"),
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Protocol(m) => write!(f, "protocol: {m}"),
            ClientError::Closed => f.write_str("connection closed before a complete response"),
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
    cb: Callback,
}

struct Inner {
    engine: Arc<Engine>,
    tls: Option<TlsClientConfig>,
    idle: Mutex<HashMap<Key, Vec<Conn<ClientConn>>>>,
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
        Client {
            inner: Arc::new(Inner {
                engine,
                tls: None,
                idle: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Enables `https://` with the given TLS client configuration.
    #[must_use]
    pub fn with_tls(self, cfg: TlsClientConfig) -> Client {
        Client {
            inner: Arc::new(Inner {
                engine: self.inner.engine.clone(),
                tls: Some(cfg),
                idle: Mutex::new(HashMap::new()),
            }),
        }
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
            bytes.extend_from_slice(b"User-Agent: flash-http\r\n");
        }
        if !req.body.is_empty() || matches!(req.method, Method::Post | Method::Put | Method::Patch)
        {
            bytes.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&req.body);
        let pending = Pending {
            bytes,
            head_only: req.method == Method::Head,
            retryable: matches!(req.method, Method::Get | Method::Head | Method::Options),
            key: pu.key,
            addrs,
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
            cb,
        } = p;
        // Kept so a reused connection that turns out dead can be retried on a fresh one.
        let retry = (reused && retryable).then(|| Pending {
            bytes: bytes.clone(),
            head_only,
            retryable,
            key: key.clone(),
            addrs,
            cb: Box::new(|_| {}),
        });
        self.state = RState::Head;
        self.buf.clear();
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
        let Some(a) = self.active.take() else { return };
        let resp = a.resp.expect("response head parsed");
        let reusable = keep_alive
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
                    let mut storage = [httparse::EMPTY_HEADER; 100];
                    let mut r = httparse::Response::new(&mut storage);
                    let n = match r.parse(&self.buf) {
                        Ok(httparse::Status::Complete(n)) => n,
                        Ok(httparse::Status::Partial) => return,
                        Err(_) => return self.fail(c, ClientError::Protocol("bad response head")),
                    };
                    let status = r.code.unwrap_or(0);
                    let mut headers = Headers::new();
                    for h in r.headers.iter() {
                        let Ok(v) = std::str::from_utf8(h.value) else {
                            return self.fail(c, ClientError::Protocol("non-UTF-8 header"));
                        };
                        headers.append(h.name, v.trim());
                    }
                    let version = if r.version == Some(0) {
                        Version::Http10
                    } else {
                        Version::Http11
                    };
                    let reason = r.reason.unwrap_or("").to_owned();
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
    let c: Conn<ClientConn> = flash_core::fuzzing::conn();
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

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<flash::Error>) {
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
