//! An asynchronous HTTP/1.1 client on `akio`'s engine: callbacks or a waitable/awaitable result,
//! keep-alive connection reuse per host, chunked and close-delimited bodies, HTTPS through
//! `akio::tls` (the system's CAs by default), opt-in redirects ([`RedirectPolicy`]), per-request
//! timeouts, HTTP and SOCKS proxies ([`Proxy`], `https://` proxies included), name resolution
//! off the calling thread with Happy Eyeballs connection racing ([`akio::dns`]) and an opt-in
//! cookie jar ([`Client::with_cookies`]). See ADR-010 and ADR-059 for the rules.
//!
//! ```no_run
//! # use std::{sync::Arc, time::Duration};
//! use akio::Engine;
//! use akio_http::client::{Client, ClientRequest, Proxy, RedirectPolicy};
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
//!
//! Responses and the keep-alive pool are bounded by [`ClientOptions`]: the response head
//! (64 KiB) and body (64 MiB), and the idle pool (32 connections per host, 256 in all, closed
//! after 90 s unused).

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    },
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant},
};

use akio::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, RootCerts, Tls},
};
use akio_core::ConnInner;

use crate::raw::{RawConn, RawHandler};
pub use akio_ws::proxy::{Proxy, ProxyRefused};
use akio_ws::{
    http1,
    proxy::{Connect, ProxyServer, Refusal},
};

use crate::{
    cookie::CookieJar,
    deadline::{OnDeadline, Watch},
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
    /// Extra header fields. `Content-Length` is the body's own, whatever a field here says.
    /// `Host` is taken from the URL unless a `Host` field here gives another (a reverse proxy
    /// passing its client's on): the URL still says where to connect, and which name TLS asks
    /// for. A `User-Agent` of `akio-http` is added when there is none; an empty `User-Agent`
    /// field sends none at all, as Go's client takes it.
    pub headers: Headers,
    /// Request body.
    pub body: Vec<u8>,
    /// Limit for this request from start to the complete response, redirects included; `None`
    /// uses the client's ([`Client::with_timeout`]). On expiry the request fails with
    /// [`ClientError::Timeout`] and its connection is closed.
    pub timeout: Option<Duration>,
    /// A body written after the head, as it is produced ([`Client::request_streamed`],
    /// [`Client::request_with`]), and how it is framed; [`body`](Self::body) is then not sent.
    /// [`Client::request`] and [`Client::send`] ignore it and send `body`, as does
    /// [`H2Client`](crate::h2client::H2Client). `None` by default.
    pub streamed: Option<StreamedBody>,
    /// Limit on the wait for the response's head once the request is written whole (its last
    /// byte queued: at once for a body given whole, at [`RequestBody::finish`] for a streamed
    /// one), interim 1xx responses included; `None` uses the client's
    /// ([`ClientOptions::response_header_timeout`]). Past it the request fails with
    /// [`ClientError::HeaderTimeout`] and its connection is closed (ADR-108). Each redirect
    /// hop has its own. [`H2Client`](crate::h2client::H2Client) heeds it too (ADR-111): from
    /// the request's END_STREAM to the final response's HEADERS, past which the stream alone is
    /// reset.
    pub response_header_timeout: Option<Duration>,
    /// Limit on the gap between two reads of the response's body, from its head on; `None`
    /// uses the client's ([`ClientOptions::response_idle_timeout`]). Past it the request fails
    /// with [`ClientError::IdleTimeout`] (after [`ResponseHandler::on_head`] for a response
    /// delivered as it arrives) and its connection is closed. The time reads are held
    /// ([`ResponseBody::hold_reads`]) does not count (ADR-108). [`H2Client`] heeds it too
    /// (ADR-111): the longest gap between the response's DATA frames from its head on, the time
    /// its reads are held ([`H2Stream::hold_reads`]) not counted; past it the stream alone is
    /// reset.
    ///
    /// [`H2Client`]: crate::h2client::H2Client
    /// [`H2Stream::hold_reads`]: crate::h2client::H2Stream::hold_reads
    pub response_idle_timeout: Option<Duration>,
    /// Cancels the request when cancelled ([`CancelToken::cancel`], ADR-108). `None` by
    /// default. [`H2Client`](crate::h2client::H2Client) heeds it too (ADR-111): the stream is
    /// reset (`CANCEL`), or a request still waiting for one dropped unsent.
    pub cancel: Option<CancelToken>,
}

/// How a request body written as it is produced is framed ([`ClientRequest::streamed`], ADR-101).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamedBody {
    /// `Content-Length`: exactly this many bytes follow.
    Length(u64),
    /// `Transfer-Encoding: chunked`: each write is a chunk, ended by
    /// [`RequestBody::finish`].
    Chunked,
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
            streamed: None,
            response_header_timeout: None,
            response_idle_timeout: None,
            cancel: None,
        }
    }

    /// Marks the body as written later through a [`RequestBody`]: `len` bytes framed by
    /// `Content-Length` when known, chunked otherwise ([`streamed`](Self::streamed)).
    #[must_use]
    pub fn streamed(mut self, len: Option<u64>) -> ClientRequest {
        self.streamed = Some(match len {
            Some(n) => StreamedBody::Length(n),
            None => StreamedBody::Chunked,
        });
        self
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

    /// Sets this request's response header timeout
    /// ([`response_header_timeout`](Self::response_header_timeout)).
    #[must_use]
    pub fn response_header_timeout(mut self, d: Duration) -> ClientRequest {
        self.response_header_timeout = Some(d);
        self
    }

    /// Sets this request's response idle timeout
    /// ([`response_idle_timeout`](Self::response_idle_timeout)).
    #[must_use]
    pub fn response_idle_timeout(mut self, d: Duration) -> ClientRequest {
        self.response_idle_timeout = Some(d);
        self
    }

    /// Cancels this request when `token` is cancelled ([`cancel`](Self::cancel)).
    #[must_use]
    pub fn cancel_with(mut self, token: &CancelToken) -> ClientRequest {
        self.cancel = Some(token.clone());
        self
    }

    /// Asks the server to switch to `protocol` (RFC 9110 section 7.8; `websocket`, say): adds
    /// `Connection: Upgrade` and `Upgrade: <protocol>`. A request that carries these fields
    /// itself asks the same. Its `101 Switching Protocols` hands the connection over to the
    /// handler of [`Client::request_with`] ([`ResponseHandler::on_upgrade`], ADR-113); any
    /// other answer is an ordinary response. HTTP/1 client only.
    #[must_use]
    pub fn upgrade(mut self, protocol: &str) -> ClientRequest {
        self.headers.set("Connection", "Upgrade");
        self.headers.set("Upgrade", protocol);
        self
    }
}

/// Cancels the requests given it ([`ClientRequest::cancel_with`], ADR-108) at any point: before
/// a request is sent it is dropped; once sent, its connection is closed. The request then fails
/// with [`ClientError::Cancelled`], once, unless it was over already: a whole response's
/// callback is called on the thread that cancels, a [`ResponseHandler`] gets
/// [`on_error`](ResponseHandler::on_error) on the connection's I/O thread (or, before there is
/// a connection, on the thread that resolves or dials it, once that is done). An
/// [`H2Client`](crate::h2client::H2Client)'s request has its stream reset (`CANCEL`) and fails
/// on the connection's I/O thread, its connection left to its other streams (ADR-111).
///
/// Cheap to clone and usable from any thread. One token may serve several requests (the
/// attempts of a retrying proxy, say): cancelling it cancels every one of them that is not over,
/// and a request given a token already cancelled fails at once.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<Mutex<TokenState>>);

#[derive(Default)]
struct TokenState {
    cancelled: bool,
    /// The requests given the token; finished ones are pruned as more are added.
    exchanges: Vec<Target>,
}

/// A request a [`CancelToken`] cancels: an HTTP/1 client's, or a stream of an
/// [`H2Client`](crate::h2client::H2Client) (ADR-111).
enum Target {
    Http1(Weak<Exchange>),
    H2(crate::h2client::CancelTarget),
}

impl Target {
    fn alive(&self) -> bool {
        match self {
            Target::Http1(w) => w.strong_count() > 0,
            Target::H2(t) => t.alive(),
        }
    }

    fn cancel(&self) {
        match self {
            Target::Http1(w) => {
                if let Some(ex) = w.upgrade() {
                    ex.give_up(GaveUp::Cancelled);
                }
            }
            Target::H2(t) => t.cancel(),
        }
    }
}

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl CancelToken {
    /// A token not cancelled.
    pub fn new() -> CancelToken {
        CancelToken::default()
    }

    /// Cancels every request given the token that is not over (and any given it later).
    pub fn cancel(&self) {
        let exchanges = {
            let mut st = lock_or(&self.0);
            if st.cancelled {
                return;
            }
            st.cancelled = true;
            std::mem::take(&mut st.exchanges)
        };
        for t in &exchanges {
            t.cancel();
        }
    }

    /// Whether [`cancel`](Self::cancel) was called.
    pub fn is_cancelled(&self) -> bool {
        lock_or(&self.0).cancelled
    }

    /// Ties `ex` to the token; `false` when the token is already cancelled.
    fn attach(&self, ex: &Arc<Exchange>) -> bool {
        self.attach_target(Target::Http1(Arc::downgrade(ex)))
    }

    /// Ties an HTTP/2 stream to the token; `false` when the token is already cancelled.
    pub(crate) fn attach_h2(&self, t: crate::h2client::CancelTarget) -> bool {
        self.attach_target(Target::H2(t))
    }

    fn attach_target(&self, t: Target) -> bool {
        let mut st = lock_or(&self.0);
        if st.cancelled {
            return false;
        }
        if st.exchanges.len() == st.exchanges.capacity() {
            st.exchanges.retain(Target::alive);
        }
        st.exchanges.push(t);
        true
    }
}

/// Limits of a [`Client`] ([`Client::with_options`]). Every one has a safe default; raise them
/// where a peer is trusted. The request timeout is [`Client::with_timeout`].
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
    /// Keep-alive connections unused for this long are closed. `None` keeps them until the
    /// server closes them. Default 90 s (Go's `IdleConnTimeout`).
    pub idle_timeout: Option<Duration>,
    /// Idle keep-alive connections kept per route (host, port, scheme, proxy); a connection
    /// that would exceed it is closed instead. 0 disables reuse. Default 32.
    pub max_idle_per_host: usize,
    /// Idle keep-alive connections kept in all. Default 256.
    pub max_idle: usize,
    /// How the addresses of a server (or proxy) are raced when it has several (RFC 8305:
    /// IPv6 and IPv4 interleaved, a new attempt every 250 ms by default).
    pub happy_eyeballs: akio::dns::HappyEyeballs,
    /// Default [`ClientRequest::response_header_timeout`]. `None` by default (the request
    /// timeout, if any, bounds the wait).
    pub response_header_timeout: Option<Duration>,
    /// Default [`ClientRequest::response_idle_timeout`]. `None` by default (the request
    /// timeout, if any, bounds the body).
    pub response_idle_timeout: Option<Duration>,
}

impl Default for ClientOptions {
    fn default() -> ClientOptions {
        ClientOptions {
            max_head_bytes: 64 << 10,
            max_body_bytes: 64 << 20,
            idle_timeout: Some(Duration::from_secs(90)),
            max_idle_per_host: 32,
            max_idle: 256,
            happy_eyeballs: akio::dns::HappyEyeballs::default(),
            response_header_timeout: None,
            response_idle_timeout: None,
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
    /// The response passed a size limit of [`ClientOptions`] (which one).
    TooLarge(&'static str),
    /// The server refused a WebSocket ([`H2Client::websocket`](crate::h2client::H2Client::websocket))
    /// with this status.
    Status(u16),
    /// The response's head did not come within [`ClientRequest::response_header_timeout`].
    HeaderTimeout,
    /// The response's body went silent for [`ClientRequest::response_idle_timeout`].
    IdleTimeout,
    /// The request was cancelled ([`CancelToken::cancel`], or an HTTP/2 stream's
    /// [`H2Stream::cancel`](crate::h2client::H2Stream::cancel)).
    Cancelled,
    /// The server did not process the request, so it may be sent again, on another connection
    /// (HTTP/2: a stream above a `GOAWAY`'s last stream id, a stream reset with
    /// `REFUSED_STREAM`, or a request made after a `GOAWAY`; ADR-110).
    Refused,
    /// The HTTP/2 connection had no stream free under the server's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`, and its queue of requests waiting for one was full
    /// ([`H2Options::max_pending_streams`](crate::h2client::H2Options::max_pending_streams)).
    Busy,
}

impl ClientError {
    /// Whether this is one of the timeouts ([`Timeout`](Self::Timeout),
    /// [`HeaderTimeout`](Self::HeaderTimeout), [`IdleTimeout`](Self::IdleTimeout)).
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            ClientError::Timeout | ClientError::HeaderTimeout | ClientError::IdleTimeout
        )
    }
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
            ClientError::TooLarge(what) => write!(f, "too large: {what}"),
            ClientError::Status(s) => write!(f, "WebSocket refused with status {s}"),
            ClientError::HeaderTimeout => f.write_str("timed out waiting for the response head"),
            ClientError::IdleTimeout => f.write_str("response body idle too long"),
            ClientError::Cancelled => f.write_str("request cancelled"),
            ClientError::Refused => {
                f.write_str("request refused by the server before processing (may be retried)")
            }
            ClientError::Busy => {
                f.write_str("no stream free on the connection, and its queue full")
            }
        }
    }
}

impl std::error::Error for ClientError {}

type Callback = Box<dyn FnOnce(Result<ClientResponse, ClientError>) + Send>;

/// Called with the body of a streamed request once its head is written.
type Ready = Box<dyn FnOnce(RequestBody) + Send>;

fn lock_or<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The body of a request sent as it is produced ([`Client::request_streamed`],
/// [`ResponseHandler::on_request_body`], ADR-101). Usable from any thread.
///
/// Each [`write`](Self::write) is copied into the connection's send queue (a chunk of its own
/// when the body is chunked). Pace the producer with [`queued_bytes`](Self::queued_bytes) and
/// [`on_drain`](Self::on_drain): the client's reads of the response do not pause on this queue
/// (the connection is a relay end), so nothing else bounds it but
/// `Config::max_queued_bytes`, past which writes fail.
///
/// Dropping it unfinished closes the connection: the request fails with
/// [`ClientError::Closed`] unless its response was already complete. A response may come
/// (whole, too) before the body is finished, an early 413 say; the connection is then closed
/// once the response is in, and later writes fail.
pub struct RequestBody {
    shared: Arc<ReqBody>,
    done: bool,
}

impl std::fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestBody").finish_non_exhaustive()
    }
}

/// What a [`RequestBody`] and its connection share.
struct ReqBody {
    conn: Arc<ConnInner>,
    st: Mutex<ReqBodyState>,
    /// The response header timeout, armed when the body is finished.
    header: Option<(Arc<ConnTimer>, Duration)>,
}

struct ReqBodyState {
    framing: StreamedBody,
    written: u64,
    finished: bool,
    /// The request is over (its response complete, or failed): nothing more is sent.
    aborted: bool,
    /// The response's head came (a finish after it arms no header timeout).
    head_in: bool,
}

impl ReqBody {
    /// The request ends: whether its body was finished (the connection may be reused). An
    /// unfinished body can no longer be written.
    fn settle(&self) -> bool {
        let mut st = lock_or(&self.st);
        if !st.finished {
            st.aborted = true;
        }
        st.finished
    }
}

impl RequestBody {
    /// Appends body bytes. `Err(Closed)` when the request is over or its connection gone, or
    /// when `data` would pass a `Content-Length` body's length (the request is then failed);
    /// `Err(Overloaded)` past the connection's `max_queued_bytes`.
    pub fn write(&self, data: &[u8]) -> akio_core::Result<()> {
        let mut st = lock_or(&self.shared.st);
        if st.finished || st.aborted {
            return Err(akio_core::Error::Closed);
        }
        if data.is_empty() {
            return Ok(());
        }
        let c = &self.shared.conn;
        match st.framing {
            StreamedBody::Length(n) => {
                if st.written + data.len() as u64 > n {
                    st.aborted = true;
                    c.close();
                    return Err(akio_core::Error::Closed);
                }
                c.send(data)?;
            }
            StreamedBody::Chunked => {
                let mut out = Vec::with_capacity(data.len() + 20);
                crate::context::push_chunk_size(&mut out, data.len());
                out.extend_from_slice(data);
                out.extend_from_slice(b"\r\n");
                c.send_owned(out)?;
            }
        }
        st.written += data.len() as u64;
        Ok(())
    }

    /// Bytes written but not yet on the wire (the connection's send queue).
    pub fn queued_bytes(&self) -> usize {
        self.shared.conn.queued_bytes()
    }

    /// Calls `f` once everything queued is written (at once, on this thread, if nothing is),
    /// or when the connection closes; otherwise on the connection's I/O thread. Replaces an
    /// earlier waiter.
    pub fn on_drain(&self, f: impl FnOnce() + Send + 'static) {
        self.shared.conn.on_drain(Box::new(f));
    }

    /// Ends the body: the last chunk, or a check that the `Content-Length` was written in full
    /// (when it was not, the request fails and `Err(Closed)` is returned).
    pub fn finish(self) -> akio_core::Result<()> {
        self.finish_with_trailers(Headers::new())
    }

    /// Like [`finish`](Self::finish), with trailer fields after a chunked body (dropped for a
    /// `Content-Length` one, which has nowhere to put them).
    pub fn finish_with_trailers(mut self, trailers: Headers) -> akio_core::Result<()> {
        self.done = true;
        let mut st = lock_or(&self.shared.st);
        if st.finished || st.aborted {
            return Err(akio_core::Error::Closed);
        }
        let c = &self.shared.conn;
        match st.framing {
            StreamedBody::Length(n) => {
                if st.written != n {
                    st.aborted = true;
                    c.close();
                    return Err(akio_core::Error::Closed);
                }
            }
            StreamedBody::Chunked => {
                let mut t = Vec::with_capacity(64);
                t.extend_from_slice(b"0\r\n");
                for (n, v) in trailers.iter() {
                    t.extend_from_slice(n.as_bytes());
                    t.extend_from_slice(b": ");
                    t.extend(v.bytes().filter(|b| *b != b'\r' && *b != b'\n'));
                    t.extend_from_slice(b"\r\n");
                }
                t.extend_from_slice(b"\r\n");
                c.send_owned(t)?;
            }
        }
        st.finished = true;
        // The request is written whole: the wait for the response's head starts (unless it came
        // already, early).
        if let (false, Some((t, d))) = (st.head_in, &self.shared.header) {
            t.arm(PHASE_HEAD, *d);
        }
        Ok(())
    }
}

impl Drop for RequestBody {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut st = lock_or(&self.shared.st);
        if !st.finished && !st.aborted {
            st.aborted = true;
            self.shared.conn.close();
        }
    }
}

/// The head of a response delivered as it arrives ([`ResponseHandler::on_head`]).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResponseHead {
    /// Status code.
    pub status: u16,
    /// Reason phrase as sent.
    pub reason: String,
    /// Header fields.
    pub headers: Headers,
    /// The response's HTTP version (1.0 or 1.1).
    pub version: Version,
}

/// Controls the reads of a response delivered as it arrives ([`ResponseHandler::on_head`]).
/// Cheap to clone and usable from any thread; it does nothing once the response is over.
#[derive(Clone)]
pub struct ResponseBody {
    shared: Arc<RespBody>,
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseBody").finish_non_exhaustive()
    }
}

struct RespBody {
    conn: Arc<ConnInner>,
    /// The response is in progress.
    live: Mutex<bool>,
    /// The response idle timeout: stopped while reads are held.
    idle: Option<(Arc<ConnTimer>, Duration)>,
}

impl RespBody {
    /// The response is over: its reads are no longer held (the connection may be reused).
    fn settle(&self) {
        let mut live = lock_or(&self.live);
        if std::mem::replace(&mut *live, false) {
            self.conn.hold_reads(false);
        }
    }
}

impl ResponseBody {
    /// Stops (`true`) or resumes (`false`) reading the connection, so that the server stops
    /// sending once the socket buffers fill. Bytes already read are still delivered: at most one
    /// read's worth arrives after holding.
    ///
    /// While reads are held, the response idle timeout
    /// ([`ClientRequest::response_idle_timeout`]) is stopped; it starts again on resuming.
    pub fn hold_reads(&self, hold: bool) {
        let live = lock_or(&self.shared.live);
        if *live {
            self.shared.conn.hold_reads(hold);
            if let Some((t, d)) = &self.shared.idle {
                if hold {
                    t.disarm();
                } else {
                    t.arm(PHASE_IDLE, *d);
                }
            }
        }
    }

    /// Abandons the response: closes the connection. The handler then gets
    /// [`on_error`](ResponseHandler::on_error) with [`ClientError::Closed`] (with
    /// [`ClientError::Cancelled`] when the request was cancelled meanwhile).
    pub fn cancel(&self) {
        let live = lock_or(&self.shared.live);
        if *live {
            self.shared.conn.close();
        }
    }
}

/// Receives a response as it arrives ([`Client::request_with`], ADR-101). Its methods run on the
/// connection's I/O thread (or as the module documentation says for a failure before there is
/// a connection) and must not block. After [`on_head`](Self::on_head), exactly one of
/// [`on_end`](Self::on_end) and [`on_error`](Self::on_error) follows; a failure before the head
/// calls `on_error` alone.
pub trait ResponseHandler: Send + 'static {
    /// The request's body, when it is streamed ([`ClientRequest::streamed`]), once its head is
    /// written. The default drops it, which fails the request.
    fn on_request_body(&mut self, body: RequestBody) {
        drop(body);
    }
    /// The response head (interim 1xx responses are skipped). `body` holds and resumes the
    /// reads of the body that follows.
    fn on_head(&mut self, head: ResponseHead, body: ResponseBody);
    /// A piece of the body, as read (dechunked); valid for the call only.
    fn on_data(&mut self, chunk: &[u8]);
    /// The body is complete, with the trailer fields of a chunked one.
    fn on_end(&mut self, trailers: &Headers);
    /// The request failed (after the head: the body did not complete).
    fn on_error(&mut self, e: ClientError);
    /// A `101 Switching Protocols` answer to a request that asked to upgrade
    /// ([`ClientRequest::upgrade`], ADR-113): the connection is no longer HTTP's. Returning a
    /// handler hands it over as a plain byte stream: its [`on_open`](RawHandler::on_open) runs
    /// at once, then [`on_data`](RawHandler::on_data) with any bytes the server sent after the
    /// head, then as they arrive, and [`on_close`](RawHandler::on_close) when it closes. The
    /// request is over: neither [`on_head`](Self::on_head) nor [`on_end`](Self::on_end) nor
    /// [`on_error`](Self::on_error) follows, and its timeouts and cancel token no longer apply.
    ///
    /// The default returns `None`: the answer is then delivered as an ordinary response
    /// without a body (`on_head`, `on_end`) and the connection closed.
    fn on_upgrade(&mut self, _head: &ResponseHead, _conn: &RawConn) -> Option<Box<dyn RawHandler>> {
        None
    }
}

/// Where a response goes.
enum Deliver {
    /// Collected whole, then handed to a callback.
    Whole(Callback),
    /// Delivered as it arrives.
    Stream(Box<dyn ResponseHandler>),
}

impl Deliver {
    fn fail(self, e: ClientError) {
        match self {
            Deliver::Whole(cb) => cb(Err(e)),
            Deliver::Stream(mut h) => h.on_error(e),
        }
    }
}

/// A [`ResponseHandler`] that stores the cookies a response sets in the client's jar.
struct Cookies {
    inner: Box<dyn ResponseHandler>,
    jar: CookieJar,
    url: String,
}

impl ResponseHandler for Cookies {
    fn on_request_body(&mut self, body: RequestBody) {
        self.inner.on_request_body(body);
    }
    fn on_head(&mut self, head: ResponseHead, body: ResponseBody) {
        if let Some(o) = crate::cookie::origin(&self.url) {
            let now = crate::cookie::now_secs();
            for v in head.headers.get_all("set-cookie") {
                self.jar.store_from(&o, v, now);
            }
        }
        self.inner.on_head(head, body);
    }
    fn on_data(&mut self, chunk: &[u8]) {
        self.inner.on_data(chunk);
    }
    fn on_end(&mut self, trailers: &Headers) {
        self.inner.on_end(trailers);
    }
    fn on_error(&mut self, e: ClientError) {
        self.inner.on_error(e);
    }
}

/// A [`ResponseHandler`] that collects the response whole for a callback
/// ([`Client::request_streamed`]).
struct Collect {
    ready: Option<Ready>,
    resp: Option<ClientResponse>,
    resp_body: Option<ResponseBody>,
    max: usize,
    done: Option<Callback>,
    url: String,
}

impl Collect {
    fn finish(&mut self, r: Outcome) {
        if let Some(cb) = self.done.take() {
            cb(r);
        }
    }
}

impl ResponseHandler for Collect {
    fn on_request_body(&mut self, body: RequestBody) {
        if let Some(f) = self.ready.take() {
            f(body);
        }
    }
    fn on_head(&mut self, head: ResponseHead, body: ResponseBody) {
        let len = head
            .headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok());
        if len.is_some_and(|n| n > self.max) {
            body.cancel();
            return self.finish(Err(ClientError::TooLarge("response body too large")));
        }
        self.resp = Some(ClientResponse {
            status: head.status,
            reason: head.reason,
            headers: head.headers,
            body: Vec::with_capacity(len.unwrap_or(0).min(1 << 20)),
            trailers: Headers::new(),
            pushed: Vec::new(),
            url: std::mem::take(&mut self.url),
        });
        self.resp_body = Some(body);
    }
    fn on_data(&mut self, chunk: &[u8]) {
        let over = match &mut self.resp {
            Some(r) if r.body.len() + chunk.len() <= self.max => {
                r.body.extend_from_slice(chunk);
                false
            }
            Some(_) => true,
            None => false,
        };
        if over {
            self.resp = None;
            if let Some(b) = self.resp_body.take() {
                b.cancel();
            }
            self.finish(Err(ClientError::TooLarge("response body too large")));
        }
    }
    fn on_end(&mut self, trailers: &Headers) {
        if let Some(mut r) = self.resp.take() {
            r.trailers = trailers.clone();
            self.finish(Ok(r));
        }
    }
    fn on_error(&mut self, e: ClientError) {
        self.finish(Err(e));
    }
}

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

/// Header fields dropped on a redirect to another origin: those that carry credentials, and a
/// `Host` the request set itself, which names the first origin.
const CROSS_ORIGIN_DROPPED: &[&str] = &["authorization", "cookie", "proxy-authorization", "host"];

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
    let url = akio_ws::url::resolve(&req.url, loc)
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
        for h in CROSS_ORIGIN_DROPPED {
            next.headers.remove(h);
        }
    }
    Ok(Some(next))
}

/// Why an exchange gave up: [`GaveUp::Timeout`] or [`GaveUp::Cancelled`] (0: it did not).
#[derive(Clone, Copy)]
#[repr(u8)]
enum GaveUp {
    Timeout = 1,
    Cancelled = 2,
}

/// One logical request across its attempts (retries, redirects): delivers the outcome once and
/// carries the timeout and the cancellation.
struct Exchange {
    done: Mutex<Option<Callback>>,
    /// The site of the first request (cookies: a chain that leaves it is cross-site).
    site: OnceLock<String>,
    cross_site: AtomicBool,
    /// The connection serving the current attempt, for the timeout or a cancel to close.
    conn: Mutex<Option<Weak<ConnInner>>>,
    /// Why the exchange gave up ([`GaveUp`]), 0 while it did not.
    gave_up: AtomicU8,
    hops: AtomicU32,
}

impl Exchange {
    fn finish(&self, r: Outcome) {
        let cb = self.done.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(cb) = cb {
            cb(r);
        }
    }

    /// The error the request failed with when it timed out or was cancelled.
    fn gave_up(&self) -> Option<ClientError> {
        match self.gave_up.load(Ordering::Acquire) {
            0 => None,
            1 => Some(ClientError::Timeout),
            _ => Some(ClientError::Cancelled),
        }
    }

    /// A response delivered as it arrives ended (its handler was told): a later timeout or
    /// cancel does nothing.
    fn settle(&self) {
        self.done.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    /// The timeout passed, or the request was cancelled: fail it and close its connection. A
    /// response delivered as it arrives learns it from its connection (or the dial).
    fn give_up(&self, why: GaveUp) {
        let cb = self.done.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(cb) = cb else { return };
        self.gave_up.store(why as u8, Ordering::Release);
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .and_then(|w| w.upgrade());
        if let Some(c) = conn {
            c.close();
        }
        cb(Err(match why {
            GaveUp::Timeout => ClientError::Timeout,
            GaveUp::Cancelled => ClientError::Cancelled,
        }));
    }
}

/// What a connection's deadline ([`ConnTimer`]) is armed for.
const PHASE_NONE: u8 = 0;
/// The response's head ([`ClientRequest::response_header_timeout`]).
const PHASE_HEAD: u8 = 1;
/// The next read of the response's body ([`ClientRequest::response_idle_timeout`]).
const PHASE_IDLE: u8 = 2;

/// A connection's response header and idle deadline (ADR-108), registered the first time a
/// request on it has either timeout. Armed from the I/O thread, and from the threads that
/// finish a streamed request body or hold a response's reads.
struct ConnTimer {
    watch: Arc<Watch<ClientConn>>,
    /// What the deadline is armed for (`PHASE_*`). Written after the deadline when arming and
    /// before it when disarming, so an expiry seen with a phase set is that phase's.
    phase: AtomicU8,
}

impl ConnTimer {
    fn arm(&self, phase: u8, d: Duration) {
        self.watch.arm(Some(d));
        self.phase.store(phase, Ordering::Release);
    }

    fn disarm(&self) {
        self.phase.store(PHASE_NONE, Ordering::Release);
        self.watch.arm(None);
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
    /// The target's address when a SOCKS proxy wants addresses (`socks5://`, `socks4://`).
    tunnel_host: Option<String>,
    ex: Arc<Exchange>,
    deliver: Deliver,
    /// The body is written later through a [`RequestBody`].
    streamed: Option<StreamedBody>,
    /// The response header and idle timeouts in force.
    header_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    /// The request asks to switch protocols (`Connection: upgrade`): a `101` hands its
    /// connection over ([`ResponseHandler::on_upgrade`]).
    upgrade: bool,
}

#[derive(Clone, Default)]
struct Settings {
    tls: Option<TlsClientConfig>,
    /// The name `https://` connections send in SNI and check the certificate against, in place
    /// of the URL's host ([`Client::with_tls_server_name`]).
    tls_server_name: Option<String>,
    redirects: RedirectPolicy,
    timeout: Option<Duration>,
    proxy: Proxy,
    opts: ClientOptions,
    cookies: Option<CookieJar>,
    /// Every connection goes to this Unix-domain socket ([`Client::with_unix_socket`]).
    unix: Option<std::path::PathBuf>,
}

/// Idle keep-alive connections, newest last per route, with when each became idle.
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

    /// Takes every connection idle since `cutoff` or before out of the pool, into `out`.
    fn expire(&mut self, cutoff: Instant, out: &mut Vec<Conn<ClientConn>>) {
        let before = out.len();
        self.hosts.retain(|_, v| {
            // Oldest first: the expired ones are a prefix.
            let n = v.iter().take_while(|(_, t)| *t <= cutoff).count();
            out.extend(v.drain(..n).map(|(c, _)| c));
            !v.is_empty()
        });
        self.total -= out.len() - before;
    }
}

struct Inner {
    engine: Arc<Engine>,
    settings: Settings,
    /// The system's CAs, built on first `https://` use without [`Client::with_tls`].
    system_tls: OnceLock<Result<TlsClientConfig, String>>,
    idle: Mutex<Pool>,
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
                idle: Mutex::new(Pool::default()),
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

    /// Sends `name` in SNI, and checks the server's certificate against it, on every `https://`
    /// connection, in place of the URL's host: for servers reached by an address whose
    /// certificate names another host, as a proxy's upstream often is. Connections are still
    /// kept and reused by the URL's host and port. An empty `name` restores the URL's host.
    #[must_use]
    pub fn with_tls_server_name(self, name: impl Into<String>) -> Client {
        let name = name.into();
        self.rebuild(|s| s.tls_server_name = (!name.is_empty()).then_some(name))
    }

    /// Connects to the Unix-domain stream socket at `path` for every request, whatever the
    /// URL's host and port, as the Docker daemon's API on `/var/run/docker.sock` is reached
    /// (ADR-120): the URL's host is still the request's `Host` and keys the idle connections,
    /// `https://` still runs TLS over the socket, and no name is resolved and no proxy used.
    /// `None` restores TCP.
    #[must_use]
    pub fn with_unix_socket(self, path: Option<std::path::PathBuf>) -> Client {
        self.rebuild(|s| s.unix = path)
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

    /// Replaces the limits ([`ClientOptions`]).
    #[must_use]
    pub fn with_options(self, opts: ClientOptions) -> Client {
        self.rebuild(|s| s.opts = opts)
    }

    /// The limits in force.
    pub fn options(&self) -> &ClientOptions {
        &self.inner.settings.opts
    }

    /// Sends requests through `proxy` where it applies: `https://` through a `CONNECT` tunnel,
    /// `http://` as absolute-form requests to the proxy. None by default; the environment is
    /// only read through [`Proxy::from_env`].
    #[must_use]
    pub fn with_proxy(self, proxy: Proxy) -> Client {
        self.rebuild(|s| s.proxy = proxy)
    }

    /// Stores the cookies responses set in `jar` and sends the matching ones with every
    /// request, each hop of a redirect chain included (the rules: [`crate::cookie`]). None by
    /// default. A `Cookie` field set on a request is kept, the jar's cookies after it.
    #[must_use]
    pub fn with_cookies(self, jar: CookieJar) -> Client {
        self.rebuild(|s| s.cookies = Some(jar))
    }

    /// The cookie jar, if any.
    pub fn cookies(&self) -> Option<&CookieJar> {
        self.inner.settings.cookies.as_ref()
    }

    /// Sends `req`; `done` is called once with the outcome (on an I/O thread, or as the module
    /// documentation says).
    pub fn request(
        &self,
        mut req: ClientRequest,
        done: impl FnOnce(Result<ClientResponse, ClientError>) + Send + 'static,
    ) {
        req.streamed = None;
        let ex = self.exchange(&req, Box::new(done));
        self.attempt(ex, req, None);
    }

    /// Sends `req` with a body written as it is produced (ADR-101): `on_ready` gets the
    /// [`RequestBody`] on the connection's I/O thread once the head is written, after a connect
    /// or on a reused connection. The body is framed as [`ClientRequest::streamed`] says
    /// (chunked when it is `None`); [`ClientRequest::body`] is not sent. `done` gets the
    /// response whole, as [`request`](Self::request) does, possibly before the body is
    /// finished.
    ///
    /// Such a request is never retried (its body cannot be sent again), nor redirected: on a
    /// reused connection the server had closed it fails with [`ClientError::Closed`] or
    /// [`ClientError::Io`], and a 3xx response is returned as it is.
    pub fn request_streamed(
        &self,
        mut req: ClientRequest,
        on_ready: impl FnOnce(RequestBody) + Send + 'static,
        done: impl FnOnce(Result<ClientResponse, ClientError>) + Send + 'static,
    ) {
        req.streamed.get_or_insert(StreamedBody::Chunked);
        let collect = Collect {
            ready: Some(Box::new(on_ready)),
            resp: None,
            resp_body: None,
            max: self.inner.settings.opts.max_body_bytes,
            done: Some(Box::new(done)),
            url: req.url.clone(),
        };
        self.request_with(req, collect);
    }

    /// Sends `req` and delivers the response to `handler` as it arrives (ADR-101): the head,
    /// then each piece of the body, whose reads the handler can hold and resume
    /// ([`ResponseBody::hold_reads`]). [`ClientOptions::max_body_bytes`] does not apply: the
    /// handler decides. A body given by [`ClientRequest::streamed`] goes to
    /// [`ResponseHandler::on_request_body`].
    ///
    /// Redirects are not followed (a 3xx response goes to the handler). The request's timeout
    /// ([`ClientRequest::timeout`], [`Client::with_timeout`]) runs until the body is complete;
    /// a retry on a fresh connection is made, as for [`request`](Self::request), only for a
    /// `GET`, `HEAD` or `OPTIONS` without a streamed body and before any byte of the response.
    /// The keep-alive pool takes the connection back after [`ResponseHandler::on_end`]. A
    /// request that asks to upgrade ([`ClientRequest::upgrade`]) may have its connection handed
    /// over on `101` ([`ResponseHandler::on_upgrade`], ADR-113).
    pub fn request_with(&self, req: ClientRequest, handler: impl ResponseHandler) {
        let ex = self.exchange(&req, Box::new(|_| {}));
        let mut h: Box<dyn ResponseHandler> = Box::new(handler);
        if let Some(jar) = &self.inner.settings.cookies {
            h = Box::new(Cookies {
                inner: h,
                jar: jar.clone(),
                url: req.url.clone(),
            });
        }
        self.attempt(ex, req, Some(h));
    }

    /// The exchange of a new request, with its timeout armed and its cancel token attached.
    /// `done` is the callback of a whole response, a placeholder for one delivered as it
    /// arrives. A token already cancelled fails a whole response at once (a handler learns it
    /// from the dial).
    fn exchange(&self, req: &ClientRequest, done: Callback) -> Arc<Exchange> {
        let ex = Arc::new(Exchange {
            done: Mutex::new(Some(done)),
            site: OnceLock::new(),
            cross_site: AtomicBool::new(false),
            conn: Mutex::new(None),
            gave_up: AtomicU8::new(0),
            hops: AtomicU32::new(0),
        });
        if let Some(t) = &req.cancel {
            if !t.attach(&ex) {
                ex.give_up(GaveUp::Cancelled);
                return ex;
            }
        }
        if let Some(d) = req.timeout.or(self.inner.settings.timeout) {
            let weak = Arc::downgrade(&ex);
            crate::timer::after(d, move || {
                if let Some(ex) = weak.upgrade() {
                    ex.give_up(GaveUp::Timeout);
                }
            });
        }
        ex
    }

    /// Sends `req` (the first one, or a redirect's) as part of `ex`; to `handler` as it
    /// arrives when there is one, else whole to `ex`'s callback.
    fn attempt(
        &self,
        ex: Arc<Exchange>,
        req: ClientRequest,
        handler: Option<Box<dyn ResponseHandler>>,
    ) {
        if let Some(e) = ex.gave_up() {
            // Cancelled before it was sent (a whole response's callback was told already).
            if let Some(mut h) = handler {
                h.on_error(e);
            }
            return;
        }
        let pu = match parse_url(&req.url) {
            Ok(p) => p,
            Err(e) => {
                return match handler {
                    Some(mut h) => {
                        ex.settle();
                        h.on_error(e);
                    }
                    None => ex.finish(Err(e)),
                };
            }
        };
        let streamed = req.streamed;
        let opts = &self.inner.settings.opts;
        let header_timeout = req.response_header_timeout.or(opts.response_header_timeout);
        let idle_timeout = req.response_idle_timeout.or(opts.response_idle_timeout);
        let proxy = self
            .inner
            .settings
            .proxy
            .select(pu.key.tls, &pu.key.host, pu.key.port)
            .cloned();
        // HTTP proxies take `http://` requests in absolute form; SOCKS proxies tunnel them.
        let absolute = proxy.as_ref().filter(|p| !pu.key.tls && p.is_http());
        let mut bytes = Vec::with_capacity(160 + req.body.len());
        let scheme_host = match absolute {
            Some(_) => format!("http://{}", pu.host_header),
            None => String::new(),
        };
        // The request's own `Host`, when it has one (A11), else the URL's.
        let host = req
            .headers
            .get("host")
            .map(|h| h.trim())
            .filter(|h| !h.is_empty())
            .map_or_else(|| pu.host_header.clone(), |h| h.replace(['\r', '\n'], ""));
        bytes.extend_from_slice(
            format!(
                "{} {scheme_host}{} HTTP/1.1\r\nHost: {host}\r\n",
                req.method.as_str(),
                pu.target,
            )
            .as_bytes(),
        );
        if let Some(auth) = absolute.and_then(|p| p.authorization.as_deref()) {
            bytes.extend_from_slice(format!("Proxy-Authorization: {auth}\r\n").as_bytes());
        }
        let jar = self.inner.settings.cookies.as_ref();
        let mut cookie = String::new();
        for (n, v) in req.headers.iter() {
            if jar.is_some() && n.eq_ignore_ascii_case("cookie") {
                // One `Cookie` field: the request's, then the jar's.
                if !cookie.is_empty() {
                    cookie.push_str("; ");
                }
                cookie.push_str(v);
            } else if !n.eq_ignore_ascii_case("host")
                && !n.eq_ignore_ascii_case("content-length")
                && !(streamed.is_some() && n.eq_ignore_ascii_case("transfer-encoding"))
                && !(v.is_empty() && n.eq_ignore_ascii_case("user-agent"))
            {
                bytes.extend_from_slice(
                    format!("{n}: {}\r\n", v.replace(['\r', '\n'], "")).as_bytes(),
                );
            }
        }
        let origin = jar.and_then(|_| crate::cookie::origin(&req.url));
        if let (Some(jar), Some(o)) = (jar, &origin) {
            let site = jar.site(&o.host);
            if *ex.site.get_or_init(|| site.clone()) != site {
                ex.cross_site.store(true, Ordering::Relaxed);
            }
            let cross = ex.cross_site.load(Ordering::Relaxed);
            if let Some(h) =
                jar.header_for(o, req.method.as_str(), cross, crate::cookie::now_secs())
            {
                if !cookie.is_empty() {
                    cookie.push_str("; ");
                }
                cookie.push_str(&h);
            }
        }
        if !cookie.is_empty() {
            bytes.extend_from_slice(
                format!("Cookie: {}\r\n", cookie.replace(['\r', '\n'], "")).as_bytes(),
            );
        }
        if req.headers.get("user-agent").is_none() {
            bytes.extend_from_slice(b"User-Agent: akio-http\r\n");
        }
        match streamed {
            Some(StreamedBody::Length(n)) => {
                bytes.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
            }
            Some(StreamedBody::Chunked) => {
                bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
            None => {
                if !req.body.is_empty()
                    || matches!(req.method, Method::Post | Method::Put | Method::Patch)
                {
                    bytes.extend_from_slice(
                        format!("Content-Length: {}\r\n", req.body.len()).as_bytes(),
                    );
                }
            }
        }
        bytes.extend_from_slice(b"\r\n");
        if streamed.is_none() {
            bytes.extend_from_slice(&req.body);
        }
        let mut key = pu.key;
        key.proxy = proxy.as_ref().map(|p| (p.host.clone(), p.port));
        let head_only = req.method == Method::Head;
        let upgrade = req.headers.has_token("connection", "upgrade");
        let retryable = streamed.is_none()
            && matches!(req.method, Method::Get | Method::Head | Method::Options);
        if let Some(h) = handler {
            return self.dispatch(Pending {
                bytes,
                head_only,
                retryable,
                key,
                proxy,
                addrs: Vec::new(),
                tunnel_host: None,
                ex,
                deliver: Deliver::Stream(h),
                streamed,
                header_timeout,
                idle_timeout,
                upgrade,
            });
        }
        // The request is kept only when a redirect may need it again.
        let policy = self.inner.settings.redirects;
        let (url, saved) = if policy.max > 0 {
            (req.url.clone(), Some(req))
        } else {
            (req.url, None)
        };
        let (me, ex2) = (self.clone(), ex.clone());
        let jar = self.inner.settings.cookies.clone();
        let cb: Callback = Box::new(move |r| match r {
            Ok(mut resp) => {
                if let Some(jar) = &jar {
                    if let Some(o) = crate::cookie::origin(&url) {
                        let now = crate::cookie::now_secs();
                        for v in resp.headers.get_all("set-cookie") {
                            jar.store_from(&o, v, now);
                        }
                    }
                }
                if let Some(req) = saved {
                    let hops = ex2.hops.load(Ordering::Relaxed);
                    match redirect(policy, hops, &req, &resp) {
                        Ok(Some(next)) => {
                            ex2.hops.store(hops + 1, Ordering::Relaxed);
                            if ex2.gave_up().is_none() {
                                me.attempt(ex2, next, None);
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
            tunnel_host: None,
            ex,
            deliver: Deliver::Whole(cb),
            streamed: None,
            header_timeout,
            idle_timeout,
            upgrade,
        });
    }

    /// Sends `req` and returns a handle to wait on or await.
    pub fn send(&self, req: ClientRequest) -> ResponseFuture {
        let shared = FutureShared::new();
        let s = shared.clone();
        self.request(req, move |r| s.complete(r));
        ResponseFuture { shared }
    }

    fn pool(&self) -> std::sync::MutexGuard<'_, Pool> {
        self.inner.idle.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reuses an idle keep-alive connection when there is one, else dials.
    fn dispatch(&self, p: Pending) {
        let mut expired = Vec::new();
        let idle = {
            let mut pool = self.pool();
            let cutoff = self
                .inner
                .settings
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
                // Straight to the connection's loop, not through the logical pool: a pooled
                // handler waiting on this request must not need a pool thread for it to start
                // (rules §1). If the connection closes before the request starts there, start
                // over on a new one.
                let (me, again) = (self.clone(), self.clone());
                let mut p = OrElse::new(p, move |p| again.dial(p));
                let _ = conn.run_on_loop(move |h: &mut ClientConn, c| {
                    if let Some(p) = p.take() {
                        h.begin(c, p, me, true);
                    }
                });
            }
            Some(_) => self.dispatch(p), // closed meanwhile: try the next idle one
            None => self.dial(p),
        }
    }

    /// Puts a connection whose response is complete back into the pool, unless the pool is
    /// full; whether it was kept (the caller closes it otherwise).
    fn put_idle(&self, key: &Key, c: &Conn<ClientConn>) -> bool {
        let opts = &self.inner.settings.opts;
        let arm = {
            let mut pool = self.pool();
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
        if let (true, Some(d)) = (arm, opts.idle_timeout) {
            Client::arm_sweep(Arc::downgrade(&self.inner), d);
        }
        true
    }

    /// Schedules a sweep of expired idle connections after `delay`. The sweep holds the client
    /// weakly and re-arms itself while connections are idle, so an unused client still lets its
    /// idle connections go. At most one sweep per client is pending.
    fn arm_sweep(inner: Weak<Inner>, delay: Duration) {
        crate::timer::after(delay, move || {
            let Some(inner) = inner.upgrade() else { return };
            let Some(d) = inner.settings.opts.idle_timeout else {
                return;
            };
            let now = Instant::now();
            let mut expired = Vec::new();
            let next = {
                let mut pool = inner.idle.lock().unwrap_or_else(|e| e.into_inner());
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
                let due = (t + d).saturating_duration_since(now);
                Client::arm_sweep(Arc::downgrade(&inner), due.max(Duration::from_millis(100)));
            }
        });
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
        if let Some(e) = p.ex.gave_up() {
            // A whole response's callback was told already; a handler learns it here.
            return p.deliver.fail(e);
        }
        if let Some(path) = &self.inner.settings.unix {
            return self.dial_unix(p, path);
        }
        let local = p.proxy.as_ref().is_some_and(|s| s.resolves_locally())
            && p.tunnel_host.is_none()
            && p.key.host.parse::<std::net::IpAddr>().is_err();
        if local {
            // A SOCKS proxy that takes addresses only: resolve the target first.
            let socks4 = p.proxy.as_ref().is_some_and(|s| s.is_socks4());
            let (host, port) = (p.key.host.clone(), p.key.port);
            let me = self.clone();
            return akio::dns::resolve(&host, port, move |r| {
                let r = r.and_then(|a| akio_ws::proxy::pick_target(a, socks4));
                match r {
                    Ok(a) => {
                        p.tunnel_host = Some(a.ip().to_string());
                        me.dial(p);
                    }
                    Err(e) => {
                        let e = p.ex.gave_up().unwrap_or(ClientError::Io(e));
                        p.deliver.fail(e);
                    }
                }
            });
        }
        if p.addrs.is_empty() {
            // Resolve the proxy (when there is one) or the target, off this thread.
            let (host, port) = match &p.proxy {
                Some(s) => (s.host.clone(), s.port),
                None => (p.key.host.clone(), p.key.port),
            };
            let me = self.clone();
            return akio::dns::resolve(&host, port, move |r| match r {
                Ok(a) => {
                    p.addrs = a;
                    me.dial(p);
                }
                Err(e) => {
                    let e = p.ex.gave_up().unwrap_or(ClientError::Io(e));
                    p.deliver.fail(e);
                }
            });
        }
        let key = p.key.clone();
        let addrs = p.addrs.clone();
        let tunnel = p.proxy.clone().filter(|s| key.tls || !s.is_http());
        let tunnel_host = p.tunnel_host.clone().unwrap_or_else(|| key.host.clone());
        let proxy_tls = p.proxy.as_ref().filter(|s| s.tls).map(|s| s.host.clone());
        let slot = Arc::new(Mutex::new(Some(p)));
        let refusal = tunnel.as_ref().map(|_| Refusal::default());
        let acceptor = DialAcceptor {
            pending: slot.clone(),
            client: self.clone(),
            refusal: refusal.clone(),
        };
        let fail = move |e: io::Error| {
            let taken = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(p) = taken {
                let e = p.ex.gave_up().unwrap_or(ClientError::Io(e));
                p.deliver.fail(e);
            }
        };
        let he = self.inner.settings.opts.happy_eyeballs;
        let engine = &self.inner.engine;
        // TLS to the proxy itself (`https://` proxies), with the client's TLS configuration.
        let proxy_cfg = match proxy_tls {
            Some(name) => match self.tls() {
                Ok(c) => Some((c, name)),
                Err(e) => return fail(e),
            },
            None => None,
        };
        if key.tls {
            let a = match self.tls().and_then(|cfg| {
                let name = self.inner.settings.tls_server_name.as_deref();
                Tls::client(cfg, name.unwrap_or(&key.host), acceptor)
            }) {
                Ok(a) => a,
                Err(e) => return fail(e),
            };
            match (tunnel, refusal) {
                (Some(proxy), Some(r)) => {
                    let c = Connect::new(&tunnel_host, key.port, &proxy, r, a);
                    match over_proxy_tls(c, &proxy_cfg) {
                        Ok(c) => he.dial(engine, addrs, c, fail),
                        Err(e) => fail(e),
                    }
                }
                _ => he.dial(engine, addrs, a, fail),
            }
        } else if let (Some(proxy), Some(r)) = (tunnel, refusal) {
            let c = Connect::new(&tunnel_host, key.port, &proxy, r, acceptor);
            match over_proxy_tls(c, &proxy_cfg) {
                Ok(c) => he.dial(engine, addrs, c, fail),
                Err(e) => fail(e),
            }
        } else if let Some((cfg, name)) = proxy_cfg {
            // `http://` in absolute form to an `https://` proxy: TLS to the proxy only.
            match Tls::client(cfg, &name, acceptor) {
                Ok(a) => he.dial(engine, addrs, a, fail),
                Err(e) => fail(e),
            }
        } else {
            he.dial(engine, addrs, acceptor, fail);
        }
    }
}

impl Client {
    /// [`Client::dial`] to the Unix-domain socket `path` ([`Client::with_unix_socket`]).
    fn dial_unix(&self, p: Pending, path: &std::path::Path) {
        let tls = p.key.tls.then(|| p.key.host.clone());
        let slot = Arc::new(Mutex::new(Some(p)));
        let acceptor = DialAcceptor {
            pending: slot.clone(),
            client: self.clone(),
            refusal: None,
        };
        let fail = move |e: io::Error| {
            let taken = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(p) = taken {
                let e = p.ex.gave_up().unwrap_or(ClientError::Io(e));
                p.deliver.fail(e);
            }
        };
        let engine = &self.inner.engine;
        match tls {
            Some(host) => match self.tls().and_then(|cfg| {
                let name = self.inner.settings.tls_server_name.as_deref();
                Tls::client(cfg, name.unwrap_or(&host), acceptor)
            }) {
                Ok(a) => engine.dial_unix(path, a, fail),
                Err(e) => fail(e),
            },
            None => engine.dial_unix(path, acceptor, fail),
        }
    }
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
        let was_idle = self.client.pool().remove(c.id());
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
    /// Switched protocols (`101`): the connection's bytes go to the handler it was handed to.
    Tunnel(Box<(RawConn, Box<dyn RawHandler>)>),
}

struct Active {
    deliver: Deliver,
    head_only: bool,
    retry: Option<Pending>,
    /// The response being collected whole.
    resp: Option<ClientResponse>,
    version: Version,
    /// The response said `Connection: close`.
    conn_close: bool,
    /// The request's body written as it is produced.
    req_body: Option<Arc<ReqBody>>,
    /// The reads of a response delivered as it arrives.
    resp_body: Option<Arc<RespBody>>,
    /// The request asks to switch protocols.
    upgrade: bool,
}

/// The per-connection client handler.
pub struct ClientConn {
    state: RState,
    buf: Vec<u8>,
    /// Decoded chunks of a body delivered as it arrives, reused.
    scratch: Vec<u8>,
    active: Option<Active>,
    client: Option<Client>,
    key: Option<Key>,
    received_any: bool,
    /// Progress on the response head being received.
    head: http1::Resume,
    /// Head bytes of interim (1xx) responses already received for the request in flight.
    head_seen: usize,
    /// The exchange of the request in flight (its timeout closes this connection).
    ex: Option<Arc<Exchange>>,
    /// Where the proxy tunnel (if any) records a refusal.
    refusal: Option<Refusal>,
    /// The connection is marked a relay end (a streamed request body is being written).
    relayed: bool,
    /// The response header and idle deadline, once a request on this connection had one.
    timer: Option<Arc<ConnTimer>>,
    /// The response idle timeout of the request in flight.
    idle_timeout: Option<Duration>,
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
            scratch: Vec::new(),
            active: None,
            client: None,
            key: None,
            received_any: false,
            head: http1::Resume::default(),
            head_seen: 0,
            ex: None,
            refusal: None,
            relayed: false,
            timer: None,
            idle_timeout: None,
        }
    }

    fn opts(&self) -> Option<&ClientOptions> {
        self.client.as_ref().map(|c| &c.inner.settings.opts)
    }

    /// Whether the response in flight goes to a [`ResponseHandler`] as it arrives.
    fn streaming(&self) -> bool {
        matches!(
            self.active,
            Some(Active {
                deliver: Deliver::Stream(_),
                ..
            })
        )
    }

    /// Hands a piece of the body to the handler, or appends it to the response collected whole.
    fn body_data(active: &mut Option<Active>, data: &[u8]) {
        match active {
            Some(Active {
                deliver: Deliver::Stream(h),
                ..
            }) => h.on_data(data),
            Some(Active { resp: Some(r), .. }) => r.body.extend_from_slice(data),
            _ => {}
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
            tunnel_host,
            ex,
            deliver,
            streamed,
            header_timeout,
            idle_timeout,
            upgrade,
        } = p;
        {
            let mut slot = ex.conn.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(e) = ex.gave_up() {
                // Timed out or cancelled while this connection was being set up: a whole
                // response's callback was told already, a handler learns it here.
                drop(slot);
                c.close();
                return deliver.fail(e);
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
            tunnel_host,
            ex: ex.clone(),
            deliver: Deliver::Whole(Box::new(|_| {})),
            streamed: None,
            header_timeout,
            idle_timeout,
            upgrade,
        });
        self.ex = Some(ex);
        self.state = RState::Head;
        self.buf.clear();
        self.head = http1::Resume::default();
        self.head_seen = 0;
        self.received_any = false;
        self.client = Some(client);
        self.key = Some(key);
        self.idle_timeout = idle_timeout;
        if self.timer.is_none() {
            if let Some(t) = header_timeout.into_iter().chain(idle_timeout).min() {
                self.timer = Some(Arc::new(ConnTimer {
                    watch: Watch::register(c, t),
                    phase: AtomicU8::new(PHASE_NONE),
                }));
            }
        }
        let header = header_timeout.and_then(|d| Some((self.timer.clone()?, d)));
        let req_body = streamed.map(|framing| {
            Arc::new(ReqBody {
                conn: c.inner().clone(),
                st: Mutex::new(ReqBodyState {
                    framing,
                    written: 0,
                    finished: false,
                    aborted: false,
                    head_in: false,
                }),
                header: header.clone(),
            })
        });
        // The body's producer paces this connection's queue itself (`RequestBody::on_drain`):
        // the response must still be read meanwhile (an early 413, say).
        if self.relayed != req_body.is_some() {
            self.relayed = req_body.is_some();
            c.inner().set_relayed(self.relayed);
        }
        self.active = Some(Active {
            deliver,
            head_only,
            retry,
            resp: None,
            version: Version::Http11,
            conn_close: false,
            req_body: req_body.clone(),
            resp_body: None,
            upgrade,
        });
        if c.send_owned(bytes).is_err() {
            return self.fail(c, ClientError::Closed);
        }
        // A body given whole is written with the head: the wait for the response's head starts
        // now. A streamed one starts it from `RequestBody::finish`.
        if let (None, Some((t, d))) = (&req_body, &header) {
            t.arm(PHASE_HEAD, *d);
        }
        if let Some(shared) = req_body {
            let body = RequestBody {
                shared,
                done: false,
            };
            if let Some(Active {
                deliver: Deliver::Stream(h),
                ..
            }) = &mut self.active
            {
                h.on_request_body(body);
            }
        }
    }

    /// The request in flight is over: its body can no longer be written, its reads are no
    /// longer held, a later timeout does nothing. Whether the body was finished.
    fn settle(&self, a: &Active) -> bool {
        if let Some(r) = &a.resp_body {
            r.settle();
        }
        // After the response's reads are settled: a resume racing with this cannot re-arm it.
        if let Some(t) = &self.timer {
            t.disarm();
        }
        if matches!(a.deliver, Deliver::Stream(_)) {
            if let Some(ex) = &self.ex {
                ex.settle();
            }
        }
        a.req_body.as_ref().is_none_or(|b| b.settle())
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
        let gave_up = self.ex.as_ref().and_then(|x| x.gave_up());
        if let Some(a) = self.active.take() {
            // A reused connection the server had already closed: one retry on a fresh one.
            if let (Some(mut p), Some(client), false, false) = (
                a.retry,
                self.client.clone(),
                self.received_any,
                gave_up.is_some(),
            ) {
                if matches!(e, ClientError::Closed | ClientError::Io(_)) {
                    p.deliver = a.deliver;
                    client.dial(p);
                    c.close();
                    return;
                }
            }
            let a = Active { retry: None, ..a };
            self.settle(&a);
            // The timeout or a cancel closed the connection: a handler learns why (a whole
            // response's callback was told already).
            let e = gave_up.unwrap_or(e);
            c.close();
            return a.deliver.fail(e);
        }
        c.close();
    }

    /// Finishes the response in flight.
    fn complete(&mut self, c: &Conn<Self>, keep_alive: bool, trailers: Headers) {
        self.state = RState::Idle;
        let Some(a) = self.active.take() else { return };
        // An unfinished request body: the connection is not reusable (the server answered
        // early, a 413 say).
        let body_done = self.settle(&a);
        let shutting_down = self
            .client
            .as_ref()
            .is_some_and(|cl| cl.inner.shutting_down.load(Ordering::Relaxed));
        let reusable = keep_alive
            && body_done
            && !shutting_down
            && a.version == Version::Http11
            && !a.conn_close;
        let kept = reusable
            && match (&self.client, &self.key) {
                (Some(client), Some(key)) => client.put_idle(key, c),
                _ => false,
            };
        if !kept {
            c.close();
        }
        match a.deliver {
            Deliver::Whole(cb) => {
                let mut resp = a.resp.expect("response head parsed");
                if !trailers.is_empty() {
                    resp.trailers = trailers;
                }
                cb(Ok(resp));
            }
            Deliver::Stream(mut h) => h.on_end(&trailers),
        }
    }

    /// A `101 Switching Protocols` came: the request is over, and its connection is handed
    /// over to the handler's [`RawHandler`] (ADR-113), or closed. A `101` to a request that did
    /// not ask to upgrade fails it.
    fn switched(&mut self, c: &Conn<Self>, head: ResponseHead) {
        if !self.active.as_ref().is_some_and(|a| a.upgrade) {
            return self.fail(
                c,
                ClientError::Protocol("101 to a request that asked for no upgrade"),
            );
        }
        self.state = RState::Idle;
        let Some(a) = self.active.take() else { return };
        // Its timeouts and cancel no longer apply; the connection never goes back to the pool.
        self.settle(&a);
        if let Some(t) = &self.timer {
            t.watch.release();
        }
        self.timer = None;
        self.ex = None;
        match a.deliver {
            Deliver::Stream(mut h) => {
                let raw = RawConn(c.inner().clone());
                match h.on_upgrade(&head, &raw) {
                    Some(mut tunnel) => {
                        tunnel.on_open(&raw);
                        let rest = std::mem::take(&mut self.buf);
                        if !rest.is_empty() && c.is_open() {
                            tunnel.on_data(&raw, &rest);
                        }
                        self.state = RState::Tunnel(Box::new((raw, tunnel)));
                    }
                    None => {
                        c.close();
                        let shared = Arc::new(RespBody {
                            conn: c.inner().clone(),
                            live: Mutex::new(false),
                            idle: None,
                        });
                        h.on_head(head, ResponseBody { shared });
                        h.on_end(&Headers::new());
                    }
                }
            }
            Deliver::Whole(cb) => {
                c.close();
                cb(Ok(ClientResponse {
                    status: head.status,
                    reason: head.reason,
                    headers: head.headers,
                    body: Vec::new(),
                    trailers: Headers::new(),
                    pushed: Vec::new(),
                    url: String::new(),
                }));
            }
        }
    }

    /// Parses what is buffered. Returns once more bytes are needed.
    fn advance(&mut self, c: &Conn<Self>) {
        loop {
            match &mut self.state {
                RState::Tunnel(_) => return,
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
                    if status == 101 {
                        let head = ResponseHead {
                            status,
                            reason,
                            headers,
                            version,
                        };
                        return self.switched(c, head);
                    }
                    let head_only = self.active.as_ref().is_some_and(|a| a.head_only);
                    let no_body = head_only || status == 204 || status == 304;
                    let te_chunked = headers.has_token("transfer-encoding", "chunked");
                    let cl = headers.get("content-length").map(str::parse::<usize>);
                    // A handler takes the body as it arrives and decides about its size.
                    let streaming = self.streaming();
                    let max_body = match self.opts() {
                        Some(o) if !streaming => o.max_body_bytes,
                        _ => usize::MAX,
                    };
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
                    let conn_close = headers.has_token("connection", "close");
                    // The head is in: the header timeout ends, the idle one starts with the body.
                    let idle = self
                        .idle_timeout
                        .filter(|_| next.is_some())
                        .and_then(|d| Some((self.timer.clone()?, d)));
                    if let Some(t) = &self.timer {
                        let req_body = self.active.as_ref().and_then(|a| a.req_body.clone());
                        // Under the body's lock: a `finish` racing with this arms nothing.
                        let st = req_body.as_ref().map(|b| lock_or(&b.st));
                        match &idle {
                            Some((_, d)) => t.arm(PHASE_IDLE, *d),
                            None => t.disarm(),
                        }
                        if let Some(mut st) = st {
                            st.head_in = true;
                        }
                    }
                    if let Some(a) = &mut self.active {
                        a.version = version;
                        a.conn_close = conn_close;
                        match &mut a.deliver {
                            Deliver::Whole(_) => {
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
                                    url: String::new(),
                                });
                            }
                            Deliver::Stream(h) => {
                                let shared = Arc::new(RespBody {
                                    conn: c.inner().clone(),
                                    live: Mutex::new(true),
                                    idle,
                                });
                                a.resp_body = Some(shared.clone());
                                let head = ResponseHead {
                                    status,
                                    reason,
                                    headers,
                                    version,
                                };
                                h.on_head(head, ResponseBody { shared });
                                if !c.is_open() {
                                    return; // cancelled: `on_close` tells the handler
                                }
                            }
                        }
                    }
                    match next {
                        None => self.complete(c, true, Headers::new()),
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
                    Self::body_data(&mut self.active, &self.buf[..n]);
                    self.buf.drain(..n);
                    if !c.is_open() {
                        return;
                    }
                    if done {
                        self.complete(c, true, Headers::new());
                    }
                }
                RState::Chunked(dec) => {
                    if self.buf.is_empty() {
                        return;
                    }
                    let max_body = match &self.active {
                        Some(Active { resp: Some(r), .. }) => self
                            .client
                            .as_ref()
                            .map_or(usize::MAX, |c| c.inner.settings.opts.max_body_bytes)
                            .saturating_sub(r.body.len()),
                        _ => usize::MAX,
                    };
                    let mut out = std::mem::take(&mut self.scratch);
                    out.clear();
                    let r = dec.feed(&self.buf, &mut out, max_body);
                    match r {
                        Ok(n) => {
                            self.buf.drain(..n);
                            let done = dec.is_done();
                            let trailers = if done { dec.trailers() } else { Headers::new() };
                            if !out.is_empty() {
                                Self::body_data(&mut self.active, &out);
                            }
                            self.scratch = out;
                            if !c.is_open() {
                                return;
                            }
                            if done {
                                self.complete(c, true, trailers);
                            }
                        }
                        Err(crate::parse::ChunkError::TooLarge) => {
                            return self.fail(c, ClientError::TooLarge("response body too large"));
                        }
                        Err(_) => return self.fail(c, ClientError::Protocol("bad chunked body")),
                    }
                }
                RState::UntilClose => {
                    let max_body = match &self.active {
                        Some(Active { resp: Some(r), .. }) => self
                            .client
                            .as_ref()
                            .map_or(usize::MAX, |c| c.inner.settings.opts.max_body_bytes)
                            .saturating_sub(r.body.len()),
                        _ => usize::MAX,
                    };
                    let over = self.buf.len() > max_body;
                    if !over {
                        Self::body_data(&mut self.active, &self.buf);
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

/// Fuzzing: feeds `pieces` as the responses to requests on one connection (re-armed after each
/// complete response, as a keep-alive client would before its next request).
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn fuzz_responses(pieces: &[&[u8]], head_only: bool) {
    let c: Conn<ClientConn> = akio_core::fuzzing::conn();
    let mut h = ClientConn::new();
    let arm = |h: &mut ClientConn| {
        h.state = RState::Head;
        h.active = Some(Active {
            deliver: Deliver::Whole(Box::new(|_| {})),
            head_only,
            retry: None,
            resp: None,
            version: Version::Http11,
            conn_close: false,
            req_body: None,
            resp_body: None,
            upgrade: false,
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
        if let RState::Tunnel(t) = &mut self.state {
            let (raw, h) = &mut **t;
            return h.on_data(raw, data);
        }
        self.received_any = true;
        self.buf.extend_from_slice(data);
        self.advance(c);
        // A read of the body: the idle timeout starts over, unless the handler holds the reads
        // (the time held does not count; resuming re-arms it).
        if let (Some(t), Some(d)) = (&self.timer, self.idle_timeout) {
            if matches!(
                self.state,
                RState::Body { .. } | RState::Chunked(_) | RState::UntilClose
            ) && !c.inner().read_held()
            {
                t.arm(PHASE_IDLE, d);
            }
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<akio::Error>) {
        if let Some(t) = &self.timer {
            t.watch.release();
        }
        match &mut self.state {
            RState::Tunnel(t) => t.1.on_close(),
            RState::UntilClose => self.complete(c, false, Headers::new()),
            RState::Idle => {
                // Closed while idle (by the server, or expired): leave the pool.
                if let Some(cl) = &self.client {
                    cl.pool().remove(c.id());
                }
            }
            _ => self.fail(c, ClientError::Closed),
        }
    }
}

impl Drop for ClientConn {
    fn drop(&mut self) {
        if let Some(t) = &self.timer {
            t.watch.release();
        }
    }
}

impl OnDeadline for ClientConn {
    fn on_deadline(&mut self, c: &Conn<Self>) {
        let Some(t) = &self.timer else { return };
        // The phase first: an expiry seen with a phase set is that phase's (see `ConnTimer`).
        let phase = t.phase.load(Ordering::Acquire);
        if phase == PHASE_NONE || !t.watch.fired() {
            return; // disarmed, or re-armed since it fired
        }
        match (&self.state, phase) {
            (RState::Head, PHASE_HEAD) => self.fail(c, ClientError::HeaderTimeout),
            (RState::Body { .. } | RState::Chunked(_) | RState::UntilClose, PHASE_IDLE)
                if !c.inner().read_held() =>
            {
                self.fail(c, ClientError::IdleTimeout);
            }
            _ => {}
        }
    }
}

/// Work handed to a connection's loop ([`Conn::run_on_loop`]) with what to do if it never
/// runs: the loop drops a completion whose connection closed first, and then `fallback` gets
/// the item back (on whichever thread drops it), so whoever waits on it is answered instead of
/// waiting for good.
pub(crate) struct OrElse<T, F: FnOnce(T)> {
    item: Option<T>,
    fallback: Option<F>,
}

impl<T, F: FnOnce(T)> OrElse<T, F> {
    pub(crate) fn new(item: T, fallback: F) -> Self {
        OrElse {
            item: Some(item),
            fallback: Some(fallback),
        }
    }

    /// The item, for the work that runs; the fallback is then not called.
    pub(crate) fn take(&mut self) -> Option<T> {
        self.item.take()
    }
}

impl<T, F: FnOnce(T)> Drop for OrElse<T, F> {
    fn drop(&mut self) {
        if let (Some(item), Some(f)) = (self.item.take(), self.fallback.take()) {
            f(item);
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
