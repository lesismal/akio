//! Requests, responses, headers.

use std::{net::SocketAddr, sync::Arc, time::SystemTime};

/// An HTTP request method.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// DELETE
    Delete,
    /// PATCH
    Patch,
    /// OPTIONS
    Options,
    /// CONNECT
    Connect,
    /// TRACE
    Trace,
    /// Anything else, as sent (case-sensitive).
    Other(String),
}

impl Method {
    /// Parses a method token.
    pub fn parse(s: &str) -> Method {
        match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "PATCH" => Method::Patch,
            "OPTIONS" => Method::Options,
            "CONNECT" => Method::Connect,
            "TRACE" => Method::Trace,
            other => Method::Other(other.to_owned()),
        }
    }

    /// The method as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
            Method::Options => "OPTIONS",
            Method::Connect => "CONNECT",
            Method::Trace => "TRACE",
            Method::Other(s) => s,
        }
    }
}

/// HTTP header fields: ordered, names compared case-insensitively, duplicates allowed.
///
/// All names and values live in one string, and the positions of the first two fields are
/// kept inline, so a small set of fields costs one allocation and a larger one two, however
/// many fields it holds (a parsed request head used to cost two per field).
#[derive(Clone, Default)]
pub struct Headers {
    s: Store,
}

/// What [`Headers`] holds. Dropping storage worth keeping refills this thread's empty response
/// spare (see [`Headers::spare`]), so a response a client hands its caller, who drops it, lends
/// its storage to the next response parsed on the thread (ADR-081). A private type, so the
/// `Drop` is not part of `Headers`' API.
#[derive(Clone, Default)]
struct Store {
    buf: String,
    fields: Spans,
}

impl Drop for Store {
    #[inline]
    fn drop(&mut self) {
        // The usual case on servers: the storage was already handed back (`mem::take`).
        if self.buf.capacity() != 0 {
            self.keep();
        }
    }
}

impl Store {
    /// Moves the storage into this thread's response spare if that is empty and the storage
    /// not too large (an occupied spare stays: no cascade of drops).
    fn keep(&mut self) {
        if self.buf.capacity() > SPARE_HEADERS_MAX || self.fields.heap_capacity() > SPARE_FIELDS_MAX
        {
            return;
        }
        // `try_with`: not during the thread's TLS teardown (the spare's own drop lands here).
        let _ = SPARE_RESP.try_with(|c| {
            let cur = c.take();
            if cur.s.buf.capacity() != 0 {
                c.set(cur);
                return;
            }
            let mut h = Headers {
                s: Store {
                    buf: std::mem::take(&mut self.buf),
                    fields: std::mem::take(&mut self.fields),
                },
            };
            h.s.buf.clear();
            h.s.fields.clear();
            c.set(h);
        });
    }
}

/// Per field: name at `buf[.0...1]`, value at `buf[.1...2]`.
type Span = (usize, usize, usize);

/// Fields whose positions [`Spans`] keeps inline.
const INLINE: usize = 2;

/// Field positions: up to [`INLINE`] inline (as `u16`, in the vector's niche, so `Spans` is
/// no larger than a `Vec`: `Headers` is moved around inside every request and response), then
/// in a vector.
#[derive(Clone)]
enum Spans {
    Inline(u8, [[u16; 3]; INLINE]),
    Heap(Vec<Span>),
}

impl Default for Spans {
    fn default() -> Spans {
        Spans::Inline(0, [[0; 3]; INLINE])
    }
}

/// Iterates [`Spans`].
enum SpanIter<'a> {
    Inline(std::slice::Iter<'a, [u16; 3]>),
    Heap(std::slice::Iter<'a, Span>),
}

impl Iterator for SpanIter<'_> {
    type Item = Span;

    #[inline]
    fn next(&mut self) -> Option<Span> {
        match self {
            SpanIter::Inline(i) => i
                .next()
                .map(|&[x, y, z]| (usize::from(x), usize::from(y), usize::from(z))),
            SpanIter::Heap(i) => i.next().copied(),
        }
    }
}

impl Spans {
    fn with_capacity(n: usize) -> Spans {
        if n <= INLINE {
            Spans::default()
        } else {
            Spans::Heap(Vec::with_capacity(n))
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            Spans::Inline(n, _) => usize::from(*n),
            Spans::Heap(v) => v.len(),
        }
    }

    #[inline]
    fn iter(&self) -> SpanIter<'_> {
        match self {
            Spans::Inline(n, a) => SpanIter::Inline(a[..usize::from(*n)].iter()),
            Spans::Heap(v) => SpanIter::Heap(v.iter()),
        }
    }

    fn push(&mut self, f: Span) {
        if let Spans::Inline(n, a) = self {
            let i = usize::from(*n);
            if let (true, Ok(z)) = (i < INLINE, u16::try_from(f.2)) {
                // `f.0 <= f.1 <= f.2`, so they fit too.
                a[i] = [f.0 as u16, f.1 as u16, z];
                *n += 1;
                return;
            }
            let mut v = Vec::with_capacity(4 * INLINE);
            v.extend(self.iter());
            *self = Spans::Heap(v);
        }
        if let Spans::Heap(v) = self {
            v.push(f);
        }
    }

    /// Empties the positions, keeping a vector's capacity.
    #[inline]
    fn clear(&mut self) {
        match self {
            Spans::Inline(n, _) => *n = 0,
            Spans::Heap(v) => v.clear(),
        }
    }

    /// Room for `n` positions without growing (a vector when `n` is past the inline ones).
    #[inline]
    fn reserve(&mut self, n: usize) {
        match self {
            Spans::Inline(..) if n > INLINE => *self = Spans::Heap(Vec::with_capacity(n)),
            Spans::Heap(v) => v.reserve(n),
            Spans::Inline(..) => {}
        }
    }

    /// The vector's capacity (0 inline).
    #[inline]
    fn heap_capacity(&self) -> usize {
        match self {
            Spans::Inline(..) => 0,
            Spans::Heap(v) => v.capacity(),
        }
    }

    fn retain(&mut self, mut keep: impl FnMut(Span) -> bool) {
        match self {
            Spans::Inline(n, a) => {
                let mut w = 0;
                for r in 0..usize::from(*n) {
                    let [x, y, z] = a[r];
                    if keep((usize::from(x), usize::from(y), usize::from(z))) {
                        a[w] = a[r];
                        w += 1;
                    }
                }
                *n = w as u8;
            }
            Spans::Heap(v) => v.retain(|&f| keep(f)),
        }
    }
}

/// A spare `Headers` storage larger than this (bytes of names and values) is not kept for the
/// next request or response (an occasional large head should not pin its memory to the thread).
pub(crate) const SPARE_HEADERS_MAX: usize = 4096;
/// Nor one with room for more field positions than this.
const SPARE_FIELDS_MAX: usize = 64;

thread_local! {
    /// The storage of the last request head this thread finished with, emptied, for the next
    /// request's head (HTTP/1.1, HTTP/2 and HTTP/3). Per thread for the reason the spare
    /// target is (ADR-025): it is still in cache when the next request is parsed here.
    static SPARE_REQ: std::cell::Cell<Headers> = const { std::cell::Cell::new(Headers::EMPTY) };
    /// The storage of the last response head this thread encoded, for the next response built
    /// with [`Response::with_body`] (and [`Response::text`]) on this thread.
    static SPARE_RESP: std::cell::Cell<Headers> = const { std::cell::Cell::new(Headers::EMPTY) };
    /// The buffer of the last response body this thread copied out, emptied, for the next
    /// [`Response::text`] given a `&str` here.
    static SPARE_BODY: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
}

/// A spare body buffer larger than this is not kept.
const SPARE_BODY_MAX: usize = 4096;

/// The bytes of a [`Response::text`] body: a `&str` copied into this thread's spare body
/// buffer (allocating only when there is none or it is too small), anything else through
/// `Into<String>` as before.
#[inline]
fn text_body<T: Into<String>>(v: T) -> Vec<u8> {
    match akio_buf::text::as_str(&v) {
        Some("") => Vec::new(),
        Some(s) => {
            let mut b = SPARE_BODY.with(std::cell::Cell::take);
            b.extend_from_slice(s.as_bytes());
            b
        }
        None => v.into().into_bytes(),
    }
}

/// Keeps `body`, which the transport has copied out, as this thread's spare body buffer
/// (replacing the one there), unless it is empty or larger than worth keeping.
#[inline]
pub(crate) fn recycle_body(mut body: Vec<u8>) {
    if body.capacity() != 0 && body.capacity() <= SPARE_BODY_MAX {
        body.clear();
        SPARE_BODY.with(|c| c.set(body));
    }
}

/// Which spare a [`Headers`] storage comes from and goes back to.
#[derive(Clone, Copy)]
pub(crate) enum Spare {
    /// Request heads.
    Req,
    /// Response heads.
    Resp,
}

impl Spare {
    #[inline]
    fn with<R>(self, f: impl FnOnce(&std::cell::Cell<Headers>) -> R) -> R {
        match self {
            Spare::Req => SPARE_REQ.with(f),
            Spare::Resp => SPARE_RESP.with(f),
        }
    }
}

impl Headers {
    const EMPTY: Headers = Headers {
        s: Store {
            buf: String::new(),
            fields: Spans::Inline(0, [[0; 3]; INLINE]),
        },
    };

    /// An empty set.
    pub fn new() -> Headers {
        Headers::default()
    }

    /// [`with_capacity`](Self::with_capacity) in the storage of a head this thread is done
    /// with ([`recycle`](Self::recycle)), so a head allocates only when there is none or it is
    /// too small.
    #[inline]
    pub(crate) fn spare(from: Spare, fields: usize, bytes: usize) -> Headers {
        let mut h = from.with(std::cell::Cell::take);
        h.s.buf.reserve(bytes);
        h.s.fields.reserve(fields);
        h
    }

    /// Empties `self` and keeps its storage for the next [`spare`](Self::spare) on this
    /// thread, unless it is larger than worth keeping.
    #[inline]
    pub(crate) fn recycle(mut self, to: Spare) {
        if self.s.buf.capacity() == 0
            || self.s.buf.capacity() > SPARE_HEADERS_MAX
            || self.s.fields.heap_capacity() > SPARE_FIELDS_MAX
        {
            return;
        }
        self.s.buf.clear();
        self.s.fields.clear();
        to.with(|c| c.set(self));
    }

    /// An empty set with room for `fields` fields totalling `bytes` bytes of names and values.
    pub fn with_capacity(fields: usize, bytes: usize) -> Headers {
        Headers {
            s: Store {
                buf: String::with_capacity(bytes),
                fields: Spans::with_capacity(fields),
            },
        }
    }

    #[inline]
    fn field(&self, f: &Span) -> (&str, &str) {
        (&self.s.buf[f.0..f.1], &self.s.buf[f.1..f.2])
    }

    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Every value of `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Whether a comma-separated header (such as `Connection`) lists `token`, ignoring case.
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// Adds a field after the existing ones.
    pub fn append(&mut self, name: impl AsRef<str>, value: impl AsRef<str>) {
        let a = self.s.buf.len();
        self.s.buf.push_str(name.as_ref());
        let b = self.s.buf.len();
        self.s.buf.push_str(value.as_ref());
        self.s.fields.push((a, b, self.s.buf.len()));
    }

    /// Replaces every field called `name` with one.
    pub fn set(&mut self, name: impl AsRef<str>, value: impl AsRef<str>) {
        let name = name.as_ref();
        self.remove(name);
        self.append(name, value);
    }

    /// Removes every field called `name`.
    pub fn remove(&mut self, name: &str) {
        let before = self.s.fields.len();
        let buf = &self.s.buf;
        self.s
            .fields
            .retain(|f| !buf[f.0..f.1].eq_ignore_ascii_case(name));
        if self.s.fields.len() == before {
            return;
        }
        // Reclaim the removed bytes once they are most of the buffer.
        let live: usize = self.s.fields.iter().map(|f| f.2 - f.0).sum();
        if self.s.buf.len() > 2 * live + 256 {
            let mut c = Headers::with_capacity(self.s.fields.len(), live);
            for (n, v) in self.iter() {
                c.append(n, v);
            }
            *self = c;
        }
    }

    /// All fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.s.fields.iter().map(|f| self.field(&f))
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.s.fields.len()
    }

    /// Whether there are no fields.
    pub fn is_empty(&self) -> bool {
        self.s.fields.len() == 0
    }
}

impl PartialEq for Headers {
    fn eq(&self, other: &Headers) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Headers {}

impl std::fmt::Debug for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// HTTP version of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2 (requests that arrived on an h2 stream).
    Http2,
    /// HTTP/3 (requests that arrived on a QUIC stream, see `akio-h3`).
    Http3,
}

/// A parsed request, with its body fully received.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Request {
    /// Request method.
    pub method: Method,
    /// The request target in origin form (`/a/b?x=1`), as sent but for one in absolute form
    /// (`http://a.example/a/b?x=1`), which the HTTP/1 server gives here by its path and query, its
    /// authority becoming the `Host` field (RFC 9112 §3.2.2, ADR-177); [`raw_target`] keeps it as
    /// sent. `*` for `OPTIONS *`, the authority (`a.example:443`) for a `CONNECT`.
    ///
    /// [`raw_target`]: Request::raw_target
    pub target: String,
    /// Protocol version.
    pub version: Version,
    /// Header fields.
    pub headers: Headers,
    /// Trailer fields of a chunked body.
    pub trailers: Headers,
    /// The body (decoded if it was chunked).
    pub body: Vec<u8>,
    /// The client's address: the source a trusted PROXY header named, when akio-mux's
    /// `ProxyProtocol` layer read one for the connection, else the socket's peer (ADR-118).
    pub peer: SocketAddr,
    /// The address the request came to (akit A148): the local address of the connection's
    /// socket on HTTP/1.1 and HTTP/2, the local address of the UDP socket the QUIC connection
    /// was accepted on for HTTP/3 (for a listener bound to `0.0.0.0` or `[::]`, that unspecified
    /// address with its port). Not the destination a PROXY header names (`peer` takes the
    /// header's source). An unspecified address, port 0, where there is none (a Unix-domain
    /// socket, a virtual connection, a request built with [`Request::new`]).
    pub local: SocketAddr,
    /// The `:protocol` of an extended CONNECT request (RFC 8441 / RFC 9220: `websocket` for
    /// WebSocket over HTTP/3); `None` for every other request.
    pub protocol: Option<String>,
    /// The certificate chain the client sent and the TLS handshake verified (DER, leaf first),
    /// for mutual TLS: set by the HTTP/1.1, HTTP/2 and HTTP/3 servers on a request over TLS
    /// whose client sent a certificate to a server asking for one (`akio_tls`'s
    /// `ServerConfigBuilder::client_auth_required` or `client_auth_optional`, which check it
    /// against their roots). `None` in the clear, without a certificate, and on a request that
    /// arrived as TLS 1.3 early data, before the client's certificate. Shared by the
    /// connection's requests (ADR-109).
    pub peer_certificates: Option<Arc<[Vec<u8>]>>,
    /// An HTTP/1 target in absolute form, as sent (`raw_target`).
    pub(crate) absolute: Option<Box<str>>,
}

impl Request {
    /// A request with `method` for `target` (`/a/b?x=1`): HTTP/1.1, no headers, an empty body
    /// and unspecified peer and local addresses. Handy for testing services; set the other fields as
    /// needed.
    pub fn new(method: Method, target: impl Into<String>) -> Request {
        Request {
            method,
            target: target.into(),
            version: Version::Http11,
            headers: Headers::new(),
            trailers: Headers::new(),
            body: Vec::new(),
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
            local: SocketAddr::from(([0, 0, 0, 0], 0)),
            protocol: None,
            peer_certificates: None,
            absolute: None,
        }
    }

    /// The request target as the client sent it: [`target`](Request::target), but for an HTTP/1
    /// target in absolute form (`GET http://a.example/a?b HTTP/1.1`), which `target` gives in
    /// origin form (`/a?b`) and this as sent, for logs (ADR-177).
    pub fn raw_target(&self) -> &str {
        self.absolute.as_deref().unwrap_or(&self.target)
    }

    /// The path of the target, without the query.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    /// The query string, without the `?`.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }

    /// The value of query parameter `key` (not percent-decoded).
    pub fn query_param(&self, key: &str) -> Option<&str> {
        self.query()?
            .split('&')
            .filter_map(|kv| kv.split_once('=').or(Some((kv, ""))))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }
}

/// A response to send.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header fields. `Content-Length`, `Date` and `Connection` are added when encoding unless
    /// present.
    pub headers: Headers,
    /// The body.
    pub body: Vec<u8>,
    /// A file to send after the head instead of `body` (sent with `sendfile(2)` on plain TCP).
    pub file: Option<FileBody>,
    /// The body is streamed: no `Content-Length` is added.
    pub(crate) streaming: bool,
    /// The coding a streamed body is compressed with, set by the `compress` middleware's
    /// filter when the head goes out (ADR-074).
    pub(crate) stream_coding: Option<crate::coding::StreamCoding>,
    /// What [`keep_until_sent`](Response::keep_until_sent) keeps (ADR-112): one pointer, so
    /// that a response without it costs a word.
    pub(crate) kept: Option<Arc<Kept>>,
    /// What sees a streamed body as it is sent ([`tap_body`](Response::tap_body), ADR-116).
    pub(crate) tap: Option<crate::tap::TapSlot>,
    /// Trailer fields sent after the body (HTTP/2; ignored on HTTP/1).
    pub trailers: Option<Headers>,
}

/// A value [`Response::keep_until_sent`] keeps alive. It is never looked at, only dropped, so
/// it cannot be seen half-changed after a panic: asserting unwind safety keeps `Response`
/// `UnwindSafe`.
pub(crate) struct Kept(
    #[allow(dead_code, reason = "kept for its drop")]
    std::panic::AssertUnwindSafe<Box<dyn std::any::Any + Send + Sync>>,
);

impl std::fmt::Debug for Kept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kept")
    }
}

/// A byte range of an open file used as a response body.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FileBody {
    /// The open file.
    pub file: Arc<std::fs::File>,
    /// First byte to send.
    pub offset: u64,
    /// Number of bytes to send.
    pub len: u64,
}

impl FileBody {
    /// `len` bytes of `file` starting at `offset`.
    pub fn new(file: Arc<std::fs::File>, offset: u64, len: u64) -> FileBody {
        FileBody { file, offset, len }
    }
}

impl Response {
    /// An empty response with `status`.
    pub fn new(status: u16) -> Response {
        Response {
            status,
            headers: Headers::new(),
            body: Vec::new(),
            file: None,
            streaming: false,
            stream_coding: None,
            kept: None,
            tap: None,
            trailers: None,
        }
    }

    /// Whether this is the head of a streamed response ([`Context::stream_response`],
    /// [`Detached::stream_response`]), as a response filter sees it: its body is written later,
    /// in pieces, and [`body`](Response::body) is empty.
    ///
    /// [`Context::stream_response`]: crate::Context::stream_response
    /// [`Detached::stream_response`]: crate::Detached::stream_response
    pub fn is_streaming(&self) -> bool {
        self.streaming
    }

    /// The content coding a streamed body is compressed with (ADR-112): set by a response
    /// filter on the head of a streamed response, every write of the body then goes through
    /// the coding's encoder and is flushed, so that the client can decode what was written so
    /// far. The filter sets `Content-Encoding` (the coding's [`name`](crate::Coding::name)) and
    /// `Vary` itself, and removes `Content-Length`. A HEAD answer keeps the fields and encodes
    /// nothing. `None` sends the body as written.
    ///
    /// A response whose body is a [file](Response::file) is sent as a streamed one with the
    /// coding (ADR-124): its `Content-Length` dropped, chunked on keep-alive HTTP/1.1, the file
    /// read in 64 KiB pieces on the disk pool `files::Files` uses and each piece encoded there
    /// and written, the next read once fewer than 256 KiB are queued on the connection. A read
    /// that fails (the file shrank) cuts the body: the connection closes. Ignored on any other
    /// response (a whole body is the filter's to compress).
    pub fn set_stream_coding(&mut self, coding: Option<crate::Coding>) {
        self.stream_coding = coding.map(|c| c.0);
    }

    /// The coding [`set_stream_coding`](Response::set_stream_coding) set.
    pub fn stream_coding(&self) -> Option<crate::Coding> {
        self.stream_coding.map(crate::Coding)
    }

    /// Keeps `value` until the response is sent (ADR-112): for a streamed response, until its
    /// [`BodyStream`](crate::BodyStream) is finished or dropped; for any other, until the
    /// response is handed to the connection. A response filter that bounds the responses under
    /// way (encoders at once, say) keeps a guard here and gives its place back when the guard
    /// drops. A later call replaces (and drops) an earlier value.
    pub fn keep_until_sent(&mut self, value: impl std::any::Any + Send + Sync) {
        self.kept = Some(Arc::new(Kept(std::panic::AssertUnwindSafe(Box::new(
            value,
        )))));
    }

    /// Sets what sees the body of a streamed response as it is sent (ADR-116): set by a response
    /// filter on the head of a streamed response, `tap` gets each write of the body as it goes
    /// to the connection, after any [stream coding](Response::set_stream_coding), then how the
    /// body ended (see [`BodyTap`](crate::BodyTap)). Ignored, and dropped unused, on a response
    /// that is not streamed (whose filter sees the whole [`body`](Response::body)) and on a HEAD
    /// answer. A later call replaces an earlier tap.
    pub fn tap_body(&mut self, tap: impl crate::BodyTap) {
        self.tap = Some(crate::tap::TapSlot::new(Box::new(tap)));
    }

    /// Takes what [`keep_until_sent`](Response::keep_until_sent) keeps, for the stream.
    pub(crate) fn take_kept(&mut self) -> Option<Arc<Kept>> {
        self.kept.take()
    }

    /// A response whose body is `len` bytes of `file` from `offset`.
    pub fn from_file(status: u16, content_type: &str, file: FileBody) -> Response {
        let mut r = Response::new(status);
        r.headers.set("Content-Type", content_type);
        r.file = Some(file);
        r
    }

    /// Body length, whichever way the body is held.
    pub fn body_len(&self) -> u64 {
        self.file.as_ref().map_or(self.body.len() as u64, |f| f.len)
    }

    /// A `text/plain; charset=utf-8` response.
    pub fn text(status: u16, body: impl Into<String>) -> Response {
        // A `&str` is copied into this thread's spare body buffer instead of a new `String`;
        // the transport gives the buffer back once the body is in its output (ADR-081).
        Response::with_body(status, "text/plain; charset=utf-8", text_body(body))
    }

    /// A response with the given content type and body.
    pub fn with_body(status: u16, content_type: &str, body: Vec<u8>) -> Response {
        let mut r = Response::new(status);
        // Room for the content type and a few more fields in one buffer (growing an empty one
        // field by field reallocated it on every response): the storage of the last response
        // this thread sent, when there is one. Two field positions are kept inline; a third
        // field moves them into a vector.
        r.headers = Headers::spare(Spare::Resp, INLINE, content_type.len() + 64);
        r.headers.append("Content-Type", content_type);
        r.body = body;
        r
    }

    /// Sets a header, replacing earlier ones of that name.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl AsRef<str>) -> Response {
        self.headers.set(name, value);
        self
    }

    /// Serialises the response. `head_only` omits the body (HEAD) but keeps its length.
    /// Returns whether the response's own `Connection` field asks to close the connection
    /// (`close`), which the caller honours (akit A24); `keep_alive` adds a `Connection` field
    /// only when the response has none.
    pub(crate) fn encode(
        &self,
        version: Version,
        keep_alive: bool,
        head_only: bool,
        out: &mut Vec<u8>,
    ) -> bool {
        out.extend_from_slice(b"HTTP/1.1 ");
        push_uint(out, u64::from(self.status));
        out.push(b' ');
        out.extend_from_slice(reason(self.status).as_bytes());
        out.extend_from_slice(b"\r\n");
        let (mut has_len, mut has_date, mut has_conn) = (false, false, false);
        let mut close = false;
        for (n, v) in self.headers.iter() {
            has_len |= n.eq_ignore_ascii_case("content-length");
            has_date |= n.eq_ignore_ascii_case("date");
            if n.eq_ignore_ascii_case("connection") {
                has_conn = true;
                close |= v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"));
            }
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            // Header injection guard: a value cannot contain a line break.
            if v.contains(['\r', '\n']) {
                out.extend(v.bytes().filter(|b| *b != b'\r' && *b != b'\n'));
            } else {
                out.extend_from_slice(v.as_bytes());
            }
            out.extend_from_slice(b"\r\n");
        }
        let bodyless = self.status < 200 || self.status == 204 || self.status == 304;
        if !has_len && !bodyless && !self.streaming {
            out.extend_from_slice(b"Content-Length: ");
            push_uint(out, self.body_len());
            out.extend_from_slice(b"\r\n");
        }
        if !has_date {
            out.extend_from_slice(b"Date: ");
            with_http_date(|d| out.extend_from_slice(d.as_bytes()));
            out.extend_from_slice(b"\r\n");
        }
        if !has_conn {
            if !keep_alive {
                out.extend_from_slice(b"Connection: close\r\n");
            } else if version == Version::Http10 {
                out.extend_from_slice(b"Connection: keep-alive\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");
        if !head_only && !bodyless {
            out.extend_from_slice(&self.body);
        }
        close
    }
}

/// The standard reason phrase of a status code.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

thread_local! {
    static DATE: std::cell::RefCell<(u64, String)> = const { std::cell::RefCell::new((0, String::new())) };
}

/// The current time as an IMF-fixdate, cached for the current second.
pub fn http_date_now() -> String {
    with_http_date(str::to_owned)
}

/// Calls `f` with the current IMF-fixdate (cached per thread for the current second, so a
/// response costs no formatting and no allocation for it).
pub(crate) fn with_http_date<R>(f: impl FnOnce(&str) -> R) -> R {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    DATE.with(|c| {
        let mut c = c.borrow_mut();
        if c.0 != secs || c.1.is_empty() {
            *c = (secs, format_http_date(secs));
        }
        f(&c.1)
    })
}

/// Appends `n` in decimal.
pub(crate) fn push_uint(out: &mut Vec<u8>, mut n: u64) {
    let mut b = [0u8; 20];
    let mut i = b.len();
    loop {
        i -= 1;
        b[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&b[i..]);
}

/// Parses an HTTP-date to seconds since the Unix epoch, in any of the three formats RFC 9110
/// section 5.6.7 has recipients accept (ADR-116): the IMF-fixdate senders use
/// (`Sun, 06 Nov 1994 08:49:37 GMT`), the obsolete RFC 850 format
/// (`Sunday, 06-Nov-94 08:49:37 GMT`, a two-digit year from 69 in the 1900s and below it in the
/// 2000s, as Go reads it) and asctime's (`Sun Nov  6 08:49:37 1994`). The day name is not
/// checked against the date. `None` for anything else, or a date before 1970.
#[must_use]
pub fn parse_http_date(s: &str) -> Option<u64> {
    let s = s.trim();
    let (day, mon, year, time) = if let Some((_, rest)) = s.split_once(", ") {
        let rest = rest.strip_suffix(" GMT")?;
        if let Some((date, time)) = rest.split_once(' ').filter(|(d, _)| d.contains('-')) {
            // RFC 850: 06-Nov-94 08:49:37
            let mut p = date.split('-');
            let (d, m, y) = (p.next()?, p.next()?, p.next()?);
            if p.next().is_some() || y.len() != 2 {
                return None;
            }
            let y: i64 = digits(y)?;
            (d, m, if y >= 69 { 1900 + y } else { 2000 + y }, time)
        } else {
            // IMF-fixdate: 06 Nov 1994 08:49:37
            let mut p = rest.split(' ');
            let (d, m, y, t) = (p.next()?, p.next()?, p.next()?, p.next()?);
            if p.next().is_some() || y.len() != 4 {
                return None;
            }
            (d, m, digits(y)?, t)
        }
    } else {
        // asctime: Sun Nov  6 08:49:37 1994
        let mut p = s.split(' ').filter(|w| !w.is_empty());
        let (_, m, d, t, y) = (p.next()?, p.next()?, p.next()?, p.next()?, p.next()?);
        if p.next().is_some() || y.len() != 4 {
            return None;
        }
        (d, m, digits(y)?, t)
    };
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let m = MONTHS.iter().position(|&n| n == mon)? as i64 + 1;
    if day.is_empty() || day.len() > 2 {
        return None;
    }
    let d: i64 = digits(day)?;
    let mut hms = time.split(':');
    let (h, mi, sec) = (hms.next()?, hms.next()?, hms.next()?);
    if hms.next().is_some() || h.len() != 2 || mi.len() != 2 || sec.len() != 2 {
        return None;
    }
    let (h, mi, sec): (i64, i64, i64) = (digits(h)?, digits(mi)?, digits(sec)?);
    if !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).ok()
}

/// A run of ASCII digits (no sign), at most a few, as a number.
fn digits(s: &str) -> Option<i64> {
    if s.is_empty() || s.len() > 4 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Formats seconds since the Unix epoch as `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn format_http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three formats RFC 9110 section 5.6.7 has recipients accept (ADR-116).
    #[test]
    fn http_dates_in_three_formats() {
        let t = Some(784_111_777);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), t);
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), t);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), t);
        assert_eq!(parse_http_date(" Sun, 06 Nov 1994 08:49:37 GMT "), t);
        assert_eq!(
            parse_http_date("Thursday, 01-Jan-26 00:00:00 GMT"),
            parse_http_date("Thu, 01 Jan 2026 00:00:00 GMT")
        );
        for secs in [0u64, 951_782_400, 1_700_000_000, 4_102_444_800] {
            assert_eq!(parse_http_date(&format_http_date(secs)), Some(secs));
        }
        for bad in [
            "",
            "garbage",
            "0",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 8:49:37 GMT",
            "Sun, 06 Nov 94 08:49:37 GMT",
            "Sun, +6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1969 08:49:37 GMT",
            "Sunday, 06-Nov-1994 08:49:37 GMT",
            "Sun Nov  6 08:49:37",
            "Sun Nov  6 08:49:37 1994 GMT",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad:?}");
        }
    }

    /// A head's storage goes back to the thread and comes out empty for the next head, with
    /// its room; storage too large to keep, and an empty one, are not kept (ADR-081).
    #[test]
    fn spare_header_storage_is_reused_empty() {
        let mut h = Headers::spare(Spare::Req, 5, 100);
        for i in 0..5 {
            h.append(format!("n{i}"), "v");
        }
        let (cap, ptr) = (h.s.buf.capacity(), h.s.buf.as_ptr());
        assert!(matches!(h.s.fields, Spans::Heap(_)));
        h.recycle(Spare::Req);
        let mut h = Headers::spare(Spare::Req, 1, 10);
        assert!(h.is_empty() && h.s.buf.is_empty());
        assert_eq!((h.s.buf.capacity(), h.s.buf.as_ptr()), (cap, ptr));
        h.append("a", "1");
        assert_eq!(h.iter().collect::<Vec<_>>(), [("a", "1")]);
        h.recycle(Spare::Req);
        // The response spare is a different one.
        let r = Headers::spare(Spare::Resp, 1, 10);
        assert_ne!(r.s.buf.as_ptr(), ptr);
        r.recycle(Spare::Resp);
        // Too large: dropped, and the next head allocates afresh.
        let big = Headers::spare(Spare::Req, 1, SPARE_HEADERS_MAX + 1);
        big.recycle(Spare::Req);
        let h = Headers::spare(Spare::Req, 3, 10);
        assert_eq!(h.s.buf.capacity(), 10);
        assert!(matches!(h.s.fields, Spans::Heap(ref v) if v.capacity() >= 3));
        // A response built on this thread starts in the spare.
        let r = Response::text(200, "x");
        assert_eq!(
            r.headers.iter().collect::<Vec<_>>(),
            [("Content-Type", "text/plain; charset=utf-8")]
        );
    }

    /// Dropping a head refills this thread's empty response spare, and leaves an occupied one
    /// as it is (ADR-081).
    #[test]
    fn dropped_headers_refill_the_response_spare() {
        // Empty the spare first.
        let mut e = Headers::spare(Spare::Resp, 0, 0);
        drop(std::mem::take(&mut e.s.buf));
        drop(e);
        let mut h = Headers::with_capacity(3, 64);
        for i in 0..3 {
            h.append(format!("n{i}"), "v");
        }
        let ptr = h.s.buf.as_ptr();
        drop(h);
        let mut r = Headers::spare(Spare::Resp, 3, 10);
        assert!(r.is_empty() && r.s.buf.capacity() >= 64);
        assert_eq!(r.s.buf.as_ptr(), ptr);
        assert!(matches!(r.s.fields, Spans::Heap(ref v) if v.capacity() >= 3));
        r.append("a", "1");
        // An occupied spare is kept; the dropped storage is freed.
        let kept = Headers::with_capacity(1, 32);
        let kept_ptr = kept.s.buf.as_ptr();
        kept.recycle(Spare::Resp);
        drop(r);
        let s = Headers::spare(Spare::Resp, 1, 1);
        assert_eq!(s.s.buf.as_ptr(), kept_ptr);
        // Too large: not kept.
        drop(Headers::with_capacity(1, SPARE_HEADERS_MAX + 1));
        assert_eq!(Headers::spare(Spare::Resp, 0, 0).s.buf.capacity(), 0);
        drop(s);
    }

    /// A `&str` text body is copied into the thread's spare body buffer, which the transport
    /// gives back once the body is out; other bodies convert as before (ADR-081).
    #[test]
    fn text_bodies_use_the_spare_body_buffer() {
        let r = Response::text(200, "Hello, World!");
        assert_eq!(r.body, b"Hello, World!");
        let p = r.body.as_ptr();
        recycle_body(r.body);
        let local = String::from("x");
        let r = Response::text(200, local.as_str());
        assert_eq!(
            (r.body.as_ptr(), &r.body[..]),
            (p, &b"x"[..]),
            "the buffer was reused"
        );
        // An owned `String` is moved, not copied.
        let s = String::with_capacity(64) + "owned";
        let sp = s.as_ptr();
        let o = Response::text(200, s);
        assert_eq!((o.body.as_ptr(), &o.body[..]), (sp, &b"owned"[..]));
        assert_eq!(Response::text(200, 'c').body, b"c");
        assert!(Response::text(200, "").body.capacity() == 0);
        // Too large to keep: not kept, and a body that grew past the limit is not either.
        let spare_cap = || {
            SPARE_BODY.with(|c| {
                let v = c.take();
                let n = v.capacity();
                c.set(v);
                n
            })
        };
        assert_eq!(spare_cap(), 0, "the spare was taken");
        recycle_body(Vec::with_capacity(SPARE_BODY_MAX + 1));
        assert_eq!(spare_cap(), 0);
        recycle_body(r.body);
        assert!(spare_cap() > 0);
        let big = Response::text(200, &*"b".repeat(SPARE_BODY_MAX + 1));
        assert_eq!(spare_cap(), 0, "the big body took the spare");
        recycle_body(big.body);
        assert_eq!(spare_cap(), 0);
    }

    #[test]
    fn http_date_matches_rfc_example() {
        // RFC 7231: Sun, 06 Nov 1994 08:49:37 GMT
        assert_eq!(
            format_http_date(784_111_777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            format_http_date(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
    }

    #[test]
    fn push_uint_and_header_storage() {
        for n in [0u64, 7, 10, 200, 65535, u64::MAX] {
            let mut v = Vec::new();
            push_uint(&mut v, n);
            assert_eq!(v, n.to_string().as_bytes());
        }
        let mut h = Headers::with_capacity(2, 16);
        for i in 0..200 {
            h.set("X-Count", i.to_string()); // repeated set: removed bytes are reclaimed
        }
        h.append("Accept", "*/*");
        assert_eq!(h.get("x-count"), Some("199"));
        assert_eq!(h.len(), 2);
        assert!(h.s.buf.len() < 1024, "{}", h.s.buf.len());
        let mut g = Headers::new();
        g.append("x-count", "199");
        assert_ne!(h, g);
        g.append("Accept", "*/*");
        h.remove("Accept");
        g.remove("accept");
        assert_eq!(h.iter().collect::<Vec<_>>(), [("X-Count", "199")]);
        assert_eq!(format!("{h:?}"), r#"[("X-Count", "199")]"#);
    }

    #[test]
    fn headers_are_case_insensitive_and_ordered() {
        let mut h = Headers::new();
        h.append("Accept", "a");
        h.append("accept", "b");
        h.append("Connection", "Keep-Alive, Upgrade");
        assert_eq!(h.get("ACCEPT"), Some("a"));
        assert_eq!(h.get_all("accept").collect::<Vec<_>>(), ["a", "b"]);
        assert!(h.has_token("connection", "upgrade"));
        assert!(!h.has_token("connection", "close"));
        h.set("accept", "c");
        assert_eq!(h.get_all("Accept").collect::<Vec<_>>(), ["c"]);
    }

    #[test]
    fn headers_inline_then_heap() {
        // The first fields' positions are inline; more move them to the heap, in order, and
        // removal works the same way in both forms.
        for n in [0, 1, INLINE - 1, INLINE, INLINE + 1, 3 * INLINE] {
            for cap in [0, n] {
                let mut h = Headers::with_capacity(cap, 0);
                for i in 0..n {
                    h.append(format!("x-{i}"), i.to_string());
                }
                assert_eq!(h.len(), n);
                let want: Vec<(String, String)> =
                    (0..n).map(|i| (format!("x-{i}"), i.to_string())).collect();
                let got: Vec<(String, String)> = h
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect();
                assert_eq!(got, want);
                h.remove("x-0");
                h.remove("X-2");
                let left = (0..n).filter(|&i| i != 0 && i != 2).count();
                assert_eq!(h.len(), left);
                assert!(h.get("x-0").is_none() && h.get("x-2").is_none());
                if n > 3 {
                    assert_eq!(h.get("x-3"), Some("3"));
                }
                h.append("y", "z");
                assert_eq!(h.iter().last(), Some(("y", "z")));
                assert!(!h.is_empty());
            }
        }
        assert!(Headers::with_capacity(INLINE + 1, 0).is_empty());
        // Positions past `u16` move to the heap.
        let mut h = Headers::new();
        h.append("a", "x".repeat(70_000));
        h.append("b", "y");
        assert_eq!(h.get("b"), Some("y"));
        assert_eq!(h.get("a").map(str::len), Some(70_000));
        // No larger than before the inline positions (two `Vec`s' worth).
        assert_eq!(size_of::<Headers>(), 2 * size_of::<Vec<u8>>());
    }

    #[test]
    fn query_params() {
        let r = Request {
            method: Method::Get,
            target: "/a/b?x=1&y&z=3".into(),
            version: Version::Http11,
            headers: Headers::new(),
            trailers: Headers::new(),
            body: vec![],
            peer: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:2".parse().unwrap(),
            protocol: None,
            peer_certificates: None,
            absolute: None,
        };
        assert_eq!(r.path(), "/a/b");
        assert_eq!(r.query_param("x"), Some("1"));
        assert_eq!(r.query_param("y"), Some(""));
        assert_eq!(r.query_param("z"), Some("3"));
        assert_eq!(r.query_param("w"), None);
    }

    #[test]
    fn encode_adds_framing_and_strips_line_breaks() {
        let r = Response::text(200, "hi").header("X-A", "a\r\nInjected: 1");
        let mut out = Vec::new();
        r.encode(Version::Http11, true, false, &mut out);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.contains("X-A: aInjected: 1\r\n"));
        assert!(!s.contains("\r\nInjected"));
        assert!(s.ends_with("\r\n\r\nhi"));
        let mut out = Vec::new();
        r.encode(Version::Http11, false, true, &mut out);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.ends_with("\r\n\r\n"), "HEAD has no body");
    }
}

/// Decodes `%XX` escapes (and nothing else, so `+` stays `+`). `None` if an escape is malformed
/// or the result is not UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod percent_tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b%2Fc+d").as_deref(), Some("a b/c+d"));
        assert_eq!(percent_decode("%E2%82%AC").as_deref(), Some("€"));
        assert_eq!(percent_decode("100%"), None);
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%ff"), None, "not UTF-8");
    }
}
