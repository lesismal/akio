#![forbid(unsafe_code)]
//! HTTP/3 (RFC 9114) for `only`, on [`only_quic`] with QPACK (static table and literals).
//!
//! [`serve`] serves any [`only_http::Service`] (a [`only_http::Router`] with its
//! middleware) over QUIC: handlers get the same [`only_http::Context`] as on HTTP/1.1 and
//! HTTP/2, including `detach` and `stream_response`; request bodies arrive buffered.
//! [`H3Client`] sends requests on one QUIC connection.
//!
//! ```no_run
//! use only::{Engine, Listener};
//! use only_http::{Context, Router};
//!
//! # let (certs, key) = (vec![], only::tls::PrivateKey::from_pkcs8_der(vec![]));
//! let app = Router::new().get("/", |ctx: &mut Context| ctx.text(200, "hello over h3"));
//! let quic = only_h3::server_config(certs, key).unwrap();
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:443".parse().unwrap()).serve(only_h3::serve(quic, app)))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! 0-RTT (off by default, [`only_quic::ServerConfig::zero_rtt`]): a request that arrived in
//! 0-RTT packets carries `Early-Data: 1` (RFC 8470 section 5.1), as if an intermediary had
//! forwarded it early; it may be a replay, so answer what is not safe to repeat (anything
//! but a GET or HEAD without side effects, say) with `425 Too Early` and the client retries
//! it after the handshake. [`H3Client`] sends its requests in 0-RTT when its QUIC config
//! enables it ([`only_quic::ClientConfig::zero_rtt`]) and it resumes.
//!
//! Not implemented: server push, a QPACK dynamic table, extended CONNECT (WebSocket over
//! HTTP/3), streamed request bodies.
//!
//! Guide: [QUIC and HTTP/3](https://lesismal.github.io/only/en/protocols/quic-h3.html)
//! (中文: [QUIC 与 HTTP/3](https://lesismal.github.io/only/zh-CN/protocols/quic-h3.html)).
#![warn(clippy::unwrap_used)]

mod client;
mod frame;
pub mod qpack;
mod table;

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

use only_http::Service;
use only_http::message::{Headers, Method, Request, Response, Version};
use only_http::transport::{BodySink, ResponseSink};
use only_quic::Bytes;
use only_quic::{Connection, ConnectionError, Dir, QuicHandler, QuicServer, StreamId};

pub use client::{H3Client, H3ClientOptions, H3Error};
pub use frame::code;

use frame::Reader;
use qpack::FieldBuf;

/// Hashes stream IDs for the per-connection stream tables: SipHash (the default) showed up in
/// HTTP/3 profiles. IDs are chosen by the peer, but a table is bounded by the stream limits we
/// grant, so collisions cannot grow it; the multiply-and-fold spreads the IDs (which step by 4)
/// over every bucket.
#[derive(Default)]
pub(crate) struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(self.0 << 8 | u64::from(b));
        }
    }
    fn write_u64(&mut self, n: u64) {
        let h = (self.0 ^ n).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = h ^ (h >> 29);
    }
}

/// A table keyed by stream ID.
pub(crate) type StreamMap<V> = HashMap<StreamId, V, BuildHasherDefault<IdHasher>>;

/// Server limits.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H3Config {
    /// Largest request body (larger ones get 413).
    pub max_body_bytes: usize,
    /// Largest field section, as `SETTINGS_MAX_FIELD_SECTION_SIZE`.
    pub max_field_section_bytes: usize,
}

impl Default for H3Config {
    fn default() -> H3Config {
        H3Config {
            max_body_bytes: 8 << 20,
            max_field_section_bytes: 64 << 10,
        }
    }
}

/// A QUIC server config for a certificate chain and key, offering ALPN `h3`.
pub fn server_config(
    certs: Vec<only::tls::Certificate>,
    key: only::tls::PrivateKey,
) -> Result<only_quic::ServerConfig, only_quic::Error> {
    only_quic::server_config(certs, key, &[b"h3"])
}

/// Serves `service` over HTTP/3: the acceptor of a UDP listener (like `only_http::serve`).
pub fn serve<S: Service>(quic: only_quic::ServerConfig, service: S) -> QuicServer {
    serve_with(quic, H3Config::default(), service)
}

/// [`serve`] with limits (like `only_http::serve_with`).
pub fn serve_with<S: Service>(
    quic: only_quic::ServerConfig,
    cfg: H3Config,
    service: S,
) -> QuicServer {
    let svc = Arc::new(service);
    let cfg = Arc::new(cfg);
    QuicServer::new(quic, move |c: &Connection| ServerConn {
        svc: svc.clone(),
        cfg: cfg.clone(),
        peer: c.remote_addr(),
        peer_ctrl: None,
        uni: StreamMap::default(),
        reqs: StreamMap::default(),
        fields: FieldBuf::default(),
    })
}

/// The SETTINGS frame both sides send: no dynamic table, our field section limit.
pub(crate) fn control_stream_preamble(max_field: usize) -> Vec<u8> {
    let mut p = Vec::new();
    for (id, v) in [
        (frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (frame::SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (frame::SETTINGS_MAX_FIELD_SECTION_SIZE, max_field as u64),
    ] {
        frame::put_varint(&mut p, id);
        frame::put_varint(&mut p, v);
    }
    let mut out = Vec::new();
    frame::put_varint(&mut out, frame::STREAM_CONTROL);
    frame::put_frame(&mut out, frame::SETTINGS, &p);
    out
}

/// Checks a SETTINGS payload: well formed, no HTTP/2 identifiers, no duplicates.
pub(crate) fn check_settings(p: &[u8]) -> Result<(), u32> {
    let mut seen = Vec::new();
    let mut pos = 0;
    while pos < p.len() {
        let (id, a) = frame::get_varint(&p[pos..]).ok_or(code::FRAME_ERROR)?;
        pos += a;
        let (_, b) = frame::get_varint(&p[pos..]).ok_or(code::FRAME_ERROR)?;
        pos += b;
        if (0x2..=0x5).contains(&id) || seen.contains(&id) {
            return Err(code::SETTINGS_ERROR);
        }
        seen.push(id);
    }
    Ok(())
}

/// Frame types reserved by HTTP/2 that must not appear in HTTP/3.
pub(crate) fn h2_only(ty: u64) -> bool {
    matches!(ty, 0x2 | 0x6 | 0x8 | 0x9)
}

/// A peer's unidirectional stream.
pub(crate) enum Uni {
    Unknown(Reader),
    Control { r: Reader, settings: bool },
    Critical,
    Skip,
}

/// Feeds a peer's unidirectional stream; `Err(code)` is a connection error. Shared by both
/// sides (`server` refuses push streams, which only a server may open). `stop` asks the peer to
/// stop sending on a stream (`STOP_SENDING`).
pub(crate) fn on_uni(
    u: &mut Uni,
    peer_ctrl: &mut Option<StreamId>,
    stop: &mut dyn FnMut(StreamId, u32),
    id: StreamId,
    data: &[u8],
    fin: bool,
    server: bool,
) -> Result<(), u32> {
    if let Uni::Unknown(r) = u {
        r.push(data);
        let Some(ty) = r.varint() else {
            return Ok(());
        };
        let rest = r.rest().to_vec();
        *u = match ty {
            frame::STREAM_CONTROL => {
                if peer_ctrl.is_some() {
                    return Err(code::STREAM_CREATION_ERROR);
                }
                *peer_ctrl = Some(id);
                Uni::Control {
                    r: Reader::default(),
                    settings: false,
                }
            }
            frame::STREAM_QPACK_ENCODER | frame::STREAM_QPACK_DECODER => Uni::Critical,
            frame::STREAM_PUSH if server => return Err(code::STREAM_CREATION_ERROR),
            _ => {
                stop(id, code::STREAM_CREATION_ERROR);
                Uni::Skip
            }
        };
        return on_uni(u, peer_ctrl, stop, id, &rest, fin, server);
    }
    match u {
        Uni::Control { r, settings } => {
            r.push(data);
            loop {
                let f = r.frame(1 << 16).map_err(|_| code::EXCESSIVE_LOAD)?;
                let Some((ty, p)) = f else { break };
                if !*settings {
                    if ty != frame::SETTINGS {
                        return Err(code::MISSING_SETTINGS);
                    }
                    check_settings(&p)?;
                    *settings = true;
                    continue;
                }
                match ty {
                    frame::SETTINGS | frame::DATA | frame::HEADERS => {
                        return Err(code::FRAME_UNEXPECTED);
                    }
                    frame::PUSH_PROMISE => return Err(code::FRAME_UNEXPECTED),
                    t if h2_only(t) => return Err(code::FRAME_UNEXPECTED),
                    frame::MAX_PUSH_ID if !server => return Err(code::FRAME_UNEXPECTED),
                    _ => {} // GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, unknown
                }
            }
            if fin {
                return Err(code::CLOSED_CRITICAL_STREAM);
            }
        }
        Uni::Critical if fin => return Err(code::CLOSED_CRITICAL_STREAM),
        _ => {}
    }
    Ok(())
}

#[derive(Default)]
struct Req {
    r: Reader,
    /// The request from the first HEADERS frame (`Err` if malformed, answered once the stream
    /// ends) and whether it is a HEAD request.
    head: Option<Result<(Request, bool), ()>>,
    body: Vec<u8>,
    trailers: Option<Result<Headers, ()>>,
    done: bool,
}

struct ServerConn<S> {
    svc: Arc<S>,
    cfg: Arc<H3Config>,
    peer: SocketAddr,
    peer_ctrl: Option<StreamId>,
    uni: StreamMap<Uni>,
    reqs: StreamMap<Req>,
    /// Field sections are decoded here, then copied once into the request's `Headers`.
    fields: FieldBuf,
}

/// Why a request stream stopped being read.
enum Fail {
    Conn(u32),
    Stream(u32),
    Status(u16),
}

impl<S: Service> ServerConn<S> {
    fn on_req(&mut self, c: &Connection, id: StreamId, data: &[u8], fin: bool) -> Result<(), Fail> {
        // A request that arrives whole (the usual case) is read without entering the table.
        let mut whole = Req::default();
        let req = if fin && !self.reqs.contains_key(&id) {
            &mut whole
        } else {
            self.reqs.entry(id).or_default()
        };
        let Some((mut request, head_only)) =
            read_req(req, &self.cfg, self.peer, &mut self.fields, data, fin)?
        else {
            return Ok(());
        };
        if c.is_early(id) {
            // Arrived in 0-RTT (maybe a replay): marked as an RFC 8470 intermediary would, so
            // the application can answer 425 Too Early to what is not safe to repeat.
            request.headers.append("early-data", "1");
        }
        let sink = Box::new(Sink {
            c: c.clone(),
            id,
            head_only,
        });
        only_http::transport::dispatch(&*self.svc, request, sink);
        Ok(())
    }
}

/// Reads a request stream's bytes; the request once the stream has ended (`fin`). Frames are
/// read in place and field sections decoded into `fields`, so a request that arrives whole
/// costs no copy before its `Headers` are built.
fn read_req(
    req: &mut Req,
    cfg: &H3Config,
    peer: SocketAddr,
    fields: &mut FieldBuf,
    data: &[u8],
    fin: bool,
) -> Result<Option<(Request, bool)>, Fail> {
    let max_field = cfg.max_field_section_bytes;
    let max_frame = (cfg.max_body_bytes + max_field) as u64;
    if req.done {
        return Ok(None);
    }
    let Req {
        r,
        head,
        body,
        trailers,
        ..
    } = req;
    r.feed(
        data,
        max_frame,
        || Fail::Status(413),
        |ty, p| {
            match ty {
                frame::HEADERS => {
                    qpack::decode_into(p, max_field, fields).map_err(|e| match e {
                        qpack::QpackError::Decompression => {
                            Fail::Conn(code::QPACK_DECOMPRESSION_FAILED)
                        }
                        qpack::QpackError::TooLarge => Fail::Status(431),
                    })?;
                    if head.is_none() {
                        *head = Some(request_head(fields, peer).ok_or(()));
                    } else if trailers.is_none() {
                        let mut t = Headers::with_capacity(fields.len(), fields.bytes());
                        let ok = fields.strs().and_then(|f| header_list(f, &mut t));
                        *trailers = Some(ok.map(|()| t).ok_or(()));
                    } else {
                        return Err(Fail::Conn(code::FRAME_UNEXPECTED));
                    }
                }
                frame::DATA => {
                    if head.is_none() || trailers.is_some() {
                        return Err(Fail::Conn(code::FRAME_UNEXPECTED));
                    }
                    if body.len() + p.len() > cfg.max_body_bytes {
                        return Err(Fail::Status(413));
                    }
                    body.extend_from_slice(p);
                }
                frame::SETTINGS
                | frame::GOAWAY
                | frame::MAX_PUSH_ID
                | frame::CANCEL_PUSH
                | frame::PUSH_PROMISE => return Err(Fail::Conn(code::FRAME_UNEXPECTED)),
                t if h2_only(t) => return Err(Fail::Conn(code::FRAME_UNEXPECTED)),
                _ => {}
            }
            Ok(())
        },
    )?;
    if !fin {
        return Ok(None);
    }
    req.done = true;
    let head = req
        .head
        .take()
        .ok_or(Fail::Stream(code::REQUEST_INCOMPLETE))?;
    let body = std::mem::take(&mut req.body);
    let trailers = req.trailers.take();
    finish_request(head, trailers, body)
        .ok_or(Fail::Stream(code::MESSAGE_ERROR))
        .map(Some)
}

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

/// Appends regular fields to `out`; `None` if one is malformed (a pseudo-header, an uppercase
/// or connection-specific name, `te` other than `trailers`, not UTF-8).
fn header_list<'a>(
    fields: impl Iterator<Item = (&'a str, &'a str)>,
    out: &mut Headers,
) -> Option<()> {
    for (n, v) in fields {
        if n.starts_with(':') || n.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        if matches!(
            n,
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
        ) {
            return None;
        }
        if n == "te" && v != "trailers" {
            return None;
        }
        out.append(n, v);
    }
    Some(())
}

/// A request (without its body) from its field section; `None` if malformed (RFC 9114
/// §4.1.2).
fn request_head(fields: &FieldBuf, peer: SocketAddr) -> Option<(Request, bool)> {
    let (mut method, mut scheme, mut authority, mut path) = (None, None, None, None);
    // One pass (and one UTF-8 check): pseudo-header fields come first; one after a regular
    // field is refused by `header_list`.
    let mut fs = fields.strs()?.peekable();
    while let Some((n, v)) = fs.next_if(|(n, _)| n.starts_with(':')) {
        let slot = match n {
            ":method" => &mut method,
            ":scheme" => &mut scheme,
            ":authority" => &mut authority,
            ":path" => &mut path,
            _ => return None,
        };
        if slot.replace(v).is_some() {
            return None;
        }
    }
    let method = Method::parse(method?);
    if method == Method::Connect {
        if scheme.is_some() || path.is_some() || authority.is_none() {
            return None;
        }
    } else if scheme.is_none() || path.is_none_or(str::is_empty) {
        return None;
    }
    // Room for `host` too; a request with few fields keeps their positions inline.
    let mut headers = Headers::with_capacity(fields.regular() + 1, fields.bytes() + 4);
    header_list(fs, &mut headers)?;
    if let Some(a) = authority {
        if headers.get("host").is_none() {
            headers.append("host", a);
        }
    }
    let head_only = method == Method::Head;
    let target = path.or(authority).unwrap_or_default();
    let mut r = Request::new(method, target);
    r.version = Version::Http3;
    r.headers = headers;
    r.peer = peer;
    Some((r, head_only))
}

/// The request once its stream has ended; `None` if malformed (bad fields or trailers, or a
/// `content-length` that is not the body's).
fn finish_request(
    head: Result<(Request, bool), ()>,
    trailers: Option<Result<Headers, ()>>,
    body: Vec<u8>,
) -> Option<(Request, bool)> {
    let (mut r, head_only) = head.ok()?;
    if let Some(cl) = r.headers.get("content-length") {
        if cl.parse::<usize>().ok()? != body.len() {
            return None;
        }
    }
    if let Some(t) = trailers {
        r.trailers = t.ok()?;
    }
    r.body = body;
    Some((r, head_only))
}

impl<S: Service> QuicHandler for ServerConn<S> {
    fn on_connected(&mut self, c: &Connection) {
        if let Some(id) = c.open_uni() {
            let _ = c.send(
                id,
                control_stream_preamble(self.cfg.max_field_section_bytes),
            );
        }
    }

    fn on_stream_opened(&mut self, _c: &Connection, id: StreamId) {
        // Request streams get their state with their first bytes that do not end them.
        if id.dir() == Dir::Uni {
            self.uni.insert(id, Uni::Unknown(Reader::default()));
        }
    }

    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        if id.dir() == Dir::Uni {
            if let Some(u) = self.uni.get_mut(&id) {
                let mut stop = |id, e| {
                    let _ = c.stop(id, e);
                };
                if let Err(e) = on_uni(u, &mut self.peer_ctrl, &mut stop, id, &data, fin, true) {
                    c.close(e, b"");
                }
            }
            return;
        }
        match self.on_req(c, id, &data, fin) {
            Ok(()) => {}
            Err(Fail::Conn(e)) => c.close(e, b""),
            Err(Fail::Stream(e)) => {
                self.reqs.remove(&id);
                let _ = c.stop(id, e);
                let _ = c.reset(id, e);
            }
            Err(Fail::Status(s)) => {
                if let Some(r) = self.reqs.get_mut(&id) {
                    r.done = true;
                    r.body = Vec::new();
                }
                let _ = c.stop(id, code::NO_ERROR);
                let msg = if s == 413 {
                    "request body too large"
                } else {
                    "request header fields too large"
                };
                Box::new(Sink {
                    c: c.clone(),
                    id,
                    head_only: false,
                })
                .send(Response::text(s, msg));
            }
        }
        if fin {
            self.reqs.remove(&id);
        }
    }

    fn on_stream_reset(&mut self, _c: &Connection, id: StreamId, _code: u64) {
        self.reqs.remove(&id);
    }

    fn on_close(&mut self, _c: &Connection, _reason: ConnectionError) {
        self.reqs.clear();
        self.uni.clear();
    }
}

/// Decimal digits of `n`, at the end of `buf`.
pub(crate) fn digits(buf: &mut [u8; 20], mut n: u64) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[i..];
        }
    }
}

thread_local! {
    /// The current second and its `date` field line, encoded.
    static DATE: RefCell<(u64, Vec<u8>)> = const { RefCell::new((0, Vec::new())) };
}

/// Appends the `date` field line of the current second (encoded once a second per thread).
fn put_date(out: &mut Vec<u8>) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    DATE.with(|c| {
        let mut c = c.borrow_mut();
        if c.0 != secs || c.1.is_empty() {
            c.0 = secs;
            c.1.clear();
            qpack::encode_line(
                &mut c.1,
                b"date",
                only_http::message::http_date_now().as_bytes(),
            );
        }
        out.extend_from_slice(&c.1);
    });
}

/// Calls `f` with `n` lowercased (borrowed when it already is).
fn with_lower<R>(n: &str, f: impl FnOnce(&[u8]) -> R) -> R {
    let b = n.as_bytes();
    if !b.iter().any(u8::is_ascii_uppercase) {
        return f(b);
    }
    let mut stack = [0u8; 64];
    if let Some(t) = stack.get_mut(..b.len()) {
        t.copy_from_slice(b);
        t.make_ascii_lowercase();
        f(t)
    } else {
        f(&b.to_ascii_lowercase())
    }
}

/// Appends a HEADERS frame, its field section encoded straight into `out`: `:status` when
/// given and `pseudo` fields, then `headers` (names lowercased, connection-specific fields and
/// `host` dropped, CR and LF removed from values), then `date` when `add_date` and the headers
/// have none, then `content-length` when given and the headers have none.
pub(crate) fn put_head(
    out: &mut Vec<u8>,
    status: Option<u16>,
    pseudo: &[(&[u8], &[u8])],
    headers: &Headers,
    add_date: bool,
    content_length: Option<u64>,
) {
    let at = frame::begin_frame(out, frame::HEADERS);
    out.extend_from_slice(&qpack::PREFIX);
    if let Some(s) = status {
        qpack::encode_status(out, s);
    }
    for &(n, v) in pseudo {
        qpack::encode_line(out, n, v);
    }
    let (mut has_date, mut has_len) = (false, false);
    for (n, v) in headers.iter() {
        with_lower(n, |n| {
            match n {
                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
                | b"upgrade" | b"host" => return,
                b"date" => has_date = true,
                b"content-length" => has_len = true,
                _ => {}
            }
            if v.bytes().any(|b| b == b'\r' || b == b'\n') {
                let v: Vec<u8> = v.bytes().filter(|&b| b != b'\r' && b != b'\n').collect();
                qpack::encode_line(out, n, &v);
            } else {
                qpack::encode_line(out, n, v.as_bytes());
            }
        });
    }
    if add_date && !has_date {
        put_date(out);
    }
    if let (Some(len), false) = (content_length, has_len) {
        qpack::encode_content_length(out, len);
    }
    frame::end_frame(out, at);
}

pub(crate) fn data_frame(data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(data.len() + 9);
    frame::put_frame(&mut f, frame::DATA, data);
    f
}

/// Bodies up to this size are copied behind the response head and sent with it; larger ones
/// are handed to QUIC as they are, after a DATA frame header.
const COPY_BODY_MAX: usize = 16 << 10;

/// Messages whose body is at most this size are written into a buffer from only-quic's
/// per-thread pool ([`Bytes::pooled`]): no allocation per message once the pool is warm. The
/// bound keeps pooled buffers small.
pub(crate) const POOLED_BODY_MAX: usize = 2 << 10;

/// Answers a request stream.
struct Sink {
    c: Connection,
    id: StreamId,
    head_only: bool,
}

impl Sink {
    /// Appends the HEADERS frame of `resp` to `out`; whether a body may follow.
    fn head(&self, out: &mut Vec<u8>, resp: &Response, streaming: bool) -> bool {
        let bodyless = resp.status < 200 || resp.status == 204 || resp.status == 304;
        let len = (!bodyless && !streaming).then(|| resp.body_len());
        put_head(out, Some(resp.status), &[], &resp.headers, true, len);
        !(bodyless || self.head_only)
    }

    /// A buffer for the HEADERS frame of `resp` and `extra` more bytes.
    fn head_buf(resp: &Response, extra: usize) -> Vec<u8> {
        Vec::with_capacity(head_hint(&resp.headers) + 64 + extra)
    }

    /// Appends the trailers' HEADERS frame, if any, to `out`.
    fn put_trailers(&self, out: &mut Vec<u8>, trailers: Option<&Headers>) {
        if let Some(t) = trailers.filter(|t| !t.is_empty() && !self.head_only) {
            put_head(out, None, &[], t, false, None);
        }
    }

    /// Sends `out` (if not empty) and ends the stream.
    fn send_and_finish(&self, out: impl Into<Bytes>) {
        let out = out.into();
        if !out.is_empty() {
            let _ = self.c.send(self.id, out);
        }
        let _ = self.c.finish(self.id);
    }
}

/// Bytes to reserve for encoding `headers`.
pub(crate) fn head_hint(headers: &Headers) -> usize {
    headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum()
}

impl ResponseSink for Sink {
    fn send(self: Box<Self>, mut resp: Response) {
        let trailers = resp.trailers.take();
        if resp.file.is_none() && resp.body.len() <= POOLED_BODY_MAX {
            // The usual small response: head, body and trailers in one pooled buffer.
            let hint = head_hint(&resp.headers) + 64 + resp.body.len() + 9;
            let out = Bytes::pooled(hint, |out| {
                if self.head(out, &resp, false) && !resp.body.is_empty() {
                    frame::put_frame(out, frame::DATA, &resp.body);
                }
                self.put_trailers(out, trailers.as_ref());
            });
            return self.send_and_finish(out);
        }
        let small = resp.file.is_none() && resp.body.len() <= COPY_BODY_MAX;
        let extra = if small { resp.body.len() + 9 } else { 9 };
        let mut out = Sink::head_buf(&resp, extra);
        let body = self.head(&mut out, &resp, false);
        if body {
            if let Some(fb) = resp.file.take() {
                use std::os::unix::fs::FileExt;
                let _ = self.c.send(self.id, std::mem::take(&mut out));
                let mut off = fb.offset;
                let end = fb.offset + fb.len;
                let mut buf = vec![0u8; 256 << 10];
                while off < end {
                    let want = ((end - off) as usize).min(buf.len());
                    match fb.file.read_at(&mut buf[..want], off) {
                        Ok(0) | Err(_) => {
                            let _ = self.c.reset(self.id, code::INTERNAL_ERROR);
                            return;
                        }
                        Ok(n) => {
                            let _ = self.c.send(self.id, data_frame(&buf[..n]));
                            off += n as u64;
                        }
                    }
                }
            } else if small {
                if !resp.body.is_empty() {
                    frame::put_frame(&mut out, frame::DATA, &resp.body);
                }
            } else {
                frame::put_varint(&mut out, frame::DATA);
                frame::put_varint(&mut out, resp.body.len() as u64);
                let _ = self.c.send(self.id, out);
                let _ = self.c.send(self.id, std::mem::take(&mut resp.body));
                out = Vec::new();
            }
        }
        self.put_trailers(&mut out, trailers.as_ref());
        self.send_and_finish(out);
    }

    fn start_stream(self: Box<Self>, resp: Response) -> Option<Box<dyn BodySink>> {
        if self.c.is_closed() {
            return None;
        }
        let mut out = Sink::head_buf(&resp, 0);
        let body = self.head(&mut out, &resp, true);
        let _ = self.c.send(self.id, out);
        Some(Box::new(Body { s: *self, body }))
    }
}

struct Body {
    s: Sink,
    body: bool,
}

impl BodySink for Body {
    fn write(&self, data: &[u8]) -> only_core::Result<()> {
        if !self.body || data.is_empty() {
            return Ok(());
        }
        self.s
            .c
            .send(self.s.id, data_frame(data))
            .map_err(|_| only_core::Error::Closed)
    }

    fn queued_bytes(&self) -> usize {
        self.s.c.queued_bytes(self.s.id)
    }

    fn finish(self: Box<Self>, trailers: Option<Headers>) {
        let mut out = Vec::new();
        self.s.put_trailers(&mut out, trailers.as_ref());
        self.s.send_and_finish(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(wire: &[u8]) -> Vec<(String, String)> {
        let mut r = Reader::default();
        let mut out = Vec::new();
        r.feed(
            wire,
            1 << 20,
            || (),
            |ty, p| {
                assert_eq!(ty, frame::HEADERS);
                for (n, v) in qpack::decode(p, 1 << 20).unwrap() {
                    out.push((String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()));
                }
                Ok(())
            },
        )
        .unwrap();
        out
    }

    #[test]
    fn head_encoding() {
        let mut h = Headers::new();
        h.append("Content-Type", "text/plain");
        h.append("Connection", "close");
        h.append("Host", "x");
        h.append("X-Split", "a\r\nb");
        h.append(format!("X-{}", "L".repeat(80)), "long name");
        let mut out = vec![7];
        put_head(&mut out, Some(200), &[], &h, true, Some(1234));
        let got = decoded(&out[1..]);
        let long = format!("x-{}", "l".repeat(80));
        let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                ":status",
                "content-type",
                "x-split",
                long.as_str(),
                "date",
                "content-length"
            ]
        );
        assert_eq!(got[2].1, "ab");
        assert_eq!(got[5].1, "1234");
        // A date and length already present are kept and not repeated; the block is long
        // enough to need a two-byte frame length.
        h.append("date", "d");
        h.append("content-length", "5");
        h.append("x-pad", "p".repeat(100));
        let mut out = Vec::new();
        put_head(&mut out, None, &[], &h, true, Some(9));
        let got = decoded(&out);
        assert_eq!(got.iter().filter(|(n, _)| n == "date").count(), 1);
        assert_eq!(
            got.iter().find(|(n, _)| n == "content-length").unwrap().1,
            "5"
        );
        // `:status 200` and `content-type text/plain` are single static references.
        let mut h = Headers::new();
        h.append("content-type", "text/plain");
        let mut out = Vec::new();
        put_head(&mut out, Some(200), &[], &h, false, None);
        assert_eq!(out, [0x01, 0x04, 0, 0, 0xc0 | 25, 0xc0 | 53]);
        assert_eq!(digits(&mut [0; 20], 0), b"0");
        assert_eq!(
            digits(&mut [0; 20], u64::MAX),
            u64::MAX.to_string().as_bytes()
        );
    }

    #[test]
    fn request_heads() {
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let head = |fields: &[(&str, &str)]| {
            let mut b = Vec::new();
            qpack::encode(fields.iter().copied(), &mut b);
            let mut f = FieldBuf::default();
            qpack::decode_into(&b, 1 << 16, &mut f).unwrap();
            request_head(&f, peer)
        };
        let base = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "a.example"),
            (":path", "/p?q"),
        ];
        let (r, head_only) = head(&base).unwrap();
        assert!(!head_only);
        assert_eq!((r.target.as_str(), r.version), ("/p?q", Version::Http3));
        assert_eq!(r.headers.get("host"), Some("a.example"));
        let mut more = base.to_vec();
        more.push(("host", "b.example"));
        more.push(("te", "trailers"));
        let (r, _) = head(&more).unwrap();
        assert_eq!(r.headers.get_all("host").collect::<Vec<_>>(), ["b.example"]);
        for bad in [
            vec![(":method", "GET"), (":path", "/")],
            vec![(":method", "GET"), (":scheme", "https"), (":path", "")],
            vec![(":method", "CONNECT"), (":authority", "a"), (":path", "/")],
            [&base[..], &[("x", "1"), (":path", "/")]].concat(),
            [&base[..], &[(":method", "GET")]].concat(),
            [&base[..], &[(":protocol", "x")]].concat(),
            [&base[..], &[("X-Up", "1")]].concat(),
            [&base[..], &[("connection", "close")]].concat(),
            [&base[..], &[("te", "gzip")]].concat(),
        ] {
            assert!(head(&bad).is_none(), "{bad:?}");
        }
        let (r, _) = head(&[(":method", "CONNECT"), (":authority", "h:443")]).unwrap();
        assert_eq!(r.target, "h:443");
        let (r, head_only) = head(&[
            (":method", "HEAD"),
            (":scheme", "https"),
            (":path", "/"),
            ("content-length", "2"),
        ])
        .unwrap();
        assert!(head_only);
        assert!(finish_request(Ok((r.clone(), true)), None, b"ab".to_vec()).is_some());
        assert!(finish_request(Ok((r.clone(), true)), None, b"abc".to_vec()).is_none());
        assert!(finish_request(Ok((r, true)), Some(Err(())), b"ab".to_vec()).is_none());
        assert!(finish_request(Err(()), None, Vec::new()).is_none());
    }
}
