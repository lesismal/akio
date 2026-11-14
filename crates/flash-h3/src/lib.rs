//! HTTP/3 (RFC 9114) for flash, on [`flash_quic`] with QPACK (static table and literals).
//!
//! [`server`] serves any [`flash_http::Service`] (a [`flash_http::Router`] with its
//! middleware) over QUIC: handlers get the same [`flash_http::Context`] as on HTTP/1.1 and
//! HTTP/2, including `detach` and `stream_response`; request bodies arrive buffered.
//! [`H3Client`] sends requests on one QUIC connection.
//!
//! ```no_run
//! use flash::{Engine, Listener};
//! use flash_http::{Context, Router};
//!
//! # let (certs, key) = (vec![], flash_quic::rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()));
//! let app = Router::new().get("/", |ctx: &mut Context| ctx.text(200, "hello over h3"));
//! let quic = flash_h3::server_config(certs, key).unwrap();
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:443".parse().unwrap()).serve(flash_h3::server(quic, app)))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! Not implemented: server push, a QPACK dynamic table, extended CONNECT (WebSocket over
//! HTTP/3), streamed request bodies.
//!
//! Guide: [QUIC and HTTP/3](https://lesismal.github.io/flash/en/protocols/quic-h3.html)
//! (中文: [QUIC 与 HTTP/3](https://lesismal.github.io/flash/zh-CN/protocols/quic-h3.html)).

mod client;
mod frame;
pub mod qpack;
mod table;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use flash_http::Service;
use flash_http::message::{Headers, Method, Request, Response, Version};
use flash_http::transport::{BodySink, ResponseSink};
use flash_quic::{Connection, ConnectionError, Dir, QuicHandler, QuicServer, StreamId};

pub use client::H3Client;
pub use frame::code;

use frame::Reader;

/// Server limits.
#[derive(Clone, Debug)]
pub struct H3Config {
    /// Largest request body (larger ones get 413).
    pub max_body: usize,
    /// Largest field section, as `SETTINGS_MAX_FIELD_SECTION_SIZE`.
    pub max_field_section: usize,
}

impl Default for H3Config {
    fn default() -> H3Config {
        H3Config {
            max_body: 8 << 20,
            max_field_section: 64 << 10,
        }
    }
}

/// A QUIC server config for a certificate chain and key, offering ALPN `h3`.
pub fn server_config(
    certs: Vec<flash_quic::rustls::pki_types::CertificateDer<'static>>,
    key: flash_quic::rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<flash_quic::proto::ServerConfig, flash_quic::Error> {
    flash_quic::server_config(certs, key, &[b"h3"])
}

/// Serves `service` over HTTP/3: the acceptor of a UDP listener.
pub fn server<S: Service>(quic: flash_quic::proto::ServerConfig, service: S) -> QuicServer {
    server_with(quic, service, H3Config::default())
}

/// [`server`] with limits.
pub fn server_with<S: Service>(
    quic: flash_quic::proto::ServerConfig,
    service: S,
    cfg: H3Config,
) -> QuicServer {
    let svc = Arc::new(service);
    let cfg = Arc::new(cfg);
    QuicServer::new(quic, move |c: &Connection| ServerConn {
        svc: svc.clone(),
        cfg: cfg.clone(),
        peer: c.remote_addr(),
        peer_ctrl: None,
        uni: HashMap::new(),
        reqs: HashMap::new(),
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
    fields: Option<qpack::Fields>,
    body: Vec<u8>,
    trailers: Option<qpack::Fields>,
    done: bool,
}

struct ServerConn<S> {
    svc: Arc<S>,
    cfg: Arc<H3Config>,
    peer: SocketAddr,
    peer_ctrl: Option<StreamId>,
    uni: HashMap<StreamId, Uni>,
    reqs: HashMap<StreamId, Req>,
}

/// Why a request stream stopped being read.
enum Fail {
    Conn(u32),
    Stream(u32),
    Status(u16),
}

impl<S: Service> ServerConn<S> {
    fn on_req(&mut self, c: &Connection, id: StreamId, data: &[u8], fin: bool) -> Result<(), Fail> {
        let req = self.reqs.entry(id).or_default();
        let Some((request, head_only)) = read_req(req, &self.cfg, self.peer, data, fin)? else {
            return Ok(());
        };
        let sink = Box::new(Sink {
            c: c.clone(),
            id,
            head_only,
        });
        flash_http::transport::dispatch(&*self.svc, request, sink);
        Ok(())
    }
}

/// Reads a request stream's bytes; the request once the stream has ended (`fin`).
fn read_req(
    req: &mut Req,
    cfg: &H3Config,
    peer: SocketAddr,
    data: &[u8],
    fin: bool,
) -> Result<Option<(Request, bool)>, Fail> {
    {
        let max_field = cfg.max_field_section;
        let max_frame = (cfg.max_body + max_field) as u64;
        if req.done {
            return Ok(None);
        }
        req.r.push(data);
        loop {
            let f = req.r.frame(max_frame).map_err(|_| Fail::Status(413))?;
            let Some((ty, p)) = f else { break };
            match ty {
                frame::HEADERS => {
                    let fields = qpack::decode(&p, max_field).map_err(|e| match e {
                        qpack::QpackError::Decompression => {
                            Fail::Conn(code::QPACK_DECOMPRESSION_FAILED)
                        }
                        qpack::QpackError::TooLarge => Fail::Status(431),
                    })?;
                    if req.fields.is_none() {
                        req.fields = Some(fields);
                    } else if req.trailers.is_none() {
                        req.trailers = Some(fields);
                    } else {
                        return Err(Fail::Conn(code::FRAME_UNEXPECTED));
                    }
                }
                frame::DATA => {
                    if req.fields.is_none() || req.trailers.is_some() {
                        return Err(Fail::Conn(code::FRAME_UNEXPECTED));
                    }
                    if req.body.len() + p.len() > cfg.max_body {
                        return Err(Fail::Status(413));
                    }
                    req.body.extend_from_slice(&p);
                }
                frame::SETTINGS
                | frame::GOAWAY
                | frame::MAX_PUSH_ID
                | frame::CANCEL_PUSH
                | frame::PUSH_PROMISE => return Err(Fail::Conn(code::FRAME_UNEXPECTED)),
                t if h2_only(t) => return Err(Fail::Conn(code::FRAME_UNEXPECTED)),
                _ => {}
            }
        }
        if !fin {
            return Ok(None);
        }
        req.done = true;
        let fields = req
            .fields
            .take()
            .ok_or(Fail::Stream(code::REQUEST_INCOMPLETE))?;
        let body = std::mem::take(&mut req.body);
        let trailers = req.trailers.take();
        build_request(fields, trailers, body, peer)
            .ok_or(Fail::Stream(code::MESSAGE_ERROR))
            .map(Some)
    }
}

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

fn header_list(fields: qpack::Fields, out: &mut Headers) -> Option<()> {
    for (n, v) in fields {
        let n = String::from_utf8(n).ok()?;
        if n.starts_with(':') || n.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        if matches!(
            n.as_str(),
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
        ) {
            return None;
        }
        let v = String::from_utf8(v).ok()?;
        if n == "te" && v != "trailers" {
            return None;
        }
        out.append(n, v);
    }
    Some(())
}

/// A request from its field sections; `None` if malformed (RFC 9114 §4.1.2).
fn build_request(
    fields: qpack::Fields,
    trailers: Option<qpack::Fields>,
    body: Vec<u8>,
    peer: SocketAddr,
) -> Option<(Request, bool)> {
    let (mut method, mut scheme, mut authority, mut path) = (None, None, None, None);
    let mut regular = Vec::new();
    let mut in_pseudo = true;
    for (n, v) in fields {
        if n.first() == Some(&b':') {
            if !in_pseudo {
                return None;
            }
            let v = String::from_utf8(v).ok()?;
            let slot = match n.as_slice() {
                b":method" => &mut method,
                b":scheme" => &mut scheme,
                b":authority" => &mut authority,
                b":path" => &mut path,
                _ => return None,
            };
            if slot.replace(v).is_some() {
                return None;
            }
        } else {
            in_pseudo = false;
            regular.push((n, v));
        }
    }
    let method = Method::parse(&method?);
    if method == Method::Connect {
        if scheme.is_some() || path.is_some() || authority.is_none() {
            return None;
        }
    } else if scheme.is_none() || path.as_deref().is_none_or(str::is_empty) {
        return None;
    }
    let mut headers = Headers::new();
    header_list(regular, &mut headers)?;
    if let Some(a) = authority.as_deref() {
        if headers.get("host").is_none() {
            headers.set("host", a);
        }
    }
    if let Some(cl) = headers.get("content-length") {
        if cl.parse::<usize>().ok()? != body.len() {
            return None;
        }
    }
    let mut tr = Headers::new();
    if let Some(t) = trailers {
        header_list(t, &mut tr)?;
    }
    let head_only = method == Method::Head;
    let target = path.unwrap_or_else(|| authority.clone().unwrap_or_default());
    Some((
        Request {
            method,
            target,
            version: Version::Http3,
            headers,
            trailers: tr,
            body,
            peer,
        },
        head_only,
    ))
}

impl<S: Service> QuicHandler for ServerConn<S> {
    fn on_connected(&mut self, c: &Connection) {
        if let Some(id) = c.open_uni() {
            let _ = c.send(id, control_stream_preamble(self.cfg.max_field_section));
        }
    }

    fn on_stream_opened(&mut self, _c: &Connection, id: StreamId) {
        if id.dir() == Dir::Uni {
            self.uni.insert(id, Uni::Unknown(Reader::default()));
        } else {
            self.reqs.insert(id, Req::default());
        }
    }

    fn on_stream_data(&mut self, c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        if let Some(u) = self.uni.get_mut(&id) {
            let mut stop = |id, e| {
                let _ = c.stop(id, e);
            };
            if let Err(e) = on_uni(u, &mut self.peer_ctrl, &mut stop, id, &data, fin, true) {
                c.close(e, b"");
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

/// Response fields, lowercase, without connection-specific ones.
pub(crate) fn encode_fields(first: &[(&str, &str)], headers: &Headers) -> Vec<u8> {
    let mut list: Vec<(String, String)> = first
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    for (n, v) in headers.iter() {
        let n = n.to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
                | "host"
        ) {
            continue;
        }
        list.push((n, v.replace(['\r', '\n'], "")));
    }
    let mut out = Vec::new();
    qpack::encode(list.iter().map(|(n, v)| (n.as_str(), v.as_str())), &mut out);
    out
}

pub(crate) fn data_frame(data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(data.len() + 9);
    frame::put_frame(&mut f, frame::DATA, data);
    f
}

/// Answers a request stream.
struct Sink {
    c: Connection,
    id: StreamId,
    head_only: bool,
}

impl Sink {
    fn head(&self, resp: &mut Response, streaming: bool) -> bool {
        let bodyless = resp.status < 200 || resp.status == 204 || resp.status == 304;
        if resp.headers.get("date").is_none() {
            resp.headers
                .set("date", flash_http::message::http_date_now());
        }
        if !bodyless && !streaming && resp.headers.get("content-length").is_none() {
            resp.headers
                .set("content-length", resp.body_len().to_string());
        }
        let status = resp.status.to_string();
        let block = encode_fields(&[(":status", &status)], &resp.headers);
        let mut f = Vec::with_capacity(block.len() + 9);
        frame::put_frame(&mut f, frame::HEADERS, &block);
        let _ = self.c.send(self.id, f);
        !(bodyless || self.head_only)
    }

    fn trailers_and_finish(&self, trailers: Option<Headers>) {
        if let Some(t) = trailers.filter(|t| !t.is_empty() && !self.head_only) {
            let block = encode_fields(&[], &t);
            let mut f = Vec::new();
            frame::put_frame(&mut f, frame::HEADERS, &block);
            let _ = self.c.send(self.id, f);
        }
        let _ = self.c.finish(self.id);
    }
}

impl ResponseSink for Sink {
    fn send(self: Box<Self>, mut resp: Response) {
        let body = self.head(&mut resp, false);
        if body {
            if let Some(fb) = resp.file.take() {
                use std::os::unix::fs::FileExt;
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
            } else if !resp.body.is_empty() {
                let _ = self.c.send(self.id, data_frame(&resp.body));
            }
        }
        self.trailers_and_finish(resp.trailers.take());
    }

    fn start_stream(self: Box<Self>, mut resp: Response) -> Option<Box<dyn BodySink>> {
        if self.c.is_closed() {
            return None;
        }
        let body = self.head(&mut resp, true);
        Some(Box::new(Body { s: *self, body }))
    }
}

struct Body {
    s: Sink,
    body: bool,
}

impl BodySink for Body {
    fn write(&self, data: &[u8]) -> flash_core::Result<()> {
        if !self.body || data.is_empty() {
            return Ok(());
        }
        self.s
            .c
            .send(self.s.id, data_frame(data))
            .map_err(|_| flash_core::Error::Closed)
    }

    fn queued_bytes(&self) -> usize {
        self.s.c.queued_bytes(self.s.id)
    }

    fn finish(self: Box<Self>, trailers: Option<Headers>) {
        self.s.trailers_and_finish(trailers);
    }
}
