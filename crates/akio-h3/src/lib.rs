#![forbid(unsafe_code)]
//! HTTP/3 (RFC 9114) for `akio`, on [`akio_quic`] with QPACK (RFC 9204).
//!
//! [`serve`] serves any [`akio_http::Service`] (a [`akio_http::Router`] with its
//! middleware) over QUIC: handlers get the same [`akio_http::Context`] as on HTTP/1.1 and
//! HTTP/2, including `detach`, `stream_response` and streamed request bodies.
//! [`H3Client`] sends requests on one QUIC connection.
//!
//! ```no_run
//! use akio::{Engine, Listener};
//! use akio_http::{Context, Router};
//!
//! # let (certs, key) = (vec![], akio::tls::PrivateKey::from_pkcs8_der(vec![]));
//! let app = Router::new().get("/", |ctx: &mut Context| ctx.text(200, "hello over h3"));
//! let quic = akio_h3::server_config(certs, key).unwrap();
//! let engine = Engine::builder()
//!     .listen(Listener::udp("0.0.0.0:443".parse().unwrap()).serve(akio_h3::serve(quic, app)))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! 0-RTT (off by default, [`akio_quic::ServerConfig::zero_rtt`]): a request that arrived in
//! 0-RTT packets carries `Early-Data: 1` (RFC 8470 section 5.1), as if an intermediary had
//! forwarded it early; it may be a replay, so answer what is not safe to repeat (anything
//! but a GET or HEAD without side effects, say) with `425 Too Early` and the client retries
//! it after the handshake. [`H3Client`] sends its requests in 0-RTT when its QUIC config
//! enables it ([`akio_quic::ClientConfig::zero_rtt`]) and it resumes.
//!
//! QPACK uses a dynamic table ([`H3Config`]): the decoder accepts the peer's inserts (4 KiB and
//! 16 blocked streams by default); the encoder is off by default and, when enabled, inserts
//! fields that repeat, duplicates entries about to be evicted, references names and fields in
//! its table (post-base too) and leaves at most as many streams waiting for its inserts as the
//! peer's `SETTINGS_QPACK_BLOCKED_STREAMS` allows.
//!
//! WebSocket over HTTP/3 (RFC 9220): servers advertise extended CONNECT, and
//! `Context::upgrade_websocket` accepts it (a [`Router`][akio_http::Router] GET route answers
//! it as it answers an HTTP/1.1 upgrade); [`H3Client::websocket`] opens one.
//!
//! Request bodies stream: a service whose `body_mode` is `Stream` gets the body through
//! `Context::on_body` as it arrives, as on HTTP/2; [`H3Client::upload`] sends one piece by
//! piece.
//!
//! Not implemented: server push.
//!
//! Guide: [QUIC and HTTP/3](https://lesismal.github.io/akio/en/protocols/quic-h3.html)
//! (中文: [QUIC 与 HTTP/3](https://lesismal.github.io/akio/zh-CN/protocols/quic-h3.html)).
#![warn(clippy::unwrap_used)]

mod client;
mod frame;
pub mod qpack;
mod qtable;
mod table;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use akio_http::Service;
use akio_http::message::{Headers, Method, Request, Response, Version};
use akio_http::transport::{BodySink, ConnSink, SharedSink, Started};
use akio_http::ws::{WsLink, WsSession};
use akio_quic::Bytes;
use akio_quic::{Connection, ConnectionError, Dir, QuicHandler, QuicServer, StreamId};

pub use client::{H3Client, H3ClientOptions, H3Error, H3Event, H3Upload, H3WsOptions};
pub use frame::code;

use frame::{Piece, Reader, StreamReader};
use qpack::{FieldBuf, QpackError, SectionError};
use qtable::{DecTable, Encoder, Section};

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

/// HTTP/3 limits and QPACK settings of a server ([`serve_with`]); a client takes its own
/// through [`H3ClientOptions`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H3Config {
    /// Largest request body (larger ones get 413). Bodies a service takes as a stream
    /// (`akio_http::BodyMode::Stream`) are not limited.
    pub max_body_bytes: usize,
    /// Largest field section, as `SETTINGS_MAX_FIELD_SECTION_SIZE`.
    pub max_field_section_bytes: usize,
    /// The QPACK dynamic table the peer's encoder may fill for this side's decoder
    /// (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`), in bytes; 0 allows static references and literals
    /// only. Default 4096.
    pub qpack_max_table_capacity: usize,
    /// Streams the peer may leave waiting for QPACK inserts (`SETTINGS_QPACK_BLOCKED_STREAMS`).
    /// Default 16.
    pub qpack_blocked_streams: usize,
    /// The QPACK dynamic table this side's encoder uses (at most what the peer allows), in
    /// bytes; 0 encodes with static references and literals only. Default 4096 for a server
    /// (its responses' `date`, `content-type`, `server` ... become one-byte references after
    /// their second use, ADR-102), 0 for a client ([`H3ClientOptions`]). The encoder inserts
    /// fields the second time it sees them (not paths, lengths, validators, ranges or
    /// credentials; `date` is, since every response of the same second repeats it), and makes
    /// at most as many of the peer's streams wait for its inserts as the peer's
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` allows (at most 64); it evicts only entries the peer
    /// has acknowledged.
    pub qpack_encoder_capacity: usize,
    /// Run each request's service (middleware and handler) on the engine's logical pool
    /// instead of the connection's I/O thread, so handlers may block and the requests of one
    /// connection are served at the same time. Requests whose body the service takes as a
    /// stream, and CONNECTs (extended or not), stay on the I/O thread. When the pool's queue
    /// is full the request is answered `503`. Default `false`.
    pub handlers_on_logical_pool: bool,
}

impl Default for H3Config {
    fn default() -> H3Config {
        H3Config {
            max_body_bytes: 8 << 20,
            max_field_section_bytes: 64 << 10,
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            handlers_on_logical_pool: false,
            qpack_encoder_capacity: 4096,
        }
    }
}

/// A QUIC server config for a certificate chain and key, offering ALPN `h3`.
pub fn server_config(
    certs: Vec<akio::tls::Certificate>,
    key: akio::tls::PrivateKey,
) -> Result<akio_quic::ServerConfig, akio_quic::Error> {
    akio_quic::server_config(certs, key, &[b"h3"])
}

/// Serves `service` over HTTP/3: the acceptor of a UDP listener (like `akio_http::serve`).
pub fn serve<S: Service>(quic: akio_quic::ServerConfig, service: S) -> QuicServer {
    serve_with(quic, H3Config::default(), service)
}

/// [`serve`] with limits (like `akio_http::serve_with`).
pub fn serve_with<S: Service>(
    quic: akio_quic::ServerConfig,
    cfg: H3Config,
    service: S,
) -> QuicServer {
    let svc = Arc::new(service);
    let cfg = Arc::new(cfg);
    QuicServer::new(quic, move |c: &Connection| {
        let out = H3Out {
            c: c.clone(),
            outs: Arc::default(),
            drains: Arc::default(),
            gones: Arc::default(),
            enc: None,
        };
        ServerConn {
            svc: svc.clone(),
            peer: c.remote_addr(),
            conn: Peer::new(&cfg),
            cfg: cfg.clone(),
            uni: StreamMap::default(),
            reqs: StreamMap::default(),
            fields: FieldBuf::default(),
            sink: SharedSink::new(out.clone()),
            out,
            span: akio_http::trace::connection_span(c.remote_addr(), "3"),
            certs: PeerCerts::new(),
        }
    })
}

/// The control stream preamble both sides send: SETTINGS with our QPACK decoder's limits, our
/// field section limit and, from a server, extended CONNECT (RFC 9220).
pub(crate) fn control_stream_preamble(cfg: &H3Config, server: bool) -> Vec<u8> {
    let mut p = Vec::new();
    let mut set = |id, v: u64| {
        frame::put_varint(&mut p, id);
        frame::put_varint(&mut p, v);
    };
    set(
        frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
        cfg.qpack_max_table_capacity as u64,
    );
    set(
        frame::SETTINGS_QPACK_BLOCKED_STREAMS,
        cfg.qpack_blocked_streams as u64,
    );
    set(
        frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
        cfg.max_field_section_bytes as u64,
    );
    if server {
        set(frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1);
    }
    let mut out = Vec::new();
    frame::put_varint(&mut out, frame::STREAM_CONTROL);
    frame::put_frame(&mut out, frame::SETTINGS, &p);
    out
}

/// What the peer's SETTINGS said.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Settings {
    pub(crate) qpack_max_table_capacity: u64,
    pub(crate) qpack_blocked_streams: u64,
    pub(crate) connect_protocol: bool,
}

/// Checks a SETTINGS payload (well formed, no HTTP/2 identifiers, no duplicates, a valid
/// extended CONNECT flag) and reads the values we use.
pub(crate) fn check_settings(p: &[u8]) -> Result<Settings, u32> {
    let mut seen = Vec::new();
    let mut out = Settings::default();
    let mut pos = 0;
    while pos < p.len() {
        let (id, a) = frame::get_varint(&p[pos..]).ok_or(code::FRAME_ERROR)?;
        pos += a;
        let (v, b) = frame::get_varint(&p[pos..]).ok_or(code::FRAME_ERROR)?;
        pos += b;
        if (0x2..=0x5).contains(&id) || seen.contains(&id) {
            return Err(code::SETTINGS_ERROR);
        }
        match id {
            frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY => out.qpack_max_table_capacity = v,
            frame::SETTINGS_QPACK_BLOCKED_STREAMS => out.qpack_blocked_streams = v,
            frame::SETTINGS_ENABLE_CONNECT_PROTOCOL => {
                if v > 1 {
                    return Err(code::SETTINGS_ERROR);
                }
                out.connect_protocol = v == 1;
            }
            _ => {}
        }
        seen.push(id);
    }
    Ok(out)
}

/// Frame types reserved by HTTP/2 that must not appear in HTTP/3.
pub(crate) fn h2_only(ty: u64) -> bool {
    matches!(ty, 0x2 | 0x6 | 0x8 | 0x9)
}

/// The QUIC stream id as a QPACK instruction carries it.
pub(crate) fn sid(id: StreamId) -> u64 {
    let side = match id.initiator() {
        akio_quic::Side::Client => 0,
        akio_quic::Side::Server => 1,
    };
    let dir = match id.dir() {
        Dir::Bi => 0,
        Dir::Uni => 2,
    };
    (id.index() << 2) | dir | side
}

/// A peer's unidirectional stream.
pub(crate) enum Uni {
    Unknown(Reader),
    Control {
        r: Reader,
        settings: bool,
    },
    /// The peer's QPACK encoder stream: an incomplete instruction's bytes.
    Encoder(Vec<u8>),
    /// The peer's QPACK decoder stream: an incomplete instruction's bytes.
    Decoder(Vec<u8>),
    Skip,
}

/// This side's QPACK encoder with its dynamic table, shared by everything that encodes on the
/// connection (responses are sent from any thread).
///
/// A send on the connection from outside its handler runs the handler on the sending thread
/// for whatever is pending, and the handler locks the encoder to read the peer's decoder
/// stream. So nothing sends under the encoder's lock: a section leaves its inserts in
/// `Encoder::out`, and they go out after, under `send` (which the handler never waits for).
/// Taking them under `send` keeps the encoder stream in order; a thread that finds `send`
/// taken leaves them to its holder (`again`), who may be the very thread whose send ran the
/// handler that encoded them.
pub(crate) struct EncShared {
    c: Connection,
    /// Our encoder stream.
    stream: StreamId,
    e: Mutex<Encoder>,
    /// Held while inserts are sent; only ever tried.
    send: Mutex<()>,
    /// Inserts wait in `Encoder::out` for a sender.
    again: AtomicBool,
    /// Bytes taken out of `Encoder::out` and not yet handed to the connection.
    sending: AtomicUsize,
}

impl EncShared {
    fn new(c: Connection, stream: StreamId, e: Encoder) -> EncShared {
        EncShared {
            c,
            stream,
            e: Mutex::new(e),
            send: Mutex::new(()),
            again: AtomicBool::new(false),
            sending: AtomicUsize::new(0),
        }
    }

    /// Encodes a field section for stream `id` into `out` with `f` adding its lines, then sends
    /// the inserts it made (before the caller sends the section, unless another thread is
    /// sending inserts: then that one sends them, right after its own).
    fn section(
        &self,
        out: &mut Vec<u8>,
        id: StreamId,
        f: impl FnOnce(&mut Encoder, &mut Vec<u8>, &mut Section),
    ) {
        let inserted = {
            let mut e = self.e.lock().unwrap_or_else(|p| p.into_inner());
            // Inserts only as long as the encoder stream can take them (else they are lost and
            // the sections referencing them never decode): its room, less what is on its way.
            let room = self.c.send_capacity(self.stream).unwrap_or(0);
            e.room = room.saturating_sub(self.sending.load(Ordering::Acquire));
            let (mut lines, mut sec) = e.begin(sid(id));
            f(&mut e, &mut lines, &mut sec);
            e.end(out, lines, sec);
            !e.out.is_empty()
        };
        if inserted {
            self.again.store(true, Ordering::SeqCst);
            self.flush();
        }
    }

    /// Sends the inserts that wait, unless another thread is sending: it sends them then.
    fn flush(&self) {
        while self.again.load(Ordering::SeqCst) {
            let _send = match self.send.try_lock() {
                Ok(g) => g,
                Err(TryLockError::Poisoned(p)) => p.into_inner(),
                // Its holder checks again once it lets go.
                Err(TryLockError::WouldBlock) => return,
            };
            while self.again.swap(false, Ordering::SeqCst) {
                let ins = {
                    let mut e = self.e.lock().unwrap_or_else(|p| p.into_inner());
                    let ins = std::mem::take(&mut e.out);
                    self.sending.store(ins.len(), Ordering::Release);
                    ins
                };
                if !ins.is_empty() {
                    let _ = self.c.send(self.stream, ins);
                }
                self.sending.store(0, Ordering::Release);
            }
        }
    }
}

/// Connection state both sides keep: the peer's control stream and SETTINGS, and QPACK (our
/// decoder's table, our encoder once the peer allows one).
pub(crate) struct Peer {
    pub(crate) ctrl: Option<StreamId>,
    pub(crate) settings: Option<Settings>,
    /// SETTINGS arrived during the last call.
    pub(crate) new_settings: bool,
    encoder_seen: bool,
    decoder_seen: bool,
    pub(crate) dec: DecTable,
    /// Our decoder stream (when our table capacity is not 0).
    pub(crate) dec_stream: Option<StreamId>,
    /// Streams waiting for inserts, and how many may.
    pub(crate) blocked: usize,
    pub(crate) max_blocked: usize,
    pub(crate) enc: Option<Arc<EncShared>>,
    enc_capacity: u64,
    /// The table got inserts during the last call: blocked streams may go on.
    pub(crate) inserted: bool,
}

impl Peer {
    pub(crate) fn new(cfg: &H3Config) -> Peer {
        Peer {
            ctrl: None,
            settings: None,
            new_settings: false,
            encoder_seen: false,
            decoder_seen: false,
            dec: DecTable::new(cfg.qpack_max_table_capacity as u64),
            dec_stream: None,
            blocked: 0,
            max_blocked: cfg.qpack_blocked_streams,
            enc: None,
            enc_capacity: cfg.qpack_encoder_capacity as u64,
            inserted: false,
        }
    }

    /// Opens our control stream (with `preamble`) and, when our decoder has a table, our
    /// decoder stream.
    pub(crate) fn open(&mut self, c: &Connection, preamble: Vec<u8>) {
        if let Some(id) = c.open_uni() {
            let _ = c.send(id, preamble);
        }
        if self.dec.max_capacity() > 0 {
            if let Some(id) = c.open_uni() {
                let _ = c.send(id, vec![frame::STREAM_QPACK_DECODER as u8]);
                self.dec_stream = Some(id);
            }
        }
    }

    /// Acts on what the last stream data did: starts our encoder once the peer's SETTINGS
    /// allow it, and sends what our decoder has to say.
    pub(crate) fn after(&mut self, c: &Connection) {
        if std::mem::take(&mut self.new_settings) {
            let s = self.settings.unwrap_or_default();
            let max = s.qpack_max_table_capacity;
            if self.enc_capacity > 0 && max > 0 {
                if let Some(id) = c.open_uni() {
                    let mut e = Encoder::new(self.enc_capacity, max, s.qpack_blocked_streams);
                    let mut first = vec![frame::STREAM_QPACK_ENCODER as u8];
                    first.append(&mut e.out);
                    let _ = c.send(id, first);
                    self.enc = Some(Arc::new(EncShared::new(c.clone(), id, e)));
                }
            }
        }
        self.flush(c);
    }

    /// Sends our decoder stream's pending instructions.
    pub(crate) fn flush(&mut self, c: &Connection) {
        if !self.dec.out.is_empty() {
            let out = std::mem::take(&mut self.dec.out);
            if let Some(id) = self.dec_stream {
                let _ = c.send(id, out);
            }
        }
    }
}

/// Feeds a peer's unidirectional stream; `Err(code)` is a connection error. Shared by both
/// sides (`server` refuses push streams, which only a server may open). `stop` asks the peer to
/// stop sending on a stream (`STOP_SENDING`).
pub(crate) fn on_uni(
    u: &mut Uni,
    peer: &mut Peer,
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
                if peer.ctrl.is_some() {
                    return Err(code::STREAM_CREATION_ERROR);
                }
                peer.ctrl = Some(id);
                Uni::Control {
                    r: Reader::default(),
                    settings: false,
                }
            }
            frame::STREAM_QPACK_ENCODER => {
                if std::mem::replace(&mut peer.encoder_seen, true) {
                    return Err(code::STREAM_CREATION_ERROR);
                }
                Uni::Encoder(Vec::new())
            }
            frame::STREAM_QPACK_DECODER => {
                if std::mem::replace(&mut peer.decoder_seen, true) {
                    return Err(code::STREAM_CREATION_ERROR);
                }
                Uni::Decoder(Vec::new())
            }
            frame::STREAM_PUSH if server => return Err(code::STREAM_CREATION_ERROR),
            _ => {
                stop(id, code::STREAM_CREATION_ERROR);
                Uni::Skip
            }
        };
        return on_uni(u, peer, stop, id, &rest, fin, server);
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
                    peer.settings = Some(check_settings(&p)?);
                    peer.new_settings = true;
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
        Uni::Encoder(buf) => {
            let before = peer.dec.inserted();
            let n = if buf.is_empty() {
                let n = peer.dec.on_encoder_stream(data)?;
                buf.extend_from_slice(&data[n..]);
                n
            } else {
                buf.extend_from_slice(data);
                let n = peer.dec.on_encoder_stream(buf)?;
                buf.drain(..n);
                n
            };
            if n > 0 && peer.dec.inserted() != before {
                peer.inserted = true;
            }
            if fin {
                return Err(code::CLOSED_CRITICAL_STREAM);
            }
        }
        Uni::Decoder(buf) => {
            buf.extend_from_slice(data);
            let n = match &peer.enc {
                Some(e) => {
                    e.e.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .on_decoder_stream(buf)?
                }
                // No encoder: only cancellations can come (acknowledgements and increments
                // of a table we never filled are errors).
                None => Encoder::new(0, 0, 0).on_decoder_stream(buf)?,
            };
            buf.drain(..n);
            if fin {
                return Err(code::CLOSED_CRITICAL_STREAM);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Where a streamed request body goes.
pub(crate) enum Body {
    /// Nowhere (the fuzz harness).
    #[cfg_attr(not(any(test, feature = "fuzzing")), allow(dead_code))]
    Discard,
    /// The service's `Context::on_body` sink.
    Started(Started),
    /// A WebSocket over HTTP/3 (RFC 9220), boxed to keep every request's state small.
    Ws(Box<WsSession>),
}

/// What reading a request stream calls out to: whether a body streams, and dispatching a
/// request before its body.
pub(crate) trait Host {
    /// Whether the service takes `req`'s body as a stream.
    fn streams(&self, req: &Request) -> bool;
    /// Dispatches `req` now; its body follows to the returned sink.
    fn start(&mut self, req: Request, head_only: bool) -> Body;
}

/// A HEADERS frame waiting for QPACK inserts, and what the stream carried after it.
pub(crate) struct Blocked {
    pub(crate) ric: u64,
    pub(crate) section: Vec<u8>,
    /// The frames after it, re-encoded (DATA pieces as DATA frames).
    pub(crate) rest: Vec<u8>,
    pub(crate) fin: bool,
}

#[derive(Default)]
pub(crate) struct Req {
    r: StreamReader,
    /// The request from the first HEADERS frame (`Err` if malformed, answered once the stream
    /// ends) and whether it is a HEAD request.
    head: Option<Result<(Request, bool), ()>>,
    body: Vec<u8>,
    trailers: Option<Result<Headers, ()>>,
    done: bool,
    /// The request was dispatched with its head: its body goes to `sink` as it arrives.
    sink: Option<Body>,
    /// Body bytes so far (streamed) and the announced length.
    len: u64,
    content_length: Option<u64>,
    /// Whether `Host::streams` was asked.
    decided: bool,
    blocked: Option<Box<Blocked>>,
}

impl Req {
    /// Ends a dispatched request: the body is complete (`Ok`, its trailers) or it never will be.
    fn finish_sink(&mut self, ok: Option<&Headers>) {
        match (self.sink.take(), ok) {
            (Some(Body::Started(s)), Some(t)) => s.end(t),
            (Some(Body::Started(s)), None) => s.abort(),
            (Some(Body::Ws(mut w)), _) => w.on_transport_closed(),
            _ => {}
        }
    }
}

struct ServerConn<S> {
    svc: Arc<S>,
    cfg: Arc<H3Config>,
    peer: SocketAddr,
    conn: Peer,
    uni: StreamMap<Uni>,
    reqs: StreamMap<Req>,
    /// Field sections are decoded here, then copied once into the request's `Headers`.
    fields: FieldBuf,
    /// Where responses go (and those waiting for room in their stream's send buffer), shared by
    /// the connection's requests.
    out: H3Out,
    /// `out` as the connection's response sink, shared by its requests.
    sink: SharedSink,
    /// The connection span (`akio_http::trace`), ended on close.
    span: akio::log::span::Span,
    /// The client's verified certificate chain, once the handshake is done.
    certs: PeerCerts,
}

/// A connection's verified client certificate chain (`Request::peer_certificates`), asked of
/// the QUIC connection until its handshake is done, then kept: each request clones an `Arc`.
type PeerCerts = std::sync::OnceLock<Option<Arc<[Vec<u8>]>>>;

/// The chain of `c`'s client, for a request; `None` before the handshake is done (a request
/// sent in 0-RTT comes before the client's certificate).
fn peer_certs(certs: &PeerCerts, c: &Connection) -> Option<Arc<[Vec<u8>]>> {
    if let Some(v) = certs.get() {
        return v.clone();
    }
    let chain = c.peer_certificates()?;
    certs
        .get_or_init(|| (!chain.is_empty()).then(|| chain.into()))
        .clone()
}

/// Why a request stream stopped being read.
pub(crate) enum Fail {
    Conn(u32),
    Stream(u32),
    Status(u16),
}

/// [`Host`] for a server stream.
struct ServerHost<'a, S> {
    svc: &'a S,
    c: &'a Connection,
    id: StreamId,
    sink: &'a SharedSink,
    certs: &'a PeerCerts,
}

impl<S: Service> Host for ServerHost<'_, S> {
    fn streams(&self, req: &Request) -> bool {
        self.svc.body_mode(req) == akio_http::BodyMode::Stream
    }

    fn start(&mut self, mut request: Request, head_only: bool) -> Body {
        request.peer_certificates = peer_certs(self.certs, self.c);
        if self.c.is_early(self.id) {
            request.headers.append("early-data", "1");
        }
        let ws = request.protocol.as_deref() == Some("websocket");
        let mut st =
            akio_http::transport::start_conn(self.svc, request, self.sink, tag(self.id, head_only));
        if ws {
            let link = Arc::new(StreamLink::new(self.c.clone(), self.id));
            if let Some(mut w) = st.take_websocket(link) {
                w.open();
                return Body::Ws(Box::new(w));
            }
        }
        Body::Started(st)
    }
}

/// [`Host`] for a request read without a service (unit tests, fuzzing).
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) struct NoHost(pub(crate) bool);

#[cfg(any(test, feature = "fuzzing"))]
impl Host for NoHost {
    fn streams(&self, _req: &Request) -> bool {
        self.0
    }
    fn start(&mut self, _req: Request, _head_only: bool) -> Body {
        Body::Discard
    }
}

impl<S: Service> ServerConn<S> {
    fn on_req(&mut self, c: &Connection, id: StreamId, data: &[u8], fin: bool) -> Result<(), Fail> {
        // A request that arrives whole (the usual case) is read without entering the table.
        let in_table = !self.reqs.is_empty() && self.reqs.contains_key(&id);
        if fin && !in_table {
            if let Some(res) = self.read_whole(c, id, data) {
                return res;
            }
        }
        let mut whole = Req::default();
        let req = if fin && !in_table {
            &mut whole
        } else {
            self.reqs.entry(id).or_default()
        };
        let mut host = ServerHost {
            svc: &*self.svc,
            c,
            id,
            sink: &self.sink,
            certs: &self.certs,
        };
        let mut q = Qd {
            dec: &mut self.conn.dec,
            blocked: &mut self.conn.blocked,
            max_blocked: self.conn.max_blocked,
            stream: sid(id),
        };
        match read_req(
            req,
            &self.cfg,
            self.peer,
            &mut self.fields,
            &mut q,
            &mut host,
            data,
            fin,
        ) {
            Ok(Some((request, head_only))) => {
                self.dispatch(c, id, request, head_only);
                Ok(())
            }
            res => {
                if whole.blocked.is_some() || whole.sink.is_some() {
                    // Waiting for inserts, or dispatched with a body to come: keep its state.
                    self.reqs.insert(id, whole);
                }
                res.map(|_| ())
            }
        }
    }

    /// Reads a stream that arrived whole as one HEADERS frame and at most one DATA frame (the
    /// usual case) without a [`Req`] or a frame reader. `None` leaves it to [`read_req`]: other
    /// frames, a section that is malformed, too large or blocked, a CONNECT, a body
    /// too large or for a service that streams it.
    #[inline(always)]
    fn read_whole(
        &mut self,
        c: &Connection,
        id: StreamId,
        data: &[u8],
    ) -> Option<Result<(), Fail>> {
        let (section, rest) = frame::frame_at(data, frame::HEADERS)?;
        let body = match rest {
            [] => &[][..],
            _ => match frame::frame_at(rest, frame::DATA)? {
                (b, []) if b.len() <= self.cfg.max_body_bytes => b,
                _ => return None,
            },
        };
        let max_field = self.cfg.max_field_section_bytes;
        let ric =
            qpack::decode_section(section, max_field, &self.conn.dec, &mut self.fields).ok()?;
        let (request, head_only) = request_head(&self.fields, self.peer)?;
        if request.method == Method::Connect
            || (!body.is_empty() && self.svc.body_mode(&request) == akio_http::BodyMode::Stream)
        {
            return None;
        }
        if ric > 0 {
            self.conn.dec.section_ack(sid(id), ric);
        }
        Some(
            match finish_request(Ok((request, head_only)), None, body.to_vec()) {
                Some((request, head_only)) => {
                    self.dispatch(c, id, request, head_only);
                    Ok(())
                }
                None => Err(Fail::Stream(code::MESSAGE_ERROR)),
            },
        )
    }

    #[inline(always)]
    fn dispatch(&self, c: &Connection, id: StreamId, mut request: Request, head_only: bool) {
        request.peer_certificates = peer_certs(&self.certs, c);
        if c.is_early(id) {
            // Arrived in 0-RTT (maybe a replay): marked as an RFC 8470 intermediary would, so
            // the application can answer 425 Too Early to what is not safe to repeat.
            request.headers.append("early-data", "1");
        }
        let tag = tag(id, head_only);
        if self.cfg.handlers_on_logical_pool {
            return akio_http::transport::dispatch_conn_on_pool(
                &self.svc, request, &self.sink, tag,
            );
        }
        akio_http::transport::dispatch_conn(&*self.svc, request, &self.sink, tag);
    }

    /// Streams whose field sections the last inserts made decodable go on.
    fn unblock(&mut self, c: &Connection) {
        if !std::mem::take(&mut self.conn.inserted) || self.conn.blocked == 0 {
            return;
        }
        let have = self.conn.dec.inserted();
        let ready: Vec<StreamId> = self
            .reqs
            .iter()
            .filter(|(_, r)| r.blocked.as_ref().is_some_and(|b| b.ric <= have))
            .map(|(&id, _)| id)
            .collect();
        for id in ready {
            let res = self.replay(c, id);
            self.after_req(c, id, res, false);
        }
    }

    /// Reads a stream's blocked section again, then the frames held back behind it.
    fn replay(&mut self, c: &Connection, id: StreamId) -> Result<(), Fail> {
        let Some(req) = self.reqs.get_mut(&id) else {
            return Ok(());
        };
        let Some(b) = req.blocked.take() else {
            return Ok(());
        };
        self.conn.blocked -= 1;
        let mut data = Vec::with_capacity(b.section.len() + b.rest.len() + 9);
        frame::put_frame(&mut data, frame::HEADERS, &b.section);
        data.extend_from_slice(&b.rest);
        // The held-back frames come before whatever the stream's reader still holds.
        let held = std::mem::take(&mut req.r);
        let mut host = ServerHost {
            svc: &*self.svc,
            c,
            id,
            sink: &self.sink,
            certs: &self.certs,
        };
        let mut q = Qd {
            dec: &mut self.conn.dec,
            blocked: &mut self.conn.blocked,
            max_blocked: self.conn.max_blocked,
            stream: sid(id),
        };
        let res = read_req(
            req,
            &self.cfg,
            self.peer,
            &mut self.fields,
            &mut q,
            &mut host,
            &data,
            false,
        );
        req.r = held;
        res?;
        if b.fin {
            if let Some(blocked) = req.blocked.as_mut() {
                blocked.fin = true;
                return Ok(());
            }
            let res = read_req(
                req,
                &self.cfg,
                self.peer,
                &mut self.fields,
                &mut q,
                &mut host,
                &[],
                true,
            );
            if let Some((request, head_only)) = res? {
                self.dispatch(c, id, request, head_only);
            }
            self.reqs.remove(&id);
        }
        Ok(())
    }

    /// Acts on the outcome of reading a request stream.
    fn after_req(&mut self, c: &Connection, id: StreamId, res: Result<(), Fail>, fin: bool) {
        match res {
            Ok(()) => {}
            Err(Fail::Conn(e)) => c.close(e, b""),
            Err(Fail::Stream(e)) => {
                if let Some(mut r) = self.reqs.remove(&id) {
                    self.forget(id, &mut r);
                }
                let _ = c.stop(id, e);
                let _ = c.reset(id, e);
            }
            Err(Fail::Status(s)) => {
                if let Some(r) = self.reqs.get_mut(&id) {
                    if r.sink.is_some() {
                        // Already dispatched: the handler may have answered.
                        return self.after_req(c, id, Err(Fail::Stream(code::MESSAGE_ERROR)), fin);
                    }
                    r.done = true;
                    r.body = Vec::new();
                }
                let _ = c.stop(id, code::NO_ERROR);
                let msg = if s == 413 {
                    "request body too large"
                } else {
                    "request header fields too large"
                };
                Sink {
                    o: &self.out,
                    id,
                    head_only: false,
                }
                .send(Response::text(s, msg));
            }
        }
        if fin && !self.reqs.is_empty() {
            if let Some(r) = self.reqs.get(&id) {
                // Still waiting for inserts, its end noted: kept until it can be read.
                if r.blocked.is_some() {
                    return;
                }
            }
            self.reqs.remove(&id);
        }
    }

    /// A request stream that will not be read further: its sink hears nothing more and a
    /// blocked section is cancelled.
    fn forget(&mut self, id: StreamId, r: &mut Req) {
        if r.blocked.take().is_some() {
            self.conn.blocked -= 1;
            self.conn.dec.cancel(sid(id));
        }
        r.finish_sink(None);
    }
}

/// QPACK decoding context for one request stream.
pub(crate) struct Qd<'a> {
    pub(crate) dec: &'a mut DecTable,
    pub(crate) blocked: &'a mut usize,
    pub(crate) max_blocked: usize,
    pub(crate) stream: u64,
}

/// Reads a request stream's bytes; the request once the stream has ended (`fin`), unless
/// `host` took it at its head (a streamed body, an extended CONNECT). Frames are read in place
/// and field sections decoded into `fields`, so a request that arrives whole costs no copy
/// before its `Headers` are built; DATA payloads are never buffered by the reader.
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_req(
    req: &mut Req,
    cfg: &H3Config,
    peer: SocketAddr,
    fields: &mut FieldBuf,
    q: &mut Qd<'_>,
    host: &mut dyn Host,
    data: &[u8],
    fin: bool,
) -> Result<Option<(Request, bool)>, Fail> {
    let max_field = cfg.max_field_section_bytes;
    if req.done {
        return Ok(None);
    }
    let Req {
        r,
        head,
        body,
        trailers,
        sink,
        len,
        content_length,
        blocked,
        decided,
        ..
    } = req;
    let mut on_piece = |piece: Piece<'_>| -> Result<(), Fail> {
        if let Some(b) = blocked.as_mut() {
            // Held back, in order, until the section before them can be decoded.
            match piece {
                Piece::Headers(p) => frame::put_frame(&mut b.rest, frame::HEADERS, p),
                Piece::Data(p) => frame::put_frame(&mut b.rest, frame::DATA, p),
                Piece::Skip(t) => check_request_frame(t)?,
            }
            return Ok(());
        }
        match piece {
            Piece::Headers(p) => {
                let ric = match qpack::decode_section(p, max_field, q.dec, fields) {
                    Ok(ric) => ric,
                    Err(SectionError::Blocked(ric)) => {
                        if *q.blocked >= q.max_blocked {
                            return Err(Fail::Conn(code::QPACK_DECOMPRESSION_FAILED));
                        }
                        *q.blocked += 1;
                        *blocked = Some(Box::new(Blocked {
                            ric,
                            section: p.to_vec(),
                            rest: Vec::new(),
                            fin: false,
                        }));
                        return Ok(());
                    }
                    Err(SectionError::Bad(QpackError::TooLarge)) => {
                        return Err(Fail::Status(431));
                    }
                    Err(SectionError::Bad(_)) => {
                        return Err(Fail::Conn(code::QPACK_DECOMPRESSION_FAILED));
                    }
                };
                if ric > 0 {
                    q.dec.section_ack(q.stream, ric);
                }
                if head.is_none() {
                    match request_head(fields, peer) {
                        Some((request, head_only)) => {
                            if request.method == Method::Connect {
                                // A CONNECT (RFC 9114 §4.4, A134) or an extended CONNECT:
                                // dispatched now, the stream's bytes follow to the sink.
                                *content_length = sink_length(&request)?;
                                *sink = Some(host.start(request, head_only));
                                *head = Some(Err(()));
                            } else {
                                *head = Some(Ok((request, head_only)));
                            }
                        }
                        None => *head = Some(Err(())),
                    }
                } else if trailers.is_none() {
                    let mut t = Headers::with_capacity(fields.len(), fields.bytes());
                    let ok = fields.strs().and_then(|f| header_list(f, &mut t));
                    *trailers = Some(ok.map(|()| t).ok_or(()));
                } else {
                    return Err(Fail::Conn(code::FRAME_UNEXPECTED));
                }
            }
            Piece::Data(p) => {
                if head.is_none() || trailers.is_some() {
                    return Err(Fail::Conn(code::FRAME_UNEXPECTED));
                }
                *len += p.len() as u64;
                if sink.is_none() && !*decided {
                    // The body's first bytes: does the service take it as a stream? (Asked
                    // only now, so requests without a body never ask.)
                    *decided = true;
                    if matches!(head, Some(Ok((r, _))) if host.streams(r)) {
                        if let Some(Ok((request, head_only))) = head.take() {
                            *content_length = sink_length(&request)?;
                            *sink = Some(host.start(request, head_only));
                            *head = Some(Err(()));
                        }
                    }
                }
                if content_length.is_some_and(|cl| *len > cl) {
                    return Err(Fail::Stream(code::MESSAGE_ERROR));
                }
                match sink {
                    Some(Body::Started(s)) => s.body(p),
                    Some(Body::Ws(w)) => w.on_data(p),
                    Some(Body::Discard) => {}
                    None => {
                        if body.len() + p.len() > cfg.max_body_bytes {
                            return Err(Fail::Status(413));
                        }
                        body.extend_from_slice(p);
                    }
                }
            }
            Piece::Skip(t) => check_request_frame(t)?,
        }
        Ok(())
    };
    if fin && r.idle() {
        // The whole request is here (the usual case): frames read in place, no streaming.
        r.feed(
            data,
            data.len() as u64,
            || Fail::Status(413),
            |ty, p| match ty {
                frame::HEADERS => on_piece(Piece::Headers(p)),
                frame::DATA if p.is_empty() => Ok(()),
                frame::DATA => on_piece(Piece::Data(p)),
                t => on_piece(Piece::Skip(t)),
            },
        )?;
    } else {
        r.feed_stream(data, max_field as u64, || Fail::Status(431), on_piece)?;
    }
    if !fin {
        return Ok(None);
    }
    if let Some(b) = req.blocked.as_mut() {
        b.fin = true;
        return Ok(None);
    }
    req.done = true;
    if req.sink.is_some() {
        if req.content_length.is_some_and(|cl| cl != req.len)
            || matches!(req.trailers, Some(Err(())))
        {
            req.finish_sink(None);
            return Err(Fail::Stream(code::MESSAGE_ERROR));
        }
        let t = match req.trailers.take() {
            Some(Ok(t)) => t,
            _ => Headers::new(),
        };
        req.finish_sink(Some(&t));
        return Ok(None);
    }
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

/// The `content-length` of a request whose body goes to a sink (checked as it streams; a
/// buffered body is checked whole by `finish_request`).
fn sink_length(r: &Request) -> Result<Option<u64>, Fail> {
    match r.headers.get("content-length") {
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| Fail::Stream(code::MESSAGE_ERROR)),
        None => Ok(None),
    }
}

/// Frames that may not appear on a request stream.
fn check_request_frame(ty: u64) -> Result<(), Fail> {
    match ty {
        frame::SETTINGS
        | frame::GOAWAY
        | frame::MAX_PUSH_ID
        | frame::CANCEL_PUSH
        | frame::PUSH_PROMISE => Err(Fail::Conn(code::FRAME_UNEXPECTED)),
        t if h2_only(t) => Err(Fail::Conn(code::FRAME_UNEXPECTED)),
        _ => Ok(()),
    }
}

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

/// Appends regular fields to `out`; `None` if one is malformed (a pseudo-header, a name with an
/// uppercase letter or a byte no token holds, a connection-specific name, a value with a NUL, CR
/// or LF, `te` other than `trailers`, not UTF-8).
fn header_list<'a>(
    fields: impl Iterator<Item = (&'a str, &'a str)>,
    out: &mut Headers,
) -> Option<()> {
    for (n, v) in fields {
        // RFC 9114 §4.2 (and RFC 9113 §8.2.1, which it follows): a name with a byte in
        // 0x00-0x20, 0x41-0x5A (uppercase), 0x7F-0xFF or a colon, or a value with a NUL, CR or
        // LF, is malformed; an HTTP/1.1 hop behind this server would read it differently.
        if n.is_empty()
            || !n
                .bytes()
                .all(|b| matches!(b, 0x21..=0x40 | 0x5b..=0x7e) && b != b':')
            || v.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n'))
        {
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
/// §4.1.2, and RFC 9220 / RFC 8441 §4 for an extended CONNECT).
fn request_head(fields: &FieldBuf, peer: SocketAddr) -> Option<(Request, bool)> {
    let (mut method, mut scheme, mut authority, mut path, mut protocol) =
        (None, None, None, None, None);
    // One pass (and one UTF-8 check): pseudo-header fields come first; one after a regular
    // field is refused by `header_list`.
    let mut fs = fields.strs()?.peekable();
    while let Some((n, v)) = fs.next_if(|(n, _)| n.starts_with(':')) {
        if v.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
            return None;
        }
        let slot = match n {
            ":method" => &mut method,
            ":scheme" => &mut scheme,
            ":authority" => &mut authority,
            ":path" => &mut path,
            ":protocol" => &mut protocol,
            _ => return None,
        };
        if slot.replace(v).is_some() {
            return None;
        }
    }
    let method = Method::parse(method?);
    if protocol.is_some() {
        // Extended CONNECT: every pseudo-header field.
        if method != Method::Connect
            || scheme.is_none()
            || path.is_none_or(str::is_empty)
            || authority.is_none()
        {
            return None;
        }
    } else if method == Method::Connect {
        if scheme.is_some() || path.is_some() || authority.is_none() {
            return None;
        }
    } else if scheme.is_none() || path.is_none_or(str::is_empty) {
        return None;
    }
    // Room for `host` too; a request with few fields keeps their positions inline.
    let mut headers =
        akio_http::transport::request_headers(fields.regular() + 1, fields.bytes() + 4);
    header_list(fs, &mut headers)?;
    if let Some(a) = authority {
        if headers.get("host").is_none() {
            headers.append("host", a);
        }
    }
    let head_only = method == Method::Head;
    let target = path.or(authority).unwrap_or_default();
    let mut r = Request::new(method, akio_http::transport::request_target(target));
    r.version = Version::Http3;
    r.headers = headers;
    r.peer = peer;
    r.protocol = protocol.map(str::to_owned);
    Some((r, head_only))
}

/// The request once its stream has ended; `None` if malformed (bad fields or trailers, or a
/// `content-length` that is not the body's).
#[inline(always)]
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
        self.conn.open(c, control_stream_preamble(&self.cfg, true));
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
                if let Err(e) = on_uni(u, &mut self.conn, &mut stop, id, &data, fin, true) {
                    c.close(e, b"");
                    return;
                }
                self.unblock(c);
                self.conn.dec.increment();
                self.conn.after(c);
                if self.conn.enc.is_some() && self.out.enc.is_none() {
                    // Our encoder started: responses from now on may use its table.
                    self.out.enc = self.conn.enc.clone();
                    self.sink = SharedSink::new(self.out.clone());
                }
            }
            return;
        }
        match self.on_req(c, id, &data, fin) {
            // The usual case: nothing left to clean up.
            Ok(()) if !fin || self.reqs.is_empty() => {}
            res => self.after_req(c, id, res, fin),
        }
        self.conn.flush(c);
    }

    fn on_stream_reset(&mut self, c: &Connection, id: StreamId, _code: u64) {
        // The client gave up the request (`Context::on_gone`).
        self.out.gones.run(id);
        if let Some(mut r) = self.reqs.remove(&id) {
            self.forget(id, &mut r);
            self.conn.flush(c);
        }
    }

    fn on_stream_stopped(&mut self, _c: &Connection, id: StreamId, _code: u64) {
        // The response is not wanted any more: what waits for it is dropped.
        lock(&self.out.outs).remove(&id);
        run_drain(&self.out.drains, id);
        self.out.gones.run(id);
    }

    fn on_stream_writable(&mut self, c: &Connection, id: StreamId) {
        pump(c, &self.out.outs, id);
        run_drain(&self.out.drains, id);
    }

    fn on_close(&mut self, _c: &Connection, reason: ConnectionError) {
        for (_, mut r) in self.reqs.drain() {
            r.finish_sink(None);
        }
        self.uni.clear();
        lock(&self.out.outs).clear();
        let drains: Vec<_> = lock(&self.out.drains).drain().map(|(_, f)| f).collect();
        for f in drains {
            f();
        }
        let gones: Vec<_> = lock(&self.out.gones.map).drain().map(|(_, f)| f).collect();
        for f in gones {
            f();
        }
        if self.span.is_recording() {
            self.span.record("quic.close_reason", format!("{reason:?}"));
            drop(std::mem::take(&mut self.span));
        }
    }
}

/// A request stream carrying a WebSocket (RFC 9220): frames go out in DATA frames, closing
/// ends the stream.
pub(crate) struct StreamLink {
    c: Connection,
    id: StreamId,
    done: AtomicBool,
}

impl StreamLink {
    pub(crate) fn new(c: Connection, id: StreamId) -> StreamLink {
        StreamLink {
            c,
            id,
            done: AtomicBool::new(false),
        }
    }

    fn end(&self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            // Under the sender's lock too (see `send`).
            let _ = self.c.without_driving(|| self.c.finish(self.id));
        }
    }
}

impl WsLink for StreamLink {
    fn send(&self, data: Vec<u8>) -> akio_core::Result<()> {
        if !self.is_open() {
            return Err(akio_core::Error::Closed);
        }
        // The WebSocket's sender calls this holding its lock, which the handler takes too (to
        // answer a ping, or in the application's callbacks): not driven here.
        self.c
            .without_driving(|| self.c.send(self.id, data_frame(&data)))
            .map_err(|e| match e {
                akio_quic::Error::Overloaded => akio_core::Error::Overloaded,
                _ => akio_core::Error::Closed,
            })
    }

    fn close_after_send(&self) {
        self.end();
    }

    fn close(&self) {
        self.end();
    }

    fn is_open(&self) -> bool {
        !self.done.load(Ordering::Acquire) && !self.c.is_closed()
    }

    fn queued_bytes(&self) -> usize {
        self.c.queued_bytes(self.id)
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
    /// The current second, its `date` value and that value's field line, encoded.
    static DATE: RefCell<(u64, String, Vec<u8>)> =
        const { RefCell::new((0, String::new(), Vec::new())) };
}

/// Calls `f` with the `date` value of the current second and its literal field line (made
/// once a second per thread).
fn with_date<R>(f: impl FnOnce(&[u8], &[u8]) -> R) -> R {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    DATE.with(|c| {
        let mut c = c.borrow_mut();
        let (at, value, line) = &mut *c;
        if *at != secs || line.is_empty() {
            *at = secs;
            *value = akio_http::message::http_date_now();
            line.clear();
            qpack::encode_line(line, b"date", value.as_bytes());
        }
        f(value.as_bytes(), line)
    })
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
/// have none, then `content-length` when given and the headers have none. With `enc` (the
/// connection's QPACK encoder and the stream), fields may be dynamic table references.
pub(crate) fn put_head(
    out: &mut Vec<u8>,
    status: Option<u16>,
    pseudo: &[(&[u8], &[u8])],
    headers: &Headers,
    add_date: bool,
    content_length: Option<u64>,
    enc: Option<(&EncShared, StreamId)>,
) {
    let at = frame::begin_frame(out, frame::HEADERS);
    match enc {
        None => {
            out.extend_from_slice(&qpack::PREFIX);
            head_lines(
                out,
                status,
                pseudo,
                headers,
                add_date,
                content_length,
                false,
                &mut |o, n, v| qpack::encode_line(o, n, v),
            );
        }
        Some((e, id)) => e.section(out, id, |e, lines, sec| {
            head_lines(
                lines,
                status,
                pseudo,
                headers,
                add_date,
                content_length,
                true,
                &mut |o, n, v| e.line(o, sec, n, v),
            );
        }),
    }
    frame::end_frame(out, at);
}

/// The field lines of [`put_head`], each through `line` except the ones with a fast path (the
/// added `date` too, unless `dynamic`: then it goes through `line`, which may reference it).
#[allow(clippy::too_many_arguments)]
fn head_lines<F: FnMut(&mut Vec<u8>, &[u8], &[u8])>(
    out: &mut Vec<u8>,
    status: Option<u16>,
    pseudo: &[(&[u8], &[u8])],
    headers: &Headers,
    add_date: bool,
    content_length: Option<u64>,
    dynamic: bool,
    line: &mut F,
) {
    if let Some(s) = status {
        qpack::encode_status(out, s);
    }
    for &(n, v) in pseudo {
        line(out, n, v);
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
                line(out, n, &v);
            } else {
                line(out, n, v.as_bytes());
            }
        });
    }
    if add_date && !has_date {
        with_date(|value, literal| {
            if dynamic {
                line(out, b"date", value);
            } else {
                out.extend_from_slice(literal);
            }
        });
    }
    if let (Some(len), false) = (content_length, has_len) {
        qpack::encode_content_length(out, len);
    }
}

pub(crate) fn data_frame(data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(data.len() + 9);
    frame::put_frame(&mut f, frame::DATA, data);
    f
}

/// Bodies up to this size are copied behind the response head and sent with it; larger ones
/// are handed to QUIC as they are, after a DATA frame header.
const COPY_BODY_MAX: usize = 16 << 10;

/// Messages whose body is at most this size are written into a buffer from akio-quic's
/// per-thread pool ([`Bytes::pooled`]): no allocation per message once the pool is warm. The
/// bound keeps pooled buffers small.
pub(crate) const POOLED_BODY_MAX: usize = 2 << 10;

/// File bodies are read this much at a time, on the engine's logical pool, each piece once the
/// stream's send buffer has room for more (so a client that grants no flow-control credit holds
/// at most `TransportConfig::stream_send_buffer` plus one piece of a file in memory).
const FILE_CHUNK: usize = 256 << 10;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What waits to be sent on response streams of a connection, by stream.
type Outs = Mutex<StreamMap<Out>>;

/// Drain waiters per stream (`BodySink::on_drain`), run once the stream's send buffer has room.
type Drains = Mutex<StreamMap<Box<dyn FnOnce() + Send>>>;

/// What runs if a request's client goes before its response is finished
/// (`ConnSink::on_gone`, ADR-108), by stream.
#[derive(Default)]
struct Gones {
    /// Some were ever registered: responses check the map only then.
    any: AtomicBool,
    map: Drains,
}

impl Gones {
    /// The response of stream `id` is finished: its callback is dropped unrun.
    #[inline]
    fn forget(&self, id: StreamId) {
        if self.any.load(Ordering::Acquire) {
            let f = lock(&self.map).remove(&id);
            drop(f);
        }
    }

    /// The client went: runs the callback of stream `id`, if any (outside the lock).
    fn run(&self, id: StreamId) {
        if self.any.load(Ordering::Acquire) {
            run_drain(&self.map, id);
        }
    }
}

/// Runs the drain waiter of stream `id`, if any (outside the lock).
fn run_drain(drains: &Drains, id: StreamId) {
    let f = lock(drains).remove(&id);
    if let Some(f) = f {
        f();
    }
}

/// The rest of a response the stream's send buffer could not take yet, in order: bytes, then
/// a file's range, then the trailers, then the end of the stream.
#[derive(Default)]
struct Out {
    chunks: VecDeque<Bytes>,
    /// Bytes in `chunks`.
    bytes: usize,
    file: Option<FileOut>,
    tail: Option<Bytes>,
    finish: bool,
    /// A pump runs (or a file read is in flight): others leave the work to it.
    busy: bool,
    /// The stream became writable while the pump ran: it tries again before stopping.
    again: bool,
}

struct FileOut {
    file: Arc<std::fs::File>,
    off: u64,
    end: u64,
}

impl Out {
    fn push(&mut self, b: Bytes) {
        if !b.is_empty() {
            self.bytes += b.len();
            self.chunks.push_back(b);
        }
    }
}

/// The next thing a pump does.
enum Step {
    Send(Bytes),
    Read(Arc<std::fs::File>, u64, usize),
    End(bool),
    Gone,
}

/// Sends what waits on stream `id` as the send buffer takes it; runs on any thread, one pump
/// per stream at a time. No lock is held while calling into the connection (whose handler may
/// run from inside `send` and pump again).
fn pump(c: &Connection, outs: &Arc<Outs>, id: StreamId) {
    {
        let mut m = lock(outs);
        let Some(o) = m.get_mut(&id) else { return };
        if o.busy {
            o.again = true;
            return;
        }
        o.busy = true;
    }
    run(c, outs, id);
}

/// The pump's loop (the stream's `busy` is held).
fn run(c: &Connection, outs: &Arc<Outs>, id: StreamId) {
    loop {
        let step = {
            let mut m = lock(outs);
            match m.get_mut(&id) {
                None => Step::Gone,
                Some(o) => {
                    if let Some(b) = o.chunks.pop_front() {
                        o.bytes -= b.len();
                        Step::Send(b)
                    } else if let Some(f) = o.file.as_ref().filter(|f| f.off < f.end) {
                        let n = ((f.end - f.off) as usize).min(FILE_CHUNK);
                        Step::Read(f.file.clone(), f.off, n)
                    } else if let Some(t) = o.tail.take() {
                        Step::Send(t)
                    } else {
                        let fin = o.finish;
                        m.remove(&id);
                        Step::End(fin)
                    }
                }
            }
        };
        match step {
            Step::Gone => return,
            Step::End(fin) => {
                if fin {
                    let _ = c.finish(id);
                }
                return;
            }
            Step::Send(b) => match c.send(id, b.clone()) {
                Ok(()) => {}
                Err(akio_quic::Error::Overloaded) => {
                    if let Some(o) = lock(outs).get_mut(&id) {
                        o.bytes += b.len();
                        o.chunks.push_front(b);
                    }
                    if park(outs, id) {
                        return;
                    }
                }
                Err(_) => {
                    lock(outs).remove(&id);
                    return;
                }
            },
            Step::Read(file, off, n) => {
                match c.send_capacity(id) {
                    Ok(0) => {
                        if park(outs, id) {
                            return;
                        }
                        continue;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        lock(outs).remove(&id);
                        return;
                    }
                }
                // Off the I/O thread; the read's completion goes on pumping from the pool.
                return read_on_pool(
                    FileRead {
                        c: c.clone(),
                        outs: outs.clone(),
                        id,
                        file,
                        off,
                        n,
                    },
                    0,
                );
            }
        }
    }
}

/// How long the pump waits before asking a full pool again for a file read, and how many
/// times: past that (a second of a pool that stays full), the stream is reset. As
/// `akio-http`'s file pump does.
const READ_RETRY: std::time::Duration = std::time::Duration::from_millis(5);
const READ_RETRIES: u32 = 200;

/// A piece of a file to read for a stream whose pump is parked on it (its `busy` held).
struct FileRead {
    c: Connection,
    outs: Arc<Outs>,
    id: StreamId,
    file: Arc<std::fs::File>,
    off: u64,
    n: usize,
}

/// Reads the piece on the logical pool, then goes on pumping from there. A full pool is asked
/// again a little later from the HTTP layer's timer thread: the read never happens on the
/// thread that found the pool full, which may be the connection's I/O thread (rule 1).
fn read_on_pool(r: FileRead, refused: u32) {
    let c = r.c.clone();
    let cell = Arc::new(Mutex::new(Some(r)));
    let job_cell = cell.clone();
    let queued = c.spawn_blocking(move || {
        let r = lock(&job_cell).take();
        if let Some(r) = r {
            let got = read_chunk(&r.file, r.off, r.n);
            if read_done(&r.c, &r.outs, r.id, got) {
                run(&r.c, &r.outs, r.id);
            }
        }
    });
    let Err(e) = queued else { return };
    let Some(r) = lock(&cell).take() else { return };
    match e {
        akio_quic::Error::Overloaded if refused < READ_RETRIES => {
            #[cfg(test)]
            READS_REFUSED.fetch_add(1, Ordering::Relaxed);
            akio_http::transport::after(READ_RETRY, move || read_on_pool(r, refused + 1));
        }
        _ => {
            // The connection is gone, or the pool stayed full: the response cannot go on.
            lock(&r.outs).remove(&r.id);
            let _ = r.c.reset(r.id, code::INTERNAL_ERROR);
        }
    }
}

/// File reads the pool refused, asked again later (tests).
#[cfg(test)]
static READS_REFUSED: AtomicUsize = AtomicUsize::new(0);

/// File bytes read off the logical pool (tests): there should be none.
#[cfg(test)]
static FILE_READ_OFF_POOL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// File bytes read for responses (tests).
#[cfg(test)]
static FILE_READ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn read_chunk(file: &std::fs::File, off: u64, n: usize) -> std::io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; n];
    let got = file.read_at(&mut buf, off)?;
    #[cfg(test)]
    {
        FILE_READ.fetch_add(got as u64, Ordering::Relaxed);
        if std::thread::current().name() != Some("akio-pool") {
            FILE_READ_OFF_POOL.fetch_add(got as u64, Ordering::Relaxed);
        }
    }
    if got == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    buf.truncate(got);
    Ok(buf)
}

/// Queues a piece read from a file as a DATA frame; `false` (and the stream reset) when the
/// read failed (the file shrank or broke: the response cannot be completed), or the stream is
/// gone.
fn read_done(c: &Connection, outs: &Outs, id: StreamId, r: std::io::Result<Vec<u8>>) -> bool {
    let mut m = lock(outs);
    let Some(o) = m.get_mut(&id) else {
        return false;
    };
    match (r, o.file.as_mut()) {
        (Ok(buf), Some(f)) => {
            f.off += buf.len() as u64;
            o.push(Bytes::from(data_frame(&buf)));
            true
        }
        _ => {
            m.remove(&id);
            drop(m);
            let _ = c.reset(id, code::INTERNAL_ERROR);
            false
        }
    }
}

/// The pump stops until the stream is writable; `false` if it already became so (go on).
fn park(outs: &Outs, id: StreamId) -> bool {
    let mut m = lock(outs);
    let Some(o) = m.get_mut(&id) else {
        return true;
    };
    if std::mem::take(&mut o.again) {
        return false;
    }
    o.busy = false;
    true
}

/// Where a server connection's responses go: one per connection, shared by its requests
/// (each tagged with [`tag`]), so answering a request allocates nothing for its way back.
#[derive(Clone)]
struct H3Out {
    c: Connection,
    /// Responses waiting for room in their stream's send buffer.
    outs: Arc<Outs>,
    /// Streamed responses waiting for room to write more (`BodySink::on_drain`).
    drains: Arc<Drains>,
    /// What runs if a request's client goes early (`ConnSink::on_gone`).
    gones: Arc<Gones>,
    /// The connection's QPACK encoder, when it has a dynamic table.
    enc: Option<Arc<EncShared>>,
}

/// A request's [`ConnSink`] tag: its stream's index (request streams are client-initiated
/// bidirectional ones) and whether it is a HEAD request.
#[inline(always)]
fn tag(id: StreamId, head_only: bool) -> u64 {
    debug_assert!(id.initiator() == akio_quic::Side::Client && id.dir() == Dir::Bi);
    // Indexes are below 2^60.
    (id.index() << 1) | u64::from(head_only)
}

impl ConnSink for H3Out {
    #[inline]
    fn send(&self, tag: u64, resp: Response) {
        let s = Sink::of(self, tag);
        self.gones.forget(s.id);
        s.send(resp);
    }

    fn start_stream(&self, tag: u64, resp: Response) -> Option<Box<dyn BodySink>> {
        Sink::of(self, tag).start_stream(resp)
    }

    /// Runs `f` when the client resets the request stream, stops the response, or the
    /// connection closes, unless the response was finished before.
    fn on_gone(&self, tag: u64, f: Box<dyn FnOnce() + Send>) {
        let id = Sink::of(self, tag).id;
        self.gones.any.store(true, Ordering::Release);
        // Registered first: a reset handled on the I/O thread meanwhile finds it.
        lock(&self.gones.map).insert(id, f);
        if self.c.is_closed() || self.c.send_capacity(id).is_err() {
            self.gones.run(id); // gone already
        }
    }

    fn execute(&self, job: akio_core::Job) -> Result<(), akio_core::Job> {
        self.c.execute(job)
    }

    /// Holds the request stream: what arrives stays in its receive buffer and its window is not
    /// extended (`Connection::hold_reads`).
    fn hold_reads(&self, tag: u64, hold: bool) {
        let id = StreamId::new(akio_quic::Side::Client, Dir::Bi, tag >> 1);
        let _ = self.c.hold_reads(id, hold);
    }

    /// Resets the request stream, its response given up before its head went (ADR-128).
    fn reset(&self, tag: u64) {
        let id = Sink::of(self, tag).id;
        let _ = self.c.stop(id, code::INTERNAL_ERROR);
        let _ = self.c.reset(id, code::INTERNAL_ERROR);
    }
}

/// Answers one request stream.
struct Sink<'a> {
    o: &'a H3Out,
    id: StreamId,
    head_only: bool,
}

impl<'a> Sink<'a> {
    #[inline(always)]
    fn of(o: &'a H3Out, tag: u64) -> Sink<'a> {
        Sink {
            o,
            id: StreamId::new(akio_quic::Side::Client, Dir::Bi, tag >> 1),
            head_only: tag & 1 == 1,
        }
    }

    /// Appends the HEADERS frame of `resp` to `out`; whether a body may follow.
    fn head(&self, out: &mut Vec<u8>, resp: &Response, streaming: bool) -> bool {
        let bodyless = resp.status < 200 || resp.status == 204 || resp.status == 304;
        let len = (!bodyless && !streaming).then(|| resp.body_len());
        let enc = self.o.enc.as_deref().map(|e| (e, self.id));
        put_head(out, Some(resp.status), &[], &resp.headers, true, len, enc);
        !(bodyless || self.head_only)
    }

    /// A buffer for the HEADERS frame of `resp` and `extra` more bytes.
    fn head_buf(resp: &Response, extra: usize) -> Vec<u8> {
        Vec::with_capacity(head_hint(&resp.headers) + 64 + extra)
    }

    /// Appends the trailers' HEADERS frame, if any, to `out`.
    fn put_trailers(&self, out: &mut Vec<u8>, trailers: Option<&Headers>) {
        if let Some(t) = trailers.filter(|t| !t.is_empty() && !self.head_only) {
            let enc = self.o.enc.as_deref().map(|e| (e, self.id));
            put_head(out, None, &[], t, false, None, enc);
        }
    }

    /// Sends `out` (if not empty) and ends the stream; when the send buffer is full, both wait
    /// for room.
    fn send_and_finish(&self, out: impl Into<Bytes>) {
        let out = out.into();
        if !out.is_empty() {
            match self.o.c.send(self.id, out.clone()) {
                Ok(()) => {}
                Err(akio_quic::Error::Overloaded) => {
                    let mut o = Out {
                        finish: true,
                        ..Out::default()
                    };
                    o.push(out);
                    return self.queue(o);
                }
                Err(_) => return,
            }
        }
        let _ = self.o.c.finish(self.id);
    }

    /// Hands `o` to the stream's pump (after what already waits there).
    fn queue(&self, o: Out) {
        queue(&self.o.c, &self.o.outs, self.id, o);
    }
}

/// Adds `o` to what waits on stream `id` and pumps.
fn queue(c: &Connection, outs: &Arc<Outs>, id: StreamId, o: Out) {
    {
        let mut m = lock(outs);
        let e = m.entry(id).or_default();
        for b in o.chunks {
            e.push(b);
        }
        if o.file.is_some() {
            e.file = o.file;
        }
        if o.tail.is_some() {
            e.tail = o.tail;
        }
        e.finish |= o.finish;
    }
    pump(c, outs, id);
}

/// Bytes to reserve for encoding `headers`.
pub(crate) fn head_hint(headers: &Headers) -> usize {
    headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum()
}

impl Sink<'_> {
    fn send(self, mut resp: Response) {
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
            akio_http::transport::recycle_response_headers(resp.headers);
            akio_http::transport::recycle_response_body(resp.body);
            self.send_and_finish(out);
            return;
        }
        let small = resp.file.is_none() && resp.body.len() <= COPY_BODY_MAX;
        let extra = if small { resp.body.len() + 9 } else { 9 };
        let mut out = Sink::head_buf(&resp, extra);
        let body = self.head(&mut out, &resp, false);
        akio_http::transport::recycle_response_headers(std::mem::take(&mut resp.headers));
        if body {
            if let Some(fb) = resp.file.take() {
                // The head now; the file in pieces as the stream takes them, read on the pool.
                let mut tail = Vec::new();
                self.put_trailers(&mut tail, trailers.as_ref());
                let mut o = Out {
                    file: Some(FileOut {
                        file: fb.file,
                        off: fb.offset,
                        end: fb.offset + fb.len,
                    }),
                    tail: (!tail.is_empty()).then(|| Bytes::from(tail)),
                    finish: true,
                    ..Out::default()
                };
                o.push(Bytes::from(out));
                return self.queue(o);
            } else if small {
                if !resp.body.is_empty() {
                    frame::put_frame(&mut out, frame::DATA, &resp.body);
                }
                akio_http::transport::recycle_response_body(std::mem::take(&mut resp.body));
            } else {
                // A large body in memory: the head with the DATA frame header, then the body
                // as it is; whatever the send buffer refuses waits for room.
                frame::put_varint(&mut out, frame::DATA);
                frame::put_varint(&mut out, resp.body.len() as u64);
                let mut o = Out {
                    finish: true,
                    ..Out::default()
                };
                o.push(Bytes::from(out));
                o.push(Bytes::from(std::mem::take(&mut resp.body)));
                let mut tail = Vec::new();
                self.put_trailers(&mut tail, trailers.as_ref());
                o.push(Bytes::from(tail));
                return self.queue(o);
            }
        }
        self.put_trailers(&mut out, trailers.as_ref());
        self.send_and_finish(out);
    }

    fn start_stream(self, resp: Response) -> Option<Box<dyn BodySink>> {
        if self.o.c.is_closed() {
            return None;
        }
        let mut out = Sink::head_buf(&resp, 0);
        let body = self.head(&mut out, &resp, true);
        let out = Bytes::from(out);
        let queued = match self.o.c.send(self.id, out.clone()) {
            Ok(()) => false,
            Err(akio_quic::Error::Overloaded) => {
                let mut o = Out::default();
                o.push(out);
                self.queue(o);
                true
            }
            Err(_) => return None,
        };
        Some(Box::new(StreamBody {
            o: self.o.clone(),
            id: self.id,
            head_only: self.head_only,
            body,
            queued: AtomicBool::new(queued),
        }))
    }
}

struct StreamBody {
    o: H3Out,
    id: StreamId,
    head_only: bool,
    body: bool,
    /// Part of the response (its head) waited for room; writes are refused until it is out.
    queued: AtomicBool,
}

impl StreamBody {
    fn sink(&self) -> Sink<'_> {
        Sink {
            o: &self.o,
            id: self.id,
            head_only: self.head_only,
        }
    }

    /// Whether earlier parts of the response still wait for room.
    fn waiting(&self) -> bool {
        if !self.queued.load(Ordering::Acquire) {
            return false;
        }
        if lock(&self.o.outs).contains_key(&self.id) {
            return true;
        }
        self.queued.store(false, Ordering::Release);
        false
    }
}

impl BodySink for StreamBody {
    /// Fails with `Overloaded`, the data not taken, while the stream's or the connection's
    /// send buffer is full (`TransportConfig::stream_send_buffer`, `send_buffer`), as on
    /// HTTP/1.1 and HTTP/2: write again once [`queued_bytes`](BodySink::queued_bytes) went
    /// down.
    fn write(&self, data: &[u8]) -> akio_core::Result<()> {
        if !self.body || data.is_empty() {
            return Ok(());
        }
        if self.waiting() {
            return Err(akio_core::Error::Overloaded);
        }
        self.o
            .c
            .send(self.id, data_frame(data))
            .map_err(|e| match e {
                akio_quic::Error::Overloaded => akio_core::Error::Overloaded,
                _ => akio_core::Error::Closed,
            })
    }

    fn queued_bytes(&self) -> usize {
        let waiting = if self.queued.load(Ordering::Acquire) {
            lock(&self.o.outs).get(&self.id).map_or(0, |o| o.bytes)
        } else {
            0
        };
        self.o.c.queued_bytes(self.id) + waiting
    }

    /// Runs `f` once the stream's send buffer has room for more (at once if it has and nothing
    /// of the response waits), on the connection's I/O thread otherwise, or when the stream is
    /// stopped or the connection closed.
    fn on_drain(&self, f: Box<dyn FnOnce() + Send>) {
        // Registered first: a writable event from the I/O thread meanwhile finds it.
        lock(&self.o.drains).insert(self.id, f);
        // Part of the response waiting for room means a writable event is due.
        let now = match self.o.c.send_capacity(self.id) {
            Ok(room) => room > 0 && !self.waiting(),
            Err(_) => true, // the stream is gone
        };
        if now {
            run_drain(&self.o.drains, self.id);
        }
    }

    /// Resets the request stream, the body given up unfinished (ADR-128).
    fn reset(self: Box<Self>) {
        let _ = self.o.c.stop(self.id, code::INTERNAL_ERROR);
        let _ = self.o.c.reset(self.id, code::INTERNAL_ERROR);
    }

    fn finish(self: Box<Self>, trailers: Option<Headers>) {
        self.o.gones.forget(self.id);
        let mut out = Vec::new();
        self.sink().put_trailers(&mut out, trailers.as_ref());
        if self.waiting() {
            let mut o = Out {
                finish: true,
                ..Out::default()
            };
            o.push(Bytes::from(out));
            return self.sink().queue(o);
        }
        self.sink().send_and_finish(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client that asks for `/f` and counts the response stream's bytes.
    struct Fetch {
        got: Arc<std::sync::atomic::AtomicU64>,
    }
    impl QuicHandler for Fetch {
        fn on_connected(&mut self, c: &Connection) {
            let id = c.open_bi().expect("stream");
            let mut req = Vec::new();
            put_head(
                &mut req,
                None,
                &[
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/f"),
                ],
                &Headers::new(),
                false,
                None,
                None,
            );
            c.send(id, req).expect("request");
            c.finish(id).expect("finish");
        }
        fn on_stream_data(&mut self, _c: &Connection, id: StreamId, d: Bytes, _fin: bool) {
            if id.dir() == Dir::Bi {
                self.got.fetch_add(d.len() as u64, Ordering::Relaxed);
            }
        }
    }

    /// The tests that count file reads (the counters are global).
    static FILE_TESTS: Mutex<()> = Mutex::new(());

    /// A file body is read as the client takes it: a client that goes away midway leaves at
    /// most the stream's send buffer and a piece or two read ahead of what it acknowledged.
    #[test]
    fn file_reads_follow_the_peer() {
        use std::sync::atomic::AtomicU64;
        let _one = lock(&FILE_TESTS);
        let read_before = FILE_READ.load(Ordering::Relaxed);
        const LEN: u64 = 64 << 20;
        let path = std::env::temp_dir().join(format!("akio-h3-file-{}", std::process::id()));
        std::fs::File::create(&path).unwrap().set_len(LEN).unwrap();
        let file = Arc::new(std::fs::File::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let app = akio_http::Router::new().get("/f", move |ctx: &mut akio_http::Context| {
            let fb = akio_http::message::FileBody::new(file.clone(), 0, LEN);
            ctx.respond(Response::from_file(200, "application/octet-stream", fb));
        });
        let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
        let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
        let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
        let mut t = akio_quic::TransportConfig::default();
        t.stream_send_buffer = 1 << 20;
        let quic = server_config(vec![cert], key).unwrap().transport(&t);
        let s = akio::Engine::builder()
            .listen(akio::Listener::udp("127.0.0.1:0".parse().unwrap()).serve(serve(quic, app)))
            .build()
            .unwrap();
        s.start().unwrap();
        let addr = s.local_addrs()[0];
        let e = akio::Engine::builder()
            .udp_client_threads(1)
            .build()
            .unwrap();
        e.start().unwrap();
        let got = Arc::new(AtomicU64::new(0));
        let mut ct = akio_quic::TransportConfig::default();
        ct.stream_receive_window = 128 << 10;
        let cc = akio_quic::client_config_insecure(&[b"h3"])
            .unwrap()
            .transport(&ct);
        let _c = akio_quic::dial(&e, addr, "localhost", cc, Fetch { got: got.clone() }).unwrap();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while got.load(Ordering::Relaxed) < 4 << 20 {
            assert!(std::time::Instant::now() < end, "no data");
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        // The client vanishes: nothing more is acknowledged.
        e.shutdown();
        e.wait();
        let received = got.load(Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(500));
        let read = FILE_READ.load(Ordering::Relaxed) - read_before;
        let bound = received + (1 << 20) + 2 * FILE_CHUNK as u64 + (64 << 10);
        assert!(read <= bound, "read {read}, client got {received}");
        assert!(read < LEN);
        s.shutdown();
    }

    /// A file read the pool refuses is asked again a little later, never done on the thread
    /// that found the pool full (the connection's I/O thread): the response goes on once the
    /// pool has room.
    #[test]
    fn file_reads_wait_for_a_full_pool() {
        use std::sync::atomic::AtomicU64;
        use std::time::{Duration, Instant};
        const LEN: u64 = 1 << 20;
        let _one = lock(&FILE_TESTS);
        let path = std::env::temp_dir().join(format!("akio-h3-full-pool-{}", std::process::id()));
        std::fs::File::create(&path).unwrap().set_len(LEN).unwrap();
        let file = Arc::new(std::fs::File::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
        let released = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let (r2, s2) = (released.clone(), started);
        let app = akio_http::Router::new().get("/f", move |ctx: &mut akio_http::Context| {
            // The pool's one thread, then its one queue slot, wait for the test.
            let ex = ctx.executor().expect("executor");
            for _ in 0..2 {
                let (r, s) = (r2.clone(), s2.clone());
                ex.execute(move || {
                    s.store(true, Ordering::Release);
                    let end = Instant::now() + Duration::from_secs(10);
                    while !r.load(Ordering::Acquire) && Instant::now() < end {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                })
                .expect("queued");
                let end = Instant::now() + Duration::from_secs(5);
                while !s2.load(Ordering::Acquire) && Instant::now() < end {
                    std::thread::yield_now();
                }
            }
            let fb = akio_http::message::FileBody::new(file.clone(), 0, LEN);
            ctx.respond(Response::from_file(200, "application/octet-stream", fb));
        });
        let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
        let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
        let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
        let quic = server_config(vec![cert], key).unwrap();
        let mut pool = akio::PoolConfig::default();
        pool.max_threads = 1;
        pool.queue_capacity = 1;
        let s = akio::Engine::builder()
            .pool(pool)
            .listen(akio::Listener::udp("127.0.0.1:0".parse().unwrap()).serve(serve(quic, app)))
            .build()
            .unwrap();
        s.start().unwrap();
        let addr = s.local_addrs()[0];
        let e = akio::Engine::builder()
            .udp_client_threads(1)
            .build()
            .unwrap();
        e.start().unwrap();
        let got = Arc::new(AtomicU64::new(0));
        let refused = READS_REFUSED.load(Ordering::Relaxed);
        let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
        let _c = akio_quic::dial(&e, addr, "localhost", cc, Fetch { got: got.clone() }).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while READS_REFUSED.load(Ordering::Relaxed) < refused + 3 {
            assert!(Instant::now() < end, "no refused read");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(FILE_READ_OFF_POOL.load(Ordering::Relaxed), 0);
        assert!(
            got.load(Ordering::Relaxed) < LEN,
            "the body waits for the pool"
        );
        released.store(true, Ordering::Release);
        while got.load(Ordering::Relaxed) < LEN {
            assert!(Instant::now() < end, "body not received");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(FILE_READ_OFF_POOL.load(Ordering::Relaxed), 0);
        e.shutdown();
        e.wait();
        s.shutdown();
    }

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
        put_head(&mut out, Some(200), &[], &h, true, Some(1234), None);
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
        put_head(&mut out, None, &[], &h, true, Some(9), None);
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
        put_head(&mut out, Some(200), &[], &h, false, None, None);
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
            [&base[..], &[("x a", "1")]].concat(),
            [&base[..], &[("x\u{e9}", "1")]].concat(),
            [&base[..], &[("x-a", "a\0b")]].concat(),
            [&base[..], &[("x-a", "a\rb")]].concat(),
            [&base[..], &[("x-a", "a\nb")]].concat(),
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
