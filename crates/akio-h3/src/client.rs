//! An HTTP/3 client: requests multiplexed on one QUIC connection, request bodies streamed
//! ([`H3Client::upload`]), responses streamed ([`H3Client::open`], with flow control
//! backpressure) and WebSocket over HTTP/3 ([`H3Client::websocket`]).
//!
//! Responses are bounded by [`H3ClientOptions`]: body (8 MiB), field sections (64 KiB,
//! advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE`) and a total request timeout (30 s).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, mpsc};
use std::time::{Duration, Instant};

use akio_http::message::{Headers, Method, Response};
use akio_http::ws::deflate::PmdOffer;
use akio_http::ws::{WsConfig, WsHandler, WsSender, WsSession};
use akio_quic::Bytes;
use akio_quic::{Connection, ConnectionError, Dir, QuicHandler, StreamId};

use crate::frame::{self, Piece, Reader, StreamReader};
use crate::qpack::{self, FieldBuf, SectionError};
use crate::{Blocked, EncShared, H3Config, Peer, Settings, StreamLink, StreamMap, Uni, code, sid};

type Callback = Box<dyn FnOnce(Result<Response, H3Error>) + Send>;
type WsDone = Box<dyn FnOnce(Result<WsSender, H3Error>) + Send>;
type Encode = Box<dyn FnOnce(StreamId, Option<&EncShared>) -> Vec<u8> + Send>;
type EventCb = Box<dyn FnMut(H3Event<'_>) + Send>;

/// What a streamed response ([`H3Client::open`]) reports as it arrives, on the connection's
/// I/O thread. After `End` or `Error` nothing more is reported.
#[non_exhaustive]
pub enum H3Event<'a> {
    /// The response head (interim 1xx responses are skipped).
    Head {
        /// Status code.
        status: u16,
        /// Header fields.
        headers: &'a Headers,
    },
    /// Body bytes, as they arrive (valid for this call only).
    Data(&'a [u8]),
    /// Trailer fields.
    Trailers(&'a Headers),
    /// The response is complete.
    End,
    /// The request failed: reset, connection lost, a limit or the protocol broken, or no head
    /// within [`H3ClientOptions::request_timeout`] (reported from the client's timer thread).
    Error(H3Error),
}

impl std::fmt::Debug for H3Event<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Event::Head { status, .. } => f
                .debug_struct("Head")
                .field("status", status)
                .finish_non_exhaustive(),
            H3Event::Data(d) => f.debug_tuple("Data").field(&d.len()).finish(),
            H3Event::Trailers(_) => f.write_str("Trailers"),
            H3Event::End => f.write_str("End"),
            H3Event::Error(e) => f.debug_tuple("Error").field(e).finish(),
        }
    }
}

/// Limits and QPACK settings of an [`H3Client`]. Every one has a safe default.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H3ClientOptions {
    /// Largest response body; past it the request stream is stopped and the request fails
    /// with [`H3Error::TooLarge`]. Streamed responses ([`H3Client::open`]) are handed over as
    /// they arrive and not limited. Default 8 MiB (as `H3Config::max_body_bytes`).
    pub max_body_bytes: usize,
    /// Largest response field section (headers or trailers, decoded), advertised as
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`; larger ones fail the request with
    /// [`H3Error::TooLarge`]. Default 64 KiB (as `H3Config::max_field_section_bytes`).
    pub max_field_section_bytes: usize,
    /// Total time from [`H3Client::request`] (or [`H3Client::websocket`]) to the complete
    /// response (a WebSocket's: its head), waiting for the handshake or a stream included.
    /// Past it the request stream is reset (`H3_REQUEST_CANCELLED`) and the request fails with
    /// [`H3Error::Timeout`]; that callback runs on the client's timer thread. Uploads
    /// ([`H3Client::upload`]) have no timeout; streamed responses ([`H3Client::open`]) have it
    /// until their head arrives. `None` opts out. Default 30 s.
    pub request_timeout: Option<Duration>,
    /// QPACK dynamic table capacity this client's decoder allows the server
    /// (as `H3Config::qpack_max_table_capacity`). Default 4096.
    pub qpack_max_table_capacity: usize,
    /// Response streams that may wait for QPACK inserts at once
    /// (as `H3Config::qpack_blocked_streams`). Default 16.
    pub qpack_blocked_streams: usize,
    /// Dynamic table capacity this client's encoder uses, at most what the server allows
    /// (as `H3Config::qpack_encoder_capacity`). Default 0: off.
    pub qpack_encoder_capacity: usize,
}

impl Default for H3ClientOptions {
    fn default() -> H3ClientOptions {
        let h3 = H3Config::default();
        H3ClientOptions {
            max_body_bytes: 8 << 20,
            max_field_section_bytes: 64 << 10,
            request_timeout: Some(Duration::from_secs(30)),
            qpack_max_table_capacity: h3.qpack_max_table_capacity,
            qpack_blocked_streams: h3.qpack_blocked_streams,
            qpack_encoder_capacity: h3.qpack_encoder_capacity,
        }
    }
}

impl H3ClientOptions {
    /// The HTTP/3 settings these options make.
    fn h3(&self) -> H3Config {
        H3Config {
            max_field_section_bytes: self.max_field_section_bytes,
            max_body_bytes: self.max_body_bytes,
            qpack_max_table_capacity: self.qpack_max_table_capacity,
            qpack_blocked_streams: self.qpack_blocked_streams,
            qpack_encoder_capacity: self.qpack_encoder_capacity,
            ..H3Config::default()
        }
    }
}

/// Why an HTTP/3 request got no response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H3Error {
    /// The connection is closed (why).
    Closed(String),
    /// The server reset the request stream with this HTTP/3 error code ([`code`](crate::code)).
    Reset(u64),
    /// The response broke the protocol (what was wrong).
    Protocol(&'static str),
    /// No response within the timeout of a blocking call or
    /// [`H3ClientOptions::request_timeout`].
    Timeout,
    /// The server refused a WebSocket ([`H3Client::websocket`]) with this status.
    Status(u16),
    /// The response passed a size limit of [`H3ClientOptions`] (which one).
    TooLarge(&'static str),
}

impl std::fmt::Display for H3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            H3Error::Closed(why) => write!(f, "connection closed: {why}"),
            H3Error::Reset(code) => write!(f, "stream reset (code {code:#x})"),
            H3Error::Protocol(what) => write!(f, "HTTP/3 protocol error: {what}"),
            H3Error::Timeout => f.write_str("timed out"),
            H3Error::Status(s) => write!(f, "WebSocket refused with status {s}"),
            H3Error::TooLarge(what) => write!(f, "too large: {what}"),
        }
    }
}

impl std::error::Error for H3Error {}

/// How [`H3Client::websocket`] opens a WebSocket over HTTP/3 (RFC 9220).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H3WsOptions {
    /// Message limits and compression; `permessage_deflate` decides whether it is offered.
    pub config: WsConfig,
    /// What the `permessage-deflate` offer asks for.
    pub pmd: PmdOffer,
    /// Subprotocols to offer, in order of preference; the server's choice is
    /// [`WsSender::subprotocol`].
    pub protocols: Vec<String>,
    /// `Origin` header, for servers that check it.
    pub origin: Option<String>,
    /// Extra request header fields (e.g. `authorization`).
    pub headers: Vec<(String, String)>,
    /// After the close handshake, how long to wait for the server to end the stream before
    /// ending it from this side.
    pub close_timeout: Duration,
}

impl Default for H3WsOptions {
    fn default() -> H3WsOptions {
        H3WsOptions {
            config: WsConfig::default(),
            pmd: PmdOffer::default(),
            protocols: Vec::new(),
            origin: None,
            headers: Vec::new(),
            close_timeout: Duration::from_secs(3),
        }
    }
}

/// A WebSocket being opened.
struct WsOpen {
    handler: Box<dyn WsHandler>,
    cfg: WsConfig,
    pmd: Option<PmdOffer>,
    protocols: Vec<String>,
    close_timeout: Duration,
    done: WsDone,
}

/// A streamed response's callback and its request's body.
struct StreamOpen {
    ev: EventCb,
    up: Arc<UpState>,
}

impl StreamOpen {
    /// Reports `e`, unless the request was cancelled.
    fn fail(&mut self, e: H3Error) {
        self.up.fail();
        if !self.up.cancelled() {
            (self.ev)(H3Event::Error(e));
        }
    }
}

/// What a request stream is for.
enum Kind {
    /// A request whose response goes to the callback.
    Plain(Callback),
    /// A WebSocket being opened: done once the response head arrives.
    Ws(Box<WsOpen>),
    /// A streamed response: reported from its head on.
    Stream(Box<StreamOpen>),
}

impl Kind {
    fn fail(self, e: H3Error) {
        match self {
            Kind::Plain(cb) => cb(Err(e)),
            Kind::Ws(w) => (w.done)(Err(e)),
            Kind::Stream(mut s) => s.fail(e),
        }
    }
}

/// A request waiting for a stream.
struct Job {
    /// Its bytes (empty when `x.encode` encodes them once the stream is open).
    wire: Bytes,
    kind: Kind,
    /// What only uploads, WebSockets and dynamic-table encoding need (boxed, so a plain
    /// request stays small).
    x: Option<Box<JobX>>,
    /// Identifies the request to its deadline (0: none).
    token: u64,
}

struct JobX {
    /// How to encode the request once its stream id is known (QPACK with a dynamic table
    /// needs it).
    encode: Option<Encode>,
    up: Option<Arc<UpState>>,
    /// End the stream after the request's bytes (not for uploads and WebSockets).
    fin: bool,
}

impl Job {
    /// A request whose bytes are ready and end its stream.
    fn plain(wire: Bytes, kind: Kind) -> Job {
        Job {
            wire,
            kind,
            x: None,
            token: 0,
        }
    }

    fn with(wire: Result<Bytes, Encode>, fin: bool, up: Option<Arc<UpState>>, kind: Kind) -> Job {
        let (wire, encode) = match wire {
            Ok(b) => (b, None),
            Err(f) => (Bytes::default(), Some(f)),
        };
        Job {
            wire,
            kind,
            x: Some(Box::new(JobX { encode, up, fin })),
            token: 0,
        }
    }

    fn up(&self) -> Option<&Arc<UpState>> {
        self.x.as_ref()?.up.as_ref()
    }
}

struct InFlight {
    r: Reader,
    resp: Option<Response>,
    cb: Option<Callback>,
    /// What only uploads, WebSockets and blocked responses need (boxed, so a plain request's
    /// state stays small).
    x: Option<Box<Extra>>,
    /// Identifies the request to its deadline (0: none).
    token: u64,
}

#[derive(Default)]
struct Extra {
    ws: Option<Box<WsOpen>>,
    st: Option<Box<StreamOpen>>,
    up: Option<Arc<UpState>>,
    blocked: Option<Box<Blocked>>,
}

impl InFlight {
    #[inline]
    fn new(kind: Kind, up: Option<Arc<UpState>>, token: u64) -> InFlight {
        let (cb, ws, st) = match kind {
            Kind::Plain(cb) => (Some(cb), None, None),
            Kind::Ws(w) => (None, Some(w), None),
            Kind::Stream(s) => (None, None, Some(s)),
        };
        let x = (ws.is_some() || st.is_some() || up.is_some()).then(|| {
            Box::new(Extra {
                ws,
                st,
                up,
                blocked: None,
            })
        });
        InFlight {
            r: Reader::default(),
            resp: None,
            cb,
            x,
            token,
        }
    }

    fn take_kind(&mut self) -> Option<Kind> {
        match self.cb.take() {
            Some(cb) => Some(Kind::Plain(cb)),
            None => {
                let x = self.x.as_mut()?;
                match x.ws.take() {
                    Some(w) => Some(Kind::Ws(w)),
                    None => x.st.take().map(Kind::Stream),
                }
            }
        }
    }

    fn up(&self) -> Option<&Arc<UpState>> {
        self.x.as_ref()?.up.as_ref()
    }

    fn blocked(&self) -> Option<&Blocked> {
        self.x.as_ref()?.blocked.as_deref()
    }

    fn take_blocked(&mut self) -> Option<Box<Blocked>> {
        self.x.as_mut()?.blocked.take()
    }
}

#[derive(Default)]
struct State {
    ready: bool,
    closed: Option<String>,
    queue: VecDeque<Job>,
    inflight: StreamMap<InFlight>,
    /// The server's SETTINGS, once they arrived.
    settings: Option<Settings>,
    /// WebSockets waiting for the server's SETTINGS (extended CONNECT allowed?).
    ws_wait: Vec<Job>,
    next_token: u64,
    /// Request deadlines in order (every request has the same timeout), for consecutive
    /// tokens from `first`; `false` once the request finished. A finished request's entry
    /// is dropped once it reaches the front.
    deadlines: VecDeque<(Instant, bool)>,
    /// The token of `deadlines[0]`.
    first: u64,
    /// When the pending timer job runs; one job per connection, not per request.
    armed_at: Option<Instant>,
    /// Streams whose blocked response a timeout gave up: the connection's handler cancels
    /// them on the decoder stream (the timer thread cannot).
    expired_blocked: Vec<StreamId>,
}

impl State {
    fn finished(&mut self, token: u64) {
        // Tokens below `first` left with their entries; 0 is no deadline.
        if let Some(i) = token.checked_sub(self.first) {
            if let Some(d) = self.deadlines.get_mut(i as usize) {
                d.1 = false;
            }
        }
    }

    /// Drops the front deadline: its time, its token, and whether its request still waits.
    fn pop_front(&mut self) -> Option<(Instant, u64, bool)> {
        let (at, live) = self.deadlines.pop_front()?;
        self.first += 1;
        Some((at, self.first - 1, live))
    }

    fn prune(&mut self) {
        while self.deadlines.front().is_some_and(|d| !d.1) {
            self.pop_front();
        }
    }

    /// A deadline for a new request (0 without a timeout).
    fn deadline(&mut self, timeout: Option<Duration>) -> u64 {
        let Some(d) = timeout else { return 0 };
        self.prune();
        self.next_token += 1;
        let token = self.next_token;
        if self.deadlines.is_empty() {
            self.first = token;
        }
        self.deadlines.push_back((Instant::now() + d, true));
        token
    }
}

struct Shared {
    st: Mutex<State>,
    /// The QPACK encoder with a dynamic table, once the server allows one.
    enc: OnceLock<Arc<EncShared>>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// An HTTP/3 connection to one server. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct H3Client {
    conn: Connection,
    sh: Arc<Shared>,
    authority: String,
    request_timeout: Option<Duration>,
}

impl std::fmt::Debug for H3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Client").finish_non_exhaustive()
    }
}

/// The body of a request started with [`H3Client::upload`] or [`H3Client::open`]: write it in
/// pieces from any thread, then finish it. For [`open`](H3Client::open) it also paces
/// ([`hold_reads`](Self::hold_reads)) and cancels ([`cancel`](Self::cancel)) the response.
pub struct H3Upload {
    up: Arc<UpState>,
}

impl std::fmt::Debug for H3Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Upload").finish_non_exhaustive()
    }
}

struct UpState {
    c: Connection,
    s: Mutex<Up>,
    /// [`H3Upload::cancel`] was called: nothing more is reported.
    cancelled: AtomicBool,
}

#[derive(Default)]
struct Up {
    /// The stream, once open (the head is sent first).
    id: Option<StreamId>,
    /// DATA frames written before the stream opened, or refused while its send buffer was
    /// full; they go out in order once there is room.
    queued: Vec<u8>,
    finished: bool,
    /// The stream's end was sent.
    ended: bool,
    failed: bool,
    /// The response's reads are held ([`H3Upload::hold_reads`]).
    held: bool,
}

impl UpState {
    fn lock(&self) -> MutexGuard<'_, Up> {
        self.s.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn new(c: &Connection) -> UpState {
        UpState {
            c: c.clone(),
            s: Mutex::new(Up::default()),
            cancelled: AtomicBool::new(false),
        }
    }

    /// The stream is open and its head sent: what was written goes out (or the stream is
    /// cancelled, or its reads held, if that was asked before).
    fn attach(&self, id: StreamId) {
        let mut u = self.lock();
        u.id = Some(id);
        if self.cancelled() {
            let _ = self.c.reset(id, code::REQUEST_CANCELLED);
            let _ = self.c.stop(id, code::REQUEST_CANCELLED);
            return;
        }
        if u.held {
            let _ = self.c.hold_reads(id, true);
        }
        self.flush(&mut u);
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Puts the stream's reads back as the application wants them (after QPACK held them).
    fn restore_hold(&self, id: StreamId) {
        let held = self.lock().held;
        let _ = self.c.hold_reads(id, held);
    }

    /// Sends what waits (as far as the send buffer takes it), then the end if finished.
    fn flush(&self, u: &mut Up) {
        let Some(id) = u.id else { return };
        if !u.queued.is_empty() {
            let q = Bytes::from(std::mem::take(&mut u.queued));
            match self.c.send(id, q.clone()) {
                Ok(()) => {}
                // Again once the stream is writable (`on_stream_writable`).
                Err(akio_quic::Error::Overloaded) => return u.queued = q.to_vec(),
                Err(_) => return u.failed = true,
            }
        }
        if u.finished && !u.ended {
            u.ended = true;
            let _ = self.c.finish(id);
        }
    }

    fn fail(&self) {
        self.lock().failed = true;
    }
}

impl H3Upload {
    /// Sends body bytes (in a DATA frame). `false` once the request failed or was finished.
    /// What the stream's send buffer cannot take yet is kept here until it can: pace the
    /// writer with [`queued_bytes`](Self::queued_bytes).
    pub fn write(&self, data: &[u8]) -> bool {
        let mut u = self.up.lock();
        if u.failed || u.finished {
            return false;
        }
        if data.is_empty() {
            return true;
        }
        match u.id {
            Some(id) if u.queued.is_empty() => match self.up.c.send(id, crate::data_frame(data)) {
                Ok(()) => true,
                Err(akio_quic::Error::Overloaded) => {
                    frame::put_frame(&mut u.queued, frame::DATA, data);
                    true
                }
                Err(_) => false,
            },
            _ => {
                frame::put_frame(&mut u.queued, frame::DATA, data);
                true
            }
        }
    }

    /// Ends the body. `false` if the request already failed.
    pub fn finish(&self) -> bool {
        let mut u = self.up.lock();
        if u.failed {
            return false;
        }
        if !std::mem::replace(&mut u.finished, true) {
            self.up.flush(&mut u);
        }
        !u.failed
    }

    /// Bytes written but not yet sent, for pacing the writer.
    pub fn queued_bytes(&self) -> usize {
        let u = self.up.lock();
        u.queued.len() + u.id.map_or(0, |id| self.up.c.queued_bytes(id))
    }

    /// Holds (`true`) or resumes (`false`) reading a streamed response
    /// ([`H3Client::open`]): while held, no more [`H3Event::Data`] is reported (bytes already
    /// received may still be) and QUIC flow control stops the server once the stream's receive
    /// window is used, so a slow consumer bounds the memory a response takes. Holding before
    /// the head arrives holds the head too (and [`H3ClientOptions::request_timeout`] still
    /// runs). Callable from any thread, the event callback included.
    pub fn hold_reads(&self, hold: bool) {
        let mut u = self.up.lock();
        u.held = hold;
        if let Some(id) = u.id {
            let _ = self.up.c.hold_reads(id, hold);
        }
    }

    /// Abandons the request: its stream is reset and the server asked to stop sending
    /// (`H3_REQUEST_CANCELLED`); nothing more is reported (an event callback already running
    /// finishes). Writes fail from then on.
    pub fn cancel(&self) {
        let mut u = self.up.lock();
        self.up.cancelled.store(true, Ordering::Release);
        u.failed = true;
        if let Some(id) = u.id {
            let _ = self.up.c.reset(id, code::REQUEST_CANCELLED);
            let _ = self.up.c.stop(id, code::REQUEST_CANCELLED);
        }
    }
}

impl H3Client {
    /// Connects to `addr`, verifying it as `server_name`, with a QUIC client config offering
    /// ALPN `h3` (for example `akio_quic::client_config(roots, &[b"h3"])`). The engine needs
    /// UDP client threads. Requests sent before the handshake completes wait for it, unless
    /// the connection resumes with 0-RTT (`akio_quic::ClientConfig::zero_rtt`): then they go
    /// out at once, in 0-RTT packets that may be **replayed**, so make only requests that are
    /// safe to repeat on such a client (a server may answer `425 Too Early`, RFC 8470).
    pub fn dial(
        engine: &akio::Engine,
        addr: SocketAddr,
        server_name: &str,
        config: akio_quic::ClientConfig,
    ) -> Result<H3Client, akio_quic::Error> {
        H3Client::dial_with(
            engine,
            addr,
            server_name,
            config,
            H3ClientOptions::default(),
        )
    }

    /// [`dial`](Self::dial) with limits and QPACK settings.
    pub fn dial_with(
        engine: &akio::Engine,
        addr: SocketAddr,
        server_name: &str,
        config: akio_quic::ClientConfig,
        opts: H3ClientOptions,
    ) -> Result<H3Client, akio_quic::Error> {
        let h3 = opts.h3();
        let sh = Arc::new(Shared {
            st: Mutex::new(State::default()),
            enc: OnceLock::new(),
        });
        let handler = ClientConn {
            sh: sh.clone(),
            peer: Peer::new(&h3),
            cfg: h3,
            max_body: opts.max_body_bytes,
            uni: StreamMap::default(),
            ws: StreamMap::default(),
            ws_answer: None,
            dl_start: None,
            dl: StreamMap::default(),
            fields: FieldBuf::default(),
        };
        let conn = akio_quic::dial(engine, addr, server_name, config, handler)?;
        // Resuming with 0-RTT: requests go out before the handshake completes.
        if conn.early_data() == akio::tls::EarlyData::Pending {
            sh.lock().ready = true;
        }
        let authority = if addr.port() == 443 {
            server_name.to_owned()
        } else {
            format!("{server_name}:{}", addr.port())
        };
        Ok(H3Client {
            conn,
            sh,
            authority,
            request_timeout: opts.request_timeout,
        })
    }

    /// The QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Sends a request; `cb` gets the response (interim 1xx responses are skipped) or why
    /// there is none. `path` is the request target (`/a?b=c`).
    pub fn request(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Vec<u8>,
        cb: impl FnOnce(Result<Response, H3Error>) + Send + 'static,
    ) {
        let kind = Kind::Plain(Box::new(cb));
        let Some(enc) = self.sh.enc.get() else {
            // Static QPACK: encoded now, sent on a stream opened under the same lock (the
            // usual case), else queued (`start_queued` opens streams in order).
            let wire = self.encode_now(&method, path, headers, body);
            return match self.open_now(kind) {
                Ok(id) => {
                    let _ = self.conn.send(id, wire);
                    let _ = self.conn.finish(id);
                }
                Err(kind) => self.push(Job::plain(wire, kind)),
            };
        };
        match self.open_now(kind) {
            // A stream right away (the usual case): encoded with its id, nothing copied.
            Ok(id) => {
                let wire = encode_with(&method, &self.authority, path, headers, &body, id, enc);
                let _ = self.conn.send(id, wire);
                let _ = self.conn.finish(id);
            }
            Err(kind) => self.push(Job::with(
                Err(self.encode_later(method, path, headers, body)),
                true,
                None,
                kind,
            )),
        }
    }

    /// Opens a stream for a request now if nothing is queued before it; `Err` gives `kind`
    /// back when it has to wait.
    fn open_now(&self, kind: Kind) -> Result<StreamId, Kind> {
        let mut st = self.sh.lock();
        if st.closed.is_some() || !st.ready || !st.queue.is_empty() {
            return Err(kind);
        }
        let Some(id) = self.conn.open_bi() else {
            return Err(kind);
        };
        let token = self.timed(&mut st);
        st.inflight.insert(id, InFlight::new(kind, None, token));
        Ok(id)
    }

    /// The request's HEADERS and DATA frames, with static QPACK references and literals.
    #[inline]
    fn encode_now(&self, method: &Method, path: &str, headers: &Headers, body: Vec<u8>) -> Bytes {
        let pseudo = pseudo(method, &self.authority, path);
        let pseudo = pseudo_for(method, &pseudo);
        let hint = crate::head_hint(headers) + self.authority.len() + path.len() + body.len() + 64;
        let len = (!body.is_empty()).then_some(body.len() as u64);
        let encode = |wire: &mut Vec<u8>| {
            crate::put_head(wire, None, pseudo, headers, false, len, None);
            if !body.is_empty() {
                frame::put_frame(wire, frame::DATA, &body);
            }
        };
        if body.len() <= crate::POOLED_BODY_MAX {
            Bytes::pooled(hint, encode)
        } else {
            let mut wire = Vec::with_capacity(hint);
            encode(&mut wire);
            Bytes::from(wire)
        }
    }

    /// Encoding deferred until the stream is open (the dynamic table tracks sections by
    /// stream).
    fn encode_later(&self, method: Method, path: &str, headers: &Headers, body: Vec<u8>) -> Encode {
        let (authority, path, headers) = (self.authority.clone(), path.to_owned(), headers.clone());
        Box::new(move |id, enc| match enc {
            Some(enc) => encode_with(&method, &authority, &path, &headers, &body, id, enc),
            None => {
                let pseudo = pseudo(&method, &authority, &path);
                let pseudo = pseudo_for(&method, &pseudo);
                let len = (!body.is_empty()).then_some(body.len() as u64);
                let mut wire = Vec::with_capacity(crate::head_hint(&headers) + body.len() + 64);
                crate::put_head(&mut wire, None, pseudo, &headers, false, len, None);
                if !body.is_empty() {
                    frame::put_frame(&mut wire, frame::DATA, &body);
                }
                wire
            }
        })
    }

    /// A deadline for a request (0 without a timeout), the timer armed for it (`st` is
    /// locked).
    #[inline]
    fn timed(&self, st: &mut State) -> u64 {
        if self.request_timeout.is_none() {
            return 0;
        }
        let token = st.deadline(self.request_timeout);
        arm(&self.conn, &self.sh, st);
        token
    }

    #[inline(always)]
    fn push(&self, mut job: Job) {
        let mut st = self.sh.lock();
        if let Some(e) = st.closed.clone() {
            drop(st);
            if let Some(up) = job.up() {
                up.fail();
            }
            return job.kind.fail(H3Error::Closed(e));
        }
        if (job.up().is_none() || matches!(job.kind, Kind::Stream(_))) && job.token == 0 {
            // Uploads have no deadline; streamed responses have one until their head.
            job.token = self.timed(&mut st);
        }
        st.queue.push_back(job);
        let ready = st.ready;
        drop(st);
        if ready {
            start_queued(&self.conn, &self.sh);
        }
    }

    /// Starts a request whose body is written afterwards through the returned [`H3Upload`]
    /// (uploads of unknown size, or too large to hold); `cb` gets the response. Add a
    /// `content-length` header when the size is known.
    pub fn upload(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        cb: impl FnOnce(Result<Response, H3Error>) + Send + 'static,
    ) -> H3Upload {
        let up = Arc::new(UpState::new(&self.conn));
        let wire = match self.sh.enc.get() {
            None => Ok(self.encode_now(&method, path, headers, Vec::new())),
            Some(_) => Err(self.encode_later(method, path, headers, Vec::new())),
        };
        self.push(Job::with(
            wire,
            false,
            Some(up.clone()),
            Kind::Plain(Box::new(cb)),
        ));
        H3Upload { up }
    }

    /// Starts a request whose body is written afterwards through the returned [`H3Upload`]
    /// (call [`finish`](H3Upload::finish) at once when there is none) and whose response is
    /// reported piece by piece to `on_event` as it arrives, on the connection's I/O thread:
    /// [`H3Event::Head`], [`H3Event::Data`] for each piece of the body, [`H3Event::Trailers`],
    /// then [`H3Event::End`], or [`H3Event::Error`]. The body is not buffered and not limited
    /// by [`H3ClientOptions::max_body_bytes`]; pace it with [`H3Upload::hold_reads`] (QUIC flow
    /// control then holds the server back). [`H3ClientOptions::request_timeout`] applies until
    /// the head arrives; [`H3Upload::cancel`] abandons the request at any time. On a closed
    /// connection `on_event` gets [`H3Event::Error`] before this returns.
    pub fn open(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        on_event: impl FnMut(H3Event<'_>) + Send + 'static,
    ) -> H3Upload {
        let up = Arc::new(UpState::new(&self.conn));
        let wire = match self.sh.enc.get() {
            None => Ok(self.encode_now(&method, path, headers, Vec::new())),
            Some(_) => Err(self.encode_later(method, path, headers, Vec::new())),
        };
        self.push(Job::with(
            wire,
            false,
            Some(up.clone()),
            Kind::Stream(Box::new(StreamOpen {
                ev: Box::new(on_event),
                up: up.clone(),
            })),
        ));
        H3Upload { up }
    }

    /// Sends a request and waits for its response, up to `timeout`.
    pub fn request_blocking(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Response, H3Error> {
        let (tx, rx) = mpsc::channel();
        self.request(method, path, headers, body, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(timeout).map_err(|_| H3Error::Timeout)?
    }

    /// `GET path`, blocking.
    pub fn get(&self, path: &str, timeout: Duration) -> Result<Response, H3Error> {
        self.request_blocking(Method::Get, path, &Headers::new(), Vec::new(), timeout)
    }

    /// Opens a WebSocket on `path` over this connection (RFC 9220: an extended CONNECT on a
    /// new stream, which then carries the WebSocket), served by `handler` as a
    /// `akio_ws::client` connection is: callbacks on the connection's I/O thread,
    /// [`WsSender`] to send from any thread. `done` gets the sender once the server accepted
    /// (`on_open` has run), or why not: [`H3Error::Status`] for a refusal,
    /// [`H3Error::Protocol`] when the server does not allow extended CONNECT.
    pub fn websocket(
        &self,
        path: &str,
        opts: &H3WsOptions,
        handler: impl WsHandler,
        done: impl FnOnce(Result<WsSender, H3Error>) + Send + 'static,
    ) {
        let mut headers = Headers::new();
        headers.append("sec-websocket-version", "13");
        if !opts.protocols.is_empty() {
            headers.append("sec-websocket-protocol", opts.protocols.join(", "));
        }
        let pmd = opts.config.permessage_deflate.then_some(opts.pmd);
        if let Some(p) = &pmd {
            headers.append("sec-websocket-extensions", p.header());
        }
        if let Some(o) = &opts.origin {
            headers.append("origin", o.as_str());
        }
        for (n, v) in &opts.headers {
            let lower = n.to_ascii_lowercase();
            if !lower.starts_with("sec-websocket-") && lower != "origin" {
                headers.append(lower, v.as_str());
            }
        }
        let (authority, path) = (self.authority.clone(), path.to_owned());
        let wire: Encode = Box::new(move |id, enc| {
            let pseudo: [(&[u8], &[u8]); 5] = [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":authority", authority.as_bytes()),
                (b":path", path.as_bytes()),
            ];
            let mut wire = Vec::with_capacity(crate::head_hint(&headers) + 128);
            crate::put_head(
                &mut wire,
                None,
                &pseudo,
                &headers,
                false,
                None,
                enc.map(|e| (e, id)),
            );
            wire
        });
        let job = Job::with(
            Err(wire),
            false,
            None,
            Kind::Ws(Box::new(WsOpen {
                handler: Box::new(handler),
                cfg: opts.config.clone(),
                pmd,
                protocols: opts.protocols.clone(),
                close_timeout: opts.close_timeout,
                done: Box::new(done),
            })),
        );
        let mut st = self.sh.lock();
        match st.settings {
            // Extended CONNECT needs the server's SETTINGS first (RFC 8441 §3).
            None if st.closed.is_none() => {
                let mut job = job;
                job.token = self.timed(&mut st);
                st.ws_wait.push(job);
            }
            Some(s) if !s.connect_protocol => {
                drop(st);
                job.kind
                    .fail(H3Error::Protocol("server does not allow extended CONNECT"));
            }
            _ => {
                drop(st);
                self.push(job);
            }
        }
    }

    /// [`websocket`](Self::websocket), waiting up to `timeout` for the server's answer.
    pub fn websocket_blocking(
        &self,
        path: &str,
        opts: &H3WsOptions,
        handler: impl WsHandler,
        timeout: Duration,
    ) -> Result<WsSender, H3Error> {
        let (tx, rx) = mpsc::channel();
        self.websocket(path, opts, handler, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(timeout).map_err(|_| H3Error::Timeout)?
    }

    /// Closes the connection (`H3_NO_ERROR`).
    pub fn close(&self) {
        self.conn.close(code::NO_ERROR, b"");
    }
}

/// A request's HEADERS (with the dynamic table, for stream `id`) and DATA frames.
fn encode_with(
    method: &Method,
    authority: &str,
    path: &str,
    headers: &Headers,
    body: &[u8],
    id: StreamId,
    enc: &EncShared,
) -> Vec<u8> {
    let pseudo = pseudo(method, authority, path);
    let pseudo = pseudo_for(method, &pseudo);
    let len = (!body.is_empty()).then_some(body.len() as u64);
    let mut wire = Vec::with_capacity(crate::head_hint(headers) + body.len() + 64);
    crate::put_head(
        &mut wire,
        None,
        pseudo,
        headers,
        false,
        len,
        Some((enc, id)),
    );
    if !body.is_empty() {
        frame::put_frame(&mut wire, frame::DATA, body);
    }
    wire
}

/// The request pseudo-header fields (`:path` and `:scheme` are left out of a CONNECT by
/// [`pseudo_for`]).
fn pseudo<'a>(method: &'a Method, authority: &'a str, path: &'a str) -> [(&'a [u8], &'a [u8]); 4] {
    [
        (b":method", method.as_str().as_bytes()),
        (b":scheme", b"https"),
        (b":authority", authority.as_bytes()),
        (b":path", path.as_bytes()),
    ]
}

fn pseudo_for<'a, 'b>(
    method: &Method,
    p: &'b [(&'a [u8], &'a [u8]); 4],
) -> &'b [(&'a [u8], &'a [u8])] {
    if *method == Method::Connect {
        &p[..3]
    } else {
        &p[..]
    }
}

/// Makes sure a timer job runs by the earliest request deadline (`s` is `sh` locked).
fn arm(conn: &Connection, sh: &Arc<Shared>, s: &mut State) {
    let Some(&(at, _)) = s.deadlines.front() else {
        return;
    };
    if s.armed_at.is_some_and(|t| t <= at) {
        return;
    }
    s.armed_at = Some(at);
    let (conn, sh) = (conn.clone(), Arc::downgrade(sh));
    timer::at(at, move || {
        if let Some(sh) = sh.upgrade() {
            expire(&conn, &sh, at);
        }
    });
}

/// The job armed for `armed` ran: fail the requests whose deadline passed (resetting their
/// streams), then re-arm for the next deadline.
fn expire(conn: &Connection, sh: &Arc<Shared>, armed: Instant) {
    let mut s = sh.lock();
    if s.armed_at != Some(armed) {
        return; // superseded by an earlier job
    }
    s.armed_at = None;
    let now = Instant::now();
    let mut kinds = Vec::new();
    while s.deadlines.front().is_some_and(|d| d.0 <= now) {
        let Some((_, token, true)) = s.pop_front() else {
            continue;
        };
        if let Some(i) = s.queue.iter().position(|j| j.token == token) {
            kinds.extend(s.queue.remove(i).map(|j| j.kind));
        } else if let Some(i) = s.ws_wait.iter().position(|j| j.token == token) {
            kinds.push(s.ws_wait.swap_remove(i).kind);
        } else if let Some(id) = s
            .inflight
            .iter()
            .find(|(_, f)| f.token == token)
            .map(|(id, _)| *id)
        {
            if let Some(mut f) = s.inflight.remove(&id) {
                if f.take_blocked().is_some() {
                    s.expired_blocked.push(id);
                }
                if let Some(up) = f.up() {
                    up.fail();
                }
                kinds.extend(f.take_kind());
            }
            let _ = conn.reset(id, code::REQUEST_CANCELLED);
            let _ = conn.stop(id, code::REQUEST_CANCELLED);
        }
    }
    s.prune();
    arm(conn, sh, &mut s);
    drop(s);
    for k in kinds {
        k.fail(H3Error::Timeout);
    }
}

/// Opens streams for queued requests while the peer allows.
fn start_queued(conn: &Connection, sh: &Shared) {
    loop {
        let mut s = sh.lock();
        if s.queue.is_empty() || !s.ready {
            return;
        }
        let Some(id) = conn.open_bi() else { return };
        let job = s.queue.pop_front().expect("non-empty");
        let Some(x) = job.x else {
            // A plain request, its bytes ready.
            s.inflight
                .insert(id, InFlight::new(job.kind, None, job.token));
            drop(s);
            let _ = conn.send(id, job.wire);
            let _ = conn.finish(id);
            continue;
        };
        let JobX { encode, up, fin } = *x;
        s.inflight
            .insert(id, InFlight::new(job.kind, up.clone(), job.token));
        drop(s);
        let wire = match encode {
            None => job.wire,
            Some(f) => Bytes::from(f(id, sh.enc.get().map(|e| &**e))),
        };
        let _ = conn.send(id, wire);
        match &up {
            Some(up) => up.attach(id),
            None if fin => {
                let _ = conn.finish(id);
            }
            None => {}
        }
    }
}

struct ClientConn {
    sh: Arc<Shared>,
    cfg: H3Config,
    /// Largest response body.
    max_body: usize,
    peer: Peer,
    uni: StreamMap<Uni>,
    /// A WebSocket's answer `on_resp` just took off its stream, for `report`.
    ws_answer: Option<Box<WsAnswer>>,
    /// Open WebSockets, by stream.
    ws: StreamMap<(StreamReader, WsSession)>,
    /// A streamed response's head `on_resp` just took off its stream, for `report`.
    dl_start: Option<Box<DlStart>>,
    /// Streamed responses past their head, by stream.
    dl: StreamMap<Dl>,
    /// Field sections are decoded here, then copied once into the response's `Headers`.
    fields: FieldBuf,
}

fn fields_to_response(fields: &FieldBuf) -> Option<Response> {
    let mut status = None;
    let mut headers = Headers::with_capacity(fields.len(), fields.bytes());
    for (n, v) in fields.strs()? {
        if n == ":status" {
            status = v.parse::<u16>().ok();
        } else if n.starts_with(':') {
            return None;
        } else {
            headers.append(n, v);
        }
    }
    let mut r = Response::new(status?);
    r.headers = headers;
    Some(r)
}

/// A WebSocket's answer (its body: the WebSocket bytes that came with it), whether the stream
/// already ended, and the stream's reader (holding the start of a frame, maybe).
struct WsAnswer {
    w: Box<WsOpen>,
    r: Result<Response, H3Error>,
    fin: bool,
    reader: Reader,
}

/// A finished request: its callback and the response, or why there is none.
type Done = (Callback, Result<Response, H3Error>);

/// A streamed response whose head arrived (with what came along: body bytes, trailers,
/// the end), and the stream's reader (holding the start of a frame, maybe).
struct DlStart {
    s: Box<StreamOpen>,
    r: Result<Response, H3Error>,
    fin: bool,
    reader: Reader,
}

/// A streamed response past its head.
struct Dl {
    r: StreamReader,
    s: Box<StreamOpen>,
    /// Trailers arrived: nothing but the end may follow.
    trailers: bool,
    /// Trailers waiting for QPACK inserts (the stream's reads are held meanwhile).
    blocked: Option<Box<Blocked>>,
}

/// Handles one piece of a streamed response past its head.
fn dl_piece(
    peer: &mut Peer,
    fields: &mut FieldBuf,
    max_field: usize,
    id: StreamId,
    d: &mut DlParts<'_>,
    p: Piece<'_>,
) -> Result<(), H3Error> {
    if let Some(b) = d.blocked.as_mut() {
        // Held back, in order, until the trailers before them can be decoded.
        match p {
            Piece::Data(x) => frame::put_frame(&mut b.rest, frame::DATA, x),
            Piece::Headers(h) => frame::put_frame(&mut b.rest, frame::HEADERS, h),
            Piece::Skip(_) => {}
        }
        return Ok(());
    }
    match p {
        Piece::Data(x) => {
            if *d.trailers {
                return Err(H3Error::Protocol("DATA after trailers"));
            }
            if !x.is_empty() && !d.s.up.cancelled() {
                (d.s.ev)(H3Event::Data(x));
            }
        }
        Piece::Headers(h) => {
            if *d.trailers {
                return Err(H3Error::Protocol("HEADERS after trailers"));
            }
            match qpack::decode_section(h, max_field, &peer.dec, fields) {
                Ok(ric) => {
                    if ric > 0 {
                        peer.dec.section_ack(sid(id), ric);
                    }
                    *d.trailers = true;
                    let mut t = Headers::with_capacity(fields.len(), fields.bytes());
                    for (n, v) in fields.iter() {
                        t.append(String::from_utf8_lossy(n), String::from_utf8_lossy(v));
                    }
                    if !d.s.up.cancelled() {
                        (d.s.ev)(H3Event::Trailers(&t));
                    }
                }
                Err(SectionError::Blocked(ric)) => {
                    if peer.blocked >= peer.max_blocked {
                        return Err(H3Error::Protocol("too many blocked streams"));
                    }
                    peer.blocked += 1;
                    *d.blocked = Some(Box::new(Blocked {
                        ric,
                        section: h.to_vec(),
                        rest: Vec::new(),
                        fin: false,
                    }));
                }
                Err(SectionError::Bad(qpack::QpackError::TooLarge)) => {
                    return Err(H3Error::TooLarge("response field section too large"));
                }
                Err(SectionError::Bad(_)) => return Err(H3Error::Protocol("bad field section")),
            }
        }
        Piece::Skip(t) if crate::h2_only(t) || t == frame::SETTINGS => {
            return Err(H3Error::Protocol("frame not allowed on a request stream"));
        }
        Piece::Skip(_) => {}
    }
    Ok(())
}

/// The parts of a [`Dl`] a piece changes.
struct DlParts<'a> {
    s: &'a mut StreamOpen,
    trailers: &'a mut bool,
    blocked: &'a mut Option<Box<Blocked>>,
}

/// Blocked responses a timeout gave up: their sections are cancelled.
fn cancel_expired(peer: &mut Peer, st: &mut State) {
    if !st.expired_blocked.is_empty() {
        for b in std::mem::take(&mut st.expired_blocked) {
            peer.blocked -= 1;
            peer.dec.cancel(sid(b));
        }
    }
}

impl ClientConn {
    fn fail_all(&mut self, why: String) {
        let mut st = self.sh.lock();
        st.closed = Some(why.clone());
        let mut kinds: Vec<Kind> = st.queue.drain(..).map(|j| j.kind).collect();
        kinds.extend(st.ws_wait.drain(..).map(|j| j.kind));
        st.deadlines.clear();
        st.expired_blocked.clear();
        for (_, mut f) in st.inflight.drain() {
            if let Some(up) = f.up() {
                up.fail();
            }
            kinds.extend(f.take_kind());
        }
        drop(st);
        for k in kinds {
            k.fail(H3Error::Closed(why.clone()));
        }
        for (_, (_, mut ws)) in self.ws.drain() {
            ws.on_transport_closed();
        }
        for (_, mut d) in self.dl.drain() {
            d.s.fail(H3Error::Closed(why.clone()));
        }
    }

    /// Feeds a response stream; what to report, once the response is complete (a WebSocket's
    /// once its head arrived).
    #[inline(always)]
    fn on_resp(&mut self, id: StreamId, data: &[u8], fin: bool) -> Option<Done> {
        if fin {
            if let Some(done) = self.whole_resp(id, data) {
                return Some(done);
            }
        }
        let mut st = self.sh.lock();
        cancel_expired(&mut self.peer, &mut st);
        let InFlight { r, resp, x, .. } = st.inflight.get_mut(&id)?;
        // A streamed response's body is not limited (what comes with its head is handed on).
        let streamed = x.as_ref().is_some_and(|x| x.st.is_some());
        let fields = &mut self.fields;
        let peer = &mut self.peer;
        let (max_body, max_field) = (self.max_body, self.cfg.max_field_section_bytes);
        let fed = r.feed(
            data,
            max_body.saturating_add(max_field) as u64,
            || H3Error::TooLarge("response frame too large"),
            |ty, p| {
                if let Some(b) = x.as_mut().and_then(|x| x.blocked.as_mut()) {
                    // Held back, in order, until the section before them can be decoded.
                    frame::put_frame(&mut b.rest, ty, p);
                    return Ok(());
                }
                match ty {
                    frame::HEADERS => {
                        match qpack::decode_section(p, max_field, &peer.dec, fields) {
                            Ok(0) => {}
                            Ok(ric) => peer.dec.section_ack(sid(id), ric),
                            Err(SectionError::Blocked(ric)) => {
                                if peer.blocked >= peer.max_blocked {
                                    return Err(H3Error::Protocol("too many blocked streams"));
                                }
                                peer.blocked += 1;
                                x.get_or_insert_with(Box::default).blocked =
                                    Some(Box::new(Blocked {
                                        ric,
                                        section: p.to_vec(),
                                        rest: Vec::new(),
                                        fin: false,
                                    }));
                                return Ok(());
                            }
                            Err(SectionError::Bad(qpack::QpackError::TooLarge)) => {
                                return Err(H3Error::TooLarge("response field section too large"));
                            }
                            Err(SectionError::Bad(_)) => {
                                return Err(H3Error::Protocol("bad field section"));
                            }
                        }
                        match resp.as_mut() {
                            None => match fields_to_response(fields) {
                                Some(r) if r.status < 200 => {}
                                Some(r) => *resp = Some(r),
                                None => return Err(H3Error::Protocol("malformed response")),
                            },
                            Some(r) => {
                                let mut t = Headers::with_capacity(fields.len(), fields.bytes());
                                for (n, v) in fields.iter() {
                                    t.append(
                                        String::from_utf8_lossy(n),
                                        String::from_utf8_lossy(v),
                                    );
                                }
                                r.trailers = Some(t);
                            }
                        }
                    }
                    frame::DATA => match resp.as_mut() {
                        Some(r) if !streamed && r.body.len() + p.len() > max_body => {
                            return Err(H3Error::TooLarge("response body too large"));
                        }
                        Some(r) => r.body.extend_from_slice(p),
                        None => return Err(H3Error::Protocol("DATA before HEADERS")),
                    },
                    _ => {}
                }
                Ok(())
            },
        );
        let err = fed.err();
        if err.is_none() {
            if let Some(b) = x.as_mut().and_then(|x| x.blocked.as_mut()) {
                b.fin |= fin;
                return None;
            }
        }
        let ws_head = resp.is_some() && x.as_ref().is_some_and(|x| x.ws.is_some() || streamed);
        if err.is_none() && !fin && !ws_head {
            return None;
        }
        let mut f = st.inflight.remove(&id)?;
        st.finished(f.token);
        if f.x.is_some() {
            if f.take_blocked().is_some() {
                self.peer.blocked -= 1;
            }
            // A streamed response goes on from its head: its request body may too.
            if !(streamed && err.is_none() && !fin) {
                if let Some(up) = f.up() {
                    up.fail();
                }
            }
        }
        let r = match (err, f.resp.take()) {
            (Some(e), _) => Err(e),
            (None, Some(r)) => Ok(r),
            (None, None) => Err(H3Error::Protocol("stream ended without a response")),
        };
        match f.take_kind()? {
            Kind::Plain(cb) => Some((cb, r)),
            Kind::Ws(w) => {
                // Started by the caller (`report`), outside the lock.
                self.ws_answer = Some(Box::new(WsAnswer {
                    w,
                    r,
                    fin,
                    reader: std::mem::take(&mut f.r),
                }));
                None
            }
            Kind::Stream(s) => {
                // Reported by the caller (`report`), outside the lock.
                self.dl_start = Some(Box::new(DlStart {
                    s,
                    r,
                    fin,
                    reader: std::mem::take(&mut f.r),
                }));
                None
            }
        }
    }

    /// A plain request's response that arrived whole as one HEADERS frame and at most one DATA
    /// frame (the usual case): decoded before the state is locked, without a frame reader.
    /// `None` leaves it to the general path: other frames, an interim or malformed head, a
    /// section that is blocked or too large, a body too large, or a stream that is not a plain
    /// request with nothing read yet.
    #[inline(always)]
    fn whole_resp(&mut self, id: StreamId, data: &[u8]) -> Option<Done> {
        let (section, rest) = frame::frame_at(data, frame::HEADERS)?;
        let body = match rest {
            [] => &[][..],
            _ => match frame::frame_at(rest, frame::DATA)? {
                (b, []) if b.len() <= self.max_body => b,
                _ => return None,
            },
        };
        let max_field = self.cfg.max_field_section_bytes;
        let ric =
            qpack::decode_section(section, max_field, &self.peer.dec, &mut self.fields).ok()?;
        let mut r = fields_to_response(&self.fields).filter(|r| r.status >= 200)?;
        let mut st = self.sh.lock();
        cancel_expired(&mut self.peer, &mut st);
        let std::collections::hash_map::Entry::Occupied(e) = st.inflight.entry(id) else {
            return None;
        };
        if !(e.get().x.is_none() && e.get().cb.is_some() && e.get().r.idle()) {
            return None;
        }
        let mut f = e.remove();
        st.finished(f.token);
        drop(st);
        if ric > 0 {
            self.peer.dec.section_ack(sid(id), ric);
        }
        r.body = body.to_vec();
        Some((f.cb.take()?, Ok(r)))
    }

    /// Reports what a response stream produced (without the state lock: callbacks may send
    /// requests).
    #[inline]
    fn report(&mut self, c: &Connection, id: StreamId, done: Option<Done>) {
        if let Some((cb, r)) = done {
            if r.is_err() {
                // Given up (maybe before the server finished): tell it to stop sending.
                let _ = c.stop(id, code::REQUEST_CANCELLED);
            }
            return cb(r);
        }
        if let Some(a) = self.ws_answer.take() {
            let WsAnswer { w, r, fin, reader } = *a;
            self.ws_open(c, id, *w, r, fin, reader);
        }
        if let Some(d) = self.dl_start.take() {
            self.dl_begin(c, id, *d);
        }
    }

    /// A streamed response's head arrived: reports it (and what came with it), then keeps the
    /// stream for its body.
    fn dl_begin(&mut self, c: &Connection, id: StreamId, d: DlStart) {
        let DlStart {
            mut s,
            r,
            fin,
            reader,
        } = d;
        let resp = match r {
            Ok(r) => r,
            Err(e) => {
                let _ = c.stop(id, code::REQUEST_CANCELLED);
                let _ = c.reset(id, code::REQUEST_CANCELLED);
                return s.fail(e);
            }
        };
        if s.up.cancelled() {
            return;
        }
        (s.ev)(H3Event::Head {
            status: resp.status,
            headers: &resp.headers,
        });
        if !resp.body.is_empty() && !s.up.cancelled() {
            (s.ev)(H3Event::Data(&resp.body));
        }
        if let Some(t) = &resp.trailers {
            if !s.up.cancelled() {
                (s.ev)(H3Event::Trailers(t));
            }
        }
        if fin {
            if !s.up.cancelled() {
                (s.ev)(H3Event::End);
            }
            return;
        }
        let trailers = resp.trailers.is_some();
        self.prune_cancelled(c);
        self.dl.insert(
            id,
            Dl {
                r: StreamReader::from(reader),
                s,
                trailers,
                blocked: None,
            },
        );
    }

    /// Drops streamed responses cancelled through their `H3Upload` whose stream will report
    /// nothing more (a server that had sent everything need not reset it).
    fn prune_cancelled(&mut self, c: &Connection) {
        if !self.dl.values().any(|d| d.s.up.cancelled()) {
            return;
        }
        let gone: Vec<StreamId> = self
            .dl
            .iter()
            .filter(|(_, d)| d.s.up.cancelled())
            .map(|(&id, _)| id)
            .collect();
        for id in gone {
            if let Some(mut d) = self.dl.remove(&id) {
                if d.blocked.take().is_some() {
                    self.peer.blocked -= 1;
                    self.peer.dec.cancel(sid(id));
                }
            }
        }
        self.peer.flush(c);
    }

    /// Bytes of a streamed response past its head; with `fresh`, they are held-back frames
    /// fed through their own reader (the stream's keeps its place).
    fn on_dl(&mut self, c: &Connection, id: StreamId, data: &[u8], fin: bool, fresh: bool) {
        let Some(d) = self.dl.get_mut(&id) else {
            return;
        };
        let was_blocked = d.blocked.is_some();
        let max_field = self.cfg.max_field_section_bytes;
        let (peer, fields) = (&mut self.peer, &mut self.fields);
        let Dl {
            r,
            s,
            trailers,
            blocked,
        } = d;
        let mut parts = DlParts {
            s,
            trailers,
            blocked,
        };
        let mut own = StreamReader::default();
        let reader = if fresh { &mut own } else { r };
        let fed = reader.feed_stream(
            data,
            max_field as u64,
            || H3Error::TooLarge("response field section too large"),
            |p| dl_piece(peer, fields, max_field, id, &mut parts, p),
        );
        let cancelled = d.s.up.cancelled();
        if fed.is_ok() && !cancelled {
            if let Some(b) = d.blocked.as_mut() {
                b.fin |= fin;
                if !was_blocked {
                    // Nothing more is read until the inserts arrive (flow control bounds it).
                    let _ = c.hold_reads(id, true);
                }
                return;
            }
            if !fin {
                return;
            }
        }
        let Some(mut d) = self.dl.remove(&id) else {
            return;
        };
        if d.blocked.take().is_some() {
            self.peer.blocked -= 1;
            self.peer.dec.cancel(sid(id));
        }
        d.s.up.fail();
        match fed {
            _ if cancelled => {}
            Err(e) => {
                let _ = c.stop(id, code::REQUEST_CANCELLED);
                let _ = c.reset(id, code::REQUEST_CANCELLED);
                d.s.fail(e);
            }
            Ok(()) => (d.s.ev)(H3Event::End),
        }
    }

    /// Checks a WebSocket's answer and starts it.
    fn ws_open(
        &mut self,
        c: &Connection,
        id: StreamId,
        w: WsOpen,
        r: Result<Response, H3Error>,
        fin: bool,
        reader: Reader,
    ) {
        let checked = r.and_then(|resp| {
            if !(200..300).contains(&resp.status) {
                return Err(H3Error::Status(resp.status));
            }
            let mut protos = resp.headers.get_all("sec-websocket-protocol");
            let protocol = match (protos.next(), protos.next()) {
                (None, _) => None,
                (Some(p), None) if w.protocols.iter().any(|o| o == p) => Some(p.to_owned()),
                _ => {
                    return Err(H3Error::Protocol(
                        "server selected a subprotocol that was not offered",
                    ));
                }
            };
            let pmd = match &w.pmd {
                Some(offer) => offer
                    .accept_response(resp.headers.get_all("sec-websocket-extensions"))
                    .map_err(H3Error::Protocol)?,
                None => {
                    if resp
                        .headers
                        .get_all("sec-websocket-extensions")
                        .any(|v| !v.is_empty())
                    {
                        return Err(H3Error::Protocol(
                            "server accepted an extension that was not offered",
                        ));
                    }
                    None
                }
            };
            Ok((resp.body, protocol, pmd))
        });
        let (early, protocol, pmd) = match checked {
            Ok(v) => v,
            Err(e) => {
                let _ = c.stop(id, code::REQUEST_CANCELLED);
                let _ = c.reset(id, code::REQUEST_CANCELLED);
                return (w.done)(Err(e));
            }
        };
        let link = Arc::new(StreamLink::new(c.clone(), id));
        let mut ws =
            WsSession::client_with_link(link, &w.cfg, pmd, w.handler, protocol, w.close_timeout);
        let sender = ws.sender().clone();
        ws.open();
        if !early.is_empty() {
            ws.on_data(&early);
        }
        if fin {
            ws.on_transport_closed();
        } else {
            self.ws.insert(id, (StreamReader::from(reader), ws));
        }
        (w.done)(Ok(sender));
    }

    /// Bytes of an open WebSocket's stream.
    fn on_ws(&mut self, c: &Connection, id: StreamId, data: &[u8], fin: bool) {
        let Some((r, ws)) = self.ws.get_mut(&id) else {
            return;
        };
        let fed = r.feed_stream(
            data,
            self.cfg.max_field_section_bytes as u64,
            || (),
            |p| {
                match p {
                    Piece::Data(d) => ws.on_data(d),
                    // Trailers end nothing; unknown frames are skipped.
                    Piece::Headers(_) => {}
                    Piece::Skip(t) if crate::h2_only(t) || t == frame::SETTINGS => return Err(()),
                    Piece::Skip(_) => {}
                }
                Ok(())
            },
        );
        if fed.is_err() {
            c.close(code::FRAME_UNEXPECTED, b"");
        }
        if fin || fed.is_err() {
            if let Some((_, mut ws)) = self.ws.remove(&id) {
                ws.on_transport_closed();
            }
        }
    }

    /// Responses whose field sections the last inserts made decodable go on.
    fn unblock(&mut self, c: &Connection) {
        if !std::mem::take(&mut self.peer.inserted) || self.peer.blocked == 0 {
            return;
        }
        let have = self.peer.dec.inserted();
        // Streamed responses' trailers.
        let dl_ready: Vec<StreamId> = self
            .dl
            .iter()
            .filter(|(_, d)| d.blocked.as_ref().is_some_and(|b| b.ric <= have))
            .map(|(&id, _)| id)
            .collect();
        for id in dl_ready {
            let Some(b) = self.dl.get_mut(&id).and_then(|d| d.blocked.take()) else {
                continue;
            };
            self.peer.blocked -= 1;
            let mut data = Vec::with_capacity(b.section.len() + b.rest.len() + 9);
            frame::put_frame(&mut data, frame::HEADERS, &b.section);
            data.extend_from_slice(&b.rest);
            self.on_dl(c, id, &data, b.fin, true);
            if let Some(d) = self.dl.get(&id) {
                if d.blocked.is_none() {
                    d.s.up.restore_hold(id);
                }
            }
        }
        let ready: Vec<StreamId> = self
            .sh
            .lock()
            .inflight
            .iter()
            .filter(|(_, f)| f.blocked().is_some_and(|b| b.ric <= have))
            .map(|(&id, _)| id)
            .collect();
        for id in ready {
            let (b, held) = {
                let mut st = self.sh.lock();
                let Some(f) = st.inflight.get_mut(&id) else {
                    continue;
                };
                let Some(b) = f.take_blocked() else { continue };
                (b, std::mem::take(&mut f.r))
            };
            self.peer.blocked -= 1;
            let mut data = Vec::with_capacity(b.section.len() + b.rest.len() + 9);
            frame::put_frame(&mut data, frame::HEADERS, &b.section);
            data.extend_from_slice(&b.rest);
            // The held-back frames come before whatever the stream's reader still holds.
            let mut done = self.on_resp(id, &data, false);
            if let Some(f) = self.sh.lock().inflight.get_mut(&id) {
                f.r = held;
            } else if let Some(d) = self.dl_start.as_mut() {
                d.reader = held;
                d.fin |= b.fin;
            }
            if done.is_none() && self.ws_answer.is_none() && self.dl_start.is_none() && b.fin {
                done = self.on_resp(id, &[], true);
            }
            self.report(c, id, done);
        }
    }
}

impl QuicHandler for ClientConn {
    fn on_connected(&mut self, c: &Connection) {
        self.peer
            .open(c, crate::control_stream_preamble(&self.cfg, false));
        self.sh.lock().ready = true;
        start_queued(c, &self.sh);
    }

    fn on_stream_opened(&mut self, _c: &Connection, id: StreamId) {
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
                if let Err(e) = crate::on_uni(u, &mut self.peer, &mut stop, id, &data, fin, false) {
                    c.close(e, b"");
                    return;
                }
                if self.peer.new_settings {
                    self.on_settings(c);
                }
                self.unblock(c);
                self.peer.dec.increment();
                self.peer.after(c);
                if let Some(e) = &self.peer.enc {
                    let _ = self.sh.enc.set(e.clone());
                }
            }
            return;
        }
        if !self.ws.is_empty() && self.ws.contains_key(&id) {
            return self.on_ws(c, id, &data, fin);
        }
        if !self.dl.is_empty() && self.dl.contains_key(&id) {
            self.on_dl(c, id, &data, fin, false);
            return self.peer.flush(c);
        }
        match self.on_resp(id, &data, fin) {
            Some((cb, r)) => {
                if r.is_err() && !fin {
                    // Given up before the server finished: tell it to stop sending.
                    let _ = c.stop(id, code::REQUEST_CANCELLED);
                }
                cb(r);
            }
            None if self.ws_answer.is_some() || self.dl_start.is_some() => {
                self.report(c, id, None);
            }
            None => {}
        }
        self.peer.flush(c);
    }

    fn on_stream_reset(&mut self, c: &Connection, id: StreamId, code: u64) {
        if let Some((_, mut ws)) = self.ws.remove(&id) {
            return ws.on_transport_closed();
        }
        if let Some(mut d) = self.dl.remove(&id) {
            if d.blocked.take().is_some() {
                self.peer.blocked -= 1;
                self.peer.dec.cancel(sid(id));
                self.peer.flush(c);
            }
            return d.s.fail(H3Error::Reset(code));
        }
        let f = {
            let mut st = self.sh.lock();
            let f = st.inflight.remove(&id);
            if let Some(f) = &f {
                st.finished(f.token);
            }
            f
        };
        if let Some(mut f) = f {
            if f.take_blocked().is_some() {
                self.peer.blocked -= 1;
                self.peer.dec.cancel(sid(id));
                self.peer.flush(c);
            }
            if let Some(up) = f.up() {
                up.fail();
            }
            if let Some(k) = f.take_kind() {
                k.fail(H3Error::Reset(code));
            }
        }
    }

    fn on_stream_writable(&mut self, _c: &Connection, id: StreamId) {
        // An upload whose writes were refused goes on.
        let up = match self.dl.get(&id) {
            Some(d) => Some(d.s.up.clone()),
            None => self
                .sh
                .lock()
                .inflight
                .get(&id)
                .and_then(|f| f.up().cloned()),
        };
        if let Some(up) = up {
            let mut u = up.lock();
            up.flush(&mut u);
        }
    }

    fn on_streams_available(&mut self, c: &Connection, _dir: Dir) {
        start_queued(c, &self.sh);
    }

    fn on_close(&mut self, _c: &Connection, reason: ConnectionError) {
        self.fail_all(reason.to_string());
    }
}

impl ClientConn {
    /// The server's SETTINGS arrived: WebSockets waiting for them go (or fail).
    fn on_settings(&self, c: &Connection) {
        let s = self.peer.settings.unwrap_or_default();
        let mut st = self.sh.lock();
        st.settings = Some(s);
        let waiting = std::mem::take(&mut st.ws_wait);
        if s.connect_protocol {
            st.queue.extend(waiting);
            let ready = st.ready;
            drop(st);
            if ready {
                start_queued(c, &self.sh);
            }
        } else {
            drop(st);
            for j in waiting {
                j.kind
                    .fail(H3Error::Protocol("server does not allow extended CONNECT"));
            }
        }
    }
}
/// Request deadlines: one lazily started thread with a heap, fed through a channel. Jobs only
/// fail requests and reset their streams. A connection has at most one job pending (see
/// `arm`), so requests cost no timer message.
mod timer {
    use std::{
        cmp::Reverse,
        collections::BinaryHeap,
        sync::{
            OnceLock,
            mpsc::{self, RecvTimeoutError, Sender},
        },
        time::Instant,
    };

    type Job = Box<dyn FnOnce() + Send>;

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
                .name("akio-h3-timer".into())
                .spawn(move || run(&rx))
                .expect("spawn akio-h3 timer thread");
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

    /// Runs `job` on the timer thread at `at`.
    pub(super) fn at(at: Instant, job: impl FnOnce() + Send + 'static) {
        let _ = sender().send((at, Box::new(job)));
    }
}
