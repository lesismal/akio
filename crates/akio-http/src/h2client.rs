//! An HTTP/2 client: one connection multiplexing many concurrent requests, with flow control
//! both ways, trailers and (optionally) server push.
//!
//! ```no_run
//! # use akio::Engine; use akio_http::{client::ClientRequest, h2client::{H2Client, H2Options}};
//! # let engine = Engine::builder().client_threads(1).build().unwrap(); engine.start().unwrap();
//! let c = H2Client::dial_blocking(&engine, "127.0.0.1:8082".parse().unwrap(), None, H2Options::default())
//!     .unwrap();
//! let r = c.send(ClientRequest::get("http://127.0.0.1:8082/")).wait().unwrap();
//! ```
//!
//! Callbacks run on an I/O thread and must not block.
//!
//! Responses are bounded by [`H2Options`]: frames by the default `SETTINGS_MAX_FRAME_SIZE`
//! (16 KiB), header lists by `max_header_list` (64 KiB, advertised), buffered bodies by
//! `max_body_bytes` (64 MiB). Request timeouts are [`ClientRequest::timeout`].
//!
//! [`H2Client::websocket`] opens a WebSocket on a stream of the connection (RFC 8441 extended
//! CONNECT), next to the connection's other requests.
//!
//! A streamed request ([`H2Client::open`], ADR-110) can be reset ([`H2Stream::cancel`]) and timed
//! ([`ClientRequest::timeout`]), its response's reads held ([`H2Stream::hold_reads`]: the
//! stream's window is not given back), its body paced ([`H2Upload::queued_bytes`],
//! [`H2Upload::on_drain`]) and ended with trailers ([`H2Upload::finish_with_trailers`]). The
//! client heeds the server's `SETTINGS_MAX_CONCURRENT_STREAMS`
//! ([`H2Client::max_concurrent_streams`]): a request past it waits for a stream, within
//! [`H2Options::max_pending_streams`]. After the server's `GOAWAY`, [`H2Client::is_open`] is
//! `false` and the requests it did not process fail with [`ClientError::Refused`].
//!
//! Requests heed [`ClientRequest::response_header_timeout`] (from the request's END_STREAM to
//! the final response's HEADERS), [`ClientRequest::response_idle_timeout`] (the longest gap
//! between DATA frames from the head on, held reads not counted) and
//! [`ClientRequest::cancel`] (ADR-111): each resets the stream (`CANCEL`) and fails the request
//! with [`ClientError::HeaderTimeout`], [`ClientError::IdleTimeout`] or
//! [`ClientError::Cancelled`], once, leaving the connection to its other streams.

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use akio_ws::{WsConfig, WsHandler, WsLink, WsSender, WsSession, deflate::PmdOffer};

use crate::hpack::{Decoder, Encoder};
use akio::{
    Acceptor, Conn, Engine, Handler,
    tls::{ClientConfig as TlsClientConfig, Tls},
};

use crate::{
    client::{
        ClientError, ClientRequest, ClientResponse, FutureShared, Outcome, ResponseFuture,
        parse_url,
    },
    h2::{DEFAULT_FRAME, DEFAULT_WINDOW, MAX_WINDOW, PREFACE, err, flag, frame, ty},
    message::{Headers, Method},
};

/// Connection options.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H2Options {
    /// Receive window per stream.
    pub initial_window: u32,
    /// Receive window of the connection.
    pub conn_window: u32,
    /// Accept server push (`ClientResponse::pushed` then carries the pushed responses).
    pub enable_push: bool,
    /// Largest response header list (uncompressed: name + value + 32 per field), advertised as
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`. A larger response fails its request with
    /// [`ClientError::TooLarge`]; a header block (HEADERS + CONTINUATION) whose compressed
    /// size passes twice this (at least 64 KiB) ends the connection. Default 64 KiB.
    pub max_header_list: u32,
    /// Largest buffered response body ([`request`](H2Client::request),
    /// [`send`](H2Client::send), pushed responses); past it the stream is reset and the request
    /// fails with [`ClientError::TooLarge`]. Streamed responses ([`open`](H2Client::open)) are
    /// handed over as they arrive and not limited. Default 64 MiB.
    pub max_body_bytes: usize,
    /// Bytes a streamed request's body ([`H2Upload`]) may hold, written and not yet in a DATA
    /// frame (the stream's or the connection's window is closed), before writes fail
    /// (`Overloaded` from [`H2Upload::try_write`], `false` from [`H2Upload::write`]); a write is
    /// taken whatever its size when nothing is queued. Pace a producer with
    /// [`H2Upload::queued_bytes`] and [`H2Upload::on_drain`] well below it. Default 64 MiB.
    pub max_queued_bytes: usize,
    /// Requests (and streamed requests) that may wait in the client for a stream while the
    /// connection has as many open as the server's `SETTINGS_MAX_CONCURRENT_STREAMS` allows;
    /// past it a request fails with [`ClientError::Busy`] at once. `0` fails every request past
    /// the server's limit. They start in order as streams end; a waiting request's timeout and
    /// cancel apply. Default 1024.
    pub max_pending_streams: usize,
    /// How [`H2Client::connect`] races the addresses of its host, and how long one connect may
    /// take ([`akio::dns::HappyEyeballs::connect_timeout`], 10 s by default).
    /// [`H2Client::dial`] uses the engine's connect timeout.
    pub happy_eyeballs: akio::dns::HappyEyeballs,
}

impl Default for H2Options {
    fn default() -> Self {
        H2Options {
            initial_window: 1 << 20,
            conn_window: 1 << 24,
            enable_push: false,
            max_header_list: 64 << 10,
            max_body_bytes: 64 << 20,
            max_queued_bytes: 64 << 20,
            max_pending_streams: 1024,
            happy_eyeballs: akio::dns::HappyEyeballs::default(),
        }
    }
}

/// How [`H2Client::websocket`] opens a WebSocket over HTTP/2 (RFC 8441).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H2WsOptions {
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
    /// resetting it from this side. Default 3 s.
    pub close_timeout: Duration,
    /// How long to wait for the server's SETTINGS and its answer; past it the stream is reset
    /// (`CANCEL`) and the WebSocket fails with [`ClientError::Timeout`]. Default 10 s.
    pub timeout: Duration,
    /// Bytes the WebSocket may hold for the server (not yet written to the connection, because
    /// the stream's or the connection's window is closed) before sends fail with
    /// `Overloaded` (a message is taken whatever its size when nothing is queued):
    /// [`WsSender::queued_bytes`] paces a producer. Default 8 MiB.
    pub max_queued_bytes: usize,
}

impl Default for H2WsOptions {
    fn default() -> H2WsOptions {
        H2WsOptions {
            config: WsConfig::default(),
            pmd: PmdOffer::default(),
            protocols: Vec::new(),
            origin: None,
            headers: Vec::new(),
            close_timeout: Duration::from_secs(3),
            timeout: Duration::from_secs(10),
            max_queued_bytes: 8 << 20,
        }
    }
}

type WsDone = Box<dyn FnOnce(Result<WsSender, ClientError>) + Send>;

/// The callback of a WebSocket being opened, taken once: by the answer or by the timeout.
#[derive(Clone)]
struct WsOnce(Arc<Mutex<Option<WsDone>>>);

impl WsOnce {
    fn take(&self) -> Option<WsDone> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    fn fail(&self, e: ClientError) {
        if let Some(cb) = self.take() {
            cb(Err(e));
        }
    }
}

/// A WebSocket being opened.
struct WsOpen {
    url: String,
    /// Regular request fields (lowercase names).
    fields: Vec<(String, String)>,
    handler: Box<dyn WsHandler>,
    cfg: WsConfig,
    pmd: Option<PmdOffer>,
    protocols: Vec<String>,
    close_timeout: Duration,
    max_queued: usize,
    done: WsOnce,
    /// The stream it got (0 until started), for the timeout to cancel.
    sid: Arc<AtomicU32>,
}

/// The WebSocket on a stream. Dropped with its stream, whatever ended it: the opener then
/// hears [`ClientError::Closed`], an open session `on_close` (1006 unless the close handshake
/// ended it).
struct CWs(WsState);

enum WsState {
    Opening(Box<WsOpen>),
    Open(Box<WsSession>, Arc<LinkShared>),
    Gone,
}

impl CWs {
    fn fail(&mut self, e: ClientError) {
        match std::mem::replace(&mut self.0, WsState::Gone) {
            WsState::Opening(w) => w.done.fail(e),
            WsState::Open(mut s, sh) => {
                sh.closed.store(true, Ordering::Release);
                s.on_transport_closed();
            }
            WsState::Gone => {}
        }
    }
}

impl Drop for CWs {
    fn drop(&mut self) {
        self.fail(ClientError::Closed);
    }
}

/// What a WebSocket's sender queued for its stream, moved there on the I/O thread.
struct LinkShared {
    q: Mutex<LinkQ>,
    /// Bytes accepted by `send` and not yet handed to the connection.
    queued: AtomicUsize,
    max: usize,
    closed: AtomicBool,
}

#[derive(Default)]
struct LinkQ {
    chunks: VecDeque<Vec<u8>>,
    end: LinkEnd,
    /// A pump is on its way to the I/O thread.
    scheduled: bool,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum LinkEnd {
    #[default]
    No,
    /// END_STREAM after what is queued.
    Graceful,
    /// END_STREAM if the server ended its half, else `RST_STREAM CANCEL`.
    Now,
}

/// The stream of a WebSocket over HTTP/2, client side.
struct ClientLink {
    conn: Conn<H2Conn>,
    sid: u32,
    sh: Arc<LinkShared>,
}

impl ClientLink {
    fn lock(&self) -> std::sync::MutexGuard<'_, LinkQ> {
        self.sh.q.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Has the I/O thread move what is queued to the stream (once per batch).
    fn kick(&self) -> akio::Result<()> {
        let (sid, sh) = (self.sid, self.sh.clone());
        self.conn
            .spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.ws_pump(c, sid, &sh))
    }

    fn end(&self, end: LinkEnd) {
        self.sh.closed.store(true, Ordering::Release);
        let mut q = self.lock();
        q.end = q.end.max(end);
        if !std::mem::replace(&mut q.scheduled, true) {
            drop(q);
            if self.kick().is_err() {
                self.lock().scheduled = false;
            }
        }
    }
}

impl WsLink for ClientLink {
    fn send(&self, data: Vec<u8>) -> akio::Result<()> {
        if self.sh.closed.load(Ordering::Acquire) || !self.conn.is_open() {
            return Err(akio::Error::Closed);
        }
        let n = data.len();
        // One message is taken whatever its size when nothing is queued.
        let queued = self.sh.queued.load(Ordering::Acquire);
        if queued > 0 && queued + n > self.sh.max {
            return Err(akio::Error::Overloaded);
        }
        let mut q = self.lock();
        q.chunks.push_back(data);
        self.sh.queued.fetch_add(n, Ordering::AcqRel);
        if std::mem::replace(&mut q.scheduled, true) {
            return Ok(());
        }
        drop(q);
        if let Err(e) = self.kick() {
            // Not handed over: take the bytes back (sends of one sender are serialized).
            let mut q = self.lock();
            q.scheduled = false;
            q.chunks.pop_back();
            self.sh.queued.fetch_sub(n, Ordering::AcqRel);
            return Err(match e {
                akio::Error::Overloaded => akio::Error::Overloaded,
                _ => akio::Error::Closed,
            });
        }
        Ok(())
    }

    fn close_after_send(&self) {
        self.end(LinkEnd::Graceful);
    }

    fn close(&self) {
        self.end(LinkEnd::Now);
    }

    fn is_open(&self) -> bool {
        !self.sh.closed.load(Ordering::Acquire) && self.conn.is_open()
    }

    fn queued_bytes(&self) -> usize {
        self.sh.queued.load(Ordering::Acquire)
    }
}

/// Pushed responses outstanding per request; further promises are refused.
const MAX_PUSHES_PER_STREAM: u32 = 32;

type Callback = Box<dyn FnOnce(Outcome) + Send>;
type EventCb = Box<dyn FnMut(H2Event<'_>) + Send>;

/// What a streamed request ([`H2Client::open`]) reports as the response arrives.
pub enum H2Event<'a> {
    /// The response head.
    Head {
        /// Status code.
        status: u16,
        /// Header fields.
        headers: &'a Headers,
    },
    /// Body bytes, as they arrive.
    Data(&'a [u8]),
    /// Trailer fields.
    Trailers(&'a Headers),
    /// The response is complete.
    End,
    /// The stream failed: reset by the server, refused ([`ClientError::Refused`]), cancelled
    /// ([`ClientError::Cancelled`]), timed out ([`ClientError::Timeout`],
    /// [`ClientError::HeaderTimeout`], [`ClientError::IdleTimeout`]), or its connection lost.
    /// Nothing follows it.
    Error(ClientError),
}

impl<'a> std::fmt::Debug for H2Event<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Event").finish_non_exhaustive()
    }
}

const STOP_NONE: u8 = 0;
const STOP_CANCEL: u8 = 1;
const STOP_TIMEOUT: u8 = 2;
const STOP_HEADER: u8 = 3;
const STOP_IDLE: u8 = 4;

/// Where a request's response is, for its header and idle timeouts (ADR-111).
const PHASE_NONE: u8 = 0;
/// The request ended (END_STREAM sent): the header timeout runs.
const PHASE_HEAD: u8 = 1;
/// The response's head came: the idle timeout runs.
const PHASE_BODY: u8 = 2;
/// The stream is over.
const PHASE_OVER: u8 = 3;

/// Milliseconds on a monotonic clock, for the idle timeout's last activity.
fn now_ms() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let e = *EPOCH.get_or_init(std::time::Instant::now);
    u64::try_from(e.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What a request's stream and the threads that cancel, time or hold it share.
#[derive(Default)]
struct StreamCtl {
    /// The stream it got (0 until it started).
    sid: AtomicU32,
    /// Why it is to be given up (`STOP_*`); set once.
    stop: AtomicU8,
    /// Its response's reads are held: the stream's window is not given back.
    held: AtomicBool,
    /// [`ClientRequest::response_header_timeout`].
    header_timeout: Option<Duration>,
    /// [`ClientRequest::response_idle_timeout`].
    idle_timeout: Option<Duration>,
    /// `PHASE_*`: which of the two runs.
    phase: AtomicU8,
    /// When the response last made progress ([`now_ms`]): its head, a DATA frame, the end of
    /// a hold.
    last: AtomicU64,
}

impl StreamCtl {
    /// The control of `req`'s stream, with its header and idle timeouts.
    fn of(req: &ClientRequest) -> StreamCtl {
        StreamCtl {
            header_timeout: req.response_header_timeout,
            idle_timeout: req.response_idle_timeout,
            ..StreamCtl::default()
        }
    }

    /// The response progressed: the idle timeout starts over.
    fn touch(&self) {
        if self.idle_timeout.is_some() {
            self.last.store(now_ms(), Ordering::Release);
        }
    }

    /// Ties the request to its cancel token, if it has one: a token cancelled already gives
    /// the request up at once.
    fn attach(self: &Arc<Self>, req: &ClientRequest, conn: &Conn<H2Conn>) {
        if let Some(t) = &req.cancel {
            let target = CancelTarget {
                ctl: Arc::downgrade(self),
                conn: conn.clone(),
            };
            if !t.attach_h2(target) {
                self.give_up(STOP_CANCEL);
            }
        }
    }
    /// Asks for the stream to be given up for `why`: `false` when it was asked already.
    fn give_up(&self, why: u8) -> bool {
        self.stop
            .compare_exchange(STOP_NONE, why, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Why it was given up, if it was.
    fn reason(&self) -> Option<ClientError> {
        match self.stop.load(Ordering::Acquire) {
            STOP_NONE => None,
            STOP_TIMEOUT => Some(ClientError::Timeout),
            STOP_HEADER => Some(ClientError::HeaderTimeout),
            STOP_IDLE => Some(ClientError::IdleTimeout),
            _ => Some(ClientError::Cancelled),
        }
    }
}

type DrainCb = Box<dyn FnOnce() + Send>;

/// The request body of a streamed request, between its writers and its stream.
struct UpShared {
    ctl: Arc<StreamCtl>,
    q: Mutex<UpQ>,
    /// Bytes written and not yet in a DATA frame.
    queued: AtomicUsize,
    max: usize,
    /// The stream is over: nothing more is taken, nothing waits.
    closed: AtomicBool,
    drain: Mutex<Option<DrainCb>>,
}

#[derive(Default)]
struct UpQ {
    chunks: VecDeque<Vec<u8>>,
    finished: bool,
    trailers: Option<Headers>,
    /// A pump is on its way to the I/O thread.
    scheduled: bool,
}

impl UpShared {
    fn lock(&self) -> std::sync::MutexGuard<'_, UpQ> {
        self.q.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn take_drain(&self) -> Option<DrainCb> {
        self.drain.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// `n` queued bytes went into a DATA frame: the drain waiter, if that emptied the queue.
    fn sent(&self, n: usize) -> Option<DrainCb> {
        if n > 0 && self.queued.fetch_sub(n, Ordering::AcqRel) == n {
            return self.take_drain();
        }
        None
    }

    /// The stream is over (or never started): writes fail, a drain waiter runs.
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.queued.store(0, Ordering::Release);
        if let Some(f) = self.take_drain() {
            f();
        }
    }
}

/// A streamed request's body as its stream holds it: dropped with the stream, it closes the body.
struct UpLink(Arc<UpShared>);

impl Drop for UpLink {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// The request body of a streamed request ([`H2Client::open`]): write pieces, then finish.
/// Usable from any thread.
///
/// What is written waits in the stream until its flow-control window and the connection's let
/// it go out; [`queued_bytes`](Self::queued_bytes) and [`on_drain`](Self::on_drain) pace a
/// producer, and writes fail past [`H2Options::max_queued_bytes`]. Dropping it unfinished leaves
/// the request body open (as before ADR-110): finish it, or [`cancel`](Self::cancel) the stream.
pub struct H2Upload {
    conn: Conn<H2Conn>,
    up: Arc<UpShared>,
}

impl std::fmt::Debug for H2Upload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Upload").finish_non_exhaustive()
    }
}

impl H2Upload {
    /// Has the I/O thread move what is queued into the stream (once per batch).
    fn kick(&self) -> bool {
        let mut q = self.up.lock();
        if std::mem::replace(&mut q.scheduled, true) {
            return true;
        }
        drop(q);
        let up = self.up.clone();
        let ok = self
            .conn
            .spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.pump(c, &up))
            .is_ok();
        if !ok {
            self.up.lock().scheduled = false;
        }
        ok
    }

    /// Queues body bytes. `false` if they were not taken: the stream is over, the body
    /// finished, the connection gone, or [`H2Options::max_queued_bytes`] would be passed
    /// ([`try_write`](Self::try_write) tells which).
    pub fn write(&self, data: &[u8]) -> bool {
        self.try_write(data).is_ok()
    }

    /// Queues body bytes: `Err(Closed)` when the stream is over (ended, reset, cancelled, timed
    /// out), the body finished or the connection gone; `Err(Overloaded)` when they would pass
    /// [`H2Options::max_queued_bytes`] (a write is taken whatever its size when nothing is
    /// queued).
    pub fn try_write(&self, data: &[u8]) -> akio::Result<()> {
        if self.up.closed.load(Ordering::Acquire)
            || self.up.ctl.stop.load(Ordering::Acquire) != STOP_NONE
        {
            return Err(akio::Error::Closed);
        }
        if data.is_empty() {
            return Ok(());
        }
        let n = data.len();
        let queued = self.up.queued.load(Ordering::Acquire);
        if queued > 0 && queued + n > self.up.max {
            return Err(akio::Error::Overloaded);
        }
        {
            let mut q = self.up.lock();
            if q.finished {
                return Err(akio::Error::Closed);
            }
            q.chunks.push_back(data.to_vec());
            self.up.queued.fetch_add(n, Ordering::AcqRel);
        }
        if self.kick() {
            Ok(())
        } else {
            Err(akio::Error::Closed)
        }
    }

    /// Bytes written and not yet sent in a DATA frame (waiting for the stream's or the
    /// connection's window); 0 once the stream is over.
    pub fn queued_bytes(&self) -> usize {
        self.up.queued.load(Ordering::Acquire)
    }

    /// Calls `f` once nothing written waits any more (all of it in DATA frames), or when the
    /// stream is over: at once, on this thread, if that is so already, otherwise on the
    /// connection's I/O thread. Replaces an earlier waiter.
    pub fn on_drain(&self, f: impl FnOnce() + Send + 'static) {
        let mut d = self.up.drain.lock().unwrap_or_else(|p| p.into_inner());
        if self.up.queued.load(Ordering::Acquire) == 0 || self.up.closed.load(Ordering::Acquire) {
            drop(d);
            return f();
        }
        *d = Some(Box::new(f));
    }

    /// Ends the request body. `false` if the stream is over, the body was finished already or
    /// the connection is gone.
    pub fn finish(&self) -> bool {
        self.finish_with_trailers(Headers::new())
    }

    /// Ends the request body with trailer fields (a HEADERS frame after the body, ending the
    /// stream; gRPC's, say). Names are sent in lowercase; pseudo-fields and connection-specific
    /// fields are dropped. With no fields, as [`finish`](Self::finish).
    pub fn finish_with_trailers(&self, trailers: Headers) -> bool {
        if self.up.closed.load(Ordering::Acquire)
            || self.up.ctl.stop.load(Ordering::Acquire) != STOP_NONE
        {
            return false;
        }
        {
            let mut q = self.up.lock();
            if std::mem::replace(&mut q.finished, true) {
                return false;
            }
            if !trailers.is_empty() {
                q.trailers = Some(trailers);
            }
        }
        self.kick()
    }

    /// The stream's handle: cancel it, hold its response's reads.
    pub fn stream(&self) -> H2Stream {
        H2Stream {
            conn: self.conn.clone(),
            ctl: self.up.ctl.clone(),
        }
    }

    /// Resets the stream ([`H2Stream::cancel`]).
    pub fn cancel(&self) {
        self.stream().cancel();
    }
}

/// A streamed request's stream ([`H2Upload::stream`]): reset it, hold its response's reads.
/// Cheap to clone and usable from any thread; it does nothing once the stream is over.
#[derive(Clone)]
pub struct H2Stream {
    conn: Conn<H2Conn>,
    ctl: Arc<StreamCtl>,
}

impl std::fmt::Debug for H2Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Stream")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl H2Stream {
    /// Gives the request up: the stream is reset (`RST_STREAM CANCEL`) and `on_event` gets
    /// [`H2Event::Error`] with [`ClientError::Cancelled`], once, on the connection's I/O thread,
    /// unless the stream was over (or a timeout gave it up first). A request still waiting for a
    /// stream is dropped unsent. Later writes to its body fail.
    pub fn cancel(&self) {
        if self.ctl.give_up(STOP_CANCEL) {
            let ctl = self.ctl.clone();
            let _ = self
                .conn
                .spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.stop(c, &ctl));
        }
    }

    /// Holds (`true`) or resumes (`false`) the response's reads: while held, the stream's
    /// receive window is not given back, so the server stops once it has sent the window it
    /// had ([`H2Options::initial_window`]); DATA already in flight still arrives and is handed
    /// over. Resumed, what was consumed meanwhile is given back at once. The connection's
    /// window is given back as before, so the connection's other streams go on.
    pub fn hold_reads(&self, hold: bool) {
        self.ctl.held.store(hold, Ordering::Release);
        if !hold {
            // The time held does not count toward the idle timeout.
            self.ctl.touch();
            let ctl = self.ctl.clone();
            let _ = self
                .conn
                .spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.release(c, &ctl));
        }
    }

    /// The stream's id, 0 while the request waits for a stream (or if it never got one).
    pub fn id(&self) -> u32 {
        self.ctl.sid.load(Ordering::Acquire)
    }
}

/// A request's stream as a [`CancelToken`](crate::client::CancelToken) holds it (ADR-111).
pub(crate) struct CancelTarget {
    ctl: std::sync::Weak<StreamCtl>,
    conn: Conn<H2Conn>,
}

impl CancelTarget {
    /// Whether the request may still be given up (its control is not gone).
    pub(crate) fn alive(&self) -> bool {
        self.ctl.strong_count() > 0
    }

    /// As [`H2Stream::cancel`].
    pub(crate) fn cancel(&self) {
        if let Some(ctl) = self.ctl.upgrade() {
            H2Stream {
                conn: self.conn.clone(),
                ctl,
            }
            .cancel();
        }
    }
}

impl StreamCtl {
    /// In the body phase, how long until the idle timeout is due, or `None` when it is: the
    /// whole timeout while the reads are held (the time held does not count).
    fn idle_left(&self) -> Option<Duration> {
        let d = self.idle_timeout?;
        if self.held.load(Ordering::Acquire) {
            return Some(d);
        }
        let since = now_ms().saturating_sub(self.last.load(Ordering::Acquire));
        let d_ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        (since < d_ms).then(|| Duration::from_millis(d_ms - since))
    }
}

/// Checks `ctl`'s header or idle timeout (`phase`) `d` from now: on the timer thread first,
/// which re-arms an idle timeout the response's progress pushed back; then, when it looks due,
/// on the connection's I/O thread, which gives the stream up (or re-arms it). One check is
/// pending per stream at a time; none once the phase changed or the stream is over.
fn arm(conn: Conn<H2Conn>, ctl: &Arc<StreamCtl>, phase: u8, d: Duration) {
    let weak = Arc::downgrade(ctl);
    crate::timer::after(d, move || {
        let Some(ctl) = weak.upgrade() else { return };
        if ctl.phase.load(Ordering::Acquire) != phase
            || ctl.stop.load(Ordering::Acquire) != STOP_NONE
        {
            return;
        }
        if phase == PHASE_BODY {
            if let Some(wait) = ctl.idle_left() {
                return arm(conn, &ctl, phase, wait);
            }
        }
        let _ = conn.spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.expire(c, &ctl, phase));
    });
}

/// What a connection's handler and its [`H2Client`]s share.
#[derive(Debug)]
struct ClientShared {
    /// A GOAWAY came (or was sent): no new streams.
    goaway: AtomicBool,
    /// The server's `SETTINGS_MAX_CONCURRENT_STREAMS` (`u32::MAX` until it says).
    max_streams: AtomicU32,
    /// Streams this client opened that are not over.
    open: AtomicU32,
    /// Requests waiting for a stream.
    waiting: AtomicU32,
    /// [`H2Options::max_queued_bytes`].
    max_queued: usize,
}

/// One open stream of [`ClientShared::open`], counted down when its stream goes.
struct OpenSlot(Arc<ClientShared>);

impl OpenSlot {
    fn new(sh: &Arc<ClientShared>) -> OpenSlot {
        sh.open.fetch_add(1, Ordering::AcqRel);
        OpenSlot(sh.clone())
    }
}

impl Drop for OpenSlot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A dial over TLS failed because the server did not choose `h2` in ALPN (ADR-110): the
/// `io::Error`'s inner error ([`NotH2::of`]). A caller may then speak HTTP/1.1 to it
/// ([`crate::client::Client`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotH2 {
    /// The protocol the server chose, or `None` when it chose none.
    pub alpn: Option<Vec<u8>>,
}

impl NotH2 {
    /// The [`NotH2`] inside `e`, if that is why a dial failed.
    pub fn of(e: &io::Error) -> Option<&NotH2> {
        e.get_ref().and_then(|e| e.downcast_ref::<NotH2>())
    }

    fn error(alpn: Option<Vec<u8>>) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, NotH2 { alpn })
    }
}

impl std::fmt::Display for NotH2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.alpn {
            Some(p) => write!(
                f,
                "the server chose {:?} in ALPN, not h2",
                String::from_utf8_lossy(p)
            ),
            None => f.write_str("the server chose no ALPN protocol, not h2"),
        }
    }
}

impl std::error::Error for NotH2 {}

/// A connection to an HTTP/2 server. Cheap to clone.
#[derive(Debug, Clone)]
pub struct H2Client {
    conn: Conn<H2Conn>,
    shared: Arc<ClientShared>,
}

impl H2Client {
    /// Connects (prior knowledge, or TLS with ALPN `h2` when `tls` is given: the client config's
    /// `alpn_protocols` must contain `h2`), then calls `ready`. Over TLS, `ready` is called once
    /// the server's first frame came (its SETTINGS, so [`max_concurrent_streams`] is known), and
    /// fails with [`NotH2`] when the server chose another protocol in ALPN, or none.
    ///
    /// [`max_concurrent_streams`]: Self::max_concurrent_streams
    pub fn dial(
        engine: &Engine,
        addr: SocketAddr,
        tls: Option<(TlsClientConfig, &str)>,
        opts: H2Options,
        ready: impl FnOnce(Result<H2Client, io::Error>) + Send + 'static,
    ) {
        let ready: Arc<Mutex<Option<ReadyCb>>> = Arc::new(Mutex::new(Some(Box::new(ready))));
        let fail = {
            let ready = ready.clone();
            move |e: io::Error| {
                let taken = ready.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(cb) = taken {
                    cb(Err(e));
                }
            }
        };
        let mut acceptor = H2Acceptor {
            opts,
            ready,
            alpn_check: false,
        };
        match tls {
            Some((cfg, host)) => match Tls::client(cfg, host, {
                acceptor.alpn_check = true;
                acceptor
            }) {
                Ok(a) => engine.dial(addr, a, fail),
                Err(e) => fail(e),
            },
            None => engine.dial(addr, acceptor, fail),
        }
    }

    /// Resolves `host` ([`akio::dns::resolve`], off the calling thread) and connects to the
    /// first of its addresses that answers, racing them (Happy Eyeballs v2, RFC 8305:
    /// [`akio::dns::HappyEyeballs`]), then as [`dial`](Self::dial). `tls` is the TLS
    /// configuration and the name to verify (usually `host`). The race and each connect's
    /// timeout are [`H2Options::happy_eyeballs`].
    pub fn connect(
        engine: &Arc<Engine>,
        host: &str,
        port: u16,
        tls: Option<(TlsClientConfig, &str)>,
        opts: H2Options,
        ready: impl FnOnce(Result<H2Client, io::Error>) + Send + 'static,
    ) {
        let ready: Arc<Mutex<Option<ReadyCb>>> = Arc::new(Mutex::new(Some(Box::new(ready))));
        let fail = {
            let ready = ready.clone();
            move |e: io::Error| {
                let taken = ready.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(cb) = taken {
                    cb(Err(e));
                }
            }
        };
        let he = opts.happy_eyeballs;
        let mut acceptor = H2Acceptor {
            opts,
            ready,
            alpn_check: false,
        };
        match tls {
            Some((cfg, name)) => match Tls::client(cfg, name, {
                acceptor.alpn_check = true;
                acceptor
            }) {
                Ok(a) => he.connect(engine, host, port, a, fail),
                Err(e) => fail(e),
            },
            None => he.connect(engine, host, port, acceptor, fail),
        }
    }

    /// Like [`dial`](Self::dial), waiting for the result (10 s).
    pub fn dial_blocking(
        engine: &Engine,
        addr: SocketAddr,
        tls: Option<(TlsClientConfig, &str)>,
        opts: H2Options,
    ) -> io::Result<H2Client> {
        let (tx, rx) = mpsc::channel();
        H2Client::dial(engine, addr, tls, opts, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "h2 connect timed out"))?
    }

    /// Sends a request on a new stream; `done` is called once with the outcome. With
    /// [`ClientRequest::timeout`], the stream is reset (`CANCEL`) and the request fails with
    /// [`ClientError::Timeout`] when it passes (`done` then runs on the timer thread). Past the
    /// server's stream limit it waits for a stream ([`H2Options::max_pending_streams`]).
    pub fn request(&self, req: ClientRequest, done: impl FnOnce(Outcome) + Send + 'static) {
        let timeout = req.timeout;
        let mut done: Callback = Box::new(done);
        let ctl = Arc::new(StreamCtl::of(&req));
        ctl.attach(&req, &self.conn);
        if let Some(d) = timeout {
            let once = Arc::new(Mutex::new(Some(done)));
            let (o2, ctl2, conn) = (once.clone(), ctl.clone(), self.conn.clone());
            crate::timer::after(d, move || {
                let cb = o2.lock().unwrap_or_else(|p| p.into_inner()).take();
                let Some(cb) = cb else { return };
                if ctl2.give_up(STOP_TIMEOUT) {
                    let _ =
                        conn.spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.stop(c, &ctl2));
                }
                cb(Err(ClientError::Timeout));
            });
            done = Box::new(move |r| {
                let cb = once.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(cb) = cb {
                    cb(r);
                }
            });
        }
        let slot = Arc::new(Mutex::new(Some((req, done))));
        let s2 = slot.clone();
        let queued = self.conn.spawn_blocking(
            || (),
            move |h: &mut H2Conn, c, ()| {
                let taken = s2.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some((req, cb)) = taken {
                    h.start_full(c, req, Some(cb), None, ctl);
                }
            },
        );
        if queued.is_err() {
            let taken = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some((_, cb)) = taken {
                cb(Err(ClientError::Closed));
            }
        }
    }

    /// Starts a request whose body is written afterwards through the returned [`H2Upload`] and
    /// whose response is reported piece by piece to `on_event` (gRPC streaming, uploads of
    /// unknown size). `req.body`, if any, is sent first.
    ///
    /// `on_event` runs on the connection's I/O thread; after [`H2Event::Head`], exactly one of
    /// [`H2Event::End`] and [`H2Event::Error`] ends it (a failure before the head is an `Error`
    /// alone). [`H2Upload::stream`] cancels the stream and holds its reads. With
    /// [`ClientRequest::timeout`], the stream is reset (`CANCEL`) when it passes, unless it was
    /// over, and `on_event` gets [`ClientError::Timeout`]. Past the server's stream limit the
    /// request waits for a stream ([`H2Options::max_pending_streams`]).
    pub fn open(
        &self,
        mut req: ClientRequest,
        on_event: impl FnMut(H2Event<'_>) + Send + 'static,
    ) -> H2Upload {
        let ctl = Arc::new(StreamCtl::of(&req));
        ctl.attach(&req, &self.conn);
        let up = Arc::new(UpShared {
            ctl: ctl.clone(),
            q: Mutex::new(UpQ::default()),
            queued: AtomicUsize::new(0),
            max: self.shared.max_queued,
            closed: AtomicBool::new(false),
            drain: Mutex::new(None),
        });
        let first = std::mem::take(&mut req.body);
        if !first.is_empty() {
            up.queued.store(first.len(), Ordering::Release);
            up.lock().chunks.push_back(first);
        }
        if let Some(d) = req.timeout {
            let (ctl, conn) = (Arc::downgrade(&ctl), self.conn.clone());
            crate::timer::after(d, move || {
                let Some(ctl) = ctl.upgrade() else { return };
                if ctl.give_up(STOP_TIMEOUT) {
                    let _ =
                        conn.spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.stop(c, &ctl));
                }
            });
        }
        let slot = Arc::new(Mutex::new(Some((req, Box::new(on_event) as EventCb))));
        let (s2, up2) = (slot.clone(), up.clone());
        let queued = self.conn.spawn_blocking(
            || (),
            move |h: &mut H2Conn, c, ()| {
                let taken = s2.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some((req, ev)) = taken {
                    let ctl = up2.ctl.clone();
                    h.start_full(c, req, None, Some((up2, ev)), ctl);
                }
            },
        );
        if queued.is_err() {
            let taken = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some((_, mut ev)) = taken {
                up.close();
                ev(H2Event::Error(ClientError::Closed));
            }
        }
        H2Upload {
            conn: self.conn.clone(),
            up,
        }
    }

    /// Sends a request and returns a handle to wait on or await.
    pub fn send(&self, req: ClientRequest) -> ResponseFuture {
        let shared = FutureShared::new();
        let s = shared.clone();
        self.request(req, move |r| s.complete(r));
        ResponseFuture { shared }
    }

    /// Opens a WebSocket at `url` (`http`, `https`, `ws` or `wss`; the scheme only names the
    /// `:scheme` sent, the connection is this one) on a new stream of this connection (RFC 8441:
    /// an extended CONNECT, whose stream then carries the WebSocket), served by `handler` as an
    /// `akio_ws::client` connection is: callbacks on the connection's I/O thread, [`WsSender`]
    /// to send from any thread. It waits for the server's SETTINGS first. `done` gets the
    /// sender once the server accepted (`on_open` has run), or why not:
    /// [`ClientError::Status`] for a refusal, [`ClientError::Protocol`] when the server does not
    /// allow extended CONNECT, [`ClientError::Timeout`] past [`H2WsOptions::timeout`].
    ///
    /// The stream's window paces what is sent; sends fail with `Overloaded` past
    /// [`H2WsOptions::max_queued_bytes`] queued. A reset stream or a lost connection is a close
    /// without handshake (1006).
    pub fn websocket(
        &self,
        url: &str,
        opts: &H2WsOptions,
        handler: impl WsHandler,
        done: impl FnOnce(Result<WsSender, ClientError>) + Send + 'static,
    ) {
        let url = match url.split_once("://") {
            Some(("ws", rest)) => format!("http://{rest}"),
            Some(("wss", rest)) => format!("https://{rest}"),
            _ => url.to_owned(),
        };
        let mut fields = vec![("sec-websocket-version".to_owned(), "13".to_owned())];
        if !opts.protocols.is_empty() {
            fields.push(("sec-websocket-protocol".into(), opts.protocols.join(", ")));
        }
        let pmd = opts.config.permessage_deflate.then_some(opts.pmd);
        if let Some(p) = &pmd {
            fields.push(("sec-websocket-extensions".into(), p.header()));
        }
        if let Some(o) = &opts.origin {
            fields.push(("origin".into(), o.clone()));
        }
        for (n, v) in &opts.headers {
            let lower = n.to_ascii_lowercase();
            let hop = matches!(
                lower.as_str(),
                "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "te"
                    | "content-length"
            );
            if !hop && !lower.starts_with("sec-websocket-") && lower != "origin" {
                fields.push((lower, v.replace(['\r', '\n'], "")));
            }
        }
        let once = WsOnce(Arc::new(Mutex::new(Some(Box::new(done) as WsDone))));
        let sid = Arc::new(AtomicU32::new(0));
        {
            let (once, sid, conn) = (once.clone(), sid.clone(), self.conn.clone());
            crate::timer::after(opts.timeout, move || {
                let Some(cb) = once.take() else { return };
                let id = sid.load(Ordering::Acquire);
                if id != 0 {
                    let _ =
                        conn.spawn_blocking(|| (), move |h: &mut H2Conn, c, ()| h.cancel(c, id));
                }
                cb(Err(ClientError::Timeout));
            });
        }
        let open = Box::new(WsOpen {
            url,
            fields,
            handler: Box::new(handler),
            cfg: opts.config.clone(),
            pmd,
            protocols: opts.protocols.clone(),
            close_timeout: opts.close_timeout,
            max_queued: opts.max_queued_bytes,
            done: once,
            sid,
        });
        let slot = Arc::new(Mutex::new(Some(open)));
        let s2 = slot.clone();
        let queued = self.conn.spawn_blocking(
            || (),
            move |h: &mut H2Conn, c, ()| {
                let taken = s2.lock().unwrap_or_else(|p| p.into_inner()).take();
                if let Some(w) = taken {
                    h.ws_start(c, w);
                }
            },
        );
        if queued.is_err() {
            let taken = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
            if let Some(w) = taken {
                w.done.fail(ClientError::Closed);
            }
        }
    }

    /// [`websocket`](Self::websocket), waiting for the outcome (at most
    /// [`H2WsOptions::timeout`]).
    pub fn websocket_blocking(
        &self,
        url: &str,
        opts: &H2WsOptions,
        handler: impl WsHandler,
    ) -> Result<WsSender, ClientError> {
        let (tx, rx) = mpsc::channel();
        self.websocket(url, opts, handler, move |r| {
            let _ = tx.send(r);
        });
        rx.recv_timeout(opts.timeout + Duration::from_secs(1))
            .map_err(|_| ClientError::Timeout)?
    }

    /// Whether the connection can still take requests: it is open, and no `GOAWAY` came (nor
    /// was sent by [`close`](Self::close)).
    pub fn is_open(&self) -> bool {
        !self.shared.goaway.load(Ordering::Acquire) && self.conn.is_open()
    }

    /// The server's `SETTINGS_MAX_CONCURRENT_STREAMS`: how many streams this client may have
    /// open at once (`u32::MAX` until the server says). The latest value; a server may lower
    /// it at any time.
    pub fn max_concurrent_streams(&self) -> u32 {
        self.shared.max_streams.load(Ordering::Acquire)
    }

    /// Streams this client opened that are not over (requests, streamed requests and
    /// WebSockets; not the server's pushes nor requests still waiting for a stream).
    pub fn open_streams(&self) -> u32 {
        self.shared.open.load(Ordering::Acquire)
    }

    /// Requests waiting in the client for a stream, the server's limit being reached
    /// ([`H2Options::max_pending_streams`]).
    pub fn waiting_streams(&self) -> u32 {
        self.shared.waiting.load(Ordering::Acquire)
    }

    /// Closes the connection after sending GOAWAY.
    pub fn close(&self) {
        self.shared.goaway.store(true, Ordering::Release);
        let _ = self.conn.spawn_blocking(
            || (),
            |h: &mut H2Conn, c, ()| {
                let mut out = Vec::new();
                let mut p = 0u32.to_be_bytes().to_vec();
                p.extend_from_slice(&err::NO_ERROR.to_be_bytes());
                frame(&mut out, ty::GOAWAY, 0, 0, &p);
                let _ = c.send_owned(out);
                h.fail_all(ClientError::Closed);
                c.close_after_send();
            },
        );
    }
}

type ReadyCb = Box<dyn FnOnce(Result<H2Client, io::Error>) + Send>;

struct H2Acceptor {
    opts: H2Options,
    ready: Arc<Mutex<Option<ReadyCb>>>,
    /// Over TLS: `ready` waits for the server's first frame, and for ALPN to have chosen `h2`.
    alpn_check: bool,
}

impl Acceptor for H2Acceptor {
    type Handler = H2Conn;

    fn on_open(&self, c: &Conn<H2Conn>) -> H2Conn {
        let mut h = H2Conn::new(self.opts.clone());
        // Preface, our SETTINGS and a bigger connection window go out first.
        let mut out = PREFACE.to_vec();
        let mut p = Vec::new();
        for (id, v) in [
            (2u16, u32::from(self.opts.enable_push)),
            (4, self.opts.initial_window),
            (6, self.opts.max_header_list),
        ] {
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        }
        frame(&mut out, ty::SETTINGS, 0, 0, &p);
        let extra = self.opts.conn_window.saturating_sub(DEFAULT_WINDOW as u32);
        if extra > 0 {
            frame(&mut out, ty::WINDOW_UPDATE, 0, 0, &extra.to_be_bytes());
        }
        let _ = c.send_owned(out);
        let taken = self.ready.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(cb) = taken {
            if self.alpn_check {
                h.ready = Some(cb);
            } else {
                cb(Ok(H2Client {
                    conn: c.clone(),
                    shared: h.shared.clone(),
                }));
            }
        }
        h
    }
}

struct CStream {
    /// The request URL (the pushed path for a pushed stream).
    url: String,
    cb: Option<Callback>,
    status: u16,
    headers: Headers,
    body: Vec<u8>,
    trailers: Headers,
    got_head: bool,
    ended: bool,
    send_window: i64,
    recv_window: i64,
    /// Request body still to send.
    upload: VecDeque<u8>,
    upload_done: bool,
    /// More request body may still be written (streamed requests).
    upload_open: bool,
    /// Streamed requests report the response here instead of buffering it.
    events: Option<EventCb>,
    head_only: bool,
    /// For pushed streams: the path promised, and the stream that carried the promise.
    pushed_path: Option<String>,
    parent: Option<u32>,
    /// Pushed responses still outstanding for this (parent) stream.
    pending_pushes: u32,
    pushed: Vec<(String, ClientResponse)>,
    /// A WebSocket (extended CONNECT) carried by this stream.
    ws: Option<Box<CWs>>,
    /// A request's: cancel, timeout, held reads.
    ctl: Option<Arc<StreamCtl>>,
    /// A streamed request's body, closed when the stream goes.
    up: Option<UpLink>,
    /// Trailer fields to end the request body with.
    trailers_out: Option<Headers>,
    /// Receive window consumed while the reads were held, given back on resume.
    owed: u32,
    /// Counts the stream in [`ClientShared::open`] (streams this client opened).
    _slot: Option<OpenSlot>,
}

impl CStream {
    /// A stream with nothing yet: `send_window` and `recv_window` as given.
    fn new(url: String, send_window: i64, recv_window: i64) -> CStream {
        CStream {
            url,
            cb: None,
            status: 0,
            headers: Headers::new(),
            body: Vec::new(),
            trailers: Headers::new(),
            got_head: false,
            ended: false,
            send_window,
            recv_window,
            upload: VecDeque::new(),
            upload_done: false,
            upload_open: false,
            events: None,
            head_only: false,
            pushed_path: None,
            parent: None,
            pending_pushes: 0,
            pushed: Vec::new(),
            ws: None,
            ctl: None,
            up: None,
            trailers_out: None,
            owed: 0,
            _slot: None,
        }
    }
}

impl Drop for CStream {
    fn drop(&mut self) {
        // Its header and idle timeouts stop.
        if let Some(ctl) = &self.ctl {
            ctl.phase.store(PHASE_OVER, Ordering::Release);
        }
    }
}

/// A request waiting for a stream (the server's limit reached).
struct Pending {
    req: ClientRequest,
    cb: Option<Callback>,
    streaming: Option<(Arc<UpShared>, EventCb)>,
    ctl: Arc<StreamCtl>,
}

/// Fails a request that never got a stream.
fn fail_unstarted(
    cb: Option<Callback>,
    streaming: Option<(Arc<UpShared>, EventCb)>,
    e: ClientError,
) {
    if let Some(cb) = cb {
        cb(Err(e));
    } else if let Some((up, mut ev)) = streaming {
        up.close();
        ev(H2Event::Error(e));
    }
}

/// The connection's handler.
pub struct H2Conn {
    opts: H2Options,
    rbuf: Vec<u8>,
    dec: Decoder,
    enc: Encoder,
    streams: HashMap<u32, CStream>,
    next_id: u32,
    conn_send: i64,
    conn_recv: i64,
    remote_initial: i64,
    remote_max_frame: usize,
    /// A header block being assembled: (stream, promised stream, block, end_stream).
    cont: Option<(u32, Option<u32>, Vec<u8>, bool)>,
    goaway: bool,
    dead: bool,
    /// The server's first SETTINGS arrived, and whether it allows extended CONNECT.
    got_settings: bool,
    connect_protocol: bool,
    /// WebSockets waiting for the server's SETTINGS (RFC 8441 §3).
    #[allow(clippy::vec_box)] // each moves on into its stream as it is
    ws_wait: Vec<Box<WsOpen>>,
    /// Shared with the connection's [`H2Client`]s.
    shared: Arc<ClientShared>,
    /// Requests waiting for a stream, in order.
    pending: VecDeque<Pending>,
    /// Streams to reset: their response ended while their request body was still open.
    resets: Vec<u32>,
    /// Requests whose END_STREAM went out: their header timeout is to be armed.
    head_waits: Vec<Arc<StreamCtl>>,
    /// Over TLS, the dial's callback, until the server's first frame.
    ready: Option<ReadyCb>,
}

impl std::fmt::Debug for H2Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Conn").finish_non_exhaustive()
    }
}

fn window_update(out: &mut Vec<u8>, sid: u32, inc: u32) {
    if inc > 0 {
        frame(out, ty::WINDOW_UPDATE, 0, sid, &inc.to_be_bytes());
    }
}

impl H2Conn {
    fn new(opts: H2Options) -> H2Conn {
        let max_queued = opts.max_queued_bytes;
        H2Conn {
            conn_recv: DEFAULT_WINDOW
                + i64::from(opts.conn_window.saturating_sub(DEFAULT_WINDOW as u32)),
            opts,
            rbuf: Vec::new(),
            dec: Decoder::new(),
            enc: Encoder::new(),
            streams: HashMap::new(),
            next_id: 1,
            conn_send: DEFAULT_WINDOW,
            remote_initial: DEFAULT_WINDOW,
            remote_max_frame: DEFAULT_FRAME as usize,
            cont: None,
            goaway: false,
            dead: false,
            got_settings: false,
            connect_protocol: false,
            ws_wait: Vec::new(),
            shared: Arc::new(ClientShared {
                goaway: AtomicBool::new(false),
                max_streams: AtomicU32::new(u32::MAX),
                open: AtomicU32::new(0),
                waiting: AtomicU32::new(0),
                max_queued,
            }),
            pending: VecDeque::new(),
            resets: Vec::new(),
            head_waits: Vec::new(),
            ready: None,
        }
    }

    /// Abandons stream `sid` (a WebSocket's): reset it and forget it.
    fn cancel(&mut self, c: &Conn<Self>, sid: u32) {
        if self.streams.remove(&sid).is_some() && !self.dead {
            let mut out = Vec::new();
            frame(&mut out, ty::RST_STREAM, 0, sid, &err::CANCEL.to_be_bytes());
            let _ = c.send_owned(out);
        }
        self.after(c);
    }

    /// A request was given up (cancelled, timed out): reset its stream and fail it, or drop it
    /// from the queue unsent, unless it is over.
    fn stop(&mut self, c: &Conn<Self>, ctl: &Arc<StreamCtl>) {
        let e = ctl.reason().unwrap_or(ClientError::Cancelled);
        let sid = ctl.sid.load(Ordering::Acquire);
        let mine = |s: &CStream| s.ctl.as_ref().is_some_and(|x| Arc::ptr_eq(x, ctl));
        if sid != 0 && self.streams.get(&sid).is_some_and(mine) {
            let mut out = Vec::new();
            self.abort_stream(&mut out, sid, e);
            if !out.is_empty() && !self.dead {
                let _ = c.send_owned(out);
            }
        } else if let Some(i) = self.pending.iter().position(|p| Arc::ptr_eq(&p.ctl, ctl)) {
            if let Some(p) = self.pending.remove(i) {
                self.count_waiting();
                fail_unstarted(p.cb, p.streaming, e);
            }
        }
        self.after(c);
    }

    /// A stream's reads were resumed: give back the window consumed while they were held.
    fn release(&mut self, c: &Conn<Self>, ctl: &Arc<StreamCtl>) {
        if ctl.held.load(Ordering::Acquire) || self.dead {
            return;
        }
        let sid = ctl.sid.load(Ordering::Acquire);
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        let owed = std::mem::take(&mut st.owed);
        if owed > 0 && !st.ended {
            st.recv_window += i64::from(owed);
            let mut out = Vec::new();
            window_update(&mut out, sid, owed);
            let _ = c.send_owned(out);
        }
    }

    /// A header or idle timeout looks due (`arm`): give the stream up if it is, else check
    /// again when it will be.
    fn expire(&mut self, c: &Conn<Self>, ctl: &Arc<StreamCtl>, phase: u8) {
        if ctl.phase.load(Ordering::Acquire) != phase {
            return; // the head came, or the stream is over
        }
        if phase == PHASE_BODY {
            if let Some(wait) = ctl.idle_left() {
                return arm(c.clone(), ctl, phase, wait);
            }
        }
        let why = if phase == PHASE_HEAD {
            STOP_HEADER
        } else {
            STOP_IDLE
        };
        if ctl.give_up(why) {
            self.stop(c, ctl);
        }
    }

    /// Arms the header timeouts of the requests whose END_STREAM went out.
    fn arm_heads(&mut self, c: &Conn<Self>) {
        for ctl in std::mem::take(&mut self.head_waits) {
            if let Some(d) = ctl.header_timeout {
                arm(c.clone(), &ctl, PHASE_HEAD, d);
            }
        }
    }

    /// Publishes how many requests wait for a stream.
    fn count_waiting(&self) {
        let n = u32::try_from(self.pending.len()).unwrap_or(u32::MAX);
        self.shared.waiting.store(n, Ordering::Release);
    }

    /// After frames or a request's change: reset the streams whose response ended before
    /// their request body, start the requests waiting for a stream.
    fn after(&mut self, c: &Conn<Self>) {
        if !self.resets.is_empty() {
            let mut out = Vec::new();
            for sid in std::mem::take(&mut self.resets) {
                frame(&mut out, ty::RST_STREAM, 0, sid, &err::CANCEL.to_be_bytes());
            }
            if !self.dead {
                let _ = c.send_owned(out);
            }
        }
        while let Some(p) = self.pending.front() {
            if self.dead || self.goaway {
                break; // failed there
            }
            if let Some(e) = p.ctl.reason() {
                let p = self.pending.pop_front().expect("present");
                self.count_waiting();
                fail_unstarted(p.cb, p.streaming, e);
                continue;
            }
            let max = self.shared.max_streams.load(Ordering::Acquire);
            if self.shared.open.load(Ordering::Acquire) >= max {
                break;
            }
            let p = self.pending.pop_front().expect("present");
            self.count_waiting();
            self.begin(c, p.req, p.cb, p.streaming, p.ctl);
        }
    }

    /// Starts a request on a stream, or queues it while the server's stream limit is reached.
    fn start_full(
        &mut self,
        c: &Conn<Self>,
        req: ClientRequest,
        cb: Option<Callback>,
        streaming: Option<(Arc<UpShared>, EventCb)>,
        ctl: Arc<StreamCtl>,
    ) {
        if self.dead {
            return fail_unstarted(cb, streaming, ClientError::Closed);
        }
        if self.goaway {
            return fail_unstarted(cb, streaming, ClientError::Refused);
        }
        if let Some(e) = ctl.reason() {
            return fail_unstarted(cb, streaming, e);
        }
        let max = self.shared.max_streams.load(Ordering::Acquire);
        if !self.pending.is_empty() || self.shared.open.load(Ordering::Acquire) >= max {
            if self.pending.len() >= self.opts.max_pending_streams {
                return fail_unstarted(cb, streaming, ClientError::Busy);
            }
            self.pending.push_back(Pending {
                req,
                cb,
                streaming,
                ctl,
            });
            self.count_waiting();
            return;
        }
        self.begin(c, req, cb, streaming, ctl);
    }

    /// Opens a stream for a request and sends its head (and what its body allows).
    fn begin(
        &mut self,
        c: &Conn<Self>,
        req: ClientRequest,
        cb: Option<Callback>,
        streaming: Option<(Arc<UpShared>, EventCb)>,
        ctl: Arc<StreamCtl>,
    ) {
        let pu = match parse_url(&req.url) {
            Ok(p) => p,
            Err(e) => return fail_unstarted(cb, streaming, e),
        };
        let is_stream = streaming.is_some();
        let sid = self.next_id;
        self.next_id += 2;
        let mut list: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), req.method.as_str().as_bytes().to_vec()),
            (
                b":scheme".to_vec(),
                (if pu.key.tls { "https" } else { "http" })
                    .as_bytes()
                    .to_vec(),
            ),
            (b":authority".to_vec(), pu.host_header.clone().into_bytes()),
            (b":path".to_vec(), pu.target.into_bytes()),
        ];
        let mut has_cl = false;
        for (n, v) in req.headers.iter() {
            let n = n.to_ascii_lowercase();
            if matches!(
                n.as_str(),
                "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
            ) {
                continue;
            }
            has_cl |= n == "content-length";
            list.push((n.into_bytes(), v.replace(['\r', '\n'], "").into_bytes()));
        }
        if !has_cl
            && !is_stream
            && (!req.body.is_empty()
                || matches!(req.method, Method::Post | Method::Put | Method::Patch))
        {
            list.push((
                b"content-length".to_vec(),
                req.body.len().to_string().into_bytes(),
            ));
        }
        if !list.iter().any(|(n, _)| n == b"user-agent") {
            list.push((b"user-agent".to_vec(), b"akio-http".to_vec()));
        }
        let block = self
            .enc
            .encode(list.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let mut out = Vec::new();
        let end_now = req.body.is_empty() && !is_stream;
        self.header_block(&mut out, ty::HEADERS, sid, &[], &block, end_now);
        let head_only = req.method == Method::Head;
        let (up, events) = match streaming {
            Some((u, e)) => (Some(u), Some(e)),
            None => (None, None),
        };
        let mut st = CStream::new(
            req.url.clone(),
            self.remote_initial,
            i64::from(self.opts.initial_window),
        );
        st.cb = cb;
        st.upload = req.body.into();
        st.upload_open = is_stream;
        st.events = events;
        st.head_only = head_only;
        st.upload_done = st.upload.is_empty() && !is_stream;
        st.up = up.clone().map(UpLink);
        st._slot = Some(OpenSlot::new(&self.shared));
        ctl.sid.store(sid, Ordering::Release);
        st.ctl = Some(ctl);
        self.streams.insert(sid, st);
        self.send_upload(sid, &mut out);
        let _ = c.send_owned(out);
        if let Some(up) = up {
            self.pump(c, &up);
        }
        self.arm_heads(c);
    }

    /// Starts a WebSocket's extended CONNECT, once the server's SETTINGS allow it.
    fn ws_start(&mut self, c: &Conn<Self>, w: Box<WsOpen>) {
        if self.dead || self.goaway {
            return w.done.fail(ClientError::Closed);
        }
        if !self.got_settings {
            self.ws_wait.push(w);
            return;
        }
        if !self.connect_protocol {
            return w.done.fail(ClientError::Protocol(
                "server does not allow extended CONNECT",
            ));
        }
        if w.done.0.lock().unwrap_or_else(|p| p.into_inner()).is_none() {
            return; // timed out while waiting for the SETTINGS
        }
        let pu = match parse_url(&w.url) {
            Ok(p) => p,
            Err(e) => return w.done.fail(e),
        };
        let sid = self.next_id;
        self.next_id += 2;
        let scheme: &[u8] = if pu.key.tls { b"https" } else { b"http" };
        let mut list: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", scheme),
            (b":authority", pu.host_header.as_bytes()),
            (b":path", pu.target.as_bytes()),
        ];
        for (n, v) in &w.fields {
            list.push((n.as_bytes(), v.as_bytes()));
        }
        if !w.fields.iter().any(|(n, _)| n == "user-agent") {
            list.push((b"user-agent", b"akio-http"));
        }
        let block = self.enc.encode(list);
        let mut out = Vec::new();
        self.header_block(&mut out, ty::HEADERS, sid, &[], &block, false);
        w.sid.store(sid, Ordering::Release);
        let mut st = CStream::new(
            String::new(),
            self.remote_initial,
            i64::from(self.opts.initial_window),
        );
        st.upload_open = true;
        st.ws = Some(Box::new(CWs(WsState::Opening(w))));
        st._slot = Some(OpenSlot::new(&self.shared));
        self.streams.insert(sid, st);
        let _ = c.send_owned(out);
    }

    /// The server answered a WebSocket's extended CONNECT: check the answer, start the session.
    fn ws_answer(&mut self, c: &Conn<Self>, sid: u32, status: u16, hs: &Headers) {
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        let Some(WsState::Opening(w)) = st
            .ws
            .as_deref_mut()
            .map(|w| std::mem::replace(&mut w.0, WsState::Gone))
        else {
            return;
        };
        let checked = (|| {
            if !(200..300).contains(&status) {
                return Err(ClientError::Status(status));
            }
            let mut protos = hs.get_all("sec-websocket-protocol");
            let protocol = match (protos.next(), protos.next()) {
                (None, _) => None,
                (Some(p), None) if w.protocols.iter().any(|o| o == p) => Some(p.to_owned()),
                _ => {
                    return Err(ClientError::Protocol(
                        "server selected a subprotocol that was not offered",
                    ));
                }
            };
            let pmd = match &w.pmd {
                Some(offer) => offer
                    .accept_response(hs.get_all("sec-websocket-extensions"))
                    .map_err(ClientError::Protocol)?,
                None => {
                    if hs
                        .get_all("sec-websocket-extensions")
                        .any(|v| !v.is_empty())
                    {
                        return Err(ClientError::Protocol(
                            "server accepted an extension that was not offered",
                        ));
                    }
                    None
                }
            };
            Ok((protocol, pmd))
        })();
        let done = w.done.take();
        let (protocol, pmd, cb) = match (checked, done) {
            (Ok((protocol, pmd)), Some(cb)) => (protocol, pmd, cb),
            (Err(e), Some(cb)) => {
                self.cancel(c, sid);
                return cb(Err(e));
            }
            // Timed out meanwhile: nobody waits for it.
            (_, None) => return self.cancel(c, sid),
        };
        let WsOpen {
            handler,
            cfg,
            close_timeout,
            max_queued,
            ..
        } = *w;
        let sh = Arc::new(LinkShared {
            q: Mutex::new(LinkQ::default()),
            queued: AtomicUsize::new(0),
            max: max_queued,
            closed: AtomicBool::new(false),
        });
        let link: Arc<dyn WsLink> = Arc::new(ClientLink {
            conn: c.clone(),
            sid,
            sh: sh.clone(),
        });
        let mut ws = WsSession::client_with_link(link, &cfg, pmd, handler, protocol, close_timeout);
        let sender = ws.sender().clone();
        ws.open();
        if let Some(st) = self.streams.get_mut(&sid) {
            st.ws = Some(Box::new(CWs(WsState::Open(Box::new(ws), sh))));
        }
        cb(Ok(sender));
    }

    /// The server ended its half of a WebSocket's stream: the session's transport is closed,
    /// and our half ends after what is queued.
    fn ws_peer_ended(&mut self, c: &Conn<Self>, sid: u32) {
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        st.ended = true;
        let sh = match st.ws.as_deref_mut() {
            Some(CWs(WsState::Open(s, sh))) => {
                s.on_transport_closed();
                sh.clone()
            }
            _ => {
                // Ended before it opened.
                return self.cancel(c, sid);
            }
        };
        self.ws_pump(c, sid, &sh);
    }

    /// Moves what a WebSocket's sender queued into its stream, sends what the windows allow,
    /// and ends or resets the stream as asked.
    fn ws_pump(&mut self, c: &Conn<Self>, sid: u32, sh: &Arc<LinkShared>) {
        let (chunks, end) = {
            let mut q = sh.q.lock().unwrap_or_else(|p| p.into_inner());
            q.scheduled = false;
            (std::mem::take(&mut q.chunks), q.end)
        };
        let Some(st) = self.streams.get_mut(&sid) else {
            sh.queued.store(0, Ordering::Release);
            return;
        };
        for ch in chunks {
            st.upload.extend(ch);
        }
        match end {
            LinkEnd::No => {}
            LinkEnd::Graceful => st.upload_open = false,
            LinkEnd::Now if st.ended => st.upload_open = false,
            LinkEnd::Now => {
                sh.queued.store(0, Ordering::Release);
                return self.cancel(c, sid);
            }
        }
        let mut out = Vec::new();
        self.send_upload(sid, &mut out);
        if !out.is_empty() {
            let _ = c.send_owned(out);
        }
        self.ws_finish(sid);
    }

    /// A WebSocket's stream whose halves have both ended is done.
    fn ws_finish(&mut self, sid: u32) {
        if self
            .streams
            .get(&sid)
            .is_some_and(|s| s.ws.is_some() && s.ended && s.upload_done)
        {
            self.streams.remove(&sid);
        }
    }

    /// Moves what an [`H2Upload`] queued into its stream and sends what the windows allow.
    fn pump(&mut self, c: &Conn<Self>, up: &Arc<UpShared>) {
        let sid = up.ctl.sid.load(Ordering::Acquire);
        let (chunks, finished, trailers) = {
            let mut q = up.lock();
            q.scheduled = false;
            if sid == 0 {
                return; // not started yet: the start drains the queue
            }
            (std::mem::take(&mut q.chunks), q.finished, q.trailers.take())
        };
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        for ch in chunks {
            st.upload.extend(ch);
        }
        if finished {
            st.upload_open = false;
            if trailers.is_some() {
                st.trailers_out = trailers;
            }
        }
        let mut out = Vec::new();
        self.send_upload(sid, &mut out);
        if !out.is_empty() {
            let _ = c.send_owned(out);
        }
        self.arm_heads(c);
    }

    fn header_block(
        &self,
        out: &mut Vec<u8>,
        ty_: u8,
        sid: u32,
        extra: &[u8],
        block: &[u8],
        end_stream: bool,
    ) {
        let max = self.remote_max_frame;
        let cap = max.saturating_sub(extra.len());
        let (first, mut rest) = block.split_at(block.len().min(cap));
        let mut flags = if end_stream { flag::END_STREAM } else { 0 };
        if rest.is_empty() {
            flags |= flag::END_HEADERS;
        }
        let mut p = extra.to_vec();
        p.extend_from_slice(first);
        frame(out, ty_, flags, sid, &p);
        while !rest.is_empty() {
            let (chunk, r) = rest.split_at(rest.len().min(max));
            rest = r;
            frame(
                out,
                ty::CONTINUATION,
                if rest.is_empty() {
                    flag::END_HEADERS
                } else {
                    0
                },
                sid,
                chunk,
            );
        }
    }

    /// Sends as much of the stream's request body as the windows allow, then its end (an
    /// empty DATA frame, or the trailers) once it is finished.
    fn send_upload(&mut self, sid: u32, out: &mut Vec<u8>) {
        let mut drained = None;
        while let Some(st) = self.streams.get_mut(&sid) {
            if st.upload_done {
                break;
            }
            if st.upload.is_empty() {
                if st.upload_open {
                    break; // wait for more body
                }
                st.upload_done = true;
                match st.trailers_out.take() {
                    Some(t) => self.send_trailers(out, sid, &t),
                    None => frame(out, ty::DATA, flag::END_STREAM, sid, &[]),
                }
                break;
            }
            let allow = st
                .send_window
                .min(self.conn_send)
                .min(self.remote_max_frame as i64);
            if allow <= 0 {
                break;
            }
            let n = st.upload.len().min(allow as usize);
            let data: Vec<u8> = st.upload.drain(..n).collect();
            if let Some(CWs(WsState::Open(_, sh))) = st.ws.as_deref() {
                sh.queued.fetch_sub(n, Ordering::AcqRel);
            }
            if let Some(u) = &st.up {
                if let Some(f) = u.0.sent(n) {
                    drained = Some(f);
                }
            }
            let last = st.upload.is_empty() && !st.upload_open && st.trailers_out.is_none();
            st.send_window -= n as i64;
            self.conn_send -= n as i64;
            if last {
                st.upload_done = true;
            }
            frame(
                out,
                ty::DATA,
                if last { flag::END_STREAM } else { 0 },
                sid,
                &data,
            );
            if last {
                break;
            }
        }
        // The request ended (END_STREAM went out): the wait for the response's head starts.
        if let Some(ctl) = self
            .streams
            .get(&sid)
            .filter(|s| s.upload_done && !s.got_head)
            .and_then(|s| s.ctl.as_ref())
            .filter(|x| x.header_timeout.is_some())
        {
            if ctl
                .phase
                .compare_exchange(PHASE_NONE, PHASE_HEAD, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.head_waits.push(ctl.clone());
            }
        }
        if let Some(f) = drained {
            f();
        }
    }

    /// A request body's trailers, ending the stream.
    fn send_trailers(&mut self, out: &mut Vec<u8>, sid: u32, t: &Headers) {
        let list: Vec<(Vec<u8>, Vec<u8>)> = t
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v))
            .filter(|(n, _)| {
                !n.starts_with(':')
                    && !matches!(
                        n.as_str(),
                        "host"
                            | "connection"
                            | "keep-alive"
                            | "proxy-connection"
                            | "transfer-encoding"
                            | "upgrade"
                            | "te"
                            | "content-length"
                    )
            })
            .map(|(n, v)| (n.into_bytes(), v.replace(['\r', '\n'], "").into_bytes()))
            .collect();
        if list.is_empty() {
            return frame(out, ty::DATA, flag::END_STREAM, sid, &[]);
        }
        let block = self
            .enc
            .encode(list.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        self.header_block(out, ty::HEADERS, sid, &[], &block, true);
    }

    fn flush_uploads(&mut self, c: &Conn<Self>) {
        let ids: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.upload_done)
            .map(|(i, _)| *i)
            .collect();
        let mut out = Vec::new();
        for &id in &ids {
            self.send_upload(id, &mut out);
        }
        if !out.is_empty() {
            let _ = c.send_owned(out);
        }
        for id in ids {
            self.ws_finish(id);
        }
        self.arm_heads(c);
    }

    fn fail_all(&mut self, e: ClientError) {
        self.dead = true;
        self.shared.goaway.store(true, Ordering::Release);
        let msg = |e: &ClientError| match e {
            ClientError::Protocol(m) => ClientError::Protocol(m),
            ClientError::TooLarge(m) => ClientError::TooLarge(m),
            ClientError::Timeout => ClientError::Timeout,
            ClientError::Io(x) => ClientError::Io(io::Error::new(x.kind(), x.to_string())),
            _ => ClientError::Closed,
        };
        for (_, mut s) in self.streams.drain() {
            drop(s.up.take());
            if let Some(cb) = s.cb.take() {
                cb(Err(msg(&e)));
            } else if let Some(ev) = s.events.as_mut() {
                ev(H2Event::Error(msg(&e)));
            } else if let Some(w) = s.ws.as_deref_mut() {
                w.fail(msg(&e));
            }
        }
        for w in std::mem::take(&mut self.ws_wait) {
            w.done.fail(msg(&e));
        }
        let pending = std::mem::take(&mut self.pending);
        self.count_waiting();
        for p in pending {
            fail_unstarted(p.cb, p.streaming, msg(&e));
        }
    }

    fn conn_error(&mut self, c: &Conn<Self>, code: u32, why: &'static str) {
        let mut out = Vec::new();
        let mut p = 0u32.to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        frame(&mut out, ty::GOAWAY, 0, 0, &p);
        let _ = c.send_owned(out);
        self.fail_all(ClientError::Protocol(why));
        c.close_after_send();
    }

    /// Resets stream `sid` (`CANCEL`) and fails its request with `e`.
    fn abort_stream(&mut self, out: &mut Vec<u8>, sid: u32, e: ClientError) {
        let Some(mut s) = self.streams.remove(&sid) else {
            return;
        };
        drop(s.up.take());
        frame(out, ty::RST_STREAM, 0, sid, &err::CANCEL.to_be_bytes());
        if let Some(cb) = s.cb.take() {
            cb(Err(e));
        } else if let Some(ev) = s.events.as_mut() {
            ev(H2Event::Error(e));
        } else if let Some(w) = s.ws.as_deref_mut() {
            w.fail(e);
        }
        if let Some(parent) = s.parent {
            if let Some(pp) = self.streams.get_mut(&parent) {
                pp.pending_pushes = pp.pending_pushes.saturating_sub(1);
            }
            self.try_finish(parent);
        }
    }

    /// Delivers the response of `sid` if it is complete (and its pushes are).
    fn try_finish(&mut self, sid: u32) {
        let Some(st) = self.streams.get(&sid) else {
            return;
        };
        if !st.ended || st.pending_pushes > 0 {
            return;
        }
        let mut st = self.streams.remove(&sid).expect("present");
        // Writes fail from here on, before the caller hears of the end.
        drop(st.up.take());
        if !st.upload_done && st.ws.is_none() {
            // The response ended before the request body: the server wants no more of it.
            self.resets.push(sid);
        }
        if let Some(ev) = st.events.as_mut() {
            ev(H2Event::End);
            return;
        }
        let resp = ClientResponse {
            status: st.status,
            reason: String::new(),
            headers: std::mem::take(&mut st.headers),
            body: std::mem::take(&mut st.body),
            trailers: std::mem::take(&mut st.trailers),
            pushed: std::mem::take(&mut st.pushed),
            url: std::mem::take(&mut st.url),
        };
        match (st.parent, st.pushed_path.take()) {
            (Some(parent), Some(path)) => {
                if let Some(p) = self.streams.get_mut(&parent) {
                    p.pushed.push((path, resp));
                    p.pending_pushes -= 1;
                }
                self.try_finish(parent);
            }
            _ => {
                if let Some(cb) = st.cb.take() {
                    cb(Ok(resp));
                }
            }
        }
    }

    fn headers_done(
        &mut self,
        c: &Conn<Self>,
        sid: u32,
        promised: Option<u32>,
        block: Vec<u8>,
        end_stream: bool,
    ) {
        // The whole block is decoded even past the limit: HPACK state must stay in step.
        let limit = self.opts.max_header_list as usize;
        let Ok((list, size)) = self.dec.decode_limited(&block, limit) else {
            return self.conn_error(c, err::COMPRESSION, "bad header block");
        };
        if let Some(pid) = promised {
            if pid % 2 == 1 || pid == 0 || self.streams.contains_key(&pid) {
                return self.conn_error(c, err::PROTOCOL, "bad promised stream");
            }
            let refuse = !self.opts.enable_push
                || size > limit
                || self
                    .streams
                    .get(&sid)
                    .is_none_or(|p| p.pending_pushes >= MAX_PUSHES_PER_STREAM);
            // A pushed request: remember which path it is for.
            let path = list
                .iter()
                .find(|(n, _)| n == b":path")
                .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default();
            if refuse {
                let mut out = Vec::new();
                frame(
                    &mut out,
                    ty::RST_STREAM,
                    0,
                    pid,
                    &err::REFUSED_STREAM.to_be_bytes(),
                );
                let _ = c.send_owned(out);
                return;
            }
            let Some(parent) = self.streams.get_mut(&sid) else {
                return;
            };
            parent.pending_pushes += 1;
            let mut st = CStream::new(path.clone(), 0, i64::from(self.opts.initial_window));
            st.upload_done = true;
            st.pushed_path = Some(path);
            st.parent = Some(sid);
            self.streams.insert(pid, st);
            return;
        }
        if size > limit {
            let mut out = Vec::new();
            self.abort_stream(
                &mut out,
                sid,
                ClientError::TooLarge("response header list too large"),
            );
            if !out.is_empty() {
                let _ = c.send_owned(out);
            }
            return;
        }
        let Some(st) = self.streams.get_mut(&sid) else {
            return; // a reset or unknown stream: the block was decoded to keep HPACK in step
        };
        let mut hs = Headers::new();
        let mut status = 0u16;
        for (n, v) in &list {
            let v = String::from_utf8_lossy(v).into_owned();
            if n == b":status" {
                status = v.parse().unwrap_or(0);
            } else if n.first() != Some(&b':') {
                hs.append(String::from_utf8_lossy(n), v);
            }
        }
        if st.ws.is_some() {
            if !st.got_head && !(100..200).contains(&status) {
                st.got_head = true;
                self.ws_answer(c, sid, status, &hs);
            }
            // Trailers end the server's half like END_STREAM on DATA.
            if end_stream {
                self.ws_peer_ended(c, sid);
            }
            return;
        }
        if !st.got_head {
            if (100..200).contains(&status) {
                return; // interim
            }
            st.got_head = true;
            st.status = status;
            // The header timeout stops; the idle timeout starts.
            if let Some(ctl) = &st.ctl {
                ctl.touch();
                ctl.phase.store(PHASE_BODY, Ordering::Release);
                if let (Some(d), false) = (ctl.idle_timeout, end_stream) {
                    arm(c.clone(), ctl, PHASE_BODY, d);
                }
            }
            if let Some(ev) = st.events.as_mut() {
                ev(H2Event::Head {
                    status,
                    headers: &hs,
                });
            }
            st.headers = hs;
        } else {
            if let Some(ev) = st.events.as_mut() {
                ev(H2Event::Trailers(&hs));
            }
            st.trailers = hs;
        }
        if end_stream {
            st.ended = true;
            self.try_finish(sid);
        }
    }

    fn handle(&mut self, c: &Conn<Self>, ty_: u8, flags: u8, sid: u32, mut p: Vec<u8>) {
        let mut out = Vec::new();
        if self.cont.is_some() && ty_ != ty::CONTINUATION {
            // RFC 9113 §6.10: a header block is contiguous.
            return self.conn_error(c, err::PROTOCOL, "frame inside a header block");
        }
        match ty_ {
            ty::SETTINGS => {
                if flags & flag::ACK != 0 {
                    return;
                }
                if p.len() % 6 != 0 {
                    return self.conn_error(c, err::FRAME_SIZE, "bad SETTINGS");
                }
                for s in p.chunks_exact(6) {
                    let id = u16::from_be_bytes([s[0], s[1]]);
                    let v = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
                    match id {
                        1 => self.enc.set_max_table_size(v as usize),
                        // SETTINGS_MAX_CONCURRENT_STREAMS: waiting requests start (`after`)
                        // as it allows.
                        3 => self.shared.max_streams.store(v, Ordering::Release),
                        4 => {
                            if i64::from(v) > MAX_WINDOW {
                                return self.conn_error(c, err::FLOW_CONTROL, "window too large");
                            }
                            let delta = i64::from(v) - self.remote_initial;
                            self.remote_initial = i64::from(v);
                            for st in self.streams.values_mut() {
                                st.send_window += delta;
                            }
                        }
                        5 if (DEFAULT_FRAME..(1 << 24)).contains(&v) => {
                            self.remote_max_frame = v as usize;
                        }
                        // SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 §3).
                        8 => self.connect_protocol = v == 1,
                        _ => {}
                    }
                }
                frame(&mut out, ty::SETTINGS, flag::ACK, 0, &[]);
                let _ = c.send_owned(out);
                self.flush_uploads(c);
                if !std::mem::replace(&mut self.got_settings, true) {
                    for w in std::mem::take(&mut self.ws_wait) {
                        self.ws_start(c, w);
                    }
                }
            }
            ty::PING => {
                if flags & flag::ACK == 0 && p.len() == 8 {
                    frame(&mut out, ty::PING, flag::ACK, 0, &p);
                    let _ = c.send_owned(out);
                }
            }
            ty::WINDOW_UPDATE => {
                if p.len() != 4 {
                    return self.conn_error(c, err::FRAME_SIZE, "bad WINDOW_UPDATE");
                }
                let inc = i64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
                if sid == 0 {
                    self.conn_send += inc;
                } else if let Some(st) = self.streams.get_mut(&sid) {
                    st.send_window += inc;
                }
                self.flush_uploads(c);
            }
            ty::GOAWAY => {
                self.goaway = true;
                self.shared.goaway.store(true, Ordering::Release);
                // Never sent: another connection may take them.
                let pending = std::mem::take(&mut self.pending);
                self.count_waiting();
                for p in pending {
                    fail_unstarted(p.cb, p.streaming, ClientError::Refused);
                }
                if p.len() >= 8 {
                    let last = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
                    // Requests above the last processed stream were not and will not be.
                    let doomed: Vec<u32> = self
                        .streams
                        .keys()
                        .copied()
                        .filter(|id| id % 2 == 1 && *id > last)
                        .collect();
                    for id in doomed {
                        if let Some(mut s) = self.streams.remove(&id) {
                            drop(s.up.take());
                            if let Some(cb) = s.cb.take() {
                                cb(Err(ClientError::Refused));
                            } else if let Some(ev) = s.events.as_mut() {
                                ev(H2Event::Error(ClientError::Refused));
                            }
                        }
                    }
                }
            }
            ty::RST_STREAM => {
                if let Some(mut s) = self.streams.remove(&sid) {
                    drop(s.up.take());
                    let code = if p.len() == 4 {
                        u32::from_be_bytes([p[0], p[1], p[2], p[3]])
                    } else {
                        0
                    };
                    let why = || {
                        if code == err::REFUSED_STREAM {
                            ClientError::Refused
                        } else {
                            ClientError::Protocol("stream reset by the server")
                        }
                    };
                    if let Some(cb) = s.cb.take() {
                        cb(Err(why()));
                    } else if let Some(ev) = s.events.as_mut() {
                        ev(H2Event::Error(why()));
                    } else if let Some(w) = s.ws.as_deref_mut() {
                        w.fail(why());
                    }
                    if let Some(parent) = s.parent {
                        if let Some(pp) = self.streams.get_mut(&parent) {
                            pp.pending_pushes = pp.pending_pushes.saturating_sub(1);
                        }
                        self.try_finish(parent);
                    }
                }
            }
            ty::DATA => {
                let total = p.len() as u32;
                let mut start = 0;
                let mut end = p.len();
                if flags & flag::PADDED != 0 && !p.is_empty() {
                    start = 1;
                    end = p.len().saturating_sub(p[0] as usize);
                }
                self.conn_recv -= i64::from(total);
                window_update(&mut out, 0, total);
                self.conn_recv += i64::from(total);
                let end_stream = flags & flag::END_STREAM != 0;
                if let Some(st) = self.streams.get_mut(&sid).filter(|s| s.ws.is_some()) {
                    // A WebSocket's bytes: consumed now, so the window is given back now.
                    if !end_stream {
                        window_update(&mut out, sid, total);
                    }
                    if let (Some(CWs(WsState::Open(ws, _))), true) =
                        (st.ws.as_deref_mut(), start <= end)
                    {
                        ws.on_data(&p[start..end]);
                    }
                    if !out.is_empty() {
                        let _ = c.send_owned(out);
                    }
                    if end_stream {
                        self.ws_peer_ended(c, sid);
                    }
                    return;
                }
                let max_body = self.opts.max_body_bytes;
                let mut too_large = false;
                if let Some(st) = self.streams.get_mut(&sid) {
                    if !st.head_only && start <= end {
                        match st.events.as_mut() {
                            Some(ev) => ev(H2Event::Data(&p[start..end])),
                            None if st.body.len() + (end - start) > max_body => too_large = true,
                            None => st.body.extend_from_slice(&p[start..end]),
                        }
                    }
                    st.recv_window -= i64::from(total);
                    if let Some(x) = &st.ctl {
                        x.touch();
                    }
                    if flags & flag::END_STREAM == 0 {
                        if st
                            .ctl
                            .as_ref()
                            .is_some_and(|x| x.held.load(Ordering::Acquire))
                        {
                            // Held: given back on resume (`release`).
                            st.owed = st.owed.saturating_add(total);
                        } else {
                            st.recv_window += i64::from(total);
                            window_update(&mut out, sid, total);
                        }
                    }
                    if flags & flag::END_STREAM != 0 {
                        st.ended = true;
                    }
                }
                if too_large {
                    self.abort_stream(
                        &mut out,
                        sid,
                        ClientError::TooLarge("response body too large"),
                    );
                    let _ = c.send_owned(out);
                    return;
                }
                if !out.is_empty() {
                    let _ = c.send_owned(out);
                }
                if flags & flag::END_STREAM != 0 {
                    self.try_finish(sid);
                }
            }
            ty::HEADERS | ty::PUSH_PROMISE => {
                let mut block = &p[..];
                if flags & flag::PADDED != 0 && !block.is_empty() {
                    let pad = block[0] as usize;
                    block = &block[1..];
                    block = &block[..block.len().saturating_sub(pad)];
                }
                if ty_ == ty::HEADERS && flags & flag::PRIORITY != 0 && block.len() >= 5 {
                    block = &block[5..];
                }
                let mut promised = None;
                if ty_ == ty::PUSH_PROMISE {
                    if block.len() < 4 {
                        return self.conn_error(c, err::FRAME_SIZE, "short PUSH_PROMISE");
                    }
                    promised = Some(
                        u32::from_be_bytes([block[0], block[1], block[2], block[3]]) & 0x7fff_ffff,
                    );
                    block = &block[4..];
                }
                let end_stream = flags & flag::END_STREAM != 0;
                if flags & flag::END_HEADERS == 0 {
                    self.cont = Some((sid, promised, block.to_vec(), end_stream));
                } else {
                    let b = block.to_vec();
                    self.headers_done(c, sid, promised, b, end_stream);
                }
            }
            ty::CONTINUATION => {
                let Some((s, promised, mut block, end_stream)) = self.cont.take() else {
                    return self.conn_error(c, err::PROTOCOL, "stray CONTINUATION");
                };
                if s != sid {
                    return self.conn_error(c, err::PROTOCOL, "CONTINUATION on another stream");
                }
                block.append(&mut p);
                // Bounded like the server: what a CONTINUATION flood may make us buffer.
                let cap = (self.opts.max_header_list as usize)
                    .saturating_mul(2)
                    .max(1 << 16);
                if block.len() > cap {
                    return self.conn_error(c, err::ENHANCE, "header block too large");
                }
                if flags & flag::END_HEADERS == 0 {
                    self.cont = Some((s, promised, block, end_stream));
                } else {
                    self.headers_done(c, s, promised, block, end_stream);
                }
            }
            _ => {}
        }
    }
}

impl H2Conn {
    fn read_frames(&mut self, c: &Conn<Self>) {
        loop {
            if self.rbuf.len() < 9 {
                return;
            }
            let len = u32::from_be_bytes([0, self.rbuf[0], self.rbuf[1], self.rbuf[2]]) as usize;
            // We never raise SETTINGS_MAX_FRAME_SIZE, so the default is the limit (§4.2); this
            // also bounds `rbuf` before a frame is buffered whole.
            if len > DEFAULT_FRAME as usize {
                self.rbuf.clear();
                return self.conn_error(c, err::FRAME_SIZE, "frame too large");
            }
            if self.rbuf.len() < 9 + len {
                return;
            }
            let ty_ = self.rbuf[3];
            let flags = self.rbuf[4];
            let sid = u32::from_be_bytes([self.rbuf[5], self.rbuf[6], self.rbuf[7], self.rbuf[8]])
                & 0x7fff_ffff;
            let payload = self.rbuf[9..9 + len].to_vec();
            self.rbuf.drain(..9 + len);
            self.handle(c, ty_, flags, sid, payload);
            if self.dead {
                return;
            }
        }
    }

    /// Over TLS, the server's first bytes: whether ALPN chose `h2` (if not, the dial fails).
    fn check_alpn(&mut self, c: &Conn<Self>) -> bool {
        let alpn = akio::tls::tls_info(c).and_then(|i| i.alpn);
        if alpn.as_deref() == Some(b"h2") {
            return true;
        }
        if let Some(cb) = self.ready.take() {
            cb(Err(NotH2::error(alpn)));
        }
        self.fail_all(ClientError::Closed);
        c.close();
        false
    }
}

impl Handler for H2Conn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if self.dead {
            return;
        }
        if self.ready.is_some() && !self.check_alpn(c) {
            return;
        }
        self.rbuf.extend_from_slice(data);
        self.read_frames(c);
        if !self.dead {
            self.after(c);
        }
        if let Some(cb) = self.ready.take() {
            if self.dead {
                cb(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "h2 connection failed on the server's first frame",
                )));
            } else {
                cb(Ok(H2Client {
                    conn: c.clone(),
                    shared: self.shared.clone(),
                }));
            }
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, err: Option<akio::Error>) {
        if let Some(cb) = self.ready.take() {
            let why = |what: &str| {
                let detail = err.as_ref().map(|e| format!(": {e}")).unwrap_or_default();
                io::Error::new(io::ErrorKind::ConnectionAborted, format!("{what}{detail}"))
            };
            cb(Err(match akio::tls::tls_info(c) {
                None => why("h2 connection closed before the server's first frame"),
                Some(i) if i.handshaking => why("TLS handshake did not complete"),
                Some(i) if i.alpn.as_deref() == Some(b"h2") => {
                    why("h2 connection closed before the server's first frame")
                }
                Some(i) => NotH2::error(i.alpn),
            }));
        }
        self.fail_all(ClientError::Closed);
    }
}
