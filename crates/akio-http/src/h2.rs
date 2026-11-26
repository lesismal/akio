//! HTTP/2 (RFC 9113) server connection: frames, HPACK (`crate::hpack`), streams, flow control
//! in both directions, trailers, server push, graceful shutdown and the h2c upgrade.
//!
//! A connection's state lives in one [`Core`] behind a mutex. The I/O thread feeds it frames;
//! responses finished on other threads ([`H2Responder`], [`H2Stream`]) lock it to encode and queue
//! their frames. User code is never called with the lock held.

use std::{
    collections::{HashMap, VecDeque},
    hash::{BuildHasherDefault, Hasher},
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::hpack::{Decoder, Encoder, class};
use crate::observe::{H2Shard, H2Stats};
use akio_core::ConnInner;
use akio_ws::{WsLink, WsSender, WsSession};

use crate::{
    context::{BodyEvent, BodyMode, Context, Service},
    message::{FileBody, Headers, Method, Request, Response, Spare, Version},
    session::Phase,
};

/// The client connection preface.
pub(crate) const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub(crate) mod err {
    pub(crate) const NO_ERROR: u32 = 0;
    pub(crate) const PROTOCOL: u32 = 1;
    pub(crate) const INTERNAL: u32 = 2;
    pub(crate) const FLOW_CONTROL: u32 = 3;
    pub(crate) const SETTINGS_TIMEOUT: u32 = 4;
    pub(crate) const STREAM_CLOSED: u32 = 5;
    pub(crate) const FRAME_SIZE: u32 = 6;
    pub(crate) const REFUSED_STREAM: u32 = 7;
    pub(crate) const CANCEL: u32 = 8;
    pub(crate) const COMPRESSION: u32 = 9;
    pub(crate) const ENHANCE: u32 = 11;
}

pub(crate) mod ty {
    pub(crate) const DATA: u8 = 0;
    pub(crate) const HEADERS: u8 = 1;
    pub(crate) const PRIORITY: u8 = 2;
    pub(crate) const RST_STREAM: u8 = 3;
    pub(crate) const SETTINGS: u8 = 4;
    pub(crate) const PUSH_PROMISE: u8 = 5;
    pub(crate) const PING: u8 = 6;
    pub(crate) const GOAWAY: u8 = 7;
    pub(crate) const WINDOW_UPDATE: u8 = 8;
    pub(crate) const CONTINUATION: u8 = 9;
}

pub(crate) mod flag {
    pub(crate) const END_STREAM: u8 = 0x1;
    pub(crate) const ACK: u8 = 0x1;
    pub(crate) const END_HEADERS: u8 = 0x4;
    pub(crate) const PADDED: u8 = 0x8;
    pub(crate) const PRIORITY: u8 = 0x20;
}

pub(crate) const MAX_WINDOW: i64 = (1 << 31) - 1;
pub(crate) const DEFAULT_WINDOW: i64 = 65_535;
pub(crate) const DEFAULT_FRAME: u32 = 16_384;

/// HTTP/2 limits and options.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct H2Config {
    /// Streams the peer may have open at once.
    pub max_concurrent_streams: u32,
    /// Per-stream receive window advertised to the peer.
    pub initial_window: u32,
    /// Connection-level receive window (raised right after the preface).
    pub conn_window: u32,
    /// Largest header list accepted (uncompressed size); larger requests are refused.
    pub max_header_list: u32,
    /// Largest buffered request body; larger ones are reset (streamed bodies have no limit).
    pub max_body_bytes: usize,
    /// Bytes a response may hold back for a slow peer before writers get `Overloaded`.
    pub max_pending_bytes: usize,
    /// Response bytes held in memory for a slow peer over the whole connection (every stream's
    /// queued body, from `respond` and from streamed writes; file bodies are read as the peer's
    /// windows open and do not count). A response that would go past it is reset with
    /// `ENHANCE_YOUR_CALM`, a streamed write gets `Overloaded`. Default 32 MiB.
    pub max_conn_pending_bytes: usize,
    /// Streams the peer may reset (`RST_STREAM`), or make the server reset by sending invalid
    /// frames on them, per [`reset_window`](Self::reset_window); past it the connection is
    /// closed with `GOAWAY ENHANCE_YOUR_CALM` (Rapid Reset, CVE-2023-44487, and its
    /// server-triggered variant). Default 100.
    pub max_resets: u32,
    /// Connection and stream counters to update (see [`H2Stats`]); `None` (the default) counts
    /// nothing.
    pub stats: Option<H2Stats>,
    /// Frames that make no progress (`PRIORITY`, `SETTINGS`, empty `DATA` without
    /// `END_STREAM`, empty `CONTINUATION`) the peer may send per
    /// [`reset_window`](Self::reset_window); past it the connection is closed with
    /// `GOAWAY ENHANCE_YOUR_CALM` (CVE-2019-9518 and friends). Default 1000.
    pub max_control_frames: u32,
    /// The window [`max_resets`](Self::max_resets) and
    /// [`max_control_frames`](Self::max_control_frames) are counted over. Default 30 s.
    pub reset_window: Duration,
    /// Advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` and accept extended CONNECT (RFC 8441):
    /// WebSocket over HTTP/2 through `Context::upgrade_websocket`, which a
    /// [`Router`](crate::Router) answers with the path's GET route. A request for another
    /// `:protocol` is just a request the service answers. When off, `:protocol` makes a
    /// request malformed (`RST_STREAM PROTOCOL_ERROR`). Default on.
    pub enable_connect_protocol: bool,
    /// Run each stream's service (middleware and handler) on the engine's logical pool instead
    /// of the connection's I/O thread, so handlers may block and the streams of one connection
    /// are served at the same time. Requests whose body the service takes as a stream, and
    /// CONNECTs (extended or not), stay on the I/O thread. When the pool's queue is full the
    /// stream is answered `503`. Default `false` (ADR-176): streams run inline, one at a time per
    /// connection, so a handler must not block (a single request can still go to the pool with
    /// [`Context::detach_to_pool`](crate::Context::detach_to_pool)). Inline is much faster for
    /// handlers that never block: about 3.2M-4.0M requests/s against 0.49M through the pool on
    /// the same 4 CPUs (docs/BENCHMARKS.md).
    pub handlers_on_logical_pool: bool,
}

impl Default for H2Config {
    fn default() -> Self {
        H2Config {
            max_concurrent_streams: 128,
            initial_window: 1 << 20,
            conn_window: 1 << 24,
            max_header_list: 64 << 10,
            max_body_bytes: 1 << 20,
            max_pending_bytes: 8 << 20,
            max_conn_pending_bytes: 32 << 20,
            max_resets: 100,
            max_control_frames: 1000,
            reset_window: Duration::from_secs(30),
            stats: None,
            enable_connect_protocol: true,
            handlers_on_logical_pool: false,
        }
    }
}

#[derive(Clone)]
struct Settings {
    header_table: u32,
    enable_push: bool,
    max_concurrent: u32,
    initial_window: i64,
    max_frame: u32,
    max_header_list: u32,
}

impl Settings {
    fn defaults() -> Settings {
        Settings {
            header_table: 4096,
            enable_push: true,
            max_concurrent: u32::MAX,
            initial_window: DEFAULT_WINDOW,
            max_frame: DEFAULT_FRAME,
            max_header_list: u32::MAX,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SState {
    Open,
    HalfClosedRemote,
    /// We sent END_STREAM; the peer may still send.
    HalfClosedLocal,
}

enum OutChunk {
    Bytes(Vec<u8>, usize),
    File {
        file: Arc<std::fs::File>,
        off: u64,
        left: u64,
    },
}

struct Stream {
    state: SState,
    send_window: i64,
    recv_window: i64,
    /// Receive window consumed by DATA and not yet given back.
    recv_owed: i64,
    /// Request being assembled from HEADERS.
    head: Option<Request>,
    body: Vec<u8>,
    content_length: Option<u64>,
    received: u64,
    streaming: bool,
    /// An accepted extended CONNECT (RFC 8441): the stream is a tunnel, half-closed in each
    /// direction on its own (END_STREAM from us does not cancel the peer's half).
    tunnel: bool,
    /// The request is a CONNECT or an extended CONNECT (RFC 9113 §8.5, RFC 8441): a streamed
    /// `2xx` answer makes it a tunnel.
    connect: bool,
    /// The context of a streamed request, or the WebSocket of a tunnel, parked here between
    /// body events.
    parked: Option<Parked>,
    // Response output.
    out: VecDeque<OutChunk>,
    out_bytes: usize,
    head_sent: bool,
    end_pending: bool,
    sent_end: bool,
    head_only: bool,
    /// Trailer fields to send after the body.
    trailers: Option<Headers>,
    /// A pushed stream: it is never used by the peer for requests.
    pushed: bool,
    /// The handler holds the request body's reads: the window consumed is not given back.
    held: bool,
    /// Waits for the queued response bytes to be framed ([`H2Stream::on_drain`]).
    drain: Option<Waiter>,
    /// Runs if the stream goes before its response ended ([`H2Responder::on_gone`], ADR-108):
    /// dropped with the stream, unless disarmed once the response ended.
    gone: Option<Waiter>,
}

/// A drain waiter: runs when it is dropped, so a stream or connection that goes away runs it
/// too. Only ever dropped outside the core's lock ([`Locked`]), as it runs user code.
struct Waiter(Option<Box<dyn FnOnce() + Send>>);

impl Drop for Waiter {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

impl Stream {
    /// A peer request whose buffered body is still arriving.
    fn receiving_buffered(&self) -> bool {
        !self.pushed
            && !self.streaming
            && matches!(self.state, SState::Open | SState::HalfClosedLocal)
    }

    fn new(state: SState, send_window: i64, recv_window: i64) -> Stream {
        Stream {
            state,
            send_window,
            recv_window,
            recv_owed: 0,
            head: None,
            body: Vec::new(),
            content_length: None,
            received: 0,
            streaming: false,
            tunnel: false,
            connect: false,
            parked: None,
            out: VecDeque::new(),
            out_bytes: 0,
            head_sent: false,
            end_pending: false,
            sent_end: false,
            head_only: false,
            trailers: None,
            pushed: false,
            held: false,
            drain: None,
            gone: None,
        }
    }

    /// The response ended (our END_STREAM went out): the stream going away is no longer the
    /// client going early.
    fn disarm_gone(&mut self) {
        if self.sent_end {
            if let Some(mut w) = self.gone.take() {
                w.0 = None;
            }
        }
    }
}

/// What waits on a stream for its body events.
enum Parked {
    /// A streamed request's context.
    Ctx(Box<Context>),
    /// The WebSocket a tunnel carries.
    Ws(WsPark),
}

/// A WebSocket carried by a stream (RFC 8441). When the stream goes away for any reason (a
/// reset either way, the connection lost or closed, the tunnel ended) it is dropped, outside the
/// core's lock (see [`Locked`]), and tells its handler (`on_close`, 1006 unless the close
/// handshake already ended it).
struct WsPark(Box<WsSession>);

impl Drop for WsPark {
    fn drop(&mut self) {
        self.0.on_transport_closed();
    }
}

struct Cont {
    stream: u32,
    block: Vec<u8>,
    end_stream: bool,
}

/// What the driver does after releasing the lock.
// The request is inline on purpose: the service runs in a `Context` built on the stack, so a
// request costs no boxed context (the vector of actions is reused, see `SPARE_ACTIONS`).
#[allow(clippy::large_enum_variant)]
enum Action {
    /// A complete request: run the service.
    Dispatch(Request, H2Responder),
    /// A streamed request began: run the service, then park its context on the stream.
    Start(u32, Box<Context>),
    /// Body bytes for a streamed request: a range of the buffer being parsed.
    Chunk(u32, std::ops::Range<usize>),
    /// End of a streamed request body.
    End(u32, Headers),
}

/// Hashes stream ids for the stream table: SipHash (the default) showed up at ~3% of h2c
/// throughput. Ids are chosen by the peer, but a stream table is bounded by
/// `max_concurrent_streams`, so collisions cannot grow it; the multiply-and-fold still spreads
/// odd ids over every bucket.
#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8 | u64::from(b)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }
    fn write_u32(&mut self, n: u32) {
        let h = u64::from(n).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = h ^ (h >> 29);
    }
}

type StreamMap = HashMap<u32, Stream, BuildHasherDefault<IdHasher>>;

/// A decoded header block, flat: every name and value in one buffer, reused across blocks (a
/// `Vec` per name and per value cost ~12 allocations per request).
#[derive(Default)]
struct Fields {
    buf: Vec<u8>,
    /// Per field: name at `buf[.0...1]`, value at `buf[.1...2]`, and the field's
    /// [`class`] (decoded blocks; 0 in the blocks we encode).
    spans: Vec<(usize, usize, usize, u8)>,
    /// The classes of every field, ORed.
    classes: u8,
}

impl Fields {
    fn clear(&mut self) {
        self.buf.clear();
        self.spans.clear();
        self.classes = 0;
    }
    fn push(&mut self, n: &[u8], v: &[u8], class: u8) {
        let a = self.buf.len();
        self.buf.extend_from_slice(n);
        let b = self.buf.len();
        self.buf.extend_from_slice(v);
        self.spans.push((a, b, self.buf.len(), class));
        self.classes |= class;
    }
    fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.spans
            .iter()
            .map(|&(a, b, c, _)| (&self.buf[a..b], &self.buf[b..c]))
    }

    /// The whole buffer as text when no name or value has a byte over 0x7F (the usual case):
    /// one UTF-8 check for the block rather than one per string.
    fn ascii(&self) -> Option<&str> {
        if self.classes & (class::NON_ASCII | class::NAME_NON_ASCII) != 0 {
            return None;
        }
        std::str::from_utf8(&self.buf).ok()
    }

    /// `buf[a..b]` as text: a slice of `ascii` (from [`Fields::ascii`]) when there is one,
    /// else checked on its own.
    fn text<'a>(&'a self, ascii: Option<&'a str>, a: usize, b: usize) -> Option<&'a str> {
        match ascii {
            Some(t) => t.get(a..b),
            None => std::str::from_utf8(&self.buf[a..b]).ok(),
        }
    }
}

type PushHook = Arc<dyn Fn(Request, H2Responder) + Send + Sync>;
type ModeFn = Arc<dyn Fn(&Request) -> BodyMode + Send + Sync>;

struct Core {
    conn: Arc<ConnInner>,
    cfg: H2Config,
    out: Vec<u8>,
    rbuf: Vec<u8>,
    preface: bool,
    got_settings: bool,
    local: Settings,
    remote: Settings,
    conn_send: i64,
    conn_recv: i64,
    dec: Decoder,
    enc: Encoder,
    streams: StreamMap,
    last_peer: u32,
    next_push: u32,
    cont: Option<Cont>,
    goaway_recv: bool,
    goaway_sent: bool,
    dead: bool,
    peer: SocketAddr,
    tls: bool,
    /// The client's verified certificate chain, for its requests.
    peer_certs: crate::session::PeerCerts,
    /// The connection began with TLS early data: every request is marked `Early-Data: 1`
    /// (offsets are not followed through the framing, so this errs on the safe side).
    early: bool,
    push_hook: Option<PushHook>,
    mode_of: Option<ModeFn>,
    me: Weak<CoreCell>,
    /// A stream error to raise once the header block it came with has been decoded.
    pending_rst: Option<(u32, u32)>,
    /// Peer-opened streams not yet finished (for the concurrency limit and graceful close).
    open_peer: u32,
    /// Streams removed under the lock, dropped once it is released (see [`Locked`]).
    dropped: Vec<Stream>,
    /// Drain waiters due, run once the lock is released.
    waiters: Vec<Waiter>,
    /// While the I/O thread works through one read, frames are only appended to `out`; the
    /// whole batch is handed to the connection once at the end (one write, one TLS record).
    batching: bool,
    /// Handlers run on the logical pool (`H2Config::handlers_on_logical_pool`): their complete
    /// responses come back to be written by the I/O thread (see [`Deferred`]).
    deferring: bool,
    /// The header block being decoded.
    fields: Fields,
    /// Scratch for encoding a header block: lowercased names and cleaned values.
    enc_fields: Fields,
    /// Connection-level receive window consumed and not yet given back.
    conn_recv_owed: u32,
    /// Response bytes queued in memory over every stream (see `max_conn_pending_bytes`).
    queued_mem: usize,
    /// Start of the current budget window, and what was spent in it.
    budget_start: Option<Instant>,
    resets: u32,
    control: u32,
    /// Offset of the buffer `next_frame` is looking at within the whole buffer being parsed.
    at: usize,
    /// A stream finished since the last read (the idle period restarts from it).
    finished: bool,
    /// This connection's shard of [`H2Config::stats`].
    stats: Option<Arc<H2Shard>>,
    /// The connection's close was counted (streams still open at that point included).
    stats_closed: bool,
}

impl Drop for Core {
    fn drop(&mut self) {
        self.count_close();
    }
}

/// A connection's core, and beside its lock the responses its pooled handlers finished
/// ([`Deferred`]), which pool threads queue without taking the lock.
struct CoreCell {
    core: Mutex<Core>,
    deferred: Option<Deferred>,
}

impl std::ops::Deref for CoreCell {
    type Target = Mutex<Core>;
    fn deref(&self) -> &Mutex<Core> {
        &self.core
    }
}

type Shared = Arc<CoreCell>;

/// Write batching for one read (see [`Core::flush`]): the queued frames go out when this is
/// dropped, also when the service panics.
struct Batch<'a>(&'a Shared);

impl Drop for Batch<'_> {
    fn drop(&mut self) {
        let mut c = lock(self.0);
        c.batching = false;
        c.flush_now();
    }
}

/// The locked core. Streams removed while it is held are dropped only after the lock is
/// released: a stream can own a parked request context whose drop runs user code (a gRPC sink,
/// a body stream) that responds, and so locks the core again.
struct Locked<'a>(Option<MutexGuard<'a, Core>>);

impl std::ops::Deref for Locked<'_> {
    type Target = Core;
    fn deref(&self) -> &Core {
        self.0.as_ref().expect("held")
    }
}

impl std::ops::DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut Core {
        self.0.as_mut().expect("held")
    }
}

/// Capacity of the pooled output buffer a batch of responses is written into (an akio-buf size
/// class: a buffer that outgrows it is reallocated and freed, not pooled, after the write).
const OUT_POOLED: usize = 4 << 10;

thread_local! {
    /// The actions vector of the last read on this thread, emptied, for the next one.
    static SPARE_ACTIONS: std::cell::Cell<Vec<Action>> = const { std::cell::Cell::new(Vec::new()) };
    /// An empty buffer with capacity, swapped with `Core::dropped` on unlock so that dropping
    /// finished streams outside the lock allocates nothing in the steady state (a fresh `Vec`
    /// per finished stream cost ~9% of h2c throughput).
    static SPARE_DROPPED: std::cell::Cell<Vec<Stream>> = const { std::cell::Cell::new(Vec::new()) };
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let Some(mut g) = self.0.take() else { return };
        if g.dropped.is_empty() && g.waiters.is_empty() {
            return;
        }
        let waiters = std::mem::take(&mut g.waiters);
        let mut dropped = SPARE_DROPPED.take();
        std::mem::swap(&mut dropped, &mut g.dropped);
        drop(g);
        dropped.clear(); // runs the streams' drops, outside the lock
        SPARE_DROPPED.set(dropped);
        drop(waiters); // runs them
    }
}

fn lock(s: &Shared) -> Locked<'_> {
    Locked(Some(s.lock().unwrap_or_else(|p| p.into_inner())))
}

pub(crate) fn frame(out: &mut Vec<u8>, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
    frame_head(out, payload.len(), ty, flags, sid);
    out.extend_from_slice(payload);
}

/// Appends the 9-byte frame header of a `len`-byte payload.
fn frame_head(out: &mut Vec<u8>, len: usize, ty: u8, flags: u8, sid: u32) {
    out.extend_from_slice(&frame_header(len, ty, flags, sid));
}

fn frame_header(len: usize, ty: u8, flags: u8, sid: u32) -> [u8; 9] {
    let mut h = [0u8; 9];
    h[..3].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    h[3] = ty;
    h[4] = flags;
    h[5..].copy_from_slice(&(sid & 0x7fff_ffff).to_be_bytes());
    h
}

enum Fail {
    /// Connection error: GOAWAY with this code.
    Conn(u32),
}

type R<T> = Result<T, Fail>;

impl Core {
    /// Hands the queued frames to the connection, unless the I/O thread is in the middle of a
    /// read (it flushes once at the end, see [`H2Session::feed`]).
    fn flush(&mut self) {
        if !self.batching {
            self.flush_now();
        }
    }

    fn flush_now(&mut self) {
        if !self.out.is_empty() {
            let out = std::mem::take(&mut self.out);
            let _ = self.conn.send_owned(out);
        } else if self.out.capacity() != 0 {
            // A pooled buffer nothing was written to goes back (an idle connection keeps none).
            akio_buf::put(std::mem::take(&mut self.out));
        }
    }

    /// Before a response's frames: an empty output buffer is taken from the thread's buffer
    /// pool, which gets it back once the connection has written it, instead of growing one
    /// from nothing (several reallocations per batch of responses).
    #[inline]
    fn out_pooled(&mut self) {
        if self.out.capacity() == 0 {
            self.out = akio_buf::get(OUT_POOLED);
        }
    }

    #[inline]
    fn stat(&self, f: impl FnOnce(&H2Shard) -> &AtomicU64) {
        if let Some(s) = &self.stats {
            H2Shard::inc(f(s));
        }
    }

    fn insert_stream(&mut self, sid: u32, st: Stream) {
        self.stat(|s| &s.streams_opened);
        self.streams.insert(sid, st);
    }

    /// Counts the connection as closed, with the streams it still has.
    fn count_close(&mut self) {
        if let Some(s) = &self.stats {
            if !std::mem::replace(&mut self.stats_closed, true) {
                H2Shard::inc(&s.conns_closed);
                s.streams_closed
                    .fetch_add(self.streams.len() as u64, Ordering::Relaxed);
            }
        }
    }

    fn rst(&mut self, sid: u32, code: u32) {
        self.stat(|s| &s.resets_sent);
        frame(&mut self.out, ty::RST_STREAM, 0, sid, &code.to_be_bytes());
        self.close_stream(sid);
    }

    fn goaway(&mut self, code: u32) {
        if self.goaway_sent {
            return;
        }
        self.goaway_sent = true;
        self.stat(|s| &s.goaways_sent);
        let mut p = self.last_peer.to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        frame(&mut self.out, ty::GOAWAY, 0, 0, &p);
    }

    fn conn_error(&mut self, code: u32) {
        self.goaway(code);
        self.dead = true;
        self.flush_now();
        self.conn.close_after_send();
    }

    fn close_stream(&mut self, sid: u32) {
        if let Some(mut s) = self.streams.remove(&sid) {
            s.disarm_gone();
            if !self.stats_closed {
                self.stat(|s| &s.streams_closed);
            }
            if sid % 2 == 1 && !s.pushed {
                self.open_peer = self.open_peer.saturating_sub(1);
            }
            self.finished = true;
            let mem: usize = s
                .out
                .iter()
                .map(|c| match c {
                    OutChunk::Bytes(v, off) => v.len() - off,
                    OutChunk::File { .. } => 0,
                })
                .sum();
            self.queued_mem = self.queued_mem.saturating_sub(mem);
            self.dropped.push(s);
        }
        self.maybe_close_after_goaway();
    }

    fn maybe_close_after_goaway(&mut self) {
        if self.goaway_sent && self.streams.is_empty() && !self.dead {
            self.dead = true;
            self.flush_now();
            self.conn.close_after_send();
        }
    }

    /// Spends one unit of the peer's reset (`reset`) or control-frame budget; a connection
    /// error once it is exhausted.
    fn charge(&mut self, reset: bool) -> R<()> {
        let now = Instant::now();
        if self
            .budget_start
            .is_none_or(|t| now.duration_since(t) >= self.cfg.reset_window)
        {
            self.budget_start = Some(now);
            self.resets = 0;
            self.control = 0;
        }
        let (n, max) = if reset {
            self.resets += 1;
            (self.resets, self.cfg.max_resets)
        } else {
            self.control += 1;
            (self.control, self.cfg.max_control_frames)
        };
        if n > max {
            return Err(Fail::Conn(err::ENHANCE));
        }
        Ok(())
    }

    /// A stream error caused by the peer: reset the stream, charged to the reset budget (the
    /// "made you reset" variant of Rapid Reset).
    fn peer_rst(&mut self, sid: u32, code: u32) -> R<()> {
        self.rst(sid, code);
        self.charge(true)
    }

    /// `peer_rst` for a stream that was never registered.
    fn peer_rst_new(&mut self, sid: u32, code: u32) -> R<()> {
        self.rst_new(sid, code);
        self.charge(true)
    }

    // ---- sending ---------------------------------------------------------------------------

    /// Writes HEADERS (+CONTINUATIONs) for `sid` with the given block.
    fn write_header_block(
        &mut self,
        ty_: u8,
        sid: u32,
        extra: &[u8],
        block: &[u8],
        end_stream: bool,
    ) {
        let max = self.remote.max_frame as usize;
        let first_cap = max.saturating_sub(extra.len());
        let (first, mut rest) = block.split_at(block.len().min(first_cap));
        let mut flags = if end_stream { flag::END_STREAM } else { 0 };
        if rest.is_empty() {
            flags |= flag::END_HEADERS;
        }
        let mut payload = extra.to_vec();
        payload.extend_from_slice(first);
        frame(&mut self.out, ty_, flags, sid, &payload);
        while !rest.is_empty() {
            let (chunk, r) = rest.split_at(rest.len().min(max));
            rest = r;
            let f = if rest.is_empty() {
                flag::END_HEADERS
            } else {
                0
            };
            frame(&mut self.out, ty::CONTINUATION, f, sid, chunk);
        }
    }

    /// Writes the HEADERS (+ CONTINUATION) frames of a header block for `sid`: `:status` when
    /// given, `headers` (names lowercased, hop-by-hop fields dropped, line breaks removed from
    /// values), then `date` when `add_date` and the headers have none, then `content-length`
    /// when given and the headers have none. The block is encoded straight into `out`.
    fn write_headers(
        &mut self,
        sid: u32,
        status: Option<u16>,
        headers: &Headers,
        add_date: bool,
        content_length: Option<u64>,
        end_stream: bool,
    ) {
        let mut f = std::mem::take(&mut self.enc_fields);
        f.clear();
        if let Some(s) = status {
            let a = f.buf.len();
            f.buf.extend_from_slice(b":status");
            let b = f.buf.len();
            crate::message::push_uint(&mut f.buf, u64::from(s));
            f.spans.push((a, b, f.buf.len(), 0));
        }
        let (mut has_date, mut has_len) = (false, false);
        for (n, v) in headers.iter() {
            let a = f.buf.len();
            f.buf.extend(n.bytes().map(|b| b.to_ascii_lowercase()));
            let b = f.buf.len();
            match &f.buf[a..b] {
                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
                | b"upgrade" | b"host" => {
                    f.buf.truncate(a);
                    continue;
                }
                b"date" => has_date = true,
                b"content-length" => has_len = true,
                _ => {}
            }
            if v.contains(['\r', '\n']) {
                f.buf
                    .extend(v.bytes().filter(|b| *b != b'\r' && *b != b'\n'));
            } else {
                f.buf.extend_from_slice(v.as_bytes());
            }
            f.spans.push((a, b, f.buf.len(), 0));
        }
        if add_date && !has_date {
            crate::message::with_http_date(|d| f.push(b"date", d.as_bytes(), 0));
        }
        if let (Some(len), false) = (content_length, has_len) {
            let a = f.buf.len();
            f.buf.extend_from_slice(b"content-length");
            let b = f.buf.len();
            crate::message::push_uint(&mut f.buf, len);
            f.spans.push((a, b, f.buf.len(), 0));
        }
        // Encode behind a placeholder frame header, which is filled in once the size is known.
        self.out_pooled();
        let start = self.out.len();
        self.out.extend_from_slice(&[0; 9]);
        self.enc.encode_into(f.iter(), &mut self.out);
        self.enc_fields = f;
        let len = self.out.len() - start - 9;
        if len <= self.remote.max_frame as usize {
            let mut flags = flag::END_HEADERS;
            if end_stream {
                flags |= flag::END_STREAM;
            }
            self.out[start..start + 9].copy_from_slice(&frame_header(len, ty::HEADERS, flags, sid));
        } else {
            // Larger than a frame: split into CONTINUATIONs.
            let block = self.out.split_off(start + 9);
            self.out.truncate(start);
            self.write_header_block(ty::HEADERS, sid, &[], &block, end_stream);
        }
    }

    /// Sends a complete response on `sid`.
    fn send_response(&mut self, sid: u32, mut resp: Response) {
        let Some(st) = self.streams.get(&sid) else {
            return;
        };
        let head_only = st.head_only;
        let bodyless = resp.status < 200 || resp.status == 204 || resp.status == 304;
        let len = resp.body_len();
        let content_length = (!bodyless && !resp.streaming).then_some(len);
        let no_body = head_only || bodyless || len == 0;
        if !no_body
            && resp.file.is_none()
            && self.queued_mem + resp.body.len() > self.cfg.max_conn_pending_bytes
        {
            // The peer is not reading what it asked for: do not hold more of it in memory.
            self.rst(sid, err::ENHANCE);
            self.flush();
            return;
        }
        let trailers = resp.trailers.take().filter(|_| !head_only);
        let end_with_head = no_body && trailers.is_none();
        self.write_headers(
            sid,
            Some(resp.status),
            &resp.headers,
            true,
            content_length,
            end_with_head,
        );
        std::mem::take(&mut resp.headers).recycle(Spare::Resp);
        let max_frame = self.remote.max_frame as usize;
        let conn_send = self.conn_send;
        let st = self.streams.get_mut(&sid).expect("stream still present");
        st.head_sent = true;
        st.trailers = trailers;
        if end_with_head {
            st.sent_end = true;
        } else if no_body {
            st.end_pending = true;
        } else {
            match resp.file.take() {
                Some(FileBody { file, offset, len }) => {
                    st.out.push_back(OutChunk::File {
                        file,
                        off: offset,
                        left: len,
                    });
                    st.out_bytes += len as usize;
                }
                None => {
                    let n = resp.body.len();
                    if st.trailers.is_none()
                        && n <= max_frame
                        && (n as i64) <= st.send_window
                        && (n as i64) <= conn_send
                    {
                        // The common case: the whole body fits one DATA frame and the windows.
                        st.send_window -= n as i64;
                        st.sent_end = true;
                        self.conn_send -= n as i64;
                        frame(&mut self.out, ty::DATA, flag::END_STREAM, sid, &resp.body);
                        // Copied out: the buffer is the thread's spare body buffer.
                        crate::message::recycle_body(resp.body);
                        self.finish_if_done(sid);
                        self.flush();
                        return;
                    }
                    st.out_bytes += n;
                    st.out
                        .push_back(OutChunk::Bytes(std::mem::take(&mut resp.body), 0));
                    self.queued_mem += n;
                }
            }
            st.end_pending = true;
        }
        self.after_send(sid);
    }

    /// Writes as much pending DATA as the windows allow, then finishes the stream if it is done.
    fn flush_stream(&mut self, sid: u32) {
        loop {
            let max = i64::from(self.remote.max_frame);
            let Some(st) = self.streams.get_mut(&sid) else {
                return;
            };
            if st.sent_end || !st.head_sent {
                break;
            }
            let allow = st.send_window.min(self.conn_send).min(max);
            let Some(chunk) = st.out.front_mut() else {
                // Everything queued is written.
                if st.end_pending {
                    if let Some(tr) = st.trailers.take() {
                        self.write_headers(sid, None, &tr, false, None, true);
                    } else {
                        frame(&mut self.out, ty::DATA, flag::END_STREAM, sid, &[]);
                    }
                    let st = self.streams.get_mut(&sid).expect("present");
                    st.sent_end = true;
                    st.end_pending = false;
                }
                break;
            };
            if allow <= 0 {
                break;
            }
            if let OutChunk::Bytes(v, off) = chunk {
                // Straight from the queued buffer into the output; END_STREAM is set below.
                let n = (v.len() - *off).min(allow as usize);
                let head = self.out.len();
                frame_head(&mut self.out, n, ty::DATA, 0, sid);
                self.out.extend_from_slice(&v[*off..*off + n]);
                *off += n;
                if *off == v.len() {
                    st.out.pop_front();
                }
                st.out_bytes = st.out_bytes.saturating_sub(n);
                st.send_window -= n as i64;
                self.conn_send -= n as i64;
                self.queued_mem = self.queued_mem.saturating_sub(n);
                if st.out.is_empty() && st.end_pending && st.trailers.is_none() {
                    st.sent_end = true;
                    st.end_pending = false;
                    self.out[head + 4] = flag::END_STREAM;
                }
                continue;
            }
            let mut buf = Vec::new();
            let done_chunk;
            match chunk {
                OutChunk::Bytes(..) => unreachable!("handled above"),
                OutChunk::File { file, off, left } => {
                    use std::os::unix::fs::FileExt;
                    let n = (*left).min(allow as u64) as usize;
                    buf.resize(n, 0);
                    match file.read_at(&mut buf, *off) {
                        Ok(0) | Err(_) => {
                            // The file shrank or broke: the response cannot be completed.
                            st.out.clear();
                            self.rst(sid, err::INTERNAL);
                            return;
                        }
                        Ok(r) => {
                            buf.truncate(r);
                            *off += r as u64;
                            *left -= r as u64;
                            done_chunk = *left == 0;
                        }
                    }
                }
            }
            let n = buf.len() as i64;
            if done_chunk {
                st.out.pop_front();
            }
            st.out_bytes = st.out_bytes.saturating_sub(buf.len());
            st.send_window -= n;
            self.conn_send -= n;
            let last = st.out.is_empty() && st.end_pending && st.trailers.is_none();
            if last {
                st.sent_end = true;
                st.end_pending = false;
            }
            frame(
                &mut self.out,
                ty::DATA,
                if last { flag::END_STREAM } else { 0 },
                sid,
                &buf,
            );
        }
        if let Some(st) = self.streams.get_mut(&sid) {
            if st.out_bytes == 0 {
                if let Some(w) = st.drain.take() {
                    self.waiters.push(w);
                }
            }
        }
        self.finish_if_done(sid);
    }

    /// A stream whose response is fully written is closed (or half-closed while the peer sends).
    fn finish_if_done(&mut self, sid: u32) {
        let Some(st) = self.streams.get_mut(&sid) else {
            return;
        };
        if !st.sent_end {
            return;
        }
        match st.state {
            // The peer has not ended its half of the tunnel yet.
            SState::HalfClosedLocal if st.tunnel => {}
            SState::HalfClosedRemote | SState::HalfClosedLocal => self.close_stream(sid),
            SState::Open if st.tunnel => {
                // A tunnel's halves close separately: the peer may still send (its close frame,
                // say) until it ends its own half. A peer that never ends it does not keep the
                // stream: it is reset (`CANCEL`) after `TUNNEL_LINGER`.
                st.state = SState::HalfClosedLocal;
                let weak = self.me.clone();
                crate::timer::after(TUNNEL_LINGER, move || {
                    if let Some(core) = weak.upgrade() {
                        let mut c = lock(&core);
                        if c.streams.contains_key(&sid) {
                            c.rst(sid, err::CANCEL);
                            c.flush();
                        }
                    }
                });
            }
            SState::Open => {
                // Answered before the request ended: ask the peer to stop sending.
                st.state = SState::HalfClosedLocal;
                self.stat(|s| &s.resets_sent);
                frame(
                    &mut self.out,
                    ty::RST_STREAM,
                    0,
                    sid,
                    &err::NO_ERROR.to_be_bytes(),
                );
                self.close_stream(sid);
            }
        }
    }

    fn after_send(&mut self, sid: u32) {
        self.flush_stream(sid);
        self.flush();
    }

    fn flush_all_streams(&mut self) {
        if !self
            .streams
            .values()
            .any(|s| !s.out.is_empty() || s.end_pending)
        {
            return;
        }
        let ids: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.out.is_empty() || s.end_pending)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.flush_stream(id);
        }
    }

    fn window_update(&mut self, sid: u32, inc: u32) {
        if inc > 0 {
            frame(&mut self.out, ty::WINDOW_UPDATE, 0, sid, &inc.to_be_bytes());
        }
    }

    /// Gives back the connection window consumed by DATA frames, once a quarter of it is owed
    /// (one WINDOW_UPDATE per batch of uploads rather than one per DATA frame).
    fn owe_conn_window(&mut self, n: u32) {
        self.conn_recv_owed = self.conn_recv_owed.saturating_add(n);
        if self.conn_recv_owed >= self.cfg.conn_window / 4 {
            let inc = std::mem::take(&mut self.conn_recv_owed);
            self.conn_recv += i64::from(inc);
            self.window_update(0, inc);
        }
    }

    // ---- deadlines ---------------------------------------------------------------------------

    /// Which deadline fits the connection now: the preface until the peer's first `SETTINGS`,
    /// body progress while a buffered request body is incomplete, idleness otherwise. Streamed
    /// request bodies (gRPC streams, say) are paced by their service and do not count.
    fn phase(&self) -> Phase {
        if self.dead {
            Phase::Off
        } else if !self.got_settings {
            Phase::Head
        } else if self.streams.values().any(Stream::receiving_buffered) {
            Phase::Body
        } else {
            Phase::Idle
        }
    }

    /// The armed deadline passed (see [`H2Session::on_deadline`]).
    fn on_deadline(&mut self) -> Option<Phase> {
        if self.dead {
            return None;
        }
        if !self.got_settings {
            self.conn_error(err::SETTINGS_TIMEOUT);
            return None;
        }
        let stalled: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, s)| s.receiving_buffered())
            .map(|(id, _)| *id)
            .collect();
        if stalled.is_empty() && self.streams.is_empty() {
            if std::mem::take(&mut self.finished) {
                // The last stream finished (a response sent later, from the pool, say) after
                // the last read: idle from then on.
                return Some(Phase::Idle);
            }
            self.goaway(err::NO_ERROR);
            self.flush();
            self.maybe_close_after_goaway();
            return None;
        }
        for sid in stalled {
            let answered = self.streams.get(&sid).is_none_or(|s| s.head_sent);
            if answered {
                self.rst(sid, err::CANCEL);
            } else {
                if let Some(st) = self.streams.get_mut(&sid) {
                    st.body = Vec::new();
                }
                self.send_response(sid, Response::text(408, "Request Timeout"));
            }
        }
        self.flush();
        Some(self.phase())
    }

    // ---- receiving -------------------------------------------------------------------------

    /// Parses and handles at most one frame at the start of `buf`, appending what the driver
    /// has to run to `actions`. Returns the bytes consumed, `Ok(None)` if more are needed.
    fn next_frame(&mut self, buf: &[u8], actions: &mut Vec<Action>) -> R<Option<usize>> {
        if !self.preface {
            if buf.len() < PREFACE.len() {
                if !PREFACE.starts_with(buf) {
                    return Err(Fail::Conn(err::PROTOCOL));
                }
                return Ok(None);
            }
            if &buf[..PREFACE.len()] != PREFACE {
                return Err(Fail::Conn(err::PROTOCOL));
            }
            self.preface = true;
            return Ok(Some(PREFACE.len()));
        }
        if buf.len() < 9 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
        let ty_ = buf[3];
        let flags = buf[4];
        let sid = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
        if len > self.local.max_frame {
            return Err(Fail::Conn(err::FRAME_SIZE));
        }
        let end = 9 + len as usize;
        if buf.len() < end {
            return Ok(None);
        }
        let payload = &buf[9..end];
        // The first frame must be SETTINGS; a header block must be continued without interruption.
        if !self.got_settings && ty_ != ty::SETTINGS {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        if let Some(c) = &self.cont {
            if ty_ != ty::CONTINUATION || sid != c.stream {
                return Err(Fail::Conn(err::PROTOCOL));
            }
        }
        match ty_ {
            ty::DATA => self.on_data_frame(sid, flags, payload, actions)?,
            ty::HEADERS => self.on_headers(sid, flags, payload, actions)?,
            ty::PRIORITY => self.on_priority(sid, payload)?,
            ty::RST_STREAM => self.on_rst(sid, payload)?,
            ty::SETTINGS => self.on_settings(sid, flags, payload)?,
            ty::PUSH_PROMISE => return Err(Fail::Conn(err::PROTOCOL)),
            ty::PING => {
                if sid != 0 {
                    return Err(Fail::Conn(err::PROTOCOL));
                }
                if payload.len() != 8 {
                    return Err(Fail::Conn(err::FRAME_SIZE));
                }
                if flags & flag::ACK == 0 {
                    frame(&mut self.out, ty::PING, flag::ACK, 0, payload);
                }
            }
            ty::GOAWAY => {
                if sid != 0 {
                    return Err(Fail::Conn(err::PROTOCOL));
                }
                if payload.len() < 8 {
                    return Err(Fail::Conn(err::FRAME_SIZE));
                }
                self.goaway_recv = true;
                self.stat(|s| &s.goaways_received);
            }
            ty::WINDOW_UPDATE => self.on_window_update(sid, payload)?,
            ty::CONTINUATION => self.on_continuation(sid, flags, payload, actions)?,
            _ => {} // unknown frame types are ignored
        }
        Ok(Some(end))
    }

    fn on_priority(&mut self, sid: u32, p: &[u8]) -> R<()> {
        if sid == 0 {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        self.charge(false)?;
        if p.len() != 5 {
            return self.peer_rst(sid, err::FRAME_SIZE);
        }
        let dep = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
        if dep == sid {
            return self.peer_rst(sid, err::PROTOCOL);
        }
        Ok(())
    }

    fn on_rst(&mut self, sid: u32, p: &[u8]) -> R<()> {
        if sid == 0 {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        if p.len() != 4 {
            return Err(Fail::Conn(err::FRAME_SIZE));
        }
        if self.is_idle(sid) {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        self.stat(|s| &s.resets_received);
        self.close_stream(sid);
        // Rapid Reset (CVE-2023-44487): opening streams and cancelling them at once costs the
        // server a dispatch each and the peer nothing.
        self.charge(true)
    }

    /// An id the peer has not opened yet (or one of ours we have not promised).
    fn is_idle(&self, sid: u32) -> bool {
        if sid % 2 == 1 {
            sid > self.last_peer
        } else {
            sid >= self.next_push
        }
    }

    fn on_settings(&mut self, sid: u32, flags: u8, p: &[u8]) -> R<()> {
        if sid != 0 {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        if flags & flag::ACK != 0 {
            if !p.is_empty() {
                return Err(Fail::Conn(err::FRAME_SIZE));
            }
            return Ok(());
        }
        if p.len() % 6 != 0 {
            return Err(Fail::Conn(err::FRAME_SIZE));
        }
        if self.got_settings {
            // Every SETTINGS is acknowledged and walks the streams: the first one is free.
            self.charge(false)?;
        }
        self.got_settings = true;
        for c in p.chunks_exact(6) {
            let id = u16::from_be_bytes([c[0], c[1]]);
            let v = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
            match id {
                1 => {
                    self.remote.header_table = v;
                    self.enc.set_max_table_size(v as usize);
                }
                2 => match v {
                    0 => self.remote.enable_push = false,
                    1 => self.remote.enable_push = true,
                    _ => return Err(Fail::Conn(err::PROTOCOL)),
                },
                3 => self.remote.max_concurrent = v,
                4 => {
                    if i64::from(v) > MAX_WINDOW {
                        return Err(Fail::Conn(err::FLOW_CONTROL));
                    }
                    let delta = i64::from(v) - self.remote.initial_window;
                    self.remote.initial_window = i64::from(v);
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                        if s.send_window > MAX_WINDOW {
                            return Err(Fail::Conn(err::FLOW_CONTROL));
                        }
                    }
                }
                5 => {
                    if !(DEFAULT_FRAME..=(1 << 24) - 1).contains(&v) {
                        return Err(Fail::Conn(err::PROTOCOL));
                    }
                    self.remote.max_frame = v;
                }
                6 => self.remote.max_header_list = v,
                _ => {}
            }
        }
        frame(&mut self.out, ty::SETTINGS, flag::ACK, 0, &[]);
        self.flush_all_streams();
        Ok(())
    }

    fn on_window_update(&mut self, sid: u32, p: &[u8]) -> R<()> {
        if p.len() != 4 {
            return Err(Fail::Conn(err::FRAME_SIZE));
        }
        let inc = i64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
        if sid == 0 {
            if inc == 0 {
                return Err(Fail::Conn(err::PROTOCOL));
            }
            self.conn_send += inc;
            if self.conn_send > MAX_WINDOW {
                return Err(Fail::Conn(err::FLOW_CONTROL));
            }
            self.flush_all_streams();
            return Ok(());
        }
        if self.is_idle(sid) {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        if inc == 0 {
            return self.peer_rst(sid, err::PROTOCOL);
        }
        let Some(s) = self.streams.get_mut(&sid) else {
            return Ok(()); // closed: allowed to arrive late
        };
        s.send_window += inc;
        if s.send_window > MAX_WINDOW {
            return self.peer_rst(sid, err::FLOW_CONTROL);
        }
        self.flush_stream(sid);
        Ok(())
    }

    fn on_data_frame(&mut self, sid: u32, flags: u8, p: &[u8], actions: &mut Vec<Action>) -> R<()> {
        if sid == 0 {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        let total = p.len() as i64;
        self.conn_recv -= total;
        if self.conn_recv < 0 {
            return Err(Fail::Conn(err::FLOW_CONTROL));
        }
        let mut data = p;
        let mut data_at = self.at + 9;
        if flags & flag::PADDED != 0 {
            data_at += 1;
            let Some((&pad, rest)) = p.split_first() else {
                return Err(Fail::Conn(err::FRAME_SIZE));
            };
            let pad = pad as usize;
            if pad >= p.len() {
                return Err(Fail::Conn(err::PROTOCOL));
            }
            data = &rest[..rest.len() - pad];
        }
        // Padding and data both consumed connection window: it is given back (in batches).
        self.owe_conn_window(total as u32);
        if self.is_idle(sid) {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        let end = flags & flag::END_STREAM != 0;
        if data.is_empty() && !end {
            self.charge(false)?; // an empty DATA frame carries nothing (CVE-2019-9518)
        }
        let Some(st) = self.streams.get_mut(&sid) else {
            // Frames still in flight on a stream that just closed: not the peer's fault, and
            // bounded by the connection window, so not charged.
            self.rst(sid, err::STREAM_CLOSED);
            return Ok(());
        };
        if st.state != SState::Open && st.state != SState::HalfClosedLocal {
            self.rst(sid, err::STREAM_CLOSED);
            return Ok(());
        }
        st.recv_window -= total;
        if st.recv_window < 0 {
            return self.peer_rst(sid, err::FLOW_CONTROL);
        }
        st.received += data.len() as u64;
        if let Some(cl) = st.content_length {
            if st.received > cl {
                return self.peer_rst(sid, err::PROTOCOL);
            }
        }
        if end {
            if let Some(cl) = st.content_length {
                if st.received != cl {
                    return self.peer_rst(sid, err::PROTOCOL);
                }
            }
        }
        // Replenish the stream window as data arrives (bodies are consumed immediately), once
        // a quarter of it is owed.
        if total > 0 && !end {
            st.recv_owed += total;
            // Held by the handler (`BodyReads::hold`): given back when it resumes.
            if !st.held && st.recv_owed >= self.local.initial_window / 4 {
                let inc = std::mem::take(&mut st.recv_owed);
                st.recv_window += inc;
                self.window_update(sid, inc as u32);
            }
        }
        let st = self.streams.get_mut(&sid).expect("present");
        if st.streaming {
            if !data.is_empty() {
                actions.push(Action::Chunk(sid, data_at..data_at + data.len()));
            }
            if end {
                st.state = SState::HalfClosedRemote;
                actions.push(Action::End(sid, Headers::new()));
            }
        } else {
            if st.body.len() + data.len() > self.cfg.max_body_bytes {
                // Too big to buffer: answer 413; the stream is reset after the answer (the rest
                // of the upload is not wanted).
                st.body = Vec::new();
                self.send_response(sid, Response::text(413, "Payload Too Large"));
                self.flush();
                return Ok(());
            }
            st.body.extend_from_slice(data);
            if end {
                st.state = SState::HalfClosedRemote;
                if let Some(a) = self.complete_request(sid) {
                    actions.push(a);
                }
            }
        }
        Ok(())
    }

    fn on_headers(&mut self, sid: u32, flags: u8, p: &[u8], actions: &mut Vec<Action>) -> R<()> {
        if sid == 0 || sid % 2 == 0 {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        let mut block = p;
        let mut pad = 0usize;
        if flags & flag::PADDED != 0 {
            let Some((&pl, rest)) = block.split_first() else {
                return Err(Fail::Conn(err::FRAME_SIZE));
            };
            pad = pl as usize;
            block = rest;
        }
        if flags & flag::PRIORITY != 0 {
            if block.len() < 5 {
                return Err(Fail::Conn(err::FRAME_SIZE));
            }
            let dep = u32::from_be_bytes([block[0], block[1], block[2], block[3]]) & 0x7fff_ffff;
            block = &block[5..];
            if dep == sid {
                // Self-dependency is a stream error; the header block must still be decoded.
                self.pending_rst = Some((sid, err::PROTOCOL));
            }
        }
        if pad > block.len() {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        let block = &block[..block.len() - pad];
        let end_stream = flags & flag::END_STREAM != 0;
        if flags & flag::END_HEADERS == 0 {
            self.cont = Some(Cont {
                stream: sid,
                block: block.to_vec(),
                end_stream,
            });
            return Ok(());
        }
        self.headers_complete(sid, block, end_stream, actions)
    }

    fn on_continuation(
        &mut self,
        sid: u32,
        flags: u8,
        p: &[u8],
        actions: &mut Vec<Action>,
    ) -> R<()> {
        let Some(mut c) = self.cont.take() else {
            return Err(Fail::Conn(err::PROTOCOL));
        };
        if sid != c.stream {
            return Err(Fail::Conn(err::PROTOCOL));
        }
        if p.is_empty() && flags & flag::END_HEADERS == 0 {
            self.charge(false)?;
        }
        c.block.extend_from_slice(p);
        if c.block.len()
            > (self.cfg.max_header_list as usize)
                .saturating_mul(2)
                .max(1 << 16)
        {
            return Err(Fail::Conn(err::ENHANCE));
        }
        if flags & flag::END_HEADERS == 0 {
            self.cont = Some(c);
            return Ok(());
        }
        self.headers_complete(sid, &c.block, c.end_stream, actions)
    }

    /// A whole header block arrived: decode it (always: HPACK state must stay in step), then treat
    /// it as request headers or trailers.
    fn headers_complete(
        &mut self,
        sid: u32,
        block: &[u8],
        end_stream: bool,
        actions: &mut Vec<Action>,
    ) -> R<()> {
        // The whole block is decoded even past the header list limit (the dynamic table must
        // stay in step); fields past it are not kept. The list size counts name + value + 32
        // per field (RFC 9113 §6.5.2).
        let limit = self.cfg.max_header_list as usize;
        let mut fields = std::mem::take(&mut self.fields);
        fields.clear();
        let mut size = 0usize;
        let decoded = self.dec.decode_classified(block, |n, v, _, class| {
            size = size.saturating_add(n.len() + v.len() + 32);
            if size <= limit {
                fields.push(n, v, class);
            }
        });
        let r = match decoded {
            Ok(()) => self.on_header_fields(sid, &fields, size, end_stream, actions),
            Err(_) => Err(Fail::Conn(err::COMPRESSION)),
        };
        self.fields = fields;
        r
    }

    fn on_header_fields(
        &mut self,
        sid: u32,
        fields: &Fields,
        size: usize,
        end_stream: bool,
        actions: &mut Vec<Action>,
    ) -> R<()> {
        let limit = self.cfg.max_header_list as usize;
        if let Some((s, code)) = self.pending_rst.take() {
            if s == sid {
                self.last_peer = self.last_peer.max(sid);
                return self.peer_rst_new(sid, code);
            }
        }
        let existing = self.streams.contains_key(&sid);
        if existing {
            if size > limit {
                return self.peer_rst(sid, err::PROTOCOL); // trailers past the header list limit
            }
            return self.trailers(sid, fields, end_stream, actions);
        }
        if sid <= self.last_peer {
            // A closed stream cannot carry headers.
            return Err(Fail::Conn(err::STREAM_CLOSED));
        }
        self.last_peer = sid;
        if self.goaway_sent {
            return Ok(()); // ignored after our GOAWAY
        }
        if self.open_peer >= self.cfg.max_concurrent_streams || size > limit {
            self.frame_refuse(sid);
            return self.charge(true);
        }
        let Ok(req) = self.build_request(fields) else {
            return self.peer_rst_new(sid, err::PROTOCOL);
        };
        let content_length = match req.headers.get("content-length") {
            None => None,
            Some(v) => match v.parse::<u64>() {
                Ok(n) => Some(n),
                Err(_) => return self.peer_rst_new(sid, err::PROTOCOL),
            },
        };
        self.open_peer += 1;
        let state = if end_stream {
            SState::HalfClosedRemote
        } else {
            SState::Open
        };
        let mut st = Stream::new(state, self.remote.initial_window, self.local.initial_window);
        st.content_length = content_length;
        st.head_only = req.method == Method::Head;
        if req.method == Method::Connect {
            // A CONNECT (RFC 9113 §8.5, A134) or an extended CONNECT (RFC 8441): dispatched now;
            // the stream's DATA follows as the body of a streamed request, or to the WebSocket
            // the handler accepts. A streamed `2xx` makes the stream a tunnel.
            st.streaming = true;
            st.connect = true;
            let resp = H2Responder::new(self.me.clone(), sid, false);
            self.insert_stream(sid, st);
            actions.push(Action::Start(sid, Box::new(Context::new_h2(req, resp))));
            if end_stream {
                actions.push(Action::End(sid, Headers::new()));
            }
            return Ok(());
        }
        if end_stream {
            self.insert_stream(sid, st);
            if content_length.is_some_and(|cl| cl != 0) {
                return self.peer_rst(sid, err::PROTOCOL);
            }
            // A request without a body: dispatched right away, nothing parked on the stream.
            let resp = self.dispatch_responder(sid, req.method == Method::Head);
            actions.push(Action::Dispatch(req, resp));
            return Ok(());
        }
        // Does the service want the body as a stream?
        let mode = self
            .mode_of
            .as_ref()
            .map_or(BodyMode::Buffered, |f| f(&req));
        if mode == BodyMode::Stream {
            // The request goes to the service now; trailers reach it with the end event.
            st.streaming = true;
            let resp = H2Responder::new(self.me.clone(), sid, req.method == Method::Head);
            self.insert_stream(sid, st);
            actions.push(Action::Start(sid, Box::new(Context::new_h2(req, resp))));
            return Ok(());
        }
        st.head = Some(req);
        self.insert_stream(sid, st);
        Ok(())
    }

    fn frame_refuse(&mut self, sid: u32) {
        self.stat(|s| &s.resets_sent);
        frame(
            &mut self.out,
            ty::RST_STREAM,
            0,
            sid,
            &err::REFUSED_STREAM.to_be_bytes(),
        );
    }

    /// RST_STREAM for a stream that was never registered.
    fn rst_new(&mut self, sid: u32, code: u32) {
        self.stat(|s| &s.resets_sent);
        frame(&mut self.out, ty::RST_STREAM, 0, sid, &code.to_be_bytes());
    }

    fn trailers(
        &mut self,
        sid: u32,
        fields: &Fields,
        end_stream: bool,
        actions: &mut Vec<Action>,
    ) -> R<()> {
        let Some(st) = self.streams.get_mut(&sid) else {
            return Ok(());
        };
        if st.state == SState::HalfClosedRemote {
            return self.peer_rst(sid, err::STREAM_CLOSED);
        }
        if !end_stream {
            // Trailers must end the stream.
            return self.peer_rst(sid, err::PROTOCOL);
        }
        let mut tr = Headers::new();
        // RFC 9113 §8.2.1 (A169): no pseudo-header, a name with no byte a token cannot hold, a
        // value with no NUL, CR or LF (`BAD_NAME` covers the colon of a pseudo-header).
        if fields.classes & (class::BAD_NAME | class::BAD_VALUE) != 0 {
            return self.peer_rst(sid, err::PROTOCOL);
        }
        let ascii = fields.ascii();
        for &(a, b, c, _) in &fields.spans {
            if let (Some(n), Some(v)) = (fields.text(ascii, a, b), fields.text(ascii, b, c)) {
                tr.append(n, v);
            }
        }
        let st = self.streams.get_mut(&sid).expect("present");
        if let Some(cl) = st.content_length {
            if st.received != cl {
                return self.peer_rst(sid, err::PROTOCOL);
            }
        }
        st.state = SState::HalfClosedRemote;
        if st.streaming {
            actions.push(Action::End(sid, tr));
            return Ok(());
        }
        if let Some(h) = st.head.as_mut() {
            h.trailers = tr;
        }
        actions.extend(self.complete_request(sid));
        Ok(())
    }

    /// The responder of a complete request: one that hands its response back to the I/O thread
    /// when sent from a pooled handler ([`Deferred`]).
    fn dispatch_responder(&self, sid: u32, head_only: bool) -> H2Responder {
        let mut r = H2Responder::new(self.me.clone(), sid, head_only);
        r.deferred = self.deferring;
        r
    }

    /// Turns the assembled request into a context to dispatch.
    fn complete_request(&mut self, sid: u32) -> Option<Action> {
        let st = self.streams.get_mut(&sid)?;
        let mut req = st.head.take()?;
        req.body = std::mem::take(&mut st.body);
        let resp = self.dispatch_responder(sid, req.method == Method::Head);
        Some(Action::Dispatch(req, resp))
    }

    fn build_request(&mut self, fields: &Fields) -> Result<Request, ()> {
        let (pseudo, mut headers) = request_fields(fields, self.cfg.enable_connect_protocol)?;
        let Pseudo {
            method,
            path,
            authority,
            scheme,
            protocol,
        } = pseudo;
        let method = method.ok_or(())?;
        let path = if method == "CONNECT" && protocol.is_none() {
            // A CONNECT (RFC 9113 §8.5): `:authority` alone names the tunnel's host and port,
            // `:scheme` and `:path` are omitted; the target is the authority, as an HTTP/1.1
            // CONNECT's (A134).
            if scheme.is_some() || path.is_some() {
                return Err(());
            }
            authority.ok_or(())?
        } else {
            let path = path.ok_or(())?;
            scheme.ok_or(())?;
            // `:path` is in origin form, or `*` for `OPTIONS` (RFC 9113 §8.3.1): an absolute
            // URI or anything else is malformed, so no request is routed by a target that is
            // not a path (ADR-177).
            if !(path.starts_with('/') || (path == "*" && method == "OPTIONS")) {
                return Err(());
            }
            // An extended CONNECT carries every pseudo-header field (RFC 8441 §4).
            if protocol.is_some() && (method != "CONNECT" || path.is_empty() || authority.is_none())
            {
                return Err(());
            }
            path
        };
        if let Some(a) = authority {
            if headers.get("host").is_none() {
                headers.append("host", a);
            }
        }
        if self.early {
            headers.append("early-data", "1");
        }
        Ok(Request {
            method: Method::parse(method),
            target: crate::context::new_target(path),
            version: Version::Http2,
            headers,
            trailers: Headers::new(),
            body: Vec::new(),
            peer: self.peer,
            local: self.conn.local_addr(),
            protocol: protocol.map(str::to_owned),
            peer_certificates: self.peer_certs.get(&self.conn),
            absolute: None,
        })
    }
}

/// A request's pseudo-header fields.
#[derive(Default)]
struct Pseudo<'a> {
    method: Option<&'a str>,
    path: Option<&'a str>,
    authority: Option<&'a str>,
    scheme: Option<&'a str>,
    protocol: Option<&'a str>,
}

/// A request header block's pseudo-header fields and regular fields, or `Err` when it is
/// malformed (RFC 9113 §8.2-8.3): a pseudo-header after a regular field, unknown or repeated, a
/// name or value RFC 9113 §8.2.1 refuses, a connection-specific field, `te` other than
/// `trailers`, not UTF-8. `connect_protocol`: whether `:protocol` is allowed (RFC 8441 §3).
fn request_fields(fields: &Fields, connect_protocol: bool) -> Result<(Pseudo<'_>, Headers), ()> {
    if fields.classes & class::BAD_VALUE != 0 {
        return Err(()); // a NUL, CR or LF: RFC 9113 §8.2.1, pseudo-header fields too (A169)
    }
    let Pseudo {
        mut method,
        mut path,
        mut authority,
        mut scheme,
        mut protocol,
    } = Pseudo::default();
    // The regular fields fit in one allocation (the pseudo-headers are not kept as fields;
    // a request with few regular fields keeps their positions inline).
    let n = fields
        .spans
        .iter()
        .filter(|&&(a, b, _, _)| a == b || fields.buf[a] != b':')
        .count();
    let mut headers = Headers::spare(Spare::Req, n, fields.buf.len());
    let mut regular = false;
    let mut cookies: Option<String> = None;
    let ascii = fields.ascii();
    for &(a, b, c, cl) in &fields.spans {
        let n = &fields.buf[a..b];
        let v = fields.text(ascii, b, c).ok_or(())?;
        if n.first() == Some(&b':') {
            if regular {
                return Err(()); // pseudo-header after a regular one
            }
            let slot = match n {
                b":method" => &mut method,
                b":path" => &mut path,
                b":authority" => &mut authority,
                b":scheme" => &mut scheme,
                // Only once we allowed it (RFC 8441 §3).
                b":protocol" if connect_protocol => &mut protocol,
                _ => return Err(()),
            };
            if slot.replace(v).is_some() {
                return Err(());
            }
            continue;
        }
        regular = true;
        if cl & class::BAD_NAME != 0 {
            return Err(()); // RFC 9113 §8.2.1: uppercase, a byte no token holds (A169)
        }
        let n = fields.text(ascii, a, b).ok_or(())?;
        match n {
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" => {
                return Err(());
            }
            "te" if v != "trailers" => return Err(()),
            "cookie" => match &mut cookies {
                Some(c) => {
                    c.push_str("; ");
                    c.push_str(v);
                }
                None => cookies = Some(v.to_owned()),
            },
            _ => headers.append(n, v),
        }
    }
    if let Some(c) = cookies {
        headers.append("cookie", c);
    }
    Ok((
        Pseudo {
            method,
            path,
            authority,
            scheme,
            protocol,
        },
        headers,
    ))
}

// ---- response side, usable from any thread ---------------------------------------------------

/// The complete responses of a connection's handlers that ran on the logical pool
/// (`H2Config::handlers_on_logical_pool`), on their way back to the connection's owning thread
/// (its I/O thread, or the worker of its next round). A pool thread only queues its response
/// and, if no drain is pending, posts one ([`ConnInner::run_on_loop`]); the drain locks the
/// core once and encodes and writes the whole batch, as an inline read does. Written from the
/// pool threads themselves, every response cost a `send` (and a TCP segment) and a fight over
/// the core's lock with the connection's other streams finishing at the same time: about 9 us
/// of CPU per request against 1 us inline (docs/BENCHMARKS.md).
struct Deferred {
    conn: Arc<ConnInner>,
    queue: Mutex<Vec<(u32, Response)>>,
    /// A drain is posted and has not yet taken the queue.
    posted: AtomicBool,
    /// The drain's spare vector (only the owning thread touches it).
    spare: Mutex<Vec<(u32, Response)>>,
}

impl Deferred {
    fn new(conn: Arc<ConnInner>) -> Deferred {
        Deferred {
            conn,
            queue: Mutex::new(Vec::new()),
            posted: AtomicBool::new(false),
            spare: Mutex::new(Vec::new()),
        }
    }

    fn push(cell: &Shared, sid: u32, resp: Response) {
        let Some(d) = &cell.deferred else { return };
        d.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((sid, resp));
        // Queued before the flag is looked at, and the drain clears the flag before it takes
        // the queue: a response is either taken by a pending drain or posts a new one.
        if !d.posted.swap(true, Ordering::SeqCst) {
            let cell = cell.clone();
            if !d.conn.run_on_loop(move || Deferred::drain(&cell)) {
                // Closed: nothing will write them; the streams went with the connection.
                d.queue.lock().unwrap_or_else(|p| p.into_inner()).clear();
            }
        }
    }

    /// On the connection's owning thread: writes everything queued, in one go.
    fn drain(cell: &Shared) {
        let Some(d) = &cell.deferred else { return };
        d.posted.store(false, Ordering::SeqCst);
        let mut batch = std::mem::take(&mut *d.spare.lock().unwrap_or_else(|p| p.into_inner()));
        std::mem::swap(
            &mut batch,
            &mut *d.queue.lock().unwrap_or_else(|p| p.into_inner()),
        );
        {
            let mut c = lock(cell);
            let batching = c.batching;
            c.batching = true;
            for (sid, resp) in batch.drain(..) {
                c.send_response(sid, resp);
            }
            c.batching = batching;
            c.flush();
        }
        *d.spare.lock().unwrap_or_else(|p| p.into_inner()) = batch;
    }
}

/// Sends the response of one HTTP/2 stream.
#[derive(Clone)]
pub(crate) struct H2Responder {
    core: Weak<CoreCell>,
    sid: u32,
    head_only: bool,
    /// Set on the responders of requests dispatched to the logical pool (see [`Deferred`]).
    deferred: bool,
}

impl H2Responder {
    fn new(core: Weak<CoreCell>, sid: u32, head_only: bool) -> H2Responder {
        H2Responder {
            core,
            sid,
            head_only,
            deferred: false,
        }
    }

    pub(crate) fn send(&self, resp: Response) {
        // From the handler of a request dispatched to the pool, on its pool job: back to the
        // I/O thread. Anything else (detached work, other threads, timers) writes it here.
        if self.deferred && crate::pool::deferring() {
            if let Some(cell) = self.core.upgrade() {
                Deferred::push(&cell, self.sid, resp);
            }
            return;
        }
        if let Some(core) = self.core.upgrade() {
            lock(&core).send_response(self.sid, resp);
        }
    }

    /// Gives the response up before its head went: resets the stream (ADR-128).
    pub(crate) fn reset(&self) {
        if let Some(core) = self.core.upgrade() {
            let mut c = lock(&core);
            if c.streams.contains_key(&self.sid) {
                c.rst(self.sid, err::INTERNAL);
                c.flush();
            }
        }
    }

    /// Holds the reads of this stream's request body.
    pub(crate) fn reads(&self) -> H2Reads {
        H2Reads {
            core: self.core.clone(),
            sid: self.sid,
        }
    }

    /// Runs `f` if the stream goes (reset by the peer, the connection closed) before its
    /// response ended; at once when it is gone already. Replaces an earlier one.
    pub(crate) fn on_gone(&self, f: Box<dyn FnOnce() + Send>) {
        let Some(core) = self.core.upgrade() else {
            return f();
        };
        let mut c = lock(&core);
        let Some(st) = c.streams.get_mut(&self.sid) else {
            drop(c);
            return f();
        };
        if let Some(mut old) = st.gone.replace(Waiter(Some(f))) {
            old.0 = None;
        }
    }

    /// The connection, while the session lives.
    pub(crate) fn conn(&self) -> Option<Arc<ConnInner>> {
        self.core.upgrade().map(|c| lock(&c).conn.clone())
    }

    /// Starts a response whose body is written later; `None` if the connection is gone.
    pub(crate) fn start_stream(&self, resp: Response) -> Option<H2Stream> {
        let core = self.core.upgrade()?;
        {
            let mut c = lock(&core);
            if !c.streams.contains_key(&self.sid) {
                return None;
            }
            let end = self.head_only;
            c.write_headers(self.sid, Some(resp.status), &resp.headers, true, None, end);
            if let Some(st) = c.streams.get_mut(&self.sid) {
                st.head_sent = true;
                // A `2xx` streamed to a CONNECT or an extended CONNECT opens the tunnel (RFC 9113
                // §8.5, RFC 8441 section 5, ADR-113, ADR-122): the stream's halves close
                // separately from now on.
                if st.connect && (200..300).contains(&resp.status) {
                    st.tunnel = true;
                }
                if end {
                    st.sent_end = true;
                }
            }
            c.finish_if_done(self.sid);
            c.flush();
        }
        Some(H2Stream {
            core: self.core.clone(),
            sid: self.sid,
            head_only: self.head_only,
            done: false,
        })
    }

    /// Accepts an extended CONNECT (RFC 8441): sends `resp`'s head without ending the stream,
    /// which carries the tunnel from now on. `false` if the stream is gone.
    pub(crate) fn start_tunnel(&self, resp: &Response) -> bool {
        let Some(core) = self.core.upgrade() else {
            return false;
        };
        let mut c = lock(&core);
        if c.streams.get(&self.sid).is_none_or(|s| s.head_sent) {
            return false;
        }
        c.write_headers(
            self.sid,
            Some(resp.status),
            &resp.headers,
            true,
            None,
            false,
        );
        if let Some(st) = c.streams.get_mut(&self.sid) {
            st.head_sent = true;
            st.tunnel = true;
        }
        c.flush();
        true
    }

    /// Promises (and starts serving) `path` on a new stream. `false` if pushing is not possible.
    pub(crate) fn push(&self, path: &str, authority: &str) -> bool {
        let Some(core) = self.core.upgrade() else {
            return false;
        };
        let (promised, hook, req) = {
            let mut c = lock(&core);
            // PUSH_PROMISE only goes on a peer-initiated stream (RFC 9113 §6.6): a pushed
            // request cannot push again (which also bounds handlers that push recursively). The
            // peer's concurrency limit covers pushed streams, and stream ids must not wrap.
            let pushed_open = c.streams.values().filter(|s| s.pushed).count();
            if !c.remote.enable_push
                || c.goaway_recv
                || c.goaway_sent
                || self.sid % 2 == 0
                || !c.streams.contains_key(&self.sid)
                || pushed_open >= c.remote.max_concurrent as usize
                || c.next_push > 0x7fff_ffff
            {
                return false;
            }
            let Some(hook) = c.push_hook.clone() else {
                return false;
            };
            let promised = c.next_push;
            c.next_push += 2;
            let scheme = if c.tls { "https" } else { "http" };
            let list: Vec<(Vec<u8>, Vec<u8>)> = vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), scheme.as_bytes().to_vec()),
                (b":authority".to_vec(), authority.as_bytes().to_vec()),
                (b":path".to_vec(), path.as_bytes().to_vec()),
            ];
            let block = c
                .enc
                .encode(list.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
            c.write_header_block(
                ty::PUSH_PROMISE,
                self.sid,
                &promised.to_be_bytes(),
                &block,
                false,
            );
            let mut st = Stream::new(
                SState::HalfClosedRemote,
                c.remote.initial_window,
                c.local.initial_window,
            );
            st.pushed = true;
            c.insert_stream(promised, st);
            c.flush();
            let mut headers = Headers::new();
            headers.append("host", authority);
            let core = &mut *c;
            let peer_certificates = core.peer_certs.get(&core.conn);
            let req = Request {
                method: Method::Get,
                target: path.to_owned(),
                version: Version::Http2,
                headers,
                trailers: Headers::new(),
                body: Vec::new(),
                peer: c.peer,
                local: c.conn.local_addr(),
                protocol: None,
                peer_certificates,
                absolute: None,
            };
            (promised, hook, req)
        };
        hook(req, H2Responder::new(self.core.clone(), promised, false));
        true
    }
}

/// Holds the reads of a streamed request body on an HTTP/2 stream
/// ([`BodyReads`](crate::BodyReads)): its flow-control window is not given back meanwhile.
#[derive(Clone)]
pub(crate) struct H2Reads {
    core: Weak<CoreCell>,
    sid: u32,
}

impl H2Reads {
    pub(crate) fn hold(&self, hold: bool) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        let mut c = lock(&core);
        let Some(st) = c.streams.get_mut(&self.sid) else {
            return;
        };
        if st.held == hold {
            return;
        }
        st.held = hold;
        if hold || st.recv_owed == 0 || !matches!(st.state, SState::Open | SState::HalfClosedLocal)
        {
            return;
        }
        let inc = std::mem::take(&mut st.recv_owed);
        st.recv_window += inc;
        c.window_update(self.sid, inc as u32);
        c.flush();
    }
}

/// A response body being written in pieces on an HTTP/2 stream.
pub(crate) struct H2Stream {
    core: Weak<CoreCell>,
    sid: u32,
    head_only: bool,
    done: bool,
}

impl H2Stream {
    pub(crate) fn write(&self, data: &[u8]) -> akio_core::Result<()> {
        if data.is_empty() || self.head_only {
            return Ok(());
        }
        let core = self.core.upgrade().ok_or(akio_core::Error::Closed)?;
        let mut c = lock(&core);
        let max = c.cfg.max_pending_bytes;
        let conn_full = c.queued_mem + data.len() > c.cfg.max_conn_pending_bytes;
        let Some(st) = c.streams.get_mut(&self.sid) else {
            return Err(akio_core::Error::Closed);
        };
        if conn_full || st.out_bytes + data.len() > max {
            return Err(akio_core::Error::Overloaded);
        }
        st.out_bytes += data.len();
        st.out.push_back(OutChunk::Bytes(data.to_vec(), 0));
        c.queued_mem += data.len();
        c.flush_stream(self.sid);
        c.flush();
        Ok(())
    }

    pub(crate) fn queued_bytes(&self) -> usize {
        self.core.upgrade().map_or(0, |c| {
            lock(&c).streams.get(&self.sid).map_or(0, |s| s.out_bytes)
        })
    }

    /// Runs `f` once the stream's queued bytes are all framed (at once if they are), or when
    /// the stream or the connection goes away. Replaces an earlier waiter.
    pub(crate) fn on_drain(&self, f: Box<dyn FnOnce() + Send>) {
        let Some(core) = self.core.upgrade() else {
            return f();
        };
        let mut c = lock(&core);
        let mut f = Some(f);
        if let Some(st) = c.streams.get_mut(&self.sid).filter(|s| s.out_bytes > 0) {
            if let Some(mut old) = st.drain.replace(Waiter(f.take())) {
                old.0 = None; // replaced, not run
            }
        }
        drop(c);
        if let Some(f) = f {
            f();
        }
    }

    pub(crate) fn finish(self) {
        self.finish_with(None);
    }

    pub(crate) fn finish_with(mut self, trailers: Option<Headers>) {
        self.done = true;
        if let Some(core) = self.core.upgrade() {
            let mut c = lock(&core);
            if let Some(st) = c.streams.get_mut(&self.sid) {
                if !self.head_only {
                    st.end_pending = true;
                    st.trailers = trailers;
                }
            }
            c.flush_stream(self.sid);
            c.flush();
        }
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // The body can no longer be completed: cancel the stream.
        if let Some(core) = self.core.upgrade() {
            let mut c = lock(&core);
            if c.streams.contains_key(&self.sid) {
                c.rst(self.sid, err::INTERNAL);
                c.flush();
            }
        }
    }
}

/// The stream of an accepted extended CONNECT carrying a WebSocket (RFC 8441): frames go out in
/// DATA frames as the stream's and the connection's windows allow; sends fail with
/// `Overloaded` past `max_pending_bytes` queued on the stream (one message is taken whatever its
/// size when nothing is queued) or `max_conn_pending_bytes` on the connection; closing ends the
/// stream (END_STREAM), or resets it (`CANCEL`) when the peer has not ended its half.
struct H2WsLink {
    core: Weak<CoreCell>,
    sid: u32,
}

/// How long a tunnel that ended our half (END_STREAM: after its WebSocket's close frame, or its
/// streamed response finished) waits for the peer to end its own before resetting the stream
/// (`CANCEL`).
const TUNNEL_LINGER: Duration = Duration::from_secs(5);

impl WsLink for H2WsLink {
    fn send(&self, data: Vec<u8>) -> akio_core::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let core = self.core.upgrade().ok_or(akio_core::Error::Closed)?;
        let mut c = lock(&core);
        let max = c.cfg.max_pending_bytes;
        let conn_full = c.queued_mem + data.len() > c.cfg.max_conn_pending_bytes;
        let Some(st) = c.streams.get_mut(&self.sid) else {
            return Err(akio_core::Error::Closed);
        };
        if st.sent_end || st.end_pending {
            return Err(akio_core::Error::Closed);
        }
        // A message is taken whatever its size when nothing waits (it is the application's,
        // not the peer's): the bound is on what piles up behind a closed window.
        if conn_full || (st.out_bytes > 0 && st.out_bytes + data.len() > max) {
            return Err(akio_core::Error::Overloaded);
        }
        let n = data.len();
        st.out_bytes += n;
        st.out.push_back(OutChunk::Bytes(data, 0));
        c.queued_mem += n;
        c.flush_stream(self.sid);
        c.flush();
        Ok(())
    }

    fn close_after_send(&self) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        let mut c = lock(&core);
        let Some(st) = c.streams.get_mut(&self.sid) else {
            return;
        };
        if std::mem::replace(&mut st.end_pending, !st.sent_end) || st.sent_end {
            return; // already ending
        }
        // A peer that never ends its half does not keep the stream (`finish_if_done`).
        c.flush_stream(self.sid);
        c.flush();
    }

    fn close(&self) {
        let Some(core) = self.core.upgrade() else {
            return;
        };
        let mut c = lock(&core);
        let Some(st) = c.streams.get_mut(&self.sid) else {
            return;
        };
        if st.state == SState::HalfClosedRemote {
            // The peer ended its half: end ours after what is queued.
            if !st.sent_end {
                st.end_pending = true;
            }
            c.flush_stream(self.sid);
        } else {
            c.rst(self.sid, err::CANCEL);
        }
        c.flush();
    }

    fn is_open(&self) -> bool {
        self.core.upgrade().is_some_and(|core| {
            let c = lock(&core);
            !c.dead
                && c.streams
                    .get(&self.sid)
                    .is_some_and(|s| !s.sent_end && !s.end_pending)
        })
    }

    fn queued_bytes(&self) -> usize {
        self.core.upgrade().map_or(0, |c| {
            lock(&c).streams.get(&self.sid).map_or(0, |s| s.out_bytes)
        })
    }
}

// ---- the driver the HTTP session owns --------------------------------------------------------

/// An HTTP/2 connection served by `service`.
pub(crate) struct H2Session<S> {
    core: Shared,
    service: Arc<S>,
    /// The logical pool, when complete requests run there (`H2Config::handlers_on_logical_pool`).
    pool: Option<crate::pool::Executor>,
    /// The deadline phase after the last read (computed under the lock it takes anyway).
    phase: std::cell::Cell<Phase>,
    /// The connection's handle on the listener's response observer (ADR-158).
    observer: Option<Arc<dyn crate::ResponseObserver>>,
}

impl<S: Service> H2Session<S> {
    /// Starts HTTP/2 on `conn`. `initial` are bytes already read (the start of the preface);
    /// `upgrade` is the HTTP/1 request of an `h2c` upgrade with the peer's `HTTP2-Settings`.
    #[allow(clippy::too_many_arguments)] // one call site, the HTTP/1 session's
    pub(crate) fn new(
        conn: Arc<ConnInner>,
        cfg: H2Config,
        service: Arc<S>,
        peer: SocketAddr,
        initial: &[u8],
        upgrade: Option<(Request, Vec<u8>)>,
        early: bool,
        observer: Option<Arc<dyn crate::ResponseObserver>>,
    ) -> H2Session<S> {
        let tls = conn.has_transport();
        let pool = cfg
            .handlers_on_logical_pool
            .then(|| crate::pool::Executor::conn(conn.clone()));
        let deferred = pool.as_ref().map(|_| Deferred::new(conn.clone()));
        let svc_mode = service.clone();
        let svc_push = service.clone();
        let obs_push = observer.clone();
        let local = Settings {
            max_concurrent: cfg.max_concurrent_streams,
            initial_window: i64::from(cfg.initial_window),
            max_header_list: cfg.max_header_list,
            ..Settings::defaults()
        };
        let conn_window = cfg.conn_window;
        let stats = cfg.stats.as_ref().map(H2Stats::shard);
        if let Some(s) = &stats {
            H2Shard::inc(&s.conns_opened);
        }
        let core: Shared = Arc::new_cyclic(|me| {
            let mut dec = Decoder::new();
            dec.set_max_allowed_table_size(local.header_table as usize);
            let core = Mutex::new(Core {
                conn,
                cfg,
                out: Vec::new(),
                rbuf: Vec::new(),
                preface: false,
                got_settings: false,
                local,
                remote: Settings::defaults(),
                conn_send: DEFAULT_WINDOW,
                conn_recv: DEFAULT_WINDOW,
                dec,
                enc: Encoder::new(),
                streams: StreamMap::default(),
                last_peer: 0,
                next_push: 2,
                cont: None,
                goaway_recv: false,
                goaway_sent: false,
                dead: false,
                peer,
                tls,
                peer_certs: crate::session::PeerCerts::default(),
                early,
                push_hook: Some(Arc::new(move |req: Request, resp: H2Responder| {
                    let mut ctx = Context::new_h2(req, resp);
                    ctx.set_observer(obs_push.as_ref());
                    let g = crate::trace::begin(&mut ctx);
                    svc_push.call(&mut ctx);
                    drop(g);
                    finalize(&mut ctx);
                })),
                mode_of: svc_mode
                    .streams_bodies()
                    .then(|| -> ModeFn { Arc::new(move |r: &Request| svc_mode.body_mode(r)) }),
                me: me.clone(),
                stats: stats.clone(),
                stats_closed: false,
                pending_rst: None,
                open_peer: 0,
                dropped: Vec::new(),
                waiters: Vec::new(),
                batching: false,
                deferring: deferred.is_some(),
                fields: Fields::default(),
                enc_fields: Fields::default(),
                conn_recv_owed: 0,
                queued_mem: 0,
                budget_start: None,
                resets: 0,
                control: 0,
                at: 0,
                finished: false,
            });
            CoreCell { core, deferred }
        });
        let s = H2Session {
            core,
            service,
            pool,
            phase: std::cell::Cell::new(Phase::Head),
            observer,
        };
        let mut first = Vec::new();
        {
            let mut c = lock(&s.core);
            // Our SETTINGS and a larger connection window go out first.
            let mut p = Vec::new();
            for (id, v) in [
                (3u16, c.local.max_concurrent),
                (4, c.local.initial_window as u32),
                (6, c.local.max_header_list),
            ] {
                p.extend_from_slice(&id.to_be_bytes());
                p.extend_from_slice(&v.to_be_bytes());
            }
            if c.cfg.enable_connect_protocol {
                // SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 §3).
                p.extend_from_slice(&[0, 8, 0, 0, 0, 1]);
            }
            frame(&mut c.out, ty::SETTINGS, 0, 0, &p);
            let extra = conn_window.saturating_sub(DEFAULT_WINDOW as u32);
            c.window_update(0, extra);
            c.conn_recv += i64::from(extra);
            if let Some((req, settings)) = upgrade {
                // The upgrade request is stream 1; the peer's settings came in its header.
                if c.on_settings(0, 0, &settings).is_err() {
                    c.conn_error(err::PROTOCOL);
                } else {
                    // The ack frame `on_settings` queued is for the header's settings: the
                    // client does not expect one, but it is harmless; drop it to stay exact.
                    let n = c.out.len();
                    c.out.truncate(n - 9);
                    // The peer's own SETTINGS frame still has to open its half of the preface.
                    c.got_settings = false;
                    c.last_peer = 1;
                    c.open_peer = 1;
                    let mut st = Stream::new(
                        SState::HalfClosedRemote,
                        c.remote.initial_window,
                        c.local.initial_window,
                    );
                    st.head_only = req.method == Method::Head;
                    st.head = Some(req);
                    c.insert_stream(1, st);
                    if let Some(a) = c.complete_request(1) {
                        first.push(a);
                    }
                }
            }
            c.flush();
        }
        for a in first {
            s.run(a, &[]);
        }
        s.feed(initial);
        s
    }

    pub(crate) fn on_data(&self, data: &[u8]) {
        self.feed(data);
    }

    /// Handles one read: frames are parsed in place (from `data`, or from the bytes left over
    /// from earlier reads plus `data`), and everything they produce, including the responses
    /// the service sends on this thread, is handed to the connection once at the end.
    fn feed(&self, data: &[u8]) {
        let held = {
            let mut c = lock(&self.core);
            if c.dead {
                self.phase.set(Phase::Off);
                return;
            }
            c.batching = true;
            if c.rbuf.is_empty() {
                None
            } else {
                c.rbuf.extend_from_slice(data);
                Some(std::mem::take(&mut c.rbuf))
            }
        };
        let batch = Batch(&self.core);
        // Declared after `batch`, so dropped before it: a `503` for a request the pool refuses
        // goes out with the rest of the read.
        let gather = crate::pool::Gather::begin(self.pool.is_some());
        let buf = held.as_deref().unwrap_or(data);
        let mut pos = 0;
        let mut actions = SPARE_ACTIONS.take();
        loop {
            let more = {
                let mut c = lock(&self.core);
                loop {
                    if c.dead {
                        self.phase.set(Phase::Off);
                        return;
                    }
                    c.at = pos;
                    match c.next_frame(&buf[pos..], &mut actions) {
                        Ok(None) => break false,
                        Ok(Some(n)) => pos += n,
                        Err(Fail::Conn(code)) => {
                            c.conn_error(code);
                            self.phase.set(Phase::Off);
                            return;
                        }
                    }
                    if !actions.is_empty() {
                        break true;
                    }
                }
            };
            // The service runs without the lock.
            for a in actions.drain(..) {
                self.run(a, buf);
            }
            if !more {
                break;
            }
        }
        // Keep what is left of an incomplete frame for the next read.
        let mut c = lock(&self.core);
        match held {
            Some(mut v) => {
                v.drain(..pos);
                c.rbuf = v;
            }
            None => c.rbuf.extend_from_slice(&data[pos..]),
        }
        self.phase.set(c.phase());
        // Streams finished during this read are covered by the deadline armed after it.
        c.finished = false;
        drop(c);
        drop(gather);
        drop(batch);
        SPARE_ACTIONS.set(actions);
    }

    fn run(&self, a: Action, buf: &[u8]) {
        match a {
            Action::Dispatch(req, resp) => {
                let mut ctx = Context::new_h2(req, resp);
                ctx.set_observer(self.observer.as_ref());
                if let Some(exec) = &self.pool {
                    return crate::pool::call_on_pool(self.service.clone(), ctx, exec);
                }
                let g = crate::trace::begin(&mut ctx);
                self.service.call(&mut ctx);
                drop(g);
                finalize(&mut ctx);
                ctx.recycle_request();
            }
            Action::Start(sid, mut ctx) => {
                ctx.set_streamed();
                ctx.set_observer(self.observer.as_ref());
                let g = crate::trace::begin(&mut ctx);
                self.service.call(&mut ctx);
                drop(g);
                if ctx.body_stopped() {
                    return self.stop_body(sid);
                }
                let parked = match ctx.take_upgrade() {
                    Some(up) => {
                        // A WebSocket accepted on an extended CONNECT (its `200` is out).
                        let link: Arc<dyn WsLink> = Arc::new(H2WsLink {
                            core: Arc::downgrade(&self.core),
                            sid,
                        });
                        let mut ws = WsSession::with_link(link, &up.cfg, up.pmd, up.handler);
                        ws.open();
                        Parked::Ws(WsPark(Box::new(ws)))
                    }
                    None => Parked::Ctx(ctx),
                };
                self.park(sid, parked);
            }
            Action::Chunk(sid, range) => match self.take_parked(sid) {
                Some(Parked::Ctx(mut ctx)) => {
                    ctx.deliver(BodyEvent::Chunk(&buf[range]));
                    if ctx.body_stopped() {
                        return self.stop_body(sid);
                    }
                    self.park(sid, Parked::Ctx(ctx));
                }
                Some(Parked::Ws(mut ws)) => {
                    ws.0.on_data(&buf[range]);
                    self.park(sid, Parked::Ws(ws));
                }
                None => {}
            },
            Action::End(sid, trailers) => match self.take_parked(sid) {
                Some(Parked::Ctx(mut ctx)) => {
                    ctx.deliver(BodyEvent::End(&trailers));
                    finalize(&mut ctx);
                }
                // The peer ended its half of the tunnel: the WebSocket's transport is closed
                // (dropping it says so, and ends our half).
                Some(Parked::Ws(ws)) => drop(ws),
                None => {}
            },
        }
    }

    /// The stream's request body was refused (`Context::limit_body`, akit A49): its context
    /// (answered, or detached) is not parked again, so later DATA goes nowhere, and the stream
    /// gives the client no more window. A response already done reset the stream (`NO_ERROR`);
    /// one still to come does once it is.
    fn stop_body(&self, sid: u32) {
        H2Reads {
            core: Arc::downgrade(&self.core),
            sid,
        }
        .hold(true);
    }

    fn take_parked(&self, sid: u32) -> Option<Parked> {
        lock(&self.core).streams.get_mut(&sid)?.parked.take()
    }

    /// Parks `p` on its stream again; if the stream went away meanwhile, `p` is dropped once
    /// the lock is released (a WebSocket then hears that its transport closed).
    fn park(&self, sid: u32, p: Parked) {
        let left = {
            let mut c = lock(&self.core);
            match c.streams.get_mut(&sid) {
                Some(st) => {
                    st.parked = Some(p);
                    None
                }
                None => Some(p),
            }
        };
        drop(left);
    }

    /// The deadline phase after the last read.
    pub(crate) fn phase(&self) -> Phase {
        self.phase.get()
    }

    /// The armed deadline passed: an unfinished preface closes the connection, stalled
    /// buffered uploads are answered `408`, and a connection without streams is closed
    /// gracefully. Returns the deadline to arm next, if the connection stays.
    pub(crate) fn on_deadline(&self) -> Option<Phase> {
        lock(&self.core).on_deadline()
    }

    /// Graceful shutdown: GOAWAY now, close when the open streams have finished. WebSockets
    /// carried by streams are closed with 1001 (going away).
    pub(crate) fn shutdown(&self) {
        let ws: Vec<WsSender> = {
            let mut c = lock(&self.core);
            c.goaway(err::NO_ERROR);
            c.flush();
            c.maybe_close_after_goaway();
            c.streams
                .values()
                .filter_map(|s| match &s.parked {
                    Some(Parked::Ws(w)) => Some(w.0.sender().clone()),
                    _ => None,
                })
                .collect()
        };
        for w in ws {
            w.close(1001, "going away");
        }
    }

    pub(crate) fn on_close(&self) {
        let mut c = lock(&self.core);
        c.dead = true;
        c.count_close();
        let all: Vec<Stream> = c
            .streams
            .drain()
            .map(|(_, mut s)| {
                s.disarm_gone();
                s
            })
            .collect();
        c.dropped.extend(all);
    }
}

fn finalize(ctx: &mut Context) {
    if !ctx.responded() && !ctx.is_detached() {
        ctx.respond(Response::text(500, "handler did not respond"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{hint::black_box, time::Instant};

    /// The request checks as A169 merged them: a pass per name and per value beside a UTF-8
    /// check per string (the micro-benchmark's reference).
    fn per_byte(fields: &Fields) -> Result<usize, ()> {
        let mut kept = 0;
        for (n, v) in fields.iter() {
            if v.iter().any(|&b| matches!(b, 0 | b'\r' | b'\n')) {
                return Err(());
            }
            let v = std::str::from_utf8(v).map_err(|_| ())?;
            if n.first() == Some(&b':') {
                kept += v.len();
                continue;
            }
            if n.is_empty()
                || !n
                    .iter()
                    .all(|&b| matches!(b, 0x21..=0x40 | 0x5b..=0x7e) && b != b':')
            {
                return Err(());
            }
            let n = std::str::from_utf8(n).map_err(|_| ())?;
            kept += n.len() + v.len();
        }
        Ok(kept)
    }

    /// The same walk with the decoder's classes and one UTF-8 check per block.
    fn classed(fields: &Fields) -> Result<usize, ()> {
        if fields.classes & class::BAD_VALUE != 0 {
            return Err(());
        }
        let ascii = fields.ascii();
        let mut kept = 0;
        for &(a, b, c, cl) in &fields.spans {
            let v = fields.text(ascii, b, c).ok_or(())?;
            if fields.buf.get(a) == Some(&b':') {
                kept += v.len();
                continue;
            }
            if cl & class::BAD_NAME != 0 {
                return Err(());
            }
            kept += fields.text(ascii, a, b).ok_or(())?.len() + v.len();
        }
        Ok(kept)
    }

    /// A literal field without indexing, raw strings (RFC 7541 §6.2.2): every one is scanned.
    fn literal(out: &mut Vec<u8>, n: &[u8], v: &[u8]) {
        out.push(0);
        for s in [n, v] {
            assert!(s.len() < 127);
            out.push(s.len() as u8);
            out.extend_from_slice(s);
        }
    }

    fn time(label: &str, n: u32, mut f: impl FnMut() -> usize) {
        for _ in 0..n / 10 {
            black_box(f());
        }
        let t = Instant::now();
        let mut sum = 0usize;
        for _ in 0..n {
            sum = sum.wrapping_add(black_box(f()));
        }
        let ns = t.elapsed().as_secs_f64() * 1e9 / f64::from(n);
        println!("{label:<58} {ns:7.1} ns/block ({sum})");
    }

    /// Micro-benchmark of a request header block's decoding and RFC 9113 §8.2.1 checks (A169):
    /// `cargo test --release -p akio-http --lib h2::tests::request_head_cost -- --ignored
    /// --nocapture`. Blocks as `h2load` sends them (indexed from the second request on) and as a
    /// browser does (more and longer fields), plus every field as an unindexed literal, the case
    /// where each string is scanned. Each line: decode into `Fields` (the same decoder, which
    /// works out the classes of literals either way), then the checks with a pass per string
    /// and UTF-8 per string (A169 as merged) or with the decoder's classes.
    #[test]
    #[ignore]
    fn request_head_cost() {
        let h2load: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/plaintext"),
            (b":scheme", b"http"),
            (b":authority", b"127.0.0.1:7401"),
            (b"user-agent", b"h2load nghttp2/1.59.0"),
        ];
        let browser: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":authority", b"www.example.com"),
            (b":scheme", b"https"),
            (b":path", b"/static/js/app.4f1c2b.js?v=20261126"),
            (b"sec-ch-ua", b"\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""),
            (b"sec-ch-ua-mobile", b"?0"),
            (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            (b"accept", b"*/*"),
            (b"sec-fetch-site", b"same-origin"),
            (b"sec-fetch-mode", b"no-cors"),
            (b"referer", b"https://www.example.com/products/list?page=2"),
            (b"accept-encoding", b"gzip, deflate, br, zstd"),
            (b"accept-language", b"en-US,en;q=0.9,zh-CN;q=0.8"),
            (b"cookie", b"session=8f2d1c0e9b7a6f5e4d3c2b1a; theme=dark; consent=yes"),
        ];
        const N: u32 = 2_000_000;
        for (name, list) in [("h2load", h2load), ("browser", browser)] {
            let mut enc = Encoder::new();
            let _first = enc.encode(list.iter().copied());
            let indexed = enc.encode(list.iter().copied());
            let mut lit = Vec::new();
            for (n, v) in list {
                literal(&mut lit, n, v);
            }
            for (kind, block) in [("indexed", &indexed), ("literals", &lit)] {
                let mut dec = Decoder::new();
                dec.decode(&_first).expect("first block");
                let mut fields = Fields::default();
                for (check, classes) in [("UTF-8 per string", false), ("classes", true)] {
                    time(&format!("{name}, {kind}, {check}"), N, || {
                        fields.clear();
                        dec.decode_classified(block, |n, v, _, c| fields.push(n, v, c))
                            .expect("decodes");
                        if classes {
                            classed(&fields).expect("valid")
                        } else {
                            per_byte(&fields).expect("valid")
                        }
                    });
                }
                // Both walks agree, and request_fields accepts the block.
                assert_eq!(per_byte(&fields), classed(&fields));
                let (p, h) = request_fields(&fields, false).expect("a valid request");
                assert_eq!(p.method, Some("GET"));
                assert!(h.len() + 4 >= list.len());
            }
        }
    }
}
