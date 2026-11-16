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
    sync::{Arc, Mutex, MutexGuard, Weak},
};

use crate::hpack::{Decoder, Encoder};
use only_core::ConnInner;

use crate::{
    context::{BodyEvent, BodyMode, Context, Service},
    message::{FileBody, Headers, Method, Request, Response, Version},
};

/// The client connection preface.
pub(crate) const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub(crate) mod err {
    pub(crate) const NO_ERROR: u32 = 0;
    pub(crate) const PROTOCOL: u32 = 1;
    pub(crate) const INTERNAL: u32 = 2;
    pub(crate) const FLOW_CONTROL: u32 = 3;
    pub(crate) const STREAM_CLOSED: u32 = 5;
    pub(crate) const FRAME_SIZE: u32 = 6;
    pub(crate) const REFUSED_STREAM: u32 = 7;
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
    /// The context of a streamed request, parked here between body events.
    ctx: Option<Box<Context>>,
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
}

impl Stream {
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
            ctx: None,
            out: VecDeque::new(),
            out_bytes: 0,
            head_sent: false,
            end_pending: false,
            sent_end: false,
            head_only: false,
            trailers: None,
            pushed: false,
        }
    }
}

struct Cont {
    stream: u32,
    block: Vec<u8>,
    end_stream: bool,
}

/// What the driver does after releasing the lock.
enum Action {
    /// A complete request: run the service.
    Dispatch(Box<Context>),
    /// A streamed request began: run the service, then park its context on the stream.
    Start(u32, Box<Context>),
    /// Body bytes for a streamed request.
    Chunk(u32, Vec<u8>),
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
    /// Per field: name at `buf[.0...1]`, value at `buf[.1...2]`.
    spans: Vec<(usize, usize, usize)>,
}

impl Fields {
    fn clear(&mut self) {
        self.buf.clear();
        self.spans.clear();
    }
    fn push(&mut self, n: &[u8], v: &[u8]) {
        let a = self.buf.len();
        self.buf.extend_from_slice(n);
        let b = self.buf.len();
        self.buf.extend_from_slice(v);
        self.spans.push((a, b, self.buf.len()));
    }
    fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.spans
            .iter()
            .map(|&(a, b, c)| (&self.buf[a..b], &self.buf[b..c]))
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
    /// The connection began with TLS early data: every request is marked `Early-Data: 1`
    /// (offsets are not followed through the framing, so this errs on the safe side).
    early: bool,
    push_hook: Option<PushHook>,
    mode_of: Option<ModeFn>,
    me: Weak<Mutex<Core>>,
    /// A stream error to raise once the header block it came with has been decoded.
    pending_rst: Option<(u32, u32)>,
    /// Peer-opened streams not yet finished (for the concurrency limit and graceful close).
    open_peer: u32,
    /// Streams removed under the lock, dropped once it is released (see [`Locked`]).
    dropped: Vec<Stream>,
    /// While the I/O thread works through one read, frames are only appended to `out`; the
    /// whole batch is handed to the connection once at the end (one write, one TLS record).
    batching: bool,
    /// The header block being decoded.
    fields: Fields,
    /// Scratch for encoding a header block: lowercased names and cleaned values.
    enc_fields: Fields,
    /// Connection-level receive window consumed and not yet given back.
    conn_recv_owed: u32,
}

type Shared = Arc<Mutex<Core>>;

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

thread_local! {
    /// An empty buffer with capacity, swapped with `Core::dropped` on unlock so that dropping
    /// finished streams outside the lock allocates nothing in the steady state (a fresh `Vec`
    /// per finished stream cost ~9% of h2c throughput).
    static SPARE_DROPPED: std::cell::Cell<Vec<Stream>> = const { std::cell::Cell::new(Vec::new()) };
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let Some(mut g) = self.0.take() else { return };
        if g.dropped.is_empty() {
            return;
        }
        let mut dropped = SPARE_DROPPED.take();
        std::mem::swap(&mut dropped, &mut g.dropped);
        drop(g);
        dropped.clear(); // runs the streams' drops, outside the lock
        SPARE_DROPPED.set(dropped);
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
        }
    }

    fn rst(&mut self, sid: u32, code: u32) {
        frame(&mut self.out, ty::RST_STREAM, 0, sid, &code.to_be_bytes());
        self.close_stream(sid);
    }

    fn goaway(&mut self, code: u32) {
        if self.goaway_sent {
            return;
        }
        self.goaway_sent = true;
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
        if let Some(s) = self.streams.remove(&sid) {
            if sid % 2 == 1 && !s.pushed {
                self.open_peer = self.open_peer.saturating_sub(1);
            }
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
            f.spans.push((a, b, f.buf.len()));
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
            f.spans.push((a, b, f.buf.len()));
        }
        if add_date && !has_date {
            crate::message::with_http_date(|d| f.push(b"date", d.as_bytes()));
        }
        if let (Some(len), false) = (content_length, has_len) {
            let a = f.buf.len();
            f.buf.extend_from_slice(b"content-length");
            let b = f.buf.len();
            crate::message::push_uint(&mut f.buf, len);
            f.spans.push((a, b, f.buf.len()));
        }
        // Encode behind a placeholder frame header, which is filled in once the size is known.
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
                        self.finish_if_done(sid);
                        self.flush();
                        return;
                    }
                    st.out_bytes += n;
                    st.out
                        .push_back(OutChunk::Bytes(std::mem::take(&mut resp.body), 0));
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
            SState::HalfClosedRemote | SState::HalfClosedLocal => self.close_stream(sid),
            SState::Open => {
                // Answered before the request ended: ask the peer to stop sending.
                st.state = SState::HalfClosedLocal;
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
        if p.len() != 5 {
            self.rst(sid, err::FRAME_SIZE);
            return Ok(());
        }
        let dep = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
        if dep == sid {
            self.rst(sid, err::PROTOCOL);
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
        self.close_stream(sid);
        Ok(())
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
            self.rst(sid, err::PROTOCOL);
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&sid) else {
            return Ok(()); // closed: allowed to arrive late
        };
        s.send_window += inc;
        if s.send_window > MAX_WINDOW {
            self.rst(sid, err::FLOW_CONTROL);
            return Ok(());
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
        if flags & flag::PADDED != 0 {
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
        let Some(st) = self.streams.get_mut(&sid) else {
            self.rst(sid, err::STREAM_CLOSED);
            return Ok(());
        };
        if st.state != SState::Open && st.state != SState::HalfClosedLocal {
            self.rst(sid, err::STREAM_CLOSED);
            return Ok(());
        }
        st.recv_window -= total;
        if st.recv_window < 0 {
            self.rst(sid, err::FLOW_CONTROL);
            return Ok(());
        }
        st.received += data.len() as u64;
        if let Some(cl) = st.content_length {
            if st.received > cl {
                self.rst(sid, err::PROTOCOL);
                return Ok(());
            }
        }
        let end = flags & flag::END_STREAM != 0;
        if end {
            if let Some(cl) = st.content_length {
                if st.received != cl {
                    self.rst(sid, err::PROTOCOL);
                    return Ok(());
                }
            }
        }
        // Replenish the stream window as data arrives (bodies are consumed immediately), once
        // a quarter of it is owed.
        if total > 0 && !end {
            st.recv_owed += total;
            if st.recv_owed >= self.local.initial_window / 4 {
                let inc = std::mem::take(&mut st.recv_owed);
                st.recv_window += inc;
                self.window_update(sid, inc as u32);
            }
        }
        let st = self.streams.get_mut(&sid).expect("present");
        if st.streaming {
            if !data.is_empty() {
                actions.push(Action::Chunk(sid, data.to_vec()));
            }
            if end {
                st.state = SState::HalfClosedRemote;
                let tr = std::mem::take(
                    &mut st
                        .head
                        .as_mut()
                        .map(|h| h.trailers.clone())
                        .unwrap_or_default(),
                );
                actions.push(Action::End(sid, tr));
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
        let decoded = self.dec.decode_with(block, |n, v, _| {
            size = size.saturating_add(n.len() + v.len() + 32);
            if size <= limit {
                fields.push(n, v);
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
                self.rst(sid, code);
                return Ok(());
            }
        }
        let existing = self.streams.contains_key(&sid);
        if existing {
            if size > limit {
                self.rst(sid, err::PROTOCOL); // trailers past the header list limit
                return Ok(());
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
        if self.open_peer >= self.cfg.max_concurrent_streams {
            self.frame_refuse(sid);
            return Ok(());
        }
        if size > limit {
            self.frame_refuse(sid);
            return Ok(());
        }
        let Ok(req) = self.build_request(fields) else {
            self.rst_new(sid, err::PROTOCOL);
            return Ok(());
        };
        let content_length = match req.headers.get("content-length") {
            None => None,
            Some(v) => match v.parse::<u64>() {
                Ok(n) => Some(n),
                Err(_) => {
                    self.rst_new(sid, err::PROTOCOL);
                    return Ok(());
                }
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
        if end_stream {
            self.streams.insert(sid, st);
            if content_length.is_some_and(|cl| cl != 0) {
                self.rst(sid, err::PROTOCOL);
                return Ok(());
            }
            // A request without a body: dispatched right away, nothing parked on the stream.
            let resp = H2Responder::new(self.me.clone(), sid, req.method == Method::Head);
            actions.push(Action::Dispatch(Box::new(Context::new_h2(req, resp))));
            return Ok(());
        }
        // Does the service want the body as a stream?
        let mode = self
            .mode_of
            .as_ref()
            .map_or(BodyMode::Buffered, |f| f(&req));
        if mode == BodyMode::Stream {
            st.streaming = true;
            let resp = H2Responder::new(self.me.clone(), sid, req.method == Method::Head);
            st.head = Some(req.clone());
            self.streams.insert(sid, st);
            actions.push(Action::Start(sid, Box::new(Context::new_h2(req, resp))));
            return Ok(());
        }
        st.head = Some(req);
        self.streams.insert(sid, st);
        Ok(())
    }

    fn frame_refuse(&mut self, sid: u32) {
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
            self.rst(sid, err::STREAM_CLOSED);
            return Ok(());
        }
        if !end_stream {
            // Trailers must end the stream.
            self.rst(sid, err::PROTOCOL);
            return Ok(());
        }
        let mut tr = Headers::new();
        for (n, v) in fields.iter() {
            if n.first() == Some(&b':') || n.iter().any(u8::is_ascii_uppercase) {
                self.rst(sid, err::PROTOCOL);
                return Ok(());
            }
            if let (Ok(n), Ok(v)) = (std::str::from_utf8(n), std::str::from_utf8(v)) {
                tr.append(n, v);
            }
        }
        let st = self.streams.get_mut(&sid).expect("present");
        if let Some(cl) = st.content_length {
            if st.received != cl {
                self.rst(sid, err::PROTOCOL);
                return Ok(());
            }
        }
        st.state = SState::HalfClosedRemote;
        if let Some(h) = st.head.as_mut() {
            h.trailers = tr.clone();
        }
        if st.streaming {
            actions.push(Action::End(sid, tr));
            return Ok(());
        }
        actions.extend(self.complete_request(sid));
        Ok(())
    }

    /// Turns the assembled request into a context to dispatch.
    fn complete_request(&mut self, sid: u32) -> Option<Action> {
        let st = self.streams.get_mut(&sid)?;
        let mut req = st.head.take()?;
        req.body = std::mem::take(&mut st.body);
        let resp = H2Responder::new(self.me.clone(), sid, req.method == Method::Head);
        Some(Action::Dispatch(Box::new(Context::new_h2(req, resp))))
    }

    fn build_request(&self, fields: &Fields) -> Result<Request, ()> {
        let (mut method, mut path, mut authority, mut scheme) = (None, None, None, None);
        // The regular fields fit in one allocation (the pseudo-headers are not kept as fields;
        // a request with few regular fields keeps their positions inline).
        let n = fields
            .spans
            .iter()
            .filter(|&&(a, b, _)| a == b || fields.buf[a] != b':')
            .count();
        let mut headers = Headers::with_capacity(n, fields.buf.len());
        let mut regular = false;
        let mut cookies: Option<String> = None;
        for (n, v) in fields.iter() {
            let v = std::str::from_utf8(v).map_err(|_| ())?;
            if n.first() == Some(&b':') {
                if regular {
                    return Err(()); // pseudo-header after a regular one
                }
                let slot = match n {
                    b":method" => &mut method,
                    b":path" => &mut path,
                    b":authority" => &mut authority,
                    b":scheme" => &mut scheme,
                    _ => return Err(()),
                };
                if slot.replace(v).is_some() {
                    return Err(());
                }
                continue;
            }
            regular = true;
            if n.iter().any(u8::is_ascii_uppercase) {
                return Err(());
            }
            let n = std::str::from_utf8(n).map_err(|_| ())?;
            match n {
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                | "upgrade" => {
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
        let (method, path) = (method.ok_or(())?, path.ok_or(())?);
        scheme.ok_or(())?;
        if method != "CONNECT" && path.is_empty() {
            return Err(());
        }
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
            target: path.to_owned(),
            version: Version::Http2,
            headers,
            trailers: Headers::new(),
            body: Vec::new(),
            peer: self.peer,
        })
    }
}

// ---- response side, usable from any thread ---------------------------------------------------

/// Sends the response of one HTTP/2 stream.
#[derive(Clone)]
pub(crate) struct H2Responder {
    core: Weak<Mutex<Core>>,
    sid: u32,
    head_only: bool,
}

impl H2Responder {
    fn new(core: Weak<Mutex<Core>>, sid: u32, head_only: bool) -> H2Responder {
        H2Responder {
            core,
            sid,
            head_only,
        }
    }

    pub(crate) fn send(&self, resp: Response) {
        if let Some(core) = self.core.upgrade() {
            lock(&core).send_response(self.sid, resp);
        }
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
            c.streams.insert(promised, st);
            c.flush();
            let mut headers = Headers::new();
            headers.append("host", authority);
            let req = Request {
                method: Method::Get,
                target: path.to_owned(),
                version: Version::Http2,
                headers,
                trailers: Headers::new(),
                body: Vec::new(),
                peer: c.peer,
            };
            (promised, hook, req)
        };
        hook(req, H2Responder::new(self.core.clone(), promised, false));
        true
    }
}

/// A response body being written in pieces on an HTTP/2 stream.
pub(crate) struct H2Stream {
    core: Weak<Mutex<Core>>,
    sid: u32,
    head_only: bool,
    done: bool,
}

impl H2Stream {
    pub(crate) fn write(&self, data: &[u8]) -> only_core::Result<()> {
        if data.is_empty() || self.head_only {
            return Ok(());
        }
        let core = self.core.upgrade().ok_or(only_core::Error::Closed)?;
        let mut c = lock(&core);
        let max = c.cfg.max_pending_bytes;
        let Some(st) = c.streams.get_mut(&self.sid) else {
            return Err(only_core::Error::Closed);
        };
        if st.out_bytes + data.len() > max {
            return Err(only_core::Error::Overloaded);
        }
        st.out_bytes += data.len();
        st.out.push_back(OutChunk::Bytes(data.to_vec(), 0));
        c.flush_stream(self.sid);
        c.flush();
        Ok(())
    }

    pub(crate) fn queued_bytes(&self) -> usize {
        self.core.upgrade().map_or(0, |c| {
            lock(&c).streams.get(&self.sid).map_or(0, |s| s.out_bytes)
        })
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

// ---- the driver the HTTP session owns --------------------------------------------------------

/// An HTTP/2 connection served by `service`.
pub(crate) struct H2Session<S> {
    core: Shared,
    service: Arc<S>,
}

impl<S: Service> H2Session<S> {
    /// Starts HTTP/2 on `conn`. `initial` are bytes already read (the start of the preface);
    /// `upgrade` is the HTTP/1 request of an `h2c` upgrade with the peer's `HTTP2-Settings`.
    pub(crate) fn new(
        conn: Arc<ConnInner>,
        cfg: H2Config,
        service: Arc<S>,
        peer: SocketAddr,
        initial: &[u8],
        upgrade: Option<(Request, Vec<u8>)>,
        early: bool,
    ) -> H2Session<S> {
        let tls = conn.has_transport();
        let svc_mode = service.clone();
        let svc_push = service.clone();
        let local = Settings {
            max_concurrent: cfg.max_concurrent_streams,
            initial_window: i64::from(cfg.initial_window),
            max_header_list: cfg.max_header_list,
            ..Settings::defaults()
        };
        let conn_window = cfg.conn_window;
        let core: Shared = Arc::new_cyclic(|me| {
            let mut dec = Decoder::new();
            dec.set_max_allowed_table_size(local.header_table as usize);
            Mutex::new(Core {
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
                early,
                push_hook: Some(Arc::new(move |req: Request, resp: H2Responder| {
                    let mut ctx = Context::new_h2(req, resp);
                    svc_push.call(&mut ctx);
                    finalize(&mut ctx);
                })),
                mode_of: Some(Arc::new(move |r: &Request| svc_mode.body_mode(r))),
                me: me.clone(),
                pending_rst: None,
                open_peer: 0,
                dropped: Vec::new(),
                batching: false,
                fields: Fields::default(),
                enc_fields: Fields::default(),
                conn_recv_owed: 0,
            })
        });
        let s = H2Session { core, service };
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
                    c.streams.insert(1, st);
                    if let Some(a) = c.complete_request(1) {
                        first.push(a);
                    }
                }
            }
            c.flush();
        }
        for a in first {
            s.run(a);
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
        let buf = held.as_deref().unwrap_or(data);
        let mut pos = 0;
        let mut actions = Vec::new();
        loop {
            let more = {
                let mut c = lock(&self.core);
                loop {
                    if c.dead {
                        return;
                    }
                    match c.next_frame(&buf[pos..], &mut actions) {
                        Ok(None) => break false,
                        Ok(Some(n)) => pos += n,
                        Err(Fail::Conn(code)) => {
                            c.conn_error(code);
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
                self.run(a);
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
        drop(c);
        drop(batch);
    }

    fn run(&self, a: Action) {
        match a {
            Action::Dispatch(mut ctx) => {
                self.service.call(&mut ctx);
                finalize(&mut ctx);
            }
            Action::Start(sid, mut ctx) => {
                self.service.call(&mut ctx);
                let mut c = lock(&self.core);
                if let Some(st) = c.streams.get_mut(&sid) {
                    st.ctx = Some(ctx);
                }
            }
            Action::Chunk(sid, data) => {
                if let Some(mut ctx) = self.take_ctx(sid) {
                    ctx.deliver(BodyEvent::Chunk(&data));
                    let mut c = lock(&self.core);
                    if let Some(st) = c.streams.get_mut(&sid) {
                        st.ctx = Some(ctx);
                    }
                }
            }
            Action::End(sid, trailers) => {
                if let Some(mut ctx) = self.take_ctx(sid) {
                    ctx.deliver(BodyEvent::End(&trailers));
                    finalize(&mut ctx);
                }
            }
        }
    }

    fn take_ctx(&self, sid: u32) -> Option<Box<Context>> {
        lock(&self.core).streams.get_mut(&sid)?.ctx.take()
    }

    /// Graceful shutdown: GOAWAY now, close when the open streams have finished.
    pub(crate) fn shutdown(&self) {
        let mut c = lock(&self.core);
        c.goaway(err::NO_ERROR);
        c.flush();
        c.maybe_close_after_goaway();
    }

    pub(crate) fn on_close(&self) {
        let mut c = lock(&self.core);
        c.dead = true;
        let all: Vec<Stream> = c.streams.drain().map(|(_, s)| s).collect();
        c.dropped.extend(all);
    }
}

fn finalize(ctx: &mut Context) {
    if !ctx.responded() && !ctx.is_detached() {
        ctx.respond(Response::text(500, "handler did not respond"));
    }
}
