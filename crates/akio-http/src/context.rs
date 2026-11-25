//! The per-request [`Context`] and the [`Service`] / [`Middleware`] traits.

use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use akio_core::{Part, ResponseSlot, ResponseStream};

use crate::h2::{H2Responder, H2Stream};
use akio_ws::{WsConfig, WsHandler, deflate::PmdParams};

use crate::coding::StreamEncoder;
use crate::gate::{BodyFilter, Gate, GateHandle};
use crate::message::{Headers, Method, Request, Response, Spare, Version};
use crate::router::RouteInfo;
use akio_log::span::Span;

/// Application code: handles one request.
///
/// `call` runs on the connection's I/O thread, so it must not block. To do slow work, call
/// [`Context::detach_to_pool`] (or [`Context::detach`] and finish the response later from any
/// thread), or run every request on the logical pool with `run_on_pool`
/// ([`HttpConfig`](crate::HttpConfig), [`H2Config`](crate::H2Config)).
pub trait Service: Send + Sync + 'static {
    /// Handles `ctx`. It must either respond, or detach the context and respond later; if it
    /// does neither, the client gets a 500.
    fn call(&self, ctx: &mut Context);

    /// How the request body should be delivered for `req` (whose head is complete and whose body
    /// is not). The default buffers it (within `HttpConfig::max_body_bytes`) before `call`.
    fn body_mode(&self, _req: &Request) -> BodyMode {
        BodyMode::Buffered
    }

    /// Whether [`body_mode`](Self::body_mode) may answer [`BodyMode::Stream`] for some request.
    /// `false` lets the server skip asking for every request with a body (for a router, a
    /// second route lookup). The default, `true`, is always correct.
    fn streams_bodies(&self) -> bool {
        true
    }
}

/// How a request body reaches the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BodyMode {
    /// Fully received (and size-limited) before `call`; the body is `ctx.body()`.
    Buffered,
    /// `call` runs as soon as the head is parsed; register [`Context::on_body`] to receive the
    /// chunks as they arrive. No size limit applies: the sink decides what to do with the data.
    Stream,
}

/// Marks a service as taking its request body as a stream; see [`BodyMode::Stream`].
pub struct Streaming<S>(pub S);

impl<S> std::fmt::Debug for Streaming<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Streaming").finish_non_exhaustive()
    }
}

impl<S: Service> Service for Streaming<S> {
    fn call(&self, ctx: &mut Context) {
        self.0.call(ctx);
    }
    fn body_mode(&self, _req: &Request) -> BodyMode {
        BodyMode::Stream
    }
    fn streams_bodies(&self) -> bool {
        true
    }
}

/// A piece of a streamed request body; see [`Context::on_body`].
pub enum BodyEvent<'a> {
    /// More body bytes.
    Chunk(&'a [u8]),
    /// The body is complete; chunked bodies may carry trailer fields.
    End(&'a Headers),
}

impl<'a> std::fmt::Debug for BodyEvent<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyEvent").finish_non_exhaustive()
    }
}

type Sink = Box<dyn FnMut(&mut Context, BodyEvent<'_>) + Send>;
type Filter = Box<dyn FnOnce(&mut Response, &Request) + Send>;
type EndHook = Box<dyn FnOnce(End) + Send>;
type GoneHook = Box<dyn FnOnce() + Send>;
type HoldHook = Box<dyn FnOnce(HeldHead, &Request) + Send>;

/// How a request ended, for [`Context::on_end`] (ADR-127).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum End {
    /// Its response was handed to the connection in full: a whole response once sent, a
    /// streamed one once [`BodyStream::finish`]ed (its last byte, and on HTTP/1.1 its last
    /// chunk, queued on the connection or stream), an upgrade once its `101` (or `200`) went
    /// out or the connection was taken over ([`Context::upgrade_raw`]).
    Sent,
    /// It ended before that: its client went (as [`Context::on_gone`] hears it: the connection
    /// closed, or on HTTP/2 and HTTP/3 the stream reset or its response stopped), or the server
    /// gave its response up (a [`Detached`] or [`BodyStream`] dropped unfinished, which closes
    /// the connection or resets the stream).
    Gone,
}

/// A request's end hooks ([`Context::on_end`]) and its peer-gone callback
/// ([`Context::on_gone`]), shared by the context and whatever holds its response (a
/// [`Detached`], a [`BodyStream`]); the transport holds it weakly, to run when the client goes.
/// Made only for a request that registers one.
#[derive(Default)]
pub(crate) struct Hooks(Mutex<HookState>);

#[derive(Default)]
struct HookState {
    /// The [`Context::on_gone`] callback: run when the client goes, dropped once the response
    /// is sent.
    gone: Option<GoneHook>,
    /// The [`Context::on_end`] hooks, in registration order, each run once.
    ends: Vec<EndHook>,
    /// How the request ended, once it did: a hook registered later runs at once with it.
    ended: Option<End>,
    /// The transport was asked to tell the client's going.
    watched: bool,
    /// The transport told it: a callback set later runs at once.
    client_went: bool,
}

fn lock_hooks(h: &Hooks) -> std::sync::MutexGuard<'_, HookState> {
    h.0.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Hooks {
    /// The client went (the transport's peer-gone callback): the [`Context::on_gone`] callback
    /// runs, and the request ends [`End::Gone`] unless it already ended.
    fn client_gone(&self) {
        let (gone, ends) = {
            let mut st = lock_hooks(self);
            st.client_went = true;
            let gone = st.gone.take();
            if st.ended.is_some() {
                (gone, Vec::new())
            } else {
                st.ended = Some(End::Gone);
                (gone, std::mem::take(&mut st.ends))
            }
        };
        if let Some(g) = gone {
            g();
        }
        for f in ends {
            f(End::Gone);
        }
    }

    /// The request ended `end`, unless it already ended. Once sent, the [`Context::on_gone`]
    /// callback is dropped unrun; when given up ([`End::Gone`] from a dropped [`Detached`] or
    /// stream) it stays for the transport, which runs it as the connection or stream closes.
    fn end(&self, end: End) {
        let (gone, ends) = {
            let mut st = lock_hooks(self);
            if st.ended.is_some() {
                return;
            }
            st.ended = Some(end);
            let gone = if end == End::Sent {
                st.gone.take()
            } else {
                None
            };
            (gone, std::mem::take(&mut st.ends))
        };
        drop(gone);
        for f in ends {
            f(end);
        }
    }

    /// Adds an end hook; runs it at once when the request already ended.
    fn add_end(&self, f: EndHook) {
        let ended = {
            let mut st = lock_hooks(self);
            if st.ended.is_none() {
                st.ends.push(f);
                return;
            }
            st.ended
        };
        if let Some(e) = ended {
            f(e);
        }
    }

    /// Sets the [`Context::on_gone`] callback, replacing an earlier one; dropped when the
    /// response was already sent, run at once when the client already went.
    fn set_gone(&self, f: GoneHook) {
        let old = {
            let mut st = lock_hooks(self);
            if st.ended == Some(End::Sent) {
                return;
            }
            if st.client_went {
                drop(st);
                return f();
            }
            st.gone.replace(f)
        };
        drop(old);
    }

    /// Asks the transport of `out` to tell the client's going, once.
    fn watch(self: &Arc<Self>, out: &mut Out) {
        if std::mem::replace(&mut lock_hooks(self).watched, true) {
            return;
        }
        let w = Arc::downgrade(self);
        out.on_gone(Box::new(move || {
            if let Some(h) = w.upgrade() {
                h.client_gone();
            }
        }));
    }
}

/// The duty to end a request's hooks, carried with its response (a [`Detached`], a
/// [`BodyStream`]): [`sent`](Self::sent) once the response is out, [`End::Gone`] when dropped
/// before.
#[derive(Default)]
struct EndGuard(Option<Arc<Hooks>>);

impl EndGuard {
    fn sent(&mut self) {
        if let Some(h) = self.0.take() {
            h.end(End::Sent);
        }
    }
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.end(End::Gone);
        }
    }
}

impl<F> Service for F
where
    F: Fn(&mut Context) + Send + Sync + 'static,
{
    fn call(&self, ctx: &mut Context) {
        self(ctx);
    }
    fn streams_bodies(&self) -> bool {
        false
    }
}

/// Wraps a [`Service`]: runs before and/or after it, or answers without calling it.
pub trait Middleware: Send + Sync + 'static {
    /// Handles `ctx`, usually by calling `next.call(ctx)`.
    fn handle(&self, ctx: &mut Context, next: &dyn Service);
}

impl<F> Middleware for F
where
    F: Fn(&mut Context, &dyn Service) + Send + Sync + 'static,
{
    fn handle(&self, ctx: &mut Context, next: &dyn Service) {
        self(ctx, next);
    }
}

/// Everything the response path needs, shared by [`Context`] and [`Detached`].
struct Responder {
    slot: ResponseSlot,
    version: Version,
    keep_alive: bool,
    head_only: bool,
    /// [`Context::on_gone`] registered a peer-gone callback under this slot's number (it fits
    /// in the padding: `Out` stays 24 bytes), forgotten once the response is sent.
    gone: bool,
}

/// Where a response goes: an HTTP/1 ordered slot, or an HTTP/2 stream.
enum Out {
    H1(Responder),
    H2(H2Responder),
    Ext(ExtOut),
}

/// A response for a transport outside this crate (HTTP/3): the connection's sink (a thin
/// pointer) and the transport's tag for this request. 16 bytes, so `Out` (and `Context`, boxed
/// per request on HTTP/2) stays as small as with the boxed sink it replaces.
pub(crate) struct ExtOut(pub(crate) crate::transport::SharedSink, pub(crate) u64);

impl ExtOut {
    #[inline]
    fn send(self, resp: Response) {
        self.0.get().send(self.1, resp);
    }

    fn start_stream(self, resp: Response) -> Option<Box<dyn crate::transport::BodySink>> {
        self.0.get().start_stream(self.1, resp)
    }
}

impl Out {
    /// Gives the response up before its head went: closes the HTTP/1 connection, resets the
    /// stream (ADR-128).
    fn cut(self) {
        match self {
            Out::H1(r) => drop(r),
            Out::H2(r) => r.reset(),
            Out::Ext(e) => e.0.get().reset(e.1),
        }
    }

    fn on_gone(&mut self, f: Box<dyn FnOnce() + Send>) {
        match self {
            Out::H1(r) => r.set_gone(f),
            Out::H2(r) => r.on_gone(f),
            Out::Ext(e) => e.0.get().on_gone(e.1, f),
        }
    }

    /// Sends `resp`, its filters applied, then ends the request's hooks [`End::Sent`] (a coded
    /// file's, streamed, once its stream finishes). A response with a held head or body filters
    /// goes through them first (ADR-128).
    fn send(
        self,
        mut resp: Response,
        fin: &mut Finish,
        req: &mut ReqSrc<'_>,
        end: EndGuard,
    ) -> u16 {
        if fin.asyncs.is_some() && req.get().method != Method::Connect {
            return send_async(self, resp, fin, req, end, false).0;
        }
        fin.apply(&mut resp, req.get());
        self.deliver(resp, req.get(), end)
    }

    /// Sends `resp`, whose filters ran, then ends the request's hooks.
    fn deliver(self, resp: Response, req: &Request, mut end: EndGuard) -> u16 {
        let status = resp.status;
        if resp.stream_coding.is_some()
            && resp.file.is_some()
            && status >= 200
            && status != 204
            && status != 304
        {
            // A file body a filter gave a coding (ADR-124): read and encoded on the disk pool.
            coded_file(self, resp, req, end);
            return status;
        }
        match self {
            Out::H1(r) => r.send(resp),
            Out::H2(r) => r.send(resp),
            Out::Ext(r) => r.send(resp),
        }
        end.sent();
        status
    }
}

/// Sends `resp`, whose body is a file and which a response filter gave a stream coding, as a
/// streamed response (ADR-124): `Content-Length` dropped, chunked on keep-alive HTTP/1.1, the
/// file read in pieces on the disk pool and each piece encoded there and written under the
/// connection's backpressure ([`FilePump`]). A HEAD answer sends the head alone.
fn coded_file(out: Out, mut resp: Response, req: &Request, end: EndGuard) {
    let Some(file) = resp.file.take() else { return };
    resp.streaming = true;
    resp.headers.remove("Content-Length");
    let chunked = matches!(&out, Out::H1(r) if r.version == Version::Http11 && r.keep_alive);
    if chunked {
        resp.headers.set("Transfer-Encoding", "chunked");
    }
    let Some(stream) = open_stream(out, resp, req, chunked, end) else {
        return;
    };
    if req.method == Method::Head || file.len == 0 {
        stream.finish();
        return;
    }
    FilePump {
        stream,
        file: file.file,
        offset: file.offset,
        left: file.len,
        refused: 0,
    }
    .submit();
}

/// A file body being read, encoded and written on the disk pool (ADR-124).
struct FilePump {
    stream: BodyStream,
    file: Arc<std::fs::File>,
    offset: u64,
    left: u64,
    /// Times in a row the pool refused the next run.
    refused: u32,
}

/// What [`FilePump`] reads at a time: each piece is encoded and flushed as one write.
const PUMP_PIECE: usize = 64 << 10;
/// Bytes queued on the connection past which [`FilePump`] waits for it to drain.
const PUMP_HIGH: usize = 256 << 10;
/// How long [`FilePump`] waits before asking a full pool again, and how many times: past
/// that (a second of a pool that stays full), the response is cut and its connection closed.
const PUMP_RETRY: Duration = Duration::from_millis(5);
const PUMP_RETRIES: u32 = 200;

impl FilePump {
    /// Runs the pump on the disk pool; a full pool is asked again a little later.
    fn submit(self) {
        let cell = Arc::new(Mutex::new(Some(self)));
        let job_cell = cell.clone();
        let job = Box::new(move || {
            let p = job_cell
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(p) = p {
                p.run();
            }
        });
        if crate::files::disk_pool().try_execute(job).is_err() {
            let p = cell.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(mut p) = p {
                p.refused += 1;
                if p.refused <= PUMP_RETRIES {
                    crate::timer::after(PUMP_RETRY, move || p.submit());
                }
                // Else dropped: the stream unfinished closes the connection.
            }
        }
    }

    /// Reads, encodes and writes pieces until the file is sent (the stream finished), the
    /// connection falls behind (resumed when it drains) or a read or write fails (the stream
    /// dropped, which closes the connection: the body is cut).
    fn run(mut self) {
        self.refused = 0;
        let mut buf = vec![0u8; PUMP_PIECE.min(usize::try_from(self.left).unwrap_or(PUMP_PIECE))];
        while self.left > 0 {
            let n = buf
                .len()
                .min(usize::try_from(self.left).unwrap_or(usize::MAX));
            let Some(piece) = buf.get_mut(..n) else {
                return;
            };
            if std::os::unix::fs::FileExt::read_exact_at(&*self.file, piece, self.offset).is_err()
                || self.stream.write(piece).is_err()
            {
                return; // the file shrank, or the client went
            }
            self.offset = self.offset.saturating_add(n as u64);
            self.left -= n as u64;
            if self.left > 0 && self.stream.queued_bytes() > PUMP_HIGH {
                return self.wait();
            }
        }
        self.stream.finish();
    }

    /// Resumes on the disk pool once the connection drained (or is gone).
    fn wait(self) {
        let cell: Arc<Mutex<Option<FilePump>>> = Arc::new(Mutex::new(None));
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (c, f) = (cell.clone(), fired.clone());
        // `on_drain` may run at once, here: the pump is put in its cell after, and the flag
        // tells whether that happened.
        self.stream.on_drain(move || {
            f.store(true, std::sync::atomic::Ordering::SeqCst);
            let p = c.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(p) = p {
                p.submit();
            }
        });
        *cell.lock().unwrap_or_else(PoisonError::into_inner) = Some(self);
        if fired.load(std::sync::atomic::Ordering::SeqCst) {
            let p = cell.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(p) = p {
                p.submit();
            }
        }
    }
}

/// Response filters: the first two inline (a middleware stack rarely registers more), the rest
/// in a vector, so a request with filters does not also allocate a list for them. Outer filters
/// ([`Context::add_outer_response_filter`], ADR-116) go in the vector, marked.
#[derive(Default)]
struct Filters {
    inline: [Option<Filter>; 2],
    /// Each filter, and whether it is an outer one.
    rest: Vec<(bool, Filter)>,
}

impl Filters {
    #[inline]
    fn is_empty(&self) -> bool {
        self.inline[0].is_none() && self.rest.is_empty()
    }

    fn push(&mut self, f: Filter) {
        match self.inline.iter_mut().find(|s| s.is_none()) {
            Some(slot) => *slot = Some(f),
            None => self.rest.push((false, f)),
        }
    }

    fn push_outer(&mut self, f: Filter) {
        self.rest.push((true, f));
    }

    /// Takes the ordinary filters, in registration order, leaving the outer ones.
    fn drain_ordinary(&mut self) -> impl Iterator<Item = Filter> {
        let [a, b] = std::mem::take(&mut self.inline);
        let rest = std::mem::take(&mut self.rest);
        let (outer, ordinary): (Vec<_>, Vec<_>) = rest.into_iter().partition(|(outer, _)| *outer);
        self.rest = outer;
        a.into_iter()
            .chain(b)
            .chain(ordinary.into_iter().map(|(_, f)| f))
    }

    /// Takes every filter: the ordinary ones in registration order, then the outer ones in
    /// reverse registration order.
    fn drain(&mut self) -> impl Iterator<Item = Filter> {
        let [a, b] = std::mem::take(&mut self.inline);
        let mut rest = std::mem::take(&mut self.rest);
        // Only a request with an outer filter pays for sorting them out.
        let outer: Vec<Filter> = if rest.iter().any(|(outer, _)| *outer) {
            let (outer, ordinary): (Vec<_>, Vec<_>) =
                rest.into_iter().partition(|(outer, _)| *outer);
            rest = ordinary;
            outer.into_iter().rev().map(|(_, f)| f).collect()
        } else {
            Vec::new()
        };
        a.into_iter()
            .chain(b)
            .chain(rest.into_iter().map(|(_, f)| f))
            .chain(outer)
    }
}

/// What is applied to a response on its way out.
struct Finish {
    extra: Headers,
    filters: Filters,
    /// Set with the time header: reading the clock for every request costs.
    started: Option<Instant>,
    time_header: Option<Cow<'static, str>>,
    /// The request span (`crate::trace`), ended when the response goes out.
    span: Span,
    /// Held heads and body filters (ADR-128), once one is registered.
    asyncs: Option<Box<Asyncs>>,
}

/// A response's held heads and body filters (ADR-128), in registration order.
#[derive(Default)]
struct Asyncs {
    holds: Vec<(Duration, HoldHook)>,
    filters: Vec<Box<dyn BodyFilter>>,
}

impl Finish {
    fn new() -> Finish {
        Finish {
            extra: Headers::new(),
            filters: Filters::default(),
            started: None,
            time_header: None,
            span: Span::none(),
            asyncs: None,
        }
    }

    fn asyncs(&mut self) -> &mut Asyncs {
        self.asyncs.get_or_insert_with(Box::default)
    }

    /// The first half of [`apply`](Self::apply) for a response with held heads or body filters
    /// (ADR-128): the ordinary filters and the extra headers, which the hooks see.
    fn apply_inner(&mut self, resp: &mut Response, req: &Request) {
        if !self.span.is_none() {
            crate::trace::responded(std::mem::take(&mut self.span), resp);
        }
        for f in self.filters.drain_ordinary() {
            f(resp, req);
        }
        for (n, v) in self.extra.iter() {
            if resp.headers.get(n).is_none() {
                resp.headers.append(n, v);
            }
        }
        self.extra = Headers::new();
    }

    /// Runs the filters, then adds the extra headers the response did not set.
    #[inline]
    fn apply(&mut self, resp: &mut Response, req: &Request) {
        // Most responses have none of these: skip the draining and lookups.
        if self.filters.is_empty()
            && self.extra.is_empty()
            && self.time_header.is_none()
            && self.span.is_none()
        {
            return;
        }
        if !self.span.is_none() {
            crate::trace::responded(std::mem::take(&mut self.span), resp);
        }
        for f in self.filters.drain() {
            f(resp, req);
        }
        for (n, v) in self.extra.iter() {
            if resp.headers.get(n).is_none() {
                resp.headers.append(n, v);
            }
        }
        if let Some(h) = &self.time_header {
            use std::io::Write as _;
            // `<ms>ms` formatted on the stack.
            let ms = self.started.map_or(0.0, |s| s.elapsed().as_secs_f64()) * 1e3;
            let mut buf = [0u8; 40];
            let n = {
                let mut w = &mut buf[..];
                let _ = write!(w, "{ms:.3}ms");
                40 - w.len()
            };
            resp.headers
                .set(&**h, std::str::from_utf8(&buf[..n]).unwrap_or("0ms"));
        }
    }
}

impl Responder {
    /// Runs `f` when the connection closes before the response is sent ([`Context::on_gone`]).
    fn set_gone(&mut self, f: Box<dyn FnOnce() + Send>) {
        if let Some(c) = self.slot.conn() {
            self.gone = c.on_peer_gone(self.slot.seq(), f);
        }
    }

    fn forget_gone(&mut self) {
        if std::mem::take(&mut self.gone) {
            if let Some(c) = self.slot.conn() {
                c.forget_peer_gone(self.slot.seq());
            }
        }
    }

    /// Sends `resp`, its filters applied.
    fn send(mut self, resp: Response) {
        self.forget_gone();
        let status = resp.status;
        // From the I/O thread's buffer pool: the connection gives it back there once written.
        let mut head = akio_buf::get(192 + resp.body.len());
        resp.encode(self.version, self.keep_alive, self.head_only, &mut head);
        resp.headers.recycle(Spare::Resp);
        // The body is in `head` now (or not sent at all): its buffer is the thread's spare.
        crate::message::recycle_body(resp.body);
        let bodyless = status < 200 || status == 204 || status == 304;
        match resp.file {
            Some(f) if !self.head_only && !bodyless => self.slot.fill_parts(
                vec![
                    Part::Bytes(head),
                    Part::File {
                        file: f.file,
                        offset: f.offset,
                        len: f.len,
                    },
                ],
                !self.keep_alive,
            ),
            _ if self.keep_alive => self.slot.fill(head),
            _ => self.slot.fill_close(head),
        }
    }
}

/// The request of a [`Context`]: owned (no allocation) until a [`Detached`] or a WebSocket
/// upgrade needs to share it.
// Inline on purpose: boxing the request is the allocation this saves.
#[allow(clippy::large_enum_variant)]
enum ReqCell {
    Own(Request),
    Shared(Arc<Request>),
}

impl ReqCell {
    /// The request, shared from now on.
    fn share(&mut self) -> Arc<Request> {
        let a = match self {
            ReqCell::Shared(a) => return a.clone(),
            ReqCell::Own(r) => Arc::new(std::mem::replace(r, Request::new(Method::Get, ""))),
        };
        *self = ReqCell::Shared(a.clone());
        a
    }
}

impl std::ops::Deref for ReqCell {
    type Target = Request;
    fn deref(&self) -> &Request {
        match self {
            ReqCell::Own(r) => r,
            ReqCell::Shared(a) => a,
        }
    }
}

/// The request, for the response path: the context's (shared only when a held head or a body
/// filter needs to keep it, ADR-128), or a [`Detached`]'s.
enum ReqSrc<'a> {
    Cell(&'a mut ReqCell),
    Arc(&'a Arc<Request>),
}

impl ReqSrc<'_> {
    fn get(&self) -> &Request {
        match self {
            ReqSrc::Cell(c) => c,
            ReqSrc::Arc(a) => a,
        }
    }

    fn arc(&mut self) -> Arc<Request> {
        match self {
            ReqSrc::Cell(c) => c.share(),
            ReqSrc::Arc(a) => Arc::clone(a),
        }
    }
}

/// A target buffer larger than this is not kept for the next request (an occasional long
/// target should not pin its memory to the thread).
pub(crate) const SPARE_TARGET_MAX: usize = 1024;

thread_local! {
    /// The target buffer of the last request this thread finished with, emptied, for the next
    /// request's target. Per thread rather than per connection: the next request parsed on
    /// this thread finds it still in cache, as the allocator's own free list would (a buffer
    /// kept per connection is cold when that connection's turn comes again; measured on h2c).
    static SPARE_TARGET: std::cell::Cell<String> = const { std::cell::Cell::new(String::new()) };
}

/// A new request's target: `target` written into this thread's spare buffer (see
/// [`Context::recycle_target`]), so requests do not allocate one each.
#[inline]
pub(crate) fn new_target(target: &str) -> String {
    let mut t = SPARE_TARGET.take();
    t.push_str(target);
    t
}

/// One request being handled, and the means to answer it.
pub struct Context {
    req: ReqCell,
    params: crate::router::Params,
    locals: Vec<(String, String)>,
    fin: Finish,
    responder: Option<Out>,
    status: Option<u16>,
    detached: bool,
    /// Running on the logical pool (`run_on_pool`): the connection cannot be taken over.
    pooled: bool,
    upgrade: Option<PendingUpgrade>,
    raw: Option<Box<dyn crate::raw::RawHandler>>,
    sink: Option<Sink>,
    route: Option<&'static RouteInfo>,
    /// The body arrives after `call` ([`BodyMode::Stream`]): its reads can be held.
    streamed: bool,
    /// HTTP/1: the hold on the connection's reads that [`body_reads`](Self::body_reads) gave
    /// out, released when the body ends.
    reads: Option<Arc<H1Reads>>,
    /// The request's end hooks and peer-gone callback, once one is registered (ADR-127).
    hooks: Option<Arc<Hooks>>,
}

impl Drop for Context {
    fn drop(&mut self) {
        // Dropped still holding its response, unanswered (its connection or stream closes
        // with it): the request ends there.
        if self.responder.is_some() {
            if let Some(h) = &self.hooks {
                h.end(End::Gone);
            }
        }
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

/// A WebSocket upgrade accepted by [`Context::upgrade_websocket`], applied by the session.
pub(crate) struct PendingUpgrade {
    pub handler: Box<dyn WsHandler>,
    pub cfg: WsConfig,
    pub pmd: Option<PmdParams>,
    /// The `200` already sent on a transport outside this crate (HTTP/3), kept until the
    /// transport takes the stream over.
    pub ext: Option<Box<dyn crate::transport::BodySink>>,
}

/// Options for [`Context::upgrade_websocket`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct WsOptions {
    /// Message limits and compression.
    pub config: WsConfig,
    /// Subprotocols the server speaks, in no particular order; the client's first choice among
    /// them is selected.
    pub protocols: Vec<String>,
    /// If set, a request with an `Origin` header is refused with 403 unless this returns true for
    /// it. Requests without `Origin` (non-browser clients) are not affected.
    pub origin_allowed: Option<fn(&str) -> bool>,
}

impl Context {
    pub(crate) fn new(req: Request, slot: ResponseSlot, keep_alive: bool) -> Context {
        let head_only = req.method == Method::Head;
        Context {
            responder: Some(Out::H1(Responder {
                slot,
                version: req.version,
                keep_alive,
                head_only,
                gone: false,
            })),
            fin: Finish::new(),
            req: ReqCell::Own(req),
            params: Default::default(),
            locals: Vec::new(),
            status: None,
            detached: false,
            pooled: false,
            upgrade: None,
            raw: None,
            sink: None,
            route: None,
            streamed: false,
            reads: None,
            hooks: None,
        }
    }

    /// A context whose response goes to a transport outside this crate.
    #[inline(always)]
    pub(crate) fn new_ext(req: Request, sink: ExtOut) -> Context {
        let mut c = Context::new_h2_like(req);
        c.responder = Some(Out::Ext(sink));
        c
    }

    /// Once the handler is done: if this context still owns the request (the handler neither
    /// detached nor upgraded it), its target buffer and its header storage become the thread's
    /// spares for the next request's (see [`new_target`] and `Headers::spare`), unless they
    /// grew past what is worth keeping.
    #[inline]
    pub(crate) fn recycle_request(&mut self) {
        if let ReqCell::Own(r) = &mut self.req {
            // A request moved out ([`suspend`](Self::suspend)) left an empty one: nothing to keep.
            if r.target.capacity() == 0 {
                return;
            }
            if r.target.capacity() <= SPARE_TARGET_MAX {
                let mut t = std::mem::take(&mut r.target);
                t.clear();
                SPARE_TARGET.set(t);
            }
            std::mem::take(&mut r.headers).recycle(Spare::Req);
        }
    }

    fn new_h2_like(req: Request) -> Context {
        Context {
            fin: Finish::new(),
            req: ReqCell::Own(req),
            params: Default::default(),
            locals: Vec::new(),
            status: None,
            detached: false,
            pooled: false,
            upgrade: None,
            raw: None,
            sink: None,
            route: None,
            streamed: false,
            reads: None,
            hooks: None,
            responder: None,
        }
    }

    /// A context for a request on an HTTP/2 stream.
    pub(crate) fn new_h2(req: Request, responder: H2Responder) -> Context {
        Context {
            fin: Finish::new(),
            req: ReqCell::Own(req),
            params: Default::default(),
            locals: Vec::new(),
            status: None,
            detached: false,
            pooled: false,
            upgrade: None,
            raw: None,
            sink: None,
            route: None,
            streamed: false,
            reads: None,
            hooks: None,
            responder: Some(Out::H2(responder)),
        }
    }

    /// The request.
    pub fn req(&self) -> &Request {
        &self.req
    }

    /// The request, to change before the handler sees it (ADR-126): a middleware sets, adds and
    /// removes its fields, changes its target (a rewritten path), its method or its body. What
    /// reads the request afterwards sees the change: [`path`](Self::path),
    /// [`header`](Self::header), the handlers after this middleware, [`Files`](crate::files::Files)'
    /// conditional and range fields, the response filters' `&Request`. Route parameters keep
    /// reading the path they were matched in ([`param`](Self::param)): a router matches before
    /// its routes' layers run, so a target changed by one of them does not route the request
    /// again, while one changed by a [`Middleware`] wrapping the whole router does.
    ///
    /// `None` once the request is shared: after [`detach`](Self::detach) (the [`Detached`] has
    /// it) or a WebSocket upgrade. A context resumed after [`suspend`](Self::suspend) has it
    /// whole, to change.
    ///
    /// The request's framing is the server's: a changed `Content-Length` or
    /// `Transfer-Encoding` does not change how the rest of its body is read.
    pub fn req_mut(&mut self) -> Option<&mut Request> {
        self.params.pin(self.req.path());
        match &mut self.req {
            ReqCell::Own(r) => Some(r),
            ReqCell::Shared(a) => Arc::get_mut(a),
        }
    }

    /// The method.
    pub fn method(&self) -> &Method {
        &self.req.method
    }

    /// The path, without the query.
    pub fn path(&self) -> &str {
        self.req.path()
    }

    /// A request header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.req.headers.get(name)
    }

    /// The request body.
    pub fn body(&self) -> &[u8] {
        &self.req.body
    }

    /// The client's address: the source of the PROXY header akio-mux's `ProxyProtocol` layer
    /// read for the connection, when it read one naming an address, else the socket's peer
    /// ([`Request::peer`], ADR-118).
    pub fn peer(&self) -> SocketAddr {
        self.req.peer
    }

    /// A route parameter (`:id`, `{id:re}` or `*rest`) matched by the router, percent-decoded
    /// (once, at dispatch; a value with a malformed escape or invalid UTF-8 is returned as sent).
    /// A decoded wildcard may contain `/` that was sent as `%2F`: use
    /// [`param_raw`](Self::param_raw) where segment boundaries matter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name, self.req.path())
    }

    /// A route parameter exactly as it appears in the request path (not percent-decoded).
    pub fn param_raw(&self, name: &str) -> Option<&str> {
        self.params.raw(name, self.req.path())
    }

    pub(crate) fn set_params(&mut self, params: crate::router::Params) {
        self.params = params;
    }

    /// Stores a value for later middleware/handlers of this request.
    pub fn set_local(&mut self, key: &str, value: impl Into<String>) {
        self.locals.retain(|(k, _)| k != key);
        self.locals.push((key.to_owned(), value.into()));
    }

    /// A value stored with [`set_local`](Self::set_local).
    pub fn local(&self, key: &str) -> Option<&str> {
        self.locals
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Adds a header to the response, whenever and however it is sent, unless the response sets
    /// that header itself.
    pub fn add_response_header(&mut self, name: &str, value: impl AsRef<str>) {
        self.fin.extra.set(name, value);
    }

    /// Registers a function that edits the response just before it is sent (compression, ETags).
    /// Filters run in registration order, on the thread that sends the response.
    pub fn add_response_filter(
        &mut self,
        f: impl FnOnce(&mut Response, &Request) + Send + 'static,
    ) {
        self.fin.filters.push(Box::new(f));
    }

    /// Adds a response filter that runs after every filter
    /// [`add_response_filter`](Self::add_response_filter) adds, the outer filters in the reverse
    /// of the order they were added (ADR-116): a middleware that registers one before calling the
    /// handlers it wraps sees the response as the middlewares inside it left it (encoded by a
    /// `compress` filter, say), as a cache in front of them must.
    pub fn add_outer_response_filter(
        &mut self,
        f: impl FnOnce(&mut Response, &Request) + Send + 'static,
    ) {
        self.fin.filters.push_outer(Box::new(f));
    }

    /// Holds the response's head back where it would go, until work done elsewhere decides on it
    /// (ADR-128): a WebAssembly plugin's `proxy_on_response_headers` run on its pool, say.
    ///
    /// `f` runs on the thread sending the response, once the response filters
    /// ([`add_response_filter`](Self::add_response_filter)) ran and the extra headers
    /// ([`add_response_header`](Self::add_response_header)) were added, with the response's
    /// head in a [`HeldHead`] and the request. It must not block: it hands the head on, and
    /// whatever takes it calls [`HeldHead::resume`] (or `respond`, or `fail`) from any thread.
    /// The outer filters ([`add_outer_response_filter`](Self::add_outer_response_filter)) run
    /// after, then the head goes. Several held heads go one after another, in the order they
    /// were added.
    ///
    /// Meanwhile a response sent whole waits whole, and what the handler writes to a streamed
    /// one is held, its [`BodyStream::queued_bytes`] counting it (a producer pacing itself on
    /// them waits, as for a slow client), up to 4 MiB, past which its writes fail and the
    /// response is cut. Past `timeout` the response is cut, as [`HeldHead::fail`] cuts it, and
    /// a later answer does nothing. A response to `CONNECT`, and an upgrade's, go at once.
    pub fn hold_response_head(
        &mut self,
        timeout: Duration,
        f: impl FnOnce(HeldHead, &Request) + Send + 'static,
    ) {
        self.fin.asyncs().holds.push((timeout, Box::new(f)));
    }

    /// Passes the response's body through `filter`, whose work is done elsewhere (ADR-128): a
    /// WebAssembly plugin's `proxy_on_response_body` and `proxy_on_response_trailers` run on its
    /// pool, say. See [`BodyFilter`] for its calls.
    ///
    /// The filter is given the body once the head went (after any held head,
    /// [`hold_response_head`](Self::hold_response_head)): a streamed body as the handler writes
    /// it, a body sent whole in one last call, a file body as it is read (on the disk pool). Its
    /// output goes on to the next body filter (they run in the order they were added), then
    /// through the stream coding a response filter set and any [`BodyTap`](crate::BodyTap), to
    /// the client. A response sent whole goes as a streamed one, without `Content-Length`, so
    /// the response filters see a streamed head. What is written while a call is under way is
    /// held, as under a held head, up to 4 MiB; the filter's output is paced by the client, the
    /// next call waiting for what the connection holds of it.
    ///
    /// Not called for a response without a body (to `HEAD`, or `1xx`, `204`, `304`), nor for a
    /// response to `CONNECT` or an upgrade's: the filter is dropped. The request's
    /// [`on_end`](Self::on_end) hooks run once the filtered body finished
    /// ([`End::Sent`]), or the response was cut.
    pub fn add_body_filter(&mut self, filter: impl BodyFilter) {
        self.fin.asyncs().filters.push(Box::new(filter));
    }

    /// Adds `header: <elapsed>ms` (time since this call; at dispatch for the `response_time`
    /// middleware) to the response.
    pub fn set_response_time_header(&mut self, header: &str) {
        self.fin.time_header = Some(Cow::Owned(header.to_owned()));
        self.fin.started.get_or_insert_with(Instant::now);
    }

    /// [`set_response_time_header`](Self::set_response_time_header) without copying the name.
    pub(crate) fn set_response_time_header_static(&mut self, header: &'static str) {
        self.fin.time_header = Some(Cow::Borrowed(header));
        self.fin.started.get_or_insert_with(Instant::now);
    }

    /// Receives a streamed request body (see [`BodyMode::Stream`]). The sink is called with each
    /// chunk and finally with `End`; it may respond (early, too) or detach the context.
    pub fn on_body(&mut self, f: impl FnMut(&mut Context, BodyEvent<'_>) + Send + 'static) {
        self.sink = Some(Box::new(f));
    }

    /// Delivers a body event to the sink, if any.
    pub(crate) fn deliver(&mut self, ev: BodyEvent<'_>) {
        if let Some(mut sink) = self.sink.take() {
            sink(self, ev);
            if self.sink.is_none() {
                self.sink = Some(sink);
            }
        }
    }

    /// Holds and resumes the reads of a streamed request body ([`BodyMode::Stream`], ADR-101),
    /// to pace the client by whatever the body is fed to (an upstream, say). `None` when the
    /// body is not streamed, or the response was already taken ([`detach`](Self::detach),
    /// [`stream_response`](Self::stream_response)): take it before. It works after `detach`,
    /// from any thread. See [`BodyReads::hold`].
    pub fn body_reads(&mut self) -> Option<BodyReads> {
        if !self.streamed {
            return None;
        }
        let inner = match self.responder.as_ref()? {
            Out::H1(r) => {
                let conn = r.slot.conn()?.clone();
                let reads = self
                    .reads
                    .get_or_insert_with(|| {
                        Arc::new(H1Reads {
                            conn,
                            st: Mutex::new((false, false)),
                        })
                    })
                    .clone();
                ReadsInner::H1(reads)
            }
            Out::H2(r) => ReadsInner::H2(r.reads()),
            Out::Ext(e) => ReadsInner::Ext(e.0.clone(), e.1),
        };
        Some(BodyReads(inner))
    }

    /// Calls `f` once if the client goes before the response is finished (ADR-108): on
    /// HTTP/1 its connection closes or it finishes sending (EOF: a client that half-closes after
    /// its request counts as gone, as Go's server takes it); on HTTP/2 and HTTP/3 the connection
    /// closes or the client resets the request's stream or stops its response. `f` runs on the
    /// connection's I/O thread (HTTP/2: the thread that drops the stream, usually that one), or
    /// at once on this thread when that already happened. It
    /// replaces an earlier `f`, carries over to [`detach`](Self::detach) and to a streamed
    /// response ([`BodyStream`]) until it is finished, and is dropped unrun once the response
    /// is sent whole or finished. A transport outside this crate runs it as its
    /// [`ConnSink::on_gone`](crate::transport::ConnSink::on_gone) says. Nothing when a response
    /// was already sent.
    ///
    /// A proxy cancels its upstream request from it ([`CancelToken`](crate::client::CancelToken)).
    pub fn on_gone(&mut self, f: impl FnOnce() + Send + 'static) {
        self.with_hooks(|h| h.set_gone(Box::new(f)));
    }

    /// Calls `f` once when the request is done with (ADR-127): [`End::Sent`] once its response
    /// was handed to the connection in full (a streamed one's once [`BodyStream::finish`]ed),
    /// [`End::Gone`] when its client went first (as [`on_gone`](Self::on_gone) hears it), or
    /// its response was given up (a [`Detached`] or [`BodyStream`] dropped unfinished, a
    /// context dropped unanswered). Whatever happens to the request after this call (answered
    /// here, detached, streamed, suspended, upgraded, run on the pool), `f` runs exactly once:
    /// a limit that counts requests under way gives the place back from it, an access log
    /// takes a streamed response's duration from it.
    ///
    /// Hooks run in the order they were added, on the thread that ends the request: the one
    /// that sends the response or finishes the stream, or the connection's I/O thread when the
    /// client goes. Registered after the request ended, `f` runs at once. Registering one also
    /// watches for the client's going, as `on_gone` does (on HTTP/1, an EOF from the client
    /// counts).
    ///
    /// `false`, `f` dropped unrun, when the response was already taken
    /// ([`detach`](Self::detach), [`stream_response`](Self::stream_response), an upgrade) with
    /// no hook registered before: the request can no longer be followed from here. Register
    /// before taking the response, or on the [`Detached`] ([`Detached::on_end`]).
    pub fn on_end(&mut self, f: impl FnOnce(End) + Send + 'static) -> bool {
        let mut f = Some(f);
        if self.with_hooks(|h| {
            if let Some(f) = f.take() {
                h.add_end(Box::new(f));
            }
        }) {
            return true;
        }
        match f {
            Some(f) if !self.detached && self.status.is_some() => {
                // Sent from this context, with no hook to follow it: it ended.
                f(End::Sent);
                true
            }
            _ => false,
        }
    }

    /// Runs `add` with the request's hooks: made, and the transport then asked to tell the
    /// client's going, while this context still holds the response; the existing ones once it
    /// does not (`false` when there are none).
    fn with_hooks(&mut self, add: impl FnOnce(&Hooks)) -> bool {
        if let Some(out) = self.responder.as_mut() {
            let h = self.hooks.get_or_insert_with(Arc::default);
            add(h);
            h.watch(out);
            return true;
        }
        match &self.hooks {
            Some(h) => {
                add(h);
                true
            }
            None => false,
        }
    }

    /// The duty to end this request's hooks, for what takes its response.
    fn end_guard(&self) -> EndGuard {
        EndGuard(self.hooks.clone())
    }

    /// Marks the request as one whose body arrives after `call` (see [`body_reads`]).
    pub(crate) fn set_streamed(&mut self) {
        self.streamed = true;
    }

    /// HTTP/1: the streamed body ended; its reads are no longer held (the next request's are
    /// not the handler's to hold).
    pub(crate) fn end_reads(&self) {
        if let Some(r) = &self.reads {
            r.end();
        }
    }

    /// HTTP/1: whether the handler holds the body's reads (the client is then not slow).
    pub(crate) fn reads_held(&self) -> bool {
        self.reads.as_ref().is_some_and(|r| lock_reads(&r.st).0)
    }

    /// The route the [`Router`](crate::Router) matched (method and pattern, e.g.
    /// `GET /users/:id`), set before the route's middleware and handler run. `None` before
    /// routing, for unmatched requests (404/405) and outside a router.
    pub fn route(&self) -> Option<&'static RouteInfo> {
        self.route
    }

    pub(crate) fn set_route(&mut self, route: &'static RouteInfo) {
        self.route = Some(route);
        if !self.fin.span.is_none() {
            crate::trace::routed(&mut self.fin.span, route);
        }
    }

    /// The context of this request's span (akio-log spans, `akio_http::request`), when request
    /// spans are enabled: pass it to an outgoing request's `traceparent`
    /// ([`SpanContext::to_traceparent`](akio_log::span::SpanContext::to_traceparent)) or enter
    /// it on another thread. While the handler runs, the span is also the thread's current one.
    pub fn span_context(&self) -> Option<akio_log::span::SpanContext> {
        self.fin.span.context()
    }

    pub(crate) fn set_span(&mut self, span: Span) {
        self.fin.span = span;
    }

    /// Whether a response has been sent (or the context detached).
    pub fn responded(&self) -> bool {
        self.responder.is_none()
    }

    /// The status of the response sent from this context, once there is one.
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// Sends `resp`. Only the first response counts; later calls are ignored.
    pub fn respond(&mut self, resp: Response) {
        if let Some(r) = self.responder.take() {
            let end = self.end_guard();
            let mut req = ReqSrc::Cell(&mut self.req);
            self.status = Some(r.send(resp, &mut self.fin, &mut req, end));
        }
    }

    /// Sends a `text/plain` response.
    pub fn text(&mut self, status: u16, body: impl Into<String>) {
        self.respond(Response::text(status, body));
    }

    /// Sends a response with the given content type.
    pub fn bytes(&mut self, status: u16, content_type: &str, body: Vec<u8>) {
        self.respond(Response::with_body(status, content_type, body));
    }

    /// Takes over the right to respond, so the response can be sent after `call` returns and
    /// from any thread. Responses to pipelined requests still go out in request order.
    /// `None` if a response was already sent.
    pub fn detach(&mut self) -> Option<Detached> {
        let responder = self.responder.take()?;
        self.detached = true;
        Some(Detached {
            end: self.end_guard(),
            req: self.req.share(),
            params: std::mem::take(&mut self.params).boxed(),
            fin: Finish {
                extra: std::mem::take(&mut self.fin.extra),
                filters: std::mem::take(&mut self.fin.filters),
                started: self.fin.started,
                time_header: self.fin.time_header.take(),
                span: std::mem::take(&mut self.fin.span),
                asyncs: self.fin.asyncs.take(),
            },
            responder,
        })
    }

    /// Answers later: [detaches](Self::detach) the request and calls `f` with it once `delay`
    /// has passed, **on this I/O thread** (a loop timer, ADR-103): no lock, no other thread, no
    /// wakeup, and the response is written by the thread that owns the connection. `f` never
    /// runs early. `false` (and `f` is dropped) if a response was already sent.
    ///
    /// Called off an I/O thread, `f` runs on the crate's shared timer thread instead. If the
    /// loop already holds `akio_core::timer::MAX_TIMERS_PER_LOOP` timers, `f` is dropped and,
    /// with it, the request: the connection closes.
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # use akio_http::{Context, message::Response};
    /// fn delayed(ctx: &mut Context) {
    ///     ctx.after(Duration::from_millis(10), |d| d.respond(Response::text(200, "late")));
    /// }
    /// ```
    pub fn after(&mut self, delay: Duration, f: impl FnOnce(Detached) + Send + 'static) -> bool {
        let Some(d) = self.detach() else {
            return false;
        };
        if akio_core::timer::on_loop() {
            let _ = akio_core::timer::after(delay, move || f(d));
        } else {
            crate::timer::after(delay, move || f(d));
        }
        true
    }

    /// Starts a response whose body is produced piece by piece (server-sent events, large
    /// generated downloads). `headers` are sent with the head; the framing is `chunked` on
    /// keep-alive HTTP/1.1 and close-delimited otherwise. Response filters see the head
    /// (status and headers, no body); the [`compress`](crate::middleware::compress)
    /// middleware compresses the body when [`Compress::stream`](crate::middleware::Compress)
    /// is set, flushing the encoder on every write. `None` if a response was already started. Write from any thread; dropping the stream
    /// without [`BodyStream::finish`] closes the connection.
    ///
    /// On HTTP/2 and HTTP/3, a `2xx` streamed to an extended CONNECT (RFC 8441, RFC 9220) that
    /// the handler did not [`upgrade_websocket`](Self::upgrade_websocket) opens a tunnel
    /// (ADR-113): the stream's bytes arrive as the streamed request body ([`on_body`](Self::on_body),
    /// held with [`body_reads`](Self::body_reads)), the stream's halves close separately, and a
    /// peer that never ends its half after [`BodyStream::finish`] is reset after a few seconds.
    pub fn stream_response(&mut self, status: u16, headers: Headers) -> Option<BodyStream> {
        let out = self.responder.take()?;
        self.detached = true;
        self.status = Some(status);
        let end = self.end_guard();
        let mut req = ReqSrc::Cell(&mut self.req);
        start_stream(out, &mut self.fin, &mut req, status, headers, end)
    }

    /// Server push (HTTP/2): promises `GET path` to the client and serves it with the same
    /// service on a new stream. `false` when the connection is not HTTP/2, the client disabled
    /// push, or the connection is shutting down.
    pub fn push(&mut self, path: &str) -> bool {
        let authority = self.req.headers.get("host").unwrap_or("").to_owned();
        match &self.responder {
            Some(Out::H2(r)) => r.push(path, &authority),
            _ => false,
        }
    }

    /// Turns this request into a WebSocket connection served by `handler`.
    ///
    /// HTTP/1.1: validates the handshake (`GET`, `Upgrade`/`Connection` tokens, version 13, a
    /// well-formed key, the origin policy), answers `101 Switching Protocols` and switches the
    /// connection to WebSocket; the handler's `on_open` runs right away. Returns `false` after
    /// answering a bad handshake itself (400, 403 or 426), in which case the connection stays
    /// HTTP. Do not pipeline requests behind an upgrade request.
    ///
    /// HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220): the request is an extended CONNECT with
    /// `:protocol` `websocket` (which [`Router`](crate::Router) routes to the path's GET route);
    /// it is answered `200` and its stream carries the WebSocket connection, with the same
    /// checks (version 13, origin), subprotocol selection and `permessage-deflate`. On HTTP/2
    /// the stream's flow control paces the peer, and sends past
    /// [`H2Config::max_pending_bytes`](crate::H2Config::max_pending_bytes) queued fail with
    /// `Overloaded`; a reset stream is a close without handshake (1006).
    pub fn upgrade_websocket(&mut self, handler: impl WsHandler, opts: &WsOptions) -> bool {
        if self.responder.is_none() || self.pooled {
            return false;
        }
        if matches!(self.responder, Some(Out::Ext(_) | Out::H2(_))) {
            return self.upgrade_websocket_connect(Box::new(handler), opts);
        }
        let r = self.req.share();
        let h = &r.headers;
        if r.method != Method::Get || r.version != Version::Http11 {
            self.text(400, "WebSocket upgrade needs GET over HTTP/1.1");
            return false;
        }
        if !h.has_token("connection", "upgrade") || !h.has_token("upgrade", "websocket") {
            self.text(400, "missing Upgrade: websocket");
            return false;
        }
        if h.get("sec-websocket-version") != Some("13") {
            self.respond(
                Response::text(426, "unsupported WebSocket version")
                    .header("Sec-WebSocket-Version", "13"),
            );
            return false;
        }
        let Some(key) = h.get("sec-websocket-key").filter(|k| akio_ws::valid_key(k)) else {
            self.text(400, "bad Sec-WebSocket-Key");
            return false;
        };
        if let (Some(allowed), Some(origin)) = (opts.origin_allowed, h.get("origin")) {
            if !allowed(origin) {
                self.text(403, "origin not allowed");
                return false;
            }
        }
        let mut resp = Response::new(101)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Accept", akio_ws::accept_key(key));
        if let Some(p) =
            akio_ws::select_subprotocol(h.get_all("sec-websocket-protocol"), &opts.protocols)
        {
            resp = resp.header("Sec-WebSocket-Protocol", p);
        }
        let mut pmd = None;
        if opts.config.permessage_deflate {
            if let Some((params, header)) =
                akio_ws::deflate::negotiate(h.get_all("sec-websocket-extensions"))
            {
                resp = resp.header("Sec-WebSocket-Extensions", header);
                pmd = Some(params);
            }
        }
        // The connection continues as WebSocket whatever the request said about keep-alive.
        if let Some(Out::H1(r)) = self.responder.as_mut() {
            r.keep_alive = true;
        }
        self.respond(resp);
        self.upgrade = Some(PendingUpgrade {
            handler: Box::new(handler),
            cfg: opts.config.clone(),
            pmd,
            ext: None,
        });
        true
    }

    /// [`upgrade_websocket`](Self::upgrade_websocket) on HTTP/2 or a transport outside this
    /// crate (HTTP/3): an extended CONNECT answered `200` with the head only, the stream left
    /// open.
    fn upgrade_websocket_connect(&mut self, handler: Box<dyn WsHandler>, opts: &WsOptions) -> bool {
        let r = self.req.share();
        let h = &r.headers;
        if r.method != Method::Connect || r.protocol.as_deref() != Some("websocket") {
            self.text(
                400,
                if matches!(self.responder, Some(Out::H2(_))) {
                    "WebSocket over HTTP/2 needs an extended CONNECT (RFC 8441)"
                } else {
                    "WebSocket over HTTP/3 needs an extended CONNECT (RFC 9220)"
                },
            );
            return false;
        }
        if h.get("sec-websocket-version") != Some("13") {
            self.respond(
                Response::text(426, "unsupported WebSocket version")
                    .header("Sec-WebSocket-Version", "13"),
            );
            return false;
        }
        if let (Some(allowed), Some(origin)) = (opts.origin_allowed, h.get("origin")) {
            if !allowed(origin) {
                self.text(403, "origin not allowed");
                return false;
            }
        }
        let mut headers = Headers::new();
        if let Some(p) =
            akio_ws::select_subprotocol(h.get_all("sec-websocket-protocol"), &opts.protocols)
        {
            headers.append("sec-websocket-protocol", p);
        }
        let mut pmd = None;
        if opts.config.permessage_deflate {
            if let Some((params, header)) =
                akio_ws::deflate::negotiate(h.get_all("sec-websocket-extensions"))
            {
                headers.append("sec-websocket-extensions", header);
                pmd = Some(params);
            }
        }
        // The head goes out as a streamed response's (no content length, the stream stays
        // open); the transport carries the WebSocket bytes on it from now on.
        let mut resp = Response::new(200);
        resp.headers = headers;
        resp.streaming = true;
        self.fin.apply(&mut resp, &r);
        self.status = Some(200);
        let ext = match self.responder.take() {
            Some(Out::Ext(out)) => match out.start_stream(resp) {
                Some(body) => Some(body),
                None => {
                    // The stream is gone: so is the request.
                    drop(self.end_guard());
                    return false;
                }
            },
            // HTTP/2: the session takes the stream over once the handler returns.
            Some(Out::H2(out)) => {
                if !out.start_tunnel(&resp) {
                    drop(self.end_guard());
                    return false;
                }
                None
            }
            other => {
                self.responder = other;
                return false;
            }
        };
        self.detached = true;
        self.end_guard().sent();
        self.upgrade = Some(PendingUpgrade {
            handler,
            cfg: opts.config.clone(),
            pmd,
            ext,
        });
        true
    }

    /// Hands the connection over to `handler` as a plain byte stream once this request is
    /// dispatched: nothing is sent for the request (the handler writes whatever the protocol
    /// needs, such as `HTTP/1.1 200 Connection Established`). HTTP/1 only; `false` otherwise.
    pub fn upgrade_raw(&mut self, handler: impl crate::raw::RawHandler) -> bool {
        if self.pooled {
            return false;
        }
        match self.responder.take() {
            Some(Out::H1(mut r)) => {
                // The connection is the handler's now: its close is not a client gone early.
                r.forget_gone();
                // Keep the response order: earlier pipelined answers still go out first.
                r.slot.fill(Vec::new());
                self.detached = true;
                self.end_guard().sent();
                self.raw = Some(Box::new(handler));
                true
            }
            other => {
                self.responder = other;
                false
            }
        }
    }

    pub(crate) fn take_raw(&mut self) -> Option<Box<dyn crate::raw::RawHandler>> {
        self.raw.take()
    }

    pub(crate) fn take_upgrade(&mut self) -> Option<PendingUpgrade> {
        self.upgrade.take()
    }

    /// Whether [`detach`](Self::detach) was called.
    pub(crate) fn is_detached(&self) -> bool {
        self.detached
    }

    /// Pauses the request, so that work it waits for (a password checked on the logical pool,
    /// a call to an authorization server) runs after [`Service::call`] returns, and the request
    /// then goes on where it stopped: [`Suspended::resume`] runs a closure with the request's
    /// context, from any thread, as `call` would have gone on (the next middleware, the
    /// handler), and answers `500` if it neither responded nor detached. Responses to
    /// pipelined HTTP/1.1 requests still go out in request order. For the work itself on the
    /// pool, see [`suspend_to_pool`](Self::suspend_to_pool) (ADR-109).
    ///
    /// The context the server keeps reads as detached once `call` returns. `None` (nothing
    /// changed) when the response was sent or taken, the request was upgraded, or its body is
    /// streamed ([`BodyMode::Stream`]): the server feeds such a body to this context after
    /// `call`, so it cannot move. A service that wants to suspend a request with a body asks
    /// for it whole in [`Service::body_mode`].
    ///
    /// A resumed context may be suspended again (a second check). It cannot take the connection over
    /// ([`upgrade_websocket`](Self::upgrade_websocket), [`upgrade_raw`](Self::upgrade_raw)), as
    /// one run on the pool cannot.
    pub fn suspend(&mut self) -> Option<Suspended> {
        if self.streamed || self.upgrade.is_some() || self.raw.is_some() || self.detached {
            return None;
        }
        let responder = self.responder.take()?;
        self.detached = true;
        // The request moves whole, so the resumed context can change it (`req_mut`); the one the
        // server keeps reads as detached and is not asked for it again.
        let req = std::mem::replace(&mut self.req, ReqCell::Own(Request::new(Method::Get, "")));
        let ctx = Context {
            req,
            params: std::mem::take(&mut self.params),
            locals: std::mem::take(&mut self.locals),
            fin: std::mem::replace(&mut self.fin, Finish::new()),
            responder: Some(responder),
            status: self.status,
            detached: false,
            pooled: true,
            upgrade: None,
            raw: None,
            sink: None,
            route: self.route,
            streamed: false,
            reads: None,
            hooks: self.hooks.take(),
        };
        Some(Suspended(Some(Box::new(ctx))))
    }

    /// Suspends the request ([`suspend`](Self::suspend)) and runs `work` with it on the
    /// engine's logical pool, which resumes it when done. `false` when it cannot be suspended
    /// (nothing changed then, and the caller still has the request), or when the pool has no
    /// room: the request is answered `503` (`Retry-After: 1`) then, as
    /// [`detach_to_pool`](Self::detach_to_pool) answers it.
    pub fn suspend_to_pool(&mut self, work: impl FnOnce(Suspended) + Send + 'static) -> bool {
        let Some(exec) = self.executor() else {
            return false;
        };
        let Some(s) = self.suspend() else {
            return false;
        };
        crate::pool::queue_suspended(&exec, s, work)
    }

    /// Marks the context as run on the logical pool.
    pub(crate) fn set_pooled(&mut self) {
        self.pooled = true;
    }

    /// The pool handle of the connection the response goes to.
    pub(crate) fn out_executor(&self) -> Option<crate::pool::Executor> {
        use crate::pool::Executor;
        match self.responder.as_ref()? {
            Out::H1(r) => r.slot.conn().cloned().map(Executor::conn),
            Out::H2(r) => r.conn().map(Executor::conn),
            Out::Ext(e) => Some(Executor::ext(e.0.clone())),
        }
    }
}

/// Holds the reads of a streamed request body; see [`Context::body_reads`]. Cheap to clone and
/// usable from any thread.
#[derive(Clone)]
pub struct BodyReads(ReadsInner);

#[derive(Clone)]
enum ReadsInner {
    H1(Arc<H1Reads>),
    H2(crate::h2::H2Reads),
    Ext(crate::transport::SharedSink, u64),
}

impl std::fmt::Debug for BodyReads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyReads").finish_non_exhaustive()
    }
}

impl BodyReads {
    /// Stops (`true`) or resumes (`false`) taking the body from the client.
    ///
    /// - HTTP/1.1 holds the connection's reads, and so the pipelined requests behind this one,
    ///   as it must. Bytes already read are still delivered (at most one read's worth), and the
    ///   body's timeout (`HttpConfig::body_timeout`) does not fire while reads are held. The
    ///   hold ends with the body.
    /// - HTTP/2 stops giving the stream's flow-control window back, so the client stops once
    ///   the window it has is used (`H2Config`'s initial window); the other streams go on.
    /// - HTTP/3 holds the stream as the transport allows ([`ConnSink::hold_reads`]).
    ///
    /// [`ConnSink::hold_reads`]: crate::transport::ConnSink::hold_reads
    pub fn hold(&self, hold: bool) {
        match &self.0 {
            ReadsInner::H1(r) => r.hold(hold),
            ReadsInner::H2(r) => r.hold(hold),
            ReadsInner::Ext(s, tag) => s.get().hold_reads(*tag, hold),
        }
    }
}

/// HTTP/1: a request body's hold on its connection's reads.
pub(crate) struct H1Reads {
    conn: Arc<akio_core::ConnInner>,
    /// Held; the body ended (no more holding).
    st: Mutex<(bool, bool)>,
}

fn lock_reads(m: &Mutex<(bool, bool)>) -> std::sync::MutexGuard<'_, (bool, bool)> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl H1Reads {
    fn hold(&self, hold: bool) {
        let mut st = lock_reads(&self.st);
        if st.1 || st.0 == hold {
            return;
        }
        st.0 = hold;
        self.conn.hold_reads(hold);
    }

    fn end(&self) {
        let mut st = lock_reads(&self.st);
        st.1 = true;
        if std::mem::replace(&mut st.0, false) {
            self.conn.hold_reads(false);
        }
    }
}

/// A request paused by [`Context::suspend`], to go on later from any thread with
/// [`resume`](Self::resume). Dropping it unresumed answers the request `500`.
pub struct Suspended(Option<Box<Context>>);

impl std::fmt::Debug for Suspended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Suspended").finish_non_exhaustive()
    }
}

impl Suspended {
    /// The request.
    pub fn req(&self) -> &Request {
        // Always set until resumed or dropped, which take `self`.
        match &self.0 {
            Some(ctx) => ctx.req(),
            None => &EMPTY_REQUEST,
        }
    }

    /// Goes on with the request: runs `f` with its context on this thread, then answers `500`
    /// if `f` neither responded nor detached it.
    pub fn resume(mut self, f: impl FnOnce(&mut Context)) {
        if let Some(mut ctx) = self.0.take() {
            f(&mut ctx);
            finish_suspended(&mut ctx);
        }
    }
}

impl Drop for Suspended {
    fn drop(&mut self) {
        if let Some(mut ctx) = self.0.take() {
            finish_suspended(&mut ctx);
        }
    }
}

fn finish_suspended(ctx: &mut Context) {
    if !ctx.responded() && !ctx.detached {
        ctx.respond(Response::text(500, "handler did not respond"));
    }
}

/// What [`Suspended::req`] gives in a state it cannot be seen in.
static EMPTY_REQUEST: std::sync::LazyLock<Request> =
    std::sync::LazyLock::new(|| Request::new(Method::Get, ""));

/// A request whose response will be sent later; see [`Context::detach`]. Dropping it without
/// responding closes the connection.
pub struct Detached {
    /// Ends the request's hooks: when the response goes, or [`End::Gone`] when dropped first.
    end: EndGuard,
    req: Arc<Request>,
    /// Boxed (and only when there are parameters) to keep `Detached` small.
    params: Option<Box<crate::router::Params>>,
    fin: Finish,
    responder: Out,
}

impl std::fmt::Debug for Detached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detached").finish_non_exhaustive()
    }
}

impl Detached {
    /// The request.
    pub fn req(&self) -> &Request {
        &self.req
    }

    /// The request, shared: for work that runs apart from the response (`Files`' disk work,
    /// which a timeout may answer meanwhile).
    pub(crate) fn req_arc(&self) -> Arc<Request> {
        self.req.clone()
    }

    /// A route parameter, percent-decoded (see [`Context::param`]).
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.as_ref()?.get(name, self.req.path())
    }

    /// A route parameter as sent (see [`Context::param_raw`]).
    pub fn param_raw(&self, name: &str) -> Option<&str> {
        self.params.as_ref()?.raw(name, self.req.path())
    }

    /// Calls `f` once if the client goes before the response is finished, as
    /// [`Context::on_gone`] says; replaces an earlier `f` (one registered on the context too).
    pub fn on_gone(&mut self, f: impl FnOnce() + Send + 'static) {
        self.with_hooks(|h| h.set_gone(Box::new(f)));
    }

    /// Calls `f` once when the request is done with, as [`Context::on_end`] says (ADR-127); with
    /// the hooks registered on the context, in order.
    pub fn on_end(&mut self, f: impl FnOnce(End) + Send + 'static) {
        self.with_hooks(|h| h.add_end(Box::new(f)));
    }

    /// Runs `add` with the request's hooks (the context's, or new ones), then has its
    /// transport tell the client's going.
    fn with_hooks(&mut self, add: impl FnOnce(&Hooks)) {
        let h = self.end.0.get_or_insert_with(Arc::default);
        add(h);
        h.watch(&mut self.responder);
    }

    /// Sends the response. Safe from any thread.
    pub fn respond(mut self, resp: Response) {
        let end = std::mem::take(&mut self.end);
        let mut req = ReqSrc::Arc(&self.req);
        self.responder.send(resp, &mut self.fin, &mut req, end);
    }

    /// Starts a streamed response, as [`Context::stream_response`] does, from any thread.
    pub fn stream_response(mut self, status: u16, headers: Headers) -> Option<BodyStream> {
        let end = std::mem::take(&mut self.end);
        let mut req = ReqSrc::Arc(&self.req);
        start_stream(
            self.responder,
            &mut self.fin,
            &mut req,
            status,
            headers,
            end,
        )
    }
}

fn start_stream(
    out: Out,
    fin: &mut Finish,
    req: &mut ReqSrc<'_>,
    status: u16,
    headers: Headers,
    end: EndGuard,
) -> Option<BodyStream> {
    let mut resp = Response::new(status);
    resp.headers = headers;
    resp.streaming = true;
    // The filters run first: the compress middleware's picks the body's coding.
    let chunked = is_chunked(&out);
    if chunked {
        resp.headers.set("Transfer-Encoding", "chunked");
    }
    if fin.asyncs.is_some() && req.get().method != Method::Connect {
        return send_async(out, resp, fin, req, end, true).1;
    }
    fin.apply(&mut resp, req.get());
    open_stream(out, resp, req.get(), chunked, end)
}

/// A status whose response has no body.
fn bodyless(status: u16) -> bool {
    status < 200 || status == 204 || status == 304
}

/// Sends `resp` through the held heads and body filters registered for it (ADR-128): the
/// ordinary response filters and the extra headers first, then each held head in turn, then the
/// outer filters, then the head goes, and the body through the filters. `streamed`: `resp` is
/// the head of a streamed response, whose stream is returned (the writer's side of the first
/// gate, written before the head goes). A whole response through body filters goes as a streamed
/// one, without `Content-Length`. Returns the status the ordinary filters left.
fn send_async(
    out: Out,
    mut resp: Response,
    fin: &mut Finish,
    req: &mut ReqSrc<'_>,
    end: EndGuard,
    streamed: bool,
) -> (u16, Option<BodyStream>) {
    let mut fin = std::mem::replace(fin, Finish::new());
    let Asyncs { holds, mut filters } = fin.asyncs.take().map(|a| *a).unwrap_or_default();
    let head = req.get().method == Method::Head;
    // A body to filter goes as a stream: the response filters see a streamed head (the
    // compress middleware's picks a stream coding, applied to what the filters let out).
    let converted = !streamed && !filters.is_empty() && !head && !bodyless(resp.status);
    if converted {
        resp.streaming = true;
        resp.headers.remove("Content-Length");
    }
    fin.apply_inner(&mut resp, req.get());
    let status = resp.status;
    if head || bodyless(status) {
        filters.clear();
    }
    let converted = converted && !filters.is_empty();
    if !converted && !streamed {
        // Sent whole: undo the conversion when a filter made the response bodyless.
        resp.streaming = false;
    }
    let mut filters = filters.into_iter();
    let mut front = None;
    let mut writer = None;
    let mut file = None;
    if streamed || converted {
        let gate = Gate::new(filters.next());
        if converted {
            resp.headers.remove("Content-Length");
            file = resp.file.take();
            if file.is_some() {
                writer = Some(BodyStream::gated(&gate));
            } else {
                let trailers = resp.trailers.take().unwrap_or_default();
                gate.preload(std::mem::take(&mut resp.body), trailers);
            }
        }
        if streamed {
            writer = Some(BodyStream::gated(&gate));
        }
        front = Some(gate);
    }
    let going = Going {
        out,
        fin,
        req: req.arc(),
        end,
        holds: holds.into_iter(),
        filters: filters.collect(),
        front,
        file,
        writer: if streamed { None } else { writer.take() },
    };
    going.advance(resp);
    (status, if streamed { writer } else { None })
}

/// A response between its head settling and going (ADR-128).
struct Going {
    out: Out,
    /// What is left of the finish: the outer filters and the time header.
    fin: Finish,
    req: Arc<Request>,
    end: EndGuard,
    /// The held heads still to go through.
    holds: std::vec::IntoIter<(Duration, HoldHook)>,
    /// The body filters after the first (which is the front gate's).
    filters: Vec<Box<dyn BodyFilter>>,
    /// The gate the body is written to, for a streamed (or converted) response.
    front: Option<Arc<Gate>>,
    /// A whole response's file body, read into `writer` once the head went.
    file: Option<crate::message::FileBody>,
    writer: Option<BodyStream>,
}

/// Past this, a held head has no deadline (an `Instant` that far would overflow).
const HOLD_FOREVER: Duration = Duration::from_secs(100 * 365 * 24 * 3600);

impl Going {
    /// Goes through the next held head, or sends the head.
    fn advance(mut self, resp: Response) {
        let Some((timeout, hook)) = self.holds.next() else {
            return self.go(resp);
        };
        let req = self.req.clone();
        let cell = Arc::new(Mutex::new(Some(self)));
        if timeout < HOLD_FOREVER {
            let w = Arc::downgrade(&cell);
            crate::timer::after(timeout, move || {
                if let Some(c) = w.upgrade() {
                    let g = c.lock().unwrap_or_else(PoisonError::into_inner).take();
                    drop(c);
                    if let Some(g) = g {
                        g.cut();
                    }
                }
            });
        }
        hook(
            HeldHead {
                resp: Some(resp),
                cell: Some(cell),
            },
            &req,
        );
    }

    /// The head goes, after the outer filters; then the body, through the filters.
    fn go(mut self, mut resp: Response) {
        let req = self.req.clone();
        self.fin.apply(&mut resp, &req);
        let Some(front) = self.front.take() else {
            self.out.deliver(resp, &req, self.end);
            return;
        };
        if front.failed() {
            // The handler gave the stream up, or wrote past the bound, while the head was held.
            return self.out.cut();
        }
        resp.streaming = true;
        resp.body = Vec::new();
        let chunked = is_chunked(&self.out);
        if chunked {
            resp.headers.set("Transfer-Encoding", "chunked");
        }
        let Some(mut s) = open_stream(self.out, resp, &req, chunked, self.end) else {
            front.fail();
            return;
        };
        for f in self.filters.into_iter().rev() {
            s = BodyStream::gated(&Gate::opened(f, s));
        }
        front.open(s);
        if let (Some(file), Some(stream)) = (self.file.take(), self.writer.take()) {
            if req.method == Method::Head || file.len == 0 {
                stream.finish();
                return;
            }
            FilePump {
                stream,
                file: file.file,
                offset: file.offset,
                left: file.len,
                refused: 0,
            }
            .submit();
        }
    }

    /// Cuts the response: its connection closed or stream reset, its request ended
    /// [`End::Gone`].
    fn cut(self) {
        if let Some(f) = &self.front {
            f.fail();
        }
        self.out.cut();
    }

    /// Sends `resp` in place of the held response, whole, after the outer filters.
    fn replace(mut self, mut resp: Response) {
        if let Some(f) = self.front.take() {
            f.fail();
        }
        let req = self.req.clone();
        self.fin.apply(&mut resp, &req);
        self.out.deliver(resp, &req, self.end);
    }
}

/// A response's head held back while work elsewhere decides on it
/// ([`Context::hold_response_head`], ADR-128): a WebAssembly plugin's
/// `proxy_on_response_headers` on its pool, say. Change its fields, then
/// [`resume`](Self::resume) it, from any thread; [`respond`](Self::respond) replaces the
/// response, [`fail`](Self::fail) cuts it. Dropped unresumed, it fails the response.
pub struct HeldHead {
    /// Always set until resumed, replaced or failed.
    resp: Option<Response>,
    /// The rest of the response; taken by whichever comes first of the hook's answer and the
    /// deadline.
    cell: Option<Arc<Mutex<Option<Going>>>>,
}

impl std::fmt::Debug for HeldHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldHead")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl HeldHead {
    /// The response's status.
    pub fn status(&self) -> u16 {
        self.resp.as_ref().map_or(0, |r| r.status)
    }

    /// The response's header fields.
    pub fn headers(&self) -> &Headers {
        static NONE: std::sync::LazyLock<Headers> = std::sync::LazyLock::new(Headers::new);
        self.resp.as_ref().map_or(&NONE, |r| &r.headers)
    }

    /// The response's header fields, to change. The framing is the server's: a changed
    /// `Content-Length` or `Transfer-Encoding` is the caller's to keep true.
    pub fn headers_mut(&mut self) -> &mut Headers {
        let r = self.resp.get_or_insert_with(|| Response::new(500));
        &mut r.headers
    }

    /// The body of a response sent whole, as the response filters left it; `None` when it is
    /// streamed, a file, or goes through body filters ([`Context::add_body_filter`]), which see it.
    pub fn body(&self) -> Option<&[u8]> {
        let r = self.resp.as_ref()?;
        (!r.streaming && r.file.is_none()).then_some(r.body.as_slice())
    }

    /// Whether the response is still to go: `false` once the deadline cut it.
    pub fn is_live(&self) -> bool {
        self.cell
            .as_ref()
            .is_some_and(|c| c.lock().unwrap_or_else(PoisonError::into_inner).is_some())
    }

    fn take(&mut self) -> Option<(Going, Response)> {
        let cell = self.cell.take()?;
        let g = cell.lock().unwrap_or_else(PoisonError::into_inner).take()?;
        Some((g, self.resp.take()?))
    }

    /// Lets the response go on, its head as changed: through the next held head, or to the
    /// client, its body through the body filters. Nothing once the deadline cut it.
    pub fn resume(mut self) {
        if let Some((g, resp)) = self.take() {
            g.advance(resp);
        }
    }

    /// Sends `resp` in place of the held response, whole, after the outer response filters
    /// (and through no held head or body filter): a plugin's local response. What the handler
    /// writes to a streamed response's body meanwhile fails. Nothing once the deadline cut it.
    pub fn respond(mut self, resp: Response) {
        if let Some((g, _)) = self.take() {
            g.replace(resp);
        }
    }

    /// Fails the response: its HTTP/1 connection is closed, its HTTP/2 or HTTP/3 stream reset,
    /// and the request ends [`End::Gone`].
    pub fn fail(mut self) {
        if let Some((g, _)) = self.take() {
            g.cut();
        }
    }
}

impl Drop for HeldHead {
    fn drop(&mut self) {
        if let Some((g, _)) = self.take() {
            g.cut();
        }
    }
}

/// A streamed body to `out` is chunked: keep-alive HTTP/1.1.
fn is_chunked(out: &Out) -> bool {
    matches!(out, Out::H1(r) if r.version == Version::Http11 && r.keep_alive)
}

/// [`start_stream`] once the filters ran: the stream of `resp`, a streamed head.
fn open_stream(
    out: Out,
    mut resp: Response,
    req: &Request,
    chunked: bool,
    end: EndGuard,
) -> Option<BodyStream> {
    // A HEAD answer has the coding's headers and no body to encode.
    let coder = resp
        .stream_coding
        .take()
        .filter(|_| req.method != Method::Head)
        .map(|c| Box::new(Mutex::new(StreamEncoder::new(c))));
    // Kept by the stream until it ends (`Response::keep_until_sent`).
    let kept = resp.take_kept();
    // A HEAD answer sends no body to see. A stream that does not start drops the tap, which
    // tells it the body was cut.
    let tap = resp
        .tap
        .take()
        .filter(|_| req.method != Method::Head)
        .and_then(|t| t.take())
        .map(Box::new);
    let inner = match out {
        Out::H1(r) => {
            let mut head = Vec::with_capacity(192);
            resp.encode(r.version, r.keep_alive, r.head_only, &mut head);
            Inner::H1 {
                conn: r.slot.conn().cloned(),
                gone: r.gone,
                stream: r.slot.stream(head),
                chunked,
                keep_alive: r.keep_alive,
                head_only: r.head_only,
            }
        }
        Out::H2(r) => Inner::H2(r.start_stream(resp)?),
        Out::Ext(r) => Inner::Ext(r.start_stream(resp)?),
    };
    Some(BodyStream {
        inner,
        coder,
        tap,
        kept,
        end,
    })
}

/// A response body being written in pieces; see [`Context::stream_response`].
pub struct BodyStream {
    inner: Inner,
    /// The content coding's encoder (ADR-074); the lock also keeps concurrent writes in the
    /// order they are encoded.
    coder: Option<Box<Mutex<StreamEncoder>>>,
    /// What sees the body as it is sent (ADR-116).
    tap: Option<Box<crate::tap::StreamTap>>,
    /// What a response filter kept until the body is sent (ADR-112), dropped with the stream.
    #[allow(dead_code, reason = "kept for its drop")]
    kept: Option<Arc<crate::message::Kept>>,
    /// Ends the request's hooks once finished, [`End::Gone`] when dropped unfinished.
    end: EndGuard,
}

impl std::fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyStream").finish_non_exhaustive()
    }
}

enum Inner {
    H1 {
        /// For [`BodyStream::on_drain`].
        conn: Option<Arc<akio_core::ConnInner>>,
        /// [`Context::on_gone`]'s callback is registered (under the response's number),
        /// forgotten when finished.
        gone: bool,
        stream: ResponseStream,
        chunked: bool,
        keep_alive: bool,
        head_only: bool,
    },
    H2(H2Stream),
    Ext(Box<dyn crate::transport::BodySink>),
    /// Through held heads and body filters (ADR-128) to the response's own stream.
    Gate(GateHandle),
}

impl BodyStream {
    /// The writer's side of `gate`.
    fn gated(gate: &Arc<Gate>) -> BodyStream {
        BodyStream {
            inner: Inner::Gate(GateHandle(Some(gate.clone()))),
            coder: None,
            tap: None,
            kept: None,
            end: EndGuard::default(),
        }
    }

    /// Appends body bytes. `Err` means the connection is gone or too far behind: stop producing.
    ///
    /// When the response is compressed, the bytes are encoded and the encoder flushed, so that
    /// the client can decode everything written so far: each write goes out as it is made.
    pub fn write(&self, data: &[u8]) -> akio_core::Result<()> {
        match &self.coder {
            None => self.send(data),
            Some(_) if data.is_empty() => Ok(()),
            Some(c) => {
                let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
                self.send(c.encode(data, false))
            }
        }
    }

    /// Writes `data`, as encoded, to the transport, and shows it to the tap.
    fn send(&self, data: &[u8]) -> akio_core::Result<()> {
        let r = self.inner.write(data);
        if let Some(t) = &self.tap {
            t.wrote(data, r.is_ok());
        }
        r
    }

    /// The encoder's last output, written before the stream ends.
    fn end_coding(&mut self) {
        if let Some(c) = self.coder.take() {
            let mut c = c.into_inner().unwrap_or_else(PoisonError::into_inner);
            let _ = self.send(c.encode(&[], true));
        }
    }

    /// Tells the tap how the body ended.
    fn end_tap(&mut self, end: crate::TapEnd) {
        if let Some(t) = self.tap.take() {
            t.end(end);
        }
    }

    /// Gives the body up unfinished: as dropping it, and on HTTP/3 the stream reset (ADR-128).
    pub(crate) fn cut(self) {
        if let Inner::Ext(s) = self.inner {
            s.reset();
        }
    }

    /// Bytes written but not yet on the wire, for pacing the producer.
    pub fn queued_bytes(&self) -> usize {
        match &self.inner {
            Inner::H1 { stream, .. } => stream.queued_bytes(),
            Inner::H2(s) => s.queued_bytes(),
            Inner::Ext(s) => s.queued_bytes(),
            Inner::Gate(g) => g.gate().map_or(0, |g| g.queued_bytes()),
        }
    }

    /// Calls `f` once [`queued_bytes`](Self::queued_bytes) is down to nothing (ADR-101), or
    /// when the connection (or stream) is gone, to resume a producer paused while the client
    /// was behind. Runs `f` at once, on this thread, when nothing is queued; otherwise on the
    /// connection's I/O thread. Replaces an earlier waiter.
    ///
    /// - HTTP/1.1: the connection's send queue is empty (one waiter per connection, as
    ///   `akio_core::Conn::on_drain`).
    /// - HTTP/2: the stream's queued bytes were all framed, as its flow-control window allowed.
    /// - HTTP/3: as the transport says ([`BodySink::on_drain`]).
    ///
    /// [`BodySink::on_drain`]: crate::transport::BodySink::on_drain
    pub fn on_drain(&self, f: impl FnOnce() + Send + 'static) {
        match &self.inner {
            Inner::H1 { conn: Some(c), .. } => c.on_drain(Box::new(f)),
            Inner::H1 { conn: None, .. } => f(),
            Inner::H2(s) => s.on_drain(Box::new(f)),
            Inner::Ext(s) => s.on_drain(Box::new(f)),
            Inner::Gate(g) => match g.gate() {
                Some(g) => g.on_drain(Box::new(f)),
                None => f(),
            },
        }
    }

    /// Completes the body (the final chunk) and lets later responses go out.
    pub fn finish(mut self) {
        self.end_coding();
        self.end_tap(crate::TapEnd::Finished);
        self.inner.finish();
        self.end.sent();
    }

    /// Like [`finish`](Self::finish), with trailer fields after the body (HTTP/2 trailers, or
    /// the chunked trailer section on HTTP/1.1).
    pub fn finish_with_trailers(mut self, trailers: Headers) {
        self.end_coding();
        self.end_tap(crate::TapEnd::Trailers);
        self.inner.finish_with_trailers(trailers);
        self.end.sent();
    }
}

impl Inner {
    fn write(&self, data: &[u8]) -> akio_core::Result<()> {
        match self {
            Inner::H1 {
                stream,
                chunked,
                head_only,
                ..
            } => {
                if data.is_empty() || *head_only {
                    return Ok(());
                }
                let mut out = Vec::with_capacity(data.len() + 20);
                if *chunked {
                    push_chunk_size(&mut out, data.len());
                    out.extend_from_slice(data);
                    out.extend_from_slice(b"\r\n");
                } else {
                    out.extend_from_slice(data);
                }
                stream.write(out)
            }
            Inner::H2(s) => s.write(data),
            Inner::Ext(s) => s.write(data),
            Inner::Gate(g) => match g.gate() {
                Some(g) => g.write(data),
                None => Err(akio_core::Error::Closed),
            },
        }
    }

    fn finish(self) {
        match self {
            Inner::H1 {
                conn,
                gone,
                stream,
                chunked,
                keep_alive,
                head_only,
            } => {
                forget_gone(conn.as_ref(), gone, stream.seq());
                if chunked && !head_only {
                    let _ = stream.write(b"0\r\n\r\n".to_vec());
                }
                stream.finish(!keep_alive);
            }
            Inner::H2(s) => s.finish(),
            Inner::Ext(s) => s.finish(None),
            Inner::Gate(g) => g.finish(Headers::new()),
        }
    }

    fn finish_with_trailers(self, trailers: Headers) {
        match self {
            Inner::H1 {
                conn,
                gone,
                stream,
                chunked,
                keep_alive,
                head_only,
            } => {
                forget_gone(conn.as_ref(), gone, stream.seq());
                if chunked && !head_only {
                    let mut t = Vec::with_capacity(64);
                    t.extend_from_slice(b"0\r\n");
                    for (n, v) in trailers.iter() {
                        t.extend_from_slice(n.as_bytes());
                        t.extend_from_slice(b": ");
                        t.extend(v.bytes().filter(|b| *b != b'\r' && *b != b'\n'));
                        t.extend_from_slice(b"\r\n");
                    }
                    t.extend_from_slice(b"\r\n");
                    let _ = stream.write(t);
                }
                stream.finish(!keep_alive);
            }
            Inner::H2(s) => s.finish_with(Some(trailers)),
            Inner::Ext(s) => s.finish(Some(trailers)),
            Inner::Gate(g) => g.finish(trailers),
        }
    }
}

/// The response is finished: the connection's close no longer means the client went early.
fn forget_gone(conn: Option<&Arc<akio_core::ConnInner>>, gone: bool, seq: u64) {
    if let (Some(c), true) = (conn, gone) {
        c.forget_peer_gone(seq);
    }
}

/// Appends a chunk-size line (`<hex>\r\n`) for `n` bytes.
pub(crate) fn push_chunk_size(out: &mut Vec<u8>, n: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digits = ((usize::BITS - n.leading_zeros()).div_ceil(4)).max(1) as usize;
    for i in (0..digits).rev() {
        out.push(HEX[(n >> (i * 4)) & 15]);
    }
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    #[test]
    fn chunk_size_lines() {
        for n in [
            0usize,
            1,
            9,
            10,
            15,
            16,
            255,
            256,
            4096,
            65_535,
            1 << 20,
            usize::MAX,
        ] {
            let mut out = Vec::new();
            super::push_chunk_size(&mut out, n);
            assert_eq!(out, format!("{n:x}\r\n").into_bytes(), "{n}");
        }
    }
}
#[cfg(test)]
#[test]
fn responders_stay_small() {
    // `Context` is boxed per request on HTTP/2: a larger `Out` measurably costs (ADR-025).
    assert_eq!(size_of::<Option<Out>>(), 24);
    assert_eq!(size_of::<ExtOut>(), 16);
}
