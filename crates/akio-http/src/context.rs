//! The per-request [`Context`] and the [`Service`] / [`Middleware`] traits.

use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use akio_core::{Part, ResponseSlot, ResponseStream};

use crate::h2::{H2Responder, H2Stream};
use akio_ws::{WsConfig, WsHandler, deflate::PmdParams};

use crate::coding::StreamEncoder;
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
    fn on_gone(&mut self, f: Box<dyn FnOnce() + Send>) {
        match self {
            Out::H1(r) => r.set_gone(f),
            Out::H2(r) => r.on_gone(f),
            Out::Ext(e) => e.0.get().on_gone(e.1, f),
        }
    }

    fn send(self, mut resp: Response, fin: &mut Finish, req: &Request) -> u16 {
        match self {
            Out::H1(r) => r.send(resp, fin, req),
            Out::H2(r) => {
                fin.apply(&mut resp, req);
                let status = resp.status;
                r.send(resp);
                status
            }
            Out::Ext(r) => {
                fin.apply(&mut resp, req);
                let status = resp.status;
                r.send(resp);
                status
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
}

impl Finish {
    fn new() -> Finish {
        Finish {
            extra: Headers::new(),
            filters: Filters::default(),
            started: None,
            time_header: None,
            span: Span::none(),
        }
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

    fn send(mut self, mut resp: Response, fin: &mut Finish, req: &Request) -> u16 {
        self.forget_gone();
        fin.apply(&mut resp, req);
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
        status
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
            responder: Some(Out::H2(responder)),
        }
    }

    /// The request.
    pub fn req(&self) -> &Request {
        &self.req
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
        if let Some(out) = self.responder.as_mut() {
            out.on_gone(Box::new(f));
        }
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
            self.status = Some(r.send(resp, &mut self.fin, &self.req));
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
            req: self.req.share(),
            params: std::mem::take(&mut self.params).boxed(),
            fin: Finish {
                extra: std::mem::take(&mut self.fin.extra),
                filters: std::mem::take(&mut self.fin.filters),
                started: self.fin.started,
                time_header: self.fin.time_header.take(),
                span: std::mem::take(&mut self.fin.span),
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
    pub fn after(
        &mut self,
        delay: std::time::Duration,
        f: impl FnOnce(Detached) + Send + 'static,
    ) -> bool {
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
        start_stream(out, &mut self.fin, &self.req, status, headers)
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
                None => return false,
            },
            // HTTP/2: the session takes the stream over once the handler returns.
            Some(Out::H2(out)) => {
                if !out.start_tunnel(&resp) {
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
        let ctx = Context {
            req: ReqCell::Shared(self.req.share()),
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
        self.responder.on_gone(Box::new(f));
    }

    /// Sends the response. Safe from any thread.
    pub fn respond(mut self, resp: Response) {
        self.responder.send(resp, &mut self.fin, &self.req);
    }

    /// Starts a streamed response, as [`Context::stream_response`] does, from any thread.
    pub fn stream_response(mut self, status: u16, headers: Headers) -> Option<BodyStream> {
        start_stream(self.responder, &mut self.fin, &self.req, status, headers)
    }
}

fn start_stream(
    out: Out,
    fin: &mut Finish,
    req: &Request,
    status: u16,
    headers: Headers,
) -> Option<BodyStream> {
    let mut resp = Response::new(status);
    resp.headers = headers;
    resp.streaming = true;
    // The filters run first: the compress middleware's picks the body's coding.
    let chunked = matches!(&out, Out::H1(r) if r.version == Version::Http11 && r.keep_alive);
    if chunked {
        resp.headers.set("Transfer-Encoding", "chunked");
    }
    fin.apply(&mut resp, req);
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
}

impl BodyStream {
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

    /// Bytes written but not yet on the wire, for pacing the producer.
    pub fn queued_bytes(&self) -> usize {
        match &self.inner {
            Inner::H1 { stream, .. } => stream.queued_bytes(),
            Inner::H2(s) => s.queued_bytes(),
            Inner::Ext(s) => s.queued_bytes(),
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
        }
    }

    /// Completes the body (the final chunk) and lets later responses go out.
    pub fn finish(mut self) {
        self.end_coding();
        self.end_tap(crate::TapEnd::Finished);
        self.inner.finish();
    }

    /// Like [`finish`](Self::finish), with trailer fields after the body (HTTP/2 trailers, or
    /// the chunked trailer section on HTTP/1.1).
    pub fn finish_with_trailers(mut self, trailers: Headers) {
        self.end_coding();
        self.end_tap(crate::TapEnd::Trailers);
        self.inner.finish_with_trailers(trailers);
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
