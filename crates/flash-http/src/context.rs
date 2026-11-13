//! The per-request [`Context`] and the [`Service`] / [`Middleware`] traits.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use flash_core::{Part, ResponseSlot, ResponseStream};

use crate::h2::{H2Responder, H2Stream};
use flash_ws::{WsConfig, WsHandler, deflate::PmdParams};

use crate::message::{Headers, Method, Request, Response, Version};

/// Application code: handles one request.
///
/// `call` runs on the connection's I/O thread, so it must not block. To do slow work, call
/// [`Context::detach`] and finish the response later, from the logical pool or any thread.
pub trait Service: Send + Sync + 'static {
    /// Handles `ctx`. It must either respond, or detach the context and respond later; if it
    /// does neither, the client gets a 500.
    fn call(&self, ctx: &mut Context);

    /// How the request body should be delivered for `req` (whose head is complete and whose body
    /// is not). The default buffers it (within `HttpConfig::max_body_bytes`) before `call`.
    fn body_mode(&self, _req: &Request) -> BodyMode {
        BodyMode::Buffered
    }
}

/// How a request body reaches the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyMode {
    /// Fully received (and size-limited) before `call`; the body is `ctx.body()`.
    Buffered,
    /// `call` runs as soon as the head is parsed; register [`Context::on_body`] to receive the
    /// chunks as they arrive. No size limit applies: the sink decides what to do with the data.
    Stream,
}

/// Marks a service as taking its request body as a stream; see [`BodyMode::Stream`].
pub struct Streaming<S>(pub S);

impl<S: Service> Service for Streaming<S> {
    fn call(&self, ctx: &mut Context) {
        self.0.call(ctx)
    }
    fn body_mode(&self, _req: &Request) -> BodyMode {
        BodyMode::Stream
    }
}

/// A piece of a streamed request body; see [`Context::on_body`].
pub enum BodyEvent<'a> {
    /// More body bytes.
    Chunk(&'a [u8]),
    /// The body is complete; chunked bodies may carry trailer fields.
    End(&'a Headers),
}

type Sink = Box<dyn FnMut(&mut Context, BodyEvent<'_>) + Send>;
type Filter = Box<dyn FnOnce(&mut Response, &Request) + Send>;

impl<F> Service for F
where
    F: Fn(&mut Context) + Send + Sync + 'static,
{
    fn call(&self, ctx: &mut Context) {
        self(ctx)
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
        self(ctx, next)
    }
}

/// Everything the response path needs, shared by [`Context`] and [`Detached`].
struct Responder {
    slot: ResponseSlot,
    version: Version,
    keep_alive: bool,
    head_only: bool,
}

/// Where a response goes: an HTTP/1 ordered slot, or an HTTP/2 stream.
enum Out {
    H1(Responder),
    H2(H2Responder),
}

impl Out {
    fn send(self, mut resp: Response, fin: &mut Finish) -> u16 {
        match self {
            Out::H1(r) => r.send(resp, fin),
            Out::H2(r) => {
                fin.apply(&mut resp);
                let status = resp.status;
                r.send(resp);
                status
            }
        }
    }
}

/// What is applied to a response on its way out.
struct Finish {
    extra: Headers,
    filters: Vec<Filter>,
    started: Instant,
    time_header: Option<String>,
    req: Arc<Request>,
}

impl Finish {
    /// Runs the filters, then adds the extra headers the response did not set.
    fn apply(&mut self, resp: &mut Response) {
        for f in self.filters.drain(..) {
            f(resp, &self.req);
        }
        for (n, v) in self.extra.iter() {
            if resp.headers.get(n).is_none() {
                resp.headers.append(n, v);
            }
        }
        if let Some(h) = &self.time_header {
            resp.headers.set(
                h.clone(),
                format!("{:.3}ms", self.started.elapsed().as_secs_f64() * 1e3),
            );
        }
    }
}

impl Responder {
    fn send(self, mut resp: Response, fin: &mut Finish) -> u16 {
        fin.apply(&mut resp);
        let status = resp.status;
        let mut head = Vec::with_capacity(192 + resp.body.len());
        resp.encode(self.version, self.keep_alive, self.head_only, &mut head);
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

/// One request being handled, and the means to answer it.
pub struct Context {
    req: Arc<Request>,
    params: Vec<(String, String)>,
    locals: Vec<(String, String)>,
    fin: Finish,
    responder: Option<Out>,
    status: Option<u16>,
    detached: bool,
    upgrade: Option<PendingUpgrade>,
    raw: Option<Box<dyn crate::raw::RawHandler>>,
    sink: Option<Sink>,
}

/// A WebSocket upgrade accepted by [`Context::upgrade_websocket`], applied by the session.
pub(crate) struct PendingUpgrade {
    pub handler: Box<dyn WsHandler>,
    pub cfg: WsConfig,
    pub pmd: Option<PmdParams>,
}

/// Options for [`Context::upgrade_websocket`].
#[derive(Clone, Debug, Default)]
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
        let req = Arc::new(req);
        Context {
            responder: Some(Out::H1(Responder {
                slot,
                version: req.version,
                keep_alive,
                head_only,
            })),
            fin: Finish {
                extra: Headers::new(),
                filters: Vec::new(),
                started: Instant::now(),
                time_header: None,
                req: req.clone(),
            },
            req,
            params: Vec::new(),
            locals: Vec::new(),
            status: None,
            detached: false,
            upgrade: None,
            raw: None,
            sink: None,
        }
    }

    /// A context for a request on an HTTP/2 stream.
    pub(crate) fn new_h2(req: Request, responder: H2Responder) -> Context {
        let req = Arc::new(req);
        Context {
            fin: Finish {
                extra: Headers::new(),
                filters: Vec::new(),
                started: Instant::now(),
                time_header: None,
                req: req.clone(),
            },
            req,
            params: Vec::new(),
            locals: Vec::new(),
            status: None,
            detached: false,
            upgrade: None,
            raw: None,
            sink: None,
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

    /// The peer address.
    pub fn peer(&self) -> SocketAddr {
        self.req.peer
    }

    /// A route parameter (`:id` or `*rest`) matched by the router.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn set_params(&mut self, params: Vec<(String, String)>) {
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
    pub fn add_response_header(&mut self, name: &str, value: impl Into<String>) {
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

    /// Adds `header: <elapsed>ms` (time since the request was dispatched) to the response.
    pub fn set_response_time_header(&mut self, header: &str) {
        self.fin.time_header = Some(header.to_owned());
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
            self.status = Some(r.send(resp, &mut self.fin));
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
            req: self.req.clone(),
            params: std::mem::take(&mut self.params),
            fin: Finish {
                extra: std::mem::take(&mut self.fin.extra),
                filters: std::mem::take(&mut self.fin.filters),
                started: self.fin.started,
                time_header: self.fin.time_header.take(),
                req: self.req.clone(),
            },
            responder,
        })
    }

    /// Starts a response whose body is produced piece by piece (server-sent events, large
    /// generated downloads). `headers` are sent with the head; the framing is `chunked` on
    /// keep-alive HTTP/1.1 and close-delimited otherwise. Response filters do not apply.
    /// `None` if a response was already started. Write from any thread; dropping the stream
    /// without [`BodyStream::finish`] closes the connection.
    pub fn stream_response(&mut self, status: u16, headers: Headers) -> Option<BodyStream> {
        let out = self.responder.take()?;
        self.detached = true;
        self.status = Some(status);
        start_stream(out, &mut self.fin, status, headers)
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
    /// Validates the handshake (`GET`, HTTP/1.1, `Upgrade`/`Connection` tokens, version 13, a
    /// well-formed key, the origin policy), answers `101 Switching Protocols` and switches the
    /// connection to WebSocket; the handler's `on_open` runs right away. Returns `false` after
    /// answering a bad handshake itself (400, 403 or 426), in which case the connection stays
    /// HTTP. Do not pipeline requests behind an upgrade request.
    pub fn upgrade_websocket(&mut self, handler: impl WsHandler, opts: &WsOptions) -> bool {
        if self.responder.is_none() {
            return false;
        }
        let r = self.req.clone();
        let h = &r.headers;
        if r.method != Method::Get || r.version != Version::Http11 {
            self.text(400, "WebSocket upgrade needs GET over HTTP/1.1");
            return false;
        }
        if matches!(self.responder, Some(Out::H2(_))) {
            self.text(400, "WebSocket over HTTP/2 is not supported");
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
        let Some(key) = h
            .get("sec-websocket-key")
            .filter(|k| flash_ws::valid_key(k))
        else {
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
            .header("Sec-WebSocket-Accept", flash_ws::accept_key(key));
        if let Some(p) =
            flash_ws::select_subprotocol(h.get_all("sec-websocket-protocol"), &opts.protocols)
        {
            resp = resp.header("Sec-WebSocket-Protocol", p);
        }
        let mut pmd = None;
        if opts.config.permessage_deflate {
            if let Some((params, header)) =
                flash_ws::deflate::negotiate(h.get_all("sec-websocket-extensions"))
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
        });
        true
    }

    /// Hands the connection over to `handler` as a plain byte stream once this request is
    /// dispatched: nothing is sent for the request (the handler writes whatever the protocol
    /// needs, such as `HTTP/1.1 200 Connection Established`). HTTP/1 only; `false` otherwise.
    pub fn upgrade_raw(&mut self, handler: impl crate::raw::RawHandler) -> bool {
        match self.responder.take() {
            Some(Out::H1(r)) => {
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
}

/// A request whose response will be sent later; see [`Context::detach`]. Dropping it without
/// responding closes the connection.
pub struct Detached {
    req: Arc<Request>,
    params: Vec<(String, String)>,
    fin: Finish,
    responder: Out,
}

impl Detached {
    /// The request.
    pub fn req(&self) -> &Request {
        &self.req
    }

    /// A route parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Sends the response. Safe from any thread.
    pub fn respond(mut self, resp: Response) {
        self.responder.send(resp, &mut self.fin);
    }

    /// Starts a streamed response, as [`Context::stream_response`] does, from any thread.
    pub fn stream_response(mut self, status: u16, headers: Headers) -> Option<BodyStream> {
        start_stream(self.responder, &mut self.fin, status, headers)
    }
}

fn start_stream(out: Out, fin: &mut Finish, status: u16, headers: Headers) -> Option<BodyStream> {
    let mut resp = Response::new(status);
    resp.headers = headers;
    resp.streaming = true;
    match out {
        Out::H1(r) => {
            let chunked = r.version == Version::Http11 && r.keep_alive;
            if chunked {
                resp.headers.set("Transfer-Encoding", "chunked");
            }
            fin.apply(&mut resp);
            let mut head = Vec::with_capacity(192);
            resp.encode(r.version, r.keep_alive, r.head_only, &mut head);
            Some(BodyStream(Inner::H1 {
                stream: r.slot.stream(head),
                chunked,
                keep_alive: r.keep_alive,
                head_only: r.head_only,
            }))
        }
        Out::H2(r) => {
            fin.apply(&mut resp);
            r.start_stream(resp).map(|s| BodyStream(Inner::H2(s)))
        }
    }
}

/// A response body being written in pieces; see [`Context::stream_response`].
pub struct BodyStream(Inner);

enum Inner {
    H1 {
        stream: ResponseStream,
        chunked: bool,
        keep_alive: bool,
        head_only: bool,
    },
    H2(H2Stream),
}

impl BodyStream {
    /// Appends body bytes. `Err` means the connection is gone or too far behind: stop producing.
    pub fn write(&self, data: &[u8]) -> flash_core::Result<()> {
        match &self.0 {
            Inner::H1 {
                stream,
                chunked,
                head_only,
                ..
            } => {
                if data.is_empty() || *head_only {
                    return Ok(());
                }
                let mut out = Vec::with_capacity(data.len() + 16);
                if *chunked {
                    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
                    out.extend_from_slice(data);
                    out.extend_from_slice(b"\r\n");
                } else {
                    out.extend_from_slice(data);
                }
                stream.write(out)
            }
            Inner::H2(s) => s.write(data),
        }
    }

    /// Bytes written but not yet on the wire, for pacing the producer.
    pub fn queued_bytes(&self) -> usize {
        match &self.0 {
            Inner::H1 { stream, .. } => stream.queued_bytes(),
            Inner::H2(s) => s.queued_bytes(),
        }
    }

    /// Completes the body (the final chunk) and lets later responses go out.
    pub fn finish(self) {
        match self.0 {
            Inner::H1 {
                stream,
                chunked,
                keep_alive,
                head_only,
            } => {
                if chunked && !head_only {
                    let _ = stream.write(b"0\r\n\r\n".to_vec());
                }
                stream.finish(!keep_alive);
            }
            Inner::H2(s) => s.finish(),
        }
    }

    /// Like [`finish`](Self::finish), with trailer fields after the body (HTTP/2 trailers, or
    /// the chunked trailer section on HTTP/1.1).
    pub fn finish_with_trailers(self, trailers: Headers) {
        match self.0 {
            Inner::H1 {
                stream,
                chunked,
                keep_alive,
                head_only,
            } => {
                if chunked && !head_only {
                    let mut t = b"0\r\n".to_vec();
                    for (n, v) in trailers.iter() {
                        t.extend_from_slice(
                            format!("{n}: {}\r\n", v.replace(['\r', '\n'], "")).as_bytes(),
                        );
                    }
                    t.extend_from_slice(b"\r\n");
                    let _ = stream.write(t);
                }
                stream.finish(!keep_alive);
            }
            Inner::H2(s) => s.finish_with(Some(trailers)),
        }
    }
}
