//! The per-request [`Context`] and the [`Service`] / [`Middleware`] traits.

use std::{net::SocketAddr, sync::Arc};

use flash_core::ResponseSlot;

use crate::message::{Headers, Method, Request, Response, Version};

/// Application code: handles one request.
///
/// `call` runs on the connection's I/O thread, so it must not block. To do slow work, call
/// [`Context::detach`] and finish the response later, from the logical pool or any thread.
pub trait Service: Send + Sync + 'static {
    /// Handles `ctx`. It must either respond, or detach the context and respond later; if it
    /// does neither, the client gets a 500.
    fn call(&self, ctx: &mut Context);
}

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

impl Responder {
    fn send(self, mut resp: Response, extra: &Headers) -> u16 {
        for (n, v) in extra.iter() {
            if resp.headers.get(n).is_none() {
                resp.headers.append(n, v);
            }
        }
        let status = resp.status;
        let mut out = Vec::with_capacity(160 + resp.body.len());
        resp.encode(self.version, self.keep_alive, self.head_only, &mut out);
        if self.keep_alive {
            self.slot.fill(out);
        } else {
            self.slot.fill_close(out);
        }
        status
    }
}

/// One request being handled, and the means to answer it.
pub struct Context {
    req: Arc<Request>,
    params: Vec<(String, String)>,
    locals: Vec<(String, String)>,
    extra: Headers,
    responder: Option<Responder>,
    status: Option<u16>,
    detached: bool,
}

impl Context {
    pub(crate) fn new(req: Request, slot: ResponseSlot, keep_alive: bool) -> Context {
        let head_only = req.method == Method::Head;
        Context {
            responder: Some(Responder {
                slot,
                version: req.version,
                keep_alive,
                head_only,
            }),
            req: Arc::new(req),
            params: Vec::new(),
            locals: Vec::new(),
            extra: Headers::new(),
            status: None,
            detached: false,
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
        self.extra.set(name, value);
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
            self.status = Some(r.send(resp, &self.extra));
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
            extra: self.extra.clone(),
            responder,
        })
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
    extra: Headers,
    responder: Responder,
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
    pub fn respond(self, resp: Response) {
        self.responder.send(resp, &self.extra);
    }
}
