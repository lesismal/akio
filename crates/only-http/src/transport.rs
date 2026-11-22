//! Serving [`Service`]s over transports that live outside this crate (HTTP/3 in `only-h3`):
//! the transport parses a request, then dispatches it with [`dispatch_conn`] to its
//! connection's [`ConnSink`], which writes the response its own way. Handlers see the same
//! [`Context`] as on HTTP/1 and HTTP/2.
//!
//! The older per-request [`ResponseSink`] ([`dispatch`], [`start`]) still works but costs an
//! allocation per request (ADR-025).

use std::sync::Arc;

use only_ws::{WsLink, WsSession};

use crate::context::{BodyEvent, Context, ExtOut, Service};
use crate::message::{Headers, Request, Response, Spare};

/// Where a connection's responses go: one sink per connection, shared by its requests, each
/// request told apart by a `tag` the transport chooses (a stream id, flags) when it dispatches
/// it with [`dispatch_conn`] or [`start_conn`] (shared through a [`SharedSink`]). Unlike a boxed [`ResponseSink`] per request,
/// nothing is allocated for a request's way back.
///
/// Responses may be sent from any thread (a [`Detached`](crate::Detached) request), hence
/// `Sync`.
pub trait ConnSink: Send + Sync + 'static {
    /// Sends the complete response to the request tagged `tag` (filters and extra headers
    /// already applied).
    fn send(&self, tag: u64, resp: Response);
    /// Sends the head of the response to the request tagged `tag`; its body follows through
    /// the returned sink. `None` if the stream is gone.
    fn start_stream(&self, tag: u64, resp: Response) -> Option<Box<dyn BodySink>>;
}

/// A connection's [`ConnSink`], shared by its requests: cloning it is one reference count
/// increment, and a request holds it in 8 bytes (a thin pointer), which keeps
/// [`Context`] as small as it was with a boxed sink per request.
#[derive(Clone)]
pub struct SharedSink(Arc<Box<dyn ConnSink>>);

impl SharedSink {
    /// Shares `sink` among a connection's requests.
    pub fn new(sink: impl ConnSink) -> SharedSink {
        SharedSink(Arc::new(Box::new(sink)))
    }

    /// The sink.
    #[inline]
    pub fn get(&self) -> &dyn ConnSink {
        &**self.0
    }
}

impl std::fmt::Debug for SharedSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSink").finish_non_exhaustive()
    }
}

/// Where a transport's response goes: one boxed sink per request.
#[deprecated(
    since = "1.0.0-rc.2",
    note = "allocates per request; implement `ConnSink` and use `dispatch_conn` / `start_conn` (ADR-025)"
)]
pub trait ResponseSink: Send + 'static {
    /// Sends a complete response (filters and extra headers already applied).
    fn send(self: Box<Self>, resp: Response);
    /// Sends the head of a response whose body follows through the returned sink; `None` if
    /// the stream is gone.
    fn start_stream(self: Box<Self>, resp: Response) -> Option<Box<dyn BodySink>>;
}

/// The body of a streamed response (see [`Context::stream_response`]).
pub trait BodySink: Send + 'static {
    /// Appends body bytes; `Err` when the stream is gone.
    fn write(&self, data: &[u8]) -> only_core::Result<()>;
    /// Bytes written but not yet on the wire.
    fn queued_bytes(&self) -> usize;
    /// Ends the body, with trailer fields if any.
    fn finish(self: Box<Self>, trailers: Option<Headers>);
}

/// A per-request [`ResponseSink`] served as a [`ConnSink`] (the deprecated path allocates for
/// it; the responder stays one shape for everything else).
#[allow(deprecated)]
struct Boxed(std::sync::Mutex<Option<Box<dyn ResponseSink>>>);

#[allow(deprecated)]
impl Boxed {
    fn new(sink: Box<dyn ResponseSink>) -> Boxed {
        Boxed(std::sync::Mutex::new(Some(sink)))
    }

    fn take(&self) -> Option<Box<dyn ResponseSink>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

#[allow(deprecated)]
impl ConnSink for Boxed {
    fn send(&self, _tag: u64, resp: Response) {
        if let Some(s) = self.take() {
            s.send(resp);
        }
    }

    fn start_stream(&self, _tag: u64, resp: Response) -> Option<Box<dyn BodySink>> {
        self.take()?.start_stream(resp)
    }
}

/// Runs `service` for `req`, answering through `sink`. A handler that neither responds nor
/// detaches gets a 500 sent for it. The request body is `req.body` (`Context::on_body` is not
/// called); see [`start`] for a body that arrives later.
#[deprecated(
    since = "1.0.0-rc.2",
    note = "allocates per request; use `dispatch_conn` (ADR-025)"
)]
#[allow(deprecated)]
#[inline(always)]
pub fn dispatch<S: Service + ?Sized>(service: &S, req: Request, sink: Box<dyn ResponseSink>) {
    let mut ctx = Context::new_ext(req, ExtOut(SharedSink::new(Boxed::new(sink)), 0));
    let g = crate::trace::begin(&mut ctx);
    service.call(&mut ctx);
    drop(g);
    finalize(&mut ctx);
}

/// Runs `service` for `req`, answering through the connection's `sink` with `tag` (see
/// [`ConnSink`]). A handler that neither responds nor detaches gets a 500 sent for it. The
/// request body is `req.body` (`Context::on_body` is not called); see [`start_conn`] for a body
/// that arrives later.
///
/// When the handler did not keep the request (it neither detached nor upgraded it), the
/// request's target buffer and header storage are kept for the next target and headers built
/// with [`request_target`] and [`request_headers`] on this thread.
#[inline(always)]
pub fn dispatch_conn<S: Service + ?Sized>(service: &S, req: Request, sink: &SharedSink, tag: u64) {
    let mut ctx = Context::new_ext(req, ExtOut(sink.clone(), tag));
    let g = crate::trace::begin(&mut ctx);
    service.call(&mut ctx);
    drop(g);
    finalize(&mut ctx);
    ctx.recycle_request();
}

/// A [`Request::target`] for a new request: `target` copied into the buffer of a request this
/// thread finished with earlier (see [`dispatch_conn`]), so it allocates only when there is
/// none or it is too small. HTTP/1.1 and HTTP/2 build their targets the same way.
#[inline]
pub fn request_target(target: &str) -> String {
    crate::context::new_target(target)
}

/// Storage for a new request's [`Request::headers`]: room for `fields` fields of `bytes` bytes
/// of names and values (as [`Headers::with_capacity`]) in the storage of a request this thread
/// finished with earlier (see [`dispatch_conn`]), so it allocates only when there is none or
/// it is too small. HTTP/1.1 and HTTP/2 build their request headers the same way.
#[inline]
pub fn request_headers(fields: usize, bytes: usize) -> Headers {
    Headers::spare(Spare::Req, fields, bytes)
}

/// Hands the headers of a response the transport has finished encoding back to this thread,
/// for the next response built with [`Response::with_body`] (or [`Response::text`]) here, as
/// HTTP/1.1 and HTTP/2 do after writing a response head.
#[inline]
pub fn recycle_response_headers(headers: Headers) {
    headers.recycle(Spare::Resp);
}

#[inline]
fn finalize(ctx: &mut Context) {
    if !ctx.responded() && !ctx.is_detached() {
        ctx.respond(Response::text(500, "handler did not respond"));
    }
}

/// Runs `service` for `req` whose body has not arrived yet (`Service::body_mode` said
/// [`BodyMode::Stream`](crate::BodyMode::Stream), or an extended CONNECT): feed the body to
/// the returned [`Started`] as it arrives, as HTTP/2 does. One boxed sink per request; see
/// [`start_conn`].
#[deprecated(
    since = "1.0.0-rc.2",
    note = "allocates a sink per request; use `start_conn` (ADR-025)"
)]
#[allow(deprecated)]
pub fn start<S: Service + ?Sized>(
    service: &S,
    req: Request,
    sink: Box<dyn ResponseSink>,
) -> Started {
    let mut ctx = Box::new(Context::new_ext(
        req,
        ExtOut(SharedSink::new(Boxed::new(sink)), 0),
    ));
    let g = crate::trace::begin(&mut ctx);
    service.call(&mut ctx);
    drop(g);
    Started { ctx }
}

/// Runs `service` for `req` whose body has not arrived yet, as [`start`] does, answering
/// through the connection's `sink` with `tag` (see [`ConnSink`]).
pub fn start_conn<S: Service + ?Sized>(
    service: &S,
    req: Request,
    sink: &SharedSink,
    tag: u64,
) -> Started {
    let mut ctx = Box::new(Context::new_ext(req, ExtOut(sink.clone(), tag)));
    let g = crate::trace::begin(&mut ctx);
    service.call(&mut ctx);
    drop(g);
    Started { ctx }
}

/// A request dispatched before its body (see [`start_conn`]).
pub struct Started {
    ctx: Box<Context>,
}

impl std::fmt::Debug for Started {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Started").finish_non_exhaustive()
    }
}

impl Started {
    /// More body bytes, for the `Context::on_body` sink.
    pub fn body(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.ctx.deliver(BodyEvent::Chunk(data));
        }
    }

    /// The body is complete (with its trailer fields); a handler that neither responded nor
    /// detached gets a 500 sent for it.
    pub fn end(mut self, trailers: &Headers) {
        self.ctx.deliver(BodyEvent::End(trailers));
        finalize(&mut self.ctx);
    }

    /// The request ended without its body (the stream was reset or the connection lost): the
    /// sink hears nothing more, and nothing is sent.
    pub fn abort(self) {}

    /// The WebSocket the handler accepted with `Context::upgrade_websocket` (RFC 9220), its
    /// `200` already sent: the stream's bytes from now on go to [`WsSession::on_data`], and its
    /// frames go out through `link`.
    pub fn take_websocket(&mut self, link: Arc<dyn WsLink>) -> Option<WsSession> {
        let up = self.ctx.take_upgrade()?;
        // The streamed head's sink is no longer needed: `link` writes to the same stream.
        drop(up.ext);
        Some(WsSession::with_link(link, &up.cfg, up.pmd, up.handler))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::message::Method;
    use crate::{Context, Router};

    /// Records what each tag was answered.
    #[derive(Default)]
    struct Collect(Mutex<Vec<(u64, u16, Vec<u8>)>>);

    impl ConnSink for Collect {
        fn send(&self, tag: u64, resp: Response) {
            self.0.lock().unwrap().push((tag, resp.status, resp.body));
        }
        fn start_stream(&self, _tag: u64, _resp: Response) -> Option<Box<dyn BodySink>> {
            None
        }
    }

    struct ArcSink(Arc<Collect>);

    impl ConnSink for ArcSink {
        fn send(&self, tag: u64, resp: Response) {
            self.0.send(tag, resp);
        }
        fn start_stream(&self, tag: u64, resp: Response) -> Option<Box<dyn BodySink>> {
            self.0.start_stream(tag, resp)
        }
    }

    #[test]
    fn conn_sink_answers_by_tag_and_reuses_targets() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let k = kept.clone();
        let svc = Router::new()
            .get("/a/:x", |ctx: &mut Context| {
                let x = ctx.param("x").unwrap().to_owned();
                ctx.text(200, x);
            })
            .get("/later", move |ctx: &mut Context| {
                k.lock().unwrap().push(ctx.detach().unwrap());
            })
            .get("/none", |_ctx: &mut Context| {});
        let sink = Arc::new(Collect::default());
        let shared = SharedSink::new(ArcSink(sink.clone()));
        let s = || &shared;

        // Answered right away: the target's buffer is kept for the thread's next target.
        let first = String::from("/a/first-and-longer");
        let (ptr, cap) = (first.as_ptr(), first.capacity());
        dispatch_conn(&svc, Request::new(Method::Get, first), s(), 7);
        let next = request_target("/a/2");
        assert_eq!(
            (next.as_ptr(), next.capacity(), next.as_str()),
            (ptr, cap, "/a/2")
        );
        dispatch_conn(&svc, Request::new(Method::Get, next), s(), 8);
        // Detached: the request is kept, its buffer too; answered later with its tag.
        let later = request_target("/later");
        assert_eq!(later.as_ptr(), ptr);
        dispatch_conn(&svc, Request::new(Method::Get, later), s(), 9);
        let t = request_target("/none");
        assert_ne!(t.as_ptr(), ptr);
        // No response: a 500 for it, the buffer kept.
        let p = t.as_ptr();
        dispatch_conn(&svc, Request::new(Method::Get, t), s(), 10);
        let again = request_target("");
        assert_eq!(again.as_ptr(), p);
        drop(again);
        // A target too long to keep is not.
        let long = format!("/a/{}", "z".repeat(crate::context::SPARE_TARGET_MAX));
        let p = long.as_ptr();
        dispatch_conn(&svc, Request::new(Method::Get, long), s(), 11);
        let x = request_target("/x");
        assert_ne!(x.as_ptr(), p);
        let d = kept.lock().unwrap().pop().unwrap();
        assert_eq!(d.req().target, "/later");
        d.respond(Response::text(202, "late"));

        let got = sink.0.lock().unwrap().clone();
        let got: Vec<(u64, u16, &[u8])> = got.iter().map(|(t, s, b)| (*t, *s, &b[..])).collect();
        assert_eq!(got[0], (7, 200, &b"first-and-longer"[..]));
        assert_eq!(got[1], (8, 200, &b"2"[..]));
        assert_eq!((got[2].0, got[2].1), (10, 500));
        assert_eq!((got[3].0, got[3].1), (11, 200));
        assert_eq!(got[4], (9, 202, &b"late"[..]));
    }
}
