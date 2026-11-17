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
use crate::message::{Headers, Request, Response};

/// Where a connection's responses go: one sink per connection, shared by its requests, each
/// request told apart by a `tag` the transport chooses (a stream id, flags) when it dispatches
/// it with [`dispatch_conn`] or [`start_conn`]. Unlike a boxed [`ResponseSink`] per request,
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
    let mut ctx = Context::new_ext(req, ExtOut::Boxed(sink));
    service.call(&mut ctx);
    finalize(&mut ctx);
}

/// Runs `service` for `req`, answering through the connection's `sink` with `tag` (see
/// [`ConnSink`]). A handler that neither responds nor detaches gets a 500 sent for it. The
/// request body is `req.body` (`Context::on_body` is not called); see [`start_conn`] for a body
/// that arrives later.
///
/// Returns the request's target buffer, emptied, when the handler did not keep the request
/// (it neither detached nor upgraded it): build the connection's next [`Request::target`] in
/// it and that request allocates no target of its own. Otherwise an empty `String` (no
/// capacity).
#[inline(always)]
pub fn dispatch_conn<S: Service + ?Sized>(
    service: &S,
    req: Request,
    sink: Arc<dyn ConnSink>,
    tag: u64,
) -> String {
    let mut ctx = Context::new_ext(req, ExtOut::Conn(sink, tag));
    service.call(&mut ctx);
    finalize(&mut ctx);
    ctx.take_target()
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
    let mut ctx = Box::new(Context::new_ext(req, ExtOut::Boxed(sink)));
    service.call(&mut ctx);
    Started { ctx }
}

/// Runs `service` for `req` whose body has not arrived yet, as [`start`] does, answering
/// through the connection's `sink` with `tag` (see [`ConnSink`]).
pub fn start_conn<S: Service + ?Sized>(
    service: &S,
    req: Request,
    sink: Arc<dyn ConnSink>,
    tag: u64,
) -> Started {
    let mut ctx = Box::new(Context::new_ext(req, ExtOut::Conn(sink, tag)));
    service.call(&mut ctx);
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

    #[test]
    fn conn_sink_answers_by_tag_and_hands_the_target_back() {
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
        let s = || -> Arc<dyn ConnSink> { sink.clone() };

        // Answered right away: the target comes back emptied, with its capacity.
        let t = dispatch_conn(&svc, Request::new(Method::Get, "/a/first"), s(), 7);
        assert!(t.is_empty() && t.capacity() >= "/a/first".len());
        // It serves as the next request's target.
        let mut next = t;
        next.push_str("/a/2");
        let t = dispatch_conn(&svc, Request::new(Method::Get, next), s(), 8);
        assert!(t.capacity() > 0);
        // Detached: the request is kept, nothing comes back; answered later with its tag.
        let t = dispatch_conn(&svc, Request::new(Method::Get, "/later"), s(), 9);
        assert_eq!(t.capacity(), 0);
        // No response: a 500 for it, the target back.
        let t = dispatch_conn(&svc, Request::new(Method::Get, "/none"), s(), 10);
        assert!(t.capacity() > 0);
        // A target too long to keep is not handed back.
        let long = format!("/a/{}", "z".repeat(crate::context::SPARE_TARGET_MAX));
        let t = dispatch_conn(&svc, Request::new(Method::Get, long), s(), 11);
        assert_eq!(t.capacity(), 0);
        let d = kept.lock().unwrap().pop().unwrap();
        assert_eq!(d.req().target, "/later");
        d.respond(Response::text(202, "late"));

        let got = sink.0.lock().unwrap().clone();
        let got: Vec<(u64, u16, &[u8])> = got.iter().map(|(t, s, b)| (*t, *s, &b[..])).collect();
        assert_eq!(got[0], (7, 200, &b"first"[..]));
        assert_eq!(got[1], (8, 200, &b"2"[..]));
        assert_eq!((got[2].0, got[2].1), (10, 500));
        assert_eq!((got[3].0, got[3].1), (11, 200));
        assert_eq!(got[4], (9, 202, &b"late"[..]));
    }
}
