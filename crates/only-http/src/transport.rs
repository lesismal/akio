//! Serving [`Service`]s over transports that live outside this crate (HTTP/3 in `only-h3`):
//! the transport parses a request, then [`dispatch`]es it with a [`ResponseSink`] that writes
//! the response its own way. Handlers see the same [`Context`] as on HTTP/1 and HTTP/2.

use std::sync::Arc;

use only_ws::{WsLink, WsSession};

use crate::context::{BodyEvent, Context, Service};
use crate::message::{Headers, Request, Response};

/// Where a transport's response goes.
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
#[inline(always)]
pub fn dispatch<S: Service + ?Sized>(service: &S, req: Request, sink: Box<dyn ResponseSink>) {
    let mut ctx = Context::new_ext(req, sink);
    let g = crate::trace::begin(&mut ctx);
    service.call(&mut ctx);
    drop(g);
    finalize(&mut ctx);
}

#[inline]
fn finalize(ctx: &mut Context) {
    if !ctx.responded() && !ctx.is_detached() {
        ctx.respond(Response::text(500, "handler did not respond"));
    }
}

/// Runs `service` for `req` whose body has not arrived yet (`Service::body_mode` said
/// [`BodyMode::Stream`](crate::BodyMode::Stream), or an extended CONNECT): feed the body to
/// the returned [`Started`] as it arrives, as HTTP/2 does.
pub fn start<S: Service + ?Sized>(
    service: &S,
    req: Request,
    sink: Box<dyn ResponseSink>,
) -> Started {
    let mut ctx = Box::new(Context::new_ext(req, sink));
    let g = crate::trace::begin(&mut ctx);
    service.call(&mut ctx);
    drop(g);
    Started { ctx }
}

/// A request dispatched before its body (see [`start`]).
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
