//! Serving [`Service`]s over transports that live outside this crate (HTTP/3 in `flash-h3`):
//! the transport parses a request, then [`dispatch`]es it with a [`ResponseSink`] that writes
//! the response its own way. Handlers see the same [`Context`] as on HTTP/1 and HTTP/2.

use crate::context::{Context, Service};
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
    fn write(&self, data: &[u8]) -> flash_core::Result<()>;
    /// Bytes written but not yet on the wire.
    fn queued_bytes(&self) -> usize;
    /// Ends the body, with trailer fields if any.
    fn finish(self: Box<Self>, trailers: Option<Headers>);
}

/// Runs `service` for `req`, answering through `sink`. A handler that neither responds nor
/// detaches gets a 500 sent for it. Request bodies arrive buffered (`Context::on_body` is not
/// called).
pub fn dispatch<S: Service + ?Sized>(service: &S, req: Request, sink: Box<dyn ResponseSink>) {
    let mut ctx = Context::new_ext(req, sink);
    service.call(&mut ctx);
    if !ctx.responded() && !ctx.is_detached() {
        ctx.respond(Response::text(500, "handler did not respond"));
    }
}
