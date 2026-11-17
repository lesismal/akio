//! Request and connection spans (only-log's span API), created only while spans of their level
//! are enabled ([`only_log::span::enabled`], one atomic load otherwise).
//!
//! * `http.server.request` spans (level `info`, target `only_http::request`, kind server):
//!   named after the method, renamed `"<method> <route>"` once the router has matched a route;
//!   fields `http.request.method`, `url.path`, `network.protocol.version`, `client.address`,
//!   `http.route` and `http.response.status_code`; status error for 5xx. A W3C `traceparent`
//!   header makes the span a child of the caller's. The span ends when the response head is
//!   sent (or the request is dropped unanswered).
//! * `http.server.connection` spans (level `debug`, target `only_http::connection`): one per
//!   connection, from accept to close, with `client.address` and the protocol version.

use only_log::{
    Level,
    span::{self, Entered, Parent, Span, SpanBuilder, SpanContext, SpanKind, SpanStatus},
};

use crate::{
    context::Context,
    message::{Request, Response, Version},
    router::RouteInfo,
};

/// Target of request spans.
pub const REQUEST_TARGET: &str = "only_http::request";
/// Target of connection spans.
pub const CONNECTION_TARGET: &str = "only_http::connection";

pub(crate) fn version_str(v: Version) -> &'static str {
    match v {
        Version::Http10 => "1.0",
        Version::Http11 => "1.1",
        Version::Http2 => "2",
        Version::Http3 => "3",
    }
}

/// Starts the request span of `ctx` (when request spans are on) and enters it for the
/// service call; the guard must be dropped when the call returns.
#[inline(always)]
pub(crate) fn begin(ctx: &mut Context) -> Option<Entered<'static>> {
    if !span::enabled(Level::Info) {
        return None;
    }
    begin_slow(ctx)
}

#[cold]
#[inline(never)]
fn begin_slow(ctx: &mut Context) -> Option<Entered<'static>> {
    let s = request_span(ctx.req());
    let sc = s.context();
    ctx.set_span(s);
    sc.map(span::enter_context)
}

fn request_span(req: &Request) -> Span {
    let parent = req
        .headers
        .get("traceparent")
        .and_then(SpanContext::from_traceparent);
    let method = req.method.as_str().to_owned();
    SpanBuilder::new(Level::Info, REQUEST_TARGET, method.clone())
        .kind(SpanKind::Server)
        .parent(Parent::Explicit(parent))
        .field("http.request.method", method)
        .field("url.path", req.path().to_owned())
        .field("network.protocol.version", version_str(req.version))
        .field("client.address", req.peer.ip().to_string())
        .start()
}

/// The router matched `route`: rename the span and record the route.
pub(crate) fn routed(s: &mut Span, route: &RouteInfo) {
    if s.is_recording() {
        s.set_name(format!("{} {}", route.method().as_str(), route.pattern()));
        s.record("http.route", route.pattern().to_owned());
    }
}

/// The response is going out: record the status and end the span.
pub(crate) fn responded(s: Span, resp: &Response) {
    let mut s = s;
    if s.is_recording() {
        s.record("http.response.status_code", u64::from(resp.status));
        if resp.status >= 500 {
            s.set_status(SpanStatus::Error(std::borrow::Cow::Borrowed(
                "server error",
            )));
        }
    }
}

/// A connection span (level `debug`), or none.
#[inline(always)]
pub(crate) fn connection(peer: std::net::SocketAddr, proto: &'static str) -> Span {
    if !span::enabled(Level::Debug) {
        return Span::none();
    }
    connection_slow(peer, proto)
}

#[cold]
#[inline(never)]
fn connection_slow(peer: std::net::SocketAddr, proto: &'static str) -> Span {
    SpanBuilder::new(Level::Debug, CONNECTION_TARGET, "http.server.connection")
        .kind(SpanKind::Server)
        .parent(Parent::Root)
        .field("client.address", peer.ip().to_string())
        .field("client.port", u64::from(peer.port()))
        .field("network.protocol.version", proto)
        .start()
}
