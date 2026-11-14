#![forbid(unsafe_code)]
//! HTTP/1.1 for flash.
//!
//! * Sans-io parsing ([`httparse`](https://docs.rs/httparse) for the head, an incremental decoder
//!   for chunked bodies with trailers), pipelining, keep-alive, `Expect: 100-continue`, limits.
//! * [`Service`] / [`Context`]: handlers run inline on the I/O thread; call
//!   [`Context::detach`] to finish a response later (logical pool, other threads). Responses to
//!   pipelined requests always go out in request order.
//! * [`Router`]: static, `:param` and `*wildcard` segments, 405 with `Allow`, HEAD from GET,
//!   nesting. [`middleware`]: recover, request id, CORS, access log.
//!
//! ```no_run
//! use flash::{Engine, Listener};
//! use flash_http::{Context, Router, serve};
//!
//! let app = Router::new()
//!     .get("/", |ctx: &mut Context| ctx.text(200, "hello"))
//!     .get("/users/:id", |ctx: &mut Context| {
//!         let id = ctx.param("id").unwrap_or("?").to_owned();
//!         ctx.text(200, format!("user {id}"));
//!     });
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("127.0.0.1:8080".parse().unwrap()).serve(serve(app)))
//!     .build()
//!     .unwrap();
//! engine.run().unwrap();
//! ```
//!
//! WebSocket: [`Context::upgrade_websocket`] switches a request to a `flash_ws::WsHandler` (re-exported
//! as [`ws`]), with subprotocols, an origin check and `permessage-deflate`.
//!
//! Routing ([`Router`]) is allocation-free and supports static, regexp (`{id:[0-9]+}`, default
//! `regex` feature), plain (`:id`) and wildcard (`*rest`) segments, in that order of precedence;
//! parameters are percent-decoded once ([`Context::param`], raw in [`Context::param_raw`]).

pub mod client;
mod context;
pub mod files;
mod h2;
pub mod h2client;
#[doc(hidden)]
pub mod hpack;
pub mod message;
pub mod middleware;
pub mod observe;
mod parse;
pub mod raw;
mod router;
mod session;
pub mod transport;

pub use context::{
    BodyEvent, BodyMode, BodyStream, Context, Detached, Middleware, Service, Streaming, WsOptions,
};
pub use flash_ws as ws;
pub use h2::H2Config;
pub use message::{FileBody, Headers, Method, Request, Response, Version};
pub use router::{RouteMatch, Router};
pub use session::{HttpAcceptor, HttpConfig, Session, serve, serve_with};
