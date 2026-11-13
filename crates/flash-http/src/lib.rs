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
//! Not yet implemented: streaming request/response bodies (bodies are buffered, within limits),
//! `sendfile`/static files, regexp route parameters, an HTTP client, WebSocket upgrade.

mod context;
pub mod message;
pub mod middleware;
mod parse;
mod router;
mod session;

pub use context::{Context, Detached, Middleware, Service};
pub use message::{Headers, Method, Request, Response, Version};
pub use router::Router;
pub use session::{HttpAcceptor, HttpConfig, Session, serve, serve_with};
