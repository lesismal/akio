#![forbid(unsafe_code)]
//! HTTP/1.1 and HTTP/2 for flash: server, router, middleware, static files and clients.
//!
//! * HTTP/1.x: sans-io parsing ([`httparse`](https://docs.rs/httparse) for the head, an
//!   incremental decoder for chunked bodies with trailers), pipelining, keep-alive,
//!   `Expect: 100-continue`, limits.
//! * [`Service`] / [`Context`]: handlers run inline on the I/O thread; call
//!   [`Context::detach`] to finish a response later (logical pool, other threads). Responses to
//!   pipelined requests always go out in request order.
//! * [`Router`]: static, `:param` and `*wildcard` segments, 405 with `Allow`, HEAD from GET,
//!   nesting. [`middleware`]: recover, request id, CORS, logger, response time, compress,
//!   ETag, CSRF, rate limiter; [`files::Files`] for static files.
//! * HTTP/2 on the same port (prior knowledge, `h2c` upgrade, TLS ALPN `h2`), configured by
//!   [`HttpConfig::h2`]; clients: [`client::Client`] (HTTP/1.1) and [`h2client::H2Client`].
//! * [`observe`]: Prometheus metrics, a runtime debug endpoint, a structured access log.
//! * [`transport`]: the hook through which `flash-h3` serves the same services over HTTP/3.
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
//!
//! Guide: [HTTP servers](https://lesismal.github.io/flash/en/protocols/http-server.html), [Routing, middleware and static files](https://lesismal.github.io/flash/en/protocols/http-routing.html), [HTTP clients](https://lesismal.github.io/flash/en/protocols/http-clients.html), [Observability](https://lesismal.github.io/flash/en/observability.html)
//! (中文: [HTTP 服务端](https://lesismal.github.io/flash/zh-CN/protocols/http-server.html)、[路由、中间件与静态文件](https://lesismal.github.io/flash/zh-CN/protocols/http-routing.html)、[HTTP 客户端](https://lesismal.github.io/flash/zh-CN/protocols/http-clients.html)、[可观测性](https://lesismal.github.io/flash/zh-CN/observability.html)).
#![warn(clippy::unwrap_used)]

pub mod client;
mod context;
pub mod files;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
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
/// The seam between HTTP transports and [`Service`]s (flash-h3 dispatches through it).
/// `#[doc(hidden)]`: unstable, outside the semver promise (docs/api-stability.md).
#[doc(hidden)]
pub mod transport;

pub use context::{
    BodyEvent, BodyMode, BodyStream, Context, Detached, Middleware, Service, Streaming, WsOptions,
};
pub use flash_ws as ws;
pub use h2::H2Config;
pub use message::{FileBody, Headers, Method, Request, Response, Version};
pub use router::{RouteMatch, Router};
pub use session::{HttpAcceptor, HttpConfig, Session, serve, serve_with};
