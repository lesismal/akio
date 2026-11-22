# Migrating from hyper and axum

akio-http covers the ground of hyper (HTTP/1.1 and HTTP/2 server and clients) and of axum's
routing and middleware, with `akio`'s model underneath: handlers are synchronous functions on the
connection's I/O thread, and slow work is detached instead of awaited.

## Mapping

| axum / hyper / tower | akio-http |
|---|---|
| `axum::serve(listener, app)` / `hyper::server::conn` | `Engine::builder().listen(Listener::tcp(addr).serve(serve(app)))` |
| `Router::new().route("/users/:id", get(h))` | `Router::new().get("/users/:id", h)` |
| `/{id}` (axum 0.8), `/:id` (0.7) | both `{id}` and `:id` |
| `/*rest`, `/{*rest}` | `*rest`, `{*rest}` |
| regex routes (not in axum) | `{id:[0-9]+}` |
| `.nest("/api", api)` | `.nest("/api", api)` |
| `.fallback(h)` | `.fallback(h)` (also replaces 405 answers) |
| `.layer(L)` (tower `Layer`) | `.layer(mw)` with `Fn(&mut Context, &dyn Service)` |
| `route_layer` / per-route layers | layer a nested router, or add the layer before later routes (layers wrap routes registered so far) |
| `async fn handler(..) -> impl IntoResponse` | `fn handler(ctx: &mut Context)` that calls `ctx.text/bytes/respond` |
| `Path<T>` | `ctx.param("name")` (percent-decoded) and parse it |
| `Query<T>` | `ctx.req().query_param("k")` (not decoded) / `ctx.req().query()` |
| `HeaderMap`, `TypedHeader` | `ctx.header("name")`, `ctx.req().headers` |
| `Json<T>` (extract / respond) | `serde_json::from_slice(ctx.body())` / `ctx.bytes(200, "application/json", serde_json::to_vec(&v)?)` (bring serde yourself) |
| `Bytes` / `String` body | `ctx.body()` |
| body streaming (`Body::into_data_stream`) | `Streaming(svc)` + `ctx.on_body(..)` |
| `State<Arc<S>>` | capture an `Arc<S>` in the handler closure |
| `Extension<T>` set by middleware | `ctx.set_local(k, v)` / `ctx.local(k)` (strings) |
| `Response::builder().status(..).header(..)` | `Response::new(status).header(..)`, `Response::text`, `Response::with_body` |
| `Sse` / streaming responses | `ctx.stream_response(status, headers)` → `BodyStream` |
| `WebSocketUpgrade` | `ctx.upgrade_websocket(handler, &WsOptions)` |
| `tower_http::services::ServeDir` | `files::Files::new(dir)` |
| `CompressionLayer`, `CorsLayer`, `TraceLayer`, `RequestIdLayer`, `CatchPanicLayer` | `middleware::compress`, `cors`, `logger` / `observe::access_log`, `request_id`, `recover` |
| `TimeoutLayer` | none: detach and answer 503/504 from your own timer if needed |
| `tower::limit::RateLimitLayer` | `middleware::limiter(rate, burst)` (per client IP) |
| `axum-server` / `tokio-rustls` TLS | `akio::tls::Tls::server(cfg, serve(app))` |
| `hyper::client` / `reqwest` | `client::Client`, `h2client::H2Client` |
| `tonic` | `akio-grpc` |

## Handlers

An axum handler:

```rust,ignore
// axum (for comparison, not compiled here)
async fn user(Path(id): Path<u32>, State(db): State<Arc<Db>>) -> Result<Json<User>, StatusCode> {
    let user = db.load(id).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(user))
}
```

In akio-http, the quick part of a handler runs inline and the slow part is detached:

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:handlers}}
```

Shared state is captured instead of extracted:

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:state}}
```

## Routers and middleware

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:router}}
```

Writing a middleware is a plain function instead of a tower `Layer` + `Service` pair:

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:middleware}}
```

Differences to keep in mind:

- **Ordering:** the last `.layer(..)` is the outermost, as in axum. But a `akio` layer wraps only
  the routes registered *before* it (and the fallback); axum's `.layer` wraps every route of the
  router.
- **After the response:** a handler may detach, so "code after `next.call(ctx)`" may run before
  the response exists. Use `ctx.add_response_filter(|resp, req| ..)` to edit or observe the final
  response, and `ctx.status()` only for synchronous handlers.
- **Errors:** there is no `Result`-returning handler; respond with the error status yourself, or
  let `recover()` turn panics into 500.
- **Route conflicts** panic at registration, like axum.

## Serving

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:serve}}
```

HTTP/2 is on by default on the same port (prior knowledge, h2c upgrade, or ALPN `h2` under TLS);
hyper needs `auto::Builder` for that. HTTP/3 serves the same router with akio-h3
([QUIC and HTTP/3](../protocols/quic-h3.md)).

## Clients

`reqwest`/`hyper` client calls map to `client::Client::send(..).await` or `.wait()`; HTTP/2
multiplexing to `H2Client`. Redirects, cookies and proxies are not handled by `akio`'s clients.
See [HTTP clients](../protocols/http-clients.md).

## What you give up and what you get

You give up `async` handlers, extractors and the tower ecosystem. You get handlers with no
per-request future, lock-free per-connection state, ordered pipelining for free,
explicit backpressure, per-listener backends (io_uring, eBPF steering), and HTTP/1, HTTP/2 and
HTTP/3 behind one `Context`.
