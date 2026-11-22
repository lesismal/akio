# 从 hyper 与 axum 迁移

akio-http 覆盖了 hyper（HTTP/1.1 与 HTTP/2 服务端和客户端）以及 axum 的路由和中间件所涉及的
范围，底层是 akio 的模型：handler 是在连接所属 I/O 线程上执行的同步函数，慢操作用 detach
而不是 await。

## 对照

| axum / hyper / tower | akio-http |
|---|---|
| `axum::serve(listener, app)` / `hyper::server::conn` | `Engine::builder().listen(Listener::tcp(addr).serve(serve(app)))` |
| `Router::new().route("/users/:id", get(h))` | `Router::new().get("/users/:id", h)` |
| `/{id}`（axum 0.8）、`/:id`（0.7） | `{id}` 与 `:id` 都支持 |
| `/*rest`、`/{*rest}` | `*rest`、`{*rest}` |
| 正则路由（axum 没有） | `{id:[0-9]+}` |
| `.nest("/api", api)` | `.nest("/api", api)` |
| `.fallback(h)` | `.fallback(h)`（也替换 405 应答） |
| `.layer(L)`（tower `Layer`） | `.layer(mw)`，`mw` 为 `Fn(&mut Context, &dyn Service)` |
| `route_layer` / 单路由 layer | 给嵌套 router 加 layer，或在后续路由之前添加 layer（layer 包装此前注册的路由） |
| `async fn handler(..) -> impl IntoResponse` | 调用 `ctx.text/bytes/respond` 的 `fn handler(ctx: &mut Context)` |
| `Path<T>` | `ctx.param("name")`（已百分号解码），再自行解析 |
| `Query<T>` | `ctx.req().query_param("k")`（未解码）/ `ctx.req().query()` |
| `HeaderMap`、`TypedHeader` | `ctx.header("name")`、`ctx.req().headers` |
| `Json<T>`（提取 / 响应） | `serde_json::from_slice(ctx.body())` / `ctx.bytes(200, "application/json", serde_json::to_vec(&v)?)`（自行引入 serde） |
| `Bytes` / `String` body | `ctx.body()` |
| body 流（`Body::into_data_stream`） | `Streaming(svc)` + `ctx.on_body(..)` |
| `State<Arc<S>>` | 在 handler 闭包中捕获 `Arc<S>` |
| 中间件设置的 `Extension<T>` | `ctx.set_local(k, v)` / `ctx.local(k)`（字符串） |
| `Response::builder().status(..).header(..)` | `Response::new(status).header(..)`、`Response::text`、`Response::with_body` |
| `Sse` / 流式响应 | `ctx.stream_response(status, headers)` → `BodyStream` |
| `WebSocketUpgrade` | `ctx.upgrade_websocket(handler, &WsOptions)` |
| `tower_http::services::ServeDir` | `files::Files::new(dir)` |
| `CompressionLayer`、`CorsLayer`、`TraceLayer`、`RequestIdLayer`、`CatchPanicLayer` | `middleware::compress`、`cors`、`logger` / `observe::access_log`、`request_id`、`recover` |
| `TimeoutLayer` | 无：需要时 detach，并用你自己的定时器回复 503/504 |
| `tower::limit::RateLimitLayer` | `middleware::limiter(rate, burst)`（按客户端 IP） |
| `axum-server` / `tokio-rustls` 的 TLS | `akio::tls::Tls::server(cfg, serve(app))` |
| `hyper::client` / `reqwest` | `client::Client`、`h2client::H2Client` |
| `tonic` | `akio-grpc` |

## handler

一个 axum handler：

```rust,ignore
// axum（仅作对比，此处不编译）
async fn user(Path(id): Path<u32>, State(db): State<Arc<Db>>) -> Result<Json<User>, StatusCode> {
    let user = db.load(id).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(user))
}
```

在 akio-http 中，handler 里快的部分直接执行，慢的部分 detach：

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:handlers}}
```

共享状态通过捕获而不是提取获得：

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:state}}
```

## router 与中间件

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:router}}
```

编写中间件只需一个普通函数，而不是 tower 的 `Layer` + `Service` 组合：

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:middleware}}
```

需要注意的差异：

- **顺序：** 与 axum 一样，最后一个 `.layer(..)` 在最外层。但 akio 的 layer 只包装在它*之前*
  注册的路由（以及 fallback）；axum 的 `.layer` 包装 router 的所有路由。
- **响应之后：** handler 可能 detach，所以"`next.call(ctx)` 之后的代码"执行时响应可能还不存在。
  用 `ctx.add_response_filter(|resp, req| ..)` 修改或观察最终响应，`ctx.status()` 只对同步
  handler 有意义。
- **错误：** handler 不返回 `Result`；自己用错误状态码答复，或让 `recover()` 把 panic 变成 500。
- **路由冲突** 在注册时 panic，与 axum 相同。

## 启动服务

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:serve}}
```

同一端口上默认启用 HTTP/2（prior knowledge、h2c 升级，或 TLS 下的 ALPN `h2`）；hyper 需要
`auto::Builder` 才能做到。HTTP/3 用 akio-h3 提供同一个 router
（[QUIC 与 HTTP/3](../protocols/quic-h3.md)）。

## 客户端

`reqwest`/`hyper` 的客户端调用对应 `client::Client::send(..).await` 或 `.wait()`；HTTP/2 复用
对应 `H2Client`。akio 的客户端不处理重定向、cookie 和代理。见
[HTTP 客户端](../protocols/http-clients.md)。

## 放弃了什么，得到了什么

你放弃了 `async` handler、提取器和 tower 生态。你得到的是：没有每请求 future 的 handler、
无锁的每连接状态、天然保序的流水线、显式背压、按 listener 选择后端（io_uring、eBPF 分流），
以及在同一个 `Context` 之后的 HTTP/1、HTTP/2 和 HTTP/3。
