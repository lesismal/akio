# HTTP 客户端

两个客户端的连接都运行在 flash 的 `Engine` 上（给它设置 `client_threads(n)` 并 `start()`）。
结果通过 I/O 线程上的回调到达（回调不能阻塞），或者通过 `ResponseFuture` 获取：可以
`wait()`、`wait_timeout(d)` 或 `.await`。

## HTTP/1.1：`client::Client`

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:client}}
```

- `Client::new(Arc<Engine>)`，克隆开销很小。`with_tls(Arc<rustls::ClientConfig>)` 启用
  `https://`。
- `ClientRequest::get(url)`、`ClientRequest::post(url, body)`、`.header(name, value)`；也可以
  自己填 `method`、`url`、`headers`、`body`。`Host`、`Content-Length` 和 `Connection` 会自动添加。
- `client.send(req)` 返回 `ResponseFuture`；`client.request(req, callback)` 使用回调。
- `ClientResponse` 包含 `status`、`reason`、`headers`、`body`（已去掉 chunked 编码）、`trailers`。
- keep-alive 连接按主机复用；在复用连接上发出的请求如果发现连接已失效，会在新连接上重试一次。
- 地址回退：依次尝试解析出的每个地址（`localhost` 往往先解析出 `::1`）。
- `ClientError`：`InvalidUrl`、`Io`、`Protocol`、`Closed`。

尚未完成：重定向、单请求超时（用 `wait_timeout` 或 engine 的空闲超时）、在调用线程之外做
域名解析（解析发生在 `send`/`request` 中，可能阻塞）。

## HTTP/2：`h2client::H2Client`

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:h2client}}
```

- `H2Client::dial(engine, addr, tls, opts, ready)` 或 `dial_blocking(engine, addr, tls,
  opts)`。`tls = None` 表示 prior knowledge 的明文 HTTP/2；`Some((cfg, server_name))` 使用 TLS，
  且 `cfg.alpn_protocols` 中必须包含 `h2`。
- 一个连接复用所有请求；`H2Client` 克隆开销很小，可在任何线程使用。`send(req)` →
  `ResponseFuture`，`request(req, callback)`。
- `H2Options`：`initial_window`（1 MiB）、`conn_window`（16 MiB）、`enable_push`（false；开启后
  `ClientResponse::pushed` 携带被推送的响应）。
- 双向流式：`open(req, on_event)` 返回用于写请求 body 的 `H2Upload`（`write`、`finish`），并在
  响应到达时报告 `H2Event::Head`、`Data`、`Trailers`、`End` 或 `Error`。flash-grpc 的客户端
  就建立在它之上。
- `is_open()`、`close()`。

## HTTP/3

`flash_h3::H3Client` 见 [QUIC 与 HTTP/3](quic-h3.md)。

## 在异步代码中 await

`ResponseFuture` 实现了 `Future`，所以异步代码（包括 tokio）可以 `.await` 它；连接本身仍
运行在 flash 的 I/O 线程上。见[从 tokio 迁移](../migration/from-tokio.md)。
