# HTTP/1.1 与 HTTP/2 服务端

`only-http` 用同一套编程模型提供 HTTP/1.0、HTTP/1.1 和 HTTP/2：`Service` 为每个请求拿到一个
`&mut Context`，在连接所属的 I/O 线程上执行。

## 启动服务

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:serve}}
```

`serve(service)` / `serve_with(HttpConfig, service)` 返回一个 `HttpAcceptor`：直接交给
listener，或者用 `Tls::server` 包装成 HTTPS。`HttpConfig`：

| 字段 | 默认值 | 含义 |
|---|---|---|
| `max_header_bytes` | 64 KiB | 请求行 + 头部；超出返回 431 |
| `max_body_bytes` | 1 MiB | 缓冲的请求 body；超出返回 413 |
| `h2` | `Some(H2Config::default())` | HTTP/2 设置，`None` 表示只提供 HTTP/1 |
| `head_timeout` | 10 s | 从请求头第一个字节到结束（第一个请求从连接建立算起），一次滴一个字节的对端无法让半个请求头一直存活（slowloris）；超时返回 408 并关闭。HTTP/2：等待客户端的 `SETTINGS`（GOAWAY `SETTINGS_TIMEOUT`） |
| `keep_alive_timeout` | 75 s | 等待下一个请求；仍在准备的响应会在关闭前发出。HTTP/2：这么久没有任何帧且没有打开的 stream 时发送 GOAWAY |
| `body_timeout` | 60 s | 请求 body 这么久没有进展：返回 408（流式的 HTTP/1 body 直接断开）。HTTP/2：只针对缓冲的上传（流式上传，例如 gRPC stream，由其 service 自己控制节奏） |

每个超时设为 `None` 即关闭。它们由每个进程一个的清扫线程检查，节拍是最短超时的一小部分
（5 ms 到 1 s），因此在超时之后、最多两个节拍内触发，绝不会提前。

`H2Config`：`max_concurrent_streams`（128）、`initial_window`（每 stream 1 MiB）、
`conn_window`（16 MiB）、`max_header_list`（64 KiB）、`max_body_bytes`（1 MiB，缓冲的
body）、`max_pending_bytes`（一个响应为慢对端积压超过 8 MiB 后，写入方会收到
`Overloaded`）、`max_conn_pending_bytes`（整个连接所有 stream 在内存中积压的响应 body
上限 32 MiB；超出后该响应以 `ENHANCE_YOUR_CALM` 重置，流式写入收到 `Overloaded`）、
`max_resets`（每个 `reset_window` 内对端重置的 stream，以及因对端帧而被服务端重置的
stream，最多 100 个：Rapid Reset，CVE-2023-44487）、`max_control_frames`（每个
`reset_window` 内最多 1000 个 `PRIORITY`、额外的 `SETTINGS`、空 `DATA` 或空
`CONTINUATION` 帧）和 `reset_window`（30 s）。超出任一预算，连接收到
`GOAWAY ENHANCE_YOUR_CALM`。

HTTP/2 按连接选择：客户端前言（prior knowledge，以及 ALPN 为 `h2` 的 TLS）或
`Upgrade: h2c` 请求。两个版本使用同一个 service 和同一套中间件；HTTP/3 也复用它们
（[QUIC 与 HTTP/3](quic-h3.md)）。

## Service 与 `Context`

任何 `Fn(&mut Context) + Send + Sync + 'static` 都是 `Service`，`Router` 也是。service 必须
**响应**或者 **detach**；两者都不做时客户端会收到 500。

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:handlers}}
```

读取请求：

| 调用 | 返回 |
|---|---|
| `ctx.method()`、`ctx.path()`、`ctx.header(name)`、`ctx.body()`、`ctx.peer()` | 基本信息 |
| `ctx.req()` | 完整的 `Request`（`target`、`version`、`headers`、`trailers`、`body`、`query_param`） |
| `ctx.param(name)` / `ctx.param_raw(name)` | 路由参数，百分号解码后 / 原样 |
| `ctx.local(key)` | 中间件用 `set_local` 存入的值 |

响应：

| 调用 | 效果 |
|---|---|
| `ctx.text(status, body)` / `ctx.bytes(status, type, body)` | 完整响应 |
| `ctx.respond(Response)` | 任意响应；`Response::from_file` 发送文件区间（明文 TCP 上用 `sendfile`） |
| `ctx.detach()` → `Detached` | 稍后在任何线程答复：`respond`、`stream_response` |
| `ctx.stream_response(status, headers)` → `BodyStream` | chunked（HTTP/1.1）或 DATA 帧（HTTP/2）；`write`、`queued_bytes`、`finish`、`finish_with_trailers` |
| `ctx.push(path)` | HTTP/2 服务端推送 `GET path` |
| `ctx.upgrade_websocket(handler, &opts)` | 切换到 WebSocket（[章节](websocket.md)） |
| `ctx.upgrade_raw(handler)` | 接管原始连接（`RawHandler`），HTTP CONNECT 代理就是这样做的 |

只有第一个响应有效。`Response::header` 设置头部；缺少 `Content-Length`、`Date` 和
`Connection` 时会自动添加。

## detach：永远不要阻塞 handler

`ctx.detach()` 把答复的权利交给一个 `Detached` 值，你可以把它移到任何线程。流水线 HTTP/1.1
请求的响应仍按请求顺序发出（only-http 为每个请求预留一个有序响应槽位），HTTP/2 的各个
stream 互不影响。handler 一返回，I/O 线程就空闲了。

慢的部分放在哪里执行：自己的线程、自己的线程池，或另一个运行时；见
[阻塞任务](../concepts/blocking.md)和[从 tokio 迁移](../migration/from-tokio.md)。

## 流式传输

响应 body：`ctx.stream_response(..)`（或 `Detached::stream_response`）返回一个可在任何线程写入
的 `BodyStream`。keep-alive 的 HTTP/1.1 上使用 chunked，否则以关闭连接作为结束；排在更早的
流水线响应之后时会按顺序暂存。响应过滤器（压缩、ETag）不作用于流式 body。不调用 `finish`
就丢弃 stream 会关闭连接。

请求 body：默认在 service 执行前缓冲整个 body（最多 `max_body_bytes`）。用 `Streaming(svc)`
包装 service（或重写 `Service::body_mode`），它会在请求头解析完后立即执行，并通过
`ctx.on_body` 逐块接收 body，最后收到带 trailer 的 `BodyEvent::End`。流式 body 没有大小限制，
由接收方自行决定。

## 已为你处理的协议细节

- keep-alive、`Connection: close`、HTTP/1.0；流水线且响应保持顺序。
- `Expect: 100-continue`。
- 带扩展和 trailer、可在任意位置被切开的 chunked body。
- 请求走私防护：`Content-Length` 与 `Transfer-Encoding` 同时出现、重复的 `Content-Length`。
- GET 路由自动应答不带 body 的 HEAD。
- HTTP/2：HPACK、双向流控、h2c 升级、服务端推送、停机时发送 `GOAWAY`；h2spec strict 147/147。
- 优雅停机：在途响应完成后关闭 HTTP/1 连接；HTTP/2 发送 `GOAWAY`。

## 对比

HTTP/1.1、流水线 HTTP/1.1、h2c 与 TLS 上的 HTTP/2 在 epoll 与 io_uring 下与 hyper 和 fib 的对比见
[docs/BENCHMARKS.zh-CN.md](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md)
（本节曾把这份对比报告列为尚未完成）。
