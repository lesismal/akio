# arpc

`only-arpc` 使用 [lesismal/arpc](https://github.com/lesismal/arpc) 和 fib 的 `arpc` package 的
线路格式，因此可以与这两者的 Go 端互通（由 `tools/interop/arpc/run.sh` 做双向检查）。

每个连接在**两端**都是一个 `Peer`：任意一端都可以调用、通知或打开 stream，并用自己拿到的
`Routes` 处理对端的调用。

## 服务端

```rust,ignore
{{#include ../../../../crates/only-arpc/examples/guide-arpc.rs:server}}
```

`Routes`：

| 构建方法 | 含义 |
|---|---|
| `handle(method, Fn(&mut Context))` | 处理 `method` 的调用和通知；`""` 是未知方法的兜底（否则返回 "method not found"） |
| `handle_stream(method, open)` | 处理对端打开的 stream：`open(&Stream)` 返回接收 `Message(bytes)` 和 `Eof` 的 `FnMut(&Stream, StreamEvent)` |
| `on_connected(Fn(&Peer))`、`on_disconnected(Fn(&Peer))` | 连接事件 |
| `max_body_bytes(n)` | 方法名 + 载荷的最大长度（64 MiB）；超出则关闭连接 |
| `max_streams_per_conn(n)` | 对端在一个连接上同时打开的 stream 上限（1024）；超出后新打开的 stream 立即被结束，与未提供的方法相同 |
| `call_timeout(Option<Duration>)` | 使用这些路由的连接上以 `timeout: None` 发起的调用的超时（30 秒）；设为 `None` 则一直等到连接关闭 |

在 handler 中，`Context` 提供 `method()`、`body()`、`is_notify()`、`peer()`，用 `write(payload)`
或 `error(text)` 答复，或者 `detach()` 得到 `Responder`（稍后在任何线程 `write` / `error`）。
handler 在 I/O 线程上执行，不能阻塞。

`Server`（可克隆）：`broadcast(method, payload)` 用一个共享的已编码帧向所有已连接的客户端发送
通知；`peers()` 列出它们。

## 客户端

```rust,ignore
{{#include ../../../../crates/only-arpc/examples/guide-arpc.rs:client}}
```

`only_arpc::dial_blocking(&engine, addr, routes)` 阻塞到第一个连接建立（最多 10 s），之后每秒
**自动重连**，直到调用 `Peer::close()`。

`Peer`（可克隆，可在任何线程使用）：

| 方法 | 含义 |
|---|---|
| `call(method, payload, timeout) -> CallFuture` | `wait()`（或 `.await`）得到 `Result<Vec<u8>, CallError>`；`timeout: None` 使用路由的 `call_timeout`（30 秒） |
| `call_async(method, payload, timeout, done)` | 回调形式 |
| `notify(method, payload) -> bool` | 单向消息 |
| `new_stream(method, on_event) -> Stream` | `send`、`close_send`、`id`、`method`、`peer` |
| `is_connected()`、`peer_addr()`、`close()` | 状态 |

`CallError`：`Remote(text)`（对端返回了错误）、`Closed`、`Timeout`。

载荷是字节。Go 端默认原样发送 `string` 和 `[]byte`，其他值用 JSON 编码；Rust 端相应地编解码。

尚未完成：Go arpc 的中间件 / coder 链、客户端连接池。
