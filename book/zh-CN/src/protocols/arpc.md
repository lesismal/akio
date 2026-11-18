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
| `max_pending_calls(n)` | 一个连接上等待应答的调用上限（65536）；超出的调用立即以 `CallError::Overloaded` 失败 |
| `middleware(Fn(&mut Context, Next))`、`method_middleware(method, ...)` | 包裹 handler（见下文） |
| `coder(impl Coder)` | 在线路上变换帧（见下文） |

在 handler 中，`Context` 提供 `method()`、`body()`、`is_notify()`、`peer()`、`values()` /
`values_mut()`、`responded()`，用 `write(payload)`
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
| `call_with`、`call_async_with`、`notify_with` | 同上，附带给 coder 的 `Values` |
| `notify(method, payload) -> bool` | 单向消息 |
| `new_stream(method, on_event) -> Stream` | `send`、`close_send`、`id`、`method`、`peer` |
| `is_connected()`、`peer_addr()`、`pending_calls()`、`ping()`、`close()` | 状态 |

`CallError`：`Remote(text)`（对端返回了错误）、`Closed`、`Timeout`、`Overloaded`（该连接上等待
应答的调用过多；未发送）。

载荷是字节。Go 端默认原样发送 `string` 和 `[]byte`，其他值用 JSON 编码；Rust 端相应地编解码。

## 中间件与 coder

```rust,ignore
{{#include ../../../../crates/only-arpc/examples/guide-arpc.rs:middleware}}
```

**中间件**包裹每个请求和通知的 handler：先按添加顺序执行全局中间件（`Routes::middleware`），
再执行该方法自己的中间件（`method_middleware`），最后是 handler（或 "method not found"）。中间件
拿到 `Context` 和 `Next`：在 `next.run(ctx)` 之前做的事发生在 handler 之前，之后做的事发生在
handler 答复之后；不调用 `next.run` 直接返回即中止调用链（先用 `ctx.error` 答复）。与 Go 的
`Handler.Use` 不同，顺序与中间件相对 handler 的注册先后无关。用 `ctx.values_mut()` 设置的值对
后续中间件和 handler 可见。客户端的路由处理服务端发来的调用，所以中间件在两端用法相同。stream
没有中间件（与 Go 相同）。没有中间件的路由直接调用 handler，没有额外开销。

**Coder**（`only_arpc::coder`）改写整个帧，对应 Go 的 `MessageCoder`：发送的帧按添加顺序经过
各 coder，接收的帧按相反顺序，所以两端需要相同的 coder 链。每个 coder 在保留头字节中用一位标记
自己的处理，位与 Go 的 `arpcex/extension/middleware/coder` 相同：

| Coder | Go 对应 | 作用 |
|---|---|---|
| `Gzip::new(threshold)`（`.level(..)`） | `coder/gzip.New(threshold)`，第 7 位 | 对长于 `threshold` 的帧，把保留字节之后的全部内容 gzip 压缩（变小才用）；接收的帧**最多解压到 `max_body_bytes`**（压缩炸弹会关闭连接） |
| `Appender::new(name, bit)` | `coder.NewAppender(name, bit, ...)`；tracing 用第 0 位 | 在帧尾追加消息的值 `name`（名字、值、2 字节长度），接收端存入 `Values` |

应答用请求的值编码，所以 appender 会把它们带回去（与 Go 相同）。实现 `Coder` 即可编写自己的
coder（`encode(&mut Vec<u8>, &Values)`、`decode(&mut Vec<u8>, &mut Values, max_body) ->
Result<(), CoderError>`；可用 `flag_bit` / `set_flag_bit`，每个 coder 之后 body 长度会自动修正）。
decode 出错会关闭连接。ping 和 pong 不经过 coder。

## 连接池

```rust,ignore
{{#include ../../../../crates/only-arpc/examples/guide-arpc.rs:pool}}
```

`Pool::builder()` 建立 `size` 个连接（4 个），共享同一个 `Routes`，全部连上后返回
（`connect_timeout`，10 秒；有一个失败则关闭其余连接）。`pool.call` / `call_with` / `call_async`
/ `notify` 选择一个在线的连接：`Balance::RoundRobin`（默认，每线程游标，选择时不共享计数器）或
`Balance::LeastPending`（等待应答的调用最少）。断开的连接每隔 `reconnect_interval`（1 秒）重连，
期间被跳过；全部断开时调用立即以 `Closed` 失败。`heartbeat(Some(interval))`（15 秒）定期 ping 每个
连接，若某次 ping 在一个间隔内没有收到任何数据就关闭它，从而替换掉沉默的对端。每个连接有自己的
`max_pending_calls`，每个调用有自己的截止时间。`peer()`、`peers()`、`connected()`、`close()`。
