# WebSocket

`akio-ws` 实现了 RFC 6455 以及 `permessage-deflate`（RFC 7692）。服务端通过 akio-http 的
升级进入（HTTP/1.1，或 HTTP/3 上的 extended CONNECT）；客户端拨号 `ws://` 和 `wss://` URL。两端使用同一个 handler trait。一致性：
Autobahn|Testsuite 服务端 298 OK + 3 informational（核心）以及 216/216（permessage-deflate）；
客户端 517 项中 514 OK + 3 informational；CI 中由 `tools/autobahn/run.sh` 运行。

## handler

```rust,ignore
pub trait WsHandler: Send + 'static {
    fn on_open(&mut self, ws: &WsSender) {}
    fn on_message(&mut self, ws: &WsSender, msg: Message) {}   // Message::Text(String) | Binary(Vec<u8>)
    fn on_message_ref(&mut self, ws: &WsSender, msg: MessageRef<'_>) { /* 调用 on_message */ }
    fn on_pong(&mut self, ws: &WsSender, payload: &[u8]) {}
    fn on_close(&mut self, code: Option<u16>, reason: &str) {}
}
```

回调在连接所属的 I/O 线程上执行，收到的是完整的（已重组、已解压、已做 UTF-8 校验的）消息，
不能阻塞。`on_close` 恰好执行一次，参数是对端的关闭码、本端因协议错误关闭时使用的关闭码，
或者在没有关闭握手、底层连接直接断开时为 1006。

实现 `on_message` 得到拥有所有权的消息；实现 `on_message_ref` 则得到借用自连接缓冲区、只在本次调用内有效的消息
（`MessageRef::Text(&str)` | `Binary(&[u8])`）：每条消息没有分配也没有拷贝，所以回显、把消息原样转发的中继、
只保留解析结果的解析器都应使用它。默认的 `on_message_ref` 复制消息后调用 `on_message`。

`WsSender` 是 `Clone + Send + Sync`：保留它的克隆即可在其他线程发送（不同线程的帧不会交错）：

| 方法 | 效果 |
|---|---|
| `send_text`、`send_binary` | 一条消息（协商了压缩且长度不小于 `compress_min_bytes` 时压缩） |
| `send_text_fragmented`、`send_binary_fragmented` | 按给定大小拆成多个帧 |
| `send_prepared(&PreparedMessage)` | 为多个连接只编码一次的消息（不压缩发送） |
| `ping`、`pong` | 控制帧 |
| `close(code, reason)` | 发起关闭握手（`akio_ws::protocol::close::NORMAL` 等） |
| `subprotocol()`、`is_open()` | 协商的子协议、状态 |

## 服务端

```rust,ignore
{{#include ../../../../crates/akio-ws/examples/guide-ws.rs:server}}
```

`ctx.upgrade_websocket(handler, &WsOptions)` 校验握手（GET、HTTP/1.1、`Upgrade`/`Connection`
令牌、版本 13、key、origin 策略），应答 `101 Switching Protocols` 并切换连接；`on_open` 立即
执行。握手不合法时它自己应答 400、403 或 426，返回 `false`，连接保持为 HTTP。不要在升级请求
之后流水线发送其他请求。在 HTTP/2（RFC 8441）和 HTTP/3（RFC 9220）上，同一个调用接受 extended CONNECT
并应答 `200`；此后请求所在的流承载 WebSocket，与连接上的其他请求并存。见
[HTTP/2 上的 WebSocket](#http2-上的-websocket) 和 [HTTP/3 上的 WebSocket](quic-h3.md#http3-上的-websocket)。

`WsOptions`：

- `config: WsConfig`：`max_message_bytes`（16 MiB，按解压后计算；超出以 1009 关闭；消息压缩后的字节数
  同样受限，为该上限再加八分之一，对端无法无限地分片发送压缩消息）、
  `permessage_deflate`（true：客户端提出时接受）、`compress_min_bytes`（128）。
- `protocols`：服务端支持的子协议；选择其中客户端最优先的那个。
- `origin_allowed: Option<fn(&str) -> bool>`：带 `Origin` 头的请求，除非它返回 true，否则以 403
  拒绝。不带 `Origin` 的请求（非浏览器客户端）不受影响。

由于升级就是一个普通路由，挂在它前面的一切（认证、限流、日志等中间件）都作用于握手请求。

## 客户端

```rust,ignore
{{#include ../../../../crates/akio-ws/examples/guide-ws.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/akio-ws/examples/guide-ws.rs:dial}}
```

- `client::dial_blocking(&engine, url, &opts, handler)` 阻塞到握手完成，返回 `WsSender`；不要在同一个
  engine 的 I/O 线程上调用它。
- `client::dial(&engine, url, &opts, handler, on_error)` 是非阻塞形式：成功时执行 `on_open`，
  失败时调用一次 `on_error(WsClientError)`（`InvalidUrl`、`Io`、`Status`、`Handshake`、
  `Timeout`、`Closed`、`TooManyRedirects`）。
- `DialOptions`：`config`（各项上限；`permessage_deflate` 决定是否提出压缩）、`pmd`（压缩提议
  的参数）、`protocols`、`origin`、`headers`（如 `Authorization`、cookie）、`tls`（`None`：使用
  系统 CA；ALPN 中不要提供 `h2`）、`server_name`、`handshake_timeout`（10 s，含重定向）、
  `close_timeout`（3 s）、`proxy`（默认无；`akio_ws::proxy::Proxy::from_env()` 显式启用环境变量）
  和 `max_redirects`（0）。
- 代理：代理适用的每个连接（`ws://` 和 `wss://`）都经 `CONNECT host:port` 隧道，`socks5://` /
  `socks5h://` / `socks4://` / `socks4a://` 代理则经 SOCKS 隧道；被拒绝时是携带
  `akio_ws::proxy::ProxyRefused` 的 `WsClientError::Io`。`Proxy` 类型和规则与
  [HTTP 客户端](http-clients.md#代理)相同。
- 重定向（`max_redirects > 0`）：带 `Location` 的 301、302、303、307 和 308；`http`/`https` 的
  location 变为 `ws`/`wss`；`wss://` 从不转到 `ws://`；跨源时从 `headers` 中删除 `Authorization`、
  `Cookie` 和 `Proxy-Authorization`。浏览器不跟随 WebSocket 重定向，因此默认关闭。
- 客户端所在的 engine 优雅停机时，已打开的连接以 1001（going away）和关闭握手关闭。
- 帧用不可预测的密钥加掩码；依次尝试解析出的每个地址；域名在调用线程之外解析（`akio::dns`）。

运行 `cargo run -p akio-ws --example guide-ws` 可以看到一个有两个客户端的聊天室，浏览器聊天
示例见 `crates/akio-http/examples/ws-chat.rs`。

## HTTP/2 上的 WebSocket

HTTP/2 服务端宣告 `SETTINGS_ENABLE_CONNECT_PROTOCOL`，所以持有该源站 h2 连接的浏览器会在这条连接上打开
WebSocket。路由仍是同一个 `.get("/ws", ...)`：`Router` 用该路径的 GET 路由应答 `websocket` 的
extended CONNECT，`ctx.req().protocol` 为 `Some("websocket")`。`H2Config::enable_connect_protocol = false`
可将其关闭。

`H2Client::websocket(url, &H2WsOptions, handler, done)`（或 `websocket_blocking`）在 `H2Client` 的连接上
打开一个（见 [HTTP 客户端](http-clients.md#http2h2clienth2client)）；`done` 得到 `WsSender`，服务端拒绝时
得到 `ClientError::Status`。`H2WsOptions` 包含 `DialOptions` 中适用的字段（`config`、`pmd`、`protocols`、
`origin`、`headers`、`close_timeout`），以及 `timeout`（10 秒）和 `max_queued_bytes`（8 MiB）。

每个 WebSocket 是一条流，由流和连接的窗口调速。对端不打开窗口时，排队超过 `H2Config::max_pending_bytes`
（服务端）或 `H2WsOptions::max_queued_bytes`（客户端）后发送返回 `Overloaded`；`WsSender::queued_bytes`
告诉生产者何时该等待。close 帧结束我方这一半流，`RST_STREAM` 或连接丢失以 1006 到达 `on_close`，优雅
关闭以 1001 关闭。

## 为 WebSocket 调速

消息来自其他连接或要写往其他连接的中继或隧道，通过 `WsSender` 在任意线程上联动它们的背压（规则 8）：

- `queued_bytes()`：等待发出的字节；超过高水位时，暂停向这个 WebSocket 供数据的一方。
- `on_drain(f)`：这个队列重新变空时（已经为空则立即）或连接关闭时运行 `f`；以最后设置的为准。在
  HTTP/3 上，与流式响应一样，在 QUIC 流的发送缓冲区有空间时运行。
- `hold_reads(true)` / `hold_reads(false)`：停止和恢复读取对端，使得在这个 WebSocket 交付的内容无法
  继续写出时，由对端的流量控制让它停下。在 TCP 或 TLS 上是连接的读取；在 HTTP/2 和 HTTP/3 上是流的
  读取（不归还其窗口），连接上的其他流照常进行。
- `peer_addr()`：对端地址（流的话为 HTTP/2 或 QUIC 连接的对端）。
- `set_relayed(true)`：在 TCP 或 TLS 上，连接的读取不再因为自己的输出超过 `write_high_watermark` 而
  暂停（`Conn::set_relayed`）；`set_max_queued_bytes(Some(n))` 给它自己的发送队列上限
  （`Conn::set_max_queued_bytes`）。在 HTTP/2 和 HTTP/3 上前者不做任何事，后者以 `Unsupported` 失败。

## 立即结束 WebSocket

`WsSender::close(code, reason)` 把关闭帧排在已排队的数据之后发送，客户端随后等待服务端回应（最多
`close_timeout`）。对于出错的链路、被踢出的对端或正在停止的服务，`WsSender::abort()` 立即结束它，可在
任意线程或 handler 的回调中调用：不发关闭帧，丢弃已排队但尚未写出的数据，之后的发送以 `Closed` 失败，
handler 不再收到任何内容。在 TCP 或 TLS 上关闭连接；在 HTTP/2 上重置流（`CANCEL`）；在 HTTP/3 上双向
重置流（`H3_REQUEST_CANCELLED`）；HTTP/2 或 QUIC 连接及其上的其他流继续存在。两端的 `on_close` 都收到
1006（中止一方在其连接的 I/O 线程上收到），除非关闭握手已经结束了会话。中止也会截断进行中的关闭握手。

## 尚未完成

客户端：跨重定向携带 cookie（可以自行用 `akio_http::cookie::CookieJar::header` 设置 `Cookie` 头；
`https://` 代理与 Happy Eyeballs 已完成，ADR-059）；`client::dial` 仍是 HTTP/1.1（HTTP/2 上的
WebSocket 需要 `H2Client`）。基于 HTTP/2 的 WebSocket（RFC 8441，见上文）与基于 HTTP/3 的 WebSocket
（RFC 9220，见 [QUIC 与 HTTP/3](quic-h3.md#http3-上的-websocket)）均已完成。
