# WebSocket

`only-ws` 实现了 RFC 6455 以及 `permessage-deflate`（RFC 7692）。服务端通过 only-http 的
升级进入；客户端拨号 `ws://` 和 `wss://` URL。两端使用同一个 handler trait。一致性：
Autobahn|Testsuite 服务端 298 OK + 3 informational（核心）以及 216/216（permessage-deflate）；
客户端 517 项中 514 OK + 3 informational；CI 中由 `tools/autobahn/run.sh` 运行。

## handler

```rust,ignore
pub trait WsHandler: Send + 'static {
    fn on_open(&mut self, ws: &WsSender) {}
    fn on_message(&mut self, ws: &WsSender, msg: Message);   // Message::Text(String) | Binary(Vec<u8>)
    fn on_pong(&mut self, ws: &WsSender, payload: &[u8]) {}
    fn on_close(&mut self, code: Option<u16>, reason: &str) {}
}
```

回调在连接所属的 I/O 线程上执行，收到的是完整的（已重组、已解压、已做 UTF-8 校验的）消息，
不能阻塞。`on_close` 恰好执行一次，参数是对端的关闭码、本端因协议错误关闭时使用的关闭码，
或者在没有关闭握手、底层连接直接断开时为 1006。

`WsSender` 是 `Clone + Send + Sync`：保留它的克隆即可在其他线程发送（不同线程的帧不会交错）：

| 方法 | 效果 |
|---|---|
| `send_text`、`send_binary` | 一条消息（协商了压缩且长度不小于 `compress_min_bytes` 时压缩） |
| `send_text_fragmented`、`send_binary_fragmented` | 按给定大小拆成多个帧 |
| `send_prepared(&PreparedMessage)` | 为多个连接只编码一次的消息（不压缩发送） |
| `ping`、`pong` | 控制帧 |
| `close(code, reason)` | 发起关闭握手（`only_ws::protocol::close::NORMAL` 等） |
| `subprotocol()`、`is_open()` | 协商的子协议、状态 |

## 服务端

```rust,ignore
{{#include ../../../../crates/only-ws/examples/guide-ws.rs:server}}
```

`ctx.upgrade_websocket(handler, &WsOptions)` 校验握手（GET、HTTP/1.1、`Upgrade`/`Connection`
令牌、版本 13、key、origin 策略），应答 `101 Switching Protocols` 并切换连接；`on_open` 立即
执行。握手不合法时它自己应答 400、403 或 426，返回 `false`，连接保持为 HTTP。不要在升级请求
之后流水线发送其他请求。

`WsOptions`：

- `config: WsConfig`：`max_message_bytes`（16 MiB，按解压后计算；超出以 1009 关闭）、
  `permessage_deflate`（true：客户端提出时接受）、`compress_min_bytes`（128）。
- `protocols`：服务端支持的子协议；选择其中客户端最优先的那个。
- `origin_allowed: Option<fn(&str) -> bool>`：带 `Origin` 头的请求，除非它返回 true，否则以 403
  拒绝。不带 `Origin` 的请求（非浏览器客户端）不受影响。

由于升级就是一个普通路由，挂在它前面的一切（认证、限流、日志等中间件）都作用于握手请求。

## 客户端

```rust,ignore
{{#include ../../../../crates/only-ws/examples/guide-ws.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/only-ws/examples/guide-ws.rs:dial}}
```

- `client::dial_blocking(&engine, url, &opts, handler)` 阻塞到握手完成，返回 `WsSender`；不要在同一个
  engine 的 I/O 线程上调用它。
- `client::dial(&engine, url, &opts, handler, on_error)` 是非阻塞形式：成功时执行 `on_open`，
  失败时调用一次 `on_error(WsClientError)`（`InvalidUrl`、`Io`、`Status`、`Handshake`、
  `Timeout`、`Closed`）。
- `DialOptions`：`config`（各项上限；`permessage_deflate` 决定是否提出压缩）、`pmd`（压缩提议
  的参数）、`protocols`、`origin`、`headers`（如 `Authorization`、cookie）、`tls`（`wss://`
  必需；ALPN 中不要提供 `h2`）、`server_name`、`handshake_timeout`（10 s）、`close_timeout`
  （3 s）。
- 帧用不可预测的密钥加掩码；依次尝试解析出的每个地址；域名解析在调用线程上进行。

运行 `cargo run -p only-ws --example guide-ws` 可以看到一个有两个客户端的聊天室，浏览器聊天
示例见 `crates/only-http/examples/ws-chat.rs`。

## 尚未完成

客户端：系统根证书（请自行加载到 `only::tls::RootCerts`）、代理、重定向、engine 停机时发送 1001（目前连接以
1006 结束）。服务端：基于 HTTP/2 或 HTTP/3 的 WebSocket（extended CONNECT）。
