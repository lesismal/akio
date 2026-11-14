# QUIC 与 HTTP/3

`flash-quic` 在 flash 的 UDP 引擎上运行 sans-io 的 [quinn-proto](https://docs.rs/quinn-proto)
状态机；`flash-h3` 在其上实现 HTTP/3（RFC 9114）和 QPACK，可以提供任意 flash-http `Service`。
与 quic-go 以及 fib 自己的 QUIC/HTTP/3 做过双向互通测试（`tools/interop/h3/run.sh`）。

## QUIC

```rust,ignore
{{#include ../../../../crates/flash-quic/examples/guide-quic.rs:server}}
```

```rust,ignore
{{#include ../../../../crates/flash-quic/examples/guide-quic.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/flash-quic/examples/guide-quic.rs:engine}}
```

它如何嵌入 flash：

- `QuicServer` 是一个 **UDP listener** 的 acceptor。该 listener 的每个数据报都经过同一个
  `quinn_proto::Endpoint`，由它按连接 ID 路由，所以迁移到新地址的客户端仍保持原连接。
- 每个 QUIC 连接从工厂得到一个 `QuicHandler`。它的回调一次一个、按顺序执行，在读到该数据报的
  I/O 线程上或在一个共享的定时器线程上；回调不能阻塞。
- `flash_quic::dial(&engine, addr, server_name, client_cfg, handler)` 在一个独立的 UDP socket 上
  发起客户端连接；engine 需要 `udp_client_threads(n)`。
- 多数据报的 transmit 用 `Conn::send_segments` 发出（Linux 上为 UDP GSO / `sendmmsg`）。
  `Config::udp_gro` 对大流量接收方有帮助。

`QuicHandler` 回调：`on_connected`、`on_stream_opened`、`on_stream_data(c, id, data, fin)`
（必须实现）、`on_stream_reset`、`on_stream_stopped`、`on_streams_available`、`on_datagram`、
`on_close(reason)`。

`Connection`（可克隆，可在任何线程使用）：`open_bi`、`open_uni`、`send(id, data)`、`finish`、
`reset`、`stop`、`queued_bytes(id)`、`send_datagram`、`close(code, reason)`、`remote_addr`、
`alpn`、`server_name`、`rtt`、`stats`、`is_closed`。写永不阻塞：`send` 把流控允许的部分交给
quinn，其余按 stream 暂存，等对端给出额度；用 `queued_bytes` 控制生产者节奏。

配置辅助函数（TLS 1.3，`ring` 实现）：`server_config(certs, key, alpn)`、
`server_config_from(rustls::ServerConfig)`、`client_config(roots, alpn)`、
`client_config_from(rustls::ClientConfig)`，以及仅用于测试的 `client_config_insecure(alpn)`。
`quinn_proto` 以 `flash_quic::proto` 重新导出，用于传输参数（`TransportConfig`）。
`QuicServer::connections()` 和 `close_all(code, reason)` 在停机时有用。

## HTTP/3

```rust,ignore
{{#include ../../../../crates/flash-h3/examples/guide-h3.rs:server}}
```

`flash_h3::server(quic_cfg, service)`（或 `server_with(.., H3Config)`）返回一个通过 HTTP/3 提供
该 service 的 `QuicServer`。`flash_h3::server_config(certs, key)` 就是 ALPN 为 `h3` 的
`server_config`。handler 拿到的 `Context` 与 HTTP/1.1 和 HTTP/2 上相同，包括 `detach`、
`stream_response` 和 trailer；`ctx.req().version` 为 `Version::Http3`。请求 body 以缓冲方式
到达。`H3Config`：`max_body`（8 MiB，超出返回 413）和 `max_field_section`（64 KiB，作为
`SETTINGS_MAX_FIELD_SECTION_SIZE` 发送；超出返回 431）。

常见的部署方式是在一个 engine 里同时在 TCP（TLS 上的 HTTP/1.1 + HTTP/2）和 UDP（HTTP/3）上
提供同一个应用：两个 listener 使用同一个端口号。`Router` 会被移入它的 acceptor 且不是
`Clone`，所以要么用一个函数为每个 listener 各构建一次，要么共享一个：
`let app = Arc::new(router);`，然后在两个 listener 上都提供
`move |ctx: &mut Context| app.call(ctx)`（需要引入 `flash_http::Service`）。

```rust,ignore
{{#include ../../../../crates/flash-h3/examples/guide-h3.rs:client}}
```

`H3Client::connect(&engine, addr, server_name, client_cfg)`（ALPN `h3`）；握手完成前发出的
请求会等待握手完成。`request(method, path, headers, body, callback)`、
`request_blocking(..)`、`get(path, timeout)`、`close()`、`connection()`。

## HTTP/3 如何复用 flash-http

flash-http 提供了一个 transport 钩子 `flash_http::transport`：transport 解析出请求后调用
`dispatch(service, request, sink)`，其中 `ResponseSink` 用它自己的方式写响应（完整响应用
`send`，流式响应用 `start_stream` 返回一个 `BodySink`）。flash-h3 在 QUIC stream 上实现了这些
sink，所以 router、中间件和 handler 都无需改动。见[架构](../architecture.md)。

## 尚未完成

curl/quiche 互通测试、基于 HTTP/3 的 WebSocket（extended CONNECT）、QPACK 动态表（宣告容量为
0）、服务端推送、流式请求 body。
