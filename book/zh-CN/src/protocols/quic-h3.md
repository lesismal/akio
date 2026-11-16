# QUIC 与 HTTP/3

`only-quic` 是在本 crate 内基于 `only-tls` 和 `only-crypto` 以 sans-io 状态机实现的 QUIC v1
（RFC 9000、9001、9002）、v2（RFC 9369）及数据报（RFC 9221），运行在 only 的 UDP 引擎上；`only-h3` 在其上实现
HTTP/3（RFC 9114）和 QPACK，可以提供任意 only-http `Service`。与 quic-go 做过双向互通测试（流与
数据报的原生 QUIC 回显，含 Retry、密钥更新、150 MB 传输、版本 2 与客户端迁移：
`tools/interop/quic/run.sh`），HTTP/3
则与 quic-go 以及 fib 自己的 QUIC/HTTP/3 双向互通（`tools/interop/h3/run.sh`）；ngtcp2 与 OpenSSL 3.5
的 QUIC 实现作为我方服务端的客户端在 Docker 中验证（`tools/interop/quic/docker.sh`）。

## QUIC

```rust,ignore
{{#include ../../../../crates/only-quic/examples/guide-quic.rs:server}}
```

```rust,ignore
{{#include ../../../../crates/only-quic/examples/guide-quic.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/only-quic/examples/guide-quic.rs:engine}}
```

它如何嵌入 only：

- `QuicServer` 是一个 **UDP listener** 的 acceptor。该 listener 的每个数据报都经过同一个
  endpoint，由它按连接 ID 路由，所以迁移到新地址的客户端（经路径验证后）仍保持原连接。endpoint
  还会对未知版本回复版本协商、对未知连接 ID 发送无状态重置，并在握手压力大时用 Retry 验证客户端
  地址。
- 每个 QUIC 连接从工厂得到一个 `QuicHandler`。它的回调一次一个、按顺序执行，在读到该数据报的
  I/O 线程上或在一个共享的定时器线程上；回调不能阻塞。
- `only_quic::dial(&engine, addr, server_name, client_cfg, handler)` 在一个独立的 UDP socket 上
  发起客户端连接；engine 需要 `udp_client_threads(n)`。
- 满尺寸的数据报每批最多 10 个，用 `Conn::send_segments` 发出（Linux 上为 UDP GSO /
  `sendmmsg`）。处理器在自身回调里发起的写入会先攒起来，回调返回后与 ACK 一起发出，因此请求
  处理器的响应头、响应体和 FIN 通常在同一个包里。ACK 每个接收批次生成一次；收到的包在池化缓冲区
  中解密，流数据与之共享缓冲区。UDP GRO（`Config::udp_gro`，Linux 上默认开启）让大流量接收方
  一次接收整批 GSO 数据。

`QuicHandler` 回调：`on_connected`、`on_stream_opened`、`on_stream_data(c, id, data, fin)`
（必须实现）、`on_stream_reset`、`on_stream_stopped`、`on_streams_available`、`on_datagram`、
`on_close(reason)`。

`Connection`（可克隆，可在任何线程使用）：`open_bi`、`open_uni`、`send(id, data)`、`finish`、
`reset`、`stop`、`queued_bytes(id)`、`send_datagram`、`close(code, reason)`、`remote_addr`、
`alpn`、`server_name`、`rtt`、`stats`、`is_closed`。负载类型是 `only_quic::Bytes`（引用计数、
可切片；收到的数据是解密后数据包的切片，不再复制）。写永不阻塞：`send` 把数据排队，按流量控制与
拥塞控制允许的速度发出；用 `queued_bytes`（尚未发出的字节数）控制生产者节奏。

配置（TLS 1.3）：`server_config(certs, key, alpn)`（使用 `only::tls::Certificate` /
`PrivateKey`）、`server_config_from(&only::tls::ServerConfig)`、`client_config(roots, alpn)`
（使用 `only::tls::RootCerts`）、`client_config_from(&only::tls::ClientConfig)`，以及仅用于测试
的 `client_config_insecure(alpn)`。它们返回 only 自己的 `ServerConfig` / `ClientConfig`；
`.transport(&TransportConfig)` 设置流数量上限、窗口、空闲超时、keep-alive、MTU 探测与拥塞控制
算法，`ServerConfig::migration(bool)` 控制客户端迁移。`server_config` 开启会话票据，复用同一个
`ClientConfig` 的客户端会恢复会话；`ClientConfig` 的各个克隆还共享服务器下发的 NEW_TOKEN 令牌，
下次连接时可免去地址验证的限制。`unstable` cargo feature 保留但不启用任何内容（自研实现之前它
暴露 quinn-proto）。
`QuicServer::connections()` 和 `close_all(code, reason)` 在停机时有用。

### 版本、ECN、BBR 与迁移

- **版本**：QUIC v1 与 v2（RFC 9369）。服务端两者都接受（可用 `ServerConfig::versions` 收窄），并以
  客户端的版本应答；客户端以 `ClientConfig::version`（默认 v1）开始，服务端回以不含该版本的版本协商
  包时，在双方都支持的版本上重新开始一次，并以 version_information 传输参数（RFC 9368）防止伪造的
  降级。`Connection::version()` 返回所用版本。未实现兼容版本协商（在一次握手中切换版本）。
- **ECN**（`TransportConfig::ecn`，默认开启）：Linux 上以 ECT(0) 发送，逐个数据报读取收到的码点并在
  ACK_ECN 帧中报告，验证路径（RFC 9000 第 13.4 节），CE 标记视为拥塞；清除或丢弃标记的路径回退为不带
  标记发送。其他平台不打标记（Linux 上也可用 `ONLY_UDP_ECN=0` 关闭）。`stats().ecn_capable` /
  `ecn_ce_events`。
- **拥塞控制**：`TransportConfig::congestion` 可选 CUBIC（默认）、NewReno 或实验性的
  `Congestion::Bbr`：基于投递速率采样的 BBRv1 模型（Startup、Drain、ProbeBW、ProbeRTT），加上 BBRv2/v3
  对丢包或 CE 标记超过 2% 的轮次的上限。在模拟的 20 Mbit/s、40 ms 路径上，它把 RTT 保持在最小值的
  约 6% 以内（CUBIC 会填满缓冲），1% 随机丢包下吞吐是 CUBIC 的 4 倍。
- **迁移**：客户端换地址（NAT 重绑定）后，服务端在路径验证后跟随。客户端可用
  `Connection::migrate(&engine)` 主动迁移：换到新的本地 UDP socket，或在服务端提供了首选地址时迁到
  该地址（`ServerConfig::preferred_address(addr)`，由同一个 `QuicServer` 的克隆在第二个监听器上提供
  服务；客户端用 `Connection::preferred_address()` 查看）。新路径先用一个未用过的连接 ID 探测，得到
  回应后切换；三个 PTO 内无回应则留在原路径。

### 0-RTT

默认关闭：`ServerConfig::zero_rtt(true)` 与 `ClientConfig::zero_rtt(true)`。客户端用允许 0-RTT 的票据
恢复会话时，`dial` 之后即可打开流（使用服务端在上一次连接中给出的限额），流数据随第一批包以 0-RTT 包
发出；服务端以 0.5-RTT 应答，比完整握手早一个往返。服务端只在传输限额与签发票据时相同的情况下接受
0-RTT，并使用 only-tls 的防重放（10 秒新鲜度窗口加上每个服务端一份有上限的近期 ClientHello 记录）；
否则，或 0-RTT 包丢失时，数据以 1-RTT 包重发（Retry 之后以 0-RTT 发往新的连接 ID）。客户端用
`Connection::early_data()` 得知结果；服务端用 `Connection::is_early(stream)` 判断哪些流来自 0-RTT，
only-h3 会给这类请求加上 `Early-Data: 1`（RFC 8470），处理函数可对不能安全重复的请求回
`425 Too Early`。配置开启时 `H3Client` 会以 0-RTT 发送请求。0-RTT 数据可被重放（发往共享票据的其他
服务端，或在窗口内由能诱使客户端重试的攻击者发起），且没有前向保密。

## HTTP/3

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:server}}
```

`only_h3::serve(quic_cfg, service)`（或 `serve_with(.., H3Config)`）返回一个通过 HTTP/3 提供
该 service 的 `QuicServer`。`only_h3::server_config(certs, key)` 就是 ALPN 为 `h3` 的
`server_config`。handler 拿到的 `Context` 与 HTTP/1.1 和 HTTP/2 上相同，包括 `detach`、
`stream_response` 和 trailer；`ctx.req().version` 为 `Version::Http3`。请求 body 以缓冲方式
到达。`H3Config`：`max_body`（8 MiB，超出返回 413）和 `max_field_section`（64 KiB，作为
`SETTINGS_MAX_FIELD_SECTION_SIZE` 发送；超出返回 431）。

常见的部署方式是在一个 engine 里同时在 TCP（TLS 上的 HTTP/1.1 + HTTP/2）和 UDP（HTTP/3）上
提供同一个应用：两个 listener 使用同一个端口号。`Router` 会被移入它的 acceptor 且不是
`Clone`，所以要么用一个函数为每个 listener 各构建一次，要么共享一个：
`let app = Arc::new(router);`，然后在两个 listener 上都提供
`move |ctx: &mut Context| app.call(ctx)`（需要引入 `only_http::Service`）。

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:client}}
```

`H3Client::dial(&engine, addr, server_name, client_cfg)`（ALPN `h3`）；握手完成前发出的
请求会等待握手完成（以 0-RTT 恢复会话时除外，见上文）。`request(method, path, headers, body, callback)`、
`request_blocking(..)`、`get(path, timeout)`、`close()`、`connection()`。
`H3Client::dial_with(.., H3ClientOptions)` 设置限制：超过 `max_body_bytes`（8 MiB）或
`max_field_section_bytes`（64 KiB，会通告给对端）时停止该响应 stream，并以 `H3Error::TooLarge`
使请求失败；`request_timeout`（30 s，从 `request` 到完整响应）会重置 stream 并以
`H3Error::Timeout` 使其失败（这个回调在定时器线程上运行）。

## HTTP/3 如何复用 only-http

only-http 提供了一个 transport 钩子 `only_http::transport`：transport 解析出请求后调用
`dispatch(service, request, sink)`，其中 `ResponseSink` 用它自己的方式写响应（完整响应用
`send`，流式响应用 `start_stream` 返回一个 `BodySink`）。only-h3 在 QUIC stream 上实现了这些
sink，所以 router、中间件和 handler 都无需改动。见[架构](../architecture.md)。

一个请求的开销：帧直接在收到的流数据上原地读取，字段段解码进连接复用的缓冲区，再复制一次进请求的
`Headers`；响应的 HEADERS 帧直接用 QPACK 编码进交给 QUIC 的缓冲区，不超过 16 KiB 的响应体和 trailer
也放在一起（每个响应只写一次；更大的响应体随后发送，不复制）。在 Ryzen 7 7800X3D 上，单连接 64 个请求
在途约 84 万请求/秒（[性能测试](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md)）。

## 尚未完成

curl/quiche 互通测试、基于 HTTP/3 的 WebSocket（extended CONNECT）、QPACK 动态表（宣告容量为
0）、服务端推送、流式请求 body。
