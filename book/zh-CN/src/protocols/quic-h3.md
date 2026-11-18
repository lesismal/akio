# QUIC 与 HTTP/3

`only-quic` 是在本 crate 内基于 `only-tls` 和 `only-crypto` 以 sans-io 状态机实现的 QUIC v1
（RFC 9000、9001、9002）、v2（RFC 9369）及数据报（RFC 9221），运行在 only 的 UDP 引擎上；`only-h3` 在其上实现
HTTP/3（RFC 9114）和 QPACK，可以提供任意 only-http `Service`。与 quic-go 做过双向互通测试（流与
数据报的原生 QUIC 回显，含 Retry、密钥更新、150 MB 传输、版本 2 与客户端迁移：
`tools/interop/quic/run.sh`），HTTP/3
则与 quic-go 以及 fib 自己的 QUIC/HTTP/3 双向互通（`tools/interop/h3/run.sh`）；ngtcp2 与 OpenSSL 3.5
的 QUIC 实现作为我方服务端的客户端在 Docker 中验证（`tools/interop/quic/docker.sh`），兼容版本协商则
与 ngtcp2 自己的客户端和服务端双向验证（`tools/interop/quic/ngtcp2-cvn.sh`）。

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
（必须实现）、`on_stream_reset`、`on_stream_stopped`、`on_streams_available`、
`on_stream_writable`、`on_datagram`、`on_close(reason)`。

`Connection`（可克隆，可在任何线程使用）：`open_bi`、`open_uni`、`send(id, data)`、`finish`、
`reset`、`stop`、`queued_bytes(id)`、`send_capacity(id)`、`send_datagram`、
`spawn_blocking(work)`、`close(code, reason)`、`remote_addr`、`alpn`、`server_name`、`rtt`、
`stats`、`is_closed`。负载类型是 `only_quic::Bytes`（引用计数、可切片；收到的数据是解密后数据包
的切片，不再复制）。写永不阻塞：`send` 把数据排队，按流量控制与拥塞控制允许的速度发出。

发送缓冲区有上限。一个流持有已写入但尚未确认的数据，最多 `TransportConfig::stream_send_buffer`
（16 MiB），一个连接的所有流合计最多 `send_buffer`（16 MiB）。超过任一上限时，`send` 返回
`Error::Overloaded` 且不接收数据；当该流和连接的缓冲区降到上限的四分之三时，回调
`on_stream_writable(c, id)`（每次拒绝回调一次）。生产者写到被拒为止，并在该回调里继续；
`send_capacity(id)` 返回剩余空间（为零时同样会触发该回调），因此可以只在有空间时才读取文件的下一
块。在上限之下被接收的一次写入可以越过上限，所以一个流最多持有上限加一次写入。
`spawn_blocking(work)` 在 engine 的逻辑池上执行 `work`（磁盘读取等阻塞工作），`work` 里可以调用
该连接。

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

各项上限及默认值（全部有界；`None` / `MAX` 取消上限）：

| 设置 | 默认值 | 含义 |
|---|---|---|
| `TransportConfig::max_concurrent_bidi_streams`、`max_concurrent_uni_streams` | 100、100 | 对端可同时打开的流数 |
| `TransportConfig::stream_receive_window` | 1.25 MB | 对端在一个流上可领先应用读取发送的字节数 |
| `TransportConfig::receive_window` | 10 MB（流窗口的 8 倍） | 一个连接所有流合计的同类限制（`None`：不限） |
| `TransportConfig::send_window` | 10 MB | 所有流上已发送未确认的字节数 |
| `TransportConfig::stream_send_buffer` | 16 MiB | 一个流为发送持有的字节数，超过后 `send` 返回 `Overloaded` |
| `TransportConfig::send_buffer` | 16 MiB | 一个连接所有流合计的同类限制 |
| `TransportConfig::max_idle_timeout` | 30 s | 关闭静默的连接 |
| `TransportConfig::datagram_receive_buffer_size`、`datagram_send_buffer_size` | 1.25 MB、1 MiB | 两个方向缓冲的不可靠数据报 |
| `ServerConfig::max_connections(n)` | 10,000 | 服务器同时持有的连接数（握手中、打开或关闭中）；超过后新客户端立即收到 `CONNECTION_REFUSED`，服务器不保留任何状态（与无状态重置一起限速；由 `QuicServer::refused_connections()` 计数） |

进行中的握手超过 4096 个时，新客户端还必须先用 Retry 证明其地址。

### 版本、ECN、BBR 与迁移

- **版本**：QUIC v1 与 v2（RFC 9369）。服务端两者都接受（可用 `ServerConfig::versions` 收窄），并以
  客户端的版本应答；客户端以 `ClientConfig::version`（默认 v1）开始，服务端回以不含该版本的版本协商
  包时，在双方都支持的版本上重新开始一次，并以 version_information 传输参数（RFC 9368）防止伪造的
  降级。`Connection::version()` 返回所用版本。
- **兼容版本协商**（RFC 9368 第 4 节，[ADR-013](https://github.com/lesismal/only/blob/main/docs/adr/013-shared-anti-replay-and-compatible-vn.zh-CN.md)）：
  `ServerConfig::prefer_version(Version::V2)` 让以 v1 开始、并在 version_information 中列出 v2 的客户端
  在握手内切换到 v2，不多花往返（`V1` 则反向）。默认关闭（服务端用客户端的版本应答）。服务端在应答前读完
  整个首个 ClientHello，因此 ClientHello 跨多个包、Retry 之后以及 0-RTT 时都可用（客户端的 0-RTT 包保持
  首个版本，RFC 9369 第 4.1 节）。only-quic 客户端总会跟随切换。不带 version_information 的客户端
  （quic-go）不会被切换；ngtcp2 双向都能切换。

  ```rust,ignore
  let cfg = only_quic::server_config(certs, key, &[b"h3"])?
      .prefer_version(only_quic::Version::V2);
  ```
- **票据与令牌按版本区分**（RFC 9369 第 5 节，[ADR-014](https://github.com/lesismal/only/blob/main/docs/adr/014-quic-version-bound-resumption.zh-CN.md)）：
  会话票据或 NEW_TOKEN 令牌属于签发它的连接所用的版本，兼容切换后即协商出的版本。服务端只用客户端起始
  版本的票据恢复会话（其他版本的票据走完整握手，没有 0-RTT），也只用该版本的令牌验证地址（Retry 令牌
  同样如此）。客户端绝不在 v2 中出示 v1 的票据或令牌，反之亦然：只要自己支持，它就以该服务端最新票据
  （没有票据时看令牌）的版本开始连接，而不是 `ClientConfig::version`。因此配置为 v1、被偏好 v2 的服务端
  切到 v2 的客户端，下次直接以 v2 开始，带 0-RTT 恢复会话，无需切换。
- **ECN**（`TransportConfig::ecn`，默认开启）：Linux、macOS 与 only-dpdk 上以 ECT(0) 发送，逐个数据报读取收到的码点并在
  ACK_ECN 帧中报告，验证路径（RFC 9000 第 13.4 节），CE 标记视为拥塞；清除或丢弃标记的路径回退为不带
  标记发送。其他平台不打标记（Linux 与 macOS 上也可用 `ONLY_UDP_ECN=0` 关闭）。`stats().ecn_capable` /
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
`425 Too Early`。配置开启时 `H3Client` 会以 0-RTT 发送请求。0-RTT 数据可被重放（在窗口内由能诱使
客户端重试的攻击者发起；或发往共享票据的其他服务端，除非这些服务端共享防重放记录：用
`session_ticket_key` 与 `anti_replay_store` 构建其 TLS 配置，见 TLS 章节），且没有前向保密。

## HTTP/3

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:server}}
```

`only_h3::serve(quic_cfg, service)`（或 `serve_with(.., H3Config)`）返回一个通过 HTTP/3 提供
该 service 的 `QuicServer`。`only_h3::server_config(certs, key)` 就是 ALPN 为 `h3` 的
`server_config`。handler 拿到的 `Context` 与 HTTP/1.1 和 HTTP/2 上相同，包括 `detach`、
`stream_response`、trailer、流式请求 body 和 WebSocket 升级（见下文）；`ctx.req().version` 为
`Version::Http3`。`H3Config`：`max_body_bytes`（8 MiB，更大的缓冲 body 返回 413）、
`max_field_section_bytes`（64 KiB，作为 `SETTINGS_MAX_FIELD_SECTION_SIZE` 发送；超出返回 431）
以及下文介绍的 QPACK 设置。

响应遵循 QUIC 发送缓冲区：流暂时接收不了的部分随响应等待，在 `on_stream_writable` 报告有空间时
发出，因此不给流控额度的客户端最多让服务器为每个流持有 `stream_send_buffer`。文件 body
（`Response::from_file`、静态文件）每次读取 256 KiB，在 engine 的逻辑池上进行，且只在流有空间
容纳这一块时才读，绝不在 I/O 线程上读（逻辑池满时就地读取一块）。流式 body 的 `write` 在缓冲区
满时返回 `Overloaded`，与 HTTP/1.1 和 HTTP/2 一致：等 `queued_bytes()` 下降后再写。

常见的部署方式是在一个 engine 里同时在 TCP（TLS 上的 HTTP/1.1 + HTTP/2）和 UDP（HTTP/3）上
提供同一个应用：两个 listener 使用同一个端口号。`Router` 会被移入它的 acceptor 且不是
`Clone`，所以要么用一个函数为每个 listener 各构建一次，要么共享一个：
`let app = Arc::new(router);`，然后在两个 listener 上都提供
`move |ctx: &mut Context| app.call(ctx)`（需要引入 `only_http::Service`）。

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:client}}
```

`H3Client::dial(&engine, addr, server_name, client_cfg)`（ALPN `h3`），或用
`dial_with(.., H3ClientOptions)` 指定限制和 QPACK 设置；握手完成前发出的
请求会等待握手完成（以 0-RTT 恢复会话时除外，见上文）。`request(method, path, headers, body, callback)`、
`request_blocking(..)`、`get(path, timeout)`、`upload(..)`、`websocket(..)`、`close()`、
`connection()`。响应以缓冲方式到达。
`H3Client::dial_with(.., H3ClientOptions)` 设置限制：超过 `max_body_bytes`（8 MiB）或
`max_field_section_bytes`（64 KiB，会通告给对端）时停止该响应 stream，并以 `H3Error::TooLarge`
使请求失败；`request_timeout`（30 s，从 `request` 或 `websocket` 到完整响应，WebSocket 为其头部；
上传没有超时）会重置 stream 并以 `H3Error::Timeout` 使其失败（这个回调在定时器线程上运行）。
它也接受 QPACK 设置（见下文）。

### 流式请求 body

`body_mode` 为 `BodyMode::Stream` 的 service（用 `Streaming` 包装）会在请求的第一批 body 字节
到达时被调用，并通过 `ctx.on_body` 随 QUIC 交付逐段收到 body，与 HTTP/1.1 和 HTTP/2 完全一样；
`max_body_bytes` 对它不适用，而且读取器从不暂存 DATA 帧（只暂存不完整的帧头或 HEADERS 帧），所以
几 GB 的上传也以常量内存通过。`content-length` 与 body 不一致时重置该流（`H3_MESSAGE_ERROR`）。
缓冲模式的 service 不受影响。

客户端的 `upload(method, path, &headers, callback)` 立即发送头部并返回一个 `H3Upload`：可从任意
线程调用 `write(&[u8])`，然后 `finish()`，用 `queued_bytes()` 控制写入节奏；响应交给 callback。

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:upload}}
```

### HTTP/3 上的 WebSocket

服务端宣告 extended CONNECT（RFC 9220），`ctx.upgrade_websocket(handler, &WsOptions)` 接受它：
子协议、origin 检查和 `permessage-deflate` 与 HTTP/1.1 上相同，应答为 `200`，此后请求流承载
WebSocket，由 only-ws 分帧，`WsHandler` 回调和 `WsSender` 不变。`Router` 把 `websocket` 的
extended CONNECT 路由到该路径的 GET 路由，所以一个 `.get("/ws", ...)` 同时服务 HTTP/1.1 升级和
HTTP/3。这种请求的 `ctx.req().protocol` 为 `Some("websocket")`。不支持 HTTP/2 上的 WebSocket
（RFC 8441）。

`H3Client::websocket(path, &H3WsOptions, handler, done)`（或 `websocket_blocking`）在客户端的连接
上与普通请求并存地打开一个 WebSocket：它先等待服务端的 SETTINGS，服务端应答 `200` 后 `done` 拿到
`WsSender`（否则为 `H3Error::Status`）。

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:websocket}}
```

### QPACK 动态表

QPACK（RFC 9204）用一张由各自编码器通过 encoder stream 填充的表来压缩重复的头部字段。
`H3Config`（服务端）和 `H3ClientOptions`（客户端）中：

- `qpack_max_table_capacity`（4096）和 `qpack_blocked_streams`（16）：对端编码器可以对我方解码器
  使用多少。引用了尚未收到的插入的字段段会等待它们，最多到 blocked streams 上限；确认通过我方
  decoder stream 发回。nghttp3（curl）和 OpenSSL QUIC 等对端一旦看到这张表就会使用。容量设为 0
  则只允许静态引用和字面量。
- `qpack_encoder_capacity`（0，关闭）：我方编码器的表，最多为对端允许的容量。它只引用对端已确认的
  条目，所以从不让对端等待；只插入会重复的字段（不插路径、日期、长度、校验器、凭据和 cookie）。
  在携带大量相同自定义字段的连接上它能省字节，代价是每个消息一次加锁；quic-go 和 fib 不宣告动态表，
  与它们通信时它不起作用。默认值的理由见
  [ADR-011](https://github.com/lesismal/only/blob/main/docs/adr/011-h3-websocket-qpack-streaming.zh-CN.md)。

## HTTP/3 如何复用 only-http

only-http 提供了一个 transport 钩子 `only_http::transport`：transport 解析出请求后用连接的
`ConnSink` 调用 `dispatch_conn(service, request, sink, tag)`，sink 用它自己的方式把响应写给 tag
指明的请求（完整响应用 `send`，流式响应用 `start_stream` 返回一个 `BodySink`）。sink 由连接的
所有请求共享（经瘦句柄 `SharedSink`），请求 target 用 `request_target` 写进按线程保留的已完成请求的缓冲，所以两者都不再每请求分配一次
（ADR-025；旧的装箱 `ResponseSink` 与 `dispatch` 已弃用）。only-h3 在 QUIC stream 上实现了这个
sink，所以 router、中间件和 handler 都无需改动。见[架构](../architecture.md)。

一个请求的开销：帧直接在收到的流数据上原地读取，字段段解码进连接复用的缓冲区，再复制一次进请求的
`Headers`；响应的 HEADERS 帧直接用 QPACK 编码进交给 QUIC 的缓冲区，不超过 16 KiB 的响应体和 trailer
也放在一起（每个响应只写一次；更大的响应体随后发送，不复制）。在 Ryzen 7 7800X3D 上，单连接 64 个请求
在途约 84 万请求/秒（[性能测试](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md)）。

## 尚未完成

服务端推送；HTTP/2 上的 WebSocket（RFC 8441）；客户端的流式响应（`H3Client` 缓冲响应）；我方 QPACK
编码器的 Duplicate 指令和动态名称引用。
