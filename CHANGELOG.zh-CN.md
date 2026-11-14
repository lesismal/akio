# 变更日志

[English](CHANGELOG.md)

flash 的所有重要变更都记录在这里。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，flash 从 1.0.0 起遵循
[语义化版本](https://semver.org/lang/zh-CN/)，具体定义见
[docs/api-stability.zh-CN.md](docs/api-stability.zh-CN.md)。弃用遵循
[docs/deprecation.zh-CN.md](docs/deprecation.zh-CN.md)。workspace 中所有 crate 共用一个版本号。

## [Unreleased]

### 新增

- `flash-media`（M7 流媒体），新 crate：一个流 hub，周围是 RTMP、RTSP、SRT、HTTP-FLV、WS-FLV、HLS
  以及 WHIP/WHEP 信令。
  - `hub`：按路径区分的流，一个推流者多个订阅者，用于秒开的 GOP 缓存，`Dropper`（慢播放者丢帧至下一个
    关键帧），推流 / 播放鉴权钩子，轨道未知前先预留路径，等待（重新）推流者，`Timeline` 时间戳规整，
    按流统计。
  - RTMP 服务端：简单握手与 Flash digest 握手、chunk 流、推流 / 播放、Enhanced RTMP（H.265 `hvc1`、
    Opus）；AMF0 / AMF3；FLV 封装 / 解封装（传统与增强 tag）。
  - HTTP-FLV 与 WS-FLV 播放（`HttpFlv`），MPEG-TS 分段的 HLS，支持 LL-HLS 分片、预加载提示与阻塞式刷新
    （`Hls`），同时分发二者的 `MediaHttp`；MPEG-TS 封装器。
  - RTSP 1.0 服务端（ANNOUNCE/RECORD、DESCRIBE/SETUP/PLAY，支持 TCP 交织与 UDP，Digest/Basic 鉴权），
    H.264/H.265/AAC/Opus/G.711 的 RTP 打包与解包（为带 B 帧的视频推算解码时间），SDP，以及带
    `WebRtcEngine` 集成 trait 的 WHIP/WHEP HTTP 信令。
  - SRT live 模式（HSv5 主叫/监听、ARQ、TSBPD、基于密码的 AES-CTR 加密、stream ID 访问控制），提供基于
    hub 的 `SrtServer` 与 `srt::dial` / `push` / `pull`；增量式 MPEG-TS 解复用器（`mpegts::demux`）。
  - 已与作为推流端和播放端的 ffmpeg / ffprobe 互通测试（SRT 在 Docker 中使用 libsrt）；模糊测试目标
    `rtmp_server`、`flv_demux`、`amf_decode`、`rtsp_server`、`sdp_parse`、`rtp_depacketize`、
    `mpegts_demux`、`srt_listener`、`srt_conn`。
- `flash_ws::WsSender::queued_bytes`，供向慢速对端推流的生产者控制节奏。

## [1.0.0-rc.1] - 2026-11-14

1.0 的第一个发布候选版：API 冻结以供评审。每个 crate 的公开 API 记录在 `api/<crate>.txt` 中，并在
CI 中检查。

### 新增

**核心引擎（M0–M1）**
- 每核一线程的事件循环：每个 I/O 线程拥有自己的 reactor、连接、缓冲区和定时器轮；回调直接在所属
  线程上运行，因此连接级 handler 状态无需加锁（ADR-001..004）。
- `Handler` / `Acceptor` / `fn_acceptor`，以及 `Conn`：可克隆的 `Send + Sync` 句柄，提供 `send`、
  `send_owned`、`send_shared`（`SharedBuf`）、`send_segments`、`cork`/`flush`、
  `close`/`close_after_send`、`hold_reads`、`on_drain`；连接关闭后使用句柄返回 `Error::Closed`。
- 后端：`flash-epoll` 中的 epoll（Linux）与 kqueue（macOS）；`SO_REUSEPORT` 分发 accept；异步
  `Engine::dial`。
- 背压（写高水位、`max_queued_bytes`）、空闲与写超时、连接数上限、带超时的优雅停机。
- 连接发送路径的 `loom` 模型；5,000 个同时连接与 100,000 个空闲连接的压力测试。

**逻辑线程池、io_uring、UDP、TLS（M2）**
- `flash-pool` 自适应有界线程池；`Conn::spawn_blocking`，完成回调回到连接所属 I/O 线程；有序响应
  槽（`Conn::reserve_response`、`ResponseSlot`、`ResponseStream`）。
- 慢回调检测（`Config::slow_callback_threshold`、`slow_hook`）。
- `flash-uring`：io_uring 后端（multishot accept/recv、provided-buffer ring、内核探测并回退到
  epoll）；按 listener 选择后端（`Listener::backend`）。
- UDP：`Listener::udp`（每个对端一个 `Conn`）、`Engine::dial_udp`、`recvmmsg`/`sendmmsg`、UDP
  GSO/GRO、`udp_max_peers`。
- `flash-tls`：rustls 作为 `Conn` 之下的 sans-io 传输层（`Tls::server`、`Tls::client`、`tls_info`）。

**HTTP 与 WebSocket（M3）**
- `flash-http`：支持 pipelining、chunked 消息体与 trailer、流式请求与响应体的 HTTP/1.1 服务器，
  `Router`（静态 > `:param` > `*wildcard`、正则参数、嵌套、layer），中间件（recover、request id、
  CORS、logger、response time、compress、etag、csrf、limiter），静态文件（`files::Files`：range、
  预压缩文件、缓存、`sendfile`），HTTP/1 客户端（`client::Client`、`ResponseFuture`）。
- `flash-ws`：RFC 6455 及 permessage-deflate、`PreparedMessage` 广播、子协议、origin 检查；服务端
  升级（`Context::upgrade_websocket`）与客户端（`flash_ws::client`）；Autobahn 测试全部通过。

**HTTP/2 与更多协议（M4）**
- 基于同一 `Service` 的 HTTP/2 服务器（h2c prior knowledge 与 upgrade、ALPN `h2`、流量控制、HPACK、
  push）以及 `h2client::H2Client`；h2spec 全部通过。
- `flash-mux`（一个端口上的多种协议）、`flash-arpc`（lesismal/arpc 线上格式）、`flash-grpc`（基于
  flash-http 的 unary 与流式 gRPC、gzip、deadline、拦截器、可选 prost 辅助）、`flash-socks`
  （SOCKS5/4/4a 与 HTTP CONNECT）。

**QUIC、HTTP/3、KCP、eBPF（M5）**
- `flash-quic`（在 flash UDP 上驱动 quinn-proto）与 `flash-h3`（带 QPACK 的 HTTP/3，客户端与服务端）。
- `flash-kcp`：与 skywind3000/kcp 和 kcp-go 兼容的 KCP（加密、Reed–Solomon FEC）。
- `flash-ebpf`：通过 `Accel::Ebpf` 按 CPU 或一致性哈希的 `SO_REUSEPORT` 分流（经典 BPF 无需特权，
  有特权时用 eBPF），以及内核内的 sockmap `Relay`。

**生产就绪（M6）**
- 遥测：每线程计数器、`Engine::metrics`（Prometheus 与 JSON）、连接表、慢回调环形记录、设置热更新
  （`Engine::reload`）、`flash_http::observe` 端点与 HTTP 指标。
- 带种子的混沌测试（engine、fd 耗尽、TLS、HTTP/WebSocket）。

**1.0 稳定化**
- 21 个 fuzz 目标及语料和覆盖率报告；`cargo-deny`/`cargo-audit` 门禁；unsafe 审查
  （docs/unsafe-review.zh-CN.md）、Miri 与 sanitizer job；严格的 lint 集；中英文 mdBook 指南及迁移
  指南；基准测试报告。
- API 冻结：`docs/api-stability.zh-CN.md`（semver、MSRV 与平台策略）、`docs/deprecation.zh-CN.md`、
  本变更日志、由 CI job `public-api` 检查的公开 API 快照（`api/*.txt`、`tools/api/public-api.sh`），
  以及在 1.0.0 发布后生效的 `semver-checks` job。
- 评审新增的 API：`AnyAcceptor` 与 `Listener::serve_any`（类型擦除的 acceptor，`flash-mux` 使用）；
  `Request::new`、`ClientRequest::new`/`body`、`FileBody::new`；`flash` 再导出 `Part`、
  `ResponseStream`、`Transport` 和 `SharedBuf`（`flash-core` 也再导出 `SharedBuf`）；
  `flash_h3::H3Error`；`InflateError`、`ProtocolError`（ws）、`FrameError`（arpc）和 `QpackError`
  实现 `Display`/`Error`；`flash_core::Error::source` 返回底层 I/O 错误。
- 每个公开类型都实现 `Debug`；构建器方法带 `#[must_use]`。

### 变更（破坏性，附迁移方式）

配置与报告结构体以及将会增长的枚举现在是 `#[non_exhaustive]`：在 flash 之外不能再使用结构体
字面量。从 `Default`（或预设）开始，再给字段赋值：

```rust
// 之前
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// 之后
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

受影响的结构体：`flash`：`Config`、`UringConfig`、`EbpfConfig`、`PoolConfig`、`PoolStats`、
`SlowCallback`、`UdpStats`、`ConnInfo`、`LoopMeta`、`LoopCounters`、`LoopMetrics`、`Metrics`、
`ReloadReport`、`SlowRecord`；`flash-tls`：`TlsInfo`；`flash-http`：`HttpConfig`、`H2Config`、
`H2Options`、`WsOptions`、`Request`、`Response`、`FileBody`、`ClientRequest`、`ClientResponse`、
`Cors`、`Compress`、`LogRecord`、`HttpSnapshot`；`flash-ws`：`WsConfig`、`DialOptions`、`PmdOffer`、
`PmdParams`、`ProtocolError`；`flash-grpc`：`CallOptions`、`Status`、`Metadata`；`flash-kcp`：
`KcpConfig`、`Stats`；`flash-h3`：`H3Config`；`flash-ebpf`：`AttachOptions`、`SteerInfo`、`Probe`；
`flash-arpc`：`proto::Message`。枚举（`match` 需加通配分支）：`flash::Error`、`Part`、`Backend`、
`Accel`、`AccelStatus`、`flash_http::Method`、`Version`、`BodyMode`、`ClientError`、
`flash_ws::client::WsClientError`、`deflate::InflateError`、`flash_mux::Rule`、
`flash_arpc::CallError`、`proto::Cmd`、`flash_quic::Error`、`flash_h3::qpack::QpackError`、
`flash_kcp::KcpError`、`CloseReason`、`flash_ebpf::Steering`、`HashKey`、`Tier`。

重命名与签名变更：

| Crate | 之前 | 之后 |
|---|---|---|
| flash | `Listener::serve_dyn(Arc<dyn DynAcceptor>)`（隐藏） | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| flash-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor`（另有 `From<Mux> for AnyAcceptor`；可直接把 `Mux` 传给 `serve_any`） |
| flash-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| flash-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| flash-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| flash-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| flash-ws | `client::connect(..)`（阻塞） | `client::dial_blocking(..)` |
| flash-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| flash-arpc | `dial(..)`（阻塞） | `dial_blocking(..)` |
| flash-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| flash-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)`（与 `GrpcServer::compress` 同名） |
| flash-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| flash-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| flash-h3 | `server(quic, service)` | `serve(quic, service)` |
| flash-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)`（配置在 service 之前，与 `flash_http::serve_with` 一致） |
| flash-h3 | `H3Config::max_body`、`max_field_section` | `max_body_bytes`、`max_field_section_bytes` |
| flash-h3 | `request`、`request_blocking`、`get` 返回 `Result<Response, String>` | `Result<Response, H3Error>`（`Closed`、`Reset(code)`、`Protocol`、`Timeout`） |
| flash-kcp | `Config` | `KcpConfig` |
| flash-kcp | `KcpServer::new`、`dial`、`dial_conv`、`Crypt::new` 返回 `Result<_, String>` | `std::io::Result<_>`（设置有误时为 `InvalidInput`） |
| flash-kcp | `Kcp::stats: [u64; 4]`（公开字段） | 改为私有；请用 `Session::stats()` |
| flash-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| flash-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

移出受保护 API（现为 `#[doc(hidden)]`；面向后端或测试的辅助，可能在任何发布中变化）：
`flash_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter, telemetry::json_str,
telemetry::prometheus_header}` 以及仅供后端使用的 `Telemetry` 方法、`flash::{DynAcceptor,
DynHandler}` 再导出、`flash_http::transport`、`flash_ws::WsSession`、
`flash_ebpf::{cbpf, SLOTS, slot_table, expected_index}`。

版本：所有 crate 均为 `1.0.0-rc.1`，相互之间以精确（`=`）版本依赖；`flash-sys`、`flash-buf`、
`flash-timer`、`flash-pool`、`flash-epoll` 和 `flash-uring` 是内部 crate，自身不作 semver 承诺
（见 docs/api-stability.zh-CN.md）。

[Unreleased]: https://github.com/lesismal/flash/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/flash/releases/tag/v1.0.0-rc.1
