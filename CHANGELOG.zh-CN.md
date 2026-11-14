# 变更日志

[English](CHANGELOG.md)

flash 的所有重要变更都记录在这里。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，flash 从 1.0.0 起遵循
[语义化版本](https://semver.org/lang/zh-CN/)，具体定义见
[docs/api-stability.zh-CN.md](docs/api-stability.zh-CN.md)。弃用遵循
[docs/deprecation.zh-CN.md](docs/deprecation.zh-CN.md)。workspace 中所有 crate 共用一个版本号。

## [Unreleased]

### 新增

- `flash-prefork`（M6，可选）：用多个 worker 进程服务同一个程序。supervisor 以 N 个 worker 的身份重新执行
  当前二进制（不在多线程之后 fork），每个 worker 运行自己的 `Engine`；监听套接字通过 `SO_REUSEPORT`
  共享（Linux 默认），或从 supervisor 继承（`ListenMode::Inherit`，macOS 默认；重启与重载期间不拒绝任何
  连接）；崩溃的 worker 按指数退避重启；SIGTERM/SIGINT 让 worker 排空后退出，SIGHUP（或
  `Supervisor::reload`）启动新一代 worker，并在替代者就绪后停止对应的旧 worker；可选 CPU 绑核（Linux）；
  `Worker` 提供序号、worker 数与代数。示例 `prefork-http`，手册章节“多进程服务（prefork）”。
- `flash::Listener::tcp_from_std`：服务一个已绑定并在监听的套接字（从 supervisor 继承、systemd socket
  activation）；内部的 `EpollGroup::bind_listener` / `UringGroup::bind_listener`。
- `flash-sys`（内部）：`process` 模块（在 `pre_exec` 中让子进程继承 fd、设置 CPU 亲和性与父进程退出信号，
  `take_inherited_fd`、`reserve_reuseport`、self-pipe 方式的 `signal_pipe`、`kill`）。

### 修复

- io_uring：优雅关闭期间，multishot accept 在取消生效前已完成接受的连接会被重置；现在它们会被服务
  （收到第一份数据后调用 `on_shutdown`），并且排空要等 accept 真正结束才完成，监听套接字因此确实被关闭。
- `flash-dpdk`（实验性，M6）：内核旁路后端。用户态 TCP/IP 协议栈（smoltcp，IPv4）运行在 flash 的
  I/O 线程上，底层可以是 DPDK 端口（按 `EalConfig` 初始化 EAL，每个 rx/tx 队列对一个线程，mbuf
  批量收发，多队列时用 RSS 并在队列间扇出 ARP）、Linux TAP 接口、AF_PACKET socket 或进程内的
  `MemoryWire`。UDP listener 每次 `on_data` 交付一个数据报，TCP listener 交付字节流，支持
  `dial` / `dial_udp`、背压、空闲超时、遥测与优雅关闭，因此协议 crate（flash-kcp 等）无需修改即可
  运行。同一设备上的多个 listener 共享该设备的协议栈与线程。
- `flash`：cargo feature `dpdk`（`Backend::Dpdk(DpdkConfig)`，再导出 `flash::dpdk`）与 `dpdk-pmd`
  （同时支持 DPDK 端口；通过 pkg-config 查找并链接 libdpdk）。实验性：不在 semver 承诺范围内
  （docs/api-stability.zh-CN.md）。
- `flash-core`（面向后端，`#[doc(hidden)]`）：`ConnInner::new_virtual` 与
  `ConnInner::drain_output`，供由用户态协议栈搬运字节的连接使用。
- `tools/dpdk/`（Dockerfile + `test.sh`）与重型 CI 任务 `dpdk`：基于发行版的 DPDK 构建，并通过
  DPDK 的 `net_tap` PMD（单队列与双队列）smoltcp 的 TAP 设备以及 veth 对上的 AF_PACKET，与内核协议栈互测 UDP/TCP echo。
- `Engine::bind_udp` 与 `UdpBinding`（flash、flash-core）：在引擎运行中绑定的非连接 UDP socket，
  像 UDP 监听器一样服务（每个对端地址一个连接），并可用 `UdpBinding::send_to` 向任意地址发送。
  ICE agent 与 TURN 中继需要它。
- `flash-turn`（新 crate）：STUN 编解码（RFC 8489，含 TURN 与 ICE 属性、`MESSAGE-INTEGRITY`、
  `FINGERPRINT`）、`StunServer`，以及 UDP 上的 TURN 中继 `TurnServer`（RFC 8656）：长期凭据的分配
  （`static_auth`，以及用于 TURN REST API 的 `ephemeral_auth`）、权限、通道、Send/Data 指示、刷新、
  `EVEN-PORT` 与 `RESERVATION-TOKEN`、无状态 nonce、配额，以及默认拒绝私有与回环对端的对端策略；
  `TurnCore` 是同一服务器的 sans-io 状态机。互通：pion/turn 客户端与 coturn 的
  `turnutils_uclient`。
- `flash-webrtc`（新 crate）：基于 sans-io 的 `str0m` 0.24、跑在 flash UDP 上的 WebRTC。
  `RtcServer` 服务一个 UDP 监听器（默认 ICE-lite，按 ICE 用户名与源地址分流各 peer）；`Endpoint`
  在 `bind_udp` socket 上运行完整 ICE agent，可从 STUN 服务器获取 server-reflexive 候选。`Peer`
  （任意线程）可在数据通道上发送、写媒体、请求关键帧、重新协商；`PeerHandler` 回调对每个 peer
  逐个执行。DTLS 1.2/1.3 与指纹校验、SRTP（AES-CM、AES-GCM）、SCTP 数据通道（可靠或不可靠、
  有序或无序）、带 NACK、PLI/FIR、TWCC 的 RTP/RTCP。纯 Rust 加密实现（RustCrypto 与 `dimpl`，
  无需 C 工具链）。与 pion 互通（两种 offer 方向的数据通道与媒体，以及经 flash TURN 中继），并与 fib
  的 Go 版 WebRTC 互通（数据通道）；
  `tools/interop/webrtc/run.sh`。
- 模糊测试目标 `stun_message`、`turn_server` 与 `webrtc_sdp`。
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
- `flash-bittorrent`（M7）：bencode；v1 .torrent 文件（路径安全检查、`Builder`）与磁力链接；HTTP
  与 UDP tracker 的编解码、`TrackerClient`（flash-http、`dial_udp`）和 `TrackerServer`（共用一个
  存储的 flash-http service 与 UDP acceptor）；带 Fast 扩展、扩展协议、ut_metadata 和 ut_pex 的
  peer wire 协议；MSE/PE（DH-768、RC4）；带 LEDBAT 的 uTP；主线 DHT；`port::UdpPort`，让 uTP 与
  DHT 共用一个 flash UDP listener；以及 `client::Client`（磁力链接、带残局模式的最稀有优先选片、
  请求流水线、带乐观 unchoke 的 choke 算法、在逻辑池上进行的存储与 SHA-1 校验、PEX、DHT、
  tracker、事件）。与 libtorrent 2.0 和 aria2 1.37 互通（`tools/interop/bittorrent/run.sh`）；
  模糊测试目标 `bt_bencode`、`bt_peer_wire`、`bt_krpc`、`bt_utp`、`bt_tracker`、`bt_mse`。
- `Engine::dial_udp_from`：在 UDP listener 自己的 socket 上建立对端连接，使发往新地址的数据报从
  listener 的端口发出（DHT 节点、uTP）。

### 修复

- 当 engine 同时有 TCP listener 与 UDP listener（或 UDP 客户端线程）但没有 `client_threads` 时，
  `Engine::dial` 不再选中 UDP group（并因此失败）。

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
