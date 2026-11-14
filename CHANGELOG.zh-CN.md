# 变更日志

[English](CHANGELOG.md)

only 的所有重要变更都记录在这里。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，only 从 1.0.0 起遵循
[语义化版本](https://semver.org/lang/zh-CN/)，具体定义见
[docs/api-stability.zh-CN.md](docs/api-stability.zh-CN.md)。弃用遵循
[docs/deprecation.zh-CN.md](docs/deprecation.zh-CN.md)。workspace 中所有 crate 共用一个版本号。

## [Unreleased]

### 更名：项目现在叫 `only`

crates.io 上的 `flash` 名称已被占用，因此项目从 **flash** 更名为 **only**（DEV-PLAN“1.0.0 发布决定”）。
所有 crate、路径、标识符与名称随之改变；下面的条目已经使用新名称。

| 之前 | 之后 |
|---|---|
| crate `flash`（`use flash::...`） | `only`（`use only::...`） |
| crate `flash-*`（代码中为 `flash_*`），目录 `crates/flash-*` | `only-*`（`only_*`）、`crates/only-*`：`flash-sys` → `only-sys`、`flash-buf` → `only-buf`、`flash-timer` → `only-timer`、`flash-pool` → `only-pool`、`flash-core` → `only-core`、`flash-epoll` → `only-epoll`、`flash-uring` → `only-uring`、`flash-tls` → `only-tls`、`flash-http` → `only-http`、`flash-ws` → `only-ws`、`flash-mux` → `only-mux`、`flash-socks` → `only-socks`、`flash-arpc` → `only-arpc`、`flash-grpc` → `only-grpc`、`flash-kcp` → `only-kcp`、`flash-quic` → `only-quic`、`flash-h3` → `only-h3`、`flash-ebpf` → `only-ebpf`、`flash-prefork` → `only-prefork`、`flash-dpdk` → `only-dpdk`、`flash-turn` → `only-turn`、`flash-webrtc` → `only-webrtc`、`flash-media` → `only-media`、`flash-bittorrent` → `only-bittorrent` |
| 环境变量 `FLASH_*`（`FLASH_TEST_BACKEND`、`FLASH_UDP_GSO`、`FLASH_UDP_GRO`、`FLASH_PREFORK_*`、`FLASH_CHAOS*`、`FLASH_DPDK_*` 等） | `ONLY_*` |
| Prometheus 指标 `flash_*`（`flash_connections_open`、`flash_http_requests_total`、`flash_tls_handshake_failures_total` 等） | `only_*` |
| 日志 target `flash`、`flash_http::access`、`flash_webrtc` 等 | `only`、`only_http::access`、`only_webrtc` 等 |
| 线程名 `flash-io-*`、`flash-pool`、`flash-quic-timer` 等 | `only-io-*`、`only-pool`、`only-quic-timer` 等 |
| `flash_media::srt` 中的别名 `FlashConn` | `OnlyConn` |
| API 快照 `api/flash-*.txt`、工具的 Docker 镜像与卷 `flash-*` | `api/only-*.txt`、`only-*` |

在仓库本身改名之前，GitHub 仓库与文档站点仍使用 `lesismal/only` 的 URL。

### 变更（破坏性，1.0.0 之前）：封装 1.0 之前的依赖

rustls 0.23、quinn-proto 0.11、str0m 0.24 与 prost 0.13 不再出现在受保护的 API 中，因此 1.0.0 之后
升级它们（或用自研代码替换）不是破坏性变更。直接访问移到新的 `unstable` cargo feature 之后（`only`、
`only-tls`、`only-quic`、`only-webrtc`），与 `only-grpc` 的 `prost` feature 一样不在 semver 承诺之内
（docs/api-stability.zh-CN.md，“公开依赖”）。

| 之前 | 之后 |
|---|---|
| `only::tls::rustls`（再导出） | 仅 `unstable` feature |
| `rustls::ServerConfig::builder()...with_single_cert(chain, key)` + `alpn_protocols` | `only::tls::ServerConfig::builder(chain, key).alpn([..]).build()?`（另有 `sni_cert`、`client_auth_required` / `_optional`、`session_cache`、`session_tickets`、`tls13_only`） |
| `rustls::ClientConfig::builder().with_root_certificates(roots)...` | `only::tls::ClientConfig::builder().roots(roots).alpn([..]).build()?`（另有 `client_cert`、`sni`、`resumption`、`tls13_only`、`insecure_skip_verify`） |
| `CertificateDer`、`PrivateKeyDer`、`RootCertStore` | `only::tls::{Certificate, PrivateKey, RootCerts}`（`from_pem`、`from_der`、`from_pkcs8_der`） |
| `Tls::server(Arc<rustls::ServerConfig>, a)`、`Tls::client(Arc<rustls::ClientConfig>, ..)` | `Tls::server(ServerConfig, a)`、`Tls::client(ClientConfig, ..)` |
| `Client::with_tls(Arc<rustls::ClientConfig>)`、`H2Client::dial(.., Some((Arc<..>, name)), ..)`、`DialOptions::tls: Option<Arc<..>>` | 同上，改用 `only::tls::ClientConfig` |
| `only_quic::{proto, rustls}` 再导出、`VarInt` | 仅 `unstable` feature（`proto`）；删除 `VarInt` |
| `only_quic::{StreamId, Dir, ConnectionError, TransportConfig}`（quinn 的类型） | only 自己的类型（另有 `Side`、`Congestion`、`UdpStats`）；`ConnectionError` 的变体改为结构体形式（`ApplicationClosed { code, reason }`、`TransportError { code, reason }`） |
| `Connection::stats() -> quinn_proto::ConnectionStats` | `ConnectionStats`（`udp_tx`、`udp_rx`、`rtt`、`cwnd`、`lost_packets` 等） |
| `server_config(Vec<CertificateDer>, PrivateKeyDer, alpn) -> quinn_proto::ServerConfig` | `server_config(Vec<Certificate>, PrivateKey, alpn) -> only_quic::ServerConfig`（`.transport(&TransportConfig)`、`.migration(bool)`） |
| `server_config_from(rustls::ServerConfig)`、`client_config(RootCertStore, ..)`、`client_config_from(rustls::ClientConfig)` | `server_config_from(&only::tls::ServerConfig)`、`client_config(RootCerts, ..)`、`client_config_from(&only::tls::ClientConfig)` |
| `Error::Connect(quinn_proto::ConnectError)` | `Error::Connect(String)` |
| `only_h3::server_config(Vec<CertificateDer>, PrivateKeyDer)`、`serve(quinn_proto::ServerConfig, ..)`、`H3Client::dial(.., quinn_proto::ClientConfig)` | `Certificate` / `PrivateKey`、`only_quic::ServerConfig`、`only_quic::ClientConfig` |
| `only_grpc::codec::{encode, decode}` 约束为 `prost::Message` | 约束为 `only_grpc::codec::Message`（`encode_to`、`decode_from`）；`prost` feature 为 prost 消息实现它 |
| `only_webrtc::str0m` 再导出、`Peer::with_rtc`、`crypto_provider`、`generate_certificate` | 仅 `unstable` feature（`str0m`、`with_rtc`、`crypto_provider_str0m`）；`generate_certificate` 改为内部函数 |
| str0m 的 `ChannelId`、`ChannelConfig`、`Reliability`、`Mid`、`Pt`、`MediaKind`、`Direction`、`Frequency`、`MediaTime`、`MediaData`、`MediaAdded`、`KeyframeRequest(Kind)`、`RtpPacket`、`Candidate`、`IceConnectionState`、`RtcConfig`、`Event` | 同名的 only 自有类型（`ChannelConfig` 为 `#[non_exhaustive]`：先 `ChannelConfig::new(label)` 再设置字段；`MediaData::data` / `RtpPacket::payload` 为 `Arc<[u8]>`） |
| `create_offer(h, \|api: &mut SdpApi\| ..)`、`renegotiate(..)`；`api.add_channel(label.into())`、`api.add_media(kind, dir, None, None, None)` | `SdpChanges`：`add_channel(label)`、`add_channel_with_config(&cfg)`、`add_media(kind, dir, None, None)`、`set_direction`、`stop_media`、`ice_restart` |
| `Peer::open_channel(ChannelConfig)`、`payload_type(mid, str0m::format::Codec)` | `open_channel(&ChannelConfig)`、`payload_type(mid, only_webrtc::Codec)` |
| `PeerHandler::on_event(&str0m::Event)` | `on_event(&Event)`：`Event::ChannelBufferedAmountLow(id)` 或 `Event::Other(OtherEvent)` |
| `Error::Rtc(str0m::RtcError)`、`impl From<str0m::RtcError> for Error` | `Error::Rtc(only_webrtc::RtcError)`；新增 `Error::InvalidCandidate` |
| `Endpoint::add_candidate(str0m::Candidate)` | `Candidate::host(addr)` / `server_reflexive(addr, base)` / `relayed(addr, base)` / `parse(sdp)` |

### 新增

- `only-prefork`（M6，可选）：用多个 worker 进程服务同一个程序。supervisor 以 N 个 worker 的身份重新执行
  当前二进制（不在多线程之后 fork），每个 worker 运行自己的 `Engine`；监听套接字通过 `SO_REUSEPORT`
  共享（Linux 默认），或从 supervisor 继承（`ListenMode::Inherit`，macOS 默认；重启与重载期间不拒绝任何
  连接）；崩溃的 worker 按指数退避重启；SIGTERM/SIGINT 让 worker 排空后退出，SIGHUP（或
  `Supervisor::reload`）启动新一代 worker，并在替代者就绪后停止对应的旧 worker；可选 CPU 绑核（Linux）；
  `Worker` 提供序号、worker 数与代数。示例 `prefork-http`，手册章节“多进程服务（prefork）”。
- `only::Listener::tcp_from_std`：服务一个已绑定并在监听的套接字（从 supervisor 继承、systemd socket
  activation）；内部的 `EpollGroup::bind_listener` / `UringGroup::bind_listener`。
- `only-sys`（内部）：`process` 模块（在 `pre_exec` 中让子进程继承 fd、设置 CPU 亲和性与父进程退出信号，
  `take_inherited_fd`、`reserve_reuseport`、self-pipe 方式的 `signal_pipe`、`kill`）。
- `only-deflate`（内部，DEV-PLAN“不依赖第三方”第 A 波）：纯安全 Rust、无依赖的 DEFLATE、zlib 与 gzip，
  替代 `only-ws`（permessage-deflate）、`only-http`（压缩中间件）与 `only-grpc`（gzip 消息）中的
  `flate2`/`zlib-rs`。流式 `Inflater`（任意拆分输入、有界输出、窗口 2^8..2^15、与 zlib 相同的编码检查）
  与 `Deflater`（哈希链、惰性匹配、zlib 级别 0..=9、限长动态 Huffman、固定或存储块、同步/完全刷新、
  窗口 2^8..2^15），以及 Adler-32 与 CRC-32。与 zlib-rs 和 `gzip(1)` 双向互通；模糊测试目标
  `deflate_inflate`（与 zlib-rs 差分）和 `deflate_roundtrip`；Miri 运行其测试，Miri 任务重新运行
  only-grpc 的 gzip 测试（docs/unsafe-review.zh-CN.md 中 zlib-rs 的别名问题不再适用）。其他 crate 的公开
  API 不变。
- `only-ws`：permessage-deflate 支持 8 位窗口。服务端接受 `server_max_window_bits=8`（以前会拒绝该提议），
  被告知 `client_max_window_bits=8` 的客户端会压缩（以前发送未压缩消息）；此时压缩器把距离限制在
  250 字节以内。`deflate::Deflater`、`deflate::Inflater` 与 `protocol::Decoder` 现在实现 `UnwindSafe`
  （不再持有 zlib-rs 状态）。

### 修复

- io_uring：优雅关闭期间，multishot accept 在取消生效前已完成接受的连接会被重置；现在它们会被服务
  （收到第一份数据后调用 `on_shutdown`），并且排空要等 accept 真正结束才完成，监听套接字因此确实被关闭。
- `only-dpdk`（实验性，M6）：内核旁路后端。用户态 TCP/IP 协议栈（smoltcp，IPv4）运行在 only 的
  I/O 线程上，底层可以是 DPDK 端口（按 `EalConfig` 初始化 EAL，每个 rx/tx 队列对一个线程，mbuf
  批量收发，多队列时用 RSS 并在队列间扇出 ARP）、Linux TAP 接口、AF_PACKET socket 或进程内的
  `MemoryWire`。UDP listener 每次 `on_data` 交付一个数据报，TCP listener 交付字节流，支持
  `dial` / `dial_udp`、背压、空闲超时、遥测与优雅关闭，因此协议 crate（only-kcp 等）无需修改即可
  运行。同一设备上的多个 listener 共享该设备的协议栈与线程。
- `only`：cargo feature `dpdk`（`Backend::Dpdk(DpdkConfig)`，再导出 `only::dpdk`）与 `dpdk-pmd`
  （同时支持 DPDK 端口；通过 pkg-config 查找并链接 libdpdk）。实验性：不在 semver 承诺范围内
  （docs/api-stability.zh-CN.md）。
- `only-core`（面向后端，`#[doc(hidden)]`）：`ConnInner::new_virtual` 与
  `ConnInner::drain_output`，供由用户态协议栈搬运字节的连接使用。
- `tools/dpdk/`（Dockerfile + `test.sh`）与重型 CI 任务 `dpdk`：基于发行版的 DPDK 构建，并通过
  DPDK 的 `net_tap` PMD（单队列与双队列）smoltcp 的 TAP 设备以及 veth 对上的 AF_PACKET，与内核协议栈互测 UDP/TCP echo。
- `Engine::bind_udp` 与 `UdpBinding`（only、only-core）：在引擎运行中绑定的非连接 UDP socket，
  像 UDP 监听器一样服务（每个对端地址一个连接），并可用 `UdpBinding::send_to` 向任意地址发送。
  ICE agent 与 TURN 中继需要它。
- `only-turn`（新 crate）：STUN 编解码（RFC 8489，含 TURN 与 ICE 属性、`MESSAGE-INTEGRITY`、
  `FINGERPRINT`）、`StunServer`，以及 UDP 上的 TURN 中继 `TurnServer`（RFC 8656）：长期凭据的分配
  （`static_auth`，以及用于 TURN REST API 的 `ephemeral_auth`）、权限、通道、Send/Data 指示、刷新、
  `EVEN-PORT` 与 `RESERVATION-TOKEN`、无状态 nonce、配额，以及默认拒绝私有与回环对端的对端策略；
  `TurnCore` 是同一服务器的 sans-io 状态机。互通：pion/turn 客户端与 coturn 的
  `turnutils_uclient`。
- `only-webrtc`（新 crate）：基于 sans-io 的 `str0m` 0.24、跑在 only UDP 上的 WebRTC。
  `RtcServer` 服务一个 UDP 监听器（默认 ICE-lite，按 ICE 用户名与源地址分流各 peer）；`Endpoint`
  在 `bind_udp` socket 上运行完整 ICE agent，可从 STUN 服务器获取 server-reflexive 候选。`Peer`
  （任意线程）可在数据通道上发送、写媒体、请求关键帧、重新协商；`PeerHandler` 回调对每个 peer
  逐个执行。DTLS 1.2/1.3 与指纹校验、SRTP（AES-CM、AES-GCM）、SCTP 数据通道（可靠或不可靠、
  有序或无序）、带 NACK、PLI/FIR、TWCC 的 RTP/RTCP。纯 Rust 加密实现（RustCrypto 与 `dimpl`，
  无需 C 工具链）。与 pion 互通（两种 offer 方向的数据通道与媒体，以及经 only TURN 中继），并与 fib
  的 Go 版 WebRTC 互通（数据通道）；
  `tools/interop/webrtc/run.sh`。
- 模糊测试目标 `stun_message`、`turn_server` 与 `webrtc_sdp`。
- `only-media`（M7 流媒体），新 crate：一个流 hub，周围是 RTMP、RTSP、SRT、HTTP-FLV、WS-FLV、HLS
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
- `only_ws::WsSender::queued_bytes`，供向慢速对端推流的生产者控制节奏。
- `only-bittorrent`（M7）：bencode；v1 .torrent 文件（路径安全检查、`Builder`）与磁力链接；HTTP
  与 UDP tracker 的编解码、`TrackerClient`（only-http、`dial_udp`）和 `TrackerServer`（共用一个
  存储的 only-http service 与 UDP acceptor）；带 Fast 扩展、扩展协议、ut_metadata 和 ut_pex 的
  peer wire 协议；MSE/PE（DH-768、RC4）；带 LEDBAT 的 uTP；主线 DHT；`port::UdpPort`，让 uTP 与
  DHT 共用一个 only UDP listener；以及 `client::Client`（磁力链接、带残局模式的最稀有优先选片、
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
- 后端：`only-epoll` 中的 epoll（Linux）与 kqueue（macOS）；`SO_REUSEPORT` 分发 accept；异步
  `Engine::dial`。
- 背压（写高水位、`max_queued_bytes`）、空闲与写超时、连接数上限、带超时的优雅停机。
- 连接发送路径的 `loom` 模型；5,000 个同时连接与 100,000 个空闲连接的压力测试。

**逻辑线程池、io_uring、UDP、TLS（M2）**
- `only-pool` 自适应有界线程池；`Conn::spawn_blocking`，完成回调回到连接所属 I/O 线程；有序响应
  槽（`Conn::reserve_response`、`ResponseSlot`、`ResponseStream`）。
- 慢回调检测（`Config::slow_callback_threshold`、`slow_hook`）。
- `only-uring`：io_uring 后端（multishot accept/recv、provided-buffer ring、内核探测并回退到
  epoll）；按 listener 选择后端（`Listener::backend`）。
- UDP：`Listener::udp`（每个对端一个 `Conn`）、`Engine::dial_udp`、`recvmmsg`/`sendmmsg`、UDP
  GSO/GRO、`udp_max_peers`。
- `only-tls`：rustls 作为 `Conn` 之下的 sans-io 传输层（`Tls::server`、`Tls::client`、`tls_info`）。

**HTTP 与 WebSocket（M3）**
- `only-http`：支持 pipelining、chunked 消息体与 trailer、流式请求与响应体的 HTTP/1.1 服务器，
  `Router`（静态 > `:param` > `*wildcard`、正则参数、嵌套、layer），中间件（recover、request id、
  CORS、logger、response time、compress、etag、csrf、limiter），静态文件（`files::Files`：range、
  预压缩文件、缓存、`sendfile`），HTTP/1 客户端（`client::Client`、`ResponseFuture`）。
- `only-ws`：RFC 6455 及 permessage-deflate、`PreparedMessage` 广播、子协议、origin 检查；服务端
  升级（`Context::upgrade_websocket`）与客户端（`only_ws::client`）；Autobahn 测试全部通过。

**HTTP/2 与更多协议（M4）**
- 基于同一 `Service` 的 HTTP/2 服务器（h2c prior knowledge 与 upgrade、ALPN `h2`、流量控制、HPACK、
  push）以及 `h2client::H2Client`；h2spec 全部通过。
- `only-mux`（一个端口上的多种协议）、`only-arpc`（lesismal/arpc 线上格式）、`only-grpc`（基于
  only-http 的 unary 与流式 gRPC、gzip、deadline、拦截器、可选 prost 辅助）、`only-socks`
  （SOCKS5/4/4a 与 HTTP CONNECT）。

**QUIC、HTTP/3、KCP、eBPF（M5）**
- `only-quic`（在 only UDP 上驱动 quinn-proto）与 `only-h3`（带 QPACK 的 HTTP/3，客户端与服务端）。
- `only-kcp`：与 skywind3000/kcp 和 kcp-go 兼容的 KCP（加密、Reed–Solomon FEC）。
- `only-ebpf`：通过 `Accel::Ebpf` 按 CPU 或一致性哈希的 `SO_REUSEPORT` 分流（经典 BPF 无需特权，
  有特权时用 eBPF），以及内核内的 sockmap `Relay`。

**生产就绪（M6）**
- 遥测：每线程计数器、`Engine::metrics`（Prometheus 与 JSON）、连接表、慢回调环形记录、设置热更新
  （`Engine::reload`）、`only_http::observe` 端点与 HTTP 指标。
- 带种子的混沌测试（engine、fd 耗尽、TLS、HTTP/WebSocket）。

**1.0 稳定化**
- 21 个 fuzz 目标及语料和覆盖率报告；`cargo-deny`/`cargo-audit` 门禁；unsafe 审查
  （docs/unsafe-review.zh-CN.md）、Miri 与 sanitizer job；严格的 lint 集；中英文 mdBook 指南及迁移
  指南；基准测试报告。
- API 冻结：`docs/api-stability.zh-CN.md`（semver、MSRV 与平台策略）、`docs/deprecation.zh-CN.md`、
  本变更日志、由 CI job `public-api` 检查的公开 API 快照（`api/*.txt`、`tools/api/public-api.sh`），
  以及在 1.0.0 发布后生效的 `semver-checks` job。
- 评审新增的 API：`AnyAcceptor` 与 `Listener::serve_any`（类型擦除的 acceptor，`only-mux` 使用）；
  `Request::new`、`ClientRequest::new`/`body`、`FileBody::new`；`only` 再导出 `Part`、
  `ResponseStream`、`Transport` 和 `SharedBuf`（`only-core` 也再导出 `SharedBuf`）；
  `only_h3::H3Error`；`InflateError`、`ProtocolError`（ws）、`FrameError`（arpc）和 `QpackError`
  实现 `Display`/`Error`；`only_core::Error::source` 返回底层 I/O 错误。
- 每个公开类型都实现 `Debug`；构建器方法带 `#[must_use]`。

### 变更（破坏性，附迁移方式）

配置与报告结构体以及将会增长的枚举现在是 `#[non_exhaustive]`：在 only 之外不能再使用结构体
字面量。从 `Default`（或预设）开始，再给字段赋值：

```rust
// 之前
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// 之后
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

受影响的结构体：`only`：`Config`、`UringConfig`、`EbpfConfig`、`PoolConfig`、`PoolStats`、
`SlowCallback`、`UdpStats`、`ConnInfo`、`LoopMeta`、`LoopCounters`、`LoopMetrics`、`Metrics`、
`ReloadReport`、`SlowRecord`；`only-tls`：`TlsInfo`；`only-http`：`HttpConfig`、`H2Config`、
`H2Options`、`WsOptions`、`Request`、`Response`、`FileBody`、`ClientRequest`、`ClientResponse`、
`Cors`、`Compress`、`LogRecord`、`HttpSnapshot`；`only-ws`：`WsConfig`、`DialOptions`、`PmdOffer`、
`PmdParams`、`ProtocolError`；`only-grpc`：`CallOptions`、`Status`、`Metadata`；`only-kcp`：
`KcpConfig`、`Stats`；`only-h3`：`H3Config`；`only-ebpf`：`AttachOptions`、`SteerInfo`、`Probe`；
`only-arpc`：`proto::Message`。枚举（`match` 需加通配分支）：`only::Error`、`Part`、`Backend`、
`Accel`、`AccelStatus`、`only_http::Method`、`Version`、`BodyMode`、`ClientError`、
`only_ws::client::WsClientError`、`deflate::InflateError`、`only_mux::Rule`、
`only_arpc::CallError`、`proto::Cmd`、`only_quic::Error`、`only_h3::qpack::QpackError`、
`only_kcp::KcpError`、`CloseReason`、`only_ebpf::Steering`、`HashKey`、`Tier`。

重命名与签名变更：

| Crate | 之前 | 之后 |
|---|---|---|
| only | `Listener::serve_dyn(Arc<dyn DynAcceptor>)`（隐藏） | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| only-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor`（另有 `From<Mux> for AnyAcceptor`；可直接把 `Mux` 传给 `serve_any`） |
| only-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| only-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| only-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| only-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| only-ws | `client::connect(..)`（阻塞） | `client::dial_blocking(..)` |
| only-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| only-arpc | `dial(..)`（阻塞） | `dial_blocking(..)` |
| only-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| only-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)`（与 `GrpcServer::compress` 同名） |
| only-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| only-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| only-h3 | `server(quic, service)` | `serve(quic, service)` |
| only-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)`（配置在 service 之前，与 `only_http::serve_with` 一致） |
| only-h3 | `H3Config::max_body`、`max_field_section` | `max_body_bytes`、`max_field_section_bytes` |
| only-h3 | `request`、`request_blocking`、`get` 返回 `Result<Response, String>` | `Result<Response, H3Error>`（`Closed`、`Reset(code)`、`Protocol`、`Timeout`） |
| only-kcp | `Config` | `KcpConfig` |
| only-kcp | `KcpServer::new`、`dial`、`dial_conv`、`Crypt::new` 返回 `Result<_, String>` | `std::io::Result<_>`（设置有误时为 `InvalidInput`） |
| only-kcp | `Kcp::stats: [u64; 4]`（公开字段） | 改为私有；请用 `Session::stats()` |
| only-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| only-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

移出受保护 API（现为 `#[doc(hidden)]`；面向后端或测试的辅助，可能在任何发布中变化）：
`only_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter, telemetry::json_str,
telemetry::prometheus_header}` 以及仅供后端使用的 `Telemetry` 方法、`only::{DynAcceptor,
DynHandler}` 再导出、`only_http::transport`、`only_ws::WsSession`、
`only_ebpf::{cbpf, SLOTS, slot_table, expected_index}`。

版本：所有 crate 均为 `1.0.0-rc.1`，相互之间以精确（`=`）版本依赖；`only-sys`、`only-buf`、
`only-timer`、`only-pool`、`only-epoll` 和 `only-uring` 是内部 crate，自身不作 semver 承诺
（见 docs/api-stability.zh-CN.md）。

[Unreleased]: https://github.com/lesismal/only/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/only/releases/tag/v1.0.0-rc.1
