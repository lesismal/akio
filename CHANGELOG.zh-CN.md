# 变更日志

[English](CHANGELOG.md)

only 的所有重要变更都记录在这里。格式遵循
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，only 从 1.0.0 起遵循
[语义化版本](https://semver.org/lang/zh-CN/)，具体定义见
[docs/api-stability.zh-CN.md](docs/api-stability.zh-CN.md)。弃用遵循
[docs/deprecation.zh-CN.md](docs/deprecation.zh-CN.md)。workspace 中所有 crate 共用一个版本号。

## [Unreleased]

### 新增：可扩展（L4S）的 CE 响应、RFC 6679 信令、经 TURN 的 ECN、DTLS 锁定、DTLS-SRTP MKI（only-rtp、only-webrtc）

ADR-082（docs/adr/082-webrtc-l4s-rfc6679-dtls-latching-mki.zh-CN.md），纯增量；默认行为不变：

- **对 CE 的可扩展响应。** only-rtp 新增 `EcnResponse::{Classic, Scalable}`，用
  `BandwidthEstimator::set_ecn_response` 设置。使用可扩展响应时，CE 不再算丢包：
  - CE 比例按往返轮次以 1/16 的增益平滑（`ce_fraction`；轮次来自 `set_rtt`）。
  - 它以 `alpha / 2` 削减第三个速率，每个窗口至多一次。
  - 没有 CE 的一轮让该速率线性增长。
  - 时延过载期间到达的 CE 仍算丢包（经典回退）。
  - `on_ecn_counts` 接收基于计数器的 ECN 反馈。

  only-webrtc 在标记 ECT(1) 时使用可扩展响应。标记期间，pacing 为估计值的 1.5 倍、突发 1 ms（原为 2.5
  倍与 40 ms）。在模拟的 6 Mbps L4S 队列中，ECT(1) 得到 4.9 Mbps、队列 1.3 ms；ECT(0) 为 1.36 Mbps，
  不用 ECN 时队列为 7.3 ms。
- **RFC 6679 信令。** 开启 ECN 标记时，各段提议并应答：
  - `a=ecn-capable-rtp:rtp mode=setread; ect=N`，
  - `a=rtcp-fb:<pt> nack ecn`，
  - `a=rtcp-xr:ecn-sum`。

  only-rtp 新增 `EcnFeedback`（RTPFB FMT 8）、`EcnSummary`（XR 块类型 13）、`EcnReceiver`、
  `EcnCounters` 与 `EcnDelta`。

  没有 RFC 8888 时，接收端报告每个源的计数器：收到第一个 ECT 包或 CE 标记时尽早发送，每次报告时发送，并在报告
  块旁附上摘要。发送端根据报告之间的差值验证路径，并把 CE 交给估计器。
- **经 TURN 的 ECN，TCP 路径上关闭。** 经 UDP 分配中继的 RTP 带着码点发往 TURN 服务器，RFC 8656 §12 要求服务器
  复制该码点。来自 UDP 分配的数据报保留其码点。ICE-TCP 候选以及经 TCP / TLS 的分配从不启动 ECN：它们保持关闭，
  而不是失败。
- **在 DTLS-SRTP 密钥存在之前锁定。** 无 ICE 且开启锁定时，来自未知源的 ClientHello 会得到一次无状态的 cookie
  交换。带 cookie 的 ClientHello 把路径对暂时移到该源。握手以 SDP 指纹完成后即锁定；握手失败、被关闭或 4 s
  超时时，路径对移回，peer 继续存活。锁定时把 `actpass` 提议应答为 `passive`。
- **DTLS-SRTP 的 SRTP MKI。** `RtcConfig::set_dtls_srtp_mki_length`：DTLS 客户端在 `use_srtp` 中提议 MKI，
  服务端同意客户端的 MKI，之后 SRTP / SRTCP 携带它。
- **互通与模糊测试。** `webrtc-interop` 新增 `ONLY_INTEROP_SIP=dtls` 与 `ONLY_INTEROP_DTLS_MKI`。
  `tools/interop/webrtc/latch.sh` 新增 DTLS-SRTP 话机用例。`rtp_rtcp` 模糊测试目标对 RFC 6679 格式做往返。

### 新增：带 GSS-API 保护的 SOCKS5 UDP ASSOCIATE（only-socks、only-ws）

ADR-071 的 2026-11-22 更新，API 没有变化：

- 有 GSS-API 逐消息保护时不再拒绝 `UDP ASSOCIATE`：客户端与转发端之间的每个数据报是一条用控制连接的上下文
  封装的 RFC 1961 封装数据消息（§5），服务端的转发、`SocksClient::udp_associate` 与
  `SocksClient::udp_associate_blocking`（现在接受保护）都如此；无法解封装的数据报被丢弃。
- `GssContext` 文档：`unwrap` 应接受乱序的令牌，因为数据报会丢失和乱序。
- `tools/interop/socks/gssapi.sh` 增加 UDP 用例：独立的 Python 客户端对 Dante 与 only-socks 服务端，
  only-socks 的客户端（engine 与阻塞）对两者，级别 0 到 2。共 27/27。

### 新增：压缩流式响应（only-http、only-brotli）

ADR-074（docs/adr/074-compressed-streamed-responses.zh-CN.md），只有新增：

- `Compress::stream: Option<StreamCompress>`（默认关闭）：`compress` 中间件也压缩流式响应
  （`Context::stream_response`），编码与缓冲响应一样按 `Accept-Encoding` 协商（br、提供时的 zstd、gzip、
  deflate），条件是状态码 200、可压缩的类型、没有 `Content-Encoding`；去掉 `Content-Length`，设置
  `Vary: Accept-Encoding`。每个流一个编码器，适用于 HTTP/1.1、HTTP/1.0、HTTP/2 和 HTTP/3。
- 每次 `BodyStream::write` 都编码并刷新（deflate 同步刷新，zstd 与 brotli 的 `Flush::Flush`），所以每个
  server-sent event 到达即可解码；`finish` 结束编码。默认值很小（`StreamCompress`）：gzip / deflate 1，
  zstd 1 配 `zstd_window_log` 17，brotli 4 配 `brotli_window_bits` 18：每个打开的流约 0.3、0.5 和 1.3 MiB。
- only-brotli 的流式 `Compressor` 在缓冲区积累两个窗口时滑动（原来要等一个窗口加一个 1 MiB 的元块），
  小窗口的流因此保持小：质量 4、窗口位数 18 时每个流从 2.0 MiB 降到 1.3 MiB。输出不变。
- 修复：`etag()` 给流式 200 响应打上空消息体的 ETag。
- 测量（在 gpu51 上与 main 同批 A/B。未设置 `stream` 时流式响应的速度与 main 相同（每响应 16 个
  小事件 0.999 倍，16 x 16 KiB 1.011 倍）；压缩时服务器 CPU 是瓶颈：gzip / zstd / br 每个 16 事件的响应
  多花 6 / 27 / 110 us（不压缩 17 us），每核 HTML 0.93 / 0.54 / 0.16 GB/s，事件字节压到 35% / 34% /
  26%，HTML 压到 18% / 6.1% / 5.4%。每个保持打开的流的服务器 RSS（1,000 个流）在 3 个事件后为 148 / 112 /
  424 KiB，6,000 个事件后为 268 / 324 / 1,106 KiB，不压缩时为 1.2-2.6 KiB；docs/BENCHMARKS.zh-CN.md）。

### 新增：以跳数限制 255 发送、可用于纯 IPv6 链路的 IPv6 mDNS（only-sys、only、only-webrtc）

ADR-078（docs/adr/078-mdns-ipv6-hop-limit-ipv6-only.zh-CN.md），只有新增：

- `only_sys::set_multicast_hops_v6` / `multicast_hops_v6`（`IPV6_MULTICAST_HOPS`，std 没有）。带 IPv6
  组的 `Engine::bind_udp_multicast_on` 现在以跳数限制 255 发送并打开组播回环，与 IPv4 路径以 TTL 255
  发送一致（RFC 6762 §11；设置 `check-response-ttl=yes` 的 avahi 会忽略以默认跳数限制 1 发出的 IPv6
  应答）。
- IPv4 或 IPv6 的 mDNS 套接字持有共享端口时，`Endpoint::conceal_host_candidates` 即可用：在纯 IPv6
  链路上（`224.0.0.251` 无路由）名字经 `ff02::fb` 应答，而不是调用失败。
- `tools/interop/webrtc/mdns6.sh`：纯 IPv6 容器（veth，链路本地与 ULA 地址）中在 epoll 与 io_uring 上
  运行 mDNS 测试，avahi 0.8 解析我方被隐藏的名字，并发布一个由我方解析并连通的名字；`browser.sh` 检查
  Chrome 157 与唯一主机候选为被隐藏 IPv6 地址的端点互通。`webrtc-interop` 新增 `mdns-conceal` 与
  `mdns-resolve` 模式。

### 新增：TURN TCP 分配，RFC 6062（only-turn）

ADR-076（docs/adr/076-turn-tcp-allocations.zh-CN.md）：

- 服务器：TCP 与 TLS 客户端可以请求 `REQUESTED-TRANSPORT` TCP。中继地址是一个监听中的 TCP socket（每个服务器
  一个接受线程轮询全部监听 socket，把连接交给引擎）；Connect 从中继地址向对端打开连接（446、447）；持有权限的
  对端连入时以 ConnectionAttempt 通告；在新的客户端连接上发送 ConnectionBind（同一凭据，接受控制连接的
  nonce）后，它变成通向对端的原始管道。已绑定的连接绕过分配分片；背压双向联动（`hold_reads` / `on_drain`），
  绑定前对端的字节最多保留到同一水位。未绑定的连接 30 秒后关闭；关闭任一侧即关闭另一侧；分配结束时全部关闭。
- `TurnConfig::{tcp_relays（true）, max_tcp_connections（64）, tcp_relay_buffer（64 KiB）}`、
  `TurnStats::tcp_connections`；`TurnEnv` 新增用于 TCP 中继与连接的带默认实现的方法，`TurnCore` 新增
  `tcp_connected`、`tcp_incoming`、`tcp_closed`。
- 客户端：`ClientConfig::tcp_allocation`、`Client::{connect, create_permission, data_connection}`、
  `ClientEvent::{Connected, ConnectFailed, ConnectionAttempt}`、`client::{DataConnection, DataState}`
  （sans-io 的 ConnectionBind，交回对端的首批字节）。
- STUN：`Method::{CONNECT, CONNECTION_BIND, CONNECTION_ATTEMPT}`、`attr::CONNECTION_ID`。
- 变更：经 UDP 或 DTLS 的 TCP Allocate 现在回 400（RFC 6062 第 5.1 节）而不是 442；UDP 与 TCP 之外的传输仍回 442。
- fuzz 目标 `turn_tcp`；`tools/interop/webrtc/turn-tcp.sh`：coturn 的 `turnutils_uclient -T` 对 only-turn，
  only_turn 客户端对 coturn、pion/turn 与 only-turn，pion/turn 的 TCP 分配客户端对 only-turn 与 coturn，经 TCP
  与 TLS。
- UDP 中继路径不变：gpu51 上与 main 同轮 A/B，`turn-relay-bench 8 6 4`（8 对，双向 100 字节数据报），quiet.sh 下交替 6 轮：平均总量 30.86 万 vs 26.80 万数据报/秒（1.15 倍；各轮波动约 ±20%，应理解为无回退而非提升）。

### 新增：ECN 可用的 RTP、无 ICE 媒体的锁定、无 BUNDLE 时的拥塞控制（only-webrtc、only-core、only-sys）

ADR-077（docs/adr/077-webrtc-ecn-latching-unbundled-cc.zh-CN.md），只有新增：

- ECN 可用的 RTP（`RtcConfig::set_ecn_marking(EcnMarking::{Ect0, Ect1})`，默认关闭）：在使用 RFC 8888
  反馈且带宽估计器运行时标记 RTP（从不标记 RTCP、STUN、DTLS 或 SCTP），先每四个包标记一个，直到有十个
  已标记包被报告带着标记到达，之后全部标记；标记被清除或改写，或已标记包丢失而未标记包没有丢失，都会
  停止该路径上的标记（RFC 6679 §7.2-7.4）；CE 对估计器按丢包计。按传输分别进行，换新路径重新开始。
  Chrome 157 接收 ECT(1) 并使路径通过验证（`tools/interop/webrtc/ecn.sh`）。
- 无 ICE 媒体的锁定（`RtcConfig::set_latching(Latching::{Once, Rebind(quiet)})`，默认关闭）：在传输的
  SRTP 密钥下通过认证（且通过重放检查）的 RTP / RTCP 包把该组件的地址对移到其来源；端点把来自未知来源的
  数据报交给正在锁定的 peer，只用于这一检查。`tools/interop/webrtc/latch.sh`：位于 iptables NAT 之后的
  SIP 风格话机，含重新绑定。
- 不做 BUNDLE 的会话重新协商 transport-cc 与 RFC 8888，并以一个估计器和一个 pacer 处理所有传输的反馈：
  RFC 8888 按传输进行；传输级序号跟随远端的编号方式（一个空间，如 libwebrtc / Chrome；或在远端表现出
  按传输编号后每个传输一个空间），按传输的结果经对齐和排序后交给估计器；排队的包、填充和探测都从各自的
  传输发出。
- `PeerStats` 新增 `ecn_marked_sent`、`ecn_failures`、`ecn_state`、`latched`、`twcc_spaces`。only-core：
  `UdpBinding::send_to_ecn`（文档隐藏）；only-sys：Linux 上的 `send_to_ecn`。
- 行为变化：不做 BUNDLE 的会话的 offer 与 answer 带有 transport-cc / `ack ccfb`（ADR-072 曾去掉它们）。
- 工具：`webrtc-bench` 示例（两个回环 `Endpoint` 之间的媒体 / 数据通道吞吐）；`webrtc-interop` 新增
  `sip-gateway`、`client … sip`、fec-server 的 `direct` 以及 `ONLY_INTEROP_{ECN,LATCH,SIP,BWE}`。

### 新增：AES-128 的 I 帧播放列表、RTSP RECORD 会话的 RTCP 同步、rendition report 的查询串（only-media）

ADR-075（docs/adr/075-media-aes-iframes-record-sync-report-queries.zh-CN.md）：

- AES-128 下的 HLS I 帧播放列表（此前 `HlsConfig::iframe_playlist` 在此被忽略）：每个 I 帧是
  独立资源 `/<path>/iframe-<n>.ts`（`.m4s`），即 ADR-070 的范围所指字节，用其分片的密钥整体
  加密，IV 为它在 I 帧播放列表中的媒体序列号；列表中不带 `EXT-X-BYTERANGE`，位于其分片的
  `EXT-X-KEY` 之后。随分片保存并计入 `max_bytes`。播放器无法解密 AES-128 分片中间的字节范围
  （分片中间没有 PKCS #7 填充）。明文 I 帧播放列表不再以 `EXT-X-KEY:METHOD=NONE` 开头。
- `RtspConfig::rtcp_sync`（新增，默认开启）：RECORD 会话按推流端的 RTCP 发送者报告对齐轨道，
  与客户端拉流相同（ADR-070）：交织 RTCP 通道、复用在 RTP 通道上的 RTCP、UDP 的 RTP 与 RTCP
  端口。`false` 保持之前按到达计时。
- 行为变更，hub：时间早于订阅者收到的第一个包的音频（任何非视频包）在音频达到该时间之前被
  丢弃，而不再交给会把它钳成同一时间戳的 sink（同步后的流与 AAC 预滚可能早于 GOP 的关键帧；
  ffmpeg 经 RTSP 播放时报告 DTS 非单调）。
- LL-HLS 的 `EXT-X-RENDITION-REPORT` URI 带上请求的查询串（去掉 `_HLS_` 指令），令牌因此能
  到达另一 rendition 的阻塞重载。
- 测试：AES-128 I 帧解密后等于未加密的范围（两种格式、分段、密钥轮换）；ffmpeg 把每个 AES-128
  I 帧解码为一帧源画面并能播放 I 帧播放列表；经 TCP、RTP 复用 RTCP 与 UDP 的 RECORD 会话收到
  偏斜的发送者报告（500 ms，早到与迟到；60 s 被忽略；关闭同步）。
  `tools/interop/media/hls-iframes.sh`：无头 Chrome 中的 hls.js 与 Shaka Player（fMP4 上的
  trick play）。`tests/client_bench.rs` 新增基准 `rtsp-record`。
- 与 main 在 gpu51 上同轮 A/B（`quiet.sh`，单个固定核心，交替 7 轮，取中位数，head / base）：hub 扇出 1.005 / 0.994 / 0.996（1 / 16 / 256 个订阅者；最初逐订阅者逐包检查新下限的版本在 256 时为 1.043，现在仅当有订阅者尚未越过下限时循环才检查）；RTSP RECORD 入流（新增 `rtsp-record`）1.007、RTSP 拉流 1.003、RTMP 拉流 0.996；`bench_segmenting` MPEG-TS 1.065、MPEG-TS LL-HLS 0.981、fMP4 0.961、fMP4 LL-HLS 1.020、AES-128 0.995 至 0.998、SAMPLE-AES MPEG-TS 1.015、`cbcs` 1.002。分片的逐包路径没有改动（独立加密的 I 帧、查询串与新路由都是按分片或按请求，且不在此基准中）；普通 MPEG-TS 与 fMP4 反向变化，`cbcs` 在仅 hub.rs 不同的两轮之间从 1.055 变为 1.002：属于代码布局。macOS aarch64 上同样的比较全部在 0.97 至 1.03 之间。

### 变更：brotli 块分割（only-brotli）

ADR-069 的 2026-11-22 补记，API 不变；从 4 级起输出有变化：

- 字面量、插入-复制符号与距离被分成块类型并写出块切换命令。10–11 级：Google 的迭代块分割器与直方图聚类，
  字面量与距离的上下文映射覆盖块类型与上下文，最多为窗口两倍的 meta-block（一次性压缩），11 级第二遍解析
  按块类型为字面量定价。4–9 级：对 64 KiB 及以上的 meta-block 使用 Google 一遍完成的贪心分割器，只有省下
  meta-block 的 1% 时才保留。
- 11 级在 Silesia 前 20 MB 上从比 libbrotli 1.2.1 大 4.7% 变为小 4.5%，10 级从 +7.6% 变为 +0.8%；
  HTTP 负载上 11 级为 +0.9–1.3%（之前 +0.9–2.6%），证书链不变；4–9 级在 Silesia 上小 0.2–0.75%，在混合
  数据上小 3–4.4%，HTTP 负载逐字节相同（docs/BENCHMARKS.zh-CN.md，“brotli 块分割”）。
- 10–11 级在 Silesia 上慢约 30%（文本与证书链上不变），4 级在 Silesia 上慢 12%，在 64 KiB 以上最终未分割
  的负载上慢 1–6%；1 级不变。解码器不变；带块类型的流与 libbrotli 的流一样解码。
- 测试：4–11 级找到并写出块类型，CLI 互通测试加入交错语料，`brotli_roundtrip` 加入产生多块类型流的种子。

### 新增：机制由应用提供的 SOCKS5 GSS-API 认证（only-socks、only-ws）

ADR-071（docs/adr/071-socks-gssapi-pluggable-mechanism.zh-CN.md），只有新增：

- 服务端（`Socks::gssapi(factory, levels)`）与客户端（`SocksClient::gssapi(factory, level)`）实现
  RFC 1961（方法 1）：上下文建立、保护级别协商，以及在 `Protection::Integrity` /
  `Protection::Confidentiality` 下对请求、应答与整个隧道的封装（`Protection::None`：只认证）。GSS-API
  机制由应用通过 `only_socks::gssapi::GssContext`（`step`、`wrap`、`unwrap`、`peer_name`）提供；workspace
  不链接任何 GSS-API 库。
- 建立步骤从不在 I/O 线程上执行：服务端在逻辑池中执行，客户端在辅助线程中执行并通过 `TransportWaker`
  恢复。服务端的访问钩子通过 `Request::user()` 看到 GSS-API 对端。GSS-API 服务端关闭 SOCKS4 与“无认证”。
- 有保护时拒绝：`UDP ASSOCIATE`（服务端回复 7；客户端拒绝经 GSS-API 的 UDP；此后已取消，见上一条）、
  客户端的阻塞辅助函数（代理
  授予的级别高于请求时也拒绝）、`sockmap` 拼接、放在 `Tls::server` 里的服务端。
- `tools/interop/socks/gssapi.sh`：Docker 中的 MIT Kerberos KDC、only-socks 客户端与服务端（经仅用于测试
  的 `python3-gssapi` 垫片）、重新编译并启用 GSS-API 的 Dante，以及一个独立的 RFC 1961 客户端：所有级别
  15/15。

### 新增：protobuf `utf8_validation = NONE`（only-protobuf、only-protobuf-build）

只有新增：

- 带 `features.utf8_validation = NONE` 的 `string` 字段生成为 `only_protobuf::ProtoString`（字节，解码时
  不检查 UTF-8：`to_str`、`to_string_lossy`、`as_bytes`；编解码器 `encoding::ProtoStringCodec`），各种形态
  （单个、repeated、map 的键与值、oneof、extension）都是如此；其 getter 返回 `&[u8]`。
  `Config::proto2_unchecked_strings(true)` 对 proto2 字符串（其旧有的 NONE）同样处理；默认情况下 proto2
  字符串仍是 `String` 并照旧检查。
- 动态消息遵循描述符：不要求 UTF-8 的 `string` 字段（`NONE` 以及 proto2）把不是 UTF-8 的内容保存为
  `Value::Bytes`（`DynamicMessage::set` 在这类字段上接受它）；JSON 输出时有损替换，文本格式输出时转义并能
  解析回来。行为变化：动态解码不是 UTF-8 的 proto2 字符串现在会成功（之前失败）。
- 描述符：map 字段的 features 会复制到其 entry 的 key 与 value 上，与 protoc 一致。
- 不含 `NONE` 的文件生成的代码逐字节不变；一致性运行器 v35.1 依旧通过 5627 + 909 项 / 失败 0 项。

### 变更：musl 布局测试（only-sys）

- `only_sys::ffi` 的布局与常量现在也在 `aarch64-unknown-linux-musl` 与 `x86_64-unknown-linux-musl`
  （Alpine）上与 `libc` crate 对比。musl 的 `struct cmsghdr` 按 4 字节对齐，内核与我们的按 8 字节对齐
  （大小与偏移一致）；其余没有差别。docs/api-stability.zh-CN.md 把使用 musl 的 Linux 列为第 2 级。

### 新增：基准测试脚本加入 monoio，与 quiche 互通（工具）

- `tools/bench-ref/monoio-ref`：monoio 0.2 参照服务端（每核一线程，每个线程一个运行时和一个
  `SO_REUSEPORT` listener；TCP echo，HTTP/1.1 `/plaintext` 与 `/json`，支持流水线），由 `tools/bench`
  以 `monoio-uring` 和 `monoio-epoll`（它的 io_uring driver 与 legacy driver）运行；`http.sh` 对没有
  HTTP/2 的服务端跳过 h2c 用例（`has_h2`）。结果与方法见 docs/BENCHMARKS.zh-CN.md。
- `tools/interop/quic/quiche.sh`：quiche 0.30.1（在 Docker 中按发布标签构建）与 `only-h3` / `only-quic`
  双向互通：quiche-client 对 HTTP/3 服务端（版本协商、单连接 50 个请求、300 KB POST、流式响应、
  0-RTT、客户端迁移），并以 HTTP/0.9（`hq-interop`）对 `only-quic`；`H3Client` 与 only-quic 客户端对
  quiche-server，有无 Retry 各一遍（3 MiB 上传时对方 STOP_SENDING 后回 405、超过其 100 流上限的并发
  请求、暂停后恢复的流式响应）。`quic-interop` 示例新增 `hq` 模式（服务端与客户端），`h3-interop`
  新增 `client-quiche` 模式。双方均未发现缺陷。

### 新增：用户态协议栈的 IPv6 自动配置、Accurate ECN 与 AF_XDP 共享 UMEM / 巨帧（only-dpdk、only-ebpf）

ADR-068（docs/adr/068-userspace-stack-slaac-accecn-af-xdp-multibuffer.zh-CN.md），仅新增（默认全部关闭）：

- `DpdkConfig::ipv6_slaac`：发送路由器请求，并从路由器通告中为每个 /64 前缀生成全局地址
  （EUI-64），取得默认路由器、链路上前缀、MTU 与跳数限制，按 RFC 4862 生存期维护。即使没有
  `address6` 也会打开 IPv6。`only_dpdk::ipv6_addresses(&Device)` 报告可用地址。
- `DpdkConfig::ipv6_dad`：地址使用前做重复地址检测（RFC 4862 5.4，带 RFC 7527 nonce）；链路本地
  地址重复则关闭 IPv6。
- `DpdkConfig::tcp_accecn`：用户态 TCP 的 Accurate ECN（RFC 9768），可回退到 RFC 3168 ECN 或不用
  ECN；与 Linux 6.18+（`net.ipv4.tcp_ecn = 3`）互通。
- `AfXdpConfig::shared_umem`（`XDP_SHARED_UMEM`：所有队列共用一个 UMEM，`frames` 为总数）与
  `AfXdpConfig::multi_buffer`（`XDP_USE_SG`：一帧跨多个 chunk，AF_XDP 上 `DpdkConfig::mtu` 可达
  9000）；底层为 `only_ebpf::xsk::XskConfig::shared_umem` / `multi_buffer` 与 `XskSocket::send_frags`。
- 多队列设备上，路由器通告与邻居发现一样复制到每个队列；新增 `#[doc(hidden)] only_dpdk::tcp_ecn_stats`。

修复：多队列设备上，拨出连接的 ICMP / ICMPv6 差错（目的不可达、包过大）与该连接的其他包一样交给
拥有它的队列。RSS 只按地址对这类差错做哈希，它可能落到别的队列而丢失（拨向关闭端口的 UDP 连接因此
超时，而不是以“不可达”失败）。

### 新增：自动重连的 RTMP / RTSP 客户端、RTCP 音视频同步、HLS I 帧播放列表、rendition report、会话密钥、H.265 `cbcs`（only-media）

ADR-070（docs/adr/070-media-reconnect-av-sync-iframes-hevc-cbcs.zh-CN.md），均为新增：

- **自动重连**：`only_media::Reconnect`（`initial_delay` 500 ms、`max_delay` 30 s、
  `max_attempts` `None`；`Reconnect::new(&Arc<Engine>)` 弱引用持有引擎），用于新增的
  `RtmpClientConfig::reconnect` 与 `RtspClientConfig::reconnect`（默认 `None`）。再试一次可能好转
  的错误会在逐次翻倍、有上限的退避后重连，会话进入直播后重置；URL 错误、hub 错误与凭据被拒仍为
  终止性错误。拉流保留其 hub 路径与订阅者，并重新发布新会话的轨道（对 sink 而言是时间线重启）；
  推流从缓存的 GOP 重新订阅（RTSP 会重新 ANNOUNCE 流当前的轨道）。RTMP：
  `ClientState::Reconnecting`、`RtmpClient::reconnects()`，第一次连接也会重试。RTSP：在短命线程上
  尝试，`RtspClient::{reconnects, is_live}`；第一个会话必须成功。
- **RTSP 音视频同步**：`RtspClientConfig::rtcp_sync`（默认 `true`）：拉流依据服务器的 RTCP 发送端
  报告把各轨 RTP 时间戳映射到服务器的 NTP 时钟，相对于第一个完成同步的轨；修正只让时间向前，报告
  早到时在流进入直播前生效。
- **HLS I 帧播放列表**：`HlsConfig::iframe_playlist`（默认 `false`）：`/<path>/iframes.m3u8`
  （`EXT-X-I-FRAMES-ONLY`、`EXT-X-BYTERANGE`；MPEG-TS 范围为 PAT、PMT 与关键帧 PES，fMP4 中每个
  关键帧一个分片），多码率播放列表中的 `EXT-X-I-FRAME-STREAM-INF`；AES-128 下不提供。分段、分片与
  init 的响应支持单个字节范围（206 / 416，`Accept-Ranges: bytes`）。
- **rendition report**：多码率组中的 LL-HLS 媒体播放列表为其余码率写
  `EXT-X-RENDITION-REPORT`（`LAST-MSN`、`LAST-PART`）。
- **`EXT-X-SESSION-KEY`**：多码率播放列表中写出每个加密码率的当前密钥。
- **fMP4 中 H.265 的 SAMPLE-AES `cbcs`**：H.265 SPS / PPS / slice segment 头解析器让每个 slice 头
  保持明文（在 200 个 slice 上与 ffmpeg 的 `trace_headers` 一致）。
- 顺带修复：RTSP 客户端在 `is_closed()` 为真时其 hub 路径已释放（与 RTMP 相同）。
- 模糊测试目标 `h265_sample_encryption`；`tests/client_bench.rs` 测量 RTMP 与 RTSP 拉流的接入开销。
- 性能（gpu51，`quiet.sh`，固定一个核，7 轮交替，取中位数，新 / 旧）：
  HLS 切片（`bench_segmenting`，每包纳秒）MPEG-TS 0.939、MPEG-TS LL-HLS 0.996、fMP4 0.950、
  fMP4 LL-HLS 0.921（正在写入的分段现在原地借用，不再每个包都从流状态中移出再放回；I 帧状态装箱），
  AES-128 0.987 至 0.996，SAMPLE-AES MPEG-TS 0.997，`cbcs` fMP4 1.019（每个 NAL 单元按 H.264 /
  H.265 分派）；RTMP 拉流接入 1.013，RTSP 拉流接入 1.015（每条消息 / 每个 RTP 包 246 与 269 ns，
  `tests/client_bench.rs`）。

### 新增：发送节拍器（pacer）、libwebrtc 的 FEC 掩码与保护策略、RFC 8888 中的 ECN、网络状态估计与调高上限时的探测（only-webrtc、only-rtp）

ADR-073（docs/adr/073-webrtc-pacer-fec-policy-ecn.zh-CN.md）：

- **Pacer**（only-webrtc）：带宽估计器打开时，视频、FEC 与重传经一个队列发出，排空速率为估计值的
  2.5 倍，突发额度 40 ms（重传优先；队列上限 8192 个包 / 8 MB；最老的包将等待 2 s 时加速排空）；音频从不
  延迟；transport-wide 序号与 abs-send-time 在包离开时写入；队列中的媒体填充探测时隙；可选填充
  （`RtcConfig::set_padding_rate`）。`RtcConfig::enable_pacing(false)` 关闭；没有估计器时不排队。
- **探测**（only-rtp `BandwidthEstimator`）：运行时 `set_bounds` 在调高上限时探测（only-webrtc：
  `RtcConfig::set_bwe_bounds`、`Peer::set_bitrate_bounds`）；`set_network_state_estimate` 把探测限制在
  外部链路容量估计以内并向其探测（每 5 s；延迟控制把估计值压在其 70 % 以下时每 3 s）；估计器自己的链路
  容量估计（`link_capacity`）驱动 3 s 探测。
- **FEC**（only-rtp `fec`）：最多 12 个包的组使用 libwebrtc 的 random / bursty 掩码表（`packet_masks`、
  `FecMaskType`），跨帧分组规则与关键帧因子（`FecProtection`、`FecEncoder::{set_protection, push_frame}`），
  以及其保护策略（`ProtectionPolicy`、`protection_factors`：按丢包率与每帧比特数查码率表，RTT 感知的
  NACK/FEC 混合）。only-webrtc 为每个发送流使用它们；`set_fec_protection` 限定因子；
  `RtcConfig::set_fec_mask(FecMask::{Random, Bursty})`。
- **RFC 8888 报告中的 ECN**：endpoint 把每个数据报的 ECN 码点（UDP 后端本已读取）交给 peer，RFC 8888
  反馈报告它，估计器把标记 CE 的包按丢失计（`PacketResult::ecn`、`BandwidthEstimator::ecn_counts`）。
- **simulcast 线路上的 FlexFEC**（每个编码一个不声明的 FlexFEC 流，以 MID 与所修复的 RID 标识）；
  **PCMU、PCMA 与 G.722 的 RED**（`RtcConfig::enable_audio_red`，`red/8000`）；**不带 FEC 的视频 RED**
  （`FecMechanism::Red`；接受只有 `red` 没有 `ulpfec` 的对端）。
- **部分重建的 ULPFEC 包**交给 depacketizer（`FecDecoder::take_partials`、`FrameAssembler::push_partial`、
  `Frame::partial`；这样的帧不是 `contiguous`）。
- only-webrtc 的 RTCP XR VoIP 指标携带由 E-model 计算的 **R 因子与 MOS**（ITU-T G.107：`EModel`、
  `mos_from_r`、`BurstLossModel::{loss_fraction, burst_ratio}`）。
- 统计（`PeerStats` 事件）：`fec_partial`、`paced_dropped`、`ecn_ect_received`、`ecn_ce_received`、
  `ecn_ce_reported`。
- 行为变化：估计器运行时媒体按节拍发送；FEC 保护遵循 libwebrtc 的策略，不再是三倍丢包率（有 NACK 且
  RTT 低于 20 ms 时 delta 帧不加 FEC）；simulcast 线路提供 FlexFEC；VoIP 指标携带 R 与 MOS。only-rtp
  （内部层）：`PacketResult` 新增字段 `ecn`，`Frame` 新增字段 `partial`。
- 测试：模拟时间（1 Mbps 估计值下关键帧摊开到 156 ms，同时音频立即发出；重传顺序；队列上限；调高上限
  时的探测；经 RFC 8888 的 ECN；10 % 丢包下 PCMU RED 收到 300 帧中的 297-298 帧，无 RED 263-268 帧；部分帧；
  simulcast FlexFEC）；libwebrtc 表值与策略值；估计器模拟链路（调高的上限 0.15 s 达到；网络状态估计限制
  探测；20 % CE 与 20 % 丢包一样压低估计值）。互通：`tools/interop/webrtc/pacing.sh` 对 Chrome 157（发往
  Chrome 的最大突发 pacing 时 4 个包、不 pacing 时 7 个；6 个以上的突发 0 次对 15 次；Chrome 解码 300 帧中的
  299-300 帧），`fec.sh` 结果不变（5 % 丢包、无 NACK 时 ULPFEC 381/400、FlexFEC 391/400 帧）；真实丢包（`tests/netem.rs`，
  Docker 中 `tc netem loss 5%`，去掉 NACK）：300 帧完整收到无 FEC 251 帧，ULPFEC 300，FlexFEC 299，
  pacing 下 FlexFEC 300。
- 基准（gpu51，同轮 A/B）：与分支点 57696b6b 在 gpu51 上的同轮 A/B（`quiet.sh`，CPU 2-9，交替 7 轮，取中位数），两个回环
  `Endpoint` 之间单向 VP8：默认配置（无估计器，因此无 pacer）0.999x（142.7 对 142.8 MB/s）；FEC 固定在
  64/256 时 ULPFEC 0.993x（120.2 对 121.1 MB/s）、FlexFEC 0.994x（122.2 对 122.9 MB/s），差距来自
  libwebrtc 的掩码：其每个 FEC 包覆盖的媒体包比原来的交织掩码多（最初每帧都重新计算策略的版本测得
  0.988x / 0.981x）。

### 新增：无 BUNDLE 或无 ICE 的 WebRTC 传输、SDES 的 MKI 与数据通道、通道优先级、TURN DTLS 连接 ID（only-webrtc、only-turn、only-ice）

ADR-072（docs/adr/072-webrtc-transports-sdes-priorities-turn-cids.zh-CN.md），只有新增：

- 数据通道优先级（`ChannelConfig` 中的 `ChannelPriority`，随 DCEP 发送并读取对端的值；
  `Peer::channel_priority` / `set_channel_priority`）与 SCTP 流调度器（`ChannelScheduler`、
  `RtcConfig::set_sctp_scheduler`；默认加权公平排队）。
- 无 BUNDLE 的会话：`RtcConfig::set_bundle_policy(BundlePolicy::Disabled)`、不带 `a=group:BUNDLE` 的
  远端 offer、拒绝我方 BUNDLE 的应答，都使每个段拥有自己的 ICE 代理、DTLS 关联与 SRTP 密钥（与
  `bundlePolicy: "max-compat"` 的 Chrome 双向可用）；`Endpoint::bind_transport_socket` 为传输提供各自的
  套接字；`Peer::add_remote_candidate_in` 把 trickle 候选交给其段。不带 rtcp-mux 的此类会话现在可以有
  多个段和数据通道。不做 BUNDLE 的会话不协商传输级拥塞控制。
- 组件 2 上的 RTCP：`gather_srflx` / `gather_relay(_via)` 从 RTCP 套接字收集服务器反射与中继候选；
  `RtcServer::rtcp_candidates` 与 `RtcServer::rtcp()`（`RtcRtcp`）用于 ICE-lite 服务器的 RTCP 监听器。
- 无 ICE 的 SDES-SRTP（`RtcConfig::enable_ice(false)`，或不带 ICE 的远端 SDP：普通 `c=` / `m=` 端口
  媒体与 `a=rtcp`）、带 MKI 与多个主密钥（我方 offer 用 `RtcConfig::set_sdes_mki_length`）、与数据通道
  并存（应用段中运行 DTLS）。
- only-turn：基于 DTLS 的 TURN 监听器协商 8 字节连接 ID；客户端路径跟随来自新地址且通过认证的记录，
  分配保持不变（`TurnServer::dtls_with_connection_ids` 设置其他长度或关闭）。only-webrtc 的 DTLS 中继
  客户端发送服务器的 CID。
- only-ice：`mdns::MULTICAST_V6`、`mdns::multicast_v6_on`、`Candidate::with_scope_id`、
  `IceAgent::set_fixed_pair` / `is_fixed`（无 ICE 的路径）。

### 变更：不带 BUNDLE 的远端 offer（only-webrtc）

不带 `a=group:BUNDLE` 的多段远端 offer 现在以每段一个传输应答（此前的应答带一个 offer 未要求的
BUNDLE 组，无法连通）。

### 新增：only-brotli 与 only-zstd 的流式 API、字典与更好的最高级别压缩率

ADR-069（docs/adr/069-brotli-zstd-streaming-dictionaries-ratios.zh-CN.md），增量 API：

- 两个 crate 都有流式 API，形状同 only-deflate：`Compressor::compress(input, &mut out, Flush)`
  （`Flush::{None, Flush, Finish}`、窗口设置、`reset`）以及 `Decompressor::decompress_vec` /
  `decompress`，返回 `Progress { consumed, produced, done }`；无论输入如何内存都有界：zstd 解码器至多
  收集一个块，持有帧的窗口（`max_window`，默认 8 MiB）；brotli 解码器从最后一条完整命令或头部单元处
  继续，因此在任何位置切分输入（包括逐字节）代价都与整体输入相差无几，且至多比交付提前解码 1 MiB
  （`max_window_bits`）。zstd 的 `Flush` 把待压缩输入写成一个块，brotli 的则以空元数据块结束 meta-block。
- zstd 字典：`Dictionary`（原始内容，或 `zstd --train` 的训练格式，带 Dictionary_ID、码表与重复偏移）、
  `compress_with_dictionary`、`decompress_with_dictionary`、流式类型上的 `with_dictionary`；新错误
  `WrongDictionary`、`BadDictionary`。brotli 原始（LZ77 前缀）字典，用法同 `brotli -D` 与 Google 的
  `BROTLI_SHARED_DICTIONARY_RAW`：`compress_with_dictionary`、`decompress_with_dictionary`、
  `with_dictionary`；新错误 `WindowTooLarge`。两者都与命令行工具双向核对。
- 压缩率：zstd 16..=22 级做最优解析（libzstd 的 `btopt` / `btultra`：二叉树匹配查找、按在块之间沿用的
  符号统计定价的最短路径、1–3 遍），各级别都可复用上一个块的码表；brotli 10..=11 级使用静态字典词。在
  基准语料上 zstd 19 现在比 libzstd 大 0.3–1.4%（之前 1.3–7.6%），级别 16 在 Silesia 与 JSON 上更小，brotli 11 比 libbrotli 大 0.9–4.7%（之前 3.5–11.4%；
  块分割随后完成，见上文“brotli 块分割”）。
- 这些级别的压缩变慢，与参考编码器一样：zstd 19 为 3.5–10.9 MB/s（libzstd 3.9–12），brotli 10–11 在
  文本上约为之前速度的一半（docs/BENCHMARKS.zh-CN.md）。
- 解码速度基本不变（安静主机上与 main 同批 A/B：每格 −2.2..+4.9%；小证书链至多慢 2%，约 0.15 µs；
  docs/BENCHMARKS.zh-CN.md）。
- 模糊测试目标 `zstd_stream`、`zstd_stream_roundtrip`、`brotli_stream`、`brotli_stream_roundtrip`。
- only-http 不变：流式响应仍不压缩（ADR-069 第 4 节；此后已压缩，ADR-074）。

### 新增：引擎连接的内核 TLS，硬件优先（only-tls、only-core、only-sys、only）

ADR-067（docs/adr/067-kernel-tls-engine-offload.zh-CN.md），只有新增（默认关闭）：

- `ServerConfigBuilder::ktls` / `ClientConfigBuilder::ktls` 与 `only_tls::Ktls`：握手完成后，epoll 或
  io_uring 上的 `Tls` 连接把记录层交给 Linux。`Ktls::Hardware` 只卸载支持 TLS 卸载的网卡自己完成的部分
  （本地地址所在接口的 `tls-hw-tx-offload` / `tls-hw-rx-offload`；AES-GCM），用内核的 `TlsTxDevice` /
  `TlsRxDevice` 计数器确认，并不再提供驱动拒绝过的组合；在没有这类网卡的主机上什么都不改变。
  `Ktls::Software` / `Ktls::SoftwareTx` 使用软件 kTLS（双向 / 只发送方向）。
  `ktls_zerocopy_sendfile(true)` 为网卡卸载的连接设置 `TLS_TX_ZEROCOPY_RO`。
- 发送方向在内核中时，应用数据不再在用户态加密，`send_file` 与静态文件经 `sendfile(2)` 发出；控制记录
  与密钥更新按顺序排队。接收方向在内核中时，`on_data` 直接拿到解密后的数据，控制记录（告警、KeyUpdate、
  close_notify）用 `recvmsg` 读取。io_uring 先让 multishot recv 停在记录边界，再移交接收方向。
- `TlsInfo::ktls_tx` / `ktls_rx`（`KtlsPath::Software` / `Hardware`）、`TlsCounts::ktls_*` 与指标
  `only_tls_ktls_total{side, dir, path}`。
- only-core：`Transport::{wants_offload, offload, kernel_send, take_ops, kernel_record}`（默认方法）、
  `Offloaded`、`SocketOp`（Linux）。
- only-sys：`netdev_tls_offload`、`netdev_features`、`interface_addrs`、`tls_stat`、
  `ktls_tx_zerocopy_ro`、`ktls_rx_expect_no_pad`、`kernel_at_least`（隐藏模块）。
- Feature：`only-tls/ktls` 与 `only/ktls`；`experimental-ktls` 保留为别名。
- 基准服务器支持 `ONLY_KTLS=off|hardware|software|software-tx`；`tools/bench/ktls-engine.sh` 运行引擎
  A/B。
- 性能（docs/BENCHMARKS.zh-CN.md，“引擎中的内核 TLS”）：默认构建，以及在没有 TLS 卸载网卡的主机上的
  `Ktls::Hardware`，与 main 相比没有变化（epoll 与 io_uring 上每秒握手数与 HTTPS 请求数都在 0.5% 以内）。
  软件 kTLS 在这颗 CPU 上仍然更慢（HTTPS 为 0.77 倍），与之前的评估一致。硬件路径未测量（测试主机没有这类
  网卡）。
- 测试：`crates/only/tests/ktls.rs`（epoll 与 io_uring）、curl / `openssl s_client` 对启用 kTLS 的
  `http-bench`（10/10）、`ONLY_INTEROP_KTLS=require` 下的 `tools/interop/tls/run.sh`（175/175）。

### 新增：静态文件缓存的变更通知（only-http、only-sys）

ADR-066（docs/adr/066-static-files-change-notifications.zh-CN.md），只有新增（默认关闭）：

- `Files::watch(true)`：缓存经 inotify（Linux）或 kqueue `EVFILT_VNODE`（macOS）跟随磁盘变化，不再每个
  `check_interval` 重查。路径上的目录（自根目录起）、文件及其压缩同名文件都有监视的缓存项，在变化把它
  丢弃之前不访问磁盘：写入或属性变化，文件、同名文件或路径上目录的重命名或删除，或事件丢失（溢出）。
  每个 `Files` 一个 `only-files-watch` 线程，`Files` 丢弃后退出。
- 通知无法担保的缓存项仍按间隔规则：Linux 上的符号链接与有多个硬链接的文件；在变化正被报告时读入的
  缓存项；超过 `Files::max_watches(n)`（默认 1024：目录监视数，macOS 上另加每个缓存文件一个文件描述符）
  的缓存项；通知无法建立或出错时的全部缓存项。不适用于网络文件系统与 FUSE，其他机器的修改不产生通知。
- only-sys：`FsWatcher`（`watch_dir`、`watch_file`、`unwatch`、`wait`、`wake`）、`FsEvent`、`WatchId`。
- I/O 线程上的命中路径多读一个 relaxed 原子量；不打开 `watch` 时其余一切不变。

### 新增：无连接的 UDP listener，`DatagramsHandler`（only、only-core、only-epoll、only-uring）

ADR-065（docs/adr/065-connectionless-datagrams.zh-CN.md），只有新增（每对端连接的 UDP listener
不变）：

- `Listener::udp(addr).serve_datagrams(factory)`：每个 I/O 线程一个 `DatagramsHandler`，而不是每个
  对端一个 `Conn`。`on_datagrams(&Datagrams, &mut Replies)` 以 `(peer, &[u8])` 对的形式拿到每个
  接收批次；在 `Replies` 上排队的、发往任意地址的回复在它返回时一起发出（Linux 上用 `sendmmsg`，
  发往同一地址、长度相同的连续数据报合并为 UDP GSO）。没有对端表、空闲超时和 `on_open` /
  `on_close`：内存不随对端数量增长；`on_shutdown` 可发出最后的数据报。
- `DatagramSender`（`Send + Sync + Clone`；来自工厂函数、`Replies::sender` 或
  `Engine::datagram_sender`）可在任意线程向任意地址发送。
- 有上限：回复队列计入 `Config::max_queued_bytes`（超出时 `send_to` 返回 `WouldBlock`）；有数据报
  等待 socket 空间时，该线程暂停读取。
- 支持 epoll、kqueue 和 io_uring（每个 socket 一个 ring poll，走同一条 `recvmmsg` / `sendmmsg`
  路径；`ONLY_DEFAULT_BACKEND=uring` 生效）；不支持 DPDK（`Unsupported`）。与每对端 UDP listener
  一样，`Engine::set_threads` 会被拒绝。
- 示例 `udp-dns`（DNS 风格应答器）；`bench-server udp-dgram`。gpu51 上 64 B echo A/B：
  每对端 UDP 不变（req/s 1.02 倍，每请求 CPU 1.00 倍）；`serve_datagrams` 的 req/s 为 1.08 倍（epoll）/
  1.09 倍（io_uring），每请求服务端 CPU 少 7–8%。

### 新增：客户端的 cookie 容器、Happy Eyeballs、DNS 缓存与 `https://` 代理；SOCKS 分片与 TLS；macOS 信任设置（only、only-http、only-ws、only-socks、only-tls）

ADR-059（docs/adr/059-client-cookies-happy-eyeballs-proxy-tls.zh-CN.md），只有新增：

- `only_http::cookie::CookieJar` 与 `Client::with_cookies`：RFC 6265 cookie，采用 RFC 6265bis 规则
  （Domain 与公共后缀：单标签与 IP 总是算，完整列表经 `CookieJar::public_suffixes` 接入；Path；
  Secure、`__Secure-` / `__Host-`；HttpOnly；离开第一个站点的重定向链上的 SameSite；Max-Age /
  Expires，最多 400 天），有上限（`CookieLimits`：4096 字节、每个域 50 个、总共 3000 个，最久未用的
  先淘汰），对重定向链的每一跳生效。不挂容器时不生效。
- `only::dns`：有上限的应答缓存（`CacheConfig`：`getaddrinfo` 不给 TTL，因此用固定的 30 秒，1024 个
  名字，默认不缓存失败；`set_cache`、`clear_cache`）与共享的进行中查询；Happy Eyeballs v2
  （`HappyEyeballs`，RFC 8305：协议族交替，每 250 毫秒或失败后立即发起一次尝试，落败的连接在发送前
  关闭），在一个有上限的竞速线程上进行，胜者交给 engine。HTTP/1 客户端（`ClientOptions::happy_eyeballs`）、
  WebSocket 客户端（`DialOptions::happy_eyeballs`）与新增的 `H2Client::connect(engine, host, port, ...)`
  都这样竞速。
- HTTP 与 WebSocket 客户端及 `Proxy::from_env` 支持 `https://` 代理 URL（到代理的 TLS，按名字校验其
  证书；`https://` / `wss://` 目标为 TLS 套 TLS）。
- only-socks：`SocksClient::tls`（engine 方法经 TLS 连接代理），分片发送 UDP 数据报
  （`UdpAssociation::send_fragmented`、`BlockingUdp::send_fragmented`，以及服务端需显式开启的
  `Socks::udp_fragment_size`）；客户端的 UDP 关联在代理某个地址不可达时改试下一个地址。
- macOS 上的 `RootCerts::system()` 应用用户、管理员与系统的信任设置（`security
  trust-settings-export`）：被标记为不信任的 CA 被去掉，在 System 或登录钥匙串中被标记为信任的 CA
  成为根证书，System 钥匙串中未被信任的证书不再算根证书。
- fuzz 目标 `cookie_parse` 与 `tls_trust_plist`。未做：PAC、Windows 证书库、GSSAPI。

### 新增：完整的 QPACK 编码器与 HTTP/3 客户端流式响应（only-h3、only-quic）

ADR-061（docs/adr/061-qpack-encoder-h3-streamed-responses.zh-CN.md），只有新增（默认值不变：编码器
仍关闭，`qpack_encoder_capacity: 0`）：

- QPACK 编码器（RFC 9204），设置 `qpack_encoder_capacity` 后：插入使用静态或动态名称引用或字面名称，
  只插入出现过两次的字段（从不插入路径、日期、长度、校验器、范围、凭据或 cookie）；对即将被驱逐且被引用
  的条目使用 Duplicate；字面字段行使用动态名称引用；用 post-base 索引引用同一段插入的条目；引用未确认
  条目的段只在对端 `SETTINGS_QPACK_BLOCKED_STREAMS`（现从其 SETTINGS 读取，最多 64）之内；只驱逐已确认
  且未被引用的条目；Section Acknowledgement、Stream Cancellation 与 Insert Count Increment 处理同前。
- `H3Client::open(method, path, headers, on_event) -> H3Upload`：流式响应在连接的 I/O 线程上以
  `H3Event::{Head, Data, Trailers, End, Error}` 报告（不缓冲，不受 `max_body_bytes` 限制），请求体通过
  返回的 `H3Upload` 写入（上传与下载可同时进行）。`H3Upload::hold_reads(bool)` 暂停与恢复读取响应，
  由 QUIC 流量控制让服务器停下；`H3Upload::cancel()` 放弃请求。`request_timeout` 只作用到响应头。
- `only_quic::Connection::hold_reads(id, bool)`：暂停交付一个流的数据；暂停期间数据留在接收缓冲区，
  恢复前不扩大该流的窗口。
- 服务器推送仍不做（浏览器已放弃，见 ADR-061）。
- 测试：针对每条编码器规则的单元测试；新 fuzz 目标 `qpack_encoder`（我方编码器对我方解码器，链路延迟并
  拆分编码器流、延迟确认、取消流）；`tools/interop/h3/nghttp3-qpack.py`（libnghttp3 的 QPACK 解码器，即
  curl 所用的那个，通过新的 `qpack-pipe` 示例检验我方编码器：线上的 curl、quic-go 与 fib 都通告解码器表
  为 0）；流式响应的端到端测试。
- `quic-bench h3`（gpu51，对 main b22519ae 两次同轮 A/B，各 7 轮交替）：默认配置（编码器关闭）持平，两次分别为 0.997 倍和 1.001 倍（14 轮合计 0.999 倍，86.39 万 vs 86.48 万请求/秒；客户端请求路径只多了一次流式响应检查）；两端编码器都开启时为旧编码器同样开启时的 0.991 倍（72.21 万 vs 72.89 万），即默认配置的 0.833 倍（旧编码器为 0.839 倍），因此编码器默认仍关闭。

### 新增：异步 0-RTT 防重放存储、可轮换的会话票据密钥、BoGo（only-tls、only-core、only-quic）

ADR-062（docs/adr/062-tls-async-anti-replay-ticket-rotation-bogo.zh-CN.md），只有新增（默认配置行为不变）：

- `AsyncAntiReplayStore` / `ReplayCheck` 与 `ServerConfigBuilder::async_anti_replay_store`：远程存储（Redis
  之类）的应答不再阻塞 I/O 线程。需要检查的 0-RTT ClientHello 挂起其握手（其间到达的字节暂存，有上限），
  存储在任意线程调用 `ReplayCheck::complete` 后在其 I/O 线程上继续；`ServerConfigBuilder::anti_replay_timeout`
  （1 秒）超时未应答则拒绝早期数据（失败即关闭，握手以 1-RTT 恢复继续）。TCP 与 QUIC 均支持。
- only-core：`Transport::set_waker`（带默认实现）与 `TransportWaker`，让等待对端以外事件的传输层可以请其 I/O
  线程再次轮询。
- `TicketKeys` 与 `ServerConfigBuilder::session_ticket_keys`：可轮换的会话票据密钥，一把负责封装，此前最多三把
  （`MAX_TICKET_KEYS`）仍能解开各自的票据；由应用轮换（`rotate`、`set`），或按周期从服务器共享的密钥派生
  （`TicketKeys::derived`：共享票据的服务器同步轮换），或按周期随机生成（`TicketKeys::random`）。定时密钥把
  票据声明的有效期限制在一个周期内。
- `status_request_v2`（RFC 6961）：从不发送，收到时忽略（决定与理由见 ADR）。OCSP 验证此前已完成（ADR-038、
  ADR-049）；已更正 DEV-PLAN。
- BoGo：shim（`crates/only-tls/examples/bogo-shim.rs`）与 `tools/interop/tls/bogo.sh` 以固定提交运行 BoringSSL 的测试运行器，配置为 `tools/interop/tls/bogo_config.json`（禁用的领域与已知失败，逐条写明原因）：8,110 个测试中 882 个通过，没有意外失败，1,122 个未实现，6,106 个被禁用。

### 修复（only-media）

- RTMP 拉流：`RtmpClient::is_closed` 为真之后（或 `close`、丢弃句柄返回之后），hub 路径即已释放；此前已连接的拉流要等连接关闭完成才释放，立即再拉同一路径可能得到 `HubError::StreamBusy`。会话现在通过 `Arc` 共享 publisher；gpu51 上同一轮 A/B（`quiet.sh`，固定单核，向拉流会话灌入示例 FLV 的 282,001 条消息）为 47.17 ms，修改前 47.24 ms（0.999 倍）。

### 修复（only-tls）

- 由 BoGo 发现：不支持 TLS 1.3 的服务端不再拒绝 TLS_FALLBACK_SCSV（RFC 7507）；带 supported_groups 而没有 key_share 的 ClientHello 得到 `missing_extension` 而不是 HelloRetryRequest（RFC 8446 §9.2）；TLS 1.2 服务端确认 server_name（RFC 6066 §3）；超过 2^14 + 1 字节的 TLS 1.3 带填充明文以 `record_overflow` 拒绝（RFC 8446 §5.4）；TLS 1.2 客户端拒绝非空的 server_name 确认，未请求的 TLS 1.3 server_name 确认为 `unsupported_extension`；对端叶证书的 keyUsage 不含 digitalSignature 时为 `bad_certificate`（RFC 8446 §4.4.2.2）；未请求的 CertificateEntry 扩展为 `unsupported_extension`（RFC 8446 §4.4.2）；格式错误的 TLS 1.3 pre_shared_key 不再导致 TLS 1.2 握手失败；不向不支持 psk_dhe_ke 的客户端发送票据（RFC 8446 §4.2.9）；我方下一次发送应用数据之前的多个 update_requested KeyUpdate 只回应一次（RFC 8446 §4.6.3）。

### 新增：跨进程 BPF 分流、prefork 重载时的 listener 迁移与 AF_XDP（only-ebpf、only-prefork、only-dpdk）

ADR-063（docs/adr/063-shared-steering-migration-af-xdp.zh-CN.md），只有新增（不显式开启则一切不变）：

- `only_ebpf::SharedSteering`：一个固定在 bpffs 中、由多个进程的 `SO_REUSEPORT` socket 共用的
  `SK_REUSEPORT` 程序、socket 数组与 Maglev 表。接口有 `create`（所有者，drop 时删除 pin）、`open`、
  `at(first, count)` 和 `join(fds)`，`join` 填入本进程的槽位。支持按 CPU 或哈希分流，哈希与表都和
  `attach_reuseport` 相同。在 Linux 5.14+ 上程序以 `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` 加载
  （`migrates()`）：无论 `net.ipv4.tcp_migrate_req` 如何设置，关闭中的 listener 的 accept 队列与半连接
  都会迁移到其槽位当前的 socket。另有 `SteerInfo::{shared, migrate}`、
  `Probe::{reuseport_migrate, af_xdp}` 和门面中的 `EbpfConfig::shared`。
- `Prefork::bpf_steering(BpfSteering { steering, threads, dir, strict })`（`ListenMode::ReusePort`，
  Linux）：supervisor 为每个地址固定一组（`workers * threads` 个槽位），每个 worker 的 `listener(i)`
  加入自己的槽位。重启或重载后的 worker 接管自己的槽位，因此重载时新 worker 一构建完成就接过旧 worker
  的那份流量，旧 listener 关闭时仍在排队的连接会迁移过去。没有特权或 bpffs 时 worker 照旧使用内核哈希
  （设置 `strict` 则失败）。无法迁移的 `ReusePort` 重载会记录警告。另有 `Supervisor::bpf_steering`、
  `DEFAULT_BPF_DIR`。
- `only_dpdk::Device::AfXdp(AfXdpConfig)`：AF_XDP socket 作为用户态协议栈的一种链路，与 TAP、
  AF_PACKET 并列，不需要 DPDK。每个队列一个 socket 和一个 I/O 线程，每个 socket 一块 UMEM，四个环由该
  线程轮询，另有一个手工汇编的 XDP 程序把每个队列重定向到对应的 socket。驱动支持时零拷贝，否则拷贝
  模式（`ZeroCopy`）；先 native，否则 generic XDP（`XdpMode`，重新导出）。默认 MAC 取接口自己的。
- 测试只使用 veth 对与网络命名空间：共享槽位、accept 队列与半连接的迁移、多进程分流，以及在持续建连
  下的重载与先停止后杀死的 worker（没有丢失，accept 计数吻合），外加 AF_XDP 的内核对端测试（native、
  generic、IPv6、两个队列）。降级路径在去掉 capability 后测试。`tools/bench/afxdp.sh` 与示例
  `link-bench` 对比 AF_XDP 与 AF_PACKET（docs/BENCHMARKS.zh-CN.md）。

### 新增：HTTP/2 上的 WebSocket（RFC 8441，only-http）

ADR-060（docs/adr/060-h2-websocket.zh-CN.md），仅新增：

- 服务端：HTTP/2 服务端宣告 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 并接受 extended CONNECT（`:protocol`，
  同时带 `:scheme`、`:path` 和 `:authority`；畸形请求以 `PROTOCOL_ERROR` 重置）。
  `Context::upgrade_websocket` 在 HTTP/2 上像在 HTTP/3 上一样接受 `:protocol websocket`（版本 13、
  origin 策略、子协议、`permessage-deflate`，应答 `200`），由 `Router` 的 GET 路由应答，所以一个
  `.get("/ws", ...)` 同时服务 HTTP/1.1、HTTP/2 和 HTTP/3 上的 WebSocket。
  `H2Config::enable_connect_protocol`（默认开启）可将其关闭。
- 客户端：`H2Client::websocket(url, &H2WsOptions, handler, done)` 与 `websocket_blocking` 在客户端
  连接的一条流上打开 WebSocket，与其请求并存；它们会先等待服务端的 SETTINGS。新增 `H2WsOptions`（config、
  deflate 提议、子协议、origin、额外头、关闭超时、`timeout` 10 秒、`max_queued_bytes` 8 MiB），以及表示
  被拒绝的 `ClientError::Status(u16)`。
- 每个 WebSocket 受其流和连接的流量控制约束；超过 `max_pending_bytes`（服务端每流；每连接为
  `max_conn_pending_bytes`）或 `max_queued_bytes`（客户端）后发送返回 `Overloaded`。close 帧结束我方
  这一半流，对端的 END_STREAM 结束它那一半；`RST_STREAM` 和连接丢失是无握手关闭（1006）；优雅关闭以
  1001 关闭 WebSocket。对端在我方结束后 5 秒内不结束它那一半，或在客户端关闭超时内不应答客户端的关闭，
  流被重置（`CANCEL`）。
- 与 Go 的 HTTP/2 在 h2c 和 TLS 上双向互通（`tools/interop/h2ws/run.sh`：net/http 服务端，
  golang.org/x/net/http2 客户端），并与无头 Chrome 互通：它在所加载页面的 HTTP/2 连接上打开 WebSocket。新增 fuzz 目标 `h2_websocket`；`h2_server` 增加 extended CONNECT 种子。
- 性能：不带 `:protocol` 的请求走与之前相同的分支。gpu51 上对 `b22519ae` 的同轮 A/B（`quiet.sh` 下
  交错 7 轮，epoll）：h2c 64 × 16 逐轮比值中位数 0.991，h2c 16 × 128 为 1.004，都在各轮波动
  （±10–36%）之内；见 docs/BENCHMARKS.zh-CN.md。gpu51 上 fuzz：`h2_server` 480 万次、
  `h2_websocket` 230 万次（各 10 分钟），无崩溃。

### 新增：gRPC 与 TLS 上的 OTLP、OTLP 日志、span 事件与链接、exemplar、导出重试（only-export、only-log、only-core、only-http）

ADR-064（docs/adr/064-otlp-grpc-tls-logs-events-exemplars.zh-CN.md），API 只有新增：

- only-export：`ExporterBuilder::otlp_grpc` / `otlp_grpc_with(endpoint, metadata)` 用 only-grpc 的客户端经
  OTLP/gRPC 导出（私有 engine，一个客户端 I/O 线程，首次推送时启动）。gRPC 和 HTTP 的 `https://` 端点经 only-tls
  连接：系统根证书或 `tls_roots(RootCerts)`，`tls_client_cert(chain, key)` 用于双向 TLS，`tls_server_name`。
- only-export：`logs(level)` 安装一个 only-log logger，记录作为 OTLP `LogRecord` 发出（`/v1/logs` 或
  `LogsService/Export`）：body、严重级别、键值、`code.file.path` / `code.line.number`，以及记录所在处当前 span 的
  trace id 和 span id。`forward_logs(logger, level)` 继续供给另一个 logger；`log_queue(max, batch)` 限定队列
  （默认 4096 / 512）；导出器自身线程上的记录不导出。
- only-log：span 事件与链接：`SpanEvent`、`SpanLink`、`Span::add_event` / `push_event` / `add_link`、
  `SpanBuilder::link`，每个 span 各最多 `MAX_EVENTS` / `MAX_LINKS`（128）个，超出计入
  `SpanData::dropped_events` / `dropped_links`；经 OTLP 导出。
- only-core：exemplar：`Exemplar`、`ExemplarReservoir`、`ExemplarHistogram`、
  `Registry::histogram_with_exemplars`、`HistogramSnapshot::exemplars` / `with_exemplars`。only-http：
  `HttpMetrics::with_exemplars()` 在延迟直方图上保留请求 span 的 id。经 OTLP 导出（Prometheus 文本格式中没有）。
- only-export：`ExportStats` 新增 `otlp_logs_ok` / `otlp_logs_failed`、`otlp_retried`、`metric_points_rejected`、
  `spans_rejected`、`logs_exported` / `logs_dropped` / `logs_rejected` / `logs_queued`；统计收集器新增相应的
  `only_export_*` 序列。

### 变更：only-export 重试失败的推送

- 可重试的失败（连不上、超时、HTTP 429 / 502 / 503 / 504、gRPC `UNAVAILABLE` 及其他可重试状态码）让 collector 进入
  退避（`retry(initial, max, max_elapsed)`，默认 1 秒到 30 秒并带抖动，或按 `Retry-After`），并保留每种信号失败的那
  一批直到它存在了 `max_elapsed`（默认 5 分钟），不再直接丢弃；退避结束时用新快照推送指标。
  `retry(.., .., Duration::ZERO)` 恢复以前的丢弃行为。其他失败仍丢弃这一批。partial success 会被计数。
- `flush()` 遇到第一个可重试的失败即停止（剩下的留在队列中）；`spans_queued` 包含等待重试的那一批。
- 接受 `https://` 端点（以前报错）。

### 新增：WebRTC 对端中 RTCP 走独立 ICE 组件、XR 接收块与 ULPFEC 保护级别（only-webrtc）

ADR-058（docs/adr/058-webrtc-rtcp-components-xr-ulpfec-levels.zh-CN.md），只有新增（默认对端的 SDP
与行为不变）：

- 不复用 RTCP 的流（RFC 5761，使用 ADR-055 的 ICE 组件）：`Endpoint::bind_rtcp` 绑定第二个套接字，
  其主机候选是 ICE 组件 2（`Endpoint::rtcp_addr`）。之后不带 `a=rtcp-mux` 的 offer（SIP 终端、较老的
  RTP 栈）以 `a=rtcp` 应答，RTCP 走组件 2；带它的 offer（浏览器、pion）照旧。
  `RtcConfig::set_rtcp_mux_policy`（默认 `RtcpMuxPolicy::Require`，另有 `Negotiate`、`Off`）决定我方
  offer 的写法。DTLS-SRTP 每个组件各握手一次（RFC 5764 §4.1：SRTCP 用组件 2 的密钥），SDES-SRTP 两个
  组件都用 SDP 中的密钥；两个组件都就绪才算连接。这种会话只有一个媒体段、没有数据通道（无 rtcp-mux 就
  没有 BUNDLE）；组件 2 只有主机与 peer-reflexive 候选；`RtcServer` 没有组件 2。
- `RtcConfig::enable_rtcp_xr_blocks(XrBlocks)`：关于接收流的 RTCP XR 丢包 RLE、重复 RLE、包接收时间
  与 VoIP 指标（RFC 3611，`a=rtcp-xr:pkt-loss-rle pkt-dup-rle pkt-rcpt-times voip-metrics`，双方都
  列出才发送；VoIP 指标仅音频），每秒由接收日志生成一次，抽稀到一个数据报内；收到的块产生
  `XrReceipts` / `VoipMetrics` 事件并累计到统计中。
- `RtcConfig::set_ulpfec_level0(Some(l0))`：发送视频时使用带保护级别的 ULPFEC（RFC 5109 §5），只用于能
  读级别的接收方（本栈；Chrome 只读级别 0）。默认关闭。
- CNAME 改为 RFC 7022 的随机 CNAME（`only_rtp::random_cname`），每个对端连接新生成；收到的 SDES 项以
  类型化形式报告（`SourceDescription` 事件）；`PeerStats` 指明 RTCP 是否复用。
- 模糊测试：`webrtc_sdp` 还会以带组件 2 候选、全部 XR 块与 ULPFEC 级别的配置运行；新增两个不复用 RTCP
  的种子。互通：pion 既没有非复用策略也没有 ICE 多组件，因此不复用 RTCP 的检查在 `Endpoint` 之间进行；
  浏览器与 pion 脚本看到的 SDP 不变。

### 新增：每个 ICE 数据流支持多个组件（only-ice）

ADR-055（docs/adr/055-ice-components.zh-CN.md），只有新增（单组件代理的行为不变）：

- `IceConfig::components`（默认 1）：代理（full 或 lite）可处理多组件数据流（RFC 8445），例如不使用
  rtcp-mux、各用各的端口的 RTP（组件 1）与 RTCP（组件 2）。`Candidate::with_component(n)` 生成组件
  `n` 的本地候选（优先级随之改变，foundation 不变）；远端候选照旧带着自己的组件号。
- 所有组件共用一个检查列表，采用 RFC 8445 §6.1.2.6 的初始状态（每个 foundation 中组件号最小的候选对
  为 Waiting、其余为 Frozen；候选以其他顺序 trickle 进来时也如此）并跨组件解冻；提名（常规、激进、
  重新提名）、选定、同意新鲜度以及 lite 代理的状态都按组件进行；ICE 重启覆盖所有组件，每个组件在
  新一代为它提名之前保留原选定候选对。每个组件都有选定候选对后状态才为 `Connected` / `Completed`，
  任一组件同意失效时为 `Disconnected`，某个组件再也无法选定时为 `Failed`。
- `IceEvent::ComponentSelectedPair { component, local, remote }`、
  `IceAgent::{components, selected_pair_of, send_pair_of}`；`SelectedPair`、`selected_pair()` 与
  `send_pair()` 仍是组件 1 的。
- 互通：`tests/libnice.rs` 与 `tools/interop/ice/run.sh` 用两个组件与 libnice 0.1.21 互通五种组合
  （libnice 控制方分别用激进提名与常规提名、受控、lite；only-ice lite）。`ice_stun` 模糊测试目标也
  驱动双组件代理。only-webrtc 仍在组件 1 上复用 RTP 与 RTCP；在那里支持不带 rtcp-mux 的数据流是后续
  工作。

### 新增：ULPFEC 保护级别、由收包生成 XR 块、类型化 SDES 项（only-rtp）

ADR-053（docs/adr/053-ulpfec-levels-xr-receipts-sdes-items.zh-CN.md）：

- **ULPFEC 级别**（RFC 5109 §7.4，任意多个）：`FecHeader::ulp_levels` / `write_level`；
  `FecEncoder::encode_ulp` 按显式级别构造 FEC 包并检查 §7.4 的规则；`FecEncoder::set_ulp_level0(Some(l0))`
  用交织的 FEC 包保护每个包的前 `l0` 字节、全组其余部分保护一次（每组丢一个包时仍能完整恢复，修复字节
  约为 `m * l0 + longest - l0` 而不是 `m * longest`）。解码器以任意顺序逐个区间重建包，完整后才返回
  （`FecDecoder::partially_recovered` 统计其余的包）。与 RFC 5109 §10.2 示例逐字节一致（M 恢复位按
  勘误 3461）。
- **由收包生成 XR 块**（RFC 3611 §4.1-4.3）：`ReceiptLog` 生成丢包 RLE、重复 RLE 与包接收时间块（支持
  稀疏化；接收时间采用 RTP 时钟），`RecvStream::{enable_receipt_log, receipt_blocks}` 用流的收包喂给它；
  `RleReport::{encode, decode, reported_seqs}` 复现 §4.1 的示例。与 pion/rtcp v1.2.20 逐字节一致（其写出器
  在块数为奇数时漏掉空块，我们会补上）。
- **VoIP 指标**（§4.7）：`BurstLossModel::report` 配合 `VoipQuality`（往返与端系统时延、信号 / 噪声电平、
  RERL、应用提供的 R 因子与 MOS，未提供或超出范围时发送 127、PLC、抖动缓冲）；`pcm_level_dbm0`。
- **SDES 项**：`SdesItem`（文本项，为每个已注册类型 CNAME .. MID 提供常量；带前缀与值的 PRIV）转换
  `Rtcp::SourceDescription` 中的二元组；`random_cname`（RFC 7022）。大于 127 的 PRIV 前缀长度现在能在
  解析后保留（以前变成 U+FFFD）；文本与 BYE 原因在字符边界处截断到 255 字节。与 pion/rtcp v1.2.20 逐字节
  一致。
- API 均为新增，只有 `FecHeader` 的新公有字段 `ulp_levels` 除外（only-rtp 属内部层级）。`rtp_rtcp` 与
  `rtp_fec` 模糊测试目标覆盖以上全部（gpu51 上各 16 分钟：`rtp_rtcp` 290 万次、`rtp_fec` 159 万次，代码中没有发现问题；更早的一次 `rtp_rtcp` 运行发现的是目标自身过严的检查（RLE 块在块的区间结束前就结束），已作为回归输入保留）。
- 未做：接入 only-webrtc（XR 接收 / VoIP 块、ULPFEC 级别、随机 CNAME）；不交出部分恢复的包；不估算 R 因子
  / MOS。

### 新增：DTLS 上的 TURN、IPv6 上的 mDNS 与 SDES-SRTP（only-turn、only-webrtc、only）

ADR-054（docs/adr/054-turn-dtls-mdns-ipv6-sdes.zh-CN.md）：

- `TurnServer::dtls(&tls::ServerConfig)`：UDP 监听器上的 DTLS TURN（RFC 7350），使用 TLS 监听器的证书：
  无状态 cookie，DTLS 1.3 可回退到 DTLS 1.2，每条记录一条 STUN / ChannelData 消息，分配随 DTLS 关联存在
  （close_notify、致命告警、空闲超时或同一地址的新握手都会释放它）；`TurnServer::dtls_relay_of`。
  only-turn 现在依赖 only-dtls。
- `RelayServer::dtls` 与 `turns:host[:port]?transport=udp` URL（不再报错）：`Endpoint` 在自己 UDP 套接字
  上的 DTLS 关联中分配，服务器证书按 TLS 客户端配置的根证书校验；得到 UDP relay 候选及 server-reflexive
  候选；关联丢失后重新分配。
- IPv6 上的 mDNS：`Endpoint::resolve_mdns` 增加一个 `[::]:5353` 套接字，在每个有链路本地地址的接口上加入
  `ff02::fb`，按接口查询，在查询所来的链路上应答；远端链路本地地址保留其接口（SDP 不携带作用域 ID）。
  IPv4 行为不变；没有 IPv6 的主机只跑 IPv4。
- `only`：`Engine::bind_udp_multicast_on(group, interfaces, acceptor)` 在列出的每个接口索引上加入 IPv6
  组播组（0 为默认接口；拒绝加入的接口被跳过）。IPv4 组只接受 `&[0]`（否则 `InvalidInput`）。
  `bind_udp_multicast` 即 `bind_udp_multicast_on(group, &[0], ..)`，行为不变。
- `RtcConfig::enable_sdes_srtp`（默认关闭）：面向 SIP 网关的 SDES-SRTP（RFC 4568）：offer 为 `RTP/SAVPF`，
  每个套件一行 `a=crypto`（AEAD-AES-256/128-GCM、AES-256/128-CM-HMAC-SHA1-80、AES-128-CM-HMAC-SHA1-32），
  并应答 SDES offer；SRTP 密钥取自 SDP，没有 DTLS，没有数据通道；不支持 MKI 与会话参数。DTLS-SRTP offer
  仍以 DTLS-SRTP 应答：浏览器永远看不到 `a=crypto`。
- 模糊测试：新目标 `turn_dtls`；`webrtc_sdp` 试用 SDES 配置。
- 互通：`tools/interop/webrtc/turn-dtls.sh`（Docker 中的 coturn 4.6）：`turnutils_uclient -S` 对 only-turn
  的 DTLS 监听器，only_turn 客户端与两个经中继的 `Endpoint` 对 coturn 的 DTLS 监听器（协商为 DTLS 1.2）。

### 新增：SRTP 的 AES-f8 与 SEED（only-srtp），only-crypto 的 SEED

ADR-052（docs/adr/052-srtp-f8-seed.zh-CN.md），仅新增：

- **only-crypto**：`seed` 模块，包含 `Seed`（RFC 4269：分组加解密、CTR）、`SeedGcm`（SP 800-38D，
  完整或截短的标签）与 `SeedCcm`（RFC 3610）。常数时间且不查表：S 盒由固定切片 AES 的 Boyar-Peralta
  求逆电路经域同构再加仿射变换得到（对每个输入都与 RFC 4269 的表比对），G 函数在 16 个字上位切片
  （ECB / CTR / GCM 同时处理 16 个分组），单个分组与 CCM 的 CBC-MAC 走单字路径；没有硬件路径。
  ct-dudect 新增目标 `seed-key` 与 `seed-block`。
- **only-srtp**：`Profile::{AesF8HmacSha1_80, AesF8HmacSha1_32}`（AES-f8，RFC 3711 §4.1.2；SDES 名称
  `F8_128_HMAC_SHA1_80/32`）与 `Profile::{SeedCtrHmacSha1_80, SeedCcm80, SeedGcm96}`（RFC 5669，
  SEED-CTR PRF；`SEED_CTR_128_HMAC_SHA1_80`、`SEED_128_CCM_80`、`SEED_128_GCM_96`），与其他配置一样
  支持 MKI、密钥派生率、RFC 6904 头部扩展加密与 cryptex。`Profile::ALL` 列出 15 种；`is_aead` 对
  SEED-CCM / SEED-GCM 为真；新增 `Profile::session_salt_len`（AEAD 为 12；SEED AEAD 的主盐仍为 14
  字节）。它们没有 DTLS-SRTP 编号，因此 `only-webrtc` 不协商它们（那里没有实现 SDES）。
- 验证：RFC 3711 B.1、RFC 4269 附录 B、RFC 5669 A.1-A.3（A.1 的标签是对不含 ROC 的明文计算的 HMAC，
  因此只使用其密钥流）、RFC 3610（用 AES 验证 CCM 构造）、OpenSSL `seed-ecb`，以及一个独立的 Python
  实现（基于 pyca/cryptography 的 `testdata/f8_seed.py`）：libsrtp 交叉验证的 25 组用例 / 115 个包在
  五种配置下双向逐字节一致。
- 基准（gpu51，`quiet.sh`，CPU 2，1200 字节载荷，protect）：AES-f8 2.26 µs（AES-128-CM 1.18 µs）、
  SEED-CTR 18.3 µs（66 MB/s）、SEED-GCM 20.4 µs、SEED-CCM 98 µs（12 MB/s）；160 字节：354 ns、3.6、
  3.9 与 16.1 µs。原有配置对比 main aca9e988（三轮交替）：AES-CM 与 160 字节 AES-GCM 在 ±1.6% 以内，
  1200 字节 AES-GCM 单独测量时持平（在完整用例序列中 protect +1.5-2.2%）；A/B 途中发现的两处 AES-GCM
  回退（+3% 与 +2.4%）已消除（ADR-052）。

### 变更：更快的 brotli 解码（only-brotli）

公共 API 不变，输出不变（见 docs/BENCHMARKS.zh-CN.md 的 “Brotli 与 Zstandard”）。在
`tools/codec-bench brotli` 的 HTTP 负载上解码用时为 libbrotli 1.2.1 的 1.08–1.34 倍（之前 1.42–1.73
倍），在 Silesia 上为 1.04–1.32 倍（之前 1.13–1.56 倍）。

- 命令循环的状态（位读取器、输出、输出位置、最近的距离）放在局部变量里，元块末尾、输出上限与窗口
  余量合并为每次写入一次比较；距离上下文与短距离码查表得到，根表大小固定。
- 前缀码表在读码长时就收集信息再构建，不再遍历没有码的符号，码长码改用 32 项的表：解码一条
  2.7 KB 证书链时建表曾占 40%。
- 周期小于 16、不超过 32 字节的复制以 8 字节为块进行。
- 输出只提前清零到元块末尾，因此在很大的上限下解码小输出时不再先清零 128 KiB（2.7 KB 证书链、
  16 MiB 上限：266 → 370 MB/s）。
- `tools/codec-bench`：`BENCH_BR_LIMIT=N` 以 `N` 而非精确大小作为输出上限解码。

### 新增：WebRTC peer 默认 DTLS 1.3、cryptex、加密头部扩展、Opus RED 与 simulcast 线路上的 FEC（only-webrtc）

ADR-048（docs/adr/048-webrtc-dtls13-cryptex-opus-red-simulcast-fec.zh-CN.md）：

- **变更**：peer 默认提供 DTLS 1.3（RFC 9147）并可回退到 DTLS 1.2（`RtcConfig::enable_dtls13`，设为
  `false` 则只用 DTLS 1.2）。SDP 不变。Chrome 157 在两种 DTLS 角色下都协商 DTLS 1.3；对 pion 等 DTLS
  1.2 对端以 DTLS 1.2 应答（两种角色均已验证）。
- `RtcConfig::enable_cryptex`：提供并接受 `a=cryptex`（RFC 9335）；双方都声明后，发送的 RTP 的头部扩展
  与 CSRC 被加密。已与 Chrome 157 的 `rtpHeaderEncryptionPolicy: "require"`（需要
  `--enable-experimental-web-platform-features`）双向验证。
- `RtcConfig::enable_encrypted_header_extensions`：为音频电平、MID、RID、修复 RID、视频方向与播放延迟
  在空闲的单字节 ID 上提供 RFC 6904 加密扩展变体（`urn:ietf:params:rtp-hdrext:encrypt`），并在 answer
  中采用。没有浏览器提供它们。SRTP MKI 不进入 WebRTC：DTLS-SRTP 没有对应的 SDP，浏览器也不使用。
- `RtcConfig::enable_opus_red(Option<u8>)`：Opus RED（`red/48000/2`，负载类型 63）排在 Opus 之前，
  这正是让 libwebrtc 发送它的条件；收到的冗余代替丢失的包（重复的丢弃），发送的 Opus 携带至多两个先前
  的包。双向 10 % 丢包下 Chrome 157 隐藏的音频从 20 % 降到 2-3 %。
- simulcast 线路上的 ULPFEC（`FecMechanism::Ulpfec`）：每个编码有自己的 FEC 编码器、丢包估计与速率，
  RED 与 ULPFEC 在该编码的 SSRC 上并带其 RID，与 Chrome 的发送方式一致；收到的 simulcast 按层修复（每个
  peer 至多 8 个 FEC 解码器）。simulcast 线路不使用 FlexFEC（基于 RID 的 simulcast 不声明 FEC 流）。
- 统计事件报告 DTLS 版本、以 cryptex 收到的包数与由 RED 恢复的包数。
- 互通：`tools/interop/webrtc/browser.sh`（两种角色的 DTLS 1.3、双向 cryptex、我方带按编码 ULPFEC 的
  simulcast 线路经过 5 % 丢包且无 NACK：Chrome 全部解码，没有 FEC 时几乎解不出）、`fec.sh`（丢包下的
  Opus RED、Chrome 的按层 ULPFEC）、`run.sh`（pion 回退到 DTLS 1.2）、Firefox 158 下的 DTLS 1.3
  （两种 DTLS 角色）。`webrtc-interop` 示例新增 `ONLY_INTEROP_*` 开关，并可让 SFU 经过有损代理。
- 基准（gpu51 与 main 436b47e7 同轮 A/B，`quiet.sh`，CPU 2-9，进程内 peer，双方均为 DTLS 1.2，取六组安静轮次的中位数：每秒建立的 peer 连接 0.990x，4000 字节 VP8 帧媒体 0.995x（752 对 756 MB/s），120 字节帧 0.993x：无回退。新默认的 DTLS 1.3 握手比 DTLS 1.2 多约 5 % CPU；媒体吞吐不变，开启 cryptex 时也一样）。

### 新增：P-521、RSA-PSS 密钥与 TLS 1.3 客户端的 OCSP 响应（only-crypto、only-x509、only-tls）

ADR-049（docs/adr/049-p521-rsa-pss-keys-client-ocsp.zh-CN.md），只增不改：

- **only-crypto**：`p521`（NIST P-521 上的 ECDH 与 ECDSA，API 同 `p256` / `p384`，标量 66 字节，默认
  SHA-512，RFC 6979 nonce；基于独立的 `2⁵²¹ - 1` 域与完备公式的可移植常量时间代码；ct-dudect 目标
  `p521-ecdh`、`p521-keygen`、`p521-sign`）；`pkey::PublicKey::{P521, RsaPss}`、
  `pkey::PrivateKey::{P521, RsaPss}` 与 `pkey::PssParams`，用于带或不带参数的 `id-RSASSA-PSS` 密钥
  （RFC 4055），它们只在参数范围内做 RSA-PSS 签名与验签；`der::oid::SECP521R1`。Wycheproof P-521
  ECDSA / ECDH 与 RFC 6979 A.2.7 向量，OpenSSL 生成的 PSS 密钥。
- **only-x509**：P-521 与 RSA-PSS 密钥的证书可以解析、验证与签发（`tests/data/pss-p521` 中为 OpenSSL
  生成的证书链）。
- **only-tls**：组 secp521r1（排在最后）、`ecdsa_secp521r1_sha512` 与 `rsa_pss_pss_sha256/384/512`
  （服务端与客户端证书，TLS 1.3 与 1.2）；`ServerConfigBuilder::client_ocsp_policy` 要求 TLS 1.3 客户端
  随证书发送 OCSP 响应并校验（ADR-038 的策略；硬失败时拒绝 TLS 1.2 客户端证书），
  `ClientConfigBuilder::client_cert_ocsp_response` 在被要求时发送，服务端的 `TlsInfo::ocsp_response`
  保存它。与 OpenSSL、Go 互通（`tools/interop/tls/run.sh`）。`status_request_v2` 仍不实现（仅限
  TLS 1.2，已过时）。
- 默认 ClientHello 列出 secp521r1（多 2 字节）；默认握手的其他部分不变。

### 新增：估计器中的带宽探测（only-rtp、only-webrtc）

ADR-050（docs/adr/050-bwe-probing.zh-CN.md）。`only_rtp::BandwidthEstimator` 像 libwebrtc 一样
探测路径，视频的爬升从数十秒缩短到不到一秒：

- **only-rtp**：以起始速率的 3 倍和 6 倍发送探测簇（至少 15 ms / 5 个包，按目标速率控制节奏），
  结果跟得上时翻倍继续；受应用限制时（`application_limited()`）每 5 s 一次；估计值大幅下降之后；
  `on_network_change(now)` 之后从头开始。`poll_probe(now)` / `probe_timeout()` / `on_probe_sent`
  / `cancel_probes` 驱动发送，`TwccSender::on_sent_probe` 与 `CcfbSender::on_sent_probe` 标记探测包，
  `PacketResult::probe` 带回簇 id，测得的送达速率提升基于时延与丢包的速率。`SendStream::padding`
  构造探测包（最近媒体的 RTX 副本或填充包）。默认开启；`with_probing(false)` 保持以前的行为。
  **破坏性变更**（内部层级）：`PacketResult` 新增公开字段 `probe`。
- **only-webrtc**：开启 `enable_bwe` 后，探测包作为发送最多的流最近包的 RTX 副本发出，节奏由
  `poll_output` 的超时控制；ICE 选中新的候选对时重新开始估计。公开 API 不变。
- 模拟链路、起始 300 kbps：0.5 / 2 / 10 Mbps 的 90 % 在 0.15 / 0.25 / 0.35 s 达到（以前 5.4 / 23 /
  44 s），峰值至多为容量的 1.12 倍。以 Chrome 157 为接收方（新增 `tools/interop/webrtc/bwe.sh`）：
  连接后 0.2 s 达到 10 Mbps（以前估计值停在起始的 1 Mbps）。

### 变更：更快的 Zstandard 解码，第二轮（only-zstd）

公共 API 不变（docs/BENCHMARKS.zh-CN.md，“zstd 解码第二轮”“zstd 字面量”与“zstd 双符号 Huffman 表”；
安静的 gpu51，在
`tools/codec-bench zstd` 中与 libzstd 1.5.7 对比）：

- 解压在 HTTP 负载上用时为 libzstd 的 1.16–1.39 倍（之前 1.46–1.64 倍）：JavaScript 1.38–1.39 倍
  （之前 1.59–1.61 倍），证书链 1.16–1.27 倍（之前 1.49–1.64 倍），JSON 1.37–1.38 倍，HTML
  1.31–1.33 倍；Silesia 级别 1 与 3 为 1.22–1.24 倍、级别 19 为 1.39 倍（之前 1.32–1.33 倍与
  1.57 倍）。解码器按线程在调用之间保留其表与字面量缓冲区，如同 libzstd 复用的上下文（约 20 KB，
  另加至多 32 KiB 字面量），序列以 64 个为一批先解码再执行（附加位允许时每个序列只读一次位），四个
  Huffman 流采用 libzstd 的快速循环解码。仍为 `#![forbid(unsafe_code)]`，无 BMI2 路径。每个 fuzz
  目标 16 分钟（`zstd_decompress`、`zstd_roundtrip`）。
- 较大的 Huffman 编码字面量段（按 libzstd 的 `HUF_selectDecoder` 规则）改用双符号表解码，每次查表
  一个或两个符号：字面量解码在 Zen 4 上快 13–21%，在 Apple M 系列上快 35–37%（JavaScript 字面量，16–60 KB）；端到端 JSON、JavaScript
  与 HTML 快 1.6–3%，Silesia −0.8…+1.4%。按线程保留的解码器保留该表（多 16 KB）。
- 压缩输出改变：编码器只在 Huffman 编码节省超过 2 字节加字面量的 1/64 时才使用它，不足 64 个字面量时
  保留为 raw，与 libzstd 相同（`ZSTD_minGain`）。我们自己的证书链帧解码快 2.3–3.2 倍（之前不到
  libzstd 帧速度的一半），大 4–17 字节；JSON、HTML 与 JavaScript 逐字节相同，Silesia 大 0.004%。
- `tools/codec-bench`：`BENCH_OWN=0` 跳过各库解码自身输出，`BENCH_DUMP=DIR` 写出被计时的 zstd 帧。

### 变更：更快的 brotli 与 Zstandard 解码和编码（only-brotli、only-zstd）

公共 API 不变（见 docs/BENCHMARKS.zh-CN.md 的 “Brotli 与 Zstandard”；在 `tools/codec-bench` 中与
libbrotli 1.2.1、libzstd 1.5.7 对比，该工具新增 `brotli` / `zstd` 模式与语料脚本）。

- **解码器**（输出不变）：解压用时为 libzstd 的 1.3–1.7 倍（之前 1.7–2.4 倍）、libbrotli 的 1.1–1.7 倍
  （之前 1.4–3.1 倍）；在 Silesia 上 zstd 级别 1 解码 849 MB/s（之前 541，libzstd 1,120），brotli 级别 5
  解码 467 MB/s（之前 333，libbrotli 716）。输出同时作为提前清零的窗口（从不超过上限），字面量与匹配以 16 字节为块复制；位读取无分支
  且保留在寄存器中；zstd 的四个 Huffman 流交错同步解码，预定义序列表不再每块复制；brotli 每次补充
  解码三个字面量，经每个块类型的 “上下文 → 树” 表查找。边界不变：内存仍不超过上限，截断的 brotli
  输入改为每条命令检查一次（而非每个字面量），代价仍以输出为界。
- **zstd 编码器**（输出改变）：级别 1–2 改用 libzstd 的 `fast` 匹配查找，3–4 改用 `double_fast`，
  不再是惰性哈希链；Huffman 码构造与位写入也更快：快 2.1–3.2 倍；大小与 libzstd 相差 −3…+2%
  （级别 3 在小的 HTTP 负载上比之前大 1–7%，原来的惰性搜索在那里胜过 libzstd 的级别 3）。
- **brotli 编码器**（输出改变）：0–6 级用每个哈希值一个桶代替哈希链（5–6 级用 5 字节哈希），2–4 级
  采用 Google 的候选数（4 级：4 个而非 16 个），像 Google 一样跳过不可压缩数据，10 级以下的上下文
  聚类更便宜：Silesia 上 q4 快 3.4 倍、q5 快 2.4 倍、q6 快 2.6 倍；q5–q6 大小变化 −1.2…+0.8%
  （证书链上大 2–3%，only-tls 对证书链使用 11 级），q4 大 1–9%，但不再以四倍于 libbrotli 的搜索量
  换取比其 q4 更小的输出。brotli 10–11 级与 zstd 5–22 级速度不变，输出除上下文聚类与 Huffman 码构造带来的
  细微差别外也不变。

### 变更：路由约束改用 `only-regex`（only-http、only-regex）

ADR-051（docs/adr/051-router-on-only-regex.zh-CN.md）。路由器的正则参数（`/users/{id:[0-9]+}`，部分段中的
也一样）现在由 `only-regex` 匹配，即 only-log 消息过滤背后的引擎；路由器自己的引擎（`only_http::re`，
`#[doc(hidden)]`，不是公共 API）已从普通构建中移除。

- **匹配结果不变。** 约束仍然匹配整段，`\d \w \s` 仍只认 ASCII。旧引擎接受的每个模式匹配的段完全相同：
  差分测试（仓库中所有正则路由、旧引擎的测试模式、3 000 个各带约 30 个主体的生成模式、20 000 个随机语法
  片段）与 `regex_match` 模糊测试目标对两者进行比较，旧引擎冻结保留为仅供测试的参照。
- **更多语法**：标志 `(?i)`（Unicode 大小写折叠）、`(?m)`、`(?s)`、`(?U)`，可取反、可限定范围；`\A \z`；
  `\b \B`（ASCII 单词边界）；Unicode 与含点号的组名；最多 20 000 条指令的程序。**唯一的收紧**：同一约束中
  两个同名分组现在会在注册时 panic，与 `regex` crate 一致（组名从来不会被捕获）。
- **更快**：每次约束检查耗时减少约三分之一（7 位数字上的 `[0-9]+` 8.5 → 5.7 ns，`\d{4}-\d{2}-\d{2}`
  11.9 → 7.6 ns）；router-bench 的多样正则表每次查找 46.0 → 42.0 ns，`[0-9]+` 表保持 28.1 ns。编译约束会
  构建 DFA：注册时 7–13 µs，原先 2.1 µs。
- **only-regex**（内部层级）：`RegexBuilder`，带 `whole_text`（匹配整段文本，相当于 `\A(?:...)\z`）与
  `ascii_classes`（ASCII 的 `\d \w \s` 与 `\b`）；`Regex` 的相等比较包含选项。`Regex::is_match` 先在紧凑
  循环中运行预先构建的 DFA，only-log 的消息过滤也因此快了几个百分点。

### 性能：VAES-AVX2 内核处理整条 AES-GCM 消息；aarch64 上 P-256 的 divsteps（only-crypto）

无 API 变化。

- **VAES-AVX2 AES-GCM 内核**（有 VAES 而无 AVX-512 的 CPU：Zen 3、Alder Lake / Raptor Lake）：与 AVX-512 内核
  一样，一次调用完成整条消息：`E(J0)`、AAD（至多 256 字节）、256 字节组、其后的尾部与长度块。AVX2 没有字节
  掩码，所以尾部经补零的栈缓冲区处理（4 或 8 个 ymm 向量，密钥流由常量表掩码）。此前除完整的 256 字节组外
  全部走 128 位内核。在 Zen 4 上强制使用 AVX2 内核测得，相对同一次运行中的 128 位内核：200 B 1.00 倍 →
  1.84–1.90 倍，1 KiB 1.47–1.75 倍 → 1.81–2.12 倍，1400 B 1.50–1.70 倍 → 1.82–2.09 倍，64 B 0.91–1.01 倍 →
  1.12–1.20 倍；相对 ring，1 KiB 0.88–1.00 倍 → 1.03–1.13 倍。没有可用的 Zen 3 或 Alder Lake 机器。
- **aarch64 上的 P-256**：safegcd 的 divsteps 改为汇编（Apple M4 Pro 上求逆 1.66 → 1.26 µs），孪生曲线的加法
  改用 OpenSSL 的公式。签名 +9%（ring 的 1.15 倍 → 1.25 倍），密钥生成 +3.5%，ECDH 为 ring 的 0.98 倍 → 1.00
  倍。首次测量 aarch64 汇编：P-256 验签为 ring 的 1.04 倍，X25519 1.04 倍（docs/BENCHMARKS.zh-CN.md）。

### 新增：mDNS ICE 候选、激进提名与重新提名、同时打开的 ICE-TCP（only-ice、only-webrtc、only）

ADR-044（docs/adr/044-ice-mdns-renomination-tcp-so.zh-CN.md），仅新增（不使用就没有任何变化）：

- **only-webrtc**：`Endpoint::resolve_mdns(&engine, timeout)` 解析浏览器发来的 `<uuid>.local`
  主机候选（描述中的与 trickle 的；经共享的 5353 端口和 `224.0.0.251` 发送一次性 mDNS 查询，缓存
  应答，从不阻塞 I/O 线程），使 `Endpoint` 能以主机对主机的方式连到浏览器；
  `Endpoint::conceal_host_candidates()` 把我方主机候选写成 mDNS 名字并应答对它们的查询。已与开启
  mDNS 隐藏的无头 Chrome 157 测试（双方互相解析对方的名字）。`RtcConfig::enable_ice_renomination`
  （`a=ice-options:renomination`）与 `RtcConfig::enable_ice_aggressive_nomination`。
  `Endpoint::listen_tcp_so(&engine, addr)`：同时打开的 ICE-TCP 候选（RFC 6544 `tcptype so`）。端点
  解析名字时，`Peer::add_remote_candidate` 接受 mDNS 候选行。
- **only-ice**：`mdns` 模块（RFC 6762 编解码）、`Candidate::{parse_resolved, with_hostname,
  hostname, with_related}`、`IceConfig::{aggressive_nomination, renomination}`、
  `IceAgent::set_remote_renomination`（NOMINATION 属性；提名后发现的更好候选对会被采用）。受控代理
  现在选择最大的 NOMINATION 值，没有该属性时选择优先级最高的被提名候选对，而不是最后一次提名。
  模糊测试目标 `ice_mdns`。
- **only**：`Engine::bind_udp_multicast(group, acceptor)`（与其他成员共享组播组端口）与
  `Engine::dial_from(local, addr, acceptor, on_error)`（从已绑定的共享本地端口发起连接）；only-sys
  的 `connect_nonblocking_from`。

### 新增：DTLS 1.3 连接 ID 更新、握手后客户端认证与早期数据（only-dtls）

ADR-045（docs/adr/045-dtls13-cid-updates-pha-early-data.zh-CN.md），均为新增且默认关闭：

- **连接 ID 更新**（RFC 9147 §9）：`Connection::new_connection_ids(count, immediate)`
  （NewConnectionId）、`request_connection_ids(n)`（RequestConnectionId，对端自动答复）、
  `rotate_connection_id()`、`spare_connection_ids()`、`local_connection_ids()`、
  `peer_connection_id()`；最多 8 个有效 CID，对端改用更新的 CID 后旧 CID 退役，
  `Event::LocalConnectionIds` 报告监听方应路由的集合。`AlertDescription::TooManyCidsRequested`。
- **握手后客户端认证**（RFC 8446 §4.6.2）：`Config::with_post_handshake_auth`（客户端）、
  `Connection::request_client_certificate` 与 `Event::ClientCertificate`（服务端）。
- **早期数据（0-RTT）**，基于票据：`Config::with_early_data(max)`、`Config::with_anti_replay`、
  `AntiReplayStore` / `MemoryAntiReplay`（记录 binder 并检查票据年龄新鲜度）、
  `Connection::send_early_data`、`Session::max_early_data`、`Event::EarlyData`、
  `HandshakeInfo::early_data`。早期数据被接受的 ClientHello 跳过 HelloRetryRequest cookie 交换。
- `Error::NotAvailable`：连接未协商或尚不具备条件的操作。
- 握手后 flight（NewSessionTicket、KeyUpdate 与新消息）共用一个队列。
- 测试 `tests/dtls13_post.rs`；fuzz 目标 `dtls_post_handshake`；与 wolfSSL 5.8.4 互通（双向早期数据
  与握手后认证；互通镜像现以 `--enable-earlydata --enable-postauth` 构建 wolfSSL，镜像名由
  `DTLS_INTEROP_IMAGE` 指定）；示例 `dtls-hs-bench`（每秒握手数、DTLS 1.3 记录）。非 ECDHE 密钥交换与
  CBC 套件有意不做（README、ADR-045）。

### 新增：证书策略、间接 CRL、Ed448、X448 与 DSA 验签（only-x509、only-crypto、only-tls）

ADR-046（docs/adr/046-x509-policies-indirect-crls-ed448-dsa.zh-CN.md）：

- **only-x509**：证书策略处理（基于 RFC 9618 策略图的 RFC 5280 §6.1）：
  `Verifier::policies(PolicyOptions)`（初始策略集、显式策略、禁止策略映射 / anyPolicy）、
  `Verifier::verify_path` → `VerifiedPath { chain, policies: ValidPolicies }`、
  `Error::PolicyViolation`；`Certificate::{certificate_policies, policy_mappings,
  policy_constraints, inhibit_any_policy, is_self_issued}`、`PolicyConstraints`、
  `ext::{ANY_POLICY, POLICY_MAPPINGS, POLICY_CONSTRAINTS, INHIBIT_ANY_POLICY}`。间接 CRL 与由 CA
  另一把密钥签发的 CRL（签名者路径须验证到同一个根，并检查其吊销）：`Verifier::crl_signers`、
  `Crl::find_for`、`RevokedCertificate::certificate_issuer`、`DistributionPoint::relative_name`、
  `IssuingDistributionPoint::relative_name`（新增公开字段）；CRL 的适用范围现在按证书的分发点及其
  原因判断。rfc822Name 与 URI 名称约束（以及主题中的 emailAddress），自签发中间证书不受名称约束、
  不计入 pathLen，`Verifier::allow_ca_end_entity`，`attr::EMAIL_ADDRESS`；Ed448 与 DSA 证书和
  CRL。NIST PKITS 测试（`tests/pkits.rs`、`tools/pkits/prepare.sh`）：248 次运行中 242 次符合预期。
- **only-crypto**：`hash::{Shake128, Shake256}`、`ed448`、`x448`、`dsa`（仅验签）、
  `rsa::HashAlg::Sha224`、`pkey::SignatureAlgorithm::{Ed448, DsaSha1, DsaSha224, DsaSha256}`、
  `pkey::{PublicKey, PrivateKey}::Ed448`、`pkey::PublicKey::Dsa`、`der::oid::{ED448, X448, DSA,
  DSA_WITH_SHA1, DSA_WITH_SHA224, DSA_WITH_SHA256}`；`pk_bench 448`；ct-dudect 目标 `x448`、
  `ed448-keygen`、`ed448-sign`。
- **only-tls**：组 x448（0x001e，排在最后）与签名方案 ed448（0x0808），TLS 1.3 与 1.2；
  `tools/interop/tls/run.sh` 中与 OpenSSL 的互通用例。
- 模糊测试目标 `x509_policy` 与 `crypto_ed448_dsa`；`x509_parse` 与 `x509_crl` 覆盖新的扩展与间接
  CRL 条目。

### 变更：路径验证细节（only-x509）

- 配置了 CRL 时，吊销在候选路径到达根证书后自顶向下检查，而不是在建链过程中检查。policyConstraints
  要求显式策略而路径上没有时现在会失败（`Error::PolicyViolation`），策略扩展格式错误的证书不再能
  解析。CRL 序列号按有符号 INTEGER 比较（−1 的 CRL 条目不再匹配序列号 255），`CrlParams` 与 OCSP
  CertID 按原样写出序列号。

### 新增：WebRTC 对端中的 FEC、RTCP XR、TMMBR 与 RFC 8888 反馈（only-webrtc、only-rtp）

ADR-039（docs/adr/039-webrtc-fec-xr-tmmbr-ccfb.zh-CN.md），仅新增且默认关闭（默认对端的 SDP 不变）：

- **only-webrtc**：`RtcConfig::enable_fec(Option<FecMechanism>)`（`FecMechanism::FlexFec`：带
  `a=ssrc-group:FEC-FR` 流的 `flexfec-03`；`FecMechanism::Ulpfec`：`red` + RTX + `ulpfec`），用于非
  simulcast 的视频行：收到的 FEC 在帧组装器和 NACK 之前修复包，发送的视频按修复前丢包率的三倍保护，
  并限制在 `RtcConfig::set_fec_protection(min, max)` 内（每 256 个媒体包，默认 0..=128）。
  `RtcConfig::enable_ccfb` 协商 RFC 8888（`ack ccfb`；answer 去掉 transport-cc），之后在确认与带宽估计
  两方面都取代传输层反馈。`RtcConfig::enable_rtcp_xr`（`a=rtcp-xr:rcvr-rtt=all`、`rrtr`）：接收方参考
  时间与 DLRR 为接收行提供 RTT；收到的 RRTR 总会应答。`RtcConfig::enable_tmmbr`（`ccm tmmbr`）与
  `Peer::request_max_bitrate(mid, Option<u64>)`；收到的 TMMBR 以 TMMBN 应答，并与 REMB 一起限制估计值。
  RTCP 的 NTP 时间改为跟随对端的单调时钟。
- **only-rtp**：`RecvStream::receive_recovered`（由 FEC 重建的包：不 NACK，也不计为已收到）与
  `FrameAssembler::skip`（不承载媒体的序号，如 ULPFEC 或填充包，不算缺口）。
- 互通：`tools/interop/webrtc/fec.sh` 对照无头 Chrome 157（丢包下双向 FlexFEC 与 ULPFEC、双向 RFC 8888、
  XR DLRR RTT、TMMBR）；`webrtc-interop` 示例的 `fec-server` 模式在服务端前放一个有损 UDP 代理。

### 新增：SRTP 的 MKI 与换钥、密钥派生率、AES-192/256-CM 与 NULL、RFC 6904 头部扩展加密、cryptex（only-srtp）；DTLS-SRTP MKI（only-dtls）

ADR-040（docs/adr/040-srtp-mki-cryptex.zh-CN.md）：

- **保护配置**：`Profile::Aes192CmHmacSha1_80/32`、`Aes256CmHmacSha1_80/32`（RFC 6188）与
  `NullHmacSha1_80/32`（RFC 5764；SRTCP 发送时 E 标志为 0）。新增 `Profile::sdes_name` /
  `from_sdes_name`、`Profile::encrypts`。
- **MKI 与换钥**：`Context::new_with_mki`、`add_master_key`、`set_send_mki`、`remove_master_key`、
  `send_mki`、`mki_len`（最多 16 个主密钥，MKI 长 1-255 字节；按包中的 MKI 选择密钥，否则为
  `Error::UnknownMki`；滚动计数器与重放窗口在密钥之间按 SSRC 保持）。
- **密钥派生率**：`Context::with_key_derivation_rate`（0 或不超过 2^24 的 2 的幂，RFC 3711
  §4.3.1），每个主密钥按流缓存最近一次 `r` 的会话密钥。
- **头部加密**：`Context::with_encrypted_header_extensions`（RFC 6904；AEAD 也用 AES-CM 密钥流，
  RFC 7714 §8.3）与 `Context::with_cryptex`（RFC 9335：CSRC 与整个扩展体，`0xC0DE` / `0xC2DE`，
  只有 CSRC 时补空扩展；仍接受未使用 cryptex 的包）。
- **无分配的变体**：`protect_rtp_into`、`unprotect_rtp_into`、`protect_rtcp_into`、
  `unprotect_rtcp_into`。
- **only-dtls**：`Config::with_srtp_mki`（客户端提供）、`Config::with_srtp_accept_mki`（服务端回显，
  默认关闭）、`HandshakeInfo::srtp_mki`；服务端返回不同的非空 MKI 时握手失败（RFC 5764 §4.1.3），
  DTLS 1.2 与 1.3 均如此。
- 测试：RFC 6188、RFC 6904 与 RFC 9335 向量；与 libsrtp main 逐字节交叉验证 230 个包
  （`tools/interop/srtp`，每种配置、MKI、RFC 6904、cryptex）；新 fuzz 目标 `srtp_features`。libsrtp
  遇到扩展元素之间的填充不推进密钥流，RFC 6904 在这一点上遵循 RFC。
- 基准（gpu51，`examples/srtp_bench.rs`，每包纳秒，基线 -> 本变更）：已有配置不变（在噪声内）或更快：unprotect 全部快 0-5 %（AES-128-CM 160 B 255.2 -> 243.0，AES-128-GCM 1200 B 178.3 -> 176.3），AES-CM protect 在 ±1.3 % 内，AEAD protect 1200 B 在 ±0.3 % 内，160 B 慢 1-2 %（AES-128-GCM 86.8 -> 88.6）。每个包对 SSRC 状态的查找由两次减为一次。新功能在 1200 B、带一个 CSRC 与三个扩展元素时的 AES-128-GCM protect / unprotect：普通 542.7 / 175.9，MKI 547.6 / 179.3，cryptex 555.7 / 187.1，RFC 6904 626.4 / 252.7。
- `only-webrtc` 尚未协商（SDP `a=cryptex`、加密 extmap、DTLS-SRTP MKI）。

### 变更：`only_srtp::Profile`（破坏性，内部层级）

`Profile` 改为 `#[non_exhaustive]`，`Profile::ALL` 有十项，`Profile::id` 返回 `Option<u16>`
（RFC 6188 的配置没有 DTLS-SRTP 编号）。新增 `Error::Config`、`Error::UnknownMki`、
`Error::Unsupported`。

### 新增：SCTP HEARTBEAT、对端重启、零校验和与入向重置请求（only-sctp）

ADR-042（docs/adr/042-sctp-heartbeat-restart-zero-checksum.zh-CN.md）；only-sctp 属于 Internal 层级：

- **HEARTBEAT**（RFC 9260 §8.3，`Config::heartbeat_interval`，默认 30 s）：空闲关联测量 RTT
  （`Association::rtt`）并能发现已消失的对端：未获应答的 HEARTBEAT 计入 `max_retransmissions`
  （单路径时即 Path.Max.Retrans），之后关联失败，即最后一次交互后 60-150 s。此前只应答。
- **对端重启**（RFC 9260 §5.2.2、§5.2.4）：已建立关联收到 INIT 时回复带新 tag 和 Tie-Tags 的
  INIT ACK；重启后对端的 COOKIE ECHO 关闭所有通道、丢弃排队数据并重新开始，发出新的
  `Event::Restarted`。重复的回复 COOKIE ACK，其他组合丢弃，关闭过程中拒绝重启。此前直接忽略。
- **零校验和**（RFC 9653，`Config::zero_checksum`，默认开启）：INIT / INIT ACK 中声明 "SCTP over
  DTLS"；接受零校验和，对端也声明时握手之后发送零校验和（`Association::zero_checksum`）：数据路径两端
  都不再计算 CRC-32C。内存中的 SCTP 快 1.20-1.31 倍（`examples/sctp_bench.rs`，gpu51 上与 46f25f81
  同轮 A/B，7 轮中位数）；两个回环 `Endpoint` 之间含 DTLS 的数据通道 1.003 倍。Firefox 158 与
  Chrome 157 不提供，pion/sctp 提供。
- **Incoming SSN Reset** 与 **SSN/TSN Reset** 请求（RFC 6525 §5.2.3-4）改为执行而非拒绝：前者以我们的
  Outgoing SSN Reset Request 作答（通道随之关闭），后者在我们没有在途数据时执行（双向新 TSN，SSN 归零）。
- `Event` 现为 `#[non_exhaustive]`。
- 互通：经 only-webrtc 与 Firefox 158（usrsctp）两个 offer 方向互通，含 150 s 空闲（新增
  `tools/interop/webrtc/firefox.sh`，WebDriver BiDi；`webrtc-interop` 示例支持 `ONLY_INTEROP_BIND`）；
  与 pion/sctp 使用零校验和互通（`tools/interop/sctp/run.sh`）；Chrome 157 照常通过。模糊测试
  `sctp_packet` 新增种子，gpu51 上 11 分钟，无崩溃。
- 未实现（WebRTC 均不使用）：多宿主、AUTH、ASCONF、ECN。

### 新增：SRT rendezvous、MPEG-TS 中的 AV1、录制为 MPEG-TS、HLS SAMPLE-AES（only-media）

ADR-043（docs/adr/043-media-srt-rendezvous-av1-ts-sample-aes.zh-CN.md），均为新增：

- **SRT rendezvous**（HSv5）：`srt::Conn::rendezvous` / `Conn::is_rendezvous`，以及在绑定于 `local` 的 UDP
  socket 上运行的 `srt::{rendezvous, push_rendezvous, pull_rendezvous}(engine, local, remote, ..)`。双方挥手，
  与 libsrt 相同的 cookie 竞争选出发起方（HSREQ，带其密钥的 KMREQ），应答方回复 HSRSP / KMRSP，收到 AGREEMENT
  （或发起方的下一个包）后连接。等待 `handshake_timeout` 的十倍。已与 libsrt 1.5.4（`srt-live-transmit`）
  测试推流与拉流，明文与加密。
- **MPEG-TS 中的 AV1**（AOM "Carriage of AV1 in MPEG-2 TS"）：流类型 0x06，带 `AV01` 注册描述符与 AV1 视频
  描述符，OBU 位于起始码之后并加防竞争字节，每个 PES 一个时间分隔符；解封装器也读取 GStreamer 的 `AV1G`。AV1 现可
  经 SRT、HLS MPEG-TS 与 MPEG-TS 录制传输。VP8 / VP9 没有 MPEG-TS 映射（写入文档）。
- **录制为 MPEG-TS**：`RecordFormat::MpegTs`（`.ts`），每个视频关键帧前重复 PAT / PMT。
- **HLS SAMPLE-AES**：`hls::EncryptionMethod::{Aes128, SampleAes}`、`HlsEncryption::method`（字段与构造方法）。
  MPEG-TS：Apple 的样本加密（流类型 0xdb / 0xcf，`zavc` / `aacd` / `apad`；H.264 slice 前 32 字节明文后 1:9，
  AAC 帧），每个密钥一个随机 IV 写入 `IV` 属性。fMP4：`cbcs`（带 `sinf` / `tenc` 与常量 IV 的 `encv` / `enca`，
  `senc` / `saiz` / `saio`；解析 H.264 slice 头并保持明文）。只承载 H.264 与 AAC 轨道（其它轨道不进入分段）。
  ffmpeg 能逐帧正确解码两者。
- 模糊测试目标 `srt_rendezvous` 与 `h264_sample_encryption`；`mpegts_demux` 增加 AV1 种子。

### 新增：自研 brotli 与 Zstandard（only-brotli、only-zstd），用于证书压缩（only-tls）和 HTTP（only-http）

ADR-041（docs/adr/041-brotli-zstd.zh-CN.md），新增 API：

- **`only-brotli`**（新的内部 crate，RFC 7932）与 **`only-zstd`**（新的内部 crate，RFC 8878）：纯安全
  Rust、无依赖，一次性的 `decompress(data, limit)` 和 `compress(Level, data)`。解码器覆盖完整格式（brotli：
  所有窗口大小、元数据与未压缩 meta-block、块切换、上下文模式与映射、静态字典及其 121 种变换；zstd：拼接帧与
  可跳过帧、Huffman 与 treeless 字面量、predefined / RLE / FSE / repeat 表、重复偏移、内容大小与 XXH64 校验和），
  接受与拒绝的输入与参考解码器一致；输出和内存止于 `limit`（`Error::TooLarge`），解压炸弹的代价不超过它。
  编码器（基于哈希链的 LZ77、Huffman / FSE 编码）对证书链的压缩率不差于 zlib 9 级。`only_zstd::xxh64` 公开。
  测试：官方测试向量（brotli `testdata` 的全部 44 个流；zstd 的 golden 解压、错误与压缩文件，1000 个
  `decodecorpus` 帧）、`brotli` 与 `zstd` 命令行双向互通，以及对照 Google brotli 解码器（`brotli-decompressor`）
  和 libzstd 的差分模糊测试目标（`brotli_decompress`、`brotli_roundtrip`、`zstd_decompress`、`zstd_roundtrip`）。
- **only-tls**：证书压缩（RFC 8879）在 zlib 之外支持 brotli 和 zstd。客户端提供 brotli、zstd、zlib；服务器在
  客户端提供的算法中发送最小的结果（每张证书每种算法只压缩一次并缓存），客户端证书同理。新增
  `CertCompression { Zlib, Brotli, Zstd }` 与两个 builder 上的 `certificate_compression_algorithms(&[CertCompression])`；
  `certificate_compression(true)` 现在表示三种全开（默认值不变：服务器开、客户端关）。与以 brotli、zstd、zlib
  构建的 OpenSSL 3.5 双向互通（`tools/interop/tls/certcomp.Dockerfile`、`tools/interop/tls/run.sh`；
  `tls-interop --cert-comp`）。
- **only-http**：`Compress::brotli` 与 `Compress::zstd`（级别，默认 `None`）让 `middleware::compress` 对接受它们的
  客户端回应 `br` / `zstd`（优先顺序 br、zstd、gzip、deflate）；`Files` 也服务 `.zst` 副本（`Content-Encoding: zstd`）。

### 新增：HLS 加密与录制（only-media），AES-CBC（only-crypto）

ADR-034（docs/adr/034-media-hls-encryption-recording.zh-CN.md），均为新增：

- **HLS AES-128**：`HlsConfig::encryption`（`HlsEncryption { keys, rotate_every }`）用
  AES-128-CBC + PKCS #7 加密每个分片和 LL-HLS part（MPEG-TS 与 fMP4），IV 为媒体序列号（part
  单独加密，使用其分片的 IV），每个密钥的第一条媒体之前写 `#EXT-X-KEY:METHOD=AES-128`；fMP4 初始化
  分片保持明文（出现在密钥之后的 map 前写 `METHOD=NONE`）。`KeyProvider`（`key(path, n) -> HlsKey`、
  `authorize(path, n, &Context)`）发放密钥并决定 `/<path>/key-<n>.key` 请求（拒绝时 403）；
  `HlsKey::with_uri` 指向外部密钥服务器；`RandomKeys` 发放随机密钥。密钥每 `rotate_every` 个分片
  轮换，只在仍有保留的分片使用它时提供。`MediaHttp` 把 `.key` 交给 `Hls`。用 ffmpeg 播放加密的
  直播播放列表测试。
- **录制**：`only_media::record::{Recorder, RecordConfig, RecordFormat, RecordHooks,
  RecordFile, NoHooks}` 把 Hub 中的流录制为 fMP4 或 FLV 文件，按 `segment_duration` /
  `segment_bytes` 在关键帧处切换文件，重新推流时也切换，用 `max_files` 轮换，提供 `file_name`、
  `on_start`、`on_stop`（在 `sync_all` 之后）与 `on_remove` 钩子。文件由录制器自己的写线程写入，
  从不在 I/O 线程上；队列受 `max_queued_bytes`（32 MiB）约束，超过时关闭当前文件并丢包直到下一个
  关键帧（`Recorder::dropped`）。录制的文件用 ffprobe / ffmpeg 检查。
- **only-crypto**：`Aes::{encrypt_cbc, decrypt_cbc, encrypt_cbc_padded, decrypt_cbc_padded}`
  （SP 800-38A 向量，PKCS #7 与 OpenSSL 对照）。

### 新增：macOS 上与 only-dpdk UDP 上的 ECN（only-sys、only-quic、only-dpdk）

ADR-035（docs/adr/035-ecn-macos-and-userspace-udp.zh-CN.md）。QUIC 连接现在在 macOS 上和用户态
协议栈上也会标记 ECT(0)、读取收到的码点并校验 ECN，不再只限于 Linux。only-sys 仅在 macOS 上新增
`enable_ecn`、`ecn_available`、`recv_from_ecn` 与 `send_to_ecn`（每个数据报一次 `sendmsg` /
`recvmsg`，带 `IP_TOS` / `IPV6_TCLASS` 控制消息；`ONLY_UDP_ECN=0` 可关闭），供 kqueue UDP 循环与
only-core 在 macOS 上写数据报使用。only-dpdk 的 UDP 把码点写入 IP 头，并报告收到的码点
（`Conn::rx_ecn`）；only-core 对虚拟数据报套接字也保留码点（隐藏的 `ConnInner::drain_output_ecn`）。
`quic_conn` 模糊测试目标现在会选择路径如何对待 ECN（保留、清除、CE、ECT(1)）；此前它的数据报从不
带标记。与 quic-go 的互通脚本在 macOS 上也检查 ECN 校验。only-quic 的 README 不再把兼容版本协商列为缺失（已在 ADR-013 与 ADR-014 中完成）。Linux 的
API 快照无变化；unsafe 清单：only-sys 91 → 97 个块。

### 新增：RTCP XR、TMMBR / TMMBN、RFC 8888 反馈与 FEC（only-rtp）

ADR-036（docs/adr/036-rtp-xr-tmmbr-ccfb-fec.zh-CN.md）。`only-rtp` 属于 Internal 层级；`Rtcp` 新增四个
变体（PT 207 与 RTPFB 3 / 4 / 11 不再解析为 `Rtcp::Unknown`），其余均为新增：

- **RTCP XR**（RFC 3611）：`Rtcp::ExtendedReport`，`XrBlock` 覆盖全部报告块（丢包 / 重复 RLE、接收
  时间、RRTR、DLRR、统计摘要、VoIP 指标、未知块）。`RrtrResponder` 用 DLRR 应答 RRTR；`rtt_from_dlrr`
  与 `RecvStream::{handle_dlrr, rtt}` 让不发送 SR 的接收方得到 RTT；`RecvStream::{statistics_summary,
  duplicates}`；用于 VoIP 指标的 `BurstLossModel`（附录 A.2，复现 §4.7.2 示例）。
- **TMMBR / TMMBN**（RFC 5104）：`Rtcp::{Tmmbr, Tmmbn}` 与 `TmmbItem`；`bounding_set`、
  `bounded_bitrate`、`TmmbrHandler`（按请求者保存请求，25 s 超时，生成 TMMBN）。
- **RFC 8888**：`Rtcp::CongestionControl(CcfbFeedback)`（`CcfbStream`、`CcfbMetric`、ATO 常量）；
  `CcfbReceiver` 按媒体 SSRC 生成带 ECN 的反馈（50 ms / 100 个包）；`CcfbSender` 把它映射为供
  `BandwidthEstimator` 使用的 `PacketResult`。
- **FEC**（`only_rtp::fec`）：用于 ULPFEC（RFC 5109）、libwebrtc `flexfec-03` 与 RFC 8627 两种 FlexFEC
  的 `FecEncoder` / `FecDecoder` / `FecHeader`；按帧交织掩码，迭代且逐字节一致的恢复；`fec::red`
  （RFC 2198 解析 / 写出 / 封装 / 解封装）。
- 测试对照 libwebrtc 单元测试向量、RFC 3611 示例与模拟丢包；新增 fuzz 目标 `rtp_fec`，扩充
  `rtp_rtcp`。尚未接入 `only-webrtc`。

### 新增：SCTP 消息交错（I-DATA）与流调度器（only-sctp）

ADR-037（docs/adr/037-sctp-idata-schedulers.zh-CN.md），仅新增（only-sctp 属于 Internal 层级）：

- **I-DATA / I-FORWARD-TSN（RFC 8260 §2）**，默认提供（`Config::message_interleaving`），对端也提供时
  使用（`Association::message_interleaving`）：不同通道上消息的分片交错发送，大消息不再阻塞其他通道上的
  小消息（在另一通道上排在 200 kB 消息之后的 4 字节消息，现在在第一个往返内到达，而不是在它之后）。
  否则照旧使用 DATA 与 FORWARD TSN；收到未协商的那种数据 chunk 时中止关联（protocol violation）。
- **流调度器（RFC 8260 §3）**：`Config::scheduler`，可选 `Scheduler::{FirstComeFirstServed,
  RoundRobin, RoundRobinPerPacket, Priority, FairCapacity, WeightedFairQueueing}`（默认加权公平排队），
  依据通道优先级：`ChannelOptions::with_priority`、对端 DATA_CHANNEL_OPEN 中的值、
  `Association::set_channel_priority`（RFC 8832 语义，越大越重要；0 按 256 处理）。此前消息按先到先服务
  发送。
- 发送端按流排队，分片在获得 TSN 时从每条消息的一块共享缓冲区切出；使用 I-DATA 时，只有在已开始的
  消息不超过对端窗口一半时才开始新消息，因此同时发送许多大消息不会让对端窗口被不完整消息占满；单 chunk 消息跳过重组，按序到达的
  I-DATA 分片直接追加。gpu51 上与 59d41cc2 同轮 A/B（`quiet.sh`，CPU 2-9，7 轮交替，取中位数）：内存中的 SCTP（`examples/sctp_bench.rs`）1 KiB 消息 1.19 倍（DATA 回退 1.21 倍）、64 KiB 1.33 倍（1.14 倍）、16 KiB 无序 1.12 倍（1.08 倍）、四个通道 1.20 倍（1.07 倍）；两个回环 `Endpoint` 之间含 DTLS 的数据通道吞吐 0.986 倍（189.0 对 191.7 MB/s；此前一次为 1.009 倍，各轮相差 ±5%）：无回退。
- 互通：经 UDP 与 pion/sctp v1.12.0（新增 `tools/interop/sctp/run.sh`：两种角色，pion 的交错开与关，
  有无丢包）；pion WebRTC 协商 I-DATA；无头 Chrome 157 双向，默认走 DATA，也走 I-DATA（`browser.sh`
  新增的 `CHROME_ARGS` 打开其 `WebRTC-DataChannelMessageInterleaving` field trial）。fuzz 目标
  `sctp_packet` 驱动一对 I-DATA 关联和一对 DATA 关联。only-webrtc 不改 API，沿用新的默认值。

### 新增：证书吊销：CRL、OCSP、装订响应校验（only-x509、only-tls）

ADR-038（docs/adr/038-x509-revocation.zh-CN.md），均为新增。库内不访问网络：CRL 与 OCSP 响应由应用获取。

- **only-tls**：`RevocationPolicy::{Off, SoftFail, HardFail}`（默认关闭，关闭时无开销）；
  `ClientConfigBuilder::ocsp_policy` 在 TLS 1.3 与 1.2 中校验服务器为叶证书装订的 OCSP 响应（由签发者或带
  id-kp-OCSPSigning 的委托响应者签名、针对该叶证书、在 5 分钟偏差内有效）并自动请求装订：软失败只拒绝有效的
  “revoked”（`certificate_revoked`），硬失败要求有效的“good”（否则 `bad_certificate_status_response`）。
  `Crls` 配合 `ClientConfigBuilder::crls` 与 `ServerConfigBuilder::client_crls` 检查对端证书链中根以下的每张
  证书。
- **only-x509**（内部 crate）：`Crl`、`CrlSet`（完整与 delta CRL、原因码、issuingDistributionPoint 范围、
  removeFromCRL）、`Verifier::{crls, revocation_mode, clock_skew}`、`RevocationMode`、`OcspResponse` /
  `OcspValidation` / `OcspRequest`（RFC 6960、nonce、SHA-1/256/384/512 的 CertID）、
  `Certificate::{crl_distribution_points, ocsp_urls, ca_issuer_urls}`、生成器 `CrlParams` 与
  `OcspResponseParams`、新的 `Error` 变体。
- 测试使用 OpenSSL 生成的 CRL 与 OCSP 响应（`tests/data/revocation/gen.sh`），内存中的 TLS 覆盖每种策略，与
  `openssl s_server -status_file` 及 OpenSSL CRL 互通；新的模糊测试目标 `x509_crl` 与 `x509_ocsp`。

### 新增：protobuf 文本格式（only-protobuf）

ADR-030（docs/adr/030-protobuf-text-format.zh-CN.md），均为新增：`only_protobuf::text` 为生成消息
（`to_string`、`to_string_with`、`from_str`、`from_str_with`）和 `DynamicMessage`（`parse_dynamic`、
`to_text`、`from_text`）解析和输出文本格式，带 `PrintOptions`（`single_line`、
`print_unknown_fields`、`type_pool`）、`ParseOptions`（`allow_unknown_fields`、`type_pool`）和
`TextError`（行号与列号）。支持标量、按名字或数值的枚举、带全部转义的 string 与 bytes、`{ }` 或
`< >` 中的消息、两种写法的 repeated 字段、map、oneof、group、扩展（`[pkg.ext]`）、`Any` 展开
（`[type.googleapis.com/...]`）、注释、分隔符、十六进制 / 八进制整数、`inf` / `nan`。protobuf
一致性运行器 v35.1：文本格式通过 909 项、失败 0 项（此前跳过 909 项）；二进制 + JSON 仍为通过
5627 项。新增 fuzz 目标 `protobuf_text`（解析 → 输出 → 再解析）。

### 新增：BitTorrent 快速续传

`only-bittorrent`（ADR-033，docs/adr/033-bittorrent-fast-resume.zh-CN.md），增量：

- **`ClientConfig::resume_dir`**（默认无）与 **`resume_interval`**（30 秒）：每个种子的状态保存为
  `<info hash 十六进制>.resume`，有改动时定时保存、暂停后不久保存、`Client::close` 时（最后一次写入
  之后）保存，均为原子写入（临时文件、fsync、rename）；`Client::remove` 删除它。再次添加的种子从中
  恢复，不对数据做哈希检查。
- **格式**：带版本、以 SHA-256 校验和收尾的 bencode：已有分片位图、info 字典、v2 分片层、每个文件
  的大小与修改时间、对等方、tracker、web seed、跨会话的上传/下载累计与做种时间、速率与做种限制。
  损坏、截断、属于其他种子或更高版本的数据会被拒绝（`TorrentEvent::ResumeRejected`，随后完整检查）；
  绝不会 panic（fuzz 目标 `bt_resume`）。
- **校验**：大小或修改时间变化的文件，其分片重新检查（`TorrentEvent::ResumeAccepted { pieces,
  rechecking }`、`TorrentStats::pieces_checked`）。崩溃后，客户端仍在下载的文件按大小信任（客户端
  自己之后的写入让它们更新）；最后一个保存间隔内的分片会重新下载。
- **字节形式**：`Torrent::resume_data`、`AddOptions::resume_data`、`Client::add_resume`（仅凭续传
  数据添加种子；`AddError::Resume`、`ResumeError`）、`Torrent::save_resume_data`。自定义存储通过
  `Storage::file_stamps`（`FileStamp`）报告文件。
- `TorrentStats` 新增 `total_uploaded` 与 `total_downloaded`；续传时 `seeding_time` 与做种限制跨会话
  累计。
- 测试：`close` 后与下载中途 `SIGKILL` 后重启且没有分片被重新哈希、改动的文件单独重新检查、v1/v2/
  混合种子、恢复 v2 磁力链接的分片层。gpu51 上 bt-bench 512 MiB TCP 为改动前的 1.01 倍（噪声）。fuzz `bt_resume` 11 分钟无问题。

### 新增：`Endpoint` 经 TCP 与 TLS 使用 TURN、主动及服务器端 ICE-TCP、与 Chrome 的 simulcast

新增 API（ADR-032，docs/adr/032-webrtc-turn-streams-ice-tcp-simulcast.zh-CN.md）：

- **经 TCP 与 TLS 分配的中继候选**：`Endpoint::gather_relay_via(&engine, &server, timeout)`，参数为
  `RelayServer`（`udp`、`tcp`、`tls(addr, server_name, tls_config, ..)`，或
  `from_url("turn:host?transport=tcp" | "turns:host")`，`turns:` 还需 `tls_config`）。分配依附于 engine
  的一条连接；其候选优先级低于经 UDP 分配的候选，且不带来 server-reflexive 候选；排队超过 256 KiB 时丢弃
  中继数据。
- **丢失的分配会重新建立**（连接关闭、刷新失败），1 秒后开始，等待时间加倍至最多一分钟，`gather_relay`
  也是如此：新的中继候选为新 peer 替换旧候选，并加入已打开的 peer；对端可从中继到达时这些 peer 继续工作。
- **主动 ICE-TCP**：`Endpoint::dial_tcp(&engine)` 增加一个主动 TCP 候选（端口 9），在每个候选对发出第一次
  检查时为它拨一条连接；主动与被动连接共用 256 的上限。
- **`RtcServer` 上的被动 ICE-TCP**：`RtcServer::tcp_candidates(addrs)` 与 `RtcServer::tcp()`（engine TCP
  监听器的 `RtcTcp` acceptor）；连接数最多为 `max_peers` 的两倍。
- **`Endpoint::candidate_filter(f)`**：新 peer 使用并发出的本地候选（只用中继或只用 TCP 的策略）；
  `Candidate::kind()` 与 `Candidate::transport()`。
- **`Peer::request_layer_keyframe(mid, rid, kind)`**：只向接收到的某一 simulcast 层发 PLI 或 FIR（SFU
  切换观众所看的层）。已用无头 Chrome 双向验证 simulcast：Chrome 发出三层 VP8，Chrome 解码所选的层，我方的
  simulcast 回退为第一层（Chrome 不接收 simulcast）。
- `only-ice`（内部层级）：`Candidate::relayed_over_stream`。新 fuzz 目标 `webrtc_turn_url`。互通：pion（在
  only-turn 与 pion/turn 上经 TCP/TLS 的中继，双向 ICE-TCP），coturn（经 TCP/TLS 的中继），Chrome（只用
  ICE-TCP，只用经 UDP/TCP/TLS 的中继，simulcast 与层选择）。

### 新增：only-media 的 VP8、VP9 与 AV1，多码率 HLS 播放列表

新增（ADR-031，docs/adr/031-media-vp8-vp9-av1-multivariant-hls.zh-CN.md）：

- **hub 中的 VP8、VP9 与 AV1**：`Codec::{Vp8, Vp9, Av1}`，有规范形式（`vpcC` / `av1C` 配置记录、帧、由带长度
  OBU 组成的 AV1 temporal unit），关键帧由码流判定，因此 GOP 缓存、HLS 切片与慢播放器丢包对它们同样有效。
  承载于 Enhanced RTMP / FLV（`vp09`、`av01`、`vp08`）、RTSP（经 only-rtp 的 RFC 7741 / RFC 9628 / AV1 RTP，
  录制与播放）、fMP4 HLS（`vp08` / `vp09` + `vpcC`，`av01` + `av1C`）以及 WHIP / WHEP（`webrtc::rtc_config`
  启用它们）。MPEG-TS 不承载。新模块 `codec::vp8`、`codec::vp9`、`codec::av1`；`Track::video_from_keyframe`、
  `Track::codec_string`（RFC 6381）；`rtp::Depacketizer::picture_size`。
- **多码率 HLS**：`Hls::add_multivariant(name, Multivariant)` 在 `/<name>.m3u8` 提供由分别发布的多路流组成的
  播放列表（`Variant`：路径、配置或由分段测得的码率、音频组；`AudioRendition`：组、名称、语言、默认），带
  `BANDWIDTH`、`AVERAGE-BANDWIDTH`、`CODECS`、`RESOLUTION`、`AUDIO` 与 `EXT-X-MEDIA` 音频组，适用于 MPEG-TS 与
  fMP4，并支持 LL-HLS；`Hls::remove_multivariant`。
- 变更：`webrtc::rtc_config` 现在接受 VP8、VP9 与 AV1，只含这些编码的 WHIP offer 会被发布，不再被拒绝（406）。
  修复：`flv::parse_video` 会丢掉 `avc1` / `hvc1` 以外 FourCC 的 coded frames 的前 3 个字节。视频无法被分段格式
  承载的流（MPEG-TS 中的 VP9 或 AV1）在 HLS 中不再卡住，而是按纯音频流切片。修复：直播播放列表的
  `EXT-X-TARGETDURATION` 可能在刷新之间变化（出现 1.007 s 的分段后由 1 变为 2），Chrome 自带的 HLS 播放器
  会拒绝；现在按 RFC 8216 四舍五入取整，且永不减小。修复：RTP 的 AAC 解包（RTSP 录制）在 AU-headers-length 为 1 到 8
  位时会 panic（由 fuzz 发现）。
- 热路径，在 gpu51 上与之前的 main 同轮 A/B（交替 5 轮取中位数，head/base）：hub 扇出到 1 / 16 / 256 个订阅者
  1.008 / 1.009 / 1.011；HLS 切片 TS 0.976、TS + part 1.016、fMP4 1.005、fMP4 + part 1.011；FLV 解码 H.264 0.976、
  H.265 0.993。退休指令数相同或更少；单项 1–3% 的波动会随无关的代码改动变化（代码布局）。
- 互通：ffmpeg / ffprobe 验证 Enhanced RTMP 与 fMP4 HLS 上的 VP9 与 AV1、RTSP 上的 VP8 / VP9 / AV1（录制与播放，
  TCP 与 UDP）、两种格式的多码率播放列表；headless Chrome 通过 WHIP 推 VP8、VP9、AV1 与 H.264，通过 WHEP 解码，
  并播放多码率 fMP4 LL-HLS 播放列表（`tools/interop/media/browser.sh`）。

### 新增：only-log 的 `/regex` 消息过滤，基于新的内部 crate only-regex

增量（ADR-047，docs/adr/047-log-regex-filters.zh-CN.md）：

- **only-log**：`ONLY_LOG=info,only_http=debug/connection (reset|refused)` 只保留格式化后的消息与模式匹配的记录，与 env_logger 相同（第一个 `/` 之后的全部内容都是模式；空模式不过滤）。新增 `Filter::message_regex`、`Filter::message_pattern` 与 `Filter::matches(&Record)`（级别加消息；消息逐段送入匹配器，不拼接字符串）；`Filter` 的 `Display` 会写回模式。`FmtLogger` 直接匹配它已经为这一行格式化好的消息。没有模式的过滤器不增加任何开销。`"info/x".parse::<Filter>()` 以前报错，现在成功；无效模式产生指明 `/pattern` 及出错字节位置的 `ParseFilterError`。
- **only-regex**（新的内部 crate，无依赖，`#![forbid(unsafe_code)]`）：`Regex::new`、`is_match(&str)`、`is_match_fmt(fmt::Arguments)`（不分配内存）。语法为去掉捕获、环视与 Unicode 类的 `regex` crate 语法：支持 Unicode 的 `\d \w \s`、字符类、贪婪与惰性重复、分支、分组、`^ $ \A \z \b \B`、标志 `i` `m` `s` `U`。Thompson NFA，编译时在字符类（ASCII 查表，其余用区间）上构建 DFA，并以 Pike VM 回退：任何模式都是线性时间，约每字符 1 ns。Unicode 表由 `tools/regex-tables` 从 regex-syntax 生成；差分模糊测试目标 `regex_search` 与 `regex` crate 对比；`tools/codec-bench logregex` 比较两者性能。

### 变更：P-256 生成密钥、签名与 ECDH 更快；无 IFMA 时 RSA 平方用 Karatsuba

only-crypto 在带 BMI2 + ADX 与 AVX2 的 x86_64 上：P-256 固定基梳形表与 ECDH 乘法在整个标量乘法中把累加点留在同一个汇编帧里。Zen 4 上对比 ring：生成密钥 1.40 倍 → 1.57 倍，签名 1.38 倍 → 1.49 倍，ECDH 1.12 倍 → 1.15 倍，secp256r1 TLS 握手为 rustls+ring 的 1.07 倍 → 1.08 倍。在没有 AVX-512 IFMA 的 x86_64 CPU 上，3072 与 4096 位 RSA 的平方改为一层 Karatsuba：验签 +5% / +9%。常数时间性质不变（`tools/ct-dudect`：无泄漏）。无公开 API 变更（docs/BENCHMARKS.zh-CN.md）。

### 新增：SOCKS 客户端、HTTP/WebSocket 客户端的 SOCKS 代理、UDP 分片重组、SOCKS4 BIND

增量（ADR-019，docs/adr/019-socks-client-fragments-socks4-bind.zh-CN.md）：

- **`only_socks::SocksClient`**：SOCKS5 `CONNECT`、`BIND` 与 `UDP ASSOCIATE`（无认证或用户名/
  密码），SOCKS4 与 SOCKS4a `CONNECT` 与 `BIND`。在 engine 上：`dial`（一个 acceptor；若是 `Tls`
  acceptor 则在隧道内运行 TLS）、`bind`（`on_bound` 得到代理的监听地址）、`udp_associate`（一个
  `UdpAssociation`：`send_to`、`close`；数据报交给 `on_datagram`）；隧道打开前的所有失败（代理不可达、
  拒绝、乱码、超时）都交给 `on_error`。阻塞方式：`dial_blocking`（一个 `TcpStream`）、`bind_blocking`
  （`BlockingBind::accept`）、`udp_associate_blocking`（`BlockingUdp`）。
  `from_url("socks5h://user:pass@host")`、`handshake_timeout`（10 秒）、`bind_timeout`（60 秒）、
  `Version`、`impl From<SocketAddr> for Dest`，并重新导出 `ProxyRefused`。
- **`only_http::client::Client` 与 `only_ws::client::dial` 支持 SOCKS 代理**：`Proxy` 接受
  `socks5://`、`socks5h://`、`socks4://` 与 `socks4a://` URL（默认端口 1080，URL 凭据作为 RFC 1929
  凭据或 SOCKS4 user id）；所有请求（包括 `http://`）都走隧道；`socks5`/`socks4` 先解析目标（优先
  IPv4），`socks5h`/`socks4a` 由代理解析。拒绝是 `ProxyRefused`，带最接近的 HTTP 状态码以及新增的
  `ProxyRefused::socks_reply()`。
- **UDP 分片重组**（RFC 1928 `FRAG`），用于 SOCKS5 服务端中继和客户端关联：按序的序列，最多
  65,507 字节，每个关联一个，5 秒计时。
- 服务端支持 **SOCKS4 `BIND`**，与 SOCKS5 共用 `Socks::bind(true)` 开关和 `allow` 钩子。
- 行为变化：`Proxy::from_env` 也读取 `all_proxy` / `ALL_PROXY`；原来丢弃分片数据报的中继现在会重组；
  设置 `bind(true)` 时会处理 SOCKS4 `BIND` 请求。
- 互通（`tools/interop/socks/run.sh`，15/15）：我们的客户端对 Dante 和 only-socks，curl/PySocks/
  手写客户端对服务端（分片、SOCKS4 BIND）。新增模糊测试目标 `socks_client`（客户端握手、隧道
  transport、重组）。

### 新增：arpc 中间件、coder 与客户端连接池（only-arpc）

均为新增（ADR-023，docs/adr/023-arpc-middleware-coders-pools.zh-CN.md）：

- **中间件**：`Routes::middleware`（所有请求和通知）与 `Routes::method_middleware(method, ..)`
  接受 `Fn(&mut Context, Next)`；`next.run(ctx)` 执行调用链的其余部分（其后的代码在 handler 之后
  执行），不调用它直接返回即中止。顺序固定（全局、方法、handler），与注册先后无关。新增
  `Context::values` / `values_mut` / `responded`。没有中间件的路由直接调用 handler。
- **Coder**（`only_arpc::coder`）：作用于整帧的 `Coder` trait，`Routes::coder`，按添加顺序编码、
  逆序解码，与 Go 的 `MessageCoder` 相同。`Gzip::new(threshold)`（保留位第 7 位，解压量受
  `max_body_bytes` 限制）与 `Appender::new(name, bit)`（tracing 用第 0 位）与
  `arpcex/extension/middleware/coder` 线路兼容。`Values` 通过 `Peer::call_with` /
  `call_async_with` / `notify_with` 携带，应答用请求的值编码。已与 fib 的 Go arpc 双向验证
  （`tools/interop/arpc/run.sh`）；新增模糊测试目标 `arpc_coders`。
- **连接池**：`Pool::builder()`（`size`、`balance`：`Balance::RoundRobin` / `LeastPending`、
  `heartbeat`、`reconnect_interval`、`connect_timeout`）`.dial(..)`；调用发往在线的连接，心跳会
  关闭并替换沉默的连接。
- **等待应答的调用有上限**：`Routes::max_pending_calls`（默认每连接
  `DEFAULT_MAX_PENDING_CALLS` = 65536）；超出时调用以新增的 `CallError::Overloaded` 失败。新增
  `Peer::pending_calls`、`Peer::ping`。
- 实测（gpu51，同轮 A/B，10 轮中位数）：无中间件的调用为之前的 0.98 倍，一个中间件为无中间件的
  1.00 倍，均在约 4% 的噪声内；每次调用的用户态指令 +1.5%，周期数不变。

### 新增：BitTorrent v2 与混合种子、web seed、LSD、IPv6 DHT、速率与做种限制

`only-bittorrent`（ADR-018，docs/adr/018-bittorrent-v2-webseeds-lsd-ipv6-limits.zh-CN.md）：

- **BEP 52 v2 与混合种子。** 新模块 `merkle`（SHA-256 默克尔树、分片层、按 libtorrent 方式生成的
  哈希请求证明）。`metainfo`：`InfoHashV2`、`TorrentVersion`、`FileEntry::pieces_root`、
  `PieceLayers`、`MetaInfo::{info_hash_v2, piece_layers, verify_piece}`、
  `Info::{verify_piece_with, piece_file, file_pieces, ...}`、`Builder::version`。v2 文件按分片
  边界排布（纯 v2 种子由解析器合成填充文件），三种种子共用一个分片空间。`MetaInfo::info_hash` 为
  对等方使用的哈希（纯 v2 种子为截断的 SHA-256）。磁力链接 `urn:btmh:`。peer wire：v2 握手位，
  hash request / hashes / hash reject（`Handshake::with_v2`；客户端只为 v2 与混合种子设置该位）。客户端以两个哈希公告并接受混合种子，为磁力链接用哈希请求
  获取缺失的分片层，并应答对方的哈希请求。解析时拒绝与根不符的分片层，以及两部分不一致的混合种子。
- **Web seed（BEP 19）**，经 only-http 客户端：`ClientConfig::web_seeds`（默认开启）、
  `AddOptions::web_seeds`、`Torrent::add_web_seed`、`TorrentEvent::WebSeedError`；每个范围请求
  最多 4 MiB，每个 web seed 同时一个分片，退避最长 10 分钟。
- **本地服务发现（BEP 14）**：模块 `lsd`，`ClientConfig::lsd`（默认开启；私有种子从不使用），在
  独立线程上运行，每秒最多处理 50 条公告。
- **IPv6**：监听 `[::]:port` 的客户端为双栈（IPv4 对等方保持普通地址）；DHT 维护 IPv6 路由表
  （BEP 32：`nodes6`、`want`、`Node::set_ipv6`、`compact_nodes6`、`Client::dht_nodes6`）。
- **速率限制**（`RateLimits`；`ClientConfig::rate_limits`、`Client::set_rate_limits`、
  `AddOptions::rate_limits`、`Torrent::set_rate_limits`）与**做种限制**（`SeedLimits` 分享率与
  时间；`TorrentEvent::SeedLimitReached` 并暂停种子）。`TorrentStats` 新增 `seeding_time` 与
  `web_seeds_active`。
- 互操作：与 libtorrent 2.0 双向互通 v2 与混合种子（.torrent 与磁力链接），与 aria2 1.37 互通混合
  种子，从 nginx 获取 web seed，Docker 网络上的 LSD。新增模糊测试目标 `bt_lsd` 与 `bt_merkle`；
  扩展 `bt_bencode`、`bt_peer_wire`、`bt_krpc`。
- 有意不实现 BEP 44（ADR-018）。

### 新增：protobuf 的 group、extension、edition、JSON 与反射；gRPC 服务端反射

ADR-022（docs/adr/022-protobuf-gaps.zh-CN.md）：

- **only-protobuf-build**：proto2 `group` 字段、`extend` 块（带类型的 `Extension` /
  `RepeatedExtension` 常量）、扩展范围、MessageSet；edition 2023 与 2024 及特性解析（字段存在性、
  封闭枚举、packed / expanded、`DELIMITED`、命名风格、`export` / `local`）；自定义 option 与文本格式
  聚合值；与 protoc 一致的描述符，按包内嵌（`FILE_DESCRIPTOR_SET`、`descriptor_pool()`），
  `Config::descriptors`、`Config::file_descriptor_set_path`；内置 `descriptor.proto`、`type.proto`、
  `api.proto`、`source_context.proto`。
- **only-protobuf**：`ExtensionSet`、`Extendable`、`Extension`、`RepeatedExtension`；
  `encoding::GroupCodec`、封闭枚举解码函数；`Enumeration::is_known`；`reflect`（`DescriptorPool`、
  各描述符、`DynamicMessage`、`Value`、`ReflectMessage`）；`json`（标准 proto3 JSON、well-known
  类型、`ignore_unknown_fields`）；`well_known` 中的描述符类型。
- **only-grpc**：`reflection::register`（gRPC 服务端反射 v1 与 v1alpha，供 grpcurl / grpcui
  使用），反射消息位于 `reflection::v1` / `v1alpha`；现在依赖 only-protobuf。
- 验证：protobuf 一致性运行器 v35.1，二进制 + JSON 通过 5627 项、失败 0 项
  （`tools/protobuf-test/conformance/run.sh`）；描述符集与 protoc 一致；grpcurl
  （`tools/interop/grpc/grpcurl.sh`）；fuzz 目标 `protobuf_json`、`protobuf_descriptor`。

行为变化：proto2（封闭）枚举字段遇到未知数值时放入未知字段，不再存入字段；proto2 消息的扩展字段现在
位于 `extensions`，不再在 `unknown_fields` 中；超过 5 字节的 tag 被拒绝（与 C++ 一致）。编解码开销不变：在 gpu51 上与上一提交同轮 A/B
（交替 5 轮取中位数，prost 作对照）：Point 12/18 ns → 12/18 ns，Feature 19/47 ns → 18/45 ns，
AllTypes 编码 309 → 312 ns（+1%，prost 509 → 505），解码 1629 → 1448 ns（−11%，prost 1788 → 1749）。

### 新增：only-dtls 的 DTLS 1.3、连接 ID、PSK 与会话恢复

除注明外均为新增（ADR-021，docs/adr/021-dtls13-cid-resumption.zh-CN.md；only-dtls 属 Internal 层）：

- **DTLS 1.3**（RFC 9147），沿用同一个 sans-io `Connection`：带记录号加密的统一记录头，随 KeyUpdate
  递增的 epoch（`Connection::update_keys`，密钥接近使用上限前自动更新），ACK 且只重传未确认的分片，
  无状态的 HelloRetryRequest cookie（`HelloVerifier::check` 对 DTLS 1.3 ClientHello 回以 HRR），
  `use_srtp`，TLS 1.3 导出器。用 `Config::with_versions` 开启（默认只有 DTLS 1.2，`Config::webrtc`
  也一样）；同时启用两个版本时，遇到只支持 1.2 的对端回退到 DTLS 1.2，并做 RFC 8446 降级检查。新增
  `Version`、`Connection::version`、`HandshakeInfo::version`、`CipherSuite::TLS13` 与
  `CipherSuite::is_tls13`。
- **连接 ID**：DTLS 1.2 的 RFC 9146 `tls12_cid` 记录与 DTLS 1.3 CID，配合
  `Config::with_connection_id`、`Connection::local_connection_id`、
  `HandshakeInfo::{local_connection_id, peer_connection_id}` 以及按 CID 分发数据报的
  `only_dtls::connection_id`。
- **会话恢复**：DTLS 1.2 会话 ID（上限 1024 条的缓存）与 RFC 5077 票据，DTLS 1.3 NewSessionTicket
  （`psk_dhe_ke`），配合 `Config::with_session_resumption`、`with_ticket_key`（`TicketKey`）、
  `with_ticket_lifetime`（默认 2 小时，最长 7 天）、`Event::NewSession(Box<Session>)`、
  `Connection::client_resume` 与 `HandshakeInfo::resumed`。
- **外部 PSK**：`Psk`、`Config::with_psks`、DTLS 1.2 的 PSK / ECDHE-PSK AEAD 套件（`CipherSuite::PSK`、
  `is_psk`）以及 DTLS 1.3 外部 PSK；只做 PSK 的服务端无需证书。`HandshakeInfo::psk_identity`；告警
  `MissingExtension`、`UnknownPskIdentity`。
- 变更：`Config` 默认套件列表以 DTLS 1.3 与 PSK 套件开头（只在对应版本或配置了 PSK 时使用，只用
  DTLS 1.2 的配置行为不变）；DTLS 1.3 握手后 `Connection::poll_timeout` 也可能返回时间（最后一轮待
  确认、票据、KeyUpdate）。
- 测试：MTU 256 下模拟丢包、乱序、重复链路上的 DTLS 1.3（含 KeyUpdate 与 CID），部分重传，最后一轮与
  ACK 丢失，cookie，会话恢复，PSK，版本协商；密钥计划对照 RFC 8448。互通（`tools/interop/dtls/run.sh`，
  新增 `Dockerfile` 与 `dtls13.sh`）：OpenSSL 4.1 与 wolfSSL 5.8.4（DTLS 1.3 双向、HRR、MTU 300、
  KeyUpdate、会话恢复、PSK、版本协商、与 wolfSSL 的 CID），pion/dtls v3（CID、PSK 套件）。fuzz 目标
  `dtls_record` 与 `dtls_handshake` 覆盖 CID 与统一头记录以及 DTLS 1.3 状态机。DTLS 1.2 记录层在 gpu51 上
  同轮 A/B（新增 `dtls-bench` 示例）：64 字节记录为原来的 0.97-1.01，1 KiB 为 1.00-1.02。

### 新增：TCP 与 TLS 上的 TURN、TURN 客户端、ICE-TCP 与 simulcast 发送

新增（ADR-017，docs/adr/017-webrtc-turn-gaps.zh-CN.md）：

- **TCP 与 TLS 上的 TURN**（`only-turn`）：`TurnServer::stream()` 返回用于 TCP 监听器的 `TurnStream`
  acceptor，用 `only::tls::Tls` 包装后用于 TLS 监听器（`turns:`），与 UDP 监听器共享分配、配额与凭据。经
  连接建立的分配随连接结束（`TurnCore::remove_client`）；新增 `TurnConfig::stream_allocate_timeout`（30 秒：
  未分配的连接被关闭）与 `max_stream_queue`（256 KiB：排队超过该值的连接，发给它的中继数据被丢弃）。
  `TurnServer::stream_relay_of`。STUN 与 ChannelData 分帧在 `only_turn::framing`（`FrameReader`、
  `frame_len`、`MAX_FRAME`）；`TurnEnv` 新增带默认实现的方法 `pads_channel_data`。不实现 RFC 6062 TCP
  中继（`442`）。
- **TURN 客户端** `only_turn::client::{Client, ClientConfig, ClientEvent, ClientState, ClientError}`：
  sans-io，在 UDP 或流上维护一个分配；长期凭据、过期 nonce、刷新、channel 及权限回退、对端使用期间的绑定
  刷新、UDP 重传；默认最多 64 个对端、等待绑定的数据 64 KiB。
- **`Endpoint` 的 relay 候选**：`Endpoint::gather_relay(server, username, password, timeout)` 通过
  endpoint 的 UDP socket 分配，加入 relay 候选（以及服务器看到的 server-reflexive 地址）；该分配由
  endpoint 的 peer 共享，在 WebRTC 定时器线程上刷新，由 `Endpoint::close` 删除。每个 endpoint 最多 4 个。
  新增 `Error::Turn`。
- **ICE-TCP**（RFC 6544）：`Endpoint::listen_tcp(&engine, addr)` 在独立端口上加入被动 TCP host 候选；连接
  由专用线程接受（最多 256 条），须在 10 秒内发来指向该 endpoint 某个 peer 的检查，并承载 RFC 4571 帧。
  TCP 候选优先级低于 UDP。`only-ice`（内部层级）新增 `TcpType`、`Candidate::host_tcp`、
  `Candidate::tcp_type` 与 `only_ice::tcp`；`ParseError::Tcp` 删除。
- **simulcast 发送**（RFC 8853）：`SdpChanges::add_simulcast_media(kind, dir, rids, ..)` 与
  `Peer::write_simulcast(mid, rid, ..)`：每个 RID 一条 RTP 流与 RTX 流，SDP 中的 `a=rid` / `a=simulcast`，
  MID 与 RID 头扩展（重传带 repaired RID），按编码的发送者报告、NACK 与 PLI/FIR（`KeyframeRequest::rid`）；
  由 answer 的 `a=simulcast:recv` 选择发送的编码。作为应答方，本栈接受 simulcast offer（answer 中带
  `a=simulcast:recv`，RTX 按 repaired RID 映射）。
- 互通（`tools/interop/webrtc/run.sh`，新增在 Linux 容器中运行全部检查的 `linux.sh`）：pion/turn 与 coturn
  客户端经 UDP、TCP、TLS 对 `only-turn`；`only_turn` 客户端经 UDP、TCP、TLS 对 pion/turn、coturn 与
  `only-turn`；只带 relay 候选（来自 `only-turn`、pion/turn、coturn）以及只带被动 TCP 候选的 `Endpoint`
  对 pion；pion 收到 h/m/l 三层 simulcast。新增 fuzz 目标 `turn_stream` 与 `ice_tcp`。

### 新增：only-media 的 fMP4 HLS、RTMP 与 RTSP 客户端、WebRTC 媒体

新增（ADR-016，docs/adr/016-media-fmp4-clients-webrtc.zh-CN.md）：

- **fMP4 / CMAF HLS**：`HlsConfig::format = SegmentFormat::Fmp4` 提供 `init-<n>.mp4`、`seg-<n>.m4s` 与
  LL-HLS 分片 `part-<n>.<m>.m4s`（H.264、H.265、AAC、Opus），与 MPEG-TS 并存，后者仍为默认。新模块
  `fmp4`（`Muxer`、`Demuxer`、`write_styp`）。
- **RTMP 客户端** `rtmp::client::{push, pull}`：把 hub 中的流转推到 RTMP 服务器，或拉流进 hub（Enhanced RTMP
  H.265/Opus），连接、握手、每条命令与空闲均有超时，消息与发送队列有上限。
- **RTSP 客户端** `rtsp::client::{pull, push}`（播放与录制，TCP 交织或 UDP，Digest 与 Basic 认证，保活，
  RTCP 报告）；`rtsp::message::Reply` 与 `Parser::client`。
- **WHIP/WHEP 媒体**：开启新的 cargo feature `webrtc` 后，`webrtc::RtcMedia` 经 only-webrtc 承载 H.264、
  H.265、Opus 与 G.711：WHIP 推入 hub，WHEP 从 hub 播出。`WhipServer` 会丢弃对端未经 `DELETE` 就结束的会话。
- **关键帧请求**：`Publisher::on_keyframe_request`、`Subscription::request_keyframe`、`Hub::request_keyframe`，
  按 `HubConfig::keyframe_request_interval`（500 ms）节流；WebRTC 观众的 PLI/FIR 以 PLI 形式到达 WHIP 推流者。
- 互通：ffmpeg/ffprobe（fMP4 HLS 普通与 LL-HLS、RTMP 与 RTSP 监听模式）、mediamtx（RTMP，RTSP 走 TCP 与
  UDP）、ffmpeg 的 WHIP 封装器与 pion（WHIP、WHEP、PLI 往返）。新 fuzz 目标 `fmp4_demux`、`rtmp_client`、
  `rtsp_client`。
- 修复：only-webrtc 的 `Endpoint::config`、`close_on_disconnect` 与 `connect_timeout` 在 `bind` 之后会 panic。

### 新增：XDP 限速、I/O 线程绑核、eBPF 哈希分流、内核拼接的 SOCKS 隧道

均为新增（ADR-027，docs/adr/027-ebpf-xdp-pinning-socks-splice.zh-CN.md）：

- **`only::ebpf::xdp::RateLimiter`**：XDP 中按源地址的令牌桶。可只计 TCP SYN（防连接洪泛）或计
  所有包，源保存在有上限的按 CPU LRU map 中；以 native 或 generic 模式、通过 BPF link 或 netlink
  挂载。永不替换他人的程序，drop 时卸载，提供 `stats()` 与 `forget()`。
- **`EbpfConfig::pin_threads`**：把 n 个 I/O 线程中的线程 `i` 绑到 `c % n == i` 的 CPU 上，使
  `Steering::Cpu` 选中的线程运行在收包 CPU 上。同时新增 `ebpf::cpu_pinning`、
  `SteerInfo::pinned_threads` 与 `only_sys::process::{allowed_cpus, pin_current_thread}`。
- **`Steering::Hash` 的 eBPF 层**（需特权）：与经典层的哈希和所选线程相同，socket 写在
  `REUSEPORT_SOCKARRAY` 中，与加入组的顺序无关。
- **sockmap relay**：拼接前已排队的字节会被转发，不再等待后续数据。新增 `Relay::splice_inner`、
  `Relay::splice_inner_with`（在转发任何字节前写出最后一条握手消息）与 `ebpf::byte_counts`。
- **only-socks**：`ProxyConfig::sockmap` / `Socks::sockmap` 把 SOCKS 与 HTTP `CONNECT` 隧道拼接到
  内核中转发（需显式开启），无法拼接时回退到用户态转发。
- `bench-server` 的 `ONLY_ACCEL` 开关、`ebpf-bench` 示例、`tools/bench/ebpf.sh`；fuzz 目标
  `xdp_rate_limit`。

### 新增：only-dpdk 用户态协议栈的 IPv6、ECN 与 pacing

新增 API（ADR-026，docs/adr/026-userspace-ipv6-ecn-pacing.zh-CN.md；only-dpdk 属实验性）：

- `Backend::Dpdk` 支持 **IPv6**：设置 `DpdkConfig::address6` 即启用（外加由 MAC 派生的链路本地
  地址），另有 `prefix_len6`（64）与 `gateway6`。listener 为双栈（端口同时服务两种地址族；listener
  地址可为 `::`、`address6` 或链路本地地址），`dial` / `dial_udp` 接受 IPv6 对端。带上限地遍历扩展
  首部并回应参数问题，分片与重组（按 RFC 5722 丢弃重叠分片，原子分片），ICMPv6 回显与差错报文，路径
  MTU 缓存，NDP 复用 ARP 缓存的待解析队列（首个 SYN 不再丢失），回应针对本栈地址的 DAD 探测，MLDv2
  报告；NDP 帧复制到每个队列，AF_PACKET 加入 all-multicast。地址为静态配置：没有 SLAAC、路由器通告
  与 DAD。
- **ECN**（`DpdkConfig::tcp_ecn`，RFC 3168）与 **pacing**（`DpdkConfig::tcp_pacing`，速率为
  `cwnd / srtt`，慢启动时乘 2，之后乘 1.2），默认均关闭。模拟的 20 帧瓶颈队列上：ECN 丢包由 29 次
  降为 0，pacing 由 29 次降为 14。
- 邻居缓存限制为未解析邻居排队的字节数（每个协议栈 4 MiB）。
- IPv4 性能不变（x86 上内存链路 `stack-bench`，新/main）：请求/响应 1.02-1.04，UDP 与大块传输 1.01，
  顺序建连 0.99；邻居缓存不再使用 SipHash。
- 未完成：校验和 / TSO / LRO 卸载（手头的 PMD 用软件实现）。
- 测试：模拟有损链路上的 IPv6 与 ECN / pacing，双栈内存链路测试，Docker 中基于 IPv6 的内核互通
  （TAP、AF_PACKET、双队列 DPDK `net_tap`：`ping -6`、含分片的 UDP、双向 TCP、开启 ECN 与 pacing 的
  `netem` 丢包）；模糊测试目标 `dpdk_ipv6`、`dpdk_icmpv6`、`dpdk_ndp`。

### 变更：UDP 数据报以拥有所有权的接收缓冲区交付（only-sys、only-epoll、only-quic；ADR-024）

UDP 循环（epoll、io_uring 与 macOS；服务端与拨号 socket）接收进池化的接收 slab，并可把每个数据报作为拥有所有权的
缓冲区交给 handler（隐藏的 `Handler::OWNED_DATA` / `on_data_owned`），GRO 批次切分不复制。only-quic 使用它并原地
解密，从内核到解密后的负载之间不再有复制。UDP 对端表用带密钥的乘法折叠哈希（作为隐藏的 `only_core::hash` 与
only-quic 共用）代替 SipHash。`only-buf` 现在只在一个模块（`slab`，经 Miri 与 loom 检查；docs/unsafe-review.zh-CN.md）
中允许 unsafe 代码。回环上的同轮 A/B：QUIC 批量、HTTP/3、握手与 UDP echo 都在 1% 以内（HTTP/3 1.01，其余 1.00；
docs/BENCHMARKS.zh-CN.md）。不选择启用的 handler（包括加密的 handler）没有变化。公开 API 无变化。

### 变更：HTTP 请求不再每次装箱响应 sink、不再每次分配 target（ADR-025）

HTTP/3 分配优化之后点名的最后两处每请求分配已去掉
（docs/adr/025-per-connection-response-sink.zh-CN.md）：

- **复用 target 缓冲。** handler 处理完一个它没有 detach、也没有升级的请求后，该请求的 target 缓冲
  （不超过 1 KiB）成为本线程的备用缓冲。该线程上解析的下一个请求把 target 写进去，HTTP/1.1、HTTP/2
  和 HTTP/3 都如此。之所以按线程而非按连接：按连接的缓冲在轮到该连接时已不在缓存中，第一版因此让
  h2c 每请求多约 100 个周期。`Request::target` 仍是 `String`，handler、router 和中间件不变。
- **每个连接一个响应 sink。** only-http 的 transport 钩子（`only_http::transport`，
  `#[doc(hidden)]`，不在 semver 承诺内）新增：
  - `ConnSink`：`send` / `start_stream`，都带每请求的 `u64` tag；
  - `SharedSink`：指向它的瘦句柄；
  - `dispatch_conn` / `start_conn`，以及供构造请求的 transport 使用的 `request_target`。

  only-h3 对一个连接的所有请求都通过同一个 sink 应答（tag：流序号与 HEAD 标志），不再每请求装箱
  一个 sink 并克隆三个 `Arc`。由于句柄是瘦指针，`Context` 的 responder 保持 16 字节。胖指针
  `Arc<dyn ConnSink>` 加 tag 会让 `Context` 增大 8 字节；HTTP/2 每个请求装箱一个 `Context`，h2c
  因此多花约 1% 的周期。
- 每请求分配器调用（x86_64 上用 bpftrace 计数）：`quic-bench h3` 两端 11.0 → 9.0；HTTP/1.1 服务端
  6.0 → 5.0，pipeline 6.0 → 5.0，h2c 6.5 → 5.5。此前 HTTP/3 条目中的 8.6 用的是另一种计数方式；
  按本方法，ADR-011 之前的 776f001e 为 10.8。
- gpu51（Zen 4，空闲主机）同一次运行的 A/B：
  - HTTP/3 GET，一个连接、64 个并发：1.0059 倍（两次各 7 轮交替：1.0087 倍和 1.0032 倍）。
  - 服务端每请求用户态周期（`perf stat`，7 轮中位数）：HTTP/1.1 0.951 倍，pipeline 0.968 倍，h2c
    0.973 倍；指令数减少 1.2%–1.4%。

| 之前（已弃用，仍可编译） | 之后 |
|---|---|
| `impl ResponseSink for S`（`send(self: Box<Self>, resp)`） | `impl ConnSink for C`（`send(&self, tag, resp)`），每个连接一个 |
| `transport::dispatch(&svc, req, Box::new(s))` | 每个连接一次 `let sink = SharedSink::new(c);`，然后 `transport::dispatch_conn(&svc, req, &sink, tag)` |
| `transport::start(&svc, req, Box::new(s))` | `transport::start_conn(&svc, req, &sink, tag)` |
| `Request::new(m, path.to_owned())` | `Request::new(m, transport::request_target(path))`（可选） |

### 新增：span、推送导出（OTLP、StatsD）、HTTP 按路由标签、HTTP/2 gauge

只有新增（ADR-020，docs/adr/020-spans-and-push-export.zh-CN.md）：

- **only-log 中的 span**（`only::log::span`）：`Span`、`SpanBuilder`、`span!` / `info_span!` ……、支持解析和
  输出 W3C `traceparent` 的 `SpanContext`、`Tracer`（`set_tracer`）、独立的最大 span 级别
  （`set_max_span_level`，默认关闭：禁用的 span 只花一次 relaxed 读）、`enter` / `in_scope` / `enter_context` /
  `current`。`FmtLogger` 在 span 内加上 `trace_id` / `span_id`。没有 `tracing` 桥接（原因见 ADR-020）。
- **HTTP 请求与连接 span**：每个 HTTP/1.x、HTTP/2、HTTP/3 请求一个 `only_http::request`（`info`，种类
  server），路由后命名为 `"GET /users/:id"`，带方法、路径、路由、协议版本、客户端地址和状态码，带
  `traceparent` 时作为其子 span；每条连接一个 `only_http::connection`（`debug`）。`Context::span_context()`、
  `Context::route()`（`RouteInfo`）、`only_http::trace`。
- **HTTP 按路由的指标**：`HttpMetrics::with_routes(n)` 用路由的方法和模式（绝不是原始路径）标注请求与延迟，
  最多 `n` 个路由（≤ 4096），之后是 `route="other"`；未匹配的请求是 `route="unmatched"`。
  `HttpMetrics::route_snapshot()`，族 `only_http_route_requests_total` 和 `only_http_route_request_duration_seconds`。
- **HTTP/2 gauge**：通过新的 `H2Config::stats` 设置 `observe::H2Stats`：打开中和累计的连接与流、两个方向的
  `RST_STREAM` 和 `GOAWAY` 帧（`only_http2_*`）。
- **新 crate `only-export`**：在一个后台线程上把指标（新增的 `Telemetry::collect_all()` 和额外收集器）和 span
  经 OTLP/HTTP（protobuf 或 JSON）推送到 OpenTelemetry collector，并经 UDP 推送到 StatsD / DogStatsD（计数器
  增量）。span 队列有界（满时丢弃并计数），推送失败计数且不重试，OTLP 每一步都有超时，支持采样比例。在 Docker
  里对 OpenTelemetry Collector 做端到端测试（`tools/otel/e2e.sh`）；fuzz 目标 `log_traceparent`、
  `export_http_response`、`export_otlp`。
- only-core：`Metrics::collect_into` 与 `Telemetry::collect_all`（引擎序列以 `Families` 表示，与 Prometheus
  渲染一致）。

### 新增：读缓冲区、backlog 和 UDP 空闲超时的热更新；I/O 线程数调整

ADR-028（docs/adr/028-hot-reload-buffers-backlog-threads.zh-CN.md）：

- `Engine::reload` 现在会应用 **`read_buffer`**（每个 I/O 线程在两批事件之间替换缓冲区，已打开的
  连接从下一次读开始使用新大小；io_uring 在连接的接收重新挂起时把它们转到新的 provided-buffer 组）、
  **`backlog`**（对活的监听套接字重新 `listen`；新增 `only_sys::set_backlog`）和
  **`udp_idle_timeout`**（重新设置已打开对端的定时器）。`ReloadReport::ignored` 现在列出
  `max_pending_responses`、`write_timeout`、`connect_timeout`、`udp_max_peers`、`udp_gro`。
  `Live` 为这三项新增 getter/setter。
- **`Engine::threads()` / `Engine::set_threads(index, n)`**：在 engine 运行时增减 TCP listener 或
  client 组的 I/O 线程（epoll、kqueue、io_uring）。扩容为每个新线程增加一个 `SO_REUSEPORT` 套接字
  （Linux）或共享套接字的克隆；缩容让编号最大的线程退役，它们把监听套接字交给其他线程（排队的连接
  不会被重置），并继续服务自己的连接直到关闭：连接从不在线程之间迁移。新增
  `Config::retire_timeout`（默认 `None`，可热更新），到期后优雅关闭退役线程仍在服务的连接。
  `LoopMetrics::retiring`，Prometheus `only_loop_retiring`。UDP listener、DPDK 和启用 BPF 分流的
  listener 返回 `Unsupported`。
- only-prefork：**原地重载**：`Controller::reload_in_place` / `Supervisor::reload_in_place` 和
  SIGUSR1 让每个 worker 执行 `Worker::on_reload` 钩子（不替换进程即应用新配置和线程数）；
  `Worker::reloads`、`Status::in_place_reloads`。
- 热路径不变（同轮 A/B 见 docs/BENCHMARKS.zh-CN.md 的“热更新”）。

### 新增：GitHub Pages 文档站点、书中示例的运行脚本

- `book/site.sh` 构建发布在 `lesismal.github.io/only` 的站点：两本书、每页的语言切换与 API 链接、
  本地化的 404 页与全站 `404.html`，以及 `/api/` 下每个已发布 crate 的 rustdoc。
  `book/check-site.py` 在相同的基础路径下服务该站点，检查每个内部链接、资源与片段（包括各 crate
  rustdoc 指回手册的链接）、两本书页面一致，以及 404 处理。`.github/workflows/pages.yml` 运行这两者，
  并在发布 release 时或手动触发时部署；只在 release 时运行的 `book-deploy` 任务已移出 `ci.yml`。
  启用 Pages 是一次性的仓库设置。
- `book/check-guides.sh` 运行书中引用代码的每个程序：21 个 `guide-*` 示例（各自以 0 退出或失败）、
  只提供服务的示例（`guide-media`、`guide-media-rtsp`、`echo`、`udp-echo`、`hello`、`prefork-http`，
  从外部探测）以及 gRPC 一章生成的桩代码；在 Linux 上于私有网络命名空间中运行。在 macOS、Linux arm64
  与 Linux x86_64 上通过，epoll 与 io_uring（`ONLY_DEFAULT_BACKEND=uring`）均通过。
- `ONLY_DEFAULT_BACKEND=uring`（ADR-029，Linux）：未调用 `Listener::backend` 的 TCP listener 由 io_uring
  服务（非 strict：不可用时回退到 epoll 并给出警告）。显式选择的后端总是优先；UDP listener 与客户端线程
  不受影响；每次 `Engine::build` 读取一次。这是测试与诊断开关，使不改代码的程序（指南示例）也能在 io_uring
  上运行。没有公共 API 变化。
- `book/check-includes.py` 还会检查 `book/en` 与 `book/zh-CN` 章节相同，且各章的标题、引用、代码块、
  表格行与列表项一致。
- 文档与代码对齐：HTTP/3 上的 WebSocket 不再列为未完成；配置参考中的 `H3Config` / `H3ClientOptions`
  字段名与 QPACK 默认值、`DialOptions::proxy` / `max_redirects`、`ONLY_UDP_ECN` 与 `ONLY_LOG`；
  only-quic 支持 v1 与 v2；示例表列出全部示例；中文 RTSP 一章补上认证一条。修复三处失效的 rustdoc
  链接（only-log、only-h3、only-bittorrent）。

### 新增：HTTP/3 上的 WebSocket、QPACK 动态表、流式 HTTP/3 请求 body

均为新增（ADR-011，docs/adr/011-h3-websocket-qpack-streaming.zh-CN.md）：

- **HTTP/3 上的 WebSocket**（RFC 9220）。服务端宣告 extended CONNECT；
  `Context::upgrade_websocket` 以与 HTTP/1.1 相同的检查、子协议和 `permessage-deflate` 接受它，
  应答 `200`，并在请求流上承载 WebSocket，`WsHandler` / `WsSender` 不变。`Router` 把
  `websocket` 的 extended CONNECT 路由到该路径的 GET 路由，所以一个 `.get("/ws", ...)` 同时服务
  HTTP/1.1 和 HTTP/3。新增 `Request::protocol`（`:protocol`）。客户端：`H3Client::websocket` /
  `websocket_blocking` 与 `H3WsOptions`；被拒绝时返回 `H3Error::Status`。
- **QPACK 动态表**（RFC 9204），服务端在 `H3Config`、客户端在 `H3ClientOptions`（`H3Client::dial_with`）中配置：
  `qpack_max_table_capacity`（4096）和 `qpack_blocked_streams`（16）用于我方解码器（encoder/decoder
  stream、按顺序暂存被阻塞的字段段、确认、增量和取消），`qpack_encoder_capacity`（0，关闭）用于我方
  编码器，它只引用已确认的条目，因此从不阻塞对端。新增错误码 `code::QPACK_ENCODER_STREAM_ERROR` /
  `QPACK_DECODER_STREAM_ERROR`。服务端现在宣告 4 KiB 动态表：nghttp3（curl）和 OpenSSL QUIC 会立即
  使用。
- **HTTP/3 流式请求 body**：`BodyMode::Stream` 的 service 与 HTTP/1、HTTP/2 一样通过
  `Context::on_body` 随到随收，不受 `max_body_bytes` 限制；请求读取器从不暂存 DATA 负载。客户端：
  `H3Client::upload` 返回 `H3Upload`（`write`、`finish`、`queued_bytes`）。
- 互通：quic-go（双向 HTTP/3 WebSocket 与流式上传），Docker 中通过 libcurl 的 ngtcp2/nghttp3 和
  OpenSSL QUIC（nghttp3 会填充我方解码器的表）。新增 fuzz 目标 `qpack_dynamic`；`h3_frame` 和
  `h3_request` 覆盖 QPACK 流、被阻塞的字段段、extended CONNECT 和流式读取器。
- 编码器关闭时的 HTTP/3 吞吐：`quic-bench h3` 同轮 A/B 为不含这些功能的版本的 1.025 倍（gpu51 上
  88.13 万 vs 85.96 万 请求/秒，两次各 7 轮交替：1.024 倍和 1.027 倍，14 轮全部更快），每请求少约
  300 条指令（x86 callgrind）。完整到达的请求或响应（一个 HEADERS 帧、至多一个 DATA 帧）不经帧读取器
  和每流状态直接读取，客户端在加锁前解码；请求截止时间按 token 下标索引队列而不再哈希；请求在已持有的
  锁下直接打开流。两端都开启 QPACK 编码器时在该
  基准上慢 18%（请求很小，每个都要确认一次），这正是编码器默认关闭的原因。

### 变更：处处安全默认值、不阻塞事件循环的 I/O、更精简的热路径（ADR-009，docs/rules.zh-CN.md）

新的开发规则（docs/rules.zh-CN.md，改编自 fit）：绝不阻塞 I/O 线程、消息体流式且有界、背压联动、处处有超时和
带安全默认值的上限、热路径上构建时优先于请求时、验证与改动相称。代码已按这些规则审查；下列每个上限都有安全
默认值，0 / `None` 仍是显式的关闭方式。

**引擎（only-core、事件循环、only-tls）**
- `Config::write_timeout` 60 s（原为 `None`）；`Config::udp_max_peers` 65536（原为 `None`）；新增
  `Config::connect_timeout`（10 s），用于 epoll、kqueue 和 io_uring 上的 `Engine::dial`。
- 新增 `Config::max_pending_responses`（32）：排在未完成响应之后的流水线响应会暂停读取（并计入写水位线 /
  `max_queued_bytes`），不再无限堆积。
- TLS 握手超时：`ServerConfigBuilder::handshake_timeout` / `ClientConfigBuilder::handshake_timeout`
  （10 s），由事件循环通过新的 `Transport::handshake_timeout` 执行。
- 热路径：cork 状态改为原子量，无人等待时跳过 drain 锁，命令队列保留容量；每个流水线请求的无竞争加锁操作
  约从 7 次降到 4 次。

**HTTP 服务端（only-http）**
- `HttpConfig::head_timeout` 10 s（slowloris；408）、`keep_alive_timeout` 75 s、`body_timeout` 60 s；
  HTTP/2 的 preface/SETTINGS 截止时间和空闲 GOAWAY。
- HTTP/2 Rapid Reset 与洪泛预算：`H2Config::max_resets`（每 30 s 100 次，含 MadeYouReset）、
  `max_control_frames`（每窗口 1000）→ GOAWAY ENHANCE_YOUR_CALM；所有流合计的 `max_conn_pending_bytes`
  （32 MiB）。
- 静态文件只在线程池上访问磁盘（16 线程、4096 排队，满时 503）；缓存命中留在 I/O 线程，压缩副本（及其不存在）
  被缓存，响应头每个条目只格式化一次，缓存分为 16 个 RwLock 分片。
- 请求路径：每个路由请求不再增减共享 `Arc`，405 的 `Allow` 预先计算，带消息体的请求只路由一次，metrics 的
  `in_flight` 按分片，响应过滤器内联存放，CORS / compress / limiter / csrf / request_id 不再每请求格式化或
  使用全局锁。流水线 HTTP/1.1 和 h2c 约 +3–4%（同一轮 A/B），普通 HTTP/1.1 在 1% 以内。

**HTTP 客户端（only-http、only-h3）**：HTTP/1 响应头 64 KiB、消息体 64 MiB、请求超时 30 s、空闲连接池每主机
32 个 / 总计 256 个、空闲 90 s 过期；HTTP/2 在缓冲前检查帧大小，头块上限 2 × `max_header_list`，消息体 64 MiB，
每个请求最多 32 个 push；HTTP/3 消息体 8 MiB、字段段 64 KiB、请求超时 30 s。新增 `ClientError::Timeout` /
`TooLarge`、`H3Error::TooLarge`。

**gRPC 与 arpc**：全局 `Mutex<Vec>` 截止时间线程被可取消、分片的截止时间服务取代（带截止时间的调用：gRPC ×17、
arpc ×278 调用/秒；不带：+1%）。`grpc-timeout` 限制在 `GrpcServer::max_deadline`（24 h）以内，
`GrpcClient::default_timeout`（30 s），`max_collect_bytes`（64 MiB）；arpc `Routes::max_streams_per_conn`
（1024）和 `call_timeout`（30 s）；每条消息更少的复制和加锁。

**WebSocket、媒体、WebRTC**：压缩（permessage-deflate）消息也受限（关闭码 1009）；帧头在栈上编码、缓冲区复用
（1 KiB 普通回显 +7–11%）。RTMP 分块读取器原地解析（原为 O(n²) 复制），未完成消息上限 32 MiB；没有关键帧时
HLS 分段在 `max_bytes` 处切分；hub 每路径 1024 个流 / 1000 个订阅者，WHIP 256 个会话，SRT 1024 个连接，RTMP
握手 10 s / 空闲 60 s，RTSP 会话超时被执行（60 s）且请求超时 10 s；`RtcServer` / `Endpoint::max_peers`（1024）。

**QUIC、HTTP/3、KCP**：每流和每连接的 QUIC 发送缓冲区上限（均为 16 MiB），配合 `Error::Overloaded` 和
`QuicHandler::on_stream_writable`；`receive_window` 10 MB（原为不限）；`ServerConfig::max_connections`
（10,000，无状态 CONNECTION_REFUSED）。HTTP/3 文件消息体只在流有空间时在线程池上读取。KCP `max_sessions` 4096
和 `KcpHandler::on_writable`。4 MiB 的每流默认值让 QUIC 单流批量传输慢约 2.5%，因此每流默认值与每连接相同（16 MiB 在 gpu51 上与基线持平）。

**SOCKS、mux、TURN、BitTorrent、log、DTLS**
- SOCKS / HTTP CONNECT：**目标地址默认只允许公网**（解析后拒绝回环、私网、链路本地、CGNAT、组播和保留地址，
  包括映射形式；BIND 和 UDP ASSOCIATE 同样适用）；握手 10 s、空闲 5 min、早期数据上限 256 KiB、CONNECT 的
  DNS 在有界线程池上解析。
- only-mux 嗅探超时 5 s。TURN 分配按客户端分片（中继吞吐约 140k → 513k 数据报/秒）。BitTorrent tracker 的 DNS
  移出 I/O 线程，tracker 服务端 10 万个 swarm / 每 swarm 1000 个对端并带淘汰，uTP 入站表 1024。only-dtls 在
  cookie 交换前限制重组缓冲。
- only-log：可选的 `FmtLogger::non_blocking`（有界队列，满时丢弃并计数）；默认仍为同步。

### 新增：HTTP 与 WebSocket 客户端的重定向、超时、代理、系统根证书（ADR-010）

- 重定向，需显式开启：`client::RedirectPolicy`（默认 `none()`、`limit(n)`、`allow_https_downgrade`），
  配合 `Client::with_redirects`。跟随 301/302/303/307/308，方法与请求体遵循 RFC 9110 第 15.4 节，支持相对
  `Location`，重定向到其他源时删除 `Authorization` / `Cookie` / `Proxy-Authorization`，默认不跟随
  https → http，超过上限时返回 `ClientError::TooManyRedirects`；`ClientResponse::url` 是最终应答的 URL。
  WebSocket 握手通过 `DialOptions::max_redirects`（默认 0；`WsClientError::TooManyRedirects`）跟随重定向。
- 单请求超时：`ClientRequest::timeout` / `.timeout(d)` 与 `Client::with_timeout`，覆盖解析、连接、TLS、
  响应与重定向（`ClientError::Timeout`，连接被关闭）。`H2Client` 通过重置流来遵守它。
- 在调用线程之外解析域名：新增 `only::dns::resolve`（无依赖的解析线程池，最多 4 个线程；IP 字面量直接应答），
  HTTP/1 与 WebSocket 客户端使用它。
- 系统根证书：`only::tls::RootCerts::system()`（`SSL_CERT_FILE` / `SSL_CERT_DIR`、通过 `/usr/bin/security`
  读取 macOS 钥匙串、Linux/BSD 的 CA 证书包与目录）。**行为变化：**没有 `with_tls` 的 `Client` 和
  `DialOptions::tls = None` 现在对 `https://` / `wss://` 使用它，而不是报错。
- HTTP 代理：`only_ws::proxy::Proxy`（在 `only_http::client::Proxy` 重新导出；`all`、`http`、`https`、
  `no_proxy`，以及需显式调用的 `from_env`，读取 `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`）、
  `Client::with_proxy`、`DialOptions::proxy`。`http://` 用绝对形式，`https://`、`ws://` 和 `wss://` 经
  `CONNECT`；代理 URL 中的凭据变成 `Proxy-Authorization: Basic`；被拒绝时是携带 `ProxyRefused` 的
  `io::Error`。
- 客户端所在 engine 优雅停机时，WebSocket 客户端以 1001（going away）关闭已打开的连接（以前以 1006 结束）。

### 新增：SOCKS5 BIND 与 UDP ASSOCIATE、SOCKS 访问控制钩子、`Engine::adopt_tcp`

- `only-socks` 支持 SOCKS5 `BIND` 与 `UDP ASSOCIATE`（RFC 1928），默认均关闭
  （`Socks::bind(true)`、`Socks::udp_associate(true)`；`bind_timeout`、`udp_idle_timeout`）。
  UDP：每个关联一个转发 socket（engine 需要 `udp_client_threads`），按 IP 和端口识别客户端，丢弃
  分片，只转发来自客户端发送过的目的地的应答，随控制连接或空闲超时结束。BIND：在代理地址上监听，
  两次回复，接受到的连接带背压转发。
- `Socks::allow(|request| ..)`：覆盖 `CONNECT`（SOCKS5/4/4a）、`BIND`、`UDP ASSOCIATE` 以及每个 UDP
  目的地的访问控制钩子，新增 `Command`、`Dest`、`Request` 类型。拒绝时回复 2（SOCKS4：0x5b）或丢弃
  数据报。
- `Engine::adopt_tcp(stream, acceptor, on_error)` 把在 engine 之外 accept 的 TCP 流当作拨号连接来
  服务（epoll 与 io_uring）。
- 互操作：`tools/interop/socks/run.sh`（curl、PySocks、BIND 与 UDP 边界情况；以 Dante 作为参考
  服务器）。ADR-012。新增 API（`api/only-socks.txt`、`api/only.txt`）。

### 新增：`ONLY_LOG` 过滤指令与编译期日志级别上限

- `only::log::Filter`：从 env_logger 风格的指令（`info,only_http=debug,only_quic::conn=trace,only_http::access=off`）
  得到按 target 的级别，只解析一次。`only::log::init_from_env(default)` 安装按 `ONLY_LOG` 过滤的格式化
  logger；需显式调用，否则没有代码读取环境变量。`FmtLogger::filter` / `init_filtered` 接受在代码中
  构造的过滤器。
- only-log 的 cargo feature `max_level_*` / `release_max_level_*` 与 `STATIC_MAX_LEVEL`，与 `log`
  crate 相同：超出上限的语句被编译掉。不开启时生成的代码不变（禁用的 `trace!`：x86_64 上
  0.400 → 0.401 ns，macOS 上二进制相同）。ADR-012。新增 API（`api/only-log.txt`）。

### 新增：共享的 0-RTT 防重放存储（only-tls）与兼容版本协商（only-quic）

新增 API（ADR-013，docs/adr/013-shared-anti-replay-and-compatible-vn.zh-CN.md）：

- **`AntiReplayStore`**（only-tls）：服务端记录已接受早期数据的 ClientHello 的地方。只有一个方法
  `check_and_insert(binder, ttl) -> io::Result<bool>`，须为原子操作，只针对本会接受早期数据的 ClientHello 在
  握手路径上调用。出错时**失败即关闭**（拒绝早期数据，客户端在握手后重发）。默认实现 `MemoryAntiReplay`（即原有
  的每配置一份、有界的记录，10 万条）现已公开。`ServerConfigBuilder::anti_replay_store(Arc<dyn AntiReplayStore>)`
  接入共享存储（Redis `SET key 1 NX PX ttl`，示意见本书 TLS 章节）；`ServerConfigBuilder::session_ticket_key([u8; 48])`
  让多个进程或多台机器上的服务端能接受彼此的票据。QUIC 服务端经由其 TLS 配置获得这两项。已接受的 ClientHello 现保留 30 秒（原为 20 秒）：10 秒新鲜度窗口的两倍，再加一个窗口
  容许共享存储的服务端之间时钟有偏差。
- **兼容版本协商**（only-quic，RFC 9368 第 4 节）：`ServerConfig::prefer_version(Version)` 让以另一版本开始、
  并在 version_information 中列出偏好版本的客户端在握手内切换过去，不多花往返；ClientHello 跨多个包、Retry
  之后以及 0-RTT 时同样可用（0-RTT 包保持客户端的首个版本，RFC 9369 第 4.1 节）。默认关闭：服务端用客户端的
  版本应答。only-quic 客户端总会跟随这种切换（无法解密的、伪造的另一版本 Initial 不会让它切换）。
- 测试：共享票据密钥与“远程”存储的两台 TLS 服务端拒绝从一台重放到另一台的 ClientHello（各自记录时则被接受），
  存储失败时拒绝早期数据，在模拟链路上对 QUIC 做同样的检查；模拟链路上的兼容协商（无额外往返、Retry 加 15%
  丢包、跨两个包的 ClientHello、跨切换的 0-RTT、v2 切到 v1、无偏好或客户端列表无 v2 时不切换、伪造的 Initial）。
  Fuzz：`quic_conn` 的连接对现在会切换到 v2，`tls_server` 也会运行 ClientHello 预读。互通：新增
  `tools/interop/quic/ngtcp2-cvn.sh`，在 Docker 中与实现了 RFC 9368 的 ngtcp2 1.11 双向验证（其客户端被 only-h3
  切到 v2，含 0-RTT；only-quic 被其服务端切到 v2 与 v1）；quic-go 未实现 RFC 9368，因此
  `tools/interop/quic/run.sh` 检查其客户端在偏好另一版本的服务端上保持原版本。
- 代价：未测出（BENCHMARKS.zh-CN.md，握手 A/B）。

### 变更：QUIC 会话票据与令牌绑定到 QUIC 版本（only-tls、only-quic）

RFC 9369 第 5 节（ADR-014，docs/adr/014-quic-version-bound-resumption.zh-CN.md）：

- 会话票据或 NEW_TOKEN 令牌属于签发它的连接所用的 QUIC 版本，兼容版本协商之后即协商出的版本。服务端只用
  客户端起始版本的票据恢复会话（其他版本的票据走不带 0-RTT 的完整握手），也只用该版本的令牌验证地址；
  Retry 令牌同样绑定版本。
- 客户端绝不在 v2 中出示 v1 的票据或令牌，反之亦然：只要自己支持，就以该服务端最新票据（没有票据时看
  令牌）的版本开始，而不是 `ClientConfig::version`。配置为 v1、被偏好 v2 的服务端切到 v2 的客户端，下次
  直接以 v2 开始并带 0-RTT 恢复，无需切换。
- 升级：此前签发的票据与令牌未绑定版本，QUIC 服务端不再接受（每个客户端多一次完整、地址未验证的握手）。
  TCP 上的 TLS 不受影响（格式 2 的会话仍可解码）。公开 API 无变化（隐藏的 `only_tls::quic` 接口新增
  带版本的构造函数）。
- 测试：only-tls 按版本区分票据（出示、拒绝、由 `set_ticket_version` 改版本、未绑定的握手互不使用）；
  only-quic 按版本校验令牌；模拟链路上被切到 v2 的客户端以 v2 带票据、令牌与 0-RTT 恢复，v1 的票据不在
  v2 中使用。互通：`tools/interop/quic/ngtcp2-cvn.sh` 另外检查 ngtcp2 1.11 的客户端（它对被切到 v2 的
  连接得到的票据仍以 v1 重新开始）得到完整握手，以 v2 开始时带 0-RTT 恢复（跨切换的 0-RTT 仍有检查，
  使用共享票据密钥的孪生端口签发的 v1 票据）。

### 变更：没有 AVX-512 IFMA 的 CPU 上 Poly1305 使用 AVX2

在没有 AVX-512 IFMA 的 x86_64 CPU（Zen 2 与 Zen 3、大多数 Intel 客户端处理器）上，only-crypto 的 Poly1305（因而
ChaCha20-Poly1305）对 512 字节及以上的连续分组在 AVX2 上以 2²⁶ 为基数每步吸收四个分组，原先是标量循环。在 Zen 4 上
通过 AVX2 路径测量：ChaCha20-Poly1305 加密 16–64 KiB +20%，1 KiB +7%（docs/BENCHMARKS.zh-CN.md）。有 IFMA 的 CPU
与 512 字节以下的消息不变。公开 API 无变化。

### 新增：静态文件多区间响应、打开文件缓存淘汰、段内部分匹配路由

- `files::Files` 对多个区间（`Range: bytes=0-9,500-599`）返回 `206` 与 `multipart/byteranges` 响应体
  （RFC 9110 14.6 节），各部分按请求顺序排列。重叠的区间及相距不足 80 字节的区间会被合并（14.2 节）；
  超出文件末尾的区间被丢弃，全部丢弃时才返回 `416`；超过 32 个区间、或各部分合计超过 1 MiB 的请求头会被
  忽略，直接发送整个文件。`If-Range` 与单区间时一样生效。格式错误的区间仍返回 `416`。
- 打开文件缓存（`Files::max_open_files`）满时淘汰最近最少使用的句柄（CLOCK），不再对新文件不经缓存直接
  发送；能发现被 rename 覆盖的文件（除大小与修改时间外还比较设备号与 inode），并移除已删除文件的条目。
- `Router` 模式可在一段内混合字面文本与参数：`/{name}.txt`、`/v{major:[0-9]+}.{minor}`、
  `/{owner}/{repo}.git`（ADR-007）。匹配为线性、段内不回溯；优先级为 静态 > 部分段 > 正则 > 参数 > 通配。
  查找仍不分配内存。含 `{…}` 组的静态段现在是模式，花括号不配对时注册即 panic。

无公共 API 变化（`api/only-http.txt` 不变）。

### 新增：TLS record_size_limit、证书压缩与 OCSP stapling（only-tls）

增量配置（ADR-008，docs/adr/008-tls-extensions.zh-CN.md）：

- **record_size_limit**（RFC 8449，TLS 1.3 与 1.2）：`ServerConfigBuilder::record_size_limit` /
  `ClientConfigBuilder::record_size_limit`（64 到 16385，默认 16385）。客户端总是发送自己的值，服务端在客户端
  发送时回以自己的值；之后双方写出的受保护记录按对方的限制切分，收到超过自己限制的记录报 `record_overflow`。
  早期数据遵循签发票据的那条连接上的限制。QUIC 中不使用。对端限制小于 16 KiB 时拒绝（实验性的）内核 TLS 卸载。
- **证书压缩**（RFC 8879，TLS 1.3，zlib 由 only-deflate 提供；没有自研 brotli/zstd，因此只提供 zlib）：两个构建器
  上的 `certificate_compression(bool)`，**服务端默认开启**（证书链只压缩一次并复用，每次握手无额外开销），
  **客户端默认关闭**（解压收到的证书链约需 1–2 µs，约为内存中握手的 1%）。服务端的 CertificateRequest 提供压缩时
  客户端证书也会压缩。收到的消息最多解压到 128 KiB，长度必须与声明的一致。
- **OCSP stapling**：`ServerConfigBuilder::ocsp_response(der)` / `sni_ocsp_response(name, der)` 为请求它的客户端
  装订 DER 响应（TLS 1.3 放在 CertificateEntry 中，TLS 1.2 用 CertificateStatus；会话恢复时不发送）；
  `ClientConfigBuilder::ocsp_stapling(true)` 请求响应，新增的 `TlsInfo::ocsp_response` 保存收到的响应。**不做验证**
  （only-x509 尚无 OCSP）；服务端只检查配置的值在结构上是成功的 `OCSPResponse`。
- ClientHello 现在带有 record_size_limit（6 字节）。`only-tls` 依赖 `only-deflate`。
- 修复：长度不对的 TLS 1.3 KeyUpdate 报 `decode_error`（原为 `illegal_parameter`；tlsfuzzer 的
  “large KeyUpdate message” 探测会随机失败）。
- 测试：带扩展的内存矩阵（两个版本、各密钥类型、双向低至 64 字节的限制、任一方关闭压缩、带 SNI 与会话恢复的
  OCSP）、反例、fuzz 语料；互通（`tools/interop/tls/run.sh`）覆盖 OpenSSL（OCSP 由 s_client 验证，与 Debian 的
  OpenSSL 3.5 双向 zlib 压缩，忽略 max_fragment_length）、Go（双向 OCSP）与 GnuTLS（双向 record_size_limit 与
  OCSP）；tlsfuzzer 的 `test-record-size-limit.py`、`test-tls13-certificate-compression.py` 与
  `test-tls13-client-certificate-compression.py`。握手性能不变（同批 A/B，docs/BENCHMARKS.zh-CN.md）。

### 新增：可插拔的指标收集器（ADR-015）

应用与协议指标出现在 engine 的 `/metrics` 端点上，不依赖第三方 crate。新模块 `only::metrics`
（`only_core::metrics`）：`Collector` trait、`Families` 快照（Prometheus 文本 0.0.4 或 JSON，或通过
`iter` / `get` 读取）、度量工具 `Counter`、`Gauge`、`Histogram` 与具名工具的 `Registry`、`fn_collector`、
`DEFAULT_BUCKETS`。`Telemetry::register_collector(collector, labels)` / `unregister_collector`、
`Telemetry::collect` 与 `Telemetry::render_prometheus`（先 engine 序列，再收集器），`observe::metrics_handler`
现在输出后者。现成的收集器：only-http `HttpMetrics`（新增族 `only_http_requests_by_version_total{version}`、
字段 `HttpSnapshot::by_version`、`observe::VERSION_LABELS`）、only-quic `QuicServer`（`only_quic_*`：连接、
两个方向的数据报与字节、发送与丢失的包、拥塞事件；总数包含已关闭的连接）以及 only-tls `Tls::stats()` →
`TlsStats` / `TlsCounts`（`only_tls_handshakes_total{side, version}`、`only_tls_resumed_total`、
`only_tls_early_data_total{outcome}`）。只有新增 API；engine 自身的序列不变。示例：
`cargo run -p only-http --example guide-metrics`。

在安静主机上测量了 engine 遥测的开销（同一轮 A/B，docs/BENCHMARKS.zh-CN.md“遥测开销”）：HTTP/1.1
上没有可测的开销（关闭回调计时或把计数器编译掉为 0.998–1.006×）；echo 各行在噪声之内。带新版本计数的
`HttpMetrics::middleware()` 为原中间件的 0.997–1.005×。

### 变更：AVX-512 上短消息的 ChaCha20-Poly1305 更快

在具备 AVX-512 的 x86_64 上，only-crypto 的 ChaCha20 处理四个分组时每个寄存器存放每个分组的一行（用于消息开头与
短尾部），不完整的最后一组在字节掩码下直接经内核处理而不经缓冲区，并按实测内核耗时为开头选四个或八个分组；
AEAD 的 Poly1305 不再经过流式缓冲区。Zen 4，同批 A/B：加密 64 B 408 → 481 MB/s（ring 的 0.83 倍 → 0.98 倍），
1 KiB 1.00 倍 → 1.08 倍，1400 B 0.99 倍 → 1.21 倍；解密 64 B 0.76 倍 → 0.85 倍；1 KiB 的 TLS 1.3
ChaCha20-Poly1305 记录相对 rustls + ring 1.09 倍 → 1.15 倍（docs/BENCHMARKS.zh-CN.md）。16 KiB 及以上不变。
公开 API 无变化。

### 变更：RSA 验签在 AVX-512 IFMA 上计算，约快 2.5–3.4 倍

在支持 AVX-512 IFMA 的 x86_64 上，RSA 公开运算 `sᵉ mod n`（验签，以及每个签名发出前的校验）对 2048、3072 与
4096 位模数改为以 2⁵² 为基数计算（新增 3072 与 4096 位的几乎 Montgomery 乘法），`e = 65537` 只需 18 次乘积
（原为 21 次）；构造公钥时用更快的长除法求 `R² mod n`，不再做 Montgomery 乘法。Zen 4，空闲机器上同一次运行的
A/B 对比：RSA-2048 / 3072 / 4096 PKCS#1 验签快 2.51 / 3.00 / 3.39 倍（ring 的 1.22 / 1.10 / 1.09 倍 → 3.07 /
3.30 / 3.70 倍），含密钥解析的验签快 2.31 / 2.76 / 3.04 倍（1.02 / 0.95 / 0.95 倍 → 2.35 / 2.64 / 2.90 倍），
签名快 2–4%；使用 RSA-2048 证书的 TLS 1.3 握手为 rustls + ring 的 1.67 倍 → 1.82 倍（docs/BENCHMARKS.zh-CN.md）。
没有 IFMA 时（以及 `ONLY_CRYPTO_PORTABLE=1`）更少的乘积与更快的除法同样有效：2048 位可移植验签为 ring 的
0.59 倍 → 0.70 倍。私钥模幂及其常数时间性质不变。没有公共 API 变化。

### 变更：每个 HTTP/3 请求的内存分配更少

`quic-bench h3` 两端合计，一个 HTTP/3 请求及其响应的分配次数从 21.6 降到 8.6：only-quic 把流数据交给应用时
不再经过临时向量；only-h3 把较小的响应头与请求头写进 only-quic 的每线程池化缓冲区（隐藏的 `Bytes::pooled`，
不是公共 API），并原地加宽 HEADERS 帧的长度字段；only-http 的 `Context` 自己持有请求，直到 `Detached` 或
WebSocket 升级需要共享它，`Headers` 内联保存前两个字段的位置（仍是 48 字节）。QPACK 写 `:status`、
`content-length` 与 date 行（每秒编码一次）时不再查静态表，请求头只做一次 UTF-8 检查。Zen 4，空闲机器上同一次
运行的 A/B 对比：HTTP/3 GET，单连接，64 个并发 820,741 → 883,127 请求/秒（1.08 倍）；HTTP/1.1 与 h2c 在噪声
范围内不变（docs/BENCHMARKS.zh-CN.md）。没有公共 API 变化。

### 修复：构建 io_uring 引擎的线程不再遭遇无端的 `EINTR`

`io_uring_setup` 会把调用线程挂到新 ring 上；ring 销毁时，内核的退出工作会向所有挂在上面的线程发送
类似信号的 task_work（`TIF_NOTIFY_SIGNAL`）。后端探测与每个 I/O 线程的 ring 原先都在调用
`EngineBuilder::build`（或 `Engine::set_threads`）的线程上创建，于是探测用的 ring 或之后引擎的 ring
销毁时，该线程可能被打断：内核不会重启的阻塞调用（例如带超时的 socket 读）随即以 `EINTR` 失败，
而这发生在构建之后很久、与 io_uring 毫无关系的代码里。现在 ring 的创建与探测都在一个短命的专用线程上进行，
该线程退出时内核即解除挂接；每个 I/O 线程仍在启用自己的 ring 时挂上。这正是 only-socks 的
`udp_blocking_and_on_the_engine` 在 io_uring 下偶发失败的原因（负载下约每 100 次 3 次）：
中继各跳都已送达数据报，阻塞的 `recv_from` 却返回了 `EINTR`。新测试
`uring_engine_teardown_does_not_interrupt_the_building_thread`（only 的 `engine` 测试）在修复前每次都失败。
公共 API 不变；I/O 路径不变。

### 修复：QUIC 客户端的 0-RTT 不再先于 Initial 发出

`only_quic::dial` 在引擎线程上打开客户端的 UDP 套接字，在此之前发送的数据报暂存于积压队列。
原先套接字先登记、积压后发送，其间别的线程发送的数据（例如以 0-RTT 恢复的 `H3Client::dial`
之后立即发出的请求）会让 0-RTT 包先于 Initial 上线。服务端此时尚无 0-RTT 密钥，丢弃这些包，
请求在握手完成后以 1-RTT 重发、不带早期数据标记，尽管服务端已接受 0-RTT。恰在清空积压时入队的
数据报也可能滞留不发。现在在积压队列的锁内先清空积压、再登记套接字（迁移探测的套接字同样处理）。
这正是 only-h3 `zero_rtt` 测试偶发失败的原因（负载下约百分之二），该测试现在用中继扣住服务端的
握手报文直到请求发出，并等待会话票据而不是休眠。公共 API 无变化。

### 修复：`only_bittorrent::Client::close` 等待其线程退出

TSan 的首次运行（见下）报告了一处线程泄漏：`close` 关闭引擎与磁盘线程池后立即返回，因此之后 I/O 线程回调与 `Storage` 调用仍可能执行，而丢弃 client 会使这些线程脱离（detach）。现在 `close` 在引擎的 I/O 线程、磁盘线程池与维护线程都退出后才返回，因此不能在 client 自己的线程中调用（例如在 `Storage` 方法内）。

### 修复：HTTP 客户端不再拖住引擎的优雅关闭

`only_http::client::Client` 在引擎优雅关闭期间仍把空闲的 keep-alive 连接留在连接池中，因此只要客户端发过请求，`Engine::wait` 就要等满整个 `Config::shutdown_timeout`（默认 10 秒）。现在空闲连接在关闭开始时立即关闭；有请求在途的连接先交付响应，然后关闭而不再放回连接池。

### 新增：AddressSanitizer 与 ThreadSanitizer 运行（`tools/sanitizers/`）

2026-11-16 首次用 ASan（含 LeakSanitizer）与 TSan 运行工作区测试：所有 crate 在 Linux arm64 Docker 中覆盖 epoll 与 io_uring，含 unsafe 代码的 crate 与引擎后端在 x86_64 上运行（包括 AVX-512/IFMA/VAES/BMI2 汇编路径）。没有内存错误、内存泄漏或数据竞争；上述线程泄漏是唯一的报告。`tools/sanitizers/run.sh` 按 crate 运行，可在 Docker 中或原生运行；重型 CI 任务 `sanitizers` 现在用它覆盖整个工作区，而不是原先的八个 crate。其中的 `rustc-wrapper.sh` 让 `compiler_builtins` 不插桩构建，否则在 aarch64 上使用 `-Zbuild-std` 时所有插桩二进制都会在启动时崩溃。为 TSan 调整了两个测试：`only-sys` 的 `signal_to_pipe` 改为在等待的线程上触发信号（信号若落在阻塞于裸 futex 等待的线程上，TSan 永远不会执行其处理函数），only-ws 的客户端测试按 `ONLY_TEST_TIMEOUT_SCALE` 缩放其 10 秒期限。

### 变更：RSA 签名在同一个 AVX-512 IFMA 循环中计算 CRT 两半

在支持 AVX-512 IFMA 的 x86_64 上，RSA 私钥运算的两个半模幂（模 p 与模 q）现在同步推进：同一个汇编循环的
每次迭代各推进一个数字步，两条串行约简链因此重叠，不再各自等待。Zen 4，空闲机器上同一次运行的 A/B 对比：
RSA-2048 PKCS#1 签名 3,867 → 5,231 次/秒（ring 的 1.63 倍 → 2.20 倍），RSA-3072 1,436 → 1,691（2.19 倍），
RSA-4096 753 → 870（2.55 倍）；使用 RSA-2048 证书的 TLS 1.3 握手为 rustls + ring 的 1.45 倍 → 1.69 倍
（docs/BENCHMARKS.zh-CN.md）。验签、其他 CPU 以及两个素数位数不同的密钥不变。仍是常数时间（没有依赖秘密数据的
分支，已在反汇编中检查）。没有公共 API 变化。

### 变更：TLS 记录加密和解密前不再预先清零输出

TLS 记录层在 AEAD 写入记录的密文或明文之前不再清零那段空间：only-crypto 的 AES-GCM 与
ChaCha20-Poly1305 新增隐藏的 `encrypt_append` / `decrypt_append`，直接写入 `Vec<u8>` 的空闲容量（经由一个
很小的 `unsafe` 模块 `only_crypto::fill`，只有每个字节都写入后才扩展向量；打开失败时不追加任何内容，并把已写
的字节清零）。only-tls 仍是 `#![forbid(unsafe_code)]`。Zen 4 上的 TLS 1.3 记录（加密 + 解密，同一次运行
A/B）：AES-128-GCM +6.9–8.3%，AES-256-GCM +7.4–8.7%，ChaCha20-Poly1305 +3.3–6.4%（docs/BENCHMARKS.zh-CN.md）。
公开 API 不变。

### 新增：供应用自建转发使用的 `Conn::set_relayed`

基于 `hold_reads` / `on_drain` 自建的转发现在可以用 `Conn::set_relayed(true)` 跳过引擎按写水位暂停
读取的行为（`CONNECT` / 协议升级后的转发用 `only_http::raw::RawConn::set_relayed`）。否则，转发到
只有能写时才读的对端会死锁：与 only-socks 内部已修复的问题相同，现在应用代码也能避免。立即生效；
`Config::max_queued_bytes` 仍然适用。公开 API 为增量（快照已更新）。

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

### 评估：io_uring 注册文件、`SEND_ZC`、`MSG_RING` 唤醒、基于 ring 的发送（未采用）

- 在 Linux 7.0 / Ryzen 7 7800X3D 上按“同一轮内提升至少 3%、其他场景不退步”的规则测量
  （docs/BENCHMARKS.zh-CN.md，“io_uring 特性评估”）；没有一项达标，因此 io_uring 后端保持不变。`SEND_ZC`
  在 16 KiB 到 256 KiB 时慢 12–27%，每请求 CPU 多 10–36%（回环总是拷贝）；没有 ring 的线程发出的
  `MSG_RING` 唤醒（`IORING_REGISTER_SEND_MSG_RING`）在 `spawn_blocking` 往返上 +1.5–4.8%，其他场景
  −1.3% 到 +0.2%；注册 ring fd 为 −3.6% 到 +0.5%；注册文件在引擎中没有可节省的东西（稳态下每个请求
  不提交任何条目）。基于 ring 的发送（`IORING_OP_SEND`）在裸 ring 上 +1–4%、每请求 CPU 少 2–6%，但需要
  重新设计共用的写路径（写来自任意线程），留作后续工作。
- 新的测量工具：only-uring 中被忽略的 `eval_server` 测试（`src/eval.rs`，直接在 ring 上运行的最小
  HTTP/1.1 应答程序：`write` / `SEND` / `SEND_ZC`，可选 direct accept 与注册文件）以及
  `tools/bench/uring-eval.sh`。它用到的额外 io_uring 绑定（`SEND`、`SEND_ZC`、direct accept、固定文件
  close、稀疏 `REGISTER_FILES`、`MSG_RING` 与 `REGISTER_SEND_MSG_RING`）只在测试中编译。公共 API 不变。

### 新增：TLS 1.3 早期数据与 QUIC 0-RTT（需显式开启，带防重放）

- **`only-tls`**：早期数据（RFC 8446 第 4.2.10 节），双方默认关闭。
  `ServerConfigBuilder::early_data(max_bytes)` 签发带 `max_early_data_size` 的票据，并在票据的第一个
  PSK、密码套件、ALPN 协议与 SNI 名都一致时接受早期数据（HelloRetryRequest 之后绝不接受；超量为
  `unexpected_message`）；它在握手完成前被读取，以 EndOfEarlyData 结束。`ClientConfigBuilder::early_data(true)`
  把应用在握手前写入的数据作为早期数据发送（不超过票据上限），服务端拒绝时（包括 HelloRetryRequest
  之后）在握手后重发。新增 `EarlyData`（`NotAttempted`、`Pending`、`Accepted`、`Rejected`）与
  `TlsInfo::early_data` / `early_data_len`。
- **防重放**（开启早期数据时始终生效）：票据年龄的 10 秒新鲜度窗口（RFC 8446 第 8.3 节），以及每个
  `ServerConfig` 一份被接受 ClientHello 的 PSK binder 记录，保留 20 秒、上限 100,000 条（第 8.2 节）：
  重放的 ClientHello 其早期数据被拒绝，记录满时拒绝早期数据直到条目过期。不覆盖共享票据的多个进程或
  机器（已在文档中说明）。
- **`only-quic`**：0-RTT（RFC 9001 第 4.6 节），`ServerConfig::zero_rtt` / `ClientConfig::zero_rtt`
  （默认关闭）。恢复会话的客户端从记住的传输参数起步（RFC 9000 第 7.4.1 节），`dial` 后立即打开流并以
  0-RTT 包发送（v1 与 v2），合并在 Initial 之后。服务端只在限额与签发票据时相同的情况下接受 0-RTT，
  以 0.5-RTT 应答；客户端重发被拒或丢失的 0-RTT 数据（Retry 之后以 0-RTT，否则以 1-RTT）。新增
  `Connection::early_data` 与 `Connection::is_early(stream)`。
- **HTTP**：only-h3 给以 0-RTT 到达的请求加上 `Early-Data: 1`（RFC 8470），配置开启时 `H3Client` 以 0-RTT
  发送请求；TLS 上的 only-http 标记作为早期数据到达的 HTTP/1.1 请求（以及以早期数据开始的连接上的每个
  HTTP/2 请求）。处理函数对不能安全重复的请求回 `425 Too Early`。
- 测试：TLS 状态机（接受、拒绝、HelloRetryRequest、重放、过期的票据年龄、ALPN/SNI 绑定、
  `max_early_data` 上限），模拟网络上的 QUIC（接受、拒绝、0-RTT 包丢失、Retry、重放的首批包、v2），
  回环上的 QUIC、HTTP/3 与 TLS 上的 HTTP/1.1。互通：与 quic-go 双向的 v1 与 v2 0-RTT
  （`tools/interop/quic/run.sh`），与 OpenSSL `s_client` / `s_server -early_data` 双向的早期数据，接受与
  拒绝两种情况（`tools/interop/tls/run.sh`）。0-RTT 包与早期数据握手的 fuzz 种子。
- 另外：等待密钥后才处理的包、0-RTT / 0.5-RTT 包不再产生 RTT 样本；在途的 0-RTT 包不会推迟握手的探测
  定时器。
- 安全：早期数据与 0-RTT 没有前向保密，并且可能被单个服务端的记录之外的方式重放；README 与指南说明了
  何时（不）应开启。

### 新增：`only-quic` 的 ECN、BBR、客户端迁移、preferred_address 与 QUIC v2

- **ECN**（RFC 9000 第 13.4 节、RFC 9002 第 7.1 节），`TransportConfig::ecn`（默认开启）：Linux 上
  以 ECT(0) 发送，在 ACK_ECN 帧中报告收到的码点；用十个包的测试期和对端计数验证路径，CE 标记视为
  拥塞事件，清除、改写或丢弃带标记包的路径回退为不带标记发送。新增
  `ConnectionStats::ecn_capable` / `ecn_ce_events`。UDP 层逐个数据报传递码点：接收时用
  `IP_RECVTOS` / `IPV6_RECVTCLASS`，发送时每条 `sendmmsg` 消息带一个 `IP_TOS` / `IPV6_TCLASS`
  控制消息（`only_sys::enable_ecn`、`ecn_available`、`RecvBatch::ecn`、`Batch::push_ecn`；
  `ONLY_UDP_ECN=0` 关闭）。
- **BBR**：`Congestion::Bbr` 不再运行 CUBIC，而是基于投递速率采样的 BBRv1 模型与状态机，加上
  BBRv2/v3 对丢包或 CE 标记超过 2% 的轮次的上限。在测试机上用网络命名空间加 netem（100 Mbit/s、
  40 ms RTT、双向各回显 40 MB）：1% 丢包时 73 对 CUBIC 的 5 Mbit/s，60 个包的缓冲时 75 对 36 Mbit/s，
  干净的深缓冲上都是 84 Mbit/s。实验性。
- **客户端迁移**：`Connection::migrate(&engine)` 把客户端连接迁到新的本地 UDP socket 或服务端的
  首选地址，先用一个未用过的连接 ID 探测新路径；探测无回应时留在原路径。新增
  `Connection::preferred_address()`、`Error::Migration`。
- **preferred_address**：`ServerConfig::preferred_address(addr)` 提供首选地址（连接 ID 序号 1 及其
  重置令牌）；`QuicServer` 现在实现 `Clone`，同一个服务端可在第二个监听器上服务该地址。
- **QUIC 版本 2**（RFC 9369）：`Version`、`ClientConfig::version`、`ServerConfig::versions`、
  `Connection::version()`。服务端接受 1 和 2；收到版本协商包的客户端在双方都支持的版本上重新开始
  一次，并以 RFC 9368 的 version_information 参数防降级。未实现兼容版本协商（在握手中切换版本）。
- 互通（`tools/interop/quic/run.sh`）：与 quic-go 双向的版本 2（停在 quic-go 第一次密钥更新之前：
  quic-go v0.62 对版本 2 的密钥更新用了版本 1 的标签，与 RFC 9369 第 3.3.2 节不符）、双向客户端迁移
  （我方使用 BBR），以及 Linux 上与 quic-go 的 ECN 验证。
- 对来自其他地址的路径探测的回应现在使用单独的连接 ID（RFC 9000 第 9.5 节）；quic-go 的迁移客户端
  需要这一点。
- 未完成：0-RTT。

环回基准上的开销（`quic-bench`，测试机，CPU 2–5，与合并基点交替五轮取中位数）：bulk 18,704 →
18,288 Mbit/s（−2.2%；`ONLY_UDP_ECN=0` 时 −1.5%），HTTP/3 839,148 → 824,949 req/s（−1.7%；
−1.0%），完整握手 9,725 → 9,615/s（−1.1%；−0.8%）。ECN 的部分来自每个数据报的控制消息与 ACK_ECN
计数。

### 评估：内核 TLS 卸载（未采用，实验性 feature）

- 在 Linux 7.0 / Ryzen 7 7800X3D 上用 TLS 上的 HTTP/1.1 测量了握手后把 only-tls 的记录密钥交给 Linux
  内核（kTLS）的方案（`tools/bench/ktls.sh`）：内核的软件 TLS 在 1 KiB 响应时为 only-tls 自己记录层的
  0.83 倍，16 KiB 时 0.65 倍，256 KiB 时 0.40 倍，用 `sendfile` 发送 10 MB 文件对比 only-tls 的 `pread`
  加加密为 0.48 倍，每字节服务器 CPU 为 1.3 到 2.5 倍（docs/BENCHMARKS.zh-CN.md，“内核 TLS（kTLS）
  评估”）。它没有接入 `Tls` 或引擎。
- 卸载代码保留下来以便重新测量，放在 `only-tls` 新增的**实验性** feature `experimental-ktls` 之后（默认
  关闭，不在 semver 承诺之内，无公共 API）：阻塞测试流（`only_tls::stream`，隐藏）可在握手后卸载
  （TLS 1.3 与 1.2，AES-128/256-GCM 与 ChaCha20-Poly1305，告警、close_notify、NewSessionTicket，以及
  Linux 6.14+ 上的双向 KeyUpdate，回退到用户态），并配有 `ktls-bench` 示例、`tls-interop --ktls` /
  `ONLY_INTEROP_KTLS=require tools/interop/tls/run.sh`（对 OpenSSL 与 Go 107/107 通过）以及
  `crates/only-tls/tests/ktls.rs`（没有 `tls` 内核模块时跳过）。`only-sys` 新增隐藏的 `ktls` 模块
  （`TCP_ULP`、`SOL_TLS`、记录类型 cmsg），`linux/tls.h` 的结构体在布局测试中与 `libc` 对照。
- 文档：README、book 的 crate 列表与 fib 迁移指南中过时的“底层为 rustls”说法，以及 ROADMAP 的 TLS 行，
  已改为实际情况（自研 TLS 1.3 / 1.2）。

### 性能：`only-crypto` 中基于 VAES-AVX2 的 AES-GCM，AVX-512 内核内的掩码尾部

公开 API 不变（新增仅供测试与基准测试使用的 `#[doc(hidden)]` `AesGcm::with_cipher_avx2` 与 `AesGcm::kernel`）。

- 具备 VAES、VPCLMULQDQ 与 AVX-512 的 x86_64：整条消息在 512 位内核的一次调用中完成。不超过 256 字节的
  AAD 在内核中做 GHASH，最后一个不完整的组（1 到 255 字节）用 AVX-512 字节掩码加载与存储，不再走 128 位路径，
  长度块与 `E(J0)` 在同一次调用中给出标签；256 字节以下的消息把 AAD、数据与长度块放在一次归约里。
  AES-128-GCM 加密 1 KiB 7,902 → 10,433 MB/s（ring 的 1.00 倍 → 1.32 倍），1400 B 8,356 → 10,632（1.10 倍 →
  1.46 倍），64 B 1,204 → 1,383（1.11 倍 → 1.29 倍）；解密 1 KiB 1.04 倍 → 1.22 倍；16–64 KiB 不变（1.16–1.18 倍）。
- 具备 VAES 与 VPCLMULQDQ 但没有 AVX-512 的 x86_64（Zen 3、Alder Lake / Raptor Lake）：新增 VAES-AVX2 内核，
  每次迭代用 8 个 256 位寄存器处理 16 个分组，每组一次 GHASH 归约，处理完整的 256 字节组（其余部分走 128 位
  路径）。在关闭 AVX-512 内核的 Zen 4 上测得（没有 Zen 3 可用）：为这些 CPU 之前所用 128 位内核的 1.55–2.35 倍
  （AES-128 加密 16 KiB 6,310 → 12,671 MB/s）。
- `only-tls` 的 TLS 1.3 记录随之提升：AES-128-GCM 1 KiB 为 rustls + ring 的 1.51 倍 → 1.58 倍，16 KiB 1.56 倍 →
  1.60 倍。记录层在 AEAD 写入之前仍先把输出清零：把明文复制进来再原地加密在 16 KiB 上慢 6%，复用缓冲区只是把
  memset 换成复制，而跳过清零（16 KiB 快 10%）需要在 `#![forbid(unsafe_code)]` 的 crate 中使用 `unsafe`，因此
  没有这样做（docs/BENCHMARKS.zh-CN.md）。
- 测试：每个内核（AVX-512、AVX2、128 位、可移植）在 0..=600 的每个长度、若干大长度、0..=300 及 512 以上的每种
  AAD 长度上互相比较，覆盖未对齐、原地与非原地，并跑 CAVP 与 Wycheproof 向量；`crypto_aead` 模糊测试目标也比较
  AVX2 内核。在 Zen 4 上原生运行，也设置 `ONLY_CRYPTO_PORTABLE=1` 运行。
- `unsafe`：`gcm::hw` / `gcm::hw::vaes` 增加 5 个块与 1 个 `unsafe fn`（AVX2 内核的两个 `asm!` 块、整条消息的
  调用），见 docs/unsafe-review.zh-CN.md。Miri 永远不会执行到 `asm!`。

### 修复：io_uring 在读取暂停后仍调用 `on_data`

- `only-uring`：连接的输出队列达到 `Config::write_high_watermark`，或处理器调用了
  `hold_reads(true)` 后，后端会取消多次接收（multishot recv），但在取消生效前已到达的完成事件（机器
  快、对端持续灌数据时可达十几个 16 KiB 的读取）仍会交给 `on_data`。echo 类处理器于是越过水位线一直
  排队到 `max_queued_bytes`，得到 `Error::Overloaded`；`hold_reads` 也没有真正暂停读取。这使得在
  16 线程、Linux 7.0 的机器上用 io_uring 运行时 `chaos_engine` 每次都失败（"echo send failed:
  overloaded"）。现在这些输入按顺序留在连接里（其后的 EOF 也一样），读取恢复时再交付，与 epoll、
  kqueue 直接停止读取的行为一致。API 不变。

### 修复：SOCKS 与 HTTP CONNECT 隧道在背压下可能卡死

- `only-socks`：隧道（SOCKS5/4/4a 或 HTTP `CONNECT`）在转发大量数据时可能永久停住。引擎的写背压
  （`Config::write_high_watermark`）在上游连接有排队的客户端数据时会暂停读取该上游，但这些读取的数据
  是发往客户端的，并不进入这个队列。上游如果在自己的写被阻塞时不读（echo 服务器、大多数请求/响应式
  服务器），就会等代理，而代理也在等它。表现为负载较高时 `socks5_ipv4_domain_and_backpressure` 偶尔
  卡住 10 秒（kqueue、epoll 与 io_uring 都会）；先发送再读取的上游则每次都会卡住。现在隧道两端只由
  转发自身的暂停/恢复来调节。各后端（epoll、kqueue、io_uring、DPDK）都遵循新增的隐藏方法
  `ConnInner::set_relayed`。公共 API 不变。

### 性能：`only-h3` 的 HTTP/3 请求处理，`only-quic` 中带密钥的快速哈希

单连接 64 个请求在途的 HTTP/3 GET 从 429,038 升到 838,721 请求/秒（1.95 倍，交替运行七轮取中位数；
AMD Ryzen 7 7800X3D，回环，CPU 2–5）；QUIC 批量传输 +5%，握手持平。profile 中内存分配器从 31.8% 降到
11.2% 的采样，SipHash 从 7.3% 降到 0.1%。API 不变；与 quic-go 和 fib 双向互通测试通过。

- only-h3：请求与响应的帧直接在收到的流数据上原地读取（只缓冲末尾不完整的帧）；字段段解码到一个复用的
  扁平缓冲区，一次性做 UTF-8 校验，再复制一次进请求或响应的 `Headers`；以前每个字段要两个 `Vec`，
  每个名字和值各一个 `String`，外加第二份头部列表。
- only-h3：HEADERS 帧直接用 QPACK 编码进输出缓冲区，`:status`、`date`（每线程每秒格式化一次）和
  `content-length` 直接写在那里，不再先加进响应头；静态表引用按名字长度查找，不再用两个 SipHash
  映射；响应的 HEADERS、不超过 16 KiB 的响应体和 trailer 一次写给 QUIC（更大的响应体随后发送，不复制）。
- only-h3：一次收全的请求不进入流表就读完；流表改用乘法折叠哈希（大小受我们授予的流数量上限约束）。
- only-quic：endpoint 的连接 ID 表、连接表与客户端 socket 表（按对端地址）改用每张表各取新随机密钥的
  哈希（64×64→128 位乘法折叠），不再用 SipHash；客户端可以选择第一个 Initial 的连接 ID，密钥使得
  无法预先算出相互碰撞的 ID。连接 ID 只对实际使用的字节做哈希。单看这一项，批量传输 +3%（每个数据报
  查一次表）；HTTP/3 一个数据报承载许多请求，几乎看不出差别。
- only-quic：按序到达的流确认直接前移发送缓冲区的头部，不再经过已确认区间树（每次确认分配并释放一个
  节点）；流发送缓冲区的第一块数据内联保存，只写一次的流不需要分配队列。
- only-http：`Response::text` 与 `Response::with_body` 一次分配好头部存储，不再逐个字段扩容。

### 性能：`only-crypto` 中基于 AVX-512 与 IFMA 的 ChaCha20-Poly1305，TLS 记录非原地加解密

在 x86_64 上，ChaCha20-Poly1305 加密 16 KiB 为 4,597 MB/s（之前 1,752，ring 的 1.30 倍），1400 B 为
2,541（1,070，ring 的 0.96 倍），64 B 为 412（283，0.83 倍）；使用 TLS_CHACHA20_POLY1305_SHA256 的
TLS 1.3 记录在 16 KiB 时从 rustls + ring 的 0.55 倍提升到 1.42 倍，1 KiB 时从 0.64 倍提升到 1.02 倍
（AMD Ryzen 7 7800X3D；docs/BENCHMARKS.zh-CN.md）。API 不变。

- ChaCha20 在 zmm 寄存器中每次迭代处理 16 个分组，使用 `vprold` 循环移位，消息余下部分用一组 16、8（ymm）
  或 4（xmm）个分组处理，均为 `asm!` 内核（`chacha::hw::avx512`；AVX-512 intrinsic 在 MSRV 上不稳定）。
  没有 AVX-512 的 CPU 仍走 AVX2 路径。
- 对 256 字节及以上的连续分组，Poly1305 在 AVX-512 IFMA 上每步处理 8 个分组（`chacha::hw::ifma`，在 44 位
  limb 上使用 `vpmadd52luq` / `vpmadd52huq`），经 `Feature::Ifma` 检测；其余情况，以及其他 CPU 与 aarch64
  上，用 2⁶⁴ 进制的标量循环替换 44 位两分组循环（AVX2 路径上 16 KiB 快 1.3 倍）。
- `ChaCha20Poly1305::encrypt_detached_from` / `decrypt_detached_from`（`#[doc(hidden)]`，与 AES-GCM 的相同）：
  only-tls 非原地加解密 ChaCha20-Poly1305 记录，不再先复制。`new_avx2` / `new_portable`（`#[doc(hidden)]`）
  把密钥固定在较窄的路径上，供测试、`crypto_aead` 模糊测试目标与 `examples/chacha-sizes.rs`（按长度与 ring
  对比）使用。
- 正确性：0..=600 的每个长度与若干大长度经过 AVX-512 / IFMA、AVX2 与可移植三条路径，覆盖未对齐、原地与
  非原地、伪造标签、接近回绕的计数器，Poly1305 覆盖全 1 分组与极端的 `r` / `s`，在 Zen 4 上分别在设置与不设置
  `ONLY_CRYPTO_PORTABLE=1` 时原生运行。`unsafe`：+6 个块，+2 个 `unsafe fn`（docs/unsafe-review.zh-CN.md）。

### 新增：`only-crypto` 中 P-256 与 X25519 的 aarch64 汇编（尚未做性能测试）

aarch64 上 P-256 的域与群阶运算以及 X25519 阶梯的域运算改用内联汇编（`ec::hw_aarch64`、
`curve25519::hw_aarch64`），与 x86_64 的 BMI2 + ADX 代码对应；API 不变。

- P-256：模 `p` 与模 `n` 的 Montgomery 乘法与平方、加法、减法、`2ᵏ·a` 与 `3·a`，四个 64 位 limb，
  `MUL`/`UMULH` 求积，`ADDS`/`ADCS`/`SUBS`/`SBCS` 进位链，`CSEL` 修正；模 `p` 的约简只用移位与减法（同
  OpenSSL 的 `ecp_nistz256-armv8`），模 `n` 的约简中四个 limb 乘积有两个用移位代替。与 x86_64 一样，`P256`
  分派到建立在这个域上的孪生曲线；求逆是 safegcd（可移植的 divsteps），最后一次乘法用汇编，孪生曲线沿用
  `Curve::jac_*` 钩子的可移植默认实现（点运算公式、查表、4 位梳形表），运行在汇编域运算之上。
- X25519：阶梯的域运算使用四个 64 位 limb（每次乘积 16 个 `MUL` + 16 个 `UMULH`，而 2⁵¹ 进制需要 25 个
  128 位乘积），用 `CSEL` 按 `2²⁵⁶ ≡ 38` 折叠，交换用掩码。
- 所有 ARMv8.0 CPU 都有这些指令：aarch64 上 `hardware_features()` 报告 `umulh`；
  `ONLY_CRYPTO_PORTABLE=1` / `set_portable(true)` 切回可移植实现，Miri 永不执行这些汇编。
- 正确性：在随机值、边界值以及 20,000–50,000 次相互依赖的运算链上与可移植域运算做差分测试，孪生曲线与
  可移植曲线比较（密钥生成、ECDH、签名、验签），RFC 7748 向量（包括 1,000,000 次迭代，`--ignored`）与
  Wycheproof，均在 macOS（Apple 芯片）与 arm64 Linux 上运行。已反汇编秘密路径的 release 代码：汇编中没有
  条件分支，周围代码只有循环计数、公开边界、CPU 特性检查与最后的无穷远点判断。
- **尚未做性能测试**：设计依据指令数；在实测之前不声称 aarch64 上有任何加速。

### 性能：`only-http` 中 HTTP/2 与流水线 HTTP/1 的热路径

在自研替换完成后重新剖析（DEV-PLAN“性能优化”）；API 不变。

- HTTP/2：帧直接在读缓冲区中原地解析（不再每帧复制一次，剩余字节每次读只移动一次）；解码出的头部字段放进
  一个复用的缓冲区，而不是每个字段两个 `Vec`；头部块直接 HPACK 编码进输出缓冲区，`:status`、`date` 与
  `content-length` 也直接写在那里；能放进一个 DATA 帧且不超过流控窗口的响应体不再经过流的发送队列；
  流表用乘法折叠哈希代替 SipHash。
- HTTP/2：一次读所产生的一切（包括服务在 I/O 线程上发出的响应）在这次读处理结束时一次性交给连接写出
  （一批只产生一个 TLS 记录，而不是每个响应一个）；处理读期间其他线程发出的响应并入这一批，其余时候立即发出。
- HTTP/2 流控：连接与流的接收窗口在欠下四分之一时才归还，而不是每个 DATA 帧两个 WINDOW_UPDATE。
- HTTP/1：请求头先按最多 32 个字段解析（只在需要时才用 100 个），分帧所需的字段（`Host`、`Connection`、
  `Content-Length`、`Transfer-Encoding`、`Expect`）一次遍历找出。
- Ryzen 7 7800X3D，服务端 4 个线程（epoll）：h2c 64 连接 × 16 流 2.28M → 4.05M 请求/秒（1.78 倍，
  现为 fib 的 1.25 倍），h2c 16 × 128 2.37M → 4.71M，TLS 上的 HTTP/2 1.58M → 4.03M（2.5 倍，fib 的 1.33 倍），
  HTTP/1.1 流水线 ×16 3.99M → 4.26M（+7%，fib 的 1.14 倍）。h2spec：147/147。表格见 docs/BENCHMARKS.zh-CN.md；
  压测脚本（`tools/bench`，新增 README）在没有 wrk 时用 `h2load --h1` 驱动 HTTP/1.1，并新增了 TLS 上的
  HTTP/2 与多流用例。

### 性能：`only-crypto` 的 CPU 指令加速

`only-crypto` 现在在 CPU 支持时使用 CPU 指令（运行时检测），每条路径都以常数时间的可移植实现作为回退
（DEV-PLAN“性能优化”）；API 不变。

- x86_64：SHA-1 / SHA-256 使用 SHA-NI，AES-NI CTR 一次 8 个分组，AES-GCM 的 PCLMULQDQ GHASH（每次归约
  8 个分组）与 CTR 单趟融合，CRC-32 与 CRC-32C 使用 PCLMULQDQ 折叠以及 SSE4.2 `crc32` 指令，AVX2 ChaCha20
  （8 个分组）。
- aarch64：ARMv8 SHA1/SHA2、ARMv8 AES CTR、与 CTR 融合的 PMULL GHASH、ARMv8 CRC32 指令；ChaCha20 使用由
  编译器向量化的 4 分组并行布局（其他平台的可移植路径也是它）。
- 安全 Rust：44 位 limb 的 Poly1305（每步两个分组）；P-256 的专用 Montgomery 约简、加法链求逆、`[k]G` 的
  有符号仿射点梳形表以及无需求逆的 Jacobian wNAF 验签；Ed25519 交错 wNAF 验签；Curve25519、NIST 域与 RSA
  的专用平方；定长 RSA Montgomery 乘法；其余求逆使用窗口幂运算。
- `unsafe` 仍只出现在指令模块（`aes::hw`、`gcm::hw`、`hash::hw`、`crc::hw`、`chacha::hw`）中，每次调用前
  都经过检测（docs/unsafe-review.zh-CN.md）。`ONLY_CRYPTO_PORTABLE=1` 强制使用可移植实现（测试、基准）；
  Miri 运行的也是它。
- Ryzen 7 7800X3D 单核：SHA-1 3.6 倍、SHA-256 6.5 倍（与 RustCrypto crate 持平），AES-128-GCM
  364 → 6 484 MB/s，CRC-32 2.7 → 20 GB/s，ChaCha20-Poly1305 3 倍，P-256 验签 1.67 倍 / 签名 1.46 倍，Ed25519
  验签 1.49 倍，RSA-2048 签名 1.38 倍；TLS 1.3 握手 1.5 倍，16 KiB AES-GCM 记录 15 倍（分别为 rustls + ring
  的 0.60 倍与 0.64 倍）。表格见 docs/BENCHMARKS.zh-CN.md。

### 性能：更快的 TLS 1.3 握手（`only-crypto` 中的 P-256 与 X25519）

握手的性能剖析中曲线运算占 98% 以上；API 不变（`tools/api/public-api.sh` 无变化）。在基准主机上单核、
内存中与 rustls 0.23 + ring 对比：X25519 完整握手 3,055 → 5,027 次/秒（rustls 的 0.61 倍 → 1.00 倍），
secp256r1 2,306 → 4,552 次/秒（0.45 倍 → 0.89 倍）。

- x86_64 上带 BMI2 + ADX 时（运行时检测，`cpu` 新增特性 `adx`）的 P-256：模 `p` 与模群阶的 Montgomery
  乘法与平方、加法、减法与小倍数运算用内联汇编实现（`mulx`、`adcx`/`adox`、`cmov`；新的硬件模块
  `ec::hw`）。这些运算在一个“孪生”曲线类型上执行，它与可移植实现共享 Montgomery 表示和基点预计算表，
  因此每次操作只分派一次。
- 常数时间的标量乘法改用 Jacobian 坐标与 `a = -3` 公式：可变基点（ECDH）用 Booth 重编码的有符号
  5 位窗口，固定基点（密钥生成、签名）用有符号梳形表加混合加法。无穷远点的情形用掩码选择处理；对
  `[1, n)` 中的标量不会出现两个相同的操作数（代码中给出证明，测试检查 `n mod 32 ≥ 17`）。倍点为
  4M + 4S，并融合了 `2ᵏ·a`/`3·a`。
- P-256 标量求逆使用专用加法链（255 次平方、40 次乘法）；ECDSA 验签对公开的 `s` 用二进制扩展欧几里得
  算法求逆，并直接用射影坐标的公钥建表而不求逆。`SecretKey::public_key` 得到的公钥在编码前保持射影
  坐标（编码时做一次常数时间求逆）。
- X25519：公钥按 edwards25519 上的 `[k]B` 计算再映射为 `u = (1 + y)/(1 - y)`（使用 Ed25519 基点表，
  现在是带有符号数字的仿射 Niels 表项：每个数字 7M）；x86_64 带 BMI2 + ADX 时 Montgomery 阶梯在四个
  64 位 limb 上用内联汇编运行（`curve25519::hw`），2⁵¹ 进制的阶梯仍是可移植路径。
- 与 ring 对比的微基准（`--example pk_bench`，次/秒，优化前 → 优化后）：P-256 签名 34,152 → 59,837
  （0.45 倍 → 0.79 倍），验签 13,404 → 25,138（0.51 倍 → 0.96 倍），ECDH 10,380 → 27,288（0.35 倍 →
  0.91 倍），密钥生成 54,581 → 108,263（0.49 倍 → 0.96 倍）；X25519 30,696 → 36,488（0.84 倍 → 1.00 倍）；
  Ed25519 签名从 ring 的 1.15 倍到 1.53 倍；P-384 签名、验签、ECDH 与密钥生成比之前快 1.13–1.47 倍。
  RSA 不变。
- 常数时间证据：秘密标量路径的反汇编（x86_64 含汇编，aarch64 为可移植代码）中，条件分支只出现在循环
  计数、公开下标、求逆加法链的公开指数位、CPU 特性检查以及“结果为无穷远点”的判断上（见 `ct.rs`）。
  每个汇编例程都在随机值与边界值上与可移植代码比较，所有已知答案测试都在设置与不设置
  `ONLY_CRYPTO_PORTABLE=1` 时各跑一遍。
- `unsafe`：`only-crypto` 新增 13 个 `asm!` 块（`ec::hw` 8 个，`curve25519::hw` 5 个；见
  docs/unsafe-review.zh-CN.md）。

### 性能：`only-crypto` 的宽 AES-GCM 与 CRC，TLS 记录非原地加解密

公开 API 不变（只新增 `#[doc(hidden)]` 辅助函数）。

- 具备 VAES、VPCLMULQDQ 与 AVX-512 的 x86_64（Zen 4、Ice Lake 及更新；通过 CPUID 与 XCR0 检测）：AES-GCM
  加密与解密以一趟 512 位处理完成，每次循环 16 个分组，AES 轮函数与上一组的 GHASH 交织，每 16 个分组归约
  一次（BoringSSL / Linux `aes-gcm-avx10` 的设计；因为这些 intrinsic 比 MSRV 新，用 `asm!` 编写）。在
  Zen 4 上 512 位内核在所有长度上都快于同一内核的 256 位寄存器版本，因此只保留它；其他 CPU 继续使用
  AES-NI + PCLMULQDQ 内核。CRC-32 / CRC-32C 从 512 字节起在 512 位寄存器上每步折叠 256 字节。
- 所有具备 AES 与无进位乘法指令的 CPU：消息的最后几个字节与 `J0` 一次通过 AES，短 AAD、尾部密文与长度块
  一次通过 GHASH（64 字节消息快 1.8–2.1 倍）。
- `only-tls` 非原地加解密记录：AEAD 直接读取调用方的明文或收到的记录，只写一次输出，不再先复制再原地处理
  （复制占 16 KiB 记录的 30%）。
- Ryzen 7 7800X3D 单核：AES-128-GCM 加密 16 KiB 6,455 → 15,048 MB/s（ring 的 0.51 倍 → 1.19 倍），
  1400 B 4,249 → 8,163，64 B 611 → 1,185；TLS 1.3 记录加密 + 解密 16 KiB 2,739 → 6,603 MB/s（rustls + ring
  的 0.69 倍 → 1.65 倍）；CRC-32 16 KiB 20.0 → 74.9 GB/s（crc32fast 的 0.27 倍 → 1.02 倍）。表格见
  docs/BENCHMARKS.zh-CN.md。
- `unsafe`：新的 `gcm::hw::vaes` 内核、`asm!` CRC 折叠以及 CPUID / XGETBV（`cpu::hw`），均记录在
  docs/unsafe-review.zh-CN.md 中。Miri 永远不会执行到 `asm!`（检测不到任何特性）。

### 性能：`only-crypto` 中 P-256 的整点汇编、宽梳形表与 safegcd

无 API 变化（`tools/api/public-api.sh` 不变）。在基准机的单个核心上与 ring 0.17 / rustls 0.23 在同一次运行中
对比（交替运行五轮取中位数；机器同时被另一个基准测试占用，绝对速率偏低 20–30%，见 docs/BENCHMARKS.zh-CN.md）：
P-256 签名为 ring 的 0.77 倍 → 1.25 倍，生成密钥 0.94 倍 → 1.33 倍，验签 0.98 倍 → 1.04 倍，ECDH 0.94 倍 →
0.96 倍；TLS 1.3 secp256r1 握手为 rustls 的 0.94 倍 → 1.12 倍。

- x86_64 上带 BMI2 + ADX 时：P-256 孪生曲线的 Jacobian 倍点（`a = -3`）、加法与混合加法各是一个作用于小栈帧
  的 `asm!` 块，乘法与约简和周围的模加、模减、模倍融合（累加值留在寄存器中；每个乘积的低半部分单独约简，
  再加上高半部分）。连续的倍点（ECDH 每个窗口五次，验签中两次加法之间的若干次）共用一个帧。一次倍点约
  355 个周期，原来约 480 个。曲线 trait 增加了这些例程与查表的钩子，aarch64 的孪生曲线可以用同样方式接入。
- 固定基点（生成密钥、签名）在孪生曲线有 AVX2 时：Booth 重编码的有符号 6 位数字，作用于 43 行、每行 32 个
  仿射点的梳形表（88 KiB，首次使用时构造），43 次混合加法代替 65 次；每行都用 256 位读取与 `vpcmpeqq`
  掩码完整扫描。6 位与 7 位梳形表测得持平，5 位与 8 位更慢。ECDH 的窗口表也这样扫描。没有 AVX2 时仍用
  4 位梳形表。
- 模 P-256 素数与群阶的求逆改用 safegcd（libsecp256k1 形式的 Bernstein–Yang divsteps，新模块 `safegcd`），
  常数时间，x86_64 上 divsteps 用汇编，其他平台用带掩码的 Rust：签名中的标量求逆 20.9k → 7.0k 个周期，
  域求逆约 12.7k → 约 7–9k。所有路径（包括可移植路径）都不再使用费马加法链。
- 正确性：整点例程在随机 `Z` 的随机点、Wycheproof 中全部合法的 ECDH 点、`P + P`、`P + (-P)` 与无穷远点上
  与可移植公式逐 limb 比较；safegcd 在两个模数的随机值与边界值上与费马求逆比较；宽梳形表在随机标量与边界
  标量（每个最高位数字）上与完备公式的参考实现比较；宽梳形表不会遇到相同操作数的论证写在 `ec/hw.rs` 中。
- 常数时间证据（Zen 4 上 release 反汇编）：点运算例程、AVX2 查表与 `Fe::invert` 中没有任何条件分支；
  每个 `divsteps_59` 只有一个（循环计数）；`ecdh_x_impl`、`sign_impl` 与 `hw::mul_base` 中只有 CPU 特性与
  `OnceLock` 检查、循环计数、公开的数字位置与边界、输出长度以及最后的无穷远点判断。
- `unsafe`：`ec::hw` 新增 6 个块与 2 个 `unsafe fn`（点运算共用一个块、divsteps 一个块、两个 AVX2 查表及其
  两处调用；见 docs/unsafe-review.zh-CN.md）。

### 性能：`only-crypto` 中 x86_64 上开销更低的 P-256 点运算公式

无 API 变化（`tools/api/public-api.sh` 不变）。在空闲的基准机上测量（Zen 4，CPU 2，交替运行五轮取中位数，
同一次运行中对比 ring 0.17）：P-256 ECDH 为 ring 的 1.08 倍 → 1.12 倍（32,351 → 33,904 次/秒），签名 1.36 倍
→ 1.38 倍，验签 1.08 倍 → 1.10 倍，生成密钥 1.36 倍 → 1.40 倍。上一条记录中的 0.96 倍是在有负载的机器上测得的；
在空闲时，这次修改之前的代码已经是 1.08 倍。TLS 1.3 握手没有变化（secp256r1 为 rustls 的 1.07 倍，X25519 为
1.08 倍）：一次 ECDH 约占一次握手的 1%。

- P-256 孪生曲线的整点汇编改用 OpenSSL `ecp_nistz256` 的公式：加法为 12M + 4S，配 7 次模加减，代替
  add-2007-bl 的 11M + 5S 与 13 次模加减（这里乘法与平方开销相同，线性运算则不然）；混合加法为 8M + 3S，代替
  7M + 4S（7 次对 14 次）；倍点先算 `2Y`，于是 `Z₃ = 2Y·Z`、`4β = X·(2Y)²`、`8γ² = ((2Y)²)²/2`（新增模减半）
  只需 10 次线性运算，原来是 14 次。加法返回同一个点的另一种表示（`(X, Y, Z)` 而不是 `(4X, 8Y, 2Z)`）；倍点的
  limb 与原来相同。
- 点运算例程中的 Montgomery 约简在四步中都把 `p₃` 放在 `rdx` 中，并用 `shlx`/`shrx` 拆分 `m·2⁹⁶`（编译器保留的
  `rbx` 存放移位计数 32，在帧中保存与恢复）：每步从 10 条指令减为 7 条。
- 周期数（`perf stat`，Zen 4）：加法 745 → 721，混合加法 537 → 508，倍点 355 → 348，可变基点标量乘法
  148.1k → 140.6k，固定基点（梳形表）29.8k → 28.9k。倍点表现为每次乘法固定约 44 个周期：调整顺序（先算独立的
  乘积，或先算 `Y` 链）慢了 8–10%，OpenSSL 式把约简交织进乘积各行持平，把 `cmov` 选择换成 `xor`/`and` 掩码
  慢了 10%，因此都没有采用。
- 正确性：`points_match_portable` 逐 limb 比较倍点，加法则按点比较（交叉相乘，`Z = 0` 恰好出现在可移植公式
  给出 `Z = 0` 的地方），并新增两侧为全零无穷远点的情形；模减半在随机值与边界值上检查。
- 常数时间：Zen 4 上 release 反汇编中，`ecdh_x_impl`（17 处：循环计数、公开的数字位置与边界、CPU 特性检查、
  输出长度与最后的无穷远点判断）、`hw::mul_base`、`divsteps_59` 与 `safegcd::inv_with` 的条件分支与之前相同，
  点运算例程中没有。
- `unsafe`：没有新增块；点运算块保存并恢复 `rbx`（docs/unsafe-review.zh-CN.md）。

### 性能：`only-crypto` 中基于 BMI2 + ADX 与 AVX-512 IFMA 的 RSA

无 API 变化（`tools/api/public-api.sh` 不变）。在空闲的基准机上测量（Zen 4，CPU 2，新旧二进制交替运行三轮，
同一次运行中对比 ring 0.17，单位次/秒）：RSA-2048 PKCS#1 v1.5 签名 1,192 → 3,910（ring 的 0.49 倍 → 1.61 倍），
RSA-3072 371 → 1,455（0.47 倍 → 1.85 倍），RSA-4096 156 → 755（0.45 倍 → 2.19 倍）；验签 39,250 → 79,970
（0.60 倍 → 1.22 倍）、18,300 → 33,440（1.10 倍）、10,110 → 19,090（1.09 倍）；含公钥解析的验签（即验证一个证书
签名；ring 每次调用都会解析）5,850 → 67,090（0.09 倍 → 1.02 倍），3072 与 4096 位为 0.95 倍与 0.95 倍。
only-tls 使用 RSA-2048 证书的完整握手（`tls-bench` 新增一行）：775 → 2,586 次/秒，rustls + ring 的 0.43 倍
→ 1.44 倍。

- 在支持 AVX-512 IFMA 的 x86_64 上（新增 `cpu` 特性 `ifma`：CPUID leaf 7 加 AVX-512 状态），2048、3072 与
  4096 位密钥的 CRT 模幂以 2⁵² 为基数运算（`bignum::ifma`）：对 20、32 或 40 个数字做几乎 Montgomery 乘法，
  每个乘积一个 `asm!` 块，操作数放在寄存器中（20 与 32 个数字用 `ymm`，40 个用 `zmm`）；20 个数字时用两个
  累加器，使每个寄存器每步只承担两次相互依赖的乘加；最低位数字与下一个 `yᵢ` 在通用寄存器中计算，使这条依赖链
  不经过向量单元；进位用一个 generate / propagate 掩码字规整。整个模幂过程中结果都小于 `2p`，最后做一次带掩码的
  减法。一次 1024 位乘法需要 416 个周期。
- 没有 IFMA、但有 BMI2 + ADX 时：16 至 64 个 limb 的 Montgomery 乘法与平方用 `asm!` 实现（`bignum::hw`；
  `mulx` 加两条进位链的操作数扫描，行用汇编器的 `.rept` 展开，下一步约简因子直接取自寄存器，32 个 limb 以内有
  专用平方，最后的减法用 `cmovnz`）：1024 位乘法 1,240 → 805 个周期，平方 1,490 → 681；只走这条路径时 RSA-2048
  签名为 ring 的 0.99 倍，验签 1.20 倍。
- 模幂：固定 5 位窗口（原为 4 位），扁平的预计算表中偶数项用平方得到，每次查表用 AVX2 `vpcmpeqq` 掩码一遍扫过
  全部 32 个表项（没有 AVX2 时用常数时间的 `ct` 掩码）。
- `R² mod m`：秘密素数用 `64 + k` 次倍加与六次 Montgomery 平方，代替 `128k` 次倍加（常数时间）；公开模数用一次
  长除法；密钥解析不再是证书校验的主要开销。私钥运算保留盲化（现在用专用平方更新），省去四次 2048 位的形式转换，
  并用三次乘法把盲化后的输入约简到各素数域。
- 没有尝试 Karatsuba：在这些位数下，汇编的行循环已没有多少可省。
- 正确性：`asm_matches_generic`（在每个规模上把 BMI2 + ADX 代码与通用 CIOS 比较：随机值，以及 0、1、m - 1、
  m - 2、R - 1、R - m，最高 limb 满与不满的模数，200 步运算链），`ifma_pow_matches`（用边界底数与指数把 IFMA
  模幂与平方-乘法比较），`r2_constructions`；`rsa_vs_ring` 现在用 2048、3072（新增）与 4096 位（新增）密钥签名，
  要求 PKCS#1 v1.5 签名与 ring 逐字节一致，并在强制可移植实现时再比较一次；Wycheproof 的 RSA 向量不变，两条
  路径都通过。
- 常数时间：Zen 4 上的 release 反汇编中，`Mont::mul_into` / `sqr_into`、`ifma::amm`、`ifma::pow`、`Mont::pow`、
  查表、`Mont::new`、`crt_combine` 与 `private_op` 的条件分支只有循环计数、按公开 limb 数与数字个数的分派、
  CPU 特性、切片与内存分配检查、公开的窗口位置、盲化缓存与最后的故障检查（数量见 `src/ct.rs`）。
- `unsafe`：`only-crypto` 新增 7 个块与 1 个 `unsafe fn`（`bignum::hw`：两个 Montgomery 汇编块与 AVX2 查表；
  `bignum::ifma`：IFMA 汇编块）；见 docs/unsafe-review.zh-CN.md。

### 新增：`only-crypto` 的统计计时测试（`tools/ct-dudect`）

dudect 式测试（对固定与随机秘密做 Welch t 检验，随机交错，`rdtsc` / `cntvct_el0` 计时，分位数裁剪与二阶
检验，`|t| > 4.5` 视为泄漏），在硬件与可移植代码上测量依赖秘密的路径：P-256 ECDH、生成密钥与签名，X25519
及其生成密钥，Ed25519 签名，RSA-2048 签名，AES-GCM 与 ChaCha20-Poly1305 的标签校验，HMAC 校验，`ct_eq` 与
`ct.rs` 原语；以 A/A 测试和两个故意泄漏的函数作为自检。这是新的 workspace 内部工具（不发布，无新依赖）；
CI 中作为信息性任务 `ct-dudect` 运行（不属于 `ci-ok`，t 值保存为 artifact）。在 Zen 4 上未见泄漏，只有两处
细小且时有时无的差异有待进一步测量（退化的全零 X25519 标量；P-256 可移植签名处于阈值边缘）；方法与结果见
[docs/constant-time.zh-CN.md](docs/constant-time.zh-CN.md)。

### 性能：`only-deflate` 的存储块只复制一次

无 API 变化；压缩输出逐字节不变。在基准主机上测量（Zen 4，CPU 2，新旧 `bench` 二进制交替五轮，zlib-rs 在同一次
运行中）：解压级别 6 的随机数据（存储块）15,456 → 34,278 MB/s（zlib-rs 的 0.43 倍 → 0.94 倍），级别 9 为
15,357 → 34,003 MB/s。文本与 JSON（字面量与匹配）不变。

- 存储块从输入直接复制到调用方的输出，不再经过窗口；一段连续的存储数据只把最后一个窗口大小（至多 32 KiB）的部分
  放进历史，每次调用一次，在压缩块或尾部需要之前完成。
- `Inflater::decompress_vec` 用 `extend_from_slice` 追加存储数据（无需先填零再复制）；块头在没有输出空间时解码。
  `decompress` 预先保留两倍输入大小（不超过上限）的空间。
- 测试：三种格式下存储块在每个输入字节处切开、按每种输出大小读取（经 `decompress` 与 `decompress_vec`），以及
  长于窗口的存储块（至多 65,535 字节）之后按最大距离匹配，窗口为 512 字节、4 KiB 与 32 KiB。
- 尝试后放弃：在以字面量为主的路径上每次补充位缓冲后解码至多五个字面量（原为三个），没有可测的差别。

### 性能：QUIC 数据通路（默认 GRO、按批 ACK、池化接收缓冲区）

API 不变（`tools/api/public-api.sh` 无变化：新增的钩子是 `#[doc(hidden)]`）。一个默认值改变：
`Config::udp_gro` 现在为 `true`。在基准主机上测量（Zen 4，回环，`quic-bench` 客户端与服务端在 CPU 2–5，
新旧交替七轮取中位数，部分轮次主机上有外部负载）：单流批量传输 6,378 → 16,066 Mbit/s（2.52×），
HTTP/3 427,901 → 443,299 请求/秒（1.04×），完整握手 9,294 → 9,542/秒（持平）。同一程序的 quinn-proto
版本在同一次运行中为 4,613 Mbit/s 与 56,934 请求/秒，本版本为 15,999 Mbit/s 与 430,098 请求/秒
（3.5× 与 7.6×）。

- `only-core`：`Handler::on_batch_end`（`#[doc(hidden)]`，默认什么也不做，不在稳定性承诺之内）告诉 UDP
  处理器：调用过它 `on_data` 的那个接收批次结束了。only-epoll 的 UDP 循环（io_uring 后端与 macOS 上的 UDP
  也由它服务）在批次的回复发出之前，对每个连接每批调用一次（一次 `recvmmsg`；macOS 上最多 32 次
  `recv_from`/`recv`）；填满整批的拨号连接现在每批之后就发出，而不是最多八批之后。其他后端（only-dpdk）
  不调用它。
- `Config::udp_gro` 默认为 `true`（Linux，内核支持 `UDP_GRO` 时；只探测一次，`ONLY_UDP_GRO=0` 仍可关闭，
  `read_buffer` 仍需至少 64 KiB）。服务端、绑定与拨号 socket 上合并的接收照旧按 `UDP_GRO` 分段大小拆开，
  `on_data` 仍然每次一个数据报（only-kcp、only-turn、only-webrtc 与 DNS 的测试不变地通过）。仅此一项，
  QUIC 批量传输 6.4 → 9.8 Gbit/s：发送方的一批 GSO 数据完整到达接收 socket，而不是被拆段。64 字节 UDP
  echo 开关 GRO 各交替 15 轮：差别不超出该场景的噪声。
- UDP 循环每次接收调用读一次时钟，并把每个计时回调的结束时间当作下一个回调的开始（与 TCP 循环相同）：
  每个数据报读三次时钟变为一次。
- only-quic 每个接收批次只确认一次：每个数据报之后处理器照常运行，已就绪的数据立即发出，但只含 ACK 的包
  等到 `on_batch_end`（每批一个，而不是每两个包一个）；QUIC 定时器也每批只设置一次。把处理器事件与数据
  也推迟到批次结束的变体在批量传输上测得 1.45×，但 HTTP/3 下降 28%（64 个在途请求变成每个往返一个
  步调一致的批次），因此没有采用。在 socket 第一次收到 `on_batch_end` 之前（以及在没有该钩子的后端上），
  每个数据报照旧单独驱动。
- 收到的数据报只复制一次，进入每线程的缓冲池（`Arc<Vec<u8>>`）并就地解密；流数据与数据报是其 `Bytes`
  切片，切片全部释放（可在任意线程）后缓冲区被复用。这取代了每个包两次分配（复制及其外层 `Arc`）。仍有
  一次复制：处理器以引用方式拿到 `recvmmsg` 的槽位，而就地解密需要本方独占的缓冲区。
- 已发送的包记录在按包号索引的环形缓冲中（`proto/conn/sent.rs`），不再用 `BTreeMap`；已确认或已丢失
  的包的帧列表被新包复用。
- 剖析中发现但未处理的：对端地址与连接 ID 表上的 SipHash（约占接收方 2%），以及 only-h3/only-http 中的
  分配与头部哈希（`encode_fields`、`Headers`），它们是 HTTP/3 剖析的主要部分。

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

### 变更（破坏性，1.0.0 之前）：自研日志门面 `only-log` 取代 `log`

DEV-PLAN 第 B 波。`only` 不再依赖 `log` crate，而是通过新的公开 crate `only-log`（无依赖，以
`only::log` 重新导出）记日志：级别、target、沿用 `log` 宏语法的结构化键值对、存放在原子变量中的全局
最大级别（被禁用的语句只需一次 relaxed 读：0.25-0.29 ns，`log` 为 0.36 ns）、带 `set_logger` /
`set_boxed_logger` 的 `Logger` trait，以及内置 logger（`only::log::init(level)` 向 stderr 输出格式化
行，`StderrLogger`）。target、消息和键名保持不变；未安装 logger 时，错误与慢回调警告仍打印到 stderr。
新增的 `log` cargo feature（`only`、`only-core`、`only-log`；不在 semver 承诺之内）桥接到 `log`
crate：未安装 only-log logger 时记录交给 `log` 的 logger（`Config::log_level` 也会像以前一样设置
`log::max_level`），`only::log::bridge::route_log_to_only()` 则把 `log` 的记录（str0m、rustls ……）
送入 only-log 的 logger。

迁移：

| 之前 | 之后 |
|---|---|
| `env_logger::init()`（或任意 `log` logger） | 不变，在 `only` 上开启 `features = ["log"]`；或改用 `only::log::init(only::log::LevelFilter::Info)` |
| `cfg.log_level = Some(log::LevelFilter::Info)` | `Some(only::log::LevelFilter::Info)`（开启 `log` feature 时也可写 `Some(log::LevelFilter::Info.into())`） |
| `Telemetry::set_log_level(log::LevelFilter)` | `set_log_level(only::log::LevelFilter)` |
| `impl log::Log for MyLogger` | `impl only::log::Logger for MyLogger`（`enabled` 与 `flush` 有默认实现）；用 `only::log::set_logger` 安装 |
| `record.key_values().visit(&mut visitor)` | `record.key_values().iter()` / `.get("conn_id")`；值实现了 `Display` |
| `log::max_level()` | `only::log::max_level()` |

### 变更：自研密码学（`only-crypto`，DEV-PLAN 第 A 波）

- 新的内部 crate `only-crypto`（只依赖 std，除 AES-NI / ARMv8 AES 模块外 `#![deny(unsafe_code)]`）：SHA-1、
  SHA-224/256、SHA-384/512、MD5、HMAC、HKDF、PBKDF2、CRC-32 / CRC-32C、AES-128/192/256（检测到 CPU
  指令时使用指令，否则使用常数时间 fixsliced 软件实现）及 CTR、带常数时间 GHASH 的 AES-GCM、ChaCha20-Poly1305、base64（严格解码）、操作系统随机数与
  ChaCha20 生成器。用 NIST CAVP、RFC 与 Wycheproof 向量测试，并（在测试与模糊测试目标中）与被替代的
  crate 交叉比对。
- `only-kcp`、`only-turn`、`only-ws`、`only-http`、`only-media`、`only-bittorrent` 和
  `only-webrtc` 改用它，不再依赖 sha1、sha2、md-5、hmac、pbkdf2、aes、aes-gcm、ctr、crc32fast、
  base64 与 getrandom（它们只作为 dev / fuzz 的参照实现保留，在第 D 波之前仍经由 str0m/dimpl 间接存在）。
  公开 API 与线上格式不变（KCP 加密，包括旧实现封装的“黄金”数据报；TURN MESSAGE-INTEGRITY/FINGERPRINT；
  WebSocket accept key；BitTorrent info hash 与 MSE；SRT 密钥包装与 AES-CTR；RTMP digest 握手；SRTP）。
- `only-sys`（内部，`#[doc(hidden)]`）：基于 `getrandom(2)` / `getentropy(2)` 的 `fill_random`，
  回退到 `/dev/urandom`。
### 新增：公钥密码学与 X.509（`only-crypto`、新的 `only-x509`，DEV-PLAN 第 B 波）

为自研 TLS 1.2/1.3、DTLS、QUIC 与 WebRTC 协议栈（第 C、D 波）打基础；协议 crate 目前还没有使用它们，
行为没有变化。

- `only-crypto`（内部层级；API 只增不减）：X25519（RFC 7748）、Ed25519（RFC 8032，严格验证：`S` 必须规范、
  比较 `R` 的编码）、P-256 与 P-384 上的 ECDH 和 ECDSA（RFC 6979 确定性 nonce，DER 与定长签名，带校验的
  SEC1 点）、RSA PKCS#1 v1.5 与 PSS 签名/验证（SHA-256/384/512，SHA-1 仅验证），模数 2048–8192 位（CRT、
  盲化、结果校验），严格 DER 读写器、PEM，以及密钥编码（PKCS#8 v1/v2、SEC1、PKCS#1、
  SubjectPublicKeyInfo），统一在 `pkey::{PrivateKey, PublicKey, SignatureAlgorithm}` 之后。`Error` 新增
  `InvalidKey`、`Encoding`、`Unsupported`、`Random`、`ZeroSharedSecret`。常数时间的域运算（P-256/P-384 与
  标量用 Montgomery，Curve25519 用 2⁵¹ 进制）、完备加法公式、读取全部表项的查表。
- 新的内部 crate `only-x509`（`#![forbid(unsafe_code)]`）：证书解析（严格 DER；subjectAltName、
  basicConstraints、keyUsage、extKeyUsage、nameConstraints、密钥标识符），基于 `RootStore` 的证书链构建与
  校验（有效期、CA/pathLen、密钥用途、EKU、DNS/IP/directoryName 名称约束、未知关键扩展、签名校验次数上限），
  RFC 6125 服务器名匹配（仅最左标签通配符、IP SAN），以及自签名和 CA 签发证书的生成
  （`CertificateParams`、`generate_simple_self_signed`）。
- 测试：Wycheproof（X25519、Ed25519、ECDSA P-256/P-384 的 DER 与 P1363、ECDH P-256/P-384、RSA PKCS#1 v1.5
  与 PSS 验证、RSA 签名生成）、RFC 7748 / 8032 / 6979 向量、与 ring 和 RustCrypto p256/p384 签名逐字节一致
  且互相验证、真实证书链（Google Trust Services、Let's Encrypt 的 ECDSA 与 RSA 链）、OpenSSL 生成的证书链与
  密钥（RSA-PSS、P-384、Ed25519）、与 rcgen 和 rustls-webpki 互通、构造的反例证书链；模糊测试目标
  `x509_parse` 与 `crypto_sig_verify`（与 ring 差分），并有语料回放测试。

### 新增：自研 DTLS 1.2（新的 `only-dtls`，DEV-PLAN 第 C 波）

自研 WebRTC 协议栈的 DTLS 层（第 D 波将用它替代 str0m 的 `dimpl`）；目前还没有代码使用它，因此行为不变。

- 新的内部 crate `only-dtls`（`#![forbid(unsafe_code)]`，只依赖 `only-crypto` 与 `only-x509`）：
  sans-io 的 DTLS 1.2（RFC 6347）`Connection`，可作任一角色，由 `handle_datagram`、`poll_transmit`、
  `poll_event`、`poll_timeout` / `handle_timeout` 与 `send_application_data` 驱动。记录层支持 epoch、
  48 位序列号与 64 条记录的防重放窗口；握手消息按配置的 MTU 分片并支持乱序重组；按指数退避重传
  flight（RFC 6347 §4.2.4），对端重发上一 flight 时也重传；无状态的 HMAC-SHA-256 HelloVerifyRequest
  cookie（`HelloVerifier` 供在证明返回可达性之前不分配任何状态的监听方使用）。
- 密码套件 `TLS_ECDHE_{ECDSA,RSA}_WITH_{AES_128_GCM_SHA256, AES_256_GCM_SHA384,
  CHACHA20_POLY1305_SHA256}`，群 X25519 / P-256 / P-384，ECDSA、Ed25519、RSA-PSS 与 RSA PKCS#1 签名；
  扩展主密钥（RFC 7627，默认必需）；拒绝重协商（RFC 5746）。
- WebRTC：`Config::webrtc`，自签名证书的双向认证，可由 `PeerVerifier::Fingerprints`（SDP
  `a=fingerprint`）、回调校验或交给调用方；`Identity::generate_self_signed`、`Fingerprint`（SDP 格式）、
  `use_srtp`（RFC 5764）支持 `SRTP_AEAD_AES_128_GCM`、`SRTP_AEAD_AES_256_GCM`、
  `SRTP_AES128_CM_HMAC_SHA1_80/32`，SRTP 主密钥随 `Event::Connected` 给出，以及 RFC 5705 导出器
  （`export_keying_material`）。
- 测试：在 MTU 256、25% 丢包、重复与乱序的模拟链路上握手，每个套件配合 ECDSA P-256/P-384、Ed25519 与
  RSA 证书，负面用例（错误指纹、重放、篡改记录、错误 cookie、超时、缺少客户端证书、无共同套件）；
  与 OpenSSL `s_client`/`s_server -dtls1_2`（Docker 中的 3.5 与 4.1；`-use_srtp` 与 `-keymatexport`
  的密钥一致）和 pion/dtls v3 双向互通（`tools/interop/dtls/run.sh`），并在内存中与 `dimpl` 互通
  （`tests/dimpl.rs`）；fuzz 目标 `dtls_record` 与 `dtls_handshake` 及语料回放测试。未实现：DTLS 1.3
  （RFC 9147）、连接 ID、会话恢复、PSK。
### 变更：`only-tls` 自研 TLS 1.3 与 1.2（DEV-PLAN 第 C 波；不再依赖 rustls、ring）

`only-tls` 现在依据 RFC 自己实现 TLS，基于 `only-crypto` 与 `only-x509`（`#![forbid(unsafe_code)]`，
无第三方依赖）。受保护的 API 不变（`api/only-tls.txt` 完全相同）：`ServerConfig` / `ClientConfig`
构建器、`Certificate`、`PrivateKey`、`RootCerts`、`Error`、`Tls`、`TlsInfo`、`tls_info`；only-http
（HTTP/1.1，经 ALPN 的 HTTP/2）、only-ws（`wss://`）、only-socks、only-grpc 与 only-mux 无需改动即
运行其上。

- TLS 1.3（RFC 8446）：双方完整握手、HelloRetryRequest（回显 cookie）、密钥调度、KeyUpdate（应答，
  并在达到 AES-GCM 记录上限前主动发送）、NewSessionTicket 与 PSK 会话恢复（`psk_dhe_ke`；
  `session_tickets(true)` 为无状态票据，会话缓存为一次性缓存票据）、客户端证书、中间设备兼容模式，
  拒绝 0-RTT（按 RFC 8446 4.2.10 跳过）。
- TLS 1.2（RFC 5246 + RFC 7627 扩展主密钥 + RFC 5746 重协商指示，以 `no_renegotiation` 警告拒绝
  重协商）：仅 ECDHE 搭配 ECDSA、Ed25519 或 RSA 证书与 AEAD 套件，按会话 ID 与 RFC 5077 票据恢复，
  客户端证书；设置并检查 RFC 8446 的降级哨兵。
- 套件：TLS_AES_128_GCM_SHA256、TLS_AES_256_GCM_SHA384、TLS_CHACHA20_POLY1305_SHA256 以及六个
  ECDHE-ECDSA/RSA 的 AES-GCM / ChaCha20-Poly1305 TLS 1.2 套件。组：X25519、secp256r1、secp384r1。
  签名：ECDSA P-256/P-384、Ed25519、RSA-PSS（rsae）与 RSA PKCS#1 v1.5（TLS 1.2 与证书）。扩展：SNI、
  ALPN、supported_versions、key_share、signature_algorithms、psk_key_exchange_modes、pre_shared_key、
  early_data、cookie、extended_master_secret、renegotiation_info、session_ticket、ec_point_formats；
  未知扩展被忽略。
- 记录层：16 KiB 分片、TLS 1.3 内层内容类型与填充、严格的状态机、握手消息跨记录重组（跨密钥切换则拒绝）、
  close_notify、告警、警告告警数量有上限；证书由 `only-x509` 验证（链、有效期、EKU、DNS 名与 IP 地址）；
  `insecure_skip_verify` 不变。
- 面向 QUIC 的内核（`only_tls::quic`，`#[doc(hidden)]`，内部）：同一套 TLS 1.3 状态机，不经记录层，
  按加密级别驱动（握手字节进出、各级别的流量密钥、quic_transport_parameters、强制 ALPN、无兼容模式、
  RFC 9001 密钥派生辅助函数及其附录 A 向量），供第 D 波的自研 QUIC 使用。在那之前 only-quic 仍用
  quinn-proto，其 rustls 配置现由 only-quic 根据 only-tls 的配置自行构建（rustls 只留作 only-quic 的依赖）。
- 测试：RFC 8448 跟踪（简单 1-RTT、恢复绑定值、HelloRetryRequest：密钥调度、transcript、Finished、记录
  逐字节一致），覆盖所有套件、组、密钥类型与版本的内存握手，会话恢复、客户端认证、低至单字节的分片、
  KeyUpdate、降级检测与反例；互通矩阵（`tools/interop/tls/run.sh`，107 个用例：OpenSSL
  `s_server`/`s_client`、Go `crypto/tls` 双向、curl 的 HTTP/1.1 与 HTTP/2），`tools/interop/grpc/run.sh`
  新增 TLS 一环，`only` 的 TLS 测试保留 rustls 客户端；以 tlsfuzzer 测试服务端（`tools/interop/tls/tlsfuzzer.sh`：
  33 个适用的 TLS 1.3 / 1.2 脚本，985 个探测，5 个已知且有记录的失败）；fuzz 目标 `tls_server`、`tls_client`、
  `tls_record` 及语料回放。
- 性能（Apple M4 Pro，服务端 2 线程，rustls 客户端）：完整握手约为 rustls+ring 的 0.7 倍（`only-crypto`
  的 P-256 ECDSA 与 X25519 慢于 ring 的汇编），小记录持平，大块吞吐约 0.45 倍（`only-crypto` 的 GHASH
  为可移植实现；PMULL / PCLMULQDQ 是第 A 波的后续工作）。

迁移：only-tls 的 `unstable` feature（以及 `only/unstable` 中与 TLS 相关的部分）不再暴露任何内容：
`only::tls::rustls`、`ServerConfig::from_rustls` / `as_rustls` 与 `ClientConfig::from_rustls` /
`as_rustls` 已移除（它们本就不在 semver 承诺之内）。`ServerConfigBuilder::build` 在私钥与证书不匹配时
也会报错。rcgen 与 rustls 已从 only-tls、only-http、only-ws、only-mux、only-h3、only-quic、only-grpc
的 dev-dependencies 中移除（测试证书改由 `only-x509` 生成）；`only` 的 TLS 测试保留 rustls 客户端作为
互通对端。

### 变更：`only-quic` 自研 QUIC v1（DEV-PLAN 第 D 波；不再依赖 quinn-proto、rustls、bytes）

`only-quic` 现在依据 RFC 9000、9001、9002 以及 RFC 9221 数据报自行实现 QUIC，是基于 `only-tls`
（其不经记录层的 TLS 1.3，`only_tls::quic`）与 `only-crypto` 的 sans-io 核心
（`#![forbid(unsafe_code)]`，无第三方依赖）。quinn-proto、其内部的 rustls（及 ring）以及 `bytes` crate
已从 only-quic 和 only-h3 中移除；工作区里已没有库依赖 rustls。除负载类型外 API 不变（迁移见下）：
`QuicServer`、`dial`、`Connection`、`QuicHandler`、`ServerConfig` / `ClientConfig` /
`TransportConfig`、`StreamId`、`ConnectionError`、`ConnectionStats`；only-h3 的 API 不变
（`api/only-h3.txt` 完全相同）。

- 数据包：长/短包头、三个包号空间、包号编码、包头保护（AES、ChaCha20）、AES-128/256-GCM 与
  ChaCha20-Poly1305 包保护、合并数据包、Initial 与路径验证的填充、版本协商、带完整性标签的 Retry、无状态
  重置（对未知连接 ID 发送，按令牌识别）、1-RTT 密钥更新（每几百万个包发起一次，对端发起时跟随）。
- 帧：RFC 9000 的全部帧以及 DATAGRAM，并遵守按包类型的限制；流级与连接级流量控制、流数量上限
  （MAX_STREAMS 批量下发）、BLOCKED 帧、最终大小检查、以 RESET_STREAM 回应 STOP_SENDING。
- 丢包恢复（RFC 9002）：RTT 估计、按包序与时间阈值的丢包检测、探测超时与握手防死锁探测、持续拥塞、
  NewReno 与 CUBIC（RFC 9438）、pacing、3 倍放大限制、ACK 延迟规则、空闲超时、保活、探测到 1452 字节的
  路径 MTU 发现。
- Endpoint：按连接 ID 路由（8 字节 ID，用 NEW_CONNECTION_ID 下发、退役后补充）、握手压力大时使用 Retry、
  NEW_TOKEN 地址验证（令牌按服务器名保存在 `ClientConfig` 中）、经路径验证的迁移
  （`ServerConfig::migration(false)` 拒绝迁移）、传输参数与连接 ID 校验、基于票据的会话恢复
  （`server_config` 开启票据）。
- I/O：满尺寸的数据报成批地用 GSO 发出（`Conn::send_segments`，最多 10 个）；在连接自身回调中发起的写入
  先攒起来，回调返回后与 ACK 一起发出，因此 HTTP/3 响应的头、体与 FIN 通常在同一个包里。
- 测试：RFC 9001 附录 A 向量、各组件的单元测试，以及模拟网络（丢包、乱序、重复、MTU、断网、虚拟时钟）上
  的握手、大块传输、多流、迁移、密钥更新、Retry、会话恢复、重置与超时测试；与 quic-go 的原生 QUIC 双向互通
  （新增 `tools/interop/quic/run.sh`：流与数据报，然后是 Retry、密钥更新与 150 MB 的流）以及与 quic-go、
  fib 的 HTTP/3 双向互通（`tools/interop/h3/run.sh`）；在 Docker 中以 ngtcp2 1.11（通过 libcurl-gnutls）
  和 OpenSSL 3.5 的 QUIC（curl、libcurl、`openssl s_client -quic`）作为我方服务端的客户端（新增
  `tools/interop/quic/docker.sh`）；fuzz 目标 `quic_packet`、`quic_frame`、
  `quic_conn`，并回放语料。
- 性能（与 quinn-proto 版本对比，同一个回环基准 `crates/only-h3/examples/quic-bench.rs`）：在 AMD Ryzen 7 7800X3D（Linux，回环，交替运行 3 轮）上，完整握手 6705-6785 次/秒，对比 6536-6674 次/秒（约 1.0 倍）；单流大块吞吐 3.1-3.6 Gbit/s，对比 4.6-4.7 Gbit/s（约 0.72 倍；包保护使用 `only-crypto` 的硬件 AES-GCM）；单连接 64 个并发的 HTTP/3 请求 17.1 万次/秒，对比 5.8 万次/秒（约 2.9 倍，因为响应、FIN 与 ACK 共用数据包）。

迁移：流与数据报负载改为 `only_quic::Bytes`（原为 `bytes::Bytes`），这是唯一的签名变化
（`QuicHandler::on_stream_data`、`QuicHandler::on_datagram`，以及接受 `impl Into<only_quic::Bytes>` 的
`Connection::send` 与 `Connection::send_datagram`）。它的形状相同（引用计数；`new`、`from_static`、
`copy_from_slice`、`slice`、`split_to`、`split_off`、`truncate`、`advance`、`Deref<Target = [u8]>`、
`From<Vec<u8>>`、`From<&'static [u8]>`、`From<&'static str>`、`From<String>`、`Vec<u8>: From<Bytes>`），
通常只需改导入：`use bytes::Bytes;` 改为 `use only_quic::Bytes;`。only-quic 的 `unstable` feature 保留且为空：
`only_quic::proto`、`ServerConfig::from_quinn` / `as_quinn_mut` 与 `ClientConfig::from_quinn` /
`as_quinn_mut` 已移除（它们本就不在 semver 承诺之内）。`Congestion::Bbr`（实验性）实际运行 CUBIC。
`Connection::queued_bytes` 统计尚未发出的字节数。`dial` 发起的连接结束后其 UDP socket 会被关闭（以前一直保持到引擎停止）；`open_bi` / `open_uni` 从不运行处理器回调，因此可以在持有处理器也会获取的锁时调用。未实现：0-RTT、发送 ECN 标记、客户端主动迁移、
preferred_address、QUIC v2。

### 变更：`only-webrtc` 使用自研 WebRTC 协议栈（DEV-PLAN 第 D 波；不再依赖 str0m、dimpl、p256）

`only-webrtc` 在 API 不变的前提下（`RtcServer`、`Endpoint`、`Peer`、`PeerHandler` 及其顺序保证、
`ChannelConfig`、`Codec`、`SdpChanges`、`Event`、`RtcError` 等）改为运行在自研、sans-io、无第三方
依赖的 WebRTC 协议栈上。新增四个内部 crate，均为 `#![forbid(unsafe_code)]`，构建于 `only-crypto`
之上：

- `only-ice`：ICE（RFC 8445）完整 agent 与 ICE-lite：候选优先级与 foundation、带节奏控制与重传的
  检查列表、peer-reflexive 候选、常规提名、角色冲突（487）、在获得远端凭据之前到达的检查、consent
  freshness（RFC 7675）、trickle（RFC 8838）与重启；STUN 使用 `only-turn` 的编解码。RFC 5769 向量；
  与 pion/ice 互通。
- `only-srtp`：SRTP/SRTCP（RFC 3711、RFC 7714），支持 AES-CM-HMAC-SHA1-80/32 与
  AEAD-AES-128/256-GCM、ROC 估计、防重放窗口；RFC 3711 与 RFC 7714 向量，并与 pion/srtp 逐字节比对。
- `only-rtp`：RTP 头扩展（单字节与双字节形式）、RTCP（SR、RR、SDES、BYE、通用 NACK、PLI、FIR、REMB、
  传输层拥塞控制反馈）、带 NACK + RTX（RFC 4588）、报告与 RTT 的收发流、TWCC 与基于时延和丢包的
  带宽估计；Opus、G.711、G.722、VP8、VP9、H.264（RFC 6184）、H.265（RFC 7798）与 AV1 的载荷格式，
  以及无抖动缓冲延迟的组帧器。与 pion/rtp、pion/rtcp、pion/interceptor 逐字节比对。
- `only-sctp`：基于 DTLS 的 SCTP（RFC 8261；RFC 9260 的核心部分），拥塞控制、快速重传、PR-SCTP
  FORWARD-TSN（RFC 3758）、流重置（RFC 6525）、DCEP 数据通道（RFC 8831/8832）；经 UDP 与
  pion/sctp 1.8 和 1.12 互通。

`only-webrtc` 本身新增了 SDP offer/answer（BUNDLE、rtcp-mux、编解码器 / RTX / rtcp-fb / extmap 协商、
ssrc 与 FID 组、setup 角色与指纹、ICE-lite、候选、sctp-port / max-message-size、重新协商与 ICE 重启）
以及把各层粘合起来的 sans-io peer。测试覆盖模拟丢包链路（ICE + DTLS + SCTP + 媒体），并与 pion（数据
通道、Opus/VP8 回显、PLI、TURN 中继，两个 offer 方向）、fib 的 Go WebRTC（双向）以及无头 Chrome
（`tools/interop/media/browser.sh`：数据通道，Chrome 的摄像头与麦克风媒体回显后由其解码，两个 offer
方向）互通。新增 fuzz 目标 `ice_stun`、`srtp_unprotect`、`rtp_rtcp`、`rtp_codec`、`sctp_packet`；
`webrtc_sdp` 现在驱动新的 SDP 代码。

迁移说明：

- `only-webrtc` 的 `unstable` feature 现在是预留的空 feature：`only_webrtc::str0m`、
  `crypto_provider_str0m`、`Peer::with_rtc`、`RtcConfig::with_str0m` 与 `OtherEvent::as_str0m`
  已移除（它们本就不在 semver 承诺内）。
- 受保护的 API 不变，只是 `Event`、`OtherEvent`、`RtcConfig`、`RtcError` 与 `SdpChanges` 现在实现了
  `RefUnwindSafe`（`RtcError` 还实现了 `UnwindSafe`）：只增加了 auto trait，没有减少。
- 行为：默认不再提供 H.265（用 `RtcConfig::enable_h265(true)` 开启）；DTLS 只支持 1.2（浏览器与 pion
  协商的都是 1.2）；应答方取 DTLS 客户端角色（`a=setup:active`）；`OtherEvent` 的 `Debug` 输出变了
  （它从来不是稳定的）；`Endpoint` 仍没有 TURN 客户端（与以前一样，relay 候选需在别处获得）。
- 依赖：str0m、dimpl、p256 / ecdsa / elliptic-curve、它们引入的 RustCrypto crate 以及 rand 0.9 已退出
  库的依赖图；only-dtls 与 dimpl 的内存互通测试已删除。p256/p384 0.13 仍是 only-crypto 交叉检查的
  dev-dependency，因此 `deny.toml` 中对 RUSTSEC-2026-0387（crypto-bigint）的忽略现在只涉及它们。

### 变更：自研 HTTP 编解码（不再依赖 httparse、loona-hpack、regex）

DEV-PLAN“长期：去除第三方依赖”第 A 波。公开 API 不变。

- HTTP/1 头部解析（only-http 的请求、chunked trailer 与客户端响应，only-ws 客户端握手响应）改用自研解析器
  `only_ws::http1`（`#[doc(hidden)]`）：零拷贝；增量（分多次读到的头部只扫描一遍，不再每次读都从头重新解析；
  会话也不再每次读都复制已缓存的字节）；按 RFC 9110/9112 严格校验：方法与字段名必须是 token，请求目标必须是
  可见 ASCII（httparse 放行的非 ASCII 字节现在返回 400），请求行各元素之间恰好一个 SP，拒绝孤立 CR、冒号前
  或首个字段前的空白以及过时的折行（响应中同样拒绝），行尾接受 CRLF 或单独 LF。头部值不再做 `str::trim`
  （按 RFC 9110 只去掉两侧的 SP/HTAB）。速度与 httparse（SIMD）相当，用的是安全代码中的按字扫描
  （`tools/codec-bench`）。
- HPACK 改为自研（`only_http::hpack`，`#[doc(hidden)]`）：编码器带动态表，Huffman 编码不更长时使用，
  `authorization` / `proxy-authorization` / 较短的 `cookie` 用 never-indexed 字面量，对端修改
  `SETTINGS_HEADER_TABLE_SIZE` 后按 RFC 7541 §4.2 发送动态表大小更新（loona-hpack 从不发送）；解码器带动态表，
  大小更新只允许出现在头部块开头且不超过我方设置，整数不超过 32 位，解码过程中即应用头部列表大小限制（整个块
  仍会处理完，使动态表保持同步）；Huffman 解码每次处理 4 位。RFC 7541 附录 C 的向量双向通过；h2spec 147/147。
- 路由约束（`{id:[0-9]+}`）改用自研线性时间引擎（`only_http::re`）：字面量、`.`、带范围/取反/转义的字符类、
  ASCII 的 `\d \w \s`（及其取反）、分组（含命名分组，不做捕获）、`|`、`* + ? {m} {m,} {m,n}` 及其惰性形式、
  `^`/`$`；不支持的语法（标志、`\b`、`\p{..}`、反向引用、POSIX 字符类、字符类集合运算、超过 1000 的计数）
  在注册时 panic 并指出问题。正则参数始终可用；only-http 的 `regex` cargo feature 保留为空操作以保持兼容。
- 模糊测试：`http1_request` / `http1_client` 将头部解析器与 httparse 对比，`hpack` 与 loona-hpack 对比（编解码
  双向互通），新增的 `regex_match` 与 `regex` crate 对比；这些 crate 只作为 `fuzz/` 与 `tools/codec-bench`
  微基准（都在库的 workspace 之外）的依赖保留。
### 变更（内部）：自研系统调用与 io_uring 绑定（不再依赖 `libc`、`io-uring`）

DEV-PLAN“不依赖三方库”第 B 波。公开 API 不变；行为、errno 与 `EINTR` 处理不变。

- `only-sys` 在 `only_sys::ffi`（`#[doc(hidden)]`，内部）中声明自有的操作系统绑定：C 类型、常量、`#[repr(C)]` 结构体（`sockaddr_in`/`in6`/`storage`/`ll`、`msghdr`、`mmsghdr`、带 `CMSG_*` 辅助函数的 `cmsghdr`、`iovec`、`epoll_event`（x86_64 上为 packed）、`kevent`、`timespec`、`pollfd`、`cpu_set_t`、`sigaction`、`utsname`），以及 C 库（Linux，glibc 或 musl）与 libSystem（macOS）函数的 `extern "C"` 声明。没有 C 封装的系统调用（`bpf`、`io_uring_*`）经 `syscall(2)` 调用，系统调用号按架构区分。支持 Linux x86_64 与 aarch64（riscv64 / loongarch64 共用通用布局）以及 macOS aarch64 / x86_64；其他 Linux 架构会以明确的错误信息编译失败，而不是悄悄使用错误的布局。
- 每个布局与常量都在仅测试用的模块中与 `libc` crate 对比（`libc` 现在只是 dev-dependency），已在 macOS aarch64、Linux aarch64 和 Linux x86_64 上验证。
- `only-uring` 拥有自研 io_uring 绑定（`ring`）：`io_uring_setup` / `io_uring_enter` / `io_uring_register`，按内核内存序访问的 mmap SQ/CQ ring 与 SQE 数组，反应器用到的提交项（multishot accept、带缓冲区选择的 multishot recv、poll add、async cancel 与 cancel-any、read），CQE 标志，opcode 探测与 `IORING_FEAT_*` 检查（探测现在也要求 `IORING_FEAT_EXT_ARG`），SQPOLL 以及 cooperative / single-issuer / deferred task-run 设置。buffer ring、`KernelBuf`、在途取消与 graveyard 逻辑不变。
- `only-ebpf` 与 `only-dpdk`（TAP、AF_PACKET）改用 `only_sys::ffi`。

### 变更（实验性层级）：only-dpdk 使用自研 TCP/IP 协议栈

`only-dpdk` 不再依赖 smoltcp（DEV-PLAN“去除第三方依赖”第 A 波）：用户态协议栈改为 only 自研，位于
`crates/only-dpdk/src/net`（安全 Rust，`#![forbid(unsafe_code)]`，无依赖），`Device` 种类、
`DpdkConfig` 与 `Backend::Dpdk` 的集成方式不变。

- 以太网 II；ARP 缓存 60 s，并为等待解析的报文排队（发往新邻居的第一个 SYN 不再被丢弃，smoltcp 版本
  因此要多等 1 s 的 SYN 重传）；IPv4 发送分片与带上限的重组（超过 MTU 的 UDP 数据报现在可用）；ICMP
  回显应答、端口/协议不可达，收到的不可达会交付给已拨出的 UDP 连接（以 `ConnectionRefused` 关闭，与
  内核后端一致）。
- 遵循 RFC 9293 的 TCP：RFC 6298 的 RTT / RTO，SACK（RFC 2018）与 RFC 6675 风格的恢复，NewReno
  快速恢复（RFC 6582），CUBIC（RFC 9438，默认）或 NewReno，窗口缩放与时间戳及 PAWS（RFC 7323），
  延迟 ACK，keepalive，可复用的 TIME-WAIT，RFC 5961 挑战 ACK，带 SYN cookie 的监听 backlog。
- I/O 循环改为事件驱动，并使用每连接一项的定时器堆（smoltcp 版本在每轮有流量的迭代中检查所有连接）；
  ACK 按接收批次合并；内存链路的一端发送后会唤醒对端线程。
- 多队列 DPDK 端口上可以拨号（原先返回 `Unsupported`）：本地端口对应其队列，RSS 放到其他队列的回包
  会被转交。
- `DpdkConfig` 新字段：`syn_cookies`（默认 `true`）、`congestion`（新类型 `only::dpdk::Congestion`，
  默认 `Cubic`）、`tcp_keepalive`（默认 `None`）。`udp_buffer` 现在限制每个 UDP 端口排队的数据报。
- TAP 与 AF_PACKET 设备直接使用 `libc`（`src/sys.rs`）；AF_PACKET socket 使用 8 MiB 接收缓冲区，并
  跳过本机发出的帧。
- 测试：逐层单元测试、虚拟时间中的模拟丢包/乱序链路，内核对端测试新增 `tc netem` 丢包、20 ms 下的
  4 MiB 窗口、500 条并发连接、向内核拨号与 ping；模糊测试目标 `dpdk_ethernet`、`dpdk_arp`、
  `dpdk_ipv4`、`dpdk_tcp`、`dpdk_udp`、`dpdk_icmp`、`dpdk_stack`。基准示例 `stack-bench`；与 smoltcp
  版本的 A/B 对比见 docs/BENCHMARKS.zh-CN.md。
- `deny.toml`：去掉了 smoltcp 带来的 0BSD 许可证与 `bitflags@1` 重复项。

### 变更（性能）：QUIC 与 TLS 热路径（DEV-PLAN 性能优化）

API 无变化。Ryzen 7 7800X3D，回环，交替运行三轮（见 docs/BENCHMARKS.zh-CN.md）：

- `only-quic`：单流大块吞吐 3.4-3.7 → 5.7-5.8 Gbit/s（quinn-proto 版本的 1.25 倍，之前为 0.72 倍），单连接 64 个并发的
  HTTP/3 请求 17.1 万 → 41.5-42.6 万次/秒，握手 +2%。pacer 原先把 RTT 下限设为 1 ms，令牌桶一空就通过定时器线程为每个包
  唤醒一次发送方；现在使用测得的 RTT，并等整批令牌补满再发（与 quinn-proto 相同），被 pacing 的数据以 GSO 批次从 I/O 线程
  发出（每 GiB：futex 调用 42.3 万 → 5600 次，上下文切换 18.2 万 → 9500 次）。另外每个包的簿记更省（流映射不再用 SipHash，
  按序插入区间只需一次查找，批次缓冲区与包号空间选择不再逐个数据报分配内存）。
- `only-tls`：收到的记录只复制一次，直接进入调用方的明文缓冲区并在那里解密（以前经过接收缓冲区再复制出来）；大块写入一次性
  为所有记录预留空间。16-64 KiB 记录的加密 + 解密提升 5-7%。握手经过剖析：98% 以上是曲线运算与哈希，因此未改动。新增
  `crates/only-tls/examples/tls-bench.rs`，与 rustls 0.23 + ring 对比（仅为开发依赖）。

### 变更（性能）：only-deflate 达到 zlib-rs 的速度（DEV-PLAN 性能优化）

`only-deflate`（仍为 `#![forbid(unsafe_code)]`，无依赖，不用 SIMD）的压缩速度现在为使用 zlib-rs
后端的 flate2 的 0.94-1.48 倍（之前为 0.25-0.9 倍），输出最多大 0.5%（45 组级别 × 语料中 36 组完全
相同）；解压为 0.82-1.23 倍（之前为 0.7-0.85 倍）。在 x86-64 上测量，表格见 docs/BENCHMARKS.zh-CN.md。
对每种窗口大小（8 按 9 布局）输出的流与之前一样有效；API 不变。

- 压缩采用 zlib-ng / zlib-rs 的级别表与匹配策略：四字节哈希（级别 9 为三字节）；级别 1 为 `quick`
  （每个位置只探测一次，直接写出固定编码块，若存储块更小则改用存储块），级别 2 为 `fast`，级别 3-6 为
  `medium`（贪心，级别 5 起向前多看一个匹配），级别 7-9 为惰性的 `slow`，级别 9 使用 zlib-ng 的跳链
  搜索。候选匹配先做廉价的排除检查，再每次比较 8 字节。**级别 1 的输出现在比之前最多大 40%**（与
  zlib-ng、zlib-rs 的级别 1 相同），速度为之前的 1.7-2.9 倍；级别 2-9 快 1.03-4 倍，输出比之前小 12%
  到大 3.4% 不等。
- `Deflater::reset`（不保留上下文的 permessage-deflate）对短流只清空它用过的哈希槽，而不是整张表；
  存储块直接从窗口写出；构造 Huffman 编码时统计码长不再受存储转发停顿影响。
- 解压：快速路径无分支地补充 64 位比特，每次补充后解码最多三个字面量或一个长度/距离对；匹配以 8 或
  16 字节为单位复制（重叠匹配也是）；完整编码的解码表不再预先清零。
- permessage-deflate 回显（`pmd_echo`，级别 6，保留上下文）与 zlib-rs 相比：64 B 消息 1.84 倍，
  512 B 1.04 倍，4 KiB 1.00 倍，64 KiB 0.98 倍（之前为 1.36 / 0.62 / 0.75 / 0.54 倍），线上字节与
  zlib-rs 相同。
- `bench` 示例覆盖级别 1..=9（`BENCH_LEVELS`）、生成的语料加上传入的文件，并提供剖析模式
  （`BENCH_PROFILE`）；新的流式测试覆盖每个级别、窗口大小与刷新方式。

### 新增

- `only-protobuf` 与 `only-protobuf-build`（DEV-PLAN“不依赖第三方”第 A 批）：自研的 protobuf
  运行时与代码生成器，取代 prost，没有任何依赖。
  - `only-protobuf`：线格式、`Message`（编码、解码、合并、长度前缀分帧）、开放枚举
    （`Enumeration`）、保留未知字段（`UnknownFields`）、`Name`、有界解码（最多 100 层嵌套、检查
    长度、检查 UTF-8；线类型不符的字段作为未知字段保留，与 C++、Go 一致），以及 `well_known`
    （`Empty`、`Timestamp`、`Duration`、`Any`、包装类型、`FieldMask`、`Struct` / `Value` /
    `ListValue`，含与 `std` 类型的转换和 `Any::pack` / `unpack`）。编码结果与 protoc 的 C++
    运行时逐字节一致。
  - `only-protobuf-build`：`.proto` 解析器（proto3 与 proto2：消息、嵌套类型、枚举、`optional`、
    `required`、`repeated`、`map`、`oneof`、默认值、package、import、内置 well-known 类型）与供
    `build.rs` 使用的 Rust 代码生成器（`compile(&["x.proto"], out_dir)`、`Config`），不需要
    `protoc`。service 生成 `only-grpc` 桩代码：`<service>_server` 中的 trait 与 `register`，以及
    类型化的 `<service>_client`；此时消息也实现 `only_grpc::codec::Message`。
  - 用 protoc 生成的黄金编码、与 prost 的差分（测试与 fuzz 目标 `protobuf_diff`），以及与 grpc-go
    自带的 route_guide / helloworld 生成代码双向互通（`tools/interop/grpc/run.sh`，新增
    `tools/protobuf-test`）做了验证。
- `only-grpc`：`Sink::send_message` 与 `ClientSink::send_message`（编码一个 `codec::Message` 后
  发送），以及重导出 `only_grpc::Headers`。

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

### 弃用

- `only-grpc` 的 `prost` feature（不在 semver 承诺之内）：仍可使用，请改用 `only-protobuf` /
  `only-protobuf-build`。它可能在某个 minor 版本中移除。

### 修复

- `only-ws`：每个 WebSocket 连接都带着约 2 KB 内联的 permessage-deflate 状态（`Option` 中的
  only-deflate inflater 与 deflater），即使没有协商压缩；现在状态改为装箱。升级 + 一次 echo 之后的
  空闲连接：3,486 → 1,426 字节。
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
