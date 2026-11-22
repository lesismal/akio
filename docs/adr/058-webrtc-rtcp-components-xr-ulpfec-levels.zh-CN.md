# ADR-058：akio-webrtc 中 RTCP 走独立 ICE 组件、XR 接收块与 ULPFEC 保护级别

[English](058-webrtc-rtcp-components-xr-ulpfec-levels.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

下层已实现的两组功能此前无法在对端连接中使用：

- **ICE 组件**（ADR-055）：`akio_ice::IceAgent` 已能处理多组件数据流，但 akio-webrtc 始终在组件 1
  上复用 RTP 与 RTCP（rtcp-mux、BUNDLE）。不提供 `a=rtcp-mux` 的对端（SIP 终端、较老的 RTP 栈：
  RFC 5761 允许它们在单独端口发送 RTCP，并以 RFC 3605 的 `a=rtcp` 指明）仍会收到带
  `a=rtcp-mux` 的应答，其 RTCP 永远到不了。
- **akio-rtp**（ADR-053）：由 `ReceiptLog` 生成的 XR 丢包 RLE、重复 RLE 与包接收时间块，
  `BurstLossModel::report` 给出的完整 VoIP 指标，ULPFEC 保护级别（`FecEncoder::set_ulp_level0`），
  类型化 SDES 项（`SdesItem`）与 RFC 7022 CNAME（`random_cname`）。对端此前只发送 XR 接收方参考
  时间 / DLRR，忽略收到的 SDES，CNAME 是自定字母表的 16 字符随机串。

约束：浏览器与 pion 看到的内容必须与之前完全一致（默认仍为 rtcp-mux、BUNDLE，不新增属性）；公共 API
（public 层级）不得暴露 internal 层级类型；只改 akio-webrtc（akio-ice 与 akio-rtp 无需改动）。

## 决定

### 1. RTCP 走 ICE 组件 2

- **RTCP 套接字。** `Endpoint::bind_rtcp(engine, addr)` 在端点的 hub 上绑定第二个 UDP 套接字；其主机
  候选（组件 2，`Candidate::with_component(2)`，与组件 1 共享 foundation）交给新建的对端。
  `Endpoint::rtcp_addr` 返回其地址。组件 2 候选发出的数据报从这个套接字发出（按候选 base 的地址匹配，
  套接字绑定在未指定地址时按端口与地址族匹配）；收到的数据报与其他数据报一样路由（先按源地址，再按 ICE
  用户名）。组件 2 只有主机候选与 peer-reflexive 候选：RTCP 的 server-reflexive 与中继候选需要每个端点
  再做一次 STUN 查询和一次 TURN 分配，未实现。`RtcServer`（单监听端口、ICE-lite）没有组件 2。
- **自己发出的 offer 的策略**：`RtcConfig::set_rtcp_mux_policy(RtcpMuxPolicy)`。`Require`（默认）
  只提供 `a=rtcp-mux`，与以前及浏览器一致。`Negotiate` 同时提供 `a=rtcp-mux` 与
  `a=rtcp:9 IN IP4 0.0.0.0` 以及组件 2 候选（RFC 5761 §5.1.1，JSEP 的写法），由应答决定。`Off` 不写
  `a=rtcp-mux`（会话一开始就有两个组件），需要 RTCP 套接字（否则 `apply` 失败）。
- **对方的 offer** 无论策略如何都会应答：第一个在用的音频或视频段有 `a=rtcp-mux` 时（所有浏览器、pion）
  用 rtcp-mux；没有且端点有 RTCP 套接字时，RTCP 走组件 2；没有 RTCP 套接字时，照旧以 rtcp-mux 应答
  （现有部署不受影响）。对 `Negotiate` offer 的应答若没有 `a=rtcp-mux`，offer 方切换为两个组件。
- **单一传输。** BUNDLE 依赖 rtcp-mux（RFC 8843 §9.1），而本栈只运行一个 ICE 代理、每个组件一个 DTLS
  关联、一对 SRTP 上下文：不复用 RTCP 的会话只有一个在用的段，且没有数据通道。超出的描述或变更会被
  明确拒绝（多段且无 rtcp-mux 的 offer、对 `Negotiate` offer 去掉 rtcp-mux 且多段的应答、带数据通道的
  `Off`、往这种会话里加媒体）。此时我方描述中不写 `a=group:BUNDLE`。
- **代理只切换一次。** 对端起始时是单组件代理（默认行为逐字节不变）；第一次协商决定使用两个组件时，
  用相同的凭据、角色、选项与候选（再加上组件 2 的候选）重建代理——在加入远端描述的候选之前，因此尚未
  做过任何检查。之后的描述保持组件数（RFC 5761 §5.1.3：复用不因重新 offer 而切换）；ICE 重启覆盖两个
  组件（ADR-055）。
- **密钥。** DTLS-SRTP 每个组件各做一次握手（RFC 5764 §4.1），角色都按 `a=setup`，证书与指纹相同：
  组件 1 的密钥保护 SRTP，组件 2 的密钥保护 SRTCP（在组件 2 的选中候选对 `send_pair_of(2)` 上收发）。
  服务端角色的组件 2 握手在该组件收到第一个 DTLS 数据报时开始（ICE 选出候选对之前，回复发往其源地址）。
  SDES-SRTP 每个方向用同一个 `a=crypto` 密钥为两个组件加密（RFC 4568：主密钥同时用于该流的 SRTP 与
  SRTCP）。用组件 1 的 DTLS 密钥保护的 SRTCP 在组件 2 上不被接受。
- **已连接**表示所有密钥就绪且 ICE 为每个组件都选出了候选对：DTLS-SRTP 需两次握手完成，SDES 需 SDP
  密钥与两个候选对。`PeerStats` 新增 `rtcp_mux`。

### 2. 关于接收流的 XR 块

- `RtcConfig::enable_rtcp_xr_blocks(XrBlocks)`，`XrBlocks::{LOSS_RLE, DUPLICATE_RLE,
  RECEIPT_TIMES, VOIP_METRICS, ALL}`（用 `|` 组合）在每段一行 `a=rtcp-xr` 中提供并接受 RFC 3611 §5.1
  的格式 `pkt-loss-rle`、`pkt-dup-rle`、`pkt-rcpt-times`、`voip-metrics`（同时开启 `enable_rtcp_xr`
  时还带 `rcvr-rtt=all`）。双方都列出某格式时该行才发送这种块（带参数的格式也算，未知格式忽略）；VoIP
  指标只在音频行提供和发送。默认不开启：`a=rtcp-xr` 不变。
- **发送**：这类行的每个接收流维护一个接收日志（`RecvStream::enable_receipt_log`，每个区间 4096 个
  序号）。每个 RTCP 间隔（1 秒）发出关于上次报告以来各序号的块，单独组成一个复合包：先是该行发送方 SSRC
  的空接收报告，再是 XR（RFC 3550 §6.1 要求报告在前；单独的复合包让其他流的报告保持在 MTU 以内）。
  RLE 块抽稀（§4.1 的 T）到最多报告 1500 个序号，接收时间最多 96 个；XR 主体不超过 900 字节。VoIP 指标
  来自每个流一个的 `BurstLossModel`，用该区间的丢包轨迹喂入，再
  `report(ssrc, 20 ms, &VoipQuality { round_trip, .. })`：丢包、丢弃、突发与间隙字段是实测的；往返时间
  取自该流；只有编解码器和应用知道的质量字段（电平、R 因子、MOS、抖动缓冲）按不可用发送。FEC 重建的包
  计为丢失，与接收报告一致。
- **接收**：关于本端所发流的丢包 RLE、重复 RLE 与接收时间块，按每个 XR 包每个流产生一个 `XrReceipts`
  事件（收到、丢失、重复的序号数，报告的接收时间数），并在 `PeerStats` 中累计（`xr_received`、
  `xr_lost`、`xr_duplicated`）；VoIP 指标产生 `VoipMetrics` 事件。

### 3. ULPFEC 保护级别

`RtcConfig::set_ulpfec_level0(Some(l0))` 对每个 ULPFEC 编码器调用 `FecEncoder::set_ulp_level0`
（协商了 `red` / `ulpfec` 的行，包括 simulcast 各编码）：一帧的 FEC 包保护每个包的前 `l0` 字节，最后
一个再加一个覆盖其余部分的级别 1。默认 `None`：与以前一样整包 ULPFEC。SDP 中没有任何东西表明接收方能读
级别，而 libwebrtc 只读级别 0（Chrome 中长于 `l0` 的丢失包会被错误重建），因此它只用于对端也是本栈的
情况；文档中已注明。接收端无需改动：akio-rtp 的解码器能从任意多个级别重建包。

### 4. CNAME 与 SDES 项

- 对端连接的 CNAME 为 12 个随机字节的 `random_cname`（RFC 7022 §4.2：短期持久，96 位随机数的 base64），
  每个对端连接新生成（以前是 16 个随机字母数字，同样每个连接不同）。
- 收到的 SDES 块按源转为类型化的 `SdesItem`；某个源的项首次到达或变化时，`SourceDescription` 事件报告
  它们（最多记住 64 个源）。

新事件是 `Event::Other` 背后 crate 私有 `Other` 的变体（与现有统计事件一样，其结构不作承诺）。

### API

只有新增：`Endpoint::{bind_rtcp, rtcp_addr}`、`RtcConfig::{set_rtcp_mux_policy,
enable_rtcp_xr_blocks, set_ulpfec_level0}`、`RtcpMuxPolicy`（`#[non_exhaustive]`）、`XrBlocks`。
akio-ice 与 akio-rtp 无改动。

## 影响

- 测试（`crates/akio-webrtc/src/rtc/tests_mux.rs`，模拟网络与时间）：两个不复用 RTCP 的对端，
  DTLS-SRTP：无 `a=rtcp-mux`、有 `a=rtcp`、无 BUNDLE，组件 2 候选与组件 1 同 foundation、优先级少 1；
  两次握手；双向音频；RTP 只在组件 1 端口之间、RTCP 只在组件 2 端口之间、DTLS 两者都有；双方都有发送方
  报告与 RTT；用组件 1 密钥保护的 SRTCP 包在组件 2 上被拒、用组件 2 密钥保护的同一包被接受。`Negotiate`
  策略对复用的对端（一个组件，保留 BUNDLE，重新 offer 不带组件 2）与不复用的对端（两个组件）。不复用
  RTCP 的 SDES-SRTP（RTCP 在组件 2，没有 DTLS 数据报）。默认策略、浏览器 offer、发给没有 RTCP 套接字的
  对端的无 rtcp-mux offer 都照旧应答；各种拒绝。XR 协商（取交集，VoIP 指标仅音频，与 `rcvr-rtt` 并存）；
  在丢失 10 % 媒体的链路上的接收块与 VoIP 指标（丢包计数在范围内，VoIP 块中的丢包率与往返时间，统计中的
  累计）；未协商时不发送。RFC 7022 CNAME 与类型化 SDES 事件。`l0 = 120` 的 ULPFEC 在 8 % 丢包且无 NACK
  时：200 个三包帧中至少 180 个完整（与整包 ULPFEC 相差不超过 10 帧），字节数不到其 85 %。
- 集成测试（`crates/akio-webrtc/tests/rtcp_mux.rs`，两个带 RTCP 套接字的 `Endpoint` 经回环）：用
  DTLS-SRTP 和 SDES-SRTP 在两个组件上回送 Opus（发送方报告、`rtcp_mux: false`、统计中有 RTT）；
  `Negotiate` 与默认策略保持 rtcp-mux；端到端协商 XR 块（接收块、VoIP 指标与 SDES 事件）；组件 2 的
  检查从 RTCP 套接字发出。现有 akio-webrtc 测试不变且通过。
- 互通：浏览器与 pion 总是复用；pion/webrtc 只实现 `require` 策略，pion/ice 只有一个组件（ADR-055），
  因此没有不复用 RTCP 的 pion 检查。两组件的 ICE 层已与 libnice 验证（ADR-055）；默认对端的 SDP 不变，
  浏览器与 pion 脚本（`tools/interop/webrtc`）不受影响。
- 模糊测试：`webrtc_sdp` 还会用一个带组件 2 候选、`Negotiate` 策略、全部 XR 块与 ULPFEC 级别的配置尝试
  每个输入，并检查应答不会同时带 `a=rtcp-mux` 与 `a=rtcp`、无 rtcp-mux 时不带 BUNDLE、且恰在对端切换为
  两个组件后在用的段中带 `a=rtcp`；新增两个种子（一个 `Off` offer 及其应答）。在 gpu51 上运行 16 分钟：
  28.7 万次，代码中未发现问题（更早的一次运行发现目标中的检查过严：唯一的非复用段被拒绝时没有段可带
  `a=rtcp`；该输入保留为回归用例）。
- 代价：不复用 RTCP 的会话多一次 DTLS 握手和一路同意检查；带 RTCP 套接字的端点多占一个套接字。XR 接收块
  每个接收流需要一个最多 4096 项（每项 8 字节）的接收日志，每个流每秒一个复合包。
- 未完成：组件 2 的 server-reflexive 与中继候选；一个会话多个传输（无 BUNDLE），因此不复用 RTCP 的会话
  只有一个媒体段、没有数据通道；`RtcServer` 上的组件 2；需要编解码器的 VoIP 质量字段（电平、R 因子、
  MOS、抖动缓冲；此后已在 ADR-085 完成：按编解码器的 G.107 / G.107.1 估算，以及接收应用数值的
  `Peer::set_voip_quality`）；表明接收方能读 ULPFEC 级别的信令。
