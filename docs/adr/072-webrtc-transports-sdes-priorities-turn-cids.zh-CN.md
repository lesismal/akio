# ADR-072：无 BUNDLE 或无 ICE 的传输、SDES 变体、数据通道优先级与 TURN DTLS 连接 ID

[English](072-webrtc-transports-sdes-priorities-turn-cids.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

此前的工作在 akio-webrtc、akio-turn 与 akio-ice 中留下了 DEV-PLAN 标为未完成的缺口：

- **数据通道优先级与 SCTP 流调度器**（ADR-037）：akio-sctp 已实现 RFC 8260 调度器与 RFC 8832
  通道优先级，但 akio-webrtc 两者都未暴露：每个通道的 DCEP 优先级都是 256，关联固定使用加权公平
  排队，无法给通道分配权重。
- **每个会话只有一个传输**（ADR-058）：本栈只运行一个 ICE 代理、一个 DTLS 关联和一对 SRTP 上下文。
  不做 BUNDLE 的对端（带音频和视频的 SIP 终端，以及 `bundlePolicy: "max-compat"` 的浏览器遇到拒绝
  BUNDLE 的应答时）无法服务，因此不带 rtcp-mux 的会话只能有一个段且没有数据通道。
- **组件 2**（不带 rtcp-mux 的 RTCP）只有主机候选与对端反射候选，`RtcServer`（单个监听器上的
  ICE-lite）没有组件 2。
- **SDES-SRTP**（ADR-054）必须有 ICE，不接受带 MKI 的行，也不允许数据通道。
- **基于 DTLS 的 TURN**（ADR-054）以五元组标识客户端：NAT 重新绑定就会丢掉关联及其分配。
- **akio-ice** 没有导出 IPv6 mDNS 组，也无法给解析出的链路本地候选指定接口。

约束：默认情况下浏览器与 pion 看到的内容与之前一致；另一个会话同时在修改 akio-rtp 以及
akio-webrtc 的 pacing / FEC / RED / 反馈代码，因此对 `rtc.rs` 的修改是挂钩而非重写；public 层级的
API 不得暴露 internal 层级的类型。

## 决定

### 1. 数据通道优先级与调度器

`ChannelPriority`（`VeryLow`、默认的 `Low`、`Medium`、`High`；DCEP 值 128 / 256 / 512 / 1024，
即 RFC 8831 §6.4 与 W3C 的映射）放在 `ChannelConfig::priority`（`with_priority`）中，随 DCEP 打开
消息发送；对端打开的通道的优先级取自其消息（取最接近的级别；0 视为 low）。`Peer::channel_priority`
与 `Peer::set_channel_priority`（只影响本端调度器：DCEP 没有更新消息）。`ChannelScheduler`（先来先服务、
轮询、按包轮询、优先级、公平容量、默认的加权公平排队）由 `RtcConfig::set_sctp_scheduler` 选择。两者都在
crate 内映射到 akio-sctp 的类型。

### 2. 无 BUNDLE 时的多个传输

- **何时。** 满足以下任一条件时会话不做 BUNDLE：我方首个 offer 使用
  `RtcConfig::set_bundle_policy(BundlePolicy::Disabled)`；首个远端 offer 没有 `a=group:BUNDLE`
  （或我方禁用了 BUNDLE：此时我方应答拒绝该组，RFC 9143 §7.3.3）；我方首个 offer 的应答没有带上我方的组。
  该决定只做一次；之后的描述若让已建立的 BUNDLE 会话停止 BUNDLE，将被拒绝。
- **什么。** 每个使用中的段有自己的传输：一个 ICE 代理（角色、选项和候选从主传输复制）、一个 DTLS
  关联、SRTP 上下文、SDES 密钥和 RTCP 组件（不带 rtcp-mux 的媒体段两个组件，应用段一个）。DTLS 角色、
  证书与远端指纹属于会话。我方的段带有其传输的凭据和候选，不带组。凭据：主传输的 ufrag 后接传输序号，
  加上自己的密码，这样端点 hub 能凭 ufrag 前 8 个字符找到对端；若应答拒绝了我方的 BUNDLE offer，则使用
  主传输自己的凭据（我方 offer 给每个段的就是它）。
- **怎么做。** `Rtc` 中每个传输各自的字段（`ice`、`dtls`、SRTP 上下文、SDES 状态、RTCP 组件、首个
  DTLS 来源、等待中的 mDNS 候选）组成传输状态，`Rtc::with_tp` 把传输 `k` 的状态换入、运行现有代码、再换
  回。非当前的传输总是那张旁表中的那些。入口按需重定向或分发：数据报经解复用，定时器分给每个传输，媒体
  走其所在行的传输，RTCP 走发送它的 SSRC 所在行的传输（第一个包的发送方 SSRC），SCTP 走应用段的传输。
  ICE 状态按 W3C 规则聚合（任一 disconnected；否则全部 new；否则任一 new 或 checking；否则全部
  completed；否则 connected）；所有传输都有了密钥后才报告一次 `Connected`。
- **解复用。** 连通性检查交给其 USERNAME 中 ufrag 所指的传输；多个传输共享 ufrag 时，以及其他所有数据
  报，交给拥有数据报到达的本地地址的传输（传输各有套接字时），否则交给其选中对、远端候选或首个 DTLS
  数据报的来源与之相同的传输。因此同一套接字上的多个传输靠远端地址区分，所有不做 BUNDLE 的对端都满足
  这一点（每个段一个 ICE 代理或端口）。
- **每个传输一个套接字。** `Endpoint::bind_transport_socket` 绑定更多套接字；第一个之后的第 n 个传输
  使用第 n 个套接字的主机候选，这样两个 akio 端点也能不做 BUNDLE（一方有即可）。每个传输的组件 2
  仍在 RTCP 套接字上。
- **限制。** 传输级拥塞控制需要单一传输：不做 BUNDLE 的会话不协商 transport-cc 与 RFC 8888 反馈
  （事后协商到的也会移除），因此那里既不做带宽探测也不运行估计器。trickle 候选用
  `Peer::add_remote_candidate_in(mid, ..)` 指明其段。

### 3. 组件 2：服务器反射与中继候选，`RtcServer`

- `Endpoint::gather_srflx` 也会从 RTCP 套接字（需事先绑定）询问，并添加组件 2 的服务器反射候选；
  两个应答都要收到。`gather_relay(_via)` 从 RTCP 套接字再做一次分配（每个中继知道自己是否属于组件 2：
  套接字、base、候选组件）；两者都须成功；每个组件最多四个分配。来自 TURN 服务器的数据报按其到达的
  套接字匹配到对应中继。
- `RtcServer::rtcp_candidates(addrs)` 为由 `RtcServer::rtcp()`（`RtcRtcp`）服务的第二个 UDP 监听器添加
  组件 2 主机候选：其连接与主监听器的连接分开保存，组件 2 候选发出的数据从这些连接发出（一个无锁标志
  让没有 RTCP 监听器的服务器保持原路径）。

### 4. SDES：无 ICE、MKI、与数据通道并存

- **无 ICE。** `RtcConfig::enable_ice(false)` 让我方描述变为普通形式：没有 ICE 属性与候选，`c=` 写
  首个主机候选的地址，`m=` 写其端口，不带 rtcp-mux 时 `a=rtcp` 写组件 2 的端口和地址。不论该设置如何，
  没有 `a=ice-ufrag` 的远端描述都按这种方式处理。此时 ICE 代理获得固定候选对（新增的
  `IceAgent::set_fixed_pair`）：从我方与远端同地址族的主机候选到 `c=` 地址和 `m=` 端口，组件 2 到
  `a=rtcp`（或下一个端口；带 rtcp-mux 时为同一端口）。代理不做检查、consent 或定时器，立即为
  `Completed`。端点在对端发送任何东西之前就把来自这些地址的数据报路由给它（hub 通过
  `Rtc::take_plain_remotes` 得知这些地址）。SDP 层现在读写 `c=` 行（未指定地址表示“无”）。普通传输
  同样可用于 DTLS-SRTP。
- **MKI。** 接受带 `|<值>:<长度>` 的 `a=crypto` 密钥参数（1..=128 字节，RFC 4568 §9.1）、以 `;` 分隔的
  多个主密钥（必须都带同一长度且取值互异的 MKI）、生命期（接受但不强制）以及 `WSH=` 窗口大小提示；其他
  会话参数（`KDR=`、`UNENCRYPTED_*`、`FEC_*`）仍使该行不可用。SRTP 上下文获得全部主密钥
  （`Context::new_with_mki` 与 `add_master_key`），以第一个发送。我方应答的密钥带与 offer 相同长度的
  MKI；`RtcConfig::set_sdes_mki_length` 让我方 offer 带 MKI。
- **与数据通道并存。** 应用段带 `a=fingerprint` 与 `a=setup`（媒体段只带 `a=crypto`）；DTLS 在同一传输
  （无 BUNDLE 时为应用段自己的传输）上运行，只承载 SCTP：其 SRTP 密钥被忽略，媒体仍由 SDP 中的密钥
  加密，SCTP 在 DTLS 握手完成后才启动（对端更早就凭 SDP 密钥与 ICE 对进入已连接）。

### 5. 基于 DTLS 的 TURN 监听器上的连接 ID

`TurnServer::dtls` 要求客户端使用 8 字节连接 ID（DTLS 1.2 为 RFC 9146，1.3 为 RFC 9147 §9；需协商，
不支持的客户端不受影响）；`TurnServer::dtls_with_connection_ids` 可设置其他长度或关闭。监听器为其关联
的有效 CID 建立索引（有上限）。来自一个没有自身关联的五元组、而其 CID 指向某个关联的数据报，会交给该
关联；一旦其中某条记录通过认证（解出了应用数据记录），客户端的路径就移到这个五元组（RFC 9146 §6）：
响应和中继数据发往那里，而分配仍以关联最初的地址作为身份，因此不会在分片之间迁移。伪造或重放的记录
不会移动任何东西。持有路径的连接记录在会话中，因此除非路径移动，数据报不需要额外获取分片锁。
akio-webrtc 的 DTLS 中继客户端在服务器要求时发送服务器的 CID。

### 6. akio-ice

在 `MULTICAST_V4` 旁新增 `mdns::MULTICAST_V6`（`[ff02::fb]:5353`）与 `mdns::multicast_v6_on(scope)`；
`Candidate::with_scope_id(scope)` 为 IPv6 链路本地候选（地址，以及与地址相同时的 base）指定接口；SDP
中从不出现。akio-webrtc 保持其设计（ICE 之前去掉 scope id，由 hub 记住），并使用 `multicast_v6_on`。

### API

均为新增。akio-webrtc：`ChannelPriority`、`ChannelScheduler`、`ChannelConfig::{priority,
with_priority}`、`RtcConfig::{set_sctp_scheduler, set_bundle_policy, enable_ice,
set_sdes_mki_length}`、`BundlePolicy`、`Peer::{channel_priority, set_channel_priority,
add_remote_candidate_in}`、`Endpoint::bind_transport_socket`、`RtcServer::{rtcp_candidates, rtcp}`、
`RtcRtcp`。akio-turn：`TurnServer::dtls_with_connection_ids`。akio-ice：
`mdns::{MULTICAST_V6, multicast_v6_on}`、`Candidate::with_scope_id`、
`IceAgent::{set_fixed_pair, is_fixed}`。`ChannelConfig` 带 `#[non_exhaustive]`，新增字段不构成破坏。

## 后果

- 对浏览器与 pion 默认行为不变：提供并接受 BUNDLE、ICE 开启、DCEP 优先级 256、加权公平排队。有两处
  行为变化：没有 `a=group:BUNDLE` 且有多个段的远端 offer 现在以每段一个传输应答（此前的应答带一个 offer
  从未要求的 BUNDLE 组，无法工作）；TURN DTLS 监听器与提供 CID 的客户端协商 CID。
- 测试：模拟网络（`rtc/tests_transports.rs`）：优先级到达对端，优先级调度器先服务高优先级通道，提高的
  优先级生效，加权公平排队与轮询按配置分配；三个传输（音频、视频、数据）各在自己的地址对上，各自运行
  DTLS，媒体传输上有 RTP / RTCP，检查只在传输内部，只有一次 `Connected`；拒绝 BUNDLE 的应答使 offer 方
  在单个套接字上拆分；不带 BUNDLE 也不带 rtcp-mux 的音视频（四个组件，RTCP 各在组件 2 上）；无 ICE、
  RTCP 独立端口的 SDES（没有 STUN 或 DTLS，RTP 与 RTCP 在各自端口对上）；手写的带 rtcp-mux 与 2 字节
  MKI 的 SIP offer；双向带 MKI 的 SDES；与数据通道并存的 SDES 媒体。回环上的 Endpoint：双向无 BUNDLE
  （数据通道、音视频回显；`tests/bundle.rs`），带 MKI 与 RTCP 套接字的无 ICE SDES，带数据通道的 SDES
  （`tests/sdes.rs`），经 akio-turn 中继候选的 RTCP（四个分配），组件 2 服务器反射候选，带 RTCP 监听器
  的 ICE-lite `RtcServer`（`tests/rtcp_mux.rs`）。akio-turn（`tests/dtls.rs`）：关联中途换到新套接字的
  客户端在 DTLS 1.2 与 1.3 下都保留其分配，带 CID 的伪造记录不移动路径，新地址发出的 close_notify 释放
  分配，关闭 CID 时不协商。akio-ice：固定候选对（事件、状态、无任何运行、移动候选对）、scope id、IPv6 组。
  `a=crypto` MKI 解析、`c=` 行、普通地址与状态聚合的单元测试。
- 互通：无头 Chrome 157（`tools/interop/webrtc/bundle.sh`）：`bundlePolicy: "max-compat"` 的 Chrome 向
  拒绝 BUNDLE 的 `RtcServer` 提供音频、视频与数据通道时运行三个传输（见其统计），数据与媒体回显并解码；
  akio `Endpoint` 不带 BUNDLE 提供音频和一个通道时，经两个传输收到 Chrome 的麦克风。Chrome 157 没有
  `RTCDataChannel.priority`（发送 256），pion 总是 BUNDLE 且发送 256，因此优先级只在 akio 对端之间验证；
  pion 脚本（`run.sh`）与 Chrome 脚本（`browser.sh`）未经修改全部通过。
- 模糊测试：新目标 `webrtc_sdes`（`a=crypto` 值往返一致并能建立上下文）；`webrtc_sdp` 还尝试带 MKI 的
  无 ICE SDES 与协商 RTCP 的无 BUNDLE 配置，并检查密钥从不与指纹同段、对无 ICE offer 的应答不带 ICE、
  禁用的 BUNDLE 从不出现、没有任何段同时带 `a=rtcp-mux` 与 `a=rtcp`；新增种子。Linux arm64 上：`webrtc_sdes`
  15 分钟 3100 万次运行，无问题；`webrtc_sdp` 发现两个缺陷，均已修复并保留为回归输入（所有提供的段都被拒绝时，
  禁用的 BUNDLE 被写成空组；应用段占用了某个媒体行的 mid，导致该媒体行运行在数据通道的传输上）；修复后 15 分钟 17 万次运行，无问题。
- 性能（gpu51 上与 57696b6b 的同轮 A/B，`quiet.sh`，CPU 2-9，7 轮交替，取中位数）：两个回环 `Endpoint`
  之间的 RTP 媒体 92.1 对 92.1 MB/s（1.000 倍），数据通道 189.7 对 189.7 MB/s（1.000 倍），经监听器与中继
  的 DTLS 上的 TURN 230,804 对 231,015 数据报/秒（1.001 倍；100 字节 ChannelData，CID 路径开启）：无回退。
- 代价：不做 BUNDLE 的会话每个段运行一个 ICE 代理、一次 DTLS 握手与 consent 检查；交换状态是每次重定向
  调用的少量字段移动（BUNDLE 会话中没有：每个挂钩先检查空表）。TURN DTLS 监听器为每个有效 CID 保存
  一个索引项。
- 未完成：锁定普通媒体实际来源地址（NAT 后的对称 RTP）；我方也在单个套接字上时，远端从同一地址为多个
  传输发送；跨传输的传输级拥塞控制；`WSH` 以外的 SDES 会话参数；usrsctp（Firefox）的优先级。
