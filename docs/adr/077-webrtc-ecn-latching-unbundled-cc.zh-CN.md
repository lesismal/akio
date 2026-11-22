# ADR-077：ECN 可用的 RTP、无 ICE 媒体的锁定，以及无 BUNDLE 时跨传输的拥塞控制

[English](077-webrtc-ecn-latching-unbundled-cc.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-072 与 ADR-073 在 akio-webrtc 的"尚未完成"列表中留下三项：

- **发送 ECN 可用的包。** RFC 8888 报告携带每个包到达时的 ECN 码点，估计器把 CE 按丢包计（ADR-073），
  但本端从不标记：`Rtc` 的输出不带码点，`Endpoint` 通过不带控制消息的 `UdpBinding::send_to` 发送。
  akio-quic 已经能标记并验证 ECN（ADR-013 / ADR-035，`Conn::send_segments_ecn`，`IP_TOS` /
  `IPV6_TCLASS`），也就是说套接字层只为连接提供了这一能力，绑定的套接字没有。
- **普通媒体的锁定。** 无 ICE 的传输（ADR-072，`enable_ice(false)`，SIP 风格）发往远端描述的 `c=` 地址与
  `m=` 端口，端点也只把来自那里的数据报交给 peer。位于 NAT 之后的话机写出的是私有地址，无法到达；它的包
  从 NAT 的映射地址到来，没有东西会路由它们：双向都没有媒体。SIP 网关用对称 RTP / "comedia" 锁定解决这一
  问题（RFC 7362）。
- **无 BUNDLE 时的传输级拥塞控制。** ADR-072 从不做 BUNDLE 的会话中去掉了 transport-cc 与 RFC 8888，所以
  每段一个传输的会话不运行估计器、探测与 pacing。

约束：对浏览器和 pion 默认不变；除非配置，线上没有变化（不做 BUNDLE 的会话重新协商拥塞控制反馈除外）；
做 BUNDLE 的会话热路径上不增加工作。

## 决策

### 1. ECN 可用的 RTP（`RtcConfig::set_ecn_marking`，`rtc/ecn.rs`）

- **可选开启**：`EcnMarking::{Off（默认）, Ect0, Ect1}`。ECT(1) 是 L4S（RFC 9331）与 libwebrtc 使用的；
  ECT(0) 是经典 ECN（RFC 3168，RFC 6679 的默认值）。只有在使用 RFC 8888 反馈（双方协商：它报告到达时的
  码点，验证需要它；传输层反馈不报告）且带宽估计器运行时（标记的流量必须响应 CE，RFC 3168 §5，响应者就是
  估计器）路径才会标记。
- **标记什么**：只标记 RTP——媒体、重传、FEC、填充与探测。从不标记 RTCP（RFC 6679 §7.2 与 §7.3.1
  "SHALL NOT"）、STUN、DTLS 或 SCTP：WebRTC 对 SCTP 的用法中数据通道没有 ECN 响应（RFC 8831 不使用 SCTP
  的 ECN；ADR-042），而没有响应者的标记正是 RFC 3168 所禁止的。
- **启动**（RFC 6679 §7.2.1，以 RFC 8888 作为反馈）：在不知道标记能否到达时，每四个 RTP 包标记一个
  （"一小部分"）。发送的包按 SSRC 与序号连同其码点记住（最近 2048 个），每个 RFC 8888 报告条目在估计器
  看到结果之前与之匹配。十个已标记包被报告带着标记（或 CE）到达，且丢失的不超过其四分之一，路径即通过
  验证（单播的"暂定成功"）：此后每个 RTP 包都标记。
- **失败**（RFC 6679 §7.4）：一个已标记包被报告到达时没有其标记（被清除为 Not-ECT，或 ECT(1) 被改写为
  ECT(0)），该路径立即停止标记；已标记包无法到达（丢失十个、一个也没收到）时同样如此，或在有十六个已标记
  结果后，已标记包的丢包率超过一半并且超过未标记丢包率的三倍再加 10 %。路径处于可用状态时，64 个已标记
  结果的窗口中丢失超过一半会让路径回到启动阶段，重新比较已标记与未标记的丢包（§7.4.1）。失败的路径保持不
  标记（RFC 建议完全使用失败后停用）；新的路径（ICE 地址对、锁定的地址）重新开始。无法读取码点的接收端报告
  Not-ECT，在它报告的第一个已标记包之后标记即停止。
- **按路径**：每个传输（ADR-072）有自己的状态，随传输一起换入；RFC 8888 报告按每个 SSRC 所属的传输拆分。
- **CE**：像 ADR-073 那样按丢包交给估计器（`PacketResult::ecn`）；基于丢包的控制的阈值（2 % 到 10 % 之间
  保持，以上下降）作用于 CE 的比例。这是经典响应；未实现可伸缩（L4S）响应。
- **套接字**：`Output::Transmit` 携带码点；hub 用新增的 `UdpBinding::send_to_ecn`（一次带 `IP_TOS` /
  `IPV6_TCLASS` 控制消息的 `sendmsg`；Linux 上是新增的 `akio_sys::send_to_ecn`，macOS 原本就有）发送已标记
  的数据报，在 `RtcServer` 的连接上用 `Conn::send_segments_ecn`。未标记的数据报走原来的调用。
  `AKIO_UDP_ECN=0` 像对 QUIC 那样关闭码点；TURN 中继与 ICE-TCP 不带码点（于是报告显示 Not-ECT，路径转为
  不标记）。
- **统计**：`PeerStats` 新增 `ecn_marked_sent`、`ecn_failures` 与 `ecn_state`。

### 2. 无 ICE 媒体的锁定（`RtcConfig::set_latching`，`rtc/latch.rs`）

- **可选开启**：`Latching::{Off（默认）, Once, Rebind(Duration)}`。`Once`：第一个通过认证的包的来源永久
  成为远端（如果它就来自 SDP 地址，也包括 SDP 地址）。`Rebind(quiet)`：先是第一个，之后在已锁定的来源
  `quiet` 时间内没有发送任何通过认证的包时，可移到另一个通过认证的来源（NAT 重新绑定、话机切换网络）；
  `Duration::ZERO` 跟随每个来自新来源的通过认证的包。
- **以 SRTP 认证为门槛。** 来自任何 peer 都不认识的地址的数据报，只有 RTP 或 RTCP 才会交给仍可锁定、并且在
  该数据报到达的本地地址上的 peer（在 hub 注册；`Once` 的 peer 在每个组件都锁定后离开列表；每个数据报最多
  64 个 peer，从上次停下的位置开始）。peer 用每个传输的 SRTP / SRTCP 密钥去验证；只有标签验证通过、且 SRTP
  的重放窗口接受的包才被采用（并像平常一样接收）。因此伪造的包只花费每个开放 peer 一次 HMAC，不起作用；已
  收到的包的副本无法通过重放检查，所以不在路径上的攻击者无法移动媒体（在路径上的攻击者本来就可以）。包所属
  ICE 组件的地址对移到其来源（`IceAgent::set_fixed_pair`，它发出选中地址对变化：估计器与 ECN 在新路径上
  重新开始）；不复用 RTCP 时，RTCP 由它自己的 SRTCP 单独锁定。端点把新来源路由给该 peer，并忘掉之前锁定的
  地址（从不忘掉描述中的地址）。
- **重新 offer** 若重复某组件的 SDP 地址，保留已锁定的地址对；新的地址让该组件的锁定重新开始。
- **限制**：SRTP 密钥存在之前不会锁定：使用 DTLS-SRTP 时，握手需要 SDP 中的地址（SIP 场景所用的 SDES 一开始
  就有密钥）。锁定只用于无 ICE 的传输；有 ICE 时，连通性检查与 peer-reflexive 候选已经做到这一点。
- **统计**：`PeerStats::latched` 计数移动次数。

### 3. 无 BUNDLE 时跨传输的拥塞控制（`rtc/cc.rs`）

- **重新协商**：transport-cc 与 `ack ccfb` 保留在不做 BUNDLE 的会话的每一行上。
- **RFC 8888** 按 SSRC 报告：每个传输有自己的接收端（其报告从该传输发出，内容是它承载的流），发送记录属于
  会话，从任何传输到来的报告按每个 SSRC 所属的传输拆分（用于按路径的 ECN）。
- **传输级序号**有两种约定。草案按传输为包编号；libwebrtc 按 peer 连接编号——其 `PacketRouter` 中一个计数器
  覆盖所有传输，一个反馈生成器——Chrome 157 证实了这一点（`tools/interop/webrtc/bundle.sh`：服务端把
  Chrome 在三个传输上的编号识别为一个空间）。两者混用会在两个方向上都破坏反馈：按传输的接收端会把发往其他
  传输的序号报告为丢失，按连接的接收端会看到两个空间相撞。所以会话跟随远端的编号方式，从远端发送的包中判断
  （`Spaces`）：同一序号到达两个传输，或序号相差超过 1024，属于不同空间；一个序号的前一个序号到达了另一个
  传输，则属于同一空间。在远端表现出不同空间之前，会话在一个空间中编号，并用一个接收端确认所有传输（这正是
  libwebrtc 发送和期望的，所以只接收的 Chrome 也能工作）；一旦表现出来，每个传输得到自己的发送端与接收端，
  随传输状态一起换入，反馈按传输在其上发送，并且每个传输的编号从共享空间停下的位置继续（远端接收端不能看到
  序号倒退）。因此按传输编号只用于按传输编号的远端（草案的模型）；在两个本协议栈之间以及与浏览器之间，编号
  是共享的。
- **一个估计器覆盖多个空间**（`Merge`）：按传输的结果带着各自时钟锚点上的到达时间，按传输到来、不按发送
  顺序。它们会被对齐（每个传输的到达时间相对于其最小单向时延，所以共享瓶颈的传输之间排队时延可以比较），
  保留到每个有在途包的传输都报告到它们的发送时间（最多 300 ms），再按发送顺序重新编号后交给估计器。RFC 8888
  的结果共享远端的报告时钟，只需排序。共享编号不需要这些。
- **一个 pacer**：排队的包记住其传输并从那里发出（`Queued::tp`）；填充与探测从承载它们的流的传输发出；重传
  从其所属行的传输发出。收到的 RTP 用传输自己的头部扩展映射解析。
- **统计**：`PeerStats::twcc_spaces`（"unknown"、"shared"、"per-transport"；BUNDLE 时为 `None`）。

### API

只有新增。akio-webrtc：`EcnMarking`、`Latching`、`RtcConfig::{set_ecn_marking, set_latching}`。
akio-core：`UdpBinding::send_to_ecn`（`#[doc(hidden)]`，与 `Conn::send_segments_ecn` 一样不在稳定性承诺内）。
akio-sys：Linux 上的 `send_to_ecn`（macOS 原本就有）。

## 后果

- 做 BUNDLE 的会话、浏览器与 pion 的默认行为不变。不做 BUNDLE 的会话现在协商 transport-cc / RFC 8888，并在
  估计器打开时运行估计器、探测与 pacing。
- 测试：模拟网络（`rtc/tests_ecn.rs`）：保留标记的路径通过验证（开始时标记四分之一的包，然后全部；从不标记
  RTCP、STUN 或 DTLS），清除或改写标记的路径在少量探测后失败并停止标记，CE 标记到达估计器而不使路径失败，
  没有 RFC 8888 或关闭时不标记；网关锁定位于模拟 NAT 之后的话机（复用与不复用 RTCP，RTCP 单独锁定），不锁定
  时没有媒体，伪造与重放的包不移动任何东西，NAT 重新绑定按 `Once` / `Rebind(500 ms)` / `Rebind(0)` 被跟随
  或不被跟随；共享与按传输编号的无 BUNDLE 会话（双向识别）以及按传输验证 ECN 的 RFC 8888；编码器跟随估计
  的情况下经 800 kbps 瓶颈的单一估计：BUNDLE、无 BUNDLE 共享编号、无 BUNDLE 按传输编号三者相互在
  0.6-1.4 倍之内（一次运行中 656 / 657 / 697 kbps）。ECN 状态机、锁定策略、编号识别与合并的单元测试；Linux 上
  `akio_sys::send_to_ecn` 的测试（IPv4 与 IPv6，每个码点）。回环上的 Endpoint（`tests/ecn_latch.rs`）：标记
  经内核套接字到达且路径通过验证，应答写着无人监听端口的话机通过锁定被找到（不锁定则找不到），无 BUNDLE
  时估计值随两个传输的反馈上升。
- 互通：headless Chrome 157（`tools/interop/webrtc/ecn.sh`，RFC 8888 字段试验）：Chrome 把收到的视频包计为
  带 ECT(1)（`packetsReceivedWithEct1` 1015 个中 946 个；其余在验证之前到达，或是未标记包的 RTX），其 RFC 8888
  报告使路径通过验证；经 fec-server 的 UDP 代理（会清除码点）时，路径在一个已标记包后失败，视频继续（199 帧中
  解码 199 帧）。Chrome 自己发出的包都不带 ECN。`bundle.sh`：`bundlePolicy: "max-compat"` 的 Chrome（三个
  传输）把服务端的估计值从 300 kbps 推到 19.9 Mbps，编号共享。网络命名空间中位于 iptables MASQUERADE NAT
  之后的 SIP 风格话机（`tools/interop/webrtc/latch.sh`，Docker）：不锁定时话机收不到任何回声；`Once` 时网关
  锁定 NAT 的映射（移动一次），100 个包返回；重新绑定之后（删除话机的 conntrack 条目，NAT 另选一个随机端口），
  `Once` 停止回声，而 `Rebind(1 s)` 跟随新的映射（移动两次），300 个包返回。pion 总是做 BUNDLE，也没有普通
  模式：`run.sh` 不变地通过，Chrome 的 `browser.sh` 也是。
- 性能：在 gpu51 上与 main 04a32fb5 的同轮 A/B（`quiet.sh`，CPU 2-9，交替，取中位数；新示例 `webrtc-bench`，默认配置）：两个回环 `Endpoint` 之间单向 VP8 RTP 177.8 对 178.0 MB/s（0.999 倍，7 轮）；单个数据通道 154.8 对 156.3 MB/s（0.990 倍，7 轮）以及 155.9 对 157.0 MB/s（0.993 倍，11 轮，分支先跑）：数据通道慢约 1 %，处于波动范围边缘（区间重叠）；其路径只多了每个输出数据报一个码点字节与每个收到数据报的两次标志检查。
- 代价：开启 ECN 时，每发送一个 RTP 包一个哈希表项（最近 2048 个），每个已标记数据报一次带控制消息的
  `sendmsg`；开启锁定时，来自未知来源的数据报对每个开放 peer 做一次 SRTP 标签检查；无 BUNDLE 时有按传输的
  反馈状态，按传输编号时结果为排序最多保留 300 ms。
- 未做：对 CE 的可伸缩（L4S）响应（CE 按丢包计）；RFC 6679 自身的信令（`a=ecn-capable-rtp`、RTCP ECN 反馈
  消息、XR ECN 摘要）以及使用传输层反馈时的 ECN（其中没有码点）；在失败的路径上重试 ECN；DTLS-SRTP 密钥就绪
  前的锁定；经 TURN 中继与 ICE-TCP 的标记；按传输编号时，发送端使链路过载且不理会估计值时估计器的表现（模拟的
  800 kbps 链路上不管估计值持续发送 1 Mbps，结束在 30 kbps 下限，而 BUNDLE 时为 63-187 kbps，三种模式在那里都
  很混乱）。
