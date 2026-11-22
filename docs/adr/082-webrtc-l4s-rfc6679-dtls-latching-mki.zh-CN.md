# ADR-082：可扩展（L4S）的 CE 响应、RFC 6679 信令、经中继的 ECN、锁定 DTLS 握手，以及 DTLS-SRTP 的 MKI

[English](082-webrtc-l4s-rfc6679-dtls-latching-mki.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-077 让 RTP 可以带 ECN，并为无 ICE 的媒体加入了锁定。它留下了以下几项：

- **CE 按丢包计。** 报告为 CE 的包在基于丢包的控制里算作一次丢包。这是经典响应（RFC 3168），ECT(1)
  流量得到的也是它。RFC 9331 §4.3 要求 ECT(1) 流量做出*可扩展*的响应。L4S 队列（RFC 9332）在包等待约
  1 毫秒时就会标记，因此经典发送端会退让到远低于链路速率的位置。
- **ECN 依赖 RFC 8888。** 验证与 CE 信号只来自 RFC 8888 报告。只实现 RFC 6679 本身的端点无法使用：它们用
  `a=ecn-capable-rtp`、RTCP ECN 反馈消息和 XR ECN 摘要。这类端点包括 SIP 协议栈，以及用传输级反馈做拥塞
  控制的对端。
- **TURN 与 ICE-TCP。** 经中继时不发送码点。在 TCP 路径上，接收端于是报告 Not-ECT，路径在几次探测后被判
  为"失败"。
- **锁定依赖 SRTP 密钥。** 使用 DTLS-SRTP 且没有 ICE 时，握手需要先知道远端地址。NAT 之后的话机，按它 SDP
  里的私有地址永远无法到达。
- **DTLS-SRTP 没有 MKI。** SDES 的 MKI 在 ADR-072 中加入。only-dtls 与 only-srtp 已经支持 `use_srtp` 的 MKI
  （RFC 5764 §4.1.3），但没有地方使用它。

约束：默认行为不变。每项新行为都来自一个已有选项或新的可选开启项。做 BUNDLE 的会话热路径上不增加工作。

## 决策

### 1. 对 CE 的可扩展响应（`only_rtp::EcnResponse`，`BandwidthEstimator`）

- `BandwidthEstimator::set_ecn_response(EcnResponse::{Classic（默认）, Scalable})`。`set_rtt` 给出响应
  的轮次。`on_ecn_counts(now, ect, ce)` 接收来自没有逐包结果的反馈的汇总计数（第 2 节）。`ce_fraction()`
  报告平滑后的比例。
- **可扩展**（TCP Prague / DCTCP 的形式，用于速率）：
  - CE 不再算丢包。
  - 每轮（RTT 限制在 25..500 ms 之间，未知时 100 ms）对带 ECN 的结果中被标为 CE 的比例做增益 1/16 的平滑
    （`alpha`）。
  - 某轮里出现*上次削减之后*发出的包的 CE 标记时，把第三个速率降为
    `(1 - alpha/2) x min(估计值, 已确认速率)`。与 DCTCP 一样，每个窗口最多一次。
  - 没有 CE 的一轮，每 RTT 增加每 RTT 八分之一个 1200 字节的包。虚拟 RTT 至少 25 ms，即 Prague 的 RTT
    无关性。增长上限为已确认速率的 1.5 倍 + 10 kbps。
  - 估计值取基于时延、基于丢包与可扩展三个速率中的最小者。
  - 回退（RFC 9331 §4.3）：时延检测器报告过载时到达的 CE 也算丢包。经典 ECN 队列只在时延已经增长后才标记。
  - 汇总计数器不带发送时间。此时削减后 RTT + 100 ms 内的标记计入 alpha，但不会再次削减。
- **增长增益。** Reno 的每 RTT 一个包让速率越过链路。有节奏的发送端要晚一个 RTT 加一个反馈间隔才知道，这时
  阶跃标记的队列已经标记了整轮。随后时延检测器看到队列增长，以缓慢的方式削减速率。在模拟的 2 Mbps L4S 队列
  中：增益 1 得到 89 % 的利用率，1/8 在 0.4 ms 队列下得到 93 %，经典响应得到 82 %。
- **only-webrtc**：标记 ECT(1) 时选择可扩展响应；ECT(0) 保持经典响应。来自 RTCP 的 RTT 交给估计器。
- **标记 ECT(1) 时的 pacing**：估计值的 1.5 倍，突发额度 1 ms，而不是 2.5 倍与 40 ms。一帧作为一个突发发出
  时，无论速率高低都会在队列里排上好几个包，L4S 队列会标记它们。模拟的 6 Mbps 阶跃标记队列，编码器为估计值的
  90 %：

  | Pacing | 收到 | 队列 |
  | --- | --- | --- |
  | 2.5x / 40 ms | 3.9 Mbps | |
  | 1.5x / 5 ms | 2.6-3.4 Mbps | |
  | 1.5x / 1 ms | 4.9 Mbps | 1.3 ms |
  | 不用 ECN | 4.7-5.1 Mbps | 7.3 ms |
  | ECT(0) 经典 | 1.36 Mbps | |

### 2. RFC 6679 信令（`rtc/ecn_fb.rs`；only-rtp 的 `EcnFeedback`、`EcnSummary`、`EcnReceiver`）

- **线上格式**（only-rtp `ecn.rs`）：
  - RTCP ECN 反馈消息是 RTPFB FMT 8。它携带扩展最高序号、ECT(0) / ECT(1) / CE / not-ECT 计数器、丢失数
    与重复数。
  - XR ECN 摘要报告是块类型 13，每个源五个字。长度不是五的倍数的块被丢弃。
  - 两者都以 `Rtcp::Unknown` / `XrBlock::Unknown` 传递，并提供双向转换。给这两个枚举加变体会破坏穷尽匹配。
  - `EcnReceiver` 维护每个源的计数器：在 512 个序号的窗口内识别重复，丢失数为期望数减收到数，扩展序号的编号
    方式与 RFC 3550 报告块相同。它会标出新情况：某个源的第一个带 ECN 的包，或一个 CE 标记。
- **SDP。** 开启 ECN 标记时：
  - 每个音频和视频段提议 `a=ecn-capable-rtp:rtp mode=setread; ect=N`、`a=rtcp-fb:<pt> nack ecn`，并在
    `a=rtcp-xr` 中加入 `ecn-sum`。
  - 方法列表中包含 "rtp" 的提议按同样方式应答，只带一种方法。
  - 只实现 "rtp" 启动方法：没有 "ice"（STUN ECN-CHECK），也没有 "leap"。其他提议的应答里不带该属性，于是双向
    都不用 RFC 6679（§6.1.1）。
  - 双方都需开启，因为应答方需要配置 ECN 标记。远端的 `ect=` 偏好不被遵循：每一方标记自己配置的码点。
- **接收。**
  - 有新情况时发送反馈消息（至多每 20 ms 一次），每次常规报告也会发送。每条消息从接收该源的媒体行发出，并走
    该行的传输。
  - 协商了 `ecn-sum` 时，每段的复合报告携带该段各源的摘要。
  - 使用 RFC 8888 时以上都不发送：它的报告已经带有每个码点。
- **发送。**
  - 远端能读取 ECN（`setread` 或 `readonly`）并通过反馈消息或摘要报告它时，可以在没有 RFC 8888 的情况下标
    记，只要估计器依靠传输级反馈运行。
  - 关于某个源的两份报告之差，与两者扩展最高序号之间发出的包对应。第一份报告作为基线。
  - 标记以另一种 ECT 回来，或标记的包到达时没有一个带 ECN、而 not-ECT 计数能解释它们，路径就失败。
  - 否则计数作为收到或丢失交给 ADR-077 的状态机：启动、可用、重度丢包时回到测试。
  - 摘要与同一复合包中关于同一源的报告块匹配。CE 差值交给估计器（`on_ecn_counts`）。

### 3. 经 TURN 的 ECN，以及 TCP 路径上关闭

- **经 UDP 的 TURN。** 中继的 RTP 以 ChannelData 或 Send 指示到达服务器。这个数据报带上 RTP 包的码点；STUN
  请求从不带码点。RFC 8656 §12 要求服务器把码点复制到被中继的数据报上（其"首选行为"）。
- **另一个方向。** 来自 UDP 分配的数据报保留到达时的码点：服务器复制了对端的码点。经 DTLS 到服务器时，外层
  数据报的码点属于该关联本身，因此不使用。
- **能验证什么。** 中继是否复制由验证决定。按 RFC 8656 允许的方式设为 Not-ECT 的中继，与任何清除码点的中间
  设备一样使路径失败，媒体照常以不标记的方式继续。
- **only-turn 自己的服务器还不复制。** 它的中继路径正在别处修改（TCP 分配，ADR-076），因此保持原样。经过它
  的路径在几次探测后验证失败。
- **TCP 路径。** 本地候选是 ICE-TCP（RFC 6544），或者分配经 TCP / TLS 建立时，没有码点可给。这里的 ECN 是
  TCP 自己的事，经流到达的 TURN 服务器也没有东西可复制。这样的路径从不启动 ECN：它保持*关闭*，而不是失败。
  端点会把经流中继的候选告诉 peer（`Rtc::set_no_ecn`）。之后的 UDP 路径照常开始启动阶段。

### 4. 锁定 DTLS 握手（`rtc/latch.rs`）

- **何时。** 没有 ICE、配置了锁定、DTLS-SRTP 且本端是 DTLS *服务端*、握手未完成，并且尚未从描述地址收到任何
  东西。锁定时把 `actpass` 提议应答为 `passive`，由远端发起握手。本端的提议仍是 `actpass`。远端应答
  `passive` 时本端成为客户端，这时什么都不会锁定：我们的 ClientHello 发往不可达的 SDP 地址。
- **先交换 cookie。**
  - 来自未知源的 DTLS 数据报用 `only_dtls::HelloVerifier` 检查（无状态）。每个进程一个验证器：端点把数据报
    依次交给各个正在锁定的 peer，所以一个 cookie 在下一个 peer 那里也必须能验证通过。
  - 没有有效 cookie 的 ClientHello 得到一个 HelloVerifyRequest 或 DTLS 1.3 HelloRetryRequest，状态不变。
  - 端点把该源路由到作答的 peer，于是第二个 ClientHello 到达同一个 peer。由于路径对还没有移动，它要经过同样
    的检查。
- **暂定锁定。** 带有效 cookie 的 ClientHello 证明该源在其地址上能收到数据。分量 1 的路径对暂时移到那里，一个
  新的服务端关联与之运行，端点也开始路由该源。
- **确认。**
  - 远端证书必须与描述中的指纹一致。完成的握手按策略锁定：移动被计数，SDP 地址被释放。
  - 失败（证书不对）、被关闭或 4 s 内未完成的握手把路径对移回，不会杀死 peer，其他源随后可以尝试。
  - 一个握手进行期间，其他源的 ClientHello 被忽略，它们的重传会在之后进来。
- **安全。** 路径外的攻击者拿不到它收不到数据的地址的 cookie，没有远端私钥也完成不了握手。读到 SDP 的人可以从
  自己的地址每次占用暂定位置 4 s，从而拖延呼叫，但无法接管媒体。
- **限制。**
  - 分量 2 自己的 DTLS（不复用 RTCP 时）不以这种方式锁定。它像以前一样，在密钥存在后依靠 SRTCP 锁定。
  - 同一本地地址上的多个锁定 peer 按端点交出数据报的顺序得到握手。证书检查失败的 peer 会把下一次尝试让给下一
    个 peer。每个呼叫使用不同的本地地址（`bind_transport_socket`）可以避免这种情况。

### 5. DTLS-SRTP 的 SRTP MKI（`RtcConfig::set_dtls_srtp_mki_length`）

- 0（默认）表示不用，否则为 1..=128 字节。
- **作为 DTLS 客户端：** 在 `use_srtp` 中提议该长度的 MKI。其值为会话内的握手计数，因此可以区分后来一次握手的
  密钥。
- **作为服务端：** 同意客户端提议的任何 MKI（`with_srtp_accept_mki`）。
- 达成一致时，SRTP 与 SRTCP 上下文双向携带它，包括分量 2 的上下文。不同意的对端以空 MKI 应答，SRTP 不带 MKI
  运行。
- 目前会话中途不会重新换钥：不会发起 DTLS 重新握手。MKI 的作用在于要求带 MKI 的网关，以及将来的换钥。

### API

纯增量。

- only-rtp：`EcnResponse`、`BandwidthEstimator::{set_ecn_response, ecn_response, set_rtt, ce_fraction,
  on_ecn_counts}`、`EcnCounters`、`EcnDelta`、`EcnFeedback`、`EcnSummary`、`EcnReceiver`、
  `ECN_FEEDBACK_FMT`、`ECN_SUMMARY_BT`。
- only-webrtc：`RtcConfig::set_dtls_srtp_mki_length`。
- only-turn、only-dtls、only-srtp 不变。

## 后果

- **默认行为**不变。开启 ECN 标记时，提议中带有 RFC 6679 的属性。Chrome 会忽略它们，不认识它们的远端也一样。
- **测试：**
  - only-rtp：估计器经过模拟的 L4S 队列（可扩展、经典、不用 ECN 三者对比，2 与 10 Mbps，CE 比例随速率增长
    而下降）；计数器路径；反馈与摘要的往返；接收端计数，包括序号回绕、丢失、重复与迟到。
  - only-webrtc 模拟网络：ECT(1) 经过 6 Mbps 阶跃标记队列，达到链路的 82 %，队列 1.3 ms，而 ECT(0) 为
    1.36 Mbps；没有 RFC 8888 时的 RFC 6679 协商、验证、清除 / 改标检测以及 CE 交给估计器；应答方不标记时不用
    RFC 6679；TCP 路径为关闭而非失败；DTLS 握手锁定 NAT 之后的话机，两种提议方向都覆盖（先交换 cookie），未开
    启选项时不锁定，外来证书被尝试并拒绝之后话机再锁定；DTLS-SRTP MKI 协商成功（复用与不复用 RTCP），任一方
    关闭时不用。
  - 回环上的端点：应答中写了一个无效端口的 DTLS 话机，通过锁定找到。
- **模糊测试：** `rtp_rtcp` 目标双向转换 ECN 反馈与摘要，并驱动一个 `EcnReceiver`。`webrtc_sdp` 的种子包含
  RFC 6679 的提议与应答。
- **互通：** 见 2026-11-22 的 CHANGELOG / DEV-PLAN 条目。Chrome 157 用 `ecn.sh`；`latch.sh` 中 NAT 之后是一台
  DTLS-SRTP 话机。
- **性能：** gpu51 上与 main 7e4db2d9 的同轮 A/B（`webrtc-bench`，默认配置，7 轮，取中位数）：媒体 0.999 倍，
  数据通道 0.997 倍，区间重叠（docs/BENCHMARKS.zh-CN.md）。
- **代价：**
  - 开启 ECN 时：协商后每个收到的 RTP 包做一次 RFC 6679 计数器更新；每份报告遍历两份报告之间的序号。
  - 使用 ECT(1) 时：pacing 更平滑，帧在大约自身时长内发出，而不是一次性发出。
  - DTLS 锁定时：每个来自未知源的 ClientHello 一次 HMAC。
- **尚未完成：**
  - RFC 6679 的 "ice" 与 "leap" 启动方法，以及遵循远端的 `ect=` 偏好。
  - ICE-TCP 上 RTP 的 ECN 反馈（没有可给的）。
  - 在 only-turn 自己的中继里复制码点。
  - 对已失败的路径重试 ECN。
  - 锁定分量 2 的 DTLS。
  - 本端必须作为 DTLS 客户端时的锁定。
  - DTLS 换钥，因此 MKI 的值只在不同会话的握手之间变化。
