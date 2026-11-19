# ADR-050：only-rtp 估计器中的带宽探测

[English](050-bwe-probing.md) | 简体中文

状态：已接受（2026-11-19）

## 背景

`only_rtp::BandwidthEstimator`（ADR-036，由 transport-wide 或 RFC 8888 反馈驱动的、类似 GCC
的发送端估计器）此前只按 AIMD 规则增长：每秒 8 %，在上次下降的速率附近改为加性增长，且永远不超过
已确认码率的 1.5 倍 + 10 kbps。因此从 300 kbps 起步的 WebRTC 发送方要 23 s 才能达到 2 Mbps
链路的 90 %，10 Mbps 要 44 s；受应用限制的发送方（编码器已在最高层、SFU 只转发一层）永远不知道
还有更多带宽：对照无头 Chrome，回显服务器的估计值整轮都停在起始的 1 Mbps。crate README 把
“估计器中的探测”列为未实现。

libwebrtc 用探测解决这个问题：`ProbeController` 决定何时探测、以什么速率探测，`BitrateProber`
以目标速率发送一个包*簇*（至少 15 ms、5 个包），`ProbeBitrateEstimator` 把簇的反馈换算成测得的
速率并设为基于时延的估计值。探测包是填充包或最近媒体的 RTX 副本，在 pacer 中打上簇 id。

only-webrtc 没有 pacer：`write_media` 把一帧分包后立即全部交给传输层。另一个会话正在同时修改
only-webrtc（DTLS 1.3、cryptex、Opus RED），因此 only-webrtc 的改动必须很小，且只在发送路径内。

## 决定

1. **探测放在 only-rtp 中，sans-io，位于 `BandwidthEstimator` 之后**（私有模块 `probe`），
   默认开启；`with_probing(false)` 完全恢复之前的估计器（从不请求探测，其余不变）。
   - *何时*（libwebrtc `ProbeController` 的默认值）：开始时以起始速率的 3 倍和 6 倍各探测一簇；
     等待结果期间，结果超过上次探测的 70 % 就以估计值的两倍再探测一次（1 s 内没有这样的结果、
     或到达上界 / REMB 上限时停止）。受应用限制时，每 5 s 以估计值的两倍探测一次。估计值大幅
     下降（低于前值的 66 %）后，当时延检测器恢复正常（欠载转为正常，或下降后 500 ms）时以至多
     下降前速率的 85 % 探测一次，之后只要估计值仍低于该值，就在 30 s 内每 3 s 探测一次；这种
     探测的目标不超过估计值的两倍，结果跟得上时继续往上探测。`on_network_change(now)`（路径
     改变）把时延与丢包状态重置到起始速率，并重新开始探测。
   - *受应用限制*由反馈本身测得（无需额外钩子）：最近 500 ms 内发送的媒体（按包结果中的发送时间，
     不含探测包）低于估计值的 60 % 时进入，高于 70 % 时离开。`application_limited()` 报告该状态。
   - *节奏*：有包到期时 `poll_probe(now)` 返回 `ProbePacket { cluster, size }`（调用到返回
     `None` 为止），`probe_timeout()` 给出下一个包的到期时间；调用方用
     `on_probe_sent(now, cluster, bytes)` 报告实际发送的字节，已发送的字节数按簇速率决定下一个包
     何时到期。一簇至少 15 ms、5 个包；包大小以每簇约 10 个包为目标（200..1200 字节），使丢失一个
     包对结果的影响更小。最多 4 个簇排队；1 s 内未开始发送的簇被丢弃。
   - *测量*（libwebrtc 的 `ProbeBitrateEstimator`）：`TwccSender::on_sent_probe` 与
     `CcfbSender::on_sent_probe` 记录探测包及其簇，`PacketResult` 增加 `probe: Option<u32>`。
     一簇 80 % 的包与字节到达后，以至多一秒内的发送速率（不含最后发送的包）和接收速率（不含最先
     收到的包）得出结果：取两者较小值；接收速率低于发送速率的 90 % 时（已饱和）取接收速率的
     95 %；接收 / 发送之比超过 2 则丢弃。**偏离**：测量还计入在簇的发送区间内发送的媒体包（来自
     同一批反馈）。libwebrtc 的 pacer 会在簇内发送媒体，所以它的簇本来就带着媒体；我们的探测包
     与未经 pacing 的媒体并行发出、共享瓶颈，不计入媒体时，饱和簇只报告探测包所占的份额（10 Mbps
     上得到 7.2 而不是 9.5 Mbps）。
   - *作用*：除非检测器判定过载，结果把基于时延的速率提升到该值（并退出加性增长区），并把基于
     丢包的速率提升到至少该值，因此中等丢包（2..10 %，此时基于丢包的速率保持不变）不会阻止爬升。
     结果从不降低估计值（libwebrtc 的 `SetEstimate` 可能会降低）；下降仍由时延与丢包检测器负责。
     结果受上下界及 REMB / TMMBR 上限约束。
   - 对 libwebrtc 下降后探测的**偏离**：libwebrtc 只在受应用限制（或刚结束）时、下降后 5 s 内、
     每 5 s 至多一次地探测。我们不要求受应用限制，并在 30 s 内每 3 s 以不超过估计值两倍的速率
     持续探测，因为没有 pacer 来填补空隙时，AIMD 需要数十秒才能从短暂下降中恢复（容量从 2 阶跃到
     10 Mbps：3.6 s，而不是 30 s 内都恢复不了）。
2. **`SendStream::padding(now, size, rtx_pt, map, f)`** 构造探测包：历史中载荷放得下的最新包
   （否则取最新包）的 RTX 副本，接收方把它当作重复包；历史为空或没有 RTX 时，构造只含填充的包
   （至多 255 字节填充），有 RTX 流时放在 RTX 流上，否则以下一个序号放在媒体流上。探测包不进入
   历史，也不计入已发送 / 已重传计数。流尚未发送任何东西时返回 `None`。
3. **only-webrtc：最小的 pacer 钩子**（新文件 `rtc/pacing.rs`，`rtc.rs` 中 11 行）。启用
   估计器（`RtcConfig::enable_bwe`）后，每次 `write_media` 之后以及 `handle_timeout` 中运行
   `send_probes`，`poll_output` 的超时包含探测超时；探测包走在有拥塞控制反馈（transport-wide 或
   RFC 8888）的各行中发送媒体最多的流上，带新的 transport-wide 序号与 abs-send-time，在 RTX 上把
   RID 移到 repaired-RID 扩展（与应答 NACK 相同）。发送媒体之前不探测；无法发送的簇（没有 ICE 候选对、没有这样的流）用 `cancel_probes` 丢弃，使探测
   超时不会停留在过去。ICE 选中的候选对改变
   （不是第一个候选对）时调用 `on_network_change`。没有配置项：探测随 `enable_bwe` 一起开启。

## 影响

- 模拟链路（`crates/only-rtp/src/tests_probe.rs`：编码器跟随估计值、帧大小 ±20 %，单向 20 ms，
  300 ms 尾部丢弃 FIFO，每 100 ms 一次反馈；起始 300 kbps），探测开 / 关：0.5 Mbps 的 90 % 用时
  0.15 s / 5.4 s，2 Mbps 为 0.25 s / 23.4 s，10 Mbps 为 0.35 s / 44.3 s；估计值峰值为容量的
  1.12x / 1.03x / 1.01x（关：1.08x / 1.01x / 0.30x）；最大排队时延 81 / 32 / 22 ms。阶跃
  10 -> 2 -> 10 Mbps：0.6 s 内降到 2 Mbps 的 110 %，阶跃后 3.6 s 回到 10 Mbps 的 90 %（关：30 s
  内都回不去），2 Mbps 期间峰值 1.05x。4 Mbps 上 5 % 随机丢包：0.35 s 达到 90 %（关：永远达不到；
  基于丢包的速率停在起始值）。10 Mbps 上 6 Mbps 的竞争流量：我们的份额稳定在剩余 4 Mbps 的 0.93。
  编码器上限 1 Mbps、链路 10 Mbps：30 s 后估计值 9.5 Mbps（关：1.65 Mbps）。这些运行是确定性的
  （有种子、模拟时间）；测试中还包括 40 个种子、0..2 % 丢包的扫描。
- Chrome 157 作为接收方（`tools/interop/webrtc/bwe.sh`：fec-server 开启估计器、起始 1 Mbps，
  回显 Chrome 的 VP8，15 s）：之前估计值从未离开 1 Mbps；现在连接后 0.17-0.22 s 达到 10 Mbps
  （transport-wide 与 RFC 8888 反馈都是如此），之后到达 20 Mbps 上界，Chrome 解码了全部回显帧
  （RTX 副本被当作重复包）。
- 估计值现在很早就达到链路容量，因此时延检测器的过载削减（500 ms 内已确认速率的 85 %，在快速
  爬升时滞后）可能随后到来；下降后的探测会把它拉回。10 Mbps 上 5-30 s 的平均估计值为容量的
  0.86（关：0.13）。
- 探测消耗带宽：每次探测约 15 ms、至多估计值的两倍（10 Mbps 上前 30 s 共 78 kB）。
- API 全部是新增，只有 `PacketResult` 多了一个公开字段（only-rtp 属于内部层级：crate 外的
  `PacketResult` 结构体字面量需要加上 `probe: None`）：`ProbePacket`、
  `BandwidthEstimator::{with_probing, poll_probe, probe_timeout, on_probe_sent,
  cancel_probes, on_network_change, application_limited}`、`TwccSender::on_sent_probe`、
  `CcfbSender::on_sent_probe`、`SendStream::padding`。only-webrtc 的公开 API 不变。
- 未完成：提高配置的最大值时探测、libwebrtc 基于网络状态估计的探测以及探测不确定度 / 快速恢复
  变体；only-webrtc 中真正的 pacer（媒体仍按帧突发发出）；only-webrtc 中关闭探测的配置开关。
