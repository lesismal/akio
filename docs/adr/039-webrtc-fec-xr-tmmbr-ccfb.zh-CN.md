# ADR-039：akio-webrtc 对端中的 FEC、RTCP XR、TMMBR 与 RFC 8888 反馈

[English](039-webrtc-fec-xr-tmmbr-ccfb.md) | 简体中文

状态：已接受（2026-11-19）

## 背景

ADR-036 为 `akio-rtp` 加入了 RTCP 扩展报告（RFC 3611）、TMMBR / TMMBN（RFC 5104）、RTP 拥塞控制反馈
（RFC 8888）与 FEC（ULPFEC、FlexFEC、RED），但 `akio-webrtc` 的对端既不协商也不使用它们。接入需要：
SDP（载荷类型、FEC SSRC 组、反馈属性）、FEC 保护率策略、在帧组装器和 NACK 之前修复包的接收路径，以及
RTCP 调度。浏览器最重要：任何改变默认对端 offer / answer 内容的做法都可能改变 Chrome 的发送行为。

对照 Chrome 157 得到的事实（`tools/interop/webrtc/fec.sh`）：

- 视频默认提供 `red` / `rtx` / `ulpfec`；`flexfec-03` 只在 field trial
  `WebRTC-FlexFEC-03-Advertised` 下提供（发送 FlexFEC 需要 `WebRTC-FlexFEC-03`）。answer 一旦接受
  `red`，Chrome 就把每个视频包都放进 RED；ULPFEC 保护的是去掉 RED 头后的包（头扩展保持发送时的样子）。
- 它（在 `WebRTC-RFC8888CongestionControlFeedback` 下）在每个载荷类型上（包括 RTX 和 FEC 的）都提供
  `a=rtcp-fb:<pt> ack ccfb`，并同时提供 `transport-cc`。只有 answer 在该媒体段的每个载荷类型上都带
  `ack ccfb` 时它才发送 RFC 8888 反馈；否则只要协商了传输层序号头扩展，它就继续发送传输层反馈。
- 它会用 DLRR 应答接收方参考时间（XR RRTR），接受 `a=rtcp-xr:rcvr-rtt=all`，并且即使 SDP 中没有
  `ccm tmmbr` 也遵守 TMMBR（发送码率随之变化，并回复 TMMBN）。
- 它的接收报告给出 FEC 修复之前的丢包，重传到达的包计为已收到。

## 决定

1. **默认关闭的配置**（`RtcConfig`，默认对端的 SDP 与行为不变）：`enable_fec(Option<FecMechanism>)`，
   其中 `FecMechanism::{FlexFec, Ulpfec}`（`#[non_exhaustive]`）；`set_fec_protection(min, max)`
   （保护因子的上下界，单位为每 256 个媒体包的 FEC 包数，默认 0..=128）；`enable_ccfb`、
   `enable_rtcp_xr`、`enable_tmmbr`。`Peer::request_max_bitrate(mid, Option<u64>)` 发送 TMMBR。
2. **SDP。** 在非 simulcast 的视频行上：FlexFEC 为 `flexfec-03/90000`（PT 115，`fmtp
   repair-window=10000000`，`transport-cc` 反馈），该行发送时附带 `a=ssrc-group:FEC-FR <媒体> <fec>`
   与 FEC SSRC 的 `a=ssrc` 行；ULPFEC 为 `red/90000`（116）及其 RTX（117，`apt=116`）和
   `ulpfec/90000`（118）。answer 只接受远端提供的、与所配置机制相符的载荷类型（ULPFEC 需要 `red` 与
   `ulpfec` 同时存在）。`ack ccfb` 加到每个编解码器的反馈中（音频也加），`ccm tmmbr` 与 libwebrtc 的
   `rrtr` 加到视频的反馈中，`a=rtcp-xr:rcvr-rtt=all` 加到媒体段；反馈仍取与远端的交集。协商了
   `ack ccfb` 时，answer 去掉 `transport-cc` 与传输层序号头扩展，并在该段每个载荷类型（RTX、RED、FEC）
   上重复 `ack ccfb`——正是这一点让 Chrome 切换过来。
3. **发送 FEC。** 每个发送行一个 `FecEncoder`，在第一次受保护的写入时创建。ULPFEC：每个媒体包都以 RED
   （仅主块）发出，编码器拿到的是去掉 RED 后的包；FEC 载荷以 ulpfec 载荷类型的 RED 块在媒体 SSRC 上
   发出（因此占用媒体序号，也能被重传）。FlexFEC：FEC 载荷在该行自己的 FEC `SendStream` 上发出。两者都
   带新的 mid / 传输层序号 / abs-send-time 扩展。对 RED 包的 NACK 用 RED 的 RTX 载荷类型应答。
4. **保护率策略。** 保护因子为 `3 × 丢包率`（低于 1 % 时为 0），并钳到配置的上下界；`丢包率` 对关于
   受保护流的接收报告做平滑（EWMA ½），取报告的丢包比例与自上次报告以来被重传的包所占比例中的较大者，
   因为 NACK 会在报告体现之前就把丢包修好。自上次报告以来什么都没发送时不更新。没有照搬 libwebrtc 的
   表格及其 NACK / FEC 混合策略（RTT 低于约 20 ms 时不发 FEC）；可用 `min` 保持保护因子。
5. **接收 FEC** 发生在帧组装器和 NACK 之前：FlexFEC 包（按载荷类型识别，被保护的 SSRC 取自其头）或
   RED 中的 ULPFEC 块交给被保护流的解码器（每个对端最多 4 个解码器，每个约 1.5 MB）；媒体包（去掉 RED 后）也记入解码器；重建出的包经
   `RecvStream::receive_recovered`（akio-rtp 新增：不再算缺失，因此不会被 NACK，但也不计为已收到，所以
   报告仍给出修复前的丢包，与 Chrome 一致）进入接收流，然后进入组装器。ULPFEC 包和纯填充包所占的序号用
   `FrameAssembler::skip`（akio-rtp 新增）标记，组装器不必把它当作缺口去等待。重传包不送入解码器
   （它们的头扩展与被保护的原包不同）。
6. **RFC 8888。** 任一行协商成功后，收到的 RTP（所有 SSRC）交给每 50 ms 轮询一次的 `CcfbReceiver`，
   替代传输层反馈；每个发出的 RTP 包都记入 `CcfbSender`；由 RFC 8888 反馈驱动带宽估计器（此时忽略
   传输层反馈，避免重复计数）。
7. **XR。** 协商了 XR 且有接收的行在报告中附带接收方参考时间块；收到的 RRTR 总是在每轮报告中以一个
   DLRR 应答；指向我方某个 SSRC 的 DLRR 给出接收方 RTT，用于 NACK 节奏并出现在统计中。
8. **TMMBR。** 关于我方流的请求交给每个发送 SSRC 一个 `TmmbrHandler`（最多 16 个），每次都以 TMMBN
   应答，边界值（按该流实测的包速率）与 REMB 一起限制带宽估计；变化以事件报告。我方自己的请求在设置
   期间随每轮报告重复发送，撤销时发送一次值为 0 的 TMMBR。
9. **RTCP 时钟。** RTCP 的 NTP 时间改为从创建时取的锚点起按对端的 `Instant` 推进（`Rtc::ntp`），
   不再每次读取墙上时钟，因此 SR / RR、DLRR 与 RFC 8888 的计算是单调的，模拟时间的测试也能测出真实 RTT。

## 影响

- 公共 API 只有新增：`FecMechanism`、五个 `RtcConfig` 方法、`Peer::request_max_bitrate`；akio-rtp 新增
  `RecvStream::receive_recovered` 与 `FrameAssembler::skip`（Internal 层级）。默认配置生成的 SDP 与之前
  相同；`tools/interop/webrtc/browser.sh` 与 `run.sh` 不加修改即通过。
- Chrome 157（带上述 field trial）：FlexFEC 与 ULPFEC 双向（每个方向每 20 个 RTP 包丢 1 个且去掉 NACK
  时，Chrome 解码 400 帧中的 381–392 帧，没有 FEC 时只有 8 帧；服务端从 Chrome 的 FEC 重建 50–55 个
  包）、RFC 8888 双向、XR DLRR RTT、TMMBR（150 kbps 的请求下 Chrome 发送 136 kbps）。
- 默认配置的媒体吞吐不变（gpu51 同轮 A/B，两个回环 `Endpoint`：main 的 0.996x）；保护的代价就是它
  多发送的内容（64/256 时有效吞吐 80-84 MB/s，对比 92）。
- 未完成：simulcast 行与音频（Opus RED）上的 FEC、libwebrtc 的掩码表及考虑 RTT 的混合策略、在估计中
  计入 FEC 开销、RFC 8888 报告中的 ECN（此处不从 socket 读取）、除 RRTR / DLRR 外的 XR 块上线、在组装器
  中区分丢失的 ULPFEC 包与丢失的媒体包（没有 NACK 时，这样的缺口与其他丢包一样要等待超时）。
