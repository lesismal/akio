# only-rtp

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 RTP 与 RTCP，安全 Rust（`#![forbid(unsafe_code)]`），
没有依赖：数据包、RTCP 反馈、带 NACK 与 RTX 的单流收发状态、传输层拥塞控制与带宽估计，以及编解码器
载荷格式。它是自研 WebRTC 协议栈的媒体层（其下由 [`only-srtp`](../only-srtp) 加密）。这是内部 crate
（docs/api-stability.zh-CN.md）：API 跟随该协议栈的需要，可能在任何发布中变化。

## 驱动方式

全部是 sans-io：方法接收数据包和 `Instant`，返回数据包。随机数（SSRC、初始序列号）由调用方提供。

```rust,ignore
use only_rtp::*;

let map = ExtensionMap::default_video();            // 或根据 SDP 的 a=extmap 行构建
// 发送。
let mut send = SendStream::new(ssrc, 90_000, Some(rtx_ssrc), initial_seq);
let mut twcc_tx = TwccSender::new();
let mut bwe = BandwidthEstimator::new(1_000_000);
let ext = ExtensionValues { mid: Some(mid), transport_cc: Some(twcc_tx.next_seq()), ..Default::default() };
let pkt = send.write(now, pt, marker, timestamp, &payload, &ext, &map);
twcc_tx.on_sent(ext.transport_cc.unwrap(), now, pkt.len());
// 对端的 RTCP。
for p in parse_compound(&rtcp)? {
    match p {
        Rtcp::Nack { lost, .. } => { for p in send.resend(now, &lost, Some(rtx_pt), &map) { /* 发送 */ } }
        Rtcp::TransportCc(fb) => bwe.on_packet_results(now, &twcc_tx.on_feedback(now, &fb)),
        Rtcp::ReceiverReport { reports, .. } => { for r in &reports { send.handle_report_block(now, ntp_time(SystemTime::now()), r) } }
        Rtcp::Remb { bitrate, .. } => bwe.set_remote_estimate(bitrate),
        _ => {}
    }
}
// 接收。
let h = RtpHeader::parse(&packet, &map).unwrap();
let ext_seq = recv.receive(now, h.sequence_number, h.timestamp);  // None：重复或过旧
twcc_rx.on_received(h.ext.transport_cc.unwrap(), now);
if let Some(lost) = recv.poll_nack(now) { /* Rtcp::Nack { lost, .. } */ }
if let Some(fb) = twcc_rx.poll_feedback(now, local_ssrc, h.ssrc) { /* 发送 */ }
let rb = recv.report_block(now);                                   // 用于 RR / SR
```

- `RtpHeader::parse` / `write`：固定头、CSRC、填充（`padding_len`）以及 RFC 8285 一字节 / 两字节
  头部扩展（当所有 id 不超过 14 且所有值为 1..=16 字节时 `write` 使用一字节形式）。`is_rtcp` 区分
  同一流上的 RTP / RTCP（RFC 5761）。
- `SendStream`：保留最近 1024 个包 / 2 秒；`resend` 用 RTX（RFC 4588）或原始包响应 NACK，每个包每
  10 毫秒最多重发一次；`sender_report` 给出 SR 发送者信息；`handle_report_block` 由 LSR / DLSR 计算 RTT。
- `RecvStream`：跨越 16 位回绕的扩展序列号，拒绝重复包和落后超过 2048 的包；报告块（丢包率 / 累计
  丢包、RFC 3550 A.8 抖动、LSR / DLSR）；乱序等待 RTT/4（5..20 毫秒）后发送 NACK，每个 RTT（默认
  100 毫秒）重复，最多 10 次或 1 秒；`poll_timeout` 给出下次轮询时间。
- `TwccReceiver` 每 100 毫秒或每 100 个包按 libwebrtc 的打包方式生成反馈；`TwccSender` 把反馈对应到
  已发送的包，得到 `PacketResult`。
- `BandwidthEstimator`：类 GCC 的时延梯度趋势线与自适应阈值、以确认码率为上限的 AIMD 码率控制、基于
  丢包的控制（>10% 降低，<2% 提高）、REMB 上限与上下界。
- `codec`：打包 / 解包（Opus 等音频、VP8、VP9、H.264、H.265、AV1）以及帧组装。

## 协议覆盖

- 头部扩展：mid、rtp-stream-id、repaired-rtp-stream-id、abs-send-time、transport-wide-cc、
  ssrc-audio-level、video-orientation、toffset、playout-delay。
- RTCP：SR、RR、SDES、BYE、通用 NACK、传输层拥塞控制反馈（游程与两种状态向量块，小 / 大时间差）、
  PLI、FIR、REMB；其他包保留为 `Rtcp::Unknown`。解析严格检查长度且不会 panic。

未实现：RTCP XR、TMMBR / TMMBN、FEC（ULPFEC、FlexFEC）、RFC 8888 反馈、估计器中的探测、SDES 中
类型 / 文本对以外的内容。

## 测试

- 与 pion 逐字节对照：带一字节和两字节扩展及填充的 RTP 头（pion/rtp v1.10.6）；SR、RR、NACK、PLI、
  FIR、REMB、SDES、BYE 及复合包（pion/rtcp v1.2.20）；pion/interceptor TWCC recorder 生成的反馈，
  包含回绕、空洞、乱序和大时间差，`TwccReceiver` 用相同到达时间逐字节复现。
- 所有 RTCP 类型以及两种扩展形式（含 CSRC 与填充）的头部往返；畸形头部、扩展与 RTCP 长度。
- 流：RTX 格式、历史上限、SR 外推与 RTT、回绕与乱序、丢包统计、抖动、NACK 调度（乱序等待、恢复、
  按 RTT 重复、放弃、不连续），以及模拟丢包链路上 NACK / RTX 恢复全部包。
- 7 万个带丢包的包上的 TWCC 端到端测试；模拟链路上估计器在干净链路上增长，在 1 Mbps 瓶颈下稳定在
  其以下，在 25% 丢包下回退。
- 模糊测试：`fuzz/` 中的 `rtp_rtcp` 目标（头部解析 / 写出 / 再解析、复合 RTCP 往返、驱动流与 TWCC
  发送端）；`fuzzing::tests` 在 stable 上回放其语料。
