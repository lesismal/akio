# only-rtp

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 RTP 与 RTCP，安全 Rust（`#![forbid(unsafe_code)]`），
没有依赖：数据包、RTCP 反馈、带 NACK 与 RTX 的单流收发状态、传输层与 RFC 8888 拥塞控制反馈及带宽
估计、RTCP 扩展报告、TMMBR / TMMBN、前向纠错（ULPFEC、FlexFEC、RED），以及编解码器载荷格式。它是自研 WebRTC 协议栈的媒体层（其下由 [`only-srtp`](../only-srtp) 加密）。这是内部 crate
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
  丢包的控制（>10% 降低，<2% 提高）、REMB 上限与上下界；以及类似 libwebrtc 的探测（ADR-050）：以
  起始速率的 3 倍和 6 倍探测，结果跟得上时翻倍继续，受应用限制时每 5 s 一次，估计值大幅下降之后，以及
  `on_network_change` 之后重新开始。调用方把 `poll_probe(now)` 要求的包（`probe_timeout()` 给出时间）
  作为最近媒体的 RTX 副本或填充包（`SendStream::padding`）发出，用 `TwccSender::on_sent_probe` /
  `CcfbSender::on_sent_probe` 记录、用 `on_probe_sent` 报告；反馈（`PacketResult::probe`）测出簇的
  送达速率，用于提升估计值。`with_probing(false)` 关闭探测。
- `codec`：打包 / 解包（Opus 等音频、VP8、VP9、H.264、H.265、AV1）以及帧组装。
- RTCP XR（RFC 3611）：`RrtrResponder` 用 DLRR 应答接收方参考时间，`RecvStream::handle_dlrr` /
  `rtt_from_dlrr` 让不发送 SR 的接收方得到 RTT；`RecvStream::statistics_summary` 生成统计摘要块；
  `ReceiptLog`（`RecvStream::enable_receipt_log` / `receipt_blocks`）根据收到的包生成丢包 RLE、重复
  RLE 与包接收时间块，支持稀疏化；`BurstLossModel`（RFC 3611 A.2）填写 VoIP 指标中的丢包 / 突发 /
  间隙字段，配合 `VoipQuality`（时延、电平、RERL、应用提供的 R / MOS、PLC、抖动缓冲）生成完整的块
  （`report`）；`pcm_level_dbm0` 测量信号与噪声电平（ADR-053）。
- SDES：`SdesItem` 把 `Rtcp::SourceDescription` 的 `(类型, 文本)` 对转换为类型化的项，包括 PRIV 的前缀与
  值，并为每个已注册类型（CNAME .. MID）提供常量；`random_cname` 生成 RFC 7022 的 CNAME。
- TMMBR / TMMBN（RFC 5104）：`TmmbrHandler` 保存各接收方针对某媒体 SSRC 的请求，计算边界集
  （`bounding_set`、`bounded_bitrate`）并构造 TMMBN。
- RFC 8888：`CcfbReceiver` 按媒体 SSRC 生成拥塞控制反馈（含 ECN），每 50 毫秒或每 100 个包一次；
  `CcfbSender` 像 TWCC 一样把它转换成供估计器使用的 `PacketResult`。
- `fec`：用于 ULPFEC（RFC 5109）、Chrome 发送的 FlexFEC（`flexfec-03`）和 RFC 8627 FlexFEC 的
  `FecEncoder` / `FecDecoder`：按帧使用交织掩码（保护率单位 1/256），凡是某个 FEC 包只缺一个包就将其
  逐字节恢复；`fec::red` 处理 RFC 2198（WebRTC 中 ULPFEC 走 RED）。ULPFEC 也支持多个保护级别
  （RFC 5109 §7.4，ADR-053）：`set_ulp_level0(Some(l0))` 用交织的 FEC 包保护每个包的前 `l0` 字节，
  其余部分每组保护一次；`encode_ulp` 接受显式级别；解码器逐个区间重建包，完整后才返回。多级保护只适用于
  实现了它的接收方：libwebrtc 只读第 0 级。

```rust,ignore
// FlexFEC：每帧约 30 % 的 FEC 保护，在另一端恢复。
let mut enc = FecEncoder::new(FecScheme::Flexfec03, media_ssrc, 77);
for payload in enc.push(&rtp_packet, marker) { /* 在 FEC SSRC 上发送 */ }
let mut dec = FecDecoder::new(FecScheme::Flexfec03, media_ssrc);
for p in dec.on_media(&received) { /* 恢复出的 RTP 包 */ }
for p in dec.on_fec(fec_payload) { /* ... */ }
```

## 协议覆盖

- 头部扩展：mid、rtp-stream-id、repaired-rtp-stream-id、abs-send-time、transport-wide-cc、
  ssrc-audio-level、video-orientation、toffset、playout-delay。
- RTCP：SR、RR、SDES、BYE、通用 NACK、传输层拥塞控制反馈（游程与两种状态向量块，小 / 大时间差）、
  RFC 8888 拥塞控制反馈、PLI、FIR、REMB、TMMBR、TMMBN，以及包含 RFC 3611 全部报告块的扩展报告（丢包与
  重复 RLE、接收时间、RRTR、DLRR、统计摘要、VoIP 指标）；其他包保留为 `Rtcp::Unknown`（未知 XR 块为
  `XrBlock::Unknown`）。解析严格检查长度且不会 panic。
- FEC：ULPFEC（任意多个保护级别）、FlexFEC `flexfec-03`（libwebrtc 的头格式）与 RFC 8627（灵活掩码，
  一个被保护 SSRC）、RED。细节见 ADR-036 与 ADR-053。
- SDES 项：每个已注册类型（RFC 3550 §6.5、IANA）、PRIV 的前缀 / 值，文本在字符边界处截断。

`only-webrtc` 在配置后协商并使用以上全部（ADR-039）；为此 `RecvStream::receive_recovered` 记录由 FEC
重建的包（不再被 NACK，但报告中仍计为丢失），`FrameAssembler::skip` 标记不承载媒体的序号（ULPFEC、
填充包），使其不被当作缺口。

未实现：FlexFEC 重传与固定 L/D 包、多个被保护 SSRC、libwebrtc 的掩码表；交出部分恢复的包；R 因子 /
MOS 估算（由应用提供）。only-webrtc 尚未发送接收日志或 VoIP 的 XR 块，也未使用 ULPFEC 多级保护或随机
CNAME。

## 测试

- 与 pion 逐字节对照：带一字节和两字节扩展及填充的 RTP 头（pion/rtp v1.10.6）；SR、RR、NACK、PLI、
  FIR、REMB、SDES、BYE 及复合包（pion/rtcp v1.2.20）；pion/interceptor TWCC recorder 生成的反馈，
  包含回绕、空洞、乱序和大时间差，`TwccReceiver` 用相同到达时间逐字节复现。
- 所有 RTCP 类型以及两种扩展形式（含 CSRC 与填充）的头部往返；畸形头部、扩展与 RTCP 长度。
- 流：RTX 格式、历史上限、SR 外推与 RTT、回绕与乱序、丢包统计、抖动、NACK 调度（乱序等待、恢复、
  按 RTT 重复、放弃、不连续），以及模拟丢包链路上 NACK / RTX 恢复全部包。
- 7 万个带丢包的包上的 TWCC 端到端测试；模拟链路上估计器在干净链路上增长，在 1 Mbps 瓶颈下稳定在
  其以下，在 25% 丢包下回退。
- 模拟链路上的探测（编码器跟随估计值、尾部丢弃瓶颈、单向 20 ms；起始 300 kbps），有 / 无探测：
  0.5、2 与 10 Mbps 的 90 % 分别在 0.15 / 0.25 / 0.35 s 达到，而不是 5.4 / 23 / 44 s，峰值至多为
  容量的 1.12 倍；10 -> 2 -> 10 Mbps 阶跃 3.6 s 恢复（无探测时 30 s 内都恢复不了）；5 % 丢包、15 %
  丢包、竞争流量、受应用限制的编码器；40 个种子；簇的节奏与测量、填充包。
- libwebrtc 单元测试向量：TMMBR、TMMBN、RRTR、DLRR 与空 XR 逐字节一致；其写出器产生、读取器接受的
  FlexFEC-03 掩码；其 ULPFEC 头读取用例。RFC 3611 §4.7.2 突发示例（丢包、丢弃、突发 / 间隙密度与时长）；
  按 §3.1 拼装的 RFC 8888 包；每种 XR 块的往返；边界集。
- ADR-053：逐字节核对 RFC 5109 §10.2 两级示例（勘误 3461）、每个单包丢失、第 1 级先于第 0 级、丢两个
  包、§7.4 规则、400 个有损帧上的第 0 级模式；由收包生成 RFC 3611 §4.1 的 RLE 示例；丢包 / 重复 RLE 与
  接收时间块与 pion/rtcp v1.2.20 逐字节一致（偶数个块：pion 漏掉奇数时的空块）；300 条随机轨迹在稀疏化
  与回绕下的 RLE 编码 / 解码；跨回绕的接收日志；VoIP 报告字段与 PCM 电平；含 PRIV、MID、RtpStreamId 的
  SDES 与 pion/rtcp v1.2.20 逐字节一致；RFC 7022 CNAME。
- 在有丢包的模拟双流链路上由 RFC 8888 反馈驱动估计器；每种方案的 FEC 恢复（组内突发、5000 个包 5 %
  随机丢包、经 RED 的 ULPFEC），逐字节核对每个恢复出的包。
- 模糊测试：`fuzz/` 中的 `rtp_rtcp` 目标（头部解析 / 写出 / 再解析、复合 RTCP 往返、驱动流、TWCC 与
  RFC 8888 发送端、RRTR 应答器和 TMMBR 处理器、SDES 项、RLE 重编码、VoIP 报告、接收日志）与 `rtp_fec`
  目标（含 ULPFEC 级别的 FEC 头与 RED 的解析 / 重写、任意输入驱动解码器、编码器 → 有损解码器恢复，包括
  第 0 级模式与显式级别）；`fuzzing::tests` 在 stable 上回放其语料。
