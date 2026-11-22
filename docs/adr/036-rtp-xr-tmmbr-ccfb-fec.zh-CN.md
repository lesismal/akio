# ADR-036：akio-rtp 中的 RTCP XR、TMMBR / TMMBN、RFC 8888 反馈与 FEC

[English](036-rtp-xr-tmmbr-ccfb-fec.md) | 简体中文

状态：已接受（2026-11-18）

## 背景

`akio-rtp`（自研 WebRTC 协议栈的媒体层）此前列为未实现的有：RTCP 扩展报告（RFC 3611）、
TMMBR / TMMBN（RFC 5104）、RTP 拥塞控制反馈（RFC 8888）以及前向纠错（ULPFEC、FlexFEC）。它们都是
一种线格式加一份状态，都不需要 I/O，因此都符合本 crate 的 sans-io 形态。`akio-rtp` 属于 Internal
层级（docs/api-stability.md）：API 可以变化，但变化需要记录。

需要先确定两处格式问题：

- **FlexFEC。** Chrome 以 `flexfec-03` 协商 FlexFEC（需要 field trial `WebRTC-FlexFEC-03` /
  `-Advertised`）。libwebrtc 的 `ForwardErrorCorrection::CreateFlexfec` 使用
  `Flexfec03HeaderReader/Writer`，它**不是** RFC 8627：在 8 字节恢复字段之后是 `SSRCCount`（= 1）
  和三个保留字节，然后是被保护的 SSRC 与序号基准，掩码的 K 位在**最后一段**为 1（掩码 15、46 或
  109 位）。RFC 8627 §4.2.2.1 把被保护的 SSRC 放进 FEC 包 RTP 头的 CSRC 列表，掩码紧跟在 SN base
  之后，k 位为 1 表示**后面还有**一段（15、46 或 110 位）。libwebrtc 也有 RFC 8627 的读写器，但
  `flexfec-03` 不用它。两种格式都保护每个媒体包 12 字节固定头之后的全部内容。
- **RFC 8888 的 `num_reports`。** libwebrtc 的 `CongestionControlFeedback` 把它当作该流 16 位
  度量块的个数来读写（覆盖 `begin_seq` .. `begin_seq + num_reports - 1`），每个流补齐到 32 位；
  发送方 SSRC 之后没有媒体 SSRC 字段；包以 32 位报告时间戳（NTP 中间 32 位）结尾。

## 决定

1. **RTCP。** `Rtcp` 新增 `ExtendedReport { ssrc, blocks: Vec<XrBlock> }`（PT 207）、
   `Tmmbr` / `Tmmbn { sender_ssrc, entries: Vec<TmmbItem> }`（205/3、205/4；媒体 SSRC 字段写 0，
   解析时忽略）以及 `CongestionControl(CcfbFeedback)`（205/11）。`XrBlock` 覆盖 RFC 3611 的全部
   报告块：丢包与重复 RLE（原始 chunk，去掉末尾的空 chunk）、包接收时间、接收方参考时间、DLRR、
   统计摘要（各标志位以 `Option` 表示；ToH 3 视为未报告）和 VoIP 指标（原始字段），其他类型为
   `XrBlock::Unknown`。解析依旧严格检查长度且绝不 panic；写出时对放不进 16 位长度的列表截断，
   TMMB 开销钳到 9 位、ATO 钳到 13 位，过大的 TMMB 指数像 REMB 一样饱和。
2. **XR 状态。** `RrtrResponder`（媒体发送方）记住最多 32 个接收方各自最后一个 RRTR，保留一分钟，
   并以 DLRR 块应答；`rtt_from_dlrr` 与 `RecvStream::handle_dlrr` 让不发送 SR 的接收方也能得到
   RTT（同时用于 NACK 节奏）。`RecvStream::statistics_summary` 报告自上次调用以来的区间（丢包、
   重复、传输时间差的最小 / 最大 / 平均 / 标准差；本层不知道 TTL），`RecvStream::duplicates`
   统计重复包。`BurstLossModel` 是 RFC 3611 附录 A.2 的突发 / 间隙模型，用于 VoIP 指标块；通话
   从间隙状态开始（第一次丢包按其前已有 Gmin 个包来判断），这样能精确复现 §4.7.2 的示例，而照字面
   执行的算法（开始时处于“突发”状态）不能。电平、质量与抖动缓冲字段保持“不可用”，由应用填写。
3. **TMMBR。** `bounding_set` 计算 RFC 5104 §3.5.4.2 的边界集：直线
   `bitrate - 8 * overhead * packet_rate` 在包速率 >= 0 上的下包络（在直线到达零处截断；忽略零码率）；
   `bounded_bitrate` 对其求值。`TmmbrHandler` 针对一个媒体 SSRC 保存每个请求者的最新请求（0 bit/s
   表示撤销，超时 25 s 同 libwebrtc，最多 64 个请求者），报告边界集是否变化，并构造条目标明所有者的
   TMMBN。
4. **RFC 8888。** `CcfbReceiver` 按媒体 SSRC 记录到达（含 ECN），每 50 ms（可设置）或积压 100 个包时
   生成反馈，每个包最多 500 条报告，每个媒体包只报告一次；ATO 为 `now - arrival`，单位 1/1024 s，
   含超范围 / 不可用的特殊值。`CcfbSender` 按 SSRC 记录发送，并把报告映射为 `PacketResult`（到达时间
   = 展开后的报告时间戳 - ATO，与 TWCC 一样锚定到本地 `Instant`；结果按跨流的发送序号排序），因此
   `BandwidthEstimator` 可以像使用 TWCC 一样使用 RFC 8888。ATO 为超范围或不可用的包离开记录但不产生
   结果。
5. **FEC**（公开模块 `fec`）。`FecScheme::{Ulpfec, Flexfec03, Flexfec}` 选择头格式：ULPFEC
   （RFC 5109，单级，16/48 位掩码，保护长度 = 最长的包）、libwebrtc 的 `flexfec-03`，或带灵活掩码
   的 RFC 8627（一个被保护 SSRC，由调用方放进 CSRC 列表）。校验覆盖 P/X/CC、M/PT、长度 - 12、时间戳
   以及固定头之后的每个字节（CSRC、扩展、载荷、填充），因此恢复出的包逐字节一致。`FecEncoder` 按帧
   把一个 SSRC 的外发媒体包分组（最多 `MAX_FEC_GROUP` = 48，同 libwebrtc），输出
   `round(k * rate / 256)`（至少 1）个交织的 FEC 载荷（`interleaved_masks`：第 i 个 FEC 包保护
   j ≡ i mod m 的包，因此长度不超过 m 的突发丢包可恢复）；`encode` 接受显式掩码。`FecDecoder` 保留
   1024 个序号范围内的媒体包和 64 个 FEC 载荷，凡是某个 FEC 包只缺一个包时就重建它，并随着恢复迭代
   帮助其他 FEC 包。`FecHeader` 暴露解析后的头。`fec::red` 解析与写出 RFC 2198 载荷，并对包的主块
   做封装 / 解封装，这正是 WebRTC 承载 ULPFEC 的方式（FEC 保护去掉 RED 后的媒体包）。FEC 载荷以裸
   形式返回：由调用方经 `SendStream` / RED 在正确的 SSRC 上发送，因此头扩展（mid、传输层序号）与
   媒体包一样可用。
6. **测试与模糊测试。** 与 libwebrtc 单元测试向量逐字节一致（TMMBR、TMMBN、RRTR、DLRR、空 XR、
   FlexFEC-03 写出与读取的掩码、ULPFEC 头读取）、RFC 3611 §4.7.2 突发示例、手工拼装的 RFC 8888 包、
   每种报告块的往返、各处理器的测试、在有丢包的模拟双流链路上由 RFC 8888 反馈驱动带宽估计，以及 FEC
   恢复（组内突发、每种方案 5000 个包 5 % 随机丢包、经 RED 的 ULPFEC），逐字节核对恢复出的包。
   `rtp_rtcp` fuzz 目标把新包送入新处理器；新目标 `rtp_fec` 解析并重写 FEC 头与 RED，向解码器输入
   任意媒体 / FEC，并做一次编码器 → 有损解码器的往返，断言恢复逐字节一致。

未完成：接入 `akio-webrtc`。这需要 SDP 方面的工作（`a=rtcp-fb:* ack ccfb` 并切换估计器的反馈来源；
带 `a=ssrc-group:FEC-FR` FEC SSRC 的 `flexfec-03`，或 `red` + `ulpfec` 载荷类型；`a=rtcp-xr`）、
与估计器联动的 FEC 保护率策略，以及 RTCP 调度中的 TMMBR / XR，因此并不小；没有它就无法与 Chrome
核对 FlexFEC 或 RFC 8888（Chrome 只在协商后才发送二者）。同样未完成：FlexFEC 重传（R）与固定 L/D（F）
包、多个被保护 SSRC、ULPFEC 第 1 级、libwebrtc 的随机 / 突发掩码表（这里用交织掩码）、生成丢包 /
重复 RLE 与接收时间报告块，以及 VoIP 质量字段（R 因子、MOS）。

## 影响

- 除 `Rtcp` 枚举外均为新增：它多了四个变体（它没有 `#[non_exhaustive]`；树内的 match 已有通配分支）。
  以前解析为 `Rtcp::Unknown` 的包（PT 207、RTPFB 3 / 4 / 11）现在解析为新变体，这些类型中格式错误的
  包现在会报错。
- 没有新依赖；全部保持 `#![forbid(unsafe_code)]`。
