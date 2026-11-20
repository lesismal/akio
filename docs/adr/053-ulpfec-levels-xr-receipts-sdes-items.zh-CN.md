# ADR-053：ULPFEC 保护级别、由收包生成 XR 块、类型化 SDES 项

[English](053-ulpfec-levels-xr-receipts-sdes-items.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

only-rtp 的 README 列出了 ADR-036 留下的三处空缺：

- **ULPFEC 第 1 级。** `fec` 只读写单一保护级别的 ULPFEC，保护长度为被保护包中最长者。RFC 5109
  §5 / §7.4 允许一个 FEC 包携带多个级别：第 0 级保护其各包固定头之后的前 L0 字节（及其头部字段），
  第 1 级保护随后的 L1 字节，所保护的包集合可以不同，依此类推（不等级保护，ULP）。解析器忽略第 0 级
  载荷之后的一切；比保护长度更长的包根本无法重建。
- **生成 XR 块。** RFC 3611 的每种块都能解析和写出，但没有任何东西能根据接收方的所见生成丢包 RLE
  （§4.1）、重复 RLE（§4.2）或包接收时间（§4.3）块；VoIP 指标（§4.7）只有 `BurstLossModel` 给出的
  丢包 / 突发 / 间隙字段。
- **SDES 中类型 / 文本对以外的内容。** `Rtcp::SourceDescription` 存放 `(项类型, String)` 对。PRIV
  （RFC 3550 §6.5.8）由前缀长度字节、前缀和值组成；前缀长度大于 127 时不是 UTF-8，解析时被替换为
  U+FFFD。写出时在 255 字节处截断，可能截在字符中间。

约束：only-webrtc 构造 `Rtcp::SourceDescription(Vec<(u32, Vec<(u8, String)>)>)` 并解析 FEC 头，且另一个
会话正在修改它，所以该变体的类型保持不变，也不改动 only-webrtc。libwebrtc、Chrome 与 pion 都不使用
ULPFEC 多级保护，也不使用 RLE / 接收时间块，因此逐字节的参照是 RFC 示例和 pion/rtcp 的块写出器。

## 决定

1. **在 `fec` 中支持任意多个 ULPFEC 级别。**
   - `FecHeader` 新增 `ulp_levels: Vec<UlpLevel>`（偏移、保护长度及该级载荷的起始位置）；第 0 级载荷之后
     只要还有字节，解析器就继续读取级别头（第 0 级保护长度超出载荷时仍视为单级，与以前相同），截断的
     级别、超出末尾的载荷或空掩码会被拒绝。L 位作用于所有级别；`FecHeader::write_level(i)` 写出级别头。
   - `FecEncoder::encode_ulp(media, fec)` 按显式级别构造 FEC 包（每级一个
     `UlpLevelSpec { mask, protection_len }`，第 0 级在前），并检查 §7.4 的规则：一个包在第 0 级以上每级
     至多被保护一次；在第 0 级被多次保护时保护长度必须相同；仅当某处在第 p - 1 级保护了它，才能在第 p
     级保护它。头部字段取自第 0 级的包（§8.1；RFC 5109 §10.2 的图中 M = 0，勘误 3461 确认以正文为准）。
     SN base 仍是组内最小序号，与以前及 libwebrtc 一致。
   - `FecEncoder::set_ulp_level0(Some(l0))` 是现成的方案：组内交织的各 FEC 包保护每个包的前 `l0` 字节
     （及头部），最后一个 FEC 包另带覆盖全组其余部分的第 1 级。每组丢一个包时可完整恢复，丢多个时恢复
     各包的开头（CSRC、扩展头、载荷描述符）；修复字节从 `m * longest` 降到约 `m * l0 + longest - l0`。
     默认 `None`：与以前完全相同的整包保护。仅适用于实现了多级保护的接收方：libwebrtc 的 ULPFEC
     读取器只读第 0 级，因此发往 Chrome 时，长于 `l0` 的丢失包会被错误重建；only-webrtc 仍使用整包
     ULPFEC。
   - 解码器分段重建包：每个收到或重建的包记录头部是否已知以及已知的字节区间；某一级在其区间上除一个包
     以外都已知时，即可重建那个包的该区间（第 0 级还重建头部与长度），顺序不限——第 1 级的区间可以在
     头部已知之前重建。包完整后才返回；`FecDecoder::partially_recovered()` 统计其余的包。单级 FEC
     （libwebrtc 的 ULPFEC、两种 FlexFEC）走同一路径，只有一个覆盖全部的区间。
2. **由收包生成 XR 块。** `ReceiptLog`（针对一个源）在至多 65533 个序号的区间内（§4.1 禁止 65534 及
   以上）记录每个包首次到达的时间与重复情况，序号按附录 A.1 的要求展开（与上一个相差 32768 以内，
   恰好相等时取不回绕的一方）。它为任意稀疏化因子生成丢包 RLE（1 = 收到）、重复 RLE（0 = 有重复，按
   §4.2 的定义）与接收时间块；接收时间采用 RTP 时钟、以首包时间戳为锚点（§4.3 要求可比较的单位），
   每段连续收到的被报告序号各一个块（接收时间块不得覆盖丢失的包）。`RleReport::encode` 对 15 个及以上的
   连续相同值或轨迹末尾使用游程块，其余使用位向量：正好是 §4.1 示例中的第二种编码。
   `RleReport::decode` / `reported_seqs` 将块读回。`RecvStream::enable_receipt_log` 让 `receive` 喂给一个
   日志（FEC 重建的包仍计为丢失，与接收报告一致），`receipt_blocks` 返回所选的块并开始下一区间。
3. **完整的 VoIP 指标。** `BurstLossModel::report(ssrc, packet_ms, &VoipQuality)` 补上只有应用知道的字段：
   往返时延与端系统时延、信号 / 噪声电平、RERL、R 因子与 MOS（超出范围的值按 §4.7.5 的要求发送为
   127）、PLC 与抖动缓冲（接收端配置字节、标称 / 最大 / 绝对最大时延）。本 crate 不计算任何质量分数
   （G.107 的 E 模型需要 RTP 层没有的编解码器损伤因子）；`pcm_level_dbm0` 从 16 位 PCM 测量电平（满幅
   正弦 = +3.14 dBm0）。
4. **不改变变体的类型化 SDES 项。** `SdesItem`（`Text { item_type, text }`、`Priv { prefix, value }`）与
   二元组互相转换，并为每个已注册类型提供常量（CNAME .. MID，IANA 注册表：H323-CADDR、APSI RFC 6776、
   RGRP RFC 8861、RtpStreamId / RepairedRtpStreamId RFC 8852、CCID RFC 8849、MID RFC 9143）。在二元组形式
   中，PRIV 的前缀长度是第一个 `char`（U+0000..=U+00FF，线上占一个字节），因此长度最大 255 都能保留；
   长度小于 128 时文本与以前逐字节相同。文本（及 BYE 原因）在字符边界处截断到 255 字节。`random_cname`
   给出 RFC 7022 的短期持久 CNAME（96 个随机位的 base64）。RFC 6051（快速同步）定义的是头部扩展与反馈
   消息，不是 SDES 项，不在本次范围内。

## 影响

- 测试（`crates/only-rtp/src/tests_levels.rs`）：逐字节核对 RFC 5109 §10.2 示例（含勘误 3461）；逐个
  单包丢失的恢复（B、C 完整恢复，A、D 恢复到 L0 + L1）；第 1 级先于第 0 级到达；丢两个包（只恢复开头，
  迟到的包到达后再补全其余部分）；级别规则；长掩码与畸形级别；有损链路上的第 0 级模式（400 帧，每帧
  2..12 个包，10 % 丢包：每个单包丢失都被恢复，返回的每个包都与原包相同，L0 = 0、40、100 时修复字节都
  少于整包 FEC）。由喂入的日志生成 RFC 3611 §4.1 示例（45 个包，丢两个或三个，T = 0 与 T = 2）；与
  pion/rtcp v1.2.20 逐字节一致的丢包 / 重复 RLE 与接收时间块；300 条随机轨迹在稀疏化与回绕下经
  encode / decode 往返；跨 16 位回绕、含重复的接收日志，容量、区间与相等距离规则；`RecvStream` 集成。
  VoIP 报告字段与 `pcm_level_dbm0`。与 pion/rtcp v1.2.20 逐字节一致的含 PRIV、MID、RtpStreamId 的
  SDES；200 字节的 PRIV 前缀；截断；RFC 7022 向量。
- pion 的 RLE 写出器在块数为奇数时漏掉所需的空块（其块长度因此少一个字）；pion 向量使用偶数个块，奇数
  情况按 RFC 3611 正文核对。
- 模糊测试：`rtp_rtcp` 将每个解析出的 SDES 二元组转为项再转回，重新编码每个解析出的 RLE 块的轨迹，
  用解析出的块构造 VoIP 报告，并用 RTP 载荷喂给接收日志（其块写出后能解析回来，且从不把未收到的包
  报告为收到）；`rtp_fec` 重写解析出的 ULPFEC 级别，以第 0 级模式运行编码器，并编码显式的两级 FEC 包，
  其单包丢失必须精确恢复。每个目标在 gpu51 上运行 16 分钟：`rtp_rtcp` 290 万次、`rtp_fec` 159 万次，
  代码中没有发现问题（更早的一次运行发现的是目标自身过严的检查，已作为回归输入保留）。
- API 均为新增，只有 `FecHeader` 的新字段除外（only-rtp 属内部层级；结构体字面量需加上
  `ulp_levels: Vec::new()`）：`fec::{UlpLevel, UlpLevelSpec}`、`FecHeader::write_level`、
  `FecEncoder::{set_ulp_level0, encode_ulp}`、`FecDecoder::partially_recovered`、`ReceiptLog`、
  `MAX_XR_SPAN`、`RleReport::{encode, decode, reported_seqs}`、
  `RecvStream::{enable_receipt_log, receipt_log, receipt_blocks}`、`VoipQuality`、`Plc`、
  `JitterBufferConfig`、`BurstLossModel::report`、`pcm_level_dbm0`、`SdesItem`、`random_cname`。行为变化：
  解析出的前缀长度大于 127 的 PRIV 项保留该长度（为 U+0080..U+00FF），不再变成 U+FFFD；写出的文本在
  字符边界处截断。
- 未做：接入 only-webrtc（在其 XR 中发送 `ReceiptLog` 的块或 VoIP 指标、在音视频线路上使用
  `set_ulp_level0`、用 `random_cname` 生成随机 CNAME）——因另一个会话负责 only-webrtc，留作后续工作。
  不交出部分恢复的包（解包器需要能接受截断的载荷）。不估算 R 因子 / MOS。
