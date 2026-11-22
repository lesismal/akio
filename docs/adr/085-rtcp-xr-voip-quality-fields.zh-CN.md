# ADR-085：RTCP XR VoIP 指标中与编解码器相关的字段：按编解码器的 G.107 / G.107.1，应用提供的值

[English](085-rtcp-xr-voip-quality-fields.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-058 为接收的音频发送 RTCP XR VoIP 指标（RFC 3611 §4.7），ADR-073 加入 E-model 来填写 R 因子、
MOS-LQ 与 MOS-CQ。其“未完成”一行仍留着“与编解码器相关的 VoIP 质量字段”，已有的实现有三处不足：

- **所有编解码器一个模型。** 每个流都按带丢包隐藏的 G.711（`Ie = 0`、`Bpl = 25.1`）评分，Opus 与
  G.722 通话的得分与 G.711 相同，接收方配置字节也不说明丢包隐藏。
- **时延损伤用的是近似。** Cole 与 Rosenbluth 的拟合（`Id = 0.024 d + 0.11 (d - 177.3) H`）在约
  300 ms 以内与 G.107 的默认曲线吻合，之后偏离（400 ms 时 34.1 对 31.1，500 ms 时 47.5 对 38.6）。
- **应用无从提供数值。** akio-webrtc 把未解码的音频交给应用：它没有抖动缓冲，也看不到采样，因此信号
  与噪声电平、残余回声回损、抖动缓冲字段与端系统时延只能来自应用，而此前没有提供它们的 API。

## 决定

### 1. E-model（akio-rtp）

- `EModel` 按 G.107 §7 计算，接收方无法测量的参数都取表 3 默认值：`No`、`Ro`（94.77）与
  `Is = Iolr + Ist + Iq`（1.41）按公式算出，完整的时延损伤 `Id = Idte + Idle + Idd` 取 `Ta = T`、
  `Tr = 2T`（TELR 65 dB 的讲话者回声、WEPL 110 dB 的听者回声、超过 `mT` = 100 ms 的绝对时延）。无损伤时
  R = 93.21。`EModel::delay_impairment` 签名不变，现在给出这个 `Id`。
- **宽带编解码器**按 G.107.1：`R_wb = 129 - Id - Ie,wb,eff`，
  `Ie,wb,eff = Ie,wb + (129 - Ie,wb) Ppl / (Ppl / BurstR + Bpl)` 中以 129 代替 95，评分再除以 1.29
  换算到 VoIP 块的 R 字段与 MOS 公式所用的窄带刻度。无损伤的宽带通话评为 100（MOS 4.5），无损伤的
  G.711 通话为 93.2（MOS 4.41）。`EModel::wideband(ie_wb, bpl_wb)`、`EModel::is_wideband`。
- **编解码器表**：`EModel::for_codec(name, plc)`，按 SDP 编码名：

  | 编码 | 刻度 | Ie | Bpl | 来源 |
  |---|---|---|---|---|
  | PCMU、PCMA | 窄带 | 0 | 25.1，`Plc::Disabled` 时 4.3 | G.113 附录 I（G.711 附录 I 的 PLC） |
  | G729 | 窄带 | 11 | 19 | G.113 附录 I（G.729A + VAD） |
  | G723 | 窄带 | 15 | 16.1 | G.113 附录 I（G.723.1 6.3 kbit/s + VAD） |
  | G722 | 宽带 | 13 | 4.3 | G.113 附录 IV 64 kbit/s 的 `Ie,wb`；G.107.1 的默认 `Bpl` |
  | opus | 宽带 | 0 | 25.1 | 无 ITU-T 值：假定 |

  G.722 的丢包隐藏是可选的（附录 III、IV），因此不给它抗丢包加分。ITU-T 没有 Opus 的规划值（文献中有
  仪器化推导，但不在 G.113 中）：假定它在 WebRTC 使用的码率下是透明的，即宽带参考 `Ie,wb = 0`，丢包
  隐藏与 G.711 附录 I 一样稳健。两者都写在文档里；`EModel::codec` / `EModel::wideband` 可传入实测值。
- `Plc::of_codec(name)`：解码器总会做的丢包隐藏：Opus（RFC 6716 §4.4）为 `Enhanced`，G.729 与
  G.723.1 为 `Standard`，其余为 `Unspecified`。
- `EModel::estimate_report(&BurstLossModel, &VoipQuality, jitter, packet)`：根据至今的丢包、其突发比
  （由突发 / 间隙段得出的 G.107 BurstR）、往返时间与端系统时延估算：端系统时延用应用给出的值，否则用
  已知抖动缓冲的标称时延加一个包，否则用两倍到达间隔抖动加一个包。`EModelScore::fill` 只填写仍为
  `None` 的评分字段。
- `VoipMetrics::quality()`：时延、电平、评分与接收方配置字段上 `BurstLossModel::report` 的逆运算（127、
  超出范围的评分、为零的时延以及未知或保留的抖动缓冲类型都成为 `None`），使收到的块读作有类型的值。

### 2. akio-webrtc

- 每个接收音频流的报告使用所收编解码器的表项与丢包隐藏（表中没有的编解码器按带丢包隐藏的 G.711）；
  除非应用另有说明，RX config 携带 `Plc::of_codec`；Gmin 仍为 16。
- `Peer::set_voip_quality(mid, VoipQuality, Option<EModel>)`：应用对它解码、播放的音频所知道的：信号与
  噪声电平（`pcm_level_dbm0`）、RERL、抖动缓冲（标称 / 最大 / 绝对最大、是否自适应、调整速率）、端系统
  时延、它的丢包隐藏、外部段的 R 因子，以及它自己的 R / MOS（此时替代估算值）。给出的抖动缓冲或端系统
  时延也会改善估算。模型替代编解码器表中的值。仍为 `None` 的照旧作为不可用发送（电平与评分为 127，
  时延为 0，抖动缓冲类型为未知）。
- 收到的 VoIP 指标仍为 `VoipMetrics` 事件（文档中注明 `VoipMetrics::quality`）；`PeerStats` 不变。

### API

仅新增。akio-rtp：`EModel::{wideband, is_wideband, for_codec, estimate_report}`、
`EModelScore::fill`、`Plc::of_codec`、`VoipMetrics::quality`。akio-webrtc：`Peer::set_voip_quality`。
签名不变而行为改变的：`EModel::delay_impairment` 与 `EModel::score` 使用 G.107 完整的 `Id` 与计算出的
`Ro - Is`（原来的常数 93.2 现为 93.21），akio-webrtc 的报告按编解码器评分。

## 影响

- 测试（akio-rtp `tests_voip.rs`、`emodel.rs`）：G.107 默认值（`No` -61.18、`Ro` 94.77、`Is` 1.41、
  R 93.2、MOS 4.41）；ITU-T SG12 G.107.1 计算器的默认结果（R 128.8、MOS 4.50）；G.109 表 1 的 R / MOS
  对；按 §7.4 手算的 `Id`：150 ms 为 3.82、300 ms 为 20.69，300 ms 以内与 Cole 和 Rosenbluth 的拟合相差
  不到 1 分，单调；G.113 的 `Ie,eff` 例子（G.729A 在 2 % 随机与突发丢包下，G.711 有无丢包隐藏，宽带刻度
  上的 G.722）；丢包下各编解码器的排序；`estimate_report` 对端系统时延的选择与 `fill`；VoIP 块经线路
  往返后还原为同一个 `VoipQuality`（固定与自适应缓冲、保留类型、超出范围的评分）。`rtp_rtcp` 模糊测试
  目标检查解码在再次报告后保持不变，且每种编解码器的估算都在范围内。akio-webrtc（`tests_mux.rs`，模拟
  网络）：10 % 丢包下的 Opus 按宽带评分、带增强丢包隐藏、电平不可用；应用给出的电平、RERL、外部 R、丢包
  隐藏与抖动缓冲按原样到达发送方，它选择的编解码器模型使 R 低于对端默认的 Opus，它自己的评分替代估算值。
- 开销：协商了 VoIP 指标时，每个接收音频流每秒一次估算（几十次 `pow` / `log`）；否则没有。没有改动热
  路径，因此未做 A/B。
- 未完成：Opus 全带码率下的 G.107.2 全带模型；随协商码率变化的编解码器值（Opus、48 / 56 kbit/s 的
  G.722、不带 VAD 的 G.729）；带附录丢包隐藏的 G.722 的 `Bpl,wb`；在 akio-webrtc 内测量抖动缓冲（它没有
  抖动缓冲）。

## 更新（2026-11-22）：ADR-087

ADR-087 完成了本 ADR 的"未完成"各项：G.107.2 全频带、按码率的编解码器取值
（`EModel::for_codec_rate`）、带附录 III / IV 丢包隐藏的 G.722 的 `Bpl,wb`，以及 akio-webrtc
中的抖动缓冲（`RtcConfig::set_audio_jitter_buffer`），由它填写抖动缓冲与丢弃字段。

它还按 G.107.1（06/2019）及其勘误 1 更正了上文的宽带模型：

- `Ie,eff,WB` 中应为 95，本 ADR 写成了 129。
- `Id,WB` 有自己的讲话者回声项与 `1.29 Idd`。

G.722 现在取 G.113 的双耳 `Ie,wb`（5），不再用单耳的 13。上文的编解码器表由 ADR-087 的表取代。
