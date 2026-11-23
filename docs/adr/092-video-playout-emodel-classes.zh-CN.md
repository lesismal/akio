# ADR-092：视频播放缓冲，E-model 时延敏感度等级与房间噪声，VoIP 包长与迟到丢弃

[English](092-video-playout-emodel-classes.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

ADR-087 的"未完成"清单里留下了这些项：

- 视频帧一经帧组装器拼完整就交出，没有播放定时。
- 时延敏感度等级（`sT` / `mT`）固定为"默认"。
- 没有按 03/2023 版由房间噪声计算 `Ro,FB`。
- 没有采用已发表的 Opus 值，单耳宽带表也不可选。
- VoIP 块的突发与间隙时长假定包长 20 ms。
- 某包在一个报告区间被报为丢失，之后的区间里才被丢弃，这种情况没有对上。

重新阅读了原文：G.107（06/2015）、G.107.1（06/2019 + 勘误 1）、G.107.2（06/2019 与 03/2023）、
G.113（09/2024 + 01/2026 的 Erratum 1）。各文档的规定如下：

- **时延等级。** G.107 §7.4 表 1 有三个等级：Default（`sT` 1，`mT` 100 ms）、Low（0.55，120）、
  Very low（0.4，150）。
  - 电信级与企业级电话"必须"用默认等级；不清楚用户或场景时也用默认等级。用了其他等级，应随结果
    注明。
  - G.107.2（03/2023）数值相同，等级名为 Default / Medium / Low，规则相同。
  - G.107.1 没有等级：它的 `Idd` 就是默认等级的，乘 1.29。
- **房间噪声。** G.107.2（03/2023）式 7-2 至 7-6 由噪声推出 `Ro,FB`，`Nc` 与 `Nfo` 取 -96 dBm0p
  （表 2）。该版各处都没有给房间噪声 `Ps` / `Pr` 的默认值。
  - 套用 G.107 的 35 dB(A)，`Ro,FB` 是 121.5 而不是 148：每个全频带通话都低 26.5 分。
  - G.107.1 把 `Ps` / `Pr` 列为"研究中"。
- **单耳表。** G.113 表 IV.1 给出单耳（手柄）的暂定 `Ie,wb`：G.722（64 / 56 / 48 kbit/s 下为
  13 / 20 / 31）、按模式的 G.722.2（6.6 时 41 .. 23.05 时 1，23.85 时 8）及其他。它不给 `Bpl,wb`；
  `Bpl,wb` 只出现在双耳表里。
- **Opus。** G.113 与 P.833.2 都没有出现 Opus。
  - Alahmadi、Pocta、Melvin 发表了窄带与宽带 Opus 1.2.1 的仪器法（POLQA，P.834）`Ie` 与 `Bpl`
    （ISSC 2020，doi:10.1109/ISSC49989.2020.9180160），只覆盖低码率：NB 6..11 kbit/s，
    WB 11..15 kbit/s。
  - 论文需付费。数值取自作者公开的博士论文（NUI Galway，2020，表 5.8、5.9、5.13、5.14），
    论文中说明这些值发表在上述会议论文里。
- **EVS。** G.113 只有 EVS 的 SWB 模式（附录 V），它的 NB、WB 模式没有数值。

## 决定

### 1. 视频播放缓冲（akio-rtp `VideoPlayout<T>`）

`VideoPlayout<T>` 是 sans-IO 的，按帧组装器给出的解码顺序保存一路视频的完整帧。

- **输入。** `push(ts, completed, flags, data, bytes)`。标志（`VideoFrameFlags`）有：
  - `KEYFRAME`；
  - `DISCONTINUOUS`（此帧前有包缺失）；
  - `REPAIRED`：由重传补齐，或在一个正被修复或放弃的包后面等待。
- **输出。** `pop(now)` 按顺序在各帧的播放时刻交出帧，`poll_timeout()` 给出下一帧何时到期。
- **播放。** 帧在 `ts + offset` 播放。offset 是最小传输时间（完成时刻减媒体时间，取两个 5 s
  窗口的最小值）加目标时延。
  - 帧不会在完整之前、也不会在前一帧之前播放。
  - 帧完整后等待的时间不超过上界。
- **目标。** 取以下各项的最大值：
  - 各帧超出最小传输时间的时延的 95 百分位（2 ms 桶，每帧按 0.997 遗忘）；
  - 最近 10 s 内最近两个关键帧各自的时延。

  若最近 10 s 内有帧需要修复，再加往返时间（`set_round_trip`）。全部限制在 `PlayoutDelay` 的界内。
  - **关键帧。** 关键帧比其间的帧大许多倍，到达更慢。它们数量太少，推不动百分位，但一个迟到的
    关键帧会卡住其后的所有帧。
  - **NACK。** 修复过的帧不进直方图（它们的时延是修复造成的）。往返时间为一次重传留出余地；
    libwebrtc 在只靠 NACK 保护一路流时，抖动估计也加上 RTT。
- **调整。**
  - 时延变长立即生效。
  - 时延变短在关键帧处立即生效（预测从这里重新开始，播放器可以跳过）；其他时候每秒最多缩短
    一个帧间隔。
  - 因时延变短而到期的缓冲帧在变更的那一刻播放，不会更早。
- **迟到帧**立即交出并计数，不丢弃：后面的帧要以它为参考预测。
- **上界。** 最多 256 帧、16 MiB。
  - 满时，丢弃最旧帧之后第一个缓冲关键帧之前的帧。
  - 没有这样的关键帧时，丢弃最旧的一帧，`take_keyframe_request()` 表示需要关键帧。
  - 丢弃之后的那一帧 `contiguous = false`。
- **时钟跳变。** 相邻两帧之间，媒体时间与完成时间的差变化超过 10 s 时，缓冲的帧立即交出，时钟
  重新开始（`resyncs`）。
- **统计。** `VideoPlayoutStats`：received、played、late、repaired、dropped、resyncs、delay、
  target。
- **共用估计器。** 音频 `JitterBuffer` 与 `VideoPlayout` 现在共用一个时延估计器（`delay.rs`）：
  最小值窗口和遗忘直方图。音频缓冲的行为不变。

akio-webrtc：

- `RtcConfig::set_video_playout_buffer(Option<PlayoutDelay>)`，默认关闭，只在帧模式下起作用。
- 开启时，各视频组装器拼完整的帧进入该流的缓冲，由 peer 的定时器交出。
  - `MediaData::playout_time` 带出播放时刻。
  - 由经 RTX 到达的包放出的帧，或与缺口后的帧一起或在其后出来的帧，标为已修复。
  - 往返时间取该流的，仅用于带 `nack` 的线路。
  - 因没有可恢复的关键帧而丢帧时，在带 `nack pli` 的线路上发送 PLI。
- 缺失的包仍由组装器按包数放弃（`set_reordering_size`），不按播放截止时间。
- `Peer::video_playout_stats(mid) -> Vec<(ssrc, VideoPlayoutStats)>`。

### 2. E-model（akio-rtp）

- **`DelaySensitivity`** { `Default`, `Low`, `VeryLow` }，配 `EModel::with_delay_sensitivity` 与
  `delay_sensitivity`。
  - `Idd` 采用 `sT` 与 `mT`（G.107 式 7-27 / 7-28；G.107.2 式 7-8b，乘 1.48）。
  - 宽带模型保持默认等级：G.107.1 没有等级。
  - akio-webrtc 中，`RtcConfig::set_voip_delay_sensitivity` 把等级用到编解码器的模型上。应用自己
    给出的模型保留它自己的等级。
- **`EModel::with_room_noise(send, receive)`**（dB(A)，钳到 0..=85）。接收端无法测量房间噪声，
  由应用提供。
  - 窄带：G.107 的 `Ps` / `Pr` 进入 `No`，从而影响 `Ro`、`Is` 与讲话者回声。默认 35。
  - 全频带：`Ro,FB` 由 G.107.2（03/2023）式 7-2 至 7-6 算出。35 dB(A) 时 121.48，0 时 147.29，
    50 时 96.29。
  - 宽带：忽略。
  - 不给房间噪声时，全频带仍为 148，评分不会悄悄改变。
  - `EModel::max_rating()` 给出模型自身刻度的最高值。
- **`EModel::for_codec_monotic(name, plc, bitrate)`。** G.722 与 AMR-WB 取表 IV.1 的单耳
  `Ie,wb`，`Bpl,wb` 用双耳的（唯一发表的）。其他编解码器与 `for_codec_rate` 相同。
- **`EModel::opus(OpusBand, bitrate)`**：
  - 窄带：G.107 刻度，6..9 kbit/s 下 VBR `Ie` 23 .. 11.7，随机丢包 `Bpl` 24.6 .. 18.9（博士论文
    表 5.13 / 5.14）。
  - 宽带：11..13 kbit/s 下 `Ie,wb` 28.4 .. 20，`Bpl,wb` 23.9 .. 19.5（表 5.8 / 5.9）。
  - 全频带：ADR-087 的值（DAGA 2021 的 `Ie,FB`，EVS 的 `Bpl,fb`）。
  - 高于表中码率的取最高码率的值，这会低估这些码率下的 Opus。
  - RTP 编码名看不出频带，所以 `for_codec_rate("opus", ..)` 仍按全频带。应用通过
    `Peer::set_voip_quality` 的模型选择频带。
  - 没有采用 CBR 列和 SWB 表（148 刻度，`Rswb = 1.48 Rnb`）：WebRTC 的 Opus 是 VBR、全频带，
    DAGA 2021 测的就是全频带。
- **EVS NB / WB** 不纳入：没有发表的数值。已在 `for_codec_rate` 中说明。

### 3. VoIP 指标（akio-webrtc）

- **包长。** 每路接收的音频流由相邻序号的时间戳测出包长（`PacketTime`）。不超过当前值两倍的步长
  才替换它，DTX 静音不会被当成一个包。
  - 有抖动缓冲时以它的帧长为准。测出包长之前用 20 ms。
  - 包长决定突发与间隙时长（取整到 ms）、E-model 评分所用的码率，以及 E-model 的包时延。
- **跨区间的迟到丢弃。**
  - 记住每个报告给出的丢失序号：最多 1024 个，最旧的先丢弃。
  - 某个被丢弃的序号不在当前区间内，却在这些记录之中，说明它曾被报为丢失、之后迟到。
    `BurstLossModel::on_late_discard()` 把一次计数从丢失移到丢弃。突发 / 间隙状态和 E-model 用的
    丢失比例都不变：两者对模型都是丢失。
  - 被报为丢失、之后到达并且被**播放**的包，仍计为丢失：接收日志的区间已经过去，突发模型也没有
    "其实没丢"这一说。

### API

改动是新增的。

- akio-rtp：
  - `VideoPlayout`、`VideoPlayoutFrame`、`VideoPlayoutStats`、`VideoFrameFlags`。
  - `VIDEO_PLAYOUT_MAX_FRAMES`、`VIDEO_PLAYOUT_MAX_BYTES`。
  - `DelaySensitivity`、`OpusBand`。
  - `EModel::{with_delay_sensitivity, delay_sensitivity, with_room_noise, max_rating,
    for_codec_monotic, opus}`。
  - `BurstLossModel::on_late_discard`。
- akio-webrtc：`RtcConfig::{set_video_playout_buffer, set_voip_delay_sensitivity}` 与
  `Peer::video_playout_stats`。

API 未变但行为变化的：

- XR VoIP 块的时长与码率按测得的包长计算，不再总是 20 ms。
- 前一区间报为丢失的包，在之后迟到丢弃时，现在计为丢弃。

## 后果

- **测试，akio-rtp `tests_video.rs`。** 由 VP8 包拼出的帧经过 `FrameAssembler` 与缓冲，模拟抖动、
  乱序与丢包：
  - 0..40 ms 抖动下 1800 帧：完成时刻分散超过 30 ms，播放分散小于 25 ms，最多 1/20 的帧显示
    不均匀，时延 30..50 ms。
  - 1% 丢包、60 ms RTT 重传。不加往返时间时目标低于 30 ms，修复过的帧迟到；加上后目标为 RTT 加
    抖动，迟到帧降到三分之一或更少。
  - 每 2 s 一个 40 包的关键帧：目标覆盖它们的 40 ms。关键帧让画面停顿最多 10 ms 的抖动。
  - 修复余量 10 s 后过期。
  - 时延在关键帧处立即缩短，关键帧之间每秒最多缩短一帧。
  - 上界：帧数、字节数、按关键帧丢帧、请求关键帧。
  - 不超过上界、时钟跳变、时间戳回绕。
- **测试，`tests_voip.rs`**（期望值由公式独立算出，不依赖代码）：
  - 各等级的 `Idd`：Low 在 200 / 300 ms 为 2.253017 / 10.094228；Very low 在 200 / 300 ms 为
    0.949825 / 6.178555。
  - 房间噪声：窄带 `Ro - Is` 在 35 / 50 / 60 dB(A) 为 93.3553 / 86.4917 / 70.4164；全频带
    `Ro,FB` 在 35 / 0 / 50 dB(A) 为 121.4849 / 147.2859 / 96.2943。
  - 单耳表各行、Opus NB / WB 各行，以及 9 kbit/s 窄带 Opus 在 2% 丢包下（`Ie,eff` 19.6713）。
  - 时长随包长缩放，以及 `on_late_discard`。
- **测试，akio-webrtc `tests_mux.rs`**：
  - 两个 peer 以 30 帧/s 传 VP8，经 10..50 ms 时延与 2% 丢包，由 NACK / RTX 修复。每帧都在其播放
    时刻按顺序交出。91% 的帧按一个帧间隔显示，而完成时刻只有 15%。时延约 80 ms（抖动加一个往返）。
  - 被报丢失、下一区间被丢弃的包：丢失 / 丢弃率从未匹配时的 (22, 0) 变为 (18, 3)。
  - 40 ms 包给出以 40 ms 为步长的时长。
  - 三个时延等级对 250 ms 的评分按顺序排列。
- **模糊测试。** `rtp_rtcp` 目标用任意步长、标志与大小驱动一个 `VideoPlayout`，检查顺序、上界，
  以及从不在完整之前或超过上界后播放。它还用模糊的等级、房间噪声、单耳表与 Opus 频带评分。
- **代价**：见 BENCHMARKS 的"视频播放缓冲（ADR-092，同轮 A/B）"。
- **未完成**：
  - 在帧的播放截止时间放弃缺失的视频包。组装器仍按包数放弃。
  - 考虑帧大小的抖动估计（libwebrtc 的卡尔曼滤波）：关键帧靠测得的时延覆盖。
  - 从 SDP（`maxplaybackrate`）选择 Opus 频带。
  - 被报丢失、之后到达并被播放的包。
  - EVS NB / WB 的数值（未发表）。
  - 时间伸缩，仍是解码器的职责。
