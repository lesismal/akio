# ADR-087：全频带与按码率的 E-model，以及 only-webrtc 中的音频抖动缓冲

[English](087-fullband-emodel-audio-jitter-buffer.md) | 简体中文

状态：已接受（2026-11-22）

## 背景

ADR-085 为 RTCP XR VoIP 指标用 E-model 评估收到的音频。它留下了四件事没做：G.107.2（全频带）、
随码率变化的编解码器取值、G.722 带附录丢包隐藏时的 `Bpl,wb`，以及 only-webrtc 里的抖动缓冲。
only-webrtc 目前在音频帧一到达就交给应用。

重新阅读现行文本后发现，ADR-085 的宽带模型并不是 G.107.1（06/2019，含 01/2020 的勘误 1）：

- 式 7-15 是 `Ie,eff,WB = Ie,WB + (95 - Ie,WB) Ppl / (Ppl + Bpl)`。ADR-085 在该写 95 的地方
  用了 129。
- `Id,WB` 有自己的讲话者回声项：`Roe = -1.5 (-69 - RLR)`（勘误 1）、`Re,WB = 80 + 3
  (TERV,WB - 14)`，`TERV,WB` 中还有 `K` 项。它的 `Idd` 是 G.107 的 1.29 倍。ADR-085 用的是
  `Ro` 取 129 的窄带 `Id`。

数值取自 ITU-T PDF：G.107（06/2015）、G.107.1（06/2019 + 勘误 1）、G.107.2（06/2019 与
03/2023）、G.113（09/2024，含 01/2026 的勘误 1）。

## 决定

### 1. E-model（only-rtp）

- **宽带模型按 G.107.1 及其勘误 1 改正**：`R = 129 - Id,WB - Ie,eff,WB`，采用它的讲话者回声
  项、`1.29 Idd`，式 7-15 中用 95。G.107.1 没有突发比，这里保留 G.107 的 `Ppl / BurstR`；
  随机丢包时它与式 7-15 完全一致。
- **全频带（G.107.2）**：`EModel::fullband(ie_fb, bpl_fb)`、`with_burst_robustness(brf)`、
  `is_fullband`。
  - `R = 148 - 1.48 Idd - Ie,eff,FB`，其中 `Is,FB = 0`、`A = 0`，时延敏感度取 "default" 类。
  - `Ie,eff,FB = Ie,FB + (132 - Ie,FB) (Ppl - (1 - BurstR) / Brf) / (Ppl + Bpl)`（03/2023 版
    式 7-10，比例限制在 0..=1）。
  - `Ro,FB` 取量表上限 148，与 06/2019 版相同。03/2023 版由噪声电平推导它，但没有给出室内
    噪声 `Ps` / `Pr` 的默认值；不计室内噪声时，该公式得 147.5。
  - R 字段与 MOS 取 `R / 1.48`（附件 A），宽带对应取 `R / 1.29`。
  - `EModel::scaled_delay_impairment(d)` 给出模型自身量表上的时延损伤。
- **按码率的编解码器取值**：`EModel::for_codec_rate(name, plc, bitrate)`。
  `for_codec(name, plc)` 等同于不给码率。码率落在两档之间时取较低一档；低于最低档时取最低档。

  | 编码 | 量表 | Ie | Bpl | 来源 |
  |---|---|---|---|---|
  | PCMU、PCMA | 窄带 | 0 | 25.1（无 PLC 时 4.3） | G.113 表 I.4 |
  | G729 | 窄带 | 11 | 19 | 表 I.4（G.729A + VAD） |
  | G723 | 窄带 | 15（低于 5.8 kbit/s 时 19） | 16.1 | 表 I.1、I.4 |
  | G722 64 kbit/s | 宽带 | 5 | 附录 III PLC（`Enhanced`）7.1、附录 IV（`Standard`）5.1，否则 4.3 | 表 IV.3、IV.4 |
  | G722 56 / 48 kbit/s | 宽带 | 10 / 41 | 4.3 | 表 IV.3 |
  | AMR-WB | 宽带 | 56（6.6）.. 8（23.05）、10（23.85）；无码率时按 12.65 | 12.65 / 23.05 / 23.85 时 4.3 / 4.6 / 4.9，其余 4.3 | 表 IV.3、IV.4 |
  | EVS | 全频带 | 22.7（9.6）.. 7.2（24.4）.. 10.2（48）；无码率时按 13.2 | 13 .. 9.3；13.2 时 `Brf` 3.28 | 表 V.3（SWB 模式） |
  | opus，有码率 | 全频带 | 37.85（13 kbit/s）.. 0（48），线性插值 | 同码率的 EVS 值 | 由 P.863 推导，DAGA 2021（非 ITU-T） |
  | opus，无码率 | 宽带 | 0 | 25.1 | 假设（ADR-085） |

  - 宽带取值用 G.113 的双耳（耳机或扬声器）数据：这几张表附带 `Bpl,wb`，而丢包正是这些指标
    关心的。单耳（手柄）的表 IV.1 给 G.722 的值是 13 / 20 / 31，可以用 `EModel::wideband`
    传入。因此 G.722 的 `Ie,wb` 从 ADR-085 的 13 变为 5。
  - 不带 VAD 的 G.729 用 `EModel::codec(10.0, 19.0)`：`Ie` 取表 I.1，`Bpl` 取唯一公布的
    G.729A + VAD 那一个。
  - ITU-T 没有公布 Opus 的规划值。有码率时，Opus 取 Michael、Mittag 与 Möller 依 P.863 为
    Opus 1.3 推导的 `Ie,FB`（DAGA 2021，表 2）；没有公布 Opus 的 `Bpl`，因此假设它的
    `Bpl,fb` 与同码率的 EVS 相同。
  - `Plc::of_codec` 新增 EVS（`Enhanced`）与 AMR / AMR-WB（`Standard`）。
- **only-webrtc 的码率**：每包载荷比特数除以包长。包长取抖动缓冲测得的帧长，没有则取
  20 ms。2 字节及以下的包（Opus DTX）不计入。统计按每个报告间隔进行，所以 Opus 按实际码率
  评为全频带。

### 2. 抖动缓冲（only-rtp）

`JitterBuffer<T>` 不做 I/O，管理一条单包成帧的流。帧用
`push(ext_seq, ts, marker, arrival, data, bytes)` 放入，用 `pop(now)` 按序号顺序、在各自的
播放时刻取出；`poll_timeout()` 给出下一帧何时到期。

- **播放时刻**：`ts + offset`。offset 是近来最小的传输时间加目标时延。最小传输时间取两个
  5 s 窗口内的最小值，因此时钟漂移和路由变化会让它移动。
- **目标时延**：每个包超出该最小值的时延的第 95 百分位，取自一个 2 ms 分桶的直方图，每个包
  按 0.997 遗忘（50 包/秒时约 7 s），并限制在 `PlayoutDelay` 的范围内。每 8 个包重算一次，
  遇到晚于目标的包时立即重算。
  - `PlayoutDelay::adaptive(min, max)`（默认 0..500 ms）或 `fixed(d)`，最大 2 s。
- **调整**：
  - 时延变长立即生效，停顿由应用做丢包隐藏。
  - 时延变短在讲话段开始、且缓冲为空时生效。讲话段开始的标志是 marker 位，或时间戳的跳跃
    大于序号的跳跃（DTX）。
  - 从不停顿的流每秒最多缩短一帧，由应用吸收这一帧的差（时间伸缩属于解码器，这里不做）。
- **丢包**：缺失的帧在后面某一帧到期时放弃，那一帧以 `contiguous = false` 交出。
  - 此后才到的包为迟到包，丢弃。
  - 缓冲满（超过 1024 个槽位或 256 KiB）时到达的包也丢弃，记为溢出。序号跳跃超过两个窗口时
    缓冲从头开始。
  - 一帧在自己的播放时刻之后才到、但更后面的帧还没交出时，仍会立即播放。
  - 重复包丢弃；`skip(seq)` 把 FEC 或填充包的序号标为非空缺。
- **统计**：`JitterBufferStats`（received、played、lost、late、overflow、duplicates、
  reordered、delay、target）。
  - `drain_discarded()` 给出迟到和溢出包的序号，两次调用之间最多 4096 个。
  - `xr_config()` 给出 RFC 3611 的视角。自适应缓冲报告调整速率 1（时延变长立即生效），以
    当前时延为 nominal，上限为 maximum 与 absolute maximum。固定缓冲三项都报告其时延。
  - 另有 `frame_duration()` 与 `drain()`。
- **上界**（docs/rules.md）：槽位、最多 1002 个直方图桶、4096 个丢弃序号。每包 O(1)，另外
  每 8 个包扫描直方图到该百分位为止。

### 3. only-webrtc

- `RtcConfig::set_audio_jitter_buffer(Option<PlayoutDelay>)`，默认关闭。
  - 打开后，在帧模式下，每条收到的音频流经 `JitterBuffer`，取代帧组装器及其重排等待。
  - 帧仍从 `on_media_data` 交出，按顺序、在各自的播放时刻交出：peer 的定时器为下一帧唤醒。
  - `MediaData::playout_time` 携带该时刻（不用缓冲时为 `None`）。空缺之后的帧
    `contiguous = false`。
  - RTP 模式与视频不变。
- **进入 VoIP 指标**：
  - 缓冲的丢弃计为突发模型中的 discarded 包：先收到，后丢弃。
  - 它的 `xr_config()` 填写抖动缓冲字段（RX config 的自适应位、速率、nominal / maximum /
    abs max）。
  - 它的 nominal 时延加一个包，就是 E-model 所用的端系统时延。
  - 应用用 `set_voip_quality` 给出的值仍然优先。
- `Peer::jitter_buffer_stats(mid) -> Vec<(ssrc, JitterBufferStats)>`。

### API

改动只有新增。

- only-rtp：
  - `EModel::{fullband, with_burst_robustness, is_fullband, for_codec_rate, scaled_delay_impairment}`。
  - `JitterBuffer`、`JitterBufferStats`、`JitterFrame`、`JitterPush`、`PlayoutDelay`。
  - `MAX_PLAYOUT_DELAY`、`JITTER_BUFFER_MAX_FRAMES`、`JITTER_BUFFER_MAX_BYTES`。
- only-webrtc：`RtcConfig::set_audio_jitter_buffer`、`Peer::jitter_buffer_stats`，以及
  `MediaData::playout_time`（`#[non_exhaustive]` 结构体的新字段）。

有些数值变了，但 API 不变：

- 宽带评分按 G.107.1 计算。有丢包时比 ADR-085 高（用 95 而不是 129）；有时延时，按宽带的
  回声项计算。
- G.722 取双耳 `Ie,wb` 5。应用声明了丢包隐藏时，同时取表 IV.4 的 `Bpl,wb`。
- only-webrtc 测量 Opus 的码率，所以 Opus 按码率评为全频带。

## 影响

- **测试，only-rtp `tests_voip.rs`**：
  - G.107.1 默认值：`Idle,WB` 0.1537、R 128.846、MOS 4.4992。
  - 带附录 III PLC 的 G.722 在 2 % 丢包下：`Ie,eff,WB` 24.78、R 104.07、MOS 4.0491；带
    附录 IV PLC 时为 30.35。
  - 200 / 300 ms 时 `Idd,WB` 为 3.9273 / 19.0413。
  - G.107.2：R 148 → 100 / MOS 4.5；全频带量表上的 R 129 → MOS 4.2634；200 / 300 ms 时
    `Id,FB` 为 4.5057 / 21.8458。
  - EVS 13.2 在 2 % 丢包下：`Ie,eff,FB` 33.874、R 114.126、MOS 3.9103。BurstR 2、`Brf` 3.28
    时为 36.431。EVS 48 在 1 % 下为 21.691。
  - 按码率的查表，以及 Opus 随码率单调。
  - 公布的文件除默认值外没有算例。这些数值都是独立于代码、由公式算出的。
- **测试，only-rtp `tests_jitter.rs`**，20 ms 帧：
  - 3000 帧在 0..60 ms 均匀抖动、3 % 丢包下：时延 58 ms，708 个乱序，每个包恰好计入一次。
  - 重复包与迟到包。
  - 跳过 FEC 序号。
  - 经历 1.2 s 的 +600 ms 时延后，新讲话段从目标时延（< 15 ms）重新开始。不停顿的流每次最多
    缩短一帧（19 s 内 5 到 20 次）。
  - 上界：字节数、槽位数、序号跳跃、时延范围、时间戳回绕。
- **测试，only-webrtc `tests_mux.rs`**（模拟网络）：
  - 单向 10..70 ms、3 % 丢包：489 帧按序交出，全部在播放时刻后 5 ms 以内；时延 60 ms。发送端
    收到的指标为 nominal 60 / abs max 500，RX config 为自适应，32 kbit/s 的 Opus R 为 79。
  - 同样的抖动下用固定 0 ms 的缓冲：迟到帧计入丢弃率，而不是丢包率。
- **模糊测试**：`rtp_rtcp` 模糊测试目标用模糊得到的码率评估 EVS、AMR-WB 与 Opus。
- **开销**：见 BENCHMARKS 中的 "音频抖动缓冲（ADR-087，同次运行 A/B）"。
  - 缓冲关闭时，接收路径每包多一次标志检查，每个音频包多两次计数器加法。
  - 缓冲本身在 M 系列笔记本上每帧约 40 ns（`jitter-bench`）。
- **尚未完成**：
  - 视频：帧仍在组装完成后立即从组装器交出，没有播放时刻。
  - 时间伸缩（加速 / 扩展）属于解码器。
  - 时延敏感度类别（G.107 / G.107.2 的 `sT` / `mT`）固定为 "default"。
  - 03/2023 版由室内噪声推导的 `Ro,FB`：缺少 `Ps` / `Pr` 的默认值。
  - Opus 的 ITU-T 取值：没有采用 Al-Ahmadi 等人公布的 Opus 窄带 / 宽带值。同样缺少的还有 EVS
    的 NB / WB 模式（未公布），以及可选用的单耳宽带表。
  - VoIP 块的突发与间隙时长仍假设 20 ms 的包。
  - 若一个包在报告其丢失的间隔之后的某个间隔里才被丢弃，不做匹配。
