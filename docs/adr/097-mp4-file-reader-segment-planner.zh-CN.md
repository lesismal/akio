# ADR-097：无 I/O 的 MP4 文件读取器与 HLS 分段规划（akio-media `mp4`）

[English](097-mp4-file-reader-segment-planner.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

akit（fit 的 Rust 对应物）把媒体库作为点播服务：不转码，在关键帧处从普通（渐进式）MP4 文件切出 HLS 分段
（fMP4 或 MPEG-TS），并把文件作为频道播放进 hub。这是 akit 的请求 A7，对应 fit 在 fib 中的 A64（`media/mp4`）。

akio-media 已有分片 MP4 的复用器与解复用器（`fmp4`）和 HLS，但没有能读普通 MP4 文件采样表（`stts`、`ctts`、
`stss`、`stsc`、`stsz` / `stz2`、`stco` / `co64`、`elst`）的部分。一部两小时影片的这种文件有几十万个采样，
`moov` 有几 MB，可能在文件开头，也可能在末尾。

约束：

- **规则 3。** 库代码不得阻塞 I/O 线程。文件由调用方在线程池或其自己的线程上读取，因此读取器本身不做 I/O。
- **规则 7 与 10。** 每张表都有上限。
- **DEV-PLAN 第 4 节。** 协议解析器要有模糊测试目标。

## 决定

### 1. 新模块 `akio_media::mp4`，无 I/O

fib 的读取器通过 `io.ReaderAt` 读取；akio 的读取器接收调用方读到的字节，分三步：

- **`Locator`。** `next_read() -> (offset, len)` 指出至多 16 字节（一个 box 头），`feed(bytes)` 接收这些字节。
  调用方若读得更多（如文件前 64 KiB）可整段传入，其中的每个头都会被使用。
  - 它沿顶层头（32 位、64 位与 0 大小）走到 `moov`，返回 `MoovLocation`（偏移、大小、文件大小、`ftyp`
    的主品牌）。
  - 遇到 `moof` 返回 `Mp4Error::Fragmented`（这类文件由 `fmp4::Demuxer` 读取）。box 超出文件末尾返回
    `NoMoov`（文件被截断）。
- **`Movie::parse(moov, &location, &Limits)`。** 接收一次读入的整个 `moov` box，至多
  `Limits::max_moov_bytes`（默认 64 MiB；两小时影片的 `moov` 不到 10 MB）。
  - fib 第二遍再通过文件读取 `moov` 中的表。短暂持有 `moov` 的代价与索引相当，并让解析器成为普通的切片
    解析器，更易设限与做模糊测试。
  - `Movie::from_bytes(file)` 对整个在内存中的文件完成这两步。
- **`Plan` / `Segment`。** 规划切点、给出字节范围，并把读到的字节变成包（第 4 节）。

### 2. 一条轨道包含什么

`Mp4Track` 包含：

- `id`、`handler`、`language`（ISO 639-2/T，缺省 `und`）、`name`（取 `udta/name`，否则取 `hdlr` 的名字）、
  `timescale`、`duration`；
- `format`：采样条目的四字符码；
- `track`：由 `fmp4::Demuxer` 所用的同一个采样条目解析器读出的 `av::Track`。该解析器现在是 `pub(crate)`，
  读取 `avc1` / `avc3`、`hvc1` / `hev1`、`av01`、`vp08` / `vp09`、`mp4a`（`esds`，含 QuickTime 版本 1 与 2）
  和 `Opus`；
- `edits`、`shift`、`index`。

媒体栈不承载的格式为 `Codec::Unknown`，保留其 `format`。AC-3 / E-AC-3 属于这一类：给 `av::Codec` 增加编解码器
意味着要教会每个复用器，在这里代价不低。无法解析的采样条目同样视为 Unknown 而非报错，这样一条坏轨道不会让整个
文件无法播放，其采样仍被索引。

### 3. 紧凑的采样索引

`SampleIndex` 以紧凑形式保存这些表，而非每个采样一项：

- **大小。** 采用能容纳所有大小的最窄宽度（`u8`、`u16`、`u32`）；`stsz` 统一大小时不占空间。
- **解码时间。** `stts` 存为游程（首个采样、增量、首个采样的解码时间）。
- **合成偏移。** `ctts` 存为游程（首个采样、偏移）；游程更占空间时改为每采样一个 `i32`。两个版本都按有符号
  读取，与 ffmpeg 一致。`ctts` 短于采样数时其余为 0。
- **同步采样。** `stss` 存为有序列表（文件中无序时排序并去重）；没有 `stss` 时为 `None`。
- **块。** 每个块的首个采样与文件偏移（`stco` 或 `co64`），由 `stsc` 展开。

查询：

- `sample(i)`、`first_at_or_after_dts`、`keyframe_at_or_before` 与 `keyframe_at_or_after` 都是二分查找。
- `iter(from)` / `range(from, to)` 以每采样常数代价遍历。
- `Mp4Track::keyframe_at(time)` 找出在给定时间或之前呈现的最后一个关键帧（对呈现得更晚的 B 帧关键帧会往回退）。

在合成的一小时 60 fps 含 B 帧加 AAC 文件上（384,750 个采样）实测：索引占 1.6 MB（每采样 4.2 字节），
解析用时 1.1 ms（release 构建，在 macOS 开发机上）。

### 4. 分段与到复用器的衔接

- **切分。** `Plan::new(&movie, target)` 在第一条视频轨的关键帧处切分；没有视频时在第一条已知编解码器的轨道上切分。
  - 分段在应当开始的时刻之后、呈现时间达到或超过 `target` 的第一个关键帧处结束，与 ffmpeg 的 `-hls_time`
    切法一致。
  - 规划每段只占 16 字节，`Segment` 按需计算。
  - 其他轨道按切点呈现时间以解码时间划分；其他视频轨在其下一个关键帧处划分。
- **时间线。** 时间为呈现时间线（已应用编辑列表），整体推后 `Plan::delay()`，使任何解码时间都不为负。负的解码
  时间会被 `tfdt` 截断，在 MPEG-TS 中会回绕。
- **一个分段提供什么。**
  - `byte_ranges(&movie, max_gap)`：排序并合并（含至多 `max_gap` 的空隙）的范围，供调用方在 I/O 线程之外读取。
  - `packets(&movie, &[(offset, &bytes)])`：按解码顺序的规范 `Packet`，索引 `Movie::av_tracks()`。
  - `write_fmp4(...)`：一个 `moof` + `mdat`，序号为 `index + 1`。点播分段的生成不按顺序，因此新增了
    `fmp4::Muxer::set_next_sequence`。
  - `write_ts(...)`：PAT/PMT，然后每个采样一个 PES。
  - `Plan::vod_playlist(init, uri)`：点播媒体播放列表（`EXT-X-PLAYLIST-TYPE:VOD`，fMP4 时有 `EXT-X-MAP`，
    以 `ENDLIST` 结尾）。
- **NAL 单元长度。** NAL 单元长度为 1 或 2 字节的 H.264 / H.265 采样会改写为 4 字节长度，`av_tracks()` 相应
  修改配置记录：`av` 的规范形式要求 4 字节。

### 5. 编辑列表

与 fib 及播放器一致：

- 第一个播放的编辑之前的空编辑会延后该轨道；
- 该编辑的媒体时间在其起点呈现（`Mp4Track::shift`）；
- 之后的编辑保存在 `edits` 中，不应用。

### 6. 限制与不可信输入

`Limits` 默认值：

| 限制 | 默认值 |
| --- | --- |
| `max_moov_bytes` | 64 MiB |
| `max_boxes`（顶层头，以及 `moov` 内） | 65,536 |
| `max_tracks` | 64 |
| 每轨 `max_samples` | 2^24 |
| `max_edits` | 1024 |
| `max_segments` | 2^20 |

在限制之外：

- 每个计数在分配之前都与其 box 的字节数核对。所有分配都受 `moov` 字节数约束；只有采样数不超过条目数两倍时
  才使用稠密 `ctts`。
- 2^24 个采样的统一大小 `stsz` 不做任何按采样的分配。
- 解析器按固定的 box 布局遍历，从不按输入递归，box 深度天然有界。
- 表之间必须一致：
  - `stts` 覆盖每个采样；
  - `stsc` 把每个采样放进某个块；
  - `stsc` 的首块号递增；
  - 每个块的采样都在文件之内；
  - 解码时间低于 2^61。
- 超出范围的 `stss` 条目被忽略。
- 未支持：`cmov`、第一个之后的采样描述、采样分组、加密。

### 7. 测试

- **ffmpeg 测试文件。** 复制了 fib `media/mp4/testdata` 的七个文件及其 ffprobe 输出（MIT，同一作者）：
  H.264 / H.265 / AV1 搭配 AAC / Opus，`moov` 在两端，B 帧，负合成偏移，空编辑。与 ffprobe 核对：
  - 每个采样的偏移、大小、时长、DTS、PTS 与同步标志，含与不含编辑列表两种情况；
  - 每条轨道的编解码器、尺寸、采样率与声道数；
  - 配置的 SHA-256。
- **合成文件**，覆盖每张表的每种形式：
  - `stsz`，4、8、16 位的 `stz2`，以及统一大小；
  - `ctts` 缺失、版本 0 与版本 1；
  - `stss` 有列表、缺失、为空与倒序；
  - `stco` 与 `co64`；64 位 `mdat`；版本 1 的头；`moov` 在任一端；
  - 两个版本的编辑列表；
  - 空块。

  每种查询都与遍历结果核对。
- **畸形输入。** 畸形表、在每个字节处截断、随机破坏 `moov`，以及每个限制恰好达到与恰好超出。
- **规划与复用。** 多种目标时长下的规划（每个采样恰在一个分段中、以关键帧开始、时长）；分段复用为 fMP4 后
  解复用回来；复用为 TS 后解复用回来；NAL 长度加宽。
- **模糊测试目标** `mp4_read`。
- **互通**（`tests/mp4_interop.rs`）。由 ffmpeg 生成十秒文件（含 B 帧、`moov` 在末尾的 H.264 + AAC，
  faststart 的 H.265 + AAC，H.264 + Opus），通过 `Locator` 与范围读取来读，按 2 秒切分。然后：
  - 每个 fMP4 与 TS 分段解码时 ffmpeg 无错误，且以关键帧开始；
  - 两种点播播放列表都能播完全部 250 帧。

## 影响

- akit 可以不转码地把 MP4 文件作为 HLS 提供（或把其包送入 hub），所有文件 I/O 都在它自己的线程上。
- `fmp4::Muxer::set_next_sequence` 是新增的公开方法；`mp4` 之外没有其他改动。
- AC-3 / E-AC-3 轨道会被索引但不承载；支持它们是跨各复用器的编解码器改动（TS 流类型 0x81 / 0x87，`ac-3` /
  `ec-3` 条目）。
