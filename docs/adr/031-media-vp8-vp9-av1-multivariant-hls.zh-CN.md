# ADR-031：媒体 hub 中的 VP8、VP9 与 AV1，多码率（multivariant）HLS 播放列表

[English](031-media-vp8-vp9-av1-multivariant-hls.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

ADR-016 之后 `only-media` 还有两个缺口。hub 只承载 H.264 与 H.265 视频：提供 VP8、VP9 或 AV1 的
WHIP 媒体行被回答为 inactive，Enhanced RTMP 的 `vp09` / `av01` FourCC 以及 RTSP 的 `VP8` / `VP9` /
`AV1` rtpmap 都被丢弃，尽管 `only-rtp` 已有这些负载格式、`only-webrtc` 也能协商它们；浏览器默认用 VP8
和 VP9 推流，AV1 是低码率下的首选编码。另外 HLS 只提供媒体播放列表，每路流一个：播放器无法在同一来源的
多个 rendition 之间选择（自适应码率），也无法选择备选音频 rendition。

## 决定

全部为新增；行为变化列在“影响”一节。

### 编码及其规范形式

- `Codec::Vp8`、`Codec::Vp9`、`Codec::Av1`（该枚举为 `#[non_exhaustive]`）；它们的 `is_video` 为真。
  规范形式（见 `av` 模块文档）：VP8 与 VP9 的 `Track::config` 是 `VPCodecConfigurationRecord`
  （不含 version 与 flags 的 `vpcC`），AV1 的是 `AV1CodecConfigurationRecord`（`av1C`，含 sequence
  header OBU）；`Packet::data` 是一个 VP8 / VP9 帧（VP9 superframe 保持原样），或一个 AV1 temporal
  unit：带 `obu_size`、不含 temporal delimiter 的 OBU 序列（即 ISO BMFF 存储样本的方式）。
- 包是否为关键帧由码流决定：VP8 帧标签、VP9 未压缩头（`frame_type`，且不是 `show_existing_frame`）、
  AV1 第一个帧头为显示的 `KEY_FRAME`。每个 ingest 都据此设置，GOP 缓存、HLS 切片与慢播放器丢包无需改动
  即可工作。
- `Track::video` 从 `av1C` 中的 sequence header 读取 AV1 画面尺寸；`Track::video_from_keyframe(codec,
  frame)` 由一个关键帧构造 VP8 / VP9 / AV1 轨道（配置记录与尺寸），供没有带外配置的来源（RTP、
  WebRTC）使用。`Track::codec_string()` 给出 RFC 6381 字符串（`avc1.PPCCLL`、`hvc1.1.6.L93.B0`、
  `vp09.PP.LL.DD`、`av01.P.LLT.DD`、`mp4a.40.N`、`opus`、`mp4a.40.34`）。
- 新的编码辅助模块：`codec::vp8`（`is_keyframe`、`keyframe_size`、`config`），`codec::vp9`
  （`Config` 即 `vpcC`，含 `parse`、`encode`、`codec_string`；`level_for`；`Keyframe`、
  `parse_keyframe`、`is_keyframe`），`codec::av1`（`obus`、`Obu`、`to_sample`、`SequenceHeader`、
  `Config` 即 `av1C`，含 `from_sequence_header`、`parse`、`encode`、`sequence_header`、
  `codec_string`；`sequence_header_obu`、`is_keyframe`、`OBU_*`）。

### 各协议的接入与输出

- **Enhanced RTMP / FLV**：`parse_video`、`Decoder` 与 `Encoder` 支持 `vp09`、`av01` 与 `vp08`
  FourCC。sequence start 是配置记录（`vp09` / `vp08` 带 `vpcC` box 的 4 字节 version 与 flags，与
  ffmpeg 写法一致，解析时去掉、写出时补回）；coded frames 不带 composition time。解码器会暂存 VP8 /
  VP9 流，直到第一个关键帧给出画面尺寸。AV1 的 temporal delimiter 被丢弃。RTMP 客户端的
  `fourCcList` 列出这些 FourCC。
- **RTSP / RTP**：`rtp::supported` 包含 VP8、VP9 与 AV1；`rtp::Packetizer` 与 `rtp::Depacketizer`
  使用 `only-rtp` 的负载格式（RFC 7741、RFC 9628、AOM 的 AV1 RTP 规范）；缺包的帧被丢弃。对这些编码，
  `Depacketizer::take_config` 返回最近一个关键帧的配置，新增的 `Depacketizer::picture_size` 返回其尺寸；
  RTSP 录制端（服务端与客户端 pull）在第一个关键帧到达后上线。SDP 双向映射 `VP8/90000`、`VP9/90000`、
  `AV1/90000` rtpmap。`only-media` 现在依赖 `only-rtp`（自研 crate，ADR-005 仍然成立）。
- **fMP4 / CMAF**：`vp08` / `vp09` 样本描述带 `vpcC`（version 1），`av01` 带 `av1C`；解复用器能读回。
  MPEG-TS 不承载它们（没有 HLS 播放器认识的映射）；当某路流的视频无法被分段格式承载时，HLS 按纯音频流处理
  （按时间切片，而不是一直等待永远不会出现的关键帧）。
- **WebRTC**：`webrtc::rtc_config` 启用 VP8、VP9 与 AV1。WHIP 原样传递 VP8 / VP9 帧，AV1 temporal
  unit 以带长度的 OBU 传递，轨道信息取自每个关键帧的头；WHEP 原样发送（不转 Annex B，也不插参数集）。

### 多码率 HLS 播放列表（`hls`）

- `Multivariant { variants: Vec<Variant>, audio: Vec<AudioRendition> }`；
  `Variant { path, bandwidth: Option<u64>, audio_group: Option<String> }`（`Variant::new`）；
  `AudioRendition { group, name, path, language: Option<String>, default: bool }`
  （`AudioRendition::new`）。均为 `#[non_exhaustive]`。
- `Hls::add_multivariant(name, Multivariant)` 在 `/<name>.m3u8` 提供播放列表；
  `Hls::remove_multivariant(name) -> bool`。每个 rendition 是单独发布的一路 hub 流；播放列表为每个音频
  rendition 列出 `EXT-X-MEDIA:TYPE=AUDIO`（`GROUP-ID`、`NAME`、`LANGUAGE`、`DEFAULT`、`AUTOSELECT`、
  `CHANNELS`、`URI`），为每个 variant 列出 `EXT-X-STREAM-INF`：`BANDWIDTH`（配置值，或该 variant 与其
  音频组分段的峰值码率之和，此时还给出 `AVERAGE-BANDWIDTH`）、`CODECS`（分段格式所承载轨道的编码字符串，
  含音频组的）、`RESOLUTION` 与 `AUDIO`。fMP4 为 version 7，MPEG-TS 为 3；LL-HLS 无需额外内容（媒体
  播放列表带有 part）。
- URI 相对于多码率播放列表，并带上它的 query string，使令牌能在媒体播放列表请求中到达 hub 的
  `on_subscribe` 钩子。
- 请求会启动每个 rendition 的 muxer，在每个 rendition 都已知轨道、且（码率需测量时）已有一个分段后作答；
  否则请求被挂起（每 50 ms 检查一次，不占用线程），在三个目标时长加 `play_wait` 之后用已就绪的
  rendition 作答，一个都没有则返回 503。

## 备选方案

- **在 MPEG-TS 中承载 AV1 或 VP9**（AV1 有 AOM 草案）：否决；没有 HLS 播放器能读取，HLS 为它们规定的
  容器是 fMP4。
- **对每个包从码流解析尺寸与 level**：为热路径考虑否决；只解析关键帧，且只在没有带外配置的接入上解析。
- **由一路流的多个轨道构成多码率播放列表**（每个视频轨一个 variant）：否决；各 rendition 是分别编码的
  （编码器阶梯、多个 WHIP 推流者），而每路流本身已经是一个媒体播放列表。为构建阶梯而转码不在范围内。
- **强制在配置中给出 `BANDWIDTH`**：不作为唯一方式；测量分段得到的正是播放器看到的码率，配置值仍然可用。

## 影响

- only-media 新增公开 API：三个 `Codec` 变体、`Track::video_from_keyframe`、`Track::codec_string`、
  `codec::vp8` / `codec::vp9` / `codec::av1` 模块、`rtp::Depacketizer::picture_size`、
  `hls::{Multivariant, Variant, AudioRendition}`、`Hls::add_multivariant` / `remove_multivariant`。
  crate 外对 `Codec` 的穷尽匹配本就需要通配分支（`#[non_exhaustive]`）。
- 行为变化：`webrtc::rtc_config` 接受 VP8、VP9 与 AV1，因此只含这些编码的 WHIP offer 现在会被发布，
  而不是被拒绝（406）；WHEP 也会提供它们。`flv::parse_video` 对 `avc1` / `hvc1` 以外的 FourCC 的 coded
  frames 不再丢掉 3 个字节（原先读取了它们并不存在的 composition time）。对于视频无法被分段格式承载的流，
  HLS 按纯音频流切片，而不是始终切不出分段。
- 顺带修复：直播媒体播放列表的 `EXT-X-TARGETDURATION` 可能在两次刷新之间变化（原先取所列最长分段向上取整，
  1.007 s 的分段会把 1 s 的目标变成 2）；现在取配置的目标时长与最长分段按四舍五入取整中的较大者
  （RFC 8216 4.3.3.1），且永不减小。Chrome 自带的 HLS 播放器会拒绝这种变化。LL-HLS 的 part 仍可能比
  `PART-TARGET` 长出不到一帧，与之前相同。
- Fuzz：`rtp_depacketize` 也会构造 VP8、VP9 与 AV1 轨道；为它、`flv_demux`（`vp09`、`av01`）与
  `sdp_parse` 新增种子。它发现 RTP 的 AAC 解包在 AU-headers-length 为 1 到 8 位时会
  panic（已修复，保留回归输入）。
- 新增测试数据：`vp9_opus.flv`、`av1_opus.flv`（ffmpeg 写出的 Enhanced FLV）、`vp8.ivf`。新增默认忽略的
  基准测试：`hls::tests::bench_segmenting` 与 `tests/media_bench.rs`（hub 扇出、FLV 解码）。
- 热路径，在 gpu51 上与之前的 main 同轮 A/B（交替 5 轮取中位数，head/base）：hub 扇出到 1 / 16 / 256 个订阅者
  1.008 / 1.009 / 1.011；HLS 切片 TS 0.976、TS + part 1.016、fMP4 1.005、fMP4 + part 1.011；FLV 解码 H.264 0.976、
  H.265 0.993。退休指令数相同或更少；单项 1–3% 的波动会随无关的代码改动变化（代码布局）。
- 互通：ffmpeg / ffprobe 验证 Enhanced RTMP 与 fMP4 HLS 上的 VP9 与 AV1、RTSP 上的 VP8 / VP9 / AV1
  （录制与播放，TCP 与 UDP）；headless Chrome 通过 WHIP 推 VP8、VP9、AV1 与 H.264 并通过 WHEP 解码，
  还能播放多码率 fMP4 LL-HLS 播放列表（`tools/interop/media/browser.sh`）。
