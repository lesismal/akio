# ADR-016：fMP4 HLS、RTMP 与 RTSP 客户端、媒体 hub 中的 WebRTC 媒体

[English](016-media-fmp4-clients-webrtc.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

`only-media`（M7）在 DEV-PLAN 中留有四个缺口：HLS 只产出 MPEG-TS 分段，需要 CMAF（以及分片 MP4 中的
Opus 或 HEVC）的播放器和 CDN 无法使用；hub 能提供 RTMP 与 RTSP 服务，却无法向其他服务器转推或从其拉流，
因为没有 RTMP 与 RTSP 客户端；WHIP/WHEP 只有信令（`NoMedia` 返回 501），尽管 `only-webrtc` 已能承载
H.264、H.265 与 Opus。WebRTC 观众还需要向推流者请求关键帧（PLI），而 hub 没有这条通路。

## 决定

全部为新增；现有行为与默认值不变。

### hub 中的关键帧请求

- `Publisher::on_keyframe_request(hook)` 设置推流者被请求关键帧时的动作
  （`hub::KeyframeHook = Arc<dyn Fn() + Send + Sync>`）；推流者关闭时清除。
- `Subscription::request_keyframe() -> bool` 与 `Hub::request_keyframe(path) -> bool` 发出请求。它们从不阻塞，
  可在 sink 回调内调用：钩子由独立的互斥锁保护，而非流的互斥锁。
- 同一个流的请求按 `HubConfig::keyframe_request_interval`（`DEFAULT_KEYFRAME_REQUEST_INTERVAL`，500 ms）
  节流，众多观众只让推流者付出一个关键帧。
- 视频订阅者加入时若没有缓存的关键帧（`no_gop_cache`，或尚无 GOP），立即请求，而不是等一个 GOP。

### fMP4 / CMAF（`only_media::fmp4`、`hls::SegmentFormat`）

- `fmp4::Muxer`（`new(&[Track])`、`init_segment`、`write_packet`、`flush(end, out)`、`carries`、
  `has_tracks`、`pending_bytes`、`has_pending`）写出初始化分段（带 CMAF brand 的 `ftyp`，含 `mvex`/`trex`
  的 `moov`）与 `moof`+`mdat` 分片：绝对的 `tfdt`（version 1），`trun` 中的样本时长、大小、标志与合成时间
  偏移（有负值时为有符号）。另有 `fmp4::write_styp`。承载 H.264（`avc1`/`avcC`）、H.265（`hvc1`/`hvcC`）、
  AAC（`mp4a`/`esds`）、Opus（`Opus`/`dOps`，由 OpusHead 生成）；与 TS 封装器一样，不承载 G.711 与 MP3。
  每个分片每条轨道至多 1 GiB、2^20 个样本。
- `fmp4::Demuxer`（`feed`、`tracks`、`Event`、`Fmp4Error`）把初始化分段与分片解析回轨道与包，是测试的
  对照，也是模糊测试目标（`fmp4_demux`）：每个 box 的大小都对照其父 box 检查，嵌套由代码固定，子 box 与
  轨道数量有上限，每次 `feed` 复制出的字节数不超过其输入。
- `HlsConfig::format: SegmentFormat`（默认 `MpegTs`，或 `Fmp4`；`extension`、`content_type`）。fMP4 模式下
  播放列表为 version 7（有分片时为 9），`#EXT-X-MAP:URI="init-<n>.mp4"` 仅在初始化分段字节变化时改变，分段为
  `seg-<n>.m4s`（`styp` + 完整分片），LL-HLS 分片 `part-<n>.<m>.m4s` 为完整分片。`max_bytes`、强制切分、
  阻塞式刷新与空闲超时与 TS 相同。`MediaHttp` 把 `.m4s` 与 `.mp4` 交给 `Hls`。

### RTMP 客户端（`only_media::rtmp::client`）

- `push(engine, url, hub, path, RtmpClientConfig) -> Result<RtmpClient, ClientError>` 把 hub 中的流推到
  RTMP 服务器；`pull(...)` 立即预占 `path`，把从服务器播放到的内容发布进 hub。另有 `RtmpUrl`（`parse`、
  `query`、`resolve`）、`ClientState`、`ClientError`、`DEFAULT_PORT`。`RtmpClient`：`url`、`addr`、`state`、
  `is_closed`、`error`、`close`；丢弃即关闭。
- 两者在 `Engine::dial` 之后都运行在 I/O 线程上。IP 字面量无需 DNS；主机名在调用线程上解析（文档注明会阻塞；
  `RtmpClientConfig::addr` 可避免）。
- 上限与超时（默认）：连接 10 s，握手 10 s，每条命令的应答 10 s，拉流空闲 30 s，消息大小 16 MiB，推流
  `write_queue_limit` 2 MiB（`Dropper`）与 `max_write_queue` 16 MiB（断开），`source_wait` 10 s。

### RTSP 客户端（`only_media::rtsp::client`）

- `pull(engine, url, hub, path, RtspClientConfig) -> Result<RtspClient, ClientError>` 从 RTSP 服务器播放进
  hub（路径立即预占；视频参数集已知时上线，来自 SDP 或带内）；`push(...)` 把 hub 中的流录制到服务器
  （ANNOUNCE、SETUP `mode=record`、RECORD）。`RtspTransport`（默认 `Tcp`，交织；`Udp`，每条轨道用
  `Engine::bind_udp` 绑定一对偶/奇 RTP/RTCP 端口）。`RtspClient`：`path`、`close`（尽力发送 TEARDOWN）、
  `is_closed`、`error`；丢弃即关闭。由 `rtsp` 再导出。
- 与 RTMP 客户端不同，`pull` 与 `push` 在 PLAY 或 RECORD 得到应答后才返回，因此在握手期间阻塞调用者，
  不得在 I/O 线程上调用（文档注明）；之后会话运行在引擎上。主机名在调用线程上解析；`RtspClientConfig::addr`
  可避免。
- 用 URL 中的 userinfo 做 Digest（MD5，`qop=auth`）与 Basic 认证，每个请求至多重试两次；以服务器会话超时的
  一半（否则 30 s）用 GET_PARAMETER（或 OPTIONS）保活；录制时定期发送 RTCP 发送者报告，UDP 播放时发送接收者报告。
- `rtsp::message`：`Reply`（`header`、`headers_named`、`cseq`）、`Frame::Reply`、`Parser::client`
  （完整应答，头部与 body 上限与请求相同）。
- 上限与超时（默认）：连接 10 s，每次应答 10 s，拉流空闲 10 s，头部与 body 同服务端解析器，TCP 推流
  `write_queue_limit` 2 MiB / `max_write_queue` 16 MiB，`push_wait` 10 s。

### WebRTC 媒体（`only_media::webrtc`，cargo feature `webrtc`）

- 可选、非默认的 feature `webrtc` 引入对 `only-webrtc` 的依赖（自研，ADR-005 依然成立）。
  `RtcMedia::new(RtcServer, RtcMediaConfig)` 实现 `whip::WebRtcEngine`；`RtcMedia::rtc_server(addrs)` 与
  `webrtc::rtc_config()` 给出启用 H.264、H.265、Opus、PCMU 与 PCMA 的 `RtcServer`。
- WHIP：H.264/H.265 帧（Annex B）转为 AVCC，配置记录由带内参数集构建；Opus 与 G.711 透传。hub 无法承载的
  媒体行（VP8、VP9、AV1、G.722）被忽略；没有任何可承载编码的 offer 得到 406。时间取自每条媒体行的 RTP 时钟，
  按首帧到达时刻对齐。`Publisher::on_keyframe_request` 发送 PLI。轨道确定前保留的包有上限
  （`max_pending_packets` 512、`max_pending_bytes` 8 MiB），一直不开始的媒体行在 `track_timeout`（5 s）后放弃。
- WHEP：ICE/DTLS 建立后才订阅，默认从下一个关键帧开始（`play_gop_cache` 为 false），H.264/H.265 以 Annex B
  发送并在关键帧前带上参数集，Opus 与 G.711 原样发送；不发送 AAC 与 MP3（不转码）。观众的 PLI 或 FIR 变为
  `Subscription::request_keyframe`。
- `WebRtcSession::is_closed`（默认 `false`）让 `WhipServer` 丢弃对端未经 `DELETE` 就结束的会话，使其不再占用
  `max_sessions` 名额。

## 考虑过的方案

- **把 fMP4 做成独立服务**：否决；切分、分片与阻塞式刷新完全相同，因此它是 `Hls` 的格式选项。
- **把 `webrtc` 设为默认 feature**：因编译时间否决；不开启时 WHIP/WHEP 信令依然可用（配合 `NoMedia` 或自定义引擎）。
- **为 WHEP 把 AAC 转码为 Opus**：超出范围（项目中没有编解码器实现）。
- **返回 future 的异步客户端 API**：项目没有运行时；客户端沿用 `srt::push` / `srt::pull` 的方式（启动后返回带
  状态与错误的句柄）。

## 后果

- only-media 新增公共 API（新模块 `fmp4`、`rtmp::client`、`rtsp::client`，feature 下的 `webrtc`；
  `HubConfig` 与 `HlsConfig` 新增字段，二者均为 `#[non_exhaustive]`；`WebRtcSession` 新增带默认实现的方法）。
  API 快照覆盖 `webrtc` feature。
- 新模糊测试目标：`fmp4_demux`、`rtmp_client`、`rtsp_client`。
- hub、HLS 与各客户端的每个缓冲都有带默认值的上限，每次对外交互都在超时之下（规则 7 至 10）。
- 顺带修复 `only-webrtc`：`Endpoint::config`、`close_on_disconnect` 与 `connect_timeout` 在 `bind` 之后总是
  panic；现在它们作用于此后创建的 peer（签名不变）。
- TS 模式下的一处行为变化：正在写入的分段以不连续开头且尚无分片时，播放列表不再输出 `EXT-X-PRELOAD-HINT`
  （被提示的分片无法携带该标签）。
