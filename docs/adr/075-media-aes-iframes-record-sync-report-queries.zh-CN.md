# ADR-075：AES-128 的 I 帧播放列表、RTSP RECORD 会话的 RTCP 同步、rendition report 的查询串

[English](075-media-aes-iframes-record-sync-report-queries.md) | 简体中文

状态：已采纳（2026-11-22）

## 背景

ADR-070 在 `akio-media` 中留下三处空缺：

- **AES-128 下的 I 帧播放列表**。AES-128 时 `HlsConfig::iframe_playlist` 被忽略：I 帧播放列表
  给出分片的字节范围，而 AES-128 分片是一整段 CBC 密文，PKCS #7 填充只在末尾。分片中间的一段
  只能以前一个密文块为 IV 解密（每个条目前一个带 `IV` 属性的 `EXT-X-KEY`，范围按块对齐），而且
  没有填充。播放器对解密出的每个资源都去除 PKCS #7 填充：hls.js 按最后一个解密字节的值截掉
  相应字节数，ffmpeg 的 `crypto` 协议在读到的末尾检查填充。RFC 8216 未规定 AES-128 分片的字节
  范围，Apple 的工具也只把 I 帧播放列表与明文或 SAMPLE-AES 媒体的字节范围搭配。
- **RECORD 会话的 RTCP 同步**。ADR-070 用服务器的 RTCP 发送者报告对齐 RTSP 客户端拉取的轨道。
  RTSP 服务器忽略推流端的 RTCP（交织的 RTCP 通道被丢弃，UDP RTCP 端口读到即弃），所以录入的
  音视频保持各自首包到达时的偏移。
- **rendition report 的查询串**。`EXT-X-RENDITION-REPORT` 的 URI 只有路径：切换 rendition 的
  播放器用这个 URI 发出新 rendition 的阻塞重载，媒体播放列表查询串里的令牌（给 hub 的
  `on_subscribe` 钩子，或前面的 CDN）到不了那里。构建播放列表的地方不知道查询串。

## 决定

1. **AES-128 的 I 帧是独立资源。** 同时开启 `iframe_playlist` 与 AES-128 时，每个 I 帧（字节与
   ADR-070 的范围相同：MPEG-TS 中的 PAT、PMT 与关键帧 PES；fMP4 中关键帧的 `moof` + `mdat`
   片段）在其分片关闭时整体加密：分片的密钥，CBC 与 PKCS #7，IV 为该 I 帧的编号，即它在 I 帧
   播放列表中的媒体序列号（与 RFC 8216 5.2 对分片的规定一致，不写 `IV` 属性）。它在
   `/<path>/iframe-<n>.ts`（`.m4s`；单个字节范围的请求与分片一样应答）提供，列表中不带
   `EXT-X-BYTERANGE`，位于其分片的 `EXT-X-KEY` 之后（fMP4：在明文 `EXT-X-MAP` 之后，与媒体
   播放列表相同）。密钥、轮换与密钥授权不变（I 帧用其分片的密钥，随分片离开）。
   `EXT-X-I-FRAME-STREAM-INF` 的带宽按填充后的资源计算。SAMPLE-AES 仍用字节范围（其容器是
   明文）。公共 API 不变：`iframe_playlist` 在 AES-128 下也按其说明工作。
   - 代价：仅当两个选项同时开启。关键帧字节多存一份（每个另加至多 16 字节），随其分片计入
     `max_bytes`；它们在分片关闭时再加密一次（逐包路径无额外工作）。其他配置每次关闭分片多
     一次匹配。
   - 未采用：字节范围加逐条 IV（如上：没有填充，播放器会截掉 I 帧的一部分或失败）；按请求
     重新加密（每次请求耗 CPU，且明文已不在）。
2. **`RtspConfig::rtcp_sync`**（新的公共字段，默认 `true`）：RECORD 会话把推流端的 RTCP 交给
   与客户端拉流相同的 `Recorder`：每条轨道的交织 RTCP 通道、复用在 RTP 通道上的 RTCP（按包
   类型识别，与客户端相同），以及来自推流端 RTP 或 RTCP 端口的数据报（按包类型识别 RTCP）。
   规则与 ADR-070 相同：时间从到达开始，有了报告和数据包的轨道改用推流端的 NTP 时钟，相对于
   第一条同步的轨道，只向前移动，报告先到时在上线前就对齐，超过 10 s 的修正与 NTP 时间为 0
   的报告被忽略。`false` 保持按到达计时。与客户端一样默认开启：发送报告的推流端（ffmpeg、
   OBS、摄像头）得回采集时的偏移，其他不变。
3. **订阅者从其第一个包开始。** 同步后的流可能带有时间早于 GOP 起始关键帧的音频（AAC 编码器
   的预滚帧，ffmpeg 把它们的时间放在第一帧视频之前，现在保留了这一时间）。所有 `from_zero`
   的 sink（RTSP 播放端、HLS、HTTP-FLV、录制、WebRTC、RTSP 客户端推流）把这类音频钳到自己的
   起始时间，发出多个时间戳相同的音频帧（ffmpeg：“non monotonically increasing dts”）。hub 现在
   为每个订阅者记住其自 tracks 以来收到的第一个包的解码时间，在有包达到该时间之前，丢弃时间
   早于它的非视频包（因此同一次推流中后来的时间跳变仍会送达；新的推流或 `set_tracks` 重新
   开始；只有视频的流没有下限）。视频总是送达。仅当可能还有订阅者尚未越过下限时，分发循环才
   检查下限（每条流一个标志，订阅者开始或重新开始时置位，由循环清除）：稳态下没有开销。
4. **rendition report 的 URI 带上请求的查询串**，去掉其中的 `_HLS_` 指令（RFC 8216bis 6.2.5
   保留了该前缀：`_HLS_msn`、`_HLS_part`、`_HLS_skip`……）：播放器在该 URI 上追加自己的指令，
   与对当前播放列表做阻塞重载时完全一样。播放列表请求（以及挂起的阻塞重载）保存查询串用于
   应答。公共 API 不变。

## 影响

- 测试（`cargo test -p akio-media`）：两种格式、有无分段、密钥轮换下的 AES-128 I 帧播放列表，
  每个 `iframe-<n>` 用其分片的密钥和其编号的 IV 解密后，正好等于未加密流的播放列表所给的范围，
  分片本身不变，流的字节计数包含这些 I 帧；明文 I 帧播放列表不再以多余的
  `EXT-X-KEY:METHOD=NONE` 开头；hub 的下限（GOP 回放、直播开始、新的推流、后来的跳变）；带
  请求查询串的 rendition report（去掉指令，去掉引号）；向 RECORD 会话发送把音频放在视频之后
  500 ms 的发送者报告，而数据包同时到达：TCP（RTCP 通道）、RTCP 复用在 RTP 通道上的 TCP 与
  UDP（RTCP 端口），报告在媒体之前（从第一个包起对齐）和在中途（之后的包移动，音频时间持续
  递增），相差 60 s 的报告被忽略，关闭同步时按到达计时（`tests/rtsp_interop.rs`）。
- 互通：ffmpeg 把每个 AES-128 I 帧（取回、解密，fMP4 加上明文初始化分片）解码为源中恰好
  一帧，H.264 与 H.265 皆然，并能直接播放 I 帧播放列表，每个条目一帧源画面
  （`tests/hls_iframes.rs`）；LL-HLS 的 rendition report 带有 `?token=…`，由它构造的阻塞重载
  得到应答。无头 Chrome 中（`tools/interop/media/hls-iframes.sh`）：hls.js 1.5.20 播放两种格式
  的 AES-128 多变体播放列表，并单独播放 H.264 的 I 帧播放列表（每个 I 帧都解密并追加，
  MPEG-TS 中帧被解码）；Shaka Player 4.12.6 列出 I 帧轨道，在 fMP4 上的 trick play 中取回、
  解密并解码 I 帧。Shaka 的 MPEG-TS 转封装器在样例两个关键帧之一单独作为 I 帧时失败（3018，
  AUD、SPS、PPS、IDR，无 SEI），加密与否都一样，ADR-070 的明文字节范围亦然，而 ffmpeg 能解码
  该 I 帧，Shaka 在完整分片中也能播放；macOS 上的 Chrome 完全无法经 MSE 解码这个 H.265 样例：
  这两项由脚本报告，不作要求。现有的 RTSP 互通（`ffmpeg -f rtsp` 推流，ffmpeg 经 TCP 与 UDP
  播放）在开启同步后发现了决定 3 中预滚音频被钳位的问题。
- 模糊测试目标：不变，均可构建。
- 代价：与 main 在 gpu51 上同轮 A/B（`quiet.sh`，单个固定核心，交替 7 轮，取中位数，head / base）：hub 扇出 1.005 / 0.994 / 0.996（1 / 16 / 256 个订阅者；最初逐订阅者逐包检查新下限的版本在 256 时为 1.043，现在仅当有订阅者尚未越过下限时循环才检查）；RTSP RECORD 入流（新增 `rtsp-record`）1.007、RTSP 拉流 1.003、RTMP 拉流 0.996；`bench_segmenting` MPEG-TS 1.065、MPEG-TS LL-HLS 0.981、fMP4 0.961、fMP4 LL-HLS 1.020、AES-128 0.995 至 0.998、SAMPLE-AES MPEG-TS 1.015、`cbcs` 1.002。分片的逐包路径没有改动（独立加密的 I 帧、查询串与新路由都是按分片或按请求，且不在此基准中）；普通 MPEG-TS 与 fMP4 反向变化，`cbcs` 在仅 hub.rs 不同的两轮之间从 1.055 变为 1.002：属于代码布局。macOS aarch64 上同样的比较全部在 0.97 至 1.03 之间。新基准 `rtsp-record`（`tests/client_bench.rs`）以每轨每轮一个发送者报告驱动 RECORD 会话；交织路径现在匹配 RTCP 通道并检查包类型。
- 未做：H.264、H.265（fMP4）与 AAC 以外编码的 SAMPLE-AES；向推流端发送 RTCP 接收者报告；重连
  时重新解析主机名。
