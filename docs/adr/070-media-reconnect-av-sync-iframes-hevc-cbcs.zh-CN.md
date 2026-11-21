# ADR-070：自动重连的 RTMP / RTSP 客户端、RTCP 音视频同步、HLS I 帧播放列表、rendition report、会话密钥、H.265 `cbcs`

[English](070-media-reconnect-av-sync-iframes-hevc-cbcs.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

在 ADR-016、031、034 与 043 之后，`only-media` 仍列为未完成的有：自动重连的 RTMP 与 RTSP
客户端、RTSP 客户端基于 RTCP 的音视频同步（ADR-016），HLS I 帧播放列表与 rendition report
（ADR-031），`EXT-X-SESSION-KEY`（ADR-034），以及 H.265 的 SAMPLE-AES（ADR-043）。

- 中继摄像头或向 CDN 推流的客户端必须挺过对端重启。没有重连时，应用只能盯着
  `is_closed()` 再新建客户端，而拉流此时会丢掉它在 hub 中的路径（订阅它的播放器被断开，
  其间别的发布者还可能占用该路径）。
- 同一 RTSP 会话各轨的 RTP 时间戳基值随机、时钟不同；只有 RTCP 发送端报告（某一时刻的 NTP
  时间及同一时刻的 RTP 时间戳）能把它们联系起来。客户端此前让每轨时间从其首个包到达时
  开始（与 RTSP 服务端对待推流者相同），音频相对视频的偏差就等于两者首包到达时刻与采集
  时刻之差。
- I 帧播放列表（RFC 8216 4.3.3.6，`EXT-X-I-FRAMES-ONLY`）让播放器用分段的字节范围做拖动预览
  与快进快退。rendition report（RFC 8216bis 4.4.5.4）让切换码率的 LL-HLS 播放器无需先取新
  播放列表就能对新码率发出第一次阻塞式刷新。`EXT-X-SESSION-KEY` 让播放器在取媒体播放列表
  之前就能取密钥。
- H.265 `cbcs` 要求每个 slice segment 头保持明文，因此必须解析它：头长度取决于 SPS
  （短期参考图像集，包括帧间预测的集合、长期参考图像、SAO、时域 MVP、以 CTB 计的图像大小）
  与 PPS（依赖 slice、额外头比特、加权预测、列表修改、tile / 波前入口点、去块覆盖、头扩展、
  range 扩展的色度 QP 偏移列表）。

## 决定

全部为新增（新配置字段的默认值保持原有行为，唯一例外是默认开启的
`RtspClientConfig::rtcp_sync`）。

1. **重连策略**：`only_media::Reconnect`（也从 `rtmp::client` 与 `rtsp::client` 重新导出）：
   `initial_delay`（500 ms）、`max_delay`（30 s）、`max_attempts`（`None`：直到关闭），由
   `Reconnect::new(&Arc<Engine>)` 构建，弱引用持有引擎（客户端在其上重新拨号；复用启动时解析
   出的地址，因此域名解析从不在调用者线程之外进行）。每次尝试失败后等待时间翻倍，直到上限，
   会话进入直播后重置。新增 `RtmpClientConfig::reconnect` 与 `RtspClientConfig::reconnect`
   （默认 `None`）。
   - **哪些错误重连**：再试一次可能好转的错误。终止性的有：URL 错误与解析失败、hub 错误
     （路径被占用、推流的源已离开）、凭据被拒（RTSP 401 / 403 与 `Unauthorized`；RTMP
     `…Connect.Rejected` 与 `…Denied`），以及 RTSP 中没有可承载轨道的流。其余（连接被拒或被
     关闭、超时、协议错误、其他拒绝如 `NetStream.Play.StreamNotFound` 或 RTSP 404 / 503、服务端
     结束流、推流的源更换了编码）都会重连。
   - **RTMP**：客户端本就是异步的，失败后进入新增的 `ClientState::Reconnecting`，由媒体定时器
     安排重新拨号；连接带有代数（`epoch`）：被替换连接的回调（迟到的 `on_close`、为它触发的
     定时器、已在途的包）都被忽略，每条媒体消息多一次原子读取。第一次连接也会重试。
     `RtmpClient::reconnects()` 统计首次推流/播放之后又进入推流状态的会话数；重连期间
     `error()` 返回上一会话的错误。
   - **RTSP**：握手会阻塞调用者，因此客户端拆成每连接一个的会话（原有状态机）与拥有 hub 侧
     的 `Client`，后者在会话结束时决定是否重连：退避在媒体定时器上进行，每次尝试在自己的
     短命线程上运行（`only-rtsp-reconnect`；规则禁止阻塞定时器或 I/O 线程，且线程池任务不得
     等待事件循环）。第一个会话必须成功：`pull` / `push` 与以前一样返回它的错误。推流在每次
     尝试前重新读取 hub 流的当前轨道，因此换了编码的源会被重新 ANNOUNCE。新增
     `RtspClient::{reconnects, is_live}`。
   - **hub**：拉流在各会话间保留同一个 `Publisher`（现为共享的 `Arc`）：路径保持占用并以最后
     的轨道保持直播，订阅者留下，下一会话的首个轨道经 `Publisher::set_tracks` 下发，所有
     sink 都把它当作重新发布（`on_tracks`：时间线重启，HLS 写入 discontinuity）。推流重新订阅，
     并从缓存的 GOP 开始。关闭（或放弃）时在 `is_closed()` 变为真**之前**释放路径（即
     1c745f1d 的保证，现在 RTSP 也有：其会话以前在 recorder 取消发布之前就把自己标为已关闭）。
2. **RTSP recorder 中的 RTCP 音视频同步**（客户端拉流背后的接入）：
   `RtspClientConfig::rtcp_sync`（默认 `true`）。每轨仍从首包到达开始。发送端报告（每个 RTCP
   复合包中的第一个 SR，经 TCP 交织通道、与 RTP 复用的 RTCP 以及 UDP RTCP socket）按轨保存；
   一轨一旦既有报告又有包，就算出其首个 RTP 时间戳对应的 NTP 时间，其偏移改为该时间相对于
   第一个完成同步之轨所定基准的差值。偏移只向前移动：当某轨需要后移时，改为把基准与所有
   已同步的轨前移，因此时间始终递增。在首包之前到达的报告（ffmpeg 与 mediamtx 会早发）也作用
   于该首包所完成的包，因此流在进入直播时就已对齐。大于 10 s 的修正会被忽略（报告的时钟
   不一致，或根本不是时钟），NTP 时间为 0 的报告也忽略。每个 RTP 包多一次判断（`first && sync`）。
3. **HLS I 帧播放列表**：`HlsConfig::iframe_playlist`（默认 `false`）为带可承载视频的流提供
   `/<path>/iframes.m3u8`：版本 4（fMP4 为 7），`EXT-X-I-FRAMES-ONLY`，所列分段中每个视频
   关键帧一项，带指向其分段的 `EXT-X-BYTERANGE`，`EXTINF` 到下一个关键帧为止（越过
   discontinuity 或在直播边缘时到其分段末尾），独立的媒体序号，以及与媒体播放列表相同的
   discontinuity 序号、map 与密钥。MPEG-TS 的范围为 PAT、PMT 与关键帧的 PES（muxer 在每个
   关键帧前写入表），可单独解码。fMP4 中开启该选项时每个关键帧有自己的分片：先冲刷其前的
   待写数据，在下一个视频样本处切出它的分片（包含关键帧及其间的音频）并记为范围。使用
   AES-128 时不提供（对整个分段做的 CBC 无法从中间解密，除非拿到前一块，播放器不会这样做，
   RFC 8216 对这种字节范围也没有规定）；SAMPLE-AES 的容器是明文的，可以使用。分段、分片与
   init 的响应现在支持单个字节范围（`Range: bytes=a-b`、`a-`、`-n`），返回 206 或 416，并声明
   `Accept-Ranges: bytes`（多范围请求得到完整内容）。多码率播放列表以
   `EXT-X-I-FRAME-STREAM-INF` 列出每个变体的 I 帧播放列表（`BANDWIDTH` 为其 I 帧的峰值码率，
   `CODECS` 为其视频编码，`RESOLUTION`，带查询串的 `URI`）。
4. **rendition report**：启用 LL-HLS 分片时，被多码率播放列表列出的流的媒体播放列表末尾，
   为其所在多码率播放列表中其余每个正在运行 muxer 的码率写一行
   `EXT-X-RENDITION-REPORT:URI=…,LAST-MSN=…,LAST-PART=…`（URI 相对于本媒体播放列表）。每个流在
   其发布者线程上把最新分片发布为一个原子量（`msn << 20 | part`）；在本流锁下构建的播放列表
   读取其他流的原子量，只取服务级的映射锁，而这些锁从不在持有某个流的锁时被获取
   （`Hls::stream` 不再在持有映射锁时去锁流）。
5. **会话密钥**：加密的多码率播放列表用 `EXT-X-SESSION-KEY` 写出每个码率的当前密钥（相同的
   `METHOD`，`URI` 改为相对于多码率播放列表，绝对地址除外，MPEG-TS SAMPLE-AES 带 `IV`），并
   按 RFC 8216 4.3.4.5 去重。尚无密钥的码率不列。
6. **H.265 `cbcs`**：`codec::h265` 解析 slice segment 头所依赖的内容（`SliceSps`、`SlicePps`；
   仅 layer 0；拒绝 PPS 的多层 / 3D / SCC 扩展）以及 `slice_header_len`（H.265 7.3.6.1，到
   `byte_alignment()` 为止，计入防竞争字节；短期集合最多 64 个，每侧最多 16 幅图像，长期图像
   最多 32 幅，每个列表最多 15 个参考，头扩展最多 256 字节）。fMP4 `cbcs` muxer 承载 H.265
   （`encv`，`frma` 为 `hvc1`）：每个 slice 为一个子样本，其明文部分以 slice segment 头结束，
   其余按 1:9 模式加密；其他 NAL 单元保持明文（头无法解析的 slice 也保持明文，与 H.264 相同）。
   参数集来自 `hvcC` 与带内，每类最多保留 256 个。MPEG-TS 中的 SAMPLE-AES 仍只承载 H.264 与
   AAC（Apple 的格式没有定义 H.265）。

## 后果

- 测试（`cargo test -p only-media`）：RTMP 对脚本化服务端（拉流重连三次，保留路径与订阅者
  并重新发布；拒绝及尝试次数上限使其结束且路径已释放；推流从关键帧重新发送）；RTSP 对本
  crate 的服务端（经可随时断开的 TCP 转发器），拉流经 TCP 与 UDP 在同一端口换成 H.265 后恢复，
  推流经 TCP；recorder 按把音频置于视频之后 500 ms 的发送端报告对齐两轨，报告早到与晚到均
  测试（时间保持递增），关闭同步时按到达时间；两种格式的 I 帧播放列表，每个范围单独解封装
  恰好得到一个关键帧；rendition report 与另一码率的状态一致；多码率播放列表中的会话密钥与
  I 帧条目；字节范围；H.265 slice segment 头长度在两个 x265 样本的每个 slice 上都与 ffmpeg 的
  `trace_headers` 一致（波前入口点与 SAO；每帧三个 slice、加权预测、四个参考与 B 金字塔、
  带内参数集：共 200 个 slice）；H.265 的 `cbcs` 分片解密后等于源。
- 互通：ffmpeg 把每个 I 帧字节范围（以 `Range` 请求获取，fMP4 加上 init 分段）解码为恰好一帧
  源画面，ffprobe 能读取带 I 帧条目的多码率播放列表（`tests/hls_iframes.rs`）；ffmpeg 逐帧正确
  播放 SAMPLE-AES H.265 fMP4，普通与 LL-HLS（`tests/hls_encryption.rs`）；Docker 中的
  mediamtx 1.21.4 在 RTSP 与 RTMP 拉取 ffmpeg 推流及我们自己的推流时被重启两次，六个客户端
  全部重连、拉流重新发布，RTSP 拉流的轨道在首秒内由 mediamtx 的报告完成同步（修正最多约
  130 ms），与到达时间的步调差在 250 ms 以内（`tests/mediamtx_reconnect.rs`，默认忽略）。
- 模糊测试：新目标 `h265_sample_encryption`（参数集与 slice 经过解析器与 `cbcs` muxer，每个
  访问单元按其 `senc` 子样本解密回原样），种子来自两个 H.265 样本。
- 开销：HLS 切片路径每个视频包多一次标志判断、每个分片多一次原子写，RTSP 接入每个 RTP 包多一次
  判断，RTMP 拉流每条媒体消息多一次原子读取。第一次 A/B 显示 fMP4 切片慢了 20 %：正在写入的分段
  每个包都要从流状态中移出再放回，而它因 I 帧字段变大了。现在改为原地借用，I 帧状态装箱。gpu51 上
  同一轮的 A/B（`quiet.sh`，固定一个核，7 轮交替，取中位数，新 / 旧）：`bench_segmenting`
  MPEG-TS 0.939、MPEG-TS LL-HLS 0.996、fMP4 0.950、fMP4 LL-HLS 0.921、AES-128 0.987 至 0.996、
  SAMPLE-AES MPEG-TS 0.997、`cbcs` fMP4 1.019；`tests/client_bench.rs`（新增：经模糊测试入口测量
  RTMP 与 RTSP 拉流接入）RTMP 1.013、RTSP 1.015。
- 未完成：H.264、H.265（fMP4）与 AAC 以外编码的 SAMPLE-AES；AES-128 下的 I 帧播放列表；
  rendition report URI 上的查询串（构建播放列表处不知道媒体播放列表的查询串）；RTSP 服务端
  RECORD 会话中的 RTCP 同步（recorder 已支持，服务端未开启）；重连时重新解析主机名。
