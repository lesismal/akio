# 流媒体：hub、RTMP、HTTP-FLV、HLS

`only-media` 是直播服务端工具集：一个流 **hub**，周围是全部推流与播放协议。通过 RTMP、RTSP 或
SRT 推上来的流，可以用 RTMP、RTSP、SRT、HTTP-FLV、WS-FLV 和 HLS 播放，协议之间没有任何胶水代码：
每个协议都把收到的内容转换成 `only_media::av` 的规范包，再从规范包封装输出。

| 协议 | 推流 | 播放 | 章节 |
|---|---|---|---|
| RTMP（digest 握手、Enhanced RTMP 的 H.265 / VP9 / AV1 / VP8 / Opus），服务端与客户端 | 支持 | 支持 | 本章 |
| HTTP-FLV、WS-FLV | – | 支持 | 本章 |
| HLS（MPEG-TS 或 fMP4/CMAF、LL-HLS 分片、阻塞式刷新、多码率播放列表） | – | 支持 | 本章 |
| RTSP（TCP 交织与 UDP），服务端与客户端 | 支持 | 支持 | [RTSP 与 WHIP/WHEP](media-rtsp.md) |
| SRT live（ARQ、TSBPD、AES） | 支持 | 支持 | [SRT](media-srt.md) |
| WHIP / WHEP（媒体需 `webrtc` feature） | 支持 | 支持 | [RTSP 与 WHIP/WHEP](media-rtsp.md) |

编码：H.264、H.265、AAC 和 Opus，凡容器能承载之处都支持；VP8、VP9 与 AV1 支持 Enhanced RTMP / FLV、RTSP、
WHIP / WHEP 与 fMP4 HLS（不支持 MPEG-TS）；容器允许时还有 G.711 与 MP3。下面的代码片段来自 `crates/only-media/examples/guide-media.rs`。

## 规范形式

`av::Track` 描述一路基本流：`Codec` 及其 ISO BMFF 形式的配置（带参数集的
`AVCDecoderConfigurationRecord` / `HEVCDecoderConfigurationRecord`、VP8 与 VP9 的
`VPCodecConfigurationRecord`、带 sequence header 的 `AV1CodecConfigurationRecord`、AAC 的
`AudioSpecificConfig`、`OpusHead`），以及画面尺寸或采样率。`av::Packet` 是一个访问单元：AVCC 视频（4 字节
NAL 长度，不含访问单元分隔符）、VP8 / VP9 帧、AV1 temporal unit（带长度、不含 temporal delimiter 的
OBU）、不带 ADTS 的 AAC 原始帧、Opus 包；解码时间与显示时间以纳秒计。包的 `keyframe` 由码流判定（IDR /
IRAP、VP8 / VP9 关键帧、AV1 显示的 `KEY_FRAME`）：GOP 缓存、HLS 分段与慢播放器丢包都从这些包开始。
`only_media::codec` 提供 AVCC 与 Annex B 互转、解析配置记录、SPS、VP9 关键帧头与 AV1 sequence header
（画面尺寸）以及 ADTS 分帧的工具；`Track::video_from_keyframe` 由关键帧构造 VP8 / VP9 / AV1 轨道，
`Track::codec_string` 给出 RFC 6381 字符串（`avc1.64001F`、`vp09.00.31.08`、`av01.0.04M.08`、
`mp4a.40.2`……）。

## Hub

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:hub}}
```

- **按路径区分的流。** RTMP 的 `rtmp://host/app/name` 推送 `app/name`；RTSP、SRT、HTTP 与 WHIP 使用
  相同的路径（`rtsp://host/app/name`、`http://host/app/name.flv`、`streamid=#!::r=app/name`）。URL 的
  查询串放在 `PeerInfo::query` 里。
- **一个推流者，多个订阅者。** 同一路径的第二个推流者会被 `HubError::StreamBusy` 拒绝；尚不知道自身轨道的
  推流（RTMP 在序列头之前、SRT 在首个 PMT 和参数集之前）会先**预留**路径，因此拒绝发生在握手阶段。
- **鉴权钩子。** `on_publish` 和 `on_subscribe` 一次性为所有协议做鉴权；`on_unpublish` 观察推流者离开。
  钩子运行时不持有 hub 的任何锁。
- **上限。** `max_streams`（1024）和 `max_subscribers`（每路径 1000）约束客户端能增长的表；超出后推流和
  播放以 `HubError::Limit` 失败（HTTP 为 503，SRT 为 OVERLOAD）。设为 0 表示不限。
- **GOP 缓存，秒开。** 每路流保存自最近一个视频关键帧以来的所有包（纯音频流保存最近一秒），上限为
  `gop_cache_bytes`。新订阅者先收到轨道和缓存，再收到更新的包，所以播放立即从一幅完整画面开始。
- **背压。** 分发在推流者的 I/O 线程上同步进行：sink 把数据排入自己的连接队列，从不阻塞。每个输出都用
  `hub::Dropper` 包装 sink：连接队列超过 `write_queue_limit` 时丢包，之后视频从下一个关键帧恢复（音频立即
  恢复）；超过 `max_write_queue` 时断开该播放者。慢播放者既不会拖慢推流者，也不会让内存增长。
- **时间戳规整。** `hub::Timeline` 让每个输出的时间戳在重新推流和编码变化之后仍按轨道递增，因此等待
  （`play_wait`）下一个推流者的播放者可以平滑续播。
- **统计。** `Hub::streams()` / `stream_info(path)` 给出推流者及其协议和地址、轨道、订阅者数、流入字节
  和包数，以及因慢播放者而丢弃的包数。

自定义 sink（录制、转推、分析）实现 `Sink` 即可：

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:sink}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:subscribe}}
```

丢弃 `Subscription`（或 `Publisher`）即结束。`SubscribeOptions::wait` 让订阅可以先于推流者存在，并在
重新推流后继续；`no_gop_cache` 从下一个关键帧开始而不使用缓存。

## RTMP

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:rtmp}}
```

`RtmpServer` 是一个 `Acceptor`。它支持简单握手和 Flash digest（"complex"）握手、完整的 chunk 流（四种
头格式、扩展时间戳、chunk 大小变更、abort、聚合消息、确认），并应答 `connect`、`releaseStream`、
`FCPublish`、`createStream`、`publish`、`play`、`getStreamLength`、`FCUnpublish`、`deleteStream`、
`closeStream`。推流者的 FLV tag 经 `flv::Decoder` 解析（传统 codec id，包括以 12 表示的 H.265，以及
Enhanced RTMP 的 FourCC `hvc1`、`vp09`、`av01`、`vp08`、`Opus`、`mp4a`）；播放者先收到 onMetaData 和序列头，然后是 GOP 缓存，
由 `flv::Encoder` 写出（H.265 写作 `hvc1`，或在 `EncoderConfig::legacy_hevc` 时写作 codec id 12）。
`RtmpConfig::on_connect` 可按 app 和 tcUrl 拒绝连接。RTMPS 就是放在 only-tls 之后的 RTMP。客户端须在
`handshake_timeout`（10 s）内完成握手；连接 `idle_timeout`（60 s）内什么都没发送则被关闭（播放者除外：
不再读取的播放者由引擎的写超时约束）。单条消息上限 16 MiB，一个连接所有 chunk 流中未完成的消息合计上限
32 MiB。

## HTTP-FLV、WS-FLV 与 HLS

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:http}}
```

`MediaHttp` 按扩展名分发给两个 only-http 服务，它们也可以单独挂载：

- **`HttpFlv`**：`GET /app/name.flv` 输出一个永不结束的 FLV 文件（HTTP/1.1 上为 chunked，HTTP/2 上为
  流）。响应在订阅被接受后才开始，所以不存在的流返回 404，被拒绝的返回 403。同一 URL 升级为 WebSocket
  即 **WS-FLV**：第一个二进制消息是 FLV 头，之后每个 tag 一条消息，符合 flv.js 与 mpegts.js 的预期。
- **`Hls`**：`GET /app/name/index.m3u8` 在首次请求时启动一个 muxer（它订阅 hub，在 `idle_timeout`
  内无请求后停止），在超过 `target_duration` 后的关键帧处于内存中切出 MPEG-TS 分段，保留
  `playlist_size` 个分段的滑动窗口以及供迟到读者使用的 `keep_segments` 个，总量受 `max_bytes` 约束（达到该值仍没有关键帧可切的分段在此处切开），
  并以 `EXT-X-DISCONTINUITY` 标记重新推流。设置 `part_duration` 后加入低延迟 HLS 标签：
  `EXT-X-PART`、`EXT-X-PRELOAD-HINT`、`EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES`，以及阻塞式播放列表
  刷新（`?_HLS_msn=&_HLS_part=`）。需要等待的请求被挂起（不占线程），在分段或分片切出时由推流者线程应答。
- **fMP4 / CMAF 分段**：`HlsConfig::format = SegmentFormat::Fmp4` 切出分片 MP4 而非 MPEG-TS（H.264、
  H.265、VP8、VP9、AV1、AAC 与 Opus；MPEG-TS 不承载 VP8 / VP9 / AV1，视频无法承载的流按纯音频流切片）。播放列表用 `#EXT-X-MAP:URI="init-<n>.mp4"` 指向初始化分段（仅当编码配置变化时换新），
  分段为 `seg-<n>.m4s`，LL-HLS 分片为 `part-<n>.<m>.m4s`，每个分片由一个或多个完整的 `moof`+`mdat`
  组成。`only_media::fmp4`（`Muxer`、`Demuxer`）也可单独使用。
- **多码率播放列表**：同一来源的各个 rendition 作为单独的流发布（编码器阶梯、多个 WHIP 推流者），由
  `Hls::add_multivariant` 组合在一起：

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:multivariant}}
```

  `GET /live/show.m3u8` 为每个 `Variant` 列出一条 `EXT-X-STREAM-INF`：`BANDWIDTH`（配置值，或其分段与其
  音频组分段的峰值码率之和，此时还有 `AVERAGE-BANDWIDTH`）、`CODECS`（分段格式所承载轨道的 RFC 6381 字符串）、
  `RESOLUTION` 与 `AUDIO`，并为每个 `AudioRendition` 列出一条 `EXT-X-MEDIA:TYPE=AUDIO`。URI 是相对路径，并带上
  请求的 query string。首个请求会启动每个 rendition 的 muxer，在每个 rendition 都已知轨道且有一个分段后作答
  （尚未发布的 rendition 在三个目标时长后被略去）。两种分段格式与 LL-HLS 都适用。启用 LL-HLS 分片时，每个
  rendition 的媒体播放列表末尾会为其所在多码率播放列表中的其余每个 rendition 写一行
  `EXT-X-RENDITION-REPORT`（`LAST-MSN`、`LAST-PART`），切换码率的播放器因此能立即对新码率发出第一次阻塞式刷新。
- **I 帧播放列表**：设置 `HlsConfig::iframe_playlist` 后，带视频的流还提供 `GET /app/name/iframes.m3u8`
  （`EXT-X-I-FRAMES-ONLY`，用于拖动预览与快进快退）：所列分段中每个关键帧一项，一个指向其分段、可单独解码的
  `EXT-X-BYTERANGE`（MPEG-TS：PAT、PMT 与关键帧的 PES；fMP4：只含该关键帧的 `moof` + `mdat` 分片，此时 muxer
  在每个关键帧处切分片，并写在 `EXT-X-MAP` 之后）。分段、分片与 init 的响应以 206 应答单个 `Range: bytes=…`。
  多码率播放列表以 `EXT-X-I-FRAME-STREAM-INF` 列出每个变体的 I 帧播放列表（`BANDWIDTH` 为其 I 帧的峰值码率）。
  AES-128 下不提供（其密文无法从分段中间读取）；SAMPLE-AES 可用。
- **加密**：`HlsConfig::encryption` 用 AES-128（`#EXT-X-KEY:METHOD=AES-128`，CBC 加 PKCS #7）加密每个
  分段和 LL-HLS 分片，MPEG-TS 与 fMP4 相同：

```rust,ignore
use only_media::hls::{HlsConfig, HlsEncryption, HlsKey, KeyProvider};
use only_http::Context;

struct Keys; // 应用自己的密钥与权限检查
impl KeyProvider for Keys {
    // 在推流者线程上、某个分段需要密钥 `n` 时调用：不得阻塞。每次返回新的随机密钥
    // （流重启后密钥序号和 IV 都会从 0 重新开始）。
    fn key(&self, path: &str, n: u64) -> HlsKey {
        HlsKey::new(new_random_key(path, n)) // 并按应用需要记下它
    }
    // 每个 GET /<path>/key-<n>.key 请求，在请求方的 I/O 线程上调用（返回 false 时 403）。
    fn authorize(&self, path: &str, _n: u64, ctx: &Context) -> bool {
        ctx.header("cookie").is_some_and(|c| entitled(c, path))
    }
}

let mut cfg = HlsConfig::default();
cfg.encryption = Some(HlsEncryption::new(Keys).rotate_every(10)); // 每 10 个分段换一个密钥
```

  IV 是媒体序列号（不写 `IV` 属性），分片按其分段的 IV 单独加密，与播放器解密分片的方式一致。播放列表在
  密钥适用的第一条媒体之前写出密钥；fMP4 初始化分段保持明文（出现在密钥之后的 map 前写
  `#EXT-X-KEY:METHOD=NONE`）。只要仍有保留的分段使用某个密钥，就在 `key-<n>.key` 以
  `Cache-Control: private, no-store` 提供它，或由播放器从 `HlsKey::with_uri` 给出的 URI 获取。播放器
  请求密钥 URI 时带 cookie 和请求头，不带播放列表的 query string。`RandomKeys` 向所有人发放随机密钥
  （用于测试，或链接本身保密的场景）。

- **SAMPLE-AES**：`HlsEncryption::new(keys).method(EncryptionMethod::SampleAes)` 在容器内部加密样本，
  容器结构保持明文，密钥提供者、轮换与密钥 URI 都不变（`#EXT-X-KEY:METHOD=SAMPLE-AES`）。承载 H.264 与
  AAC，fMP4 中还有 H.265；其它轨道不进入分段，而不是以明文发出。
  - MPEG-TS：Apple 的样本加密。长于 48 字节的编码 slice 保留前 32 字节明文，之后每十个 16 字节块加密一个
    （AES-128-CBC，每个 NAL 单元从 IV 重新开始，作用于去除防竞争字节后的 NAL，加密后重新加入防竞争字节）；
    AAC 帧保留 ADTS 头和其后 16 字节明文，加密其余完整的块。PMT 会标明（流类型 0xdb 与 0xcf、`zavc` /
    `aacd`、`apad` 音频设置信息）。每个密钥一个随机 IV，写为 `IV` 属性（每个分段一个 IV 会让跨分段边界预读的
    播放器解错，ffmpeg 就是如此）。
  - fMP4：ISO/IEC 23001-7 的 `cbcs` 方案。初始化分段使用 `encv` / `enca` 条目及 `sinf`（`frma`、`schm`
    `cbcs`、带常量 IV 的 `tenc`）；分片带 `senc`、`saiz` 与 `saio`。每个 slice 的 NAL 头与 slice 头保持明文
    （解析 H.264 slice 头：参考列表修改、加权预测、参考帧标记；也解析 H.265 slice segment 头：短期参考图像集、
    长期参考图像、加权预测、tile 与波前入口点），slice 数据按 1:9 模式加密；AAC 样本整体加密。

  加密的多码率播放列表以 `EXT-X-SESSION-KEY` 写出每个 rendition 的当前密钥，播放器因此能在取第一个媒体
  播放列表之前就获取密钥。

  ffmpeg 能播放两者，逐帧解密正确。它对已预读的所有数据使用同一把密钥（fMP4 则一直使用打开时的密钥），
  因此在密钥轮换处会解出错误数据；Safari 与 hls.js 按分段获取密钥。

## 转发：RTMP 客户端

`only_media::rtmp::client` 把 hub 中的流推到另一台 RTMP 服务器，或从它拉流进 hub，使 `only-media`
的 hub 可以喂给 CDN 或转发上游编码器：

```rust,ignore
use only_media::rtmp::client::{self, RtmpClientConfig};

// hub 路径 live/cam -> rtmp://cdn.example/live/cam
let push = client::push(&engine, "rtmp://203.0.113.9/live/cam", &hub, "live/cam",
                        RtmpClientConfig::default())?;
// rtmp://origin/live/in -> hub 路径 relay/in（立即预占）
let pull = client::pull(&engine, "rtmp://203.0.113.10/live/in", &hub, "relay/in",
                        RtmpClientConfig::default())?;
```

两者都立即返回；会话运行在 I/O 线程上（`Engine::dial`）。`state()` 与 `error()` 反映进展，`close()`
（或丢弃句柄）结束会话。IP 字面量无需 DNS；主机名在调用线程上解析，所以请在 I/O 线程之外调用，或设置
`RtmpClientConfig::addr`。每一步都有超时（连接、握手、每条命令的应答各 10 s；拉流 30 s 收不到数据即结束），
收到的消息有上限（16 MiB），推流落后时先削减到关键帧再断开，与服务端的播放者相同。H.265 与 Opus 以
Enhanced RTMP 发送。

设置 `RtmpClientConfig::reconnect` 后，客户端能挺过对端离开：再试一次可能好转的错误（连接被关闭或被拒、
超时、服务端结束或拒绝该流且原因不是凭据）会使其进入 `ClientState::Reconnecting`，并在退避后重新拨号，退避
时间翻倍直到上限，会话一旦开始推流 / 播放就重置：

```rust,ignore
use std::{sync::Arc, time::Duration};
use only_media::{Reconnect, rtmp::client::{self, RtmpClientConfig}};

let engine = Arc::new(engine); // 客户端在它上面重新拨号（弱引用持有）
let mut cfg = RtmpClientConfig::default();
cfg.reconnect = Some(Reconnect::new(&engine).max_delay(Duration::from_secs(10)));
let pull = client::pull(&engine, "rtmp://203.0.113.10/live/in", &hub, "relay/in", cfg)?;
// 等待期间 pull.state() == ClientState::Reconnecting；pull.reconnects() 计数。
```

期间拉流保持对 hub 路径的预占：播放者保持订阅，并把新会话的轨道当作重新发布（时间线重启，HLS 写入
discontinuity）。推流重新订阅，并从缓存的 GOP 开始。URL 错误、hub 拒绝与凭据被拒仍会结束客户端；
`max_attempts` 限制连续尝试次数。`close()` 在 `is_closed()` 返回真之前释放拉流的路径。

## 录制

`only_media::record::Recorder` 把 hub 中的流写成分片 MP4、FLV 或 MPEG-TS 文件：

```rust,ignore
use std::time::Duration;
use only_media::record::{RecordConfig, RecordFile, RecordFormat, RecordHooks, Recorder};

struct Hooks;
impl RecordHooks for Hooks {
    // 在录制器的写线程上调用：可以阻塞（上传、写数据库）。
    fn on_stop(&self, f: &RecordFile, result: Result<(), &std::io::Error>) {
        println!("{} {:?} {} bytes {:?}", f.stream, f.duration, f.bytes, result);
    }
}

let mut cfg = RecordConfig::new("/var/lib/only/rec");
cfg.format = RecordFormat::Fmp4; // 或 Flv、MpegTs
cfg.segment_duration = Some(Duration::from_secs(600));
cfg.max_files = 144; // 保留最近一天的十分钟文件
let rec = Recorder::with_hooks(hub.clone(), cfg, Hooks);
rec.start("live/cam")?; // 最多等待 `cfg.wait`（10 秒）推流者出现，重新推流时也是
```

数据包像对任何播放者一样在推流者线程上封装；文件的创建、写入、同步（`on_stop` 之前 `sync_all`）与轮换由
录制器自己的写线程完成，从不在 I/O 线程上。文件从视频关键帧开始，时间戳从 0 起，在超过
`segment_duration` 或 `segment_bytes` 后的第一个关键帧处切换，重新推流或编码变化时也切换。到写线程的队列
有界（`max_queued_bytes`，32 MiB）：磁盘跟不上时关闭当前文件并丢包（`Recorder::dropped`），直到队列降到一半、
关键帧开始下一个文件，所以慢磁盘只会在文件之间留下空档，不会产生损坏的文件。`RecordHooks::file_name` 为文件
命名（相对 `dir`），`on_start`、`on_stop` 与 `on_remove`（轮换）跟踪文件。要录制所有流，在 hub 的
`on_publish` 钩子中调用 `start`。MPEG-TS 文件在每个视频关键帧前（以及至少每秒）重复 PAT 与 PMT，因此被截断
的文件也能从任一关键帧播放。

## MPEG-TS 中的 AV1

MPEG-TS 封装器与解封装器按开放媒体联盟的规范（"Carriage of AV1 in MPEG-2 TS"）承载 AV1：流类型 0x06，
带 `AV01` 注册描述符与 AV1 视频描述符（0x80），每个 PES 一个时间单元（置 `data_alignment_indicator`），
每个 OBU 前有 `00 00 01` 起始码并加入防竞争字节，开头是时间分隔符，缺少序列头的关键帧前补上序列头。解封装器也
读取 GStreamer 的临时映射 `AV1G`（裸 OBU）。因此 AV1 现在可以经 SRT 与 HLS MPEG-TS 发出，也能录制为 MPEG-TS。
ffmpeg 目前还不能解封装 MPEG-TS 中的 AV1（其支持仍在评审中）；格式按规范核对，通过封装器与解封装器的往返验证，
并把 ffmpeg 提取的 PES 负载交给另一个独立实现的起始码格式读回后用 dav1d 解码：每一帧都与源相同。VP8 与 VP9 根本没有 MPEG-TS 映射：仍只用于 fMP4、FLV、RTP 与 WebRTC。

## 运行

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:engine}}
```

```console
$ cargo run -p only-media --example guide-media
$ ffmpeg -re -f lavfi -i testsrc=size=640x360:rate=25 -f lavfi -i sine \
    -c:v libx264 -g 50 -c:a aac -f flv rtmp://127.0.0.1:1935/live/cam
$ ffprobe rtmp://127.0.0.1:1935/live/cam
$ ffprobe http://127.0.0.1:8080/live/cam.flv
$ ffplay http://127.0.0.1:8080/live/cam/index.m3u8
```

## 互通

集成测试（`crates/only-media/tests/*_interop.rs`，未安装 ffmpeg 时跳过）以 ffmpeg 9 作为推流端，
ffprobe / ffmpeg 作为播放端：

| 推流端 | 播放端 | 编码 |
|---|---|---|
| `ffmpeg -f flv rtmp://…` | `ffprobe` / `ffmpeg -i rtmp://…` | H.264 + AAC、H.265 + Opus（Enhanced RTMP） |
| `ffmpeg -f flv rtmp://…` | `ffprobe` / `ffmpeg -i http://…/x.flv` 与 `…/index.m3u8`（开启 LL-HLS） | H.264 + AAC、H.265 + AAC |
| `ffmpeg -f rtsp rtsp://…` | RTMP、HTTP-FLV、HLS、RTSP（UDP） | H.264 + AAC |
| `ffmpeg -f flv rtmp://…` | RTSP（TCP） | H.264 + AAC |
| hub 推流者 | 手写的 HTTP-FLV、WS-FLV 与 HLS 客户端 | H.264 + AAC |
| hub 推流者 | `ffprobe` / `ffmpeg -i …/index.m3u8`，fMP4，普通与 LL-HLS | H.264 + AAC、H.265 + AAC、H.265 + Opus、VP9 + Opus、AV1 + Opus |
| `ffmpeg -f flv rtmp://…`（Enhanced RTMP） | `ffprobe` / `ffmpeg -i rtmp://…` | VP9 + Opus、AV1 + Opus |
| hub 推流者（3 个 rendition） | `ffprobe` / `ffmpeg -i …/show.m3u8`，MPEG-TS 与 fMP4 LL-HLS | H.265 + H.264 两个 variant，AAC 音频组 |
| 经 WHIP 推流的 Chrome（`tools/interop/media/browser.sh`） | hls.js、Chrome 自带播放器：多码率 fMP4 LL-HLS | AV1 阶梯 + Opus |
| RTMP 客户端推流 | `ffmpeg -listen 1 -i rtmp://…`、mediamtx（`--ignored`） | H.264 + AAC、H.265 + AAC |
| `ffmpeg -listen 1 -f flv rtmp://…`、mediamtx | RTMP 客户端拉流 | H.264 + AAC、H.265 + AAC |
| hub 推流者，AES-128 加密并轮换密钥 | `ffprobe` / `ffmpeg -headers … -i …/index.m3u8`，MPEG-TS 与 fMP4，普通与 LL-HLS | H.264 + AAC |
| hub 推流者，SAMPLE-AES（MPEG-TS）与 `cbcs`（fMP4） | `ffmpeg -headers … -i …/index.m3u8 -f framemd5`：每一帧都与源相同，普通与 LL-HLS | H.264 + AAC；H.265 + AAC（`cbcs`） |
| hub 推流者（2 个 rendition），I 帧播放列表 | 每个 `EXT-X-BYTERANGE` 以 `Range` 获取后由 `ffmpeg` 解码为恰好一帧源画面；对多码率播放列表执行 `ffprobe` | H.264 + AAC、H.265 + AAC；MPEG-TS 与 fMP4 LL-HLS |
| ffmpeg → mediamtx（重启两次，`--ignored`） | RTMP 与 RTSP 客户端的拉流与推流自动重连 | H.264 + AAC |
| hub 推流者，`Recorder` | 对每个 fMP4、FLV 与 MPEG-TS 文件执行 `ffprobe` / `ffmpeg -i` | H.264 + AAC、H.265 + AAC |

RTSP 与 SRT 的互通表在各自章节中。模糊测试覆盖 RTMP 会话（`rtmp_server`）与客户端（`rtmp_client`）、
FLV（`flv_demux`）、fMP4（`fmp4_demux`）、AMF（`amf_decode`）以及 RTSP、SDP、RTP、MPEG-TS（含 AV1）和 SRT
（含 rendezvous 握手，`srt_rendezvous`）的解析器，还有 H.264 slice 头解析器与两种样本加密
（`h264_sample_encryption`），以及 H.265 slice segment 头解析器与 `cbcs`（`h265_sample_encryption`）。

## 不支持

H.264、H.265（fMP4）与 AAC 以外编码的 SAMPLE-AES、AES-128 下的 I 帧播放列表、
MPEG-TS 中的 VP8 / VP9（无规范）、RTMPS 客户端、RTMPE / RTMPT、AMF3 应答、Enhanced RTMP 多轨、转码。
