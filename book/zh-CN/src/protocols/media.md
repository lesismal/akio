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
  （尚未发布的 rendition 在三个目标时长后被略去）。两种分段格式与 LL-HLS 都适用。
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
  （用于测试，或链接本身保密的场景）。不支持 SAMPLE-AES / CBCS。

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

## 录制

`only_media::record::Recorder` 把 hub 中的流写成分片 MP4 或 FLV 文件：

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
cfg.format = RecordFormat::Fmp4; // 或 Flv
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
`on_publish` 钩子中调用 `start`。

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
| hub 推流者，`Recorder` | 对每个 fMP4 与 FLV 文件执行 `ffprobe` / `ffmpeg -i` | H.264 + AAC、H.265 + AAC |

RTSP 与 SRT 的互通表在各自章节中。模糊测试覆盖 RTMP 会话（`rtmp_server`）与客户端（`rtmp_client`）、
FLV（`flv_demux`）、fMP4（`fmp4_demux`）、AMF（`amf_decode`）以及 RTSP、SDP、RTP、MPEG-TS 和 SRT 的解析器。

## 不支持

HLS SAMPLE-AES / CBCS、I-frame 播放列表与 rendition report、MPEG-TS 中的 VP8 / VP9 / AV1、RTMPS 客户端、
RTMPE / RTMPT、AMF3 应答、Enhanced RTMP 多轨、录制为 MPEG-TS、转码。
