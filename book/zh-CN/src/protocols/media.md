# 流媒体：hub、RTMP、HTTP-FLV、HLS

`only-media` 是直播服务端工具集：一个流 **hub**，周围是全部推流与播放协议。通过 RTMP、RTSP 或
SRT 推上来的流，可以用 RTMP、RTSP、SRT、HTTP-FLV、WS-FLV 和 HLS 播放，协议之间没有任何胶水代码：
每个协议都把收到的内容转换成 `only_media::av` 的规范包，再从规范包封装输出。

| 协议 | 推流 | 播放 | 章节 |
|---|---|---|---|
| RTMP（digest 握手、Enhanced RTMP 的 H.265 / Opus） | 支持 | 支持 | 本章 |
| HTTP-FLV、WS-FLV | – | 支持 | 本章 |
| HLS（MPEG-TS、LL-HLS 分片、阻塞式刷新） | – | 支持 | 本章 |
| RTSP（TCP 交织与 UDP） | 支持 | 支持 | [RTSP 与 WHIP/WHEP](media-rtsp.md) |
| SRT live（ARQ、TSBPD、AES） | 支持 | 支持 | [SRT](media-srt.md) |
| WHIP / WHEP | 信令（媒体可插入） | 信令 | [RTSP 与 WHIP/WHEP](media-rtsp.md) |

编码：H.264、H.265、AAC 和 Opus，凡容器能承载之处都支持（容器允许时还有 G.711 与 MP3）。下面的代码片段
来自 `crates/only-media/examples/guide-media.rs`。

## 规范形式

`av::Track` 描述一路基本流：`Codec` 及其 ISO BMFF 形式的配置（带参数集的
`AVCDecoderConfigurationRecord` / `HEVCDecoderConfigurationRecord`、AAC 的 `AudioSpecificConfig`、
`OpusHead`），以及画面尺寸或采样率。`av::Packet` 是一个访问单元：AVCC 视频（4 字节 NAL 长度，不含访问
单元分隔符）、不带 ADTS 的 AAC 原始帧、Opus 包；解码时间与显示时间以纳秒计。`only_media::codec`
提供 AVCC 与 Annex B 互转、解析配置记录与 SPS（画面尺寸）以及 ADTS 分帧的工具。

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
Enhanced RTMP 的 FourCC `hvc1`、`Opus`、`mp4a`）；播放者先收到 onMetaData 和序列头，然后是 GOP 缓存，
由 `flv::Encoder` 写出（H.265 写作 `hvc1`，或在 `EncoderConfig::legacy_hevc` 时写作 codec id 12）。
`RtmpConfig::on_connect` 可按 app 和 tcUrl 拒绝连接。RTMPS 就是放在 only-tls 之后的 RTMP。

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
  `playlist_size` 个分段的滑动窗口以及供迟到读者使用的 `keep_segments` 个，总量受 `max_bytes` 约束，
  并以 `EXT-X-DISCONTINUITY` 标记重新推流。设置 `part_duration` 后加入低延迟 HLS 标签：
  `EXT-X-PART`、`EXT-X-PRELOAD-HINT`、`EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES`，以及阻塞式播放列表
  刷新（`?_HLS_msn=&_HLS_part=`）。需要等待的请求被挂起（不占线程），在分段或分片切出时由推流者线程应答。

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

RTSP 与 SRT 的互通表在各自章节中。模糊测试覆盖 RTMP 会话（`rtmp_server`）、FLV（`flv_demux`）、
AMF（`amf_decode`）以及 RTSP、SDP、RTP、MPEG-TS 和 SRT 的解析器。

## 不支持

fMP4 HLS 分段与 HLS 加密、RTMP 客户端（推 / 拉转发）、RTMPE / RTMPT、AMF3 应答、Enhanced RTMP
多轨、AV1 / VP9、录制到文件、转码。
