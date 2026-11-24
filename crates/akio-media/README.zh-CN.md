# akio-media

[English](README.md)

[akio](https://github.com/lesismal/akio) 的流媒体组件：一个流 hub，周围是 RTMP、RTSP、SRT、
HTTP-FLV、WS-FLV、HLS 以及 WHIP/WHEP。每个协议都与 `akio_media::av` 的规范包互相转换，因此用任一
协议推上来的流都能用其它所有协议播放。

| 模块 | 功能 |
|---|---|
| `hub` | 按路径区分的流，一个推流者多个订阅者，GOP 缓存（秒开），慢播放者丢帧至下一个关键帧，推流 / 播放鉴权钩子，等待推流者与重新推流，时间戳规整（`Timeline`），统计 |
| `rtmp` | 服务端与客户端（`rtmp::client::{push, pull}`，可按需以有上限的退避自动重连）：简单握手与 Flash digest 握手、chunk 流、推流 / 播放、Enhanced RTMP（H.265 `hvc1`、VP9 `vp09`、AV1 `av01`、VP8 `vp08`、Opus） |
| `rtsp`、`rtp`、`sdp` | RTSP 1.0 服务端与客户端（`rtsp::client::{pull, push}`，可按需自动重连；录制与拉流的各轨按 RTCP 发送端报告对齐）：基于 TCP 交织与 UDP 的 ANNOUNCE/RECORD 和 DESCRIBE/SETUP/PLAY，Digest/Basic 鉴权；H.264、H.265、VP8、VP9、AV1、AAC、Opus、G.711 的 RTP |
| `srt` | SRT live 模式：HSv5 主叫、监听与 rendezvous、ARQ、TSBPD 延迟、基于密码的 AES-CTR、stream ID 访问控制；`push` / `pull`（以及经 rendezvous 的 `push_rendezvous` / `pull_rendezvous`） |
| `httpflv`、`hls`、`http` | HTTP-FLV 与 WS-FLV；MPEG-TS 或 fMP4（CMAF）分段的 HLS，LL-HLS 分片、预加载提示与阻塞式刷新，以及由分别发布的多路流组成的多码率播放列表（含 I 帧播放列表（AES-128 下亦可）、带请求 query string 的 rendition report 与会话密钥），带密钥轮换与密钥提供者钩子的 AES-128 或 SAMPLE-AES 加密（MPEG-TS 中为 Apple 的样本加密，用于 H.264 与 AAC；fMP4 中为 `cbcs`，用于 H.264、H.265 与 AAC）；同时分发二者的 `MediaHttp` |
| `record` | 把 hub 中的流录制为 fMP4、FLV 或 MPEG-TS 文件：按时长或大小在关键帧处切换文件、轮换、开始 / 结束钩子，由独立线程（从不是 I/O 线程）在有界队列之后写入 |
| `whip`、`webrtc` | WHIP / WHEP HTTP 信令与 `WebRtcEngine` trait；开启 `webrtc` feature 后，`webrtc::RtcMedia` 经 akio-webrtc 承载 H.264 / H.265 / VP8 / VP9 / AV1 / Opus / G.711，观众的 PLI 会到达推流者 |
| `mp4` | 非分片的 MP4 文件，读取器本身不做 I/O（调用方在 I/O 线程之外读取它指出的字节范围）：`moov` 在开头或末尾，紧凑的采样索引，按时间查找关键帧，以及不转码、在关键帧处切出的 HLS 分段，复用为 fMP4 或 MPEG-TS，并给出点播播放列表 |
| `flv`、`mpegts`、`fmp4`、`amf`、`codec` | FLV 封装/解封装（传统与 Enhanced RTMP tag）、MPEG-TS 封装/解封装（H.264、H.265、AV1、AAC、Opus、MP3）、分片 MP4 封装/解封装、AMF0/AMF3、H.264 / H.265 / VP8 / VP9 / AV1 / AAC / Opus 工具 |

```rust,no_run
use akio::{Engine, Listener};
use akio_http::{Router, serve};
use akio_media::{Hub, hls::{Hls, HlsConfig}, http::MediaHttp,
    httpflv::{HttpFlv, HttpFlvConfig}, rtmp::{RtmpConfig, RtmpServer}};

let hub = Hub::default();
let media = MediaHttp::new()
    .flv(HttpFlv::new(hub.clone(), HttpFlvConfig::default()))
    .hls(Hls::new(hub.clone(), HlsConfig::default()));
let engine = Engine::builder()
    .listen(Listener::tcp("0.0.0.0:1935".parse().unwrap())
        .serve(RtmpServer::new(hub.clone(), RtmpConfig::default())))
    .listen(Listener::tcp("0.0.0.0:8080".parse().unwrap())
        .serve(serve(Router::new().get("/*path", media))))
    .build()
    .unwrap();
engine.run().unwrap();
// ffmpeg -re -i in.mp4 -c copy -f flv rtmp://127.0.0.1/live/s
// ffplay http://127.0.0.1:8080/live/s.flv   |   ffplay http://127.0.0.1:8080/live/s/index.m3u8
```

每个协议都以 ffmpeg / ffprobe 作为推流端和播放端做了互通测试（SRT 在带 libsrt 的 Docker 中），命令与
结果见书中章节：[流媒体](https://lesismal.github.io/akio/zh-CN/protocols/media.html)、
[RTSP 与 WHIP/WHEP](https://lesismal.github.io/akio/zh-CN/protocols/media-rtsp.html)、
[SRT](https://lesismal.github.io/akio/zh-CN/protocols/media-srt.html)。

不支持：H.264 / H.265（fMP4）/ AAC 以外编码的 SAMPLE-AES、转码，以及 MPEG-TS 中的 VP8 / VP9（没有任何规范定义它们的映射，也没有解封装器读取）。MPEG-TS 中的 AV1 遵循 AOM 的映射，ffmpeg 目前还不能解封装（其支持仍在评审中）。

许可证：MIT。
