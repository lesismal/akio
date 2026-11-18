# only-media

[English](README.md)

[only](https://github.com/lesismal/only) 的流媒体组件：一个流 hub，周围是 RTMP、RTSP、SRT、
HTTP-FLV、WS-FLV、HLS 以及 WHIP/WHEP。每个协议都与 `only_media::av` 的规范包互相转换，因此用任一
协议推上来的流都能用其它所有协议播放。

| 模块 | 功能 |
|---|---|
| `hub` | 按路径区分的流，一个推流者多个订阅者，GOP 缓存（秒开），慢播放者丢帧至下一个关键帧，推流 / 播放鉴权钩子，等待推流者与重新推流，时间戳规整（`Timeline`），统计 |
| `rtmp` | 服务端与客户端（`rtmp::client::{push, pull}`）：简单握手与 Flash digest 握手、chunk 流、推流 / 播放、Enhanced RTMP（H.265 `hvc1`、VP9 `vp09`、AV1 `av01`、VP8 `vp08`、Opus） |
| `rtsp`、`rtp`、`sdp` | RTSP 1.0 服务端与客户端（`rtsp::client::{pull, push}`）：基于 TCP 交织与 UDP 的 ANNOUNCE/RECORD 和 DESCRIBE/SETUP/PLAY，Digest/Basic 鉴权；H.264、H.265、VP8、VP9、AV1、AAC、Opus、G.711 的 RTP |
| `srt` | SRT live 模式：HSv5 主叫与监听、ARQ、TSBPD 延迟、基于密码的 AES-CTR、stream ID 访问控制；`push` / `pull` |
| `httpflv`、`hls`、`http` | HTTP-FLV 与 WS-FLV；MPEG-TS 或 fMP4（CMAF）分段的 HLS，LL-HLS 分片、预加载提示与阻塞式刷新，以及由分别发布的多路流组成的多码率播放列表，带密钥轮换与密钥提供者钩子的 AES-128 加密；同时分发二者的 `MediaHttp` |
| `record` | 把 hub 中的流录制为 fMP4 或 FLV 文件：按时长或大小在关键帧处切换文件、轮换、开始 / 结束钩子，由独立线程（从不是 I/O 线程）在有界队列之后写入 |
| `whip`、`webrtc` | WHIP / WHEP HTTP 信令与 `WebRtcEngine` trait；开启 `webrtc` feature 后，`webrtc::RtcMedia` 经 only-webrtc 承载 H.264 / H.265 / VP8 / VP9 / AV1 / Opus / G.711，观众的 PLI 会到达推流者 |
| `flv`、`mpegts`、`fmp4`、`amf`、`codec` | FLV 封装/解封装（传统与 Enhanced RTMP tag）、MPEG-TS 封装/解封装、分片 MP4 封装/解封装、AMF0/AMF3、H.264 / H.265 / VP8 / VP9 / AV1 / AAC / Opus 工具 |

```rust,no_run
use only::{Engine, Listener};
use only_http::{Router, serve};
use only_media::{Hub, hls::{Hls, HlsConfig}, http::MediaHttp,
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
结果见书中章节：[流媒体](https://lesismal.github.io/only/zh-CN/protocols/media.html)、
[RTSP 与 WHIP/WHEP](https://lesismal.github.io/only/zh-CN/protocols/media-rtsp.html)、
[SRT](https://lesismal.github.io/only/zh-CN/protocols/media-srt.html)。

暂不支持：HLS SAMPLE-AES / CBCS、SRT rendezvous、MPEG-TS 中的 VP8 / VP9 / AV1、录制为 MPEG-TS、转码。

许可证：MIT。
