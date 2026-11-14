# only-media

[English](README.md)

[only](https://github.com/lesismal/only) 的流媒体组件：一个流 hub，周围是 RTMP、RTSP、SRT、
HTTP-FLV、WS-FLV、HLS 以及 WHIP/WHEP 信令。每个协议都与 `only_media::av` 的规范包互相转换，因此用任一
协议推上来的流都能用其它所有协议播放。

| 模块 | 功能 |
|---|---|
| `hub` | 按路径区分的流，一个推流者多个订阅者，GOP 缓存（秒开），慢播放者丢帧至下一个关键帧，推流 / 播放鉴权钩子，等待推流者与重新推流，时间戳规整（`Timeline`），统计 |
| `rtmp` | 服务端：简单握手与 Flash digest 握手、chunk 流、推流 / 播放、Enhanced RTMP（H.265 `hvc1`、Opus） |
| `rtsp`、`rtp`、`sdp` | RTSP 1.0 服务端：基于 TCP 交织与 UDP 的 ANNOUNCE/RECORD 和 DESCRIBE/SETUP/PLAY，Digest/Basic 鉴权；H.264、H.265、AAC、Opus、G.711 的 RTP |
| `srt` | SRT live 模式：HSv5 主叫与监听、ARQ、TSBPD 延迟、基于密码的 AES-CTR、stream ID 访问控制；`push` / `pull` |
| `httpflv`、`hls`、`http` | HTTP-FLV 与 WS-FLV；MPEG-TS 分段的 HLS，LL-HLS 分片、预加载提示与阻塞式刷新；同时分发二者的 `MediaHttp` |
| `whip` | WHIP / WHEP HTTP 信令，媒体侧通过 `WebRtcEngine` trait 接入 |
| `flv`、`mpegts`、`amf`、`codec` | FLV 封装/解封装（传统与 Enhanced RTMP tag）、MPEG-TS 封装/解封装、AMF0/AMF3、H.264 / H.265 / AAC / Opus 工具 |

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

暂不支持：fMP4 HLS 与 HLS 加密、RTMP 与 RTSP 客户端（转推/拉流）、SRT rendezvous、WebRTC 媒体
（WebRTC crate 通过 `whip::WebRtcEngine` 接入）、AV1 / VP9、录制、转码。

许可证：MIT。
