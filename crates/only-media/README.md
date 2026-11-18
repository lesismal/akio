# only-media

[中文](README.zh-CN.md)

Streaming media for [`only`](https://github.com/lesismal/only): one stream hub with RTMP,
RTSP, SRT, HTTP-FLV, WS-FLV, HLS and WHIP/WHEP around it. Every protocol converts to
and from the canonical packets of `only_media::av`, so a stream published with one protocol
plays with every other.

| Module | What it does |
|---|---|
| `hub` | streams by path, one publisher and many subscribers, GOP cache (fast start), slow-player dropping to the next keyframe, publish / play auth hooks, wait-for-publisher and republish, timestamp normalization (`Timeline`), statistics |
| `rtmp` | server and client (`rtmp::client::{push, pull}`): simple and Flash digest handshake, chunk stream, publish / play, Enhanced RTMP (H.265 `hvc1`, Opus) |
| `rtsp`, `rtp`, `sdp` | RTSP 1.0 server and client (`rtsp::client::{pull, push}`): ANNOUNCE/RECORD and DESCRIBE/SETUP/PLAY over TCP interleaved and UDP, Digest/Basic auth; RTP for H.264, H.265, AAC, Opus, G.711 |
| `srt` | SRT live mode: HSv5 caller and listener, ARQ, TSBPD latency, AES-CTR with passphrase, stream ID access control; `push` / `pull` |
| `httpflv`, `hls`, `http` | HTTP-FLV and WS-FLV; HLS with MPEG-TS or fMP4 (CMAF) segments, LL-HLS parts, preload hints and blocking reload; `MediaHttp` dispatching both |
| `whip`, `webrtc` | WHIP / WHEP HTTP signalling with a `WebRtcEngine` trait; with the `webrtc` feature, `webrtc::RtcMedia` carries H.264 / H.265 / Opus / G.711 through only-webrtc, viewer PLIs reaching the publisher |
| `flv`, `mpegts`, `fmp4`, `amf`, `codec` | FLV mux/demux (legacy and Enhanced RTMP tags), MPEG-TS mux/demux, fragmented MP4 mux/demux, AMF0/AMF3, H.264 / H.265 / AAC / Opus helpers |

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

Interoperability is tested with ffmpeg / ffprobe as publisher and player for every protocol
(SRT in Docker with libsrt); the commands and results are in the book chapters:
[Streaming media](https://lesismal.github.io/only/en/protocols/media.html),
[RTSP and WHIP/WHEP](https://lesismal.github.io/only/en/protocols/media-rtsp.html),
[SRT](https://lesismal.github.io/only/en/protocols/media-srt.html).

Not supported yet: HLS encryption and multivariant playlists, SRT rendezvous, AV1 / VP9 / VP8
in the hub, recording, transcoding.

License: MIT.
