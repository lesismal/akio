# only-media

[中文](README.zh-CN.md)

Streaming media for [`only`](https://github.com/lesismal/only): one stream hub with RTMP,
RTSP, SRT, HTTP-FLV, WS-FLV, HLS and WHIP/WHEP around it. Every protocol converts to
and from the canonical packets of `only_media::av`, so a stream published with one protocol
plays with every other.

| Module | What it does |
|---|---|
| `hub` | streams by path, one publisher and many subscribers, GOP cache (fast start), slow-player dropping to the next keyframe, publish / play auth hooks, wait-for-publisher and republish, timestamp normalization (`Timeline`), statistics |
| `rtmp` | server and client (`rtmp::client::{push, pull}`, reconnecting with a bounded backoff on request): simple and Flash digest handshake, chunk stream, publish / play, Enhanced RTMP (H.265 `hvc1`, VP9 `vp09`, AV1 `av01`, VP8 `vp08`, Opus) |
| `rtsp`, `rtp`, `sdp` | RTSP 1.0 server and client (`rtsp::client::{pull, push}`, reconnecting on request; recorded and pulled tracks lined up by RTCP sender reports): ANNOUNCE/RECORD and DESCRIBE/SETUP/PLAY over TCP interleaved and UDP, Digest/Basic auth; RTP for H.264, H.265, VP8, VP9, AV1, AAC, Opus, G.711 |
| `srt` | SRT live mode: HSv5 caller, listener and rendezvous, ARQ, TSBPD latency, AES-CTR with passphrase, stream ID access control; `push` / `pull` (and over a rendezvous: `push_rendezvous` / `pull_rendezvous`) |
| `httpflv`, `hls`, `http` | HTTP-FLV and WS-FLV; HLS with MPEG-TS or fMP4 (CMAF) segments, LL-HLS parts, preload hints and blocking reload, multivariant playlists over renditions published as separate streams (with I-frame playlists, also under AES-128, rendition reports carrying the request's query, and session keys), AES-128 or SAMPLE-AES encryption (Apple's sample encryption in MPEG-TS for H.264 and AAC, `cbcs` in fMP4 for H.264, H.265 and AAC) with key rotation and a key provider hook; `MediaHttp` dispatching both |
| `record` | recording hub streams to fMP4, FLV or MPEG-TS files: cut by duration or size at keyframes, rotation, start / stop hooks, written by a thread of its own (never an I/O thread) behind a bounded queue |
| `whip`, `webrtc` | WHIP / WHEP HTTP signalling with a `WebRtcEngine` trait; with the `webrtc` feature, `webrtc::RtcMedia` carries H.264 / H.265 / VP8 / VP9 / AV1 / Opus / G.711 through only-webrtc, viewer PLIs reaching the publisher |
| `flv`, `mpegts`, `fmp4`, `amf`, `codec` | FLV mux/demux (legacy and Enhanced RTMP tags), MPEG-TS mux/demux (H.264, H.265, AV1, AAC, Opus, MP3), fragmented MP4 mux/demux, AMF0/AMF3, H.264 / H.265 / VP8 / VP9 / AV1 / AAC / Opus helpers |

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

Not supported: SAMPLE-AES for codecs other than H.264 / H.265 (fMP4) / AAC, transcoding, and
VP8 / VP9 in MPEG-TS (no mapping is specified for them, and no demuxer reads one). AV1 in MPEG-TS
follows the AOM mapping, which ffmpeg cannot demux yet (its support is still under review).

License: MIT.
