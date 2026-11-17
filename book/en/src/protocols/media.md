# Streaming media: hub, RTMP, HTTP-FLV, HLS

`only-media` is a live streaming server toolkit: one stream **hub** with every ingest and
egress protocol around it. A stream published over RTMP, RTSP or SRT plays over RTMP, RTSP,
SRT, HTTP-FLV, WS-FLV and HLS, with no protocol-to-protocol glue: every protocol converts what
it receives into the canonical packets of `only_media::av` and muxes from them.

| Protocol | In (publish) | Out (play) | Chapter |
|---|---|---|---|
| RTMP (digest handshake, Enhanced RTMP H.265 / Opus), server and client | yes | yes | this one |
| HTTP-FLV, WS-FLV | – | yes | this one |
| HLS (MPEG-TS or fMP4/CMAF, LL-HLS parts, blocking reload) | – | yes | this one |
| RTSP (TCP interleaved and UDP), server and client | yes | yes | [RTSP and WHIP/WHEP](media-rtsp.md) |
| SRT live (ARQ, TSBPD, AES) | yes | yes | [SRT](media-srt.md) |
| WHIP / WHEP (media with the `webrtc` feature) | yes | yes | [RTSP and WHIP/WHEP](media-rtsp.md) |

Codecs: H.264, H.265, AAC and Opus everywhere they can be carried (G.711 and MP3 where the
container allows). Snippets below are from `crates/only-media/examples/guide-media.rs`.

## The canonical form

`av::Track` describes an elementary stream: its `Codec` and its configuration in the ISO BMFF
form (the `AVCDecoderConfigurationRecord` / `HEVCDecoderConfigurationRecord` with the parameter
sets, the AAC `AudioSpecificConfig`, the `OpusHead`), plus picture size or sample rate.
`av::Packet` is one access unit: AVCC video (4-byte NAL lengths, no access unit delimiters),
raw AAC frames without ADTS, Opus packets; decode and presentation times in nanoseconds.
`only_media::codec` has the helpers to go between AVCC and Annex B, parse the configuration
records and SPS (picture size), and frame ADTS.

## The hub

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:hub}}
```

- **Streams by path.** RTMP `rtmp://host/app/name` publishes `app/name`; RTSP, SRT, HTTP and
  WHIP use the same paths (`rtsp://host/app/name`, `http://host/app/name.flv`,
  `streamid=#!::r=app/name`). The URL's query string travels in `PeerInfo::query`.
- **One publisher, many subscribers.** A second publisher of a path is refused with
  `HubError::StreamBusy`, and an ingest that does not know its tracks yet (RTMP before its
  sequence headers, SRT before the first PMT and parameter sets) **reserves** the path, so the
  refusal happens in the handshake.
- **Auth hooks.** `on_publish` and `on_subscribe` authorize every protocol at once;
  `on_unpublish` observes publishers leaving. Hooks run without any hub lock held.
- **Limits.** `max_streams` (1024) and `max_subscribers` (1000 per path) bound the tables a
  client grows; past them publishes and plays fail with `HubError::Limit` (503 over HTTP,
  OVERLOAD over SRT). 0 removes a limit.
- **GOP cache, fast start.** Each stream keeps every packet since the last video keyframe (an
  audio-only stream its last second), bounded by `gop_cache_bytes`. A new subscriber hears the
  tracks and the cache before anything newer, so playback starts at once with a picture.
- **Backpressure.** Fan-out is synchronous on the publisher's I/O thread: sinks queue onto
  their connection and never block. Every egress wraps its sink in `hub::Dropper`: while the
  connection's queue is over `write_queue_limit`, packets are dropped, and video then resumes
  at the next keyframe (audio at once); past `max_write_queue` the player is disconnected. A
  slow player never slows the publisher or grows memory.
- **Timestamp normalization.** `hub::Timeline` keeps each egress's timestamps increasing per
  track across republishes and codec changes, so a player that waits (`play_wait`) for the
  next publisher continues smoothly.
- **Stats.** `Hub::streams()` / `stream_info(path)` give the publisher, its protocol and
  address, tracks, subscriber count, bytes and packets in, and packets dropped for slow
  players.

A sink of your own (recorder, relay, analytics) is a `Sink`:

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:sink}}
```

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:subscribe}}
```

Dropping the `Subscription` (or the `Publisher`) ends it. `SubscribeOptions::wait` lets a
subscription exist before its publisher and survive a republish; `no_gop_cache` starts at the
next keyframe instead of the cache.

## RTMP

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:rtmp}}
```

`RtmpServer` is an `Acceptor`. It does the simple and the Flash digest ("complex") handshake,
the full chunk stream (all four header formats, extended timestamps, chunk size changes,
aborts, aggregate messages, acknowledgements), and answers `connect`, `releaseStream`,
`FCPublish`, `createStream`, `publish`, `play`, `getStreamLength`, `FCUnpublish`,
`deleteStream`, `closeStream`. Publishers' FLV tags go through `flv::Decoder` (legacy codec ids
including H.265 as id 12, and Enhanced RTMP FourCCs `hvc1`, `Opus`, `mp4a`); players get
onMetaData and the sequence headers first, then the GOP cache, written by `flv::Encoder`
(H.265 as `hvc1`, or codec id 12 with `EncoderConfig::legacy_hevc`). `RtmpConfig::on_connect`
can reject connections by app and tcUrl. RTMPS is RTMP behind only-tls. A client must finish
the handshake within `handshake_timeout` (10 s), and a connection that sends nothing for
`idle_timeout` (60 s) is closed (players are exempt: a player that stops reading is bounded by
the engine's write timeout). Messages are limited to 16 MiB and unfinished messages over all
chunk streams of a connection to 32 MiB.

## HTTP-FLV, WS-FLV and HLS

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:http}}
```

`MediaHttp` dispatches by extension to two only-http services you can also mount on their own:

- **`HttpFlv`**: `GET /app/name.flv` streams an FLV file that never ends (chunked on
  HTTP/1.1, a stream on HTTP/2). The response starts once the subscription is accepted, so a
  missing stream is a 404 and a refused one a 403. The same URL upgraded to a WebSocket is
  **WS-FLV**: the FLV header as the first binary message, then one message per tag, as flv.js
  and mpegts.js expect.
- **`Hls`**: `GET /app/name/index.m3u8` starts a muxer on first request (it subscribes to the
  hub and stops after `idle_timeout` without requests) that cuts MPEG-TS segments in memory at
  keyframes after `target_duration`, keeps a sliding window of `playlist_size` segments plus
  `keep_segments` for late readers, bounded by `max_bytes` (a segment that reaches it without a
  keyframe to cut at is cut there), and marks republishes with
  `EXT-X-DISCONTINUITY`. With `part_duration` it adds the Low-Latency HLS tags:
  `EXT-X-PART`, `EXT-X-PRELOAD-HINT`, `EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES`, and blocking
  playlist reloads (`?_HLS_msn=&_HLS_part=`). Requests that must wait are parked (no thread is
  held) and answered by the publisher's thread when the segment or part is cut.
- **fMP4 / CMAF segments**: `HlsConfig::format = SegmentFormat::Fmp4` cuts fragmented MP4
  instead of MPEG-TS (H.264, H.265, AAC and Opus). The playlist names an init segment with
  `#EXT-X-MAP:URI="init-<n>.mp4"` (a new one only when the codec configuration changes),
  segments are `seg-<n>.m4s` and LL-HLS parts `part-<n>.<m>.m4s`, each part one or more whole
  `moof`+`mdat` fragments. `only_media::fmp4` (`Muxer`, `Demuxer`) is usable on its own.

## Relaying: the RTMP client

`only_media::rtmp::client` pushes a hub stream to another RTMP server, or pulls one from it into
the hub, so an `only-media` hub can feed a CDN or relay an upstream encoder:

```rust,ignore
use only_media::rtmp::client::{self, RtmpClientConfig};

// hub path live/cam -> rtmp://cdn.example/live/cam
let push = client::push(&engine, "rtmp://203.0.113.9/live/cam", &hub, "live/cam",
                        RtmpClientConfig::default())?;
// rtmp://origin/live/in -> hub path relay/in (reserved at once)
let pull = client::pull(&engine, "rtmp://203.0.113.10/live/in", &hub, "relay/in",
                        RtmpClientConfig::default())?;
```

Both return at once; the session runs on an I/O thread (`Engine::dial`). `state()` and `error()`
tell how it goes, `close()` (or dropping the handle) ends it. An IP literal needs no DNS; a host
name is resolved on the calling thread, so call them off the I/O threads or set
`RtmpClientConfig::addr`. Every step has a timeout (connect, handshake, each command response,
10 s; a pull that receives nothing for 30 s ends), received messages are bounded (16 MiB), and a
push that falls behind is cut back to keyframes and then disconnected, like a player of the
server. H.265 and Opus go out as Enhanced RTMP.

## Running it

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

## Interoperability

The integration tests (`crates/only-media/tests/*_interop.rs`, skipped when ffmpeg is not
installed) run ffmpeg 9 as publisher and ffprobe / ffmpeg as player:

| Publisher | Player | Codecs |
|---|---|---|
| `ffmpeg -f flv rtmp://…` | `ffprobe` / `ffmpeg -i rtmp://…` | H.264 + AAC, H.265 + Opus (Enhanced RTMP) |
| `ffmpeg -f flv rtmp://…` | `ffprobe` / `ffmpeg -i http://…/x.flv` and `…/index.m3u8` (LL-HLS on) | H.264 + AAC, H.265 + AAC |
| `ffmpeg -f rtsp rtsp://…` | RTMP, HTTP-FLV, HLS, RTSP (UDP) | H.264 + AAC |
| `ffmpeg -f flv rtmp://…` | RTSP (TCP) | H.264 + AAC |
| hub publisher | hand-written HTTP-FLV, WS-FLV and HLS clients | H.264 + AAC |
| hub publisher | `ffprobe` / `ffmpeg -i …/index.m3u8`, fMP4, plain and LL-HLS | H.264 + AAC, H.265 + AAC, H.265 + Opus |
| RTMP client push | `ffmpeg -listen 1 -i rtmp://…`, mediamtx (`--ignored`) | H.264 + AAC, H.265 + AAC |
| `ffmpeg -listen 1 -f flv rtmp://…`, mediamtx | RTMP client pull | H.264 + AAC, H.265 + AAC |

RTSP and SRT have their own tables in their chapters. Fuzz targets cover the RTMP session
(`rtmp_server`) and client (`rtmp_client`), FLV (`flv_demux`), fMP4 (`fmp4_demux`), AMF
(`amf_decode`), RTSP, SDP, RTP, MPEG-TS and SRT parsers.

## Not supported

HLS encryption and multivariant playlists, RTMPS client, RTMPE / RTMPT, AMF3 replies, Enhanced
RTMP multitrack, AV1 / VP9 / VP8 in the hub, recording to files, transcoding.
