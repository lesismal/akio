# Streaming media: hub, RTMP, HTTP-FLV, HLS

`only-media` is a live streaming server toolkit: one stream **hub** with every ingest and
egress protocol around it. A stream published over RTMP, RTSP or SRT plays over RTMP, RTSP,
SRT, HTTP-FLV, WS-FLV and HLS, with no protocol-to-protocol glue: every protocol converts what
it receives into the canonical packets of `only_media::av` and muxes from them.

| Protocol | In (publish) | Out (play) | Chapter |
|---|---|---|---|
| RTMP (digest handshake, Enhanced RTMP H.265 / Opus) | yes | yes | this one |
| HTTP-FLV, WS-FLV | – | yes | this one |
| HLS (MPEG-TS, LL-HLS parts, blocking reload) | – | yes | this one |
| RTSP (TCP interleaved and UDP) | yes | yes | [RTSP and WHIP/WHEP](media-rtsp.md) |
| SRT live (ARQ, TSBPD, AES) | yes | yes | [SRT](media-srt.md) |
| WHIP / WHEP | signalling (media plugs in) | signalling | [RTSP and WHIP/WHEP](media-rtsp.md) |

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
can reject connections by app and tcUrl. RTMPS is RTMP behind only-tls.

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
  `keep_segments` for late readers, bounded by `max_bytes`, and marks republishes with
  `EXT-X-DISCONTINUITY`. With `part_duration` it adds the Low-Latency HLS tags:
  `EXT-X-PART`, `EXT-X-PRELOAD-HINT`, `EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES`, and blocking
  playlist reloads (`?_HLS_msn=&_HLS_part=`). Requests that must wait are parked (no thread is
  held) and answered by the publisher's thread when the segment or part is cut.

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

RTSP and SRT have their own tables in their chapters. Fuzz targets cover the RTMP session
(`rtmp_server`), FLV (`flv_demux`), AMF (`amf_decode`), RTSP, SDP, RTP, MPEG-TS and SRT parsers.

## Not supported

fMP4 HLS segments and HLS encryption, RTMP client (push / pull relay), RTMPE / RTMPT, AMF3
replies, Enhanced RTMP multitrack, AV1 / VP9, recording to files, transcoding.
