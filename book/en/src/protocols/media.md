# Streaming media: hub, RTMP, HTTP-FLV, HLS

`only-media` is a live streaming server toolkit: one stream **hub** with every ingest and
egress protocol around it. A stream published over RTMP, RTSP or SRT plays over RTMP, RTSP,
SRT, HTTP-FLV, WS-FLV and HLS, with no protocol-to-protocol glue: every protocol converts what
it receives into the canonical packets of `only_media::av` and muxes from them.

| Protocol | In (publish) | Out (play) | Chapter |
|---|---|---|---|
| RTMP (digest handshake, Enhanced RTMP H.265 / VP9 / AV1 / VP8 / Opus), server and client | yes | yes | this one |
| HTTP-FLV, WS-FLV | – | yes | this one |
| HLS (MPEG-TS or fMP4/CMAF, LL-HLS parts, blocking reload, multivariant playlists) | – | yes | this one |
| RTSP (TCP interleaved and UDP), server and client | yes | yes | [RTSP and WHIP/WHEP](media-rtsp.md) |
| SRT live (ARQ, TSBPD, AES) | yes | yes | [SRT](media-srt.md) |
| WHIP / WHEP (media with the `webrtc` feature) | yes | yes | [RTSP and WHIP/WHEP](media-rtsp.md) |

Codecs: H.264, H.265, AAC and Opus everywhere they can be carried; VP8, VP9 and AV1 over
Enhanced RTMP / FLV, RTSP, WHIP / WHEP and fMP4 HLS (not MPEG-TS); G.711 and MP3 where the
container allows. Snippets below are from `crates/only-media/examples/guide-media.rs`.

## The canonical form

`av::Track` describes an elementary stream: its `Codec` and its configuration in the ISO BMFF
form (the `AVCDecoderConfigurationRecord` / `HEVCDecoderConfigurationRecord` with the parameter
sets, the `VPCodecConfigurationRecord` of VP8 and VP9, the `AV1CodecConfigurationRecord` with
the sequence header, the AAC `AudioSpecificConfig`, the `OpusHead`), plus picture size or sample
rate. `av::Packet` is one access unit: AVCC video (4-byte NAL lengths, no access unit
delimiters), VP8 / VP9 frames, AV1 temporal units (OBUs with sizes, no temporal delimiter), raw
AAC frames without ADTS, Opus packets; decode and presentation times in nanoseconds. A packet's
`keyframe` comes from the bitstream (IDR / IRAP, VP8 / VP9 keyframe, AV1 shown `KEY_FRAME`):
the GOP cache, HLS segments and the dropping of slow players start at those. `only_media::codec`
has the helpers to go between AVCC and Annex B, parse the configuration records, SPS, VP9
keyframe headers and AV1 sequence headers (picture size), and frame ADTS;
`Track::video_from_keyframe` builds a VP8 / VP9 / AV1 track from a keyframe and
`Track::codec_string` gives the RFC 6381 string (`avc1.64001F`, `vp09.00.31.08`,
`av01.0.04M.08`, `mp4a.40.2`...).

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
including H.265 as id 12, and Enhanced RTMP FourCCs `hvc1`, `vp09`, `av01`, `vp08`, `Opus`,
`mp4a`); players get
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
  keyframe to cut at is cut there; a segment past `target_duration` asks the publisher for a
  keyframe, at most once per target, since WebRTC encoders send them on request only), and
  marks republishes with
  `EXT-X-DISCONTINUITY`. With `part_duration` it adds the Low-Latency HLS tags:
  `EXT-X-PART`, `EXT-X-PRELOAD-HINT`, `EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES`, and blocking
  playlist reloads (`?_HLS_msn=&_HLS_part=`). Requests that must wait are parked (no thread is
  held) and answered by the publisher's thread when the segment or part is cut.
- **fMP4 / CMAF segments**: `HlsConfig::format = SegmentFormat::Fmp4` cuts fragmented MP4
  instead of MPEG-TS (H.264, H.265, VP8, VP9, AV1, AAC and Opus; MPEG-TS has no VP8 / VP9 /
  AV1, and a stream whose video it cannot carry is cut like an audio-only one). The playlist names an init segment with
  `#EXT-X-MAP:URI="init-<n>.mp4"` (a new one only when the codec configuration changes),
  segments are `seg-<n>.m4s` and LL-HLS parts `part-<n>.<m>.m4s`, each part one or more whole
  `moof`+`mdat` fragments. `only_media::fmp4` (`Muxer`, `Demuxer`) is usable on its own.
- **Multivariant playlists**: renditions of one source are published as separate streams (an
  encoder ladder, several WHIP publishers) and tied together by `Hls::add_multivariant`:

```rust,ignore
{{#include ../../../../crates/only-media/examples/guide-media.rs:multivariant}}
```

  `GET /live/show.m3u8` lists an `EXT-X-STREAM-INF` per `Variant` with `BANDWIDTH` (configured,
  or the peak bitrate of its segments plus its audio group's, then with `AVERAGE-BANDWIDTH`),
  `CODECS` (the RFC 6381 strings of the tracks the segment format carries), `RESOLUTION` and
  `AUDIO`, and an `EXT-X-MEDIA:TYPE=AUDIO` per `AudioRendition`. URIs are relative and carry the
  request's query string. The first request starts every rendition's muxer and is answered
  once each has its tracks and a segment (renditions not published yet are left out after
  three target durations). It works with both formats and with LL-HLS. With LL-HLS parts,
  each rendition's media playlist ends with an `EXT-X-RENDITION-REPORT` (`LAST-MSN`,
  `LAST-PART`) for every other rendition of its multivariant playlists, so a player switching
  renditions can issue its first blocking reload of the new one at once. The report's URI
  carries the playlist request's query string (its `_HLS_` directives taken out), so a token
  reaches the other rendition as it reaches blocking reloads.
- **I-frame playlists**: with `HlsConfig::iframe_playlist`, a stream with video also serves
  `GET /app/name/iframes.m3u8` (`EXT-X-I-FRAMES-ONLY`, for scrubbing and trick play): one
  entry per keyframe of the listed segments, an `EXT-X-BYTERANGE` into its segment that decodes
  on its own (MPEG-TS: the PAT, PMT and the keyframe's PES; fMP4: a `moof` + `mdat` fragment
  holding the keyframe, which the muxer then cuts at every keyframe, behind the `EXT-X-MAP`).
  Segment, part and init responses answer a single `Range: bytes=…` with 206. Multivariant
  playlists list each variant's I-frame playlist with `EXT-X-I-FRAME-STREAM-INF` (`BANDWIDTH`
  the peak bitrate of its I-frames). SAMPLE-AES keeps the byte ranges (its containers are
  clear). With AES-128, whose CBC ciphertext players cannot decrypt from the middle of a
  segment, each I-frame is a resource of its own instead, `iframe-<n>.ts` (`.m4s`): the same
  bytes encrypted whole with its segment's key, the IV its media sequence number in the I-frame
  playlist, listed without `EXT-X-BYTERANGE` after the segment's `EXT-X-KEY`.
- **Encryption**: `HlsConfig::encryption` encrypts every segment and LL-HLS part with
  AES-128 (`#EXT-X-KEY:METHOD=AES-128`, CBC with PKCS #7), MPEG-TS and fMP4 alike:

```rust,ignore
use only_media::hls::{HlsConfig, HlsEncryption, HlsKey, KeyProvider};
use only_http::Context;

struct Keys; // the application's keys and entitlement check
impl KeyProvider for Keys {
    // On the publisher's thread when a segment needs key `n`: must not block. A fresh random
    // key each call (a restarted stream counts keys and IVs from 0 again).
    fn key(&self, path: &str, n: u64) -> HlsKey {
        HlsKey::new(new_random_key(path, n)) // and remember it for the application's own use
    }
    // For each GET /<path>/key-<n>.key, on the requester's I/O thread (403 when false).
    fn authorize(&self, path: &str, _n: u64, ctx: &Context) -> bool {
        ctx.header("cookie").is_some_and(|c| entitled(c, path))
    }
}

let mut cfg = HlsConfig::default();
cfg.encryption = Some(HlsEncryption::new(Keys).rotate_every(10)); // a new key every 10 segments
```

  The IV is the media sequence number (no `IV` attribute), and a part is encrypted on its own
  from its segment's IV, as players decrypt parts. The playlist names a key before the first
  media it applies to; fMP4 init segments stay clear (`#EXT-X-KEY:METHOD=NONE` before a map
  that follows a key). Keys are served at `key-<n>.key` with `Cache-Control: private,
  no-store` while a kept segment uses them, or players fetch them from the URI given with
  `HlsKey::with_uri`. Players send cookies and headers to key URIs, not the playlist's query
  string. `RandomKeys` issues random keys to everyone (for tests and links that are secret
  themselves).

- **SAMPLE-AES**: `HlsEncryption::new(keys).method(EncryptionMethod::SampleAes)` encrypts the
  samples inside the container and leaves its structure clear, with the same key provider,
  rotation and key URIs (`#EXT-X-KEY:METHOD=SAMPLE-AES`). It carries H.264 and AAC, and H.265
  in fMP4; other tracks are left out of the segments rather than sent in the clear.
  - MPEG-TS: Apple's sample encryption. Coded slices longer than 48 bytes keep 32 bytes clear,
    then one 16-byte block in ten is encrypted (AES-128-CBC from the IV in every NAL unit, on
    the unescaped NAL unit, emulation prevention applied again); AAC frames keep the ADTS
    header and 16 bytes clear and encrypt their whole blocks. The PMT says so (stream types
    0xdb and 0xcf, `zavc` / `aacd`, the `apad` audio setup). Each key has a random IV, written
    as the `IV` attribute (an IV per segment would break players that read ahead across a
    segment boundary, as ffmpeg does).
  - fMP4: the `cbcs` scheme of ISO/IEC 23001-7. The init segment has `encv` / `enca` entries
    with `sinf` (`frma`, `schm` `cbcs`, `tenc` with a constant IV); fragments have `senc`,
    `saiz` and `saio`. Each slice's NAL header and slice header stay clear (the H.264 slice
    header is parsed: reference list changes, weighted prediction, reference marking; so is
    the H.265 slice segment header: short-term reference picture sets, long-term pictures,
    weighted prediction, tile and wavefront entry points) and its slice data is encrypted in a
    1:9 pattern; AAC samples are encrypted whole.

  An encrypted multivariant playlist names the current key of each rendition with
  `EXT-X-SESSION-KEY`, so players can fetch the keys before the first media playlist.

  ffmpeg plays both, decrypted frame for frame. It applies one key to everything it has read
  ahead (and, for fMP4, the key it opened with), so with key rotation it decodes garbage
  around a key change; Safari and hls.js fetch keys per segment.

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

With `RtmpClientConfig::reconnect` the client survives the far end going away: an error
another try may cure (the connection closing or refused, a timeout, the server ending or
refusing the stream other than for credentials) moves it to `ClientState::Reconnecting`, and it
dials again after a backoff that doubles up to a bound and resets once a session streams:

```rust,ignore
use std::{sync::Arc, time::Duration};
use only_media::{Reconnect, rtmp::client::{self, RtmpClientConfig}};

let engine = Arc::new(engine); // the client dials again on it (held weakly)
let mut cfg = RtmpClientConfig::default();
cfg.reconnect = Some(Reconnect::new(&engine).max_delay(Duration::from_secs(10)));
let pull = client::pull(&engine, "rtmp://203.0.113.10/live/in", &hub, "relay/in", cfg)?;
// pull.state() == ClientState::Reconnecting while it waits; pull.reconnects() counts.
```

A pull keeps its hub path reserved meanwhile: players stay subscribed and hear the new
session's tracks as a republish (their timelines restart, HLS writes a discontinuity). A push
subscribes again and starts from the cached GOP. Each try looks the URL's host name up again
(on a short-lived thread, as the lookup blocks), so a server that came back at another address
under the same name is found, and dials the name's addresses in turn until one connects;
`addr()` is the address dialed last. A name that fails to resolve is tried again like a refused
connect. Bad URLs, hub refusals and refused
credentials still end the client; `max_attempts` bounds the tries in a row. `close()` frees a
pull's path before `is_closed()` says so.

## Recording

`only_media::record::Recorder` writes hub streams to fragmented MP4, FLV or MPEG-TS files:

```rust,ignore
use std::time::Duration;
use only_media::record::{RecordConfig, RecordFile, RecordFormat, RecordHooks, Recorder};

struct Hooks;
impl RecordHooks for Hooks {
    // On the recorder's writer thread: may block (upload, database).
    fn on_stop(&self, f: &RecordFile, result: Result<(), &std::io::Error>) {
        println!("{} {:?} {} bytes {:?}", f.stream, f.duration, f.bytes, result);
    }
}

let mut cfg = RecordConfig::new("/var/lib/only/rec");
cfg.format = RecordFormat::Fmp4; // or Flv, or MpegTs
cfg.segment_duration = Some(Duration::from_secs(600));
cfg.max_files = 144; // keep the last day of ten-minute files
let rec = Recorder::with_hooks(hub.clone(), cfg, Hooks);
rec.start("live/cam")?; // waits up to `cfg.wait` (10 s) for a publisher, and across republishes
```

Packets are muxed on the publisher's thread like for any player; the files are created,
written, synced (`sync_all` before `on_stop`) and rotated by the recorder's own writer thread,
never by an I/O thread. Files start at a video keyframe with timestamps from 0 and are cut at
the first keyframe after `segment_duration` or `segment_bytes`, and at a republish or codec
change. The queue to the writer is bounded (`max_queued_bytes`, 32 MiB): when the disk falls
behind, the current file is closed and packets are dropped (`Recorder::dropped`) until the
queue is half empty and a keyframe starts the next file, so a slow disk leaves a gap between
files, never a broken one. `RecordHooks::file_name` names files (relative to `dir`), and
`on_start`, `on_stop` and `on_remove` (rotation) follow them. To record every stream, call
`start` from the hub's `on_publish` hook. MPEG-TS files repeat the PAT and PMT before every
video keyframe (and every second), so a cut or truncated file still plays from any keyframe.

## AV1 in MPEG-TS

The MPEG-TS muxer and demuxer carry AV1 as the Alliance for Open Media specifies ("Carriage
of AV1 in MPEG-2 TS"): stream type 0x06 with the `AV01` registration descriptor and the AV1
video descriptor (0x80), one temporal unit per PES (`data_alignment_indicator` set), each OBU
after a `00 00 01` start code with emulation prevention bytes, a temporal delimiter first and
the sequence header before keyframes that lack one. The demuxer also reads GStreamer's
provisional `AV1G` mapping (plain OBUs). So AV1 now goes out over SRT and HLS MPEG-TS and is
recorded to MPEG-TS. ffmpeg cannot demux AV1 in MPEG-TS yet (its support is under review);
the format is checked against the specification, by remuxing a stream through the muxer and
the demuxer, and by decoding (dav1d) what ffmpeg extracts from the PES payloads after a
separate implementation of the start-code format reads it back: every frame equals the
source's. VP8 and VP9 have no MPEG-TS mapping at all: they stay fMP4, FLV, RTP and
WebRTC only.

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
| hub publisher | `ffprobe` / `ffmpeg -i …/index.m3u8`, fMP4, plain and LL-HLS | H.264 + AAC, H.265 + AAC, H.265 + Opus, VP9 + Opus, AV1 + Opus |
| `ffmpeg -f flv rtmp://…` (Enhanced RTMP) | `ffprobe` / `ffmpeg -i rtmp://…` | VP9 + Opus, AV1 + Opus |
| hub publishers (3 renditions) | `ffprobe` / `ffmpeg -i …/show.m3u8`, MPEG-TS and fMP4 LL-HLS | H.265 + H.264 variants, AAC audio group |
| Chrome over WHIP (`tools/interop/media/browser.sh`) | hls.js, Chrome's own player: multivariant fMP4 LL-HLS | AV1 ladder + Opus |
| RTMP client push | `ffmpeg -listen 1 -i rtmp://…`, mediamtx (`--ignored`) | H.264 + AAC, H.265 + AAC |
| `ffmpeg -listen 1 -f flv rtmp://…`, mediamtx | RTMP client pull | H.264 + AAC, H.265 + AAC |
| hub publisher, AES-128 with key rotation | `ffprobe` / `ffmpeg -headers … -i …/index.m3u8`, MPEG-TS and fMP4, plain and LL-HLS | H.264 + AAC |
| hub publisher, SAMPLE-AES (MPEG-TS) and `cbcs` (fMP4) | `ffmpeg -headers … -i …/index.m3u8 -f framemd5`: every frame equals the source's, plain and LL-HLS | H.264 + AAC; H.265 + AAC (`cbcs`) |
| hub publishers (2 renditions), I-frame playlists | every `EXT-X-BYTERANGE` fetched with `Range` and decoded by `ffmpeg` to exactly one source frame; `ffprobe` of the multivariant playlist | H.264 + AAC, H.265 + AAC; MPEG-TS and fMP4 LL-HLS |
| hub publishers (2 renditions), AES-128 I-frame playlists with key rotation | every `iframe-<n>` decrypted and decoded by `ffmpeg` to one source frame; `ffmpeg` plays the I-frame playlist; hls.js (multivariant and I-frame playlists) and Shaka Player (trick play, fMP4) in headless Chrome (`tools/interop/media/hls-iframes.sh`) | H.264 + AAC, H.265 + AAC; MPEG-TS and fMP4 |
| ffmpeg → mediamtx (restarted twice, `--ignored`) | RTMP and RTSP client pulls and pushes reconnecting | H.264 + AAC |
| hub publisher, `Recorder` | `ffprobe` / `ffmpeg -i` of each fMP4, FLV and MPEG-TS file | H.264 + AAC, H.265 + AAC |

RTSP and SRT have their own tables in their chapters. Fuzz targets cover the RTMP session
(`rtmp_server`) and client (`rtmp_client`), FLV (`flv_demux`), fMP4 (`fmp4_demux`), AMF
(`amf_decode`), RTSP, SDP, RTP, MPEG-TS (with AV1) and SRT parsers (with the rendezvous
handshake, `srt_rendezvous`), the H.264 slice header parser with both sample encryptions
(`h264_sample_encryption`) and the H.265 slice segment header parser with `cbcs`
(`h265_sample_encryption`).

## Not supported

SAMPLE-AES for codecs other than H.264, H.265 (fMP4) and AAC,
VP8 / VP9 in MPEG-TS (unspecified), RTMPS client, RTMPE / RTMPT, AMF3 replies, Enhanced RTMP
multitrack, transcoding.
