# ADR-016: fMP4 HLS, RTMP and RTSP clients, WebRTC media in the media hub

English | [简体中文](016-media-fmp4-clients-webrtc.zh-CN.md)

Status: accepted (2026-11-17)

## Context

`akio-media` (M7) left four gaps listed in DEV-PLAN: HLS only produced MPEG-TS segments, so
players and CDNs that want CMAF (and Opus or HEVC in fragmented MP4) could not use it; the hub
could serve RTMP and RTSP but not relay to or from another server, because there was no RTMP or
RTSP client; and WHIP/WHEP was signalling only (`NoMedia` answered 501), although `akio-webrtc`
carries H.264, H.265 and Opus. WebRTC viewers also need a way to ask the publisher for a
keyframe (PLI), which the hub had no path for.

## Decision

All additions are additive; existing behaviour and defaults are unchanged.

### Keyframe requests in the hub

- `Publisher::on_keyframe_request(hook)` sets what a publisher does when asked for a keyframe
  (`hub::KeyframeHook = Arc<dyn Fn() + Send + Sync>`); cleared when the publisher closes.
- `Subscription::request_keyframe() -> bool` and `Hub::request_keyframe(path) -> bool` ask. They
  never block and may be called from a sink's callbacks: the hook lives under its own mutex, not
  the stream's.
- Requests of one stream are throttled by `HubConfig::keyframe_request_interval`
  (`DEFAULT_KEYFRAME_REQUEST_INTERVAL`, 500 ms), so many viewers cost the publisher one keyframe.
- A video subscriber that joins without a cached keyframe (`no_gop_cache`, or no GOP yet) asks at
  once instead of waiting a GOP.

### fMP4 / CMAF (`akio_media::fmp4`, `hls::SegmentFormat`)

- `fmp4::Muxer` (`new(&[Track])`, `init_segment`, `write_packet`, `flush(end, out)`,
  `carries`, `has_tracks`, `pending_bytes`, `has_pending`) writes an init segment (`ftyp` with CMAF
  brands, `moov` with `mvex`/`trex`) and `moof`+`mdat` fragments with absolute `tfdt` (version 1)
  and `trun` sample durations, sizes, flags and composition offsets (signed when negative).
  `fmp4::write_styp`. Carried: H.264 (`avc1`/`avcC`), H.265 (`hvc1`/`hvcC`), AAC (`mp4a`/`esds`),
  Opus (`Opus`/`dOps`, from the OpusHead); G.711 and MP3 are not carried, like the TS muxer.
  Per fragment at most 1 GiB and 2^20 samples per track.
- `fmp4::Demuxer` (`feed`, `tracks`, `Event`, `Fmp4Error`) parses init and fragments back into
  tracks and packets. It is the test oracle and the fuzz target (`fmp4_demux`); every box size is
  checked against its parent, nesting is fixed by the code, child boxes and tracks are capped, and
  the bytes copied out per `feed` are bounded by its input.
- `HlsConfig::format: SegmentFormat` (`MpegTs` default, `Fmp4`; `extension`, `content_type`). In
  fMP4 mode the playlist is version 7 (9 with parts), `#EXT-X-MAP:URI="init-<n>.mp4"` changes only
  when the init bytes change, segments are `seg-<n>.m4s` (`styp` + whole fragments), LL-HLS parts
  `part-<n>.<m>.m4s` are whole fragments. `max_bytes`, the forced cut, blocking reloads and the
  idle timeout apply as for TS. `MediaHttp` routes `.m4s` and `.mp4` to `Hls`.

### RTMP client (`akio_media::rtmp::client`)

- `push(engine, url, hub, path, RtmpClientConfig) -> Result<RtmpClient, ClientError>` publishes a
  hub stream to an RTMP server; `pull(...)` reserves `path` at once and publishes what it plays
  from a server. `RtmpUrl` (`parse`, `query`, `resolve`), `ClientState`, `ClientError`,
  `DEFAULT_PORT`. `RtmpClient`: `url`, `addr`, `state`, `is_closed`, `error`, `close`; dropping it
  closes.
- Both run on an I/O thread after `Engine::dial`. An IP literal needs no DNS; a host name is
  resolved on the caller's thread (documented as blocking; `RtmpClientConfig::addr` avoids it).
- Bounds and timeouts (defaults): connect 10 s, handshake 10 s, each command response 10 s, pull
  idle 30 s, message size 16 MiB, push `write_queue_limit` 2 MiB (`Dropper`) and
  `max_write_queue` 16 MiB (disconnect), `source_wait` 10 s.

### RTSP client (`akio_media::rtsp::client`)

- `pull(engine, url, hub, path, RtspClientConfig) -> Result<RtspClient, ClientError>` plays from
  an RTSP server into the hub (the path is reserved at once; the stream goes live when the video
  parameter sets are known, from the SDP or in band); `push(...)` records a hub stream to a server
  (ANNOUNCE, SETUP `mode=record`, RECORD). `RtspTransport` (`Tcp` default, interleaved; `Udp`, an
  even/odd RTP/RTCP pair per track bound with `Engine::bind_udp`). `RtspClient`: `path`, `close`
  (TEARDOWN best effort), `is_closed`, `error`; dropping it closes. Re-exported from `rtsp`.
- Unlike the RTMP client, `pull` and `push` return once PLAY or RECORD is answered, so they block
  the caller for the handshake and must not run on an I/O thread (documented); the session then
  runs on the engine. Host names are resolved on the caller's thread; `RtspClientConfig::addr`
  avoids it.
- Digest (MD5, `qop=auth`) and Basic authentication from the URL's userinfo, at most two retries per
  request; keep-alives with GET_PARAMETER (or OPTIONS) at half the server's session timeout (else
  30 s); periodic RTCP sender reports when recording, receiver reports over UDP when playing.
- `rtsp::message`: `Reply` (`header`, `headers_named`, `cseq`), `Frame::Reply`, `Parser::client`
  (whole responses under the same head and body bounds as requests).
- Bounds and timeouts (defaults): connect 10 s, each response 10 s, pull idle 10 s, head and body
  as the server's parser, TCP push `write_queue_limit` 2 MiB / `max_write_queue` 16 MiB,
  `push_wait` 10 s.

### WebRTC media (`akio_media::webrtc`, cargo feature `webrtc`)

- The optional, non-default feature `webrtc` adds a dependency on `akio-webrtc` (in-house, so
  ADR-005 holds). `RtcMedia::new(RtcServer, RtcMediaConfig)` implements `whip::WebRtcEngine`;
  `RtcMedia::rtc_server(addrs)` and `webrtc::rtc_config()` give an `RtcServer` with H.264, H.265,
  Opus, PCMU and PCMA.
- WHIP: H.264/H.265 frames (Annex B) become AVCC with configuration records built from the
  in-band parameter sets; Opus and G.711 pass through. Lines the hub cannot carry (VP8, VP9, AV1,
  G.722) are ignored; an offer with none it can carry is 406. Times come from each line's RTP clock,
  aligned on the first frames' arrival. `Publisher::on_keyframe_request` sends a PLI. Packets held
  before the tracks are known are bounded (`max_pending_packets` 512, `max_pending_bytes` 8 MiB),
  and a line that never starts is given up after `track_timeout` (5 s).
- WHEP: subscribes once ICE/DTLS is up, from the next keyframe by default (`play_gop_cache`
  false), sends H.264/H.265 as Annex B with the parameter sets before keyframes, Opus and G.711 as
  they are; AAC and MP3 are not sent (no transcoding). A viewer's PLI or FIR becomes
  `Subscription::request_keyframe`.
- `WebRtcSession::is_closed` (default `false`) lets `WhipServer` drop sessions whose peer ended
  without a `DELETE`, so they no longer hold `max_sessions` slots.

## Alternatives considered

- **fMP4 as a separate service**: rejected; segmenting, parts and blocking reload are the same, so
  it is a format choice of `Hls`.
- **Making `webrtc` a default feature**: rejected for build time; WHIP/WHEP signalling stays
  available without it (with `NoMedia` or a custom engine).
- **Transcoding AAC to Opus for WHEP**: out of scope (no codec implementations in the project).
- **Async client APIs returning futures**: the project has no runtime; the clients follow
  `srt::push` / `srt::pull` (start, then a handle with state and error).

## Consequences

- Additive public API in akio-media (new modules `fmp4`, `rtmp::client`, `rtsp::client`,
  `webrtc` behind a feature; new fields in `HubConfig` and `HlsConfig`, both `#[non_exhaustive]`;
  a defaulted trait method on `WebRtcSession`). The API snapshot covers the `webrtc` feature.
- New fuzz targets: `fmp4_demux`, `rtmp_client`, `rtsp_client`.
- The hub, HLS and the clients keep every buffer bounded with a default and every exchange under a
  timeout (rules 7 to 10).
- `akio-webrtc` fix found on the way: `Endpoint::config`, `close_on_disconnect` and
  `connect_timeout` always panicked after `bind`; they now apply to peers created afterwards
  (same signatures).
- One behaviour change in TS mode: while the segment being written starts with a discontinuity and
  has no parts yet, the playlist leaves out `EXT-X-PRELOAD-HINT` (the hinted part could not carry
  that tag).
