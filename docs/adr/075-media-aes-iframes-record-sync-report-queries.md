# ADR-075: AES-128 I-frame playlists, RTCP sync for RTSP RECORD sessions, query strings on rendition reports

English | [简体中文](075-media-aes-iframes-record-sync-report-queries.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-070 left three gaps in `akio-media`:

- **I-frame playlists with AES-128**. `HlsConfig::iframe_playlist` was ignored with AES-128:
  an I-frame playlist names byte ranges of segments, and an AES-128 segment is one CBC
  ciphertext with PKCS #7 padding at its end. A range in its middle could only be decrypted
  with the previous ciphertext block as its IV (an `EXT-X-KEY` with an `IV` attribute before
  every entry, the range aligned to blocks), and it would have no padding. Players remove
  PKCS #7 padding from every resource they decrypt: hls.js strips as many bytes as the last
  decrypted byte says, ffmpeg's `crypto` protocol checks the padding at the end of what it
  reads. RFC 8216 says nothing about byte ranges of AES-128 segments, and Apple's tools only
  pair I-frame playlists with byte ranges of clear or SAMPLE-AES media.
- **RTCP sync in RECORD sessions**. ADR-070 lined up the RTSP client's pulled tracks by the
  server's RTCP sender reports. The RTSP server ignored a publisher's RTCP (the interleaved
  RTCP channels were dropped, the UDP RTCP port read and discarded), so recorded audio and
  video kept the offset their first packets arrived with.
- **Query strings on rendition reports**. `EXT-X-RENDITION-REPORT` URIs were bare paths: a
  player that switches renditions issues its blocking reload of the new one from that URI, so
  a token in the media playlist's query (for the hub's `on_subscribe` hook, or a CDN in front)
  did not reach it. The query was not known where playlists were built.

## Decision

1. **AES-128 I-frames are resources of their own.** With `iframe_playlist` and AES-128, each
   I-frame (the same bytes as the range ADR-070 names: PAT, PMT and the keyframe's PES in
   MPEG-TS; the keyframe's `moof` + `mdat` fragment in fMP4) is encrypted whole when its
   segment is closed, with the segment's key, CBC with PKCS #7, the IV being the I-frame's
   number, which is its media sequence number in the I-frame playlist (no `IV` attribute, as
   RFC 8216 5.2 has for segments). It is served at `/<path>/iframe-<n>.ts` (`.m4s`; single
   byte ranges answered as for segments) and listed without `EXT-X-BYTERANGE`, after the
   `EXT-X-KEY` of its segment (fMP4: after the clear `EXT-X-MAP`, as in the media
   playlist). Keys, rotation and key authorization are unchanged (an I-frame uses its
   segment's key and leaves with the segment). `EXT-X-I-FRAME-STREAM-INF` bandwidths count
   the padded resources. SAMPLE-AES keeps byte ranges (its containers are clear). No public
   API changes: `iframe_playlist` now does what it says with AES-128.
   - Cost: only with both options on. The keyframe bytes are kept a second time (plus up to
     16 bytes each), counted against `max_bytes` with their segment; they are encrypted once
     more, at the segment's close (no per-packet work). Other configurations pay one
     match per segment close.
   - Rejected: per-entry IVs over byte ranges (above: no padding, players strip some of the
     I-frame or fail), re-encrypting on request (CPU per request, and the plaintext is gone).
2. **`RtspConfig::rtcp_sync`** (new public field, default `true`): a RECORD session feeds
   the publisher's RTCP to the same `Recorder` as the client's pull: the interleaved RTCP
   channel of each track, RTCP muxed on its RTP channel (recognized by packet type, as in the
   client), and datagrams from the publisher's RTP or RTCP port (RTCP by packet type). The
   recorder's rules are ADR-070's: times start at arrival, a track with a report and a packet
   moves to the publisher's NTP clock relative to the first track synchronized, forward
   only, aligned before going live when reports come first, corrections over 10 s and reports
   with an NTP time of 0 ignored. `false` keeps arrival-based times. On by default like the
   client's: publishers that send reports (ffmpeg, OBS, cameras) get their capture offset
   back, others are unchanged.
3. **Subscribers start at their first packet.** A synchronized stream can carry audio timed
   before the keyframe a GOP starts with (an AAC encoder's priming frames, which ffmpeg
   times before the first video frame, now keep that time). Every `from_zero` sink (RTSP
   players, HLS, HTTP-FLV, recordings, WebRTC, the RTSP client's push) clamped such audio to
   its first time, sending several audio frames with one timestamp (ffmpeg: "non
   monotonically increasing dts"). The hub now remembers, per subscriber, the decode time of
   the first packet it heard since its tracks, and leaves out non-video packets timed before
   it until one reaches it (so a later timestamp jump within a publish is still delivered;
   a new publish or `set_tracks` starts over; a stream of video only has no floor). Video
   always goes. The delivery loop looks at floors only while a subscriber may still have one
   to pass (a flag per stream, set when a subscriber starts or restarts, cleared by the
   loop): the steady state costs nothing.
4. **Rendition report URIs carry the request's query** without its `_HLS_` directives
   (RFC 8216bis 6.2.5 reserves the prefix: `_HLS_msn`, `_HLS_part`, `_HLS_skip`...): a
   player appends its own to that URI, exactly as for the blocking reloads of the playlist it
   is reading. The playlist request (and a parked blocking reload) keeps the query for the
   answer. No public API changes.

## Consequences

- Tests (`cargo test -p akio-media`): AES-128 I-frame playlists in both formats with and
  without parts and with key rotation, every `iframe-<n>` decrypting with its segment's key
  and the IV of its number to exactly the range the unencrypted stream's playlist names,
  segments unchanged, the stream's byte count including the sealed I-frames; clear I-frame
  playlists no longer start with a needless `EXT-X-KEY:METHOD=NONE`; the hub's floor (GOP
  replay, live start, a new publish, a later jump); rendition reports with the request's
  query (directives removed, quotes dropped); RECORD sessions fed sender reports putting
  audio 500 ms after video while the packets arrive together, over TCP (RTCP channels),
  TCP with RTCP muxed on the RTP channels and UDP (RTCP ports), before the media (aligned
  from the first packet) and halfway (later packets move, audio times keep increasing),
  reports 60 s apart ignored, sync off following arrival (`tests/rtsp_interop.rs`).
- Interop: ffmpeg decodes every AES-128 I-frame (fetched, decrypted, with the clear init
  segment in fMP4) to exactly one frame of the source, H.264 and H.265, and plays the
  I-frame playlist itself, one source frame per entry (`tests/hls_iframes.rs`); the LL-HLS
  rendition report carries `?token=…` and a blocking reload built from it is answered. In
  headless Chrome (`tools/interop/media/hls-iframes.sh`): hls.js 1.5.20 plays the AES-128
  multivariant playlists in both formats and the H.264 I-frame playlist on its own (every
  I-frame decrypted and appended, frames decoded in MPEG-TS); Shaka Player 4.12.6 lists the
  I-frame tracks and, in trick play over fMP4, fetches, decrypts and decodes I-frames. Shaka's
  MPEG-TS transmuxer fails (3018) on one of the sample's two keyframes as a lone I-frame (AUD,
  SPS, PPS, IDR without SEI), encrypted or not, ADR-070's clear byte ranges included, while
  ffmpeg decodes that I-frame and Shaka plays it inside whole segments; Chrome on macOS does
  not decode the H.265 sample over MSE at all: both are reported by the script, not required.
  The existing RTSP interop (`ffmpeg -f rtsp` publishing, ffmpeg playing over TCP and UDP)
  found the priming-audio clamp of decision 3 once sync was on.
- Fuzz targets: unchanged, all build.
- Cost: same-run A/B against main on gpu51 (`quiet.sh`, one pinned core, 7 alternating rounds, medians, head / base): hub fan-out 1.005 / 0.994 / 0.996 (1 / 16 / 256 subscribers; a first version that checked the new floor per subscriber and packet cost 1.043 at 256, now the loop checks floors only while a subscriber has one to pass); RTSP RECORD ingest (`rtsp-record`, new) 1.007, RTSP pull 1.003, RTMP pull 0.996; `bench_segmenting` MPEG-TS 1.065, MPEG-TS LL-HLS 0.981, fMP4 0.961, fMP4 LL-HLS 1.020, AES-128 0.995 to 0.998, SAMPLE-AES MPEG-TS 1.015, `cbcs` 1.002. Nothing changed on the segmenting packet path (sealed I-frames, queries and the new routes are per segment or per request, and not in this benchmark); the plain MPEG-TS and fMP4 cases move in opposite directions and `cbcs` moved from 1.055 to 1.002 between two runs that differed only in hub.rs: code layout. On macOS aarch64 the same comparison is 0.97 to 1.03 throughout. The new `rtsp-record` benchmark (`tests/client_bench.rs`) drives a RECORD session with a sender report per track and round; the interleaved path now matches the RTCP channel and checks the packet type.
- Not done: SAMPLE-AES for codecs other than H.264, H.265 (fMP4) and AAC; RTCP receiver
  reports to recorders; re-resolving a host name on reconnect.
