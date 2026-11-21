# ADR-070: Reconnecting RTMP / RTSP clients, RTCP A/V sync, HLS I-frame playlists, rendition reports, session keys, H.265 `cbcs`

English | [简体中文](070-media-reconnect-av-sync-iframes-hevc-cbcs.zh-CN.md)

Status: accepted (2026-11-21)

## Context

After ADR-016, 031, 034 and 043, `only-media` still listed as not done: reconnecting RTMP and
RTSP clients and RTCP-based A/V sync in the RTSP client (ADR-016), HLS I-frame playlists and
rendition reports (ADR-031), `EXT-X-SESSION-KEY` (ADR-034) and SAMPLE-AES for H.265
(ADR-043).

- A client that relays a camera or pushes to a CDN must survive the far end restarting.
  Without reconnects the application had to watch `is_closed()` and start a new client, and a
  pull then lost its hub path (players subscribed to it were dropped, and another publisher
  could take the path meanwhile).
- RTP timestamps of the tracks of one RTSP session have random bases and clocks; only the RTCP
  sender reports (an NTP time with the RTP timestamp of the same instant) relate them. The
  client started each track's times at its first packet's arrival, as the RTSP server does for
  publishers, which skews audio against video by however much their first packets' arrival
  differs from their capture.
- An I-frame playlist (RFC 8216 4.3.3.6, `EXT-X-I-FRAMES-ONLY`) lets players scrub and show
  trick play from byte ranges of the segments. Rendition reports (RFC 8216bis 4.4.5.4) let an
  LL-HLS player switching renditions issue its first blocking reload of the new one without
  fetching its playlist first. `EXT-X-SESSION-KEY` lets players fetch keys before the media
  playlists.
- H.265 `cbcs` keeps each slice segment header clear, which needs it parsed: the header's
  length depends on the SPS (short-term reference picture sets, including inter-predicted
  ones, long-term pictures, SAO, temporal MVP, the picture size in CTBs) and the PPS (dependent
  slices, extra header bits, weighted prediction, list modification, tiles / wavefront entry
  points, deblocking overrides, header extensions, range extension chroma QP offset lists).

## Decision

All additions are additive (new config fields default to the old behaviour, but
`RtspClientConfig::rtcp_sync`, which defaults to on).

1. **Reconnect policy**: `only_media::Reconnect` (also re-exported from `rtmp::client` and
   `rtsp::client`): `initial_delay` (500 ms), `max_delay` (30 s), `max_attempts` (`None`: until
   closed), built from `Reconnect::new(&Arc<Engine>)`, which holds the engine weakly (the
   client dials again on it; the address resolved at start is reused, so no name lookup ever
   runs off the caller's thread). The delay doubles after each failed try up to the bound and
   resets when a session goes live. `RtmpClientConfig::reconnect` and
   `RtspClientConfig::reconnect` (default `None`).
   - **What reconnects**: errors another try may cure. Final are bad URLs and resolution,
     hub errors (a busy path, a push whose source left), refused credentials (RTSP 401 / 403
     and `Unauthorized`; RTMP `…Connect.Rejected` and `…Denied`) and, for RTSP, a stream with
     no carried track. Everything else (connection refused or closed, timeouts, protocol
     errors, other refusals such as `NetStream.Play.StreamNotFound` or RTSP 404 / 503, the
     server ending the stream, a push whose stream changed its codecs) reconnects.
   - **RTMP**: the client already ran asynchronously, so a failure moves it to the new
     `ClientState::Reconnecting`, the media timer schedules the redial, and the connection has
     a generation (`epoch`): callbacks of a replaced connection (a late `on_close`, a timer
     firing for it, a packet already in flight) are ignored, one atomic load per media
     message. The first connection is retried too. `RtmpClient::reconnects()` counts sessions
     that streamed after the first; `error()` reports the last session's error while
     reconnecting.
   - **RTSP**: the handshake blocks the caller, so the client is split into a per-connection
     session (the existing state machine) and a `Client` that owns the hub side and decides,
     when a session ends, whether to reconnect: the backoff runs on the media timer, the try on
     a short-lived thread of its own (`only-rtsp-reconnect`; the rules forbid blocking a timer
     or an I/O thread, and a pool task must not wait on a loop). The first session must come
     up: `pull` / `push` return its error, as before. A push reads the hub stream's current
     tracks again before each try, so a source that changed codecs is announced anew.
     `RtspClient::{reconnects, is_live}` are new.
   - **The hub**: a pull keeps one `Publisher` (now shared, `Arc`) across sessions: the path
     stays reserved and live with its last tracks, subscribers stay, and the next session's
     first tracks go through `Publisher::set_tracks`, which every sink hears as a republish
     (`on_tracks`: timelines restart, HLS writes a discontinuity). A push subscribes again and
     starts from the cached GOP. Closing (or giving up) frees the path **before** `is_closed()`
     turns true (the guarantee of 1c745f1d, now also for RTSP, whose session used to flag
     itself closed before its recorder unpublished).
2. **RTCP A/V sync** in the RTSP recorder (the ingest behind the client's pull):
   `RtspClientConfig::rtcp_sync` (default `true`). Each track starts, as before, at its first
   packet's arrival. Sender reports (the first SR of each RTCP compound, over TCP interleaved
   channels, RTP-muxed RTCP and the UDP RTCP sockets) are kept per track; once a track has a
   report and a packet, the NTP time of its first RTP timestamp is computed, and its offset
   becomes that time relative to the reference set by the first track synchronized. Offsets
   only move forward: when a track would have to move back, the reference and every track
   already synchronized move forward instead, so times keep increasing. A report that arrived
   before the first packet (ffmpeg and mediamtx send one early) also applies to the packets
   that packet completed, so the stream goes live already aligned. Corrections larger than
   10 s are ignored (the reports' clocks disagree, or carry no real clock), as are reports with
   an NTP time of 0. One check per RTP packet (`first && sync`).
3. **HLS I-frame playlists**: `HlsConfig::iframe_playlist` (default `false`) serves
   `/<path>/iframes.m3u8` for streams with carried video: version 4 (7 with fMP4),
   `EXT-X-I-FRAMES-ONLY`, one entry per video keyframe of the listed segments with
   `EXT-X-BYTERANGE` into its segment, `EXTINF` until the next keyframe (or its segment's end
   past a discontinuity or at the live edge), its own media sequence numbering, the
   discontinuity sequence, maps and keys of the media playlist. MPEG-TS ranges are the PAT,
   PMT and the keyframe's PES (the muxer writes the tables before every keyframe), which
   decode on their own. In fMP4 every keyframe gets a fragment of its own when the option is
   on: what is pending is flushed before it, and its fragment is cut at the next video sample
   (it holds the keyframe and the audio in between) and recorded as the range. Not offered
   with AES-128 (CBC over the whole segment cannot be decrypted from the middle without the
   previous block, which players do not do; RFC 8216 says nothing for byte ranges there);
   SAMPLE-AES works, as its containers are clear. Segment, part and init responses now answer
   a single byte range (`Range: bytes=a-b`, `a-`, `-n`) with 206 or 416 and say
   `Accept-Ranges: bytes` (multi-range requests get the whole body). Multivariant playlists
   list each variant's I-frame playlist with `EXT-X-I-FRAME-STREAM-INF` (`BANDWIDTH` the peak
   bitrate of its I-frames, `CODECS` its video codec, `RESOLUTION`, `URI` with the query
   string).
4. **Rendition reports**: with LL-HLS parts, a media playlist of a stream that a
   multivariant playlist lists ends with `EXT-X-RENDITION-REPORT:URI=…,LAST-MSN=…,LAST-PART=…`
   for every other rendition of the multivariant playlists it is in whose muxer runs (the URI
   relative to this media playlist). Each stream publishes its newest part as one atomic
   (`msn << 20 | part`) on its publisher thread; a playlist, built under its own stream's
   lock, reads the others' atomics and takes only the service's map locks, which are never held
   while a stream's lock is taken (`Hls::stream` no longer locks a stream with the map held).
5. **Session keys**: an encrypted multivariant playlist names the current key of every
   rendition with `EXT-X-SESSION-KEY` (same `METHOD`, `URI` made relative to the multivariant
   playlist unless absolute, the `IV` of SAMPLE-AES in MPEG-TS), deduplicated, as
   RFC 8216 4.3.4.5 asks. Renditions without a key yet are left out.
6. **H.265 `cbcs`**: `codec::h265` parses what slice segment headers depend on (`SliceSps`,
   `SlicePps`; layer 0; the PPS multilayer / 3D / SCC extensions refused) and
   `slice_header_len` (H.265 7.3.6.1 to `byte_alignment()`, emulation prevention bytes
   counted, at most 64 short-term sets, 16 pictures per side, 32 long-term pictures, 15
   references per list, 256 header extension bytes). The fMP4 `cbcs` muxer carries H.265
   (`encv` with `frma` `hvc1`): every slice is a subsample whose clear part ends with its
   slice segment header, the rest in the 1:9 pattern; other NAL units clear (and a slice whose
   header does not parse, as for H.264). The parameter sets come from the `hvcC` and in band,
   bounded at 256 of each kind. SAMPLE-AES in MPEG-TS still carries H.264 and AAC only
   (Apple's format defines no H.265).

## Consequences

- Tests (`cargo test -p only-media`): RTMP against a scripted server (a pull reconnected three
  times with its path and subscriber kept and republished, a refusal and a bound on the tries
  ending it with the path freed, a push resending from a keyframe); RTSP against this crate's
  server stopped and restarted on the same port (pull over TCP and UDP coming back with
  H.265 instead of H.264, push over TCP); the recorder lining two tracks up by sender reports
  that put audio 500 ms after video, early and late (times kept increasing), and following
  arrival with sync off; I-frame playlists in both formats with every range demuxed on its
  own to exactly one keyframe; rendition reports matching the other rendition's state; session
  keys and I-frame stream entries in multivariant playlists; byte ranges; the H.265 slice
  segment header lengths equal ffmpeg's `trace_headers` on every slice of two x265 samples
  (wavefront entry points and SAO; three slices per picture, weighted prediction, four
  references and a B-pyramid, parameter sets in band: 200 slices); `cbcs` fragments of H.265
  decrypt to the source.
- Interop: ffmpeg decodes every I-frame byte range (fetched with a `Range` request, with the
  init segment in fMP4) to exactly one frame of the source and ffprobe reads the multivariant
  playlists with I-frame entries (`tests/hls_iframes.rs`); ffmpeg plays SAMPLE-AES H.265 fMP4
  frame for frame, plain and LL-HLS (`tests/hls_encryption.rs`); mediamtx 1.21.4 in Docker
  restarted twice under RTSP and RTMP pulls of an ffmpeg publisher and of our own pushes, all
  six clients reconnecting and the pulls republishing, the RTSP pull's tracks synchronized by
  mediamtx's reports within its first second (corrections up to about 130 ms) and in step
  with their arrival within 250 ms (`tests/mediamtx_reconnect.rs`, ignored by default).
- Fuzzing: new target `h265_sample_encryption` (parameter sets and slices through the parsers
  and the `cbcs` muxer, every access unit decrypted back from its `senc` subsamples), with
  seeds from both H.265 samples.
- Cost: the HLS segmenting path gained a flag check per video packet and an atomic store per
  part, the RTSP ingest one check per RTP packet, the RTMP pull one atomic load per media
  message. A first A/B showed fMP4 segmenting 20 % slower: the segment being written, moved out
  of the stream state and back for every packet, had grown by the I-frame fields. It is now
  borrowed in place and the I-frame state boxed. Same-run A/B on gpu51 (`quiet.sh`, one pinned
  core, 7 alternating rounds, medians, head / base): `bench_segmenting` MPEG-TS 0.939,
  MPEG-TS LL-HLS 0.996, fMP4 0.950, fMP4 LL-HLS 0.921, AES-128 0.987 to 0.996, SAMPLE-AES
  MPEG-TS 0.997, `cbcs` fMP4 1.019; `tests/client_bench.rs` (new: the RTMP and RTSP pull
  ingest through the fuzz entry points) RTMP 1.013, RTSP 1.015.
- Not done: SAMPLE-AES for codecs other than H.264, H.265 (fMP4) and AAC; I-frame playlists
  with AES-128; query strings on rendition report URIs (the media playlist's query is not
  known where playlists are built); RTCP sync in the RTSP server's RECORD sessions (the
  recorder supports it, the server does not turn it on); re-resolving a host name on reconnect.
