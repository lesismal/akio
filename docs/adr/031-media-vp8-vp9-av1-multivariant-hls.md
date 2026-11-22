# ADR-031: VP8, VP9 and AV1 in the media hub, multivariant HLS playlists

English | [简体中文](031-media-vp8-vp9-av1-multivariant-hls.zh-CN.md)

Status: accepted (2026-11-18)

## Context

ADR-016 left `akio-media` with two gaps. The hub carried only H.264 and H.265 video: WHIP lines
offering VP8, VP9 or AV1 were answered inactive, Enhanced RTMP's `vp09` / `av01` FourCCs and
RTSP's `VP8` / `VP9` / `AV1` rtpmaps were dropped, although `akio-rtp` has the payload formats
and `akio-webrtc` negotiates them; browsers publish VP8 and VP9 by default and AV1 is the codec
of choice for low bitrates. And HLS served only media playlists, one per stream: a player could
not choose among renditions of one source (adaptive bitrate) or pick an alternative audio
rendition.

## Decision

All additions are additive; the behaviour changes are listed under Consequences.

### Codecs and their canonical form

- `Codec::Vp8`, `Codec::Vp9`, `Codec::Av1` (the enum is `#[non_exhaustive]`); `is_video` is
  true for them. Canonical forms (`av` module docs): `Track::config` is the
  `VPCodecConfigurationRecord` (`vpcC` without version and flags) for VP8 and VP9 and the
  `AV1CodecConfigurationRecord` (`av1C`, with the sequence header OBU) for AV1; `Packet::data`
  is one VP8 / VP9 frame (a VP9 superframe as it came) or one AV1 temporal unit of OBUs with
  `obu_size` and no temporal delimiter (as ISO BMFF stores samples).
- A packet is a keyframe when its bitstream says so: VP8 frame tag, VP9 uncompressed header
  (`frame_type`, not `show_existing_frame`), AV1 first frame header a shown `KEY_FRAME`. Every
  ingest sets it, so the GOP cache, HLS segmenting and slow-player dropping work unchanged.
- `Track::video` reads the AV1 picture size from the sequence header in `av1C`;
  `Track::video_from_keyframe(codec, frame)` builds the VP8 / VP9 / AV1 track (configuration
  record and size) from a keyframe, for sources without out-of-band configuration (RTP,
  WebRTC). `Track::codec_string()` gives the RFC 6381 string (`avc1.PPCCLL`,
  `hvc1.1.6.L93.B0`, `vp09.PP.LL.DD`, `av01.P.LLT.DD`, `mp4a.40.N`, `opus`, `mp4a.40.34`).
- New codec helpers: `codec::vp8` (`is_keyframe`, `keyframe_size`, `config`), `codec::vp9`
  (`Config` = `vpcC` with `parse`, `encode`, `codec_string`; `level_for`; `Keyframe`,
  `parse_keyframe`, `is_keyframe`), `codec::av1` (`obus`, `Obu`, `to_sample`,
  `SequenceHeader`, `Config` = `av1C` with `from_sequence_header`, `parse`, `encode`,
  `sequence_header`, `codec_string`; `sequence_header_obu`, `is_keyframe`, `OBU_*`).

### Ingest and egress per protocol

- **Enhanced RTMP / FLV**: `vp09`, `av01` and `vp08` FourCCs in `parse_video`, `Decoder` and
  `Encoder`. A sequence start is the configuration record (`vp09` / `vp08` with the 4-byte
  version and flags of the `vpcC` box, as ffmpeg writes it, stripped when parsed and written
  back); coded frames carry no composition time. The decoder holds a VP8 / VP9 stream back
  until the first keyframe gives its picture size. AV1 temporal delimiters are dropped. The
  RTMP client's `fourCcList` names them.
- **RTSP / RTP**: `rtp::supported` includes VP8, VP9 and AV1; `rtp::Packetizer` and
  `rtp::Depacketizer` use `akio-rtp`'s payload formats (RFC 7741, RFC 9628, the AOM AV1 RTP
  spec); a frame missing a packet is dropped. `Depacketizer::take_config` returns the
  configuration of the last keyframe for them and the new `Depacketizer::picture_size` its
  size; the RTSP recorder (server and client pull) goes live once the first keyframe is in.
  SDP maps the `VP8/90000`, `VP9/90000`, `AV1/90000` rtpmaps both ways. `akio-media` now
  depends on `akio-rtp` (in-house, ADR-005 holds).
- **fMP4 / CMAF**: `vp08` / `vp09` sample entries with `vpcC` (version 1) and `av01` with
  `av1C`; the demuxer reads them back. MPEG-TS does not carry them (no mapping HLS players
  know); HLS treats a stream whose video the format cannot carry like an audio-only one (it is
  cut on time, not stalled waiting for a keyframe that never comes).
- **WebRTC**: `webrtc::rtc_config` enables VP8, VP9 and AV1. WHIP passes VP8 / VP9 frames as
  they are and AV1 temporal units as sized OBUs, with the track from each keyframe's header;
  WHEP sends them as they are (no Annex B conversion, no parameter sets).

### Multivariant HLS playlists (`hls`)

- `Multivariant { variants: Vec<Variant>, audio: Vec<AudioRendition> }`;
  `Variant { path, bandwidth: Option<u64>, audio_group: Option<String> }` (`Variant::new`);
  `AudioRendition { group, name, path, language: Option<String>, default: bool }`
  (`AudioRendition::new`). All `#[non_exhaustive]`.
- `Hls::add_multivariant(name, Multivariant)` serves `/<name>.m3u8`;
  `Hls::remove_multivariant(name) -> bool`. Each rendition is a hub stream published on its
  own; the playlist lists `EXT-X-MEDIA:TYPE=AUDIO` per audio rendition (`GROUP-ID`, `NAME`,
  `LANGUAGE`, `DEFAULT`, `AUTOSELECT`, `CHANNELS`, `URI`) and `EXT-X-STREAM-INF` per variant
  with `BANDWIDTH` (configured, or the peak segment bitrate of the variant plus its audio
  group, then also `AVERAGE-BANDWIDTH`), `CODECS` (the codec strings of the tracks the segment
  format carries, the audio group's included), `RESOLUTION` and `AUDIO`. Version 7 for fMP4, 3
  for MPEG-TS; LL-HLS needs nothing more (the media playlists carry the parts).
- URIs are relative to the multivariant playlist and carry its query string, so tokens reach
  the hub's `on_subscribe` hook on the media playlist requests.
- A request starts the muxer of every rendition and is answered when each has its tracks and,
  when its bandwidth is measured, one segment; else it is parked (checked every 50 ms, no
  thread held) and answered after three target durations plus `play_wait` with the renditions
  that are ready, or 503 with none.

## Alternatives considered

- **AV1 or VP9 in MPEG-TS** (the AOM draft for AV1): rejected; no HLS player reads it, and fMP4
  is the container HLS specifies for them.
- **Decoding size and level from the bitstream on every packet**: rejected for the hot path;
  only keyframes are parsed, and only on ingests without out-of-band configuration.
- **A multivariant playlist built from one stream's tracks** (each video track a variant):
  rejected; renditions are encoded separately (an encoder ladder, several WHIP publishers) and
  each stream is already a media playlist. Transcoding to build a ladder is out of scope.
- **Requiring `BANDWIDTH` in the configuration**: rejected as the only way; measuring segments
  is what a player sees, and a configured value stays possible.

## Consequences

- Additive public API in akio-media: three `Codec` variants, `Track::video_from_keyframe`,
  `Track::codec_string`, modules `codec::vp8` / `codec::vp9` / `codec::av1`,
  `rtp::Depacketizer::picture_size`, `hls::{Multivariant, Variant, AudioRendition}`,
  `Hls::add_multivariant` / `remove_multivariant`. Code matching `Codec` exhaustively outside
  the crate already needed a wildcard (`#[non_exhaustive]`).
- Behaviour changes: `webrtc::rtc_config` accepts VP8, VP9 and AV1, so WHIP offers with only
  those are now published instead of refused (406); WHEP offers them. `flv::parse_video` no
  longer drops 3 bytes of coded frames of FourCCs other than `avc1` / `hvc1` (it read a
  composition time those do not have). HLS cuts streams whose video the format does not carry
  like audio-only streams instead of never cutting a segment.
- Fixed on the way: `EXT-X-TARGETDURATION` of a live media playlist could change between
  reloads (it was the longest listed segment rounded up, so a 1.007 s segment turned a 1 s
  target into 2); it is now the configured target or the longest segment rounded to the
  nearest second (RFC 8216 4.3.3.1), and never decreases. Chrome's own HLS player refused the
  change. LL-HLS parts still run up to one frame past `PART-TARGET`, as before.
- Fuzzing: `rtp_depacketize` also builds VP8, VP9 and AV1 tracks; new seeds for it,
  `flv_demux` (`vp09`, `av01`) and `sdp_parse`.
  It found a panic of the RTP AAC depacketizer on an AU-headers-length of 1 to 8 bits (fixed;
  regression input kept).
- New test data: `vp9_opus.flv`, `av1_opus.flv` (ffmpeg Enhanced FLV), `vp8.ivf`. New ignored
  benchmarks: `hls::tests::bench_segmenting` and `tests/media_bench.rs` (hub fan-out, FLV
  decoding).
- Hot paths, same-run A/B against the previous main on gpu51 (5 alternating rounds, medians,
  head/base): hub fan-out to 1 / 16 / 256 subscribers 1.008 / 1.009 / 1.011; HLS segmenting
  TS 0.976, TS + parts 1.016, fMP4 1.005, fMP4 + parts 1.011; FLV decoding H.264 0.976,
  H.265 0.993. Retired instructions are equal or lower; per-case swings of 1-3% follow
  unrelated code changes (code layout).
- Interop: ffmpeg / ffprobe for VP9 and AV1 over Enhanced RTMP and fMP4 HLS, VP8 / VP9 / AV1
  over RTSP (record and play, TCP and UDP); headless Chrome publishes VP8, VP9, AV1 and H.264
  over WHIP and decodes them over WHEP, and plays a multivariant fMP4 LL-HLS playlist
  (`tools/interop/media/browser.sh`).
