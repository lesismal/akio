# ADR-043: SRT rendezvous, AV1 in MPEG-TS, recording to MPEG-TS, HLS SAMPLE-AES

English | [简体中文](043-media-srt-rendezvous-av1-ts-sample-aes.zh-CN.md)

Status: accepted (2026-11-19)

## Context

`only-media` listed as unsupported: HLS SAMPLE-AES / CBCS, SRT rendezvous, VP8 / VP9 / AV1 in
MPEG-TS, recording to MPEG-TS and transcoding.

- **SRT rendezvous** is how two SRT endpoints behind NATs meet: neither listens, both send
  handshakes to the other from a known port. The handshake (draft-sharabayko-srt-01 4.3.2)
  differs from caller / listener: both sides wave, a cookie contest picks an initiator.
- **AV1 in MPEG-TS** is specified by the Alliance for Open Media ("Carriage of AV1 in MPEG-2
  TS"): private data (stream type 0x06) with the `AV01` registration descriptor and an AV1
  video descriptor, OBUs in a start-code format. No released ffmpeg demuxes it yet (a patch
  series is under review), GStreamer uses a provisional mapping of its own (`AV1G`, plain
  OBUs). **VP8 and VP9 have no MPEG-TS mapping** at all: no stream type, registration or
  descriptor is defined anywhere and no demuxer reads one, so there is nothing to implement.
- **Recording** (ADR-034) wrote fMP4 and FLV; MPEG-TS is what many archives and broadcast
  tools expect.
- **SAMPLE-AES** (ADR-034 left it out) encrypts samples inside the container, which some
  delivery chains and FairPlay-style workflows require. ADR-034's reasons: CBCS for H.264 must
  leave each slice header clear, which needs the slice header parsed (it depends on the SPS and
  PPS, reference list changes, weighted prediction and reference marking), and SAMPLE-AES in
  MPEG-TS needs per-codec elementary stream rewriting. Revisited here: Apple's MPEG-TS format
  does not parse slice headers (32 fixed clear bytes) and only covers H.264 and AAC (plus AC-3,
  which the hub does not carry); the H.264 slice header parser is about 200 lines and can be
  checked against ffmpeg's `trace_headers`; ffmpeg decrypts both formats, so both can be tested
  end to end. H.265 `cbcs` would need the H.265 slice segment header (short-term reference
  picture sets, and more) and is left out.

Transcoding stays out of scope (it needs codecs, not containers).

## Decision

All additions are additive.

1. **SRT rendezvous** (`srt::Conn::rendezvous(cfg, remote, now)`, `Conn::is_rendezvous`;
   `srt::rendezvous`, `push_rendezvous`, `pull_rendezvous(engine, local, remote, ..)` on a UDP
   socket bound with `Engine::bind_udp`, datagrams from other addresses ignored). HSv5 only:
   - Both sides send `WAVEAHAND` (version 5, extension field 0, the key length in the
     encryption field) every 250 ms until they hear the peer. The cookie contest is libsrt's
     (the 32-bit difference of the cookies; the larger initiates; a draw picks a new cookie).
   - The **initiator** sends `CONCLUSION` with HSREQ (and KMREQ with a key it generates when
     it has a passphrase) and answers every handshake without HSRSP with it; on the
     responder's HSRSP (and KMRSP) it is connected and sends `AGREEMENT`, sent again when the
     responder repeats its HSRSP.
   - The **responder** answers waves with an empty `CONCLUSION`; on the HSREQ it decodes the
     initiator's KMREQ with its own passphrase (mismatch: rejection, `BAD_SECRET` / `UNSECURE`
     both ways), takes the latencies (the larger wins, as before), answers HSRSP (and KMRSP) and
     connects on the `AGREEMENT`, or on the initiator's next packet when it is lost.
   - Each side sends from its own initial sequence number and receives from the peer's. No
     stream ID is sent (libsrt does not use one in rendezvous). The handshake waits ten times
     `handshake_timeout`, as libsrt does. HSv4 rendezvous (SRT before 1.3) is refused.
2. **AV1 in MPEG-TS**, muxer and demuxer: stream type 0x06, PES stream ID 0xbd, the `AV01`
   registration descriptor first and the AV1 video descriptor (tag 0x80: marker, version 1,
   the `av1C` profile / level / tier / colour fields, `hdr_wcg_idc` 3, no initial presentation
   delay). One temporal unit per PES with `data_alignment_indicator`; a temporal delimiter,
   then each OBU (with `obu_size`, which the spec recommends) after `00 00 01` with
   emulation prevention bytes; the configuration's sequence header before keyframes that lack
   one. The demuxer cuts each OBU at its `obu_size` (an unsized one loses trailing zeros),
   drops temporal delimiters, takes the configuration from the first keyframe's sequence
   header, and also reads GStreamer's `AV1G` (plain OBUs). VP8 / VP9 stay out of MPEG-TS
   (documented).
3. **Recording to MPEG-TS**: `RecordFormat::MpegTs` (`.ts`; H.264, H.265, AV1, AAC, Opus, MP3)
   with the existing `mpegts::Muxer`; the PAT and PMT start each file and are repeated before
   every video keyframe and at least every second, so a file plays from any keyframe.
4. **HLS SAMPLE-AES**: `EncryptionMethod::{Aes128 (default), SampleAes}`,
   `HlsEncryption::method`. Same keys, provider, rotation and key URIs;
   `#EXT-X-KEY:METHOD=SAMPLE-AES`. Only H.264 and AAC tracks are carried (others are left out
   of the segments rather than sent in the clear); parts and init segments need nothing more.
   - **MPEG-TS** (Apple, MPEG-2 Stream Encryption Format for HLS): stream types 0xdb / 0xcf,
     `private_data_indicator` `zavc` / `aacd`, the `apad` registration descriptor with the
     audio setup information (`zaac`, the `AudioSpecificConfig`). Coded slices (NAL types 1, 5)
     longer than 48 bytes: emulation prevention removed, 32 bytes clear, then one encrypted
     16-byte block in every ten while more than 16 bytes remain, CBC from the IV in every NAL
     unit, emulation prevention applied again. AAC: the ADTS header and 16 bytes clear, the
     whole blocks after them encrypted, CBC from the IV in every frame. **The IV is one random
     IV per key, written as the `IV` attribute**, not the media sequence number: ffmpeg
     decrypts the packets it reads ahead across a segment boundary (and those it flushes at
     the end) with the current segment's IV, so per-segment IVs corrupt frames there; Apple's
     own tools write an `IV` attribute too.
   - **fMP4: `cbcs`** (ISO/IEC 23001-7 10.4): `encv` / `enca` sample entries with `sinf`
     (`frma`, `schm` `cbcs` 1.0, `tenc` version 1: protected, pattern 1:9 for video and none
     for audio, `Per_Sample_IV_Size` 0, a zero KID, a random 16-byte constant IV per muxer).
     Video samples: one subsample per coded slice, its clear part the 4-byte length, NAL header
     and slice header (H.264 7.3.3 parsed from the SPS / PPS of the configuration record and in
     band: frame number, field flags, POC, redundant picture count, reference index overrides,
     reference list modification, weighted prediction table, reference marking, CABAC init,
     QP deltas, deblocking; rounded up to a whole byte, emulation prevention bytes counted),
     the slice data encrypted in the 1:9 pattern from the constant IV; other NAL units clear (a
     slice whose header does not parse, e.g. with slice groups, stays clear). `senc` (subsample
     flag) with `saiz` / `saio` per fragment (only `senc` when a sample has more than 42
     subsamples, which `saiz` cannot size). Audio samples: every whole block, no `senc`.
   - The H.264 SPS parser behind `sps_size` now also returns the fields slices depend on; the
     slice header parser matches ffmpeg's `trace_headers` on every slice of the test sample.

## Consequences

- SRT peers behind NATs can meet; tested against libsrt 1.5.4 (`srt-live-transmit` from
  Debian's `srt-tools` in Docker, `tests/srt_rendezvous.rs`): `only` pulls what
  srt-live-transmit relays from ffmpeg and pushes a stream it writes to a file that ffprobe /
  ffmpeg decode, clear and encrypted, and two `only` engines meet each other; unit tests run
  both cookie orders, a lost AGREEMENT, lost waves, mismatched passphrases and the timeout.
  ffmpeg's `mode=rendezvous` binds to the URL's address and connects to the same address, so
  it cannot meet a peer on another host or port and is not used.
- AV1 goes out over SRT, HLS MPEG-TS and MPEG-TS recordings, and comes in over SRT. Checked
  against the AOM specification and by round trips through the muxer and demuxer (the AV1 +
  Opus sample, with and without in-band sequence headers, and GStreamer's mapping), and once by
  hand: ffmpeg 9 demuxes the stream as data, its PES payloads read back by a separate (Python)
  implementation of the start-code format decode with dav1d to frames identical to the
  source's (MD5 of all 50). No released player demuxes AV1 in MPEG-TS yet.
- Recordings can be MPEG-TS; ffprobe / ffmpeg decode every file (duration cuts, size cuts with
  rotation, an H.265 republish).
- SAMPLE-AES plays in ffmpeg frame for frame (`tests/hls_encryption.rs` compares the MD5 of
  every decoded frame with the source's, MPEG-TS and fMP4, plain and LL-HLS); with key rotation
  the TS segments are decrypted by an independent implementation in the test and every slice
  and AAC frame equals the source's, and the `cbcs` unit test decrypts fragments under two
  keys. ffmpeg itself cannot follow a key change (it applies one key to what it read ahead, and
  for fMP4 keeps the key it opened with), so its playback check runs without rotation.
  Segments read without the key do not decode to the source.
- Cost: unencrypted and AES-128 streams pay one `Option` check per packet in the TS and fMP4
  muxers (the SAMPLE-AES / `cbcs` work is in out-of-line functions, and the HLS segment being
  written did not grow: SAMPLE-AES keeps its key where AES-128 keeps its ciphertext state).
  `bench_segmenting` on gpu51 (quiet, pinned, 7 alternating rounds, medians, head / main):
  TS 1.027, TS-LL 0.999, fMP4 1.017, fMP4-LL 0.984, AES-128 cases 0.996 to 1.005; retired
  instructions +0.7 % (TS and fMP4), the rest code layout. SAMPLE-AES costs about 470 ns per
  packet in MPEG-TS (AES-128: 500) and `cbcs` 300 ns in fMP4 (one AES block per 160 bytes of
  slice data, plus the slice header parse).
- Not done: SAMPLE-AES for H.265 (its slice segment header), AC-3 / E-AC-3, Opus and other
  codecs; `EXT-X-SESSION-KEY`; FairPlay key systems (`KEYFORMAT` other than identity); SRT HSv4
  rendezvous; VP8 / VP9 in MPEG-TS (unspecified); transcoding.
