# ADR-034: HLS encryption and recording in the media hub

English | [简体中文](034-media-hls-encryption-recording.zh-CN.md)

Status: accepted (2026-11-18)

## Context

`akio-media` listed two gaps that keep it out of common deployments. HLS was served in the
clear: a paid or private stream needs at least `EXT-X-KEY:METHOD=AES-128`, the one encryption
every HLS player (Safari, hls.js, ExoPlayer, ffmpeg) supports without DRM, with keys an
application hands out to the viewers it chooses and rotates. And a hub stream could not be
written to disk, which every streaming server is asked for (archives, compliance, VOD from
live). `akio-crypto` had AES with CTR and GCM, but no CBC.

Both touch the data plane: HLS segments are cut on the publisher's I/O thread, and recording is
disk I/O, which docs/rules.md 1 keeps off I/O threads.

## Decision

All additions are additive.

1. **AES-CBC in `akio-crypto`.** `Aes::encrypt_cbc` / `decrypt_cbc` (in place, whole blocks,
   the chaining value carried in and out so a message can be processed in pieces; decryption
   four blocks at a time) and `Aes::encrypt_cbc_padded` / `decrypt_cbc_padded` (PKCS #7; the
   padding is checked in constant time, and the documentation warns about padding oracles).
   Tested with the SP 800-38A vectors (AES-128 and AES-256, hardware and portable paths, whole
   and split) and PKCS #7 outputs checked against OpenSSL.
2. **HLS AES-128.** `HlsConfig::encryption: Option<HlsEncryption>` (`keys: Arc<dyn
   KeyProvider>`, `rotate_every` segments, 0 = never). Every segment and every LL-HLS part is
   encrypted whole with AES-128-CBC and PKCS #7, for MPEG-TS and fMP4 alike:
   - **IV**: the media sequence number, as RFC 8216 5.2 defines when `EXT-X-KEY` has no `IV`
     attribute. A part is a resource of its own, so it is encrypted on its own from its
     segment's IV (as hls.js and Safari decrypt parts). No `IV` attribute is ever written: one
     tag would then fix one IV for every segment until the next tag.
   - **Playlist**: `#EXT-X-KEY:METHOD=AES-128,URI="key-<n>.key"` before the first media line
     (part or segment) of key `n`, again only when the key changes. fMP4 init segments stay
     clear: `EXT-X-KEY` applies to the `EXT-X-MAP` that follows it, and an encrypted map would
     need an `IV` attribute, so a map that follows a key is preceded by
     `#EXT-X-KEY:METHOD=NONE` and the key is named again before the next segment. As with a
     discontinuity or a new map, no preload hint is written for a segment that needs a new key
     tag until its first part is out.
   - **Keys**: `KeyProvider::key(path, n) -> HlsKey` (16 bytes and an optional URI) is called
     on the publisher's thread when a segment starts that needs key `n` (the first, then every
     `rotate_every` segments); it must not block, and must return a fresh key each time: a
     muxer that restarts counts keys and media sequence numbers (the IVs) from 0 again. `KeyProvider::authorize(path, n, &Context)`
     decides each request for `/<path>/key-<n>.key` (403 when refused; default: allow) and
     runs on the requester's I/O thread. Keys are answered `application/octet-stream` with
     `Cache-Control: private, no-store`, only while a kept segment uses them; `HlsKey::with_uri`
     points players at the application's own key server instead. `RandomKeys` issues keys from
     a ChaCha20 generator seeded by the OS. `MediaHttp` routes `.key` to `Hls`.
   - **Cost on the publisher's thread**: the segment's ciphertext is built as it grows, 64 KiB
     at a time, so its end costs no more than one part; parts are encrypted when cut. The
     ciphertext of the segment being written counts toward `max_bytes`. Unencrypted streams pay
     one `None` check per packet.
3. **Recording** (`akio_media::record`). `Recorder::new(hub, RecordConfig)` /
   `with_hooks(.., impl RecordHooks)`, `start(path)`, `stop(path)`, `stop_all`, `active`,
   `dropped`, `queued_bytes`. `RecordConfig`: `dir`, `format` (`RecordFormat::Fmp4` default, or
   `Flv`), `segment_duration`, `segment_bytes`, `max_files` (rotation per recording),
   `max_queued_bytes` (32 MiB), `wait` (10 s: a recording may start before its publisher and
   survives a republish; `None` needs a live stream), `flv` (encoder options).
   - The sink muxes on the publisher's thread with the existing muxers (`fmp4::Muxer`,
     `flv::Encoder`) and hands bytes in chunks of up to 256 KiB (and at video keyframes) to
     the recorder's **writer thread**, which owns every file: create (with directories), write
     through a 256 KiB buffer, `sync_all` on close, delete for rotation, and every hook.
     docs/rules.md 1.2 prefers the engine's logical pool, but a hub sink has no connection to
     reach it through (`Conn::spawn_blocking`), and rule 1.3 allows a dedicated thread; one
     per recorder keeps a file's writes in order without locking.
   - Files start at a video keyframe (any packet for audio-only streams), each with timestamps
     from 0, and are cut at the first keyframe after `segment_duration` or `segment_bytes`
     (without a keyframe, at four times `segment_bytes`), and at every republish or track
     change. fMP4 fragments are cut at keyframes and at least every second.
   - **Backpressure**: when queued bytes pass `max_queued_bytes`, the file is closed and
     packets are dropped (counted in `dropped`) until the queue is half empty and a keyframe
     starts the next file: a slow disk costs a gap between files, never a broken file or
     unbounded memory, and never stalls the publisher.
   - **Hooks** (`RecordHooks`, on the writer thread, so they may block): `file_name(stream,
     index, started, ext)` (relative to `dir`; names with `..` or absolute ones fall back to
     the default `<stream>-<unix ms>-<index>.<ext>`; called on the publisher's thread),
     `on_start(&RecordFile)`, `on_stop(&RecordFile, Result<(), &io::Error>)` after the file is
     synced, `on_remove(&Path)` for rotation. `RecordFile` has the stream, path, index, start
     time, media duration and size.

## Consequences

- An encrypted stream plays in every HLS player without DRM; keys can be rotated and
  authorized per request, or served by the application. Tested: unit tests (ciphertext of
  segments and parts against the unencrypted stream, rotation, key tags around maps and
  discontinuities, provider URIs, incremental encryption against one-shot) and
  `tests/hls_encryption.rs` (MPEG-TS and fMP4, plain and LL-HLS: key requests refused without
  the header the provider wants, each segment and part decrypted with the served key, ffmpeg
  decoding the live encrypted playlist with `-headers` and every decrypted segment).
- Recording writes valid files under a bounded queue and never touches the disk from an I/O
  thread. Tested (`tests/record.rs`): cuts by duration and size, rotation with `on_remove`,
  a republish with H.265, a stalled writer (drops, bounded queue, files still whole), hook
  names; ffprobe / ffmpeg decode every file, which starts with a keyframe at 0 and lasts what
  its `on_stop` reported.
- Not done: `SAMPLE-AES` and CBCS (fMP4 `encv`/`enca` + `sinf` + `senc`). CBCS for H.264 and
  H.265 must leave every slice header clear, which needs slice header parsing (PPS-dependent,
  with reference list and weighted prediction syntax) per NAL unit, and SAMPLE-AES in MPEG-TS
  needs per-codec elementary stream rewriting; neither fits this change cleanly, and AES-128
  already plays everywhere. Also not done: `EXT-X-SESSION-KEY` in multivariant playlists, key
  tokens from the playlist's query string (players do not carry them to key URIs: the
  provider checks headers or cookies, or names its own URI), recording to MPEG-TS, a `moov`
  with the total duration (files are fragmented; players read the fragments).
- The writer thread is one per recorder: a recorder writing many streams to one slow disk
  shares that disk's speed among them; a second recorder gets a second thread.
