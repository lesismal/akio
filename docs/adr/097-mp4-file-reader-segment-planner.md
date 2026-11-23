# ADR-097: A sans-io reader of MP4 files and an HLS segment planner (akio-media `mp4`)

English | [简体中文](097-mp4-file-reader-segment-planner.zh-CN.md)

Status: accepted (2026-11-23)

## Context

akit (the Rust counterpart of fit) serves a media library as video on demand: it cuts HLS
segments (fMP4 or MPEG-TS) out of progressive MP4 files at keyframes, without transcoding, and
plays files into the hub as channels. This is akit's request A7, the counterpart of fit's A64 in
fib (`media/mp4`).

akio-media had a fragmented MP4 muxer and demuxer (`fmp4`) and HLS, but nothing that reads the
sample tables of a regular MP4 file (`stts`, `ctts`, `stss`, `stsc`, `stsz` / `stz2`,
`stco` / `co64`, `elst`). Such a file of a two-hour film holds hundreds of thousands of samples.
Its `moov` is several megabytes, at the front of the file or at its end.

Constraints:

- **Rule 3.** Library code must not block an I/O thread. A file is read on the pool or a thread
  of the caller's, so the reader itself does no I/O.
- **Rules 7 and 10.** Every table is bounded.
- **DEV-PLAN section 4.** Protocol parsers have fuzz targets.

## Decision

### 1. A new module `akio_media::mp4`, sans-io

fib's reader reads through an `io.ReaderAt`; akio's takes bytes the caller read, in three
steps:

- **`Locator`.** `next_read() -> (offset, len)` names at most 16 bytes (a box header) and
  `feed(bytes)` takes them. A caller that read more (the first 64 KiB) passes it all, and every
  header inside is used.
  - It walks top-level headers (sizes of 0, 32 and 64 bits) to the `moov` and returns a
    `MoovLocation` (offset, size, file size, `ftyp` major brand).
  - A `moof` is `Mp4Error::Fragmented` (`fmp4::Demuxer` reads those). A box running past the
    end is `NoMoov` (a file cut short).
- **`Movie::parse(moov, &location, &Limits)`.** It takes the whole `moov` box, read in one go,
  at most `Limits::max_moov_bytes` (64 MiB by default; a two-hour film's is under 10 MB).
  - fib reads the tables of the `moov` through the file in a second pass. Holding the `moov`
    briefly costs about what the index costs, and makes the parser a plain slice parser, which
    is simpler to bound and to fuzz.
  - `Movie::from_bytes(file)` does both steps for a file held in memory.
- **`Plan` / `Segment`.** Plan the cuts, name the byte ranges, and turn the bytes read into
  packets (section 4).

### 2. What a track has

`Mp4Track` has:

- `id`, `handler`, `language` (ISO 639-2/T, `und`), `name` (from `udta/name`, else `hdlr`'s
  name), `timescale`, `duration`;
- `format`: the sample entry's four-character code;
- `track`: an `av::Track` read by the same sample-entry parser `fmp4::Demuxer` uses. That
  parser is now `pub(crate)`. It reads `avc1` / `avc3`, `hvc1` / `hev1`, `av01`, `vp08` /
  `vp09`, `mp4a` (`esds`, QuickTime versions 1 and 2) and `Opus`;
- `edits`, `shift`, `index`.

Formats the stack does not carry are `Codec::Unknown` with their `format` kept. AC-3 / E-AC-3
are among them: adding a codec to `av::Codec` means teaching every muxer, which was not cheap
here. A sample entry that does not parse is also Unknown rather than an error, so one bad track
does not make a file unplayable. Its samples stay indexed.

### 3. A compact sample index

`SampleIndex` keeps the tables in compact form, not an entry per sample:

- **Sizes.** At the narrowest width that holds every size (`u8`, `u16`, `u32`), or none when
  `stsz` has one size for all.
- **Decode times.** `stts` as runs (first sample, delta, decode time of the first).
- **Composition offsets.** `ctts` as runs (first sample, offset), or one `i32` a sample when the
  runs would take more. Both versions are read signed, as ffmpeg does. A `ctts` shorter than
  the samples leaves the rest at 0.
- **Sync samples.** `stss` as a sorted list (sorted and deduplicated if the file's is not);
  `None` when there is no `stss`.
- **Chunks.** Per chunk its first sample and its file offset (`stco` or `co64`), expanded from
  `stsc`.

Lookups:

- `sample(i)`, `first_at_or_after_dts`, `keyframe_at_or_before` and `keyframe_at_or_after` are
  binary searches.
- `iter(from)` / `range(from, to)` walk samples at constant cost each.
- `Mp4Track::keyframe_at(time)` finds the last keyframe presented at or before a time (stepping
  back past B-frame keyframes presented later).

Measured on a synthetic hour at 60 fps with B-frames plus AAC (384,750 samples): the index
takes 1.6 MB (4.2 bytes a sample) and parses in 1.1 ms (release build, on the macOS development machine).

### 4. Segments and the glue to the muxers

- **Cutting.** `Plan::new(&movie, target)` cuts at the keyframes of the first video track; a
  movie without video cuts on its first track of a known codec.
  - A segment ends at the first keyframe presented `target` or more after the start it is due
    at, as ffmpeg's `-hls_time` cuts.
  - The plan keeps 16 bytes a segment and computes a `Segment` when asked.
  - Other tracks are split by decode time at the cut's presentation time; another video track
    splits at its next keyframe.
- **The timeline.** Times are the presentation timeline (edit list applied), moved later by
  `Plan::delay()` so that no decode time is negative. A negative decode time would be clamped
  by `tfdt` and wrapped by MPEG-TS.
- **What a segment gives.**
  - `byte_ranges(&movie, max_gap)`: sorted, merged ranges (gaps up to `max_gap` included) for
    the caller to read off the I/O thread.
  - `packets(&movie, &[(offset, &bytes)])`: canonical `Packet`s in decode order, indexing
    `Movie::av_tracks()`.
  - `write_fmp4(...)`: one `moof` + `mdat` with sequence number `index + 1`. That needs the new
    `fmp4::Muxer::set_next_sequence`, since VOD segments are made out of order.
  - `write_ts(...)`: PAT/PMT, then a PES a sample.
  - `Plan::vod_playlist(init, uri)`: a VOD media playlist (`EXT-X-PLAYLIST-TYPE:VOD`,
    `EXT-X-MAP` for fMP4, `ENDLIST`).
- **NAL unit lengths.** H.264 / H.265 samples with 1- or 2-byte NAL unit lengths are rewritten
  with 4-byte ones, and `av_tracks()` patches the record to match: the canonical form of `av`
  requires 4.

### 5. Edit lists

As fib and players do:

- the empty edits before the first edit that plays delay the track;
- that edit's media time is presented at its start (`Mp4Track::shift`);
- later edits are kept in `edits` and not applied.

### 6. Limits and untrusted input

`Limits` defaults:

| Limit | Default |
| --- | --- |
| `max_moov_bytes` | 64 MiB |
| `max_boxes` (top-level headers, and in the `moov`) | 65,536 |
| `max_tracks` | 64 |
| `max_samples` a track | 2^24 |
| `max_edits` | 1024 |
| `max_segments` | 2^20 |

Beyond the limits:

- Every count is checked against the bytes of its box before anything is allocated. Every
  allocation is bounded by the `moov`'s bytes; the dense `ctts` is used only when the samples
  are at most twice its entries.
- A constant-size `stsz` of 2^24 samples allocates nothing per sample.
- The parser walks a fixed box layout and never recurses on input, so box depth is bounded by
  construction.
- Tables must agree:
  - `stts` covers every sample;
  - `stsc` puts every sample in a chunk;
  - `stsc` first chunks increase;
  - every chunk's samples lie within the file;
  - decode times stay below 2^61.
- Out-of-range `stss` entries are ignored.
- Left out: `cmov`, sample descriptions after the first, sample groups, encryption.

### 7. Tests

- **ffmpeg fixtures.** The seven files of fib's `media/mp4/testdata` are copied with their
  ffprobe output (MIT, same author): H.264 / H.265 / AV1 with AAC / Opus, `moov` at both ends,
  B-frames, negative composition offsets, an empty edit. Checked against ffprobe:
  - every sample's offset, size, duration, DTS, PTS and sync flag, with and without the edit
    list;
  - every track's codec, size, rate and channels;
  - the SHA-256 of its configuration.
- **Synthetic files** with every form of each table:
  - `stsz`, `stz2` of 4, 8 and 16 bits, and a constant size;
  - `ctts` absent, version 0 and version 1;
  - `stss` listed, absent, empty and reversed;
  - `stco` and `co64`; a 64-bit `mdat`; version 1 headers; the `moov` at either end;
  - edit lists of both versions;
  - empty chunks.

  Every lookup is checked against a walk.
- **Malformed input.** Malformed tables, truncation at every byte, random corruption of the
  `moov`, and each limit just at and just over.
- **Planning and muxing.** Plans at several targets (every sample in exactly one segment,
  keyframe starts, durations); segments muxed to fMP4 and demuxed back; segments muxed to TS
  and demuxed back; NAL length widening.
- **Fuzz target** `mp4_read`.
- **Interop** (`tests/mp4_interop.rs`). ffmpeg writes ten-second files (H.264 + AAC with
  B-frames and `moov` at the back, H.265 + AAC with faststart, H.264 + Opus). They are read
  through `Locator` and range reads, and cut at 2 s. Then:
  - every fMP4 and TS segment decodes with no ffmpeg error and starts with a keyframe;
  - both VOD playlists play all 250 frames.

## Consequences

- akit can serve MP4 files as HLS (or feed their packets to the hub) without transcoding, with
  all file I/O on its own threads.
- `fmp4::Muxer::set_next_sequence` is a new public method; nothing else outside `mp4` changes.
- AC-3 / E-AC-3 tracks are indexed but not carried; adding them is a codec change across the
  muxers (TS stream types 0x81 / 0x87, `ac-3` / `ec-3` entries).
