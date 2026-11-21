# ADR-069: Streaming, dictionaries and top-level ratios in only-brotli and only-zstd

English | [简体中文](069-brotli-zstd-streaming-dictionaries-ratios.zh-CN.md)

Status: accepted (2026-11-21)

## Context

ADR-041 added `only-brotli` and `only-zstd` with one-shot APIs only: the output vector is the
window, so memory is bounded by the caller's limit, which is what certificate compression and
buffered HTTP bodies need. It left out streaming and dictionaries ("nothing in the workspace
needs them yet") and did not aim at the reference encoders' ratios: brotli 11 came out 3.5-11%
larger than libbrotli on the benchmark corpus, zstd 19 1.3-7.6% larger than libzstd (no block
splitting, no static dictionary references, no optimal parsing in zstd). DEV-PLAN lists the three
as not done. Constraints: decoding must not get slower (the one-shot decoders are tuned against
the C libraries, docs/BENCHMARKS.md), still `#![forbid(unsafe_code)]` without BMI2 paths, and
every new entry point bounded in memory whatever the input says.

## Decision

### 1. Streaming APIs, shaped like only-deflate's

Both crates get `Compressor` (`compress(input, &mut out, Flush)`, `Flush::{None, Flush, Finish}`,
`reset`, `total_in`, `is_finished`, a window setting) and `Decompressor` (`decompress_vec(input,
&mut out, limit)` and `decompress(input, &mut [u8])` returning `Progress { consumed, produced,
done }`, `is_done`, `reset`, `total_in` / `total_out`, a window limit), as `Deflater` / `Inflater`
are. Errors are sticky until `reset`. The one-shot functions are unchanged.

- **zstd decoder**: frames are self-delimiting by block, so the decoder gathers at most one
  block of input (or a header) across calls, decodes it with the one-shot block decoder into a
  window buffer and delivers output under the caller's limit. The window slides (one copy)
  once it holds the frame's window plus as much again; a frame whose window exceeds
  `max_window` (8 MiB by default, RFC 9659's HTTP limit) is refused. XXH64 is computed
  incrementally. Because the window is the frame's window and not the whole frame, a match
  reaching further back than what is held is `BadOffset`, as in libzstd's streaming decoder.
- **brotli decoder**: meta-blocks are not byte-aligned and have no compressed length, so
  re-decoding a meta-block from its start whenever more input arrives would be quadratic (a
  16 MiB meta-block fed in 1460-byte segments). Instead the one-shot decoder's pieces are made
  resumable at unit boundaries: the meta-block header is read one unit at a time (a block type
  description, the distance parameters, a context map's tree code or one of its entries, one
  prefix code) and the command loop records a checkpoint (bit reader, output position, distance
  ring, block switching state) at each command. A unit that consumed bits past the input, or
  failed after doing so, is rolled back to its checkpoint and retried with more input; an
  error is the stream's only if no bit past the input was used. The worst case re-reads one
  prefix code or one command per input byte. The command loop is a `const STREAM: bool`
  generic: the one-shot instantiation compiles the checkpoints, the pause and the window base
  out. The decoder also pauses at a command boundary 1 MiB ahead of delivery, so memory is the
  window (sliding at twice its size), 1 MiB, the prefix codes and one unit of input.
- **Encoders**: a buffer of history and pending input; a block (zstd, 128 KiB) or meta-block
  (brotli, 1 MiB / 256 KiB at 10-11) is compressed when full or on `Flush`. The match finder's
  state survives between blocks (its positions rebased when the buffer slides by a multiple
  of the chain table size). zstd `Flush` writes the pending input as a block (blocks are
  byte-aligned); brotli `Flush` ends the meta-block and pads with an empty metadata block,
  as `BROTLI_OPERATION_FLUSH` does. A stream whose whole input arrives before anything is
  written is the one-shot output, content size included.

### 2. Dictionaries

- **zstd**: `Dictionary::new(bytes)` parses the trained format of `zstd --train`
  (Dictionary_ID, Huffman and FSE tables, repeat offsets, content; libzstd's checks) or takes
  anything else as raw content (`Dictionary::raw` forces it); cloning shares it. Decoding puts
  the content before the frame in the window and starts the frame with the dictionary's tables
  and repeat offsets; a frame naming another Dictionary_ID is `WrongDictionary`, one naming
  none uses the dictionary given (libzstd's rule). The one-shot `decompress_with_dictionary`
  runs on the streaming decoder. Encoding puts the content before the input for the match
  finder, starts from the dictionary's repeat offsets and lets the first blocks reuse its
  tables. For that the encoder now tracks the tables the decoder holds, so every block may also
  repeat the previous block's Huffman code (Treeless_Literals_Block) or sequence tables
  (Repeat_Mode) when that is estimated cheaper. Dictionary references stay within the frame's
  window from the content's end, as libzstd's encoder keeps them.
- **brotli**: raw (LZ77 prefix) dictionaries, the kind `brotli -D` and RFC 9842's `dcb`
  coding use, with Google's decoder semantics (`BrotliDecoderAttachDictionary` with
  `BROTLI_SHARED_DICTIONARY_RAW`): a distance beyond the window's reach addresses the
  dictionary first (the copy must stay within it), then the static dictionary with the
  dictionary's length added. The encoder takes dictionary positions as candidates while the
  output is within the window. The serialized shared-dictionary format of RFC 9841 (custom word
  lists and transforms) is not implemented: Google's CLI cannot produce it, nothing here needs
  it, and its decoding changes the static-dictionary path of the hot loop.

### 3. Ratios at the top levels

- **zstd 16..=22**: a shortest-path parse per block (libzstd's `btopt` / `btultra`) over
  candidates from libzstd's binary-tree match finder (a tree of suffixes per 4-byte hash,
  re-linked around each inserted position; increasing lengths, at most 16). Hash chains were
  tried first: on JSON the long chains of near-equal candidates made level 19 30 times slower
  than before and 5 times slower than libzstd, and shortening them cost ratio; the trees find
  better candidates in a fraction of the time. The path is priced with literal and
  literal-length / match-length / offset code costs from the previous block's parse (libzstd
  carries its statistics over too; starting every block from the predefined distributions made
  level 16 3.7% larger than the lazy parser it replaced on Silesia), the first block from
  estimates with at least two passes, then from the previous pass (1 pass at 16, 2 at 17-18, 3
  from 19), the literal length code charged as literals come (libzstd's pricing), the repeat
  offsets followed along each path. 3-byte matches are not ported.
- **brotli 10-11**: static dictionary references, the main thing missing: an index of the
  dictionary's words by their first four bytes in lower case, each position looked up after
  each transform prefix and checked against the identity, uppercase and omit-last transforms
  with their suffixes; the references are shortest-path candidates (copy length = word length,
  distance = window reach + 1 + raw dictionary + address, ring untouched). Block splitting was
  not done: it needs block-type and block-length codes, per-type context maps and a splitter
  (Google's iterative histogram assignment), and pays mostly on mixed binary data. Larger
  meta-blocks at 10-11 were tried and dropped (JSON 0.3% smaller, Silesia 0.17% larger).

### 4. HTTP

`only-http` was checked for buffering: buffered responses are compressed whole by the
`compress` middleware (one-shot, best ratio, `Content-Length` known), and streamed responses
(`Context::stream_response`) are sent uncompressed with every coding, gzip included: response
filters do not apply to them. Nothing buffers a streamed body, so nothing changes there now.
Compressing streamed responses (an encoder per stream, a flush per write for server-sent
events, a `Compress` switch, per-stream memory sized down) is a feature of its own, left for
later; the streaming APIs make it possible. The HTTP client decodes no content codings.

## Consequences

- Additive API in both crates (`Compressor`, `Decompressor`, `Flush`, `Progress`,
  `compress_with_dictionary`, `decompress_with_dictionary`; zstd `Dictionary`,
  `DEFAULT_MAX_WINDOW`; new `Error` variants `WrongDictionary`, `BadDictionary` (zstd) and
  `WindowTooLarge` (brotli); the enums are `#[non_exhaustive]`). Snapshots updated.
- Output changes: zstd frames at every level may repeat tables (smaller for multi-block
  inputs), and levels 16-22 parse optimally; brotli 10-11 use static dictionary words. Our
  decoders, `zstd -d`, `brotli -d`, libzstd and brotli-decompressor decode them (tests and fuzz
  targets).
- Ratios, sizes against the C libraries on the benchmark corpus (deterministic): zstd 19 from
  +1.3..7.6% to +0.3..1.4% (Silesia 20 MB 6,160,823 → 5,785,046, libzstd 5,723,399; JSON 46,894
  → 44,386 / 44,267; HTML 7,173 → 6,985 / 6,967; JavaScript 20,726 → 20,190 / 20,102; certificate
  chains 1,736 → 1,724 / 1,701 and 2,563 → 2,545 / 2,531), level 16 smaller than libzstd's on
  Silesia and JSON; brotli 11 from +3.5..11.4% to
  +0.9..4.7% (HTML 6,739 → 6,202, libbrotli 6,048; JSON 43,638 → 42,754 / 41,813; JavaScript
  19,936 → 19,252 / 19,077; chains 1,693 → 1,640 / 1,615 and 2,515 → 2,454 / 2,430; Silesia
  unchanged at 5,599,939 / 5,348,162).
- Compression at the top levels is slower, as optimal parsing is in libzstd: zstd 19 at 3.5-10.9
  MB/s (was 7-59; libzstd 3.9-12), zstd 16 at 6.5-14 (libzstd 9.6-18.6), brotli 10-11 at
  about half the speed on text. Tree links double the zstd match tables at 16-22 (64 MiB at
  19-22 with an 8 MiB window, as libzstd's).
- Decoding speed unchanged: same-run A/B against main on the quiet host, zstd -1.8..+3.1% and
  brotli -2.2..+4.9% per cell, and the small certificate chains within +-0.9% in a dedicated
  three-round loop under both the default and the benchmark build profile (docs/BENCHMARKS.md,
  "Streaming, dictionaries and ratios").
- Four fuzz targets: `zstd_stream`, `brotli_stream` (streaming decoder in pieces against the
  one-shot decoder, with and without dictionaries; arbitrary bytes as a zstd dictionary),
  `zstd_stream_roundtrip`, `brotli_stream_roundtrip` (streaming compressor with pieces, flushes,
  windows and dictionaries from the input; everything decodable after each flush; libzstd and
  brotli-decompressor as oracles).
