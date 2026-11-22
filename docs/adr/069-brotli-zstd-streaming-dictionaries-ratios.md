# ADR-069: Streaming, dictionaries and top-level ratios in akio-brotli and akio-zstd

English | [简体中文](069-brotli-zstd-streaming-dictionaries-ratios.zh-CN.md)

Status: accepted (2026-11-21)

## Context

ADR-041 added `akio-brotli` and `akio-zstd` with one-shot APIs only: the output vector is the
window, so memory is bounded by the caller's limit, which is what certificate compression and
buffered HTTP bodies need. It left out streaming and dictionaries ("nothing in the workspace
needs them yet") and did not aim at the reference encoders' ratios: brotli 11 came out 3.5-11%
larger than libbrotli on the benchmark corpus, zstd 19 1.3-7.6% larger than libzstd (no block
splitting, no static dictionary references, no optimal parsing in zstd). DEV-PLAN lists the three
as not done. Constraints: decoding must not get slower (the one-shot decoders are tuned against
the C libraries, docs/BENCHMARKS.md), still `#![forbid(unsafe_code)]` without BMI2 paths, and
every new entry point bounded in memory whatever the input says.

## Decision

### 1. Streaming APIs, shaped like akio-deflate's

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

  **Note 2026-11-22: RFC 9841 serialized shared dictionaries done** (additive API:
  `SharedDictionary`, `decompress_with_shared_dictionary`, `Decompressor::with_shared_dictionary`,
  `compress_with_shared_dictionary`, `Error::BadDictionary`). `SharedDictionary::new` parses
  the format of RFC 9841 section 5: the signature `0x91 0x00`, an LZ77 prefix, up to 64 word
  lists (words of 4 to 31 bytes, at most 2^15 of a length), up to 64 transform lists (up to 256
  prefix / suffix stringlets ending with the empty one, up to 255 transforms over 23
  operations: RFC 7932's 21 plus `ShiftFirst` / `ShiftAll` with their 16-bit parameters), up to
  64 dictionaries pairing a word list with a transform list (either may be brotli's own) and an
  optional context map. Where the RFC's prose and Google's implementation
  (`c/common/shared_dictionary.c`, the format's only producer and consumer) differ, Google's
  wins: a transform is the triplet (prefix, operation, suffix), not (prefix, suffix,
  operation); the prefix length is a varint of at most five bytes and at most 2^30 - 1. Unlike
  Google's parser, bytes after the last field are refused. Decoding follows Google's decoder:
  a distance beyond the window and the prefix is a static reference of length 4..=31 into the
  dictionary that the context map gives for the literal context of the last two output bytes
  (under the current literal block type's context mode; dictionary 0 without a map); an
  address past that dictionary's words × transforms continues in the others, in order, skipping
  those without words of the length; an empty transformed word at a distance of 120 or less is
  an error (a reference that may take no bits would otherwise make no progress, forever). The
  hot loop does not change: static references already left it for an `#[inline(never)]`
  function, which now also gets the context lookup table and passes custom dictionaries on to a
  cold function; the decoder holds the prefix and an optional pointer to the custom
  dictionaries where it held the prefix. Same-run A/B on gpu51 without a dictionary: decoding speed unchanged (geometric mean of branch / main over HTTP payloads, certificate chains and 20 MB of Silesia at levels 1, 5, 9 and 11: 0.996 on libbrotli's streams, 0.999 on our own, Silesia 0.999..1.006, within the spread of the libbrotli control; docs/BENCHMARKS.md, "Brotli shared dictionaries").
  The encoder uses the prefix only and, when the dictionary has custom static dictionaries,
  emits no static references (built-in words would decode as custom ones); searching custom
  word lists is not done, nor a streaming `Compressor` constructor (`with_dictionary(prefix)`
  serves dictionaries that are `is_raw()`). Checked against libbrotli built with
  `BROTLI_EXPERIMENTAL` (`tools/interop/brotli-shared/run.sh`): 20,000 random dictionaries with
  hand-made streams of references (every operation, context maps, fallback, prefix copies)
  decode to the same output or are refused by both; libbrotli's encoder with four dictionaries
  (a prefix; custom words; custom words and transforms; two word lists and brotli's own chosen
  by context) at q1/5/9/11 on alice29.txt decodes with ours (custom words in use from q5), and
  ours decodes with libbrotli. Not done: RFC 9841's large-window brotli and framing format
  (sections 6 and 8), compound dictionaries (several prefixes).

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

  **Note 2026-11-22: block splitting done** (no API change). Literals, insert-and-copy symbols
  and distances get block types (`encode/split.rs`). Levels 10 and 11 port Google's
  `block_splitter`: histograms seeded from samples, 3 (10) or 10 (11) rounds of a cheapest-path
  assignment of symbols to histograms with a block switch cost, then the blocks clustered into
  at most 256 types with Google's histogram-cost clustering, which also builds the context maps
  over (literal block type, 64 contexts) and (distance block type, 4 copy-length contexts); the
  meta-block is written with one literal code, with the single-type context map and with block
  types, and the smallest is kept; meta-blocks under 8 KiB are not split. With block types,
  meta-blocks of up to twice the window pay at 10 and 11 (still parsed in 256 KiB blocks;
  streaming keeps 256 KiB meta-blocks). Level 11's second parse pass prices each literal by the
  histogram of the literal block type its position falls in after splitting the first pass's
  literals; without that, the parse priced from one histogram fitted the split meta-block worse
  than level 10's single pass on x-ray. Levels 4..=9 split meta-blocks of 64 KiB or more with
  Google's one-pass greedy `BlockSplitter`, each literal block type coding the context map's
  clusters with codes of its own where that pays, and keep the types only if they save 1% of
  the meta-block (writing block switches costs time; HTTP text stays unsplit). Results on the
  benchmark corpus (docs/BENCHMARKS.md, "Brotli block splitting"): level 11 on the first 20 MB
  of Silesia from +4.7% to -4.5% of libbrotli's size (5,104,415 / 5,346,776), level 10 from
  +7.6% to +0.8%, HTTP payloads at 11 +0.9..1.3% (was +0.9..2.6%), certificate chains
  unchanged; levels 4-9 0.2-0.75% smaller on Silesia, 3-4.4% on a mixed file, HTTP payloads
  byte-identical. Costs: levels 10-11 about 30% slower on Silesia (unchanged on text and
  certificate chains), level 4 12% slower on Silesia and 1-6% on unsplit payloads above
  64 KiB; the decoder is unchanged, our own block-typed streams decode like libbrotli's
  (8-22% slower than our old single-type streams on Silesia). Tried and dropped: a context mode
  per literal block type, sliding-window literal costs, the full splitter at the middle levels.

### 4. HTTP

`akio-http` was checked for buffering: buffered responses are compressed whole by the
`compress` middleware (one-shot, best ratio, `Content-Length` known), and streamed responses
(`Context::stream_response`) are sent uncompressed with every coding, gzip included: response
filters do not apply to them. Nothing buffers a streamed body, so nothing changes there now.
Compressing streamed responses (an encoder per stream, a flush per write for server-sent
events, a `Compress` switch, per-stream memory sized down) is a feature of its own, left for
later; the streaming APIs make it possible. The HTTP client decodes no content codings.
(Done since: ADR-074.)

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
- Decoding speed: same-run A/B against main on the quiet host, zstd -1.8..+3.1% and brotli
  -2.2..+4.9% per cell; in a dedicated loop over the small certificate chains zstd -1.1..+2.3%
  and brotli 0..+2.0% (at most about 0.15 us per chain, the brotli part from reading headers
  unit by unit), depending on the build profile (docs/BENCHMARKS.md, "Streaming, dictionaries
  and ratios").
- Four fuzz targets: `zstd_stream`, `brotli_stream` (streaming decoder in pieces against the
  one-shot decoder, with and without dictionaries; arbitrary bytes as a zstd dictionary),
  `zstd_stream_roundtrip`, `brotli_stream_roundtrip` (streaming compressor with pieces, flushes,
  windows and dictionaries from the input; everything decodable after each flush; libzstd and
  brotli-decompressor as oracles).
