# only-zstd

[中文](README.zh-CN.md)

Zstandard (RFC 8878) for [`only`](https://github.com/lesismal/only), in pure safe Rust
(`#![forbid(unsafe_code)]`) without dependencies. It is the `zstd` algorithm of TLS certificate
compression (RFC 8879) in `only-tls` and the `zstd` content coding of `only-http`. An internal
crate (docs/api-stability.md): use it through those crates.

- `decompress(data, limit)`: one-shot decompression of one or more concatenated frames,
  skippable frames included, into at most `limit` bytes (`Error::TooLarge` beyond: the
  decompression-bomb defence). The whole format: raw, RLE and compressed blocks; raw, RLE,
  Huffman (one or four streams, tree descriptions direct or FSE-compressed, codes up to 12 bits)
  and treeless literals; predefined, RLE, FSE-compressed and repeated sequence tables; repeat
  offsets; Frame_Content_Size and the XXH64 Content_Checksum are verified. Frame_Content_Size is
  only a hint: a frame announcing more than the limit is refused at once, and memory is reserved
  up to the limit at most. Huffman and FSE streams are read backwards through a 64-bit container
  with table-driven decoding: the four literal streams in lockstep (libzstd's fast loop: bits
  left-aligned in a register, refilled from the position of a marker bit; for literal sections
  large enough by libzstd's rule, a double-symbol table giving one or two symbols per lookup,
  the streams that are not finished going on together), sequences decoded in
  batches of 64 (one bit read per sequence when the extra bits allow) and then executed, from
  tables sized for unchecked lookups; literals and matches are copied in 16-byte chunks into a
  window zeroed one block ahead (still never past the limit). The decoding tables and the
  literals buffer are kept per thread between calls, as libzstd's reused context keeps them
  (about 36 KB, plus up to 32 KiB of literals).
- `compress(level, data)`: one frame with Frame_Content_Size and a content checksum, a single
  segment up to 8 MiB (larger inputs get an 8 MiB window, the limit RFC 9659 sets for HTTP).
  Levels follow zstd's 1..=22 scale (`Level::FASTEST` 1, `DEFAULT` 3, `BEST` 22).
- `Compressor` / `Decompressor`: streaming. The compressor takes input in pieces and writes a
  block (128 KiB) at a time; `Flush::Flush` writes everything taken so far as complete blocks,
  `Flush::Finish` ends the frame (a frame whose input all arrived before anything was written is
  the one `compress` writes). Streamed frames have no content size and a window of 512 KiB
  (level 1) to 8 MiB (level 16 up), or `window_log(10..=23)`; the compressor's buffer slides,
  keeping the window, and its match tables are sized for the window (at levels 19..=22 and an
  8 MiB window 16 MiB of hash heads and 64 MiB of tree links, as libzstd's). The decompressor takes concatenated and skippable frames in pieces of any
  size: it gathers at most one block of input (128 KiB, or a header), decodes it with the
  one-shot block decoder into a window that slides once twice the frame's window is held, and
  delivers output under a size limit (`decompress_vec`) or into a slice (`decompress`); frames
  whose window is larger than `max_window` (8 MiB by default, RFC 9659's HTTP limit) are refused
  with `Error::WindowTooLarge`. Memory is bounded whatever the input: about twice the window
  plus two blocks.
- `Dictionary`: raw content (any bytes, Dictionary_ID 0) or the trained format that `zstd
  --train` writes (magic number, Dictionary_ID, Huffman and FSE tables, repeat offsets,
  content; checked as libzstd checks it, `Error::BadDictionary`). `compress_with_dictionary`,
  `decompress_with_dictionary`, `Compressor::with_dictionary` and
  `Decompressor::with_dictionary` use it: matches may refer back into the content while the
  frame is within its window, a trained dictionary's repeat offsets start the frame and its
  tables may be reused by the first blocks (Treeless_Literals_Block and Repeat_Mode), and the
  frame names the Dictionary_ID. A frame naming another dictionary is refused
  (`Error::WrongDictionary`); one naming none uses the dictionary given, as libzstd does.
- `xxh64(data, seed)`: XXH64, whose low 32 bits are the content checksum.

```rust
use only_zstd::{Error, Level, compress, decompress};

let data = b"the quick brown fox jumps over the lazy dog; ".repeat(100);
let packed = compress(Level::BEST, &data);
assert_eq!(decompress(&packed, data.len()).unwrap(), data);
assert_eq!(decompress(&packed, data.len() - 1), Err(Error::TooLarge));
```

**Decoder conformance.** The decoder accepts and rejects what libzstd does: the table
description reader is a port of libzstd's `FSE_readNCount` (including how it reads near the end
of its input), Huffman weights are decoded with the same two-state termination rule and checked as
`HUF_readStats` checks them, and the literals, sequences and frame checks follow
`zstd_decompress.c` / `zstd_decompress_block.c` (Block_Maximum_Size, the 4-stream minimum of 6
literals, repeat tables only after a block with sequences, offsets of zero or before the frame's
start, bit streams that must end exactly after the last sequence, trailing bytes after the last
frame). Like libzstd's one-shot API, windows up to 2³¹ · 15/8 bytes are accepted (the window is the
output itself, bounded by the limit) and empty input or only skippable frames decode to nothing.
Intentional differences, all stricter, are what the differential fuzz target tolerates:

- every Huffman-coded literal stream must end exactly where its symbols do
  (`Error::BadHuffmanStream`); libzstd's fast four-stream decoder does not check this (the content
  checksum is what catches such corruption there);
- a block decoding to more than Block_Maximum_Size is refused (`Error::BadBlock`), as by libzstd's
  streaming decoder and by its one-shot decoder after 1.5.7;
- legacy (pre-1.0) frames are not supported (`Error::BadMagic`).

Frames naming a dictionary are refused without one (`Error::DictionaryRequired`), as by libzstd.
The streaming decoder holds the frame's window rather than the whole frame, so a match reaching
further back than what it holds (at least the window) is refused (`Error::BadOffset`), as by
libzstd's streaming decoder; the one-shot decoder lets matches reach back to the frame's start.

**Encoder.** LZ77 in a window the size of the input (at most 8 MiB), with libzstd's match
finders: level 1 and 2 are `fast` (one hash table of the next 6 bytes, one candidate per
position, skipping ahead faster in data without matches), 3 and 4 `double_fast` (tables of the
next 8 and 5 bytes; a long match wins, a short one is checked against a long one a byte later),
both greedy, trying the first repeat offset one byte ahead first and taking runs of the second
repeat offset right after a match; levels 5..=15 walk hash chains of 4-byte hashes (from 8
candidates at level 5 to 160 at 15, stopping at a "nice" length) after trying the three repeat
offsets, lazily (5) or lazy2 (6..=15: a better match one or two bytes later wins), comparing
matches by length minus the cost of their offset as zstd does. Levels 16..=22 parse optimally,
as libzstd's `btopt` / `btultra`: every position's candidate matches come from binary trees of
suffixes, one per 4-byte hash (libzstd's `bt` match finder: inserting a position re-links the
tree around it, 48 to 512 nodes visited, each compared from the length already shared on its
side; increasing lengths only, the 16 longest kept; positions inside a match of the "nice"
length are not searched, and after a match longer than 384 bytes up to 192 positions are not
entered), then a shortest path through the block is found, priced with the bit costs of the
literals and of the literal length, match length and offset codes (from the previous block's
parse, or estimated from the block's bytes and the predefined distributions for the first
block, then from the previous pass: one pass at 16, two at 17 and 18, three from 19, at least
two on the first block), the literal length code paid as literals come, the three
repeat offsets followed along each path (matches of length 3 at a repeat offset included), long
matches taken whole. Blocks hold at most 128 KiB. Literals are Huffman-coded (code
lengths of a plain Huffman code, or limited to 11 bits by package-merge when longer, one stream below 256 literals, four above, the tree
described with FSE-compressed weights or 4 bits per weight, whichever is smaller), stored raw or
RLE when that is smaller; the previous block's code (or a trained dictionary's) is reused
without a description when it codes every literal for less. Each of the three sequence fields
uses whichever of an RLE, the predefined, an FSE-compressed table (normalized at every useful
accuracy log) or the previous block's table (Repeat_Mode) costs the fewest estimated bits. A block that does not shrink is stored raw, and a block of one repeated byte is an
RLE block.

Tests: XXH64 known answers (checked against `xxhash.h`); the official vectors of
facebook/zstd `tests/golden-decompression` (all decode to libzstd's output),
`tests/golden-decompression-errors` (all rejected) and `tests/golden-compression` (round trips at
every level, also through `zstd -d`), copied under `tests/data` with their license; round trips at
every level on text, binary, incompressible, empty, one-byte, long-period, all-byte-value and
larger-than-a-block data, each also with the exact size as limit (succeeds) and one byte less
(`TooLarge`); `zstd(1)` in both directions when installed: frames of levels 1..=19, `--ultra
-22`, `--long`, `--fast`, small windows (1 KiB blocks), small target block sizes, `--no-check`,
`--no-content-size`, several strategies, concatenated frames with skippable frames between them
decode with ours, and our output at every level passes `zstd -d` and `zstd -t`; truncation at every
byte and bit flips at every byte (an error or, with the checksum, the original data; never a
panic); bombs (10 000 RLE blocks, a frame announcing a terabyte) refused within the limit at once;
100 000 empty frames or blocks decode in linear time; frame-level errors one by one.

Streaming and dictionaries (`tests/stream.rs`): streamed frames at several levels, piece
sizes and flush modes decode with both decoders, fed whole, in 4 KiB pieces and a byte at a
time; windows from 1 KiB to 512 KiB with sliding buffers; every flush makes everything so far
decodable; output limits within a call, slices, truncation, sticky errors, concatenated and
skippable frames; the trained dictionary `tests/data/records.dict` (made by `zstd --train
--dictID=1234567`) and a raw one round trip at several levels, one-shot and streamed, and halve
the size of small JSON records; malformed dictionaries; and with `zstd(1)`: our streamed frames
and dictionary frames (trained and raw) decode with `zstd -d [-D]`, and its frames (streamed from a
pipe, without a content size) and dictionary frames decode with ours.

Fuzz targets `zstd_decompress` (never panics, exact limit, differential against libzstd through
the `zstd` crate with only the differences above tolerated), `zstd_roundtrip` (our output
decodes to the input with only-zstd and with libzstd), `zstd_stream` (the streaming decoder in
pieces agrees with the one-shot decoder, with and without the trained dictionary; arbitrary
bytes parsed as a dictionary never panic and a dictionary that parses round trips a sample) and
`zstd_stream_roundtrip` (the streaming compressor with piece sizes, flushes, windows and
dictionaries from the input: everything decodable after each flush, both decoders and libzstd
give the input back). A mutation-based differential run of
10 million inputs against libzstd 1.5.7 found no other difference.

Benchmark: `cargo run --release -p only-zstd --example zstd-bench [FILE...]` prints, per level
(`BENCH_LEVELS=1,3,19` picks some; default 1, 3, 9, 19, 22), the ratio next to zlib level 9
(only-deflate) and libzstd (`zstd -b`, when installed), and compression and decompression speed
next to libzstd's, on TLS 1.3 Certificate messages built from the chains in
`fuzz/corpus/x509_parse`, generated text, JSON and random data, and each file given.

Against the C library in-process (Silesia and HTTP payloads, docs/BENCHMARKS.md):
`tools/codec-bench/corpus.sh` builds the corpus, then
`cargo run --release --manifest-path tools/codec-bench/Cargo.toml zstd FILE...`.

Limitations: no long-distance matching, multithreading or dictionary training; the encoder's
optimal parser finds no 3-byte matches (its trees hash 4 bytes), so at level 19 it is 0.3-1.4%
larger than libzstd on the benchmark corpus (docs/BENCHMARKS.md).
