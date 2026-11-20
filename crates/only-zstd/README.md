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

Frames naming a dictionary are refused (`Error::DictionaryRequired`), as by libzstd without one.

**Encoder.** LZ77 in a window the size of the input (at most 8 MiB), with libzstd's match
finders: level 1 and 2 are `fast` (one hash table of the next 6 bytes, one candidate per
position, skipping ahead faster in data without matches), 3 and 4 `double_fast` (tables of the
next 8 and 5 bytes; a long match wins, a short one is checked against a long one a byte later),
both greedy, trying the first repeat offset one byte ahead first and taking runs of the second
repeat offset right after a match; levels 5..=22 walk hash chains of 4-byte hashes (from 8
candidates at level 5 to 768 at 22, stopping at a "nice" length) after trying the three repeat
offsets, lazily (5) or lazy2 (6..=22: a better match one or two bytes later wins), comparing
matches by length minus the cost of their offset as zstd does. Blocks hold at most 128 KiB. Literals are Huffman-coded (code
lengths of a plain Huffman code, or limited to 11 bits by package-merge when longer, one stream below 256 literals, four above, the tree
described with FSE-compressed weights or 4 bits per weight, whichever is smaller), stored raw or
RLE when that is smaller. Each of the three sequence fields uses whichever of an RLE, the
predefined or an FSE-compressed table (normalized at every useful accuracy log) costs the fewest
estimated bits. A block that does not shrink is stored raw, and a block of one repeated byte is an
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

Fuzz targets `zstd_decompress` (never panics, exact limit, differential against libzstd through
the `zstd` crate with only the differences above tolerated) and `zstd_roundtrip` (our output
decodes to the input with only-zstd and with libzstd). A mutation-based differential run of
10 million inputs against libzstd 1.5.7 found no other difference.

Benchmark: `cargo run --release -p only-zstd --example zstd-bench [FILE...]` prints, per level
(`BENCH_LEVELS=1,3,19` picks some; default 1, 3, 9, 19, 22), the ratio next to zlib level 9
(only-deflate) and libzstd (`zstd -b`, when installed), and compression and decompression speed
next to libzstd's, on TLS 1.3 Certificate messages built from the chains in
`fuzz/corpus/x509_parse`, generated text, JSON and random data, and each file given.

Against the C library in-process (Silesia and HTTP payloads, docs/BENCHMARKS.md):
`tools/codec-bench/corpus.sh` builds the corpus, then
`cargo run --release --manifest-path tools/codec-bench/Cargo.toml zstd FILE...`.

Limitations: no streaming API (the decoder needs the whole input and keeps the whole output,
which is what certificate compression and buffered HTTP bodies need); no dictionaries; no
long-distance matching, optimal parsing or multithreading in the encoder, so its ratios at the
highest levels trail libzstd's; the encoder never emits treeless literals or repeated sequence
tables (the decoder handles both).
