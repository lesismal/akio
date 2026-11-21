# only-brotli

[中文](README.zh-CN.md)

Brotli (RFC 7932) for [`only`](https://github.com/lesismal/only), in pure safe Rust
(`#![forbid(unsafe_code)]`) without dependencies. It is the `br` content coding of the
compression middleware in `only-http` and the brotli algorithm of TLS certificate compression
(RFC 8879) in `only-tls`. An internal crate (docs/api-stability.md): use it through those crates.

- `decompress(data, limit)`: one-shot decompression of one complete brotli stream into at most
  `limit` bytes. The whole format is implemented: window sizes 2^10..2^24 (the non-standard
  large-window extension is refused), empty, metadata (skipped) and uncompressed meta-blocks,
  simple and complex prefix codes, block types and block counts for literals, commands and
  distances, the four literal context modes, context maps with run lengths and inverse
  move-to-front, `NPOSTFIX` / `NDIRECT` distance codes, the four-entry distance ring with its 16
  short codes, and the static dictionary (122,784 bytes, Google's `dictionary.bin` of v1.1.0,
  checked against RFC 7932 Appendix A) with all 121 transforms. It accepts and rejects the same
  streams as `brotli-decompressor`, the Rust port of Google's decoder (padding bits that must be
  zero, superfluous length nibbles, reserved bits, over-subscribed or incomplete prefix codes,
  repeated simple-code symbols, context map runs and repeats past the end, invalid distances and
  dictionary references); data after the end of the stream is an error (`TrailingData`).
  Where `brotli-decompressor` 5 departs from Google's C decoder v1.1.0 this crate follows the C
  decoder: a meta-block whose commands produce more bytes than its header declares is refused
  (`BadBlockLength`) in every meta-block, not only the last.
  Hostile input cannot make it panic or allocate beyond `limit`: every insert, copy and
  dictionary word is checked against the meta-block length and the limit before it is written,
  the output vector (which is also the window, zeroed up to 128 KiB ahead so that matches can be
  copied in 16-byte chunks) grows geometrically but never past the limit,
  and the prefix code tables are bounded by the format (a few megabytes at most). Reading past
  the end of the input yields zero bits that are counted and checked at least once per command,
  so truncated input costs no more than its length plus the output.
  A 64-bit bit reader (refilled without branching on the bits left, three literals per refill)
  and two-level prefix code tables (8-bit root) do the decoding; literals of a block type whose
  context map has one tree skip the context computation.
- `compress(level, data)`: levels 0..=11 on brotli's quality scale (`Level::FASTEST` = 1,
  `Level::DEFAULT` = 6, `Level::BEST` = 11). LZ77 with Google's match finders: at levels
  0..=6 a bucket per hash holding its last 1, 2, 2, 4, 4, 16 or 32 positions (Google's `H2`..`H6`;
  hashes of the next four bytes, five at levels 5 and 6), at 7..=11 hash chains; greedy at levels
  0..=3, lazy matching at 4..=9 (Google's backward reference score, up to four steps ahead), and
  at 10 and 11 a shortest-path parse over all candidate matches priced with the symbol costs of
  a previous pass (one pass at 10, two at 11), long matches taken whole; there the static
  dictionary's words are candidates too: the words are indexed by their first four bytes in
  lower case, and at each position the input is looked up after each transform prefix it starts
  with and checked against the identity, uppercase (first or all, ASCII) and omit-last
  transforms with their suffixes, the cheapest address kept per length (a reference leaves the
  distance ring alone, as the decoder does). Below level 10, after
  64 literals without a match only every second position is looked at, after 320 every fourth
  (Google's heuristic for data that does not compress). The four distances of the distance ring
  are always candidates (short codes instead of extra bits). Meta-blocks of 1 MiB (at levels
  10 and 11 up to twice the window, parsed in blocks of 256 KiB, and ending early at an eighth
  of that in literals or commands, as Google's are; 256 KiB when streaming), `NPOSTFIX` =
  `NDIRECT` = 0; from level 5 literals use a context map: the 64 contexts of each context mode
  (UTF-8 and signed at 5..=6, all four from 7) are clustered greedily by the estimated cost of
  their histograms (contexts with fewer than 32 literals start out as one cluster; below level
  10 a meta-block needs 4096 literals for this) and the map is kept when the estimate says it
  pays. Block splitting from level 4: literals, insert-and-copy symbols and distances get block
  types and block switch commands. Levels 4..=9 split meta-blocks of 64 KiB or more in one pass
  like Google's greedy `BlockSplitter` (a block of 512 or 1024 symbols gets a new type when
  coding it with either of the last two types would cost a threshold more bits), each literal
  block type coding the context map's clusters with codes of its own where that pays and with
  codes shared by all types elsewhere; the types are kept only when the estimate says they save
  at least 1% of the meta-block (block switches cost time to write: JSON and HTML stay
  unsplit, mixed or binary data is split). Levels 10 and 11 split meta-blocks of 8 KiB or more
  like Google's `block_splitter`: histograms seeded from
  samples, three (10) or ten (11) rounds of a cheapest-path assignment of symbols to histograms
  with a block switch cost, then the blocks clustered into at most 256 types; each literal block
  type takes its cheapest context mode, and the contexts of all literal block types (4 distance
  contexts per distance block type) are clustered into one context map with Google's
  histogram-cost clustering. At 10 and 11 the meta-block is written with one literal code, with
  the context map and with block types, and the smallest is kept. Level 11's second parse pass
  prices each literal by the histogram of the literal block type its position falls in after
  splitting the first pass's literals, so the parse fits the blocks it is coded with. Prefix codes are limited to
  15 bits, written in the simple form when they have at most
  four symbols, with Google's run-length coding of code lengths; context maps try move-to-front
  and every run-length setting and keep the shortest. A meta-block that would come out larger
  than its bytes is stored. The window is the smallest of 2^16..2^22 that holds the input.

- `Compressor` / `Decompressor`: streaming. The compressor takes input in pieces and writes a
  meta-block at a time; `Flush::Flush` ends the meta-block and pads to a byte boundary with an
  empty metadata block (as Google's `BROTLI_OPERATION_FLUSH`), `Flush::Finish` ends the stream
  (a stream whose input all arrived before anything was written is the one `compress` writes).
  Streamed output has a window of 2^22 bytes (`window_bits(10..=24)`), and the compressor's
  buffer slides, keeping the window. The decompressor takes the stream in pieces of any size and
  decodes it with the one-shot decoder's code, resumed where the input ran out at the last
  complete unit: a command, or a part of a meta-block header (a block type description, a
  context map entry, a prefix code). A unit that used bits past the input is undone (output,
  bit position, distance ring and block switching state go back to the unit's start) and taken
  again with more input, so input split anywhere, a byte at a time included, costs little more
  than whole input. Output is decoded at most 1 MiB ahead of delivery, under a size limit
  (`decompress_vec`) or into a slice (`decompress`), and the window slides once it holds twice
  the stream's window; `max_window_bits` refuses larger windows (`Error::WindowTooLarge`).
  Memory is bounded whatever the input: the window up to twice over, 1 MiB of output, the
  meta-block's prefix codes and the input of one unit.
- `compress_with_dictionary` / `decompress_with_dictionary` (and `with_dictionary` on the
  streaming types): raw (LZ77 prefix) dictionaries, as `brotli -D` and Google's
  `BrotliDecoderAttachDictionary(BROTLI_SHARED_DICTIONARY_RAW, ...)` use them: a distance just
  beyond the window's reach (the output so far while it is shorter than the window) copies from
  the dictionary as if it preceded the output, the copy staying within it, and static
  dictionary addresses start after it. The encoder takes dictionary positions as match
  candidates while the output is within the window.

```rust
use only_brotli::{Level, compress, decompress};

let data = b"the quick brown fox jumps over the lazy dog; ".repeat(100);
let packed = compress(Level::DEFAULT, &data);
assert_eq!(decompress(&packed, data.len()).unwrap(), data);
```

Tests: Google's test vectors (a subset of `tests/testdata` of brotli v1.1.0 is committed under
`tests/data`, decoded and compared by length and FNV-1a hash; `BROTLI_TESTDATA=<dir>` runs all
of them); `brotli(1)` in both directions when it is installed (its output at every quality
0..=11, windows 2^10..2^24 and distances of several MiB decodes with ours; ours at every level
decodes with `brotli -d`); round trips at every level on text, JSON, binary, random,
low-entropy, long-period and mixed data, the empty input and every length up to 300; DER
certificate chains at level 11 no larger than zlib level 9 (only-deflate); every prefix of a
stream, every single-bit flip and random junk (an error, never a panic); exact limits; streams
made by hand for every window size, metadata, uncompressed meta-blocks, bad headers and
padding, dictionary words and transforms, invalid dictionary references and distances; and a
decompression bomb (817 bytes that would expand to 1 GiB) refused with `TooLarge` without
allocating more than the limit. Streaming and dictionaries (`tests/stream.rs`): streamed
output at levels 0..=11, several piece sizes and flush modes decodes with both decoders, fed
whole, in pieces and a byte at a time; windows of 1 KiB to 256 KiB with sliding buffers; every
flush makes everything so far decodable; output limits, slices, truncation, trailing bytes;
every truncation and bit flip of a stream gives the same verdict streamed (in 3-byte pieces) as
one-shot; raw dictionaries at every level, within and beyond the window; and with `brotli(1)`:
our streams decode with `brotli -d`, its streams at qualities 0..=11 and windows 2^16 and 2^24
decode streamed, and dictionary streams decode both ways with `-D`. Fuzz targets
`brotli_decompress` (differential against `brotli-decompressor`: same verdict, same output),
`brotli_roundtrip` (our output decodes with both decoders), `brotli_stream` (the streaming
decoder in pieces agrees with the one-shot decoder, with and without a raw dictionary) and
`brotli_stream_roundtrip` (the streaming compressor with piece sizes, flushes, windows and
dictionaries from the input: everything decodable after each flush, both decoders and
`brotli-decompressor` give the input back).

Benchmark: `cargo run --release -p only-brotli --example brotli-bench [FILE...]` prints the size,
ratio and compression and decompression throughput at levels 0..=11 (`BENCH_LEVELS=1,6,11`
picks some) on generated text, JSON and random data plus each file given, with the zlib
level 9 size as a baseline and, when `brotli(1)` is installed, its size at the same quality and
its time to decode our stream.

Against the C library in-process (Silesia and HTTP payloads, docs/BENCHMARKS.md):
`tools/codec-bench/corpus.sh` builds the corpus, then
`cargo run --release --manifest-path tools/codec-bench/Cargo.toml brotli FILE...`.

Limitations: the encoder searches the static dictionary only at levels 10 and 11 and not under
the omit-first transforms, always uses `NPOSTFIX` = `NDIRECT` = 0, and supports raw
dictionaries only, not the serialized shared dictionaries of RFC 9841 (custom word lists and
transforms), which Google's CLI does not offer either. Its output at level 11 is 0.9-1.3%
larger than Google's on the HTTP payloads of the benchmark corpus and 4.5% smaller on its
Silesia part (docs/BENCHMARKS.md, "Brotli block splitting"). Prefix codes are stored from the exact code lengths or from
counts smoothed for run-length coding (zopfli's `OptimizeHuffmanForRle`), whichever is cheaper,
which matters for small inputs: on DER certificate chains of a few kilobytes level 11 is 4-5%
smaller than zlib level 9 and 1-1.5% larger than `brotli -q 11` (github.com's chain: 1640, zlib
1719, `brotli` 1615; wikipedia.org's: 2454, 2589, 2430).
