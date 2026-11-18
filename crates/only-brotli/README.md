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
  the output vector (which is also the window) grows geometrically but never past the limit,
  and the prefix code tables are bounded by the format (a few megabytes at most). Reading past
  the end of the input yields zero bits that are counted and checked at least once per literal
  and per command, so truncated input costs no more than its length plus the output.
  A 64-bit bit reader and two-level prefix code tables (8-bit root) do the decoding.
- `compress(level, data)`: levels 0..=11 on brotli's quality scale (`Level::FASTEST` = 1,
  `Level::DEFAULT` = 6, `Level::BEST` = 11). LZ77 over hash chains of the next four bytes:
  greedy at levels 0..=3, lazy matching at 4..=9 (Google's backward reference score, up to four
  steps ahead), and at 10 and 11 a shortest-path parse over all candidate matches priced with
  the symbol costs of a previous pass (one pass at 10, two at 11), long matches taken whole.
  The four distances of the distance ring are always candidates (short codes instead of extra
  bits). Meta-blocks of 1 MiB (256 KiB at levels 10 and 11), one block type per category,
  `NPOSTFIX` = `NDIRECT` = 0; from level 5 literals use a context map: the 64 contexts of each
  context mode (UTF-8 and signed at 5..=6, all four from 7) are clustered greedily by the
  estimated cost of their histograms and the map is kept only when it makes the meta-block
  smaller. Prefix codes are limited to 15 bits, written in the simple form when they have at most
  four symbols, with Google's run-length coding of code lengths; context maps try move-to-front
  and every run-length setting and keep the shortest. A meta-block that would come out larger
  than its bytes is stored. The window is the smallest of 2^16..2^22 that holds the input.

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
allocating more than the limit. Fuzz targets `brotli_decompress` (differential against
`brotli-decompressor`: same verdict, same output) and `brotli_roundtrip` (our output decodes
with both decoders).

Benchmark: `cargo run --release -p only-brotli --example brotli-bench [FILE...]` prints the size,
ratio and compression and decompression throughput at levels 0..=11 (`BENCH_LEVELS=1,6,11`
picks some) on generated text, JSON and random data plus each file given, with the zlib
level 9 size as a baseline and, when `brotli(1)` is installed, its size at the same quality and
its time to decode our stream.

Limitations: decompression is one-shot (the whole stream in, the whole output out, as
certificate compression and buffered HTTP bodies need); there is no streaming decoder or
encoder. The encoder uses one block type per category (no block splitting), no static
dictionary references and no custom dictionaries, so its output is a few percent larger than
Google's at the same quality on text. Prefix codes are stored from the exact code lengths or
from counts smoothed for run-length coding (zopfli's `OptimizeHuffmanForRle`), whichever is
cheaper, which matters for small inputs: on DER certificate chains of a few kilobytes level 11
is 1-3% smaller than zlib level 9 (a lone small leaf about 1% larger) and 2-5% larger than
`brotli -q 11` (a 375-byte leaf: 353 bytes, zlib 348,
`brotli` 352; github.com's chain: 1693, 1719, 1615; wikipedia.org's: 2515, 2589, 2430).
