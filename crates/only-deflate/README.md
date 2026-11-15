# only-deflate

[中文](README.zh-CN.md)

DEFLATE (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952) for [`only`](https://github.com/lesismal/only),
in pure safe Rust (`#![forbid(unsafe_code)]`) without dependencies. It is the compression behind
permessage-deflate in `only-ws`, the compression middleware of `only-http` and gzip messages in
`only-grpc`. An internal crate (docs/api-stability.md): use it through those crates.

- `Inflater`: streaming decompression of raw DEFLATE, zlib and gzip. Input may be split
  anywhere and output taken in pieces of any size; `decompress_vec` takes a size limit (the
  decompression-bomb defence); window sizes 2^8..2^15; `reset` and `reset_keep_window` (context
  takeover across final blocks). The decoder applies zlib's checks to Huffman code descriptions
  (over-subscribed and incomplete codes, repeats, missing end-of-block), so it accepts and
  rejects the same streams; the differential fuzz target checks that against zlib-rs. A fast
  path decodes three literals or a length/distance pair per 64-bit refill and copies matches 8
  or 16 bytes at a time.
- `Deflater`: LZ77 over hash chains of the next four bytes (three at level 9) with the level
  table and match finders of zlib-ng / zlib-rs: `quick` (level 1: one probe per position,
  fixed-code blocks written directly, replaced by stored blocks when those are smaller), `fast`
  (level 2: greedy), `medium` (levels 3..=6: greedy, looking one match ahead from level 5),
  `slow` (levels 7..=9: lazy matching; level 9 walks the chain of whichever string inside the
  current match reaches furthest back). Candidates are compared 8 bytes at a time; level 0 is
  stored. Each block is coded with whichever is smallest of a dynamic Huffman code (lengths
  limited to 15 bits, 7 for the code length code), the fixed code or stored blocks.
  `Flush::Sync` (the `00 00 ff ff` marker), `Flush::Full`, `Flush::Finish`; window sizes
  2^8..2^15 (8 is laid out as 9 with distances of at most 250, so the output is valid for a
  256-byte window); `reset` for no-context-takeover (after a short stream it clears only the
  hash slots that stream used).
- `compress` / `decompress`: one-shot helpers; `Adler32` / `Crc32` (slicing-by-8).

```rust
use only_deflate::{Deflater, Flush, Format, Inflater, Level};

// permessage-deflate style: one stream, a sync flush per message, history kept.
let mut d = Deflater::with_window_bits(Format::Raw, Level::DEFAULT, 15);
let mut inf = Inflater::new(Format::Raw);
for msg in [&b"hello websocket"[..], b"hello websocket again"] {
    let mut wire = Vec::new();
    d.compress(msg, &mut wire, Flush::Sync);
    let mut out = Vec::new();
    inf.decompress_vec(&wire, &mut out, 1 << 20).unwrap();
    assert_eq!(out, msg);
}
```

Tests: round trips over text, binary, incompressible, empty, single-byte and long-period data at
every level, format and window; interop both ways with zlib-rs (through flate2, a dev-dependency)
and with `gzip(1)`; every literal, length and distance through the fixed code; sync-flush
boundaries with context takeover (the class of the miniz_oxide bug Autobahn once found); input
and output split at every size; stored blocks split at every input byte and output size, and
stored blocks longer than the window followed by matches into them; streaming with every level, window size and flush kind;
truncation, bit flips and checksum errors. Fuzz targets `deflate_inflate` (differential against
zlib-rs) and `deflate_roundtrip`. Miri runs the unit tests.

Benchmark: `cargo run --release -p only-deflate --example bench [FILE...]` prints ratio and
throughput against flate2 (zlib-rs) at levels 1..=9 (`BENCH_LEVELS=1,6,9` picks some) on
generated text, JSON and random data plus each file given; the `pmd_echo` example measures a
permessage-deflate echo. On x86-64 the output is as small as zlib-rs's at every level (at most
0.5% larger), compression runs at 0.94-1.48x its speed and decompression at 0.82-1.23x (stored
blocks 0.94x: they are copied straight into the output, and only their last 32 KiB into the
window); see docs/BENCHMARKS.md.
