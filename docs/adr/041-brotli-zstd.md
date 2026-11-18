# ADR-041: In-house brotli and Zstandard, in certificate compression and HTTP

English | [简体中文](041-brotli-zstd.zh-CN.md)

Status: accepted (2026-11-19)

## Context

`only-tls` compressed certificates (RFC 8879) with zlib only, through `only-deflate`, because
there was no in-house brotli or zstd and the workspace takes no third-party library
dependencies. Browsers and CDNs prefer the other two: Chrome offers only brotli, Firefox offers
zlib, brotli and zstd, and Cloudflare-style servers send brotli. A client that offers zlib alone
gets uncompressed chains from servers that only do brotli, and a server that only does zlib
sends Chrome its chain uncompressed. The same holds for HTTP: `only-http`'s compression
middleware answered `gzip` / `deflate` only, and its static files served `.br` and `.gz` twins
but no `.zst`.

## Decision

1. **Two new internal crates**, organised like `only-deflate` (pure safe Rust, no
   dependencies, `#![forbid(unsafe_code)]`, a `fuzzing` feature for `fuzz/`, an
   `examples/bench.rs`, CLI interop tests that skip when the tool is missing), in the
   "Internal" tier of docs/api-stability.md:
   - **`only-brotli`** (RFC 7932): `decompress(data, limit)` (the complete format: window
     sizes 2^10..2^24, uncompressed and metadata meta-blocks, simple and complex prefix codes,
     block switching, the four context modes and context maps, NPOSTFIX/NDIRECT distances, the
     static dictionary with its 121 transforms) and `compress(Level, data)` (LZ77 over hash
     chains, Huffman codes per meta-block, uncompressed meta-blocks when smaller); `Level` on
     brotli's quality scale 0..=11.
   - **`only-zstd`** (RFC 8878): `decompress(data, limit)` (concatenated and skippable frames,
     raw / RLE / compressed blocks, raw / RLE / Huffman / treeless literals with 1 or 4
     streams, predefined / RLE / FSE / repeat sequence tables, repeat offsets, the XXH64
     content checksum and content size checked) and `compress(Level, data)` (one frame with
     content size and checksum, LZ77 over hash chains, Huffman literals, FSE or predefined
     sequence tables, raw / RLE blocks when smaller); `Level` on zstd's scale 1..=22.
   - One-shot APIs only: the output is the window, so memory is bounded by `limit` (no
     allocation follows a size the input declares beyond it) and work is linear in input plus
     output; a decompression bomb stops at `limit` with `Error::TooLarge`. Dictionaries (zstd
     `Dictionary_ID`, brotli's shared dictionaries) and streaming are not implemented: nothing
     in the workspace needs them yet.
2. **`only-tls`** offers and accepts brotli, zstd and zlib (in that order in the
   `compress_certificate` extension). A server compresses its chain with every algorithm the
   client offers that it has on, once per certificate and algorithm (cached, as zlib was), and
   sends the smallest, or the plain Certificate when none is smaller; the client does the same
   for its certificate with the algorithms of the CertificateRequest. Additive public API:
   `CertCompression { Zlib, Brotli, Zstd }` (`#[non_exhaustive]`, with `id()`), and
   `certificate_compression_algorithms(&[CertCompression])` on both builders
   (`certificate_compression(true)` means all three; defaults unchanged: on for servers, off
   for clients). Received chains are still decompressed into at most 128 KiB and must have
   exactly the announced length; an algorithm not offered is `illegal_parameter`.
3. **`only-http`**, additive: `Compress::brotli` and `Compress::zstd` (`Option` levels,
   default `None`) make the compression middleware answer `br` or `zstd` to clients that
   accept them, in the order br, zstd, gzip, deflate; with both `None` it behaves as before.
   `Files` also serves `file.zst` twins (`Content-Encoding: zstd`), between `.br` and `.gz` in
   preference.

## Consequences

- Clients with compression on (`certificate_compression(true)`) receive compressed chains
  from servers that do only brotli or zstd; servers save the most bytes each client allows.
  The first handshake per certificate and algorithm pays the compression once.
- Tests: all 44 streams of brotli's `tests/testdata` (23 committed); zstd's
  golden-decompression (4), golden-decompression-errors (3, rejected) and golden-compression
  files, and 1000 `decodecorpus` frames; the `brotli` and `zstd` CLIs both ways (every level,
  window sizes, small blocks, no checksum or content size, concatenated and skippable frames);
  round trips, every truncation and bit flip, limits and bombs (an 817-byte brotli stream
  expanding to 1 GiB stops at the limit with allocations bounded by it). In only-tls: every
  algorithm alone and all together, the smallest picked, no common algorithm, malformed
  messages at every byte and length; in only-http: the encoding chosen for Chrome's and
  Firefox's `Accept-Encoding`, `q=0`, `.zst` twins.
- Interop (`tools/interop/tls/run.sh` in `tools/interop/tls/certcomp.Dockerfile`, OpenSSL 3.5.4
  built with brotli, zstd and zlib): server and client certificates compressed with each
  algorithm in both directions, and OpenSSL's client offering all three: 151 of 151 cases on
  gpu51 (x86-64).
- Fuzzing: `brotli_decompress` and `zstd_decompress` are differential (Google's decoder as
  `brotli-decompressor` with the large-window extension off; libzstd 1.5.7 without legacy
  frames), tolerating only where ours is stricter: a meta-block whose commands overrun its
  declared length (the C decoder rejects it too), Huffman literal streams not ending where
  their symbols do, a block larger than Block_Maximum_Size. 961 s each on gpu51 without a
  failure: 0.97M, 6.6M inputs; `brotli_roundtrip` 38k (36k more after the last encoder change) and `zstd_roundtrip` 2.3M.
- Performance (Apple M-series, report, not a gate): decoding runs at 0.55-0.75x the `brotli`
  CLI on text (faster on JSON) and 0.35-0.5x libzstd; a certificate chain of 2.7-4 KB decodes in
  2.5-7 µs (zstd), 7-10 µs (zlib), 16-25 µs (brotli). Compressing it once at the best level takes
  0.1 ms (zstd) to 0.4-3 ms (brotli). Ratios on chains of a few KB: brotli 11 is 1-3% smaller
  than zlib 9 (2-5% larger than `brotli -q 11`), zstd 22 within 1% of zlib 9 (1.5% larger than
  libzstd -19); a lone 375-byte leaf compresses to 353 bytes (brotli), 357 (zstd), 348 (zlib).
- Two more crates to maintain. The encoders aim at correctness and a ratio at least as good as
  zlib's at its best level on certificate chains, not at the reference encoders' ratios
  (no context modeling search, no optimal parsing): they are used once per certificate, and
  for HTTP bodies only when an application turns them on.
