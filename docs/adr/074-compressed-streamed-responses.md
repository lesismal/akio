# ADR-074: Compressed streamed responses in only-http

English | [简体中文](074-compressed-streamed-responses.zh-CN.md)

Status: accepted (2026-11-21), updated 2026-11-22

## Context

The `compress` middleware compresses buffered responses whole, with the one-shot encoders of
only-deflate, only-brotli and only-zstd: best ratio, `Content-Length` known. Streamed responses
(`Context::stream_response`: server-sent events, large generated downloads) went out as written
with every coding (ADR-069 section 4). Their heads did pass through the response filters, but
the compress filter skipped them because their body was empty. ADR-069 gave both crates
streaming encoders (`Compressor::compress(input, &mut out, Flush)`) and left the HTTP side
for later. Constraints:

- an event must reach the client when it is written: an encoder that holds output back until a
  block fills breaks server-sent events, chat and progress streams;
- a stream keeps its encoder (window and match tables) for as long as it is open, and an
  event stream may stay open for hours on thousands of connections, so memory per stream
  matters more than ratio;
- buffered responses and existing configurations must not change;
- `BodyStream::write` takes `&self` and may be called from any thread.

## Decision

### 1. An opt-in switch, the same negotiation

`Compress` gets `stream: Option<StreamCompress>`, `None` by default: streamed responses stay
uncompressed unless the application asks. The coding is negotiated from `Accept-Encoding` as for
buffered responses, among the same encodings (`br` and `zstd` only when `Compress::brotli` /
`Compress::zstd` offer them, then `gzip`, `deflate`), and the same responses qualify: status 200,
a compressible `Content-Type` (text, JSON, JavaScript, XML, SVG, wasm; `text/event-stream`
included), no `Content-Encoding` already (an encoded body is left alone). `min_bytes` does not
apply, the length not being known. A compressed stream loses a `Content-Length` the handler gave
and gets `Content-Encoding` and `Vary: Accept-Encoding`. A HEAD answer gets the same head and no
encoder.

### 2. Where the encoder sits

The compress filter already runs on the streamed head (`Finish::apply` in `start_stream`). It
now recognises the head (`Response::streaming`), and instead of compressing a body it records the
chosen coding in a crate-private `Response::stream_coding`, a 3-byte `Copy` enum (coding, level,
window) that fits in `Response`'s padding, so no response grows and `Response` stays `Clone`.
`start_stream` takes it after the filters ran and before the head is encoded, and the
`BodyStream` gets an encoder, `Option<Box<Mutex<StreamEncoder>>>`: `None` for every stream that
is not compressed, which then writes as before. One encoder per stream, created in a few
nanoseconds (the encoders allocate their window and tables on the first data). Because
`write(&self)` may be called from several threads, the mutex covers encoding and handing the
output to the transport together, so the output is written in the order it was encoded.
The encoder sits above the transport, so HTTP/1.1 chunked, HTTP/1.0 close-delimited, HTTP/2
and HTTP/3 (`transport::BodySink`) streams are all covered.

### 3. A flush per write

Every `write` compresses its bytes and flushes: gzip and deflate with a sync flush (an empty
stored block, `00 00 FF FF`), zstd with `Flush::Flush` (the pending input as a block), brotli
with `Flush::Flush` (the meta-block ended and padded with an empty metadata block). Whatever
was written can then be decoded from what was sent, so each write still goes out as one chunk or
DATA frame and arrives unbuffered. `finish` and `finish_with_trailers` write the end of the
stream (`Finish`) before the transport's end. A write per event is what event sources do, so
the flush is not configurable: a producer that wants bigger blocks writes bigger pieces. The
cost is a few bytes per write (the 4-byte sync marker and a block header for deflate, a 3-byte
block header for zstd, a meta-block header and an empty metadata block for brotli). The output goes through a buffer kept by the
encoder, dropped after a write that grew it past 64 KiB, so an idle stream holds its window
and tables but not its largest write.

### 4. Small defaults

`StreamCompress::default()`: gzip and deflate at level 1, zstd at level 1 with a 128 KiB window
(`window_log` 17), brotli at quality 4 with a 256 KiB window (`window_bits` 18). All five are
settings. Measured with a counting allocator on a stream of 90-byte JSON events (30,000 events,
past every window), per stream:

| Coding | Memory after 3 events | Steady state | Size / input |
|---|---:|---:|---:|
| gzip 1 | 320 KiB | 320 KiB | 0.216 |
| gzip 6 | 320 KiB | 320 KiB | 0.200 |
| zstd 1, window 17 / 18 / 19 | 128 KiB | 476 / 824 / 1520 KiB | 0.176 / 0.175 / 0.177 |
| zstd 3, window 17 | 768 KiB | 1116 KiB | 0.177 |
| brotli 1, window 18 | 384 KiB | 1080 KiB | 0.198 |
| brotli 4, window 18 / 19 / 20 | 640 KiB | 1336 / 2032 / 3424 KiB | 0.164 |
| brotli 5, window 18 | 2176 KiB | 2872 KiB | 0.160 |

The match tables are sized by level, the buffers by window: on small events the larger windows
and levels buy nothing, zstd 3 and brotli 5 cost two to four times the memory of zstd 1 and
brotli 4, gzip 1 costs a quarter of gzip 6's CPU for 0.016 of ratio, and brotli quality 0-5 all
spend about the same time on a 16-event stream. Hence the defaults.

### 5. only-brotli slides at two windows

The brotli encoder slid its buffer once it held a window plus a meta-block (1 MiB) behind the
current position, so a 256 KiB window still kept up to 1.3 MiB of input: brotli 4 took
2,032 KiB per stream with window bits 18 and 3,424 KiB with 19 or 20. It now slides once it holds two
windows, as the zstd encoder does: the copy is still amortized over a window of input (the drop
is a multiple of the window, the chain table's size), the output is unchanged (a smaller buffer
holds the same window), and brotli 4 with window 18 went from 2,032 to 1,336 KiB per stream.

## Consequences

- Additive API: `Compress::stream`, `StreamCompress` (`level`, `brotli`, `brotli_window_bits`,
  `zstd`, `zstd_window_log`, `#[non_exhaustive]`, `Default`). `BodyStream`'s private field is
  now named (the snapshot shows `BodyStream` instead of `BodyStream(_)`). Nothing changes for
  buffered responses or with `stream` unset.
- `ETag` no longer tags streamed responses: the etag filter saw their empty body and gave every
  streamed 200 the tag of an empty body (and could answer one `304`).
- `Context::stream_response`'s documentation said response filters do not apply to streamed
  responses; they see the head, and now say so.
- Tests: every coding over HTTP/1.1 chunked (300 events and three 256 KiB writes, decoded with
  our streaming decoders and with `gzip -d`, `brotli -d`, `zstd -d`, flate2 for deflate), an
  HTTP/1.0 close-delimited stream, server-sent events in lock step over HTTP/1.1 and HTTP/2
  (the server writes the next event only after the client has decoded the previous one from
  what it received; with the zstd flush turned off the test stalls and fails), and what stays
  as written (no switch, encoded bodies, binary types, other statuses, no accepted coding, HEAD,
  no ETag).
- Measured on the quiet host (`tools/bench/stream-compress.sh`, `stream-bench` example), see
  docs/BENCHMARKS.md "Compressed streamed responses": a
  same-run A/B against main on gpu51. With `stream` unset streamed responses run at
  main's speed (16 small events per response 0.999x, 16 x 16 KiB 1.011x); compressed, the
  server's CPU is the limit: 6 / 27 / 110 us more per 16-event response for gzip / zstd / br
  (17 us uncompressed), 0.93 / 0.54 / 0.16 GB/s of HTML per core, event bytes down to 35% / 34% /
  26%, HTML to 18% / 6.1% / 5.4%. Server RSS per held stream (1,000 streams) 148 / 112 /
  424 KiB after 3 events and 268 / 324 / 1,106 KiB after 6,000, against 1.2-2.6 KiB uncompressed.
- Not done: brotli's cost per flushed write, about 3 us for an 80-byte event (zstd 0.27 us), from
  the meta-block header and prefix codes written for every meta-block, and its setup of about
  70 us per stream; match tables sized by window rather than by level (libzstd's
  `ZSTD_adjustCParams`), which would shrink small-window streams further; compressing
  streamed requests on the client.

## Update (2026-11-22): brotli's fixed costs per write and per stream

The first two items of "Not done" above. Profiled on gpu51 (perf, quality 4, window bits 18):
a flushed write of an 87-byte event took 3.95 us, two thirds of it building and storing the
meta-block's three prefix codes (alphabets of 256, 704 and 64 symbols, of which an event uses a
few dozen, a handful and one or two): passes over the whole alphabet that updated a counter in
memory per symbol (a store-to-load dependency per symbol, mostly on the counter of length 0),
the code lengths run-length coded three times for the choice between exact and smoothed
lengths, and about 50 allocations. Setting up a stream (one event and the end) took 13 us, 40%
of it clearing 640 KiB of bucket tables, sized by level whatever the window and the data.

Decision, in only-brotli's encoder (the decoder and the API are unchanged):

1. **Prefix codes in time mostly proportional to the symbols used.** Histograms are scanned
   16 entries at a time (an OR the compiler vectorizes) for the used symbols; Huffman depths
   are built from those alone, on the stack for up to 64 symbols; canonical codes are assigned
   to used symbols only, packed with their lengths (`code << 4 | length`, one load per symbol
   written); a complex code's run-length tokens and code length code are prepared once
   (`Complex`), priced in closed form and written from the same preparation; the smoothed
   alternative is skipped when smoothing changed no count (it would give the same lengths).
   The choices are the same, so the output of `compress` is **bit for bit the same at every
   level** (hashes of every level's output over the test vectors and generated corpora
   compared before and after): level 11 and Silesia sizes cannot change.
2. **Stream tables that grow with the stream, sized by window.** A stream's match tables
   start as those of an empty input (2^8 buckets, or 2^10 hashes and a 1 KiB chain: a few
   KiB) and are sized before each meta-block for the data the stream holds, as `compress`
   sizes them for its input (about two entries per byte, at most the level's): for up to the
   reach (the window, or two with a raw dictionary), not three windows as before, since a match
   never reaches further. Growing takes room for fourfold growth, and the full size once the
   stream holds a sixteenth of the reach, so a response written in 16 KiB pieces gets its final
   tables with its first piece and an event stream rebuilds a few times in its first kilobytes.
   A rebuild enters the buffered positions again (from the reach back); a hash chain that only
   grows longer moves its links to their new slots instead. Streams' output changes slightly
   (smaller tables while the stream is short, as for a short one-shot input, and the window
   bound at small windows): +0.00 to +0.11% on the round-trip corpus with windows 2^16..2^22,
   and the same bytes as before on the HTTP benchmark's events and HTML.

Measured (same-run A/B against main `7e4db2d9` on gpu51 under `quiet.sh`; docs/BENCHMARKS.md
"Brotli streaming encoder: fixed costs"). `stream-cost` example, quality 4, window 18, CPU 2:
4.03 → 1.96 us per flushed 87-byte event (49 → 32 allocations), 13.5 → 5.3 us per one-event
stream, 119 → 58 us per 16-event response, 641 → 6 KiB allocated after 3 events (1,297 KiB in
steady state, unchanged), HTML in flushed 16 KiB writes +8.6%. Quality 1 and 5 alike (5: setup
27 → 5.6 us, 2,177 → 18 KiB after 3 events); at quality 9, responses of 16 KiB pieces are 5-8%
slower in this build, the time being the unchanged chain search at another code alignment (same
machine code and instruction count, more branch misses; equal when run on another CPU). Over HTTP (`stream-bench`, the defaults): br
server CPU per 16-event server-sent-events response 123.5 → 67.5 us (17 us uncompressed, zstd
43 us), responses per second 1.83x; 16 x 16 KiB HTML responses 1,695 → 1,576 us (-7%,
0.155 → 0.166 GB/s per core); server RSS per held stream 424 → 9 KiB after 3 events and about the
same after 6,000 (1,007-1,147 KiB before, 1,112-1,165 after, across two runs; the allocated
size is the same). Fuzzing: `brotli_roundtrip` and `brotli_stream_roundtrip` 10 minutes each,
no failure. New tests: small flushed writes at levels 0..=11 with windows that slide and do not
decode after every flush with both decoders and `brotli -d` (the stream so far plus the byte
`Finish` adds); the tables grow as described.

Still not done: brotli's write still costs about 7 times zstd's (2 us against 0.27 us), the
three prefix codes per meta-block being inherent to the format (a cheaper code at high event
rates would be a static or reused code chosen by cost, as Google's encoder does at quality
0..2); at quality 9 a flushed event costs 8 us, mostly the chain search, and at 10..11
83 us (optimal parsing), so they stay unsuited to event streams.
