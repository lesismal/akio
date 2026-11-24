# ADR-112: A stream coding any response filter can set, and compressed copies of cached files

English | [简体中文](112-stream-coding-for-filters-and-compressed-copies.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit, a reverse proxy built on akio, ports fit's `compress` middleware and the `compress` field of
fit's static handler (akit's I47). Its requests A90 and A91 name what akio-http lacked, checked
against akio main `f6750e93`:

- **A90.** The encoder a `BodyStream` runs its writes through (ADR-074) could be chosen only by
  akio's own `compress` middleware: `Response::stream_coding` and `Response::streaming` were
  `pub(crate)`. fit's middleware negotiates differently (q values among the encodings it offers,
  in their order; every status that carries a body but 206; `no-transform`, `Content-Range` and a
  declared length below `min_bytes` left alone; strong `ETag`s made weak), and bounds how many
  responses are compressed at once (`max_in_flight`), so a filter of akit's own must pick the
  coding, and must learn when a compressed stream ends to give its place back.
- **A91.** fit's static handler keeps a file it holds in memory compressed too, with each
  encoding of its `compress` a client asks for, made once on its file pool at a level that makes
  it small and served from then on. akio's `Files` serves compressed twins from disk (ADR-100) but
  made no copies.

Constraints: additive API (`docs/api-stability.md`); nothing new blocks an I/O thread; a response
that uses none of it costs what it did.

## Decision

### A90: `Coding`, `Response::set_stream_coding`, `Response::keep_until_sent`

- **`akio_http::Coding`** (`Copy`): `gzip(level)`, `deflate(level)`, `br(quality, window_bits)`,
  `zstd(level, window_log)`, levels and windows clamped as `StreamCompress`'s are; `name()` gives
  its `Content-Encoding` token. It wraps the 3-byte `StreamCoding` of ADR-074.
- **`Response::is_streaming()`**: whether a filter sees the head of a streamed response.
- **`Response::set_stream_coding(Option<Coding>)`** and **`stream_coding()`**: the coding the
  stream's writes go through, as the `compress` middleware sets it. The filter sets
  `Content-Encoding`, `Vary` and drops `Content-Length` itself; HEAD keeps the fields and encodes
  nothing; ignored on a response that is not streamed.
- **`Response::keep_until_sent(value)`**: keeps `value` until the response is sent: for a
  streamed response until its `BodyStream` is finished or dropped (a client that goes drops it
  with the producer's failed write), else until the response is handed to the connection. A
  filter bounding its responses keeps a guard there and counts the place back in its `Drop`. It
  is one `Option<Arc<_>>` in `Response` (a word, `None` unless set) and one in `BodyStream`; the
  value is wrapped in `AssertUnwindSafe` (never looked at, only dropped) so `Response` stays
  `UnwindSafe`.
- **`middleware::compressible(content_type)`** is public, and takes fonts, icons, BMP and
  `application/ecmascript` as fit's list does; akio's `compress` middleware uses it.

### A91: `Files::compress`

- **`Files::compress(&["br", "zstd", "gzip"])`**: the codings, in order of preference among
  equal q values. A file kept in memory (`max_cached_bytes`), of 1400 bytes or more and of a
  compressible type, gets one slot per coding (`OnceLock<Option<Arc<Cached>>>` and a flag): the
  first request whose best accepted coding has no copy yet starts a job on the disk pool and gets
  the file as it is; once made, the copy is served on the I/O thread to every client that prefers
  it. A copy that saves less than a twentieth is not kept (the slot remembers it, and the coding
  drops out of the choice). A job the pool refuses clears the flag for a later request.
- Levels: gzip 9, brotli 9, zstd 19, windows no larger than the file. A copy has its own `ETag`
  (the file's with `-coding` added), `Content-Encoding`, no `Accept-Ranges`; a ranged request is
  answered from the file; a twin on disk goes ahead of a copy; every answer about a file says
  `Vary: Accept-Encoding` when `compress` is set. The copies live with the file's entry and go
  when it is replaced (the file changed or was evicted).

## Not done

- A file body sent from disk (`Response::file`, files above `max_cached_bytes`) is not encoded:
  a coding would need the file read in pieces on the disk pool and encoded there, with the
  stream's backpressure (akit's A92).
- The copies are not counted against a total memory bound: `Files` has none yet (akit's A15).
  Each copy is smaller than its file, and there are at most three per file.

## Consequences

- akit's `compress` middleware compresses streamed (proxied) responses and memory bodies as fit's
  does, with its own negotiation and bound; its `static` handler takes `compress`.
- No hot-path change for responses that set nothing: one more `None` word in `Response`, and the
  file serving path checks an empty slice.
