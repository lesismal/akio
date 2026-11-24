# ADR-116: Body taps, outer response filters and HTTP-dates in all three formats

English | [简体中文](116-body-taps-outer-filters-http-dates.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit's response cache (its iteration I67, fit's `cache` middleware) keeps a response as it goes
to the client, and stores it once all of it has gone: it never holds a response back to store it.
fit does this with fib's body filter, which sees every write of the body. akit asked for three
things (A111, A112, A113), checked against akio main `c5cf4353`:

- **A111.** A response filter sees the head of a streamed response
  (`Context::stream_response`, `Detached::stream_response`) but not its body: the writes go
  straight from `BodyStream::write` to the transport. Nothing could copy a proxied body as it
  passed, nor learn whether it ended whole, cut short (the client went, the stream was dropped) or
  with trailers (akit's proxy ends a body its upstream broke off with one).
- **A112.** A cache reads `Date`, `Expires`, `Last-Modified` and `If-Modified-Since`. RFC 9110
  section 5.6.7 has recipients accept three formats (IMF-fixdate, RFC 850, asctime), as Go's
  `http.ParseTime` does for fit; akio parsed only the first, privately, in `files.rs`.
- **A113.** Filters run in registration order: an outer middleware's filter, registered before
  the handlers it wraps, runs before an inner one's. A cache in front of `compress` would see a
  response before it is compressed and store it unencoded under `Vary: Accept-Encoding` it does
  not yet carry. fit runs its header hooks innermost first; akio's order is relied on by akit's
  middlewares, so it cannot change for everyone.

Constraints: no unsafe, nothing blocks an I/O thread, additive API, nothing added to the cost of a
response that sets none of this.

## Decision

**A111: `Response::tap_body(impl BodyTap)`.**

- `trait BodyTap: Send + 'static { fn data(&mut self, &[u8]); fn end(&mut self, TapEnd); }`
  and `#[non_exhaustive] enum TapEnd { Finished, Trailers, Cut }`.
- Set by a response filter on the head of a streamed response. The stream then shows each write
  to the tap after it went through the stream coding (ADR-112), without the transport's framing:
  the bytes of the representation the head describes, `Content-Encoding` included. A write that
  fails is not shown, and makes the end `Cut`. `end` is called once, last: `Finished` from
  `finish`, `Trailers` from `finish_with_trailers`, `Cut` when the stream is dropped unfinished,
  a write failed, or the stream never started.
- Ignored (dropped unused) on a response that is not streamed, whose filter has the whole `body`,
  and on a HEAD answer.
- The calls come from the thread writing the stream, one at a time: the tap sits behind a mutex
  in the `BodyStream`, as the coder does, so a stream written from several threads is seen in
  order. `Response` carries the tap as one `Option<Arc<Mutex<Option<Box<dyn BodyTap>>>>>` word
  (`Response` stays `Clone` and `UnwindSafe`); `BodyStream` gets one `Option<Box<_>>` word.

**A112: `akio_http::parse_http_date(&str) -> Option<u64>`**, seconds since the Unix epoch, in the
three formats; an RFC 850 two-digit year reads as Go reads it (69 and up in the 1900s, below in
the 2000s). `Files` keeps its own strict IMF-fixdate reading of `If-Modified-Since`.

**A113: `Context::add_outer_response_filter(f)`.** Outer filters run after every ordinary filter,
the last added first: a middleware that adds one before calling what it wraps sees the response as
the middlewares inside left it. They are kept in the filters' overflow vector, marked, so the
inline slots and the size of `Context` and `Detached` do not change; only a request with an outer
filter pays to sort them out when the response goes.

## Consequences

- akit's cache keeps proxied (streamed) and whole responses as they go, encoded as the client got
  them, and stores one only when its body ended `Finished`.
- No cost for a response with no tap and no outer filter: one more `None` word in `Response` and
  in `BodyStream`, and one more `is_empty` check of the filters' vector.
- A tapped stream takes an uncontended lock per write; the tap's own work (a copy) is the
  caller's.
