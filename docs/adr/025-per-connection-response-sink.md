# ADR-025: Per-connection response sinks and reused request targets

English | [简体中文](025-per-connection-response-sink.zh-CN.md)

Status: accepted (2026-11-18)

## Context

After the HTTP/3 allocation pass (CHANGELOG "fewer allocations per HTTP/3 request") two
allocations per request were left that looked like they needed a public API change:

- **The boxed response sink.** `akio_http::transport::dispatch(service, req, sink)` takes a
  `Box<dyn ResponseSink>` whose `send(self: Box<Self>, ..)` consumes it. akio-h3 boxed a `Sink`
  (the connection, the queue of responses waiting for room, the QPACK encoder, the stream id)
  for every request, cloning three `Arc`s into it.
- **The request target.** `Request::target` is a `String`, allocated for every request on
  HTTP/1.1, HTTP/2 and HTTP/3.

At `quic-bench h3` (both ends in one process) main ab65d376 makes 11.0 allocator calls per
request; the HTTP/1.1 server 6.0, h2c 6.5.

## Decision

1. **A sink per connection, a tag per request.** `akio_http::transport` gains
   `trait ConnSink: Send + Sync + 'static { fn send(&self, tag: u64, resp: Response);
   fn start_stream(&self, tag: u64, resp: Response) -> Option<Box<dyn BodySink>>; }`, the handle
   `SharedSink` (`SharedSink::new(sink)`, `Clone`, `get()`), and
   `dispatch_conn(service, req, &SharedSink, tag: u64)` /
   `start_conn(service, req, &SharedSink, tag) -> Started`. The transport keeps one sink per
   connection and tells requests apart by a tag of its choosing. A request's way back is then one
   uncontended reference count increment on a per-connection object, where it used to be a box and
   three clones. akio-h3's tag is the request stream's index shifted left by one, with the HEAD
   flag in bit 0. When akio-h3's QPACK encoder starts (after the peer's SETTINGS), the connection
   gets a new sink that carries it. Requests already dispatched keep the old sink and encode with
   the static table, which is always valid.
2. **`SharedSink` is a thin pointer** (`Arc<Box<dyn ConnSink>>`). The responder `Context` stores
   inline is then 16 bytes, the same as the boxed sink it replaces. A fat `Arc<dyn ConnSink>`
   plus the tag took 24 bytes and grew `Context` from 648 to 656 bytes. HTTP/2 boxes a `Context`
   per request, so h2c paid about 1% of server cycles per request (measured). A unit test keeps
   `Option<Out>` at 24 bytes.
3. **Target buffers are reused per thread; `Request::target` stays a `String`.** When a handler
   is done with a request it did not keep (no `detach`, no WebSocket upgrade), its target buffer
   is emptied and becomes the thread's spare (`thread_local`). The next request parsed on that
   thread writes its target into the spare: HTTP/1.1 (`parse_head`), HTTP/2 (`build_request`)
   and HTTP/3 (akio-h3 through `transport::request_target(&str) -> String`). A buffer larger
   than 1 KiB is not kept.
4. **The boxed API stays, deprecated.** `ResponseSink`, `dispatch` and `start` keep working; the
   boxed sink is adapted into a `SharedSink`, one more allocation on that path only. They are
   marked `#[deprecated(since = "1.0.0-rc.2")]` and can be removed at 2.0.

### Alternatives considered

- **Keeping the spare target per connection** (a field in the HTTP/1 `Session`, the HTTP/2
  connection core and akio-h3's `ServerConn`). This was the first version. On h2c it removed
  127 instructions per request but added about 100 cycles and 3.4 L1d misses. The cause is the
  interleaving: with 16 connections on a thread, a connection's buffer is cold by the time its
  next request comes. Kept per thread, the buffer is reused as the allocator's LIFO free list
  would reuse it, while it is still in cache. The per-thread version is also simpler: no fields,
  and no hand-over across the HTTP/2 core lock.
- **An inline or shared `Target` type** for `Request::target` (a 23-byte small string, or a
  span in a shared head buffer, with `&str` accessors). Rejected because it changes the field's
  type. `req.target.clone()` into a `String`, `push_str` and matching on `String` would stop
  compiling; akio-socks and the logger middleware do this in the workspace. A small string also
  needs `unsafe` (`from_utf8_unchecked`) or a UTF-8 check per access, in a crate that forbids
  `unsafe`, and it covers only short targets, while the reused buffer covers every length. A
  span in `Headers`' buffer breaks when a handler replaces `req.headers`.
- **Pooling the boxed `Sink` inside akio-h3** (the box goes back to a per-connection free list
  in `send`). No API change, but detached responses are sent from other threads, so the list
  needs a lock, and the three `Arc` clones per request stay.
- **Recycling the whole `Request`** (headers buffer, body) the same way. Possible later; out
  of scope here. (Done for the header storage, of requests and responses, in ADR-081.)

## Consequences

- Allocator calls per request (malloc, calloc, realloc and posix_memalign, counted with
  bpftrace uprobes on gpu51, x86_64): `quic-bench h3` both ends 11.0 → 9.0; HTTP/1.1 server
  6.0 → 5.0, pipelined 6.0 → 5.0, h2c 6.5 → 5.5.
- Same-run A/B on gpu51 under `quiet.sh`:
  - HTTP/3 1.0059× (two runs of 7 alternating rounds: 1.0087× and 1.0032×).
  - Server user-space cycles per request (`perf stat`, medians of 7): HTTP/1.1 0.951×,
    pipelined 0.968×, h2c 0.973×.
  - User-space instructions per request −1.2% to −1.4% in all three.
- These requests still allocate their own target: those whose handler detaches or upgrades
  (the request is shared), the first request on a thread, and a target longer than the spare.
  A detached request's buffer is freed wherever the request is dropped.
- Each thread keeps at most 1 KiB of spare target buffer.
- API (akio-http, additive): `transport::ConnSink`, `transport::SharedSink`,
  `transport::dispatch_conn`, `transport::start_conn` and `transport::request_target`.
  `transport::ResponseSink`, `transport::dispatch` and `transport::start` are deprecated.
  `akio_http::transport` is `#[doc(hidden)]` and outside the semver promise
  (docs/api-stability.md), so the API snapshots do not change; the old items are kept anyway for
  transports written against them. Nothing changes in `Request`, `Context` or anything else
  handlers use.

### Migration

| Before | After |
|---|---|
| `impl ResponseSink for MySink { fn send(self: Box<Self>, r) .. }` | `impl ConnSink for MyConn { fn send(&self, tag: u64, r) .. }`, one per connection |
| `transport::dispatch(&svc, req, Box::new(MySink { .. }))` | `let sink = SharedSink::new(MyConn { .. })` once per connection, then `transport::dispatch_conn(&svc, req, &sink, tag)` |
| `transport::start(&svc, req, Box::new(MySink { .. }))` | `transport::start_conn(&svc, req, &sink, tag)` |
| `Request::new(m, path.to_owned())` per request | `Request::new(m, transport::request_target(path))` (optional) |

Handlers, routers and middleware need no change. Code that calls the deprecated functions keeps
compiling, with deprecation warnings.
