# ADR-081: Per-thread header storage, pooled response heads, HTTP/2 requests without a boxed context

English | [简体中文](081-per-thread-head-storage.zh-CN.md)

Status: accepted (2026-11-22)

## Context

ADR-025 left these allocations per request: HTTP/2's `Box<Context>`, the headers buffer and
the response allocations. After it, the HTTP/1.1 server made 5.0 allocator calls per request,
pipelined HTTP/1.1 5.0, h2c 5.5, and `quic-bench h3` (both ends in one process) 9.0. Counting
method: bpftrace uprobes on malloc, calloc, realloc, posix_memalign and aligned_alloc in the
server process, `http-bench` on gpu51, h2load. To find where each one comes from, a build with
frame pointers and line tables, `ustack()` per call, and `addr2line -i` on the frames.

| Where | HTTP/1.1 | h2c | HTTP/3 server |
|---|---:|---:|---:|
| Request header storage (`parse_head`, HTTP/2 `build_request`, only-h3 `request_head`) | 1 | 1 | 1 |
| `Response::with_body`: its header buffer, and a vector of field positions (it reserved room for 4 fields; 2 are kept inline) | 2 | 2 | 2 |
| The response body: `ctx.text(200, "Hello, World!")` turns the `&str` into a `String` | 1 | 1 | 1 |
| The HTTP/1.1 response head (`Vec::with_capacity(192 + body)`) | 1 | | |
| `Box<Context>` per HTTP/2 request | | 1 | |
| The HTTP/2 connection's output buffer, grown again from empty after every flush (reallocations) | | ~0.5 | |

The `quic-bench` client side adds 4 more: the response's `Headers` (buffer and positions), its
body, and the benchmark's request. QUIC itself adds about 1.

## Decision

1. **Per-thread spare header storage.** Each thread keeps one spare `Headers` storage for
   request heads and one for response heads. A spare is a buffer for names and values plus the
   field-position vector, emptied. Request heads take the request spare: HTTP/1.1 `parse_head`,
   HTTP/2 `build_request`, and only-h3 through `transport::request_headers(fields, bytes)`. It
   goes back with the target buffer (ADR-025) when the handler is done with a request it still
   owns (`Context::recycle_request`, which replaces `recycle_target`).
   `Response::with_body` takes the response spare, and so do `text` and everything built on
   them. It goes back once the head is encoded: the HTTP/1.1 responder, HTTP/2 `send_response`,
   and only-h3's sink through `transport::recycle_response_headers`. Storage over 4 KiB or over
   64 field positions is not kept. There are two spares, not one, because a request's head is
   still alive while its response is built. They are per thread for ADR-025's reason: the next
   head parsed on the thread finds the storage still in cache.
2. **`with_body` keeps its positions inline.** It reserves 2 field positions, which are kept
   inline, instead of 4, which needed a vector. A third field moves them into a vector, as any
   third field did before.
3. **HTTP/1.1 response heads use only-buf's pool.** The head is encoded into
   `only_buf::get(192 + body)`, a 512-byte or larger size class. The connection gives such a
   buffer back to the pool of the thread that writes it (`consume`). Inside `on_data` that is
   the I/O thread at the end of the callback, so the buffer is back before the next request.
   only-core now also gives back a buffer that `send_owned` wrote in full right away (sends
   from other threads when nothing is queued), and the plaintext buffer TLS has just sealed.
4. **HTTP/2 dispatches a request without boxing its context.** `Action::Dispatch` carries the
   `Request` and the stream's responder. `run` builds the `Context` on its stack, as HTTP/1.1
   does. Streamed requests and extended CONNECT keep the boxed context, which is parked on the
   stream. The vector of actions is a per-thread spare.
5. **The HTTP/2 output buffer comes from the pool.** When a response head is written into an
   empty output buffer, the buffer is taken from only-buf's pool (4 KiB class), instead of
   growing from nothing. The flush hands it to the connection, which gives it back to the
   pool once it is written. One that nothing was written to goes back at the flush, so an
   idle connection holds none.

### Alternatives considered

- **Reusing the response body.** `Context::text` and `Response::text` take
  `impl Into<String>`, so a `&str` becomes a new `String` in std before only-http sees it.
  Changing the bound to `AsRef<str>` would break callers whose type is only `Into<String>`.
  This allocation stays, one per request, in the handler.
- **Copying the head into the connection's queue.** The head would be encoded into a
  per-thread scratch buffer, then a new `ResponseSlot` method would copy it into the queue's
  tail buffer, coalescing pipelined responses. That needs only-core API and an extra copy.
  The pooled buffer reaches the same count without either.
- **A per-thread spare `Box<Context>` for HTTP/2.** The box keeps the finished context, and
  whatever its request held, until the next request. Building the context on the stack is
  simpler and frees nothing late.
- **One spare for request and response heads.** Both are alive at once, so the response would
  always find the spare taken.
- **Spares per connection.** ADR-025 measured them cold.

## Consequences

- Allocator calls per request, server only (bpftrace, gpu51, epoll and io_uring alike):
  - HTTP/1.1: 5.0 → 1.0.
  - Pipelined HTTP/1.1: 5.0 → 1.0.
  - h2c: 5.5 → 1.0.
  - `quic-bench h3` both ends: 9.0 → 6.0. The server makes 1; the client 4 (response headers
    2, body 1, the benchmark's request 1); QUIC about 1.
  The 1 left on the server is the handler's response body.
- Same-run A/B on gpu51 under `quiet.sh` (7 alternating rounds, medians; server on CPUs 0–3,
  h2load on 4–11; `perf stat` on the server over the h2load run):

| Case | req/s before → after | × | server user cycles / request | × | instructions / request | × |
  |---|---:|---:|---:|---:|---:|---:|
  | HTTP/1.1, 256 connections | 580,082 → 579,612 | 0.999 | 4,948 → 4,883 | 0.987 | 6,904 → 6,471 | 0.937 |
  | HTTP/1.1 pipelined 16 × 256 | 3,700,614 → 3,815,779 | 1.031 | 2,484 → 2,329 | 0.938 | 6,055 → 5,436 | 0.898 |
  | h2c 64 connections × 16 streams | 3,152,801 → 3,285,438 | 1.042 | 4,355 → 4,092 | 0.940 | 9,013 → 8,376 | 0.929 |
  | HTTP/3 GET, one connection, 64 in flight (`quic-bench h3 10 64`, CPUs 2–5) | 870,751 → 884,259 | 1.016 | | | | |

  Plain HTTP/1.1 is held by the client and the kernel (one read and one write per request), so
  its req/s does not move; its cycles per request were the noisiest figure (0.96–1.01× by
  round). The new build was faster on HTTP/3 in 6 of 7 rounds.

- Memory: each thread keeps at most two header storages of up to 4 KiB each, plus the
  1 KiB target. While a pipelined HTTP/1.1 head is queued, it sits in a 512-byte buffer (it
  was sized exactly). The pool keeps at most 64 buffers per size class per thread.
- A response sent from another thread (a detached request) is encoded in that thread's pool,
  or in a new buffer when the pool is empty. It goes back to the pool of the thread that
  writes it.
- API: no public change. Additions under `#[doc(hidden)]` `only_http::transport`, outside the
  snapshots: `request_headers` and `recycle_response_headers`. only-http now depends on
  only-buf.
- Not done:
  - The response body (above).
  - The HTTP/3 client's response headers and body. They belong to the caller, so they are not
    recycled; a response with three or more fields needs the position vector.
  - QUIC's own allocations.
