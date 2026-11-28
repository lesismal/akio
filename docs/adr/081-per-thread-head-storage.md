# ADR-081: Per-thread header storage, pooled response heads, HTTP/2 requests without a boxed context

English | [简体中文](081-per-thread-head-storage.zh-CN.md)

Status: accepted (2026-11-22), updated 2026-11-23

## Context

ADR-025 left these allocations per request: HTTP/2's `Box<Context>`, the headers buffer and
the response allocations. After it, the HTTP/1.1 server made 5.0 allocator calls per request,
pipelined HTTP/1.1 5.0, h2c 5.5, and `quic-bench h3` (both ends in one process) 9.0. Counting
method: bpftrace uprobes on malloc, calloc, realloc, posix_memalign and aligned_alloc in the
server process, `http-bench` on gpu51, h2load. To find where each one comes from, a build with
frame pointers and line tables, `ustack()` per call, and `addr2line -i` on the frames.

| Where | HTTP/1.1 | h2c | HTTP/3 server |
|---|---:|---:|---:|
| Request header storage (`parse_head`, HTTP/2 `build_request`, akio-h3 `request_head`) | 1 | 1 | 1 |
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
   HTTP/2 `build_request`, and akio-h3 through `transport::request_headers(fields, bytes)`. It
   goes back with the target buffer (ADR-025) when the handler is done with a request it still
   owns (`Context::recycle_request`, which replaces `recycle_target`).
   `Response::with_body` takes the response spare, and so do `text` and everything built on
   them. It goes back once the head is encoded: the HTTP/1.1 responder, HTTP/2 `send_response`,
   and akio-h3's sink through `transport::recycle_response_headers`. Storage over 4 KiB or over
   64 field positions is not kept. There are two spares, not one, because a request's head is
   still alive while its response is built. They are per thread for ADR-025's reason: the next
   head parsed on the thread finds the storage still in cache.
2. **`with_body` keeps its positions inline.** It reserves 2 field positions, which are kept
   inline, instead of 4, which needed a vector. A third field moves them into a vector, as any
   third field did before.
3. **HTTP/1.1 response heads use akio-buf's pool.** The head is encoded into
   `akio_buf::get(192 + body)`, a 512-byte or larger size class. The connection gives such a
   buffer back to the pool of the thread that writes it (`consume`). Inside `on_data` that is
   the I/O thread at the end of the callback, so the buffer is back before the next request.
   akio-core now also gives back a buffer that `send_owned` wrote in full right away (sends
   from other threads when nothing is queued), and the plaintext buffer TLS has just sealed.
4. **HTTP/2 dispatches a request without boxing its context.** `Action::Dispatch` carries the
   `Request` and the stream's responder. `run` builds the `Context` on its stack, as HTTP/1.1
   does. Streamed requests and extended CONNECT keep the boxed context, which is parked on the
   stream. The vector of actions is a per-thread spare.
5. **The HTTP/2 output buffer comes from the pool.** When a response head is written into an
   empty output buffer, the buffer is taken from akio-buf's pool (4 KiB class), instead of
   growing from nothing. The flush hands it to the connection, which gives it back to the
   pool once it is written. One that nothing was written to goes back at the flush, so an
   idle connection holds none.

### Alternatives considered

- **Reusing the response body.** `Context::text` and `Response::text` take
  `impl Into<String>`, so a `&str` becomes a new `String` in std before akio-http sees it.
  Changing the bound to `AsRef<str>` would break callers whose type is only `Into<String>`.
  This allocation stays, one per request, in the handler.
- **Copying the head into the connection's queue.** The head would be encoded into a
  per-thread scratch buffer, then a new `ResponseSlot` method would copy it into the queue's
  tail buffer, coalescing pipelined responses. That needs akio-core API and an extra copy.
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
  was sized exactly). The pool keeps at most 64 buffers per size class per thread (and, since ADR-190, at most
  256 KiB of a class).
- A response sent from another thread (a detached request) is encoded in that thread's pool,
  or in a new buffer when the pool is empty. It goes back to the pool of the thread that
  writes it.
- API: no public change. Additions under `#[doc(hidden)]` `akio_http::transport`, outside the
  snapshots: `request_headers` and `recycle_response_headers`. akio-http now depends on
  akio-buf.
- Not done:
  - The response body (above).
  - The HTTP/3 client's response headers and body. They belong to the caller, so they are not
    recycled; a response with three or more fields needs the position vector.
  - QUIC's own allocations.

## Update (2026-11-23): response bodies, the HTTP/3 client's heads, QUIC's hot path

### Context

What ADR-081 left, counted the same way (bpftrace uprobes on the allocator; for the stacks a
frame-pointer build with line tables, run without address randomisation, `addr2line -i`):

| Where | per request / per MB |
|---|---:|
| Handler body: `ctx.text(200, "Hello, World!")` makes a `String` (HTTP/1.1, pipelined, h2c, HTTP/3 server) | 1 |
| `quic-bench h3` client: response `Headers` (buffer and positions, the response has 3 fields) | 1.96 |
| `quic-bench h3` client: response body (`body.to_vec()`, the caller's `Vec<u8>`) | 0.98 |
| `quic-bench h3`: the benchmark's own request callback (`Box<dyn FnOnce>`) | 1.0 |
| `quic-bench h3`: QUIC and the UDP loop | ~0.7 |
| QUIC bulk, per MB (one connection, about 740 packets): frame lists of sent packets beyond the 64 spares | 208 |
| QUIC bulk: a datagram buffer per `poll_transmit`, even when it returns nothing | 108 |
| QUIC bulk: the list of packets an ACK takes out, and the ACK frame's range vector | 68 |
| QUIC bulk: akio-core's `sendmmsg` map and GSO parts, akio-epoll's and akio-core's per-flush lists | 77 |

### Decision

1. **`text` bodies in a per-thread spare buffer.** `Response::text` / `Context::text` keep their
   `impl Into<String>` bound. A hidden helper, `akio_buf::text::as_str`, tells whether the
   argument's type is `&str` (for any lifetime; dtolnay's `typeid::of` technique, the only
   `unsafe`, Miri-checked) and returns it. A `&str` is copied into the thread's spare body
   buffer; any other type goes through `Into<String>` as before (a `String` is moved, not
   copied). Once the body is copied into the output, the transport gives its buffer back as the
   thread's spare (up to 4 KiB): the HTTP/1.1 responder, HTTP/2's one-frame path and akio-h3's
   sink through the hidden `transport::recycle_response_body`. A body the transport does not
   copy (an HTTP/2 body larger than a frame or the windows, an HTTP/3 body over 16 KiB, a
   file) is not recycled.
2. **Dropped `Headers` storage refills the thread's empty response spare.** `Headers` holds its
   buffer and positions in a private type with a `Drop` that moves them into the response spare
   when that is empty and the storage is not over the spare limits (an occupied spare is left
   alone, so there is no cascade). The `Drop` is on the private type, so `Headers`' API and
   snapshot are unchanged. The HTTP/3 client builds a response's headers in the response spare
   (hidden `transport::response_headers`); a caller that drops the response in its callback, on
   the client's I/O thread, lends the storage to the next response.
3. **QUIC's hot path.** The datagram buffer of `poll_transmit` comes from akio-buf's pool (the
   UDP layer already gives pooled buffers back once written); one that holds nothing goes
   straight back. An ACK frame's ranges are checked by the parser and read in place
   (`AckRanges`, decoded again while iterating) instead of collected in a vector. The packets an
   acknowledgment takes out are collected in a list the connection keeps (up to 1024 entries).
   Spare frame lists are kept up to the number of 1-RTT packets in flight (at least 64), since
   one receive batch can acknowledge most of them before anything is sent.
4. **The UDP flush.** akio-core's `send_datagrams` keeps its message map in its thread-local
   batch and builds a GSO message's parts in an array on the stack. `flush_datagram_peers` takes
   any `Deref<Target = ConnInner>` and, for one connection, builds no lists; the epoll UDP loop
   keeps the list of connections it flushes.

### Alternatives considered

- **Bodies from akio-buf's pool** (the first version: `akio_buf::get` for the copy, `put` once
  copied out). Same counts, but the pool's size-class search and `RefCell` on both ends cost
  more than glibc's cached malloc/free of a 13-byte string: pipelined HTTP/1.1 took 1.033× the
  server user cycles per request (worse in all 7 rounds), req/s 0.986×. A `Cell<Vec<u8>>` spare,
  like the header spares, brought it back to 1.004×.
- **Changing the bound to `AsRef<str>`** (ADR-081): still a breaking change.
- **`Drop` on `Response` to recycle the client's body.** `Response` has public fields; a `Drop`
  impl forbids moving them out (`let body = resp.body;`), a breaking change. The client's body
  stays the caller's allocation.
- **A `Drop` on `Headers` itself.** Works the same, but adds `impl Drop for Headers` to the
  public API snapshot.
- **An inline small vector for sent packets' frames.** Grows `Sent`, which the ring of packets
  in flight moves around; keeping more spare lists is simpler and allocates nothing after the
  first flight.

### Consequences

- Allocator calls (bpftrace, gpu51):
  - HTTP/1.1, pipelined HTTP/1.1, h2c, server only: 1.0 → 0 per request (epoll and io_uring;
    about 1,300–3,900 calls over runs of 1.6–11 million requests, from timers and connection
    setup).
  - `quic-bench h3` both ends: 6.0 → 2.03 per request: the client's response body (the
    caller's) and the benchmark's request callback, plus about 0.03 in QUIC.
  - QUIC bulk (`quic-bench bulk 2000`): 482 → 21.5 per MB.
- Same-run A/B on gpu51 under `quiet.sh` against `main` at `5cc005c0` (7 alternating rounds,
  medians; HTTP: `http-bench` epoll, server on CPUs 0–3 with 4 threads, `h2load` with 8 threads
  on CPUs 4–11, 10-second runs, `perf stat -e cycles:u,instructions:u` on the server; HTTP/3:
  `quic-bench h3 10 64` and bulk: `quic-bench bulk 8000`, both on CPUs 2–5, `perf stat` on the
  whole process, so HTTP/3 cycles are both ends):

  | Case | req/s before → after | × | user cycles / request | × | instructions / request | × |
  |---|---:|---:|---:|---:|---:|---:|
  | HTTP/1.1, 256 connections | 578,340 → 580,183 | 1.003 | 4,861 → 4,738 | 0.975 | 6,470 → 6,457 | 0.998 |
  | HTTP/1.1 pipelined 16 × 256 | 3,800,088 → 3,798,787 | 1.000 | 2,304 → 2,314 | 1.004 | 5,435 → 5,416 | 0.997 |
  | h2c 64 connections × 16 streams | 3,286,046 → 3,313,472 | 1.008 | 4,099 → 4,054 | 0.989 | 8,369 → 8,331 | 0.996 |
  | HTTP/3 GET, one connection, 64 in flight (both ends) | 790,826 → 794,709 | 1.005 | 6,416 → 6,447 | 1.005 | 17,273 → 16,920 | 0.980 |
  | QUIC bulk, one stream (Mbit/s) | 18,550 → 19,007 | 1.025 | | | | |

  Pipelined cycles per request ranged 1.000–1.014× by round (noise level for that figure; its
  instructions fell). HTTP/3 cycles are both ends of a fixed-time run; its instructions fell 2%.
  Bulk was faster in 7 of 7 rounds.
- Memory: each thread keeps one spare body buffer of up to 4 KiB. A response dropped on a
  thread that is not an I/O thread (a client response sent to the caller's thread) fills that
  thread's response spare (up to 4 KiB). A QUIC connection keeps as many spare frame lists as it
  had 1-RTT packets in flight (a few dozen bytes each plus the list's capacity), until it closes,
  and an acknowledgment list of up to 1024 entries.
- API: no public change; snapshots unchanged. Hidden additions: `akio_buf::text::as_str`,
  `akio_http::transport::{response_headers, recycle_response_body}`; akio-core's hidden
  `ConnInner::flush_datagram_peers` is generic over the connection handle.
- Tests: pipelined / sequential `text(&str)` bodies around the size limits, sent from the
  handler and from another thread, on HTTP/1.1, HTTP/2 and HTTP/3; H3 client responses checked
  and dropped in the callback with heads of every size; unit tests of the spares and of
  `as_str` (also under Miri); akio-quic's ACK round-trip tests on `AckRanges` (the fuzz harness adapted, built and clippy-clean, not run);
  quic-go interop (`tools/interop/quic/run.sh`) passes.
- Not done:
  - The HTTP/3 client's response body: the caller's `Vec<u8>` (see above).
  - Bodies the transport does not copy (large HTTP/2 and HTTP/3 bodies, files), and handler
    bodies of other types (`String`, `Vec<u8>`): the handler's allocation.
  - The HTTP/1.1 and HTTP/2 clients (`akio_http::client`, `h2client`) still allocate their
    response heads per response.
  - QUIC with many connections per loop thread: a flush of several connections still builds
    two lists.
