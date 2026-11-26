# ADR-176: HTTP/2 handlers inline by default again

English | [简体中文](176-http2-handlers-inline-by-default.zh-CN.md)

Status: accepted (2026-11-26). Reverses the default set by the 2026-11-25 update of
[ADR-094](094-handlers-on-the-logical-pool.md); the rest of ADR-094 stands.

## Context

ADR-094 (2026-11-23) added a `handlers_on_logical_pool` switch to every protocol, off by default. Its update of
2026-11-25 (`d33d4dd3`) turned `H2Config::handlers_on_logical_pool` on by default, so that the streams of one
HTTP/2 connection are served at the same time rather than one after another on its I/O thread.

The same-run A/B of 2026-11-26 ([BENCHMARKS](../BENCHMARKS.md#request-checks-and-client-timer-cancel-akit-a169-a171-same-run-ab-2026-11-26))
measured what that default costs a service whose handlers never block: h2c in `http-bench` (4 I/O
threads, `h2load` 64 × 16 and 16 × 128) serves 0.47-0.53 M requests/s on the pool against
4.4-6.1 M inline, on the same host with the same binaries: 9-13 times less. Each pooled request
pays two hand-offs between threads that an inline one does not:

- the request: a push on the pool's queue (one `Mutex` shared by every I/O thread) and a
  `Condvar` wake of a pool thread;
- the response: written into the connection's HTTP/2 state from the pool thread, under the lock
  the I/O thread takes for every frame it reads, then sent to the connection from a foreign
  thread, which wakes the loop to write it. Inline, the responses of one read go out in one
  write.

`perf` on the pooled server (same section, follow-up) puts `Mutex::lock_contended` first (5.7%
of the samples), then the kernel's spin locks, wake-ups and system calls; no handler-side symbol
reaches 1%. Over 6 s the pooled server makes 1.46 M context switches and spends 8.3 µs of CPU per
request, against 70 and 0.87 µs inline.

The update's other change, the deadlock fix of the HTTP clients (`Conn::run_on_loop`: a client
called from a pool task reaches its connection's loop without a pool job of its own), does not
depend on this default.

## Decision

`H2Config::handlers_on_logical_pool` defaults to `false` again, as `HttpConfig::handlers_on_logical_pool`,
`H3Config::handlers_on_logical_pool`, `GrpcServer::handlers_on_logical_pool` and `Routes::handlers_on_logical_pool` do. Nothing else
changes: the switch, what it moves and what stays inline, `503` from a full pool,
`Context::detach_to_pool` and `Context::suspend_to_pool` for single requests.
`http-bench` takes `AKIO_BENCH_H2_POOL=1` to serve HTTP/2 on the pool.

## Why it is safe

- **No release had the pool default.** It arrived on 2026-11-25 under `[Unreleased]`; every
  release up to 1.0.0-rc.1 served HTTP/2 inline. An application built on a release sees no
  change; one that follows `main` sees the default it had until the day before.
- **The deadlock fix stays.** The HTTP/1.1 and HTTP/2 clients reach their loop with
  `Conn::run_on_loop` whatever this switch says, so a handler on the pool that calls a client and
  waits for it still needs no second pool thread (`tests/handlers_on_logical_pool.rs` sets the switch itself).
- **The rule every protocol follows.** Rules §1: nothing on an I/O thread blocks; work that can
  only block goes to the pool, per request (`detach_to_pool`, `suspend_to_pool`,
  `spawn_blocking`) or per protocol (`handlers_on_logical_pool`). HTTP/1.1, HTTP/3, gRPC and arpc have always
  defaulted to inline under that rule; HTTP/2 now does again. A handler that blocks anyway is
  reported by the slow-callback detector (`Config::slow_callback_threshold`).
- **The main user does not need it.** akit takes `HttpConfig::default()` for its proxy
  listeners, whose handlers never block (upstream requests are asynchronous; blocking checks go
  to the pool request by request through `suspend_to_pool`, akit's A65): with the pool default it
  paid the 9-13 times for nothing.

## Consequences

- A service whose HTTP/2 handlers block sets `handlers_on_logical_pool: true` (or sends those requests to the
  pool one by one). One that does not, and blocks, holds up its connection's other streams and
  its thread's other connections, as on HTTP/1.1; a handler that waits inline for a client
  request served by its own I/O thread never gets the answer (rules §1). Both were so until
  2026-11-25.
- The streams of one connection are served one after another on its I/O thread, in the order
  their requests complete, which costs nothing while handlers do not block.
- `Context::after` from an HTTP/2 handler runs its callback on the I/O thread again (a loop
  timer), not on the shared timer thread.

## Not done

- **A cheaper pool path.** Batching the hand-offs (one queue push and one wake-up per read
  rather than per request, responses of several streams in one cross-thread send) and a pool
  queue that is not one shared lock would narrow the gap; the hand-offs themselves stay. A
  follow-up for `akio-pool` and the HTTP/2 responder.
- **An automatic mode** (inline until a handler is seen to take long, then the pool): it costs a
  clock read per request, and still blocks the loop for the requests that teach it. Not built.
