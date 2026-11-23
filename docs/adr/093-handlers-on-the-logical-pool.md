# ADR-093: Protocol handlers on the logical pool, per protocol, off by default

English | [简体中文](093-handlers-on-the-logical-pool.zh-CN.md)

Status: accepted (2026-11-23)

## Context

Protocol handlers run on the connection's I/O thread (ADR-001, rules §1). A handler that blocks
stalls every connection of that thread, so blocking work had to be moved by hand: `detach` and
answer from a thread of the application's choosing, or `Conn::spawn_blocking` for raw handlers.

Two things were missing:

- **A per-protocol switch.** Applications whose handlers mostly block (a database per request)
  wanted every request on the pool. They also wanted the requests of one multiplexed connection
  (HTTP/2 streams, HTTP/3 requests, gRPC calls, arpc requests) served at the same time rather than
  one after another on the I/O thread.
- **One call for "this request goes to the pool".** `detach` plus a pool handle. The HTTP
  `Context` had no way to reach the engine's pool.

HTTP/1.1 response order is already kept by the ordered response positions
(`Conn::reserve_response`). Every request reserves its position before its handler runs, and
both inline answers and detached ones fill that position. Mixing them is therefore already
ordered.

## Decision

- **akio-core.** `ConnInner::execute(job) -> Result<(), Job>` queues a job on the engine's pool
  and hands it back, unrun, when the pool refuses it. `Conn::execute(work)` is the same for
  applications. It differs from `spawn_blocking` in having no completion.
  `akio_quic::Connection::execute` does the same for QUIC connections.
- **akio-http.**
  - `HttpConfig::run_on_pool` (HTTP/1.1) and `H2Config::run_on_pool` (HTTP/2), both `false` by
    default.
  - When on, a complete request runs its middleware and handler on the pool. Then comes the `500`
    for a handler that neither answered nor detached.
  - Requests stay inline when they may take the connection over (HTTP/1.1 `CONNECT` / `Upgrade`,
    HTTP/2 extended CONNECT) or when their body is taken as a stream. Those handlers interact with
    the session on the I/O thread.
  - A pooled context refuses `upgrade_websocket` / `upgrade_raw`.
  - `Context::executor()` returns an `Executor` for the request's connection.
    `Context::detach_to_pool(f)` detaches and runs `f` on the pool.
  - `ConnSink::execute` (default: no pool) and `transport::dispatch_conn_on_pool` let a transport
    outside the crate do the same.
- **akio-h3.** `H3Config::run_on_pool`, through `dispatch_conn_on_pool`.
- **akio-grpc.**
  - `GrpcServer::run_on_pool(bool)`. gRPC takes bodies as streams, so the HTTP switch does not
    reach it.
  - Each call gets a queue. One pool job at a time opens the call and hands over its messages in
    order, so a handler sees exactly what it would inline, while different calls run at once.
  - Messages waiting for a busy handler count against `max_collect_bytes`.
  - A handler that panics ends its call with `INTERNAL`.
- **akio-arpc.** `Routes::run_on_pool(bool)` covers requests and notifies; streams stay inline.
  `SERVER_BUSY` is the error text when the pool refuses.
- **A full pool** answers at once: HTTP `503` with `Retry-After: 1`, gRPC `RESOURCE_EXHAUSTED`,
  arpc `SERVER_BUSY`.
  - A refused job comes back as an opaque `FnOnce`. A thread-local flag set around running it
    inline tells it to answer "busy" instead of doing its work. This avoids an allocation per
    request to keep the context reachable.

## Consequences

- Handlers may block when the switch is on, and multiplexed connections gain per-connection
  concurrency. The cost is one hand-off per request (a pool queue push and a thread wake-up).
  The default stays inline, where non-blocking handlers are fastest.
- arpc notifies, and requests on HTTP/2, HTTP/3 and arpc, may complete in any order when pooled.
  HTTP/1.1 responses and each gRPC call's messages keep their order.
- Request spans of pooled requests are entered on the pool thread.
- Thread-local spare buffers are not recycled for pooled requests.

## Not done

- Pool dispatch for streamed request bodies: the body sink would have to be fed across threads.
- A per-route switch on `Router`. `detach_to_pool` covers a single route.
