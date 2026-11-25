# Blocking work: the logical pool

Callbacks run on the I/O thread, so a callback that blocks for 5 ms stalls every connection on
that thread for 5 ms. The benchmark report shows what that costs: four I/O threads that block
5 ms per request serve about 550 requests per second; the same work moved to the logical pool
serves about 32,000 ([BENCHMARKS](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md)).

`akio` does not guess which code blocks. **You move blocking work explicitly**, and the result
comes back to the connection's own thread.

## `spawn_blocking`

```rust,ignore
pub fn spawn_blocking<R, W, D>(&self, work: W, done: D) -> Result<()>
where
    R: Send + 'static,
    W: FnOnce() -> R + Send + 'static,                 // runs on the logical pool
    D: FnOnce(&mut H, &Conn<H>, R) + Send + 'static,   // runs on the connection's I/O thread
```

- `work` runs on a pool thread and may block (database, file system, slow RPC, CPU-heavy code).
- `done` is posted back to the **owning I/O thread** and gets `&mut` access to the handler, so
  the handler state stays lock-free. What it sends is corked and flushed when it returns.
- If the connection closed meanwhile, `done` is skipped. It is also skipped if `work` panicked
  (the panic is counted in `PoolStats::panicked`).
- It fails with `Error::Overloaded` when the pool queue is full and `Error::Closed` when the
  connection (or the pool) is closed.

## `run_on_loop`

```rust,ignore
pub fn run_on_loop(&self, f: impl FnOnce(&mut H, &Conn<H>) + Send + 'static) -> Result<()>
```

The `done` half alone: `f` runs on the owning I/O thread with `&mut` access to the handler,
posted straight to the loop, with no pool thread involved. Use it to reach the handler from
another thread (a pool job, a timer, your own thread). Never use an empty `spawn_blocking`
for this: when the pool is full, or its threads all wait on this very connection, that job
never runs. If the connection closes before `f` runs, `f` is dropped unrun, so a guard it owns
can answer whoever waits on it; on an already closed connection it fails with `Error::Closed`.

## Ordered response slots

Pool jobs finish in any order. For protocols where replies must follow request order (HTTP/1.1
pipelining, line protocols, arpc-style framing), reserve the position first:

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:offload}}
```

`Conn::reserve_response()` (call it on the I/O thread, in request order) returns a
`ResponseSlot`. Responses are written in reservation order no matter in which order slots are
filled, from any thread:

| `ResponseSlot` method | Effect |
|---|---|
| `fill(Vec<u8>)` | Supplies the bytes. |
| `fill_close(Vec<u8>)` | Supplies the bytes; close once they and everything before are written. |
| `fill_parts(Vec<Part>, close_after)` | Bytes and file ranges (`Part::File` goes out with `sendfile`). |
| `stream(head) -> ResponseStream` | A response produced piece by piece: `write`, `queued_bytes`, `finish(close_after)`. |

Dropping an unfilled slot (or a `ResponseStream` without `finish`) **closes the connection**:
the stream would otherwise stall forever behind the missing response. A plain `Conn::send` is
*not* held behind unfilled slots; do not mix the two for the same stream of replies.

## Sizing the pool

The pool is engine-wide, created lazily and adaptive (`akio_pool`):

```rust,ignore
let mut pool = PoolConfig::default();       // #[non_exhaustive]: set fields on the default
pool.min_threads = 0;                       // kept alive when idle
pool.max_threads = cores * 8 (at least 8);  // started on demand
pool.queue_capacity = 65_536;               // beyond it: Error::Overloaded
pool.keep_alive = Duration::from_secs(30);  // idle threads above min_threads retire
EngineBuilder::pool(pool)
```

Those are the defaults. `Engine::pool_stats()` (and the metrics endpoint) report threads, idle
threads, queue length, completed, panicked and rejected jobs.

Choose `max_threads` by what the blocking work waits on: a database pool of 50 connections gains
nothing from 200 pool threads. Choose `queue_capacity` by how much latency you accept before
shedding load: `Overloaded` is the signal to answer "busy" (HTTP 503) instead of queueing more.

## In protocol crates

Protocol crates expose the same idea in their own terms; the handler never blocks and the answer
is sent later from any thread:

| Crate | Mechanism |
|---|---|
| akio-http | `Context::detach()` returns a `Detached` you `respond` from any thread; `Context::detach_to_pool(f)` detaches and runs `f` on the engine's pool; pipelined responses stay ordered. |
| akio-ws | `WsSender` is `Clone + Send + Sync`; send from any thread. |
| akio-grpc | The `Sink` handed to a method is usable from any thread. |
| akio-arpc | `Context::detach()` returns a `Responder`. |
| akio-quic / akio-kcp | `Connection` / `Session` are cloneable handles; send from any thread. |

These give you the "answer later" half; run the work wherever suits you: a thread of your own,
your own pool, or another runtime ([Migrating from tokio](../migration/from-tokio.md) shows the
bridge). For raw `Handler`s, `Conn::spawn_blocking` uses the engine's pool.

## Running every handler on the pool

The HTTP, gRPC and arpc servers can also run **every** request's handler on the pool, so
handlers may block and the requests of one connection are served at the same time instead of
one after another. It is set per protocol, and on by default only for HTTP/2, whose streams
would otherwise be served one at a time on their connection's I/O thread (set
`h2.run_on_pool = false` to keep non-blocking handlers inline):

```rust,ignore
let mut http = HttpConfig::default();
http.run_on_pool = true;                         // HTTP/1.1
let mut h2 = H2Config::default();
h2.run_on_pool = true;                           // HTTP/2 streams
http.h2 = Some(h2);
let mut h3 = H3Config::default();
h3.run_on_pool = true;                           // HTTP/3 (akio-h3)
let grpc = GrpcServer::new().run_on_pool(true);  // gRPC calls
let routes = Routes::new().run_on_pool(true);    // arpc requests and notifies
```

- **What moves.** The middleware and the handler. Parsing, limits, flow control and (for gRPC)
  interceptors and message decoding stay on the I/O thread.
- **What stays inline.** Requests that may take the connection over (HTTP/1.1 `CONNECT` and
  `Upgrade`, extended CONNECT on HTTP/2 and HTTP/3), requests whose body the service takes as a
  stream, arpc streams. A pooled handler's `upgrade_websocket` / `upgrade_raw` return `false`.
- **Order.** HTTP/1.1 responses go out in request order whether each request ran inline, on the
  pool, or was detached by its handler: every request reserves its response position before it
  runs. A gRPC call's messages reach its handler one at a time and in order; different calls run
  at once. arpc answers go out as they are ready (callers match them by sequence number), and
  notifies may be handled in any order.
- **A full pool.** The request is answered at once: HTTP `503` with `Retry-After`, gRPC
  `RESOURCE_EXHAUSTED`, arpc the error `SERVER_BUSY` (a notify is dropped).

Handlers that never block gain nothing from it: each request then pays a hand-off to a pool
thread. Turn it on where handlers block, or for a single request use `detach_to_pool`.

## Slow-callback detection

Every callback is timed while `Config::slow_callback_threshold` is set (100 ms by default). A
callback that runs longer is counted, kept in a ring of recent records
(`Engine::slow_callbacks()`, the debug endpoint) and reported to `Config::slow_hook`, or logged
(target `akio`, level `warn`), or printed to stderr when no logger is installed. Treat each
report as a bug: something on the I/O thread blocked.
