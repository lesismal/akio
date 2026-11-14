# Blocking work: the logical pool

Callbacks run on the I/O thread, so a callback that blocks for 5 ms stalls every connection on
that thread for 5 ms. The benchmark report shows what that costs: four I/O threads that block
5 ms per request serve about 550 requests per second; the same work moved to the logical pool
serves about 32,000 ([BENCHMARKS](https://github.com/lesismal/flash/blob/main/docs/BENCHMARKS.md)).

`only` does not guess which code blocks. **You move blocking work explicitly**, and the result
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

## Ordered response slots

Pool jobs finish in any order. For protocols where replies must follow request order (HTTP/1.1
pipelining, line protocols, arpc-style framing), reserve the position first:

```rust,ignore
{{#include ../../../../crates/only/examples/guide-basics.rs:offload}}
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

The pool is engine-wide, created lazily and adaptive (`only_pool`):

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
| only-http | `Context::detach()` returns a `Detached` you `respond` from any thread; pipelined responses stay ordered. |
| only-ws | `WsSender` is `Clone + Send + Sync`; send from any thread. |
| only-grpc | The `Sink` handed to a method is usable from any thread. |
| only-arpc | `Context::detach()` returns a `Responder`. |
| only-quic / only-kcp | `Connection` / `Session` are cloneable handles; send from any thread. |

These give you the "answer later" half; run the work wherever suits you: a thread of your own,
your own pool, or another runtime ([Migrating from tokio](../migration/from-tokio.md) shows the
bridge). For raw `Handler`s, `Conn::spawn_blocking` uses the engine's pool.

## Slow-callback detection

Every callback is timed while `Config::slow_callback_threshold` is set (100 ms by default). A
callback that runs longer is counted, kept in a ring of recent records
(`Engine::slow_callbacks()`, the debug endpoint) and reported to `Config::slow_hook`, or logged
(target `only`, level `warn`), or printed to stderr when no logger is installed. Treat each
report as a bug: something on the I/O thread blocked.
