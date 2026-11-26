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
pool.max_blocked_threads = cores * 8 (at least 8); // stand-ins for threads in akio::blocking
pool.name = "akio-pool".into();             // in the pressure logs; the engine's pool is "akio"
EngineBuilder::pool(pool)
```

Those are the defaults. `Engine::pool_stats()` (and the metrics endpoint) report threads, idle
threads, queue length, completed, panicked and rejected jobs, and the threads waiting in
`akio::blocking` (see below).

Choose `max_threads` by what the blocking work waits on: a database pool of 50 connections gains
nothing from 200 pool threads. Choose `queue_capacity` by how much latency you accept before
shedding load: `Overloaded` is the signal to answer "busy" (HTTP 503) instead of queueing more.

### New work and resumed work

The queue limit is where new work is turned away. The next step of work admitted already (the
next piece of a file being sent, the next message of a gRPC call whose handler is idle) is not
new work: cutting it would throw away what was done, and trying again later would need a timer.
`Pool::resume` (and `ConnInner::resume`, `Executor::resume`, `akio_quic::Connection::resume`)
queues such a step in a lane of its own: never refused while the pool runs, taken by the threads
before new work, so admitted work finishes first, and counted against the room left for new
work, so a pool busy finishing turns new work away sooner. What bounds it is its owners: each
keeps at most one step queued or running (a pump, a call, a piece). `PoolStats` reports the lane
(`resumes`) and the deepest both have been (`max_queued`).

### A pool task that waits

A pool task that waits for something only the same pool can produce would hang once every
thread waits so: a handler on the pool (`handlers_on_logical_pool`) that calls, through a
blocking client, a route of the same engine whose handlers run on the pool too, then `wait()`s.
The inner request sits in the queue behind the waiters, with no thread to run it. Wrap such a
wait in `akio::blocking(|| ...)`: while the thread waits there it counts as blocked, and queued
work that no idle thread will take gets a new thread, up to `max_threads` plus one per blocked
thread, at most `max_blocked_threads` more. When the waits end, a thread above that allowance
leaves after the job it is running, without waiting for `keep_alive`.

akio's blocking clients do it already: `ResponseFuture::wait` and `wait_timeout` (HTTP/1.1 and
HTTP/2), arpc's `CallFuture::wait`, gRPC's `unary` and `collect`, `request_blocking` and
`get` of HTTP/3, and the `*_blocking` dials. Wrap your own waits on a channel, a condition
variable or a join the same way; nested calls count once, and off a pool thread `blocking`
just runs the closure (`akio::on_pool_thread()` tells which). Doing the sub-work inline, or
starting the next stage from a completion, still needs no extra thread and is better where it
fits (rules §1).

`PoolStats` reports the threads blocked now (`blocked`), the threads started for them
(`compensated`), and the times queued work found no thread because more threads were blocked
than `max_blocked_threads` stands in for (`blocked_at_ceiling`): raise the limit, or wait less
on the pool. `max_blocked_threads = 0` turns the stand-ins off.

### Pressure: what the pool logs

A pool says when it is under pressure, through `akio-log` (target `akio-pool`, with the pool's
`name` in the message and the `pool` field), and costs nothing while it is not: no timer, no
thread. A submission that finds the backlog (new and resumed jobs waiting) past half of
`queue_capacity`, a submission refused for a full queue, and work held up by
`max_blocked_threads` each hand the pool to a watcher thread, `akio-pool-watch`, started then
and shared by every pool of the process. While some pool is watched, it samples the watched
pools every 100 ms:

- the backlog rising to 50, 75 or 90% of `queue_capacity` is a warning, to 100% (new work
  refused) an error; a level is left only once the backlog falls 10 points below it, and a
  refusal or a hit of the stand-in limit between two samples counts as 100%, so a burst the
  samples miss is still seen;
- threads blocked at the `max_blocked_threads` ceiling get a warning of their own;
- each line is logged at most once per 10 s per pool and level; the next one says how many were
  held back meanwhile;
- once the backlog has stayed under 40% for a second, with no refusal and no stand-in limit hit,
  the pool leaves with one info line summing up the episode (how long, the deepest backlog, the
  refusals, the threads started for blocked ones). When no pool is left, the watcher exits; the
  next pool past the line starts it again.

`PoolStats::warnings` counts the rises per level (50, 75, 90, 100%; held-back lines included)
and `PoolStats::watched` tells whether the pool is watched now. The metrics endpoint exports
them for the engine's pool as `akio_pool_pressure_warnings_total{level="50"|"75"|"90"|"100"}`
and `akio_pool_watched`, beside `akio_pool_resumes`, `akio_pool_max_queued`,
`akio_pool_blocked`, `akio_pool_compensated_total` and `akio_pool_blocked_at_ceiling_total`
([Observability](../observability.md)). A warning at 50% is a sign to look, not a fault; an
error at 100% means `Overloaded` answers are going out.

## A pool of your own

Blocking work of one kind that must hold up nothing else (a cache's disk tier, whose disk may
hang) gets a pool of its own, apart from the engine's: `akio::Pool`, the same bounded pool.

```rust,ignore
let mut cfg = akio::PoolConfig::default();
cfg.max_threads = 16;
cfg.queue_capacity = 4096;
let disk = akio::Pool::new(cfg);                          // Arc<Pool>
match disk.try_execute(Box::new(move || { /* read the file, then conn.run_on_loop(..) */ })) {
    Ok(()) => {}
    Err(akio::Rejected(_job)) => { /* full or shut down: answer "busy" */ }
}
// at the end: disk.shutdown(); disk.join();
```

`try_execute` never blocks; `Rejected` gives the job back when the queue is full or the pool is
shut down. `resume` queues the next step of work the pool admitted before and is refused only
once the pool is shut down (see above). `Pool::stats()` reports it as `Engine::pool_stats()` does the engine's.
Give it a `name` (`cfg.name = "disk".into()`) so its pressure logs tell it from the others;
akio's own disk pools are `akio-http-disk` and `akio-bittorrent-disk`.

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
one after another. It is set per protocol and off by default everywhere: each request then
costs a hand-off to the pool, which for handlers that never block is most of the work (HTTP/2
streams with trivial handlers: about 0.49M requests/s on the pool against 3.2M–4.0M inline on
the same 4 CPUs). Turn it on where handlers block, HTTP/2 especially, whose streams are otherwise
served one at a time on their connection's I/O thread:

```rust,ignore
let mut http = HttpConfig::default();
http.handlers_on_logical_pool = true;                         // HTTP/1.1
let mut h2 = H2Config::default();
h2.handlers_on_logical_pool = true;                           // HTTP/2 streams
http.h2 = Some(h2);
let mut h3 = H3Config::default();
h3.handlers_on_logical_pool = true;                           // HTTP/3 (akio-h3)
let grpc = GrpcServer::new().handlers_on_logical_pool(true);  // gRPC calls
let routes = Routes::new().handlers_on_logical_pool(true);    // arpc requests and notifies
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
