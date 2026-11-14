# Migrating from tokio

tokio is a general-purpose async runtime; flash is a network library with no runtime. They solve
overlapping problems with different shapes, and they can live in the same process.

## The mental model

| tokio | flash |
|---|---|
| a task per connection, `async fn` with `.await` points | a `Handler` per connection, callbacks (`on_data`, `on_close`) |
| work-stealing scheduler: a task may resume on any worker | thread-per-core: a connection never leaves its I/O thread |
| state lives in the task's future (often `Arc<Mutex<..>>` when shared) | state lives in the handler (`&mut self`, no lock, no `Sync`) |
| `socket.read(&mut buf).await` pulls data | `on_data(&mut self, c, data)` is pushed data |
| `socket.write_all(&buf).await` waits for buffer space | `c.send(&buf)` never waits: it writes or queues, bounded by watermarks |
| `tokio::spawn` for concurrency | concurrency is per connection; there is nothing to spawn on the I/O thread |
| `tokio::task::spawn_blocking(f).await` | `c.spawn_blocking(work, done)`: `done` runs back on the connection's thread |
| `tokio::time::timeout`, `sleep` | `Config::idle_timeout`; your own timer thread for anything else |
| `tokio::sync::mpsc` to talk to a connection task | clone the `Conn` and call `send`/`close` from anywhere |
| `CancellationToken` / dropping the task | `Conn::close()`, `Engine::shutdown()` |
| `tokio::net::TcpListener::bind` + accept loop | `Listener::tcp(addr).serve(acceptor)` |
| hyper / axum on top | flash-http on top ([guide](from-hyper-axum.md)) |

An echo server in tokio, for comparison (not compiled as part of this book):

```rust,ignore
// tokio
let listener = tokio::net::TcpListener::bind("127.0.0.1:7000").await?;
loop {
    let (mut sock, _) = listener.accept().await?;
    tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        loop {
            let n = match sock.read(&mut buf).await { Ok(0) | Err(_) => return, Ok(n) => n };
            if sock.write_all(&buf[..n]).await.is_err() { return; }
        }
    });
}
```

The flash version is the [echo example](../getting-started.md#a-tcp-echo-server): no accept
loop, no task, no buffer management; the engine reads into its per-thread buffer and calls you.

## What changes in your code

1. **Parsing becomes incremental.** You cannot `.await` "the next 4 bytes". Keep a buffer or a
   parser state machine in the handler and feed it each `on_data` slice (most protocol crates,
   and the guide's line protocol, do exactly that).
2. **No `.await` inside handlers.** Anything that waits goes elsewhere: `spawn_blocking` for
   blocking code, another thread or runtime for async code, and the reply comes back through
   the `Conn` (or `Detached`, `WsSender`, `Sink`, ...).
3. **Backpressure is explicit.** Instead of `write_all` suspending the task, watch
   `queued_bytes()`, use `hold_reads`/`on_drain` when relaying, and handle `Error::Overloaded`
   ([Backpressure](../concepts/backpressure.md)).
4. **Shared state** moves from `Arc<Mutex<..>>` captured by tasks to fields of the acceptor
   (shared, `Sync`) and fields of the handler (per connection, unshared).

## When to use the logical pool

Use `Conn::spawn_blocking` (or `Context::detach` plus your own thread) for anything that can
take more than a few microseconds of waiting or more than a fraction of a millisecond of CPU:
synchronous database drivers, file I/O, DNS resolution, compression of large bodies, password
hashing, calls to blocking SDKs. Keep parsing, routing, small serialization and in-memory
lookups inline: they are cheaper than the hand-off.

Lower `slow_callback_threshold` during development to find what you missed.

## Bridging flash and tokio

flash's handles are `Send + Sync` and its client results are `Future`s, so the two worlds can
call each other.

**From flash to async code.** Detach the request (or keep the `Conn`) and hand the job to the
other runtime through a channel; answer from there:

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:worker}}
```

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:handoff}}
```

With tokio, `start_worker` would be a runtime (`tokio::runtime::Runtime::new()`), the channel
a `tokio::sync::mpsc::UnboundedSender` (its `send` does not block, so it is safe on the I/O
thread), and the loop `while let Some(job) = rx.recv().await { tokio::spawn(..) }` with
`job.reply.respond(..)` at the end of each task. `Detached::respond`, `Conn::send`,
`WsSender::send_text` and the other handles never block, so calling them from async tasks is
fine.

**From async code to flash.** flash-http's `ResponseFuture` (HTTP/1 and HTTP/2 clients) and
flash-arpc's `CallFuture` implement `Future`: `.await` them in any executor. The connection
itself runs on flash's I/O threads; the future is completed from there and wakes your task.

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:await}}
```

The example uses a ten-line `block_on` instead of tokio to keep the repository free of a tokio
dependency:

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:block_on}}
```

**Running both in one process.** Build the flash engine, `start()` it, keep it in an `Arc`, and
run your tokio runtime as usual. Call `engine.shutdown()` from your tokio shutdown path and
`engine.wait()` from a blocking context (`spawn_blocking`), since `wait` blocks.

Things to avoid:

- calling blocking waits (`ResponseFuture::wait`, `client::dial_blocking`, `GrpcClient::unary`) from
  inside a tokio task: use `.await` where available, or `spawn_blocking`;
- calling those blocking helpers on a flash I/O thread: they can deadlock waiting for the very
  thread they block;
- `block_on` inside a flash callback.

## Async adapters

A `Future`-based adapter for flash connections (`Conn::spawn(async ..)`) is not planned before
1.0 (see the ROADMAP's non-goals). For a fully async stack, tokio with hyper/axum remains the
natural choice; flash fits where thread-per-core callbacks, explicit backpressure and
per-listener backends (io_uring, eBPF steering) are what you want.
