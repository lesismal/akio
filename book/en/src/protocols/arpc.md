# arpc

`flash-arpc` speaks the wire format of [lesismal/arpc](https://github.com/lesismal/arpc) and
fib's `arpc` package, so it talks to Go peers of either (checked in both directions by
`tools/interop/arpc/run.sh`).

Every connection is a `Peer` on **both** ends: either side can call, notify or open streams, and
each serves the other's calls with the `Routes` it was given.

## Server

```rust,ignore
{{#include ../../../../crates/flash-arpc/examples/guide-arpc.rs:server}}
```

`Routes`:

| Builder | Meaning |
|---|---|
| `handle(method, Fn(&mut Context))` | serve calls and notifies of `method`; `""` is the fallback for unknown methods (otherwise they get "method not found") |
| `handle_stream(method, open)` | serve streams the peer opens: `open(&Stream)` returns the `FnMut(&Stream, StreamEvent)` that receives `Message(bytes)` and `Eof` |
| `on_connected(Fn(&Peer))`, `on_disconnected(Fn(&Peer))` | connection events |
| `max_body_bytes(n)` | longest method + payload accepted (64 MiB); longer closes the connection |

In a handler, `Context` gives `method()`, `body()`, `is_notify()`, `peer()`, and answers with
`write(payload)` or `error(text)`, or `detach()` → `Responder` (`write` / `error` later, from any
thread). Handlers run on the I/O thread and must not block.

`Server` (cloneable): `broadcast(method, payload)` sends a notify to every connected client with
one shared encoded frame; `peers()` lists them.

## Client

```rust,ignore
{{#include ../../../../crates/flash-arpc/examples/guide-arpc.rs:client}}
```

`flash_arpc::dial_blocking(&engine, addr, routes)` blocks until the first connection is up (10 s at most)
and then **keeps reconnecting** every second until `Peer::close()`.

`Peer` (cloneable, any thread):

| Method | Meaning |
|---|---|
| `call(method, payload, timeout) -> CallFuture` | `wait()` (or `.await`) for `Result<Vec<u8>, CallError>` |
| `call_async(method, payload, timeout, done)` | callback form |
| `notify(method, payload) -> bool` | one-way message |
| `new_stream(method, on_event) -> Stream` | `send`, `close_send`, `id`, `method`, `peer` |
| `is_connected()`, `peer_addr()`, `close()` | state |

`CallError`: `Remote(text)` (the peer answered with an error), `Closed`, `Timeout`.

Payloads are bytes. Go peers send `string` and `[]byte` as they are and other values
JSON-encoded by default; encode and decode on the Rust side accordingly.

Not done: the middleware/coder chain of Go arpc, client pools.
