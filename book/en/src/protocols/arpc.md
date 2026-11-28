# arpc

`akio-arpc` speaks the wire format of [lesismal/arpc](https://github.com/lesismal/arpc) and
fib's `arpc` package, so it talks to Go peers of either (checked in both directions by
`tools/interop/arpc/run.sh`).

Every connection is a `Peer` on **both** ends: either side can call, notify or open streams, and
each serves the other's calls with the `Routes` it was given.

## Server

```rust,ignore
{{#include ../../../../crates/akio-arpc/examples/guide-arpc.rs:server}}
```

`Routes`:

| Builder | Meaning |
|---|---|
| `handle(method, Fn(&mut Context))` | serve calls and notifies of `method`; `""` is the fallback for unknown methods (otherwise they get "method not found") |
| `handle_stream(method, open)` | serve streams the peer opens: `open(&Stream)` returns the `FnMut(&Stream, StreamEvent)` that receives `Message(bytes)` and `Eof` |
| `on_connected(Fn(&Peer))`, `on_disconnected(Fn(&Peer))` | connection events |
| `max_body_bytes(n)` | longest method + payload accepted (64 MiB); longer closes the connection |
| `max_streams_per_conn(n)` | most streams the peer may have open on one connection (1024); a stream opened past it is ended at once, like one for a method not served |
| `call_timeout(Option<Duration>)` | timeout of calls made with `timeout: None` on connections using these routes (30 s); `None` lets them wait until the connection closes |
| `max_pending_calls(n)` | most calls one connection may have waiting for their answer (65536); a call past it fails at once with `CallError::Overloaded` |
| `middleware(Fn(&mut Context, Next))`, `method_middleware(method, ...)` | wrap handlers (below) |
| `coder(impl Coder)` | transform frames on the wire (below) |

In a handler, `Context` gives `method()`, `body()`, `is_notify()`, `peer()`, `values()` /
`values_mut()`, `responded()`, and answers with
`write(payload)` or `error(text)`, or `detach()` → `Responder` (`write` / `error` later, from any
thread). Handlers run on the I/O thread and must not block.

`Server` (cloneable): `broadcast(method, payload)` sends a notify to every connected client with
one shared encoded frame; `peers()` lists them.

## Client

```rust,ignore
{{#include ../../../../crates/akio-arpc/examples/guide-arpc.rs:client}}
```

`akio_arpc::dial_blocking(&engine, addr, routes)` blocks until the first connection is up (10 s at most)
and then **keeps reconnecting** every second until `Peer::close()`.

The engine's graceful shutdown (`Engine::shutdown`) ends every arpc connection, client and server
alike, once its work is done: calls already sent wait for their answers and calls being served are
answered, while new calls fail with `CallError::Closed` unsent (`notify` returns `false`), the
other side's new calls are answered with `SERVER_BUSY`, `is_connected()` turns `false` and a
client stops reconnecting. The connection closes at once when nothing is in flight; open streams
end (`StreamEvent::Eof`) when it closes.

`Peer` (cloneable, any thread):

| Method | Meaning |
|---|---|
| `call(method, payload, timeout) -> CallFuture` | `wait()` (or `.await`) for `Result<Vec<u8>, CallError>`; `timeout: None` uses the routes' `call_timeout` (30 s) |
| `call_async(method, payload, timeout, done)` | callback form: `done` runs on the connection's I/O thread for an answer or the connection's loss (it must not block), at once when the call is not sent, and for `Timeout` on the callbacks thread (`akio-arpc-callbacks`, one per process), never on the thread that fires deadlines, so a blocking `call(..).wait()` there is safe |
| `call_with`, `call_async_with`, `notify_with` | the same with `Values` for the coders |
| `notify(method, payload) -> bool` | one-way message |
| `new_stream(method, on_event) -> Stream` | `send`, `close_send`, `id`, `method`, `peer` |
| `is_connected()`, `peer_addr()`, `pending_calls()`, `ping()`, `close()` | state |

`CallError`: `Remote(text)` (the peer answered with an error), `Closed`, `Timeout`, `Overloaded`
(too many calls pending on the connection; not sent).

Payloads are bytes. Go peers send `string` and `[]byte` as they are and other values
JSON-encoded by default; encode and decode on the Rust side accordingly.

## Middleware and coders

```rust,ignore
{{#include ../../../../crates/akio-arpc/examples/guide-arpc.rs:middleware}}
```

**Middleware** wraps the handler of every request and notify: global middleware
(`Routes::middleware`) runs first, in the order added, then the method's own
(`method_middleware`), then the handler (or "method not found"). A middleware gets the
`Context` and `Next`: what it does before `next.run(ctx)` happens before the handler, what it
does after happens once the handler has answered; returning without `next.run` aborts the chain
(answer with `ctx.error` first). Unlike Go's `Handler.Use`, the order does not depend on when a
middleware is registered relative to the handlers. Values set with `ctx.values_mut()` are seen by
later middleware and the handler. A client's routes serve the calls its server makes, so
middleware works the same on both sides. Streams have no middleware (as in Go). Routes with no
middleware call the handler directly, with no cost.

**Coders** (`akio_arpc::coder`) rewrite whole frames, as Go's `MessageCoder`: frames sent go
through the coders in the order added, frames received in the opposite order, so both ends need
the same chain. Each coder marks its work in a bit of the reserved header byte, the same bits as
Go's `arpcex/extension/middleware/coder`:

| Coder | Go counterpart | What it does |
|---|---|---|
| `Gzip::new(threshold)` (`.level(..)`) | `coder/gzip.New(threshold)`, bit 7 | gzip everything after the reserved byte of frames longer than `threshold`, if smaller; received frames are inflated **at most to `max_body_bytes`** (a bomb closes the connection) |
| `Appender::new(name, bit)` | `coder.NewAppender(name, bit, ...)`; tracing uses bit 0 | appends the message's value `name` (name, value, 2-byte length) and stores it in the receiver's `Values` |

A response is coded with the request's values, so an appender echoes them back (as in Go). Write
your own by implementing `Coder` (`encode(&mut Vec<u8>, &Values)`, `decode(&mut Vec<u8>, &mut
Values, max_body) -> Result<(), CoderError>`; `flag_bit` / `set_flag_bit` help, the body length
is fixed up after each coder). A decode error closes the connection. Pings and pongs are not
coded.

## Pools

```rust,ignore
{{#include ../../../../crates/akio-arpc/examples/guide-arpc.rs:pool}}
```

`Pool::builder()` dials `size` connections (4) sharing one `Routes` and returns once all are up
(`connect_timeout`, 10 s; if one fails, the others are closed). `pool.call` / `call_with` /
`call_async` / `notify` pick a connection that is up: `Balance::RoundRobin` (default, a per-thread
cursor, so picking shares no counter) or `Balance::LeastPending` (fewest calls waiting). Lost
connections reconnect every `reconnect_interval` (1 s) and are skipped meanwhile; with none up,
calls fail at once with `Closed`. `heartbeat(Some(interval))` (15 s) pings each connection and
closes one whose ping got nothing back within an interval, so a silent peer is replaced. Each
connection keeps its own `max_pending_calls` and every call its deadline. `peer()`, `peers()`,
`connected()`, `close()`.
