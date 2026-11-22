# Handlers, acceptors and `Conn`

## The handler is the connection state

```rust,ignore
pub trait Handler: Send + Sized + 'static {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]);
    fn on_close(&mut self, c: &Conn<Self>, err: Option<Error>) {}
}
```

One handler value exists per connection. It is created on the connection's I/O thread and only
ever touched there, so it must be `Send` (it is created once and stays) but not `Sync`: plain fields,
`Cell`/`RefCell`, buffers and parsers are all fine (`Rc` is not, since it is not `Send`) (ADR-003).

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:handler}}
```

- `on_data` receives bytes as they arrive. TCP is a byte stream: one call may hold part of a
  message or several messages, so frame them yourself (or use a protocol crate). `data` borrows
  the I/O thread's read buffer (or an io_uring provided buffer) and is valid only during the call.
  At most `Config::read_buffer` bytes arrive per call (16 KiB on io_uring).
- `on_close` runs exactly once, after every `on_data`. `err` is `None` for an orderly close
  (peer EOF after pending output drained, or a local `close`), `Some(Error::Io(..))` otherwise,
  for example `TimedOut` from the idle timeout.
- A panic inside a callback closes that connection (and is reported to `on_close`); the I/O
  thread keeps running.

## The acceptor creates handlers

```rust,ignore
pub trait Acceptor: Send + Sync + 'static {
    type Handler: Handler;
    fn on_open(&self, c: &Conn<Self::Handler>) -> Self::Handler;
    fn on_shutdown(&self, c: &Conn<Self::Handler>) {}
    fn transport(&self) -> Option<Box<dyn Transport>> { None }
}
```

The acceptor is shared by all I/O threads of a listener (hence `Sync`). `on_open` runs on the
owning I/O thread for every accepted or dialed connection and returns its handler; it may
already `send`. `on_shutdown` is called for each open connection during a graceful shutdown.
`transport` layers a byte-stream transformation (TLS) under every connection; see
[TLS](../protocols/tls.md).

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:acceptor}}
```

For the common case where the acceptor holds nothing, wrap a closure with `fn_acceptor`:

```rust,ignore
Listener::tcp(addr).serve(fn_acceptor(|_c: &Conn<Echo>| Echo))
```

(A blanket `impl Acceptor for Fn(&Conn<H>) -> H` is impossible in Rust's coherence rules, hence
the wrapper.)

## `Conn`: a thread-safe handle

`Conn<H>` is `Clone + Send + Sync` for any `H` (ADR-002). The type parameter only types the
`spawn_blocking` completion; the handle itself is an `Arc` to the shared connection state.

| Method | What it does |
|---|---|
| `send(&[u8])` | Writes now if the socket takes it, queues (copies) the rest. Never blocks. |
| `send_owned(Vec<u8>)` | Same, without copying what must be queued. |
| `send_shared(SharedBuf)` | Same with a reference-counted buffer: encode a broadcast once. |
| `send_segments(Vec<u8>, size)` | UDP: several datagrams at once (GSO / `sendmmsg` where Linux allows); TCP: `send_owned`. |
| `cork()` / `flush()` | Coalesce writes until `flush` (inside callbacks this is automatic). |
| `close()` | Close now, discarding unsent data. |
| `close_after_send()` | Close once everything queued is written; later sends fail. |
| `hold_reads(bool)` | Pause / resume reading from the peer. |
| `on_drain(f)` | Call `f` once the send queue is empty (or the connection closed). |
| `queued_bytes()` | Bytes accepted but not yet written. |
| `spawn_blocking(work, done)` | Run `work` on the logical pool, `done` back on the I/O thread. |
| `reserve_response()` | Reserve an ordered response position. |
| `id()`, `is_open()`, `peer_addr()`, `local_addr()` | Identity and state. |
| `with_transport(f)` | Inspect the transport layer (see `akio::tls::tls_info`). |

Using a handle after the connection closed returns `Error::Closed`: it never panics and never
touches a recycled file descriptor. The descriptor is released when the connection is closed
*and* every handle is dropped.

### Sending from other threads

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:cross_thread}}
```

On the owning thread `send` writes directly when nothing is queued. From another thread it takes
the connection's write lock, tries the same direct write, queues what is left and wakes the
owning loop to flush it. The lock covers only the send queue and is never held while your code
runs, so there is no lock-ordering deadlock to worry about.

Everything sent inside a callback (`on_open`, `on_data`, a `spawn_blocking` completion) is
corked: it leaves in one `writev` when the callback returns.

### Errors

`Conn` operations return `akio::Result<T>` with `akio::Error`:

| Variant | Meaning |
|---|---|
| `Closed` | The connection is closed or closing; nothing happened. |
| `Overloaded` | The send queue is over `Config::max_queued_bytes`, or the logical pool queue is full. |
| `Io(io::Error)` | An OS error (the connection is being closed). |

## Rules of thumb

- Never block in a callback: no blocking I/O, no `Mutex` held for long, no `thread::sleep`, no
  waiting on a channel. Use `spawn_blocking` or another thread plus a cloned `Conn`.
- Keep per-connection state in the handler; keep shared state in the acceptor (behind `Arc`
  and `Sync` types).
- Copy `data` if you need it after the callback.
