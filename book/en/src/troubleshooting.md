# Troubleshooting and FAQ

## "slow callback: ... blocked its I/O thread"

A callback ran longer than `slow_callback_threshold` (100 ms by default). Every other connection
on that thread waited meanwhile. Find the callback kind and connection in the message (or
`Engine::slow_callbacks()`, the debug endpoint's `slow` view) and move the blocking part to
`spawn_blocking`, `Context::detach` or another thread. Common culprits: synchronous database or
HTTP clients, file reads, DNS resolution (`ToSocketAddrs`), `Mutex`es contended with other
threads, logging to a slow sink, a static-file cache miss on a large file.

## Latency spikes for everyone on one thread

Same cause as above, below the threshold. Compare `akio_loop_callback_seconds_total` between
threads; a hot connection cannot move to another thread, so consider `Steering::Hash` /
`Steering::Cpu` placement or splitting traffic across more connections.

## `Error::Overloaded`

From `send*`: the connection already has `max_queued_bytes` queued: the peer does not read fast
enough. Pause producing (`queued_bytes()`, `on_drain`) or close it. From `spawn_blocking`: the
logical pool queue is full. Shed load (HTTP 503) or raise `PoolConfig` limits if the work is
legitimately bursty.

## `Error::Closed` from a `Conn` I kept

The connection closed (peer gone, idle timeout, error). This is the normal signal to stop;
handles never panic and never touch a reused descriptor.

## Responses come out of order

Mixing ordered slots with plain sends: `Conn::send` is not held behind reserved but unfilled
`ResponseSlot`s. Use slots for every reply of an ordered protocol. (akio-http does this for you.)

## A connection closed by itself right after a request

- A `ResponseSlot` or `ResponseStream` was dropped without being filled/finished: `akio` closes
  the connection, because the reply stream cannot continue.
- An HTTP handler neither responded nor detached: the client got a 500.
- A callback panicked: the connection is closed and `on_close` receives the error. Use
  `middleware::recover()` in HTTP to turn panics into 500s.

## `build()` fails

- `listener without .serve(..)`: every listener needs an acceptor.
- `Address already in use`: another process has the port. Give each TCP listener its own
  address; a TCP and a UDP listener on the same port number are fine (HTTP/1+2 and HTTP/3 on
  443, for example).
- `... is not supported`: `strict` io_uring or eBPF on a kernel or platform without it, or UDP on
  io_uring with `strict`.

## io_uring is not used

The kernel lacks it (older than 5.19, or disabled by `kernel.io_uring_disabled` / a seccomp
profile, as in many containers): `akio` logs `io_uring unavailable (...); using epoll`. Set
`UringConfig::strict` to fail instead.

## eBPF steering shows `Degraded`

Not Linux, no `SO_REUSEPORT` socket group (macOS, or a single-thread listener), or the program
could not be attached. Classic BPF needs no privileges; eBPF programs need `CAP_BPF` /
`CAP_SYS_ADMIN`. The reason string says which.

## No log output

`akio` logs through `akio::log`; install a logger (`akio::log::init(akio::log::LevelFilter::Info)`),
or enable the `log` feature to use a `log` crate logger such as env_logger. Without one, only
errors and slow-callback warnings are printed (to stderr). Access logs need `observe::access_log()` and the
`akio_http::access` target enabled.

## Tests or tools hang on macOS

Small default socket buffers on macOS make single-threaded blocking test clients deadlock when
they write a lot before reading. Read and write from separate threads, or read in a loop.

## FAQ

**Is `akio` async? Can I use it with tokio?** `akio` is callback-based and has no runtime. Its
handles are `Send + Sync`, its client futures can be awaited from any executor, and work can be
handed to tokio and answered from there. See [Migrating from tokio](migration/from-tokio.md).

**Can a connection move to another thread?** No. That is what makes handler state lock-free.

**Why is my handler not `Sync`?** It does not need to be: only its own I/O thread touches it.

**Does `akio` support Windows?** No (no IOCP backend is planned before 1.0).

**Is DPDK supported?** Not yet; it is planned (milestone M6).

**How do I serve HTTP and HTTPS on one port?** Use akio-mux with `Rule::Tls` routed to
`Tls::server(cfg, serve(app))` and `Rule::Http` routed to `serve(app)`.

**How do I get the client IP behind a proxy?** `ctx.peer()` is the TCP peer; read
`X-Forwarded-For` / `Forwarded` yourself when you trust the proxy.
