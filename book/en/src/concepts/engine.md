# Engine, listeners and backends

## The engine

An `Engine` is a set of listeners, each served by its own **group** of I/O threads, plus a
shared logical pool and a telemetry hub. You build it with `Engine::builder()`:

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-basics.rs:engine}}
```

- `build()` validates the configuration, binds every listener (so port conflicts fail here) and
  prepares the threads. Nothing runs yet.
- `start()` spawns the I/O threads and returns. It is idempotent.
- `wait()` blocks until a `shutdown()` has completed; `run()` is `start()` + `wait()`.
- `Engine` is `Send + Sync`. Put it in an `Arc` when other threads need to call `shutdown`,
  `dial`, `metrics` or `reload` while `wait` blocks.
- `local_addrs()` returns the bound addresses in the order the listeners were added (port 0
  resolved). Client-only thread groups (`client_threads`, `udp_client_threads`) come after them
  and show the unspecified address.

## Listeners

`Listener::tcp(addr)` or `Listener::udp(addr)`, then:

| Method | Meaning | Default |
|---|---|---|
| `.serve(acceptor)` | who handles the connections (required) | none: `build` fails |
| `.threads(n)` | I/O threads of this listener | one per core |
| `.backend(Backend::..)` | `Epoll` (kqueue on macOS) or `IoUring(UringConfig)` | `Epoll` |
| `.accel(Accel::..)` | `None` or `Ebpf(EbpfConfig)` steering | `None` |

Each listener gets its own threads; listeners never share an I/O thread. Several listeners with
different handler types, backends and thread counts can live in one engine.

## Backends

| Backend | Platforms | Notes |
|---|---|---|
| `Backend::Epoll` | Linux (epoll), macOS (kqueue) | The default. Each Linux thread binds its own `SO_REUSEPORT` socket and the kernel spreads connections; on macOS the threads share one listening socket. |
| `Backend::IoUring(UringConfig)` | Linux 5.19+ | Multishot accept and recv, a provided-buffer ring per thread (idle connections hold no buffer), single-issuer rings. If the kernel lacks it the listener falls back to epoll with a warning, unless `UringConfig { strict: true, .. }`. |

UDP listeners are always served by the readiness backend (epoll/kqueue): with `recvmmsg` /
`sendmmsg` and GSO the batching that io_uring would bring is already there. Asking for
`IoUring { strict: true }` on a UDP listener fails `build`.

`UringConfig` has `entries` (submission queue depth, 0 = default), `sqpoll` (a kernel polling
thread) and `strict`.

Which backend to pick is a measurement question; see [Performance tuning](../performance.md).
In the benchmark report io_uring was within a few percent of epoll when the client was the
bottleneck and 10–25% ahead when the server was.

## Acceleration: eBPF steering

`Accel::Ebpf(EbpfConfig)` attaches a `SO_REUSEPORT` program that chooses which I/O thread gets a
new TCP connection or UDP peer: `Steering::Cpu` (the CPU that received the packet, `cpu %
threads`) or `Steering::Hash` (a Maglev-style consistent hash of the source IP, or IP and port).
It works with any backend. Classic BPF needs no privileges; eBPF programs are used when the
process is privileged. When nothing can be attached the listener keeps the kernel's default
hashing and reports why; `strict: true` turns that into a build error.

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-config.rs:listeners}}
```

`Engine::accel_status()` reports, per listener, `Off`, `Steering(info)` or `Degraded(reason)`.
Steering needs a `SO_REUSEPORT` socket group, so it is Linux-only; on macOS it always degrades.

## Thread-per-core

Every connection is owned by exactly one I/O thread from accept to close (ADR-001). That thread
reads the socket, runs your callbacks, runs the timers of its connections and flushes their
queues. Consequences:

- Your per-connection state needs no lock and no `Sync`.
- Events of one connection are handled in order, one at a time.
- A slow callback delays every other connection on that thread. This is why callbacks must not
  block, and why flash measures callbacks and reports slow ones (see
  [Observability](../observability.md)).
- Load is balanced per connection, not per request: a hot connection cannot move to an idle
  thread. Steering (above) controls the initial placement.

Client connections created with `Engine::dial` run on the threads added with
`EngineBuilder::client_threads(n)`, or, without them, on the threads of the last listener added.
UDP dials (`Engine::dial_udp`) need `udp_client_threads(n)` or a UDP listener.
