# Engine, listeners and backends

## The engine

An `Engine` is a set of listeners served by **groups** of I/O threads (by default the TCP
listeners of one backend share one group, ADR-130), plus a shared logical pool and a telemetry
hub. You build it with `Engine::builder()`:

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:engine}}
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
| `.threads(n)` | `n` I/O threads of its own instead of the shared ones | shared (see below) |
| `.dedicated()` | I/O threads of its own, one per core | shared (see below) |
| `.backend(Backend::..)` | `Epoll` (kqueue on macOS) or `IoUring(UringConfig)` | `Epoll` |
| `.accel(Accel::..)` | `None` or `Ebpf(EbpfConfig)` steering | `None` |
| `.balance(Balance::..)` | `LeastConnections`: a thread holding more than its share hands a new connection, before its first read, to the thread with the fewest (ADR-105); `Kernel`: keep what the socket accepted | `LeastConnections` (`Kernel` under steering or NUMA `incoming_cpu`) |

TCP listeners on epoll/kqueue with event loops **share** one group of I/O threads,
`EngineBuilder::io_threads(n)` (one per core by default), whatever their port, protocol or
handler type: an HTTP, a gRPC and an admin port on 8 cores run 8 I/O threads, not 24 (ADR-130).
Each thread polls every listener's sockets and runs the right acceptor and accept filter; each
connection stays on the thread that accepted it. A listener that sets `.threads(n)` or
`.dedicated()` gets a group of its own instead (isolation: its connections never wait behind
another listener's callbacks), and so do UDP, datagram, DPDK and BPF-steered listeners;
io_uring listeners share a group per ring options, work-stealing listeners share workers per
`WorkStealingConfig`. Removing a shared listener closes its sockets and drains its connections only;
`Engine::set_threads` on a shared listener resizes the shared group, for all its listeners.
Several listeners with different handler types, backends and thread counts can live in one
engine.

`EngineBuilder::pin_io_threads(true)` (or `AKIO_PIN_IO_THREADS=1`) pins each I/O thread to one
CPU of those the process may use, in turn over the groups (Linux). With as many busy I/O threads
as CPUs, which a shared group sized to the CPUs often is, the scheduler can otherwise leave two
of them on one CPU for a while and another CPU idle; pinned, HTTP/1.1 over 3 listeners sharing
4 threads on 4 CPUs ran as fast as with 12 dedicated threads (docs/BENCHMARKS.md). A pinned thread
cannot move away from other busy threads on its CPU, though: h2c, whose handlers run on the
logical pool by default, lost up to half its throughput pinned on the same CPUs. Turn it on for
handlers served inline on CPUs the I/O threads have to themselves. NUMA placement and BPF
steering pin their own groups.

## Backends

| Backend | Platforms | Notes |
|---|---|---|
| `Backend::Epoll` | Linux (epoll), macOS (kqueue) | The default. Each Linux thread binds its own `SO_REUSEPORT` socket and the kernel spreads connections; on macOS the threads share one listening socket. |
| `Backend::IoUring(UringConfig)` | Linux 5.19+ | Multishot accept and recv, a provided-buffer ring per thread (idle connections hold no buffer), single-issuer rings. If the kernel lacks it the listener falls back to epoll with a warning, unless `UringConfig::strict` is set. |
| `Backend::Dpdk(DpdkConfig)` | Linux (DPDK, TAP, AF_PACKET); any platform for the in-memory wire | Experimental, cargo feature `dpdk` (`dpdk-pmd` for DPDK ports). Kernel bypass: a userspace TCP/IP stack on its own I/O threads, one per NIC queue, shared by every listener on the device. See [Kernel bypass (DPDK)](../dpdk.md). |

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
{{#include ../../../../crates/akio/examples/guide-config.rs:listeners}}
```

`Engine::accel_status()` reports, per listener, `Off`, `Steering(info)` or `Degraded(reason)`.
Steering needs a `SO_REUSEPORT` socket group, so it is Linux-only; on macOS it always degrades.

Both policies have an eBPF tier when the process is privileged. It names every thread's socket in
a `REUSEPORT_SOCKARRAY`, so thread `i` serves `fds[i]` whatever order the sockets joined the
group in. The hash is the same as the classic tier's, so `ebpf::expected_index` holds for both.
`pin_threads: true` pins I/O thread `i` of `n` to the CPUs `c` with `c % n == i`; with
`Steering::Cpu`, the thread a flow is steered to then runs on the CPU that received the flow.
`SteerInfo::pinned_threads` says how many threads were pinned.

## Acceleration: XDP rate limiting

`akio::ebpf::xdp::RateLimiter` attaches an XDP program to a network interface. It gives every
source address a token bucket (`rate` packets per second, `burst` at once) and drops what exceeds
it before the kernel allocates anything for the packet. By default it counts only TCP SYNs
(connection-flood protection). `Count::AllPackets` counts every IPv4/IPv6 packet.

```rust,ignore
use akio::ebpf::xdp::{RateLimiter, XdpLimit};
let mut cfg = XdpLimit::default(); // 100 SYN/s per source, burst 200, 16384 sources
cfg.rate = 50;
let limiter = RateLimiter::attach("eth0", &cfg)?; // detached when dropped
println!("{:?} {:?}", limiter.mode(), limiter.stats()?);
```

It needs `CAP_NET_ADMIN` and `CAP_BPF`. It runs in native (driver) mode where the driver
supports it and in generic mode otherwise. It attaches with a BPF link, which the kernel removes
if the process dies, or with netlink on kernels older than 5.9, and it never replaces a program
someone else attached.

Limits:

- Buckets are per receiving CPU, so a source whose flows land on several RX queues gets `rate`
  per queue.
- Spoofed, ever-changing sources each get a fresh bucket; SYN cookies cover that case.
- The source map is a bounded LRU (`max_sources`).

## Work stealing (the default)

A TCP or Unix-domain stream listener on epoll/kqueue that does not choose runs on work stealing
(`Scheduling::WorkStealing`, ADR-104): a pool of workers (one per CPU, `WorkStealingConfig`, or
`.threads(n)` of its own) runs each round of a connection (read, callbacks, write) on whichever
worker is free, one round of a connection at a time. Per-connection state still needs no lock,
and a connection's events are still handled in order; a slow callback holds its own worker, not
the connections of a thread, and load spreads by work rather than by connection.
`Engine::set_threads` does not resize a work-stealing listener: choose
`.scheduling(Scheduling::EventLoops)` for one that should be resized. io_uring, DPDK, BPF-steered
and UDP listeners always run on event loops (below). `AKIO_DEFAULT_SCHEDULING=event-loops` makes
event loops the default (a test and diagnostic knob).

## Thread-per-core

With event loops (`Scheduling::EventLoops`, and on io_uring, DPDK, BPF steering and UDP), every
connection is owned by exactly one I/O thread from accept to close (ADR-001). That thread
reads the socket, runs your callbacks, runs the timers of its connections and flushes their
queues. Consequences:

- Your per-connection state needs no lock and no `Sync`.
- Events of one connection are handled in order, one at a time.
- A slow callback delays every other connection on that thread. This is why callbacks must not
  block, and why `akio` measures callbacks and reports slow ones (see
  [Observability](../observability.md)).
- Load is balanced per connection, not per request: a hot connection cannot move to an idle
  thread. Steering (above) controls the initial placement.

Client connections created with `Engine::dial` run on the threads added with
`EngineBuilder::client_threads(n)`, or, without them, on the threads of the last listener added.
UDP dials (`Engine::dial_udp`) need `udp_client_threads(n)` or a UDP listener.
