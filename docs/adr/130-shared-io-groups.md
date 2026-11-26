# ADR-130: Listeners of one backend share an I/O thread group

English | [简体中文](130-shared-io-groups.zh-CN.md)

Status: accepted (2026-11-25). Phase 1 (epoll/kqueue, per-thread loops), phase 2 (rounds
scheduling) and phase 3 (io_uring) built.

## Context

ADR-004 lets each listener pick its backend, and the engine has so far given every listener a
group of I/O threads of its own, one per core by default (`Listener::threads`). A service with
an HTTP port, a gRPC port and an admin port on 8 cores therefore ran 24 I/O threads, three per
core, each set idle most of the time and all of them competing for the same cores when busy.
Nothing requires it: an epoll/kqueue loop can poll any number of listening sockets, and
listeners on the same backend differ only in their acceptor, their accept filter and whether
they are Unix-domain sockets. Only listeners on different backends (or schedulings) cannot run
on one loop.

## Decision

1. **Listeners share by default.** At build time and in `Engine::add_listener`, a TCP listener
   (bound, inherited or Unix-domain) joins the engine's shared group for its key: backend,
   scheduling and accept-time balancing (`Balance`). The engine creates that group with the
   first listener of the key and sizes it with `EngineBuilder::io_threads(n)` (default: one per
   core). One HTTP and one gRPC listener on 8 cores now run 8 I/O threads, not 16. With rounds
   scheduling (ADR-104) the key is the resolved `RoundsConfig` (pollers and workers), which
   also sizes the group: listeners with one configuration share its workers and pollers.
2. **A listener can still have its own group.** `Listener::threads(n)` (any explicit count) or
   the new `Listener::dedicated()` (one per core) keeps the ADR-004 arrangement for that
   listener: isolation for an admin port or a latency-critical protocol, or a size of its own.
   Listeners that need per-listener threads always get their own group: BPF steering
   (`Accel::Ebpf`, whose program steers to the listener's own sockets), UDP and datagram
   listeners and DPDK (other loop types).
3. **One loop, several listeners.** An epoll/kqueue loop keeps, per listener of its group, the
   acceptor, the accept filter, whether it is Unix-domain and whether it was removed, and polls
   the listener's sockets under a token that names the listener and the socket. Accepting runs
   the right filter and acceptor; each connection remembers its listener. On Linux each listener
   still has one `SO_REUSEPORT` socket per thread, elsewhere clones of one socket, and thread
   resizing (ADR-028) moves each listener's sockets as before.
4. **Removing one listener affects only it** (ADR-099). `remove_listener` closes its sockets on
   every thread; `shutdown_listener(id, drain)` runs `on_shutdown` for that listener's
   connections and closes those still open after `drain`. The group's threads keep serving the
   other listeners and stay up, even with none left, until the engine shuts down.
5. **The engine's per-listener API keeps its meaning.** `local_addrs`, `listeners`, `threads`
   and the `ListenerId`s still have one entry per listener. `threads()` reports the shared
   group's size for each of its listeners, and `set_threads(i, n)` / `set_listener_threads(id,
   n)` on a shared listener resize the shared group, for all of its listeners. Dials (`dial`
   without client threads) go to the last listener's group as before, shared or not.
6. **Telemetry.** A shared group's threads have no single listener: `LoopMeta::listener` is
   `None` for them, and `ConnInfo::owner.listener` names the listener each accepted connection
   came from. Per-thread counters (`accepted`, `filtered`, ...) count all of the group's
   listeners.

## Consequences

- Fewer threads by default: one set per backend instead of one per listener, so the cores are
  not oversubscribed by idle loops and a busy listener can use every thread.
- Less isolation by default: a slow inline handler of one listener delays the connections of
  the others on its thread. Blocking work belongs on the logical pool anyway (rules §1; HTTP/2
  handlers run there by default since 2026-11-25); `Listener::dedicated()` restores isolation.
- Listeners with explicit `threads(n)`, the common case in tests and tuned deployments, behave
  exactly as before.
- `set_threads` on one listener can now change the threads of others; the docs say so.
- The `Group` trait gains keyed listener operations (backend-facing, `#[doc(hidden)]`).

## Phase 2: rounds scheduling (built 2026-11-25)

A rounds group's listening sockets were already accept jobs of their own, each with its
acceptor. A shared rounds group keeps a listener table (each listener's accept jobs and accept
filter); a listener added later gets accept jobs posted to the pollers (`RCmd::AddJob`), which
register them; each connection remembers its listener, so removing one listener closes its
accept jobs and drains its connections only (`RCmd::StopListening` names it), and the
connection table names each connection's listener. Unix-domain listeners join too: their
accept jobs accept without reading an address (2026-11-26; until then a Unix-domain listener
with rounds scheduling was bound as a TCP one, at its unspecified address).

## Phase 3: io_uring (built 2026-11-26)

An io_uring loop keeps the same listener table as an epoll loop and arms one multishot accept
per listening socket, its `user_data` naming listener and socket. Removing a listener cancels
its accepts and takes its `SO_REUSEPORT` sockets out of the address's group; what a cancelled
accept still delivers is served by that listener's acceptor (and, with a drain, shut down after
its first data), and only its connections are drained. io_uring listeners share a group per
ring options (`UringConfig::entries`, `sqpoll`), sized by `EngineBuilder::io_threads`; where
io_uring is unavailable they fall back to the shared epoll group (or fail with `strict`), as a
listener of its own falls back.

## Follow-up: pinning I/O threads (2026-11-26)

A shared group sized to the CPUs has exactly as many busy I/O threads as CPUs, and unpinned the
scheduler sometimes leaves two of them on one CPU for most of a run while another CPU idles
(measured on gpu51: two of the 4 threads on one CPU in up to 19 of 20 samples, HTTP/1.1 over 3
listeners 10% to 20% slower in those runs). Dedicated groups hid it by oversubscribing the CPUs
(12 threads on 4). `EngineBuilder::pin_io_threads` (or `AKIO_PIN_IO_THREADS=1`), off by default,
pins each I/O thread to one allowed CPU in turn over the groups; groups NUMA placement or BPF
steering pin are left alone. It is not the default: pinned threads cannot get out of the way of
other busy threads on their CPUs. Measured (docs/BENCHMARKS.md): pinned, HTTP/1.1 over 3
listeners sharing 4 threads matched 12 dedicated threads with a 1% spread; h2c, whose handlers
run on the logical pool on the same CPUs, fell by up to half. Served inline (`run_on_pool` off),
h2c pinned was the fastest configuration (4.0M requests/s), which puts the drop on the pool.
`EngineBuilder::reserve_pool_cpus(n)` gives the pool CPUs of its own when pinning; it helped
pooled h2c on io_uring and not on epoll, so it is a tool to measure with, not a recommendation.

## Not done

- UDP and datagram listeners: their loops are of another type.
