# ADR-130: Listeners of one backend share an I/O thread group

English | [简体中文](130-shared-io-groups.zh-CN.md)

Status: accepted (2026-11-25). Phase 1 (epoll/kqueue, per-thread loops) built; io_uring and
rounds scheduling still give each listener a group of its own.

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
   core). One HTTP and one gRPC listener on 8 cores now run 8 I/O threads, not 16.
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

## Not done (later phases)

- io_uring: a ring can poll several listeners the same way (multishot accept per listener);
  until then io_uring listeners keep groups of their own.
- Rounds scheduling (ADR-104): its workers are one pool per listener group; sharing them needs
  the listener table of point 3 in its pollers.
- UDP and datagram listeners: their loops are of another type.
