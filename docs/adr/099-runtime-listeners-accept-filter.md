# ADR-099: TCP listeners added, removed and drained at run time, and a filter on accepted connections

English | [简体中文](099-runtime-listeners-accept-filter.zh-CN.md)

Status: accepted (2026-11-23)

## Context

A gateway reloads its configuration without a restart: listeners appear, disappear or change
their TLS settings, and the connections of a listener that goes away either keep running or are
drained. fib, under fit, has `AddBinding`, `RemoveBinding` and `ShutdownBinding` for that, and
`Binding.Filter` for allow / deny lists checked on accept. akit, the Rust counterpart of fit on
`akio`, asked for both (akit `docs/akio-api-requests.md`, A1 and A3).

`akio` fixed its TCP listeners at `EngineBuilder::build`. At run time it had `bind_udp`,
`adopt_tcp` (a stream accepted elsewhere), thread resizing (`set_threads`, ADR-028) and
engine-wide `shutdown`, but no listener of its own could be added or closed, and nothing ran
between `accept` and the acceptor except the `max_connections` check.

`akio` is at 1.0.0-rc.1: what changes must be additive. `Engine::local_addrs`, `threads`,
`accel_status` and `set_threads` name listeners by build index, and `accel_status` returns a
borrowed slice, so they cannot grow at run time without a breaking change.

## Decision

### Listener ids

1. **`ListenerId`**: an opaque, copyable id (`ListenerId::get() -> u64`). The listeners given
   to the builder get ids `0..n` in the order they were added (their index in `local_addrs`);
   listeners added at run time get the next ones. Ids are never reused within an engine.
2. **`Engine::listeners() -> Vec<ListenerInfo>`**: the TCP listeners still accepting, build-time
   ones first, then added ones, each with `id`, `local_addr`, `threads` and `accel`
   (`AccelStatus`). UDP and datagram listeners are listed too (`udp: true`) so the ids line up
   with `local_addrs`, but only TCP listeners can be removed or filtered.
3. The index-based methods keep covering exactly what the builder made (listeners, then client
   groups), unchanged: a removed build-time listener stays in `local_addrs` / `threads` (its
   index is stable, its thread count drops to 0 as its threads leave). Runtime listeners are
   reached by id only: `Engine::set_listener_threads(id, n)` is `set_threads` by id (any TCP
   listener).

### Adding

4. **`Engine::add_listener(Listener) -> io::Result<ListenerId>`** binds a TCP listener the way
   `build` does, with the same code: its backend (epoll / kqueue / io_uring, with the io_uring
   fallback and `strict`), `AKIO_DEFAULT_BACKEND` read once at build (ADR-029), its thread count
   (one `SO_REUSEPORT` socket per thread on Linux, one shared socket elsewhere), an inherited
   socket (`Listener::tcp_from_std`), `Accel::Ebpf` steering (strict or degraded, reported in
   `ListenerInfo::accel`), the engine's `Config` and live settings, its pool and telemetry, and
   NUMA placement when the engine places threads (the `NumaReport` keeps describing the build).
   When the engine has started, the new threads start at once; before `start`, `start` starts
   them. Bind errors come back from the call, as from `build`.
5. Refused: UDP and datagram listeners (`InvalidInput`: `bind_udp` is the run-time UDP API),
   DPDK listeners (`Unsupported`: their I/O threads are shared by device), a listener without
   `serve` (`InvalidInput`), after `shutdown` (`NotConnected`), and past the limit below.
6. **Limit** (rule 10): `EngineBuilder::max_listeners(n)`, default 1024, counts the listeners
   accepting (of every kind) plus the removed ones whose threads are still serving connections
   (they hold threads). `add_listener` past it fails with `io::ErrorKind::QuotaExceeded`. Build-time
   listeners count, the limit does not apply to the builder itself.

### Removing and draining

7. **`Engine::remove_listener(id)`**: the listener stops accepting and its listening sockets are
   closed; its open connections keep running untouched, on the threads that own them
   (connections never move, ADR-001). Each I/O thread exits once its last connection is closed.
8. **`Engine::shutdown_listener(id, drain: Duration)`**: the same, and every open connection of
   the listener gets `Acceptor::on_shutdown` at once (as in an engine shutdown: an HTTP server
   sends `Connection: close` / GOAWAY), and those still open after `drain` are closed
   (`on_close` runs). `Duration::ZERO` closes them on the next loop iteration.
9. Both return once every I/O thread of the listener has handled the command, waiting up to a
   second for a busy one (`Group::await_unlisted`, called with the engine's lock released;
   called on an I/O thread they do not wait, rule 1). A thread closes its listening socket
   (epoll / kqueue) or, on io_uring, first takes it out of listening with `shutdown(SHUT_RD)`,
   since its multishot accept keeps it open until its cancellation completes, and an
   `SO_REUSEPORT` socket still listening meanwhile would take a share of the new connections,
   to reset them when it closes. Connections the kernel had queued on it and not yet accepted
   are reset, as when any listening socket closes. To replace a listener without a gap, add the
   new one first: on Linux both share the port (`SO_REUSEPORT`) until the old one is removed,
   and once removal returns new connections go to the new one only. Binding the same address
   again after a removal succeeds once the old sockets are closed (within a loop iteration).
   A first version returned once the command was posted, and io_uring kept the old sockets
   listening until the cancellations completed: akit's reload, replacing a listener at its
   address, had a first request reset in about one run in four on io_uring (and, more rarely,
   on epoll).
10. The threads of a removed listener that also serve `dial` / `adopt_tcp` (the last TCP
    listener of the builder when there are no `client_threads`) stay up for those until the
    engine shuts down; `shutdown_listener` on it drains dialed connections too, since they run
    on the same threads. Applications that add and remove listeners should set
    `client_threads`.
11. Errors: `NotFound` for an unknown or already removed id, `Unsupported` for UDP / datagram /
    DPDK listeners. The groups of removed listeners are joined when their threads have exited
    (on the next listener call, and by `wait`), and their per-thread counters leave
    `Metrics::loops`; their totals are kept in `Metrics::total`, which therefore never goes back.
12. `Engine::wait` blocks until `shutdown` was called and every thread, the added listeners' ones
    included, has exited; an engine with no listener at all (one meant to get them at run time)
    now waits for `shutdown` as well instead of returning at once.

### The accept filter

13. **`Listener::filter(Fn(&SocketAddr) -> bool + Send + Sync + 'static)`**: called on the I/O
    thread with the peer's address right after `accept`, before the `max_connections` check,
    the acceptor's `on_open` and any transport (TLS) work; `false` closes the stream at once.
    A filter that panics refuses the connection (and is logged). Refused connections are counted
    per thread in the new counter `LoopCounters::filtered` (`akio_connections_filtered_total`);
    they are not counted as accepted.
14. **`Engine::set_listener_filter(id, f)`** / **`clear_listener_filter(id)`** swap it at run time,
    in force for every `accept` that starts after the call returns (a deny takes effect at once,
    on every thread). The group holds the filter in a cell with a generation counter, replaced
    under a lock; each thread keeps its own copy and, per accept, reads the generation (one
    atomic load of a rarely written cache line) and fetches the filter only when it changed.
    Threads added by `set_threads` share the cell. A first version posted the filter to each
    thread as a loop command: a thread woken with the command and a new connection in the same
    batch accepted that connection with the old filter (events run before commands), which the
    Linux tests caught.
15. TCP listeners on epoll, kqueue and io_uring. `filter` on a UDP or datagram listener fails
    `build` / `add_listener` with `InvalidInput`, on a DPDK listener with `Unsupported`.

### Backends

16. `akio_core::Group` gains `stop_listening(drain: Option<Duration>, exit_when_idle)`,
    `set_filter`, `finished` and `loop_stats` (hidden, default `Unsupported` / no-op), and the
    hidden `FilterCell` / `FilterView`; epoll / kqueue and io_uring groups implement them with
    the loop command `StopListening` and the shared filter cell. A loop that stopped listening drops listening sockets handed to it later (a
    `set_threads` handover in flight). On io_uring the multishot accept is cancelled; what it
    still delivers before the cancellation completes is served (and, when draining, shut down
    after its first data, as in an engine shutdown).

## Consequences

- Additive API in `akio`: `ListenerId`, `ListenerInfo`, `Engine::{add_listener, remove_listener,
  shutdown_listener, listeners, set_listener_threads, set_listener_filter,
  clear_listener_filter}`, `EngineBuilder::max_listeners`, `Listener::filter`; in `akio-core`
  the counter `filtered` and the hidden `Group` methods, `AcceptFilter`, `FilterCell` and
  `FilterView`; hidden
  `Telemetry::unregister_loops`.
- No change on the read / write path. Accept gains a branch and, on listener groups, one
  atomic load.
- `wait` on an engine without listeners blocks until `shutdown` (it returned at once).

Not done: run-time UDP and datagram listeners (use `bind_udp`); removing listeners of the DPDK
backend; a filter on UDP peers (done in ADR-178).

## Verification

- `tests/runtime_listeners.rs` (akio), on epoll and kqueue, and on io_uring with
  `AKIO_TEST_BACKEND=uring`: adding a listener while the engine runs and before it starts, with
  traffic on the others; removal under traffic keeps open connections echoing while new ones are
  refused, and the threads exit when they close; `shutdown_listener` calls `on_shutdown` and
  closes what is left at the drain deadline (and not before); the port of a removed listener can
  be bound again; `max_listeners` just under, at and over the limit, and counting removed
  listeners still draining; ids, `listeners()`, unknown ids; `set_listener_threads` on a runtime
  listener; a listener replaced at its own address 50 times, each removal followed at once by
  connections that must all be served (Linux).
- The filter refusing and accepting by address, swapped and cleared at run time under traffic,
  the `filtered` counter, a panicking filter, a filter on a UDP listener refused.
- Workspace suite on macOS, Linux arm64 in Docker (epoll and io_uring) and x86_64 (gpu51).
