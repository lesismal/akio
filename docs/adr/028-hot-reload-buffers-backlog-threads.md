# ADR-028: Hot reload of read buffer, backlog, UDP idle timeout and I/O thread count

English | [简体中文](028-hot-reload-buffers-backlog-threads.zh-CN.md)

Status: accepted (2026-11-17)

## Context

`Engine::reload` / `Live` (M6) changes the idle timeout, slow-callback settings, queue limit, high
watermark, connection limit, shutdown timeout and log level without a restart. The read buffer,
the listen backlog, the UDP idle timeout and the I/O thread counts were fixed at build time and
reported in `ReloadReport::ignored`. Changing them meant a restart, or, under akio-prefork, a
generation swap, which on Linux `SO_REUSEPORT` resets the connections queued on the old workers'
sockets unless `net.ipv4.tcp_migrate_req` is set.

Constraints: ADR-001 (a connection belongs to one I/O thread for its whole life; handler state is
neither locked nor `Sync`), ADR-002 (locks only around the send queue, never held across user
code), docs/rules.md (never block an I/O thread; no per-event global lock), and the steady-state
hot path must not change.

## Decision

### Settings (`Config` / `Live`)

- **`read_buffer`** is reloadable. Each I/O thread swaps its read buffer when it handles the
  reload notification, between two batches of events: no `on_data` holds a borrow then, so this is
  the next idle point of every connection of that thread, and open connections read into the new
  size from their next read on. epoll/kqueue: the scratch buffer is reallocated. UDP: the receive
  batch is rebuilt; sockets with GRO on (decided at build time) keep slots of at least 64 KiB.
  io_uring: the provided-buffer ring is shared with the kernel, so the loop registers a second
  buffer group of the new size (group ids alternate 0/1, the completion's operation code says
  which group a buffer came from), cancels the multishot receives armed on the old group, re-arms
  each on the new group when its cancellation completes, and unregisters and frees the old group
  once no receive uses it; a further change waits for that.
- **`backlog`** is reloadable: every I/O thread calls `listen(2)` again on the listening sockets
  it holds (`akio_sys::set_backlog`); Linux and macOS update the queue limit of a live socket in
  place. Sockets handed between threads (below) and new ones take the current value.
- **`udp_idle_timeout`** is reloadable; UDP threads re-arm every peer's timer against
  `min(udp_idle_timeout, idle_timeout)` (both live now; before, the initial `idle_timeout` capped
  it).
- **`retire_timeout: Option<Duration>`** (new, default `None`, reloadable): see shrinking.
- `ReloadReport::ignored` now names the settings that really stay fixed: `max_pending_responses`,
  `write_timeout`, `connect_timeout`, `udp_max_peers`, `udp_gro`.

### Thread counts: `Engine::threads()` and `Engine::set_threads(index, n)`

Per group (TCP listener or client group, in `local_addrs` order), on epoll, kqueue and io_uring.
The group keeps a **roster** of its active loops (an `RwLock<Vec<..>>` read on the control path
only: dials and listener handover, never per event) and per loop index a slot with an atomic state
`ACTIVE` / `RETIRING` / `EXITED`. `set_threads` runs under the group's own lock on the caller's
thread, posts commands to the loops and returns without waiting for them to act. The one wait:
growing into the index of a loop that committed to exiting joins that thread (it has no
connection left, so this is short), because the new loop reuses its counters and the old thread
must not touch them afterwards.

- **Grow**: for each new index, a retiring loop of that index is revived (CAS `RETIRING → ACTIVE`,
  then a `Revive` command); otherwise a new loop is started, reusing the counters (`LoopStats`) of
  the exited loop of that index so metrics series stay continuous and one series exists per index
  ever used. The loop gets a listening socket: on Linux a new `SO_REUSEPORT` socket bound into the
  listener's group (the kernel starts sending it its share of new connections), or the socket of
  that index bound earlier, which the active loop holding it passes back (`GiveListener`);
  elsewhere, and for inherited listeners, a clone of the shared socket.
- **Shrink**: the highest loops leave the roster, are marked `RETIRING` and get a `Retire`
  command. A retiring loop stops accepting at once and hands its `SO_REUSEPORT` sockets to active
  loops (`AddListener`); the sockets stay open throughout, so connections that reach their accept
  queue meanwhile wait instead of being reset (the difference to closing them, or to a prefork
  generation swap). Clones of a shared socket are just closed (the others keep listening).
  io_uring cancels the loop's multishot accept first and serves whatever it still accepted.
- **Which connections move: none.** A retiring loop keeps serving the connections it owns until
  they close; ADR-001 stays intact (no handler crosses threads, no per-connection owner pointer
  becomes mutable). It exits when it has no connection and no pending dial or accept left: it
  commits with CAS `RETIRING → EXITED`, which fails if the group revived it meanwhile. With
  `retire_timeout` set, the connections still open when it expires get `on_shutdown` (the graceful
  path of engine shutdown: HTTP finishes its response and closes, WebSocket sends 1001, so clients
  reconnect to active threads), and those still open `shutdown_timeout` later are closed.
- Dials and adopted streams go to the roster round-robin, posted under its read lock, so a loop
  retired right after receives the dial before its `Retire` and serves it. Commands left in the
  queue of an exiting loop that must not be lost (a listening socket, a dial) are passed on.
- Not offered (`Unsupported`): UDP listeners (a socket added to or removed from a UDP
  `SO_REUSEPORT` group re-hashes peers to other threads, splitting their state), DPDK groups, and
  listeners with BPF steering (`Accel::Ebpf`: the steering map would have to be rebuilt).
- `LoopStats`/`LoopMetrics` gain `retiring`, rendered as `akio_loop_retiring` and in JSON.

### akio-prefork

- `Controller::reload_in_place()` / `Supervisor::reload_in_place()` and SIGUSR1 to the supervisor
  send a new control byte to every running worker, which runs the hook set with
  `Worker::on_reload(Fn())` on its control thread (also on SIGUSR1 sent to the worker itself).
  The hook typically re-reads the configuration and calls `Engine::reload` and
  `Engine::set_threads`. No process is replaced, no connection touched. `Status::in_place_reloads`
  and `Worker::reloads()` count them.
- A generation swap (SIGHUP, `Controller::reload`) is unchanged and still the way to change code,
  listeners or fixed settings. Its workers start from what their start-up code loads, so in-place
  changes survive it only if the configuration source was updated too.
- With `ListenMode::Inherit` the workers share one socket: a backlog reload in any worker changes
  it for all of them. With `ReusePort` a worker that grows adds sockets to the cross-process
  group, so it receives a larger share of new connections; shrinking hands sockets within the
  worker and resets nothing (unlike a generation swap without `tcp_migrate_req`).

## Alternatives considered

- **Moving idle connections to other threads on shrink**: would need the connection's owner
  (`ConnInner`'s loop link) to become mutable and synchronised on every cross-thread send, wake
  and completion, plus handing the fd, the handler box, timers and, on io_uring, in-flight
  operations between rings. It breaks ADR-001's guarantee that per-connection state never changes
  threads (users may keep thread-local caches) and adds a cost to the cross-thread path. Letting
  connections finish, with `retire_timeout` and `on_shutdown` to bound it, keeps the hot path and
  the threading model unchanged.
- **Closing a retiring loop's `SO_REUSEPORT` socket**: resets its queued connections (the problem
  `tcp_migrate_req` exists for); handing it to another loop costs nothing and loses nothing.
- **Thread counts in `Config`**: threads are per listener (`Listener::threads`), not engine-wide;
  an index-based call matches `local_addrs`.
- **Resizing UDP groups by keeping retired sockets alive**: a retired socket keeps receiving its
  hash share of new peers, so the thread could never retire; left out until steering (eBPF) can
  pin existing peers.

## Consequences

- Additive public API: `Config::retire_timeout`, `Live::{read_buffer, set_read_buffer, backlog,
  set_backlog, udp_idle_timeout, set_udp_idle_timeout, retire_timeout, set_retire_timeout}`,
  `LoopMetrics::retiring`, `Engine::{threads, set_threads}`, `akio_sys::set_backlog`,
  akio-prefork `Controller::reload_in_place`, `Supervisor::reload_in_place`, `Worker::{on_reload,
  reloads}`, `Status::in_place_reloads`. Behaviour change: `Engine::reload` now applies
  `read_buffer`, `backlog` and `udp_idle_timeout` instead of reporting them ignored.
- Hot path: unchanged except that the poll-token match tests a listener bit instead of comparing
  with one constant, and io_uring selects the buffer group from the completion's operation code;
  measured with a same-run A/B (docs/BENCHMARKS.md, "Hot reload").
- A loop that retires with long-lived connections and no `retire_timeout` keeps its thread until
  they close; `Metrics` shows it (`retiring`). Repeated shrink/grow cycles do not accumulate
  threads: growing revives retiring loops first.
- After shrinking on Linux one loop may hold several `SO_REUSEPORT` sockets and take a larger share
  of new connections until the group grows again.
