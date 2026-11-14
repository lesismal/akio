# Multi-process serving (prefork)

`flash-prefork` serves one program from several worker processes, each running its own
`Engine`, under a supervisor that restarts crashed workers, drains them on shutdown and replaces
them on reload. It buys isolation (a crash or a stuck callback takes down one worker), upgrades
without downtime, and per-process resources that do not contend across cores. Inside a worker
everything is ordinary flash.

## A worker and its supervisor

The worker is a function that builds an engine on the listener the supervisor prepared and hands
it to `Worker::serve`:

```rust,ignore
{{#include ../../../crates/flash-prefork/examples/prefork-http.rs:worker}}
```

`main` configures the supervisor and calls `run` with that function:

```rust,ignore
{{#include ../../../crates/flash-prefork/examples/prefork-http.rs:supervisor}}
```

The same `main` runs in every process. In the supervisor, `run` binds the addresses, starts the
workers by **re-executing the current binary** with the same arguments plus `FLASH_PREFORK_*`
environment variables, and supervises them; it never calls the worker function. In a worker,
`run` finds those variables and calls the worker function with a `Worker`. Re-executing instead of
`fork` avoids the hazards of forking a multi-threaded process: each worker starts from `main` with
a clean address space. Keep start-up work that only workers need inside the worker function.

`Worker` tells the worker who it is: `index()` (0-based, kept by a restarted or reloaded
replacement), `workers()` (to take a per-process share of a machine-wide limit, such as database
connections), `generation()` (0, then one more per reload) and `addrs()`. `listener(i)` returns a
`flash::Listener` for address `i`, to configure with `.threads()`, `.backend()` and `.serve()` as
usual.

## Sharing the port

| `ListenMode` | Sockets | Balancing | Workers exiting |
|---|---|---|---|
| `ReusePort` (Linux default) | each worker binds with `SO_REUSEPORT`, one socket per I/O thread; the supervisor reserves the port without listening | kernel hash over every worker's sockets | connections queued on a closing worker's sockets are reset unless `net.ipv4.tcp_migrate_req=1` (Linux 5.14+) |
| `Inherit` (macOS default) | the supervisor listens once; workers inherit the socket (`Listener::tcp_from_std`) | first worker to accept | nothing is refused: the supervisor keeps the socket listening |

macOS accepts several processes binding one port with `SO_REUSEPORT` but sends every connection
to the last one, so `Auto` picks `Inherit` there. On Linux with io_uring, prefer `ReusePort`: with
an inherited socket one ring's multishot accept tends to take every connection.

`Listener::tcp_from_std` is also how a single-process server serves a socket it did not bind
itself, from systemd socket activation for instance.

## Lifecycle and signals

| Event | What happens |
|---|---|
| SIGTERM / SIGINT to the supervisor, `Supervisor::shutdown` | every worker is asked to stop: `Worker::serve` calls `Engine::shutdown` (stop accepting, finish in-flight requests) and returns; workers still running after `shutdown_timeout` are killed; a second signal kills at once |
| SIGHUP, `Supervisor::reload` | a new generation starts; each old worker is stopped once its replacement reported ready; a replacement not ready within `ready_timeout` is killed and the old worker kept |
| a worker exits on its own | restarted with the same index after `restart_backoff` (100 ms doubling to 10 s) |
| the supervisor dies | workers see their control socket close (on Linux they also get SIGTERM via `PR_SET_PDEATHSIG`) and drain |
| SIGTERM / SIGINT to a worker | it drains like a stop request |

Workers run in their own process group, so a terminal's Ctrl-C reaches only the supervisor, which
then drains them. `Worker::serve` reports readiness after `Engine::start`; a worker that runs its
engine another way calls `Worker::ready` itself, or reloads never replace it.
`Prefork::spawn` returns a `Supervisor` handle (for tests and admin endpoints) with `status()`,
`reload()`, `shutdown()` and `wait()`, and installs no signal handlers.

To upgrade the binary, replace the program file, then send SIGHUP: the new generation runs the new
code while the old one drains.

With `Inherit`, a reload refuses or resets no connection. One gap remains: a connection an old
worker accepted just before it began draining, whose request had not arrived yet, is closed by
flash-http's graceful shutdown, which closes connections with no request in flight (about 1 in
5,000 requests during a reload under continuous load in the tests).

## CPU pinning

`pin_cpus(CpuPinning::PerWorker)` runs worker `i` on CPU `i % CPUs`, `CpuPinning::Sets` assigns
CPU lists. The affinity is set in the child before `exec`, so all threads of the worker inherit
it. Linux only.

## eBPF steering and prefork

`Accel::Ebpf` attaches a steering program to a listener's reuseport group. In `ReusePort` prefork
the sockets of all workers form a single group, and a program attached from one worker replaces
the group's program and indexes only that worker's sockets: every new connection would go to the
worker that attached last. Do not combine the two (`Worker::serve` warns when it sees it). With
`Inherit`, a worker's listener forms no reuseport group and `Accel::Ebpf` reports `Degraded`.
Cross-process steering through a program pinned in bpffs is not implemented yet.

## Testing

The integration tests (`crates/flash-prefork/tests/prefork.rs`) run their own binary as the
workers: requests are answered by several PIDs, a crashed worker is replaced, a shutdown lets
in-flight requests finish, and a reload under continuous load swaps every worker without a
refused or reset connection.
