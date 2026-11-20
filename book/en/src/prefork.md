# Multi-process serving (prefork)

`only-prefork` serves one program from several worker processes, each running its own
`Engine`, under a supervisor that restarts crashed workers, drains them on shutdown and replaces
them on reload. It buys isolation (a crash or a stuck callback takes down one worker), upgrades
without downtime, and per-process resources that do not contend across cores. Inside a worker
everything is ordinary `only`.

## A worker and its supervisor

The worker is a function that builds an engine on the listener the supervisor prepared and hands
it to `Worker::serve`:

```rust,ignore
{{#include ../../../crates/only-prefork/examples/prefork-http.rs:worker}}
```

`main` configures the supervisor and calls `run` with that function:

```rust,ignore
{{#include ../../../crates/only-prefork/examples/prefork-http.rs:supervisor}}
```

The same `main` runs in every process. In the supervisor, `run` binds the addresses, starts the
workers by **re-executing the current binary** with the same arguments plus `ONLY_PREFORK_*`
environment variables, and supervises them; it never calls the worker function. In a worker,
`run` finds those variables and calls the worker function with a `Worker`. Re-executing instead of
`fork` avoids the hazards of forking a multi-threaded process: each worker starts from `main` with
a clean address space. Keep start-up work that only workers need inside the worker function.

`Worker` tells the worker who it is: `index()` (0-based, kept by a restarted or reloaded
replacement), `workers()` (to take a per-process share of a machine-wide limit, such as database
connections), `generation()` (0, then one more per reload) and `addrs()`. `listener(i)` returns a
`only::Listener` for address `i`, to configure with `.threads()`, `.backend()` and `.serve()` as
usual.

## Sharing the port

| `ListenMode` | Sockets | Balancing | Workers exiting |
|---|---|---|---|
| `ReusePort` (Linux default) | each worker binds with `SO_REUSEPORT`, one socket per I/O thread; the supervisor reserves the port without listening | kernel hash over every worker's sockets | connections queued on a closing worker's sockets are reset unless they migrate: with `bpf_steering` to the new worker (Linux 5.14+), or with `net.ipv4.tcp_migrate_req=1` to a random live one |
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
| SIGUSR1, `Supervisor::reload_in_place` | every running worker runs its `Worker::on_reload` hook; no process is replaced ([below](#reload-in-place)) |
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
only-http's graceful shutdown, which closes connections with no request in flight (about 1 in
5,000 requests during a reload under continuous load in the tests).

## Reload in place

A generation swap replaces processes: it is how new code, new listeners and settings fixed at
build time take effect. Settings that `Engine::reload` and `Engine::set_threads` change at runtime
(idle timeouts, limits, read buffer, backlog, I/O thread counts; see
[Observability and hot reload](observability.md#hot-reload)) can instead be applied inside the
running workers:

```rust,ignore
let engine = Arc::new(Engine::builder().config(load_config()?.engine).listen(..).build()?);
let e = engine.clone();
worker.on_reload(move || {
    // On the worker's control thread, not an I/O thread: reading a file is fine.
    if let Ok(c) = load_config() {
        e.reload(&c.engine);
        let _ = e.set_threads(0, c.threads);
    }
});
worker.serve(&engine)
```

`Supervisor::reload_in_place()` (or SIGUSR1 to the supervisor) sends every running worker a
reload request; the worker runs its hook (SIGUSR1 sent to one worker runs only that one). Nothing
restarts and no connection is touched: shrinking hands a thread's listening sockets to the
worker's other threads instead of closing them, so on Linux with `ReusePort` it resets nothing,
unlike a generation swap without `tcp_migrate_req`. `Status::in_place_reloads` and
`Worker::reloads()` count them.

How the two interact:

- A worker started later (a crash restart, or the next generation) builds its engine from what its
  start-up code loads. Update the configuration source along with the in-place reload, or the
  change is lost at the next restart.
- With `Inherit` all workers share one listening socket: a `backlog` reload in any worker changes
  it for all of them (and for the next generation, which inherits the same socket).
- With `ReusePort` each worker's I/O threads own sockets of the shared `SO_REUSEPORT` group, so
  the kernel spreads new connections by socket, not by process: a worker with more threads gets a
  larger share.

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

`Prefork::bpf_steering(BpfSteering::new(steering, threads))` steers across processes instead
(ADR-063). The supervisor pins one program and socket array per address in bpffs, with
`workers * threads` slots. Each worker's `listener(i)` comes with `threads` I/O threads and joins
its own slots, and a restarted or reloaded worker takes the same slots over. On Linux 5.14+ the
program is also the `SELECT_OR_MIGRATE` policy: a reload's new worker takes its slots as soon as
it is built, and what the old listeners still had queued migrates to it when they close, so a
`ReusePort` reload resets nothing, without `tcp_migrate_req`. Without root or bpffs the workers
fall back to the kernel's hashing (or the spawn fails with `strict`).

## Testing

The integration tests (`crates/only-prefork/tests/prefork.rs`) run their own binary as the
workers: requests are answered by several PIDs, a crashed worker is replaced, a shutdown lets
in-flight requests finish, and a reload under continuous load swaps every worker without a
refused or reset connection.
