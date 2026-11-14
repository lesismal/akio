# flash-prefork

English | [简体中文](README.zh-CN.md)

Serve one program from several worker processes, each running its own flash `Engine`, under a
supervisor that restarts crashed workers, drains them on shutdown and swaps them for new ones on
reload. The Rust counterpart of fib's `prefork` package.

Why several processes when flash already runs one event loop per core? Isolation (a crash, a
leak or a stuck callback takes down one worker, not the server), zero-downtime upgrades (a reload
starts the new binary before the old one stops), and per-process resources (allocator arenas,
caches) that do not contend across cores.

```rust
use flash::{Conn, Engine, Handler, fn_acceptor};
use flash_prefork::Prefork;

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn main() -> std::io::Result<()> {
    Prefork::new()
        .workers(4)
        .listen("0.0.0.0:8080".parse().unwrap())
        .run(|worker| {
            let engine = Engine::builder()
                .listen(worker.listener(0)?.threads(2).serve(fn_acceptor(|_c: &Conn<Echo>| Echo)))
                .build()?;
            worker.serve(&engine)
        })
}
```

The same `main` runs in the supervisor and in every worker: the supervisor re-executes the
current binary with the same arguments and `FLASH_PREFORK_*` environment variables, and `run`
calls the closure only in the workers. Re-executing instead of `fork` keeps clear of
fork-after-threads hazards (locks held by other threads, allocator state): every worker starts
from `main`. Work only the workers need (loading data, opening pools) belongs in the closure.

A full HTTP example: [`examples/prefork-http.rs`](examples/prefork-http.rs)
(`cargo run --release -p flash-prefork --example prefork-http`).

## Listening sockets

| `ListenMode` | How | Balancing | Restart / reload |
|---|---|---|---|
| `ReusePort` (Linux default) | every worker binds the address with `SO_REUSEPORT` (one socket per I/O thread); the supervisor only reserves the port, bound but not listening | the kernel hashes connections over all workers' sockets | connections queued on a closing worker's sockets are reset, unless `sysctl net.ipv4.tcp_migrate_req=1` (Linux 5.14+) |
| `Inherit` (macOS default) | the supervisor binds and listens once; workers inherit the socket and their threads share it | whichever worker accepts first | nothing is refused: the socket keeps listening in the supervisor |
| `Auto` | `ReusePort` on Linux, `Inherit` elsewhere | | |

macOS accepts `SO_REUSEPORT` binds from several processes but does not balance (the last bound
socket gets the connections), hence `Inherit` there. On Linux with the io_uring backend,
`Inherit` balances poorly (the multishot accept of one ring tends to take every connection);
prefer `ReusePort`.

## Lifecycle

- **Start**: `Prefork::run` (or `Prefork::spawn` for a handle) binds or reserves the addresses
  (port 0 resolves once), then starts the workers; a program that cannot be started fails the
  call. Workers run in their own process group and with stdin closed.
- **Ready**: `Worker::serve` starts the engine, then reports ready to the supervisor over a
  private control socket (`Worker::ready` when you run the engine yourself).
- **Crash**: a worker that exits without being asked to is restarted with the same index after an
  exponential backoff (`restart_backoff`, 100 ms doubling to 10 s, reset after a worker lived that
  long).
- **Shutdown**: SIGTERM or SIGINT to the supervisor (or `Supervisor::shutdown`) asks every worker
  to stop; `Worker::serve` then calls `Engine::shutdown` (stop accepting, let in-flight requests
  finish) and returns. Workers still running after `shutdown_timeout` (30 s) are killed; a second
  signal kills at once. A terminal's Ctrl-C reaches only the supervisor, which drains the workers.
- **Reload**: SIGHUP (or `Supervisor::reload`) starts a new generation; each old worker is asked
  to stop once its replacement reported ready. A replacement not ready within `ready_timeout` is
  killed and the old worker kept. Replace the program file first to upgrade the binary. With
  `Inherit` no connection is refused or reset; one caveat: a connection an old worker accepted just
  before it began draining, whose request had not arrived yet, is closed by flash-http's graceful
  shutdown (it closes connections with no request in flight). In the tests that is about 1 in
  5,000 requests during a reload under continuous load.
- **Supervisor death**: workers see their control socket close (and, on Linux, receive SIGTERM
  through `PR_SET_PDEATHSIG`) and drain.
- **Signals to a worker**: SIGTERM / SIGINT make it drain like a stop request.

`Supervisor::status()` lists the workers (index, pid, generation, ready, draining) and counts
restarts and reloads.

## Worker API

`Worker::index()` (0-based, kept across restarts and reloads), `workers()` (to size per-process
shares of a machine-wide resource such as a database's connection limit), `generation()`,
`addrs()`, `listener(i)` (a `flash::Listener` for address `i`, ready for `.threads()`,
`.backend()`, `.serve()`), `serve(&engine)`, `ready()`, `wait_for_stop()`.

`Prefork::workers(0)` runs the closure in the supervisor's own process with one worker that binds
the addresses itself, which is handy under a debugger.

## CPU pinning

`pin_cpus(CpuPinning::PerWorker)` runs worker `i` on CPU `i % CPUs`; `CpuPinning::Sets` gives each
worker a CPU list. The affinity is set in the child before `exec`, so every thread of the worker
inherits it. Linux only (macOS has no affinity API; a warning is logged).

## eBPF steering (`Accel::Ebpf`)

In `ReusePort` mode the sockets of **all** workers form one kernel reuseport group (same address,
same user). A steering program is a property of the group: attaching one from a worker replaces
the group's program, and the program flash builds indexes only that worker's own sockets, so every
new connection would go to the worker that attached last. Do not combine `Accel::Ebpf` with
`ReusePort` prefork (`Worker::serve` logs a warning when it sees it). In `Inherit` mode a worker's
listener is not a reuseport group of its own and `Accel::Ebpf` reports `Degraded`. Balancing
across processes with a program shared through bpffs (fib's `BalanceReusePort`) is not
implemented yet.

## Platform support

Linux and macOS. The supervisor and workers are plain processes: no fork after threads, no
signal-unsafe work in the child before `exec` (only `fcntl`, `prctl`, `sched_setaffinity`).

Guide: [Multi-process serving (prefork)](https://lesismal.github.io/flash/en/prefork.html).
