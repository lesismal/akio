# only-prefork

English | [简体中文](README.zh-CN.md)

Serve one program from several worker processes, each running its own `only` `Engine`, under a
supervisor that restarts crashed workers, drains them on shutdown and swaps them for new ones on
reload. The Rust counterpart of fib's `prefork` package.

Why several processes when `only` already runs one event loop per core? Isolation (a crash, a
leak or a stuck callback takes down one worker, not the server), zero-downtime upgrades (a reload
starts the new binary before the old one stops), and per-process resources (allocator arenas,
caches) that do not contend across cores.

```rust
use only::{Conn, Engine, Handler, fn_acceptor};
use only_prefork::Prefork;

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
current binary with the same arguments and `ONLY_PREFORK_*` environment variables, and `run`
calls the closure only in the workers. Re-executing instead of `fork` keeps clear of
fork-after-threads hazards (locks held by other threads, allocator state): every worker starts
from `main`. Work only the workers need (loading data, opening pools) belongs in the closure.

A full HTTP example: [`examples/prefork-http.rs`](examples/prefork-http.rs)
(`cargo run --release -p only-prefork --example prefork-http`).

## Listening sockets

| `ListenMode` | How | Balancing | Restart / reload |
|---|---|---|---|
| `ReusePort` (Linux default) | every worker binds the address with `SO_REUSEPORT` (one socket per I/O thread); the supervisor only reserves the port, bound but not listening | the kernel hashes connections over all workers' sockets | connections queued on a closing worker's sockets are reset, unless they migrate: with `bpf_steering` (Linux 5.14+) to the new worker, or with `sysctl net.ipv4.tcp_migrate_req=1` to a random live one |
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
  before it began draining, whose request had not arrived yet, is closed by only-http's graceful
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
`addrs()`, `listener(i)` (a `only::Listener` for address `i`, ready for `.threads()`,
`.backend()`, `.serve()`), `serve(&engine)`, `ready()`, `wait_for_stop()`.

`Prefork::workers(0)` runs the closure in the supervisor's own process with one worker that binds
the addresses itself, which is handy under a debugger.

## CPU pinning

`pin_cpus(CpuPinning::PerWorker)` runs worker `i` on CPU `i % CPUs`; `CpuPinning::Sets` gives each
worker a CPU list. The affinity is set in the child before `exec`, so every thread of the worker
inherits it. Linux only (macOS has no affinity API; a warning is logged).

## eBPF steering across workers (`bpf_steering`)

In `ReusePort` mode the sockets of **all** workers form one kernel reuseport group, and a steering
program belongs to the group. A worker's own `Accel::Ebpf` would replace it with a program that
only knows that worker's sockets, so every new connection would go to the worker that attached
last (`Worker::serve` warns). Use the shared program instead (ADR-063):

```rust,ignore
use only::ebpf::{HashKey, Steering};
use only_prefork::{BpfSteering, Prefork};

Prefork::new()
    .workers(4)
    .listen("0.0.0.0:8080".parse().unwrap())
    .bpf_steering(BpfSteering::new(Steering::Hash(HashKey::SrcIp), 2)) // 2 I/O threads per worker
    .run(|worker| {
        // listener(0) already has 2 threads and joins this worker's slots.
        let engine = Engine::builder().listen(worker.listener(0)?.serve(app)).build()?;
        worker.serve(&engine)
    })
```

- The supervisor loads one `SK_REUSEPORT` program and socket array per address, with
  `workers * threads` slots, and pins them under `/sys/fs/bpf/only-prefork/<ip>_<port>`
  (`BpfSteering::dir`). It removes them when it stops.
- Worker `i` puts its sockets in slots `i * threads..(i + 1) * threads`. A restarted or reloaded
  worker takes the same slots over.
- `Steering::Cpu` sends a flow to slot `cpu % slots`. `Steering::Hash` uses the Maglev table of
  `attach_reuseport`, so `only::ebpf::expected_index(steering, workers * threads, peer, local)`
  names the slot, and the worker is the slot divided by `threads`.
- **Reloads lose nothing** (Linux 5.14+, `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`). A new worker
  takes its slots as soon as its engine is built. When the old worker's listeners close, what
  they still had queued (accepted handshakes, pending ones) migrates to the socket now in its
  slot. A worker that dies migrates its queue to the others. No sysctl is needed.
- **Needs** root (or `CAP_BPF`) in the supervisor and the workers, and bpffs. Without them a
  warning is logged and the workers use the kernel's hashing; `BpfSteering::strict` fails the
  spawn instead. `Supervisor::bpf_steering(i)` says whether it is active.
- Keep the listener at `threads` I/O threads; `Engine::set_threads` is `Unsupported` for a
  steered listener.

In `Inherit` mode a worker's listener is not a reuseport group of its own: `Accel::Ebpf` reports
`Degraded` and `bpf_steering` is ignored (nothing needs migrating there).

## Platform support

Linux and macOS. The supervisor and workers are plain processes: no fork after threads, no
signal-unsafe work in the child before `exec` (only `fcntl`, `prctl`, `sched_setaffinity`).

Guide: [Multi-process serving (prefork)](https://lesismal.github.io/only/en/prefork.html).
