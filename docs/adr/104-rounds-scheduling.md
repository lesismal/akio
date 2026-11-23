# ADR-104: Two scheduling modes for TCP listeners: per-thread loops and rounds on a worker pool

English | [简体中文](104-rounds-scheduling.zh-CN.md)

Status: proposed (2026-11-23; updated 2026-11-24: workers drive the pollers, measurements)

## Context

ADR-001 made every connection belong to one I/O thread for its whole life: the kernel's
`SO_REUSEPORT` hash picks the thread, and `on_data` runs inline there. That keeps handler state
lock-free and is the fastest arrangement when there are many connections of similar cost, but
the load of a thread is whatever its connections happen to bring:

- with few connections per thread the hash is uneven (ADR-100 measured 95 to 150 connections
  per thread for 1024 connections on 8 threads);
- a few heavy connections (a multiplexed HTTP/2 or gRPC client, a proxy upstream) saturate
  their thread while the others idle, and nothing can move them;
- a slow callback stalls every other connection of its thread.

ADR-100 balances connection *counts* at accept time and ADR-094 moves handlers onto the pool
per protocol. Neither spreads the work of a connection that is already open. fib (Go) and
the Go runtime do: a few pollers only report readiness, and each *round* of a connection (read,
handler, write) runs on whichever worker is idle.

## Decision

1. **A listener chooses its scheduling**: `akio::Scheduling::Loops` (the default, ADR-001
   unchanged) or `Scheduling::Rounds(RoundsConfig)`. `Listener::scheduling` sets it; the
   environment variable `AKIO_DEFAULT_SCHEDULING=rounds` sets it for listeners that did not (a
   test knob, like `AKIO_DEFAULT_BACKEND`, ADR-029), except where the listener asked for
   something only per-thread loops do: io_uring (its own choice or `AKIO_DEFAULT_BACKEND`'s) or
   BPF steering (`Accel::Ebpf`).
2. **Rounds mode** (`akio-epoll`, epoll on Linux and kqueue on macOS):
   - **Drivers, polled by the workers** (as Tokio's multi-thread runtime). There are no poller
     threads: each epoll/kqueue instance (`RoundsConfig::pollers`, default 1) is a *driver*
     behind a lock. A worker with nothing to run takes a free driver and waits in its
     `epoll_wait`; the connections it finds ready go to its own queue, and parked workers are
     woken to steal them. A busy worker polls the drivers without blocking every 61 rounds
     (Tokio's `event_interval`), so under load events are collected with no thread waking
     another. A driver also accepts and runs the control path (dials, timers, telemetry,
     shutdown); it never reads, writes or runs user code. A connection is registered once,
     edge-triggered for reads and writes (`EPOLLET` / `EV_CLEAR`), so a round makes no
     `epoll_ctl`. Dedicated poller threads (the first prototype) remain behind
     `AKIO_ROUNDS_POLLERS=dedicated` for comparison; they lose (see Measurements).
   - **Workers** (`RoundsConfig::workers`, 0 = auto: one per CPU) run rounds. A round of a
     connection runs `on_open` if it has not run, the `spawn_blocking` completions posted to it,
     flushes its queue, reads until the socket is drained (at most 16 reads, then it yields to
     the back of the queue), calls `on_data` for each read with the output corked, and writes
     what the round queued in one go.
   - **Order per connection**: each connection folds events into a pending bit set and has a
     `scheduled` flag; only the poster that sets the flag queues the connection, so at most one
     worker runs it at a time, and a round started after an event sees it. This is what lets
     `Handler: Send` (not `Sync`) keep working unchanged.
   - **The worker pool** is not `akio-pool` (one mutex-guarded queue, sized for blocking work):
     each worker has its own queue, an idle worker steals half of another's queue, spins 64
     times and parks; a poster wakes a parked worker only when none is spinning (and, when every
     idle worker is in `epoll_wait`, interrupts one through the driver's eventfd). Rounds started from a worker (a send from another connection's handler
     that needs a flush) go to that worker's own queue.
   - Blocking work still belongs on the logical pool (`spawn_blocking`, `run_on_pool`): a
     blocked worker delays the connections queued behind it, though the others steal them.
3. **What is the same**: `Conn` and `ConnInner` (already thread-safe, ADR-002), the cork and
   flush protocol, backpressure, `hold_reads`, ordered responses, `close_after_send`, idle /
   write / handshake / connect timeouts, slow-callback reports (per worker), `max_connections`,
   kernel TLS offload. Every protocol crate runs unmodified: their thread-local caches are only
   borrowed within one callback.
4. **Not in rounds mode** (prototype scope): UDP listeners (they keep their loops; a warning is
   logged), io_uring (`Backend::IoUring` with rounds is rejected), `set_threads` (returns
   `Unsupported`), BPF steering (it steers to pollers, which is pointless). The workers are one
   pool per listener group.

## Consequences

- Load spreads by work instead of by connection: a heavy connection uses one worker at a time,
  but the other connections of "its" poller go to other workers.
- Every round costs a hand-off: a queue push by the poller, possibly a wake-up of a parked
  worker, and the connection's state moving between cores. For many small, evenly spread
  connections, per-thread loops stay the faster choice; that is why they stay the default.
- Handler state may be touched by different threads in successive rounds (never at once), so a
  handler must not rely on thread-locals across callbacks. None of ours does.

## Measurements

gpu51 (Ryzen 7 7800X3D, Linux 7.0), 2026-11-24. Server on CPUs 0-3,8-11 (8 logical CPUs; loops:
8 threads; rounds: 8 workers, 1 driver), clients on the other 8. 10 s per case; two or three
rounds, which agree within a few percent for rounds and vary up to 20% for loops (the kernel's
hash differs per run). "CPU" is server CPU seconds per run (about 88 is all 8 CPUs).

`skew-bench` (CPU-bound requests; `conns`, in-flight `depth`, `work` per request):

| Case | Loops | Rounds | Requests per connection, min-max | CPU |
|---|---|---|---|---|
| 12 conns, depth 4, 50 µs | 114k-132k/s, p99 0.85-1.27 ms | **151k/s, p99 0.39 ms** | loops 32k-189k, rounds 126k-126k | 66-77 → 88 |
| 8 conns, depth 8, 100 µs | 39k-59k/s, p99 1.6-3.2 ms | **78k/s, p99 0.82 ms** | loops 25k-98k, rounds 98k-98k | 44-66 → 87 |
| 64 conns (4 at 500 µs, rest 20 µs), depth 2 | 210k-258k/s, p99 2.4-2.8 ms | 217k/s, **p99 1.5 ms** | loops 4k-134k, rounds 14k-35k | 88 both |
| 256 conns, depth 1, 10 µs | **481k/s**, p99 1.1 ms | 450k/s (-6%), **p99 0.92 ms** | loops 11k-26k, rounds 17.5k-17.6k | 87 / 85 |

TCP echo (`echo-bench`, 8 client threads; `bench-server`):

| Case | Loops | Rounds | CPU |
|---|---|---|---|
| 64 conns x 64 B | 840k-915k/s | **983k/s** | 57-62 → 76 |
| 1024 conns x 64 B | **1.01M-1.09M/s** | 978k-988k/s (-6%) | 67-72 → 71 |
| 256 conns x 1 KiB | 906k-1.08M/s | 952k-955k/s | 62-72 → 71 |

What was tried on the way, same host:

- **Dedicated poller threads** (2 pollers + 8 workers, the first prototype): 256 conns x 10 µs
  had p99 4.1 ms, all of it between the request reaching the server socket and its round
  starting (the client's own `write` took 8 µs at p99; the way back 28 µs). Changing the thread
  counts (2:6, 1:7), the spin, or pinning the pollers to CPUs of their own (which took their
  involuntary context switches from hundreds to single digits) left it at 4.0-5.4 ms. Workers
  polling the drivers removed it (0.92 ms), and with it the extra threads.
- **Two drivers** instead of one: 3% more throughput at 256 conns, worse tails (p99 0.57 ms
  against 0.39 ms at 12 conns, 2.2-2.5 ms against 1.5 ms with the heavy connections).
- **Spin** 0 / 64 / 1000 and **busy-poll interval** 31 / 61 / 127 rounds: no effect on
  `skew-bench` (within 1%); spinning 1000 times answers 2-4% more echo requests at 11% more CPU.
  The defaults stay at 64 and 61.

Conclusions:

- Where loops leave CPUs idle because of how the kernel spread the connections (few connections
  per thread), rounds use all of them: 15-100% more throughput and tails 2-4x shorter.
- Where loops already saturate every CPU with evenly spread connections, rounds cost about 6% of
  throughput (the hand-off per round), with equal or shorter tails.
- So loops stay the default; rounds are the choice for few or uneven connections.

HttpArena profiles (`akio-rounds` against `akio-loops`, same source) follow in the shared batch.
