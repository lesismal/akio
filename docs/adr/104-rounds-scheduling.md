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

### HttpArena

gpu51, unified batch, 2026-11-24 09:16-11:43, after the stop and panic fixes. Each profile ran
twice, best of three runs each, and the two are averaged. Rounds use 8 workers and 1 driver. Two
pairs: `akio-rounds` against `akio-loops` (the rounds branch alone, same source), and
`akio-all-rounds` against `akio-all` (every merged optimisation, only the scheduling differs).

| Profile | Loops | Rounds | Change |
|---|---|---|---|
| baseline 4096c | 1.083M | 1.038M | -4.1% |
| pipelined 4096c | 7.15M | 6.95M | -2.8% |
| limited-conn 4096c | 867k | 814k | -6.2% |
| json-tls 4096c | 444k | 443k | 0 |
| baseline-h2c 256c / 1024c / 4096c | 7.07M / 6.91M / 6.27M | 7.08M / 6.88M / 6.27M | 0 |
| unary-grpc 256c / 1024c | 3.18M / 3.08M | 3.19M / 3.08M | 0 |
| echo-ws 512c / 4096c / 16384c | 1.25M / 1.22M / 1.00M | 1.11M / 1.16M / 1.03M | -10.6% / -4.4% / +2.4% |
| echo-ws-pipeline 512c / 4096c / 16384c | 15.6M / 15.3M / 12.9M | 14.1M / 14.7M / 13.0M | -9.8% / -4.0% / +0.6% |
| async 32000c (`akio-all` pair) | 602k | 673k | **+11.9%** |
| echo-ws-limited 512c / 4096c (`akio-all` pair) | 858k / 845k | 583k / 812k | **-32.0%** / -4.0% |
| json-comp 4096c / 16384c (`akio-all` pair) | 228k / 222k | 222k / 216k | -2.7% / -2.5% |
| static-h2 1024c (`akio-all` pair) | 802k | 774k | -3.5% |

Fixed-rate profiles:

- latency-10k: same p99 (about 0.05 ms), but 17.2 µs of CPU per request against 9.5 µs. The likely cause: an idle
  worker parks for at most 10 ms and the driver wakes it through the eventfd, so a light load pays
  for wakeups that loops do not have.
- latency-1m: p99 7.8-10.4 ms against 3.3-4.4 ms for `akio-all` (loops with the ADR-100 tail
  fixes), with slightly less CPU per request (7.5 against 7.7 µs). Main without those fixes had
  0.9-1.1 s.
- 8gbit: same throughput, 24 µs of CPU per request against 18 µs.

echo-ws-limited at 512 connections used only 5.7 of 8 CPUs under rounds. That profile reconnects
constantly, and every accept, registration and close goes through the one driver, so the driver
becomes the bottleneck when connections are short-lived.

So, on real HTTP traffic with evenly spread connections:

- Rounds win where a request holds a thread for long and the load is uneven (async, +12%), and tie
  on h2c and gRPC.
- They lose 3-10% on many small requests over many connections, up to 32% when connections are
  short-lived, and spend more CPU at light load.
- Loops stay the default. Next for rounds: spread accept and close over more than one driver, and
  cut the wakeups at light load.
