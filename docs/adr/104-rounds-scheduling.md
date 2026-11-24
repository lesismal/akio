# ADR-104: Two scheduling modes for TCP listeners: per-thread loops and rounds on a worker pool

English | [简体中文](104-rounds-scheduling.zh-CN.md)

Status: proposed (2026-11-23; updated 2026-11-24: workers drive the pollers, measurements;
second revision 2026-11-24: accepts and closes on the workers, fewer wake-ups at light load)

## Context

ADR-001 made every connection belong to one I/O thread for its whole life: the kernel's
`SO_REUSEPORT` hash picks the thread, and `on_data` runs inline there. That keeps handler state
lock-free and is the fastest arrangement when there are many connections of similar cost, but
the load of a thread is whatever its connections happen to bring:

- with few connections per thread the hash is uneven (ADR-105 measured 95 to 150 connections
  per thread for 1024 connections on 8 threads);
- a few heavy connections (a multiplexed HTTP/2 or gRPC client, a proxy upstream) saturate
  their thread while the others idle, and nothing can move them;
- a slow callback stalls every other connection of its thread.

ADR-105 balances connection *counts* at accept time and ADR-094 moves handlers onto the pool
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
     another. A driver runs the control path (dials, timers, telemetry, shutdown); it never
     accepts, reads, writes or runs user code. A connection is registered once,
     edge-triggered for reads and writes (`EPOLLET` / `EV_CLEAR`), so a round makes no
     `epoll_ctl`. Dedicated poller threads (the first prototype) remain behind
     `AKIO_ROUNDS_POLLERS=dedicated` for comparison; they lose (see Measurements).
   - **Accepting and closing are spread over the workers** (2026-11-24, second revision). On
     Linux a listener has one `SO_REUSEPORT` socket per worker (elsewhere one, cloned per
     driver), registered edge-triggered with a driver. Its readiness queues an *accept job* on
     the workers, scheduled like a connection (a pending flag and a `scheduled` flag, so one
     worker at a time accepts from a socket): the worker accepts up to 64 connections, creates
     them, registers them with the thread-safe `Registry` and queues their first rounds. The
     connections of a driver and their idle, write and handshake timers are in a *connection
     table* sharded by id (`2 x workers` shards, 4 to 64, each a mutex around a map and a timer
     wheel): a worker adds what it accepts, and the round that finalizes a connection removes it
     and cancels its timers, so neither an accept nor a close posts a message to the driver or
     writes its eventfd. The driver looks connections up in the table to hand out events and
     fires the table's timers; a worker arming a timer earlier than the driver's current wait
     interrupts the wait. Accept errors pause that socket for 100 ms (the driver re-arms it);
     shutdown closes the sockets under their job's lock, so every connection an accept job
     opened is in the table when `on_shutdown` is sent, and later ones see the drain flag.
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
     that needs a flush) go to that worker's own queue. When every other worker is parked, a
     poll wakes no one for the first job it queued, which its worker runs next, and one parked
     worker per job after that (Tokio's rule): at light load a poll finds one connection and its
     round runs with no thread waking another. A worker that found work by searching wakes
     another if more is queued. One parked worker, the *watch*, sleeps at most 10 ms, for a
     driver whose last poller went into a long round; the others sleep until woken (or their
     loop timer is due).
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
  for wakeups that loops do not have. (Measured later: the cause was a worker woken per request,
  not the parking; see the second revision.)
- latency-1m: p99 7.8-10.4 ms against 3.3-4.4 ms for `akio-all` (loops with the ADR-105 tail
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
- Loops stay the default. Next for rounds: take accept and close off the driver, and cut the
  wake-ups at light load (done in the second revision below; HttpArena not rerun yet).

### Second revision: accepts and closes on the workers, fewer wake-ups (2026-11-24)

gpu51 as above (server on 8 CPUs; loops 8 threads; rounds 8 workers, 1 driver), two rounds of
every case, `skew-bench` and `echo-bench`. "main" is rounds before this revision, "new" after it.
Server CPU is read from `/proc` around each run. The short-lived cases run 5 s each and wait
until the kernel's conntrack table has room first: at 200k connections a second it fills up
(2M entries, 120 s each in TIME_WAIT) and then drops SYNs, which had made earlier churn runs
meaningless for whichever mode ran next.

**Short-lived connections** (`skew-bench churn`: each client connects, sends N 16-byte requests
one at a time, closes, starts over):

| Case | Loops | Rounds main | Rounds new | Server CPU s: loops / main / new |
|---|---|---|---|---|
| 512 clients x 10 requests | 713k-720k req/s | 513k-519k (-28%) | **693k-712k** (-2%) | 46-47 / 36 / 47-48 |
| 512 clients x 1 request | 205k-206k conn/s | 102k-103k (-50%) | **207k-208k** (+1%) | 43 / 22 / 47-48 |
| 2048 clients x 10 requests | 757k-878k req/s | 689k-693k | **900k-909k** (+3% to +19%) | 49-55 / 46-47 / 58 |

**Fixed low rate** (`skew-bench rate`: 1024 open connections, requests at a fixed total rate,
16-byte echo; CPU per request = server CPU / requests sent):

| Case | Loops | Rounds main | Rounds new |
|---|---|---|---|
| 10k req/s: CPU per request | 9.1 µs | 16.3 µs | **11.3 µs** |
| 10k req/s: context switches per request | 1.11 | 2.27 | **1.18** |
| 10k req/s: p50 / p99 | 17 / 20 µs | 18 / 20 µs | 17 / 19-20 µs |
| 50k req/s: CPU per request | 8.7 µs | 15.6 µs | **9.9 µs** |

Where the light-load CPU went (main, 10k req/s, `AKIO_ROUNDS_TRACE=1` and `perf stat` on the
server): per second 10,001 rounds, **10,001 unparks and 10,001 parks**, 19.1k futex calls, 25.2k
`epoll_wait` calls, 19.5k context switches (loops: 9.5k context switches, 9.5k `epoll_wait`, no
futex). Every request woke a second worker: the worker blocked in `epoll_wait` found one
connection, queued it on its own queue, and the submit woke a parked worker "to steal it"; then it
ran the round itself, the woken worker found nothing, spun, took the driver and blocked in
`epoll_wait`, and the first one parked. Two context switches and four extra syscalls per
request; the 10 ms park timeouts (700 wake-ups a second for 7 idle workers) were a small part.

With only the first fix (a poll wakes no one for the job its worker runs next): 0 unparks, 700
parks a second (the 10 ms timeouts), 10.7k context switches, 1.10 s of server CPU over 9 s against
1.57 s. Toggling the parts on one build (server CPU over 11 s at 10k req/s; echo with 64
connections), from a build without the non-blocking poll before spinning (1.19 s; 904k req/s):
that poll back, as committed, 1.25-1.28 s and 969k-979k; waking a worker for every job a poll
finds (main's rule) 1.75-1.76 s and 907k-909k; every parked worker on a 10 ms timeout (main's
parking) 1.26 s and 901k-903k; all three, about main's worker loop, 1.84-1.87 s and 976k (main
itself: 1.79-1.83 s, 981k-983k). So the wake-up per request is the cost; the poll before spinning
costs about 0.6 µs per request at light load and is worth 7% on echo, so it stays.

**Regression checks** (same runs):

| Case | Loops | Rounds main | Rounds new |
|---|---|---|---|
| skew 12 conns, depth 4, 50 µs | 114k-132k/s, p99 0.84 ms | 151k/s, p99 0.39 ms | 151k/s, p99 0.39 ms |
| skew 8 conns, depth 8, 100 µs | 30k-49k/s, p99 3.2 ms | 78.4k/s, p99 0.82 ms | 78.4k/s, p99 0.82 ms |
| skew 64 conns (4 at 500 µs), depth 2 | 209k-231k/s, p99 2.6-2.7 ms | 217k/s, p99 1.5 ms | 217k/s, p99 1.5 ms |
| skew 256 conns, depth 1, 10 µs | 482k/s, p99 1.04 ms | 450k-451k/s, p99 0.92 ms | 442k-444k/s (-1.7%), p99 0.89 ms |
| echo 64 conns x 64 B | 1.06M-1.10M/s | 980k-989k/s | 980k-988k/s |
| echo 1024 conns x 64 B | 1.19M-1.22M/s | 1.017M-1.022M/s | 992k-998k/s (-2.4%) |
| echo 256 conns x 1 KiB | 1.09M-1.17M/s | 952k-957k/s | 927k-933k/s (-2.6%) |

Conclusions of the revision:

- With accepts and closes off the driver, short-lived connections use every CPU and match loops
  (-2% to +19%) instead of losing 28-50%.
- At light load a round no longer wakes a second thread: 11.3 µs of CPU per request at 10k req/s
  instead of 16.3 (loops 9.1), with the same latency. The rest of the gap is the non-blocking
  poll before spinning, the spin itself, and the queue and table locks.
- Few or uneven connections and h2c-like work are unchanged; echo over many connections loses
  another 2-3%.
