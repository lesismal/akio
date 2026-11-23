# ADR-102: Two scheduling modes for TCP listeners: per-thread loops and rounds on a worker pool

English | [简体中文](102-rounds-scheduling.zh-CN.md)

Status: proposed (2026-11-23)

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
   - **Pollers** (`RoundsConfig::pollers`, 0 = auto: one with 4 CPUs or fewer, otherwise one per
     4 CPUs and at least 2) wait for readiness, accept, and handle the control path (dials,
     timers, telemetry, shutdown). They never read, write or run user code. A connection is
     registered once, edge-triggered for reads and writes (`EPOLLET` / `EV_CLEAR`), so a
     poller makes no `epoll_ctl` per round.
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
     each worker has its own queue, pollers spread connections over them in turn, and an idle
     worker steals from the others before it parks; a poster wakes a parked worker only when
     none is spinning. Rounds started from a worker (a send from another connection's handler
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

To be filled in by the A/B runs (gpu51): raw TCP echo, HTTP/1.1 plaintext and pipelined,
WebSocket echo, and a skewed load (few connections, uneven cost) in both modes.
