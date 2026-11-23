# ADR-100: Accept-time balancing of connections over a listener's threads

English | [简体中文](100-accept-time-balancing.zh-CN.md)

Status: accepted (2026-11-23)

## Context

A TCP listener on Linux binds one `SO_REUSEPORT` socket per I/O thread and the kernel hashes
each new connection to one of them (ADR-001); the connection then lives on that thread. The
hash is even only on average. HttpArena's `latency-1m` profile paces 1024 keep-alive
connections at a fixed 1M requests/s (zrk, about 977 requests/s on every connection) against 8
I/O threads, about 92% of what the server can do closed-loop (1.09M). Measured on gpu51
(Ryzen 7800X3D, server cpuset 0-3,8-11) with the engine's own counters (`Engine::metrics`,
`LoopMetrics::open`, reads, loop iterations) and per-thread CPU from `/proc`:

| Offered | Connections per thread (kernel hash) | Saturated thread | p99 |
|---|---|---|---|
| 1.0M/s | 137 129 119 141 122 123 127 126 | thread 3 (141): 100% CPU, ~1 000 loop iterations/s instead of ~100 000, 136k reads/s against 138k offered | 376 ms (max 1.2 s; 1.35 s in the board run) |
| 0.9M/s | 138 132 120 133 150 137 119 95 | thread 4 (150) | 10 ms (p99.9 53 ms) |

Every connection carries the same load, so a thread's load is its connection count. The thread
with the most connections is offered more than one core can serve; its backlog (and the latency
zrk measures from each request's scheduled time) grows for the whole run while the other
threads idle part of the time. Nothing in the loop was unfair: every readiness event is one
`read`, the handler, and an immediate flush. dusty-tuned (zio, a multi-threaded runtime that
moves work between executors) holds p99 at 3 ms at the same rate and CPU because no executor is
left with more than its share.

ADR-001 rules out moving a connection once it is open, and the eBPF steering of ADR-006 places
flows by CPU or by a hash of the peer, not by load (and an eBPF program that reads per-thread
load needs privileges the classic-BPF tier does not have).

## Decision

1. **A connection may be handed to another thread of its listener once, at accept time, before
   anything is read from it.** `on_open` and every later callback run on the receiving thread,
   so ADR-001 still holds: a connection belongs to one thread for its whole life; only the
   choice of that thread changes.
2. **The rule** (`akio_core::balance`): a thread that accepts a connection while it holds more
   than `2 + min / 32` connections above the thread with the fewest hands it to that thread.
   A thread's load is its open connections plus those handed to it and not opened yet
   (`LoopStats::load`; the hand-off is counted on the target before it is posted, so threads
   accepting at the same moment see it). At 128 connections per thread the spread is bounded
   to about 3%; with few connections per thread (short-lived connections), a difference of two
   is not acted on, so a hand-off is not paid on every accept.
3. **Mechanism**: the accepting loop posts `Cmd::Adopt { stream, peer, acceptor }` to the target
   loop (its command queue and wake-up, as for dials), which opens the connection as if it had
   accepted it. epoll/kqueue and io_uring implement it. A handed connection that reaches a loop
   being retired by `set_threads` is passed on to an active loop; one that reaches a loop that is
   shutting down is closed (epoll) or served for its first request and then shut down
   (io_uring, as for a connection its cancelled multishot accept completes).
4. **API**: `akio::Balance { Kernel, LeastConnections }` (`#[non_exhaustive]`), set with
   `Listener::balance`. **The default is `LeastConnections`**, because the failure it prevents
   (one saturated thread while the others have room) is the default configuration's, and the
   cost is small. It is turned off where the placement was asked for: a listener whose
   `Accel::Ebpf` steering program is attached (CPU affinity or a consistent hash of the peer)
   and an engine with NUMA `SO_INCOMING_CPU` (ADR-088). UDP listeners ignore it (a peer is
   defined by its socket's hash). `Group::set_balance` (hidden) carries it to the backends.
5. **Load is counted in connections**, not in CPU time: connections are what the thread
   inherits for good, the count is exact and cheap to read from other threads, and with equal
   per-connection load (the case that fails) it is the load. A workload whose connections differ
   widely in cost is not balanced by it, as before.

## Consequences

- The connections of one listener are spread within the slack whatever the kernel's hash did;
  thread-per-core, lock-free handler state and per-connection ordering are unchanged.
- An accept on an over-share thread costs one cross-thread wake-up of the target (a command and
  an `eventfd` write) and a read of every active thread's counters (a read lock on the roster).
  Threads that are even pay only the counter reads.
- The kernel's choice of thread is no longer final, so locality the kernel chose (the CPU that
  received the SYN) can be lost; that is why steering and `incoming_cpu` keep `Kernel`.
- `Balance::Kernel` restores the previous behaviour exactly.
- Not done: weighting by CPU time or by queued requests; balancing per request (that would
  need connection migration, which ADR-001 rejects).

## Measurements

The numbers before the change are those in Context (gpu51, HttpArena `latency-1m`, the board
run and the engine's own counters). The same-run A/B with the change (`akio-lat` against `akio`
and dusty-tuned, latency-1m p99 and CPU, baseline and pipelined throughput) is pending: HttpArena
runs on gpu51 were paused before it ran. The tests in `crates/akio/tests/balance.rs` check the
spread (with `Balance::Kernel` the 4-thread spread test sees 6, 17, 94 and 139 connections on
macOS) and that no callback runs off its `on_open` thread.
