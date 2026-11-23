# ADR-001: Threading model

English | [简体中文](001-threading-model.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

thread-per-core: every connection belongs to exactly one I/O thread for its whole life. New connections are spread over threads by `SO_REUSEPORT` (optionally steered by eBPF, ADR-006). Callbacks run inline on that thread.

## Consequences

- Handler state needs no lock and no `Sync`; ordering per connection is trivially preserved.
- A slow callback delays its thread's other connections. Mitigations: documented non-blocking contract, explicit `spawn_blocking` (ADR-002/003), slow-callback detection with a configurable threshold.
- Unlike fib (any idle worker runs a connection's next round), load balancing is by connection, not by round; hot connections cannot migrate. Accepted trade-off.

## Update (2026-11-23, ADR-100)

The thread a connection lives on is now chosen at accept time, not only by the kernel: a thread that accepts a connection while it holds more than `2 + min / 32` connections above the least loaded thread of its listener hands it to that thread before anything is read (`Balance::LeastConnections`, the default; `Balance::Kernel` keeps the kernel's choice). `on_open` and every later callback run on the receiving thread, so a connection still belongs to one thread for its whole life.
