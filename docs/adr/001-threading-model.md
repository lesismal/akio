# ADR-001: Threading model

English | [简体中文](001-threading-model.zh-CN.md)

Status: accepted (2026-11-13)

## Decision

thread-per-core: every connection belongs to exactly one I/O thread for its whole life. New connections are spread over threads by `SO_REUSEPORT` (optionally steered by eBPF, ADR-006). Callbacks run inline on that thread.

## Consequences

- Handler state needs no lock and no `Sync`; ordering per connection is trivially preserved.
- A slow callback delays its thread's other connections. Mitigations: documented non-blocking contract, explicit `spawn_blocking` (ADR-002/003), slow-callback detection with a configurable threshold.
- Unlike fib (any idle worker runs a connection's next round), load balancing is by connection, not by round; hot connections cannot migrate. Accepted trade-off.
