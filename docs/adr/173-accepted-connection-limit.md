# ADR-173: A connection limit that counts only accepted connections

English | [简体中文](173-accepted-connection-limit.zh-CN.md)

Status: accepted (2026-11-26). akit's A215.

## Context

`Config::max_connections` closes an accepted connection past it, but counts every connection of
the engine: dialed ones and UDP peers too. A gateway whose upstream pools dial on the engine that
serves its listeners then gives its clients' room to its upstream connections: at 100,000 and
30,000 upstream connections open, the 70,001st client is refused. fit's `limits.max_conns`
bounds "the client connections the listeners keep open".

## Decision

1. **`Config::max_accepted_connections: usize`** (0, no limit, by default), reloadable as
   `max_connections` is (`Live::set_max_accepted_connections`). Accepted TCP connections past it,
   across the engine's listeners, are closed right after `accept` and counted as `rejected`,
   whatever the engine dials. Both limits apply when both are set.
2. **Counted with A30's counters.** `Telemetry` keeps the connections open (`open`) and, apart,
   those that are not accepted TCP ones (`open_other`: dialed, UDP peers, TUN devices), so that
   `open_accepted()` is the one less the other (akit's A30). An accept already adds to `open`;
   with a limit set it also reads `open_other`, on the same cache line, and refuses the
   connection when `open` less `open_other` reached it. Without one the accept path is as it
   was. Closing gives back what opening took (`conn_closed(accepted)` in every backend).

## Consequences

- An application that dials on its serving engine can bound its clients alone.
- With a limit set, one more relaxed load on accept, of a line the accept writes anyway; none
  without.
