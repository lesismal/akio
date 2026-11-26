# ADR-172: A budget of the bytes queued across an engine's connections

English | [简体中文](172-engine-budget-of-queued-bytes.zh-CN.md)

Status: accepted (2026-11-26). akit's A214.

## Context

`Config::write_high_watermark` pauses one connection's reads while its own output is queued past
it, and `max_queued_bytes` refuses a send past a per-connection cap. Neither bounds the sum: at a
256 KiB watermark, 100,000 slow clients may make an engine queue 25 GiB. fit (on fib) has
`limits.max_pending_bytes`, half the memory by default: past it, every connection stops reading
until some output drains. akio's roadmap promised an engine-wide `max_pending_bytes`, but the code
had none, and an application cannot build it on top: it would have to hold the reads of every
connection from outside the I/O threads that own them.

## Decision

1. **`Config::max_pending_bytes: Option<usize>`** (default `None`; `Some(0)` is none too),
   reloadable, also `Live::set_max_pending_bytes`. While the bytes queued for sending across the
   engine reach it, every connection's reads pause after its current read; they resume once the
   sum is back at three quarters of it.
2. **The sum is taken off the I/O threads.** Every I/O thread already keeps its queued bytes in
   a gauge (`LoopStats::queued_bytes`, updated as output is queued and written). While a budget is
   set, a watcher thread (`akio-budget`, one per engine's telemetry) sums the gauges every
   millisecond while the sum is at least half the budget, every 10 ms below, and raises or lowers
   one flag. The write path is unchanged; no shared counter is added to it. The budget is soft:
   what is queued between two sums can pass it, by at most what the engine writes in a
   millisecond or two, and each connection is still bounded by `max_queued_bytes`.
3. **Reads pause through `ConnInner::read_held`.** Every backend (epoll/kqueue event loops, work
   stealing, io_uring, DPDK, tun) asks it after each read and when it re-arms reading. While the
   flag is up it answers yes and *parks* the connection, once per episode: its id and loop go into a
   table (an episode number on the connection tells whether it is in this episode's table). Lowering
   the flag empties the table and wakes each parked connection through its loop (`wake_conn`, as
   `hold_reads(false)` does), so it re-arms its reads. A connection that reads nothing is never
   parked and costs nothing; one that closes while parked leaves the table. The table is bounded by
   the open connections. Checking the flag costs one relaxed load of a line written only when an
   episode starts or ends.
4. **Every connection pauses**, accepted and dialed: a proxy's upstream reads are what fills its
   clients' queues. Writes go on, so the queues drain; a peer that never reads is closed by
   `write_timeout`. UDP peers are not paused (no stream to hold).
5. **Telemetry.** `LoopCounters::budget_pauses` (`akio_budget_pauses_total`) counts the
   connections paused, per episode; `Telemetry::pending_bytes` is the sum and
   `Telemetry::over_budget` the flag.

## Consequences

- An engine with a budget bounds what many slow peers together hold, as fit does.
- One thread per engine while a budget is set, waking 100 to 1,000 times a second; none without.
- A handler that asks `read_held()` sees the budget's pause too (the HTTP client then does not
  count the time held against its body idle timeout, as for `hold_reads`).
- An application cannot tell a budget pause from a watermark one per connection; the counters
  tell them apart.

## Not done

- A share of the memory as the budget ("50%"): the application computes the bytes (akit does, as
  fit's `sysmem`).
