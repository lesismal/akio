# ADR-181: A connection's own bound of its send queue

English | [简体中文](181-own-send-queue-bound.zh-CN.md)

Status: accepted (2026-11-27). akit's A234.

## Context

`Config::max_queued_bytes` bounds the bytes queued for every connection of an engine (64 MiB by
default; rule 7): past it a send fails with `Overloaded` and queues nothing. An engine serves
connections of different kinds with one bound. fit's tunnel raises the bound of each tunnel link to
what its tunnels may have in flight (64 tunnels' 4 MiB windows plus control messages, about
260 MiB: `SetQueueLimit`), so that a link never refuses a send its tunnels' windows allow, while the
gateway's clients keep the engine's (akit sets it from `limits.max_write_queue_bytes`, 32 MiB). The
LLM mesh's links carry streams with windows of their own in the same way. akio had no bound of a
connection's own, so akit paced its links by a high water of its own below the engine's bound.

## Decision

1. **`Conn::set_max_queued_bytes(Option<usize>)`** (and on `ConnInner` and `ConnHandle`): the
   connection's own bound in place of the engine's; `None` restores the engine's.
   `Conn::max_queued_bytes()` reads the bound in force. Callable from any thread at any time; the
   next send is checked against it.
2. **Kept in the write state**, under the write lock every send takes anyway: `None` reads the
   engine's live value (`Telemetry::live`, so a reload still applies to connections without a bound
   of their own), `Some(n)` replaces it. Nothing else on the send path changes.
3. **Every check of the bound goes through it**: `send` and its variants, `send_room` (which
   akio-ws's batches size themselves by), HTTP/1.1's ordered responses held back behind an
   unfinished one, and a file sent through a transport, which must fit whole.
4. **Lowering the bound below what is queued drops nothing**: the queued bytes go out, later sends
   fail until the queue is back under the bound.
5. **`Config::write_high_watermark` is left alone.** A link that queues far past the watermark is
   one end of a relay and marks itself so (`set_relayed`); a bound of its own does not change when
   its reads pause.

## Consequences

- akit's tunnel links get fit's `LinkQueue` and drop their own 8 MiB high water; the LLM mesh's
  links get their streams' windows times `max_inflight`.
- `WriteState` is 16 bytes larger per connection (an `Option<usize>`); a send reads the option
  before the engine's live value. DEV-PLAN section 4 names the A/B a benchmark task should run.
- Tests (`crates/akio/tests/queue_bound.rs`, on every backend the suites run): a bound of the
  connection's own just under, at and over it, lowered below what is queued, restored with `None`
  through a handle, not inherited by the next connection, and set from a thread other than the
  connection's while the peer reads nothing.
- Not done: a high watermark of the connection's own (none was asked for), and a bound of its own
  for a UDP listener's peers, which share their socket's reply queue.
