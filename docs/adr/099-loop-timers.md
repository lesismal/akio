# ADR-099: Timers on the I/O loop

English | [简体中文](099-loop-timers.zh-CN.md)

Status: accepted (2026-11-23)

## Context

Every I/O loop already had a timer wheel (`akio-timer`), but only for the engine's own
deadlines (idle, write, handshake and connect timeouts). An application that wanted to do
something on a connection later — answer in 10 ms, retry, enforce a per-request deadline — had
no timer of its own: the book said "your own timer thread". So the reply was produced on that
thread and crossed back: a lock to queue the work, `Detached::respond` (or `Conn::send`) from a
foreign thread taking the connection's locks and writing its socket there, and, when the write
did not complete, a command posted to the loop with an `eventfd` wakeup. The timer threads also
compete for the CPUs the loops run on.

HttpArena's `async` profile measures exactly this: `GET /delay/10` over 32,000 held connections.
Our entry answered from sharded `Mutex<BinaryHeap>` timer threads and reached RESULT_BEFORE.

## Decision

1. **`akio_core::timer`** (re-exported as `akio::timer`): `after(delay, f) -> Result<Timer>`
   schedules `f: FnOnce() + 'static` on the **calling** I/O thread's wheel. The wheel lives in a
   thread-local installed by the loop when it starts and removed when it exits, so scheduling
   and firing take no lock and involve no other thread; `f` need not be `Send`. Off an I/O
   thread `after` returns `Error::Closed`; `on_loop()` tells which case applies.
2. **Timing**: millisecond ticks from the loop's start; the deadline is the first tick at or
   after `now + delay`, so a timer never fires early. Each loop iteration polls with the shorter
   of its own timeout and the wheel's next deadline (rounded up to whole milliseconds), runs the
   due timers after the I/O events and **before** draining its command queue, so wakes that the
   timers post for their own connections are handled in the same iteration. A wheel that was
   idle is advanced to the current tick before a new timer goes in.
3. **`Timer::cancel`** drops the closure (only on the thread that set it; elsewhere `false`).
   Dropping a `Timer` does not cancel it.
4. **Limits** (rules 7 and 10): `MAX_TIMERS_PER_LOOP` = 2^20 per loop, then `Error::Overloaded`;
   delays clamped to `MAX_DELAY` (2^32 − 1 ms). Pending timers are dropped, unrun, when the loop
   exits (shutdown, a thread retired by `set_threads`); a panicking timer is caught and logged.
5. **Every loop has one**: epoll / kqueue TCP and UDP loops, io_uring, DPDK (where it also keeps
   the adaptive loop from sleeping past a deadline).
6. **akio-http `Context::after(delay, f: FnOnce(Detached) + Send)`** detaches the request and
   calls `f` from a loop timer on the connection's thread; off an I/O thread it falls back to the
   crate's existing timer thread (hence `Send`). `false` when a response was already sent.

Not chosen: a per-connection `Conn::after` delivering `&mut H` like `spawn_blocking` (it would
route every timer through the command queue and its mutex, and tie timers to `Handler`
types that HTTP/2 and HTTP/3 services do not see); a shared timer service with cross-thread
delivery (that is the cost being removed).

## Consequences

- Additive API: `akio::timer::{after, on_loop, Timer, MAX_TIMERS_PER_LOOP, MAX_DELAY}`,
  `akio_http::Context::after`. `install`, `uninstall`, `fire`, `next_wait`, `poll_timeout` are
  `#[doc(hidden)]` backend plumbing. akio-core now depends on akio-timer (already a workspace
  crate; no new third-party dependency).
- A loop without timers pays a thread-local read per iteration.
- Measured on gpu51 (HttpArena `async`, same-run A/B, 3 rounds; `akio` = the timer threads,
  `akio-timer` = `Context::after`): RESULTS. Profile: PROFILE.
