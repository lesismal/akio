# Timers on the I/O loop

Every I/O thread has a timer wheel. `akio::timer::after` puts a closure on the wheel of the
**calling** I/O thread; when it is due, that same thread runs it between two polls, like any
other callback. Nothing is locked, no other thread is involved, and nothing has to be woken up:
the loop already sleeps no longer than its next timer.

```rust,ignore
pub fn after(delay: Duration, f: impl FnOnce() + 'static) -> Result<Timer>
```

- Call it from a callback (`on_data`, `on_close`, a `spawn_blocking` completion, another timer).
  On any other thread it returns `Error::Closed`: there is no loop there to run it.
- `f` does not need to be `Send`: it never leaves the thread. It may capture `Rc`s and other
  thread-bound state of your handler.
- It never runs early. It runs on the first loop iteration at least `delay` later, normally
  within a millisecond (the wheel counts milliseconds), later if the thread is busy.
- `Timer::cancel()` drops the closure without running it (on the thread that set it). Dropping
  a `Timer` does not cancel it.
- A loop holds at most `timer::MAX_TIMERS_PER_LOOP` (about a million) timers; past that `after`
  returns `Error::Overloaded`. Delays over `timer::MAX_DELAY` (about 49 days) are clamped.
- Timers still pending when the loop exits (shutdown, a thread retired by `set_threads`) are
  dropped without running. A panic in one is caught and logged; the others still run.

A connection handle captured by the closure is the usual way back to the connection:

```rust,ignore
impl Handler for Delayed {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (c, reply) = (c.clone(), data.to_vec());
        // Answer in 10 ms, from this same thread.
        let _ = akio::timer::after(Duration::from_millis(10), move || {
            let _ = c.send(&reply);
        });
    }
}
```

If the connection closed meanwhile, the `send` returns `Error::Closed` and nothing else happens.

## Answering an HTTP request later

`akio_http::Context::after` detaches the request and hands the `Detached` to your closure on the
connection's own thread once the delay has passed:

```rust,ignore
fn delayed(ctx: &mut Context) {
    ctx.after(Duration::from_millis(10), |d| d.respond(Response::text(200, "late")));
}
```

Pipelined HTTP/1.1 requests are still answered in request order; HTTP/2 and HTTP/3 streams are
answered as their timers fire. Called somewhere that is not an I/O thread, `Context::after`
falls back to akio-http's shared timer thread.

## When to use which

| You want | Use |
|---|---|
| Do something on this connection's thread later (a delayed reply, a retry, a per-request deadline, a heartbeat) | `akio::timer::after` / `Context::after` |
| Close connections that go quiet, or whose writes stall | `Config::idle_timeout`, `Config::write_timeout` |
| Run blocking work and come back | [`spawn_blocking`](blocking.md) |
| Fire from outside the engine (a scheduler, a clock unrelated to any connection) | a thread of your own, sending through a `Conn` |

A timer thread of your own still works, but each reply then crosses threads: a lock to queue
it, a write from the wrong thread, a wakeup of the loop. On HttpArena's `async` profile
(32,000 connections each waiting 10 ms per request) that path cost about a fifth of the
throughput; see ADR-099 for the measurements.
