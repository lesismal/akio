# ADR-154: A connect timeout per dial, and timers off the I/O threads

English | [简体中文](154-dial-options-and-send-timers.zh-CN.md)

Status: accepted (2026-11-26; akit A12, A79, A45)

## Context

A gateway dials many upstreams on one engine, each with its own connect timeout (fit's
`connect_timeout` per upstream). `Engine::dial` had one, the engine's `Config::connect_timeout`,
armed by the backends on the I/O thread's wheel when the dial is posted. `HappyEyeballs` raced
two addresses or more within its own `connect_timeout`, but dialed a lone address (an IP
literal, a name with one record) and the addresses of a race the racer was too busy to take with
`Engine::dial`, so the engine's timeout held there. akit set the engine's timeout to the shortest
of its upstreams' as a stopgap (akit A12 for HTTP, A79 for its layer 4 services).

A gateway's control plane also needs timers: health probes every interval and their deadlines,
idle sweeps, cache lock expiries, refreshes. akio's timers were loop-local (ADR-103: on the
calling I/O thread only) or private (akio-http's request-timeout thread). akit ran a thread of
its own with a bounded heap (akit A45).

## Decision

1. **`DialOptions`** (akio-core, re-exported by `akio`): `#[non_exhaustive]`, built with
   `DialOptions::new().connect_timeout(d)`; `connect_timeout: None` means the engine's.
   **`Engine::dial_with(addr, opts, acceptor, on_error)`** is `dial` with them.
2. The backend-facing `Group` trait gains `dial_with`; its default ignores the options and
   calls `dial`. The TCP groups implement it: epoll/kqueue loops and io_uring carry the timeout
   in their dial command and arm the connect deadline with it in place of
   `Config::connect_timeout`; rounds scheduling likewise; DPDK uses it in place of its stack's own
   10 s. Shared listener groups (ADR-130) forward it. The deadline is the same wheel entry as
   before (whole milliseconds, at least one, clamped to `timer::MAX_DELAY`), so a dial costs
   nothing more.
3. **`HappyEyeballs`** dials every attempt within its `connect_timeout`: a lone address and the
   addresses dialed in turn go through `dial_with`. The clients that dial through it (akio-http's
   `Client`, `H2Client::connect`, akio-ws) thus bound a lone address too; `H2Client::dial` (one
   address, no race) uses `H2Options::happy_eyeballs.connect_timeout` as well.
4. `dial_udp` takes no connect timeout: UDP has no handshake (the socket is connected at once and
   `on_open` runs right away), and a silent peer is ended by `Config::udp_idle_timeout`.
5. **`akio::timer::after_send(delay, f: FnOnce() + Send) -> Result<SendTimer>`** (next to the
   loop-local `after`): `f` runs on one process-wide timer thread (`akio-timer`), started on
   first use and leaving after 30 s with nothing pending. Timers are kept in one ordered map
   (`BTreeMap<(Instant, seq), Job>`) under one lock: setting is an insert (and a wakeup only when
   the new timer is due first), `SendTimer::cancel()` (from any thread) a removal that says whether
   it was still pending. The thread pops what is due under the lock, in batches of 256, and runs
   the jobs outside it; a panic is caught and logged. Bounded: `MAX_SEND_TIMERS` (2^20) pending,
   then `Error::Overloaded`; delays clamped to `MAX_DELAY`. Never early.
6. Jobs share one thread, so they must be quick and must not block; one with work to do posts
   it (to a connection with `Conn::run_on_loop`, to a pool, to a channel). On an I/O thread
   `after` stays the cheaper choice (no lock, no other thread).

Not chosen:
- A timeout argument on `dial` itself: a breaking change, and options grow (a local address, a
  socket option) better in a struct.
- `Engine::after` (an engine-bound timer run on one of its I/O threads, dropped when it stops):
  it needs a command that runs a closure on any loop of every backend, and akit's callers
  (a JWKS refresh, a cache lock, a FastCGI pool tick) often hold no engine. A job reaches a
  connection's loop with `Conn::run_on_loop`; an engine-bound form can come later if needed.
- Making akio-http's private timer thread public: its API is shaped by the client's request
  timeouts.

## Consequences

- Additive API: `DialOptions`, `Engine::dial_with`, `timer::{after_send, SendTimer,
  MAX_SEND_TIMERS}`. `Group::dial_with` is `#[doc(hidden)]` backend plumbing.
- `HappyEyeballs::connect_timeout` now bounds a lone address; an application that relied on the
  engine's (longer) timeout there sees its own instead. Both default to 10 s.
- No hot path changes: a dial carries one more `Option<Duration>`; accepted connections are
  untouched. Nothing to benchmark.
- The timer thread takes one lock per set or cancel, shared by every thread of the process: fine
  for control-plane rates (akit: two timers per probed address per interval), not meant for
  per-request use on I/O threads, which have `after`.
