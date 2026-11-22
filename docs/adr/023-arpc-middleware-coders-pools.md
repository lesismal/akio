# ADR-023: arpc middleware, coders and client pools

English | [简体中文](023-arpc-middleware-coders-pools.zh-CN.md)

Status: accepted (2026-11-17)

## Context

`akio-arpc` spoke Go arpc's wire format (calls, notifies, streams, broadcast, reconnect) but
lacked three things Go arpc applications rely on (DEV-PLAN M4, "not done"):

- **middleware** (`Handler.Use`): authentication, logging, timing, recovery around handlers;
- **coders** (`Handler.UseCoder`, `MessageCoder`): whole-frame transformations, in practice
  `arpcex/extension/middleware/coder`'s gzip (reserved-byte bit 7) and its value appender
  (tracing, bit 0), which carries a value of the message's `Values` to the peer;
- **client pools** (`ClientPool`): several connections to one server.

Go's `Use` is order-dependent: a middleware runs before the handlers registered after it and
*after* those registered before it, and continues the chain on its own unless `Abort` is called.
Go's gzip coder inflates without a bound. Go's `ClientPool.Next` is a shared atomic round robin
and has no notion of load or of a silent connection. docs/rules.md requires middleware chains to
be built once (rule 11), no shared counters per call (rule 12), bounded decompression (rule 6) and
a safe default for every table (rule 10), which the table of pending calls did not have.

## Decision

Additive API in `akio-arpc` (one new `CallError` variant; the enum is `#[non_exhaustive]`):

- **Middleware**: `Routes::middleware(Fn(&mut Context, Next))` (every request and notify,
  unknown methods included) and `Routes::method_middleware(method, ...)`. Order is fixed and
  independent of registration order: global middleware in the order added, then the method's,
  then the handler (or `METHOD_NOT_FOUND`). `Next::run(self, ctx)` runs the rest; code after it
  is "after the handler"; returning without it aborts (an explicit `next`, as in tower/axum,
  instead of Go's implicit continue plus `Abort`). `Next` borrows slices of the immutable
  `Routes`: no allocation and no reference count per message; with no middleware the handler is
  called directly. `Context::values` / `values_mut` / `responded` are new. Streams have no
  middleware, as in Go. A client's `Routes` serve the calls its server makes, so the same chain is
  the client-side middleware; Go has no outgoing-call middleware and neither does this.
- **Coders**: `pub mod coder` with `trait Coder { encode(&mut Vec<u8>, &Values); decode(&mut
  Vec<u8>, &mut Values, max_body) -> Result<(), CoderError> }` on whole frames,
  `Routes::coder(c)`; encode in the order added, decode in reverse (Go's order). The body length
  is fixed after each coder, a decoded body over `max_body_bytes` or a decode error closes the
  connection, pings and pongs are never coded. Built in: `Gzip::new(threshold)` (bit 7,
  compresses bytes 5.. as Go does; inflation bounded by `max_body_bytes` via
  `akio_deflate::decompress`'s limit, so a bomb costs at most the limit) and
  `Appender::new(name, bit)` (Go's appender layout: name, value, 2-byte big-endian length; strict
  length checks where Go would panic). `Values` is a small string → bytes map (`Vec`-backed, free
  when empty). Calls carry values with `Peer::call_with` / `call_async_with` / `notify_with`;
  answers are coded with the request's values, as in Go. When a connection has coders, the
  decoder yields raw frames (`Decoder::feed_frames`) so coded headers (gzip replaces the cmd
  byte) are not rejected before decoding; without coders the old path is unchanged.
- **Bounded pending calls**: `Routes::max_pending_calls(n)`, default
  `DEFAULT_MAX_PENDING_CALLS` = 65536 per connection; a call past it fails at once with
  `CallError::Overloaded` and is not sent. `Peer::pending_calls()` (a per-connection atomic
  stored under the existing lock) and `Peer::ping()` are new.
- **Pools**: `Pool::builder()` → `PoolBuilder { size (4), balance, heartbeat (15 s),
  reconnect_interval (1 s), connect_timeout (10 s) }.dial(engine, addr, routes)`; all
  connections must come up or the dial fails and closes the others (Go's behaviour).
  `Balance::RoundRobin` (default; per-thread cursor, no shared counter) or
  `Balance::LeastPending` (fewest `pending_calls`, ties in turn). Connections that are down are
  skipped (a per-peer `connected` flag, no lock); with none up a call fails at once with
  `Closed`. The heartbeat pings every interval and closes a connection whose ping got nothing
  back within an interval, so its reconnect replaces it. `Pool::{peer, peers, connected, call,
  call_with, call_async, notify, close}`.

Interop: `tools/interop/arpc/run.sh` runs, besides the plain checks, a fib Go arpc server and
client with the arpcex gzip and appender coders (ported to fib's `MessageCoder`, same bits) and a
Go middleware that refuses calls without the trace value, against an akio-arpc server and pool
with the same chain and a Rust middleware doing the same, in both directions; both sides count
the compressed frames they inflated. Fuzzing: new target `arpc_coders` (frames → coder chain →
parser, split-invariance, decoded size bound, encode/decode identity).

## Alternatives considered

- **Go's `Use` semantics** (implicit continue, `Abort`, registration-order dependent): rejected;
  the explicit `Next` is harder to misuse and expresses before/after directly. Go peers are not
  affected, middleware is local.
- **Typed (`Any`) values**: Go's are `map[any]any`; only bytes can cross the wire, and typed
  extensions would add a second map. Middleware that needs typed state keeps it in its closure.
- **Coders on `Message` instead of bytes**: Go's coders rewrite the raw buffer, including header
  bytes (gzip compresses the cmd and sequence number), so only a byte-level interface is
  compatible.
- **A shared atomic round robin** (Go): rejected by rule 12; a per-thread cursor spreads calls as
  well for one caller and better for many.

## Consequences

- Additive API; existing programs unchanged except that more than 65536 calls pending on one
  connection now fail with `Overloaded` (raise it with `max_pending_calls`).
- Same-run A/B on gpu51 (`arpc-bench 8 64 5 64`, 10 alternating rounds, medians): main 8.37M
  calls/s, this change without middleware 8.22M (0.98x), with one pass-through middleware 8.22M
  (1.00x of no middleware); round-to-round spread is about 4%, so these are within noise.
  `perf stat` per call: user instructions 4963 → 5034 (+1.5%, the pending bound and the coder and
  heartbeat checks) and +40 per middleware; cycles per call unchanged (7008 / 6939 / 6865);
  syscalls per call identical.
- `akio-arpc` now depends on `akio-deflate` (in-workspace, ADR-005 unaffected).
