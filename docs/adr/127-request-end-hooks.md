# ADR-127: A request's end heard: its response sent in full, or its client gone

English | [简体中文](127-request-end-hooks.zh-CN.md)

Status: accepted (2026-11-25)

## Context

fit's `concurrency_limit` counts a request as under way until its response is sent or its client
has gone (fib's `OnFinish` and `OnCancel`); its access log and metrics take a streamed response's
duration to its end; ADR-125's Proxy-Wasm host runs a plugin's done, log and delete callbacks once
a request is over. akio-http told a service neither (akit's request A48):

- The one hook was a response filter, which runs when the response's head is sent: a streamed
  response (`stream_response`, which akit's proxy uses for every body past 64 KiB) left the limit
  while its body still went out.
- `on_gone` (ADR-108) hears a client that goes, but holds one callback: a limit and a proxy
  cancelling its upstream could not both use it.
- A request given up by the server (a `Detached` or a `BodyStream` dropped unfinished) told
  nothing.

## Decision

`Context::on_end(f: impl FnOnce(End) + Send + 'static) -> bool` and `Detached::on_end(f)`, with
`#[non_exhaustive] enum End { Sent, Gone }`. Each `f` runs exactly once, whatever happens to the
request after it is registered (answered, detached, streamed, suspended, upgraded, run on the
pool):

- `End::Sent` once the response was handed to the connection in full: a whole response once sent
  (an HTTP/1 response queued on its connection, in its pipelined order), a streamed one once
  `BodyStream::finish` queued its last byte, a file body a filter encoded (ADR-124) once its pump
  finished, an upgrade once its `101` (or HTTP/2 and HTTP/3 `200`) went or the connection was
  taken over (`upgrade_raw`).
- `End::Gone` when the request ended before that: its client went, as `on_gone` hears it (the
  connection closed, an HTTP/1 EOF, an HTTP/2 or HTTP/3 stream reset or stopped), heard while it
  waits detached or streams; or the server gave its response up (a `Detached` or `BodyStream`
  dropped unfinished, a context dropped unanswered).

Several hooks run in the order they were added, on the thread that ends the request (the one that
sends or finishes, or the connection's I/O thread when the client goes). A hook added after the
end runs at once with it. `Context::on_end` returns `false`, `f` dropped unrun, only when the
response was already taken (detached, streamed, upgraded) with no hook registered before: the
request can no longer be followed from the context; register before, or on the `Detached`.

**How.** A request that registers `on_end` or `on_gone` gets one `Hooks` (an `Arc` of a mutex
holding the `on_gone` callback, the end hooks and how the request ended), shared by the context
and whatever takes its response (`Detached`, `BodyStream`), each holding it in an `EndGuard` that
ends it `Sent` when the response is out and `Gone` when dropped first. The transport holds it
weakly through its one peer-gone callback (ADR-108), registered once: the client going runs the
`on_gone` callback and ends the request `Gone`. `on_gone` keeps its meaning (one callback, the last
one set; dropped once the response is sent; run at once when registered after the client went) and
now lives beside the end hooks instead of taking the transport's one slot. A request that
registers neither pays nothing: no allocation, and `respond` moves an empty guard.

A form without a boxed closure (as A29's observer) was considered: the hooks are per request, and
a middleware's state is its own; a box per hook is the price of composing several (a limit, a
log, a plugin).

## Consequences

- akit's `concurrency_limit` gives a request's place back on `on_end` rather than at the
  response's head; its access log, metrics and tracing take a streamed response's duration to its
  end; ADR-125's host (milestone W6) calls a plugin's done, log and delete callbacks from it.
- `Context` implements `Drop` (an unanswered context ends its hooks); `suspend` carries the hooks
  to the resumed context.

## Tests

`crates/akio-http/tests/end_hooks.rs` (HTTP/1.1 and HTTP/2, epoll and io_uring): a whole response,
two hooks in order, a detached one answered from another thread with `on_gone` beside it unheard, a
streamed response ended at its finish and not its head, a suspended request, the server's own 500,
a hook added after the response (at once) and after a detach with none (refused); a detached
request whose client goes (heard before the `Detached` is let go), an unfinished stream (`on_gone`
then `Gone`, once each), a `Detached` dropped, an HTTP/2 stream reset and a connection closed; a
hook added after the client went, run at once on the caller's thread. `crates/akio-h3/tests/
end_hooks.rs`: the same over HTTP/3. The `on_gone` tests (ADR-108) pass unchanged.
