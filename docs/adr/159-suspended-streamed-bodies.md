# ADR-159: A request whose body streams, suspended with its reads held

English | [简体中文](159-suspended-streamed-bodies.zh-CN.md)

Status: accepted (2026-11-26)

## Context

ADR-109 lets a middleware suspend a request (`Context::suspend`) while it waits (a password
checked on the pool, an authorization server), then resume it into the next middleware and the
handler. It refused a request whose body streams to its handler (`BodyMode::Stream`): the server
feeds the body to the context it called after `call` returns, so that context cannot move. A
middleware that cannot know at `body_mode` whether it will suspend must then ask for every body
whole, within `max_body_bytes`: akit's `forward_auth`, `basic_auth`, `jwt` and WebAssembly
plugins do, so the proxy behind them loses its streamed uploads and holds whole bodies in memory
(akit's request A75).

## Decision

`Context::suspend` suspends a request whose body streams. The context the server keeps stays
where it is and goes on being fed the body; it passes the body on, through a relay, to the
context resumed from the suspension:

- **The reads are held from the suspension**, as `BodyReads::hold(true)` holds them: HTTP/1.1
  stops reading the connection, HTTP/2 stops giving the stream's window back, HTTP/3 holds the
  stream. What arrives meanwhile is kept for the resumed context: on HTTP/1.1 what one read
  brought (64 KiB by default), on HTTP/2 and HTTP/3 at most the stream's flow-control window.
- **Resumed**: once `Suspended::resume`'s closure returns, the resumed context is installed in
  the relay. Its sink (`on_body`, registered in the closure; one registered before suspending
  goes with the request) gets what was kept, then the rest as it arrives, in order; then the
  suspension's hold ends. A handler that took `body_reads` in the closure and held them keeps
  them held: the hold is the handler's and the suspension's together, so its `hold(false)`
  inside the closure takes effect once it is installed. The resumed context lives until its body
  ends, as a streamed request's does, and is answered `500` then if it neither responded nor
  detached.
- **Suspended again** inside the closure: the new suspension takes the same relay, still holding.
  A context already installed (taking its body) cannot be suspended (`None`).
- **Dropped unresumed**: answered `500`, then installed with no sink, so its body is read and
  dropped and the connection goes on to the next request.
- **The client goes** while suspended: the context the server keeps is dropped with the
  connection or stream, which cuts the relay; `on_gone` runs as for any suspended request (the
  hooks went with the request); the resumed context, once installed, is dropped with its sink and
  hears no end.

**How.** `Relay` (in `context.rs`), shared by the two contexts (`RelaySide::Feed` on the server's,
`RelaySide::Take` on the resumed one): a mutex over the kept bytes and trailers, the installed
context, and the hold's two parts. The body reaches the resumed sink from one thread at a time (a
`busy` flag) and never under the lock: the server's thread as pieces arrive, the resuming thread
for what was kept, each draining what the other kept meanwhile before it parks the context. The
hold is applied outside the lock too, by one thread at a time that looks again after, since
letting HTTP/3 reads go delivers what was held on the calling thread. `BodyReads` carries the
relay for a resumed context, so the handler's hold goes through it. Nothing changes for a request
that is not suspended: the server's context checks one `Option` in `deliver`.

**Rejected.** Moving the body to the resumed context's thread: the body arrives on the
connection's thread and is valid for that call only. Moving the context back to the connection's
thread on resume: a context cannot hop to a loop without knowing the connection's handler type,
and the thread that resumes would wait for it.

## Consequences

- akit's `forward_auth`, `basic_auth`, `jwt` and the WebAssembly plugins stop asking for bodies
  whole: a request whose body streams is suspended with its reads held, and the proxy behind
  them streams the upload once the check let it through.
- A sink registered on a resumed context may run on the resuming thread (for what was kept) and
  then on the connection's thread; a sink is `Send` and called by one thread at a time, as before.

## Tests

`crates/akio-http/tests/suspend_stream.rs` (HTTP/1.1 and HTTP/2, epoll and io_uring): a body
read with its head, one sent in pieces during and after the suspension, a chunked one suspended
twice, each reaching the resumed handler whole and in order, and a context taking its body not
suspended again; requests pipelined behind one wait their turn, one dropped unresumed is answered
500 and its body read past; a 32 MiB upload suspended 300 ms is paced by the socket buffers and
the server kept one read (64 KiB); a resumed handler holding the reads gets nothing until it lets
them go; a client gone while suspended runs `on_gone` and its body never ends; over HTTP/2 what
was kept is at most the stream's window. `crates/akio-http/tests/suspend.rs`: a streamed body
resumed inline and dropped. `crates/akio-h3/tests/suspend_stream.rs`: HTTP/3.
