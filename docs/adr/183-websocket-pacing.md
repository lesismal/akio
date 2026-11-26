# ADR-183: A WebSocket's reads held, its drain heard, and its peer's address

English | [简体中文](183-websocket-pacing.zh-CN.md)

Status: accepted (2026-11-27). akit's A236.

## Context

A tunnel link, and a link of an LLM mesh, carries many streams whose bytes come from other
connections. When the link's queue passes its high water, what feeds it is held and resumes once
the queue drains; when what the link delivers cannot be written on, the link's own reads are held,
so that the peer's window stops it (rules 8 and 9; fit's WebSocket links have `SetReadPaused` and
`OnDrain` as its TCP ones do). akio-ws's `WsSender` had `queued_bytes` and nothing else of the kind:
no way to stop reading a WebSocket, no callback when its queue drains, no peer address (which a
hub's per-address bounds and access policy need). Nothing in akio-ws or akio-http's upgrade glue
reached `hold_reads` or `on_drain` of the transport underneath, which is a TCP or TLS connection,
an HTTP/2 stream (RFC 8441) or an HTTP/3 stream (RFC 9220), on the server and the client side.

## Decision

1. **Methods on `WsSender`**, the handle an application already keeps and uses from any thread,
   rather than a `WsHandler::on_drain` callback: `hold_reads(bool)`, `on_drain(FnOnce)`,
   `peer_addr() -> Option<SocketAddr>`, `set_relayed(bool)` and
   `set_max_queued_bytes(Option<usize>) -> Result<()>`. They mirror `Conn`'s, so a relay maps a
   WebSocket link onto the same wire abstraction as a TCP one; a waiter set per use (the last one
   wins) needs no watermark configured in the library and no state in idle sessions.
2. **The transport does the work.** akio-ws's doc-hidden `WsLink` (the non-TCP transports) gets
   `hold_reads`, `on_drain` and `peer_addr` with defaults; each transport implements them with
   what it has:
   - **TCP or TLS** (server through `Context::upgrade_websocket`, client through
     `akio_ws::client`): the connection's `hold_reads`, `on_drain`, `peer_addr`, `set_relayed`
     and `set_max_queued_bytes` (ADR-181).
   - **HTTP/2, server**: the stream's `held` flag of a streamed request body (its window is not
     given back while held; given back at once on resume) and the drain waiter of a streamed
     response (once the stream's bytes are all framed, or the stream goes), shared as functions.
   - **HTTP/2, client**: the same on the WebSocket's stream: a held flag in the link's shared
     state (DATA is counted as owed instead of given back; a resume posts the window update to the
     connection's loop) and a drain waiter run when the link's queued bytes reach 0 in a DATA
     frame, or the stream is given up or gone.
   - **HTTP/3** (both sides): `Connection::hold_reads` on the request stream (what arrives stays
     in the QUIC stream's buffer), and the connection's drain waiters by stream, run when the
     stream becomes writable, is stopped, reset or forgotten, or the connection closes.
3. **Drained means `queued_bytes()` is 0**, the same measure an application paces by: the
   connection's queue over TCP, the stream's bytes not yet framed over HTTP/2. Over HTTP/3, QUIC
   reports room in a stream's send buffer, not emptiness (writes past it are refused and room is
   reported at three quarters), so the waiter runs once the buffer has room, as for a streamed
   response's `BodyStream::on_drain` (ADR-101); documented as such.
4. **A waiter set inside the handler's callback** on a plain TCP session first moves what the
   callback sent so far (the session's batch, which is not in the connection's queue yet) into the
   connection's queue, so it runs once that is out, after the callback, not at once.
5. **Relaying and a bound of its own are the connection's.** Over HTTP/2 and HTTP/3 a stream's
   reads never pause for its own output and the connection is shared: `set_relayed` does nothing
   there and `set_max_queued_bytes` fails with `Unsupported` (the stream's queue is bounded by
   `H2Config::max_pending_bytes`, `H2WsOptions::max_queued_bytes` or QUIC's send buffers).
6. **`dial_blocking`'s wrapper forwards `on_message_ref`.** The handler `akio_ws::client`'s
   `dial_blocking` wraps to hand the sender back forwarded `on_message` only, so a handler that
   implements `on_message_ref` alone (as the trait allows) got nothing; it now forwards both.

## Consequences

- akit's WebSocket links map `hold_reads`, `on_drain`, `queued` and `peer` onto these, as its
  TCP links do onto `Conn`; the LLM mesh holds a link's reads while a stream's reader is slow past
  its window.
- Cost: an HTTP/2 client WebSocket's DATA reads one atomic flag; its link state grows by a flag and
  a waiter slot; an HTTP/3 WebSocket link holds an `Arc` of its connection's drain map. Nothing
  else on a data path. DEV-PLAN section 4 names what a benchmark task should measure.
- Tests (akio-http `tests/ws_pacing.rs`, akio-h3 `tests/ws_pacing.rs`, on the backends the suites
  run): over HTTP/1.1, HTTP/2 and HTTP/3, each side holding its reads while the other sends until
  it backs up (nothing more delivered, the sender's waiter not run), then resuming (everything
  delivered, the waiter run on the I/O thread, a later waiter at once); the peers' addresses; over
  TCP a waiter set inside the callback that runs after it, a relayed connection reading past its
  high watermark, and a bound of its own just under, at and over it; the HTTP/2 and HTTP/3
  refusals of a bound of its own; a waiter set after an HTTP/3 WebSocket closed.
- Not done: over HTTP/3, a waiter on a stream whose peer finished its half normally runs when the
  stream is next writable, stopped or the connection closes, not when the WebSocket's session
  ends; a `WsHandler::on_drain` callback (the request's alternative) was not added.
