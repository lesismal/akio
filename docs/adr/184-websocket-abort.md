# ADR-184: A WebSocket ended at once, what is queued dropped

English | [简体中文](184-websocket-abort.zh-CN.md)

Status: accepted (2026-11-27). akit's A238.

## Context

A tunnel link closes at once, dropping what it has queued, when the link fails (a frame that does
not parse, a breach of its protocol), when a hub kicks a peer or revokes its token, and when a role
stops: fit's WebSocket transport calls `Abort`, as its TCP, TLS and QUIC links call `Close`. akio-ws's
`WsSender` had `close(code, reason)` alone, which queues a close frame behind what is queued (a
tunnel link may have hundreds of MiB queued) and closes once it is written (a server) or once the
peer answers or `close_timeout` passes (a client). A kicked or failed WebSocket link so went on
sending what it had queued, and a client's waited for its peer. The transport under a WebSocket is
a TCP or TLS connection, an HTTP/2 stream (RFC 8441) or an HTTP/3 stream (RFC 9220), on the server
and the client side; nothing reached its abrupt end from the sender.

## Decision

1. **`WsSender::abort(&self)`**, beside `close`, callable from any thread and from the handler's
   callbacks: marks the sender closed (later sends fail with `Closed`) and aborted (nothing more
   reaches the handler: `WsSession::on_data` drops what follows, and an abort inside a callback
   stops the rest of that read), drops what a plain session's batch or other threads' late queue
   collected, and has the transport end now. No close frame: the peer sees the transport end, as
   when a process dies, which is what `on_close`'s 1006 (RFC 6455 section 7.1.5) reports to both
   ends. A second abort, and a `close` after it, do nothing; an abort cuts short a close handshake
   under way.
2. **The transport ends itself.** akio-ws's doc-hidden `WsLink` gets `abort()`, defaulting to
   `close()`; each transport implements it:
   - **TCP or TLS**: the connection's `close()`, which discards unsent data; `on_close` follows on
     the I/O thread and tells the session (1006). No TLS `close_notify`: an abort is not a clean
     end.
   - **HTTP/2, server**: `RST_STREAM CANCEL` whatever the state of the stream's halves (`close`
     ends our half with END_STREAM when the peer ended its own); the stream's queue is dropped
     with it and its parked session, dropped outside the core's lock, hears 1006.
   - **HTTP/2, client**: a new end of the link's queue, `Abort` (above `Now`), which the
     connection's loop takes as dropping what was queued and resetting the stream (`CANCEL`) even
     when the server ended its half; the stream's WebSocket hears 1006 as the stream goes.
   - **HTTP/3** (both sides): `RESET_STREAM` and `STOP_SENDING` with `H3_REQUEST_CANCELLED` (the
     QUIC send buffer is dropped), then the connection's handler ends the session. The session is
     the handler's, and QUIC tells a handler of the peer's resets, not its own; a peer that already
     finished its half answers a `STOP_SENDING` with nothing. So akio-quic gets
     `Connection::notify()` and `QuicHandler::on_notify(&mut self, c)`: a flag the delivering loop
     checks after the events, as for `on_shutdown`, so the handler runs work other threads left
     for it, once per batch of calls, on the thread that delivers the connection's events and
     never after `on_close`. akio-h3 queues the aborted stream in a per-connection list and
     notifies; its `on_notify` forgets the stream (the session hears 1006, its drain waiter runs).
     All in `Connection::without_driving`, so an abort from a thread holding a lock the handler's
     callbacks take does not run them in place.
3. **Over HTTP/2 and HTTP/3 the connection goes on**: an abort ends one WebSocket, not the
   connection that carries it and others (as resetting a request stream does); bytes already
   framed onto the shared connection still go out.

## Consequences

- akit's `WsWire::close` (a failed link, a kick, a revoked token, a role stopped) aborts, as
  `ConnWire::close` closes a TCP link; the LLM mesh's links the same.
- Cost: a WebSocket session reads one more atomic flag per read and per message delivered; a
  QUIC connection's delivering loop reads one more flag per round. DEV-PLAN section 4 names what a
  benchmark task should measure.
- Tests (akio-http `tests/ws_abort.rs` over HTTP/1.1 plain and TLS and over HTTP/2, akio-h3
  `tests/ws_abort.rs` over HTTP/3, akio-quic `tests/control.rs` for `notify`): either side aborting
  with a backlog queued behind a peer that holds its reads (its sends fail at once, both ends hear
  1006 once, the peer gets less than was sent), with nothing queued, and from inside its handler's
  callback (nothing after it delivered); over HTTP/1.1 a client's close handshake cut short; over
  HTTP/2 and HTTP/3 the connection and another WebSocket on it going on; `notify` from another
  thread, under `without_driving`, twice from a callback (once, after it) and after close (never).
- Not done: a status code other than 1006 for the aborting side (it sent nothing, so 1006 is what
  both ends saw); a TCP RST (`SO_LINGER` 0) in place of the FIN of `close`.
