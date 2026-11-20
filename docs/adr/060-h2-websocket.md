# ADR-060: WebSocket over HTTP/2 (RFC 8441)

English | [简体中文](060-h2-websocket.zh-CN.md)

Status: accepted (2026-11-20)

## Context

ADR-011 brought WebSocket to HTTP/3 (RFC 9220) through the existing API: the server accepts an
extended CONNECT in `Context::upgrade_websocket`, a `Router` answers it with the path's GET
route, the client opens one with `H3Client::websocket`, and only-ws writes through a hidden
`WsLink` seam. HTTP/2 was left out: `upgrade_websocket` answered 400 on an HTTP/2 stream, the
server did not advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`, a request with `:protocol` was
malformed, and `H2Client` had no WebSocket. Browsers open WebSockets on an HTTP/2 connection they
already hold when the server allows it, so an h2 origin forced them onto a second, HTTP/1.1
connection; and our own clients could not share one connection between requests and WebSockets.

## Decision

1. **Server: same API as HTTP/1.1 and HTTP/3.** The HTTP/2 server advertises
   `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441 §3) and accepts `:protocol` on CONNECT, which
   then needs `:scheme`, `:path` and `:authority` (§4; anything else, or `:protocol` on another
   method, is `RST_STREAM PROTOCOL_ERROR`). The request reaches the service with
   `Request::protocol` set and its stream open, like a streamed request; `Router` answers an
   extended CONNECT for `websocket` with the path's GET route (unchanged from ADR-011), so one
   `.get("/ws", ...)` serves WebSocket over HTTP/1.1, HTTP/2 and HTTP/3.
   `Context::upgrade_websocket` checks version 13 and the origin policy and negotiates the
   subprotocol and `permessage-deflate` as on HTTP/3, answers `200` with the head only, and
   the HTTP/2 session parks a `WsSession` (through `WsLink`) on the stream: its DATA frames
   are the WebSocket's bytes from then on. A request for another `:protocol` is a request the
   service answers. `H2Config::enable_connect_protocol` (default **on**) turns it all off: not
   advertised, and `:protocol` is malformed again.
2. **Client:** `H2Client::websocket(url, &H2WsOptions, handler, done)` and
   `websocket_blocking(..)`, on the client's existing connection next to its requests. The URL
   may be `http`, `https`, `ws` or `wss` (it only names `:scheme`, `:authority` and `:path`).
   It waits for the server's first SETTINGS (§3); `done` gets the `WsSender` once the server
   answered 2xx (`on_open` has run), or `ClientError::Status(u16)` (new, the enum is
   `#[non_exhaustive]`) for a refusal, `ClientError::Protocol` when the server does not allow
   extended CONNECT, `ClientError::Timeout` past `H2WsOptions::timeout`. `H2WsOptions` mirrors
   `H3WsOptions` (config, deflate offer, subprotocols, origin, headers, close timeout) plus
   `timeout` (10 s) and `max_queued_bytes` (8 MiB).
3. **Flow control and backpressure.** Each WebSocket is one stream with its own windows. What
   arrives is decoded when it arrives, so its receive window is given back as it is consumed
   (the server in quarters, as for other streams; the client at once, as for its responses);
   the peer's WebSocket is paced by our windows and our `max_message_bytes`. What we send waits
   for the stream's and the connection's send windows: on the server in the stream's queue,
   where `H2Config::max_pending_bytes` per stream and `max_conn_pending_bytes` per connection
   make further sends fail with `Overloaded`; on the client in the link's queue, bounded by
   `H2WsOptions::max_queued_bytes`. A message is taken whatever its size when nothing is queued
   (it is the application's, bounded by its own `max_message_bytes`, not the peer's): the bound
   is on what piles up behind a closed window, as over TCP, where only the unwritten tail
   counts. `WsSender::queued_bytes` reports that queue, so a producer can pace itself.
4. **Closing and resets.** A WebSocket close ends our half of the stream (END_STREAM after the
   close frame), the peer's END_STREAM ends its half, and the stream closes once both have; an
   accepted tunnel is half-closed in each direction on its own (an ordinary HTTP/2 request
   answered before its body ended is reset with `NO_ERROR` instead). END_STREAM from the peer
   is the transport closing, `RST_STREAM` either way and a lost connection are a close without
   handshake: the handler's `on_close` gets 1006 unless the handshake already ended it. A
   client whose close is not answered resets the stream (`CANCEL`) after its close timeout; a
   server whose END_STREAM is not answered resets it after 5 s. Graceful shutdown sends GOAWAY
   and closes every WebSocket with 1001, so the connection ends once they have.
5. **Client link.** `H2Client`'s connection state lives on its I/O thread. Its `WsLink` queues
   frames under a small mutex and hands them to the I/O thread with one `spawn_blocking`
   per batch (only when none is on its way), where they join the stream's upload queue that
   the windows drain, as `H2Upload` does.

## Consequences

- The server's SETTINGS frame is six bytes longer. `Stream` gains a flag and its parked
  context became a two-case enum (8 bytes more per open stream); requests without `:protocol`
  go through the same branches as before. h2c A/B on gpu51 (see the CHANGELOG entry for the
  numbers) is within run-to-run spread.
- Interop (`tools/interop/h2ws/run.sh`): Go's HTTP/2 both ways, over h2c and TLS: net/http's
  server, and golang.org/x/net/http2's transport as the client (net/http's own transport
  refuses the `:protocol` field; x/net needs `-tags http2legacy` on Go 1.27, and both
  `GODEBUG=http2xconnect=1`). Text, a 3 MiB binary message (many window updates),
  `permessage-deflate` both ways, fragmented messages, ping and the close handshake, with a
  plain request and a second WebSocket on the same connection.
- Fuzzing: a new target `h2_websocket` feeds WebSocket bytes (cut into DATA frames as the input
  says) or raw frames after an accepted extended CONNECT; `h2_server` gains extended CONNECT
  seeds.
- A peer that never ends its half after our END_STREAM keeps the stream up to 5 s; until then
  it counts against `max_concurrent_streams`. When that timer resets the stream before the
  handshake finished, the handler's `on_close` (1006) runs on the timer thread rather than the
  connection's I/O thread.
- Not done: WebSocket over HTTP/2 through the HTTP/1 `only_ws::client::dial` (it stays
  HTTP/1.1; HTTP/2 needs an `H2Client`), and RFC 8441 for other protocols than WebSocket on the
  client.
