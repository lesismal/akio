# ADR-113: The HTTP/1 client hands a connection over on `101`, and a streamed `2xx` to an HTTP/2 extended CONNECT is a tunnel

English | [简体中文](113-client-upgrade-handover-h2-tunnels.zh-CN.md)

Status: accepted (2026-11-24)

## Context

akit proxies WebSockets (its iteration I49) as fit does: the client's handshake goes to the
upstream as an HTTP/1.1 upgrade, and once the upstream switches the client is switched with the
upstream's answer and the two byte streams are joined, each side's reads held while the other is
behind. An HTTP/1.1 client asks with `Upgrade`; an HTTP/2 or HTTP/3 one with an extended CONNECT
(RFC 8441, RFC 9220). akit asked for two things (A93, A94), checked against akio main `f6750e93`:

- **A93.** akio-http's `Client` read a `101 Switching Protocols` as a response without a body,
  ended the exchange and put the connection back in the keep-alive pool: the bytes that followed
  were "bytes nobody asked for" and closed it. Nothing could take the connection over, so a proxy
  could not reach an upstream's switched connection through the client, its pool, its TLS and its
  timeouts (`crates/akio-http/src/client.rs`, `advance`).
- **A94.** An HTTP/2 server already dispatches an extended CONNECT as a streamed request: the
  stream's DATA reaches `Context::on_body`, `BodyReads` holds it, and a streamed response
  (`Context::stream_response`, `Detached::stream_response`) writes back with `on_drain`. But only
  `Context::upgrade_websocket` marked the stream a tunnel, whose halves close separately: a
  streamed `200` finished while the client's half was open was answered with `RST_STREAM
  NO_ERROR`, which cut the client's last bytes (a WebSocket close frame's echo) off. akit's proxy
  must answer only after the upstream did, so it cannot use `upgrade_websocket` (which answers at
  once, with its own choice of subprotocol and extensions, and ends the WebSocket at the server).
  HTTP/3 (`akio-h3`) already keeps the two halves apart: QUIC closes a stream's directions
  separately, and a finished response does not stop the request side.

Constraints: no unsafe, nothing blocks an I/O thread, no new field in the HTTP/1 `Session` (its
`size_tests` keep it within 256 bytes), additive API.

## Decision

**A93: `ResponseHandler::on_upgrade`.**

- `ClientRequest::upgrade(protocol)` sets `Connection: Upgrade` and `Upgrade: <protocol>`; any
  request carrying a `Connection: upgrade` token asks the same.
- `ResponseHandler::on_upgrade(&mut self, head: &ResponseHead, conn: &RawConn) ->
  Option<Box<dyn RawHandler>>`, with a default returning `None`. On a `101` to a request that asked
  to upgrade, the client settles the request (its timeouts and `CancelToken` no longer apply,
  the connection never returns to the pool) and calls it. A returned handler gets the connection
  as a plain byte stream: `on_open` at once, then `on_data` with any bytes the server sent after
  the head, then as they arrive, and `on_close`. Neither `on_head`, `on_end` nor `on_error`
  follows. `None`: the `101` is delivered as a response without a body (`on_head`, `on_end`) and
  the connection closed.
- `RawConn` is akio-http's existing handle (`Context::upgrade_raw`'s): `send`, `hold_reads`,
  `on_drain`, `queued_bytes`, `set_relayed`, `close_after_send`; over TLS its bytes are sealed by
  the connection's transport as before.
- A whole response (`Client::request`, `send`) to an upgrade request returns the `101` and closes
  the connection. A `101` to a request that did not ask to upgrade fails it with
  `ClientError::Protocol`. Before the `101`, the request's header timeout, total timeout and
  token apply as to any request.

The handler state lives in the client connection's handler (`ClientConn`'s new `RState::Tunnel`),
so a read goes straight to the `RawHandler` with no lock and no copy.

**A94: a streamed `2xx` to an extended CONNECT opens the tunnel.**

- HTTP/2: a stream records that its request is an extended CONNECT; a streamed response whose
  status is `2xx` makes it a tunnel, exactly as `upgrade_websocket`'s `200` does. Its halves then
  close separately: our END_STREAM (`BodyStream::finish`) leaves the peer's half open, and its
  DATA still reaches `on_body` until it ends it (`BodyEvent::End`). A peer that never ends its half
  is reset (`CANCEL`) `TUNNEL_LINGER` (5 s) after our END_STREAM went out; the linger timer moves
  from the WebSocket link's `close_after_send` into the stream's half-close, where both tunnels
  pass. A non-`2xx` answer is no tunnel and keeps the ordinary behaviour (`RST_STREAM NO_ERROR`
  when answered before the request ended).
- HTTP/3: unchanged, documented and tested.

Rejected:

- **A new `Context::upgrade_tunnel`** taking the HTTP/2 or HTTP/3 stream over at once, with its
  own answer later: the streamed request and streamed response already carry everything a tunnel
  needs (reads held per stream, writes paced by `on_drain`, the client gone by `on_gone`); a
  second path would duplicate them.
- **Deferring the HTTP/1 server's upgrade** (`Detached::upgrade_raw`): the HTTP/1 session would
  have to stop parsing after a request that asks to upgrade until the handler decides, a state
  the 256-byte `Session` would pay for on every connection. `Context::upgrade_raw` in the handler,
  with the `101` or the refusal written by the handler once the upstream answered, needs nothing
  new.
- **Returning the connection from `on_head`** (a `ResponseBody::take_conn`): `on_head` is followed
  by `on_end` or `on_error`, a contract every handler relies on; a separate callback keeps it.

## Consequences

- akit's I49 proxies WebSockets from HTTP/1.1, HTTP/2 and HTTP/3 clients to HTTP/1.1 (and TLS)
  upstreams through its pools, with backpressure both ways.
- Costs: `Pending` and `Active` gain a `bool`; `RState` a boxed variant; an HTTP/2 `Stream` a
  `bool`. Nothing on the hot path changes: a request that does not upgrade reads the flag once.
  Not measured (rule 20).
- Tests: `akio-http/tests/tunnels.rs` (a `101` handing the connection over with the bytes after
  the head, outliving the request's timeout and token; a refusal, a handler that declines, a
  `101` not asked for, a whole response; a header timeout before the `101`; an HTTP/2 extended
  CONNECT answered with a streamed `200`: either half ending first, the linger reset, a refusal
  that is no tunnel) and `akio-h3/tests/tunnel.rs` (the HTTP/3 halves), on epoll and io_uring.
