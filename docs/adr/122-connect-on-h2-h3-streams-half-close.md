# ADR-122: CONNECT on HTTP/2 and HTTP/3 streams, and a connection's send direction shut down

English | [简体中文](122-connect-on-h2-h3-streams-half-close.zh-CN.md)

Status: accepted (2026-11-25)

## Context

fit's `forward_proxy` tunnels a `CONNECT` on an HTTP/1.1 connection, on an HTTP/2 stream
(RFC 9113 §8.5) and on an HTTP/3 stream (RFC 9114 §4.4). akio-http dispatched an HTTP/2 stream
as a tunnel only for an extended CONNECT (`:protocol`, ADR-113) and refused a plain one, which
omits `:scheme` and `:path`, as malformed; akio-h3 parsed a plain one but dispatched it only
once its stream ended, which a tunnel's never does before the answer. akio-socks's
`connect_proxy` tunnels with `Context::upgrade_raw`, HTTP/1 only: on a stream it returned
`false` and the request was never answered. akit answers such requests `501` meanwhile, and
asked for this as A134 (`akit/docs/akio-api-requests.md`).

A tunnel's halves close separately: RFC 9113 §8.5 has a proxy pass the client's END_STREAM on as
a TCP FIN. akio had no way to shut a connection's send direction down and keep reading:
`close_after_send` closes both.

## Decision

- **akio-http (HTTP/2).** A `CONNECT` without `:protocol` carries `:method` and `:authority`
  alone; `:scheme` or `:path`, or no `:authority`, makes it malformed (`RST_STREAM
  PROTOCOL_ERROR`). Its target is the authority, as an HTTP/1.1 `CONNECT`'s. Like an extended
  CONNECT it is dispatched at once, its DATA the streamed request body (`on_body`, held with
  `body_reads`), and a streamed `2xx` makes the stream a tunnel whose halves close separately
  (ADR-113's linger and reset apply). `H2Client` sends one in the same shape: a request whose
  method is `CONNECT` carries `:method` and `:authority` alone, the authority its `Host` field
  (else the URL's host), so `H2Client::open` is a tunnel's client end.
- **akio-h3.** A `CONNECT` (extended or not) is dispatched at its head, its stream's bytes going
  to the sink; a streamed `2xx` is a tunnel, as ADR-113 has it.
- **akio-socks.** `connect_proxy` relays a `CONNECT` on an HTTP/2 or HTTP/3 stream on that
  stream, next to the connection's other requests: the same target parsing, destination policy
  (403), name resolution on its resolver threads, connect check (`ProxyConfig::connected`),
  connect, handshake and idle timeouts as on HTTP/1.1, the failures answered `400`, `403`, `502`,
  `503` or `504`. Once the upstream is connected it answers a streamed `200`. The stream's DATA
  goes to the upstream as it arrives, its reads held (`BodyReads`) while the upstream's queue is
  past the watermark and until it is connected (what came before, at most the watermark, goes
  first); the upstream's bytes go out on the stream, its reads held while the stream's queue is
  past the watermark (`BodyStream::on_drain`). The client's END_STREAM shuts the upstream's send
  direction down once its bytes are written; the upstream's close ends our half. A client that
  resets its stream or goes closes the upstream (`on_gone`); a timeout answers `504` before the
  `200` and resets the stream after it. The watchdog's sessions are any client `Side` now: a
  connection or a stream.
- **akio-core.** `ConnInner::shutdown_write_after_send` and `Conn::shutdown_write_after_send`
  shut the send direction down (`shutdown(SHUT_WR)`) once the queue is empty, after a
  transport's closing message, and keep reading. It is done where the queue is written, which
  every stream backend (epoll, kqueue, io_uring) shares; datagram and virtual (DPDK) connections,
  and sends kernel TLS took over, ignore it.

Rejected:

- **`Context::upgrade_raw` on a stream.** A stream is not a byte stream of its own: its DATA
  shares the connection's flow control and its end is END_STREAM or a reset. The streamed
  request and response already carry what a tunnel needs (ADR-113 rejected a second path too).
- **Closing the upstream on the client's END_STREAM.** It drops whatever the upstream still
  sends back (an echo, the answer to a request sent with the end), which the half-close keeps.
- **Accepting a plain CONNECT with `:scheme` and `:path`.** RFC 9113 §8.5 makes it malformed,
  as Go's server does.

## Consequences

- akit's `forward_proxy` hands every `CONNECT` to `connect_proxy` on all three protocols.
- No new `unsafe`. `WriteState` gains two flags.
- Tests: `crates/akio-http/tests/tunnels.rs` (a plain CONNECT dispatched at once and tunnelled,
  malformed ones reset), `crates/akio-h3/tests/tunnel.rs` (the same on HTTP/3),
  `crates/akio-socks/tests/connect_streams.rs` (two tunnels on one HTTP/2 connection carrying
  4 MiB each way through the windows and watermarks, the client's END_STREAM, refusals `400`,
  `403` and `502`, a reset closing the upstream, an upstream's close ending our half, the idle
  timeout, `H2Client::open` as the client; a tunnel and a refusal on HTTP/3),
  `crates/akio/tests/conn_api.rs`
  (`shutdown_write_after_send_keeps_reading`); epoll and io_uring.
