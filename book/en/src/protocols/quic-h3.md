# QUIC and HTTP/3

`only-quic` is QUIC v1 (RFC 9000, 9001, 9002) and v2 (RFC 9369) with datagrams (RFC 9221), implemented in the
crate as a sans-io state machine on `only-tls` and `only-crypto`, running on `only`'s UDP engine;
`only-h3` implements HTTP/3 (RFC 9114) and QPACK on top and serves any only-http `Service`.
Interop is tested in both directions with quic-go (raw QUIC echo of streams and datagrams,
with Retry, key updates, a 150 MB transfer, version 2 and client migration:
`tools/interop/quic/run.sh`) and, for HTTP/3,
with quic-go and fib's QUIC/HTTP/3 (`tools/interop/h3/run.sh`); ngtcp2 and OpenSSL 3.5's QUIC
stack are checked as clients of our servers in Docker (`tools/interop/quic/docker.sh`).

## QUIC

```rust,ignore
{{#include ../../../../crates/only-quic/examples/guide-quic.rs:server}}
```

```rust,ignore
{{#include ../../../../crates/only-quic/examples/guide-quic.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/only-quic/examples/guide-quic.rs:engine}}
```

How it fits on `only`:

- A `QuicServer` is the acceptor of a **UDP listener**. Every datagram of that listener goes
  through one endpoint, which routes it by connection id, so a client that migrates to a new
  address keeps its connection (after path validation). The endpoint also answers unknown
  versions with Version Negotiation, sends stateless resets for unknown connection ids and,
  under handshake load, validates client addresses with Retry.
- Each QUIC connection gets a `QuicHandler` from the factory. Its callbacks run one at a time, in
  order, on the I/O thread that read the datagram or on a shared timer thread; they must not
  block.
- `only_quic::dial(&engine, addr, server_name, client_cfg, handler)` starts a client
  connection on a UDP socket of its own; the engine needs `udp_client_threads(n)`.
- Full-size datagrams go out in batches of up to 10 with `Conn::send_segments` (UDP GSO /
  `sendmmsg` on Linux). Writes a handler makes from inside its own callbacks are corked: they
  leave together, with the acknowledgments, once the callback returns, so a request handler's
  headers, body and FIN usually share one packet. Acknowledgments are made once per receive
  batch, and received packets are decrypted in pooled buffers that their stream data shares. UDP
  GRO (`Config::udp_gro`, on by default on Linux) lets a bulk receiver take whole GSO batches.

`QuicHandler` callbacks: `on_connected`, `on_stream_opened`, `on_stream_data(c, id, data, fin)`
(required), `on_stream_reset`, `on_stream_stopped`, `on_streams_available`, `on_datagram`,
`on_close(reason)`.

`Connection` (cloneable, usable from any thread): `open_bi`, `open_uni`, `send(id, data)`,
`finish`, `reset`, `stop`, `queued_bytes(id)`, `send_datagram`, `close(code, reason)`,
`remote_addr`, `alpn`, `server_name`, `rtt`, `stats`, `is_closed`. Payloads are
`only_quic::Bytes` (reference counted and sliceable; received data is a slice of the decrypted
packet, so it is not copied again). Writes never block: `send` queues the bytes, which go out as
flow and congestion control allow; pace producers with `queued_bytes` (bytes not sent yet).

Configuration (TLS 1.3): `server_config(certs, key, alpn)` with `only::tls::Certificate` /
`PrivateKey`, `server_config_from(&only::tls::ServerConfig)`, `client_config(roots, alpn)` with
`only::tls::RootCerts`, `client_config_from(&only::tls::ClientConfig)`, and
`client_config_insecure(alpn)` for tests only. They return `only`'s own `ServerConfig` /
`ClientConfig`; `.transport(&TransportConfig)` sets stream limits, windows, idle timeout,
keep-alive, MTU discovery and the congestion controller, `ServerConfig::migration(bool)` client
migration. `server_config` enables session tickets, so clients reusing a `ClientConfig` resume
sessions; clones of a `ClientConfig` also share the NEW_TOKEN tokens servers hand out, which
skip the address-validation limits on the next connection. The `unstable` cargo feature is
reserved and enables nothing (it exposed quinn-proto before the in-house implementation).
`QuicServer::connections()` and `close_all(code, reason)` help at shutdown.

### Versions, ECN, BBR and migration

- **Versions**: QUIC v1 and v2 (RFC 9369). A server accepts both (`ServerConfig::versions`
  narrows it) and answers in the client's; a client starts in `ClientConfig::version` (v1 by
  default) and, when a server answers with Version Negotiation without it, starts over once in a
  version both speak, the version_information transport parameter (RFC 9368) guarding against a
  forged downgrade. `Connection::version()` tells which is in use. Compatible version negotiation
  (switching inside one handshake) is not implemented.
- **ECN** (`TransportConfig::ecn`, on by default): on Linux packets go out ECT(0), received
  codepoints are read per datagram and reported in ACK_ECN frames, the path is validated (RFC 9000
  section 13.4) and CE marks count as congestion; a path that bleaches or drops marks falls back
  to unmarked packets. Elsewhere packets are not marked (`ONLY_UDP_ECN=0` turns marking off on
  Linux too). `stats().ecn_capable` / `ecn_ce_events`.
- **Congestion control**: `TransportConfig::congestion` picks CUBIC (default), NewReno or
  `Congestion::Bbr`, an experimental BBR: BBRv1's model (Startup, Drain, ProbeBW, ProbeRTT) on
  delivery-rate samples with BBRv2/v3's bound on rounds losing or CE-marking more than 2%. On a
  simulated 20 Mbit/s, 40 ms path it keeps the RTT within about 6% of the minimum where CUBIC fills the
  buffer, and gets 4x CUBIC's goodput under 1% random loss.
- **Migration**: servers follow clients that change address (NAT rebinding) after path
  validation. A client moves by itself with `Connection::migrate(&engine)`: to a new local UDP
  socket, or to the server's preferred address when it offered one
  (`ServerConfig::preferred_address(addr)`, served by a clone of the same `QuicServer` on a
  second listener; `Connection::preferred_address()` on the client). The new path is probed
  under a connection ID not used before and adopted once answered; without an answer within
  three PTOs the connection stays where it was.

### 0-RTT

Off by default: `ServerConfig::zero_rtt(true)` and `ClientConfig::zero_rtt(true)`. A client
that resumes with a ticket allowing 0-RTT can open streams right after `dial` (under the limits
the server gave on the earlier connection) and their data leaves in 0-RTT packets with the
first flight; the server answers in 0.5-RTT, a round trip earlier than after a full handshake.
The server accepts 0-RTT only under the same transport limits as when it issued the ticket and
with only-tls's replay protection (a 10-second freshness window and a bounded record of recent
ClientHellos per server); otherwise, or when 0-RTT packets are lost, the data goes again in
1-RTT packets (after a Retry, in 0-RTT to the new connection ID). `Connection::early_data()`
tells the client what happened; `Connection::is_early(stream)` tells the server which streams
came early, and only-h3 marks such requests `Early-Data: 1` (RFC 8470), so handlers can answer
`425 Too Early` to what is not safe to repeat. `H3Client` sends its requests in 0-RTT when its
config enables it. 0-RTT data can be replayed (to another server sharing tickets, or within the
window by an attacker who can make the client retry) and is not forward secret.

## HTTP/3

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:server}}
```

`only_h3::serve(quic_cfg, service)` (or `serve_with(.., H3Config)`) returns a `QuicServer`
serving the service over HTTP/3. `only_h3::server_config(certs, key)` is `server_config` with
ALPN `h3`. Handlers get the same `Context` as on HTTP/1.1 and HTTP/2, including `detach`,
`stream_response`, trailers, streamed request bodies and WebSocket upgrades (below);
`ctx.req().version` is `Version::Http3`. `H3Config`: `max_body_bytes` (8 MiB, a larger buffered
body gets 413), `max_field_section_bytes` (64 KiB, sent as `SETTINGS_MAX_FIELD_SECTION_SIZE`;
larger gets 431) and the QPACK settings described below.

A common deployment serves the same application on TCP (HTTP/1.1 + HTTP/2 over TLS) and on UDP
(HTTP/3) in one engine: two listeners on the same port number. A `Router` is moved into its
acceptor and is not `Clone`, so either build it with a function called once per listener, or
share one: `let app = Arc::new(router);` and serve `move |ctx: &mut Context| app.call(ctx)`
(with `only_http::Service` in scope) on both.

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:client}}
```

`H3Client::dial(&engine, addr, server_name, client_cfg)` (ALPN `h3`), or `dial_with(.., &H3Config)`
for the field section and QPACK settings; requests sent before
the handshake completes wait for it (unless the client resumes with 0-RTT, see above). `request(method, path, headers, body, callback)`,
`request_blocking(..)`, `get(path, timeout)`, `upload(..)`, `websocket(..)`, `close()`,
`connection()`. Responses arrive buffered.

### Streamed request bodies

A service whose `body_mode` is `BodyMode::Stream` (wrap it in `Streaming`) is called at the
request's first body bytes and receives the body through `ctx.on_body`, piece by piece as QUIC
delivers it, exactly as on HTTP/1.1 and HTTP/2; `max_body_bytes` does not apply to it, and the
reader never holds a DATA frame (only an incomplete frame header or HEADERS frame), so a
multi-gigabyte upload passes through in constant memory. A `content-length` that does not match
the body resets the stream (`H3_MESSAGE_ERROR`). Buffered services are unchanged.

On the client, `upload(method, path, &headers, callback)` sends the head at once and returns an
`H3Upload`: `write(&[u8])` from any thread, `finish()`, and `queued_bytes()` to pace the writer;
the response goes to the callback.

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:upload}}
```

### WebSocket over HTTP/3

Servers advertise extended CONNECT (RFC 9220), and `ctx.upgrade_websocket(handler, &WsOptions)`
accepts one: subprotocols, the origin check and `permessage-deflate` work as on HTTP/1.1, the
answer is `200`, and the request stream then carries the WebSocket, framed by only-ws, with the
same `WsHandler` callbacks and `WsSender`. `Router` routes an extended CONNECT for `websocket`
to the path's GET route, so a single `.get("/ws", ...)` serves both HTTP/1.1 upgrades and
HTTP/3. `ctx.req().protocol` is `Some("websocket")` for such a request. WebSocket over HTTP/2
(RFC 8441) is not supported.

`H3Client::websocket(path, &H3WsOptions, handler, done)` (or `websocket_blocking`) opens one on
the client's connection, next to its requests: it waits for the server's SETTINGS, and `done`
gets the `WsSender` once the server answered `200` (`H3Error::Status` otherwise).

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:websocket}}
```

### QPACK dynamic table

QPACK (RFC 9204) compresses repeated header fields with a table each side's encoder fills
through an encoder stream. In `H3Config`:

- `qpack_max_table_capacity` (4096) and `qpack_blocked_streams` (16): what the peer's encoder
  may use against our decoder. A field section that refers to inserts not received yet waits
  for them, up to the blocked-streams limit; acknowledgements go back on our decoder stream.
  Peers such as nghttp3 (curl) and OpenSSL's QUIC use the table as soon as it is offered.
  Set the capacity to 0 to allow static references and literals only.
- `qpack_encoder_capacity` (0, off): this side's encoder table, at most what the peer allows.
  It only references entries the peer has acknowledged, so it never makes the peer wait; it
  inserts fields that repeat (not paths, dates, lengths, validators, credentials or cookies).
  It saves bytes on connections that carry many messages with the same custom fields, at the
  cost of a lock per message; quic-go and fib advertise no table, so it does nothing with them.
  [ADR-011](https://github.com/lesismal/only/blob/main/docs/adr/011-h3-websocket-qpack-streaming.md)
  explains the defaults.

## How HTTP/3 reuses `only-http`

only-http exposes a transport hook, `only_http::transport`: a transport parses a request and
calls `dispatch(service, request, sink)` with a `ResponseSink` that writes the response its own
way (`send` for a complete response, `start_stream` returning a `BodySink` for a streamed one).
only-h3 implements those sinks on QUIC streams, which is why routers, middleware and handlers
work unchanged. See [Architecture](../architecture.md).

What a request costs: frames are read in place from the received stream data, the field section
is decoded into a buffer the connection reuses and copied once into the request's `Headers`, and
the response's HEADERS frame is QPACK-encoded straight into the buffer handed to QUIC, together
with a body of up to 16 KiB and the trailers (one write per response; a larger body follows
without a copy). One connection with 64 requests in flight serves about 840 k req/s on a
Ryzen 7 7800X3D ([benchmarks](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.md)).

## Not done

Server push; WebSocket over HTTP/2 (RFC 8441); streamed responses on the client (`H3Client`
buffers them); the Duplicate instruction and dynamic name references in our QPACK encoder.
