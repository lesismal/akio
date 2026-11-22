# QUIC and HTTP/3

`only-quic` is QUIC v1 (RFC 9000, 9001, 9002) and v2 (RFC 9369) with datagrams (RFC 9221), implemented in the
crate as a sans-io state machine on `only-tls` and `only-crypto`, running on `only`'s UDP engine;
`only-h3` implements HTTP/3 (RFC 9114) and QPACK on top and serves any only-http `Service`.
Interop is tested in both directions with quic-go (raw QUIC echo of streams and datagrams,
with Retry, key updates, a 150 MB transfer, version 2 and client migration:
`tools/interop/quic/run.sh`) and, for HTTP/3,
with quic-go and fib's QUIC/HTTP/3 (`tools/interop/h3/run.sh`); ngtcp2 and OpenSSL 3.5's QUIC
stack are checked as clients of our servers in Docker (`tools/interop/quic/docker.sh`), and
ngtcp2's own client and server for compatible version negotiation, both ways
(`tools/interop/quic/ngtcp2-cvn.sh`). quiche (0.30.1) is checked both ways in Docker:
quiche-client against our HTTP/3 server (Version Negotiation, many requests, uploads, 0-RTT,
migration) and, over raw QUIC streams with HTTP/0.9 (`hq-interop`), against `only-quic`; `H3Client`
and `only-quic`'s client against quiche-server, with and without Retry
(`tools/interop/quic/quiche.sh`).

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
(required), `on_stream_reset`, `on_stream_stopped`, `on_streams_available`,
`on_stream_writable`, `on_datagram`, `on_close(reason)`.

`Connection` (cloneable, usable from any thread): `open_bi`, `open_uni`, `send(id, data)`,
`finish`, `reset`, `stop`, `queued_bytes(id)`, `send_capacity(id)`, `send_datagram`,
`spawn_blocking(work)`, `close(code, reason)`, `remote_addr`, `alpn`, `server_name`, `rtt`,
`stats`, `is_closed`. Payloads are `only_quic::Bytes` (reference counted and sliceable; received
data is a slice of the decrypted packet, so it is not copied again). Writes never block: `send`
queues the bytes, which go out as flow and congestion control allow.

Send buffers are bounded. A stream holds what was written and not yet acknowledged up to
`TransportConfig::stream_send_buffer` (16 MiB), and all streams of a connection together up to
`send_buffer` (16 MiB). Past either, `send` fails with `Error::Overloaded` and does not take the
data; `on_stream_writable(c, id)` follows once the stream's and the connection's buffers are down
to three quarters (once per refusal). A producer writes until refused and resumes from that
callback; `send_capacity(id)` tells the room left (and arms the same callback when it is zero),
so a file can be read only when there is room for the piece. A write accepted below the limit may
pass it, so a stream holds at most its limit plus one write. `spawn_blocking(work)` runs `work`
on the engine's logical pool (disk reads and other blocking work), from where it may call the
connection.

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

Limits and their defaults (every one bounded; the `None` / `MAX` values lift a limit):

| Setting | Default | Meaning |
|---|---|---|
| `TransportConfig::max_concurrent_bidi_streams`, `max_concurrent_uni_streams` | 100, 100 | streams the peer may have open at once |
| `TransportConfig::stream_receive_window` | 1.25 MB | bytes the peer may send on one stream ahead of the application |
| `TransportConfig::receive_window` | 10 MB (8 × the stream window) | the same over all streams of a connection (`None`: unlimited) |
| `TransportConfig::send_window` | 10 MB | bytes in flight (sent, not acknowledged) on all streams |
| `TransportConfig::stream_send_buffer` | 16 MiB | bytes one stream holds for sending before `send` fails with `Overloaded` |
| `TransportConfig::send_buffer` | 16 MiB | the same over all streams of a connection |
| `TransportConfig::max_idle_timeout` | 30 s | closes a silent connection |
| `TransportConfig::datagram_receive_buffer_size`, `datagram_send_buffer_size` | 1.25 MB, 1 MiB | unreliable datagrams buffered each way |
| `ServerConfig::max_connections(n)` | 10,000 | connections a server holds (handshaking, open or closing); beyond it a new client is refused at once with `CONNECTION_REFUSED`, keeping no state (rate limited like stateless resets; counted by `QuicServer::refused_connections()`) |

Above 4096 handshakes in progress, new clients must also prove their address with a Retry.

### Versions, ECN, BBR and migration

- **Versions**: QUIC v1 and v2 (RFC 9369). A server accepts both (`ServerConfig::versions`
  narrows it) and answers in the client's; a client starts in `ClientConfig::version` (v1 by
  default) and, when a server answers with Version Negotiation without it, starts over once in a
  version both speak, the version_information transport parameter (RFC 9368) guarding against a
  forged downgrade. `Connection::version()` tells which is in use.
- **Compatible version negotiation** (RFC 9368 section 4, [ADR-013](https://github.com/lesismal/only/blob/main/docs/adr/013-shared-anti-replay-and-compatible-vn.md)):
  `ServerConfig::prefer_version(Version::V2)` moves clients that start in v1 and list v2 in their
  version_information to v2 within the handshake, without a round trip (and `V1` the other way).
  Off by default (the server answers in the client's version). The server reads the whole first
  ClientHello before answering, so it works when the ClientHello spans several packets, after a
  Retry and with 0-RTT (the client's 0-RTT packets stay in its first version, RFC 9369 section
  4.1). only-quic clients always follow such a switch. Clients without version_information
  (quic-go) are never switched; ngtcp2 switches both ways.

  ```rust,ignore
  let cfg = only_quic::server_config(certs, key, &[b"h3"])?
      .prefer_version(only_quic::Version::V2);
  ```
- **Tickets and tokens are per version** (RFC 9369 section 5, [ADR-014](https://github.com/lesismal/only/blob/main/docs/adr/014-quic-version-bound-resumption.md)):
  a session ticket or NEW_TOKEN token belongs to the version of the connection that issued it,
  the negotiated one after a compatible switch. A server resumes only a ticket from the version
  the client started in (another one gets a full handshake, without 0-RTT) and validates the
  address only with a token from it (Retry tokens too). A client never presents a v1 ticket or
  token in v2 or the other way round: it starts in the version of its newest ticket for the
  server (else of its token) when it speaks it, rather than `ClientConfig::version`. So a client
  configured for v1 that a server preferring v2 moved to v2 starts its next connection in v2 and
  resumes, with 0-RTT, without a switch.
- **ECN** (`TransportConfig::ecn`, on by default): on Linux, macOS and over only-dpdk packets go out ECT(0), received
  codepoints are read per datagram and reported in ACK_ECN frames, the path is validated (RFC 9000
  section 13.4) and CE marks count as congestion; a path that bleaches or drops marks falls back
  to unmarked packets. Elsewhere packets are not marked (`ONLY_UDP_ECN=0` turns marking off on
  Linux and macOS too). `stats().ecn_capable` / `ecn_ce_events`.
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
config enables it. 0-RTT data can be replayed (within the window by an attacker who can make the
client retry, or to another server sharing tickets unless the servers share the anti-replay
record: build their TLS configuration with `session_ticket_key` and `anti_replay_store`, see the
TLS chapter) and is not forward secret.

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

Responses follow the QUIC send buffers: what a stream cannot take yet waits with the response
and goes out as `on_stream_writable` reports room, so a client that grants no flow-control credit
holds the server to `stream_send_buffer` per stream. A file body (`Response::from_file`, static
files) is read 256 KiB at a time on the engine's logical pool, each piece only once the stream
has room for it, never on the I/O thread (if the pool is full, one piece is read in place). A
streamed body's `write` fails with `Overloaded` while the buffer is full, as on HTTP/1.1 and
HTTP/2: write again once `queued_bytes()` went down.

A common deployment serves the same application on TCP (HTTP/1.1 + HTTP/2 over TLS) and on UDP
(HTTP/3) in one engine: two listeners on the same port number. A `Router` is moved into its
acceptor and is not `Clone`, so either build it with a function called once per listener, or
share one: `let app = Arc::new(router);` and serve `move |ctx: &mut Context| app.call(ctx)`
(with `only_http::Service` in scope) on both.

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:client}}
```

`H3Client::dial(&engine, addr, server_name, client_cfg)` (ALPN `h3`), or `dial_with(.., H3ClientOptions)`
for limits and QPACK settings; requests sent before
the handshake completes wait for it (unless the client resumes with 0-RTT, see above). `request(method, path, headers, body, callback)`,
`request_blocking(..)`, `get(path, timeout)`, `upload(..)`, `open(..)`, `websocket(..)`,
`close()`, `connection()`. Responses to `request` arrive buffered; `open` streams them (below).
`H3Client::dial_with(.., H3ClientOptions)` sets the limits: `max_body_bytes` (8 MiB) and
`max_field_section_bytes` (64 KiB, advertised) stop the response stream and fail the request
with `H3Error::TooLarge`; `request_timeout` (30 s, from `request` or `websocket` to the
complete response, a WebSocket's or a streamed response's head; uploads have none) resets the
stream and fails it with
`H3Error::Timeout` (that callback runs on a timer thread). It also takes the QPACK settings
(below).

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

### Streamed responses on the client

`open(method, path, &headers, on_event)` is the counterpart of `H2Client::open`: it returns an
`H3Upload` for the request body (`finish()` at once when there is none) and reports the response
to `on_event` on the connection's I/O thread as it arrives: `H3Event::Head { status, headers }`,
`Data(&[u8])` for each piece (not buffered, not limited by `max_body_bytes`), `Trailers`, then
`End`, or `Error(H3Error)`. Upload and download can run at the same time. `hold_reads(true)` on
the handle pauses reading: QUIC flow control then stops the server once the stream's receive
window (`TransportConfig::stream_receive_window`) is used, so a slow consumer bounds the memory a
download takes; `hold_reads(false)` resumes it. Both work from any thread, the event callback
included (`only_quic::Connection::hold_reads` does the same for any stream). `cancel()` resets
the stream and nothing more is reported. `request_timeout` applies until the head.

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:download}}
```

### WebSocket over HTTP/3

Servers advertise extended CONNECT (RFC 9220), and `ctx.upgrade_websocket(handler, &WsOptions)`
accepts one: subprotocols, the origin check and `permessage-deflate` work as on HTTP/1.1, the
answer is `200`, and the request stream then carries the WebSocket, framed by only-ws, with the
same `WsHandler` callbacks and `WsSender`. `Router` routes an extended CONNECT for `websocket`
to the path's GET route, so a single `.get("/ws", ...)` serves both HTTP/1.1 upgrades and
HTTP/3. `ctx.req().protocol` is `Some("websocket")` for such a request. WebSocket over HTTP/2
(RFC 8441) works the same way, see [WebSocket](websocket.md#websocket-over-http2).

`H3Client::websocket(path, &H3WsOptions, handler, done)` (or `websocket_blocking`) opens one on
the client's connection, next to its requests: it waits for the server's SETTINGS, and `done`
gets the `WsSender` once the server answered `200` (`H3Error::Status` otherwise).

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:websocket}}
```

### QPACK dynamic table

QPACK (RFC 9204) compresses repeated header fields with a table each side's encoder fills
through an encoder stream. In `H3Config` (servers) and `H3ClientOptions` (clients):

- `qpack_max_table_capacity` (4096) and `qpack_blocked_streams` (16): what the peer's encoder
  may use against our decoder. A field section that refers to inserts not received yet waits
  for them, up to the blocked-streams limit; acknowledgements go back on our decoder stream.
  Peers such as nghttp3 (curl) and OpenSSL's QUIC use the table as soon as it is offered.
  Set the capacity to 0 to allow static references and literals only.
- `qpack_encoder_capacity` (0, off): this side's encoder table, at most what the peer allows.
  It inserts a field the second time it sees it (never paths, dates, lengths, validators,
  credentials or cookies), with a static or dynamic name reference or a literal name; refers to
  entries inserted by the same message with post-base indices; uses dynamic name references in
  literals; duplicates entries about to be evicted; and evicts only entries the peer has
  acknowledged. It makes at most as many of the peer's streams wait for its inserts as the
  peer's `SETTINGS_QPACK_BLOCKED_STREAMS` allows (0: never). It saves bytes on connections that
  carry many messages with the same custom fields, at the cost of a lock per message and the
  peer's acknowledgements; quic-go, fib and curl advertise no table, so it does nothing with
  them. [ADR-011](https://github.com/lesismal/only/blob/main/docs/adr/011-h3-websocket-qpack-streaming.md)
  and [ADR-061](https://github.com/lesismal/only/blob/main/docs/adr/061-qpack-encoder-h3-streamed-responses.md)
  explain the defaults.

## How HTTP/3 reuses `only-http`

only-http exposes a transport hook, `only_http::transport`: a transport parses a request and
calls `dispatch_conn(service, request, sink, tag)` with its connection's `ConnSink`, which writes
the response its own way (`send` for a complete response, `start_stream` returning a `BodySink`
for a streamed one) to the request the tag names. The sink is shared by the connection's
requests (through a thin `SharedSink`), and request targets and headers are built with
`request_target` and `request_headers` in the storage of a finished request kept per thread;
after encoding a response's head the sink hands its header storage back with
`recycle_response_headers`. So none of these costs an allocation per request (ADR-025, ADR-081;
the older boxed `ResponseSink` with `dispatch` is deprecated). only-h3 implements the sink on QUIC streams, which is why routers, middleware and
handlers work unchanged. See [Architecture](../architecture.md).

What a request costs: frames are read in place from the received stream data, the field section
is decoded into a buffer the connection reuses and copied once into the request's `Headers`, and
the response's HEADERS frame is QPACK-encoded straight into the buffer handed to QUIC, together
with a body of up to 16 KiB and the trailers (one write per response; a larger body follows
without a copy). One connection with 64 requests in flight serves about 840 k req/s on a
Ryzen 7 7800X3D ([benchmarks](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.md)).

## Not done

Server push is left out on purpose: browsers dropped it, and 103 Early Hints replaced its use
([ADR-061](https://github.com/lesismal/only/blob/main/docs/adr/061-qpack-encoder-h3-streamed-responses.md)).
