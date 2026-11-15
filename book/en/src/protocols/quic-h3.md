# QUIC and HTTP/3

`only-quic` is QUIC v1 (RFC 9000, 9001, 9002) with datagrams (RFC 9221), implemented in the
crate as a sans-io state machine on `only-tls` and `only-crypto`, running on `only`'s UDP engine;
`only-h3` implements HTTP/3 (RFC 9114) and QPACK on top and serves any only-http `Service`.
Interop is tested in both directions with quic-go (raw QUIC echo of streams and datagrams,
with Retry, key updates and a 150 MB transfer: `tools/interop/quic/run.sh`) and, for HTTP/3,
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

## HTTP/3

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:server}}
```

`only_h3::serve(quic_cfg, service)` (or `serve_with(.., H3Config)`) returns a `QuicServer`
serving the service over HTTP/3. `only_h3::server_config(certs, key)` is `server_config` with
ALPN `h3`. Handlers get the same `Context` as on HTTP/1.1 and HTTP/2, including `detach`,
`stream_response` and trailers; `ctx.req().version` is `Version::Http3`. Request bodies arrive
buffered. `H3Config`: `max_body` (8 MiB, larger gets 413) and `max_field_section` (64 KiB, sent
as `SETTINGS_MAX_FIELD_SECTION_SIZE`; larger gets 431).

A common deployment serves the same application on TCP (HTTP/1.1 + HTTP/2 over TLS) and on UDP
(HTTP/3) in one engine: two listeners on the same port number. A `Router` is moved into its
acceptor and is not `Clone`, so either build it with a function called once per listener, or
share one: `let app = Arc::new(router);` and serve `move |ctx: &mut Context| app.call(ctx)`
(with `only_http::Service` in scope) on both.

```rust,ignore
{{#include ../../../../crates/only-h3/examples/guide-h3.rs:client}}
```

`H3Client::dial(&engine, addr, server_name, client_cfg)` (ALPN `h3`); requests sent before
the handshake completes wait for it. `request(method, path, headers, body, callback)`,
`request_blocking(..)`, `get(path, timeout)`, `close()`, `connection()`.

## How HTTP/3 reuses `only-http`

only-http exposes a transport hook, `only_http::transport`: a transport parses a request and
calls `dispatch(service, request, sink)` with a `ResponseSink` that writes the response its own
way (`send` for a complete response, `start_stream` returning a `BodySink` for a streamed one).
only-h3 implements those sinks on QUIC streams, which is why routers, middleware and handlers
work unchanged. See [Architecture](../architecture.md).

## Not done

curl/quiche interop runs, WebSocket over HTTP/3 (extended CONNECT), the QPACK dynamic table
(capacity 0 is advertised), server push, streamed request bodies.
