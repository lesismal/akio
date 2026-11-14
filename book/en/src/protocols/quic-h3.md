# QUIC and HTTP/3

`flash-quic` runs the sans-io [quinn-proto](https://docs.rs/quinn-proto) state machine on flash's
UDP engine; `flash-h3` implements HTTP/3 (RFC 9114) and QPACK on top and serves any flash-http
`Service`. Interop is tested in both directions with quic-go and with fib's QUIC/HTTP/3
(`tools/interop/h3/run.sh`).

## QUIC

```rust,ignore
{{#include ../../../../crates/flash-quic/examples/guide-quic.rs:server}}
```

```rust,ignore
{{#include ../../../../crates/flash-quic/examples/guide-quic.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/flash-quic/examples/guide-quic.rs:engine}}
```

How it fits on flash:

- A `QuicServer` is the acceptor of a **UDP listener**. Every datagram of that listener goes
  through one `quinn_proto::Endpoint`, which routes it by connection id, so a client that
  migrates to a new address keeps its connection.
- Each QUIC connection gets a `QuicHandler` from the factory. Its callbacks run one at a time, in
  order, on the I/O thread that read the datagram or on a shared timer thread; they must not
  block.
- `flash_quic::dial(&engine, addr, server_name, client_cfg, handler)` starts a client
  connection on a UDP socket of its own; the engine needs `udp_client_threads(n)`.
- Transmits of several datagrams go out with `Conn::send_segments` (UDP GSO / `sendmmsg` on
  Linux). `Config::udp_gro` can help bulk receivers.

`QuicHandler` callbacks: `on_connected`, `on_stream_opened`, `on_stream_data(c, id, data, fin)`
(required), `on_stream_reset`, `on_stream_stopped`, `on_streams_available`, `on_datagram`,
`on_close(reason)`.

`Connection` (cloneable, usable from any thread): `open_bi`, `open_uni`, `send(id, data)`,
`finish`, `reset`, `stop`, `queued_bytes(id)`, `send_datagram`, `close(code, reason)`,
`remote_addr`, `alpn`, `server_name`, `rtt`, `stats`, `is_closed`. Writes never block:
`send` hands quinn what flow control allows and keeps the rest per stream until the peer grants
credit; pace producers with `queued_bytes`.

Configuration (TLS 1.3): `server_config(certs, key, alpn)` with `flash::tls::Certificate` /
`PrivateKey`, `server_config_from(&flash::tls::ServerConfig)`, `client_config(roots, alpn)` with
`flash::tls::RootCerts`, `client_config_from(&flash::tls::ClientConfig)`, and
`client_config_insecure(alpn)` for tests only. They return flash's own `ServerConfig` /
`ClientConfig`; `.transport(&TransportConfig)` sets stream limits, windows, idle timeout,
keep-alive, MTU discovery and the congestion controller, `ServerConfig::migration(bool)` client
migration. `StreamId`, `Dir`, `Side`, `ConnectionError` and `ConnectionStats` are flash types
too, so quinn-proto stays out of the API; the `unstable` cargo feature (outside the semver
promise) re-exports it as `flash_quic::proto` and adds `from_quinn` / `as_quinn_mut`.
`QuicServer::connections()` and `close_all(code, reason)` help at shutdown.

## HTTP/3

```rust,ignore
{{#include ../../../../crates/flash-h3/examples/guide-h3.rs:server}}
```

`flash_h3::serve(quic_cfg, service)` (or `serve_with(.., H3Config)`) returns a `QuicServer`
serving the service over HTTP/3. `flash_h3::server_config(certs, key)` is `server_config` with
ALPN `h3`. Handlers get the same `Context` as on HTTP/1.1 and HTTP/2, including `detach`,
`stream_response` and trailers; `ctx.req().version` is `Version::Http3`. Request bodies arrive
buffered. `H3Config`: `max_body` (8 MiB, larger gets 413) and `max_field_section` (64 KiB, sent
as `SETTINGS_MAX_FIELD_SECTION_SIZE`; larger gets 431).

A common deployment serves the same application on TCP (HTTP/1.1 + HTTP/2 over TLS) and on UDP
(HTTP/3) in one engine: two listeners on the same port number. A `Router` is moved into its
acceptor and is not `Clone`, so either build it with a function called once per listener, or
share one: `let app = Arc::new(router);` and serve `move |ctx: &mut Context| app.call(ctx)`
(with `flash_http::Service` in scope) on both.

```rust,ignore
{{#include ../../../../crates/flash-h3/examples/guide-h3.rs:client}}
```

`H3Client::dial(&engine, addr, server_name, client_cfg)` (ALPN `h3`); requests sent before
the handshake completes wait for it. `request(method, path, headers, body, callback)`,
`request_blocking(..)`, `get(path, timeout)`, `close()`, `connection()`.

## How HTTP/3 reuses flash-http

flash-http exposes a transport hook, `flash_http::transport`: a transport parses a request and
calls `dispatch(service, request, sink)` with a `ResponseSink` that writes the response its own
way (`send` for a complete response, `start_stream` returning a `BodySink` for a streamed one).
flash-h3 implements those sinks on QUIC streams, which is why routers, middleware and handlers
work unchanged. See [Architecture](../architecture.md).

## Not done

curl/quiche interop runs, WebSocket over HTTP/3 (extended CONNECT), the QPACK dynamic table
(capacity 0 is advertised), server push, streamed request bodies.
