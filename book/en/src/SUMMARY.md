# Summary

[Introduction](introduction.md)

# User guide

- [Getting started](getting-started.md)
- [Concepts](concepts/index.md)
  - [Engine, listeners and backends](concepts/engine.md)
  - [Handlers, acceptors and `Conn`](concepts/handlers.md)
  - [Blocking work: the logical pool](concepts/blocking.md)
  - [Backpressure](concepts/backpressure.md)
  - [Lifecycle and shutdown](concepts/lifecycle.md)
- [Protocols](protocols/index.md)
  - [TCP and UDP](protocols/tcp-udp.md)
  - [TLS](protocols/tls.md)
  - [HTTP/1.1 and HTTP/2 servers](protocols/http-server.md)
  - [Routing, middleware and static files](protocols/http-routing.md)
  - [HTTP clients](protocols/http-clients.md)
  - [WebSocket](protocols/websocket.md)
  - [QUIC and HTTP/3](protocols/quic-h3.md)
  - [gRPC](protocols/grpc.md)
  - [arpc](protocols/arpc.md)
  - [SOCKS and HTTP CONNECT proxies](protocols/socks.md)
  - [Protocol multiplexing](protocols/mux.md)
  - [KCP](protocols/kcp.md)

# Operations

- [Configuration reference](configuration.md)
- [Observability and hot reload](observability.md)
- [Performance tuning](performance.md)
- [Multi-process serving (prefork)](prefork.md)
- [Troubleshooting and FAQ](troubleshooting.md)

# Migration guides

- [From fib (Go)](migration/from-fib.md)
- [From tokio](migration/from-tokio.md)
- [From hyper and axum](migration/from-hyper-axum.md)

# Internals

- [Architecture](architecture.md)
- [Crate map and API docs](crates.md)
