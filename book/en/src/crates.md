# Crate map and API docs

The API reference is rustdoc. Until the crates are published, build it locally:

```console
$ cargo doc --workspace --no-deps --open
```

| Crate | Role | Book chapter |
|---|---|---|
| `flash` | facade: `Engine`, `Listener`, `Backend`, `Accel`, re-exports of the core API, `tls`, `ebpf` | [Concepts](concepts/index.md) |
| `flash-core` | `Conn`, `Handler`, `Acceptor`, `Config`, `Transport`, `Telemetry`; backend-facing traits | [Handlers](concepts/handlers.md) |
| `flash-pool` | the logical (blocking-work) pool | [Blocking work](concepts/blocking.md) |
| `flash-buf` | size-class buffer pool, `SharedBuf` | [Architecture](architecture.md) |
| `flash-timer` | hierarchical timer wheel used by the I/O loops | [Architecture](architecture.md) |
| `flash-sys` | audited `unsafe` syscall wrappers (poller, waker, sockets, batched UDP) | [Architecture](architecture.md) |
| `flash-epoll` | epoll / kqueue backend, UDP groups | [Engine and backends](concepts/engine.md) |
| `flash-uring` | io_uring backend | [Engine and backends](concepts/engine.md) |
| `flash-ebpf` | `SO_REUSEPORT` steering, sockmap relay | [Engine and backends](concepts/engine.md) |
| `flash-tls` (`flash::tls`) | rustls as a connection transport | [TLS](protocols/tls.md) |
| `flash-http` | HTTP/1.1, HTTP/2, Router, middleware, static files, clients, observability | [HTTP servers](protocols/http-server.md) |
| `flash-ws` | WebSocket server session and client | [WebSocket](protocols/websocket.md) |
| `flash-quic` | QUIC on quinn-proto | [QUIC and HTTP/3](protocols/quic-h3.md) |
| `flash-h3` | HTTP/3 and QPACK | [QUIC and HTTP/3](protocols/quic-h3.md) |
| `flash-grpc` | gRPC server and client | [gRPC](protocols/grpc.md) |
| `flash-arpc` | arpc (lesismal/arpc wire format) | [arpc](protocols/arpc.md) |
| `flash-socks` | SOCKS4/4a/5 and HTTP CONNECT proxies | [SOCKS](protocols/socks.md) |
| `flash-mux` | several protocols on one port | [Multiplexing](protocols/mux.md) |
| `flash-kcp` | KCP (kcp-go compatible) | [KCP](protocols/kcp.md) |

Design records: [docs/adr](https://github.com/lesismal/flash/tree/main/docs/adr). Plan and
status: [docs/ROADMAP.md](https://github.com/lesismal/flash/blob/main/docs/ROADMAP.md),
[docs/DEV-PLAN.md](https://github.com/lesismal/flash/blob/main/docs/DEV-PLAN.md). Benchmarks:
[docs/BENCHMARKS.md](https://github.com/lesismal/flash/blob/main/docs/BENCHMARKS.md).
