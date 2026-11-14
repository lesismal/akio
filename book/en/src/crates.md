# Crate map and API docs

The API reference is rustdoc. Until the crates are published, build it locally:

```console
$ cargo doc --workspace --no-deps --open
```

The public crates follow semver from 1.0.0; `flash-pool`, `flash-buf`, `flash-timer`,
`flash-sys`, `flash-epoll` and `flash-uring` are internal implementation crates whose own APIs may
change in any release (use them through `flash` / `flash-core`). Items marked `#[doc(hidden)]`
are not covered either. Details:
[docs/api-stability.md](https://github.com/lesismal/flash/blob/main/docs/api-stability.md),
changes: [CHANGELOG.md](https://github.com/lesismal/flash/blob/main/CHANGELOG.md).

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
| `flash-prefork` | multi-process serving: supervisor, worker restarts, graceful shutdown and reload | [Prefork](prefork.md) |
| `flash-dpdk` (`flash::dpdk`, experimental) | kernel bypass: userspace TCP/IP (smoltcp) over DPDK / TAP / AF_PACKET | [Kernel bypass (DPDK)](dpdk.md) |
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
| `flash-webrtc` | WebRTC on str0m: ICE, DTLS-SRTP, data channels, media | [WebRTC](protocols/webrtc.md) |
| `flash-turn` | STUN codec, STUN and TURN servers | [WebRTC](protocols/webrtc.md) |
| `flash-media` | streaming media: hub, RTMP, RTSP, SRT, FLV, HTTP-FLV, WS-FLV, HLS, WHIP/WHEP signalling | [Streaming media](protocols/media.md) |

Design records: [docs/adr](https://github.com/lesismal/flash/tree/main/docs/adr). Plan and
status: [docs/ROADMAP.md](https://github.com/lesismal/flash/blob/main/docs/ROADMAP.md),
[docs/DEV-PLAN.md](https://github.com/lesismal/flash/blob/main/docs/DEV-PLAN.md). Benchmarks:
[docs/BENCHMARKS.md](https://github.com/lesismal/flash/blob/main/docs/BENCHMARKS.md).
