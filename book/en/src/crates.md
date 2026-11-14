# Crate map and API docs

The API reference is rustdoc. Until the crates are published, build it locally:

```console
$ cargo doc --workspace --no-deps --open
```

The public crates follow semver from 1.0.0; `only-pool`, `only-buf`, `only-timer`,
`only-sys`, `only-epoll` and `only-uring` are internal implementation crates whose own APIs may
change in any release (use them through `only` / `only-core`). Items marked `#[doc(hidden)]`
are not covered either. Details:
[docs/api-stability.md](https://github.com/lesismal/flash/blob/main/docs/api-stability.md),
changes: [CHANGELOG.md](https://github.com/lesismal/flash/blob/main/CHANGELOG.md).

| Crate | Role | Book chapter |
|---|---|---|
| `only` | facade: `Engine`, `Listener`, `Backend`, `Accel`, re-exports of the core API, `tls`, `ebpf` | [Concepts](concepts/index.md) |
| `only-core` | `Conn`, `Handler`, `Acceptor`, `Config`, `Transport`, `Telemetry`; backend-facing traits | [Handlers](concepts/handlers.md) |
| `only-pool` | the logical (blocking-work) pool | [Blocking work](concepts/blocking.md) |
| `only-buf` | size-class buffer pool, `SharedBuf` | [Architecture](architecture.md) |
| `only-timer` | hierarchical timer wheel used by the I/O loops | [Architecture](architecture.md) |
| `only-sys` | audited `unsafe` syscall wrappers (poller, waker, sockets, batched UDP) | [Architecture](architecture.md) |
| `only-epoll` | epoll / kqueue backend, UDP groups | [Engine and backends](concepts/engine.md) |
| `only-uring` | io_uring backend | [Engine and backends](concepts/engine.md) |
| `only-ebpf` | `SO_REUSEPORT` steering, sockmap relay | [Engine and backends](concepts/engine.md) |
| `only-prefork` | multi-process serving: supervisor, worker restarts, graceful shutdown and reload | [Prefork](prefork.md) |
| `only-dpdk` (`only::dpdk`, experimental) | kernel bypass: userspace TCP/IP (smoltcp) over DPDK / TAP / AF_PACKET | [Kernel bypass (DPDK)](dpdk.md) |
| `only-tls` (`only::tls`) | TLS (rustls underneath) as a connection transport | [TLS](protocols/tls.md) |
| `only-http` | HTTP/1.1, HTTP/2, Router, middleware, static files, clients, observability | [HTTP servers](protocols/http-server.md) |
| `only-ws` | WebSocket server session and client | [WebSocket](protocols/websocket.md) |
| `only-quic` | QUIC on quinn-proto | [QUIC and HTTP/3](protocols/quic-h3.md) |
| `only-h3` | HTTP/3 and QPACK | [QUIC and HTTP/3](protocols/quic-h3.md) |
| `only-grpc` | gRPC server and client | [gRPC](protocols/grpc.md) |
| `only-arpc` | arpc (lesismal/arpc wire format) | [arpc](protocols/arpc.md) |
| `only-socks` | SOCKS4/4a/5 and HTTP CONNECT proxies | [SOCKS](protocols/socks.md) |
| `only-mux` | several protocols on one port | [Multiplexing](protocols/mux.md) |
| `only-kcp` | KCP (kcp-go compatible) | [KCP](protocols/kcp.md) |
| `only-webrtc` | WebRTC on str0m: ICE, DTLS-SRTP, data channels, media | [WebRTC](protocols/webrtc.md) |
| `only-turn` | STUN codec, STUN and TURN servers | [WebRTC](protocols/webrtc.md) |
| `only-media` | streaming media: hub, RTMP, RTSP, SRT, FLV, HTTP-FLV, WS-FLV, HLS, WHIP/WHEP signalling | [Streaming media](protocols/media.md) |
| `only-bittorrent` | BitTorrent: trackers, peer wire + MSE, uTP, DHT, client (libtorrent and aria2 compatible) | [BitTorrent](protocols/bittorrent.md) |

Design records: [docs/adr](https://github.com/lesismal/flash/tree/main/docs/adr). Plan and
status: [docs/ROADMAP.md](https://github.com/lesismal/flash/blob/main/docs/ROADMAP.md),
[docs/DEV-PLAN.md](https://github.com/lesismal/flash/blob/main/docs/DEV-PLAN.md). Benchmarks:
[docs/BENCHMARKS.md](https://github.com/lesismal/flash/blob/main/docs/BENCHMARKS.md).
