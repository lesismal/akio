# Crate map and API docs

The API reference is rustdoc. Until the crates are published, build it locally:

```console
$ cargo doc --workspace --no-deps --open
```

The public crates follow semver from 1.0.0; `akio-pool`, `akio-buf`, `akio-timer`,
`akio-sys`, `akio-epoll`, `akio-uring` and `akio-crypto` are internal implementation crates whose own APIs may
change in any release (use them through `akio` / `akio-core`). Items marked `#[doc(hidden)]`
are not covered either. Details:
[docs/api-stability.md](https://github.com/lesismal/akio/blob/main/docs/api-stability.md),
changes: [CHANGELOG.md](https://github.com/lesismal/akio/blob/main/CHANGELOG.md).

| Crate | Role | Book chapter |
|---|---|---|
| `akio` | facade: `Engine`, `Listener`, `Backend`, `Accel`, re-exports of the core API, `tls`, `ebpf` | [Concepts](concepts/index.md) |
| `akio-core` | `Conn`, `Handler`, `Acceptor`, `Config`, `Transport`, `Telemetry`; backend-facing traits | [Handlers](concepts/handlers.md) |
| `akio-log` (`akio::log`) | logging facade: levels, targets, key-values, `Logger`, built-in loggers, `AKIO_LOG` filters, compile-time caps, spans with W3C trace context, optional `log` bridge | [Observability](observability.md) |
| `akio-pool` | the logical (blocking-work) pool | [Blocking work](concepts/blocking.md) |
| `akio-buf` | size-class buffer pool, `SharedBuf` | [Architecture](architecture.md) |
| `akio-timer` | hierarchical timer wheel used by the I/O loops | [Architecture](architecture.md) |
| `akio-sys` | audited `unsafe` syscall wrappers (poller, waker, sockets, batched UDP, OS randomness) | [Architecture](architecture.md) |
| `akio-crypto` | dependency-free crypto for the protocol crates: SHA-1/2, MD5, HMAC, HKDF, PBKDF2, CRC-32, constant-time AES (CTR, GCM), ChaCha20-Poly1305, base64, randomness | [Architecture](architecture.md) |
| `akio-epoll` | epoll / kqueue backend, UDP groups | [Engine and backends](concepts/engine.md) |
| `akio-uring` | io_uring backend | [Engine and backends](concepts/engine.md) |
| `akio-ebpf` | `SO_REUSEPORT` steering, sockmap relay | [Engine and backends](concepts/engine.md) |
| `akio-prefork` | multi-process serving: supervisor, worker restarts, graceful shutdown and reload | [Prefork](prefork.md) |
| `akio-dpdk` (`akio::dpdk`, experimental) | kernel bypass: its own userspace TCP/IP stack over DPDK / TAP / AF_PACKET | [Kernel bypass (DPDK)](dpdk.md) |
| `akio-tls` (`akio::tls`) | TLS 1.3 / 1.2 (in-house) as a connection transport | [TLS](protocols/tls.md) |
| `akio-http` | HTTP/1.1, HTTP/2, Router, middleware, static files, clients, observability | [HTTP servers](protocols/http-server.md) |
| `akio-export` | push export: metrics, spans and logs over OTLP (HTTP with protobuf or JSON, gRPC; plain or TLS) and metrics to StatsD / DogStatsD, from a background thread | [Observability](observability.md#push-export-otlp-and-statsd) |
| `akio-ws` | WebSocket server session and client | [WebSocket](protocols/websocket.md) |
| `akio-quic` | QUIC v1 and v2 (own implementation) | [QUIC and HTTP/3](protocols/quic-h3.md) |
| `akio-h3` | HTTP/3 and QPACK | [QUIC and HTTP/3](protocols/quic-h3.md) |
| `akio-grpc` | gRPC server and client | [gRPC](protocols/grpc.md) |
| `akio-protobuf`, `akio-protobuf-build` | protobuf runtime, and the `.proto` code generator for `build.rs` (no protoc, gRPC stubs) | [gRPC](protocols/grpc.md) |
| `akio-arpc` | arpc (lesismal/arpc wire format) | [arpc](protocols/arpc.md) |
| `akio-socks` | SOCKS4/4a/5 (CONNECT, BIND, UDP ASSOCIATE, access control) and HTTP CONNECT proxies | [SOCKS](protocols/socks.md) |
| `akio-mux` | several protocols on one port | [Multiplexing](protocols/mux.md) |
| `akio-kcp` | KCP (kcp-go compatible) | [KCP](protocols/kcp.md) |
| `akio-webrtc` | WebRTC on the in-house stack (`akio-ice`, `akio-dtls`, `akio-srtp`, `akio-rtp`, `akio-sctp`): ICE, DTLS-SRTP, data channels, media | [WebRTC](protocols/webrtc.md) |
| `akio-turn` | STUN codec, STUN and TURN servers | [WebRTC](protocols/webrtc.md) |
| `akio-media` | streaming media: hub, RTMP, RTSP, SRT, FLV, HTTP-FLV, WS-FLV, HLS, WHIP/WHEP signalling | [Streaming media](protocols/media.md) |
| `akio-bittorrent` | BitTorrent: trackers, peer wire + MSE, uTP, DHT, client (libtorrent and aria2 compatible) | [BitTorrent](protocols/bittorrent.md) |

Design records: [docs/adr](https://github.com/lesismal/akio/tree/main/docs/adr). Plan and
status: [docs/ROADMAP.md](https://github.com/lesismal/akio/blob/main/docs/ROADMAP.md),
[docs/DEV-PLAN.md](https://github.com/lesismal/akio/blob/main/docs/DEV-PLAN.md). Benchmarks:
[docs/BENCHMARKS.md](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.md).
