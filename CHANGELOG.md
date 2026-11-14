# Changelog

[中文](CHANGELOG.zh-CN.md)

All notable changes to flash are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and flash adheres to
[Semantic Versioning](https://semver.org/) from 1.0.0 on, as defined in
[docs/api-stability.md](docs/api-stability.md). Deprecations follow
[docs/deprecation.md](docs/deprecation.md). All crates of the workspace share one version.

## [Unreleased]

### Added

- `flash-dpdk` (experimental, M6): a kernel-bypass backend. A userspace TCP/IP stack (smoltcp,
  IPv4) runs on flash I/O threads over a DPDK port (EAL init from `EalConfig`, one rx/tx queue
  pair and one thread per queue, mbuf rx/tx bursts, RSS with ARP fanned out between queues), a
  Linux TAP interface, an AF_PACKET socket or an in-process `MemoryWire`. UDP listeners deliver one
  datagram per `on_data` and TCP listeners a byte stream, with `dial` / `dial_udp`, backpressure,
  idle timeouts, telemetry and graceful shutdown, so protocol crates (flash-kcp, ...) run
  unchanged. Listeners on the same device share its stack and threads.
- `flash`: cargo features `dpdk` (`Backend::Dpdk(DpdkConfig)`, re-export `flash::dpdk`) and
  `dpdk-pmd` (also DPDK ports; links libdpdk found with pkg-config). Experimental: outside the
  semver promise (docs/api-stability.md).
- `flash-core` (backend-facing, `#[doc(hidden)]`): `ConnInner::new_virtual` and
  `ConnInner::drain_output` for connections whose bytes a userspace stack moves.
- `tools/dpdk/` (Dockerfile + `test.sh`) and the heavy CI job `dpdk`: builds against the
  distribution's DPDK and runs UDP/TCP echo against the kernel stack over DPDK's `net_tap` PMD
  (one and two queues), over smoltcp's TAP device and over AF_PACKET on a veth pair.

## [1.0.0-rc.1] - 2026-11-14

First release candidate of 1.0: the API is frozen for review. The public API of every crate is
recorded in `api/<crate>.txt` and checked in CI.

### Added

**Core engine (M0–M1)**
- Thread-per-core event loops: each I/O thread owns its reactor, connections, buffers and timer
  wheel; callbacks run inline on the owning thread, so per-connection handler state needs no lock
  (ADR-001..004).
- `Handler` / `Acceptor` / `fn_acceptor`, and `Conn`: a cloneable `Send + Sync` handle with
  `send`, `send_owned`, `send_shared` (`SharedBuf`), `send_segments`, `cork`/`flush`,
  `close`/`close_after_send`, `hold_reads`, `on_drain`; using a closed handle returns
  `Error::Closed`.
- Backends: epoll (Linux) and kqueue (macOS) in `flash-epoll`; `SO_REUSEPORT` accept distribution;
  asynchronous `Engine::dial`.
- Backpressure (write high watermark, `max_queued_bytes`), idle and write timeouts, connection
  limit, graceful shutdown with a timeout.
- `loom` models for the connection send path, stress tests with 5,000 simultaneous and 100,000
  idle connections.

**Logical pool, io_uring, UDP, TLS (M2)**
- `flash-pool` adaptive bounded pool; `Conn::spawn_blocking` with the completion back on the
  connection's I/O thread; ordered response slots (`Conn::reserve_response`, `ResponseSlot`,
  `ResponseStream`).
- Slow-callback detection (`Config::slow_callback_threshold`, `slow_hook`).
- `flash-uring`: io_uring backend (multishot accept/recv, provided-buffer rings, kernel probe with
  fallback to epoll); per-listener backend choice (`Listener::backend`).
- UDP: `Listener::udp` (one `Conn` per peer), `Engine::dial_udp`, `recvmmsg`/`sendmmsg`, UDP
  GSO/GRO, `udp_max_peers`.
- `flash-tls`: rustls as a sans-io transport layer under `Conn` (`Tls::server`, `Tls::client`,
  `tls_info`).

**HTTP and WebSocket (M3)**
- `flash-http`: HTTP/1.1 server with pipelining, chunked bodies and trailers, streaming request
  and response bodies, `Router` (static > `:param` > `*wildcard`, regex parameters, nesting,
  layers), middleware (recover, request id, CORS, logger, response time, compress, etag, csrf,
  limiter), static files (`files::Files`: ranges, precompressed twins, cache, `sendfile`), HTTP/1
  client (`client::Client`, `ResponseFuture`).
- `flash-ws`: RFC 6455 with permessage-deflate, `PreparedMessage` broadcast, subprotocols, origin
  check; server upgrade (`Context::upgrade_websocket`) and client (`flash_ws::client`); Autobahn
  suite clean.

**HTTP/2 and more protocols (M4)**
- HTTP/2 server on the same `Service` (h2c prior knowledge and upgrade, ALPN `h2`, flow control,
  HPACK, push) and `h2client::H2Client`; h2spec clean.
- `flash-mux` (several protocols on one port), `flash-arpc` (lesismal/arpc wire format),
  `flash-grpc` (unary and streaming gRPC on flash-http, gzip, deadlines, interceptors, optional
  prost helpers), `flash-socks` (SOCKS5/4/4a and HTTP CONNECT).

**QUIC, HTTP/3, KCP, eBPF (M5)**
- `flash-quic` (quinn-proto over flash UDP) and `flash-h3` (HTTP/3 with QPACK, client and server).
- `flash-kcp`: KCP compatible with skywind3000/kcp and kcp-go (crypts, Reed–Solomon FEC).
- `flash-ebpf`: `SO_REUSEPORT` steering by CPU or consistent hash (classic BPF unprivileged, eBPF
  when privileged) via `Accel::Ebpf`, and an in-kernel sockmap `Relay`.

**Production readiness (M6)**
- Telemetry: per-thread counters, `Engine::metrics` (Prometheus and JSON), connection table,
  slow-callback ring, live reload of settings (`Engine::reload`), `flash_http::observe` endpoints
  and HTTP metrics.
- Seeded chaos test suites (engine, fd exhaustion, TLS, HTTP/WebSocket).

**1.0 stabilization**
- 21 fuzz targets with corpora and coverage reporting; `cargo-deny`/`cargo-audit` gate; unsafe
  review (docs/unsafe-review.md), Miri and sanitizer jobs; strict lint set; mdBook guide in English
  and Chinese with migration guides; benchmark report.
- API freeze: `docs/api-stability.md` (semver, MSRV and platform policy), `docs/deprecation.md`,
  this changelog, public API snapshots (`api/*.txt`, `tools/api/public-api.sh`) checked by the CI
  job `public-api`, and a `semver-checks` job that activates once 1.0.0 is published.
- New API from the review: `AnyAcceptor` and `Listener::serve_any` (type-erased acceptors, used
  by `flash-mux`); `Request::new`, `ClientRequest::new`/`body`, `FileBody::new`; re-exports of
  `Part`, `ResponseStream`, `Transport` and `SharedBuf` from `flash` (and `SharedBuf` from
  `flash-core`); `flash_h3::H3Error`; `Display`/`Error` for `InflateError`, `ProtocolError`
  (ws), `FrameError` (arpc) and `QpackError`; `flash_core::Error::source` returns the I/O error.
- Every public type implements `Debug`; builder methods are `#[must_use]`.

### Changed (breaking, with migration)

Config and report structs and the enums that may grow are now `#[non_exhaustive]`: struct
literals no longer compile outside flash. Start from `Default` (or a preset) and assign fields:

```rust
// before
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// after
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

Affected structs: `flash`: `Config`, `UringConfig`, `EbpfConfig`, `PoolConfig`, `PoolStats`,
`SlowCallback`, `UdpStats`, `ConnInfo`, `LoopMeta`, `LoopCounters`, `LoopMetrics`, `Metrics`,
`ReloadReport`, `SlowRecord`; `flash-tls`: `TlsInfo`; `flash-http`: `HttpConfig`, `H2Config`,
`H2Options`, `WsOptions`, `Request`, `Response`, `FileBody`, `ClientRequest`, `ClientResponse`,
`Cors`, `Compress`, `LogRecord`, `HttpSnapshot`; `flash-ws`: `WsConfig`, `DialOptions`, `PmdOffer`,
`PmdParams`, `ProtocolError`; `flash-grpc`: `CallOptions`, `Status`, `Metadata`; `flash-kcp`:
`KcpConfig`, `Stats`; `flash-h3`: `H3Config`; `flash-ebpf`: `AttachOptions`, `SteerInfo`, `Probe`;
`flash-arpc`: `proto::Message`. Enums (add a wildcard arm to `match`): `flash::Error`, `Part`,
`Backend`, `Accel`, `AccelStatus`, `flash_http::Method`, `Version`, `BodyMode`, `ClientError`,
`flash_ws::client::WsClientError`, `deflate::InflateError`, `flash_mux::Rule`,
`flash_arpc::CallError`, `proto::Cmd`, `flash_quic::Error`, `flash_h3::qpack::QpackError`,
`flash_kcp::KcpError`, `CloseReason`, `flash_ebpf::Steering`, `HashKey`, `Tier`.

Renames and signature changes:

| Crate | Before | After |
|---|---|---|
| flash | `Listener::serve_dyn(Arc<dyn DynAcceptor>)` (hidden) | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| flash-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor` (also `From<Mux> for AnyAcceptor`; pass the `Mux` to `serve_any` directly) |
| flash-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| flash-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| flash-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| flash-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| flash-ws | `client::connect(..)` (blocking) | `client::dial_blocking(..)` |
| flash-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| flash-arpc | `dial(..)` (blocking) | `dial_blocking(..)` |
| flash-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| flash-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)` (same name as `GrpcServer::compress`) |
| flash-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| flash-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| flash-h3 | `server(quic, service)` | `serve(quic, service)` |
| flash-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)` (config before service, as in `flash_http::serve_with`) |
| flash-h3 | `H3Config::max_body`, `max_field_section` | `max_body_bytes`, `max_field_section_bytes` |
| flash-h3 | `Result<Response, String>` from `request`, `request_blocking`, `get` | `Result<Response, H3Error>` (`Closed`, `Reset(code)`, `Protocol`, `Timeout`) |
| flash-kcp | `Config` | `KcpConfig` |
| flash-kcp | `KcpServer::new`, `dial`, `dial_conv`, `Crypt::new` returning `Result<_, String>` | `std::io::Result<_>` (`InvalidInput` for bad settings) |
| flash-kcp | `Kcp::stats: [u64; 4]` (public field) | private; use `Session::stats()` |
| flash-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| flash-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

Moved out of the covered API (now `#[doc(hidden)]`; backend-facing or test helpers that may change
in any release): `flash_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter,
telemetry::json_str, telemetry::prometheus_header}` and backend-only `Telemetry` methods,
`flash::{DynAcceptor, DynHandler}` re-exports, `flash_http::transport`, `flash_ws::WsSession`,
`flash_ebpf::{cbpf, SLOTS, slot_table, expected_index}`.

Versioning: all crates are at `1.0.0-rc.1` and depend on each other with exact (`=`) versions;
`flash-sys`, `flash-buf`, `flash-timer`, `flash-pool`, `flash-epoll` and `flash-uring` are internal
crates without a semver promise of their own (see docs/api-stability.md).

[Unreleased]: https://github.com/lesismal/flash/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/flash/releases/tag/v1.0.0-rc.1
