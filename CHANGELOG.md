# Changelog

[中文](CHANGELOG.zh-CN.md)

All notable changes to flash are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and flash adheres to
[Semantic Versioning](https://semver.org/) from 1.0.0 on, as defined in
[docs/api-stability.md](docs/api-stability.md). Deprecations follow
[docs/deprecation.md](docs/deprecation.md). All crates of the workspace share one version.

## [Unreleased]

### Added

- `flash-prefork` (M6, optional): serve one program from several worker processes. A supervisor
  re-executes the current binary as N workers (no fork after threads), each running its own
  `Engine`; listeners are shared with `SO_REUSEPORT` (Linux default) or inherited from the
  supervisor (`ListenMode::Inherit`, the macOS default; no connection is refused across restarts
  and reloads); crashed workers are restarted with exponential backoff; SIGTERM/SIGINT drain the
  workers, SIGHUP (or `Supervisor::reload`) starts a new generation and stops each old worker once
  its replacement is ready; optional CPU pinning (Linux); `Worker` gives the index, worker count
  and generation. Example `prefork-http`, book chapter "Multi-process serving (prefork)".
- `flash::Listener::tcp_from_std`: serve an already bound and listening socket (inherited from a
  supervisor, systemd socket activation); internal `EpollGroup::bind_listener` /
  `UringGroup::bind_listener`.
- `flash-sys` (internal): `process` module (child fd inheritance, CPU affinity and parent-death
  signal in `pre_exec`, `take_inherited_fd`, `reserve_reuseport`, a self-pipe `signal_pipe`, `kill`).

### Fixed

- io_uring: during a graceful shutdown, connections the multishot accept completed before its
  cancellation took effect were reset; they are now served (`on_shutdown` after their first data),
  and the drain ends only once the accept has ended, so the listening socket is really closed.
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
- `Engine::bind_udp` and `UdpBinding` (flash, flash-core): an unconnected UDP socket bound
  while the engine runs, served like a UDP listener (one connection per peer address), that
  sends to any address with `UdpBinding::send_to`. What ICE agents and TURN relays need.
- `flash-turn` (new crate): the STUN codec (RFC 8489, with the TURN and ICE attributes,
  `MESSAGE-INTEGRITY`, `FINGERPRINT`), `StunServer`, and `TurnServer`, a TURN relay over UDP
  (RFC 8656): allocations with long-term credentials (`static_auth`, `ephemeral_auth` for the
  TURN REST API), permissions, channels, Send/Data indications, refresh, `EVEN-PORT` and
  `RESERVATION-TOKEN`, stateless nonces, quotas, and a peer policy refusing private and
  loopback peers by default; `TurnCore` is the same server as a sans-io state machine. Interop:
  pion/turn client and coturn's `turnutils_uclient`.
- `flash-webrtc` (new crate): WebRTC on the sans-io `str0m` 0.24 over flash UDP. `RtcServer`
  serves a UDP listener (ICE-lite by default, peers demultiplexed by ICE username and source
  address); `Endpoint` runs a full ICE agent on a `bind_udp` socket, with server-reflexive
  candidates from a STUN server. `Peer` (any thread) sends on data channels, writes media,
  requests keyframes, renegotiates; `PeerHandler` callbacks run one at a time per peer. DTLS
  1.2/1.3 with fingerprint verification, SRTP (AES-CM, AES-GCM), SCTP data channels (reliable or
  not, ordered or not), RTP/RTCP with NACK, PLI/FIR, TWCC. A pure-Rust crypto provider
  (RustCrypto and `dimpl`, no C toolchain). Interop with pion (data channels and media in both
  offer directions, through a flash TURN relay) and with fib's Go WebRTC (data channels);
  `tools/interop/webrtc/run.sh`.
- Fuzz targets `stun_message`, `turn_server` and `webrtc_sdp`.
- `flash-media` (M7 streaming media), a new crate: one stream hub with RTMP, RTSP, SRT,
  HTTP-FLV, WS-FLV, HLS and WHIP/WHEP signalling around it.
  - `hub`: streams by path, one publisher and many subscribers, GOP cache for fast start,
    `Dropper` (slow players drop to the next keyframe), publish / play auth hooks, reserve
    before the tracks are known, waiting for (re)publishers, `Timeline` timestamp
    normalization, per-stream statistics.
  - RTMP server: simple and Flash digest handshake, chunk stream, publish / play, Enhanced RTMP
    (H.265 `hvc1`, Opus); AMF0 / AMF3; FLV mux / demux (legacy and enhanced tags).
  - HTTP-FLV and WS-FLV playback (`HttpFlv`), HLS with MPEG-TS segments, LL-HLS parts,
    preload hints and blocking reload (`Hls`), `MediaHttp` dispatching both; MPEG-TS muxer.
  - RTSP 1.0 server (ANNOUNCE/RECORD, DESCRIBE/SETUP/PLAY over TCP-interleaved and UDP,
    Digest/Basic auth), RTP packetization for H.264/H.265/AAC/Opus/G.711 with decode times
    derived for B-frame video, SDP, and WHIP/WHEP HTTP signalling with a `WebRtcEngine`
    integration trait.
  - SRT live mode (HSv5 caller/listener, ARQ, TSBPD, AES-CTR encryption with passphrase,
    stream ID access control) with a hub-backed `SrtServer` and `srt::dial` / `push` / `pull`;
    incremental MPEG-TS demuxer (`mpegts::demux`).
  - Interop-tested with ffmpeg / ffprobe as publisher and player (SRT with libsrt in Docker);
    fuzz targets `rtmp_server`, `flv_demux`, `amf_decode`, `rtsp_server`, `sdp_parse`,
    `rtp_depacketize`, `mpegts_demux`, `srt_listener`, `srt_conn`.
- `flash_ws::WsSender::queued_bytes`, for pacing a producer that streams to a slow peer.
- `flash-bittorrent` (M7): bencode; .torrent v1 files (path safety, `Builder`) and magnet links;
  HTTP and UDP trackers as codecs, a `TrackerClient` (flash-http, `dial_udp`) and a
  `TrackerServer` (a flash-http service and a UDP acceptor on one store); the peer wire protocol
  with the Fast extension, the extension protocol, ut_metadata and ut_pex; MSE/PE (DH-768, RC4);
  uTP with LEDBAT; the mainline DHT; `port::UdpPort`, uTP and the DHT on one flash UDP listener;
  and a `client::Client` (magnets, rarest-first picker with endgame, pipelining, choking with
  optimistic unchoke, storage and SHA-1 on a logical pool, PEX, DHT, trackers, events). Interop
  with libtorrent 2.0 and aria2 1.37 (`tools/interop/bittorrent/run.sh`); fuzz targets
  `bt_bencode`, `bt_peer_wire`, `bt_krpc`, `bt_utp`, `bt_tracker`, `bt_mse`.
- `Engine::dial_udp_from`: a peer connection on a UDP listener's own socket, so datagrams to a
  new address leave from the listener's port (DHT nodes, uTP).

### Fixed

- `Engine::dial` no longer picks a UDP group (and fails) when the engine has both TCP listeners
  and UDP listeners or UDP client threads, but no `client_threads`.

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
