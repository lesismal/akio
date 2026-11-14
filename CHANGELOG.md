# Changelog

[中文](CHANGELOG.zh-CN.md)

All notable changes to `only` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and `only` adheres to
[Semantic Versioning](https://semver.org/) from 1.0.0 on, as defined in
[docs/api-stability.md](docs/api-stability.md). Deprecations follow
[docs/deprecation.md](docs/deprecation.md). All crates of the workspace share one version.

## [Unreleased]

### Renamed: the project is now `only`

The crates.io name `flash` is taken, so the project was renamed from **flash** to **only**
(DEV-PLAN "1.0.0 release decisions"). Every crate, path, identifier and name changed with it;
the entries below already use the new names.

| Before | After |
|---|---|
| crate `flash` (`use flash::...`) | `only` (`use only::...`) |
| crates `flash-*` (`flash_*` in code), directories `crates/flash-*` | `only-*` (`only_*`), `crates/only-*`: `flash-sys` → `only-sys`, `flash-buf` → `only-buf`, `flash-timer` → `only-timer`, `flash-pool` → `only-pool`, `flash-core` → `only-core`, `flash-epoll` → `only-epoll`, `flash-uring` → `only-uring`, `flash-tls` → `only-tls`, `flash-http` → `only-http`, `flash-ws` → `only-ws`, `flash-mux` → `only-mux`, `flash-socks` → `only-socks`, `flash-arpc` → `only-arpc`, `flash-grpc` → `only-grpc`, `flash-kcp` → `only-kcp`, `flash-quic` → `only-quic`, `flash-h3` → `only-h3`, `flash-ebpf` → `only-ebpf`, `flash-prefork` → `only-prefork`, `flash-dpdk` → `only-dpdk`, `flash-turn` → `only-turn`, `flash-webrtc` → `only-webrtc`, `flash-media` → `only-media`, `flash-bittorrent` → `only-bittorrent` |
| environment variables `FLASH_*` (`FLASH_TEST_BACKEND`, `FLASH_UDP_GSO`, `FLASH_UDP_GRO`, `FLASH_PREFORK_*`, `FLASH_CHAOS*`, `FLASH_DPDK_*` ...) | `ONLY_*` |
| Prometheus series `flash_*` (`flash_connections_open`, `flash_http_requests_total`, `flash_tls_handshake_failures_total` ...) | `only_*` |
| log targets `flash`, `flash_http::access`, `flash_webrtc` ... | `only`, `only_http::access`, `only_webrtc` ... |
| thread names `flash-io-*`, `flash-pool`, `flash-quic-timer` ... | `only-io-*`, `only-pool`, `only-quic-timer` ... |
| `flash_media::srt` alias `FlashConn` | `OnlyConn` |
| API snapshots `api/flash-*.txt`, tool Docker images and volumes `flash-*` | `api/only-*.txt`, `only-*` |

The GitHub repository and the documentation site keep their `lesismal/only` URLs until the
repository itself is renamed.

### Changed (breaking, before 1.0.0): pre-1.0 dependencies wrapped

rustls 0.23, quinn-proto 0.11, str0m 0.24 and prost 0.13 no longer appear in the covered API, so
upgrading them (or replacing them with in-house code) is not a breaking change after 1.0.0.
Raw access moved behind new `unstable` cargo features (`only`, `only-tls`, `only-quic`,
`only-webrtc`), outside the semver promise like the `prost` feature of `only-grpc`
(docs/api-stability.md, "Public dependencies").

| Before | After |
|---|---|
| `only::tls::rustls` (re-export) | `unstable` feature only |
| `rustls::ServerConfig::builder()...with_single_cert(chain, key)` + `alpn_protocols` | `only::tls::ServerConfig::builder(chain, key).alpn([..]).build()?` (also `sni_cert`, `client_auth_required` / `_optional`, `session_cache`, `session_tickets`, `tls13_only`) |
| `rustls::ClientConfig::builder().with_root_certificates(roots)...` | `only::tls::ClientConfig::builder().roots(roots).alpn([..]).build()?` (also `client_cert`, `sni`, `resumption`, `tls13_only`, `insecure_skip_verify`) |
| `CertificateDer`, `PrivateKeyDer`, `RootCertStore` | `only::tls::{Certificate, PrivateKey, RootCerts}` (`from_pem`, `from_der`, `from_pkcs8_der`) |
| `Tls::server(Arc<rustls::ServerConfig>, a)`, `Tls::client(Arc<rustls::ClientConfig>, ..)` | `Tls::server(ServerConfig, a)`, `Tls::client(ClientConfig, ..)` |
| `Client::with_tls(Arc<rustls::ClientConfig>)`, `H2Client::dial(.., Some((Arc<..>, name)), ..)`, `DialOptions::tls: Option<Arc<..>>` | the same with `only::tls::ClientConfig` |
| `only_quic::{proto, rustls}` re-exports, `VarInt` | `unstable` feature only (`proto`); `VarInt` removed |
| `only_quic::{StreamId, Dir, ConnectionError, TransportConfig}` (quinn's) | `only`'s own types (plus `Side`, `Congestion`, `UdpStats`); `ConnectionError` variants are struct-like (`ApplicationClosed { code, reason }`, `TransportError { code, reason }`) |
| `Connection::stats() -> quinn_proto::ConnectionStats` | `ConnectionStats` (`udp_tx`, `udp_rx`, `rtt`, `cwnd`, `lost_packets` ...) |
| `server_config(Vec<CertificateDer>, PrivateKeyDer, alpn) -> quinn_proto::ServerConfig` | `server_config(Vec<Certificate>, PrivateKey, alpn) -> only_quic::ServerConfig` (`.transport(&TransportConfig)`, `.migration(bool)`) |
| `server_config_from(rustls::ServerConfig)`, `client_config(RootCertStore, ..)`, `client_config_from(rustls::ClientConfig)` | `server_config_from(&only::tls::ServerConfig)`, `client_config(RootCerts, ..)`, `client_config_from(&only::tls::ClientConfig)` |
| `Error::Connect(quinn_proto::ConnectError)` | `Error::Connect(String)` |
| `only_h3::server_config(Vec<CertificateDer>, PrivateKeyDer)`, `serve(quinn_proto::ServerConfig, ..)`, `H3Client::dial(.., quinn_proto::ClientConfig)` | `Certificate` / `PrivateKey`, `only_quic::ServerConfig`, `only_quic::ClientConfig` |
| `only_grpc::codec::{encode, decode}` bound on `prost::Message` | bound on `only_grpc::codec::Message` (`encode_to`, `decode_from`); the `prost` feature implements it for prost messages |
| `only_webrtc::str0m` re-export, `Peer::with_rtc`, `crypto_provider`, `generate_certificate` | `unstable` feature only (`str0m`, `with_rtc`, `crypto_provider_str0m`); `generate_certificate` is internal |
| str0m's `ChannelId`, `ChannelConfig`, `Reliability`, `Mid`, `Pt`, `MediaKind`, `Direction`, `Frequency`, `MediaTime`, `MediaData`, `MediaAdded`, `KeyframeRequest(Kind)`, `RtpPacket`, `Candidate`, `IceConnectionState`, `RtcConfig`, `Event` | `only`'s own types of the same names (`ChannelConfig` is `#[non_exhaustive]`: `ChannelConfig::new(label)` then set fields; `MediaData::data` / `RtpPacket::payload` are `Arc<[u8]>`) |
| `create_offer(h, \|api: &mut SdpApi\| ..)`, `renegotiate(..)`; `api.add_channel(label.into())`, `api.add_media(kind, dir, None, None, None)` | `SdpChanges`: `add_channel(label)`, `add_channel_with_config(&cfg)`, `add_media(kind, dir, None, None)`, `set_direction`, `stop_media`, `ice_restart` |
| `Peer::open_channel(ChannelConfig)`, `payload_type(mid, str0m::format::Codec)` | `open_channel(&ChannelConfig)`, `payload_type(mid, only_webrtc::Codec)` |
| `PeerHandler::on_event(&str0m::Event)` | `on_event(&Event)`: `Event::ChannelBufferedAmountLow(id)` or `Event::Other(OtherEvent)` |
| `Error::Rtc(str0m::RtcError)`, `impl From<str0m::RtcError> for Error` | `Error::Rtc(only_webrtc::RtcError)`; new `Error::InvalidCandidate` |
| `Endpoint::add_candidate(str0m::Candidate)` | `Candidate::host(addr)` / `server_reflexive(addr, base)` / `relayed(addr, base)` / `parse(sdp)` |

### Changed: in-house cryptography (`only-crypto`, DEV-PLAN wave A)

- New internal crate `only-crypto` (std only, `#![deny(unsafe_code)]` except its AES-NI / ARMv8
  AES module): SHA-1, SHA-224/256, SHA-384/512, MD5, HMAC, HKDF, PBKDF2, CRC-32 / CRC-32C,
  AES-128/192/256 (CPU instructions when detected, else constant-time fixsliced software) with CTR, AES-GCM with a constant-time GHASH, ChaCha20-Poly1305, base64 (strict decoding), OS
  randomness and a ChaCha20 generator. Tested against NIST CAVP, RFC and Wycheproof vectors and
  cross-checked (tests and fuzz targets) against the crates it replaces.
- `only-kcp`, `only-turn`, `only-ws`, `only-http`, `only-media`, `only-bittorrent` and
  `only-webrtc` use it instead of sha1, sha2, md-5, hmac, pbkdf2, aes, aes-gcm, ctr, crc32fast,
  base64 and getrandom (those remain dev-/fuzz-only references, and transitively under
  str0m/dimpl until wave D). Public APIs and wire formats are unchanged (KCP crypt incl. golden
  datagrams sealed by the old code, TURN MESSAGE-INTEGRITY/FINGERPRINT, WebSocket accept keys,
  BitTorrent info hashes and MSE, SRT key wrap and AES-CTR, RTMP digest handshake, SRTP).
- `only-sys` (internal, `#[doc(hidden)]`): `fill_random` over `getrandom(2)` / `getentropy(2)`
  with a `/dev/urandom` fallback.

### Added

- `only-prefork` (M6, optional): serve one program from several worker processes. A supervisor
  re-executes the current binary as N workers (no fork after threads), each running its own
  `Engine`; listeners are shared with `SO_REUSEPORT` (Linux default) or inherited from the
  supervisor (`ListenMode::Inherit`, the macOS default; no connection is refused across restarts
  and reloads); crashed workers are restarted with exponential backoff; SIGTERM/SIGINT drain the
  workers, SIGHUP (or `Supervisor::reload`) starts a new generation and stops each old worker once
  its replacement is ready; optional CPU pinning (Linux); `Worker` gives the index, worker count
  and generation. Example `prefork-http`, book chapter "Multi-process serving (prefork)".
- `only::Listener::tcp_from_std`: serve an already bound and listening socket (inherited from a
  supervisor, systemd socket activation); internal `EpollGroup::bind_listener` /
  `UringGroup::bind_listener`.
- `only-sys` (internal): `process` module (child fd inheritance, CPU affinity and parent-death
  signal in `pre_exec`, `take_inherited_fd`, `reserve_reuseport`, a self-pipe `signal_pipe`, `kill`).

### Fixed

- io_uring: during a graceful shutdown, connections the multishot accept completed before its
  cancellation took effect were reset; they are now served (`on_shutdown` after their first data),
  and the drain ends only once the accept has ended, so the listening socket is really closed.
- `only-dpdk` (experimental, M6): a kernel-bypass backend. A userspace TCP/IP stack (smoltcp,
  IPv4) runs on `only` I/O threads over a DPDK port (EAL init from `EalConfig`, one rx/tx queue
  pair and one thread per queue, mbuf rx/tx bursts, RSS with ARP fanned out between queues), a
  Linux TAP interface, an AF_PACKET socket or an in-process `MemoryWire`. UDP listeners deliver one
  datagram per `on_data` and TCP listeners a byte stream, with `dial` / `dial_udp`, backpressure,
  idle timeouts, telemetry and graceful shutdown, so protocol crates (only-kcp, ...) run
  unchanged. Listeners on the same device share its stack and threads.
- `only`: cargo features `dpdk` (`Backend::Dpdk(DpdkConfig)`, re-export `only::dpdk`) and
  `dpdk-pmd` (also DPDK ports; links libdpdk found with pkg-config). Experimental: outside the
  semver promise (docs/api-stability.md).
- `only-core` (backend-facing, `#[doc(hidden)]`): `ConnInner::new_virtual` and
  `ConnInner::drain_output` for connections whose bytes a userspace stack moves.
- `tools/dpdk/` (Dockerfile + `test.sh`) and the heavy CI job `dpdk`: builds against the
  distribution's DPDK and runs UDP/TCP echo against the kernel stack over DPDK's `net_tap` PMD
  (one and two queues), over smoltcp's TAP device and over AF_PACKET on a veth pair.
- `Engine::bind_udp` and `UdpBinding` (`only`, only-core): an unconnected UDP socket bound
  while the engine runs, served like a UDP listener (one connection per peer address), that
  sends to any address with `UdpBinding::send_to`. What ICE agents and TURN relays need.
- `only-turn` (new crate): the STUN codec (RFC 8489, with the TURN and ICE attributes,
  `MESSAGE-INTEGRITY`, `FINGERPRINT`), `StunServer`, and `TurnServer`, a TURN relay over UDP
  (RFC 8656): allocations with long-term credentials (`static_auth`, `ephemeral_auth` for the
  TURN REST API), permissions, channels, Send/Data indications, refresh, `EVEN-PORT` and
  `RESERVATION-TOKEN`, stateless nonces, quotas, and a peer policy refusing private and
  loopback peers by default; `TurnCore` is the same server as a sans-io state machine. Interop:
  pion/turn client and coturn's `turnutils_uclient`.
- `only-webrtc` (new crate): WebRTC on the sans-io `str0m` 0.24 over `only` UDP. `RtcServer`
  serves a UDP listener (ICE-lite by default, peers demultiplexed by ICE username and source
  address); `Endpoint` runs a full ICE agent on a `bind_udp` socket, with server-reflexive
  candidates from a STUN server. `Peer` (any thread) sends on data channels, writes media,
  requests keyframes, renegotiates; `PeerHandler` callbacks run one at a time per peer. DTLS
  1.2/1.3 with fingerprint verification, SRTP (AES-CM, AES-GCM), SCTP data channels (reliable or
  not, ordered or not), RTP/RTCP with NACK, PLI/FIR, TWCC. A pure-Rust crypto provider
  (RustCrypto and `dimpl`, no C toolchain). Interop with pion (data channels and media in both
  offer directions, through a `only` TURN relay) and with fib's Go WebRTC (data channels);
  `tools/interop/webrtc/run.sh`.
- Fuzz targets `stun_message`, `turn_server` and `webrtc_sdp`.
- `only-media` (M7 streaming media), a new crate: one stream hub with RTMP, RTSP, SRT,
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
- `only_ws::WsSender::queued_bytes`, for pacing a producer that streams to a slow peer.
- `only-bittorrent` (M7): bencode; .torrent v1 files (path safety, `Builder`) and magnet links;
  HTTP and UDP trackers as codecs, a `TrackerClient` (only-http, `dial_udp`) and a
  `TrackerServer` (a only-http service and a UDP acceptor on one store); the peer wire protocol
  with the Fast extension, the extension protocol, ut_metadata and ut_pex; MSE/PE (DH-768, RC4);
  uTP with LEDBAT; the mainline DHT; `port::UdpPort`, uTP and the DHT on one `only` UDP listener;
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
- Backends: epoll (Linux) and kqueue (macOS) in `only-epoll`; `SO_REUSEPORT` accept distribution;
  asynchronous `Engine::dial`.
- Backpressure (write high watermark, `max_queued_bytes`), idle and write timeouts, connection
  limit, graceful shutdown with a timeout.
- `loom` models for the connection send path, stress tests with 5,000 simultaneous and 100,000
  idle connections.

**Logical pool, io_uring, UDP, TLS (M2)**
- `only-pool` adaptive bounded pool; `Conn::spawn_blocking` with the completion back on the
  connection's I/O thread; ordered response slots (`Conn::reserve_response`, `ResponseSlot`,
  `ResponseStream`).
- Slow-callback detection (`Config::slow_callback_threshold`, `slow_hook`).
- `only-uring`: io_uring backend (multishot accept/recv, provided-buffer rings, kernel probe with
  fallback to epoll); per-listener backend choice (`Listener::backend`).
- UDP: `Listener::udp` (one `Conn` per peer), `Engine::dial_udp`, `recvmmsg`/`sendmmsg`, UDP
  GSO/GRO, `udp_max_peers`.
- `only-tls`: rustls as a sans-io transport layer under `Conn` (`Tls::server`, `Tls::client`,
  `tls_info`).

**HTTP and WebSocket (M3)**
- `only-http`: HTTP/1.1 server with pipelining, chunked bodies and trailers, streaming request
  and response bodies, `Router` (static > `:param` > `*wildcard`, regex parameters, nesting,
  layers), middleware (recover, request id, CORS, logger, response time, compress, etag, csrf,
  limiter), static files (`files::Files`: ranges, precompressed twins, cache, `sendfile`), HTTP/1
  client (`client::Client`, `ResponseFuture`).
- `only-ws`: RFC 6455 with permessage-deflate, `PreparedMessage` broadcast, subprotocols, origin
  check; server upgrade (`Context::upgrade_websocket`) and client (`only_ws::client`); Autobahn
  suite clean.

**HTTP/2 and more protocols (M4)**
- HTTP/2 server on the same `Service` (h2c prior knowledge and upgrade, ALPN `h2`, flow control,
  HPACK, push) and `h2client::H2Client`; h2spec clean.
- `only-mux` (several protocols on one port), `only-arpc` (lesismal/arpc wire format),
  `only-grpc` (unary and streaming gRPC on only-http, gzip, deadlines, interceptors, optional
  prost helpers), `only-socks` (SOCKS5/4/4a and HTTP CONNECT).

**QUIC, HTTP/3, KCP, eBPF (M5)**
- `only-quic` (quinn-proto over `only` UDP) and `only-h3` (HTTP/3 with QPACK, client and server).
- `only-kcp`: KCP compatible with skywind3000/kcp and kcp-go (crypts, Reed–Solomon FEC).
- `only-ebpf`: `SO_REUSEPORT` steering by CPU or consistent hash (classic BPF unprivileged, eBPF
  when privileged) via `Accel::Ebpf`, and an in-kernel sockmap `Relay`.

**Production readiness (M6)**
- Telemetry: per-thread counters, `Engine::metrics` (Prometheus and JSON), connection table,
  slow-callback ring, live reload of settings (`Engine::reload`), `only_http::observe` endpoints
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
  by `only-mux`); `Request::new`, `ClientRequest::new`/`body`, `FileBody::new`; re-exports of
  `Part`, `ResponseStream`, `Transport` and `SharedBuf` from `only` (and `SharedBuf` from
  `only-core`); `only_h3::H3Error`; `Display`/`Error` for `InflateError`, `ProtocolError`
  (ws), `FrameError` (arpc) and `QpackError`; `only_core::Error::source` returns the I/O error.
- Every public type implements `Debug`; builder methods are `#[must_use]`.

### Changed (breaking, with migration)

Config and report structs and the enums that may grow are now `#[non_exhaustive]`: struct
literals no longer compile outside `only`. Start from `Default` (or a preset) and assign fields:

```rust
// before
let cfg = Config { idle_timeout: Some(d), ..Config::default() };
// after
let mut cfg = Config::default();
cfg.idle_timeout = Some(d);
```

Affected structs: `only`: `Config`, `UringConfig`, `EbpfConfig`, `PoolConfig`, `PoolStats`,
`SlowCallback`, `UdpStats`, `ConnInfo`, `LoopMeta`, `LoopCounters`, `LoopMetrics`, `Metrics`,
`ReloadReport`, `SlowRecord`; `only-tls`: `TlsInfo`; `only-http`: `HttpConfig`, `H2Config`,
`H2Options`, `WsOptions`, `Request`, `Response`, `FileBody`, `ClientRequest`, `ClientResponse`,
`Cors`, `Compress`, `LogRecord`, `HttpSnapshot`; `only-ws`: `WsConfig`, `DialOptions`, `PmdOffer`,
`PmdParams`, `ProtocolError`; `only-grpc`: `CallOptions`, `Status`, `Metadata`; `only-kcp`:
`KcpConfig`, `Stats`; `only-h3`: `H3Config`; `only-ebpf`: `AttachOptions`, `SteerInfo`, `Probe`;
`only-arpc`: `proto::Message`. Enums (add a wildcard arm to `match`): `only::Error`, `Part`,
`Backend`, `Accel`, `AccelStatus`, `only_http::Method`, `Version`, `BodyMode`, `ClientError`,
`only_ws::client::WsClientError`, `deflate::InflateError`, `only_mux::Rule`,
`only_arpc::CallError`, `proto::Cmd`, `only_quic::Error`, `only_h3::qpack::QpackError`,
`only_kcp::KcpError`, `CloseReason`, `only_ebpf::Steering`, `HashKey`, `Tier`.

Renames and signature changes:

| Crate | Before | After |
|---|---|---|
| `only` | `Listener::serve_dyn(Arc<dyn DynAcceptor>)` (hidden) | `Listener::serve_any(impl Into<AnyAcceptor>)` |
| only-mux | `Mux::into_dyn() -> Arc<dyn DynAcceptor>` | `Mux::into_any() -> AnyAcceptor` (also `From<Mux> for AnyAcceptor`; pass the `Mux` to `serve_any` directly) |
| only-mux | `Mux::route_dyn(rule, Arc<dyn DynAcceptor>)` | `Mux::route_any(rule, impl Into<AnyAcceptor>)` |
| only-mux | `Mux::max_sniff(n)` | `Mux::max_sniff_bytes(n)` |
| only-http | `H2Client::connect(..)` | `H2Client::dial(..)` |
| only-http | `H2Client::connect_blocking(..)` | `H2Client::dial_blocking(..)` |
| only-ws | `client::connect(..)` (blocking) | `client::dial_blocking(..)` |
| only-ws | `INTERNAL_ERROR` | `protocol::close::INTERNAL` |
| only-arpc | `dial(..)` (blocking) | `dial_blocking(..)` |
| only-arpc | `Routes::max_body(n)` | `Routes::max_body_bytes(n)` |
| only-grpc | `GrpcClient::gzip(bool)` | `GrpcClient::compress(bool)` (same name as `GrpcServer::compress`) |
| only-grpc | `GrpcServer::max_message(n)` | `GrpcServer::max_message_bytes(n)` |
| only-h3 | `H3Client::connect(..)` | `H3Client::dial(..)` |
| only-h3 | `server(quic, service)` | `serve(quic, service)` |
| only-h3 | `server_with(quic, service, cfg)` | `serve_with(quic, cfg, service)` (config before service, as in `only_http::serve_with`) |
| only-h3 | `H3Config::max_body`, `max_field_section` | `max_body_bytes`, `max_field_section_bytes` |
| only-h3 | `Result<Response, String>` from `request`, `request_blocking`, `get` | `Result<Response, H3Error>` (`Closed`, `Reset(code)`, `Protocol`, `Timeout`) |
| only-kcp | `Config` | `KcpConfig` |
| only-kcp | `KcpServer::new`, `dial`, `dial_conv`, `Crypt::new` returning `Result<_, String>` | `std::io::Result<_>` (`InvalidInput` for bad settings) |
| only-kcp | `Kcp::stats: [u64; 4]` (public field) | private; use `Session::stats()` |
| only-ebpf | `Relay::new_unchecked(pairs)` | `Relay::new_any_kernel(pairs)` |
| only-ebpf | `Relay::splice_conns(&Arc<ConnInner>, &Arc<ConnInner>)` | `Relay::splice_conns(&Conn<A>, &Conn<B>)` |

Moved out of the covered API (now `#[doc(hidden)]`; backend-facing or test helpers that may change
in any release): `only_core::{LoopLink, Task, Pool, LoopStats, telemetry::Counter,
telemetry::json_str, telemetry::prometheus_header}` and backend-only `Telemetry` methods,
`only::{DynAcceptor, DynHandler}` re-exports, `only_http::transport`, `only_ws::WsSession`,
`only_ebpf::{cbpf, SLOTS, slot_table, expected_index}`.

Versioning: all crates are at `1.0.0-rc.1` and depend on each other with exact (`=`) versions;
`only-sys`, `only-buf`, `only-timer`, `only-pool`, `only-epoll` and `only-uring` are internal
crates without a semver promise of their own (see docs/api-stability.md).

[Unreleased]: https://github.com/lesismal/only/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/lesismal/only/releases/tag/v1.0.0-rc.1
