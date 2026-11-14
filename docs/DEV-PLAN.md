# `only` Development Plan

English | [简体中文](DEV-PLAN.zh-CN.md)

> Status: **approved** (2026-11-13), together with the ROADMAP.
>
> Original note: Companion document: [ROADMAP.md](ROADMAP.md) (what, why, when). This document covers **how**: repository layout, public API sketch, per-milestone task breakdown, testing and collaboration rules.

## 1. Repository layout (Cargo workspace)

```text
only/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ only-sys/               # unsafe syscall wrappers: epoll/kqueue/io_uring/eventfd/sendfile/splice…
│  ├─ only-buf/               # size-class buffer pool, shared read-only buffers (Bytes-style)
│  ├─ only-timer/             # hierarchical timer wheel
│  ├─ only-pool/              # logical thread pool (adaptive, bounded queue, overload policy)
│  ├─ only-core/              # Engine / Listener / Conn / Handler / Reactor trait
│  ├─ only-epoll/             # epoll (+kqueue) reactor
│  ├─ only-uring/             # io_uring reactor
│  ├─ only-ebpf/              # eBPF acceleration layer (aya), feature-gated
│  ├─ only-dpdk/              # DPDK reactor + userspace stack, feature-gated
│  ├─ only-tls/               # rustls sans-io integration (+ optional kTLS)
│  ├─ only-http/              # HTTP/1.x, HTTP/2, Router, Context, static files
│  ├─ only-ws/                # WebSocket
│  ├─ only-mux/               # several protocols on one port, by sniffing
│  ├─ only-middleware/        # compress/cors/csrf/etag/limiter/logger/recover/requestid…
│  ├─ only-arpc/  only-grpc/  only-socks/  only-kcp/  only-quic/  only-h3/
│  ├─ only-media/ only-webrtc/ only-bittorrent/   # M7, separate crates
│  └─ only/                   # facade crate: re-exports + feature flags
├─ examples/                   # echo, http, ws, proxy, blocking-offload …
├─ benches/                    # cross-implementation benchmark suite (incl. scripts against fib)
├─ fuzz/                       # cargo-fuzz targets
├─ tests/                      # integration / interop / chaos tests
└─ docs/                       # ROADMAP, DEV-PLAN, adr/ (architecture decision records)
```

Dependency direction (one way): `sys → buf/timer/pool → core → {epoll,uring,ebpf,dpdk}`; `core → tls → http/ws/…`. Protocol crates depend only on the public traits of `only-core`, never on a specific backend.

## 2. Public API sketch (settled in the M0 ADRs)

```rust
pub trait Handler: Send + 'static {
    type Conn: Send + 'static;                       // per-connection state, touched only on the owning I/O thread, no Sync needed
    fn on_open(&self, c: &Conn) -> Self::Conn;
    fn on_data(&self, c: &Conn, st: &mut Self::Conn, data: &[u8]);   // non-blocking, inline on the I/O thread
    fn on_close(&self, c: &Conn, st: Self::Conn, err: Option<Error>);
    fn on_hangup(&self, _c: &Conn, _st: &mut Self::Conn) {}          // optional
    fn on_shutdown(&self, _c: &Conn) {}                              // optional
}

#[derive(Clone)] pub struct Conn(Arc<ConnInner>);                    // Send + Sync
impl Conn {
    pub fn send(&self, data: &[u8]) -> Result<()>;
    pub fn send_owned(&self, data: Vec<u8>) -> Result<()>;
    pub fn send_shared(&self, data: SharedBuf) -> Result<()>;
    pub fn send_file(&self, f: &File, off: u64, len: u64) -> Result<()>;
    pub fn cork(&self); pub fn flush(&self) -> Result<()>;
    pub fn close(&self); pub fn close_after_send(&self);
    pub fn hold_reads(&self, hold: bool);
    pub fn notify_output(&self, limit: usize, cb: impl FnOnce(Result<()>) + Send + 'static);
    pub fn spawn_blocking<R: Send + 'static>(
        &self,
        work: impl FnOnce() -> R + Send + 'static,
        done: impl FnOnce(&Conn, &mut H::Conn, R) + Send + 'static,   // returns to the owning I/O thread
    ) -> Result<()>;
    pub fn local_addr(&self) -> SocketAddr; pub fn peer_addr(&self) -> SocketAddr;
}

pub enum Backend { Epoll, IoUring(UringConfig), Dpdk(DpdkConfig) /* Kqueue on macOS only */ }
pub enum Accel   { None, Ebpf(EbpfConfig) }
```
> This is only a sketch: how `Handler::Conn` and the `spawn_blocking` callback obtain `&mut Self::Conn` (generics vs. `dyn Any`) will be decided in M0 by prototyping, picking the form that is friendliest to users and adds no `Sync` bound.

## 3. Milestone task breakdown

Each task is marked `[ ]`, with the deliverable in parentheses. Each milestone must pass its **DoD (ROADMAP section 4) + a benchmark report + a CHANGELOG entry**.

### M0 Kick-off and skeleton (1–2 weeks)
- [x] workspace + `rust-toolchain.toml` + `rustfmt/clippy` config + LICENSE
- [x] CI: Linux x86_64/aarch64 + macOS; `fmt / clippy -D warnings / test / miri (pure-Rust crates) / loom`
- [x] ADR-001 threading model; ADR-002 Conn lock model and lifecycle; ADR-003 Handler and per-connection state type; ADR-004 backend abstraction `Reactor` trait; ADR-005 dependency policy; ADR-006 role of eBPF
- [x] Prototype 2–3 `Handler` API shapes and choose one
- [x] Benchmark scaffold: echo load tool + reference implementations (fib, tokio, monoio)

### M1 Core engine: epoll + kqueue (4–6 weeks)
- [x] `only-sys`: epoll, eventfd, `accept4`, `writev`, `sendfile`, `splice`, `SO_REUSEPORT`, non-blocking socket options
- [x] `only-buf`: size-class pool, thread-local cache, ref-counted `SharedBuf`
- [x] `only-timer`: timer wheel (connection read/write/idle timeouts, user timers)
- [x] `only-core`: `Engine/Listener/Reactor/Handler/Conn`; per-I/O-thread event loop; accept distribution; command queue + eventfd wakeup
- [x] Cross-thread `Conn` path: send queue, direct-write-first, loop wakeup, close state machine, generation guard
- [x] Backpressure: write watermark, `hold_reads`, `max_pending_bytes`; graceful shutdown
- [x] Async dial (client connections)
- [x] kqueue reactor (shared logic; develop/debug on macOS)
- [x] Tests: unit, `loom` (cork/send/close races, 5 models, run in CI), 5,000 simultaneous connections + 20×500 connect/close cycles with fd-leak check (macOS and Linux)
- [x] Idle timeout wired into the loop (`Config::idle_timeout`, timer wheel per I/O thread)
- [x] M1 leftovers done in the benchmark pass: 100k-connection run (100k idle connections in ~55 MB), `Config::write_timeout` (no-progress output closes with `TimedOut`; `idle_timeout` serves as the read timeout), echo comparison against fib/tokio (`docs/BENCHMARKS.md`). Not done: monoio comparison, dedicated (non-shared) Linux hardware
- **Deliverable**: `examples/echo`, echo benchmark report v0

> M1 status: **closed except the items above.** Verified on Linux (epoll) and macOS (kqueue): 12 engine tests, 2 stress tests, 5 loom models (a deliberately broken `mark_closed` makes the loom model fail, so it does explore the race). `echo-bench` now multiplexes connections over a few client threads; on one macOS machine `only` and a 4-thread tokio echo both land at ~105–115k req/s, i.e. the client is still the bottleneck, so this run says "same class" but cannot rank them. The fib comparison needs fib to have a plain TCP echo (it has none yet) and a two-machine Linux setup; it moves to the benchmark report in M2. `Conn::spawn_blocking` is M2.

### M2 Multi-backend + logical pool + UDP + TLS (6–8 weeks)
- [x] `only-pool`: adaptive thread pool (grows on demand to a max, idle threads retire), bounded queue, overload = `Error::Overloaded`, stats
- [x] `Conn::spawn_blocking` + callback re-posted to the I/O thread (skipped if the connection closed or `work` panicked); ordered response slots (`reserve_response`; an unfilled dropped slot closes the connection)
- [x] Slow-callback detection (`Config::slow_callback_threshold`, default 100 ms; `slow_hook` or stderr). Metrics export is still open
- [x] `only-uring`: multishot accept and recv, provided-buffer ring, cooperative/deferred task-run + single-issuer rings, eventfd wake-up, kernel probe (5.19+) with automatic fallback to epoll (`UringConfig::strict` to refuse). Writes use the shared direct-`write`/queue path with a `poll(POLLOUT)` for the backlog
- [ ] `only-uring`: not used yet (only worth it if measurements ask for them): registered files, `SEND_ZC`, `MSG_RING` wake-up, ring-based sends
- [x] **Per-listener backend**: several backends in one Engine with independently configured thread groups (tested: epoll + io_uring listeners in one engine); unsupported combinations return clear errors
- [x] UDP (server side): `Listener::udp`; one `Conn` per peer address with the normal `Handler` (`on_data` per datagram, `send` = one datagram, any thread), idle eviction (`Config::udp_idle_timeout`), graceful shutdown that does not wait for a drain, `spawn_blocking` and `close_after_send` work; `SO_REUSEPORT` sockets per thread on Linux (a peer stays on one thread), single thread elsewhere; `recvmmsg` batching on Linux. Tested on macOS and Linux
- [x] UDP client: `Engine::dial_udp` (+ `EngineBuilder::udp_client_threads`, or the threads of a UDP listener): every dialed connection has its own `connect`ed socket, so its own local port; `on_open` runs at once, `on_data` per datagram, idle timeout, `close()`; an ICMP "port unreachable" ends it with `ConnectionRefused`. Tested against a `only` UDP server (30 concurrent dials = 30 distinct peers), closed port, silent server, cross-thread send
- [x] UDP batching (Linux): `recvmmsg` for server and dialed sockets; the replies of one receive batch leave across peers with `sendmmsg`, equal-size runs to one peer as UDP GSO (probed at runtime, off for good on EIO/EINVAL, `ONLY_UDP_GSO=0`); `Conn::send_segments`, used by only-quic (up to 10 datagrams per transmit); opt-in GRO (`Config::udp_gro`); `Config::udp_max_peers` with drop counting (`Engine::udp_stats`). Burst sends cost 30–46% less server CPU per datagram, 64 B echo about +19%. Not done: connectionless `DatagramsHandler`; io_uring UDP judged not worth it (recvmmsg/sendmmsg already batch); measurements on a real NIC
- [x] `only-tls`: rustls driven sans-io through a `Transport` layer under `Conn` (server and client, `Tls::server` / `Tls::client` wrap any acceptor; handlers see plaintext), handshake on the I/O thread with application bytes held back until it completes, close_notify on `close_after_send`, `tls_info` (ALPN, SNI, version). Session tickets, SNI certificate selection, client auth, versions: through rustls's own configs. Tested on epoll and io_uring: echo (3 MiB), ALPN/SNI, garbage and untrusted-cert clients, `spawn_blocking` + ordered slots over TLS, `only` dialing `only`
- [ ] kTLS evaluation (not started); TLS 1.3 early data and client-certificate helpers are left to rustls configuration
- [x] Tests: the whole engine/offload/stress suite runs on epoll and on io_uring (`ONLY_TEST_BACKEND=uring`, also in CI on Linux); mixed-backend listeners. Also done: blocking-offload tests (I/O thread not stalled, completion on I/O thread with handler state, pool full, connection closed early, ordering, slot drop, slow callback)
- **Deliverable**: `examples/blocking-offload` (done), backend comparison benchmark report (done: [BENCHMARKS.md](BENCHMARKS.md))

> M2 status: logical pool and io_uring done; all 21 engine/offload/stress tests pass on both backends on Linux (kernel 6.12, Docker), repeated runs without failures. **io_uring vs epoll, same Docker VM, echo, 64 B, client on the same machine:** with 4 server threads / 256 connections both are client-bound (~0.8–1.0M req/s each, no ranking possible); with 1 server thread / 512 connections (server-bound) epoll gave 416k and 492k, io_uring 527k and 538k, i.e. io_uring about 10–25% ahead. The first io_uring implementation, which re-submitted a `PROVIDE_BUFFERS` request per received chunk, reached only ~60% of epoll; returning buffers through a buffer ring (a memory write instead of a submission) removed that gap. Numbers come from a VM shared with the client; treat them as direction, not as a benchmark report. **M2 is complete.** Benchmark report: [BENCHMARKS.md](BENCHMARKS.md). In short: TCP echo in the same class as fib and tokio (ahead of fib everywhere measured, behind tokio by ~15% at 64 connections and 16 KiB, ahead at 512), io_uring not faster than epoll in that setup, the logical pool recovers ~58× over blocking inline.

### M3 HTTP/1 + WebSocket (6–8 weeks)
- [x] `only-http` h1 server: `httparse` head parsing, own incremental chunked decoder (extensions, trailers, any split), pipelining with in-order responses (ordered slots), keep-alive/`Connection: close`/HTTP/1.0, `Expect: 100-continue`, limits (header size, body size, header count), smuggling guards (CL+TE, duplicate CL), `Context` with `detach()` for responses finished later from any thread, graceful shutdown that lets in-flight responses finish. Tested on epoll and io_uring
- [x] Streaming: request bodies via `Streaming(svc)` + `ctx.on_body` (chunks, trailers, no size limit), response bodies via `ctx.stream_response` (chunked / close-delimited, ordered behind earlier pipelined responses); `sendfile(2)` for file bodies (read through memory over TLS); core support: `ResponseStream`, `Part::File`
- [x] h1 follow-ups: HTTP/1 over TLS tests (`tests/tls.rs`: keep-alive, pipelining, large and chunked bodies, static files, WebSocket upgrade); route parameters percent-decoded once at dispatch (`Context::param`), raw text through `param_raw`. Static files: `If-Match`/`If-Unmodified-Since` (412), date-aware `If-Modified-Since`, `If-Range`, cached open handle and metadata for large files (`max_open_files`). Not done: multi-range responses, eviction in the open-file cache
- [x] Router: static > `:param` > `*wildcard`, backtracking, 405 with `Allow`, HEAD from GET, `nest`, per-router layers, custom fallback; duplicate/conflicting routes panic at registration
- [x] Router follow-ups: allocation-free lookup (parameter positions inline, names shared from the tree), `Router::lookup`/`RouteMatch`; `examples/router-bench.rs` with 52 GitHub-style routes: ~30 ns and 0 allocations per lookup vs ~130 ns and 4.4 before. Regexp parameters `{id:[0-9]+}` (default `regex` feature), `{id}`/`{*rest}` aliases; precedence static > regexp > param > wildcard, with backtracking. Not done: partial-segment patterns (`/{name}.txt`)
- [x] Middleware: recover, request id, CORS (preflight), access logger
- [x] Middleware: response time, compress (gzip/deflate), etag + 304, csrf (double-submit cookie), per-IP token-bucket limiter. Brotli is not offered (no brotli dependency yet)
- [x] Static files (`files::Files`): path safety, MIME, ETag/Last-Modified/304, single ranges, index files, pre-compressed `.br`/`.gz` twins, in-memory cache with a stat interval, `sendfile` for big files. inotify-based change tracking is not done (stat interval instead)
- [x] `only-ws`: RFC 6455 + permessage-deflate (context takeover, server window bits), `PreparedMessage` broadcast, subprotocols, origin check, close handshake; Autobahn|Testsuite: 298 OK + 3 informational (core), 216/216 OK (permessage-deflate), run in CI by `tools/autobahn/run.sh`. A miniz_oxide deflate bug found by Autobahn (flate2 now uses zlib-rs)
- [x] WebSocket client (`only_ws::client::dial`/`connect`): `ws://`/`wss://` via `only::tls` (SNI, custom rustls config), address fallback, handshake checks (key/accept, subprotocol, origin, extra headers), handshake/close timeouts, permessage-deflate offer honouring the server's choices, masked frames, RFC close handshake, fragmented sends. Autobahn client suite (`tools/autobahn/run.sh client`): 514 OK + 3 informational of 517, no-context-takeover pass 216/216; interop with fib's Go websocket server. Not done: system roots, proxies, redirects, close 1001 on engine shutdown
- [x] HTTP/1 async client (`client::Client`): callbacks, `ResponseFuture` (`wait`, `wait_timeout`, `.await`), keep-alive reuse per host with one retry when a reused connection turns out dead, chunked/close-delimited bodies, HTTPS via `only::tls`, address fallback (::1 then 127.0.0.1). Not done: redirects, per-request timeout, DNS off the calling thread
- [x] Unified benchmark report (`docs/BENCHMARKS.md`, `tools/bench`: Docker image, wrk/h2load/echo-bench, memory at 10k/100k connections, perf profiles, A/B against another revision; new hyper-ref, extended tokio-ref/fib-ref): HTTP/1.1 plaintext/pipelined/JSON, h2c, TCP/UDP/TLS/WebSocket echo vs hyper, tokio, tokio-tungstenite and fib. Optimizations: own HPACK Huffman decoder (h2c 0.29M → 1.87M req/s, ×6.4), HTTP/1.1 hot path (plaintext +4–9%, pipelined +17%), per-connection memory (keep-alive 1.6 → 0.9 KB, WebSocket 2.1 → 1.7 KB). Still behind fib on pipelined HTTP/1.1 (~0.8×) and h2c; numbers from a shared, noisy host
- **Deliverable**: `examples/http`, `examples/ws-chat`

> M3 status: **feature-complete except the comparison report** (moved to the benchmark pass): h1 server with streaming and sendfile, router, 9 middlewares, static files, only-ws with Autobahn at 100% (core 298+3 informational, permessage-deflate 216/216), h1 client. Examples: `crates/only-http/examples/{hello,ws-chat,ws-echo}.rs`.

### M4 HTTP/2 + multi-protocol (8–10 weeks)
- [x] HTTP/2 (`only-http`, same `Service`/`Context` as HTTP/1): frames, streams, flow control both ways, HPACK (`loona-hpack`), h2c by prior knowledge and `Upgrade`, TLS ALPN `h2`, server push (`ctx.push`), streamed bodies both ways, GOAWAY graceful shutdown; h2spec strict 147/147 (CI job `h2spec`); curl interop (prior knowledge, upgrade, POST); `h2client::H2Client` (multiplexing, flow control, push, TLS). Found on the way: rustls refuses >64 KiB of plaintext per write, `only-tls` now seals in record-sized pieces
- [x] `only-mux`: first-bytes sniffing (TLS, HTTP/1, HTTP/2 preface, SOCKS4/5, prefixes, custom rules, fallback); the chosen acceptor owns the connection as if it had accepted it (replayed bytes, pool completions, graceful shutdown)
- [x] `only-arpc`: lesismal/arpc wire format; two-way calls, notifies, async calls with timeouts, detached answers, streams, broadcast (one shared frame), client reconnect; checked against fib's Go arpc in both directions (`tools/interop/arpc/run.sh`). Not done: middleware/coders chain, client pools
- [x] `only-grpc`: unary, server/client streaming and bidi on only-http's HTTP/2 (server shares the port with plain HTTP), metadata headers + trailers, trailers-only errors, deadlines (`grpc-timeout`), interceptors, gzip both ways, message limits, prost helpers (feature `prost`); client on `H2Client::open` (new streamed-request API). Interop with grpc-go v1.85 in both directions (`tools/interop/grpc/run.sh`)
- [x] `only-socks`: SOCKS5 (no auth / username+password, IPv4/IPv6/domain resolved on the pool), SOCKS4/4a, HTTP `CONNECT` proxy (via `Context::upgrade_raw`); callback-to-callback relay with two-way backpressure (`Conn::on_drain`, new in core; it exposed a lost-wake-up when a queue emptied outside the loop's flush, fixed). Not done: SOCKS BIND / UDP ASSOCIATE, a Linux `splice` path
- [x] Tests: interop with curl (h2 prior knowledge, h2c upgrade), h2spec, grpc-go, fib's Go arpc. Not run: nghttp2 tools, tonic
- **Deliverable**: `examples/grpc`, `examples/proxy` (as `crates/only-grpc/examples/grpc-interop.rs`, `crates/only-socks` tests)

> M4 status: **done.** HTTP/2 (h2spec 147/147), only-mux, only-socks, only-arpc (Go interop), only-grpc (grpc-go interop).

### M5 QUIC/H3 + KCP + eBPF (8–10 weeks)
- [x] `only-quic`/`only-h3`: on a sans-io QUIC core (quinn-proto/quiche, decided after evaluation), QPACK, WebSocket over H3; interop with curl/quiche — quinn-proto 0.11 chosen. `only-quic`: one `quinn_proto::Endpoint` per UDP listener (connection-id routing, so migration works), `QuicServer` acceptor and `dial`, `QuicHandler` callbacks (streams, resets, stop-sending, datagrams, close) run one at a time per connection, non-blocking writes with per-stream queues released on `Writable`, a shared timer thread, rustls (ring) config helpers. `only-h3`: HTTP/3 framing, QPACK with static table + literals (dynamic table capacity 0, Huffman decoding), control/QPACK streams and their error rules, any `only_http::Service` served over H3 through a new `only_http::transport` hook (same `Context`, incl. `detach`, `stream_response`, trailers), body/field-section limits (413/431), `H3Client`. Interop both directions with quic-go v0.62 and fib's own QUIC/HTTP/3 (`tools/interop/h3/run.sh`). Not done: curl/quiche runs (no HTTP/3 build at hand), WebSocket over H3 (extended CONNECT), QPACK dynamic table, server push, streamed request bodies
- [x] `only-kcp`: compatible with skywind3000/kcp and kcp-go (crypt, XOR, FEC), flush on demand — sans-io KCP core (port of fib's), kcp-go Reed–Solomon FEC (klauspost matrix), crypts none/xor/aes/aes-128/aes-192/aes-128-gcm; `KcpServer` acceptor on a UDP listener (per-peer sessions, conversation replacement, `max_sessions`), `dial`, `KcpHandler` callbacks on the I/O thread, one shared timer thread driven by `next_flush`; dead-link close; interop with kcp-go v5 both directions for six crypt/FEC combinations, also through a relay dropping every 7th datagram (`tools/interop/kcp/run.sh`)
- [x] `only-ebpf`: `SO_REUSEPORT` steering by CPU (`cpu % threads`) or deterministic consistent hash (Maglev, 251 slots, by source IP or IP+port); classic BPF works unprivileged for TCP and UDP, eBPF (`SK_REUSEPORT` + sockarray) when privileged. `Accel::Ebpf(EbpfConfig)` degrades instead of failing (or `strict`), `Engine::accel_status()` reports what was attached. Sockmap relay (`SOCKHASH` by socket cookie + `sk_skb` verdict): `Relay::splice`/`splice_conns` relay two TCP conns in-kernel; needs Linux 6.15+ by default because 6.12 loses data on EAGAIN in the psock backlog (reproduced). Programs are hand-assembled and loaded with raw `bpf(2)` (no aya, no nightly; ADR-006). Not done: XDP rate limiting, thread–CPU pinning, only-socks relay wiring, eBPF hash tier, eBPF benchmark
- [x] Tests: eBPF programs run in a privileged Docker container (eBPF tier, relay) and unprivileged (classic BPF, fallback), on epoll and io_uring; `ONLY_TEST_EXPECT_EBPF=1` turns skips into failures. Not done: local VM run
- **Deliverable**: `examples/h3`, `examples/kcp`, eBPF acceleration benchmark

### M6 DPDK + production readiness (6–8 weeks)
- [x] `only-dpdk` (experimental): smoltcp userspace TCP/IP stack on `only` I/O threads; EAL init from `EalConfig`, one thread per rx/tx queue, mbuf rx/tx bursts through a C shim, RSS with ARP fan-out; also TAP, AF_PACKET and an in-memory wire. `Backend::Dpdk(DpdkConfig)` behind features `dpdk`/`dpdk-pmd`; UDP and TCP listeners, `dial`/`dial_udp`; only-kcp runs unchanged. Verified against the Linux kernel stack in Docker (DPDK `net_tap` with 1 and 2 queues, TAP, AF_PACKET on veth); heavy CI job `dpdk`. Not done: IPv6, IP fragmentation and offloads, multi-queue dial, SACK/congestion control, real-NIC benchmarks
- [x] Production: per-I/O-thread relaxed counters (connections, bytes, reads/writes, UDP datagrams, send-queue gauge, backpressure/overload, TLS handshake failures, loop iterations/events/callback time, slow callbacks) plus pool stats, `Engine::metrics()` rendered as Prometheus text or JSON; structured logs through the `log` facade with key-values (stderr fallback, `Config::log_level`); runtime debug: connection table gathered by the loops, slow-callback ring buffer, per-thread loop stats; only-http `metrics_handler`, `HttpMetrics` (status classes, latency histogram), `access_log`, token-guarded `debug_handler`; hot reload via `Engine::reload`/`Live` (idle timeout, slow threshold/hook, queue limit, high watermark, new `max_connections`, shutdown timeout, log level). Not done: `tracing` feature, reload of buffer size/backlog/threads/UDP idle timeout, per-route HTTP labels, overhead measured on a quiet host
- [x] Chaos tests: seeded, reproducible suites for the engine (`only/tests/chaos.rs`), fd exhaustion (`chaos_fd.rs`), TLS (`chaos_tls.rs`) and HTTP/WebSocket (`only-http/tests/chaos.rs`): RST aborts, half close, slow and non-reading clients, pool saturation, EMFILE, shutdown under load; invariants: `on_close` exactly once, no stall, bounded queues, no fd leak. Fast seeds by default, `ONLY_CHAOS=1 ONLY_CHAOS_SECS=300` soaks (clean on macOS, Linux epoll and io_uring). Bugs fixed: EOF cut off pending ordered responses; an over-limit ordered response vanished; epoll spun on EMFILE; io_uring missed an RST after data; io_uring could reuse an fd still named by unsubmitted SQEs
- [x] Prefork (optional): `only-prefork`: a supervisor re-executes the binary as N workers, each with its own `Engine`; listeners shared via SO_REUSEPORT (Linux default) or inherited (macOS default, no refused connections across restarts/reloads); crash restart with backoff, SIGTERM/SIGINT drain, SIGHUP/`Supervisor::reload` generation swap, pdeathsig, CPU pinning; `Listener::tcp_from_std`. Not done: bpffs-shared cross-process eBPF steering; ReusePort reload needs `tcp_migrate_req`
- **Deliverable**: soak report (≥72h)

### M7 Heavy protocols (open-ended)
- [x] Streaming media (`only-media`): one hub (GOP cache, slow-player dropping to keyframes, auth hooks, republish wait, timestamp normalization, stats); RTMP server (digest handshake, Enhanced RTMP H.265/Opus), HTTP-FLV, WS-FLV, HLS (MPEG-TS, LL-HLS parts, blocking reload), RTSP server (TCP/UDP, record/play, Digest auth), SRT live (ARQ, TSBPD, AES, push/pull), WHIP/WHEP signalling; interop with ffmpeg/ffprobe for every protocol; 9 fuzz targets. Not done: fMP4 HLS, encryption, RTMP/RTSP clients, SRT rendezvous, WebRTC media in the hub
- [x] WebRTC (`only-webrtc`, `only-turn`): str0m 0.24 over `only` UDP with a pure-Rust crypto provider; ICE-lite `RtcServer` and full-ICE `Endpoint` (new `Engine::bind_udp`), DTLS-SRTP, SCTP data channels, RTP/RTCP with NACK/PLI/TWCC; STUN codec/server and TURN server (long-term and REST credentials, channels, EVEN-PORT, quotas). Interop with pion (both ways, also via `only` TURN), fib, pion/turn and coturn; 3 fuzz targets. Not done: TURN over TCP/TLS, TURN client for `Endpoint`, ICE-TCP, mDNS
- [x] BitTorrent (`only-bittorrent`): bencode, v1 metainfo and magnets, HTTP/UDP trackers (client and server), peer wire with Fast extension, ut_metadata, PEX and MSE/RC4, uTP with LEDBAT, mainline DHT, client (rarest-first, endgame, choking, storage on the logical pool); new `Engine::dial_udp_from`. Interop 15/15 with libtorrent 2.0.11 and aria2 1.37; 6 fuzz targets. Not done: BEP 52 (v2/hybrid), web seeds, LSD, BEP 44, IPv6 DHT, rate and seed limits
- Each is a separate crate with its own README and tests; advance in parallel as time and community allow.

### 1.0 Stabilization
- [x] API review and freeze, semver policy, deprecation process: public API inventoried and snapshotted (`api/*.txt`, cargo public-api, `public-api` CI gate; `semver-checks` activates once 1.0.0 is published); `Debug` and `#[must_use]` enforced by lints; configs, reports and growing enums `#[non_exhaustive]`; backend plumbing `#[doc(hidden)]`; `AnyAcceptor`/`serve_any`; consistent `dial`/`dial_blocking`, `serve`/`serve_with`, `*_bytes`; typed errors instead of `String` (kcp, h3); migration table in `CHANGELOG.md`; `docs/api-stability.md` (semver tiers, MSRV 1.85, platform tiers), `docs/deprecation.md`; version 1.0.0-rc.1 with publish metadata. Open before 1.0.0: the crates.io name `flash` is taken; pre-1.0 public dependencies (rustls, quinn-proto, prost) (both resolved in "1.0.0 release decisions" below)
- [x] Full fuzz corpora and coverage report, `cargo-audit/deny`, unsafe review checklist. Fuzzing: `fuzz/` cargo-fuzz project with 21 targets (HTTP/1, HTTP/2 + HPACK, WebSocket, arpc, gRPC, SOCKS, mux, KCP, HTTP/3 + QPACK, cBPF), minimized corpora (~2.6 MB) replayed by stable unit tests, ~14 min per target on Linux, nightly CI job; fixed an HTTP/2 deadlock, recursive server push, gRPC `grpc-timeout` panic/overflow, KCP RTT overflow, unbounded SOCKS buffering. Supply chain: `deny.toml` + `.cargo/audit.toml`, `cargo deny`/`cargo audit` clean and gated in CI (one dev-only advisory ignored with a reason until MSRV 1.88). Unsafe: confined to only-sys, only-uring and only-ebpf, every other crate `forbid(unsafe_code)`, missing safety comments are errors, inventory `--check` in CI (`docs/unsafe-review.md`, `SECURITY.md`); 12 issues fixed (incl. a `RecvBatch` heap overflow, io_uring buffer aliasing and freeing buffers with operations in flight, unchecked bpf(2) key/value sizes). Miri extended to the protocol crates; it found UB inside zlib-rs 0.6.8 (to report upstream). Not done: first ASan/TSan run (heavy CI job added)
- [x] CI hardening and coverage: strict lint set (`missing_docs` deny, `unreachable_pub`, `unwrap_used` in library code, curated pedantic/nursery lints), rustdoc `-D warnings`; matrix: Linux x86_64/arm64 × epoll/io_uring, macOS (best effort), MSRV 1.85, cargo-hack feature powerset, Miri, loom, Autobahn (server + client), h2spec, book build + Pages deploy, heavy jobs (Go interop, nightly fuzz); single `ci-ok` gate. Coverage job (cargo-llvm-cov, both backends merged): 85.9% → 91.6% lines, every crate ≥ 85%. Fixed along the way: only-quic panic on wrong-direction streams, 15 callbacks run under a slot lock, `--no-default-features` test build, two test races. Not verified on GitHub itself yet (Pages setting, fib checkout, Codecov)
- [x] Docs site + migration guides + architecture document: mdBook `book/en` + `book/zh-CN` (getting started, concepts, one chapter per protocol, configuration reference, observability and hot reload, performance tuning, troubleshooting), built by `book/build.sh`; every snippet included from 14 runnable `guide-*` examples; migration guides from fib, tokio and hyper/axum; `docs/architecture.md` with Mermaid diagrams; crate rustdocs link to the book; root README. Not done: Pages deployment, running the guide examples on Linux

### 1.0.0 release decisions (2026-11-14)
- [x] Rename the project to **only**: crates `only`, `only-core`, `only-http`, … (the crates.io name `flash` is taken), across code, docs, book, tools and CI: directories and packages `crates/only-*`, `only_*` paths, `ONLY_*` environment variables, `only_*` metrics, `only*` log targets and thread names, `api/only-*.txt` snapshots, Docker images, the books and all docs; the GitHub repository and Pages URLs (`lesismal/flash`) stay until the repository is renamed; CHANGELOG has the mapping
- [x] Wrap the pre-1.0 public dependencies (rustls, quinn-proto, prost, str0m) behind the project's own types, keeping raw access only in an `unstable` feature, so upgrading them is not a breaking change: `tls::{ServerConfig, ClientConfig}` builders (PEM/DER certificates and keys, SNI chains, ALPN, client auth, session cache and tickets, roots, insecure-for-tests) and `tls::Error` used by TLS, HTTP/HTTP-2 clients, WebSocket client, QUIC and HTTP/3; own QUIC `ServerConfig` / `ClientConfig` / `TransportConfig`, `StreamId` / `Dir` / `Side`, `ConnectionError`, `ConnectionStats`; gRPC `codec::Message` trait with the prost adapter behind the `prost` feature (outside semver); own WebRTC ids, media, events, candidates, `RtcConfig` and `SdpChanges`, `Peer::with_rtc` behind `unstable`; snapshots contain no rustls/quinn/prost/str0m type; migration table in CHANGELOG
- Callback names stay domain-specific (`on_connected` for QUIC, `on_open` for WebSocket, …)

### Long term: no third-party dependencies
- [ ] Implement in-house, one by one, every third-party dependency the libraries use (TLS 1.2/1.3 and the crypto primitives instead of rustls/ring/aws-lc, QUIC instead of quinn-proto, HPACK, protobuf runtime instead of prost, the WebRTC stack instead of str0m/dimpl, the userspace TCP/IP stack instead of smoltcp, deflate/zlib, regex, `log`, …), each behind the same public API, with interop and fuzzing as gates; track the list and the order in this section

## 4. Engineering rules
- **Branches/commits**: `main` stays releasable; feature branches + PRs; Conventional Commits.
- **Code**: `#![forbid(unsafe_code)]` by default; unsafe allowed only in `only-sys`, the backends and `only-buf`, each with a `// SAFETY:` comment.
- **Test pyramid**: unit → loom/miri → integration/interop → chaos → benchmark; new features need tests and protocol parsers need fuzz targets.
- **ADRs**: any decision affecting the public API, threading/lock model or dependencies is first written as `docs/adr/NNN-*.md`.
- **Docs**: every crate has crate-level docs and runnable doctests; READMEs stay bilingual (as in fib), `X.md` in English and `X.zh-CN.md` in Chinese.
- **Performance**: a PR touching hot paths attaches before/after benchmarks; nightly benchmarks compare against historical baselines.

## 5. Suggested order after approval
1. M0: settle ADR-001 to 004 and the `Handler`/`Conn` API prototype first (the foundation for everything else and the costliest to change).
2. M1: get epoll TCP echo and cross-thread `Conn::send` working, and bring in loom and benchmarks early.
3. M2: start with the logical pool (it directly shapes the `Handler` state type), then io_uring.
4. The rest follows the milestone order; M7 may run in parallel.
