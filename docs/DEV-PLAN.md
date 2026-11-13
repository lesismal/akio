# flash Development Plan

English | [简体中文](DEV-PLAN.zh-CN.md)

> Status: **approved** (2026-11-13), together with the ROADMAP.
>
> Original note: Companion document: [ROADMAP.md](ROADMAP.md) (what, why, when). This document covers **how**: repository layout, public API sketch, per-milestone task breakdown, testing and collaboration rules.

## 1. Repository layout (Cargo workspace)

```text
flash/
├─ Cargo.toml                  # workspace
├─ crates/
│  ├─ flash-sys/               # unsafe syscall wrappers: epoll/kqueue/io_uring/eventfd/sendfile/splice…
│  ├─ flash-buf/               # size-class buffer pool, shared read-only buffers (Bytes-style)
│  ├─ flash-timer/             # hierarchical timer wheel
│  ├─ flash-pool/              # logical thread pool (adaptive, bounded queue, overload policy)
│  ├─ flash-core/              # Engine / Listener / Conn / Handler / Reactor trait
│  ├─ flash-epoll/             # epoll (+kqueue) reactor
│  ├─ flash-uring/             # io_uring reactor
│  ├─ flash-ebpf/              # eBPF acceleration layer (aya), feature-gated
│  ├─ flash-dpdk/              # DPDK reactor + userspace stack, feature-gated
│  ├─ flash-tls/               # rustls sans-io integration (+ optional kTLS)
│  ├─ flash-http/              # HTTP/1.x, HTTP/2, Router, Context, static files
│  ├─ flash-ws/                # WebSocket
│  ├─ flash-mux/               # several protocols on one port, by sniffing
│  ├─ flash-middleware/        # compress/cors/csrf/etag/limiter/logger/recover/requestid…
│  ├─ flash-arpc/  flash-grpc/  flash-socks/  flash-kcp/  flash-quic/  flash-h3/
│  ├─ flash-media/ flash-webrtc/ flash-bittorrent/   # M7, separate crates
│  └─ flash/                   # facade crate: re-exports + feature flags
├─ examples/                   # echo, http, ws, proxy, blocking-offload …
├─ benches/                    # cross-implementation benchmark suite (incl. scripts against fib)
├─ fuzz/                       # cargo-fuzz targets
├─ tests/                      # integration / interop / chaos tests
└─ docs/                       # ROADMAP, DEV-PLAN, adr/ (architecture decision records)
```

Dependency direction (one way): `sys → buf/timer/pool → core → {epoll,uring,ebpf,dpdk}`; `core → tls → http/ws/…`. Protocol crates depend only on the public traits of `flash-core`, never on a specific backend.

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
- [x] `flash-sys`: epoll, eventfd, `accept4`, `writev`, `sendfile`, `splice`, `SO_REUSEPORT`, non-blocking socket options
- [x] `flash-buf`: size-class pool, thread-local cache, ref-counted `SharedBuf`
- [x] `flash-timer`: timer wheel (connection read/write/idle timeouts, user timers)
- [x] `flash-core`: `Engine/Listener/Reactor/Handler/Conn`; per-I/O-thread event loop; accept distribution; command queue + eventfd wakeup
- [x] Cross-thread `Conn` path: send queue, direct-write-first, loop wakeup, close state machine, generation guard
- [x] Backpressure: write watermark, `hold_reads`, `max_pending_bytes`; graceful shutdown
- [x] Async dial (client connections)
- [x] kqueue reactor (shared logic; develop/debug on macOS)
- [x] Tests: unit, `loom` (cork/send/close races, 5 models, run in CI), 5,000 simultaneous connections + 20×500 connect/close cycles with fd-leak check (macOS and Linux)
- [x] Idle timeout wired into the loop (`Config::idle_timeout`, timer wheel per I/O thread)
- [ ] Not done, carried to later milestones: 100k-connection run, read/write timeouts, echo comparison against fib/tokio/monoio on dedicated Linux hardware
- **Deliverable**: `examples/echo`, echo benchmark report v0

> M1 status: **closed except the items above.** Verified on Linux (epoll) and macOS (kqueue): 12 engine tests, 2 stress tests, 5 loom models (a deliberately broken `mark_closed` makes the loom model fail, so it does explore the race). `echo-bench` now multiplexes connections over a few client threads; on one macOS machine flash and a 4-thread tokio echo both land at ~105–115k req/s, i.e. the client is still the bottleneck, so this run says "same class" but cannot rank them. The fib comparison needs fib to have a plain TCP echo (it has none yet) and a two-machine Linux setup; it moves to the benchmark report in M2. `Conn::spawn_blocking` is M2.

### M2 Multi-backend + logical pool + UDP + TLS (6–8 weeks)
- [x] `flash-pool`: adaptive thread pool (grows on demand to a max, idle threads retire), bounded queue, overload = `Error::Overloaded`, stats
- [x] `Conn::spawn_blocking` + callback re-posted to the I/O thread (skipped if the connection closed or `work` panicked); ordered response slots (`reserve_response`; an unfilled dropped slot closes the connection)
- [x] Slow-callback detection (`Config::slow_callback_threshold`, default 100 ms; `slow_hook` or stderr). Metrics export is still open
- [x] `flash-uring`: multishot accept and recv, provided-buffer ring, cooperative/deferred task-run + single-issuer rings, eventfd wake-up, kernel probe (5.19+) with automatic fallback to epoll (`UringConfig::strict` to refuse). Writes use the shared direct-`write`/queue path with a `poll(POLLOUT)` for the backlog
- [ ] `flash-uring`: not used yet (only worth it if measurements ask for them): registered files, `SEND_ZC`, `MSG_RING` wake-up, ring-based sends
- [x] **Per-listener backend**: several backends in one Engine with independently configured thread groups (tested: epoll + io_uring listeners in one engine); unsupported combinations return clear errors
- [x] UDP (server side): `Listener::udp`; one `Conn` per peer address with the normal `Handler` (`on_data` per datagram, `send` = one datagram, any thread), idle eviction (`Config::udp_idle_timeout`), graceful shutdown that does not wait for a drain, `spawn_blocking` and `close_after_send` work; `SO_REUSEPORT` sockets per thread on Linux (a peer stays on one thread), single thread elsewhere; `recvmmsg` batching on Linux. Tested on macOS and Linux
- [x] UDP client: `Engine::dial_udp` (+ `EngineBuilder::udp_client_threads`, or the threads of a UDP listener): every dialed connection has its own `connect`ed socket, so its own local port; `on_open` runs at once, `on_data` per datagram, idle timeout, `close()`; an ICMP "port unreachable" ends it with `ConnectionRefused`. Tested against a flash UDP server (30 concurrent dials = 30 distinct peers), closed port, silent server, cross-thread send
- [ ] UDP not done: `sendmmsg`, GRO/GSO, a connectionless batched `DatagramsHandler`, io_uring-backed UDP (an io_uring listener request is served by epoll), a cap on the number of peers, batched receive for dialed sockets (one `recv` per datagram)
- [x] `flash-tls`: rustls driven sans-io through a `Transport` layer under `Conn` (server and client, `Tls::server` / `Tls::client` wrap any acceptor; handlers see plaintext), handshake on the I/O thread with application bytes held back until it completes, close_notify on `close_after_send`, `tls_info` (ALPN, SNI, version). Session tickets, SNI certificate selection, client auth, versions: through rustls's own configs. Tested on epoll and io_uring: echo (3 MiB), ALPN/SNI, garbage and untrusted-cert clients, `spawn_blocking` + ordered slots over TLS, flash dialing flash
- [ ] kTLS evaluation (not started); TLS 1.3 early data and client-certificate helpers are left to rustls configuration
- [x] Tests: the whole engine/offload/stress suite runs on epoll and on io_uring (`FLASH_TEST_BACKEND=uring`, also in CI on Linux); mixed-backend listeners. Also done: blocking-offload tests (I/O thread not stalled, completion on I/O thread with handler state, pool full, connection closed early, ordering, slot drop, slow callback)
- **Deliverable**: `examples/blocking-offload` (done), backend comparison benchmark report (done: [BENCHMARKS.md](BENCHMARKS.md))

> M2 status: logical pool and io_uring done; all 21 engine/offload/stress tests pass on both backends on Linux (kernel 6.12, Docker), repeated runs without failures. **io_uring vs epoll, same Docker VM, echo, 64 B, client on the same machine:** with 4 server threads / 256 connections both are client-bound (~0.8–1.0M req/s each, no ranking possible); with 1 server thread / 512 connections (server-bound) epoll gave 416k and 492k, io_uring 527k and 538k, i.e. io_uring about 10–25% ahead. The first io_uring implementation, which re-submitted a `PROVIDE_BUFFERS` request per received chunk, reached only ~60% of epoll; returning buffers through a buffer ring (a memory write instead of a submission) removed that gap. Numbers come from a VM shared with the client; treat them as direction, not as a benchmark report. **M2 is complete.** Benchmark report: [BENCHMARKS.md](BENCHMARKS.md). In short: TCP echo in the same class as fib and tokio (ahead of fib everywhere measured, behind tokio by ~15% at 64 connections and 16 KiB, ahead at 512), io_uring not faster than epoll in that setup, the logical pool recovers ~58× over blocking inline.

### M3 HTTP/1 + WebSocket (6–8 weeks)
- [x] `flash-http` h1 server: `httparse` head parsing, own incremental chunked decoder (extensions, trailers, any split), pipelining with in-order responses (ordered slots), keep-alive/`Connection: close`/HTTP/1.0, `Expect: 100-continue`, limits (header size, body size, header count), smuggling guards (CL+TE, duplicate CL), `Context` with `detach()` for responses finished later from any thread, graceful shutdown that lets in-flight responses finish. Tested on epoll and io_uring
- [x] Streaming: request bodies via `Streaming(svc)` + `ctx.on_body` (chunks, trailers, no size limit), response bodies via `ctx.stream_response` (chunked / close-delimited, ordered behind earlier pipelined responses); `sendfile(2)` for file bodies (read through memory over TLS); core support: `ResponseStream`, `Part::File`
- [ ] h1 not done: HTTP/1 over TLS tests (the `Tls` wrapper composes, untested here), percent-decoding of route parameters (`percent_decode` is provided)
- [x] Router: static > `:param` > `*wildcard`, backtracking, 405 with `Allow`, HEAD from GET, `nest`, per-router layers, custom fallback; duplicate/conflicting routes panic at registration
- [ ] Router not done: regexp parameters, allocation-free routing (it allocates a `Vec` and `String`s per request) and its benchmark
- [x] Middleware: recover, request id, CORS (preflight), access logger
- [x] Middleware: response time, compress (gzip/deflate), etag + 304, csrf (double-submit cookie), per-IP token-bucket limiter. Brotli is not offered (no brotli dependency yet)
- [x] Static files (`files::Files`): path safety, MIME, ETag/Last-Modified/304, single ranges, index files, pre-compressed `.br`/`.gz` twins, in-memory cache with a stat interval, `sendfile` for big files. inotify-based change tracking is not done (stat interval instead)
- [x] `flash-ws`: RFC 6455 + permessage-deflate (context takeover, server window bits), `PreparedMessage` broadcast, subprotocols, origin check, close handshake; Autobahn|Testsuite: 298 OK + 3 informational (core), 216/216 OK (permessage-deflate), run in CI by `tools/autobahn/run.sh`. A miniz_oxide deflate bug found by Autobahn (flate2 now uses zlib-rs)
- [x] HTTP/1 async client (`client::Client`): callbacks, `ResponseFuture` (`wait`, `wait_timeout`, `.await`), keep-alive reuse per host with one retry when a reused connection turns out dead, chunked/close-delimited bodies, HTTPS via `flash::tls`, address fallback (::1 then 127.0.0.1). Not done: redirects, per-request timeout, DNS off the calling thread
- [ ] HTTP/1 comparison report vs hyper and fib (plaintext, pipelined, json): moves to the unified benchmark pass after the feature phase
- **Deliverable**: `examples/http`, `examples/ws-chat`

> M3 status: **feature-complete except the comparison report** (moved to the benchmark pass): h1 server with streaming and sendfile, router, 9 middlewares, static files, flash-ws with Autobahn at 100% (core 298+3 informational, permessage-deflate 216/216), h1 client. Examples: `crates/flash-http/examples/{hello,ws-chat,ws-echo}.rs`.

### M4 HTTP/2 + multi-protocol (8–10 weeks)
- [x] HTTP/2 (`flash-http`, same `Service`/`Context` as HTTP/1): frames, streams, flow control both ways, HPACK (`loona-hpack`), h2c by prior knowledge and `Upgrade`, TLS ALPN `h2`, server push (`ctx.push`), streamed bodies both ways, GOAWAY graceful shutdown; h2spec strict 147/147 (CI job `h2spec`); curl interop (prior knowledge, upgrade, POST); `h2client::H2Client` (multiplexing, flow control, push, TLS). Found on the way: rustls refuses >64 KiB of plaintext per write, `flash-tls` now seals in record-sized pieces
- [ ] `flash-mux`: first-bytes sniffing (HTTP/TLS/SOCKS/custom)
- [ ] `flash-arpc`: wire-compatible, two-way calls, notify, stream, broadcast, reconnect
- [ ] `flash-grpc`: unary + streaming, metadata, deadline, interceptor, gzip; pluggable codec (prost)
- [ ] `flash-socks` + HTTP CONNECT proxy: callback-to-callback relay, two-way backpressure; splice path on Linux
- [ ] Tests: interop with curl/nghttp2/grpc-go/tonic
- **Deliverable**: `examples/grpc`, `examples/proxy`

### M5 QUIC/H3 + KCP + eBPF (8–10 weeks)
- [ ] `flash-quic`/`flash-h3`: on a sans-io QUIC core (quinn-proto/quiche, decided after evaluation), QPACK, WebSocket over H3; interop with curl/quiche
- [ ] `flash-kcp`: compatible with skywind3000/kcp and kcp-go (crypt, XOR, FEC), flush on demand
- [ ] `flash-ebpf`: load REUSEPORT selection programs via aya (CPU affinity / consistent hash), sockmap/`sk_msg` relay, optional XDP rate limiting; degrade without privileges or kernel support
- [ ] Tests: eBPF programs run in both a CI container (privileged) and a local VM
- **Deliverable**: `examples/h3`, `examples/kcp`, eBPF acceleration benchmark

### M6 DPDK + production readiness (6–8 weeks)
- [ ] `flash-dpdk`: EAL init, mbuf rx/tx, userspace TCP/IP stack selection and integration (UDP first, then TCP), integration with Engine thread groups
- [ ] Production: metrics (Prometheus-style), structured logs, runtime debug/pprof equivalents (connection table, queue depth, slow callbacks), config hot reload
- [ ] Chaos tests: random disconnects, half close, slow clients, pool saturation, fd exhaustion
- [ ] Prefork (optional)
- **Deliverable**: soak report (≥72h)

### M7 Heavy protocols (open-ended)
- [ ] Streaming media (RTMP/RTSP/SRT/FLV/HLS/WHIP/WHEP + hub)
- [ ] WebRTC (ICE/DTLS-SRTP/DataChannel/TURN)
- [ ] BitTorrent (metainfo/tracker/peer wire/uTP/DHT/MSE)
- Each is a separate crate with its own README and tests; advance in parallel as time and community allow.

### 1.0 Stabilization
- [ ] API review and freeze, semver policy, deprecation process
- [ ] Full fuzz corpora and coverage report, `cargo-audit/deny`, unsafe review checklist
- [ ] Docs site + migration guides (from fib / tokio / hyper) + architecture document

## 4. Engineering rules
- **Branches/commits**: `main` stays releasable; feature branches + PRs; Conventional Commits.
- **Code**: `#![forbid(unsafe_code)]` by default; unsafe allowed only in `flash-sys`, the backends and `flash-buf`, each with a `// SAFETY:` comment.
- **Test pyramid**: unit → loom/miri → integration/interop → chaos → benchmark; new features need tests and protocol parsers need fuzz targets.
- **ADRs**: any decision affecting the public API, threading/lock model or dependencies is first written as `docs/adr/NNN-*.md`.
- **Docs**: every crate has crate-level docs and runnable doctests; READMEs stay bilingual (as in fib), `X.md` in English and `X.zh-CN.md` in Chinese.
- **Performance**: a PR touching hot paths attaches before/after benchmarks; nightly benchmarks compare against historical baselines.

## 5. Suggested order after approval
1. M0: settle ADR-001 to 004 and the `Handler`/`Conn` API prototype first (the foundation for everything else and the costliest to change).
2. M1: get epoll TCP echo and cross-thread `Conn::send` working, and bring in loom and benchmarks early.
3. M2: start with the logical pool (it directly shapes the `Handler` state type), then io_uring.
4. The rest follows the milestone order; M7 may run in parallel.
