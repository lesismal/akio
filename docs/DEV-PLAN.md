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
- [ ] `flash-pool`: adaptive thread pool, bounded queue, overload policy, metrics
- [ ] `Conn::spawn_blocking` + callback re-posted to the I/O thread; ordered response slots; semantics of completion callbacks after the connection closed
- [ ] Slow-callback detection (threshold, logs/metrics)
- [ ] `flash-uring`: multishot accept/recv, provided buffer ring, registered files, `SEND_ZC`, `MSG_RING` cross-thread wakeup; kernel feature probing and automatic fallback
- [ ] **Per-listener backend**: several backends in one Engine with independently configured thread groups; config validation and clear errors
- [ ] UDP: one connection per peer, `recvmmsg/sendmmsg`, GRO/GSO; batched `DatagramsHandler` interface
- [ ] `flash-tls`: rustls sans-io driving, handshake on the I/O thread, session tickets, SNI, ALPN; evaluate kTLS
- [ ] Tests: the same echo test matrix on epoll and io_uring; mixed-backend listeners; blocking-offload stress (pool full, connection closed early)
- **Deliverable**: `examples/blocking-offload`, backend comparison benchmark report

### M3 HTTP/1 + WebSocket (6–8 weeks)
- [ ] `flash-http` h1: sans-io parser (pipelining, chunked, trailers, streaming body, Expect: 100), `Context`/`Respond`, `sendfile`
- [ ] Router (static > regexp param > param > catch-all, 405/Allow, Mount/Group); allocation-free routing benchmark
- [ ] Middleware: recover, logger, requestid, responsetime, compress, cors, csrf, etag, limiter
- [ ] Static file cache (pre-compressed `.br/.gz`, inotify-based change tracking)
- [ ] `flash-ws`: RFC 6455 + permessage-deflate, `PreparedMessage` broadcast, Autobahn in CI
- [ ] HTTP/1 async client (callback and future result channels)
- [ ] HTTP/1 comparison report vs hyper and fib (plaintext, pipelined, json)
- **Deliverable**: `examples/http`, `examples/ws-chat`

### M4 HTTP/2 + multi-protocol (8–10 weeks)
- [ ] HTTP/2: frames/streams/flow control, HPACK, h2c (prior knowledge + Upgrade), server push, h2spec in CI; h2 client
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
