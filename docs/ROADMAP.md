# `only` Roadmap

English | [简体中文](ROADMAP.zh-CN.md)

> Status: **approved** (2026-11-13). All open questions resolved: eBPF = acceleration/steering layer (+ optional AF_XDP); every other proposal in section 7 accepted. Items marked `⚠ TBC` below are now decided as written.
>
> Original note: Items marked `⚠ TBC` are places where I changed the original design or where the intent is ambiguous and needs your decision. They are collected in the "Open questions" list at the end.

`only` is the Rust counterpart of [fib](../../fib) (Go): the same feature surface, implemented the Rust way (ownership, `Send/Sync` boundaries, zero-cost abstractions, feature flags, sans-io protocol layers).

## 1. Goals and non-goals

**Goals**
1. Cover the protocols and features of fib (see the parity matrix in section 3), delivered in prioritized phases.
2. Multiple I/O backends: epoll, io_uring, eBPF, DPDK. **Each listener can choose its backend independently.**
3. A `Connection` handle usable across threads (locked; `Send + Sync + Clone`): any thread may `send`/`close`/....
4. A logical thread pool: callbacks are **non-blocking and run directly on the I/O thread** by default; blocking work is dispatched to the logical pool explicitly by the user, and its completion callback returns to the connection's owning I/O thread.
5. Performance: on the same machine, no worse than fib, and in the same class as or better than tokio+hyper, monoio and glommio.

**Non-goals (at least before 1.0)**
- No async/await runtime (`only` is not a tokio replacement). A `Future` adapter may come after 1.0.
- No Windows (IOCP) support. Linux is the first-class platform; macOS gets a kqueue backend for development and testing.
- No rewriting of mature sans-io crypto/protocol implementations (see 2.6).

## 2. Core design (key differences from fib)

### 2.1 Threading model: thread-per-core, a connection belongs to one I/O thread
- Each I/O thread owns a reactor, its own connection table, buffer pool and timer wheel. `SO_REUSEPORT` (optionally an eBPF program) spreads new connections across threads.
- Unlike fib, where each read round may land on any idle worker (no affinity), `only` runs callbacks **directly on the I/O thread**, so a connection necessarily belongs to one thread. Per-connection handler state then needs no `Sync` and no lock.
- Cost: a heavy callback delays the other connections on the same thread. That is exactly why the logical pool exists (see 2.3). The docs must state the "callbacks must not block" contract, and `only` provides slow-callback detection (configurable threshold; logs/metrics on overrun).

### 2.2 Connection: a handle with an internal lock
```text
Conn  (Clone + Send + Sync)  ──►  Arc<ConnInner>
                                    ├─ id / generation (guards against fd reuse)
                                    ├─ owner: LoopHandle (wake channel of the owning I/O thread)
                                    ├─ Mutex<WriteState> (send queue, cork, watermark, close state)
                                    └─ atomic state bits (open / closing / read-paused)
```
- **On the I/O thread**: `send` writes directly first (`write`/`writev` when the queue is empty); what does not fit is queued and EPOLLOUT is armed / a uring SQE submitted.
- **On other threads**: lock and enqueue, then wake the owning loop through an eventfd / uring `MSG_RING` to flush. The lock protects only the send queue, and **user callbacks are never invoked while it is held** (no lock-inversion deadlocks).
- Calling a handle after the connection is closed returns `Err(Closed)`: no UB, no panic.
- fib-equivalent capabilities: `cork`, `send_owned/send_shared`, `send_file` (sendfile), `splice_to`, `close_after_send`, `hold_reads`, `attachment`, `notify_output(limit, cb)` for backpressure notification.

### 2.3 Logical thread pool
```rust
// Default: the callback runs inline on the I/O thread and never blocks
fn on_data(&mut self, c: &Conn, data: &[u8]) { c.send(b"pong"); }

// Blocking work (DB / files / remote calls): dispatch explicitly; the result returns to the owning I/O thread
fn on_data(&mut self, c: &Conn, data: &[u8]) {
    let req = parse(data);
    c.spawn_blocking(move || db.query(req), |c, st, result| {   // callback is back on the I/O thread
        c.send(encode(result));
    });
}
```
- The completion callback runs on the **connection's owning I/O thread**, so the connection state `st` stays lock-free. If the connection closed in the meantime, the callback is skipped (or run with `Err(Closed)`, configurable).
- Bounded queue plus overload policy (reject / drop / backpressure via `hold_reads`); the pool scales adaptively (like fib's adaptive taskpool).
- For protocols that need in-order replies (HTTP/1.1 pipelining, arpc, ...) there are **ordered response slots**, so asynchronous completions cannot reorder replies.
- `⚠ TBC`: also provide an async bridge such as `Conn::spawn(async_fut)`? (Suggested: after 1.0.)

### 2.4 Backend abstraction and per-listener backend choice
```rust
Engine::builder()
    .listen(Listener::tcp("0.0.0.0:8080").backend(Backend::IoUring).handler(http))
    .listen(Listener::tcp("0.0.0.0:9000").backend(Backend::Epoll).handler(rpc))
    .listen(Listener::udp("0.0.0.0:443").backend(Backend::Dpdk(cfg)).handler(h3))
    .build()?.run()
```
- Internally a `Reactor` trait (accept / read / write / timer / wake / close) is implemented by each backend; protocol layers depend only on `Conn` and `Handler` and never see the backend.
- When several backends coexist in one Engine, **each backend has its own group of I/O threads** (thread count configurable per listener, default one per core). The logical pool, timers and buffer pool can be shared engine-wide.
- One ownership convention: `on_data(&[u8])` is a borrow that is invalid once the callback returns (epoll borrows the loop's buffer, io_uring a provided-buffer-ring entry, DPDK an mbuf). To keep the data, copy it or use `data.to_owned_buf()`.

### 2.5 Role of each backend
| Backend | Role | Notes |
| --- | --- | --- |
| epoll | Baseline, default | Edge-triggered; `accept4`, `writev`, `sendfile`, `splice`, `recvmmsg/sendmmsg`, UDP GRO/GSO |
| kqueue | macOS/BSD development and regression | Shares most reactor logic with epoll; not tuned for peak performance |
| io_uring | High-performance Linux backend | multishot accept/recv, provided buffer ring, registered files/buffers, `SEND_ZC`, optional SQPOLL, `MSG_RING` cross-thread wakeups; kernel feature probing with automatic fallback to epoll |
| eBPF | `⚠ TBC`, see below | Not a standalone I/O backend but an **acceleration/steering layer**: `SO_REUSEPORT` BPF thread selection (by CPU / consistent hash), in-kernel forwarding via sockmap/`sk_msg` (proxy/relay), optional XDP filtering/rate limiting |
| DPDK | Kernel bypass, peak performance | Needs a userspace TCP/IP stack (evaluate smoltcp / f-stack bindings); UDP and basic TCP first, then extend; takes over the NIC and hugepages, so deployment is demanding: last phase |

> **On the eBPF ambiguity**: an eBPF program does not do userspace send/receive itself, so listing it next to epoll/io_uring/DPDK as an "Engine" needs a definition first. My suggestion is the "acceleration/steering layer + optional AF_XDP data path" in the table above: `Backend::Epoll + Accel::Ebpf(..)`, with AF_XDP as a lighter kernel-bypass option besides DPDK. Please confirm this matches your intent.

### 2.6 Other design decisions
- **sans-io protocol layers**: HTTP/1, HTTP/2, WebSocket, QUIC, KCP, ... are written as pure state machines driven by `only`'s Handler. This makes them easy to fuzz, to unit-test without an Engine, and to reuse across backends.
- **Buffers**: a size-class buffer pool (thread-local cache plus global recycling) and `Bytes`-like reference-counted shared buffers for broadcast (like fib's `PreparedMessage`/`SendShared`).
- **Backpressure**: per-connection write watermark pauses reads, engine-wide `max_pending_bytes`, `hold_reads`.
- **Graceful shutdown**: `Engine::shutdown()` notifies handlers and waits for connections to drain.
- **Dependency policy**: fib has zero dependencies; in Rust the policy is "few and well chosen": `libc`, `io-uring` (or a thin in-house wrapper), `aya` (eBPF), and mature sans-io crates such as `rustls`/`quinn-proto` behind features, with the core crates close to dependency-free. `⚠ TBC`
- **unsafe governance**: `unsafe` lives only in `only-sys`, the backends and the buffer pool, with SAFETY comments; core concurrent structures are verified with `loom`, protocol parsers with `cargo-fuzz`, and the pure-Rust parts run under `miri`.

## 3. Parity matrix with fib

Priority: P0 = required for 1.0; P1 = strongly recommended for 1.0; P2 = after 1.0.

| Capability | fib | `only` priority | Milestone | Notes |
| --- | --- | --- | --- | --- |
| TCP / Unix sockets, async dial | ✓ | P0 | M1 | sendfile / splice / writev / cork / half close |
| UDP (one connection per peer, batched I/O) | ✓ | P0 | M2 | recvmmsg/sendmmsg, GRO/GSO |
| TLS 1.2/1.3 | ✓ (in-house) | P0 | M2 | rustls sans-io; kTLS optional |
| HTTP/1.x (pipelining, chunked, sendfile) | ✓ | P0 | M3 | in-house or reuse; SIMD parsing ideas from httparse |
| Router / middleware / static file cache | ✓ | P0 | M3 | chi-style, allocation-free routing |
| WebSocket (RFC 6455 + permessage-deflate) | ✓ | P0 | M3 | Autobahn suite in CI |
| HTTP/2 (h2/h2c, server push) | ✓ | P0 | M4 | h2spec in CI; HPACK reused or in-house |
| mux (several protocols on one port) | ✓ | P0 | M4 | |
| arpc | ✓ | P1 | M4 | wire-compatible with lesismal/arpc |
| gRPC | ✓ | P1 | M4 | works with the prost/tonic ecosystem (pluggable codec) |
| SOCKS4/4a/5, HTTP CONNECT proxy | ✓ | P1 | M4 | accelerated with splice / sockmap |
| HTTP/3 + QUIC | ✓ (in-house) | P1 | M5 | sans-io core from quinn-proto or quiche |
| KCP | ✓ | P1 | M5 | compatible with skywind3000/kcp, kcp-go (incl. FEC/crypt) |
| Async clients (h1/h2/h3/ws) | ✓ | P1 | M4–M5 | callback and future result channels |
| Prefork (multi-process SO_REUSEPORT) | ✓ | P2 | M6 | little gain without a GC; demoted to optional |
| Streaming media (RTMP/RTSP/SRT/FLV/HLS/WHIP/WHEP) | ✓ | P2 | M7 | large; separate crates |
| WebRTC (ICE/DTLS-SRTP/DataChannel/TURN) | ✓ | P2 | M7 | evaluate sans-io implementations such as str0m |
| BitTorrent (incl. DHT/uTP/MSE) | ✓ | P2 | M7 | separate crate, last |
| eBPF acceleration | — | P1 | M5 | see 2.5 |
| DPDK backend | — | P2 | M6 | see 2.5 |

## 4. Milestones

> Estimates assume one lead developer and are for ordering and risk awareness only, **not commitments**. AI assistance can shorten coding time a lot, but benchmark tuning and protocol conformance testing will not shrink proportionally.

| Milestone | Version | Theme | Definition of done | Estimate |
| --- | --- | --- | --- | --- |
| **M0** | — | Kick-off and skeleton | workspace, CI (fmt/clippy/test/miri/loom), design docs (ADRs) settled, echo benchmark scaffold | 1–2 weeks |
| **M1** | 0.1 | Core engine (epoll + kqueue) | TCP echo works; cross-thread `Conn` send/close; buffer pool, timers; stable at 10k+ connections; same class as fib echo | 4–6 weeks |
| **M2** | 0.2 | Multi-backend + logical pool + UDP + TLS | io_uring backend; **per-listener backend**; logical pool `spawn_blocking`+callback; UDP; rustls integration; io_uring measurably ahead of epoll | 6–8 weeks |
| **M3** | 0.3 | HTTP/1 + WebSocket | Router/middleware/static files; Autobahn all green; HTTP/1 benchmark report vs hyper and fib | 6–8 weeks |
| **M4** | 0.4 | HTTP/2 + multi-protocol | h2spec all green; mux; arpc; gRPC; SOCKS/CONNECT; async clients | 8–10 weeks |
| **M5** | 0.5 | QUIC/H3 + KCP + eBPF | HTTP/3 interop (curl/quiche); KCP interop with kcp-go; eBPF REUSEPORT steering + sockmap relay | 8–10 weeks |
| **M6** | 0.6 | DPDK + production readiness | DPDK basic UDP/TCP path; metrics/logging/pprof equivalents; soak and chaos tests | 6–8 weeks |
| **M7** | 0.7+ | Heavy protocols | media, WebRTC, BitTorrent (separate crates; parallel/community-driven) | open |
| **1.0** | 1.0 | Stabilization | API freeze, semver promise, security review (fuzz coverage, `cargo-audit`, unsafe review), docs and examples complete | — |

## 5. Quality and performance assurance
- **Correctness**: Autobahn (WS), h2spec (H2), and interop tests against curl / nghttp2 / quiche / kcp-go in CI.
- **Concurrency**: `loom` covers the Conn send queue and close state machine; stress tests cover cross-thread `send` racing `close`.
- **Fuzzing**: at least one `cargo-fuzz` target per sans-io parser.
- **Performance gates**: fixed baselines (`only`'s own history, fib, hyper/tokio, monoio), run nightly in CI, alert on regressions beyond a threshold. Scenarios: echo, HTTP/1 plaintext, pipelined, HTTP/2 multiplexed, WS echo, TLS, memory with 100k idle connections.
- **Platform matrix**: Linux x86_64/aarch64 (io_uring with tiered kernel-feature probing, ≥5.19 for the full set), macOS arm64 (kqueue).

## 6. Main risks
| Risk | Impact | Mitigation |
| --- | --- | --- |
| Scope too large (fib is huge) | 1.0 never ships | P0/P1/P2 tiers; heavy protocols in separate crates that do not block 1.0 |
| Callbacks run on the I/O thread and users write blocking code | every connection on the thread stalls | slow-callback detection + docs + an API where blocking work must go through an explicit `spawn_blocking` |
| Cross-thread `Conn` lock causes deadlocks / latency jitter | stability | never call back while locked, loom tests, lock scope limited to the send queue |
| io_uring kernel fragmentation, DPDK deployment cost | compatibility | feature probing + automatic fallback; DPDK late and marked experimental |
| eBPF needs privileges / recent kernels | limited deployment | optional feature; falls back to the default SO_REUSEPORT hash |
| Security risk of in-house TLS/QUIC | security | no in-house cryptography; reuse mature sans-io libraries (rustls, quinn-proto, ...) |

## 7. Open questions
1. **What eBPF means**: adopt the "acceleration/steering layer (REUSEPORT thread selection, sockmap forwarding, optional AF_XDP)", or did you mean something else?
2. **Reuse mature crates for TLS/QUIC/HPACK, ...** (rustls, quinn-proto, ...) instead of writing everything in-house as fib does? I recommend reuse, for security and schedule.
3. **Threading model**: agree to "a connection belongs to one I/O thread (thread-per-core)" and drop fib's "any worker per round" no-affinity model?
4. **Platforms**: Linux first-class plus macOS (kqueue) as a development backend, no Windows. OK?
5. Should the **async bridge** (`Future` adapter) wait until after 1.0?
6. Are the **P2 heavy protocols** (media / WebRTC / BitTorrent) and Prefork acceptable after 1.0 as separate crates?
7. **License and MSRV**: keep fib's LICENSE? MSRV policy (suggested: edition 2024, follow stable-2).
