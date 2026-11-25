# `akio` architecture

English | [简体中文](architecture.zh-CN.md)

This document describes how `akio` is built: the crates and their dependencies, the threading and
locking model, what happens on a read and a write on each backend, how memory is managed, how
protocols are layered, and how connections and engines end. The decisions behind it are recorded
in the [ADRs](https://github.com/lesismal/akio/tree/main/docs/adr); the user-facing
explanation is in the [book](https://lesismal.github.io/akio/en/).

## 1. Crates

```mermaid
flowchart BT
    sys["akio-sys<br/>unsafe syscalls: epoll/kqueue,<br/>eventfd/pipe, sockets, recvmmsg/sendmmsg"]
    crypto["akio-crypto<br/>SHA-1/2, MD5, HMAC, HKDF, PBKDF2, CRC-32,<br/>AES-CTR/GCM, ChaCha20-Poly1305, base64, RNG,<br/>X25519, Ed25519, X448, Ed448, P-256/P-384/P-521, RSA, DSA verify, DER/PEM"]
    x509["akio-x509<br/>certificates, chain validation, generation"]
    dtls["akio-dtls<br/>sans-io DTLS 1.2, DTLS-SRTP"]
    srtp["akio-srtp<br/>SRTP/SRTCP"]
    rtp["akio-rtp<br/>RTP/RTCP, packetizers,<br/>NACK/RTX, TWCC, BWE"]
    sctp["akio-sctp<br/>SCTP, data channels"]
    ice["akio-ice<br/>ICE agent (full, lite)"]
    buf["akio-buf<br/>size-class pool, SharedBuf"]
    timer["akio-timer<br/>timer wheel"]
    deflate["akio-deflate<br/>DEFLATE, zlib, gzip"]
    brotli["akio-brotli<br/>brotli"]
    zstd["akio-zstd<br/>Zstandard"]
    logc["akio-log<br/>logging facade"]
    regexc["akio-regex<br/>linear-time regex"]
    wasm["akio-wasm (experimental)<br/>WebAssembly for plugins"]
    pool["akio-pool<br/>logical pool"]
    core["akio-core<br/>Conn, ConnInner, Handler, Acceptor,<br/>Transport, Telemetry, Group trait"]
    epoll["akio-epoll<br/>epoll / kqueue groups, UDP groups"]
    uring["akio-uring<br/>io_uring groups"]
    ebpf["akio-ebpf<br/>reuseport steering, sockmap relay"]
    dpdk["akio-dpdk (experimental)<br/>own userspace TCP/IP over DPDK / TAP / AF_PACKET"]
    tun["akio-tun<br/>TUN devices (Linux, macOS utun)"]
    tls["akio-tls<br/>own TLS 1.3/1.2 Transport"]
    facade["akio<br/>Engine, Listener, Backend, Accel"]
    http["akio-http<br/>h1, h2, Router, middleware,<br/>files, clients, observe"]
    ws[akio-ws]
    grpc[akio-grpc]
    arpc[akio-arpc]
    socks[akio-socks]
    mux[akio-mux]
    quic["akio-quic<br/>QUIC v1, sans-io"]
    h3[akio-h3]
    kcp[akio-kcp]
    turn["akio-turn<br/>STUN, TURN"]
    webrtc["akio-webrtc<br/>SDP, peers, RtcServer, Endpoint"]
    media["akio-media<br/>hub, RTMP, RTSP, SRT,<br/>HTTP-FLV, HLS, WHIP"]

    buf --> core
    pool --> core
    logc --> core
    regexc --> logc
    regexc --> http
    core --> epoll
    sys --> epoll
    timer --> epoll
    core --> uring
    sys --> uring
    timer --> uring
    core --> ebpf
    core --> dpdk
    sys --> ebpf
    core --> tls
    epoll --> facade
    uring --> facade
    ebpf --> facade
    dpdk -.->|feature dpdk| facade
    core --> tun
    sys --> tun
    tun -.->|feature tun| facade
    wasm -.->|feature wasm| facade
    tls --> facade
    facade --> ws
    deflate --> ws
    deflate --> http
    deflate --> grpc
    deflate --> tls
    brotli --> tls
    brotli --> http
    zstd --> tls
    zstd --> http
    facade --> http
    ws --> http
    http --> grpc
    facade --> arpc
    http --> socks
    core --> mux
    facade --> quic
    quic --> h3
    http --> h3
    facade --> kcp
    facade --> turn
    turn --> webrtc
    http --> media
    sys --> crypto
    crypto --> x509
    x509 --> dtls
    crypto --> dtls
    crypto --> srtp
    crypto --> sctp
    crypto --> ice
    turn --> ice
    dtls --> webrtc
    srtp --> webrtc
    rtp --> webrtc
    sctp --> webrtc
    ice --> webrtc
    crypto --> ws
    crypto --> http
    crypto --> kcp
    crypto --> turn
    crypto --> webrtc
    crypto --> media
```

- **Dependency direction is one way**: `sys → buf/timer/pool → core → backends → akio →
  protocols`. Protocol crates depend on `akio-core`'s public traits and the ``akio`` facade,
  never on a specific backend.
- **Cryptography is in-house**: `akio-crypto` (std only; `unsafe` only for the AES-NI / ARMv8
  AES instructions, with a constant-time portable fallback; the random syscall is in `akio-sys`) provides the hashes, MACs, KDFs, CRC-32, constant-time AES-CTR/GCM,
  ChaCha20-Poly1305, base64 and randomness the protocol crates need (KCP crypt, STUN/TURN,
  WebSocket handshakes, SRTP, SRT, RTMP, BitTorrent), plus the public-key algorithms and key
  formats (X25519, Ed25519, X448, Ed448, ECDH/ECDSA P-256/P-384/P-521, RSA PKCS#1/PSS, DSA
  verification, DER/PEM, PKCS#8) that
  `akio-x509` (certificate parsing, chain validation, generation) builds on. TLS 1.2/1.3 runs on
  these two crates in `akio-tls` (wave C), DTLS in `akio-dtls`, and QUIC in `akio-quic` on
  `akio-tls`'s record-free TLS 1.3 core (`akio_tls::quic`) and `akio-crypto` (wave D).
- **WebRTC is in-house** (wave D): `akio-dtls` (`#![forbid(unsafe_code)]`, on
  `akio-crypto` and `akio-x509` only) is a sans-io DTLS 1.2 client/server with DTLS-SRTP
  (`use_srtp`, RFC 5705 exporter) and fingerprint-pinned self-signed certificates, driven like
  `akio-quic` drives its state machine (`handle_datagram` / `poll_transmit` / `poll_event` /
  `poll_timeout` / `handle_timeout`, no threads or clocks), and the other layers are sans-io
  crates of the same shape: `akio-ice` (ICE agent, on `akio-turn`'s STUN codec), `akio-srtp`,
  `akio-rtp` (RTP/RTCP, payload formats, NACK/RTX, TWCC and bandwidth estimation) and
  `akio-sctp` (SCTP and DCEP data channels), all `#![forbid(unsafe_code)]`. `akio-webrtc` adds
  SDP offer/answer and drives a sans-io `Rtc` per peer from the I/O threads and one timer
  thread; it has no third-party dependency.
- **`unsafe` is confined** to `akio-sys` (which also holds the workspace's own OS bindings, `akio_sys::ffi`, in place of the `libc` crate), `akio-uring` (its own io_uring binding, ring and buffer-ring memory), `akio-ebpf` (raw `bpf(2)`), `akio-dpdk` (the DPDK FFI) and `akio-crypto`'s AES-instruction module,
  each block with a `SAFETY:` comment. The other crates are `#![forbid(unsafe_code)]` or contain
  no `unsafe` code.
- **Sans-io protocol cores**: HTTP/1 parsing (own zero-copy incremental head parser and chunked
  decoder), HTTP/2 framing and HPACK (own), WebSocket framing and permessage-deflate (DEFLATE from the own `akio-deflate`), KCP, QPACK
  and HTTP/3 framing are state machines fed bytes by `akio`; so is TLS (own record layer and
  TLS 1.3 / 1.2 handshake machines in `akio-tls`), QUIC (`akio-quic`'s own packets, frames,
  streams, recovery and connection-ID routing endpoint: datagrams in, datagrams out, timers
  passed in) and the WebRTC stack (ADR-005), all behind `akio`'s own types (docs/api-stability.md).
- The facade `akio` re-exports the core API (`Conn`, `Handler`, `Acceptor`, `Config`, ...) and
  composes backend groups into an `Engine`.

## 2. Threading model

```mermaid
flowchart LR
    K(("kernel<br/>SO_REUSEPORT<br/>+ optional BPF"))
    subgraph Engine
      subgraph LA["shared epoll group, 2 threads: listeners A and C"]
        A0["I/O thread 0<br/>poller, conns, timer wheel"]
        A1["I/O thread 1"]
      end
      subgraph LB["Listener B: io_uring, 2 threads"]
        B0["I/O thread 0<br/>ring, buffer ring, conns"]
        B1["I/O thread 1"]
      end
      C0["client I/O thread<br/>(Engine::dial)"]
      P[("logical pool<br/>adaptive, bounded")]
      T[("Telemetry hub")]
    end
    K --> A0
    K --> A1
    K --> B0
    K --> B1
    A0 -- "spawn_blocking work" --> P
    P -- "completion posted back" --> A0
```

- An `Engine` runs its listeners on **groups** of I/O threads (plus optional client groups for
  `dial` and `dial_udp`). A group is a set of I/O threads; each thread runs one event loop that
  owns its connections, its timer wheel (`akio-timer`, millisecond ticks) and its read
  buffer(s) (ADR-001, ADR-004). Groups implement the internal `akio_core::Group` trait.
- **Shared groups** (ADR-130): TCP listeners on epoll/kqueue loops share one group
  (`EngineBuilder::io_threads`, one thread per core by default), and so do io_uring listeners
  with the same ring options, unless they ask for threads of their own (`Listener::threads`,
  `Listener::dedicated`). Each loop keeps a table of the group's listeners (acceptor, accept
  filter, Unix-domain or not, removed or not), polls their sockets under tokens naming listener
  and socket (io_uring: one multishot accept per socket, its `user_data` naming both), and each
  connection remembers its listener. Rounds-scheduled listeners share workers and pollers per
  `RoundsConfig` (each listener's sockets are accept jobs carrying its acceptor). UDP,
  datagram, DPDK and BPF-steered listeners have groups of their own.
- **Accept distribution**: on Linux every thread binds its own `SO_REUSEPORT` socket and the
  kernel (or a steering program from `akio-ebpf`) picks the thread; on macOS the threads share
  one listening socket and race to accept.
- **A connection never migrates.** Its handler is created on its thread and only touched there,
  which is why `Handler: Send` but not `Sync` (ADR-003).
- **The logical pool** (`akio-pool`) is engine-wide, adaptive (threads start on demand up to a
  maximum and retire when idle) and bounded (a full queue rejects with `Overloaded`).
  `Conn::spawn_blocking` runs work there and posts the completion back to the owning loop as a
  type-erased task (`LoopLink::post_task`); the loop runs it with `&mut` access to the handler,
  or drops it if the connection is gone. `Conn::run_on_loop` posts such a task directly, with
  no pool job: the way for other threads (the HTTP clients, deadline sweepers) to reach a
  handler, which works however full the pool is.
- **Cross-thread commands** reach a loop through its command queue (a `Mutex<Vec<Cmd>>`) plus a
  waker (eventfd on Linux, a pipe on macOS): `Wake(id)` (flush a queue), `Close(id)`,
  `Task(id, completion)`, `Dial`, `DialUdp`, `Shutdown`, and telemetry requests (connection
  table snapshots, live-setting reloads). A pending-wake flag coalesces wake-ups.

## 3. The connection and its lock (ADR-002)

```text
Conn<H>  (Clone + Send + Sync, PhantomData<fn() -> H>)
   └── Arc<ConnInner>
         ├── id                     process-unique; also guards against fd reuse
         ├── socket                 TcpStream, or a peer on a shared UdpSocket
         ├── state: AtomicU8        OPEN → CLOSING → CLOSED
         ├── read-held / backpressure flags (atomics)
         ├── link: Arc<dyn LoopLink>    wake_conn / close_conn / post_task / pool / stats
         ├── Mutex<WriteState>      send queue, queued bytes, cork, close_after_send,
         │                          on_drain callback, Transport (TLS), datagram flag
         └── Mutex<Ordered>         reserved response slots (ResponseSlot / ResponseStream)
```

- **The write lock guards only the send state** and is never held while user code runs; user
  callbacks run on the loop without it. This rules out lock-ordering deadlocks between
  connections and handlers. The send / close / cork protocols are model-checked with `loom`
  (`RUSTFLAGS="--cfg loom" cargo test -p akio-core --lib --release -- loom`).
- **The fd is released** when the connection is closed *and* the last `Arc<ConnInner>` is
  dropped, so a stale handle can never write to a recycled descriptor; operations on a closed
  connection return `Error::Closed`.
- `Conn<H>` is generic only so that `spawn_blocking` completions are typed
  `FnOnce(&mut H, &Conn<H>, R)`; the `PhantomData<fn() -> H>` keeps it `Send + Sync` for any `H`.

## 4. Data flow

### 4.1 Read, epoll / kqueue

```mermaid
sequenceDiagram
    participant K as Kernel
    participant L as I/O loop (epoll/kqueue)
    participant H as Handler
    participant C as ConnInner
    K->>L: readable (level-triggered)
    loop up to 16 reads while the socket has data
        L->>K: read(fd, scratch)
        L->>C: cork
        L->>H: on_data(conn, scratch[..n])
        H->>C: send (queued while corked)
        L->>C: uncork and flush (one writev)
        Note over L: stop on a short read, hold_reads,<br/>close, or queue at the high watermark
    end
    L->>L: refresh interest (read paused if backpressured, write armed if queued)
```

- One scratch buffer per thread (`Config::read_buffer`, 64 KiB): idle connections hold no read
  buffer, and `on_data` borrows the scratch for the duration of the call.
- Reading stops early when the handler paused reads, closed the connection, or let its queue
  reach the high watermark: backpressure takes effect within the same event.
- EOF from the peer turns into `close_after_send`: what is owed is written, then the connection
  closes and `on_close(None)` runs.

### 4.2 Read, io_uring

- Each thread owns a ring (cooperative task-run, deferred task-run and single-issuer where the
  kernel allows it) and a **provided-buffer ring** of 1024 buffers of `min(read_buffer, 16 KiB)`
  bytes.
- Each listening socket has one **multishot accept** in flight; each connection has one
  **multishot recv** selecting buffers from the ring, so idle connections hold no buffer.
- A completion carries the buffer id: `on_data` borrows that buffer, and when the callback
  returns the buffer goes back to the ring with a memory write (no syscall, no new submission).
  A first version re-submitted `PROVIDE_BUFFERS` per chunk and reached only ~60% of epoll; the
  buffer ring removed that gap.
- `hold_reads` and backpressure cancel the multishot recv and re-arm it on resume.
- Wake-ups from other threads arrive as an eventfd read completion.

### 4.3 Write, all backends

```mermaid
flowchart TD
    S["send(data)"] --> T{"transport?"}
    T -- TLS --> E["seal into records<br/>under the write lock"]
    T -- none --> Q
    E --> Q{"queue empty<br/>and not corked?"}
    Q -- yes --> W["write directly to the socket<br/>from the calling thread"]
    W --> P{"all written?"}
    P -- yes --> D["done"]
    P -- no --> A
    Q -- no --> A["append to the queue<br/>size-class buffer, owned, shared or file chunk"]
    A --> X{"queue was empty and<br/>not corked?"}
    X -- yes --> WK["wake the owning loop"]
    X -- no --> D
    WK --> F["loop flushes with writev / sendfile,<br/>keeps write interest (epoll/kqueue)<br/>or poll POLLOUT (io_uring) while a backlog remains"]
```

- The write path is shared by all backends and lives in `ConnInner`: `send` from any thread
  tries a direct `write`; only the remainder is queued, and the owning loop flushes it when the
  socket becomes writable (epoll/kqueue write interest; on io_uring a one-shot
  `poll(POLLOUT)`).
- Inside callbacks the connection is corked, so everything sent leaves in one `writev` when the
  callback returns.
- Chunks are owned bytes (from `akio-buf` size classes, appended to when there is room),
  `SharedBuf` broadcasts, file ranges (`sendfile(2)`, never copied, not counted against
  `max_queued_bytes`), or segmented UDP buffers.
- Limits: reads pause at `write_high_watermark` and resume at a quarter of it;
  `max_queued_bytes` makes `send` fail with `Overloaded`. `on_drain` callbacks fire when the
  queue empties.

### 4.4 UDP

- UDP listeners always use the readiness backend. On Linux each thread has its own
  `SO_REUSEPORT` socket (a peer hashes to one thread); elsewhere one thread serves the listener.
- Each new peer address becomes a `ConnInner` over the shared socket, with the normal `Handler`;
  a per-listener peer table, idle eviction (`udp_idle_timeout`) and an optional cap
  (`udp_max_peers`).
- Receives use `recvmmsg` (with GRO by default where the kernel supports it, split back into
  datagrams by the `UDP_GRO` segment size). Each connection a receive batch reached gets one
  internal `on_batch_end` after its last datagram (akio-quic acknowledges and sends there). Replies
  produced while handling a receive batch are collected per socket and sent with `sendmmsg` across
  peers;
  equal-size runs to one peer become one GSO message (`UDP_SEGMENT`, probed once, disabled for
  good on `EIO`/`EINVAL`).
- Receive slots are pooled slabs (`akio_buf::slab`, ADR-024): a handler that asks for owned
  datagrams (the hidden `Handler::OWNED_DATA`, akio-quic) gets each one as a writable range cut off
  the slab it arrived in (`on_data_owned`) and may keep it; akio-quic decrypts it there, so a
  1-RTT datagram is not copied between the kernel and the application. Other handlers read in
  place. Peer tables hash addresses with the keyed folded multiply of `akio_core::hash`.
- `dial_udp` creates a `connect`ed socket per dialed connection, so ICMP errors are reported to
  it (`ConnectionRefused` closes it).
- QUIC and KCP sit on top of this: their acceptors receive datagrams through `on_data`, run their
  own sans-io state machines and send through `Conn::send` / `send_segments`; a shared timer
  thread per crate drives retransmission and pacing deadlines.

## 5. Memory and buffers

| Buffer | Owner | Size |
|---|---|---|
| epoll/kqueue read scratch | one per I/O thread | `read_buffer` (64 KiB) |
| io_uring provided buffers | one ring per I/O thread | 1024 × `min(read_buffer, 16 KiB)` |
| send queue chunks | per connection, only while something is queued | `akio-buf` size classes: 512 B, 4, 16, 64, 256 KiB |
| broadcast frames | shared (`SharedBuf` = `Arc<[u8]>`) | encoded once |
| protocol buffers (HTTP head, WebSocket frames, HTTP/2 frames) | per connection state machine | grow with the message, bounded by protocol limits |

- `akio-buf` keeps a small **thread-local** cache of `Vec<u8>` per size class, so taking and
  returning a queue buffer takes no lock. Buffers freed on another thread join that thread's
  (bounded) cache.
- Received data is borrowed, never copied by `akio` before your callback. Keeping it requires an
  explicit copy, which keeps every backend zero-copy on the read side (ADR-004).
- Memory per connection is bounded by `max_queued_bytes` for queues and by protocol limits
  (`max_header_bytes`, `max_body_bytes`, `max_message_bytes`, HTTP/2 windows) for parsers.

## 6. Protocol layering

```mermaid
flowchart TB
    subgraph TCP["TCP connection on an I/O thread"]
      sock[socket] --> tr["Transport (optional): TLS (akio-tls)"]
      tr --> hb["HandlerBox: decode, then on_data"]
      hb --> sess["akio-http Session (a Handler)"]
      sess -- "preface, h2c upgrade, ALPN h2" --> h2["H2Session: streams"]
      sess -- "Upgrade: websocket" --> ws["WsSession, then WsHandler"]
      sess -- "upgrade_raw" --> raw["RawHandler: CONNECT tunnel"]
      sess --> svc["Service, Router, middleware: Context"]
      h2 --> svc
    end
    subgraph UDP["UDP listener"]
      udp["UDP peers"] --> quic["akio-quic Endpoint, then QuicHandler"]
      quic --> h3["akio-h3 ServerConn"]
      h3 -- "transport::dispatch_conn + ConnSink" --> svc2["the same Service: Context"]
      udp --> kcp["akio-kcp sessions, then KcpHandler"]
    end
```

- **`Transport` (TLS).** `Acceptor::transport()` returns an optional `akio_core::Transport`
  installed under the connection before `on_open`. Bytes read are passed through
  `Transport::recv` (producing plaintext and possibly handshake bytes to send) before the
  handler sees them; everything sent goes through `Transport::seal` under the write lock, in
  wire order. Application bytes sent during the handshake are held back by the transport and
  emitted when it completes. `close_after_send` appends `Transport::shutdown` output
  (`close_notify`). `akio-tls`'s `Tls<A>` is an acceptor wrapper that supplies its own TLS
  transport (record layer plus TLS 1.3 / 1.2 state machines, sans-io), so any acceptor (HTTP, arpc, raw handlers) gains TLS without knowing about it.
- **HTTP versions share `Context`.** The `akio-http` `Session` handler parses HTTP/1 and switches
  to an `H2Session` on the client preface, an `h2c` upgrade or ALPN `h2`. Both build a `Context`
  whose responder is either an ordered `ResponseSlot` (HTTP/1, so pipelined responses stay in
  order even when detached) or an HTTP/2 stream.
- **Transport hook for HTTP/3.** `akio_http::transport` lets a transport outside the crate serve
  a `Service`: it parses a request and calls `dispatch_conn(service, request, sink, tag)`, where
  the sink is the connection's `ConnSink` (`send`, `start_stream` returning a `BodySink`, each
  given the request's tag), shared through a thin `SharedSink`; targets are built with
  `request_target` and headers with `request_headers`, which reuse a finished request's
  storage kept per thread (ADR-025, ADR-081). akio-h3 implements those on QUIC streams, so routers, middleware, `detach`
  and `stream_response` behave the same on HTTP/3. The older per-request `ResponseSink`
  (`dispatch`, `start`) is deprecated.
- **Upgrades.** `Context::upgrade_websocket` answers 101 and replaces the HTTP state machine with
  a `WsSession` on the same connection; `Context::upgrade_raw` hands the raw byte stream to a
  `RawHandler` (the HTTP CONNECT proxy). The WebSocket session keeps the type-erased
  `ConnInner`, so `WsSender` outlives the HTTP handler type.
- **Multiplexing.** `akio-mux` is a type-erased acceptor (`DynAcceptor`) that buffers the first
  bytes, picks a route, then creates the chosen acceptor's handler and replays the bytes to it;
  `spawn_blocking` completions and `on_shutdown` are forwarded to the chosen acceptor.

## 7. Lifecycle and shutdown

```mermaid
sequenceDiagram
    participant U as caller
    participant E as Engine
    participant G as each I/O loop
    participant A as Acceptor
    U->>E: shutdown()
    E->>G: Cmd::Shutdown (every group)
    G->>G: stop accepting (deregister the listener)
    G->>A: on_shutdown(conn) for each open connection
    G->>G: connections still dialing: on_error(ConnectionAborted)
    loop at most every 50 ms until empty or the deadline
        G->>G: run events, flush, close finished connections
    end
    G->>G: deadline (shutdown_timeout): finalize the rest (on_close runs)
    G-->>E: thread exits
    U->>E: wait() joins the threads, then stops the logical pool
```

- `build` binds every listener (so bind errors surface early) but starts nothing; `start`
  spawns the loops; `run` = `start` + `wait`.
- Connection close is a three-state machine on an atomic (`OPEN → CLOSING → CLOSED`):
  `close_after_send` moves to CLOSING and the loop finalizes once the queue is empty; `close`,
  errors, EOF after the drain, the idle timeout and panics finalize directly. `on_close` runs
  exactly once on the owning thread; pending completions for the connection are dropped.
- One listener can go while the engine runs (ADR-099): `remove_listener` posts
  `StopListening` to its loops, which close their listening sockets and keep their connections
  until they close, then exit; `shutdown_listener` also runs `on_shutdown` on them and closes
  the rest at its drain deadline. `add_listener` binds and starts a new group as `build` would,
  or adds the listener to its shared group. Removing a listener of a shared group closes only
  its sockets and drains only its connections; the threads stay for the others until
  `shutdown`. `wait` joins those groups too, and returns only after `shutdown`.
- The pool is stopped only after the I/O threads exit, because completions need a loop to run
  on.

## 8. Error handling

- **Connection operations** return `akio_core::Result<T>` with `Error::Closed` (the operation had
  no effect), `Error::Overloaded` (a bound was hit; the caller decides) or `Error::Io` (an OS
  error; the connection is being closed). A failing write from a non-loop thread schedules the
  close on the owning loop and returns `Closed`.
- **Panics** in handler callbacks are caught on the I/O thread (`catch_unwind`): the connection is
  closed with an error and the thread keeps serving others. Panics in pool jobs are caught by the
  pool, counted, and the completion is skipped.
- **Transport errors** (bad TLS records, failed handshakes) flush the transport's alert, close the
  connection and are counted separately (handshake vs. later).
- **Build-time errors** are `io::Error`: bind failures, missing acceptors, unsupported strict
  combinations (`ErrorKind::Unsupported`).
- **Degradation over failure** for optional accelerations: io_uring falls back to epoll and BPF
  steering to kernel hashing unless `strict`, and the fallback is logged and reported
  (`Engine::accel_status`).
- **Nothing is lost silently**: when no `log` backend is installed, errors and slow-callback
  warnings go to stderr.

## 9. Observability plumbing

Each loop owns a cache-line aligned `LoopStats` (relaxed atomic counters) registered with the
engine's `Telemetry` hub together with a way to post it commands. Metrics snapshots sum the
counters on demand; the connection table is gathered by asking each loop for a snapshot (with a
timeout); slow callbacks are timed around every callback while a threshold is set and kept in a
ring of 256 records. Live settings (`Live`) are atomics read on each use, which is what makes
`Engine::reload` free on the hot path. akio-http's `observe` module renders all of this as
Prometheus text and JSON debug views.

## 10. How the architecture is tested

- `loom` models of the send / close / cork protocols (5 models, run in CI).
- The engine, offload and stress suites run on epoll and on io_uring (`AKIO_TEST_BACKEND=uring`).
- 5,000 simultaneous connections and connect/close cycles with fd-leak checks.
- Interop: h2spec, Autobahn (server and client), grpc-go, quic-go, kcp-go, fib.
- eBPF programs tested privileged (eBPF tier, relay) and unprivileged (classic BPF, fallback).
