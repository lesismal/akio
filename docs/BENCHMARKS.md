# Benchmarks

English | [简体中文](BENCHMARKS.zh-CN.md)

One campaign, run on 2026-11-15 on a quiet bare-metal host from a single commit (`10070cff`, after
the in-house replacements and the per-area performance passes: crypto CPU acceleration, deflate,
the QUIC pacer, the TLS record path, h2 and HTTP/1). Every table below comes from that campaign.
The earlier per-area before/after figures are summarised under [History](#history).

## Host and method

- **Host**: AMD Ryzen 7 7800X3D (Zen 4, 8 cores / 16 threads, up to 5.05 GHz, AES-NI, SHA-NI,
  PCLMULQDQ, VAES, AVX-512), 61 GB RAM, Ubuntu 24.04, Linux 7.0.0-42, x86-64, no VM.
- **Toolchains**: Rust 1.100.0 (release profile of the workspace), Go 1.27.4 for fib-ref (fib at
  `42e6de6`), h2load (nghttp2) 1.59.0. Reference crates: tokio 1.54, hyper 1.12 (+ hyper-util
  `auto`), tokio-tungstenite 0.28, tokio-rustls 0.26 / rustls 0.23 with ring.
- **Quiet host**: every measurement ran under `quiet.sh run`, a wrapper that takes a lock against
  other benchmark jobs, stops the host's other services (an inference server, the remote desktop,
  a kind cluster), switches the power profile to `performance` (governor `performance`, boost
  on), runs the whole suite and restores everything afterwards. Load average before the run: 0.1.
- **Pinning**: network servers on CPUs 0–3 with 4 I/O threads (tokio: 4 workers; fib:
  `GOMAXPROCS` follows the 4-CPU affinity); the load generator on CPUs 4–7 and 12–15 with 8
  threads; CPUs 8–11 (the SMT siblings of the server's cores) idle. QUIC runs client and server
  in one process on CPUs 2–5; the in-memory and micro benchmarks run on CPU 2.
- **Rounds**: network figures are the **median of 3 rounds** of 5 s after a 1 s warm-up
  (WebSocket: 5 rounds); a round runs every case against every server in turn, each run against a
  freshly started server. Micro benchmarks: median of 3 runs of the whole program. `±` is half the
  min–max spread of the rounds as a percentage of the median; it is left out where it is ≤3%.
  The echo, WebSocket and memory rows come from a second pass an hour later with the same
  binaries: in the first pass several servers could not bind their port (see Reproducing), and the
  harness was fixed before re-running them.
- **Backends**: `only-epoll` and `only-uring` are the same server with `Backend::Epoll` and
  `Backend::IoUring`. QUIC/HTTP/3 has its own UDP threads (no backend choice), and UDP echo runs
  on the epoll UDP loop for both backends, so those rows have one `only` column.
- **Servers** (the same handlers everywhere): `crates/only/examples/bench-server.rs` (TCP/TLS/UDP
  echo) and `crates/only-http/examples/http-bench.rs` (HTTP/1.1 + h2c + h2 over TLS, `/plaintext`,
  `/json`, WebSocket echo on `/ws`); the references in `tools/bench-ref/` (`tokio-ref`,
  `hyper-ref`, `fib-ref`). TLS is TLS 1.3 with an ECDSA P-256 self-signed certificate everywhere
  (only-tls for `only`, tokio-rustls for tokio, `fib/tls` for fib). JSON: `only` uses a small
  hand-written serializer in the example, hyper serde_json, fib `encoding/json`.
- **Load generators**: `h2load --h1` for HTTP/1.1 (wrk is not installed on the host; pipelining
  is `-m 16`), `h2load` for HTTP/2 (prior knowledge for h2c, ALPN `h2` over TLS), the in-repo
  `tools/echo-bench` for echo (closed loop), TLS handshakes (rustls client) and memory (the
  connection holder).

### Limits

- **Loopback only**: client and server share one machine, its memory bandwidth and the kernel's
  loopback path; there is no NIC, no real latency, no packet loss. **DPDK is not measured**: the
  host has no NIC that DPDK could drive, so `only-dpdk` appears only through its userspace TCP/IP
  stack over the in-process memory wire.
- **h2load ceiling**: with 8 threads h2load tops out around 4–5 M requests/s. The h2c and h2-over-
  TLS rows of `only` sit at that level (the server kept its 4 CPUs busy, but the client was close
  to saturated too), so they are lower bounds for `only`.
- **Client-bound cells**: the TLS handshake rate is limited by the client (8 threads doing the
  client half of every handshake with rustls); keep-alive HTTP/1.1 is kernel-bound (one read and
  one write per request).
- The reference servers are not tuned beyond their defaults. No latency percentiles.

## Results

### HTTP/1.1 and HTTP/2 (requests/s)

HTTP/1.1: 256 connections. h2c and h2 over TLS: connections × concurrent streams.

| Case | only-epoll | only-uring | hyper | fib |
|---|---:|---:|---:|---:|
| HTTP/1.1 `GET /plaintext` | 729,229 | 774,202 | 650,511 | 620,200 |
| HTTP/1.1 `GET /plaintext`, pipelined ×16 | 4,289,270 | 4,400,739 | 855,912 | 3,750,364 |
| HTTP/1.1 `GET /json` | 724,779 (±4%) | 771,332 | 633,300 | 594,476 |
| h2c, 64 × 16 | 4,097,129 | 4,133,600 (±12%) | 1,031,686 | 3,231,636 |
| h2c, 16 × 128 | 5,363,059 (±4%) | 4,896,627 (±11%) | 1,361,642 | 4,006,582 |
| HTTP/2 over TLS 1.3, 64 × 16 | 3,975,030 (±7%) | 4,000,032 (±8%) | – ¹ | 3,049,105 |

¹ hyper-ref has no TLS listener.

`only` is 1.1–1.25× hyper and fib for keep-alive HTTP/1.1, 5× hyper and 1.14–1.17× fib pipelined,
3.6–4× hyper and 1.22–1.34× fib for h2c, and 1.3× fib for HTTP/2 over TLS (within the h2load ceiling,
see Limits).

### WebSocket echo (messages/s, 256 connections, 5 rounds)

| Message | only-epoll | only-uring | tokio-tungstenite | fib |
|---|---:|---:|---:|---:|
| 64 B | 665,276 (±8%) | 777,098 (±8%) | 576,076 | 577,582 |
| 1 KiB | 703,772 (±6%) | 709,751 (±7%) | 564,847 (±4%) | 565,032 |

`only` is 1.15–1.35× tokio-tungstenite and fib. Five rounds here because the `only` columns move
by up to ±8% between rounds (the first pass of the campaign, 3 rounds, gave 633–776 k for 64 B).

### TCP, UDP and TLS echo

TCP echo (requests/s; message size × connections):

| Load | only-epoll | only-uring | tokio | fib |
|---|---:|---:|---:|---:|
| 64 B × 64 | 754,603 | 713,819 (±9%) | 729,335 | 481,178 |
| 64 B × 256 | 668,463 (±6%) | 799,869 (±5%) | 751,788 | 572,302 |
| 64 B × 1024 | 716,397 | 774,846 (±4%) | 613,240 | 629,617 |
| 1 KiB × 64 | 654,182 | 626,264 (±8%) | 717,015 | 474,448 |
| 1 KiB × 256 | 729,516 | 766,693 (±6%) | 728,833 | 546,375 |
| 1 KiB × 1024 | 714,955 (±4%) | 791,433 | 654,371 (±10%) | 611,613 |
| 16 KiB × 64 | 402,461 (±10%) | 418,771 (±10%) | 441,178 | 189,719 |
| 16 KiB × 256 | 399,796 (±5%) | 395,342 (±8%) | 441,920 | 241,439 |
| 16 KiB × 1024 | 436,176 | 421,909 | 364,162 (±11%) | 274,924 (±5%) |

| Case | only-epoll | only-uring | tokio | fib |
|---|---:|---:|---:|---:|
| UDP echo, 64 B × 64 sockets (req/s) | 993,328 (±11%) | – ¹ | 251,740 | 338,269 |
| TLS 1.3 echo, 1 KiB × 64 (req/s) | 580,041 (±11%) | 584,406 (±10%) | 597,582 | 435,730 |
| TLS 1.3 full handshakes/s (32 clients) | 26,406 | 27,423 | 27,774 (±4%) | 20,539 |

¹ UDP runs on the epoll UDP loop for both backends. The tokio UDP reference is one task looping on
`recv_from`/`send_to`, the simplest tokio server, not its best case.

The TCP rows of `only` and tokio plateau at 0.65–0.8 M req/s from 64 to 1024 connections, which
points at the closed-loop client (8 threads) as much as at the servers: read them as "same class",
with fib behind at small and 16 KiB messages. The handshake rate is client-bound (see Limits): it
shows that only-tls on the server side keeps up with tokio-rustls, not a server maximum (in memory,
only-tls does 0.89–1.00× rustls' handshakes, see below).

### Memory per connection

Server RSS growth divided by the connections held open (`tools/bench/mem.sh`, 3 rounds, all within
±1% unless noted): the client opens the connections (spread over 127.0.0.1–4, so one client holds
more than 64 k), takes each through one exchange, then keeps them all idle while the server's
`VmRSS` is read. Bytes per connection, 10,000 connections unless noted. tokio's per-connection
read buffer is set to 4 KiB here (`TOKIO_REF_BUF`).

| Connection state | only-epoll | only-uring | tokio | hyper | fib |
|---|---:|---:|---:|---:|---:|
| idle TCP (connected only) | 603 | 603 | 5,008 | – | 280 |
| idle TCP, **100,000 connections** | 564 | 564 | 5,008 | – | 288 |
| TCP after one 64 B echo | 603 | 603 | 5,008 | – | 414 (±4%) |
| HTTP/1.1 keep-alive after one request | 937 | 936 | – | 17,447 | 1,643 |
| WebSocket after upgrade + one echo | 1,426 ³ | 1,414 ³ | 137,320 ² | – | 563 |
| TLS 1.3 after handshake + one echo | 8,192 | 8,186 | 15,124 | – | 6,815 |

² tokio-tungstenite with its default configuration keeps large per-connection read/write buffers.

³ Re-measured after a fix (median of 3 rounds, same host, same harness): this campaign's build
had 3,486 (epoll) / 3,485 (uring); see the end of History.

only-uring allocates its provided-buffer ring (1024 × 16 KiB per I/O thread) up front: its
baseline RSS is ~69 MB against ~3.5 MB for epoll, and that is not counted per connection. 100,000
idle connections cost `only` ~56 MB above the baseline.

### QUIC and HTTP/3 (`crates/only-h3/examples/quic-bench.rs`, loopback, CPUs 2–5)

| Case | only |
|---|---:|
| bulk, one stream, 2 GiB | 5,754 Mbit/s (5,749–5,785) |
| HTTP/3 GET, one connection, 64 in flight | 427,612 req/s (425,096–427,634) |
| full handshakes, 8 in flight | 6,640/s (6,618–6,640) |

No reference: the harness has no quic-go or fib QUIC server (see Not measured). During wave D
the quinn-proto build of the same program did 4.6 Gbit/s, 58 k req/s and ~6,600 handshakes/s.

**After the QUIC datapath pass** (2026-11-16, same host and pinning, `42d67dde` → after, median of
seven alternating rounds; an outside workload loaded the host during some rounds, so the ranges
are wide and the ratios are the figure to read):

| Case | before | after | after / before |
|---|---:|---:|---:|
| bulk, one stream, 2 GiB | 6,378 Mbit/s (4,083–6,428) | 16,066 Mbit/s (10,598–16,308) | 2.52 |
| HTTP/3 GET, one connection, 64 in flight | 427,901 req/s (324,321–434,382) | 443,299 req/s (335,410–444,711) | 1.04 |
| full handshakes, 8 in flight | 9,294/s (8,252–9,514) | 9,542/s (6,406–9,591) | 1.03 |

The quinn-proto build (the wave D tree with this harness) in another same-run comparison: bulk
4,613 against 15,999 Mbit/s (3.5×), HTTP/3 56,934 against 430,098 req/s (7.6×); its handshake
figure (202/s) is an artifact of the old stack under this harness and is left out. The
handshake row moved from 6,640 to ~9,300 before this pass through the P-256 and X25519 work in
only-crypto.

**After the HTTP/3 pass** (2026-11-16, same host and pinning, `dbc7563f` → after, median of seven
alternating rounds; the HTTP/3 row is a later run on a quiet host, bulk and handshakes come from
a run with outside load in some rounds):

| Case | before | after | after / before |
|---|---:|---:|---:|
| HTTP/3 GET, one connection, 64 in flight | 429,038 req/s (407,591–451,293) | 838,721 req/s (837,994–842,671) | 1.95 |
| bulk, one stream, 2 GiB | 16,414 Mbit/s (15,536–16,573) | 17,255 Mbit/s (16,693–17,467) | 1.05 |
| full handshakes, 8 in flight | 8,452/s (8,417–8,479) | 8,513/s (8,319–8,542) | 1.01 |

Profile of the HTTP/3 case (`perf`, both ends in one process): the allocator 31.8% → 11.2% of
the samples, SipHash 7.3% → 0.1%; only-quic and the kernel now take the larger shares (21.6% and
27.8%). The keyed hasher alone (SipHash build of the same tree against it, seven rounds): bulk
16,836 → 17,366 Mbit/s (+3%), HTTP/3 flat.

**After the HTTP/3 allocation pass** (2026-11-16, same host and pinning, quiet host, `62ea6318` →
after, median of seven alternating rounds):

| Case | before | after | after / before |
|---|---:|---:|---:|
| HTTP/3 GET, one connection, 64 in flight | 820,741 req/s (807,108–827,664) | 883,127 req/s (875,505–888,021) | 1.08 |

Allocations per request (both ends of the benchmark, counted with a counting allocator) went from
21.6 to 8.6: stream data reaches the event queue without two temporary vectors per delivery (4 per
request); small response and request heads are written into only-quic's pooled buffers instead of
a `Vec` plus the `Arc` of its `Bytes` (4); `Context` owns its request until something needs to
share it (1); a HEADERS frame of 64 bytes or more widens its length in place instead of splicing
(1); `Headers` keeps its first two field positions inline (3). The allocator went from 10.8% to
5.7% of the profile. QPACK writes `:status`, `content-length` and the date line (encoded once a
second) without a static table search; it was ~2% of the profile each way before and is now
about the same share of a shorter request. The rest is what a request needs (its target, its
`Headers` buffer, the response body, the boxed response sink).

The only-http changes are shared with HTTP/1.1 and HTTP/2, checked in the same quiet window
(`http-bench`, server on CPUs 0–3, h2load as in the table above, three alternating rounds; server
CPU time per request over 12 M requests is the steadier figure, since these rows sit at the
client's or the kernel's limit):

| Case | req/s before → after | after / before | server CPU per request before → after |
|---|---:|---:|---:|
| HTTP/1.1 `GET /plaintext` | 736,242 → 733,623 | 1.00 | 5,455 → 5,477 ns |
| HTTP/1.1 pipelined ×16 | 4,424,976 → 4,400,598 | 0.99 | 901 → 905 ns |
| h2c 64 × 16 | 4,328,640 → 4,297,478 | 0.99 | 925 → 926 ns |

Within run-to-run spread (an earlier window of the same code measured pipelined HTTP/1.1 at 899
against 903–908 ns). A first version kept four field positions inline: `Headers` grew from 48 to 80
bytes, and the extra copying of requests and responses cost HTTP/2 about 3% of server CPU per
request; two positions packed into the vector's niche keep it at 48 bytes.

**After the UDP owned receive buffers** (2026-11-18, ADR-024, same host and pinning, quiet host,
`ab65d376` → after, medians of alternating rounds; HTTP/3 and handshakes from five rounds, bulk
and UDP echo from a separate eleven-round run with 10-second echo runs; UDP echo is
`bench-server udp` on CPUs 0–3 with `echo-bench` 64 connections × 64 bytes on CPUs 4–11):

| Case | before | after | after / before |
|---|---:|---:|---:|
| bulk, one stream, 2 GiB | 18,637 Mbit/s (17,826–18,784) | 18,589 Mbit/s (17,397–18,649) | 1.00 |
| HTTP/3 GET, one connection, 64 in flight | 875,157 req/s (853,738–881,995) | 884,727 req/s (856,582–885,431) | 1.01 |
| full handshakes, 8 in flight | 3,926/s (3,869–3,930) | 3,924/s (3,896–3,941) | 1.00 |
| UDP echo, 64 B | 800,397 req/s (721,007–877,768) | 799,617 req/s (751,826–858,771) | 1.00 |
| UDP echo, server CPU per request (11 rounds) | 4,445 ns | 4,443 ns | 1.00 |

Datagrams now reach only-quic in the receive slab the kernel wrote them into and are decrypted
there, so the one copy left out of the `recvmmsg` slot is gone; the UDP loop's peer table uses the
keyed multiply hasher instead of SipHash. On loopback neither shows up beyond noise: bulk was
0.98–1.005 over four runs and HTTP/3 1.001–1.011 over three. The first version cost the UDP echo
server 3.4% more CPU per request (round-robin slabs went cold in cache, and every slot was reset
after each `recvmmsg`); slots now reuse their own slab once it is free and only the slots the last
call could have written are reset. The handshake rate is lower than in the tables above because
of the host state in this window (192 failed handshakes on both sides, every run); the ratio is
the figure to read.

### TLS 1.3 in memory (`crates/only-tls/examples/tls-bench.rs`, CPU 2)

Both ends in one thread, the same self-signed ECDSA P-256 certificate verified by the client, no
tickets; records sealed by the client and opened by the server. rustls 0.23 + ring is a
dev-dependency.

| Case | only-tls | rustls + ring | only / rustls |
|---|---:|---:|---:|
| full handshakes/s, X25519 | 5,027 | 5,025 | 1.00 |
| full handshakes/s, secp256r1 | 4,552 | 5,126 | 0.89 |
| full handshakes/s, X25519, RSA-2048 certificate ³ | 3,270 | 1,802 | 1.82 |
| seal + open 1 KiB, AES-128-GCM (MB/s) ⁴ | 3,168 | 1,810 | 1.75 |
| seal + open 16 KiB, AES-128-GCM ⁴ | 7,062 | 4,116 | 1.72 |
| seal + open 64 KiB, AES-128-GCM ⁴ | 6,876 | ² | – |
| seal + open 1 KiB, AES-256-GCM ⁴ | 2,906 | 1,692 | 1.72 |
| seal + open 16 KiB, AES-256-GCM ⁴ | 6,283 | 3,754 | 1.67 |
| seal + open 64 KiB, AES-256-GCM ⁴ | 6,119 | ² | – |
| seal + open 1 KiB, ChaCha20-Poly1305 ⁴ | 1,038 | 905 | 1.15 |
| seal + open 16 KiB, ChaCha20-Poly1305 ⁴ | 2,216 | 1,497 | 1.48 |
| seal + open 64 KiB, ChaCha20-Poly1305 ⁴ | 2,206 | 1,519 | 1.45 |

² rustls at 64 KiB swings between ~2,200 and ~3,900 MB/s from run to run (its receive side takes
at most 16 KiB of plaintext before it must be read out), so no ratio is given.

³ The server signs with RSA-PSS, the client verifies the certificate and that signature (the
RSA pass, the interleaved CRT halves and verification on IFMA, below); 775/s (0.43×) before the
RSA pass, 2,586/s (1.44×) before the interleaving, 3,002/s (1.67×) before verification on IFMA.

⁴ From the record zero-fill removal (below), median of five rounds alternated with the previous
code, rustls in the same runs: AES-128 1 KiB 1.62× → 1.75×, 16 KiB 1.58× → 1.72×, AES-256 16 KiB
1.54× → 1.67×, ChaCha20-Poly1305 1 KiB 1.01× → 1.08×, 16 KiB 1.43× → 1.48×. Before it, the AES-GCM
leftovers pass had taken AES-128 1 KiB from 1.51× to 1.58×. The ChaCha20-Poly1305 short-message
pass (below) then took the 1 KiB row from 1.09× to 1.15× (987 → 1,038 MB/s, same-run A/B).

Handshakes were 3,055 (X25519) and 2,306 (secp256r1) per second before the P-256 / X25519
pass (0.61× and 0.45×; History). The handshake profile is still dominated by curve arithmetic:
the P-256 doubling of the ECDH and the signature verification, then the X25519 ladder. The AES-GCM
records run on the VAES + VPCLMULQDQ + AVX-512 kernel and are sealed and opened out of place (the
AEAD reads the caller's plaintext or the received record and writes the output once; before, a
copy came first, 30% of the 16 KiB profile): 2.4× the previous release at 16–64 KiB (AES-128
2,739 → 6,603 MB/s at 16 KiB, 0.69× → 1.65× rustls + ring). ChaCha20-Poly1305 records run on the
AVX-512 ChaCha20 and IFMA Poly1305 kernels, also out of place: 0.55× → 1.42× rustls + ring at
16 KiB (below).

#### TLS extensions: handshake A/B (`tls-bench handshakes 2`, CPU 2)

record_size_limit, certificate compression and OCSP stapling (ADR-008), three rounds alternated
with `659f3c90` on the quiet host, mean full handshakes/s with default configurations (the client
sends record_size_limit; certificate compression is on for the server and off for the client):

| case | before | after | after / before |
|---|---:|---:|---:|
| X25519 | 5,438 | 5,445 | 1.00 |
| secp256r1 | 5,451 | 5,434 | 1.00 |
| X25519, RSA-2048 certificate | 3,290 | 3,295 | 1.00 |

A first run with compression on in the client too measured 0.99× in all three cases (5,426 →
5,376, 5,439 → 5,402, 3,296 → 3,262): inflating the 329-byte compressed certificate costs about
1.3 µs (2.2 µs for the RSA one), mostly only-deflate's fixed cost per stream, which is why clients
offer compression only when asked to.

#### Shared anti-replay store and compatible version negotiation: handshake A/B

ADR-013 (2026-11-17, `46c3c9ab` → branch, alternated rounds on the quiet host through `quiet.sh`;
default configurations, so no store call and no version switch, which is the path every
connection takes). QUIC with `quic-bench` on CPUs 2–5 (seven rounds of `handshakes 5 8`, three
of `resume 300`), TLS with `tls-bench handshakes 2` on CPU 2 (three rounds):

| case | before | after | after / before |
|---|---:|---:|---:|
| QUIC full handshakes/s, 8 in flight (median) | 9,496 | 9,497 | 1.00 |
| QUIC resumed, 0-RTT: dial to answer (median of medians) | 228.4 µs | 225.5 µs | 0.99 |
| QUIC resumed, 1-RTT: dial to answer (median of medians) | 270.2 µs | 268.0 µs | 0.99 |
| TLS full handshakes/s, X25519 (mean) | 5,431 | 5,425 | 1.00 |
| TLS full handshakes/s, secp256r1 (mean) | 5,439 | 5,441 | 1.00 |
| TLS full handshakes/s, X25519, RSA-2048 certificate (mean) | 3,290 | 3,293 | 1.00 |

A server with `prefer_version` copies the client's first Initial CRYPTO data (one ClientHello,
about 300 bytes to a few KiB) once per connection; the store is called only for ClientHellos
whose early data would be accepted.

#### Asynchronous anti-replay store and rotating ticket keys: handshake A/B

ADR-062 (2026-11-21, `b22519ae` → this branch, alternating runs on the quiet host through
`quiet.sh`; default configurations, so no store is called and tickets use the fixed key: the
path every connection takes). TLS with `tls-bench handshakes 2` on CPU 2 (three rounds), QUIC
with `quic-bench` on CPUs 2–5 (`handshakes 5 8` seven rounds, `resume 300` three rounds):

| Case | Before | After | After / before |
|---|---:|---:|---:|
| TLS full handshakes/s, X25519 (mean) | 5,361 | 5,323 | 0.99 |
| TLS full handshakes/s, secp256r1 (mean) | 5,454 | 5,419 | 0.99 |
| TLS full handshakes/s, X25519, RSA-2048 certificate (mean) | 3,242 | 3,258 | 1.00 |
| QUIC full handshakes/s, 8 concurrent (median) | 3,934 | 3,922 | 1.00 |
| QUIC resumed, 0-RTT: dial to answer (median of the round medians) | 253.6 µs | 252.0 µs | 0.99 |
| QUIC resumed, 1-RTT: dial to answer (median of the round medians) | 293.7 µs | 294.8 µs | 1.00 |

The rustls column of `tls-bench`, run in the same processes, moved by as much (4,961 → 4,954
handshakes/s on average), so the TLS differences are within the host's noise. A first QUIC
handshake set of three rounds, always base first, read 0.97; seven rounds with the order
reversed read 1.00 (rounds 3,676–3,942/s for both).

### Kernel TLS (kTLS) evaluation (`crates/only-tls/examples/ktls-bench.rs`, `tools/bench/ktls.sh`)

Question: after only-tls finishes a handshake, should the record keys go to the Linux kernel
(`setsockopt(TCP_ULP, "tls")`, `SOL_TLS` `TLS_TX` / `TLS_RX`), so that the kernel encrypts and
decrypts records, plaintext flows on the socket and `sendfile(2)` works under TLS? **Answer: no.
On this host the kernel's software kTLS is slower than only-tls's own record layer in every case
measured, and slowest exactly where it was supposed to win (large responses and `sendfile`).**
The offload is kept behind only-tls's `experimental-ktls` feature for re-measuring, and is not
wired into `Tls` or the engine.

Method: one thread-per-connection HTTP/1.1-over-TLS server (`ktls-bench`) whose record layer is
either only-tls in user space (`user`: responses sealed by only-tls and written; the file read in
64 KiB chunks with `pread` and sealed) or the kernel (`ktls`: the same handshake by only-tls, then
the keys handed over; responses written as plaintext; the file sent with `sendfile`). Same
binary, same handshake (TLS 1.3, X25519, ECDSA P-256, no tickets), AES-128-GCM unless noted.
Server on CPUs 0–3, `h2load --h1` with 8 threads on CPUs 4–7 and 12–15, 8 s per run after a 2 s
warm-up, 3 interleaved rounds (median shown; the rounds agreed within 1–2%), all under
`quiet.sh`. Linux 7.0, Ryzen 7 7800X3D; the kernel's AES-GCM is `generic-gcm-vaes-avx512`
(the same VAES + AVX-512 class of code as only-crypto's), ChaCha20-Poly1305 is
`rfc7539(chacha20-lib,poly1305-generic)`. The server was CPU-bound in every case (4.0 CPU-seconds
per second), so CPU per byte is server CPU time (user + system, from `/proc`) over bytes served.

| Case (connections) | only-tls req/s | kTLS req/s | kTLS / only | only-tls CPU ns/B | kTLS CPU ns/B | kTLS / only CPU per byte |
|---|---:|---:|---:|---:|---:|---:|
| 1 KiB responses (64) | 531,393 | 439,368 | 0.83 | 6.77 | 8.55 | 1.26 |
| 16 KiB (64) | 358,494 | 233,814 | 0.65 | 0.679 | 1.042 | 1.53 |
| 256 KiB (32) | 66,057 (16.1 GB/s) | 26,415 (6.45 GB/s) | 0.40 | 0.231 | 0.577 | 2.50 |
| 10 MB file (16): `pread` + seal vs `sendfile` | 1,391 (13.0 GB/s) | 669 (6.24 GB/s) | 0.48 | 0.288 | 0.597 | 2.07 |
| 16 KiB, ChaCha20-Poly1305 (64) | 284,155 | 175,070 | 0.62 | 0.858 | 1.393 | 1.62 |
| 16 KiB, TLS 1.2 AES-128-GCM (64) | 358,377 | 242,912 | 0.68 | 0.680 | 1.003 | 1.47 |

Loopback has a 64 KiB MTU; with the client in a network namespace behind a veth pair with a
1500-byte MTU (`VETH=1`, GSO/GRO on, as with a NIC) the ratios were the same: 0.83 (1 KiB),
0.65 (16 KiB), 0.40 (256 KiB), 0.49 (file). Offloading costs 14–20 µs per connection (`TCP_ULP`
plus two `SOL_TLS` keys), against ~200 µs of CPU for a whole full handshake, both ends together
(5,027/s in `tls-bench`): a noticeable addition for short connections.

Why (perf, 10 MB file case): with kTLS, 96% of the server's samples are under `tls_sw_sendmsg`,
but the AES-GCM itself is only ~12%. The kernel pushes every 16 KiB record to TCP on its own
(`tls_push_record` → `tcp_push`: ~55% of the samples in the TCP/IP transmit path, including the
loopback receive softirq, against ~29% for user space, which hands TCP 64 KiB of records per
`write`), and it allocates and zeroes fresh pages for each record (`kernel_init_pages` ~5%). In
user space the same work is only-crypto's GCM (22%) plus the `pread` and `write` copies (~14%
each); saving those copies does not make up for the per-record cost in the kernel. Small
responses lose less (0.83×) because the per-request work there is dominated by the syscalls and
TCP, which both modes share.

When kTLS could still pay off: a NIC with TLS offload (`tls-hw-tx-offload`, e.g. ConnectX-6 Dx;
none on this host), where the kernel hands records to the NIC unencrypted and `sendfile` really
is zero-copy; or a host whose user-space AES-GCM is much slower than the kernel's (no VAES).
Neither applies to only-tls on x86_64 with VAES; re-measure with `tools/bench/ktls.sh` before
reconsidering.

What the experimental code covers (tests: `crates/only-tls/tests/ktls.rs` on a kTLS kernel,
in-memory unit tests anywhere; `ONLY_INTEROP_KTLS=require tools/interop/tls/run.sh` passed 107/107
against OpenSSL 3.0.13 and Go 1.27 with only's side offloaded): TLS 1.3 and 1.2 with AES-128-GCM,
AES-256-GCM and ChaCha20-Poly1305; the keys and sequence numbers exported after the handshake
(only when nothing is buffered); alerts, close_notify and post-handshake messages (NewSessionTicket,
KeyUpdate) through the record-type control message; TLS 1.3 KeyUpdate in both directions by
re-installing keys (Linux 6.14+; older kernels keep TLS 1.3 in user space, since a peer can rekey
at any time); fallback to user space when the `tls` module or the suite is missing. Not done:
the engine integration (epoll / io_uring receive with `TLS_GET_RECORD_TYPE`, control records in
the write queue), `TLS_RX_EXPECT_NO_PAD`, and sending our own KeyUpdate before the AES-GCM record
limit (the kernel does not count for us).

### io_uring features evaluation (`tools/bench/uring-eval.sh`, engine A/B)

Measured 2026-11-16. Question (DEV-PLAN M2): should the io_uring backend use registered files, `SEND_ZC`, `MSG_RING`
wake-ups or ring-based sends? Rule: adopt only with a clear same-run gain of at least 3% and no
regression elsewhere. **Answer: none of them, for now.** Ring-based sends are the only one with a
real signal (2–7% less server CPU per request on a bare ring), but the engine writes from any
thread straight to the socket, so using them is a redesign of the write path, not a switch.
`SEND_ZC` loses everywhere on loopback; the others are within noise. Linux 7.0, Ryzen 7 7800X3D,
everything under `quiet.sh`, server on CPUs 0–3 (4 threads), `h2load` / `echo-bench` with 8
threads on CPUs 4–7 and 12–15; the backend already uses multishot accept and recv, a
provided-buffer ring, and `COOP_TASKRUN` + `SINGLE_ISSUER` + `DEFER_TASKRUN` rings.

**Send mechanisms on a bare ring.** The engine cannot switch to ring sends without that
redesign, so they were measured on a minimal HTTP/1.1 responder driven straight on only-uring's
ring (the ignored `eval_server` test, `crates/only-uring/src/eval.rs`): the same multishot accept
and recv as the backend, one fixed response per request from a static buffer (so `SEND_ZC` never
waits for a buffer to come back: its best case), sent with `write(2)` from the completion handler
(what the engine does), with `IORING_OP_SEND` entries submitted with the next wait, or with
`IORING_OP_SEND_ZC`; "+fixed" adds direct accept into a registered file table and
`IOSQE_FIXED_FILE` on every entry. 256 connections, 5 interleaved rounds of 5 s, medians;
throughput relative to `write`, and server CPU (user + system, from `/proc`) per request.

| Response (in flight per connection) | `write` req/s | SEND | SEND +fixed | SEND_ZC | SEND_ZC +fixed | CPU µs/req: write / SEND / +fixed / ZC |
|---|---:|---:|---:|---:|---:|---|
| 13 B body (16, pipelined) | 9,011,289 | 1.038 | 1.066 | 0.885 | 0.911 | 0.333 / 0.312 / 0.309 / 0.366 |
| 1 KiB (16, pipelined) | 7,302,214 | 1.035 | 1.046 | 0.880 | 0.866 | 0.546 / 0.527 / 0.525 / 0.622 |
| 16 KiB (1) | 495,080 | 1.033 | 1.039 | 0.877 | 0.881 | 8.08 / 7.82 / 7.79 / 9.20 |
| 64 KiB (1) | 296,010 | 1.018 | 1.025 | 0.768 | 0.772 | 13.52 / 13.27 / 13.21 / 17.64 |
| 256 KiB (1) | 110,173 | 1.011 | 1.016 | 0.733 | 0.738 | 36.3 / 35.8 / 35.8 / 49.5 |

- **`SEND_ZC`: not adopted.** 12–27% slower and 10–36% more CPU per request, worst for the large
  responses it is meant for. With `IORING_SEND_ZC_REPORT_USAGE` every notification said the
  kernel had copied the data: loopback (and a veth pair) cannot hand pages to the receiver, so
  zero-copy turns into a copy plus page pinning plus a second completion per send. It can only
  win with a real NIC and responses of 16 KiB and up, and then needs the send buffer held until
  its notification, which the engine's write queue does not do. Re-measure with
  `tools/bench/uring-eval.sh` on a host with a NIC.
- **Ring-based sends (`IORING_OP_SEND`): not adopted now; the one candidate worth a project.**
  +1–4% throughput and 2–6% less CPU per request than `write(2)`, most for small responses (the
  sends of a whole completion batch go to the kernel in the one `io_uring_enter` the loop makes
  anyway). In the engine, `Conn::send` from any thread writes straight to the socket and only
  queues the rest, and that write path is shared with epoll; ring sends need the bytes owned until
  their completion, one send in flight per connection, and ordering against direct writes from
  other threads. For the HTTP server the saved ~0.02 µs per pipelined request is ~2–3% of its
  CPU per request (0.9 µs at 4.5 M req/s on 4 cores), under the bar.
- **Registered files (direct accept, `IOSQE_FIXED_FILE`): not adopted.** On top of ring sends,
  +0.4–2.7%. In the engine there is nothing for them to save: counting submissions over a
  plaintext run (2.3 M requests, and 13.6 M pipelined) showed 520 entries in total, i.e. two per
  connection (the multishot recv and the reset watch) plus the loops' own; in steady state the
  backend submits no entry per request, and the only per-request system calls are the response
  `write` and a shared `io_uring_enter`. Direct descriptors also have no normal fd, which the
  direct `write` path from other threads needs.

**Engine A/B** (temporary patch of the reactor behind an environment switch, both variants in
every round, fresh server per run, `http-bench` / `bench-server`):

| Case | Registered ring fd (5 rounds) | `MSG_RING` wake-up, run 1 (5 rounds) | `MSG_RING`, run 2 (7 rounds) |
|---|---:|---:|---:|
| HTTP/1.1 plaintext, 256 connections | 0.985 | 0.995 | 1.002 |
| HTTP/1.1 pipelined 16 x 256 | 1.000 | 1.002 | 1.001 |
| TCP echo 64 B x 256 | 0.964 | 0.964 | 0.974 |
| TCP echo 16 KiB x 256 | 0.982 | 1.044 | 0.983 |
| `spawn_blocking` echo (`block-pool 0`), 64 B x 256 | 1.005 | 1.048 | 1.030 |
| `spawn_blocking` echo, 64 B x 64 | | | 0.987 |
| `spawn_blocking` echo, 1 KiB x 256 | | | 1.015 |

- **Registered ring fd (`IORING_REGISTER_RING_FDS` + `IORING_ENTER_REGISTERED_RING`): not
  adopted.** It saves the fd lookup of each `io_uring_enter`, and the loop makes about one enter
  per 20 requests at 256 connections: −3.6% to +0.5%, i.e. noise (the plain echo rows move ±10%
  between rounds on this host).
- **`MSG_RING` wake-ups: not adopted.** Another thread (a pool thread finishing a
  `spawn_blocking`, a cross-thread `close`) wakes the loop by writing its eventfd, which a
  pending `read` on the ring completes; with `IORING_REGISTER_SEND_MSG_RING` (6.13+) a thread
  without a ring can post a completion straight into the loop's CQ, so the loop no longer
  re-arms the eventfd read. It works (strace: 8,949 `io_uring_register` calls replaced 5,558
  eventfd writes in 2 s of pool echo), but the gain is only where wake-ups dominate and not clear:
  +3.0–4.8% for 64 B pool echo with 256 connections, +1.5% at 1 KiB, −1.3% with 64 connections;
  pool round trips are dominated by the pool's own futex wake-ups (~94% of the server's syscall
  time). Cross-thread `Conn::send` needs no wake-up at all unless the socket is full (it writes
  directly), so it gains nothing.
- **Already in use**: `COOP_TASKRUN`, `SINGLE_ISSUER`, `DEFER_TASKRUN` (fallbacks when refused),
  multishot accept and recv, the provided-buffer ring; `SQPOLL` is opt-in (`UringConfig::sqpoll`).
  Registered buffers would only serve `SEND_ZC` (fixed send buffers) or `READ_FIXED`; with
  multishot recv on provided buffers and direct writes there is nothing to register. Recv
  bundles and incremental buffer consumption were not tried.

### Telemetry overhead (engine A/B, `tools/bench`)

Measured 2026-11-16. Question (DEV-PLAN M6 "overhead measured on a quiet host"): what do the
engine's always-on counters and the callback timing cost? Three builds of the same commit, run
interleaved in one session under `quiet.sh` (5 rounds of 5 s, medians, a fresh server per run;
server on CPUs 0–3 with 4 threads, `h2load` / `echo-bench` with 8 threads on CPUs 4–7 and 12–15):
**default** (counters on, callbacks timed because the slow-callback threshold defaults to 100 ms),
**no timing** (`slow_callback_threshold: None`), **no counters** (no timing, and every
per-thread counter update compiled out). Ratios are against the default build; `±` is half the
min–max spread of the rounds.

| Load | backend | default | no timing | no counters |
|---|---|---:|---:|---:|
| HTTP/1.1 plaintext, 256 conns | epoll | 744,197 | 1.001 | 1.006 |
| HTTP/1.1 plaintext, 256 conns | io_uring | 791,360 | 0.998 | 1.002 |
| HTTP/1.1 pipelined ×16, 256 conns | epoll | 4,495,865 | 0.999 | 1.004 (±12%) |
| HTTP/1.1 pipelined ×16, 256 conns | io_uring | 4,632,963 | 0.998 | 1.001 |
| TCP echo 64 B × 256 (±4–8%) | epoll | 716,872 | 0.972 | 0.969 |
| TCP echo 64 B × 256 (±4–8%) | io_uring | 731,461 | 1.077 | 1.061 |
| TCP echo 1 KiB × 256 (±4–9%) | epoll | 702,327 | 1.023 | 1.034 |
| TCP echo 1 KiB × 256 (±4–9%) | io_uring | 776,740 | 0.990 | 0.983 |
| UDP echo 64 B × 64 (±9–11%) | epoll | 977,216 | 1.051 | 1.035 |

**Answer: no measurable cost.** The HTTP rows (spread ≤2% except one outlier round) put both
switches within ±0.6% of the default; the echo rows move both ways by more than any plausible
effect, inside their round-to-round noise (the closed-loop echo client is the bottleneck, see
"TCP, UDP and TLS echo"). The counters are plain loads and stores on a cache line owned by the
I/O thread, and the timing is one clock read per callback reused across a batch, so this matches
expectations; the defaults stay as they are.

**Collectors (ADR-015).** Registered collectors run only when metrics are rendered; on the request
path the change touches only `HttpMetrics`, which now also counts the request's HTTP version.
Same harness, 7 rounds, `http-bench` with and without `HttpMetrics::middleware()`, built from
`main` at `659f3c90` and from the collectors branch (all four in one session):

| Load | backend | `main`, no middleware | branch, no middleware | `main` + middleware | branch + middleware | branch / `main` with middleware |
|---|---|---:|---:|---:|---:|---:|
| HTTP/1.1 plaintext, 256 conns | epoll | 732,560 | 1.000 | 0.979 | 0.984 | 1.005 |
| HTTP/1.1 plaintext, 256 conns | io_uring | 775,805 | 1.004 | 0.979 | 0.982 | 1.003 |
| HTTP/1.1 pipelined ×16, 256 conns | epoll | 4,429,622 | 1.002 | 0.903 | 0.900 | 0.997 |
| HTTP/1.1 pipelined ×16, 256 conns | io_uring | 4,546,534 | 1.008 | 0.904 | 0.902 (±10%) | 0.998 |

No measurable change. The first version of the per-version counter (an extra atomic add at
dispatch, the version captured in the response closure) measured 0.988 on io_uring pipelined in
three runs; the version is now read from the request in the response filter, HTTP/1.1 is derived
(responses minus the other versions, kept monotonic), and the shard's layout keeps the status
class, latency sum and first latency bucket on one cache line. The middleware itself costs about
2% at 0.75 M req/s and 10% at 4.5 M req/s pipelined, on `main` as on the branch.

### Observability overhead (ADR-020, `tools/bench`)

Measured 2026-11-18 on gpu51 under `quiet.sh` (5 s runs, medians, a fresh server per run; server on
CPUs 0–3 with 4 threads, `h2load` with 8 threads on CPUs 4–7 and 12–15). **Off**: main (ab65d376)
against this branch's `http-bench`, 7 rounds. **On**: `crates/only-export/examples/obs-bench.rs`
(the same routes) with one feature switched on, 5 rounds, against the branch's `http-bench`
(spans: against main, from a later run with the deferred-fields fix). `±` is half the min–max spread.

| Load (epoll) | off: branch / main | `HttpMetrics` | + per-route labels | `H2Stats` | spans 1% sampled | spans 100%, exported |
|---|---:|---:|---:|---:|---:|---:|
| HTTP/1.1 plaintext, 256 conns | 1.000 / 1.050 (±4%) (io_uring 1.005) | 0.987 | 0.987 | 1.002 | 0.972 (±9%) | 0.746 |
| HTTP/1.1 pipelined ×16 | 0.989 / 0.998 (±3%) (io_uring 0.999) | 0.928 | 0.925 | 0.997 | 0.883 | 0.540 |
| h2c 64 conns × 16 streams | 1.080 / 0.993 (±13% / ±2%) (io_uring 1.019) | 0.923 (±9%) | 0.918 | 0.992 | 0.875 (±5%) | 0.547 |

**Answers.** With everything off the request path is unchanged (two runs: 0.989 and 0.998 for
pipelined epoll, the rest within ±1% or within noise). `H2Stats` costs nothing measurable; per-route
labels add about 0.5% to the existing `HttpMetrics` middleware (whose own ~7% at 4.6M pipelined
requests/s is the closure and response filter per request, unchanged by this work). Spans cost what
they do: at 1% sampling, an unsampled request span is a box, two random ids and the thread-local
enter (about 12% at 4.6M requests/s, 3% at 0.7M); at 100% every request also allocates its fields
and the exporter thread encodes and sends ~2.5M spans/s on the same four CPUs. Sample in
production (`sample_ratio`), or give the exporter thread its own CPU.

### OTLP export additions (ADR-064, same-run A/B)

Measured 2026-11-21 on gpu51 under `quiet.sh`. Question: do span events and links, OTLP logs,
exemplars and the export changes cost anything while they are off? `base` is `main` at
`b22519ae`, `new` the otlp-gaps branch, built in one session and run alternately, pinned to one
CPU (micro-benchmarks) or with the server on CPUs 0–3 (4 threads, epoll) and `h2load` (8
threads, 256 connections, 5 s) on CPUs 4–7 and 12–15. Medians; ratios are new / base.

| Benchmark | rounds | base | new / base |
|---|---:|---:|---:|
| only-log `trace!` disabled, 2 key-values | 5 × 2 | 0.272 ns | 1.009 |
| only-log `info_span!` with spans off, 2 fields | 5 × 2 | 0.615 ns | 0.998 |
| only-log `span::enabled` (spans off) | 5 × 2 | 0.407 ns | 0.994 |
| only-log `log_enabled!` disabled | 5 × 2 | 0.406 ns | 0.998 |
| `Histogram::observe` (no exemplars) | 7 | 4.643 ns | 1.005 |
| `HttpMetrics` middleware (exemplars off), HTTP/1.1 plaintext | 7 | 731,820 req/s | 0.999 |
| `HttpMetrics` middleware (exemplars off), pipelined ×16 | 7 | 4,284,243 req/s | 1.001 |

**Answers.** Disabled log and span statements are unchanged (within ±1%). A first version kept
an exemplar flag inside `Histogram` and measured 1.15 (inlined offer), then 1.04 (out of line, a
branch per observation); exemplars now live in their own `ExemplarHistogram`, and a plain
histogram is back at 1.005. The `HttpMetrics` middleware with exemplars off is unchanged. The
`only_export` code itself runs on its own thread.

### Hot reload (engine A/B, `tools/bench`)

Measured 2026-11-18 on gpu51. Question (ADR-028): does the reloadable read buffer and backlog and
the resizable thread groups change the steady-state hot path? The changes there are a listener
bit tested in the poll token instead of one constant compared, a few per-iteration checks for a
retiring loop, and on io_uring the buffer group chosen from the completion's operation code.
`base` is `main` at `ab65d376`, `new` the branch; both built in one session and run interleaved
under `quiet.sh` (5 s runs, medians, a fresh server per run; server on CPUs 0–3 with 4 threads,
`h2load` / `echo-bench` with 8 threads on CPUs 4–7 and 12–15). Ratios are new / base; `±` is
half the min–max spread of the rounds.

| Load | backend | base | new / base |
|---|---|---:|---:|
| HTTP/1.1 plaintext, 256 conns (11 rounds) | epoll | 715,480 | 1.004 |
| HTTP/1.1 plaintext, 256 conns (11 rounds) | io_uring | 770,331 | 1.005 |
| HTTP/1.1 pipelined ×16, 256 conns (11 rounds) | epoll | 4,509,363 | 0.996 |
| HTTP/1.1 pipelined ×16, 256 conns (11 rounds) | io_uring | 4,658,051 | 0.999 |
| TCP echo 64 B × 1024 conns (5 rounds, ±2–4%) | epoll | 739,312 | 1.007 |
| TCP echo 64 B × 1024 conns (5 rounds, ±2–4%) | io_uring | 805,131 | 0.973 |
| TCP echo 64 B × 64 conns (5 rounds, ±3–15%) | epoll | 766,225 | 0.956 |
| TCP echo 64 B × 64 conns (5 rounds, ±3–15%) | io_uring | 746,246 | 0.933 |

**Answer: unchanged.** A first 5-round run put pipelined at 0.983 (epoll) and 0.991 (io_uring)
with a 1% spread; the 11-round rerun of the HTTP rows gives 0.996 and 0.999 (per-round ratio
medians 0.998 for both); this row moves by about 1% between runs of the same build on this
host. The echo rows move both ways inside their round-to-round noise (the closed-loop echo
client is the bottleneck, see "TCP, UDP and TLS echo").

### Cryptography (`only-crypto`, `--example bench` and `--example pk_bench`, CPU 2)

Hardware paths detected at run time: AES-NI, PCLMULQDQ, SHA-NI, SSE4.2 CRC32, AVX2, VAES +
VPCLMULQDQ + AVX-512 (AES-GCM at every length, CRC folding from 512 bytes), BMI2 + ADX. The comparison
columns are the RustCrypto crates `only-crypto` replaced (also with run-time CPU detection;
crc32fast for CRC-32) and ring 0.17 for public-key operations.

| Operation (MB/s) | Size | only-crypto | RustCrypto | ratio |
|---|---:|---:|---:|---:|
| SHA-1 | 16 KiB | 2,546 | 2,545 | 1.00 |
| SHA-1, BitTorrent piece | 256 KiB | 2,558 | 2,558 | 1.00 |
| SHA-256 | 16 KiB | 2,365 | 2,371 | 1.00 |
| SHA-256 | 1400 B | 2,189 | 2,221 | 0.99 |
| HMAC-SHA1 (STUN message) | 100 B | 583 | 624 | 0.94 |
| CRC-32 | 1400 B | 35,164 | crc32fast 30,400 | 1.16 |
| CRC-32 | 16 KiB | 74,885 | crc32fast 73,153 | 1.02 |
| CRC-32C | 1400 B | 40,383 | – | – |
| AES-128, one block (CFB chain, KCP) | 16 B | 3,197 | 3,486 | 0.92 |
| AES-128-CTR | 1400 B | 7,716 | 8,493 | 0.91 |
| AES-128-CTR | 16 KiB | 8,393 | 11,546 | 0.73 |
| AES-128-GCM seal | 1400 B | 8,644 | aes-gcm 1,944 | 4.45 |
| AES-128-GCM seal | 16 KiB | 15,316 | aes-gcm 2,153 | 7.11 |
| AES-128-GCM open | 16 KiB | 13,262 | aes-gcm 2,083 | 6.37 |
| AES-256-GCM seal | 16 KiB | 13,335 | aes-gcm 2,002 | 6.66 |
| ChaCha20-Poly1305 seal | 1400 B | 2,579 | 776 | 3.32 |
| ChaCha20-Poly1305 seal | 16 KiB | 4,606 | 1,921 | 2.40 |
| SHA-512 (portable) | 16 KiB | 540 | 823 | 0.66 |
| MD5 (portable) | 16 KiB | 686 | 815 | 0.84 |
| base64 encode | 1400 B | 2,059 | 2,739 | 0.75 |
| PBKDF2-HMAC-SHA1, 4096 rounds (kcptun key) | – | 0.83 ms | 0.57 ms | – |

| Operation (op/s) | only-crypto | ring | ratio |
|---|---:|---:|---:|
| Ed25519 sign | 89,784 | 58,979 | 1.53 |
| Ed25519 verify | 27,714 | 31,874 | 0.87 |
| X25519 agreement | 36,488 | 36,512 | 1.00 |
| P-256 ECDSA sign | 59,837 | 75,840 | 0.79 |
| P-256 ECDSA verify | 25,138 | 26,140 | 0.96 |
| P-256 ECDH | 27,288 | 29,913 | 0.91 |
| P-256 key generation | 108,263 | 112,440 | 0.96 |
| P-384 ECDSA sign | 10,553 | 3,330 | 3.17 |
| P-384 ECDSA verify | 4,330 | 1,849 | 2.34 |
| P-384 ECDH | 4,387 | 3,579 | 1.23 |
| P-384 key generation | 19,331 | 3,586 | 5.39 |
| RSA-2048 PKCS#1 sign | 5,511 | 2,434 | 2.26 |
| RSA-2048 PKCS#1 verify | 200,748 | 65,392 | 3.07 |
| RSA-2048 verify + key parse | 153,716 | 65,392 | 2.35 |
| RSA-3072 PKCS#1 sign | 1,766 | 789 | 2.24 |
| RSA-3072 PKCS#1 verify | 100,719 | 30,486 | 3.30 |
| RSA-4096 PKCS#1 sign | 899 | 346 | 2.60 |
| RSA-4096 PKCS#1 verify | 64,911 | 17,534 | 3.70 |

The P-256 rows and X25519 run on BMI2 + ADX (`ec::hw`, `curve25519::hw`; `adx` in the detected
paths). With every hardware path off (`ONLY_CRYPTO_PORTABLE=1`, which also turns off SHA-NI for
the RFC 6979 HMACs) P-256 does 0.42× (sign), 0.58× (verify), 0.52× (ECDH) and 0.60× (key
generation) of ring, X25519 0.84×, and the handshakes 0.62× (X25519) and 0.49× (secp256r1) of
rustls. The P-256 rows above are from the previous pass; the next table has this pass.

#### P-256 whole-point assembly, wide comb, safegcd (`--example pk_bench`, `tls-bench handshakes 2`, CPU 2)

Median of five alternating rounds of the previous code (`7cefa48b`) and this pass. The host was
busy with another benchmark during the whole window (load average 9–10, the sibling of CPU 2
loaded), so every absolute rate is 20–30% below the quiet figures in the tables above; the
ratios are measured in the same run, `only` and ring/rustls back to back.

| op/s (loaded host) | before | after | ring / rustls | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|
| P-256 ECDSA sign | 46,445 | 73,287 | 72,238 | 0.77 | 1.25 |
| P-256 ECDSA verify | 18,601 | 19,281 | 19,131 | 0.98 | 1.04 |
| P-256 ECDH | 19,900 | 20,922 | 21,050 | 0.94 | 0.96 |
| P-256 key generation | 78,234 | 111,338 | 103,483 | 0.94 | 1.33 |
| TLS 1.3 full handshakes/s, secp256r1 | 4,363 | 5,290 | 4,027–4,601 | 0.94 | 1.12 |
| TLS 1.3 full handshakes/s, X25519 | 3,645 | 3,701 | 4,033–4,630 | 0.94 | 1.06 |

Cycles on this CPU (`perf stat`, quiet moments): a doubling 481 → 355 (whole-point assembly,
five in one frame), an addition 881 → 778, a mixed addition 618 → 564; the fixed-base
multiplication 40.5k → 31k (43 windows of 6 bits instead of 65 of 4: 6-bit and 7-bit combs tie,
5 and 8 bits are slower); the variable-base multiplication ~190k → 159k; the scalar inversion
20.9k → 7.0k and the field inversion 12.7k → ~7–9k (safegcd with assembly divsteps instead of
Fermat chains). With `ONLY_CRYPTO_PORTABLE=1` the portable safegcd lifts sign from 0.41× to about
0.45× ring and ECDH from 0.52× to 0.57×.

#### P-256 point formulas (`--example pk_bench`, `tls-bench handshakes 2`, CPU 2)

Median of five alternating rounds of the previous code (`1376b324`) and this pass, both against
ring 0.17 / rustls 0.23 in the same run, on a quiet host (load average about 1; the services
stopped by `quiet.sh`). On the same quiet host the previous code is already ahead of ring in
ECDH: the 0.96× above was a loaded-host figure.

| op/s (quiet host) | before | after | ring / rustls | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|
| P-256 ECDSA sign | 103,471 | 105,399 | 76,155–76,287 | 1.36 | 1.38 |
| P-256 ECDSA verify | 28,319 | 28,834 | 26,268–26,309 | 1.08 | 1.10 |
| P-256 ECDH | 32,351 | 33,904 | 30,067–30,141 | 1.08 | 1.12 |
| P-256 key generation | 153,678 | 158,921 | 113,089–113,374 | 1.36 | 1.40 |
| TLS 1.3 full handshakes/s, secp256r1 | 5,504 | 5,489 | 5,115–5,157 | 1.07 | 1.07 |
| TLS 1.3 full handshakes/s, X25519 | 5,496 | 5,464 | 5,030–5,062 | 1.09 | 1.08 |

The change: OpenSSL's `ecp_nistz256` formulas in the whole-point assembly (addition 12M + 4S with
seven modular additions and subtractions instead of 11M + 5S with thirteen, mixed addition
8M + 3S with seven instead of 7M + 4S with fourteen, the doubling from `2Y` with a modular
halving: ten linear operations instead of fourteen), and a reduction step of seven instructions
instead of ten (`p₃` kept in `rdx`, `shlx`/`shrx` by `rbx = 32`). Cycles (`perf stat`, min of
five alternating rounds): doubling 355 → 348, addition 745 → 721, mixed addition 537 → 508,
variable-base multiplication 148.1k → 140.6k, the whole ECDH through the public API (decode,
multiply, invert, encode) 147.7k, fixed-base comb 29.8k → 28.9k, field inversion 6.2k. The
handshakes did not move: one ECDH is about 1% of a handshake.

Tried and left out, by the same measurement: the doubling's products reordered (independent
ones first, or the `Y` chain first) 8–10% slower; an OpenSSL-style reduction interleaved with the
product rows neutral (+1%); the `cmov` selections of the final subtractions replaced by
`xor`/`and` masks 10% slower. A doubling behaves as about 44 cycles per product whatever the
order, which is close to the throughput of the `mulx` and flag-reading instructions it issues
rather than to its dependency chain.

#### P-256 frame-resident comb and ECDH, RSA Karatsuba squaring (`--example pk_bench`, `tls-bench handshakes 2`, CPU 2)

2026-11-18, three alternating rounds of `main` (`ab65d376`) and this pass, against ring 0.17 /
rustls 0.23 in the same run, on the quiet host (`quiet.sh`); medians.

| op/s (quiet host) | before | after | ring / rustls | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|
| P-256 ECDSA sign | 106,718 | 114,996 | 76,891–77,187 | 1.38 | 1.49 |
| P-256 ECDSA verify | 28,935 | 29,069 | 26,318–26,405 | 1.10 | 1.10 |
| P-256 ECDH | 33,886 | 34,701 | 30,223–30,328 | 1.12 | 1.15 |
| P-256 key generation | 159,957 | 179,385 | 114,507–114,982 | 1.40 | 1.57 |
| TLS 1.3 full handshakes/s, secp256r1 | 5,436 | 5,528 | 5,072–5,142 | 1.07 | 1.08 |
| TLS 1.3 full handshakes/s, X25519 | 5,417 | 5,468 | 4,913–5,002 | 1.08 | 1.10 |

The change: the fixed-base comb and the ECDH multiplication keep the accumulator in one assembly
frame for the whole multiplication. Each window's table entry is scanned with AVX2 and negated by
masks straight into the frame, the doublings and the addition run on it in place, and the special
cases (an accumulator at the identity, a zero digit) are masked selects on the frame instead of
`Jac` values copied in and out of every point routine. Key generation +12%, signing +8%, ECDH
+2.5%. Tried and left out: a 7-bit comb (37 rows of 64 points, 151 KiB) measured the same as the
6-bit one before this change and 2–3% slower after it (key generation 179k → 175k/s); an affine
ECDH table (one batched inversion, then mixed additions) and skipping the reductions of values
only multiplied in the doubling (one of its ten linear operations qualifies) were estimated at
break-even and 0.5%.

RSA on x86_64 without AVX-512 IFMA (measured on the same Zen 4 with the IFMA path switched off in
both builds): squaring at 48 and 64 limbs is now one level of Karatsuba over the 24- and 32-limb
squaring assembly, instead of a full multiplication. Verify 3072 39,851 → 41,994/s (+5.4%), 4096
22,170 → 24,155/s (+9.0%), with key parse +5.9% / +3.8%; 2048 and signing (CRT halves of 16–32
limbs) unchanged. A Karatsuba multiplication at 48 / 64 limbs was correct but is used only twice
per verification and was left out. CPUs with IFMA run 2048–4096-bit RSA on IFMA and do not reach
this code. `tools/ct-dudect p256` (60 s per target, hardware path): no leak (max |t| 3.48).

#### P-256 and X25519 on aarch64 (Apple M4 Pro, `--example pk_bench`)

2026-11-19, the first measurement of the aarch64 assembly (`ec::hw_aarch64`,
`curve25519::hw_aarch64`; tested since 2026-11-17, never benchmarked), macOS on an Apple M4 Pro
(14 cores), ring 0.17 in the same runs (its `ecp_nistz256-armv8` P-256 and fiat X25519). The
machine was shared with other builds (load average 7–10, at times far higher), so these are
medians of five alternating rounds of `main` (`436b47e7`) and this pass; the portable column is
`main` with `ONLY_CRYPTO_PORTABLE=1` (median of three rounds).

| op/s (M4 Pro, shared) | portable | assembly before | after | ring | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|---:|
| P-256 ECDSA sign | 46,803 | 99,487 | 108,571 | 85,350–86,622 | 1.15 | 1.25 |
| P-256 ECDSA verify | 17,042 | 34,355 | 34,817 | 33,242–33,509 | 1.03 | 1.04 |
| P-256 ECDH | 19,160 | 37,147 | 37,746 | 37,736–37,800 | 0.98 | 1.00 |
| P-256 key generation | 76,905 | 146,501 | 151,611 | 127,811–128,366 | 1.15 | 1.18 |
| X25519 | 48,708 | 57,511 | 57,067 | 54,619–54,794 | 1.05 | 1.04 |

The assembly field doubles P-256 against the portable code and gives X25519 +18%. Where the time
goes (a timing loop over the `P256A` twin's routines, release build): a Montgomery
multiplication 11.8 ns, a squaring 10.6 ns, a modular addition 5.5 ns (latencies, each feeding
the next), a Jacobian doubling 70 ns, an addition 122 ns, a mixed addition 84 ns, an inversion
1.66 µs, the variable-base multiplication 26.4 µs. The inversion was the portable part worth
moving: safegcd's divsteps went through `ct::mask` (a `black_box` round trip through memory per
condition). This pass:

- **Divsteps in assembly** (`hw_aarch64::divsteps_59`, the x86_64 twin's loop with masks from
  `ASR` and `SBFX`): inversion 1.66 → 1.26 µs. Signing has two inversions (the nonce modulo `n`,
  `Z` modulo `p`), key generation and ECDH one: sign +9%, key generation +3.5%, ECDH +1.6%.
- **OpenSSL's point formulas** for the twin's addition (12M + 4S) and mixed addition (8M + 3S),
  as on x86_64: seven modular additions and subtractions instead of fourteen. Addition
  122 → 108 ns, mixed addition 84 → 80 ns (within the noise of this machine).
- **Whole-point assembly: not done.** A doubling takes 70 ns where its critical path (four
  dependent multiplications and three additions) is about 64 ns at the measured latencies: the
  out-of-order core already overlaps the independent operations, and with 31 general registers
  the compiler keeps the operands of the inline `asm!` field operations in registers, so a
  whole-point block could only drop the moves between them. The x86_64 gain came from spills
  with 16 registers, which aarch64 does not have. A faster doubling would need a shorter field
  multiplication (about 50 cycles of latency; an interleaved reduction), not point-level assembly.

`tools/ct-dudect` on this machine: see docs/constant-time.md.

#### RSA (`--example pk_bench rsa`, `tls-bench handshakes`, CPU 2)

Three alternating rounds of the previous code (`7f5c483a`, with this pass's benchmark files) and
this pass, against ring 0.17 / rustls 0.23 in the same run, on a quiet host (load average 1–2,
the services stopped by `quiet.sh`); the rounds agreed within 1%. "verify + key parse" builds
the public key from `(n, e)` before each verification, as ring's `RsaPublicKeyComponents` does on
every call: the cost of checking one certificate signature.

| op/s (quiet host) | before | after | ring / rustls | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|
| RSA-2048 PKCS#1 sign | 1,192 | 3,910 | 2,429 | 0.49 | 1.61 |
| RSA-2048 PKCS#1 verify | 39,250 | 79,970 | 65,600 | 0.60 | 1.22 |
| RSA-2048 verify + key parse | 5,850 | 67,090 | 65,600 | 0.09 | 1.02 |
| RSA-3072 PKCS#1 sign | 371 | 1,455 | 787 | 0.47 | 1.85 |
| RSA-3072 PKCS#1 verify | 18,300 | 33,440 | 30,550 | 0.60 | 1.10 |
| RSA-3072 verify + key parse | 2,627 | 28,980 | 30,550 | 0.09 | 0.95 |
| RSA-4096 PKCS#1 sign | 156 | 755 | 345 | 0.45 | 2.19 |
| RSA-4096 PKCS#1 verify | 10,110 | 19,090 | 17,540 | 0.58 | 1.09 |
| RSA-4096 verify + key parse | 1,400 | 16,560 | 17,540 | 0.08 | 0.95 |
| TLS 1.3 full handshakes/s, X25519, RSA-2048 certificate | 775 | 2,586 | 1,800 | 0.43 | 1.44 |

Signing runs on AVX-512 IFMA here (`ifma` in the detected paths): radix-2⁵² almost Montgomery
multiplication, 416 cycles for 1,024 bits (84 ns at 4.93 GHz), 787 for 1,536 and 1,210 for 2,048;
a whole 1,024-bit CRT half-exponentiation takes 113 µs. Verification and CPUs without IFMA use
the BMI2 + ADX assembly: a 1,024-bit Montgomery multiplication 805 cycles (portable 1,245),
squaring 681 (portable 1,486), 2,048-bit 3,045 and 2,700 cycles. Measured on that path alone
(before the IFMA code), RSA-2048 signing was 0.99× ring and verification 1.20×. The MULX row
pattern (`mulx`, `adcx`, `adox` per product) runs at about 1.5 cycles per product on Zen 4 in a
probe, so the multiplication is near what this instruction mix allows. With
`ONLY_CRYPTO_PORTABLE=1` signing is 0.50× ring and verification 0.59× (the key parse no longer
dominates: 0.53×). Tried and dropped by measurement: computing the next reduction factor from a
register instead of memory (no change), `zmm` accumulators for 32 digits (slower than `ymm` with
the operands in registers), a second accumulator for the `m` products and splitting each step
into low/high halves at 32 and 40 digits (no gain: the shared multiply/shuffle pipes are the
limit), memory operands for the IFMA instructions (half the throughput on Zen 4). The two CRT
halves were later interleaved in one loop (next subsection): signing 1.61× → 2.20× ring.

#### RSA: both CRT halves in one IFMA loop (`--example pk_bench rsa`, `tls-bench handshakes`, CPU 2)

The two half-exponentiations of a signature (mod p and mod q) now run in lockstep through one
`asm!` loop (`amm20_x2` / `amm32_x2` / `amm40_x2`): each digit step does the scalar part and the
vector part of half 1, then those of half 2. One AMM alone waited on its serial chain (digit 0 →
`yᵢ = digit₀·k0` → the next digit 0, about 21 cycles per step at 20 digits for 14 cycles of
vector work); the two halves' chains are independent, so the core overlaps them. Each half keeps
its accumulator, `a` and `m` in registers (all 32 vector registers at 20 and 40 digits; `zmm` at
32 digits, where `ymm` does not fit); the zero register gave way to a zero-masked shift, the
reduction factors are read from memory and the output pointer waits in `k7`. Per half (timing
probe `bignum::ifma::tests::timing`, CPU 2):

| modulus | AMM before | AMM interleaved | exponentiation before | interleaved |
|---|---:|---:|---:|---:|
| 1,024 bits (20 digits) | 83.4 ns | 62.2 ns | 114.0 µs | 83.2 µs (1.37×) |
| 1,536 bits (32 digits) | 162.5 ns | 132.5 ns | 323.5 µs | 272.4 µs (1.19×) |
| 2,048 bits (40 digits) | 246.5 ns | 205.3 ns | 632 µs | 541 µs (1.17×) |

Three alternating rounds of `a965d26c` and this change on a quiet host (RSA-4096: four rounds of
2 s, the 1 s rounds after the 3072-bit row were unsteady); the rounds agreed within 0.5%:

| op/s | before | after | ring / rustls | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|
| RSA-2048 PKCS#1 sign | 3,867 | 5,231 | 2,372 | 1.63 | 2.20 |
| RSA-3072 PKCS#1 sign | 1,436 | 1,691 | 770 | 1.87 | 2.19 |
| RSA-4096 PKCS#1 sign | 753 | 870 | 341 | 2.21 | 2.55 |
| TLS 1.3 full handshakes/s, X25519, RSA-2048 certificate | 2,559 | 2,976 | 1,760 | 1.45 | 1.69 |

Verification (public exponent, one modulus) is unchanged. Tried and left out: issuing both scalar
parts before both vector parts (it needs a second pair of broadcast registers, and the loop
already runs at about 15 cycles per half-step against roughly 13.5 cycles of multiply, shift and
broadcast work on the two shared pipes). Verification moved to IFMA later (next subsection).

#### RSA verification on IFMA (`--example pk_bench rsa`, `tls-bench handshakes`, CPU 2)

The public operation `sᵉ mod n` (verification, and the check of each signature before it is
released) now runs on AVX-512 IFMA as well, as left-to-right square-and-multiply over `e`: two new
single-modulus AMMs for public moduli, `amm64` (3,072 bits: eight `zmm` registers per number,
60 digit steps over operands padded to 64 digits) and `amm80` (4,096 bits: ten registers per
number, 30 of the 32, so the top lane shifts in zero by masking, the output pointer waits in `k7`,
the constants are set after the loop in registers of `m`, and the final carry ripple runs over
80 lanes in two words); 2,048 bits use the existing `amm40`. Into the `2^(52D)` form with one
AMM by `R'² mod n` (from `R² mod n` by a short division) and out of it with the last product, by
`s` instead of `s·R'`: 18 AMMs for `e = 65537`. The 64-bit path (no IFMA, and other sizes) does
the same in its own Montgomery form, 16 squarings and two multiplications instead of 17 + 2
plus the two conversions (one squaring was of 1). Building the key got cheaper too: `R mod n` and
`R² mod n` both from the long division (no Montgomery multiplication), whose quotient digits now
come from a precomputed reciprocal of the divisor's top limb (Möller–Granlund) with 64-bit
products instead of a 128-bit division and 128-bit products per digit; the byte conversions work
a limb at a time. Per operation (timing probe `bignum::ifma::tests::timing`, CPU 2):

| modulus | AMM | `s^65537 mod n` |
|---|---:|---:|
| 2,048 bits (40 digits) | 246 ns | 4.9 µs |
| 3,072 bits (60 of 64 digits) | 497 ns | 10.1 µs |
| 4,096 bits (80 digits) | 789 ns | 15.3 µs |

(3,072 bits ran 524 ns per AMM with all 64 steps. A whole verification on BMI2 + ADX took 12.5,
29.8 and 52.2 µs before.) Three alternating rounds of `62ea6318` and
this change on a quiet host, ring / rustls in the same runs; the rounds agreed within 1%:

| op/s | before | after | ring / rustls | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|
| RSA-2048 PKCS#1 verify | 80,005 | 200,748 | 65,392 | 1.22 | 3.07 |
| RSA-2048 verify + key parse | 66,674 | 153,716 | 65,392 | 1.02 | 2.35 |
| RSA-3072 PKCS#1 verify | 33,541 | 100,719 | 30,486 | 1.10 | 3.30 |
| RSA-3072 verify + key parse | 29,116 | 80,470 | 30,486 | 0.95 | 2.64 |
| RSA-4096 PKCS#1 verify | 19,170 | 64,911 | 17,534 | 1.09 | 3.70 |
| RSA-4096 verify + key parse | 16,707 | 50,850 | 17,534 | 0.95 | 2.90 |
| RSA-2048 PKCS#1 sign | 5,285 | 5,511 | 2,434 | 2.17 | 2.26 |
| RSA-3072 PKCS#1 sign | 1,712 | 1,766 | 789 | 2.17 | 2.24 |
| RSA-4096 PKCS#1 sign | 869 | 899 | 346 | 2.52 | 2.60 |
| TLS 1.3 full handshakes/s, X25519, RSA-2048 certificate | 3,002 | 3,270 | 1,802 | 1.67 | 1.82 |

Verification is 2.51× / 3.00× / 3.39× the previous code, 2.31× / 2.76× / 3.04× with the key
parse; signing gains 2–4% from the cheaper check. With `ONLY_CRYPTO_PORTABLE=1` (two alternating
rounds): verify 0.59× → 0.70× ring at 2,048 bits (0.60× → 0.70×, 0.57× → 0.69× at 3,072 and
4,096), with the key parse 0.53× → 0.66× (0.53× → 0.67×, 0.52× → 0.65×). The key parse is now
about a quarter of "verify + key parse" at 2,048 bits (1.8 µs: the division for `R²`, the copies,
the allocations); the AMMs themselves are latency-bound on one chain here, with no second
exponentiation to interleave.

#### Ed448, X448 and DSA (`--example pk_bench 448`, CPU 2)

2026-11-19, ADR-046, the same host through `quiet.sh` (load average 4–10 from processes outside
the benchmark lock during the runs; two consistent runs of three, the third 10–25% lower).
ring has none of these, so the ratio column is against our own Ed25519 / X25519:

| Operation (op/s) | only-crypto | vs |
|---|---:|---|
| Ed448 sign | 3,520 | 0.04× Ed25519 sign |
| Ed448 verify | 2,630 | 0.11× Ed25519 verify |
| X448 agree | 3,515 | 0.10× X25519 |
| DSA 2048/256 verify (SHA-256) | 1,970 | 0.08× Ed25519 verify |

Ed448 and X448 are portable constant-time code on the generic seven-limb Montgomery field (no
assembly, no precomputed base-point table); they are not on any default fast path (TLS offers
x448 last).

#### P-521 (`--example pk_bench 521`, `tls-bench handshakes 2`, CPU 2)

2026-11-19, ADR-049, the same host through `quiet.sh` (load from processes outside the benchmark
lock during the run: the handshake rounds below vary by up to 30%). ring has no P-521, so the
comparison is OpenSSL 3.0.13 (`openssl speed ecdsap521 ecdhp521`, Ubuntu's build, which has
OpenSSL's 64-bit P-521 code) on the same core; P-521 has no hardware path here, so the default
and `ONLY_CRYPTO_PORTABLE=1` runs are the same code (best of the two):

| Operation (op/s) | only-crypto | OpenSSL 3.0.13 | only / OpenSSL |
|---|---:|---:|---:|
| P-521 ECDSA sign (SHA-512) | 5,651 | 5,190 | 1.09 |
| P-521 ECDSA verify | 2,562 | 2,441 | 1.05 |
| P-521 ECDH | 2,700 | 3,224 | 0.84 |
| P-521 key generation (`d·G`) | 10,903 | – | – |

On an Apple M-series core (not quiet) against Homebrew's OpenSSL 4.1: sign about 1.07×, verify
0.85–0.95×, ECDH about 0.54×.

Handshakes with the default configurations (the ClientHello now lists secp521r1, 2 bytes more),
before = `main` at `436b47e7`, three alternated rounds; best round of each side, as the load
outside the lock made single rounds unreliable:

| case | before | after | after / before |
|---|---:|---:|---:|
| X25519 | 5,391 | 5,411 | 1.00 |
| secp256r1 | 5,310 | 5,421 | 1.02 |
| X25519, RSA-2048 certificate | 3,169 | 3,253 | 1.03 |

#### AES-GCM by message size (`--example gcm-sizes`, CPU 2)

MB/s of message bytes with 13 bytes of AAD, median of three alternating rounds; before = `main`
at `a1cc9b49` (AES-NI + PCLMULQDQ, eight blocks per reduction), after = the VAES + VPCLMULQDQ +
AVX-512 kernel (sixteen blocks per loop iteration and reduction, AES rounds interleaved with the
GHASH of the previous group) with the fused short tail. Open copies the sealed message into the
working buffer first on both sides. ring 0.17 runs its VAES/AVX2 kernel on this CPU.

| AES-128-GCM | before | after | ring | after / ring |
|---|---:|---:|---:|---:|
| seal 64 B | 611 | 1,185 | 1,073 | 1.10 |
| seal 1 KiB | 4,539 | 7,623 | 7,809 | 0.98 |
| seal 1400 B | 4,249 | 8,163 | 7,377 | 1.11 |
| seal 16 KiB | 6,455 | 15,048 | 12,689 | 1.19 |
| seal 64 KiB | 6,540 | 15,862 | 12,845 | 1.23 |
| open 64 B | 532 | 1,120 | 928 | 1.21 |
| open 1 KiB | 4,034 | 7,178 | 7,053 | 1.02 |
| open 1400 B | 3,978 | 7,539 | 7,133 | 1.06 |
| open 16 KiB | 5,671 | 13,296 | 11,035 | 1.20 |
| open 64 KiB | 5,515 | 12,792 | 11,230 | 1.14 |

| AES-256-GCM | before | after | ring | after / ring |
|---|---:|---:|---:|---:|
| seal 64 B | 595 | 1,137 | 1,076 | 1.06 |
| seal 1 KiB | 4,135 | 6,932 | 7,240 | 0.96 |
| seal 1400 B | 4,008 | 7,055 | 6,599 | 1.07 |
| seal 16 KiB | 5,737 | 13,142 | 11,370 | 1.16 |
| seal 64 KiB | 5,858 | 13,819 | 11,623 | 1.19 |
| open 64 B | 575 | 1,059 | 926 | 1.14 |
| open 1 KiB | 3,416 | 6,596 | 6,591 | 1.00 |
| open 1400 B | 3,320 | 6,533 | 6,642 | 0.98 |
| open 16 KiB | 4,552 | 11,607 | 10,131 | 1.15 |
| open 64 KiB | 4,555 | 11,632 | 10,452 | 1.11 |

Width: on Zen 4 (512-bit operations issued as two 256-bit halves) the same kernel on 256-bit
registers (eight blocks per iteration) was slower at every size, so only the 512-bit kernel
ships: AES-128 seal 16 KiB 15,100 vs 13,100 MB/s, 1 KiB 7,600 vs 6,800, open 16 KiB 13,150 vs
11,775. Short messages gained from the tail, not the width: the last bytes of a message and `J0`
go through AES in one call and a short AAD, the tail ciphertext and the length block through
one GHASH call (it was three GHASH calls and a separate CTR pass), which doubled 64-byte
messages for every CPU with AES and carry-less multiplication instructions.

What was left for AES-GCM after this pass (1 KiB to 1.4 KiB at 0.96–1.11× ring, the 128-bit
path on CPUs with VAES but no AVX-512, the TLS record zero-fill) is the next subsection. Other
gaps: ChaCha20-Poly1305 below 1.4 KiB
was at 0.82–0.96× ring (now 0.98× for a 64-byte seal, 0.85× open, above ring from 1 KiB:
"ChaCha20-Poly1305 short messages" below) and CPUs without AVX-512 / IFMA ran the AVX2 ChaCha20 with a scalar
Poly1305 (now an AVX2 Poly1305: "Poly1305 on AVX2" below); P-256
ECDH is at 1.12× ring (a doubling ~348 cycles, about 44 per product whatever their order);
Ed25519 verification is portable; without IFMA RSA-2048 signing is at parity with ring; SHA-512 and MD5 are portable.

#### AES-GCM: VAES-AVX2 kernel, masked tails, record zero-fill (`--example gcm-sizes`, `tls-bench records`, CPU 2)

Median of five alternating rounds of the previous code (`main` at `dbc7563f`) and this pass,
ring measured in the same runs, 13 bytes of AAD. Another workload kept the load average at
1.0–1.9 (CPU 2 itself was free); the ratios come from the same runs. "AVX2 kernel" is this
pass's VAES-AVX2 kernel forced on this Zen 4 (`AesGcm::with_cipher_avx2`): it stands in for CPUs
with VAES but no AVX-512 (Zen 3, Alder Lake / Raptor Lake), which were not available to measure;
"128-bit" is the AES-NI + PCLMULQDQ kernel those CPUs ran before.

| AES-128-GCM, MB/s | before | after | ring | after / ring | before / ring | AVX2 kernel | 128-bit | AVX2 / 128-bit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| seal 64 B | 1,204 | 1,383 | 1,075 | 1.29 | 1.11 | 1,198 | 1,192 | 1.01 |
| seal 1 KiB | 7,902 | 10,433 | 7,933 | 1.32 | 1.00 | 6,846 | 4,369 | 1.57 |
| seal 1400 B | 8,356 | 10,632 | 7,271 | 1.46 | 1.10 | 7,533 | 4,770 | 1.58 |
| seal 16 KiB | 15,273 | 15,610 | 13,435 | 1.16 | 1.18 | 12,671 | 6,310 | 2.01 |
| seal 64 KiB | 16,071 | 16,037 | 13,717 | 1.17 | 1.23 | 12,546 | 6,461 | 1.94 |
| open 64 B | 1,103 | 1,336 | 927 | 1.44 | 1.19 | 1,089 | 1,111 | 0.98 |
| open 1 KiB | 7,240 | 8,878 | 7,283 | 1.22 | 1.04 | 6,256 | 4,040 | 1.55 |
| open 1400 B | 7,814 | 9,515 | 7,416 | 1.28 | 1.05 | 7,061 | 4,325 | 1.63 |
| open 16 KiB | 13,588 | 13,784 | 11,727 | 1.18 | 1.20 | 11,112 | 5,589 | 1.99 |
| open 64 KiB | 13,109 | 13,031 | 11,692 | 1.11 | 1.13 | 11,082 | 5,586 | 1.98 |

| AES-256-GCM, MB/s | before | after | ring | after / ring | before / ring | AVX2 kernel | 128-bit | AVX2 / 128-bit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| seal 64 B | 1,137 | 1,250 | 1,076 | 1.16 | 1.06 | 1,141 | 1,128 | 1.01 |
| seal 1 KiB | 7,152 | 9,447 | 7,335 | 1.29 | 0.98 | 6,323 | 3,847 | 1.64 |
| seal 1400 B | 7,106 | 9,559 | 6,865 | 1.39 | 1.08 | 6,654 | 4,124 | 1.61 |
| seal 16 KiB | 13,167 | 13,652 | 11,545 | 1.18 | 1.11 | 11,795 | 5,712 | 2.06 |
| seal 64 KiB | 13,821 | 13,983 | 11,813 | 1.18 | 1.13 | 11,602 | 5,881 | 1.97 |
| open 64 B | 1,056 | 1,335 | 917 | 1.46 | 1.15 | 1,047 | 1,036 | 1.01 |
| open 1 KiB | 6,665 | 8,543 | 6,461 | 1.32 | 0.97 | 6,119 | 3,386 | 1.81 |
| open 1400 B | 7,057 | 8,700 | 6,862 | 1.27 | 1.04 | 6,557 | 3,610 | 1.82 |
| open 16 KiB | 12,004 | 12,104 | 10,427 | 1.16 | 1.13 | 10,509 | 4,473 | 2.35 |
| open 64 KiB | 11,490 | 11,584 | 10,019 | 1.16 | 1.12 | 10,202 | 4,478 | 2.28 |

TLS 1.3 records (seal + open, same rounds; rustls + ring in the same runs): AES-128-GCM 1 KiB
2,721 → 2,948 MB/s (1.51× → 1.58×), 16 KiB 6,555 → 6,707 (1.56× → 1.60×), 64 KiB 6,457 → 6,493;
AES-256-GCM 1 KiB 2,519 → 2,737 (1.42× → 1.55×), 16 KiB 5,930 → 5,976 (1.56×); ChaCha20-Poly1305
unchanged (918, 2,157, 2,129).

What changed:

- **The whole message in the AVX-512 kernel.** An AAD of up to 256 bytes is hashed inside the
  kernel; the last partial group (1 to 255 bytes) is loaded and stored under AVX-512 byte masks
  (k1–k4; masked-off bytes are neither read nor written) and hashed with `Hⁿ … H¹`, taken by a
  pointer into a power table padded with sixteen zero entries so the four vector loads never
  leave it; the length block and `E(J0)` (computed on one lane at the start, overlapping the
  first group) give the tag in the same call. A message under 256 bytes whose AAD, data and
  length block fit in sixteen blocks takes a short path: all of them are multiplied by
  `Hᵀ … H¹` and reduced once, the AAD and (when opening) the ciphertext products overlapping the
  AES rounds, with one vector each when both are at most 64 bytes. The first version without the
  short path lost 7% at 64 B (three dependent reductions: AAD, data, length block) and gained the
  same 32% at 1 KiB; the short path took 64 B from 1,112 to 1,383 MB/s.
- **VAES-AVX2 kernel** for CPUs without AVX-512, selected when CPUID reports VAES +
  VPCLMULQDQ + AVX2 with the OS saving the YMM state but no AVX-512: sixteen blocks per
  iteration in eight ymm registers, the AES rounds interleaved with the GHASH of the previous
  group (sealing) or the same group (opening), one reduction per sixteen blocks. VEX has only
  sixteen vector registers, so the round keys are broadcast from memory each round and the
  constants are memory operands. Eight blocks per iteration (four ymm states) was slower: 16 KiB
  seal 11,540 vs 12,660 MB/s, 1 KiB 6,530 vs 6,890, open within 1% (four independent AES states
  do not cover the latency of two AES pipes). It handles whole 256-byte groups; the rest of a
  message goes through the 128-bit path. Against ring's own VAES-AVX2 code on this host it is at
  0.86× (seal 1 KiB) to 1.11× (seal 64 B), 0.94× at 16 KiB.
- **TLS record zero-fill: kept at the time, removed since** (an `unsafe` step in only-crypto,
  see "TLS record zero-fill removed" below). Measured in one run (three alternating rounds, AES-128-GCM,
  seal + open MB/s): the current code (zero-fill, then the AEAD out of place) 16 KiB 6,620 / 6,675,
  copying the plaintext into the record and sealing in place 6,256 / 6,259 (−6%; 64 KiB −8%,
  1 KiB −2%), and as a reference only, not committed, no zero-fill through `unsafe` `set_len`
  7,297 / 7,313 (+10%; 64 KiB +8%, 1 KiB +4%). A record-layer buffer reused across records
  would trade the memset for a memcpy, the cost of the copy variant. With the caller's `Vec<u8>`
  as output and `#![forbid(unsafe_code)]` in only-tls, every safe variant writes the output
  twice, so the zero-fill (the cheaper second write) stays; removing it needs the `unsafe` step.
  ChaCha20-Poly1305 1 KiB records were 7% faster with the copy and in-place seal (the ChaCha
  out-of-place path costs more on short messages), 16–64 KiB the same or slower; not changed.

#### AES-GCM: the whole message on the VAES-AVX2 kernel (`--example gcm-sizes`, forced AVX2 key, CPU 2)

2026-11-19, three alternating rounds of `main` (`436b47e7`) and this pass through `quiet.sh`,
the VAES-AVX2 kernel forced on the Zen 4 (`AesGcm::with_cipher_avx2`: it stands in for Zen 3 and
Alder Lake / Raptor Lake, which have VAES but no AVX-512; no such host was reachable), 13 bytes
of AAD. The host was busy (load average 8–11 from other workloads, CPU 2 itself free) and
absolute MB/s moved by up to 40% between runs of the same binary, so the table gives the ratios
measured within one run, medians of the three rounds: the AVX2 kernel against the 128-bit
AES-NI + PCLMULQDQ kernel (what those CPUs ran before the AVX2 kernel existed) and against ring.

| AES-128-GCM | AVX2 / 128-bit before | after | AVX2 / ring before | after |
|---|---:|---:|---:|---:|
| seal 64 B | 1.01 | 1.12 | 0.98 | 1.03 |
| seal 200 B | 0.99 | 1.84 | 0.90 | 1.66 |
| seal 1 KiB | 1.47 | 1.81 | 0.92 | 1.05 |
| seal 1400 B | 1.50 | 1.82 | 0.89 | 1.20 |
| seal 4000 B | 1.73 | 1.90 | 0.92 | 1.01 |
| seal 16 KiB | 1.95 | 1.99 | 1.01 | 1.02 |
| open 64 B | 1.00 | 1.20 | 1.21 | 1.23 |
| open 200 B | 1.00 | 1.90 | 0.83 | 1.58 |
| open 1 KiB | 1.56 | 1.87 | 1.00 | 1.03 |
| open 1400 B | 1.57 | 1.94 | 0.90 | 1.20 |
| open 4000 B | 1.74 | 1.93 | 0.91 | 1.00 |
| open 16 KiB | 1.93 | 1.96 | 1.07 | 1.08 |

| AES-256-GCM | AVX2 / 128-bit before | after | AVX2 / ring before | after |
|---|---:|---:|---:|---:|
| seal 64 B | 0.91 | 1.13 | 0.88 | 0.99 |
| seal 200 B | 0.98 | 1.86 | 0.91 | 1.70 |
| seal 1 KiB | 1.51 | 1.89 | 0.88 | 1.13 |
| seal 1400 B | 1.70 | 1.89 | 1.23 | 1.25 |
| seal 4000 B | 1.75 | 2.01 | 0.95 | 1.08 |
| seal 16 KiB | 1.98 | 2.02 | 1.03 | 1.06 |
| open 64 B | 1.00 | 1.14 | 1.13 | 1.11 |
| open 200 B | 1.00 | 1.89 | 0.83 | 1.57 |
| open 1 KiB | 1.75 | 2.12 | 0.90 | 1.12 |
| open 1400 B | 1.69 | 2.09 | 0.88 | 1.14 |
| open 4000 B | 1.91 | 2.12 | 0.94 | 1.05 |
| open 16 KiB | 2.13 | 2.19 | 1.09 | 1.11 |

The AVX2 kernel used to take whole 256-byte groups only: the AAD was hashed before it, the rest
of the message (up to 255 bytes) ran on the 128-bit path, and the length block and `E(J0)` were
a third step, so a message under 256 bytes never reached it (ratio 1.00) and a 1 KiB message
paid three dependent GHASH reductions around it. Now one call per message (two when the TLS
record layer's input is split between two buffers): `E(J0)` first (one block, overlapping what
follows), the AAD (up to 256 bytes) in a GHASH pass before the groups, the groups, then the tail
and the length block. AVX2 has no byte masks, so the tail, the AAD before it and the length block
after it are copied into a zero-padded 544-byte stack buffer; the tail is encrypted in place on
four ymm vectors (up to 128 bytes) or eight, the keystream ANDed with 256 bytes of a constant
`0xff…ff 00…00` table from offset `256 - t` so the padding and the length block stay, and one
GHASH pass (up to sixteen blocks per reduction, from the power table's entry `16 - m`, the vector
past the last block meeting its zero entries) hashes the AAD (when there were no groups), the
tail and the length block. Opening hashes the buffer before decrypting it in place. The first
version (always eight vectors for the tail, a second buffer for the opened tail) measured
64 B at 1.05–1.09× the 128-bit kernel; four vectors for short tails and in-place opening took it
to 1.12–1.20×. Not tried: `vpmaskmovd` loads and stores straight from the message (dword
granularity, so a scalar remainder too; masked stores are slow on several AMD cores), and 128-bit VAES lanes for the tail (the stack buffer costs two copies of at most 255
bytes, a few nanoseconds). The AVX-512 kernel is unchanged.

#### ChaCha20-Poly1305 by message size (`--example chacha-sizes`, `tls-bench records`, CPU 2)

Median of five alternating rounds of the previous code (`main` at `7724cd2a`) and this pass,
ring measured in the same runs (13 bytes of AAD; open copies the sealed message into the
working buffer first). Another workload kept the load average at 1.2–2.6 during the window
(CPU 2 itself was free); the ratios come from the same runs. Hardware paths: AVX-512 and IFMA.

| MB/s | before | after | AVX2 path | portable | ring | after / ring | after / before |
|---|---:|---:|---:|---:|---:|---:|---:|
| seal 64 B | 283 | 412 | 300 | 300 | 498 | 0.83 | 1.46 |
| seal 1 KiB | 1,454 | 2,322 | 1,639 | 619 | 2,472 | 0.94 | 1.60 |
| seal 1400 B | 1,070 | 2,541 | 1,981 | 624 | 2,644 | 0.96 | 2.37 |
| seal 16 KiB | 1,752 | 4,597 | 2,264 | 661 | 3,536 | 1.30 | 2.62 |
| seal 64 KiB | 1,768 | 4,863 | 2,308 | 663 | 3,560 | 1.37 | 2.75 |
| open 64 B | 281 | 396 | 291 | 291 | 481 | 0.82 | 1.41 |
| open 1 KiB | 1,421 | 2,317 | 1,609 | 613 | 2,474 | 0.94 | 1.63 |
| open 1400 B | 1,062 | 2,501 | 1,937 | 618 | 2,637 | 0.95 | 2.35 |
| open 16 KiB | 1,698 | 4,270 | 2,173 | 650 | 3,353 | 1.27 | 2.51 |
| open 64 KiB | 1,709 | 4,558 | 2,213 | 655 | 3,356 | 1.36 | 2.67 |
| ChaCha20 alone, 16 KiB | 4,082 | 7,071 | | | | | 1.73 |
| Poly1305 alone, 16 KiB | 3,118 | 15,411 | | | | | 4.94 |

TLS 1.3 records with TLS_CHACHA20_POLY1305_SHA256 (seal + open, median of three alternating
rounds): 1 KiB 581 → 931 MB/s (rustls + ring 913, 0.64× → 1.02×), 16 KiB 828 → 2,141 (1,511,
0.55× → 1.42×), 64 KiB 818 → 2,124 (1,529, 0.53× → 1.39×).

What changed: ChaCha20 runs sixteen blocks per iteration in zmm registers (`vprold` rotations,
everything in the 32 vector registers), the rest of a message in one more group of sixteen,
eight (ymm) or four (xmm) blocks; the Poly1305 key block and the first three message blocks come
from one four-block call. Poly1305 absorbs eight blocks per step on AVX-512 IFMA (44-bit limbs,
`vpmadd52luq`/`vpmadd52huq`, lane `i` multiplied by `r⁸` per step and by `r⁸⁻ⁱ` at the end)
for runs of 256 bytes and more; shorter runs and CPUs without IFMA use a radix-2⁶⁴ scalar
loop (the 44-bit two-block loop it replaced was slower at every size: the AVX2 path above is
1.29–1.31× the previous code at 16–64 KiB with the same ChaCha20). The powers of `r` are
computed before the cipher pass so their multiplications overlap it. The TLS record layer seals
and opens ChaCha20-Poly1305 records out of place like AES-GCM (no copy first). Width: on Zen 4
the ymm kernel for the bulk was slower than the zmm one (ChaCha20 alone 16 KiB 4,650–5,600 vs
7,070 MB/s); the xmm kernel costs about as much per call as the ymm one, so a rest of more than
four blocks takes the wider group. Not done: stitching ChaCha20 and Poly1305 into one pass. The
two kernels alone bound a sequential seal at about 4,850 MB/s at 16 KiB and the measured 4,600
is within 6% of it; on Zen 4 both use the same vector pipes, and a scalar Poly1305 stitched
into the vector ChaCha20 (ring's design) is slower than IFMA. 64-byte messages are at 0.83×
ring: one four-block xmm call (latency-bound) and the scalar Poly1305 of six blocks.

#### TLS record zero-fill removed (`gcm-sizes`, `chacha-sizes`, `tls-bench records`, CPU 2)

The record layer zero-filled the space for a record's ciphertext (seal) or plaintext (open) in
the output `Vec<u8>` before the AEAD wrote it out of place (above: kept, because every safe
alternative wrote the output twice). only-crypto now has hidden `encrypt_append` /
`decrypt_append` for AES-GCM and ChaCha20-Poly1305 that write straight into the vector's spare
capacity: the vector kernels through raw pointers they already took, the rest (the bytes after
the kernels' whole groups, the portable paths, the ChaCha20 head blocks) with
`MaybeUninit::write`, and the vector grows only once every byte holds a value (`only_crypto::fill`,
docs/unsafe-review.md; Miri-checked on the portable paths). A failed open appends nothing and
zeroes what it wrote. only-tls keeps `#![forbid(unsafe_code)]`.

Same-run A/B on this host, median of five alternating rounds of the previous code (`main` at
`f34c79e3`) and this change (both with `taskset -c 2`, `quiet.sh`), rustls 0.23 + ring in the
same runs. TLS 1.3 records, seal + open MB/s:

| Suite | Size | before | after | after / before | rustls + ring | after / rustls |
|---|---|---:|---:|---:|---:|---:|
| AES-128-GCM | 1 KiB | 2,924 | 3,168 | +8.3% | 1,810 | 1.75 |
| AES-128-GCM | 16 KiB | 6,518 | 7,062 | +8.3% | 4,116 | 1.72 |
| AES-128-GCM | 64 KiB | 6,435 | 6,876 | +6.9% | 4,156 ² | – |
| AES-256-GCM | 1 KiB | 2,688 | 2,906 | +8.1% | 1,692 | 1.72 |
| AES-256-GCM | 16 KiB | 5,781 | 6,283 | +8.7% | 3,754 | 1.67 |
| AES-256-GCM | 64 KiB | 5,695 | 6,119 | +7.4% | 3,892 ² | – |
| ChaCha20-Poly1305 | 1 KiB | 915 | 974 | +6.4% | 904 | 1.08 |
| ChaCha20-Poly1305 | 16 KiB | 2,146 | 2,216 | +3.3% | 1,497 | 1.48 |
| ChaCha20-Poly1305 | 64 KiB | 2,130 | 2,206 | +3.6% | 1,519 | 1.45 |

The AEAD alone, out of place as the record layer runs it (`--example gcm-sizes` /
`chacha-sizes`, same runs, MB/s): `from` zero-fills the vector first (the old record path),
`append` writes into its spare capacity.

| AEAD (kernel) | Size | seal from | seal append | open from | open append |
|---|---|---:|---:|---:|---:|
| AES-128-GCM (VAES-AVX-512) | 64 B | 1,223 | 1,266 (+3.5%) | 1,180 | 1,204 (+2.0%) |
| AES-128-GCM (VAES-AVX-512) | 1 KiB | 8,964 | 9,877 (+10.2%) | 8,747 | 9,637 (+10.2%) |
| AES-128-GCM (VAES-AVX-512) | 16 KiB | 14,211 | 15,657 (+10.2%) | 14,172 | 15,705 (+10.8%) |
| AES-128-GCM (VAES-AVX-512) | 64 KiB | 14,548 | 16,171 (+11.2%) | 14,603 | 16,247 (+11.3%) |
| AES-128-GCM (VAES-AVX2) | 16 KiB | 10,706 | 11,489 (+7.3%) | 11,131 | 11,862 (+6.6%) |
| AES-128-GCM (VAES-AVX2) | 64 KiB | 10,866 | 12,602 (+16.0%) | 11,687 | 12,639 (+8.1%) |
| AES-128-GCM (AES-NI + PCLMULQDQ) | 16 KiB | 5,709 | 5,916 (+3.6%) | 5,288 | 5,455 (+3.2%) |
| AES-256-GCM (VAES-AVX-512) | 16 KiB | 12,356 | 13,402 (+8.5%) | 12,380 | 13,524 (+9.2%) |
| ChaCha20-Poly1305 (AVX-512 / IFMA) | 64 B | 394 | 406 (+3.0%) | 383 | 395 (+3.1%) |
| ChaCha20-Poly1305 (AVX-512 / IFMA) | 1 KiB | 2,387 | 2,430 (+1.8%) | 2,367 | 2,441 (+3.1%) |
| ChaCha20-Poly1305 (AVX-512 / IFMA) | 16 KiB | 4,481 | 4,610 (+2.9%) | 4,475 | 4,631 (+3.5%) |
| ChaCha20-Poly1305 (AVX2) | 16 KiB | 2,148 | 2,180 (+1.5%) | 2,148 | 2,177 (+1.4%) |
| ChaCha20-Poly1305 (portable) | 16 KiB | 641 | 644 (+0.5%) | 642 | 644 (+0.3%) |

The ChaCha20-Poly1305 short-record cost of the out-of-place path (the earlier note: copy and
seal in place was faster at 1 KiB) is mostly gone: against a copy into the vector and an
in-place seal, `append` is −1.5% at 64 B (406 vs 412 MB/s), equal at 256 B and 1 KiB and +6% at
16 KiB; `from` was −4.4% at 64 B. In-place AES-GCM and ChaCha20-Poly1305 (the same
`gcm-sizes` / `chacha-sizes` rows of the earlier subsections) moved by −2.2% to +4.7% between
the two builds, within this host's run-to-run spread; an intermediate build without `#[inline]`
on the `Fill` helpers was 4–6% slower on 64-byte in-place messages (128-bit AES-GCM seal,
ChaCha20-Poly1305 open), which the final build does not show.

#### ChaCha20-Poly1305 short messages (`--example chacha-sizes`, `tls-bench records`, CPU 2)

Messages under about 1.4 KiB were below ring (64 B at 0.83×, 1 KiB 0.94–1.00×): a short message
is one latency-bound cipher call plus a scalar Poly1305, and the profile of a 64-byte seal was
62% the four-block xmm call that makes the Poly1305 key and the first three message blocks (about
21 cycles per round: sixteen registers, 48 instructions per round for four blocks). What changed:

- Four blocks run with one row of each block per zmm register (OpenSSL's layout: the column
  round, `vpshufd` turns the diagonals into columns, the diagonal round, back): 15 instructions
  per round instead of 48, with about the same dependency chain. It replaces the xmm kernel for
  the head of a message and for tails of up to four blocks. Kept: the word-sliced ymm (eight
  blocks) and zmm (sixteen) kernels. Two row sets side by side as an eight-block kernel was
  slower than the ymm one (ChaCha20 alone, 512 B: 127 vs 108 ns per call).
- A last partial group goes through the kernel under AVX-512 BW byte masks instead of a zeroed
  1 KiB buffer and two copies. Whole blocks of that group still use plain loads and stores: a
  first version masked every block of the group and lost 5–8% at 16 KiB when the buffer was not
  64-byte aligned (on Zen 4 a masked access that crosses a cache line costs tens of cycles).
- The head of a message is four or eight blocks, whichever leaves the cheaper rest by the
  measured kernel times (about 63 ns for a row group, 83 for a ymm group, 140 for a zmm group):
  256 B and 1400 B take one call fewer.
- The AEAD's Poly1305 absorbs the padded AAD, the ciphertext and the length block directly
  (fixed-size copies for a partial block) instead of going through the streaming buffer: no
  `memcpy` calls for a few bytes.

Median of five alternating rounds of the previous code (`main` at `62ea6318`) and this change,
ring in the same runs, MB/s (AVX-512 + IFMA path; the AVX2 and portable paths moved by 0–3%):

| MB/s | before | after | after / before | ring | before / ring | after / ring |
|---|---:|---:|---:|---:|---:|---:|
| seal 64 B | 408 | 481 | 1.18 | 489 | 0.83 | 0.98 |
| seal 1 KiB | 2,440 | 2,646 | 1.08 | 2,440 | 1.00 | 1.08 |
| seal 1400 B | 2,566 | 3,137 | 1.22 | 2,598 | 0.99 | 1.21 |
| seal 16 KiB | 4,642 | 4,690 | 1.01 | 3,461 | 1.34 | 1.36 |
| open 64 B | 366 | 410 | 1.12 | 482 | 0.76 | 0.85 |
| open 1 KiB | 2,410 | 2,547 | 1.06 | 2,433 | 0.99 | 1.05 |
| open 1400 B | 2,534 | 3,056 | 1.21 | 2,576 | 0.98 | 1.19 |
| open 16 KiB | 4,315 | 4,385 | 1.02 | 3,289 | 1.31 | 1.33 |

Seal by size (`PROFILE_LEN`, three rounds): 192 B +15%, 256 B +47%, 448 B +38%, 512 B +11%,
960 B +19%, 2 KiB +4%. TLS 1.3 records with TLS_CHACHA20_POLY1305_SHA256 (seal + open, three
rounds): 1 KiB 987 → 1,038 MB/s (+5.2%, 1.09× → 1.15× rustls + ring), 16 KiB 2,225 → 2,240, 64 KiB
2,190 → 2,217. Left: opening 64-byte messages (0.85× ring; the tag must be checked before the
plaintext is written, so the cipher and the scalar Poly1305 cannot overlap), and the 512-byte
zeroed head buffer.

#### Poly1305 on AVX2 (`--example chacha-sizes`, the `avx2` key, CPU 2)

CPUs with AVX2 but without AVX-512 IFMA (Zen 2 and 3, most Intel client parts) ran Poly1305 on
the radix-2⁶⁴ scalar loop. Poly1305 now absorbs four blocks per step on AVX2 in radix 2²⁶
(poly1305-donna / OpenSSL's layout: limb `j` of four accumulators per register, 25 `vpmuludq`
per step, every step multiplied by `r⁴` and the last lane by lane by `r⁴, r², r³, r`) for runs
of 512 bytes and more; below that the powers of `r` cost more than the kernel saves (256–448 B
were 3–10% slower with it). Two accumulator sets (eight blocks per step) spilled out of the
sixteen ymm registers and were slower. Writing the differential test found that converting the
summed lanes back to radix 2⁶⁴ needs a second full carry pass (with `r = 1` and all-ones blocks a
carry ripples up to bit 128).

Measured on Zen 4 through the AVX2 key (`ChaCha20Poly1305::new_avx2`: AVX2 ChaCha20 and now AVX2
Poly1305; no host without AVX-512 was available), median of five alternating rounds against
`main`, MB/s: seal 1 KiB 1,654 → 1,767 (+6.8%), 1400 B 1,998 → 2,200 (+10.1%), 16 KiB 2,270 →
2,729 (+20.2%), 64 KiB 2,311 → 2,795 (+20.9%); open 16 KiB 2,190 → 2,617 (+19.5%). The default
path (AVX-512 + IFMA), the portable code and messages under 512 bytes are unchanged.

### Deflate (`only-deflate`, `--example bench` and `--example pmd_echo`, CPU 2)

Against flate2 1.1 with the `zlib-rs` backend (AVX2/BMI2 paths chosen at run time; only-deflate
is `#![forbid(unsafe_code)]` without SIMD); each program run takes the best of several rounds of
≥200 ms per cell, the table the median of 3 runs. Corpora: generated English-like text (4 MB),
JSON lines (4 MB), random bytes (1 MB), the repository's Rust sources concatenated (6.0 MB) and
the host's `libc.so.6` (2.1 MB). Inflate decodes zlib-rs's output of the same level.

| Corpus | Level | Ratio only / zlib-rs | Deflate MB/s only / zlib-rs | Inflate MB/s only / zlib-rs |
|---|---:|---|---|---|
| text | 1 | 2.200 / 2.201 | 549 / 367 | 856 / 995 |
| text | 3 | 3.601 / 3.601 | 202 / 193 | 1,096 / 1,076 |
| text | 6 | 4.058 / 4.062 | 38 / 39 | 1,500 / 1,201 |
| text | 9 | 4.186 / 4.186 | 15 / 14 | 1,280 / 1,215 |
| JSON | 1 | 4.838 / 4.839 | 1,229 / 1,109 | 2,141 / 2,331 |
| JSON | 3 | 7.552 / 7.552 | 452 / 454 | 2,251 / 2,512 |
| JSON | 6 | 7.604 / 7.604 | 208 / 214 | 2,266 / 2,478 |
| JSON | 9 | 7.761 / 7.761 | 121 / 117 | 2,253 / 2,543 |
| random | 1 | 1.000 / 0.948 | 135 / 144 | 526 / 637 |
| random | 6 | 1.000 / 1.000 | 80 / 76 | 34,278 / 36,688 |
| Rust sources | 1 | 2.731 / 2.731 | 486 / 387 | 846 / 889 |
| Rust sources | 3 | 3.833 / 3.833 | 206 / 198 | 959 / 958 |
| Rust sources | 6 | 4.098 / 4.106 | 99 / 100 | 1,030 / 1,013 |
| Rust sources | 9 | 4.151 / 4.151 | 60 / 54 | 1,073 / 1,048 |
| libc.so.6 | 1 | 1.724 / 1.724 | 280 / 250 | 577 / 670 |
| libc.so.6 | 3 | 2.109 / 2.109 | 126 / 123 | 556 / 643 |
| libc.so.6 | 6 | 2.160 / 2.160 | 85 / 84 | 581 / 663 |
| libc.so.6 | 9 | 2.242 / 2.242 | 41 / 29 | 569 / 653 |

Output is never more than 0.2% larger than zlib-rs's in these cells; compression runs at
0.94–1.5× zlib-rs's speed, decompression at 0.83–1.25×. Stored blocks (random data at levels
≥3) inflate at 0.94×: they are copied once, straight into the output, and only their last 32 KiB
into the window (0.42× before, when they went through the window; the random level 6 cell is the
median of five alternating rounds of the old and new binaries, old 15,456 / 36,277).

permessage-deflate echo (client deflate → server inflate → server deflate → client inflate,
level 6, context takeover, JSON-like messages):

| Message | only-deflate (echoes/s) | zlib-rs | ratio | wire bytes (both) |
|---|---:|---:|---:|---:|
| 64 B | 628,894 | 348,873 | 1.80 | 5 |
| 512 B | 80,625 | 79,044 | 1.02 | 80 |
| 4 KiB | 17,166 | 17,147 | 1.00 | 481 |
| 64 KiB | 1,375 | 1,404 | 0.98 | 6,897 |

### Brotli and Zstandard (`only-brotli`, `only-zstd`, `tools/codec-bench`, CPU 2, 2026-11-19)

Against the C reference libraries in the same process: libzstd 1.5.7 (the `zstd` crate, one-shot
calls on reused contexts, content checksum on as in ours) and Google's libbrotli 1.2.1
(`brotlic-sys`, one-shot calls, lgwin 22, decoding into a reused buffer), both built from their
bundled sources (libzstd picks its BMI2 paths at run time and uses its x86-64 assembly Huffman
decoder); only-brotli and only-zstd are `#![forbid(unsafe_code)]`, built for baseline x86-64.
Corpora (`tools/codec-bench/corpus.sh`): the Silesia corpus as one tar (the slowest levels on its
first 20 MB) and typical HTTP payloads: the workspace's `cargo metadata` JSON, the largest rustdoc
page and the search script of only-http's documentation, and two DER certificate chains. Best of
three rounds of ≥300 ms (one call per round on Silesia; level 11 and level 19 compression timed
once). "Decompress" decodes the C library's stream with both decoders. "Before" is the same tool
built against the crates as they were before this pass (`436b47e7`), run right after on the same
host. The host was not idle (load 6 falling to 1 during the run, the "before" columns at the lower
load), so single cells move by about ±10%.

zstd:

| Corpus | Level | Size only / C | Compress MB/s only (before) / C | Decompress MB/s only (before) / C | C / only |
|---|---:|---|---|---|---:|
| Silesia (212 MB) | 1 | 70,907,335 / 73,216,948 | 300 (127) / 571 | 921 (852) / 1,120 | 1.22 |
| Silesia (212 MB) | 3 | 66,565,671 / 66,131,721 | 231 (86) / 360 | 839 (782) / 1,040 | 1.24 |
| Silesia, first 20 MB | 19 | 6,158,589 / 5,723,363 | 7.1 (7.1) / 5.5 | 1,173 (1,029) / 1,624 | 1.39 |
| JSON (657 KB) | 1 | 65,110 / 63,680 | 654 (275) / 1,242 | 3,101 (2,849) / 4,240 | 1.37 |
| JSON (657 KB) | 3 | 61,154 / 60,477 | 614 (203) / 1,073 | 3,034 (2,761) / 4,173 | 1.38 |
| JSON (657 KB) | 19 | 46,888 / 44,269 | 22 (22) / 4.3 | 3,503 (3,273) / 4,825 | 1.38 |
| HTML (45 KB) | 1 | 8,431 / 8,357 | 495 (233) / 1,147 | 2,008 (1,764) / 2,634 | 1.31 |
| HTML (45 KB) | 3 | 7,981 / 7,969 | 430 (175) / 943 | 1,998 (1,758) / 2,638 | 1.32 |
| HTML (45 KB) | 19 | 7,173 / 6,967 | 58 (56) / 3.9 | 1,998 (1,759) / 2,651 | 1.33 |
| JS (92 KB) | 1 | 24,974 / 24,919 | 399 (150) / 809 | 1,512 (1,286) / 2,107 | 1.39 |
| JS (92 KB) | 3 | 23,420 / 23,345 | 342 (108) / 655 | 1,471 (1,271) / 2,041 | 1.39 |
| JS (92 KB) | 19 | 20,726 / 20,102 | 27 (27) / 5.6 | 1,454 (1,252) / 2,012 | 1.38 |
| cert chain (2.7 KB) | 1 | 1,808 / 1,770 | 149 (57) / 386 | 816 (642) / 948 | 1.16 |
| cert chain (2.7 KB) | 3 | 1,791 / 1,770 | 127 (49) / 301 | 1,708 (1,331) / 2,104 | 1.23 |
| cert chain (2.7 KB) | 19 | 1,736 / 1,701 | 52 (37) / 11 | 1,488 (1,172) / 1,873 | 1.26 |
| cert chain (4.1 KB) | 1 | 2,654 / 2,636 | 176 (71) / 458 | 1,997 (1,621) / 2,543 | 1.27 |
| cert chain (4.1 KB) | 3 | 2,617 / 2,589 | 165 (60) / 364 | 1,926 (1,559) / 2,447 | 1.27 |
| cert chain (4.1 KB) | 19 | 2,563 / 2,531 | 50 (42) / 12 | 1,838 (1,487) / 2,323 | 1.26 |

The zstd decompression cells are from the second decoder pass (2026-11-20, quiet host, see below):
only (main at `aca9e988`, the first pass) / C, measured in the same run. Our sizes on Silesia and
the certificate chains are after the literals change below ("zstd literals").

brotli:

| Corpus | Level | Size only / C | Compress MB/s only (before) / C | Decompress MB/s only (aca9e988) / C | C / only |
|---|---:|---|---|---|---:|
| Silesia (212 MB) | 1 | 68,088,477 / 73,455,775 | 117 (111) / 359 | 469 (397) / 585 | 1.25 |
| Silesia (212 MB) | 4 | 63,972,366 / 64,132,974 | 78 (23) / 133 | 565 (489) / 720 | 1.27 |
| Silesia (212 MB) | 5 | 58,932,318 / 59,510,923 | 46 (19) / 89 | 545 (468) / 718 | 1.32 |
| Silesia (212 MB) | 6 | 57,954,494 / 58,432,310 | 36 (14) / 77 | 564 (478) / 744 | 1.32 |
| Silesia, first 20 MB | 11 | 5,599,940 / 5,346,712 | 0.7 (0.7) / 1.0 | 513 (473) / 535 | 1.04 |
| JSON (657 KB) | 1 | 62,442 / 67,165 | 384 (383) / 1,048 | 1,744 (1,318) / 1,877 | 1.08 |
| JSON (657 KB) | 4 | 54,756 / 54,633 | 228 (193) / 324 | 2,186 (1,649) / 2,448 | 1.12 |
| JSON (657 KB) | 5 | 48,018 / 48,884 | 164 (127) / 203 | 2,365 (1,747) / 2,703 | 1.14 |
| JSON (657 KB) | 6 | 47,205 / 47,678 | 138 (110) / 184 | 2,467 (1,788) / 2,877 | 1.17 |
| JSON (657 KB) | 11 | 43,630 / 41,742 | 0.6 (0.6) / 1.3 | 2,296 (1,690) / 2,750 | 1.20 |
| HTML (45 KB) | 1 | 7,976 / 8,716 | 249 (241) / 811 | 1,209 (915) / 1,514 | 1.25 |
| HTML (45 KB) | 4 | 7,499 / 7,573 | 179 (136) / 274 | 1,297 (1,011) / 1,679 | 1.30 |
| HTML (45 KB) | 5 | 7,069 / 6,890 | 71 (38) / 150 | 1,300 (1,002) / 1,734 | 1.33 |
| HTML (45 KB) | 6 | 7,021 / 6,826 | 68 (37) / 136 | 1,306 (1,011) / 1,745 | 1.34 |
| HTML (45 KB) | 11 | 6,739 / 6,048 | 2.0 (1.9) / 1.6 | 1,126 (896) / 1,436 | 1.27 |
| JS (92 KB) | 1 | 23,344 / 25,616 | 138 (138) / 555 | 830 (628) / 1,054 | 1.27 |
| JS (92 KB) | 4 | 21,890 / 22,546 | 97 (80) / 134 | 954 (738) / 1,234 | 1.29 |
| JS (92 KB) | 5 | 20,918 / 20,789 | 58 (40) / 91 | 946 (724) / 1,247 | 1.32 |
| JS (92 KB) | 6 | 20,793 / 20,585 | 54 (37) / 82 | 962 (733) / 1,264 | 1.31 |
| JS (92 KB) | 11 | 19,936 / 19,077 | 3.0 (3.0) / 1.6 | 845 (666) / 1,062 | 1.26 |
| cert chain (2.7 KB) | 1 | 1,721 / 1,868 | 55 (48) / 244 | 356 (279) / 455 | 1.28 |
| cert chain (2.7 KB) | 4 | 1,717 / 1,759 | 52 (46) / 86 | 371 (304) / 469 | 1.26 |
| cert chain (2.7 KB) | 5 | 1,734 / 1,694 | 51 (46) / 73 | 371 (301) / 476 | 1.28 |
| cert chain (2.7 KB) | 6 | 1,734 / 1,694 | 48 (46) / 72 | 371 (302) / 477 | 1.28 |
| cert chain (2.7 KB) | 11 | 1,693 / 1,615 | 6.3 (6.5) / 1.1 | 368 (297) / 466 | 1.27 |
| cert chain (4.1 KB) | 1 | 2,598 / 2,736 | 69 (55) / 288 | 407 (325) / 498 | 1.23 |
| cert chain (4.1 KB) | 4 | 2,563 / 2,611 | 65 (52) / 102 | 434 (365) / 524 | 1.21 |
| cert chain (4.1 KB) | 5 | 2,593 / 2,549 | 65 (1.6) / 92 | 448 (372) / 546 | 1.22 |
| cert chain (4.1 KB) | 6 | 2,593 / 2,549 | 63 (1.6) / 89 | 448 (372) / 546 | 1.22 |
| cert chain (4.1 KB) | 11 | 2,515 / 2,430 | 2.2 (0.7) / 1.2 | 462 (380) / 571 | 1.24 |

The brotli decompression columns are from a second decoder pass (2026-11-20, quiet host, same tool
and corpus script; the JSON is regenerated, 656 KB): "(aca9e988)" is the decoder after the first
pass, built into the same tool and run alternately with this one (two rounds each on the HTTP
payloads, one on Silesia), best cell kept. Brotli decoding now takes 1.08–1.34× libbrotli's time on
the HTTP payloads (was 1.42–1.73×) and 1.04–1.32× on Silesia (was 1.13–1.56×). The slow payloads
were not bound by context maps: at levels 5–6 libbrotli writes a single literal tree for the HTML
and JavaScript files, and about 90% of their bytes come from copies (HTML at level 5: 2,136
commands, 2,193 literals, 40,884 copied bytes, distances mostly 16 or more, copies mostly 16 bytes
or fewer), so the time went to the per-command path (about a million instructions per decode of the
HTML page at 4.1 per cycle, the loop's state spilled to the stack) and, on the certificate chains,
to building prefix code tables (40% of the time). What changed (output unchanged): the command loop
keeps the bit reader, the output, its position and the last distances in locals, checks the
meta-block end, the limit and the window's spare room as one position per write (`make_room` past
it), takes distance contexts and the 16 short distance codes from tables, decodes a distance code
and its extra bits from one refill, masks the command symbol into a 1024-entry table instead of `%
704`, and looks up roots of a fixed 256 entries without bounds checks; prefix code tables are built
from the lengths as they are read (symbols with a code and counts per length, so no pass over the
symbols without one; codes up to 8 bits straight into the root, longer ones sorted for second-level
tables sized as Google's `NextTableBitSize`; bit reversal through a byte table, since x86-64 has no
instruction for `reverse_bits`), and the code length code gets a 32-entry table instead of a
256-entry one; copies of up to 32 bytes with a period under 16 go in 8-byte chunks instead of
`memmove`/`memset` calls; the output is zeroed ahead only up to the end of the meta-block, so a
small output decoded under a large limit no longer zeroes 128 KiB first (`BENCH_BR_LIMIT=16777216`,
level 5: the 2.7 KB chain 266 → 370 MB/s, the 4.1 KB one 337 → 446 MB/s, against 300 → 371 and 372 →
448 with an exact limit). Still `#![forbid(unsafe_code)]` and baseline x86-64 (no BMI2 paths).

**Decompression** went from 1.7–2.4× libzstd's time to 1.3–1.7× and from 1.4–3.1× libbrotli's to
1.1–1.7×. On Silesia zstd takes 1.32–1.33× libzstd's time at levels 1 and 3 (1.57× at 19) and
brotli 1.46–1.54× libbrotli's at levels 1–6 (1.13× at 11). On the HTTP payloads zstd takes
1.45–1.66× and brotli 1.42–1.73×; context-modelled brotli streams of a few tens of kilobytes (HTML,
JavaScript at levels 5–6) are the slowest, where per-literal context lookups and table building
weigh most. The ~1.5× goal is met on Silesia (zstd level 19: 1.57×), for zstd on JSON and HTML,
and for brotli at levels 1–4 on JSON and on the 4 KB chain; elsewhere it is missed by up to 0.23×
(brotli 1.55–1.73× on HTML, JavaScript, the 2.7 KB chain and JSON at levels 5–11; zstd 1.59–1.66×
on JavaScript and the chains). What changed (output unchanged): the output is the window, zeroed
one block (zstd) or 128 KiB (brotli) ahead and never past the limit, so literals and matches are
copied in 16-byte chunks instead of through `Vec::extend_from_within`; bit readers live in locals
(brotli's lived in `self`, which kept LLVM from holding it in registers across output stores),
zstd's with branch-free reads, brotli's refilled by ORing in the next 8 bytes without a branch on
the bits left; zstd decodes its four Huffman streams in lockstep from tables sized for unchecked
lookups and references the predefined sequence tables instead of copying them per block; brotli
decodes three literals per refill, through a context → tree offset table per block type (none at
all when a block type's context map has one tree), with a 704-entry command table and prefix code
tables built in place. A double-symbol Huffman table for zstd literals was tried and dropped
(slower on Zen 4). (The brotli decoding figures in this paragraph are from before the second
pass described under the brotli table.)

**zstd decoding, second pass** (2026-11-20, no API change, output unchanged; the zstd
decompression cells above). Measured on a quiet host (the bench host's `quiet.sh`: no desktop,
model service or kind cluster), CPU 2, both builds alternated twice, best of each; the
first pass's numbers for main (`aca9e988`) reproduced within 2%. libzstd's time over ours went
from 1.46–1.64× to 1.16–1.39× on the HTTP payloads and from 1.32–1.33× / 1.57× to 1.22–1.24× /
1.39× on Silesia: JavaScript 1.38–1.39× (was 1.59–1.61×), the 2.7 KB chain 1.16–1.26×
(1.49–1.64×), the 4.1 KB chain 1.26–1.27× (1.63–1.64×), JSON 1.37–1.38×, HTML 1.31–1.33×; every
cell is under 1.4×. Still `#![forbid(unsafe_code)]`, baseline x86-64, no BMI2 paths. Profiles
(`perf`) showed two costs: on the chains (raw literals, 100–170 sequences, three FSE-coded tables
per frame) building tables weighed most, and every call allocated and zeroed about 20 KB of them;
on JavaScript (6,100–7,100 sequences) the sequence loop ran about 1.6× libzstd's instructions (at an
IPC of 5.4) and spilled values to the stack. What changed:
- the decoding tables and the literals buffer are kept per thread between calls (libzstd's reused
  context; about 20 KB, plus up to 32 KiB of literals), and literal buffers are no longer zeroed;
- sequences are decoded in batches of 64 and then executed: two loops with fewer live values;
  when the extra bits total less than 31 (libzstd's condition) one read takes the extra bits and
  the three state updates of a sequence; the three tables sit side by side (one base register),
  the predefined ones copied in only when the mode changes; a sequence ending 16 bytes or more
  before the end of the room and of the literals is copied in 16-byte chunks after two
  comparisons, with no overflow checks;
- the four Huffman streams use libzstd's fast loop: bits left-aligned in a register above a
  marker bit, refilled from the marker's position, the table's accuracy log a constant (one copy
  of the loop per log), up to 8 symbols per stream between refills while every window lies in
  its stream;
- FSE tables are built straight into the decoding entries, Huffman weight tables on the stack.

Tried and dropped: a bit reader keeping its position as the slice length (worse code on x86-64 and
AArch64), a mask table instead of `(1 << n) - 1` (3% slower on JavaScript), batches of 4–16
(5–10% faster on Apple M-series, 1–4% slower on Zen 4). libzstd's double-symbol Huffman tables
came after ("zstd double-symbol Huffman tables" below).

**zstd literals** (2026-11-20, output changes): the encoder keeps a block's literals raw unless
Huffman coding saves more than 2 bytes plus 1/64 of them, and never Huffman-codes fewer than 64,
as libzstd does (`ZSTD_minGain`, `LITERAL_NOENTROPY`). Raw literals decode several times faster:
on the certificate chains our own frames (the ones TLS certificate compression sends) decoded at
870–965 MB/s, under half the speed of libzstd's frames, because the Huffman tables saved 4–17
bytes. Same quiet host, CPU 2, both builds alternated twice, decoding each encoder's own output
with only-zstd: the 2.7 KB chain 2,426–2,862 MB/s (was 873–915) and 8–17 bytes larger, the 4.1 KB
chain 2,133–2,257 MB/s at levels 1 and 3 (was 924–965) and 4–12 bytes larger (level 19 already
raw); JSON, HTML and JavaScript byte-identical, Silesia 0.004% larger (2,672 and 2,834 bytes at
levels 1 and 3).

**zstd double-symbol Huffman tables** (2026-11-20, no API change, output unchanged). For a
four-stream literals section that libzstd's `HUF_selectDecoder` would decode with its
double-symbol table (by its timings per size and compression ratio: from about 4.5–6.7 KB of
literals at the ratios of the HTTP payloads), the decoder builds one from the single-symbol table
(11 bits, 12 for a 12-bit code; an entry holds one symbol, or two when the next code fits in the
bits left) and decodes one or two symbols per lookup, writing two bytes and moving on by one or
two; the table stays with the per-thread decoder (16 KB more). The streams then move apart and
run out at different times (their codes take more or fewer bits), so when one stops the others
go on together, three, two, then one; finishing them one by one had left up to 12% of a stream's
symbols to a serial loop. Literal decoding alone (JavaScript, JSON and HTML literals, 16–60 KB,
CPU 2): 0.52–0.53 ns per byte → 0.41–0.45 on Zen 4 (13–21% faster), JavaScript literals
0.62–0.65 → 0.40–0.41 on Apple M-series (35–37%); building the table costs 0.4–0.6 µs on Zen 4,
so it pays from about 5–10 KB, in line with libzstd's rule. End to end, same quiet host, both builds (`6154345c` and this) alternated twice,
best of each: JSON +2.5–3.0% (3,094–3,489 → 3,176–3,594 MB/s), JavaScript +1.6–2.5%, HTML +1.6%,
Silesia level 19 +1.4%, level 3 unchanged and level 1 −0.8% (929 → 922 MB/s); libzstd's time
over ours on JavaScript 1.34–1.40× (1.36–1.42× for the old build in the same run). On x86-64
without BMI2 the single-symbol loop already runs at about 4.5 instructions per cycle with 5
instructions per symbol, so the double table gains less there than on Apple M-series. Tried and dropped: a 17-byte
output window per stream and round (more live values than x86-64's 16 registers: spilled, no
gain; positions in the one literals buffer instead), the symbols of a round gathered in a
register and stored once (8–20% slower).

**Compression** (output changes; round trips, the C libraries decoding our output in every cell
above, the crates' CLI interop tests and the round-trip fuzz targets check it): zstd levels 1–2
use libzstd's `fast` match finder (6-byte hash, its search strength) and 3–4 `double_fast`
instead of hash chains with lazy matching, Huffman codes start from a plain Huffman code and fall
back to package-merge only when it is too deep, and literals and sequences are written through a
64-bit accumulator flushed bytewise: 2.1–3.2× faster, now 1.6–2.6× libzstd's time (was 4.2–6.8×).
Sizes are within −3…+2% of libzstd's at levels 1 and 3; level 1 is 2.6% smaller than before on
Silesia, level 3 1.4% larger on Silesia and 1–7% larger on the HTTP payloads (it was a lazy
chain search, better than libzstd's level 3). Brotli levels 0–6 keep the last positions of each
hash in a bucket instead of chains (Google's `H2`..`H6`: the same candidates in one cache line,
5-byte hashes at 5–6), levels 2–4 look at as many candidates as Google's (level 4: 4, was 16),
the distance ring has quick rejects, data that does not compress is skipped through as Google's
encoder does, contexts with fewer than 32 literals start out clustered together, and below
level 10 the context map is kept on the clustering's estimate instead of writing each meta-block
three times: Silesia 3.4× (q4), 2.4× (q5) and 2.6× (q6) faster, now 1.7–2.2× libbrotli's time
(was 4.6–5.8×); HTTP payloads 1.0–1.9× faster at q4–q6, a 4 KB chain 40× at q5–q6 (no
clustering below 4096 literals: 3% larger). Sizes at q5–q6 are 0.4–1.2% smaller on Silesia and
JSON, 0.7–0.8% larger on HTML and JavaScript and 2–3% larger on the certificate chains; q4 is
1–9% larger than before and now about libbrotli's q4 size (+0.2% on JSON, 0.3–3% smaller on the
rest; it had looked at four times Google's candidates). Level 11 and zstd level 19 are
unchanged in speed (0.7× and 1.3× the C libraries' speed on Silesia) and stay 3–11% (brotli 11)
and 1–8% (zstd 19) larger than the reference encoders' output, which use block splitting,
static-dictionary references and optimal parsing (`btultra2`) that these encoders do not have.

### Codec micro benchmarks (`tools/codec-bench`, CPU 2, ns per operation)

A separate workspace, so httparse, loona-hpack, regex and the C libraries (brotlic-sys, zstd) stay
out of the libraries.

| Operation | only | replaced crate |
|---|---:|---:|
| HTTP/1 request head, 1 header | 59 | httparse 59 |
| HTTP/1 request head, browser-like, 11 headers | 204 | httparse 170 |
| HTTP/1 response head, 7 headers | 141 | httparse 117 |
| same browser-like request delivered in 16-byte reads (resumed vs re-parsed) | 1,797 | httparse 4,042 |
| HPACK decode, first request block, Huffman | 1,474 | loona-hpack 113,348 |
| HPACK decode, first request block, raw literals | 433 | loona-hpack 619 |
| HPACK decode, first response block, Huffman | 423 | loona-hpack 51,162 |
| HPACK decode, request block, all indexed | 255 | loona-hpack 306 |
| HPACK encode response, warm table | 72 | loona-hpack 284 |
| HPACK encode response, fresh table (only Huffman-codes) | 268 | loona-hpack 285 |
| route regexp `[0-9]+` on `1234567` (only-regex since ADR-051; was 8.5) | 5.7 | regex 15.7 |
| route regexp `\d{4}-\d{2}-\d{2}` (was 11.9) | 7.6 | regex 17.0 |
| route regexp `[a-z0-9_-]{3,16}` on 14 chars (was 17.6) | 10.6 | regex 20.0 |
| compile `\d{4}-\d{2}-\d{2}` (builds the DFA; was 2,124) | 7,262 | regex 112,501 |

Message filter regexps (`codec-bench logregex`, `only-regex`, unanchored search on an 86-byte log
line; 2026-11-19):

| Operation | only | regex |
|---|---:|---:|
| `connection reset` (literal: `str::contains`) | 6.8 | 12.3 |
| `timeout\|refused\|unreachable`, no match | 92.7 | 16.0 |
| `(?i)CONNECTION (reset\|refused)` | 69.0 | 85.8 |
| `\b\d+ms\b` | 92.9 | 32.7 |
| `conn \d+\.\d+\.\d+\.\d+:\d+` | 35.4 | 35.2 |
| `timeout\|refused\|unreachable`, non-ASCII line, no match | 91.9 | 15.7 |
| `(?i)réinitialisée`, non-ASCII line | 81.6 | 55.7 |
| compile `connection reset` | 15,567 | 2,025 |
| compile `(?i)CONNECTION (reset\|refused)` | 25,529 | 56,690 |
| compile `\b\d+ms\b` | 99,455 | 39,273 |

The DFA runs at about 1 ns per character, ASCII or not; `regex` is faster where its SIMD literal
search applies. only-log's `overhead` bench: `Filter::matches` costs 7.1 ns without a pattern and
107 ns with `/connection (reset|refused)` on a 72-byte message, formatting included.

The head parser scans 8 bytes at a time in safe code (httparse uses SSE4.2/AVX2 on x86-64): within
1.0–1.2× of httparse on whole heads, 2.2× faster on heads that arrive in pieces.

### Userspace TCP/IP stack (`only-dpdk --example stack-bench`, in-process memory wire, CPUs 2–3)

Two engines of `only-dpdk`'s own stack joined by the in-process memory wire, no NIC and no DPDK
driver. This measures the protocol code and its I/O loop only.

| Case | only-dpdk stack |
|---|---:|
| TCP echo, one connection, 64 KiB buffers | 1,431 MB/s each way (±10%) |
| TCP echo, one connection, 1 MiB buffers | 1,562 MB/s each way |
| sequential connections (dial, 1 request/response, close) | 63,365/s |
| median time to the first response of a new connection | 15.6 µs |
| 100 concurrent connections: all established / request-responses per second | 1.28 ms / 840 k |
| 1000 concurrent connections: all established / request-responses per second | 16.9 ms / 1,058 k |
| UDP request/response (one in flight) | 39,931/s (35,890–89,964) |

The UDP row swings by 2.5× between runs (it is one exchange at a time, so it measures the wake-up
latency of the two engine threads).

### eBPF acceleration (`tools/bench/ebpf.sh`)

Run on 2026-11-18 on the same host (Linux 7.0, root, under `quiet.sh`), from branch
`claude/ebpf-gaps-6b8982`. Each table is a same-run A/B: the cases alternate within each of 3
rounds of 5 s, and the figure is the median.

**Steering** (`bench-server` echo, 4 epoll I/O threads on CPUs 0–3, `ONLY_ACCEL`; `echo-bench`
with 256 connections × 64 B from 8 threads on CPUs 4–7 and 12–15). Over loopback the SYN and the
data are processed on the client's CPU, so this measures the cost of the programs and of
pinning, not the RSS locality steering is meant for (the host's NICs are down).

| `ONLY_ACCEL` | req/s | vs none |
|---|---:|---:|
| none (kernel reuseport hash) | 669,683 (±3%) | 1.00 |
| `cpu` (eBPF tier, `Steering::Cpu`) | 743,669 | 1.11 |
| `cpu-pin` (plus `pin_threads`) | 756,969 | 1.13 |
| `hash` (eBPF tier, `Steering::Hash(SrcIpPort)`) | 701,630 | 1.05 |

The programs cost nothing measurable. The gain over the kernel's hash is most likely placement
(not measured per thread): with 256 connections, the kernel's hash can leave the 4 threads unevenly loaded, while CPU steering
spreads connections by the client thread's CPU and the hash tier by Maglev slots. Pinning adds
1.8% and made the rounds steadier (±0.1%).

**SOCKS5 tunnel, userspace relay vs sockmap splice** (`ebpf-bench socks`: 2 epoll I/O threads,
8 tunnels uploading 256 KiB writes to a sink as fast as they can; CPU is the whole machine's busy
time from `/proc/stat`, per GB moved).

| Relay | Throughput | CPU-s per GB | CPUs busy |
|---|---:|---:|---:|
| userspace (`ProxyConfig::sockmap = None`) | 62.9 Gbit/s | 0.49 | 3.9 |
| sockmap (`Relay::new`) | 124.2 Gbit/s (±7%) | 0.93 | 14.5 |

Splicing doubles the tunnels' throughput (1.97×), because the relay no longer runs on the
proxy's 2 I/O threads: the kernel relays in softirq and in the psock backlog workers on every
CPU. It is not cheaper per byte here. Over loopback, the clients, the sink and the relay share
the machine's 16 CPUs, so it spends about 1.9× the CPU per GB to go twice as fast. All 8 tunnels
were spliced. The userspace relay is unchanged by the fast path's checks: in a same-run A/B
against `ab65d376` (5 alternating rounds) it ran at 1.00× on epoll (66.7 Gbit/s) and 0.99× on
io_uring (31.3 vs 31.7 Gbit/s, inside io_uring's ±7% spread).

**XDP rate limiter** (`ebpf-bench`: a UDP flood of 64-byte datagrams from 4 threads in one
network namespace over a veth pair to another; the limiter counts every packet at 1/s per
source, so nearly everything is dropped).

| Receiver | Flood sent | Handled |
|---|---:|---:|
| no XDP, a socket reading the datagrams | 1.57 Mpps | 1.42 Mpps received |
| XDP native (veth driver mode) | 2.76 Mpps | 2.15 Mpps dropped |
| XDP generic (`skb` mode) | 2.01 Mpps | 1.88 Mpps dropped |

The sender, which over veth also runs the receiver's softirq, is the limit in every row. With
the packets dropped at XDP it pushes 1.76× more in native mode and 1.28× more in generic mode
than when they go up the stack to a socket. Native XDP drops 1.52× the packets the socket path
delivers.

### Connectionless UDP

**`DatagramsHandler` against per-peer UDP** (2026-11-21, ADR-065; gpu51, Ryzen 7 7800X3D, Linux
7.0, quiet host via `quiet.sh`, one alternating run: 64-byte echo, `bench-server` with 4 threads
on CPUs 0–3, `echo-bench` 64 sockets × 64 B with 8 threads on CPUs 4–11, 10-second runs, 9
rounds in rotating order; medians, server CPU per request from `/proc`):

| Server | req/s, median (range) | vs per-peer before | server CPU per request | vs before |
|---|---:|---:|---:|---:|
| per-peer `Listener::udp(..).serve`, before (`b22519ae`) | 768,144 (684,519–860,916) | 1.00 | 4,745 ns | 1.00 |
| per-peer, after | 781,173 (712,511–841,607) | 1.02 | 4,747 ns | 1.00 |
| `serve_datagrams`, epoll | 829,051 (726,597–926,309) | 1.08 | 4,407 ns | 0.93 |
| `serve_datagrams`, io_uring | 838,496 (680,238–912,182) | 1.09 | 4,364 ns | 0.92 |

The per-peer path does not regress (throughput within the run-to-run spread, CPU per request
equal). Without the peer lookup, `Conn` and per-peer cork/flush bookkeeping the connectionless
echo costs 7–8% less server CPU per request; with 64 clients on loopback the client is close to
its limit, so throughput gains less than that. Rerun with `tools/bench/udp-dgram.sh`.

### AF_XDP vs AF_PACKET under the userspace stack (`tools/bench/afxdp.sh`)

Run on 2026-11-21 on the same host (Linux 7.0, root, under `quiet.sh`), from branch
`claude/ebpf-xdp-2df444` (ADR-063). It is a same-run A/B: the two links alternate within each of 5
rounds of 5 s (the order swaps every round), and the figure is the median.

The setup: the only-dpdk stack serves UDP and TCP echo on one end of a veth pair, in the root
namespace, with its I/O thread pinned to CPU 2. Kernel clients run in a network namespace on
the other end (4 threads on CPUs 4–7, `link-bench` example). TSO, GSO and GRO are off on both
ends, so both links move one MTU-sized frame per segment. AF_XDP ran in native XDP and copy mode
(a veth has no zero-copy AF_XDP); AF_PACKET is the existing `Device::AfPacket`.

| Case | AF_PACKET | AF_XDP | AF_XDP / AF_PACKET |
|---|---:|---:|---:|
| UDP request/response, 64 B, 4 in flight | 255,599/s (±0.3%) | 428,413/s (414–465 k) | 1.68 |
| TCP request/response, 64 B, 4 connections | 220,053/s | 348,673/s (339–379 k) | 1.58 |
| TCP connections/s (connect, 8 B echo, close) | 23,727/s | 29,492/s | 1.24 |
| TCP echo, one connection, MB/s each way | 274.6 | 814.7 | 2.97 |

AF_PACKET pays a `recvfrom` system call and an skb per received frame, plus a `write` per sent
frame. AF_XDP moves frames through shared rings: one copy into the UMEM on receive, in place on
send, and one `sendmsg` kick per batch. The difference is largest for bulk TCP, where each
direction carries full-size frames. Connection churn gains least: most of its cost is in the
kernel clients' own connect and close. This measures copy mode; zero-copy on a NIC that supports
it is not measured (the host's NICs are not used).

### WebSocket over HTTP/2 (ADR-060, h2c A/B)

Measured 2026-11-21 on gpu51. Question: does accepting extended CONNECT change the h2c request
path? The changes there are a `:protocol` check in the header decoder, a `tunnel` flag on the
stream, and the parked context as a two-case enum. `base` is `main` at `b22519ae`, `new` the
branch (`http-bench`, epoll); both built in one session and run interleaved under `quiet.sh`,
7 rounds (5 s runs, a fresh server per run; server on CPUs 0–3 with 4 threads, `h2load` with
8 threads on CPUs 4–7 and 12–15). `±` is half the min–max spread of the rounds.

| Load | base median | new median | new / base (medians) | per-round ratio median |
|---|---:|---:|---:|---:|
| h2c 64 conns × 16 streams | 3,607,629 (±22%) | 3,801,917 (±36%) | 1.054 | 0.991 |
| h2c 16 conns × 128 streams | 5,373,158 (±10%) | 5,022,618 (±11%) | 0.935 | 1.004 |

**Answer: no measurable change.** h2c rounds on this host spread far wider than the difference: both directions appear in each row (h2c 64 × 16
per-round ratios 0.54–1.26, 16 × 128 0.82–1.14), and the per-round ratio medians are within 1%.

## Not measured

- **DPDK** with a real NIC (none on the host); `only-dpdk` only through its stack benchmark above.
- QUIC and HTTP/3 against quic-go or another implementation (no reference server in the harness).
- hyper over TLS (hyper-ref has no TLS listener); hyper for raw TCP/UDP/WebSocket (not its job).
- Latency percentiles, memory under sustained load (only idle after one exchange), real networks,
  monoio.

## History

Short summaries of the per-area passes; the full tables are in the git history of this file.

- **2026-11-14, shared VM** (aarch64 Docker VM on a laptop, other jobs running, ±20–50% between
  rounds): the first cross-library tables. HPACK Huffman decoding built once took h2c from 292 k to
  1.87 M req/s (×6.4); one clock read per callback, `Headers` in one string and hashing the
  connection tables with a multiply took HTTP/1.1 plaintext +9% and pipelined +17%; inline queue
  heads and boxed HTTP session states cut TCP-after-echo memory 739 → 607 B and HTTP keep-alive
  1,624 → 912 B per connection.
- **HTTP hot paths** (this host, `main` at `df90c0b3` → after): h2 frames parsed in place, decoded
  headers in one reused buffer, HPACK encoded straight into the output, one write per read, flow
  control credited per quarter window, HTTP/1 heads parsed with 32 slots first. h2c 64 × 16
  2.28 M → 4.05 M (epoll), 16 × 128 2.37 M → 4.71 M, HTTP/2 over TLS 1.58 M → 4.03 M (2.5×),
  pipelined HTTP/1.1 +7–8%, keep-alive HTTP/1.1 +1% (kernel-bound). Before the pass `only` was
  0.52–0.70× fib on HTTP/2; this campaign has it at 1.22–1.34×.
- **Crypto CPU acceleration** (this host, `354f3bc5` → after): AES-128-GCM 16 KiB 364 → 6,484 MB/s
  (17.8×), SHA-256 6.5×, SHA-1 3.6×, CRC-32 7.3×, ChaCha20-Poly1305 3×; P-256 sign 1.46×, verify
  1.67×, Ed25519 verify 1.49×, RSA-2048 1.36–1.38×. TLS records 9–15× faster, handshakes 1.4–1.5×.
- **P-256 and X25519 for TLS handshakes** (this host, CPU 2, median of three alternating rounds,
  `a1cc9b49` → after): P-256 field and order arithmetic in BMI2/ADX assembly behind run-time
  detection, Jacobian scalar multiplication (Booth 5-bit windows, signed comb with mixed
  additions), a scalar inversion chain, X25519 public keys from the Edwards base table and an
  ADX ladder. P-256 sign 34,152 → 59,837 op/s, verify 13,404 → 25,138, ECDH 10,380 → 27,288, key
  generation 54,581 → 108,263; X25519 30,696 → 36,488; Ed25519 sign 67,644 → 89,784; P-384
  1.13–1.47×. Handshakes 3,055 → 5,027/s (X25519, 1.00× rustls) and 2,306 → 4,552/s (secp256r1,
  0.89×).
- **P-256 whole-point assembly** (this host, CPU 2, median of five alternating rounds on a
  loaded host, `7cefa48b` → after): doubling, addition and mixed addition as single `asm!` blocks
  (doublings five to a frame), a 6-bit Booth comb with AVX2 scans for the fixed base, AVX2 scans
  of the ECDH window table, safegcd inversions with assembly divsteps. Against ring in the same
  run: sign 0.77× → 1.25×, key generation 0.94× → 1.33×, verify 0.98× → 1.04×, ECDH 0.94× →
  0.96×; secp256r1 handshakes 0.94× → 1.12× rustls.
- **QUIC datapath** (this host, CPUs 2–5, same-run old/new rounds, `42d67dde` → after): UDP
  GRO on by default (bulk 6.4 → 9.8 Gbit/s: a GSO batch arrives as one receive, no
  `skb_segment` on the way), acknowledgments once per receive batch through an internal
  batch-end hook of the UDP loop (9.5 → 13.6 Gbit/s), sent packets in a ring and received packets
  in pooled buffers (14.3 → 15.1), one clock read per datagram in the UDP loop instead of three
  and the QUIC timer armed once per batch (15.2 → 16.2). HTTP/3 +3–4%, handshakes flat. 64-byte
  UDP echo with GRO on and off (15 alternating rounds each): within the noise of the case
  (±15% at 64 peers; −0.3% to −0.9% with one exchange in flight).
- **HTTP/3** (this host, CPUs 2–5, same-run old/new rounds, `dbc7563f` → after): frames read in
  place, field sections decoded into one reused buffer and copied once into `Headers`, HEADERS
  QPACK-encoded straight into the output with one QUIC write per response, static-table lookups
  without SipHash maps (445 k → 730 k req/s); in-order stream ACKs without the range tree
  (+3.5%), whole requests kept out of the stream table (+2.5%), QPACK integers inline (+2%), the
  first send chunk of a stream inline (+3%), response headers sized once (+1%). 429 k → 839 k
  req/s in all (1.95×). A keyed folded-multiply hasher replaced SipHash on only-quic's
  connection-ID, connection and peer-address tables: bulk +3%.
- **P-256 point formulas** (this host, CPU 2, median of five alternating rounds on a quiet host,
  `1376b324` → after): OpenSSL's `ecp_nistz256` addition, mixed addition and doubling order in the
  whole-point assembly, a shorter reduction step. Against ring in the same run: ECDH 1.08× →
  1.12×, sign 1.36× → 1.38×, verify 1.08× → 1.10×, key generation 1.36× → 1.40×; handshakes
  unchanged (secp256r1 1.07×, X25519 1.08× rustls).
- **RSA** (this host, CPU 2, three alternating rounds on a quiet host, `7f5c483a` → after): BMI2 +
  ADX Montgomery multiplication and squaring in assembly, the exponentiation on AVX-512 IFMA
  (radix 2⁵²), 5-bit windows with one-pass AVX2 scans, `R²` by squarings or one division. Against
  ring: RSA-2048 sign 0.49× → 1.61×, 3072 0.47× → 1.85×, 4096 0.45× → 2.19×, verify 0.60× →
  1.22×, verify with the key parse 0.09× → 1.02×; RSA-2048 certificate handshakes 0.43× → 1.44×
  rustls.
- **RSA CRT halves interleaved** (this host, CPU 2, `a965d26c` → after): both half-exponentiations
  of a signature in one IFMA loop, their reduction chains overlapping. Against ring: RSA-2048 sign
  1.63× → 2.20×, 3072 1.87× → 2.19×, 4096 2.21× → 2.55×; RSA-2048 certificate handshakes 1.45× →
  1.69× rustls; verification unchanged.
- **RSA verification on IFMA** (this host, CPU 2, `62ea6318` → after): the public operation in
  radix 2⁵² (new 3,072- and 4,096-bit AMMs), 18 products for `e = 65537`, `R²` by a faster
  division. Against ring: verify 1.22× → 3.07× / 1.10× → 3.30× / 1.09× → 3.70× (2048 / 3072 /
  4096), with the key parse 1.02× → 2.35× / 0.95× → 2.64× / 0.95× → 2.90×; sign 2.26× / 2.24× /
  2.60×; RSA-2048 certificate handshakes 1.67× → 1.82× rustls.
- **Wide AES-GCM and CRC** (this host, `a1cc9b49` → after): AES-GCM on VAES + VPCLMULQDQ +
  AVX-512 (512-bit, chosen over 256-bit by measurement) 2.3–2.5× at 16–64 KiB (AES-128 seal
  16 KiB 6,455 → 15,048 MB/s, 0.51× → 1.19× ring), the fused tail 1.8–2.1× at 64 B; TLS 1.3
  records sealed and opened out of place, 2.4× at 16 KiB (0.69× → 1.65× rustls + ring); CRC-32
  folding on 512-bit registers 16 KiB 19,992 → 74,885 MB/s (0.27× → 1.02× crc32fast).
- **AES-GCM leftovers** (this host, `dbc7563f` → after): the AVX-512 kernel takes the whole
  message (AAD, masked last partial group, length block and `E(J0)`; short messages under one
  reduction): AES-128 seal 1 KiB 1.00× → 1.32× ring, 1400 B 1.10× → 1.46×, 64 B 1.11× → 1.29×,
  open 1 KiB 1.04× → 1.22×; a VAES-AVX2 kernel (sixteen blocks in eight ymm) for CPUs without
  AVX-512, 1.55–2.35× the 128-bit kernel on Zen 4; TLS 1.3 records 1 KiB 1.51× → 1.58× rustls +
  ring. The record zero-fill stays (every safe alternative measured slower).
- **TLS record zero-fill removed** (this host, `f34c79e3` → after): the record layer seals and
  opens straight into the output vector's spare capacity (only-crypto `encrypt_append` /
  `decrypt_append`, a small `unsafe` module; only-tls stays `forbid(unsafe_code)`): TLS 1.3
  records AES-128-GCM +6.9–8.3% (16 KiB 1.58× → 1.72× rustls + ring), AES-256-GCM +7.4–8.7%,
  ChaCha20-Poly1305 +3.3–6.4%; the AEAD alone out of place +10–11% at 1–64 KiB on VAES-AVX-512.
- **QUIC and TLS hot paths** (this host): the pacer floored the RTT at 1 ms and woke the sender
  per packet; with the measured RTT and burst refills (as quinn-proto does) bulk went 3.4–3.7 →
  5.7 Gbit/s (1.25× quinn-proto) and HTTP/3 171 k → 420 k req/s (7× quinn-proto). TLS records are
  decrypted where they land in the caller's buffer: +5–7% at 16–64 KiB.
- **Deflate** (this host, wave A matcher → zlib-ng strategies): compression 1.03–4× faster at
  levels 2–9 and 1.7–2.9× at level 1, decompression 1.1–1.45× faster; permessage-deflate echo of
  64 B messages 478 k → 643 k/s.
- **Userspace stack** (Apple-silicon laptop, shared): the own stack replaced smoltcp 0.12 with
  6.5–11× the bulk throughput and 11× the sequential connection rate.

This campaign reproduced the per-area figures of the HTTP, QUIC, TLS, crypto and deflate passes
within 1–2% (no regressions there). One memory figure moved: a WebSocket connection after upgrade + one echo cost 3,493 bytes
here against 1,660 in the 2026-11-14 table (the other rows are within 5% of it: idle TCP 600 →
603, HTTP keep-alive 912 → 937, TLS 8,526 → 8,192). It was a real regression, not the change of
host: the 2026-11-14 build measured on this host with the same `mem.sh` gives 1,683, and a
bisection put the jump (1,679 → 3,437) on the commit that replaced flate2 with only-deflate. The
permessage-deflate wrappers of only-ws held the new codec state inline (528 B inflater, 1,552 B
deflater; flate2 kept its state behind a pointer), and every connection carries an
`Option<Inflater>` in its decoder and an `Option<Deflater>` in its sender, so ~2 KB was paid even
when compression was not negotiated, as in this benchmark. The state is now boxed: 3,486 → 1,426
bytes (epoll) and 3,485 → 1,414 (uring), below the 2026-11-14 figure.

## Reproducing

See [tools/bench/README.md](../tools/bench/README.md). In short, on a Linux host with h2load, Go
and a fib checkout:

```sh
export CARGO_TARGET_DIR=/path/to/target
FIB_SRC=/path/to/fib tools/bench/build.sh
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 THREADS=4 CLI_THREADS=8 SECS=5 RUNS=3 \
  tools/bench/http.sh plaintext,pipelined,json,h2,h2many,h2tls,ws
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 tools/bench/echo.sh
ulimit -n 1048576; MEM_RUNS=3 tools/bench/mem.sh
taskset -c 2-5 $CARGO_TARGET_DIR/release/examples/quic-bench bulk 2048   # also: h3 5 64, handshakes 5 8
cargo run --release -p only-tls --example tls-bench all 1
cargo run --release -p only-crypto --example bench; cargo run --release -p only-crypto --example pk_bench
cargo run --release -p only-crypto --example gcm-sizes   # AES-GCM by message size against ring
BENCH_LEVELS=1,3,6,9 cargo run --release -p only-deflate --example bench SOURCES libc.so.6
cargo run --release -p only-deflate --example pmd_echo
cargo run --release --manifest-path tools/codec-bench/Cargo.toml
tools/codec-bench/corpus.sh DIR   # SILESIA=1 also downloads the Silesia corpus
BENCH_LEVELS=1,3,19 cargo run --release --manifest-path tools/codec-bench/Cargo.toml zstd DIR/*
BENCH_LEVELS=1,4,5,6,11 cargo run --release --manifest-path tools/codec-bench/Cargo.toml brotli DIR/*
cargo run --release -p only-dpdk --example stack-bench
```

`summarize.py` turns the TSV rows of the network scripts into tables. `start_server` skips ports
that client sockets of an earlier run still hold (bare Linux's ephemeral range starts at 1024).
