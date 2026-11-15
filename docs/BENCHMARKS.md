# Benchmarks

English | [简体中文](BENCHMARKS.zh-CN.md)

Measured 2026-11-14 on the branch that follows commit `23d9c59` (the performance and memory pass
described below). **Read the caveats first**: one VM on a laptop, shared with other busy jobs while
these runs were taken. The spread between rounds was often ±20% and sometimes more; treat
differences under ~20% in the comparison tables as noise and read them as "same class or not",
not as a ranking. The before/after rows of the optimizations were measured separately, with the
two builds interleaved, and are more trustworthy than the cross-library tables.

## Setup

- One Docker VM (linuxkit, Linux 6.12.5, aarch64) on an Apple-silicon Mac, **14 vCPUs shared with
  other jobs**: while these runs were taken, other agents' containers (fuzzers, test suites, an
  Autobahn server) kept roughly 4–5 vCPUs busy, unpinned, so they also ran on the benchmark's
  CPUs. Loopback only, no NIC.
- Server pinned to CPUs 0–3 with 4 I/O threads (tokio: 4 workers; fib: `GOMAXPROCS` follows the
  4-CPU affinity). Load generators pinned to CPUs 4–11 with 8 threads.
- Every figure is the **median of 3 rounds** of 5 s after a 1 s warm-up (the A/B rows: 5 rounds).
  A round runs every case against every server in turn, each run against a freshly started
  server, so a burst of noise lands on one run of each server rather than on one server. The `±`
  after a figure is half the min–max spread of the rounds, as a percentage of the median.
- Before each run the scripts sample `/proc/stat` and wait (up to 15 s) while more than 45% of the
  VM is busy; the other jobs rarely left it idler than that, so this only skips the worst bursts.
  Work outside the VM (on the macOS host) is invisible to it.
- Servers (the same handlers everywhere):
  - **only-epoll / only-uring**: `crates/only/examples/bench-server.rs` (TCP/TLS/UDP echo) and
    `crates/only-http/examples/http-bench.rs` (HTTP/1.1 + h2c `/plaintext`, `/json`, WebSocket
    echo on `/ws`), with `Backend::Epoll` / `Backend::IoUring`.
  - **tokio**: `tools/bench-ref/tokio-ref` (tokio 1, one task per connection, 64 KiB read buffer;
    TLS through tokio-rustls; WebSocket through tokio-tungstenite 0.28).
  - **hyper**: `tools/bench-ref/hyper-ref` (hyper 1 + hyper-util `auto`: HTTP/1.1 and h2c).
  - **fib**: `tools/bench-ref/fib-ref` (Go 1.27.3, fib's default config; TLS through `fib/tls`,
    HTTP through `fib/http`, WebSocket through `fib/websocket`).
- TLS: TLS 1.3 with an ECDSA P-256 self-signed certificate on every server (rustls + ring for `only`
  and tokio, crypto/tls for fib); the client does not verify the certificate.
- Load generators: `wrk` 4.1 (HTTP/1.1; pipelining through a Lua script that writes 16 requests at
  a time), `h2load` 1.64 (HTTP/2 prior knowledge, 64 connections × 16 streams, 8 threads), and the
  in-repo `tools/echo-bench` (closed-loop echo for TCP/TLS/UDP/WebSocket, full-handshake TLS rate,
  and the connection holder of the memory runs).
- JSON: hyper serialises with serde_json, fib with `encoding/json`, `only` with a small hand-written
  serializer in the example (`only` has no JSON dependency); all three build the body per request.

## Reproducing

```sh
docker build -t only-bench tools/bench          # rust:1 + wrk + h2load + perf + Go
PRIV=1 tools/bench/docker.sh 'tools/bench/build.sh && tools/bench/all.sh /tmp/t/results'
```

`docker.sh` mounts the repository at `/w` and the fib checkout (`../fib` next to the main `only`
checkout, or `$FIB_DIR`) at `/fib`, keeps the cargo registry, the target directory and the Go
modules in volumes, raises `nofile` to 1M and sets loopback-friendly sysctls (ephemeral ports
10000–65535, above the servers' ports; `tcp_tw_reuse`). The pieces also run on their own:
`echo.sh [tcp,udp,tls,tlshs]`, `http.sh [plaintext,pipelined,json,h2,ws]`, `mem.sh
[proto:kind:conns ...]`, and `profile.sh <h1|pipelined|h2|ws|tcp> <server>` (perf; needs
`PRIV=1`). The knobs (`SRV_CPUS`, `CLI_CPUS`, `THREADS`, `SECS`, `RUNS`, `KINDS`, and `BASE_DIR`
for A/B runs against the binaries of another revision, which appear as `base-epoll` /
`base-uring`) are described in `tools/bench/lib.sh`; `summarize.py` turns the raw TSV rows into the
tables below.

## Results

The cross-library tables were taken one change before the final state of the branch (before the
ordered-response state became lazily allocated, a memory-only change); the memory table and the
HTTP A/B rows below are from the final state.

### TCP echo (requests/s; message size × connections)

| Load | only-epoll | only-uring | tokio | fib |
|---|---:|---:|---:|---:|
| 64 B × 64 | 413,656 (±21%) | 463,209 (±9%) | 392,648 (±36%) | 402,295 (±4%) |
| 64 B × 256 | 774,759 (±15%) | 818,456 (±14%) | 596,489 (±29%) | 538,260 (±2%) |
| 64 B × 1024 | 704,040 (±54%) | 842,623 (±23%) | 438,664 (±20%) | 523,915 (±15%) |
| 1 KiB × 64 | 404,664 (±8%) | 463,423 (±21%) | 399,786 (±27%) | 301,771 (±1%) |
| 1 KiB × 256 | 634,095 (±21%) | 620,271 (±49%) | 609,872 (±43%) | 422,758 (±4%) |
| 1 KiB × 1024 | 1,098,164 (±20%) | 1,077,873 (±26%) | 542,744 (±34%) | 487,955 (±14%) |
| 16 KiB × 64 | 395,935 (±4%) | 309,907 (±37%) | 406,491 (±20%) | 83,666 (±10%) |
| 16 KiB × 256 | 613,344 (±24%) | 493,820 (±14%) | 602,560 (±14%) | 141,787 (±14%) |
| 16 KiB × 1024 | 619,031 (±24%) | 488,161 (±13%) | 326,409 (±20%) | 190,626 (±12%) |

### UDP echo, TLS

| Case | only-epoll | only-uring | tokio | fib |
|---|---:|---:|---:|---:|
| UDP echo, 64 B × 64 sockets (req/s) | 484,282 (±30%) | – | 359,668 (±2%) | 529,350 (±1%) |
| TLS 1.3 echo, 1 KiB × 64 (req/s) | 345,810 (±20%) | 406,917 (±19%) | 312,620 (±33%) | 269,039 (±4%) |
| TLS 1.3 full handshakes/s (32 clients) | 27,627 (±34%) | 27,743 (±35%) | 31,553 (±26%) | 9,142 (±32%) |

UDP runs on `only`'s epoll UDP loop for both backends. The tokio UDP reference is one task looping
on `recv_from`/`send_to`, the simplest tokio server, not its best case. The handshake rate is
probably limited by the client (8 threads doing the client half of every handshake) for `only` and
tokio; it shows that `only`'s TLS layer adds nothing visible over tokio-rustls, not a server maximum.

### HTTP/1.1 and HTTP/2 (requests/s, 256 connections for HTTP/1.1)

| Case | only-epoll | only-uring | hyper | fib |
|---|---:|---:|---:|---:|
| `GET /plaintext` | 769,559 (±29%) | 752,350 (±21%) | 546,363 (±16%) | 486,917 (±8%) |
| `GET /plaintext`, pipelined ×16 | 3,619,101 (±14%) | 3,233,575 (±20%) | 1,575,798 (±12%) | 4,644,526 (±20%) |
| `GET /json` | 689,533 (±41%) | 756,059 (±13%) | 552,799 (±18%) | 496,978 (±7%) |
| h2c, 64 conns × 16 streams | 1,414,553 (±7%) | 1,398,819 (±15%) | 705,017 (±8%) | 2,593,261 (±11%) |

In the quieter A/B runs below, `only` reached 1.1–1.2 M req/s for plaintext and JSON and 1.8 M req/s
for h2c: the table above caught busier moments of the host.

### WebSocket echo (messages/s, 256 connections)

| Message | only-epoll | only-uring | tokio-tungstenite | fib |
|---|---:|---:|---:|---:|
| 64 B | 840,572 (±17%) | 825,552 (±19%) | 640,534 (±24%) | 557,493 (±8%) |
| 1 KiB | 736,543 (±21%) | 587,501 (±23%) | 673,068 (±22%) | 536,800 (±6%) |

### Memory per connection

Server RSS growth divided by the connections held open (`tools/bench/mem.sh`): the client opens the
connections (spread over 127.0.0.1–4, so one client holds more than 64k), takes each through one
exchange, then keeps them all idle while the server's `VmRSS` is read. Bytes per connection,
10,000 connections unless noted. tokio's per-connection read buffer is set to 4 KiB for these runs
(`TOKIO_REF_BUF`, a memory-conscious tokio server would do the same); the 64 KiB of its throughput
runs would be mostly untouched memory anyway.

| Connection state | only-epoll | only-uring | tokio | hyper | fib |
|---|---:|---:|---:|---:|---:|
| idle TCP (connected only) | 600 | 603 | 4,993 | – | 428 |
| idle TCP, **100,000 connections** | 562 | 564 | 5,008 | – | 275 |
| TCP after one 64 B echo | 607 | 6,674 ¹ | 4,993 | – | 471 |
| HTTP/1.1 keep-alive after one request | 912 | 7,000 ¹ | – | 17,432 | 1,629 |
| WebSocket after upgrade + one echo | 1,660 | 7,759 ¹ | 137,297 ² | – | 485 |
| TLS 1.3 after handshake + one echo | 8,526 | 14,598 ¹ | 15,086 | – | 6,661 |

¹ Not per connection: io_uring receives into a provided-buffer ring of 1024 × 16 KiB per I/O thread
(64 MiB for 4 threads), allocated up front and touched page by page as the ring cycles. With 10,000
connections receiving once each, most of it gets touched (~60 MB here), which shows up as ~6 KB
"per connection"; it is a fixed ceiling that does not grow with more connections. The idle row,
where nothing was received, shows only-uring's real per-connection cost: the same as epoll.

² tokio-tungstenite with its default configuration keeps large per-connection read/write buffers.

The 100k-connection run (the M1 leftover) completed for every server: `only` held 100,000 idle
connections in ~55 MB of RSS above its baseline.

## Performance and memory pass

What was profiled and changed, with before/after numbers from interleaved A/B runs of the two
builds (`BASE_DIR`, 5 rounds × 5 s for HTTP, 3 rounds for the rest; the earlier build is the code at
`23d9c59` with only the benchmark example added).

### Profiles (perf, `tools/bench/profile.sh`)

- **h2c**: 65% of the server's CPU was in HPACK header decoding: `loona-hpack` builds its Huffman
  decoding table (nested hash maps of 257 codes) from scratch for every Huffman-coded string.
  After the fix the profile is led by malloc/free (~25%) and the kernel.
- **HTTP/1.1 plaintext**: 74% kernel (loopback TCP, wakeups), 26% user space, of which allocation
  (~4%), clock reads (~4%: five `clock_gettime` per request), request parsing and response encoding
  were the largest items.
- **TCP echo**: kernel-bound; no user-space item above 1%.

### Changes and their effect

| Change | Where | Effect (median, A/B) |
|---|---|---|
| Huffman decoding with a table built once (`only_http::hpack`); header blocks are rewritten to raw literals before `loona-hpack`, which keeps the dynamic table and validation; the same decoder serves QPACK | only-http, only-h3 | h2c: **292k → 1.87M req/s** (epoll, ×6.4), 287k → 1.82M (uring) |
| One clock read per callback instead of three: the loop caches "now" per batch of events and chains callback timing (slow-callback detection) from the previous callback's end; the response-time middleware reads the clock only when installed | only-epoll, only-uring, only-core, only-http | with the next three rows: HTTP/1.1 plaintext **1.10M → 1.20M** (epoll, +9%), 1.14M → 1.19M (uring, +4%); JSON 1.14M → 1.20M (epoll, +5%), 1.16M → 1.19M (uring, +3%); pipelined ×16 3.76M → 4.40M (epoll, 3 rounds, +17%) |
| `Headers` keeps all names and values in one string: two allocations per header set instead of two per field; response encoding without `fmt`, the date header written from the per-second cache without a clone | only-http | (included above) |
| `fill` of the response that is first in line sends directly, without a one-element `Vec<Part>` | only-core | (included above) |
| Connection tables hashed with a multiply instead of SipHash (`IdMap`) | only-core, backends | (included above) |
| Send queue and response-slot queue hold their first element inline, so a connection keeps no queue allocation between requests; the ordered-response state is allocated on first use (HTTP) | only-core | TCP after one echo **739 → 607 B** (−18%); idle TCP 554 → 600 B (+8%, the inline head), 100k idle 533 → 562 B |
| HTTP session: the WebSocket, HTTP/2 and request-body states are boxed (session 736 → 200 bytes) | only-http | HTTP keep-alive **1,624 → 912 B** (−44%); WebSocket 2,085 → 1,660 B (−20%) |

TCP echo throughput was unchanged within noise (64 B × 64: 511k → 517k; 64 B × 1024: 1.01M →
1.01M). TLS memory was unchanged (8.5 KB per connection, mostly rustls' own buffers).

After merging the later `main` (chaos fixes, lints, fuzzing), the same A/B against the pre-merge
build showed HTTP/1.1 plaintext unchanged (1.11M vs 1.12M) and memory unchanged (within 10 bytes
per connection), but h2c 9% slower (1.82M → 1.67M): the h2 session now drops finished streams after
releasing its lock, through a `Vec` that was allocated afresh for every finished stream. Reusing a
per-thread spare buffer for it brought h2c back level with the pre-merge build (1.39M vs 1.41M in
a busier moment of the host).

### New: write timeout

`Config::write_timeout` (default off): a connection that has output queued and makes no write
progress for that long is closed with `ErrorKind::TimedOut` (counted in `write_timeouts`). The
existing `idle_timeout` already acts as the read timeout (only inbound data counts as activity).
Both backends; the check runs on the idle-timeout wheel only while output is queued, so it costs
nothing on connections that keep up.

## HTTP hot paths (performance pass, 2026-11-15)

Re-profile of `only-http` after the in-house replacements (TLS, HPACK, HTTP/1 parser), on a
quiet bare-metal host rather than the shared VM above: AMD Ryzen 7 7800X3D (8 cores, 16 threads),
Ubuntu 24.04, Linux 7.0, loopback. Server pinned to CPUs 0–3 with 4 I/O threads (fib:
`GOMAXPROCS` follows the affinity), h2load 1.59 pinned to CPUs 4–7 and 12–15 with 8 threads
(CPUs 8–11, the SMT siblings of the server's cores, idle). wrk is not installed there, so HTTP/1.1
is driven by `h2load --h1` (pipelining: `-m 16`); its absolute numbers are not comparable with
the wrk rows above. Every figure is the median of 3 rounds of 5 s, the builds interleaved in
every round (`tools/bench/http.sh` with `BASE_DIR`, see [tools/bench/README.md](../tools/bench/README.md));
the spread between rounds was ≤1% except where noted. "Before" is `main` at df90c0b3; fib is
built with Go 1.27.4 from the fib checkout of the same day, hyper is `tools/bench-ref/hyper-ref`.

### Profiles before (perf, `tools/bench/profile.sh`)

- **h2c**: half the server's CPU in user space and about a quarter in malloc/free. About 40 allocations per
  request: a copy of every frame's payload and a `drain` of the read buffer per frame, two
  `Vec`s per decoded header field, the method/path/authority/scheme strings, a temporary list
  with a lowercased name and cleaned value per response header, the `date` and `content-length`
  strings, the encoded block and a payload copy, a `VecDeque` and a copy for the DATA frame, and
  a fresh output buffer handed to the connection after every frame and every response. SipHash
  on the stream table showed up at 3%.
- **HTTP/2 over TLS**: on top of that, every response (and every frame-level flush) became its
  own TLS record.
- **HTTP/1.1, pipelined ×16**: 50% kernel; in user space the head parser (header storage for 100
  fields filled per request), five header-name lookups per request, response encoding and
  malloc/free.
- **HTTP/1.1 keep-alive**: 86% kernel (one read and one write per request); nothing in user space
  above 1.3%.

### Changes

| Change | Crate |
|---|---|
| h2: frames parsed in place from the read buffer (or straight from the read when nothing is carried over); the leftover moved once per read | only-http |
| h2: decoded header fields in one reused buffer (`hpack::Decoder::decode_with`), requests built from slices with one allocation for the header set | only-http |
| h2: header blocks HPACK-encoded straight into the output behind a placeholder frame header; `:status`, `date` (per-second cache) and `content-length` written there instead of into the response's headers | only-http |
| h2: a body that fits one DATA frame and both windows written right after its HEADERS, without the stream queue; queued DATA copied from the queue straight into the output | only-http |
| h2: one write per read: frames and the responses the service sends on the I/O thread are appended to one buffer and handed to the connection when the read is done (a drop guard, so a panicking handler still flushes) | only-http |
| h2: stream table hashed with a multiply-fold hasher instead of SipHash | only-http |
| h2 flow control: receive windows (connection and stream) given back once a quarter is owed instead of two WINDOW_UPDATE frames per DATA frame | only-http |
| HTTP/1: heads parsed with storage for 32 fields first (100 only when that is not enough), framing fields found in one pass | only-http |

### Before / after (requests/s)

| Case | epoll before | epoll after | uring before | uring after |
|---|---:|---:|---:|---:|
| HTTP/1.1 `GET /plaintext`, 256 conns | 722,782 | 729,591 (+1%) | 763,999 | 773,221 (+1%) |
| HTTP/1.1 pipelined ×16, 256 conns | 3,989,430 | **4,263,945 (+7%)** | 4,074,844 | **4,382,038 (+8%)** |
| HTTP/1.1 `GET /json`, 256 conns | 719,339 | 726,737 (+1%) | 761,864 | 770,710 (+1%) |
| h2c, 64 conns × 16 streams | 2,277,248 | **4,045,984 (1.78×)** | 2,237,200 | **4,117,145 (1.84×)** |
| h2c, 16 conns × 128 streams | 2,372,441 | **4,712,691 (1.99×, ±8%)** | 2,306,368 | **5,337,945 (2.31×)** |
| HTTP/2 over TLS 1.3, 64 conns × 16 streams | 1,584,905 (±5%) | **4,027,577 (2.54×)** | 1,535,459 (±11%) | **3,942,486 (2.57×, ±7%)** |

### Against fib and hyper (requests/s, after)

| Case | only-epoll | only-uring | hyper | fib |
|---|---:|---:|---:|---:|
| HTTP/1.1 `GET /plaintext` | 729,591 | 773,221 | 635,806 | 623,863 |
| HTTP/1.1 pipelined ×16 | 4,263,945 | 4,382,038 | 854,841 | 3,741,347 |
| HTTP/1.1 `GET /json` | 726,737 | 770,710 | 625,322 | 596,983 |
| h2c, 64 conns × 16 streams | 4,045,984 | 4,117,145 | 1,031,867 | 3,239,262 |
| h2c, 16 conns × 128 streams | 4,712,691 | 5,337,945 | 1,369,063 | 3,998,168 |
| HTTP/2 over TLS 1.3, 64 × 16 | 4,027,577 | 3,942,486 | – | 3,033,656 |

Before this pass `only` was at 0.70× fib for h2c 64 × 16, 0.59× for 16 × 128 and 0.52× for
HTTP/2 over TLS, and 1.07× for pipelined HTTP/1.1 (with h2load; the earlier 0.8× came from wrk
on the shared VM). Now it is 1.25×, 1.18–1.34×, 1.33× and 1.14–1.17×. hyper-ref has no TLS
listener. During the after runs the server kept its 4 CPUs busy (`profile.sh` reports the
server's CPU time), so these are server-side limits, but h2load with 8 threads is close to its
own ceiling at ~4–5M req/s; the HTTP/2 rows may understate `only`. The keep-alive HTTP/1.1 rows
are kernel-bound (one read and one write per request on loopback) and barely moved.

After the changes the h2c profile is led by request building and header validation (UTF-8
checks), HPACK encoding, `Response::text` (the handler's own allocations) and the kernel (31%);
malloc/free fell from about 25% to ~9%.

## Cryptography (only-crypto): CPU acceleration

The performance pass gave `only-crypto` hardware paths chosen at run time (AES-NI / ARMv8 AES
with eight blocks in flight, AES-GCM with PCLMULQDQ / PMULL GHASH fused into the CTR pass,
SHA-NI / ARMv8 SHA for SHA-1 and SHA-256, PCLMULQDQ folding and SSE4.2 / ARMv8 CRC32 for CRC-32
and CRC-32C, AVX2 ChaCha20) and faster safe-Rust arithmetic (Poly1305 in 44-bit limbs, a dedicated
P-256 field reduction and inversion chain, a signed comb with affine points for `[k]G`, Jacobian
wNAF verification without inversion, Ed25519 double-scalar wNAF, squaring for Curve25519 and the
NIST/RSA Montgomery code, fixed-size RSA Montgomery). "Before" is `main` at 354f3bc5.

Reference host: AMD Ryzen 7 7800X3D (Zen 4), Ubuntu 24.04, Rust 1.100, one core pinned
(`taskset -c 2`), services stopped. `cargo run --release -p only-crypto --example bench` and
`--example pk_bench`; the comparison columns are the RustCrypto crates `only-crypto` replaced
(dev-dependencies, also with run-time CPU detection) and ring 0.17 (assembly for AES-GCM, P-256,
X25519, RSA).

| Operation (MB/s) | Size | before | after | speed-up | RustCrypto | after / RustCrypto |
|---|---:|---:|---:|---:|---:|---:|
| SHA-1 | 16 KiB | 697 | 2 543 | 3.6x | 2 545 | 1.00 |
| SHA-1, BitTorrent piece | 256 KiB | 703 | 2 558 | 3.6x | 2 558 | 1.00 |
| SHA-256 | 16 KiB | 366 | 2 383 | 6.5x | 2 384 | 1.00 |
| SHA-256 | 1400 B | 350 | 2 210 | 6.3x | 2 231 | 0.99 |
| HMAC-SHA1 (STUN message) | 100 B | 184 | 599 | 3.3x | 577 | 1.04 |
| CRC-32 | 1400 B | 2 764 | 18 526 | 6.7x | crc32fast 30 427 | 0.61 |
| CRC-32 | 16 KiB | 2 733 | 20 047 | 7.3x | crc32fast 73 703 | 0.27 |
| CRC-32C | 1400 B | 2 759 | 18 819 | 6.8x | – | – |
| AES-128, one block (CFB chain, KCP) | 16 B | 810 | 3 183 | 3.9x | 3 411 | 0.93 |
| AES-128-CTR | 1400 B | 1 538 | 7 713 | 5.0x | 8 525 | 0.90 |
| AES-128-CTR | 16 KiB | 1 555 | 8 433 | 5.4x | 11 556 | 0.73 |
| AES-128-GCM seal | 1400 B | 355 | 4 409 | 12.4x | aes-gcm 1 953 | 2.26 |
| AES-128-GCM seal | 16 KiB | 364 | 6 484 | 17.8x | aes-gcm 2 178 | 2.98 |
| AES-128-GCM open | 16 KiB | 362 | 5 657 | 15.6x | aes-gcm 2 110 | 2.68 |
| AES-256-GCM seal | 16 KiB | 358 | 5 790 | 16.2x | aes-gcm 2 016 | 2.87 |
| ChaCha20-Poly1305 seal | 1400 B | 556 | 1 086 | 2.0x | 780 | 1.39 |
| ChaCha20-Poly1305 seal | 16 KiB | 588 | 1 757 | 3.0x | 1 969 | 0.89 |
| SHA-512, MD5 (portable, unchanged) | 16 KiB | 537, 690 | 546, 690 | – | 830, 815 | 0.66, 0.85 |
| PBKDF2-HMAC-SHA1, 4096 rounds (kcptun key) | – | 2.06 ms | 0.83 ms | 2.5x | 0.56 ms | – |

| Operation (op/s) | before | after | speed-up | ring | after / ring |
|---|---:|---:|---:|---:|---:|
| Ed25519 sign | 67 635 | 67 794 | 1.00x | 59 306 | 1.14 |
| Ed25519 verify | 18 289 | 27 161 | 1.49x | 32 107 | 0.85 |
| X25519 agreement | 28 865 | 30 945 | 1.07x | 36 998 | 0.84 |
| P-256 ECDSA sign | 23 435 | 34 184 | 1.46x | 76 257 | 0.45 |
| P-256 ECDSA verify | 8 043 | 13 397 | 1.67x | 26 352 | 0.51 |
| P-256 ECDH (incl. point decoding) | 10 075 | 10 390 | 1.03x | 30 150 | 0.34 |
| P-256 key generation | 48 581 | 54 755 | 1.13x | 113 326 | 0.48 |
| P-384 ECDSA sign | 7 650 | 9 443 | 1.23x | 3 363 | 2.81 |
| P-384 ECDSA verify | 2 426 | 3 798 | 1.57x | 1 867 | 2.03 |
| P-384 ECDH | 3 005 | 3 012 | 1.00x | 3 614 | 0.83 |
| RSA-2048 PKCS#1 sign | 871 | 1 199 | 1.38x | 2 441 | 0.49 |
| RSA-2048 PKCS#1 verify | 29 019 | 39 557 | 1.36x | 66 282 | 0.60 |

Protocols on the same host: TLS 1.3 measured in memory (an out-of-tree harness driving
`only_tls::__proto::Connection` and rustls 0.23 + ring with the same self-signed ECDSA P-256
certificate, verified on both sides, no tickets; both ends of each handshake on the one core;
records sealed by one side and opened by the other), and `only_kcp::Crypt` seal + open:

| Operation | before | after | speed-up | rustls + ring | after / rustls |
|---|---:|---:|---:|---:|---:|
| TLS 1.3 full handshakes/s, X25519 | 2 028 | 3 041 | 1.50x | 5 043 | 0.60 |
| TLS 1.3 full handshakes/s, secp256r1 | 1 643 | 2 290 | 1.39x | 5 131 | 0.45 |
| TLS record seal + open, 1 KiB, AES-128-GCM (MB/s) | 170 | 1 652 | 9.7x | 1 838 | 0.90 |
| TLS record seal + open, 1 KiB, AES-256-GCM | 167 | 1 504 | 9.0x | 1 714 | 0.88 |
| TLS record seal + open, 1 KiB, ChaCha20-Poly1305 | 253 | 607 | 2.4x | 928 | 0.65 |
| TLS record seal + open, 16 KiB, AES-128-GCM | 180 | 2 673 | 14.9x | 4 167 | 0.64 |
| TLS record seal + open, 16 KiB, AES-256-GCM | 176 | 2 292 | 13.0x | 3 870 | 0.59 |
| TLS record seal + open, 16 KiB, ChaCha20-Poly1305 | 286 | 832 | 2.9x | 1 527 | 0.54 |
| KCP `aes` (CFB + CRC-32) seal + open, 1400 B (MB/s) | 399 | 541 | 1.4x | – | – |
| KCP `aes-128-gcm` seal + open, 1400 B | 167 | 1 164 | 7.0x | – | – |

aarch64 (Apple M-series laptop, not a quiet host, for the ARMv8 paths only; same examples):
SHA-1 16 KiB 639 → 2 789 MB/s, SHA-256 370 → 2 515, CRC-32 16 KiB 2 330 → 10 474 (crc32fast
89 363 with PMULL folding), AES-128-CTR 16 KiB 2 096 → 19 101, AES-128-GCM seal 16 KiB
701 → 6 315 (open 697 → 5 918), AES-256-GCM seal 693 → 7 658, ChaCha20-Poly1305 16 KiB
651 → 963; P-256 sign 27 171 → 42 254 op/s (0.50x ring), verify 9 689 → 15 703 (0.48x), Ed25519
verify 29 998 → 42 782 (0.90x), X25519 45 451 → 49 613 (0.91x), RSA-2048 sign 1 194 → 1 590
(0.53x).

What is left: AES-GCM and CRC-32 at 16 KiB trail code that uses 256/512-bit VAES and VPCLMULQDQ
(those intrinsics are newer than the MSRV, 1.85); Poly1305 is scalar (ChaCha20-Poly1305 bulk
~0.55x rustls); P-256 ECDH keeps complete formulas for every doubling of a secret scalar; RSA has
no Karatsuba; SHA-512 and MD5 stay portable.

## QUIC and TLS hot paths (performance pass)

Same host (Ryzen 7 7800X3D), services stopped, three rounds with the binaries alternating in each
round; min–max over the rounds.

### QUIC (`crates/only-h3/examples/quic-bench.rs`, loopback, `taskset -c 2-5`)

"before" is `main` with the own QUIC stack (wave D), "after" this pass, "quinn-proto" the version
before wave D built with the same benchmark program.

| Case | before | after | quinn-proto | after / before | after / quinn-proto |
|---|---:|---:|---:|---:|---:|
| bulk, one stream, 2 GiB (Gbit/s) | 3.43–3.69 | 5.74–5.77 | 4.58–4.60 | 1.6x | 1.25x |
| HTTP/3 GET, one connection, 64 in flight (req/s) | 170 824 | 415 084–425 981 | 58 021–58 199 | 2.4x | 7.2x |
| full handshakes, 8 in flight (/s) | 6 485–6 529 | 6 616–6 655 | 6 536–6 674 ¹ | 1.02x | 1.0x |

¹ From the wave D runs: the quinn-proto build's handshake loop failed in this campaign (most
dials timed out), so its earlier figure is shown.

What the profile (`perf record`, both UDP threads saturated) showed and what changed:

- **Pacing** was the bulk limit. The pacer floored the RTT at 1 ms, which caps a loopback path at
  1.25 congestion windows per millisecond, and once its bucket was empty it woke the sender for
  every single packet through the shared timer thread. Per GiB that was 422 766 futex calls,
  181 798 context switches and 195 416 `sendmmsg` calls, with packets leaving one or two at a time
  from the timer thread and the state lock contended between it and the I/O thread. The pacer now
  uses the measured RTT and, when empty, waits until a whole burst (2 ms of window, 10–256
  packets) has refilled, as quinn-proto does: 5 598 futex calls, 9 463 context switches, 47 454
  `sendmmsg` per GiB (quinn-proto: 5 449, 8 857, 49 165). The same per-packet wakeups were what
  held HTTP/3 responses back.
- Bookkeeping per packet: stream ID maps and pending-frame sets hash with a keyed multiply-rotate
  instead of SipHash; `RangeSet::insert` extends the last range with one lookup (packet numbers
  and stream bytes arrive in order); `poll_transmit` allocates its GSO batch buffer once instead
  of growing it; choosing the packet number spaces of a datagram no longer allocates; a received
  datagram's timestamp is reused instead of reading the clock twice more. Together 5.3 → 5.7
  Gbit/s.
- Already fine, unchanged: receive batching (`recvmmsg`, replies corked per batch), GSO batches of
  up to 10 segments, header protection and AEAD (AES-GCM with AES-NI/PCLMULQDQ is ~17% of a UDP
  thread). The receive path still copies each datagram once out of the `recvmmsg` buffer (the
  decrypted packet is the backing store of the `Bytes` handed to the application).

### TLS 1.3 (`crates/only-tls/examples/tls-bench.rs`, in memory, `taskset -c 2`)

New example: both ends in one thread, the same self-signed ECDSA P-256 certificate verified by
the client, no tickets; records sealed by the client and opened by the server. rustls 0.23 + ring
is a dev-dependency of only-tls (default features off, so no aws-lc).

| Case | before | after | rustls + ring | after / rustls |
|---|---:|---:|---:|---:|
| full handshakes/s, X25519 | 3 047–3 055 | 3 040–3 047 | 5 006–5 026 | 0.61 |
| full handshakes/s, secp256r1 | 2 298–2 305 | 2 298–2 301 | 5 125–5 137 | 0.45 |
| seal + open 1 KiB, AES-128-GCM (MB/s) | 1 517–1 575 | 1 513–1 543 | 1 708–1 807 | 0.86 |
| seal + open 16 KiB, AES-128-GCM | 2 627–2 641 | 2 612–2 811 | 4 066–4 110 | 0.64–0.69 |
| seal + open 64 KiB, AES-128-GCM | 2 587–2 673 | 2 787–2 794 | ² | – |
| seal + open 16 KiB, AES-256-GCM | 2 230–2 271 | 2 250–2 380 | 3 693–3 847 | 0.59–0.63 |
| seal + open 64 KiB, AES-256-GCM | 2 271–2 299 | 2 308–2 385 | ² | – |
| seal + open 16 KiB, ChaCha20-Poly1305 | 822–828 | 820–841 | 1 493–1 516 | 0.55 |

² rustls' 64 KiB figure swung between ~2 200 and ~4 100 MB/s from one binary to the next (its
receive side takes at most 16 KiB of plaintext before it must be read out), so it is not given.

- Records: a received record used to be copied into the receive buffer, decrypted there, copied
  out to the caller and the rest of the buffer shifted down. Whole records are now copied once,
  straight into the caller's plaintext buffer, and decrypted where they land; only a partial tail
  goes through the receive buffer. Sealing already encrypted in place in the output and now
  reserves room for all records of a large write at once. That is +5–7% for 16–64 KiB records;
  the rest of the gap to rustls is the AES-GCM and ChaCha20-Poly1305 kernels themselves (ring
  uses VAES/AVX2 and SIMD Poly1305; see the crypto section above).
- Handshakes: the profile has over 98% of the time in curve arithmetic and hashing (P-256 and
  X25519 against ring's assembly); allocation, copying and transcript hashing together are under
  2%, so nothing cheap was left there and the handshake code is unchanged.

## Codec micro benchmarks (in-house vs the replaced crates)

`cargo run --release --manifest-path tools/codec-bench/Cargo.toml [http1|hpack|regex]`, a separate
workspace so httparse, loona-hpack and regex stay out of the libraries. Apple M-series (aarch64,
httparse uses NEON there), best of 5 rounds, ns per operation:

| Operation | only | replaced crate |
|---|---|---|
| HTTP/1 request head, 1 header | 52 | httparse 50 |
| HTTP/1 request head, browser-like, 11 headers | 192–216 | httparse 179–187 |
| HTTP/1 response head, 7 headers | 131–146 | httparse 150–154 |
| same browser-like request delivered in 16-byte reads (resumed vs re-parsed) | 1 694–1 801 | httparse 4 597–4 767 |
| HPACK decode, first request block, Huffman | 1 759 | loona-hpack 132 435 |
| HPACK decode, first request block, raw literals | 764 | loona-hpack 902 |
| HPACK decode, request block, all indexed | 398 | loona-hpack 410 |
| HPACK encode response, warm table | 75 | loona-hpack 304 |
| HPACK encode response, fresh table (only Huffman-codes, loona does not) | 368 | loona-hpack 299 |
| route regexp `[0-9]+` on `1234567` | 5.8 | regex 12.6 |
| route regexp `\d{4}-\d{2}-\d{2}` | 10.7 | regex 13.6 |
| route regexp `[a-z0-9_-]{3,16}` on 14 chars | 16.0 | regex 15.8 |
| compile `\d{4}-\d{2}-\d{2}` | 2 652 | regex 127 213 |

The head parser scans 8 bytes at a time in safe code (no SIMD intrinsics) and stays within ~10%
of httparse on whole heads; heads that arrive in pieces are ~2.7× cheaper because only new lines
are examined. (Before, only-http's HTTP/2 path already decoded Huffman strings itself and passed
raw literals to loona-hpack, so the h2c gain over the previous release is smaller than the
Huffman rows suggest.)

## Deflate (only-deflate vs flate2 / zlib-rs)

`cargo run --release -p only-deflate --example bench [FILE...]` and `--example pmd_echo`, measured
2026-11-15 on a quiet x86-64 host (AMD Ryzen 7 7800X3D, Ubuntu 24.04, Rust 1.100, other services
stopped, pinned to one core with `taskset`), best of 3 rounds of at least 200 ms. "Before" is the
wave A matcher (zlib's greedy/lazy with a 3-byte hash), "after" the performance pass (4-byte
hash, zlib-ng's quick/fast/medium/slow strategies and level table, 8-byte compares, zlib-ng's
chain-jumping search at level 9; a decoder fast path with 64-bit refills and chunked match
copies). Corpora: generated English-like text (4 MB), JSON lines (4 MB), random bytes (1 MB), the
repository's Rust sources (4.2 MB) and glibc's `libc.so.6` (2.1 MB). Inflate decodes zlib-rs's
output of the same level. zlib-rs is flate2 1.1 with the `zlib-rs` backend (it uses AVX2/BMI2
paths chosen at run time; only-deflate is `#![forbid(unsafe_code)]` without SIMD).

| corpus | level | ratio only (before) | ratio zlib-rs | deflate MB/s only before → after | zlib-rs | inflate MB/s only before → after | zlib-rs |
|---|---|---|---|---|---|---|---|
| text | 1 | 2.200 (3.109) | 2.201 | 191 → 549 | 372 | 695 → 862 | 974 |
| text | 3 | 3.601 (3.472) | 3.601 | 78 → 206 | 196 | 840 → 1 105 | 1 092 |
| text | 6 | 4.058 (3.993) | 4.062 | 22 → 38 | 39 | 1 218 → 1 512 | 1 227 |
| text | 9 | 4.186 (4.186) | 4.186 | 5 → 15 | 14 | 1 121 → 1 285 | 1 238 |
| JSON | 1 | 4.838 (5.794) | 4.839 | 611 → 1 249 | 1 125 | 1 811 → 2 157 | 2 319 |
| JSON | 3 | 7.552 (6.614) | 7.552 | 276 → 459 | 463 | 1 944 → 2 275 | 2 518 |
| JSON | 6 | 7.604 (7.588) | 7.604 | 126 → 211 | 215 | 1 948 → 2 282 | 2 484 |
| JSON | 9 | 7.761 (8.024) | 7.761 | 50 → 124 | 117 | 2 001 → 2 270 | 2 542 |
| random | 1 | 1.000 (1.000) | 0.948 | 82 → 138 | 147 | 365 → 528 | 645 |
| random | 6 | 1.000 (1.000) | 1.000 | 79 → 81 | 74 | 15 624 → 15 357 | 36 428 |
| Rust sources | 1 | 2.720 (3.328) | 2.721 | 234 → 491 | 392 | 735 → 845 | 897 |
| Rust sources | 3 | 3.817 (3.624) | 3.817 | 150 → 209 | 199 | 819 → 959 | 964 |
| Rust sources | 6 | 4.079 (4.100) | 4.088 | 58 → 99 | 100 | 883 → 1 028 | 1 015 |
| Rust sources | 9 | 4.132 (4.137) | 4.132 | 15 → 60 | 53 | 938 → 1 070 | 1 056 |
| libc.so.6 | 1 | 1.724 (2.058) | 1.724 | 133 → 285 | 254 | 498 → 577 | 679 |
| libc.so.6 | 3 | 2.109 (2.127) | 2.109 | 94 → 129 | 123 | 481 → 557 | 651 |
| libc.so.6 | 6 | 2.160 (2.222) | 2.160 | 37 → 87 | 84 | 502 → 582 | 672 |
| libc.so.6 | 9 | 2.242 (2.233) | 2.242 | 12 → 41 | 27 | 505 → 570 | 662 |

Across all levels 1..=9 and the five corpora (45 cases) the output is never more than 0.5%
larger than zlib-rs's: identical in 36 cases, up to 0.5% larger with the medium strategy at
levels 5 and 6 on text and sources, smaller on random data at level 1 (a fixed-code block that
does not pay off becomes a stored block). Compression runs at 0.94–1.48x zlib-rs's speed
(geometric mean 1.08x; before: 0.25–0.9x), decompression at 0.82–1.23x (geometric mean 0.95x),
except stored blocks at 0.42x (they are copied twice, into the window and out of it). The levels now mean what they mean in zlib-ng and zlib-rs: level 1 compresses
1.7–2.9x faster than before with output up to 40% larger (zlib's level 1 searched more); levels
2–9 compress 1.03–4x faster, with output from 12% smaller (text and JSON at levels 2–4) to 3.4%
larger (binary data, and JSON at level 9) than before. Decompression is 1.1–1.45x faster than
before.

permessage-deflate echo (`pmd_echo`: client deflate → server inflate → server deflate → client
inflate, level 6, context takeover, JSON-like messages):

| message | before (echoes/s) | after | zlib-rs | after / zlib-rs | wire bytes after (before) / zlib-rs |
|---|---|---|---|---|---|
| 64 B | 478 180 | 643 130 | 349 455 | 1.84 | 5 (5) / 5 |
| 512 B | 50 005 | 82 218 | 78 843 | 1.04 | 80 (83) / 80 |
| 4 KiB | 13 020 | 17 110 | 17 192 | 1.00 | 481 (545) / 481 |
| 64 KiB | 766 | 1 388 | 1 409 | 0.98 | 6 897 (6 721) / 6 897 |

## Userspace TCP/IP stack (only-dpdk): own stack vs smoltcp

`cargo run --release -p only-dpdk --example stack-bench` (public API only, so the same file runs
on both versions): two engines joined by the in-process memory wire, on macOS (Apple silicon, 14
cores). The host was shared with other heavy jobs (load average 20-80), so each version ran five
times, alternating, and the table shows the medians; single runs varied by up to 10x.

| | smoltcp 0.12 (before) | own stack (after) |
|---|---:|---:|
| TCP echo, one connection, 64 KiB buffers | 75 MB/s | 492 MB/s |
| TCP echo, one connection, 1 MiB buffers | 105 MB/s | 1179 MB/s |
| sequential connections (dial, 1 request/response, close) | 2216/s | 24197/s |
| median time to the first response of a new connection | 152 µs | 36 µs |
| 100 concurrent connections: all established | 8.7 ms | 0.8 ms |
| 100 concurrent connections: request/responses per second | 155 k | 494 k |
| 1000 concurrent connections: all established | 14.1 ms | 10.2 ms |
| 1000 concurrent connections: request/responses per second | 127 k | 662 k |
| UDP request/response (one in flight) | 3.2 k/s | 14.1 k/s |

Part of the gain is the I/O loop rather than the protocol code: the memory wire now wakes the
peer's thread when it sends (before, an idle peer could sleep up to 1 ms per exchange). One run
of the new stack without that wake-up gave 39 / 209 MB/s, 779 connections/s and 759 UDP
round trips/s, so the per-exchange latency was dominated by the sleep, while the bulk and
many-connection numbers already came from the stack (ACK coalescing per burst, no per-iteration
scan of connections, a timer heap). Against the Linux kernel in Docker (AF_PACKET on a veth,
`tests/kernel_peer.rs`, release build): a 4 MiB window over a 20 ms RTT echoes 32 MiB at about
70 MB/s each way, 500 concurrent connections echo 32 KiB each in about 0.3 s, and with `netem` 2%
loss, 2 ms delay and 10% reordering both ways 8 MiB echo at about 1.6 MB/s with the kernel's
SACK counters moving. The smoltcp version had no SACK or congestion control to compare on that
link.

## What this says

- **TCP echo**: `only` is level with tokio and fib at 64 connections and ahead of both from 256
  connections on, by 1.3–2× at 1024 connections. io_uring is level with epoll for small messages
  and behind it for 16 KiB messages; that gap was not investigated.
- **HTTP/1.1**: 1.25–1.6× hyper and fib without pipelining. With 16 pipelined requests `only` does
  2.3× hyper but is behind fib (~0.8×); why was not investigated. (On the quiet host of the
  2026-11-15 pass, with h2load as the client, it is 1.14–1.17× fib.)
- **HTTP/2**: 2× hyper after the HPACK fix (it was 0.4× before), still behind fib (~0.55×); the
  next costs are per-request allocations in the h2 session. (Fixed by the HTTP hot-path pass of
  2026-11-15: 1.25–1.34× fib for h2c and 1.33× over TLS, see that section.)
- **WebSocket**: ahead of tokio-tungstenite and fib for both message sizes.
- **Memory**: an idle `only` connection costs ~0.6 KB, 8× less than tokio with a 4 KiB buffer and
  1.4–2× fib's. HTTP keep-alive connections are now below fib (0.9 vs 1.6 KB) and far below hyper
  (17 KB). WebSocket connections cost 3.4× fib's (fib stores less per upgraded connection), TLS
  connections 1.3× fib's (rustls buffers).

## Caveats

- One shared VM on a laptop-class Mac; other jobs were running throughout. The `±` columns are the
  honest error bars: several cells moved by 30–50% between rounds. Absolute numbers are not
  meaningful; ratios are indicative, and only large ones.
- Loopback only: no NIC, no real network latency, client and server compete for the same memory
  bandwidth and kernel locks.
- The client side limits some cells (TLS handshakes, the 1024-connection echo rows), which then are
  lower bounds for the server.
- fib and the reference servers were not tuned; fib's 16 KiB echo figure (a fifth of the others)
  was not investigated.
- Not measured: latency percentiles, QUIC/HTTP/3 against quic-go (optional, not done), memory
  under sustained load (only after an exchange), monoio.

Previous report: the M2 TCP echo report (commit `34ab5d5`) is in the git history of this file.
