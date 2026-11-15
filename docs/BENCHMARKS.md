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
only-tls does 0.45–0.61× rustls' handshakes, see below).

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

### TLS 1.3 in memory (`crates/only-tls/examples/tls-bench.rs`, CPU 2)

Both ends in one thread, the same self-signed ECDSA P-256 certificate verified by the client, no
tickets; records sealed by the client and opened by the server. rustls 0.23 + ring is a
dev-dependency.

| Case | only-tls | rustls + ring | only / rustls |
|---|---:|---:|---:|
| full handshakes/s, X25519 | 3,041 | 5,015 | 0.61 |
| full handshakes/s, secp256r1 | 2,300 | 5,126 | 0.45 |
| seal + open 1 KiB, AES-128-GCM (MB/s) | 1,556 | 1,782 | 0.87 |
| seal + open 16 KiB, AES-128-GCM | 2,790 | 4,090 | 0.68 |
| seal + open 64 KiB, AES-128-GCM | 2,784 | ² | – |
| seal + open 1 KiB, AES-256-GCM | 1,449 | 1,678 | 0.86 |
| seal + open 16 KiB, AES-256-GCM | 2,371 | 3,821 | 0.62 |
| seal + open 64 KiB, AES-256-GCM | 2,342 | ² | – |
| seal + open 1 KiB, ChaCha20-Poly1305 | 598 | 905 | 0.66 |
| seal + open 16 KiB, ChaCha20-Poly1305 | 843 | 1,500 | 0.56 |
| seal + open 64 KiB, ChaCha20-Poly1305 | 839 | 1,167 | 0.72 |

² rustls at 64 KiB swings between ~2,200 and ~3,900 MB/s from run to run (its receive side takes
at most 16 KiB of plaintext before it must be read out), so no ratio is given.

The handshake profile is >98% curve arithmetic and hashing (P-256 and X25519 against ring's
assembly); the record gap is the AES-GCM and ChaCha20-Poly1305 kernels (ring uses VAES/AVX2 and a
SIMD Poly1305).

### Cryptography (`only-crypto`, `--example bench` and `--example pk_bench`, CPU 2)

Hardware paths detected at run time: AES-NI, PCLMULQDQ, SHA-NI, SSE4.2 CRC32, AVX2. The comparison
columns are the RustCrypto crates `only-crypto` replaced (also with run-time CPU detection;
crc32fast for CRC-32) and ring 0.17 for public-key operations.

| Operation (MB/s) | Size | only-crypto | RustCrypto | ratio |
|---|---:|---:|---:|---:|
| SHA-1 | 16 KiB | 2,546 | 2,545 | 1.00 |
| SHA-1, BitTorrent piece | 256 KiB | 2,558 | 2,558 | 1.00 |
| SHA-256 | 16 KiB | 2,365 | 2,371 | 1.00 |
| SHA-256 | 1400 B | 2,189 | 2,221 | 0.99 |
| HMAC-SHA1 (STUN message) | 100 B | 583 | 624 | 0.94 |
| CRC-32 | 1400 B | 18,524 | crc32fast 30,448 | 0.61 |
| CRC-32 | 16 KiB | 20,019 | crc32fast 73,524 | 0.27 |
| CRC-32C | 1400 B | 18,828 | – | – |
| AES-128, one block (CFB chain, KCP) | 16 B | 3,197 | 3,486 | 0.92 |
| AES-128-CTR | 1400 B | 7,716 | 8,493 | 0.91 |
| AES-128-CTR | 16 KiB | 8,393 | 11,546 | 0.73 |
| AES-128-GCM seal | 1400 B | 4,421 | aes-gcm 1,955 | 2.26 |
| AES-128-GCM seal | 16 KiB | 6,533 | aes-gcm 2,178 | 3.00 |
| AES-128-GCM open | 16 KiB | 5,643 | aes-gcm 2,109 | 2.67 |
| AES-256-GCM seal | 16 KiB | 5,761 | aes-gcm 2,014 | 2.86 |
| ChaCha20-Poly1305 seal | 1400 B | 1,083 | 778 | 1.39 |
| ChaCha20-Poly1305 seal | 16 KiB | 1,755 | 1,969 | 0.89 |
| SHA-512 (portable) | 16 KiB | 540 | 823 | 0.66 |
| MD5 (portable) | 16 KiB | 686 | 815 | 0.84 |
| base64 encode | 1400 B | 2,059 | 2,739 | 0.75 |
| PBKDF2-HMAC-SHA1, 4096 rounds (kcptun key) | – | 0.83 ms | 0.57 ms | – |

| Operation (op/s) | only-crypto | ring | ratio |
|---|---:|---:|---:|
| Ed25519 sign | 67,763 | 58,969 | 1.15 |
| Ed25519 verify | 26,882 | 31,938 | 0.84 |
| X25519 agreement | 30,671 | 36,564 | 0.84 |
| P-256 ECDSA sign | 34,137 | 75,699 | 0.45 |
| P-256 ECDSA verify | 13,418 | 26,190 | 0.51 |
| P-256 ECDH | 10,363 | 29,958 | 0.35 |
| P-256 key generation | 54,664 | 112,178 | 0.49 |
| P-384 ECDSA sign | 9,358 | 3,333 | 2.81 |
| P-384 ECDSA verify | 3,777 | 1,848 | 2.04 |
| P-384 ECDH | 2,999 | 3,582 | 0.84 |
| P-384 key generation | 15,743 | 3,588 | 4.39 |
| RSA-2048 PKCS#1 sign | 1,192 | 2,429 | 0.49 |
| RSA-2048 PKCS#1 verify | 39,275 | 65,868 | 0.60 |

What is left: AES-GCM and CRC-32 at 16 KiB trail code that uses 256/512-bit VAES and VPCLMULQDQ
(newer than the MSRV, 1.85); Poly1305 is scalar; P-256 keeps complete formulas for the doublings
of a secret scalar; RSA has no Karatsuba; SHA-512 and MD5 are portable.

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
| random | 6 | 1.000 / 1.000 | 80 / 76 | 15,222 / 36,328 |
| Rust sources | 1 | 2.731 / 2.731 | 486 / 387 | 846 / 889 |
| Rust sources | 3 | 3.833 / 3.833 | 206 / 198 | 959 / 958 |
| Rust sources | 6 | 4.098 / 4.106 | 99 / 100 | 1,030 / 1,013 |
| Rust sources | 9 | 4.151 / 4.151 | 60 / 54 | 1,073 / 1,048 |
| libc.so.6 | 1 | 1.724 / 1.724 | 280 / 250 | 577 / 670 |
| libc.so.6 | 3 | 2.109 / 2.109 | 126 / 123 | 556 / 643 |
| libc.so.6 | 6 | 2.160 / 2.160 | 85 / 84 | 581 / 663 |
| libc.so.6 | 9 | 2.242 / 2.242 | 41 / 29 | 569 / 653 |

Output is never more than 0.2% larger than zlib-rs's in these cells; compression runs at
0.94–1.5× zlib-rs's speed, decompression at 0.83–1.25×, except stored blocks (random data at
levels ≥3) at 0.42×, because they are copied twice (into the window and out of it).

permessage-deflate echo (client deflate → server inflate → server deflate → client inflate,
level 6, context takeover, JSON-like messages):

| Message | only-deflate (echoes/s) | zlib-rs | ratio | wire bytes (both) |
|---|---:|---:|---:|---:|
| 64 B | 628,894 | 348,873 | 1.80 | 5 |
| 512 B | 80,625 | 79,044 | 1.02 | 80 |
| 4 KiB | 17,166 | 17,147 | 1.00 | 481 |
| 64 KiB | 1,375 | 1,404 | 0.98 | 6,897 |

### Codec micro benchmarks (`tools/codec-bench`, CPU 2, ns per operation)

A separate workspace, so httparse, loona-hpack and regex stay out of the libraries.

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
| route regexp `[0-9]+` on `1234567` | 8.5 | regex 15.9 |
| route regexp `\d{4}-\d{2}-\d{2}` | 11.7 | regex 16.6 |
| route regexp `[a-z0-9_-]{3,16}` on 14 chars | 17.4 | regex 19.8 |
| compile `\d{4}-\d{2}-\d{2}` | 2,185 | regex 112,199 |

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
BENCH_LEVELS=1,3,6,9 cargo run --release -p only-deflate --example bench SOURCES libc.so.6
cargo run --release -p only-deflate --example pmd_echo
cargo run --release --manifest-path tools/codec-bench/Cargo.toml
cargo run --release -p only-dpdk --example stack-bench
```

`summarize.py` turns the TSV rows of the network scripts into tables. `start_server` skips ports
that client sockets of an earlier run still hold (bare Linux's ephemeral range starts at 1024).
