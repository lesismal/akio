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

### TLS 1.3 in memory (`crates/only-tls/examples/tls-bench.rs`, CPU 2)

Both ends in one thread, the same self-signed ECDSA P-256 certificate verified by the client, no
tickets; records sealed by the client and opened by the server. rustls 0.23 + ring is a
dev-dependency.

| Case | only-tls | rustls + ring | only / rustls |
|---|---:|---:|---:|
| full handshakes/s, X25519 | 5,027 | 5,025 | 1.00 |
| full handshakes/s, secp256r1 | 4,552 | 5,126 | 0.89 |
| full handshakes/s, X25519, RSA-2048 certificate ³ | 2,586 | 1,800 | 1.44 |
| seal + open 1 KiB, AES-128-GCM (MB/s) | 2,697 | 1,760 | 1.53 |
| seal + open 16 KiB, AES-128-GCM | 6,603 | 3,994 | 1.65 |
| seal + open 64 KiB, AES-128-GCM | 6,734 | ² | – |
| seal + open 1 KiB, AES-256-GCM | 2,514 | 1,702 | 1.48 |
| seal + open 16 KiB, AES-256-GCM | 5,873 | 3,795 | 1.55 |
| seal + open 64 KiB, AES-256-GCM | 5,858 | ² | – |
| seal + open 1 KiB, ChaCha20-Poly1305 | 931 | 913 | 1.02 |
| seal + open 16 KiB, ChaCha20-Poly1305 | 2,141 | 1,511 | 1.42 |
| seal + open 64 KiB, ChaCha20-Poly1305 | 2,124 | 1,529 | 1.39 |

² rustls at 64 KiB swings between ~2,200 and ~3,900 MB/s from run to run (its receive side takes
at most 16 KiB of plaintext before it must be read out), so no ratio is given.

³ The server signs with RSA-PSS, the client verifies the certificate and that signature (the
RSA pass, below); 775/s (0.43×) before it.

Handshakes were 3,055 (X25519) and 2,306 (secp256r1) per second before the P-256 / X25519
pass (0.61× and 0.45×; History). The handshake profile is still dominated by curve arithmetic:
the P-256 doubling of the ECDH and the signature verification, then the X25519 ladder. The AES-GCM
records run on the VAES + VPCLMULQDQ + AVX-512 kernel and are sealed and opened out of place (the
AEAD reads the caller's plaintext or the received record and writes the output once; before, a
copy came first, 30% of the 16 KiB profile): 2.4× the previous release at 16–64 KiB (AES-128
2,739 → 6,603 MB/s at 16 KiB, 0.69× → 1.65× rustls + ring). ChaCha20-Poly1305 records run on the
AVX-512 ChaCha20 and IFMA Poly1305 kernels, also out of place: 0.55× → 1.42× rustls + ring at
16 KiB (below).

### Cryptography (`only-crypto`, `--example bench` and `--example pk_bench`, CPU 2)

Hardware paths detected at run time: AES-NI, PCLMULQDQ, SHA-NI, SSE4.2 CRC32, AVX2, VAES +
VPCLMULQDQ + AVX-512 (AES-GCM from 256 bytes, CRC folding from 512 bytes), BMI2 + ADX. The comparison
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
| RSA-2048 PKCS#1 sign | 3,910 | 2,429 | 1.61 |
| RSA-2048 PKCS#1 verify | 79,970 | 65,600 | 1.22 |
| RSA-3072 PKCS#1 sign | 1,455 | 787 | 1.85 |
| RSA-4096 PKCS#1 sign | 755 | 345 | 2.19 |

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
limit), memory operands for the IFMA instructions (half the throughput on Zen 4).

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

What is left: AES-GCM messages of 1 KiB to 1.4 KiB are at 0.96–1.11× ring (the wide kernel's
fixed cost; the tail after the last 256-byte group runs on the 128-bit path); CPUs with VAES but
without AVX-512 (Zen 3, Alder Lake) use the 128-bit path; the TLS record layer still zero-fills
the output before the AEAD writes it (about 9% of a 16 KiB record); ChaCha20-Poly1305 below 1.4 KiB
is at 0.82–0.96× ring and CPUs without AVX-512 / IFMA run the AVX2 ChaCha20 with a scalar
Poly1305 (no AVX2 Poly1305); P-256
ECDH is at 1.12× ring (a doubling ~348 cycles, about 44 per product whatever their order);
Ed25519 verification is portable; RSA's two CRT halves are not interleaved in one IFMA block,
and without IFMA RSA-2048 signing is at parity with ring; SHA-512 and MD5 are portable.

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
- **Wide AES-GCM and CRC** (this host, `a1cc9b49` → after): AES-GCM on VAES + VPCLMULQDQ +
  AVX-512 (512-bit, chosen over 256-bit by measurement) 2.3–2.5× at 16–64 KiB (AES-128 seal
  16 KiB 6,455 → 15,048 MB/s, 0.51× → 1.19× ring), the fused tail 1.8–2.1× at 64 B; TLS 1.3
  records sealed and opened out of place, 2.4× at 16 KiB (0.69× → 1.65× rustls + ring); CRC-32
  folding on 512-bit registers 16 KiB 19,992 → 74,885 MB/s (0.27× → 1.02× crc32fast).
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
cargo run --release -p only-dpdk --example stack-bench
```

`summarize.py` turns the TSV rows of the network scripts into tables. `start_server` skips ports
that client sockets of an earlier run still hold (bare Linux's ephemeral range starts at 1024).
