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
  2.3× hyper but is behind fib (~0.8×); why was not investigated.
- **HTTP/2**: 2× hyper after the HPACK fix (it was 0.4× before), still behind fib (~0.55×); the
  next costs are per-request allocations in the h2 session.
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
