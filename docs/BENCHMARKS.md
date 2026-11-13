# Benchmarks (M2 report)

English | [简体中文](BENCHMARKS.zh-CN.md)

Measured 2026-11-14 on commit `34ab5d5`. **Read the caveats first**: this is one machine, one set of
runs, and no variance was recorded. Treat differences under ~10% as noise and the whole report as
"same class or not", not as a ranking.

## Setup

- Linux 6.12.5 (linuxkit, a Docker VM on an Apple-silicon Mac), aarch64, 14 vCPUs, loopback.
- Server pinned to CPUs 0–3 (4 threads); load generator `echo-bench` pinned to CPUs 4–11
  (8 client threads). Closed loop: every connection sends one message, waits for the reply, repeats.
- 1 s warm-up, then 5 s × 3 runs per figure; the table shows the **median** req/s.
- Servers, all with 4 threads and the same handler (echo, or the blocking handlers below):
  - **flash-epoll**, **flash-uring**: `crates/flash/examples/bench-server` (`Backend::Epoll` / `IoUring`).
  - **tokio**: `tools/bench-ref/tokio-ref`, multi-thread runtime with 4 workers, one task per
    connection (UDP: one task looping on `recv_from`/`send_to`); TLS through tokio-rustls.
  - **fib**: `tools/bench-ref/fib-ref`, default fib config (Go 1.27.3, `GOMAXPROCS` follows the
    4-CPU affinity). fib has no TLS row because the reference server for it was not written.
- TLS: TLS 1.3, rustls with the `ring` provider on both flash and tokio, self-signed certificate,
  the client does not verify it, handshakes are completed before the measurement.
- Reproduce: `tools/bench/run.sh` (see its header; the build steps are in the commit that added it).

## Results (requests per second, median of 3)

### TCP echo

| Load | flash-epoll | flash-uring | tokio | fib |
|---|---:|---:|---:|---:|
| 1 connection, 64 B | 35,255 | 35,189 | 34,714 | 31,581 |
| 64 connections, 64 B | 532,588 | 524,265 | **628,231** | 479,041 |
| 512 connections, 64 B | **1,030,385** | 957,627 | 858,882 | 625,446 |
| 64 connections, 16 KiB | 422,596 | 400,807 | **489,537** | 77,559 |

### TLS 1.3 echo, 64 connections, 1 KiB

| flash-epoll | flash-uring | tokio |
|---:|---:|---:|
| 468,314 | 500,861 | 510,563 |

### UDP echo, 64 sockets, 64 B

| flash | tokio | fib |
|---:|---:|---:|
| 578,665 | 437,746 | 565,353 |

### 5 ms of blocking work per request, 256 connections

| Handler | flash-epoll | flash-uring | tokio | fib |
|---|---:|---:|---:|---:|
| blocks on the I/O thread / runtime worker | 549 | 548 | 631 | n/a |
| work on the logical pool / `spawn_blocking` | 32,078 | 31,802 | 36,870 | n/a |
| fib: handler blocks (fib runs handlers on its worker pool) | | | | 31,415 |

Four threads each blocking 5 ms can serve at most 800 req/s, which is what the first row shows;
256 connections each waiting 5 ms cap the second row at ~51,000 req/s.

## What this says

- **Same class as fib and tokio for TCP echo.** flash is ahead of fib at every TCP load measured
  here (1.1× at 64 connections, 1.6× at 512, and far ahead at 16 KiB), and ahead of tokio at 512
  connections but **behind tokio at 64 connections (−15%) and at 16 KiB (−14%)**. The M1 target
  "same class as fib's echo" is met on this machine; "better than tokio" is not shown.
- **io_uring is not faster than epoll here.** In this echo workload flash-uring was equal or up to
  ~7% slower, except TLS where it was ~7% faster. The earlier single-thread server-bound run
  (docs/DEV-PLAN.md) showed io_uring ahead by 10–25%, so the advantage appears when the server, not
  the client, is the bottleneck. With 4 server threads and 8 client threads the client side is
  probably limiting the 512-connection figures, which makes them an upper bound for the server,
  not a precise value.
- **The logical pool does what it is for.** A handler that blocks the I/O thread drops flash (and
  tokio) from hundreds of thousands to ~550 req/s; moving the same work to `spawn_blocking` gives
  ~58× that, within 15% of tokio's `spawn_blocking`.
- fib's blocking row is high because fib calls handlers on a worker pool by default; flash's default
  is the opposite (inline, non-blocking) by design, so blocking code has to be moved explicitly.
- UDP: flash and fib are level; the tokio reference is a single `recv_from` loop, the simplest
  possible tokio server, so that row says little about tokio's best case.

## Caveats

- One VM on a laptop-class Mac: scheduler noise, a shared host, loopback only (no NIC, no real
  network latency). Absolute numbers are not meaningful; ratios are indicative.
- No per-run spread was stored, only the median. A rerun can move any single cell by several percent.
  Earlier smoke runs (1 s × 1) had flash-uring TLS slower than flash-epoll; this run has the
  opposite order: they are within noise of each other.
- The gaps flash vs tokio at 64 connections and 16 KiB were **not profiled**; no cause is claimed.
- fib's 16 KiB result (about a fifth of the others) was not investigated; it may be a default
  buffer setting, not a property of fib in general. fib was not tuned.
- Memory, latency percentiles, connection-count scaling beyond 512, and TLS handshake rate were not
  measured. The TLS figures are record throughput on established connections.
- monoio was not run.
