# Benchmark harness

English | [简体中文](README.zh-CN.md)

The scripts behind [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md): `akio` against tokio, hyper,
monoio and fib (the Go library `akio` is the counterpart of) with the same handlers, pinned to separate
CPUs, several rounds, a fresh server per run. Linux only (taskset, `/proc`, perf).

| Script | What it runs |
|---|---|
| `build.sh` | builds every server and the load generator in release mode into `$CARGO_TARGET_DIR` (default `/tmp/t`); fib-ref needs Go and a fib checkout (`FIB_SRC`, default `/fib`) |
| `http.sh [cases]` | HTTP/1.1 and HTTP/2: `plaintext`, `pipelined` (16 requests in flight per connection), `json`, `h2` (h2c, 64 connections x 16 streams), `h2many` (h2c, 16 x 128), `h2tls` (HTTP/2 over TLS 1.3 with ALPN, 64 x 16), `ws` (WebSocket echo), `wsz` (the same with permessage-deflate, not in the default set) |
| `echo.sh [cases]` | TCP / UDP / TLS echo and TLS handshakes per second; `connect` (not in the default set): new TCP connections per second; on loopback the client's reuse of TIME_WAIT ports bounds it (about 33k/s on gpu51) until the TIME_WAIT table overflows, so compare servers only in runs of their own |
| `ktls.sh` | kernel TLS against akio-tls's own record layer (HTTP/1.1 over TLS, `ktls-bench` example, `ktls` feature; `VETH=1` puts the client behind a veth pair) |
| `ktls-engine.sh` | kernel TLS in the engine (ADR-067): interleaved A/B of TLS echo, handshakes and HTTPS between two builds and `AKIO_KTLS` modes, waiting for a quiet host before each run |
| `uring-eval.sh` | io_uring send mechanisms on a raw ring: `write(2)` vs `IORING_OP_SEND` vs `SEND_ZC`, with and without registered files, by response size (the ignored `eval_server` test of akio-uring; server CPU per request from `/proc`) |
| `numa.sh` | NUMA placement A/B (ADR-088): the same server with `AKIO_NUMA` unset and in each mode of `$MODES` (`spread`, `spread+cpu`, `spread+cpu+incoming` by default), HTTP/1.1, pipelined, h2c and TCP echo, rounds interleaved |
| `shared.sh [cases]` | shared I/O groups (ADR-130): one server with `LISTENERS` (3) HTTP listeners, each with I/O threads of its own against all sharing one group, each also pinned (`AKIO_PIN_IO_THREADS=1`), on epoll and io_uring; HTTP/1.1, pipelined and h2c load over all listeners at once (one h2load each, summed) and HTTP/1.1 on one of them; server threads and CPU per request (`http-bench` with `AKIO_BENCH_LISTENERS`, `AKIO_BENCH_SHARED`); `BACKENDS` may add `rounds`; `MODES` suffixes `-h2pool` (HTTP/2 handlers on the logical pool, `AKIO_BENCH_H2_POOL`), `-cap<N>` (pool capped at N threads, `AKIO_BENCH_POOL_MAX`) and `-pool<N>` (N CPUs kept for the logical pool, `AKIO_POOL_CPUS`) |
| `udp-dgram.sh` | UDP 64 B echo A/B: per-peer listeners of a base and a new build, connectionless `serve_datagrams` listeners on epoll and io_uring (`bench-server udp-dgram`, ADR-065; server CPU per request from `/proc`) |
| `stream-compress.sh [tput] [mem]` | compressed streamed responses A/B (ADR-074): a base build and the new one with `Compress::stream` off and on, per coding: throughput of 16 small events and of 16 x 16 KiB writes per response (h2load, server CPU per response, body bytes), and server RSS per held server-sent-events stream after 3 and 6000 events (`stream-bench` example) |
| `mem.sh [proto:kind:conns ...]` | server memory per idle connection |
| `profile.sh <case> <kind> [secs]` | perf profile of one server under one load (`h1`, `pipelined`, `h2`, `h2tls`, `ws`, `tcp`), with the CPUs the server kept busy |
| `all.sh <dir>` | everything above, raw TSV into `<dir>` |
| `summarize.py` | turns the TSV rows into the tables of BENCHMARKS.md |
| `docker.sh 'cmd'` | runs a command in the `akio-bench` image (`Dockerfile`: rust + wrk + h2load + perf + Go) |

The servers are `crates/akio-http/examples/http-bench.rs` and `crates/akio/examples/bench-server.rs`
for `akio` (`akio-epoll`, `akio-uring`), and the out-of-tree references in `tools/bench-ref/`
(`tokio-ref`, `hyper-ref`, `monoio-ref`, `fib-ref`). `monoio-ref` (monoio 0.2, thread-per-core: one
runtime and one `SO_REUSEPORT` listener per thread) serves TCP echo and HTTP/1.1 (`/plaintext`,
`/json`, pipelining; httparse, no HTTP/2); it runs as `monoio-uring` (its io_uring driver) and
`monoio-epoll` (its legacy epoll driver).

## Load generators

HTTP/1.1 uses `wrk` (pipelining through a Lua script) when it is installed, otherwise `h2load
--h1` (pipelining with `-m 16`); force one with `H1GEN=wrk|h2load`. HTTP/2 always uses `h2load`.
The two HTTP/1.1 generators give different absolute numbers, so compare only runs made with the
same one.

## Knobs

Environment variables, see `lib.sh`: `SRV_CPUS` / `CLI_CPUS` (CPU lists for `taskset`),
`THREADS` / `CLI_THREADS`, `SECS` (seconds per run), `RUNS` (rounds; tables show the median),
`KINDS` (servers, e.g. `"akio-epoll fib"`), `OUT` (TSV file), `HCONNS` (HTTP/1.1 connections),
`MAX_BUSY` / `QUIET_WAIT` (wait for an idle host before each run). Each server gets a fresh port
above `PORT` (default 7400); ports still held by sockets of an earlier run are skipped, since a
bare host's ephemeral range (1024–65535) covers them.

A/B runs: copy the binaries of the old revision (`http-bench`, `bench-server`) into a directory
and set `BASE_DIR` to it; they then run as `base-epoll` / `base-uring` next to the current build,
interleaved in every round.

## On a bare Linux host

The 2026-11-15 HTTP numbers were taken on a Ryzen 7 7800X3D (8 cores, 16 threads) without
Docker: server on CPUs 0-3 (4 I/O threads), load generator on CPUs 4-7 and 12-15 (the SMT
siblings of the server's cores, 8-11, left idle), Go installed from the official tarball for
fib-ref.

```sh
export CARGO_TARGET_DIR=/path/to/target
cargo build --release -p akio-http --example http-bench
(cd tools/bench-ref/hyper-ref && CARGO_TARGET_DIR=$CARGO_TARGET_DIR/ref cargo build --release)
(cd tools/bench-ref/monoio-ref && CARGO_TARGET_DIR=$CARGO_TARGET_DIR/ref cargo build --release)
cp -r tools/bench-ref/fib-ref /tmp/fibref && cd /tmp/fibref &&
  go mod edit -replace github.com/lesismal/fib=/path/to/fib && go build -o $CARGO_TARGET_DIR/fib-ref . && cd -
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 THREADS=4 CLI_THREADS=8 SECS=5 RUNS=3 \
  KINDS="akio-epoll akio-uring hyper fib" tools/bench/http.sh plaintext,pipelined,json,h2,h2many,h2tls
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 tools/bench/profile.sh h2 akio-epoll   # needs perf
```
