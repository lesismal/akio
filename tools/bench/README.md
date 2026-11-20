# Benchmark harness

English | [简体中文](README.zh-CN.md)

The scripts behind [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md): `only` against tokio, hyper
and fib (the Go library `only` is the counterpart of) with the same handlers, pinned to separate
CPUs, several rounds, a fresh server per run. Linux only (taskset, `/proc`, perf).

| Script | What it runs |
|---|---|
| `build.sh` | builds every server and the load generator in release mode into `$CARGO_TARGET_DIR` (default `/tmp/t`); fib-ref needs Go and a fib checkout (`FIB_SRC`, default `/fib`) |
| `http.sh [cases]` | HTTP/1.1 and HTTP/2: `plaintext`, `pipelined` (16 requests in flight per connection), `json`, `h2` (h2c, 64 connections x 16 streams), `h2many` (h2c, 16 x 128), `h2tls` (HTTP/2 over TLS 1.3 with ALPN, 64 x 16), `ws` (WebSocket echo), `wsz` (the same with permessage-deflate, not in the default set) |
| `echo.sh [cases]` | TCP / UDP / TLS echo and TLS handshakes per second |
| `ktls.sh` | kernel TLS against only-tls's own record layer (HTTP/1.1 over TLS, `ktls-bench` example, `ktls` feature; `VETH=1` puts the client behind a veth pair) |
| `uring-eval.sh` | io_uring send mechanisms on a raw ring: `write(2)` vs `IORING_OP_SEND` vs `SEND_ZC`, with and without registered files, by response size (the ignored `eval_server` test of only-uring; server CPU per request from `/proc`) |
| `udp-dgram.sh` | UDP 64 B echo A/B: per-peer listeners of a base and a new build, connectionless `serve_datagrams` listeners on epoll and io_uring (`bench-server udp-dgram`, ADR-065; server CPU per request from `/proc`) |
| `mem.sh [proto:kind:conns ...]` | server memory per idle connection |
| `profile.sh <case> <kind> [secs]` | perf profile of one server under one load (`h1`, `pipelined`, `h2`, `h2tls`, `ws`, `tcp`), with the CPUs the server kept busy |
| `all.sh <dir>` | everything above, raw TSV into `<dir>` |
| `summarize.py` | turns the TSV rows into the tables of BENCHMARKS.md |
| `docker.sh 'cmd'` | runs a command in the `only-bench` image (`Dockerfile`: rust + wrk + h2load + perf + Go) |

The servers are `crates/only-http/examples/http-bench.rs` and `crates/only/examples/bench-server.rs`
for `only` (`only-epoll`, `only-uring`), and the out-of-tree references in `tools/bench-ref/`
(`tokio-ref`, `hyper-ref`, `fib-ref`).

## Load generators

HTTP/1.1 uses `wrk` (pipelining through a Lua script) when it is installed, otherwise `h2load
--h1` (pipelining with `-m 16`); force one with `H1GEN=wrk|h2load`. HTTP/2 always uses `h2load`.
The two HTTP/1.1 generators give different absolute numbers, so compare only runs made with the
same one.

## Knobs

Environment variables, see `lib.sh`: `SRV_CPUS` / `CLI_CPUS` (CPU lists for `taskset`),
`THREADS` / `CLI_THREADS`, `SECS` (seconds per run), `RUNS` (rounds; tables show the median),
`KINDS` (servers, e.g. `"only-epoll fib"`), `OUT` (TSV file), `HCONNS` (HTTP/1.1 connections),
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
cargo build --release -p only-http --example http-bench
(cd tools/bench-ref/hyper-ref && CARGO_TARGET_DIR=$CARGO_TARGET_DIR/ref cargo build --release)
cp -r tools/bench-ref/fib-ref /tmp/fibref && cd /tmp/fibref &&
  go mod edit -replace github.com/lesismal/fib=/path/to/fib && go build -o $CARGO_TARGET_DIR/fib-ref . && cd -
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 THREADS=4 CLI_THREADS=8 SECS=5 RUNS=3 \
  KINDS="only-epoll only-uring hyper fib" tools/bench/http.sh plaintext,pipelined,json,h2,h2many,h2tls
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 tools/bench/profile.sh h2 only-epoll   # needs perf
```
