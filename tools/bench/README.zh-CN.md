# 基准测试脚本

[English](README.md) | 简体中文

[docs/BENCHMARKS.zh-CN.md](../../docs/BENCHMARKS.zh-CN.md) 背后的脚本：`only` 与 tokio、hyper、fib（`only`
所对应的 Go 库）使用相同的处理逻辑，绑定到不同的 CPU，跑多轮，每次运行都启动新的服务端。仅限 Linux
（taskset、`/proc`、perf）。

| 脚本 | 内容 |
|---|---|
| `build.sh` | 以 release 模式把所有服务端和压测客户端编译到 `$CARGO_TARGET_DIR`（默认 `/tmp/t`）；fib-ref 需要 Go 和 fib 源码（`FIB_SRC`，默认 `/fib`） |
| `http.sh [cases]` | HTTP/1.1 与 HTTP/2：`plaintext`、`pipelined`（每连接 16 个请求在途）、`json`、`h2`（h2c，64 连接 × 16 流）、`h2many`（h2c，16 × 128）、`h2tls`（TLS 1.3 + ALPN 上的 HTTP/2，64 × 16）、`ws`（WebSocket echo） |
| `echo.sh [cases]` | TCP / UDP / TLS echo，以及每秒 TLS 握手数 |
| `mem.sh [proto:kind:conns ...]` | 服务端每个空闲连接的内存 |
| `profile.sh <case> <kind> [secs]` | 某个服务端在某种负载下的 perf 剖析（`h1`、`pipelined`、`h2`、`h2tls`、`ws`、`tcp`），并给出服务端占满了几个 CPU |
| `all.sh <dir>` | 以上全部，原始 TSV 写到 `<dir>` |
| `summarize.py` | 把 TSV 行整理成 BENCHMARKS 里的表格 |
| `docker.sh 'cmd'` | 在 `only-bench` 镜像（`Dockerfile`：rust + wrk + h2load + perf + Go）中运行命令 |

`only` 的服务端是 `crates/only-http/examples/http-bench.rs` 和 `crates/only/examples/bench-server.rs`
（`only-epoll`、`only-uring`），参照实现放在仓库外的工作区 `tools/bench-ref/` 中（`tokio-ref`、
`hyper-ref`、`fib-ref`）。

## 压测客户端

HTTP/1.1 在装有 `wrk` 时用 `wrk`（通过 Lua 脚本做流水线），否则用 `h2load --h1`（用 `-m 16` 做流水线）；
可用 `H1GEN=wrk|h2load` 指定。HTTP/2 一律用 `h2load`。两种 HTTP/1.1 客户端得到的绝对数值不同，
只比较用同一种客户端得到的结果。

## 参数

环境变量，见 `lib.sh`：`SRV_CPUS` / `CLI_CPUS`（传给 `taskset` 的 CPU 列表）、`THREADS` / `CLI_THREADS`、
`SECS`（每次运行的秒数）、`RUNS`（轮数，表格取中位数）、`KINDS`（服务端，如 `"only-epoll fib"`）、
`OUT`（TSV 文件）、`HCONNS`（HTTP/1.1 连接数）、`MAX_BUSY` / `QUIET_WAIT`（每次运行前等待主机空闲）。
每个服务端使用 `PORT`（默认 7400）之上的新端口；之前运行的套接字仍占用的端口会被跳过，因为裸机的
临时端口范围（1024–65535）覆盖了它们。

A/B 对比：把旧版本的二进制（`http-bench`、`bench-server`）复制到一个目录，并把 `BASE_DIR` 设为该目录；
它们会以 `base-epoll` / `base-uring` 的名字与当前构建一起、在每一轮中交替运行。

## 在裸机 Linux 上

2026-11-15 的 HTTP 数据在一台 Ryzen 7 7800X3D（8 核 16 线程）上测得，不经 Docker：服务端在 CPU 0-3
（4 个 I/O 线程），压测客户端在 CPU 4-7 与 12-15（服务端核心的 SMT 兄弟线程 8-11 保持空闲），fib-ref
所需的 Go 从官方 tarball 安装。

```sh
export CARGO_TARGET_DIR=/path/to/target
cargo build --release -p only-http --example http-bench
(cd tools/bench-ref/hyper-ref && CARGO_TARGET_DIR=$CARGO_TARGET_DIR/ref cargo build --release)
cp -r tools/bench-ref/fib-ref /tmp/fibref && cd /tmp/fibref &&
  go mod edit -replace github.com/lesismal/fib=/path/to/fib && go build -o $CARGO_TARGET_DIR/fib-ref . && cd -
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 THREADS=4 CLI_THREADS=8 SECS=5 RUNS=3 \
  KINDS="only-epoll only-uring hyper fib" tools/bench/http.sh plaintext,pipelined,json,h2,h2many,h2tls
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 tools/bench/profile.sh h2 only-epoll   # 需要 perf
```
