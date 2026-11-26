# 基准测试脚本

[English](README.md) | 简体中文

[docs/BENCHMARKS.zh-CN.md](../../docs/BENCHMARKS.zh-CN.md) 背后的脚本：`akio` 与 tokio、hyper、monoio、fib（`akio`
所对应的 Go 库）使用相同的处理逻辑，绑定到不同的 CPU，跑多轮，每次运行都启动新的服务端。仅限 Linux
（taskset、`/proc`、perf）。

| 脚本 | 内容 |
|---|---|
| `build.sh` | 以 release 模式把所有服务端和压测客户端编译到 `$CARGO_TARGET_DIR`（默认 `/tmp/t`）；fib-ref 需要 Go 和 fib 源码（`FIB_SRC`，默认 `/fib`） |
| `http.sh [cases]` | HTTP/1.1 与 HTTP/2：`plaintext`、`pipelined`（每连接 16 个请求在途）、`json`、`h2`（h2c，64 连接 × 16 流）、`h2many`（h2c，16 × 128）、`h2tls`（TLS 1.3 + ALPN 上的 HTTP/2，64 × 16）、`ws`（WebSocket echo）、`wsz`（同上但启用 permessage-deflate，不在默认集合中） |
| `echo.sh [cases]` | TCP / UDP / TLS echo，以及每秒 TLS 握手数；`connect`（不在默认集合中）：每秒新建 TCP 连接数；在回环上它受客户端从 TIME_WAIT 复用端口的限制（gpu51 上约 33k/秒），直到 TIME_WAIT 表溢出，所以只在各自单独的运行中比较服务端 |
| `ktls.sh` | 内核 TLS 对比 akio-tls 自己的记录层（TLS 上的 HTTP/1.1，`ktls-bench` 示例，`ktls` feature；`VETH=1` 让客户端位于 veth 对的另一端） |
| `ktls-engine.sh` | 引擎中的内核 TLS（ADR-067）：两个构建与不同 `AKIO_KTLS` 模式之间交错进行的 TLS 回显、握手与 HTTPS A/B，每次运行前等待主机空闲 |
| `uring-eval.sh` | 在裸 ring 上比较 io_uring 的发送方式：`write(2)`、`IORING_OP_SEND` 与 `SEND_ZC`，有无注册文件，按响应大小（akio-uring 中被忽略的 `eval_server` 测试；每请求服务器 CPU 取自 `/proc`） |
| `numa.sh` | NUMA 放置 A/B（ADR-088）：同一服务器在未设置 `AKIO_NUMA` 与 `$MODES` 的各模式下（默认 `spread`、`spread+cpu`、`spread+cpu+incoming`），HTTP/1.1、流水线、h2c 与 TCP echo，各轮交替 |
| `shared.sh [cases]` | 共享 I/O 线程组（ADR-130）：一个服务端开 `LISTENERS`（3）个 HTTP listener，每个独占 I/O 线程与全部共享一组对比，并各自再加绑核（`AKIO_PIN_IO_THREADS=1`），epoll 和 io_uring；HTTP/1.1、流水线和 h2c 同时压所有 listener（每个一个 h2load，求和），以及只压其中一个的 HTTP/1.1；服务端线程数和每请求 CPU（`http-bench` 的 `AKIO_BENCH_LISTENERS`、`AKIO_BENCH_SHARED`） |
| `udp-dgram.sh` | UDP 64 B echo A/B：基准构建与新构建的每对端 listener，以及 epoll 和 io_uring 上的无连接 `serve_datagrams` listener（`bench-server udp-dgram`，ADR-065；每请求服务器 CPU 取自 `/proc`） |
| `stream-compress.sh [tput] [mem]` | 压缩流式响应 A/B（ADR-074）：基准构建，以及关闭和开启 `Compress::stream` 的新构建，按编码分别测：每个响应 16 个小事件和 16 次 16 KiB 写入的吞吐量（h2load，每响应服务器 CPU，消息体字节数），以及 3 个和 6000 个事件后每个保持打开的 server-sent events 流的服务器 RSS（`stream-bench` 示例） |
| `mem.sh [proto:kind:conns ...]` | 服务端每个空闲连接的内存 |
| `profile.sh <case> <kind> [secs]` | 某个服务端在某种负载下的 perf 剖析（`h1`、`pipelined`、`h2`、`h2tls`、`ws`、`tcp`），并给出服务端占满了几个 CPU |
| `all.sh <dir>` | 以上全部，原始 TSV 写到 `<dir>` |
| `summarize.py` | 把 TSV 行整理成 BENCHMARKS 里的表格 |
| `docker.sh 'cmd'` | 在 `akio-bench` 镜像（`Dockerfile`：rust + wrk + h2load + perf + Go）中运行命令 |

`akio` 的服务端是 `crates/akio-http/examples/http-bench.rs` 和 `crates/akio/examples/bench-server.rs`
（`akio-epoll`、`akio-uring`），参照实现放在仓库外的工作区 `tools/bench-ref/` 中（`tokio-ref`、
`hyper-ref`、`monoio-ref`、`fib-ref`）。`monoio-ref`（monoio 0.2，每核一线程：每个线程一个运行时和一个
`SO_REUSEPORT` listener）提供 TCP echo 和 HTTP/1.1（`/plaintext`、`/json`、流水线；用 httparse 解析，
没有 HTTP/2），分两种运行：`monoio-uring`（它的 io_uring driver）和 `monoio-epoll`（它的 legacy epoll driver）。

## 压测客户端

HTTP/1.1 在装有 `wrk` 时用 `wrk`（通过 Lua 脚本做流水线），否则用 `h2load --h1`（用 `-m 16` 做流水线）；
可用 `H1GEN=wrk|h2load` 指定。HTTP/2 一律用 `h2load`。两种 HTTP/1.1 客户端得到的绝对数值不同，
只比较用同一种客户端得到的结果。

## 参数

环境变量，见 `lib.sh`：`SRV_CPUS` / `CLI_CPUS`（传给 `taskset` 的 CPU 列表）、`THREADS` / `CLI_THREADS`、
`SECS`（每次运行的秒数）、`RUNS`（轮数，表格取中位数）、`KINDS`（服务端，如 `"akio-epoll fib"`）、
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
cargo build --release -p akio-http --example http-bench
(cd tools/bench-ref/hyper-ref && CARGO_TARGET_DIR=$CARGO_TARGET_DIR/ref cargo build --release)
(cd tools/bench-ref/monoio-ref && CARGO_TARGET_DIR=$CARGO_TARGET_DIR/ref cargo build --release)
cp -r tools/bench-ref/fib-ref /tmp/fibref && cd /tmp/fibref &&
  go mod edit -replace github.com/lesismal/fib=/path/to/fib && go build -o $CARGO_TARGET_DIR/fib-ref . && cd -
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 THREADS=4 CLI_THREADS=8 SECS=5 RUNS=3 \
  KINDS="akio-epoll akio-uring hyper fib" tools/bench/http.sh plaintext,pipelined,json,h2,h2many,h2tls
SRV_CPUS=0-3 CLI_CPUS=4-7,12-15 tools/bench/profile.sh h2 akio-epoll   # 需要 perf
```
