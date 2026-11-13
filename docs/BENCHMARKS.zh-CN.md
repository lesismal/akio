# 基准测试（M2 报告）

[English](BENCHMARKS.md) | 简体中文

测量日期 2026-11-14，提交 `34ab5d5`。**请先读“局限”**：只有一台机器、一组运行，没有记录方差。
差距在 10% 以内当作噪声，整份报告只回答“是不是同一量级”，不是排名。

## 环境与方法

- Linux 6.12.5（linuxkit，Apple 芯片 Mac 上的 Docker 虚拟机），aarch64，14 个 vCPU，回环网卡。
- 服务端固定在 CPU 0–3（4 线程）；压测器 `echo-bench` 固定在 CPU 4–11（8 个客户端线程）。
  闭环：每个连接发一条消息，等回复，再发。
- 先预热 1 秒，每个数字跑 5 秒 × 3 次，表中是 **中位数** req/s。
- 服务端都是 4 线程、同样的处理逻辑（echo，或下面的阻塞处理）：
  - **flash-epoll**、**flash-uring**：`crates/flash/examples/bench-server`（`Backend::Epoll` / `IoUring`）。
  - **tokio**：`tools/bench-ref/tokio-ref`，多线程运行时 4 个 worker，每连接一个 task
    （UDP：一个 task 循环 `recv_from`/`send_to`）；TLS 用 tokio-rustls。
  - **fib**：`tools/bench-ref/fib-ref`，fib 默认配置（Go 1.27.3，`GOMAXPROCS` 跟随 4 个 CPU 的亲和性）。
    fib 没有 TLS 一行，因为没写对应的参考服务端。
- TLS：TLS 1.3，flash 与 tokio 都用 rustls 的 `ring`，自签证书，客户端不校验，握手在测量前完成。
- 复现：`tools/bench/run.sh`（文件头有说明）。

## 结果（每秒请求数，3 次中位数）

### TCP echo

| 负载 | flash-epoll | flash-uring | tokio | fib |
|---|---:|---:|---:|---:|
| 1 连接，64 B | 35,255 | 35,189 | 34,714 | 31,581 |
| 64 连接，64 B | 532,588 | 524,265 | **628,231** | 479,041 |
| 512 连接，64 B | **1,030,385** | 957,627 | 858,882 | 625,446 |
| 64 连接，16 KiB | 422,596 | 400,807 | **489,537** | 77,559 |

### TLS 1.3 echo，64 连接，1 KiB

| flash-epoll | flash-uring | tokio |
|---:|---:|---:|
| 468,314 | 500,861 | 510,563 |

### UDP echo，64 个 socket，64 B

| flash | tokio | fib |
|---:|---:|---:|
| 578,665 | 437,746 | 565,353 |

### 每个请求 5 ms 阻塞工作，256 连接

| 处理方式 | flash-epoll | flash-uring | tokio | fib |
|---|---:|---:|---:|---:|
| 在 I/O 线程 / 运行时 worker 上阻塞 | 549 | 548 | 631 | 不适用 |
| 工作交给逻辑池 / `spawn_blocking` | 32,078 | 31,802 | 36,870 | 不适用 |
| fib：handler 里阻塞（fib 默认在 worker 池里跑 handler） | | | | 31,415 |

4 个线程各阻塞 5 ms，上限是 800 req/s，第一行就是这个量级；256 个连接各等 5 ms，第二行上限约 51,000 req/s。

## 结论

- **TCP echo 与 fib、tokio 属于同一量级。** 本机上所有 TCP 负载 flash 都领先 fib（64 连接约 1.1 倍，
  512 连接约 1.6 倍，16 KiB 差距很大）；512 连接领先 tokio，但 **64 连接落后 tokio 约 15%，
  16 KiB 落后约 14%**。M1 目标“与 fib 的 echo 同级”在这台机器上达到；“优于 tokio”没有得到证明。
- **这里 io_uring 并不比 epoll 快。** echo 负载下 flash-uring 与 epoll 持平或最多慢约 7%，TLS 里快约 7%。
  之前单线程、服务端受限的测试（见 DEV-PLAN）里 io_uring 领先 10–25%，说明优势出现在服务端而不是
  客户端成为瓶颈的时候。4 个服务端线程对 8 个客户端线程时，512 连接的数字很可能受客户端限制，
  所以它们是服务端能力的下限参考，不是精确值。
- **逻辑池达到了设计目的。** 在 I/O 线程里阻塞时，flash（和 tokio）从几十万降到约 550 req/s；
  同样的工作交给 `spawn_blocking` 后约为前者的 58 倍，与 tokio 的 `spawn_blocking` 相差 15% 以内。
- fib 的阻塞那一行高，是因为 fib 默认在 worker 池里调用 handler；flash 的默认正好相反（在 I/O 线程内联、
  不允许阻塞），所以阻塞代码必须显式挪走，这是设计取舍。
- UDP：flash 与 fib 持平；tokio 参考实现只是一个 `recv_from` 循环，是最简单的写法，这一行不代表 tokio 的最佳水平。

## 局限

- 笔记本级 Mac 上的一台虚拟机：调度有噪声、宿主机共享、只有回环（没有网卡与真实网络延迟）。
  绝对数字没有意义，比值只作参考。
- 只保存了中位数，没有每次运行的离散程度，重跑时任何一格都可能变动几个百分点。
  更早的冒烟测试（1 秒 × 1 次）里 flash-uring 的 TLS 比 flash-epoll 慢，这次顺序相反，两者在噪声范围内。
- flash 在 64 连接和 16 KiB 落后 tokio 的原因 **没有做 profile**，不下结论。
- fib 的 16 KiB 结果（约为其他的五分之一）没有调查，可能只是某个默认缓冲配置，不代表 fib 的一般水平；fib 没有调优。
- 没有测内存、延迟分位数、512 以上的连接数扩展、TLS 握手速率；TLS 数字是已建立连接上的记录吞吐。
- 没有跑 monoio。
