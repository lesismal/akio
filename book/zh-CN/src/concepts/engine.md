# Engine、Listener 与后端

## Engine

`Engine` 是一组由 I/O **线程组**（group）服务的 listener（默认同一后端的 TCP listener 共享
一组，ADR-130），另外还有一个共享的逻辑线程池和一个遥测中心（telemetry hub）。用 `Engine::builder()` 构建：

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:engine}}
```

- `build()` 校验配置、绑定所有 listener（端口冲突在这里就会报错）并准备线程，此时什么都还
  没运行。
- `start()` 启动 I/O 线程后立即返回，可重复调用。
- `wait()` 阻塞到 `shutdown()` 完成为止；`run()` 就是 `start()` + `wait()`。
- `Engine` 是 `Send + Sync`。需要在 `wait` 阻塞期间从别的线程调用 `shutdown`、`dial`、
  `metrics` 或 `reload` 时，把它放进 `Arc`。
- `local_addrs()` 按添加顺序返回绑定的地址（端口 0 会解析成实际端口）。只用于客户端的线程组
  （`client_threads`、`udp_client_threads`）排在后面，显示为未指定地址。

## Listener

`Listener::tcp(addr)` 或 `Listener::udp(addr)`，然后：

| 方法 | 含义 | 默认值 |
|---|---|---|
| `.serve(acceptor)` | 由谁处理连接（必填） | 无：`build` 失败 |
| `.threads(n)` | 独占 `n` 个 I/O 线程，不使用共享线程 | 共享（见下文） |
| `.dedicated()` | 独占 I/O 线程，每核一个 | 共享（见下文） |
| `.backend(Backend::..)` | `Epoll`（macOS 上是 kqueue）或 `IoUring(UringConfig)` | `Epoll` |
| `.accel(Accel::..)` | `None` 或 `Ebpf(EbpfConfig)` 分流 | `None` |
| `.balance(Balance::..)` | `LeastConnections`：持有连接超出份额的线程把新连接在首次读取之前交给连接最少的线程（ADR-105）；`Kernel`：套接字接受到哪个线程就留在哪个线程 | `LeastConnections`（有 eBPF 分流或 NUMA `incoming_cpu` 时为 `Kernel`） |

epoll/kqueue 每线程事件循环上的 TCP listener **共享**一组 I/O 线程，即
`EngineBuilder::io_threads(n)`（默认每核一个），无论端口、协议或 handler 类型：8 核上的 HTTP、
gRPC 和管理三个端口运行 8 个 I/O 线程，而不是 24 个（ADR-130）。每个线程监听所有 listener 的
socket，并运行对应的 acceptor 和 accept 过滤器；每个连接留在接受它的线程上。设置了 `.threads(n)`
或 `.dedicated()` 的 listener 独占一组线程（隔离：它的连接不会排在其他 listener 的回调之后），
UDP、数据报、DPDK 和 BPF 引流的 listener 也独占线程组；io_uring 的 listener 按相同的 ring 选项
共享一组，工作窃取调度的 listener 按相同的 `WorkStealingConfig` 共享 worker。移除共享 listener 只
关闭它的 socket、只排空它的连接；对共享 listener 调用 `Engine::set_threads` 会调整共享组的大小，
影响组内所有 listener。handler 类型、后端和线程数各不相同的多个 listener 可以放在同一个 engine
里。

`EngineBuilder::pin_io_threads(true)`（或 `AKIO_PIN_IO_THREADS=1`）把每个 I/O 线程绑到进程可用
CPU 中的一个，在各线程组之间轮流分配（Linux）。忙碌的 I/O 线程数与 CPU 数相同时（按 CPU 数确定
大小的共享组常常如此），调度器有时会让其中两个在同一个 CPU 上待一段时间，而另一个 CPU 空闲；绑核
之后，3 个 listener 共享 4 个线程跑在 4 个 CPU 上的 HTTP/1.1 吞吐与 12 个独占线程相当
（docs/BENCHMARKS.zh-CN.md）。但绑核的线程无法避开同一 CPU 上其他繁忙的线程：handler 默认在逻辑
线程池上执行的 h2c，在相同 CPU 上绑核后吞吐最多下降一半。只在 handler inline 执行、且这些 CPU 由
I/O 线程独用时开启。NUMA 放置和 BPF 引流会自行绑定各自的线程组。

## 后端

| 后端 | 平台 | 说明 |
|---|---|---|
| `Backend::Epoll` | Linux（epoll）、macOS（kqueue） | 默认后端。Linux 上每个线程绑定自己的 `SO_REUSEPORT` socket，由内核分发新连接；macOS 上各线程共享一个监听 socket。 |
| `Backend::IoUring(UringConfig)` | Linux 5.19+ | multishot accept 与 recv，每线程一个 provided-buffer ring（空闲连接不占读缓冲），single-issuer ring。内核不支持时该 listener 回退到 epoll 并打印警告，除非设置了 `UringConfig::strict`。 |
| `Backend::Dpdk(DpdkConfig)` | Linux（DPDK、TAP、AF_PACKET）；内存链路可在任意平台使用 | 实验性，cargo feature `dpdk`（DPDK 端口需 `dpdk-pmd`）。内核旁路：用户态 TCP/IP 协议栈运行在自己的 I/O 线程上，每个网卡队列一个线程，同一设备上的所有 listener 共享。见[内核旁路（DPDK）](../dpdk.md)。 |

UDP listener 总是由就绪通知后端（epoll/kqueue）服务：有了 `recvmmsg` / `sendmmsg` 和 GSO，
io_uring 能带来的批量化已经具备了。对 UDP listener 指定 `IoUring { strict: true }` 会让
`build` 失败。

`UringConfig` 包含 `entries`（提交队列深度，0 表示默认）、`sqpoll`（内核轮询线程）和
`strict`。

选择哪个后端要靠测量；见[性能调优](../performance.md)。在基准报告中，客户端是瓶颈时
io_uring 与 epoll 相差几个百分点之内，服务端是瓶颈时 io_uring 领先 10–25%。

## 加速层：eBPF 分流

`Accel::Ebpf(EbpfConfig)` 挂载一个 `SO_REUSEPORT` 程序，决定新 TCP 连接或新 UDP peer 交给
哪个 I/O 线程：`Steering::Cpu`（收到数据包的 CPU，`cpu % threads`）或 `Steering::Hash`
（按源 IP、或源 IP 加端口做 Maglev 风格的一致性哈希）。它可以与任何后端组合。经典 BPF 不需要
特权；进程有特权时使用 eBPF 程序。什么都挂载不上时，listener 保持内核默认的哈希分发并报告
原因；`strict: true` 会把这种情况变成构建错误。

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-config.rs:listeners}}
```

`Engine::accel_status()` 按 listener 报告 `Off`、`Steering(info)` 或 `Degraded(reason)`。
分流需要一组 `SO_REUSEPORT` socket，因此只在 Linux 上可用；macOS 上总是降级。

进程有特权时，两种策略都有 eBPF 层。它在 `REUSEPORT_SOCKARRAY` 中写明每个线程的 socket，因此
无论 socket 以什么顺序加入组，线程 `i` 都服务 `fds[i]`。哈希与经典层相同，
`ebpf::expected_index` 对两层都成立。`pin_threads: true` 把 n 个 I/O 线程中的线程 `i` 绑到满足
`c % n == i` 的 CPU 上；配合 `Steering::Cpu`，流被分到的线程就运行在收到该流的 CPU 上。
`SteerInfo::pinned_threads` 给出实际绑核的线程数。

## 加速层：XDP 限速

`akio::ebpf::xdp::RateLimiter` 在网卡上挂一个 XDP 程序：每个源地址一个令牌桶（每秒 `rate`
个包，突发 `burst` 个），超出的包在内核为它分配任何东西之前就被丢弃。默认只计 TCP SYN（防连接
洪泛）；`Count::AllPackets` 计所有 IPv4/IPv6 包。

```rust,ignore
use akio::ebpf::xdp::{RateLimiter, XdpLimit};
let mut cfg = XdpLimit::default(); // 每源 100 SYN/s，突发 200，16384 个源
cfg.rate = 50;
let limiter = RateLimiter::attach("eth0", &cfg)?; // drop 时卸载
println!("{:?} {:?}", limiter.mode(), limiter.stats()?);
```

需要 `CAP_NET_ADMIN` 与 `CAP_BPF`。驱动支持时以 native（驱动）模式运行，否则用 generic 模式。
挂载优先用 BPF link（进程退出时由内核移除），5.9 以前的内核改用 netlink；他人已挂载的程序永不
替换。

限制：

- 令牌桶按接收 CPU 划分：一个源的多个流若落在多个 RX 队列上，每个队列各有 `rate` 的额度。
- 伪造且不断变化的源地址各自拿到新桶，这种情况靠 SYN cookies 应对。
- 源表是有上限的 LRU（`max_sources`）。

## 工作窃取（默认）

epoll/kqueue 上没有显式选择调度方式的 TCP 或 Unix 域流 listener 使用工作窃取
（`Scheduling::WorkStealing`，ADR-104）：一组 worker（默认每个 CPU 一个，由 `WorkStealingConfig`
或 listener 自己的 `.threads(n)` 决定）在任意空闲的 worker 上执行连接的每一轮（读、回调、写），同一个
连接一次只执行一轮。每连接状态仍然不需要锁，同一个连接的事件仍然按顺序处理；慢回调只占住它自己的
worker，而不是拖住一个线程上的所有连接，负载按工作量而不是按连接分摊。`Engine::set_threads` 不会调整
工作窃取 listener 的线程数：需要调整的 listener 请选择 `.scheduling(Scheduling::EventLoops)`。
io_uring、DPDK、BPF 引流和 UDP 的 listener 总是使用事件循环（见下）。
`AKIO_DEFAULT_SCHEDULING=event-loops` 把默认改为事件循环（测试和诊断开关）。

## 每核一线程

使用事件循环时（`Scheduling::EventLoops`，以及 io_uring、DPDK、BPF 引流和 UDP），每个连接从 accept
到关闭都只由一个 I/O 线程拥有（ADR-001）。这个线程读 socket、执行你的
回调、运行其连接的定时器并刷出它们的发送队列。由此可知：

- 每连接状态不需要锁，也不需要 `Sync`。
- 同一个连接的事件按顺序逐个处理。
- 一个慢回调会拖慢同一线程上的所有其他连接。所以回调不能阻塞，akio 也会测量回调耗时并
  报告慢回调（见[可观测性](../observability.md)）。
- 负载按连接均衡，而不是按请求：一个热点连接无法迁移到空闲线程。上面的分流控制的是初始
  放置。

用 `Engine::dial` 发起的客户端连接运行在 `EngineBuilder::client_threads(n)` 添加的线程上；
没有这些线程时，运行在最后添加的 listener 的线程上。UDP dial（`Engine::dial_udp`）需要
`udp_client_threads(n)` 或一个 UDP listener。
