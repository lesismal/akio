# Engine、Listener 与后端

## Engine

`Engine` 是一组 listener，每个 listener 由自己的一**组**（group）I/O 线程服务，另外还有一个
共享的逻辑线程池和一个遥测中心（telemetry hub）。用 `Engine::builder()` 构建：

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-basics.rs:engine}}
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
| `.threads(n)` | 该 listener 的 I/O 线程数 | 每核一个 |
| `.backend(Backend::..)` | `Epoll`（macOS 上是 kqueue）或 `IoUring(UringConfig)` | `Epoll` |
| `.accel(Accel::..)` | `None` 或 `Ebpf(EbpfConfig)` 分流 | `None` |

每个 listener 有自己的线程，listener 之间从不共享 I/O 线程。handler 类型、后端和线程数各不
相同的多个 listener 可以放在同一个 engine 里。

## 后端

| 后端 | 平台 | 说明 |
|---|---|---|
| `Backend::Epoll` | Linux（epoll）、macOS（kqueue） | 默认后端。Linux 上每个线程绑定自己的 `SO_REUSEPORT` socket，由内核分发新连接；macOS 上各线程共享一个监听 socket。 |
| `Backend::IoUring(UringConfig)` | Linux 5.19+ | multishot accept 与 recv，每线程一个 provided-buffer ring（空闲连接不占读缓冲），single-issuer ring。内核不支持时该 listener 回退到 epoll 并打印警告，除非设置了 `UringConfig { strict: true, .. }`。 |

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
{{#include ../../../../crates/flash/examples/guide-config.rs:listeners}}
```

`Engine::accel_status()` 按 listener 报告 `Off`、`Steering(info)` 或 `Degraded(reason)`。
分流需要一组 `SO_REUSEPORT` socket，因此只在 Linux 上可用；macOS 上总是降级。

## 每核一线程

每个连接从 accept 到关闭都只由一个 I/O 线程拥有（ADR-001）。这个线程读 socket、执行你的
回调、运行其连接的定时器并刷出它们的发送队列。由此可知：

- 每连接状态不需要锁，也不需要 `Sync`。
- 同一个连接的事件按顺序逐个处理。
- 一个慢回调会拖慢同一线程上的所有其他连接。所以回调不能阻塞，flash 也会测量回调耗时并
  报告慢回调（见[可观测性](../observability.md)）。
- 负载按连接均衡，而不是按请求：一个热点连接无法迁移到空闲线程。上面的分流控制的是初始
  放置。

用 `Engine::dial` 发起的客户端连接运行在 `EngineBuilder::client_threads(n)` 添加的线程上；
没有这些线程时，运行在最后添加的 listener 的线程上。UDP dial（`Engine::dial_udp`）需要
`udp_client_threads(n)` 或一个 UDP listener。
