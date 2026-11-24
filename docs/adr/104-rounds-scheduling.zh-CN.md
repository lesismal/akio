# ADR-104：TCP listener 的两种调度模式：每线程事件循环，与在 worker 池上执行的轮次

[English](104-rounds-scheduling.md) | 简体中文

状态：提议中（2026-11-23；2026-11-24 更新：由 worker 驱动 poller，补充测量）

## 背景

ADR-001 规定每个连接在整个生命周期内只属于一个 I/O 线程：由内核的 `SO_REUSEPORT` 哈希选线程，
`on_data` 在该线程内联执行。这样 handler 状态无需加锁，在连接多、各连接开销相近时也最快。但一个
线程的负载取决于分到它的连接恰好带来多少工作：

- 每个线程连接数少时，哈希并不均匀（ADR-105 实测 8 个线程分 1024 个连接，每线程 95 到 150 个）；
- 少数重负载连接（一个多路复用的 HTTP/2 或 gRPC 客户端、一个代理上游）把它所在的线程跑满，其它
  线程空闲，而连接无法迁移；
- 一个慢回调会拖住同线程的所有连接。

ADR-105 在 accept 时平衡各线程的连接**数量**，ADR-094 按协议把 handler 放到线程池上执行。两者都
不能分摊一个已经建立的连接的工作。fib（Go）和 Go runtime 可以：少量 poller 只报告就绪事件，连接的
每一**轮**（读、handler、写）交给任意空闲的 worker 执行。

## 决定

1. **由 listener 选择调度方式**：`akio::Scheduling::Loops`（默认，ADR-001 不变）或
   `Scheduling::Rounds(RoundsConfig)`，用 `Listener::scheduling` 设置。环境变量
   `AKIO_DEFAULT_SCHEDULING=rounds` 为没有显式设置的 listener 选择轮次模式（测试开关，与
   ADR-029 的 `AKIO_DEFAULT_BACKEND` 相同）。但如果 listener 要求了只有每线程事件循环才支持的东西，
   环境变量不生效：io_uring（listener 自己选的或 `AKIO_DEFAULT_BACKEND` 指定的）和 BPF 调度
   （`Accel::Ebpf`）。
2. **轮次模式**（`akio-epoll`，Linux 上 epoll，macOS 上 kqueue）：
   - **由 worker 轮询的 driver**（与 Tokio 的多线程 runtime 相同）。没有 poller 线程：每个
     epoll/kqueue 实例（`RoundsConfig::pollers`，默认 1）是一个由锁保护的 *driver*。没有任务可执行
     的 worker 拿到一个空闲的 driver，在它的 `epoll_wait` 中等待；它发现的就绪连接进入自己的队列，并
     唤醒 park 的 worker 来偷。忙碌的 worker 每执行 61 轮就不阻塞地轮询一次 driver（Tokio 的
     `event_interval`），所以满载时收集事件不需要任何线程唤醒另一个线程。driver 也负责 accept 和
     控制路径（dial、定时器、遥测、关闭），从不读写，也不执行用户代码。连接只注册一次，读写都用边沿
     触发（`EPOLLET` / `EV_CLEAR`），所以一轮不需要调用 `epoll_ctl`。专门的 poller 线程（第一版
     原型）保留在 `AKIO_ROUNDS_POLLERS=dedicated` 之后，仅供对比；它表现更差（见"测量"）。
   - **Worker**（`RoundsConfig::workers`，0 = 自动：每个 CPU 一个）执行轮次。连接的一轮依次：
     若 `on_open` 还没执行则执行它；执行投递给它的 `spawn_blocking` 完成回调；刷出发送队列；读到
     socket 读空为止（最多 16 次读，之后让出、排到队尾）；每次读到数据就在 cork 状态下调用
     `on_data`；最后把这一轮排队的输出一次写出。
   - **每个连接内保持顺序**：每个连接把事件合并成一组待处理位，并有一个 `scheduled` 标志；只有把
     标志置位的那一方才把连接放进队列，所以同一时刻最多一个 worker 在执行它，事件发生之后开始的
     一轮一定能看到这个事件。正因如此，`Handler: Send`（不要求 `Sync`）无需任何改动。
   - **Worker 池**不用 `akio-pool`（单个由互斥锁保护的队列，为阻塞任务设计）：每个 worker 有自己
     的队列，空闲 worker 从别的 worker 的队列偷走一半，自旋 64 次后 park；投递方只在没有 worker 自旋
     时才唤醒一个 park 的 worker（如果空闲 worker 都在 `epoll_wait` 中，就通过 driver 的 eventfd
     打断其中一个）。从 worker 上发起的轮次（另一个连接的
     handler 中的 send 需要刷出时）进入该 worker 自己的队列。
   - 阻塞任务仍然应该放到逻辑线程池（`spawn_blocking`、`run_on_pool`）：阻塞的 worker 会推迟排在
     它后面的连接，虽然其它 worker 会把它们偷走。
3. **保持不变的部分**：`Conn` 与 `ConnInner`（本来就是线程安全的，ADR-002）、cork 与 flush 协议、
   背压、`hold_reads`、有序响应、`close_after_send`、空闲 / 写 / 握手 / 连接超时、慢回调报告（按
   worker 统计）、`max_connections`、内核 TLS offload。所有协议 crate 无需修改：它们的线程局部缓存
   只在单次回调内借用。
4. **轮次模式不支持的**（原型范围）：UDP listener（继续使用事件循环，并记录一条警告）、io_uring
   （`Backend::IoUring` 加轮次模式会被拒绝）、`set_threads`（返回 `Unsupported`）、BPF 调度（它
   只能把连接分给 poller，没有意义）。每个 listener group 一个 worker 池。

## 影响

- 负载按工作量而不是按连接分摊：一个重负载连接同一时刻只占一个 worker，而与它同属一个 poller 的
  其它连接会交给别的 worker。
- 每一轮都有一次交接开销：poller 入队，可能唤醒一个 park 的 worker，连接状态在 CPU 核之间迁移。
  对大量小而均匀的连接，每线程事件循环仍然更快，所以它仍是默认值。
- handler 状态可能在相邻的两轮里被不同线程访问（但绝不会同时），所以 handler 不能跨回调依赖线程
  局部变量。我们自己的 handler 都没有这样做。

## 测量

gpu51（Ryzen 7 7800X3D，Linux 7.0），2026-11-24。服务端绑 CPU 0-3,8-11（8 个逻辑 CPU；loops：8 个
线程；rounds：8 个 worker、1 个 driver），客户端用另外 8 个。每个场景 10 秒；跑两到三轮，rounds 各轮
相差几个百分点以内，loops 各轮最多相差 20%（每次运行内核哈希的结果不同）。"CPU" 是服务端每次运行用掉
的 CPU 秒数（约 88 即 8 个 CPU 全部用满）。

`skew-bench`（CPU 密集的请求；连接数、每连接在途请求数、每请求的 CPU 时间）：

| 场景 | Loops | Rounds | 各连接请求数（最少~最多） | CPU |
|---|---|---|---|---|
| 12 个连接，在途 4，50 µs | 11.4 万~13.2 万/s，p99 0.85~1.27 ms | **15.1 万/s，p99 0.39 ms** | loops 3.2 万~18.9 万，rounds 12.6 万~12.6 万 | 66~77 → 88 |
| 8 个连接，在途 8，100 µs | 3.9 万~5.9 万/s，p99 1.6~3.2 ms | **7.8 万/s，p99 0.82 ms** | loops 2.5 万~9.8 万，rounds 9.8 万~9.8 万 | 44~66 → 87 |
| 64 个连接（4 个 500 µs，其余 20 µs），在途 2 | 21.0 万~25.8 万/s，p99 2.4~2.8 ms | 21.7 万/s，**p99 1.5 ms** | loops 0.4 万~13.4 万，rounds 1.4 万~3.5 万 | 两者都约 88 |
| 256 个连接，在途 1，10 µs | **48.1 万/s**，p99 1.1 ms | 45.0 万/s（-6%），**p99 0.92 ms** | loops 1.1 万~2.6 万，rounds 1.75 万~1.76 万 | 87 / 85 |

TCP echo（`echo-bench`，8 个客户端线程；`bench-server`）：

| 场景 | Loops | Rounds | CPU |
|---|---|---|---|
| 64 个连接 x 64 B | 84.0 万~91.5 万/s | **98.3 万/s** | 57~62 → 76 |
| 1024 个连接 x 64 B | **101 万~109 万/s** | 97.8 万~98.8 万/s（-6%） | 67~72 → 71 |
| 256 个连接 x 1 KiB | 90.6 万~108 万/s | 95.2 万~95.5 万/s | 62~72 → 71 |

过程中尝试过的方案（同一台机器）：

- **专门的 poller 线程**（2 个 poller + 8 个 worker，第一版原型）：256 个连接 x 10 µs 时 p99 为 4.1 ms，
  全部发生在"请求到达服务端 socket"到"它的一轮开始"之间（客户端自己的 `write` p99 只有 8 µs，回程
  28 µs）。改变线程配比（2:6、1:7）、自旋次数，或把 poller 绑到独占的 CPU（它们被动切换的次数从几百
  降到个位数），都还在 4.0~5.4 ms。改为由 worker 轮询 driver 后消失（0.92 ms），多出来的线程也没了。
- **两个 driver** 代替一个：256 个连接时吞吐高 3%，但尾延迟更差（12 个连接时 p99 0.57 ms 对 0.39 ms，
  有重负载连接时 2.2~2.5 ms 对 1.5 ms）。
- **自旋** 0 / 64 / 1000 次与**忙时轮询间隔** 31 / 61 / 127 轮：对 `skew-bench` 没有影响（1% 以内）；
  自旋 1000 次让 echo 多处理 2%~4% 的请求，但多花 11% 的 CPU。默认值保持 64 和 61。

结论：

- 如果因为内核分配连接的方式（每线程连接少）让 loops 有 CPU 空闲，rounds 能用上所有 CPU：吞吐提高
  15%~100%，尾延迟缩短 2~4 倍。
- 如果 loops 已经用均匀分布的连接把所有 CPU 跑满，rounds 每轮的交接让吞吐低约 6%，尾延迟相同或更短。
- 所以默认仍是 loops；连接少或负载不均时选 rounds。

### HttpArena

gpu51 统一批次，2026-11-24 09:16~11:43，已包含停止和 panic 的修复。每个场景跑 2 轮，每轮取 3 次中最好的，
再取平均。rounds 用 8 个 worker、1 个 driver。两组对比：`akio-rounds` 对 `akio-loops`（只有 rounds 分支，
同一份源码），以及 `akio-all-rounds` 对 `akio-all`（合并了全部优化，只换调度模式）。

| 场景 | loops | rounds | 变化 |
|---|---|---|---|
| baseline 4096c | 1.083M | 1.038M | -4.1% |
| pipelined 4096c | 7.15M | 6.95M | -2.8% |
| limited-conn 4096c | 867k | 814k | -6.2% |
| json-tls 4096c | 444k | 443k | 0 |
| baseline-h2c 256c / 1024c / 4096c | 7.07M / 6.91M / 6.27M | 7.08M / 6.88M / 6.27M | 0 |
| unary-grpc 256c / 1024c | 3.18M / 3.08M | 3.19M / 3.08M | 0 |
| echo-ws 512c / 4096c / 16384c | 1.25M / 1.22M / 1.00M | 1.11M / 1.16M / 1.03M | -10.6% / -4.4% / +2.4% |
| echo-ws-pipeline 512c / 4096c / 16384c | 15.6M / 15.3M / 12.9M | 14.1M / 14.7M / 13.0M | -9.8% / -4.0% / +0.6% |
| async 32000c（`akio-all` 组） | 602k | 673k | **+11.9%** |
| echo-ws-limited 512c / 4096c（`akio-all` 组） | 858k / 845k | 583k / 812k | **-32.0%** / -4.0% |
| json-comp 4096c / 16384c（`akio-all` 组） | 228k / 222k | 222k / 216k | -2.7% / -2.5% |
| static-h2 1024c（`akio-all` 组） | 802k | 774k | -3.5% |

固定速率场景：

- latency-10k：p99 相同（约 0.05 ms），但每请求 CPU 17.2 µs 对 9.5 µs。可能的原因：空闲的 worker 最多 park 10 ms，
  由 driver 通过 eventfd 唤醒，负载轻时要为 loops 没有的唤醒付出代价。
- latency-1m：p99 7.8~10.4 ms，`akio-all`（loops，带 ADR-105 尾延迟修复）是 3.3~4.4 ms；每请求 CPU 略少
  （7.5 对 7.7 µs）。没有这些修复的 main 是 0.9~1.1 s。
- 8gbit：吞吐相同，每请求 CPU 24 µs 对 18 µs。

echo-ws-limited 512 个连接时，rounds 只用了 8 个 CPU 中的 5.7 个。这个场景不停地重连，每次 accept、注册、
关闭都经过唯一的 driver，连接寿命短时 driver 就成了瓶颈。

所以，在连接分布均匀的真实 HTTP 流量上：

- 请求占用线程时间长、负载不均时 rounds 占优（async +12%），h2c 和 gRPC 持平。
- 大量连接上的小请求慢 3%~10%，连接寿命短时最多慢 32%，负载轻时更费 CPU。
- 默认仍是 loops。rounds 下一步：把 accept 和关闭分散到多个 driver，减少轻负载时的唤醒。
