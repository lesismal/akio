# ADR-102：TCP listener 的两种调度模式：每线程事件循环，与在 worker 池上执行的轮次

[English](102-rounds-scheduling.md) | 简体中文

状态：提议中（2026-11-23）

## 背景

ADR-001 规定每个连接在整个生命周期内只属于一个 I/O 线程：由内核的 `SO_REUSEPORT` 哈希选线程，
`on_data` 在该线程内联执行。这样 handler 状态无需加锁，在连接多、各连接开销相近时也最快。但一个
线程的负载取决于分到它的连接恰好带来多少工作：

- 每个线程连接数少时，哈希并不均匀（ADR-100 实测 8 个线程分 1024 个连接，每线程 95 到 150 个）；
- 少数重负载连接（一个多路复用的 HTTP/2 或 gRPC 客户端、一个代理上游）把它所在的线程跑满，其它
  线程空闲，而连接无法迁移；
- 一个慢回调会拖住同线程的所有连接。

ADR-100 在 accept 时平衡各线程的连接**数量**，ADR-094 按协议把 handler 放到线程池上执行。两者都
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
   - **Poller**（`RoundsConfig::pollers`，0 = 自动：4 个 CPU 及以下 1 个，否则每 4 个 CPU 一个、
     至少 2 个）等待就绪事件、accept，并处理控制路径（dial、定时器、遥测、关闭）。它们从不读写，
     也不执行用户代码。连接只注册一次，读写都用边沿触发（`EPOLLET` / `EV_CLEAR`），所以 poller
     不需要每轮调用 `epoll_ctl`。
   - **Worker**（`RoundsConfig::workers`，0 = 自动：每个 CPU 一个）执行轮次。连接的一轮依次：
     若 `on_open` 还没执行则执行它；执行投递给它的 `spawn_blocking` 完成回调；刷出发送队列；读到
     socket 读空为止（最多 16 次读，之后让出、排到队尾）；每次读到数据就在 cork 状态下调用
     `on_data`；最后把这一轮排队的输出一次写出。
   - **每个连接内保持顺序**：每个连接把事件合并成一组待处理位，并有一个 `scheduled` 标志；只有把
     标志置位的那一方才把连接放进队列，所以同一时刻最多一个 worker 在执行它，事件发生之后开始的
     一轮一定能看到这个事件。正因如此，`Handler: Send`（不要求 `Sync`）无需任何改动。
   - **Worker 池**不用 `akio-pool`（单个由互斥锁保护的队列，为阻塞任务设计）：每个 worker 有自己
     的队列，poller 轮流把连接分给各 worker，空闲 worker 在 park 之前先从其它 worker 偷任务；投递方
     只在没有 worker 自旋时才唤醒一个 park 的 worker。从 worker 上发起的轮次（另一个连接的
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

由 A/B 测试（gpu51）补充：原始 TCP echo、HTTP/1.1 plaintext 与 pipeline、WebSocket echo，以及负载
倾斜场景（连接少、各连接开销不均），两种模式各跑一遍。
