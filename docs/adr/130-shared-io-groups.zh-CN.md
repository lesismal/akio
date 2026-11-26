# ADR-130：同一后端的 listener 共享一组 I/O 线程

[English](130-shared-io-groups.md) | 简体中文

状态：已采纳（2026-11-25）。第一阶段（epoll/kqueue、每线程事件循环）、第二阶段（轮次调度）和
第三阶段（io_uring）已实现。

## 背景

ADR-004 允许每个 listener 选择自己的后端，而 engine 迄今为每个 listener 建立一组独立的 I/O
线程，默认每核一个（`Listener::threads`）。于是在 8 核机器上开 HTTP、gRPC 和管理三个端口的服务
会运行 24 个 I/O 线程，每核三个；每组大部分时间空闲，繁忙时又争抢同样的核。这并不是必需的：一个
epoll/kqueue 事件循环可以监听任意多个监听 socket，同一后端的 listener 之间只在 acceptor、accept
过滤器以及是否为 Unix 域 socket 上不同。只有不同后端（或不同调度方式）的 listener 无法运行在同一个
事件循环上。

## 决定

1. **listener 默认共享。** 构建时以及 `Engine::add_listener` 时，TCP listener（绑定的、继承的或
   Unix 域的）加入 engine 中与其键对应的共享线程组，键为：后端、调度方式和 accept 时的均衡方式
   （`Balance`）。该组随该键的第一个 listener 创建，大小由 `EngineBuilder::io_threads(n)` 决定
   （默认每核一个）。8 核上的一个 HTTP 和一个 gRPC listener 现在运行 8 个 I/O 线程，而不是 16 个。
   轮次调度（ADR-104）下，键是解析后的 `RoundsConfig`（poller 数和 worker 数），它同时决定组的
   大小：配置相同的 listener 共享其 worker 和 poller。
2. **listener 仍可独占一组。** `Listener::threads(n)`（任何显式数量）或新增的
   `Listener::dedicated()`（每核一个）让该 listener 保持 ADR-004 的方式：为管理端口或对延迟敏感的
   协议提供隔离，或单独确定线程数。需要按 listener 分配线程的总是独占一组：BPF 引流
   （`Accel::Ebpf`，其程序引流到该 listener 自己的 socket）、UDP 和数据报 listener 以及 DPDK
   （事件循环类型不同）。
3. **一个事件循环，多个 listener。** epoll/kqueue 事件循环为所在组的每个 listener 保存 acceptor、
   accept 过滤器、是否为 Unix 域以及是否已被移除，并以同时标明 listener 和 socket 的令牌监听该
   listener 的 socket。accept 时运行对应的过滤器和 acceptor；每个连接记住自己的 listener。在 Linux
   上每个 listener 仍是每线程一个 `SO_REUSEPORT` socket，其他系统上是同一 socket 的克隆；线程数
   调整（ADR-028）照旧移动每个 listener 的 socket。
4. **移除一个 listener 只影响它自己**（ADR-099）。`remove_listener` 在所有线程上关闭它的 socket；
   `shutdown_listener(id, drain)` 对该 listener 的连接执行 `on_shutdown`，并在 `drain` 之后关闭仍
   打开的连接。组内线程继续服务其他 listener，即使一个 listener 都不剩也保持运行，直到 engine
   关闭。
5. **engine 按 listener 的 API 含义不变。** `local_addrs`、`listeners`、`threads` 以及各个
   `ListenerId` 仍然每个 listener 一项。`threads()` 为共享组的每个 listener 报告该组的大小；对共享
   listener 调用 `set_threads(i, n)` / `set_listener_threads(id, n)` 会调整共享组的大小，影响组内
   所有 listener。拨号（没有客户端线程时的 `dial`）照旧交给最后一个 listener 的组，无论是否共享。
6. **遥测。** 共享组的线程不属于某一个 listener：它们的 `LoopMeta::listener` 为 `None`，而
   `ConnInfo::owner.listener` 标明每个被 accept 的连接来自哪个 listener。按线程的计数器
   （`accepted`、`filtered` 等）统计组内所有 listener。

## 影响

- 默认线程更少：每个后端一组，而不是每个 listener 一组，空闲的事件循环不再过度占用核，繁忙的
  listener 可以用上所有线程。
- 默认隔离更弱：一个 listener 的慢 inline handler 会延迟同一线程上其他 listener 的连接。阻塞工作
  本就应放在逻辑线程池上（规则 §1，`handlers_on_logical_pool`）；
  `Listener::dedicated()` 可恢复隔离。
- 显式设置 `threads(n)` 的 listener（测试和调优部署中的常见情况）行为完全不变。
- 对一个 listener 调用 `set_threads` 现在可能改变其他 listener 的线程；文档对此有说明。
- `Group` trait 增加按键操作 listener 的方法（面向后端，`#[doc(hidden)]`）。

## 第二阶段：轮次调度（2026-11-25 实现）

轮次调度组的监听 socket 本来就各自是带 acceptor 的 accept 任务。共享的轮次调度组保存 listener 表
（每个 listener 的 accept 任务和 accept 过滤器）；之后加入的 listener 的 accept 任务投递给 poller
（`RCmd::AddJob`），由 poller 注册；每个连接记住自己的 listener，所以移除一个 listener 只关闭它的
accept 任务、只排空它的连接（`RCmd::StopListening` 标明它），连接表也标明每个连接的 listener。
Unix 域 listener 也一样加入：它们的 accept 任务 accept 时不读取地址（2026-11-26；此前使用轮次调度的
Unix 域 listener 被当作 TCP listener 绑定在未指定地址上）。

## 第三阶段：io_uring（2026-11-26 实现）

io_uring 事件循环保存与 epoll 事件循环相同的 listener 表，并为每个监听 socket 提交一个 multishot
accept，其 `user_data` 标明 listener 和 socket。移除一个 listener 会取消它的 accept，并把它的
`SO_REUSEPORT` socket 移出该地址的组；被取消的 accept 仍送达的连接由该 listener 的 acceptor 服务
（有排空时在首批数据之后关闭），并且只排空它的连接。io_uring listener 按 ring 选项
（`UringConfig::entries`、`sqpoll`）共享一组，大小由 `EngineBuilder::io_threads` 决定；io_uring
不可用时，它们与独占线程组时一样退回 epoll 的共享组（或在 `strict` 时报错）。

## 后续：I/O 线程绑核（2026-11-26）

按 CPU 数确定大小的共享组，忙碌 I/O 线程数正好等于 CPU 数；不绑核时，调度器有时会在一次运行的
大部分时间里让其中两个线程待在同一个 CPU 上，而另一个 CPU 空闲（在 gpu51 上测得：4 个线程中有两个
在同一 CPU 上的采样最多达 20 次中的 19 次，这些运行中 3 个 listener 的 HTTP/1.1 慢 10% 到 20%）。
独占线程组因为 CPU 超额分配（4 个 CPU 上 12 个线程）而掩盖了这一点。`EngineBuilder::pin_io_threads`
（或 `AKIO_PIN_IO_THREADS=1`）默认关闭，开启后把每个 I/O 线程在各线程组之间轮流绑到一个允许的
CPU 上；NUMA 放置或 BPF 引流已绑定的线程组保持不变。不默认开启的原因：绑核的线程无法避开同一 CPU
上其他繁忙的线程。实测（docs/BENCHMARKS.zh-CN.md）：绑核后，3 个 listener 共享 4 个线程的
HTTP/1.1 与 12 个独占线程相当，波动在 1% 以内；handler 在同一组 CPU 的逻辑线程池上执行的 h2c 最多
下降一半。改为 inline 执行（关闭 `handlers_on_logical_pool`）后，绑核的 h2c 是最快的配置（每秒 400 万请求），
说明下降来自线程池。`EngineBuilder::reserve_pool_cpus(n)` 在绑核时给线程池单独的 CPU；它对 io_uring
上走线程池的 h2c 有帮助，对 epoll 没有，所以它是用来测量的工具，而不是推荐配置。

## 未做

- UDP 和数据报 listener：它们的事件循环是另一种类型。
