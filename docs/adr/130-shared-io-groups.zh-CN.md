# ADR-130：同一后端的 listener 共享一组 I/O 线程

[English](130-shared-io-groups.md) | 简体中文

状态：已采纳（2026-11-25）。第一阶段（epoll/kqueue、每线程事件循环）已实现；io_uring 和
轮次调度仍为每个 listener 建立独立的线程组。

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
  本就应放在逻辑线程池上（规则 §1；自 2026-11-25 起 HTTP/2 handler 默认在线程池上执行）；
  `Listener::dedicated()` 可恢复隔离。
- 显式设置 `threads(n)` 的 listener（测试和调优部署中的常见情况）行为完全不变。
- 对一个 listener 调用 `set_threads` 现在可能改变其他 listener 的线程；文档对此有说明。
- `Group` trait 增加按键操作 listener 的方法（面向后端，`#[doc(hidden)]`）。

## 未做（后续阶段）

- io_uring：一个 ring 可以用同样的方式监听多个 listener（每个 listener 一个 multishot accept）；
  在此之前 io_uring listener 仍独占线程组。
- 轮次调度（ADR-104）：它的 worker 是每个 listener 组一个池；共享它们需要在其 poller 中加入第 3 点的
  listener 表。
- UDP 和数据报 listener：它们的事件循环是另一种类型。
