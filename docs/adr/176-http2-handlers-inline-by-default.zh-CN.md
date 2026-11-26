# ADR-176：HTTP/2 handler 默认重新 inline 执行

[English](176-http2-handlers-inline-by-default.md) | 简体中文

状态：已采纳（2026-11-26）。撤销 [ADR-094](094-handlers-on-the-logical-pool.zh-CN.md) 2026-11-25
更新所设的默认值；ADR-094 的其余部分不变。

## 背景

ADR-094（2026-11-23）为每个协议加了 `run_on_pool` 开关，默认关闭。它在 2026-11-25 的更新
（`d33d4dd3`）把 `H2Config::run_on_pool` 改为默认开启，使一个 HTTP/2 连接的各个 stream 同时处理，
而不是在它的 I/O 线程上逐个处理。

2026-11-26 的同场 A/B（[BENCHMARKS](../BENCHMARKS.zh-CN.md)）测出了这个默认值让 handler 从不阻塞的
服务付出的代价：同一台机器、同一批二进制，`http-bench` 的 h2c（4 个 I/O 线程，`h2load` 64 × 16 与
16 × 128）在线程池上每秒 0.47-0.53 M 请求，inline 时为 4.4-6.1 M，相差 9-13 倍。每个走线程池的请求
都要付出 inline 请求没有的两次跨线程交接：

- 请求：推入线程池的队列（所有 I/O 线程共用的一把 `Mutex`），并用 `Condvar` 唤醒一个线程池线程；
- 响应：由线程池线程写入连接的 HTTP/2 状态，所持的锁也是 I/O 线程每读一帧都要取的那把，然后从外部
  线程发给连接，这又要唤醒事件循环去写。inline 时，一次读取产生的所有响应用一次写发出。

线程池服务端上的 `perf`（见同一节）显示，时间花在内核的 futex 与唤醒路径和锁竞争上，而不是 handler 上。

那次更新的另一项改动，即 HTTP 客户端的死锁修复（`Conn::run_on_loop`：线程池任务中调用的客户端无需
自己的线程池任务就能进入连接的事件循环），并不依赖这个默认值。

## 决定

`H2Config::run_on_pool` 的默认值改回 `false`，与 `HttpConfig::run_on_pool`、`H3Config::run_on_pool`、
`GrpcServer::run_on_pool` 和 `Routes::run_on_pool` 一致。其余不变：开关本身、它搬走什么和留下什么、
线程池满时的 `503`、针对单个请求的 `Context::detach_to_pool` 与 `Context::suspend_to_pool`。
`http-bench` 用 `AKIO_H2_RUN_ON_POOL=1` 让 HTTP/2 在线程池上执行。

## 为什么这样做是安全的

- **没有任何发布版本带有线程池默认值。** 它在 2026-11-25 进入 `[Unreleased]`；直到 1.0.0-rc.1 的
  每个发布版本都 inline 处理 HTTP/2。基于发布版本构建的应用看不到任何变化；跟随 `main` 的应用回到
  前一天为止的默认值。
- **死锁修复保留。** 无论这个开关如何，HTTP/1.1 与 HTTP/2 客户端都通过 `Conn::run_on_loop` 进入
  事件循环，所以线程池上的 handler 调用客户端并等待结果时，仍不需要第二个线程池线程
  （`tests/run_on_pool.rs` 自己设置该开关）。
- **所有协议遵循的规则。** 规则 §1：I/O 线程上的任何东西都不阻塞；只能阻塞的工作交给线程池，按请求
  （`detach_to_pool`、`suspend_to_pool`、`spawn_blocking`）或按协议（`run_on_pool`）。HTTP/1.1、
  HTTP/3、gRPC 和 arpc 在这条规则下一直默认 inline；HTTP/2 现在重新如此。仍然阻塞的 handler 会被
  慢回调检测器（`Config::slow_callback_threshold`）报告。
- **主要用户并不需要它。** akit 的代理 listener 使用 `HttpConfig::default()`，其 handler 从不阻塞
  （上游请求是异步的；阻塞的检查通过 `suspend_to_pool` 按请求交给线程池，即 akit 的 A65）：在线程池
  默认值下，它白白付出了 9-13 倍的代价。

## 影响

- HTTP/2 handler 会阻塞的服务设置 `run_on_pool: true`（或把这些请求逐个交给线程池）。不这样做而又
  阻塞的服务，会拖住同一连接的其他 stream 和同一线程的其他连接，与 HTTP/1.1 相同；inline 等待一个由
  自己的 I/O 线程服务的客户端请求的 handler 永远等不到结果（规则 §1）。这两点在 2026-11-25 之前
  一直如此。
- 一个连接的各个 stream 在它的 I/O 线程上按请求完成的顺序逐个处理；handler 不阻塞时这没有代价。
- HTTP/2 handler 中调用 `Context::after` 时，回调重新在 I/O 线程上执行（事件循环定时器），而不是在
  共享的定时器线程上。

## 未做

- **更便宜的线程池路径。** 把交接合并（每次读取而不是每个请求一次入队和一次唤醒，多个 stream 的响应
  合成一次跨线程发送），以及不再是一把共享锁的线程池队列，可以缩小差距；交接本身仍在。这是
  `akio-pool` 与 HTTP/2 responder 的后续工作。
- **自动模式**（inline 执行，直到发现某个 handler 耗时过长，再改走线程池）：每个请求要多读一次时钟，
  而且在学到之前的那些请求仍会阻塞事件循环。没有实现。
