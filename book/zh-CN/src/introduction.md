# 简介

[English](../en/) | [简体中文](../zh-CN/)

**akio** 是 Rust 的事件驱动网络库，是 Go 库 [fib](https://github.com/lesismal/fib) 的
Rust 对应物：功能面相同，但用 Rust 的方式实现：用所有权代替垃圾回收，用 `Send`/`Sync`
边界代替约定，协议状态机都是 sans-io 的，而且没有异步运行时。

```text
           你的 Handler / Service / WsHandler / QuicHandler ...
                 │ 回调，在连接所属的 I/O 线程上直接执行
 ┌───────────────┴─────────────────────────────────────────────────┐
 │ akio-http  akio-ws  akio-grpc  akio-arpc  akio-socks  ...  │  协议（sans-io）
 │ akio-tls（Transport 层）          akio-quic / akio-kcp（UDP）│
 ├─────────────────────────────────────────────────────────────────┤
 │ akio（Engine、Listener、Backend、Accel）  akio-core（Conn）   │
 ├─────────────────────────────────────────────────────────────────┤
 │ akio-epoll（epoll / kqueue）   akio-uring（io_uring）         │  每个 listener 一个后端
 │ akio-ebpf（SO_REUSEPORT 分流、sockmap 转发）                   │  可选加速层
 └─────────────────────────────────────────────────────────────────┘
```

## akio 的不同之处

- **同一连接一次只执行一轮。** 同一个连接的回调绝不会并发执行，因此每连接状态不需要锁，也不需要
  `Sync`。默认情况下（epoll/kqueue），连接的每一轮（读、回调、写）在任意空闲的工作窃取 worker 上
  执行；使用每核一线程的事件循环（`Scheduling::EventLoops`，io_uring 总是如此）时，连接从建立到
  关闭只属于一个 I/O 线程，回调直接在这个线程上执行。
- **回调，而不是 future。** `Handler` 收到的是 `on_data(&mut self, conn, bytes)`。没有执行器，
  没有每连接一个任务，热路径上也没有 `.await`。
- **线程安全的连接句柄。** `Conn` 是 `Clone + Send + Sync`：任何线程都可以 `send`、`close`
  或暂停读，而且都不会阻塞。
- **显式的阻塞任务池。** `Conn::spawn_blocking` 把任务交给有界、自适应的*逻辑线程池*执行，
  再把结果带回连接自己的 I/O 线程；对流水线协议还提供有序响应槽位。
- **每个 listener 独立选择后端。** 同一个 engine 里，HTTP listener 可以跑在 io_uring 上，
  RPC listener 跑在 epoll 上，各有各的线程；eBPF 分流是与之正交的一层。
- **同一内核上的多种协议。** TCP、UDP、TLS、HTTP/1.1、HTTP/2、WebSocket、HTTP/3 与 QUIC、
  gRPC、arpc、SOCKS4/5 与 HTTP CONNECT、KCP，以及按首字节嗅探的端口复用。

## 如何阅读本书

- 初次接触 akio：先读[快速上手](getting-started.md)，再读[核心概念](concepts/index.md)
  各章。它们很短，讲的是每个协议 crate 都遵守的规则。
- 查找某个协议：[协议](protocols/index.md)部分每个 crate 一章。
- 在生产环境运行 akio：[配置](configuration.md)、[可观测性](observability.md)、
  [性能调优](performance.md)和[故障排查](troubleshooting.md)。
- 从 Go、tokio 或 axum 迁移：见[迁移指南](migration/from-fib.md)。
- 想了解内部实现：见[架构](architecture.md)。

本书中的每一段 Rust 代码都引用自仓库里的示例程序，并由 `cargo build --workspace --examples`
编译检查；每段代码都注明了文件名，可以直接运行（`cargo run -p <crate> --example <name>`）。

## 状态

akio 正在接近 1.0。Linux 是第一等平台（epoll、io_uring、eBPF）；macOS 使用 kqueue，
用于开发。不支持 Windows。已完成和未完成的内容按里程碑记录在
[docs/DEV-PLAN.zh-CN.md](https://github.com/lesismal/akio/blob/main/docs/DEV-PLAN.zh-CN.md)；
实测性能见
[docs/BENCHMARKS.zh-CN.md](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.zh-CN.md)。
