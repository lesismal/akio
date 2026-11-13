# ADR-004：Reactor 抽象与每 listener 后端

[English](004-reactor-abstraction.md) | 简体中文

状态：已采纳（2026-11-13）

## 决定

每个后端实现内部的 `Reactor` trait（accept、read、write、timer、wake、close）。协议 crate 只依赖 `Conn`/`Handler`。`Listener::backend(..)` 为每个 listener 选择后端；Engine 为每种在用的后端运行一组 I/O 线程（可按 listener 配置大小，默认每核一个）。逻辑池、定时器、缓冲池可在 Engine 级共享。

数据所有权：`on_data(&[u8])` 是借用，回调返回后失效（epoll：loop 缓冲；io_uring：provided buffer ring 条目；DPDK：mbuf）。io_uring 在缺少所需内核特性时降级为 epoll；macOS/BSD 开发用 kqueue 实现。

## 影响

- 可以混合后端（如 io_uring 的 HTTP + epoll 的 RPC + DPDK 的 UDP）。
- 借用式读取使所有后端保持零拷贝；需要保留数据时必须显式拷贝。
- 1.0 之前该 trait 属内部接口，可能变动；公开面只有 `Backend`/`Listener`。
