# ADR-005：依赖策略

[English](005-dependency-policy.md) | 简体中文

状态：已采纳（2026-11-13）

## 决定

核心 crate（`akio-core`、`akio-buf`、`akio-timer`、`akio-pool`）近乎零依赖；`akio-sys` 允许使用 `libc`。成熟的 **sans-io** crate 通过 feature 复用而不重写：`rustls`（TLS）、`quinn-proto` 或 `quiche`（QUIC，M5 评估后决定）、`aya`（eBPF）、`io-uring`（或自研薄封装）。不自研密码学。我们自己实现的协议状态机（HTTP/1、HTTP/2、WebSocket、KCP）采用 sans-io 并做模糊测试。

## 影响

- 安全性与工期优先于 fib 的零依赖立场。
- 每新增一个依赖需在 ADR 中记录，并在 CI 中通过 `cargo-deny`/`cargo-audit`（1.0 前加入）。
- `unsafe` 仅限 `akio-sys`、后端与 `akio-buf`；其余 crate 一律 `#![forbid(unsafe_code)]`。
