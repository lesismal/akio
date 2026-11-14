# 安全策略

[English](SECURITY.md) | 简体中文

## 支持的版本

flash 尚未发布 1.0。在 1.0.0 发布之前，只有 `main` 分支的最新提交会得到修复。自 1.0.0 起，支持当前主版本的最新次版本；安全修复以补丁版本发布，并在适用时，于新次版本发布后的 3 个月内向前一个次版本回移植。

## 报告漏洞

**请不要通过公开的 issue、pull request 或 discussion 报告安全问题。**

请通过 GitHub 的[私密漏洞报告](https://github.com/lesismal/flash/security/advisories/new)（“Security”标签页 -> “Report a vulnerability”）私下提交，并尽量包含：

- 受影响的 crate、版本或提交、操作系统/内核版本以及后端（epoll、kqueue、io_uring）；
- 问题描述及其影响（内存安全、拒绝服务、协议走私、信息泄露……）；
- 最小复现（代码、抓包或测试用例），如有；
- 是否希望署名致谢，以及署名方式。

## 处理流程

| 步骤 | 目标时间 |
|---|---|
| 确认收到报告 | 3 个工作日内 |
| 初步评估（接受 / 需要更多信息 / 不构成漏洞） | 7 天内 |
| 已接受报告的修复或缓解 | 高危/严重：30 天内；其它：尽力而为 |
| 公开通告 | 修复发布时，与报告者协调 |

已接受的问题会以 GitHub Security Advisory 发布，并提交到 [RustSec 漏洞数据库](https://rustsec.org/)，使 `cargo audit` / `cargo deny` 的用户能收到告警。我们遵循协调披露：请在公开细节前给我们合理的修复时间（默认 90 天；若漏洞已被利用则更短）。

## 范围

在范围内：本仓库的所有 crate（`crates/*`），包括 `unsafe` 代码中的内存安全缺陷（见 [docs/unsafe-review.zh-CN.md](docs/unsafe-review.zh-CN.md)）、远端对端可触发的解析器与协议状态机缺陷（HTTP/1、HTTP/2、HTTP/3、WebSocket、KCP、QUIC 接入层、SOCKS5、gRPC、mux）、绕过文档所述限制的资源耗尽，以及 TLS 默认配置问题。

不在范围内：`tools/` 下的压测与互通工具；不影响 flash 使用方式的依赖漏洞（请向上游报告，我们用 `cargo deny` 跟踪）；需要超出所配置限制的资源才能造成的拒绝服务。

## 已有的加固措施

- CI 中运行 `cargo deny check`（RustSec 漏洞通告、许可证、重复版本、来源）和 `cargo audit`；见 [deny.toml](deny.toml)。
- `unsafe` 仅存在于 `flash-sys`、`flash-uring` 和 `flash-ebpf` 的 `sys` 模块；其它 crate 一律 `#![forbid(unsafe_code)]`。每个 `unsafe` 块都用 `SAFETY:` 注释说明其不变式，由 Clippy 强制检查。审查流程见 [docs/unsafe-review.zh-CN.md](docs/unsafe-review.zh-CN.md)。
- 纯 Rust crate 跑 Miri，`flash-core` 的并发原语跑 loom，协议解析器做模糊测试。
