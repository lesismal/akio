# 架构决策记录（ADR）

[English](README.md) | 简体中文

所有记录状态：**已采纳**（ADR-001 至 006 于 2026-11-13，ADR-007 于 2026-11-16）。

- [ADR-001：线程模型](001-threading-model.zh-CN.md)
- [ADR-002：Conn 句柄与锁模型](002-conn-lock-model.zh-CN.md)
- [ADR-003：Handler 与每连接状态](003-handler-and-state.zh-CN.md)
- [ADR-004：Reactor 抽象与每 listener 后端](004-reactor-abstraction.zh-CN.md)
- [ADR-005：依赖策略](005-dependency-policy.zh-CN.md)
- [ADR-006：eBPF 的定位](006-ebpf-role.zh-CN.md)
- [ADR-007：段内部分匹配的路由模式](007-partial-segment-routes.zh-CN.md)
- [ADR-008：TLS record_size_limit、证书压缩与 OCSP stapling](008-tls-extensions.zh-CN.md)
- [ADR-013：共享的 0-RTT 防重放存储与 QUIC 兼容版本协商](013-shared-anti-replay-and-compatible-vn.zh-CN.md)
