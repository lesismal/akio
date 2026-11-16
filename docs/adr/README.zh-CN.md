# 架构决策记录（ADR）

[English](README.md) | 简体中文

所有记录状态：**已采纳**（ADR-001 至 006 于 2026-11-13，ADR-007 至 009 于 2026-11-16）。

- [ADR-001：线程模型](001-threading-model.zh-CN.md)
- [ADR-002：Conn 句柄与锁模型](002-conn-lock-model.zh-CN.md)
- [ADR-003：Handler 与每连接状态](003-handler-and-state.zh-CN.md)
- [ADR-004：Reactor 抽象与每 listener 后端](004-reactor-abstraction.zh-CN.md)
- [ADR-005：依赖策略](005-dependency-policy.zh-CN.md)
- [ADR-006：eBPF 的定位](006-ebpf-role.zh-CN.md)
- [ADR-007：段内部分匹配的路由模式](007-partial-segment-routes.zh-CN.md)
- [ADR-008：TLS record_size_limit、证书压缩与 OCSP stapling](008-tls-extensions.zh-CN.md)
- [ADR-009：引擎上限与超时的安全默认值](009-safe-defaults.zh-CN.md)
- [ADR-010：HTTP 与 WebSocket 客户端：重定向、超时、解析、系统根证书、代理](010-http-client-gaps.zh-CN.md)
- [ADR-012：SOCKS5 BIND / UDP ASSOCIATE、`Engine::adopt_tcp` 与 only-log 过滤器](012-socks-commands-and-log-filters.zh-CN.md)
