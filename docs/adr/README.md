# Architecture Decision Records

English | [简体中文](README.zh-CN.md)

Status of all records: **accepted** (ADR-001 to 006 on 2026-11-13, ADR-007 to 009 on 2026-11-16).

- [ADR-001: Threading model](001-threading-model.md)
- [ADR-002: Conn handle and lock model](002-conn-lock-model.md)
- [ADR-003: Handler and per-connection state](003-handler-and-state.md)
- [ADR-004: Reactor abstraction and per-listener backends](004-reactor-abstraction.md)
- [ADR-005: Dependency policy](005-dependency-policy.md)
- [ADR-006: Role of eBPF](006-ebpf-role.md)
- [ADR-007: Partial-segment route patterns](007-partial-segment-routes.md)
- [ADR-008: TLS record_size_limit, certificate compression and OCSP stapling](008-tls-extensions.md)
- [ADR-009: Safe defaults for engine limits and timeouts](009-safe-defaults.md)
- [ADR-010: HTTP and WebSocket client: redirects, timeouts, resolution, system roots, proxies](010-http-client-gaps.md)
- [ADR-012: SOCKS5 BIND / UDP ASSOCIATE, `Engine::adopt_tcp`, and only-log filters](012-socks-commands-and-log-filters.md)
- [ADR-013: Shared 0-RTT anti-replay store and QUIC compatible version negotiation](013-shared-anti-replay-and-compatible-vn.md)
- [ADR-014: QUIC session tickets and tokens bound to the QUIC version](014-quic-version-bound-resumption.md)
- [ADR-015: Pluggable metrics collectors](015-metrics-collectors.md) (accepted 2026-11-16)
