# Architecture Decision Records

English | [简体中文](README.zh-CN.md)

Status of all records: **accepted** (ADR-001 to 006 on 2026-11-13, ADR-007 on 2026-11-16).

- [ADR-001: Threading model](001-threading-model.md)
- [ADR-002: Conn handle and lock model](002-conn-lock-model.md)
- [ADR-003: Handler and per-connection state](003-handler-and-state.md)
- [ADR-004: Reactor abstraction and per-listener backends](004-reactor-abstraction.md)
- [ADR-005: Dependency policy](005-dependency-policy.md)
- [ADR-006: Role of eBPF](006-ebpf-role.md)
- [ADR-007: Partial-segment route patterns](007-partial-segment-routes.md)
- [ADR-008: TLS record_size_limit, certificate compression and OCSP stapling](008-tls-extensions.md)
- [ADR-012: SOCKS5 BIND / UDP ASSOCIATE, `Engine::adopt_tcp`, and only-log filters](012-socks-commands-and-log-filters.md)
