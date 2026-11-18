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
- [ADR-011：HTTP/3 上的 WebSocket（RFC 9220）、QPACK 动态表与流式请求 body](011-h3-websocket-qpack-streaming.zh-CN.md)
- [ADR-012：SOCKS5 BIND / UDP ASSOCIATE、`Engine::adopt_tcp` 与 only-log 过滤器](012-socks-commands-and-log-filters.zh-CN.md)
- [ADR-013：共享的 0-RTT 防重放存储与 QUIC 兼容版本协商](013-shared-anti-replay-and-compatible-vn.zh-CN.md)
- [ADR-014：QUIC 会话票据与令牌绑定到 QUIC 版本](014-quic-version-bound-resumption.zh-CN.md)
- [ADR-015：可插拔的指标收集器](015-metrics-collectors.zh-CN.md)（2026-11-16 采纳）
- [ADR-019：SOCKS 客户端、HTTP/WebSocket 客户端的 SOCKS 代理、UDP 分片重组与 SOCKS4 BIND](019-socks-client-fragments-socks4-bind.zh-CN.md)（2026-11-17 采纳）
- [ADR-023：arpc 中间件、coder 与客户端连接池](023-arpc-middleware-coders-pools.zh-CN.md)（2026-11-17 采纳）
- [ADR-018：BitTorrent v2 与混合种子、Web 种子、LSD、IPv6 DHT、速率与做种限制](018-bittorrent-v2-webseeds-lsd-ipv6-limits.zh-CN.md)（2026-11-17 采纳）
- [ADR-022：protobuf 的 group、extension、edition、JSON 与反射](022-protobuf-gaps.zh-CN.md)（2026-11-18 采纳）
- [ADR-021：only-dtls 的 DTLS 1.3、连接 ID、PSK 与会话恢复](021-dtls13-cid-resumption.zh-CN.md)
- [ADR-017：TCP/TLS 上的 TURN、TURN 客户端、ICE-TCP 与 simulcast 发送](017-webrtc-turn-gaps.zh-CN.md)（2026-11-17 采纳）
- [ADR-016：fMP4 HLS、RTMP 与 RTSP 客户端、媒体 hub 中的 WebRTC 媒体](016-media-fmp4-clients-webrtc.zh-CN.md)（2026-11-17 采纳）
