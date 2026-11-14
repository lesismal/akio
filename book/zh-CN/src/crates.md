# crate 一览与 API 文档

API 参考由 rustdoc 生成。在这些 crate 发布之前，请在本地构建：

```console
$ cargo doc --workspace --no-deps --open
```

公开 crate 从 1.0.0 起遵循 semver；`only-pool`、`only-buf`、`only-timer`、`only-sys`、
`only-epoll` 和 `only-uring` 是内部实现 crate，其自身 API 可能在任何发布中变化（请通过 `only` /
`only-core` 使用）。标记为 `#[doc(hidden)]` 的条目同样不受保护。详见
[docs/api-stability.zh-CN.md](https://github.com/lesismal/flash/blob/main/docs/api-stability.zh-CN.md)，
变更记录：[CHANGELOG.zh-CN.md](https://github.com/lesismal/flash/blob/main/CHANGELOG.zh-CN.md)。

| crate | 作用 | 指南章节 |
|---|---|---|
| `only` | facade：`Engine`、`Listener`、`Backend`、`Accel`，重新导出核心 API、`tls`、`ebpf` | [核心概念](concepts/index.md) |
| `only-core` | `Conn`、`Handler`、`Acceptor`、`Config`、`Transport`、`Telemetry`；面向后端的 trait | [Handler](concepts/handlers.md) |
| `only-pool` | 逻辑（阻塞任务）线程池 | [阻塞任务](concepts/blocking.md) |
| `only-buf` | 分级缓冲池、`SharedBuf` | [架构](architecture.md) |
| `only-timer` | I/O 事件循环使用的分层时间轮 | [架构](architecture.md) |
| `only-sys` | 经过审查的 `unsafe` 系统调用封装（poller、唤醒器、socket、批量 UDP） | [架构](architecture.md) |
| `only-epoll` | epoll / kqueue 后端、UDP 线程组 | [Engine 与后端](concepts/engine.md) |
| `only-uring` | io_uring 后端 | [Engine 与后端](concepts/engine.md) |
| `only-ebpf` | `SO_REUSEPORT` 分流、sockmap 转发 | [Engine 与后端](concepts/engine.md) |
| `only-prefork` | 多进程服务：supervisor、worker 重启、优雅关闭与重载 | [Prefork](prefork.md) |
| `only-dpdk`（`only::dpdk`，实验性） | 内核旁路：基于 DPDK / TAP / AF_PACKET 的用户态 TCP/IP（smoltcp） | [内核旁路（DPDK）](dpdk.md) |
| `only-tls`（`only::tls`） | 作为连接 transport 的 TLS（底层为 rustls） | [TLS](protocols/tls.md) |
| `only-http` | HTTP/1.1、HTTP/2、Router、中间件、静态文件、客户端、可观测性 | [HTTP 服务端](protocols/http-server.md) |
| `only-ws` | WebSocket 服务端会话与客户端 | [WebSocket](protocols/websocket.md) |
| `only-quic` | 基于 quinn-proto 的 QUIC | [QUIC 与 HTTP/3](protocols/quic-h3.md) |
| `only-h3` | HTTP/3 与 QPACK | [QUIC 与 HTTP/3](protocols/quic-h3.md) |
| `only-grpc` | gRPC 服务端与客户端 | [gRPC](protocols/grpc.md) |
| `only-arpc` | arpc（lesismal/arpc 线路格式） | [arpc](protocols/arpc.md) |
| `only-socks` | SOCKS4/4a/5 与 HTTP CONNECT 代理 | [SOCKS](protocols/socks.md) |
| `only-mux` | 一个端口上的多种协议 | [协议复用](protocols/mux.md) |
| `only-kcp` | KCP（兼容 kcp-go） | [KCP](protocols/kcp.md) |
| `only-webrtc` | 基于 str0m 的 WebRTC：ICE、DTLS-SRTP、数据通道、媒体 | [WebRTC](protocols/webrtc.md) |
| `only-turn` | STUN 编解码、STUN 与 TURN 服务器 | [WebRTC](protocols/webrtc.md) |
| `only-media` | 流媒体：hub、RTMP、RTSP、SRT、FLV、HTTP-FLV、WS-FLV、HLS、WHIP/WHEP 信令 | [流媒体](protocols/media.md) |
| `only-bittorrent` | BitTorrent：tracker、peer wire + MSE、uTP、DHT、客户端（兼容 libtorrent 和 aria2） | [BitTorrent](protocols/bittorrent.md) |

设计记录：[docs/adr](https://github.com/lesismal/flash/tree/main/docs/adr)。计划与状态：
[docs/ROADMAP.zh-CN.md](https://github.com/lesismal/flash/blob/main/docs/ROADMAP.zh-CN.md)、
[docs/DEV-PLAN.zh-CN.md](https://github.com/lesismal/flash/blob/main/docs/DEV-PLAN.zh-CN.md)。
基准测试：[docs/BENCHMARKS.zh-CN.md](https://github.com/lesismal/flash/blob/main/docs/BENCHMARKS.zh-CN.md)。
