# 目录

[简介](introduction.md)

# 使用指南

- [快速上手](getting-started.md)
- [核心概念](concepts/index.md)
  - [Engine、Listener 与后端](concepts/engine.md)
  - [Handler、Acceptor 与 `Conn`](concepts/handlers.md)
  - [阻塞任务：逻辑线程池](concepts/blocking.md)
  - [背压](concepts/backpressure.md)
  - [生命周期与停机](concepts/lifecycle.md)
- [协议](protocols/index.md)
  - [TCP 与 UDP](protocols/tcp-udp.md)
  - [TLS](protocols/tls.md)
  - [HTTP/1.1 与 HTTP/2 服务端](protocols/http-server.md)
  - [路由、中间件与静态文件](protocols/http-routing.md)
  - [HTTP 客户端](protocols/http-clients.md)
  - [WebSocket](protocols/websocket.md)
  - [QUIC 与 HTTP/3](protocols/quic-h3.md)
  - [gRPC](protocols/grpc.md)
  - [arpc](protocols/arpc.md)
  - [SOCKS 与 HTTP CONNECT 代理](protocols/socks.md)
  - [协议复用](protocols/mux.md)
  - [KCP](protocols/kcp.md)
  - [WebRTC、STUN 与 TURN](protocols/webrtc.md)
  - [流媒体：hub、RTMP、HTTP-FLV、HLS](protocols/media.md)
    - [RTSP 与 WHIP/WHEP](protocols/media-rtsp.md)
    - [SRT](protocols/media-srt.md)
  - [BitTorrent](protocols/bittorrent.md)

# 运维

- [配置参考](configuration.md)
- [可观测性与热更新](observability.md)
- [性能调优](performance.md)
- [多进程服务（prefork）](prefork.md)
- [内核旁路（DPDK）](dpdk.md)
- [故障排查与常见问题](troubleshooting.md)

# 迁移指南

- [从 fib（Go）迁移](migration/from-fib.md)
- [从 tokio 迁移](migration/from-tokio.md)
- [从 hyper 与 axum 迁移](migration/from-hyper-axum.md)

# 内部实现

- [架构](architecture.md)
- [crate 一览与 API 文档](crates.md)
