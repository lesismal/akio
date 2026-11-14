# 协议

每个协议 crate 都建立在同一个核心之上：它是（或者生成）一个 `Acceptor`，交给 `Listener` 的
`.serve(..)`；它的回调在连接所属 I/O 线程上执行，不能阻塞；它的"发送"句柄可以在任何线程使用。

| crate | 服务端用法 | 客户端 | 章节 |
|---|---|---|---|
| `only` | `Listener::tcp` / `udp` + 你的 `Handler` | `Engine::dial`、`dial_udp` | [TCP 与 UDP](tcp-udp.md) |
| `only::tls` | `Tls::server(cfg, acceptor)` | `Tls::client(cfg, name, acceptor)` | [TLS](tls.md) |
| `only-http` | `serve(service)` / `serve_with(cfg, service)` | `client::Client`、`h2client::H2Client` | [HTTP 服务端](http-server.md)、[路由](http-routing.md)、[客户端](http-clients.md) |
| `only-ws` | `Context::upgrade_websocket`（only-http） | `client::dial` / `connect` | [WebSocket](websocket.md) |
| `only-quic` | UDP listener 上的 `QuicServer::new(cfg, factory)` | `only_quic::dial` | [QUIC 与 HTTP/3](quic-h3.md) |
| `only-h3` | UDP listener 上的 `only_h3::serve(cfg, service)` | `H3Client` | [QUIC 与 HTTP/3](quic-h3.md) |
| `only-grpc` | `GrpcServer`（一个 only-http service） | `GrpcClient` | [gRPC](grpc.md) |
| `only-arpc` | `Server::new(routes)` | `only_arpc::dial_blocking` | [arpc](arpc.md) |
| `only-socks` | `Socks::new(engine_ref)`、`connect_proxy(engine_ref)` | – | [SOCKS 与 CONNECT](socks.md) |
| `only-mux` | `Mux::new().route(rule, acceptor)` + `serve_any` | – | [协议复用](mux.md) |
| `only-kcp` | UDP listener 上的 `KcpServer::new(cfg, factory)` | `only_kcp::dial` | [KCP](kcp.md) |
| `only-webrtc` | UDP listener 上的 `RtcServer::new(addrs)` | `Endpoint::bind(engine, addr)` | [WebRTC](webrtc.md) |
| `only-turn` | UDP listener 上的 `TurnServer::new(cfg)` 或 `StunServer` | – | [WebRTC](webrtc.md) |
| `only-media` | 围绕同一个 `Hub` 的 `RtmpServer`、`RtspServer`、`SrtServer`（UDP）、`MediaHttp` / `WhipServer`（only-http 服务） | `srt::dial` / `push` / `pull` | [流媒体](media.md) |
| `only-bittorrent` | `Client::new(cfg)`（自带 listener）；`TrackerServer::http()` / `udp()`；`port::UdpPort` | `Client`、`TrackerClient` | [BitTorrent](bittorrent.md) |

互通性用参考实现测试过：h2spec（147/147）、Autobahn（WebSocket 服务端与客户端）、grpc-go、
quic-go 和 fib（HTTP/3）、kcp-go，以及 fib 的 Go 版 arpc；脚本位于 `tools/interop` 和
`tools/autobahn`。
