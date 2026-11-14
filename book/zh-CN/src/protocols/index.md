# 协议

每个协议 crate 都建立在同一个核心之上：它是（或者生成）一个 `Acceptor`，交给 `Listener` 的
`.serve(..)`；它的回调在连接所属 I/O 线程上执行，不能阻塞；它的"发送"句柄可以在任何线程使用。

| crate | 服务端用法 | 客户端 | 章节 |
|---|---|---|---|
| `flash` | `Listener::tcp` / `udp` + 你的 `Handler` | `Engine::dial`、`dial_udp` | [TCP 与 UDP](tcp-udp.md) |
| `flash::tls` | `Tls::server(cfg, acceptor)` | `Tls::client(cfg, name, acceptor)` | [TLS](tls.md) |
| `flash-http` | `serve(service)` / `serve_with(cfg, service)` | `client::Client`、`h2client::H2Client` | [HTTP 服务端](http-server.md)、[路由](http-routing.md)、[客户端](http-clients.md) |
| `flash-ws` | `Context::upgrade_websocket`（flash-http） | `client::dial` / `connect` | [WebSocket](websocket.md) |
| `flash-quic` | UDP listener 上的 `QuicServer::new(cfg, factory)` | `flash_quic::dial` | [QUIC 与 HTTP/3](quic-h3.md) |
| `flash-h3` | UDP listener 上的 `flash_h3::serve(cfg, service)` | `H3Client` | [QUIC 与 HTTP/3](quic-h3.md) |
| `flash-grpc` | `GrpcServer`（一个 flash-http service） | `GrpcClient` | [gRPC](grpc.md) |
| `flash-arpc` | `Server::new(routes)` | `flash_arpc::dial_blocking` | [arpc](arpc.md) |
| `flash-socks` | `Socks::new(engine_ref)`、`connect_proxy(engine_ref)` | – | [SOCKS 与 CONNECT](socks.md) |
| `flash-mux` | `Mux::new().route(rule, acceptor)` + `serve_any` | – | [协议复用](mux.md) |
| `flash-kcp` | UDP listener 上的 `KcpServer::new(cfg, factory)` | `flash_kcp::dial` | [KCP](kcp.md) |
| `flash-media` | 围绕同一个 `Hub` 的 `RtmpServer`、`RtspServer`、`SrtServer`（UDP）、`MediaHttp` / `WhipServer`（flash-http 服务） | `srt::dial` / `push` / `pull` | [流媒体](media.md) |

互通性用参考实现测试过：h2spec（147/147）、Autobahn（WebSocket 服务端与客户端）、grpc-go、
quic-go 和 fib（HTTP/3）、kcp-go，以及 fib 的 Go 版 arpc；脚本位于 `tools/interop` 和
`tools/autobahn`。
