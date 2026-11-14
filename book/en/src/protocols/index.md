# Protocols

Every protocol crate sits on the same core: it is an `Acceptor` (or produces one) that you
`.serve(..)` on a `Listener`, its callbacks run on the connection's I/O thread and must not
block, and its "send" handles are usable from any thread.

| Crate | Serve it with | Client | Chapter |
|---|---|---|---|
| `only` | `Listener::tcp` / `udp` + your `Handler` | `Engine::dial`, `dial_udp` | [TCP and UDP](tcp-udp.md) |
| `only::tls` | `Tls::server(cfg, acceptor)` | `Tls::client(cfg, name, acceptor)` | [TLS](tls.md) |
| `only-http` | `serve(service)` / `serve_with(cfg, service)` | `client::Client`, `h2client::H2Client` | [HTTP servers](http-server.md), [Routing](http-routing.md), [Clients](http-clients.md) |
| `only-ws` | `Context::upgrade_websocket` (only-http) | `client::dial` / `connect` | [WebSocket](websocket.md) |
| `only-quic` | `QuicServer::new(cfg, factory)` on a UDP listener | `only_quic::dial` | [QUIC and HTTP/3](quic-h3.md) |
| `only-h3` | `only_h3::serve(cfg, service)` on a UDP listener | `H3Client` | [QUIC and HTTP/3](quic-h3.md) |
| `only-grpc` | `GrpcServer` (a only-http service) | `GrpcClient` | [gRPC](grpc.md) |
| `only-arpc` | `Server::new(routes)` | `only_arpc::dial_blocking` | [arpc](arpc.md) |
| `only-socks` | `Socks::new(engine_ref)`, `connect_proxy(engine_ref)` | – | [SOCKS and CONNECT](socks.md) |
| `only-mux` | `Mux::new().route(rule, acceptor)` + `serve_any` | – | [Multiplexing](mux.md) |
| `only-kcp` | `KcpServer::new(cfg, factory)` on a UDP listener | `only_kcp::dial` | [KCP](kcp.md) |
| `only-webrtc` | `RtcServer::new(addrs)` on a UDP listener | `Endpoint::bind(engine, addr)` | [WebRTC](webrtc.md) |
| `only-turn` | `TurnServer::new(cfg)` or `StunServer` on a UDP listener | – | [WebRTC](webrtc.md) |
| `only-media` | `RtmpServer`, `RtspServer`, `SrtServer` (UDP), `MediaHttp` / `WhipServer` (only-http services) around one `Hub` | `srt::dial` / `push` / `pull` | [Streaming media](media.md) |
| `only-bittorrent` | `Client::new(cfg)` (its own listeners); `TrackerServer::http()` / `udp()`; `port::UdpPort` | `Client`, `TrackerClient` | [BitTorrent](bittorrent.md) |

Interoperability is tested against reference implementations: h2spec (147/147), Autobahn
(WebSocket server and client), grpc-go, quic-go and fib (HTTP/3), kcp-go, and fib's Go arpc;
the scripts are under `tools/interop` and `tools/autobahn`.
