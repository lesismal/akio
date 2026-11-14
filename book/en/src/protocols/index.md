# Protocols

Every protocol crate sits on the same core: it is an `Acceptor` (or produces one) that you
`.serve(..)` on a `Listener`, its callbacks run on the connection's I/O thread and must not
block, and its "send" handles are usable from any thread.

| Crate | Serve it with | Client | Chapter |
|---|---|---|---|
| `flash` | `Listener::tcp` / `udp` + your `Handler` | `Engine::dial`, `dial_udp` | [TCP and UDP](tcp-udp.md) |
| `flash::tls` | `Tls::server(cfg, acceptor)` | `Tls::client(cfg, name, acceptor)` | [TLS](tls.md) |
| `flash-http` | `serve(service)` / `serve_with(cfg, service)` | `client::Client`, `h2client::H2Client` | [HTTP servers](http-server.md), [Routing](http-routing.md), [Clients](http-clients.md) |
| `flash-ws` | `Context::upgrade_websocket` (flash-http) | `client::dial` / `connect` | [WebSocket](websocket.md) |
| `flash-quic` | `QuicServer::new(cfg, factory)` on a UDP listener | `flash_quic::dial` | [QUIC and HTTP/3](quic-h3.md) |
| `flash-h3` | `flash_h3::server(cfg, service)` on a UDP listener | `H3Client` | [QUIC and HTTP/3](quic-h3.md) |
| `flash-grpc` | `GrpcServer` (a flash-http service) | `GrpcClient` | [gRPC](grpc.md) |
| `flash-arpc` | `Server::new(routes)` | `flash_arpc::dial` | [arpc](arpc.md) |
| `flash-socks` | `Socks::new(engine_ref)`, `connect_proxy(engine_ref)` | – | [SOCKS and CONNECT](socks.md) |
| `flash-mux` | `Mux::new().route(rule, acceptor)` + `serve_dyn` | – | [Multiplexing](mux.md) |
| `flash-kcp` | `KcpServer::new(cfg, factory)` on a UDP listener | `flash_kcp::dial` | [KCP](kcp.md) |

Interoperability is tested against reference implementations: h2spec (147/147), Autobahn
(WebSocket server and client), grpc-go, quic-go and fib (HTTP/3), kcp-go, and fib's Go arpc;
the scripts are under `tools/interop` and `tools/autobahn`.
