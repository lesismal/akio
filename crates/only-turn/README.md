# only-turn

[中文](README.zh-CN.md)

STUN and TURN for [`only`](https://github.com/lesismal/only): servers over `only` UDP, TCP, TLS
and DTLS listeners, and a sans-io TURN client.

- `stun`: the STUN message codec (RFC 8489) with the TURN (RFC 8656) and ICE (RFC 8445)
  attributes, `MESSAGE-INTEGRITY` (HMAC-SHA1), `FINGERPRINT`, long-term keys.
- `StunServer`: answers Binding requests (server-reflexive address discovery).
- `TurnServer`: a TURN relay over UDP: allocations with long-term credentials (`static_auth`,
  `ephemeral_auth` for the TURN REST API), permissions, channels, Send/Data indications,
  refresh and lifetimes, `EVEN-PORT`/`RESERVATION-TOKEN`, stateless nonces, quotas, and a peer
  policy that refuses relaying into loopback and private networks by default. It answers STUN
  Binding requests too. Relay sockets are bound at run time with `only::Engine::bind_udp`.
- `TurnServer::stream()`: the same server for TCP listeners and TLS ones (`only::tls::Tls`):
  STUN and ChannelData framed on the stream (`framing`), relays over UDP, an allocation per
  connection; and TCP allocations (RFC 6062, ADR-076): a TCP relayed address, Connect,
  ConnectionAttempt for peers with a permission, ConnectionBind on new client connections,
  then raw bytes both ways with linked backpressure.
- `TurnServer::dtls(&tls_config)`: the same server for UDP listeners whose clients talk DTLS
  (RFC 7350, `turns:...?transport=udp`, on `only-dtls`): stateless cookies, DTLS 1.3 with
  fallback to 1.2, one STUN or ChannelData message per record, an allocation per DTLS
  association (ADR-054).
- `client::Client`: a sans-io TURN client over UDP or a stream (allocate, refresh, channels,
  permissions), and of TCP allocations (`ClientConfig::tcp_allocation`, `Client::connect`,
  `client::DataConnection` for ConnectionBind); `only-webrtc`'s `Endpoint::gather_relay` drives
  one.
- `client::TcpAllocation`: TCP allocations driven by an `only` engine, nothing blocking: the
  control connection and its timers, `connect` / `accept` whose data connections are served by
  the application's own acceptor (the ConnectionBind is a transport layer under its handler).
- `TurnConfig::tcp_connect_timeout` (30 s): how long a Connect waits for the peer, independent
  of the engine's `connect_timeout`.
- `TurnCore`: the same server as a sans-io state machine.

```rust,no_run
use std::sync::Arc;
use only::{Engine, Listener};
use only_turn::{TurnConfig, TurnServer, static_auth};

let auth = static_auth("example.org", [("alice", "secret")]);
let turn = TurnServer::new(TurnConfig::new("example.org", auth, "203.0.113.7".parse().unwrap()));
let engine = Arc::new(
    Engine::builder()
        .listen(Listener::udp("0.0.0.0:3478".parse().unwrap()).serve(turn.clone()))
        .build()
        .unwrap(),
);
turn.set_engine(&engine);
engine.run().unwrap();
```

Interop: the pion/turn client and coturn's `turnutils_uclient` (`tools/interop/webrtc/run.sh`,
`COTURN=1`; over DTLS: `tools/interop/webrtc/turn-dtls.sh`, which also relays `only-webrtc`
`Endpoint`s through coturn's DTLS listener; TCP allocations: `tools/interop/webrtc/turn-tcp.sh`,
coturn and pion/turn clients and servers both ways), and pion WebRTC peers relayed to a `only`
WebRTC server.

The DTLS listener negotiates connection IDs (RFC 9146, RFC 9147 §9; 8 bytes by default,
`dtls_with_connection_ids`): a client whose address changes keeps its association and
allocation, its path following the first authenticated record from the new address (ADR-072).

Guide: [WebRTC, STUN and TURN](https://lesismal.github.io/only/en/protocols/webrtc.html).
