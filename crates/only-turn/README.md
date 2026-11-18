# only-turn

[中文](README.zh-CN.md)

STUN and TURN for [`only`](https://github.com/lesismal/only): servers over `only` UDP, TCP and TLS
listeners, and a sans-io TURN client.

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
  connection. TCP relays (RFC 6062) are not offered.
- `client::Client`: a sans-io TURN client over UDP or a stream (allocate, refresh, channels,
  permissions); `only-webrtc`'s `Endpoint::gather_relay` drives one.
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
`COTURN=1`), and pion WebRTC peers relayed to a `only` WebRTC server.

Guide: [WebRTC, STUN and TURN](https://lesismal.github.io/only/en/protocols/webrtc.html).
