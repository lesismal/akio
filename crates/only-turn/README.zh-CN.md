# only-turn

[English](README.md)

[only](https://github.com/lesismal/only) 的 STUN 与 TURN 服务器，运行在 only UDP socket 上。

- `stun`：STUN 消息编解码（RFC 8489），含 TURN（RFC 8656）与 ICE（RFC 8445）属性、
  `MESSAGE-INTEGRITY`（HMAC-SHA1）、`FINGERPRINT`、长期凭据密钥。
- `StunServer`：应答 Binding 请求（发现 server-reflexive 地址）。
- `TurnServer`：UDP 上的 TURN 中继：长期凭据的分配（`static_auth`，以及用于 TURN REST API 的
  `ephemeral_auth`）、权限、通道、Send/Data 指示、刷新与生存期、`EVEN-PORT`/`RESERVATION-TOKEN`、
  无状态 nonce、配额，以及默认拒绝中继到回环与私有网络的对端策略。它也应答 STUN Binding 请求。
  中继 socket 通过 `only::Engine::bind_udp` 在运行时绑定。
- `TurnCore`：同一服务器的 sans-io 状态机。

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

互通：pion/turn 客户端与 coturn 的 `turnutils_uclient`（`tools/interop/webrtc/run.sh`，
`COTURN=1`），以及经中继连到 only WebRTC 服务器的 pion WebRTC peer。

指南：[WebRTC、STUN 与 TURN](https://lesismal.github.io/only/zh-CN/protocols/webrtc.html)。
