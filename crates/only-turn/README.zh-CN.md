# only-turn

[English](README.md)

[only](https://github.com/lesismal/only) 的 STUN 与 TURN：运行在 only UDP、TCP、TLS 与 DTLS 监听器上的服务器，
以及 sans-io 的 TURN 客户端。

- `stun`：STUN 消息编解码（RFC 8489），含 TURN（RFC 8656）与 ICE（RFC 8445）属性、
  `MESSAGE-INTEGRITY`（HMAC-SHA1）、`FINGERPRINT`、长期凭据密钥。
- `StunServer`：应答 Binding 请求（发现 server-reflexive 地址）。
- `TurnServer`：UDP 上的 TURN 中继：长期凭据的分配（`static_auth`，以及用于 TURN REST API 的
  `ephemeral_auth`）、权限、通道、Send/Data 指示、刷新与生存期、`EVEN-PORT`/`RESERVATION-TOKEN`、
  无状态 nonce、配额，以及默认拒绝中继到回环与私有网络的对端策略。它也应答 STUN Binding 请求。
  中继 socket 通过 `only::Engine::bind_udp` 在运行时绑定。
- `TurnServer::stream()`：用于 TCP 监听器与 TLS 监听器（`only::tls::Tls`）的同一服务器：STUN 与
  ChannelData 在流上分帧（`framing`），中继走 UDP，分配随连接存在；以及 TCP 分配（RFC 6062，ADR-076）：
  TCP 中继地址、Connect、有权限的对端连入时的 ConnectionAttempt、在新客户端连接上的 ConnectionBind，
  之后双向传输原始字节，背压两侧联动。
- `TurnServer::dtls(&tls_config)`：用于客户端说 DTLS 的 UDP 监听器的同一服务器（RFC 7350，
  `turns:...?transport=udp`，基于 `only-dtls`）：无状态 cookie，DTLS 1.3 可回退到 1.2，每条记录一条
  STUN 或 ChannelData 消息，分配随 DTLS 关联存在（ADR-054）。
- `client::Client`：UDP 或流上的 sans-io TURN 客户端（分配、刷新、channel、权限），也支持 TCP 分配
  （`ClientConfig::tcp_allocation`、`Client::connect`、用于 ConnectionBind 的 `client::DataConnection`）；
  `only-webrtc` 的 `Endpoint::gather_relay` 驱动它。
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
`COTURN=1`；DTLS 上：`tools/interop/webrtc/turn-dtls.sh`，它还让 `only-webrtc` 的 `Endpoint` 经
coturn 的 DTLS 监听器中继；TCP 分配：`tools/interop/webrtc/turn-tcp.sh`，coturn 与 pion/turn 的客户端和服务器
双向互通），以及经中继连到 only WebRTC 服务器的 pion WebRTC peer。

DTLS 监听器协商连接 ID（RFC 9146、RFC 9147 §9；默认 8 字节，`dtls_with_connection_ids`）：地址变化的
客户端保留其关联与分配，路径跟随新地址上第一条通过认证的记录（ADR-072）。

指南：[WebRTC、STUN 与 TURN](https://lesismal.github.io/only/zh-CN/protocols/webrtc.html)。
