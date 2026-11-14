# flash-webrtc

[English](README.md)

[flash](https://github.com/lesismal/flash) 的 WebRTC：在 flash UDP socket 上驱动 sans-io 的
[str0m](https://github.com/algesten/str0m) 状态机。

- **ICE**：ICE-lite 服务端（`Listener::udp` 上的 `RtcServer`，所有 peer 共用一个端口）与完整 ICE
  agent（以 `Engine::bind_udp` 绑定 socket 的 `Endpoint`），host 与 server-reflexive 候选
  （`Endpoint::gather_srflx`），trickle 候选，consent freshness，连接超时。
- **DTLS-SRTP**：带证书指纹校验的 DTLS 1.2/1.3；AES-CM-SHA1-80 与 AEAD-AES-128/256-GCM 的
  SRTP/SRTCP。
- **数据通道**：带 DCEP 的 SCTP；可靠或部分可靠、有序或无序。
- **媒体**：RTP/RTCP，Opus、VP8、VP9、H.264、H.265、AV1 打包；NACK 与 RTX、PLI/FIR、TWCC 与带宽
  估计；帧模式或 RTP 模式。
- **SDP** offer/answer 与重新协商。
- **纯 Rust 加密**（`crypto_provider`）：RustCrypto 与 `dimpl` DTLS 栈，不需要 C 工具链。

```rust,no_run
use flash::{Engine, Listener};
use flash_webrtc::{ChannelId, Peer, PeerHandler, RtcServer};

struct Echo;
impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary);
    }
}

let server = RtcServer::new(vec!["203.0.113.7:3478".parse().unwrap()]);
let engine = Engine::builder()
    .listen(Listener::udp("0.0.0.0:3478".parse().unwrap()).serve(server.clone()))
    .build()
    .unwrap();
engine.start().unwrap();
let offer: String = todo!("the remote SDP offer");
let (_peer, answer) = server.accept_offer(&offer, Echo).unwrap(); // 来自 WHIP/WHEP、WebSocket 等
```

与 pion 互通（两种 offer 方向的数据通道与媒体，以及经 flash TURN 中继），也与 fib 的 Go 版 WebRTC 互通：
`tools/interop/webrtc/run.sh`。STUN 与 TURN 服务器在 [`flash-turn`](../flash-turn/README.zh-CN.md)。

指南：[WebRTC、STUN 与 TURN](https://lesismal.github.io/flash/zh-CN/protocols/webrtc.html)。
