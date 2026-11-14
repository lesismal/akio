# only-webrtc

[中文](README.zh-CN.md)

WebRTC for [`only`](https://github.com/lesismal/only): the sans-io
[str0m](https://github.com/algesten/str0m) state machine driven over `only` UDP sockets.

- **ICE**: ICE-lite server (`RtcServer` on a `Listener::udp`, all peers on one port) and a full
  ICE agent (`Endpoint` on a socket bound with `Engine::bind_udp`), host and server-reflexive
  candidates (`Endpoint::gather_srflx`), trickle candidates, consent freshness, a connect timeout.
- **DTLS-SRTP**: DTLS 1.2/1.3 with certificate fingerprint verification; SRTP/SRTCP with
  AES-CM-SHA1-80 and AEAD-AES-128/256-GCM.
- **Data channels**: SCTP with DCEP; reliable or partially reliable, ordered or unordered.
- **Media**: RTP/RTCP, packetization of Opus, VP8, VP9, H.264, H.265, AV1; NACK and RTX, PLI/FIR,
  TWCC and bandwidth estimation; frame mode or RTP mode.
- **SDP** offer/answer and renegotiation.
- **Pure Rust crypto**: RustCrypto and the `dimpl` DTLS stack, no C toolchain.
- **Own types**: str0m stays out of the API (upgrading it is not a breaking change); the
  `unstable` cargo feature gives raw access (`only_webrtc::str0m`, `Peer::with_rtc`).

```rust,no_run
use only::{Engine, Listener};
use only_webrtc::{ChannelId, Peer, PeerHandler, RtcServer};

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
let (_peer, answer) = server.accept_offer(&offer, Echo).unwrap(); // from WHIP/WHEP, a WebSocket ...
```

Interop with pion (data channels and media in both offer directions, also through a `only` TURN
relay) and with fib's Go WebRTC: `tools/interop/webrtc/run.sh`. STUN and TURN servers are in
[`only-turn`](../only-turn/README.md).

Guide: [WebRTC, STUN and TURN](https://lesismal.github.io/only/en/protocols/webrtc.html).
