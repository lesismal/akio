# only-webrtc

[English](README.md)

[only](https://github.com/lesismal/only) 的 WebRTC：自研、sans-io、无第三方依赖的 WebRTC 协议栈，
在 only UDP socket 上驱动。每一层都是安全 Rust（`#![forbid(unsafe_code)]`），构建于
`only-crypto` 之上。

- **ICE**（[`only-ice`](../only-ice/README.zh-CN.md)，RFC 8445）：ICE-lite 服务端（`Listener::udp`
  上的 `RtcServer`，所有 peer 共用一个端口）与完整 ICE agent（以 `Engine::bind_udp` 绑定 socket 的
  `Endpoint`）；host、server-reflexive（`Endpoint::gather_srflx`）与 peer-reflexive 候选，
  检查列表，常规提名，角色冲突，trickle ICE（RFC 8838），ICE 重启，consent freshness
  （RFC 7675），连接超时。
- **DTLS-SRTP**（[`only-dtls`](../only-dtls/README.zh-CN.md)）：DTLS 1.2，角色取自 `a=setup`，
  校验证书指纹；SRTP/SRTCP（[`only-srtp`](../only-srtp/README.zh-CN.md)，RFC 3711 / RFC 7714）
  支持 AES-CM-HMAC-SHA1-80/32 与 AEAD-AES-128/256-GCM，防重放，ROC 处理；密钥来自 DTLS 导出器。
- **数据通道**（[`only-sctp`](../only-sctp/README.zh-CN.md)）：基于 DTLS 的 SCTP（RFC 8261），
  拥塞控制、重传、PR-SCTP FORWARD-TSN（RFC 3758）、用于关闭通道的流重置（RFC 6525）、CRC32C；
  DCEP（RFC 8832）；可靠 / 最大重传次数 / 最大生存期，有序或无序，二进制 / 字符串 / 空消息，
  buffered-amount-low 事件。
- **媒体**（[`only-rtp`](../only-rtp/README.zh-CN.md)）：RTP/RTCP，Opus、G.711、G.722、VP8、
  VP9、H.264、H.265 与 AV1 打包；无抖动缓冲延迟的组帧器（`on_media_data`）或 RTP 模式
  （`on_rtp`）；发送/接收报告，通用 NACK 与 RTX（RFC 4588），PLI/FIR，REMB，传输层拥塞控制
  （TWCC 头扩展与反馈）及基于时延和丢包的带宽估计。
- **SDP** offer/answer（JSEP）：BUNDLE、rtcp-mux、mid/msid、ssrc/FID、extmap、
  rtpmap/fmtp/rtcp-fb 协商、setup/fingerprint、ice-ufrag/pwd/options/lite、候选、
  sctp-port/max-message-size；重新协商（新增媒体、方向、ICE 重启）。
- **自有类型**：API 全部是本 crate 自己的类型；`unstable` cargo feature 目前不增加任何内容。

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
let (_peer, answer) = server.accept_offer(&offer, Echo).unwrap(); // 来自 WHIP/WHEP、WebSocket ……
```

互通：与 pion（两个 offer 方向的数据通道、Opus/VP8 回显与 PLI，也经过 `only` TURN 中继）以及 fib
的 Go WebRTC 双向互通：`tools/interop/webrtc/run.sh`；与无头 Chrome 双向互通（数据通道，Chrome
的虚拟摄像头与麦克风媒体回显后由 Chrome 解码）：`tools/interop/webrtc/browser.sh`。STUN 与 TURN
服务端在 [`only-turn`](../only-turn/README.zh-CN.md) 中。

未实现：TURN 客户端（relay 本地候选需在别处获得）、simulcast 发送与分层选择、FEC、RTCP XR、
SDES-SRTP、DTLS 1.3。

指南：[WebRTC、STUN 与 TURN](https://lesismal.github.io/only/zh-CN/protocols/webrtc.html)。
