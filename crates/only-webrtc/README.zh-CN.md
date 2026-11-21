# only-webrtc

[English](README.md)

[only](https://github.com/lesismal/only) 的 WebRTC：自研、sans-io、无第三方依赖的 WebRTC 协议栈，
在 only UDP socket 上驱动。每一层都是安全 Rust（`#![forbid(unsafe_code)]`），构建于
`only-crypto` 之上。

- **ICE**（[`only-ice`](../only-ice/README.zh-CN.md)，RFC 8445）：ICE-lite 服务端（`Listener::udp`
  上的 `RtcServer`，所有 peer 共用一个端口）与完整 ICE agent（以 `Engine::bind_udp` 绑定 socket 的
  `Endpoint`）；host、server-reflexive（`Endpoint::gather_srflx`）与 peer-reflexive 候选，
  检查列表，常规提名（以 `RtcConfig::enable_ice_aggressive_nomination` / `enable_ice_renomination`
  启用激进提名与重新提名），角色冲突，trickle ICE（RFC 8838），ICE 重启，consent freshness
  （RFC 7675），连接超时；与浏览器一样解析 mDNS（`.local`）候选，并把我方主机地址隐藏在 mDNS 名字
  之后（`Endpoint::resolve_mdns`、`conceal_host_candidates`），走 IPv4（`224.0.0.251`）与 IPv6
  （`ff02::fb`，在每个有链路本地地址的接口上加入；链路本地地址保留其接口，ADR-054）。
- **DTLS-SRTP**（[`only-dtls`](../only-dtls/README.zh-CN.md)）：DTLS 1.3（RFC 9147，与 Chrome 157
  协商一致），可回退到 DTLS 1.2（pion；`RtcConfig::enable_dtls13(false)` 只用 DTLS 1.2），角色取自
  `a=setup`，校验证书指纹；SRTP/SRTCP（[`only-srtp`](../only-srtp/README.zh-CN.md)，RFC 3711 /
  RFC 7714）支持 AES-CM-HMAC-SHA1-80/32 与 AEAD-AES-128/256-GCM，防重放，ROC 处理；密钥来自 DTLS
  导出器。可选开启（ADR-048）：cryptex（`a=cryptex`，RFC 9335，`enable_cryptex`）与 RFC 6904 加密头部
  扩展（`enable_encrypted_header_extensions`）。面向 SIP 网关等非浏览器对端可选开启（ADR-054）：
  SDES-SRTP（`enable_sdes_srtp`，SDP 中的 RFC 4568 `a=crypto` 密钥，`RTP/SAVPF`；支持 MKI 与多个主密钥，
  `set_sdes_mki_length`；与之并存的数据通道在自己的段中运行 DTLS；无 ICE 时（`enable_ice(false)` 或远端
  SDP 不带 ICE）媒体发往 `c=` 地址与 `m=` 端口，ADR-072；DTLS-SRTP offer 仍以 DTLS-SRTP 应答，浏览器
  永远看不到 `a=crypto`）。
- **数据通道**（[`only-sctp`](../only-sctp/README.zh-CN.md)）：基于 DTLS 的 SCTP（RFC 8261），
  拥塞控制、重传、PR-SCTP FORWARD-TSN（RFC 3758）、用于关闭通道的流重置（RFC 6525）、CRC32C；
  DCEP（RFC 8832）；可靠 / 最大重传次数 / 最大生存期，有序或无序，二进制 / 字符串 / 空消息，
  buffered-amount-low 事件。
- **媒体**（[`only-rtp`](../only-rtp/README.zh-CN.md)）：RTP/RTCP，Opus、G.711、G.722、VP8、
  VP9、H.264、H.265 与 AV1 打包；无抖动缓冲延迟的组帧器（`on_media_data`）或 RTP 模式
  （`on_rtp`）；发送/接收报告，通用 NACK 与 RTX（RFC 4588），PLI/FIR，REMB，传输层拥塞控制
  （TWCC 头扩展与反馈）及基于时延和丢包、会探测路径的带宽估计（ADR-050：开始时、受应用限制时、
  下降之后以及 ICE 候选对改变时，以短簇节奏发送最近媒体的 RTX 副本）。可选开启（`RtcConfig`，ADR-039、ADR-048）：视频
  FEC（带 `a=ssrc-group:FEC-FR` 流的 FlexFEC `flexfec-03`，或 RED 中的 ULPFEC，后者也与 Chrome 一样按
  simulcast 线路的每个编码发送），在帧组装器和 NACK 之前修复包，按修复前丢包率调节发送的保护率；Opus
  RED（`red/48000/2`，排在 Opus 之前使 Chrome 发送；冗余副本代替丢失的包，最多发送两个）；用 RFC 8888 拥塞控制反馈代替 TWCC；RTCP XR 接收方参考时间
  （接收方 RTT）；TMMBR / TMMBN（`Peer::request_max_bitrate`，收到的请求会限制估计值）。可选开启
  （ADR-058）：关于接收流的 RTCP XR 丢包 RLE、重复 RLE、接收时间与 VoIP 指标（`enable_rtcp_xr_blocks`，
  收到的以事件报告）；带保护级别的 ULPFEC（`set_ulpfec_level0`，用于能读级别的接收方，不包括 Chrome）。
  CNAME 是每个对端连接一个的 RFC 7022 随机 CNAME；收到的 SDES 项以类型化形式报告。
- **RTCP 走独立端口**（ADR-058，不复用 RTCP 的 RFC 5761，ICE 组件 2）：调用 `Endpoint::bind_rtcp`
  后，不带 `a=rtcp-mux` 的 offer（SIP 终端、较老的 RTP 栈）以 `a=rtcp` 应答，RTCP 走单独的套接字；
  `RtcConfig::set_rtcp_mux_policy` 让我方 offer 提议（`Negotiate`）或要求（`Off`）这种方式。DTLS-SRTP
  每个组件各握手一次（RFC 5764），SDES-SRTP 两个组件都加密。浏览器仍用 rtcp-mux 与 BUNDLE。组件 2
  从 RTCP 套接字获得服务器反射与中继候选（ADR-072），ICE-lite 的 `RtcServer` 可为它另设监听器
  （`rtcp_candidates`、`rtcp()`）。
- **无 BUNDLE**（ADR-072）：`set_bundle_policy(BundlePolicy::Disabled)`、不带 `a=group:BUNDLE` 的远端
  offer 或拒绝我方 BUNDLE 的应答，使每个段拥有自己的 ICE 代理、DTLS 关联与 SRTP 密钥（与 Chrome
  `max-compat` 双向互通）；`Endpoint::bind_transport_socket` 为传输提供各自的套接字。此时没有传输级拥塞控制。
- **数据通道优先级**（ADR-072）：`ChannelPriority`（DCEP 128 到 1024）与 SCTP 流调度器
  （`set_sctp_scheduler`：默认加权公平排队，另有优先级、轮询等）。
- **SDP** offer/answer（JSEP）：BUNDLE、rtcp-mux（或 `a=rtcp`）、mid/msid、ssrc/FID、extmap、
  rtpmap/fmtp/rtcp-fb 协商、setup/fingerprint、ice-ufrag/pwd/options/lite、候选、
  sctp-port/max-message-size；重新协商（新增媒体、方向、ICE 重启）；simulcast 发送（`a=rid`、
  `a=simulcast`、RID/MID 头扩展）与接收，以及用于层选择的按层关键帧请求（`request_layer_keyframe`）。
- **`Endpoint` 的候选**：host、server-reflexive（`gather_srflx`）、经 UDP、DTLS（RFC 7350，
  `RelayServer::dtls`、`turns:...?transport=udp`）、TCP 或 TLS 的 TURN 分配得到的
  relay（`gather_relay`，以及用 `RelayServer` 或 `turn:`/`turns:` URL 的 `gather_relay_via`；丢失的分配会
  重新建立）、被动、主动与同时打开的 ICE-TCP（`listen_tcp`、`dial_tcp`、`listen_tcp_so`，RFC 6544），
  以及候选策略（`candidate_filter`，相当于 `iceTransportPolicy`）。`RtcServer` 可在 engine 的 TCP
  监听器上提供被动 ICE-TCP（`tcp_candidates`、`tcp`）。
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
的虚拟摄像头与麦克风媒体回显后由 Chrome 解码；用 mDNS 隐藏地址的 `Endpoint` 与开启 mDNS 隐藏的
Chrome 互相解析对方名字后连通；两种 DTLS 角色的 DTLS 1.3；在 Chrome 的 `rtpHeaderEncryptionPolicy`
"require" 下双向 cryptex；我方 simulcast 线路带按编码的 ULPFEC 经过丢包）：
`tools/interop/webrtc/browser.sh`；与无头 Chrome 的丢包下 FEC（双方的 FEC）、双向 RFC 8888、XR 与
TMMBR、双向丢包下的 Opus RED、simulcast 上 Chrome 的按层 ULPFEC：`tools/interop/webrtc/fec.sh`；以 Chrome 为接收方时估计值的爬升（探测）：
`tools/interop/webrtc/bwe.sh`；与无头 Firefox
双向互通（与 usrsctp 之间的数据通道）：`tools/interop/webrtc/firefox.sh`；coturn 的 DTLS 监听器（经
`turns:...?transport=udp` 由它中继的 `Endpoint`）：`tools/interop/webrtc/turn-dtls.sh`；纯 IPv6 链路上
的 IPv6 mDNS（avahi 解析我方被隐藏的名字并发布由我方解析的名字）：`tools/interop/webrtc/mdns6.sh`
（经 IPv6 与 Chrome 的互通在 `browser.sh` 中）。STUN 与 TURN
服务端在 [`only-turn`](../only-turn/README.zh-CN.md) 中。

与 Chrome（`max-compat`）双向的无 BUNDLE 互通：`tools/interop/webrtc/bundle.sh`。

未实现：simulcast 线路上的 FlexFEC（基于 RID 的 simulcast 不声明 FEC 流；Chrome 也不发送）、DTLS-SRTP
下的 MKI（没有对应的 SDP，也没有浏览器使用）、与浏览器的 RFC 6904（没有浏览器提供）、让普通（无 ICE）
媒体锁定其实际来源地址、不做 BUNDLE 的会话中跨传输的传输级拥塞控制。pion 没有非复用或非 BUNDLE 模式，
Chrome 157 没有 `RTCDataChannel.priority`：这些在 `Endpoint` 之间测试。浏览器和 pion 都没有同时打开的
ICE-TCP 候选：`listen_tcp_so` 在 `Endpoint` 之间测试。

指南：[WebRTC、STUN 与 TURN](https://lesismal.github.io/only/zh-CN/protocols/webrtc.html)。
