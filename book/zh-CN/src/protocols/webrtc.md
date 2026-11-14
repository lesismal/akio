# WebRTC、STUN 与 TURN

两个 crate：

- `only-webrtc` 在 only UDP socket 上运行 WebRTC peer，基于自研、sans-io、无第三方依赖的协议栈
  （DEV-PLAN 第 D 波），每层一个 crate，均为 `#![forbid(unsafe_code)]` 并构建于 `only-crypto` 之上：
  `only-ice`（完整 ICE agent 与 ICE-lite、检查列表、提名、角色冲突、peer-reflexive 候选、trickle、
  重启、consent freshness）、`only-dtls`（带证书指纹校验的 DTLS 1.2 与 DTLS-SRTP 密钥）、
  `only-srtp`（AES-CM-HMAC-SHA1-80/32 与 AEAD-AES-128/256-GCM 的 SRTP/SRTCP，防重放）、
  `only-sctp`（基于 DTLS 的 SCTP，拥塞控制、PR-SCTP、流重置、DCEP 数据通道：可靠或不可靠、有序或
  无序）以及 `only-rtp`（RTP/RTCP，Opus、G.711、G.722、VP8、VP9、H.264、H.265 与 AV1 打包，组帧器，
  NACK 与 RTX、PLI/FIR、REMB、TWCC 与带宽估计、发送/接收报告）。`only-webrtc` 本身负责 SDP
  offer/answer（BUNDLE、rtcp-mux、编解码器与头扩展协商、重新协商），并用 only 的 I/O 线程和一个
  共享定时器线程驱动各个 peer。
- `only-turn` 提供 STUN 编解码、STUN 服务器和 TURN 服务器（UDP 上的 RFC 8656）。

互通测试对象是 pion（Go）：两种 offer 方向、数据通道与媒体、直连以及经 only TURN 中继；还有 fib
的 Go 版 WebRTC（数据通道，双向）；TURN
服务器则与 pion/turn 客户端和 coturn 的 `turnutils_uclient` 互通（`tools/interop/webrtc/run.sh`，
`COTURN=1` 时包括 coturn）。无头 Chrome 在两个 offer 方向上均经过测试：数据通道，以及 Chrome
的虚拟摄像头与麦克风媒体由 `RtcServer` 回显后再由 Chrome 解码（`tools/interop/webrtc/browser.sh`）。

## 一个引擎上的服务器、TURN 服务器与客户端

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:engine}}
```

- `RtcServer::new(addrs)` 是一个 **UDP listener** 的 acceptor；它的所有 peer 共用这个端口。`addrs`
  是远端访问该监听器所用的地址（公网 IP 与端口），作为 host 候选写进每份 SDP。默认运行
  **ICE-lite**：服务器只应答连通性检查，适合一切公网可达的服务（SFU、WHIP/WHEP 端点）。数据报
  先按首个检查的 ICE 用户名、之后按源地址分派给各 peer。
- 构建方法（须在克隆前调用）：`config(|| rtc_config()...)` 构造每个 peer 的 `RtcConfig`
  （编解码器、RTP 模式、BWE、统计等），`ice_lite(false)` 改为完整 agent，`close_on_disconnect(bool)`
  （默认 true：consent 过期的 peer 被关闭），`connect_timeout(Some(d))`（默认 30 秒：接受了 offer
  却一直连不上的 peer 被丢弃）。
- `TurnServer::new(TurnConfig::new(realm, auth, relay_ip))` 在另一个 UDP listener 上提供 TURN 与
  STUN。中继 socket 在运行时绑定，因此它需要引擎：`set_engine(&engine)`。

## 类型

API 使用 only 自己的类型：`ChannelId`、`ChannelConfig`、`Mid`、`Pt`、`Codec`、`MediaKind`、
`Direction`、`MediaTime` / `Frequency`、`MediaData`、`MediaAdded`、`RtpPacket`、
`KeyframeRequest`、`Candidate`、`IceConnectionState`、`RtcConfig`、`SdpChanges`、`Event`。底层
的协议 crate 属于内部层级（其 API 可能在任何发布中变化），不会出现在 API 中。`unstable` cargo
feature 保留给不在 semver 承诺内的 API，目前不增加任何内容（以前用于暴露 str0m）。

## Peer 与 handler

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:handler}}
```

`PeerHandler` 的每个回调都有默认实现：`on_ice_state`、`on_connected`、`on_channel_open` /
`on_channel_data` / `on_channel_close`、`on_media_added`、`on_media_data`（解包后的样本，默认的
帧模式）、`on_rtp`（RTP 模式）、`on_keyframe_request`（远端的 PLI/FIR）、`on_event`
（`Event::ChannelBufferedAmountLow`，以及统计、带宽估计、发送报告等 `Event::Other`）、`on_close`。一个 peer 的回调逐个、按序执行，运行在读到
数据报的 I/O 线程、定时器线程或调用 `Peer` 方法的线程上；回调不能阻塞。

`Peer` 克隆开销很小，可在任意线程使用：

| 方法 | 作用 |
|---|---|
| `send(channel, data, binary)` | 发送数据通道消息（`Ok(false)`：缓冲已满） |
| `open_channel(cfg)` | 新建通道；已有通道时无需重新协商 |
| `write_media(mid, pt, wallclock, rtp_time, data)` | 写一个样本（自动打包） |
| `payload_type(mid, codec)` | 某编解码器协商得到的 payload type |
| `request_keyframe(mid, kind)` | 向远端发送方发 PLI 或 FIR |
| `renegotiate(f)` / `accept_answer` / `accept_offer` | 首次交换之后的 SDP 变更 |
| `add_remote_candidate(line)` | trickle ICE |
| `close()` | DTLS close notify，随后 `on_close` |

## 完整 ICE 客户端：`Endpoint`

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/only-webrtc/examples/guide-webrtc.rs:endpoint}}
```

`Endpoint::bind(&engine, addr)` 用 `Engine::bind_udp` 绑定一个 UDP socket（引擎需要
`udp_client_threads(n)` 或一个 UDP listener）。ICE agent 需要的正是非连接 socket：一个本地端口向
每个远端候选发送检查。host 候选是 `addr`；`addr` 为未指定地址时，取默认路由所在网卡的地址。
`gather_srflx(stun, timeout)` 向 STUN 服务器询问公网地址并加为 server-reflexive 候选（会阻塞：
不要在回调中调用）。`create_offer(handler, |sdp| ...)` 通过 `SdpChanges` 添加通道与媒体；
`accept_offer` 应答远端 offer。`Endpoint` 可与 ICE-lite 服务器、浏览器和 pion 以及其他
`Endpoint` 通信。

## TURN

`TurnConfig` 字段（均为公开字段，`TurnConfig::new` 设置默认值）：

| 字段 | 默认值 | 含义 |
|---|---|---|
| `realm`、`auth` | – | 长期凭据：`static_auth(realm, users)` 或 `ephemeral_auth(secret)`（TURN REST API，由 `ephemeral_credentials` 签发） |
| `relay_ip`、`public_ip` | –、无 | 中继绑定在 `relay_ip`；若设置了 `public_ip`，告诉客户端的是它（1:1 NAT） |
| `default_lifetime`、`max_lifetime` | 600 秒、3600 秒 | 分配的生存期 |
| `permission_lifetime`、`channel_lifetime` | 300 秒、600 秒 | RFC 8656 规定值 |
| `nonce_lifetime` | 600 秒 | nonce 无状态（过期时间加上它与客户端地址的 HMAC） |
| `max_allocations`、`max_allocations_per_user` | 16384、1024 | 配额（508、486） |
| `max_permissions`、`max_channels` | 256、256 | 每个分配的上限（508） |
| `peer_allowed`、`allow_private_peers` | 无、false | 默认拒绝回环、私有、链路本地、组播与保留地址的对端（`denied_by_default`）：中继进服务器自身网络会构成 SSRF 漏洞 |

支持 Allocate、Refresh、CreatePermission、ChannelBind、Send 与 Data 指示、ChannelData、带
`RESERVATION-TOKEN` 的 `EVEN-PORT` 以及 `REQUESTED-ADDRESS-FAMILY`；请求通过
`MESSAGE-INTEGRITY` 认证（`401`/`438` 质询），`FINGERPRINT` 会被校验并回带。中继流量经由客户端在
监听器上的连接发送，因此静默超过 `Config::udp_idle_timeout`（60 秒）的客户端在再次发送之前收不到
来自对端的数据：TURN 监听器应调大该超时。`TurnCore` 是不含 I/O 的同一服务器（由 `TurnEnv` 负责
发送），便于嵌入或测试。单独的 `StunServer` 只应答 Binding 请求。

## 尚未完成

TCP/TLS 上的 TURN，以及 `only-webrtc` 中的 TURN 客户端（`Endpoint` 的 relay 候选）；TCP 上的
ICE；解析 mDNS 候选（使用它们的对端仍可通过 peer-reflexive 候选连通）；simulcast 发送与分层
选择；FEC；RTCP XR；DTLS 1.3。
