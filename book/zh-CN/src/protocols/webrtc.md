# WebRTC、STUN 与 TURN

两个 crate：

- `flash-webrtc` 在 flash UDP socket 上运行 WebRTC peer。协议本身由
  [str0m](https://github.com/algesten/str0m) 完成，它是 sans-io 的 WebRTC 状态机：ICE（完整 agent 与
  ICE-lite、consent freshness）、带证书指纹校验的 DTLS 1.2/1.3、SRTP/SRTCP（AES-CM-SHA1-80、
  AEAD-AES-128/256-GCM）、SCTP 数据通道（DCEP；可靠或不可靠、有序或无序）、RTP/RTCP 媒体（Opus、
  VP8、VP9、H.264、H.265、AV1 打包；NACK 与 RTX、PLI/FIR、TWCC 与带宽估计、发送/接收报告）以及 SDP
  offer/answer。flash 用自己的 I/O 线程和一个共享定时器线程驱动它，并接入纯 Rust 的加密实现
  （RustCrypto 加 `dimpl` DTLS 栈：不需要 C 工具链，也不需要 OpenSSL）。
- `flash-turn` 提供 STUN 编解码、STUN 服务器和 TURN 服务器（UDP 上的 RFC 8656）。

互通测试对象是 pion（Go）：两种 offer 方向、数据通道与媒体、直连以及经 flash TURN 中继；还有 fib
的 Go 版 WebRTC（数据通道，双向）；TURN
服务器则与 pion/turn 客户端和 coturn 的 `turnutils_uclient` 互通（`tools/interop/webrtc/run.sh`，
`COTURN=1` 时包括 coturn）。

## 一个引擎上的服务器、TURN 服务器与客户端

```rust,ignore
{{#include ../../../../crates/flash-webrtc/examples/guide-webrtc.rs:engine}}
```

- `RtcServer::new(addrs)` 是一个 **UDP listener** 的 acceptor；它的所有 peer 共用这个端口。`addrs`
  是远端访问该监听器所用的地址（公网 IP 与端口），作为 host 候选写进每份 SDP。默认运行
  **ICE-lite**：服务器只应答连通性检查，适合一切公网可达的服务（SFU、WHIP/WHEP 端点）。数据报
  先按首个检查的 ICE 用户名、之后按源地址分派给各 peer。
- 构建方法（须在克隆前调用）：`config(|| rtc_config()...)` 构造每个 peer 的 str0m `RtcConfig`
  （编解码器、RTP 模式、BWE 等），`ice_lite(false)` 改为完整 agent，`close_on_disconnect(bool)`
  （默认 true：consent 过期的 peer 被关闭），`connect_timeout(Some(d))`（默认 30 秒：接受了 offer
  却一直连不上的 peer 被丢弃）。
- `TurnServer::new(TurnConfig::new(realm, auth, relay_ip))` 在另一个 UDP listener 上提供 TURN 与
  STUN。中继 socket 在运行时绑定，因此它需要引擎：`set_engine(&engine)`。

## Peer 与 handler

```rust,ignore
{{#include ../../../../crates/flash-webrtc/examples/guide-webrtc.rs:handler}}
```

`PeerHandler` 的每个回调都有默认实现：`on_ice_state`、`on_connected`、`on_channel_open` /
`on_channel_data` / `on_channel_close`、`on_media_added`、`on_media_data`（解包后的样本，默认的
帧模式）、`on_rtp`（RTP 模式）、`on_keyframe_request`（远端的 PLI/FIR）、`on_event`（str0m 报告的
其余一切：统计、带宽估计、发送报告等）、`on_close`。一个 peer 的回调逐个、按序执行，运行在读到
数据报的 I/O 线程、定时器线程或调用 `Peer` 方法的线程上；回调不能阻塞。

`Peer` 克隆开销很小，可在任意线程使用：

| 方法 | 作用 |
|---|---|
| `send(channel, data, binary)` | 发送数据通道消息（`Ok(false)`：缓冲已满） |
| `open_channel(cfg)` | 新建通道；已有通道时无需重新协商 |
| `write_media(mid, pt, wallclock, rtp_time, data)` | 写一个样本（由 str0m 打包） |
| `payload_type(mid, codec)` | 某编解码器协商得到的 payload type |
| `request_keyframe(mid, kind)` | 向远端发送方发 PLI 或 FIR |
| `renegotiate(f)` / `accept_answer` / `accept_offer` | 首次交换之后的 SDP 变更 |
| `add_remote_candidate(line)` | trickle ICE |
| `with_rtc(f)` | 调用任意 str0m API，之后驱动该 peer |
| `close()` | DTLS close notify，随后 `on_close` |

## 完整 ICE 客户端：`Endpoint`

```rust,ignore
{{#include ../../../../crates/flash-webrtc/examples/guide-webrtc.rs:client}}
```

```rust,ignore
{{#include ../../../../crates/flash-webrtc/examples/guide-webrtc.rs:endpoint}}
```

`Endpoint::bind(&engine, addr)` 用 `Engine::bind_udp` 绑定一个 UDP socket（引擎需要
`udp_client_threads(n)` 或一个 UDP listener）。ICE agent 需要的正是非连接 socket：一个本地端口向
每个远端候选发送检查。host 候选是 `addr`；`addr` 为未指定地址时，取默认路由所在网卡的地址。
`gather_srflx(stun, timeout)` 向 STUN 服务器询问公网地址并加为 server-reflexive 候选（会阻塞：
不要在回调中调用）。`create_offer(handler, |sdp| ...)` 通过 str0m 的 `SdpApi` 添加通道与媒体；
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

TCP/TLS 上的 TURN，以及 `flash-webrtc` 中的 TURN 客户端（`Endpoint` 的 relay 候选）；TCP 上的
ICE；mDNS 候选。str0m 自身的限制同样适用（见其文档）。
