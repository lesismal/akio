# WebRTC、STUN 与 TURN

两个 crate：

- `only-webrtc` 在 only UDP socket 上运行 WebRTC peer，基于自研、sans-io、无第三方依赖的协议栈
  （DEV-PLAN 第 D 波），每层一个 crate，均为 `#![forbid(unsafe_code)]` 并构建于 `only-crypto` 之上：
  `only-ice`（完整 ICE agent 与 ICE-lite、检查列表、提名、角色冲突、peer-reflexive 候选、trickle、
  重启、consent freshness）、`only-dtls`（带证书指纹校验的 DTLS 1.2 与 1.3 及 DTLS-SRTP 密钥，见下文）、
  `only-srtp`（AES-CM-HMAC-SHA1-80/32 与 AEAD-AES-128/256-GCM 的 SRTP/SRTCP，防重放；该 crate
  还支持 AES-192/256-CM、NULL、MKI 与换钥、cryptex 以及 RFC 6904 头部扩展加密，peer 尚未在 SDP 中
  协商它们）、
  `only-sctp`（基于 DTLS 的 SCTP，拥塞控制、PR-SCTP、流重置、DCEP 数据通道：可靠或不可靠、有序或
  无序；对端提供时使用 I-DATA 消息交错，大消息不再阻塞其他通道上的小消息，各通道按优先级以加权公平
  排队共享关联，ADR-037）以及 `only-rtp`（RTP/RTCP，Opus、G.711、G.722、VP8、VP9、H.264、H.265 与 AV1 打包，组帧器，
  NACK 与 RTX、PLI/FIR、REMB、TWCC 与带宽估计、发送/接收报告；还有 RTCP XR、TMMBR / TMMBN、
  RFC 8888 反馈与 ULPFEC / FlexFEC / RED，peer 尚未使用）。`only-webrtc` 本身负责 SDP
  offer/answer（BUNDLE、rtcp-mux、编解码器与头扩展协商、重新协商），并用 only 的 I/O 线程和一个
  共享定时器线程驱动各个 peer。
- `only-turn` 提供 STUN 编解码、STUN 服务器、TURN 服务器（UDP、TCP 与 TLS 上的 RFC 8656）以及
  sans-io 的 TURN 客户端。

互通测试对象是 pion（Go）：两种 offer 方向、数据通道与媒体、直连以及经 only TURN 中继，`Endpoint`
只提供中继候选（来自 only、pion/turn 与 coturn 的 TURN 服务器，经 UDP、TCP 与 TLS 分配）、只提供被动或
只提供主动 ICE-TCP 候选，pion 经 ICE-TCP 连到 `RtcServer`，以及向 pion 发送 simulcast；还有 fib 的 Go 版 WebRTC（数据通道，双向）；TURN 服务器经 UDP、TCP 与 TLS 与 pion/turn
客户端和 coturn 的 `turnutils_uclient` 互通；TURN 客户端经 UDP、TCP 与 TLS 与 pion/turn、coturn 和 only
互通（`tools/interop/webrtc/run.sh`，`COTURN=1` 时包括 coturn，`linux.sh` 在 Linux 容器中全部运行）。无头 Chrome 在两个 offer 方向上均经过测试：数据通道，以及 Chrome
的虚拟摄像头与麦克风媒体由 `RtcServer` 回显后再由 Chrome 解码；只用 ICE-TCP（Chrome 连到 `RtcServer`，
`Endpoint` 连到 Chrome）；只用中继（Chrome 以 `iceTransportPolicy: "relay"` 经 `only-turn` 的 UDP、TCP 与
TLS，`Endpoint` 只带经 TCP 或 TLS 分配的中继候选）；以及 simulcast：Chrome 向 SFU 发送三层 VP8，SFU 以
simulcast 及所选的一层发回，在 Chrome 解码时切换层（`tools/interop/webrtc/browser.sh`）。pion 与我们
协商 I-DATA；Chrome 157 使用 DATA chunk，除非打开其 `WebRTC-DataChannelMessageInterleaving` field trial
（打开后同样的测试经 I-DATA 通过）。SCTP 层本身也经 UDP 与 pion/sctp 互通测试，交错开与关、有无丢包
（`tools/interop/sctp/run.sh`）。

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
  却一直连不上的 peer 被丢弃），`max_peers(n)`（默认 1024，即 `DEFAULT_MAX_PEERS`：超出后 offer 以
  `Error::TooManyPeers` 失败；0 表示不限；`Endpoint` 上绑定之后也可设置）。
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
| `write_simulcast(mid, rid, pt, wallclock, rtp_time, data)` | 写 simulcast 某一编码的样本 |
| `payload_type(mid, codec)` | 某编解码器协商得到的 payload type |
| `request_keyframe(mid, kind)` | 向远端发送方发 PLI 或 FIR |
| `request_layer_keyframe(mid, rid, kind)` | 只向接收到的某一 simulcast 层发 PLI 或 FIR |
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

### 中继候选

`gather_relay(turn_server, username, password, timeout)` 通过 endpoint 的 UDP socket 在 TURN 服务器上
分配一个中继地址，加为 relay 候选（服务器看到的 server-reflexive 地址若是新的也一并加入）；与
`gather_srflx` 一样会阻塞。该分配由 endpoint 的所有 peer 共享，并持续维持（刷新、权限与 channel，在
WebRTC 定时器线程上）直到 `Endpoint::close` 将其删除。每个 endpoint 最多 4 个分配；被拒或超过上限返回
`Error::Turn`，无应答返回 `Error::Timeout`。

```rust,ignore
let ep = Endpoint::bind(&engine, "0.0.0.0:0".parse()?)?;
let relayed = ep.gather_relay("203.0.113.7:3478".parse()?, "alice", "secret", Duration::from_secs(5))?;
```

屏蔽 UDP 的网络经 TCP 或 443 端口上的 TLS 访问 TURN 服务器：`gather_relay_via(&engine, &server,
timeout)` 接受一个 `RelayServer`，可用 `RelayServer::udp`、`tcp` 或 `tls(addr, server_name, tls_config,
..)` 创建，也可像浏览器的 `iceServers` 那样从 URL 解析（`turn:host[:port][?transport=udp|tcp]`、
`turns:host[:port]`；`turns:` 服务器还需要 `tls_config`，因为没有默认根证书）。由引擎拨号建立连接（需要
`client_threads(n)` 或一个 TCP listener），分配依附于该连接。经 TCP 或 TLS 分配的候选优先级低于经 UDP
分配的候选，且不产生 server-reflexive 候选。建立后丢失的分配（连接关闭、刷新失败）会在 1 秒后重新分配，
之后等待时间加倍至最多一分钟：新的中继候选为新 peer 替换旧候选，并加入已打开的 peer；对端可从中继到达时
这些 peer 继续工作（否则用 ICE 重启把它提供给对端）。

```rust,ignore
let turns = RelayServer::from_url("turns:turn.example.com:443", "alice", "secret")?
    .tls_config(tls_client_config);
let relayed = ep.gather_relay_via(&engine, &turns, Duration::from_secs(5))?;
```

`candidate_filter(f)` 是 endpoint 的 `iceTransportPolicy`：新 peer 只使用并只发出 `f` 接受的本地候选，
例如 `|c| c.kind() == "relay"`（只用中继）或 `|c| c.transport() == "tcp"`（只用 ICE-TCP）。

### TCP 上的 ICE

`listen_tcp(&engine, addr)` 在单独的 TCP 端口上加入被动 ICE-TCP 候选（RFC 6544）：位于屏蔽 UDP 的网络后
的浏览器或 pion 以主动候选连上来，在该连接上运行 ICE、DTLS、SCTP 与 SRTP（RFC 4571 分帧）。引擎需要
TCP I/O 线程（`client_threads(n)` 或一个 TCP listener）。由专用线程接受连接，同时最多 256 条；10 秒内
第一帧不是指向该 endpoint 某个 peer 的连通性检查的连接被关闭，peer 关闭时其连接也被关闭。TCP 候选的
优先级低于 UDP，能用 UDP 的 peer 仍然用 UDP。

`dial_tcp(&engine)` 加入一个主动 ICE-TCP 候选（主机主地址，端口按 SDP 的写法为 9）：为连上只监听 TCP 的
服务器，endpoint 在每个候选对发出第一次检查时为它拨一条连接，所有数据都走这条连接。失败的连接由下一次
检查重新拨号；主动与被动连接共用一个上限（256）。

`RtcServer` 也支持被动 ICE-TCP：`tcp_candidates(addrs)` 在其 answer 与 offer 中加入被动 TCP 候选，
`server.tcp()` 是这些地址上引擎 TCP listener 的 acceptor，UDP 被屏蔽的浏览器因此可以直接连到服务器：

```rust,ignore
let server = RtcServer::new(vec![public_udp]).tcp_candidates(vec![public_tcp]);
let engine = Engine::builder()
    .listen(Listener::udp(udp_addr).serve(server.clone()))
    .listen(Listener::tcp(tcp_addr).serve(server.tcp()))
    .build()?;
```

规则相同（10 秒内第一次检查，peer 关闭时其连接随之关闭）；连接数最多为 `max_peers` 的两倍。

### Simulcast

`SdpChanges::add_simulcast_media(kind, dir, &["h", "m", "l"], stream_id, track_id)` 添加一条按 RID 各发
一个 RTP 流的媒体行（RFC 8853，与浏览器一样按质量从高到低排列），`Peer::write_simulcast(mid, rid, pt,
wallclock, rtp_time, data)` 写某一编码的样本：由应用以各自的分辨率与码率编码每一层。offer 列出这些 RID
（`a=rid`、`a=simulcast:send`）；由 answer 的 `a=simulcast:recv` 决定发送哪些（没有它时只发第一个）。每个
编码有自己的 SSRC 与 RTX 流，包带 MID 与 RID 头扩展，关键帧请求带上其 RID（`KeyframeRequest::rid`）。
作为应答方，本栈也接受远端（如浏览器）发来的 simulcast（用 `MediaData::rid` 区分各层）。向观众转发其中
一层的 SFU 按 `MediaData::rid` 选层，在新层的关键帧处切换，并用 `Peer::request_layer_keyframe(mid, rid,
kind)` 只向发布者请求该层的关键帧（`crates/only-webrtc/examples/webrtc-interop.rs` 的 `sfu` 模式即如此，
切换时改写 RTP 时间戳）。Chrome 不接收 simulcast：它的 answer 去掉了 `a=simulcast`，因此只向它发送第一个
编码。

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

`TurnServer` 按客户端地址把分配分成若干分片（约每个 CPU 四个，至少 8 个），每个分片有自己的锁：
不同分配的数据报不会在 I/O 线程之间争用，过期清扫每次只持有一个分片，已认证的 Allocate 的中继
socket 在获取任何锁之前绑定。配额仍是整个服务器范围的。

### TCP 与 TLS 上的 TURN

`turn.stream()` 是 TCP listener 的 acceptor，用 `only::tls::Tls` 包装后用于 TLS listener（`turns:`，通常
为 5349 或 443 端口）：与 UDP listener 共享分配、配额与凭据。中继仍走 UDP；不提供 TCP 中继（RFC 6062，
回 `442`）。

```rust,ignore
let engine = Arc::new(
    Engine::builder()
        .listen(Listener::udp("0.0.0.0:3478".parse()?).serve(turn.clone()))
        .listen(Listener::tcp("0.0.0.0:3478".parse()?).serve(turn.stream()))
        .listen(Listener::tcp("0.0.0.0:5349".parse()?).serve(Tls::server(tls_cfg, turn.stream())))
        .build()?,
);
turn.set_engine(&engine);
```

| 字段 | 默认值 | 含义 |
|---|---|---|
| `stream_allocate_timeout` | 30 秒 | 到时仍未分配的连接被关闭 |
| `max_stream_queue` | 256 KiB | 排队超过该值的连接，发给它的中继数据被丢弃（保持数据报语义；响应总会发送） |

经连接建立的分配随连接结束。STUN 与 ChannelData 在流上按各自的长度分帧
（`only_turn::framing::FrameReader`），ChannelData 填充到 4 字节。

### TURN 客户端

`only_turn::client::Client` 是单个分配的 sans-io 客户端，跑在 UDP 或 TCP/TLS 流上
（`ClientConfig::stream(true)`）：用长期凭据应答 401 质询、更新过期 nonce、刷新分配、在首次 `send_to` 时为
每个对端绑定 channel（失败时退回到权限与 Send 指示）、在对端使用期间刷新这些绑定，并在 UDP 上重传。由调用者
搬运字节：`poll_transmit` 发往服务器，把收到的内容交给 `handle_input`（中继数据以 `(peer, payload)` 返回），
在 `poll_timeout` 时调用 `handle_timeout`。上限：64 个对端、等待绑定的数据 64 KiB。`Endpoint::gather_relay`
在 UDP 上驱动一个客户端。

## DTLS 层：WebRTC 用 DTLS 1.2，按需开启 DTLS 1.3

`only-dtls` 是 sans-io 连接（`Connection`：喂入数据报和定时器到期，发送 `poll_transmit` 返回的
内容），支持 DTLS 1.2（RFC 6347）与 DTLS 1.3（RFC 9147）。WebRTC 使用 DTLS 1.2：`Config::webrtc`
只启用它，因为 pion 和浏览器的协议栈协商的是 DTLS 1.2，提供 1.3 只会让 ClientHello 变大（ADR-021）。
WebRTC 之外，`Config::with_versions(vec![Version::Dtls13, Version::Dtls12])` 同时提供两个版本，
遇到只支持 1.2 的对端时回退到 DTLS 1.2（带 RFC 8446 降级检查）。

- **DTLS 1.3**：带加密记录号的统一记录头，随 KeyUpdate 递增的 epoch（`Connection::update_keys`，
  密钥接近使用上限前也会自动更新），用 ACK 只重传一轮中丢失的分片，无状态的 HelloRetryRequest
  cookie（也可由连接前面的 `HelloVerifier::check` 发出）。
- **连接 ID**（`Config::with_connection_id`）：DTLS 1.2 用 RFC 9146 的 `tls12_cid` 记录，DTLS 1.3
  把 CID 放在统一头里。监听方用 `only_dtls::connection_id(datagram, len)` 而不是地址分发数据报，
  NAT 映射变化的对端仍能保住连接。
- **会话恢复**（`Config::with_session_resumption`）：DTLS 1.2 会话 ID（有上限的缓存）与 RFC 5077
  票据，DTLS 1.3 NewSessionTicket（`psk_dhe_ke`，始终前向安全）。客户端收到
  `Event::NewSession(session)`，用 `Connection::client_resume` 重连；票据用可在服务端之间共享的
  `TicketKey` 封装，恢复时校验器会再次检查对端证书。
- **外部 PSK**（`Config::with_psks`）：DTLS 1.2 的 PSK 与 ECDHE-PSK AEAD 套件以及 DTLS 1.3
  `psk_dhe_ke`；只做 PSK 的服务端不需要证书。

互通测试覆盖 OpenSSL 3.5 / 4.1、wolfSSL 5.8 和 pion/dtls（`tools/interop/dtls/run.sh`）。

## 尚未完成

TCP 中继（RFC 6062）；DTLS 上的 TURN；同时打开的 ICE-TCP（`tcptype so`）；解析 mDNS 候选（使用它们的
对端仍可通过 peer-reflexive 候选连通）；对端中的 FEC、RTCP XR、TMMBR 与 RFC 8888 反馈（自 ADR-036 起
`only-rtp` 已实现：ULPFEC、FlexFEC `flexfec-03` 与 RFC 8627、RED、全部 XR 报告块、TMMBR 边界集、RFC 8888
的生成与匹配；`only-webrtc` 尚未协商它们）；WebRTC 默认使用 DTLS 1.3；DTLS 1.3 的 0-RTT 与
NewConnectionId。新增内容的细节见 ADR-017 与 ADR-032。
