# WebRTC、STUN 与 TURN

两个 crate：

- `only-webrtc` 在 only UDP socket 上运行 WebRTC peer，基于自研、sans-io、无第三方依赖的协议栈
  （DEV-PLAN 第 D 波），每层一个 crate，均为 `#![forbid(unsafe_code)]` 并构建于 `only-crypto` 之上：
  `only-ice`（完整 ICE agent 与 ICE-lite、检查列表、提名、角色冲突、peer-reflexive 候选、trickle、
  重启、consent freshness）、`only-dtls`（DTLS 1.3，可回退到 1.2，带证书指纹校验及 DTLS-SRTP 密钥，见下文）、
  `only-srtp`（AES-CM-HMAC-SHA1-80/32 与 AEAD-AES-128/256-GCM 的 SRTP/SRTCP，防重放；该 crate
  还支持 AES-192/256-CM、NULL、MKI 与换钥、cryptex 以及 RFC 6904 头部扩展加密，peer 尚未在 SDP 中
  协商它们）、
  `only-sctp`（基于 DTLS 的 SCTP，拥塞控制、PR-SCTP、流重置、DCEP 数据通道：可靠或不可靠、有序或
  无序；对端提供时使用 I-DATA 消息交错，大消息不再阻塞其他通道上的小消息，各通道按优先级以加权公平
  排队共享关联，ADR-037；空闲关联发送 HEARTBEAT、对端重启与 RFC 9653 零校验和，ADR-042）以及 `only-rtp`（RTP/RTCP，Opus、G.711、G.722、VP8、VP9、H.264、H.265 与 AV1 打包，组帧器，
  NACK 与 RTX、PLI/FIR、REMB、TWCC 与带宽估计、发送/接收报告、RTCP XR、TMMBR / TMMBN、
  RFC 8888 反馈与 ULPFEC / FlexFEC / RED，配置后由 peer 协商使用，见下文“FEC 与更多 RTCP”）。
  `only-webrtc` 本身负责 SDP
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
simulcast 及所选的一层发回，在 Chrome 解码时切换层；启用激进提名的 `Endpoint`；以及把主机地址隐藏在
mDNS 名字之后的 `Endpoint` 向同样这样做（默认如此）的 Chrome 发起 offer，双方互相解析对方名字，主机
对主机连通，IPv4 与 IPv6 都验证（`tools/interop/webrtc/browser.sh`）。pion 与我们
协商 I-DATA；Chrome 157 使用 DATA chunk，除非打开其 `WebRTC-DataChannelMessageInterleaving` field trial
（打开后同样的测试经 I-DATA 通过）。SCTP 层本身也经 UDP 与 pion/sctp 互通测试，交错开与关、有无丢包、
零校验和（`tools/interop/sctp/run.sh`）。无头 Firefox（usrsctp）经 WebDriver BiDi 在两个 offer 方向上测试：
数据通道回显、大消息、较长的空闲期（期间 SCTP HEARTBEAT 维持关联）、Firefox 关闭通道后重新打开
（`tools/interop/webrtc/firefox.sh`）。

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

DTLS 上的 TURN（RFC 7350）保留 UDP 并加密控制通道：`RelayServer::dtls(addr, server_name, tls_config, ..)`
或 `turns:host[:port]?transport=udp`（再加 `tls_config`）。分配跑在 endpoint 自己 UDP socket 上的 DTLS
关联中（DTLS 1.3，可像 coturn 那样回退到 1.2），服务器证书按 TLS 配置的根证书对 `server_name` 校验；
候选是 UDP relay 候选，服务器给出的映射地址与普通 UDP 一样成为 server-reflexive 候选。关联丢失即丢失
分配，随后以新的握手重新分配。

```rust,ignore
let dtls = RelayServer::from_url("turns:turn.example.com:5349?transport=udp", "alice", "secret")?
    .tls_config(tls_client_config);
let relayed = ep.gather_relay_via(&engine, &dtls, Duration::from_secs(5))?;
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

`listen_tcp_so(&engine, addr)` 加入一个同时打开候选（`tcptype so`），它与远端的 `so` 候选配对：双方
同时在两个公布的端口之间发起连接。该端口在监听（`SO_REUSEPORT`），检查也从它拨出
（`Engine::dial_from`），因此无论哪边的连接先到，结果都是一条连接：SYN 交叉即 TCP 同时打开，否则
监听端接受对方的连接，我方的检查改走那条连接。浏览器和 pion 都没有 `so` 候选（libnice 有）；在两个
`Endpoint` 之间，凡是 TCP 能直连的地方都可以用。

### mDNS 候选

浏览器不暴露主机地址：没有摄像头或麦克风权限的页面得到的主机候选形如
`candidate:1 1 udp 2113937151 1f3c...-9a.local 54321 typ host`，浏览器在本地网络上应答对这个名字
的组播 DNS 查询（RFC 6762）。没有解析器时这类候选会被跳过，`Endpoint` 只有在浏览器的检查先到达自己
时才能连到同一局域网上的浏览器。

```rust,ignore
let ep = Endpoint::bind(&engine, "0.0.0.0:0".parse()?)?;
ep.resolve_mdns(&engine, Duration::from_secs(5))?; // 解析浏览器的 .local 名字
ep.conceal_host_candidates()?;                      // 我方也写成 .local 名字
```

`resolve_mdns` 在与系统应答器共享的 mDNS 端口 5353 上打开一个套接字（`Engine::bind_udp_multicast`，
加入 `224.0.0.251`；端口绑定不了时改用请求单播应答的临时端口），与 endpoint 自己的套接字一样由引擎
I/O 线程服务。描述中的或经 `add_remote_candidate` trickle 来的每个 `.local` 候选会立即查询，1 秒、
2 秒后再查，之后每 2 秒一次直到超时；收到应答后，对端得到带地址的候选。应答以及浏览器创建名字时
发出的通告都按 TTL 缓存。`conceal_host_candidates` 让新对端把每个主机候选以随机的 `<uuid>.local`
名字发出（每个地址一个），并隐藏其他候选的相关地址（`0.0.0.0:0`）；套接字应答对这些名字的查询，
浏览器或另一个 endpoint 因而能解析它们。

IPv6 与 IPv4 并行（ADR-054）：`[::]:5353` 上的第二个套接字在每个有链路本地地址的接口上加入 `ff02::fb`
（`Engine::bind_udp_multicast_on`），查询从每个接口发出，应答发回查询所来的链路。IPv6 主机地址与 IPv4
的一样隐藏（AAAA 记录）。SDP 不携带作用域 ID，所以 endpoint 记住远端链路本地地址的接口（来自解析它的
应答或它的流量），发送时加回去。没有 IPv6 的主机只跑 IPv4。IPv6 应答按 RFC 6762 的要求以跳数限制 255
发出（ADR-078；引擎的 IPv6 组播绑定会设置它），两个地址族都能应答：在 `224.0.0.251` 无路由的纯 IPv6 链路
上，`conceal_host_candidates` 只经 `ff02::fb` 应答。`tools/interop/webrtc/mdns6.sh` 在纯 IPv6 容器中对
avahi 验证这一点，`browser.sh` 则用唯一主机候选为被隐藏 IPv6 地址的 endpoint 对 Chrome 验证。

### 提名

控制方（offer 方，或面对 ICE-lite 远端的任一方）提名一个候选对：在没有更好的候选对仍在检查时，选能用
的最好那个。`RtcConfig` 中还可以开启两种模式：`enable_ice_aggressive_nomination(true)` 让每个检查都带
USE-CANDIDATE（第一个能用的候选对立即使用，更好的再替换它）；`enable_ice_renomination(true)` 在 offer
中写 `a=ice-options:renomination`，远端也支持时，提名后继续检查更好的候选对，后来能用的更好候选对（例如
晚到的 trickle 候选）会以更大的 NOMINATION 值再次提名。无论自身配置如何，受控方都遵循收到的最大
NOMINATION 值，没有该值时取最好的被提名候选对。

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

### FEC 与更多 RTCP

默认全部关闭（默认 peer 的 offer 与 answer 与以前完全相同），在 `RtcConfig` 中逐项打开（ADR-039、ADR-048）：

```rust,ignore
let cfg = only_webrtc::rtc_config()
    .enable_fec(Some(FecMechanism::FlexFec)) // 或 Ulpfec（red + ulpfec）、Red（只有 red，无 FEC）
    .set_fec_protection(0, 128)              // 每 256 个媒体包的 FEC 包数：上下界
    .set_fec_mask(FecMask::Random)           // libwebrtc 的掩码表：Random 或 Bursty
    .enable_opus_red(Some(1))                // Opus RED，一个冗余包（最多 2 个）
    .enable_audio_red(Some(1))               // PCMU、PCMA 与 G.722 的 RED（red/8000）
    .enable_ccfb(true)                       // 用 RFC 8888 反馈代替传输层反馈
    .enable_rtcp_xr(true)                    // XR 接收方参考时间 / DLRR：接收方 RTT
    .enable_rtcp_xr_blocks(XrBlocks::ALL)    // XR 丢包 / 重复 RLE、接收时间、VoIP 指标
    .set_ulpfec_level0(Some(120))            // ULPFEC 保护级别：只用于对端也是本栈时
    .enable_tmmbr(true)                      // a=rtcp-fb ccm tmmbr
    .enable_bwe(None);
```

- **FEC** 用于视频行。FlexFEC 即 libwebrtc 的 `flexfec-03`，是用
  `a=ssrc-group:FEC-FR` 声明的独立 FEC 流（Chrome 需要 field trial
  `WebRTC-FlexFEC-03-Advertised/Enabled/WebRTC-FlexFEC-03/Enabled/`）；ULPFEC 在媒体流上经 RED 承载，
  浏览器默认就会提供。simulcast 行上每个编码按自己的丢包率各自保护：ULPFEC 走该编码的 RED 流（Chrome
  的做法），或每个编码一个 FlexFEC 流——它不在 SDP 中声明（RID simulcast 不指明 SSRC），而是携带 MID 与
  所修复的 RID，因此只用于对端也是本栈时。收到的 FEC 在帧组装器和 NACK 之前修复包（修复的包不会被
  NACK，但接收报告仍把它们算作丢失，与 Chrome 一致）；FEC 只能部分重建的包（ULPFEC 保护级别）在后一帧
  到达时交给 depacketizer，其所在帧以 `contiguous: false` 交出。分组保护方式与 libwebrtc 相同
  （ADR-073）：最多 12 个包的组用它的掩码表；保护策略综合修复前丢包率（报告的丢包，或接收方要求重传的
  包所占比例；取最近 10 s 的最大值）、每帧比特数，以及接收方 NACK 时的往返时间：RTT 低于 20 ms 时 delta
  帧不加 FEC，RTT 越大一组跨越的帧越多，RTT 低于 200 ms 时小帧不加 FEC。关键帧保护更多。
  `set_fec_protection` 限定保护因子；`min` 大于 0 时从一开始就保护。
- **其他编解码器的 RED**（`enable_audio_red`）：PCMU、PCMA 与 G.722 的 `red/8000`，排在各编解码器之前，
  每个包带最多两个之前的包。`FecMechanism::Red` 以 RED 发送视频但不发 FEC 包（无论哪种配置，都接受对端
  只有 `red` 没有 `ulpfec`）。
- **Opus RED**（RFC 2198，`red/48000/2`）：`enable_opus_red(Some(n))` 把 RED 排在 Opus *之前*，因为
  libwebrtc 只向把 RED 排在前面的对端发送 RED（Chrome 自己的 offer 把它放在 Opus 之后）。收到的 RED
  会被拆开：冗余副本代替丢失的包（已到达的包的副本被丢弃）；发送的 Opus 携带前 `n` 个包（`Some(0)`
  发送普通 Opus，但仍接收 RED）。
- **RFC 8888**：双方都提供 `ack ccfb` 时，收到的媒体用 RFC 8888 反馈确认，替代传输层反馈，带宽估计器
  也基于它运行；Chrome 需要 `WebRTC-RFC8888CongestionControlFeedback/Enabled,offer:true/`。报告携带每个
  包到达时的 ECN 码点（UDP 后端读取）；发送端把被报告为 CE 的包在估计器中按丢失计。按配置，本端也标记自己的
  RTP（见下一条）。
- **ECN 可用的 RTP**（ADR-077，`set_ecn_marking(EcnMarking::Ect1)` 或 `Ect0`）：使用 RFC 8888 且估计器
  运行时，路径表明标记能到达后，RTP 以 ECT(1) / ECT(0) 发出：未知时每四个包标记一个，十个已标记包带着
  标记返回后全部标记（RFC 6679 §7.2）。报告显示标记被清除或改变，或已标记包丢失而未标记包没有丢失，会
  停止该路径上的标记（新的 ICE 地址对或锁定的地址重新开始）。RTCP、STUN、DTLS 与 SCTP 从不标记。
  Chrome 157 接收 ECT(1)（其 `packetsReceivedWithEct1`）并使路径通过验证；Chrome 不标记它发出的包
  （`tools/interop/webrtc/ecn.sh`，其中也展示了清除码点的代理使标记停止）。
- **RTCP XR**（`a=rtcp-xr:rcvr-rtt=all`）：只接收的行也能（从发送方的 DLRR）得到 RTT，用于 NACK 节奏。
- **关于接收流的 XR 块**（ADR-058，`pkt-loss-rle pkt-dup-rle pkt-rcpt-times voip-metrics`）：双方都
  列出某格式时才发送，每个接收流每秒一次，内容是上次报告以来的序号（抽稀到一个数据报内）；VoIP 指标只在
  音频行发送，丢包、突发与间隙字段实测，带往返时间，以及由 E-model（ITU-T G.107，宽带编解码器用
  G.107.1；ADR-085）根据丢包、其突发性、往返时间与端系统时延算出的 R 因子、MOS-LQ 与 MOS-CQ，使用所收
  编解码器在 G.113 中的规划值（`EModel::for_codec`：PCMU、PCMA、G.722、G.729、G.723.1，以及 Opus 的一条
  假定值，因为它没有规划值），并在接收方配置中带上它的丢包隐藏。只有解码、播放音频的应用才知道的值，由
  应用经 `set_voip_quality` 提供；其余以不可用（127）发送。收到的块以 `XrReceipts` 与 `VoipMetrics`
  事件报告（后者可用 `metrics.quality()` 解码），并累计到统计中。

  ```rust,ignore
  use only_rtp::{JitterBufferConfig, VoipQuality, pcm_level_dbm0};

  // 解码之后：讲话段的语音电平，抖动缓冲的当前状态。
  peer.set_voip_quality(mid, VoipQuality {
      signal_level: pcm_level_dbm0(&talkspurt),
      noise_level: pcm_level_dbm0(&silence),
      jitter_buffer: Some(JitterBufferConfig {
          adaptive: true,
          rate: 4,
          nominal: Duration::from_millis(60),
          maximum: Duration::from_millis(120),
          abs_max: Duration::from_millis(500),
      }),
      ..VoipQuality::default()
  }, None)?; // None：使用所收编解码器的 E-model 值
  ```
- **ULPFEC 保护级别**（RFC 5109 §5）：`set_ulpfec_level0(Some(l0))` 时一帧的 FEC 包保护每个包的前
  `l0` 字节，另有一个级别覆盖其余部分一次：单个丢包能完整修复，修复字节少得多。libwebrtc 只读级别 0
  （Chrome 会把长包重建错），因此面向浏览器时不要开启。
- **TMMBR**：`Peer::request_max_bitrate(mid, Some(bps))` 请求远端发送方最多发送 `bps`（随每轮报告重复，
  直到传入 `None`）；Chrome 会遵守。关于我方流的请求以 TMMBN 应答，并像 REMB 一样限制带宽估计。

`tools/interop/webrtc/fec.sh` 用 headless Chrome 检查以上全部：每个方向每 20 个 RTP 包丢 1 个且去掉
NACK 时，有 FEC 时 Chrome 解码回显的 400 帧中的 381–397 帧，没有 FEC 时只有 8-15 帧；双向 10 % 丢包下，
双向 Opus RED 时 Chrome 只隐藏 2-3 % 的音频，没有时为 20 %；Chrome 的三层 simulcast 带有按层的 ULPFEC，
可据此修复。`browser.sh` 让我方带按编码 ULPFEC 的 simulcast 行经过 5 % 丢包且无 NACK 发给 Chrome：
Chrome 解码了全部帧，没有 FEC 时几乎一帧都解不出。

### 头部保护：cryptex 与加密扩展

```rust,ignore
let cfg = only_webrtc::rtc_config()
    .enable_cryptex(true)                     // a=cryptex（RFC 9335）
    .enable_encrypted_header_extensions(true); // RFC 6904 extmap
```

普通 SRTP 下 RTP 头部扩展（MID、RID、音频电平……）与 CSRC 是明文。使用 **cryptex** 时双方都声明
`a=cryptex`（与 Chrome 一样写在会话级），每个包的扩展块与 CSRC 都被加密；只要本端提供或接受了它，
收到的 cryptex 包就会被解密。页面设置 `RTCConfiguration.rtpHeaderEncryptionPolicy`（需要
`--enable-experimental-web-platform-features`）时 Chrome 157 会提供它，"require" 时拒绝不支持它的对端。
**RFC 6904** 则只加密选定扩展的值：offer 额外给出 `a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`
变体（音频电平、MID、RID、修复 RID、视频方向、播放延迟，使用空闲的单字节 ID），answer 对以两种形式
提供的扩展选择加密变体。没有浏览器提供 RFC 6904，它适用于与本栈类似的对端。不协商 MKI：DTLS-SRTP
没有对应的 SDP。

### 面向 SIP 网关的 SDES-SRTP

```rust,ignore
let ep = ep.config(|| only_webrtc::rtc_config().enable_sdes_srtp(true));
```

SIP 网关常用 SDP 安全描述（RFC 4568）而不是 DTLS-SRTP 提供 SRTP 密钥。`enable_sdes_srtp(true)` 时
offer 的媒体段为 `RTP/SAVPF`，每个套件一行 `a=crypto`（AEAD-AES-256/128-GCM、带 HMAC-SHA1-80 的
AES-256-CM 与 AES-128-CM、带 HMAC-SHA1-32 的 AES-128-CM），各带随机密钥，没有 fingerprint；SDES offer
（带 `a=crypto` 的 `RTP/SAVP` 或 `RTP/SAVPF`）以本方能用的第一行和本方自己的密钥应答。各方用自己的
密钥加密、用对方的密钥解密；ICE 有了候选对即连通。密钥只与信令一样机密。带 MKI（`|1:4`）与多个主密钥的行
可以采用，此时我方应答的密钥带相同长度的 MKI；`set_sdes_mki_length(4)` 让我方 offer 带 MKI。窗口大小提示
（`WSH=`）以外的会话参数使该行不可用。DTLS-SRTP offer 仍以 DTLS-SRTP 应答，所以浏览器永远看不到
`a=crypto`。

数据通道可以与 SDES 媒体并存：应用段带 `a=fingerprint` 与 `a=setup`，DTLS 在那里只承载 SCTP，媒体仍用
SDP 中的密钥（ADR-072）。

许多网关根本不做 ICE。不带 `a=ice-ufrag` 的远端 SDP 按普通媒体处理：RTP 发往其 `c=` 地址与 `m=` 端口，
RTCP 发往 `a=rtcp`（或下一个端口），应答也以同样方式写出我方主机地址与端口。`enable_ice(false)` 让我方
offer 也成为普通形式：

```rust,ignore
let ep = ep.config(|| {
    only_webrtc::rtc_config()
        .enable_sdes_srtp(true)
        .enable_ice(false)
        .set_rtcp_mux_policy(RtcpMuxPolicy::Off) // RTCP 走 RTCP 套接字的端口
});
```

没有 ICE 就没有任何东西检查路径：默认情况下远端必须能在它写出的地址上到达（ADR-072）。位于 NAT 之后的
话机写出自己的私有地址，却从 NAT 的映射地址发送；锁定（对称 RTP、"comedia"，ADR-077）会跟随它：

```rust,ignore
.set_latching(Latching::Once)                              // 第一个通过认证的来源
.set_latching(Latching::Rebind(Duration::from_secs(2)))    // 静默 2 秒后可再次移动
```

来自端点不认识的地址的数据报会用仍可锁定的 peer 的 SRTP 密钥去验证；通过认证（且不是重放）的包会被接收，
并把传输（RTP，以及独立端口上的 RTCP，各自分开）移到它的来源。伪造或重放的包不会移动任何东西。使用
DTLS-SRTP 时，握手之前不会锁定，而握手需要 SDP 中的地址。`tools/interop/webrtc/latch.sh` 在网络命名空间
中运行位于 iptables NAT 之后的 SIP 风格话机，包括 NAT 重新绑定。

### RTCP 走独立端口（不复用 RTCP）

```rust,ignore
let ep = Endpoint::bind(&engine, "0.0.0.0:5004".parse()?)?;
ep.bind_rtcp(&engine, "0.0.0.0:5005".parse()?)?; // ICE 组件 2
let ep = ep.config(|| only_webrtc::rtc_config().set_rtcp_mux_policy(RtcpMuxPolicy::Negotiate));
```

浏览器与 pion 总是复用 RTP 与 RTCP（rtcp-mux、BUNDLE），默认对端也一样。SIP 终端与较老的 RTP 栈未必
如此：它们的 offer 没有 `a=rtcp-mux`，RTCP 发往单独的端口（RFC 5761，`a=rtcp`）。带 RTCP 套接字的
`Endpoint` 以 `a=rtcp` 应答它们，并以两个组件运行 ICE（ADR-055）：RTP 走组件 1，RTCP 走组件 2，各有
自己的选中候选对。DTLS-SRTP 每个组件各握手一次（RFC 5764：SRTCP 用组件 2 的密钥），SDES-SRTP 两个组件
都用 SDP 中的密钥；两个组件都就绪对端才算连接。带 `a=rtcp-mux` 的 offer 照旧以它应答。我方 offer 按
`set_rtcp_mux_policy` 书写：`Require`（默认）只写 rtcp-mux，`Negotiate` 写 rtcp-mux 加 `a=rtcp` 与
组件 2 候选（由应答决定），`Off` 不写 rtcp-mux。没有 rtcp-mux 就没有 BUNDLE（RFC 8843 §9.1），因此多段的
会话需要每段一个传输（见下一节）。请在收集候选之前绑定 RTCP 套接字：之后 `gather_srflx` 与
`gather_relay` 也会从它收集组件 2 的服务器反射与中继候选。`RtcServer` 可为组件 2 另设监听器：

```rust,ignore
let server = RtcServer::new(vec![main]).rtcp_candidates(vec![rtcp]);
Engine::builder()
    .listen(Listener::udp(main).serve(server.clone()))
    .listen(Listener::udp(rtcp).serve(server.rtcp()))
```

### 无 BUNDLE：每段一个传输

```rust,ignore
let ep = ep.config(|| only_webrtc::rtc_config().set_bundle_policy(BundlePolicy::Disabled));
ep.bind_transport_socket(&engine, "0.0.0.0:0".parse()?)?; // 可选：每个额外的段一个
```

默认情况下会话的各段共享一个传输（BUNDLE）。不做 BUNDLE 的对端得到每段一个传输：没有 `a=group:BUNDLE`
的 offer、未带上我方组的应答，或我方以 `BundlePolicy::Disabled` 发出的 offer（它也会拒绝远端的组）。此时
每个段有自己的 ICE 代理（SDP 中有自己的凭据与候选）、DTLS 关联、SRTP 密钥，以及不复用 RTCP 时的 RTCP
组件；媒体、RTCP 与 SCTP 从各自段的传输发出，所有传输都就绪后才触发 `on_connected`。
`bundlePolicy: "max-compat"` 的 Chrome 在两个方向上都以这种方式工作（`tools/interop/webrtc/bundle.sh`）。
除非 `bind_transport_socket` 为它们提供各自的套接字，这些传输共享端点的套接字，并靠远端地址区分（不做
BUNDLE 的对端每段总有一个地址）。拥塞控制反馈（transport-cc、RFC 8888）像 BUNDLE 时一样协商，一个估计器和
一个 pacer 服务所有传输（ADR-077）：RFC 8888 按传输进行；传输级序号跟随远端的编号方式，像 libwebrtc 那样在
所有传输上共用一个空间（Chrome 即如此，`bundle.sh` 中检查），或在远端按传输编号时每个传输一个空间；排队的
包从各自的传输发出。
trickle 候选用 `Peer::add_remote_candidate_in(mid, candidate)` 指明其段。

### 数据通道优先级

```rust,ignore
let ch = api.add_channel_with_config(&ChannelConfig::new("video-meta").with_priority(ChannelPriority::High));
let ep = ep.config(|| only_webrtc::rtc_config().set_sctp_scheduler(ChannelScheduler::Priority));
```

通道的优先级随 DCEP 打开消息发给对端（128、256、512 或 1024；远端通道的优先级见
`Peer::channel_priority`），并决定 SCTP 流调度器如何在有数据排队的通道间分配关联：默认为加权公平排队
（通道按其优先级值成比例地获得字节），也可选严格优先级、轮询、按包轮询、公平容量或先来先服务。
`Peer::set_channel_priority` 之后可以改变本端的权重（DCEP 没有更新消息）。Chrome 157 没有
`RTCDataChannel.priority`，总是发送 256。

### 带宽探测

开启 `enable_bwe` 后，估计器会像 libwebrtc 一样探测路径（ADR-050）：以目标速率节奏发送短簇（15 ms
或更长）的最近视频 RTX 副本，由其反馈（transport-wide 或 RFC 8888）看出路径能送达多少。媒体一开始
流动就以起始速率的 3 倍和 6 倍探测，结果跟得上就翻倍继续；编码器发送量远低于估计值时每 5 s 探测一次；
估计值大幅下降之后也会探测；ICE 换到另一个候选对时从头开始。结果只会提升估计值，降低仍由时延与丢包
检测器负责。在模拟的 10 Mbps 链路上，从 300 kbps 起步的发送方 0.35 s 即达到 90 %，而不是 44 s；
`tools/interop/webrtc/bwe.sh` 以 Chrome 为接收方检查这一点（连接后 0.2 s 估计值达到 10 Mbps，以前
一直停在起始值）。

估计值的上下限为 `set_bwe_bounds(min, max)`（默认 30 kbps 与 20 Mbps）；`Peer::set_bitrate_bounds`
在运行中的 peer 上修改，调高的上限会立即被探测（ADR-073）。only-rtp 的
`BandwidthEstimator::set_network_state_estimate` 还接受外部的链路容量估计：向它探测，且从不超过它。

### 发送节拍（pacing）

估计器打开时，发送的媒体按节拍发出（ADR-073），与 libwebrtc 相同：视频、FEC 与重传经一个队列发出，
排空速率为估计值的 2.5 倍，一次最多可发出 40 ms 的字节量，所以普通帧整帧发出，关键帧被摊开（1 Mbps
估计值下 60 kB 的关键帧约需 150 ms）。重传优先；音频从不排队。transport-wide 序号与 abs-send-time 在
包离开时写入，因此估计器看到的是真实发送时间。`set_padding_rate(bps)` 在无数据可发时加入填充（近期
媒体的 RTX 副本），使安静期间估计值仍有测量；`enable_pacing(false)` 关闭 pacing。队列最多 8192 个包
（8 MB），最老的包将等待 2 s 时加速排空：应用应跟随 `EgressBitrateEstimate` 事件，否则会在上限处丢帧。
`tools/interop/webrtc/pacing.sh` 用 Chrome 展示：估计值上限 300 kbps 时，发往 Chrome 的 RTP 最大突发
pacing 时为 4 个包，不 pacing 时为 7 个。

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
为 5349 或 443 端口）：与 UDP listener 共享分配、配额与凭据。中继走 UDP；客户端请求 TCP 分配时走 TCP
（见下一节）。

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

### TCP 分配（RFC 6062）

TCP 或 TLS 客户端可以请求 `REQUESTED-TRANSPORT` TCP：此时它的中继地址是一个监听中的 TCP socket，
中继的是 TCP 连接而不是数据报。浏览器从不请求它；SIP、XMPP 客户端以及经 TURN 隧道传输 TCP 协议的应用会用到，
coturn 与 pion/turn 也都提供。

- **Connect**：客户端指定一个对端；服务器*从中继地址*连接它，回复 `CONNECTION-ID`（对端连不上时回 447，
  与该对端地址已有连接时回 446）。适用对端策略（403）；不需要权限。
- **对端连入**中继地址时需要其 IP 的权限（CreatePermission，与 UDP 相同）；没有权限的连接被立即关闭，
  有权限时客户端收到带 `CONNECTION-ID` 的 ConnectionAttempt 指示。
- **ConnectionBind**：客户端向服务器打开一条*新*连接，并把它绑定到该 ID（同一凭据；接受控制连接的 nonce）。
  成功之后，这条连接与对端连接双向传输原始字节；关闭任一侧都会关闭另一侧，分配结束（控制连接关闭、删除、
  过期）时全部关闭。无人绑定的连接 30 秒后关闭。

服务器让已绑定连接的字节不经过分配分片：两侧直接写入对方，当一侧排队超过 `tcp_relay_buffer` 时，暂停读取
另一侧直到它排空（`hold_reads` / `on_drain`），因此慢读者会减慢对端，而不是让内存增长。绑定之前，对端的字节
最多保留到同一水位，然后暂停读取它。每个服务器用一个线程轮询各中继地址的监听 socket，把接受的连接交给引擎；
没有 I/O 线程等待 `accept`。

| 字段 | 默认值 | 含义 |
|---|---|---|
| `tcp_relays` | true | 提供 TCP 分配（false：442） |
| `max_tcp_connections` | 64 | 一个 TCP 分配的连接数（超出时 Connect 回 508，连入的对端被关闭） |
| `tcp_relay_buffer` | 64 KiB | 每个方向保留的量：绑定前对端的字节，以及使另一侧暂停的队列水位 |

Connect 受引擎的 `Config::connect_timeout`（默认 10 秒）限制；RFC 6062 要求至少 30 秒，需要时在服务 TURN 的
引擎上调大它。到某个对端的连接刚关闭时，再次 Connect 同一对端地址可能失败（447），因为旧的四元组仍处于
TIME_WAIT；RFC 6062 本就要求客户端等 10 秒再重试同一对端。

### DTLS 上的 TURN

`turn.dtls(&tls_cfg)?` 是客户端说 DTLS 的 UDP listener 的 acceptor（RFC 7350，
`turns:host:5349?transport=udp`），证书与 TLS listener 相同，分配、配额与凭据共享。在保存任何状态之前，
ClientHello 先以无状态 cookie 应答；提供 DTLS 1.3，可回退到 1.2。每条记录携带一条 STUN 或 ChannelData
消息，不填充。分配随其 DTLS 关联存在：close_notify、致命告警、`udp_idle_timeout` 的静默或同一地址上的
新握手都会释放它。支持连接 ID（RFC 9146、RFC 9147 §9）的客户端会被要求使用 8 字节的连接 ID：客户端地址
变化（NAT 重新绑定）时，其记录仍指向原关联，一旦其中某条在新地址上通过认证，路径就移到新地址；分配保持不变。
`turn.dtls_with_connection_ids(&tls_cfg, None)` 关闭它。与 coturn 的 `turnutils_uclient -S` 以及 coturn
自己的 DTLS listener 互通（`tools/interop/webrtc/turn-dtls.sh`）。

```rust,ignore
Engine::builder()
    .listen(Listener::udp("0.0.0.0:5349".parse()?).serve(turn.dtls(&tls_cfg)?))
```

### TURN 客户端

`only_turn::client::Client` 是单个分配的 sans-io 客户端，跑在 UDP 或 TCP/TLS 流上
（`ClientConfig::stream(true)`）：用长期凭据应答 401 质询、更新过期 nonce、刷新分配、在首次 `send_to` 时为
每个对端绑定 channel（失败时退回到权限与 Send 指示）、在对端使用期间刷新这些绑定，并在 UDP 上重传。由调用者
搬运字节：`poll_transmit` 发往服务器，把收到的内容交给 `handle_input`（中继数据以 `(peer, payload)` 返回），
在 `poll_timeout` 时调用 `handle_timeout`。上限：64 个对端、等待绑定的数据 64 KiB。`Endpoint::gather_relay`
在 UDP 上驱动一个客户端。

TCP 分配用 `ClientConfig::tcp_allocation(true)`（经 TCP 或 TLS）。`connect(peer)` 发送 Connect，回应为
`ClientEvent::Connected { peer, id }` 或 `ConnectFailed`；`create_permission(peer)` 安装一个持续刷新的权限，
此后连入的对端以 `ClientEvent::ConnectionAttempt { peer, id }` 出现。要使用一条连接，向服务器打开一条新连接，
在其上驱动 `client.data_connection(now, id)` 得到的 `DataConnection`：发送 `poll_transmit` 给出的内容
（ConnectionBind），把读到的内容交给 `handle_input`，它返回取走的字节数；`state()` 变为 `DataState::Bound`
后，这次读取的剩余部分及之后的一切都是对端的字节，写入的内容发往对端。

```rust,ignore
let mut ctl = Client::new(ClientConfig::new(server, "alice", "secret").tcp_allocation(true), now);
// ……在一条 TCP 连接上驱动 ctl，直到 ClientEvent::Allocated……
ctl.connect(now, peer);
// ……ClientEvent::Connected { id, .. }……
let mut data_conn = TcpStream::connect(server)?;
let mut bind = ctl.data_connection(now, id).unwrap();
while let Some(m) = bind.poll_transmit() {
    data_conn.write_all(&m)?;
}
let n = data_conn.read(&mut buf)?;
let used = bind.handle_input(&buf[..n]);
if *bind.state() == DataState::Bound {
    peer_bytes(&buf[used..n]); // data_conn 现在是通向对端的管道
}
```

`tools/interop/webrtc/turn-tcp.sh` 对 coturn（`turnutils_uclient -T` 及其服务器）与 pion/turn（其 TCP 分配
客户端与服务器）做互通检查，经 TCP 与 TLS。

## DTLS 层：DTLS 1.3，可回退到 DTLS 1.2

`only-dtls` 是 sans-io 连接（`Connection`：喂入数据报和定时器到期，发送 `poll_transmit` 返回的
内容），支持 DTLS 1.2（RFC 6347）与 DTLS 1.3（RFC 9147）。`Config::with_versions(vec![Version::Dtls13,
Version::Dtls12])` 同时提供两个版本，遇到只支持 1.2 的对端时回退到 DTLS 1.2（带 RFC 8446 降级检查）。
`Config::webrtc` 本身只启用 DTLS 1.2（ADR-021）；`only-webrtc` 的 peer 加上 DTLS 1.3（ADR-048，
`RtcConfig::enable_dtls13`，默认开启），Chrome 157 在两种 DTLS 角色下都会协商 DTLS 1.3，pion 仍用
DTLS 1.2。

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
- **CID 更新**（DTLS 1.3，ADR-045）：`Connection::new_connection_ids` 与 `request_connection_ids`
  交换新的 CID（NewConnectionId / RequestConnectionId）；`rotate_connection_id` 在地址变化后切换到
  备用 CID，使新旧路径无法关联；`Event::LocalConnectionIds` 让监听方的路由表保持精确。
- **握手后客户端认证**（DTLS 1.3）：用 `Config::with_post_handshake_auth` 提供该能力的客户端，可随时被
  `Connection::request_client_certificate` 要求出示证书；答复为 `Event::ClientCertificate`。
- **早期数据（0-RTT）**（DTLS 1.3，`Config::with_early_data`，默认关闭）：恢复会话的客户端在握手完成前
  用 `Connection::send_early_data` 发送；服务端对每个 ClientHello 只收到一次 `Event::EarlyData`（票据
  年龄检查与可在服务端之间共享的 binder `AntiReplayStore`）。早期数据可被重放，只应放幂等请求。

互通测试覆盖 OpenSSL 3.5 / 4.1、wolfSSL 5.8 和 pion/dtls（`tools/interop/dtls/run.sh`）。

## 尚未完成

DTLS-SRTP 下的 SRTP MKI；对 CE 标记的可伸缩（L4S）响应；DTLS-SRTP 密钥就绪前的锁定。
新增内容的细节见 ADR-017、ADR-032、ADR-039、ADR-044、ADR-045、ADR-048、ADR-054、ADR-058、ADR-072、
ADR-073、ADR-076 与 ADR-077。
