# ADR-032：`Endpoint` 经 TCP 与 TLS 使用 TURN、主动及服务器端 ICE-TCP、与 Chrome 的 simulcast

[English](032-webrtc-turn-streams-ice-tcp-simulcast.md) | 简体中文

状态：已接受（2026-11-18）

## 背景

[ADR-017](017-webrtc-turn-gaps.zh-CN.md) 留下了这些 WebRTC 缺口：

- `Endpoint` 只能经 UDP 分配中继候选，尽管 sans-io 的 `akio_turn::client::Client` 已支持流式
  TURN；屏蔽 UDP 的网络只能经 TCP 或 443 端口上的 TLS 访问 TURN 服务器（`turn:?transport=tcp`、
  `turns:`）；
- `Endpoint` 有被动 ICE-TCP 候选却没有主动候选，因此连不上只走 TCP 的服务器（使用 ICE TCP mux
  的 pion、位于不友好 UDP 防火墙后的媒体服务器）；
- `RtcServer`（ICE-lite，一个 UDP 端口）完全没有 ICE-TCP，UDP 被屏蔽的浏览器只能经 TURN 中继到达它；
- simulcast 只对 pion 测过，两个方向都没有对 Chrome 测过；只转发多层之一的 SFU 也无法只向发送方
  请求该层的关键帧。

## 决定

### 1. 经 TCP 与 TLS 分配的中继候选（`akio-webrtc`）

- **`RelayServer`**：`Endpoint` 在其上分配的 TURN 服务器：`RelayServer::udp(addr, user,
  password)`、`::tcp(..)`、`::tls(addr, server_name, tls::ClientConfig, ..)`，或
  `RelayServer::from_url("turn:host[:port][?transport=udp|tcp]" | "turns:host[:port]
  [?transport=tcp]", user, password)`（RFC 7065，默认端口 3478 与 5349，IPv6 写在方括号中）。
  `from_url` 会解析主机名（阻塞，与 `gather_relay` 本身一样）；`turns:` 服务器在使用前需要
  `RelayServer::tls_config`，因为 `akio-tls` 没有默认根证书（URL 中的主机名就是验证证书时使用的
  名字）。`addr()` 与 `transport()` 可读回。
- **`Endpoint::gather_relay_via(&Arc<Engine>, &RelayServer, timeout)`**：任意传输上的
  `gather_relay`。在流上由 engine 拨号建立连接（`Engine::dial`，TLS 时用 `Tls::client` 包装），
  客户端以 `ClientConfig::stream(true)` 运行，连接中的字节由 `akio_turn::framing::FrameReader`
  切分。每个服务器加传输一个分配；每个 endpoint 最多 4 个，与此前相同。
- **候选**：无论控制连接用什么传输，中继地址都是 UDP，但经 TCP 或 TLS 分配的候选排在经 UDP
  分配的候选之后（本地偏好在 TCP 上减半、在 TLS 上减为四分之一，与浏览器的排序一致），并有自己的
  foundation（`akio_ice::Candidate::relayed_over_stream`，内部层级）。流式分配不产生服务器反射
  候选：服务器看到的是 TCP 地址。
- **背压与上限**：连接建立前最多 64 KiB 的消息排队等待；连接排队超过 256 KiB 时丢弃中继数据
  （ChannelData、Send indication：媒体已过时，DTLS、SCTP 与 RTP 会恢复），请求与响应总会发出。
- **丢失与重连**：建立后丢失的分配（连接关闭，或经 UDP 时刷新失败）会在 1 秒后重新分配，等待时间
  加倍至最多一分钟，只要 endpoint 还在；一次成功会重置等待时间。新的中继地址在 endpoint 的候选中
  替换旧地址，并加入每个已打开的 peer（`Hub::relay_reallocated`），其 agent 会对已知的远端候选检查
  它：远端可从中继到达的 peer 无需信令即可恢复（已测试：切断连接约一秒后数据重新流动）。只经旧
  中继地址到达对端的 peer 需要一次 ICE 重启，其 offer 会带上新候选。peer 仍从已退役的中继地址
  发送的数据会被丢弃，而不是从主机 socket 发出。首次分配之前的失败会被报告（`Error::Turn`、
  `Error::Timeout`），不重试。

### 2. `Endpoint` 上的主动 ICE-TCP

- **`Endpoint::dial_tcp(&Arc<Engine>) -> SocketAddr`** 增加一个主动 TCP 主机候选：endpoint 的
  主主机地址加端口 9，这正是 SDP 为主动候选写的地址（RFC 6544 §4.5），因此也是 agent 配对时的
  本地地址。agent 将它与远端被动候选配对；一个候选对的第一次检查会让 endpoint 为该 peer 与远端
  地址拨一条连接（RFC 6544 §5.1：每个候选对一条连接），连接建立前最多排队 64 KiB；发往尚无连接的
  远端的其他数据报被丢弃。连接上到达的帧作为从远端地址发往候选地址的数据报交给该 peer。失败或关闭
  的连接会被遗忘，agent 的下一次检查会重新拨号；peer 关闭时其连接随之关闭。endpoint 的主动与被动
  连接共用一个上限（256）。
- **不实现同时打开（`tcptype so`）**：浏览器与 pion 都不提供它，而且它需要两端穿过 NAT 同时
  连接，这一点 UDP 上的 ICE 或 TURN 中继做得更好。

### 3. `RtcServer` 上的被动 ICE-TCP

这符合 ICE-lite 的设计：lite agent 只应答检查、从不发送检查，被动候选也只接受连接，因此服务器
不需要自己的连接逻辑。

- **`RtcServer::tcp_candidates(addrs)`** 在每个 answer 与 offer 中加入被动 TCP 主机候选；
  **`RtcServer::tcp() -> RtcTcp`** 是这些地址上 engine TCP 监听器的 acceptor
  （`Listener::tcp(addr).serve(server.tcp())`），服务器的连接因此像其他连接一样运行在 engine 的
  I/O 线程上。
- 规则与 endpoint 的被动候选相同：第一帧必须在 10 秒内是指向服务器某个 peer 的检查，之后的帧作为
  数据报交给该 peer，peer 从候选地址发出的数据加帧后写回（排队超过 1 MiB 时丢弃），peer 关闭时其
  连接随之关闭。连接数最多为 `RtcServer::max_peers` 的两倍（至少 256；不限 peer 时为 4096）。
  监听器绑定在未指定地址上时，由连接的本地地址选择候选（精确地址，否则端口与地址族相同者）。
- TCP 监听器可以与 UDP 监听器使用同一端口，因此 TCP 与 UDP 候选可能地址相同：peer 记住经连接到达它的远端
  地址（最多 16 个，在它自己的锁下），发往这些地址的数据走连接，因此 UDP 路径不取共享锁；`akio-ice` 的
  agent 能区分同一地址上的 UDP 与 TCP 本地候选（此前会把后加入的当作重复丢弃）。连接只在第一次检查时查找
  一次它的 peer。
- 在内部，endpoint 与服务器的 ICE-TCP 共用一个 `TcpSide`（被动候选、主动候选，按远端地址以及按
  peer 与远端地址索引的连接）。

### 4. 选择本地候选：`Endpoint::candidate_filter`

- **`Endpoint::candidate_filter(f)`**：新 peer 只使用 `f` 接受的本地候选，体现在其 agent 以及其
  offer 和 answer 中：相当于浏览器的 `iceTransportPolicy`（`|c| c.kind() == "relay"`），或只用
  ICE-TCP（`|c| c.transport() == "tcp"`）。重新分配得到的中继候选只有通过过滤才会提供给已打开的
  peer。**`Candidate::kind()`**（`host`、`srflx`、`prflx`、`relay`）与 **`Candidate::transport()`**
  （`udp`、`tcp`）让过滤器（以及应用）区分候选。没有它，只含中继候选的 offer 仍会让 agent 从主机
  候选发出检查，互通测试就无法证明确实使用了中继。

### 5. 与 Chrome 的 simulcast

已用无头 Chrome 验证（`tools/interop/webrtc/browser.sh`，`webrtc-interop` 示例的 `sfu` 模式）：

- **来自 Chrome**：Chrome 发布三个 VP8 编码（1280x720 的 1/4、1/2 与原尺寸，`l`、`m`、`h`）；
  `RtcServer` 的 answer 接受它们（`a=simulcast:recv l;m;h`），每个 RID 各有自己的流到达（Chrome
  报告每层都有发送的帧）。
- **层选择**：向观众转发其中一层的 SFU 在新层的关键帧处切换，并只向发布者请求该层：
  **`Peer::request_layer_keyframe(mid, rid, kind)`** 只向该 RID 的接收流发送 PLI 或 FIR（该 RID
  尚无流到达时为 `Error::UnknownMedia`）。按 l -> m -> h 切换时 Chrome 解码所选的层（宽 320、640 与
  1280 像素）。示例在切换时改写 RTP 时间戳；这与选择哪一层一样属于应用逻辑。
- **发往 Chrome**：Chrome 不协商接收 simulcast：它对带 `a=simulcast:send` 的 offer 的 answer 中没有
  `a=simulcast` 或 `a=rid`。按 RFC 8853 的规定，也正如 ADR-017 的实现，此时只发送第一个编码，且不带
  answer 未接受的 RID 扩展；Chrome 能解码（1280 像素）。我们这一侧无需修复。

## 影响

- 公开 API（新增）：`RelayServer`（`udp`、`tcp`、`tls`、`from_url`、`tls_config`、`addr`、
  `transport`），`Endpoint::{gather_relay_via, dial_tcp, candidate_filter}`，
  `RtcServer::{tcp_candidates, tcp}`，`RtcTcp`（一个 `Acceptor`）及其隐藏的处理器 `IceTcp`，
  `Peer::request_layer_keyframe`，`Candidate::{kind, transport}`；`akio-ice`（内部层级）：
  `Candidate::relayed_over_stream`。快照已更新。`gather_relay` 现在也会重新分配丢失的分配（此前
  丢失后不再恢复）。
- 没有 TCP 或中继的 endpoint 与服务器，UDP 数据路径不变：只有存在 TCP 端或中继列表时才会查看它们
  （中继数量与此前一样无锁读取）。gpu51 上与 main 8bc6a2c4 的同轮 A/B（`quiet.sh`，CPU 2-9，交替轮次）：两个回环 `Endpoint` 之间的 RTP
  媒体 1.003 倍（91.9 对 91.6 MB/s，7 轮），数据通道吞吐 1.024 倍（191.9 对 187.3 MB/s，15 轮）：无回退。
- 新 fuzz 目标 `webrtc_turn_url`（TURN URL 解析器）；`webrtc_sdp` 的种子现在包含主动 TCP 候选与
  经 TLS 分配的中继候选。中继的流式路径复用 `FrameReader`（由 `turn_stream` fuzz），主动 ICE-TCP
  路径复用 `akio_ice::tcp::FrameReader`（由 `ice_tcp` fuzz）。
- 互通：`tools/interop/webrtc/run.sh`（pion）：在 `akio-turn` 与 pion/turn 上经 TCP 与 TLS 分配
  中继候选的 `Endpoint`；双向 ICE-TCP（我方被动对 pion 主动，我方主动对 pion 的被动 TCP mux，pion
  主动对 ICE-lite 服务器的被动候选）。`linux.sh`（coturn）：在 coturn 上经 TCP 与 TLS 分配中继候选的
  `Endpoint`。`browser.sh`（Chrome）：Chrome 只经 ICE-TCP 连到服务器；Chrome 只用中继，经
  `akio-turn` 的 UDP、TCP 与 TLS；只带被动 TCP 候选、以及只带经 TCP 与 TLS 分配的中继候选的
  `Endpoint` 连到 Chrome（每一项都检查 Chrome 选中的候选对）；双向 simulcast 与层选择。
- 已知限制（未变）：同一 `Endpoint` 的 peer 共用它的 socket，因此其中两个 peer 与同一个远端 socket
  通信时共用同一个五元组，越过 ICE 用户名之后无法区分（一个测试因此使用第三个 endpoint）。
- 未完成：RFC 6062 TCP 中继、DTLS 上的 TURN、同时打开的 ICE-TCP、`RtcServer` 上的主动 ICE-TCP
  （lite agent 不发送检查）、Chrome 接收 simulcast（Chrome 的限制）。
