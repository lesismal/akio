# ADR-017：TCP/TLS 上的 TURN、TURN 客户端、ICE-TCP 与 simulcast 发送

[English](017-webrtc-turn-gaps.md) | 简体中文

状态：已接受（2026-11-17）

## 背景

`docs/DEV-PLAN.md` 中 WebRTC 还有四项未完成（M7 与 wave D）：TCP/TLS 上的 TURN、让 `akio-webrtc`
的 `Endpoint` 收集中继候选的 TURN 客户端、TCP 上的 ICE，以及 simulcast 发送。每一项都会让部署无法
只用 `akio`：屏蔽 UDP 的网络只能通过 TCP 或 443 端口上的 TLS 访问 TURN 服务器；对称 NAT 后的客户端
需要中继；位于不友好 UDP 防火墙后的服务器需要 ICE-TCP；为不同带宽观众供流的 SFU 需要推流端发送
simulcast。

## 决定

### 1. TCP 与 TLS 上的 TURN（`akio-turn`）

- **`TurnServer::stream() -> TurnStream`**：TCP 监听器的 acceptor，经 `akio::tls::Tls` 包装后也用于
  TLS 监听器（`turns:`）。它与 UDP 监听器共享服务器状态（分配、配额、nonce 密钥、中继）。流式客户端
  位于分片的另一半，因此同一地址在 UDP 和 TCP 上是两个客户端，互相访问不到对方的分配。
- **分帧（`akio_turn::framing`）**：STUN 消息与 ChannelData 首尾相接，各自由长度字段界定；ChannelData
  填充到 4 字节的倍数（RFC 8656 §12.5）。`FrameReader` 对整块到达的消息零拷贝交出，最多保留一条不完整
  的消息（64 KiB）；首字节既非 STUN 也非 ChannelData 时关闭连接。`TurnEnv::pads_channel_data`（带默认
  实现，默认 `false`）告诉 `TurnCore` 为流式客户端填充 ChannelData。
- **生命周期**：分配与其连接同生共死（RFC 8656 §3.1）：连接关闭时 `TurnCore::remove_client` 释放它。
  在 `TurnConfig::stream_allocate_timeout`（30 秒）内未分配的连接由过期清扫关闭（规则 9）。
- **背压**：中继仍走 UDP；当流式客户端的连接排队超过 `TurnConfig::max_stream_queue`（256 KiB）时，发给
  它的中继数据（ChannelData、Data indication）被丢弃，慢读者不会积压过期媒体；STUN 响应总是发送。
  另一方向从流读、以数据报发出，不会排队。
- **RFC 6062 TCP 分配：不实现。** 它用于中继到 TCP 对端（`CONNECT`、`CONNECTION-BIND`、每个对端一条
  数据连接）。WebRTC 从不需要它（浏览器与 pion 在 TCP 或 TLS 控制连接上中继 UDP，正是本 ADR 加入的
  功能），实现它会为没有 WebRTC 用途的功能引入每对端连接状态、第二条监听路径和连接尝试的生命周期。
  `REQUESTED-TRANSPORT` 为 TCP 时仍回 `442`。

### 2. TURN 客户端（`akio_turn::client`）与中继候选（`akio-webrtc`）

- **`client::Client`**：单个分配的 sans-io 客户端，跑在 UDP 或流上（`ClientConfig::stream`）：第一个
  Allocate 不带认证，然后用 401 挑战给出的长期凭据，`438` 刷新 nonce，对已认证请求的每个成功响应必须
  带有效的 `MESSAGE-INTEGRITY`。生命周期结束前一分钟 Refresh；`send_to` 首次使用时建立 channel
  （ChannelBind 同时建立权限），channel 关闭或被拒时退回到权限加 Send indication，对端在用期间每 4 分钟
  刷新一次绑定（权限有效期 5 分钟）；空闲 10 分钟的对端被遗忘。UDP 请求会重传（500 毫秒起翻倍，7 次，
  39.5 秒）；流上的请求只发一次，39.5 秒超时。上限：`max_peers`（64）、`max_pending`（等待绑定的数据
  64 KiB，每对端 16 个数据报）、channel 号 0x4000–0x4FFF。事件：`Allocated`、`Failed`、`PeerFailed`、
  `Closed`。
- **`Endpoint::gather_relay(server, username, password, timeout)`** 通过 endpoint 自己的 UDP 套接字分配
  （阻塞，与 `gather_srflx` 相同），并加入中继候选，以及服务器报告的、尚未出现过的服务器反射地址。一个
  分配服务于该 endpoint 的所有对端；每个 endpoint 最多 4 个（超过或服务器拒绝时返回 `Error::Turn`）。
  来自服务器的数据报在对端路由之前从套接字上取下，中继来的数据像到达中继地址一样交给对端；对端从中继
  地址发出的数据经客户端发送。客户端的定时器跑在共享的 WebRTC 定时器线程上。`Endpoint::close` 删除
  分配。内部的对端输出现在带源地址（`Rtc` 输出），借此区分中继或 TCP 候选对与 UDP 候选对。
- **`Endpoint` 上的 TCP/TLS TURN** 未接入：sans-io 客户端支持它，并已在两者上与 `akio`、pion/turn、
  coturn 测试，但 `Endpoint` 只通过 UDP 分配。

### 3. ICE-TCP，被动候选（`akio-ice`、`akio-webrtc`）

- `akio-ice` 的候选带传输类型：`TcpType::{Active, Passive, So}`，SDP 写法 `tcp ... tcptype`（主动候选的
  端口为 9），RFC 6544 本地优先级（方向优先级乘 2^13 加上 IPv6 优先的其他优先级），TCP 类型优先级低于
  UDP（host 为 90，与 Chrome 相同），只在同一传输内、兼容类型之间配对。被动本地候选从不发起检查：经接受
  的连接到达的检查产生一个对端反射的主动远端候选，其候选对获得触发检查、提名与 consent。RFC 4571 分帧
  在 `akio_ice::tcp`。`ParseError::Tcp` 删除（TCP 行可以解析）；该 crate 属内部层级。
- **`Endpoint::listen_tcp(&Arc<Engine>, addr)`** 在与 UDP 不同的 TCP 端口上监听并加入被动 host 候选。由
  专用线程接受连接（阻塞 `accept`，从不在 I/O 线程上，规则 1）并交给引擎（`Engine::adopt_tcp`）；同时
  最多 256 条。连接的第一帧必须在 10 秒内是一个指向该 endpoint 某个对端的检查，否则关闭；之后其帧作为
  来自连接远端地址的数据报交给该对端，对端从候选地址发出的数据经分帧发回，排队超过 1 MiB 时丢弃（数据报
  语义：DTLS、SCTP 与 RTP 自行恢复）。关闭的对端关闭其连接；`Endpoint::close` 停止监听。
- **未实现主动与同时打开的本地候选**：只能经 TCP 访问的 `Endpoint` 是服务器；屏蔽 UDP 的网络中的客户端
  使用 TCP/TLS 上的 TURN。

### 4. simulcast 发送（`akio-webrtc`）

- **`SdpChanges::add_simulcast_media(kind, dir, rids, stream_id, track_id) -> Result<Mid, Error>`**
  （1 到 8 个 RID，由字母、数字、`-`、`_` 组成，最长 16 个字符；方向须含发送）以及
  **`Peer::write_simulcast(mid, rid, pt, wallclock, rtp_time, data)`**。每个编码是独立的 RTP 流，有自己
  的 SSRC、RTX SSRC 与打包器；由应用分别编码各层。
- SDP 与浏览器写法一致（RFC 8853）：`a=rid:<id> send` 与 `a=simulcast:send a;b;c`，不写 `a=ssrc`。由
  应答中的 `a=simulcast:recv` 决定发送哪些编码（以 `~` 暂停的不发）；没有它时只发第一个。不发送的编码的
  样本被丢弃；未知 RID 返回 `Error::UnknownMedia`。
- 包带 MID 与 RTP stream id 扩展，重传（RTX）带 repaired stream id。发送者报告、报告块、NACK 与
  PLI/FIR 均按编码处理；`KeyframeRequest::rid` 指明编码。
- 作为应答方，本栈也接受远端的 simulcast offer：应答带 `a=rid:<id> recv` 与 `a=simulcast:recv`，收到的
  流带 RID（`MediaData::rid`），未声明的 RTX 映射到其 repaired RID 对应的流。层选择（像 SFU 那样从多个
  RID 中转发一个）留给应用。

## 影响

- 公共 API（新增）：`akio_turn::{framing, client}` 模块、`TurnServer::stream`、
  `TurnServer::stream_relay_of`、`TurnStream`、`TurnConfig::{stream_allocate_timeout, max_stream_queue}`、
  `TurnCore::remove_client`、`TurnEnv::pads_channel_data`（带默认实现）；`Endpoint::{gather_relay,
  listen_tcp}`、`Error::Turn`（该枚举为 `#[non_exhaustive]`）、`SdpChanges::add_simulcast_media`、
  `Peer::write_simulcast`。快照已刷新。`TurnServer` 的 UDP 数据路径在每条发往客户端的消息上多一个分支
  （连接类型），分片表加倍（一半给流式客户端）。在 gpu51 上与 main ab65d376 同轮 A/B（`quiet.sh`，CPU 2-9，
  7 轮交替）：`turn-relay-bench 64 5 4` 为 1.057 倍（65.7k 对 62.1k 数据报/秒，每轮不低于基线），两个
  `Endpoint` 之间的回环数据通道吞吐为 1.020 倍（193.2 对 189.5 MB/s，噪声范围内）：无回退。
- 新模糊测试目标 `turn_stream`（流分帧送入服务器，服务器消息送入客户端）与 `ice_tcp`（RFC 4571 分帧送入
  带被动候选的 agent）；`webrtc_sdp` 覆盖 simulcast offer/answer 与 TCP 候选。
- 互通（`tools/interop/webrtc/run.sh`、`linux.sh`）：pion/turn 客户端经 UDP、TCP、TLS 对 `akio-turn`；
  coturn 的 `turnutils_uclient` 经 UDP、TCP、TLS 对 `akio-turn`；`akio_turn` 客户端经 UDP、TCP、TLS 对
  pion/turn、coturn 与 `akio-turn`；只提供中继候选（来自 `akio-turn`、pion/turn、coturn）的 `Endpoint`
  对 pion；只提供被动 TCP 候选的 `Endpoint` 对只用主动 TCP 候选的 pion；向 pion 发送 h/m/l 三层
  simulcast，pion 收到三条 RID 流。
- 未完成：RFC 6062、`Endpoint` 上的 TCP/TLS TURN、本地主动 ICE-TCP 候选、`RtcServer` 上的 ICE-TCP、
  层选择、浏览器测试中向 Chrome 发送 simulcast。
