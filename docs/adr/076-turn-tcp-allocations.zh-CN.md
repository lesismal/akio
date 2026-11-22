# ADR-076：TURN TCP 分配（RFC 6062）

[English](076-turn-tcp-allocations.md) | 简体中文

状态：已采纳（2026-11-22）；2026-11-22 更新（由引擎驱动的客户端、Connect 超时、`Endpoint` 的决定）

## 背景

`akio-turn` 在 UDP、TCP、TLS 与 DTLS 上提供 TURN，但所有中继都是 UDP socket：请求
`REQUESTED-TRANSPORT` TCP 的 Allocate 得到 442，sans-io 客户端也只能请求 UDP。DEV-PLAN 记着
"不实现 RFC 6062 TCP 中继：WebRTC 用不到"，指南的 WebRTC 一章也把 TCP 中继列为未完成。

浏览器确实从不请求 TCP 分配，但其他 TURN 用户会：中继 TCP 媒体或文件传输的 SIP、XMPP 客户端，以及因为
TURN 服务器是双方唯一都能到达的主机而经它隧道传输 TCP 协议的应用。coturn 与 pion/turn 都实现了 RFC 6062
的两端，用 `akio` 替换它们的部署也需要。

RFC 6062 概要。客户端打开一条*控制连接*（TCP 或 TLS），以 `REQUESTED-TRANSPORT` 6 分配；中继地址是一个
监听中的 TCP socket。**Connect** 请求（`XOR-PEER-ADDRESS`）让服务器从中继地址向对端打开 TCP 连接，并以
`CONNECTION-ID` 应答。对端连入中继地址时，若它有权限，客户端收到带 `CONNECTION-ID` 的
**ConnectionAttempt** 指示。两种情况下客户端都向服务器打开一条*新*连接并发送带该 ID 的
**ConnectionBind**；成功响应之后，这条*客户端数据连接*与*对端数据连接*双向传输原始字节，不再有 TURN 分帧。
未绑定的连接 30 秒后关闭；关闭一侧即关闭另一侧；分配结束则全部关闭。错误码 446（Connection Already
Exists）与 447（Connection Timeout or Failure）。

约束：已绑定连接的字节不得经过分片状态机（不能每次读取都拿分片锁）；背压必须双向联动（规则 7、8）；
I/O 线程不得阻塞在 `accept` 上（规则 1）；所有表与缓冲都有上限；另一个会话正在修改 `akio-webrtc`，所以
改动只在 `akio-turn` 内。

## 决定

### 服务器

**状态机（`TurnCore`，sans-io）。** 分配可以带一个 TCP 部分：按 ID 与按对端传输地址索引的连接（每个对端
地址一条连接，RFC 6062 第 3 节）。RFC 6062 规定的一切由核心决定，socket 留给环境：

- *Allocate*（传输 6）：`TurnConfig::tcp_relays` 关闭或环境不支持 TCP 时回 442；客户端不在流上（核心询问
  `TurnEnv::pads_channel_data`，它恰好对 TCP/TLS 客户端为真）或请求带有 `DONT-FRAGMENT`、`EVEN-PORT`、
  `RESERVATION-TOKEN` 时回 400；地址族不符回 440。配额与 UDP 分配相同。6 与 17 以外的传输仍回 442。
- *Connect*：无分配回 437；UDP 分配上或缺少对端时回 400；地址族不符回 443；对端策略
  （`peer_allowed` / `denied_by_default`）拒绝或端口为 0 时回 403；与该对端地址已有连接（连接中、
  等待中或已绑定）时回 446；超过每个分配 `TurnConfig::max_tcp_connections`（64）回 508。否则核心把连接记为
  *连接中*并调用 `TurnEnv::connect_peer`；请求在环境调用 `TurnCore::tcp_connected` 时才应答（成功带
  `CONNECTION-ID`，或 447）。与 RFC 一致，Connect 不需要权限。
- *对端连入*：当分配对对端 IP 有未过期的权限、策略允许、还有余量且该地址没有连接时，
  `TurnCore::tcp_incoming(relay, peer)` 接受连接；它先调用 `TurnEnv::accept_peer`，再发送
  ConnectionAttempt（按此顺序，ConnectionBind 不会抢在登记之前）。否则调用者立即关闭连接（第 5.3 节）。
- *ConnectionBind*：与其他请求一样认证，只有一点不同：nonce 可以是发给数据连接自身地址的，*也*可以是发给
  持有该 ID 的分配的控制连接的（pion 与 coturn 复用控制连接的 nonce；我们的 nonce 与客户端地址绑定）。ID
  必须指向同一用户的分配中正在等待绑定的连接；否则一律 400（"不存在"与"属于别人"不做区分）。请求不是经流
  到达时也回 400。
- `handle_timeout` 中的*期限*：连接或接受后 30 秒仍未绑定的连接被关闭；环境始终没有报告的 Connect 在
  60 秒后回 447。`TurnCore::tcp_closed` 忘掉已结束的连接。删除或过期的分配关闭其所有连接
  （`TurnEnv::close_connection`）与监听 socket（`TurnEnv::close_tcp_relay`）。
- TCP 分配上的 ChannelBind 回 400；发给它的 Send 指示与 ChannelData 被丢弃。

`TurnEnv` 新方法，都有默认实现（已有环境照常编译，并以 442 拒绝 TCP 分配）：`open_tcp_relay`、
`close_tcp_relay`、`connect_peer`、`accept_peer`、`connection_bound`、`close_connection`。`TurnCore` 新方法：
`tcp_connected`、`tcp_incoming`、`tcp_closed`。`TurnStats::tcp_connections` 统计打开的连接。

**基于 `akio` 的 `TurnServer`（`tcp.rs`）。**

- 中继地址是绑定在 `relay_ip:0`、带 `SO_REUSEADDR` 与 `SO_REUSEPORT` 的非阻塞监听 socket
  （`akio_sys::listen`），因此到对端的连接可以用 `Engine::dial_from` 从同一地址发出（RFC 6062 第 5.2 节要求
  以中继地址为本端）。reuseport 绑定端口 0 理论上可能返回我们另一个中继占着的端口，所以绑定到的地址若已在
  服务器的监听表中，就关闭后重绑（最多 16 次）。
- **每个服务器一个接受线程**（"akio-turn-tcp-accept"，随第一个 TCP 分配启动），用 `akio_sys::Poller`
  轮询所有中继监听 socket；监听 socket 经命令列表与 `Waker` 加入和移除。接受的 socket 交给
  `Engine::adopt_tcp`，于是权限检查与 ConnectionAttempt 在 I/O 线程上、acceptor 的 `on_open` 里运行。
  没有每分配一个线程，也没有 I/O 线程在 `accept` 中等待。服务器被丢弃后一秒内线程退出。
- 连接是以 `CONNECTION-ID` 为键的服务器级表中的*链接*：分配的客户端与分片（ConnectionBind 从另一条连接到达，
  其客户端地址散列到另一个分片）以及两条 `akio` 连接。ID 在服务器范围内唯一：从随机起点开始的计数器，
  从不为 0。
- 在分片锁内请求的拨号在释放锁之后才发起（拨号可能同步失败，而其失败处理会再次锁该分片）。
- 消息为 ConnectionBind 的流客户端由拥有该 ID 的分片应答；成功时先发送响应，再发送对端在此期间发来的内容，
  然后连接变为原始中继：同一次读取中 ConnectionBind 之后的剩余字节发往对端（`FrameReader::push_until`
  停在该消息并交回剩余部分），连接离开客户端表，因此"从不分配的连接"的清扫不再作用于它。从不绑定的连接
  由该清扫在 `stream_allocate_timeout`（30 秒）后关闭。
- 绑定之前，对端的字节最多保留 `TurnConfig::tcp_relay_buffer`（64 KiB）；之后暂停读取对端，这会关闭其 TCP
  窗口（第 5.2 节及安全考虑），在绑定时恢复。
- 绑定之后，每一侧直接写入对方的 `Conn`，除了只取一次的每连接锁之外不拿任何锁；目标排队超过
  `tcp_relay_buffer` 字节时，暂停读取源（`hold_reads`），直到目标排空（`Conn::on_drain`）。两条连接都
  `set_relayed`，因此引擎自身的写背压不会让一对"能写时才读"的对端死锁。
- 关闭任一连接会关闭另一条并告知核心（`tcp_closed`）；控制连接关闭会删除分配，连同所有链接。
- Connect 等待引擎的 `Config::connect_timeout`（默认 10 秒）。RFC 6062 要求至少 30 秒：需要严格符合的部署
  在服务 TURN 的引擎上调大该设置；核心自己的 60 秒保护只对从不报告的环境有意义。
  （已被下文的更新取代：`TurnConfig::tcp_connect_timeout`，30 秒。）

### 客户端（`akio_turn::client`，sans-io）

- `ClientConfig::tcp_allocation(true)`（同时设置 `stream`）请求传输 6。
- `Client::connect(now, peer)` 发送 Connect；随后是 `ClientEvent::Connected { peer, id }` 或
  `ClientEvent::ConnectFailed(peer, error)`。每个对端同时最多一个 Connect。
- `Client::create_permission(now, peer)` 立即安装权限，并在客户端关闭前一直刷新，不论是否使用（连入 TCP
  中继的对端需要它；在 UDP 分配上它是一个固定的对端）。`ClientEvent::ConnectionAttempt { peer, id }` 报告
  连入的对端。
- `Client::data_connection(now, id) -> Option<DataConnection>` 为新连接返回一个 sans-io 绑定器：
  `poll_transmit` 给出 ConnectionBind（分配的凭据与 nonce），`handle_input(data) -> usize` 接收响应（完整或
  分段）并返回取走的字节数，`state()` 为 `DataState::Bound` 后调用者把 `data[n..]` 作为对端的首批字节转发；
  401/438 质询最多应答三次；`handle_timeout` / `poll_timeout` 在 `ClientConfig::timeout` 后使其失败。不以
  STUN 开头的流使其失败。
- TCP 分配上 `send_to` 返回 false；`ClientEvent` 新增三个变体（本就是 non-exhaustive）。

### 编解码与分帧

`Method::CONNECT`、`CONNECTION_BIND`、`CONNECTION_ATTEMPT`（0x00a-0x00c），`attr::CONNECTION_ID`
（0x002a）；`CONNECTION-ID` 是已知的必须理解的属性。`FrameReader::push_until`（crate 内部）是在指定消息
之后停下的 `push`。

## 后果

- `akio-turn` 依赖 `akio-sys`（内部 crate，已经通过 `akio` 在依赖图中）提供监听 socket 与 poller。没有
  第三方依赖。
- 行为变化：经 UDP 或 DTLS 的 TCP Allocate 现在回 400 而不是 442（RFC 6062 第 5.1 节）；经 TCP/TLS 则会成功，
  除非 `TurnConfig::tcp_relays` 为 false。
- 新公开 API：`TurnConfig::{tcp_relays, max_tcp_connections, tcp_relay_buffer}` 与
  `TurnConfig::tcp_relays()`；`TurnEnv::{open_tcp_relay, close_tcp_relay, connect_peer, accept_peer,
  connection_bound, close_connection}`；`TurnCore::{tcp_connected, tcp_incoming, tcp_closed}`；
  `TurnStats::tcp_connections`；`ClientConfig::tcp_allocation`（字段与构造方法）；
  `Client::{connect, create_permission, data_connection}`；`ClientEvent::{Connected, ConnectFailed,
  ConnectionAttempt}`；`DataConnection`、`DataState`；上述 STUN 常量；隐藏的 `TcpPeer` 处理器。
- 提供 TCP 分配的服务器每条中继连接占两个 socket、每个分配一个监听 socket；`max_tcp_connections` ×
  `max_allocations_per_user` 限定一个用户的占用，引擎的 `max_connections` 限定总量。
- 一条连接刚关闭后，立即从中继地址重连同一对端地址可能因四元组仍在服务器上处于 TIME_WAIT 而得到 447；
  RFC 6062 本就要求客户端等 10 秒再重试同一对端。
- UDP 中继的热路径不受影响：逐数据报的代码路径只在本就读取的分配上多了一次 `tcp.is_some()` 判断。gpu51 上
  与 main 同轮 A/B（`turn-relay-bench 8 6 4`，quiet.sh 下交替 6 轮）：平均总量 30.86 万 vs 26.80 万数据报/秒，
  1.15 倍，在各轮约 ±20% 的波动之内：无回退。

测试：`TurnCore` 单元测试（Connect 在报告时应答、连接中时 446、30 秒绑定期限、失败时及 60 秒保护触发时的 447、
端口 0 被拒、ChannelBind 被拒、连入对端的权限及其过期、每个对端地址一条连接、连接上限、用控制连接的 nonce
或自己的 nonce 做 ConnectionBind、第三个地址的 nonce 回 438、无凭据回 401、未知 ID / 已绑定 / 其他用户回 400；
Allocate 规则：只限流、不得带 UDP 专用属性、440、不支持或关闭设置时 442、配额归还；Connect 的 437 与 UDP
分配上的 400）；客户端对核心的单元测试（Connect 事件、447、空闲 15 分钟后仍在的固定权限、ConnectionAttempt、
逐字节喂入且响应后紧跟对端字节的 `DataConnection`、拒绝、438 重试、垃圾数据与期限）；`FrameReader::push_until`
在每个切点的测试；真实 TCP 与 TLS 监听器上的集成测试（`tests/tcp.rs`：从中继地址发起的 Connect、对端提前
发送的字节被保留并送达、双向同时 1 MiB、关闭任一侧即关闭另一侧、无权限的对端被关闭、有权限的被通告并经 TLS
绑定、同一 ID 的第二次绑定被拒、控制连接关闭时全部关闭、447 / 446 / 508、未知 ID 与他人 ID 的绑定、Allocate
拒绝，以及背压：不读的数据连接让写 64 MiB 的对端远未写完就停住，之后所有数据按序到达）。模糊测试：新目标
`turn_tcp`（带 TCP 环境的核心，由控制消息、数据连接消息、对端连入、拨号结果、关闭与期限驱动；以及被喂入读取的
`DataConnection`），种子覆盖每一种 RFC 6062 消息。

互通（`tools/interop/webrtc/turn-tcp.sh`，Docker；coturn 4.6、pion/turn v5.1.3）：coturn 的
`turnutils_uclient -T`（成对的客户端互相连接对方的中继地址）经 TCP 与 TLS 对 akio-turn；akio_turn 客户端
（Connect，然后一个有权限的对端连入；每条连接回显 20 条消息与 1 MiB）经 TCP 与 TLS 对 coturn、pion/turn 与
akio-turn；pion/turn 的 TCP 分配客户端（Dial 与 Accept）对 akio-turn 与 coturn。

未完成：`akio-webrtc` 的 `Endpoint` 使用 TCP 分配（没有 WebRTC 栈用它）；由引擎驱动的客户端封装（sans-io
客户端与示例展示了衔接方式）；`ADDITIONAL-ADDRESS-FAMILY` 双分配（UDP 也不支持）；独立于引擎的每个 Connect
的连接超时。

## 更新（2026-11-22）：由引擎驱动的客户端、服务器自己的 Connect 超时，以及 `Endpoint`

上文遗留的三项，均已决定，其中两项已完成。

### 服务器自己的 Connect 超时

`TurnConfig::tcp_connect_timeout`（30 秒，RFC 6062 第 5.2 节允许的最小值）同时取代引擎的
`Config::connect_timeout` 与核心固定的 60 秒保护：

- 期限由核心维护：Connect 记录 `now + tcp_connect_timeout`，到期时 `handle_timeout` 回 447 并调用
  `TurnEnv::close_connection`，与环境做什么无关。环境此时可以停止尝试。
- `TurnServer` 不再用 `Engine::dial_from` 拨号（它使用引擎的 `connect_timeout`，默认 10 秒，且不改动每个
  后端就无法为单次拨号另设超时）。原本就在轮询中继监听 socket 的接受线程现在也负责打开 Connect 的连接：
  `akio_sys::connect_nonblocking_from(relay, peer)`，注册可写事件；可写时由 `take_error` / `peer_addr`
  判断成功，已连接的 socket 交给 `Engine::adopt_tcp`，使用与以前相同的 `PeerAcceptor`。它每秒丢弃链接已不
  存在的尝试（核心已放弃，或分配已结束）并关闭其 socket。于是引擎自身的设置与 Connect 无关，两个方向都是：
  更短不会截断它，更长也不会拉长它。
- 行为变化：连接一个从不应答的对端，现在 30 秒后失败（默认引擎设置下原为 10 秒）。
- 顺带发现：接受循环把 `Poller::wait` 的事件追加到一个从不清空的 vector 中，因此它在服务器整个生命周期内
  随每个事件增长，并在每次唤醒时重放旧事件（多余的 `accept` 调用）。现在每次等待前都会清空。

### 由引擎驱动的客户端：`client::TcpAllocation`

以前应用必须自己驱动 sans-io 客户端和每个 `DataConnection`（互通示例用的是阻塞 socket）。`TcpAllocation`
在 `akio` 引擎上完成这些：

- `TcpAllocation::open(&engine, cfg, ServerTransport::{Tcp, Tls(cfg, name)}, on_event)` 拨出控制连接，
  用 `FrameReader` 切分其消息并交给 `Client`。定时器在整个进程共用的一个线程上运行（"akio-turn-timer"，
  与 `akio-webrtc` 一样是弱引用目标的最小堆），而不是每个分配一个。`on_event` 收到
  `AllocationEvent::{Allocated, ConnectionAttempt, PeerFailed, Failed, Closed}` 以及分配本身，因此可以接受
  连入尝试；回调运行时不持有任何锁。
- `connect(peer, acceptor, on_error)` 发送 Connect，收到 `Connected` 后拨出一条数据连接；
  `accept(id, acceptor, on_error)` 对 `ConnectionAttempt` 做后一步。另有 `create_permission`、`close`、
  `state`、`relayed_addr`、`mapped_addr`。
- **ConnectionBind 是一个 `Transport` 层**（`akio::Transport`，TLS 用的同一个钩子），有 TLS 时叠在 TLS 层之上。
  应用的 acceptor 直接服务这条连接，所以它的 handler 拿到的是普通的 `Conn<H>`，中间没有包装类型。该层在第一次
  `recv` 时发送请求（引擎在安装时以空输入调用它，让客户端传输层先说话；在 TLS 之下，请求在 TLS 自己的缓冲中等
  握手完成），在成功响应之前保留应用 `seal` 的内容，把响应之后的字节交给 `on_data`，此后一律透传。绑定完成前
  它报告 `handshaking`，`handshake_timeout` 为 `ClientConfig::timeout`，因此引擎的握手期限即可约束绑定，无需
  另设定时器。语义与 TLS 相同：TCP 连接建立时 `on_open` 就运行，它发送的内容会等待。
- 错误：传输层失败时，引擎关闭连接但不把错误传给 `on_close`（TLS 也是如此）。因此凡是让数据连接无法承载对端
  字节的情况都交给该调用的 `on_error`，最多一次：Connect 被拒（447、446）、拨号失败、TLS 失败、绑定被拒
  （400），或连接在应答之前结束（该层的 `Drop`）。由于该层在连接的锁内运行，它不在那里调用 `on_error`，而是
  交给定时器线程（`Timer::defer`）。
- 控制连接只持有弱引用：丢弃最后一个 `TcpAllocation` 会关闭它，服务器随后删除分配及其连接（RFC 6062）。
  捕获了分配的回调会让它保持存活。
- 新增 `ClientError::Io(kind, message)`（non-exhaustive 枚举）：连接失败。

### `Endpoint` 使用 TCP 分配：有意不做

RFC 6544 提供的是：被动中继 TCP 候选（第 5.5 节：通常 agent 只需要这一个，因为对端的服务器反射主动候选
都应能与之配合），由远端经 TURN 服务器连入；以及主动中继候选（每次检查一个 Connect）。在这里实现它需要：
每个 `Endpoint` 一个 TCP 分配，`akio-ice` 中的 `Candidate::relayed_tcp`，ICE-TCP 代码接受远端为
ConnectionAttempt 所指对端（而非 socket 对端）的数据连接，以及为每个远端候选的地址建立权限，而远端候选
经 peer 代码的多条路径到达。

价值太低，不值得这样做的原因：

- 浏览器从不建立 TCP 分配：libwebrtc 的 `TurnPort` 与 Firefox 的 nICEr 即使经 TCP 或 TLS 也发送
  `REQUESTED-TRANSPORT` UDP。没有浏览器提供中继 TCP 候选，所以我方的主动中继候选无处可连（libwebrtc 根本
  没有被动 TCP 候选）。
- 浏览器*可以*用其主动 TCP 候选连接我方的被动中继 TCP 候选。但 TURN 服务器只有在持有连接来源 IP 的权限时
  才接受这条连接，而 libwebrtc 只通告主机 TCP 候选（端口 9，NAT 之后的私有地址），不通告服务器反射 TCP 候选。
  在 TCP 真正有用的场景（浏览器一侧封锁 UDP），浏览器也没有服务器反射 UDP 候选，因此中继将看到的公网地址无从
  得知，连接会被拒绝。只有当该地址经其他途径得知时才行得通，而这意味着 UDP 可用，此时我方的 UDP 分配（我方
  需要时经 TCP 或 TLS 建立：ADR-032）同样能服务该浏览器。
- 两个 `akio` endpoint 之间，经 TCP/TLS 的 UDP 分配已经能穿过任何允许 TCP 出站的网络提供中继路径，其上还有
  ICE 自己的 consent 与 DTLS。

因此 `Endpoint` 继续收集 UDP 分配（经 UDP、DTLS、TCP 或 TLS），RFC 6062 在 WebRTC 之外有用的部分由
`TcpAllocation` 提供。若将来有浏览器通告服务器反射 TCP 候选或建立 TCP 分配，再重新考虑。

### 测试与互通

`TurnCore`：Connect 的期限是 `tcp_connect_timeout`（早一毫秒什么也不发生，到期时回 447 并关闭）。
真实 TCP 与 TLS 监听器上的 `tests/tcp_engine.rs`：在引擎上 connect 与 accept（handler 在 `on_open` 中发送的
问候在绑定之后到达对端；对端的早到字节最先到达；双向各 256 KiB；关闭任一侧都会关闭另一侧；`close` 删除分配），
失败情形（凭据错误得 401，447 交给 `on_error`，绑定未知 ID：400 交给 `on_error` 且只一次，连接被关闭；服务器
不可达：`Failed(Io)`；丢弃最后一个句柄：服务器忘掉该分配），以及独立于引擎的服务器 Connect 超时（引擎
`connect_timeout` 200 毫秒，`tcp_connect_timeout` 1.5 秒，一个接受队列已满的对端：1.5 秒后回 447；macOS 上
跳过，因为它对这类连接回复重置而不是丢弃 SYN）。在 macOS，以及 gpu51（Linux，rustc 1.100）的 epoll 与
`AKIO_TEST_BACKEND=uring` 下运行。

`tools/interop/webrtc/turn-tcp.sh` 增加了引擎客户端（`turn-tcp-interop engine-client`）对 coturn 4.6、
pion/turn v5.1.3 与 akio-turn，经 TCP 与 TLS（Connect，然后一个有权限的对端连入，各回显 20 条消息与 1 MiB）；
原有用例（coturn 的 `turnutils_uclient -T` 与 pion/turn 的客户端对服务器，服务器现在从接受线程拨出对端连接）
照常通过。在 gpu51 的 Docker 中全部通过。

没有热路径改动（UDP 中继与已绑定的 TCP 中继未动；Connect 与接受属于控制操作），因此没有做 A/B 基准。

仍未完成：`ADDITIONAL-ADDRESS-FAMILY` 双分配（UDP 也不支持；2026-11-22 已完成，ADR-083：TCP 分配仍是单一
地址族，以 IPv4 与 `ADDRESS-ERROR-CODE` 440 应答双分配请求）；`Endpoint` 使用 TCP 分配（见上）。
