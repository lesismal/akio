# ADR-091：TURN 转告 ICMP、经中继保留 DSCP、交还一个地址族

[English](091-turn-icmp-dscp-family-release.md) | 简体中文

状态：已接受（2026-11-23）；2026-11-23 更新（TTL、`DONT-FRAGMENT`、macOS 上的 ICMP、ICE 处理 ICMP：见末尾的
第一次更新）；2026-11-23 再次更新（host 候选的 ICMP，向客户端报告“包过大”和“超时”：第二次更新）

## 背景

ADR-083（双分配、经中继保留 ECN）留下了四项未做：

1. **转告 ICMP。** RFC 8656 11.5 节：服务器中继给对端的数据报引起 ICMP 错误时，服务器用一个带 `ICMP` 属性
   （0x8004：类型、代码、错误数据）、不带 `DATA` 的 Data 指示告诉客户端。akio-turn 的中继 socket 是未连接的
   UDP socket，除非设置 `IP_RECVERR`，Linux 会丢弃这类 socket 的 ICMP 错误。
2. **复制 DSCP。** 14 节建议 UDP 到 UDP 两个方向复制整个流量类别：DSCP（高六位）以及 ECN 码点（低两位）。
   此前只复制 ECN：引擎只报告并设置低两位。
3. **客户端按地址族 Refresh。** 服务器支持 Refresh 中的 `REQUESTED-ADDRESS-FAMILY`（单独刷新或删除一个地址
   族）；客户端总是两个一起刷新。
4. **`Endpoint::gather_relay` 默认双分配。** ADR-083 让它保持需显式开启。

coturn 4.6（互通参照）会复制中继数据报的 TOS 字节（它对每个数据报调用 `set_socket_tos`）；它对 ICMP 与按地址
族 Refresh 的处理经实测（见下文）。

## 决定

### akio 与 akio-sys：流量类别字节、绑定 socket 的 ICMP 错误

**整个流量类别字节。** 引擎原本就接收每个数据报的 `IP_TOS` / `IPV6_TCLASS` 控制消息（ADR-077），并保留其低
两位。现在保留整个字节：

- `akio_sys::RecvBatch::tos(i)`（Linux）与 `akio_sys::recv_from_tos`（macOS）给出该字节；`ecn(i)` /
  `recv_from_ecn` 是它的低两位，与以前相同。
- `akio_sys::send_to_tos` 与 `SendBatch::push_tos` 发送任意字节；`_ecn` 形式掩成两位，与以前相同。
- akio-core：连接保留正在交付的数据报的字节（`rx_tos`，与以前一样是一个 `AtomicU8`）；`Conn::rx_tos()` 与
  `Conn::send_segments_tos()` 与 `_ecn` 形式并列（四者都 `#[doc(hidden)]`，与 `_ecn` 一样不在稳定性承诺之内）；
  `UdpBinding::send_to_tos` 同样如此。数据报队列在原先存码点的位置按块存这个字节。akio-dpdk 的 UDP 仍然只报告和
  接受 ECN 位。
- 不带标记的数据报走原来的路径：原来的判断 `ecn != 0` 现在是 `tos != 0`。

**绑定 socket 的 ICMP 错误。** `Engine::bind_udp_icmp(addr, acceptor, on_icmp)` 是 `bind_udp` 加一个回调，
回调在 socket 的 I/O 线程上收到 `akio::IcmpError`（绑定地址、数据报的目的地址及端口、ICMP 发送者、ICMPv4 或
v6、类型、代码、下一跳 MTU）。仅限 Linux；其他平台上它就是 `bind_udp`，回调永远不会运行。

- group 设置 `IP_RECVERR`（IPv6 socket 上再设 `IPV6_RECVERR`）。此后内核把该 socket 的每个 ICMP 错误放进
  错误队列。`akio_sys::recv_icmp` 用 `recvmsg(MSG_ERRQUEUE)` 读出一个：`sock_extended_err` 给出来源、类型、
  代码与 `ee_info`（MTU），`SO_EE_OFFENDER` 给出发送者，消息名给出原数据报的目的地址，含端口，无需特权
  （平台给不出端口时 RFC 8656 允许端口为 0）。
- 两个副作用在出现的地方处理：
  - 错误队列非空时 socket 一直以 `EPOLLERR` 就绪（水平触发）。带回调的绑定 socket 的读处理先读空错误队列
    （与接收一样每个事件有上限），事件因此不会空转。
  - 内核还会把错误留作 socket 的待处理错误，下一次 `recvmsg` 或 `sendmsg` 会返回它一次（`ECONNREFUSED`、
    `EHOSTUNREACH`、`EMSGSIZE` 等）而不做任何事。在这种 socket 上，接收循环跳过这些错误，而不是打一行日志
    并结束这一批；`UdpBinding::send_to` / `send_to_tos` 遇到它们时重试一次（`akio_sys::is_icmp_error`），
    碰上待处理错误的那个数据报仍会发出。
- 本地来源的错误（`SO_EE_ORIGIN_LOCAL`）被跳过。回调 panic 会被捕获并记录。
- 只有绑定 socket（`bind_udp_icmp`）如此。监听 socket、拨号 socket（已连接：ICMP 本来就以连接错误的形式出现）
  与普通的 `bind_udp` 都不变。
- `Group` trait 新增 `bind_udp_icmp`，默认实现调用 `bind_udp`，其他后端无需改动即可编译；目前只有 epoll 的 UDP
  循环服务绑定 socket（io_uring 引擎也经它绑定 UDP）。

### akio-turn：服务器

**DSCP。** `TurnCore::handle_client_tos` / `handle_peer_tos` 接受这个字节；`TurnEnv` 新增
`send_to_client_tos` / `send_to_peer_tos`。`_ecn` 入口与环境方法保留：`handle_*_ecn` 以两位调用
`handle_*_tos`，`send_to_*_tos` 的默认实现以两位调用 `send_to_*_ecn`，已有的环境看到的与以前完全相同。
`TurnConfig::copy_dscp`（true）决定中继的数据报保留 DSCP（14 节的首选行为，也是 coturn 的做法），还是以
DSCP 0 发出（14 节的另一种做法，“尽力而为”），后者供不希望客户端和对端自选流量类别的运营者使用。ECN 两种
情况下都复制。`TurnServer` 读取 `Conn::rx_tos()`，用 `send_segments_tos` / `UdpBinding::send_to_tos` 发送。
流式客户端与以前一样既不提供也不接收这个字节。

**ICMP。** `TurnCore::handle_icmp(now, relay, peer, type, code, mtu, env)`，11.5 节：

- 只处理 ICMPv4 类型 3（目的不可达）与 11（超时），ICMPv6 类型 1（目的不可达）、2（包过大）与 3（超时）；
  地址族取中继的。其他一律丢弃。
- 中继地址必须存活，且对对端的 IP 地址有许可（与数据一样不比较端口）。对端策略照常适用。
- 客户端收到一个 Data 指示：`XOR-PEER-ADDRESS`（目的地址，端口或 0）与 `ICMP`（类型、代码，ICMPv4 3/4 与
  ICMPv6 2 时为 MTU，否则为 0），不带 `DATA`，经客户端所用的任意传输发送（有无通道无关）。不带流量类别。
- `TurnStats::icmp` 统计数量。`TurnConfig::relay_icmp`（true）可关闭它。
- `relay_icmp` 开启时，`TurnServer` 用 `Engine::bind_udp_icmp` 绑定中继 socket；回调与对端数据报一样经中继的
  路由找到分片。

STUN 编解码：`attr::ICMP`、`Message::icmp`、`MessageBuilder::icmp`。

### akio-turn：客户端

- `ClientEvent::Icmp { peer, icmp_type, code, mtu }`（11.6 节）：针对客户端有许可的地址（任意端口）的带
  `ICMP` 的 Data 指示，不交付数据。`ClientEvent` 是 `#[non_exhaustive]`，所以新增变体是只增不破。
  `TcpAllocation` 忽略它（TCP 中继不会引起 ICMP）。
- `Client::release_family(now, v6)`：交还双分配中的一个地址，即一个 lifetime 为 0、带该
  `REQUESTED-ADDRESS-FAMILY` 的 Refresh（8 节）。该地址立即离开 `relayed_addrs()`，连同其对端及其未完成的
  请求；另一个地址保留并照常刷新（不带该属性的 Refresh 现在只覆盖它）。回应无关紧要：错误被忽略（服务器会让
  地址过期）。未分配，或者它是最后一个地址时返回 `false`（删除最后一个用 `close`）。
- 没有单独为一个地址族设定生存期的*刷新*：客户端按同一个计划刷新它的所有地址，单独刷新一个在这里没有用处；
  删除一个才有用。

### akio-webrtc：`gather_relay` 仍只请求一个地址族

普通的 `Endpoint::gather_relay` 仍只请求一个地址族；`RelayServer::dual_allocation(true)` 请求两个（ADR-083）。
原因：

- 分配由端点现在和以后的所有对端共享，所以 ICE 选定之后也永远不能交还没用到的那个地址族：第二个中继端口在
  端点存活期间一直被占用，而服务器通常是别人的（托管的 TURN 服务）。
- 收益很小：IPv6 中继候选只对有 IPv6 候选、却没有 IPv4 路径的对端有意义，而纯 IPv6 的移动网络通过 464XLAT /
  NAT64 给主机提供 IPv4。libwebrtc 也不请求双分配。
- pion/turn 忽略该属性；没有 IPv6 中继的 coturn 回 440。无害，但对它们也没有收益。

知道对端可能是纯 IPv6 的应用可以按服务器开启它。

## 实测

gpu51 上的 `tools/interop/webrtc/turn-dual.sh`（Docker，回环，127.0.0.1 与 ::1 中继）：akio_turn 客户端请求
双分配，用 DSCP EF + ECT(0)（0xba）标记自己的数据报，对端用 AF41 + ECT(1)（0x89）标记回显，经每个中继向一个
关闭的端口发送，然后交还 IPv6 中继。

| 服务器 | 两个方向的流量类别 | ICMP 端口不可达 | 交还 IPv6 地址族 |
|---|---|---|---|
| akio-turn | 0xba / 0x89 保留，IPv4 与 IPv6 | 转告：3/3（IPv4）、1/4（IPv6） | 立即删除，IPv4 保留 |
| coturn 4.6 | 0xba / 0x89 保留，IPv4 与 IPv6 | 不转告 | 在其定时器周期内（约 1 秒）删除，IPv4 保留；Refresh 回成功 |
| pion/turn v5.1.3 | 清除（一个中继：它忽略该属性） | 不转告 | – |

脚本要求 akio-turn 这一行成立；其余只打印。coturn 复制 TOS 字节，与其源码一致（每个数据报调用
`set_socket_tos`）；RFC 8656 的 ICMP Data 指示它不发送。同一次运行中，coturn 的 `turnutils_uclient -Z` / `-x`
对 akio-turn 通过（40 与 80 条消息，无丢失），pion/turn 的 `REQUESTED-ADDRESS-FAMILY` 客户端也通过；
`turn-tcp.sh`（RFC 6062，对 coturn 与 pion/turn，TCP 与 TLS）不变地通过。

## 影响

- 行为变化：akio-turn 中继的数据报现在保留发送方设置的 DSCP（以前是 socket 的，通常为 0）。`copy_dscp(false)`
  恢复 DSCP 0。在会清除 DSCP 的网络上没有变化。
- 行为变化：akio-turn 的 UDP 中继 socket 在 Linux 上开启 `IP_RECVERR`，客户端会收到不可达对端的 ICMP Data
  指示。旧的 akio_turn 客户端忽略它们（没有 `DATA`）；`relay_icmp(false)` 可关闭。
- 在 `bind_udp_icmp` 的 socket 上，`UdpBinding::send_to` 在 ICMP 错误之后可能调用两次 `sendmsg`；其他 socket
  不会。
- 公开 API：只有新增（`api/akio.txt`、`api/akio-core.txt`、`api/akio-sys.txt`、`api/akio-turn.txt`）。
- 性能：gpu51 上与 main `5cc005c0` 的 UDP 中继 A/B（`turn-relay-bench 8 6 4`，`quiet.sh` 下交替 8 轮）：
  branch / main 逐轮比值中位数 1.061（各轮波动约 ±20%）：没有可测出的变化。每个数据报都标记 DSCP EF + ECT(0)
  与都只标记 ECT(0) 相比：中位数 0.973，平均 1.022，开销相同。表格见 docs/BENCHMARKS.zh-CN.md。
- 测试：
  - akio-sys：IPv4 与 IPv6 回环上的端口不可达被放进队列，读回的目的地址、发送者、类型与代码正确；待处理错误只
    返回一次（Linux）。新常量与 `libc` 的布局对照检查。
  - akio（`tests/udp.rs`）：`bind_udp_icmp` 报告端口不可达，同时 socket 继续回显，每次 `send_to` 都成功；在
    macOS 上不报告。
  - akio-turn 核心：ChannelData、Send 与 Data 指示双向复制 DSCP，`copy_dscp(false)` 时清除，只认 ECN 的环境只看到
    两位；两个地址族的每种可转告类型都转告 ICMP（只在 18.13 节规定处带 MTU），端口为 0 也转告；其他类型、无许可、
    另一地址族的中继、未知中继、`relay_icmp(false)` 与已删除的地址族都丢弃。
  - akio-turn 客户端：`release_family` 经过 30 分钟的刷新（服务器只保留 IPv4 中继），对最后一个地址拒绝；对有
    许可的地址（任意端口）产生 `ClientEvent::Icmp`，否则忽略。
  - 真实 socket 上的 `tests/dual_ecn.rs`：两个地址族上双向的四种流量类别字节（带 ECN 码点的 EF、AF41、CS1，以及
    单独的 CS6），以及 `copy_dscp(false)`；Linux 上两个地址族的端口不可达都转告给客户端，之后中继照常工作。
  - 平台：macOS，以及 gpu51 的 epoll 与 io_uring。Clippy 无警告（rustc 1.100）。
  - Fuzz：`turn_server` 从客户端和对端接收整个流量类别字节以及 ICMP 错误（选择字节 `0xfe`、`0xfc` 与从 `0x80`
    起的偶数），断言中继的数据保留该字节、ICMP Data 指示不带 `DATA`。新种子：双分配上的双向 DSCP 与 ICMP 错误。
    在 gpu51 上每个目标运行 5 分钟，四个并行（libFuzzer 加 ASan，按 cargo-fuzz 的方式构建）：`turn_server`
    222 万次、`turn_stream` 390 万次、`turn_tcp` 258 万次、`turn_dtls` 224 万次，没有发现问题。
- 未做：
  - TTL：14 节建议出站 TTL / 跳数限制为入站减 1（coturn 如此）；中继按 socket 的默认值发送。这需要每个数据报的
    `IP_RECVTTL` / `IPV6_RECVHOPLIMIT`，以及每次发送一个控制消息，与 TOS 字节类似。
  - `DONT-FRAGMENT` 仍被接受但不起作用：中继的数据报使用 socket 的 DF 设置（Linux 路径 MTU 发现的默认值）。
  - macOS 上的 ICMP：那里未连接的 UDP socket 收不到 ICMP 错误。
  - akio-webrtc 不对 `ClientEvent::Icmp` 作出反应（ICE 检查失败会稍晚完成同样的事）。

## 更新（2026-11-23）：TTL、DONT-FRAGMENT、macOS 上的 ICMP、ICE 处理 ICMP

上面留下的四项，逐一决定并完成。

### 背景，更正

RFC 8656 14 节（UDP 到 UDP）并没有 TTL 规则，上面“未做”中的说法有误：它只涉及 DSCP、ECN、IPv4 分片字段与
IPv4 选项。被它取代的 RFC 5766 12 节有（建议：入站 TTL 减 1，为 0 时丢弃；替代：默认值）。RFC 8656 在涉及 IPv6
时保留了它：13 节像路由器那样递减（13.2：“在递减跳数限制方面表现得像普通路由器”；13.1 与 13.3 按 RFC 7915），
以默认值为替代做法，3.6 节则把重置 TTL 列为中继可以做的事之一。`DONT-FRAGMENT` 见 7.2 节（Allocate）、11.2 节
（Send）与 14 / 15 节（设置什么）；13 节规定只要任一侧是 IPv6 就忽略它。

### 决策

**TTL / 跳数限制：减 1 后复制，默认开启（`TurnConfig::copy_ttl`，true）。** 它换来的是对付 21.1.7 节的环路：
被诱使互相中继的两台服务器会把一个数据报来回传递，直到某个分配过期；认证与随机端口让环路更难搭建，而递减的
TTL 无论环路是谁搭的，最多 255 跳就终止它。coturn 在发往对端的方向上递减（见下面的实测）。代价是每个方向多一个
控制消息，实测见下文。

- akio-sys：`enable_recv_ttl`（`IP_RECVTTL` / `IPV6_RECVHOPLIMIT`，按 socket，默认关闭：只有开启的 socket 才
  为这个控制消息付出代价），`RecvBatch::ttl` 与 `tos_ttl`（一次遍历控制消息得到两者），`Batch::push_ip` 与
  `send_to_ip`（在 `IP_TOS` / `IPV6_TCLASS` 旁边加 `IP_TTL` / `IPV6_HOPLIMIT`；控制缓冲区为容纳第三个消息从 64
  字节增至 96 字节），macOS 上的 `recv_from_ip`。
- akio-core（与 `_tos` 形式一样隐藏）：`Conn::rx_ttl`、`Conn::enable_rx_ttl`、`Conn::send_segments_ip`、
  `UdpBinding::send_to_ip`、`UdpBinding::enable_rx_ttl`。发送队列每个块保存一个 16 位字（低字节是流量类别，高
  字节是 TTL），原先保存一个字节；字不同的数据报不会合进同一个 GSO 消息。
- akio-turn：`IpFields`（流量类别、TTL、DF），配合 `TurnCore::handle_client_ip` / `handle_peer_ip` 与
  `TurnEnv::send_to_client_ip` / `send_to_peer_ip`，默认交给 `_tos` 方法，就像那些默认交给 `_ecn` 方法一样。
  中继的数据以入站 TTL 减 1 发出；未知（0）仍为未知（用 socket 的默认值）；以 1 到达的数据报被丢弃并计数
  （`TurnStats::ttl_expired`），但从对端发往流式客户端的数据例外，那里之后不再有数据报本身的一跳（16 节）。
  请求无论 TTL 多少都会应答。丢弃数据报时不发送 ICMP 超时：那需要原始 socket。
- `TurnServer` 在绑定中继 socket 时、以及客户端在某个监听 socket 上打开时请求 TTL（每个新客户端五元组一次
  `setsockopt`；该 socket 是共享的，所以第一个客户端的第一个数据报可能在此之前到达）。
- macOS：两个地址族都能读到 TTL，但 XNU 在发送时忽略 `IP_TTL` 控制消息（实测：数据报以 socket 的 64 发出），
  所以那里 IPv4 数据报保持默认值；IPv6 数据报能得到它们的跳数限制。

**`DONT-FRAGMENT`：据此行事。**

- `TurnEnv::sets_dont_fragment`（默认 false）：不能设置 DF 的环境按 7.2 与 11.2 节处理，把该属性当作未知且必须
  理解的属性：带它的 Allocate 回 420，并在 `UNKNOWN-ATTRIBUTES` 中列出它；带它的 Send 指示被丢弃。`TurnServer`
  在 Linux 与 macOS 上返回 true。
- 带该属性的 Send 指示，在客户端走 UDP（或 DTLS）且两侧都是 IPv4 时（14 节；13 节在涉及 IPv6 时忽略它），或
  客户端走流式传输时（15 节，任意地址族：IPv6 中继上用 `IPV6_DONTFRAG`），以 DF 置位发给对端。其余一律 DF
  清零：ChannelData、不带该属性的 Send、发往客户端的数据。14 节建议复制入站的 DF 位，而 UDP socket 读不到它；
  替代做法是 DF 为 0。
- 中继 socket 起始为 DF 清零（Linux `IP_PMTUDISC_DONT`；系统默认 `IP_PMTUDISC_WANT` 会对能放进已知路径 MTU
  的数据报置 DF）。Linux 没有按数据报设置 IPv4 DF 的办法，所以 DF 属于 socket：`TurnServer` 记住中继当前的
  设置，在需要另一设置的数据报之前、持有中继表锁时改变它（一次 `setsockopt`），这样每个数据报都按它要求的设置
  发出，而总是（或从不）要求的客户端每个数据报没有额外开销。
- akio-sys `set_dont_fragment` / `dont_fragment`（Linux 上 `IP_MTU_DISCOVER`，macOS 上 `IP_DONTFRAG`，IPv6
  socket 上 `IPV6_DONTFRAG`）；`UdpBinding::set_dont_fragment`，公开。
- 大于内核已知路径 MTU 的 DF 数据报以 `EMSGSIZE` 失败并被丢弃。

**macOS 上的 ICMP：从 ICMP socket 读取。** macOS 没有 `IP_RECVERR`，但无特权的 ICMP socket（`SOCK_DGRAM` 加
`IPPROTO_ICMP` / `IPPROTO_ICMPV6`，`ping` 用的就是它）会收到主机收到的每条 ICMP 消息的副本，包括关于其他 socket
数据报的错误（实测：回环数据报的端口不可达在两个地址族上都能收到，IPv4 带外层 IP 头，ICMPv6 不带）。被引用的
数据报给出其源地址与端口，也就是那个绑定的 socket。

- akio-sys：`IcmpListener`（macOS）与 `parse_icmp_error`（两个平台，对字节使用安全代码：引用同版本 IP 上的 UDP
  且带端口的 ICMPv4 3 / 11 / 12 与 ICMPv6 1 至 4；其余返回 `None`），`icmp_source_matches`。
- macOS 上的 akio-epoll：当某个 UDP 循环上第一个带 ICMP 处理函数的某地址族绑定 socket 注册时，循环打开该地址族
  的 ICMP socket，最后一个离开时关闭；错误交给被引用源的（地址族、端口）与地址所对应的绑定 socket 的处理函数，
  `from` 是 ICMP 消息的发送者。每次事件读取的数量有上限，与接收一样。
- 代价：每个循环的 socket 都收到主机每条 ICMP 消息的副本，并丢弃不属于自己的；绑定在 `[::]` 上的 socket 只得知
  其 IPv6 数据报的错误；能到达主机的人都可以伪造指向某个中继端口的错误，与 Linux 一样，那里内核的匹配并不更强。
  `Engine::bind_udp_icmp` 的文档说明了两个平台。

**akio-webrtc：硬 ICMP 错误让进行中的检查失败。** RFC 8445 7.2.5.2.2 节：代理可以为连通性检查处理 ICMP 错误，
硬错误应让该候选对失败。

- akio-ice：`IceAgent::handle_icmp_error(now, local, remote, type, code)`：ICMPv4 目的不可达代码 2 与 3（协议、
  端口）以及 ICMPv6 目的不可达代码 4（端口），让从 `local` 到 `remote`（端口 0 匹配任意端口）、检查尚在进行的
  候选对立即失败，而不是在约 6 秒内发满七次之后。已成功的候选对（包括选中的那个）不受影响：ICMP 没有认证（19.2
  节描述了伪造），一条工作中的路径是否仍然可用由同意新鲜度（RFC 7675）决定。软错误（主机或网络不可达、超时、
  包过大）被忽略。之后来自远端的检查会让失败的候选对恢复，与其他失败的候选对一样。
- akio-webrtc：中继把 `ClientEvent::Icmp` 转成对端点每个对端（每个传输的代理）的调用，以对端所属地址族的中继
  地址作为 `local`。不向应用报告：ICE 已做的事之外，应用没什么可做。“包过大”也不使用：DTLS、SCTP 与 RTP 的包
  都小于任何值得使用的路径 MTU。

### 实测

gpu51 上的 `tools/interop/webrtc/turn-ttl-df.sh`（Docker）：akio_turn 客户端与服务器在一个容器里，对端在经
Docker 网桥（MTU 1500）相连的另一个容器里。客户端以 TTL 40 发送，对端以 TTL 50 应答；然后发送 Send 指示：
100 字节带 `DONT-FRAGMENT`、2000 字节不带、2000 字节带、再一个 100 字节带。

| 服务器 | 客户端 → 对端的 TTL | 对端 → 客户端的 TTL | 100 B，DF | 2000 B | 2000 B，DF | 再次 100 B，DF |
|---|---|---|---|---|---|---|
| akio-turn | 39 | 49 | 中继 | 中继（分片） | 拒绝 | 中继 |
| coturn 4.6 | 39 | 64（不复制） | 中继 | 中继（分片） | 拒绝 | 未中继 |

该脚本要求 akio-turn 这一行。`turn-dual.sh`（ADR-083、ADR-091）照常通过：DSCP 与 ECN 双向复制，ICMP 端口不可达
被转告（3/3、1/4），单独交还一个地址族。

性能：gpu51 上与 main `631d7e27` 的 UDP 中继 A/B（`turn-relay-bench 8 6 4`，`quiet.sh` 下 8 轮，轮换顺序）：
branch / main 逐轮比值中位数 1.022，平均 1.039（各轮波动约 ±20%）：没有可测出的变化。同一分支开启与关闭
`copy_ttl` 相比：中位数 0.943，约 5%，与 ADR-083 中 ECN 标记的开销相当。表格见 docs/BENCHMARKS.zh-CN.md。

### 测试

- akio-sys：Linux 上双向 TTL（`send_to_ip`，以及一个同时带 GSO、流量类别与 TTL 的 `sendmmsg` 消息）与 macOS
  （IPv6 上发送跳数限制，IPv4 上为默认的 64），未请求时不报告；DF 的置位与清零；在 IPv4 与 IPv6 回环上从 ICMP
  socket 读出端口不可达并匹配到发送者（macOS）；解析器针对抓到的消息、MTU 字段、每一种截断、其他类型与协议；
  `IP_RECVTTL` 控制消息的解析。新常量与 `libc` 的布局对照检查。
- akio（`tests/udp.rs`）：`bind_udp_icmp` 现在在 macOS 上也报告端口不可达。
- akio-turn 核心：ChannelData、Send 与 Data 指示双向 TTL 减 1，0 保持，1 被丢弃并计数（请求仍会应答），
  `copy_ttl(false)`，流式客户端；`DONT-FRAGMENT`：不支持 DF 时 420 并列出它、Send 被丢弃，从 IPv4 UDP 客户端
  到 IPv4 对端以及从流式客户端时置 DF，ChannelData、不带它的 Send、UDP 客户端的 IPv6 中继与发往客户端的数据
  清零。
- 真实 socket 上的 akio-turn（`tests/ttl_df.rs`）：两个地址族上 TTL 40 / 50 以 39 / 49 到达（macOS IPv4：64），
  `copy_ttl(false)` 时为 64，TTL 1 被丢弃；在 IPv4 与 IPv6 对端上交替 DF 的 Send 指示都被中继。
  `tests/dual_ecn.rs` 的 ICMP 测试现在也在 macOS 上运行。
- akio-ice（`tests/sim.rs`）：发往关闭端口的检查在 ICMP 错误到来时立即失败（测试允许 100 毫秒），而不是数秒之后；
  软错误与其他地址被忽略，端口 0 能匹配；在模拟网络上，关闭的远端候选只得到一次检查而不是七次，代理经另一个候选
  连通，选中候选对上伪造的错误不改变任何东西。
- akio-webrtc（`tests/relay.rs`）：经 akio-turn，中继候选发往关闭端口的检查只发一次（服务器转告 ICMP 错误，
  代理让该候选对失败）；`relay_icmp(false)` 时同样的 2.5 秒内发三次或更多。
- 平台：macOS，gpu51 的 epoll 与 io_uring。Clippy 无警告。
- Fuzz：`turn_server` 增加选择字节 `0xf8` / `0xfa`（带 TTL 的对端 / 客户端数据报）与 `0xf6`（环境开始或停止
  设置 DF），并断言中继的数据带 TTL 减 1、TTL 1 从不被中继、DF 只由能设置的环境朝 IPv4 设置；新种子：双向 TTL
  以及 `DONT-FRAGMENT` 先被拒绝后被接受。新目标 `sys_icmp_error`（解析器，断言它的承诺），以 macOS 抓到的
  消息为种子。在 gpu51 上每个目标运行 5 分钟，五个并行（libFuzzer 加 ASan，按 cargo-fuzz 的方式构建）：
  `sys_icmp_error` 1.521 亿次、`turn_server` 294 万次、`turn_stream` 520 万次、`turn_tcp` 272 万次、
  `turn_dtls` 222 万次，没有发现问题。

### 未做

- 在 TTL 1 处丢弃数据报时不发送 ICMP 超时，内核拒绝的 DF 数据报也不发送“包过大”（13.2 节建议告知发送者，并从
  MTU 中减去 48 字节）：两者都被静默丢弃。前者需要原始 socket；后者意味着转告内核本地的 `EMSGSIZE` 错误。
- macOS 无法按数据报发送 IPv4 TTL：那里中继发出的 IPv4 数据报保持默认值。
- macOS 上 `[::]` 双栈 socket 只得知其 IPv6 数据报的 ICMP 错误。
- 端点自己 host 候选的 ICMP（其未连接的 socket，Linux 上的 `IP_RECVERR`）不交给 ICE：只有中继候选经 TURN
  服务器得到它。

## 更新 2（2026-11-23）：host 候选、“包过大”、“超时”

第一次更新留下三项：端点自己 host 候选的 ICMP、内核拒绝的 DF 数据报向客户端报告、在 TTL 1 处丢弃数据报时的
ICMP 超时。前两项已完成，第三项完成了无需特权的那个方向。

### 背景，更正

第一次更新的“未做”说 13.2 节建议告知被拒 DF 数据报的发送者，“并从 MTU 中减去 48 字节”。RFC 8656 的原意更精确：
13.2 节（IPv6 到 IPv6，没有分片头）丢弃大于出向链路 MTU 的数据报，并向入向数据包的发送者发送 ICMPv6
“包过大”；13.2 与 13.3 节只在该 ICMP 发往 **对端** 时把 MTU 减去 48 字节（为 Data indication 的开销留出空间：
对端的数据报包在 Data indication 里到达客户端）。发往客户端时，MTU 是到对端那一段的 MTU，那一段承载的是裸载荷；
18.13 节把 `ICMP` 属性的错误数据定义为“下一跳链路 MTU”。14 节（IPv4 到 IPv4）对放不下的 DF 数据报按 RFC 1122
处理，发送者由此收到带 MTU 的“需要分片”。

### 决策

**host 候选：在端点的 socket 上读取 ICMP。** `Endpoint::bind`、`bind_rtcp` 与 `bind_transport_socket` 改用
`Engine::bind_udp_icmp` 绑定（Linux 用 `IP_RECVERR`；macOS 用循环的 ICMP socket），像中继路径一样把每个错误交给
每个对端的各个 agent：`local` 是该 socket 绑定地址所代表的 host 候选（绑定未指定地址时即 `Endpoint` 通告的地址），
`remote` 是目的地址，去掉 scope，IPv4 映射地址还原为 IPv4。`IceAgent::handle_icmp_error` 其余不变：硬错误使从该
base 出发（host 与服务器反射候选共用它）且检查进行中的候选对失败；成功的候选对、软错误和未知地址都被忽略。不设开关：
开销就是 `bind_udp_icmp` 的开销（Linux 上每个错误读一次错误队列；macOS 上每个 UDP 循环的 ICMP socket，与该循环上的
TURN 中继等共用，收到主机的每个 ICMP 消息）。公共 API 不变：`Endpoint` 已说明 ICMP 是尽力而为。

**“包过大”：被拒的 DF 数据报报告给客户端。** `TurnServer` 以 DF 发往对端失败并得到 `EMSGSIZE`（内核知道更小的路径
MTU：Linux 检查路由的路径 MTU，macOS 检查接口的）时，客户端以 RFC 8656 Data indication 的形式收到路由器本会发给它的
消息：IPv4 中继上为 `ICMP` 类型 3 代码 4（“需要分片”），IPv6 中继上（15 节的流式客户端情形）为 ICMPv6 类型 2
代码 0，错误数据为路径 MTU，不减（见上），并带对端的地址和端口。

- MTU 来自新增的 `akio_sys::path_mtu(dest)`：一个连接到 `dest` 的 UDP socket，然后取 `IP_MTU` / `IPV6_MTU`
  （Linux：路由的 MTU，含路径 MTU 发现学到的值），macOS 上取持有该已连接 socket 本地地址的接口的 MTU
  （`SIOCGIFMTU`）。找不到 MTU，或数据报（含 IP 与 UDP 头）放得下时不报告：`EMSGSIZE` 也表示大于 socket 的发送
  缓冲区，macOS 上默认为 9216 字节（`net.inet.udp.maxdgram`），与 DF 无关。
- 每次报告三个系统调用和一个文件描述符，只在错误路径上：每个中继每 100 ms 最多报告一次。报告在分片对核心的调用返回后
  进行（不能在 `TurnEnv::send_to_peer_ip` 内部重入核心），经由已有的 `TurnCore::handle_icmp`，因此
  `relay_icmp(false)`、许可、对端策略和 `TurnStats::icmp` 与来自网络的 ICMP 一样适用。
- `TurnEnv` 与 `TurnCore` 不变：想要同样报告的自定义环境自己用这些类型调用 `handle_icmp`。
- 对端到客户端：服务器从不对发往客户端的数据设置 DF，那里不会被拒。

**“超时”：在带内告知客户端；不告知对端。** 客户端以 TTL 1 到达的数据报被丢弃（第一次更新）；现在客户端还会就它所发往的
对端收到一个带 `ICMP` 的 Data indication：IPv4 中继上为类型 11 代码 0（ICMPv4 传输中超时），IPv6 中继上为类型 3
代码 0（ICMPv6 超时）。这就是 13.2 节建议的路由器行为（“降到零时生成 ICMPv6 错误”），以 TURN 向客户端传递所有 ICMP
错误的方式送达，无需特权。由 `TurnCore` 完成（`relay_icmp`、许可与对端策略同任何 ICMP，计入 `TurnStats::icmp`），
每个分配每 100 ms 最多一次：持续发送 TTL 1 数据报的客户端每 100 ms 收到一个 indication，而不是每个数据报一个。

**拒绝：向对端发送超时。** 对端以 TTL 1 到达的数据报仍被静默丢弃。告知对端意味着从中继地址向它发送真正的 ICMP 消息（对端
不讲 TURN），并引用被丢弃数据报的 IP 头：这需要原始 socket（Linux 上 `CAP_NET_RAW`，macOS 上 root）。无特权的 ICMP
socket 帮不上忙：Linux 的 ping socket 与 macOS 的数据报 ICMP socket 都只能发送回显请求（实测：其他类型，包括超时和
目的不可达，都以 `EINVAL` 被拒）。为了回应只有环路或刻意构造的数据报才会碰到的 TTL，让 TURN 服务器获得它本不需要的
权限，得不偿失。

### 实测

- 互通（`tools/interop/webrtc/turn-ttl-df.sh`，gpu51，1500 字节网桥）：akio-turn 对 2000 字节的 DF Send indication
  回以带 MTU 1500 的 ICMP 3/4，对 TTL 1 的回以 ICMP 11/0，并中继随后的小 DF 数据报。coturn 4.6 两者都不发，随后的小
  DF 数据报也未中继。其余各行不变（akio-turn 39 / 49，coturn 39 / 64）。
- host 候选：对关闭端口的检查约 1 ms 使 ICE 失败，忽略 ICMP 时为 8.2 s（`tests/loopback.rs`，macOS）。
- 与 `main` `50a82315` 的同轮 A/B（gpu51，`quiet.sh` 下交替 8 轮；docs/BENCHMARKS.zh-CN.md）：数据通道 1.001
  （0.987–1.008）；中继合计每轮比值中位数 0.967（0.825–1.652）；12 轮纯中继复测为 1.048（0.833–1.262），到对端的比值中位数
  1.128，首轮为 0.829：没有可测出的变化，只是该基准各轮之间的噪声（单一构建到对端的速率就在 38k 到 110k 数据报/s 之间）。
- Fuzz（macOS，每个目标并行 5 分钟；没有解析器变化，因此没有新种子）：`turn_server` 82 万次、`turn_stream` 92 万次、
  `turn_tcp` 80 万次、`turn_dtls` 78 万次，没有发现问题；`turn_server` 的 TTL 选择字节现在也检查超时 indication。

### 测试

- akio-sys：两个地址族上回环地址的 `path_mtu`（Linux 65536 或调低后的 MTU；macOS 为 lo0 的 16384），连接失败时
  返回错误（macOS：未指定地址）。
- akio-turn 核心：客户端在 ChannelData 和 Send indication 上以 TTL 1 发送，针对该对端得到一个超时 indication
  （IPv4 11/0，IPv6 3/0）；无许可、`relay_icmp(false)` 或距上次不足 100 ms 时没有；对端的 TTL 1 仍然什么都不产生。
- akio-turn 真实 socket：带 `DONT-FRAGMENT`、比到对端的路径 MTU 大一字节的 Send indication（回环 MTU 被调低时，
  如带 `NET_ADMIN` 的 Linux Docker 运行；否则跳过，macOS 上也跳过：9216 字节的发送上限低于 lo0 的 16384）使客户端收到带该 MTU 的 ICMP 3/4，下一个放得下的
  照常中继；不带 `DONT-FRAGMENT` 的同样大小被中继（分片）。
- akio-webrtc（`tests/loopback.rs`）：唯一远端候选是关闭端口的端点在远少于一秒内 ICE 失败（报告为 `Disconnected`）：
  约 1 ms，host socket 收到端口不可达使检查失败；忽略 ICMP 时为 8.2 s（实测）。
- 互通：`tools/interop/webrtc/turn-ttl-df.sh` 针对 akio-turn 检查 2000 字节 DF 数据报使客户端收到带网桥 MTU 的
  ICMP 3/4，以及 TTL 1 的超时。
