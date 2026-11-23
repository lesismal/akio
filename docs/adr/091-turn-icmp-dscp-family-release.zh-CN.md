# ADR-091：TURN 转告 ICMP、经中继保留 DSCP、交还一个地址族

[English](091-turn-icmp-dscp-family-release.md) | 简体中文

状态：已接受（2026-11-23）

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
