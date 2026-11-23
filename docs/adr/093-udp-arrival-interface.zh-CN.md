# ADR-093：UDP 数据报的到达接口，按已绑定套接字选择开启；mDNS 据此确定查询所在链路

[English](093-udp-arrival-interface.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

ADR-078 更新 4 留下一项未做：引擎不告诉处理器一个数据报是从哪个接口到达的。akio-webrtc 的 mDNS 应答方只在
地址所在的链路上应答该地址的记录（RFC 6762 §6.2），因此必须知道查询来自哪条链路。没有到达接口时，它从源地址
推断（`Mdns::link_of_src`）：源地址的 scope id（IPv6 链路本地），否则是持有该地址的接口，再否则是子网包含它的
接口（最长前缀）。以下情况下这种推断是错的，或无从推断：

- **两个接口共享一个前缀**（同一局域网上的两块网卡、同一子网上的网桥与 veth、编号相同的两个 VLAN）：最长前缀
  匹配打成平手，由接口列表的顺序决定（最后一个胜出），于是来自另一条链路的查询被放到错误的链路上。真实链路上
  地址的记录随之被拒绝（"查询来自接口 N"），组播应答也从错误的链路发出。
- **源地址不在我方任何子网**（只有 169.254 地址的查询方、地址过期的主机）：更新 4 让每条记录只在它自己的链路
  上应答，只有查询方恰好在其中一条链路上时才收得到。

内核知道这个接口：`IP_PKTINFO`（Linux）/ `IP_RECVPKTINFO`（macOS）与 `IPV6_RECVPKTINFO`（两者皆有）会给
`recvmsg` / `recvmmsg` 返回的每个数据报附上一个 `in_pktinfo` / `in6_pktinfo` 控制消息，其中的 `ipi_ifindex` /
`ipi6_ifindex` 就是到达接口。引擎每次接收都已经在读控制消息（ECN 用的流量类别、GRO 段长、被请求时的 TTL），
所以问题在于 API，以及它让不请求的套接字付出什么。

引擎按后端接收 UDP 的方式：

- **epoll（Linux）** 与 **io_uring（Linux）**：两种后端上的 UDP 客户端线程以及 io_uring 后端的每个 UDP 监听器，
  都是 akio-epoll 的 `UdpLoop`（ADR-078 决定 2；io_uring 后端在自己的 ring 上只运行无连接的数据报端口，
  ADR-065）。该循环用 `recvmmsg` 读入 `akio_sys::RecvBatch`，后者给每个槽一块固定的控制消息缓冲（此前 96 字节）。
- **kqueue（macOS）**：同一个 `UdpLoop`，每次 `recvmsg` 读一个数据报（`akio_sys::recv_from_ip`，64 字节的控制
  消息缓冲）。
- **akio-dpdk**：自己的 UDP 栈，没有内核套接字。

因此在每个内核后端上，引擎的每个 `UdpBinding` 都由同一条接收路径服务。

## 决定

1. **公开 API（akio-core），均为新增。**
   - `UdpBinding::set_recv_interface(&self, on: bool) -> io::Result<()>`：请内核报告（或停止报告）该套接字收到的
     每个数据报的到达接口。Linux：`IP_PKTINFO` 与 `IPV6_RECVPKTINFO`；macOS：`IP_RECVPKTINFO` 与
     `IPV6_RECVPKTINFO`。IPv6 套接字两个都设（双栈套接字以映射地址收到 IPv4 数据报，经 IPv4 选项报告）；任一选项
     被接受即成功。其他平台返回 `ErrorKind::Unsupported`。调用时已在队列中的数据报不带接口。
   - `Conn::rx_interface(&self) -> u32`：在 `on_data`（或 `on_data_owned`）中，该数据报到达接口的索引（与
     `akio_sys::interfaces` 列出的一致，即 IPv6 链路本地地址所带的 scope id）；未请求、平台未报告（akio-dpdk、其他
     平台）或 TCP 时为 0。同一 peer 的数据报可能从不同接口到达；该值按数据报给出，与 `rx_tos` / `rx_ttl` 相同。
   - 按已绑定套接字选择开启，而不是 `Config` 开关：需要它的协议（mDNS，将来也许 DHCP 或 SSDP 应答方）拥有自己的
     套接字，其余每个套接字收到的内容与今天相同。
2. **akio-sys，均为新增。** `enable_recv_interface(fd, on) -> bool`（Linux 与 macOS）；
   `RecvInfo { tos, ttl, interface }`（`#[non_exhaustive]`，`Copy`）；Linux `RecvBatch::info(i) -> RecvInfo` 与
   `RecvBatch::interface(i)`（对一个数据报的控制消息遍历一次，即 `tos_ttl` 原先的遍历，现在也匹配 `IP_PKTINFO` /
   `IPV6_PKTINFO`；`tos_ttl` 保留并调用它）；macOS `recv_from_info(fd, buf) -> (长度, 发送方, RecvInfo)`
   （`recv_from_ip` 调用它）。每个槽的控制消息缓冲增大到 128 字节（Linux：GRO 24 + 流量类别 24 + TTL 24 +
   `in6_pktinfo` 40 = 112 字节；macOS：16 + 16 + 32 = 64，原先毫无余量）。更大的 `msg_controllen` 没有代价：内核
   只写它有的消息。
3. **接收循环（akio-epoll `UdpLoop`）** 把 `RecvInfo` 而不是 `(tos, ttl)` 交给连接，并把接口存在 TTL 旁边
   （`ConnInner::set_rx_interface`，一次 relaxed 存储，写入流量类别与 TTL 本已写入的缓存行），四条路径都如此：已绑定
   与监听套接字、拨出的套接字，Linux 与 macOS。未开启的套接字没有 pktinfo 消息：它的控制消息遍历与以前相同，只是
   每条消息多一次比较，存下的接口为 0。
4. **mDNS 使用它。** 两个 mDNS 套接字绑定后都调用 `set_recv_interface(true)`（被拒绝时记录日志，其余不变）。
   `on_query` 中，报告了到达接口时，查询的链路就是到达接口；只有未报告时（0：平台不支持，或数据报在选项设置之前
   已入队）才用推断（`link_of_src`，源地址未知时重读列表）。有两种情况即使报告了接口也仍用推断：回环源地址（本机
   自己的查询方，像以前一样在每条链路上应答），以及从回环接口到达的数据报（Linux 把本机发往自己某个地址的单播
   数据报经 `lo` 投递；其源地址仍指明链路）。不在接口列表中的索引会触发重读列表（至多每 5 秒一次），与未知源地址
   相同，因此之后才出现的接口会在应答发出前被加入组播组并为已知。到达接口从不是"未知"，所以更新 4 的"每条记录只在
   它自己的链路上应答"路径只在没有到达接口时才走。`usable_on` 的规则不变（另一个接口的子网包含该地址时仍可用：同一
   局域网上的两块网卡），现在作用于真实的到达接口。应答从查询进入的接口发回：组播应答与以前相同（IPv4：在该接口上
   加入了组时用 `send_to_on`；IPv6：scope id），现在单播应答也如此（QU 问题、传统单播查询方）：用
   `send_to_on(reply, src, f)` 代替 `send_to`，于是不在我方任何子网的查询方（169.254，路由表会让它从默认路由的接口
   发出）在自己的链路上收到应答。给出出接口时，Linux 把无路由的目的地址当作在链路上处理。

被否决的方案：

- **始终开启。** 每个套接字的每个数据报都多带 32–40 字节控制数据，循环也要白白解析它们；大多数协议（QUIC、RTP、
  TURN）从不需要。
- **整个引擎一个 `Config` 开关。** 太粗：在 QUIC 服务器旁边运行 mDNS 的进程，会在服务器的套接字上付出代价。
- **带接口的新处理器回调（`on_data_from`）。** 每个处理器都需要一个默认实现，循环也需要第二次分派；按数据报的连接
  字段对流量类别和 TTL 已经存在，不用时读取它没有代价。
- **为已绑定套接字使用 io_uring `RECVMSG`。** 它们不在 ring 上（见背景）；带提供缓冲的 multishot `recvmsg` 会带来
  自己的控制消息布局，这里没有收益。

未做：监听套接字（`Listener::udp`）没有开启方式（没有调用方；有需要时可以像 `enable_rx_ttl` 那样加一个隐藏的
`Conn` 级开关）。同一控制消息中的目的地址（组播还是单播、哪个本地地址）不报告。Linux 与 macOS 以外的平台仍用推断。

## 影响

- 新的公开 API：`UdpBinding::set_recv_interface`、`Conn::rx_interface`（akio-core，由 `akio` 重新导出）；
  `akio_sys::{enable_recv_interface, RecvInfo}`、`RecvBatch::info` / `RecvBatch::interface`（Linux）、
  `recv_from_info`（macOS）。现有签名均不变。
- 未开启的套接字：系统调用相同，控制消息相同；每个接收槽的控制消息缓冲大 32（Linux）或 64（macOS）字节；下面的
  A/B 测不出退化。
- mDNS 对来自与另一接口共享前缀的链路的查询，在正确的链路上应答；对来自不在我方任何子网的源地址的查询，在它到来
  的链路上以组播应答。

## 验证

- akio-sys `arrival_interface`（Linux `RecvBatch`、macOS `recv_from_info`）：请求前为 0；之后对 IPv4、IPv6 以及
  双栈套接字上的 IPv4 数据报为回环接口的索引，与流量类别、TTL 及（Linux）GRO 同在一个槽中；关闭后又为 0。macOS
  `control_parsing_is_bounded`：包信息过短、越界、IPv4 与 IPv6 布局。
- akio `tests/udp.rs` `bound_socket_reports_the_arrival_interface_once_asked`（回环上的单播，两个地址族，开与关）与
  `tests/shared_ports.rs` `ipv4_group_reports_the_interface_each_datagram_arrived_on`（在两个接口上加入的组，从每个
  接口发出的数据报都报告为从该接口到达；macOS lo0 + en1，Linux a0 + b0）。
- akio-webrtc `tests/mdns.rs` `ipv4_queries_are_placed_on_the_interface_they_arrived_on`：源地址属于一个接口、却从
  另一个接口发出的查询，在它到达的接口上得到应答，而不是在其源地址指向的接口上。仅 Linux：macOS 拒绝从一个接口的
  地址经另一个接口发送（`EADDRNOTAVAIL`），该测试跳过。
- `tools/interop/webrtc/mdns4.sh` 第 7 步：d0（`10.66.4.1/24`）与 e0（`10.66.4.2/24`）共享前缀，各是一对通往一个
  网络命名空间的 veth，命名空间里各有一个查询方（`10.66.4.11`、`10.66.4.12`）；每个查询方查询隐藏其所在链路地址的
  名字，都从该地址得到应答。trace 显示每个查询都被放在它到达的接口上。第 1–6 步与 `mdns6.sh` 仍全部通过；两个脚本
  均在 Linux 6.12（Docker Desktop，aarch64）上用 epoll 与 `AKIO_TEST_BACKEND=uring` 运行。
- 对照（同一脚本，`on_query` 忽略到达接口）：第 7 步失败，两个查询方都得不到应答（平局让两个查询都落在同一个接口
  上，而且 d0 / e0 出现在 mDNS 套接字启动之后，推断出的链路也未加入组：应答从默认接口发出）；上面的 mDNS 测试
  失败。那次对照运行中还有一个 `shared_ports` 测试失败了一次，原因未查明；在相同容器环境、真实分支上对两种后端再跑
  50 次 `shared_ports`，没有失败。
- macOS：`cargo test --workspace`（负载下有两个无关失败，`happy_eyeballs` 与 akio-h3 `features`，单独运行三次均
  通过），clippy `-D warnings`。gpu51 原生（rustc 1.100）：akio-sys、akio-core、akio-epoll、akio 与 akio-webrtc 的
  `cargo test --release`，epoll 与 `AKIO_TEST_BACKEND=uring`（88 / 88 个测试目标通过），clippy
  `--workspace --all-targets -D warnings`。
- 代价（gpu51，同轮 A/B，BENCHMARKS"已绑定 UDP 套接字的接收，到达接口"）：未开启的饱和已绑定套接字的接收速率为
  main 的 0.999（10 轮，0.993–1.006）；开启约多花 0.6%（每个数据报约 5 ns）。
- API 快照（`tools/api/public-api.sh`）：只有新增。
