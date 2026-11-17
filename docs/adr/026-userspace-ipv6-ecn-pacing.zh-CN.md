# ADR-026：用户态 TCP/IP 协议栈的 IPv6、ECN 与 pacing

[English](026-userspace-ipv6-ecn-pacing.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

only-dpdk 自带的协议栈（`crates/only-dpdk/src/net`）只支持 IPv4：IPv6 地址上的监听会被拒绝，
`dial` IPv6 地址返回 `Unsupported`。DEV-PLAN 把 “IPv6/NDP、offload、pacing/ECN” 列为未完成。
`DpdkConfig` 是 `#[non_exhaustive]`，且该 crate 属实验性（不在 semver 承诺内），但其 API 有快照，
因此新增字段在此记录。

## 决定

1. **栈有 IPv6 地址时启用 IPv6。** `DpdkConfig` 新增 `address6: Option<Ipv6Addr>`（默认
   `None`：仅 IPv4，行为不变）、`prefix_len6: u8`（64）和 `gateway6: Option<Ipv6Addr>`。设置
   `address6` 后，栈同时使用由 MAC 派生（修改版 EUI-64）的链路本地地址。地址为静态配置：没有
   SLAAC，忽略路由器通告（网关通过配置给出），与 IPv4 侧没有 DHCP 一致。
2. **监听为双栈。** 一个监听端口同时服务 IPv4 与 IPv6（端口本就按设备分配）。监听地址可以是
   `0.0.0.0`、IPv4 地址、`::`、`address6` 或链路本地地址；其他地址返回 `AddrNotAvailable`，栈未
   配置 `address6` 时的 IPv6 地址返回 `Unsupported`。绑定在 IPv6 地址上的监听，`local_addrs()`
   报告该 IPv6 地址。`dial` / `dial_udp` 接受两种地址族；scope id 被忽略（只有一个接口）。连接的
   `local_addr` 是实际使用的地址（对端为链路本地地址时用链路本地地址，否则用 `address6`）。
3. **IPv6 覆盖的范围。** 固定首部与扩展首部链（逐跳选项、目的选项及其动作位、拒绝仍有剩余段的
   路由首部，最多 8 个首部、每个最多 16 个选项），分片（仅源端）与重组（与 IPv4 重组器相同的
   上限：64 个数据报、1 MiB、30 s；重叠分片丢弃整个数据报，RFC 5722；原子分片不经重组，RFC 6946），
   ICMPv6（回显、端口不可达和参数问题，与 ICMPv4 共用限速额度，从不针对组播或未指定源地址发送；
   收到的不可达与 packet-too-big 会通知 UDP 和 TCP），路径 MTU 缓存（1024 个目的地址、10 分钟），
   NDP（RFC 4861：按 7.1 校验请求与通告；ARP 邻居缓存连同其待解析队列和 NUD 式刷新改为对地址族
   泛型）以及启动时和收到查询时发送的 MLDv2 报告，使开启 MLD snooping 的交换机转发被请求节点
   组播。出于同样原因，AF_PACKET 套接字在接口上加入 all-multicast；多队列端口上 ARP 与 NDP 帧会
   复制到每个队列。
4. **不做重复地址检测，但保护自己的地址。** 对运维手工分配的地址做 DAD 会让每次启动延迟一秒
   （相当于内核的 `nodad`）；栈会以发往所有节点的通告回应其他节点针对本栈地址的 DAD 探测，使新
   节点检测到冲突。
5. **ECN 与 pacing 需显式开启。** `DpdkConfig::tcp_ecn`（RFC 3168：ECN-setup SYN / SYN-ACK，仅新
   数据标记 ECT(0)，收到 CWR 前持续回显 ECE，每个往返最多降一次窗口且不重传；SYN cookie 建立的
   连接不使用 ECN）与 `DpdkConfig::tcp_pacing`（速率为 `cwnd / srtt`，慢启动乘 2，之后乘 1.2，
   由现有定时器堆中的每连接 pacing 定时器驱动，突发最多两个报文段或 100 µs）默认均为 `false`：
   两者都会改变线上行为并消耗 CPU，而我们无法测试的真实网卡路径上也未测得二者中性（手头没有
   支持 DPDK 的网卡）。仿真结果：在 20 帧的瓶颈队列上，ECN 用 10 次标记、零丢包取代了 29 次丢包
   和 27 次重传；pacing 让丢包减半（29 到 14），完成时间不变。
6. **不做校验和与分段 offload。** 手头可用的 PMD（`net_tap`、`net_af_packet`）在驱动内部用软件
   计算 offload 的校验和与 TSO，offload 只会转移开销而不会消除；mbuf 元数据路径（`ol_flags`、
   `l2_len` / `l3_len`、TSO 分段大小）也无法在硬件上验证。待有真实网卡时再议。

## 影响

- 新增公共 API：`DpdkConfig` 的五个字段（快照 `api/only-dpdk.txt`）。
- 连接表的键把两种地址族统一按 IPv4 映射的 IPv6 地址、以两个字哈希（比之前逐字节哈希
  `SocketAddrV4` 更便宜）；ISN 与 SYN cookie 对完整的 16 字节地址做哈希。
- 新增模糊测试目标 `dpdk_ipv6`、`dpdk_icmpv6`、`dpdk_ndp`；`dpdk_stack` 运行双栈协议栈。
- 未完成：SLAAC / 路由器通告、DAD、IPv6 巨型帧、MLDv1、RFC 8899 PLPMTUD、Accurate ECN
  （RFC 9768）与 L4S，以及校验和 / TSO / LRO offload。
