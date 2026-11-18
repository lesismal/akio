# 内核旁路（DPDK）

> **实验性。** `Backend::Dpdk` 与 `only::dpdk` 模块不在 semver 承诺范围内
> （[docs/api-stability.zh-CN.md](https://github.com/lesismal/only/blob/main/docs/api-stability.zh-CN.md)），
> 可能在任何发布中变化。

`Backend::Dpdk` 让 listener 运行在**用户态 TCP/IP 协议栈**上，而不是内核协议栈：only 的 I/O
线程直接轮询网络设备，运行 only 自研的 TCP/IP 协议栈（以太网、ARP、IPv4、ICMP、带 NDP 与 ICMPv6 的
IPv6、UDP、TCP；安全
Rust，`#![forbid(unsafe_code)]`，无依赖），再把数据交给与其他后端相同的 `Handler`。UDP listener 依然每次 `on_data` 收到一个数据报，TCP listener 收到
字节流；`Conn::send`、背压、`dial`、`dial_udp`、空闲超时、遥测与优雅关闭照常工作，因此 `only-kcp`
等协议 crate 无需修改即可运行。

协议栈之下的设备可以是：

| `Device` | 需要 | 用途 |
|---|---|---|
| `Dpdk(EalConfig)` | Linux、feature `dpdk-pmd`、libdpdk（通过 `pkg-config` 查找） | 生产：绑定到 DPDK 的网卡（vfio-pci），或 DPDK 虚拟设备（`net_tap`、`net_af_packet`、`net_ring` 等） |
| `Tap(name)` | Linux、`CAP_NET_ADMIN`、`/dev/net/tun` | 开发与测试：TAP 另一侧的内核就是对端 |
| `AfPacket(ifname)` | Linux、`CAP_NET_RAW` | 把协议栈放在内核不使用的现有接口上（veth 的一端、闲置网卡） |
| `Memory(MemoryPort)` | 无 | 同一进程内的两个协议栈（`MemoryWire::new()`），任意平台：测试与示例 |

## 启用

```toml
[dependencies]
only = { version = "1", features = ["dpdk"] }       # TAP、AF_PACKET、内存链路
# only = { version = "1", features = ["dpdk-pmd"] } # 外加 DPDK 端口（链接 libdpdk）
```

`dpdk-pmd` 会针对已安装的 DPDK（`pkg-config --cflags --libs libdpdk`，DPDK 21.11 或更新）编译一个
很小的 C shim。没有 libdpdk 时 crate 仍能构建，`Device::Dpdk` 会在 `build` 时以 `Unsupported`
失败；设置 `ONLY_DPDK_REQUIRE=1` 可把缺少 libdpdk 变成构建错误。Debian/Ubuntu 上：
`apt-get install dpdk-dev libdpdk-dev pkg-config`。

## 服务端

```rust,ignore
{{#include ../../../crates/only-dpdk/examples/guide-dpdk.rs:server}}
```

- `DpdkConfig::new(device, address)` 为协议栈指定 IPv4 地址；`prefix_len`（默认 24）和 `gateway`
  决定其余地址的路由。listener 地址必须是该地址或 `0.0.0.0`；端口 0 会自动选一个空闲端口。
- 配置中指向**同一设备**的所有 listener 共享一个协议栈：一个 IP 地址、一组 I/O 线程。每个
  listener 仍是独立的 group，有自己的 acceptor、配置、指标和关闭流程。`Listener::threads` 不适用：
  线程数由设备的队列数决定。

把内存链路换成 DPDK 端口：

```rust,ignore
{{#include ../../../crates/only-dpdk/examples/guide-dpdk.rs:dpdk}}
```

EAL 每个进程只初始化一次，使用第一个 DPDK 协议栈的 `args`。在真实网卡上：预留大页
（`echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`），把网卡绑定到 `vfio-pci`
（`dpdk-devbind.py -b vfio-pci 0000:03:00.0`），然后传入例如 `["-l", "2-3", "-a", "0000:03:00.0"]`，
`port = "0"`、`queues = 2`。示例中的 `--no-huge --no-shconf --no-pci --vdev=net_tap0,...` 无需大页和
网卡即可运行。

## 客户端

```rust,ignore
{{#include ../../../crates/only-dpdk/examples/guide-dpdk.rs:client}}
```

`Engine::dial` 运行在 engine 的最后一个 listener 上，`dial_udp` 运行在最后一个 UDP listener 上，
所以客户端 engine 需要在该设备上有一个 listener。拨号分散到各个队列；每个队列选用满足
`port % queues == queue` 的本地端口，被网卡 RSS 放到其他队列上的回包会转交给发起拨号的队列。
对端以 ICMP“端口不可达”回应的已拨出 UDP 连接会以 `ConnectionRefused` 关闭，与内核后端一致。

## `DpdkConfig`

| 字段 | 默认值 | 含义 |
|---|---|---|
| `device` | （必填） | 链路层，见上文 |
| `address` | （必填） | 协议栈的 IPv4 地址 |
| `prefix_len` | 24 | 本地子网 |
| `gateway` | 无 | 子网之外地址的下一跳 |
| `address6` | 无 | 协议栈的 IPv6 地址；设置后启用 IPv6（外加由 MAC 派生的链路本地地址） |
| `prefix_len6` | 64 | IPv6 子网（子网内与链路本地目的地址视为在链路上） |
| `gateway6` | 无 | IPv6 默认路由器（通常是其链路本地地址） |
| `mac` | 端口 MAC（DPDK）/ 由 `address` 派生 | 以太网地址 |
| `mtu` | 1500 | IP MTU（TCP MSS = `mtu - 40`，IPv6 上为 `mtu - 60`）；更大的 UDP 数据报会分片发送，收到的分片会重组 |
| `tcp_buffer` | 64 KiB | 每个 TCP 连接的收、发缓冲区（限制窗口；超过 64 KiB 时使用窗口缩放） |
| `udp_buffer` | 1 MiB | 每个 UDP 端口在 I/O 线程交付前可排队的数据报字节数 |
| `tcp_backlog` | 64 | 每个 TCP listener、每个队列可同时进行的握手数 |
| `syn_cookies` | true | backlog 满后用无状态 SYN cookie 应答 SYN |
| `congestion` | `Congestion::Cubic` | TCP 拥塞控制：CUBIC（RFC 9438）或 NewReno |
| `tcp_ecn` | false | 协商 ECN（RFC 3168）：数据以 ECN-capable 发送，CE 标记按丢包处理但不重传 |
| `tcp_pacing` | false | 以 `cwnd / srtt`（慢启动时 2 倍，之后 1.2 倍）的速率平滑发送，而不是整窗突发 |
| `tcp_keepalive` | 无 | 开始发送 TCP keepalive 探测前的空闲时间（9 次探测，间隔 `min(keepalive, 75 s)`） |
| `busy_poll` | false | 从不休眠（DPDK 风格，每个队列占满一个核）；否则空闲时最多休眠 1 ms |

`EalConfig`：`args`（EAL 参数）、`port`（端口序号或设备名）、`queues`（rx/tx 队列对数 = I/O 线程数，
默认 1）、`descriptors`（每队列描述符数，默认 1024）、`mbufs`（内存池大小，默认 8191）。

### IPv6

```rust,ignore
let mut cfg = DpdkConfig::new(Device::Tap("ftap0".into()), "10.0.0.2".parse()?);
cfg.address6 = Some("fd00::2".parse()?);
cfg.gateway6 = Some("fe80::1".parse()?); // 仅用于链路之外的对端
// 一个 listener 在其端口上同时服务两种地址族。
let listener = Listener::tcp("[::]:8080".parse()?).backend(Backend::Dpdk(cfg)).serve(acceptor);
```

设置 `address6` 后 listener 为双栈：端口同时接受 IPv4 与 IPv6 连接（listener 地址可以是 `0.0.0.0`、
IPv4 地址、`::`、`address6` 或链路本地地址）。`dial` 与 `dial_udp` 接受两种地址族；连到链路本地对端时
连接使用链路本地地址，否则使用 `address6`。地址为静态配置：没有 SLAAC，忽略路由器通告，协议栈不做
重复地址检测（但会回应其他节点针对本栈地址的探测，让对方发现冲突）。在开启 MLD snooping 的交换机上，
协议栈发送的 MLDv2 报告保证邻居请求能够送达。

## 工作原理

- **每个设备一个协议栈，每个队列一个线程。** 每个队列有自己的协议栈实例（ARP 缓存、连接表、
  定时器堆），由一个 I/O 线程独占。每轮迭代：执行投递来的命令，把一批收到的帧交给协议栈
  （`rte_eth_rx_burst`，直接在 mbuf 中读取），处理协议栈报告的事件（新接受与新建立的连接、可读数据、
  释放的发送空间、关闭、数据报），把 handler 排队的数据搬进协议栈的发送缓冲区，让协议栈发送（到期的
  定时器、数据，每批只发一个 ACK 而不是每段一个；帧直接构造在新分配的 mbuf 里），最后批量发送
  （`rte_eth_tx_burst`）。
- **没有每轮全量扫描。** 工作来自事件和每个连接一项（惰性重新调度）的定时器堆，空闲连接每轮迭代
  不产生开销。
- **多队列**：端口按 IP/UDP/TCP 四元组配置 RSS，同一条流始终落在同一个队列和线程上。ARP 与 NDP 帧
  会复制到所有队列，让每个协议栈都知道邻居；落到其他队列上的拨出连接的帧会被转交。
- **连接**是没有内核 socket 的 only 连接：`Conn::send`（可在任意线程调用）只入队并唤醒所属线程，
  由它在每次回调之后把字节搬进协议栈。handler 在 cork 状态下运行，一次回调发送的内容只进入协议栈
  一次。
- **线程**会注册到 EAL（`rte_thread_register`），以便使用内存池的 per-lcore 缓存。`busy_poll = false`
  时空闲线程最多休眠 1 ms（DPDK 与内存设备上，跨线程发送会提前唤醒它）。

## TCP/IP 协议栈

`crates/only-dpdk/src/net/`（取代 smoltcp，见 DEV-PLAN“长期：去除第三方依赖”）：

- **以太网 II、ARP**（RFC 826）：邻居缓存，60 s 可达超时并单播刷新；等待解析的报文会排队，发往新
  邻居的第一个 SYN 或数据报在应答到达后立即发出（smoltcp 版本会丢弃它，导致每条新连接都要等 1 s 的
  SYN 重传）。
- **IPv4**：首部校验和，大数据报分片，带上限的重组（64 个数据报、1 MiB、30 s），网关路由。
- **ICMP**：回显应答；对关闭的端口回应端口/协议不可达（限速）；收到的不可达会结束已拨出的 UDP 连接
  和握手，“需要分片”会降低 MSS。
- **IPv6**（RFC 8200）：带上限地遍历扩展首部（最多 8 个首部、每个最多 16 个选项；未知选项按动作位
  处理，拒绝仍有剩余段的路由首部，二者都回应参数问题），源端分片，在 IPv4 的上限内重组（重叠分片
  丢弃整个数据报，RFC 5722；原子分片不经重组），由 packet-too-big 维护的路径 MTU 缓存（1024 个
  目的地址、10 分钟、不低于 1280）。
- **ICMPv6**（RFC 4443）：回显（包括发往所有节点组播地址的），端口不可达与参数问题（限速，从不针对
  组播或未指定源地址发送）；收到的差错报文与 IPv4 中的处理相同。
- **NDP**（RFC 4861）：按 7.1 节校验邻居请求与通告（跳数限制 255、选项长度、DAD 形式），ARP 邻居
  缓存改为泛型（同样的待解析队列和单播请求刷新），回应针对本栈地址的 DAD 探测，启动时与收到查询时
  发送 MLDv2 报告（RFC 3810）。
- **TCP**（RFC 9293）：完整状态机，含同时打开与同时关闭、TIME-WAIT（可被新 SYN 或新拨号复用）、
  RST 规则与 RFC 5961 挑战 ACK；RTT 估计与 RTO（RFC 6298，下限 200 ms，指数退避）；SACK
  （RFC 2018）记分板与 RFC 6675 风格的丢包恢复，无 SACK 时使用 NewReno 快速恢复（RFC 6582）；
  CUBIC（RFC 9438）或 NewReno；窗口缩放与时间戳及 PAWS（RFC 7323）；MSS 选项；延迟 ACK（40 ms、
  每两个段、连接开始时快速 ACK）；关闭 Nagle；零窗口探测；keepalive；监听 backlog 与 SYN cookie
  （窗口缩放与 SACK 编码在时间戳中）；可选的 ECN（RFC 3168：只给新数据标记 ECT(0)，收到 CWR 前
  持续回显 ECE，每个往返最多降一次窗口）与 pacing（定时器堆中的每连接定时器，突发最多两个报文段或
  100 µs）。UDP 数据报双向携带 ECN 码点（与内核套接字一样经 `Conn::send_segments_ecn` /
  `Conn::rx_ecn`），因此 QUIC 在该协议栈上可通过 ECN 校验（ADR-035）。
- 校验和由软件计算（无卸载）；收到的校验和都会校验，AF_PACKET 除外（来自本机内核的帧携带的是部分
  校验和）。

为什么自研：每个队列一个实例、没有全局状态，契合 only 的每核一线程模型，无需加锁；整个协议栈都是
安全 Rust；数据路径需要的东西（按批合并 ACK、事件驱动的连接、定时器堆）无需给依赖打补丁就能做到。
F-Stack（DPDK 上的 FreeBSD 协议栈）和 Seastar 的协议栈更快、更完整，但会带来自带线程模型的 C/C++
运行时，并在数据路径上引入大量 `unsafe` FFI。

## 当前限制

- 没有校验和、TSO 或 LRO 卸载：手头可用的 PMD（`net_tap`、`net_af_packet`）在驱动内部用软件完成，
  卸载所需的元数据也无法在硬件上验证。
- IPv6 不支持 SLAAC、路由器通告、DAD、巨型帧和 MLDv1；没有 Accurate ECN / L4S；没有 TCP Fast Open；
  除 ICMP“需要分片” / packet too big 外不做路径 MTU 探测。
- ECN 与 pacing 默认关闭：在模拟的 20 帧瓶颈队列上，ECN 把 29 次丢包变成 10 次标记，pacing 让丢包
  减半，但二者都还没有在真实网卡上测量过。
- 空闲超时每 50 ms 扫描一次（不是每轮迭代）。
- `Config::write_timeout` 和 `Accel` 不适用；`send_file` 经由内存读取。
- 尚未在真实网卡上与 epoll/io_uring 做基准对比；在内存链路上与原 smoltcp 版本的 A/B 对比见
  docs/BENCHMARKS.zh-CN.md。

## 测试

单元测试用构造的帧覆盖每一层（校验和、选项、ARP 排队、重组上限、RTO、NewReno 与 CUBIC），
`src/net/sim.rs` 在虚拟时间里让两个协议栈通过模拟链路通信（时延、限速的尾丢弃队列、随机丢包、乱序）：
大块传输、长肥管道上的窗口缩放、SACK 在一个往返内修复突发丢包、无 SACK 的 NewReno、双向 10% 丢包、
RTO、零窗口、keepalive、各种关闭、SYN cookie、2000 条连接、300 条连接经由 cookie 与丢包做 echo；
IPv6 方面：邻居发现期间排队的首个 SYN、双向有损乱序链路、链路本地与双栈 listener、分片（重叠、原子
分片）、ping 与 DAD 保护、扩展首部与参数问题、packet-too-big；ECN 协商、以 CE 标记代替丢包、浅队列
下的 pacing。`tests/memory.rs` 可在任意平台运行：两个协议栈之间的 UDP 与 TCP echo（IPv4 与 IPv6，含
ECN 与 pacing）、带流控的大块 TCP 传输、有序关闭、协议栈之上的 KCP。`tools/dpdk/test.sh` 构建 `tools/dpdk/` 中的 Docker 镜像（Debian 的 DPDK 24.11），
以 `--cap-add NET_ADMIN --device /dev/net/tun` 运行 `tests/kernel_peer.rs`，以 Linux 内核自己的 socket
为对端：通过 DPDK 的 `net_tap` PMD（单队列与双队列）、TAP 设备和 veth 对上的 AF_PACKET 做 UDP（含分片
数据报）与 TCP echo，从协议栈向内核拨号（每个队列上的 TCP、UDP、ICMP 端口不可达），ping，`tc netem`
丢包/时延/乱序（内核的 SACK 计数器必须变化），20 ms RTT 下的 4 MiB 窗口，以及 500 条并发连接；
同样的测试也在 IPv6 上运行（`ping -6`、含分片的 UDP、双向 TCP、开启 ECN 与 pacing 的 `netem` 丢包、
双队列 DPDK `net_tap`）。模糊测试目标 `dpdk_ethernet`、`dpdk_arp`、`dpdk_ipv4`、`dpdk_ipv6`、
`dpdk_icmpv6`、`dpdk_ndp`、`dpdk_tcp`、`dpdk_udp`、`dpdk_icmp` 与 `dpdk_stack`（向整个双栈协议栈输入
帧）位于 `fuzz/`，其语料在 `cargo test` 中回放。CI 中的重型任务 `dpdk`
运行 `tools/dpdk/test.sh`。
