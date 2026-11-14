# 内核旁路（DPDK）

> **实验性。** `Backend::Dpdk` 与 `flash::dpdk` 模块不在 semver 承诺范围内
> （[docs/api-stability.zh-CN.md](https://github.com/lesismal/flash/blob/main/docs/api-stability.zh-CN.md)），
> 可能在任何发布中变化。

`Backend::Dpdk` 让 listener 运行在**用户态 TCP/IP 协议栈**上，而不是内核协议栈：flash 的 I/O
线程直接轮询网络设备，用 [smoltcp](https://docs.rs/smoltcp) 处理 ARP、IPv4、UDP 和 TCP，再把数据
交给与其他后端相同的 `Handler`。UDP listener 依然每次 `on_data` 收到一个数据报，TCP listener 收到
字节流；`Conn::send`、背压、`dial`、`dial_udp`、空闲超时、遥测与优雅关闭照常工作，因此 `flash-kcp`
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
flash = { version = "1", features = ["dpdk"] }       # TAP、AF_PACKET、内存链路
# flash = { version = "1", features = ["dpdk-pmd"] } # 外加 DPDK 端口（链接 libdpdk）
```

`dpdk-pmd` 会针对已安装的 DPDK（`pkg-config --cflags --libs libdpdk`，DPDK 21.11 或更新）编译一个
很小的 C shim。没有 libdpdk 时 crate 仍能构建，`Device::Dpdk` 会在 `build` 时以 `Unsupported`
失败；设置 `FLASH_DPDK_REQUIRE=1` 可把缺少 libdpdk 变成构建错误。Debian/Ubuntu 上：
`apt-get install dpdk-dev libdpdk-dev pkg-config`。

## 服务端

```rust,ignore
{{#include ../../../crates/flash-dpdk/examples/guide-dpdk.rs:server}}
```

- `DpdkConfig::new(device, address)` 为协议栈指定 IPv4 地址；`prefix_len`（默认 24）和 `gateway`
  决定其余地址的路由。listener 地址必须是该地址或 `0.0.0.0`；端口 0 会自动选一个空闲端口。
- 配置中指向**同一设备**的所有 listener 共享一个协议栈：一个 IP 地址、一组 I/O 线程。每个
  listener 仍是独立的 group，有自己的 acceptor、配置、指标和关闭流程。`Listener::threads` 不适用：
  线程数由设备的队列数决定。

把内存链路换成 DPDK 端口：

```rust,ignore
{{#include ../../../crates/flash-dpdk/examples/guide-dpdk.rs:dpdk}}
```

EAL 每个进程只初始化一次，使用第一个 DPDK 协议栈的 `args`。在真实网卡上：预留大页
（`echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`），把网卡绑定到 `vfio-pci`
（`dpdk-devbind.py -b vfio-pci 0000:03:00.0`），然后传入例如 `["-l", "2-3", "-a", "0000:03:00.0"]`，
`port = "0"`、`queues = 2`。示例中的 `--no-huge --no-shconf --no-pci --vdev=net_tap0,...` 无需大页和
网卡即可运行。

## 客户端

```rust,ignore
{{#include ../../../crates/flash-dpdk/examples/guide-dpdk.rs:client}}
```

`Engine::dial` 运行在 engine 的最后一个 listener 上，`dial_udp` 运行在最后一个 UDP listener 上，
所以客户端 engine 需要在该设备上有一个 listener。拨号只支持单队列：多队列时回包落在哪个队列由网卡
的 RSS 决定，而不是发起拨号的线程。

## `DpdkConfig`

| 字段 | 默认值 | 含义 |
|---|---|---|
| `device` | （必填） | 链路层，见上文 |
| `address` | （必填） | 协议栈的 IPv4 地址 |
| `prefix_len` | 24 | 本地子网 |
| `gateway` | 无 | 子网之外地址的下一跳 |
| `mac` | 端口 MAC（DPDK）/ 由 `address` 派生 | 以太网地址 |
| `mtu` | 1500 | IP MTU；最大 UDP 数据报为 `mtu - 28`（不做 IP 分片） |
| `tcp_buffer` | 64 KiB | 每个 TCP 连接的收、发缓冲区（也限制窗口） |
| `udp_buffer` | 1 MiB | 每个 UDP socket 的收、发缓冲区 |
| `tcp_backlog` | 64 | 每个 TCP listener、每个队列可同时进行的握手数 |
| `busy_poll` | false | 从不休眠（DPDK 风格，每个队列占满一个核）；否则空闲时最多休眠 1 ms |

`EalConfig`：`args`（EAL 参数）、`port`（端口序号或设备名）、`queues`（rx/tx 队列对数 = I/O 线程数，
默认 1）、`descriptors`（每队列描述符数，默认 1024）、`mbufs`（内存池大小，默认 8191）。

## 工作原理

- **每个设备一个协议栈，每个队列一个线程。** 每个队列有自己的 smoltcp `Interface` 和 socket 集合，
  由一个 I/O 线程独占。每轮迭代：执行投递来的命令，轮询设备（一次 `rte_eth_rx_burst` 最多 32 帧，
  直接在 mbuf 中读取），交给 smoltcp 处理，把新数据交给 handler，把 handler 排队的数据搬进 smoltcp
  的 socket 缓冲区，再轮询一次以发送（帧直接构造在新分配的 mbuf 里），最后批量发送
  （`rte_eth_tx_burst`）。
- **多队列**：端口按 IP/UDP/TCP 四元组配置 RSS，同一条流始终落在同一个队列和线程上。ARP 帧会复制
  到所有队列，让每个协议栈都知道邻居。
- **连接**是没有内核 socket 的 flash 连接：`Conn::send`（可在任意线程调用）只入队并唤醒所属线程，
  由它在每次回调之后把字节搬进协议栈。handler 在 cork 状态下运行，一次回调发送的内容只进入协议栈
  一次。
- **线程**会注册到 EAL（`rte_thread_register`），以便使用内存池的 per-lcore 缓存。`busy_poll = false`
  时空闲线程最多休眠 1 ms（DPDK 与内存设备上，跨线程发送会提前唤醒它）。

为什么选 smoltcp：它是持续维护、内存安全的 Rust 协议栈，没有全局状态，每个队列一个实例正好契合
flash 的每核一线程模型，无需加锁。F-Stack（DPDK 上的 FreeBSD 协议栈）和 Seastar 的协议栈更快、更
完整，但会带来自带线程模型的 C/C++ 运行时，并在数据路径上引入大量 `unsafe` FFI。

## 当前限制

- 仅 IPv4（无 IPv6 / 邻居发现），不做 IP 分片，没有校验和或 TSO 卸载（校验和由软件计算）。
- smoltcp 的 TCP 没有 SACK，默认也没有拥塞控制；局域网内没问题，但未针对高丢包长距离链路调优。
  每轮有流量的迭代都会检查一遍 TCP 连接，开销与该线程上的连接数成线性关系。
- `Config::write_timeout` 和 `Accel` 不适用；`send_file` 经由内存读取；ICMP 错误不会报告给拨出的
  UDP 连接。
- 尚未在真实网卡上与 epoll/io_uring 做基准对比。

## 测试

`crates/flash-dpdk/tests/memory.rs` 可在任意平台运行：两个协议栈之间的 UDP 与 TCP echo、带流控的
大块 TCP 传输、有序关闭、协议栈之上的 KCP。`tools/dpdk/test.sh` 构建 `tools/dpdk/` 中的 Docker 镜像
（Debian 的 DPDK 24.11），并以 `--cap-add NET_ADMIN --device /dev/net/tun` 运行
`tests/kernel_peer.rs`：Linux 内核自己的 socket 通过 DPDK 的 `net_tap` PMD（单队列与双队列）以及
smoltcp 的 TAP 设备，以及 veth 对上的 AF_PACKET socket，与 flash 交换 UDP 数据报和 2 MiB 的 TCP
数据。CI 中的重型任务 `dpdk` 运行同样的
测试。
