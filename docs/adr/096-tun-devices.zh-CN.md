# ADR-096：在 I/O 线程上服务 TUN 设备，独立成 crate

[English](096-tun-devices.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

fit 的 VPN 路线（[fit 决策 026](https://github.com/lesismal/fit/blob/main/docs/decisions/026-vpn.zh-CN.md)，
fib 请求 A51）以及它的 Rust 对应项目 akit（akit 请求 A8）在每个节点上运行一个 TUN 接口：覆盖网络的每个 IP 包都从设备读出、
写入设备。TUN 设备的描述符既不是引擎 accept 的 socket，也不是它 dial 的 socket：Linux 上是 `/dev/net/tun`（字符设备），
macOS 上是 `PF_SYSTEM` 内核控制 socket（`utun`）。每次读返回一个包，每次写接受一个包，两者都可以非阻塞，因此设备适合放进
就绪轮询器。没有引擎支持时，应用只能在自己的线程上阻塞地 `read`，违反规则 1，并且每个包都要跨线程传递。fib 目前还没有
TUN 包；fit 的设计写明了所需的系统调用（`IFF_TUN | IFF_NO_PI`，带 4 字节地址族头的 utun），并希望描述符挂在轮询器上。

## 决策

1. **系统调用放在 `akio-sys`（`tun` 模块）**，这是唯一允许原始系统调用的 crate：`tun_open(name, multi_queue)`
   （`open("/dev/net/tun")`，以 `IFF_TUN | IFF_NO_PI` 调用 `TUNSETIFF`，多队列时加 `IFF_MULTI_QUEUE`，每个队列一个描述符；
   非阻塞、close-on-exec），`tun_is_multi_queue`（`TUNGETIFF`），`utun_open(unit)` / `utun_name`（macOS：对
   `com.apple.net.utun_control` 执行 `CTLIOCGINFO`，以 `sockaddr_ctl` `connect`，`UTUN_OPT_IFNAME`），`read_packet` /
   `write_packet`（每次调用一个包；macOS 上读时跳过地址族头，写时用两个 iovec 的 `writev` 把头放在前面，包本身从不复制），
   `tun_gone`（该错误表示设备已消失），以及 TUN 需要的接口设置，均为数据报 socket 上的 ioctl：`if_mtu` / `if_set_mtu`、
   `if_is_up` / `if_set_up`、`if_index`、`if_add_addr` / `if_del_addr`（Linux：一个 IPv4 地址用 `SIOCSIFADDR` 与
   `SIOCSIFNETMASK`，IPv6 地址经 `struct in6_ifreq`；macOS：`SIOCAIFADDR` / `SIOCAIFADDR_IN6`，点对点，目的地址即地址本身）。
   不用 netlink：ioctl 已覆盖名字、MTU、地址与标志；直连前缀之外的路由由应用设置（fit 用 rtnetlink 与路由 socket），以后可以
   再加。交给内核的每个结构都是与 C 布局大小、对齐一致的字节数组，编译期断言并在安全代码中填写；`unsafe` 只用于调用本身
   （docs/unsafe-review.md）。
2. **新建 crate `akio-tun`**（`#![forbid(unsafe_code)]`，依赖 `akio-core` 与 `akio-sys`），而不是放进 `akio-core` 或
   `akio`：TUN 与平台相关、需要特权，只有 VPN 一类的应用需要它；`akio-core` 保持为只有连接与 trait、不含设备代码的库，后端
   也不动。`akio` 通过 cargo feature `tun` 暴露它：`akio::tun` 与 `Engine::serve_tun`。这与 `akio-dpdk` 的做法一致，后者同样
   在 `ConnInner::new_virtual` 连接之上运行自己的循环。
3. **一个队列、一个 I/O 线程、一个连接。** `TunDevice::create(&TunConfig)` 打开接口及其所有队列，并设置 MTU、地址与 up 标志
   （控制面系统调用，应在控制线程或池中调用）。`TunServer::start(device, acceptor, cfg)`，或使用引擎的池、遥测与实时设置的
   `Engine::serve_tun(device, acceptor)`，给每个队列一个线程，线程有自己的 epoll / kqueue 轮询器和一个
   `ConnInner::new_virtual(datagram)` 连接，由 acceptor 的普通 `Handler` 服务：
   - **读**：就绪时最多读 64 个包到线程的 64 KiB 缓冲区，每个包以借用的 `&[u8]` 交给 `on_data`；之后写出回调排队的内容；
   - **写**：`Conn::send`（或 `TunWriter`：覆盖所有队列、可克隆的 `Send + Sync` 句柄，按包的地址哈希选队列，使同一流保持
     顺序）只排队，并在队列原本为空时唤醒线程；线程每次 `write` 一个包，直到队列为空或设备返回 `EAGAIN`（此后关注可写直到
     写完）。队列以 `Config::max_queued_bytes` 为上限（超出时 `send` 返回 `Overloaded`：包由调用方丢弃，IP 允许如此），
     队列清空时触发 `on_drain`，`hold_reads` 暂停设备的读（规则 7 与 8）；
   - **自身背压**：待写包队列达到 `write_high_watermark` 时暂停读，降到其四分之一时恢复，除非连接被标记为 relay；
   - **错误**：读错误，或被 `tun_gone` 识别的写错误（接口被删除后的 `EBADFD`），以该错误关闭连接；其他写错误丢弃该包
     （网络也会丢弃它承载不了的包）。读关闭时（被 hold 或背压），轮询器无法报告设备已被删除：设备的唤醒带的是
     `EPOLLIN`，在空的关注集合下被 epoll 过滤掉。此时循环每秒醒来一次，用零长度写探测：设备已删除时返回 `EBADFD`，
     设备存在时返回 `EINVAL`，不会取走任何包；
   - **关闭**：`on_shutdown`，停止读，在 `shutdown_timeout` 内写出队列，然后 `on_close(None)` 并关闭描述符；最后一个队列
     关闭时接口随之销毁。
   连接没有地址（`0.0.0.0:0`），在连接表与指标中显示为后端 `tun`，慢回调与其他连接一样上报。
4. **所有后端上都用就绪循环。** 运行在 io_uring 上的引擎依然用 epoll（macOS 上用 kqueue）服务 TUN 设备，正如它服务 UDP
   监听器一样（架构 §4.4）。TUN 不是 socket，io_uring 的 multishot 接收不适用；在 `IORING_OP_READ_MULTISHOT`（Linux 6.7）
   加 provided buffer 之前，每个包的读在两种方式下都是一次系统调用，而用它需要在 io_uring 循环里新增一种槽位。若 TUN 吞吐
   成为瓶颈，再用基准测试重新评估。
5. **在内核允许之处批量处理。** TUN 每次系统调用只收发一个包（`readv` 只是把一个包分散到多个缓冲区；字符设备没有
   `recvmmsg`）。批量之处：每次唤醒最多读 64 个包，之后统一写出它们的回复；唤醒等待期间其他线程送来的包在一轮中写出；
   用 `TunConfig::queues(n)`（`IFF_MULTI_QUEUE`）时内核把各流分散到 n 个并行服务的队列。**评估了 `IFF_VNET_HDR`，暂不采用**：
   配合 `TUNSETOFFLOAD`（TSO / USO），内核交出带 `virtio_net_hdr` 的 64 KiB GSO 超级包，并以同样方式接收，这正是
   wireguard-go 与 Tailscale 的 TUN 吞吐的主要来源。它改变了 handler 看到的内容（需要自行分段的超级包、部分校验和），因此
   将作为可选项（`TunConfig::offload`），交付分段后的包或带头的包；这是后续工作，实现时再测量。
6. **macOS**：一个队列（`queues(n > 1)` 返回 `Unsupported`），名字只能是 `utunN`，只有 root 可用。前缀的路由由应用设置
   （`route add -net ... -interface utunN`）。
7. **特权。** Linux 上创建设备需要 `CAP_NET_ADMIN`（打开先前用 `TUNSETOWNER` 建好的持久设备不需要，但设置仍需要），macOS
   上需要 root；没有时 `create` 返回系统的错误（`PermissionDenied`，或 `/dev/net/tun` 不存在时的 `NotFound`）。测试只检测
   一次，打印跳过的原因并通过；对本应有特权的运行，`AKIO_TEST_EXPECT_TUN=1` 把跳过视为失败：Linux Docker 使用
   `--privileged`（或 `--cap-add NET_ADMIN --device /dev/net/tun`）加 IPv6 sysctl，以及 x86_64 基准主机上以 root 原生运行。
8. **生命周期。** `TunServer` 拥有它的线程；drop 时关闭并 join 它们。`Engine::shutdown` 管不到它们，因为引擎的 group 在构建
   时就已固定；等 group 可以在运行时添加（ADR-094 的运行时监听器）之后，`serve_tun` 也可以把服务器登记到那里。

## 影响

- VPN 节点在 akio 线程上读写 TUN，使用与其 socket 相同的 `Handler`、`Conn`、背压、遥测与池；设备与 UDP 或 QUIC 连接之间的
  转发就是跨线程的 `Conn::send` 加 `hold_reads` / `on_drain`。
- `akio-core`、各后端与 `akio` 的监听器代码都没有改动；`akio` 只多了一行模块声明、一个再导出，以及独立文件中的
  `Engine::serve_tun`。
- 从其他线程写入的包要经过一次唤醒（排队、唤醒、由循环写出），而不是由发送方直接 `write`，与所有虚拟连接相同。在
  `akio-core` 中为包描述符新增一种 `Sock`，像 UDP 那样在 `send` 中直接写，可以去掉这一跳，代价是改动核心写路径（有 loom
  模型检查）；在基准测试表明这一跳确有影响之前不做。
- 这个循环并不特定于 TUN：任何具有包语义的非阻塞描述符都可以同样服务（fib 的 `AttachPacketFD`），需要时加一个从原始描述符
  构造的入口即可。

## 备选方案

- **把 TUN 队列放在引擎的 UDP 循环上**（`akio-epoll` 的 `UdpGroup`）：这些循环按地址管理 peer，带空闲淘汰与上限；设备是每个
  队列一个长期存在的连接，而且改动会深入一个正被其他工作修改的后端。每队列一个线程也契合多队列（每个线程一个队列）。
- **放进 `akio-core` / `akio`**：理由见第 2 条。
- **用 netlink 设置地址与路由**：代码更多（构造消息、解析 ack），却没有 ioctl 做不到的事；路由可以以后再加。
- **每个设备一个阻塞读线程**（wireguard-go 的做法）：违反规则 1，每个包都有一次线程切换。

## 验证

- `akio-sys` 单元测试（掩码、名字、`ifreq` 字段、接口不存在时的错误）。
- `crates/akio-tun/tests/device.rs`：无效配置（无需特权）；创建 / 配置 / 销毁（MTU，`getifaddrs` 列出的 IPv4 与 IPv6 地址，
  修改 MTU，删除与添加地址，down / up，最后一个队列关闭后接口消失）；在引擎上经设备收发 IPv4 与 IPv6 的 UDP
  （`Engine::serve_tun`，队列出现在引擎的连接表中）；经设备 ping（`ping -4` 与 `ping -6`，由 handler 写回 ICMP 与 ICMPv6
  echo reply）；四个线程经 `TunWriter` 写入 1000 个包，全部送达；队列上限（4096 以下接受 4 个 1000 字节的包，第五个
  `Overloaded`，循环写完后触发 `on_drain`，之后又能发送）；`hold_reads` 暂停与恢复设备的读；设备被删除（`ip link del`：
  `on_close` 带错误，之后 `send` 返回 `Closed`）；四队列设备把 64 个流分散到至少两个队列，每个队列各自回显。
- Linux arm64 Docker（特权，`AKIO_TEST_EXPECT_TUN=1`）：九个测试连续三次通过；无特权时九个都以跳过信息通过。基准主机上的
  x86_64（root，内核 7.0）：`AKIO_TEST_BACKEND` 为 epoll 与 uring 时各连续三次通过；正是在这个内核上，读被 hold 时删除
  设备的用例最初失败，随后加入了决策 3 中的探测。macOS：无特权的测试通过；utun 路径只做了编译检查（开发会话中没有 root）。
  整个 workspace 的测试：macOS、Linux arm64 Docker 的 epoll 与 io_uring、x86_64 原生的 epoll 与 io_uring；仅有的失败都在
  本次改动未触及的代码中，单独重跑即通过，或在基线提交上同样失败（见提交说明）。
- `examples/tun-bench.rs` 测量经设备回显的每秒包数（队列数、流数、负载大小）；这里尚未记录数字（基准主机繁忙）。
