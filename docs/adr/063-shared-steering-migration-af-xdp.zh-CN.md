# ADR-063：经 bpffs 的跨进程分流、重载时的 listener 迁移与 AF_XDP

[English](063-shared-steering-migration-af-xdp.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

ADR-006 与 ADR-027 在 eBPF 与 prefork 方面留下四个缺口：

- **跨进程分流。** `attach_reuseport` 给每个进程各自的 `SK_REUSEPORT` 程序与 socket 数组。prefork
  的多个 worker 共用一个 `SO_REUSEPORT` 组时，每个挂载的 worker 都会把组的程序换成只认识自己 socket
  的那一个，于是所有新连接都去了最后挂载的 worker。only-prefork 只能给出警告。
- **`ListenMode::ReusePort` 下的重载。** 旧 worker 的监听 socket 关闭时，内核会重置其 accept 队列中的
  连接以及仍挂在它上面的半连接。`net.ipv4.tcp_migrate_req=1`（Linux 5.14+）会把它们改为迁移到随机一个
  存活的 listener，但这是全机设置，默认关闭。
- **AF_XDP。** ROADMAP §2.5 把它列为 DPDK 之外更轻的内核旁路，一直没有实现。
- **本地 VM 测试。** eBPF 测试只在特权 Docker 与共享的 x86 主机上运行。

## 决定

### 1. 固定（pin）在 bpffs 中的共享分流（`only_ebpf::SharedSteering`）

- `SharedSteering::create(dir, sockets, steering)` 为有 `sockets` 个槽位的组加载一个 `SK_REUSEPORT`
  程序，同时创建一个 `REUSEPORT_SOCKARRAY`、Maglev 槽位表（`ARRAY`，哈希分流使用）和一个 `meta`
  数组（存放版本、槽位数、策略和迁移标志）。四者都固定在 `dir` 中：`prog`、`socks`、`slots`、
  `meta`。`meta` 最后固定，因此 `meta` 存在的组一定是完整的。
- 策略与 `attach_reuseport` 在 `sockets` 个线程上的策略相同。`Steering::Cpu` 选择槽位
  `cpu % sockets`。`Steering::Hash` 使用同样的哈希和同样的 Maglev 表，因此
  `expected_index(steering, sockets, peer, local)` 给出的就是槽位。
- `SharedSteering::open(dir)` 在另一个进程中打开这些 pin。打开 map 时会核对大小：
  `Map::open_pinned` 读取 `BPF_OBJ_GET_INFO_BY_FD`，类型、键大小或值大小与类型化的 `Map<K, V>`
  不符就拒绝，以此保证类型化方法的可靠性（soundness）。
- `at(first, count)` 选定一段槽位。`join(fds)` 把本进程的 socket 写进自己的槽位，清空本段其余的槽位，
  并把固定的程序挂到组上。每个进程挂的都是同一个程序，因此重复挂载没有任何变化。重启的进程直接覆盖自己
  的槽位，关闭的 socket 会自动离开数组。
- `create` 返回的句柄拥有这些 pin，最后一个克隆被 drop 时删除它们；`open` 返回的句柄不拥有。
- 门面：新增字段 `EbpfConfig::shared: Option<SharedSteering>`。设置后，listener 加入共享程序而不挂
  自己的程序。失败时与其他分流失败一样降级（`AccelStatus::Degraded`），设置了 `strict` 时 `build`
  失败。`SteerInfo` 新增 `shared` 与 `migrate`。开启 `pin_threads` 时，位于槽位 `first + t` 的线程
  `t` 被绑到该槽位的 CPU 上（`c % sockets == first + t`）。
- **only-prefork**：`Prefork::bpf_steering(BpfSteering { steering, threads, dir, strict })` 用于
  Linux 上的 `ListenMode::ReusePort`。
  - supervisor 在 `dir`（默认 `/sys/fs/bpf/only-prefork`）下为每个监听地址创建一组，命名为
    `<ip>_<port>`，其中的 `.` 换成 `-`，因为 bpffs 不允许名字中有点号。每组有 `workers * threads`
    个槽位。
  - pin 目录经 `ONLY_PREFORK_BPF` 传给 worker。worker `i` 的 `listener(n)` 返回一个带 `threads` 个
    I/O 线程、加入槽位 `i * threads..(i + 1) * threads` 的 `Accel::Ebpf` 的 listener。
  - supervisor 停止时（`wait` 或 drop）删除这些 pin。被 SIGKILL 杀掉的 supervisor 会留下它们，同一
    地址上的下一个 supervisor 会替换掉。
  - `Supervisor::bpf_steering(i)` 返回句柄。原来关于每个 worker 各自分流的警告，现在只针对挂载自己
    程序的 engine。
- **降级。** 没有特权、没有 bpffs，或目录名带点号时，supervisor 记录一条警告，启动 worker 时不设置
  该变量，worker 于是使用内核的 `SO_REUSEPORT` 哈希，与本 ADR 之前一样。设置了 `strict` 则 spawn
  失败。打不开 pin 的 worker 记录警告，不带 `Accel` 继续服务。

### 2. 重载时迁移（`BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`）

- 共享程序以 `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` 挂载类型加载（Linux 5.14+）；较老的内核得到普通
  的 `SELECT` 程序，`SharedSteering::migrates()` 报告加载的是哪一种。
- 有了这种挂载类型，即使 `tcp_migrate_req` 为 0，内核也会迁移关闭中的 listener 上排队的一切：
  listener 关闭时迁移 accept 队列，半连接则在其最后一个 ACK 或数据到达时迁移。此时程序运行时
  `migrating_sk` 已设置。程序新增了一段前缀，读取 `sk_reuseport_md.migrating_sk`；它非空时，程序选择
  `sockarray[hash % sockets]`，即该流所在槽位当前的 socket。槽位为空时返回不做选择的 `SK_PASS`，由
  内核随机挑一个存活的 listener。
- **重载顺序。** 重载产生的新 worker `i` 在其 engine 构建时（报告就绪之前）就加入自己的槽位。从那时起，
  这些槽位的新连接都交给它，旧 worker 的 socket 不再被选中。supervisor 在新 worker 就绪之后才停止旧
  worker。旧 listener 关闭时，排队的连接与半连接迁移到同一槽位上的新 socket，没有任何连接被重置。
- **降级。**
  - 5.14 之前的内核或没有共享分流时，排队的连接只在 `net.ipv4.tcp_migrate_req=1` 时迁移（迁到随机
    一个存活的 listener），否则被重置。
  - supervisor 会检查该 sysctl 与程序，在第一次不会迁移的 `ReusePort` 重载时记录一条警告，并指向
    `Prefork::bpf_steering` 与 `ListenMode::Inherit`。我们从不修改这个 sysctl：它是全机设置。
  - `ListenMode::Inherit` 不需要迁移：监听 socket 一直在 supervisor 中保持打开。

### 3. AF_XDP 作为用户态协议栈的一种链路

- **位置。** AF_XDP 是现有协议栈的一种链路类型，与 TAP、AF_PACKET 并列：
  `only_dpdk::Device::AfXdp(AfXdpConfig)`，而不是新的 `Backend`。`Backend::Dpdk(DpdkConfig)` 的含义
  本来就是“跑在某种链路上的 only 用户态 TCP/IP 协议栈”，该后端的每个 listener、拨号、指标与测试在新
  链路上都无需改动即可工作。单独的 `Backend::AfXdp` 只会重复这套配置而没有收益，因此没有添加。只需
  `only` 的 `dpdk` cargo feature，不需要 `dpdk-pmd` 与 libdpdk。
- **配置。** `AfXdpConfig { interface, queues, mode: XdpMode, zero_copy: ZeroCopy, frames }`
  （`#[non_exhaustive]`，`AfXdpConfig::new(interface)`）。
  - 默认值：一个队列；`XdpMode::Auto`（从 `only_ebpf::xdp` 重新导出）；`ZeroCopy::Auto`（另有
    `Required`、`Off`）；每队列 4096 个 4 KiB 的块。
  - 协议栈的默认 MAC 是从 sysfs 读到的接口自己的地址，因此物理网卡不需要混杂模式；`DpdkConfig::mac`
    可以覆盖它。
- **数据路径**（`only_ebpf::xsk`，`#[doc(hidden)]`，不稳定；unsafe 代码在这里）：
  - 每个队列 `0..queues` 一个 socket，各有自己的 UMEM：一块匿名映射，只在 socket 关闭之后才解除映射。
  - 填充、完成、RX、TX 四个环，各 `min(2048, frames / 2)` 项。一半的块起初放在填充环中，另一半组成
    TX 池。
  - 收到的帧拷贝一次到协议栈的缓冲区，其块随即回到填充环，因此没有任何指向 UMEM 的引用活过一次调用。
    发送的帧像 DPDK mbuf 一样就地写入一个 TX 块并提交到 TX 环。拷贝模式下，或 TX 环要求唤醒时，
    `flush` 用 `sendmsg` 通知内核。完成的块回到池中。
  - socket 以 `XDP_USE_NEED_WAKEUP` 绑定，先尝试零拷贝模式。驱动在该队列上拒绝零拷贝时，换一个新
    socket 以拷贝模式绑定。
  - 重定向程序与其他程序一样手工汇编：`bpf_redirect_map(xskmap, rx_queue_index, XDP_PASS)`。它把每个
    配置的队列送到对应的 socket，其他队列的帧交给内核。挂载复用限速器的代码（重构为 `xdp::ProgLink`）：
    先 BPF link 后 netlink，先 native 后 generic，从不替换他人已挂的程序。最后一个 socket 关闭或进程
    退出时卸载程序。
  - 与 AF_PACKET 一样，接收时不校验校验和：veth 对端或本机内核发送时启用了校验和卸载。
  - 空闲时 I/O 线程在该 socket 上 `ppoll` 睡眠，与 TAP、AF_PACKET 相同；`busy_poll` 照常生效。
- **限制。**
  - 一帧放在一个块中：最大 3840 字节，因此 MTU 最大 3826。需要 Linux 5.4 或更高版本。程序需要
    `CAP_NET_ADMIN`、`CAP_NET_RAW` 与 `CAP_BPF`。
  - 配置的队列归协议栈独占：内核不再看到这些队列的流量。
  - 在 veth 上以 native 模式运行时，内核会自动关闭对端的 GSO。generic 模式下程序在 GRO 之后才看到
    帧，因此对端不能发送 GSO 聚合包，GRO 也必须关闭（测试使用 `ethtool -K ... tso off gso off gro off`）。
  - 拷贝模式的发送不经过接口的 qdisc，因此在协议栈一侧加 `tc netem` 不起作用。
  - 多队列时由网卡的 RSS 分散流量；拨号的连接沿用现有规则：端口号决定队列。
- `only_ebpf::Probe` 新增 `reuseport_migrate` 与 `af_xdp`。隐藏的 `only_dpdk::af_xdp_info(interface)`
  报告 native 还是 generic 模式、是否零拷贝以及队列数，供测试与基准测试使用。

### 4. 本地 VM 测试

macOS 开发机上没有 lima、vfkit 或 QEMU，也不为此安装新工具，因此不添加 VM 脚本。特权测试在特权 Docker
（`tools/dpdk/test.sh` 与 eBPF 的 Docker 任务）和共享的 x86 主机（`gpu51`，Linux 7.0）上运行，只使用
veth 对与网络命名空间，从不碰真实网卡。非特权的降级路径通过在不带 capability 的情况下运行同一批测试
来验证。

## 后果

- 一切仍然可选，并降级到原来的行为。
- 在 Linux 5.14+ 上，使用 `bpf_steering` 的 prefork `ReusePort` 部署重载时不会重置连接，分流策略也覆盖
  所有 worker。代价是 supervisor 与 worker 需要特权，且 supervisor 运行期间 bpffs 中有 pin。
- 对带分流（包括共享分流）的 listener，`Engine::set_threads` 仍返回 `Unsupported`：每个 worker 的槽位
  范围由 `BpfSteering::threads` 固定。
- 新增的 `unsafe` 代码只在 `only-ebpf` 中：`sys`（`OBJ_PIN`、`OBJ_GET`、`OBJ_GET_INFO_BY_FD`、
  `[u32; N]` 值的查询）与新的 `xsk` 模块。每个块都有 `SAFETY:` 注释，并已列入 docs/unsafe-review。
- API：只有新增（`SharedSteering`、`MAX_SHARED_SOCKETS`、`SteerInfo::{shared, migrate}`、
  `Probe::{reuseport_migrate, af_xdp}`、`EbpfConfig::shared`、`BpfSteering`、`DEFAULT_BPF_DIR`、
  `Prefork::bpf_steering`、`Supervisor::bpf_steering`、`Device::AfXdp`、`AfXdpConfig`、`ZeroCopy`、
  重新导出的 `XdpMode`）。`xsk` 模块与 `af_xdp_info` 是隐藏的。

## 验证

以下结果来自 `gpu51`（Linux 7.0，Ryzen 7 7800X3D），以 root 运行，`ONLY_TEST_EXPECT_EBPF=1`：

- `only-ebpf/tests/shared.rs`：
  - 两个“进程”的槽位跟随其所有者，其中一个被替换后依然如此。
  - 所有者 drop 后 pin 消失，已挂载的程序继续分流。
  - 关闭中的 listener 的 accept 队列（32 个连接）迁移到槽位上的新 socket，`TCPMigrateReqSuccess`
    计入了这些迁移。
  - 被 `TCP_DEFER_ACCEPT` 暂留的半连接在数据到达时迁移，因此迁移分支是在真实数据包上运行的。
  - 对照：没有程序且 sysctl 关闭时，同样的 accept 队列被重置。
- `only-prefork/tests/bpf.rs`，三个 worker，各两个线程：
  - 作答的 worker 正是 `expected_index` 指定的那个，杀掉并重启一个 worker 之后依然如此。
  - 在 8 个客户端线程不断建连的情况下连续重载三次，CPU 与哈希分流各测一遍：没有任何一次交互失败，
    各 worker 的 accept 计数之和恰好等于客户端成功的交互数。
  - 这些重载没有迁移任何连接（`TCPMigrateReqSuccess` 不变）：新 worker 在旧 worker 停止之前就接管了槽位，
    因此旧 listener 关闭时是空的。迁移由另一个场景覆盖：在持续建连下用 SIGSTOP 停住一个 worker，再将其杀死。
    它排队的连接（每次 7–9 个）全部迁移，没有交互失败；对照组没有程序时丢失 8–12 个。最多可能失败一次交互：
    该 worker 停止时已 accept 但尚未作答的那个连接。
  - epoll 与 io_uring 上结果相同。
  - 不在 bpffs 上的目录会降级到内核哈希，`strict` 时 spawn 失败。
- `only-dpdk/tests/kernel_peer.rs`，veth 对上的 `af_xdp_*`：
  - native/auto、generic/拷贝与 IPv6：UDP 回显、ECN、分片、2 MiB 的 TCP 回显、拨号以及到内核的 ICMP。
  - 两个队列，200 个并发连接。
  - 在 veth 上 `ZeroCopy::Required` 干净地失败。
- 无特权时的降级：同一批测试二进制在 `setpriv --inh-caps=-all --bounding-set=-all`（不带任何
  capability 的 root）下运行。only-ebpf 与 only-dpdk 的测试跳过，prefork 测试检查 worker 使用内核哈希
  照常服务；设置 `ONLY_TEST_EXPECT_EBPF=1` 时它们全部失败。

基准测试（`quiet.sh` 下同一轮 A/B，`tools/bench/afxdp.sh`，同一 veth 对，AF_XDP 为 native 拷贝模式）：与
AF_PACKET 相比，AF_XDP 的 UDP 请求/应答速率为 1.68 倍，TCP 请求/应答速率为 1.58 倍，TCP 建连速率为 1.24 倍，
单连接 TCP 回显吞吐为 2.97 倍（每个方向 814.7 对 274.6 MB/s）。详见 docs/BENCHMARKS.zh-CN.md（“用户态协议栈上的
AF_XDP 与 AF_PACKET”）。
