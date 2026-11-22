# ADR-027：XDP 限速、线程绑核、eBPF 哈希层与内核拼接的 SOCKS 隧道

[English](027-ebpf-xdp-pinning-socks-splice.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

ADR-006 规划了 eBPF 的三种用途。M5 交付了 `SO_REUSEPORT` 分流与 sockmap relay，但留下五个缺口：

- XDP 限速；
- I/O 线程绑核：没有它，`Steering::Cpu` 选中线程 `cpu % n`，却没有任何机制让该线程留在该 CPU 上；
- 把 relay 接入 akio-socks；
- 哈希分流的 eBPF 层；
- 基准测试。

补齐过程中又发现两个问题：

- 经典 BPF 哈希层返回的是 socket 在 reuseport 组中的**位置**，依赖 socket 按线程顺序加入；有 socket 离开时，位置会整体偏移。
- 挂上 psock 后，拼接**之前**已到达的数据会停在接收队列里，直到有新数据到来才被处理（verdict 由 `data_ready` 触发），并且 `SIOCINQ` 不再统计这些数据。先发问候语的服务器因此会卡住。

## 决定

1. **`akio_ebpf::xdp`**（新模块）：
   - 接口：`RateLimiter::attach(interface, &XdpLimit)` / `attach_index`、`mode()`、`attachment()`、`stats() -> XdpStats { passed, dropped, new_sources }`、`forget(IpAddr)`、`detach()`；drop 即卸载。
   - 配置：`XdpLimit { rate, burst, max_sources, count: Count::{TcpSyn, AllPackets}, mode: XdpMode::{Auto, Native, Generic} }`（`#[non_exhaustive]`）。默认值遵循 ADR-009：每源 100 包/秒、突发 200、16384 个源、只计 SYN、自动模式。另有 `Attachment::{Link, Netlink}`。
   - 程序与其余程序一样手工汇编。每个源（IPv4 映射为 IPv6）一个令牌桶，以纳秒额度存在 `LRU_PERCPU_HASH` 中。桶按 CPU 存放，包路径上没有原子操作，限额也按接收 CPU 计。计数器存放在 `PERCPU_ARRAY` 中。
   - 挂载优先用 BPF link（5.9+），进程退出时由内核卸载；回退到 netlink `IFLA_XDP`，卸载时只替换我们自己的程序（expected fd）。先尝试 native 模式，再回退 generic。他人已挂载的程序永不替换（`EBUSY`/`EEXIST`）。
2. **绑核**：`EbpfConfig::pin_threads`（默认关）把 n 个线程中的线程 `i` 绑到允许 CPU 中满足 `c % n == i` 的那些；没有这样 CPU 的线程不绑。
   - 公开接口：`akio_ebpf::cpu_pinning(threads)`、`SteerInfo::pinned_threads`、`akio_sys::process::{allowed_cpus, pin_current_thread}`。
   - 后端新增隐藏的 `Group::pin_threads` 钩子（`doc(hidden)`，不进快照）。
3. **eBPF 哈希层**：在 `AttachOptions::ebpf`（默认开启）且有特权时，`Steering::Hash` 使用一个 `SK_REUSEPORT` 程序：
   - 计算与经典层相同的哈希，因此 `expected_index` 仍然成立；
   - 槽表放在 `ARRAY` map 中，负责把哈希映射到线程；
   - 线程的 socket 从 `REUSEPORT_SOCKARRAY` 取出，所以无论加入顺序如何，线程 `i` 都拥有 `fds[i]`。

   `Tier::Ebpf` 现在覆盖两种策略。
4. **Relay**：
   - `Relay::splice` 插入两个 socket 期间先调高它们的 `SO_RCVLOWAT`，插入后再设回 1，于是按顺序对期间到达的数据运行 verdict。这样消除了卡住的问题，也消除了“只插入一半”的窗口（那段时间到达的数据会进入只有用户态才读取的 psock 队列）。
   - 新增 `Relay::splice_inner(&ConnInner, &ConnInner)` 与 `splice_inner_with(.., f)`。`f` 在两个 socket 都进入 map、但尚未转发任何字节时运行（SOCKS 应答在此写出）；`f` 失败时撤销拼接，不丢数据。
   - 新增 `relay::byte_counts(&TcpStream) -> ByteCounts { received, written }`（`TCP_INFO` 加 `SIOCOUTQ`），用于跟踪已拼接的隧道。
5. **akio-socks**：
   - `ProxyConfig::sockmap: Option<Relay>` 与 `Socks::sockmap(relay)`（需显式开启，默认 `None`）：在写出成功应答时拼接 SOCKS 与 HTTP `CONNECT` 隧道。
   - 以下情况回退到用户态转发：TLS、客户端数据已在用户态缓冲、拼接出错。
   - 空闲超时按 `byte_counts` 判断。一端关闭时，要等所有已转发的数据都进入另一端的发送队列后才关闭另一端，因为关闭 socket 会丢掉内核中的转发积压。
   - 若两端都开着时用户态仍读到已拼接隧道的负载（在拼接前已完成的 io_uring 读），则关闭隧道，避免乱序。
   - `spliced_tunnels()`（隐藏）统计拼接次数。

## 影响

- 全部可选、可降级：无特权或老内核时使用经典 BPF、不启用 XDP、在用户态转发。
- XDP 限额按源**且按接收 CPU** 计。伪造源地址的洪泛挡不住（这种情况仍靠 SYN cookies），带 VLAN 标签的帧不计数。
- 拼接后的字节绕过引擎的写水位。relay 默认仍要求 Linux 6.15+（见 ADR-006 附注）。
- 新增的 `unsafe` 只在 `akio-sys`（`sched_getaffinity`/`sched_setaffinity`）与 `akio-ebpf` 的 `sys`（`BPF_LINK_CREATE`、map lookup、netlink socket 读写、`TCP_INFO`、`SIOCOUTQ`、`SO_RCVLOWAT`）中，每处都有安全注释。
