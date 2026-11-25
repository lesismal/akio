# ADR-088：引擎线程的 NUMA 放置，默认关闭

[English](088-numa-placement.md) | 简体中文

状态：已采纳（2026-11-23）。背景中提到的 akio-prefork 已由 [ADR-121](121-akio-prefork-removed.zh-CN.md)
（2026-11-25）删除。

## 背景

在有多个 NUMA 节点的机器上（双路服务器、NPS2/NPS4 模式的 EPYC），内存与 PCIe 设备各属于一个节点；其他节点上的
线程要经过互连访问它们，延迟约为本地的 1.5–2 倍。引擎已经把大部分状态放在每个 I/O 线程里：连接终生属于一个线程，
缓冲区来自线程自己首次触碰的每线程池，定时器也是每线程的。但引擎没有让线程留在一个节点上：调度器可以迁移它，也没有
任何机制把它放到网卡附近。线程绑核只存在于 eBPF CPU 分流（`EbpfConfig::pin_threads`，线程 `i` 运行在 `c % n == i`
的 CPU 上，不考虑节点）和 `akio-prefork`（`CpuPinning`）中。DPDK 的 mempool 已经分配在端口所在的 socket 上。

## 决策

1. **akio-sys `numa`**：`nodes()` 读取 `/sys/devices/system/node/node<N>/cpulist`（不支持 NUMA 的内核读作一个
   包含所有在线 CPU 的节点），`interface_node(name)` 读取 `/sys/class/net/<name>/device/numa_node`（`-1` 为
   `None`），以及 `parse_cpulist`、`set_incoming_cpu` / `incoming_cpu`（`SO_INCOMING_CPU`）。仅 Linux；其他平台返回
   `Unsupported`。接口名在拼入路径前先检查（不含 `/`、不是点名、至多 15 字节）。
2. **akio `numa` 模块，`EngineBuilder::numa(NumaConfig)`**，默认关闭。`NumaPlacement`：`Off`、`Spread`（每组的
   线程 `i` 放在节点 `i % n`）、`Nodes(ids)`（只用这些节点，轮转）、`Interface(name)`（该接口的节点）。节点限制在
   进程可用的 CPU 内（`sched_getaffinity`，因此 `taskset` 与 cgroup 仍然生效）；没有可用 CPU 的节点被去掉。
   `NumaConfig` 字段：`per_cpu`（每个线程一个 CPU，在其节点内轮转，而不是整个节点）、`incoming_cpu`（在每个线程的
   监听套接字上设置 `SO_INCOMING_CPU`：其集合中的第一个 CPU）、`pool`（把逻辑池的线程限制在所选节点上，默认 true）、
   `strict`（构建失败而不是降级）。
3. **放置通过已有的 `Group::pin_threads` 完成**：epoll、io_uring 与 UDP 组在每个循环线程启动时绑核，热路径没有变化。
   CPU 集合按可用 CPU 数量计算，因此之后由 `set_threads` 增加的线程也会被放置。eBPF CPU 分流已绑核的组
   （`AccelStatus::Steering` 且 `pinned_threads > 0`）与 DPDK 组保持不变：分流需要自己的绑核，DPDK 自己放置
   lcore。逻辑池获得一个隐藏的 `PoolConfig::on_start` 钩子，在每个工作线程启动时绑核（除非应用自己设置了钩子）。
4. **`AKIO_NUMA`** 在构建器未被告知时提供配置：`spread`、`nodes:0,1`、`iface:eth0`、`off`，可加 `+cpu`、
   `+incoming`、`+nopool`、`+strict`（`NumaConfig::from_env`），因此不改程序也能放置并做基准测试。
5. **`Engine::numa_status()`**：`Off`、`Placed(NumaReport)`（节点；每组每个线程的节点、CPU 与
   `SO_INCOMING_CPU`；池的 CPU）或 `Degraded(原因)`（非 Linux、拓扑不可读、未知节点、接口没有节点；同时记录警告）。

内存不需要单独的策略：内核默认的（本地）策略在首次触碰页面的线程所在节点上分配，而每线程池由其线程触碰。

## 后果

- 只有新增 API：`akio::{NumaConfig, NumaPlacement, NumaStatus, NumaReport, ThreadPlacement}`、
  `EngineBuilder::numa`、`Engine::numa_status`、`akio_sys::numa`。`PoolConfig::on_start` 与 `ThreadHook` 为
  `#[doc(hidden)]`。
- 放置关闭（默认）时，构建路径只多读一次 `AKIO_NUMA`；I/O 路径不变。
- `incoming_cpu` 只在处理数据包的 CPU 正是某个套接字所指定的 CPU 时生效：回环流量由客户端的 CPU 处理，因此在单机上
  没有变化；它需要网卡的中断（RSS / RPS）落在服务器的 CPU 上。

未做：io_uring 的 ring 仍在循环启动前由辅助线程创建（其内存跟随该线程而非节点），SQPOLL 内核线程不放置
（`IORING_SETUP_SQ_AFF`）（两者已完成，见下文的更新）；没有在多节点机器上测量（手头没有：gpu51 只有一个节点），因此不对那里的收益下结论。

## 验证

- akio-sys：CPU 列表解析，从伪造的 sysfs 树读取节点与接口节点（包括没有节点目录、列表格式错误、被拒绝的名字），
  在 Linux 上读取真实拓扑并往返 `SO_INCOMING_CPU`。
- akio：放置算法（分散、每 CPU、可用 CPU 限制、未知节点、接口节点）、`AKIO_NUMA` 解析；Linux 上的
  `tests/numa.rs`，epoll 与 io_uring，在 gpu51 上各运行三次：每个 `akio-io-*` 线程的 `Cpus_allowed_list` 等于报告
  给出的 CPU 集合（先整个节点，再每线程一个 CPU），每个监听套接字都设置了 `SO_INCOMING_CPU`，`spawn_blocking` 任务
  运行在池的 CPU 上，流量正常，无法完成的放置会降级（strict 时失败）；默认关闭。macOS 上放置降级（strict 时为
  `Unsupported`）。akio-pool：启动钩子在每个工作线程上运行一次。
- gpu51 上的同轮 A/B（`tools/bench/numa.sh`，`quiet.sh` 下 5 轮交替，服务器在 CPU 0-3 上 4 个线程，单节点），
  相对放置关闭的中位数：HTTP/1.1 plaintext 1.000x（spread）、0.996x（spread+cpu）、1.001x（+incoming）；流水线
  0.998x / 0.997x / 0.997x；h2c 0.995x / 1.000x / 1.005x；TCP echo 64 B 1.026x / 1.006x / 0.982x（该用例各轮间
  波动 2–8%）。在单节点上放置既无帮助也无损害；见 BENCHMARKS。

## 更新（2026-11-23）：io_uring 的 ring 建在循环所在的节点上，SQPOLL 线程得到放置

本次完成"未做"中的前两项。

**为什么 ring 在临时线程上创建。** `io_uring_setup` 以及启用 ring 会把调用线程挂到该 ring 上；ring 销毁时，内核会给
每个挂上的线程发送类似信号的 task_work，这会打断无法重启的阻塞调用（带 `SO_RCVTIMEO` 的读返回 `EINTR`），而这可能
发生在该线程构建引擎很久之后。因此 ring 从不在调用者线程上创建，而是在一个短命的 `akio-uring-setup` 线程上创建。
快速配置是 single-issuer 加 deferred task-run 和 `IORING_SETUP_R_DISABLED`：ring 属于启用它的线程，循环线程在
第一次提交前启用它（`IORING_REGISTER_ENABLE_RINGS`）。这些都保持不变。

**为什么不直接在循环线程上创建。** 一个 group 的循环（包括 ring）在构造 group 时就已建好，这样 setup 失败（内核、
内存限制）是构建错误；CPU 集合随后才通过 `Group::pin_threads` 到达，在 `start` 之前。在循环线程上创建 ring 会把
setup 错误推迟到 `start`，并需要与每个新线程握手。

**决策。**

1. 当 `Group::pin_threads` 给 io_uring group 提供 CPU 集合时（NUMA 放置，或 eBPF CPU steering 的 `pin_threads`），
   每个已构建但尚未启动的循环会得到一个新 ring：它在一个先把自己绑定到该循环 CPU 集合的临时线程上创建，内核就在
   执行 setup 的 CPU 所在节点上分配 SQ/CQ ring 和 SQE 数组。循环构建时的旧 ring 被丢弃（没有人用过它：启用它和注册
   buffer ring 都只在循环线程上发生）。尽力而为：新 ring 创建失败时循环保留旧 ring。之后由 `set_threads` 增加的
   循环直接在自己的集合上创建 ring。
2. 启用 `UringConfig::sqpoll` 时，ring 带 `IORING_SETUP_SQ_AFF` 创建，`sq_thread_cpu` 是循环集合中的一个 CPU：
   第一个使用该集合的循环取第一个 CPU，下一个使用同一集合的循环取下一个 CPU，依此类推（若用整节点集合，同一节点上
   的循环否则会把轮询线程都堆到该节点的第一个 CPU 上）。使用 `per_cpu` 时就是循环自己的 CPU，轮询线程与循环线程共用
   它。内核拒绝该 CPU 时（离线、不在任务的 cpuset 内），ring 不带 `SQ_AFF` 创建。
3. `ThreadPlacement::sq_thread_cpu`（新增字段，该结构体为 `#[non_exhaustive]`）报告每个循环的轮询线程绑定到的
   CPU；后端通过 `#[doc(hidden)]` 的 `Group` trait 新增的默认方法 `sq_thread_cpus` 报告它。

provided buffer 的内存无需处理：分配时未被触碰，首次写入来自内核的接收和 buffer ring 的设置，两者都在（已绑定的）
循环线程上。

放置关闭时没有任何变化：不调用 `pin_threads`，ring 的创建方式与之前完全相同（未绑定的临时线程、相同的 setup
标志）。放置开启时，每个循环的 ring 在构建时创建两次（每个循环几次系统调用加一次线程创建），从不在 I/O 路径上。

**验证。** akio-uring：SQ CPU 的选择（共享与不同的集合、回绕、无集合）；在 gpu51 上，带 SQ CPU 创建的 ring 多出
一个 `iou-sqp-*` 线程，其 `Cpus_allowed_list` 恰好是该 CPU；不存在的 CPU 回退为未绑定的轮询线程；未放置的 SQPOLL
ring 和已放置的非 SQPOLL ring 与之前一样创建。`tests/numa.rs` 在 `AKIO_TEST_BACKEND=uring` 下：未放置、整节点和
每线程一个 CPU 的 SQPOLL 引擎，`iou-sqp-*` 线程的 CPU 等于报告的 `sq_thread_cpu`（循环 CPU 之一；`per_cpu` 时为
循环自己的 CPU；同一节点上的两个循环取不同 CPU），I/O 线程的放置与不用 SQPOLL 时相同，流量正常。gpu51 上与 main
的同轮 A/B：`tools/bench/numa.sh`，`KIND=akio-uring`，模式为关闭与 `spread+cpu`，`quiet.sh` 下 5 轮交替（服务器在 CPU 0-3，
4 个线程），分支 / main 的中位数：放置关闭时 HTTP/1.1 plaintext 0.999x、流水线 0.997x、h2c 0.992x、TCP echo 1.035x；
`spread+cpu` 为 1.000x、0.997x、0.994x、0.966x。放置关闭时两个构建运行相同的代码，因此该列就是噪声底线（TCP echo 各轮
间波动高达 20%）；`spread+cpu` 落在其中（见基准报告）。带放置的 SQPOLL 只做了测试，没有基准测量（基准服务器没有它的
开关）。

仍未做：在多节点机器上测量（gpu51 只有一个节点，ring 内存所在的节点在那里不可能不同；本次只证明没有退化，不证明
收益）。
