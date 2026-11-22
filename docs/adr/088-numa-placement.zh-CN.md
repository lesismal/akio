# ADR-088：引擎线程的 NUMA 放置，默认关闭

[English](088-numa-placement.md) | 简体中文

状态：已采纳（2026-11-23）

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
（`IORING_SETUP_SQ_AFF`）；没有在多节点机器上测量（手头没有：gpu51 只有一个节点），因此不对那里的收益下结论。

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
