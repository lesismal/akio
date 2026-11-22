# ADR-028：读缓冲区、backlog、UDP 空闲超时与 I/O 线程数的热更新

[English](028-hot-reload-buffers-backlog-threads.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

`Engine::reload` / `Live`（M6）可以在不重启的情况下修改空闲超时、慢回调设置、队列上限、高水位、
连接数上限、关闭超时和日志级别。读缓冲区、listen backlog、UDP 空闲超时和 I/O 线程数在构建时固定，
并在 `ReloadReport::ignored` 中报告。修改它们需要重启，或者在 akio-prefork 下做一次代际替换；而在
Linux `SO_REUSEPORT` 上，除非设置了 `net.ipv4.tcp_migrate_req`，代际替换会重置旧 worker 套接字上
排队的连接。

约束：ADR-001（连接在整个生命周期内属于一个 I/O 线程；handler 状态不加锁、不要求 `Sync`）、
ADR-002（锁只保护发送队列，从不在用户代码期间持有）、docs/rules.md（绝不阻塞 I/O 线程；不在每个
事件上取全局锁），并且稳态热路径不能改变。

## 决定

### 设置（`Config` / `Live`）

- **`read_buffer`** 可热更新。每个 I/O 线程在处理重载通知时（两批事件之间）替换读缓冲区：此时没有
  `on_data` 借用它，所以这正是该线程上每个连接的下一个空闲点，已打开的连接从下一次读开始使用新大小。
  epoll/kqueue：重新分配 scratch 缓冲区。UDP：重建接收批；开启 GRO 的套接字（构建时决定）保持至少
  64 KiB 的槽。io_uring：provided-buffer ring 与内核共享，所以线程注册一个新大小的第二个缓冲区组
  （组号在 0/1 之间交替，完成事件的操作码说明缓冲区来自哪个组），取消挂在旧组上的 multishot 接收，
  在每个取消完成时把接收重新挂到新组上，没有接收再使用旧组后注销并释放它；再次修改要等到那时。
- **`backlog`** 可热更新：每个 I/O 线程对它持有的监听套接字重新调用 `listen(2)`
  （`akio_sys::set_backlog`）；Linux 和 macOS 会就地更新活套接字的队列上限。在线程之间转交的
  套接字（见下）和新套接字采用当前值。
- **`udp_idle_timeout`** 可热更新；UDP 线程按 `min(udp_idle_timeout, idle_timeout)`（两者现在都是
  实时值；以前由初始的 `idle_timeout` 作为上限）重新设置每个对端的定时器。
- **`retire_timeout: Option<Duration>`**（新增，默认 `None`，可热更新）：见缩容。
- `ReloadReport::ignored` 现在列出真正固定的设置：`max_pending_responses`、`write_timeout`、
  `connect_timeout`、`udp_max_peers`、`udp_gro`。

### 线程数：`Engine::threads()` 与 `Engine::set_threads(index, n)`

按组（TCP listener 或 client 组，按 `local_addrs` 顺序），支持 epoll、kqueue 和 io_uring。组维护一个
活跃 loop 的**名册**（`RwLock<Vec<..>>`，只在控制路径上读：dial 和监听套接字转交，从不按事件读），
并为每个 loop 编号保存一个槽，带原子状态 `ACTIVE` / `RETIRING` / `EXITED`。`set_threads` 在调用者
线程上持有组自己的锁执行，向 loop 投递命令后返回，不等待它们执行。唯一的等待：扩容到一个已提交退出
的 loop 的编号时，先 join 该线程（它已没有连接，所以很短），因为新 loop 复用它的计数器，旧线程之后
不能再碰它们。

- **扩容**：对每个新编号，若该编号的 loop 正在退役则将其复活（CAS `RETIRING → ACTIVE`，然后发送
  `Revive` 命令）；否则启动新 loop，复用该编号已退出 loop 的计数器（`LoopStats`），使指标序列连续，
  并且每个用过的编号只有一个序列。新 loop 得到一个监听套接字：Linux 上是绑定到该 listener 组里的
  新 `SO_REUSEPORT` 套接字（内核开始把新连接按份额分给它），或者之前绑定的同编号套接字，由当前持有
  它的活跃 loop 交还（`GiveListener`）；其他平台以及继承来的 listener 上是共享套接字的克隆。
- **缩容**：编号最大的 loop 离开名册，标记为 `RETIRING` 并收到 `Retire` 命令。退役 loop 立即停止
  accept，把它的 `SO_REUSEPORT` 套接字交给活跃 loop（`AddListener`）；套接字全程保持打开，所以在此
  期间到达其 accept 队列的连接会等待而不是被重置（这正是与关闭套接字、或与 prefork 代际替换的区别）。
  共享套接字的克隆直接关闭（其他克隆继续监听）。io_uring 先取消该 loop 的 multishot accept，并服务
  它在取消生效前 accept 到的连接。每个 `SO_REUSEPORT` 套接字有一个“归属”：活跃 loop `idx % n`；
  在扩缩容期间送错了 loop 的套接字会被转发到归属处。
- **哪些连接会迁移：没有。** 退役 loop 继续服务它拥有的连接直到它们关闭；ADR-001 保持不变（handler
  不跨线程，没有任何连接的属主指针变为可变）。当它没有连接、没有进行中的 dial 或 accept 时退出：用
  CAS `RETIRING → EXITED` 提交，若组在此期间复活了它则 CAS 失败。设置了 `retire_timeout` 时，到期
  仍打开的连接收到 `on_shutdown`（engine 关闭的优雅路径：HTTP 写完响应后关闭，WebSocket 发送 1001，
  于是客户端重连到活跃线程），再过 `shutdown_timeout` 仍打开的被关闭。
- dial 和 adopt 的流按名册轮询，在其读锁下投递，所以紧接着被退役的 loop 会先收到 dial、再收到
  `Retire`，并服务它。正在退出的 loop 队列中不能丢失的命令（监听套接字、dial）会被转交出去。
- 不支持（`Unsupported`）：UDP listener（在 UDP `SO_REUSEPORT` 组里增删套接字会把对端重新哈希到
  别的线程，拆散它们的状态）、DPDK 组，以及启用 BPF 分流（`Accel::Ebpf`）的 listener（分流映射需要
  重建）。
- `LoopStats`/`LoopMetrics` 新增 `retiring`，渲染为 `akio_loop_retiring` 并出现在 JSON 中。

### akio-prefork

- `Controller::reload_in_place()` / `Supervisor::reload_in_place()` 以及向 supervisor 发送 SIGUSR1，
  会向每个运行中的 worker 发送一个新的控制字节，worker 在其控制线程上执行 `Worker::on_reload(Fn())`
  设置的钩子（直接向 worker 发送 SIGUSR1 也一样）。钩子通常重新读取配置并调用 `Engine::reload` 和
  `Engine::set_threads`。不替换进程，也不动任何连接。`Status::in_place_reloads` 和
  `Worker::reloads()` 记录次数。
- 代际替换（SIGHUP、`Controller::reload`）不变，仍是修改代码、listener 或固定设置的方式。新一代的
  worker 按启动代码加载的内容启动，所以只有配置源也被更新时，原地修改才能在代际替换后保留。
- 使用 `ListenMode::Inherit` 时 worker 共享一个套接字：任一 worker 的 backlog 热更新对所有 worker
  生效。使用 `ReusePort` 时，扩容的 worker 往跨进程的组里加入套接字，因此分到更大份额的新连接；
  缩容在 worker 内部转交套接字，不重置任何连接（不同于没有 `tcp_migrate_req` 的代际替换）。

## 考虑过的方案

- **缩容时把空闲连接迁移到其他线程**：需要连接的属主（`ConnInner` 的 loop 链接）变为可变，并在每次
  跨线程发送、唤醒和完成时同步；还要在 ring 之间转交 fd、handler、定时器，以及 io_uring 上进行中的
  操作。这打破了 ADR-001 关于每连接状态从不换线程的保证（用户可能保存线程局部缓存），并给跨线程路径
  增加开销。让连接自然结束，再用 `retire_timeout` 和 `on_shutdown` 给出上界，能保持热路径和线程模型
  不变。
- **关闭退役 loop 的 `SO_REUSEPORT` 套接字**：会重置它排队的连接（这正是 `tcp_migrate_req` 要解决的
  问题）；把它交给另一个 loop 不花代价也不丢连接。
- **把线程数放进 `Config`**：线程数按 listener 设置（`Listener::threads`），不是 engine 级的；按编号
  调用与 `local_addrs` 对应。
- **保留退役套接字来缩容 UDP 组**：退役的套接字会继续按哈希收到它那份新对端，线程永远无法退役；
  在分流（eBPF）能固定已有对端之前不做。

## 影响

- 只新增公共 API：`Config::retire_timeout`、`Live::{read_buffer, set_read_buffer, backlog,
  set_backlog, udp_idle_timeout, set_udp_idle_timeout, retire_timeout, set_retire_timeout}`、
  `LoopMetrics::retiring`、`Engine::{threads, set_threads}`、`akio_sys::set_backlog`，以及
  akio-prefork 的 `Controller::reload_in_place`、`Supervisor::reload_in_place`、
  `Worker::{on_reload, reloads}`、`Status::in_place_reloads`。行为变化：`Engine::reload` 现在会应用
  `read_buffer`、`backlog` 和 `udp_idle_timeout`，而不是报告为被忽略。
- 热路径：除了 poll token 的匹配改为测试一个 listener 位（原来是与一个常量比较）、io_uring 从完成
  事件的操作码选择缓冲区组之外不变；同轮 A/B 测量见 docs/BENCHMARKS.md 的“热更新”。
- 带着长连接退役、又没有设置 `retire_timeout` 的 loop 会一直占用线程直到连接关闭；`Metrics` 会显示它
  （`retiring`）。反复缩容/扩容不会累积线程：扩容优先复活正在退役的 loop。
- Linux 上缩容后，一个 loop 可能持有多个 `SO_REUSEPORT` 套接字，在组再次扩容之前分到更大份额的新连接。
