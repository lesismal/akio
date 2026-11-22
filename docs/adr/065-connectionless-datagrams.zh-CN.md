# ADR-065：无连接的 UDP listener（`DatagramsHandler`）

[English](065-connectionless-datagrams.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

UDP listener 把每个源地址变成一个连接：一个 `Conn`、一个 handler、一个空闲定时器，以及循环
对端表里的一项（`Listener::udp`，M2），受 `Config::udp_max_peers` 与 `udp_idle_timeout` 约束。
这对有每对端状态的协议（QUIC、DTLS、KCP、游戏会话）是对的，ADR-024 和 M2 UDP 工作中的批量化
（`recvmmsg`、一个接收批次的回复经 `sendmmsg` 与 UDP GSO 一起发出、`on_batch_end`）也都在
这条路径后面。

DNS、syslog、StatsD、NTP 式或遥测采集器对每个数据报单独应答。对它们来说对端表纯属开销：每个
再也不会出现的客户端都有一个 handler 和定时器，伪造的源地址能把表填到 `udp_max_peers`（之后
真实客户端被拒绝），每个地址还要走一遍 `on_open` / `on_close`。DEV-PLAN 把无连接的
`DatagramsHandler` 列为未完成。

约束：thread-per-core，回调在 I/O 线程内联执行（ADR-001）；不引入新依赖；每个队列都有上限且有
安全默认值（`docs/rules.zh-CN.md`）；支持 epoll、kqueue 和 io_uring；现有的每对端路径不能变慢。

## 决定

1. **服务 UDP listener 的第二种方式**：`Listener::udp(addr).serve_datagrams(factory)` 代替
   `.serve(acceptor)`。`factory: Fn(&DatagramSender) -> H` 每个 I/O 线程执行一次（Linux 上每个
   线程一个 `SO_REUSEPORT` socket，与每对端 listener 相同；其他系统一个线程），所以 handler 按
   线程划分、不需要锁：这就是 thread-per-core 意义下的“每个 listener 一个处理器”。在 TCP
   listener 上使用，或与 `.serve` 同时使用时，`build` 返回 `InvalidInput`。
2. **`DatagramsHandler` 按批接收。** `on_datagrams(&mut self, batch: &Datagrams<'_>, out:
   &mut Replies)` 每个接收批次执行一次（Linux 上一次 `recvmmsg`，最多 32 个数据报；其他系统
   最多 32 次 `recv_from` 收进同一个缓冲区）；`Datagrams` 迭代从接收槽借来的 `(SocketAddr,
   &[u8])`（GRO 合并的接收拆回单个数据报，与每对端路径相同）。`on_shutdown(&mut self, out)`
   让它发出最后的数据报。选择批次而不是每个数据报一次回调，是因为批次正是系统调用交付的单位，
   也是 handler 摊薄自身开销所需要的（每批一次加锁、一次查找、一次写日志）；逐个处理只需一个
   `for`。用两个参数而不是一个对象，是因为批次以不可变方式借用接收缓冲区，而回复以可变方式排队。
3. **回复一起发出，走同一套批量化。** `Replies::send_to(data, addr)` 把数据报复制进每线程一个
   连续缓冲区；回调返回时用 `sendmmsg` 发出（每次 64 条消息），发往同一地址、长度相同的连续数据
   报合并为一条 UDP GSO 消息（在缓冲区里连续，所以只需一个 iovec），GSO 的探测与关闭和每对端路径
   相同；没有 `sendmmsg` 的系统每个数据报一次 `sendto`。网络拒绝的数据报（过大、地址族不符、
   不可达）被丢弃，与 UDP 的语义一致。
4. **有上限，有背压。** 队列把每个数据报的字节数加 64 计入 `Config::max_queued_bytes`（默认
   64 MiB；至少能放下一个最大的数据报）。队列满时 `send_to` 先发出已排队的内容，仍放不下就以
   `WouldBlock` 拒绝（计入 `overloaded` 指标）。socket 放不下的数据报（`EAGAIN`）会等待；此时
   该线程只轮询可写、停止读取，直到它们发出，所以 socket 满会把压力传回接收侧，而不会让任何东西
   增长。超过 65,535 字节的 `send_to` 返回 `InvalidInput`。清空后容量超过 1 MiB 的缓冲区会被释放。
5. **跨线程发送**：`DatagramSender`（`Send + Sync + Clone`）包装 socket，在调用线程上用一次
   `sendto` 发送；socket 满时以 `WouldBlock` 丢弃该数据报（与 `UdpBinding::send_to` 的语义相同）。
   不经队列投递到 I/O 线程：没有需要限制的东西，没有唤醒，UDP 在线程之间也没有需要保持的顺序。
   可从工厂函数、`Replies::sender()` 或 `Engine::datagram_sender(local)`（Linux 上是第一个线程的
   socket）取得。
6. **完全没有每对端状态**：没有表、没有 `Conn`、没有空闲定时器、没有 `on_open` / `on_close`；
   `udp_max_peers`、`udp_idle_timeout`、`spawn_blocking` 和连接表都不适用（慢的工作交给应用自己
   的线程，用 `DatagramSender` 应答）。内存是接收槽、回复缓冲区和 handler，与对端数量无关。
7. **一个驱动，三个后端。** `akio_core::DatagramPort`（面向后端）持有 socket、接收批次、
   handler 和回复队列，提供 `on_readable` / `on_writable` / `wants_read` / `wants_write` /
   `shutdown` / `on_reload`。epoll/kqueue 的 UDP 循环（`UdpGroup::bind_datagrams`）在其 socket
   token 下轮询它；io_uring 循环（`UringGroup::bind_datagrams`）为每个 socket 提交一个一次性的
   `IORING_OP_POLL_ADD`（`POLLIN`，有回复等待时为 `POLLOUT`），完成时运行同一个驱动，关闭时取消。
   就绪来自 ring、I/O 走 `recvmmsg` / `sendmmsg`，正是 M2 评估的结论（带 provided buffer 的
   multishot `recvmsg` 会把批量化重新实现一遍，却没有可测的收益），现在用于一个真正运行在
   io_uring 线程上的 listener，因此 `AKIO_DEFAULT_BACKEND=uring`（ADR-029）对数据报 listener
   生效（每对端 UDP listener 仍总是运行在 epoll 的 UDP 循环上）。严格的 `UringConfig` 在
   io_uring 不可用时让 `build` 失败，与 TCP 相同。
8. **不支持**：DPDK（它的用户态 UDP 是每对端的；`build` 返回 `Unsupported`，要支持需要基于该
   协议栈的 socket 实现一个数据报端口）；`Engine::set_threads`（拒绝，与每对端 UDP listener 相同：
   向 `SO_REUSEPORT` 组增删 socket 会让对端在线程间移动）；运行时绑定的数据报 socket
   （`Engine::bind_udp` 仍是每对端的）；两个方向的 ECN 码点（每对端路径保留它们）。回调中的
   panic 会被捕获并记录，handler 继续服务：没有可关闭的连接，而停掉 listener 会让一个坏数据报
   变成一次故障。

## 影响

- DNS 式服务器不为客户端保留任何状态，伪造的源地址也无法迫使它拒绝客户端；1 万个对端的测试中
  常驻内存没有增长。
- 每对端路径不变（UDP 循环只是在 socket token 上为服务数据报端口的循环多了一个分支）；下面的
  A/B 显示没有退步。
- 公共 API 只有新增：`akio::{DatagramsHandler, Datagrams, DatagramsIter, Replies,
  DatagramSender}`、`Listener::serve_datagrams`、`Engine::datagram_sender`，以及后端构造函数
  `UdpGroup::bind_datagrams` / `UringGroup::bind_datagrams`。
- 测试：`crates/akio/tests/datagrams.rs`（跨对端的批次与边界；每批回复一次 `sendmmsg`，由
  `writes` 指标计数；向同一对端的突发；来自其他线程的发送，包括工厂函数的和 engine 的；11,000 个
  不同对端下没有对端、没有连接、RSS 有界；每对端 listener 与数据报 listener 并存；关闭时的数据报；
  panic；大小限制；误用），在 kqueue、epoll 和 io_uring（`AKIO_TEST_BACKEND=uring`）上运行；以及
  回复队列的单元测试（上限之下 / 恰好 / 之上、GSO 段边界、顺序）。
- 示例：`crates/akio/examples/udp-dns.rs`（DNS 风格应答器）；基准用 `bench-server udp-dgram`。

## 测量

gpu51（Ryzen 7 7800X3D，Linux 7.0），安静主机（`quiet.sh`），同一轮交替运行：64 字节 UDP echo，
服务端 4 线程在 CPU 0–3，`echo-bench` 64 个 socket × 64 B、8 线程在 CPU 4–11，每次 10 秒，9 轮、
顺序轮换；取中位数，每请求服务端 CPU 来自 `/proc`。

| 服务端 | req/s，中位数（范围） | 相对改动前每对端 | 每请求服务端 CPU | 相对改动前 |
|---|---:|---:|---:|---:|
| 每对端 `Listener::udp(..).serve`，改动前（`b22519ae`） | 768,144（684,519–860,916） | 1.00 | 4,745 ns | 1.00 |
| 每对端，改动后 | 781,173（712,511–841,607） | 1.02 | 4,747 ns | 1.00 |
| `serve_datagrams`，epoll | 829,051（726,597–926,309） | 1.08 | 4,407 ns | 0.93 |
| `serve_datagrams`，io_uring | 838,496（680,238–912,182） | 1.09 | 4,364 ns | 0.92 |

每对端路径没有退步（吞吐在轮间波动范围内，每请求 CPU 相同）。去掉对端查找、`Conn` 和每对端的
cork/flush 记账后，无连接 echo 每请求的服务端 CPU 少 7–8%；回环上 64 个客户端时客户端已接近其
上限，所以吞吐的提升小于这个比例。复现用 `tools/bench/udp-dgram.sh`。
