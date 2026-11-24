# ADR-106：io_uring 环上发送：响应作为 SEND 条目，随 loop 的那一次 `io_uring_enter` 发出

[English](106-uring-ring-sends.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

io_uring 后端的接收走环（provided-buffer 环上的 multishot recv，`DEFER_TASKRUN`），但每个响应
都是自己写出去的：每个回调结束时 loop 对 socket 调用 `write`/`writev`，走与 epoll 共用的写路径
（`ConnInner` 从任意线程直接写 socket，写不完的排队）。在一次读只带一个请求或消息的负载上，这就是
每个请求一次系统调用，外加共享的 `io_uring_enter`。

2026-11-16 的评估（docs/BENCHMARKS.md，“io_uring features evaluation”）在裸环上测得环上发送
吞吐 +1–4%、每请求 CPU 少 2–6%，但没有采用：写路径与 epoll 和其他线程共用，而环上发送要求字节
保留到完成为止、每个连接同时只有一个发送在途，并且要与直接写保持顺序。

在同一台机器上的 HttpArena（服务端 8 个 CPU）里，aegon（一个用 `IORING_OP_SEND` 发送、热路径上
没有收发系统调用的 C++ io_uring 框架）在系统调用受限的负载上领先 akio：echo-ws 9–17%、
echo-ws-pipeline 9–16%、HTTP/1.1 baseline 11%、pipelined 19%。profile 显示 io_uring 上的 akio
每次读一次 `writev`（echo-ws 上每次 `io_uring_enter` 约 20 条消息），aegon 则一次也没有。

之前有两个未完成的分支尝试过。一个在共用写路径（`ConnInner`）里，由 loop 的刷新描述排队的字节，
并把它们留在队列里直到完成；另一个把队首“借给”只在 `on_data` 之后由 `refresh` 发起的发送，每次
发送分配一个 box，kernel TLS 下退回 `writev`。本 ADR 采用第一种设计，它用一条不变式覆盖 loop 的
所有刷新（回调、可写、线程池完成、kernel TLS 控制记录），并从第二种设计借来“把提交推迟到这一批
结束”的做法。

## 决定

- **`ConnInner` 的环模式**（akio-core，`#[doc(hidden)]` 的后端接口）：注册时 `set_ring_sends(true)`。
  loop 自己的刷新 `uncork_flush_ring` 和 `flush_queue_ring` 不写排队的字节，而是把队列开头最多
  16 个字节块描述进一个 `RingSend`（地址、长度），并把这些字节标为在途
  （`WriteState::ring_inflight`）。字节留在队列里，`queued_bytes`、背压、`max_queued_bytes` 和
  `on_drain` 照常计入，直到后端用 `ring_sent(res)` 报告完成：它消费已发送的部分并描述下一次发送。
  短发送把余下的部分留在队首给下一个条目；`EAGAIN` 让 loop 等 `POLLOUT`；其他错误像 `writev`
  失败一样关闭连接。
- **环上发送在途时，别的都不碰 socket**：`write_queue` 立即返回，而且队列不为空，所以其他线程的
  直接写（队列为空时仍然直接写）排在它后面；kernel TLS 的 socket 操作和 `sendfile` 块也一样，
  它们到达队首后由 loop 同步执行（一次发送止于它们之前）。每个连接的顺序就是队列的顺序。往在途块
  追加数据只发生在其容量之内（`push_copy` 从不重新分配块），且在正在发送的范围之外。
- **在这一批结束时提交**：loop 记下刷新描述了发送的连接（`Loop::unsent`），在进入内核之前把每个
  再描述一次（`ring_redescribe`：期间没有东西消费队首，所以发送只会变大），然后推入一个
  `IORING_OP_SEND`（一个缓冲区）或 `IORING_OP_SENDMSG`（多个；装箱的 `msghdr` 和 iovec 归连接
  所有并复用），带 `MSG_NOSIGNAL`。于是一批里对一个连接的所有应答（多个 recv 完成、一个线程池
  完成）都在一次发送里发出，所有连接的发送都随 loop 本来就要做的那次 `io_uring_enter` 交给内核：
  一批无论多少连接作答，只花一次系统调用。每个连接最多一个发送在途。
- **关闭**：`mark_closed` 不再计入队列，但在有发送读取时保留其中的块；loop 把连接的 `ConnInner`
  和 `msghdr` 留在 `orphans` 里直到完成到达（关闭时的 shutdown 让发送很快结束），然后用
  `ring_release` 释放。仍在 `unsent` 里等待的发送内核从未见过，立即释放。loop 退出时已有的
  “全部取消并排空”也覆盖发送；超时则像 provided buffer 一样泄漏其内存。
- **TLS** 不需要新东西：应用发送时记录就被加密进队列，环上发送带的是密文。kernel TLS 下由内核
  加密 `SEND` 交给它的数据；它的控制记录和密钥更新（socket 操作）以及 `sendfile` 按队列顺序在
  两次发送之间由 loop 执行。数据报连接和用户态协议栈的连接不走这条路径。
- **写超时**：进度以完成事件报告的为准（`ring_sent` 计入已发送的字节），所以停滞的对端仍会触发
  `write_timeout`；随后的关闭结束挂起的发送。
- **开关**：所有 io_uring 连接默认开启；`AKIO_URING_SENDS=write` 恢复 `write`/`writev` 路径
  （用于 A/B 测量）。epoll 和 kqueue 不变（那里从不设置环模式；新增的检查只是对 `ring_inflight`
  的一个分支）。能力探测要求 `SEND` 和 `SENDMSG`（Linux 5.3 / 5.6，低于后端要求的 5.19）。
- **未采用**：`SEND_ZC` 和注册缓冲区（回环总是拷贝，2026-11-16 的数字仍然成立）、链接发送、
  `MSG_WAITALL` 加 `IOSQE_CQE_SKIP_SUCCESS`（loop 必须知道内核何时用完这些字节）。

## 后果

- io_uring 上每个请求不再有发送系统调用；loop 的 `io_uring_enter` 携带整批的发送。测量见下文。
- 响应在 loop 的下一次 `io_uring_enter` 之后才上线，而不是在回调中：仍在同一次 loop 迭代内，
  除批处理本身外不增加延迟。
- io_uring 连接排队的输出现在会留在队列里直到完成：`queued_bytes` 包含在途字节，连接持续发送时
  写超时检查每个超时周期装一次。
- 每次发送多一个要收割的完成事件；在 `DEFER_TASKRUN` 下发送在提交时内联执行，其完成事件在下一次
  等待时已经就绪。
- 每个连接的 `WriteState` 增加一个标志和一个计数（所有后端）。

## 测量

gpu51（Ryzen 7 7800X3D，Linux 7.0），`http-bench` 8 个 I/O 线程在 CPU 0-3,8-11，gcannon（HttpArena
的压测工具）8 个线程在 CPU 4-7,12-15，每次 5 秒，每次新起服务端，轮换顺序，3 轮取中位数（波动在 2%
以内）。`main` 是本变更之前的代码；`write` 是本次构建加 `AKIO_URING_SENDS=write`。

| 场景 | main io_uring | 环上发送 | 环上发送 / main io_uring | 环上发送 / epoll |
|---|---:|---:|---:|---:|
| echo-ws，512 连接 | 1,290,871 | 1,433,949 | 1.111 | 1.182 |
| echo-ws，4096 连接 | 1,260,852 | 1,388,751 | 1.101 | 1.171 |
| echo-ws-pipeline（16），512 | 17,862,374 | 16,813,974 | 0.941（对 `write` 1.085） | 1.140 |
| echo-ws-pipeline（16），4096 | 17,308,358 | 16,169,145 | 0.934（对 `write` 1.078） | 1.128 |
| HTTP/1.1 baseline，4096 | 1,149,072 | 1,285,558 | 1.119 | 1.168 |
| HTTP/1.1 pipelined（16），4096 | 6,806,851 | 6,638,940 | 0.975（对 `write` 0.977） | 1.001 |

在 pipelined WebSocket 两行上，新二进制即使关闭环上发送也比 main 慢 13%（`write` 为 main io_uring 的
0.867 倍，epoll 为 main epoll 的 0.872 倍），所以这个差距不在发送路径（profile 显示多出的指令在
`akio_ws::protocol::Decoder::decode`，而 akio-ws 的代码没有改动：代码布局效应，仍在调查）。与同一
构建相比，环上发送在这里快 8%。

每个响应的系统调用（服务端上的 perf stat，整个运行期间）：

| 场景 | main io_uring：合计 / writev / io_uring_enter | 环上发送：合计 / writev / io_uring_enter | epoll：合计 |
|---|---|---|---|
| echo-ws 512 | 1.057 / 1.005 / 0.051 | 0.026 / 0 / 0.026 | 2.025 |
| echo-ws-pipeline 512 | 0.066 / 0.063 / 0.0032 | 0.002 / 0 / 0.0016 | 0.127 |
| HTTP/1.1 baseline 4096 | 1.057 / 1.001 / 0.052 | 0.045 / 0 / 0.041 | 2.012 |
| HTTP/1.1 pipelined 4096 | 0.067 / 0.063 / 0.0033 | 0.003 / 0 / 0.0018 | 0.127 |
