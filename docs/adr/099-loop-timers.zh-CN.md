# ADR-099：I/O 循环上的定时器

[English](099-loop-timers.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

每个 I/O 循环本来就有一个时间轮（`akio-timer`），但只用于引擎自己的截止时间（空闲、写、握手与连接超时）。
应用若想稍后在某个连接上做点什么——10 ms 后应答、重试、按请求设截止时间——没有自己的定时器可用，书里写的是
“用你自己的定时器线程”。于是应答在那个线程上产生，再跨线程回来：用锁排队，`Detached::respond`（或
`Conn::send`）从外部线程拿连接的锁并在那里写 socket；写没写完时再向循环投递命令并用 `eventfd` 唤醒。
定时器线程还要与循环争用同一批 CPU。

HttpArena 的 `async` 场景测的正是这个：32,000 个保持的连接上的 `GET /delay/10`。我们的条目用分片的
`Mutex<BinaryHeap>` 定时器线程应答，约 572k req/s；同一台机器上最快的条目（dusty-tuned，io_uring）约 663k。

## 决定

1. **`akio_core::timer`**（以 `akio::timer` 重新导出）：`after(delay, f) -> Result<Timer>` 把
   `f: FnOnce() + 'static` 排进**调用方**所在 I/O 线程的时间轮。时间轮放在线程局部变量里，循环启动时装上、
   退出时移除，所以设定与触发都不加锁、不涉及别的线程；`f` 不必是 `Send`。不在 I/O 线程上时 `after` 返回
   `Error::Closed`；`on_loop()` 用来区分这两种情况。
2. **计时**：从循环启动起算的毫秒刻度；截止时刻是 `now + delay` 当时或之后的第一个刻度，所以定时器绝不会提前
   触发。每轮循环以自身超时与时间轮下一截止时间（向上取整到整毫秒）中较短者轮询，在 I/O 事件之后、**排空命令
   队列之前**运行到期的定时器，因此定时器为自己的连接投递的唤醒在同一轮里处理。空闲过的时间轮在放入新定时器前
   先推进到当前刻度。
3. **`Timer::cancel`** 丢弃闭包（只在设定它的线程上有效；在别处返回 `false`）。丢弃 `Timer` 不会取消它。
4. **上限**（规则 7 与 10）：每个循环 `MAX_TIMERS_PER_LOOP` = 2^20 个，超出返回 `Error::Overloaded`；
   延时夹到 `MAX_DELAY`（2^32 − 1 ms）。循环退出时（关闭、被 `set_threads` 撤下的线程）待触发的定时器不运行即被
   丢弃；定时器 panic 会被捕获并记录日志。
5. **每种循环都有**：epoll / kqueue 的 TCP 与 UDP 循环、io_uring、DPDK（在那里它还防止自适应循环睡过截止时间）。
6. **akio-http `Context::after(delay, f: FnOnce(Detached) + Send)`** 把请求分离出来，在连接所在线程上由循环
   定时器调用 `f`；不在 I/O 线程上时退回到该 crate 已有的定时器线程（因此要求 `Send`）。已经发送过响应时返回
   `false`。

未采用：按连接的 `Conn::after`，像 `spawn_blocking` 那样交出 `&mut H`（会让每个定时器都经过命令队列及其互斥锁，
并把定时器绑到 HTTP/2、HTTP/3 服务看不到的 `Handler` 类型上）；跨线程投递的共享定时器服务（正是要去掉的开销）。

## 后果

- 新增 API：`akio::timer::{after, on_loop, Timer, MAX_TIMERS_PER_LOOP, MAX_DELAY}`、
  `akio_http::Context::after`。`install`、`uninstall`、`fire`、`next_wait`、`poll_timeout` 是
  `#[doc(hidden)]` 的后端接口。akio-core 现在依赖 akio-timer（本来就是工作区 crate，没有新的第三方依赖）。
- 没有定时器的循环每轮多一次线程局部变量读取。
- gpu51 上的测量（HttpArena `async`，同轮 A/B，3 轮；`akio` = 定时器线程，`akio-timer` = `Context::after`）：
  `akio` 571,051 / 572,687 / 572,587 req/s，`akio-timer`
  597,215 / 602,551 / 600,046（+4.8 %）。不设定时器时没有可测出的变慢（2 轮）：`baseline` 1,082,708 /
  1,084,209 对 1,072,531 / 1,082,454（−0.5 %），`pipelined` 7,260,969 / 7,291,139 对 7,194,758 /
  7,142,118（−1.5 %；两次运行的 CPU% 差别比这还大）。在一次剖析运行中，`akio-timer` 设 `AKIO_BACKEND=uring`
  达到 768,853，dusty-tuned 为 662,540。剖析（同样负载下 5 s，`perf stat` / `perf record`）：使用定时器线程时服务器发生 417k 次上下文切换、
  32.8k 次 CPU 迁移、12.2k 次 `futex` 与 786k 次 `epoll_wait`；使用循环定时器时为 156、0、0 与 2.8k（循环从不
  睡眠），8 个 I/O 线程各占 12.5 % 的样本。剩下的是内核的 TCP 工作：84 % 的 CPU（接收路径、conntrack、AppArmor
  socket 检查、系统调用入口），epoll 上每个请求一次 `recvfrom` 与一次 `sendto`。在 io_uring 上接收经由环完成
  （5 s 内 162k 次 `io_uring_enter`），只剩发送是系统调用，所以同一条目设 `AKIO_BACKEND=uring` 时是这一轮最快的。
