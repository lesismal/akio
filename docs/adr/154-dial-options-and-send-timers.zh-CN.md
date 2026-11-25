# ADR-154：每次拨号自己的连接超时，以及 I/O 线程之外的定时器

[English](154-dial-options-and-send-timers.md) | 简体中文

状态：已采纳（2026-11-26；akit A12、A79、A45）

## 背景

网关在一个引擎上拨很多上游，每个上游有自己的连接超时（fit 每个上游的 `connect_timeout`）。
`Engine::dial` 只有一个：引擎的 `Config::connect_timeout`，由后端在拨号命令投递到 I/O 线程时挂到该
线程的时间轮上。`HappyEyeballs` 竞速两个及以上地址时用它自己的 `connect_timeout`，但单个地址（IP
字面量、只有一条记录的名字）以及竞速线程忙不过来时依次拨的地址都用 `Engine::dial`，于是那里生效的是
引擎的超时。akit 的权宜之计是把引擎的超时设为各上游中最短的（HTTP 为 akit A12，四层服务为 A79）。

网关的控制面也需要定时器：按间隔执行的健康探测及其截止时间、空闲清理、缓存锁过期、刷新。akio 的定时器
要么只属于事件循环（ADR-103：只能在调用它的 I/O 线程上），要么是私有的（akio-http 的请求超时线程）。
akit 为此自己跑了一个带有界堆的线程（akit A45）。

## 决定

1. **`DialOptions`**（akio-core，由 `akio` 再导出）：`#[non_exhaustive]`，用
   `DialOptions::new().connect_timeout(d)` 构造；`connect_timeout: None` 表示用引擎的。
   **`Engine::dial_with(addr, opts, acceptor, on_error)`** 即带选项的 `dial`。
2. 面向后端的 `Group` trait 新增 `dial_with`；默认实现忽略选项并调用 `dial`。TCP 组实现它：
   epoll/kqueue 事件循环和 io_uring 在拨号命令中带上超时，并用它代替 `Config::connect_timeout`
   设置连接截止时间；轮次调度同样如此；DPDK 用它代替其协议栈自己的 10 s。共享 listener 组（ADR-130）
   转发它。截止时间还是原来那个时间轮条目（整毫秒、至少一毫秒、上限为 `timer::MAX_DELAY`），所以拨号
   没有额外开销。
3. **`HappyEyeballs`** 的每一次尝试都受它的 `connect_timeout` 约束：单个地址和依次拨的地址都经由
   `dial_with`。经由它拨号的客户端（akio-http 的 `Client`、`H2Client::connect`、akio-ws）因而对单个
   地址也有界；`H2Client::dial`（一个地址，不竞速）同样使用 `H2Options::happy_eyeballs.connect_timeout`。
4. `dial_udp` 不接受连接超时：UDP 没有握手（socket 立即 connect，`on_open` 立即执行），沉默的对端由
   `Config::udp_idle_timeout` 结束。
5. **`akio::timer::after_send(delay, f: FnOnce() + Send) -> Result<SendTimer>`**（与事件循环内的
   `after` 并列）：`f` 在一个进程级定时器线程（`akio-timer`）上执行，该线程首次使用时启动，没有待执行
   的定时器 30 s 后退出。定时器保存在一把锁下的一个有序表（`BTreeMap<(Instant, seq), Job>`）中：设置
   是一次插入（只有新定时器最先到期时才唤醒线程），`SendTimer::cancel()`（可在任何线程调用）是一次删除，
   并说明它是否仍在等待。线程在锁内取出到期的条目（每批 256 个），在锁外执行；panic 会被捕获并记录。
   有界：最多 `MAX_SEND_TIMERS`（2^20）个待执行，超出返回 `Error::Overloaded`；延迟上限为
   `MAX_DELAY`。从不提前。
6. 任务共享一个线程，所以必须很快且不能阻塞；有实际工作的任务把工作投递出去（用 `Conn::run_on_loop`
   投递到连接、投递到线程池、投递到 channel）。在 I/O 线程上 `after` 仍然更便宜（无锁，不涉及其他线程）。

未选择：
- 给 `dial` 本身加一个超时参数：这是破坏性变更，而且选项（本地地址、socket 选项）放在结构体里更容易扩展。
- `Engine::after`（绑定引擎、在其某个 I/O 线程上执行、引擎停止时丢弃的定时器）：它需要一个能在每种后端
  的任意事件循环上执行闭包的命令，而 akit 的调用方（JWKS 刷新、缓存锁、FastCGI 池的 tick）往往并不持有
  引擎。任务可用 `Conn::run_on_loop` 回到连接的事件循环；需要时以后再加绑定引擎的形式。
- 公开 akio-http 的私有定时器线程：它的 API 是为客户端请求超时设计的。

## 影响

- 新增 API：`DialOptions`、`Engine::dial_with`、`timer::{after_send, SendTimer, MAX_SEND_TIMERS}`。
  `Group::dial_with` 是 `#[doc(hidden)]` 的后端管道。
- `HappyEyeballs::connect_timeout` 现在也约束单个地址；原先在那里依赖引擎（更长）超时的应用会改用它自己的。
  两者默认都是 10 s。
- 热路径不变：一次拨号多带一个 `Option<Duration>`；accept 的连接不受影响。无需基准测试。
- 定时器线程每次设置或取消都要取一把进程内所有线程共享的锁：对控制面的频率（akit：每个被探测地址每个
  间隔两个定时器）没有问题，但不适合在 I/O 线程上按请求使用，那里有 `after`。
