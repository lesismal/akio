# ADR-180：连接句柄、关闭期限，以及监听器的接受与关闭钩子

[English](180-connection-handles-and-accept-hooks.md) | 简体中文

状态：已采纳（2026-11-26）。akit 的 A232。

## 背景

fit 的控制台（以及自 fit 的 I161 起，它的 Admin API）限制未登录客户端的连接：连接在被接受 5 秒后关闭，
无论它发送什么，直到一个带有效会话的请求到来；此后两次请求之间可保持 2 分钟，会话结束时重新回到 5 秒
规则。当已打开 `max_conns` 个连接时，新连接会关闭持有最多连接的客户端最早的一个未认证连接，而不是被
拒绝。akit 要在 akio 上做到同样的事。

akio 底层已有所需的部件，却无法从这里够到：akio-core 的 `Conn<H>` 可以在任意线程关闭连接、设置它
自己的空闲超时（ADR-155），但 HTTP handler 拿到的是 `Context` 而不是连接，而 `Conn<H>` 以协议的
handler 类型为参数，应用从不写出这个类型。`Listener::filter`（ADR-099）只看到对端地址，只回答是或否，
因此没有任何机制告诉应用每个被接受的连接以及它的关闭，以便维护一张连接表；也没有办法在事先设定的
时刻关闭一个连接而不管它做什么。

## 决定

1. **`ConnHandle`（akio-core，由 `akio` 重新导出）**：可克隆、`Send + Sync` 的连接句柄，不带 handler
   类型，与 `Conn<H>` 共用同一个 `Arc<ConnInner>`：`id`、`is_open`、`local_addr`、`peer_addr`、
   `close`、`set_idle_timeout`（即 ADR-155 的那个，后端与错误相同），以及关闭期限。按连接判等和
   哈希。`Conn::handle()` 生成一个。与 `Conn` 一样，它从不触碰被回收的描述符；连接关闭后，其调用
   什么也不做或返回 `Error::Closed`。
2. **关闭期限：`close_at(Instant)`、`close_after(Duration)` 和 `cancel_close()`。** 到期时连接被关闭，
   无论它发送了什么，除非期限先被取消或替换（最后设置的那个生效）。`ConnInner` 上的一个代计数器
   （每个连接 8 字节）记录生效的期限；设置或取消都会使其前进。每次调用经由 `run_on_loop` 的路径，
   在连接自己的 I/O 线程的时间轮上放一个定时器（ADR-103；该线程没有时间轮时用进程级定时器线程），
   定时器只持有弱引用和设置时的代数，只有代数仍然相同时才关闭连接。被取消的定时器留在时间轮中直到
   到期，然后什么也不做：没有锁，没有跨线程取消，也不让任何东西多活。已经过去的期限会在循环的下一轮
   关闭连接。
3. **`Listener::on_accept(Fn(&ConnHandle))` 和 `Listener::on_close(Fn(&ConnHandle))`（akio）。** 设置
   了其中之一的监听器，其 acceptor 被包装（`akio_core::hooked`，一个 `DynAcceptor`）：`on_accept` 在
   连接的 I/O 线程上运行，位于 filter 和 `max_connections` 检查之后、任何传输层工作与 acceptor 的
   `on_open` 之前；`on_close` 在 handler 的 `on_close` 之后运行。对 `on_accept` 见过的每个连接，
   `on_close` 恰好到来一次：`on_accept`、`on_open` 或 handler 的 `on_close` panic 时也是如此（连接照旧
   被拒绝或关闭），后端丢弃一个无法注册的 handler 时也是如此。关闭是投递给循环的，所以 `on_close`
   从不在 `close` 调用内部运行，`on_accept` 可以在持有连接表锁的情况下关闭另一个连接。没有钩子的
   监听器保持 acceptor 不被包装，没有任何开销；设置了 `on_close` 的监听器每个连接多一个装箱的包装。
4. **`Context::connection() -> Option<ConnHandle>`（akio-http）**：请求所在的连接，HTTP/1.1 或
   HTTP/2（整个连接，它的所有流）；在 HTTP/3 上为 `None`（QUIC 连接属于传输层），响应交出之后也为
   `None`。从 context 的 responder 取得，所以不调用它的请求没有开销；HTTP/2 取一次连接锁。
5. **`HttpConfig` 的超时保持不变。** 连接自己的空闲超时与 HTTP 的 head、body、keep-alive 超时并行；
   较短的那个关闭空闲连接，所以要让已登录连接保持 2 分钟的应用，要把 keep-alive 超时设得至少这么长。

## 后果

- akit 的控制台和 Admin API 能沿用 fit 的规则：`on_accept` 记录每个连接及其客户端，并设置
  `close_after(5 s)`；带有效会话的请求调用 `cancel_close` 和 `set_idle_timeout(2 min)`，会话结束时
  再次 `close_after(5 s)`；超过 `max_conns` 时，`on_accept` 关闭持有最多连接的客户端最早的未认证
  连接；`on_close` 把连接移出表。它的权宜之计（控制台沿用 Admin API 的限制）可以去掉。
- 测试（akio 的 `conn_handle`、akio-http 的 `connection_handle`，在测试套件运行的每个后端上）：由钩子
  维护的连接表、从另一线程关闭、关闭一个持续发送的连接的期限、被取消的期限、被替换的期限、已经过去
  的期限、通过句柄设置的空闲超时、连接表满时的驱逐、panic 的 `on_accept`；在 HTTP/1.1 和 HTTP/2 上，
  取消期限的登录和重新设置期限的登出。
- 代价：每个 `ConnInner` 多 8 字节；每次 `close_at` 向循环投递一个任务、放一个定时器。读写路径上
  没有任何开销。DEV-PLAN 第 4 节写明了基准任务应测量的内容（每个连接带钩子和期限时的接受速率）。
- 未做：在 filter 决定之前就拿到连接的钩子（filter 仍只凭地址作答）；HTTP/3 连接的期限。
