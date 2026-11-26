# 阻塞任务：逻辑线程池

回调在 I/O 线程上执行，所以一个阻塞 5 ms 的回调会让该线程上的所有连接停顿 5 ms。基准报告
显示了代价：四个 I/O 线程每个请求阻塞 5 ms，每秒只能处理约 550 个请求；把同样的工作挪到
逻辑线程池后约为 32,000
（[BENCHMARKS](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.zh-CN.md)）。

akio 不去猜哪些代码会阻塞。**由你显式地移走阻塞任务**，结果再回到连接自己的线程。

## `spawn_blocking`

```rust,ignore
pub fn spawn_blocking<R, W, D>(&self, work: W, done: D) -> Result<()>
where
    R: Send + 'static,
    W: FnOnce() -> R + Send + 'static,                 // 在逻辑线程池执行
    D: FnOnce(&mut H, &Conn<H>, R) + Send + 'static,   // 在连接所属的 I/O 线程执行
```

- `work` 在线程池线程上执行，可以阻塞（数据库、文件系统、慢 RPC、CPU 密集计算）。
- `done` 被投递回**所属 I/O 线程**，并获得 handler 的 `&mut` 访问权，所以 handler 状态仍然
  无锁。它发送的数据会被 cork，返回时刷出。
- 如果连接在此期间已关闭，`done` 会被跳过；`work` panic 时也会跳过（panic 计入
  `PoolStats::panicked`）。
- 线程池队列已满时返回 `Error::Overloaded`，连接（或线程池）已关闭时返回 `Error::Closed`。

## `run_on_loop`

```rust,ignore
pub fn run_on_loop(&self, f: impl FnOnce(&mut H, &Conn<H>) + Send + 'static) -> Result<()>
```

只有 `done` 这一半：`f` 直接投递到所属事件循环，在所属 I/O 线程上执行并获得 handler 的 `&mut`
访问权，不经过任何线程池线程。用它从其他线程（线程池任务、定时器、你自己的线程）访问 handler。
不要为此投递一个空的 `spawn_blocking`：线程池已满，或者它的线程都在等待这个连接时，那个任务永远
不会执行。如果连接在 `f` 执行前关闭，`f` 会被直接丢弃而不执行，因此它持有的守卫可以通知等待者；
连接已经关闭时返回 `Error::Closed`。

## 有序响应槽位

线程池任务可能以任意顺序完成。对于回复必须按请求顺序发出的协议（HTTP/1.1 流水线、按行协议、
arpc 式分帧），先预留位置：

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-basics.rs:offload}}
```

`Conn::reserve_response()`（在 I/O 线程上按请求顺序调用）返回一个 `ResponseSlot`。无论槽位
以什么顺序、在哪个线程被填充，响应都按预留顺序写出：

| `ResponseSlot` 方法 | 效果 |
|---|---|
| `fill(Vec<u8>)` | 提供响应字节。 |
| `fill_close(Vec<u8>)` | 提供响应字节；它和之前的所有响应写完后关闭连接。 |
| `fill_parts(Vec<Part>, close_after)` | 字节与文件区间（`Part::File` 用 `sendfile` 发出）。 |
| `stream(head) -> ResponseStream` | 分段产生的响应：`write`、`queued_bytes`、`finish(close_after)`。 |

丢弃一个未填充的槽位（或未 `finish` 的 `ResponseStream`）会**关闭连接**：否则后续响应会
永远卡在缺失的那个响应后面。普通的 `Conn::send` *不会*排在未填充的槽位之后；同一条回复流里
不要混用两者。

## 线程池大小

线程池是全 engine 共享的，按需创建、自适应（`akio_pool`）：

```rust,ignore
let mut pool = PoolConfig::default();       // #[non_exhaustive]：在默认值上修改字段
pool.min_threads = 0;                       // 空闲时也保留的线程数
pool.max_threads = cores * 8 (至少 8);      // 按需启动
pool.queue_capacity = 65_536;               // 超出后：Error::Overloaded
pool.keep_alive = Duration::from_secs(30);  // 超过 min_threads 的空闲线程退出
EngineBuilder::pool(pool)
```

以上是默认值。`Engine::pool_stats()`（以及指标端点）报告线程数、空闲线程、队列长度、已完成、
panic 和被拒绝的任务数。

`max_threads` 按阻塞任务等待的资源来定：数据库连接池只有 50 个连接时，200 个线程池线程没有
任何好处。`queue_capacity` 按你能接受多少排队延迟来定：`Overloaded` 是该回复"忙"（HTTP 503）
而不是继续排队的信号。

## 自己的线程池

某一类不能拖住其他任何事情的阻塞任务（例如缓存的磁盘层，其磁盘可能卡住）应有一个自己的线程池，
与 engine 的分开：`akio::Pool`，同一种有界线程池。

```rust,ignore
let mut cfg = akio::PoolConfig::default();
cfg.max_threads = 16;
cfg.queue_capacity = 4096;
let disk = akio::Pool::new(cfg);                          // Arc<Pool>
match disk.try_execute(Box::new(move || { /* 读文件，然后 conn.run_on_loop(..) */ })) {
    Ok(()) => {}
    Err(akio::Rejected(_job)) => { /* 已满或已关闭：回复"忙" */ }
}
// 结束时：disk.shutdown(); disk.join();
```

`try_execute` 从不阻塞；队列已满或线程池已关闭时，`Rejected` 把任务交还。`Pool::stats()` 报告它的
状态，就像 `Engine::pool_stats()` 报告 engine 的线程池一样。

## 在协议 crate 中

协议 crate 用各自的方式提供同样的思路；handler 从不阻塞，答复可以稍后从任何线程发出：

| crate | 机制 |
|---|---|
| akio-http | `Context::detach()` 返回 `Detached`，可在任何线程上 `respond`；`Context::detach_to_pool(f)` 先 detach，再在 engine 的线程池上执行 `f`；流水线响应保持顺序。 |
| akio-ws | `WsSender` 是 `Clone + Send + Sync`，可在任何线程发送。 |
| akio-grpc | 交给方法的 `Sink` 可以在任何线程使用。 |
| akio-arpc | `Context::detach()` 返回 `Responder`。 |
| akio-quic / akio-kcp | `Connection` / `Session` 是可克隆的句柄，可在任何线程发送。 |

它们提供的是"稍后答复"这一半；工作本身放在哪里执行由你决定：自己的线程、自己的线程池，
或者另一个运行时（[从 tokio 迁移](../migration/from-tokio.md)展示了衔接方式）。对于原始的
`Handler`，`Conn::spawn_blocking` 使用 engine 的线程池。

## 让所有 handler 在线程池上执行

HTTP、gRPC 和 arpc 服务端也可以把**每个**请求的 handler 都放到线程池上执行：handler 可以阻塞，
同一连接上的多个请求同时处理，而不是一个接一个。按协议分别设置，所有协议默认关闭：开启后每个请求都要
交接一次线程池，对从不阻塞的 handler 来说这就是大部分开销（handler 很轻的 HTTP/2 stream：同样 4 个
CPU 上，走线程池约每秒 49 万请求，inline 是 320 万–400 万）。handler 会阻塞时再打开，尤其是 HTTP/2，
否则它的各个 stream 会在所属连接的 I/O 线程上逐个处理：

```rust,ignore
let mut http = HttpConfig::default();
http.handlers_on_logical_pool = true;                         // HTTP/1.1
let mut h2 = H2Config::default();
h2.handlers_on_logical_pool = true;                           // HTTP/2 的各个 stream
http.h2 = Some(h2);
let mut h3 = H3Config::default();
h3.handlers_on_logical_pool = true;                           // HTTP/3（akio-h3）
let grpc = GrpcServer::new().handlers_on_logical_pool(true);  // gRPC 调用
let routes = Routes::new().handlers_on_logical_pool(true);    // arpc 的请求和通知
```

- **移到线程池的部分。** 中间件和 handler。解析、限制、流控，以及 gRPC 的拦截器和消息解码，仍在
  I/O 线程上。
- **仍在 I/O 线程执行的请求。** 可能接管连接的请求（HTTP/1.1 的 `CONNECT` 和 `Upgrade`，HTTP/2
  与 HTTP/3 的扩展 CONNECT）、service 以流方式接收请求体的请求、arpc 的 stream。在线程池上执行的
  handler 调用 `upgrade_websocket` / `upgrade_raw` 会返回 `false`。
- **顺序。** 不论每个请求是 inline 执行、在线程池上执行，还是被 handler 自己 detach，HTTP/1.1
  的响应都按请求顺序发出：每个请求在执行前就预留了响应位置。一个 gRPC 调用的消息逐条、按顺序交给它的
  handler，不同调用同时执行。arpc 的答复谁先完成谁先发（调用方按序号匹配），通知可能以任意顺序处理。
- **线程池满时。** 请求立即得到答复：HTTP 返回带 `Retry-After` 的 `503`，gRPC 返回
  `RESOURCE_EXHAUSTED`，arpc 返回错误 `SERVER_BUSY`（通知则被丢弃）。

从不阻塞的 handler 开启它没有好处：每个请求反而多一次交给线程池线程的开销。只在 handler 会阻塞的
地方开启；单个请求用 `detach_to_pool` 即可。

## 慢回调检测

设置了 `Config::slow_callback_threshold`（默认 100 ms）时，每个回调都会计时。超时的回调会被
计数，记入最近记录的环形缓冲（`Engine::slow_callbacks()`、调试端点），并报告给
`Config::slow_hook`；没有 hook 时写日志（target `akio`，级别 `warn`），没有安装日志实现时
打印到 stderr。每一条报告都应当作 bug 对待：I/O 线程上有东西阻塞了。
