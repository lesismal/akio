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

## 在协议 crate 中

协议 crate 用各自的方式提供同样的思路；handler 从不阻塞，答复可以稍后从任何线程发出：

| crate | 机制 |
|---|---|
| akio-http | `Context::detach()` 返回 `Detached`，可在任何线程上 `respond`；流水线响应保持顺序。 |
| akio-ws | `WsSender` 是 `Clone + Send + Sync`，可在任何线程发送。 |
| akio-grpc | 交给方法的 `Sink` 可以在任何线程使用。 |
| akio-arpc | `Context::detach()` 返回 `Responder`。 |
| akio-quic / akio-kcp | `Connection` / `Session` 是可克隆的句柄，可在任何线程发送。 |

它们提供的是"稍后答复"这一半；工作本身放在哪里执行由你决定：自己的线程、自己的线程池，
或者另一个运行时（[从 tokio 迁移](../migration/from-tokio.md)展示了衔接方式）。对于原始的
`Handler`，`Conn::spawn_blocking` 使用 engine 的线程池。

## 慢回调检测

设置了 `Config::slow_callback_threshold`（默认 100 ms）时，每个回调都会计时。超时的回调会被
计数，记入最近记录的环形缓冲（`Engine::slow_callbacks()`、调试端点），并报告给
`Config::slow_hook`；没有 hook 时写日志（target `akio`，级别 `warn`），没有安装日志实现时
打印到 stderr。每一条报告都应当作 bug 对待：I/O 线程上有东西阻塞了。
