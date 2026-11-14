# 背压

`send` 永不阻塞。这保证了 I/O 线程的安全，但也意味着快生产者遇到慢消费者时，数据会堆积在
内存里，除非有东西把压力推回去。only 在三个层面推回压力。

## 1. 连接自身队列过高时暂停读

当一个连接排队的数据达到 `Config::write_high_watermark`（默认 256 KiB）时，only 停止从它
读取，队列降到该值的四分之一时恢复。因此，一个只管发流水线请求而不读响应的客户端会让自己
变慢，而不会让服务端内存增长。每次暂停都会计数（`only_backpressure_events_total`），并在
连接表中按连接显示。

## 2. 超过硬上限时 `send` 失败

每个连接排队超过 `Config::max_queued_bytes`（默认 64 MiB）时，`send*` 返回
`Error::Overloaded` 并且不排队任何数据（计入 `only_overloaded_total`）。把它理解为"这个
对端跟不上了"：关闭它、丢弃这条消息，或者停止生产。

在回调之外运行的生产者（流式发送文件的线程、广播者）应当用 `queued_bytes()` 控制节奏；在
HTTP 中用 `ResponseStream::queued_bytes` / `BodyStream::queued_bytes`，不要等到 `Overloaded`。

## 3. 转发：`hold_reads` + `on_drain`

数据从连接 A 流向连接 B 时（代理、隧道、汇聚），增长的是 B 的队列。B 落后时停止读 A，B 排空
后恢复读 A：

```rust,ignore
{{#include ../../../../crates/only/examples/guide-basics.rs:backpressure}}
```

- `hold_reads(true)` 停止读取对端数据（随后内核接收缓冲区被填满，TCP 流控让发送方变慢）。
  `hold_reads(false)` 恢复。
- `on_drain(f)` 在该连接排队的数据全部写出后调用 `f`；没有排队数据时立即调用；连接关闭时也
  会调用。它是一次性的：下次需要时再注册。

only-socks 正是这样在两个方向上转发的。

## 线程池与协议

- 逻辑线程池队列有上限（`PoolConfig::queue_capacity`）：`spawn_blocking` 返回 `Overloaded`，
  而不是无限排队。
- HTTP/2 在两个方向上执行流控，并限制一个响应为慢对端积压的数据量
  （`H2Config::max_pending_bytes`）。
- QUIC（`Connection::queued_bytes(stream)`）和 KCP（`Session::send` 返回 `KcpError::Full`、
  `Config::write_queue`）暴露各自的发送窗口。
- UDP 没有背压：socket 拒收的数据报被丢弃，这是 UDP 允许的。

## 值得设置的上限

| 配置项 | 默认值 | 用途 |
|---|---|---|
| `write_high_watermark` | 256 KiB | 积压很多的连接暂停读 |
| `max_queued_bytes` | 64 MiB | 每连接内存硬上限 |
| `max_connections` | 0（不限） | 打开的连接超过此数后拒绝新 accept |
| `idle_timeout` | 无 | 关闭长时间没有发来数据的连接 |
| `HttpConfig::max_body_bytes` | 1 MiB | 缓冲的请求 body 上限（超出返回 413） |
| `PoolConfig::queue_capacity` | 65,536 | 有界的阻塞任务队列 |

前四项都可以在运行时通过 `Engine::reload` 修改。
