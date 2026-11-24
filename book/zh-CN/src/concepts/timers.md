# I/O 循环上的定时器

每个 I/O 线程都有一个时间轮。`akio::timer::after` 把一个闭包放到**调用它的** I/O 线程的时间轮上；
到期时，由同一个线程在两次 poll 之间执行它，和其他回调一样。不加锁，不经过别的线程，也不需要唤醒：
循环本来就不会睡得比它的下一个定时器更久。

```rust,ignore
pub fn after(delay: Duration, f: impl FnOnce() + 'static) -> Result<Timer>
```

- 在回调里调用（`on_data`、`on_close`、`spawn_blocking` 的完成回调、另一个定时器）。在其他线程上
  调用返回 `Error::Closed`：那里没有循环来执行它。
- `f` 不需要 `Send`：它不会离开这个线程，可以捕获 `Rc` 等绑定线程的 handler 状态。
- 绝不提前执行。它在至少 `delay` 之后的第一次循环迭代中执行，通常误差在一毫秒内（时间轮以毫秒计），
  线程忙时会更晚。
- `Timer::cancel()` 丢弃闭包而不执行（须在设置它的线程上调用）。丢弃 `Timer` 句柄**不会**取消定时器。
- 一个循环最多持有 `timer::MAX_TIMERS_PER_LOOP`（约一百万）个定时器，超过后 `after` 返回
  `Error::Overloaded`。超过 `timer::MAX_DELAY`（约 49 天）的延迟会被截断。
- 循环退出（停机、`set_threads` 缩减线程）时仍未到期的定时器被丢弃，不会执行。某个定时器 panic
  会被捕获并记录日志，其余照常执行。

闭包捕获连接句柄，是回到连接的常见方式：

```rust,ignore
impl Handler for Delayed {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (c, reply) = (c.clone(), data.to_vec());
        // 10 ms 后在同一个线程上回复。
        let _ = akio::timer::after(Duration::from_millis(10), move || {
            let _ = c.send(&reply);
        });
    }
}
```

如果连接在此期间已关闭，`send` 返回 `Error::Closed`，别的什么也不会发生。

## 稍后回复 HTTP 请求

`akio_http::Context::after` 分离（detach）请求，在延迟过后于连接自己的线程上把 `Detached` 交给闭包：

```rust,ignore
fn delayed(ctx: &mut Context) {
    ctx.after(Duration::from_millis(10), |d| d.respond(Response::text(200, "late")));
}
```

HTTP/1.1 流水线请求仍按请求顺序应答；HTTP/2 和 HTTP/3 的流在各自定时器触发时应答。在非 I/O 线程上
调用时，`Context::after` 退回到 akio-http 共享的定时器线程。

## 怎么选

| 你想要 | 用 |
|---|---|
| 稍后在这个连接的线程上做点事（延迟回复、重试、单请求截止时间、心跳） | `akio::timer::after` / `Context::after` |
| 关闭长时间没有动静或写阻塞的连接 | `Config::idle_timeout`、`Config::write_timeout` |
| 执行阻塞任务再回来 | [`spawn_blocking`](blocking.md) |
| 从引擎外部触发（调度器，与任何连接无关的时钟） | 自己的线程，通过 `Conn` 发送 |

自己的定时器线程仍然可用，但每个回复都要跨线程：加锁入队、在别的线程上写、唤醒循环。在 HttpArena 的
`async` 场景（32,000 个连接，每个请求等待 10 ms）中，这条路径大约损失五分之一的吞吐；测量数据见
ADR-103。
