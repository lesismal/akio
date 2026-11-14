# 从 tokio 迁移

tokio 是通用的异步运行时；flash 是没有运行时的网络库。两者解决的问题有重叠，形态却不同，而且
可以共存于同一个进程。

## 思维模型

| tokio | flash |
|---|---|
| 每连接一个任务，带 `.await` 点的 `async fn` | 每连接一个 `Handler`，回调（`on_data`、`on_close`） |
| 工作窃取调度：任务可能在任意 worker 上恢复 | 每核一线程：连接永远不离开它的 I/O 线程 |
| 状态存在任务的 future 里（共享时常用 `Arc<Mutex<..>>`） | 状态存在 handler 里（`&mut self`，无锁，无需 `Sync`） |
| `socket.read(&mut buf).await` 拉取数据 | `on_data(&mut self, c, data)` 推送数据 |
| `socket.write_all(&buf).await` 等待缓冲区空间 | `c.send(&buf)` 从不等待：写出或排队，由水位线限制 |
| 用 `tokio::spawn` 获得并发 | 并发以连接为单位；I/O 线程上没有可 spawn 的东西 |
| `tokio::task::spawn_blocking(f).await` | `c.spawn_blocking(work, done)`：`done` 回到连接所属线程执行 |
| `tokio::time::timeout`、`sleep` | `Config::idle_timeout`；其他需求用你自己的定时器线程 |
| 用 `tokio::sync::mpsc` 与连接任务通信 | 克隆 `Conn`，在任何地方调用 `send`/`close` |
| `CancellationToken` / drop 掉任务 | `Conn::close()`、`Engine::shutdown()` |
| `tokio::net::TcpListener::bind` + accept 循环 | `Listener::tcp(addr).serve(acceptor)` |
| 上层的 hyper / axum | 上层的 flash-http（[指南](from-hyper-axum.md)） |

作为对比，tokio 中的 echo 服务（不作为本书的一部分编译）：

```rust,ignore
// tokio
let listener = tokio::net::TcpListener::bind("127.0.0.1:7000").await?;
loop {
    let (mut sock, _) = listener.accept().await?;
    tokio::spawn(async move {
        let mut buf = vec![0; 4096];
        loop {
            let n = match sock.read(&mut buf).await { Ok(0) | Err(_) => return, Ok(n) => n };
            if sock.write_all(&buf[..n]).await.is_err() { return; }
        }
    });
}
```

flash 版本见 [echo 示例](../getting-started.md#一个-tcp-echo-服务)：没有 accept 循环，没有任务，
不需要管理缓冲区；engine 读入每线程的缓冲区后调用你的代码。

## 代码中需要改变的地方

1. **解析变成增量式。** 你无法 `.await`"接下来的 4 个字节"。在 handler 中保存一个缓冲区或
   解析器状态机，把每次 `on_data` 的切片喂给它（大多数协议 crate 以及本指南的行协议就是这样
   做的）。
2. **handler 内没有 `.await`。** 任何需要等待的东西都放到别处：阻塞代码用 `spawn_blocking`，
   异步代码交给其他线程或运行时，回复通过 `Conn`（或 `Detached`、`WsSender`、`Sink` 等）送回。
3. **背压是显式的。** 不再是 `write_all` 挂起任务，而是关注 `queued_bytes()`，转发时使用
   `hold_reads`/`on_drain`，并处理 `Error::Overloaded`（[背压](../concepts/backpressure.md)）。
4. **共享状态** 从任务捕获的 `Arc<Mutex<..>>`，变成 acceptor 的字段（共享、`Sync`）和 handler
   的字段（每连接、不共享）。

## 何时使用逻辑线程池

任何可能等待超过几微秒、或占用超过零点几毫秒 CPU 的工作，都用 `Conn::spawn_blocking`（或
`Context::detach` 加你自己的线程）：同步数据库驱动、文件 I/O、域名解析、压缩大 body、密码
哈希、调用阻塞的 SDK。解析、路由、小规模序列化和内存查找保持直接执行：它们比交接的开销还小。

开发时调低 `slow_callback_threshold`，找出遗漏的地方。

## 衔接 flash 与 tokio

flash 的句柄是 `Send + Sync`，客户端结果是 `Future`，所以两个世界可以互相调用。

**从 flash 到异步代码。** detach 请求（或保留 `Conn`），通过 channel 把任务交给另一个运行时，
在那里答复：

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:worker}}
```

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:handoff}}
```

换成 tokio 时，`start_worker` 会是一个运行时（`tokio::runtime::Runtime::new()`），channel 用
`tokio::sync::mpsc::UnboundedSender`（它的 `send` 不阻塞，因此可以在 I/O 线程上调用），循环
写成 `while let Some(job) = rx.recv().await { tokio::spawn(..) }`，每个任务最后调用
`job.reply.respond(..)`。`Detached::respond`、`Conn::send`、`WsSender::send_text` 等句柄从不
阻塞，所以在异步任务里调用它们没有问题。

**从异步代码到 flash。** flash-http 的 `ResponseFuture`（HTTP/1 与 HTTP/2 客户端）和
flash-arpc 的 `CallFuture` 实现了 `Future`：可以在任何执行器里 `.await`。连接本身运行在 flash
的 I/O 线程上；future 在那里完成并唤醒你的任务。

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:await}}
```

为了不给仓库引入 tokio 依赖，示例用一个十行的 `block_on` 代替 tokio：

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-bridge.rs:block_on}}
```

**在同一进程中同时运行两者。** 构建 flash engine，`start()`，保存在 `Arc` 中，然后照常运行
tokio 运行时。在 tokio 的停机流程里调用 `engine.shutdown()`，并在阻塞上下文
（`spawn_blocking`）中调用 `engine.wait()`，因为 `wait` 会阻塞。

需要避免的：

- 在 tokio 任务内部调用阻塞等待（`ResponseFuture::wait`、`client::connect`、
  `GrpcClient::unary`）：能 `.await` 就 `.await`，否则用 `spawn_blocking`；
- 在 flash 的 I/O 线程上调用这些阻塞辅助函数：它们可能因为等待被自己阻塞的那个线程而死锁；
- 在 flash 回调里 `block_on`。

## 异步适配

1.0 之前不计划提供基于 `Future` 的 flash 连接适配器（`Conn::spawn(async ..)`）（见 ROADMAP
的非目标）。如果要完全异步的技术栈，tokio 加 hyper/axum 仍是自然的选择；当你需要每核一线程的
回调、显式背压和按 listener 选择后端（io_uring、eBPF 分流）时，flash 更合适。
