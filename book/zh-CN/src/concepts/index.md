# 核心概念

akio 的核心很小，所有协议 crate 都遵守几条规则。学一次就够了：

| 规则 | 章节 |
|---|---|
| **engine** 拥有若干 **listener**；每个 listener 有自己的**后端**和 I/O 线程。 | [Engine、Listener 与后端](engine.md) |
| 一个连接只属于**一个 I/O 线程**；它的 **handler** 就是它的状态，回调直接在该线程上执行。`Conn` 是线程安全的句柄。 | [Handler、Acceptor 与 `Conn`](handlers.md) |
| 回调**不能阻塞**。阻塞任务交给**逻辑线程池**；结果回到连接所属线程，预留了槽位时按顺序发出。 | [阻塞任务](blocking.md) |
| `send` 永不阻塞；队列有上限；对端跟不上时暂停读。 | [背压](backpressure.md) |
| 停机是优雅的：停止接收、通知、排空、超时后强制关闭。 | [生命周期与停机](lifecycle.md) |

这些章节的代码片段来自
[`crates/akio/examples/guide-basics.rs`](https://github.com/lesismal/akio/blob/main/crates/akio/examples/guide-basics.rs)
（运行：`cargo run -p akio --example guide-basics`）。
