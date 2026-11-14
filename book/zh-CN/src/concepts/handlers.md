# Handler、Acceptor 与 `Conn`

## handler 就是连接状态

```rust,ignore
pub trait Handler: Send + Sized + 'static {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]);
    fn on_close(&mut self, c: &Conn<Self>, err: Option<Error>) {}
}
```

每个连接有一个 handler 值。它在连接所属的 I/O 线程上创建，也只在那里被访问，所以它必须是
`Send`（创建一次后留在那里），但不必是 `Sync`：普通字段、`Cell`/`RefCell`、缓冲区、解析器
都可以（`Rc` 不行，因为它不是 `Send`）（ADR-003）。

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-basics.rs:handler}}
```

- `on_data` 在数据到达时被调用。TCP 是字节流：一次调用可能只有一条消息的一部分，也可能有好
  几条消息，所以要自己分帧（或者使用协议 crate）。`data` 借用的是 I/O 线程的读缓冲区（或
  io_uring 的 provided buffer），只在本次调用期间有效。每次调用最多收到
  `Config::read_buffer` 字节（io_uring 上为 16 KiB）。
- `on_close` 恰好执行一次，在所有 `on_data` 之后。正常关闭（对端 EOF 且待发数据已写完，或本端
  `close`）时 `err` 为 `None`，否则为 `Some(Error::Io(..))`，例如空闲超时产生的 `TimedOut`。
- 回调里的 panic 会关闭该连接（并报告给 `on_close`）；I/O 线程继续运行。

## acceptor 创建 handler

```rust,ignore
pub trait Acceptor: Send + Sync + 'static {
    type Handler: Handler;
    fn on_open(&self, c: &Conn<Self::Handler>) -> Self::Handler;
    fn on_shutdown(&self, c: &Conn<Self::Handler>) {}
    fn transport(&self) -> Option<Box<dyn Transport>> { None }
}
```

acceptor 由一个 listener 的所有 I/O 线程共享（所以要 `Sync`）。每个被 accept 或 dial 成功的
连接都会在其所属 I/O 线程上调用 `on_open`，返回它的 handler；`on_open` 里已经可以 `send`。
优雅停机时，每个仍打开的连接都会收到 `on_shutdown`。`transport` 在每个连接之下叠加一层字节流
变换（TLS）；见 [TLS](../protocols/tls.md)。

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-basics.rs:acceptor}}
```

acceptor 不需要任何状态的常见情况下，用 `fn_acceptor` 包装一个闭包：

```rust,ignore
Listener::tcp(addr).serve(fn_acceptor(|_c: &Conn<Echo>| Echo))
```

（Rust 的一致性规则不允许 `impl Acceptor for Fn(&Conn<H>) -> H` 这样的覆盖实现，所以需要
这个包装。）

## `Conn`：线程安全的句柄

对任意 `H`，`Conn<H>` 都是 `Clone + Send + Sync`（ADR-002）。类型参数只用来给
`spawn_blocking` 的完成回调定类型；句柄本身是指向共享连接状态的 `Arc`。

| 方法 | 作用 |
|---|---|
| `send(&[u8])` | socket 能写就立即写，剩下的排队（复制）。永不阻塞。 |
| `send_owned(Vec<u8>)` | 同上，排队部分不复制。 |
| `send_shared(SharedBuf)` | 同上，使用引用计数缓冲区：广播只编码一次。 |
| `send_segments(Vec<u8>, size)` | UDP：一次发多个数据报（Linux 上尽量用 GSO / `sendmmsg`）；TCP 上等同 `send_owned`。 |
| `cork()` / `flush()` | 合并写直到 `flush`（回调内自动如此）。 |
| `close()` | 立即关闭，丢弃未发送的数据。 |
| `close_after_send()` | 排队的数据写完后关闭；之后的发送失败。 |
| `hold_reads(bool)` | 暂停 / 恢复读取对端数据。 |
| `on_drain(f)` | 发送队列清空（或连接关闭）时调用 `f`。 |
| `queued_bytes()` | 已接受但尚未写出的字节数。 |
| `spawn_blocking(work, done)` | `work` 在逻辑线程池执行，`done` 回到 I/O 线程执行。 |
| `reserve_response()` | 预留一个有序响应位置。 |
| `id()`、`is_open()`、`peer_addr()`、`local_addr()` | 标识与状态。 |
| `with_transport(f)` | 查看 transport 层（见 `flash::tls::tls_info`）。 |

连接关闭后再使用句柄会返回 `Error::Closed`：既不会 panic，也不会碰到被复用的文件描述符。
连接关闭*并且*所有句柄都被 drop 之后，描述符才会释放。

### 从其他线程发送

```rust,ignore
{{#include ../../../../crates/flash/examples/guide-basics.rs:cross_thread}}
```

在所属线程上，队列为空时 `send` 直接写 socket。在其他线程上，它先拿连接的写锁，同样尝试
直接写，把剩下的排队，然后唤醒所属的事件循环去刷出。这把锁只保护发送队列，你的代码运行时
从不持有它，因此不必担心锁顺序导致的死锁。

在回调（`on_open`、`on_data`、`spawn_blocking` 的完成回调）里发送的所有数据都处于 cork
状态：回调返回时合并成一次 `writev` 发出。

### 错误

`Conn` 的操作返回 `flash::Result<T>`，错误类型为 `flash::Error`：

| 变体 | 含义 |
|---|---|
| `Closed` | 连接已关闭或正在关闭；操作没有生效。 |
| `Overloaded` | 发送队列超过 `Config::max_queued_bytes`，或逻辑线程池队列已满。 |
| `Io(io::Error)` | 操作系统错误（连接正在被关闭）。 |

## 经验法则

- 永远不要在回调里阻塞：不要阻塞 I/O，不要长时间持有 `Mutex`，不要 `thread::sleep`，不要等
  channel。用 `spawn_blocking`，或另起线程并带上克隆的 `Conn`。
- 每连接状态放在 handler 里；共享状态放在 acceptor 里（用 `Arc` 和 `Sync` 类型）。
- 回调之后还要用 `data`，就复制它。
