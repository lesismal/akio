# ADR-114：借用的 WebSocket 消息与无锁发送路径

[English](114-borrowed-websocket-messages.md) | 简体中文

状态：已接受（2026-11-23）

## 背景

HttpArena 的 WebSocket 场景（gpu51，gcannon `--ws`，小文本消息）中 akio 落后于 Proa。Proa 是基于
hyper/tokio 的参赛实现，它的回显循环在读缓冲区里解析帧、就地去掩码，把每个回复追加到同一个输出缓冲区，每次读后只写
一次：

| 场景 | Proa | akio（`main`） |
|---|---:|---:|
| echo-ws 512 / 4096 / 16384 连接 | 1.32 M / 1.29 M / 1.05 M | 1.24 M / 1.21 M / 999 k |
| echo-ws-pipeline（16 条在途） | 20.4 M / 19.5 M / 15.9 M | 15.7 M / 15.2 M / 12.8 M |

akio 本来就是每次读后只写一次（事件循环在 `on_data` 前后 cork 连接），所以差距在每条消息的 CPU 开销。`main`
对每条消息：

1. 分配消息（解码器里 `Vec::with_capacity`，再 `String::from_utf8`），经过一个 `events` `Vec` 搬运，按值交给
   `on_message`；
2. 对文本做两次 UTF-8 校验：到达时增量校验一次，`String::from_utf8` 里再校验一次；
3. 获取 `WsSender` 的 `Tx` 互斥锁，换入换出两个线程局部缓冲区，把帧编码到其中一个，再在连接的写锁下复制进连接
   的发送队列。

Proa 都不做（它也不校验 UTF-8、不重组分片；akio 必须保留这两点，RFC 6455 和 Autobahn 都要求）。

## 决定

1. **借用式解码。** `Decoder::decode_ref(input, |EventRef| -> bool)` 把每条消息和控制帧以借用形式交出，借自解码
   器的缓冲区（未掩码时直接借自 `input`），只在本次调用内有效。消息缓冲区在消息之间保留（超过 64 KiB 则释放，与压
   缩缓冲区一致）。当 `input` 中有一个完整的、未分片、未压缩且不超限的数据帧时，只去掩码一次复制到该缓冲区、只做
   一次 UTF-8 校验；其他情况（分片、压缩、跨读的帧、控制帧、所有错误）走通用路径，交出的事件和错误完全相同。
   `Decoder::decode` 的 API 不变，建立在它之上。
2. **`WsHandler::on_message_ref(&WsSender, MessageRef<'_>)`**，`MessageRef::Text(&str)` | `Binary(&[u8])`。
   默认实现复制消息（`MessageRef::to_message`）后调用 `on_message`，后者现在有空的默认实现：handler 实现其中一个
   即可，已有的 handler 不受影响（拥有所有权的消息开销与以前相同）。回显、转发、只保留解析结果的解析器使用借用形
   式（规则 5：需要保留的才复制）。
3. **"plain" 发送端的无锁发送路径。** 服务端、TCP、连接未协商压缩的发送端发送不分片的消息时不再获取 `Tx` 互斥锁：
   编码这些消息不需要 `Tx` 里的任何东西。帧头（在栈上）和载荷通过 `ConnInner::send_parts` 交给连接：当字节不能
   立即写出时（在回调中，或排在已有数据之后）在连接写锁下把两者追加到队列，否则拼接后按 `send_owned` 的方式发送。
   不同线程的帧仍然不会交错：由连接的写锁排序。
4. **关闭帧不会被越过。** 没有 `Tx` 锁后，与 `close` 竞争的 plain 发送端可能把数据帧排到关闭帧之后。对 plain 发
   送端，关闭帧走 `ConnInner::send_then_close`：在同一个临界区内入队并设置 `close_after_send`，之后的发送都返回
   `Closed`。`closed` 改为无需锁即可读取的原子量。有压缩的连接、客户端（用 `Tx` 中的密钥掩码）以及 TCP 以外的传
   输（HTTP/2、HTTP/3）仍走原来的加锁路径，不变。

5. **每次读只向连接发送一次。** plain 会话的 `on_data` 执行期间，handler 发送的内容不加锁地追加到每线程的批次中
   （帧头加载荷），处理完这次读后整批一次交给连接；批次达到 64 KiB 或达到本次读开始时连接队列剩余的容量
   （`ConnInner::send_room`）时提前发送（更大的消息单独发送）。在此期间其他线程的发送进入一个小的"迟到"队列（至多
   4 MiB，超出返回 `Overloaded`），紧跟在批次之后发送；其他线程的关闭也排在那里：其他线程因 handler 发出的某条消
   息而发送的内容（它在 handler 发送之后才得知）在线上一定排在那条消息之后，与每次发送立即进入连接队列时一样。
   handler 发送控制帧、分片或预编码的消息、关闭时先把批次发出。handler 展开（panic）时由守卫关闭批次。

`send_parts`、`send_then_close` 和 `send_room` 位于 `#[doc(hidden)]` 的 `ConnInner` 上，不在 semver 承诺范围内。公开新增
（`MessageRef`、`on_message_ref`、`EventRef`、`decode_ref`、`EventRef::to_event`）都是新增；`on_message` 获得
默认实现不是破坏性变更。

## 后果

- 回显路径上每条消息：没有分配、没有锁，一次复制进（去掩码），一次复制进批次，一次 UTF-8 校验；每次读一次发送到连
  接，外加几把无竞争的锁。gpu51 上 echo-ws-pipeline 提升 12–13%（512 连接 15.7 M → 17.8 M；Proa 20.4 M），
  echo-ws 提升 1%（受系统调用限制），echo-ws-limited 和 HTTP 不变。与 Proa 余下的差距是 Proa 省掉的用户态工作
  （UTF-8），与 aegon 的差距还在于经由 io_uring 提交的发送，akio 的 io_uring 后端还没有这样做。
  测量见 docs/BENCHMARKS.zh-CN.md 的"WebSocket 回显热路径（ADR-114）"。
- Autobahn|Testsuite：服务端 298 OK + 3 informational，permessage-deflate 216/216，客户端 514 OK + 3
  informational，无上下文接管 216/216，与以前相同。
- `ws_frames` 模糊测试目标本来就检查事件和错误不依赖读的边界，这正好把整帧路径与通用路径相比较：十分钟 470 万次运行（libFuzzer，macOS arm64），没有失败。
- 既不实现 `on_message` 也不实现 `on_message_ref` 的 handler 现在能编译，但会丢弃消息；文档说明须实现其一。
- 未做：在读缓冲区里零复制去掩码（事件循环的缓冲区是共享的，对 handler 只读），以及压缩连接的无锁路径（压缩器状
  态需要互斥锁保证的顺序）。
