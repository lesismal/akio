# ADR-189：WebSocket 的迟到队列计入节流，并以连接的上限为界

[English](189-websocket-late-queue-pacing.md) | 简体中文

状态：已采纳（2026-11-28）。akit 的 A305。

## 背景

在 akio-ws 中，不压缩的 TCP 或 TLS 服务端 WebSocket 是“plain”会话（`session.rs`，自 `26b811df`）：
其 I/O 线程处于 `on_data` 中时，handler 发送的内容收集在线程本地的批次里，读取结束时一次发出；其他
线程同时发送的内容进入迟到队列（`TxShared::late`），紧跟在批次之后发出，使得其他线程因 handler
发送的某条消息而发送的消息不会超过它。

这个队列对节流不可见，而且有自己的上限：

- `WsSender::queued_bytes` 与 `on_drain` 只报告连接的发送队列；I/O 线程处于 handler 中时它不会变化，
  而且常常为空。按 `queued_bytes` 节流的生产者（规则 8：akit 的 console 套接字在超过 256 KiB 时暂停
  console 连接的读取）从不暂停。
- 超过 `LATE_MAX`（4 MiB）后迟到的发送以 `Overloaded` 失败，而 `queued_bytes` 读数为 0，远低于连接的
  `max_queued_bytes`（默认 64 MiB）。
- `end_batch` 用 `let _ = conn.send(..)` 发送迟到字节：如果连接拒绝（超过 `max_queued_bytes`，
  `LATE_MAX` 并不考虑它），发送时返回 `Ok` 的消息被悄悄丢弃。读取中发起的关闭也会把关闭帧放在它们
  前面，之后连接以已关闭为由拒绝它们。

akit-tunnel 的加密 console WebSocket（每条消息的序号就是它的 AES-GCM nonce，丢一条消息通道就结束）
运行 `large_transfers_both_ways` 时 50 次中有 3 到 5 次以“could not be sent (overloaded)”失败，
失败时 `queued_bytes()` 都是 0。

## 决定

1. **迟到队列计为已排队。** plain 会话的 `queued_bytes` 是连接的队列，加上迟到字节（保存在队列旁边
   的一个原子量里，不加锁读取），在 I/O 线程上于读取中询问时，还加上 handler 批次中的内容。
2. **`on_drain` 等待迟到字节。** 持有迟到字节时设置的等待者与它们放在一起，读取结束、它们并入连接的
   队列时交给连接（`ConnInner::on_drain`），在该队列写完后运行。没有迟到字节时设置的等待者照旧交给
   连接（I/O 线程处于 handler 中时连接的队列不会排空，所以之后加入的迟到字节会在它运行之前并入）。
   仍以最后设置的等待者为准；abort 会立即运行暂存的等待者。
3. **只有一个上限：连接的。** 去掉 `LATE_MAX`。迟到字节、批次的预留与连接的队列之和不超过连接的
   `max_queued_bytes`：当 `late + reserved + len > send_room()` 时迟到的发送以 `Overloaded` 被拒绝。
   批次在读取开始时以及每次在读取中途发出时，从迟到字节之外的剩余空间中预留至多 64 KiB
   （`BATCH_MAX`）；批次打开期间其所有者绕过批次发送的内容（大于批次的消息、控制帧、分片或预编码
   消息、关闭）都经过迟到队列的锁，超出迟到字节留下的空间即被拒绝。因此按 `queued_bytes` 在远低于
   `max_queued_bytes` 处节流的发送方永远不会被拒绝。
4. **已接受的内容一定发出。** 批次与迟到字节以 `ConnInner::send_admitted`（隐藏）交给连接：它们在被
   接受时已按上限计算过，只会被已关闭或正在关闭的连接拒绝，绝不返回 `Overloaded`。传输层的分帧（TLS
   记录）可能让队列每条记录超出上限几个字节，而不是拒绝已告知发送方发出的内容。读取中发起的关闭在
   迟到队列的锁内先发出批次与迟到字节，再发关闭帧，因此关闭帧之后不会再接受任何内容。拒绝只可能来自
   已经在结束的连接，会话会报告这个结束（`on_close`）。

其他会话类型没有迟到队列：压缩会话与客户端会话在发送方的锁内直接发往连接，HTTP/2 与 HTTP/3 上的
WebSocket 发往其流（`WsLink`），所以它们的 `queued_bytes` 已经覆盖发送接受的全部内容。

## 影响

- akit 的节流闸门（`akit-tunnel/src/pace.rs`）在迟到队列增长时暂停 console 的读取，
  `large_transfers_both_ways` 不再遇到被拒绝的发送；akit 无需改动。
- 现在拒绝发生在连接自身会拒绝的位置（默认 64 MiB），而不是 4 MiB。
- 开销：迟到的发送需要获取连接的写锁读取 `send_room`（仅在读取进行中）；`begin_batch` 与
  `end_batch` 获取的锁与之前相同；handler 在读取中每条消息的路径不变（与其预留比较一次）。
- 在读取中设置的 `on_drain`，在没有排队内容但其他线程有迟到字节时不再立即运行，而是在它们写完后运行。

## 验证

`crates/akio-http/tests/ws.rs`：`late_sends_count_in_queued_bytes_and_are_bounded_by_the_connections_queue`
（I/O 线程被保持在一次读取中；另一线程的发送计入 `queued_bytes`，`on_drain` 在它们写完前不运行，
拒绝发生在 8 MiB `max_queued_bytes` 的一条消息加批次预留之内、超过 4 MiB，所有被接受的消息按序到达）、
`late_sends_go_before_a_close_from_inside_the_read`，以及
`a_sender_paced_on_queued_bytes_is_never_refused_while_the_handler_reads`（在 1 MiB 上限下以 256 KiB
节流发送 2000 × 16 KiB，同时客户端让 handler 保持忙碌）。`tests/tls.rs`：
`late_sends_over_tls_fill_the_connections_queue_and_all_arrive`（在 TLS 上填满到上限，所有被接受的
内容都到达）。没有这一改动时四个测试都失败。akit-tunnel 的 `large_transfers_both_ways`（akit
`efd37874`）在 gpu51 上按 akit 的测法六份同时运行，每种后端 240 次：针对 akio `5893a0ed`，epoll 失败
16 次、io_uring 失败 24 次，每次都伴随 hub 的“could not be sent (overloaded)”；针对本改动两种后端都没有
失败，也没有被拒绝的发送（单独运行每种后端也是 50 次全部通过）。
