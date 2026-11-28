# ADR-188：关闭时仍有未交付输入的连接会重置对端，io_uring 与 epoll 一致

[English](188-close-resets-undelivered-input.md) | 简体中文

状态：已采纳（2026-11-28）。akit 的 A302。

## 背景

akit 在 FastCGI 连接的客户端离开时，会在响应中途放弃这个连接：应用仍在写入时调用 `Conn::close`。
在 epoll 上应用立即得知：`finalize` 先 `shutdown(Both)` 再关闭套接字，Linux 发现有已接收但未读的数据，
发送重置，应用的下一次写入随即失败，与 fit 中 Go 的 `net.Conn.Close` 效果相同。在 io_uring 上，偶尔
应用会一直阻塞，直到内核丢弃 akio 已成孤儿的套接字（`tcp_fin_timeout`，60 秒）：`ss` 显示 akio 一侧处于
FIN-WAIT-2 且没有排队数据，应用一侧处于 CLOSE-WAIT，几 MB 数据未发出，面对的是零窗口。

机制已在 Linux 7.0 上验证（`tests/close_reset.rs` 的 `a_close_right_after_resuming_reads_resets_the_peer`，
没有本改动时失败）：在 `finalize` 的 shutdown 之后才进入内核的 multishot recv（与恢复读取同一轮内提交，
或者因 `DEFER_TASKRUN` 推迟到循环下次进入内核时才重试），仍会取走套接字中已排队的数据：
`shutdown(SHUT_RD)` 并不阻止读取已排队的数据。循环忽略这些完成事件（连接已不存在），于是最终关闭时
没有未读数据，只发 FIN，不发重置。而且 Linux 对 `SHUT_RD` 之后读走的数据不发送窗口更新
（`tcp_cleanup_rbuf`），已经填满窗口的对端看到的始终是零窗口：孤儿套接字变成 FIN-WAIT-2 的 time-wait
套接字，保留它最后通告的窗口，只回应对端的探测，从不重置它。

## 决定

1. **`Conn::close` 在所有后端含义一致**：关闭时若 TCP 连接还有从未交给 handler 的输入，就在 shutdown
   发出的 FIN 之后重置对端。在 epoll 上这是 Linux 对关闭时仍有未读输入的套接字的固有规则。io_uring
   后端现在给出相同结果：
   - 已读取但被暂存的输入（读取暂停：`held_in`），或在 handler 关闭之后、循环的 `finalize` 运行之前
     读到的输入，会在 `finalize` 时对套接字设置 `SO_LINGER {on, 0}`；
   - `finalize` 时仍在进行的 multishot recv 会让连接的套接字保持打开（`Loop::reads_ending`），直到它的
     最终完成事件，同时提交一个取消请求保证它结束；如果它在此期间取走了输入，则在释放套接字之前设置
     `SO_LINGER {on, 0}`。如果取消先生效，输入留在队列中，内核自己会发送重置。
   重置在套接字的最后一个引用释放时发出：立即，或者在最后一个 `Conn` 句柄被丢弃时，与 epoll 相同。
2. **akit 不需要新 API。** 不新增 `Conn::abort`（请求中的方案 (b)：总是重置）；读完对端全部数据的连接
   在两个后端上仍然只以 FIN 结束，因此 `close_after_send` 之前写出的响应不会被重置截断。
3. **akio-sys 新增 `reset_on_close(&TcpStream)`**（`SO_LINGER {on, 0}`），以及绑定 `SO_LINGER` 和
   `struct linger`（与 `libc` 对照检查）。

## 后果

- akit 的 FastCGI `cut_connections` 在 io_uring 上通过：应用的写入与 epoll 上一样被重置。akit 无需改动。
- macOS（kqueue）不变：它的协议栈对关闭时仍有未读输入的套接字发送 FIN、丢弃这些输入，并对对端的下一个
  报文段回复重置，因此仍在写入的对端在那里同样会被重置，只是晚一个报文段。`Conn::close` 的文档写明了这一点。
- io_uring 上的开销：关闭一个 recv 已就绪的连接时多提交一个取消请求（其完成事件被忽略），并把套接字的
  `Arc` 放在一个表中，直到 recv 的最后一个完成事件，而 shutdown 会让它立即到来。数据路径不变（正在关闭的
  连接每个完成事件多一次标志检查）。
- 测试（`crates/akio/tests/close_reset.rs`，两个后端）：上传中途关闭、对端填满窗口时循环正忙、读取被暂停，
  这三种情况下写入方都在 20 秒期限内被重置；恢复读取后立即关闭的竞争会重置已停止写入的对端（Linux）；
  读完整个请求并在应答之后关闭的连接仍以 FIN 结束。
