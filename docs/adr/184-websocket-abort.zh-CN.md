# ADR-184：立即结束 WebSocket，丢弃排队的数据

[English](184-websocket-abort.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A238。

## 背景

隧道链路在出错时（帧无法解析、违反其协议）、hub 踢出对端或吊销其令牌时，以及角色停止时，会立即关闭，
丢弃已排队的数据：fit 的 WebSocket 传输调用 `Abort`，正如它的 TCP、TLS 和 QUIC 链路调用 `Close`。
akio-ws 的 `WsSender` 只有 `close(code, reason)`：它把关闭帧排在已排队的数据之后（隧道链路可能排着
数百 MiB），写出后才关闭（服务端），或等对端回应、或等到 `close_timeout`（客户端）。于是被踢出或出错的
WebSocket 链路会继续发送已排队的数据，客户端还要等待对端。WebSocket 之下的传输可能是 TCP 或 TLS 连接、
HTTP/2 流（RFC 8441）或 HTTP/3 流（RFC 9220），服务端和客户端都有；发送端无法让它立即结束。

## 决定

1. **`WsSender::abort(&self)`**，与 `close` 并列，可在任意线程和 handler 的回调中调用：把发送端标记为
   已关闭（之后的发送以 `Closed` 失败）和已中止（handler 不再收到任何内容：`WsSession::on_data`
   丢弃其后的数据，回调中的中止会停止该次读取的其余部分），丢弃普通会话的批次和其他线程迟到队列中
   收集的数据，并让传输立即结束。不发关闭帧：对端看到传输结束，如同进程退出，这正是 `on_close` 的
   1006（RFC 6455 第 7.1.5 节）向两端报告的。再次中止，以及中止后的 `close`，什么也不做；中止会截断
   进行中的关闭握手。
2. **由传输自己结束。** akio-ws 中 doc-hidden 的 `WsLink` 增加 `abort()`，默认调用 `close()`；
   每种传输各自实现：
   - **TCP 或 TLS**：连接的 `close()`，丢弃未发送的数据；随后 `on_close` 在 I/O 线程上通知会话
     （1006）。不发 TLS `close_notify`：中止不是干净的结束。
   - **HTTP/2 服务端**：无论流两半的状态如何，都发 `RST_STREAM CANCEL`（`close` 在对端已结束其一半时
     以 END_STREAM 结束我方一半）；流的队列随之丢弃，停放的会话在核心锁之外被丢弃，收到 1006。
   - **HTTP/2 客户端**：链路队列新增一种结束方式 `Abort`（高于 `Now`），连接的事件循环据此丢弃已排队的
     数据并重置流（`CANCEL`），即使服务端已结束其一半；流上的 WebSocket 随流消失收到 1006。
   - **HTTP/3**（两端）：以 `H3_REQUEST_CANCELLED` 发 `RESET_STREAM` 和 `STOP_SENDING`（丢弃 QUIC
     发送缓冲区），然后由连接的 handler 结束会话。会话属于 handler，而 QUIC 只把对端的重置告诉
     handler，不告诉它自己的；已经结束其一半的对端对 `STOP_SENDING` 不作任何回应。因此 akio-quic
     新增 `Connection::notify()` 和 `QuicHandler::on_notify(&mut self, c)`：一个标志，由投递循环在
     事件之后检查（与 `on_shutdown` 相同），让 handler 在投递该连接事件的线程上执行其他线程留给它的
     工作，每批调用一次，且绝不在 `on_close` 之后。akio-h3 把被中止的流放入每个连接的列表并通知；
     它的 `on_notify` 遗忘该流（会话收到 1006，排空等待者运行）。全部在
     `Connection::without_driving` 中完成，因此持有 handler 回调也会获取的锁的线程中止时，不会就地
     运行那些回调。
3. **在 HTTP/2 和 HTTP/3 上连接继续存在**：中止只结束一个 WebSocket，不结束承载它和其他流的连接
   （与重置请求流相同）；已组帧到共享连接上的字节仍会发出。

## 影响

- akit 的 `WsWire::close`（链路出错、踢出、令牌吊销、角色停止）改为中止，正如 `ConnWire::close`
  关闭 TCP 链路；LLM 网格的链路同样如此。
- 代价：WebSocket 会话每次读取和每条交付的消息多读一个原子标志；QUIC 连接的投递循环每轮多读一个
  标志。DEV-PLAN 第 4 节写明了基准任务应测量的内容。
- 测试（akio-http `tests/ws_abort.rs` 覆盖明文和 TLS 上的 HTTP/1.1 以及 HTTP/2，akio-h3
  `tests/ws_abort.rs` 覆盖 HTTP/3，akio-quic `tests/control.rs` 覆盖 `notify`）：任一端在对端暂停读取、
  己方积压未发出时中止（其发送立即失败，两端各收到一次 1006，对端收到的少于已发送的）、没有积压时
  中止，以及在 handler 回调中中止（之后没有任何交付）；在 HTTP/1.1 上截断客户端的关闭握手；在 HTTP/2
  和 HTTP/3 上连接和其上另一个 WebSocket 继续工作；从其他线程、在 `without_driving` 中、在回调中调用
  两次（回调之后运行一次）以及关闭之后（不运行）的 `notify`。
- 未做：中止一方使用 1006 以外的状态码（它什么也没发，两端看到的都是 1006）；用 TCP RST
  （`SO_LINGER` 为 0）代替 `close` 的 FIN。
