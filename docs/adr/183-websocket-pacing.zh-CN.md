# ADR-183：WebSocket 的读取暂停、排空通知与对端地址

[English](183-websocket-pacing.md) | 简体中文

状态：已采纳（2026-11-27）。akit 的 A236。

## 背景

隧道链路以及 LLM 网格的链路承载许多流，这些流的字节来自其他连接。链路的队列超过高水位时，暂停向它
供数据的一方，队列排空后恢复；链路交付的内容无法继续写出时，暂停链路自己的读取，使对端的窗口让它
停下（规则 8 和 9；fit 的 WebSocket 链路与 TCP 链路一样有 `SetReadPaused` 和 `OnDrain`）。akio-ws
的 `WsSender` 只有 `queued_bytes`：无法停止读取 WebSocket，队列排空时没有回调，也没有对端地址（hub
按地址的限额和访问策略需要它）。akio-ws 和 akio-http 的升级胶水代码（`Context::upgrade_websocket`）
都没有触及底层传输的 `hold_reads` 或 `on_drain`；底层传输可能是 TCP 或 TLS 连接、HTTP/2 流（RFC 8441）
或 HTTP/3 流（RFC 9220），服务端和客户端都有。

## 决定

1. **`WsSender` 上的方法**，即应用本就持有并可在任意线程使用的句柄，而不是 `WsHandler::on_drain`
   回调：`hold_reads(bool)`、`on_drain(FnOnce)`、`peer_addr() -> Option<SocketAddr>`、
   `set_relayed(bool)` 和 `set_max_queued_bytes(Option<usize>) -> Result<()>`。它们与 `Conn` 的
   方法对应，因此中继可以把 WebSocket 链路映射到与 TCP 链路相同的抽象上；按次设置的等待者（以最后
   设置的为准）不需要在库中配置水位，空闲会话也不需要状态。
2. **由传输完成工作。** akio-ws 中 doc-hidden 的 `WsLink`（非 TCP 传输）增加带默认实现的
   `hold_reads`、`on_drain` 和 `peer_addr`；每种传输用它已有的机制实现：
   - **TCP 或 TLS**（服务端经由 `Context::upgrade_websocket`，客户端经由 `akio_ws::client`）：连接的
     `hold_reads`、`on_drain`、`peer_addr`、`set_relayed` 和 `set_max_queued_bytes`（ADR-181）。
   - **HTTP/2 服务端**：流式请求体所用的流 `held` 标志（暂停期间不归还窗口；恢复时立即归还），以及
     流式响应的排空等待者（流的字节全部组帧后，或流消失时），二者提取为共用函数。
   - **HTTP/2 客户端**：在 WebSocket 的流上做同样的事：链路共享状态中的暂停标志（DATA 记为欠下的窗口
     而不是立即归还；恢复时把窗口更新投递到连接的事件循环），以及当链路的排队字节在某个 DATA 帧中
     降到 0，或流被放弃、消失时运行的排空等待者。
   - **HTTP/3**（两端）：请求流上的 `Connection::hold_reads`（到达的数据留在 QUIC 流的缓冲区中），
     以及连接按流保存的排空等待者，在流变为可写、被 stop、被 reset 或被遗忘、或连接关闭时运行。
3. **排空即 `queued_bytes()` 为 0**，与应用调速所依据的量相同：TCP 上是连接的队列，HTTP/2 上是流中
   尚未组帧的字节。在 HTTP/3 上，QUIC 报告的是流发送缓冲区有空间，而不是为空（超出的写入被拒绝，
   在四分之三处报告有空间），因此等待者在缓冲区有空间时运行，与流式响应的 `BodyStream::on_drain`
   （ADR-101）相同；文档中如实说明。
4. **在 handler 回调内设置的等待者**：在普通 TCP 会话上，先把回调到目前为止发送的内容（会话的批量
   缓冲，尚未进入连接的队列）移入连接的队列，因此它在这些内容发出后、回调结束之后运行，而不是立即
   运行。
5. **中继标记和自己的上限属于连接。** 在 HTTP/2 和 HTTP/3 上，流的读取从不因为自己的输出而暂停，
   连接也是共享的：`set_relayed` 在那里不做任何事，`set_max_queued_bytes` 以 `Unsupported` 失败（流的
   队列由 `H2Config::max_pending_bytes`、`H2WsOptions::max_queued_bytes` 或 QUIC 的发送缓冲区限定）。
6. **`dial_blocking` 的包装转发 `on_message_ref`。** `akio_ws::client` 的 `dial_blocking` 为交回
   sender 而包装 handler，原先只转发 `on_message`，因此只实现 `on_message_ref` 的 handler（trait 允许
   这样）什么也收不到；现在两者都转发。

## 影响

- akit 的 WebSocket 链路把 `hold_reads`、`on_drain`、`queued` 和 `peer` 映射到这些方法上，与它的 TCP
  链路映射到 `Conn` 上一样；LLM 网格在某个流的读者慢于其窗口时暂停链路的读取。
- 开销：HTTP/2 客户端 WebSocket 每收到一个 DATA 读一次原子标志；其链路状态多一个标志和一个等待者
  槽位；HTTP/3 WebSocket 链路持有其连接排空表的一个 `Arc`。数据路径上没有别的变化。DEV-PLAN 第 4 节
  写明了基准任务应测量的内容。
- 测试（akio-http `tests/ws_pacing.rs`、akio-h3 `tests/ws_pacing.rs`，在各套件运行的后端上）：在
  HTTP/1.1、HTTP/2 和 HTTP/3 上，一端暂停读取，另一端发送直到积压（不再交付，发送方的等待者不运行），
  然后恢复（全部交付，等待者在 I/O 线程上运行，之后设置的等待者立即运行）；两端的对端地址；在 TCP 上，
  回调内设置的等待者在回调之后运行、中继连接在超过高水位后仍然读取，以及自己的上限恰好低于、等于和
  超过它；HTTP/2 和 HTTP/3 拒绝自己的上限；HTTP/3 WebSocket 关闭后设置的等待者。
- 未做：在 HTTP/3 上，对端正常结束其一半的流上的等待者，在流下次可写、被 stop 或连接关闭时运行，而
  不是在 WebSocket 会话结束时运行；请求中的备选方案 `WsHandler::on_drain` 回调没有添加。
