# ADR-060：HTTP/2 上的 WebSocket（RFC 8441）

[English](060-h2-websocket.md) | 简体中文

状态：已采纳（2026-11-20）

## 背景

ADR-011 通过现有 API 把 WebSocket 带到了 HTTP/3（RFC 9220）：服务端在 `Context::upgrade_websocket`
中接受 extended CONNECT，`Router` 用该路径的 GET 路由应答它，客户端用 `H3Client::websocket` 打开，
only-ws 通过隐藏的 `WsLink` 接缝写出。HTTP/2 当时没有做：`upgrade_websocket` 在 HTTP/2 流上应答 400，
服务端不宣告 `SETTINGS_ENABLE_CONNECT_PROTOCOL`，带 `:protocol` 的请求是畸形请求，`H2Client` 也没有
WebSocket。浏览器在服务端允许时会在已持有的 HTTP/2 连接上打开 WebSocket，所以 h2 源站会迫使它们另开一条
HTTP/1.1 连接；我们自己的客户端也无法让请求和 WebSocket 共用一条连接。

## 决策

1. **服务端：与 HTTP/1.1 和 HTTP/3 相同的 API。** HTTP/2 服务端宣告 `SETTINGS_ENABLE_CONNECT_PROTOCOL`
   （RFC 8441 §3），并接受 CONNECT 上的 `:protocol`，此时要求 `:scheme`、`:path` 和 `:authority`
   （§4；其他情况，或其他方法上的 `:protocol`，都是 `RST_STREAM PROTOCOL_ERROR`）。请求带着
   `Request::protocol` 交给服务，流保持打开，与流式请求一样；`Router` 用该路径的 GET 路由应答
   `websocket` 的 extended CONNECT（沿用 ADR-011），所以一个 `.get("/ws", ...)` 同时服务 HTTP/1.1、
   HTTP/2 和 HTTP/3 上的 WebSocket。`Context::upgrade_websocket` 与 HTTP/3 一样检查版本 13 和 origin
   策略、协商子协议和 `permessage-deflate`，只应答 `200` 的头部，HTTP/2 会话把一个 `WsSession`（经
   `WsLink`）挂在该流上：此后它的 DATA 帧就是 WebSocket 的字节。请求其他 `:protocol` 是由服务应答的
   普通请求。`H2Config::enable_connect_protocol`（默认**开启**）可整体关闭：不宣告，`:protocol` 重新
   视为畸形。
2. **客户端：** `H2Client::websocket(url, &H2WsOptions, handler, done)` 与 `websocket_blocking(..)`，
   在客户端已有的连接上与请求并存。URL 可以是 `http`、`https`、`ws` 或 `wss`（只用来给出 `:scheme`、
   `:authority` 和 `:path`）。它先等服务端的第一个 SETTINGS（§3）；服务端应答 2xx 后（`on_open` 已
   运行）`done` 得到 `WsSender`，否则得到原因：拒绝时为新增的 `ClientError::Status(u16)`（该枚举是
   `#[non_exhaustive]`），服务端不允许 extended CONNECT 时为 `ClientError::Protocol`，超过
   `H2WsOptions::timeout` 时为 `ClientError::Timeout`。`H2WsOptions` 对应 `H3WsOptions`（config、
   deflate 提议、子协议、origin、额外头、关闭超时），另加 `timeout`（10 秒）和 `max_queued_bytes`
   （8 MiB）。
3. **流量控制与背压。** 每个 WebSocket 是一条有自己窗口的流。收到的数据随到随解码，所以接收窗口随消费
   归还（服务端按四分之一批量归还，与其他流相同；客户端立即归还，与其响应相同）；对端 WebSocket 受我方
   窗口和 `max_message_bytes` 约束。我方发送的数据等待流和连接的发送窗口：服务端排在流的队列中，超过
   每流 `H2Config::max_pending_bytes` 或每连接 `max_conn_pending_bytes` 后发送返回 `Overloaded`；客户端
   排在链路队列中，上限为 `H2WsOptions::max_queued_bytes`。队列为空时，无论消息多大都会接受（消息来自
   应用自身，受其 `max_message_bytes` 约束，而非对端可控）：上限约束的是在关闭的窗口后堆积的部分，与 TCP
   上只计算未写出的尾部相同。`WsSender::queued_bytes` 报告这个队列，生产者可以据此自行调速。
4. **关闭与重置。** WebSocket 关闭会结束我方这一半流（close 帧之后发 END_STREAM），对端的 END_STREAM
   结束它那一半，两半都结束后流关闭；已接受的隧道两个方向各自半关闭（普通 HTTP/2 请求若在请求体结束前
   就已应答，则改为以 `NO_ERROR` 重置）。对端的 END_STREAM 即传输关闭，任一方向的 `RST_STREAM` 以及
   连接丢失都是无握手关闭：除非握手已结束会话，handler 的 `on_close` 收到 1006。客户端的关闭得不到应答时，
   在关闭超时后重置流（`CANCEL`）；服务端的 END_STREAM 得不到应答时，5 秒后重置。优雅关闭发送 GOAWAY，
   并以 1001 关闭每个 WebSocket，于是它们结束后连接随之结束。
5. **客户端链路。** `H2Client` 的连接状态在它的 I/O 线程上。它的 `WsLink` 在一个小互斥锁下排队帧，每批
   用一次 `spawn_blocking` 交给 I/O 线程（仅当没有正在途中的那一次），在那里并入流的上传队列，由窗口
   放行，与 `H2Upload` 相同。

## 影响

- 服务端的 SETTINGS 帧多 6 字节。`Stream` 多一个标志，挂起的 context 变成两种情况的枚举（每个打开的流
  多 8 字节）；不带 `:protocol` 的请求走与之前相同的分支。gpu51 上对 `b22519ae` 的 h2c 同轮 A/B（交错
  7 轮）：逐轮比值中位数 0.991（64 × 16）和 1.004（16 × 128），在各轮波动之内
  （docs/BENCHMARKS.zh-CN.md，“HTTP/2 上的 WebSocket”）。
- 互通（`tools/interop/h2ws/run.sh`）：与 Go 的 HTTP/2 双向互通，覆盖 h2c 和 TLS：服务端为 net/http，
  客户端为 golang.org/x/net/http2 的 transport（net/http 自己的 transport 拒绝 `:protocol` 字段；在
  Go 1.27 上 x/net 需要 `-tags http2legacy`，两者都需要 `GODEBUG=http2xconnect=1`）。覆盖文本、3 MiB
  二进制消息（多次窗口更新）、双向 `permessage-deflate`、分片消息、ping 和关闭握手，同一连接上还有普通
  请求和第二个 WebSocket。浏览器也已验证：无头 Chrome 157 从我方 TLS 服务端加载页面，先 fetch，再打开
  WebSocket，它在同一条 HTTP/2 连接上发出（`permessage-deflate`、子协议、300 KB 消息、以 1000 关闭）；
  服务端确认该 WebSocket 是经 HTTP/2 接受的。
- Fuzz：新目标 `h2_websocket` 在已接受的 extended CONNECT 之后送入 WebSocket 字节（按输入切成 DATA
  帧）或原始帧；`h2_server` 增加 extended CONNECT 种子。gpu51 上各跑 10 分钟（libFuzzer、ASan）：
  `h2_server` 480 万次、`h2_websocket` 230 万次，无崩溃。
- 对端在我方 END_STREAM 之后一直不结束它那一半时，流最多保留 5 秒，在此之前计入
  `max_concurrent_streams`。若该定时器在握手完成前重置流，handler 的 `on_close`（1006）在定时器线程上
  而非连接的 I/O 线程上运行。
- 未完成：经 HTTP/1 的 `only_ws::client::dial` 走 HTTP/2 上的 WebSocket（它仍是 HTTP/1.1；HTTP/2 需要
  `H2Client`），以及客户端对 WebSocket 以外协议的 RFC 8441。
