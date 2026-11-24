# ADR-101：带联动背压的流式消息体：边产生边发送的客户端请求体、边到达边交付的客户端响应、服务端请求对读取的暂停与排空通知

[English](101-streamed-bodies-linked-backpressure.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit 是基于 akio 的反向代理，必须边到达边转发消息体，并联动两侧的背压（规则 4 和 8）：上游跟不上时停止读客户端；
客户端跟不上时停止读上游。akit 的需求 A19、A20 和 A21 列出了 akio-http 为此缺少的东西：

- **A19。** HTTP/1 客户端只接受完整的请求体（`ClientRequest::body: Vec<u8>`，与请求头一起编码，用一次
  `send_owned` 发出）。代理必须先把每个上传完整保存，上游才能看到第一个字节。
- **A20。** 客户端把每个响应体完整收集，上限 `ClientOptions::max_body_bytes`（64 MiB），只回调一次。下载被整个
  保存，超过 64 MiB 就失败，慢客户端也无法让上游慢下来：连接的读取从不暂停。
- **A21。** 以流方式接收请求体（`BodyMode::Stream`）的服务端 handler 按客户端发送的速度得到数据，流式响应
  （`BodyStream`）只能轮询（`queued_bytes`）。两者都够不到连接的 `hold_reads` 或 `on_drain`。HTTP/2 在 DATA
  到达时就归还流的接收窗口，不管 handler 怎么处理数据。

akio-core 已在每个连接上具备这两半（`ConnInner::hold_reads`、`on_drain`、写水位、`set_relayed`），akio-quic 在每个
流上也有（`Connection::hold_reads`、带 `StreamWritable` 的 `send_capacity`）。只有 akio-http 的 raw 连接暴露了它们。

约束：API 只增不改；完整消息体的路径行为不变；新东西都不阻塞 I/O 线程；每个队列都有上限。

## 决定

### A19：边产生边写出的客户端请求体

- **`ClientRequest::streamed: Option<StreamedBody>`**，由 `ClientRequest::streamed(len)` 设置：
  `StreamedBody::Length(n)` 发送 `Content-Length: n`，`StreamedBody::Chunked` 发送
  `Transfer-Encoding: chunked`。此时不发送 `body`，并丢弃请求自带的 `Transfer-Encoding` 字段。
  `Client::request` 与 `Client::send` 忽略它。
- **`Client::request_streamed(req, on_ready, done)`**：请求头入队后（新连接建立后或在复用的连接上），
  `on_ready(RequestBody)` 在连接的 I/O 线程上运行。`done` 像 `request` 那样得到完整响应。
- **`RequestBody`**（`Send`）：`write(&[u8])` 复制进连接的发送队列（分块时自成一块）；`queued_bytes()`；
  `on_drain(f)`（即连接的 `on_drain`：队列清空或连接关闭时运行 `f`，没有排队内容时立即运行）；
  `finish()`（最后一块，或检查长度已写满）与 `finish_with_trailers(Headers)`（分块消息体之后的 trailer）。
  写超出长度或未写满就结束，请求失败。未结束就丢弃会关闭连接。
- 写流式请求体期间，连接被标记为中继一端（`set_relayed`）：它的读取不因自身排队的输出而暂停，所以提前到来的
  响应（413）仍会被读到。由生产者控制队列速度；超过 `Config::max_queued_bytes` 的写被拒绝。
- **响应可能在消息体写完前到来**，也可能是完整的：`done`（或 handler）得到它，响应收完后连接被关闭而不是放回池中，
  之后的写失败。
- **从不重试，从不跟随重定向**：消息体无法重发。在服务端已关闭的复用连接上，请求以 `Closed` 或 `Io` 失败，
  与 Go 客户端对无法回绕的消息体的做法相同。3xx 交给调用者。

### A20：边到达边交付的客户端响应

- **`Client::request_with(req, handler: impl ResponseHandler)`**。trait：
  - `on_request_body(RequestBody)`：流式请求体（如有；默认实现丢弃它，请求随之失败）；
  - `on_head(ResponseHead, ResponseBody)`：状态码、原因短语、字段和版本，跳过 1xx 中间响应；
  - `on_data(&[u8])`：读到的每段消息体，已去分块，只在调用期间有效（规则 5）；
  - `on_end(&Headers)`（附分块消息体的 trailer）或 `on_error(ClientError)`。请求头之后两者恰好发生其一。
- **`ResponseBody`**（`Clone`、`Send`）：`hold_reads(bool)` 暂停和恢复连接的读取；`cancel()` 关闭连接（handler
  随后得到 `on_error(Closed)`）。响应结束后两者都不再起作用，连接放回池中之前会解除暂停。
- `ClientOptions::max_body_bytes` 不适用，由 handler 决定。不跟随重定向。请求超时一直计到 `on_end`。客户端有
  cookie 容器时从响应头存入 cookie。是否在新连接上重试与 `request` 相同：只对没有流式请求体的 `GET`、`HEAD`、
  `OPTIONS`，且在收到任何响应字节之前。
- `request_streamed` 就是 `request_with` 加一个在 `max_body_bytes` 内收集完整响应的 handler；`request` 与
  `send` 保持原有路径，不变。

### A21：服务端请求对读取的暂停，以及流式响应的排空通知

- **`Context::body_reads() -> Option<BodyReads>`**，用于以流方式接收消息体的请求（`BodyMode::Stream`，HTTP/1.1、
  HTTP/2、HTTP/3 皆可）。它读取 responder，因此要在 `detach` 或 `stream_response` 之前获取；句柄可 `Clone`、
  `Send`，之后仍可用。`BodyReads::hold(bool)`：
  - **HTTP/1.1** 暂停连接的读取，因而也暂停其后流水线中的请求，这是必须的。暂停随消息体结束而结束（下一个请求的
    读取不归这个 handler 管），暂停期间消息体超时不触发：慢的不是客户端。
  - **HTTP/2** 停止归还流的接收窗口（恢复时归还欠下的部分），客户端用完手中的窗口（默认 1 MiB）就停下，其它流照常。
  - **HTTP/3** 通过新增的 `ConnSink::hold_reads(tag, hold)`（默认什么也不做）；akio-h3 暂停 QUIC 流
    （`Connection::hold_reads`）。
  - 已读到的字节仍会交付：HTTP/1.1 最多一次读取的量，HTTP/2 与 HTTP/3 是窗口内已在途的数据。
- **`BodyStream::on_drain(f)`**：响应排队的字节让开路之后，或连接、流已不在时运行 `f`；如果已经如此则立即在调用
  线程上运行，否则在连接的 I/O 线程上。它替换之前的等待者。
  - **HTTP/1.1**：连接的发送队列已空（akio-core 每个连接一个 `on_drain` 等待者，同一时刻只有一个流式响应持有它）。
  - **HTTP/2**：流排队的字节已按流控窗口允许的全部组帧；其余由对端窗口约束。等待者在 core 的锁外运行：等待者只在
    丢弃流的地方被丢弃，而丢弃即运行（`Locked`）。
  - **HTTP/3**：新增的 `BodySink::on_drain`（默认立即运行）；akio-h3 在流的发送缓冲重新有空间时（`send_capacity`，
    缓冲降到四分之三时的 `StreamWritable`）、流被停止时或连接关闭时运行它。

不采纳：

- **在客户端或 HTTP/1.1 上提供低水位的 `on_drain`。** akio-core 的 `on_drain` 在队列清空时触发；再加一个更低的阈值
  需要修改核心，却没有测得的收益。生产者在自己的水位之上暂停，排空时恢复。
- **把流式请求的消息体扣住到响应头到来，以便在新连接上重试。** 先读完消息体再应答的服务端会死锁；Go 也不这样做。
- **HTTP/1.1 上扣住一次读取的剩余部分**（保留已读字节直到恢复）：恢复后若没有新数据可读，它们永远不会交付。一次读取
  受读缓冲大小约束。
- **本次改动中让 `H2Client` 支持流式。** akit 的 I18（h2 上游）在后面；届时可以给 `H2Client` 加上同一个 handler trait。（其流式请求此后已有按流的背压，沿用事件回调而非该 trait：ADR-110。）
- **响应读取之间的空闲超时**（fit 的 `response_idle_timeout`，A20 的最后一点）。它属于 akit 的 I17，并且需要在
  handler 暂停读取时停下读取间隔的计时。（此后已由 ADR-108 完成。）

## 影响

- akit 的 I16 可以在 HTTP/1 上游上边到达边转发消息体，并联动背压：客户端消息体 → 由 `queued_bytes` / `on_drain`
  控制速度的 `RequestBody`，客户端的读取用 `BodyReads` 暂停；上游响应 → `ResponseHandler`，客户端的
  `BodyStream::queued_bytes` 高时用 `ResponseBody::hold_reads` 暂停上游的读取，由 `BodyStream::on_drain` 恢复。
- 完整消息体的客户端路径行为不变。`ClientConn` 每个请求多三个字段；HTTP/2 释放锁时多检查一个 vector。两者都未测量
  （规则 20）：应由基准任务在安静主机上对 `client-bench` 与 h2c 做 A/B，并测量流式消息体与完整消息体下代理式中继的
  表现（DEV-PLAN 第 4 节）。
- 测试：`akio-http/tests/stream_bodies.rs`（按排空控制速度的分块与定长请求体、trailer、过长、过短与被丢弃的消息体、
  写消息体时提前到来的 413、边到达边交付且读取可暂停与恢复并超出客户端消息体上限的响应、trailer、取消、连接复用、
  双向同时流式；服务端在 HTTP/1.1 上暂停消息体且消息体超时短于暂停时间，在 HTTP/2 上暂停时另一个流照常进行，两者上
  按排空控制速度的下载）以及 `akio-h3/tests/body_reads.rs`（受流窗口约束的被暂停消息体、按排空通知控制速度的下载）。
