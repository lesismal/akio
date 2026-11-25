# ADR-157：关闭连接或带长度的响应，由中间件限制的请求 body

[English](157-http1-close-length-body-limit.md) | 简体中文

状态：已采纳（2026-11-26）

## 背景

akit 的四个需求向 akio-http 要 fit 的 Go 服务器给其 handler 的能力：

- **A24。** 服务在读取请求 body 之前拒绝请求（body 超限的 `413`、缺少 token 的 `401`）后，
  无法在回答后关闭 HTTP/1 连接：keep-alive 只由请求决定，服务设置的 `Connection: close` 被发出
  但不被遵从，body 的其余部分仍被读取（交给无人读的 sink，或丢弃），直到 body 超时。快速的客户端
  能让服务器读取一个它已拒绝的无界 body，并在同一连接上再试。
- **A49。** fit 的 `body_limit` 为任何读取 body 的 handler 限制它。akio-http 中只有 listener 的
  `max_body_bytes` 限制缓冲的 body；流式 body（`BodyMode::Stream`）不受限地交给 handler 的
  sink，中间件既看不到也包装不了这个 sink。
- **A35。** 流式 HTTP/1.1 响应在 keep-alive 连接上总是 chunked；随之给出的 `Content-Length`
  与 `Transfer-Encoding: chunked` 一起发出（不合法），所以 akit 丢掉它：被代理的下载失去长度，
  客户端无法分辨被截断的 body。
- **A148。** handler 能看到请求的对端，却看不到请求到达的地址（CGI 的 `SERVER_ADDR` 和
  `SERVER_PORT`，供 akit 的 FastCGI handler 使用）。

## 决定

**HTTP/1 遵从响应的 `Connection: close`（A24）。** `Response::encode` 报告响应自己的
`Connection` 字段是否含 `close` 记号（它本就扫描各字段；热路径上没有多一遍扫描）。这样的响应，
无论来自 `respond`、`Detached`、被扣住的响应头还是流式响应头，写出后关闭连接，不论请求要求什么，
并且连接的读取被暂停（`hold_reads`）：服务拒绝的 body 的其余部分不再读取。完整响应在发出时暂停
读取；流式响应在结束时暂停，所以一边流式回答一边仍读请求的 handler（中继）在那之前仍能拿到
body。响应由 handler 就地发出时，会话也停下：body 正在流入的请求丢弃其 context 和 sink（不再
投递），排在其后的流水线请求不再解析。没有单独的 `close_after_response()`：HTTP 就是用这个字段
表达的，编码器能看到它，HTTP/2 和 HTTP/3 本就把它当作连接相关字段丢弃。

**`Context::limit_body(&mut self, max: u64) -> bool`（A49）。** 它降低请求 body 的上限（再次
调用保留较低者）。已到达的 body（缓冲的，或没有 body）长于 `max` 时立即回答 `413`，连接保留。
流式 body 由 context 统计它投递给 sink 的字节；声明的 `Content-Length` 超过 `max`，或已投递超过
`max`，立即拒绝 body；之后增长超过上限的 body 在那时被拒绝。拒绝后：

- sink 收到新的 `BodyEvent::TooLarge` 并被丢弃（之后什么也收不到，也没有 `End`）；
- context 仍持有响应时，请求被回答 `413`；已取走响应的 handler（`detach`、`stream_response`）
  按 sink 收到的事件自行回答；
- HTTP/1：`413` 带 `Connection: close`（于是适用 A24）；会话丢弃 context，暂停读取，并在之前的
  响应（含 handler 自己的回答）之后预留一次关闭；
- HTTP/2：流的 context 不再停放（之后的 DATA 无处可去），流不再给出窗口；响应完成后流以
  `NO_ERROR` 重置，与任何在请求结束前发出的响应一样；
- HTTP/3：`Started::body_refused` 告知传输层，传输层发送带 `H3_NO_ERROR` 的 `STOP_SENDING`，
  并丢弃仍然到达的数据。

请求被拒绝时 `limit_body` 返回 `false`：中间件不再调用 handler。错误以新变体表达，而不是在
`Chunk` 和 `End` 旁加 `Err`，因为 sink 本就匹配事件；`BodyEvent` 保持穷尽（事件枚举，见
docs/api-stability.md），所以新增变体会破坏穷尽匹配，这在 1.0.0 之前允许，并在变更日志中注明。

**按长度定界的流式 HTTP/1 响应（A35）。** `stream_response` 把响应头给出的 `Content-Length`
（每个值都能解析且一致、状态码有 body、没有 `Transfer-Encoding`）作为 body 的定界。定界在响应
过滤器运行之后于 `open_stream` 中确定：过滤器设置的流式编码（`Response::set_stream_coding`）会
丢掉该字段（编码后的 body 不是这个长度），body 过滤器（ADR-128）也会，因为它们改变 body；没有
长度时，keep-alive 的 HTTP/1.1 上 body 用 chunked，否则以关闭连接定界，与之前一样。有长度的
body 按写入原样发出，剩余长度以原子方式计数（写入可来自任何线程）：超出长度的写入整体被拒绝，
返回 `Error::Io(InvalidInput)`，一个字节也不写；body 不足其长度时 `finish` 关闭连接（被截断的
body 必须如此），请求以 `End::Gone` 结束，其 tap 收到 `TapEnd::Cut`。`HEAD` 的回答保留该字段
且不发 body。HTTP/2 和 HTTP/3 自己为 body 定界并保留该字段。曾考虑单独的
`stream_response_sized(status, headers, len)`；响应头里的字段就是要发出的、过滤器能看到的内容，
从那里读取它，无需第二种方式表达同一件事。

**`Request::local: SocketAddr` 和 `Context::local_addr()`（A148）。** 与 `peer` 一样填写：
HTTP/1.1 和 HTTP/2 上是连接的本地地址，HTTP/3 上是 UDP socket 的本地地址（新增的
`akio_quic::Connection::local_addr`，在服务器接受连接时记录），没有时为未指定地址。它是 socket
的地址，不是 PROXY 头的目的地址。

## 后果

- 被拒绝的 body 不再被读取：旧行为下只有 body 超时限制它。接收缓冲区中有未读字节时关闭连接，
  内核可能发送 reset，客户端可能在看到回答之前收到它；服务器不做延迟关闭（Go 等半秒）：只发不读
  的客户端可能错过 `413`。先发请求头再等待（或使用 `Expect: 100-continue`）的客户端能收到它。
- 请求 body 仍在流入时，`Detached` 回答 `Connection: close` 会暂停连接的读取；handler 的
  `BodyReads::hold(false)` 可能在关闭之前恢复读取。
- akio-http 之外对 `BodyEvent` 的每个 `match` 都需要 `TooLarge` 分支（akit：它的各个 sink）。
- `Context` 增加两个 `u64` 和三个标志，`Request` 增加一个 `SocketAddr`；`Out` 仍为 24 字节。
  每个 chunk 的开销是一次加法和一次比较。尚未测量：DEV-PLAN 第 4 节有对应的行和要测的内容。
- 测试：`akio-http/tests/body_limit.rs`（A24、HTTP/1 和 HTTP/2 上的 A49、A148）、
  `akio-http/tests/sized_stream.rs`（A35）、`akio-h3/tests/limit_body.rs`（HTTP/3 上的 A49、
  A148），在 kqueue、epoll、io_uring 和轮次调度上运行。
