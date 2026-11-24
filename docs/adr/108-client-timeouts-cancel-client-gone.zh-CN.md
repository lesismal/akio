# ADR-108：HTTP/1 客户端的响应头超时、空闲超时与取消，服务端请求得知客户端离开，运行时修改写超时

[English](108-client-timeouts-cancel-client-gone.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit 是基于 akio 的反向代理，像 fit 一样约束一次上游交换：上游开始响应可用多久（`response_header_timeout`，超时答
504），响应体中途可静默多久（`response_idle_timeout`，响应被截断），整个交换多久（`response_timeout`），以及客户端
可以多久不读响应（`write_stall_timeout`）。客户端离开时它也会放弃上游请求（fit 的 `OnCancel`）。akit 的需求
A36、A37 和 A38 列出了 akio 为此缺少的东西：

- **A36。** HTTP/1 客户端每个请求只有一个超时（`ClientRequest::timeout`，直到响应结束）。代理无法对迟迟不开始的上游
  答 504，同时又让长下载继续；也无法截断中途停顿的上游。ADR-101 没有做空闲间隔超时：它需要在 handler 暂停读取时
  停表。
- **A37。** 请求体完整发送的请求在响应头到来前没有句柄：`Client::request` 与 `request_with` 不返回任何东西，
  `ResponseBody::cancel` 随响应头才有。上游思考期间客户端离开，上游会继续工作，连接和一个 `max_conns` 名额也一直
  被占用，直到上游回答或请求超时。
- **A38。** detach 的请求（`Context::detach`）在写之前得不到客户端离开的任何消息。HTTP/1 上流式接收请求体的请求在
  客户端离开后仍保留着消息体 sink：会话在其状态中持有 context，且连接为尚欠的响应保持打开（EOF 只会在响应之后排一个
  关闭）。另外 `Config::write_timeout` 在构建引擎时固定，akit 无法在 reload 时应用 `write_stall_timeout`。

约束：API 只增不改（函数的返回类型也属于 API，见 `docs/api-stability.md`）；已有路径行为不变；新东西都不阻塞 I/O
线程；没有无上限增长的东西。

## 决定

### A36：响应头超时与空闲超时（akio-http 客户端）

- **`ClientRequest::response_header_timeout` 与 `response_idle_timeout`**（`Option<Duration>`，同名 builder），
  默认取新的 **`ClientOptions::response_header_timeout` 与 `response_idle_timeout`**（`None`）。名字取自 fit：
  `ClientOptions::idle_timeout` 已是连接池的。
- **响应头超时**从请求完整写出（最后一个字节入队：完整请求体随请求头入队时；流式请求体在 `RequestBody::finish` 时，
  所以长上传不计入）计到最终响应头；1xx 中间响应不会停表（Go 的 `ResponseHeaderTimeout` 也不会）。每一跳重定向
  各自计时。
- **空闲超时**是从响应头开始，两次读取消息体之间的最长间隔。handler 暂停读取（`ResponseBody::hold_reads(true)`）
  期间停表；恢复时重新计时；暂停期间仍交付的读取不重新计时。
- 超过任一超时，请求以新的 **`ClientError::HeaderTimeout`** 或 **`ClientError::IdleTimeout`** 失败（对 handler
  在 `on_head` 之后），连接被关闭；完整响应的回调得到该错误。`ClientError::is_timeout()` 涵盖三种超时。请求超时
  照旧运行。
- **机制。** 每个连接一个截止时间，复用服务端的（`deadline::Watch`：设置是一次 relaxed store，一个扫描线程，到期
  投递到 I/O 线程），在连接上第一次有请求带这两个超时之一时注册。两个阶段先后发生（先响应头，后消息体），所以一个
  截止时间就够；一个原子阶段值在设置时写在截止时间之后、取消时写在之前，用来区分过期的到期（已重设、已取消，或池中
  连接上一个请求留下的）和真正的到期。I/O 线程在每次读到消息体时重设；`finish` 与 `hold_reads` 在各自线程上设置；
  响应头的到来与 `finish` 在流式请求体的锁下排序。

### A37：在任意时刻取消请求

- **`CancelToken`**（`Clone`、`Send`、`Sync`、`Default`）：`new`、`cancel`、`is_cancelled`，用
  **`ClientRequest::cancel_with(&token)`**（字段 `ClientRequest::cancel`）交给请求。`request`、`request_with`、
  `request_streamed` 与 `send` 的签名不变。
- 取消时：尚未发送的请求被丢弃（已取消的令牌使其立即失败，不发起连接）；已发送的请求关闭其连接。请求以新的
  **`ClientError::Cancelled`** 失败，只一次，除非已经结束：完整响应的回调在取消的线程上调用（如同超时的回调在定时器
  线程上运行），handler 在连接的 I/O 线程上得到 `on_error`；还没有连接时，在解析或拨号结束的地方得到。
- 一个令牌可以服务多个请求（代理的重试）：取消它会取消其中每个尚未结束的请求。令牌持有弱引用，增长时清理已结束的
  请求。
- 实现在原本就承载请求超时的 exchange 上：它现在记录放弃的原因（超时或取消），原先检查超时的每个地方都报告这个原因。

### A38：服务端请求得知客户端离开；运行时修改写超时

- **`Context::on_gone(f)` 与 `Detached::on_gone(f)`**：客户端在响应完成前离开时运行 `f` 一次，在连接的 I/O 线程上；
  若已经发生则立即在调用线程上运行。它替换先前的 `f`，从 context 带到 `detach` 和流式响应（`BodyStream`）直到其结束，
  响应完整发出或结束后被丢弃而不运行（未结束就丢弃的 `BodyStream` 会关闭连接，算作离开）。
  - **HTTP/1**：连接关闭，或客户端结束发送（EOF）。发完请求就半关闭的客户端被视为离开，如同 Go 的服务端在读取结束时
    取消请求的 context。机制：akio-core 中的 **`ConnInner::on_peer_gone(key, f) -> bool`** 与
    **`forget_peer_gone(key)`**，在读到对端 EOF（`close_after_responses`）或连接标记为关闭时运行。key 是响应槽的序号
    （`ResponseSlot::seq`），所以 responder 只在填充字节里放一个标志（`Option<Out>` 仍为 24 字节，ADR-025），发送时
    注销回调。
  - **HTTP/2**：流被客户端重置，或在我们的 END_STREAM 发出前随连接一起丢弃。回调是流上一个丢弃即运行的 waiter（同
    ADR-101 的排空 waiter），在我们的 END_STREAM 之后流关闭时解除，因此在 core 的锁外运行。
  - **HTTP/3** 及其他传输：新的 **`ConnSink::on_gone(tag, f)`**，默认实现丢弃 `f` 而不运行（无法判断的传输从不调用
    它）。akio-h3 在客户端对请求流发 RESET_STREAM、对响应发 STOP_SENDING 或连接关闭时运行它，在响应发出或结束时注销
    （仅当该连接上曾注册过回调时才查这张表）。
- **HTTP/1 会话在连接关闭时丢弃流式请求的 context 及其 sink**，如同 HTTP/2 丢弃已关闭连接的流；客户端的 EOF 在消息体
  中途到来时会关闭连接（消息体无法完成，而等待它的 detach handler 会一直占着连接直到消息体超时）。
- **`Live::set_write_timeout(Option<Duration>)`** 与 `Live::write_timeout()`，由 `Telemetry::reload` /
  `Engine::reload` 应用（现在出现在 `applied` 中，不再在 `ignored` 中）。epoll 与 io_uring 事件循环在原先读取
  `Config::write_timeout` 的地方读取它：已排定的检查按原设置运行，并以新值重设；`None` 在下一次检查时停止检查；重新设置
  后，在下一次有输出入队的写时开始检查。发现超时已关闭的检查不再让其定时器保持为待定状态。

否决的方案：

- **让 `request` 与 `request_with` 返回句柄。** 按 `docs/api-stability.md`，改变返回类型是破坏性变更（作为
  `FnOnce()` 的 `|| client.request(..)` 将无法编译）；而传入的令牌也能覆盖重试和以后的传输，无需新入口。
- **每次设置都在客户端定时器线程（`crate::timer`）上排一个任务**：每次读取重设空闲超时会在每次读取时压入一个堆
  条目。服务端的截止时间只需一次 store。
- **对流式请求体在请求头入队时就开始响应头超时。** 代理在客户端发送期间一直在流式上传；大多数服务端在消息体之后
  才回答。
- **为截断的 HTTP/1 消息体增加 `BodyEvent::Aborted`**：`BodyEvent` 不是 `#[non_exhaustive]`，新增变体会破坏穷尽
  匹配。改为丢弃 sink，与 HTTP/2 相同。
- **本次变更包含 `H2Client`。** akit 的 I18（h2 上游）在后面；届时同样的请求字段适用于它。`H2Client` 忽略它们，正如它
  忽略 `ClientRequest::streamed`。

## 影响

- akit 的 I17b 可以为每个代理请求设置 `response_header_timeout` 与 `response_idle_timeout`（`HeaderTimeout` 答
  504，`IdleTimeout` 截断响应），给每个上游请求一个在 `on_gone` 中取消的 `CancelToken`（且不计入上游健康），并在
  启动和 reload 时用 `Live::set_write_timeout` 应用 `limits.write_stall_timeout`。
- 代价：`ClientConn` 多一个 `Option<Arc>` 和一个 `Option<Duration>`，每次读取多一次分支判断；请求多三个字段。
  HTTP/1 的 responder 大小不变，HTTP/2 的流多一个 `Option<Waiter>`，akio-core 每个连接的写状态多一个 `Vec` 和一个
  计数器；流式 HTTP/1 请求注册一个 peer-gone 回调（一次加锁和一次 push），akio-h3 的响应读一个原子量。均未测量
  （规则 20）：基准任务应在安静主机上对 `client-bench`、HTTP/1 流水线与流式请求体服务、h2c 和 h3 做 A/B。
- 测试：`akio-http/tests/client_cancel.rs`（永不到来的响应头、短响应头超时下的长消息体、停顿的消息体、暂停读取超过
  空闲超时、流式请求体的响应头超时从 finish 起算、复用连接上的截止时间，发送前、等待响应头时、消息体中途、多个请求共用
  以及结束后的取消），`akio-http/tests/on_gone.rs`（HTTP/1：detach 的请求、已回答与流式的响应、客户端离开后才注册的
  回调、中途截断的上传及其 sink；HTTP/2：流被重置与连接关闭），`akio-h3/tests/on_gone.rs`（连接关闭）以及
  `akio/tests/reload.rs`（运行时开启和关闭写超时）。
