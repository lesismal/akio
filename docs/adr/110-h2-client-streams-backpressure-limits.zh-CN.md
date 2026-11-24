# ADR-110：HTTP/2 客户端流式请求的重置、超时与请求尾部字段；按流的背压；服务端的流上限、`GOAWAY`、连接超时与 ALPN

[English](110-h2-client-streams-backpressure-limits.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit 是基于 akio 的反向代理，用 akio 的 `H2Client` 代理到 HTTP/2 上游（h2 与 h2c），像代理 HTTP/1 交换一样流式
转发每次交换（ADR-101、ADR-108）。它的 I18 用临时方案做到了这一点；akit 的需求 A51、A52 和 A53 列出了 `H2Client`
缺少的东西，已对照 akio main `4f7169c4`（`crates/akio-http/src/h2client.rs`）核实：

- **A51。** 流式请求（`H2Client::open`）返回的 `H2Upload` 只有 `write` 和 `finish`：无法重置（`H2Conn::cancel`
  是私有的，只有 `request` 的超时用得到），`open` 忽略 `ClientRequest::timeout`，请求体也无法以尾部字段结束（如 gRPC
  的）。收到 `GOAWAY` 时，高于其最后流 id 的流被丢弃，完整请求的回调会失败，但流式请求的 `on_event` 永远得不到通知；
  并且 `is_open` 仍为 `true`，而每个新流都以 `Closed` 失败。
- **A52。** 规则 8 要求背压联动。客户端在 DATA 到达时立即归还每个流的接收窗口（每帧一个 `window_update`），慢的消费
  者无法让服务端慢下来；`H2Upload::write` 无上限地排队，也不报告任何东西。
- **A53。** 客户端忽略 `SETTINGS_MAX_CONCURRENT_STREAMS`（设置 3），连接池无法确定一个连接的容量，超过上限的请求被
  服务端拒绝。`connect` 用 `HappyEyeballs::default()` 竞速地址（固定 10 秒连接超时）。TLS 上无论 ALPN 选了什么，
  客户端都说 h2。

约束：API 只增不改（`docs/api-stability.md`：不改签名；`H2Options` 与 `ClientError` 是 `#[non_exhaustive]`）；
新东西都不阻塞 I/O 线程；所有队列都有上限。

## 决定

### A51：重置、超时、尾部字段、`GOAWAY`

- **`H2Stream`**（`Clone`、`Send`、`Sync`），由 **`H2Upload::stream()`** 得到：`cancel()`、`hold_reads(bool)`
  （A52）和 `id()`。**`H2Upload::cancel()`** 即 `stream().cancel()`。
- **取消**：流被重置（`RST_STREAM CANCEL`），`on_event` 在连接的 I/O 线程上收到一次
  `H2Event::Error(ClientError::Cancelled)`，除非流已结束或超时先放弃了它。仍在等待流的请求（A53）不发送直接丢弃。
  之后的写入失败。
- **超时**：`open` 像 `request` 一样启用 `ClientRequest::timeout`：超时后流被重置（`CANCEL`），`on_event` 收到
  `Error(ClientError::Timeout)`，除非流已结束。定时器以弱引用持有流的状态。
- **机制。** 每个请求（`request` 和 `open`）有一个 `StreamCtl`（`Arc`）：它的流 id（启动前为 0）、放弃它的原因（一次
  compare-and-swap，所以取消和超时只让它失败一次）以及暂停读取的标志。取消或超时设置原因后投递到 I/O 线程：若流仍是
  该请求的就重置它，或把它从等待队列中删除。投递与请求的启动是两个独立的 `spawn_blocking` 后续，彼此无序：启动时若发现
  原因已设置，请求直接失败而不发送。`request` 的超时走同一路径，所以启动前就已超时的请求之后不再被发送。
- **尾部字段**：**`H2Upload::finish_with_trailers(Headers)`** 在最后一个 DATA（都不带 `END_STREAM`）之后用一个带
  `END_STREAM` 的 HEADERS 帧结束请求体。字段名转为小写；伪字段和连接相关字段被丢弃；一个不剩时等同 `finish`。HPACK
  在 I/O 线程上发送时按帧顺序编码它们。
- **`GOAWAY`**：高于其最后流 id 的流以新的 **`ClientError::Refused`** 失败（服务端没有处理它们，可以在别处重发）：完
  整请求的回调和流式请求的 `on_event` 都一样。等待流的请求以及 `GOAWAY` 之后发起的请求也以 `Refused` 失败。被
  `REFUSED_STREAM` 重置的流是 `Refused`（原为 `Protocol("stream refused")`）。收到 `GOAWAY` 或 `close` 发出
  `GOAWAY` 之后，**`H2Client::is_open`** 为 `false`。
- **响应先于请求体结束**（提前回答、gRPC 服务端的尾部字段）：流被重置（`CANCEL`），与 Go 的 transport 一样，而不是在服
  务端留下半开的流；从此请求体的写入失败。`on_event` 收到 `End` 或 `Error` 时写入已经会失败：流对请求体的持有先被
  释放。

### A52：按流的背压

- **接收**：`H2Stream::hold_reads(true)` 停止归还该流的接收窗口：DATA 帧计入欠账，不发 `WINDOW_UPDATE`。已在路上的
  DATA 仍会到达并交付，最多一个窗口（`H2Options::initial_window`，默认 1 MiB）。`hold_reads(false)` 立即归还欠账。
  连接级窗口仍在 DATA 到达时归还，连接上的其他流照常进行（与服务端一致，ADR-101）。
- **发送**：**`H2Upload::queued_bytes()`**（已写入但尚未进入 DATA 帧的字节：在共享队列或流的队列里），
  **`H2Upload::on_drain(f)`**（降到 0 或流结束时运行 `f` 一次：已满足时在调用线程上立即运行，否则在 I/O 线程上；只有一
  个等待者，后者替换前者），以及 **`H2Upload::try_write(&[u8]) -> akio::Result<()>`**：流已结束、请求体已结束或连接
  已断开时 `Err(Closed)`，超过新的 **`H2Options::max_queued_bytes`**（64 MiB；队列为空时任意大小的一次写入都接受，
  与 WebSocket link 相同）时 `Err(Overloaded)`。`write` 仍是 `-> bool`，现在等于 `try_write(..).is_ok()`。写入成批
  投递：每批一次投递到 I/O 线程，而不是每次写入一次。

### A53：服务端的流上限、连接超时、ALPN

- **`H2Client::max_concurrent_streams()`**（服务端最新的 `SETTINGS_MAX_CONCURRENT_STREAMS`，服务端告知前为
  `u32::MAX`）、**`open_streams()`**（本客户端打开且未结束的流：请求、流式请求和 WebSocket；不含推送）和
  **`waiting_streams()`**。
- **超过上限的请求在客户端里按顺序等待**，在流结束或上限提高时启动；最多等待新的
  **`H2Options::max_pending_streams`**（1024）个，超过时请求立即以新的 **`ClientError::Busy`** 失败。设为 `0` 时超过
  上限的请求都以 `Busy` 失败（由调用方选择：排队，或另拨一个连接）。等待中的请求的超时和取消照常生效。WebSocket 计入
  上限但不等待。
- **连接超时**：新的 **`H2Options::happy_eyeballs`** 是 `connect` 竞速所用的设置（其 `connect_timeout` 默认 10 秒），
  与 HTTP/1 的 `ClientOptions::happy_eyeballs`（A12）一样。`dial` 仍用引擎的。
- **ALPN**：TLS 上 `dial` 和 `connect` 在服务端的第一批字节（它的 SETTINGS，此时 `max_concurrent_streams` 已知）到达
  后才调用 `ready`，并先检查 ALPN 选择的是 `h2`。若不是（另一个协议，或没有），连接被关闭，`ready` 得到一个
  `io::Error`（`Unsupported`），其内部错误是新的 **`NotH2 { alpn }`**（`NotH2::of(&e)`）；调用方可回退到 HTTP/1.1
  （`akio_http::client::Client`）。在此之前关闭的连接报告握手失败，若握手选了别的协议则报告 `NotH2`。先验知识（无 TLS）
  仍在连接建立时调用 `ready`。

否决：

- **`connect_with(engine, host, port, tls, opts, HappyEyeballs, ready)`**（A53 的建议）：竞速设置属于 `H2Options`，
  就像它在 `ClientOptions` 里一样；少一个入口。
- **`ready` 得到 `enum { H2(H2Client), Http1(Conn) }`**：从 `on_open` 起连接的 handler 就是 h2 的，而 akio-http 的
  HTTP/1 客户端自己拨号并维护连接池。回退多花一次握手，调用方记住每个地址后只花一次。
- **`H2Stream::consume(n)`**（A52 的可选项）：代理只需暂停与恢复；随字节转交逐步归还窗口，等有调用方需要再加。
- **让 `write` 无上限、只限制 `try_write`**：无上限的队列违反规则 4。默认 64 MiB 与缓冲消息体的上限相同，以前通过
  `open` 写入完整消息体的生产者仍然可用。
- **未结束的 `H2Upload` 被丢弃时重置流**（如同 `RequestBody` 的 drop 会关闭连接）：在响应仍在流式到达时、未 finish 就
  丢弃它的调用方，会看到以前不会发生的重置。保持原样；`cancel` 才重置。
- **`H2Client` 上的 `CancelToken` 以及响应头、空闲超时（ADR-108）**：A51–A53 没有要求。`H2Stream::cancel` 和
  `ClientRequest::timeout` 足以支持 akit 的 I18b；需要时其余几项可复用 `StreamCtl`（加第三种原因）。
- **同时暂停连接级窗口**：一个暂停的流会让连接上的其他流也停下。

## 影响

- akit 的 I18b 可以去掉临时方案：放弃的流被重置，而不是让它的连接退役；`open` 的超时取代按地址的定时检查；请求尾部
  字段发往上游；`GOAWAY` 让被放弃的流以 `Refused` 失败（502 或重试）并让连接退役（`is_open`）；下载用 `hold_reads`
  暂停（不再需要 `HELD_LIMIT`）；上传按 `queued_bytes` / `on_drain` 控速；按 `max_concurrent_streams` 确定连接容量；
  拨号受 `happy_eyeballs` 约束；`h2` 上游在 `NotH2` 时回退到 HTTP/1.1。
- 可见的行为变化（都是改进）：`REFUSED_STREAM` 和被 `GOAWAY` 放弃的请求以 `Refused` 失败（不再是 `Protocol` /
  `Closed`）；`GOAWAY` 之后的请求以 `Refused` 失败；`GOAWAY` 之后 `is_open` 为 `false`；超过服务端上限的请求排队等待，
  而不是被服务端拒绝；流结束后 `H2Upload::write` 和 `finish` 返回 `false`；TLS 拨号的 `ready` 在服务端第一帧之后到来。
- 代价：每个请求分配一个 `StreamCtl`（以前分配一个 `Arc<AtomicU32>`）；每个流多五个字段；每个 DATA 帧读一次原子量；
  `on_data` 结束时检查一个空向量和等待队列。未测量（规则 20）：应有一个基准任务在安静的主机上对 h2c 的
  `client-bench` 式请求速率以及流式上传/下载做 A/B。
- 测试：`akio-http/tests/h2_client_frames.rs`（对脚本化服务端：取消只重置一次、取消与启动竞争、超时、请求尾部字段、
  响应先于请求体结束、`GOAWAY` 拒绝流式请求、暂停读取时流窗口不归还而连接窗口照常归还、上传队列有上限并能排空、服务端
  流上限下一个请求等待一个以 `Busy` 拒绝；`REFUSED_STREAM` / `GOAWAY` 测试现在期望 `Refused`）以及
  `akio-http/tests/h2.rs`（TLS 拨号得知服务端上限；选择 `http/1.1` 的 TLS 服务端让拨号以 `NotH2` 失败）。
