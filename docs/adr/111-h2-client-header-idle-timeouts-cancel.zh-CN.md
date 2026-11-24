# ADR-111：HTTP/2 客户端遵循响应头超时、空闲超时与 `CancelToken`

[English](111-h2-client-header-idle-timeouts-cancel.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

ADR-108（akit 的 A36、A37）为 akio 的 HTTP/1 客户端加上了请求的 `response_header_timeout`、
`response_idle_timeout` 和 `cancel`（`CancelToken`），没有包括 `H2Client`：它忽略这三个字段。ADR-110（A51）
为 `H2Client` 的请求加上了重置（`H2Stream::cancel`）和整个请求的 `ClientRequest::timeout`。akit 以 fit 相同的
响应头与空闲超时代理到 HTTP/2 上游，并在客户端离开时放弃请求，无论请求进行到哪一步；它的 I17b 以每个地址
100 ms 的定时检查逐流检查响应头、静默与令牌，并通过让整条连接退役来放弃一个超时的流。akit 的需求 A66 要求
`H2Client` 像 `Client` 一样遵循这三个字段；对照的是 akio main `f6750e93`（`crates/akio-http/src/h2client.rs`
一个都没有读取）。

约束：不加新的公开 API（字段已存在；`ClientError::HeaderTimeout`、`IdleTimeout` 和 `Cancelled` 已存在）；
不阻塞 I/O 线程；一个流的超时不得影响连接上的其他流；每个 DATA 帧不分配内存、不向其他线程投递。

## 决定

`H2Client::request` 与 `H2Client::open` 遵循请求的这三个字段：

- **`response_header_timeout`** 从请求的 END_STREAM 发出时开始计时（无消息体的请求随 HEADERS 发出；否则在
  最后一个 DATA 帧或尾部字段之后，因此仍在写入的流式消息体不计入），到最终响应的 HEADERS 为止（1xx 中间响应
  不会停止它）。超过后流被重置（`RST_STREAM CANCEL`），请求以 `ClientError::HeaderTimeout` 失败。
- **`response_idle_timeout`** 是从响应头起相邻两个 DATA 帧之间的最长间隔；流的读取被暂停的时间
  （`H2Stream::hold_reads`，ADR-110）不计入，恢复后重新计时。超过后流被重置，请求以
  `ClientError::IdleTimeout` 失败（对流式请求，在 `H2Event::Head` 之后）。
- **`cancel`**：`CancelToken` 像 `H2Stream::cancel` 一样取消 `H2Client` 的请求：流被重置（`CANCEL`），
  仍在等待流（服务端上限）的请求不发送即丢弃，请求以 `ClientError::Cancelled` 失败。已取消的令牌让请求不发送
  即失败。一个令牌可以同时覆盖 HTTP/1 与 HTTP/2 的请求。

每一种都只让请求失败一次（整个请求的回调，或 `H2Event::Error`），以它们、`ClientRequest::timeout` 和
`H2Stream::cancel` 中先到者为准，并把连接留给其他流。

机制：

- **`StreamCtl`**（ADR-110 的每请求状态）增加两个时长、一个阶段（无、等待响应头、消息体中、结束）以及响应
  最近一次进展的时间（单调时钟上的毫秒数）。新增的两种放弃原因经同一个比较并交换映射为 `HeaderTimeout` 与
  `IdleTimeout`，因此最先的原因胜出。
- **定时器。** 阶段开始时，I/O 线程在 akio-http 的定时器线程（`crate::timer::after`，即
  `ClientRequest::timeout` 所用的那个）上安排一次检查：END_STREAM 发出时安排响应头检查（`send_upload` 记下，
  写帧者安排），响应头到达时安排空闲检查。DATA 帧只存储进展时间（设置了空闲超时时，一次原子存储）。定时器线程
  上的检查在阶段已变或流已放弃时什么都不做；流有进展（或被暂停）的空闲检查按剩余时间（或整个超时）重新安排
  自己，因此每个流同时只有一个待执行的检查。看起来到期的检查投递到连接的 I/O 线程，由它决定：那里的阶段是
  准确的（响应头可能刚好到达），并通过 ADR-110 的 `stop` 放弃并重置该流。
- **阶段随流结束**：流的状态被丢弃时（结束、重置、失败、连接丢失）把阶段设为结束，因此即使 `H2Upload`
  仍持有 `StreamCtl`，检查也无事可做。
- **`CancelToken`** 以枚举保存其请求：HTTP/1 的交换（弱引用，同以前）或 h2 的流（其 `StreamCtl` 的弱引用，
  以及用于投递重置的连接句柄）。令牌中已结束的请求照旧被清理；`StreamCtl` 不在了，h2 流即视为结束。

被否决的方案：

- **每个 DATA 帧一个定时器**（每帧重新安排空闲检查）：I/O 线程上每帧一次堆插入和一次通道发送。存储时间加
  惰性重排只需一次原子存储。
- **引擎的每连接截止时间**（ADR-108 中 HTTP/1 的 `ConnTimer`）：每条连接只有一个截止时间，而一条 h2 连接
  承载许多各有超时的流。
- **在定时器线程上做决定**：响应头可能在检查与重置之间到达；流的状态只在 I/O 线程上准确。
- **让 `StreamCtl` 持有连接句柄**（令牌只需持有 `StreamCtl`）：连接的处理器拥有其各流的 `StreamCtl`，
  流存活期间形成循环引用。
- **在 `H2Options` 中设默认值**（如 `ClientOptions::response_header_timeout`）：没有需求；调用方按请求设置。
  需要时再加（`H2Options` 是 `#[non_exhaustive]`）。

## 影响

- akit 的 I18b 去掉逐地址检查每个 h2 流的响应头、静默与令牌的定时检查：因其中之一而放弃的流被重置，连接
  留给其他流。
- 代价：`StreamCtl` 增加两个 `Option<Duration>`、一个字节和一个 `u64`；DATA 帧读一个字段，设置了空闲超时时
  再读一次时钟并存储；带响应头超时的请求安排一个定时任务，带空闲超时的流式响应大约每个超时长度一个；带令牌
  的请求获取一次令牌的锁。不设这些字段时什么都不安排。未测量（规则 20）：基准任务应在安静主机上对设置与不设置
  两个超时的 h2c 请求速率做 A/B。
- 测试：`akio-http/tests/h2_client_frames.rs`，对脚本化服务端：响应头超时只重置它自己的流（连接上的另一个
  请求得到应答），且在流式消息体仍未结束时不计时；空闲超时放行在其内持续到达的响应、在响应头之后重置停滞的
  响应、读取暂停期间不触发；一个令牌在同一连接上各重置一次整请求与流式请求，已取消的令牌让请求不发送即失败。
