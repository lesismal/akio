# ADR-011：HTTP/3 上的 WebSocket（RFC 9220）、QPACK 动态表与流式请求 body

[English](011-h3-websocket-qpack-streaming.md) | 简体中文

状态：已采纳（2026-11-16）

## 背景

`only-h3` 通过 HTTP/3 提供 only-http 的 service，但与同一技术栈里的 HTTP/1.1、HTTP/2 以及其他
HTTP/3 实现相比有三处缺口：没有 WebSocket（RFC 9220 extended CONNECT）；QPACK 没有动态表（宣告
容量 0，nghttp3 等对端无法压缩重复字段）；请求 body 总是缓冲（`BodyMode::Stream` 的 service 在
HTTP/1 和 HTTP/2 上可用而在 HTTP/3 上不行，上传受 `max_body_bytes` 限制）。客户端既不能流式上传，
也不能打开 WebSocket。补上这些会涉及 only-h3、only-http 和 only-ws 的公共 API。

## 决策

1. **服务端 HTTP/3 WebSocket，沿用现有 API。** `Context::upgrade_websocket(handler, &WsOptions)`
   在 HTTP/3 上接受 `:protocol websocket` 的 extended CONNECT：与 HTTP/1.1 一样检查版本 13 和
   origin 策略，以同样方式协商子协议和 `permessage-deflate`，应答 `200`（只有头部），此后请求流
   承载 WebSocket，由 only-ws 分帧，`WsHandler` / `WsSender` 模型不变。服务端总是宣告
   `SETTINGS_ENABLE_CONNECT_PROTOCOL`：未知协议的请求只是一个由 service 回答的普通请求。`Router`
   用路径的 **GET 路由**回答 `websocket` 的 extended CONNECT（就像用它回答 HEAD），因此一个
   `.get("/ws", ...)` 同时服务 HTTP/1.1 和 HTTP/3 上的 WebSocket。HTTP/2（RFC 8441）仍不支持
   （400）。
   - `Request::protocol: Option<String>` 携带 `:protocol`（该结构体为 `#[non_exhaustive]`；每个
     请求多 24 字节，见“后果”）。
2. **客户端 HTTP/3 WebSocket：** `H3Client::websocket(path, &H3WsOptions, handler, done)` 和
   `websocket_blocking(..)`。它们先等待服务端的 SETTINGS（RFC 8441 §3），服务端不允许 extended
   CONNECT 时以 `H3Error::Protocol` 失败，被拒绝时以新增的 `H3Error::Status(u16)` 失败。
   `H3WsOptions` 对应 `only_ws::client::DialOptions`（配置、deflate 提议、子协议、origin、头部、
   关闭超时）。
3. **only-ws 增加传输接缝：** `WsSender` 通过 TCP 连接（与以前一样）或一个 `WsLink` trait 对象
   （`#[doc(hidden)]`，与 `WsSession` 一样不在 semver 承诺内）写出，配套
   `WsSession::with_link` / `client_with_link`。TCP 路径是一次枚举匹配，而不是虚调用。
4. **QPACK 动态表（RFC 9204），双向，服务端设置放在 `H3Config`**，客户端放在 `H3ClientOptions`
   （`H3Client::dial_with(.., H3ClientOptions)`，与响应限制和请求超时并列）：
   - `qpack_max_table_capacity`（默认 **4096**）和 `qpack_blocked_streams`（默认 **16**）约束对端
     编码器能对我方解码器做什么：插入经对端的 encoder stream 到达；需要尚未收到的插入的字段段会
     等待（该流后续字节按顺序重新编码暂存），最多到 blocked streams 上限，超过则以
     `QPACK_DECOMPRESSION_FAILED` 关闭连接。我方 decoder stream 发送 Section Acknowledgement、
     Insert Count Increment 和 Stream Cancellation。内存受每连接的容量约束，被阻塞的流再加上 QUIC
     流控允许进入的数据。
   - `qpack_encoder_capacity`（默认 **0**：关闭）启用我方编码器的动态表，最多为对端允许的容量。
     编码器是保守的：只引用对端已确认的条目（Known Received Count），因此从不阻塞对端，也从不占用
     对端的 blocked streams 额度；只插入会重复的字段（不插 `:path`、`date`、`content-length`、
     校验器、range、凭据和 cookie），每个条目最多占表的四分之一，只淘汰没有未确认字段段引用的
     条目；最多跟踪 1024 个未确认字段段（超过后不再引用，因此从不确认的对端无法让它的内存增长）。
     响应可以从任意线程发出，所以编码器在一个 mutex 后面；编码器关闭时不加任何锁。
   - **为什么编码器默认关闭。** 解码器默认开启后，会压缩的对端（curl 里的 nghttp3、OpenSSL 的
     协议栈）已经能在与我们通信时节省它们的字节。开启我方编码器节省的是我方字节（端到端测试中，
     重复自定义头部的请求字节少 20% 以上），但每个用到动态表的字段段都必须在 decoder stream 上确认
     （RFC 9204），每个消息还要获取编码器的 mutex：在 `quic-bench h3`（请求很小）上两端都开启
     编码器时只有默认配置的 0.82 倍。只有对端解码器允许动态表时才有收益，而 quic-go、fib 和 curl
     宣告的都是 0。为大多数对端用不上的收益付出每连接的成本，不是好的默认值；需要时打开一个设置
     即可。
5. **服务端流式请求 body，与 HTTP/2 一致。** 请求流用一个从不缓冲 DATA 负载的读取器读取（只暂存
   不完整的帧头或 HEADERS 帧）。`body_mode` 为 `Stream` 的 service 在请求的第一批 body 字节到达时
   派发（因此没有 body 的请求从不询问），通过 `Context::on_body` 收到它们；`max_body_bytes` 对它
   不适用；仍然检查 `content-length`（不一致时以 `H3_MESSAGE_ERROR` 重置流）。缓冲模式的 service
   行为不变。钩子是 `only_http::transport::start` / `Started`（transport 模块是
   `#[doc(hidden)]`），它也把已接受的 WebSocket 交给传输层。
6. **客户端流式上传：** `H3Client::upload(method, path, headers, cb) -> H3Upload`，带 `write`、
   `finish` 和 `queued_bytes`（用于控制节奏），与 `H2Client::open` 的 `H2Upload` 类似；响应和
   `request` 一样交给 `cb`。
7. **新的 HTTP/3 错误码**，在 `only_h3::code` 中：`QPACK_ENCODER_STREAM_ERROR`、
   `QPACK_DECODER_STREAM_ERROR`。

## 后果

- `Request` 增加 24 字节（`protocol`）。编码器关闭时 `quic-bench h3` 与上一版本速度相同：在 gpu51
  （CPU 2-5）上两次同轮 A/B，各 7 轮交替，分别为 0.998 倍和 1.003 倍，14 轮合计 1.001 倍（88.32 万
  vs 88.27 万 请求/秒）；每请求周期数相同，每请求指令数 +0.8%。最初的完整版本为 0.956 倍。回到持平
  靠的是：没有动态引用的字段段走纯静态解码；整个到达的请求原地读取完整帧；上传、WebSocket、被阻塞
  字段段以及除字节外还需要别的东西的排队请求，其附加状态装箱；每请求的调用保持内联（请求有 232
  字节，每经过一次非内联调用就被复制一次）。精确到函数的指令数来自 callgrind（arm64，Docker）。
- 与加入了客户端上限（响应限制、请求截止时间）和 QUIC 发送上限的 main 2d1f5720 相比，合并后的分支在
  同一基准上为 0.980 倍（84.25 万 vs 85.96 万 请求/秒；0.984 倍和 0.977 倍，14 轮全部更低）。功能本身
  的开销没有变化（callgrind，arm64：only-h3/only-http 每请求 +169 条指令，与合并前相同）；在 x86 上为
  +252 条指令（整体每请求 +1.6%，周期数 +2.6%），分散在请求路径上，没有单一热点。
- 服务端的 SETTINGS 现在带有 4 KiB 动态表、16 个 blocked streams 和 extended CONNECT，并会打开一个
  QPACK decoder stream；会压缩的对端立即使用这张表。互通：quic-go（双向 HTTP/3 WebSocket、双向
  流式上传；它的 QPACK 没有动态表），以及 Docker 中通过 libcurl 的 ngtcp2/nghttp3 和 OpenSSL QUIC，
  其中 nghttp3 的编码器会填充我方的表，对端分别是关闭和开启我方编码器的服务端。
- 新的 fuzz 目标 `qpack_dynamic` 覆盖 encoder stream 解析（与切分无关）、动态字段段以及我方编码器
  对我方解码器；`h3_frame` 和 `h3_request` 覆盖流式读取器、QPACK 流、被阻塞的字段段和 extended
  CONNECT。
- 未完成：HTTP/2 上的 WebSocket（RFC 8441）、我方编码器的 Duplicate 指令和动态名称引用、客户端的
  流式响应 API（`H3Client` 仍缓冲响应）、服务端推送。
