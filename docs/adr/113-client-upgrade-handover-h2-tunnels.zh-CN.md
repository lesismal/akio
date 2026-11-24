# ADR-113：HTTP/1 客户端在 `101` 时交出连接，HTTP/2 扩展 CONNECT 的流式 `2xx` 应答即隧道

[English](113-client-upgrade-handover-h2-tunnels.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit 像 fit 一样代理 WebSocket（其迭代 I49）：客户端的握手以 HTTP/1.1 upgrade 发往上游，上游切换协议后，
再用上游的应答切换客户端，并把两条字节流接起来，一侧落后时暂停另一侧的读取。HTTP/1.1 客户端用 `Upgrade`
请求；HTTP/2 或 HTTP/3 客户端用扩展 CONNECT（RFC 8441、RFC 9220）。akit 提出两项请求（A93、A94），已在
akio main `f6750e93` 上核对：

- **A93。** akio-http 的 `Client` 把 `101 Switching Protocols` 当作没有响应体的响应：结束这次交换，把连接放回
  keep-alive 池，之后到达的字节被当作“没人要的字节”并关闭连接。没有办法接管这条连接，代理无法经由客户端
  （及其连接池、TLS 与超时）拿到上游已切换协议的连接（`crates/akio-http/src/client.rs` 的 `advance`）。
- **A94。** HTTP/2 服务端已把扩展 CONNECT 作为流式请求分发：流的 DATA 到达 `Context::on_body`，`BodyReads`
  可暂停读取，流式响应（`Context::stream_response`、`Detached::stream_response`）配合 `on_drain` 写回。
  但只有 `Context::upgrade_websocket` 会把流标记为两半各自关闭的隧道：客户端一半仍开着时结束的流式 `200`
  会以 `RST_STREAM NO_ERROR` 收尾，截掉客户端最后的字节（例如 WebSocket 关闭帧的回应）。akit 的代理要等上游
  应答后才能应答，所以不能用 `upgrade_websocket`（它立即应答，自行选择子协议与扩展，并在服务端终结
  WebSocket）。HTTP/3（`akio-h3`）本就让两半分开：QUIC 流的两个方向分别关闭，结束的响应不会停止请求一侧。

约束：没有 unsafe，不阻塞 I/O 线程，HTTP/1 `Session` 不加字段（`size_tests` 要求它不超过 256 字节），
API 只增不改。

## 决定

**A93：`ResponseHandler::on_upgrade`。**

- `ClientRequest::upgrade(protocol)` 设置 `Connection: Upgrade` 与 `Upgrade: <protocol>`；任何带
  `Connection: upgrade` 记号的请求同样视为请求升级。
- `ResponseHandler::on_upgrade(&mut self, head: &ResponseHead, conn: &RawConn) ->
  Option<Box<dyn RawHandler>>`，默认返回 `None`。对请求升级的请求收到 `101` 时，客户端结束该请求（其超时与
  `CancelToken` 不再生效，连接不再回到池中）并调用它。返回的处理器以普通字节流接管连接：立即调用
  `on_open`，再以服务端在头部之后发送的字节调用 `on_data`，之后随到随调，关闭时调用 `on_close`。此后不再调用
  `on_head`、`on_end` 或 `on_error`。返回 `None`：`101` 作为没有响应体的响应交付（`on_head`、`on_end`），
  连接关闭。
- `RawConn` 是 akio-http 已有的句柄（`Context::upgrade_raw` 所用）：`send`、`hold_reads`、`on_drain`、
  `queued_bytes`、`set_relayed`、`close_after_send`；在 TLS 上其字节照旧由连接的传输层加密。
- 对升级请求的整体响应（`Client::request`、`send`）返回 `101` 并关闭连接。对未请求升级的请求返回的 `101`
  以 `ClientError::Protocol` 失败。收到 `101` 之前，请求的响应头超时、总超时与取消令牌照常生效。

处理器状态存放在客户端连接的处理器中（`ClientConn` 新增的 `RState::Tunnel`），读取直接交给 `RawHandler`，
无锁、无拷贝。

**A94：对扩展 CONNECT 的流式 `2xx` 应答打开隧道。**

- HTTP/2：流记录其请求是否为扩展 CONNECT；状态为 `2xx` 的流式响应使其成为隧道，与 `upgrade_websocket` 的
  `200` 完全相同。此后两半各自关闭：我方 END_STREAM（`BodyStream::finish`）后对端一半仍开着，其 DATA 继续到达
  `on_body`，直到对端结束（`BodyEvent::End`）。对端一直不结束其一半时，我方 END_STREAM 发出后
  `TUNNEL_LINGER`（5 秒）以 `CANCEL` 重置该流；这个计时从 WebSocket 链路的 `close_after_send` 移到流的半关闭
  处，两种隧道都经过这里。非 `2xx` 的应答不是隧道，保持原有行为（请求未结束即应答时 `RST_STREAM NO_ERROR`）。
- HTTP/3：不变，补充文档与测试。

否决：

- **新增 `Context::upgrade_tunnel`**，立即接管 HTTP/2 或 HTTP/3 流、稍后再自行应答：流式请求与流式响应已具备
  隧道所需的一切（按流暂停读取、以 `on_drain` 控制写入节奏、以 `on_gone` 得知客户端离开），第二条路径只会重复。
- **推迟 HTTP/1 服务端的升级**（`Detached::upgrade_raw`）：HTTP/1 会话必须在请求升级的请求之后停止解析，
  直到处理器做出决定，这个状态要让 256 字节的 `Session` 在每条连接上付出代价。在处理器中调用
  `Context::upgrade_raw`，等上游应答后由处理器写出 `101` 或拒绝应答，不需要任何新东西。
- **从 `on_head` 交出连接**（`ResponseBody::take_conn`）：`on_head` 之后必有 `on_end` 或 `on_error`，所有处理器
  都依赖这一约定；单独的回调可以保持它。

## 影响

- akit 的 I49 经由其连接池，把来自 HTTP/1.1、HTTP/2 与 HTTP/3 客户端的 WebSocket 代理到 HTTP/1.1（及 TLS）
  上游，双向背压。
- 代价：`Pending` 与 `Active` 各加一个 `bool`；`RState` 加一个装箱的变体；HTTP/2 `Stream` 加一个 `bool`。
  热路径不变：不升级的请求只读一次该标志。未测量（规则 20）。
- 测试：`akio-http/tests/tunnels.rs`（`101` 交出连接并带上头部之后的字节，且比请求的超时与令牌活得久；拒绝、
  处理器不接管、未请求的 `101`、整体响应；`101` 之前的响应头超时；以流式 `200` 应答的 HTTP/2 扩展 CONNECT：
  任一半先结束、延迟后的重置、不是隧道的拒绝）与 `akio-h3/tests/tunnel.rs`（HTTP/3 的两半），在 epoll 与
  io_uring 上运行。
