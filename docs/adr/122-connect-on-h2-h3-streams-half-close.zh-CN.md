# ADR-122：HTTP/2 和 HTTP/3 流上的 CONNECT，以及关闭连接的发送方向

[English](122-connect-on-h2-h3-streams-half-close.md) | 简体中文

状态：已采纳（2026-11-25）

## 背景

fit 的 `forward_proxy` 能在 HTTP/1.1 连接、HTTP/2 流（RFC 9113 §8.5）和 HTTP/3 流（RFC 9114
§4.4）上为 `CONNECT` 建立隧道。akio-http 只把扩展 CONNECT（`:protocol`，ADR-113）的 HTTP/2 流
当作隧道分派，而把省略 `:scheme` 和 `:path` 的普通 CONNECT 当作格式错误拒绝；akio-h3 能解析
普通 CONNECT，却要等它的流结束才分派，而隧道的流在应答之前从不结束。akio-socks 的
`connect_proxy` 用 `Context::upgrade_raw` 建立隧道，只支持 HTTP/1：在流上它返回 `false`，请求
永远得不到应答。akit 目前对这类请求回 `501`，并以 A134 提出了这个需求
（`akit/docs/akio-api-requests.md`）。

隧道的两半各自关闭：RFC 9113 §8.5 要求代理把客户端的 END_STREAM 作为 TCP FIN 传下去。akio 没有
办法只关闭连接的发送方向而继续读取：`close_after_send` 会把两个方向都关掉。

## 决定

- **akio-http（HTTP/2）。** 不带 `:protocol` 的 `CONNECT` 只携带 `:method` 和 `:authority`；
  出现 `:scheme` 或 `:path`，或缺少 `:authority`，即为格式错误（`RST_STREAM PROTOCOL_ERROR`）。
  它的目标就是 authority，与 HTTP/1.1 的 `CONNECT` 相同。它像扩展 CONNECT 一样立即分派，DATA 是
  流式请求体（`on_body`，可用 `body_reads` 暂停），流式的 `2xx` 使该流成为两半各自关闭的隧道
  （ADR-113 的逗留与重置同样适用）。`H2Client` 以同样的形式发送：方法为 `CONNECT` 的请求只携带
  `:method` 和 `:authority`，authority 取它的 `Host` 字段（否则取 URL 的主机），因此
  `H2Client::open` 可以作为隧道的客户端一端。
- **akio-h3。** `CONNECT`（扩展的或普通的）在收到头部时就分派，流上的字节交给 sink；流式的
  `2xx` 即为隧道，与 ADR-113 相同。
- **akio-socks。** `connect_proxy` 在 HTTP/2 或 HTTP/3 流上为 `CONNECT` 做中继，与该连接上的其他
  请求并行：目标解析、目的地策略（403）、在解析线程上做名字解析、连接检查
  （`ProxyConfig::connected`）、连接超时、握手超时和空闲超时都与 HTTP/1.1 相同，失败以 `400`、
  `403`、`502`、`503` 或 `504` 应答。上游连上后回复流式的 `200`。流上的 DATA 到达即发往上游；
  上游队列超过水位线时、以及上游连上之前，暂停该流的读取（`BodyReads`），连上之前收到的数据
  （至多一个水位线）先发出；上游的字节写到流上，流的队列超过水位线时暂停上游的读取
  （`BodyStream::on_drain`）。客户端的 END_STREAM 在其字节写完后关闭上游的发送方向；上游关闭则
  结束我方这一半。客户端重置流或离开时关闭上游（`on_gone`）；超时在 `200` 之前回 `504`，之后则
  重置该流。看门狗的会话现在可以是任意客户端 `Side`：连接或流。
- **akio-core。** `ConnInner::shutdown_write_after_send` 与 `Conn::shutdown_write_after_send`
  在队列清空后（传输层的结束消息之后）关闭发送方向（`shutdown(SHUT_WR)`），并继续读取。它在写出
  队列的地方完成，所有流式后端（epoll、kqueue、io_uring）共用这段代码；数据报与虚拟（DPDK）连接，
  以及发送已交给内核 TLS 的连接，忽略它。

被否决的方案：

- **在流上使用 `Context::upgrade_raw`。** 流本身不是独立的字节流：它的 DATA 与连接共享流量控制，
  结束方式是 END_STREAM 或重置。流式请求与流式响应已经具备隧道所需的一切（ADR-113 也否决了第二条
  路径）。
- **客户端 END_STREAM 时关闭上游。** 这会丢掉上游仍在回送的数据（回显、随结束一起发出的请求的
  应答），半关闭则保留它们。
- **接受带 `:scheme` 和 `:path` 的普通 CONNECT。** RFC 9113 §8.5 规定其格式错误，Go 的服务端
  也如此处理。

## 影响

- akit 的 `forward_proxy` 在三种协议上都把每个 `CONNECT` 交给 `connect_proxy`。
- 没有新增 `unsafe`。`WriteState` 多了两个标志。
- 测试：`crates/akio-http/tests/tunnels.rs`（普通 CONNECT 立即分派并建立隧道，格式错误的被
  重置），`crates/akio-h3/tests/tunnel.rs`（HTTP/3 上同样），
  `crates/akio-socks/tests/connect_streams.rs`（一个 HTTP/2 连接上的两条隧道，经过窗口与水位线
  各自双向传输 4 MiB；客户端的 END_STREAM；`400`、`403`、`502` 拒绝；重置关闭上游；上游关闭结束
  我方这一半；空闲超时；以 `H2Client::open` 作为客户端；HTTP/3 上的隧道和拒绝），
  `crates/akio/tests/conn_api.rs`
  （`shutdown_write_after_send_keeps_reading`）；epoll 与 io_uring。
