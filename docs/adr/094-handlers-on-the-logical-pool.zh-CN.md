# ADR-094：协议 handler 在逻辑线程池上执行，按协议配置，默认关闭

[English](094-handlers-on-the-logical-pool.md) | 简体中文

状态：已采纳（2026-11-23；2026-11-25 更新：`H2Config::handlers_on_logical_pool` 默认开启；2026-11-26 更新：
改回默认关闭，并把开关从 `run_on_pool` 改名，见[更新（2026-11-26）](#更新2026-11-26http2-恢复-inline以及改名)）

## 背景

协议 handler 运行在连接所属的 I/O 线程上（ADR-001、规则 §1）。阻塞的 handler 会卡住该线程上的所有
连接，所以阻塞工作只能手动移走：先 `detach`，再从应用自选的线程答复；原始 handler 则用
`Conn::spawn_blocking`。

缺少两样东西：

- **按协议的开关。** handler 大多会阻塞的应用（每个请求查一次数据库）希望所有请求都在线程池上执行。
  它们还希望一个多路复用连接上的多个请求（HTTP/2 stream、HTTP/3 请求、gRPC 调用、arpc 请求）同时
  处理，而不是在 I/O 线程上一个接一个。
- **一个"把这个请求放到线程池"的调用。** 即 `detach` 加上线程池句柄。HTTP 的 `Context` 原先拿不到
  engine 的线程池。

HTTP/1.1 的响应顺序已经由有序响应位置（`Conn::reserve_response`）保证。每个请求在 handler 执行前
预留位置，inline 答复和 detach 后的答复都填进这个位置。因此两者混合时本来就有序。

## 决定

- **akio-core。** `ConnInner::execute(job) -> Result<(), Job>` 把任务放进 engine 的线程池；线程池
  拒绝时原样交还、不执行。`Conn::execute(work)` 是给应用的同样接口，与 `spawn_blocking` 的区别是
  没有完成回调。`akio_quic::Connection::execute` 为 QUIC 连接提供同样的能力。
- **akio-http。**
  - `HttpConfig::handlers_on_logical_pool`（HTTP/1.1）和 `H2Config::handlers_on_logical_pool`（HTTP/2），默认都是 `false`。
  - 开启后，完整的请求在线程池上执行中间件和 handler，之后才处理"handler 既没答复也没 detach 时
    返回 `500`"。
  - 两类请求仍在 I/O 线程执行：可能接管连接的请求（HTTP/1.1 `CONNECT` / `Upgrade`、HTTP/2 扩展
    CONNECT），以及请求体以流方式交付的请求。这些 handler 要在 I/O 线程上与 session 交互。
  - 在线程池上的 context 会拒绝 `upgrade_websocket` / `upgrade_raw`。
  - `Context::executor()` 返回该请求所在连接的 `Executor`；`Context::detach_to_pool(f)` 先
    detach，再在线程池上执行 `f`。
  - `ConnSink::execute`（默认：没有线程池）和 `transport::dispatch_conn_on_pool` 让本 crate 之外的
    传输层也能这样做。
- **akio-h3。** `H3Config::handlers_on_logical_pool`，经由 `dispatch_conn_on_pool` 实现。
- **akio-grpc。**
  - `GrpcServer::handlers_on_logical_pool(bool)`。gRPC 以流方式接收请求体，HTTP 的开关管不到它。
  - 每个调用有一个队列：同一时刻只有一个线程池任务打开该调用，并按顺序交付它的消息，所以 handler
    看到的与 inline 时完全一样，而不同调用同时执行。
  - 等待忙碌 handler 的消息计入 `max_collect_bytes`。
  - panic 的 handler 以 `INTERNAL` 结束它的调用。
- **akio-arpc。** `Routes::handlers_on_logical_pool(bool)` 作用于请求和通知；stream 仍在 I/O 线程。线程池拒绝时的
  错误文本是 `SERVER_BUSY`。
- **线程池满时**立即答复：HTTP 返回带 `Retry-After: 1` 的 `503`，gRPC 返回 `RESOURCE_EXHAUSTED`，
  arpc 返回 `SERVER_BUSY`。
  - 被拒绝的任务以不透明的 `FnOnce` 形式交还。在 inline 执行它的前后设置一个线程局部标志，告诉它
    答复"忙"而不是执行原工作。这样不必为了能拿回 context 而每个请求多一次分配。

## 影响

- 开启后 handler 可以阻塞，多路复用连接获得单连接内的并发。代价是每个请求多一次交接（一次线程池入队
  和一次线程唤醒）。默认仍为 inline，非阻塞 handler 在 inline 下最快。
- 开启后，arpc 通知，以及 HTTP/2、HTTP/3、arpc 的请求，可能以任意顺序完成。HTTP/1.1 的响应和每个
  gRPC 调用的消息保持顺序。
- 线程池上执行的请求，其请求 span 在线程池线程上进入。
- 线程池上执行的请求不回收线程局部的备用缓冲区。

## 未做

- 流式请求体的线程池分发：请求体的 sink 需要跨线程喂数据。
- `Router` 上按路由的开关。单个路由用 `detach_to_pool` 即可。

## 更新（2026-11-25）：HTTP/2 默认在线程池上执行（2026-11-26 撤回）

`H2Config::handlers_on_logical_pool` 的默认值改为 `true`；其他开关（`HttpConfig::handlers_on_logical_pool`、
`H3Config::handlers_on_logical_pool`、`GrpcServer::handlers_on_logical_pool`、`Routes::handlers_on_logical_pool`）仍默认关闭。

- inline 时，一个 HTTP/2 连接的各个 stream 在它的 I/O 线程上按请求完成的顺序逐个处理：慢 handler
  会拖住同一连接的其他 stream 以及该线程上的所有其他连接；而连接从不迁移（ADR-001），一个繁忙的
  多路复用客户端只会压在一个线程上。多路复用正是使用 HTTP/2 的理由，所以默认改为让同一连接的各个
  stream 同时处理。
- 留在 I/O 线程上的部分不变：流式请求体和 CONNECT（包括扩展 CONNECT，即 HTTP/2 上的 WebSocket）。
- 现在默认就要承担的代价：每个完整请求一次线程池交接；同一连接的响应可能以任意顺序完成（HTTP/2
  允许）；线程池满时回 `503` 并带 `Retry-After: 1`；请求 span 在线程池线程上进入；线程池上的请求
  不回收线程局部的备用缓冲区；在线程池 handler 中调用 `Context::after` 时，回调在本 crate 共享的
  定时器线程上执行，而不是 I/O 线程。
- handler 从不阻塞的服务可以设置 `handlers_on_logical_pool: false` 恢复 inline 路径。

## 更新（2026-11-26）：HTTP/2 恢复 inline，以及改名

`H2Config::handlers_on_logical_pool` 的默认值改回 `false`，与其他开关一致。在 gpu51 上实测
（docs/BENCHMARKS.zh-CN.md，共享 I/O 线程组）：4 个 I/O 线程、4 个 CPU，handler 很轻的 h2c 走线程池
约每秒 49 万请求，inline 则是 320 万–400 万，给线程池更多 CPU 也提不高这个上限；改用 Rounds
调度或调整线程池线程数也不行（16 个线程结果相同，更少则更低）。让所有不阻塞的
HTTP/2 服务默认损失大部分吞吐，这个取舍不对；handler 会阻塞的服务自行打开开关（或用
`Context::detach_to_pool` 分离单个请求），2026-11-25 更新中的理由留作这个开关的说明。

这些开关原名 `run_on_pool`，既没说明什么在那里执行，也没说明是哪个线程池（轮次调度的线程组本身也是
一组 worker）。现在所有协议（`HttpConfig`、`H2Config`、`H3Config`、`GrpcServer`、`Routes`）都叫
`handlers_on_logical_pool`：每个请求的中间件和 handler，在引擎的逻辑线程池上执行。旧名字没有随任何
版本发布，所以不保留别名。

[ADR-176](176-http2-handlers-inline-by-default.zh-CN.md) 记录了同一决定所依据的 A169、A171 同轮 A/B（线程池上慢 9–13 倍）和线程池路径的 profile。
