# ADR-020：Span、推送导出（OTLP、StatsD）、HTTP 按路由标签与 HTTP/2 gauge

[English](020-spans-and-push-export.md) | 简体中文

状态：已采纳（2026-11-17）

## 背景

ADR-015 让引擎拥有了经 Prometheus 抓取提供的可插拔收集器，并留下了 DEV-PLAN（M6“生产”和 akio-log 条目）
列出的四个缺口：没有 span（akio-log 只有记录；“`tracing` feature”是未完成项）、没有推送导出（StatsD、OTLP）、
HTTP 指标没有按路由的标签（需要基数策略）、HTTP/2 除按版本的请求数外没有连接和流的 gauge。库不引入第三方依赖
（ADR-005），I/O 线程绝不阻塞（docs/rules.md 第 1 条），队列有界（第 7 条），热路径每个请求不加全局锁、
不增减共享引用计数（第 12 条）。

## 决定

### 在 akio-log 中实现 span，不做 `tracing` 桥接

akio-log 增加 `span` 模块（`akio::log::span`），没有依赖：

- `SpanContext`（128 位 trace id、64 位 span id、采样标志、远端标志），支持解析和输出 W3C `traceparent`；
  `Span`（可空的 box：禁用的 span 是一个指针，对它的所有方法都是空操作）、`SpanBuilder`、`span!` /
  `error_span!` …… `trace_span!`，键值语法与记录宏相同；`record`、`set_name`、`set_kind`、`set_status`、
  `enter`（线程局部的当前 span，由守卫恢复）、`in_scope`、`enter_context`、`current`。
- `Tracer`（`enabled`、`sample`、`on_end(SpanData)`），每个进程安装一次（`set_tracer` / `set_boxed_tracer`），
  以及独立的最大 span 级别（`set_max_span_level`，默认 `Off`），与日志级别分开，打开日志不会打开 span。
  一条 span 语句先检查编译期上限和这个级别（一次 relaxed 读），与日志语句相同。
- 父级：显式给出的上下文（可以是远端的），否则是线程当前的 span，否则开始新的 trace。根 span 和远端父级的
  采样由 tracer 决定；本地 span 的子 span 跟随父级。未采样的 span 保留 id（用于传播），不记录任何东西。
- `FmtLogger` 为进入的 span 内写出的记录加上 `trace_id` / `span_id`。

不做 `tracing` 桥接（可选 feature 也不做）：`tracing` 的 subscriber 需要由 `tracing` 宏构建的 `&'static`
callsite 元数据，转发 akio-log 的 span 要么为每个不同的 span 名泄漏元数据，要么用固定 callsite 把名字藏进字段，
对它的生态都不友好；而且桥接要跟随一个演进很快、不在 semver 承诺内的 crate。常见的去处——OpenTelemetry
collector——由下面的推送导出覆盖；其他去处，`Tracer` 是任何应用都能实现的三方法 trait。

### HTTP 埋点

akio-http 在三个分派点（HTTP/1.x、HTTP/2 流和 push、akio-h3 使用的 transport 接缝）启动请求 span（target
`akio_http::request`，级别 `info`，种类 server），带 `traceparent` 时作为其子 span；在调用 service 期间进入它；
路由器匹配时改名为 `"<method> <route>"`；在响应路径（`Finish::apply`，detach 和流式响应也经过这里）结束，记录
状态码，5xx 设置错误状态。检查是内联的 `akio_log::span::enabled(Level::Info)`，工作放在冷函数里。连接 span
（`akio_http::connection`，`debug`）覆盖 HTTP/1.x/HTTP/2 会话和 HTTP/3 连接（akio-h3 使用
`akio_http::trace::connection_span`）。新增公开项：`Context::route`、`Context::span_context`、`RouteInfo`、
`trace::{REQUEST_TARGET, CONNECTION_TARGET, connection_span}`。

### 按路由的标签

路由器为每个不同的方法和模式驻留一个 `RouteInfo`（方法、模式、进程内唯一 id），做法与驻留参数名相同，匹配时
存进 `Context`（一次指针写入）。`HttpMetrics::with_routes(n)`（n ≤ 4096）通过一个用 compare-and-swap 无锁填充的
固定开放寻址表把路由 id 映射到槽位；槽位计数器（状态类别、延迟直方图）与现有总数一样分片。标签是模式，绝不是
路径；超过 `n` 的路由共用 `route="other"`，未匹配的请求是 `route="unmatched"`。`HttpMetrics::new()` 不变：
没有表，只有一个可预测的分支。新增 `route_snapshot()` 和两个族（`akio_http_route_requests_total`、
`akio_http_route_request_duration_seconds`）。

### HTTP/2 gauge

`H2Stats`（分片的 relaxed 计数器，一个 `Collector`），通过新字段 `H2Config::stats` 设置（默认 `None`）：
打开和关闭的连接与流（gauge 是它们的差）、两个方向的 `RST_STREAM` 和 `GOAWAY` 帧。连接关闭时，它仍打开的流
被计为关闭，只计一次（在关闭时或 core 被 drop 时）。

### 推送导出：新 crate `akio-export`

依赖：akio-core、akio-log、akio-protobuf（都是自有 crate）。一个线程（`akio-export`）：

- 每个间隔发送指标：`Telemetry::collect_all()`（新增，配合 `Metrics::collect_into`：引擎的序列以 `Families`
  表示，与 Prometheus 渲染一致）加上额外的收集器；
- OTLP/HTTP，protobuf（用 akio-protobuf 的线格式原语手工编码）或 JSON，来自同一棵消息树；计数器为累积单调
  sum，gauge，显式分桶直方图；span 按 target 分组到 scope；
- 经 UDP 的 StatsD 和 DogStatsD：基于有界的上次值表计算计数器增量，gauge，直方图 count/sum/bucket 增量，
  数据报按大小上限打包；
- span：`traces(level)` 安装一个 tracer，它的 `on_end` 把 span 推入按总数限界的分片队列（默认 4096）；超出时
  span 被丢弃并计数。批次每个 `span_interval` 发送一次，或攒满一批时发送（`try_send` 唤醒，从不等待）。

单独的 crate 让不导出的程序、以及 akio-core，不必链接 akio-protobuf 和客户端代码。不提供 gRPC 上的 OTLP：
所有 collector 都接受 HTTP/protobuf，后台线程也不需要 HTTP/2 客户端。不提供到 collector 的 TLS：客户端是基于
`std::net` 的明文 HTTP/1.1，面向本地 collector 或 agent。

## 考虑过的其他方案

- **akio-log 的可选 `tracing` feature**（与 `log` 桥接一样不在 semver 内）：因上述 callsite 原因拒绝；
  如果有用户需要，可以作为独立 crate 再议。
- **span 与日志共用级别**：拒绝；应用把日志调到 `info` 就会开始为请求 span 付费。
- **以请求路径为键、配 LRU 的按路由标签**：输入无界，每个请求一把锁；路由器本来就知道模式。
- **加互斥锁的路由表**：每个请求一把全局锁（第 12 条）。
- **在 I/O 线程上导出，或重试失败的推送**：阻塞和无界内存。
- **把导出器放进 akio-core 或 akio-http**：每个服务器都要链接 protobuf 运行时和客户端。

## 影响

- akio-log、akio-core、akio-http 的公开 API 只有新增（`H2Config` 多了一个字段；它是 `#[non_exhaustive]`，
  只有 crate 内部的结构体字面量需要修改），外加一个新 crate。
- 全部关闭时，请求路径多一次原子读（span）、一次指针写入（路由）和两个预测良好的分支：没有可测变化
  （docs/BENCHMARKS.zh-CN.md“可观测性开销”）。开启时：`H2Stats` 无开销，按路由标签约 0.5%，在每秒 460 万
  pipelined 请求下 span 采样 1% 约 12%，100% 并导出约 46%。
- tracer 按进程安装：每个进程一个带 traces 的导出器。
- 未完成：gRPC 上的 OTLP、到 collector 的 TLS、OTLP 日志、span 事件和链接、exemplar、`tracing` 桥接。除桥接外均由
  [ADR-064](064-otlp-grpc-tls-logs-events-exemplars.zh-CN.md) 补齐，它还把“推送失败即丢弃”改为退避重试。
