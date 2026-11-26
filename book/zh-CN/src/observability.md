# 可观测性与热更新

每个 engine 都有一个**遥测中心**（`akio::Telemetry`）：每线程计数器、连接表、慢回调记录以及
实时（可热更新的）设置。engine 构建之前通过 `Config::telemetry` 访问，构建之后通过
`Engine::telemetry()` 访问。I/O 线程用 relaxed 原子操作更新各自的普通计数器（按缓存行对齐，
每个事件既不加锁也不分配内存）；快照按需汇总。

## 在代码中

```rust,ignore
{{#include ../../../crates/akio/examples/guide-config.rs:observe}}
```

| 调用 | 返回 |
|---|---|
| `Engine::metrics()` | `Metrics`：每线程的 `LoopMetrics`（所属、是否运行、计数器）、`total`、`open_connections`、`open_accepted`（只计 accept 的 TCP 连接，不含拨出的连接和 UDP 对端；也可用 `Telemetry::open_accepted()`）、`pool`、`uptime`；`to_prometheus()`、`to_json()` |
| `Engine::connections(timeout)` | 连接表：每个连接一个 `ConnInfo`（id、对端、本端、所属线程、存活时长、空闲时长、收发字节、排队字节、是否暂停读、是否背压、transport、是否 UDP）。通过询问每个 I/O 线程收集；不要在 I/O 线程的回调里调用 |
| `Engine::slow_callbacks()` | 最近的慢回调（最多 256 条），由旧到新 |
| `Engine::pool_stats()` | 逻辑线程池的线程数、空闲数、排队数、完成数、panic 数、拒绝数；排队的续作任务数、最深积压、在 `akio::blocking` 里阻塞的线程数、补位线程数、碰到补位上限的次数；各档压力告警次数，以及池子此刻是否被监视（[阻塞任务](concepts/blocking.md)） |
| `Engine::udp_stats()` | 打开的 UDP 对端数，以及被 `udp_max_peers` 拒绝的数据报数 |
| `Engine::accel_status()` | 每个 listener 的 eBPF 分流状态 |
| `Telemetry::collect()`、`Telemetry::render_prometheus()` | 已注册收集器的 `Families`（Prometheus 或 JSON）；engine 序列加收集器序列，即 `metrics_handler` 输出的内容 |

## Prometheus

engine 指标（每个 I/O 线程一条序列，标签为 `listener`、`backend`、`thread`）：

| 序列 | 类型 |
|---|---|
| `akio_connections_accepted_total`、`akio_connections_dialed_total`、`akio_connections_closed_total` | counter |
| `akio_connections_rejected_total`（max_connections）、`akio_connections_filtered_total`（`Listener::filter`）、`akio_accept_errors_total`、`akio_idle_timeouts_total` | counter |
| `akio_read_bytes_total`、`akio_reads_total`、`akio_written_bytes_total`、`akio_writes_total` | counter |
| `akio_udp_datagrams_received_total`、`akio_udp_datagrams_sent_total` | counter |
| `akio_send_queue_bytes` | gauge |
| `akio_backpressure_events_total`、`akio_overloaded_total` | counter |
| `akio_tls_handshake_failures_total`、`akio_transport_errors_total` | counter |
| `akio_loop_iterations_total`、`akio_loop_events_total`、`akio_loop_callbacks_total`、`akio_loop_callback_seconds_total`、`akio_slow_callbacks_total` | counter |
| `akio_connections_open`、`akio_loop_running`、`akio_loop_max_command_batch`（线程一次从命令列表取走的最多命令数） | gauge |
| `akio_pool_threads`、`akio_pool_active`、`akio_pool_queued`、`akio_pool_resumes`、`akio_pool_max_queued`、`akio_pool_blocked`、`akio_pool_watched` | gauge |
| `akio_pool_completed_total`、`akio_pool_panicked_total`、`akio_pool_rejected_total`、`akio_pool_compensated_total`、`akio_pool_blocked_at_ceiling_total`、`akio_pool_pressure_warnings_total{level="50"...}` | counter |
| `akio_uptime_seconds` | gauge |

`observe::HttpMetrics` 提供的 HTTP 指标：`akio_http_requests_total{class="2xx"...}`、
`akio_http_request_duration_seconds`（直方图，桶从 0.5 ms 到 10 s）、
`akio_http_requests_in_flight`、`akio_http_requests_by_version_total{version="1.0|1.1|2|3"}`
（按请求的协议版本统计的响应数；在 h2 和 h3 上即已应答的请求流数量）。QUIC 与 TLS 指标来自各自的收集器，
见[自定义指标](#自定义指标)。

**开销。** 计数器始终开启；设置了慢回调阈值（默认）时还会对回调计时。在安静主机上做的同一轮 A/B
（Ryzen 7 7800X3D、Linux 7.0、5 轮）没有测到开销：关闭计时或把计数器编译掉后，HTTP/1.1 plaintext
与 pipelined 为 0.998–1.006×，TCP 与 UDP echo 在各自 ±5–10% 的噪声之内（docs/BENCHMARKS.zh-CN.md
“遥测开销”）。

`akio_loop_callback_seconds_total / akio_loop_iterations_total` 和慢回调计数是最先要看的：
它们告诉你 handler 是否让 I/O 线程一直忙碌。

## HTTP 端点

```rust,ignore
{{#include ../../../crates/akio-http/examples/guide-observe.rs:endpoints}}
```

- `observe::metrics_handler(telemetry, Some(http_metrics))` 以 Prometheus 文本格式（0.0.4）应答：
  engine 序列、每个已注册的收集器（见[自定义指标](#自定义指标)），以及传入的 `http_metrics`。
- `observe::debug_handler(telemetry, token)` 是一个需要显式启用的运行时调试端点（相当于 Go 的
  pprof 页面），以 JSON 应答。把它挂在通配路由下；路径最后一段选择视图：`conns`（连接表）、
  `loops`（每线程计数器、汇总、线程池）、`slow`（最近的慢回调）、`live`（当前实时设置）。设置了
  token 时，请求必须带 `Authorization: Bearer <token>`（常量时间比较），否则返回 401。连接表在
  辅助线程上收集，从不在服务该请求的 I/O 线程上收集。没有 token 时不要对外公开它。
- `HttpMetrics::middleware()` 按状态类别计数请求、记录延迟、跟踪在途请求。
- `observe::access_log()` 通过 `log` facade 为每个响应写一条结构化记录。

## 自定义指标

任何实现了 `akio::metrics::Collector` 的东西都可以注册到遥测中心，随后出现在同一个 `/metrics`
端点上，位于 engine 自身序列之后（ADR-015）。不涉及任何第三方 crate。

```rust,ignore
{{#include ../../../crates/akio-http/examples/guide-metrics.rs:collectors}}
```

- `Registry` 持有具名的 `Counter`、`Gauge`、`Histogram`（共享原子量，更新不加锁）；以相同名称和
  标签再次获取会返回同一个工具。
- **Exemplar。** `ExemplarHistogram::new(bounds)`（或 `Registry::histogram_with_exemplars`）是一种直方图，每个桶
  记住最近一次在已采样 span 内的观测值，连同该 span 的 trace id 和 span id（`HistogramSnapshot::exemplars`）；
  `HttpMetrics::with_exemplars()` 对请求延迟直方图做同样的事，取自请求 span。它们经 OTLP 导出（Prometheus
  文本格式没有它们的位置）。普通 `Histogram` 不为它们付出任何代价（是单独的类型）；`ExemplarHistogram` 每次观测多一次线程局部读取，
  在已采样 span 内再加一次读时钟和一次从不等待的 `try_lock`（ADR-064）。
- `fn_collector(|out| ...)` 把闭包变成每次抓取都会运行的收集器；`out.counter`、`out.gauge`、
  `out.histogram` 添加样本。非法名称、重复的标签名和类型冲突会被丢弃（计入 `Families::dropped()`），
  从不 panic。
- `Telemetry::register_collector(collector, labels)` 给该收集器的每个样本加上常量标签：两个收集器
  输出相同的族时（比如两个 QUIC 服务器），给每次注册不同的标签。`unregister_collector(id)` 取消注册。
- `metrics_handler(telemetry, http)` 输出 `Telemetry::render_prometheus()`（先 engine 序列，再收集器）；
  若 `HttpMetrics` 已作为收集器注册，`http` 传 `None`。

不经 HTTP，以快照形式取得同样的数据：

```rust,ignore
{{#include ../../../crates/akio-http/examples/guide-metrics.rs:snapshot}}
```

现成的收集器：

| 收集器 | 序列 |
|---|---|
| `akio_http::observe::HttpMetrics` | `akio_http_requests_total{class}`、`akio_http_request_duration_seconds`、`akio_http_requests_in_flight`、`akio_http_requests_by_version_total{version}`；用 `with_routes(n)` 时还有 `akio_http_route_requests_total{method, route, class}` 和 `akio_http_route_request_duration_seconds{method, route}` |
| `akio_http::observe::H2Stats`（设在 `H2Config::stats`） | `akio_http2_connections_open`、`akio_http2_connections_total`、`akio_http2_streams_open`、`akio_http2_streams_total`、`akio_http2_resets_total{direction}`、`akio_http2_goaways_total{direction}` |
| `akio_export::Exporter::collector()` | `akio_export_pushes_total{sink, signal, result}`（signal 为 `metrics`、`traces`、`logs`）、`akio_export_otlp_retries_total`、`akio_export_metric_points_rejected_total`、`akio_export_{spans,logs}_exported_total`、`_dropped_total`、`_rejected_total`、`_queued`、`akio_export_statsd_dropped_series_total` |
| `akio_quic::QuicServer`（`akio_h3::serve` 返回的也是它） | `akio_quic_connections_open`（gauge）、`akio_quic_connections_accepted_total`、`akio_quic_connections_closed_total`、`akio_quic_datagrams_total{dir}`、`akio_quic_bytes_total{dir}`、`akio_quic_packets_sent_total`、`akio_quic_packets_lost_total`、`akio_quic_lost_bytes_total`、`akio_quic_congestion_events_total`、`akio_quic_ecn_ce_events_total` |
| `akio::tls::TlsStats`，来自 `Tls::stats()` | `akio_tls_handshakes_total{side, version}`、`akio_tls_resumed_total{side}`、`akio_tls_early_data_total{side, outcome}` |

QUIC 的总数包含已关闭的连接，因此不会下降。收集器运行在处理抓取的线程上（或导出器的线程上，见
[推送导出](#推送导出otlp-与-statsd)），从不在 I/O 线程的热路径上：请让它们保持轻量。

## 按路由的指标与 HTTP/2

```rust,ignore
{{#include ../../../crates/akio-export/examples/guide-export.rs:routes}}
```

- `HttpMetrics::with_routes(n)` 为每个路由增加一行：方法和路由器匹配到的**模式**
  （`GET /users/:id`），绝不是原始路径，因此序列数受注册的路由数和 `n`（最多 4096）约束。超过 `n`
  之后出现的路由共用 `route="other"`；没有匹配任何路由的请求（404、405）记为
  `method="*", route="unmatched"`。路由只有在路由器内部才知道，所以要用 `Router::layer` 安装中间件。
  路由的槽位通过一次无锁表探测找到；计数器和总数一样分片（每个路由每个分片约 200 字节）。
  `route_snapshot()` 不经 Prometheus 直接读取。`Context::route()` 把匹配到的 `RouteInfo` 交给你自己的中间件。
- `H2Stats` 按服务端的视角统计 HTTP/2 连接和流：当前打开数的 gauge（流从 `HEADERS` 起打开，直到关闭或
  被重置；连接关闭时它的流随之关闭）、总数、收发的 `RST_STREAM` 和 `GOAWAY` 帧。一个 `H2Stats`
  可以给多个监听器共用；不设 `H2Config::stats` 就什么都不统计。

## Span

`akio::log` 除了记录还有 span：带字段、父级、种类和状态的计时工作单元，用 W3C trace id 和 span id 标识。
span 结束时交给一个 `Tracer`（导出器，见下文）；它们有自己的最大级别，默认 `Off`：在调高之前，一条 span
语句只花一次 relaxed 原子读，什么也不创建。

```rust,ignore
{{#include ../../../crates/akio-export/examples/guide-export.rs:spans}}
```

- `span!(target: .., Level::Info, "name", key = value, ...)` 和 `info_span!` …… 启动一个 span（字段沿用
  记录的语法，没有 `;` 和消息）。`record`、`set_name`、`set_status`、`set_kind` 修改它；drop 即结束。
  `span.enter()` 让它成为线程当前的 span，直到守卫被 drop：期间启动的 span 是它的子 span，期间写出的记录由
  `FmtLogger` 加上 `trace_id=.. span_id=..`。在事件循环上，只在为它运行的代码周围进入 span，不要跨回调；
  `akio::log::span::enter_context(ctx)` 把上下文带到别的线程。
- 请求 span 启用时，akio-http 为每个 HTTP/1.1、HTTP/2 和 HTTP/3 请求启动一个**请求 span**（target
  `akio_http::request`，级别 `info`，种类 server）：路由器匹配后命名为 `GET /users/:id`（未匹配的请求只用方法名），
  带 `http.request.method`、`url.path`、`http.route`、`network.protocol.version`、`client.address` 和
  `http.response.status_code`；5xx 设置错误状态。处理函数运行期间它是当前 span，响应头发出时结束（detach
  的响应在任何地方发出时结束）。请求带 `traceparent` 头时，它成为调用方 span 的子 span；`ctx.span_context()`
  给出要向下游传播的上下文（`to_traceparent()`）。
- **连接 span**（target `akio_http::connection`，级别 `debug`）覆盖一条连接从 accept 到关闭，带客户端地址和协议版本。
- **事件与链接。** `span.add_event("retry", &[("attempt", 2u64.into())])` 记录 span 中某一时刻发生的事
  （`push_event` 接受自带时间的 `SpanEvent`）；`span.add_link(ctx, &[..])`，或在 span 开始时用
  `SpanBuilder::link(SpanLink::new(ctx))`，指向另一个 span（同一 trace 或其他 trace，比如一个批处理链接它服务的
  请求）。每个 span 各最多保留 128 个（`MAX_EVENTS`、`MAX_LINKS`）；多出的计入 `SpanData::dropped_events` /
  `dropped_links` 并照此导出。对不记录的 span 它们什么也不做。
- 采样由 tracer 按 trace 决定一次（导出器的 `sample_ratio`）；调用方 `traceparent` 的标志会被遵从。未采样的 span
  仍带有 id（它的子 span 和发出的头保持未采样），但不记录任何东西。
- 自定义 tracer：实现 `akio::log::span::Tracer`（`enabled`、`sample`、`on_end`），用 `set_tracer` 加
  `set_max_span_level` 安装。`on_end` 运行在结束 span 的线程上，常常是 I/O 线程：把 span 入队，绝不阻塞。

没有 `tracing` 桥接：`tracing` 的 subscriber 需要由它自己的宏创建的 `'static` callsite 元数据，转发 akio-log 的
span 意味着按 span 名泄漏元数据，或者把名字藏进字段；OTLP 导出覆盖了常见的去处，其他去处可以用 `Tracer` 对接
（ADR-020）。

## 推送导出（OTLP 与 StatsD）

`akio-export` crate 在一个后台线程上推送指标、span 和日志记录，用的是工作区自研的 HTTP、gRPC、TLS 和
protobuf 代码，没有第三方依赖：

```rust,ignore
{{#include ../../../crates/akio-export/examples/guide-export.rs:export}}
```

- **发送什么。** 每个 `interval`（默认 10 秒）发送一次与抓取相同的快照：engine 的序列和所有已注册的收集器
  （`Telemetry::collect_all()`），再加上用 `.collector(..)` 传入的收集器。span 和日志记录每个 `span_interval`
  （默认 2 秒）发送一次，队列攒满一批（512）时提前发送。
- **OTLP/HTTP**（`otlp_http`，或 `otlp_http_with(endpoint, Encoding::Json, headers)`）：`POST /v1/metrics`、
  `/v1/traces` 和 `/v1/logs`，protobuf（`application/x-protobuf`）或 OTLP/JSON。**OTLP/gRPC**
  （`otlp_grpc("http://collector:4317")`、`otlp_grpc_with(endpoint, metadata)`）：三个 collector 服务的一元
  `Export` 方法，使用 akio-grpc 的客户端，运行在一个只有一个客户端 I/O 线程的私有 engine 上，首次推送时启动。
  计数器成为累积的单调 sum，gauge 仍是 gauge，直方图成为带 exemplar 的显式分桶直方图；标签成为属性，
  `service.name` 和 `resource_attr(..)` 成为 resource。span（连同事件和链接）和日志记录按 target 分成不同的
  instrumentation scope。指标已被抓取或发往 StatsD 时，`otlp_traces_only()` 让 OTLP 不发指标。
- **TLS。** `https://` 端点（两种协议均可）经 akio-tls 连接，gRPC 用 ALPN `h2`，HTTP 用 `http/1.1`。collector
  的证书按系统根证书校验，或按 `tls_roots(RootCerts)`（私有 CA）校验；`tls_client_cert(chain, key)` 应答要求客户端
  证书的 collector；`tls_server_name(..)` 覆盖校验的名字（默认是端点的主机名）。TLS 选项配 `http://` 端点在 `start`
  时报错。
- **日志。** `logs(level)` 安装一个 logger（进程级的 akio-log logger），把不超过 `level` 的记录转成 OTLP
  `LogRecord`：消息作为 body，带严重级别、键值作为属性、`code.file.path` 与 `code.line.number`，以及记录所在处当前
  span 的 trace id 和 span id，collector 因而能把一次请求的日志和它的 trace 放在一起。
  `forward_logs(FmtLogger::new(), LevelFilter::Warn)` 同时把记录交给另一个 logger。最大日志级别取两者中更详细的一个。
  导出器自己线程上的记录不会被导出。与 tracer 一样，logger 每个进程只能安装一次。
- **StatsD**（`statsd(addr, Flavor::DogStatsd | Flavor::Statsd)`、`statsd_options(prefix, max_packet,
  max_series)`）：计数器发送距上次推送的增量（`name:3|c`），gauge 发送值（`|g`），直方图发送 `.count`、`.sum`
  和每个桶的 `.bucket` 增量（带 `le` 标签）。DogStatsD 用 tag 携带标签（`|#route:/users/:id,class:2xx`）；
  普通 StatsD 把它们拼进名字（`name.class.2xx`）。多行打包进最多 1432 字节的数据报。span 和日志不发往 StatsD。
- **不在 I/O 线程上，且有界。** I/O 线程只把结束的 span 和记录交给分片队列（默认各 4096，`span_queue` /
  `log_queue`）：超出时被丢弃并计数，从不等待。StatsD 的增量表最多保留 `max_series` 个序列（默认 10 000）。OTLP
  的每一步（连接、TLS 握手、写、读，或一次 gRPC 调用）都有超时（默认 5 秒），HTTP 响应最多读 1 MiB。
- **collector 不可用时。** 可能自行恢复的失败（连不上、超时、HTTP 429、502、503、504，gRPC `UNAVAILABLE`、
  `DEADLINE_EXCEEDED`、`RESOURCE_EXHAUSTED` 等）让 collector 进入退避：`retry(initial, max, max_elapsed)`，默认从
  1 秒起翻倍到 30 秒并带抖动，或按服务器的 `Retry-After`。期间每种信号失败的那一批等待重发（每种信号一批），新数据在
  有界队列中等待；退避结束时立即发送这一批和队列，指标用新快照重新推送（它们是累积的）。超过 `max_elapsed`（默认
  5 分钟；`Duration::ZERO` 表示从不重试）仍失败的一批被丢弃并计数。其他失败（HTTP 400、gRPC `INVALID_ARGUMENT`、
  客户端拒绝的 TLS 证书等）立即丢弃这一批。collector 在 partial success 中拒绝的条目会被计数（`spans_rejected`、
  `logs_rejected`、`metric_points_rejected`）。
- `flush()` 忽略退避立即推送并等待；遇到可重试的失败即结束，其余留在队列中。`shutdown()`（或 drop 导出器）再推送
  一次然后停止线程。tracer 和 logger 每个进程只能安装一次：第二个带 `traces(..)` 或 `logs(..)` 的导出器启动会失败。

`tools/otel/e2e.sh` 在 Docker 里对 OpenTelemetry Collector（contrib）运行端到端测试：OTLP/HTTP 的 protobuf 和
JSON、OTLP/gRPC，明文以及带客户端证书的 TLS（脚本生成私有 CA），带事件和链接的 trace，与请求 span 关联的日志，带
exemplar 的指标，以及进入 statsd receiver 的 DogStatsD；检查 collector 的 file exporter 输出。

## 日志

akio 通过自己的日志门面 `akio-log`（以 `akio::log` 重新导出）输出带键值对的记录。每个进程安装一次
logger 即可看到：

```rust,ignore
// 向 stderr 输出格式化行：`2026-11-14T08:00:00.000123Z INFO  akio: engine started listeners=[...]`
akio::log::init(akio::log::LevelFilter::Info).unwrap();

// 或者：按 target 设上限、输出到 stdout、不带时间戳 ……
akio::log::FmtLogger::new()
    .target_level("akio_http::access", akio::log::LevelFilter::Off)
    .stdout()
    .init(akio::log::LevelFilter::Debug)
    .unwrap();

// 或者自己的输出：实现 `akio::log::Logger`（`enabled`、`log`、`flush`），调用
// `akio::log::set_logger(&MY_LOGGER)` 和 `akio::log::set_max_level(..)`。
```

记录提供 `level()`、`target()`、`args()`（消息，延迟格式化）、`key_values()`（`iter()`、
`get("conn_id")`；值实现了 `Display`）以及源码位置。没有安装 logger 时，错误和慢回调警告会打印到
stderr（`akio: ...`），不会悄无声息地丢失；其余记录被丢弃。最大级别默认为 `Off`，并且最先检查，只需
一次 relaxed 原子读，因此被禁用的语句开销远低于一纳秒。

`FmtLogger` 在记录日志的线程上、持有流的锁写出每一行：如果 stderr 是一个无人读取的管道，该线程
（可能是 I/O 线程）就会阻塞。对于日志输出可能积压的服务器，`.non_blocking(akio::log::DEFAULT_QUEUE_LINES)`
把格式化好的行放入队列交给写线程（16 384 行）；队列满时行被丢弃并计数（在 `init` 之前保留一个克隆，
调用 `dropped()`），写线程赶上后用单独一行报告丢弃数。退出前调用 `akio::log::flush()`。默认仍是同步
写出，因此进程未 flush 就退出时不会丢行。

**从环境变量按 target 设置级别。** `akio::log::init_from_env(default)` 只读取一次 `AKIO_LOG`，
其中是 env_logger 风格的指令，并据此安装格式化 logger：

```text
AKIO_LOG=info,akio_http=debug,akio_quic::conn=trace,akio_http::access=off ./server
```

`level` 设置没有指令点名的 target 的级别（没有时它们关闭），`target=level` 设置某个 target 及其子模块
（`target::...`）的级别，单独的 `target` 表示 `trace`；最具体的 target 胜出。未设置时 `default` 作用于
所有 target；无法解析时 stderr 上会有一行说明原因，并使用 `default`。不调用 `init_from_env` 就没有代码
读取该变量。同样的语法可以在代码中构造过滤器：`"info,akio_http=debug".parse::<akio::log::Filter>()`，再
`FmtLogger::new().init_filtered(filter)`，或在自己的 `Logger` 中调用 `filter.enabled(metadata)`。与
env_logger 不同，`akio=debug` 不匹配 `akio_http`（target 按 `::` 边界匹配）。

**消息过滤。** 与 env_logger 相同，指令后面的 `/regex` 只保留格式化后的消息（不含 target、级别和键值对）
中某处与模式匹配的记录：

```text
AKIO_LOG='info,akio_http=debug/(?i)conn(ection)? (reset|refused)|timed out' ./server
```

第一个 `/` 之后的全部内容都是模式，包括空格和逗号（因此模式里可以有 `/`，env_logger 则会拒绝）；空模式
不过滤任何记录，无效的模式与其他指令错误一样在 stderr 上报告。语法是去掉捕获、环视和 Unicode 类之后的
`regex` crate 语法：字符类与范围、支持 Unicode 的 `\d \w \s`、`* + ? {m,n}`（贪婪或惰性）、分支、分组、
`^ $ \A \z`、单词边界 `\b \B`，以及标志 `(?i)`（Unicode 大小写折叠）、`(?m)`、`(?s)`。引擎是工作区内的
`akio-regex`：Thompson NFA，并在解析过滤器时构建 DFA，因此匹配从不回溯（任何模式都不会让一次日志调用
变慢），代价约为消息每字符一纳秒。`FmtLogger` 直接匹配它本来就要为这一行格式化的消息；在自己的
`Logger` 中，`filter.matches(record)` 同时检查级别和消息，把消息逐段送入匹配器而不拼接字符串。没有模式的
过滤器完全不付出这些开销。代码中的写法：`Filter::new(LevelFilter::Info).message_regex("timed out")?`。

**编译期上限。** akio-log 的 feature `max_level_off` …… `max_level_trace` 以及 `release_max_level_*`
（后者用于没有 debug assertions 的构建）在编译期移除超出上限的语句，与 `log` crate 相同；结果是
`akio::log::STATIC_MAX_LEVEL`。只应在应用中开启（feature 在整个依赖图中合并）：
`akio-log = { version = "1", features = ["release_max_level_info"] }`。

**已有的 `log` 配置（env_logger、`tracing-log`、fern ……）。** 开启 `log` feature
（`akio = { version = "1", features = ["log"] }`）。未安装 akio-log logger 时，每条记录都以相同的
级别、target、消息和键值对交给 `log` crate 的 logger，有效最大级别为 `log::max_level()`；
`Config::log_level` 也会设置 `log` 的级别。反方向（把使用 `log` 的 crate，例如 str0m 或 rustls 的记录
送入 akio-log logger）调用 `akio::log::bridge::route_log_to_only()`。该 feature 不在 semver 承诺之内：
它跟随 `log` 0.4。

| target | 级别 | 记录 |
|---|---|---|
| `akio` | info | `engine started`（listener）、`engine shutting down`（打开的连接数）、`configuration reloaded`（applied、ignored） |
| `akio` | warn | 慢回调（`kind`、`conn_id`、`elapsed_us`、`limit_us`、`thread`、`listener`）；io_uring / BPF 回退 |
| `akio` | error | poller 失败 |
| `akio` | debug | 被 `max_connections` 拒绝的连接 |
| `akio` | trace | `connection opened` / `connection closed`（`conn_id`、`peer`、`local`、`dialed`、`error`） |
| `akio_http::access` | info | 访问日志：`method`、`target`、`status`、`peer`、`elapsed_us`、`request_id` |

`Config::log_level`（可热更新）会调用 `akio::log::set_max_level`，因此日志详细程度可以在运行时调整。

## 慢回调

见[阻塞任务](concepts/blocking.md#慢回调检测)。报告发给 `Config::slow_hook`；没有 hook 时写一条
`warn` 日志；没有日志实现时打印到 stderr。每条报告同时进入 `Engine::slow_callbacks()` 和调试
端点的 `slow` 视图，包含回调类型（`on_data`、`on_close`、`spawn_blocking completion` 等）、
耗时、阈值和所属线程。

## 热更新

```rust,ignore
{{#include ../../../crates/akio/examples/guide-config.rs:reload}}
```

`Engine::reload(&Config)`（或 `Telemetry::reload`）无需重启即可应用可在运行时修改的设置，并返回
`ReloadReport`：`applied`（已变更的项）和 `ignored`（有变化但需要重启的项）：

| 可热更新 | 构建时固定 |
|---|---|
| `idle_timeout`、`slow_callback_threshold`、`slow_hook`、`max_queued_bytes`、`write_high_watermark`、`max_connections`、`shutdown_timeout`、`retire_timeout`、`log_level`、`read_buffer`、`backlog`、`udp_idle_timeout` | `max_pending_responses`、`write_timeout`、`connect_timeout`、`udp_max_peers`、`udp_gro`、listener、后端、线程池大小 |

对已经打开的连接和套接字：

- **空闲超时**（`idle_timeout`、`udp_idle_timeout`）：已打开连接和 UDP 对端的定时器按新值重新设置；
  UDP 对端取两者中较短的一个。
- **`write_high_watermark`**：对每个连接重新评估背压。
- **`read_buffer`**：每个 I/O 线程在两批事件之间（此时没有 `on_data` 借用它）替换读缓冲区，
  所以已打开的连接从下一次读开始使用新大小。io_uring 下线程会注册一个新大小的第二个
  provided-buffer 组（仍以 16 KiB 为上限），每个连接在其 multishot 接收重新挂起时转到新组；
  没有接收再使用旧组后，旧组被释放。开启 GRO 的 UDP 线程保持至少 64 KiB 的槽。
- **`backlog`**：每个监听套接字重新调用一次 `listen(2)`；内核就地更新这个活套接字的队列上限
  （受 `net.core.somaxconn` / `kern.ipc.somaxconn` 限制）。

I/O 线程对大多数实时设置每次使用时只做一次 relaxed 读，其余的在处理重载通知时应用，所以热更新
不给热路径带来任何开销。也可以通过 `Telemetry::live()` 上的 setter 单独修改某个值，然后调用
`Telemetry::notify_reload()`。

### I/O 线程数

`Engine::threads()` 按 `local_addrs()` 的顺序列出每个 listener 和 client 组当前活跃的 I/O
线程数；`Engine::set_threads(index, n)` 在 engine 运行时修改其中一个（ADR-028）。它在变更投递给
I/O 线程后即返回，不等待它生效（扩容到一个正在退出的退役线程的编号时会先 join 它）。

- **扩容**启动新线程（或让正在退役的线程重新活跃）。Linux 上每个新线程在该 listener 的组里绑定
  自己的 `SO_REUSEPORT` 套接字，内核把新连接按份额分给它；macOS 上以及继承来的 listener，
  新线程在共享套接字的克隆上 accept。dial 分摊到所有活跃线程。
- **缩容**让编号最大的线程退役。退役线程立即停止 accept，并把监听套接字交给留下的线程；
  套接字全程保持打开，所以 accept 队列中等待的连接不会被重置。**连接从不在线程之间迁移**：
  退役线程继续服务它拥有的连接，最后一个关闭后退出。设置了 `Config::retire_timeout` 时，
  到期仍打开的连接会收到 `on_shutdown`（HTTP 写完进行中的响应后关闭，WebSocket 发送 1001），
  再过 `shutdown_timeout` 仍未关闭的被关闭；客户端会重连到活跃线程。
- 退役中的线程显示在 `Metrics::loops`（`retiring: true`）、Prometheus 指标 `akio_loop_retiring`
  和 JSON（`"retiring"`）中；已退出的线程报告 `running: false`，在同一编号上重新启动的线程延续
  它的计数器。
- UDP listener（在 UDP `SO_REUSEPORT` 组里增删套接字会把对端挪到别的线程）、DPDK 以及设置了
  `Accel::Ebpf` 分流的 listener 不支持，返回 `Unsupported`。

akio 自己不监视配置文件：从你使用的机制触发 `reload`（`SIGHUP` 处理器、文件监视器、或者像
上例那样的管理路由）。
