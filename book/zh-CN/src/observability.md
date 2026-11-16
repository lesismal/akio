# 可观测性与热更新

每个 engine 都有一个**遥测中心**（`only::Telemetry`）：每线程计数器、连接表、慢回调记录以及
实时（可热更新的）设置。engine 构建之前通过 `Config::telemetry` 访问，构建之后通过
`Engine::telemetry()` 访问。I/O 线程用 relaxed 原子操作更新各自的普通计数器（按缓存行对齐，
每个事件既不加锁也不分配内存）；快照按需汇总。

## 在代码中

```rust,ignore
{{#include ../../../crates/only/examples/guide-config.rs:observe}}
```

| 调用 | 返回 |
|---|---|
| `Engine::metrics()` | `Metrics`：每线程的 `LoopMetrics`（所属、是否运行、计数器）、`total`、`open_connections`、`pool`、`uptime`；`to_prometheus()`、`to_json()` |
| `Engine::connections(timeout)` | 连接表：每个连接一个 `ConnInfo`（id、对端、本端、所属线程、存活时长、空闲时长、收发字节、排队字节、是否暂停读、是否背压、transport、是否 UDP）。通过询问每个 I/O 线程收集；不要在 I/O 线程的回调里调用 |
| `Engine::slow_callbacks()` | 最近的慢回调（最多 256 条），由旧到新 |
| `Engine::pool_stats()` | 逻辑线程池的线程数、空闲数、排队数、完成数、panic 数、拒绝数 |
| `Engine::udp_stats()` | 打开的 UDP 对端数，以及被 `udp_max_peers` 拒绝的数据报数 |
| `Engine::accel_status()` | 每个 listener 的 eBPF 分流状态 |
| `Telemetry::collect()`、`Telemetry::render_prometheus()` | 已注册收集器的 `Families`（Prometheus 或 JSON）；engine 序列加收集器序列，即 `metrics_handler` 输出的内容 |

## Prometheus

engine 指标（每个 I/O 线程一条序列，标签为 `listener`、`backend`、`thread`）：

| 序列 | 类型 |
|---|---|
| `only_connections_accepted_total`、`only_connections_dialed_total`、`only_connections_closed_total` | counter |
| `only_connections_rejected_total`（max_connections）、`only_accept_errors_total`、`only_idle_timeouts_total` | counter |
| `only_read_bytes_total`、`only_reads_total`、`only_written_bytes_total`、`only_writes_total` | counter |
| `only_udp_datagrams_received_total`、`only_udp_datagrams_sent_total` | counter |
| `only_send_queue_bytes` | gauge |
| `only_backpressure_events_total`、`only_overloaded_total` | counter |
| `only_tls_handshake_failures_total`、`only_transport_errors_total` | counter |
| `only_loop_iterations_total`、`only_loop_events_total`、`only_loop_callbacks_total`、`only_loop_callback_seconds_total`、`only_slow_callbacks_total` | counter |
| `only_connections_open`、`only_loop_running` | gauge |
| `only_pool_threads`、`only_pool_active`、`only_pool_queued` | gauge |
| `only_pool_completed_total`、`only_pool_panicked_total`、`only_pool_rejected_total` | counter |
| `only_uptime_seconds` | gauge |

`observe::HttpMetrics` 提供的 HTTP 指标：`only_http_requests_total{class="2xx"...}`、
`only_http_request_duration_seconds`（直方图，桶从 0.5 ms 到 10 s）、
`only_http_requests_in_flight`、`only_http_requests_by_version_total{version="1.0|1.1|2|3"}`
（按请求的协议版本统计的响应数；在 h2 和 h3 上即已应答的请求流数量）。QUIC 与 TLS 指标来自各自的收集器，
见[自定义指标](#自定义指标)。

**开销。** 计数器始终开启；设置了慢回调阈值（默认）时还会对回调计时。在安静主机上做的同一轮 A/B
（Ryzen 7 7800X3D、Linux 7.0、5 轮）没有测到开销：关闭计时或把计数器编译掉后，HTTP/1.1 plaintext
与 pipelined 为 0.998–1.006×，TCP 与 UDP echo 在各自 ±5–10% 的噪声之内（docs/BENCHMARKS.zh-CN.md
“遥测开销”）。

`only_loop_callback_seconds_total / only_loop_iterations_total` 和慢回调计数是最先要看的：
它们告诉你 handler 是否让 I/O 线程一直忙碌。

## HTTP 端点

```rust,ignore
{{#include ../../../crates/only-http/examples/guide-observe.rs:endpoints}}
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

任何实现了 `only::metrics::Collector` 的东西都可以注册到遥测中心，随后出现在同一个 `/metrics`
端点上，位于 engine 自身序列之后（ADR-015）。不涉及任何第三方 crate。

```rust,ignore
{{#include ../../../crates/only-http/examples/guide-metrics.rs:collectors}}
```

- `Registry` 持有具名的 `Counter`、`Gauge`、`Histogram`（共享原子量，更新不加锁）；以相同名称和
  标签再次获取会返回同一个工具。
- `fn_collector(|out| ...)` 把闭包变成每次抓取都会运行的收集器；`out.counter`、`out.gauge`、
  `out.histogram` 添加样本。非法名称、重复的标签名和类型冲突会被丢弃（计入 `Families::dropped()`），
  从不 panic。
- `Telemetry::register_collector(collector, labels)` 给该收集器的每个样本加上常量标签：两个收集器
  输出相同的族时（比如两个 QUIC 服务器），给每次注册不同的标签。`unregister_collector(id)` 取消注册。
- `metrics_handler(telemetry, http)` 输出 `Telemetry::render_prometheus()`（先 engine 序列，再收集器）；
  若 `HttpMetrics` 已作为收集器注册，`http` 传 `None`。

不经 HTTP，以快照形式取得同样的数据：

```rust,ignore
{{#include ../../../crates/only-http/examples/guide-metrics.rs:snapshot}}
```

现成的收集器：

| 收集器 | 序列 |
|---|---|
| `only_http::observe::HttpMetrics` | `only_http_requests_total{class}`、`only_http_request_duration_seconds`、`only_http_requests_in_flight`、`only_http_requests_by_version_total{version}` |
| `only_quic::QuicServer`（`only_h3::serve` 返回的也是它） | `only_quic_connections_open`（gauge）、`only_quic_connections_accepted_total`、`only_quic_connections_closed_total`、`only_quic_datagrams_total{dir}`、`only_quic_bytes_total{dir}`、`only_quic_packets_sent_total`、`only_quic_packets_lost_total`、`only_quic_lost_bytes_total`、`only_quic_congestion_events_total`、`only_quic_ecn_ce_events_total` |
| `only::tls::TlsStats`，来自 `Tls::stats()` | `only_tls_handshakes_total{side, version}`、`only_tls_resumed_total{side}`、`only_tls_early_data_total{side, outcome}` |

QUIC 的总数包含已关闭的连接，因此不会下降。收集器运行在处理抓取的线程上，从不在 I/O 线程的热路径上：
请让它们保持轻量。没有内置推送导出（StatsD、OTLP）；`Families` 里有这类导出器需要的全部数据。

## 日志

only 通过自己的日志门面 `only-log`（以 `only::log` 重新导出）输出带键值对的记录。每个进程安装一次
logger 即可看到：

```rust,ignore
// 向 stderr 输出格式化行：`2026-11-14T08:00:00.000123Z INFO  only: engine started listeners=[...]`
only::log::init(only::log::LevelFilter::Info).unwrap();

// 或者：按 target 设上限、输出到 stdout、不带时间戳 ……
only::log::FmtLogger::new()
    .target_level("only_http::access", only::log::LevelFilter::Off)
    .stdout()
    .init(only::log::LevelFilter::Debug)
    .unwrap();

// 或者自己的输出：实现 `only::log::Logger`（`enabled`、`log`、`flush`），调用
// `only::log::set_logger(&MY_LOGGER)` 和 `only::log::set_max_level(..)`。
```

记录提供 `level()`、`target()`、`args()`（消息，延迟格式化）、`key_values()`（`iter()`、
`get("conn_id")`；值实现了 `Display`）以及源码位置。没有安装 logger 时，错误和慢回调警告会打印到
stderr（`only: ...`），不会悄无声息地丢失；其余记录被丢弃。最大级别默认为 `Off`，并且最先检查，只需
一次 relaxed 原子读，因此被禁用的语句开销远低于一纳秒。

**从环境变量按 target 设置级别。** `only::log::init_from_env(default)` 只读取一次 `ONLY_LOG`，
其中是 env_logger 风格的指令，并据此安装格式化 logger：

```text
ONLY_LOG=info,only_http=debug,only_quic::conn=trace,only_http::access=off ./server
```

`level` 设置没有指令点名的 target 的级别（没有时它们关闭），`target=level` 设置某个 target 及其子模块
（`target::...`）的级别，单独的 `target` 表示 `trace`；最具体的 target 胜出。未设置时 `default` 作用于
所有 target；无法解析时 stderr 上会有一行说明原因，并使用 `default`。不调用 `init_from_env` 就没有代码
读取该变量。同样的语法可以在代码中构造过滤器：`"info,only_http=debug".parse::<only::log::Filter>()`，再
`FmtLogger::new().init_filtered(filter)`，或在自己的 `Logger` 中调用 `filter.enabled(metadata)`。与
env_logger 不同，`only=debug` 不匹配 `only_http`（target 按 `::` 边界匹配），也不支持 `/regex` 消息过滤。

**编译期上限。** only-log 的 feature `max_level_off` …… `max_level_trace` 以及 `release_max_level_*`
（后者用于没有 debug assertions 的构建）在编译期移除超出上限的语句，与 `log` crate 相同；结果是
`only::log::STATIC_MAX_LEVEL`。只应在应用中开启（feature 在整个依赖图中合并）：
`only-log = { version = "1", features = ["release_max_level_info"] }`。

**已有的 `log` 配置（env_logger、`tracing-log`、fern ……）。** 开启 `log` feature
（`only = { version = "1", features = ["log"] }`）。未安装 only-log logger 时，每条记录都以相同的
级别、target、消息和键值对交给 `log` crate 的 logger，有效最大级别为 `log::max_level()`；
`Config::log_level` 也会设置 `log` 的级别。反方向（把使用 `log` 的 crate，例如 str0m 或 rustls 的记录
送入 only-log logger）调用 `only::log::bridge::route_log_to_only()`。该 feature 不在 semver 承诺之内：
它跟随 `log` 0.4。

| target | 级别 | 记录 |
|---|---|---|
| `only` | info | `engine started`（listener）、`engine shutting down`（打开的连接数）、`configuration reloaded`（applied、ignored） |
| `only` | warn | 慢回调（`kind`、`conn_id`、`elapsed_us`、`limit_us`、`thread`、`listener`）；io_uring / BPF 回退 |
| `only` | error | poller 失败 |
| `only` | debug | 被 `max_connections` 拒绝的连接 |
| `only` | trace | `connection opened` / `connection closed`（`conn_id`、`peer`、`local`、`dialed`、`error`） |
| `only_http::access` | info | 访问日志：`method`、`target`、`status`、`peer`、`elapsed_us`、`request_id` |

`Config::log_level`（可热更新）会调用 `only::log::set_max_level`，因此日志详细程度可以在运行时调整。

## 慢回调

见[阻塞任务](concepts/blocking.md#慢回调检测)。报告发给 `Config::slow_hook`；没有 hook 时写一条
`warn` 日志；没有日志实现时打印到 stderr。每条报告同时进入 `Engine::slow_callbacks()` 和调试
端点的 `slow` 视图，包含回调类型（`on_data`、`on_close`、`spawn_blocking completion` 等）、
耗时、阈值和所属线程。

## 热更新

```rust,ignore
{{#include ../../../crates/only/examples/guide-config.rs:reload}}
```

`Engine::reload(&Config)`（或 `Telemetry::reload`）无需重启即可应用可在运行时修改的设置，并返回
`ReloadReport`：`applied`（已变更的项）和 `ignored`（有变化但需要重启的项）：

| 可热更新 | 构建时固定 |
|---|---|
| `idle_timeout`、`slow_callback_threshold`、`slow_hook`、`max_queued_bytes`、`write_high_watermark`、`max_connections`、`shutdown_timeout`、`log_level` | `read_buffer`、`backlog`、`udp_idle_timeout`、listener、后端、线程数、线程池大小 |

已打开的连接会立即采用新的空闲超时和水位线（重新设置定时器、重新评估背压）。UDP listener
保持构建时的空闲超时。I/O 线程每次使用实时设置时只做一次 relaxed 读，所以热更新不给热路径
带来任何开销。也可以通过 `Telemetry::live()` 上的 setter 单独修改某个值，然后调用
`Telemetry::notify_reload()`。

only 自己不监视配置文件：从你使用的机制触发 `reload`（`SIGHUP` 处理器、文件监视器、或者像
上例那样的管理路由）。
