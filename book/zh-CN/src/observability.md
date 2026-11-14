# 可观测性与热更新

每个 engine 都有一个**遥测中心**（`flash::Telemetry`）：每线程计数器、连接表、慢回调记录以及
实时（可热更新的）设置。engine 构建之前通过 `Config::telemetry` 访问，构建之后通过
`Engine::telemetry()` 访问。I/O 线程用 relaxed 原子操作更新各自的普通计数器（按缓存行对齐，
每个事件既不加锁也不分配内存）；快照按需汇总。

## 在代码中

```rust,ignore
{{#include ../../../crates/flash/examples/guide-config.rs:observe}}
```

| 调用 | 返回 |
|---|---|
| `Engine::metrics()` | `Metrics`：每线程的 `LoopMetrics`（所属、是否运行、计数器）、`total`、`open_connections`、`pool`、`uptime`；`to_prometheus()`、`to_json()` |
| `Engine::connections(timeout)` | 连接表：每个连接一个 `ConnInfo`（id、对端、本端、所属线程、存活时长、空闲时长、收发字节、排队字节、是否暂停读、是否背压、transport、是否 UDP）。通过询问每个 I/O 线程收集；不要在 I/O 线程的回调里调用 |
| `Engine::slow_callbacks()` | 最近的慢回调（最多 256 条），由旧到新 |
| `Engine::pool_stats()` | 逻辑线程池的线程数、空闲数、排队数、完成数、panic 数、拒绝数 |
| `Engine::udp_stats()` | 打开的 UDP 对端数，以及被 `udp_max_peers` 拒绝的数据报数 |
| `Engine::accel_status()` | 每个 listener 的 eBPF 分流状态 |

## Prometheus

engine 指标（每个 I/O 线程一条序列，标签为 `listener`、`backend`、`thread`）：

| 序列 | 类型 |
|---|---|
| `flash_connections_accepted_total`、`flash_connections_dialed_total`、`flash_connections_closed_total` | counter |
| `flash_connections_rejected_total`（max_connections）、`flash_accept_errors_total`、`flash_idle_timeouts_total` | counter |
| `flash_read_bytes_total`、`flash_reads_total`、`flash_written_bytes_total`、`flash_writes_total` | counter |
| `flash_udp_datagrams_received_total`、`flash_udp_datagrams_sent_total` | counter |
| `flash_send_queue_bytes` | gauge |
| `flash_backpressure_events_total`、`flash_overloaded_total` | counter |
| `flash_tls_handshake_failures_total`、`flash_transport_errors_total` | counter |
| `flash_loop_iterations_total`、`flash_loop_events_total`、`flash_loop_callbacks_total`、`flash_loop_callback_seconds_total`、`flash_slow_callbacks_total` | counter |
| `flash_connections_open`、`flash_loop_running` | gauge |
| `flash_pool_threads`、`flash_pool_active`、`flash_pool_queued` | gauge |
| `flash_pool_completed_total`、`flash_pool_panicked_total`、`flash_pool_rejected_total` | counter |
| `flash_uptime_seconds` | gauge |

`observe::HttpMetrics` 提供的 HTTP 指标：`flash_http_requests_total{class="2xx"...}`、
`flash_http_request_duration_seconds`（直方图，桶从 0.5 ms 到 10 s）、
`flash_http_requests_in_flight`。

`flash_loop_callback_seconds_total / flash_loop_iterations_total` 和慢回调计数是最先要看的：
它们告诉你 handler 是否让 I/O 线程一直忙碌。

## HTTP 端点

```rust,ignore
{{#include ../../../crates/flash-http/examples/guide-observe.rs:endpoints}}
```

- `observe::metrics_handler(telemetry, Some(http_metrics))` 以 Prometheus 文本格式（0.0.4）应答。
- `observe::debug_handler(telemetry, token)` 是一个需要显式启用的运行时调试端点（相当于 Go 的
  pprof 页面），以 JSON 应答。把它挂在通配路由下；路径最后一段选择视图：`conns`（连接表）、
  `loops`（每线程计数器、汇总、线程池）、`slow`（最近的慢回调）、`live`（当前实时设置）。设置了
  token 时，请求必须带 `Authorization: Bearer <token>`（常量时间比较），否则返回 401。连接表在
  辅助线程上收集，从不在服务该请求的 I/O 线程上收集。没有 token 时不要对外公开它。
- `HttpMetrics::middleware()` 按状态类别计数请求、记录延迟、跟踪在途请求。
- `observe::access_log()` 通过 `log` facade 为每个响应写一条结构化记录。

## 日志

flash 通过 [`log`](https://docs.rs/log) facade 输出带键值对的记录；安装任意实现（env_logger、
`log` 到 `tracing` 的桥接等）即可看到。没有安装日志实现时，错误和慢回调警告会打印到 stderr，
不会悄无声息地丢失。

| target | 级别 | 记录 |
|---|---|---|
| `flash` | info | `engine started`（listener）、`engine shutting down`（打开的连接数）、`configuration reloaded`（applied、ignored） |
| `flash` | warn | 慢回调（`kind`、`conn_id`、`elapsed_us`、`limit_us`、`thread`、`listener`）；io_uring / BPF 回退 |
| `flash` | error | poller 失败 |
| `flash` | debug | 被 `max_connections` 拒绝的连接 |
| `flash` | trace | `connection opened` / `connection closed`（`conn_id`、`peer`、`local`、`dialed`、`error`） |
| `flash_http::access` | info | 访问日志：`method`、`target`、`status`、`peer`、`elapsed_us`、`request_id` |

`Config::log_level`（可热更新）会调用 `log::set_max_level`，因此日志详细程度可以在运行时调整。

## 慢回调

见[阻塞任务](concepts/blocking.md#慢回调检测)。报告发给 `Config::slow_hook`；没有 hook 时写一条
`warn` 日志；没有日志实现时打印到 stderr。每条报告同时进入 `Engine::slow_callbacks()` 和调试
端点的 `slow` 视图，包含回调类型（`on_data`、`on_close`、`spawn_blocking completion` 等）、
耗时、阈值和所属线程。

## 热更新

```rust,ignore
{{#include ../../../crates/flash/examples/guide-config.rs:reload}}
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

flash 自己不监视配置文件：从你使用的机制触发 `reload`（`SIGHUP` 处理器、文件监视器、或者像
上例那样的管理路由）。
