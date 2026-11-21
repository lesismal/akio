# only-export

[English](README.md)

[`only`](https://github.com/lesismal/only) 的推送导出，没有第三方依赖（`#![forbid(unsafe_code)]`；使用工作区自研的
HTTP、gRPC、TLS 和 protobuf crate）：在一个后台线程上，经 OTLP（HTTP 或 gRPC，明文或 TLS）把指标、span 和日志记录发往
OpenTelemetry collector，经 UDP 把指标发往 StatsD / DogStatsD。

- **指标**：每个间隔发送引擎的序列和所有注册到遥测中心的收集器（`Telemetry::collect_all()`，与 Prometheus
  抓取渲染的数据相同），再加上直接传入的收集器。OTLP：累积单调 sum、gauge、带 exemplar（已采样 span 的 trace id）的
  显式分桶直方图。StatsD：距上次推送的计数器增量、gauge、直方图 count/sum/bucket 增量；DogStatsD tag 或普通的点分名字。
- **Span**：`traces(level)` 为 only-log 的 span（`only::log::span`，包括 only-http 和 only-h3 的 HTTP 请求 span）
  安装 tracer，连同事件和链接分批发送，可设采样比例。
- **日志**：`logs(level)` 安装一个 logger，把 only-log 的记录作为 OTLP `LogRecord` 发送，带记录所在处当前 span 的
  trace id 和 span id；`forward_logs(..)` 让它们同时继续写到 stderr（或任意 logger）。
- **传输**：`otlp_http`（protobuf 或 JSON）和 `otlp_grpc`（only-grpc 的客户端）；`https://` 端点经 only-tls 连接，
  使用系统根证书或 `tls_roots`，`tls_client_cert` 用于双向 TLS。
- **不在 I/O 线程上，且有界**：I/O 线程只把结束的 span 和记录放进有界队列（超出的被丢弃并计数）。collector 不可用时
  以指数退避（或按其 `Retry-After`）重试，每种信号保留一批失败的数据直到最大时长；partial success 会被计数。OTLP 的
  每一步都有超时。`Exporter::collector()` 报告导出器自身的计数器。

```rust,no_run
use std::time::Duration;
use only::{Config, log::LevelFilter};
use only_export::{Exporter, Flavor};

let cfg = Config::default();
let exporter = Exporter::builder()
    .service_name("checkout")
    .telemetry(cfg.telemetry.clone())
    .interval(Duration::from_secs(10))
    .otlp_grpc("https://collector.internal:4317") // 或 .otlp_http("http://127.0.0.1:4318")
    .statsd("127.0.0.1:8125", Flavor::DogStatsd)
    .traces(LevelFilter::Info)
    .logs(LevelFilter::Info)
    .start()
    .unwrap();
// ……用 `cfg` 构建并运行引擎……
exporter.shutdown();
```

设计：[ADR-020](../../docs/adr/020-spans-and-push-export.zh-CN.md)、
[ADR-064](../../docs/adr/064-otlp-grpc-tls-logs-events-exemplars.zh-CN.md)。指南：
[可观测性](https://lesismal.github.io/only/zh-CN/observability.html#推送导出otlp-与-statsd)。
对 OpenTelemetry Collector 的端到端测试（gRPC 与 HTTP，明文与 TLS）：`tools/otel/e2e.sh`（Docker）。
