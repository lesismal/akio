# only-export

[English](README.md)

[`only`](https://github.com/lesismal/only) 的推送导出，没有依赖（`#![forbid(unsafe_code)]`；只依赖
only-core、only-log 和 only-protobuf）：在一个后台线程上，经 OTLP/HTTP 把指标和 span 发往 OpenTelemetry
collector，经 UDP 把指标发往 StatsD / DogStatsD。

- **指标**：每个间隔发送引擎的序列和所有注册到遥测中心的收集器（`Telemetry::collect_all()`，与 Prometheus
  抓取渲染的数据相同），再加上直接传入的收集器。OTLP：累积单调 sum、gauge、显式分桶直方图。StatsD：距上次推送的
  计数器增量、gauge、直方图 count/sum/bucket 增量；DogStatsD tag 或普通的点分名字。
- **Span**：`traces(level)` 为 only-log 的 span（`only::log::span`，包括 only-http 和 only-h3 的 HTTP 请求
  span）安装一个 tracer，按批发送，支持采样比例。
- **不在 I/O 线程上，且有界**：I/O 线程只把结束的 span 入队（队列有界；超出的 span 被丢弃并计数）。推送失败会计数，
  不重试。OTLP 的每一步都有超时。`Exporter::collector()` 报告导出器自己的计数器。
- OTLP/HTTP 支持 protobuf（`application/x-protobuf`）或 JSON；只支持明文 `http://`（发往本地 collector 或 agent）。

```rust,no_run
use std::time::Duration;
use only::{Config, log::LevelFilter};
use only_export::{Exporter, Flavor};

let cfg = Config::default();
let exporter = Exporter::builder()
    .service_name("checkout")
    .telemetry(cfg.telemetry.clone())
    .interval(Duration::from_secs(10))
    .otlp_http("http://127.0.0.1:4318")
    .statsd("127.0.0.1:8125", Flavor::DogStatsd)
    .traces(LevelFilter::Info)
    .start()
    .unwrap();
// …… 用 `cfg` 构建并运行 engine ……
exporter.shutdown();
```

设计：[ADR-020](../../docs/adr/020-spans-and-push-export.zh-CN.md)。指南：
[可观测性](https://lesismal.github.io/only/zh-CN/observability.html#推送导出otlp-与-statsd)。
对 OpenTelemetry Collector 的端到端测试：`tools/otel/e2e.sh`（Docker）。
