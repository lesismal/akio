# only-export

[中文](README.zh-CN.md)

Push export for [`only`](https://github.com/lesismal/only), without third-party dependencies
(`#![forbid(unsafe_code)]`; the workspace's own HTTP, gRPC, TLS and protobuf crates): metrics,
spans and log records to an OpenTelemetry collector over OTLP (HTTP or gRPC, plain or TLS),
metrics to StatsD / DogStatsD over UDP, from one background thread.

- **Metrics**: every interval, the engine's series and every collector registered with the
  telemetry hub (`Telemetry::collect_all()`, the same data a Prometheus scrape renders), plus
  collectors passed directly. OTLP: cumulative monotonic sums, gauges, explicit-bucket
  histograms with exemplars (trace ids of sampled spans). StatsD: counter deltas since the
  previous push, gauges, histogram count/sum/bucket deltas; DogStatsD tags or plain dotted names.
- **Spans**: `traces(level)` installs a tracer for only-log spans (`only::log::span`, the HTTP
  request spans of only-http and only-h3 among them) and sends them in batches, with their
  events and links, and a sampling ratio.
- **Logs**: `logs(level)` installs a logger that sends only-log records as OTLP `LogRecord`s,
  with the trace and span ids of the span current where they were logged;
  `forward_logs(..)` keeps writing them to stderr (or any logger) too.
- **Transports**: `otlp_http` (protobuf or JSON) and `otlp_grpc` (only-grpc's client);
  `https://` endpoints over only-tls with the system's roots or `tls_roots`, and
  `tls_client_cert` for mutual TLS.
- **Off the I/O threads, bounded**: I/O threads only queue finished spans and records (bounded
  queues; items past them are dropped and counted). A collector that is away is retried with
  exponential backoff (or its `Retry-After`), keeping one failed batch per signal until a maximum
  age; partial successes are counted. Every OTLP step has a timeout. `Exporter::collector()`
  reports the exporter's own counters.

```rust,no_run
use std::time::Duration;
use only::{Config, log::LevelFilter};
use only_export::{Exporter, Flavor};

let cfg = Config::default();
let exporter = Exporter::builder()
    .service_name("checkout")
    .telemetry(cfg.telemetry.clone())
    .interval(Duration::from_secs(10))
    .otlp_grpc("https://collector.internal:4317") // or .otlp_http("http://127.0.0.1:4318")
    .statsd("127.0.0.1:8125", Flavor::DogStatsd)
    .traces(LevelFilter::Info)
    .logs(LevelFilter::Info)
    .start()
    .unwrap();
// ... build and run the engine with `cfg` ...
exporter.shutdown();
```

Design: [ADR-020](../../docs/adr/020-spans-and-push-export.md),
[ADR-064](../../docs/adr/064-otlp-grpc-tls-logs-events-exemplars.md). Guide:
[Observability](https://lesismal.github.io/only/en/observability.html#push-export-otlp-and-statsd).
End-to-end tests against the OpenTelemetry Collector (gRPC and HTTP, plain and TLS):
`tools/otel/e2e.sh` (Docker).
