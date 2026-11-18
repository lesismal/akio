# only-export

[中文](README.zh-CN.md)

Push export for [`only`](https://github.com/lesismal/only), without dependencies
(`#![forbid(unsafe_code)]`; only-core, only-log and only-protobuf): metrics and spans to an
OpenTelemetry collector over OTLP/HTTP, metrics to StatsD / DogStatsD over UDP, from one
background thread.

- **Metrics**: every interval, the engine's series and every collector registered with the
  telemetry hub (`Telemetry::collect_all()`, the same data a Prometheus scrape renders), plus
  collectors passed directly. OTLP: cumulative monotonic sums, gauges, explicit-bucket
  histograms. StatsD: counter deltas since the previous push, gauges, histogram
  count/sum/bucket deltas; DogStatsD tags or plain dotted names.
- **Spans**: `traces(level)` installs a tracer for only-log spans (`only::log::span`, the HTTP
  request spans of only-http and only-h3 among them) and sends them in batches, with a sampling
  ratio.
- **Off the I/O threads, bounded**: I/O threads only queue finished spans (a bounded queue;
  spans past it are dropped and counted). Failed pushes are counted, not retried. Every OTLP
  step has a timeout. `Exporter::collector()` reports the exporter's own counters.
- OTLP/HTTP in protobuf (`application/x-protobuf`) or JSON; plain `http://` only (send to a local
  collector or agent).

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
// ... build and run the engine with `cfg` ...
exporter.shutdown();
```

Design: [ADR-020](../../docs/adr/020-spans-and-push-export.md). Guide:
[Observability](https://lesismal.github.io/only/en/observability.html#push-export-otlp-and-statsd).
End-to-end test against the OpenTelemetry Collector: `tools/otel/e2e.sh` (Docker).
