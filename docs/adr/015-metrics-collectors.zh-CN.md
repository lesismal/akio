# ADR-015：可插拔的指标收集器

[English](015-metrics-collectors.md) | 简体中文

状态：已采纳（2026-11-16）

## 背景

引擎导出自己的计数器（`Engine::metrics()`，Prometheus 文本或 JSON），only-http 用
`observe::metrics_handler(telemetry, Option<HttpMetrics>)` 提供它们。此外的东西都无法加入这个端点：
应用自己的计数器，或协议 crate 已有的统计（QUIC `ConnectionStats`、TLS 握手结果、各 HTTP 版本的请求数）
只能另开端点或手写 handler。项目不引入第三方依赖（ADR-005），所以 `prometheus` / `metrics` crate 不可用。

## 决定

新增模块 `only_core::metrics`（再导出为 `only::metrics`），无依赖：

- **`Collector`** trait（`Send + Sync`）：`fn collect(&self, out: &mut Families)`。按需调用（一次抓取），
  从不在 I/O 热路径上。
- **`Families`**：一次抓取构建的快照。`counter` / `gauge` / `histogram` 各添加一个样本（名称、帮助、标签、值）；
  同名样本无论到达顺序都归入同一个 `Family`。名称和标签名按 Prometheus 语法检查，标签值会转义；名称非法、
  或类型与所属族不同的样本被丢弃（抓取从不 panic）。用 `to_prometheus` / `write_prometheus`（文本格式 0.0.4）
  或 `to_json` 输出，或通过 `iter` / `get`（`Family`、`Sample`、`Value`、`HistogramSnapshot`）以程序方式读取。
  `collect_from(collector, labels)` 运行一个收集器，并给它的每个样本加上常量标签。值为 `f64`，与 Prometheus 一致。
- 供应用代码使用的**度量工具**：`Counter`、`Gauge`、`Histogram`（`Arc` 的廉价克隆，relaxed 原子操作，
  更新时不加锁）和 `Registry`——一个持有具名工具的 `Collector`（以相同名称和标签再次调用
  `registry.counter(name, help, labels)` 返回已有的工具）。
- **引擎挂钩**：`Telemetry::register_collector(Arc<dyn Collector>, labels) -> CollectorId`、
  `unregister_collector(id)`、`collect()`（已注册收集器的 `Families`）和 `render_prometheus()`（先引擎序列，
  再收集器）。`metrics_handler` 输出 `render_prometheus()`，因此每个已注册的收集器都出现在现有端点上，无需新 handler。
- **协议收集器**，均为新增的 `impl Collector`：
  - only-http `HttpMetrics`（原有序列不变，另加 `only_http_requests_by_version_total{version}`，
    即 HTTP/1.x、h2、h3 各自的请求/流数）；
  - only-quic `QuicServer`（打开/接受/关闭的连接数，两个方向的数据报与字节，发送与丢失的包，丢失字节，拥塞事件；
    总数包含已关闭的连接）；
  - only-tls `TlsStats`，来自 `Tls::stats()`（按版本与角色统计的完成握手、会话恢复、早期数据接受/拒绝）。
    失败的握手仍计入引擎的 `only_tls_handshake_failures_total`。

## 考虑过的替代方案

- **推送导出（StatsD、OTLP）**：需要线上客户端和调度，不在本次范围。`Families` 以后可以渲染成任何格式，
  推送可以建立在同样的收集器之上。
- **让引擎自身序列也走 `Families`**：暂不采用；`Metrics` 保持原有的输出和 JSON 结构（已有仪表盘不受影响）。
- **按路由的 HTTP 标签**：单独条目（需要先定基数策略）。

## 影响

- 只有新增的公开 API（新模块、新方法、新 trait 实现）；除 `HttpMetrics` 多一个族外，现有输出不变。
- 收集器列表在锁内复制后，收集器在锁外运行：慢收集器只会拖慢一次抓取，不影响引擎。
- 两个收集器以相同标签输出同一个族会产生重复样本；给每次注册不同的常量标签
  （`register_collector(c, &[("server", "a")])`）是调用方的责任。
