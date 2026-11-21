# ADR-064：gRPC 与 TLS 上的 OTLP、OTLP 日志、span 事件与链接、exemplar、导出重试

[English](064-otlp-grpc-tls-logs-events-exemplars.md) | 简体中文

状态：已接受（2026-11-20）

## 背景

ADR-020 加入了推送导出（`only-export`：在一个后台线程上做 OTLP/HTTP 与 StatsD），并在 DEV-PLAN（M6 中
ADR-020 那一条）留下五个缺口：gRPC 上的 OTLP、到 collector 的 TLS、OTLP 日志、span 事件与链接、exemplar。它还选择了
推送失败时丢弃而不重试。此后工作区有了自研的 gRPC 客户端（only-grpc，基于 only-http 的 HTTP/2 客户端）、TLS
（only-tls）和 protobuf 运行时（only-protobuf），这些都不再需要第三方 crate（ADR-005）。约束不变：不在 I/O 线程上
导出（docs/rules.zh-CN.md 规则 1），每个队列有界且有安全默认值（规则 7、10），关闭的信号所对应的语句开销保持不变。

## 决定

### Span 事件与链接（only-log）

`SpanEvent`（名字、时间、字段）和 `SpanLink`（一个 `SpanContext`、字段），都是 `#[non_exhaustive]`，带构造函数
和 `field` 构建方法。`Span::add_event(name, &[(key, FieldValue)])` 用 span 自己的时钟给事件打时间（开始时间加单调
时钟经过的时间，与结束时间一致）；`Span::push_event` 接受现成的事件；`Span::add_link` 和 `SpanBuilder::link` 添加
链接（OpenTelemetry 建议在创建时给出链接，采样器能看到）。每个 span 最多保留 `MAX_EVENTS` = `MAX_LINKS` = 128 个
（OpenTelemetry 的默认值）；多出的计入 `SpanData::dropped_events` / `dropped_links`，并作为 OTLP 的 dropped 计数
导出。`SpanData`（`#[non_exhaustive]`）新增这四个字段。对关闭或未采样的 span 这些方法什么也不做；关闭路径（空指针
`Span`）不受影响。

### Exemplar（only-core、only-http）

`Exemplar`（值、时间、trace id、span id）与 `ExemplarReservoir`：每个桶一个槽位，保留最近一次在已采样 span 内的
观测（OpenTelemetry 的 aligned-histogram reservoir）。`offer_current` 读取线程当前的 span（only-log 的线程局部
变量），已采样时再读时钟，然后对槽位 `try_lock`：从不等待；两个线程同时写同一个桶时保留其中一个。
`ExemplarHistogram`（`Histogram` 加一个 reservoir，用 `ExemplarHistogram::new(bounds)` 或
`Registry::histogram_with_exemplars` 创建）是单独的类型，所以普通 `Histogram::observe` 的代码与以前相同（把开关放在
`Histogram` 内部会多一个分支，在 gpu51 上测得占 4.7 ns 观测的 4%）；
`HistogramSnapshot::exemplars` 携带它们（`with_exemplars` 给快照设置）。only-http 中
`HttpMetrics::with_exemplars()` 为请求延迟直方图保留 exemplar：中间件在分派时取得请求 span 的上下文（仅当开启
exemplar 且该 span 已采样），响应发出时提交延迟，因此 detach 的响应仍指向它的请求 span。exemplar 经 OTLP 导出
（`HistogramDataPoint.exemplars`，OTLP/JSON 中 id 为十六进制）；Prometheus 0.0.4 文本格式没有它们的位置，保持不变。

### OTLP 日志（only-export）

`ExporterBuilder::logs(level)` 安装一个 logger（`only_log::set_boxed_logger`），把不超过 `level` 的每条记录复制进
一个有界的分片队列（即 span 队列的代码，现已泛型化）：时间、级别、target、格式化后的消息、键值（`FieldValue`）、文件和
行号，以及 `span::current()`（记录所在线程的当前 span）。导出器把它们作为 `ExportLogsServiceRequest` 发送：每个 target
一个 scope，严重级别数字与文本，body，属性外加 `code.file.path` 与 `code.line.number`，`trace_id`、`span_id` 和 trace
flags。`forward_logs(logger, level)` 同时把记录交给另一个 logger（stderr、文件）；全局最大级别设为两者中更详细的一个
（`Config::log_level` 由 engine 稍后应用，以它为准）。导出器自己线程上的记录（工作线程和 gRPC engine 的 I/O 线程，用
线程局部标志标记）不会被导出：不会出现关于导出日志的日志再被导出的循环。与 tracer 一样，logger 每个进程只能安装一次；
`start` 在安装任何一个之前先检查两者（都无法卸载）。默认队列容量 4096 条，每批 512 条。

### gRPC 上的 OTLP

`otlp_grpc(endpoint)` / `otlp_grpc_with(endpoint, metadata)` 用 only-grpc 的 `GrpcClient` 调用 `MetricsService`、
`TraceService` 和 `LogsService` 的一元 `Export` 方法，底层是私有 `Engine`（一个客户端 I/O 线程）上的 `H2Client`，
在首次推送时于导出线程上构建并启动（`shutdown_timeout` 为 200 ms，关闭即刻完成）。导出线程阻塞在 `unary` 中（受超时
约束）；I/O 线程只运行连接的回调。以 `UNAVAILABLE`、`DEADLINE_EXCEEDED` 或 `CANCELLED` 失败的调用会丢弃连接，下次推送
重新拨号。请求体与 HTTP 路径发送的 protobuf 相同（同一个编码器）。考虑过共用应用的 engine：那会把导出器的连接放到应用
的 I/O 线程上，并把导出器的生命周期绑到 engine 上；多一个线程比这种耦合代价更小。

### 到 collector 的 TLS

两种协议都接受 `https://` 端点。配置：`tls_roots(RootCerts)`（私有 CA；默认 `RootCerts::system()`）、
`tls_client_cert(chain, key)`（双向 TLS）、`tls_server_name(name)`（默认是端点的主机名）。导出器自己构建 only-tls 的
`ClientConfig`，以保证 ALPN 正确（gRPC 用 `h2`，HTTP 用 `http/1.1`）。OTLP/HTTP 在 `TcpStream` 上运行阻塞的
`only_tls::stream::Stream`（读写超时同样约束握手）；gRPC 把配置交给 `H2Client::dial`。TLS 选项配 `http://` 端点，或
没有 OTLP 时，在 `start` 报错，而不是被悄悄忽略。

### 退避重试

ADR-020 丢弃失败的推送。遇到重启或限流的 collector，这会丢掉中断期间结束的所有 span；队列有界时重试的内存也有界，所以
现在默认重试。可能自行恢复的失败（连不上、超时、HTTP 429 / 502 / 503 / 504，gRPC `CANCELLED`、`DEADLINE_EXCEEDED`、
`RESOURCE_EXHAUSTED`、`ABORTED`、`OUT_OF_RANGE`、`UNAVAILABLE`、`DATA_LOSS`：OTLP 规范列出的那些）让 collector 进入
退避，各信号共享（它们发往同一处）：`retry(initial, max, max_elapsed)`，默认从 1 秒翻倍到 30 秒并带抖动（名义延迟的
一半到全部），或按服务器的 `Retry-After`（秒，以 `max_elapsed` 为上限）。每种信号失败的那一批被保留（每种信号一批，
已编码），退避结束时先于新数据重发；新的 span 和记录在有界队列中等待；指标不保留，退避结束时用新快照推送（累积语义让
错过的快照变得多余）。超过 `max_elapsed`（默认 5 分钟；为零则不重试）的一批被丢弃并计数。其他失败（除 429 以外的
HTTP 4xx，gRPC `INVALID_ARGUMENT`、`UNAUTHENTICATED` 等；客户端拒绝的证书属于连接失败，因此会重试）立即丢弃这一批。
collector 不可用期间的内存：队列上限加上每种信号一批已编码的数据。

`flush()` 忽略一次退避，遇到可重试的失败即结束这一轮，所以对已失效的 collector 做 flush（或 `shutdown` 的最后一次
推送）只等一个超时，而不是每种信号各等一个。退避结束后，工作线程立即发送等待中的那一批并清空队列，而不是等到下一个
`span_interval`。

### Partial success 与统计

读取响应（HTTP 响应体最多 1 MiB，同以前；gRPC 消息），用 only-protobuf 的 reader 解码其中的 `partial_success`：被拒绝
的条目计数（`metric_points_rejected`、`spans_rejected`、`logs_rejected`），不重试。`ExportStats`
（`#[non_exhaustive]`）新增 `otlp_logs_ok/failed`、`otlp_retried`、各拒绝计数，以及日志队列的 exported / dropped /
queued；`spans_queued` 和 `logs_queued` 包含等待重试的那一批。统计收集器新增 `only_export_pushes_total{signal="logs"}`、
`only_export_otlp_retries_total`、`only_export_metric_points_rejected_total`、`only_export_logs_*` 和
`only_export_spans_rejected_total`。

### 依赖

only-export 现在依赖 only、only-http、only-grpc 和 only-tls（全部自研；使用 `only` 的程序本就包含 only-tls）。它们不是
可选 feature：会导出的程序就是基于 `only` 构建的程序，本就链接了它们；feature 只会让 API 快照和测试矩阵成倍增加而省不下
什么。

## 考虑过的替代方案

- **在 `std::net` 上手写 HTTP/2 客户端来跑 gRPC**：要维护第二套 HTTP/2 实现；only-grpc 的客户端已经能与 collector 的
  grpc-go 互通。
- **指标快照也重试**：累积 sum 让旧快照在新快照发出后变得多余；保留它们会让内存随中断时长增长。
- **无限重试（永不放弃）**：永不恢复的 collector 会让每种信号的一批永远占着内存并让队列一直满着；`max_elapsed` 限制了
  这一点，把它设大是使用者的选择。
- **所有直方图都带 exemplar**：每个程序中每个直方图的每次观测都要多一次线程局部读取。即使是放在 `Histogram` 内部的
  可选开关也会让每次观测多一个分支（微基准中 4%），所以用单独的类型。
- **在 Prometheus 文本输出中带 exemplar**：只有 OpenMetrics 支持；`metrics_handler` 输出的 0.0.4 格式保持不变。
- **把日志记录作为 span 事件**：OpenTelemetry 把它们当作通过 id 关联的不同信号；collector 和后端也是这样建索引的。
- **用 log appender trait 代替安装 logger**：only-log 的工作方式就是每个进程一个 logger；`forward_logs` 覆盖了保留
  stderr 输出的需求。

## 影响

- only-log、only-core、only-http 和 only-export 的公共 API 只有新增（`#[non_exhaustive]` 结构体的字段、新类型、方法
  和常量）；API 快照只增不减。
- only-export 的行为变化：失败的推送会退避重试（以前丢弃），接受 `https://` 端点（以前报错）。
  `ExporterBuilder::retry(.., .., Duration::ZERO)` 恢复丢弃失败批次的行为（collector 仍会被退避）。
- 全部关闭时热路径没有变化：关闭的 span 或日志语句仍是同一次原子读取（同一轮 A/B 为 0.994–1.009，docs/BENCHMARKS.zh-CN.md“OTLP 导出新增功能”），
  普通 `Histogram` 不变（exemplar 在 `ExemplarHistogram` 中），不带 exemplar 的 `HttpMetrics` 每个请求多一个分支（测不出：0.999 和 1.001）。
- 使用 gRPC 导出器的进程多一个线程（私有 engine 的 I/O 线程）。
- 未完成：指数直方图、请求体 gzip 压缩、gRPC `RetryInfo` 细节（使用导出器自己的退避）、OpenMetrics exemplar、`tracing`
  桥接。
