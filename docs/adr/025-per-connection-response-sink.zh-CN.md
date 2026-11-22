# ADR-025：按连接的响应 sink 与复用的请求 target

[English](025-per-connection-response-sink.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

HTTP/3 分配优化（CHANGELOG“每个 HTTP/3 请求更少的分配”）之后，还剩两处每请求分配，看起来需要
改动公共 API 才能去掉：

- **装箱的响应 sink。** `akio_http::transport::dispatch(service, req, sink)` 接受一个
  `Box<dyn ResponseSink>`，其 `send(self: Box<Self>, ..)` 会消耗它。akio-h3 为每个请求装箱一个
  `Sink`（连接、等待发送空间的响应队列、QPACK 编码器、流 id），并为此克隆三个 `Arc`。
- **请求 target。** `Request::target` 是 `String`，HTTP/1.1、HTTP/2 和 HTTP/3 上每个请求都分配
  一次。

在 `quic-bench h3`（两端同一进程）上，main ab65d376 每个请求调用分配器 11.0 次；HTTP/1.1 服务端
6.0 次，h2c 6.5 次。

## 决策

1. **每个连接一个 sink，每个请求一个 tag。** `akio_http::transport` 新增
   `trait ConnSink: Send + Sync + 'static { fn send(&self, tag: u64, resp: Response);
   fn start_stream(&self, tag: u64, resp: Response) -> Option<Box<dyn BodySink>>; }`、句柄
   `SharedSink`（`SharedSink::new(sink)`，可 `Clone`，`get()`）以及
   `dispatch_conn(service, req, &SharedSink, tag: u64)` /
   `start_conn(service, req, &SharedSink, tag) -> Started`。传输层每个连接保留一个 sink，用自己
   选定的 tag 区分请求。这样请求的回程只是对按连接对象的一次无竞争引用计数加一，原先则是一次装箱
   加三次克隆。akio-h3 的 tag 是请求流序号左移一位，最低位是 HEAD 标志。akio-h3 的 QPACK 编码器
   启动后（收到对端 SETTINGS 之后），连接会换上一个带编码器的新 sink。已分发的请求继续用旧 sink，
   只用静态表编码，这总是合法的。
2. **`SharedSink` 是瘦指针**（`Arc<Box<dyn ConnSink>>`）。这样 `Context` 内联保存的 responder
   为 16 字节，与它取代的装箱 sink 相同。胖指针 `Arc<dyn ConnSink>` 加 tag 占 24 字节，会让
   `Context` 从 648 增至 656 字节。HTTP/2 每个请求装箱一个 `Context`，实测 h2c 每请求服务端周期
   因此增加约 1%。有单元测试保证 `Option<Out>` 保持 24 字节。
3. **target 缓冲按线程复用；`Request::target` 仍是 `String`。** handler 处理完一个它没有保留的
   请求后（没有 `detach`，没有 WebSocket 升级），该请求的 target 缓冲被清空，成为本线程的备用缓冲
   （`thread_local`）。该线程上解析的下一个请求把 target 写进这个备用缓冲：HTTP/1.1
   （`parse_head`）、HTTP/2（`build_request`）和 HTTP/3（akio-h3 通过
   `transport::request_target(&str) -> String`）。大于 1 KiB 的缓冲不保留。
4. **装箱 API 保留并标为弃用。** `ResponseSink`、`dispatch` 和 `start` 仍然可用；装箱 sink 被
   适配进一个 `SharedSink`，仅在这条路径上多一次分配。它们标记为
   `#[deprecated(since = "1.0.0-rc.2")]`，可在 2.0 移除。

### 考虑过的其他方案

- **按连接保留备用 target**（HTTP/1 `Session`、HTTP/2 连接 core 和 akio-h3 `ServerConn` 中各一个
  字段）。这是第一版。在 h2c 上它每请求少 127 条指令，却多约 100 个周期、多 3.4 次 L1d 未命中。
  原因在于交错：一个线程上有 16 个连接，轮到某连接的下一个请求时，它的缓冲早已不在缓存中。按线程
  保留时，缓冲的复用方式与分配器的 LIFO 空闲链表一样，复用时仍在缓存中。按线程的实现也更简单：
  没有新增字段，也不必跨 HTTP/2 core 的锁转交。
- **为 `Request::target` 引入内联或共享的 `Target` 类型**（23 字节小字符串，或共享头部缓冲中的
  区间，提供 `&str` 访问器）。否决，因为它改变字段类型：`req.target.clone()` 赋给 `String`、
  `push_str`、按 `String` 匹配等写法都会编译失败，工作区中 akio-socks 和日志中间件就这样用。小字符串
  在禁止 `unsafe` 的 crate 里要么需要 `unsafe`（`from_utf8_unchecked`），要么每次访问都做 UTF-8
  检查，而且只覆盖短 target，复用缓冲则覆盖任意长度。`Headers` 缓冲中的区间在 handler 替换
  `req.headers` 时会失效。
- **在 akio-h3 内池化装箱的 `Sink`**（`send` 时把盒子放回按连接的空闲链表）。无需改 API，但
  detach 的响应会从其他线程发送，链表需要加锁，且每请求三次 `Arc` 克隆依旧。
- **以同样方式回收整个 `Request`**（头部缓冲、body）。以后可以做，不在本次范围内。（请求和响应的头部存储已在 ADR-081 中回收。）

## 后果

- 每请求分配器调用（malloc、calloc、realloc 和 posix_memalign，在 gpu51 x86_64 上用 bpftrace
  uprobe 计数）：`quic-bench h3` 两端 11.0 → 9.0；HTTP/1.1 服务端 6.0 → 5.0，pipeline 6.0 → 5.0，
  h2c 6.5 → 5.5。
- gpu51 上 `quiet.sh` 下同一次运行的 A/B：
  - HTTP/3 1.0059 倍（两次各 7 轮交替：1.0087 倍和 1.0032 倍）。
  - 服务端每请求用户态周期（`perf stat`，7 轮中位数）：HTTP/1.1 0.951 倍，pipeline 0.968 倍，
    h2c 0.973 倍。
  - 三者用户态每请求指令数均减少 1.2%–1.4%。
- 以下请求仍会分配自己的 target：handler detach 或升级的请求（请求被共享）、线程上的第一个请求，
  以及比备用缓冲更长的 target。detach 的请求的缓冲在该请求被丢弃的地方释放。
- 每个线程最多保留 1 KiB 备用 target 缓冲。
- API（akio-http，仅新增）：`transport::ConnSink`、`transport::SharedSink`、
  `transport::dispatch_conn`、`transport::start_conn` 和 `transport::request_target`。
  `transport::ResponseSink`、`transport::dispatch` 和 `transport::start` 标为弃用。
  `akio_http::transport` 是 `#[doc(hidden)]`，不在 semver 承诺内（docs/api-stability.md），所以
  API 快照不变；旧条目仍保留，供基于它们编写的 transport 使用。`Request`、`Context` 以及 handler
  用到的其他一切都不变。

### 迁移

| 之前 | 之后 |
|---|---|
| `impl ResponseSink for MySink { fn send(self: Box<Self>, r) .. }` | `impl ConnSink for MyConn { fn send(&self, tag: u64, r) .. }`，每个连接一个 |
| `transport::dispatch(&svc, req, Box::new(MySink { .. }))` | 每个连接一次 `let sink = SharedSink::new(MyConn { .. })`，然后 `transport::dispatch_conn(&svc, req, &sink, tag)` |
| `transport::start(&svc, req, Box::new(MySink { .. }))` | `transport::start_conn(&svc, req, &sink, tag)` |
| 每个请求 `Request::new(m, path.to_owned())` | `Request::new(m, transport::request_target(path))`（可选） |

handler、router 和中间件无需改动。调用已弃用函数的代码仍能编译，会有弃用警告。
