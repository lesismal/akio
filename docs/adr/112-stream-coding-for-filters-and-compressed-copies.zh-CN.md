# ADR-112：任何响应过滤器都能设置的流编码，以及缓存文件的压缩副本

[English](112-stream-coding-for-filters-and-compressed-copies.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit 是建在 akio 上的反向代理，它移植 fit 的 `compress` 中间件和 fit 静态文件处理器的 `compress`
字段（akit 的 I47）。它的需求 A90 和 A91 指出了 akio-http 缺少的东西（对照 akio main `f6750e93`）：

- **A90.** `BodyStream` 写入时经过的编码器（ADR-074）只能由 akio 自己的 `compress` 中间件选择：
  `Response::stream_coding` 和 `Response::streaming` 都是 `pub(crate)`。fit 的中间件协商方式不同
  （在它提供的编码中按 q 值选，q 值相同按配置顺序；除 206 外所有带消息体的状态码；有 `no-transform`、
  `Content-Range` 或声明长度小于 `min_bytes` 时不压缩；强 `ETag` 改为弱 `ETag`），并限制同时压缩的
  响应数（`max_in_flight`），因此要由 akit 自己的过滤器选编码，并且要知道压缩的流何时结束以归还名额。
- **A91.** fit 的静态文件处理器把内存中保存的文件也按客户端要的每种 `compress` 编码各保存一份压缩
  副本：在文件线程池上以压得小的级别做一次，此后直接提供。akio 的 `Files` 能提供磁盘上的压缩孪生
  文件（ADR-100），但不做副本。

约束：只增加 API（`docs/api-stability.zh-CN.md`）；新增的东西不阻塞 I/O 线程；不用它的响应开销不变。

## 决定

### A90：`Coding`、`Response::set_stream_coding`、`Response::keep_until_sent`

- **`akio_http::Coding`**（`Copy`）：`gzip(level)`、`deflate(level)`、`br(quality, window_bits)`、
  `zstd(level, window_log)`，级别和窗口按 `StreamCompress` 的方式截断；`name()` 给出它的
  `Content-Encoding` 名。它包装 ADR-074 的 3 字节 `StreamCoding`。
- **`Response::is_streaming()`**：过滤器看到的是否是流式响应的头部。
- **`Response::set_stream_coding(Option<Coding>)`** 与 **`stream_coding()`**：流的写入经过的编码，
  和 `compress` 中间件设置的一样。`Content-Encoding`、`Vary` 由过滤器自己设置，`Content-Length`
  由它删除；HEAD 保留这些字段，不编码任何内容；对非流式响应无效。
- **`Response::keep_until_sent(value)`**：把 `value` 保留到响应发出为止：流式响应保留到它的
  `BodyStream` 结束或被丢弃（客户端离开时，生产者写入失败后丢弃它），其他响应保留到交给连接为止。
  限制响应数的过滤器在这里放一个守卫，在其 `Drop` 中归还名额。`Response` 中多一个 `Option<Arc<_>>`
  （一个字，未设置时为 `None`），`BodyStream` 中也是一个；值包在 `AssertUnwindSafe` 里（从不读取，
  只会被丢弃），`Response` 因此仍是 `UnwindSafe`。
- **`middleware::compressible(content_type)`** 公开，并像 fit 的列表一样包括字体、图标、BMP 和
  `application/ecmascript`；akio 的 `compress` 中间件也用它。

### A91：`Files::compress`

- **`Files::compress(&["br", "zstd", "gzip"])`**：编码，q 值相同时按此顺序优先。保存在内存中
  （`max_cached_bytes`）、不小于 1400 字节且类型可压缩的文件，每种编码有一个槽位
  （`OnceLock<Option<Arc<Cached>>>` 加一个标志）：客户端最想要的编码还没有副本时，第一个这样的请求在
  磁盘线程池上启动一个任务，自己拿到原文件；副本做好后，在 I/O 线程上提供给所有首选它的客户端。
  节省不到二十分之一的副本不保留（槽位记住这一点，该编码不再参与选择）。线程池拒绝的任务会清除标志，
  留给之后的请求。
- 级别：gzip 9、brotli 9、zstd 19，窗口不大于文件。副本有自己的 `ETag`（原文件的加上 `-编码`）、
  `Content-Encoding`，没有 `Accept-Ranges`；范围请求用原文件回答；磁盘上的孪生文件优先于副本；
  设置了 `compress` 时，关于文件的所有回答都带 `Vary: Accept-Encoding`。副本随文件的缓存项存在，
  缓存项被替换（文件改变或被淘汰）时一起消失。

## 未做

- 从磁盘发送的文件体（`Response::file`，大于 `max_cached_bytes` 的文件）不编码：这需要在磁盘线程池上
  分块读取并编码，并带上流的背压（akit 的 A92）。
- 副本不计入总内存上限：`Files` 还没有这样的上限（akit 的 A15）。每份副本都比原文件小，每个文件最多三份。

## 影响

- akit 的 `compress` 中间件像 fit 一样压缩流式（代理）响应和内存中的消息体，用它自己的协商和上限；
  它的 `static` 处理器支持 `compress`。
- 不设置这些的响应在热路径上没有变化：`Response` 多一个为 `None` 的字，文件服务路径多检查一个空切片。
