# ADR-116：消息体旁路、外层响应过滤器与三种格式的 HTTP 日期

[English](116-body-taps-outer-filters-http-dates.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit 的响应缓存（它的迭代 I67，即 fit 的 `cache` 中间件）在响应发往客户端的同时保留一份，整个响应发完后才存下：
它从不为了存储而扣住响应。fit 借助 fib 的消息体过滤器做到这一点，它能看到消息体的每一次写入。akit 提出了三项
需求（A111、A112、A113），对照 akio main `c5cf4353` 核实：

- **A111.** 响应过滤器能看到流式响应（`Context::stream_response`、`Detached::stream_response`）的响应头，
  却看不到它的消息体：写入从 `BodyStream::write` 直接进入传输层。没有办法在代理的消息体经过时复制它，也无法
  知道它是完整结束、被截断（客户端离开、流被丢弃），还是带着 trailer 结束（上游中途断开时 akit 的代理会以
  trailer 结束消息体）。
- **A112.** 缓存要读 `Date`、`Expires`、`Last-Modified` 与 `If-Modified-Since`。RFC 9110 第 5.6.7 节要求
  接收方接受三种格式（IMF-fixdate、RFC 850、asctime），fit 用 Go 的 `http.ParseTime` 正是如此；akio 只在
  `files.rs` 内部私有地解析第一种。
- **A113.** 过滤器按注册顺序运行：外层中间件在调用它所包裹的处理器之前注册的过滤器，先于内层的运行。放在
  `compress` 前面的缓存会在响应被压缩之前看到它，以未编码的形式存下，而它此时还没有 `Vary: Accept-Encoding`。
  fit 的响应头钩子由内向外运行；akit 的中间件依赖 akio 现有的顺序，因此不能对所有人改变。

约束：不用 unsafe，不阻塞 I/O 线程，只增加 API，不给什么都不设置的响应增加开销。

## 决定

**A111：`Response::tap_body(impl BodyTap)`。**

- `trait BodyTap: Send + 'static { fn data(&mut self, &[u8]); fn end(&mut self, TapEnd); }` 与
  `#[non_exhaustive] enum TapEnd { Finished, Trailers, Cut }`。
- 由响应过滤器设置在流式响应的响应头上。此后流把每次写入在经过流编码（ADR-112）之后、不带传输层分帧地交给
  旁路：即响应头所描述的表示的字节，包括 `Content-Encoding` 的编码。失败的写入不交给旁路，并使结束方式为
  `Cut`。`end` 只调用一次，且最后调用：`finish` 给出 `Finished`，`finish_with_trailers` 给出 `Trailers`，
  流未完成就被丢弃、某次写入失败或流从未开始时给出 `Cut`。
- 对非流式响应（其过滤器拿得到完整的 `body`）和 HEAD 应答，旁路被忽略（不使用即丢弃）。
- 调用来自写流的线程，一次一个：旁路像编码器一样放在 `BodyStream` 中的互斥锁后，因此从多个线程写的流也按
  写入顺序被看到。`Response` 以一个 `Option<Arc<Mutex<Option<Box<dyn BodyTap>>>>>` 字携带旁路
  （`Response` 仍是 `Clone` 与 `UnwindSafe`）；`BodyStream` 多一个 `Option<Box<_>>` 字。

**A112：`akio_http::parse_http_date(&str) -> Option<u64>`**，返回自 Unix 纪元起的秒数，接受三种格式；RFC 850
的两位年份按 Go 的方式解读（69 及以上为 1900 年代，以下为 2000 年代）。`Files` 对 `If-Modified-Since` 仍保留
它自己的严格 IMF-fixdate 解析。

**A113：`Context::add_outer_response_filter(f)`。** 外层过滤器在所有普通过滤器之后运行，后添加的先运行：中间件在
调用它所包裹的处理器之前添加一个外层过滤器，就能看到内层中间件处理后的响应。它们放在过滤器的溢出向量中并加
标记，因此内联槽位以及 `Context`、`Detached` 的大小都不变；只有带外层过滤器的请求在响应发出时付出分拣的代价。

## 影响

- akit 的缓存在代理（流式）响应和完整响应发出时保留它们，与客户端收到的编码一致，并且只在消息体以 `Finished`
  结束时才存下。
- 没有旁路、没有外层过滤器的响应没有开销：`Response` 与 `BodyStream` 各多一个 `None` 字，过滤器向量多一次
  `is_empty` 检查。
- 有旁路的流每次写入多一次无竞争的加锁；旁路自己的工作（一次复制）由调用方承担。
