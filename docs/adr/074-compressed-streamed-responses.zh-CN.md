# ADR-074：only-http 压缩流式响应

[English](074-compressed-streamed-responses.md) | 简体中文

状态：已采纳（2026-11-21）

## 背景

`compress` 中间件用 only-deflate、only-brotli 和 only-zstd 的一次性编码器整体压缩缓冲的响应：压缩率
最好，`Content-Length` 已知。流式响应（`Context::stream_response`：server-sent events、大的生成式下载）
对任何编码都按写入原样发送（ADR-069 第 4 节）。它们的响应头其实经过了响应过滤器，但 compress 过滤器因为
消息体为空而跳过了它们。ADR-069 给两个 crate 加了流式编码器（`Compressor::compress(input, &mut out,
Flush)`），HTTP 这边留待以后。约束：

- 事件写出时就必须到达客户端：把输出攒到块满才发的编码器会破坏 server-sent events、聊天和进度流；
- 流在打开期间一直持有自己的编码器（窗口和匹配表），而事件流可能在成千上万个连接上开几个小时，所以每个
  流的内存比压缩率更重要；
- 缓冲的响应和已有配置不能变；
- `BodyStream::write` 取 `&self`，可以从任何线程调用。

## 决定

### 1. 显式开启，协商方式不变

`Compress` 新增 `stream: Option<StreamCompress>`，默认 `None`：除非应用要求，流式响应仍不压缩。编码
与缓冲响应一样按 `Accept-Encoding` 协商，候选编码也相同（`br` 和 `zstd` 只在 `Compress::brotli` /
`Compress::zstd` 提供时才有，然后是 `gzip`、`deflate`），符合条件的响应也相同：状态码 200、可压缩的
`Content-Type`（文本、JSON、JavaScript、XML、SVG、wasm；包括 `text/event-stream`）、尚无
`Content-Encoding`（已编码的消息体不动）。`min_bytes` 不适用，因为长度未知。压缩的流去掉处理器给的
`Content-Length`，加上 `Content-Encoding` 和 `Vary: Accept-Encoding`。HEAD 的回答得到相同的响应头，
不建编码器。

### 2. 编码器的位置

compress 过滤器本来就作用于流式响应头（`start_stream` 中的 `Finish::apply`）。现在它识别出这种响应头
（`Response::streaming`），不压缩消息体，而是把选定的编码记在 crate 内部的 `Response::stream_coding`
中：一个 3 字节的 `Copy` 枚举（编码、级别、窗口），放得进 `Response` 的填充字节，所以响应都不变大，
`Response` 也仍是 `Clone`。`start_stream` 在过滤器运行之后、编码响应头之前取出它，`BodyStream` 得到
一个编码器 `Option<Box<Mutex<StreamEncoder>>>`：不压缩的流都是 `None`，写入路径和以前一样。每个流一个
编码器，创建只需几纳秒（编码器在第一次有数据时才分配窗口和表）。由于 `write(&self)` 可能被多个线程调用，
互斥锁同时覆盖编码和把输出交给传输层，输出按编码顺序写出。编码器位于传输层之上，所以 HTTP/1.1 chunked、
HTTP/1.0 以关闭定界、HTTP/2 和 HTTP/3（`transport::BodySink`）的流都适用。

### 3. 每次写入刷新一次

每次 `write` 压缩其字节并刷新：gzip 和 deflate 用同步刷新（一个空的 stored 块，`00 00 FF FF`），zstd 用
`Flush::Flush`（把待处理的输入写成一个块），brotli 用 `Flush::Flush`（结束元块并用一个空的元数据块补齐）。
这样已写入的内容都能从已发送的字节解码，每次写入仍作为一个 chunk 或 DATA 帧发出、不经缓冲到达。`finish`
和 `finish_with_trailers` 在传输层结束之前写出流的结尾（`Finish`）。事件源本来就是每个事件写一次，所以
刷新不可配置：想要更大块的生产者就写更大的片段。代价是每次写入多几个字节（deflate 为 4 字节的同步标记加
块头，zstd 为 3 字节的块头，brotli 为元块头加空元数据块）。输出经过编码器保留的缓冲区，一次写入让它超过
64 KiB 后就丢弃，所以空闲的流持有的是窗口和表，而不是它最大的那次写入。

### 4. 小的默认值

`StreamCompress::default()`：gzip 和 deflate 级别 1，zstd 级别 1、128 KiB 窗口（`window_log` 17），
brotli 质量 4、256 KiB 窗口（`window_bits` 18）。五项都可设置。用计数分配器在一个 90 字节 JSON 事件的流
（30,000 个事件，超过所有窗口）上测得的每个流的数据：

| 编码 | 3 个事件后的内存 | 稳定状态 | 大小 / 输入 |
|---|---:|---:|---:|
| gzip 1 | 320 KiB | 320 KiB | 0.216 |
| gzip 6 | 320 KiB | 320 KiB | 0.200 |
| zstd 1，窗口 17 / 18 / 19 | 128 KiB | 476 / 824 / 1520 KiB | 0.176 / 0.175 / 0.177 |
| zstd 3，窗口 17 | 768 KiB | 1116 KiB | 0.177 |
| brotli 1，窗口 18 | 384 KiB | 1080 KiB | 0.198 |
| brotli 4，窗口 18 / 19 / 20 | 640 KiB | 1336 / 2032 / 3424 KiB | 0.164 |
| brotli 5，窗口 18 | 2176 KiB | 2872 KiB | 0.160 |

匹配表的大小由级别决定，缓冲区由窗口决定：对小事件，更大的窗口和级别换不来什么；zstd 3 和 brotli 5 的
内存是 zstd 1 和 brotli 4 的两到四倍；gzip 1 的 CPU 是 gzip 6 的四分之一，压缩率只差 0.016；在 16 个事件
的流上，brotli 质量 0-5 花的时间差不多。默认值由此而来。

### 5. only-brotli 在两个窗口时滑动

brotli 编码器原来在当前位置之后积累了一个窗口加一个元块（1 MiB）时才滑动缓冲区，所以 256 KiB 的窗口仍要
保留至多 1.3 MiB 的输入：brotli 4 在窗口位数 18 时每个流 2,032 KiB，19 或 20 时 3,424 KiB。现在与 zstd
编码器一样，积累两个窗口就滑动：复制仍摊销在一个窗口的输入上（丢弃量是窗口即链表大小的倍数），输出不变
（更小的缓冲区持有同样的窗口），brotli 4、窗口 18 从每个流 2,032 KiB 降到 1,336 KiB。

## 影响

- 新增 API：`Compress::stream`、`StreamCompress`（`level`、`brotli`、`brotli_window_bits`、`zstd`、
  `zstd_window_log`，`#[non_exhaustive]`，`Default`）。`BodyStream` 的私有字段现在有名字（快照中显示为
  `BodyStream` 而不是 `BodyStream(_)`）。缓冲的响应、以及未设置 `stream` 时，一切不变。
- `ETag` 不再标记流式响应：etag 过滤器看到的是它们的空消息体，给每个流式 200 响应都打上空消息体的标签
  （还可能回答 `304`）。
- `Context::stream_response` 的文档原来说响应过滤器不作用于流式响应；它们其实看得到响应头，现在文档如实说明。
- 测试：每种编码经 HTTP/1.1 chunked（300 个事件和三次 256 KiB 的写入，用我们的流式解码器以及 `gzip -d`、
  `brotli -d`、`zstd -d` 解码，deflate 用 flate2），一个 HTTP/1.0 以关闭定界的流，HTTP/1.1 和 HTTP/2
  上步调一致的 server-sent events（服务端要等客户端从已收到的字节中解码出上一个事件后才写下一个；关掉
  zstd 的刷新后测试卡住并失败），以及应保持原样的情况（未开启、已编码的消息体、二进制类型、其他状态码、
  没有可接受的编码、HEAD、无 ETag）。
- 在安静主机上测量（`tools/bench/stream-compress.sh`，`stream-bench` 示例），见 docs/BENCHMARKS.zh-CN.md
  "压缩的流式响应"：在 gpu51 上与 main 同批 A/B。未设置 `stream` 时流式响应的速度与 main 相同（每响应 16 个
  小事件 0.999 倍，16 x 16 KiB 1.011 倍）；压缩时服务器 CPU 是瓶颈：gzip / zstd / br 每个 16 事件的响应
  多花 6 / 27 / 110 us（不压缩 17 us），每核 HTML 0.93 / 0.54 / 0.16 GB/s，事件字节压到 35% / 34% /
  26%，HTML 压到 18% / 6.1% / 5.4%。每个保持打开的流的服务器 RSS（1,000 个流）在 3 个事件后为 148 / 112 /
  424 KiB，6,000 个事件后为 268 / 324 / 1,106 KiB，不压缩时为 1.2-2.6 KiB。
- 未做：brotli 每次刷新写入的开销，一个 80 字节的事件约 3 us（zstd 0.27 us），来自每个元块都要写出的
  元块头和前缀码，以及每个流约 70 us 的初始化；按窗口而不是按级别确定匹配表大小（libzstd 的
  `ZSTD_adjustCParams`），能让小窗口的流更小；客户端压缩流式请求。
