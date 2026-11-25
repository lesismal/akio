# ADR-124：`Files` 作为网关的静态文件处理器、内存有界，以及文件消息体编码

[English](124-files-as-a-gateway-static-handler.md) | 简体中文

状态：已采纳（2026-11-25）

## 背景

akit 用 akio-http 的 `Files` 实现 fit 的 `static` 处理器，并移植 fit 的测试。还剩三项 akit
需求（`akit/docs/akio-api-requests.md`）：

- **A14。** fit 对一些请求的回答与 `Files` 不同：按顺序尝试的索引文件（或没有）；不带斜杠
  请求的目录重定向（`301`，保留查询串）；带尾斜杠请求的文件回 `404`；Go 的内容类型（`.xml`
  为 `text/xml; charset=utf-8`、`.avif`、系统的 `mime.types`）；`default_type`，否则从前 512
  字节嗅探类型；不可读的文件回 `403`；只打开普通文件（FIFO 会占住磁盘池线程直到有写者）；
  `:` 与其他字符一样；它自己的简短错误正文；去掉前缀后的目录列表以完整路径为标题。
- **A15。** fit 在内存中最多保留 `max_cache_bytes`（64 MiB）的文件，并对在文件池上等待超过
  池超时的请求回 `503`。`Files` 只限制单个文件的大小而不限制总量，排队的请求会一直等到磁盘
  返回。
- **A92。** fit 的 `compress` 中间件也压缩从磁盘读取的大文件。akio 用 `sendfile(2)`（或在
  传输层读取）发送文件消息体；过滤器无法为它设置编码，而在 I/O 线程上读文件来编码是不允许的。

## 决定

**A14**，作为 `Files` 的构建设置（未提及处默认值不变）：

- `index_files(&[&str])`：代表目录的文件，按顺序尝试；可以为空。`index(name)` 保留，即一个
  元素的列表。
- `redirect_directories(bool)`：不带斜杠请求的目录回 `301`，指向加上斜杠的请求路径（包括
  前缀），保留查询串，会被读成主机名的路径（`//x`）被修正。
- `mime_types(Arc<MimeTypes>)`：按扩展名的内容类型。`MimeTypes::builtin()` 是 Go 的内置表；
  `MimeTypes::system()` 再按 Go 的 `mime` 包在 Unix 上的方式加入系统文件（shared-mime-info 的
  `globs2` 只补充扩展名，否则各 `mime.types` 文件依次覆盖；`text/` 类型加
  `charset=utf-8`），只读一次且大小有界。不设置时仍用 `Files` 自己的短表。
- `default_type(Option<&str>)` 与 `sniff(bool)`：扩展名给不出类型的文件的类型。
  `files::sniff` 即 Go 的 `http.DetectContentType`；字节在磁盘池上随文件读取，类型随缓存项
  保存。这种文件的压缩孪生文件用默认类型，否则为 `application/octet-stream`。
- `error_response(f)`：`Files` 自己做出的回答（`301`、`403`、`404`、`405`、`500`、`503`），
  `Location`、`Allow` 与 `Retry-After` 由 `Files` 添加。
- `serve_prefixed(ctx, prefix, path)`：给去掉了路径前缀的调用者用的 `serve`，目录列表与
  重定向写出完整路径。挂在路由下时 `Service::call` 对路由那部分做同样的事，并保留请求的尾
  斜杠（路由的通配符会去掉它）。
- 固定行为：不可读的文件（`PermissionDenied`）回 `403`；既不是普通文件也不是目录的（从不
  打开）以及带尾斜杠请求的文件回 `404`；名字中允许 `:`。

**A15**：

- `max_cache_bytes(n)`（默认 64 MiB）：内存中保留的字节，文件、压缩孪生文件与副本
  （`compress`，生成时计入）合计，按最近最少使用（与打开句柄相同的 CLOCK）淘汰。缓存在同一把
  锁下有两个环：打开的句柄（`max_open_files`）与持有字节的缓存项。单个超过上限的文件只为本次
  请求读取，不保留。
- `disk_timeout(Option<Duration>)`：在磁盘池上排队、超时内未得到回答的请求回 `503` 并带
  `Retry-After: 1`；其工作在之后运行时不再回答。等待的请求按截止时间排序；akio-http 的定时器
  线程每隔超时的八分之一清扫一次（只在有请求等待时安排），回答超时的、丢掉已回答的。列表
  有界（8192，超过时压缩）。工作读磁盘时只持有请求，不持有回答的锁，所以挂起的磁盘不会卡住
  清扫。

**A92**：响应过滤器在消息体为文件的响应上留下流编码（`Response::set_stream_coding`，
ADR-112）时，响应以流式发送：去掉 `Content-Length`，长连接 HTTP/1.1 用 chunked（否则以关闭
定界，HTTP/2 与 HTTP/3 按帧），文件在 `Files` 的磁盘池上以 64 KiB 分片读取，每片在那里编码并
写出，连接上排队少于 256 KiB 时再读下一片（`BodyStream::on_drain`）。读或写失败时丢弃流，
截断消息体并关闭连接；池满时每 5 ms 重试，持续一秒。HEAD 只发送头部。过滤器现在对 HTTP/1 与
HTTP/2、HTTP/3 在同一处运行（`Out::send`）。

## 影响

- akit 的 `static` 处理器接受 fit 的 `index` 列表、`default_type` 与 `max_cache_bytes`，其
  `compress` 中间件也压缩从磁盘发送的消息体。
- `Files` 现在默认限制内存（64 MiB），此前只限制单个文件：小文件很多的服务器保留最常用的那些。
- 测试：`files::mime::tests`（Go 的表、按 Go 的方式读系统文件、Go 的嗅探用例）；
  `files::tests::memory_cache_is_bounded_and_keeps_hot_files` 与
  `compressed_copies_count_in_the_memory_bound`（每一步后检查两个环的不变量）；
  `tests/files_gateway.rs`（索引文件、路由下与前缀下的重定向、尾斜杠、`:`、内容类型、`403`、
  FIFO、错误正文、磁盘挂起时超时的 `503`）；`tests/file_coding.rs`（HTTP/1.1、HTTP/1.0 与
  HTTP/2 上的 gzip、HEAD、不可压缩的 3 MiB 与慢客户端、中途离开的客户端）。epoll 与 io_uring。
