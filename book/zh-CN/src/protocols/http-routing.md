# 路由、中间件与静态文件

## Router

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:router}}
```

路径段：

| 模式 | 匹配 | 参数 |
|---|---|---|
| `users` | 恰好这一段 | – |
| `{name}.txt`、`v{major}.{minor}`、`{id:[0-9]+}.json` | 同一段内的字面文本与参数 | `name` 等 |
| `{id:[0-9]+}` | 整段匹配正则的一段 | `id` |
| `:id` 或 `{id}` | 任意一段 | `id` |
| `*rest` 或 `{*rest}` | 其后的全部内容，只能作为最后一段 | `rest` |

优先级为 **静态 > 部分段 > 正则 > 参数 > 通配**，并带回溯：静态分支在更深处匹配失败时会再尝试下一种。
查找不分配内存（`examples/router-bench.rs` 中 52 条 GitHub 风格路由约 30 ns，无论是否使用正则或部分段）。
`Router::lookup(method, path)` 只返回匹配结果、不分发。

部分段（[ADR-007](https://github.com/lesismal/akio/blob/main/docs/adr/007-partial-segment-routes.zh-CN.md)）
在一段内混合字面文本与 `{name}` 或 `{name:regexp}` 组。段首、段尾的字面文本分别在段首、段尾匹配；中间
每个参数非空，并在其后文本**第一次**出现处结束；正则参数还必须匹配其整个取值。不会尝试其他切分，因此
匹配保持线性：

| 模式 | 路径段 | 参数 |
|---|---|---|
| `{name}.txt` | `a.b.txt` | `name = a.b` |
| `{name}.{ext}` | `a.b.c` | `name = a`、`ext = b.c` |
| `v{major:[0-9]+}.{minor}` | `v1.10` | `major = 1`、`minor = 10` |
| `pre-{mid}-post` | `pre-a-b-post` | `mid = a-b` |

部分段之间，字面文本多的先试（`{name}.tar.gz` 先于 `{name}.gz`），其次按注册顺序。两个参数之间必须有
字面文本，通配符不能与其他内容同段，否则注册时 panic。

正则参数使用工作区的线性时间引擎 `akio-regex`（ADR-051）：表达式必须匹配整段，匹配耗时与段长度成线性关系
（不回溯，因此不存在病态模式；注册时构建 DFA，每字符约 1 纳秒）。支持的语法（含义与 `regex` crate 相同）：

- 字面量（任意 Unicode 字符）、`.`（除换行外的任意字符）、`^` / `$`（以及 `\A` / `\z`）；
- 字符类 `[a-z0-9_]`、`[^.]`，支持范围、取反与转义；位于开头的 `]` 以及位于开头或末尾的 `-` 按字面处理；
- `\d`、`\w`、`\s` 与 `\D`、`\W`、`\S`，**只匹配 ASCII**（`[0-9]`、`[0-9A-Za-z_]`、
  `[\t\n\x0B\x0C\r ]`：段按原样、即百分号编码的形式匹配），以及 `\b` / `\B`（ASCII 单词边界）；
- 转义 `\n \t \r \f \v \a`、`\x41`、`\x{1F600}`、`\u0041`、`\u{41}`、`\U0001F600`，以及任何转义的 ASCII
  标点（`\.`、`\-`、`\{` 等）；
- 分组 `(...)`、`(?:...)`、`(?P<name>...)`、`(?<name>...)`（不做捕获；组名不能重复）、选择 `|`、量词
  `*`、`+`、`?`、`{m}`、`{m,}`、`{m,n}`（计数最多 1000）及其惰性形式；
- 标志 `(?i)`（不区分大小写，Unicode 简单大小写折叠：`{name:(?i)[a-z]+}`）、`(?m)`、`(?s)`、`(?U)`，
  可取反（`(?-i)`）与限定范围（`(?i:...)`）。

其余语法（`\p{L}`、反向引用、环视、POSIX 字符类 `[[:alpha:]]`、字符类集合运算 `&&` `--` `~~`）会在注册时
被拒绝，并给出指明问题的信息。ADR-051 之前路由器使用自己的引擎，它还拒绝标志、`\b \B \A \z` 与非 ASCII
组名，并接受两个同名分组；其他所有模式的匹配结果与之前完全相同。早期版本的 `regex` cargo feature 不再有任何作用。

行为：

- 方法：`get`、`post`、`put`、`delete`、`patch`、`options`，或 `route(Method, path, svc)`。
- 路径存在但方法不对时返回 **405** 并带 `Allow` 头；路径不存在时返回 **404**。`fallback(svc)`
  同时替换两者（`Allow` 列表在 `ctx.local("akio.allow")` 中）。
- `HEAD` 由 `GET` 路由应答，不带 body。
- 重复或冲突的路由、不在最后的通配段、不配对的花括号、非法正则都会**在注册时 panic**：启动时就发现，而不是
  在生产环境。
- `nest(prefix, router)` 挂载另一个 router；它自己的 layer 对它的路由继续有效。
- 参数在分发时百分号解码一次（`ctx.param`）；`ctx.param_raw` 给出原样文本。

## 中间件

中间件是任意 `Fn(&mut Context, &dyn Service) + Send + Sync + 'static`（或实现了
`Middleware::handle` 的类型）。调用 `next.call(ctx)` 继续，或者不调用它直接答复：

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:middleware}}
```

在上面的 router 里，它只保护嵌套的 `/admin` router：
`Router::new().get("/stats", hello).layer(auth)`，再用 `.nest("/admin", admin)` 挂载。

`Router::layer(mw)` 包装**到目前为止**注册的所有路由以及 fallback；最后添加的 layer 最先执行
（最外层）。在某次 `layer` 调用之后添加的路由不会被它包装，因此可以通过注册顺序控制中间件的
作用范围。

由于 handler 可能 detach，需要最终响应的中间件应注册过滤器，而不是在 `next.call` 返回后检查：
`ctx.add_response_filter(|resp, req| ..)` 在响应发出前执行，在发送响应的那个线程上运行。
`ctx.add_response_header` 添加一个头部，除非响应自己设置了它。

内置中间件（`akio_http::middleware` 与 `akio_http::observe`）：

| 中间件 | 作用 |
|---|---|
| `recover()` | 被包装 service 中的 panic 变成 500，而不是关闭连接 |
| `request_id()` | 沿用传入的 `X-Request-Id` 或生成一个；存入 `ctx.local("request_id")` 并在响应中回显 |
| `cors(Cors { allow_origin, allow_methods, allow_headers, max_age })` | 以 204 应答预检请求，添加 `Access-Control-Allow-Origin` |
| `logger(fn(&LogRecord))` | 每个请求结束后调用你的函数（方法、target、peer、状态、耗时） |
| `response_time()` | 添加 `X-Response-Time` 头 |
| `compress(Compress { min_bytes, level, brotli, zstd, stream })` | 对客户端接受的文本类 body 做 br/zstd（设置时）/gzip/deflate |
| `etag()` | 添加 `ETag`，对 `If-None-Match` 返回 304 |
| `csrf()` | double-submit cookie：`csrf_token` cookie，非安全方法须在 `X-CSRF-Token` 头中带上同样的值 |
| `limiter(rate, burst)` | 按客户端 IP 的令牌桶，超出返回 429 和 `Retry-After` |
| `observe::HttpMetrics::middleware()` | 请求计数与延迟直方图（[可观测性](../observability.md)） |
| `observe::access_log()` | 通过 `akio::log` 输出结构化访问日志 |

`br` 和 `zstd`（自研的 `akio-brotli` 与 `akio-zstd`，ADR-041）默认关闭：把 `Compress::brotli` /
`Compress::zstd` 设为某个级别，即对接受它们的客户端使用，优先顺序为 br、zstd、gzip、deflate。预压缩的
`.br`、`.zst` 和 `.gz` 文件由 `Files` 提供。中间件压缩的是完整缓冲的消息体。流式响应
（`Context::stream_response`）按写入原样发送，除非设置了 `Compress::stream`（ADR-074）：这时逐次写入
压缩，每次写入后刷新编码器，使每个 server-sent event 仍能立即到达客户端；每个流的默认值很小
（`StreamCompress`：gzip 1，zstd 1 配 128 KiB 窗口，brotli 4 配 256 KiB 窗口；每个打开的流约 0.3、0.5 和
1.3 MiB，指输出了一个窗口之后；brotli 的匹配表随流增长，只发了几个事件的流只占几 KiB）。brotli 每次小写入的
CPU 开销仍然最大（每次刷新的事件约 1 us，zstd 0.3 us），高频事件流宜提供 zstd，或交给 gzip。

中间件不使用字典。需要交换用共享字典压缩的 brotli 数据的应用可以直接用 `akio-brotli` 解码：原始（LZ77
前缀）字典，即 `brotli -D` 与 RFC 9842 的 `dcb` 所用的那种（`decompress_with_dictionary`），以及带自定义
词表与变换的 RFC 9841 序列化共享字典（`SharedDictionary::new`、`decompress_with_shared_dictionary`；
ADR-069）；编码器使用前缀，并在级别 10 和 11 使用自定义词（ADR-079）。RFC 9841 的其余部分也在中间件之外
提供：大窗口流（`decompress_large_window`、`Compressor::large_window`；窗口最大 1 GiB，只用于事先约定的
对端），以及封装格式，即资源之间可以互作字典的容器，带元数据、部分数据块和供列出资源的重复元数据
（`read_container`、`Container::read`、`ContainerWriter`）。

```rust,ignore
{{#include ../../../../crates/akio-http/examples/guide-http.rs:compression}}
```

## 静态文件

`files::Files::new(root)` 是一个 service。把它挂在参数名为 `path` 的通配路由上
（`/static/*path`），或者作为 fallback（此时使用请求路径）。

| 构建方法 | 默认值 | 含义 |
|---|---|---|
| `index(name)` | `index.html` | 请求目录时提供的文件 |
| `max_cached_bytes(n)` | 256 KiB | 不超过此大小的文件缓存在内存中（0 关闭） |
| `max_open_files(n)` | 64 | 更大的文件保留打开的句柄并缓存元数据；满时先淘汰最近最少使用的（CLOCK） |
| `check_interval(d)` | 5 s | 缓存条目在重新检查磁盘之前被信任的时长 |
| `watch(on)` | 关闭 | 经 inotify（Linux）/ kqueue（macOS）跟随变化：有监视的缓存项在变化把它丢弃之前一直被信任（不适用于网络文件系统与 FUSE） |
| `max_watches(n)` | 1024 | `watch` 最多建立的监视数（目录；macOS 上另加每个缓存文件一个文件描述符）；超过后按 `check_interval` 规则 |
| `cache_control(v)` | 无 | 每个文件响应的 `Cache-Control` 头 |
| `twins(encodings)` | `br`、`zstd`、`gzip` | 提供的压缩副本，按 q 值相同时的偏好排列；`&[]`：不提供，也不发送 `Vary` |
| `try_paths(candidates)` | 无 | 依次尝试的路径（`try_files`）：`{path}` 是请求的路径，结尾的 `/` 表示目录；提供第一个存在的，否则 404 |
| `hide(f)` | 无 | `f` 返回 true 的路径答 404，`try_paths` 的候选被跳过 |
| `list_directories(n)` | 0（关闭） | 为带斜杠请求、没有索引文件的目录生成 HTML 列表；最多读取 `n` 项 |

`Files::serve(ctx, path)` 提供调用者给出的路径，供按自己的路径路由（去掉前缀）的 service 使用。

功能：`GET`/`HEAD`；`ETag` 与 `Last-Modified`；`If-None-Match` / `If-Modified-Since`（304），
`If-Match` / `If-Unmodified-Since`（412）；由 `If-Range` 保护的 `Range` 请求（206/416）；拒绝 `..`
等越界路径（跟随符号链接）；向接受的客户端提供 `file.ext.br` / `file.ext.zst` / `file.ext.gz`（`Accept-Encoding` 按 q 值排得最高的那个）；明文 TCP 上大文件用
`sendfile(2)` 发送（TLS 下经内存读取）。

多个区间（`Range: bytes=0-9,500-599,-10`）返回 `206` 与 `multipart/byteranges` 响应体（RFC 9110
14.6 节），每个区间一个部分，各带 `Content-Type` 与 `Content-Range`，按请求顺序排列。按 RFC 9110 14.2
节，重叠的区间以及相距不足 80 字节的区间会被合并（合并后的部分放在其第一个成员的位置；合并后只剩一个
区间时返回带 `Content-Range` 的普通 `206`）；超出文件末尾的区间被丢弃，全部丢弃时才返回 `416`。作为
防滥用措施，超过 32 个区间、或各部分合计超过 1 MiB 的请求头会被忽略，直接发送整个文件：multipart
响应体在内存中组装（`sendfile` 只用于单区间）。

打开文件缓存最多持有 `max_open_files` 个句柄。全部占用时，新的大文件替换最近最少使用的那个（CLOCK：
指针上次经过后被用过的条目获得第二次机会）。文件的大小、修改时间或 inode 变化时条目会被替换，因此即使
大小和时间相同，原子 `rename` 覆盖也能被发现；文件被删除时条目被移除（在检查间隔之后）。正在发送的响应
持有自己的句柄，被淘汰的文件在其最后一个响应完成后才关闭。

只有仍在信任期内的缓存命中在 I/O 线程上应答。未命中、重新检查以及其他任何要碰磁盘的工作（`stat`、
`open`、把小文件读进缓存、从大文件读取多 range 响应的各部分）都被分离到所有 `Files` 共用的一个小型
磁盘线程池（最多 16 个线程、4096 个排队请求；超出时返回 `503` 和 `Retry-After: 1`），响应也从那里
发出。`file.br` / `file.zst` / `file.gz` 是否存在随文件一起缓存，校验值和固定的头部每个条目只格式化一次。尚未完成：基于 inotify 的失效
（目前用 stat 间隔代替）；小文件的内存缓存只受现有文件数量限制，没有字节预算。
