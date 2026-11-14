# 路由、中间件与静态文件

## Router

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:router}}
```

路径段：

| 模式 | 匹配 | 参数 |
|---|---|---|
| `users` | 恰好这一段 | – |
| `{id:[0-9]+}` | 整段匹配正则的一段（默认启用的 `regex` feature） | `id` |
| `:id` 或 `{id}` | 任意一段 | `id` |
| `*rest` 或 `{*rest}` | 其后的全部内容，只能作为最后一段 | `rest` |

优先级为 **静态 > 正则 > 参数 > 通配**，并带回溯：静态分支在更深处匹配失败时会再尝试参数
分支。查找不分配内存（`examples/router-bench.rs` 中 52 条 GitHub 风格路由约 30 ns）。
`Router::lookup(method, path)` 只返回匹配结果、不分发。

行为：

- 方法：`get`、`post`、`put`、`delete`、`patch`、`options`，或 `route(Method, path, svc)`。
- 路径存在但方法不对时返回 **405** 并带 `Allow` 头；路径不存在时返回 **404**。`fallback(svc)`
  同时替换两者（`Allow` 列表在 `ctx.local("flash.allow")` 中）。
- `HEAD` 由 `GET` 路由应答，不带 body。
- 重复或冲突的路由、不在最后的通配段、非法正则都会**在注册时 panic**：启动时就发现，而不是
  在生产环境。
- `nest(prefix, router)` 挂载另一个 router；它自己的 layer 对它的路由继续有效。
- 参数在分发时百分号解码一次（`ctx.param`）；`ctx.param_raw` 给出原样文本。

## 中间件

中间件是任意 `Fn(&mut Context, &dyn Service) + Send + Sync + 'static`（或实现了
`Middleware::handle` 的类型）。调用 `next.call(ctx)` 继续，或者不调用它直接答复：

```rust,ignore
{{#include ../../../../crates/flash-http/examples/guide-http.rs:middleware}}
```

在上面的 router 里，它只保护嵌套的 `/admin` router：
`Router::new().get("/stats", hello).layer(auth)`，再用 `.nest("/admin", admin)` 挂载。

`Router::layer(mw)` 包装**到目前为止**注册的所有路由以及 fallback；最后添加的 layer 最先执行
（最外层）。在某次 `layer` 调用之后添加的路由不会被它包装，因此可以通过注册顺序控制中间件的
作用范围。

由于 handler 可能 detach，需要最终响应的中间件应注册过滤器，而不是在 `next.call` 返回后检查：
`ctx.add_response_filter(|resp, req| ..)` 在响应发出前执行，在发送响应的那个线程上运行。
`ctx.add_response_header` 添加一个头部，除非响应自己设置了它。

内置中间件（`flash_http::middleware` 与 `flash_http::observe`）：

| 中间件 | 作用 |
|---|---|
| `recover()` | 被包装 service 中的 panic 变成 500，而不是关闭连接 |
| `request_id()` | 沿用传入的 `X-Request-Id` 或生成一个；存入 `ctx.local("request_id")` 并在响应中回显 |
| `cors(Cors { allow_origin, allow_methods, allow_headers, max_age })` | 以 204 应答预检请求，添加 `Access-Control-Allow-Origin` |
| `logger(fn(&LogRecord))` | 每个请求结束后调用你的函数（方法、target、peer、状态、耗时） |
| `response_time()` | 添加 `X-Response-Time` 头 |
| `compress(Compress { min_bytes, level })` | 对客户端接受的文本类 body 做 gzip/deflate |
| `etag()` | 添加 `ETag`，对 `If-None-Match` 返回 304 |
| `csrf()` | double-submit cookie：`csrf_token` cookie，非安全方法须在 `X-CSRF-Token` 头中带上同样的值 |
| `limiter(rate, burst)` | 按客户端 IP 的令牌桶，超出返回 429 和 `Retry-After` |
| `observe::HttpMetrics::middleware()` | 请求计数与延迟直方图（[可观测性](../observability.md)） |
| `observe::access_log()` | 通过 `log` facade 输出结构化访问日志 |

不提供 Brotli 压缩（暂无 brotli 依赖）；预压缩的 `.br` 文件由 `Files` 提供。

## 静态文件

`files::Files::new(root)` 是一个 service。把它挂在参数名为 `path` 的通配路由上
（`/static/*path`），或者作为 fallback（此时使用请求路径）。

| 构建方法 | 默认值 | 含义 |
|---|---|---|
| `index(name)` | `index.html` | 请求目录时提供的文件 |
| `max_cached_bytes(n)` | 256 KiB | 不超过此大小的文件缓存在内存中（0 关闭） |
| `max_open_files(n)` | 64 | 更大的文件保留打开的句柄并缓存元数据 |
| `check_interval(d)` | 5 s | 缓存条目在重新检查磁盘之前被信任的时长 |
| `cache_control(v)` | 无 | 每个文件响应的 `Cache-Control` 头 |

功能：`GET`/`HEAD`；`ETag` 与 `Last-Modified`；`If-None-Match` / `If-Modified-Since`（304），
`If-Match` / `If-Unmodified-Since`（412）；由 `If-Range` 保护的单区间 `Range` 请求
（206/416）；拒绝 `..` 等越界路径（跟随符号链接）；向接受的客户端提供 `file.ext.br` /
`file.ext.gz`；明文 TCP 上大文件用 `sendfile(2)` 发送（TLS 下经内存读取）。

缓存未命中时在 I/O 线程上读文件，所以缓存的文件要小、检查间隔要合理。尚未完成：多区间响应、
基于 inotify 的失效（目前用 stat 间隔代替）、打开文件缓存的淘汰。
