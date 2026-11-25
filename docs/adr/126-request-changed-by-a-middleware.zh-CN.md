# ADR-126：由中间件修改的请求

[English](126-request-changed-by-a-middleware.md) | 简体中文

状态：已采纳（2026-11-25）

## 背景

网关的中间件在处理器看到请求之前修改它：fit 的 `headers` 中间件设置、添加和删除请求头字段，
`rewrite` 中间件修改路径，ForwardAuth 把认证服务的字段复制进请求，JWT 把声明作为字段加入，
Proxy-Wasm 插件的请求阶段（ADR-125）编辑请求的字段和路径。akio-http 的 `Context` 只以共享
引用给出请求（`req()`），所以 akit 把修改后的字段放在一个上下文本地值里、把重写后的路径放在
另一个里，每个读取请求的处理器都要知道这两者（akit 的需求 A33）。

请求在被共享之前归上下文所有：`Detached` 和 WebSocket 升级会取得它的 `Arc`，而 `suspend`
（ADR-109）把一份共享副本移入恢复后的上下文，服务器自己保留另一份。

## 决定

`Context::req_mut(&mut self) -> Option<&mut Request>`：可修改的请求，用来改它的字段、目标、
方法或消息体。之后读取请求的地方都看到修改：`path()`、`header()`、该中间件之后的处理器、
`Files` 的条件请求和范围字段、响应过滤器拿到的 `&Request`。

- 请求被共享后返回 `None`：`detach` 之后（请求归 `Detached`）或 WebSocket 升级之后。
- `suspend` 现在把整个请求移入恢复后的上下文，后者可以修改它（ForwardAuth 在调用之后复制
  字段）；服务器保留的上下文持有一个空请求，不会再被读取（它已分离，也不会被回收）。
- 路由参数仍读取它们匹配时的路径：路由器的参数是路径上的区间，所以对带参数的已路由请求第一次
  调用 `req_mut` 时，把路径复制进参数（一次分配，仅在此时）。路由器在其路由的层运行之前匹配：
  由某个层修改的目标不会让请求重新路由，而由整个路由器之前的中间件修改的目标会。
- 请求的分帧仍由服务器决定：修改 `Content-Length` 或 `Transfer-Encoding` 不会改变其余消息体
  的读取方式。

也考虑过只提供 `set_target` 或 `headers_mut`：更窄，但请求编辑（Proxy-Wasm 插件的）也可能
修改方法，而给出 `&mut Request` 并不多花什么。

## 影响

- akit 去掉其临时方案：`headers`、ForwardAuth 和 JWT 中间件就地修改请求字段，`rewrite` 修改
  其目标，akit-listener 的规范路径就是请求的目标。
- 热路径不变：`req_mut` 只是对所有权请求的一次匹配，参数的复制只在修改带参数的已路由请求时
  发生。

## 测试

`crates/akio-http/tests/req_mut.rs`（HTTP/1.1 和 HTTP/2，epoll 和 io_uring）：在路由器之前
设置、添加和删除字段并重写目标（路由器按新路径路由），处理器、`path()`、`header()` 和响应过滤器
都看到修改；同一连接上的下一个请求不受影响；由路由的层修改的目标，其参数（解码后和原始的）仍是
匹配时路径上的；`detach` 之后为 `None`；恢复后的挂起请求可以修改。
`crates/akio-h3/tests/end_hooks.rs`：同样的重写走 HTTP/3。
