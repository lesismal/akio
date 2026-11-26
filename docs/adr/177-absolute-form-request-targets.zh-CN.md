# ADR-177：按源服务器的方式处理绝对形式的请求目标

[English](177-absolute-form-request-targets.md) | 简体中文

状态：已采纳（2026-11-26）。akit 的 A200。

## 背景

HTTP/1.1 请求可以用绝对形式给出目标：`GET http://a.example/admin/x?q HTTP/1.1`。RFC 9112 §3.2.2
要求源服务器接受它，以目标的 authority 作为请求的 host，忽略 `Host`；Go 的服务端就是这样做的
（`r.URL.Path` 为 `/admin/x`，`r.Host` 为 `a.example`），fit 也是。akio 的 HTTP/1 服务端原样复制目标：
`Request::path()` 为 `http://a.example/admin/x`，`Host` 仍是字段所写的值。按 path 路由的路由器（akio-http
的或 akit 的）认不出这个路径，而以 origin 形式请求上游的代理会向上游请求 `/admin/x`。akit 的模糊测试
（I77）发现这样写的请求绕过了保护 `/admin/*` 的路由，经兜底路由到达上游；akit 目前在 listener 中改写这类目标。

服务端此前也接受请求行能容纳的任何其他目标：`GET a.example:443`（authority 形式，属于 `CONNECT`）、
`GET admin/x`、`GET *`。

## 决定

1. **HTTP/1：绝对形式的目标按其 path 和 query 处理。** 请求头解析器识别
   `scheme "://" authority path-abempty ["?" query]`（RFC 3986 §3；任意 scheme），把 `Request::target`
   设为其 origin 形式：`/admin/x?q`，path 为空时为 `/`（`http://a?q` 为 `/?q`）。authority 的 host 和
   端口（去掉用户信息，`http://u:p@a.example:8080/x` 取 `a.example:8080`）按 RFC 9112 §3.2.2 的要求替换
   `Host` 字段。`Request::path()`、`query()`、路由器、中间件和服务看到的是普通请求。
2. **`Request::raw_target()`** 给出发送时的目标：这类请求为绝对形式，其他请求即 `target`。访问日志
   （`observe::access_log`）记录它。它保存在 `Request` 的私有 `Option<Box<str>>` 字段中，只有绝对形式的
   目标才分配。
3. **替换之前，`Host` 仍按 RFC 9112 §3.2 检查：** 没有 `Host` 的 HTTP/1.1 请求、有多个 `Host` 的任何请求，
   不论目标如何都以 400 应答。HTTP/1.0 不需要 `Host`；目标的 authority 同样成为其 `Host`。
4. **只接受 RFC 9112 §3.2 定义的形式。** 任何方法都可用 origin 形式，`CONNECT` 以外的方法可用绝对形式，
   `*` 只用于 `OPTIONS`，`CONNECT` 的目标照旧不限（其 authority 形式由服务检查）。其他目标，包括其他方法的
   authority 形式，以及 host 为空（RFC 9110 §4.2.1）或含有 RFC 3986 不允许出现在 host 和端口中的字节的
   绝对形式，均以 400 应答并关闭连接。
5. **HTTP/2 和 HTTP/3：`:path` 为 origin 形式，或 `OPTIONS` 的 `*`。** `:authority` 与 `:path` 本就分开，
   无需拆分；RFC 9113 §8.3.1 和 RFC 9114 §4.3.1 规定 `http` 和 `https` 的 `:path` 为 origin 形式（`OPTIONS`
   可为 `*`）。`:path` 为其他内容（包括绝对 URI）的请求是畸形的：HTTP/2 服务端以 `PROTOCOL_ERROR` 重置该流，
   HTTP/3 服务端像拒绝其他畸形请求一样拒绝它。这项检查不论 `:scheme` 为何都适用：akio 的服务端是 `http`
   和 `https` 的源服务器，不是路径的 path 会像 HTTP/1 目标那样到达路由器。扩展 CONNECT 的 `:path` 也须为
   origin 形式。

## 影响

- 绝对形式的请求走其 path 的路由，host 取目标的 host：akit 的 listener 所做的改写由 akio 完成，akit 的
  临时方案可以去掉（包括其 `RouterRequest::host` 覆盖，因为 `Host` 已被替换）。
- 曾从 `Request::target` 读取绝对形式的应用改为读 `raw_target()`。依赖 `Host` 优先于目标 authority 的
  应用现在看到的是 authority。
- 源服务器无法处理的形式（`CONNECT` 以外的 authority 形式、相对路径、`OPTIONS` 以外的 `*`）被拒绝；
  此前它们按不是路径的目标路由。
- 开销：origin 形式的请求对目标多做一次字节判断（`/`），`Request` 多 16 字节；只有绝对形式的请求要做
  拆分和一次分配。解析器在热路径上（规则 16）；流水线 HTTP/1 请求的同轮 A/B 留给基准测试任务（规则 20），
  预计没有变化。
- 测试：解析单元测试（`absolute_form_parts`、`request_target_forms`），路由测试
  `absolute_form_targets_are_routed_by_their_path`（tests/http.rs），HTTP/2（`h2_frames.rs` 的
  `malformed_requests_are_reset`）和 HTTP/3（`request_heads`）用例，以及 `http1_request` 模糊测试目标
  的不变式（解析得到的目标是路径、`OPTIONS` 的 `*` 或 `CONNECT` 的目标），并加入两个种子。
