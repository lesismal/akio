# HTTP 客户端

两个客户端的连接都运行在 only 的 `Engine` 上（给它设置 `client_threads(n)` 并 `start()`）。
结果通过 I/O 线程上的回调到达（回调不能阻塞），或者通过 `ResponseFuture` 获取：可以
`wait()`、`wait_timeout(d)` 或 `.await`。

## HTTP/1.1：`client::Client`

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:client}}
```

- `Client::new(Arc<Engine>)`，克隆开销很小。`https://` 使用系统 CA
  （`only::tls::RootCerts::system()`）；`with_tls(only::tls::ClientConfig)` 替换它（自己的根证书、
  客户端证书、ALPN）。
- `ClientRequest::get(url)`、`ClientRequest::post(url, body)`、`.header(name, value)`、
  `.timeout(d)`；也可以自己填 `method`、`url`、`headers`、`body`、`timeout`。`Host`、
  `Content-Length` 和 `Connection` 会自动添加。
- `client.send(req)` 返回 `ResponseFuture`；`client.request(req, callback)` 使用回调。
- `ClientResponse` 包含 `status`、`reason`、`headers`、`body`（已去掉 chunked 编码）、`trailers`
  和 `url`（最终应答的 URL，即重定向之后的）。
- keep-alive 连接按主机（以及按代理）复用；在复用连接上发出的请求如果发现连接已失效，会在新连接上
  重试一次。
- 域名在调用线程之外解析，由 `only::dns` 的解析线程完成（最多 4 个，按需启动）；IP 字面量不需要解析。
  依次尝试解析出的每个地址（`localhost` 往往先解析出 `::1`）。
- `ClientError`：`InvalidUrl`、`Io`、`Protocol`、`Closed`、`Timeout`、`TooManyRedirects`、
  `TooLarge`。
- 限制（`Client::with_options(ClientOptions)`），每项都有安全的默认值：

  | 字段 | 默认值 | 超过后 |
  |---|---|---|
  | `max_head_bytes` | 64 KiB | 响应头（含 1xx 响应头）→ `ClientError::TooLarge` |
  | `max_body_bytes` | 64 MiB | 任何分帧方式；更大的 `Content-Length` 立即失败 → `TooLarge`（`usize::MAX` 表示不限制） |
  | `idle_timeout` | 90 s | 连接池中闲置这么久的连接会被关闭 |
  | `max_idle_per_host` | 32 | 同一路由更多的空闲连接会被关闭（0：不复用） |
  | `max_idle` | 256 | 全部空闲连接总数 |

每个 `with_*` 都返回拥有独立连接池的新客户端；配置一次后克隆使用。

### 重定向

默认关闭：3xx 响应原样返回。`with_redirects(RedirectPolicy::limit(n))` 跟随带 `Location` 的
301、302、303、307 和 308 响应（相对地址按请求 URL 解析），遵循 RFC 9110 第 15.4 节：

| 状态码 | 方法与请求体 |
|---|---|
| 303 | 不带请求体的 `GET`（`HEAD` 保持 `HEAD`） |
| 301、302 | `POST` 变为不带请求体的 `GET`；其他方法连同请求体保持不变 |
| 307、308 | 方法和请求体保持不变 |

丢弃请求体时，相应的 `Content-*` 字段也一并去掉。重定向到另一个源（scheme、主机或端口不同）时删除
`Authorization`、`Cookie` 和 `Proxy-Authorization`，并在链的剩余部分保持删除。`https://` 到
`http://` 不跟随（返回该 3xx），除非 `RedirectPolicy::limit(n).allow_https_downgrade(true)`。
超过 `n` 次重定向（例如循环）以 `ClientError::TooManyRedirects` 失败。没有 cookie 容器。

### 超时

`ClientRequest::timeout(d)`，或对所有请求生效的 `Client::with_timeout(d)`，限制整个交换过程：解析、
连接、TLS、发送、完整响应和所有重定向。到期时请求以 `ClientError::Timeout` 失败，其连接被关闭（不会
复用或重试）。`ResponseFuture::wait_timeout` 只是停止等待，请求仍在继续。

### 代理

```rust,ignore
use only_http::client::{Client, Proxy};
let client = Client::new(engine)
    .with_proxy(Proxy::all("http://user:pass@proxy.internal:3128")?.no_proxy("localhost,.corp"));
// 或者显式启用环境变量（http_proxy、https_proxy、all_proxy、no_proxy，也认大写）：
let client = Client::new(engine).with_proxy(Proxy::from_env()?);
// 或者 SOCKS 代理（主机名由代理解析）：
let client = Client::new(engine).with_proxy(Proxy::all("socks5h://user:pass@proxy.internal")?);
```

`http://` 请求以绝对形式发给代理（`GET http://host/path HTTP/1.1`）；`https://` 经
`CONNECT host:port` 隧道，在隧道内与目标建立 TLS。代理 URL 中的凭据变成
`Proxy-Authorization: Basic`。代理拒绝建立隧道时，请求以 `ClientError::Io` 失败，其内部错误是
`only_http::client::ProxyRefused`（`status()`、`reason()`）。`NO_PROXY` 条目：`*`、主机名（及其
子域）、IP 地址、CIDR 网段，均可带 `:port`。不支持到代理本身的 TLS。除非调用
`Proxy::from_env()`，否则不会读取环境变量；`all_proxy` / `ALL_PROXY` 用于专门变量没有设置的协议。

SOCKS 代理（`socks5://`、`socks5h://`、`socks4://`、`socks4a://`，默认端口 1080）：所有请求，包括
`http://`，都经 SOCKS 隧道到达目标。`socks5h` 和 `socks4a` 把主机名交给代理；`socks5` 和 `socks4`
先解析目标并请求它的第一个 IPv4 地址（curl 的约定）。URL 中的凭据是 SOCKS5 用户名/密码（RFC
1929），或 SOCKS4 的 user id。拒绝同样是 `ProxyRefused`，带最接近的 HTTP 状态码（认证 407、“不允许”
403、目标不可达 502），`socks_reply()` 给出 SOCKS 应答码。这些客户端之外的 SOCKS 用法（BIND、UDP、
阻塞 socket）见 [SOCKS 客户端](socks.md#socks-客户端)。

这些规则背后的考虑见
[ADR-010](https://github.com/lesismal/only/blob/main/docs/adr/010-http-client-gaps.zh-CN.md) 与
[ADR-019](https://github.com/lesismal/only/blob/main/docs/adr/019-socks-client-fragments-socks4-bind.zh-CN.md)。

## HTTP/2：`h2client::H2Client`

```rust,ignore
{{#include ../../../../crates/only-http/examples/guide-http.rs:h2client}}
```

- `H2Client::dial(engine, addr, tls, opts, ready)` 或 `dial_blocking(engine, addr, tls,
  opts)`。`tls = None` 表示 prior knowledge 的明文 HTTP/2；`Some((cfg, server_name))` 使用 TLS，
  且 `cfg.alpn_protocols` 中必须包含 `h2`。
- 一个连接复用所有请求；`H2Client` 克隆开销很小，可在任何线程使用。`send(req)` →
  `ResponseFuture`，`request(req, callback)`。
- `H2Options`：`initial_window`（1 MiB）、`conn_window`（16 MiB）、`enable_push`（false；开启后
  `ClientResponse::pushed` 携带被推送的响应，每个请求最多 32 个未完成的推送）。
- 限制：超过默认 `SETTINGS_MAX_FRAME_SIZE`（16 KiB）的帧，以及超过 `max_header_list` 两倍的
  头部块（HEADERS + CONTINUATION）会结束连接；解码后超过 `max_header_list`（64 KiB，会通告给
  对端）的头部列表，或超过 `max_body_bytes`（64 MiB）的缓冲 body，会重置该 stream（`CANCEL`）
  并以 `TooLarge` 使请求失败。流式请求（`open`）的 body 随到随交，不限制大小。
- 双向流式：`open(req, on_event)` 返回用于写请求 body 的 `H2Upload`（`write`、`finish`），并在
  响应到达时报告 `H2Event::Head`、`Data`、`Trailers`、`End` 或 `Error`。only-grpc 的客户端
  就建立在它之上。
- `is_open()`、`close()`。
- 遵守 `ClientRequest::timeout`：该流被重置（`CANCEL`），请求以 `ClientError::Timeout` 失败；连接
  仍可使用。一条连接只对应一个源：不跟随重定向，不走代理。

## HTTP/3

`only_h3::H3Client` 见 [QUIC 与 HTTP/3](quic-h3.md)。

## 在异步代码中 await

`ResponseFuture` 实现了 `Future`，所以异步代码（包括 tokio）可以 `.await` 它；连接本身仍
运行在 only 的 I/O 线程上。见[从 tokio 迁移](../migration/from-tokio.md)。
