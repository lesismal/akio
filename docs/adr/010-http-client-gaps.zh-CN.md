# ADR-010：HTTP 与 WebSocket 客户端：重定向、超时、解析、系统根证书、代理

[English](010-http-client-gaps.md) | 简体中文

状态：已采纳（2026-11-16）

## 背景

akio-http 的 HTTP/1 客户端（`client::Client`）、HTTP/2 客户端（`h2client::H2Client`）和 akio-ws
的 WebSocket 客户端（`client::dial`）可用，但缺少真实部署都会遇到的能力：不跟随重定向、没有单请求
超时、`getaddrinfo` 在调用线程上执行（在回调里调用时会阻塞 I/O 线程）、没有默认信任库（调用方要自己
找 CA 文件）、不支持代理，以及引擎关闭时 WebSocket 客户端不发关闭帧就断开连接。补齐这些要在四个 crate
里增加公共 API，并做几个产品决定，记录于此。项目规则不变：不引入第三方依赖。

## 决定

1. **在调用线程之外解析域名：`akio::dns`。** `akio::dns::resolve(host, port, done)` 对 IP 字面量
   直接在调用线程应答，域名交给进程级的解析线程池（最多 4 个 `akio-dns` 线程，按需启动，空闲 10 秒
   后退出）；`done` 在解析线程上运行，按系统顺序给出所有地址（空结果是 `NotFound`）。不用引擎的逻辑
   池：解析可能耗时数秒，不应拖慢应用的阻塞任务，而且客户端在连接（也就是 `Conn`）存在之前就需要它。
   解析无法取消；已超时的请求忽略迟到的结果。HTTP/1 客户端只在该路由没有空闲 keep-alive 连接时才解析；
   WebSocket 客户端每次都解析。`H2Client::dial` 仍然接收 `SocketAddr`。
2. **系统根证书：`akio::tls::RootCerts::system()`。** 每个进程读取一次并缓存。设置了
   `SSL_CERT_FILE` / `SSL_CERT_DIR` 时以它们为准（OpenSSL 惯例，部署可以让所有客户端指向自己的
   证书库）。macOS：用 `/usr/bin/security find-certificate -a -p` 导出系统钥匙串
   （`SystemRootCertificates.keychain` 和 `/Library/Keychains/System.keychain`），失败时回退到
   `/etc/ssl/cert.pem`；**不**应用钥匙串的信任设置（管理员标记为不信任的 CA），这是不链接
   Security.framework 的代价，已写入文档。其他 Unix：按常见发行版路径取第一个存在的证书包
   （Debian/Ubuntu/Alpine/Arch 的 `ca-certificates.crt`、Fedora/RHEL、openSUSE、FreeBSD……），
   否则读证书目录。akio-x509 无法解析的证书被跳过；一个证书都没有时报错。**客户端默认使用它**：
   没有 `with_tls` 的 `Client` 和 `DialOptions::tls = None` 现在对 `https://` / `wss://` 使用
   系统 CA（以前会报 "needs Client::with_tls" / "needs DialOptions::tls"）。这把一个错误变成了
   预期行为，对传入配置的调用方没有任何变化。
3. **重定向：显式开启，`client::RedirectPolicy`。** `Client::with_redirects(policy)`；
   `RedirectPolicy::none()`（默认，现有调用方照旧看到 3xx 响应）或 `RedirectPolicy::limit(n)`。
   跟随带 `Location` 的 301、302、303、307、308，相对请求 URL 解析（RFC 3986 第 5 节，丢弃片段）；
   300、304、305 从不跟随。方法与请求体按 RFC 9110 第 15.4 节：303 把除 `HEAD` 外的方法改为不带
   请求体的 `GET`；301 和 302 把 `POST` 改为不带请求体的 `GET`（所有浏览器和 curl 的做法），其他方法
   保持不变；307 和 308 保持方法和请求体。丢弃请求体时一并去掉描述它的字段（`Content-Type`、
   `Content-Length`、`Content-Encoding`、`Content-Language`、`Content-Location`、
   `Transfer-Encoding`）。**凭据不跨源泄露**：scheme、主机（不区分大小写）或端口变化时，删除
   `Authorization`、`Cookie` 和 `Proxy-Authorization`，并在整条链的剩余部分保持删除，即使链又回到
   原来的源。**https → http 不跟随**，除非 `allow_https_downgrade(true)`；此时返回该 3xx 响应
   （报错会让调用方看不到可能需要检查的 `Location`）。超过上限（循环也在这里结束）是
   `ClientError::TooManyRedirects`；不是 `http(s)` URL 的 `Location` 是 `ClientError::InvalidUrl`。
   没有 cookie 容器：需要跨重定向携带 cookie 的客户端自己跟随重定向。`ClientResponse::url` 给出最终
   应答的 URL。WebSocket 客户端的握手通过 `DialOptions::max_redirects`（默认 0）使用同样的规则：
   `http`/`https` 的 location 映射为 `ws`/`wss`，从不跟随 `wss → ws`，跨源跳转从
   `DialOptions::headers` 中删除同样的字段并清除 `server_name` 覆盖，`WsClientError::TooManyRedirects`
   终止循环。浏览器不跟随 WebSocket 重定向；RFC 6455 第 4.1 节允许跟随，因此默认关闭。`H2Client`
   是到一个源的一条连接，不跟随重定向。
4. **单请求超时。** `ClientRequest::timeout: Option<Duration>`（以及 `.timeout(d)`）和作为默认值的
   `Client::with_timeout(d)`。它覆盖整个交换过程：解析、连接、TLS、请求、完整响应以及所有重定向（与
   Go 的 `Client.Timeout` 一致；调用方考虑的是一个总预算）。到期时请求以 `ClientError::Timeout`
   失败（在定时器线程上回调），其连接被关闭，不会回到连接池，也不会重试。`H2Client` 同样遵守
   `ClientRequest::timeout`：用 `CANCEL` 重置该流，连接仍可使用。超时发生时仍在连接中的拨号会走完，
   随后被关闭。WebSocket 客户端保留 `handshake_timeout`，现在它覆盖整个重定向链。
5. **HTTP 代理：`akio_ws::proxy::Proxy`，在 `akio_http::client::Proxy` 重新导出。** 它放在
   akio-ws 中，因为两个客户端都需要，而 akio-http 已经依赖 akio-ws。`Proxy::all(url)`、
   `.http(url)`、`.https(url)`、`.no_proxy(list)`、`Proxy::from_env()`、`is_empty()`、
   `applies(secure, host, port)`。**环境变量需显式启用**：除非调用方传入 `Proxy::from_env()`，否则
   不会读取（`http_proxy`/`HTTP_PROXY`、`https_proxy`/`HTTPS_PROXY`、`no_proxy`/`NO_PROXY`，小写
   优先；设置了 `REQUEST_METHOD` 时忽略 `HTTP_PROXY`，防范 "httpoxy"）；无法使用的值会报错，而不是
   悄悄绕过代理。只支持明文 HTTP 代理（`http://[user:pass@]host[:port]`，默认端口 80；凭据变成
   `Proxy-Authorization: Basic`）；不支持到代理本身的 TLS 和 SOCKS（akio-socks 是独立的）。
   `NO_PROXY` 条目：`*`、匹配自身及其子域的主机名（前导 `.`/`*.` 可选）、IP 地址、CIDR 网段，均可带
   `:port`；回环地址不做特殊处理（需要时请列出）。路由：`http://` 目标以绝对形式请求发给代理（keep-alive
   连接按代理分池）；`https://`、`ws://` 和 `wss://` 经 `CONNECT host:port` 隧道。隧道是一个叠在 TLS
   传输层之下的 `Transport`（隐藏的 `akio_ws::proxy::Connect` acceptor 包装）：它发送 `CONNECT`，
   在收到 2xx 之前暂存 TLS 首个 flight 和应用字节，之后不再介入（`tls_info` 仍能看到 TLS 传输层）。
   非 2xx 的应答使连接失败，产生携带 `akio_ws::proxy::ProxyRefused`（状态码和原因；401/403/407 的
   kind 为 `PermissionDenied`）的 `io::Error`，以 `ClientError::Io` / `WsClientError::Io` 报告；
   代理的响应体绝不会被当作目标服务器的响应展示。
6. **引擎关闭时 WebSocket 发送 1001。** 客户端 acceptor 的 `on_shutdown` 对已打开的连接以 1001
   （"going away"）开始关闭握手（服务器应答，TCP 连接在 `close_timeout` 内结束），并丢弃仍在握手的连接。
7. **API 汇总**（全部为新增；涉及的枚举和结构体都是 `#[non_exhaustive]`）：
   - `akio`：模块 `dns`（`resolve`、`literal`、`MAX_THREADS`、`IDLE`）。
   - `akio-tls`：`RootCerts::system()`。
   - `akio-ws`：模块 `proxy`（`Proxy`、`ProxyRefused`）；`DialOptions::{proxy, max_redirects}`；
     `WsClientError::TooManyRedirects`。
   - `akio-http`：`client::{RedirectPolicy, Proxy, ProxyRefused}`；
     `Client::{with_redirects, with_timeout, with_proxy}`；`ClientRequest::timeout`（字段和构建方法）；
     `ClientResponse::url`；`ClientError::{Timeout, TooManyRedirects}`。

## 影响

- 客户端的请求路径上不再有阻塞调用；从 I/O 线程回调中发起的重定向不再在该线程上解析域名。
- 在 Linux 和 macOS 上 `https://` 和 `wss://` 无需配置即可使用；没有 CA 库的主机会报告查找过的位置。
  不遵守 macOS 钥匙串信任设置；需要它的部署设置 `SSL_CERT_FILE` 或传入自己的 `RootCerts`。
- 每个 `Client::with_*` 返回拥有独立 keep-alive 连接池的客户端，与 `with_tls` 一贯的行为一致。
- 未做、以后可增量添加：cookie 容器、HTTPS（TLS）与 SOCKS 代理、代理自动配置、URL 内 Basic 凭据以外的
  `Proxy-Authenticate` 质询、Happy Eyeballs（地址按顺序尝试）、DNS 缓存、Windows 证书库。
