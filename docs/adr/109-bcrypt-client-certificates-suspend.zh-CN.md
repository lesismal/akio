# ADR-109：bcrypt、每个请求上的客户端证书，以及请求的挂起与恢复

[English](109-bcrypt-client-certificates-suspend.md) | 简体中文

状态：已采纳（2026-11-24）

## 背景

akit（基于 akio 的网关）移植 fit 的 `basic_auth` 与 `client_cert` 中间件（其迭代 I42，请求
A63、A64、A65）：

- `basic_auth` 用 bcrypt 哈希（`htpasswd -B` 和 Go 的 `x/crypto/bcrypt` 生成的那种）校验 HTTP
  Basic 密码。`akio-crypto` 有 PBKDF2 和 HKDF，没有 bcrypt（A63）。
- `client_cert` 只放行客户端发送了、且监听器 TLS 已验证过证书的请求，并把证书主题传下去。服务端
  处理器此前看不到这张证书：`TlsInfo` 不带它，处理器拿到的是 `Context` 而不是连接（A64）。
- 一次 bcrypt 校验要花几毫秒到几十毫秒的 CPU，不能在 I/O 线程上做。fit 在一个小线程池里校验，
  请求在此期间等待，校验后继续执行下一个中间件和处理器。在 akio 中，中间件可以分离响应并在线程池
  里作答，却无法继续执行链：下一个处理器要的是 `Context`，而分离的请求没有。`run_on_pool` 把监听器
  的所有请求都搬到线程池，为了偶尔一次 bcrypt 让每个请求都多一次线程切换（A65）。ForwardAuth（请求
  继续前先询问授权服务器）也有同样的需求。

## 决定

- **`akio_crypto::bcrypt`**：`Hash::parse`（`$2a$`、`$2b$`、`$2y$`、`$2$`，代价 4 到 31，失败时
  `ParseError` 说明原因）、`Hash::verify`（EksBlowfish，23 字节常数时间比较；与 Go 和 OpenBSD 一样
  只读密码的前 72 字节；与 Go 一样忽略盐和哈希字节之外的多余位）、`Display`（写回哈希）、`hash`
  （随机盐，`$2b$`，拒绝超过 72 字节的密码）和 `hash_with_salt`。Blowfish 的表是 π 的各位数字，
  由程序生成并与 Go 的表核对。与所有 bcrypt 一样，Blowfish 用依赖密钥的字节索引 S 盒；一次校验的
  耗时只取决于代价。
- **`Request::peer_certificates: Option<Arc<[Vec<u8>]>>`**（akio-http）：客户端发送并经 TLS 握手
  验证的证书链，DER，叶证书在前，由 HTTP/1.1、HTTP/2 和 HTTP/3 服务端设置。会话在握手完成后向传输层
  取一次（`akio_tls::peer_chain`，此后共享该链；握手完成前为 `PeerChain::Handshaking`），每个请求拿到
  一个 `Arc`：每个连接拷贝一次，每个请求一次引用计数，没有证书的连接没有任何开销。以 TLS 1.3 早期
  数据到达的请求没有证书：客户端证书在它之后才到。恢复的会话带有被恢复会话的证书链（会话状态本就
  保存了它）。`TlsInfo::peer_certificates` 和 `akio_quic::Connection::peer_certificates` 也给出它。
  `Request` 与 `TlsInfo` 是 `#[non_exhaustive]`：新增字段不破坏兼容。
- **`Context::suspend` → `Suspended`** 与 **`Suspended::resume(f)`**（akio-http）：上下文移入
  `Suspended`（请求改为共享；参数、本地值、响应过滤器与额外头、响应者），服务端自己持有的上下文
  视为已分离；`resume` 在调用线程上用它运行 `f`，若 `f` 既未响应也未分离则回 `500`，与服务端在
  `call` 之后的做法一致。未恢复就丢弃时回 `500`。HTTP/1.1 的响应保持顺序（响应者占着请求的位置）。
  恢复后的上下文可以再次挂起；与线程池上的上下文一样，它不能接管连接。
  **`Context::suspend_to_pool(work)`** 在逻辑线程池上用挂起的请求运行 `work`，线程池满时与
  `detach_to_pool` 一样回 `503` 并带 `Retry-After: 1`。
- 消息体**流式**传递的请求（`BodyMode::Stream`）不能挂起（返回 `None`）：服务端在 `call` 之后把
  消息体交给该上下文。想挂起带消息体请求的服务要求整体读取消息体（`Service::body_mode`）；
  `run_on_pool` 的界线相同。

## 影响

网关可以校验密码、证书和外部授权，既不阻塞 I/O 线程，也不必把其他请求搬离 I/O 线程。API 为新增。
`suspend` 不支持流式消息体是唯一代价：akit 的 `basic_auth` 只对密码尚未校验过的请求要求整体读取
消息体（在监听器的消息体上限内）；以后的版本可以让挂起的请求改为暂停其消息体的读取。

## 验证

- `akio-crypto` 的 bcrypt：Go（`$2a$`）、Apache `htpasswd -B`（`$2y$`）生成的哈希与 OpenBSD 的
  测试向量，空密码、非 ASCII 和含 NUL 的密码，72 字节截断，由盐复现哈希，以及各种畸形哈希及其原因。
- `akio-http/tests/peer_certificates.rs`：TLS 上的 HTTP/1.1 与 HTTP/2，有无客户端证书，第二个（恢复
  的）连接，以及明文；`akio-h3/tests/peer_certificates.rs` 覆盖 HTTP/3。
- `akio-http/tests/suspend.rs`：从线程池和其他线程恢复挂起的请求，挂起两次的请求，本地值、过滤器
  和头得以保留，流水线 HTTP/1.1 响应按序（开或不开 `run_on_pool`），丢弃或未作答时回 `500`，线程池
  满时回 `503`，整体读取的消息体得以保留，流式消息体被拒绝，以及 HTTP/2 的流。在 epoll 与 io_uring
  上运行。
