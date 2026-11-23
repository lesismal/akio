# ADR-093：由可稍后应答的解析器按握手选择服务端证书

[English](093-tls-cert-resolver.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

`ServerConfigBuilder` 在构建配置时就固定了服务端证书：一条默认证书链，加上 `sni_cert` 的各条证书链。
akit（基于 akio 的网关，akit `docs/akio-api-requests.md` 第 A2 项）还需要两件事，fit 从 Go 的
`tls.Config.GetCertificate` 得到它们：

1. **服务期间替换证书。** 自动 HTTPS 大约每 60 天续期一次证书；为此重建服务端配置会丢掉会话缓存和票据
   密钥，还要推送到每个监听器。
2. **按需 TLS。** 某个名称还没有证书时，它的 ClientHello 会触发一次 ACME 签发，握手要等上几秒。规则 1
   禁止在 I/O 线程上等待。

ADR-062 已经能在不占用线程的情况下挂起服务端握手：异步防重放存储。ClientHello 被保留，什么也不发送；
应答到达时（来自任意线程），唤醒器向连接的 I/O 线程投递一个任务（TCP 用 `TransportWaker`），或者驱动
QUIC 连接，于是带着应答从头再处理同一个 ClientHello。

## 决定

1. **服务端配置上的解析器。**

   ```rust
   pub trait CertResolver: Send + Sync {
       fn resolve(&self, hello: &ClientHelloInfo<'_>, done: CertDone);
   }
   impl ServerConfigBuilder { pub fn cert_resolver(self, r: Arc<dyn CertResolver>) -> Self; }
   impl ServerConfig { pub fn builder_with_resolver(r: Arc<dyn CertResolver>) -> ServerConfigBuilder; }
   ```

   `ClientHelloInfo` 给出 SNI 名称（小写）、客户端提供的 ALPN 协议、签名算法和密码套件、正在协商的版本
   （以及是否为 QUIC）。`CertDone` 是 `Send` 的，可在任意线程上应答一次：

   - `complete(CertifiedKey)`：使用这条证书链；
   - `use_default()`：使用没有解析器时配置会用的证书（该名称的 `sni_cert` 证书链，否则默认证书链；用
     `builder_with_resolver` 构建且两者都没有时为 `unrecognized_name`）；
   - `fail(CertAlert)`：以 `handshake_failure`、`unrecognized_name`、`access_denied` 或 `internal_error`
     中止。

   不应答就丢弃视为 `internal_error`。`CertDone::is_abandoned()` 表示握手已不在了（连接关闭、超时），
   供解析器跳过没人等的工作。
2. **`CertifiedKey`** 是一条证书链及其私钥，只在 `CertifiedKey::new` 时校验一次两者匹配，可附带 stapling
   用的 OCSP 响应；克隆开销很小（共享），并在使用它的各次握手之间保留它算出的压缩证书消息（RFC 8879）。
3. **同步快速路径就是在 `resolve` 内应答。** 证书在内存里的解析器在返回前应答：握手在同一次调用中继续，
   不挂起，也不唤醒什么。`CertStore` 就是这样一个现成的解析器：名称（精确名称，或匹配一层子域的
   `*.example.com`）到 `CertifiedKey` 的映射，可随时在任意线程上用 `insert` / `remove` / `set_default`
   替换（每次完整握手一次读锁和一次 `Arc` 克隆）。akit 续期时 `insert` 新证书即可；按需签发则包装一个
   `CertStore`，命中时在调用内应答，未命中时由 ACME 任务应答（书中 TLS 一章有示意代码）。
4. **与 ADR-062 一样的挂起。** 只在完整握手时调用解析器，时机是 ClientHello 已检查完毕、版本、候选密码
   套件和 PSK 都已确定之后：会话恢复的握手（TLS 1.3 PSK、TLS 1.2 票据或会话 ID）不发送证书，也不调用它；
   有 HelloRetryRequest 时，为第二个 ClientHello 调用。如果 `resolve` 返回时还没有应答，握手保留该
   ClientHello，什么也不发送就返回；应答唤醒连接，带着给出的证书再处理同一个 ClientHello（不再查找 PSK：
   之前没找到）。期间到达的字节按 ADR-062 的上限等待。同一份代码服务于引擎上的 `Tls::server`、阻塞式
   测试 stream 和 QUIC（`QuicTls`，akio-quic 已经会唤醒并恢复它：在应答的线程上驱动连接，只持有连接的弱引用）。
5. **超时。** `ServerConfigBuilder::cert_resolver_timeout`（默认 10 s，至少 1 ms）：到时没有应答，握手以
   `internal_error` 失败。它与 ADR-062 共用计时线程（从防重放应答推广到任何挂起等待的应答）。握手超时
   （10 s，TCP）或 QUIC 的空闲超时仍然限定整个握手：按需签发时两者都要调大。
6. **等待中握手的上限。** `ServerConfigBuilder::max_pending_cert_resolutions`（每个配置默认 1024，至少
   1）。一个握手从 `resolve` 未应答返回起计入，直到被重新处理或被丢弃。到达上限时仍然调用解析器，因此
   签发高峰期间内存中已有的证书照常使用；解析器未在调用内应答的握手不再等待，而是以 `internal_error`
   失败，它的 `CertDone` 被放弃。
7. **静态路径不变。** 没有解析器时，证书的选择与以前相同（每次完整握手多一次 `Option` 判断）。下面的
   A/B 对此做了测量。

## 后果

- 存在没有默认证书的 `ServerConfig`（`builder_with_resolver`）。akio-turn 的 DTLS 配置取默认证书链，
  遇到这种配置会返回错误。
- 解析器在任何认证之前看到 ClientHello：它不能对每个名称做无上限的工作（按需签发需要白名单或速率限制，
  这是 akit 的事）。
- 未做：按客户端的 certificate_authorities 或 signature_algorithms_cert 选择证书（信息都在，匹配由解析器
  负责），以及客户端按握手选择客户端认证证书。

## 验证

akio-tls 的单元测试（`proto/resolver_tests.rs`）：调用内应答与稍后应答、从其他线程应答、TLS 1.2 与 1.3、
HelloRetryRequest、会话恢复不调用解析器、有无默认证书时的 `use_default`、告警、被丢弃的 `CertDone`、超时、
等待上限、等待期间连接被丢弃、QUIC、`CertStore`（通配符、替换）。akio 的引擎测试（`tests/tls.rs`）：在各
后端上经引擎从其他线程应答的解析器，客户端为标准实现（rustls），以及等待期间连接被关闭；akio-quic（`tests/zero_rtt.rs`）中在 QUIC 上做同样的测试。静态证书握手在安静主机上的 A/B：见提交
说明与 CHANGELOG。
