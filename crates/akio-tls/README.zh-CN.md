# akio-tls

[English](README.md)

[`akio`](https://github.com/lesismal/akio) 的 TLS 1.3 与 1.2，由本 crate 依据 RFC、基于
[`akio-crypto`](../akio-crypto) 与 [`akio-x509`](../akio-x509)（证书压缩另用
[`akio-deflate`](../akio-deflate)、[`akio-brotli`](../akio-brotli) 与 [`akio-zstd`](../akio-zstd)）实现：sans-io、安全 Rust
（`#![forbid(unsafe_code)]`）、无第三方依赖。它在 API 不变的前提下替代了 rustls 与 ring（DEV-PLAN
第 C 波）。

用 `Tls::server`（或供 `Engine::dial` 使用的 `Tls::client`）包装任意 acceptor，其 handler 看到的就是
明文；握手在连接所属的 I/O 线程上进行，从不阻塞。用 `ServerConfig::builder(chain, key)`（SNI 证书、由可稍后在其他线程上应答的
`CertResolver` 按握手选择的证书（ADR-093）、
ALPN、客户端认证、会话缓存与票据、`tls13_only`、记录大小限制、证书压缩、装订的 OCSP 响应）与
`ClientConfig::builder()`（根证书、ALPN、客户端证书、SNI、会话恢复、记录大小限制、证书压缩、OCSP
stapling 及其校验、CRL、仅供测试的 `insecure_skip_verify`）配置；`tls_info` 读取协商结果。

```rust,no_run
use akio_tls::{Certificate, PrivateKey, ServerConfig, Tls};
# struct Echo; impl akio_core::Handler for Echo { fn on_data(&mut self, _: &akio_core::Conn<Self>, _: &[u8]) {} }
let chain = Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = ServerConfig::builder(chain, key).alpn(["h2", "http/1.1"]).build().unwrap();
let acceptor = Tls::server(cfg, akio_core::fn_acceptor(|_c: &akio_core::Conn<Echo>| Echo));
# let _ = acceptor;
```

## 协议

- **TLS 1.3**（RFC 8446）：双方完整握手、HelloRetryRequest（回显 cookie）、密钥调度、KeyUpdate
  （应答；在达到 AES-GCM 记录上限前主动发送）、NewSessionTicket 与使用 `psk_dhe_ke` 的 PSK 恢复
  （无状态票据，或来自会话缓存的一次性票据）、客户端证书（CertificateRequest）、中间设备兼容模式；
  双方都开启时支持早期数据（0-RTT，见下文），否则拒绝并按 RFC 8446 4.2.10 跳过。
- **TLS 1.2**（RFC 5246、RFC 7627 扩展主密钥、RFC 5746 重协商指示）：仅 ECDHE 搭配 ECDSA、Ed25519、
  Ed448 或 RSA 证书与 AEAD 套件（无 CBC、无 RSA 密钥交换、无静态 DH），会话 ID 与 RFC 5077 票据，客户端
  证书；以 `no_renegotiation` 警告拒绝重协商。
- 套件 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`、
  `ECDHE-{ECDSA,RSA}-AES{128,256}-GCM` 与 `ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305`；组 X25519、
  secp256r1、secp384r1、x448（ADR-046）、secp521r1（排在最后；ADR-049）；签名方案 ECDSA
  P-256/P-384/P-521、Ed25519、Ed448、使用 `rsaEncryption` 密钥的 RSA-PSS（`rsa_pss_rsae_*`）与使用
  `id-RSASSA-PSS` 密钥的 RSA-PSS（`rsa_pss_pss_*`，受密钥参数约束，TLS 1.3 与 1.2；ADR-049）、
  RSA PKCS#1 v1.5（TLS 1.2 与证书）。
- 记录层：16 KiB 分片、TLS 1.3 内层内容类型与填充、带降级哨兵的版本协商、严格的状态机、握手消息跨
  记录重组且绝不跨密钥切换、告警与 close_notify、常量时间的 Finished / 绑定值校验。
- 证书由 `akio-x509` 验证（链、有效期、EKU、DNS 名与 IP 地址）。
- 扩展：record_size_limit（RFC 8449）、证书压缩（RFC 8879：zlib、brotli、zstd）与 OCSP stapling（RFC 6066 /
  RFC 8446 4.4.2.1），见下文。

### record_size_limit、证书压缩、OCSP stapling

决定记录在 [ADR-008](../../docs/adr/008-tls-extensions.zh-CN.md)。

- **record_size_limit**（RFC 8449，TLS 1.3 与 1.2，QUIC 中不用）：两个构建器上的
  `record_size_limit(n)` 设定我们接受的最大记录，按 RFC 的口径为 64 到 16385 字节（TLS 1.3 含内容类型
  字节；TLS 1.2 上限 16384），默认 16385。客户端总是发送自己的值；只要客户端发了，服务端就回以自己的值。
  之后双方写出的受保护记录按对方的限制切分，收到超过自己限制的受保护记录则以 `record_overflow` 拒绝；
  明文记录不受限制。早期数据遵循签发票据的那条连接上的限制。不支持该扩展的对端（OpenSSL、Go）不会得到也
  不会被施加限制。未实现 OpenSSL 的 max_fragment_length（RFC 6066）：按 RFC 8449 对已支持
  record_size_limit 一方的建议，忽略该请求。
- **证书压缩**（RFC 8879，TLS 1.3）：zlib、brotli 和 zstd，由自研的 `akio-deflate`、`akio-brotli` 与
  `akio-zstd` 提供（[ADR-041](../../docs/adr/041-brotli-zstd.zh-CN.md)）。服务端默认开启：对提供该扩展的客户端，
  用其提供的算法中压得最小的那种，在压缩后比原链更小时发送压缩的证书链（每张证书每种算法只压缩一次并复用，
  每次握手没有额外开销），并在 CertificateRequest 中为客户端证书提供这三种。客户端默认关闭
  （`certificate_compression(true)` 提供 brotli、zstd 和 zlib）：每收到一条压缩的证书链要解压一次，耗时几微秒，
  约为内存中完整握手的百分之一到二。任一 builder 上的 `certificate_compression_algorithms(&[CertCompression])`
  只启用其中几种。收到的压缩证书最多解压到 128 KiB，长度必须与声明的完全一致（否则 `bad_certificate`）；
  未提供的算法报 `illegal_parameter`。
- **OCSP stapling**：`ServerConfigBuilder::ocsp_response(der)`（SNI 证书链用 `sni_ocsp_response`）
  为请求它的客户端装订一个 DER 格式的 OCSP 响应（TLS 1.3：放在叶证书的 CertificateEntry 中；TLS 1.2：
  ServerHello 中的 `status_request` 加 CertificateStatus 消息；会话恢复时不发送）。该响应只检查是否像一个
  成功的 `OCSPResponse`；按时刷新由调用方负责。`ClientConfigBuilder::ocsp_stapling(true)` 请求响应，
  `TlsInfo::ocsp_response` 保存收到的内容。
- **吊销检查**（ADR-038；不访问网络：响应与 CRL 由应用获取）：
  `ClientConfigBuilder::ocsp_policy(RevocationPolicy::{Off, SoftFail, HardFail})` 校验服务器为叶证书
  装订的响应（通过 `akio-x509` 按 RFC 6960：由签发者或带 id-kp-OCSPSigning 的委托响应者签名、针对该证书、
  thisUpdate / nextUpdate 在 5 分钟偏差内有效；TLS 1.3 与 1.2），策略不为 Off 时自动请求装订。软失败只拒绝
  有效的“revoked”（`certificate_revoked`）；硬失败要求有效的“good”，否则以
  `bad_certificate_status_response` 失败。`ClientConfigBuilder::crls(Crls, policy)` 与
  `ServerConfigBuilder::client_crls(Crls, policy)` 用 CRL（完整与 delta，RFC 5280）检查对端证书链中根以下的
  每张证书；硬失败下没有当前 CRL 覆盖的证书会失败（`certificate_unknown`）。恢复的会话不再检查；刷新 CRL
  需要构建新的配置。默认全部关闭，没有开销。
- **客户端的 OCSP 响应**（TLS 1.3 客户端认证，RFC 8446 4.4.2.1；ADR-049）：
  `ServerConfigBuilder::client_ocsp_policy(policy)` 请求它（在 CertificateRequest 中发送空的
  status_request），并按与上面相同的策略和规则校验客户端装订在叶证书 CertificateEntry 中的响应；
  `ClientConfigBuilder::client_cert_ocsp_response(der)` 是客户端被要求时装订的响应。TLS 1.2 无法携带，
  因此硬失败时拒绝 TLS 1.2 的客户端证书；OpenSSL 与 Go 既不发送也不请求（它们的客户端忽略该请求：软失败
  下可通过）。服务端的 `TlsInfo::ocsp_response` 即客户端的响应。

### 早期数据（0-RTT）

双方默认关闭。`ServerConfigBuilder::early_data(max_bytes)` 让新票据携带 `max_early_data_size`，
并接受用这些票据恢复会话的客户端发来的早期数据；`ClientConfigBuilder::early_data(true)` 让客户端把
应用在握手完成前写入的数据作为早期数据（不超过票据的上限）紧跟在 ClientHello 之后发出。

- **接受**：只针对第一个 PSK，且套件、ALPN 协议、SNI 名都与票据一致，HelloRetryRequest 之后不接受
  （RFC 8446 4.2.10）；服务端在握手完成前读取它，以 EndOfEarlyData 结束。读到超过允许量的数据时
  以 `unexpected_message` 失败。
- **拒绝**：服务端跳过被拒的早期数据；客户端保留副本，握手后作为普通数据重发，字节流两种情况下完全
  相同。
- **可见**：`TlsInfo::early_data`（`NotAttempted`、`Pending`、`Accepted`、`Rejected`）与
  `TlsInfo::early_data_len`（流开头这么多字节是早期数据）。akio-http 给作为早期数据到达的 HTTP/1.1
  请求加上 `Early-Data: 1`（RFC 8470；HTTP/2 则是这种连接上的每个请求），处理函数可以回 `425 Too Early`。
- **防重放**（开启早期数据时强制生效）：仅当客户端报告的票据年龄与服务端计算的年龄相差不超过 10 秒
  时才接受早期数据（RFC 8446 8.3），并把每个被接受早期数据的 ClientHello 的 PSK binder 记录两倍窗口
  时长（RFC 8446 8.2，“ClientHello 记录”）；binder 已在记录中的 ClientHello，其早期数据被拒绝（握手仍以
  1-RTT 完成）。记录有上限（每个 `ServerConfig` 100,000 条）：满了就拒绝早期数据，直到条目过期。之所以
  选它而不是一次性票据，是因为它适用于无状态票据，且每个恢复会话的 ClientHello 只多一次查找。

**安全权衡。** 早期数据没有前向保密（只受恢复密钥保护），且**可被重放**：上述记录能挡住窗口内对同一
服务端进程的重放，但挡不住发往共享票据的其他进程或机器的重放，也挡不住攻击者诱使客户端重试、在新
ClientHello 中再次发送同一请求。只为可安全重复的请求（幂等读取）开启它，其他操作前先检查
`TlsInfo::early_data` / `Early-Data: 1`，对其余请求回 `425 Too Early`。

未实现：`status_request_v2`（RFC 6961，中间证书的 OCSP；仅限 TLS 1.2，从未广泛部署，已被 TLS 1.3 中
每个 CertificateEntry 自带的状态取代，ADR-049）、获取 OCSP 响应或 CRL（由应用负责；`akio-x509` 给出
URL）、以哈希长度之外的盐长做 RSA-PSS 签名。

内核 TLS（`ktls` feature，ADR-067）：`ServerConfigBuilder::ktls` / `ClientConfigBuilder::ktls` 在握手后
把引擎连接的记录层移入 Linux。`Ktls::Hardware` 只卸载支持 TLS 卸载的网卡自己完成的部分（按接口检查，
由内核计数器确认），在其他主机上什么都不改变；`Ktls::Software` / `SoftwareTx` 使用内核的软件记录层，
在当前 CPU 上比本 crate 的慢，`sendfile` 也不例外（docs/BENCHMARKS.zh-CN.md，“内核 TLS（kTLS）评估”）。
默认关闭。

## 内部结构

- `proto`：记录层，TLS 1.3 / 1.2 客户端与服务端状态机（它们按顺序产出动作：按加密级别的握手消息、
  密钥切换、告警），密钥调度与 TLS 1.2 PRF，会话与票据。
- `quic`（`#[doc(hidden)]`，内部）：同一套 TLS 1.3 状态机，不经记录层，供 QUIC 实现使用：按加密级别
  输入输出握手字节、各级别的流量密钥、quic_transport_parameters 扩展、强制 ALPN、无兼容模式、RFC 9001
  密钥派生辅助函数。`akio-quic` 的自研 QUIC（DEV-PLAN 第 D 波）驱动它。
- `stream`（`#[doc(hidden)]`）：基于 `Read + Write` 的阻塞 TLS 流，供测试、示例与互通驱动程序
  （`examples/tls-interop.rs`）使用。
- `unstable` feature 为空（过去用于暴露 rustls）；`fuzzing` 启用 fuzz 入口。

## 测试

- RFC 8448 跟踪向量（简单 1-RTT、恢复绑定值、HelloRetryRequest）：密钥调度、transcript、Finished 值与
  受保护记录逐字节一致；RFC 9001 附录 A 的密钥派生向量。
- 覆盖所有套件、组、证书类型与版本的内存握手，会话恢复、客户端认证、SNI / ALPN、KeyUpdate、低至单字节
  的分片、close_notify、降级检测、篡改、意外记录与垃圾数据；record_size_limit（两个版本、双向低至 64 字节的
  限制、超限记录、遵循票据限制的早期数据）、证书压缩（服务端与客户端证书、任一方关闭、格式错误的消息）与
  OCSP stapling（两个版本、SNI、会话恢复），单独及组合测试；吊销检查：每种策略对正常、委托、吊销、未知、过期、
  伪造、针对其他证书、内容不透明与缺失的装订响应（两个版本），服务器与客户端证书链的 CRL，客户端的 OCSP
  响应（正常、委托、吊销、未知、针对其他证书、缺失；TLS 1.2 下各策略）；P-521 与 RSA-PSS 密钥
  （`id-RSASSA-PSS`）的服务端与客户端证书、secp521r1。
- 互通（`tools/interop/tls/run.sh`）：与 OpenSSL `s_server` / `s_client` 及 Go `crypto/tls` 双向互通，
  覆盖所有套件、组、密钥类型、客户端认证、会话恢复、HRR、ALPN、KeyUpdate、early data 与 OCSP stapling（由
  `s_client` 验证），secp521r1、P-521 与 RSA-PSS 密钥证书（`rsa_pss_pss_sha256`，TLS 1.3 与 1.2；仅 OpenSSL，
  Go 不支持 RSA-PSS 密钥）用于服务端与客户端，客户端 OCSP 请求对 OpenSSL（它忽略该请求）以及本库客户端与服务端
  之间经 TCP（正常、吊销、缺失），本库客户端校验 `s_server -status_file` 的装订响应（正常、吊销、缺失；软/硬失败）并检查
  OpenSSL 生成的 CRL，与以 zlib、brotli、zstd 构建的 OpenSSL 3.2+ 测试这三种证书压缩（Debian 的有 zlib 与 zstd；
  `tools/interop/tls/certcomp.Dockerfile` 构建三者俱全的版本），安装了 GnuTLS 时测试
  record_size_limit 与 OCSP，另有 curl 对
  akio-http（HTTP/1.1 与 HTTP/2）；需要 OpenSSL 3.0 或更新版本（early data 用例以不带 `-www` 的
  `s_server` 运行，因为 3.0 拒绝 `-www` 与 `-early_data` 同用；客户端发送后关闭连接，再检查 `s_server`
  的日志）；与 grpc-go 的 TLS 上 gRPC（`tools/interop/grpc/run.sh`）；`akio` crate 的
  TLS 测试中使用 rustls 客户端。
- 以 tlsfuzzer 测试服务端（`tools/interop/tls/tlsfuzzer.sh`，Docker）：适用的 36 个脚本（不含 CBC、RSA 密钥交换、
  FFDHE、外部 PSK 等），包括 record_size_limit 与证书压缩（服务端与客户端证书），共 1,096 个探测；已知失败（在
  其余适用的脚本中使用 CBC 套件、RSA 密钥交换或 TLS 1.0/1.1 的探测，以及少数其他探测）及其原因记录在脚本中。
- Fuzz：`fuzz/` 中的 `tls_server`、`tls_client`、`tls_record`；`fuzzing::tests` 在 stable 上回放其语料。
