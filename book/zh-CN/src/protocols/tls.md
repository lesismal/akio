# TLS

`only::tls`（即 `only-tls` crate）是连接之下的一个 **transport 层**，带有自研的 TLS 1.3 与 1.2
实现：依据 RFC、基于 `only-crypto` 与 `only-x509` 编写，sans-io，`#![forbid(unsafe_code)]`，
无第三方依赖。包装任意 acceptor 之后，它的 handler 看到的都是明文：
`on_data` 收到解密后的字节，`Conn::send*` 自动加密。

## 服务端

```rust,ignore
{{#include ../../../../crates/only/examples/guide-tls.rs:server}}
```

## 客户端

```rust,ignore
{{#include ../../../../crates/only/examples/guide-tls.rs:client}}
```

`Tls::client(config, server_name, acceptor)` 以 `server_name` 校验服务端证书并把它作为 SNI
发送。名字不是合法的 DNS 名或 IP 地址时返回错误。

两者都可以用 `cargo run -p only --example guide-tls` 运行。

## 工作方式

- 握手在连接所属的 I/O 线程上进行，与其他连接交错执行，从不阻塞。
- 握手完成前发送的数据（例如在 `on_open` 里发送的）会被暂存，握手一完成就刷出。
- `close_after_send()` 在排队的数据之后发送 `close_notify`。
- 握手失败或收到坏记录时，先刷出 alert 再关闭连接；握手阶段的失败
  （`only_tls_handshake_failures_total`）和之后的失败（`only_transport_errors_total`）分别计数。
- 记录按不超过一个 TLS 记录的大小分段封装，所以大块发送没有问题。
- 连接表中显示 `transport: "tls"`。

## 协商结果

`tls_info(&conn)` 返回 `TlsInfo`，包含 `handshaking`、`alpn`、`server_name`（SNI，仅服务端）
和 `version`；非 TLS 连接返回 `None`。

## 协议支持

| | TLS 1.3（RFC 8446） | TLS 1.2（RFC 5246） |
|---|---|---|
| 密钥交换 | X25519、secp256r1、secp384r1；HelloRetryRequest | 同样这些组上的 ECDHE（无 RSA 密钥交换、无静态 DH） |
| 密码套件 | AES-128-GCM-SHA256、AES-256-GCM-SHA384、CHACHA20-POLY1305-SHA256 | ECDHE-ECDSA / ECDHE-RSA 搭配 AES-128/256-GCM 与 CHACHA20-POLY1305（无 CBC） |
| 证书 | ECDSA P-256/P-384、Ed25519、RSA（PSS 签名） | 同上，RSA 也可用 PKCS#1 v1.5 |
| 会话恢复 | 票据 + PSK（`psk_dhe_ke`）：`.session_tickets(true)` 为无状态票据，会话缓存为一次性缓存票据 | 会话 ID（缓存）与 RFC 5077 票据 |
| 其他 | KeyUpdate（应答，并在达到 AES-GCM 记录上限前主动发送）、客户端证书、中间设备兼容模式；客户端提供的 0-RTT 被拒绝并跳过 | 扩展主密钥（RFC 7627）、重协商指示（RFC 5746），拒绝重协商 |

两者共有：SNI、ALPN、close_notify、16 KiB 记录、TLS 1.3 内层内容类型与填充、降级哨兵、严格的状态机
（意外消息、空记录或交错记录、跨密钥切换的握手数据都是致命错误）。证书由 `only-x509` 验证：链接到
根证书、有效期、扩展密钥用途、DNS 名（RFC 6125 通配符）与 IP 地址。客户端优先 AES-128-GCM，其次
AES-256-GCM，然后 ChaCha20-Poly1305；服务端按自己的偏好选择，并优先使用客户端已发送的 key share
（合适时不发 HelloRetryRequest）。

一致性：RFC 8448 跟踪作为单元测试，tlsfuzzer（`tools/interop/tls/tlsfuzzer.sh`），以及与 OpenSSL、Go `crypto/tls`、curl 和 rustls 的互通矩阵
（`tools/interop/tls/run.sh`、`tools/interop/grpc/run.sh`、`only` crate 的 TLS 测试）。与 rustls 0.23 +
ring 相比的速度（`tls-bench`，带 VAES 的 x86_64）：X25519 完整握手持平，AES-128-GCM 记录在 1 KiB 与 16 KiB
时均约为 1.6 倍。

## 配置

配置使用 only 自己的类型；协议内部细节不属于 API。`Certificate::from_pem` / `from_der`、`PrivateKey::from_pem` /
`from_der` / `from_pkcs8_der` 与 `RootCerts` 负责加载证书材料。

| 需求 | 服务端：`ServerConfig::builder(chain, key)` | 客户端：`ClientConfig::builder()` |
|---|---|---|
| 证书 | 证书链与私钥；按 SNI 名称用 `.sni_cert(name, chain, key)` | `.client_cert(chain, key)` |
| 信任 | `.client_auth_required(roots)` / `.client_auth_optional(roots)` | `.roots(roots)` |
| ALPN（`h2`、`http/1.1`、自定义） | `.alpn(["h2", "http/1.1"])` | `.alpn([..])` |
| 会话恢复 | `.session_cache(entries)`、`.session_tickets(true)` | `.resumption(false)` 关闭 |
| 协议版本 | `.tls13_only(true)` | `.tls13_only(true)` |
| SNI | | `.sni(false)` 不再发送 |
| 仅限测试 | | `.insecure_skip_verify()` |

`.build()` 检查证书与私钥（包括私钥是否属于叶子证书），返回配置或 `only::tls::Error`；配置克隆开销
很小。过去用来暴露被封装的 rustls 的 `unstable` cargo feature 现在为空（保留它，以便引用它的构建
继续可用）。

## 与其他 crate 配合

- only-http：`Tls::server(cfg, serve(app))`。设置 `alpn_protocols = [h2, http/1.1]` 后，同一个
  listener 会为协商了 `h2` 的客户端提供 HTTP/2。
- only-ws 客户端：`wss://` 使用 `DialOptions::tls`。
- only-http 客户端：`Client::with_tls(cfg)`、`H2Client::dial(.., Some((cfg, name)), ..)`。
- QUIC 与 HTTP/3 在 QUIC 内部使用 TLS 1.3：见 `only_quic::server_config` 与
  `server_config_from(&tls_config)`。`only-quic` 的自研 QUIC（DEV-PLAN 第 D 波）用同一份
  `only::tls` 配置驱动 `only-tls` 内不经记录层的 TLS 1.3 内核（内部 API）。

## 内核 TLS

不使用：内核 TLS 卸载（握手后把记录密钥交给 Linux，使 `sendfile` 在 TLS 下可用）已经测量过，比 only-tls
自己的记录层慢，从 1 KiB 响应的 0.83 倍到 256 KiB 的 0.40 倍，10 MB 文件用 `sendfile` 对比 `pread`
加加密为 0.48 倍（[测量结果](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md#内核-tlsktls评估)）。卸载代码保留在实验性的
`experimental-ktls` cargo feature 之后（只用于阻塞测试流与基准，没有接入 `Tls`，不在 semver 承诺之内），
以便重新测量，例如在带 TLS 卸载的网卡上。

## 尚未完成

发送或接受 TLS 1.3 early data（0-RTT）；record_size_limit、证书压缩、OCSP stapling
（忽略 status_request）；RSA-PSS 密钥（`rsa_pss_pss_*`）；P-521；系统根证书（请自行加载到
`RootCerts`）。

## 编写自己的 transport

`only_core::Transport` 就是 TLS 实现的 trait：`recv(cipher, plain, out)`、
`seal(plain, out)`、`shutdown(out)`，外加 `name` 和 `handshaking`。从 `Acceptor::transport`
返回一个实现，就能在连接之下叠加任意字节流变换。所有调用都在连接的写锁下按线路顺序进行，
不能阻塞。
