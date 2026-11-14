# only-tls

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 TLS 1.3 与 1.2，由本 crate 依据 RFC、基于
[`only-crypto`](../only-crypto) 与 [`only-x509`](../only-x509) 实现：sans-io、安全 Rust
（`#![forbid(unsafe_code)]`）、无第三方依赖。它在 API 不变的前提下替代了 rustls 与 ring（DEV-PLAN
第 C 波）。

用 `Tls::server`（或供 `Engine::dial` 使用的 `Tls::client`）包装任意 acceptor，其 handler 看到的就是
明文；握手在连接所属的 I/O 线程上进行，从不阻塞。用 `ServerConfig::builder(chain, key)`（SNI 证书、
ALPN、客户端认证、会话缓存与票据、`tls13_only`）与 `ClientConfig::builder()`（根证书、ALPN、客户端
证书、SNI、会话恢复、仅供测试的 `insecure_skip_verify`）配置；`tls_info` 读取协商结果。

```rust,no_run
use only_tls::{Certificate, PrivateKey, ServerConfig, Tls};
# struct Echo; impl only_core::Handler for Echo { fn on_data(&mut self, _: &only_core::Conn<Self>, _: &[u8]) {} }
let chain = Certificate::from_pem(&std::fs::read("cert.pem").unwrap()).unwrap();
let key = PrivateKey::from_pem(&std::fs::read("key.pem").unwrap()).unwrap();
let cfg = ServerConfig::builder(chain, key).alpn(["h2", "http/1.1"]).build().unwrap();
let acceptor = Tls::server(cfg, only_core::fn_acceptor(|_c: &only_core::Conn<Echo>| Echo));
# let _ = acceptor;
```

## 协议

- **TLS 1.3**（RFC 8446）：双方完整握手、HelloRetryRequest（回显 cookie）、密钥调度、KeyUpdate
  （应答；在达到 AES-GCM 记录上限前主动发送）、NewSessionTicket 与使用 `psk_dhe_ke` 的 PSK 恢复
  （无状态票据，或来自会话缓存的一次性票据）、客户端证书（CertificateRequest）、中间设备兼容模式；
  拒绝 0-RTT（并按 RFC 8446 4.2.10 跳过）。
- **TLS 1.2**（RFC 5246、RFC 7627 扩展主密钥、RFC 5746 重协商指示）：仅 ECDHE 搭配 ECDSA、Ed25519
  或 RSA 证书与 AEAD 套件（无 CBC、无 RSA 密钥交换、无静态 DH），会话 ID 与 RFC 5077 票据，客户端
  证书；以 `no_renegotiation` 警告拒绝重协商。
- 套件 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`、
  `ECDHE-{ECDSA,RSA}-AES{128,256}-GCM` 与 `ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305`；组 X25519、
  secp256r1、secp384r1；签名方案 ECDSA P-256/P-384、Ed25519、RSA-PSS（rsae）、RSA PKCS#1 v1.5
  （TLS 1.2 与证书）。
- 记录层：16 KiB 分片、TLS 1.3 内层内容类型与填充、带降级哨兵的版本协商、严格的状态机、握手消息跨
  记录重组且绝不跨密钥切换、告警与 close_notify、常量时间的 Finished / 绑定值校验。
- 证书由 `only-x509` 验证（链、有效期、EKU、DNS 名与 IP 地址）。

未实现：发送或接受 0-RTT、record_size_limit、证书压缩、OCSP stapling（忽略 status_request）、
RSA-PSS 密钥、P-521、kTLS。

## 内部结构

- `proto`：记录层，TLS 1.3 / 1.2 客户端与服务端状态机（它们按顺序产出动作：按加密级别的握手消息、
  密钥切换、告警），密钥调度与 TLS 1.2 PRF，会话与票据。
- `quic`（`#[doc(hidden)]`，内部）：同一套 TLS 1.3 状态机，不经记录层，供 QUIC 实现使用：按加密级别
  输入输出握手字节、各级别的流量密钥、quic_transport_parameters 扩展、强制 ALPN、无兼容模式、RFC 9001
  密钥派生辅助函数。DEV-PLAN 第 D 波的自研 QUIC 将驱动它；在那之前 only-quic 仍使用 quinn-proto（及其
  rustls），配置由本 crate 的配置构建。
- `stream`（`#[doc(hidden)]`）：基于 `Read + Write` 的阻塞 TLS 流，供测试、示例与互通驱动程序
  （`examples/tls-interop.rs`）使用。
- `unstable` feature 为空（过去用于暴露 rustls）；`fuzzing` 启用 fuzz 入口。

## 测试

- RFC 8448 跟踪向量（简单 1-RTT、恢复绑定值、HelloRetryRequest）：密钥调度、transcript、Finished 值与
  受保护记录逐字节一致；RFC 9001 附录 A 的密钥派生向量。
- 覆盖所有套件、组、证书类型与版本的内存握手，会话恢复、客户端认证、SNI / ALPN、KeyUpdate、低至单字节
  的分片、close_notify、降级检测、篡改、意外记录与垃圾数据。
- 互通（`tools/interop/tls/run.sh`）：与 OpenSSL `s_server` / `s_client` 及 Go `crypto/tls` 双向互通，
  覆盖所有套件、组、密钥类型、客户端认证、会话恢复、HRR、ALPN 与 KeyUpdate，另有 curl 对 only-http
  （HTTP/1.1 与 HTTP/2）；与 grpc-go 的 TLS 上 gRPC（`tools/interop/grpc/run.sh`）；`only` crate 的
  TLS 测试中使用 rustls 客户端。
- 以 tlsfuzzer 测试服务端（`tools/interop/tls/tlsfuzzer.sh`，Docker）：适用的 33 个脚本（不含 CBC、RSA 密钥交换、
  FFDHE、外部 PSK 等），985 个探测，5 个已知失败及其原因记录在脚本中。
- Fuzz：`fuzz/` 中的 `tls_server`、`tls_client`、`tls_record`；`fuzzing::tests` 在 stable 上回放其语料。
