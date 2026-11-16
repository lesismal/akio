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

`tls_info(&conn)` 返回 `TlsInfo`，包含 `handshaking`、`alpn`、`server_name`（SNI，仅服务端）、
`version`、`early_data` 与 `early_data_len`（见[早期数据](#早期数据0-rtt)）以及 `ocsp_response`（客户端，
见 [OCSP stapling](#ocsp-stapling)）；非 TLS 连接返回 `None`。

## 协议支持

| | TLS 1.3（RFC 8446） | TLS 1.2（RFC 5246） |
|---|---|---|
| 密钥交换 | X25519、secp256r1、secp384r1；HelloRetryRequest | 同样这些组上的 ECDHE（无 RSA 密钥交换、无静态 DH） |
| 密码套件 | AES-128-GCM-SHA256、AES-256-GCM-SHA384、CHACHA20-POLY1305-SHA256 | ECDHE-ECDSA / ECDHE-RSA 搭配 AES-128/256-GCM 与 CHACHA20-POLY1305（无 CBC） |
| 证书 | ECDSA P-256/P-384、Ed25519、RSA（PSS 签名） | 同上，RSA 也可用 PKCS#1 v1.5 |
| 会话恢复 | 票据 + PSK（`psk_dhe_ke`）：`.session_tickets(true)` 为无状态票据，会话缓存为一次性缓存票据 | 会话 ID（缓存）与 RFC 5077 票据 |
| 其他 | KeyUpdate（应答，并在达到 AES-GCM 记录上限前主动发送）、客户端证书、中间设备兼容模式；双方开启时支持早期数据（0-RTT），否则拒绝并跳过；证书压缩（RFC 8879，zlib） | 扩展主密钥（RFC 7627）、重协商指示（RFC 5746），拒绝重协商 |
| record_size_limit（RFC 8449） | 支持 | 支持 |

两者共有：SNI、ALPN、close_notify、16 KiB 记录（对端设有 record_size_limit 时更小）、OCSP stapling、
TLS 1.3 内层内容类型与填充、降级哨兵、严格的状态机
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
`from_der` / `from_pkcs8_der` 与 `RootCerts` 负责加载证书材料。`RootCerts::system()` 是操作系统的
信任库，每个进程读取一次：设置了 `SSL_CERT_FILE` / `SSL_CERT_DIR` 时用它们，macOS 上用系统钥匙串（通过
`/usr/bin/security` 导出；不应用信任设置），其他 Unix 上用发行版的 CA 证书包或证书目录。未提供
`ClientConfig` 时，HTTP 和 WebSocket 客户端使用它（ADR-010）。

| 需求 | 服务端：`ServerConfig::builder(chain, key)` | 客户端：`ClientConfig::builder()` |
|---|---|---|
| 证书 | 证书链与私钥；按 SNI 名称用 `.sni_cert(name, chain, key)` | `.client_cert(chain, key)` |
| 信任 | `.client_auth_required(roots)` / `.client_auth_optional(roots)` | `.roots(roots)` |
| ALPN（`h2`、`http/1.1`、自定义） | `.alpn(["h2", "http/1.1"])` | `.alpn([..])` |
| 会话恢复 | `.session_cache(entries)`、`.session_tickets(true)` | `.resumption(false)` 关闭 |
| 协议版本 | `.tls13_only(true)` | `.tls13_only(true)` |
| SNI | | `.sni(false)` 不再发送 |
| 早期数据（0-RTT） | `.early_data(max_bytes)` | `.early_data(true)` |
| 记录大小限制（RFC 8449） | `.record_size_limit(bytes)` | `.record_size_limit(bytes)` |
| 握手超时（默认 10 s：超时仍在握手的连接以 `TimedOut` 关闭，并计入 `only_tls_handshake_failures_total`） | `.handshake_timeout(Some(d))`，`None` 为不限 | `.handshake_timeout(Some(d))` |
| 证书压缩 | 默认开启；`.certificate_compression(false)` 关闭 | `.certificate_compression(true)` 开启 |
| OCSP stapling | `.ocsp_response(der)`、`.sni_ocsp_response(name, der)` | `.ocsp_stapling(true)` |
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

## 早期数据（0-RTT）

默认关闭，需要双方都开启。服务端设置 `.early_data(max_bytes)`（并开启会话恢复）后，签发的票据允许
这么多早期数据；客户端设置 `.early_data(true)` 并用这样的票据恢复会话时，应用在握手完成前写入的数据
紧跟在 ClientHello 之后发出，省掉一个往返。服务端在握手完成前就读取它，`on_data` 能早一个往返看到请求。

- 服务端只针对票据的第一个 PSK、密码套件、ALPN 协议与 SNI 名接受早期数据，HelloRetryRequest 之后
  绝不接受，也不接受超过允许量的数据。
- 服务端拒绝时（配置不同、HelloRetryRequest、疑似重放），跳过早期记录；客户端在握手后重发同样的
  字节，应用两种情况下看到的字节流相同。
- `TlsInfo::early_data` 给出 `NotAttempted`、`Pending`（客户端，收到答复前）、`Accepted` 或
  `Rejected`；`TlsInfo::early_data_len` 是流开头作为早期数据发送的字节数。only-http 给落在这个范围
  内的 HTTP/1.1 请求加上 `Early-Data: 1`（RFC 8470；HTTP/2 则是以早期数据开始的连接上的每个请求）。

开启早期数据时**防重放**始终生效：仅当客户端看到的票据年龄与服务端的相差不超过 10 秒时才接受
（RFC 8446 第 8.3 节），并把每个被接受的 ClientHello 的 PSK binder 记录 30 秒（第 8.2 节：窗口的两倍，再加一个窗口容许共享存储的服务端之间时钟有偏差）；见过的
ClientHello 其早期数据被拒绝，按普通会话恢复继续。每个 `ServerConfig` 最多记录 100,000 个 ClientHello，
满了就拒绝早期数据。

**共享票据的多台服务端**（[ADR-013](https://github.com/lesismal/only/blob/main/docs/adr/013-shared-anti-replay-and-compatible-vn.zh-CN.md)）。
多个进程或多台机器用同一个 `.session_ticket_key(key)`（48 字节保密随机数：16 字节密钥名加 32 字节密钥；
轮换即构建新配置）构建时，可接受彼此签发的票据。此时它们还需要共用一份重放记录，否则发往一台服务端的首个
飞行被截获后可重放到另一台：`.anti_replay_store(store)` 接受任意 `Arc<dyn AntiReplayStore>`，其唯一方法
把 ClientHello 的 binder 记录一段时间，并告知它是否是新的。它在握手中于 I/O 线程上调用，且只针对本会接受
早期数据的 ClientHello，因此要保持简短并设超时。出错时**失败即关闭**：拒绝早期数据，客户端在握手后重发。
默认实现是 `MemoryAntiReplay`（即上文每个配置一份的记录）。用 Redis 时，每次调用一条原子的
`SET key 1 NX PX ttl`：

```rust,ignore
use std::{io, sync::Arc, time::Duration};
use only_tls::{AntiReplayStore, ServerConfig};

struct RedisReplay { pool: MyRedisPool } // 任意设了较短超时的客户端

impl AntiReplayStore for RedisReplay {
    fn check_and_insert(&self, binder: &[u8], ttl: Duration) -> io::Result<bool> {
        let key = format!("only:0rtt:{}", hex(binder));
        // 设置成功（首次出现）返回 "OK"，键已存在（重放）返回 nil。
        let reply = self.pool.set_nx_px(&key, "1", ttl.as_millis() as u64)
            .map_err(io::Error::other)?; // 超时同样如此：拒绝早期数据
        Ok(reply.is_some())
    }
}

let cfg = ServerConfig::builder(chain, key)
    .session_ticket_key(ticket_key)          // 每台服务端相同
    .early_data(16384)
    .anti_replay_store(Arc::new(RedisReplay { pool }))
    .build()?;
```

存储必须是原子的（先读后写会放过并发的重放）；跨区域且有复制延迟时，每个区域使用自己的存储与票据密钥。
QUIC 服务端通过 `only_quic::server_config_from(&cfg)` 获得这两项。

**安全权衡。** 早期数据没有前向保密，且可被重放：上述记录能挡住窗口内对同一服务端（或共享其存储的服务端）
的重放，挡不住客户端被诱使再次发送的请求。只为可安全重复的请求（无副作用的读取）
开启它，其余请求回 `425 Too Early`：

```rust,ignore
.post("/pay", |ctx: &mut Context| {
    if ctx.header("early-data") == Some("1") {
        return ctx.text(425, "too early"); // 客户端会在握手后重试
    }
    // ...
})
```

## 记录大小限制、证书压缩、OCSP stapling

决定记录在 [ADR-008](https://github.com/lesismal/only/blob/main/docs/adr/008-tls-extensions.zh-CN.md)。

**record_size_limit**（RFC 8449，TLS 1.3 与 1.2）。任一方的 `.record_size_limit(n)` 设定自己接受的最大
记录：按 RFC 的口径为 64 到 16385 字节（TLS 1.3 中该值包含 1 字节内容类型；TLS 1.2 上限为 16384），默认
16385。客户端总是发送自己的值，只要客户端发了，服务端就回以自己的值；此后双方写出的受保护记录按对方的
限制切分，收到超过自己限制的记录则报 `record_overflow`。明文的握手记录不受限制，早期数据遵循签发票据的
那条连接上的限制。不支持该扩展的对端（OpenSSL、Go）既不会得到也不会被施加限制。QUIC 中不使用（没有记录）。

```rust,ignore
// 无法缓存 16 KiB 记录的小设备。
let cfg = ClientConfig::builder().roots(roots).record_size_limit(1024).build()?;
```

**证书压缩**（RFC 8879，TLS 1.3）。服务端默认开启：对提供 zlib 的客户端，在压缩后更小时发送压缩的证书链
（每条链只压缩一次并复用，握手没有额外开销），其 CertificateRequest 也为客户端证书提供它。客户端默认关闭：
解压收到的证书链约需 1–2 µs，约为内存中完整握手的 1%，换来几十到几百字节的节省；更在意线路字节数时用
`.certificate_compression(true)` 开启。只有 zlib（由自研的 `only-deflate` 提供；没有自研的 brotli 或 zstd）。
收到的证书最多解压到 128 KiB，长度必须与声明的完全一致。

### OCSP stapling

服务端为请求它的客户端装订一个 DER 格式的 OCSP 响应（TLS 1.3：放在叶证书的 CertificateEntry 中；TLS 1.2：
CertificateStatus 消息；会话恢复时不发送）：

```rust,ignore
let ocsp = std::fs::read("leaf.ocsp.der")?; // 从 CA 的响应者获取，由你负责刷新
let cfg = ServerConfig::builder(chain, key).ocsp_response(ocsp).build()?;
```

`.build()` 只检查它是否像一个成功的 `OCSPResponse`。响应会过期（通常几天内）：在那之前获取新的响应并构建
新的配置。

客户端用 `.ocsp_stapling(true)` 请求响应，`tls_info(&conn).ocsp_response` 保存收到的 DER 字节。**它们未经
验证**：`only-x509` 尚不检查 OCSP（响应者签名、有效期、证书 ID），关心吊销状态的应用必须自己验证该响应。

## 内核 TLS

不使用：内核 TLS 卸载（握手后把记录密钥交给 Linux，使 `sendfile` 在 TLS 下可用）已经测量过，比 only-tls
自己的记录层慢，从 1 KiB 响应的 0.83 倍到 256 KiB 的 0.40 倍，10 MB 文件用 `sendfile` 对比 `pread`
加加密为 0.48 倍（[测量结果](https://github.com/lesismal/only/blob/main/docs/BENCHMARKS.zh-CN.md#内核-tlsktls评估)）。卸载代码保留在实验性的
`experimental-ktls` cargo feature 之后（只用于阻塞测试流与基准，没有接入 `Tls`，不在 semver 承诺之内），
以便重新测量，例如在带 TLS 卸载的网卡上。

## 尚未完成

OCSP 响应验证、brotli/zstd 证书压缩、`status_request_v2`；RSA-PSS 密钥（`rsa_pss_pss_*`）；P-521；
Windows 证书库与 macOS 信任设置。

## 编写自己的 transport

`only_core::Transport` 就是 TLS 实现的 trait：`recv(cipher, plain, out)`、
`seal(plain, out)`、`shutdown(out)`，外加 `name` 和 `handshaking`。从 `Acceptor::transport`
返回一个实现，就能在连接之下叠加任意字节流变换。所有调用都在连接的写锁下按线路顺序进行，
不能阻塞。
