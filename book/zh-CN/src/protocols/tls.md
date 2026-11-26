# TLS

`akio::tls`（即 `akio-tls` crate）是连接之下的一个 **transport 层**，带有自研的 TLS 1.3 与 1.2
实现：依据 RFC、基于 `akio-crypto` 与 `akio-x509` 编写，sans-io，`#![forbid(unsafe_code)]`，
无第三方依赖。包装任意 acceptor 之后，它的 handler 看到的都是明文：
`on_data` 收到解密后的字节，`Conn::send*` 自动加密。

## 服务端

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-tls.rs:server}}
```

## 客户端

```rust,ignore
{{#include ../../../../crates/akio/examples/guide-tls.rs:client}}
```

`Tls::client(config, server_name, acceptor)` 以 `server_name` 校验服务端证书并把它作为 SNI
发送。名字不是合法的 DNS 名或 IP 地址时返回错误。

两者都可以用 `cargo run -p akio --example guide-tls` 运行。

## 工作方式

- 握手在连接所属的 I/O 线程上进行，与其他连接交错执行，从不阻塞。
- 握手完成前发送的数据（例如在 `on_open` 里发送的）会被暂存，握手一完成就刷出。
- `close_after_send()` 在排队的数据之后发送 `close_notify`。
- 握手失败或收到坏记录时，先刷出 alert 再关闭连接；握手阶段的失败
  （`akio_tls_handshake_failures_total`）和之后的失败（`akio_transport_errors_total`）分别计数。
- 记录按不超过一个 TLS 记录的大小分段封装，所以大块发送没有问题。
- 连接表中显示 `transport: "tls"`。

## 协商结果

`tls_info(&conn)` 返回 `TlsInfo`，包含 `handshaking`、`alpn`、`server_name`（SNI，仅服务端）、
`version`、`early_data` 与 `early_data_len`（见[早期数据](#早期数据0-rtt)）以及 `ocsp_response`（客户端：
服务端的响应，见 [OCSP stapling](#ocsp-stapling)；服务端：TLS 1.3 客户端的响应，见[吊销检查](#吊销检查)）；
非 TLS 连接返回 `None`。

## 协议支持

| | TLS 1.3（RFC 8446） | TLS 1.2（RFC 5246） |
|---|---|---|
| 密钥交换 | X25519、secp256r1、secp384r1、x448、secp521r1（排在最后）；HelloRetryRequest | 同样这些组上的 ECDHE（无 RSA 密钥交换、无静态 DH） |
| 密码套件 | AES-128-GCM-SHA256、AES-256-GCM-SHA384、CHACHA20-POLY1305-SHA256 | ECDHE-ECDSA / ECDHE-RSA 搭配 AES-128/256-GCM 与 CHACHA20-POLY1305（无 CBC） |
| 证书 | ECDSA P-256/P-384/P-521、Ed25519、Ed448、RSA（PSS 签名：`rsaEncryption` 密钥用 `rsa_pss_rsae_*`，`id-RSASSA-PSS` 密钥用 `rsa_pss_pss_*`） | 同上，RSA（`rsaEncryption` 密钥）也可用 PKCS#1 v1.5 |
| 会话恢复 | 票据 + PSK（`psk_dhe_ke`）：`.session_tickets(true)` 为无状态票据，会话缓存为一次性缓存票据 | 会话 ID（缓存）与 RFC 5077 票据 |
| 其他 | KeyUpdate（应答，并在达到 AES-GCM 记录上限前主动发送）、客户端证书、中间设备兼容模式；双方开启时支持早期数据（0-RTT），否则拒绝并跳过；证书压缩（RFC 8879：zlib、brotli、zstd） | 扩展主密钥（RFC 7627）、重协商指示（RFC 5746），拒绝重协商 |
| record_size_limit（RFC 8449） | 支持 | 支持 |

两者共有：SNI、ALPN、close_notify、16 KiB 记录（对端设有 record_size_limit 时更小）、OCSP stapling、
TLS 1.3 内层内容类型与填充、降级哨兵、严格的状态机
（意外消息、空记录或交错记录、跨密钥切换的握手数据都是致命错误）。证书由 `akio-x509` 验证：链接到
根证书、有效期、扩展密钥用途、DNS 名（RFC 6125 通配符）与 IP 地址。客户端优先 AES-128-GCM，其次
AES-256-GCM，然后 ChaCha20-Poly1305；服务端按自己的偏好选择，并优先使用客户端已发送的 key share
（合适时不发 HelloRetryRequest）。

一致性：RFC 8448 跟踪作为单元测试，tlsfuzzer（`tools/interop/tls/tlsfuzzer.sh`），以及与 OpenSSL、Go `crypto/tls`、curl 和 rustls 的互通矩阵
（`tools/interop/tls/run.sh`、`tools/interop/grpc/run.sh`、`akio` crate 的 TLS 测试）。与 rustls 0.23 +
ring 相比的速度（`tls-bench`，带 VAES 的 x86_64）：X25519 与 secp256r1（ECDSA P-256 证书）完整握手均约为 1.1 倍，AES-128-GCM 记录在 1 KiB 与 16 KiB
时均约为 1.6 倍，ChaCha20-Poly1305 记录在 1 KiB 时约 1.2 倍、16 KiB 时约 1.5 倍。ChaCha20-Poly1305 AEAD 本身在 64 字节消息上与 ring 相当（加密 1.11 倍，解密 0.98 倍；见 docs/BENCHMARKS.zh-CN.md）。

## 配置

配置使用 akio 自己的类型；协议内部细节不属于 API。`Certificate::from_pem` / `from_der`、`PrivateKey::from_pem` /
`from_der` / `from_pkcs8_der` 与 `RootCerts` 负责加载证书材料。`RootCerts::system()` 是操作系统的
信任库，每个进程读取一次：设置了 `SSL_CERT_FILE` / `SSL_CERT_DIR` 时用它们，macOS 上用钥匙串（通过
`/usr/bin/security` 导出，并应用用户、管理员与系统的信任设置：去掉被标记为不信任的 CA，加入在 System
或登录钥匙串中被标记为信任的 CA，ADR-059），其他 Unix 上用发行版的 CA 证书包或证书目录。未提供
`ClientConfig` 时，HTTP 和 WebSocket 客户端使用它（ADR-010）。

| 需求 | 服务端：`ServerConfig::builder(chain, key)` | 客户端：`ClientConfig::builder()` |
|---|---|---|
| 证书 | 证书链与私钥；按 SNI 名称用 `.sni_cert(name, chain, key)`；按握手用 `.cert_resolver(r)`（见下文） | `.client_cert(chain, key)` |
| 信任 | `.client_auth_required(roots)` / `.client_auth_optional(roots)` | `.roots(roots)` |
| ALPN（`h2`、`http/1.1`、自定义） | `.alpn(["h2", "http/1.1"])` | `.alpn([..])` |
| 会话恢复 | `.session_cache(entries)`、`.session_tickets(true)` | `.resumption(false)` 关闭 |
| 协议版本 | `.tls13_only(true)` | `.tls13_only(true)` |
| SNI | | `.sni(false)` 不再发送 |
| 早期数据（0-RTT） | `.early_data(max_bytes)` | `.early_data(true)` |
| 记录大小限制（RFC 8449） | `.record_size_limit(bytes)` | `.record_size_limit(bytes)` |
| 握手超时（默认 10 s：超时仍在握手的连接以 `TimedOut` 关闭，并计入 `akio_tls_handshake_failures_total`） | `.handshake_timeout(Some(d))`，`None` 为不限 | `.handshake_timeout(Some(d))` |
| 证书压缩 | 默认开启；`.certificate_compression(false)` 关闭 | `.certificate_compression(true)` 开启 |
| OCSP stapling | `.ocsp_response(der)`、`.sni_ocsp_response(name, der)` | `.ocsp_stapling(true)`；`.ocsp_policy(RevocationPolicy::HardFail)` 校验它 |
| CRL（[吊销检查](#吊销检查)） | `.client_crls(crls, policy)` | `.crls(crls, policy)` |
| 客户端的 OCSP 响应（TLS 1.3） | `.client_ocsp_policy(policy)` 请求并校验 | `.client_cert_ocsp_response(der)` 在被请求时发送 |
| 固定服务端证书（按其 SHA-256，代替根证书、名称和有效期检查；自签名的 hub） | | `.pin_sha256(vec![sha256_of_leaf_der])` |
| 仅限测试 | | `.insecure_skip_verify()` |

`.build()` 检查证书与私钥（包括私钥是否属于叶子证书），返回配置或 `akio::tls::Error`；配置克隆开销
很小。过去用来暴露被封装的 rustls 的 `unstable` cargo feature 现在为空（保留它，以便引用它的构建
继续可用）。

## 与其他 crate 配合

- akio-http：`Tls::server(cfg, serve(app))`。设置 `alpn_protocols = [h2, http/1.1]` 后，同一个
  listener 会为协商了 `h2` 的客户端提供 HTTP/2。
- akio-ws 客户端：`wss://` 使用 `DialOptions::tls`。
- akio-http 客户端：`Client::with_tls(cfg)`、`H2Client::dial(.., Some((cfg, name)), ..)`。
- QUIC 与 HTTP/3 在 QUIC 内部使用 TLS 1.3：见 `akio_quic::server_config` 与
  `server_config_from(&tls_config)`。`akio-quic` 的自研 QUIC（DEV-PLAN 第 D 波）用同一份
  `akio::tls` 配置驱动 `akio-tls` 内不经记录层的 TLS 1.3 内核（内部 API）。

## 早期数据（0-RTT）

默认关闭，需要双方都开启。服务端设置 `.early_data(max_bytes)`（并开启会话恢复）后，签发的票据允许
这么多早期数据；客户端设置 `.early_data(true)` 并用这样的票据恢复会话时，应用在握手完成前写入的数据
紧跟在 ClientHello 之后发出，省掉一个往返。服务端在握手完成前就读取它，`on_data` 能早一个往返看到请求。

- 服务端只针对票据的第一个 PSK、密码套件、ALPN 协议与 SNI 名接受早期数据，HelloRetryRequest 之后
  绝不接受，也不接受超过允许量的数据。
- 服务端拒绝时（配置不同、HelloRetryRequest、疑似重放），跳过早期记录；客户端在握手后重发同样的
  字节，应用两种情况下看到的字节流相同。
- `TlsInfo::early_data` 给出 `NotAttempted`、`Pending`（客户端，收到答复前）、`Accepted` 或
  `Rejected`；`TlsInfo::early_data_len` 是流开头作为早期数据发送的字节数。akio-http 给落在这个范围
  内的 HTTP/1.1 请求加上 `Early-Data: 1`（RFC 8470；HTTP/2 则是以早期数据开始的连接上的每个请求）。

开启早期数据时**防重放**始终生效：仅当客户端看到的票据年龄与服务端的相差不超过 10 秒时才接受
（RFC 8446 第 8.3 节），并把每个被接受的 ClientHello 的 PSK binder 记录 30 秒（第 8.2 节：窗口的两倍，再加一个窗口容许共享存储的服务端之间时钟有偏差）；见过的
ClientHello 其早期数据被拒绝，按普通会话恢复继续。每个 `ServerConfig` 最多记录 100,000 个 ClientHello，
满了就拒绝早期数据。

**共享票据的多台服务端**（[ADR-013](https://github.com/lesismal/akio/blob/main/docs/adr/013-shared-anti-replay-and-compatible-vn.zh-CN.md)、
[ADR-062](https://github.com/lesismal/akio/blob/main/docs/adr/062-tls-async-anti-replay-ticket-rotation-bogo.zh-CN.md)）。
多个进程或多台机器用同一个 `.session_ticket_key(key)`（48 字节保密随机数：16 字节密钥名加 32 字节密钥）构建时，
可接受彼此签发的票据；若要轮换密钥而不拒绝已发出的票据，则用同一组 `.session_ticket_keys(keys)`：

```rust,ignore
use akio_tls::TicketKeys;
// 每台服务端按周期从共享密钥派生同一把密钥：同步轮换。
let keys = TicketKeys::derived(&shared_secret, Duration::from_secs(6 * 3600));
// 或手动轮换（把同一把新密钥推送到每台服务端），旧密钥仍能解开：
let keys = TicketKeys::new(first_key);
keys.rotate(next_key); // 最多 4 把：一把封装，三把仍能解开
```

此时它们还需要共用一份重放记录，否则发往一台服务端的首个飞行被截获后可重放到另一台。跨网络的存储交给
`.async_anti_replay_store(store)`：其唯一方法把 ClientHello 的 binder 记录一段时间，并在之后从任意线程告知它
是否是新的。等待应答的握手被挂起（其间 I/O 线程继续服务其他连接），应答后在其 I/O 线程上继续；
`.anti_replay_timeout(..)`（1 秒）内没有应答则拒绝早期数据。只有本会接受早期数据的 ClientHello 才会调用存储。
出错时**失败即关闭**：拒绝早期数据，客户端在握手后重发。用 Redis 时，在非阻塞客户端上每次调用一条原子的
`SET key 1 NX PX ttl`：

```rust,ignore
use std::{io, sync::Arc, time::Duration};
use akio_tls::{AsyncAntiReplayStore, ReplayCheck, ServerConfig, TicketKeys};

struct RedisReplay { client: MyAsyncRedis } // 在客户端自己的线程上回复

impl AsyncAntiReplayStore for RedisReplay {
    fn check_and_insert(&self, binder: &[u8], ttl: Duration, done: ReplayCheck) {
        let key = format!("akio:0rtt:{}", hex(binder));
        // 发出后立即返回；回复回调给出应答：设置成功（首次出现）为 "OK"，键已存在（重放）
        // 为 nil，出错则拒绝早期数据。
        self.client.set_nx_px(&key, "1", ttl.as_millis() as u64, move |reply| {
            done.complete(reply.map(|r| r.is_some()).map_err(io::Error::other));
        });
    }
}

let cfg = ServerConfig::builder(chain, key)
    .session_ticket_keys(TicketKeys::derived(&shared_secret, Duration::from_secs(6 * 3600)))
    .early_data(16384)
    .async_anti_replay_store(Arc::new(RedisReplay { client }))
    .build()?;
```

在内存中应答的存储可以改为实现同步的 `AntiReplayStore`，交给 `.anti_replay_store(store)`（在 I/O 线程上调用，
因此不得等待）；默认实现是 `MemoryAntiReplay`（即上文每个配置一份的记录）。

存储必须是原子的（先读后写会放过并发的重放）；跨区域且有复制延迟时，每个区域使用自己的存储与票据密钥。
QUIC 服务端通过 `akio_quic::server_config_from(&cfg)` 获得这两项。

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

## 按握手选择证书

决定记录在 [ADR-098](https://github.com/lesismal/akio/blob/main/docs/adr/098-tls-cert-resolver.zh-CN.md)。
服务端配置上的 `CertResolver` 为每次完整握手选择证书，用于服务期间替换的证书（ACME 续期）和握手期间签发的
证书（按需 TLS）。它在 I/O 线程上被调用，参数是 `ClientHelloInfo`（SNI 名称、客户端提供的 ALPN 协议、签名
算法与密码套件、版本、是否为 QUIC）和一个 `CertDone`，后者可在任意线程上应答一次：

- `done.complete(key)` 使用一个 `CertifiedKey`（证书链及其私钥，只校验一次；请复用该值，它会保留压缩过的
  证书消息）；
- `done.use_default()` 使用没有解析器时配置会用的证书（该名称的 `sni_cert` 证书链，否则默认证书链；
  都没有则 `unrecognized_name`）；
- `done.fail(CertAlert::AccessDenied)`（或 `HandshakeFailure`、`UnrecognizedName`、`InternalError`）
  结束握手；不应答就丢弃 `done` 视为 `internal_error`。

在 `resolve` 返回前应答，握手就在同一次调用里继续。否则握手等待而不占用线程（该线程上的其他连接照常进行），
应答后在自己的 I/O 线程上继续；适用于 TCP 与 QUIC、TLS 1.2 与 1.3。会话恢复的握手不发送证书，不调用解析器；
HelloRetryRequest 之后只为第二个 ClientHello 调用一次。
限制：`.cert_resolver_timeout(d)`（10 s；超时则 `internal_error`；握手超时同样是 10 s 且仍然生效，按需签发时
两者都要调大）和 `.max_pending_cert_resolutions(n)`（每个配置 1024 个等待中的握手；超过后需要等待的握手失败，
在调用内给出的应答仍然照常使用）。`done.is_abandoned()` 告诉较慢的解析器已经没有人在等了。

`CertStore` 是一个现成的、在调用内应答的解析器：名称（精确名称，或匹配一层子域的 `*.example.com`）到
`CertifiedKey` 的映射，随时可用 `insert`、`remove` 和 `set_default` 修改。

```rust,ignore
use akio_tls::{CertDone, CertResolver, CertStore, CertifiedKey, ClientHelloInfo, ServerConfig};

let store = CertStore::new();
store.insert("a.example.com", CertifiedKey::from_pem(&chain_pem, &key_pem)?);
let cfg = ServerConfig::builder_with_resolver(Arc::new(store.clone())).build()?;
// 之后在任意线程上续期：新的握手拿到新的证书链。
store.insert("a.example.com", CertifiedKey::from_pem(&new_chain, &new_key)?);

// 按需：缓存命中时在调用内应答，未命中时由签发任务应答。
struct OnDemand { store: CertStore, issuer: Issuer }
impl CertResolver for OnDemand {
    fn resolve(&self, hello: &ClientHelloInfo<'_>, done: CertDone) {
        match (self.store.get(hello.server_name()), hello.server_name()) {
            (Some(k), _) => done.complete(k),
            (None, Some(name)) if self.issuer.allowed(name) => self.issuer.issue(name, done),
            _ => done.use_default(),
        }
    }
}
```

## 记录大小限制、证书压缩、OCSP stapling

决定记录在 [ADR-008](https://github.com/lesismal/akio/blob/main/docs/adr/008-tls-extensions.zh-CN.md)。

**record_size_limit**（RFC 8449，TLS 1.3 与 1.2）。任一方的 `.record_size_limit(n)` 设定自己接受的最大
记录：按 RFC 的口径为 64 到 16385 字节（TLS 1.3 中该值包含 1 字节内容类型；TLS 1.2 上限为 16384），默认
16385。客户端总是发送自己的值，只要客户端发了，服务端就回以自己的值；此后双方写出的受保护记录按对方的
限制切分，收到超过自己限制的记录则报 `record_overflow`。明文的握手记录不受限制，早期数据遵循签发票据的
那条连接上的限制。不支持该扩展的对端（OpenSSL、Go）既不会得到也不会被施加限制。QUIC 中不使用（没有记录）。

```rust,ignore
// 无法缓存 16 KiB 记录的小设备。
let cfg = ClientConfig::builder().roots(roots).record_size_limit(1024).build()?;
```

**证书压缩**（RFC 8879，TLS 1.3）。服务端默认开启：对提供 zlib、brotli 或 zstd 的客户端，用其提供的算法中
压得最小的那种，在压缩后更小时发送压缩的证书链（每条链每种算法只压缩一次并复用，握手没有额外开销），其
CertificateRequest 也为客户端证书提供这三种。客户端默认关闭：解压收到的证书链需要几微秒，约为内存中完整握手的
百分之一到二，换来几十到几百字节的节省；更在意线路字节数时用 `.certificate_compression(true)` 开启（提供
brotli、zstd 和 zlib；`.certificate_compression_algorithms(&[CertCompression::Brotli])` 只选其中几种）。三者都是
自研的：`akio-deflate`、`akio-brotli` 与 `akio-zstd`（[ADR-041](https://github.com/lesismal/akio/blob/main/docs/adr/041-brotli-zstd.zh-CN.md)）。
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

客户端用 `.ocsp_stapling(true)` 请求响应，`tls_info(&conn).ocsp_response` 保存收到的 DER 字节；只有设置了
OCSP 策略时才会校验（见下一节）。

### 吊销检查

默认关闭，关闭时没有开销。本库从不获取任何东西（I/O 线程上没有阻塞 I/O）：装订响应来自服务器，CRL 来自你的
应用。

```rust,ignore
use akio::tls::{ClientConfig, Crls, RevocationPolicy};

let mut crls = Crls::new();
crls.add_pem(&std::fs::read("ca.crl.pem")?)?; // 由你下载并刷新
let cfg = ClientConfig::builder()
    .roots(roots)
    .ocsp_policy(RevocationPolicy::HardFail) // 要求有效的 "good" 装订响应
    .crls(crls, RevocationPolicy::SoftFail)  // 只有列出吊销时才失败
    .build()?;
```

- **装订的 OCSP**（`.ocsp_policy`，不为 `Off` 时自动请求装订）：响应必须由叶证书的签发者或其委托的响应者
  （id-kp-OCSPSigning）签名、指向该叶证书且当前有效（thisUpdate / nextUpdate 在 5 分钟时钟偏差内）。`SoftFail`
  只拒绝有效的“revoked”（告警 `certificate_revoked`）；`HardFail` 还拒绝缺失、无效、过期或“unknown”的响应
  （`bad_certificate_status_response`）。只覆盖叶证书；恢复的会话不再检查。
- **客户端的 OCSP 响应**（服务端 `.client_ocsp_policy`，ADR-049）：服务端在 CertificateRequest 中要求 TLS 1.3
  客户端提供响应（RFC 8446 4.4.2.1），并按相同的规则与策略检查客户端随证书装订的响应。客户端只在被要求时发送
  `.client_cert_ocsp_response(der)` 的响应。TLS 1.2 无法携带，因此 `HardFail` 下拒绝 TLS 1.2 的客户端证书
  （请配合 `.tls13_only(true)`）。OpenSSL 与 Go 客户端既不发送也不在意该请求：`SoftFail` 下可以通过。
- **CRL**（客户端用 `.crls`，服务端检查客户端证书用 `.client_crls`）：根以下的每张证书都用其签发者当前的 CRL
  检查（完整与 delta、issuingDistributionPoint 范围，签名只验证一次），包括间接 CRL 以及由 CA 另一把
  密钥签发的 CRL，前提是签名证书位于对端发送的证书链或根证书中，且自身能验证到同一个根（ADR-046）。被列出的证书以 `certificate_revoked`
  失败；`HardFail` 下没有当前 CRL 的证书以 `certificate_unknown` 失败。刷新时构建新的配置。

去哪里获取，以及自己查询响应者：内部 crate `akio-x509`（无 semver 承诺）提供
`Certificate::crl_distribution_points()` 与 `ocsp_urls()`、`OcspRequest` 与 `OcspResponse::verify`（ADR-038）。

## 内核 TLS

握手完成后，`Tls` 的连接可以把记录层交给 Linux（内核 TLS，`ktls` cargo feature，ADR-067），由内核或
自己做 TLS 的网卡加密发送的数据、解密收到的数据，`send_file` 与静态文件也重新走 `sendfile`。默认关闭，
因为内核的**软件**记录层比 akio-tls 自己的慢：从 1 KiB 响应的 0.83 倍到 256 KiB 的 0.40 倍，10 MB 文件用
`sendfile` 对比 `pread` 加加密为 0.48 倍（[测量结果](https://github.com/lesismal/akio/blob/main/docs/BENCHMARKS.zh-CN.md#内核-tlsktls评估)）。

```rust,ignore
use akio::tls::{Ktls, ServerConfig};

let cfg = ServerConfig::builder(chain, key)
    // 只卸载支持 TLS 卸载的网卡自己完成的部分；其他地方什么都不做。
    .ktls(Ktls::Hardware)
    .build()?;
```

- `Ktls::Hardware`：连接本地地址所在接口开启了 `tls-hw-tx-offload`（`ethtool -k`；例如 NVIDIA
  ConnectX-6 Dx 及更新型号）时卸载发送方向，同时开启 `tls-hw-rx-offload` 时也卸载接收方向；仅限
  AES-GCM。内核计数器确认网卡接管了每个方向；驱动拒绝的组合（内核回退到软件）不再尝试。在没有这类
  网卡的主机上，每个连接只多一次缓存的检查，什么都不改变：可以放心地在所有地方打开。
- `Ktls::Software` / `Ktls::SoftwareTx`：软件 kTLS，双向或只发送方向。在当前 CPU 上更慢；用于对比和
  需要明文留在内核中的场景。
- `ktls_zerocopy_sendfile(true)`：由网卡加密时，让它直接从页缓存读取 `sendfile` 的页面
  （`TLS_TX_ZEROCOPY_RO`）；仅在发送过程中文件绝不会被修改时使用。
- `TlsInfo::ktls_tx` / `ktls_rx` 说明每个方向去了哪里（`KtlsPath::Software` / `Hardware`），
  `TlsStats` 对此计数（`akio_tls_ktls_total{side, dir, path}`）。
- 需要带 `tls` 模块的 Linux；TLS 1.3 需要 6.14（已卸载方向的密钥更新）。支持 epoll 与 io_uring、服务端
  与客户端；不支持 DPDK、QUIC 与 DTLS。接收方向需要 `read_buffer` 不小于 16 KiB。只要内核拒绝，连接
  就留在用户态。

## 尚未完成

获取 OCSP 响应或 CRL；中间证书的 OCSP（`status_request_v2`：仅限 TLS 1.2 且已过时，ADR-049）；
Windows 证书库（Windows 不是目标平台）。

## 编写自己的 transport

`akio_core::Transport` 就是 TLS 实现的 trait：`recv(cipher, plain, out)`、
`seal(plain, out)`、`shutdown(out)`，外加 `name` 和 `handshaking`。从 `Acceptor::transport`
返回一个实现，就能在连接之下叠加任意字节流变换。所有调用都在连接的写锁下按线路顺序进行，
不能阻塞。
