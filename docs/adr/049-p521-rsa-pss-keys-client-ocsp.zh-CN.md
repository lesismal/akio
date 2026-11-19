# ADR-049：P-521、RSA-PSS 密钥与 TLS 1.3 客户端的 OCSP 响应

[English](049-p521-rsa-pss-keys-client-ocsp.md) | 简体中文

状态：已采纳（2026-11-19）

## 背景

only-tls 的 README 在未实现项中列出：RSA-PSS 密钥、P-521、TLS 1.3 客户端认证中客户端的 OCSP 响应，
以及 `status_request_v2`。only-crypto 只有 P-256 与 P-384 上的 ECDH 和 ECDSA，RSA 密钥只有
`rsaEncryption` 一种（这种密钥做 RSASSA-PSS 签名，即 TLS 1.3 的 `rsa_pss_rsae_*`，已支持）。
密钥为 `id-RSASSA-PSS`（RFC 4055，OpenSSL 的 `genpkey -algorithm RSA-PSS`）的证书和 P-521
证书无法解析，只提供 secp521r1 或只提供 `rsa_pss_pss_*` 的对端无法连接。RFC 8446 第 4.4.2.1
节还允许服务端要求 TLS 1.3 客户端随证书发送 OCSP 响应；only-tls 的服务端从不要求，客户端也从不
发送，尽管 ADR-038 在客户端一侧的机制（装订的响应，按 `RevocationPolicy` 校验）已经具备。

## 决定

1. **only-crypto，P-521**（内部层级）：新增 `p521` 模块，API 与 `p256` / `p384` 相同（`SecretKey`、
   `PublicKey`、`Signature`、`SCALAR_LEN = 66`；默认 SHA-512，可用任意 `Hash` 预哈希；RFC 6979
   随机数，`bits2int` 取最左 521 位；DER 与 132 字节定长签名；压缩与非压缩 SEC1 点，均经校验）。
   它是独立实现，不用通用的 `ec` 模块：后者假设标量为 `8·L` 字节，并依赖 `n` 接近 `2^(64L)`
   来证明不存在例外情形；P-521 放在九个 64 位肢中，还空出 55 位。实现为：
   - 基域 `GF(2⁵²¹ - 1)` 用九个非饱和肢（八个 58 位，一个 57 位）：乘积的高半部分加倍后折回低半部分
     （`2⁵²² ≡ 2`），一次进位链，最高进位回到第 0 肢；加法和减法（带 `2p` 偏移）以一次对所有肢同时
     进行的进位步结束；求逆 `a^(p-2)` 与平方根 `a^(2⁵¹⁹)` 用固定的链。各肢的界写在模块里并由测试断言；
   - 点用射影坐标与 Renes、Costello、Batina 的完备公式（`a = -3`），因此任何例外情形都无需论证：
     ECDH 用有符号 5 位 Booth 窗口，查表 `0·P … 16·P` 时掩码扫描整张表，倍点在 Jacobian 坐标中进行
     （dbl-2001-b，把单位元 `(1:1:0)` 映射到自身；不存在二阶点）；生成密钥与签名用 131 行 `G` 的仿射
     倍数组成的有符号 4 位梳（完备混合加法，每个数位读整行）；验签用交错 wNAF，依据公开数据变时；
   - 标量域用 `field.rs` 的通用 Montgomery 代码（九肢）。只有可移植 Rust：P-521 很少用到，不值得写汇编。
     `tools/ct-dudect` 新增 `p521-ecdh`、`p521-keygen`、`p521-sign`。
   - `pkey::PublicKey::P521`、`pkey::PrivateKey::P521`（SPKI、PKCS#8、SEC1）、`der::oid::SECP521R1`。
2. **only-crypto，RSA-PSS 密钥**：`pkey::PublicKey::RsaPss(rsa::PublicKey, Option<PssParams>)` 与
   `pkey::PrivateKey::RsaPss(Box<rsa::PrivateKey>, Option<PssParams>)`，对应 SubjectPublicKeyInfo 和
   PKCS#8 中的 `id-RSASSA-PSS` 算法，可带或不带 `RSASSA-PSS-params`。`PssParams { hash, salt_len }`
   （`new`、`from_der`、`to_der`、`allows`）：只支持 SHA-256/384/512、MGF1 用同一哈希、trailer 为 1
   （缺省字段按 RFC 4055 取 SHA-1，结果为 `Unsupported`）。这种密钥只做 RSASSA-PSS（从不做 PKCS#1
   v1.5），带参数时只用参数中的哈希，且盐长（取哈希长度，TLS 1.3 与 X.509 都如此）不小于其最小值。
   它默认的证书签名算法是用其哈希的 RSA-PSS（无参数时为 SHA-256）。编码与 OpenSSL 逐字节相同。
3. **only-x509**：API 不变。P-521 与 `id-RSASSA-PSS` 密钥的证书可以解析、验证和签发
   （用这种密钥调用 `CertificateParams::signed_by`）；证书签名按签发者密钥的限制检查。
4. **only-tls**：
   - 组 secp521r1（0x0019），在默认列表最后（在 x448 之后：ClientHello 列出它，密钥共享仍发 X25519）；
     签名方案 `ecdsa_secp521r1_sha512`（0x0603）用于 P-521 密钥（TLS 1.2 中任何 ECDSA 方案适用于任何
     曲线，与此前 P-256、P-384 相同）；`rsa_pss_pss_sha256/384/512`（0x0809–0x080b）用于
     `id-RSASSA-PSS` 密钥，服务端与客户端证书、TLS 1.3 与 1.2（ECDHE-RSA 套件）均可，并受密钥参数约束。
     `rsae` 与 `pss` 两类方案从不在两种密钥之间混用（RFC 8446 4.2.3）。
   - **客户端的 OCSP 响应**（RFC 8446 4.4.2.1）：`ServerConfigBuilder::client_ocsp_policy(
     RevocationPolicy)` 在 TLS 1.3 的 CertificateRequest 中发送空的 `status_request`，并完全按
     `ClientConfigBuilder::ocsp_policy` 校验服务端响应的方式，校验客户端装订在叶证书 CertificateEntry
     中的响应（ADR-038：签发者或其委托的响应者签名、针对该证书、在 5 分钟误差内有效；软失败只拒绝有效的
     “已吊销”，硬失败要求有效的“良好”）。`ClientConfigBuilder::client_cert_ocsp_response(der)` 是客户端
     的响应，只在被要求时发送。服务端上的 `TlsInfo::ocsp_response` 即客户端的响应。TLS 1.2 无法让客户端
     发送它：硬失败时拒绝 TLS 1.2 的客户端证书（需要此功能的服务端应配合 `tls13_only`）。服务端未要求的
     响应被忽略，正如客户端忽略服务端未经要求发来的响应。恢复的会话不再检查。
5. **验证**：Wycheproof ECDSA P-521/SHA-512（DER 与 P1363）和 ECDH P-521 向量（已收录），RFC 6979
   A.2.7（SHA-512 与 SHA-256，也是 OpenSSL 确定性 ECDSA 的结果），OpenSSL 生成的 RSA-PSS 密钥（带与不带
   参数）及签名，only-x509 中 OpenSSL 生成的 P-521 与 RSA-PSS 密钥证书链；内存中的 TLS 矩阵覆盖 P-521 与
   RSA-PSS 密钥证书（服务端与客户端、两个版本）、secp521r1，以及各策略下客户端的 OCSP 响应；
   `tools/interop/tls/run.sh` 对 OpenSSL（secp521r1、P-521 与 RSA-PSS 密钥证书在 TLS 1.3 与 1.2 中
   双向互通、这类客户端证书，以及 OpenSSL 客户端与服务端面对客户端 OCSP 请求的行为，OpenSSL 既不发送也不
   要求）和 Go（P-521 证书与曲线）。模糊测试：`x509_parse`（SPKI 与 PKCS#8 解析，现含 PSS 参数与 P-521
   点）、`tls_server`（客户端 CertificateEntry 的扩展）。

有意不做：

- **`status_request_v2`**（RFC 6961，中间证书的 OCSP）：仅限 TLS 1.2，从未被广泛采用（OpenSSL、Go、
  BoringSSL、rustls 都没有实现），且已被 TLS 1.3 取代：TLS 1.3 中每个 CertificateEntry 都可以带
  status_request 响应（RFC 8446 4.4.2.1）。
- **以哈希长度之外的盐长签名**，以及限定为 SHA-1 或不同 MGF1 哈希的 PSS 密钥：TLS 1.3 与 Web PKI 只用
  哈希长度的盐和同哈希的 MGF1。
- **P-521 汇编**：可移植代码已与 OpenSSL 相当（见“后果”），而且 P-521 很少被协商。

## 后果

- `pkey::PublicKey`、`pkey::PrivateKey` 增加变体（non-exhaustive 枚举）；`pkey::PssParams`、`p521`、
  `der::oid::SECP521R1`、`ServerConfigBuilder::client_ocsp_policy` 与
  `ClientConfigBuilder::client_cert_ocsp_response` 为新增。用匹配 `PublicKey::Rsa` 表示“RSA 密钥”的代码
  也应匹配 `RsaPss`。
- 默认 ClientHello 多列出一个组（2 字节）；只支持 secp521r1 或只支持 `rsa_pss_pss_*` 的服务端现在可以
  连接。默认握手的其他部分不变：第一个密钥共享仍是 X25519，已有各类密钥首选的方案不变。
- P-521 性能（`pk_bench 521`，可移植 Rust；docs/BENCHMARKS.zh-CN.md）：在 x86_64 基准主机上对比
  OpenSSL 3.0.13，签名 1.09×、验签 1.05×、ECDH 0.84×；在 Apple M 系列核心上对比 OpenSSL 4.1，签名约
  1.07×、ECDH 约 0.54×。默认握手经测量不变。
