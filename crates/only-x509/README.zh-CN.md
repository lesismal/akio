# only-x509

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 X.509 证书支持，构建在 [`only-crypto`](../only-crypto)
之上，安全 Rust（`#![forbid(unsafe_code)]`），没有其他依赖。它是 DEV-PLAN 第 C、D 波计划中自研
TLS 1.2/1.3、DTLS 与 QUIC 协议栈的证书层（也将替代测试证书用的 `rcgen`）。这是内部 crate
（docs/api-stability.zh-CN.md）：API 跟随这些协议栈的需要，可能在任何发布中变化。

- `Certificate`：严格按 DER 解析 v1/v3 证书（拒绝尾随数据、BER 长度、显式编码的 v1、重复扩展以及
  内外签名算法不一致）；支持 subjectAltName（DNS、IP、电子邮件、URI、directoryName）、basicConstraints、
  keyUsage、extKeyUsage、nameConstraints、主体/颁发者密钥标识符、certificatePolicies、policyMappings、
  policyConstraints、inhibitAnyPolicy；未知的关键扩展会被记录并导致验证失败；
  PEM 读写；`verify_signed_by`。
- 基于 `RootStore` 的 `Verifier`：在无序的中间证书中构建路径（深度上限、环路检测、签名校验次数上限），
  校验有效期、CA 标志与 pathLenConstraint、keyCertSign、叶子与中间证书的 extKeyUsage（服务器或客户端认证），
  拒绝把 CA 证书当作终端实体（`allow_ca_end_entity` 可用于验证 CA 证书本身），名称约束（DNS、IP、
  directoryName、rfc822Name（包括主题中的 emailAddress）与 URI；其他形式按失败处理；自签发中间证书不受
  约束，也不计入 pathLen），证书策略（ADR-046：基于 RFC 9618 策略图的 RFC 5280 §6.1，
  `Verifier::policies(PolicyOptions)` 设置初始策略集、显式策略与各禁止标志；`verify_path` 返回用户约束
  策略集），以及 RFC 6125
  服务器名：DNS 名称与 dNSName SAN 不区分大小写地匹配，通配符只能是整个最左标签，且不能只覆盖单个标签
  （`*.com`），IP 地址只匹配 iPAddress SAN；不使用 CN。信任锚只看主体名与公钥（不检查其自身有效期，与
  rustls-webpki 相同）。
- `CertificateParams` 与 `generate_simple_self_signed`：生成自签名或 CA 签发的证书，签名密钥可以是
  ECDSA P-256（生成密钥时的默认值）、P-384 或 P-521、Ed25519、Ed448、RSA（`rsaEncryption`，或在其参数范围内
  以 RSA-PSS 签名的 `id-RSASSA-PSS`）；支持 SAN、有效期、序列号、CA/pathLen、密钥用途、
  EKU、名称约束、自定义扩展、密钥标识符。
- 吊销检查（ADR-038），不访问网络（由应用获取；`Certificate::crl_distribution_points`、`ocsp_urls` 与
  `ca_issuer_urls` 给出地址）：`Crl`（RFC 5280 第 5 节：严格的 DER/PEM、cRLNumber、delta CRL、原因码、
  invalidityDate、issuingDistributionPoint 范围；签名对签发者只验证一次并记住）与 `CrlSet::status`（带时钟
  偏差的正常 / 吊销 / 未知、delta 与 removeFromCRL、原因覆盖），由 `Verifier::crls` 配合
  `RevocationMode::{SoftFail, HardFail}` 在候选路径到达根证书后应用于整条路径；支持间接 CRL
  （certificateIssuer 条目、分发点的 cRLIssuer）以及由 CA 另一把密钥签发的 CRL，其签名证书（在中间证书、
  `Verifier::crl_signers` 和根证书中查找）必须验证到同一个根（ADR-046，RFC 5280 §6.3.3）；`OcspResponse::verify`（RFC 6960：签发者或带
  id-kp-OCSPSigning 的委托响应者、SHA-1/256/384/512 的 CertID、常数时间比较 nonce、带时钟偏差的
  thisUpdate / nextUpdate）与 `OcspRequest`；`CrlParams` 与 `OcspResponseParams` 为测试和开发用 CA 生成
  已签名的 CRL 与响应。

支持的签名算法：ECDSA 配 SHA-256/384/512（P-256、P-384、P-521 密钥）、Ed25519、Ed448、RSA PKCS#1 v1.5 配
SHA-256/384/512（SHA-1 仅用于验证旧证书）、RSA-PSS 配 SHA-256/384/512（`rsaEncryption` 密钥，以及在其
RFC 4055 参数范围内的 `id-RSASSA-PSS` 密钥，后者不能用于 PKCS#1 v1.5；ADR-049），以及 DSA 配 SHA-1/224/256
（仅验签；FIPS 186-4 规定的长度；不支持从签发者继承参数）。有意不实现（ADR-046）：签名的 OCSP 请求
（应答器并不要求；只有应用的客户端密钥才能签名）和任何网络获取（本 crate 是 sans-io 的；网络获取会让
握手停顿在第三方上、向 CA 泄露客户端访问的站点，并会访问攻击者提供的 URL）。名称按 DER 字节链接
（RFC 5280 §7.1 允许），不做 RFC 4518 的大小写和空白折叠。

```rust
use only_crypto::pkey::PrivateKey;
use only_x509::{CertificateParams, RootStore, Verifier};

let ca_key = PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap());
let ca = CertificateParams::ca("Dev CA").self_signed(&ca_key).unwrap();
let key = PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap());
let cert = CertificateParams::new(["localhost", "127.0.0.1"])
    .signed_by(&key.public_key(), &ca, &ca_key)
    .unwrap();
let (cert_pem, key_pem) = (cert.to_pem(), key.to_pkcs8_pem());

let mut roots = RootStore::new();
roots.add(ca);
Verifier::new(&roots).verify_server(&cert, &[], "localhost").unwrap();
# let _ = (cert_pem, key_pem);
```

## 测试

- 真实证书链（随仓库附带的公开证书，`tests/data/real`）：Google Trust Services（ECDSA，其根由
  GlobalSign 的 SHA-1 RSA 根交叉签名）、Let's Encrypt 的 ECDSA 链（ISRG Root X2，也可经由 X1）与 RSA 链
  （ISRG Root X1），都在有效期内的某个时间点验证；并测试名称不符、过期、尚未生效、缺少中间证书、用途不符与
  签名被篡改等反例。
- OpenSSL 生成的证书链与密钥（`tests/data/openssl`，在 Docker 中生成）：RSA-3072 根、用 RSA-PSS 签发的
  P-384 中间证书、带通配符与 IPv4/IPv6 SAN 的 Ed25519 与 RSA 叶子证书；PKCS#8、SEC1 与 PKCS#1 密钥文件；
  验证 OpenSSL 生成的 ECDSA、Ed25519、RSA PKCS#1 与 PSS 签名，确定性签名与 OpenSSL 的结果逐字节一致；
  `tests/data/pss-p521`（`gen.sh`）：使用 `id-RSASSA-PSS` 密钥（限定 SHA-256 与不带参数）的根与叶子证书，以及
  P-521 根与叶子证书，验证通过、密钥可加载，并在这些 OpenSSL 根下签发本库生成的证书。这些密钥只用于测试。
- 互通：rcgen（ring）生成的证书能在这里通过验证，rcgen 能加载我们的 PKCS#8 密钥；我们生成的 CA 与叶子证书
  能通过 rustls-webpki 的验证（都只是 dev-dependency）。
- 参照 BetterTLS / x509-limbo 构造的反例：超过 pathLen、颁发者不是 CA、CA 证书当作终端实体、缺少
  keyCertSign、中间证书的 EKU 不含 serverAuth、中间证书过期、未知关键扩展、签名密钥错误、违反名称约束
  （DNS、排除子树、IP 范围、形似后缀）、通配符边界情况、证书的每一种截断和大量字节篡改。
- 吊销（`tests/revocation.rs`）：OpenSSL 生成的 CRL（完整、delta、IDP、根）与 OCSP 响应
  （`tests/data/revocation/gen.sh`：委托响应者、CA 签名、byKey、SHA-256、无 nextUpdate、nonce、吊销、暂停、
  未知、多个单个响应；反例：没有 OCSPSigning EKU、其他 CA 的响应者、未附带签名者证书、证书不符、偏差边界两侧的
  过期与尚未生效、损坏的签名、每一种截断）；请求与 `openssl ocsp` 生成的逐字节相同；生成的 CRL 与响应覆盖
  delta 解除暂停、范围、部分原因、被吊销的中间证书与过期的响应者。
- NIST PKITS（`tests/pkits.rs`，测试套件由 `tools/pkits/prepare.sh` 下载，不纳入仓库）：第 4 节的每个
  测试都按 PKITS 文档列出的策略设置运行，吊销为 hard-fail 模式；248 次运行中 242 次符合预期，其余 6 次
  列出原因（DSA 参数继承、RFC 4518 名称折叠）。
- 在生成的证书链上测试策略、间接 CRL 与独立 CRL 密钥（`tests/policy.rs`：显式策略、
  requireExplicitPolicy、策略映射与 inhibitPolicyMapping、anyPolicy 与 inhibitAnyPolicy、格式错误的扩展、
  带 certificateIssuer 的间接 CRL、被吊销和过期的 CRL 签名者、负序列号、rfc822Name 与 URI 约束）。
- OpenSSL 生成的 Ed448 与 DSA 数据（`tests/data/ed448-dsa/gen.sh`）：Ed448 证书链、密钥与签名（我们的
  签名与 OpenSSL 的一致），DSA 2048/256 根签发的 P-256 叶子证书和 CRL。
- 模糊测试：`fuzz/` 中的目标 `x509_parse`（证书/PEM/SPKI/PKCS#8 解析、往返、自验证、策略访问器）、
  `x509_crl` 与 `x509_ocsp`（解析、往返、状态查询（包括间接 CRL 条目）与校验）以及 `x509_policy`（任意
  路径的策略处理）；`fuzzing::tests` 在 stable 上回放它们的语料。
