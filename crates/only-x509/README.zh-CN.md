# only-x509

[English](README.md)

[`only`](https://github.com/lesismal/only) 的 X.509 证书支持，构建在 [`only-crypto`](../only-crypto)
之上，安全 Rust（`#![forbid(unsafe_code)]`），没有其他依赖。它是 DEV-PLAN 第 C、D 波计划中自研
TLS 1.2/1.3、DTLS 与 QUIC 协议栈的证书层（也将替代测试证书用的 `rcgen`）。这是内部 crate
（docs/api-stability.zh-CN.md）：API 跟随这些协议栈的需要，可能在任何发布中变化。

- `Certificate`：严格按 DER 解析 v1/v3 证书（拒绝尾随数据、BER 长度、显式编码的 v1、重复扩展以及
  内外签名算法不一致）；支持 subjectAltName（DNS、IP、电子邮件、URI、directoryName）、basicConstraints、
  keyUsage、extKeyUsage、nameConstraints、主体/颁发者密钥标识符；未知的关键扩展会被记录并导致验证失败；
  PEM 读写；`verify_signed_by`。
- 基于 `RootStore` 的 `Verifier`：在无序的中间证书中构建路径（深度上限、环路检测、签名校验次数上限），
  校验有效期、CA 标志与 pathLenConstraint、keyCertSign、叶子与中间证书的 extKeyUsage（服务器或客户端认证），
  拒绝把 CA 证书当作终端实体，名称约束（DNS、IP 与 directoryName；其他形式按失败处理），以及 RFC 6125
  服务器名：DNS 名称与 dNSName SAN 不区分大小写地匹配，通配符只能是整个最左标签，且不能只覆盖单个标签
  （`*.com`），IP 地址只匹配 iPAddress SAN；不使用 CN。信任锚只看主体名与公钥（不检查其自身有效期，与
  rustls-webpki 相同）。
- `CertificateParams` 与 `generate_simple_self_signed`：生成自签名或 CA 签发的证书，签名密钥可以是
  ECDSA P-256（生成密钥时的默认值）或 P-384、Ed25519、RSA；支持 SAN、有效期、序列号、CA/pathLen、密钥用途、
  EKU、名称约束、自定义扩展、密钥标识符。
- 吊销检查（ADR-036），不访问网络（由应用获取；`Certificate::crl_distribution_points`、`ocsp_urls` 与
  `ca_issuer_urls` 给出地址）：`Crl`（RFC 5280 第 5 节：严格的 DER/PEM、cRLNumber、delta CRL、原因码、
  invalidityDate、issuingDistributionPoint 范围；签名对签发者只验证一次并记住）与 `CrlSet::status`（带时钟
  偏差的正常 / 吊销 / 未知、delta 与 removeFromCRL、原因覆盖），由 `Verifier::crls` 配合
  `RevocationMode::{SoftFail, HardFail}` 应用于整条路径；`OcspResponse::verify`（RFC 6960：签发者或带
  id-kp-OCSPSigning 的委托响应者、SHA-1/256/384/512 的 CertID、常数时间比较 nonce、带时钟偏差的
  thisUpdate / nextUpdate）与 `OcspRequest`；`CrlParams` 与 `OcspResponseParams` 为测试和开发用 CA 生成
  已签名的 CRL 与响应。

支持的签名算法：ECDSA 配 SHA-256/384/512（P-256、P-384 密钥）、Ed25519、RSA PKCS#1 v1.5 配
SHA-256/384/512（SHA-1 仅用于验证旧证书）、RSA-PSS 配 SHA-256/384/512。未实现：间接 CRL（以及由 CA
其他密钥签发的 CRL）、签名的 OCSP 请求、任何网络获取、证书策略、Ed448、DSA。

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
  验证 OpenSSL 生成的 ECDSA、Ed25519、RSA PKCS#1 与 PSS 签名，确定性签名与 OpenSSL 的结果逐字节一致。
  这些密钥只用于测试。
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
- 模糊测试：`fuzz/` 中的目标 `x509_parse`（证书/PEM/SPKI/PKCS#8 解析、往返、自验证）、`x509_crl` 与
  `x509_ocsp`（解析、往返、状态查询与校验）；`fuzzing::tests` 在 stable 上回放它们的语料。
