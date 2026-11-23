# ADR-093：akio-x509 中的证书签名请求

[English](093-x509-certificate-requests.md) | 简体中文

状态：已采纳（2026-11-23）

## 背景

基于 akio 的网关 akit 用自己的客户端通过 ACME（RFC 8555）签发证书，如同 fit 基于 Go 的 `x/crypto/acme`。
完成订单（finalize）时要发送一个 PKCS#10 证书签名请求（RFC 2986），包含订单里的名字，由证书的密钥签名（akit 的
需求 A6）。`akio-x509` 能生成证书、CRL 和 OCSP 响应，但不能生成请求，而网关不应为此自带一份 ASN.1。A6 的另一半
JWS 签名不需要新东西：`PrivateKey::sign` 配合 `SignatureAlgorithm` 已经给出 JWS 所用原始格式的
ES256/384/512、EdDSA 和 RS256。

## 决定

- **`CsrParams`**（subject、subjectAltName、extKeyUsage、其他扩展），`CsrParams::new(names)` 以第一个 DNS 名字
  作为 common name（与 `CertificateParams::new` 相同），`sign(&PrivateKey) -> CertificateRequest` 用密钥的默认算法
  签名。请求的扩展放在一个 `extensionRequest` 属性里；subject 为空时 subjectAltName 标为关键（RFC 5280
  §4.2.1.6）。
- **`CertificateRequest`**：从 DER 或 PEM（`CERTIFICATE REQUEST`，以及旧标签 `NEW CERTIFICATE REQUEST`）严格解析，
  提供 subject、公钥、签名算法、请求的扩展和 subjectAltName，其他属性不解析原样保留，`verify_signature` 检查
  持有证明。版本必须是 v1（0）；空的属性列表可以省略，空的 `extensionRequest`（OpenSSL 会这样写）也接受。
- **上限**：`MAX_REQUEST_LEN`（64 KiB）和 `MAX_ATTRIBUTES`（32）；属性或扩展重复即为错误。
- 模糊测试目标 `x509_csr`，种子来自 OpenSSL 和 akio，单元测试在 stable 上回放。

## 影响

ACME 客户端（akit 的或应用自己的）和测试 CA 不需新依赖即可生成和检查请求。纯新增 API；证书的解析和验证不变。

## 验证

单元测试（P-256、P-384、Ed25519，名字与 IP 地址，EKU 与自定义扩展，被篡改的请求，错误版本，截断，大小上限，
PEM 块）；互通：rcgen（P-256、P-384、Ed25519）和 OpenSSL 4.1（带 SAN 和 EKU 的 RSA；带 challengePassword 与空
`extensionRequest` 的 Ed25519）生成的请求在这里能解析并验证通过，这里生成的请求通过 `openssl req -verify`。
