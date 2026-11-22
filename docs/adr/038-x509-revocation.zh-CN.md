# ADR-038：证书吊销：CRL、OCSP 与装订响应的校验

[English](038-x509-revocation.md) | 简体中文

状态：已采纳（2026-11-18）

## 背景

`akio-x509` 能构建并校验证书链，但完全没有吊销检查；`akio-tls` 的服务器可以装订（staple）OCSP
响应，客户端拿到的却只是原始字节，文档写着“未校验”。客户端若不自带 ASN.1 与签名代码，就分不清
被吊销的证书和正常证书；服务器也无法拒绝被吊销的客户端证书。

吊销信息需要获取（从分发点下载 CRL，向响应者查询 OCSP），而本库在 I/O 线程上执行握手，绝不能
阻塞，在 `akio-http` 之下也没有自己的 HTTP 客户端。因此获取留给应用；库负责解析、认证并应用应用
提供的信息。

## 决策

1. **`akio-x509` 的 CRL**（RFC 5280 第 5 节）：`Crl` 严格解析 v1/v2 CRL（签名算法一致、
   `critical` 为 DEFAULT FALSE 时必须省略、扩展不重复、issuingDistributionPoint 至多一个
   “akio” 标志），支持 cRLNumber、deltaCRLIndicator、issuingDistributionPoint（fullName、
   onlyUser/onlyCA/onlySomeReasons/indirect/attribute）、authorityKeyIdentifier，以及每个条目
   的 reasonCode、invalidityDate 与 holdInstructionCode。条目按序列号排序以便二分查找。未知的
   关键（critical）CRL 扩展或条目扩展（包括间接 CRL 的 certificateIssuer）使该 CRL 不能用于查询，
   而不是无法解析。`verify_signed_by(issuer)` 检查名称、cRLSign（存在 keyUsage 时）与签名，并在
   首次成功后记住签发者的公钥，所以大 CRL 只需哈希和验签一次，而不是每次握手一次。
2. **`CrlSet::status(cert, issuer, now, skew)`** 给出 `Good`、`Revoked { time, reason }` 或
   `Unknown`（RFC 5280 第 6.3 节，不含间接 CRL）：一个 CRL 被采用的条件是来自签发者（名称与签名）、
   当前有效（thisUpdate ≤ now + skew；必须有 nextUpdate 且 ≥ now − skew）、在范围内（IDP 的
   用户/CA 限制；其 fullName 须与证书的某个分发点匹配，证书没有分发点时须是签发者的
   directoryName）且没有不支持的关键扩展。被采用的完整 CRL 列出即为吊销（其中的 removeFromCRL
   条目忽略）；`Good` 要求被采用的完整 CRL 合起来覆盖所有原因（onlySomeReasons 的划分可以拼合）；
   随后，基准号不大于所用最新完整 CRL 编号的最新当前 delta CRL 可以追加吊销，其 removeFromCRL
   可解除 certificateHold。
3. **`Verifier::crls(&set)`** 在构建路径时（每次验签之后）检查根以下的每张证书，所以被吊销的
   中间证书只会让这条路径失败，其他路径仍可能成功。`RevocationMode::{SoftFail（默认）, HardFail}`
   决定如何处理没有 CRL 覆盖的证书（`Error::RevocationUnknown`）；被吊销的证书以
   `Error::Revoked(reason)` 失败。`Verifier::clock_skew`（默认 `DEFAULT_CLOCK_SKEW`，300 秒）。
4. **`akio-x509` 的 OCSP**（RFC 6960）：`OcspResponse`（状态；`BasicOcspResponse` 含按名称或
   公钥的响应者 ID、producedAt、带 CertID 的单个响应，good / revoked（时间、原因）/ unknown，
   thisUpdate、nextUpdate、nonce、附带的证书）。`verify(cert, issuer, &OcspValidation)` 要求：
   响应成功；签名者是签发者本身，或者是附带的、与响应者 ID 匹配、由签发者签发并签名、带
   id-kp-OCSPSigning、存在 keyUsage 时含 digitalSignature、在 now ± skew 内有效的证书；
   ResponseData 上的签名有效；没有不支持的关键扩展；若设置了期望的 nonce 则必须一致（常数时间
   比较；接受 RFC 8954 的 OCTET STRING 形式与原始形式）；有一个单个响应的 CertID
   （SHA-1/256/384/512）指向该证书；thisUpdate ≤ now + skew，且 nextUpdate（缺失时用
   thisUpdate + `max_age`，默认一天）≥ now − skew。错误（`UnauthorizedResponder`、
   `BadSignature`、`NonceMismatch`、`NoMatchingResponse`、`RevocationInfoNotYetValid`、
   `RevocationInfoExpired`、`OcspStatus`）表示“不可信”；`Ok(Unknown)` 是响应者自己的回答。
   `OcspRequest` 编码请求（SHA-1 CertID，可选 nonce），与 `openssl ocsp` 生成的逐字节相同。
5. **供获取使用的钩子**：`Certificate::crl_distribution_points()`（fullName、reasons、
   cRLIssuer）、`ocsp_urls()` 与 `ca_issuer_urls()`（authorityInfoAccess）告诉应用去哪里获取；
   这两个扩展宽松解析（格式错误只丢掉该指针，证书照样能解析）。`CrlParams` 与
   `OcspResponseParams` 生成已签名的 CRL 与响应，供测试、开发用 CA 以及自行签发装订响应的服务器
   使用。
6. **`akio-tls`**（新增的公开 API）：`RevocationPolicy::{Off（默认）, SoftFail, HardFail}`；
   `ClientConfigBuilder::ocsp_policy(policy)` 校验服务器为叶证书装订的响应（TLS 1.3：叶证书
   CertificateEntry 中的 status_request，在收到 Certificate 时检查；TLS 1.2：CertificateStatus，
   在收到 ServerKeyExchange 时检查），策略不为 Off 时自动请求装订。软失败只拒绝可信且当前的
   “revoked”（`certificate_revoked`）；硬失败要求可信且当前的“good”（否则
   `bad_certificate_status_response`，或 `certificate_revoked`）。`Crls`（DER 或 PEM）配合
   `ClientConfigBuilder::crls(crls, policy)` 与 `ServerConfigBuilder::client_crls(crls, policy)`
   对服务器证书链和客户端证书执行第 3 条的链检查（被吊销：`certificate_revoked`；硬失败下未被
   覆盖：`certificate_unknown`）。恢复的会话不再检查（不发送证书）；`insecure_skip_verify` 跳过
   OCSP；刷新 CRL 需要构建新的配置。
7. **未实现**：间接 CRL 以及由 CA 单独的 CRL 签名密钥签发的 CRL；不获取 freshestCRL 指向的
   delta CRL（任何东西都不获取）；签名的 OCSP 请求；中间证书的 OCSP 检查（装订只覆盖叶证书；
   未实现 `status_request_v2`）；TLS 1.3 客户端认证中的 OCSP 响应；OCSP must-staple（TLS
   feature）扩展的检查。

## 影响

- 客户端只需配置即可拒绝被吊销的服务器，服务器也能拒绝被吊销的客户端证书。测试：OpenSSL 生成的
  CRL（完整、基于 1 号的 delta、带 fullName 的 IDP onlyUser、根 CRL）与 OCSP 响应（委托响应者、
  CA 自签、byKey、SHA-256 CertID、无 nextUpdate、nonce、revoked、certificateHold、unknown、两个
  单个响应、没有 OCSPSigning EKU、由其他 CA 认证的响应者、未附带签名者证书），覆盖过期与时钟
  偏差的两侧边界、损坏的签名以及每一种截断（`akio-x509/tests/revocation.rs`，测试数据由
  `tests/data/revocation/gen.sh` 生成）；生成的 CRL 与响应覆盖由 delta 解除的暂停、onlyCA 范围、
  部分原因覆盖、被吊销的中间证书与过期的响应者证书；内存中的 TLS 1.3 与 1.2 握手覆盖每种策略与
  响应类型，以及两端的 CRL（`akio-tls/src/proto/revocation_tests.rs`）；互通：本库客户端对
  `openssl s_server -status_file`（正常、吊销、软/硬失败下缺少装订）以及 OpenSSL 生成的 CRL
  （`tools/interop/tls/run.sh`）。
- 所有策略关闭（默认）时握手的工作量不变：校验器本来就构建好的路径改为返回而不是丢弃，各项
  检查各只是一次比较。gpu51 上的 `tls-bench handshakes`（`quiet.sh`、同一轮 A/B、5 组交替、取中位数、
  每秒完整握手数）：X25519 改前 5460、改后 5436；secp256r1 5514 / 5509；X25519 配 RSA-2048 证书
  3300 / 3295（1.00 倍，属噪声；同一轮中 rustls 的波动幅度相同）。
- 模糊测试目标 `x509_crl` 与 `x509_ocsp`（以 OpenSSL 测试数据为种子）在 gpu51 上各运行 661 秒
  （分别 2560 万与 1290 万个输入），没有失败；`fuzzing::tests` 在 stable 上回放它们的语料。
- 软失败的保护力度天生有限（能拦截或剥离装订响应的攻击者即可让它通过）；它面向无法承受响应者
  宕机导致服务中断的部署。硬失败与不装订的服务器无法连接。
- `CrlSet` 位于不可变的配置中：刷新 CRL 的应用需构建新配置（相对于下载 CRL 开销很小）并替换。
