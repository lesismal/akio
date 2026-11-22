# ADR-046：证书策略、间接 CRL、Ed448、X448 与 DSA 验签

[English](046-x509-policies-indirect-crls-ed448-dsa.md) | 简体中文

状态：已采纳（2026-11-19）

## 背景

akio-x509 的 README 列出了它尚未实现的 RFC 5280 路径验证内容：证书策略、间接 CRL 以及由 CA
另一把密钥签发的 CRL、签名的 OCSP 请求、任何网络获取、Ed448 和 DSA。政府和企业 PKI（以及任何用
NIST PKITS 做验证的人）依赖证书策略；这类 PKI 用间接 CRL 和独立的 CRL 签名密钥发布吊销信息；
Ed448 是 RFC 8032 / RFC 8410 和 TLS 1.3（签名方案 `ed448`、组 `x448`）中的另一条 EdDSA 曲线；DSA
证书仍存在于遗留 PKI 和 PKITS 中。

原先的验证器从叶子证书出发深度优先建链，每延伸一级就检查该证书的吊销状态，且只接受由该证书签发者
本身签名的 CRL。证书策略扩展被当作“已理解”而忽略：关键的 certificatePolicies 能通过，关键的
policyConstraints 却会因“未知关键扩展”而失败。

## 决定

1. **akio-crypto**（内部层级；枚举均为 `#[non_exhaustive]`）：
   - `hash::{Shake128, Shake256}`（FIPS 202）：Keccak-f[1600] 海绵结构，提供 `update` 与
     `squeeze`（可扩展输出，不实现 `Hash` trait）。
   - `ed448`（RFC 8032 §5.2，纯 Ed448，空上下文）：`SigningKey::{from_seed, generate, seed,
     verifying_key, sign}`、`VerifyingKey::{from_bytes, as_bytes, is_weak, verify}`。验签与
     `ed25519` 一样严格（`S` 必须规范、公钥未用位为零、无余因子方程，按 `R` 的编码比较）。
   - `x448`（RFC 7748）：`x448()`、`PrivateKey::{generate, from_bytes, to_bytes, public_key,
     diffie_hellman}`（拒绝全零结果）、`BASEPOINT`、`KEY_LEN`。
   - 二者基于私有模块 `curve448`：GF(2⁴⁴⁸ − 2²²⁴ − 1) 与标量域使用 `field.rs` 的通用 Montgomery
     代码（7 个 limb、掩码修正、费马求逆），edwards448 用射影坐标和 RFC 8032 的完备公式；秘密标量
     使用固定 4 位窗口并对整张表做掩码扫描，梯子使用掩码交换。不写汇编：这两条曲线很少用，可移植的
     常数时间代码是合适的取舍。`tools/ct-dudect` 新增 `x448`、`ed448-keygen`、`ed448-sign`。
   - `dsa`（FIPS 186-4 §4.7），仅验签：`PublicKey::{from_components, from_der, params_der,
     key_der, p_bits, q_bits, verify, verify_prehash}`。只接受 FIPS 规定的长度（1024/160、
     2048/224、2048/256、3072/256），密钥在构造时检查一次（`1 < g, y < p`，`g^q = y^q = 1 mod
     p`）。基于现有 bignum 代码，可变时间（数据均为公开）。
   - `rsa::HashAlg::Sha224`（用于 DSA-SHA224；RSA 签名不提供）、
     `pkey::SignatureAlgorithm::{Ed448, DsaSha1, DsaSha224, DsaSha256}`、
     `pkey::PublicKey::{Ed448, Dsa}`、`pkey::PrivateKey::Ed448`（PKCS#8），以及 `der::oid` 中的
     OID（`ED448`、`X448`、`DSA`、`DSA_WITH_SHA*`）。不支持从签发者继承 DSA 参数
     （SubjectPublicKeyInfo 中缺省参数，RFC 3279 §2.3.2）。
2. **akio-x509，证书策略**（RFC 5280 §6.1）：严格解析 certificatePolicies、policyMappings、
   policyConstraints 与 inhibitAnyPolicy（重复的策略 OID、空的 policyConstraints 或映射列表都是
   编码错误），并提供访问器（`Certificate::{certificate_policies, policy_mappings,
   policy_constraints, inhibit_any_policy, is_self_issued}`、`PolicyConstraints`、
   `ext::{ANY_POLICY, POLICY_MAPPINGS, POLICY_CONSTRAINTS, INHIBIT_ANY_POLICY}`）。每条被验证的
   路径都做策略处理，输入来自 `Verifier::policies(PolicyOptions)`（`initial_policy_set`，空表示
   any-policy；`explicit_policy`；`inhibit_policy_mapping`；`inhibit_any_policy`）。实现采用
   **RFC 9618 的策略图**而不是策略树：每一层每个策略 OID 至多一个节点，构造的映射无法让它呈指数
   增长（CVE-2023-0464）。`Verifier::verify_path` 返回 `VerifiedPath { chain, policies }`，其中
   `policies` 是用户约束策略集（`ValidPolicies::{Any, Set}`）；`verify` 仍只返回证书链。失败为
   `Error::PolicyViolation`。默认选项下，只有当某张证书的 policyConstraints 要求显式策略而路径上
   没有有效策略时才会失败，这是 RFC 5280 对所有验证器的要求。
3. **akio-x509，测试暴露出的其余 §6.1 内容**：自签发（self-issued）的中间证书不计入
   pathLenConstraint（§6.1.4 (l)），也不受名称约束（§6.1.3 (b)）；实现 rfc822Name 与 URI 名称约束
   （邮箱、主机和 `.domain` 三种形式；没有 authority 或使用 IP 字面量的 URI 按失败处理），叶子证书
   主题中的旧式 `emailAddress` 属性也按 rfc822Name 约束检查（此前这里的地址可以绕过约束）；
   `Verifier::allow_ca_end_entity(bool)` 允许把 CA 证书当作终端实体来验证（PKITS 需要，Web PKI
   默认仍为“不允许”）。
4. **akio-x509，吊销（§6.3.3）**：验证器改为在候选路径到达根证书之后、自顶向下检查吊销，因此知道
   信任锚是谁。CRL 的适用范围按证书判断：对每个分发点，CRL 签发者必须是证书的签发者，或者对于
   **间接 CRL**（IDP 中的 `indirectCRL`）是该分发点的 cRLIssuer；IDP 名称必须与分发点名称（包括
   `nameRelativeToCRLIssuer`：`DistributionPoint::relative_name`、
   `IssuingDistributionPoint::relative_name`）或其 cRLIssuer 匹配；覆盖的原因是 IDP 的
   onlySomeReasons 与分发点 reasons 的交集。间接 CRL 的条目属于其 certificateIssuer 扩展所指的
   签发者，并沿用到后续条目（`RevokedCertificate::certificate_issuer`、
   `Crl::find_for(serial, issuer)`）。CRL 签名先用证书签发者验证；否则用一张名称为 CRL 签发者且带
   cRLSign 的证书验证——即 CA 的**独立 CRL 签名密钥**或间接 CRL 签发者——在中间证书、新增的
   `Verifier::crl_signers(&[Certificate])` 和根证书中查找，且它自己的路径必须验证到**同一个信任
   锚**，包括其吊销状态（签名者路径上的签名者路径不再继续检查吊销；全部计入
   `MAX_SIGNATURE_CHECKS`）。`CrlSet::status` 保持原有约定（只信任签发者自己的密钥），并增加分发点
   匹配。增量 CRL 必须与其所扩展的完整 CRL 有相同的签发者和 IDP。序列号按有符号 INTEGER 内容比较
   （−1 的 CRL 条目不再匹配序列号为 255 的证书）。
5. **akio-tls**：组 `x448`（0x001e，在默认列表的最后，因此 ClientHello 会列出它，但首个密钥共享
   仍为 X25519）和签名方案 `ed448`（0x0808），用于 TLS 1.3 和 1.2（ECDSA 套件），包括证书
   （`Group::X448` 位于隐藏的 `__proto` 模块）。
6. **验证**：NIST PKITS 由 `crates/akio-x509/tests/pkits.rs` 运行（`tools/pkits/prepare.sh` 下载
   测试套件，不纳入仓库）。第 4 节的每个测试都按 PKITS 文档列出的设置运行，吊销为 hard-fail 模式：
   248 次运行中 242 次符合预期；其余 6 次已列出原因（DSA 参数继承；名称按 DER 字节链接而不做
   RFC 4518 的大小写和空白折叠，这是从第一版起的有意选择）。DSA 使用 FIPS 186-4 SigVer 向量，
   Ed448 与 X448 使用 RFC 8032 与 RFC 7748 的向量，另有 OpenSSL 生成的 Ed448、DSA 证书与 CRL，以及
   akio-tls 与 `openssl s_server` / `s_client` 之间使用 X448 和 Ed448 的互通测试。

有意不做：

- **签名的 OCSP 请求**（RFC 6960 §4.1.2 的可选签名）：公共应答器并不要求（CA 遵循的 RFC 5019
  轻量级规范发送未签名请求，多数应答器忽略签名），而且只有应用持有的客户端证书和私钥才能签名。
  `OcspRequest` 保持不签名。
- **通过网络获取 CRL、OCSP 响应或签发者证书**：akio-x509 与 akio-tls 是 sans-io 的；获取需要依赖
  图中位于它们之上的 HTTP 客户端，会让握手阻塞或停顿在第三方上（rules.md 第 1 条），会向 CA 泄露
  客户端访问了哪些站点，还会去访问攻击者提供的证书中的 URL（SSRF）。由应用负责获取；
  `crl_distribution_points`、`ocsp_urls` 与 `ca_issuer_urls` 给出地址。

## 影响

- 默认验证器会拒绝那些 policyConstraints 要求显式策略而路径上没有的链（符合 RFC；Web PKI 链不带
  这类约束）。策略扩展格式错误的证书不再能解析。
- 配置了 CRL 时，吊销在找到路径之后检查，而不是在搜索过程中：被吊销的中间证书仍会让搜索尝试其他
  路径。路径上错误的优先级与以前相同。
- `RevokedCertificate`、`DistributionPoint`、`IssuingDistributionPoint` 各增加一个公开字段（结构体
  字面量需要补上）；`pkey`/`rsa` 的枚举增加变体（它们是 non-exhaustive 的）。
- Ed448 与 X448 比带汇编和预计算表的 Ed25519、X25519 慢一个数量级（在 Apple M 系列单核上
  `pk_bench 448`：Ed448 签名 5.5k/s、验签 4.1k/s，X448 5.6k/s，DSA-2048 验签 1.2k/s）；它们都不在
  默认的快速路径上（X448 排在最后，从不作为首个密钥共享发送）。
