# only-crypto

[English](README.md)

[`only`](https://github.com/lesismal/only) 各 crate 使用的无依赖密码学原语，安全 Rust
（`#![deny(unsafe_code)]`，只依赖 `std`；唯一的例外是驱动 CPU AES 指令的模块；操作系统随机数的系统调用放在
`only-sys` 中）。

| 模块 | 内容 |
|---|---|
| `hash` | SHA-1、SHA-224、SHA-256、SHA-384、SHA-512、MD5（流式与一次性，`Hash` trait） |
| `mac` | 基于任意 `Hash` 的 HMAC（常数时间 `verify`） |
| `kdf` | HKDF（RFC 5869）、PBKDF2-HMAC（RFC 8018） |
| `crc` | CRC-32（IEEE，与 `crc32fast` 一致）、CRC-32C（Castagnoli），slicing-by-8 |
| `aes` | AES-128/192/256：CPU 支持时使用 AES-NI / ARMv8 AES（运行时检测），否则使用常数时间的 fixsliced 软件实现（没有以密钥为下标的查表）；ECB 分组、CTR |
| `gcm` | AES-GCM，常数时间 GHASH（BearSSL `ctmul64`） |
| `chacha` | ChaCha20、Poly1305、ChaCha20-Poly1305（RFC 8439） |
| `base64` | 标准 / URL 安全字母表，带或不带填充，严格解码 |
| `rand` | `fill_random`（getrandom / getentropy / `/dev/urandom`）、`ChaChaRng` |
| `ct_eq` | 常数时间比较 |
| `x25519` | X25519 密钥协商（RFC 7748），拒绝全零共享密钥 |
| `ed25519` | Ed25519（RFC 8032）：确定性签名，严格验证（`S` 必须规范，按编码比较 `R`） |
| `p256`、`p384` | NIST P-256 / P-384 上的 ECDH 与 ECDSA：RFC 6979 nonce，可用任意 `Hash` 预哈希，DER 与定长（P1363）签名，带校验的 SEC1 点（压缩与非压缩） |
| `rsa` | RSA PKCS#1 v1.5 与 PSS（MGF1），SHA-256/384/512（SHA-1 仅验证），模数 2048–8192 位；私钥运算使用 CRT、盲化并校验结果 |
| `der`、`pem` | 严格 DER 读写器（拒绝 BER）、常用 OID、PEM（RFC 7468） |
| `pkey` | 覆盖以上所有算法的 `PrivateKey` / `PublicKey`：PKCS#8 v1/v2、SEC1、PKCS#1、SubjectPublicKeyInfo、PEM；按 TLS 与 X.509 命名的 `SignatureAlgorithm` |

它在 `only-kcp`、`only-turn`、`only-ws`、`only-http`、`only-media`、`only-bittorrent` 和
`only-webrtc` 中替代了 sha1、sha2、md-5、hmac、pbkdf2、aes、aes-gcm、ctr、crc32fast、base64 与
getrandom（DEV-PLAN“长期：不依赖第三方库”，第 A 波）。

```rust
use only_crypto::gcm::AesGcm;
use only_crypto::hash::Sha256;
use only_crypto::mac::Hmac;

let tag = Hmac::<Sha256>::mac(b"key", b"message");
let gcm = AesGcm::new(&[0u8; 16]).unwrap();
let sealed = gcm.encrypt(&[0u8; 12], b"aad", b"plaintext");
assert_eq!(gcm.decrypt(&[0u8; 12], b"aad", &sealed).unwrap(), b"plaintext");
# let _ = tag;
```

这是一个实现用的 crate：它的 API 跟随其他 `only` crate 的需要，可能在任何发布中变化（内部层级，见
docs/api-stability.zh-CN.md）。它不是通用密码学库（不清零密钥；只有 AES 使用 CPU 指令，哈希、GHASH 与 CRC-32 是可移植代码）。
公钥部分是 DEV-PLAN 第 C、D 波计划中自研 TLS/DTLS/QUIC 协议栈的基础；证书相关功能在
[`only-x509`](../only-x509) 中。

## 公钥运算的时间特性

- 与秘密相关的代码没有依赖秘密的分支或内存下标。P-256、P-384 以及所有标量域使用 64 位 limb 的
  Montgomery 运算（CIOS），最后一步减法用掩码完成，按 limb 数泛型实现，常量在编译期推导；求逆用固定公开
  指数的费马幂运算。Curve25519 使用 2⁵¹ 进制。
- 点运算使用完备公式（`a = -3` 的 Renes–Costello–Batina 公式、统一的扩展 Edwards 加法），任何输入都走
  同一路径。秘密标量乘法使用固定 4 位窗口（可变基点）或预计算的 `j·16ⁱ·G` 梳状表（固定基点），每次查表都
  用掩码读取全部 16 项；X25519 使用 RFC 7748 的 Montgomery 阶梯和掩码交换。
- RSA 私钥运算：CRT 下按完整指数长度的固定 4 位窗口幂运算和掩码选表，基数盲化（每个密钥保存 `rᵉ` 与
  `r⁻¹`，在各素数域中用费马求逆，每次使用后平方），并在输出签名前检查 `sᵉ = m`。模约简是常数时间的；
  `p`/`q` 的 limb 数（公开信息）不做隐藏。
- 已知的可变时间部分，都只涉及公开数据：签名验证（ECDSA 的 `u₁G + u₂Q`、Ed25519 的 `[k]A`、RSA 的
  `sᵉ`）、点的解码与校验、范围检查的 `Option`/`Result` 结果、RFC 6979 的拒绝循环（概率约 2⁻³²）、
  `SecretKey::generate` 的拒绝采样、仿射坐标转换对无穷远点的分支（合法秘密标量不会出现）。
- 局限：掩码经过 `std::hint::black_box`，只能阻止而不能保证优化器不重新引入分支；尚未在二进制层面检查
  （还没有运行 dudect 或 ctgrind）。密钥不会被清零。

## 与 ring 的性能对比

`cargo run --release -p only-crypto --example pk_bench`（Apple M 系列，单核，每秒操作数；ring 的 P-256、
X25519 与 RSA Montgomery 乘法使用汇编）：

| 操作 | only | ring | 比值 |
|---|---:|---:|---:|
| Ed25519 签名 | 104,900 | 128,300 | 0.82x |
| Ed25519 验证 | 31,600 | 48,000 | 0.66x |
| X25519 协商 | 46,500 | 54,500 | 0.85x |
| P-256 ECDSA 签名 | 28,200 | 84,300 | 0.34x |
| P-256 ECDSA 验证 | 9,700 | 32,800 | 0.30x |
| P-256 ECDH（含点解码） | 12,100 | 37,000 | 0.33x |
| P-384 ECDSA 签名 | 9,800 | 4,300 | 2.27x |
| P-384 ECDSA 验证 | 3,100 | 2,400 | 1.29x |
| P-384 ECDH | 3,600 | 4,600 | 0.78x |
| RSA-2048 PKCS#1 签名 | 1,130 | 3,000 | 0.38x |
| RSA-2048 PKCS#1 验证 | 35,500 | 88,600 | 0.40x |

（ring 的 ECDH 数字包含生成其临时密钥。）后续：专用的 P-256 域运算（Solinas 约简或 fiat-crypto 风格）、
wNAF / 预计算表验签、RSA 的 Karatsuba 或 CPU 专用乘法。

## 测试

- 已知答案测试：NIST CAVP（SHAVS、HMACVS、AESAVS ECB、GCMVS）、FIPS 197、SP 800-38A、GCM
  规范、RFC 1321、2202、4231、5869、6070、3720、4648、8439，以及 Wycheproof（AES-GCM、
  ChaCha20-Poly1305、HMAC-SHA1/SHA256、HKDF-SHA256），数据放在 `tests/data/`。
- `tests/compat.rs` 把每个原语与被替代的 crate 交叉比对（仅作为 dev-dependency）；`fuzz/` 中有差分
  模糊测试目标 `crypto_hash`、`crypto_aead`、`crypto_base64`。
- `cargo run --release -p only-crypto --example bench` 与被替代的 crate 比较吞吐量。
- 公钥（`tests/pk_kat.rs`）：Wycheproof 的 X25519、Ed25519、ECDSA P-256/SHA-256（DER 与 P1363）、
  P-384/SHA-384 与 SHA-512、ECDH P-256（SPKI 与原始点）与 P-384、RSA PKCS#1 v1.5 验证（2048/SHA-256、
  3072/SHA-384、4096/SHA-512）、RSA-PSS 验证（2048/SHA-256/32、4096/SHA-512/64）、RSA PKCS#1 v1.5
  签名生成；单元测试中有 RFC 7748、8032 与 6979 向量。所有 "valid" 向量都被接受，所有 "invalid" 向量都被拒绝。
- `tests/pk_compat.rs` 与 ring 和 RustCrypto p256/p384 交叉比对（Ed25519、ECDSA RFC 6979 与 RSA PKCS#1
  签名逐字节一致；互相验证；ECDH 与 X25519 共享密钥一致；PKCS#8 密钥双向互通）。`tests/sig_diff.rs`
  回放 `crypto_sig_verify` 模糊测试目标（对合法、变异与任意的签名和密钥，与 ring 的验证结果比较）；
  only-x509 的测试覆盖 OpenSSL 生成的密钥与签名。

## 致谢

AES 核心改编自 RustCrypto `aes` crate 的 fixsliced 软件后端（MIT OR Apache-2.0），其源自
Alexandre Adomnicai 的 fixslicing C 代码；GHASH 参照 Thomas Pornin 的 BearSSL
`ghash_ctmul64.c`（MIT）；Poly1305 参照 poly1305-donna（公有领域）。
