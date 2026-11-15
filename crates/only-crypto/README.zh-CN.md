# only-crypto

[English](README.md)

[`only`](https://github.com/lesismal/only) 各 crate 使用的无依赖密码学原语，Rust 实现
（`#![deny(unsafe_code)]`，只依赖 `std`；例外是六个驱动 CPU 指令的小模块，运行时检测 CPU 特性；操作系统随机数
的系统调用放在 `only-sys` 中）。

| 硬件路径（运行时检测，常数时间的可移植回退实现） | x86_64 | aarch64 |
|---|---|---|
| AES 分组密码、CTR（同时处理 8 个分组） | AES-NI | ARMv8 AES |
| AES-GCM（GHASH 与 CTR 融合） | VAES + VPCLMULQDQ + AVX-512（每次归约 16 个分组），否则 PCLMULQDQ + AES-NI（8 个） | PMULL + ARMv8 AES |
| SHA-1、SHA-256 | SHA-NI | ARMv8 SHA1/SHA2 |
| CRC-32、CRC-32C | VPCLMULQDQ + AVX-512 或 PCLMULQDQ 折叠、SSE4.2 `crc32` | ARMv8 CRC32 |
| ChaCha20 | AVX2（8 个分组） | 可移植的 4 分组并行布局，由编译器向量化 |

设置 `ONLY_CRYPTO_PORTABLE=1`（只读取一次）可强制全部使用可移植实现；测试会在设置与不设置时各跑一遍全部已知
答案向量。在 Miri 下不会检测到任何特性。

| 模块 | 内容 |
|---|---|
| `hash` | SHA-1、SHA-224、SHA-256、SHA-384、SHA-512、MD5（流式与一次性，`Hash` trait） |
| `mac` | 基于任意 `Hash` 的 HMAC（常数时间 `verify`） |
| `kdf` | HKDF（RFC 5869）、PBKDF2-HMAC（RFC 8018） |
| `crc` | CRC-32（IEEE，与 `crc32fast` 一致）、CRC-32C（Castagnoli）：CPU 指令，否则 slicing-by-8 |
| `aes` | AES-128/192/256：CPU 支持时使用 AES-NI / ARMv8 AES（运行时检测），否则使用常数时间的 fixsliced 软件实现（没有以密钥为下标的查表）；ECB 分组、CTR |
| `gcm` | AES-GCM：具备 VAES + VPCLMULQDQ + AVX-512 时单趟 512 位处理（每次迭代与每次归约 16 个分组），否则 PCLMULQDQ / PMULL GHASH 与 AES-NI / ARMv8 的 CTR 单趟融合，再否则使用常数时间 GHASH（BearSSL `ctmul64`） |
| `chacha` | ChaCha20（AVX2 下一次 8 个分组，否则 4 分组并行）、Poly1305（44 位 limb，每步两个分组）、ChaCha20-Poly1305（RFC 8439） |
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
docs/api-stability.zh-CN.md）。它不是通用密码学库（不清零密钥；只有宽 AES-GCM 内核与 CRC 折叠使用汇编，因为其 VAES / VPCLMULQDQ / AVX-512 intrinsic 比 MSRV 新；SHA-512、MD5、Poly1305 与公钥运算是可移植的 Rust 代码）。
公钥部分是 DEV-PLAN 第 C、D 波计划中自研 TLS/DTLS/QUIC 协议栈的基础；证书相关功能在
[`only-x509`](../only-x509) 中。

## 公钥运算的时间特性

- 与秘密相关的代码没有依赖秘密的分支或内存下标。P-384 以及所有标量域使用 64 位 limb 的 Montgomery 运算
  （CIOS 乘法，平方用半规模乘积加 REDC），最后一步减法用掩码完成，按 limb 数泛型实现，常量在编译期推导。
  P-256 基域有专用的约简（`-p⁻¹ mod 2⁶⁴ = 1`，每一步只需一次真正的乘法），求逆使用加法链（255 次平方、
  12 次乘法）；其他求逆以公开指数 `p - 2` 做 4 位固定窗口幂运算。Curve25519 使用 2⁵¹ 进制并有专用平方。
- 点运算使用完备公式（`a = -3` 的 Renes–Costello–Batina 公式，包括与仿射点的混合加法；统一的扩展 Edwards
  加法），任何输入都走同一路径。`[k]G` 把 `k` 重新编码为有符号 4 位数字（掩码算术），每个数字加一个仿射梳形表
  项 `|d|·16ⁱ·G`：每次查表用掩码读取该行全部 8 项，取负与跳过零数字都是掩码选择。可变基点的秘密标量乘法
  使用固定 4 位窗口并读取全部 16 项；X25519 使用 RFC 7748 的 Montgomery 阶梯和掩码交换。
- RSA 私钥运算：CRT 下按完整指数长度的固定 4 位窗口幂运算和掩码选表（1024 至 4096 位素数使用定长
  Montgomery 代码，平方使用半规模乘积），基数盲化（每个密钥保存 `rᵉ` 与 `r⁻¹`，在各素数域中用费马求逆，
  每次使用后平方），并在输出签名前检查 `sᵉ = m`。模约简是常数时间的；`p`/`q` 的 limb 数（公开信息）不做隐藏。
- 已知的可变时间部分，都只涉及公开数据：签名验证（ECDSA 的 `u₁G + u₂Q` 使用 Jacobian 坐标、宽度 7 / 5 的
  wNAF 与射影坐标下的 `x ≡ r` 检查，Ed25519 的 `[s]B - [k]A` 使用交错 wNAF，RSA 的 `sᵉ`）、预计算表的构造、
  点的解码与校验、范围检查的 `Option`/`Result` 结果、RFC 6979 的拒绝循环（概率约 2⁻³²）、
  `SecretKey::generate` 的拒绝采样、仿射坐标转换对无穷远点的分支（合法秘密标量不会出现）。
- 局限：掩码经过 `std::hint::black_box`，只能阻止而不能保证优化器不重新引入分支；去掉它时 LLVM 确实会把部分
  带掩码的模修正编译成跳转，因此即使有性能代价也保留这道屏障。已检查 P-256 / P-384 点运算、域乘法、平方与
  求逆以及 X25519 阶梯在 x86_64 与 aarch64 上生成的代码：除循环控制外没有条件分支。尚未运行统计检测
  （dudect、ctgrind）。密钥不会被清零。所用的 CPU 指令（AES、无进位乘法、SHA、CRC32、AVX2）是常数时间的。

## 性能

AMD Ryzen 7 7800X3D（x86_64，单核），`cargo run --release -p only-crypto --example bench` 与
`--example pk_bench`；“优化前”为上一个版本，完整表格以及 TLS / KCP 数据见
[docs/BENCHMARKS.zh-CN.md](../../docs/BENCHMARKS.zh-CN.md)：

| 操作 | 优化前 | 优化后 | 对比 RustCrypto / ring |
|---|---:|---:|---:|
| SHA-1，16 KiB（MB/s） | 697 | 2 543 | sha1 的 1.00 倍 |
| SHA-256，16 KiB | 366 | 2 383 | sha2 的 1.00 倍 |
| CRC-32，16 KiB | 19 992 | 74 885 | crc32fast 的 1.02 倍 |
| AES-128-GCM 加密，16 KiB | 6 455 | 15 048 | ring 的 1.19 倍 |
| AES-128-GCM 加密，1400 B | 4 249 | 8 163 | ring 的 1.11 倍 |
| AES-128-GCM 加密，64 B | 611 | 1 185 | ring 的 1.10 倍 |
| ChaCha20-Poly1305 加密，16 KiB | 588 | 1 757 | chacha20poly1305 的 0.89 倍 |
| Ed25519 验签（次/秒） | 18 289 | 27 161 | ring 的 0.85 倍 |
| X25519 协商 | 28 865 | 30 945 | ring 的 0.84 倍 |
| P-256 ECDSA 签名 | 23 435 | 34 184 | ring 的 0.45 倍 |
| P-256 ECDSA 验签 | 8 043 | 13 397 | ring 的 0.51 倍 |
| P-256 ECDH | 10 075 | 10 390 | ring 的 0.34 倍 |
| P-384 ECDSA 验签 | 2 426 | 3 798 | ring 的 2.03 倍 |
| RSA-2048 PKCS#1 签名 | 871 | 1 199 | ring 的 0.49 倍 |
| RSA-2048 PKCS#1 验签 | 29 019 | 39 557 | ring 的 0.60 倍 |

ring 的 AES-GCM、P-256、X25519 与 RSA 使用汇编。AES-GCM 与 CRC 行对比的是此前没有 VAES / VPCLMULQDQ
的代码（`--example gcm-sizes` 对比 ring，`--example bench` 对比 crc32fast）；在 Zen 4 上，512 位内核在所有
长度上都快于同一内核的 256 位寄存器版本。后续：给没有 AVX-512 的 CPU 的 VAES + AVX2 内核、SIMD
Poly1305、更便宜的 P-256 秘密标量倍点、RSA 的 Karatsuba。

## 测试

- 已知答案测试：NIST CAVP（SHAVS、HMACVS、AESAVS ECB、GCMVS）、FIPS 197、SP 800-38A、GCM
  规范、RFC 1321、2202、4231、5869、6070、3720、4648、8439，以及 Wycheproof（AES-GCM、
  ChaCha20-Poly1305、HMAC-SHA1/SHA256、HKDF-SHA256），数据放在 `tests/data/`。
- `tests/compat.rs` 把每个原语与被替代的 crate 交叉比对（仅作为 dev-dependency）；`fuzz/` 中有差分
  模糊测试目标 `crypto_hash`、`crypto_aead`（也让宽内核、128 位与可移植三条 AES-GCM 路径原地与非原地
  互相比较）、`crypto_base64`。
- 宽 AES-GCM 内核（`gcm::tests`）：0..=600 的每个长度与若干大长度上与 128 位路径和可移植实现比较，
  覆盖未对齐、原地与非原地、组内 32 位计数器回绕，大消息还与 ring 比较；它只在具备 VAES 与 AVX-512
  的 CPU 上运行，因此这些测试要在这样的机器（Zen 4）上原生运行。
- 硬件路径：单元测试把每条硬件路径与可移植实现比较（AES、CTR、GCM、SHA-1、SHA-256 的
  `hardware_matches_portable`，CRC 的 `hardware_matches_table`，多分组 ChaCha20 与两分组 Poly1305 对比逐分组
  计算），整个测试套件还会在 x86_64 与 aarch64 上设置 `ONLY_CRYPTO_PORTABLE=1` 再跑一遍。
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
