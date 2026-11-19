# only-crypto

[English](README.md)

[`only`](https://github.com/lesismal/only) 各 crate 使用的无依赖密码学原语，Rust 实现
（`#![deny(unsafe_code)]`，只依赖 `std`；例外是十二个驱动 CPU 指令的小模块（运行时检测 CPU 特性），以及让 TLS 记录层
直接在向量空闲容量中加密和解密的 AEAD 输出缓冲区模块 `fill`；操作系统随机数
的系统调用放在 `only-sys` 中）。

| 硬件路径（运行时检测，常数时间的可移植回退实现） | x86_64 | aarch64 |
|---|---|---|
| AES 分组密码、CTR（同时处理 8 个分组） | AES-NI | ARMv8 AES |
| AES-GCM（GHASH 与 CTR 融合） | VAES + VPCLMULQDQ + AVX-512（每次归约 16 个分组，掩码尾部），否则 VAES + VPCLMULQDQ + AVX2（16 个），否则 PCLMULQDQ + AES-NI（8 个） | PMULL + ARMv8 AES |
| SHA-1、SHA-256 | SHA-NI | ARMv8 SHA1/SHA2 |
| CRC-32、CRC-32C | VPCLMULQDQ + AVX-512 或 PCLMULQDQ 折叠、SSE4.2 `crc32` | ARMv8 CRC32 |
| ChaCha20（`chacha::hw`、`chacha::hw::avx512`） | AVX-512 内联汇编（`vprold`；每次迭代 16 个分组，余下部分 8 或 4 个，4 个时每个寄存器存一行；不完整的最后一组在字节掩码下处理），否则 AVX2（8 个分组） | 可移植的 4 分组并行布局，由编译器向量化 |
| Poly1305（`chacha::hw::ifma`、`chacha::hw`） | AVX-512 IFMA 内联汇编（每步 8 个分组，用于 256 字节及以上的连续分组），否则 AVX2（以 2²⁶ 为基数每步 4 个分组，用于 512 字节及以上），否则 2⁶⁴ 进制标量实现 | 2⁶⁴ 进制标量实现 |
| P-256 域与群阶运算、X25519 阶梯（`ec::hw`、`curve25519::hw`；`ec::hw_aarch64`、`curve25519::hw_aarch64`） | BMI2 + ADX 内联汇编（`mulx`、`adcx`/`adox`） | 内联汇编（`MUL`/`UMULH`、`ADDS`/`ADCS`、`CSEL`；所有 ARMv8.0 CPU；尚未做性能测试） |
| RSA 模幂（`bignum::ifma`、`bignum::hw`） | AVX-512 IFMA（`vpmadd52luq`/`vpmadd52huq`）处理 2048 至 4096 位密钥的 CRT 两半以及 2048 至 4096 位模数的公开运算（验签），否则 BMI2 + ADX 内联汇编（Montgomery 乘法与平方） | 可移植实现 |

设置 `ONLY_CRYPTO_PORTABLE=1`（只读取一次）可强制全部使用可移植实现；测试会在设置与不设置时各跑一遍全部已知
答案向量。在 Miri 下不会检测到任何特性。

| 模块 | 内容 |
|---|---|
| `hash` | SHA-1、SHA-224、SHA-256、SHA-384、SHA-512、MD5（流式与一次性，`Hash` trait）；SHAKE128、SHAKE256（FIPS 202，`squeeze` 任意长度） |
| `mac` | 基于任意 `Hash` 的 HMAC（常数时间 `verify`） |
| `kdf` | HKDF（RFC 5869）、PBKDF2-HMAC（RFC 8018） |
| `crc` | CRC-32（IEEE，与 `crc32fast` 一致）、CRC-32C（Castagnoli）：CPU 指令，否则 slicing-by-8 |
| `aes` | AES-128/192/256：CPU 支持时使用 AES-NI / ARMv8 AES（运行时检测），否则使用常数时间的 fixsliced 软件实现（没有以密钥为下标的查表）；ECB 分组、CTR、CBC（可带 PKCS #7 填充，用于 HLS `AES-128`） |
| `gcm` | AES-GCM：具备 VAES + VPCLMULQDQ + AVX-512 时整条消息在一次 512 位调用中完成（每次迭代与每次归约 16 个分组，最后一个不完整的组用字节掩码处理），具备 VAES + VPCLMULQDQ + AVX2 时用 256 位寄存器处理完整的 256 字节组，否则 PCLMULQDQ / PMULL GHASH 与 AES-NI / ARMv8 的 CTR 单趟融合，再否则使用常数时间 GHASH（BearSSL `ctmul64`）；`encrypt_append` / `decrypt_append`（隐藏 API，供 TLS 记录层使用）直接写入向量的空闲容量，不先清零 |
| `chacha` | ChaCha20（AVX-512 下一次 16 / 8 / 4 个分组，AVX2 下 8 个，否则 4 分组并行）、Poly1305（IFMA 每步 8 个分组，AVX2 每步 4 个，否则 2⁶⁴ 进制）、ChaCha20-Poly1305（RFC 8439；供 TLS 记录层使用的非原地 `*_detached_from` 与 `*_append`） |
| `base64` | 标准 / URL 安全字母表，带或不带填充，严格解码 |
| `rand` | `fill_random`（getrandom / getentropy / `/dev/urandom`）、`ChaChaRng` |
| `ct_eq` | 常数时间比较 |
| `x25519` | X25519 密钥协商（RFC 7748），拒绝全零共享密钥 |
| `ed25519` | Ed25519（RFC 8032）：确定性签名，严格验证（`S` 必须规范，按编码比较 `R`） |
| `x448`、`ed448` | X448（RFC 7748）与 Ed448（RFC 8032，纯 Ed448、空上下文；与 Ed25519 一样严格验证），ADR-046：基于通用 7 limb Montgomery 域的可移植常数时间代码（固定窗口加掩码查表、梯子的掩码交换），无汇编 |
| `dsa` | 仅 DSA 验签（FIPS 186-4；1024/160、2048/224、2048/256、3072/256；密钥只检查一次），用于遗留证书与 CRL |
| `p256`、`p384` | NIST P-256 / P-384 上的 ECDH 与 ECDSA：RFC 6979 nonce，可用任意 `Hash` 预哈希，DER 与定长（P1363）签名，带校验的 SEC1 点（压缩与非压缩） |
| `rsa` | RSA PKCS#1 v1.5 与 PSS（MGF1），SHA-256/384/512（SHA-1 仅验证），模数 2048–8192 位；私钥运算使用 CRT、盲化并校验结果 |
| `der`、`pem` | 严格 DER 读写器（拒绝 BER）、常用 OID、PEM（RFC 7468） |
| `p521` | NIST P-521 上的 ECDH 与 ECDSA（ADR-049），API 相同、标量 66 字节：默认 SHA-512，基于 521 位的 RFC 6979 nonce，132 字节定长签名；可移植 Rust，独立的 Mersenne 素数域与完备公式 |
| `pkey` | 覆盖以上所有算法的 `PrivateKey` / `PublicKey`（DSA 只有公钥）：PKCS#8 v1/v2、SEC1、PKCS#1、SubjectPublicKeyInfo、PEM，RSA 密钥可为 `rsaEncryption` 或带 `PssParams` 限制的 `id-RSASSA-PSS`（RFC 4055；ADR-049）；按 TLS 与 X.509 命名的 `SignatureAlgorithm` |

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
docs/api-stability.zh-CN.md）。它不是通用密码学库（不清零密钥；只有宽 AES-GCM 内核与 CRC 折叠（其 VAES / VPCLMULQDQ / AVX-512 intrinsic 比 MSRV 新）以及 x86_64 上 P-256 与 Curve25519 的域运算和 RSA 的 Montgomery 运算、aarch64 上 P-256 与 Curve25519 的域运算使用汇编；SHA-512、MD5、Poly1305 与其余公钥运算是可移植的 Rust 代码）。
公钥部分是 DEV-PLAN 第 C、D 波计划中自研 TLS/DTLS/QUIC 协议栈的基础；证书相关功能在
[`only-x509`](../only-x509) 中。

## 公钥运算的时间特性

- 与秘密相关的代码没有依赖秘密的分支或内存下标。P-384 以及所有标量域使用 64 位 limb 的 Montgomery 运算
  （CIOS 乘法，平方用半规模乘积加 REDC），最后一步减法用掩码完成，按 limb 数泛型实现，常量在编译期推导。
  P-256 基域有专用的约简（`-p⁻¹ mod 2⁶⁴ = 1`，每一步只需一次真正的乘法）。P-256 基域与群阶的求逆使用
  safegcd（Bernstein–Yang divsteps，采用 libsecp256k1 的 half-delta 形式与有符号 62 位 limb：十批、每批
  59 步 divsteps，对每个输入都相同，条件都化为掩码）；其他求逆以公开指数 `p - 2` 做 4 位固定窗口幂运算。Curve25519 使用 2⁵¹ 进制并有专用平方。
- x86_64 上带 BMI2 + ADX 时（运行时检测；`ONLY_CRYPTO_PORTABLE=1` 可关闭），P-256 的域与群阶运算以及
  X25519 阶梯的域运算用内联汇编实现（`mulx`、`adcx`/`adox`，修正用 `cmov` 与 `sbb` 掩码，直线代码）。
  P-256 运算在一个与可移植实现共享 Montgomery 表示和基点预计算表的“孪生”曲线类型上执行；它的 Jacobian
  倍点（也可连续 `n` 次）、加法与混合加法各是一个作用于小栈帧的整点 `asm!` 块（乘法、约简与模加减融合，
  累加值留在寄存器中），safegcd 的 divsteps 也是汇编；有 AVX2 时，查表用 256 位读取加 `vpcmpeqq` 掩码。
- aarch64 上（所有 ARMv8.0 CPU 都具备所需指令，无需检测；`ONLY_CRYPTO_PORTABLE=1` 可关闭）P-256 的域与群阶
  运算以及 X25519 阶梯的域运算用内联汇编实现：`MUL`/`UMULH` 求积，`ADDS`/`ADCS`/`SUBS`/`SBCS` 进位链，`CSEL`
  修正，两条曲线都用四个 64 位 limb（模 P-256 素数的约简只用移位与减法，同 OpenSSL 的 `ecp_nistz256-armv8`）；
  求逆是 safegcd（可移植的 divsteps），点运算公式、查表与 4 位梳形表是建立在这个域上的可移植实现。设计依据
  指令数（4×64 乘积是 16 个 `MUL` + 16 个 `UMULH`，而 2⁵¹ 进制需要 25 个 128 位乘积）；这条路径已测试，但
  **尚未做性能测试**，因此不给出 aarch64 的性能数字。
- P-521（`p521`，ADR-049）有独立实现：基域 `2⁵²¹ - 1` 用九个非饱和肢（58 位，最高肢 57 位；乘积高半部分
  加倍折回，一次进位链，最高进位回到第 0 肢；加法以一次对所有肢同时进行的进位步结束），求逆与平方根用固定
  链，标量域用通用 Montgomery 代码。点用完备的射影公式（无需论证例外情形）：ECDH 用有符号 5 位 Booth 窗口查
  `0·P … 16·P`（每次查表读全部 17 项），倍点在 Jacobian 坐标中进行（dbl-2001-b 把单位元 `(1:1:0)` 映射到
  自身）；生成密钥与签名用 131 行 `G` 的仿射倍数组成的有符号 4 位梳，每行整行读取。只有可移植 Rust；
  `tools/ct-dudect` 测量 `p521-ecdh`、`p521-keygen`、`p521-sign`。
- P-256 / P-384 的秘密标量乘法使用 Jacobian 坐标（`a = -3`：倍点 4M + 4S，加法 11M + 5S，混合加法
  7M + 4S；P-256 孪生曲线的汇编加法用 12M + 4S 与 8M + 3S，模加减次数减半）。可变基点（ECDH）：Booth 重编码的有符号 5 位窗口（数字在 `[-16, 16]`）作用于 `1·P … 16·P`，每次
  查表读取全部 16 项，取负为掩码选择。固定基点：把 `k` 重新编码为有符号 4 位数字（掩码算术），每个数字加一个
  仿射梳形表项 `|d|·16ⁱ·G`，每次查表读取该行全部 8 项；P-256 孪生曲线在有 AVX2 时改用 Booth 重编码的有符号 6 位数字与更宽的梳形表
  （43 行，每行 32 个仿射点 `|d|·2⁶ⁱ·G`，共 88 KiB，首次使用时构造），43 次混合加法，每行都完整读取。
  Jacobian 公式并不完备：仍为无穷远点的累加值与零数字
  用掩码选择处理，而对 `[1, n)` 中的标量不会出现两个相同的操作数（证明见 `ec/mod.rs`，宽梳形表的证明见 `ec/hw.rs`，需要 `n mod 32 ≥ 17`，
  由测试检查）。点的解码、校验与预计算表的构造仍用完备公式（Renes–Costello–Batina）。
- Ed25519 的 `[k]B` 每个有符号 4 位数字加一个仿射 Niels 表项（完备的统一加法，每个数字 7M）。X25519 公钥
  就是把这个 `[k]B` 映射为 `u = (1 + y)/(1 - y)`；共享密钥使用 RFC 7748 的 Montgomery 阶梯和掩码交换。
- RSA 私钥运算：CRT 下按完整指数长度的固定 5 位窗口幂运算，每次查表读取全部 32 个表项（AVX2 的
  `vpcmpeqq` 掩码，否则用 `ct` 的掩码），基数盲化（每个密钥保存 `rᵉ` 与 `r⁻¹`，在各素数域中用费马求逆，
  每次使用后平方），并在输出签名前检查 `sᵉ = m`。在支持 AVX-512 IFMA 的 x86_64 上，2048、3072 与 4096 位
  密钥的 CRT 两半以 2⁵² 为基数运算（20、32、40 个数字，放在 `ymm` / `zmm` 寄存器中）：几乎 Montgomery 乘法
  （结果小于 `2p`，最后做一次带掩码的约简），每个乘积一个 `asm!` 块，最低位数字在通用寄存器中跟踪，进位用
  generate / propagate 掩码规整；除数字循环外没有分支。一次签名的两半交错运行，每次循环迭代各推进一个数字步
  （`Mont::pow2`、`ifma::pow_x2`），两条串行约简链因此重叠。公开运算 `sᵉ mod n`（验签与上述检查）对公开
  指数做平方-乘（`Mont::pow_public`），`e = 65537` 时为 16 次平方加 2 次乘法，2048、3072 与 4096 位模数在
  IFMA 上运算（40、60、80 个数字）。否则在有 BMI2 + ADX 时，16 至 64 个 limb 的
  Montgomery 乘法与平方是 `asm!` 块（`mulx` 加两条进位链，行完全展开，最后的减法用 `cmovnz`）；可移植代码是
  定长 CIOS。`R² mod p` 由 `64 + k` 次倍加与六次 Montgomery 平方得到（常数时间；公开模数用一次长除法）。
  `p`/`q` 的 limb 数（公开信息）不做隐藏。
- 已知的可变时间部分，都只涉及公开数据：签名验证（ECDSA 的 `u₁G + u₂Q` 使用 Jacobian 坐标、宽度 7 / 5 的
  wNAF、对 `s` 的二进制 GCD 求逆与射影坐标下的 `x ≡ r` 检查，Ed25519 的 `[s]B - [k]A` 使用交错 wNAF，RSA 的 `sᵉ`）、预计算表的构造、
  点的解码与校验、范围检查的 `Option`/`Result` 结果、RFC 6979 的拒绝循环（概率约 2⁻³²）、
  `SecretKey::generate` 的拒绝采样、仿射坐标转换对无穷远点的分支（合法秘密标量不会出现）。
- 局限：掩码经过 `std::hint::black_box`，只能阻止而不能保证优化器不重新引入分支；去掉它时 LLVM 确实会把部分
  带掩码的模修正编译成跳转，因此即使有性能代价也保留这道屏障（汇编不需要这道屏障）。已反汇编秘密标量路径在
  x86_64（含汇编）与 aarch64（含 aarch64 汇编，以及可移植实现）上的 release 代码并列出每个条件分支（方法见 `src/ct.rs`）：P-256 /
  P-384 的 `ecdh_x_impl`、`base_mul_impl`、`sign_impl` 及其内联的窗口与梳形表循环，Jacobian 倍点与加法（含整点
  汇编），宽梳形表与 AVX2 查表，域与群阶的乘法、平方与求逆（safegcd 及两种 divsteps），Ed25519 基点乘法与
  两种 X25519 阶梯；RSA 部分为 `Mont::mul_into` / `sqr_into`（内联了 BMI2 + ADX 汇编块）、`ifma::amm`（各个
  IFMA 汇编块；64 与 80 个数字的版本用于公开运算，它也在每个签名发出前做校验：`Mont::pow_public` 只在公开指数上分支）、`ifma::amm_x2`（三个交错汇编块）、`ifma::pow`、`ifma::pow_x2`、`Mont::pow`、`Mont::pow2`、AVX2 与可移植的查表、`Mont::new`、`crt_combine` 与
  `private_op`。分支只出现在循环计数、公开下标与边界（以及按 limb 数的分派、切片与内存分配检查）、其余费马求逆链的公开指数位、CPU 特性与
  `OnceLock` 检查、输出编码的长度，以及最后“结果为无穷远点”的判断上。另有 dudect 式统计计时测试
  （`tools/ct-dudect`：对固定与随机秘密做 Welch t 检验，覆盖硬件与可移植路径）从外部黑盒测量这些路径；方法与最新结果见
  [docs/constant-time.zh-CN.md](../../docs/constant-time.zh-CN.md)。密钥不会被清零。所用的 CPU 指令（AES、无进位乘法、SHA、CRC32、AVX2、`mulx`、
  `adcx`/`adox`、`cmov`、`vpmadd52luq`/`vpmadd52huq`；aarch64 上的 `MUL`、`UMULH`、设置标志位的加减法与 `CSEL`）
  是常数时间的。

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
| ChaCha20-Poly1305 加密，16 KiB | 588 | 4 597 | ring 的 1.30 倍 |
| ChaCha20-Poly1305 加密，1400 B | – | 3 137 | ring 的 1.21 倍 |
| ChaCha20-Poly1305 加密，64 B | – | 481 | ring 的 0.98 倍 |
| Ed25519 验签（次/秒） | 18 289 | 27 714 | ring 的 0.87 倍 |
| Ed25519 签名 | – | 89 784 | ring 的 1.53 倍 |
| X25519 协商 | 28 865 | 36 488 | ring 的 1.00 倍 |
| P-256 ECDSA 签名 | 23 435 | 105 399 | ring 的 1.38 倍 |
| P-256 ECDSA 验签 | 8 043 | 28 834 | ring 的 1.10 倍 |
| P-256 ECDH | 10 075 | 33 904 | ring 的 1.12 倍 |
| P-256 生成密钥 | – | 158 921 | ring 的 1.40 倍 |
| P-384 ECDSA 验签 | 2 426 | 4 330 | ring 的 2.34 倍 |
| RSA-2048 PKCS#1 签名 | 1 192 | 5 511 | ring 的 2.26 倍 |
| RSA-2048 PKCS#1 验签 | 39 244 | 200 748 | ring 的 3.07 倍 |
| RSA-2048 验签 + 密钥解析 | 5 850 | 153 716 | ring 的 2.35 倍 |
| RSA-3072 PKCS#1 签名 | 371 | 1 766 | ring 的 2.24 倍 |
| RSA-3072 验签 + 密钥解析 | 2 627 | 80 470 | ring 的 2.64 倍 |
| RSA-4096 PKCS#1 签名 | 156 | 899 | ring 的 2.60 倍 |
| RSA-4096 验签 + 密钥解析 | 1 400 | 50 850 | ring 的 2.90 倍 |
| TLS 1.3 完整握手/秒，X25519（only-tls 对比 rustls + ring） | – | 5 027 | rustls 的 1.00 倍 |
| TLS 1.3 完整握手/秒，secp256r1 | – | 4 552 | rustls 的 0.89 倍 |
| TLS 1.3 完整握手/秒，X25519，RSA-2048 证书 | 775 | 3 270 | rustls 的 1.82 倍 |

公钥各行与握手数据来自 P-256 / X25519 优化（优化前：P-256 签名 34 152、验签 13 404、ECDH 10 380、X25519
30 696 次/秒；握手 3 055 与 2 306 次/秒）。ring 的 AES-GCM、P-256、X25519 与 RSA 使用汇编。AES-GCM 与 CRC 行
对比的是此前没有 VAES / VPCLMULQDQ 的代码（`--example gcm-sizes` 对比 ring，`--example bench` 对比
crc32fast）；在 Zen 4 上，512 位内核在所有长度上都快于同一内核的 256 位寄存器版本。AES-GCM 各行来自把整条消息
移进 AVX-512 内核的那一轮（AAD、用字节掩码处理的最后一个不完整组、标签；短消息只做一次归约：1 KiB 为 ring 的
1.00 倍 → 1.32 倍，1400 B 1.10 倍 → 1.46 倍，64 B 1.11 倍 → 1.29 倍），这一轮还为没有 AVX-512 的 CPU 新增了
VAES-AVX2 内核（为 128 位内核的 1.55–2.35 倍，在关闭 AVX-512 内核的 Zen 4 上测得）。P-256 整点优化（汇编倍点与加法、带
AVX2 扫表的 6 位梳形表、safegcd 求逆）之后，在有负载的机器上同一次运行中与 ring 对比（docs/BENCHMARKS.zh-CN.md）：
签名 0.77 倍 → 1.25 倍，生成密钥 0.94 倍 → 1.33 倍，验签 0.98 倍 → 1.04 倍，ECDH 0.94 倍 → 0.96 倍，
secp256r1 握手为 rustls 的 0.94 倍 → 1.12 倍。在空闲机器上，那一版的 ECDH 已是
ring 的 1.08 倍；随后改用 OpenSSL `ecp_nistz256` 的点运算公式（模加减更少）并缩短约简步骤，ECDH 达到 ring 的
1.12 倍，签名 1.38 倍，验签 1.10 倍，生成密钥 1.40 倍（一次倍点 348 个周期，一次加法 721，可变基点标量乘法
140.6k）；表中 P-256 各行来自这最后一轮，在空闲机器上测得。RSA 各行来自 RSA 优化（优化前 = 优化之前的代码，同一次运行，空闲机器）：BMI2 + ADX 的
Montgomery 汇编、IFMA 模幂、带一遍式 AVX2 查表的 5 位窗口，以及用平方或一次除法计算 `R²`，使 RSA-2048
签名从 ring 的 0.49 倍提升到 1.61 倍（3072：0.47 倍 → 1.85 倍，4096：0.45 倍 → 2.19 倍），验签从 0.60 倍
提升到 1.22 倍（1.10 倍、1.09 倍），含密钥解析的验签（即验证一个证书签名）从 0.09 倍提升到 1.02 倍
（0.95 倍、0.95 倍），only-tls 使用 RSA-2048 证书的握手从 rustls 的 0.43 倍提升到 1.44 倍。一次 1024 位
Montgomery 乘法在 BMI2 + ADX 上需要 805 个周期（平方 681），一次 1024 位 IFMA 乘法 416 个周期；只有
BMI2 + ADX（没有 IFMA）时 RSA-2048 签名为 ring 的 0.99 倍。随后把 CRT 两半放进同一个 IFMA 循环，签名达到
ring 的 2.20 倍（3072：2.19 倍，4096：2.55 倍），RSA-2048 证书握手达到 rustls 的 1.69 倍。之后公开运算
移到 IFMA 上（新增 60 与 80 个数字的乘法，`e = 65537` 只需 18 次乘积，`R²` 用更快的除法求得），验签达到 ring
的 3.07 倍（3072：3.30 倍，4096：3.70 倍），含密钥解析的验签 2.35 倍（2.64 倍、2.90 倍；原为 1.02、0.95、
0.95 倍），握手达到 rustls 的 1.82 倍；表中 RSA 与握手各行来自这次改动，与原代码在同一次运行中交替测得。没有尝试 Karatsuba：在这些位数下，汇编的行循环
已没有多少可省。后续：VAES-AVX2 内核的掩码尾部（消息在 256 字节组之后的部分走 128 位路径）、在 Zen 3 /
Alder Lake 上测量该内核、测量 aarch64 上 P-256 与
X25519 汇编的性能（已测试，尚未做性能测试）、aarch64 上的整点运算与 divsteps 汇编。

## 测试

- 已知答案测试：NIST CAVP（SHAVS、HMACVS、AESAVS ECB、GCMVS）、FIPS 197、SP 800-38A、GCM
  规范、RFC 1321、2202、4231、5869、6070、3720、4648、8439，以及 Wycheproof（AES-GCM、
  ChaCha20-Poly1305、HMAC-SHA1/SHA256、HKDF-SHA256），数据放在 `tests/data/`。
- `tests/compat.rs` 把每个原语与被替代的 crate 交叉比对（仅作为 dev-dependency）；`fuzz/` 中有差分
  模糊测试目标 `crypto_hash`、`crypto_aead`（也让 VAES-AVX-512、VAES-AVX2、128 位与可移植四条 AES-GCM 路径原地与非原地
  互相比较，并比较 AVX-512 / IFMA、AVX2 与可移植三条 ChaCha20-Poly1305 路径，两者都包括追加路径）、`crypto_base64`。
- 追加路径（`encrypt_append` / `decrypt_append`，直接写入向量的空闲容量，不先清零）：在每个 AES-GCM 与
  ChaCha20-Poly1305 内核上，于 0..=600 的每个长度与若干大长度上和原地路径比较，覆盖向量中已有数据、空闲容量
  恰好、更大或不足、明文分在 `src` 与尾部字节（TLS 1.3 内层内容类型）两处；打开失败时向量保持原样。可移植的
  追加路径与 `fill::tests` 还在 Miri 下运行（`append_portable`、`aead_rfc8439`、`gcm_spec_vectors`、`rejects_forgeries`
  以及 only-tls 的四个 `record::` 测试），检查空闲容量中的每个字节在写入之前都不会被读取或暴露。
- AVX-512 ChaCha20 与 IFMA Poly1305 内核（`chacha::tests`）：0..=600 的每个长度与若干大长度上与 AVX2
  路径和可移植实现比较，覆盖未对齐、原地与非原地、伪造标签、接近回绕的计数器，Poly1305 覆盖全 1 分组与
  极端的 `r` / `s`；在具备 AVX-512 IFMA 的 CPU（Zen 4）上原生运行。
- 宽 AES-GCM 内核（`gcm::tests`）：AVX-512 与 AVX2 两个内核（后者用 `AesGcm::with_cipher_avx2` 强制启用）
  互相比较，并在 0..=600 的每个长度、若干大长度、0..=300 及 512 以上的每种 AAD 长度上与 128 位路径和可移植
  实现比较，覆盖未对齐、原地与非原地（包括 TLS 1.3 记录层那样输入分散在两个缓冲区）、组内 32 位计数器回绕，
  大消息还与 ring 比较；CAVP 与 Wycheproof 的 AES-GCM 向量在每个内核上都跑一遍。它们需要具备 VAES 与
  AVX-512 的 CPU，因此这些测试要在这样的机器（Zen 4）上原生运行。
- 硬件路径：单元测试把每条硬件路径与可移植实现比较（AES、CTR、GCM、SHA-1、SHA-256 的
  `hardware_matches_portable`，CRC 的 `hardware_matches_table`，多分组 ChaCha20 与 Poly1305 对比逐分组
  计算，`ec::hw`、`ec::hw_aarch64`、`curve25519::hw` 与 `curve25519::hw_aarch64` 的 `matches_portable` 在随机值
  与边界值上覆盖每个域运算例程与 X25519 阶梯，`chains_match_portable` 覆盖长串相互依赖的运算（aarch64），`ec::hw` 的 `points_match_portable` 在随机 `Z` 的随机点、Wycheproof 中全部合法的 ECDH 点、`P + P`、
  `P + (-P)` 与两种形式的无穷远点上把整点倍点（逐 limb）、加法与混合加法（按点比较：它们的公式给出另一种
  表示）和可移植公式比较，并在边界值上检查模减半，`safegcd` 的 `matches_fermat`
  覆盖 P-256 的两个模数，`twin_matches_portable` 覆盖 P-256 的密钥生成、ECDH、签名与验签，`bignum` 的 `asm_matches_generic`
  在每个规模上把 BMI2 + ADX 乘法与平方和通用 CIOS 比较（随机值，以及 0、1、m - 1、m - 2、R - 1、R - m，
  最高 limb 满与不满的模数，外加 200 步的运算链），`ifma_pow_matches` 用边界底数与指数把 IFMA 模幂和平方-乘法
  比较，`ifma_pow_x2_matches` 覆盖交错的两半（最高 limb 不同的模数，每一半各自的边界底数与指数），`r2_constructions` 覆盖两种 `R²` 计算，`pow_public_matches` 用边界底数与指数把公开运算（有无 IFMA）与 `pow_vartime` 和通用 CIOS 上的平方-乘比较，`rem_matches_bitwise` 把长除法与逐位移位相减比较（被除数覆盖需要修正商估计的情形），`be_conversions` 覆盖字节转换），整个测试套件还会在 x86_64 与
  aarch64 上设置 `ONLY_CRYPTO_PORTABLE=1` 再跑一遍。
- Jacobian 标量乘法在随机标量与边界标量（`[1, n)` 的两端、每个 Booth 数字对应的 `n - 2|d|`、进位到梳形表
  最高行的标量、宽梳形表的每个最高位数字）上与完备公式的参考实现（`mul_ref`、`mul_base_ref`）比较，覆盖
  P-256、P-384 与 P-256 孪生曲线（含整点汇编与宽梳形表）；由 Edwards 基点表计算的 X25519 公钥与 `u = 9` 上的阶梯结果比较。
- `cargo run --release -p only-crypto --example bench` 与被替代的 crate 比较吞吐量。
- 公钥（`tests/pk_kat.rs`）：Wycheproof 的 X25519、Ed25519、ECDSA P-256/SHA-256（DER 与 P1363）、
  P-384/SHA-384 与 SHA-512、P-521/SHA-512（DER 与 P1363）、ECDH P-256（SPKI 与原始点）、P-384 与 P-521、
  RSA PKCS#1 v1.5 验证（2048/SHA-256、
  3072/SHA-384、4096/SHA-512）、RSA-PSS 验证（2048/SHA-256/32、4096/SHA-512/64）、RSA PKCS#1 v1.5
  签名生成；单元测试中有 RFC 7748、8032 与 6979 向量。所有 "valid" 向量都被接受，所有 "invalid" 向量都被拒绝。
  P-521 另有 RFC 6979 A.2.7（SHA-512 与 SHA-256，也是 OpenSSL 确定性 ECDSA 的结果）；OpenSSL 生成的
  `id-RSASSA-PSS` 密钥（带与不带参数；PKCS#8 与 SPKI 编码逐字节相同，验证 OpenSSL 的签名，限制得到执行）。
- `tests/pk_compat.rs` 与 ring 和 RustCrypto p256/p384 交叉比对（Ed25519、ECDSA RFC 6979 与 RSA PKCS#1
  签名逐字节一致，RSA 覆盖 2048、3072 与 4096 位，并在强制可移植实现时再比较一次；互相验证；ECDH 与 X25519 共享密钥一致；PKCS#8 密钥双向互通）。`tests/sig_diff.rs`
  回放 `crypto_sig_verify` 模糊测试目标（对合法、变异与任意的签名和密钥，与 ring 的验证结果比较）；
  only-x509 的测试覆盖 OpenSSL 生成的密钥与签名。

## 致谢

AES 核心改编自 RustCrypto `aes` crate 的 fixsliced 软件后端（MIT OR Apache-2.0），其源自
Alexandre Adomnicai 的 fixslicing C 代码；GHASH 参照 Thomas Pornin 的 BearSSL
`ghash_ctmul64.c`（MIT）；Poly1305 参照 poly1305-donna（公有领域）。
