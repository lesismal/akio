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

## 测试

- 已知答案测试：NIST CAVP（SHAVS、HMACVS、AESAVS ECB、GCMVS）、FIPS 197、SP 800-38A、GCM
  规范、RFC 1321、2202、4231、5869、6070、3720、4648、8439，以及 Wycheproof（AES-GCM、
  ChaCha20-Poly1305、HMAC-SHA1/SHA256、HKDF-SHA256），数据放在 `tests/data/`。
- `tests/compat.rs` 把每个原语与被替代的 crate 交叉比对（仅作为 dev-dependency）；`fuzz/` 中有差分
  模糊测试目标 `crypto_hash`、`crypto_aead`、`crypto_base64`。
- `cargo run --release -p only-crypto --example bench` 与被替代的 crate 比较吞吐量。

## 致谢

AES 核心改编自 RustCrypto `aes` crate 的 fixsliced 软件后端（MIT OR Apache-2.0），其源自
Alexandre Adomnicai 的 fixslicing C 代码；GHASH 参照 Thomas Pornin 的 BearSSL
`ghash_ctmul64.c`（MIT）；Poly1305 参照 poly1305-donna（公有领域）。
