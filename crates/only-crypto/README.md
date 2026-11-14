# only-crypto

[中文](README.zh-CN.md)

Dependency-free cryptographic primitives for the [`only`](https://github.com/lesismal/only)
crates, in safe Rust on `std` only (`#![deny(unsafe_code)]`; the one exception is the module
that drives the CPU's AES instructions; the OS random syscall lives in `only-sys`).

| Module | What |
|---|---|
| `hash` | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, MD5 (streaming and one-shot, `Hash` trait) |
| `mac` | HMAC over any `Hash` (constant-time `verify`) |
| `kdf` | HKDF (RFC 5869), PBKDF2-HMAC (RFC 8018) |
| `crc` | CRC-32 (IEEE, as `crc32fast`), CRC-32C (Castagnoli), slicing-by-8 |
| `aes` | AES-128/192/256: AES-NI / ARMv8 AES when the CPU has them (detected at run time), else constant-time fixsliced software (no secret-indexed tables); ECB blocks, CTR |
| `gcm` | AES-GCM, constant-time GHASH (BearSSL `ctmul64`) |
| `chacha` | ChaCha20, Poly1305, ChaCha20-Poly1305 (RFC 8439) |
| `base64` | standard / URL-safe, padded / unpadded, strict decoding |
| `rand` | `fill_random` (getrandom / getentropy / `/dev/urandom`), `ChaChaRng` |
| `ct_eq` | constant-time comparison |

It replaces sha1, sha2, md-5, hmac, pbkdf2, aes, aes-gcm, ctr, crc32fast, base64 and getrandom
in `only-kcp`, `only-turn`, `only-ws`, `only-http`, `only-media`, `only-bittorrent` and
`only-webrtc` (DEV-PLAN, "Long term: no third-party dependencies", wave A).

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

This is an implementation crate: its API follows the needs of the other `only` crates and may
change in any release (internal tier, docs/api-stability.md). It is not a general-purpose
cryptography library (no key zeroization; only AES uses CPU instructions, the hashes, GHASH and
CRC-32 are portable code).

## Testing

- Known answers: NIST CAVP (SHAVS, HMACVS, AESAVS ECB, GCMVS), FIPS 197, SP 800-38A, the GCM
  specification, RFC 1321, 2202, 4231, 5869, 6070, 3720, 4648, 8439, and Wycheproof (AES-GCM,
  ChaCha20-Poly1305, HMAC-SHA1/SHA256, HKDF-SHA256), vendored under `tests/data/`.
- `tests/compat.rs` cross-checks every primitive against the replaced crates (dev-dependencies
  only); `fuzz/` has differential targets `crypto_hash`, `crypto_aead`, `crypto_base64`.
- `cargo run --release -p only-crypto --example bench` compares throughput with the replaced
  crates.

## Credits

The AES core is adapted from the RustCrypto `aes` crate's fixsliced software backend (MIT OR
Apache-2.0), itself from Alexandre Adomnicai's fixslicing C code; GHASH follows BearSSL's
`ghash_ctmul64.c` by Thomas Pornin (MIT); Poly1305 follows poly1305-donna (public domain).
