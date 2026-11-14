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
| `x25519` | X25519 key agreement (RFC 7748), rejecting the all-zero shared secret |
| `ed25519` | Ed25519 (RFC 8032): deterministic signing, strict verification (canonical `S`, `R` compared as encoded) |
| `p256`, `p384` | ECDH and ECDSA on NIST P-256 / P-384: RFC 6979 nonces, any `Hash` for prehashing, DER and fixed-width (P1363) signatures, validated SEC1 points (compressed and uncompressed) |
| `rsa` | RSA PKCS#1 v1.5 and PSS (MGF1) with SHA-256/384/512 (SHA-1 verification only), 2048–8192-bit moduli; private keys use the CRT with blinding and a check of the result |
| `der`, `pem` | strict DER reader and writer (rejects BER), common OIDs, PEM (RFC 7468) |
| `pkey` | `PrivateKey` / `PublicKey` over all of the above: PKCS#8 v1/v2, SEC1, PKCS#1, SubjectPublicKeyInfo, PEM; `SignatureAlgorithm` as TLS and X.509 name them |

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
CRC-32 are portable code). The public-key half is the base of the in-house TLS/DTLS/QUIC stacks
planned in DEV-PLAN waves C and D; certificates are in [`only-x509`](../only-x509).

## Public-key timing

- Secret-dependent code has no secret-dependent branches or memory indices. P-256, P-384 and
  all scalar fields use 64-bit-limb Montgomery arithmetic (CIOS) with masked final
  subtractions, generic over the limb count, constants derived at compile time; inversion is
  Fermat exponentiation with a fixed public exponent. Curve25519 uses radix 2⁵¹.
- Points use complete formulas (Renes–Costello–Batina for `a = -3`, unified extended Edwards
  addition), so no input takes a different path. Secret scalar multiplications use fixed 4-bit
  windows (variable base) or a precomputed comb table of `j·16ⁱ·G` (fixed base), and every
  lookup reads all 16 entries with masks; X25519 is the RFC 7748 ladder with masked swaps.
- RSA private operations: CRT exponentiation with fixed 4-bit windows over the full exponent
  length and masked table selection, base blinding (`rᵉ`, `r⁻¹` per key, inverted by Fermat in
  each prime field, squared after each use) and a check that `sᵉ = m` before releasing the
  signature. Moduli reductions are constant time; public `p`/`q` limb counts are not hidden.
- Known variable-time parts, all on public data: signature verification (ECDSA `u₁G + u₂Q`,
  Ed25519 `[k]A`, RSA `sᵉ`), point decoding/validation, the `Option`/`Result` outcome of range
  checks, RFC 6979's rejection loop (probability ~2⁻³²), `SecretKey::generate`'s rejection
  sampling, affine conversion branching on the identity (impossible for valid secret scalars).
- Limits: masks go through `std::hint::black_box`, which discourages but does not forbid the
  optimizer from reintroducing branches; nothing is checked at the binary level (no dudect or
  ctgrind run yet). Keys are not zeroized.

## Performance vs ring

`cargo run --release -p only-crypto --example pk_bench` (Apple M-series, one core, operations
per second; ring uses assembly for P-256, X25519 and RSA Montgomery multiplication):

| Operation | only | ring | ratio |
|---|---:|---:|---:|
| Ed25519 sign | 104,900 | 128,300 | 0.82x |
| Ed25519 verify | 31,600 | 48,000 | 0.66x |
| X25519 agreement | 46,500 | 54,500 | 0.85x |
| P-256 ECDSA sign | 28,200 | 84,300 | 0.34x |
| P-256 ECDSA verify | 9,700 | 32,800 | 0.30x |
| P-256 ECDH (incl. point decoding) | 12,100 | 37,000 | 0.33x |
| P-384 ECDSA sign | 9,800 | 4,300 | 2.27x |
| P-384 ECDSA verify | 3,100 | 2,400 | 1.29x |
| P-384 ECDH | 3,600 | 4,600 | 0.78x |
| RSA-2048 PKCS#1 sign | 1,130 | 3,000 | 0.38x |
| RSA-2048 PKCS#1 verify | 35,500 | 88,600 | 0.40x |

(ring's ECDH numbers include generating its ephemeral key.) Follow-ups: a dedicated P-256 field
(Solinas reduction or fiat-crypto style), wNAF / precomputed-table verification, Karatsuba or
CPU-specific multiplication for RSA.

## Testing

- Known answers: NIST CAVP (SHAVS, HMACVS, AESAVS ECB, GCMVS), FIPS 197, SP 800-38A, the GCM
  specification, RFC 1321, 2202, 4231, 5869, 6070, 3720, 4648, 8439, and Wycheproof (AES-GCM,
  ChaCha20-Poly1305, HMAC-SHA1/SHA256, HKDF-SHA256), vendored under `tests/data/`.
- `tests/compat.rs` cross-checks every primitive against the replaced crates (dev-dependencies
  only); `fuzz/` has differential targets `crypto_hash`, `crypto_aead`, `crypto_base64`.
- `cargo run --release -p only-crypto --example bench` compares throughput with the replaced
  crates.
- Public key (`tests/pk_kat.rs`): Wycheproof X25519, Ed25519, ECDSA P-256/SHA-256 (DER and
  P1363), P-384/SHA-384 and SHA-512, ECDH P-256 (SPKI and raw points) and P-384, RSA PKCS#1
  v1.5 verification (2048/SHA-256, 3072/SHA-384, 4096/SHA-512), RSA-PSS verification
  (2048/SHA-256/32, 4096/SHA-512/64), RSA PKCS#1 v1.5 signature generation; RFC 7748, 8032 and
  6979 vectors in unit tests. Every "valid" vector is accepted and every "invalid" one rejected.
- `tests/pk_compat.rs` cross-checks against ring and RustCrypto p256/p384 (identical Ed25519,
  ECDSA RFC 6979 and RSA PKCS#1 signatures; mutual verification; identical ECDH and X25519
  secrets; PKCS#8 keys both ways). `tests/sig_diff.rs` replays the `crypto_sig_verify` fuzz
  target (verification of valid, mutated and arbitrary signatures and keys against ring);
  only-x509's tests cover OpenSSL-made keys and signatures.

## Credits

The AES core is adapted from the RustCrypto `aes` crate's fixsliced software backend (MIT OR
Apache-2.0), itself from Alexandre Adomnicai's fixslicing C code; GHASH follows BearSSL's
`ghash_ctmul64.c` by Thomas Pornin (MIT); Poly1305 follows poly1305-donna (public domain).
