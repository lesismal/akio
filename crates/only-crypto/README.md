# only-crypto

[中文](README.zh-CN.md)

Dependency-free cryptographic primitives for the [`only`](https://github.com/lesismal/only)
crates, in Rust on `std` only (`#![deny(unsafe_code)]`; the exceptions are five small modules
that drive CPU instructions, detected at run time; the OS random syscall lives in `only-sys`).

| Hardware path (run-time detection, constant-time portable fallback) | x86_64 | aarch64 |
|---|---|---|
| AES block cipher, CTR (8 blocks in flight) | AES-NI | ARMv8 AES |
| AES-GCM (GHASH fused with CTR, 8 blocks per reduction) | PCLMULQDQ + AES-NI | PMULL + ARMv8 AES |
| SHA-1, SHA-256 | SHA-NI | ARMv8 SHA1/SHA2 |
| CRC-32, CRC-32C | PCLMULQDQ folding, SSE4.2 `crc32` | ARMv8 CRC32 |
| ChaCha20 | AVX2 (8 blocks) | portable 4-block lanes, vectorized by the compiler |

`ONLY_CRYPTO_PORTABLE=1` (read once) forces the portable code everywhere; the tests run every
known-answer vector with and without it. Under Miri nothing is detected.

| Module | What |
|---|---|
| `hash` | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, MD5 (streaming and one-shot, `Hash` trait) |
| `mac` | HMAC over any `Hash` (constant-time `verify`) |
| `kdf` | HKDF (RFC 5869), PBKDF2-HMAC (RFC 8018) |
| `crc` | CRC-32 (IEEE, as `crc32fast`), CRC-32C (Castagnoli): CPU instructions, else slicing-by-8 |
| `aes` | AES-128/192/256: AES-NI / ARMv8 AES when the CPU has them (detected at run time), else constant-time fixsliced software (no secret-indexed tables); ECB blocks, CTR |
| `gcm` | AES-GCM: PCLMULQDQ / PMULL GHASH fused with the AES-NI / ARMv8 CTR pass, else constant-time GHASH (BearSSL `ctmul64`) |
| `chacha` | ChaCha20 (8 blocks with AVX2, else 4-block lanes), Poly1305 (44-bit limbs, two blocks per step), ChaCha20-Poly1305 (RFC 8439) |
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
cryptography library (no key zeroization, no assembly; SHA-512, MD5, Poly1305 and the
public-key arithmetic are portable Rust). The public-key half is the base of the in-house TLS/DTLS/QUIC stacks
planned in DEV-PLAN waves C and D; certificates are in [`only-x509`](../only-x509).

## Public-key timing

- Secret-dependent code has no secret-dependent branches or memory indices. P-384 and all
  scalar fields use 64-bit-limb Montgomery arithmetic (CIOS multiplication, squaring as a
  half-size product plus REDC) with masked final subtractions, generic over the limb count,
  constants derived at compile time. The P-256 base field has a dedicated reduction (`-p⁻¹ mod
  2⁶⁴ = 1`, so each step costs one real multiplication) and inverts by an addition chain (255
  squarings, 12 multiplications); other inversions use 4-bit fixed windows over the public
  exponent `p - 2`. Curve25519 uses radix 2⁵¹ with a dedicated squaring.
- Points use complete formulas (Renes–Costello–Batina for `a = -3`, including the mixed
  addition with an affine point, unified extended Edwards addition), so no input takes a
  different path. `[k]G` recodes `k` into signed 4-bit digits (masked arithmetic) and adds one
  affine comb entry `|d|·16ⁱ·G` per digit: each lookup reads all 8 entries of the row with
  masks, the negation and the skipping of a zero digit are masked selects. Variable-base secret
  multiplication uses fixed 4-bit windows reading all 16 entries; X25519 is the RFC 7748 ladder
  with masked swaps.
- RSA private operations: CRT exponentiation with fixed 4-bit windows over the full exponent
  length and masked table selection (fixed-size Montgomery code for 1024- to 4096-bit primes,
  squaring by a half-size product), base blinding (`rᵉ`, `r⁻¹` per key, inverted by Fermat in
  each prime field, squared after each use) and a check that `sᵉ = m` before releasing the
  signature. Moduli reductions are constant time; public `p`/`q` limb counts are not hidden.
- Known variable-time parts, all on public data: signature verification (ECDSA `u₁G + u₂Q` in
  Jacobian coordinates with width-7 / width-5 wNAF and a projective `x ≡ r` check, Ed25519
  `[s]B - [k]A` with interleaved wNAF, RSA `sᵉ`), table construction, point
  decoding/validation, the `Option`/`Result` outcome of range checks, RFC 6979's rejection loop
  (probability ~2⁻³²), `SecretKey::generate`'s rejection sampling, affine conversion branching
  on the identity (impossible for valid secret scalars).
- Limits: masks go through `std::hint::black_box`, which discourages but does not forbid the
  optimizer from reintroducing branches; without it LLVM does turn some masked modular
  corrections into jumps, so the barrier stays even where it costs speed. The x86_64 and
  aarch64 code of the P-256 / P-384 point operations, the field multiplication, squaring and
  inversion and the X25519 ladder was inspected: no conditional branch besides loop control.
  No statistical test (dudect, ctgrind) has been run. Keys are not zeroized. The CPU
  instructions used (AES, carry-less multiplication, SHA, CRC32, AVX2) take constant time.

## Performance

AMD Ryzen 7 7800X3D (x86_64, one core), `cargo run --release -p only-crypto --example bench`
and `--example pk_bench`; before = the previous release, the full tables and the TLS / KCP
numbers are in [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md#cryptography-only-crypto-cpu-acceleration):

| Operation | before | after | vs RustCrypto / ring |
|---|---:|---:|---:|
| SHA-1, 16 KiB (MB/s) | 697 | 2 543 | 1.00x sha1 |
| SHA-256, 16 KiB | 366 | 2 383 | 1.00x sha2 |
| CRC-32, 16 KiB | 2 733 | 20 047 | 0.27x crc32fast |
| AES-128-GCM seal, 16 KiB | 364 | 6 484 | 2.98x aes-gcm |
| ChaCha20-Poly1305 seal, 16 KiB | 588 | 1 757 | 0.89x chacha20poly1305 |
| Ed25519 verify (op/s) | 18 289 | 27 161 | 0.85x ring |
| X25519 agreement | 28 865 | 30 945 | 0.84x ring |
| P-256 ECDSA sign | 23 435 | 34 184 | 0.45x ring |
| P-256 ECDSA verify | 8 043 | 13 397 | 0.51x ring |
| P-256 ECDH | 10 075 | 10 390 | 0.34x ring |
| P-384 ECDSA verify | 2 426 | 3 798 | 2.03x ring |
| RSA-2048 PKCS#1 sign | 871 | 1 199 | 0.49x ring |
| RSA-2048 PKCS#1 verify | 29 019 | 39 557 | 0.60x ring |

ring uses assembly for AES-GCM, P-256, X25519 and RSA. Follow-ups: VAES / VPCLMULQDQ kernels
(newer than the MSRV), a SIMD Poly1305, cheaper doublings for secret P-256 scalars, Karatsuba
for RSA.

## Testing

- Known answers: NIST CAVP (SHAVS, HMACVS, AESAVS ECB, GCMVS), FIPS 197, SP 800-38A, the GCM
  specification, RFC 1321, 2202, 4231, 5869, 6070, 3720, 4648, 8439, and Wycheproof (AES-GCM,
  ChaCha20-Poly1305, HMAC-SHA1/SHA256, HKDF-SHA256), vendored under `tests/data/`.
- `tests/compat.rs` cross-checks every primitive against the replaced crates (dev-dependencies
  only); `fuzz/` has differential targets `crypto_hash`, `crypto_aead` (also hardware against
  portable AES-GCM), `crypto_base64`.
- Hardware paths: unit tests compare each one with the portable code (`hardware_matches_portable`
  for AES, CTR, GCM, SHA-1, SHA-256, `hardware_matches_table` for CRC, the multi-block ChaCha20
  and two-block Poly1305 against one block at a time), and the whole suite also runs with
  `ONLY_CRYPTO_PORTABLE=1`, on x86_64 and aarch64.
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
