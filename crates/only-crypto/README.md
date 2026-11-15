# only-crypto

[中文](README.zh-CN.md)

Dependency-free cryptographic primitives for the [`only`](https://github.com/lesismal/only)
crates, in Rust on `std` only (`#![deny(unsafe_code)]`; the exceptions are ten small modules
that drive CPU instructions, detected at run time; the OS random syscall lives in `only-sys`).

| Hardware path (run-time detection, constant-time portable fallback) | x86_64 | aarch64 |
|---|---|---|
| AES block cipher, CTR (8 blocks in flight) | AES-NI | ARMv8 AES |
| AES-GCM (GHASH fused with CTR) | VAES + VPCLMULQDQ + AVX-512 (16 blocks per reduction), else PCLMULQDQ + AES-NI (8) | PMULL + ARMv8 AES |
| SHA-1, SHA-256 | SHA-NI | ARMv8 SHA1/SHA2 |
| CRC-32, CRC-32C | VPCLMULQDQ + AVX-512 or PCLMULQDQ folding, SSE4.2 `crc32` | ARMv8 CRC32 |
| ChaCha20 | AVX2 (8 blocks) | portable 4-block lanes, vectorized by the compiler |
| P-256 field and order arithmetic, X25519 ladder (`ec::hw`, `curve25519::hw`; `ec::hw_aarch64`, `curve25519::hw_aarch64`) | BMI2 + ADX inline assembly (`mulx`, `adcx`/`adox`) | inline assembly (`MUL`/`UMULH`, `ADDS`/`ADCS`, `CSEL`; every ARMv8.0 CPU; not benchmarked yet) |

`ONLY_CRYPTO_PORTABLE=1` (read once) forces the portable code everywhere; the tests run every
known-answer vector with and without it. Under Miri nothing is detected.

| Module | What |
|---|---|
| `hash` | SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, MD5 (streaming and one-shot, `Hash` trait) |
| `mac` | HMAC over any `Hash` (constant-time `verify`) |
| `kdf` | HKDF (RFC 5869), PBKDF2-HMAC (RFC 8018) |
| `crc` | CRC-32 (IEEE, as `crc32fast`), CRC-32C (Castagnoli): CPU instructions, else slicing-by-8 |
| `aes` | AES-128/192/256: AES-NI / ARMv8 AES when the CPU has them (detected at run time), else constant-time fixsliced software (no secret-indexed tables); ECB blocks, CTR |
| `gcm` | AES-GCM: on VAES + VPCLMULQDQ + AVX-512 one 512-bit pass (16 blocks per iteration and reduction), else PCLMULQDQ / PMULL GHASH fused with the AES-NI / ARMv8 CTR pass, else constant-time GHASH (BearSSL `ctmul64`) |
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
cryptography library (no key zeroization; assembly only for the wide AES-GCM kernel and CRC fold,
whose VAES / VPCLMULQDQ / AVX-512 intrinsics are newer than the MSRV, and for the P-256 and
Curve25519 field arithmetic on x86_64 and aarch64; SHA-512, MD5, Poly1305, RSA and the rest of the public-key
arithmetic are portable Rust). The public-key half is the base of the in-house TLS/DTLS/QUIC stacks
planned in DEV-PLAN waves C and D; certificates are in [`only-x509`](../only-x509).

## Public-key timing

- Secret-dependent code has no secret-dependent branches or memory indices. P-384 and all
  scalar fields use 64-bit-limb Montgomery arithmetic (CIOS multiplication, squaring as a
  half-size product plus REDC) with masked final subtractions, generic over the limb count,
  constants derived at compile time. The P-256 base field has a dedicated reduction (`-p⁻¹ mod
  2⁶⁴ = 1`, so each step costs one real multiplication). The P-256 base field and group order
  invert by safegcd (Bernstein–Yang divsteps in libsecp256k1's half-delta form, signed 62-bit
  limbs: ten batches of 59 divsteps, the same for every input, conditions as masks); other
  inversions use 4-bit fixed windows over the public exponent `p - 2`. Curve25519 uses radix 2⁵¹
  with a dedicated squaring.
- On x86_64 with BMI2 + ADX (detected at run time; off with `ONLY_CRYPTO_PORTABLE=1`) the P-256
  field and order arithmetic and the X25519 ladder's field run in inline assembly (`mulx`,
  `adcx`/`adox`, corrections by `cmov` and `sbb` masks, straight-line code). The P-256
  operations run on a twin curve type that shares the Montgomery form and the base point tables;
  its Jacobian doubling (also `n` in a row), addition and mixed addition are whole-point `asm!`
  blocks over a small stack frame (products, reductions and the modular additions fused, the
  accumulator in registers), the safegcd divsteps are assembly too, and with AVX2 the table
  scans use `vpcmpeqq` masks over 256-bit loads.
- On aarch64 (every ARMv8.0 CPU, nothing to detect; off with `ONLY_CRYPTO_PORTABLE=1`) the P-256
  field and order arithmetic and the X25519 ladder's field run in inline assembly with
  `MUL`/`UMULH` products, `ADDS`/`ADCS`/`SUBS`/`SBCS` carry chains and `CSEL` corrections, on four
  64-bit limbs for both curves (the reduction modulo the P-256 prime uses shifts and subtractions
  only, as in OpenSSL's `ecp_nistz256-armv8`); inversions are safegcd with portable divsteps, and
  the point formulas, table scans and 4-bit comb are the portable ones over that field. The design
  follows the instruction counts (a 4×64 product is 16 `MUL` + 16 `UMULH` against 25 128-bit
  products in radix 2⁵¹); this path is tested but **not benchmarked yet**, so no aarch64 numbers
  are claimed.
- Secret scalar multiplication on P-256 / P-384 uses Jacobian coordinates (`a = -3`: doubling
  4M + 4S, addition 11M + 5S, mixed addition 7M + 4S). Variable base (ECDH): Booth-recoded signed
  5-bit windows (digits in `[-16, 16]`) over `1·P … 16·P`, every lookup reading all 16 entries,
  the negation a masked select. Fixed base: `k` recoded into signed 4-bit digits (masked
  arithmetic), one affine comb entry `|d|·16ⁱ·G` per digit, each lookup reading all 8 entries of
  the row; on the P-256 twin with AVX2, Booth-recoded signed 6-bit digits over a wider comb (43
  rows of 32 affine points `|d|·2⁶ⁱ·G`, 88 KiB built on first use), 43 mixed additions and every
  row read in full. The Jacobian formulas are incomplete: an accumulator still at the identity and a zero
  digit are masked selects, and equal operands cannot occur for scalars in `[1, n)` (the proofs
  are in `ec/mod.rs` and, for the wide comb, `ec/hw.rs`; they need `n mod 32 ≥ 17`, which a test
  checks). Decoding, validation and
  table construction keep the complete formulas (Renes–Costello–Batina).
- Ed25519 `[k]B` adds one affine Niels entry per signed 4-bit digit (complete unified addition,
  7M per digit). X25519 public keys are that `[k]B` mapped to `u = (1 + y)/(1 - y)`; the shared
  secret is the RFC 7748 ladder with masked swaps.
- RSA private operations: CRT exponentiation with fixed 4-bit windows over the full exponent
  length and masked table selection (fixed-size Montgomery code for 1024- to 4096-bit primes,
  squaring by a half-size product), base blinding (`rᵉ`, `r⁻¹` per key, inverted by Fermat in
  each prime field, squared after each use) and a check that `sᵉ = m` before releasing the
  signature. Moduli reductions are constant time; public `p`/`q` limb counts are not hidden.
- Known variable-time parts, all on public data: signature verification (ECDSA `u₁G + u₂Q` in
  Jacobian coordinates with width-7 / width-5 wNAF, a binary-GCD inversion of `s` and a
  projective `x ≡ r` check, Ed25519 `[s]B - [k]A` with interleaved wNAF, RSA `sᵉ`), table
  construction, point
  decoding/validation, the `Option`/`Result` outcome of range checks, RFC 6979's rejection loop
  (probability ~2⁻³²), `SecretKey::generate`'s rejection sampling, affine conversion branching
  on the identity (impossible for valid secret scalars).
- Limits: masks go through `std::hint::black_box`, which discourages but does not forbid the
  optimizer from reintroducing branches; without it LLVM does turn some masked modular corrections
  into jumps, so the barrier stays even where it costs speed (the assembly needs no barrier). The
  release x86_64 code (with the BMI2 + ADX assembly) and aarch64 code (with the aarch64 assembly,
  and portable) of the secret-scalar paths was disassembled and every conditional branch listed
  (`src/ct.rs` has the recipe): P-256 / P-384 `ecdh_x_impl`, `base_mul_impl`, `sign_impl` with the
  inlined window and comb loops, the Jacobian doubling and additions (the whole-point assembly
  included), the wide comb and the AVX2 scans, the field and order multiplication, squaring and
  inversions (safegcd with both divsteps), the Ed25519 base multiplication and both X25519
  ladders. The only branches are loop counters, public indices and bounds, the public exponent
  bits of the remaining Fermat chains, CPU-feature and `OnceLock` checks, the length of the output
  encoding, and the final "result is the identity" test. No statistical test (dudect, ctgrind) has
  been run. Keys are not zeroized. The CPU instructions used (AES, carry-less multiplication, SHA,
  CRC32, AVX2, `mulx`, `adcx`/`adox`, `cmov`; on aarch64 `MUL`, `UMULH`, the flag-setting
  additions and `CSEL`) take constant time.

## Performance

AMD Ryzen 7 7800X3D (x86_64, one core), `cargo run --release -p only-crypto --example bench`
and `--example pk_bench`; before = the previous release, the full tables and the TLS / KCP
numbers are in [docs/BENCHMARKS.md](../../docs/BENCHMARKS.md#cryptography-only-crypto-cpu-acceleration):

| Operation | before | after | vs RustCrypto / ring |
|---|---:|---:|---:|
| SHA-1, 16 KiB (MB/s) | 697 | 2 543 | 1.00x sha1 |
| SHA-256, 16 KiB | 366 | 2 383 | 1.00x sha2 |
| CRC-32, 16 KiB | 19 992 | 74 885 | 1.02x crc32fast |
| AES-128-GCM seal, 16 KiB | 6 455 | 15 048 | 1.19x ring |
| AES-128-GCM seal, 1400 B | 4 249 | 8 163 | 1.11x ring |
| AES-128-GCM seal, 64 B | 611 | 1 185 | 1.10x ring |
| ChaCha20-Poly1305 seal, 16 KiB | 588 | 1 757 | 0.89x chacha20poly1305 |
| Ed25519 verify (op/s) | 18 289 | 27 714 | 0.87x ring |
| Ed25519 sign | – | 89 784 | 1.53x ring |
| X25519 agreement | 28 865 | 36 488 | 1.00x ring |
| P-256 ECDSA sign | 23 435 | 59 837 | 0.79x ring |
| P-256 ECDSA verify | 8 043 | 25 138 | 0.96x ring |
| P-256 ECDH | 10 075 | 27 288 | 0.91x ring |
| P-256 key generation | – | 108 263 | 0.96x ring |
| P-384 ECDSA verify | 2 426 | 4 330 | 2.34x ring |
| RSA-2048 PKCS#1 sign | 871 | 1 192 | 0.49x ring |
| RSA-2048 PKCS#1 verify | 29 019 | 39 244 | 0.59x ring |
| TLS 1.3 full handshakes/s, X25519 (only-tls vs rustls + ring) | – | 5 027 | 1.00x rustls |
| TLS 1.3 full handshakes/s, secp256r1 | – | 4 552 | 0.89x rustls |

The public-key rows and the handshakes are from the P-256 / X25519 pass (before it: P-256 sign
34 152, verify 13 404, ECDH 10 380, X25519 30 696 op/s; handshakes 3 055 and 2 306/s). ring uses
assembly for AES-GCM, P-256, X25519 and RSA. The AES-GCM and CRC rows compare with the
previous VAES / VPCLMULQDQ-less code (`--example gcm-sizes` against ring, `--example bench`
against crc32fast); on Zen 4 the 512-bit kernel beat the same kernel on 256-bit registers at every
size. The whole-point P-256 pass (assembly doublings and additions, a 6-bit comb with AVX2
scans, safegcd inversions) moved P-256 against ring, measured in the same run on a loaded host
(docs/BENCHMARKS.md): sign 0.77× → 1.25×, key generation 0.94× → 1.33×, verify 0.98× → 1.04×,
ECDH 0.94× → 0.96×, secp256r1 handshakes 0.94× → 1.12× rustls; the P-256 rows of the table are
from the pass before. Follow-ups: a VAES + AVX2 kernel for CPUs without AVX-512, a SIMD Poly1305,
a P-256 reduction interleaved with the product rows (ECDH), measuring the aarch64 assembly for
P-256 and X25519 (tested, not benchmarked) and aarch64 whole-point routines and divsteps,
Karatsuba for RSA.

## Testing

- Known answers: NIST CAVP (SHAVS, HMACVS, AESAVS ECB, GCMVS), FIPS 197, SP 800-38A, the GCM
  specification, RFC 1321, 2202, 4231, 5869, 6070, 3720, 4648, 8439, and Wycheproof (AES-GCM,
  ChaCha20-Poly1305, HMAC-SHA1/SHA256, HKDF-SHA256), vendored under `tests/data/`.
- `tests/compat.rs` cross-checks every primitive against the replaced crates (dev-dependencies
  only); `fuzz/` has differential targets `crypto_hash`, `crypto_aead` (also the wide, 128-bit
  and portable AES-GCM paths against each other, in place and out of place), `crypto_base64`.
- The wide AES-GCM kernel (`gcm::tests`): every length 0..=600 and large sizes against the
  128-bit and portable paths, misaligned, in place and out of place, the 32-bit counter
  wrapping inside a group, and large messages against ring; it runs only on a CPU with VAES
  and AVX-512, so these tests are run natively on one (Zen 4).
- Hardware paths: unit tests compare each one with the portable code (`hardware_matches_portable`
  for AES, CTR, GCM, SHA-1, SHA-256, `hardware_matches_table` for CRC, the multi-block ChaCha20
  and two-block Poly1305 against one block at a time, `ec::hw`, `ec::hw_aarch64`,
  `curve25519::hw` and `curve25519::hw_aarch64` `matches_portable` for every field routine and
  the X25519 ladder on random and edge values, `chains_match_portable` on long chains of
  dependent operations (aarch64),
  `ec::hw` `points_match_portable` for the whole-point doubling, addition and mixed addition
  against the portable formulas, limb for limb, on random points with random `Z`, every valid
  Wycheproof ECDH point, `P + P`, `P + (-P)` and the identity, `safegcd` `matches_fermat` for
  both P-256 moduli, `twin_matches_portable` for P-256 key generation, ECDH, signing and
  verification), and the
  whole suite also runs with `ONLY_CRYPTO_PORTABLE=1`, on x86_64 and aarch64.
- The Jacobian scalar multiplications are checked against the complete-formula references
  (`mul_ref`, `mul_base_ref`) on random scalars and on edge scalars (the ends of `[1, n)`,
  `n - 2|d|` for every Booth digit, carries into the comb's top row, every top digit of the wide
  comb), for P-256, P-384 and the P-256 twin (with its whole-point assembly and wide comb); X25519 public keys from the Edwards table against the ladder on `u = 9`.
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
