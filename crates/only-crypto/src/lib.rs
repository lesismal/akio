#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! Dependency-free cryptographic primitives for the `only` crates: everything their protocols
//! need, in Rust on `std` only (`#![deny(unsafe_code)]`; the exceptions are twelve small
//! modules that call CPU instructions when the CPU has them, detected at run time: `aes::hw`,
//! `gcm::hw`, `hash::hw`, `crc::hw`, `chacha::hw`, `cpu::hw` for CPUID, the inline-assembly field
//! arithmetic `ec::hw` and `curve25519::hw` (x86_64), `ec::hw_aarch64` and
//! `curve25519::hw_aarch64` (aarch64), and the RSA Montgomery arithmetic `bignum::hw` and
//! `bignum::ifma` (x86_64); and `fill`, the AEAD output buffer that lets the TLS record layer
//! seal and open straight into a vector's spare capacity without zero-filling it first).
//!
//! Hardware paths, each with a constant-time portable fallback that is also used when the
//! environment variable `ONLY_CRYPTO_PORTABLE=1` is set (tests, benchmarks):
//!
//! | | x86_64 | aarch64 |
//! |---|---|---|
//! | AES (block, CTR 8 blocks at a time) | AES-NI | ARMv8 AES |
//! | AES-GCM (GHASH, fused with CTR) | VAES + VPCLMULQDQ + AVX-512 (16 blocks per reduction), else VAES + VPCLMULQDQ + AVX2 (16), else PCLMULQDQ + AES-NI (8) | PMULL + ARMv8 AES |
//! | SHA-1, SHA-256 | SHA-NI | ARMv8 SHA1/SHA2 |
//! | CRC-32, CRC-32C | VPCLMULQDQ + AVX-512 or PCLMULQDQ folding, SSE4.2 `crc32` | ARMv8 CRC32 |
//! | ChaCha20 | AVX-512 (`vprold`; 16, 8 or 4 blocks), else AVX2 (8 blocks) | portable 4-block lanes (NEON by the compiler) |
//! | Poly1305 | AVX-512 IFMA (8 blocks per step, runs of 256 bytes and more), else radix 2⁶⁴ scalar | radix 2⁶⁴ scalar |
//! | P-256 field and scalar arithmetic, X25519 ladder | BMI2 + ADX (`mulx`, `adcx`/`adox`) | `MUL`/`UMULH`, `ADDS`/`ADCS`, `CSEL` (every ARMv8.0 CPU) |
//!
//! - [`hash`]: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and MD5, streaming or one-shot, behind
//!   the [`Hash`](hash::Hash) trait; SHAKE128 and SHAKE256.
//! - [`mac`]: HMAC over any [`Hash`](hash::Hash).
//! - [`kdf`]: HKDF (RFC 5869) and PBKDF2-HMAC (RFC 8018).
//! - [`crc`]: CRC-32 (IEEE 802.3, as zlib / `crc32fast`) and CRC-32C (Castagnoli).
//! - [`aes`]: AES-128/192/256 on the CPU's AES instructions (AES-NI, ARMv8 AES) when present,
//!   else a constant-time fixsliced software implementation (no secret-dependent table lookups
//!   or branches); CTR mode.
//! - [`gcm`]: AES-GCM with a constant-time GHASH.
//! - [`seed`]: SEED (RFC 4269) with CTR, CCM and GCM (RFC 5669, for SRTP), bitsliced S-boxes,
//!   no tables.
//! - [`chacha`]: ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439).
//! - [`base64`]: standard and URL-safe alphabets, padded or not, strict decoding.
//! - [`rand`]: the operating system's randomness ([`fill_random`](rand::fill_random)) and a
//!   ChaCha20-based generator seeded from it.
//! - [`ct_eq`]: constant-time comparison of secrets (MACs, tags).
//!
//! Public-key cryptography (for the TLS, DTLS, QUIC and WebRTC stacks and `only-x509`):
//!
//! - [`x25519`]: X25519 key agreement (RFC 7748).
//! - [`ed25519`]: Ed25519 signatures (RFC 8032) with strict verification.
//! - [`x448`], [`ed448`]: X448 (RFC 7748) and Ed448 (RFC 8032), portable constant-time code.
//! - [`dsa`]: DSA signature verification (FIPS 186-4), for legacy certificates.
//! - [`p256`], [`p384`], [`p521`]: ECDH and ECDSA on the NIST curves (RFC 6979 nonces; DER and
//!   fixed-width signatures; validated SEC1 points; P-521 on its own Mersenne-prime field with
//!   complete formulas, portable Rust).
//! - [`rsa`]: RSA PKCS#1 v1.5 and PSS signatures, 2048–8192-bit keys (CRT, blinding).
//! - [`der`], [`pem`]: strict ASN.1 DER reading/writing, PEM.
//! - [`pkey`]: algorithm-agnostic keys (PKCS#8, SEC1, PKCS#1, SubjectPublicKeyInfo; RSA keys as
//!   `rsaEncryption` or `id-RSASSA-PSS` with [`PssParams`](pkey::PssParams)) and signatures by
//!   [`SignatureAlgorithm`](pkey::SignatureAlgorithm).
//!
//! Timing: secret-dependent work (field and scalar arithmetic, scalar multiplication, RSA
//! private exponentiation) runs without secret-dependent branches or table indices: Montgomery
//! arithmetic with masked corrections (or `cmov` / `CSEL` in the assembly), Jacobian formulas
//! whose exceptional cases are masked selects or proven unreachable, Booth-recoded fixed windows
//! and a signed comb with lookups that read every table entry, inversion by fixed exponents
//! (addition chains, fixed windows), the X25519 Montgomery ladder with masked swaps.
//! Verification and public-key operations are variable time (their inputs are public: wNAF, a
//! binary-GCD inversion). The compiler is not formally prevented from reintroducing branches
//! into the Rust code (masks pass through `black_box`, nothing stronger; the x86_64 and aarch64
//! code of the point operations was checked for conditional branches), and keys are not zeroized
//! on drop. The CPU instructions used take constant time.
//!
//! This is an implementation crate of `only` (like `only-sys`): its API follows the needs of the
//! other crates and may change in any release (docs/api-stability.md). It does not try to be a
//! general-purpose cryptography library: no key zeroization, and assembly only for the wide
//! AES-GCM kernel and CRC fold, the AVX-512 ChaCha20 and IFMA Poly1305 kernels (`asm!`: the
//! VAES, VPCLMULQDQ, AVX-512 and IFMA intrinsics are newer than the MSRV) and for the P-256,
//! Curve25519 and RSA arithmetic on x86_64 (P-256 and Curve25519 also on aarch64; SHA-512, MD5
//! and the rest of the public-key arithmetic are portable Rust).
//!
//! ```
//! use only_crypto::hash::{Hash, Sha256};
//! use only_crypto::mac::Hmac;
//!
//! let d = Sha256::digest(b"abc");
//! assert_eq!(d[0], 0xba);
//! let tag = Hmac::<Sha256>::mac(b"key", b"The quick brown fox jumps over the lazy dog");
//! assert_eq!(tag[..4], [0xf7, 0xbc, 0x83, 0xf4]);
//! ```
//!
//! Guide: [Architecture](https://lesismal.github.io/only/en/architecture.html)
//! (中文: [架构](https://lesismal.github.io/only/zh-CN/architecture.html)).

pub mod aes;
pub mod base64;
pub mod chacha;
pub mod crc;
pub mod der;
pub mod dsa;
pub mod ed25519;
pub mod ed448;
pub mod gcm;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod p256;
pub mod p384;
pub mod p521;
pub mod pem;
pub mod pkey;
pub mod rand;
pub mod rsa;
pub mod seed;
pub mod x25519;
pub mod x448;

mod bignum;
mod cpu;
mod ct;
mod curve25519;
mod curve448;
mod ec;
mod error;
mod field;
mod fill;
mod safegcd;

pub use error::Error;

#[doc(hidden)]
pub use cpu::{hardware_features, is_portable, set_portable};

/// `N` bytes from the operating system's randomness.
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    rand::fill_random(&mut b).map_err(|_| Error::Random)?;
    Ok(b)
}

/// Compares two byte strings in time that depends only on their lengths, not on their contents
/// (for MACs, AEAD tags and other secrets). Strings of different lengths are unequal.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // `black_box` keeps the optimizer from turning the loop into an early-exit comparison.
    std::hint::black_box(d) == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn ct_eq() {
        assert!(super::ct_eq(b"", b""));
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"ab"));
    }
}
