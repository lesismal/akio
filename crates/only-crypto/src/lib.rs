#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! Dependency-free cryptographic primitives for the `only` crates: everything their protocols
//! need, in safe Rust on `std` only (`#![deny(unsafe_code)]`; the one exception is `aes::hw`, the
//! AES-NI / ARMv8 AES instructions used when the CPU has them).
//!
//! - [`hash`]: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and MD5, streaming or one-shot, behind
//!   the [`Hash`](hash::Hash) trait.
//! - [`mac`]: HMAC over any [`Hash`](hash::Hash).
//! - [`kdf`]: HKDF (RFC 5869) and PBKDF2-HMAC (RFC 8018).
//! - [`crc`]: CRC-32 (IEEE 802.3, as zlib / `crc32fast`) and CRC-32C (Castagnoli).
//! - [`aes`]: AES-128/192/256 on the CPU's AES instructions (AES-NI, ARMv8 AES) when present,
//!   else a constant-time fixsliced software implementation (no secret-dependent table lookups
//!   or branches); CTR mode.
//! - [`gcm`]: AES-GCM with a constant-time GHASH.
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
//! - [`p256`], [`p384`]: ECDH and ECDSA on the NIST curves (RFC 6979 nonces; DER and
//!   fixed-width signatures; validated SEC1 points).
//! - [`rsa`]: RSA PKCS#1 v1.5 and PSS signatures, 2048–8192-bit keys (CRT, blinding).
//! - [`der`], [`pem`]: strict ASN.1 DER reading/writing, PEM.
//! - [`pkey`]: algorithm-agnostic keys (PKCS#8, SEC1, PKCS#1, SubjectPublicKeyInfo) and
//!   signatures by [`SignatureAlgorithm`](pkey::SignatureAlgorithm).
//!
//! Timing: secret-dependent work (field and scalar arithmetic, scalar multiplication, RSA
//! private exponentiation) runs without secret-dependent branches or table indices: Montgomery
//! arithmetic with masked corrections, complete addition formulas, fixed windows with lookups
//! that read every table entry, the X25519 Montgomery ladder with masked swaps. Verification
//! and public-key operations are variable time (their inputs are public). The compiler is not
//! formally prevented from reintroducing branches (masks pass through `black_box`, nothing
//! stronger), and keys are not zeroized on drop.
//!
//! This is an implementation crate of `only` (like `only-sys`): its API follows the needs of the
//! other crates and may change in any release (docs/api-stability.md). It does not try to be a
//! general-purpose cryptography library: no key zeroization, and only AES uses CPU instructions
//! (the hashes, GHASH and CRC-32 are portable code).
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
pub mod ed25519;
pub mod gcm;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod p256;
pub mod p384;
pub mod pem;
pub mod pkey;
pub mod rand;
pub mod rsa;
pub mod x25519;

mod bignum;
mod ct;
mod curve25519;
mod ec;
mod error;
mod field;

pub use error::Error;

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
