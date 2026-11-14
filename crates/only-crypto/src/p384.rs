//! NIST P-384 (secp384r1): ECDH and ECDSA (SHA-384 by default; deterministic nonces, RFC 6979).
//!
//! The API is the same as [`p256`](crate::p256)'s.
//!
//! ```
//! use only_crypto::p384::SecretKey;
//!
//! let k = SecretKey::generate().unwrap();
//! let sig = k.sign(b"message");
//! k.public_key().verify(b"message", &sig).unwrap();
//! ```

crate::ec::api::curve_api!(ec::curves::P384, 6, 48, crate::hash::Sha384, "P-384");
