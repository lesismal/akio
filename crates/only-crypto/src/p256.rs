//! NIST P-256 (secp256r1): ECDH and ECDSA (SHA-256 by default; deterministic nonces, RFC 6979).
//!
//! Secret-key operations are constant time (see the crate documentation); keys decoded from
//! SEC1 are validated (on the curve, not the identity).
//!
//! ```
//! use only_crypto::p256::{SecretKey, Signature};
//!
//! let k = SecretKey::generate().unwrap();
//! let sig = k.sign(b"message");
//! let der = sig.to_der();
//! k.public_key().verify(b"message", &Signature::from_der(&der).unwrap()).unwrap();
//!
//! let peer = SecretKey::generate().unwrap();
//! assert_eq!(k.diffie_hellman(&peer.public_key()), peer.diffie_hellman(&k.public_key()));
//! ```

crate::ec::api::curve_api!(ec::curves::P256, 4, 32, crate::hash::Sha256, "P-256");
