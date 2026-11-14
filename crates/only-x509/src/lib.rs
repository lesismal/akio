#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! X.509 certificates for the `only` crates, on [`only_crypto`]: strict DER parsing, chain
//! building and validation against a root store, RFC 6125 server-name matching, and
//! certificate generation (self-signed or CA-signed) for tests and development servers.
//!
//! - [`Certificate`]: parsing (v1/v3; subjectAltName, basicConstraints, keyUsage,
//!   extKeyUsage, nameConstraints, key identifiers), PEM, signature checks.
//! - [`Verifier`] over a [`RootStore`]: path building through unordered intermediates,
//!   validity times, CA and pathLen constraints, key usage, extended key usage, name
//!   constraints, server names (DNS with leftmost-label wildcards, IP addresses).
//! - [`CertificateParams`] and [`generate_simple_self_signed`]: generation with ECDSA
//!   P-256/P-384, Ed25519 or RSA keys.
//!
//! Supported signature algorithms are those of [`only_crypto::pkey::SignatureAlgorithm`]:
//! ECDSA P-256/P-384 with SHA-256/384/512, Ed25519, RSA PKCS#1 v1.5 (SHA-1 verification only
//! for legacy chains) and RSA-PSS with SHA-256/384/512.
//!
//! Not implemented: revocation (CRL, OCSP), certificate policies, and name-constraint forms
//! other than DNS, IP and directoryName (others fail closed).
//!
//! ```
//! use only_x509::{CertificateParams, RootStore, Verifier, generate_simple_self_signed};
//!
//! // A CA, and a server certificate it issues.
//! let ca_key = only_crypto::pkey::PrivateKey::P256(only_crypto::p256::SecretKey::generate().unwrap());
//! let ca = CertificateParams::ca("Test CA").self_signed(&ca_key).unwrap();
//! let (_, leaf_key) = generate_simple_self_signed(["localhost"]).unwrap();
//! let leaf = CertificateParams::new(["localhost", "127.0.0.1"])
//!     .signed_by(&leaf_key.public_key(), &ca, &ca_key)
//!     .unwrap();
//!
//! let mut roots = RootStore::new();
//! roots.add(ca);
//! let v = Verifier::new(&roots);
//! v.verify_server(&leaf, &[], "localhost").unwrap();
//! v.verify_server(&leaf, &[], "127.0.0.1").unwrap();
//! assert!(v.verify_server(&leaf, &[], "example.com").is_err());
//! ```
//!
//! This is an implementation crate of `only`: its API follows the needs of the other crates
//! (the TLS and QUIC stacks) and may change in any release (docs/api-stability.md).

mod cert;
mod generate;
mod name;
mod time;
mod verify;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use cert::{
    BasicConstraints, Certificate, Extension, GeneralSubtree, KeyUsage, NameConstraints, ext,
};
pub use generate::{CertificateParams, IsCa, generate_simple_self_signed};
pub use name::{Attribute, GeneralName, Name, attr};
pub use verify::{
    MAX_INTERMEDIATES, MAX_SIGNATURE_CHECKS, RootStore, ServerName, Usage, Verifier,
    dns_name_matches, matches_server_name,
};

/// Why parsing or verification failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Malformed DER or PEM, or a structure that violates RFC 5280.
    Encoding,
    /// A version other than v1, v2 or v3 (or an explicitly encoded v1).
    UnsupportedVersion,
    /// The inner and outer signature algorithms differ.
    SignatureAlgorithmMismatch,
    /// An extension appears twice.
    DuplicateExtension,
    /// A critical extension this crate does not process (its OID).
    UnsupportedCriticalExtension(Vec<u8>),
    /// A certificate is not yet valid at the verification time.
    NotYetValid,
    /// A certificate has expired at the verification time.
    Expired,
    /// No path to a trusted root was found.
    UnknownIssuer,
    /// A signature did not verify.
    BadSignature,
    /// An issuer is not a CA (basicConstraints).
    NotCa,
    /// The end-entity certificate is a CA certificate.
    CaUsedAsEndEntity,
    /// A pathLenConstraint is exceeded.
    PathLenExceeded,
    /// The path would exceed [`MAX_INTERMEDIATES`].
    PathTooLong,
    /// The search exceeded [`MAX_SIGNATURE_CHECKS`].
    TooManySignatures,
    /// A CA's keyUsage lacks keyCertSign.
    KeyUsage,
    /// extKeyUsage does not allow the requested usage.
    ExtendedKeyUsage,
    /// The certificate is not valid for the server name.
    NameMismatch,
    /// The server name is not a valid DNS name or IP address.
    InvalidServerName,
    /// A name violates a CA's name constraints.
    NameConstraintViolation,
    /// A key or signature operation failed (unsupported algorithm or key, bad key).
    Crypto(only_crypto::Error),
}

impl From<only_crypto::Error> for Error {
    fn from(e: only_crypto::Error) -> Error {
        match e {
            only_crypto::Error::Encoding => Error::Encoding,
            e => Error::Crypto(e),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encoding => f.write_str("malformed certificate encoding"),
            Error::UnsupportedVersion => f.write_str("unsupported certificate version"),
            Error::SignatureAlgorithmMismatch => f.write_str("signature algorithm mismatch"),
            Error::DuplicateExtension => f.write_str("duplicate extension"),
            Error::UnsupportedCriticalExtension(o) => write!(
                f,
                "unsupported critical extension {}",
                only_crypto::der::oid::to_string(o).unwrap_or_default()
            ),
            Error::NotYetValid => f.write_str("certificate not yet valid"),
            Error::Expired => f.write_str("certificate expired"),
            Error::UnknownIssuer => f.write_str("unknown issuer"),
            Error::BadSignature => f.write_str("bad signature"),
            Error::NotCa => f.write_str("issuer is not a CA"),
            Error::CaUsedAsEndEntity => f.write_str("CA certificate used as end entity"),
            Error::PathLenExceeded => f.write_str("path length constraint exceeded"),
            Error::PathTooLong => f.write_str("certificate path too long"),
            Error::TooManySignatures => f.write_str("too many signature checks"),
            Error::KeyUsage => f.write_str("key usage does not allow certificate signing"),
            Error::ExtendedKeyUsage => f.write_str("extended key usage does not allow this use"),
            Error::NameMismatch => f.write_str("certificate not valid for this name"),
            Error::InvalidServerName => f.write_str("invalid server name"),
            Error::NameConstraintViolation => f.write_str("name constraint violation"),
            Error::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

impl std::error::Error for Error {}
