/// Why a cryptographic operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key, nonce, tag or requested output has a length the algorithm does not accept.
    InvalidLength,
    /// An authentication tag, MAC or signature did not verify; the data is forged or corrupted.
    Verification,
    /// A public or private key is malformed or unacceptable: a point not on the curve, the
    /// identity point, an RSA modulus of an unsupported size, inconsistent RSA parameters, a
    /// scalar out of range.
    InvalidKey,
    /// Malformed encoding: DER that is not strict DER, a PEM block that does not decode, a
    /// structure with the wrong shape.
    Encoding,
    /// A well-formed key or algorithm this crate does not implement (another curve, another
    /// hash, an unknown algorithm identifier).
    Unsupported,
    /// The operating system's random number generator failed.
    Random,
    /// A key agreement produced the all-zero shared secret (a low-order peer key).
    ZeroSharedSecret,
    /// A cost or size parameter is outside the algorithm's range (Argon2's time, memory or
    /// lanes).
    InvalidParameter,
    /// The memory an operation needs (Argon2's) could not be allocated.
    OutOfMemory,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "invalid length",
            Error::Verification => "authentication failed",
            Error::InvalidKey => "invalid key",
            Error::Encoding => "malformed encoding",
            Error::Unsupported => "unsupported algorithm or key type",
            Error::Random => "random number generator failed",
            Error::ZeroSharedSecret => "all-zero shared secret",
            Error::InvalidParameter => "parameter out of range",
            Error::OutOfMemory => "out of memory",
        })
    }
}

impl std::error::Error for Error {}
