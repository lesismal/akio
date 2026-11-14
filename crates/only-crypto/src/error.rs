/// Why a cryptographic operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key, nonce, tag or requested output has a length the algorithm does not accept.
    InvalidLength,
    /// An authentication tag or MAC did not verify; the data is forged or corrupted.
    Verification,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "invalid length",
            Error::Verification => "authentication failed",
        })
    }
}

impl std::error::Error for Error {}
