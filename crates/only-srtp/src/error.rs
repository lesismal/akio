//! Errors.

use std::fmt;

/// Why an SRTP or SRTCP operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The master key or master salt length does not match the [`Profile`](crate::Profile).
    KeyLength,
    /// The packet is too short, is not RTP/RTCP version 2, or its header runs past its end.
    Malformed,
    /// The authentication tag did not verify (wrong key, tampered or truncated packet, or a
    /// mis-estimated rollover counter). The packet was not decrypted.
    Authentication,
    /// The packet index was already received or is older than the replay window.
    Replay,
    /// The packet index space is exhausted (2^31 SRTCP packets or 2^48 SRTP packets for one
    /// SSRC): the keys must be renegotiated.
    IndexExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::KeyLength => "SRTP: master key or salt length does not match the profile",
            Error::Malformed => "SRTP: malformed packet",
            Error::Authentication => "SRTP: authentication failed",
            Error::Replay => "SRTP: replayed or too old packet",
            Error::IndexExhausted => "SRTP: packet index exhausted",
        })
    }
}

impl std::error::Error for Error {}
