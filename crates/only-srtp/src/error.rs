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
    /// An invalid setting: an empty, too long, duplicate or wrong-length MKI, an MKI on a
    /// context without MKIs, too many master keys, or a key derivation rate that is not 0 or a
    /// power of two up to 2^24.
    Config,
    /// The packet's MKI matches none of the context's master keys.
    UnknownMki,
    /// The packet uses something this context cannot protect: with cryptex, a header
    /// extension that is neither one-byte (`0xBEDE`) nor two-byte (`0x1000`).
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::KeyLength => "SRTP: master key or salt length does not match the profile",
            Error::Malformed => "SRTP: malformed packet",
            Error::Authentication => "SRTP: authentication failed",
            Error::Replay => "SRTP: replayed or too old packet",
            Error::IndexExhausted => "SRTP: packet index exhausted",
            Error::Config => "SRTP: invalid MKI, master key or key derivation rate setting",
            Error::UnknownMki => "SRTP: unknown MKI",
            Error::Unsupported => "SRTP: header extension not supported by cryptex",
        })
    }
}

impl std::error::Error for Error {}
