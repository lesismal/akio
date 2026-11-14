//! Codec helpers: H.264, H.265, AAC and Opus configuration records and framing.

pub mod aac;
pub mod h264;
pub mod h265;
pub mod opus;

use std::fmt;

/// A malformed codec header or configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The data ended early.
    Short,
    /// The named structure is malformed.
    Invalid(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Short => f.write_str("codec data too short"),
            CodecError::Invalid(what) => write!(f, "malformed {what}"),
        }
    }
}

impl std::error::Error for CodecError {}
