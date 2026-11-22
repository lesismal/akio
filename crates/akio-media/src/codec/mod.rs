//! Codec helpers: H.264, H.265, VP8, VP9, AV1, AAC and Opus configuration records, framing
//! and keyframe detection.

pub mod aac;
pub mod av1;
pub mod h264;
pub mod h265;
pub mod opus;
pub mod vp8;
pub mod vp9;

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
