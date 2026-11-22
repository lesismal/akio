//! Decoding errors.

use std::fmt;

/// Why a message failed to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The input ended inside a tag, varint, fixed-width value or length-delimited field.
    Truncated,
    /// A varint longer than 10 bytes, or one that overflows 64 bits.
    VarintOverflow,
    /// Field number 0, a number above 2^29 - 1, or an unknown wire type.
    InvalidTag,
    /// A field arrived with a wire type that does not match its declaration.
    WireTypeMismatch,
    /// A `string` field that is not valid UTF-8.
    InvalidUtf8,
    /// Messages (or groups) nested deeper than the recursion limit.
    RecursionLimit,
    /// An end-group tag without a matching start-group tag, or a group left open.
    UnbalancedGroup,
}

/// A malformed protobuf encoding. Carries the kind and, when known, the field number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    kind: DecodeErrorKind,
    field: Option<u32>,
}

impl DecodeError {
    /// An error of `kind`, not tied to a field.
    pub const fn new(kind: DecodeErrorKind) -> DecodeError {
        DecodeError { kind, field: None }
    }

    /// The same error, noting the field it happened in (the innermost field wins).
    #[must_use]
    pub fn in_field(mut self, field: u32) -> DecodeError {
        if self.field.is_none() {
            self.field = Some(field);
        }
        self
    }

    /// What went wrong.
    pub fn kind(&self) -> DecodeErrorKind {
        self.kind
    }

    /// The field number, when the error happened inside a known field.
    pub fn field(&self) -> Option<u32> {
        self.field
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            DecodeErrorKind::Truncated => "truncated input",
            DecodeErrorKind::VarintOverflow => "varint overflow",
            DecodeErrorKind::InvalidTag => "invalid tag",
            DecodeErrorKind::WireTypeMismatch => "wire type mismatch",
            DecodeErrorKind::InvalidUtf8 => "string is not valid UTF-8",
            DecodeErrorKind::RecursionLimit => "recursion limit exceeded",
            DecodeErrorKind::UnbalancedGroup => "unbalanced group",
        };
        write!(f, "protobuf decode error: {what}")?;
        if let Some(n) = self.field {
            write!(f, " (field {n})")?;
        }
        Ok(())
    }
}

impl std::error::Error for DecodeError {}
