//! The protobuf text format ([spec](https://protobuf.dev/reference/protobuf/textformat-spec/)),
//! for generated messages ([`ReflectMessage`]) and [`DynamicMessage`]s.
//!
//! * Parsing: fields by name (a group also by its type name), `:` optional before a message
//!   value, messages in `{ }` or `< >`, repeated fields one value at a time or as `[a, b]`,
//!   map entries as `{ key: .. value: .. }` (the last of a repeated key wins), extensions as
//!   `[pkg.ext]`, `Any` expanded as `[type.googleapis.com/pkg.Type] { .. }`, enums by name or
//!   number, `#` comments, `,` or `;` after a field. Integers in decimal, octal (`017`) or hex
//!   (`0x1F`), range-checked; floats with an optional `f` suffix, `inf`, `infinity`, `nan` in
//!   any case, out-of-range values going to infinity or zero; adjacent strings are joined, with
//!   all the escapes (`\n`, octal, `\x`, `\u`, `\U`; surrogates rejected); strings must be
//!   UTF-8. A singular field or a oneof given twice is an error; fields listed as `reserved`
//!   are skipped; unknown fields are errors unless [`ParseOptions::allow_unknown_fields`].
//!   Nesting is limited to [`RECURSION_LIMIT`].
//! * Printing: present fields in field-number order (extensions among them), one per line
//!   indented by two spaces (or on one line with [`PrintOptions::single_line`]), repeated
//!   fields one value per line, maps by key, `Any` expanded when its type is known, enums by
//!   name, floats as the shortest text that reads back the same. Unknown fields are left out
//!   unless [`PrintOptions::print_unknown_fields`] (then by number, as protoc prints them).
//!
//! ```
//! use akio_protobuf::{text, well_known::Duration};
//!
//! let d: Duration = text::from_str("seconds: 0x10 # sixteen\n nanos: -5").unwrap();
//! assert_eq!((d.seconds, d.nanos), (16, -5));
//! assert_eq!(text::to_string(&d).unwrap(), "seconds: 16\nnanos: -5\n");
//! let one = text::PrintOptions { single_line: true, ..Default::default() };
//! assert_eq!(text::to_string_with(&d, &one).unwrap(), "seconds: 16 nanos: -5");
//! ```

mod lex;
mod parse;
mod print;

use std::fmt;

use crate::reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, ReflectMessage};

/// How deeply messages may nest when parsing.
pub const RECURSION_LIMIT: usize = 100;

/// Why a message could not be parsed from text or printed as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextError {
    msg: String,
    line: usize,
    column: usize,
}

impl TextError {
    pub(crate) fn new(msg: impl Into<String>) -> TextError {
        TextError {
            msg: msg.into(),
            line: 0,
            column: 0,
        }
    }

    pub(crate) fn at(msg: impl Into<String>, line: usize, column: usize) -> TextError {
        TextError {
            msg: msg.into(),
            line,
            column,
        }
    }

    /// The line (from 1) the error was found on; 0 when it is not about a place in the input.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The column (from 1, in bytes) the error was found at; 0 when it is not about a place in
    /// the input.
    pub fn column(&self) -> usize {
        self.column
    }
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "protobuf text format: {}", self.msg)
        } else {
            write!(
                f,
                "protobuf text format: {}:{}: {}",
                self.line, self.column, self.msg
            )
        }
    }
}

impl std::error::Error for TextError {}

/// Printing settings.
#[derive(Clone, Debug, Default)]
pub struct PrintOptions {
    /// Everything on one line, fields separated by spaces (protoc's `ShortDebugString`).
    pub single_line: bool,
    /// Also print the unknown fields, by number (`1001: 5`, `1002: "x"`, `1003 { 1: 2 }`).
    pub print_unknown_fields: bool,
    /// More types for expanding `Any` (the message's own pool is searched first).
    pub type_pool: Option<DescriptorPool>,
}

/// Parsing settings.
#[derive(Clone, Debug, Default)]
pub struct ParseOptions {
    /// Skip fields and extensions the message type does not know instead of failing.
    pub allow_unknown_fields: bool,
    /// More types for expanded `Any`s (the message's own pool is searched first).
    pub type_pool: Option<DescriptorPool>,
}

/// `m` as text.
pub fn to_string<M: ReflectMessage>(m: &M) -> Result<String, TextError> {
    to_string_with(m, &PrintOptions::default())
}

/// `m` as text, with settings.
pub fn to_string_with<M: ReflectMessage>(m: &M, opts: &PrintOptions) -> Result<String, TextError> {
    let d = m.to_dynamic().map_err(|e| TextError::new(format!("{e}")))?;
    Ok(d.to_text(opts))
}

/// Parses an `M` from text.
pub fn from_str<M: ReflectMessage>(s: &str) -> Result<M, TextError> {
    from_str_with(s, &ParseOptions::default())
}

/// Parses an `M` from text, with settings.
pub fn from_str_with<M: ReflectMessage>(s: &str, opts: &ParseOptions) -> Result<M, TextError> {
    let d = parse_dynamic(M::descriptor(), s, opts)?;
    M::from_dynamic(&d).map_err(|e| TextError::new(format!("{e}")))
}

/// Parses a message of type `desc` from text.
pub fn parse_dynamic(
    desc: MessageDescriptor,
    s: &str,
    opts: &ParseOptions,
) -> Result<DynamicMessage, TextError> {
    parse::parse(desc, s, opts)
}

impl DynamicMessage {
    /// The message as text.
    pub fn to_text(&self, opts: &PrintOptions) -> String {
        print::print(self, opts)
    }

    /// Parses a message of type `desc` from text (see [`parse_dynamic`]).
    pub fn from_text(
        desc: MessageDescriptor,
        s: &str,
        opts: &ParseOptions,
    ) -> Result<DynamicMessage, TextError> {
        parse_dynamic(desc, s, opts)
    }
}

#[cfg(test)]
mod tests;
