//! The canonical proto3 JSON mapping, for generated messages ([`ReflectMessage`]) and
//! [`DynamicMessage`]s, with the well-known types' special forms (`Any`, `Timestamp`,
//! `Duration`, `FieldMask`, `Struct` / `Value` / `ListValue`, the wrappers, `Empty`).
//!
//! * Printing: fields by their JSON names (or the `.proto` names with
//!   [`PrintOptions::preserve_proto_field_names`]), 64-bit integers as strings, floats as the
//!   shortest text that reads back the same (`"NaN"`, `"Infinity"`, `"-Infinity"`), bytes as
//!   base64, enums by name, maps as objects; fields without presence are left out when they hold
//!   their default (unless [`PrintOptions::always_print_fields_with_no_presence`]); extensions
//!   as `"[full.name]"`.
//! * Parsing: strict RFC 8259 JSON (numbers kept as text, so 64-bit integers are exact); both
//!   the JSON and the `.proto` names; `null` leaves a field unset; integers as numbers or
//!   strings; enums by name or number; base64 in either alphabet, padded or not; a field given
//!   twice, or two members of a oneof, is an error; unknown fields are errors unless
//!   [`ParseOptions::ignore_unknown_fields`]. Nesting is limited to [`RECURSION_LIMIT`].
//!
//! ```
//! use akio_protobuf::{json, well_known::{Duration, Timestamp}};
//!
//! let t = Timestamp { seconds: 1_700_000_000, nanos: 500_000_000 };
//! assert_eq!(json::to_string(&t).unwrap(), "\"2023-11-14T22:13:20.500Z\"");
//! let back: Timestamp = json::from_str("\"2023-11-14T23:13:20.5+01:00\"").unwrap();
//! assert_eq!(back, t);
//! let d: Duration = json::from_str("\"-1.25s\"").unwrap();
//! assert_eq!((d.seconds, d.nanos), (-1, -250_000_000));
//! ```

mod parse;
mod print;
mod tree;
mod wkt;

use std::fmt;

use crate::reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, ReflectMessage};

/// How deeply JSON values (objects and arrays) may nest when parsing.
pub const RECURSION_LIMIT: usize = 100;

/// Why a message could not be printed as JSON or parsed from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError {
    msg: String,
}

impl JsonError {
    pub(crate) fn new(m: impl Into<String>) -> JsonError {
        JsonError { msg: m.into() }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protobuf JSON: {}", self.msg)
    }
}

impl std::error::Error for JsonError {}

pub(crate) type JResult<T> = Result<T, JsonError>;

pub(crate) fn err<T>(m: impl Into<String>) -> JResult<T> {
    Err(JsonError::new(m))
}

/// Printing settings.
#[derive(Clone, Debug, Default)]
pub struct PrintOptions {
    /// Field names as in the `.proto` file instead of their JSON (lowerCamelCase) names.
    pub preserve_proto_field_names: bool,
    /// Also print fields without presence (proto3 scalars, repeated fields, maps) holding their
    /// default value.
    pub always_print_fields_with_no_presence: bool,
    /// Enums as numbers instead of names.
    pub enums_as_numbers: bool,
    /// More types for `Any` type URLs (the message's own pool is searched first).
    pub type_pool: Option<DescriptorPool>,
}

/// Parsing settings.
#[derive(Clone, Debug, Default)]
pub struct ParseOptions {
    /// Skip fields (and enum names) the message type does not know instead of failing.
    pub ignore_unknown_fields: bool,
    /// More types for `Any` type URLs (the message's own pool is searched first).
    pub type_pool: Option<DescriptorPool>,
}

/// `m` as JSON.
pub fn to_string<M: ReflectMessage>(m: &M) -> Result<String, JsonError> {
    to_string_with(m, &PrintOptions::default())
}

/// `m` as JSON, with settings.
pub fn to_string_with<M: ReflectMessage>(m: &M, opts: &PrintOptions) -> Result<String, JsonError> {
    let d = m.to_dynamic().map_err(|e| JsonError::new(format!("{e}")))?;
    d.to_json(opts)
}

/// Parses an `M` from JSON.
pub fn from_str<M: ReflectMessage>(s: &str) -> Result<M, JsonError> {
    from_str_with(s, &ParseOptions::default())
}

/// Parses an `M` from JSON, with settings.
pub fn from_str_with<M: ReflectMessage>(s: &str, opts: &ParseOptions) -> Result<M, JsonError> {
    let d = parse_dynamic(M::descriptor(), s, opts)?;
    M::from_dynamic(&d).map_err(|e| JsonError::new(format!("{e}")))
}

/// Parses a message of type `desc` from JSON.
pub fn parse_dynamic(
    desc: MessageDescriptor,
    s: &str,
    opts: &ParseOptions,
) -> Result<DynamicMessage, JsonError> {
    let v = tree::parse(s)?;
    parse::message(desc, &v, opts, 0)
}

impl DynamicMessage {
    /// The message as JSON.
    pub fn to_json(&self, opts: &PrintOptions) -> Result<String, JsonError> {
        let mut out = String::new();
        print::message(self, opts, &mut out)?;
        Ok(out)
    }

    /// Parses a message of type `desc` from JSON (see [`parse_dynamic`]).
    pub fn from_json(
        desc: MessageDescriptor,
        s: &str,
        opts: &ParseOptions,
    ) -> Result<DynamicMessage, JsonError> {
        parse_dynamic(desc, s, opts)
    }
}

/// Finds the message type of an `Any` type URL (`.../pkg.Type`).
pub(crate) fn resolve_any(
    url: &str,
    own: &DescriptorPool,
    extra: Option<&DescriptorPool>,
) -> JResult<MessageDescriptor> {
    let name = match url.rsplit_once('/') {
        Some((_, n)) if !n.is_empty() => n,
        _ => return err(format!("invalid type URL {url:?}")),
    };
    own.get_message_by_name(name)
        .or_else(|| extra.and_then(|p| p.get_message_by_name(name)))
        .ok_or_else(|| JsonError::new(format!("unknown type {name:?} in Any")))
}

#[cfg(test)]
mod tests;
