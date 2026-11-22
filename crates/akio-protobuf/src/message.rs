//! The [`Message`] trait, enums and unknown fields.

use std::fmt;

use crate::{
    DecodeError, DecodeErrorKind,
    encoding::{self, Reader, WireType},
};

/// A protobuf message. `akio-protobuf-build` generates the implementations; the three required
/// methods are all a hand-written message needs.
pub trait Message: Default {
    /// Appends the fields (without a length prefix).
    fn encode_raw(&self, buf: &mut Vec<u8>);

    /// The length of [`encode_raw`](Self::encode_raw)'s output.
    fn encoded_len(&self) -> usize;

    /// Decodes one field whose tag was just read, merging it into `self`. Unknown fields go to
    /// the message's [`UnknownFields`] (or are skipped with [`Reader::skip_field`]).
    fn merge_field(
        &mut self,
        field: u32,
        wire_type: WireType,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError>;

    /// Decodes fields until `r` is empty, merging them into `self`.
    fn merge_from(&mut self, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        while !r.is_empty() {
            let (field, wire_type) = r.read_tag()?;
            if wire_type == WireType::EndGroup {
                return Err(DecodeError::new(DecodeErrorKind::UnbalancedGroup).in_field(field));
            }
            self.merge_field(field, wire_type, r)?;
        }
        Ok(())
    }

    /// Appends the encoding to `buf`.
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.reserve(self.encoded_len());
        self.encode_raw(buf);
    }

    /// The encoding in a new vector.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.encoded_len());
        self.encode_raw(&mut v);
        v
    }

    /// Appends the encoding prefixed with its length as a varint (the framing of
    /// `writeDelimitedTo` / `parseDelimitedFrom`).
    fn encode_length_delimited(&self, buf: &mut Vec<u8>) {
        let n = self.encoded_len();
        buf.reserve(n + encoding::varint_len(n as u64));
        encoding::put_varint(buf, n as u64);
        self.encode_raw(buf);
    }

    /// Decodes a message.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut m = Self::default();
        m.merge_from(&mut Reader::new(bytes))?;
        Ok(m)
    }

    /// Decodes a length-prefixed message (see
    /// [`encode_length_delimited`](Self::encode_length_delimited)); bytes after it are ignored.
    fn decode_length_delimited(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let mut m = Self::default();
        m.merge_from(&mut Reader::new(r.read_bytes()?))?;
        Ok(m)
    }

    /// Decodes `bytes` and merges them into `self` (scalars replaced, messages merged, repeated
    /// fields appended).
    fn merge(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        self.merge_from(&mut Reader::new(bytes))
    }

    /// Resets every field to its default.
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// The fully-qualified protobuf name of a message (`package.Message`), used by
/// [`Any`](crate::well_known::Any).
pub trait Name {
    /// `package.Outer.Inner`.
    const FULL_NAME: &'static str;

    /// `type.googleapis.com/<FULL_NAME>`, the type URL `Any` uses.
    fn type_url() -> String {
        format!("type.googleapis.com/{}", Self::FULL_NAME)
    }
}

/// A protobuf enum. Generated enums are open: a newtype over `i32` with one associated constant
/// per value, so numbers this version does not know survive decoding and re-encoding.
pub trait Enumeration: Copy + Default {
    /// The enum holding `v` (known or not).
    fn from_i32(v: i32) -> Self;
    /// The number.
    fn value(self) -> i32;
    /// The value's name in the `.proto` file, when it is a known one.
    fn name(self) -> Option<&'static str>;
    /// Whether the number is one the `.proto` file declares.
    fn is_known(self) -> bool {
        self.name().is_some()
    }
}

/// Fields a message did not recognize while decoding, kept in their encoded form and written
/// back after the known fields on encoding (proto3 semantics since 3.5).
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct UnknownFields {
    raw: Vec<u8>,
}

impl UnknownFields {
    /// None.
    pub const fn new() -> UnknownFields {
        UnknownFields { raw: Vec::new() }
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// The fields, encoded (tags included).
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Drops them.
    pub fn clear(&mut self) {
        self.raw.clear();
    }

    /// Reads the value of a field whose tag was just read and keeps it.
    pub fn merge_field(
        &mut self,
        field: u32,
        wire_type: WireType,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        let raw = r
            .skip_field(field, wire_type)
            .map_err(|e| e.in_field(field))?;
        encoding::put_tag(&mut self.raw, field, wire_type);
        self.raw.extend_from_slice(raw);
        Ok(())
    }

    /// Keeps a varint field (a closed enum's unknown number).
    pub(crate) fn push_varint(&mut self, field: u32, v: u64) {
        encoding::put_tag(&mut self.raw, field, WireType::Varint);
        encoding::put_varint(&mut self.raw, v);
    }

    /// Keeps a field given its raw value (a length-delimited one gets its length prefix).
    pub(crate) fn push_raw(&mut self, field: u32, wire_type: WireType, value: &[u8]) {
        encoding::put_tag(&mut self.raw, field, wire_type);
        if wire_type == WireType::Len {
            encoding::put_bytes(&mut self.raw, value);
        } else {
            self.raw.extend_from_slice(value);
        }
    }

    /// Appends them, as read.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.raw);
    }

    /// Their encoded length.
    pub fn encoded_len(&self) -> usize {
        self.raw.len()
    }
}

impl fmt::Debug for UnknownFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnknownFields({} bytes)", self.raw.len())
    }
}
