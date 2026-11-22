//! The wire format: varints, zigzag, fixed-width values, length-delimited fields, groups, and
//! the per-field encoders and decoders the generated code calls.
//!
//! Each protobuf scalar type has a zero-sized [`Codec`] (`Int32`, `Sint64`, `Fixed32`,
//! `StringCodec`, [`MessageCodec`], [`EnumCodec`] ...). The field functions combine a codec with
//! the field's shape:
//!
//! | Shape | Encode | Length | Decode |
//! |---|---|---|---|
//! | proto3 implicit presence (skipped when default) | [`encode_implicit`] | [`implicit_len`] | [`merge_value`] |
//! | always present (proto2 `required`, oneof member) | [`encode_required`] | [`required_len`] | [`merge_value`] |
//! | explicit presence (`optional`, message fields) | [`encode_optional`] | [`optional_len`] | [`merge_optional`], [`merge_boxed`] |
//! | `repeated`, unpacked | [`encode_repeated`] | [`repeated_len`] | [`merge_repeated`] |
//! | `repeated`, packed | [`encode_packed`] | [`packed_len`] | [`merge_repeated`] |
//! | `map<K, V>` | [`encode_map`] | [`map_len`] | [`merge_map`] |
//!
//! Decoders of repeated scalars accept both the packed and the unpacked encoding, as the
//! specification requires. Generated code checks the wire type first ([`accepts`],
//! [`accepts_repeated`]) and keeps a field with an unexpected one as an unknown field, as the
//! C++ and Go runtimes do; the `merge_*` functions themselves reject it.
//!
//! ```
//! use akio_protobuf::encoding::{self, Int32, Reader, StringCodec};
//!
//! let mut buf = Vec::new();
//! encoding::encode_implicit::<Int32>(1, &150, &mut buf);
//! encoding::encode_implicit::<StringCodec>(2, &"hi".to_string(), &mut buf);
//! assert_eq!(buf, [0x08, 0x96, 0x01, 0x12, 0x02, b'h', b'i']);
//! assert_eq!(encoding::implicit_len::<Int32>(1, &150), 3);
//!
//! let mut r = Reader::new(&buf);
//! let (field, wire_type) = r.read_tag().unwrap();
//! let mut v = 0;
//! encoding::merge_value::<Int32>(field, wire_type, &mut r, &mut v).unwrap();
//! assert_eq!(v, 150);
//! ```

use std::marker::PhantomData;

use crate::{DecodeError, DecodeErrorKind, Enumeration, Message, UnknownFields};

/// How deep messages and groups may nest while decoding (as in the C++ and Go runtimes).
pub const RECURSION_LIMIT: u32 = 100;

/// The largest field number (2^29 - 1).
pub const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;

/// The wire type in the low three bits of a tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WireType {
    /// int32, int64, uint32, uint64, sint32, sint64, bool, enum.
    Varint = 0,
    /// fixed64, sfixed64, double.
    Fixed64 = 1,
    /// string, bytes, embedded messages, packed repeated fields.
    Len = 2,
    /// Start of a (deprecated) group.
    StartGroup = 3,
    /// End of a group.
    EndGroup = 4,
    /// fixed32, sfixed32, float.
    Fixed32 = 5,
}

impl WireType {
    /// The wire type with number `v`, if it is one.
    pub const fn from_u8(v: u8) -> Option<WireType> {
        Some(match v {
            0 => WireType::Varint,
            1 => WireType::Fixed64,
            2 => WireType::Len,
            3 => WireType::StartGroup,
            4 => WireType::EndGroup,
            5 => WireType::Fixed32,
            _ => return None,
        })
    }
}

const fn err(kind: DecodeErrorKind) -> DecodeError {
    DecodeError::new(kind)
}

// ---- primitives ------------------------------------------------------------------------------

/// Appends `v` as a varint.
#[inline]
pub fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

/// The length of `v` as a varint (1 to 10).
#[inline]
pub const fn varint_len(v: u64) -> usize {
    // ceil(bits / 7) with bits >= 1, without a loop.
    ((64 - (v | 1).leading_zeros()) as usize * 9 + 64) / 64
}

/// Appends a tag (`field << 3 | wire_type`).
#[inline]
pub fn put_tag(buf: &mut Vec<u8>, field: u32, wire_type: WireType) {
    put_varint(buf, (u64::from(field) << 3) | wire_type as u64);
}

/// The length of the tag of `field`.
#[inline]
pub const fn tag_len(field: u32) -> usize {
    varint_len((field as u64) << 3)
}

/// ZigZag-encodes a 32-bit signed integer (sint32).
#[inline]
pub const fn zigzag32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

/// ZigZag-encodes a 64-bit signed integer (sint64).
#[inline]
pub const fn zigzag64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Decodes a ZigZag-encoded 32-bit value.
#[inline]
pub const fn unzigzag32(v: u32) -> i32 {
    ((v >> 1) as i32) ^ -((v & 1) as i32)
}

/// Decodes a ZigZag-encoded 64-bit value.
#[inline]
pub const fn unzigzag64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Appends a length-delimited value (length varint, then the bytes).
#[inline]
pub fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    put_varint(buf, b.len() as u64);
    buf.extend_from_slice(b);
}

/// A cursor over an encoded message. It tracks the nesting depth for [`RECURSION_LIMIT`].
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    depth: u32,
}

impl<'a> Reader<'a> {
    /// A reader over `buf` at depth 0.
    pub const fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, depth: 0 }
    }

    /// The bytes not read yet.
    pub const fn remaining(&self) -> &'a [u8] {
        self.buf
    }

    /// Whether everything has been read.
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The nesting depth (0 for the outermost message).
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Reads a varint.
    #[inline]
    pub fn read_varint(&mut self) -> Result<u64, DecodeError> {
        match self.buf.first() {
            Some(&b) if b < 0x80 => {
                self.buf = &self.buf[1..];
                Ok(u64::from(b))
            }
            _ => self.read_varint_slow(),
        }
    }

    #[cold]
    fn read_varint_slow(&mut self) -> Result<u64, DecodeError> {
        let mut v: u64 = 0;
        for i in 0..10 {
            let Some(&b) = self.buf.get(i) else {
                return Err(err(DecodeErrorKind::Truncated));
            };
            if i == 9 && b > 1 {
                return Err(err(DecodeErrorKind::VarintOverflow));
            }
            v |= u64::from(b & 0x7f) << (7 * i);
            if b < 0x80 {
                self.buf = &self.buf[i + 1..];
                return Ok(v);
            }
        }
        Err(err(DecodeErrorKind::VarintOverflow))
    }

    /// Reads a little-endian 32-bit value.
    #[inline]
    pub fn read_fixed32(&mut self) -> Result<u32, DecodeError> {
        let (head, rest) = self
            .buf
            .split_first_chunk::<4>()
            .ok_or(err(DecodeErrorKind::Truncated))?;
        self.buf = rest;
        Ok(u32::from_le_bytes(*head))
    }

    /// Reads a little-endian 64-bit value.
    #[inline]
    pub fn read_fixed64(&mut self) -> Result<u64, DecodeError> {
        let (head, rest) = self
            .buf
            .split_first_chunk::<8>()
            .ok_or(err(DecodeErrorKind::Truncated))?;
        self.buf = rest;
        Ok(u64::from_le_bytes(*head))
    }

    /// Reads a length-delimited value and returns its bytes.
    #[inline]
    pub fn read_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.read_varint()?;
        if n > self.buf.len() as u64 {
            return Err(err(DecodeErrorKind::Truncated));
        }
        let (b, rest) = self.buf.split_at(n as usize);
        self.buf = rest;
        Ok(b)
    }

    /// Reads a tag: the field number (1 ..= [`MAX_FIELD_NUMBER`]) and the wire type.
    #[inline]
    pub fn read_tag(&mut self) -> Result<(u32, WireType), DecodeError> {
        let before = self.buf.len();
        let v = self.read_varint()?;
        // A tag is at most 5 bytes (32 bits), even when its value is small.
        if before - self.buf.len() > 5 {
            return Err(err(DecodeErrorKind::InvalidTag));
        }
        let field = v >> 3;
        let wt = WireType::from_u8((v & 7) as u8);
        match wt {
            Some(wt) if field != 0 && field <= u64::from(MAX_FIELD_NUMBER) => {
                Ok((field as u32, wt))
            }
            _ => Err(err(DecodeErrorKind::InvalidTag)),
        }
    }

    /// Reads a length-delimited value as a reader one level deeper (an embedded message).
    #[inline]
    pub fn nested(&mut self) -> Result<Reader<'a>, DecodeError> {
        if self.depth >= RECURSION_LIMIT {
            return Err(err(DecodeErrorKind::RecursionLimit));
        }
        let buf = self.read_bytes()?;
        Ok(Reader {
            buf,
            depth: self.depth + 1,
        })
    }

    /// Skips the value of a field whose tag was just read and returns its raw bytes (for a
    /// group: everything up to and including the end-group tag).
    pub fn skip_field(&mut self, field: u32, wire_type: WireType) -> Result<&'a [u8], DecodeError> {
        let start = self.buf;
        match wire_type {
            WireType::Varint => {
                self.read_varint()?;
            }
            WireType::Fixed64 => {
                self.read_fixed64()?;
            }
            WireType::Fixed32 => {
                self.read_fixed32()?;
            }
            WireType::Len => {
                self.read_bytes()?;
            }
            WireType::StartGroup => self.skip_group(field)?,
            WireType::EndGroup => return Err(err(DecodeErrorKind::UnbalancedGroup)),
        }
        Ok(&start[..start.len() - self.buf.len()])
    }

    /// Decodes the fields of a group whose start tag (field `field`) was just read into `m`, up
    /// to and including the matching end-group tag. Groups count towards [`RECURSION_LIMIT`].
    pub fn merge_group<M: Message>(&mut self, field: u32, m: &mut M) -> Result<(), DecodeError> {
        if self.depth >= RECURSION_LIMIT {
            return Err(err(DecodeErrorKind::RecursionLimit));
        }
        self.depth += 1;
        let r = loop {
            if self.buf.is_empty() {
                break Err(err(DecodeErrorKind::UnbalancedGroup));
            }
            let (f, wt) = match self.read_tag() {
                Ok(t) => t,
                Err(e) => break Err(e),
            };
            if wt == WireType::EndGroup {
                break if f == field {
                    Ok(())
                } else {
                    Err(err(DecodeErrorKind::UnbalancedGroup))
                };
            }
            if let Err(e) = m.merge_field(f, wt, self) {
                break Err(e);
            }
        };
        self.depth -= 1;
        r
    }

    /// One level deeper, in the same buffer (a group).
    pub(crate) fn enter(&mut self) -> Result<(), DecodeError> {
        if self.depth >= RECURSION_LIMIT {
            return Err(err(DecodeErrorKind::RecursionLimit));
        }
        self.depth += 1;
        Ok(())
    }

    /// Back out of [`enter`](Self::enter).
    pub(crate) fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn skip_group(&mut self, field: u32) -> Result<(), DecodeError> {
        if self.depth >= RECURSION_LIMIT {
            return Err(err(DecodeErrorKind::RecursionLimit));
        }
        self.depth += 1;
        let r = loop {
            if self.buf.is_empty() {
                break Err(err(DecodeErrorKind::UnbalancedGroup));
            }
            let (f, wt) = match self.read_tag() {
                Ok(t) => t,
                Err(e) => break Err(e),
            };
            if wt == WireType::EndGroup {
                break if f == field {
                    Ok(())
                } else {
                    Err(err(DecodeErrorKind::UnbalancedGroup))
                };
            }
            if let Err(e) = self.skip_field(f, wt) {
                break Err(e);
            }
        };
        self.depth -= 1;
        r
    }
}

// ---- codecs ----------------------------------------------------------------------------------

/// How one protobuf type is encoded (value only: the tag is the field functions' job).
pub trait Codec {
    /// The Rust type holding the value.
    type Value;
    /// The wire type of a single value.
    const WIRE_TYPE: WireType;
    /// Appends the encoded value.
    fn encode(v: &Self::Value, buf: &mut Vec<u8>);
    /// The length of the encoded value.
    fn len(v: &Self::Value) -> usize;
    /// Reads a value (its tag already read and checked) into `v`: replaces a scalar, merges a
    /// message.
    fn merge(v: &mut Self::Value, r: &mut Reader<'_>) -> Result<(), DecodeError>;
    /// Whether `v` is the type's default (skipped under implicit presence).
    fn is_default(v: &Self::Value) -> bool;
}

macro_rules! varint_codec {
    ($(#[$doc:meta] $name:ident: $t:ty, |$e:ident| $enc:expr, |$d:ident| $dec:expr;)*) => {$(
        #[$doc]
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl Codec for $name {
            type Value = $t;
            const WIRE_TYPE: WireType = WireType::Varint;
            #[inline]
            fn encode(v: &$t, buf: &mut Vec<u8>) {
                let $e = *v;
                put_varint(buf, $enc);
            }
            #[inline]
            fn len(v: &$t) -> usize {
                let $e = *v;
                varint_len($enc)
            }
            #[inline]
            fn merge(v: &mut $t, r: &mut Reader<'_>) -> Result<(), DecodeError> {
                let $d = r.read_varint()?;
                *v = $dec;
                Ok(())
            }
            #[inline]
            fn is_default(v: &$t) -> bool {
                *v == <$t>::default()
            }
        }
    )*};
}

varint_codec! {
    /// `int32` (negative values take 10 bytes, sign-extended).
    Int32: i32, |v| i64::from(v) as u64, |d| d as i32;
    /// `int64`.
    Int64: i64, |v| v as u64, |d| d as i64;
    /// `uint32`.
    Uint32: u32, |v| u64::from(v), |d| d as u32;
    /// `uint64`.
    Uint64: u64, |v| v, |d| d;
    /// `sint32` (ZigZag).
    Sint32: i32, |v| u64::from(zigzag32(v)), |d| unzigzag32(d as u32);
    /// `sint64` (ZigZag).
    Sint64: i64, |v| zigzag64(v), |d| unzigzag64(d);
    /// `bool`.
    Bool: bool, |v| u64::from(v), |d| d != 0;
}

macro_rules! fixed_codec {
    ($(#[$doc:meta] $name:ident: $t:ty, $wt:ident, $read:ident, $n:literal;)*) => {$(
        #[$doc]
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl Codec for $name {
            type Value = $t;
            const WIRE_TYPE: WireType = WireType::$wt;
            #[inline]
            fn encode(v: &$t, buf: &mut Vec<u8>) {
                buf.extend_from_slice(&v.to_le_bytes());
            }
            #[inline]
            fn len(_v: &$t) -> usize {
                $n
            }
            #[inline]
            fn merge(v: &mut $t, r: &mut Reader<'_>) -> Result<(), DecodeError> {
                *v = <$t>::from_le_bytes(r.$read()?.to_le_bytes());
                Ok(())
            }
            #[inline]
            #[allow(clippy::float_cmp)]
            fn is_default(v: &$t) -> bool {
                // Bitwise for floats: -0.0 is not the default and is encoded (as in C++ and Go).
                v.to_le_bytes() == <$t>::default().to_le_bytes()
            }
        }
    )*};
}

fixed_codec! {
    /// `fixed32`.
    Fixed32: u32, Fixed32, read_fixed32, 4;
    /// `fixed64`.
    Fixed64: u64, Fixed64, read_fixed64, 8;
    /// `sfixed32`.
    Sfixed32: i32, Fixed32, read_fixed32, 4;
    /// `sfixed64`.
    Sfixed64: i64, Fixed64, read_fixed64, 8;
    /// `float`.
    Float: f32, Fixed32, read_fixed32, 4;
    /// `double`.
    Double: f64, Fixed64, read_fixed64, 8;
}

/// `string` (UTF-8 is checked when decoding).
#[derive(Clone, Copy, Debug)]
pub struct StringCodec;

impl Codec for StringCodec {
    type Value = String;
    const WIRE_TYPE: WireType = WireType::Len;
    #[inline]
    fn encode(v: &String, buf: &mut Vec<u8>) {
        put_bytes(buf, v.as_bytes());
    }
    #[inline]
    fn len(v: &String) -> usize {
        varint_len(v.len() as u64) + v.len()
    }
    #[inline]
    fn merge(v: &mut String, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        let b = r.read_bytes()?;
        let s = std::str::from_utf8(b).map_err(|_| err(DecodeErrorKind::InvalidUtf8))?;
        v.clear();
        v.push_str(s);
        Ok(())
    }
    #[inline]
    fn is_default(v: &String) -> bool {
        v.is_empty()
    }
}

/// `string` with `features.utf8_validation = NONE`: a [`ProtoString`](crate::ProtoString),
/// decoded without a UTF-8 check.
#[derive(Clone, Copy, Debug)]
pub struct ProtoStringCodec;

impl Codec for ProtoStringCodec {
    type Value = crate::ProtoString;
    const WIRE_TYPE: WireType = WireType::Len;
    #[inline]
    fn encode(v: &crate::ProtoString, buf: &mut Vec<u8>) {
        put_bytes(buf, v.as_bytes());
    }
    #[inline]
    fn len(v: &crate::ProtoString) -> usize {
        varint_len(v.len() as u64) + v.len()
    }
    #[inline]
    fn merge(v: &mut crate::ProtoString, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        let b = r.read_bytes()?;
        let v = v.as_mut_vec();
        v.clear();
        v.extend_from_slice(b);
        Ok(())
    }
    #[inline]
    fn is_default(v: &crate::ProtoString) -> bool {
        v.is_empty()
    }
}

/// `bytes`.
#[derive(Clone, Copy, Debug)]
pub struct BytesCodec;

impl Codec for BytesCodec {
    type Value = Vec<u8>;
    const WIRE_TYPE: WireType = WireType::Len;
    #[inline]
    fn encode(v: &Vec<u8>, buf: &mut Vec<u8>) {
        put_bytes(buf, v);
    }
    #[inline]
    fn len(v: &Vec<u8>) -> usize {
        varint_len(v.len() as u64) + v.len()
    }
    #[inline]
    fn merge(v: &mut Vec<u8>, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        let b = r.read_bytes()?;
        v.clear();
        v.extend_from_slice(b);
        Ok(())
    }
    #[inline]
    fn is_default(v: &Vec<u8>) -> bool {
        v.is_empty()
    }
}

/// An embedded message (length-delimited; decoding merges into the existing value).
#[derive(Debug)]
pub struct MessageCodec<M>(PhantomData<M>);

impl<M: Message> Codec for MessageCodec<M> {
    type Value = M;
    const WIRE_TYPE: WireType = WireType::Len;
    #[inline]
    fn encode(v: &M, buf: &mut Vec<u8>) {
        put_varint(buf, v.encoded_len() as u64);
        v.encode_raw(buf);
    }
    #[inline]
    fn len(v: &M) -> usize {
        let n = v.encoded_len();
        varint_len(n as u64) + n
    }
    #[inline]
    fn merge(v: &mut M, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        let mut sub = r.nested()?;
        v.merge_from(&mut sub)
    }
    #[inline]
    fn is_default(_v: &M) -> bool {
        false
    }
}

/// A message encoded as a group (proto2 `group`, or `features.message_encoding = DELIMITED`):
/// the fields between a start-group and an end-group tag of field `N`, no length prefix.
#[derive(Debug)]
pub struct GroupCodec<M, const N: u32>(PhantomData<M>);

impl<M: Message, const N: u32> Codec for GroupCodec<M, N> {
    type Value = M;
    const WIRE_TYPE: WireType = WireType::StartGroup;
    #[inline]
    fn encode(v: &M, buf: &mut Vec<u8>) {
        v.encode_raw(buf);
        put_tag(buf, N, WireType::EndGroup);
    }
    #[inline]
    fn len(v: &M) -> usize {
        v.encoded_len() + tag_len(N)
    }
    #[inline]
    fn merge(v: &mut M, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        r.merge_group(N, v)
    }
    #[inline]
    fn is_default(_v: &M) -> bool {
        false
    }
}

/// An enum (open: unknown numbers are kept).
#[derive(Debug)]
pub struct EnumCodec<E>(PhantomData<E>);

impl<E: Enumeration> Codec for EnumCodec<E> {
    type Value = E;
    const WIRE_TYPE: WireType = WireType::Varint;
    #[inline]
    fn encode(v: &E, buf: &mut Vec<u8>) {
        put_varint(buf, i64::from(v.value()) as u64);
    }
    #[inline]
    fn len(v: &E) -> usize {
        varint_len(i64::from(v.value()) as u64)
    }
    #[inline]
    fn merge(v: &mut E, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        *v = E::from_i32(r.read_varint()? as i32);
        Ok(())
    }
    #[inline]
    fn is_default(v: &E) -> bool {
        v.value() == 0
    }
}

// ---- field encoders --------------------------------------------------------------------------

/// Encodes a field with implicit presence: nothing when `v` is the default.
#[inline]
pub fn encode_implicit<C: Codec>(field: u32, v: &C::Value, buf: &mut Vec<u8>) {
    if !C::is_default(v) {
        put_tag(buf, field, C::WIRE_TYPE);
        C::encode(v, buf);
    }
}

/// Length of [`encode_implicit`].
#[inline]
pub fn implicit_len<C: Codec>(field: u32, v: &C::Value) -> usize {
    if C::is_default(v) {
        0
    } else {
        tag_len(field) + C::len(v)
    }
}

/// Encodes a field that is always written (proto2 `required`, a set oneof member).
#[inline]
pub fn encode_required<C: Codec>(field: u32, v: &C::Value, buf: &mut Vec<u8>) {
    put_tag(buf, field, C::WIRE_TYPE);
    C::encode(v, buf);
}

/// Length of [`encode_required`].
#[inline]
pub fn required_len<C: Codec>(field: u32, v: &C::Value) -> usize {
    tag_len(field) + C::len(v)
}

/// Encodes a field with explicit presence: written when `Some`, even if default.
#[inline]
pub fn encode_optional<C: Codec>(field: u32, v: Option<&C::Value>, buf: &mut Vec<u8>) {
    if let Some(v) = v {
        encode_required::<C>(field, v, buf);
    }
}

/// Length of [`encode_optional`].
#[inline]
pub fn optional_len<C: Codec>(field: u32, v: Option<&C::Value>) -> usize {
    v.map_or(0, |v| required_len::<C>(field, v))
}

/// Encodes an unpacked repeated field: one tag per element.
#[inline]
pub fn encode_repeated<C: Codec>(field: u32, v: &[C::Value], buf: &mut Vec<u8>) {
    for x in v {
        encode_required::<C>(field, x, buf);
    }
}

/// Length of [`encode_repeated`].
#[inline]
pub fn repeated_len<C: Codec>(field: u32, v: &[C::Value]) -> usize {
    tag_len(field) * v.len() + v.iter().map(C::len).sum::<usize>()
}

/// Encodes a packed repeated scalar field: one length-delimited record (nothing when empty).
#[inline]
pub fn encode_packed<C: Codec>(field: u32, v: &[C::Value], buf: &mut Vec<u8>) {
    if v.is_empty() {
        return;
    }
    put_tag(buf, field, WireType::Len);
    put_varint(buf, packed_payload_len::<C>(v) as u64);
    for x in v {
        C::encode(x, buf);
    }
}

#[inline]
fn packed_payload_len<C: Codec>(v: &[C::Value]) -> usize {
    match C::WIRE_TYPE {
        WireType::Fixed32 => 4 * v.len(),
        WireType::Fixed64 => 8 * v.len(),
        _ => v.iter().map(C::len).sum(),
    }
}

/// Length of [`encode_packed`].
#[inline]
pub fn packed_len<C: Codec>(field: u32, v: &[C::Value]) -> usize {
    if v.is_empty() {
        return 0;
    }
    let n = packed_payload_len::<C>(v);
    tag_len(field) + varint_len(n as u64) + n
}

#[inline]
fn entry_len<K: Codec, V: Codec>(k: &K::Value, v: &V::Value) -> usize {
    tag_len(1) + K::len(k) + tag_len(2) + V::len(v)
}

/// Encodes a map field: one entry message (key = 1, value = 2, both always written) per pair.
#[inline]
pub fn encode_map<'a, K, V>(
    field: u32,
    entries: impl IntoIterator<Item = (&'a K::Value, &'a V::Value)>,
    buf: &mut Vec<u8>,
) where
    K: Codec,
    V: Codec,
    K::Value: 'a,
    V::Value: 'a,
{
    for (k, v) in entries {
        put_tag(buf, field, WireType::Len);
        put_varint(buf, entry_len::<K, V>(k, v) as u64);
        put_tag(buf, 1, K::WIRE_TYPE);
        K::encode(k, buf);
        put_tag(buf, 2, V::WIRE_TYPE);
        V::encode(v, buf);
    }
}

/// Length of [`encode_map`].
#[inline]
pub fn map_len<'a, K, V>(
    field: u32,
    entries: impl IntoIterator<Item = (&'a K::Value, &'a V::Value)>,
) -> usize
where
    K: Codec,
    V: Codec,
    K::Value: 'a,
    V::Value: 'a,
{
    entries
        .into_iter()
        .map(|(k, v)| {
            let n = entry_len::<K, V>(k, v);
            tag_len(field) + varint_len(n as u64) + n
        })
        .sum()
}

// ---- field decoders --------------------------------------------------------------------------

/// Whether a singular field of codec `C` may arrive with `wire_type`. Generated code keeps a
/// field with another wire type as an unknown field, as the C++ and Go runtimes do.
#[inline]
pub fn accepts<C: Codec>(wire_type: WireType) -> bool {
    wire_type == C::WIRE_TYPE
}

/// Whether a repeated field of codec `C` may arrive with `wire_type`: its own, or
/// length-delimited (packed) for scalars.
#[inline]
pub fn accepts_repeated<C: Codec>(wire_type: WireType) -> bool {
    wire_type == C::WIRE_TYPE || (wire_type == WireType::Len && packable(C::WIRE_TYPE))
}

/// Whether values of this wire type can be packed (varints and fixed-width values).
#[inline]
const fn packable(wt: WireType) -> bool {
    matches!(wt, WireType::Varint | WireType::Fixed32 | WireType::Fixed64)
}

/// Fails unless `wire_type` is the codec's.
#[inline]
pub fn check_wire_type<C: Codec>(field: u32, wire_type: WireType) -> Result<(), DecodeError> {
    if wire_type == C::WIRE_TYPE {
        Ok(())
    } else {
        Err(err(DecodeErrorKind::WireTypeMismatch).in_field(field))
    }
}

/// Decodes a singular value into `v` (replacing a scalar, merging a message).
#[inline]
pub fn merge_value<C: Codec>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    v: &mut C::Value,
) -> Result<(), DecodeError> {
    check_wire_type::<C>(field, wire_type)?;
    C::merge(v, r).map_err(|e| e.in_field(field))
}

/// Decodes a field with explicit presence (sets it, merging into a present message).
#[inline]
pub fn merge_optional<C: Codec>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    v: &mut Option<C::Value>,
) -> Result<(), DecodeError>
where
    C::Value: Default,
{
    merge_value::<C>(field, wire_type, r, v.get_or_insert_with(Default::default))
}

/// [`merge_optional`] for a boxed (recursive) message field.
#[inline]
pub fn merge_boxed<C: Codec>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    v: &mut Option<Box<C::Value>>,
) -> Result<(), DecodeError>
where
    C::Value: Default,
{
    merge_value::<C>(field, wire_type, r, v.get_or_insert_with(Default::default))
}

/// Decodes one occurrence of a repeated field: an element, or (for scalars) a packed run.
#[inline]
pub fn merge_repeated<C: Codec>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    v: &mut Vec<C::Value>,
) -> Result<(), DecodeError>
where
    C::Value: Default,
{
    if wire_type == WireType::Len && packable(C::WIRE_TYPE) {
        let b = r.read_bytes().map_err(|e| e.in_field(field))?;
        match C::WIRE_TYPE {
            WireType::Fixed32 => v.reserve(b.len() / 4),
            WireType::Fixed64 => v.reserve(b.len() / 8),
            _ => {}
        }
        let mut sub = Reader::new(b);
        while !sub.is_empty() {
            let mut x = C::Value::default();
            C::merge(&mut x, &mut sub).map_err(|e| e.in_field(field))?;
            v.push(x);
        }
        return Ok(());
    }
    check_wire_type::<C>(field, wire_type)?;
    let mut x = C::Value::default();
    C::merge(&mut x, r).map_err(|e| e.in_field(field))?;
    v.push(x);
    Ok(())
}

/// Decodes one map entry and inserts it (a later duplicate key wins; a missing key or value is
/// the default).
#[inline]
pub fn merge_map<K, V>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    map: &mut impl Extend<(K::Value, V::Value)>,
) -> Result<(), DecodeError>
where
    K: Codec,
    V: Codec,
    K::Value: Default,
    V::Value: Default,
{
    if wire_type != WireType::Len {
        return Err(err(DecodeErrorKind::WireTypeMismatch).in_field(field));
    }
    let mut sub = r.nested().map_err(|e| e.in_field(field))?;
    let mut k = K::Value::default();
    let mut v = V::Value::default();
    let res: Result<(), DecodeError> = (|| {
        while !sub.is_empty() {
            let (f, wt) = sub.read_tag()?;
            match f {
                1 => merge_value::<K>(1, wt, &mut sub, &mut k)?,
                2 => merge_value::<V>(2, wt, &mut sub, &mut v)?,
                _ => {
                    sub.skip_field(f, wt)?;
                }
            }
        }
        Ok(())
    })();
    res.map_err(|e| e.in_field(field))?;
    map.extend(std::iter::once((k, v)));
    Ok(())
}

// ---- closed enums ----------------------------------------------------------------------------

/// Reads one value of a closed enum field (proto2 enums, `features.enum_type = CLOSED`): the
/// value when it is a known one, otherwise `None` after keeping the number in `unknown` as an
/// unknown field (the specification's behaviour for closed enums).
#[inline]
pub fn read_closed_enum<E: Enumeration>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    unknown: &mut UnknownFields,
) -> Result<Option<E>, DecodeError> {
    check_wire_type::<EnumCodec<E>>(field, wire_type)?;
    let n = r.read_varint().map_err(|e| e.in_field(field))?;
    let v = E::from_i32(n as i32);
    if v.is_known() {
        Ok(Some(v))
    } else {
        // As C++: the number as an int32, sign-extended.
        unknown.push_varint(field, i64::from(n as i32) as u64);
        Ok(None)
    }
}

/// [`merge_repeated`] for a closed enum: unknown numbers (packed or not) go to `unknown`, one
/// unpacked varint each.
pub fn merge_closed_enum_repeated<E: Enumeration>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    v: &mut Vec<E>,
    unknown: &mut UnknownFields,
) -> Result<(), DecodeError> {
    if wire_type == WireType::Len {
        let b = r.read_bytes().map_err(|e| e.in_field(field))?;
        let mut sub = Reader::new(b);
        while !sub.is_empty() {
            let n = sub.read_varint().map_err(|e| e.in_field(field))?;
            let e = E::from_i32(n as i32);
            if e.is_known() {
                v.push(e);
            } else {
                // As C++: the number as an int32, sign-extended.
                unknown.push_varint(field, i64::from(n as i32) as u64);
            }
        }
        return Ok(());
    }
    if let Some(e) = read_closed_enum::<E>(field, wire_type, r, unknown)? {
        v.push(e);
    }
    Ok(())
}

/// [`merge_map`] for a map whose values are a closed enum: an entry with an unknown value goes
/// to `unknown` whole.
pub fn merge_closed_enum_map<K, E>(
    field: u32,
    wire_type: WireType,
    r: &mut Reader<'_>,
    map: &mut impl Extend<(K::Value, E)>,
    unknown: &mut UnknownFields,
) -> Result<(), DecodeError>
where
    K: Codec,
    K::Value: Default,
    E: Enumeration,
{
    if wire_type != WireType::Len {
        return Err(err(DecodeErrorKind::WireTypeMismatch).in_field(field));
    }
    if r.depth >= RECURSION_LIMIT {
        return Err(err(DecodeErrorKind::RecursionLimit).in_field(field));
    }
    let raw = r.read_bytes().map_err(|e| e.in_field(field))?;
    let mut sub = Reader {
        buf: raw,
        depth: r.depth + 1,
    };
    let mut k = K::Value::default();
    let mut n = 0u64;
    let res: Result<(), DecodeError> = (|| {
        while !sub.is_empty() {
            let (f, wt) = sub.read_tag()?;
            match f {
                1 => merge_value::<K>(1, wt, &mut sub, &mut k)?,
                2 => {
                    check_wire_type::<EnumCodec<E>>(2, wt)?;
                    n = sub.read_varint()?;
                }
                _ => {
                    sub.skip_field(f, wt)?;
                }
            }
        }
        Ok(())
    })();
    res.map_err(|e| e.in_field(field))?;
    let e = E::from_i32(n as i32);
    if e.is_known() {
        map.extend(std::iter::once((k, e)));
    } else {
        unknown.push_raw(field, WireType::Len, raw);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for (v, enc) in [
            (0u64, &[0u8][..]),
            (1, &[1]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
            (
                u64::MAX,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            ),
        ] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(b, enc);
            assert_eq!(varint_len(v), enc.len());
            assert_eq!(Reader::new(enc).read_varint().unwrap(), v);
        }
        for n in 0..64 {
            let v = 1u64 << n;
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(varint_len(v), b.len(), "{v}");
        }
        let e = |b: &[u8]| Reader::new(b).read_varint().unwrap_err().kind();
        assert_eq!(e(&[0x80]), DecodeErrorKind::Truncated);
        assert_eq!(e(&[]), DecodeErrorKind::Truncated);
        assert_eq!(e(&[0xff; 10]), DecodeErrorKind::VarintOverflow);
        assert_eq!(
            e(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]),
            DecodeErrorKind::VarintOverflow
        );
        // Non-minimal encodings are accepted.
        assert_eq!(Reader::new(&[0x81, 0x80, 0x00]).read_varint().unwrap(), 1);
    }

    #[test]
    fn zigzag() {
        for (v, z) in [
            (0, 0),
            (-1, 1),
            (1, 2),
            (-2, 3),
            (i32::MAX, u32::MAX - 1),
            (i32::MIN, u32::MAX),
        ] {
            assert_eq!(zigzag32(v), z);
            assert_eq!(unzigzag32(z), v);
        }
        for v in [0i64, -1, 1, i64::MAX, i64::MIN, 123_456_789_012] {
            assert_eq!(unzigzag64(zigzag64(v)), v);
        }
        assert_eq!(zigzag64(i64::MIN), u64::MAX);
    }

    #[test]
    fn tags_and_skipping() {
        let e = |b: &[u8]| Reader::new(b).read_tag().unwrap_err().kind();
        assert_eq!(e(&[0x00]), DecodeErrorKind::InvalidTag); // field 0
        assert_eq!(e(&[0x0e]), DecodeErrorKind::InvalidTag); // wire type 6
        let mut r = Reader::new(&[0xf8, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(r.read_tag().unwrap(), (MAX_FIELD_NUMBER, WireType::Varint));
        assert_eq!(
            Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x10])
                .read_tag()
                .unwrap_err()
                .kind(),
            DecodeErrorKind::InvalidTag
        );
        // A group with a nested group and a varint inside: 1 { 2 { 3: 1 } }.
        let g = [0x0b, 0x13, 0x18, 0x01, 0x14, 0x0c, 0xff];
        let mut r = Reader::new(&g);
        let (f, wt) = r.read_tag().unwrap();
        assert_eq!((f, wt), (1, WireType::StartGroup));
        assert_eq!(r.skip_field(f, wt).unwrap(), &g[1..6]);
        assert_eq!(r.remaining(), &[0xff]);
        let mut r = Reader::new(&[0x0b, 0x14]);
        let (f, wt) = r.read_tag().unwrap();
        assert_eq!(
            r.skip_field(f, wt).unwrap_err().kind(),
            DecodeErrorKind::UnbalancedGroup
        );
        let mut r = Reader::new(&[0x0b]);
        let (f, wt) = r.read_tag().unwrap();
        assert_eq!(
            r.skip_field(f, wt).unwrap_err().kind(),
            DecodeErrorKind::UnbalancedGroup
        );
        // Deeply nested groups hit the recursion limit instead of the stack.
        let mut deep = vec![0x0b; 10_000];
        deep.extend(vec![0x0c; 10_000]);
        let mut r = Reader::new(&deep);
        let (f, wt) = r.read_tag().unwrap();
        assert_eq!(
            r.skip_field(f, wt).unwrap_err().kind(),
            DecodeErrorKind::RecursionLimit
        );
        // Truncated length-delimited value.
        assert_eq!(
            Reader::new(&[0x05, 1, 2]).read_bytes().unwrap_err().kind(),
            DecodeErrorKind::Truncated
        );
        assert_eq!(
            Reader::new(&[1, 2, 3]).read_fixed32().unwrap_err().kind(),
            DecodeErrorKind::Truncated
        );
    }

    #[test]
    fn scalars_and_packing() {
        let mut b = Vec::new();
        encode_implicit::<Int32>(1, &-1, &mut b);
        assert_eq!(b.len(), 11);
        assert_eq!(implicit_len::<Int32>(1, &-1), 11);
        b.clear();
        encode_implicit::<Sint32>(1, &-1, &mut b);
        assert_eq!(b, [0x08, 0x01]);
        b.clear();
        encode_implicit::<Double>(1, &0.0, &mut b);
        assert!(b.is_empty());
        encode_implicit::<Double>(1, &-0.0, &mut b);
        assert_eq!(b.len(), 9, "-0.0 is not the default");
        b.clear();
        encode_packed::<Int32>(4, &[3, 270, 86942], &mut b);
        assert_eq!(b, [0x22, 0x06, 0x03, 0x8e, 0x02, 0x9e, 0xa7, 0x05]);
        assert_eq!(packed_len::<Int32>(4, &[3, 270, 86942]), b.len());
        // Packed and unpacked decode to the same thing, and may be mixed.
        let mut unpacked = Vec::new();
        encode_repeated::<Int32>(4, &[3, 270], &mut unpacked);
        assert_eq!(repeated_len::<Int32>(4, &[3, 270]), unpacked.len());
        unpacked.extend_from_slice(&b);
        let mut r = Reader::new(&unpacked);
        let mut v = Vec::new();
        while !r.is_empty() {
            let (f, wt) = r.read_tag().unwrap();
            merge_repeated::<Int32>(f, wt, &mut r, &mut v).unwrap();
        }
        assert_eq!(v, [3, 270, 3, 270, 86942]);
        // Wrong wire type.
        let mut r = Reader::new(&[0x0d, 0, 0, 0, 0]);
        let (f, wt) = r.read_tag().unwrap();
        let e = merge_value::<Int32>(f, wt, &mut r, &mut 0).unwrap_err();
        assert_eq!(
            (e.kind(), e.field()),
            (DecodeErrorKind::WireTypeMismatch, Some(1))
        );
        // Invalid UTF-8.
        let mut r = Reader::new(&[0x0a, 0x01, 0xff]);
        let (f, wt) = r.read_tag().unwrap();
        let mut s = String::new();
        assert_eq!(
            merge_value::<StringCodec>(f, wt, &mut r, &mut s)
                .unwrap_err()
                .kind(),
            DecodeErrorKind::InvalidUtf8
        );
    }

    #[test]
    fn maps() {
        let mut m = std::collections::BTreeMap::new();
        m.insert("a".to_string(), 1i32);
        m.insert(String::new(), 0);
        let mut b = Vec::new();
        encode_map::<StringCodec, Int32>(3, &m, &mut b);
        assert_eq!(map_len::<StringCodec, Int32>(3, &m), b.len());
        assert_eq!(&b[..6], &[0x1a, 0x04, 0x0a, 0x00, 0x10, 0x00]);
        let mut back = std::collections::BTreeMap::new();
        let mut r = Reader::new(&b);
        while !r.is_empty() {
            let (f, wt) = r.read_tag().unwrap();
            merge_map::<StringCodec, Int32>(f, wt, &mut r, &mut back).unwrap();
        }
        assert_eq!(back, m);
        // Missing key and value, unknown entry fields, reversed order.
        let mut back = std::collections::BTreeMap::new();
        for e in [
            &[0x1a, 0x00][..],
            &[0x1a, 0x06, 0x10, 0x07, 0x0a, 0x01, b'k', 0x18],
        ] {
            let mut r = Reader::new(e);
            let (f, wt) = r.read_tag().unwrap();
            let res = merge_map::<StringCodec, Int32>(f, wt, &mut r, &mut back);
            if e.len() == 2 {
                res.unwrap();
            } else {
                assert_eq!(res.unwrap_err().kind(), DecodeErrorKind::Truncated);
            }
        }
        assert_eq!(back.get(""), Some(&0));
    }
}
