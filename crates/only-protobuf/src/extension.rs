//! proto2 extensions: [`ExtensionSet`] keeps the extension fields of a message (in their
//! encoded form, so nothing is lost when an extension is not known), [`Extension`] and
//! [`RepeatedExtension`] name one extension and its type, [`Extendable`] reads and writes them.
//!
//! ```
//! use only_protobuf::{Extendable, Extension, ExtensionSet, Message, encoding::{self, Int32, Reader, WireType}};
//! use only_protobuf::DecodeError;
//!
//! // `message Base { extensions 100 to 199; }`, written by hand.
//! #[derive(Debug, Default, PartialEq)]
//! struct Base {
//!     extensions: ExtensionSet,
//! }
//! impl Message for Base {
//!     fn encode_raw(&self, buf: &mut Vec<u8>) {
//!         self.extensions.encode(buf);
//!     }
//!     fn encoded_len(&self) -> usize {
//!         self.extensions.encoded_len()
//!     }
//!     fn merge_field(&mut self, field: u32, wt: WireType, r: &mut Reader<'_>) -> Result<(), DecodeError> {
//!         match field {
//!             100..=199 => self.extensions.merge_field(field, wt, r),
//!             _ => r.skip_field(field, wt).map(drop),
//!         }
//!     }
//! }
//! impl Extendable for Base {
//!     fn extension_set(&self) -> &ExtensionSet { &self.extensions }
//!     fn extension_set_mut(&mut self) -> &mut ExtensionSet { &mut self.extensions }
//! }
//!
//! // `extend Base { optional int32 weight = 100; }`
//! const WEIGHT: Extension<Base, Int32> = Extension::new(100, "pkg.weight");
//!
//! let mut b = Base::default();
//! b.set_extension(&WEIGHT, &7);
//! let back = Base::decode(&b.encode_to_vec()).unwrap();
//! assert_eq!(back.extension(&WEIGHT).unwrap(), Some(7));
//! ```

use std::{collections::BTreeMap, fmt, marker::PhantomData};

use crate::{
    DecodeError, Message,
    encoding::{self, Codec, Reader, WireType},
};

/// The extension fields of a message, by field number, each kept as it was read (tags
/// included) and written back in field-number order.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct ExtensionSet {
    fields: BTreeMap<u32, Vec<u8>>,
}

impl ExtensionSet {
    /// None.
    pub const fn new() -> ExtensionSet {
        ExtensionSet {
            fields: BTreeMap::new(),
        }
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Drops them all.
    pub fn clear(&mut self) {
        self.fields.clear();
    }

    /// Whether field `number` is present.
    pub fn contains(&self, number: u32) -> bool {
        self.fields.contains_key(&number)
    }

    /// Drops field `number`.
    pub fn remove(&mut self, number: u32) {
        self.fields.remove(&number);
    }

    /// The field numbers present, ascending.
    pub fn numbers(&self) -> impl Iterator<Item = u32> + '_ {
        self.fields.keys().copied()
    }

    /// The encoded records (tags included) of field `number`, in the order they were read.
    pub fn raw(&self, number: u32) -> Option<&[u8]> {
        self.fields.get(&number).map(Vec::as_slice)
    }

    /// Reads the value of an extension field whose tag was just read and keeps it.
    pub fn merge_field(
        &mut self,
        field: u32,
        wire_type: WireType,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        let raw = r
            .skip_field(field, wire_type)
            .map_err(|e| e.in_field(field))?;
        let rec = self.fields.entry(field).or_default();
        encoding::put_tag(rec, field, wire_type);
        rec.extend_from_slice(raw);
        Ok(())
    }

    /// Appends every field.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        for v in self.fields.values() {
            buf.extend_from_slice(v);
        }
    }

    /// The length of [`encode`](Self::encode)'s output.
    pub fn encoded_len(&self) -> usize {
        self.fields.values().map(Vec::len).sum()
    }

    /// Appends the fields numbered `start ..= end` (generated code interleaves extension ranges
    /// with the declared fields, in field-number order, as protoc does).
    pub fn encode_range(&self, start: u32, end: u32, buf: &mut Vec<u8>) {
        for v in self.fields.range(start..=end).map(|(_, v)| v) {
            buf.extend_from_slice(v);
        }
    }

    /// The length of [`encode_range`](Self::encode_range)'s output.
    pub fn range_len(&self, start: u32, end: u32) -> usize {
        self.fields.range(start..=end).map(|(_, v)| v.len()).sum()
    }

    /// Replaces field `number` with already encoded records (tags included).
    pub fn set_raw(&mut self, number: u32, records: Vec<u8>) {
        if records.is_empty() {
            self.fields.remove(&number);
        } else {
            self.fields.insert(number, records);
        }
    }

    /// Decodes a singular field with codec `C`: every occurrence merged (the last scalar wins,
    /// messages merge), `None` when absent.
    pub fn get<C: Codec>(&self, number: u32) -> Result<Option<C::Value>, DecodeError>
    where
        C::Value: Default,
    {
        let Some(raw) = self.fields.get(&number) else {
            return Ok(None);
        };
        let mut v = C::Value::default();
        let mut r = Reader::new(raw);
        while !r.is_empty() {
            let (f, wt) = r.read_tag()?;
            if f == number && encoding::accepts::<C>(wt) {
                encoding::merge_value::<C>(f, wt, &mut r, &mut v)?;
            } else {
                r.skip_field(f, wt)?;
            }
        }
        Ok(Some(v))
    }

    /// Decodes a repeated field with codec `C` (packed and unpacked occurrences alike).
    pub fn get_repeated<C: Codec>(&self, number: u32) -> Result<Vec<C::Value>, DecodeError>
    where
        C::Value: Default,
    {
        let mut out = Vec::new();
        let Some(raw) = self.fields.get(&number) else {
            return Ok(out);
        };
        let mut r = Reader::new(raw);
        while !r.is_empty() {
            let (f, wt) = r.read_tag()?;
            if f == number && encoding::accepts_repeated::<C>(wt) {
                encoding::merge_repeated::<C>(f, wt, &mut r, &mut out)?;
            } else {
                r.skip_field(f, wt)?;
            }
        }
        Ok(out)
    }

    /// Sets a singular field.
    pub fn set<C: Codec>(&mut self, number: u32, v: &C::Value) {
        let mut rec = Vec::with_capacity(encoding::required_len::<C>(number, v));
        encoding::encode_required::<C>(number, v, &mut rec);
        self.fields.insert(number, rec);
    }

    /// Sets a repeated field (removed when `v` is empty).
    pub fn set_repeated<C: Codec>(&mut self, number: u32, v: &[C::Value], packed: bool) {
        let mut rec = Vec::new();
        if packed {
            encoding::encode_packed::<C>(number, v, &mut rec);
        } else {
            encoding::encode_repeated::<C>(number, v, &mut rec);
        }
        self.set_raw(number, rec);
    }
}

impl fmt::Debug for ExtensionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        for (k, v) in &self.fields {
            m.entry(k, &format_args!("{} bytes", v.len()));
        }
        m.finish()
    }
}

/// A singular extension of message `M` whose values have codec `C` (`optional int32 x = 100;`
/// in an `extend M` block is `Extension<M, Int32>`).
pub struct Extension<M, C> {
    number: u32,
    full_name: &'static str,
    _p: PhantomData<fn() -> (M, C)>,
}

impl<M, C> Extension<M, C> {
    /// The extension with field number `number` and full name `full_name` (`pkg.name`, or
    /// `pkg.Scope.name` for one declared in a message).
    pub const fn new(number: u32, full_name: &'static str) -> Extension<M, C> {
        Extension {
            number,
            full_name,
            _p: PhantomData,
        }
    }

    /// The field number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The full name.
    pub const fn full_name(&self) -> &'static str {
        self.full_name
    }
}

impl<M, C> fmt::Debug for Extension<M, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extension({} = {})", self.full_name, self.number)
    }
}

/// A repeated extension of message `M` with codec `C`; `packed` says how
/// [`Extendable::set_repeated_extension`] encodes it (decoding accepts both).
pub struct RepeatedExtension<M, C> {
    number: u32,
    full_name: &'static str,
    packed: bool,
    _p: PhantomData<fn() -> (M, C)>,
}

impl<M, C> RepeatedExtension<M, C> {
    /// See [`Extension::new`].
    pub const fn new(number: u32, full_name: &'static str, packed: bool) -> RepeatedExtension<M, C> {
        RepeatedExtension {
            number,
            full_name,
            packed,
            _p: PhantomData,
        }
    }

    /// The field number.
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The full name.
    pub const fn full_name(&self) -> &'static str {
        self.full_name
    }

    /// Whether it is written packed.
    pub const fn packed(&self) -> bool {
        self.packed
    }
}

impl<M, C> fmt::Debug for RepeatedExtension<M, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepeatedExtension({} = {})", self.full_name, self.number)
    }
}

/// A message with extension ranges. Generated code implements it; the provided methods read and
/// write extensions through typed [`Extension`] constants.
pub trait Extendable: Message {
    /// The extension fields.
    fn extension_set(&self) -> &ExtensionSet;
    /// The extension fields, mutably.
    fn extension_set_mut(&mut self) -> &mut ExtensionSet;

    /// The value of `ext`, `None` when it is not set.
    fn extension<C: Codec>(&self, ext: &Extension<Self, C>) -> Result<Option<C::Value>, DecodeError>
    where
        C::Value: Default,
    {
        self.extension_set().get::<C>(ext.number)
    }

    /// Whether `ext` is set.
    fn has_extension<C>(&self, ext: &Extension<Self, C>) -> bool {
        self.extension_set().contains(ext.number)
    }

    /// Sets `ext` to `v`.
    fn set_extension<C: Codec>(&mut self, ext: &Extension<Self, C>, v: &C::Value) {
        self.extension_set_mut().set::<C>(ext.number, v);
    }

    /// Unsets `ext`.
    fn clear_extension<C>(&mut self, ext: &Extension<Self, C>) {
        self.extension_set_mut().remove(ext.number);
    }

    /// The values of the repeated `ext` (empty when unset).
    fn repeated_extension<C: Codec>(
        &self,
        ext: &RepeatedExtension<Self, C>,
    ) -> Result<Vec<C::Value>, DecodeError>
    where
        C::Value: Default,
    {
        self.extension_set().get_repeated::<C>(ext.number)
    }

    /// Replaces the values of the repeated `ext` (unset when `v` is empty).
    fn set_repeated_extension<C: Codec>(&mut self, ext: &RepeatedExtension<Self, C>, v: &[C::Value]) {
        self.extension_set_mut()
            .set_repeated::<C>(ext.number, v, ext.packed);
    }
}
