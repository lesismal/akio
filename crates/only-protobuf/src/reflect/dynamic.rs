//! [`DynamicMessage`]: a message of a type known only through its descriptor.

use std::{borrow::Cow, collections::BTreeMap, fmt};

use super::{Cardinality, FieldDescriptor, Kind, MessageDescriptor};
use crate::{
    DecodeError, DecodeErrorKind, UnknownFields,
    encoding::{self, Reader, WireType},
};

/// A field value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `bool`.
    Bool(bool),
    /// `int32`, `sint32`, `sfixed32`.
    I32(i32),
    /// `int64`, `sint64`, `sfixed64`.
    I64(i64),
    /// `uint32`, `fixed32`.
    U32(u32),
    /// `uint64`, `fixed64`.
    U64(u64),
    /// `float`.
    F32(f32),
    /// `double`.
    F64(f64),
    /// `string`.
    String(String),
    /// `bytes`.
    Bytes(Vec<u8>),
    /// An enum number (known or not).
    EnumNumber(i32),
    /// A message.
    Message(DynamicMessage),
    /// A repeated field's values.
    List(Vec<Value>),
    /// A map field's entries.
    Map(BTreeMap<MapKey, Value>),
}

/// A map key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MapKey {
    /// `bool`.
    Bool(bool),
    /// 32-bit signed keys.
    I32(i32),
    /// 64-bit signed keys.
    I64(i64),
    /// 32-bit unsigned keys.
    U32(u32),
    /// 64-bit unsigned keys.
    U64(u64),
    /// `string`.
    String(String),
}

impl MapKey {
    /// The key as a value.
    pub fn to_value(&self) -> Value {
        match self {
            MapKey::Bool(v) => Value::Bool(*v),
            MapKey::I32(v) => Value::I32(*v),
            MapKey::I64(v) => Value::I64(*v),
            MapKey::U32(v) => Value::U32(*v),
            MapKey::U64(v) => Value::U64(*v),
            MapKey::String(v) => Value::String(v.clone()),
        }
    }

    /// The key holding `v`, when `v` can be one.
    pub fn from_value(v: Value) -> Option<MapKey> {
        Some(match v {
            Value::Bool(v) => MapKey::Bool(v),
            Value::I32(v) => MapKey::I32(v),
            Value::I64(v) => MapKey::I64(v),
            Value::U32(v) => MapKey::U32(v),
            Value::U64(v) => MapKey::U64(v),
            Value::String(v) => MapKey::String(v),
            _ => return None,
        })
    }
}

/// The value of an unset field of this descriptor.
pub(super) fn default_value(fd: &FieldDescriptor) -> Value {
    if fd.is_map() {
        return Value::Map(BTreeMap::new());
    }
    if fd.cardinality() == Cardinality::Repeated {
        return Value::List(Vec::new());
    }
    let text = fd.default_value_text();
    if let Some(t) = text {
        if let Some(v) = parse_default(fd, t) {
            return v;
        }
    }
    match fd.kind() {
        Kind::Enum(_) => Value::EnumNumber(fd.enum_type().map_or(0, |e| e.default_number())),
        Kind::Message(_) => match fd.message_type() {
            Some(m) => Value::Message(DynamicMessage::new(m)),
            None => Value::Bool(false),
        },
        k => zero(k),
    }
}

fn zero(k: Kind) -> Value {
    match k {
        Kind::Double => Value::F64(0.0),
        Kind::Float => Value::F32(0.0),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Value::I32(0),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Value::I64(0),
        Kind::Uint32 | Kind::Fixed32 => Value::U32(0),
        Kind::Uint64 | Kind::Fixed64 => Value::U64(0),
        Kind::Bool => Value::Bool(false),
        Kind::String => Value::String(String::new()),
        Kind::Bytes => Value::Bytes(Vec::new()),
        Kind::Enum(_) => Value::EnumNumber(0),
        Kind::Message(_) => Value::Bool(false),
    }
}

fn parse_float(t: &str) -> Option<f64> {
    match t {
        "inf" => Some(f64::INFINITY),
        "-inf" => Some(f64::NEG_INFINITY),
        "nan" => Some(f64::NAN),
        _ => t.parse().ok(),
    }
}

fn parse_default(fd: &FieldDescriptor, t: &str) -> Option<Value> {
    Some(match fd.kind() {
        Kind::Double => Value::F64(parse_float(t)?),
        Kind::Float => Value::F32(parse_float(t)? as f32),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Value::I32(t.parse().ok()?),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Value::I64(t.parse().ok()?),
        Kind::Uint32 | Kind::Fixed32 => Value::U32(t.parse().ok()?),
        Kind::Uint64 | Kind::Fixed64 => Value::U64(t.parse().ok()?),
        Kind::Bool => Value::Bool(t == "true"),
        Kind::String => Value::String(t.to_owned()),
        Kind::Bytes => Value::Bytes(c_unescape(t)),
        Kind::Enum(_) => Value::EnumNumber(fd.enum_type()?.value_number(t)?),
        Kind::Message(_) => return None,
    })
}

/// Undoes protoc's `CEscape` (bytes defaults).
fn c_unescape(t: &str) -> Vec<u8> {
    let b = t.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        match b[i] {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'v' => out.push(11),
            b'x' => {
                let mut v = 0u8;
                let mut n = 0;
                while n < 2 && i + 1 < b.len() && b[i + 1].is_ascii_hexdigit() {
                    i += 1;
                    v = v.wrapping_mul(16) + (b[i] as char).to_digit(16).unwrap_or(0) as u8;
                    n += 1;
                }
                out.push(v);
            }
            c @ b'0'..=b'7' => {
                let mut v = u32::from(c - b'0');
                let mut n = 1;
                while n < 3 && i + 1 < b.len() && (b'0'..=b'7').contains(&b[i + 1]) {
                    i += 1;
                    v = v * 8 + u32::from(b[i] - b'0');
                    n += 1;
                }
                out.push(v as u8);
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// Why a value does not fit a field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetError(String);

impl fmt::Display for SetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SetError {}

/// A message of any type in a pool: present fields by number (extensions included), unknown
/// fields kept.
#[derive(Clone)]
pub struct DynamicMessage {
    desc: MessageDescriptor,
    fields: BTreeMap<u32, Value>,
    unknown: UnknownFields,
}

impl PartialEq for DynamicMessage {
    fn eq(&self, o: &DynamicMessage) -> bool {
        self.desc.full_name() == o.desc.full_name()
            && self.fields == o.fields
            && self.unknown == o.unknown
    }
}

impl fmt::Debug for DynamicMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.desc.full_name())?;
        let mut m = f.debug_map();
        for (n, v) in &self.fields {
            match self.field_descriptor(*n) {
                Some(fd) => m.entry(&format_args!("{}", fd.name()), v),
                None => m.entry(n, v),
            };
        }
        m.finish()
    }
}

impl DynamicMessage {
    /// An empty message of type `desc`.
    pub fn new(desc: MessageDescriptor) -> DynamicMessage {
        DynamicMessage {
            desc,
            fields: BTreeMap::new(),
            unknown: UnknownFields::new(),
        }
    }

    /// Decodes a message of type `desc`.
    pub fn decode(desc: MessageDescriptor, bytes: &[u8]) -> Result<DynamicMessage, DecodeError> {
        let mut m = DynamicMessage::new(desc);
        m.merge(bytes)?;
        Ok(m)
    }

    /// The type.
    pub fn descriptor(&self) -> &MessageDescriptor {
        &self.desc
    }

    /// Unknown fields (and extensions the pool does not know).
    pub fn unknown_fields(&self) -> &UnknownFields {
        &self.unknown
    }

    /// Drops the unknown fields (here and in nested messages).
    pub fn clear_unknown_fields(&mut self) {
        self.unknown.clear();
        for v in self.fields.values_mut() {
            clear_unknown(v);
        }
    }

    /// The field (or extension of this message) with number `n`.
    pub fn field_descriptor(&self, n: u32) -> Option<FieldDescriptor> {
        self.desc
            .get_field(n)
            .or_else(|| self.desc.pool().get_extension(&self.desc, n))
    }

    /// Whether the field is present (for repeated fields and maps: not empty; for implicit
    /// presence: not the default).
    pub fn has(&self, fd: &FieldDescriptor) -> bool {
        match self.fields.get(&fd.number()) {
            None => false,
            Some(Value::List(l)) => !l.is_empty(),
            Some(Value::Map(m)) => !m.is_empty(),
            Some(v) => fd.has_presence() || !is_zero(v),
        }
    }

    /// The field's value (its default when unset).
    pub fn get(&self, fd: &FieldDescriptor) -> Cow<'_, Value> {
        match self.fields.get(&fd.number()) {
            Some(v) => Cow::Borrowed(v),
            None => Cow::Owned(fd.default_value()),
        }
    }

    /// The value of the field named `name` (`None` when there is no such field).
    pub fn get_by_name(&self, name: &str) -> Option<Cow<'_, Value>> {
        let fd = self.desc.get_field_by_name(name)?;
        Some(match self.fields.get(&fd.number()) {
            Some(v) => Cow::Borrowed(v),
            None => Cow::Owned(fd.default_value()),
        })
    }

    /// A mutable reference to the field's value, inserted as its default when unset (a oneof's
    /// other members are cleared).
    pub fn get_mut(&mut self, fd: &FieldDescriptor) -> &mut Value {
        self.clear_oneof_siblings(fd);
        self.fields
            .entry(fd.number())
            .or_insert_with(|| fd.default_value())
    }

    /// Sets the field (a oneof's other members are cleared). Fails when `v` does not have the
    /// field's type.
    pub fn set(&mut self, fd: &FieldDescriptor, v: Value) -> Result<(), SetError> {
        if !value_fits(fd, &v) {
            return Err(SetError(format!(
                "{}: value does not have the field's type",
                fd.full_name()
            )));
        }
        self.clear_oneof_siblings(fd);
        if !fd.has_presence() && fd.cardinality() != Cardinality::Repeated && is_zero(&v) {
            self.fields.remove(&fd.number());
        } else {
            self.fields.insert(fd.number(), v);
        }
        Ok(())
    }

    /// Unsets the field.
    pub fn clear(&mut self, fd: &FieldDescriptor) {
        self.fields.remove(&fd.number());
    }

    /// The present fields (extensions included), by field number.
    pub fn fields(&self) -> impl Iterator<Item = (FieldDescriptor, &Value)> + '_ {
        self.fields
            .iter()
            .filter_map(|(n, v)| self.field_descriptor(*n).map(|fd| (fd, v)))
            .filter(|(fd, _)| self.has(fd))
    }

    fn clear_oneof_siblings(&mut self, fd: &FieldDescriptor) {
        for n in fd.oneof_siblings() {
            if n != fd.number() {
                self.fields.remove(&n);
            }
        }
    }

    /// Decodes `bytes` and merges them in.
    pub fn merge(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        self.merge_from(&mut Reader::new(bytes), None)
    }

    /// Merges fields until `r` is empty, or (for a group, `end` = its field number) up to the
    /// end-group tag.
    fn merge_from(&mut self, r: &mut Reader<'_>, end: Option<u32>) -> Result<(), DecodeError> {
        loop {
            if r.is_empty() {
                return match end {
                    None => Ok(()),
                    Some(_) => Err(DecodeError::new(DecodeErrorKind::UnbalancedGroup)),
                };
            }
            let (n, wt) = r.read_tag()?;
            if wt == WireType::EndGroup {
                return if end == Some(n) {
                    Ok(())
                } else {
                    Err(DecodeError::new(DecodeErrorKind::UnbalancedGroup).in_field(n))
                };
            }
            if self.desc.is_message_set() && n == 1 && wt == WireType::StartGroup {
                self.merge_message_set_item(r)?;
                continue;
            }
            match self.field_descriptor(n) {
                Some(fd) if accepts(&fd, wt) => self.merge_field(&fd, wt, r)?,
                // As the generated code: a map key or value with another wire type is an error.
                Some(_) if self.desc.is_map_entry() => {
                    return Err(DecodeError::new(DecodeErrorKind::WireTypeMismatch).in_field(n));
                }
                _ => self.unknown.merge_field(n, wt, r)?,
            }
        }
    }

    fn merge_message_set_item(&mut self, r: &mut Reader<'_>) -> Result<(), DecodeError> {
        let raw = r.skip_field(1, WireType::StartGroup)?;
        let mut item = Reader::new(raw);
        let mut id = None;
        let mut msg: Option<&[u8]> = None;
        loop {
            let (f, wt) = item.read_tag()?;
            match (f, wt) {
                (1, WireType::EndGroup) => break,
                (2, WireType::Varint) => id = Some(item.read_varint()?),
                (3, WireType::Len) => msg = Some(item.read_bytes()?),
                _ => {
                    item.skip_field(f, wt)?;
                }
            }
        }
        let fd = id
            .and_then(|i| u32::try_from(i).ok())
            .and_then(|i| self.desc.pool().get_extension(&self.desc, i));
        match (fd, msg) {
            (Some(fd), Some(m)) if fd.message_type().is_some() => {
                let Value::Message(sub) = self.get_mut(&fd) else {
                    return Err(DecodeError::new(DecodeErrorKind::WireTypeMismatch));
                };
                sub.merge(m)
            }
            _ => {
                self.unknown.push_raw(1, WireType::StartGroup, raw);
                Ok(())
            }
        }
    }

    fn merge_field(
        &mut self,
        fd: &FieldDescriptor,
        wt: WireType,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        let n = fd.number();
        if fd.is_map() {
            return self.merge_map_entry(fd, r).map_err(|e| e.in_field(n));
        }
        let repeated = fd.cardinality() == Cardinality::Repeated;
        if repeated && wt == WireType::Len && is_packable(fd.kind()) {
            let b = r.read_bytes().map_err(|e| e.in_field(n))?;
            let mut sub = Reader::new(b);
            while !sub.is_empty() {
                let v = read_scalar(fd.kind(), &mut sub).map_err(|e| e.in_field(n))?;
                if let Some(v) = self.closed_check(fd, v) {
                    self.push(fd, v);
                }
            }
            return Ok(());
        }
        if let Kind::Message(_) = fd.kind() {
            let depth_ok = r.depth() < encoding::RECURSION_LIMIT;
            if !depth_ok {
                return Err(DecodeError::new(DecodeErrorKind::RecursionLimit).in_field(n));
            }
            let mut sub = match fd.message_type() {
                Some(m) => DynamicMessage::new(m),
                None => return Err(DecodeError::new(DecodeErrorKind::WireTypeMismatch)),
            };
            if !repeated {
                if let Some(Value::Message(m)) = self.fields.remove(&n) {
                    sub = m;
                }
            }
            if wt == WireType::StartGroup {
                r.enter().map_err(|e| e.in_field(n))?;
                sub.merge_from(r, Some(n)).map_err(|e| e.in_field(n))?;
                r.leave();
            } else {
                let mut nested = r.nested().map_err(|e| e.in_field(n))?;
                sub.merge_from(&mut nested, None)
                    .map_err(|e| e.in_field(n))?;
            }
            if repeated {
                self.push(fd, Value::Message(sub));
            } else {
                self.clear_oneof_siblings(fd);
                self.fields.insert(n, Value::Message(sub));
            }
            return Ok(());
        }
        let v = read_scalar(fd.kind(), r).map_err(|e| e.in_field(n))?;
        let Some(v) = self.closed_check(fd, v) else {
            return Ok(());
        };
        if repeated {
            self.push(fd, v);
        } else {
            self.clear_oneof_siblings(fd);
            if !fd.has_presence() && is_zero(&v) {
                // Implicit presence: a default value read is the field unset.
                self.fields.remove(&n);
            } else {
                self.fields.insert(n, v);
            }
        }
        Ok(())
    }

    /// For a closed enum: an unknown number goes to the unknown fields (`None`).
    fn closed_check(&mut self, fd: &FieldDescriptor, v: Value) -> Option<Value> {
        if let (Value::EnumNumber(x), Some(e)) = (&v, fd.enum_type()) {
            if e.is_closed() && e.value_name(*x).is_none() {
                self.unknown.push_varint(fd.number(), i64::from(*x) as u64);
                return None;
            }
        }
        Some(v)
    }

    fn push(&mut self, fd: &FieldDescriptor, v: Value) {
        match self
            .fields
            .entry(fd.number())
            .or_insert_with(|| Value::List(Vec::new()))
        {
            Value::List(l) => l.push(v),
            other => *other = Value::List(vec![v]),
        }
    }

    fn merge_map_entry(
        &mut self,
        fd: &FieldDescriptor,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        let Some((kf, vf)) = fd.map_entry_fields() else {
            return Err(DecodeError::new(DecodeErrorKind::WireTypeMismatch));
        };
        let raw_start = r.remaining();
        let mut sub = r.nested()?;
        let mut entry = DynamicMessage::new(
            fd.message_type()
                .ok_or(DecodeError::new(DecodeErrorKind::WireTypeMismatch))?,
        );
        entry.merge_from(&mut sub, None)?;
        // A closed enum value the enum does not know: the whole entry is an unknown field.
        if !entry.unknown.is_empty() && vf.enum_type().is_some_and(|e| e.is_closed()) {
            let used = raw_start.len() - r.remaining().len();
            let mut rr = Reader::new(&raw_start[..used]);
            let b = rr.read_bytes()?;
            self.unknown.push_raw(fd.number(), WireType::Len, b);
            return Ok(());
        }
        let k = entry.get(&kf).into_owned();
        let v = entry.get(&vf).into_owned();
        let Some(k) = MapKey::from_value(k) else {
            return Err(DecodeError::new(DecodeErrorKind::WireTypeMismatch));
        };
        match self
            .fields
            .entry(fd.number())
            .or_insert_with(|| Value::Map(BTreeMap::new()))
        {
            Value::Map(m) => {
                m.insert(k, v);
            }
            other => *other = Value::Map(std::iter::once((k, v)).collect()),
        }
        Ok(())
    }

    /// The encoding.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    /// Appends the encoding to `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        let message_set = self.desc.is_message_set();
        for (&n, v) in &self.fields {
            let Some(fd) = self.field_descriptor(n) else {
                continue;
            };
            if message_set && fd.is_extension() {
                if let Value::Message(m) = v {
                    encoding::put_tag(buf, 1, WireType::StartGroup);
                    encoding::put_tag(buf, 2, WireType::Varint);
                    encoding::put_varint(buf, u64::from(n));
                    encoding::put_tag(buf, 3, WireType::Len);
                    encoding::put_bytes(buf, &m.encode_to_vec());
                    encoding::put_tag(buf, 1, WireType::EndGroup);
                    continue;
                }
            }
            encode_field(&fd, v, buf);
        }
        self.unknown.encode(buf);
    }

    /// The length of the encoding.
    pub fn encoded_len(&self) -> usize {
        self.encode_to_vec().len()
    }
}

fn clear_unknown(v: &mut Value) {
    match v {
        Value::Message(m) => m.clear_unknown_fields(),
        Value::List(l) => l.iter_mut().for_each(clear_unknown),
        Value::Map(m) => m.values_mut().for_each(clear_unknown),
        _ => {}
    }
}

fn is_zero(v: &Value) -> bool {
    match v {
        Value::Bool(b) => !b,
        Value::I32(x) => *x == 0,
        Value::I64(x) => *x == 0,
        Value::U32(x) => *x == 0,
        Value::U64(x) => *x == 0,
        Value::F32(x) => x.to_bits() == 0,
        Value::F64(x) => x.to_bits() == 0,
        Value::String(s) => s.is_empty(),
        Value::Bytes(b) => b.is_empty(),
        Value::EnumNumber(x) => *x == 0,
        Value::Message(_) => false,
        Value::List(l) => l.is_empty(),
        Value::Map(m) => m.is_empty(),
    }
}

fn is_packable(k: Kind) -> bool {
    !matches!(k, Kind::String | Kind::Bytes | Kind::Message(_))
}

fn wire_type(k: Kind) -> WireType {
    match k {
        Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => WireType::Fixed64,
        Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => WireType::Fixed32,
        Kind::String | Kind::Bytes | Kind::Message(_) => WireType::Len,
        _ => WireType::Varint,
    }
}

fn accepts(fd: &FieldDescriptor, wt: WireType) -> bool {
    let own = if fd.is_group() {
        WireType::StartGroup
    } else {
        wire_type(fd.kind())
    };
    wt == own
        || (fd.cardinality() == Cardinality::Repeated
            && wt == WireType::Len
            && is_packable(fd.kind()))
}

fn read_scalar(k: Kind, r: &mut Reader<'_>) -> Result<Value, DecodeError> {
    Ok(match k {
        Kind::Double => Value::F64(f64::from_bits(r.read_fixed64()?)),
        Kind::Float => Value::F32(f32::from_bits(r.read_fixed32()?)),
        Kind::Int32 => Value::I32(r.read_varint()? as i32),
        Kind::Int64 => Value::I64(r.read_varint()? as i64),
        Kind::Uint32 => Value::U32(r.read_varint()? as u32),
        Kind::Uint64 => Value::U64(r.read_varint()?),
        Kind::Sint32 => Value::I32(encoding::unzigzag32(r.read_varint()? as u32)),
        Kind::Sint64 => Value::I64(encoding::unzigzag64(r.read_varint()?)),
        Kind::Fixed32 => Value::U32(r.read_fixed32()?),
        Kind::Fixed64 => Value::U64(r.read_fixed64()?),
        Kind::Sfixed32 => Value::I32(r.read_fixed32()? as i32),
        Kind::Sfixed64 => Value::I64(r.read_fixed64()? as i64),
        Kind::Bool => Value::Bool(r.read_varint()? != 0),
        Kind::String => {
            let b = r.read_bytes()?;
            Value::String(
                std::str::from_utf8(b)
                    .map_err(|_| DecodeError::new(DecodeErrorKind::InvalidUtf8))?
                    .to_owned(),
            )
        }
        Kind::Bytes => Value::Bytes(r.read_bytes()?.to_vec()),
        Kind::Enum(_) => Value::EnumNumber(r.read_varint()? as i32),
        Kind::Message(_) => return Err(DecodeError::new(DecodeErrorKind::WireTypeMismatch)),
    })
}

fn write_scalar(v: &Value, k: Kind, buf: &mut Vec<u8>) {
    match (k, v) {
        (Kind::Double, Value::F64(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Kind::Float, Value::F32(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Kind::Int32, Value::I32(x)) => encoding::put_varint(buf, i64::from(*x) as u64),
        (Kind::Int64, Value::I64(x)) => encoding::put_varint(buf, *x as u64),
        (Kind::Uint32, Value::U32(x)) => encoding::put_varint(buf, u64::from(*x)),
        (Kind::Uint64, Value::U64(x)) => encoding::put_varint(buf, *x),
        (Kind::Sint32, Value::I32(x)) => {
            encoding::put_varint(buf, u64::from(encoding::zigzag32(*x)));
        }
        (Kind::Sint64, Value::I64(x)) => encoding::put_varint(buf, encoding::zigzag64(*x)),
        (Kind::Fixed32, Value::U32(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Kind::Fixed64, Value::U64(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Kind::Sfixed32, Value::I32(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Kind::Sfixed64, Value::I64(x)) => buf.extend_from_slice(&x.to_le_bytes()),
        (Kind::Bool, Value::Bool(x)) => encoding::put_varint(buf, u64::from(*x)),
        (Kind::String, Value::String(s)) => encoding::put_bytes(buf, s.as_bytes()),
        (Kind::Bytes, Value::Bytes(b)) => encoding::put_bytes(buf, b),
        (Kind::Enum(_), Value::EnumNumber(x)) => encoding::put_varint(buf, i64::from(*x) as u64),
        _ => {}
    }
}

fn encode_one(fd: &FieldDescriptor, v: &Value, buf: &mut Vec<u8>) {
    let n = fd.number();
    match v {
        Value::Message(m) => {
            if fd.is_group() {
                encoding::put_tag(buf, n, WireType::StartGroup);
                m.encode(buf);
                encoding::put_tag(buf, n, WireType::EndGroup);
            } else {
                encoding::put_tag(buf, n, WireType::Len);
                let b = m.encode_to_vec();
                encoding::put_bytes(buf, &b);
            }
        }
        v => {
            encoding::put_tag(buf, n, wire_type(fd.kind()));
            write_scalar(v, fd.kind(), buf);
        }
    }
}

fn encode_field(fd: &FieldDescriptor, v: &Value, buf: &mut Vec<u8>) {
    let n = fd.number();
    match v {
        Value::List(items) => {
            if items.is_empty() {
                return;
            }
            if fd.is_packed() && is_packable(fd.kind()) {
                let mut body = Vec::new();
                for x in items {
                    write_scalar(x, fd.kind(), &mut body);
                }
                encoding::put_tag(buf, n, WireType::Len);
                encoding::put_bytes(buf, &body);
            } else {
                for x in items {
                    encode_one(fd, x, buf);
                }
            }
        }
        Value::Map(m) => {
            let Some((kf, vf)) = fd.map_entry_fields() else {
                return;
            };
            for (k, v) in m {
                let mut entry = Vec::new();
                encode_one(&kf, &k.to_value(), &mut entry);
                encode_one(&vf, v, &mut entry);
                encoding::put_tag(buf, n, WireType::Len);
                encoding::put_bytes(buf, &entry);
            }
        }
        v => {
            if !fd.has_presence() && is_zero(v) {
                return;
            }
            encode_one(fd, v, buf);
        }
    }
}

/// Whether `v` can be the value of `fd`.
fn value_fits(fd: &FieldDescriptor, v: &Value) -> bool {
    if fd.is_map() {
        let Some((kf, vf)) = fd.map_entry_fields() else {
            return false;
        };
        return match v {
            Value::Map(m) => m
                .iter()
                .all(|(k, x)| scalar_fits(kf.kind(), &k.to_value()) && single_fits(&vf, x)),
            _ => false,
        };
    }
    if fd.cardinality() == Cardinality::Repeated {
        return match v {
            Value::List(l) => l.iter().all(|x| single_fits(fd, x)),
            _ => false,
        };
    }
    single_fits(fd, v)
}

fn single_fits(fd: &FieldDescriptor, v: &Value) -> bool {
    match (fd.kind(), v) {
        (Kind::Message(_), Value::Message(m)) => fd
            .message_type()
            .is_some_and(|t| t.full_name() == m.descriptor().full_name()),
        (k, v) => scalar_fits(k, v),
    }
}

fn scalar_fits(k: Kind, v: &Value) -> bool {
    matches!(
        (k, v),
        (Kind::Double, Value::F64(_))
            | (Kind::Float, Value::F32(_))
            | (Kind::Int32 | Kind::Sint32 | Kind::Sfixed32, Value::I32(_))
            | (Kind::Int64 | Kind::Sint64 | Kind::Sfixed64, Value::I64(_))
            | (Kind::Uint32 | Kind::Fixed32, Value::U32(_))
            | (Kind::Uint64 | Kind::Fixed64, Value::U64(_))
            | (Kind::Bool, Value::Bool(_))
            | (Kind::String, Value::String(_))
            | (Kind::Bytes, Value::Bytes(_))
            | (Kind::Enum(_), Value::EnumNumber(_))
    )
}
