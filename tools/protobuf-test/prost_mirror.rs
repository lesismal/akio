// prost versions of `test.all.AllTypes` and the well-known types it uses, for the
// differential tests (tests/prost_diff.rs), the fuzz target `protobuf_diff` and the benchmark.
// Included with `#[path]`; needs the `prost` crate.

#![allow(
    missing_docs,
    unreachable_pub,
    dead_code,
    clippy::derive_partial_eq_without_eq,
    clippy::enum_variant_names
)]

use std::collections::HashMap;

use only_protobuf::{Message as _, well_known};
use protobuf_test::test::{all, common};

#[derive(Clone, PartialEq, prost::Message)]
pub struct Shared {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(int32, repeated, tag = "2")]
    pub values: Vec<i32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Nested {
    #[prost(int32, tag = "1")]
    pub a: i32,
    #[prost(message, optional, boxed, tag = "2")]
    pub child: Option<Box<Nested>>,
    #[prost(string, tag = "3")]
    pub r#type: String,
    #[prost(int32, tag = "4")]
    pub deep: i32,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Choice {
    #[prost(uint32, tag = "60")]
    CUint32(u32),
    #[prost(string, tag = "61")]
    CString(String),
    #[prost(message, tag = "62")]
    CNested(Nested),
    #[prost(bytes = "vec", tag = "63")]
    CBytes(Vec<u8>),
    #[prost(int32, tag = "64")]
    CEnum(i32),
    #[prost(message, tag = "65")]
    CSelf(Box<AllTypes>),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Timestamp {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Any {
    #[prost(string, tag = "1")]
    pub type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Struct {
    #[prost(map = "string, message", tag = "1")]
    pub fields: HashMap<String, Value>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ListValue {
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<Value>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Value {
    #[prost(oneof = "Kind", tags = "1, 2, 3, 4, 5, 6")]
    pub kind: Option<Kind>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Kind {
    #[prost(int32, tag = "1")]
    NullValue(i32),
    #[prost(double, tag = "2")]
    NumberValue(f64),
    #[prost(string, tag = "3")]
    StringValue(String),
    #[prost(bool, tag = "4")]
    BoolValue(bool),
    #[prost(message, tag = "5")]
    StructValue(Struct),
    #[prost(message, tag = "6")]
    ListValue(ListValue),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Int32Value {
    #[prost(int32, tag = "1")]
    pub value: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AllTypes {
    #[prost(int32, tag = "1")]
    pub f_int32: i32,
    #[prost(int64, tag = "2")]
    pub f_int64: i64,
    #[prost(uint32, tag = "3")]
    pub f_uint32: u32,
    #[prost(uint64, tag = "4")]
    pub f_uint64: u64,
    #[prost(sint32, tag = "5")]
    pub f_sint32: i32,
    #[prost(sint64, tag = "6")]
    pub f_sint64: i64,
    #[prost(fixed32, tag = "7")]
    pub f_fixed32: u32,
    #[prost(fixed64, tag = "8")]
    pub f_fixed64: u64,
    #[prost(sfixed32, tag = "9")]
    pub f_sfixed32: i32,
    #[prost(sfixed64, tag = "10")]
    pub f_sfixed64: i64,
    #[prost(float, tag = "11")]
    pub f_float: f32,
    #[prost(double, tag = "12")]
    pub f_double: f64,
    #[prost(bool, tag = "13")]
    pub f_bool: bool,
    #[prost(string, tag = "14")]
    pub f_string: String,
    #[prost(bytes = "vec", tag = "15")]
    pub f_bytes: Vec<u8>,
    #[prost(int32, tag = "16")]
    pub f_enum: i32,
    #[prost(message, optional, tag = "17")]
    pub f_nested: Option<Nested>,
    #[prost(message, optional, tag = "18")]
    pub f_shared: Option<Shared>,
    #[prost(int32, optional, tag = "19")]
    pub o_int32: Option<i32>,
    #[prost(string, optional, tag = "20")]
    pub o_string: Option<String>,
    #[prost(int32, optional, tag = "21")]
    pub o_enum: Option<i32>,
    #[prost(message, optional, tag = "22")]
    pub o_nested: Option<Nested>,
    #[prost(int32, repeated, tag = "31")]
    pub r_int32: Vec<i32>,
    #[prost(sint64, repeated, tag = "32")]
    pub r_sint64: Vec<i64>,
    #[prost(fixed32, repeated, tag = "33")]
    pub r_fixed32: Vec<u32>,
    #[prost(double, repeated, tag = "34")]
    pub r_double: Vec<f64>,
    #[prost(bool, repeated, tag = "35")]
    pub r_bool: Vec<bool>,
    #[prost(int32, repeated, tag = "36")]
    pub r_enum: Vec<i32>,
    #[prost(int32, repeated, packed = "false", tag = "37")]
    pub r_int32_unpacked: Vec<i32>,
    #[prost(string, repeated, tag = "38")]
    pub r_string: Vec<String>,
    #[prost(bytes = "vec", repeated, tag = "39")]
    pub r_bytes: Vec<Vec<u8>>,
    #[prost(message, repeated, tag = "40")]
    pub r_nested: Vec<Nested>,
    #[prost(uint64, repeated, tag = "41")]
    pub r_uint64: Vec<u64>,
    #[prost(map = "string, int32", tag = "50")]
    pub m_string_int32: HashMap<String, i32>,
    #[prost(map = "int64, string", tag = "51")]
    pub m_int64_string: HashMap<i64, String>,
    #[prost(map = "bool, message", tag = "52")]
    pub m_bool_nested: HashMap<bool, Nested>,
    #[prost(map = "uint32, int32", tag = "53")]
    pub m_uint32_enum: HashMap<u32, i32>,
    #[prost(map = "sint32, bytes", tag = "54")]
    pub m_sint32_bytes: HashMap<i32, Vec<u8>>,
    #[prost(map = "fixed64, double", tag = "55")]
    pub m_fixed64_double: HashMap<u64, f64>,
    #[prost(oneof = "Choice", tags = "60, 61, 62, 63, 64, 65")]
    pub choice: Option<Choice>,
    #[prost(message, optional, boxed, tag = "70")]
    pub recursive: Option<Box<AllTypes>>,
    #[prost(message, optional, tag = "80")]
    pub ts: Option<Timestamp>,
    #[prost(message, optional, tag = "81")]
    pub any: Option<Any>,
    #[prost(message, optional, tag = "82")]
    pub st: Option<Struct>,
    #[prost(message, optional, tag = "83")]
    pub wrapped: Option<Int32Value>,
    #[prost(int32, tag = "536870911")]
    pub max_field_number: i32,
}

pub fn nested_to_prost(n: &all::all_types::Nested) -> Nested {
    Nested {
        a: n.a,
        child: n.child.as_deref().map(|c| Box::new(nested_to_prost(c))),
        r#type: n.r#type.clone(),
        deep: n.deep.0,
    }
}

fn shared_to_prost(s: &common::Shared) -> Shared {
    Shared {
        id: s.id.clone(),
        values: s.values.clone(),
    }
}

fn value_to_prost(v: &well_known::Value) -> Value {
    use well_known::value::Kind as K;
    Value {
        kind: v.kind.as_ref().map(|k| match k {
            K::NullValue(n) => Kind::NullValue(n.0),
            K::NumberValue(n) => Kind::NumberValue(*n),
            K::StringValue(s) => Kind::StringValue(s.clone()),
            K::BoolValue(b) => Kind::BoolValue(*b),
            K::StructValue(s) => Kind::StructValue(struct_to_prost(s)),
            K::ListValue(l) => Kind::ListValue(ListValue {
                values: l.values.iter().map(value_to_prost).collect(),
            }),
        }),
    }
}

fn struct_to_prost(s: &well_known::Struct) -> Struct {
    Struct {
        fields: s
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), value_to_prost(v)))
            .collect(),
    }
}

/// The prost view of an `AllTypes` (unknown fields are dropped: prost does not keep them).
pub fn to_prost(m: &all::AllTypes) -> AllTypes {
    use all::all_types::Choice as C;
    AllTypes {
        f_int32: m.f_int32,
        f_int64: m.f_int64,
        f_uint32: m.f_uint32,
        f_uint64: m.f_uint64,
        f_sint32: m.f_sint32,
        f_sint64: m.f_sint64,
        f_fixed32: m.f_fixed32,
        f_fixed64: m.f_fixed64,
        f_sfixed32: m.f_sfixed32,
        f_sfixed64: m.f_sfixed64,
        f_float: m.f_float,
        f_double: m.f_double,
        f_bool: m.f_bool,
        f_string: m.f_string.clone(),
        f_bytes: m.f_bytes.clone(),
        f_enum: m.f_enum.0,
        f_nested: m.f_nested.as_ref().map(nested_to_prost),
        f_shared: m.f_shared.as_ref().map(shared_to_prost),
        o_int32: m.o_int32,
        o_string: m.o_string.clone(),
        o_enum: m.o_enum.map(|e| e.0),
        o_nested: m.o_nested.as_ref().map(nested_to_prost),
        r_int32: m.r_int32.clone(),
        r_sint64: m.r_sint64.clone(),
        r_fixed32: m.r_fixed32.clone(),
        r_double: m.r_double.clone(),
        r_bool: m.r_bool.clone(),
        r_enum: m.r_enum.iter().map(|e| e.0).collect(),
        r_int32_unpacked: m.r_int32_unpacked.clone(),
        r_string: m.r_string.clone(),
        r_bytes: m.r_bytes.clone(),
        r_nested: m.r_nested.iter().map(nested_to_prost).collect(),
        r_uint64: m.r_uint64.clone(),
        m_string_int32: m.m_string_int32.clone(),
        m_int64_string: m.m_int64_string.clone(),
        m_bool_nested: m
            .m_bool_nested
            .iter()
            .map(|(k, v)| (*k, nested_to_prost(v)))
            .collect(),
        m_uint32_enum: m.m_uint32_enum.iter().map(|(k, v)| (*k, v.0)).collect(),
        m_sint32_bytes: m.m_sint32_bytes.clone(),
        m_fixed64_double: m.m_fixed64_double.clone(),
        choice: match &m.choice {
            Some(C::CUint32(v)) => Some(Choice::CUint32(*v)),
            Some(C::CString(v)) => Some(Choice::CString(v.clone())),
            Some(C::CNested(v)) => Some(Choice::CNested(nested_to_prost(v))),
            Some(C::CBytes(v)) => Some(Choice::CBytes(v.clone())),
            Some(C::CEnum(v)) => Some(Choice::CEnum(v.0)),
            Some(C::CSelf(v)) => Some(Choice::CSelf(Box::new(to_prost(v)))),
            None => None,
        },
        recursive: m.recursive.as_deref().map(|r| Box::new(to_prost(r))),
        ts: m.ts.as_ref().map(|t| Timestamp {
            seconds: t.seconds,
            nanos: t.nanos,
        }),
        any: m.any.as_ref().map(|a| Any {
            type_url: a.type_url.clone(),
            value: a.value.clone(),
        }),
        st: m.st.as_ref().map(struct_to_prost),
        wrapped: m.wrapped.as_ref().map(|w| Int32Value { value: w.value }),
        max_field_number: m.max_field_number,
    }
}

/// NaN-tolerant comparison (`NaN != NaN` breaks `PartialEq`): falls back to the debug output.
fn same(a: &AllTypes, b: &AllTypes) -> bool {
    if a == b {
        return true;
    }
    let (mut a, mut b) = (a.clone(), b.clone());
    denan(&mut a);
    denan(&mut b);
    a == b
}

fn denan_f64(v: &mut f64) {
    if v.is_nan() {
        *v = f64::MAX;
    }
}

fn denan_value(v: &mut Value) {
    match &mut v.kind {
        Some(Kind::NumberValue(n)) => denan_f64(n),
        Some(Kind::StructValue(s)) => s.fields.values_mut().for_each(denan_value),
        Some(Kind::ListValue(l)) => l.values.iter_mut().for_each(denan_value),
        _ => {}
    }
}

/// Replaces NaNs (so `==` works).
fn denan(a: &mut AllTypes) {
    if a.f_float.is_nan() {
        a.f_float = f32::MAX;
    }
    denan_f64(&mut a.f_double);
    a.r_double.iter_mut().for_each(denan_f64);
    a.m_fixed64_double.values_mut().for_each(denan_f64);
    if let Some(s) = &mut a.st {
        s.fields.values_mut().for_each(denan_value);
    }
    if let Some(r) = &mut a.recursive {
        denan(r);
    }
    if let Some(Choice::CSelf(r)) = &mut a.choice {
        denan(r);
    }
}

// ---- wire-type mismatch detection ------------------------------------------------------------

use only_protobuf::encoding::{Reader, WireType};

#[derive(Clone, Copy)]
enum S {
    /// A singular field of this wire type.
    Leaf(WireType),
    /// A repeated scalar: its wire type or packed.
    Packable(WireType),
    /// An embedded message (or map entry) with this schema.
    Msg(fn(u32) -> Option<S>),
}

const V: S = S::Leaf(WireType::Varint);
const L: S = S::Leaf(WireType::Len);
const F32: S = S::Leaf(WireType::Fixed32);
const F64: S = S::Leaf(WireType::Fixed64);

fn s_all(f: u32) -> Option<S> {
    Some(match f {
        1..=6 | 13 | 16 | 19 | 21 | 60 | 64 | 536_870_911 => V,
        7 | 9 | 11 => F32,
        8 | 10 | 12 => F64,
        14 | 15 | 20 | 38 | 39 | 61 | 63 => L,
        17 | 22 | 40 | 62 => S::Msg(s_nested),
        18 => S::Msg(s_shared),
        31 | 32 | 35 | 36 | 37 | 41 => S::Packable(WireType::Varint),
        33 => S::Packable(WireType::Fixed32),
        34 => S::Packable(WireType::Fixed64),
        50 => S::Msg(|f| [None, Some(L), Some(V)].get(f as usize).copied().flatten()),
        51 => S::Msg(|f| [None, Some(V), Some(L)].get(f as usize).copied().flatten()),
        52 => S::Msg(|f| {
            [None, Some(V), Some(S::Msg(s_nested))]
                .get(f as usize)
                .copied()
                .flatten()
        }),
        53 => S::Msg(|f| [None, Some(V), Some(V)].get(f as usize).copied().flatten()),
        54 => S::Msg(|f| [None, Some(V), Some(L)].get(f as usize).copied().flatten()),
        55 => S::Msg(|f| {
            [None, Some(F64), Some(F64)]
                .get(f as usize)
                .copied()
                .flatten()
        }),
        65 | 70 => S::Msg(s_all),
        80 => S::Msg(|f| (f == 1 || f == 2).then_some(V)),
        81 => S::Msg(|f| (f == 1 || f == 2).then_some(L)),
        82 => S::Msg(s_struct),
        83 => S::Msg(|f| (f == 1).then_some(V)),
        _ => return None,
    })
}

fn s_nested(f: u32) -> Option<S> {
    Some(match f {
        1 | 4 => V,
        2 => S::Msg(s_nested),
        3 => L,
        _ => return None,
    })
}

fn s_shared(f: u32) -> Option<S> {
    Some(match f {
        1 => L,
        2 => S::Packable(WireType::Varint),
        _ => return None,
    })
}

fn s_struct(f: u32) -> Option<S> {
    (f == 1).then_some(S::Msg(|f| match f {
        1 => Some(L),
        2 => Some(S::Msg(s_value)),
        _ => None,
    }))
}

fn s_value(f: u32) -> Option<S> {
    Some(match f {
        1 | 4 => V,
        2 => F64,
        3 => L,
        5 => S::Msg(s_struct),
        6 => S::Msg(|f| (f == 1).then_some(S::Msg(s_value))),
        _ => return None,
    })
}

/// Whether `data` has a known field with an unexpected wire type anywhere (decoders differ
/// there: C++, Go and only-protobuf keep it as an unknown field, prost fails or misreads it).
/// A tag written in more than 5 bytes: C++ (and we) reject it, prost accepts it.
fn overlong_tag(b: &[u8]) -> bool {
    b.iter().take(5).all(|&x| x & 0x80 != 0) && b.len() > 5
}

fn mismatch(data: &[u8], schema: fn(u32) -> Option<S>, depth: u32) -> bool {
    let mut r = Reader::new(data);
    while !r.is_empty() {
        let rest = r.remaining();
        let Ok((f, wt)) = r.read_tag() else {
            return overlong_tag(rest);
        };
        let wrong = match schema(f) {
            None => false,
            Some(S::Leaf(want)) => wt != want,
            Some(S::Packable(want)) => wt != want && wt != WireType::Len,
            Some(S::Msg(_)) => wt != WireType::Len,
        };
        if wrong {
            return true;
        }
        let Ok(raw) = r.skip_field(f, wt) else {
            return false;
        };
        if let Some(S::Msg(sub)) = schema(f) {
            let inner = Reader::new(raw).read_bytes();
            if depth < 100 && inner.is_ok_and(|b| mismatch(b, sub, depth + 1)) {
                return true;
            }
        }
    }
    false
}

/// Feeds `data` to both decoders: they must agree on accepting it and on the value, and the
/// re-encodings must round-trip in both directions. Inputs with a wire-type mismatch are only
/// checked for our own round trip (see `mismatch`).
pub fn differential(data: &[u8]) {
    let ours = all::AllTypes::decode(data);
    let theirs = <AllTypes as prost::Message>::decode(data);
    let mm = mismatch(data, s_all, 0);
    if let Ok(o) = &ours {
        let re = o.encode_to_vec();
        assert_eq!(re.len(), o.encoded_len());
        let again = all::AllTypes::decode(&re).expect("ours decodes ours");
        assert!(same(&to_prost(&again), &to_prost(o)), "our round trip");
        if !mm {
            let back =
                <AllTypes as prost::Message>::decode(re.as_slice()).expect("prost decodes ours");
            assert!(
                same(&back, &to_prost(o)),
                "prost reading our encoding\nours:  {:?}\nprost: {back:?}\ninput: {data:02x?}",
                to_prost(o)
            );
        }
    }
    if mm {
        return;
    }
    match (&ours, &theirs) {
        (Ok(o), Ok(t)) => assert!(
            same(&to_prost(o), t),
            "decoded values differ\nours:  {o:?}\nprost: {t:?}\ninput: {data:02x?}"
        ),
        (Err(_), Err(_)) => {}
        (Ok(o), Err(e)) => {
            panic!("only-protobuf accepted what prost rejects ({e}): {o:?}\ninput: {data:02x?}");
        }
        (Err(e), Ok(t)) => {
            panic!("only-protobuf rejected what prost accepts ({e}): {t:?}\ninput: {data:02x?}");
        }
    }
}

// ---- groups and closed enums: test.ext.Base ------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
pub struct PMeta {
    #[prost(string, optional, tag = "3")]
    pub note: Option<String>,
}

/// prost's view of `test.ext.Base`: the group, and the closed enum as plain numbers (prost
/// enums are open); the extension range is unknown to prost.
#[derive(Clone, PartialEq, prost::Message)]
pub struct PBase {
    #[prost(int32, optional, tag = "1")]
    pub id: Option<i32>,
    #[prost(group, optional, tag = "2")]
    pub meta: Option<PMeta>,
    #[prost(int32, repeated, packed = "false", tag = "4")]
    pub levels: Vec<i32>,
}

fn base_to_prost(b: &protobuf_test::test::ext::Base) -> PBase {
    PBase {
        id: b.id,
        meta: b.meta.as_ref().map(|m| PMeta {
            note: m.note.clone(),
        }),
        levels: b.levels.iter().map(|l| l.0).collect(),
    }
}

/// A field of `Base` (or of its group) that arrives with another wire type than declared: we
/// keep it as an unknown field, prost rejects the message.
fn base_mismatch(data: &[u8], in_group: bool, depth: u32) -> bool {
    let mut r = Reader::new(data);
    while !r.is_empty() {
        let rest = r.remaining();
        let Ok((f, wt)) = r.read_tag() else {
            return overlong_tag(rest);
        };
        if wt == WireType::EndGroup {
            return false;
        }
        let wrong = match (in_group, f) {
            (false, 1) => wt != WireType::Varint,
            (false, 2) => wt != WireType::StartGroup,
            (false, 4) => wt != WireType::Varint && wt != WireType::Len,
            (true, 3) => wt != WireType::Len,
            _ => false,
        };
        if wrong {
            return true;
        }
        if !in_group && f == 2 && (depth >= 100 || base_mismatch(r.remaining(), true, depth + 1)) {
            return true;
        }
        if r.skip_field(f, wt).is_err() {
            return false;
        }
    }
    false
}

/// [`differential`] for `test.ext.Base` (proto2 group, closed enum, extension range): the same
/// acceptance and the same values, except that a closed enum's unknown numbers are dropped by
/// us (kept as unknown fields) where prost keeps them.
pub fn differential_groups(data: &[u8]) {
    use protobuf_test::test::ext::Base;
    let ours = Base::decode(data);
    let theirs = <PBase as prost::Message>::decode(data);
    let mm = base_mismatch(data, false, 0);
    if let Ok(o) = &ours {
        let re = o.encode_to_vec();
        assert_eq!(re.len(), o.encoded_len());
        let again = Base::decode(&re).expect("ours decodes ours");
        assert_eq!(&again, o, "our round trip");
        if !mm {
            let mut back =
                <PBase as prost::Message>::decode(re.as_slice()).expect("prost decodes ours");
            // Our unknown closed enum numbers come back after the known fields.
            back.levels.retain(|l| *l == 1 || *l == 2);
            assert_eq!(back, base_to_prost(o), "prost reading our encoding");
        }
    }
    if mm {
        return;
    }
    match (&ours, &theirs) {
        (Ok(o), Ok(t)) => {
            let mut t = t.clone();
            t.levels.retain(|l| *l == 1 || *l == 2);
            assert_eq!(
                base_to_prost(o),
                t,
                "decoded values differ\ninput: {data:02x?}"
            );
        }
        (Err(_), Err(_)) => {}
        (Ok(o), Err(e)) => {
            panic!("only-protobuf accepted what prost rejects ({e}): {o:?}\ninput: {data:02x?}");
        }
        (Err(e), Ok(t)) => {
            panic!("only-protobuf rejected what prost accepts ({e}): {t:?}\ninput: {data:02x?}");
        }
    }
}

/// Reflection against generated code: a `DynamicMessage` of `AllTypes` and of `test.ext.Base`
/// accepts exactly what the generated decoder accepts, and both re-encode to the same bytes.
pub fn differential_dynamic(data: &[u8]) {
    use only_protobuf::reflect::{DynamicMessage, ReflectMessage};
    fn one<M: ReflectMessage + PartialEq + std::fmt::Debug>(data: &[u8], lazy: fn(&M) -> bool) {
        let typed = M::decode(data);
        let dynamic = DynamicMessage::decode(M::descriptor(), data);
        match (&typed, &dynamic) {
            (Ok(t), Ok(d)) => {
                let tb = t.encode_to_vec();
                let db = d.encode_to_vec();
                // Same values: the dynamic encoding decodes to the typed message. Compared in
                // the dynamic message's canonical encoding (maps sorted; NaN is unequal to
                // itself as a value).
                let canon = |b: &[u8]| {
                    DynamicMessage::decode(M::descriptor(), b)
                        .expect("dynamic decodes typed")
                        .encode_to_vec()
                };
                let t2 = M::decode(&db).expect("typed decodes dynamic");
                assert_eq!(
                    canon(&t2.encode_to_vec()),
                    canon(&tb),
                    "values\n{t2:?}\n{t:?}"
                );
                // Known values equal (unknown fields may come in another order: a closed enum's
                // unknown number in an extension is an unknown field to the dynamic message, an
                // extension record to the generated one).
                let mut back =
                    DynamicMessage::decode(M::descriptor(), &tb).expect("dynamic decodes typed");
                let mut d = d.clone();
                back.clear_unknown_fields();
                d.clear_unknown_fields();
                assert_eq!(back.encode_to_vec(), d.encode_to_vec(), "dynamic values");
            }
            (Err(_), Err(_)) => {}
            // Generated code keeps extension fields undecoded (an error inside one surfaces
            // when it is read); the dynamic message decodes them eagerly.
            (Ok(t), Err(_)) if lazy(t) => {}
            (t, d) => panic!("typed {t:?} vs dynamic {d:?}\ninput: {data:02x?}"),
        }
    }
    one::<all::AllTypes>(data, |_| false);
    one::<protobuf_test::test::ext::Base>(data, |b| !b.extensions.is_empty());
    one::<protobuf_test::test::ed::Item>(data, |_| false);
}
