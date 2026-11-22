//! JSON -> DynamicMessage.

use std::collections::{BTreeMap, HashSet};

use super::{
    JResult, JsonError, ParseOptions, RECURSION_LIMIT, err, resolve_any,
    tree::Json,
    wkt::{self, base64_decode, integer, is_json_number},
};
use crate::reflect::{
    Cardinality, DynamicMessage, FieldDescriptor, Kind, MapKey, MessageDescriptor, Value,
};

fn is_value_type(fd: &FieldDescriptor) -> bool {
    fd.message_type()
        .is_some_and(|m| m.full_name() == "google.protobuf.Value")
}

fn is_null_enum(fd: &FieldDescriptor) -> bool {
    fd.enum_type()
        .is_some_and(|e| e.full_name() == "google.protobuf.NullValue")
}

fn get_field(desc: &MessageDescriptor, name: &str) -> Option<FieldDescriptor> {
    desc.get_field_by_json_name(name)
        .or_else(|| desc.get_field_by_name(name))
}

/// Parses `v` as a message of type `desc`.
pub(crate) fn message(
    desc: MessageDescriptor,
    v: &Json,
    o: &ParseOptions,
    depth: usize,
) -> JResult<DynamicMessage> {
    if depth > RECURSION_LIMIT {
        return err("message nesting too deep");
    }
    if let Some(m) = special(&desc, v, o, depth)? {
        return Ok(m);
    }
    let Json::Obj(members) = v else {
        return err(format!(
            "{} must be an object, found {}",
            desc.full_name(),
            v.kind()
        ));
    };
    let mut m = DynamicMessage::new(desc);
    fields(&mut m, members, o, depth)?;
    Ok(m)
}

fn fields(
    m: &mut DynamicMessage,
    members: &[(String, Json)],
    o: &ParseOptions,
    depth: usize,
) -> JResult<()> {
    let desc = m.descriptor().clone();
    let mut seen = HashSet::new();
    let mut oneofs = HashSet::new();
    for (k, v) in members {
        let fd = if let Some(ext) = k.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            desc.pool()
                .get_extension_by_name(ext)
                .filter(|x| x.containing_message() == desc)
        } else {
            get_field(&desc, k)
        };
        let Some(fd) = fd else {
            if o.ignore_unknown_fields {
                continue;
            }
            return err(format!("{} has no field {k:?}", desc.full_name()));
        };
        if !seen.insert(fd.number()) {
            return err(format!("field {k:?} given twice"));
        }
        if *v == Json::Null && !is_value_type(&fd) && !is_null_enum(&fd) {
            continue;
        }
        if let Some((name, false)) = fd.containing_oneof() {
            if !oneofs.insert(name.clone()) {
                return err(format!("more than one member of oneof {name} set"));
            }
        }
        let Some(val) = field_value(&fd, v, o, depth)? else {
            continue;
        };
        m.set(&fd, val)
            .map_err(|e| JsonError::new(format!("{k}: {e}")))?;
    }
    Ok(())
}

fn field_value(
    fd: &FieldDescriptor,
    v: &Json,
    o: &ParseOptions,
    depth: usize,
) -> JResult<Option<Value>> {
    let name = fd.name();
    if fd.is_map() {
        let Json::Obj(members) = v else {
            return err(format!("map field {name} must be an object"));
        };
        let Some((kf, vf)) = fd.map_entry_fields() else {
            return err("map without entry fields");
        };
        let mut out = BTreeMap::new();
        for (k, x) in members {
            let key = map_key(kf.kind(), k)?;
            if *x == Json::Null && !is_value_type(&vf) && !is_null_enum(&vf) {
                return err(format!("map field {name} has a null value"));
            }
            let Some(val) = single(&vf, x, o, depth)? else {
                continue;
            };
            if out.insert(key, val).is_some() {
                return err(format!("map field {name} has a key twice"));
            }
        }
        return Ok(Some(Value::Map(out)));
    }
    if fd.cardinality() == Cardinality::Repeated {
        let Json::Arr(items) = v else {
            return err(format!("repeated field {name} must be an array"));
        };
        let mut out = Vec::with_capacity(items.len());
        for x in items {
            if *x == Json::Null && !is_value_type(fd) && !is_null_enum(fd) {
                return err(format!("repeated field {name} has a null element"));
            }
            if let Some(val) = single(fd, x, o, depth)? {
                out.push(val);
            }
        }
        return Ok(Some(Value::List(out)));
    }
    single(fd, v, o, depth)
}

fn map_key(k: Kind, s: &str) -> JResult<MapKey> {
    let bad = || JsonError::new(format!("invalid map key {s:?}"));
    let int = |lo: i128, hi: i128| -> JResult<i128> {
        if !is_json_number(s) {
            return Err(bad());
        }
        integer(s).filter(|x| (lo..=hi).contains(x)).ok_or_else(bad)
    };
    Ok(match k {
        Kind::Bool => match s {
            "true" => MapKey::Bool(true),
            "false" => MapKey::Bool(false),
            _ => return Err(bad()),
        },
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => {
            MapKey::I32(int(i32::MIN.into(), i32::MAX.into())? as i32)
        }
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => {
            MapKey::I64(int(i64::MIN.into(), i64::MAX.into())? as i64)
        }
        Kind::Uint32 | Kind::Fixed32 => MapKey::U32(int(0, u32::MAX.into())? as u32),
        Kind::Uint64 | Kind::Fixed64 => MapKey::U64(int(0, u64::MAX.into())? as u64),
        Kind::String => MapKey::String(s.to_owned()),
        _ => return Err(bad()),
    })
}

/// An integer from a JSON number or a string holding one.
fn int_in(v: &Json, lo: i128, hi: i128, what: &str) -> JResult<i128> {
    let t = match v {
        Json::Num(t) => t.as_str(),
        Json::Str(t) if is_json_number(t) => t.as_str(),
        _ => return err(format!("{what} must be an integer, found {}", v.kind())),
    };
    match integer(t) {
        Some(x) if (lo..=hi).contains(&x) => Ok(x),
        Some(_) => err(format!("{what}: {t} out of range")),
        None => err(format!("{what}: {t} is not an integer")),
    }
}

fn float(v: &Json, single: bool, what: &str) -> JResult<f64> {
    let x = match v {
        Json::Str(s) if s == "NaN" => return Ok(f64::NAN),
        Json::Str(s) if s == "Infinity" => return Ok(f64::INFINITY),
        Json::Str(s) if s == "-Infinity" => return Ok(f64::NEG_INFINITY),
        Json::Num(t) => t.parse::<f64>(),
        Json::Str(t) if is_json_number(t) => t.parse::<f64>(),
        _ => return err(format!("{what} must be a number, found {}", v.kind())),
    }
    .map_err(|_| JsonError::new(format!("{what}: invalid number")))?;
    if !x.is_finite() || (single && x.abs() > f64::from(f32::MAX)) {
        return err(format!("{what}: number out of range"));
    }
    Ok(x)
}

/// One value of `fd` (`None`: an unknown enum name skipped under `ignore_unknown_fields`).
fn single(
    fd: &FieldDescriptor,
    v: &Json,
    o: &ParseOptions,
    depth: usize,
) -> JResult<Option<Value>> {
    let what = fd.name();
    Ok(Some(match fd.kind() {
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => {
            Value::I32(int_in(v, i32::MIN.into(), i32::MAX.into(), what)? as i32)
        }
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => {
            Value::I64(int_in(v, i64::MIN.into(), i64::MAX.into(), what)? as i64)
        }
        Kind::Uint32 | Kind::Fixed32 => Value::U32(int_in(v, 0, u32::MAX.into(), what)? as u32),
        Kind::Uint64 | Kind::Fixed64 => Value::U64(int_in(v, 0, u64::MAX.into(), what)? as u64),
        Kind::Float => Value::F32(float(v, true, what)? as f32),
        Kind::Double => Value::F64(float(v, false, what)?),
        Kind::Bool => match v {
            Json::Bool(b) => Value::Bool(*b),
            _ => return err(format!("{what} must be a boolean, found {}", v.kind())),
        },
        Kind::String => match v {
            Json::Str(s) => Value::String(s.clone()),
            _ => return err(format!("{what} must be a string, found {}", v.kind())),
        },
        Kind::Bytes => match v {
            Json::Str(s) => Value::Bytes(base64_decode(s)?),
            _ => {
                return err(format!(
                    "{what} must be a base64 string, found {}",
                    v.kind()
                ));
            }
        },
        Kind::Enum(_) => {
            let Some(e) = fd.enum_type() else {
                return err("enum without a type");
            };
            match v {
                Json::Null if e.full_name() == "google.protobuf.NullValue" => Value::EnumNumber(0),
                Json::Str(s) => match e.value_number(s) {
                    Some(n) => Value::EnumNumber(n),
                    None if o.ignore_unknown_fields => return Ok(None),
                    None => return err(format!("{what}: unknown enum value {s:?}")),
                },
                Json::Num(_) => {
                    let n = int_in(v, i32::MIN.into(), i32::MAX.into(), what)? as i32;
                    if e.is_closed() && e.value_name(n).is_none() {
                        if o.ignore_unknown_fields {
                            return Ok(None);
                        }
                        return err(format!("{what}: unknown value {n} of closed enum"));
                    }
                    Value::EnumNumber(n)
                }
                _ => return err(format!("{what} must be an enum name or number")),
            }
        }
        Kind::Message(_) => {
            let Some(t) = fd.message_type() else {
                return err("message without a type");
            };
            Value::Message(message(t, v, o, depth + 1)?)
        }
    }))
}

fn set_name(m: &mut DynamicMessage, name: &str, v: Value) -> JResult<()> {
    let fd = m
        .descriptor()
        .get_field_by_name(name)
        .ok_or_else(|| JsonError::new(format!("no field {name}")))?;
    m.set(&fd, v).map_err(|e| JsonError::new(e.to_string()))
}

/// The well-known types with a special form; `None` for other messages.
fn special(
    desc: &MessageDescriptor,
    v: &Json,
    o: &ParseOptions,
    depth: usize,
) -> JResult<Option<DynamicMessage>> {
    let Some(t) = desc.full_name().strip_prefix("google.protobuf.") else {
        return Ok(None);
    };
    let mut m = DynamicMessage::new(desc.clone());
    match t {
        "Timestamp" | "Duration" => {
            let Json::Str(s) = v else {
                return err(format!("{t} must be a string"));
            };
            let (secs, nanos) = if t == "Timestamp" {
                wkt::parse_timestamp(s)?
            } else {
                wkt::parse_duration(s)?
            };
            set_name(&mut m, "seconds", Value::I64(secs))?;
            set_name(&mut m, "nanos", Value::I32(nanos))?;
        }
        "FieldMask" => {
            let Json::Str(s) = v else {
                return err("FieldMask must be a string");
            };
            let mut paths = Vec::new();
            for p in s.split(',').filter(|p| !p.is_empty()) {
                paths.push(Value::String(wkt::mask_path_from_json(p)?));
            }
            set_name(&mut m, "paths", Value::List(paths))?;
        }
        "DoubleValue" | "FloatValue" | "Int64Value" | "UInt64Value" | "Int32Value"
        | "UInt32Value" | "BoolValue" | "StringValue" | "BytesValue" => {
            let fd = desc
                .get_field(1)
                .ok_or_else(|| JsonError::new("wrapper without a value field"))?;
            if let Some(x) = single(&fd, v, o, depth)? {
                m.set(&fd, x).map_err(|e| JsonError::new(e.to_string()))?;
            }
        }
        "Struct" => {
            let fd = desc
                .get_field(1)
                .ok_or_else(|| JsonError::new("Struct without fields"))?;
            if !matches!(v, Json::Obj(_)) {
                return err("Struct must be an object");
            }
            if let Some(x) = field_value(&fd, v, o, depth)? {
                m.set(&fd, x).map_err(|e| JsonError::new(e.to_string()))?;
            }
        }
        "ListValue" => {
            let fd = desc
                .get_field(1)
                .ok_or_else(|| JsonError::new("ListValue without values"))?;
            if !matches!(v, Json::Arr(_)) {
                return err("ListValue must be an array");
            }
            if let Some(x) = field_value(&fd, v, o, depth)? {
                m.set(&fd, x).map_err(|e| JsonError::new(e.to_string()))?;
            }
        }
        "Value" => {
            let (name, json) = match v {
                Json::Null => ("null_value", None),
                Json::Bool(_) => ("bool_value", Some(v)),
                Json::Num(_) => ("number_value", Some(v)),
                Json::Str(_) => ("string_value", Some(v)),
                Json::Obj(_) => ("struct_value", Some(v)),
                Json::Arr(_) => ("list_value", Some(v)),
            };
            let fd = desc
                .get_field_by_name(name)
                .ok_or_else(|| JsonError::new("Value without its fields"))?;
            let x = match json {
                None => Value::EnumNumber(0),
                Some(Json::Num(t)) => {
                    let x: f64 = t.parse().map_err(|_| JsonError::new("invalid number"))?;
                    if !x.is_finite() {
                        return err("number out of range");
                    }
                    Value::F64(x)
                }
                Some(j) => match single(&fd, j, o, depth)? {
                    Some(x) => x,
                    None => return Ok(Some(m)),
                },
            };
            m.set(&fd, x).map_err(|e| JsonError::new(e.to_string()))?;
        }
        "Any" => any(&mut m, v, o, depth)?,
        _ => return Ok(None),
    }
    Ok(Some(m))
}

fn any(m: &mut DynamicMessage, v: &Json, o: &ParseOptions, depth: usize) -> JResult<()> {
    let Json::Obj(members) = v else {
        return err("Any must be an object");
    };
    let mut url = None;
    for (k, x) in members {
        if k == "@type" {
            if url.is_some() {
                return err("@type given twice");
            }
            match x {
                Json::Str(s) => url = Some(s.clone()),
                _ => return err("@type must be a string"),
            }
        }
    }
    let Some(url) = url else {
        if members.is_empty() {
            return Ok(());
        }
        return err("Any without @type");
    };
    let desc = resolve_any(&url, m.descriptor().pool(), o.type_pool.as_ref())?;
    let rest: Vec<(String, Json)> = members
        .iter()
        .filter(|(k, _)| k != "@type")
        .cloned()
        .collect();
    let probe = DynamicMessage::new(desc.clone());
    let inner = if desc.full_name().starts_with("google.protobuf.")
        && is_special(probe.descriptor().full_name())
    {
        let mut value = None;
        for (k, x) in &rest {
            if k == "value" {
                value = Some(x);
            } else if !o.ignore_unknown_fields {
                return err(format!(
                    "unexpected {k:?} in an Any of {}",
                    desc.full_name()
                ));
            }
        }
        let Some(value) = value else {
            return err(format!("Any of {} without value", desc.full_name()));
        };
        message(desc, value, o, depth + 1)?
    } else {
        let mut inner = DynamicMessage::new(desc);
        fields(&mut inner, &rest, o, depth + 1)?;
        inner
    };
    set_name(m, "type_url", Value::String(url))?;
    set_name(m, "value", Value::Bytes(inner.encode_to_vec()))?;
    Ok(())
}

fn is_special(name: &str) -> bool {
    matches!(
        name.strip_prefix("google.protobuf."),
        Some(
            "Any"
                | "Timestamp"
                | "Duration"
                | "FieldMask"
                | "Struct"
                | "Value"
                | "ListValue"
                | "DoubleValue"
                | "FloatValue"
                | "Int64Value"
                | "UInt64Value"
                | "Int32Value"
                | "UInt32Value"
                | "BoolValue"
                | "StringValue"
                | "BytesValue"
        )
    )
}
