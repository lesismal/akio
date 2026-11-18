//! DynamicMessage -> JSON.

use std::fmt::Write as _;

use super::{
    JResult, PrintOptions, err, resolve_any,
    tree::write_str,
    wkt::{self, base64_encode, f32_text, f64_text},
};
use crate::reflect::{Cardinality, DynamicMessage, FieldDescriptor, MapKey, Value};

/// Writes `m`, with the special forms of the well-known types.
pub(crate) fn message(m: &DynamicMessage, o: &PrintOptions, out: &mut String) -> JResult<()> {
    if let Some(w) = special(m, o)? {
        out.push_str(&w);
        return Ok(());
    }
    let name = m.descriptor().full_name().to_owned();
    if name == "google.protobuf.Any" {
        return any(m, o, out);
    }
    out.push('{');
    fields(m, o, out, &mut true)?;
    out.push('}');
    Ok(())
}

fn fields(m: &DynamicMessage, o: &PrintOptions, out: &mut String, first: &mut bool) -> JResult<()> {
    let desc = m.descriptor().clone();
    for fd in desc.fields() {
        let present = m.has(&fd);
        let always = o.always_print_fields_with_no_presence
            && !fd.has_presence()
            && fd.containing_oneof().is_none();
        if !present && !always {
            continue;
        }
        if !*first {
            out.push(',');
        }
        *first = false;
        let name = if o.preserve_proto_field_names {
            fd.name()
        } else {
            fd.json_name()
        };
        write_str(out, name);
        out.push(':');
        field_value(&fd, &m.get(&fd), o, out)?;
    }
    for (fd, v) in m.fields() {
        if !fd.is_extension() {
            continue;
        }
        if !*first {
            out.push(',');
        }
        *first = false;
        write_str(out, &format!("[{}]", fd.full_name()));
        out.push(':');
        field_value(&fd, v, o, out)?;
    }
    Ok(())
}

fn field_value(fd: &FieldDescriptor, v: &Value, o: &PrintOptions, out: &mut String) -> JResult<()> {
    if fd.is_map() {
        let Some((_, vf)) = fd.map_entry_fields() else {
            return err("map without entry fields");
        };
        out.push('{');
        if let Value::Map(m) = v {
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let ks = match k {
                    MapKey::Bool(b) => b.to_string(),
                    MapKey::I32(x) => x.to_string(),
                    MapKey::I64(x) => x.to_string(),
                    MapKey::U32(x) => x.to_string(),
                    MapKey::U64(x) => x.to_string(),
                    MapKey::String(s) => s.clone(),
                };
                write_str(out, &ks);
                out.push(':');
                single(&vf, x, o, out)?;
            }
        }
        out.push('}');
        return Ok(());
    }
    if fd.cardinality() == Cardinality::Repeated {
        out.push('[');
        if let Value::List(l) = v {
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                single(fd, x, o, out)?;
            }
        }
        out.push(']');
        return Ok(());
    }
    single(fd, v, o, out)
}

fn single(fd: &FieldDescriptor, v: &Value, o: &PrintOptions, out: &mut String) -> JResult<()> {
    match v {
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::I32(x) => {
            let _ = write!(out, "{x}");
        }
        Value::U32(x) => {
            let _ = write!(out, "{x}");
        }
        Value::I64(x) => {
            let _ = write!(out, "\"{x}\"");
        }
        Value::U64(x) => {
            let _ = write!(out, "\"{x}\"");
        }
        Value::F32(x) => out.push_str(&f32_text(*x)),
        Value::F64(x) => out.push_str(&f64_text(*x)),
        Value::String(s) => write_str(out, s),
        Value::Bytes(b) => write_str(out, &base64_encode(b)),
        Value::EnumNumber(n) => {
            let e = fd.enum_type();
            if e.as_ref()
                .is_some_and(|e| e.full_name() == "google.protobuf.NullValue")
            {
                out.push_str("null");
            } else {
                match e.as_ref().and_then(|e| e.value_name(*n)) {
                    Some(name) if !o.enums_as_numbers => write_str(out, name),
                    _ => {
                        let _ = write!(out, "{n}");
                    }
                }
            }
        }
        Value::Message(m) => message(m, o, out)?,
        Value::List(_) | Value::Map(_) => return err("nested list value"),
    }
    Ok(())
}

fn int_field(m: &DynamicMessage, name: &str) -> i64 {
    match m.get_by_name(name).as_deref() {
        Some(Value::I64(x)) => *x,
        Some(Value::I32(x)) => i64::from(*x),
        _ => 0,
    }
}

/// The JSON of a well-known type with a special form, `None` for other messages.
fn special(m: &DynamicMessage, o: &PrintOptions) -> JResult<Option<String>> {
    let name = m.descriptor().full_name();
    let Some(t) = name.strip_prefix("google.protobuf.") else {
        return Ok(None);
    };
    let mut out = String::new();
    match t {
        "Timestamp" => {
            let s = wkt::timestamp_text(int_field(m, "seconds"), int_field(m, "nanos") as i32)?;
            write_str(&mut out, &s);
        }
        "Duration" => {
            let s = wkt::duration_text(int_field(m, "seconds"), int_field(m, "nanos") as i32)?;
            write_str(&mut out, &s);
        }
        "FieldMask" => {
            let mut paths = Vec::new();
            if let Some(Value::List(l)) = m.get_by_name("paths").as_deref() {
                for p in l {
                    if let Value::String(p) = p {
                        paths.push(wkt::mask_path_to_json(p)?);
                    }
                }
            }
            write_str(&mut out, &paths.join(","));
        }
        "DoubleValue" | "FloatValue" | "Int64Value" | "UInt64Value" | "Int32Value"
        | "UInt32Value" | "BoolValue" | "StringValue" | "BytesValue" => {
            let fd = m
                .descriptor()
                .get_field(1)
                .ok_or_else(|| super::JsonError::new("wrapper without a value field"))?;
            single(&fd, &m.get(&fd), o, &mut out)?;
        }
        "Struct" => {
            let fd = m
                .descriptor()
                .get_field(1)
                .ok_or_else(|| super::JsonError::new("Struct without fields"))?;
            field_value(&fd, &m.get(&fd), o, &mut out)?;
        }
        "ListValue" => {
            let fd = m
                .descriptor()
                .get_field(1)
                .ok_or_else(|| super::JsonError::new("ListValue without values"))?;
            field_value(&fd, &m.get(&fd), o, &mut out)?;
        }
        "Value" => {
            let Some((fd, v)) = m.fields().next() else {
                return err("google.protobuf.Value has no kind set");
            };
            match (fd.name(), v) {
                ("null_value", _) => out.push_str("null"),
                ("number_value", Value::F64(x)) => {
                    if !x.is_finite() {
                        return err("google.protobuf.Value cannot hold NaN or infinity");
                    }
                    out.push_str(&f64_text(*x));
                }
                _ => single(&fd, v, o, &mut out)?,
            }
        }
        _ => return Ok(None),
    }
    Ok(Some(out))
}

fn any(m: &DynamicMessage, o: &PrintOptions, out: &mut String) -> JResult<()> {
    let url = match m.get_by_name("type_url").as_deref() {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    let value = match m.get_by_name("value").as_deref() {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };
    if url.is_empty() {
        if value.is_empty() {
            out.push_str("{}");
            return Ok(());
        }
        return err("Any with a value but no type URL");
    }
    let desc = resolve_any(&url, m.descriptor().pool(), o.type_pool.as_ref())?;
    let inner = DynamicMessage::decode(desc, &value)
        .map_err(|e| super::JsonError::new(format!("Any value: {e}")))?;
    out.push('{');
    out.push_str("\"@type\":");
    write_str(out, &url);
    if let Some(w) = special(&inner, o)? {
        out.push_str(",\"value\":");
        out.push_str(&w);
    } else if inner.descriptor().full_name() == "google.protobuf.Any" {
        out.push_str(",\"value\":");
        any(&inner, o, out)?;
    } else {
        let mut first = false;
        fields(&inner, o, out, &mut first)?;
    }
    out.push('}');
    Ok(())
}
