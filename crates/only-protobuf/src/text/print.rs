//! DynamicMessage -> text.

use std::fmt::Write as _;

use super::{
    PrintOptions, RECURSION_LIMIT,
    parse::{is_type_name, is_url_prefix},
};
use crate::{
    encoding::{Reader, WireType},
    reflect::{Cardinality, DynamicMessage, FieldDescriptor, Kind, Value},
};

/// The part of a full name before its last `.`.
fn scope(full_name: &str) -> &str {
    full_name.rsplit_once('.').map_or("", |(s, _)| s)
}

/// Whether a delimited field is written with its type's name (a proto2 group, or an editions
/// field that looks like one: named as its type in lower case, the type declared next to it).
pub(super) fn is_group_like(fd: &FieldDescriptor) -> bool {
    fd.is_group()
        && fd.message_type().is_some_and(|t| {
            t.name().to_ascii_lowercase() == fd.name()
                && scope(t.full_name()) == scope(fd.full_name())
                && t.file().name() == fd_file(fd)
        })
}

fn fd_file(fd: &FieldDescriptor) -> String {
    if fd.is_extension() {
        fd.pool()
            .file_containing_symbol(fd.full_name())
            .map(|f| f.name().to_owned())
            .unwrap_or_default()
    } else {
        fd.containing_message().file().name().to_owned()
    }
}

/// How an extension is named in brackets: its full name, or for a MessageSet item, its type's.
pub(super) fn extension_name(fd: &FieldDescriptor) -> String {
    if let Some(t) = fd.message_type() {
        if fd.containing_message().is_message_set()
            && fd.cardinality() == Cardinality::Optional
            && scope(fd.full_name()) == t.full_name()
        {
            return t.full_name().to_owned();
        }
    }
    fd.full_name().to_owned()
}

pub(super) fn print(m: &DynamicMessage, opts: &PrintOptions) -> String {
    let mut p = Printer {
        out: String::new(),
        opts,
        indent: 0,
    };
    p.message(m);
    if opts.single_line {
        while p.out.ends_with(' ') {
            p.out.pop();
        }
    }
    p.out
}

struct Printer<'o> {
    out: String,
    opts: &'o PrintOptions,
    indent: usize,
}

impl Printer<'_> {
    fn start(&mut self, name: &str) {
        if !self.opts.single_line {
            for _ in 0..self.indent {
                self.out.push_str("  ");
            }
        }
        self.out.push_str(name);
    }

    fn end_line(&mut self) {
        self.out
            .push(if self.opts.single_line { ' ' } else { '\n' });
    }

    fn open(&mut self, name: &str) {
        self.start(name);
        self.out.push_str(" {");
        self.end_line();
        self.indent += 1;
    }

    fn close(&mut self) {
        self.indent -= 1;
        self.start("}");
        self.end_line();
    }

    fn message(&mut self, m: &DynamicMessage) {
        if m.descriptor().full_name() == "google.protobuf.Any" && self.any(m) {
            return;
        }
        for (fd, v) in m.fields() {
            let name = if fd.is_extension() {
                format!("[{}]", extension_name(&fd))
            } else if is_group_like(&fd) {
                fd.message_type()
                    .map_or_else(|| fd.name().to_owned(), |t| t.name().to_owned())
            } else {
                fd.name().to_owned()
            };
            match v {
                Value::Map(map) => {
                    let Some((kf, vf)) = fd.map_entry_fields() else {
                        continue;
                    };
                    for (k, x) in map {
                        self.open(&name);
                        self.value_field("key", &kf, &k.to_value());
                        self.value_field("value", &vf, x);
                        self.close();
                    }
                }
                Value::List(l) => {
                    for x in l {
                        self.value_field(&name, &fd, x);
                    }
                }
                v => self.value_field(&name, &fd, v),
            }
        }
        if self.opts.print_unknown_fields {
            self.unknown(m.unknown_fields().as_bytes(), 0);
        }
    }

    fn value_field(&mut self, name: &str, fd: &FieldDescriptor, v: &Value) {
        if let Value::Message(m) = v {
            self.open(name);
            self.message(m);
            self.close();
            return;
        }
        self.start(name);
        self.out.push_str(": ");
        self.scalar(fd, v);
        self.end_line();
    }

    fn scalar(&mut self, fd: &FieldDescriptor, v: &Value) {
        let o = &mut self.out;
        let _ = match v {
            Value::Bool(b) => write!(o, "{b}"),
            Value::I32(x) => write!(o, "{x}"),
            Value::I64(x) => write!(o, "{x}"),
            Value::U32(x) => write!(o, "{x}"),
            Value::U64(x) => write!(o, "{x}"),
            Value::F32(x) => {
                write_float(o, f64::from(*x), x.is_nan(), &format!("{x:?}"));
                Ok(())
            }
            Value::F64(x) => {
                write_float(o, *x, x.is_nan(), &format!("{x:?}"));
                Ok(())
            }
            Value::String(s) => {
                write_bytes(o, s.as_bytes(), true);
                Ok(())
            }
            Value::Bytes(b) => {
                write_bytes(o, b, fd.kind() == Kind::String);
                Ok(())
            }
            Value::EnumNumber(n) => match fd.enum_type().as_ref().and_then(|e| e.value_name(*n)) {
                Some(name) => write!(o, "{name}"),
                None => write!(o, "{n}"),
            },
            Value::Message(_) | Value::List(_) | Value::Map(_) => Ok(()),
        };
    }

    /// An `Any` whose type is known, expanded (as `[type URL] { ... }`); false (nothing written)
    /// otherwise.
    fn any(&mut self, m: &DynamicMessage) -> bool {
        let (url, value) = (m.get_by_name("type_url"), m.get_by_name("value"));
        let (Some(Value::String(url)), Some(Value::Bytes(value))) =
            (url.as_deref(), value.as_deref())
        else {
            return false;
        };
        // Only a URL that reads back the same.
        let Some((prefix, name)) = url.rsplit_once('/') else {
            return false;
        };
        if !is_url_prefix(prefix) || !is_type_name(name) {
            return false;
        }
        let Some(desc) = m
            .descriptor()
            .pool()
            .get_message_by_name(name)
            .or_else(|| self.opts.type_pool.as_ref()?.get_message_by_name(name))
        else {
            return false;
        };
        // Expanding would drop unknown fields (unless they are printed).
        let Ok(inner) = DynamicMessage::decode(desc, value) else {
            return false;
        };
        if !self.opts.print_unknown_fields && has_unknown(&inner, 0) {
            return false;
        }
        self.open(&format!("[{url}]"));
        self.message(&inner);
        self.close();
        if self.opts.print_unknown_fields {
            self.unknown(m.unknown_fields().as_bytes(), 0);
        }
        true
    }

    /// Unknown fields by number, as protoc prints them.
    fn unknown(&mut self, raw: &[u8], depth: usize) {
        let mut r = Reader::new(raw);
        while !r.is_empty() {
            let Ok((n, wt)) = r.read_tag() else {
                return;
            };
            let num = n.to_string();
            match wt {
                WireType::Varint => {
                    let Ok(v) = r.read_varint() else { return };
                    self.start(&num);
                    let _ = write!(self.out, ": {v}");
                    self.end_line();
                }
                WireType::Fixed32 => {
                    let Ok(v) = r.read_fixed32() else { return };
                    self.start(&num);
                    let _ = write!(self.out, ": 0x{v:08x}");
                    self.end_line();
                }
                WireType::Fixed64 => {
                    let Ok(v) = r.read_fixed64() else { return };
                    self.start(&num);
                    let _ = write!(self.out, ": 0x{v:016x}");
                    self.end_line();
                }
                WireType::Len => {
                    let Ok(b) = r.read_bytes() else { return };
                    if !b.is_empty() && depth < RECURSION_LIMIT && is_field_set(b) {
                        self.open(&num);
                        self.unknown(b, depth + 1);
                        self.close();
                    } else {
                        self.start(&num);
                        self.out.push_str(": ");
                        write_bytes(&mut self.out, b, false);
                        self.end_line();
                    }
                }
                WireType::StartGroup => {
                    let Ok(all) = r.skip_field(n, wt) else { return };
                    // `all` ends with the end-group tag.
                    let mut tag = Vec::new();
                    crate::encoding::put_tag(&mut tag, n, WireType::EndGroup);
                    let body = &all[..all.len().saturating_sub(tag.len())];
                    self.open(&num);
                    if depth < RECURSION_LIMIT {
                        self.unknown(body, depth + 1);
                    }
                    self.close();
                }
                WireType::EndGroup => return,
            }
        }
    }
}

/// Whether `m` or a message in it has unknown fields.
fn has_unknown(m: &DynamicMessage, depth: usize) -> bool {
    fn value(v: &Value, depth: usize) -> bool {
        match v {
            Value::Message(m) => has_unknown(m, depth + 1),
            Value::List(l) => l.iter().any(|x| value(x, depth)),
            Value::Map(m) => m.values().any(|x| value(x, depth)),
            _ => false,
        }
    }
    depth > RECURSION_LIMIT
        || !m.unknown_fields().is_empty()
        || m.fields().any(|(_, v)| value(v, depth))
}

/// Whether `b` parses as a whole as protobuf fields.
fn is_field_set(b: &[u8]) -> bool {
    let mut r = Reader::new(b);
    while !r.is_empty() {
        match r.read_tag() {
            Ok((n, w)) if w != WireType::EndGroup => {
                if r.skip_field(n, w).is_err() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// A float: `inf`, `-inf`, `nan`, or the shortest text that reads back the same (`debug` is
/// Rust's `{:?}` of it), without a trailing `.0`.
fn write_float(o: &mut String, x: f64, nan: bool, debug: &str) {
    if nan {
        o.push_str("nan");
    } else if x.is_infinite() {
        o.push_str(if x > 0.0 { "inf" } else { "-inf" });
    } else {
        o.push_str(debug.strip_suffix(".0").unwrap_or(debug));
    }
}

/// A double-quoted string; bytes that are not printable ASCII as octal escapes (UTF-8
/// sequences kept as they are when `utf8`).
fn write_bytes(o: &mut String, b: &[u8], utf8: bool) {
    o.push('"');
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => o.push_str("\\n"),
            b'\r' => o.push_str("\\r"),
            b'\t' => o.push_str("\\t"),
            b'"' => o.push_str("\\\""),
            b'\'' => o.push_str("\\'"),
            b'\\' => o.push_str("\\\\"),
            0x20..=0x7e => o.push(c as char),
            0x80.. if utf8 => {
                // Keep a whole UTF-8 sequence.
                let n = match c {
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf7 => 4,
                    _ => 1,
                };
                if let Some(s) = b.get(i..i + n).and_then(|s| std::str::from_utf8(s).ok()) {
                    o.push_str(s);
                    i += n;
                    continue;
                }
                let _ = write!(o, "\\{c:03o}");
            }
            _ => {
                let _ = write!(o, "\\{c:03o}");
            }
        }
        i += 1;
    }
    o.push('"');
}
