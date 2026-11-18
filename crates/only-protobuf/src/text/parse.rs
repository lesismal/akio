//! Text -> DynamicMessage.

use std::collections::HashSet;

use super::{
    ParseOptions, RECURSION_LIMIT, TextError,
    lex::{Lexer, Radix, Tok},
    print::{extension_name, is_group_like},
};
use crate::reflect::{
    Cardinality, DynamicMessage, FieldDescriptor, Kind, MapKey, MessageDescriptor, Value,
};

type R<T> = Result<T, TextError>;

pub(super) fn parse(desc: MessageDescriptor, s: &str, opts: &ParseOptions) -> R<DynamicMessage> {
    let mut p = Parser {
        lex: Lexer::new(s),
        opts,
    };
    let mut m = DynamicMessage::new(desc);
    p.body(&mut m, None, 0)?;
    Ok(m)
}

struct Parser<'a, 'o> {
    lex: Lexer<'a>,
    opts: &'o ParseOptions,
}

/// What one message has been given so far.
#[derive(Default)]
struct Seen {
    /// Singular fields.
    fields: HashSet<u32>,
    /// Oneofs with a member set.
    oneofs: HashSet<String>,
    /// An `Any` was given in expanded form.
    any: bool,
}

/// The field named `name` of `desc`, or the group-like field whose type is named `name`.
fn find_field(desc: &MessageDescriptor, name: &str) -> Option<FieldDescriptor> {
    desc.get_field_by_name(name).or_else(|| {
        desc.get_field_by_name(&name.to_ascii_lowercase())
            .filter(|fd| is_group_like(fd) && fd.message_type().is_some_and(|t| t.name() == name))
    })
}

/// The extension of `desc` named `name` (a MessageSet item also by its type name).
fn find_extension(desc: &MessageDescriptor, name: &str) -> Option<FieldDescriptor> {
    let pool = desc.pool();
    pool.get_extension_by_name(name)
        .filter(|x| x.containing_message() == *desc)
        .or_else(|| {
            if desc.is_message_set() {
                pool.extensions_of(desc)
                    .into_iter()
                    .find(|x| extension_name(x) == name)
            } else {
                None
            }
        })
}

/// Whether `s` is a message name (`pkg.Type`).
pub(super) fn is_type_name(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|p| {
            let mut b = p.bytes();
            b.next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
        })
}

/// Whether `s` is a valid type URL prefix (RFC 3986 path characters, `%XX` escapes).
pub(super) fn is_url_prefix(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            if !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
            continue;
        }
        if !(c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&c)) {
            return false;
        }
        i += 1;
    }
    !s.is_empty()
}

impl<'a> Parser<'a, '_> {
    fn err_at(&self, at: usize, msg: impl Into<String>) -> TextError {
        self.lex.err_at(at, msg)
    }

    /// Fields up to `close` (or the end of the input).
    fn body(&mut self, m: &mut DynamicMessage, close: Option<u8>, depth: usize) -> R<()> {
        let mut seen = Seen::default();
        loop {
            match self.lex.peek()? {
                Tok::Eof => {
                    return match close {
                        None => Ok(()),
                        Some(c) => Err(self.lex.err(format!(
                            "expected '{}' at the end of {}",
                            c as char,
                            m.descriptor().full_name()
                        ))),
                    };
                }
                Tok::Sym(c) if Some(*c) == close => {
                    self.lex.next()?;
                    return Ok(());
                }
                _ => {}
            }
            self.field(m, &mut seen, depth)?;
            if !self.lex.eat(b';')? {
                self.lex.eat(b',')?;
            }
        }
    }

    fn field(&mut self, m: &mut DynamicMessage, seen: &mut Seen, depth: usize) -> R<()> {
        let at = self.lex.mark()?;
        let desc = m.descriptor().clone();
        let fd = match self.lex.next()? {
            Tok::Sym(b'[') => {
                let name = self.lex.bracketed()?;
                if name.contains('/') {
                    return self.any(m, seen, &name, at, depth);
                }
                match find_extension(&desc, &name) {
                    Some(fd) => fd,
                    None if self.opts.allow_unknown_fields => return self.skip_value(depth),
                    None => {
                        return Err(self.err_at(
                            at,
                            format!("{} has no extension [{name}]", desc.full_name()),
                        ));
                    }
                }
            }
            Tok::Ident(name) => match find_field(&desc, name) {
                Some(fd) => fd,
                None => {
                    if self.opts.allow_unknown_fields
                        || desc.proto().reserved_name.iter().any(|r| r == name)
                    {
                        return self.skip_value(depth);
                    }
                    return Err(
                        self.err_at(at, format!("{} has no field {name:?}", desc.full_name()))
                    );
                }
            },
            t => {
                return Err(
                    self.err_at(at, format!("expected a field name, found {}", t.describe()))
                );
            }
        };
        if fd.cardinality() != Cardinality::Repeated
            && (!seen.fields.insert(fd.number()) || (seen.any && fd.number() <= 2))
        {
            return Err(self.err_at(at, format!("field {} given twice", fd.name())));
        }
        if let Some((oneof, false)) = fd.containing_oneof() {
            if !seen.oneofs.insert(oneof.clone()) {
                return Err(self.err_at(
                    at,
                    format!("{} is the second member of oneof {oneof} given", fd.name()),
                ));
            }
        }
        let is_message = matches!(fd.kind(), Kind::Message(_));
        let colon = self.lex.eat(b':')?;
        if !is_message && !colon {
            let found = self.lex.describe()?;
            return Err(self.lex.err(format!(
                "expected ':' after field {}, found {found}",
                fd.name()
            )));
        }
        if self.lex.eat(b'[')? {
            if fd.cardinality() != Cardinality::Repeated {
                return Err(self.err_at(
                    at,
                    format!("field {} is not repeated, a list is not allowed", fd.name()),
                ));
            }
            if self.lex.eat(b']')? {
                return Ok(());
            }
            loop {
                self.element(m, &fd, depth)?;
                if self.lex.eat(b']')? {
                    return Ok(());
                }
                self.lex.expect(b',')?;
            }
        }
        self.element(m, &fd, depth)
    }

    /// One value of `fd`, stored in `m`.
    fn element(&mut self, m: &mut DynamicMessage, fd: &FieldDescriptor, depth: usize) -> R<()> {
        let v = match fd.message_type() {
            Some(t) => Value::Message(self.message(t, depth)?),
            None => self.scalar(fd)?,
        };
        if fd.is_map() {
            let (Some((kf, vf)), Value::Message(entry)) = (fd.map_entry_fields(), v) else {
                return Err(TextError::new("map without entry fields"));
            };
            let Some(key) = MapKey::from_value(entry.get(&kf).into_owned()) else {
                return Err(TextError::new("invalid map key type"));
            };
            let val = entry.get(&vf).into_owned();
            if let Value::Map(map) = m.get_mut(fd) {
                map.insert(key, val);
            }
            return Ok(());
        }
        if fd.cardinality() == Cardinality::Repeated {
            if let Value::List(l) = m.get_mut(fd) {
                l.push(v);
            }
            return Ok(());
        }
        m.set(fd, v).map_err(|e| TextError::new(e.to_string()))
    }

    /// `{ ... }` or `< ... >`.
    fn message(&mut self, desc: MessageDescriptor, depth: usize) -> R<DynamicMessage> {
        if depth >= RECURSION_LIMIT {
            return Err(self.lex.err("messages nested too deeply"));
        }
        let close = if self.lex.eat(b'{')? {
            b'}'
        } else if self.lex.eat(b'<')? {
            b'>'
        } else {
            let found = self.lex.describe()?;
            return Err(self.lex.err(format!(
                "expected '{{' or '<' for {}, found {found}",
                desc.full_name()
            )));
        };
        let mut m = DynamicMessage::new(desc);
        self.body(&mut m, Some(close), depth + 1)?;
        Ok(m)
    }

    /// `[prefix/pkg.Type] { ... }` inside an `Any`.
    fn any(
        &mut self,
        m: &mut DynamicMessage,
        seen: &mut Seen,
        url: &str,
        at: usize,
        depth: usize,
    ) -> R<()> {
        let desc = m.descriptor().clone();
        if desc.full_name() != "google.protobuf.Any" {
            return Err(self.err_at(
                at,
                format!("[{url}]: {} is not google.protobuf.Any", desc.full_name()),
            ));
        }
        let (prefix, name) = url.rsplit_once('/').unwrap_or(("", url));
        if !is_url_prefix(prefix) || !is_type_name(name) {
            return Err(self.err_at(at, format!("invalid type URL {url:?}")));
        }
        if seen.any || seen.fields.contains(&1) || seen.fields.contains(&2) {
            return Err(self.err_at(at, "Any given twice"));
        }
        seen.any = true;
        let inner = desc
            .pool()
            .get_message_by_name(name)
            .or_else(|| self.opts.type_pool.as_ref()?.get_message_by_name(name))
            .ok_or_else(|| self.err_at(at, format!("unknown type {name:?} in Any")))?;
        self.lex.eat(b':')?;
        let v = self.message(inner, depth)?;
        let (Some(tf), Some(vf)) = (desc.get_field(1), desc.get_field(2)) else {
            return Err(TextError::new("google.protobuf.Any without its fields"));
        };
        m.set(&tf, Value::String(url.to_owned()))
            .and_then(|()| m.set(&vf, Value::Bytes(v.encode_to_vec())))
            .map_err(|e| TextError::new(e.to_string()))
    }

    fn scalar(&mut self, fd: &FieldDescriptor) -> R<Value> {
        let at = self.lex.mark()?;
        let neg = self.lex.eat(b'-')?;
        let t = self.lex.next()?;
        let bad = |p: &Self, t: &Tok<'_>| {
            p.err_at(
                at,
                format!(
                    "invalid value for {} field {}: {}{}",
                    kind_name(fd.kind()),
                    fd.name(),
                    if neg { "-" } else { "" },
                    t.describe()
                ),
            )
        };
        let k = fd.kind();
        let v = match (k, t) {
            (Kind::String | Kind::Bytes, Tok::Str(mut b)) if !neg => {
                while let Tok::Str(_) = self.lex.peek()? {
                    if let Tok::Str(more) = self.lex.next()? {
                        b.extend_from_slice(&more);
                    }
                }
                if k == Kind::Bytes {
                    Value::Bytes(b)
                } else {
                    Value::String(String::from_utf8(b).map_err(|_| {
                        self.err_at(at, format!("field {} is not valid UTF-8", fd.name()))
                    })?)
                }
            }
            (Kind::Float | Kind::Double, t) => {
                let x = match &t {
                    Tok::Float(s) | Tok::Int(s, Radix::Dec) => float(s),
                    Tok::Ident(s) => special_float(s),
                    _ => None,
                };
                let Some(x) = x else {
                    return Err(bad(self, &t));
                };
                let x = if neg { -x } else { x };
                if k == Kind::Float {
                    Value::F32(x as f32)
                } else {
                    Value::F64(x)
                }
            }
            (Kind::Bool, Tok::Ident("true" | "True" | "t")) if !neg => Value::Bool(true),
            (Kind::Bool, Tok::Ident("false" | "False" | "f")) if !neg => Value::Bool(false),
            (Kind::Bool, Tok::Int(s, r)) if !neg => match integer(s, r) {
                Some(0) => Value::Bool(false),
                Some(1) => Value::Bool(true),
                _ => return Err(bad(self, &Tok::Int(s, r))),
            },
            (Kind::Enum(_), Tok::Ident(name)) if !neg => {
                match fd.enum_type().and_then(|e| e.value_number(name)) {
                    Some(n) => Value::EnumNumber(n),
                    None => {
                        return Err(self.err_at(
                            at,
                            format!("unknown enum value {name:?} for field {}", fd.name()),
                        ));
                    }
                }
            }
            (Kind::Enum(_), Tok::Int(s, r)) => {
                let n = signed(s, r, neg)
                    .and_then(|v| i32::try_from(v).ok())
                    .ok_or_else(|| bad(self, &Tok::Int(s, r)))?;
                if let Some(e) = fd.enum_type() {
                    if e.is_closed() && e.value_name(n).is_none() {
                        return Err(self.err_at(
                            at,
                            format!("unknown number {n} for closed enum field {}", fd.name()),
                        ));
                    }
                }
                Value::EnumNumber(n)
            }
            (_, Tok::Int(s, r)) => {
                let v = signed(s, r, neg);
                let out = match k {
                    Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => {
                        v.and_then(|v| i32::try_from(v).ok()).map(Value::I32)
                    }
                    Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => {
                        v.and_then(|v| i64::try_from(v).ok()).map(Value::I64)
                    }
                    Kind::Uint32 | Kind::Fixed32 => {
                        v.and_then(|v| u32::try_from(v).ok()).map(Value::U32)
                    }
                    Kind::Uint64 | Kind::Fixed64 => {
                        v.and_then(|v| u64::try_from(v).ok()).map(Value::U64)
                    }
                    _ => None,
                };
                match out {
                    // `-0` is not an unsigned integer.
                    Some(Value::U32(_) | Value::U64(_)) if neg => {
                        return Err(bad(self, &Tok::Int(s, r)));
                    }
                    Some(v) => v,
                    None => return Err(bad(self, &Tok::Int(s, r))),
                }
            }
            (_, t) => return Err(bad(self, &t)),
        };
        Ok(v)
    }

    /// Skips the value of an unknown or reserved field (its name was consumed).
    fn skip_value(&mut self, depth: usize) -> R<()> {
        let colon = self.lex.eat(b':')?;
        if self.lex.eat(b'[')? {
            if self.lex.eat(b']')? {
                return Ok(());
            }
            loop {
                self.skip_element(colon, depth)?;
                if self.lex.eat(b']')? {
                    return Ok(());
                }
                self.lex.expect(b',')?;
            }
        }
        self.skip_element(colon, depth)
    }

    fn skip_element(&mut self, colon: bool, depth: usize) -> R<()> {
        let close = match self.lex.peek()? {
            Tok::Sym(b'{') => b'}',
            Tok::Sym(b'<') => b'>',
            _ => {
                if !colon {
                    let found = self.lex.describe()?;
                    return Err(self.lex.err(format!("expected ':', found {found}")));
                }
                self.lex.eat(b'-')?;
                return match self.lex.next()? {
                    Tok::Int(..) | Tok::Float(_) | Tok::Ident(_) => Ok(()),
                    Tok::Str(_) => {
                        while let Tok::Str(_) = self.lex.peek()? {
                            self.lex.next()?;
                        }
                        Ok(())
                    }
                    t => Err(self
                        .lex
                        .err(format!("expected a value, found {}", t.describe()))),
                };
            }
        };
        if depth >= RECURSION_LIMIT {
            return Err(self.lex.err("messages nested too deeply"));
        }
        self.lex.next()?;
        loop {
            match self.lex.next()? {
                Tok::Sym(c) if c == close => return Ok(()),
                Tok::Sym(b'[') => {
                    self.lex.bracketed()?;
                }
                Tok::Ident(_) | Tok::Int(_, Radix::Dec) => {}
                t => {
                    return Err(self
                        .lex
                        .err(format!("expected a field name, found {}", t.describe())));
                }
            }
            self.skip_value(depth + 1)?;
            if !self.lex.eat(b';')? {
                self.lex.eat(b',')?;
            }
        }
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Double => "double",
        Kind::Float => "float",
        Kind::Int32 => "int32",
        Kind::Int64 => "int64",
        Kind::Uint32 => "uint32",
        Kind::Uint64 => "uint64",
        Kind::Sint32 => "sint32",
        Kind::Sint64 => "sint64",
        Kind::Fixed32 => "fixed32",
        Kind::Fixed64 => "fixed64",
        Kind::Sfixed32 => "sfixed32",
        Kind::Sfixed64 => "sfixed64",
        Kind::Bool => "bool",
        Kind::String => "string",
        Kind::Bytes => "bytes",
        Kind::Message(_) => "message",
        Kind::Enum(_) => "enum",
    }
}

/// An integer literal's value.
fn integer(s: &str, r: Radix) -> Option<u64> {
    let radix = match r {
        Radix::Dec => 10,
        Radix::Oct => 8,
        Radix::Hex => 16,
    };
    u64::from_str_radix(s, radix).ok()
}

fn signed(s: &str, r: Radix, neg: bool) -> Option<i128> {
    let v = i128::from(integer(s, r)?);
    Some(if neg { -v } else { v })
}

/// A float literal (decimal digits, `.`, exponent), saturating to infinity or zero.
fn float(s: &str) -> Option<f64> {
    // Rust does not take `1.e5`: drop the `.`.
    match s.find(".e").or_else(|| s.find(".E")) {
        Some(i) => format!("{}{}", &s[..i], &s[i + 1..]).parse().ok(),
        None => s.parse().ok(),
    }
}

fn special_float(s: &str) -> Option<f64> {
    if s.eq_ignore_ascii_case("inf") || s.eq_ignore_ascii_case("infinity") {
        Some(f64::INFINITY)
    } else if s.eq_ignore_ascii_case("nan") {
        Some(f64::NAN)
    } else {
        None
    }
}
