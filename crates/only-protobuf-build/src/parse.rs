//! A `.proto` parser: proto2, proto3 and editions (2023, 2024) files: messages, nested types,
//! enums, fields with every label, groups, `map<K, V>`, `oneof`, `extend` blocks, extension
//! ranges, `reserved`, options (with text-format aggregate values), services.

use std::{collections::HashMap, fmt::Write as _};

/// The edition of a file; proto2 and proto3 are the legacy ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Edition {
    Proto2,
    Proto3,
    E2023,
    E2024,
}

impl Edition {
    /// The `google.protobuf.Edition` number.
    pub(crate) fn number(self) -> i32 {
        match self {
            Edition::Proto2 => 998,
            Edition::Proto3 => 999,
            Edition::E2023 => 1000,
            Edition::E2024 => 1001,
        }
    }

    /// An editions file (not `syntax = "proto2"` / `"proto3"`).
    pub(crate) fn is_editions(self) -> bool {
        self >= Edition::E2023
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scalar {
    Double,
    Float,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Bool,
    String,
    Bytes,
}

impl Scalar {
    fn from_name(s: &str) -> Option<Scalar> {
        Some(match s {
            "double" => Scalar::Double,
            "float" => Scalar::Float,
            "int32" => Scalar::Int32,
            "int64" => Scalar::Int64,
            "uint32" => Scalar::Uint32,
            "uint64" => Scalar::Uint64,
            "sint32" => Scalar::Sint32,
            "sint64" => Scalar::Sint64,
            "fixed32" => Scalar::Fixed32,
            "fixed64" => Scalar::Fixed64,
            "sfixed32" => Scalar::Sfixed32,
            "sfixed64" => Scalar::Sfixed64,
            "bool" => Scalar::Bool,
            "string" => Scalar::String,
            "bytes" => Scalar::Bytes,
            _ => return None,
        })
    }

    /// Valid as a map key (integral types, bool, string).
    pub(crate) fn is_map_key(self) -> bool {
        !matches!(self, Scalar::Double | Scalar::Float | Scalar::Bytes)
    }

    /// Length-delimited on the wire (cannot be packed).
    pub(crate) fn is_len(self) -> bool {
        matches!(self, Scalar::String | Scalar::Bytes)
    }

    /// The `FieldDescriptorProto.Type` number.
    pub(crate) fn type_number(self) -> i32 {
        match self {
            Scalar::Double => 1,
            Scalar::Float => 2,
            Scalar::Int64 => 3,
            Scalar::Uint64 => 4,
            Scalar::Int32 => 5,
            Scalar::Fixed64 => 6,
            Scalar::Fixed32 => 7,
            Scalar::Bool => 8,
            Scalar::String => 9,
            Scalar::Bytes => 12,
            Scalar::Uint32 => 13,
            Scalar::Sfixed32 => 15,
            Scalar::Sfixed64 => 16,
            Scalar::Sint32 => 17,
            Scalar::Sint64 => 18,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TypeRef {
    Scalar(Scalar),
    /// As written; replaced by `Message` / `Enum` (fully qualified, leading dot) on resolution.
    Named(String),
    Message(String),
    Enum(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Label {
    /// No label: proto3 implicit presence, or presence from the features in editions.
    Implicit,
    Optional,
    Required,
    Repeated,
}

/// A value in an option or a text-format aggregate.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Constant {
    Ident(String),
    /// Integer text with its sign (decimal, `0x` hex or `0` octal).
    Int(String),
    Float(String),
    Str(Vec<u8>),
    /// `{ name: value ... }` (text format).
    Aggregate(Vec<(String, Constant)>),
    /// `[a, b]` inside an aggregate.
    List(Vec<Constant>),
}

/// `name = value` (`name` as written: `java_package`, `(my.ext).sub`, `features.enum_type`).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OptionDef {
    pub(crate) name: String,
    pub(crate) value: Constant,
}

/// Option lookup helpers.
pub(crate) trait Options {
    fn get_opt(&self, name: &str) -> Option<&Constant>;
    fn flag(&self, name: &str) -> Option<bool> {
        match self.get_opt(name) {
            Some(Constant::Ident(b)) => Some(b == "true"),
            _ => None,
        }
    }
}

impl Options for [OptionDef] {
    fn get_opt(&self, name: &str) -> Option<&Constant> {
        self.iter().rev().find(|o| o.name == name).map(|o| &o.value)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) number: u32,
    pub(crate) label: Label,
    pub(crate) ty: TypeRef,
    /// `map<key, ty>`.
    pub(crate) map_key: Option<Scalar>,
    pub(crate) oneof: Option<usize>,
    pub(crate) packed: Option<bool>,
    pub(crate) default: Option<Constant>,
    pub(crate) json_name: Option<String>,
    /// A proto2 `group` (its type is the nested message of the same name).
    pub(crate) group: bool,
    /// For an extension: the message it extends.
    pub(crate) extendee: Option<TypeRef>,
    pub(crate) options: Vec<OptionDef>,
    pub(crate) line: usize,
    /// Filled by feature resolution.
    pub(crate) resolved: Resolved,
}

/// What the features (or the legacy syntax rules) make of a field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) presence: Presence,
    /// Repeated scalars: written packed.
    pub(crate) packed: bool,
    /// Message fields: encoded as a group.
    pub(crate) delimited: bool,
    /// String fields: UTF-8 is checked (always done in Rust; recorded for reflection).
    pub(crate) verify_utf8: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Presence {
    #[default]
    Implicit,
    Explicit,
    Required,
}

#[derive(Clone, Debug)]
pub(crate) struct Oneof {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) options: Vec<OptionDef>,
    /// The synthetic oneof of a proto3 `optional` field.
    pub(crate) synthetic: bool,
}

/// An extension range or a reserved range: `start ..= end`.
#[derive(Clone, Debug)]
pub(crate) struct Range {
    pub(crate) start: u32,
    pub(crate) end: u32,
    pub(crate) options: Vec<OptionDef>,
}

#[derive(Clone, Debug)]
pub(crate) struct MessageDef {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) fields: Vec<Field>,
    pub(crate) oneofs: Vec<Oneof>,
    pub(crate) messages: Vec<MessageDef>,
    pub(crate) enums: Vec<EnumDef>,
    /// Fields of the `extend` blocks inside this message.
    pub(crate) extensions: Vec<Field>,
    pub(crate) extension_ranges: Vec<Range>,
    pub(crate) reserved_ranges: Vec<Range>,
    pub(crate) reserved_names: Vec<String>,
    pub(crate) options: Vec<OptionDef>,
    /// 2024 `export` / `local`.
    pub(crate) visibility: Option<bool>,
}

#[derive(Clone, Debug)]
pub(crate) struct EnumValue {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) number: i32,
    pub(crate) options: Vec<OptionDef>,
}

#[derive(Clone, Debug)]
pub(crate) struct EnumDef {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) values: Vec<EnumValue>,
    pub(crate) reserved_ranges: Vec<(i32, i32)>,
    pub(crate) reserved_names: Vec<String>,
    pub(crate) options: Vec<OptionDef>,
    pub(crate) visibility: Option<bool>,
    /// Filled by feature resolution: unknown numbers are kept as unknown fields, not stored.
    pub(crate) closed: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Method {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) input: TypeRef,
    pub(crate) output: TypeRef,
    pub(crate) client_streaming: bool,
    pub(crate) server_streaming: bool,
    pub(crate) options: Vec<OptionDef>,
}

#[derive(Clone, Debug)]
pub(crate) struct Service {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) methods: Vec<Method>,
    pub(crate) options: Vec<OptionDef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportKind {
    Plain,
    Public,
    Weak,
    /// 2024 `import option`: for options only, not a dependency.
    Option,
}

#[derive(Clone, Debug)]
pub(crate) struct File {
    /// The import name (`dir/x.proto`).
    pub(crate) name: String,
    pub(crate) edition: Edition,
    pub(crate) package: String,
    pub(crate) imports: Vec<String>,
    pub(crate) import_kinds: Vec<ImportKind>,
    pub(crate) messages: Vec<MessageDef>,
    pub(crate) enums: Vec<EnumDef>,
    pub(crate) services: Vec<Service>,
    /// Fields of the top-level `extend` blocks.
    pub(crate) extensions: Vec<Field>,
    pub(crate) options: Vec<OptionDef>,
}

// ---- lexer -----------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Int(String),
    Float(String),
    Str(Vec<u8>),
    Sym(char),
}

#[derive(Clone, Debug)]
struct Token {
    tok: Tok,
    line: usize,
    /// The comment block right before this token (no blank line in between).
    doc: String,
}

fn lex(src: &str, file: &str) -> Result<Vec<Token>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut line = 1;
    let mut out: Vec<Token> = Vec::new();
    let mut doc = String::new();
    let mut doc_end = 0usize; // line the pending comment ended on
    let mut last_tok_line = 0usize;
    let fail = |line: usize, m: &str| format!("{file}:{line}: {m}");
    while i < b.len() {
        let c = b[i];
        match c {
            b'\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_ascii_whitespace() => i += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let start = i + 2;
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                let text = &src[start..i];
                if line == last_tok_line {
                    continue; // a trailing comment
                }
                if !doc.is_empty() && doc_end + 1 < line {
                    doc.clear();
                }
                let text = text.strip_prefix('/').unwrap_or(text); // `///`
                doc.push_str(text.strip_prefix(' ').unwrap_or(text));
                doc.push('\n');
                doc_end = line;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let start_line = line;
                let start = i + 2;
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    if b[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
                if i + 1 >= b.len() {
                    return Err(fail(start_line, "unterminated comment"));
                }
                let text = &src[start..i];
                i += 2;
                if start_line == last_tok_line {
                    continue;
                }
                doc.clear();
                for l in text.lines() {
                    let l = l.trim();
                    let l = l.strip_prefix('*').unwrap_or(l);
                    doc.push_str(l.strip_prefix(' ').unwrap_or(l));
                    doc.push('\n');
                }
                doc_end = line;
            }
            _ => {
                let tok_line = line;
                let tok = if c.is_ascii_alphabetic() || c == b'_' {
                    let s = i;
                    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                        i += 1;
                    }
                    Tok::Ident(src[s..i].to_owned())
                } else if c.is_ascii_digit()
                    || (c == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit))
                {
                    let s = i;
                    let mut float = false;
                    if c == b'0' && matches!(b.get(i + 1), Some(b'x' | b'X')) {
                        i += 2;
                        while i < b.len() && b[i].is_ascii_hexdigit() {
                            i += 1;
                        }
                    } else {
                        while i < b.len() {
                            let d = b[i];
                            if d.is_ascii_digit() {
                                i += 1;
                            } else if d == b'.' {
                                float = true;
                                i += 1;
                            } else if d == b'e' || d == b'E' {
                                float = true;
                                i += 1;
                                if matches!(b.get(i), Some(b'+' | b'-')) {
                                    i += 1;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    if i < b.len() && (b[i].is_ascii_alphabetic() || b[i] == b'_') {
                        return Err(fail(line, "invalid number"));
                    }
                    let t = src[s..i].to_owned();
                    if float { Tok::Float(t) } else { Tok::Int(t) }
                } else if c == b'"' || c == b'\'' {
                    let (s, n) = lex_string(&b[i..]).map_err(|m| fail(line, &m))?;
                    i += n;
                    Tok::Str(s)
                } else if b"{}[]()<>;=,.:-+/".contains(&c) {
                    i += 1;
                    Tok::Sym(c as char)
                } else {
                    return Err(fail(line, &format!("unexpected character {:?}", c as char)));
                };
                let d = if !doc.is_empty() && doc_end + 1 >= tok_line {
                    std::mem::take(&mut doc)
                } else {
                    doc.clear();
                    String::new()
                };
                out.push(Token {
                    tok,
                    line: tok_line,
                    doc: d,
                });
                last_tok_line = line;
            }
        }
    }
    Ok(out)
}

/// A quoted string starting at `b[0]`; returns the bytes and the length consumed.
fn lex_string(b: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let q = b[0];
    let mut out = Vec::new();
    let mut i = 1;
    loop {
        let Some(&c) = b.get(i) else {
            return Err("unterminated string".into());
        };
        i += 1;
        match c {
            b'\n' => return Err("newline in string".into()),
            c if c == q => return Ok((out, i)),
            b'\\' => {
                let Some(&e) = b.get(i) else {
                    return Err("unterminated string".into());
                };
                i += 1;
                match e {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'a' => out.push(7),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'v' => out.push(11),
                    b'\\' | b'\'' | b'"' | b'?' => out.push(e),
                    b'x' | b'X' => {
                        let mut v = 0u32;
                        let mut n = 0;
                        while n < 2 && b.get(i).is_some_and(u8::is_ascii_hexdigit) {
                            v = v * 16 + (b[i] as char).to_digit(16).unwrap_or(0);
                            i += 1;
                            n += 1;
                        }
                        if n == 0 {
                            return Err("bad \\x escape".into());
                        }
                        out.push(v as u8);
                    }
                    b'0'..=b'7' => {
                        let mut v = u32::from(e - b'0');
                        let mut n = 1;
                        while n < 3 && b.get(i).is_some_and(|d| (b'0'..=b'7').contains(d)) {
                            v = v * 8 + u32::from(b[i] - b'0');
                            i += 1;
                            n += 1;
                        }
                        out.push(v as u8);
                    }
                    b'u' | b'U' => {
                        let n = if e == b'u' { 4 } else { 8 };
                        let hex = b.get(i..i + n).ok_or("bad unicode escape")?;
                        let s = std::str::from_utf8(hex).map_err(|_| "bad unicode escape")?;
                        let v = u32::from_str_radix(s, 16).map_err(|_| "bad unicode escape")?;
                        let ch = char::from_u32(v).ok_or("bad unicode escape")?;
                        i += n;
                        let mut tmp = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                    }
                    _ => return Err(format!("unknown escape \\{}", e as char)),
                }
            }
            c => out.push(c),
        }
    }
}

// ---- parser ----------------------------------------------------------------------------------

struct Parser<'a> {
    toks: Vec<Token>,
    pos: usize,
    file: &'a str,
    edition: Edition,
}

type PResult<T> = Result<T, String>;

const MAX_FIELD: i64 = (1 << 29) - 1;

impl Parser<'_> {
    fn err<T>(&self, m: impl std::fmt::Display) -> PResult<T> {
        let line = self
            .toks
            .get(self.pos)
            .or_else(|| self.toks.last())
            .map_or(0, |t| t.line);
        Err(format!("{}:{line}: {m}", self.file))
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.tok)
    }

    fn peek_at(&self, n: usize) -> Option<&Tok> {
        self.toks.get(self.pos + n).map(|t| &t.tok)
    }

    fn line(&self) -> usize {
        self.toks.get(self.pos).map_or(0, |t| t.line)
    }

    fn doc(&self) -> String {
        self.toks
            .get(self.pos)
            .map(|t| t.doc.clone())
            .unwrap_or_default()
    }

    fn next(&mut self) -> PResult<Tok> {
        match self.toks.get(self.pos) {
            Some(t) => {
                self.pos += 1;
                Ok(t.tok.clone())
            }
            None => self.err("unexpected end of file"),
        }
    }

    fn is_sym(&self, c: char) -> bool {
        self.peek() == Some(&Tok::Sym(c))
    }

    fn eat_sym(&mut self, c: char) -> bool {
        if self.is_sym(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_sym(&mut self, c: char) -> PResult<()> {
        if self.eat_sym(c) {
            Ok(())
        } else {
            let got = self.peek().cloned();
            self.err(format!("expected `{c}`, found {}", describe(got.as_ref())))
        }
    }

    fn is_ident(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(i)) if i == s)
    }

    fn eat_ident(&mut self, s: &str) -> bool {
        if self.is_ident(s) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn ident(&mut self) -> PResult<String> {
        match self.peek().cloned() {
            Some(Tok::Ident(s)) => {
                self.pos += 1;
                Ok(s)
            }
            got => self.err(format!(
                "expected an identifier, found {}",
                describe(got.as_ref())
            )),
        }
    }

    /// `a.b.c`, or `.a.b` (absolute) when `allow_dot`.
    fn full_ident(&mut self, allow_dot: bool) -> PResult<String> {
        let mut s = String::new();
        if allow_dot && self.eat_sym('.') {
            s.push('.');
        }
        s.push_str(&self.ident()?);
        while self.is_sym('.') {
            self.pos += 1;
            s.push('.');
            s.push_str(&self.ident()?);
        }
        Ok(s)
    }

    fn string(&mut self) -> PResult<Vec<u8>> {
        let mut out = match self.next()? {
            Tok::Str(s) => s,
            t => return self.err(format!("expected a string, found {}", describe(Some(&t)))),
        };
        // Adjacent literals concatenate.
        while let Some(Tok::Str(s)) = self.peek() {
            out.extend_from_slice(s);
            self.pos += 1;
        }
        Ok(out)
    }

    fn int(&mut self) -> PResult<i64> {
        let neg = self.eat_sym('-');
        match self.next()? {
            Tok::Int(s) => match parse_int(&s) {
                Some(v) => {
                    let v = i128::from(v);
                    let v = if neg { -v } else { v };
                    i64::try_from(v).or_else(|_| self.err("integer out of range"))
                }
                None => self.err("integer out of range"),
            },
            t => self.err(format!("expected an integer, found {}", describe(Some(&t)))),
        }
    }

    fn constant(&mut self) -> PResult<Constant> {
        if self.is_sym('{') || self.is_sym('<') {
            return self.aggregate();
        }
        let sign = if self.eat_sym('-') {
            "-"
        } else {
            self.eat_sym('+');
            ""
        };
        Ok(match self.next()? {
            Tok::Int(s) => Constant::Int(format!("{sign}{s}")),
            Tok::Float(s) => Constant::Float(format!("{sign}{s}")),
            Tok::Ident(s) if s == "inf" || s == "nan" || s == "infinity" => {
                Constant::Float(format!("{sign}{s}"))
            }
            Tok::Ident(s) if sign.is_empty() => {
                let mut s = s;
                while self.is_sym('.') {
                    self.pos += 1;
                    s.push('.');
                    s.push_str(&self.ident()?);
                }
                Constant::Ident(s)
            }
            Tok::Str(mut s) => {
                while let Some(Tok::Str(more)) = self.peek() {
                    s.extend_from_slice(more);
                    self.pos += 1;
                }
                Constant::Str(s)
            }
            t => return self.err(format!("expected a constant, found {}", describe(Some(&t)))),
        })
    }

    /// A text-format message: `{ a: 1 b { c: "x" } d: [1, 2] [ext.name]: 3 }` (or `< ... >`).
    fn aggregate(&mut self) -> PResult<Constant> {
        let close = if self.eat_sym('{') {
            '}'
        } else {
            self.expect_sym('<')?;
            '>'
        };
        let mut fields = Vec::new();
        while !self.eat_sym(close) {
            if self.eat_sym(',') || self.eat_sym(';') {
                continue;
            }
            let name = if self.eat_sym('[') {
                let mut n = String::from("[");
                // `[pkg.ext]` or `[type.googleapis.com/pkg.Msg]`.
                while !self.eat_sym(']') {
                    match self.next()? {
                        Tok::Ident(s) => n.push_str(&s),
                        Tok::Sym(c @ ('.' | '/')) => n.push(c),
                        t => return self.err(format!("unexpected {}", describe(Some(&t)))),
                    }
                }
                n.push(']');
                n
            } else {
                self.ident()?
            };
            let colon = self.eat_sym(':');
            let v = if self.is_sym('[') {
                self.pos += 1;
                let mut items = Vec::new();
                while !self.eat_sym(']') {
                    if self.eat_sym(',') {
                        continue;
                    }
                    items.push(self.constant()?);
                }
                Constant::List(items)
            } else if !colon && !(self.is_sym('{') || self.is_sym('<')) {
                return self.err("expected `:` in an aggregate value");
            } else {
                self.constant()?
            };
            fields.push((name, v));
        }
        Ok(Constant::Aggregate(fields))
    }

    /// `name` or `(ext.name).sub` in an option.
    fn option_name(&mut self) -> PResult<String> {
        let mut s = String::new();
        loop {
            if self.eat_sym('(') {
                s.push('(');
                s.push_str(&self.full_ident(true)?);
                self.expect_sym(')')?;
                s.push(')');
            } else {
                s.push_str(&self.ident()?);
            }
            if !self.eat_sym('.') {
                return Ok(s);
            }
            s.push('.');
        }
    }

    /// `option name = value;` (the keyword already consumed).
    fn option_statement(&mut self) -> PResult<OptionDef> {
        let name = self.option_name()?;
        self.expect_sym('=')?;
        let value = self.constant()?;
        self.expect_sym(';')?;
        Ok(OptionDef { name, value })
    }

    /// `[a = 1, b = 2]`.
    fn field_options(&mut self) -> PResult<Vec<OptionDef>> {
        let mut out = Vec::new();
        if !self.eat_sym('[') {
            return Ok(out);
        }
        loop {
            let name = self.option_name()?;
            self.expect_sym('=')?;
            out.push(OptionDef {
                name,
                value: self.constant()?,
            });
            if self.eat_sym(']') {
                return Ok(out);
            }
            self.expect_sym(',')?;
        }
    }

    /// `1, 2 to 5, 9 to max` (`max` is `max`); the keyword already consumed.
    fn ranges(&mut self, max: i64) -> PResult<Vec<(i64, i64)>> {
        let mut out = Vec::new();
        loop {
            let a = self.int()?;
            let b = if self.eat_ident("to") {
                if self.eat_ident("max") {
                    max
                } else {
                    self.int()?
                }
            } else {
                a
            };
            if b < a {
                return self.err(format!("range {a} to {b} is empty"));
            }
            out.push((a, b));
            if !self.eat_sym(',') {
                return Ok(out);
            }
        }
    }

    /// `reserved` (keyword consumed): ranges, or names (strings, identifiers in editions).
    fn reserved(&mut self, max: i64) -> PResult<(Vec<(i64, i64)>, Vec<String>)> {
        let mut names = Vec::new();
        if matches!(self.peek(), Some(Tok::Str(_) | Tok::Ident(_))) {
            loop {
                match self.next()? {
                    Tok::Str(s) => {
                        if self.edition.is_editions() {
                            return self.err("reserved names are identifiers in editions");
                        }
                        names.push(String::from_utf8_lossy(&s).into_owned());
                    }
                    Tok::Ident(s) => {
                        if !self.edition.is_editions() {
                            return self.err("reserved names are strings before editions");
                        }
                        names.push(s);
                    }
                    t => return self.err(format!("unexpected {}", describe(Some(&t)))),
                }
                if !self.eat_sym(',') {
                    break;
                }
            }
            self.expect_sym(';')?;
            return Ok((Vec::new(), names));
        }
        let r = self.ranges(max)?;
        self.expect_sym(';')?;
        Ok((r, names))
    }

    fn file(&mut self, name: &str) -> PResult<File> {
        let mut f = File {
            name: name.to_owned(),
            edition: Edition::Proto2,
            package: String::new(),
            imports: Vec::new(),
            import_kinds: Vec::new(),
            messages: Vec::new(),
            enums: Vec::new(),
            services: Vec::new(),
            extensions: Vec::new(),
            options: Vec::new(),
        };
        if self.eat_ident("edition") {
            self.expect_sym('=')?;
            let s = self.string()?;
            f.edition = match s.as_slice() {
                b"2023" => Edition::E2023,
                b"2024" => Edition::E2024,
                _ => {
                    return self.err(format!(
                        "edition {:?} is not supported (2023 and 2024 are)",
                        String::from_utf8_lossy(&s)
                    ));
                }
            };
            self.expect_sym(';')?;
        } else if self.eat_ident("syntax") {
            self.expect_sym('=')?;
            let s = self.string()?;
            f.edition = match s.as_slice() {
                b"proto3" => Edition::Proto3,
                b"proto2" => Edition::Proto2,
                _ => return self.err(format!("unknown syntax {:?}", String::from_utf8_lossy(&s))),
            };
            self.expect_sym(';')?;
        }
        self.edition = f.edition;
        while self.peek().is_some() {
            if self.eat_sym(';') {
                continue;
            }
            let kw = self.ident()?;
            match kw.as_str() {
                "package" => {
                    if !f.package.is_empty() {
                        return self.err("more than one package statement");
                    }
                    f.package = self.full_ident(false)?;
                    self.expect_sym(';')?;
                }
                "import" => {
                    let kind = if self.eat_ident("public") {
                        ImportKind::Public
                    } else if self.eat_ident("weak") {
                        ImportKind::Weak
                    } else if self.edition >= Edition::E2024
                        && self.is_ident("option")
                        && matches!(self.peek_at(1), Some(Tok::Str(_)))
                    {
                        self.pos += 1;
                        ImportKind::Option
                    } else {
                        ImportKind::Plain
                    };
                    let s = self.string()?;
                    self.expect_sym(';')?;
                    f.imports.push(
                        String::from_utf8(s).or_else(|_| self.err("import path is not UTF-8"))?,
                    );
                    f.import_kinds.push(kind);
                }
                "option" => f.options.push(self.option_statement()?),
                "message" => f.messages.push(self.message(None)?),
                "enum" => f.enums.push(self.enumeration(None)?),
                "export" | "local" if self.edition >= Edition::E2024 => {
                    let vis = Some(kw == "export");
                    if self.eat_ident("message") {
                        f.messages.push(self.message(vis)?);
                    } else if self.eat_ident("enum") {
                        f.enums.push(self.enumeration(vis)?);
                    } else {
                        return self.err(format!("expected `message` or `enum` after `{kw}`"));
                    }
                }
                "service" => f.services.push(self.service()?),
                "extend" => {
                    let (fields, groups) = self.extend()?;
                    f.extensions.extend(fields);
                    f.messages.extend(groups);
                }
                _ => return self.err(format!("unexpected `{kw}`")),
            }
        }
        Ok(f)
    }

    /// `extend Type { fields }` (keyword consumed): the fields, and the messages of their groups
    /// (declared in the enclosing scope).
    fn extend(&mut self) -> PResult<(Vec<Field>, Vec<MessageDef>)> {
        let extendee = TypeRef::Named(self.full_ident(true)?);
        self.expect_sym('{')?;
        let mut fields = Vec::new();
        let mut groups = Vec::new();
        while !self.eat_sym('}') {
            if self.eat_sym(';') {
                continue;
            }
            let (mut fl, g) = self.field(None)?;
            if fl.map_key.is_some() {
                return self.err("extensions cannot be maps");
            }
            if fl.label == Label::Required {
                return self.err("extensions cannot be required");
            }
            fl.extendee = Some(extendee.clone());
            fields.push(fl);
            groups.extend(g);
        }
        Ok((fields, groups))
    }

    fn message(&mut self, visibility: Option<bool>) -> PResult<MessageDef> {
        let doc = self.toks[self.pos.saturating_sub(1)].doc.clone();
        let name = self.ident()?;
        self.expect_sym('{')?;
        self.message_body(name, doc, visibility)
    }

    fn message_body(
        &mut self,
        name: String,
        doc: String,
        visibility: Option<bool>,
    ) -> PResult<MessageDef> {
        let mut m = MessageDef {
            name,
            doc,
            fields: Vec::new(),
            oneofs: Vec::new(),
            messages: Vec::new(),
            enums: Vec::new(),
            extensions: Vec::new(),
            extension_ranges: Vec::new(),
            reserved_ranges: Vec::new(),
            reserved_names: Vec::new(),
            options: Vec::new(),
            visibility,
        };
        while !self.eat_sym('}') {
            if self.eat_sym(';') {
                continue;
            }
            let doc = self.doc();
            let next_ident = matches!(self.peek_at(1), Some(Tok::Ident(_)));
            match self.peek() {
                Some(Tok::Ident(k)) => match k.as_str() {
                    "message" if next_ident && matches!(self.peek_at(2), Some(Tok::Sym('{'))) => {
                        self.pos += 1;
                        m.messages.push(self.message(None)?);
                    }
                    "enum" if next_ident && matches!(self.peek_at(2), Some(Tok::Sym('{'))) => {
                        self.pos += 1;
                        m.enums.push(self.enumeration(None)?);
                    }
                    "export" | "local"
                        if self.edition >= Edition::E2024
                            && matches!(self.peek_at(1), Some(Tok::Ident(k)) if k == "message" || k == "enum")
                            && matches!(self.peek_at(2), Some(Tok::Ident(_))) =>
                    {
                        let vis = Some(k == "export");
                        self.pos += 1;
                        if self.eat_ident("message") {
                            m.messages.push(self.message(vis)?);
                        } else {
                            self.pos += 1;
                            m.enums.push(self.enumeration(vis)?);
                        }
                    }
                    "option" if matches!(self.peek_at(1), Some(Tok::Ident(_) | Tok::Sym('('))) => {
                        self.pos += 1;
                        m.options.push(self.option_statement()?);
                    }
                    "reserved" if !matches!(self.peek_at(1), Some(Tok::Sym('.'))) && !self.is_field_decl() => {
                        self.pos += 1;
                        let (ranges, names) = self.reserved(MAX_FIELD)?;
                        for (a, b) in ranges {
                            m.reserved_ranges.push(Range {
                                start: a as u32,
                                end: b as u32,
                                options: Vec::new(),
                            });
                        }
                        m.reserved_names.extend(names);
                    }
                    "extensions" if !matches!(self.peek_at(1), Some(Tok::Sym('.'))) && !self.is_field_decl() => {
                        self.pos += 1;
                        let ranges = self.ranges(MAX_FIELD)?;
                        let options = self.field_options()?;
                        self.expect_sym(';')?;
                        for (a, b) in ranges {
                            if a < 1 || b > MAX_FIELD {
                                return self.err("extension range out of bounds");
                            }
                            m.extension_ranges.push(Range {
                                start: a as u32,
                                end: b as u32,
                                options: options.clone(),
                            });
                        }
                    }
                    "extend"
                        if (matches!(self.peek_at(1), Some(Tok::Sym('.'))) || next_ident)
                            && !self.is_field_decl() =>
                    {
                        self.pos += 1;
                        let (fields, groups) = self.extend()?;
                        m.extensions.extend(fields);
                        m.messages.extend(groups);
                    }
                    "oneof" if next_ident && matches!(self.peek_at(2), Some(Tok::Sym('{'))) => {
                        self.pos += 1;
                        let name = self.ident()?;
                        let idx = m.oneofs.len();
                        let mut o = Oneof {
                            name,
                            doc,
                            options: Vec::new(),
                            synthetic: false,
                        };
                        self.expect_sym('{')?;
                        while !self.eat_sym('}') {
                            if self.eat_sym(';') {
                                continue;
                            }
                            if self.is_ident("option")
                                && matches!(self.peek_at(1), Some(Tok::Ident(_) | Tok::Sym('(')))
                            {
                                self.pos += 1;
                                o.options.push(self.option_statement()?);
                                continue;
                            }
                            let (mut fld, g) = self.field(Some(Label::Optional))?;
                            if fld.label == Label::Repeated || fld.map_key.is_some() {
                                return self.err("oneof members cannot be repeated or maps");
                            }
                            fld.oneof = Some(idx);
                            m.fields.push(fld);
                            m.messages.extend(g);
                        }
                        m.oneofs.push(o);
                    }
                    _ => {
                        let (f, g) = self.field(None)?;
                        m.fields.push(f);
                        m.messages.extend(g);
                    }
                },
                _ => {
                    let got = self.peek().cloned();
                    return self.err(format!("unexpected {}", describe(got.as_ref())));
                }
            }
        }
        Ok(m)
    }

    /// Whether the tokens ahead are a field declaration whose type is a keyword-like name
    /// (`reserved r = 1;`, `extensions e = 2;`): `<ident> <ident> =`.
    fn is_field_decl(&self) -> bool {
        matches!(self.peek_at(1), Some(Tok::Ident(_))) && matches!(self.peek_at(2), Some(Tok::Sym('=')))
    }

    /// A field; `forced` is the label of oneof members (no label written). Returns the message
    /// a group defines.
    fn field(&mut self, forced: Option<Label>) -> PResult<(Field, Option<MessageDef>)> {
        let doc = self.doc();
        let line = self.line();
        let editions = self.edition.is_editions();
        let label = match forced {
            Some(l) => l,
            None => {
                let l = match self.peek() {
                    Some(Tok::Ident(k)) if k == "optional" => Some(Label::Optional),
                    Some(Tok::Ident(k)) if k == "required" => Some(Label::Required),
                    Some(Tok::Ident(k)) if k == "repeated" => Some(Label::Repeated),
                    _ => None,
                };
                // `optional` could itself be a message type name: a label is followed by a type.
                match l {
                    Some(l) if !matches!(self.peek_at(1), Some(Tok::Sym('='))) => {
                        if editions && l != Label::Repeated {
                            return self.err(format!(
                                "label `{}` is not allowed in editions (use features.field_presence)",
                                if l == Label::Optional { "optional" } else { "required" }
                            ));
                        }
                        self.pos += 1;
                        l
                    }
                    _ => {
                        if self.edition == Edition::Proto2
                            && !self.is_ident("map")
                            && !self.is_ident("group")
                        {
                            return self.err(
                                "proto2 fields need a label (optional, required or repeated)",
                            );
                        }
                        Label::Implicit
                    }
                }
            }
        };
        if label == Label::Required && self.edition == Edition::Proto3 {
            return self.err("required fields are not allowed in proto3");
        }
        let mut map_key = None;
        let mut group = None;
        let ty = if self.is_ident("map") && self.peek_at(1) == Some(&Tok::Sym('<')) {
            self.pos += 2;
            let k = self.ident()?;
            let key = Scalar::from_name(&k)
                .filter(|s| s.is_map_key())
                .map_or_else(|| self.err(format!("invalid map key type `{k}`")), Ok)?;
            self.expect_sym(',')?;
            let v = self.type_ref()?;
            self.expect_sym('>')?;
            if label != Label::Implicit {
                return self.err("map fields cannot have a label");
            }
            map_key = Some(key);
            v
        } else if self.is_ident("group") && matches!(self.peek_at(1), Some(Tok::Ident(_))) && matches!(self.peek_at(2), Some(Tok::Sym('='))) {
            if self.edition != Edition::Proto2 {
                return self.err("groups are only allowed in proto2 (use features.message_encoding = DELIMITED)");
            }
            if label == Label::Implicit && forced.is_none() {
                return self.err("proto2 fields need a label (optional, required or repeated)");
            }
            self.pos += 1;
            let gname = self.ident()?;
            if !gname.starts_with(|c: char| c.is_ascii_uppercase()) {
                return self.err("group names must start with a capital letter");
            }
            group = Some(gname.clone());
            TypeRef::Named(gname)
        } else {
            self.type_ref()?
        };
        let name = match &group {
            Some(g) => g.to_ascii_lowercase(),
            None => self.ident()?,
        };
        self.expect_sym('=')?;
        let n = self.int()?;
        if !(1..=MAX_FIELD).contains(&n) {
            return self.err(format!("field number {n} out of range"));
        }
        if (19_000..=19_999).contains(&n) {
            return self.err(format!(
                "field number {n} is reserved for the protobuf implementation"
            ));
        }
        let mut f = Field {
            name,
            doc,
            number: n as u32,
            label: if map_key.is_some() {
                Label::Repeated
            } else {
                label
            },
            ty,
            map_key,
            oneof: None,
            packed: None,
            default: None,
            json_name: None,
            group: group.is_some(),
            extendee: None,
            options: Vec::new(),
            line,
            resolved: Resolved::default(),
        };
        let options = self.field_options()?;
        for o in &options {
            match (o.name.as_str(), &o.value) {
                ("packed", Constant::Ident(b)) => {
                    if editions {
                        return self.err(
                            "[packed] is not allowed in editions (use features.repeated_field_encoding)",
                        );
                    }
                    f.packed = Some(b == "true");
                }
                ("default", v) => {
                    if self.edition == Edition::Proto3 {
                        return self.err("default values are not allowed in proto3");
                    }
                    f.default = Some(v.clone());
                }
                ("json_name", Constant::Str(s)) => {
                    f.json_name = Some(String::from_utf8_lossy(s).into_owned());
                }
                ("json_name", _) => return self.err("json_name must be a string"),
                _ => {}
            }
        }
        f.options = options;
        let msg = match group {
            Some(g) => {
                self.expect_sym('{')?;
                Some(self.message_body(g, String::new(), None)?)
            }
            None => {
                self.expect_sym(';')?;
                None
            }
        };
        Ok((f, msg))
    }

    fn type_ref(&mut self) -> PResult<TypeRef> {
        let name = self.full_ident(true)?;
        Ok(match Scalar::from_name(&name) {
            Some(s) => TypeRef::Scalar(s),
            None => TypeRef::Named(name),
        })
    }

    fn enumeration(&mut self, visibility: Option<bool>) -> PResult<EnumDef> {
        let doc = self.toks[self.pos.saturating_sub(1)].doc.clone();
        let name = self.ident()?;
        let mut e = EnumDef {
            name,
            doc,
            values: Vec::new(),
            reserved_ranges: Vec::new(),
            reserved_names: Vec::new(),
            options: Vec::new(),
            visibility,
            closed: false,
        };
        self.expect_sym('{')?;
        while !self.eat_sym('}') {
            if self.eat_sym(';') {
                continue;
            }
            let doc = self.doc();
            if self.is_ident("option") && !matches!(self.peek_at(1), Some(Tok::Sym('='))) {
                self.pos += 1;
                e.options.push(self.option_statement()?);
                continue;
            }
            if self.is_ident("reserved") && !matches!(self.peek_at(1), Some(Tok::Sym('='))) {
                self.pos += 1;
                let (ranges, names) = self.reserved(i64::from(i32::MAX))?;
                for (a, b) in ranges {
                    let (Ok(a), Ok(b)) = (i32::try_from(a), i32::try_from(b)) else {
                        return self.err("enum reserved range out of range");
                    };
                    e.reserved_ranges.push((a, b));
                }
                e.reserved_names.extend(names);
                continue;
            }
            let name = self.ident()?;
            self.expect_sym('=')?;
            let n = self.int()?;
            let number = i32::try_from(n).or_else(|_| self.err("enum value out of range"))?;
            let options = self.field_options()?;
            self.expect_sym(';')?;
            e.values.push(EnumValue {
                name,
                doc,
                number,
                options,
            });
        }
        if e.values.is_empty() {
            return self.err(format!("enum {} has no values", e.name));
        }
        Ok(e)
    }

    fn service(&mut self) -> PResult<Service> {
        let doc = self.toks[self.pos.saturating_sub(1)].doc.clone();
        let name = self.ident()?;
        let mut s = Service {
            name,
            doc,
            methods: Vec::new(),
            options: Vec::new(),
        };
        self.expect_sym('{')?;
        while !self.eat_sym('}') {
            if self.eat_sym(';') {
                continue;
            }
            let doc = self.doc();
            let kw = self.ident()?;
            match kw.as_str() {
                "option" => s.options.push(self.option_statement()?),
                "rpc" => {
                    let name = self.ident()?;
                    self.expect_sym('(')?;
                    let client_streaming =
                        self.is_ident("stream") && !matches!(self.peek_at(1), Some(Tok::Sym(')')));
                    if client_streaming {
                        self.pos += 1;
                    }
                    let input = TypeRef::Named(self.full_ident(true)?);
                    self.expect_sym(')')?;
                    if !self.eat_ident("returns") {
                        return self.err("expected `returns`");
                    }
                    self.expect_sym('(')?;
                    let server_streaming =
                        self.is_ident("stream") && !matches!(self.peek_at(1), Some(Tok::Sym(')')));
                    if server_streaming {
                        self.pos += 1;
                    }
                    let output = TypeRef::Named(self.full_ident(true)?);
                    self.expect_sym(')')?;
                    let mut options = Vec::new();
                    if self.eat_sym('{') {
                        while !self.eat_sym('}') {
                            if self.eat_sym(';') {
                                continue;
                            }
                            if !self.eat_ident("option") {
                                let got = self.peek().cloned();
                                return self.err(format!("unexpected {}", describe(got.as_ref())));
                            }
                            options.push(self.option_statement()?);
                        }
                    } else {
                        self.expect_sym(';')?;
                    }
                    s.methods.push(Method {
                        name,
                        doc,
                        input,
                        output,
                        client_streaming,
                        server_streaming,
                        options,
                    });
                }
                _ => return self.err(format!("unexpected `{kw}` in service")),
            }
        }
        Ok(s)
    }
}

fn describe(t: Option<&Tok>) -> String {
    match t {
        None => "end of file".into(),
        Some(Tok::Ident(s)) => format!("`{s}`"),
        Some(Tok::Int(s) | Tok::Float(s)) => format!("number {s}"),
        Some(Tok::Str(_)) => "a string".into(),
        Some(Tok::Sym(c)) => format!("`{c}`"),
    }
}

/// Decimal, `0x` hex or `0` octal, unsigned.
pub(crate) fn parse_int(s: &str) -> Option<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u64::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse().ok()
    }
}

/// Parses one `.proto` file; `name` is its import name (for errors and imports).
pub(crate) fn parse(src: &str, name: &str) -> Result<File, String> {
    let toks = lex(src, name)?;
    let mut p = Parser {
        toks,
        pos: 0,
        file: name,
        edition: Edition::Proto2,
    };
    let f = p.file(name)?;
    check(&f).map_err(|m| format!("{name}: {m}"))?;
    Ok(f)
}

/// protoc's default JSON name: underscores dropped, the letter after one capitalized.
pub(crate) fn json_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut up = false;
    for c in name.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.push(c.to_ascii_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn check(f: &File) -> Result<(), String> {
    fn msg(m: &MessageDef, edition: Edition) -> Result<(), String> {
        let mut seen = HashMap::new();
        let mut json: HashMap<String, &str> = HashMap::new();
        for fl in &m.fields {
            if let Some(prev) = seen.insert(fl.number, &fl.name) {
                return Err(format!(
                    "{}: fields {prev} and {} share number {}",
                    m.name, fl.name, fl.number
                ));
            }
            if let Some(r) = m
                .reserved_ranges
                .iter()
                .find(|r| (r.start..=r.end).contains(&fl.number))
            {
                return Err(format!(
                    "{}: field {} uses reserved number {} ({} to {})",
                    m.name, fl.name, fl.number, r.start, r.end
                ));
            }
            if m.reserved_names.contains(&fl.name) {
                return Err(format!("{}: field name {} is reserved", m.name, fl.name));
            }
            if m
                .extension_ranges
                .iter()
                .any(|r| (r.start..=r.end).contains(&fl.number))
            {
                return Err(format!(
                    "{}: field {} uses number {} of an extension range",
                    m.name, fl.name, fl.number
                ));
            }
            if fl.packed == Some(true)
                && (fl.label != Label::Repeated
                    || matches!(fl.ty, TypeRef::Scalar(s) if s.is_len()))
                && fl.map_key.is_none()
            {
                // protoc rejects this too, but only for non-repeated or length-delimited types.
                let mut e = String::new();
                let _ = write!(
                    e,
                    "line {}: [packed = true] on a non-packable field {}",
                    fl.line, fl.name
                );
                return Err(e);
            }
            if edition == Edition::Proto3 && fl.label == Label::Required {
                return Err(format!("{}: required field in proto3", fl.name));
            }
            // proto3 and editions reject JSON name conflicts (default or custom).
            if edition != Edition::Proto2 {
                let j = fl.json_name.clone().unwrap_or_else(|| json_name(&fl.name));
                if let Some(prev) = json.insert(j.clone(), &fl.name) {
                    return Err(format!(
                        "{}: fields {prev} and {} have the same JSON name {j:?}",
                        m.name, fl.name
                    ));
                }
            }
        }
        for n in &m.messages {
            msg(n, edition)?;
        }
        for e in &m.enums {
            enumeration(e, edition)?;
        }
        Ok(())
    }
    fn enumeration(e: &EnumDef, edition: Edition) -> Result<(), String> {
        if edition == Edition::Proto3 && e.values[0].number != 0 {
            return Err(format!("the first value of proto3 enum {} must be 0", e.name));
        }
        for v in &e.values {
            if e.reserved_ranges.iter().any(|&(a, b)| (a..=b).contains(&v.number)) {
                return Err(format!("{}: value {} uses a reserved number", e.name, v.name));
            }
            if e.reserved_names.contains(&v.name) {
                return Err(format!("{}: value name {} is reserved", e.name, v.name));
            }
        }
        if e.options.flag("allow_alias") != Some(true) {
            let mut seen = HashMap::new();
            for v in &e.values {
                if let Some(prev) = seen.insert(v.number, &v.name) {
                    return Err(format!(
                        "{}: {prev} and {} share number {} (set option allow_alias = true)",
                        e.name, v.name, v.number
                    ));
                }
            }
        }
        Ok(())
    }
    for m in &f.messages {
        msg(m, f.edition)?;
    }
    for e in &f.enums {
        enumeration(e, f.edition)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_proto3_file() {
        let src = r#"
            syntax = "proto3";
            // The package.
            package a.b;
            import "other.proto";
            option go_package = "x/y";
            option (my.opt).sub = { a: 1 b: [2, 3] };

            // A message.
            // Two lines.
            message M {
              int32 a = 1; // trailing, not a doc
              /* block doc */
              repeated string b = 2 [deprecated = true, packed = false];
              map<string, M> c = 3;
              optional .a.b.E d = 4;
              oneof kind {
                option (x) = 1;
                bytes e = 5;
                Inner f = 6;
              }
              message Inner { reserved 1, 2 to 5; reserved "x"; }
              enum E2 { option allow_alias = true; Z = 0; Y = 0; }
              reserved 100 to max;
            }
            enum E { E_ZERO = 0; E_NEG = -1 [(foo) = "x"]; }
            service S {
              rpc U (M) returns (M);
              rpc SS (M) returns (stream M) { option deprecated = true; }
              rpc CS (stream .a.b.M) returns (M) {}
              rpc B (stream M) returns (stream M);
            }
        "#;
        let f = parse(src, "t.proto").unwrap();
        assert_eq!((f.edition, f.package.as_str()), (Edition::Proto3, "a.b"));
        assert_eq!(f.imports, ["other.proto"]);
        let m = &f.messages[0];
        assert_eq!(m.doc, "A message.\nTwo lines.\n");
        assert_eq!(m.fields.len(), 6);
        assert_eq!(m.fields[0].doc, "");
        assert_eq!(m.fields[1].doc, "block doc\n");
        assert_eq!(m.fields[1].packed, Some(false));
        assert_eq!(m.fields[2].map_key, Some(Scalar::String));
        assert_eq!(m.fields[3].label, Label::Optional);
        assert_eq!(m.fields[3].ty, TypeRef::Named(".a.b.E".into()));
        assert_eq!(m.fields[4].oneof, Some(0));
        assert_eq!(m.oneofs[0].name, "kind");
        assert_eq!(f.enums[0].values[1].number, -1);
        let s = &f.services[0];
        let modes: Vec<_> = s
            .methods
            .iter()
            .map(|m| (m.client_streaming, m.server_streaming))
            .collect();
        assert_eq!(
            modes,
            [(false, false), (false, true), (true, false), (true, true)]
        );
    }

    #[test]
    fn parses_proto2_defaults_and_strings() {
        let src = r#"
            syntax = "proto2";
            message P {
              optional string s = 1 [default = "a\n\x41\101é" "b"];
              required int64 i = 2 [default = -0x10];
              optional double d = 3 [default = -inf];
              optional float f = 4 [default = 1.5e3];
              repeated int32 r = 5 [packed = true];
              optional bool b = 6 [default = true];
            }
        "#;
        let f = parse(src, "p.proto").unwrap();
        let fl = &f.messages[0].fields;
        assert_eq!(
            fl[0].default,
            Some(Constant::Str("a\nAAéb".as_bytes().to_vec()))
        );
        assert_eq!(fl[1].default, Some(Constant::Int("-0x10".into())));
        assert_eq!(fl[2].default, Some(Constant::Float("-inf".into())));
        assert_eq!(fl[3].default, Some(Constant::Float("1.5e3".into())));
        assert_eq!(fl[4].packed, Some(true));
        assert_eq!(fl[1].label, Label::Required);
    }

    #[test]
    fn rejects_what_it_does_not_support() {
        for (src, want) in [
            ("edition = \"2022\";", "not supported"),
            (
                "syntax = \"proto3\"; message M { optional group G = 1 { } }",
                "groups",
            ),
            (
                "edition = \"2023\"; message M { optional int32 a = 1; }",
                "not allowed in editions",
            ),
            (
                "edition = \"2023\"; message M { repeated int32 a = 1 [packed = true]; }",
                "not allowed in editions",
            ),
            (
                "syntax = \"proto2\"; message M { optional int32 a = 1; reserved 1; }",
                "reserved",
            ),
            (
                "syntax = \"proto2\"; message M { optional int32 a = 5; extensions 1 to 10; }",
                "extension range",
            ),
            (
                "syntax = \"proto3\"; message M { int32 a_b = 1; int32 aB = 2; }",
                "same JSON name",
            ),
            (
                "syntax = \"proto3\"; enum E { A = 0; B = 0; }",
                "allow_alias",
            ),
            (
                "syntax = \"proto3\"; message M { required int32 a = 1; }",
                "required",
            ),
            (
                "syntax = \"proto3\"; message M { int32 a = 1; int32 b = 1; }",
                "share number",
            ),
            (
                "syntax = \"proto3\"; message M { int32 a = 0; }",
                "out of range",
            ),
            (
                "syntax = \"proto3\"; message M { int32 a = 19000; }",
                "reserved",
            ),
            (
                "syntax = \"proto3\"; message M { map<float, int32> a = 1; }",
                "map key",
            ),
            ("syntax = \"proto2\"; message M { int32 a = 1; }", "label"),
            (
                "syntax = \"proto3\"; message M { int32 a = 1 }",
                "expected `;`",
            ),
            (
                "syntax = \"proto3\"; message M { string s = 1 [default = \"x\"]; }",
                "default",
            ),
            ("syntax = \"proto3\"; /* open", "unterminated"),
            (
                "syntax = \"proto3\"; message M { string s = 1; } $",
                "unexpected character",
            ),
        ] {
            let e = parse(src, "x.proto").unwrap_err();
            assert!(e.contains(want), "{src}: {e}");
        }
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    #[test]
    fn parses_groups_extensions_and_editions() {
        let src = r#"
            syntax = "proto2";
            package p;
            message M {
              optional group Data = 1 { optional int32 a = 2; }
              repeated group Item = 3 { required string s = 4; }
              oneof o { group Choice = 5 { optional int32 c = 6; } }
              extensions 100 to 199, 300 to max [declaration = { number: 100 full_name: ".p.x" type: "int32" }];
              extend M { optional int32 inner = 101; }
              reserved 10, 20 to 30;
              reserved "old";
            }
            extend M { repeated group G = 150 { optional int32 g = 1; } }
            option (custom) = { a: 1 b: [2, 3] c { d: "x" } [p.ext]: -inf };
        "#;
        let f = parse(src, "g.proto").unwrap();
        let m = &f.messages[0];
        assert_eq!(m.fields.len(), 3);
        assert!(m.fields.iter().all(|f| f.group));
        assert_eq!(m.fields[0].name, "data");
        assert_eq!(m.fields[2].oneof, Some(0));
        assert_eq!(
            m.messages.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["Data", "Item", "Choice"]
        );
        assert_eq!(m.extension_ranges.len(), 2);
        assert_eq!(m.extension_ranges[1].end, (1 << 29) - 1);
        assert_eq!(m.extension_ranges[0].options[0].name, "declaration");
        assert_eq!(m.extensions[0].name, "inner");
        assert_eq!(m.reserved_ranges.len(), 2);
        assert_eq!(m.reserved_names, ["old"]);
        assert_eq!(f.extensions[0].name, "g");
        assert_eq!(f.messages[1].name, "G");
        let Constant::Aggregate(a) = &f.options[0].value else {
            panic!()
        };
        assert_eq!(a.len(), 4);
        assert_eq!(a[3], ("[p.ext]".into(), Constant::Float("-inf".into())));

        let src = r#"
            edition = "2024";
            package q;
            import option "opt.proto";
            option features.field_presence = IMPLICIT;
            export message A { int32 a = 1 [features.field_presence = EXPLICIT]; local enum E { E_ZERO = 0; } }
            local message B { reserved r1, r2; }
        "#;
        let f = parse(src, "e.proto").unwrap();
        assert_eq!(f.edition, Edition::E2024);
        assert_eq!(f.import_kinds, [ImportKind::Option]);
        assert_eq!(f.messages[0].visibility, Some(true));
        assert_eq!(f.messages[0].enums[0].visibility, Some(false));
        assert_eq!(f.messages[1].reserved_names, ["r1", "r2"]);
        assert_eq!(json_name("foo_bar_baz"), "fooBarBaz");
        assert_eq!(json_name("_a__b"), "AB");
    }
}
