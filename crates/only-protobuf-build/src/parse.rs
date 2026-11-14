//! A `.proto` parser: proto2 and proto3 files (messages, nested types, enums, fields with every
//! label, `map<K, V>`, `oneof`, options, `reserved`, services). Extensions, `extend` blocks and
//! options other than `packed` and `default` are parsed and ignored; groups and editions are
//! rejected with an error.

use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Syntax {
    Proto2,
    Proto3,
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
    /// proto3 singular field without `optional`.
    Implicit,
    Optional,
    Required,
    Repeated,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Constant {
    Ident(String),
    /// Integer text with its sign (decimal, `0x` hex or `0` octal).
    Int(String),
    Float(String),
    Str(Vec<u8>),
    Aggregate,
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
    pub(crate) line: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct Oneof {
    pub(crate) name: String,
    pub(crate) doc: String,
}

#[derive(Clone, Debug)]
pub(crate) struct MessageDef {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) fields: Vec<Field>,
    pub(crate) oneofs: Vec<Oneof>,
    pub(crate) messages: Vec<MessageDef>,
    pub(crate) enums: Vec<EnumDef>,
}

#[derive(Clone, Debug)]
pub(crate) struct EnumValue {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) number: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct EnumDef {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) values: Vec<EnumValue>,
}

#[derive(Clone, Debug)]
pub(crate) struct Method {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) input: TypeRef,
    pub(crate) output: TypeRef,
    pub(crate) client_streaming: bool,
    pub(crate) server_streaming: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Service {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) methods: Vec<Method>,
}

#[derive(Clone, Debug)]
pub(crate) struct File {
    /// The import name (`dir/x.proto`).
    pub(crate) name: String,
    pub(crate) syntax: Syntax,
    pub(crate) package: String,
    pub(crate) imports: Vec<String>,
    pub(crate) messages: Vec<MessageDef>,
    pub(crate) enums: Vec<EnumDef>,
    pub(crate) services: Vec<Service>,
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
    syntax: Syntax,
}

type PResult<T> = Result<T, String>;

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
        if self.is_sym('{') {
            self.skip_braces()?;
            return Ok(Constant::Aggregate);
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
            Tok::Ident(s) if sign.is_empty() => {
                let mut s = s;
                while self.is_sym('.') {
                    self.pos += 1;
                    s.push('.');
                    s.push_str(&self.ident()?);
                }
                Constant::Ident(s)
            }
            Tok::Ident(s) if s == "inf" || s == "nan" => Constant::Float(format!("{sign}{s}")),
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

    /// Skips a balanced `{ ... }` block (aggregate option values, `extend` blocks).
    fn skip_braces(&mut self) -> PResult<()> {
        self.expect_sym('{')?;
        let mut depth = 1;
        while depth > 0 {
            match self.next()? {
                Tok::Sym('{') => depth += 1,
                Tok::Sym('}') => depth -= 1,
                _ => {}
            }
        }
        Ok(())
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
    fn option_statement(&mut self) -> PResult<(String, Constant)> {
        let name = self.option_name()?;
        self.expect_sym('=')?;
        let v = self.constant()?;
        self.expect_sym(';')?;
        Ok((name, v))
    }

    /// `[a = 1, b = 2]`.
    fn field_options(&mut self) -> PResult<Vec<(String, Constant)>> {
        let mut out = Vec::new();
        if !self.eat_sym('[') {
            return Ok(out);
        }
        loop {
            let name = self.option_name()?;
            self.expect_sym('=')?;
            out.push((name, self.constant()?));
            if self.eat_sym(']') {
                return Ok(out);
            }
            self.expect_sym(',')?;
        }
    }

    /// Skips to the end of a statement (`reserved`, `extensions`).
    fn skip_statement(&mut self) -> PResult<()> {
        while !self.eat_sym(';') {
            self.next()?;
        }
        Ok(())
    }

    fn file(&mut self, name: &str) -> PResult<File> {
        let mut f = File {
            name: name.to_owned(),
            syntax: Syntax::Proto2,
            package: String::new(),
            imports: Vec::new(),
            messages: Vec::new(),
            enums: Vec::new(),
            services: Vec::new(),
        };
        if self.eat_ident("edition") {
            return self.err("editions are not supported (use syntax = \"proto3\" or \"proto2\")");
        }
        if self.eat_ident("syntax") {
            self.expect_sym('=')?;
            let s = self.string()?;
            f.syntax = match s.as_slice() {
                b"proto3" => Syntax::Proto3,
                b"proto2" => Syntax::Proto2,
                _ => return self.err(format!("unknown syntax {:?}", String::from_utf8_lossy(&s))),
            };
            self.expect_sym(';')?;
        }
        self.syntax = f.syntax;
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
                    if !self.eat_ident("public") {
                        self.eat_ident("weak");
                    }
                    let s = self.string()?;
                    self.expect_sym(';')?;
                    f.imports.push(
                        String::from_utf8(s).or_else(|_| self.err("import path is not UTF-8"))?,
                    );
                }
                "option" => {
                    self.option_statement()?;
                }
                "message" => f.messages.push(self.message()?),
                "enum" => f.enums.push(self.enumeration()?),
                "service" => f.services.push(self.service()?),
                "extend" => {
                    self.full_ident(true)?;
                    self.skip_braces()?;
                }
                _ => return self.err(format!("unexpected `{kw}`")),
            }
        }
        Ok(f)
    }

    fn message(&mut self) -> PResult<MessageDef> {
        let doc = self.toks[self.pos.saturating_sub(1)].doc.clone();
        let name = self.ident()?;
        let mut m = MessageDef {
            name,
            doc,
            fields: Vec::new(),
            oneofs: Vec::new(),
            messages: Vec::new(),
            enums: Vec::new(),
        };
        self.expect_sym('{')?;
        while !self.eat_sym('}') {
            if self.eat_sym(';') {
                continue;
            }
            let doc = self.doc();
            match self.peek() {
                Some(Tok::Ident(k)) => match k.as_str() {
                    "message" if !matches!(self.peek_at(1), Some(Tok::Sym('.'))) => {
                        self.pos += 1;
                        m.messages.push(self.message()?);
                    }
                    "enum" if matches!(self.peek_at(1), Some(Tok::Ident(_))) => {
                        self.pos += 1;
                        m.enums.push(self.enumeration()?);
                    }
                    "option" if matches!(self.peek_at(1), Some(Tok::Ident(_) | Tok::Sym('('))) => {
                        self.pos += 1;
                        self.option_statement()?;
                    }
                    "reserved" | "extensions"
                        if !matches!(self.peek_at(1), Some(Tok::Ident(_) | Tok::Sym('.'))) =>
                    {
                        self.pos += 1;
                        self.skip_statement()?;
                    }
                    "extend"
                        if matches!(self.peek_at(1), Some(Tok::Sym('.')))
                            || matches!(self.peek_at(2), Some(Tok::Sym('{' | '.'))) =>
                    {
                        self.pos += 1;
                        self.full_ident(true)?;
                        self.skip_braces()?;
                    }
                    "oneof" if matches!(self.peek_at(2), Some(Tok::Sym('{'))) => {
                        self.pos += 1;
                        let name = self.ident()?;
                        let idx = m.oneofs.len();
                        m.oneofs.push(Oneof { name, doc });
                        self.expect_sym('{')?;
                        while !self.eat_sym('}') {
                            if self.eat_sym(';') {
                                continue;
                            }
                            if self.is_ident("option")
                                && matches!(self.peek_at(1), Some(Tok::Ident(_) | Tok::Sym('(')))
                            {
                                self.pos += 1;
                                self.option_statement()?;
                                continue;
                            }
                            let mut fld = self.field(Some(Label::Optional))?;
                            if fld.label == Label::Repeated || fld.map_key.is_some() {
                                return self.err("oneof members cannot be repeated or maps");
                            }
                            fld.oneof = Some(idx);
                            m.fields.push(fld);
                        }
                    }
                    _ => m.fields.push(self.field(None)?),
                },
                _ => {
                    let got = self.peek().cloned();
                    return self.err(format!("unexpected {}", describe(got.as_ref())));
                }
            }
        }
        Ok(m)
    }

    /// A field; `forced` is the label of oneof members (no label written).
    fn field(&mut self, forced: Option<Label>) -> PResult<Field> {
        let doc = self.doc();
        let line = self.line();
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
                        self.pos += 1;
                        l
                    }
                    _ => {
                        if self.syntax == Syntax::Proto2 && !self.is_ident("map") {
                            return self.err(
                                "proto2 fields need a label (optional, required or repeated)",
                            );
                        }
                        Label::Implicit
                    }
                }
            }
        };
        if label == Label::Required && self.syntax == Syntax::Proto3 {
            return self.err("required fields are not allowed in proto3");
        }
        let mut map_key = None;
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
        } else {
            if self.is_ident("group") {
                return self.err("groups are not supported");
            }
            self.type_ref()?
        };
        let name = self.ident()?;
        self.expect_sym('=')?;
        let n = self.int()?;
        if !(1..=i64::from((1u32 << 29) - 1)).contains(&n) {
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
            line,
        };
        for (k, v) in self.field_options()? {
            match (k.as_str(), v) {
                ("packed", Constant::Ident(b)) => f.packed = Some(b == "true"),
                ("default", v) => {
                    if self.syntax == Syntax::Proto3 {
                        return self.err("default values are not allowed in proto3");
                    }
                    f.default = Some(v);
                }
                _ => {}
            }
        }
        self.expect_sym(';')?;
        Ok(f)
    }

    fn type_ref(&mut self) -> PResult<TypeRef> {
        let name = self.full_ident(true)?;
        Ok(match Scalar::from_name(&name) {
            Some(s) => TypeRef::Scalar(s),
            None => TypeRef::Named(name),
        })
    }

    fn enumeration(&mut self) -> PResult<EnumDef> {
        let doc = self.toks[self.pos.saturating_sub(1)].doc.clone();
        let name = self.ident()?;
        let mut e = EnumDef {
            name,
            doc,
            values: Vec::new(),
        };
        self.expect_sym('{')?;
        while !self.eat_sym('}') {
            if self.eat_sym(';') {
                continue;
            }
            let doc = self.doc();
            if self.is_ident("option") && !matches!(self.peek_at(1), Some(Tok::Sym('='))) {
                self.pos += 1;
                self.option_statement()?;
                continue;
            }
            if self.is_ident("reserved") && !matches!(self.peek_at(1), Some(Tok::Sym('='))) {
                self.pos += 1;
                self.skip_statement()?;
                continue;
            }
            let name = self.ident()?;
            self.expect_sym('=')?;
            let n = self.int()?;
            let number = i32::try_from(n).or_else(|_| self.err("enum value out of range"))?;
            self.field_options()?;
            self.expect_sym(';')?;
            e.values.push(EnumValue { name, doc, number });
        }
        if e.values.is_empty() {
            return self.err(format!("enum {} has no values", e.name));
        }
        if self.syntax == Syntax::Proto3 && e.values[0].number != 0 {
            return self.err(format!(
                "the first value of proto3 enum {} must be 0",
                e.name
            ));
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
        };
        self.expect_sym('{')?;
        while !self.eat_sym('}') {
            if self.eat_sym(';') {
                continue;
            }
            let doc = self.doc();
            let kw = self.ident()?;
            match kw.as_str() {
                "option" => {
                    self.option_statement()?;
                }
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
                    if self.is_sym('{') {
                        self.skip_braces()?;
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
        syntax: Syntax::Proto2,
    };
    let f = p.file(name)?;
    check(&f).map_err(|m| format!("{name}: {m}"))?;
    Ok(f)
}

fn check(f: &File) -> Result<(), String> {
    fn msg(m: &MessageDef, syntax: Syntax) -> Result<(), String> {
        let mut seen = std::collections::HashMap::new();
        for fl in &m.fields {
            if let Some(prev) = seen.insert(fl.number, &fl.name) {
                return Err(format!(
                    "{}: fields {prev} and {} share number {}",
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
            if syntax == Syntax::Proto3 && fl.label == Label::Required {
                return Err(format!("{}: required field in proto3", fl.name));
            }
        }
        for n in &m.messages {
            msg(n, syntax)?;
        }
        Ok(())
    }
    for m in &f.messages {
        msg(m, f.syntax)?;
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
        assert_eq!((f.syntax, f.package.as_str()), (Syntax::Proto3, "a.b"));
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
            ("edition = \"2023\";", "editions"),
            (
                "syntax = \"proto2\"; message M { optional group G = 1 { } }",
                "groups",
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
            ("syntax = \"proto3\"; enum E { A = 1; }", "must be 0"),
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
