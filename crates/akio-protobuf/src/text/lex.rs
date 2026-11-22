//! Text format tokens.

use super::TextError;

/// The radix of an integer literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Radix {
    Dec,
    Oct,
    Hex,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Tok<'a> {
    /// `[A-Za-z_][A-Za-z0-9_]*`
    Ident(&'a str),
    /// The digits (without a `0x` prefix; octal ones with their leading `0`).
    Int(&'a str, Radix),
    /// A float literal, without its `f` / `F` suffix.
    Float(&'a str),
    /// One string literal, unescaped.
    Str(Vec<u8>),
    /// Any other character (`{`, `}`, `<`, `>`, `[`, `]`, `:`, `,`, `;`, `-`, `/`, ...).
    Sym(u8),
    Eof,
}

impl Tok<'_> {
    /// The token, for error messages.
    pub(super) fn describe(&self) -> String {
        match self {
            Tok::Ident(s) => format!("identifier {s:?}"),
            Tok::Int(s, Radix::Hex) => format!("number 0x{s}"),
            Tok::Int(s, _) | Tok::Float(s) => format!("number {s}"),
            Tok::Str(_) => "a string".into(),
            Tok::Sym(c) if c.is_ascii() => format!("'{}'", *c as char),
            Tok::Sym(_) => "a non-ASCII character".into(),
            Tok::Eof => "the end of the input".into(),
        }
    }
}

pub(super) struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    /// The next token and where it starts, once peeked.
    peeked: Option<(Tok<'a>, usize)>,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

impl<'a> Lexer<'a> {
    pub(super) fn new(src: &'a str) -> Lexer<'a> {
        Lexer {
            src,
            pos: 0,
            peeked: None,
        }
    }

    fn bytes(&self) -> &'a [u8] {
        self.src.as_bytes()
    }

    fn byte(&self, i: usize) -> Option<u8> {
        self.bytes().get(i).copied()
    }

    /// An error at byte offset `at`.
    pub(super) fn err_at(&self, at: usize, msg: impl Into<String>) -> TextError {
        let before = &self.bytes()[..at.min(self.src.len())];
        let line = before.iter().filter(|&&c| c == b'\n').count() + 1;
        let col = before.iter().rev().take_while(|&&c| c != b'\n').count() + 1;
        TextError::at(msg, line, col)
    }

    /// An error at the next token.
    pub(super) fn err(&mut self, msg: impl Into<String>) -> TextError {
        let at = match self.mark() {
            Ok(at) => at,
            Err(e) => return e,
        };
        self.err_at(at, msg)
    }

    /// Skips whitespace and `#` comments.
    fn skip_space(&mut self) {
        while let Some(c) = self.byte(self.pos) {
            if is_space(c) {
                self.pos += 1;
            } else if c == b'#' {
                while let Some(c) = self.byte(self.pos) {
                    self.pos += 1;
                    if c == b'\n' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    /// The next token, without consuming it.
    pub(super) fn peek(&mut self) -> Result<&Tok<'a>, TextError> {
        if self.peeked.is_none() {
            self.skip_space();
            let start = self.pos;
            let t = self.lex()?;
            self.peeked = Some((t, start));
        }
        match &self.peeked {
            Some((t, _)) => Ok(t),
            None => unreachable!(),
        }
    }

    /// Where the next token starts.
    pub(super) fn mark(&mut self) -> Result<usize, TextError> {
        self.peek()?;
        Ok(self.peeked.as_ref().map_or(self.pos, |p| p.1))
    }

    /// Consumes the next token.
    pub(super) fn next(&mut self) -> Result<Tok<'a>, TextError> {
        self.peek()?;
        match self.peeked.take() {
            Some((t, _)) => Ok(t),
            None => unreachable!(),
        }
    }

    /// Whether the next token is the symbol `c`; consumes it if so.
    pub(super) fn eat(&mut self, c: u8) -> Result<bool, TextError> {
        if *self.peek()? == Tok::Sym(c) {
            self.peeked = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Consumes the symbol `c` or fails.
    pub(super) fn expect(&mut self, c: u8) -> Result<(), TextError> {
        if self.eat(c)? {
            Ok(())
        } else {
            let found = self.describe()?;
            Err(self.err(format!("expected '{}', found {found}", c as char)))
        }
    }

    /// The next token, for error messages.
    pub(super) fn describe(&mut self) -> Result<String, TextError> {
        Ok(self.peek()?.describe())
    }

    /// The contents of `[ ... ]` (an extension name or an `Any` type URL) after the `[` was
    /// consumed, with whitespace and comments dropped, and the `]` consumed.
    pub(super) fn bracketed(&mut self) -> Result<String, TextError> {
        debug_assert!(self.peeked.is_none());
        let start = self.pos;
        let mut out = String::new();
        loop {
            self.skip_space();
            let rest = &self.src[self.pos..];
            let Some(c) = rest.chars().next() else {
                return Err(self.err_at(start, "unterminated '['"));
            };
            self.pos += c.len_utf8();
            if c == ']' {
                return Ok(out);
            }
            out.push(c);
        }
    }

    fn lex(&mut self) -> Result<Tok<'a>, TextError> {
        let start = self.pos;
        let Some(c) = self.byte(start) else {
            return Ok(Tok::Eof);
        };
        if is_ident_start(c) {
            let mut end = start + 1;
            while self.byte(end).is_some_and(is_ident) {
                end += 1;
            }
            self.pos = end;
            return Ok(Tok::Ident(&self.src[start..end]));
        }
        if c.is_ascii_digit()
            || (c == b'.' && self.byte(start + 1).is_some_and(|d| d.is_ascii_digit()))
        {
            return self.number();
        }
        if c == b'"' || c == b'\'' {
            return self.string(c);
        }
        // A symbol (one character, which may be a multi-byte one: it is then an error later).
        let ch = self.src[start..].chars().next().unwrap_or('\0');
        self.pos += ch.len_utf8();
        Ok(Tok::Sym(if ch.is_ascii() { c } else { 0x80 }))
    }

    fn digits(&mut self, ok: impl Fn(u8) -> bool) -> usize {
        let s = self.pos;
        while self.byte(self.pos).is_some_and(&ok) {
            self.pos += 1;
        }
        self.pos - s
    }

    fn number(&mut self) -> Result<Tok<'a>, TextError> {
        let start = self.pos;
        let b = |i: usize| self.byte(i);
        let tok = if b(start) == Some(b'0') && matches!(b(start + 1), Some(b'x' | b'X')) {
            self.pos += 2;
            let s = self.pos;
            if self.digits(|c| c.is_ascii_hexdigit()) == 0 {
                return Err(self.err_at(start, "expected hex digits after 0x"));
            }
            Tok::Int(&self.src[s..self.pos], Radix::Hex)
        } else if b(start) == Some(b'0') && b(start + 1).is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
            self.digits(|c| c.is_ascii_digit());
            let t = &self.src[start..self.pos];
            if t.bytes().any(|c| c > b'7') {
                return Err(self.err_at(start, format!("invalid octal number {t}")));
            }
            Tok::Int(t, Radix::Oct)
        } else {
            self.digits(|c| c.is_ascii_digit());
            let mut float = false;
            if self.byte(self.pos) == Some(b'.') {
                float = true;
                self.pos += 1;
                self.digits(|c| c.is_ascii_digit());
            }
            if matches!(self.byte(self.pos), Some(b'e' | b'E')) {
                float = true;
                self.pos += 1;
                if matches!(self.byte(self.pos), Some(b'+' | b'-')) {
                    self.pos += 1;
                }
                if self.digits(|c| c.is_ascii_digit()) == 0 {
                    return Err(self.err_at(start, "expected digits in the exponent"));
                }
            }
            let end = self.pos;
            if matches!(self.byte(self.pos), Some(b'f' | b'F')) {
                float = true;
                self.pos += 1;
            }
            let t = &self.src[start..end];
            if float {
                Tok::Float(t)
            } else {
                Tok::Int(t, Radix::Dec)
            }
        };
        if self
            .byte(self.pos)
            .is_some_and(|c| is_ident(c) || c == b'.')
        {
            return Err(self.err_at(start, "a number must be followed by a separator"));
        }
        Ok(tok)
    }

    fn string(&mut self, quote: u8) -> Result<Tok<'a>, TextError> {
        let start = self.pos;
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            let Some(c) = self.byte(self.pos) else {
                return Err(self.err_at(start, "unterminated string"));
            };
            self.pos += 1;
            match c {
                b'\n' => return Err(self.err_at(start, "a string cannot span lines")),
                b'\\' => self.escape(&mut out)?,
                c if c == quote => return Ok(Tok::Str(out)),
                c => out.push(c),
            }
        }
    }

    fn hex(&mut self, n: usize) -> Option<u32> {
        let t = self.src.get(self.pos..self.pos + n)?;
        if !t.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        self.pos += n;
        u32::from_str_radix(t, 16).ok()
    }

    fn escape(&mut self, out: &mut Vec<u8>) -> Result<(), TextError> {
        let at = self.pos - 1;
        let Some(c) = self.byte(self.pos) else {
            return Err(self.err_at(at, "unterminated string"));
        };
        self.pos += 1;
        let simple = match c {
            b'a' => Some(0x07),
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'v' => Some(0x0b),
            b'?' | b'\\' | b'\'' | b'"' => Some(c),
            _ => None,
        };
        if let Some(v) = simple {
            out.push(v);
            return Ok(());
        }
        match c {
            b'0'..=b'7' => {
                let mut v = u32::from(c - b'0');
                for _ in 0..2 {
                    match self.byte(self.pos) {
                        Some(d @ b'0'..=b'7') => {
                            v = v * 8 + u32::from(d - b'0');
                            self.pos += 1;
                        }
                        _ => break,
                    }
                }
                let v = u8::try_from(v).map_err(|_| self.err_at(at, "octal escape above \\377"))?;
                out.push(v);
            }
            b'x' | b'X' => {
                let mut v = 0u8;
                let mut n = 0;
                while n < 2 {
                    match self.byte(self.pos) {
                        Some(d) if d.is_ascii_hexdigit() => {
                            v = v * 16 + (d as char).to_digit(16).unwrap_or(0) as u8;
                            self.pos += 1;
                            n += 1;
                        }
                        _ => break,
                    }
                }
                if n == 0 {
                    return Err(self.err_at(at, "expected hex digits after \\x"));
                }
                out.push(v);
            }
            b'u' | b'U' => {
                let n = if c == b'u' { 4 } else { 8 };
                let cp = self.hex(n).ok_or_else(|| {
                    self.err_at(at, format!("expected {n} hex digits after \\{}", c as char))
                })?;
                let ch = char::from_u32(cp).ok_or_else(|| {
                    self.err_at(
                        at,
                        format!("\\{}{cp:x} is not a Unicode scalar value", c as char),
                    )
                })?;
                let mut b = [0; 4];
                out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
            }
            _ => return Err(self.err_at(at, format!("invalid escape \\{}", c as char))),
        }
        Ok(())
    }
}
