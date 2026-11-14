//! Bencoding (BEP 3): a [`Value`] tree, strict decoding with a depth limit, canonical encoding,
//! and [`raw_value`], which finds the exact bytes of a dictionary entry (an info hash is the
//! SHA-1 of the info dictionary *as encoded in the file*).
//!
//! Syntax is strict: no leading zeros, no `-0`, integers within `i64`, nothing after the value
//! (except with [`decode_prefix`], for a ut_metadata message whose dictionary is followed by raw
//! data). Unsorted and repeated dictionary keys are accepted, the last one winning, because real
//! torrents have them; [`encode`] always writes keys sorted.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

/// Nesting deeper than this is refused (hostile input would otherwise exhaust the stack).
pub const MAX_DEPTH: usize = 256;

/// A bencoded value.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// `i<n>e`
    Int(i64),
    /// `<len>:<bytes>`
    Bytes(Vec<u8>),
    /// `l...e`
    List(Vec<Value>),
    /// `d...e`, keys sorted.
    Dict(BTreeMap<Vec<u8>, Value>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(n) => write!(f, "{n}"),
            Value::Bytes(b) => match std::str::from_utf8(b) {
                Ok(s) if s.chars().all(|c| !c.is_control()) => write!(f, "{s:?}"),
                _ => write!(f, "<{} bytes>", b.len()),
            },
            Value::List(l) => f.debug_list().entries(l).finish(),
            Value::Dict(d) => f
                .debug_map()
                .entries(d.iter().map(|(k, v)| (String::from_utf8_lossy(k), v)))
                .finish(),
        }
    }
}

/// Why input is not valid bencoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Byte offset where the problem was found.
    pub offset: usize,
    /// What is wrong.
    pub reason: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bencode: {} at offset {}", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

fn err<T>(offset: usize, reason: &'static str) -> Result<T, Error> {
    Err(Error { offset, reason })
}

impl Value {
    /// A byte string from anything byte-like.
    pub fn bytes(b: impl AsRef<[u8]>) -> Value {
        Value::Bytes(b.as_ref().to_vec())
    }

    /// An empty dictionary, to fill with [`Value::insert`].
    pub fn dict() -> Value {
        Value::Dict(BTreeMap::new())
    }

    /// Sets `key` in a dictionary (does nothing on other kinds); returns `self` for chaining.
    #[must_use]
    pub fn with(mut self, key: &str, v: impl Into<Value>) -> Value {
        self.insert(key, v);
        self
    }

    /// Sets `key` in a dictionary (does nothing on other kinds).
    pub fn insert(&mut self, key: &str, v: impl Into<Value>) {
        if let Value::Dict(d) = self {
            d.insert(key.as_bytes().to_vec(), v.into());
        }
    }

    /// The entry `key` of a dictionary.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(d) => d.get(key.as_bytes()),
            _ => None,
        }
    }

    /// The integer, if this is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// The byte string, if this is one.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The byte string as UTF-8, if this is one and it is valid.
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    /// The list, if this is one.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    /// The dictionary, if this is one.
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// `get(key)` as an integer.
    pub fn int(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(Value::as_int)
    }

    /// `get(key)` as a byte string.
    pub fn bytes_at(&self, key: &str) -> Option<&[u8]> {
        self.get(key).and_then(Value::as_bytes)
    }

    /// `get(key)` as UTF-8.
    pub fn str_at(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }

    /// Encodes into `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(n) => {
                out.push(b'i');
                out.extend_from_slice(n.to_string().as_bytes());
                out.push(b'e');
            }
            Value::Bytes(b) => {
                out.extend_from_slice(b.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(b);
            }
            Value::List(l) => {
                out.push(b'l');
                for v in l {
                    v.encode_to(out);
                }
                out.push(b'e');
            }
            Value::Dict(d) => {
                out.push(b'd');
                for (k, v) in d {
                    out.extend_from_slice(k.len().to_string().as_bytes());
                    out.push(b':');
                    out.extend_from_slice(k);
                    v.encode_to(out);
                }
                out.push(b'e');
            }
        }
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Value {
        Value::Int(n)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::Bytes(s.as_bytes().to_vec())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::Bytes(s.into_bytes())
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Value {
        Value::Bytes(b)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }
}

impl From<Vec<Value>> for Value {
    fn from(l: Vec<Value>) -> Value {
        Value::List(l)
    }
}

/// Encodes `v`.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    v.encode_to(&mut out);
    out
}

/// Decodes exactly one value spanning all of `b`.
pub fn decode(b: &[u8]) -> Result<Value, Error> {
    let (v, n) = decode_prefix(b)?;
    if n != b.len() {
        return err(n, "trailing data");
    }
    Ok(v)
}

/// Decodes the value at the start of `b`; returns it and the number of bytes it took.
pub fn decode_prefix(b: &[u8]) -> Result<(Value, usize), Error> {
    let mut p = Parser { b, pos: 0 };
    let v = p.value(0)?;
    Ok((v, p.pos))
}

/// Walks the value at `pos` without building it; returns where it ends.
pub fn skip(b: &[u8], pos: usize) -> Result<usize, Error> {
    let mut p = Parser { b, pos };
    p.skip(0)?;
    Ok(p.pos)
}

/// The byte range of the value of `key` in the top-level dictionary `b` (the bytes exactly as
/// encoded): the info dictionary of a .torrent file for its info hash.
pub fn raw_value(b: &[u8], key: &[u8]) -> Result<Option<Range<usize>>, Error> {
    let mut p = Parser { b, pos: 0 };
    if p.peek() != Some(b'd') {
        return err(0, "not a dictionary");
    }
    p.pos += 1;
    let mut found = None;
    loop {
        match p.peek() {
            Some(b'e') => break,
            None => return err(p.pos, "unterminated dictionary"),
            _ => {}
        }
        let k = p.string()?;
        let start = p.pos;
        p.skip(1)?;
        if k == key {
            found = Some(start..p.pos);
        }
    }
    Ok(found)
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn int(&mut self) -> Result<i64, Error> {
        // at 'i'
        let start = self.pos;
        self.pos += 1;
        let digits_start = self.pos;
        let neg = self.peek() == Some(b'-');
        if neg {
            self.pos += 1;
        }
        let first = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == first {
            return err(self.pos, "integer without digits");
        }
        if self.peek() != Some(b'e') {
            return err(self.pos, "integer not terminated");
        }
        let digits = &self.b[first..self.pos];
        if digits.len() > 1 && digits[0] == b'0' {
            return err(first, "integer with a leading zero");
        }
        if neg && digits == b"0" {
            return err(start, "negative zero");
        }
        let s = std::str::from_utf8(&self.b[digits_start..self.pos]).map_err(|_| Error {
            offset: start,
            reason: "integer not ASCII",
        })?;
        let n = s.parse::<i64>().map_err(|_| Error {
            offset: start,
            reason: "integer out of range",
        })?;
        self.pos += 1;
        Ok(n)
    }

    fn string(&mut self) -> Result<&'a [u8], Error> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == start {
            return err(start, "expected a string length");
        }
        if self.peek() != Some(b':') {
            return err(self.pos, "string length not followed by ':'");
        }
        let digits = &self.b[start..self.pos];
        if digits.len() > 1 && digits[0] == b'0' {
            return err(start, "string length with a leading zero");
        }
        let mut n: usize = 0;
        for &d in digits {
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(usize::from(d - b'0')))
                .ok_or(Error {
                    offset: start,
                    reason: "string length out of range",
                })?;
        }
        self.pos += 1;
        if self.b.len() - self.pos < n {
            return err(start, "string runs past the end");
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= MAX_DEPTH {
            return err(self.pos, "nested too deeply");
        }
        match self.peek() {
            None => err(self.pos, "unexpected end"),
            Some(b'i') => self.int().map(Value::Int),
            Some(b'0'..=b'9') => self.string().map(|s| Value::Bytes(s.to_vec())),
            Some(b'l') => {
                self.pos += 1;
                let mut l = Vec::new();
                loop {
                    match self.peek() {
                        Some(b'e') => {
                            self.pos += 1;
                            return Ok(Value::List(l));
                        }
                        None => return err(self.pos, "unterminated list"),
                        _ => l.push(self.value(depth + 1)?),
                    }
                }
            }
            Some(b'd') => {
                self.pos += 1;
                let mut d = BTreeMap::new();
                loop {
                    match self.peek() {
                        Some(b'e') => {
                            self.pos += 1;
                            return Ok(Value::Dict(d));
                        }
                        None => return err(self.pos, "unterminated dictionary"),
                        _ => {
                            let k = self.string()?.to_vec();
                            let v = self.value(depth + 1)?;
                            d.insert(k, v);
                        }
                    }
                }
            }
            Some(_) => err(self.pos, "unexpected byte"),
        }
    }

    fn skip(&mut self, depth: usize) -> Result<(), Error> {
        if depth >= MAX_DEPTH {
            return err(self.pos, "nested too deeply");
        }
        match self.peek() {
            None => err(self.pos, "unexpected end"),
            Some(b'i') => self.int().map(drop),
            Some(b'0'..=b'9') => self.string().map(drop),
            Some(c @ (b'l' | b'd')) => {
                self.pos += 1;
                loop {
                    match self.peek() {
                        Some(b'e') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        None => return err(self.pos, "unterminated container"),
                        _ => {
                            if c == b'd' {
                                self.string()?;
                            }
                            self.skip(depth + 1)?;
                        }
                    }
                }
            }
            Some(_) => err(self.pos, "unexpected byte"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let v = Value::dict()
            .with("a", 1)
            .with("b", "xyz")
            .with("c", vec![Value::Int(-3), Value::bytes(b"\x00\x01")]);
        let e = encode(&v);
        assert_eq!(e, b"d1:ai1e1:b3:xyz1:cli-3e2:\x00\x01ee");
        assert_eq!(decode(&e).unwrap(), v);
    }

    #[test]
    fn strictness() {
        for bad in [
            &b"i01e"[..],
            b"i-0e",
            b"ie",
            b"i1",
            b"01:a",
            b"5:abc",
            b"l",
            b"d1:a",
            b"i1ei2e",
            b"x",
            b"i99999999999999999999e",
            b"d1:ae",
        ] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
        assert_eq!(decode(b"i-12e").unwrap(), Value::Int(-12));
        assert_eq!(decode(b"0:").unwrap(), Value::Bytes(vec![]));
    }

    #[test]
    fn unsorted_keys_last_wins() {
        let v = decode(b"d1:bi1e1:ai2e1:bi3ee").unwrap();
        assert_eq!(v.int("a"), Some(2));
        assert_eq!(v.int("b"), Some(3));
    }

    #[test]
    fn depth_limit() {
        let mut deep = vec![b'l'; MAX_DEPTH + 1];
        deep.extend(vec![b'e'; MAX_DEPTH + 1]);
        assert!(decode(&deep).is_err());
        assert!(skip(&deep, 0).is_err());
        let mut ok = vec![b'l'; 10];
        ok.extend(vec![b'e'; 10]);
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn raw_and_prefix() {
        let b = b"d4:infod1:xi1ee3:zzz1:qe";
        let r = raw_value(b, b"info").unwrap().unwrap();
        assert_eq!(&b[r], b"d1:xi1ee");
        assert_eq!(raw_value(b, b"nope").unwrap(), None);
        let (v, n) = decode_prefix(b"d1:ai1eeRAW").unwrap();
        assert_eq!(v.int("a"), Some(1));
        assert_eq!(n, 8);
    }
}
