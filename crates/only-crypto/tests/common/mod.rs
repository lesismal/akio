//! Test helpers: hex, the vendored vector files, and a minimal JSON reader for the Wycheproof
//! subsets (enough for their schema: objects, arrays, strings without escapes beyond `\"` `\\`
//! `\/` `\n` `\uXXXX`, numbers, booleans, null).

#![allow(dead_code, unreachable_pub)]

use std::collections::BTreeMap;

pub fn unhex(s: &str) -> Vec<u8> {
    let s = if s == "-" { "" } else { s };
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn data(name: &str) -> String {
    let p = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

/// The non-comment lines of a vendored `.txt` vector file, split on spaces.
pub fn lines(name: &str) -> Vec<Vec<String>> {
    data(name)
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().map(str::to_owned).collect())
        .collect()
}

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, k: &str) -> &Json {
        match self {
            Json::Obj(m) => m.get(k).unwrap_or_else(|| panic!("missing key {k}")),
            _ => panic!("not an object"),
        }
    }
    pub fn str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            _ => panic!("not a string: {self:?}"),
        }
    }
    pub fn hex(&self) -> Vec<u8> {
        unhex(self.str())
    }
    pub fn num(&self) -> usize {
        match self {
            Json::Num(n) => *n as usize,
            _ => panic!("not a number"),
        }
    }
    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            _ => panic!("not an array"),
        }
    }
}

pub fn parse_json(s: &str) -> Json {
    let b = s.as_bytes();
    let mut i = 0;
    let v = value(b, &mut i);
    ws(b, &mut i);
    assert_eq!(i, b.len(), "trailing data");
    v
}

fn ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn value(b: &[u8], i: &mut usize) -> Json {
    ws(b, i);
    match b[*i] {
        b'{' => {
            *i += 1;
            let mut m = BTreeMap::new();
            ws(b, i);
            if b[*i] == b'}' {
                *i += 1;
                return Json::Obj(m);
            }
            loop {
                ws(b, i);
                let Json::Str(k) = value(b, i) else {
                    panic!("object key")
                };
                ws(b, i);
                assert_eq!(b[*i], b':');
                *i += 1;
                m.insert(k, value(b, i));
                ws(b, i);
                *i += 1;
                if b[*i - 1] == b'}' {
                    return Json::Obj(m);
                }
            }
        }
        b'[' => {
            *i += 1;
            let mut a = Vec::new();
            ws(b, i);
            if b[*i] == b']' {
                *i += 1;
                return Json::Arr(a);
            }
            loop {
                a.push(value(b, i));
                ws(b, i);
                *i += 1;
                if b[*i - 1] == b']' {
                    return Json::Arr(a);
                }
            }
        }
        b'"' => {
            *i += 1;
            let mut s = String::new();
            loop {
                let c = b[*i];
                *i += 1;
                match c {
                    b'"' => return Json::Str(s),
                    b'\\' => {
                        let e = b[*i];
                        *i += 1;
                        match e {
                            b'n' => s.push('\n'),
                            b't' => s.push('\t'),
                            b'u' => {
                                let h = std::str::from_utf8(&b[*i..*i + 4]).unwrap();
                                *i += 4;
                                s.push(
                                    char::from_u32(u32::from_str_radix(h, 16).unwrap())
                                        .unwrap_or('?'),
                                );
                            }
                            other => s.push(other as char),
                        }
                    }
                    _ => {
                        // Multi-byte UTF-8 passes through byte by byte.
                        let start = *i - 1;
                        let mut end = *i;
                        while end < b.len() && (b[end] & 0xc0) == 0x80 {
                            end += 1;
                        }
                        s.push_str(std::str::from_utf8(&b[start..end]).unwrap());
                        *i = end;
                    }
                }
            }
        }
        b't' => {
            *i += 4;
            Json::Bool(true)
        }
        b'f' => {
            *i += 5;
            Json::Bool(false)
        }
        b'n' => {
            *i += 4;
            Json::Null
        }
        _ => {
            let start = *i;
            while *i < b.len() && matches!(b[*i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                *i += 1;
            }
            Json::Num(std::str::from_utf8(&b[start..*i]).unwrap().parse().unwrap())
        }
    }
}

/// Every test of every group of a Wycheproof file, with its group.
pub fn wycheproof(name: &str) -> Vec<(Json, Json)> {
    let j = parse_json(&data(name));
    let mut out = Vec::new();
    for g in j.get("testGroups").arr() {
        let mut head = g.clone();
        if let Json::Obj(m) = &mut head {
            m.remove("tests");
        }
        for t in g.get("tests").arr() {
            out.push((head.clone(), t.clone()));
        }
    }
    assert!(!out.is_empty());
    out
}
