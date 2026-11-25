//! The WebAssembly specification's test suite (`tests/spec`, converted from the `.wast` files by
//! `tools/wasm-spec/convert.sh`; pinned commit in `tests/spec/COMMIT`), the decoding and
//! validation commands (ADR-125, section 7):
//!
//! - `module`: loads; `assert_unlinkable`, `assert_uninstantiable` and `assert_trap` on a module:
//!   load (they fail when linked or instantiated, which W2 and W3 run);
//! - `assert_invalid`: refused as invalid; `assert_malformed` (binary modules): refused as
//!   malformed. A refusal for an unsupported feature counts for either;
//! - the files of refused features (`simd_*` and the proposal directories): every module is
//!   accepted or refused as unsupported, never as malformed or invalid, never with a panic, and
//!   each file refuses at least one;
//! - actions and assertions on results (`invoke`, `assert_return` ...) wait for the interpreter
//!   (W2), and text modules of `assert_malformed` are not run (binary modules only).

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use akio_wasm::{ErrorKind, Feature, Module, ModuleLimits};

// --- A small JSON reader (the crate and its tests take no dependencies). ---

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn str(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    fn num(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            Self::Num(s) => Some(s),
            _ => None,
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, b: u8) {
        self.ws();
        assert_eq!(
            self.s[self.i], b,
            "JSON: expected {:?} at {}",
            b as char, self.i
        );
        self.i += 1;
    }

    fn value(&mut self) -> Json {
        self.ws();
        match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut kv = Vec::new();
                self.ws();
                if self.s[self.i] == b'}' {
                    self.i += 1;
                    return Json::Obj(kv);
                }
                loop {
                    self.ws();
                    let Json::Str(k) = self.value() else {
                        panic!("JSON: key at {}", self.i)
                    };
                    self.eat(b':');
                    kv.push((k, self.value()));
                    self.ws();
                    self.i += 1;
                    if self.s[self.i - 1] == b'}' {
                        return Json::Obj(kv);
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.s[self.i] == b']' {
                    self.i += 1;
                    return Json::Arr(a);
                }
                loop {
                    a.push(self.value());
                    self.ws();
                    self.i += 1;
                    if self.s[self.i - 1] == b']' {
                        return Json::Arr(a);
                    }
                }
            }
            b'"' => {
                self.i += 1;
                let mut out = String::new();
                let mut units: Vec<u16> = Vec::new();
                loop {
                    let c = self.s[self.i];
                    if c == b'\\' && self.s[self.i + 1] == b'u' {
                        let h = std::str::from_utf8(&self.s[self.i + 2..self.i + 6]).unwrap();
                        units.push(u16::from_str_radix(h, 16).unwrap());
                        self.i += 6;
                        continue;
                    }
                    if !units.is_empty() {
                        out.push_str(&String::from_utf16_lossy(&units));
                        units.clear();
                    }
                    match c {
                        b'"' => {
                            self.i += 1;
                            return Json::Str(out);
                        }
                        b'\\' => {
                            out.push(match self.s[self.i + 1] {
                                b'n' => '\n',
                                b't' => '\t',
                                b'r' => '\r',
                                b'b' => '\u{8}',
                                b'f' => '\u{c}',
                                c => c as char,
                            });
                            self.i += 2;
                        }
                        _ => {
                            // Copy one UTF-8 character.
                            let len = match c {
                                0..=0x7f => 1,
                                0xc0..=0xdf => 2,
                                0xe0..=0xef => 3,
                                _ => 4,
                            };
                            out.push_str(
                                std::str::from_utf8(&self.s[self.i..self.i + len]).unwrap(),
                            );
                            self.i += len;
                        }
                    }
                }
            }
            b't' => {
                self.i += 4;
                Json::Bool(true)
            }
            b'f' => {
                self.i += 5;
                Json::Bool(false)
            }
            b'n' => {
                self.i += 4;
                Json::Null
            }
            _ => {
                let start = self.i;
                while self.i < self.s.len()
                    && matches!(
                        self.s[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                Json::Num(String::from_utf8(self.s[start..self.i].to_vec()).unwrap())
            }
        }
    }
}

fn parse_json(s: &str) -> Json {
    let mut p = Parser {
        s: s.as_bytes(),
        i: 0,
    };
    p.value()
}

#[test]
fn json_reader() {
    let j = parse_json(r#"{"a": [1, -2.5e3, "x\"é😀", true, null, {}], "b": []}"#);
    let Some(Json::Arr(a)) = j.get("a") else {
        panic!()
    };
    assert_eq!(a[1], Json::Num("-2.5e3".into()));
    assert_eq!(a[2], Json::Str("x\"é😀".into()));
    assert_eq!(a[3], Json::Bool(true));
    assert_eq!(a[4], Json::Null);
    assert_eq!(a[5], Json::Obj(vec![]));
}

// --- The runner. ---

fn spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/spec")
}

#[derive(Debug, Default)]
struct Counts {
    modules: usize,
    invalid: usize,
    malformed: usize,
    load_only: usize,
    deferred: usize,
    text: usize,
    refused: usize,
}

/// Is this file about a feature `akio-wasm` refuses?
fn refused_file(group: &str, name: &str) -> bool {
    group != "core" || name.starts_with("simd_")
}

/// Modules a proposal's file calls invalid that WebAssembly 2.0 made valid: the proposal
/// predates the change.
fn accepted_since(group: &str, name: &str, text: &str) -> bool {
    // The threads proposal is based on 1.0: several tables came with reference types.
    group == "threads" && name == "imports" && text == "multiple tables"
}

fn run_file(group: &str, json: &Path, counts: &mut Counts, failures: &mut Vec<String>) {
    let name = json.file_stem().unwrap().to_str().unwrap().to_string();
    let doc = parse_json(&fs::read_to_string(json).unwrap());
    let Some(Json::Arr(commands)) = doc.get("commands") else {
        panic!("{}: no commands", json.display())
    };
    let dir = json.with_extension("");
    let refused = refused_file(group, &name);
    let limits = ModuleLimits::default();
    let mut refused_here = 0;
    for c in commands {
        let ty = c.str("type").unwrap();
        let line = c.num("line").unwrap_or("?");
        let at = format!("{group}/{name}.wast:{line}");
        let Some(file) = c.str("filename") else {
            counts.deferred += 1;
            continue;
        };
        if c.str("module_type") == Some("text") {
            counts.text += 1;
            continue;
        }
        let bytes = fs::read(dir.join(file)).unwrap_or_else(|e| panic!("{at}: {file}: {e}"));
        let result = std::panic::catch_unwind(|| Module::new(&bytes, &limits));
        let Ok(result) = result else {
            failures.push(format!("{at}: {ty}: panicked"));
            continue;
        };
        let unsupported =
            matches!(&result, Err(e) if matches!(e.kind(), ErrorKind::Unsupported(_)));
        if unsupported {
            refused_here += 1;
        }
        match ty {
            "module"
            | "module_definition"
            | "assert_unlinkable"
            | "assert_uninstantiable"
            | "assert_trap"
            | "assert_exhaustion" => {
                if ty == "module" || ty == "module_definition" {
                    counts.modules += 1;
                } else {
                    counts.load_only += 1;
                }
                match &result {
                    Ok(_) => {}
                    Err(_) if refused && unsupported => {}
                    Err(e) => failures.push(format!("{at}: {ty} refused: {e}")),
                }
            }
            "assert_invalid" | "assert_malformed" => {
                let want = if ty == "assert_invalid" {
                    counts.invalid += 1;
                    ErrorKind::Invalid
                } else {
                    counts.malformed += 1;
                    ErrorKind::Malformed
                };
                let text = c.str("text").unwrap_or("");
                match &result {
                    Ok(_) if refused && accepted_since(group, &name, text) => {}
                    Ok(_) => failures.push(format!("{at}: {ty} ({text}) accepted")),
                    Err(e) if e.kind() == want || unsupported => {}
                    Err(e) => failures.push(format!("{at}: {ty} ({text}) refused as {e}")),
                }
            }
            _ => failures.push(format!("{at}: unexpected command {ty} with a module")),
        }
    }
    if refused {
        counts.refused += 1;
        if refused_here == 0 {
            failures.push(format!(
                "{group}/{name}: a refused feature's file, nothing refused"
            ));
        }
    }
}

#[test]
fn specification_suite() {
    let root = spec_dir();
    let mut groups: BTreeMap<String, Counts> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut files = 0;
    for g in fs::read_dir(&root).unwrap() {
        let g = g.unwrap().path();
        if !g.is_dir() {
            continue;
        }
        let group = g.file_name().unwrap().to_str().unwrap().to_string();
        let mut jsons: Vec<_> = fs::read_dir(&g)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        jsons.sort();
        let counts = groups.entry(group.clone()).or_default();
        for j in jsons {
            files += 1;
            run_file(&group, &j, counts, &mut failures);
        }
    }
    for (g, c) in &groups {
        eprintln!("{g}: {c:?}");
    }
    assert!(
        files > 180,
        "the converted suite is missing ({files} files)"
    );
    let core = &groups["core"];
    assert!(
        core.modules > 1000 && core.invalid > 1000 && core.malformed > 300,
        "{core:?}"
    );
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The features of the refused files are named as such, not as another.
#[test]
fn refused_files_name_their_feature() {
    let root = spec_dir();
    let cases: &[(&str, &str, Feature)] = &[
        ("core", "simd_const", Feature::Simd),
        ("threads", "atomic", Feature::Threads),
        ("relaxed-simd", "relaxed_min_max", Feature::Simd),
        ("wasm-3.0", "memory64", Feature::Memory64),
        ("wasm-3.0", "memory-multi", Feature::MultiMemory),
        ("wasm-3.0", "return_call", Feature::TailCalls),
        ("wasm-3.0", "try_table", Feature::ExceptionHandling),
        ("wasm-3.0", "struct", Feature::Gc),
        ("wasm-3.0", "call_ref", Feature::FunctionReferences),
        (
            "custom-page-sizes",
            "custom-page-sizes",
            Feature::CustomPageSizes,
        ),
        (
            "wide-arithmetic",
            "wide-arithmetic",
            Feature::WideArithmetic,
        ),
    ];
    for &(group, name, feature) in cases {
        let doc =
            parse_json(&fs::read_to_string(root.join(group).join(format!("{name}.json"))).unwrap());
        let Some(Json::Arr(commands)) = doc.get("commands") else {
            panic!()
        };
        let found = commands.iter().any(|c| {
            c.str("type") == Some("module")
                && c.str("filename").is_some_and(|f| {
                    let bytes = fs::read(root.join(group).join(name).join(f)).unwrap();
                    matches!(Module::new(&bytes, &ModuleLimits::default()),
                        Err(e) if e.kind() == ErrorKind::Unsupported(feature))
                })
        });
        assert!(found, "{group}/{name}: no module refused for {feature:?}");
    }
}
