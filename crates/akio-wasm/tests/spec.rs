//! The WebAssembly specification's test suite (`tests/spec`, converted from the `.wast` files by
//! `tools/wasm-spec/convert.sh`; pinned commit in `tests/spec/COMMIT`), every command
//! (ADR-125, section 7):
//!
//! - `module`: loaded and instantiated, its imports from the `spectest` module or modules
//!   `register`ed before; `assert_unlinkable`, `assert_uninstantiable` and `assert_trap` on a
//!   module: refused when instantiated, with the expected message;
//! - `invoke` and `get` actions, `assert_return` (with NaN classes), `assert_trap` (its message),
//!   `assert_exhaustion`;
//! - `assert_invalid`: refused as invalid; `assert_malformed` (binary modules): refused as
//!   malformed. A refusal for an unsupported feature counts for either;
//! - the files of refused features (`simd_*` and the proposal directories): every module is
//!   accepted or refused as unsupported, never as malformed or invalid, never with a panic, and
//!   each file refuses at least one;
//! - text modules of `assert_malformed` are not run (binary modules only).
//!
//! A file's instances share one store, which a trap does not end (`Store::set_trap_ends`): the
//! suite goes on after a trap, as the specification has it.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use akio_wasm::{
    Budget, ErrorKind, Extern, ExternRef, Feature, FuncType, GlobalType, Instance, InstanceLimits,
    InstantiateError, Limits, MemoryType, Module, ModuleLimits, RefType, Store, TableType, Trap,
    ValType, Value,
};

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
    returns: usize,
    traps: usize,
    exhaustion: usize,
    unlinkable: usize,
    uninstantiable: usize,
    actions: usize,
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

/// The `spectest` module the suite imports from, and the instances by name.
struct Env {
    store: Store<()>,
    spectest: HashMap<&'static str, Extern>,
    registered: HashMap<String, Instance>,
    named: HashMap<String, Instance>,
    current: Option<Instance>,
}

fn print_func(store: &mut Store<()>, params: &[ValType]) -> Extern {
    Extern::Func(store.func_new(FuncType::new(params, &[]), |_, _, _| Ok(())))
}

impl Env {
    fn new() -> Self {
        let mut store = Store::new((), InstanceLimits::default());
        store.set_trap_ends(false);
        let mut spectest = HashMap::new();
        use ValType::{F32, F64, I32, I64};
        spectest.insert("print", print_func(&mut store, &[]));
        spectest.insert("print_i32", print_func(&mut store, &[I32]));
        spectest.insert("print_i64", print_func(&mut store, &[I64]));
        spectest.insert("print_f32", print_func(&mut store, &[F32]));
        spectest.insert("print_f64", print_func(&mut store, &[F64]));
        spectest.insert("print_i32_f32", print_func(&mut store, &[I32, F32]));
        spectest.insert("print_f64_f64", print_func(&mut store, &[F64, F64]));
        let g = |store: &mut Store<()>, v: Value| {
            let ty = GlobalType {
                val: v.ty(),
                mutable: false,
            };
            Extern::Global(store.global_new(ty, v).unwrap())
        };
        spectest.insert("global_i32", g(&mut store, Value::I32(666)));
        spectest.insert("global_i64", g(&mut store, Value::I64(666)));
        spectest.insert("global_f32", g(&mut store, Value::F32(666.6)));
        spectest.insert("global_f64", g(&mut store, Value::F64(666.6)));
        let table = TableType {
            elem: RefType::FuncRef,
            limits: Limits {
                min: 10,
                max: Some(20),
            },
        };
        spectest.insert(
            "table",
            Extern::Table(store.table_new(table, Value::FuncRef(None)).unwrap()),
        );
        let memory = MemoryType {
            limits: Limits {
                min: 1,
                max: Some(2),
            },
        };
        spectest.insert("memory", Extern::Memory(store.memory_new(memory).unwrap()));
        Self {
            store,
            spectest,
            registered: HashMap::new(),
            named: HashMap::new(),
            current: None,
        }
    }

    /// The imports of `m`, or why they cannot be found.
    fn imports(&self, m: &Module) -> Result<Vec<Extern>, String> {
        m.imports()
            .iter()
            .map(|i| {
                let found = if &*i.module == "spectest" {
                    self.spectest.get(&*i.name).copied()
                } else {
                    self.registered
                        .get(&*i.module)
                        .and_then(|&inst| self.store.export(inst, &i.name))
                };
                found.ok_or_else(|| "unknown import".to_string())
            })
            .collect()
    }

    fn instantiate(&mut self, m: &Arc<Module>) -> Result<Instance, String> {
        let imports = self.imports(m)?;
        self.store
            .instantiate(m, &imports, &budget())
            .map_err(|e| match e {
                InstantiateError::Unlinkable { message, .. } => message.to_string(),
                InstantiateError::Trap(t) => t.message().to_string(),
                e => e.to_string(),
            })
    }

    fn instance(&self, action: &Json) -> Result<Instance, String> {
        match action.str("module") {
            Some(name) => self
                .named
                .get(name)
                .copied()
                .ok_or_else(|| format!("no module {name}")),
            None => self.current.ok_or_else(|| "no module".to_string()),
        }
    }

    /// Runs an action: its results, or the trap's message.
    fn act(&mut self, action: &Json) -> Result<Result<Vec<Value>, Trap>, String> {
        let inst = self.instance(action)?;
        let field = action.str("field").ok_or("no field")?;
        match action.str("type") {
            Some("invoke") => {
                let f = self
                    .store
                    .export_func(inst, field)
                    .ok_or_else(|| format!("no function {field}"))?;
                let Some(Json::Arr(args)) = action.get("args") else {
                    return Err("no args".into());
                };
                let args: Vec<Value> = args.iter().map(arg).collect::<Result<_, _>>()?;
                let mut results: Vec<Value> = self
                    .store
                    .func_type(f)
                    .results()
                    .iter()
                    .map(|&t| Value::default_of(t))
                    .collect();
                Ok(self
                    .store
                    .call(f, &args, &mut results, &budget())
                    .map(|()| results))
            }
            Some("get") => {
                let g = self
                    .store
                    .export(inst, field)
                    .and_then(Extern::global)
                    .ok_or_else(|| format!("no global {field}"))?;
                Ok(Ok(vec![self.store.global_get(g)]))
            }
            t => Err(format!("unknown action {t:?}")),
        }
    }
}

/// Each invocation's budget: generous, so that a bug shows as a failure, not a hang.
fn budget() -> Budget {
    Budget::deadline(Instant::now() + Duration::from_secs(20))
}

fn arg(j: &Json) -> Result<Value, String> {
    let ty = j.str("type").ok_or("no type")?;
    let v = j.str("value").ok_or("no value")?;
    let int = |v: &str| {
        v.parse::<u64>()
            .or_else(|_| v.parse::<i64>().map(|x| x as u64))
            .map_err(|e| format!("{v}: {e}"))
    };
    Ok(match ty {
        "i32" => Value::I32(int(v)? as u32 as i32),
        "i64" => Value::I64(int(v)? as i64),
        "f32" => Value::F32(f32::from_bits(int(v)? as u32)),
        "f64" => Value::F64(f64::from_bits(int(v)?)),
        "externref" if v == "null" => Value::ExternRef(None),
        "externref" => Value::ExternRef(Some(ExternRef(int(v)? as u32))),
        "funcref" if v == "null" => Value::FuncRef(None),
        _ => return Err(format!("argument {ty} {v}")),
    })
}

/// Whether `got` is what `want` describes (NaN patterns included).
fn matches(want: &Json, got: &Value) -> Result<bool, String> {
    let ty = want.str("type").ok_or("no type")?;
    let v = want.str("value");
    let nan32 = |b: u32, v: &str| match v {
        "nan:canonical" => Some(b & 0x7fff_ffff == 0x7fc0_0000),
        "nan:arithmetic" => Some(b & 0x7fc0_0000 == 0x7fc0_0000),
        _ => None,
    };
    let nan64 = |b: u64, v: &str| match v {
        "nan:canonical" => Some(b & 0x7fff_ffff_ffff_ffff == 0x7ff8_0000_0000_0000),
        "nan:arithmetic" => Some(b & 0x7ff8_0000_0000_0000 == 0x7ff8_0000_0000_0000),
        _ => None,
    };
    Ok(match (ty, got) {
        ("f32", Value::F32(x)) => {
            let v = v.ok_or("no value")?;
            match nan32(x.to_bits(), v) {
                Some(ok) => ok,
                None => {
                    Value::F32(*x).f32().map(f32::to_bits) == arg(want)?.f32().map(f32::to_bits)
                }
            }
        }
        ("f64", Value::F64(x)) => {
            let v = v.ok_or("no value")?;
            match nan64(x.to_bits(), v) {
                Some(ok) => ok,
                None => Some(x.to_bits()) == arg(want)?.f64().map(f64::to_bits),
            }
        }
        ("funcref", Value::FuncRef(f)) => match v {
            Some("null") => f.is_none(),
            _ => f.is_some(),
        },
        ("externref", Value::ExternRef(e)) => match v {
            Some("null") => e.is_none(),
            _ => Value::ExternRef(*e) == arg(want)?,
        },
        ("i32" | "i64", _) => *got == arg(want)?,
        _ => false,
    })
}

fn expect_results(c: &Json, got: &[Value]) -> Result<(), String> {
    let Some(Json::Arr(want)) = c.get("expected") else {
        return Err("no expected".into());
    };
    if want.len() != got.len() {
        return Err(format!("{} results, want {}", got.len(), want.len()));
    }
    for (w, g) in want.iter().zip(got) {
        if !matches(w, g)? {
            return Err(format!("got {got:?}, want {want:?}"));
        }
    }
    Ok(())
}

/// One command that runs something; `Err` describes a failure.
fn run_command(env: &mut Env, c: &Json, dir: &Path, counts: &mut Counts) -> Result<(), String> {
    let ty = c.str("type").unwrap_or("");
    let load = |file: &str| -> Result<Arc<Module>, String> {
        let bytes = fs::read(dir.join(file)).map_err(|e| e.to_string())?;
        Module::new(&bytes, &ModuleLimits::default())
            .map(Arc::new)
            .map_err(|e| e.to_string())
    };
    match ty {
        "module" => {
            let m = load(c.str("filename").ok_or("no filename")?)?;
            let inst = env.instantiate(&m)?;
            env.current = Some(inst);
            if let Some(name) = c.str("name") {
                env.named.insert(name.to_string(), inst);
            }
            Ok(())
        }
        "register" => {
            let inst = match c.str("name") {
                Some(n) => *env.named.get(n).ok_or("no such module")?,
                None => env.current.ok_or("no module")?,
            };
            env.registered
                .insert(c.str("as").ok_or("no name")?.to_string(), inst);
            Ok(())
        }
        "assert_unlinkable" | "assert_uninstantiable" | "assert_trap"
            if c.str("filename").is_some() =>
        {
            if ty == "assert_unlinkable" {
                counts.unlinkable += 1;
            } else {
                counts.uninstantiable += 1;
            }
            let m = load(c.str("filename").unwrap_or(""))?;
            let want = c.str("text").unwrap_or("");
            match env.instantiate(&m) {
                Ok(_) => Err(format!("instantiated, want {want:?}")),
                Err(e) if want.starts_with(&e) => Ok(()),
                Err(e) => Err(format!("{e:?}, want {want:?}")),
            }
        }
        "assert_return" | "action" => {
            if ty == "action" {
                counts.actions += 1;
            } else {
                counts.returns += 1;
            }
            match env.act(c.get("action").ok_or("no action")?)? {
                Ok(got) if ty == "action" => {
                    let _ = got;
                    Ok(())
                }
                Ok(got) => expect_results(c, &got),
                Err(t) => Err(format!("trapped: {t}")),
            }
        }
        "assert_trap" | "assert_exhaustion" => {
            if ty == "assert_trap" {
                counts.traps += 1;
            } else {
                counts.exhaustion += 1;
            }
            let want = c.str("text").unwrap_or("");
            match env.act(c.get("action").ok_or("no action")?)? {
                Ok(got) => Err(format!("returned {got:?}, want trap {want:?}")),
                Err(Trap::ValueStackExhausted | Trap::CallStackExhausted)
                    if ty == "assert_exhaustion" =>
                {
                    Ok(())
                }
                // The reference interpreter adds details ("uninitialized element 2").
                Err(t) if want.starts_with(t.message()) => Ok(()),
                Err(t) => Err(format!("trap {t}, want {want:?}")),
            }
        }
        _ => Err(format!("unexpected command {ty}")),
    }
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
    let mut env = Env::new();
    for c in commands {
        let ty = c.str("type").unwrap();
        let line = c.num("line").unwrap_or("?");
        let at = format!("{group}/{name}.wast:{line}");
        if c.str("module_type") == Some("text") {
            counts.text += 1;
            // A text module the converter also wrote as binary (`module quote`) still runs.
            if ty == "module" {
                if let Some(bin) = c.str("binary_filename") {
                    let mut c = c.clone();
                    if let Json::Obj(kv) = &mut c {
                        kv.retain(|(k, _)| k != "filename");
                        kv.push(("filename".into(), Json::Str(bin.into())));
                    }
                    if let Err(e) = run_command(&mut env, &c, &dir, counts) {
                        failures.push(format!("{at}: {ty}: {e}"));
                    }
                }
            }
            continue;
        }
        // Decoding and validation: every command with a module.
        if let Some(file) = c.str("filename") {
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
                    }
                    match &result {
                        Ok(_) => {}
                        Err(_) if refused && unsupported => continue,
                        Err(e) => {
                            failures.push(format!("{at}: {ty} refused: {e}"));
                            continue;
                        }
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
                    continue;
                }
                _ => {
                    failures.push(format!("{at}: unexpected command {ty} with a module"));
                    continue;
                }
            }
        }
        // Execution: the files of supported features (convert.sh drops the actions of the
        // refused ones).
        if refused {
            continue;
        }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_command(&mut env, c, &dir, counts)
        }));
        match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => failures.push(format!("{at}: {ty}: {e}")),
            Err(_) => {
                failures.push(format!("{at}: {ty}: panicked"));
                env = Env::new();
            }
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
        core.returns > 20_000 && core.traps > 2_000 && core.exhaustion > 10,
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
