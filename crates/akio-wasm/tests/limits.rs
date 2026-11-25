//! Every load limit just under, at and over (ADR-125, section 3), every refused feature, and
//! modules at the default limits loading in bounded time.

use std::time::{Duration, Instant};

use akio_wasm::{ErrorKind, Feature, Limit, Module, ModuleLimits};

// --- A small module encoder. ---

fn leb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn u(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    leb(v, &mut out);
    out
}

/// A vector: its count, then the items.
fn vec_of(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = u(items.len() as u64);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

fn section(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    leb(content.len() as u64, &mut out);
    out.extend_from_slice(content);
    out
}

fn module(sections: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    for s in sections {
        out.extend_from_slice(s);
    }
    out
}

const I32: u8 = 0x7f;

fn func_type(params: &[u8], results: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60];
    out.extend(u(params.len() as u64));
    out.extend_from_slice(params);
    out.extend(u(results.len() as u64));
    out.extend_from_slice(results);
    out
}

/// A function body: `(count, type)` local groups, then the instructions (with their `end`).
fn body(locals: &[(u32, u8)], code: &[u8]) -> Vec<u8> {
    let mut b = vec_of(
        &locals
            .iter()
            .map(|&(n, t)| {
                let mut g = u(u64::from(n));
                g.push(t);
                g
            })
            .collect::<Vec<_>>(),
    );
    b.extend_from_slice(code);
    let mut out = u(b.len() as u64);
    out.extend(b);
    out
}

/// A module of `n` functions of type `() -> ()` with the given bodies' code.
fn funcs_module(codes: &[&[u8]]) -> Vec<u8> {
    module(&[
        section(1, &vec_of(&[func_type(&[], &[])])),
        section(3, &vec_of(&vec![u(0); codes.len()])),
        section(
            10,
            &vec_of(&codes.iter().map(|c| body(&[], c)).collect::<Vec<_>>()),
        ),
    ])
}

fn load(bytes: &[u8], limits: &ModuleLimits) -> Result<Module, akio_wasm::Error> {
    Module::new(bytes, limits)
}

fn limit_of(r: Result<Module, akio_wasm::Error>) -> Option<Limit> {
    match r {
        Err(e) => match e.kind() {
            ErrorKind::Limit(l) => Some(l),
            k => panic!("refused for {k:?}, not a limit: {e}"),
        },
        Ok(_) => None,
    }
}

fn feature_of(bytes: &[u8]) -> Feature {
    match load(bytes, &ModuleLimits::default()) {
        Err(e) => match e.kind() {
            ErrorKind::Unsupported(f) => {
                assert!(e.to_string().contains(f.name()), "{e}");
                f
            }
            k => panic!("refused for {k:?}, not a feature: {e}"),
        },
        Ok(_) => panic!("accepted"),
    }
}

/// Checks a limit: `make(n)` builds a module counting `n`; it loads at `at` and is refused with
/// `which` at `at + 1`, under limits from `set(at)`.
fn check(
    which: Limit,
    at: u32,
    set: impl Fn(&mut ModuleLimits, u32),
    make: impl Fn(u32) -> Vec<u8>,
) {
    let mut limits = ModuleLimits::default();
    set(&mut limits, at);
    for n in [at.saturating_sub(1), at] {
        assert_eq!(
            limit_of(load(&make(n), &limits)),
            None,
            "{which:?}: {n} under a limit of {at}"
        );
    }
    assert_eq!(
        limit_of(load(&make(at + 1), &limits)),
        Some(which),
        "{which:?}: {} over a limit of {at}",
        at + 1
    );
}

// --- Limits. ---

#[test]
fn module_bytes() {
    let m = funcs_module(&[&[0x0b]]);
    let mut limits = ModuleLimits::default();
    limits.max_module_bytes = m.len();
    assert!(load(&m, &limits).is_ok());
    limits.max_module_bytes = m.len() - 1;
    assert_eq!(limit_of(load(&m, &limits)), Some(Limit::ModuleBytes));
}

#[test]
fn types() {
    check(
        Limit::Types,
        5,
        |l, n| l.max_types = n,
        |n| module(&[section(1, &vec_of(&vec![func_type(&[], &[]); n as usize]))]),
    );
}

#[test]
fn type_arity() {
    let params = |n: u32| {
        module(&[section(
            1,
            &vec_of(&[func_type(&vec![I32; n as usize], &[])]),
        )])
    };
    check(Limit::TypeArity, 6, |l, n| l.max_type_arity = n, params);
    let results = |n: u32| {
        module(&[section(
            1,
            &vec_of(&[func_type(&[], &vec![I32; n as usize])]),
        )])
    };
    check(Limit::TypeArity, 6, |l, n| l.max_type_arity = n, results);
}

fn func_import(name: &str) -> Vec<u8> {
    let mut i = vec_of(&[]); // module name ""
    i.extend(u(name.len() as u64));
    i.extend_from_slice(name.as_bytes());
    i.push(0);
    i.extend(u(0));
    i
}

#[test]
fn funcs() {
    // Defined functions only.
    check(
        Limit::Funcs,
        7,
        |l, n| l.max_funcs = n,
        |n| funcs_module(&vec![&[0x0b][..]; n as usize]),
    );
    // Imported and defined: two imports, the rest defined.
    check(
        Limit::Funcs,
        7,
        |l, n| l.max_funcs = n,
        |n| {
            let defined = n.saturating_sub(2) as usize;
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(2, &vec_of(&[func_import("a"), func_import("b")])),
                section(3, &vec_of(&vec![u(0); defined])),
                section(10, &vec_of(&vec![body(&[], &[0x0b]); defined])),
            ])
        },
    );
    // Imports alone.
    check(
        Limit::Funcs,
        3,
        |l, n| l.max_funcs = n,
        |n| {
            let imports: Vec<_> = (0..n).map(|i| func_import(&i.to_string())).collect();
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(2, &vec_of(&imports)),
            ])
        },
    );
}

#[test]
fn imports() {
    check(
        Limit::Imports,
        4,
        |l, n| l.max_imports = n,
        |n| {
            let imports: Vec<_> = (0..n).map(|i| func_import(&i.to_string())).collect();
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(2, &vec_of(&imports)),
            ])
        },
    );
}

#[test]
fn exports() {
    check(
        Limit::Exports,
        4,
        |l, n| l.max_exports = n,
        |n| {
            let exports: Vec<_> = (0..n)
                .map(|i| {
                    let name = i.to_string();
                    let mut e = u(name.len() as u64);
                    e.extend_from_slice(name.as_bytes());
                    e.extend([0, 0]); // function 0
                    e
                })
                .collect();
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(3, &vec_of(&[u(0)])),
                section(7, &vec_of(&exports)),
                section(10, &vec_of(&[body(&[], &[0x0b])])),
            ])
        },
    );
}

#[test]
fn tables_and_their_size() {
    check(
        Limit::Tables,
        3,
        |l, n| l.max_tables = n,
        |n| module(&[section(4, &vec_of(&vec![vec![0x70, 0, 0]; n as usize]))]),
    );
    check(
        Limit::TableElements,
        1000,
        |l, n| l.max_table_elements = n,
        |n| {
            let mut t = vec![0x70, 0];
            t.extend(u(u64::from(n)));
            module(&[section(4, &vec_of(&[t]))])
        },
    );
    // The maximum may be larger: growing is an instance's limit.
    let mut limits = ModuleLimits::default();
    limits.max_table_elements = 10;
    let mut t = vec![0x70, 1, 1];
    t.extend(u(u64::from(u32::MAX)));
    assert!(load(&module(&[section(4, &vec_of(&[t]))]), &limits).is_ok());
    // An imported table counts too.
    let mut imp = vec_of(&[]);
    imp.extend(vec_of(&[]));
    imp.extend([1, 0x70, 0]);
    imp.extend(u(11));
    assert_eq!(
        limit_of(load(&module(&[section(2, &vec_of(&[imp]))]), &limits)),
        Some(Limit::TableElements)
    );
}

#[test]
fn globals() {
    check(
        Limit::Globals,
        5,
        |l, n| l.max_globals = n,
        |n| {
            module(&[section(
                6,
                &vec_of(&vec![vec![I32, 0, 0x41, 0, 0x0b]; n as usize]),
            )])
        },
    );
}

#[test]
fn locals() {
    // Two parameters, the rest declared in two groups.
    check(
        Limit::Locals,
        20,
        |l, n| l.max_locals = n,
        |n| {
            let declared = n.saturating_sub(2);
            module(&[
                section(1, &vec_of(&[func_type(&[I32, I32], &[])])),
                section(3, &vec_of(&[u(0)])),
                section(
                    10,
                    &vec_of(&[body(
                        &[(declared / 2, I32), (declared - declared / 2, 0x7e)],
                        &[0x0b],
                    )]),
                ),
            ])
        },
    );
    // Parameters alone.
    let mut limits = ModuleLimits::default();
    limits.max_locals = 2;
    let m = |p: usize| {
        module(&[
            section(1, &vec_of(&[func_type(&vec![I32; p], &[])])),
            section(3, &vec_of(&[u(0)])),
            section(10, &vec_of(&[body(&[], &[0x0b])])),
        ])
    };
    assert!(load(&m(2), &limits).is_ok());
    assert_eq!(limit_of(load(&m(3), &limits)), Some(Limit::Locals));
    // A count past u32::MAX is malformed, whatever the limit.
    let over = module(&[
        section(1, &vec_of(&[func_type(&[], &[])])),
        section(3, &vec_of(&[u(0)])),
        section(10, &vec_of(&[body(&[(u32::MAX, I32), (1, I32)], &[0x0b])])),
    ]);
    let e = load(&over, &ModuleLimits::default()).unwrap_err();
    assert_eq!(
        (e.kind(), e.message()),
        (ErrorKind::Malformed, "too many locals")
    );
}

fn nested(depth: u32) -> Vec<u8> {
    // `depth` frames: the function's own and depth - 1 blocks.
    let k = depth.saturating_sub(1) as usize;
    let mut code = [0x02, 0x40].repeat(k);
    code.extend(vec![0x0b; k + 1]);
    funcs_module(&[&code])
}

#[test]
fn nesting() {
    check(Limit::Nesting, 10, |l, n| l.max_nesting = n, nested);
    // Loops and ifs count too.
    let mut limits = ModuleLimits::default();
    limits.max_nesting = 2;
    assert!(load(&funcs_module(&[&[0x03, 0x40, 0x0b, 0x0b]]), &limits).is_ok());
    let deep = funcs_module(&[&[0x03, 0x40, 0x41, 0, 0x04, 0x40, 0x0b, 0x0b, 0x0b]]);
    assert_eq!(limit_of(load(&deep, &limits)), Some(Limit::Nesting));
}

fn br_table(targets: u32) -> Vec<u8> {
    // `targets` labels, the default included, all to the function's block.
    let mut code = vec![0x41, 0, 0x0e];
    code.extend(u(u64::from(targets.saturating_sub(1))));
    code.extend(vec![0; targets.max(1) as usize]);
    code.push(0x0b);
    funcs_module(&[&code])
}

#[test]
fn br_table_targets() {
    check(
        Limit::BrTableTargets,
        8,
        |l, n| l.max_br_table_targets = n,
        br_table,
    );
}

#[test]
fn segments() {
    check(
        Limit::ElemSegments,
        3,
        |l, n| l.max_elem_segments = n,
        |n| {
            // Passive segments of no functions.
            module(&[section(9, &vec_of(&vec![vec![1, 0, 0]; n as usize]))])
        },
    );
    let datas = |n: u32| module(&[section(11, &vec_of(&vec![vec![1, 0]; n as usize]))]);
    check(
        Limit::DataSegments,
        3,
        |l, n| l.max_data_segments = n,
        datas,
    );
    // The data count section is checked before the data section.
    check(
        Limit::DataSegments,
        3,
        |l, n| l.max_data_segments = n,
        |n| {
            module(&[
                section(12, &u(u64::from(n))),
                section(11, &vec_of(&vec![vec![1, 0]; n as usize])),
            ])
        },
    );
}

/// A module at each default limit loads, in time linear in its size: well under the bound
/// below even in a debug build on a loaded host.
#[test]
fn default_limits_load_in_bounded_time() {
    let l = ModuleLimits::default();
    let bound = Duration::from_secs(20);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "functions",
            funcs_module(&vec![&[0x0b][..]; l.max_funcs as usize]),
        ),
        ("nesting", nested(l.max_nesting)),
        ("br_table", br_table(l.max_br_table_targets)),
        ("locals", {
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(3, &vec_of(&[u(0)])),
                section(
                    10,
                    &vec_of(&[body(&vec![(1, I32); l.max_locals as usize], &[0x0b])]),
                ),
            ])
        }),
        (
            "types",
            module(&[section(
                1,
                &vec_of(&vec![func_type(&[I32; 1000], &[I32; 1000]); 100]),
            )]),
        ),
        // br_table over labels of the widest type: targets × arity type checks.
        ("wide br_table", {
            let arity = 100;
            let targets = 10_000u32;
            let mut code = Vec::new();
            code.extend([0x02, 0x00]); // block (type 0): -> [i32 x arity]
            for _ in 0..arity {
                code.extend([0x41, 0]);
            }
            code.extend([0x41, 0, 0x0e]);
            code.extend(u(u64::from(targets - 1)));
            code.extend(vec![0; targets as usize]);
            code.push(0x0b); // end of the block
            code.extend(vec![0x1a; arity]); // drop them
            code.push(0x0b);
            module(&[
                section(
                    1,
                    &vec_of(&[func_type(&[], &[I32; 100]), func_type(&[], &[])]),
                ),
                section(3, &vec_of(&[u(1)])),
                section(10, &vec_of(&[body(&[], &code)])),
            ])
        }),
    ];
    for (what, bytes) in cases {
        let t = Instant::now();
        let r = load(&bytes, &l);
        let took = t.elapsed();
        assert!(r.is_ok(), "{what}: {:?}", r.err());
        assert!(took < bound, "{what}: {} bytes in {took:?}", bytes.len());
    }
}

// --- Refused features. ---

fn with_body(code: &[u8]) -> Vec<u8> {
    funcs_module(&[code])
}

fn memory_module(flags: u8) -> Vec<u8> {
    module(&[section(5, &vec_of(&[vec![flags, 1, 1]]))])
}

#[test]
fn refused_features() {
    use Feature::*;
    let cases: Vec<(Feature, Vec<u8>)> = vec![
        (
            Simd,
            module(&[section(1, &vec_of(&[func_type(&[0x7b], &[])]))]),
        ),
        (Simd, with_body(&[0xfd, 0x0c, 0x0b])),
        (Simd, with_body(&[0xfd, 0x80, 0x02, 0x0b])), // a relaxed SIMD opcode
        (Threads, memory_module(0x03)),
        (Threads, with_body(&[0xfe, 0x03, 0x00, 0x0b])),
        (
            Threads,
            module(&[section(6, &vec_of(&[vec![I32, 3, 0x41, 0, 0x0b]]))]),
        ),
        (
            ExceptionHandling,
            module(&[section(13, &vec_of(&[vec![0, 0]]))]),
        ),
        (
            ExceptionHandling,
            with_body(&[0x1f, 0x40, 0x00, 0x0b, 0x0b]),
        ),
        (ExceptionHandling, with_body(&[0x08, 0x00, 0x0b])),
        (TailCalls, with_body(&[0x12, 0x00, 0x0b])),
        (TailCalls, with_body(&[0x13, 0x00, 0x00, 0x0b])),
        (Memory64, memory_module(0x04)),
        (
            Memory64,
            module(&[section(4, &vec_of(&[vec![0x70, 0x04, 1]]))]),
        ),
        (
            MultiMemory,
            module(&[section(5, &vec_of(&[vec![0, 1], vec![0, 1]]))]),
        ),
        (MultiMemory, {
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(3, &vec_of(&[u(0)])),
                section(5, &vec_of(&[vec![0, 1]])),
                section(
                    10,
                    &vec_of(&[body(&[], &[0x41, 0, 0x28, 0x42, 1, 0, 0x1a, 0x0b])]),
                ),
            ])
        }),
        (
            ExtendedConst,
            module(&[section(
                6,
                &vec_of(&[vec![I32, 0, 0x41, 1, 0x41, 2, 0x6a, 0x0b]]),
            )]),
        ),
        (FunctionReferences, with_body(&[0x14, 0x00, 0x0b])),
        (
            FunctionReferences,
            module(&[section(1, &vec_of(&[func_type(&[0x63, 0x70], &[])]))]),
        ),
        (
            FunctionReferences,
            module(&[section(
                4,
                &vec_of(&[vec![0x40, 0x00, 0x70, 0, 1, 0xd0, 0x70, 0x0b]]),
            )]),
        ),
        (FunctionReferences, with_body(&[0xd0, 0x00, 0x1a, 0x0b])),
        (Gc, module(&[section(1, &vec_of(&[vec![0x5f, 0]]))])),
        (Gc, with_body(&[0xfb, 0x00, 0x0b])),
        (
            Gc,
            module(&[section(1, &vec_of(&[func_type(&[0x6e], &[])]))]),
        ),
        (ComponentModel, b"\0asm\x0d\0\x01\0".to_vec()),
        (
            CustomPageSizes,
            module(&[section(5, &vec_of(&[vec![0x08, 1, 0]]))]),
        ),
        (WideArithmetic, with_body(&[0xfc, 19, 0x0b])),
    ];
    for (i, (want, bytes)) in cases.iter().enumerate() {
        assert_eq!(feature_of(bytes), *want, "case {i}");
    }
}

// --- Malformed and invalid modules, with their messages. ---

#[test]
fn malformed_and_invalid() {
    let cases: Vec<(ErrorKind, &str, Vec<u8>)> = vec![
        (ErrorKind::Malformed, "unexpected end", b"\0as".to_vec()),
        (
            ErrorKind::Malformed,
            "magic header not detected",
            b"\0asx\x01\0\0\0".to_vec(),
        ),
        (
            ErrorKind::Malformed,
            "unknown binary version",
            b"\0asm\x02\0\0\0".to_vec(),
        ),
        (
            ErrorKind::Malformed,
            "malformed section id",
            module(&[section(14, &[])]),
        ),
        (
            ErrorKind::Malformed,
            "unexpected content after last section",
            module(&[section(3, &vec_of(&[])), section(1, &vec_of(&[]))]),
        ),
        (
            ErrorKind::Malformed,
            "illegal opcode",
            with_body(&[0xff, 0x0b]),
        ),
        (
            ErrorKind::Malformed,
            "section size mismatch",
            with_body(&[0x0b, 0x01]),
        ),
        (ErrorKind::Malformed, "malformed memop flags", {
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(3, &vec_of(&[u(0)])),
                section(5, &vec_of(&[vec![0, 1]])),
                section(
                    10,
                    &vec_of(&[body(&[], &[0x41, 0, 0x28, 0x20, 0, 0x1a, 0x0b])]),
                ),
            ])
        }),
        (
            ErrorKind::Invalid,
            "type mismatch",
            with_body(&[0x41, 0, 0x0b]),
        ),
        (
            ErrorKind::Invalid,
            "unknown label",
            with_body(&[0x0c, 0x01, 0x0b]),
        ),
        (
            ErrorKind::Invalid,
            "unknown memory 0",
            with_body(&[0x3f, 0x00, 0x1a, 0x0b]),
        ),
        (
            ErrorKind::Invalid,
            "unknown function",
            with_body(&[0x10, 0x05, 0x0b]),
        ),
        (
            ErrorKind::Invalid,
            "undeclared function reference",
            with_body(&[0xd2, 0x00, 0x1a, 0x0b]),
        ),
        (
            ErrorKind::Invalid,
            "unknown global",
            module(&[section(6, &vec_of(&[vec![I32, 0, 0x23, 0, 0x0b]]))]),
        ),
        (ErrorKind::Malformed, "data count section required", {
            module(&[
                section(1, &vec_of(&[func_type(&[], &[])])),
                section(3, &vec_of(&[u(0)])),
                section(10, &vec_of(&[body(&[], &[0xfc, 9, 0, 0x0b])])),
            ])
        }),
        (
            ErrorKind::Invalid,
            "memory size must be at most 65536 pages (4GiB)",
            module(&[section(5, &vec_of(&[vec![0, 0x81, 0x80, 0x04]]))]),
        ),
    ];
    for (kind, message, bytes) in cases {
        let e = load(&bytes, &ModuleLimits::default()).unwrap_err();
        assert_eq!((e.kind(), e.message()), (kind, message), "{e}");
        assert!(e.offset() <= bytes.len(), "{e}");
    }
}

#[test]
fn accepted_module_is_described() {
    // (module (import "env" "f" (func (param i32))) (memory 1 2) (table 3 funcref)
    //   (global (mut i64) (i64.const 7)) (func (export "g") (result i32) i32.const 1) (start 2)
    //   (func) (elem (i32.const 0) func 1))
    let mut imp = u(3);
    imp.extend_from_slice(b"env");
    imp.extend(u(1));
    imp.extend_from_slice(b"f");
    imp.extend([0, 0]);
    let m = module(&[
        section(
            1,
            &vec_of(&[
                func_type(&[I32], &[]),
                func_type(&[], &[I32]),
                func_type(&[], &[]),
            ]),
        ),
        section(2, &vec_of(&[imp])),
        section(3, &vec_of(&[u(1), u(2)])),
        section(4, &vec_of(&[vec![0x70, 0, 3]])),
        section(5, &vec_of(&[vec![1, 1, 2]])),
        section(6, &vec_of(&[vec![0x7e, 1, 0x42, 7, 0x0b]])),
        section(7, &vec_of(&[vec![1, b'g', 0, 1]])),
        section(8, &u(2)),
        section(9, &vec_of(&[vec![0, 0x41, 0, 0x0b, 1, 1]])),
        section(
            10,
            &vec_of(&[body(&[], &[0x41, 1, 0x0b]), body(&[], &[0x0b])]),
        ),
        section(0, b"\x04name"),
    ]);
    let module = load(&m, &ModuleLimits::default()).unwrap();
    assert_eq!(module.func_count(), 3);
    assert_eq!(&*module.imports()[0].module, "env");
    assert!(
        matches!(&module.imports()[0].ty, akio_wasm::ExternType::Func(t) if t.params() == [akio_wasm::ValType::I32])
    );
    let g = module.export("g").unwrap();
    assert_eq!(
        module.func_type(g.index).unwrap().to_string(),
        "(func (result i32))"
    );
    assert_eq!(
        module.memory().unwrap().limits,
        akio_wasm::Limits {
            min: 1,
            max: Some(2)
        }
    );
    assert_eq!(module.tables()[0].limits.min, 3);
    assert!(module.globals()[0].mutable);
    assert_eq!(module.start(), Some(2));
    assert!(module.export("h").is_none());
    fn shared<T: Send + Sync>(_: &T) {}
    shared(&module);
}
