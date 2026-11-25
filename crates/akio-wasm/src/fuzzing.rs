//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project calls
//! them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::sync::Arc;

use crate::{
    Budget, ErrorKind, Extern, ExternType, InstanceLimits, InstantiateError, Module, ModuleLimits,
    Store, Trap, Value,
};

/// Small limits, so that the fuzzer reaches them.
fn small_limits() -> ModuleLimits {
    ModuleLimits {
        max_module_bytes: 4096,
        max_types: 8,
        max_type_arity: 4,
        max_funcs: 8,
        max_imports: 4,
        max_exports: 4,
        max_tables: 2,
        max_table_elements: 16,
        max_globals: 4,
        max_locals: 8,
        max_nesting: 4,
        max_br_table_targets: 4,
        max_elem_segments: 2,
        max_data_segments: 2,
    }
}

/// `wasm_decode`: arbitrary bytes as a module, with the default limits and with small ones.
/// Never panics; a module accepted under the small limits is inside each of them, and accepted
/// under the default limits too (they are all larger); a module refused under the small limits
/// for another reason than a limit is refused the same way under the defaults; an error's text
/// is never empty.
pub fn decode(data: &[u8]) {
    let full = Module::new(data, &ModuleLimits::default());
    let small_limits = small_limits();
    let small = Module::new(data, &small_limits);
    match &small {
        Ok(m) => {
            assert!(full.is_ok(), "accepted under small limits only: {full:?}");
            let l = &small_limits;
            assert!(data.len() <= l.max_module_bytes);
            assert!(m.types.len() <= l.max_types as usize);
            for t in &m.types {
                assert!(t.params().len() <= l.max_type_arity as usize);
                assert!(t.results().len() <= l.max_type_arity as usize);
            }
            assert!(m.funcs.len() <= l.max_funcs as usize);
            assert!(m.imports.len() <= l.max_imports as usize);
            assert!(m.exports.len() <= l.max_exports as usize);
            assert!(m.tables.len() <= l.max_tables as usize);
            assert!(
                m.tables
                    .iter()
                    .all(|t| t.limits.min <= l.max_table_elements)
            );
            assert!(m.globals.len() <= l.max_globals as usize);
            assert!(m.elems.len() <= l.max_elem_segments as usize);
            assert!(m.datas.len() <= l.max_data_segments as usize);
            for (i, b) in m.bodies.iter().enumerate() {
                let ty = &m.types[m.funcs[m.imported_funcs as usize + i] as usize];
                let declared = b.locals.last().map_or(0, |&(end, _)| end as usize);
                assert!(declared.max(ty.params().len()) <= l.max_locals as usize);
            }
        }
        Err(e) => {
            assert!(!e.to_string().is_empty());
            // Refused for something else than a limit: the default limits, all larger, pass the
            // same bytes up to there and refuse it the same way, at the same place.
            if !matches!(e.kind(), ErrorKind::Limit(_)) {
                match &full {
                    Err(f) => assert!(f == e, "small limits: {e}, default limits: {f}"),
                    Ok(_) => {
                        panic!("refused under small limits ({e}), accepted under the defaults")
                    }
                }
            }
        }
    }
    if let Err(e) = &full {
        assert!(!e.to_string().is_empty());
    }
}

/// The limits `exec` runs modules under: small, so that the fuzzer reaches them.
#[must_use]
pub fn small_instance_limits() -> InstanceLimits {
    InstanceLimits {
        max_memory: 16 << 16,
        max_table_elements: 1000,
        max_value_stack: 16 << 10,
        max_call_depth: 200,
    }
}

/// The fuel `exec` gives each call.
pub const EXEC_FUEL: u64 = 200_000;

/// Imports for `m` made in `store`: host functions, and tables, memories and globals of the
/// imported types; `None` if one is over the store's limits.
///
/// Every other call of a host function (the store's state counts them) calls back into the
/// guest: an export of the calling instance, chosen by the count, with zeros, its trap
/// returned; the others return zeros. So calls nest, guest into host into guest, up to the
/// bound on re-entry, the call depth, the value stack or the fuel.
pub fn dummy_imports(store: &mut Store<u32>, m: &Module) -> Option<Vec<Extern>> {
    let exports: Arc<[Box<str>]> = m
        .exports()
        .iter()
        .filter(|e| e.kind == crate::ExportKind::Func)
        .map(|e| e.name.clone())
        .collect();
    m.imports()
        .iter()
        .map(|i| match &i.ty {
            ExternType::Func(t) => {
                let exports = Arc::clone(&exports);
                Some(Extern::Func(store.func_new(t.clone(), move |c, _, _| {
                    let n = *c.state();
                    *c.state_mut() = n.wrapping_add(1);
                    if n % 2 == 1 || exports.is_empty() {
                        return Ok(());
                    }
                    let name = &exports[n as usize / 2 % exports.len()];
                    let Some(f) = c.export(name).and_then(Extern::func) else {
                        return Ok(());
                    };
                    let ty = c.func_type(f).clone();
                    let args: Vec<Value> =
                        ty.params().iter().map(|&t| Value::default_of(t)).collect();
                    let mut out: Vec<Value> =
                        ty.results().iter().map(|&t| Value::default_of(t)).collect();
                    c.call(f, &args, &mut out)?;
                    for (v, &t) in out.iter().zip(ty.results()) {
                        assert_eq!(v.ty(), t);
                    }
                    Ok(())
                })))
            }
            ExternType::Table(t) => store
                .table_new(*t, Value::default_of(t.elem.into()))
                .ok()
                .map(Extern::Table),
            ExternType::Memory(t) => store.memory_new(*t).ok().map(Extern::Memory),
            ExternType::Global(t) => store
                .global_new(*t, Value::default_of(t.val))
                .ok()
                .map(Extern::Global),
        })
        .collect()
}

/// `wasm_exec`: a module (any bytes; a valid one from `wasm-smith` when fuzzing) instantiated
/// under small limits, each exported function called with zeros under a small budget. Never
/// panics; a call returns its type's results or a trap; a trap ends the store, after which calls
/// return `Trap::Ended`; the fuel used stays within the budget.
pub fn exec(wasm: &[u8]) {
    let Ok(m) = Module::new(wasm, &ModuleLimits::default()) else {
        return;
    };
    let m = Arc::new(m);
    let funcs: Vec<&str> = m
        .exports()
        .iter()
        .filter(|e| e.kind == crate::ExportKind::Func)
        .map(|e| &*e.name)
        .collect();
    // One store for each export (a trap ends a store), and one for instantiating alone.
    for k in 0..=funcs.len() {
        let mut store = Store::new(0u32, small_instance_limits());
        let Some(imports) = dummy_imports(&mut store, &m) else {
            return;
        };
        let inst = match store.instantiate(&m, &imports, &Budget::fuel(EXEC_FUEL)) {
            Ok(i) => i,
            Err(InstantiateError::Trap(t)) => {
                assert!(t.ends_store() && store.ended(), "{t}");
                assert_eq!(
                    store.instantiate(&m, &imports, &Budget::unlimited()),
                    Err(InstantiateError::Trap(Trap::Ended))
                );
                return;
            }
            Err(e) => {
                assert!(!e.to_string().is_empty());
                return;
            }
        };
        let Some(name) = funcs.get(k) else {
            continue;
        };
        let Some(f) = store.export_func(inst, name) else {
            panic!("export {name} is not a function");
        };
        let ty = store.func_type(f).clone();
        let args: Vec<Value> = ty.params().iter().map(|&t| Value::default_of(t)).collect();
        let mut results: Vec<Value> = ty.results().iter().map(|&t| Value::default_of(t)).collect();
        for _ in 0..2 {
            match store.call(f, &args, &mut results, &Budget::fuel(EXEC_FUEL)) {
                Ok(()) => {
                    assert!(store.fuel_used() <= EXEC_FUEL);
                    for (v, &t) in results.iter().zip(ty.results()) {
                        assert_eq!(v.ty(), t);
                    }
                }
                Err(t) => {
                    assert!(!matches!(t, Trap::BadCall(_) | Trap::Ended), "{t}");
                    assert!(store.ended());
                    assert_eq!(
                        store.call(f, &args, &mut results, &Budget::unlimited()),
                        Err(Trap::Ended)
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    fn replay(target: &str, f: fn(&[u8])) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus")
            .join(target);
        let mut n = 0;
        for e in std::fs::read_dir(&dir).expect("corpus directory") {
            let p = e.expect("entry").path();
            f(&std::fs::read(&p).expect("corpus file"));
            n += 1;
        }
        assert!(n > 0, "empty corpus {}", dir.display());
    }

    #[test]
    fn wasm_decode_corpus() {
        replay("wasm_decode", super::decode);
    }

    /// `wasm_exec`'s inputs are `wasm-smith`'s seeds, which need it to become modules: the
    /// modules of `wasm_decode`'s corpus run here instead, through the same checks.
    #[test]
    fn wasm_exec_on_the_decode_corpus() {
        replay("wasm_decode", super::exec);
    }
}
