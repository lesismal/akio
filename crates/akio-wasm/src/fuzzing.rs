//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project calls
//! them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use crate::{ErrorKind, Module, ModuleLimits};

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
}
