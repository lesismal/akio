#![no_main]

// akio-wasm against wasmi (ADR-125, section 7): the same `wasm-smith` module, instantiated in
// both with the same limits, each exported function called with the same arguments. Results
// (float bits exactly: wasmi's `deterministic` feature makes arithmetic NaNs canonical, as
// akio-wasm does), traps, and then every exported global and memory must agree. A call
// that runs out of akio-wasm's fuel, or exhausts either side's stack (their limits differ),
// ends the comparison; so does any trap (akio-wasm then ends the store).

use akio_wasm::{Budget, Extern, InstanceLimits, Module, ModuleLimits, Store, Trap, Value};
use libfuzzer_sys::arbitrary::{Result, Unstructured};
use wasmi::{Config, Engine, Linker, Val};

#[path = "wasm_smith_config.rs"]
mod wasm_smith_config;

const FUEL: u64 = 100_000;
const MAX_MEMORY: usize = 16 << 16;
const MAX_TABLE: u32 = 1000;

fn arg(u: &mut Unstructured<'_>, t: akio_wasm::ValType) -> Result<(Value, Val)> {
    use akio_wasm::ValType as T;
    Ok(match t {
        T::I32 => {
            let v: i32 = u.arbitrary()?;
            (Value::I32(v), Val::I32(v))
        }
        T::I64 => {
            let v: i64 = u.arbitrary()?;
            (Value::I64(v), Val::I64(v))
        }
        T::F32 => {
            let v: u32 = u.arbitrary()?;
            (
                Value::F32(f32::from_bits(v)),
                Val::F32(wasmi::F32::from_bits(v)),
            )
        }
        T::F64 => {
            let v: u64 = u.arbitrary()?;
            (
                Value::F64(f64::from_bits(v)),
                Val::F64(wasmi::F64::from_bits(v)),
            )
        }
        T::FuncRef => (Value::FuncRef(None), Val::FuncRef(wasmi::Nullable::Null)),
        T::ExternRef => (
            Value::ExternRef(None),
            Val::ExternRef(wasmi::Nullable::Null),
        ),
    })
}

/// Whether two values agree: bits for numbers (both runtimes make arithmetic NaNs canonical),
/// nullness for references.
fn same(a: &Value, b: &Val) -> bool {
    match (a, b) {
        (Value::I32(x), Val::I32(y)) => x == y,
        (Value::I64(x), Val::I64(y)) => x == y,
        (Value::F32(x), Val::F32(y)) => x.to_bits() == y.to_bits(),
        (Value::F64(x), Val::F64(y)) => x.to_bits() == y.to_bits(),
        (Value::FuncRef(x), Val::FuncRef(y)) => x.is_none() == y.is_null(),
        (Value::ExternRef(x), Val::ExternRef(y)) => x.is_none() == y.is_null(),
        _ => false,
    }
}

/// The wasmi trap that matches one of akio-wasm's, if both are the specification's.
fn trap_code(t: &Trap) -> Option<wasmi::TrapCode> {
    use wasmi::TrapCode as C;
    Some(match t {
        Trap::Unreachable => C::UnreachableCodeReached,
        Trap::MemoryOutOfBounds => C::MemoryOutOfBounds,
        Trap::TableOutOfBounds | Trap::UndefinedElement => C::TableOutOfBounds,
        Trap::UninitializedElement => C::IndirectCallToNull,
        Trap::IndirectCallType => C::BadSignature,
        Trap::IntegerDivideByZero => C::IntegerDivisionByZero,
        Trap::IntegerOverflow => C::IntegerOverflow,
        Trap::InvalidConversion => C::BadConversionToInteger,
        _ => return None,
    })
}

fn run(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let mut c = wasm_smith_config::config(&mut u)?;
    c.max_imports = 0;
    let module = wasm_smith::Module::new(c, &mut u)?;
    let bytes = module.to_bytes();

    let m = std::sync::Arc::new(
        Module::new(&bytes, &ModuleLimits::default()).expect("a valid module loads"),
    );
    let mut limits = InstanceLimits::default();
    limits.max_memory = MAX_MEMORY;
    limits.max_table_elements = MAX_TABLE;
    let mut store = Store::new((), limits);

    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);
    let Ok(wm) = wasmi::Module::new(&engine, &bytes) else {
        return Ok(()); // wasmi refuses something akio-wasm accepts: not ours to judge here
    };
    let mut ws = wasmi::Store::new(
        &engine,
        wasmi::StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY)
            .table_elements(MAX_TABLE as usize)
            .build(),
    );
    ws.limiter(|l| l);
    ws.set_fuel(FUEL * 100).expect("fuel");

    let ours = store.instantiate(&m, &[], &Budget::fuel(FUEL));
    let theirs = Linker::new(&engine).instantiate_and_start(&mut ws, &wm);
    let (inst, winst) = match (ours, theirs) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(akio_wasm::InstantiateError::Trap(t)), Err(e)) => {
            if let (Some(a), Some(b)) = (trap_code(&t), e.as_trap_code()) {
                assert_eq!(a, b, "instantiation traps differ");
            }
            return Ok(());
        }
        (Err(akio_wasm::InstantiateError::Trap(Trap::OutOfFuel)), Ok(_)) => return Ok(()),
        (a, b) => panic!("instantiation differs: akio-wasm {a:?}, wasmi {b:?}"),
    };

    for e in m.exports().to_vec() {
        if e.kind != akio_wasm::ExportKind::Func {
            continue;
        }
        let Some(Extern::Func(f)) = store.export(inst, &e.name) else {
            panic!("export {}", e.name)
        };
        let wf = winst.get_func(&ws, &e.name).expect("wasmi export");
        let ty = store.func_type(f).clone();
        let mut args = Vec::new();
        let mut wargs = Vec::new();
        for &t in ty.params() {
            let (a, b) = arg(&mut u, t)?;
            args.push(a);
            wargs.push(b);
        }
        let mut out: Vec<Value> = ty.results().iter().map(|&t| Value::default_of(t)).collect();
        let mut wout: Vec<Val> = wf
            .ty(&ws)
            .results()
            .iter()
            .map(|&t| Val::default_for_ty(t))
            .collect();
        let a = store.call(f, &args, &mut out, &Budget::fuel(FUEL));
        if matches!(
            a,
            Err(Trap::OutOfFuel | Trap::CallStackExhausted | Trap::ValueStackExhausted)
        ) {
            return Ok(());
        }
        let b = wf.call(&mut ws, &wargs, &mut wout);
        match (&a, &b) {
            (Ok(()), Ok(())) => {
                for (x, y) in out.iter().zip(&wout) {
                    assert!(same(x, y), "{}: akio-wasm {out:?}, wasmi {wout:?}", e.name);
                }
            }
            (Err(t), Err(w)) => {
                if w.as_trap_code() == Some(wasmi::TrapCode::StackOverflow) {
                    return Ok(());
                }
                if let (Some(x), Some(y)) = (trap_code(t), w.as_trap_code()) {
                    assert_eq!(x, y, "{}: traps differ", e.name);
                }
                return Ok(());
            }
            (Ok(()), Err(w))
                if w.as_trap_code()
                    .is_none_or(|c| c == wasmi::TrapCode::StackOverflow) =>
            {
                // wasmi out of fuel or stack: not comparable.
                return Ok(());
            }
            _ => panic!("{}: akio-wasm {a:?} {out:?}, wasmi {b:?} {wout:?}", e.name),
        }
        // The state after the call: globals and memories.
        for x in m.exports() {
            match (store.export(inst, &x.name), winst.get_export(&ws, &x.name)) {
                (Some(Extern::Global(g)), Some(wasmi::Extern::Global(wg))) => {
                    let v = store.global_get(g);
                    let w = wg.get(&ws);
                    assert!(same(&v, &w), "global {}: {v:?} vs {w:?}", x.name);
                }
                (Some(Extern::Memory(mm)), Some(wasmi::Extern::Memory(wm))) => {
                    assert!(
                        store.memory_data(mm) == wm.data(&ws),
                        "memory {} differs",
                        x.name
                    );
                }
                _ => {}
            }
        }
    }
    Ok(())
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = run(data);
});
