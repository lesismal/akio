# akio-wasm

[中文](README.zh-CN.md)

A WebAssembly runtime for plugins, for [`akio`](https://github.com/lesismal/akio), in safe Rust
(`#![forbid(unsafe_code)]`) without dependencies (ADR-125). A module is decoded, validated and
translated once, to a register form run by an interpreter, with every resource bounded: no `unsafe`, no executable memory, so a bug is a wrong result or a trap,
never memory corruption in the host. It is the runtime under akit's WASM plugins (fit's ABI and
Proxy-Wasm). Also available as `akio::wasm` (feature `wasm`).

**Experimental**: built in milestones, its API may change in any release until W4
(docs/api-stability.md). This release has **W1**, the decoder and the validator, and **W2**, the
translation and the interpreter.

- `Module::new(&bytes, &ModuleLimits)`: decodes and validates a binary module in one pass, in
  time linear in its size. `Module` lists the imports, exports (`export(name)`), types, function
  types, tables, memory, globals and start function; it is `Send + Sync`, to be shared by every
  instance made from it.
- **WebAssembly 2.0 without SIMD**: 1.0 (MVP) plus mutable globals, sign-extension operators,
  non-trapping float-to-int conversions, bulk memory, multi-value and reference types (`funcref`,
  `externref`, several tables), one 32-bit memory. That is what Go, TinyGo and Rust's
  `wasm32-wasip1` emit by default.
- **Anything else is refused at load**, with `ErrorKind::Unsupported(Feature)` naming it: SIMD
  (relaxed SIMD included), threads and atomics, exception handling, tail calls, 64-bit memories,
  several memories, extended constant expressions, typed function references, GC, custom page
  sizes, wide arithmetic and component-model binaries. Other refusals are `Malformed` or
  `Invalid`, with the specification's wording (`"type mismatch"`) and the byte offset.
- **Load limits** (`ModuleLimits`), each checked before anything is allocated for what it counts:
  module size (64 MiB), types (100 000) and their arity (1 000), functions (100 000), imports and
  exports (10 000 each), tables (100) and their initial size (10 M elements), globals (100 000),
  locals per function (50 000), block nesting (1 000), `br_table` targets (100 000), element and
  data segments (100 000 each). A module over one is refused with `ErrorKind::Limit(Limit)`.

- **The register form**: each function is translated once, in the same pass, so that every
  position of the operand stack is a fixed slot of the frame: instructions read and write slots
  (`local.get` copies nothing, constants are immediates, a comparison and its branch are one
  instruction), at most four 16-byte instructions per byte of code.
- **The interpreter**: a `match` loop with explicit frames, never native recursion; deep
  recursion is a trap, not a stack overflow. Floats follow the specification (canonical NaNs,
  `nearest` ties to even), so execution is deterministic.
- **`Store`**: instances, host functions (`func_new`) and the host's state; `Send`, not `Sync`.
  `InstanceLimits` bound each memory (128 MiB, `memory.grow` past it returns `-1`), each table
  (10 M elements), the value stack (1 Mi slots) and the call depth (10 000). **A trap ends the
  store**: later calls return `Trap::Ended`.
- **`Budget`**: each call's deadline, fuel and `InterruptHandle`, checked about every 10 000
  instructions as basic blocks are entered (bulk memory and table instructions pay by the byte),
  so a call stops within tens of microseconds of its deadline, with no watchdog thread.

```rust
use std::{sync::Arc, time::{Duration, Instant}};
use akio_wasm::{Budget, InstanceLimits, Module, ModuleLimits, Store, Trap, Value};

let bytes = std::fs::read("plugin.wasm")?;
let module = Arc::new(Module::new(&bytes, &ModuleLimits::default())?);
let mut store = Store::new((), InstanceLimits::default());
let inst = store.instantiate(&module, &[], &Budget::unlimited())?;
let run = store.export_func(inst, "run").ok_or("no run")?;
let mut out = [Value::I32(0)];
let budget = Budget::deadline(Instant::now() + Duration::from_millis(100));
match store.call(run, &[], &mut out, &budget) {
    Ok(()) => println!("{:?}", out[0]),
    Err(Trap::Deadline) => eprintln!("too slow: make another store"),
    Err(t) => eprintln!("trapped: {t}"),
}
```

Tests: the WebAssembly 2.0 specification suite, every command (`tests/spec`, converted by
`tools/wasm-spec/convert.sh` from `WebAssembly/testsuite`, Apache 2.0): 21 453 `assert_return`,
2 354 `assert_trap`, linking and instantiation; the proposals of refused features as refusal
checks; every load and run limit just under, at and over it; budgets; translation in linear time.
Fuzz targets `wasm_decode`, `wasm_exec` (modules from `wasm-smith` under small limits) and
`wasm_diff` (against wasmi) in `fuzz/`.

Next: W3 the host API (`Linker`, typed host functions) and a WASI preview 1 subset, W4 the
instance pool, W5 a performance pass, W6 akio-http's hooks for Proxy-Wasm's response callbacks.
