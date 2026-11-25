# akio-wasm

[中文](README.zh-CN.md)

A WebAssembly runtime for plugins, for [`akio`](https://github.com/lesismal/akio), in safe Rust
(`#![forbid(unsafe_code)]`) without dependencies (ADR-125). A module is decoded and validated
once, then (from milestone W2) translated to a register form and run by an interpreter, with
every resource bounded: no `unsafe`, no executable memory, so a bug is a wrong result or a trap,
never memory corruption in the host. It is the runtime under akit's WASM plugins (fit's ABI and
Proxy-Wasm). Also available as `akio::wasm` (feature `wasm`).

**Experimental**: built in milestones, its API may change in any release until W4
(docs/api-stability.md). This release has **W1**, the decoder and the validator.

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

```rust
use akio_wasm::{ErrorKind, Module, ModuleLimits};

let bytes = std::fs::read("plugin.wasm")?;
match Module::new(&bytes, &ModuleLimits::default()) {
    Ok(module) => {
        for i in module.imports() {
            println!("needs {}::{}: {:?}", i.module, i.name, i.ty);
        }
    }
    Err(e) if matches!(e.kind(), ErrorKind::Unsupported(_)) => eprintln!("{e}"),
    Err(e) => return Err(e.into()),
}
```

Tests: the decoding and validation commands of the WebAssembly 2.0 specification suite
(`tests/spec`, converted by `tools/wasm-spec/convert.sh` from `WebAssembly/testsuite`, Apache 2.0),
the proposals of refused features as refusal checks, every limit just under, at and over it, and
modules at the default limits loading in bounded time. Fuzz target `wasm_decode` in `fuzz/`.

Next: W2 the interpreter (metering, budgets, traps), W3 the host API and a WASI preview 1 subset,
W4 the instance pool, W5 a performance pass, W6 akio-http's hooks for Proxy-Wasm's response
callbacks.
