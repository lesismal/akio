# akio-wasm

[中文](README.zh-CN.md)

A WebAssembly runtime for plugins, for [`akio`](https://github.com/lesismal/akio), in safe Rust
(`#![forbid(unsafe_code)]`) without third-party dependencies (its one is akio-crypto, for random
bytes; ADR-125). A module is decoded, validated and translated once, to a register form run by an
interpreter, with every resource bounded: no `unsafe`, no executable memory, so a bug is a wrong
result or a trap, never memory corruption in the host. It is the runtime under akit's WASM plugins
(fit's ABI and Proxy-Wasm). Also available as `akio::wasm` (feature `wasm`).

**Experimental**: built in milestones, its API may change in any release until W4
(docs/api-stability.md). This release has **W1**, the decoder and the validator, **W2**, the
translation and the interpreter, **W3**, the host API and WASI preview 1's subset, and **W4**, the
instance pool.

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
- **`Linker<S>`**: host functions by module and name, typed (`func_wrap`, closures over Rust's
  `i32`, `u32`, `i64`, `u64`, `f32`, `f64`) or over `Value`s (`func_new`), resolved and
  type-checked when it instantiates a module into a store; `Clone + Send + Sync`, shared by a
  pool's threads. `trap_unresolved(true)` lets a function import nothing defines load, and trap
  if called. `Store::typed_func` checks an export's type once.
- **`Caller`**: what a host function sees: the store's state, the calling instance's exports,
  its memory through bounds-checked views (`read`, `write`, `read_u32` ...), the call's deadline
  and interrupt, `consume_fuel`, and `call`, back into the guest (as Proxy-Wasm's hosts call
  `proxy_on_memory_allocate`), under the same budget, nested at most 64 deep.
- **WASI preview 1**, the subset a plugin needs (`Linker::wasi_preview1(WasiConfig)`): arguments
  and environment, the realtime and monotonic clocks, random bytes, standard output and error to a
  sink, `poll_oneoff` sleeping no later than the call's deadline, `proc_exit` as `Trap::Exit`. No
  file system and no sockets (`EBADF`, `ENOSYS`). `Store::initialize_reactor` runs a reactor's
  `_initialize`.
- **`InstancePool<S>`**: threads that each own one instance, never the I/O threads. An I/O thread
  `submit`s a job (`FnOnce(&mut Pooled<S>) -> R`) and a completion, and goes on; the job runs on a
  free instance under a per-call deadline (100 ms), and the completion, run on the pool's thread,
  hands the result back without blocking (akio-http's `Suspended::resume`, a channel). Bounded
  queues: a shared one (1024) and one per instance (`submit_to`, served first, for a Proxy-Wasm
  context's later callbacks); a full queue refuses the job at once (`Refused`, the job and its
  completion handed back), a job that waits past `wait_timeout` (1 s) comes back as
  `JobError::Expired`. An instance a trap ended is remade before its thread's next job; one that
  will not start fails the pool. `stats()`: queue depths, running, calls, traps by kind, remakes,
  expiries, refusals.

```rust
use std::{sync::Arc, time::{Duration, Instant}};
use akio_wasm::{
    Budget, Caller, InstanceLimits, InstancePool, Linker, Module, ModuleLimits, PoolConfig, Store,
    Trap, WasiConfig,
};

// Once: load the plugin and define the host's functions.
let bytes = std::fs::read("plugin.wasm")?;
let module = Arc::new(Module::new(&bytes, &ModuleLimits::default())?);
let mut linker = Linker::<Vec<String>>::new();
linker
    .wasi_preview1(WasiConfig::new().output(|_, b| eprint!("{}", String::from_utf8_lossy(b))))?
    .func_wrap("host", "log", |c: &mut Caller<'_, Vec<String>>, (p, n): (u32, u32)| {
        let line = String::from_utf8_lossy(c.read(p, n)?).into_owned();
        c.state_mut().push(line);
        Ok(())
    })?
    .trap_unresolved(true);

// For each instance: a store, the reactor initialized, then calls under a deadline.
let mut store = Store::new(Vec::new(), InstanceLimits::default());
let inst = linker.instantiate(&mut store, &module, &Budget::unlimited())?;
store.initialize_reactor(inst, &Budget::deadline(Instant::now() + Duration::from_secs(1)))?;
let run = store.typed_func::<(), i32>(store.export_func(inst, "run").ok_or("no run")?)?;
match run.call(&mut store, (), &Budget::deadline(Instant::now() + Duration::from_millis(100))) {
    Ok(r) => println!("{r}, logged {:?}", store.state()),
    Err(Trap::Deadline) => eprintln!("too slow: make another store"),
    Err(t) => eprintln!("trapped: {t}"),
}

// Or, for a server: a pool of instances on threads of their own.
let pool = InstancePool::builder(module, linker, |_| Vec::new())
    .config(PoolConfig::default())
    .build()?;
pool.submit(
    |inst| {
        let run = inst.typed_func::<(), i32>("run")?;
        inst.call_typed(run, ()) // under the pool's per-call deadline
    },
    |r| { /* on the pool's thread: hand `r` back to the request's I/O thread */ },
)?;
```

Tests: the WebAssembly 2.0 specification suite, every command (`tests/spec`, converted by
`tools/wasm-spec/convert.sh` from `WebAssembly/testsuite`, Apache 2.0): 21 453 `assert_return`,
2 354 `assert_trap`, linking and instantiation; the proposals of refused features as refusal
checks; every load and run limit just under, at and over it; budgets; translation in linear time;
the linker, the caller's views, calls back into the guest, and each WASI function; fit's guests
(`tests/guests`, Go and Rust, rebuilt by `tests/guests/build.sh`): fit's header plugin, its sync
plugin and a Proxy-Wasm filter load, initialize and run, a loop stops at its deadline, growing
past the memory limit and panicking trap; the pool: a hung guest stopped at its deadline and its
instance remade, a full queue refused, a wait expiring, `submit_to` ahead of the shared queue, a
pool failed by an instance that will not start, closing with jobs queued. Fuzz targets `wasm_decode`, `wasm_exec` (modules from
`wasm-smith` under small limits, their imports calling back into them) and `wasm_diff` (against
wasmi) in `fuzz/`.

Next: W5 a performance pass, W6 akio-http's hooks for Proxy-Wasm's
response callbacks.
