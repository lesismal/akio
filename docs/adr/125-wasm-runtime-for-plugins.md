# ADR-125: A WebAssembly runtime for plugins: a safe interpreter in a crate of its own

English | [简体中文](125-wasm-runtime-for-plugins.zh-CN.md)

Status: accepted (2026-11-25). Built in the milestones of section 8; W1 (decoder and validator) and W2 (translation and interpreter) are done, see "As built" at the end.

## Context

akit (fit rebuilt in Rust on akio) has two iterations for WebAssembly plugins:

- **I71, WASM I: runtime and ABI.** A route runs a plugin on each request, sandboxed, on a pool of
  its own, with time and memory limits. Done when fit's header-editing plugin
  (`plugin/wasm/testdata/headers`) runs unchanged with a measured, bounded cost.
- **I72, WASM II: the Proxy-Wasm subset.** Done when fit's Proxy-Wasm tests, ported, pass.

akit uses no `unsafe` and no async runtime, and what akio lacks goes into akio (akit rule 21), so
the runtime is akio's to provide. akit asked for it as A165.

**What fit runs** (fit `7daee573`, `plugin/wasm`, decisions 017, 018 and 023):

- **The runtime is wazero** (pure Go, compiles to machine code on amd64 and arm64). Each plugin is
  compiled once per code hash and memory bound and shared across reloads; each instance has its own
  memory, bounded (`max_memory_bytes`, 128 MiB by default).
- **Plugins are WASI reactors**: Go (`GOOS=wasip1 -buildmode=c-shared`), TinyGo or Rust. Go's
  guest imports 17 `wasi_snapshot_preview1` functions (args, environ, clocks, `random_get`,
  `fd_write`, `poll_oneoff`, `proc_exit`, `sched_yield`, a few `fd_*` stubs).
- **fit's own ABI** (I71): the plugin exports `fit_on_request() -> i32` (0 go on, 1 answered) and
  imports from module `fit`: `header_get/set/add/del(kind, ...)`, `request_get(field, ...)`,
  `respond(status, body, len)` and `log(level, msg, len)`. Strings are a pointer and a length into
  the plugin's memory; a host call that breaks a bound (a field over 64 KiB, a body over 1 MiB,
  more than 256 response edits) fails the call. Edits to the response's fields are recorded and
  applied when its header is settled. The guest package also imports module `fit_sync` (sync's
  plugins), so every Go guest needs those names resolved even when it never calls them.
- **Proxy-Wasm v0.2.0/0.2.1**: root context with `vm_config` and plugin `config`; per request a
  context created, `proxy_on_request_headers`, then done, log, delete. Header maps (with
  `:method`, `:path`, `:authority`, `:scheme`), local responses, config buffers, properties,
  logging and metrics are implemented; since I81 (decision 023) also `proxy_on_response_headers`,
  `_body` and `_trailers`, on the pool, through fib's `OnHeaderAsync` and `OnBodyFilterAsync`.
  Calls out, shared data and queues, ticks, foreign functions, `set_property`, the request's body
  and trailer callbacks and resuming a paused stream answer `Unimplemented`.
- **The pool**: one goroutine per instance (CPUs, at most 16), a bounded queue (1024, then `503`),
  a wait timeout (1 s), a call timeout (100 ms) after which the call is stopped and the instance
  made again, `on_error: fail | skip`. A Proxy-Wasm context belongs to its instance, so a
  response's callbacks are queued to that instance, ahead of new requests, and an instance follows
  at most `max_streams` responses (1024).
- **Its cost**: fit's decision 018 records about 5 µs a request through a plugin and 8 µs through a
  Proxy-Wasm filter on the benchmark host.

**What the guests need from the runtime: a spike.** fit's three test guests built with Go 1.27
(`headers`, and the Proxy-Wasm SDK's `http_routing` and `http_body`), scanned opcode by opcode:

| Guest | Size | Functions | Instructions | Features used |
| --- | --- | --- | --- | --- |
| `headers` (fit ABI) | 4.6 MB | 2537 | 1.42 M | MVP, sign extension (`i64.extend32_s`, ...), saturating float-to-int, `memory.copy` / `memory.fill` |
| `http_routing` (Proxy-Wasm) | 2.9 MB | 1939 | 0.83 M | the same |
| `http_body` (Proxy-Wasm) | 2.6 MB | 1707 | 0.74 M | the same |

No multi-value blocks, no reference types, no SIMD, no threads; one table, eight globals, memory
of 37–48 pages (2.3–3 MiB) with no maximum. Rust's `wasm32-wasip1` target (1.82 and later) also
enables multi-value and reference types by default, and recent LLVM bulk memory and saturating
conversions; TinyGo uses the same set as Go.

**How much an interpreter costs: a second spike.** fit's own benchmarks on wazero's compiler and,
with nothing else changed (a `go test -overlay` that swaps `NewRuntimeConfig` for
`NewRuntimeConfigInterpreter`), on wazero's interpreter, in one run on an Apple M-series laptop
(macOS numbers are not used for decisions, rule 17; the same-run ratio is what matters here):

| Benchmark (fit `plugin/wasm`) | wazero compiler | wazero interpreter | Ratio |
| --- | --- | --- | --- |
| `BenchmarkGuestCall` (the headers plugin's call alone) | 3.6 µs | 29.6 µs | 8.1× |
| `BenchmarkWASM/plugin` (a request through it, pool hand-off included) | 5.5 µs | 32.8 µs | 6.0× |
| `BenchmarkProxyWasm` (a request through `http_routing`) | 13.3 µs | 84.0 µs | 6.3× |
| `BenchmarkWASM/none` (no plugin) | 0.29 µs | 0.31 µs | – |

wazero's interpreter is a plain stack machine over its own IR, built for portability rather than
speed; interpreters that translate to a register (slot) form first, such as wasmi's, are commonly
2–4× faster than that. A Go guest's call is mostly Go's runtime at work (allocation, write
barriers, string conversion), thousands of instructions for a handful of host calls; TinyGo and
Rust guests run the same plugin in far fewer.

**akio's constraints.** No async runtime; nothing blocks an I/O thread (rule 1); everything is
bounded and linear-time (rules 3, 4, 10); `unsafe` only in `akio-sys`, the backends, `akio-buf`
and `akio-crypto`'s named modules, every other crate `#![forbid(unsafe_code)]` (ADR-005,
`docs/unsafe-review.md`); a new dependency needs an ADR (rule 15), and akio has replaced every
library dependency it had with its own code (TLS, QUIC, deflate, regex, brotli, zstd), keeping
third-party crates only in `fuzz/` and `tools/` as references.

## Decision

### 1. An interpreter, in safe Rust, in a new crate `akio-wasm`

- **`akio-wasm`**, `#![forbid(unsafe_code)]`, with no third-party dependency (akio-log, and
  akio-crypto for `random_get`). Re-exported as `akio::wasm` behind the facade feature `wasm`.
- **An interpreter, not a compiler.** A module is decoded, validated and translated once, in one
  linear pass per function, into a register form: every WebAssembly value-stack position is a fixed
  slot in the frame (the stack height is static at each instruction), so an instruction reads and
  writes slots directly instead of pushing and popping; constants become immediates, a compare
  followed by `br_if` becomes one instruction, branch targets are resolved, and each basic block
  carries its instruction count for metering (section 3). Execution is a `match` loop over that
  form with explicit frames on a `Vec`, not native recursion: a guest's deep recursion is a trap,
  never a native stack overflow, and a host call cannot re-enter the guest.
- **Why an interpreter is enough for fit's use.** A plugin runs only on routes that configure one,
  on its own pool, never on an I/O thread, and its per-request work is small. The spike puts
  wazero's interpreter at 6–8× its compiler on fit's guests; a register interpreter should land
  at roughly 2–4× (to be measured, milestone W5), a few microseconds over fit's 5 µs, bounded per
  call. That is a cost on plugin routes, not on every request. Guests built with TinyGo or Rust
  are much cheaper per call than Go's, and the plugin guide will say so.
- **Why not a compiler.** A compiler that emits machine code needs `unsafe` and executable
  memory: mapping pages writable then executable (W^X, `MAP_JIT` and
  `pthread_jit_write_protect_np` on Apple silicon, an instruction-cache flush on aarch64) in
  `akio-sys`, calling generated code through a function pointer, and two code generators (x86_64,
  aarch64), about 15–25 thousand lines whose every bug is memory unsafety in the gateway process,
  reachable by whoever supplies a plugin. Bounds checks would be explicit in the generated code
  (guard pages need signal handlers, process-wide state akio does not take). **If** W5 shows the
  interpreter's cost blocks akit's benchmark row, a compiler is a separate ADR, living in an
  `akio-wasm::jit` module with `#![deny(unsafe_code)]` allowed only there, the page mapping in
  `akio-sys`, and the interpreter as the reference it is fuzzed against. It is not planned.
- **Why not a third-party runtime.** wasmtime (Cranelift) is a compiler with the risks above and
  over a hundred crates; wasmi is a mature interpreter but uses `unsafe` in its executor and is a
  third-party dependency in a library that has left all of them. Both stay useful outside the
  libraries: as differential references in `fuzz/` and as baselines in `tools/` (section 6).

### 2. Which WebAssembly

- **Supported**: WebAssembly 1.0 (MVP) plus mutable globals, sign-extension operators,
  non-trapping (saturating) float-to-int conversions, bulk memory (`memory.copy`, `memory.fill`,
  `memory.init`, `data.drop`, and the table operations), multi-value (functions and blocks) and
  reference types (`funcref`, `externref`, several tables, `table.get/set/size/grow/fill`). That
  is what Go, TinyGo and Rust's `wasm32-wasip1` emit by default today. One memory, 32-bit.
- **Refused at load, with an error naming the feature**: fixed-width SIMD (236 instructions; no
  guest in fit's tests uses it, a later ADR may add it), threads and atomics, exception handling,
  tail calls, 64-bit memories, several memories, extended constant expressions, typed function
  references and GC, relaxed SIMD, the component model.
- **Floats** follow the specification: `f32`/`f64` arithmetic as Rust's, `nearest` as
  `round_ties_even`, `min`/`max` with WebAssembly's NaN and signed-zero rules, NaN payloads
  canonical. Execution is deterministic but for the clock and random host functions.

### 3. The host API, and how a call stays bounded

The shape (names to be settled when built):

```rust
// Load: decode, validate, translate. Linear in the module's size; run on a pool, never on a loop.
let module: Arc<Module> = Module::new(&bytes, &ModuleLimits::default())?;

// Host functions, typed, resolved by (module, name) when an instance is made.
let mut linker: Linker<State> = Linker::new();
linker.func("fit", "header_get", &[I32; 5], &[I32], |caller: &mut Caller<State>, args, results| {
    let name = caller.memory().slice(args[1].u32(), args[2].u32())?; // bounds-checked view
    ...
    Ok(())
})?;
linker.wasi_preview1(WasiConfig::default())?; // the subset below
linker.trap_unresolved(true);                 // unused imports (fit_sync) trap only if called

// An instance: its memory, tables, globals and host state; `Send`, not `Sync`.
let mut inst: Instance<State> = linker.instantiate(&module, state, &InstanceLimits { .. })?;
let f = inst.export_func("fit_on_request")?;          // checked against its type once
let r = inst.call(f, &[], &mut out, Budget::deadline(Instant::now() + timeout))?;
```

- **Memory** is a `Vec<u8>` per instance, grown by `memory.grow` up to
  `InstanceLimits::max_memory` (128 MiB by default, as fit's); a grow past it returns `-1` as the
  specification says. Each load and store checks its range; host functions see the memory through
  bounds-checked slices only (`Caller::memory().slice/write`), so a pointer and length from the
  guest can never reach outside it.
- **Limits on loading**, each checked as the module is decoded, so validation is linear and a
  hostile module is refused early: module size (64 MiB), functions (100 000), imports and exports
  (10 000 each), locals per function (50 000), block nesting (1 000), `br_table` targets
  (100 000), table size (10 M elements), data and element segments (100 000), and the translated
  form at most a fixed multiple of the input.
- **Limits on running**: the value stack in slots (1 Mi slots, 8 MiB) and the call depth
  (10 000 frames), both traps when passed; memory as above; tables to their declared maximum and
  `max_table_elements`.
- **Metering**: each basic block's first instruction subtracts the block's instruction count from
  a counter held in the interpreter's loop. When the counter runs out the interpreter checks the
  call's **budget**: its deadline (`Instant::now()` against it), its fuel if one was set, and an
  interrupt flag the owner may raise from another thread (`InterruptHandle`, an `Arc<AtomicBool>`);
  if all allow, it refills the counter with a slice (about 10 000 instructions, tens of
  microseconds) and goes on, otherwise it traps (`Trap::Deadline`, `OutOfFuel`, `Interrupted`).
  Loops cannot escape it (every back edge starts a block), and no watchdog thread is needed: a call
  stops within one slice of its deadline. Host functions are bounded by their own limits and may
  read the budget (a `poll_oneoff` sleep ends at the deadline).
- **A trap ends the instance.** Its memory may be half-updated, so an instance that trapped is
  dropped and a new one made (as fit does), by whoever owns it; making it again, Go's `_initialize`
  included, has its own deadline (`init_timeout`, 1 s by default).
- **WASI preview 1, a subset** (`Linker::wasi_preview1`): empty `args` and `environ` unless given;
  `clock_time_get` (realtime and monotonic); `random_get` from akio-crypto's generator;
  `fd_write` on 1 and 2 to a caller-supplied sink (akit sends it to its log, rate limited);
  `poll_oneoff` for clock subscriptions only, sleeping no later than the call's deadline (it runs
  on a pool thread); `sched_yield` a no-op; `proc_exit` a trap; no preopened directories, every
  other `fd_*` and `path_*` call `EBADF` or `ENOSYS`. No file system, no sockets.

### 4. Where calls run: never on an I/O thread

- Loading (`Module::new`) and making instances run on akio's logical pool or the plugin pool,
  never on a loop: Go guests are megabytes and thousands of functions.
- **`akio_wasm::InstancePool<S>`**: a fixed number of threads, each owning one instance (instances
  are not `Sync`), as fit's pool has goroutines:
  - `submit(job) -> Result<(), Overloaded>` to any free instance through one bounded queue
    (`queue`, 1024 by default); a job not started within `wait_timeout` is handed back as expired
    (akit answers `503`);
  - `submit_to(instance, job)` to a given instance, through that instance's own bounded queue,
    served before the shared one: a Proxy-Wasm context belongs to the instance that made it, so a
    response's callbacks go back to it;
  - each job runs as `FnOnce(&mut Instance<S>) -> R` with the pool's per-call deadline, and its
    result goes back by a completion the caller gives (akit resumes the request with it, from that
    thread, through akio-http's `Suspended::resume`);
  - a trap drops the instance and makes it again before the thread takes its next job, and an
    instance that keeps failing to start marks the pool failed (every job then gets that error);
  - stats (queued, running, remade, expired, traps by kind), for akit's metrics.
- Memory is bounded per pool: instances × `max_memory`, plus the shared translated module.

### 5. Proxy-Wasm on akio-http's hooks

The ABI layers themselves, fit's own and Proxy-Wasm's, are akit's (`akit-plugin`): they are host
functions over the safe API above, need no `unsafe`, and are a gateway's policy. What akio has to
provide is how a request and its response reach the pool and come back:

| Proxy-Wasm | akio-http | Status |
| --- | --- | --- |
| `proxy_on_context_create` (root), `proxy_on_vm_start`, `proxy_on_configure` | none: run when an instance is made, on the pool | – |
| `proxy_on_context_create`, `proxy_on_request_headers` | `Context::suspend()` → `InstancePool::submit` → `Suspended::resume(f)` from the pool thread, which goes on to the next handler (ADR-109) | exists |
| `proxy_get_header_map_value`, `_pairs` on the request | `Suspended::req()` while the call runs | exists |
| `proxy_add/replace/remove_header_map_value`, `set_header_map_pairs` on the request, `:path`, `:method`, `:authority` | applied in `resume` through `Context::req_mut` | **A33** (requested by akit I40) |
| the same on the response, in the request phase | recorded, applied by a response filter (`add_response_filter`) as the header is settled | exists |
| `proxy_send_local_response` | `Context::respond` in `resume` | exists |
| `proxy_get_property`, `proxy_get_buffer_bytes` (config), `proxy_log`, metrics | host state only | – |
| `proxy_on_response_headers` | a response filter that holds the head until a call elsewhere hands it back, with a deadline; the body held meanwhile within the response's bound | **new (H1)** |
| `proxy_on_response_body`, `proxy_on_response_trailers` | a streamed body filter whose calls complete elsewhere, one at a time, through a `done` callback; the writer paced as by a slow client (pending bytes past the watermark hold the producer, rule 8); the last call carries the trailers, which it may change; the body may be held up to `max_body_bytes` (1 MiB) | **new (H2)** |
| `proxy_on_done`, `proxy_on_log`, `proxy_on_delete` | when the response has gone or the client went: a body tap's `end` (ADR-116) for streamed bodies, or akio-http's end-of-request hook | tap exists; **A48** (requested by akit I41) for the rest |
| request body and trailer callbacks, `proxy_http_call`, shared data and queues, ticks, foreign functions, `set_property`, `continue_stream` | not in fit either: `Unimplemented` | – |

H1 and H2 are fit's A41 (`OnHeaderAsync`) and A46 (`OnBodyFilterAsync`) in akio's shape, for
HTTP/1.1, HTTP/2 and HTTP/3, whole and streamed bodies, files sent by `sendfile` included (which
then go through the filter as reads, or bypass it when the plugin asks for headers only). They are
designed in detail, and requested from akit, when I72 starts; until then a Proxy-Wasm filter's
response callbacks are not called (fit's state before its I81). A request whose body is streamed
cannot be suspended (ADR-109); a plugin route asks for the body whole within its limit, or waits
for A75.

### 6. Dependencies

`akio-wasm` has none outside akio. Third-party crates appear only where akio already allows them,
outside the libraries:

- `fuzz/`: `wasm-smith` (generates valid modules from fuzzer bytes, with the feature set of
  section 2) and `wasmi` as the differential reference;
- `tools/wasm-spec/`: a script that converts the official specification tests (`.wast`) to JSON
  commands and binary modules with `wasm-tools json-from-wast`, run by hand when the pinned
  test-suite commit moves, its output committed (no tool is needed to run the tests);
- `tools/wasm-bench/` (not published): wasmi and, for scale, wasmtime, against `akio-wasm` on
  fit's guests.

### 7. Testing

- **The specification's test suite** (`WebAssembly/testsuite`, Apache 2.0, pinned commit),
  converted as above and run by a test in `akio-wasm` that reads the commands: `module`,
  `register`, `invoke`, `assert_return` (with NaN classes), `assert_trap`, `assert_exhaustion`,
  `assert_invalid`, `assert_malformed` (binary modules only), `assert_unlinkable`. Every file of the
  core suite and of the proposals adopted in section 2 runs; the files of refused features are
  listed as skipped with the reason, and must fail validation, not crash.
- **Fuzzing**, three cargo-fuzz targets in `fuzz/`, with minimized corpora replayed by stable tests
  as for akio's other targets: `wasm_decode` (arbitrary bytes: decode and validate never panic,
  stay linear, and honour the load limits), `wasm_exec` (`wasm-smith` modules run with small
  budgets: no panic, every limit traps cleanly) and `wasm_diff` (the same modules and inputs on
  `akio-wasm` and `wasmi`: same results, same traps, same memory after the call). 16 minutes a
  target on the benchmark host when built, then in the nightly job.
- **Guests**: fit's `headers`, `http_routing`, `http_body`, `properties` and `response` guests and
  its Rust sync guest, built with Go, TinyGo and Rust, run through a test linker; Go's
  `_initialize` and a call under a budget; `/loop` stops at its deadline, `/grow` fails at the
  memory limit, `/panic` traps; the instance is made again after each.
- **Limits** just under, at and over, for each limit in section 3; a module at each load limit
  loads in linear time (a test with a time bound, rule 21).
- **InstancePool**: the queue full, a wait expiring, `submit_to` ahead of the shared queue, an
  instance remade after a trap, a pool failed by an instance that will not start, shutdown with
  jobs queued.
- No test needs Miri or the sanitizers: the crate is safe Rust. Integer overflow in the
  interpreter's own arithmetic (addresses, counters) is checked by the tests in debug builds and
  by the fuzz targets, which build with overflow checks on.

### 8. Milestones

Each milestone is an akio branch with its tests; sizes are lines of Rust (tests excluded) and the
work of one session.

| # | Milestone | Size | For |
| --- | --- | --- | --- |
| W1 | Decoder and validator for section 2's features, the load limits, `wasm_decode` fuzz target | ~3 000 lines, 1–2 days | I71 |
| W2 | Translation to the register form and the interpreter: numerics, memory, tables, globals, calls, traps, metering and budgets; the specification suite passing; `wasm_exec` and `wasm_diff` | ~6 000 lines, 3–5 days | I71 |
| W3 | The host API (`Linker`, `Caller`, typed host functions, unresolved imports that trap), WASI preview 1's subset; fit's guests (Go, TinyGo, Rust) load, initialize and run | ~2 000 lines, 1–2 days | I71 |
| W4 | `InstancePool`: threads owning instances, the shared and per-instance bounded queues, deadlines, remaking, stats | ~1 000 lines, 1 day | I71 |
| W5 | Performance pass: fused instructions for the common sequences Go emits, local slots in registers of the loop, measured on the benchmark host against fit (wazero) by a benchmark task; the row in DEV-PLAN section 4 | 1–2 days, plus the benchmark task | I71's "measured, bounded cost" |
| W6 | akio-http H1 and H2 (held response heads, asynchronous body filters) over HTTP/1.1, h2 and h3, with A48 if still open | ~1 500 lines, 2–3 days | I72 |

**I71** needs W1–W4 (and A33 for request edits; W5 to report its cost); akit's side is then
`akit-plugin` with fit's ABI and its pool on `InstancePool`, a few days. **I72**'s request phase
needs nothing more; its response phase needs W6. In all, about 13 000 lines in akio over two to
three weeks of sessions, the larger part (W1–W2) a self-contained interpreter that can be built and
tested before akit uses it.

## Consequences

- akio gains a sandbox for untrusted code with no `unsafe` in it: a bug in the interpreter is a
  wrong result or a trap, not memory corruption in the gateway; `docs/unsafe-review.md` does not
  change.
- Plugins cost more per call than in fit (interpreted against compiled), bounded by the pool and
  the call's deadline, on plugin routes only; W5 says how much. The path to a compiler stays open
  and documented, behind its own ADR.
- Loading a plugin is linear in its size and done off the loops; a reload of the same code reuses
  the translated module (shared, keyed by hash and limits, as fit does).
- What akio-http gains for I72 (H1, H2) serves any filter that must think about a response off the
  loop, not only WASM.
- Open until built: the exact API names, the fuel slice, and whether `externref` is worth keeping
  before a guest needs it (it costs little; the specification tests cover it).

## As built

### W1: decoder and validator (2026-11-25)

Crate `akio-wasm` (`#![forbid(unsafe_code)]`, no dependencies): `Module::new(&bytes, &ModuleLimits)`
decodes and validates in one pass, bodies validated as they are decoded; `Module` describes the
imports, exports, types, functions, tables, memory, globals and start function, and keeps the
code for W2. Refusals are an `Error` with an `ErrorKind` (`Malformed`, `Invalid`,
`Unsupported(Feature)`, `Limit(Limit)`), the byte offset and the specification's wording. The
facade re-exports it as `akio::wasm` behind the feature `wasm`. Decided while building it:

- **The specification tests are WebAssembly 2.0's**: `WebAssembly/testsuite` pinned at
  `a8101597` (2025-09-11), the last commit whose top level is the 2.0 suite; after it the top level
  is the 3.0 draft, which re-tests 2.0 under 3.0's rules (any immutable global in a constant
  expression, for one) that section 2 does not adopt. All 2.0 files run;
  its `simd_*` files and the proposals of refused features (threads, relaxed SIMD, custom page
  sizes, wide arithmetic, and the 3.0 draft's files for memory64, multi-memory, tail calls,
  exceptions, GC and typed function references) run as refusal checks: every module accepted or
  refused as unsupported, none refused as malformed or invalid. One exception: the threads
  proposal predates reference types, so its three "multiple tables" modules are valid here. The
  converted suite is 5.7 MB in `crates/akio-wasm/tests/spec` (excluded from the published crate);
  `tools/wasm-spec/convert.sh` drops the action commands of the refused files, which could never
  run. W1 runs the decoding and validation commands (1 598 modules, 2 146 `assert_invalid`, 719
  binary `assert_malformed`, 117 modules that fail only when linked or instantiated); the rest
  waits for W2.
- **Constant expressions follow 2.0**: `global.get` names an imported, immutable global only.
- **Load limits beyond section 3's list**, so that every count is bounded: types (100 000),
  parameters and results of a type (1 000 each), tables (100), globals (100 000). The table
  limit (10 M) bounds a table's initial size; its maximum may be larger, and growing it is an
  instance's limit (W3). "The translated form at most a fixed multiple of the input" is W2's.
  Locals count the parameters. A local count past `u32::MAX` is malformed before it is over the
  limit, as the specification has it.
- **Refused features**: as section 2, plus custom page sizes and wide arithmetic, each named.
  Relaxed SIMD is reported as SIMD: its instructions take `v128` values, so a module meets SIMD
  first.
- **The crate is experimental** (docs/api-stability.md) until W4 settles its API; the snapshot
  `api/akio-wasm.txt` makes changes visible. The facade's `wasm` feature is outside akio's
  snapshot, as `dpdk` is.
- **Fuzzing**: `wasm_decode` loads each input under the default limits and under small ones; a
  module accepted under the small limits is inside each, and one refused under them for another
  reason than a limit is refused the same way, at the same offset, under the defaults.

### W2: translation and interpreter (2026-11-25)

Each body is translated right after it is validated, in the same pass over the module, to the
register form of section 1 (`instr.rs`, `translate.rs`); `exec.rs` runs it. The whole
WebAssembly 2.0 specification suite now passes, every command: 21 453 `assert_return`,
2 354 `assert_trap`, 15 `assert_exhaustion`, 83 `assert_unlinkable`, 34
`assert_uninstantiable`, `register` and the `spectest` imports. Fuzz targets `wasm_exec` and
`wasm_diff` (against wasmi 2.0) are in `fuzz/`. Decided while building it:

- **A `Store<S>` rather than an `Instance<S>`.** Section 3's sketch makes an instance own its
  memory, tables and globals. W2 puts them in a `Store<S>` that holds instances, host functions
  and the host's state, with handles (`Func`, `Memory`, `Table`, `Global`, `Instance`) into it,
  because WebAssembly lets one instance import another's memory, tables, globals and functions
  and see the same objects (the suite's `register` and linking tests need it; a table shared by
  two instances holds functions of both). A plugin's store holds one instance; the pool (W4)
  owns one store per thread, and W3's `Linker` instantiates into a store. The store is `Send`,
  not `Sync`. Handles of another store are refused by calls (`Trap::BadCall`) and make the
  accessors panic, as in wasmtime.
- **A trap ends the store**, enforced: later calls and instantiations return `Trap::Ended`
  (section 3 left it to the owner). `Store::set_trap_ends(false)` keeps the specification's
  semantics, where a store goes on after a trap; the suite runs that way, nothing else should.
  `Trap::BadCall` (arguments of the wrong number or type) runs nothing and ends nothing.
- **`Trap`** is an enum: the specification's traps (with its wording from `message()`),
  `CallStackExhausted` and `ValueStackExhausted` for the two run limits, `Deadline`,
  `OutOfFuel`, `Interrupted`, `Host(message)` for a host function's failure, and the two
  refusals. Instantiation fails with `InstantiateError::{Unlinkable, Limit, Trap}`; what the
  active segments before a failing one wrote stays written, as in 2.0.
- **The register form**: a frame is the function's locals, then one slot per position of the
  operand stack; instructions are 16 bytes and name slots. The translator keeps a stack of where
  each value is: in its slot, still in a local (`local.get` emits nothing until the local changes,
  then every pending read is copied first), or a constant (an immediate for the `i32` and `i64`
  operations that have one). An instruction whose result goes to a `local.set` writes the local
  directly; a comparison followed by `br_if` or `if` is one instruction; a call's arguments are
  already where the callee's frame starts, and its results come back there. Blocks with params
  and results move values only on a branch to a label lower in the stack (`CopyRange`), and
  `br_table` targets that move values get a stub each. Unreachable code is skipped.
- **The translated form's bound** is structural: every WebAssembly instruction emits at most
  three instructions, counting the materialization of the value it pushed, so a body is at most
  `4 × bytes + 4` instructions, checked; no `ModuleLimits` field is needed. Translation is linear:
  pending reads of locals are kept in a list and each is copied at most once (a test builds the
  quadratic case for a careless translator, 20 000 locals read then set, and a 20 000-target
  `br_table` whose every target moves two values). The module drops the code bytes once
  translated.
- **Metering**: a `Fuel(n)` instruction starts the function and every basic block a branch can
  reach (loop heads, labels with incoming branches, `else`), with `n` the WebAssembly instructions
  up to the next one. Fuel counts WebAssembly instructions; besides, bulk memory instructions,
  `memory.grow` and the zeroing of a call's locals take one unit per 64 bytes, and table
  instructions one per eight elements, so a slice stays short in time too. The slice is
  `Budget::SLICE`, 10 000. Fuel is exact: a block that cannot be paid for does not start
  (`OutOfFuel`), and `Store::fuel_used()` reports the last call's use. The first block of a call
  checks the budget, so a call past its deadline does not start.
- **Running limits** (`InstanceLimits`, section 3's values): `max_memory` (bytes, 128 MiB) and the
  memory's declared maximum, `max_table_elements` (10 M) for `table.grow` and tables made at
  instantiation, `max_value_stack` (1 Mi slots) checked on each call against the callee's whole
  frame, `max_call_depth` (10 000). A grow whose allocation fails returns `-1` too
  (`try_reserve`), so an allocation failure never aborts the process.
- **Floats**: an arithmetic result that is a NaN is the canonical NaN (positive, quiet), so
  results do not depend on the hardware's NaN propagation (x86 and Arm differ); `abs`, `neg`,
  `copysign`, loads, stores and reinterpretations keep the bits.
- **Values**: `Value::{I32, I64, F32, F64, FuncRef(Option<Func>), ExternRef(Option<ExternRef>)}`,
  floats as Rust's floats (their bits pass unchanged). `externref` is kept (section 3's open
  question): it costs nothing in the interpreter, and an `ExternRef` is a `u32` the host gives
  meaning to.
- **Host functions, the minimum for W2**: `Store::func_new(FuncType, Fn(&mut Caller<S>, &[Value],
  &mut [Value]) -> Result<(), Trap>)`, with `Caller::state(_mut)` and `memory(_mut)` (the calling
  instance's memory as a slice). They cannot call back into the guest. W3 adds the `Linker`, typed
  host functions, bounds-checked views and unresolved imports that trap.
- **Fuzzing**: `wasm_exec` generates modules with `wasm-smith` (section 2's features, at most one
  memory, small sizes) and checks that each loads (translation never refuses a valid module) and
  runs under small limits and fuel: results of the right type, or a trap that ended the store.
  Its stable replay runs `fuzzing::exec` over `wasm_decode`'s corpus, whose inputs are modules
  (`wasm_exec`'s are `wasm-smith`'s seeds). `wasm_diff` runs the same module (no imports) on
  akio-wasm and wasmi (its `deterministic` feature canonicalizes arithmetic NaNs as akio-wasm
  does, and its portable dispatch, since the tail-call one recurses natively under ASan), calls
  each export with the same arguments, and compares results (float bits exactly), traps, then
  every exported global and memory;
  running out of akio-wasm's fuel or either side's stack ends the comparison, their limits being
  different.
  Neither target's corpus is committed: their inputs are `wasm-smith` seeds, tens of megabytes
  once minimized, that only a `wasm-smith` build can turn into modules; a run grows them anew.

