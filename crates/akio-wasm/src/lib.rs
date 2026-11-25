#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! A WebAssembly runtime for plugins, in safe Rust without third-party dependencies (ADR-125): a
//! module is decoded, validated and translated once, to a register form that an interpreter runs,
//! with every resource bounded. It is the runtime under akit's WASM plugins (fit's ABI and
//! Proxy-Wasm), and is built in milestones; this release has **W1**, the decoder and the validator,
//! **W2**, the translation and the interpreter, with metering and budgets, **W3**, the host API
//! (a [`Linker`], typed host functions, WASI preview 1's subset), and **W4**, the
//! [`InstancePool`] that runs calls on threads of its own.
//!
//! ```
//! use std::{sync::Arc, time::{Duration, Instant}};
//! use akio_wasm::{Budget, InstanceLimits, Module, ModuleLimits, Store, Value};
//!
//! // (module (func (export "add") (param i32 i32) (result i32)
//! //   local.get 0 local.get 1 i32.add))
//! let bytes = [
//!     0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
//!     0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // type section
//!     0x03, 0x02, 0x01, 0x00, // function section
//!     0x07, 0x07, 0x01, 0x03, b'a', b'd', b'd', 0x00, 0x00, // export section
//!     0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b, // code section
//! ];
//! // Load once (off the I/O threads: linear in the module's size), share between instances.
//! let module = Arc::new(Module::new(&bytes, &ModuleLimits::default()).unwrap());
//! assert_eq!(module.func_type(0).unwrap().to_string(), "(func (param i32 i32) (result i32))");
//!
//! // A store holds instances and the host's state; a trap ends it.
//! let mut store = Store::new((), InstanceLimits::default());
//! let inst = store.instantiate(&module, &[], &Budget::unlimited()).unwrap();
//! let add = store.export_func(inst, "add").unwrap();
//! let mut out = [Value::I32(0)];
//! let budget = Budget::deadline(Instant::now() + Duration::from_millis(100));
//! store.call(add, &[Value::I32(2), Value::I32(40)], &mut out, &budget).unwrap();
//! assert_eq!(out, [Value::I32(42)]);
//!
//! // A module that does not validate is refused, with the reason and the offset.
//! let mut bad = bytes;
//! bad[39] = 0x7c; // i64.add on two i32s
//! let err = Module::new(&bad, &ModuleLimits::default()).unwrap_err();
//! assert_eq!(err.message(), "type mismatch");
//! ```
//!
//! # What WebAssembly
//!
//! WebAssembly 2.0 without SIMD: 1.0 (MVP) plus mutable globals, sign-extension operators,
//! non-trapping float-to-int conversions, bulk memory, multi-value and reference types
//! (`funcref`, `externref`, several tables), with one 32-bit memory. That is what Go, TinyGo and
//! Rust's `wasm32-wasip1` emit by default. A module using anything else is refused at load with
//! [`ErrorKind::Unsupported`] naming the [`Feature`]: fixed-width and relaxed SIMD, threads and
//! atomics, exception handling, tail calls, 64-bit memories, several memories, extended constant
//! expressions, typed function references and GC, custom page sizes, wide arithmetic and
//! component-model binaries. Validation follows the specification (its 2.0 test suite's decoding
//! and validation commands pass, `tests/spec.rs`).
//!
//! Floats follow the specification: `nearest` rounds ties to even, `min` and `max` have
//! WebAssembly's NaN and signed-zero rules, and an arithmetic NaN result is the canonical NaN, so
//! results do not depend on the host's hardware. Execution is deterministic.
//!
//! # Loading
//!
//! [`Module::new`] reads the bytes once: sections, then each function body is validated as it is
//! decoded and then translated, in time linear in the module's size. Every count is checked
//! against [`ModuleLimits`] before anything is allocated for it, so a hostile module is refused
//! early and cheaply: module size, types and their arity, functions, imports, exports, tables and
//! their initial size, globals, locals per function, block nesting, `br_table` targets, element
//! and data segments. The translated form is at most four 16-byte instructions per byte of code.
//! A module is large (Go guests are megabytes); load it off the I/O threads.
//!
//! # Running
//!
//! Each function is translated to a register form: every position of WebAssembly's operand stack
//! is a fixed slot in the frame, so an instruction reads and writes slots instead of pushing and
//! popping; `local.get` copies nothing, constants become immediates, a comparison followed by a
//! branch is one instruction, branch targets are resolved. The interpreter is a `match` loop
//! over it with explicit frames on a `Vec`, never native recursion: deep recursion is a trap
//! ([`Trap::CallStackExhausted`]), not a stack overflow. A host function that calls back into
//! the guest nests one native call of the loop, at most 64 deep.
//!
//! A [`Store`] holds instances, the host's functions ([`Store::func_new`]) and its state; it is
//! `Send`, not `Sync`. Every resource is bounded by [`InstanceLimits`]: each memory (128 MiB;
//! `memory.grow` past it returns `-1`), each table (10 M elements), the value stack (1 Mi slots)
//! and the call depth (10 000). Each call runs under a [`Budget`]: a deadline, fuel and an
//! [`InterruptHandle`], checked about every [`Budget::SLICE`] instructions as basic blocks are
//! entered, so a call stops within tens of microseconds of its deadline and loops cannot escape.
//! Every load and store is bounds-checked, and host functions see memory through slices only.
//!
//! **A trap ends the store**: the memory may be half-updated, so later calls return
//! [`Trap::Ended`]; drop it and make a new one.
//!
//! # Host functions
//!
//! A [`Linker`] holds host functions by module and name, and instantiates modules into stores
//! with them, each import checked against its definition's type. It belongs to no store and is
//! `Send + Sync`, to be shared by a pool's threads. [`Linker::func_wrap`] takes a typed closure
//! (`|caller, (ptr, len): (u32, u32)| -> Result<i32, Trap>`; see [`WasmTy`]),
//! [`Linker::func_new`] one over [`Value`]s. With [`Linker::trap_unresolved`], a function import
//! nothing defines resolves to one that traps when called (fit's Go guests import ABIs they never
//! call). [`Store::typed_func`] checks an export's type once, for [`TypedFunc::call`].
//!
//! A host function gets a [`Caller`]: the store's state, the calling instance's exports, and its
//! memory through bounds-checked views ([`Caller::read`], [`Caller::write`], [`Caller::read_u32`]
//! ...), so a pointer and a length from the guest never reach outside it. It may call back into
//! the guest ([`Caller::call`]), to have it allocate memory for a result as Proxy-Wasm's hosts
//! do: the call runs on top of the frames below, under the same budget and limits, nested at most
//! 64 deep, and a trap in it ends the outer call too. It may read the call's deadline and
//! interrupt, and charge it fuel ([`Caller::consume_fuel`]).
//!
//! # WASI
//!
//! [`Linker::wasi_preview1`] defines `wasi_snapshot_preview1`'s 46 functions, the subset a plugin
//! needs ([`WasiConfig`]): arguments and environment (none by default), the realtime and
//! monotonic clocks, the operating system's random bytes, standard output and error to a sink
//! (discarded by default), an empty standard input, `poll_oneoff` sleeping on clocks no later than
//! the call's deadline, `proc_exit` as [`Trap::Exit`]. No file system and no sockets: there are no
//! preopened directories, and the other functions return `EBADF` or `ENOSYS`. A WASI reactor
//! (Go's `-buildmode=c-shared`, TinyGo's, a Rust `cdylib`) is initialized once, with
//! [`Store::initialize_reactor`], before its other exports are called.
//!
//! # The instance pool
//!
//! A store is not `Sync`, and WebAssembly must not run on an I/O thread: an [`InstancePool`]
//! has a fixed number of threads, each owning one instance of a module (its store, its memory),
//! made with a [`Linker`] they share. An I/O thread [`submit`](InstancePool::submit)s a job,
//! `FnOnce(&mut Pooled<S>) -> R`, and goes on; the job runs on a free instance under a per-call
//! deadline ([`PoolConfig::call_timeout`]), and its result goes to a completion the caller gave,
//! run on the pool's thread, which hands it back to the I/O thread without blocking (akio-http's
//! `Suspended::resume`, a `ResponseSlot`, a channel a loop reads). The queues are bounded: one
//! shared, and one per instance for [`submit_to`](InstancePool::submit_to) (a Proxy-Wasm
//! context's later callbacks), served first; a full queue refuses the job at once
//! ([`Refused`]), and a job that waited past [`PoolConfig::wait_timeout`] is handed back as
//! [`JobError::Expired`]. An instance a trap ended (a guest past its deadline included) is
//! dropped and made again before its thread's next job; one that will not start fails the pool.
//! [`InstancePool::stats`] counts calls, traps by kind, remakes, expiries and refusals.

mod budget;
mod error;
mod exec;
mod instr;
mod limits;
mod linker;
mod module;
mod ops;
mod pool;
mod reader;
mod store;
mod translate;
mod trap;
mod typed;
mod types;
mod validate;
mod value;
pub mod wasi;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use budget::{Budget, InstanceLimits, InterruptHandle};
pub use error::{Error, ErrorKind, Feature, Limit};
pub use limits::ModuleLimits;
pub use linker::{LinkError, Linker};
pub use module::Module;
pub use pool::{
    InstanceId, InstancePool, JobError, PoolBuilder, PoolConfig, PoolStats, Pooled, Refusal,
    Refused, StartError, TrapStats,
};
pub use store::{Caller, InstantiateError, Store};
pub use trap::Trap;
pub use typed::{TypedFunc, WasmParams, WasmResults, WasmTy};
pub use types::{
    Export, ExportKind, ExternType, FuncType, GlobalType, Import, Limits, MemoryType, RefType,
    TableType, ValType,
};
pub use value::{Extern, ExternRef, Func, Global, Instance, Memory, Table, Value};
pub use wasi::{OutputStream, WasiConfig};
