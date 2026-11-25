#![forbid(unsafe_code)]
#![warn(clippy::unwrap_used)]
//! A WebAssembly runtime for plugins, in safe Rust without dependencies (ADR-125): a module is
//! decoded and validated once, translated to a register form and run by an interpreter, with
//! every resource bounded. It is the runtime under akit's WASM plugins (fit's ABI and
//! Proxy-Wasm), and is built in milestones; this release has the first, **W1**: the decoder and
//! the validator, with their load limits.
//!
//! ```
//! use akio_wasm::{Module, ModuleLimits, ExportKind};
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
//! let module = Module::new(&bytes, &ModuleLimits::default()).unwrap();
//! let add = module.export("add").unwrap();
//! assert_eq!(add.kind, ExportKind::Func);
//! assert_eq!(module.func_type(add.index).unwrap().to_string(), "(func (param i32 i32) (result i32))");
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
//! # Cost
//!
//! [`Module::new`] reads the bytes once: sections, then each function body is validated as it is
//! decoded, in time linear in the module's size. Every count is checked against
//! [`ModuleLimits`] before anything is allocated for it, so a hostile module is refused early and
//! cheaply: module size, types and their arity, functions, imports, exports, tables and their
//! initial size, globals, locals per function, block nesting, `br_table` targets, element and
//! data segments. A module is large (Go guests are megabytes); load it off the I/O threads.

mod error;
mod limits;
mod module;
mod ops;
mod reader;
mod types;
mod validate;

#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use error::{Error, ErrorKind, Feature, Limit};
pub use limits::ModuleLimits;
pub use module::Module;
pub use types::{
    Export, ExportKind, ExternType, FuncType, GlobalType, Import, Limits, MemoryType, RefType,
    TableType, ValType,
};
