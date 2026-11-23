//! Synchronisation primitives: `std` normally, `loom` under `--cfg loom` so that the
//! connection protocols can be model-checked.

#[cfg(not(loom))]
pub(crate) use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
};

#[cfg(loom)]
pub(crate) use loom::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
};
