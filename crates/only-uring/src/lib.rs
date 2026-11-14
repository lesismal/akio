//! The io_uring backend (Linux 5.19+).
//!
//! One `UringGroup` serves one listener with a set of I/O threads, each owning a ring.
//!
//! * Accept: per-thread `SO_REUSEPORT` listeners, each with one multishot `accept` in flight.
//! * Read: one multishot `recv` per connection, fed from a per-thread *provided-buffer ring*, so
//!   idle connections hold no buffer; `on_data` borrows the kernel-selected buffer, which goes back
//!   to the ring when the callback returns (a memory write, no syscall).
//! * Ring setup: cooperative + deferred task-run and single-issuer where the kernel allows it.
//! * Write: shared with the other backends (`ConnInner` writes straight to the socket from any
//!   thread and queues the rest); a one-shot `poll(POLLOUT)` is armed while a queue is waiting.
//! * Backpressure and `hold_reads` cancel the multishot `recv` and re-arm it on resume.
//! * Wake-up: an eventfd read that other threads signal after posting a command.
//!
//! Not used: `SEND_ZC`, registered files, `MSG_RING` wake-up.
//!
//! Guide: [Engine, listeners and backends](https://lesismal.github.io/flash/en/concepts/engine.html)
//! (中文: [Engine、Listener 与后端](https://lesismal.github.io/flash/zh-CN/concepts/engine.html)).
#![cfg(target_os = "linux")]
#![warn(clippy::unwrap_used)]
// `unsafe` is confined to the modules that talk to the kernel; see docs/unsafe-review.md.
#![deny(unsafe_code)]
#[allow(unsafe_code)]
mod group;
#[allow(unsafe_code)]
mod reactor;

pub use group::{UringGroup, UringOptions, probe};
