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
//! * Connectionless datagram listeners (ADR-065): a one-shot `POLL_ADD` per UDP socket, and on
//!   completion the shared `akio_core::DatagramPort` (`recvmmsg`, handler, `sendmmsg`). Per-peer
//!   UDP listeners run on the epoll UDP loop.
//!
//! Measured and not used (docs/BENCHMARKS.md, "io_uring features evaluation"): ring-based sends
//! (`IORING_OP_SEND`), `SEND_ZC`, registered files with direct accept, a registered ring fd and
//! `MSG_RING` wake-ups. The test-only `eval` module is the harness for the send and file cases.
//!
//! Guide: [Engine, listeners and backends](https://lesismal.github.io/akio/en/concepts/engine.html)
//! (中文: [Engine、Listener 与后端](https://lesismal.github.io/akio/zh-CN/concepts/engine.html)).
#![cfg(target_os = "linux")]
#![warn(clippy::unwrap_used)]
// `unsafe` is confined to the modules that talk to the kernel; see docs/unsafe-review.md.
#![deny(unsafe_code)]
#[cfg(test)]
#[allow(unsafe_code)]
mod eval;
#[allow(unsafe_code)]
mod group;
#[allow(unsafe_code)]
mod reactor;
#[allow(unsafe_code)]
mod ring;

pub use group::{UringGroup, UringOptions, probe};
