#![cfg(any(target_os = "linux", target_os = "macos"))]
#![forbid(unsafe_code)]
//! The readiness-based backend: epoll on Linux, kqueue on macOS.
//!
//! One [`EpollGroup`] serves one listener with a set of I/O threads, each running an event loop
//! (`Loop`) that owns its connections. See ADR-001/002/004.
//!
//! * Accept: on Linux every loop binds its own `SO_REUSEPORT` listener (the kernel spreads
//!   connections); elsewhere the loops share one listener and race to accept.
//! * Read: level-triggered, one scratch buffer per loop, handed to `on_data` as a borrow.
//! * Write: `send` tries the socket directly (from any thread); the rest is queued and written by
//!   the owning loop when the socket becomes writable.
//! * Backpressure: reads pause while a connection's queue exceeds the high watermark.

mod group;
mod reactor;
mod udp;

pub use group::EpollGroup;
pub use udp::UdpGroup;
