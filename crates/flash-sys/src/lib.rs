//! Thin, audited `unsafe` wrappers over OS primitives: a readiness [`Poller`] (epoll on Linux,
//! kqueue on macOS), a cross-thread [`Waker`], and socket helpers (`SO_REUSEPORT` listeners,
//! non-blocking connect).
//!
//! All `unsafe` in the network stack's hot path lives here, each block with a `SAFETY:` note.
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod net;
mod poller;
#[cfg(target_os = "linux")]
mod udp;
mod waker;

pub use net::{connect_nonblocking, listen, listen_udp};
pub use poller::{Event, Poller};
#[cfg(target_os = "linux")]
pub use udp::RecvBatch;
#[cfg(target_os = "linux")]
pub use waker::EventFd;
pub use waker::Waker;
