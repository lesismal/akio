//! Thin, audited `unsafe` wrappers over OS primitives: a readiness [`Poller`] (epoll on Linux,
//! kqueue on macOS), a cross-thread [`Waker`], and socket helpers (`SO_REUSEPORT` listeners,
//! non-blocking connect).
//!
//! All `unsafe` in the network stack's hot path lives here, each block with a comment stating the invariant it relies on.
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod net;
mod poller;
#[cfg(target_os = "linux")]
mod udp;
mod waker;

pub use net::{connect_nonblocking, listen, listen_udp, sendfile};
pub use poller::{Event, Poller};
#[cfg(target_os = "linux")]
pub use udp::{
    Batch, MAX_GSO_BYTES, MAX_GSO_SEGMENTS, RecvBatch, SEND_BATCH, SendBatch, disable_gso,
    enable_gro, gro_available, gso_enabled,
};
#[cfg(target_os = "linux")]
pub use waker::EventFd;
pub use waker::Waker;
