//! Thin, audited `unsafe` wrappers over OS primitives: a readiness [`Poller`] (epoll on Linux,
//! kqueue on macOS), a cross-thread [`Waker`], and socket helpers (`SO_REUSEPORT` listeners,
//! non-blocking connect, `sendfile`), the kernel CSPRNG (`getrandom` / `getentropy`, for
//! `only-crypto`), process plumbing for multi-process serving ([`process`]) and, on Linux, batched datagram I/O (`recvmmsg` /
//! `sendmmsg` with UDP GRO / GSO).
//!
//! All `unsafe` in the network stack's hot path lives here, each block with a comment stating the invariant it relies on.
//!
//! Guide: [Architecture](https://lesismal.github.io/only/en/architecture.html)
//! (中文: [架构](https://lesismal.github.io/only/zh-CN/architecture.html)).
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![warn(clippy::unwrap_used)]

#[doc(hidden)]
pub mod ffi;
mod net;
mod poller;
pub mod process;
mod random;
#[cfg(target_os = "linux")]
mod udp;
mod waker;

pub use net::{connect_nonblocking, listen, listen_udp, sendfile};
pub use poller::{Event, Poller};
#[doc(hidden)]
pub use random::fill_random;
#[cfg(target_os = "linux")]
pub use udp::{
    Batch, MAX_GSO_BYTES, MAX_GSO_SEGMENTS, RecvBatch, SEND_BATCH, SendBatch, disable_gso,
    enable_gro, gro_available, gso_enabled,
};
#[cfg(target_os = "linux")]
pub use waker::EventFd;
pub use waker::Waker;
