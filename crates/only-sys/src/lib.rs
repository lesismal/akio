//! Thin, audited `unsafe` wrappers over OS primitives: a readiness [`Poller`] (epoll on Linux,
//! kqueue on macOS), a cross-thread [`Waker`], and socket helpers (`SO_REUSEPORT` listeners,
//! non-blocking connect, `sendfile`), the kernel CSPRNG (`getrandom` / `getentropy`, for
//! `only-crypto`), process plumbing for multi-process serving ([`process`]) and, on Linux, batched datagram I/O (`recvmmsg` /
//! `sendmmsg` with UDP GRO / GSO, ECN codepoints in control messages; on macOS one datagram per
//! `sendmsg` / `recvmsg` with its ECN codepoint) and, hidden and experimental, kernel TLS offload (`TCP_ULP` "tls", `SOL_TLS`; only-tls's
//! `experimental-ktls` feature).
//!
//! All `unsafe` in the network stack's hot path lives here, each block with a comment stating the invariant it relies on.
//!
//! Guide: [Architecture](https://lesismal.github.io/only/en/architecture.html)
//! (中文: [架构](https://lesismal.github.io/only/zh-CN/architecture.html)).
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![warn(clippy::unwrap_used)]

#[doc(hidden)]
pub mod ffi;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod ktls;
mod net;
mod poller;
pub mod process;
mod random;
#[cfg(target_os = "linux")]
mod udp;
#[cfg(target_os = "macos")]
mod udp_mac;
mod waker;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use net::listen_backlog;
pub use net::{connect_nonblocking, listen, listen_udp, sendfile, set_backlog};
pub use poller::{Event, Poller};
#[doc(hidden)]
pub use random::fill_random;
#[cfg(target_os = "linux")]
pub use udp::{
    Batch, MAX_GSO_BYTES, MAX_GSO_SEGMENTS, RecvBatch, SEND_BATCH, SendBatch, disable_gso,
    ecn_available, enable_ecn, enable_gro, gro_available, gso_enabled,
};
#[cfg(target_os = "macos")]
pub use udp_mac::{ecn_available, enable_ecn, recv_from_ecn, send_to_ecn};
#[cfg(target_os = "linux")]
pub use waker::EventFd;
pub use waker::Waker;
