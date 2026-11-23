//! Thin, audited `unsafe` wrappers over OS primitives: a readiness [`Poller`] (epoll on Linux,
//! kqueue on macOS), a cross-thread [`Waker`], and socket helpers (`SO_REUSEPORT` listeners,
//! non-blocking connect, `sendfile`), file change notification ([`FsWatcher`]: inotify / kqueue
//! `EVFILT_VNODE`), the kernel CSPRNG (`getrandom` / `getentropy`, for
//! `akio-crypto`), the host's network interfaces ([`interfaces`], `getifaddrs`) and sending a
//! datagram out of one of them ([`send_to_on`]), process plumbing for multi-process serving ([`process`]) and, on Linux, batched datagram I/O (`recvmmsg` /
//! `sendmmsg` with UDP GRO / GSO, traffic class bytes (DSCP and ECN) in control messages, and
//! the ICMP errors of unconnected sockets through `IP_RECVERR`; on macOS one datagram per
//! `sendmsg` / `recvmsg` with its traffic class, and the ICMP errors of unconnected sockets
//! through an unprivileged ICMP socket) and, hidden, kernel TLS offload (`TCP_ULP`
//! "tls", `SOL_TLS`, NIC TLS offload features through ethtool; akio-tls's `ktls` feature).
//!
//! All `unsafe` in the network stack's hot path lives here, each block with a comment stating the invariant it relies on.
//!
//! Guide: [Architecture](https://lesismal.github.io/akio/en/architecture.html)
//! (中文: [架构](https://lesismal.github.io/akio/zh-CN/architecture.html)).
#![cfg(any(target_os = "linux", target_os = "macos"))]
#![warn(clippy::unwrap_used)]

#[doc(hidden)]
pub mod ffi;
mod fswatch;
#[cfg(target_os = "linux")]
mod icmp;
#[cfg(target_os = "macos")]
mod icmp_mac;
mod icmp_packet;
mod iface;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod ktls;
mod net;
pub mod numa;
mod poller;
pub mod process;
mod random;
#[cfg(target_os = "linux")]
mod udp;
#[cfg(target_os = "macos")]
mod udp_mac;
mod waker;

pub use fswatch::{FsEvent, FsWatcher, WatchId};
#[cfg(target_os = "linux")]
pub use icmp::{IcmpReport, enable_recverr, is_icmp_error, recv_icmp};
#[cfg(target_os = "macos")]
pub use icmp_mac::{IcmpListener, icmp_source_matches};
pub use icmp_packet::{IcmpPacket, parse_icmp_error};
pub use iface::{Interface, InterfaceAddr, InterfaceFlags, interfaces, send_to_on};
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use net::listen_backlog;
pub use net::{
    connect_nonblocking, connect_nonblocking_from, dont_fragment, listen, listen_udp,
    multicast_hops_v6, sendfile, set_backlog, set_dont_fragment, set_multicast_hops_v6,
    set_unicast_hops_v6, unicast_hops_v6,
};
pub use poller::{Event, Poller};
#[doc(hidden)]
pub use random::fill_random;
#[cfg(target_os = "linux")]
pub use udp::{
    Batch, MAX_GSO_BYTES, MAX_GSO_SEGMENTS, RecvBatch, SEND_BATCH, SendBatch, disable_gso,
    ecn_available, enable_ecn, enable_gro, enable_recv_ttl, gro_available, gso_enabled,
    send_to_ecn, send_to_ip, send_to_tos,
};
#[cfg(target_os = "macos")]
pub use udp_mac::{
    ecn_available, enable_ecn, enable_recv_ttl, recv_from_ecn, recv_from_ip, recv_from_tos,
    send_to_ecn, send_to_ip, send_to_tos,
};
#[cfg(target_os = "linux")]
pub use waker::EventFd;
pub use waker::Waker;
