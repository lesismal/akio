//! `only`'s BPF acceleration layer (ADR-006): not an I/O backend, but programs the kernel runs
//! on `only`'s behalf, each degrading to the plain path when unavailable.
//!
//! * **`SO_REUSEPORT` steering** ([`attach_reuseport`]): which I/O thread receives a new TCP
//!   connection or UDP peer, by [`Steering::Cpu`] (the CPU that received the packet) or
//!   [`Steering::Hash`] (deterministic consistent hashing of the peer). Two tiers: classic BPF
//!   (`SO_ATTACH_REUSEPORT_CBPF`), which works unprivileged on any Linux since 4.6, and eBPF with
//!   a `REUSEPORT_SOCKARRAY` (privileged) for CPU steering. Without either, the kernel's default
//!   4-tuple hash stays in place. The facade wires this to `Listener::accel(Accel::Ebpf(..))`.
//! * **sockmap relay** ([`Relay`]): splices two TCP sockets in the kernel (`SOCKHASH` +
//!   `sk_skb` stream verdict) for proxies; privileged, and Linux 6.15+ by default (older
//!   kernels can lose relayed data, see [`relay::MIN_KERNEL`]).
//!
//! Programs are hand-assembled (a dozen instructions each) and loaded with raw `bpf(2)` calls,
//! so building `only` needs neither a BPF toolchain nor nightly Rust, and no `aya`/libbpf.
//! Off Linux everything compiles and reports `Unsupported`.
//!
//! Guide: [eBPF steering](https://lesismal.github.io/flash/en/concepts/engine.html#acceleration-ebpf-steering)
//! (中文: [eBPF 分流](https://lesismal.github.io/flash/zh-CN/concepts/engine.html)).
#![warn(clippy::unwrap_used)]
// `unsafe` is confined to `sys` (raw bpf(2) and socket options); see docs/unsafe-review.md.
#![deny(unsafe_code)]

/// Classic BPF programs and an interpreter (tests, fuzzing). `#[doc(hidden)]`: unstable.
#[doc(hidden)]
pub mod cbpf;
mod ebpf;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod relay;
mod steer;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

pub use relay::{Relay, Splice};
pub use steer::{AttachOptions, HashKey, SteerInfo, Steering, Tier, attach_reuseport};
// Steering internals the tests check the kernel against; unstable.
#[doc(hidden)]
pub use steer::{SLOTS, expected_index, slot_table};

/// What the running kernel and process privileges allow, found by trying.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Probe {
    /// Classic BPF reuseport programs (unprivileged).
    pub reuseport_cbpf: bool,
    /// eBPF reuseport programs with a socket array (privileged).
    pub reuseport_ebpf: bool,
    /// The sockmap relay (privileged).
    pub sockmap_relay: bool,
}

/// Probes the features on throwaway sockets bound to the loopback address.
pub fn probe() -> Probe {
    #[cfg(target_os = "linux")]
    {
        let group = || -> std::io::Result<Vec<std::net::TcpListener>> {
            let a = only_sys::listen(std::net::SocketAddr::from(([127, 0, 0, 1], 0)), true, 16)?;
            let addr = a.local_addr()?;
            Ok(vec![a, only_sys::listen(addr, true, 16)?])
        };
        use std::os::fd::AsRawFd;
        let fds = |g: &[std::net::TcpListener]| g.iter().map(|l| l.as_raw_fd()).collect::<Vec<_>>();
        let reuseport_cbpf = group()
            .and_then(|g| sys::attach_reuseport_cbpf(fds(&g)[0], &cbpf::program(Steering::Cpu, 2)))
            .is_ok();
        let reuseport_ebpf = group()
            .and_then(|g| ebpf::attach_cpu_reuseport(&fds(&g)))
            .is_ok();
        Probe {
            reuseport_cbpf,
            reuseport_ebpf,
            sockmap_relay: Relay::new(1).is_ok(),
        }
    }
    #[cfg(not(target_os = "linux"))]
    Probe::default()
}
