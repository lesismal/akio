//! `akio`'s BPF acceleration layer (ADR-006): not an I/O backend, but programs the kernel runs
//! on `akio`'s behalf, each degrading to the plain path when unavailable.
//!
//! * **`SO_REUSEPORT` steering** ([`attach_reuseport`]): which I/O thread receives a new TCP
//!   connection or UDP peer, by [`Steering::Cpu`] (the CPU that received the packet) or
//!   [`Steering::Hash`] (deterministic consistent hashing of the peer). Two tiers: classic BPF
//!   (`SO_ATTACH_REUSEPORT_CBPF`), which works unprivileged on any Linux since 4.6, and eBPF with
//!   a `REUSEPORT_SOCKARRAY` (privileged) for CPU steering. Without either, the kernel's default
//!   4-tuple hash stays in place. The facade wires this to `Listener::accel(Accel::Ebpf(..))`.
//! * **shared steering** ([`SharedSteering`]): the same policies for a `SO_REUSEPORT` group
//!   whose sockets belong to several processes (each binding the same port): one program and socket array
//!   pinned in bpffs, each process filling its own slots; with Linux 5.14+ it also picks where a
//!   closing listener's queued connections migrate (`BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`).
//! * **sockmap relay** ([`Relay`]): splices two TCP sockets in the kernel (`SOCKHASH` +
//!   `sk_skb` stream verdict) for proxies; privileged, and Linux 6.15+ by default (older
//!   kernels can lose relayed data, see [`relay::MIN_KERNEL`]). [`Tunnel`] runs a spliced pair
//!   of connections by their TCP counters ([`conn_byte_counts`]): idle probe, drain on close.
//!
//! * **AF_XDP** (`xsk`, `#[doc(hidden)]`): the sockets and redirect program behind akio-dpdk's
//!   `Device::AfXdp` link.
//!
//! Programs are hand-assembled (a dozen instructions each) and loaded with raw `bpf(2)` calls,
//! so building `akio` needs neither a BPF toolchain nor nightly Rust, and no `aya`/libbpf.
//! Off Linux everything compiles and reports `Unsupported`.
//!
//! Guide: [eBPF steering](https://lesismal.github.io/akio/en/concepts/engine.html#acceleration-ebpf-steering)
//! (中文: [eBPF 分流](https://lesismal.github.io/akio/zh-CN/concepts/engine.html)).
#![warn(clippy::unwrap_used)]
// `unsafe` is confined to `sys` (raw bpf(2) and socket options) and `xsk` (AF_XDP rings);
// see docs/unsafe-review.md.
#![deny(unsafe_code)]

/// Classic BPF programs and an interpreter (tests, fuzzing). `#[doc(hidden)]`: unstable.
#[doc(hidden)]
pub mod cbpf;
mod ebpf;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
pub mod relay;
mod shared;
mod steer;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;
mod tunnel;
#[cfg(any(test, feature = "fuzzing"))]
mod vm;
pub mod xdp;
/// AF_XDP sockets for akio-dpdk's `Device::AfXdp` (ADR-063). `#[doc(hidden)]`: unstable.
#[cfg(target_os = "linux")]
#[doc(hidden)]
#[allow(unsafe_code)]
pub mod xsk;

pub use relay::{
    ByteCounts, Relay, Splice, SpliceError, byte_counts, conn_byte_counts, inner_byte_counts,
};
pub use shared::{MAX_SHARED_SOCKETS, SharedSteering};
pub use steer::{AttachOptions, HashKey, SteerInfo, Steering, Tier, attach_reuseport, cpu_pinning};
pub use tunnel::{Tunnel, TunnelSide};
pub use xdp::{RateLimiter, XdpLimit};
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
    /// The XDP rate limiter's program and maps load (privileged); attaching it to an interface
    /// is not tried.
    pub xdp: bool,
    /// Reuseport programs for `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` load (privileged, Linux
    /// 5.14+): [`SharedSteering`] programs choose where closing listeners' connections go.
    pub reuseport_migrate: bool,
    /// AF_XDP sockets, an `XSKMAP` and the redirect program can be created (privileged);
    /// binding to an interface is not tried.
    pub af_xdp: bool,
}

/// Probes the features on throwaway sockets bound to the loopback address.
pub fn probe() -> Probe {
    #[cfg(target_os = "linux")]
    {
        let group = || -> std::io::Result<Vec<std::net::TcpListener>> {
            let a = akio_sys::listen(std::net::SocketAddr::from(([127, 0, 0, 1], 0)), true, 16)?;
            let addr = a.local_addr()?;
            Ok(vec![a, akio_sys::listen(addr, true, 16)?])
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
            xdp: xdp::probe_load().is_ok(),
            reuseport_migrate: probe_migrate().is_ok(),
            af_xdp: xsk::probe().is_ok(),
        }
    }
    #[cfg(not(target_os = "linux"))]
    Probe::default()
}

/// Loads (and drops) a `SELECT_OR_MIGRATE` reuseport program.
#[cfg(target_os = "linux")]
fn probe_migrate() -> std::io::Result<()> {
    let socks = sys::Map::<u32, u64>::create(sys::MAP_REUSEPORT_SOCKARRAY, 1)?;
    sys::prog_load(
        sys::PROG_SK_REUSEPORT,
        sys::ATTACH_SK_REUSEPORT_SELECT_OR_MIGRATE,
        &ebpf::reuseport_shared(socks.fd(), socks.fd(), 1, Steering::Cpu, true),
        "akio_probe_mig",
    )
    .map(drop)
}
