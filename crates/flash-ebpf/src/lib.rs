//! flash's BPF acceleration layer (ADR-006): not an I/O backend, but programs the kernel runs
//! on flash's behalf, each degrading to the plain path when unavailable.
//!
//! * **`SO_REUSEPORT` steering** ([`attach_reuseport`]): which I/O thread receives a new TCP
//!   connection or UDP peer, by [`Steering::Cpu`] (the CPU that received the packet) or
//!   [`Steering::Hash`] (deterministic consistent hashing of the peer). Two tiers: classic BPF
//!   (`SO_ATTACH_REUSEPORT_CBPF`), which works unprivileged on any Linux since 4.6, and eBPF with
//!   a `REUSEPORT_SOCKARRAY` (privileged) for CPU steering. Without either, the kernel's default
//!   4-tuple hash stays in place. The facade wires this to `Listener::accel(Accel::Ebpf(..))`.
//! * **sockmap relay** ([`Relay`]): splices two TCP sockets in the kernel (`SOCKHASH` +
//!   `sk_skb` stream verdict) for proxies; privileged, Linux 5.13+.
//!
//! Programs are hand-assembled (a dozen instructions each) and loaded with raw `bpf(2)` calls,
//! so building flash needs neither a BPF toolchain nor nightly Rust, and no `aya`/libbpf.
//! Off Linux everything compiles and reports `Unsupported`.

pub mod cbpf;
mod ebpf;
pub mod relay;
mod steer;
#[cfg(target_os = "linux")]
mod sys;

pub use relay::{Relay, Splice};
pub use steer::{
    AttachOptions, HashKey, SLOTS, SteerInfo, Steering, Tier, attach_reuseport, expected_index,
    slot_table,
};

/// What the running kernel and process privileges allow, found by trying.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
            let a = flash_sys::listen("127.0.0.1:0".parse().unwrap(), true, 16)?;
            let addr = a.local_addr()?;
            Ok(vec![a, flash_sys::listen(addr, true, 16)?])
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
