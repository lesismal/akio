//! `SO_REUSEPORT` steering: which I/O thread a new connection (TCP) or peer (UDP) lands on.

use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
};

/// How a listener's `SO_REUSEPORT` group picks the socket (= I/O thread) for a new flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Steering {
    /// CPU affinity: the flow goes to thread `cpu % threads`, where `cpu` is the CPU that
    /// received its first packet (the TCP SYN / the UDP datagram), so a flow is served by the
    /// thread matching the CPU the NIC queue (RSS/RPS) delivers it on. Best when I/O thread `i`
    /// runs on CPU `i`.
    #[default]
    Cpu,
    /// Consistent hashing of the peer: the hash selects one of [`SLOTS`] slots, and slots are given to
    /// threads by Maglev hashing (balanced to ±1 slot), so the mapping is deterministic (it does not depend on the
    /// kernel's random seed; see [`expected_index`]) and changing the thread count from `n` to
    /// `n + 1` moves little more than the `1/(n + 1)` of the peers the new thread takes.
    Hash(HashKey),
}

/// What [`Steering::Hash`] hashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashKey {
    /// The peer's IP address only: every connection from one host lands on the same thread.
    SrcIp,
    /// The peer's IP address and port (and the local port).
    SrcIpPort,
}

/// Which kind of program was attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Classic BPF (`SO_ATTACH_REUSEPORT_CBPF`): needs no privileges. The returned index is the
    /// socket's position in the reuseport group, i.e. the order the sockets were bound in.
    Cbpf,
    /// eBPF (`SO_ATTACH_REUSEPORT_EBPF`, `BPF_PROG_TYPE_SK_REUSEPORT`) selecting from a
    /// `REUSEPORT_SOCKARRAY` map that names every thread's socket explicitly. Needs
    /// `CAP_BPF`/`CAP_SYS_ADMIN`; used for [`Steering::Cpu`].
    Ebpf,
}

/// What [`attach_reuseport`] attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SteerInfo {
    /// Program kind.
    pub tier: Tier,
    /// Policy.
    pub steering: Steering,
    /// Sockets (I/O threads) in the group.
    pub sockets: usize,
    /// Why the eBPF tier was not used, when it was wanted but classic BPF was attached instead.
    pub ebpf_unavailable: Option<String>,
}

impl fmt::Display for SteerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} steering over {} sockets ({:?})",
            self.steering, self.sockets, self.tier
        )
    }
}

/// Options of [`attach_reuseport`].
#[derive(Clone, Copy, Debug)]
pub struct AttachOptions {
    /// Try the eBPF tier first where it applies (privileged); fall back to classic BPF.
    pub ebpf: bool,
}

impl Default for AttachOptions {
    fn default() -> Self {
        AttachOptions { ebpf: true }
    }
}

/// Number of hash slots ([`Steering::Hash`]); also the maximum number of threads it supports.
pub const SLOTS: usize = 251; // prime, as Maglev requires
pub(crate) const SEED: u32 = 0x9e37_79b9;

pub(crate) const fn mix_prime() -> u32 {
    0x0100_0193
}

pub(crate) const fn fin_consts() -> (u32, u32) {
    (0x7feb_352d, 0x846c_a68b)
}

/// "lowbias32" integer finalizer.
fn fin(mut h: u32) -> u32 {
    let (c1, c2) = fin_consts();
    h ^= h >> 16;
    h = h.wrapping_mul(c1);
    h ^= h >> 15;
    h = h.wrapping_mul(c2);
    h ^ (h >> 16)
}

/// Slot → thread index for `n` threads, by Maglev hashing: every thread gets `SLOTS / n`
/// slots (±1), and going from `n` to `n + 1` threads moves few slots besides those taken over
/// by the new thread.
pub fn slot_table(n: usize) -> [u8; SLOTS] {
    let n = n.clamp(1, SLOTS);
    let m = SLOTS as u64;
    let perm: Vec<(u64, u64)> = (0..n as u32)
        .map(|i| {
            let offset = fin(i ^ 0x5bd1_e995) as u64 % m;
            let skip = fin(i.wrapping_mul(SEED) ^ 0x2545_f491) as u64 % (m - 1) + 1;
            (offset, skip)
        })
        .collect();
    let mut next = vec![0u64; n];
    let mut table = [u8::MAX; SLOTS];
    let mut filled = 0;
    'fill: loop {
        for (i, &(offset, skip)) in perm.iter().enumerate() {
            let mut c = ((offset + next[i] * skip) % m) as usize;
            while table[c] != u8::MAX {
                next[i] += 1;
                c = ((offset + next[i] * skip) % m) as usize;
            }
            table[c] = i as u8;
            next[i] += 1;
            filled += 1;
            if filled == SLOTS {
                break 'fill;
            }
        }
    }
    table
}

/// The words of the peer that the hash programs feed, in order.
fn words(key: HashKey, peer: SocketAddr, local: SocketAddr) -> Vec<u32> {
    let mut w = match peer.ip().to_canonical() {
        IpAddr::V4(a) => vec![u32::from(a)],
        IpAddr::V6(a) => a
            .octets()
            .chunks(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    };
    if key == HashKey::SrcIpPort {
        w.push(((peer.port() as u32) << 16) | local.port() as u32);
    }
    w
}

/// The thread index [`Steering::Hash`] picks for a flow from `peer` to `local` over `threads`
/// threads, with the classic BPF tier. `None` for [`Steering::Cpu`] (it depends on the CPU).
pub fn expected_index(
    steering: Steering,
    threads: usize,
    peer: SocketAddr,
    local: SocketAddr,
) -> Option<usize> {
    let Steering::Hash(key) = steering else {
        return None;
    };
    let mut h = SEED;
    for w in words(key, peer, local) {
        h = (h ^ w).wrapping_mul(mix_prime());
    }
    Some(slot_table(threads)[fin(h) as usize % SLOTS] as usize)
}

/// Attaches a selection program for `steering` to the `SO_REUSEPORT` group formed by `fds`
/// (thread `i` owns `fds[i]`; for the classic BPF tier the fds must be in the order they were
/// bound/listened, which is how flash creates them). On success the program stays attached for
/// the life of the group: there is nothing to keep alive.
///
/// Fails with `Unsupported` off Linux or when `fds` is empty, and with the kernel's error when
/// even classic BPF cannot be attached.
pub fn attach_reuseport(
    fds: &[i32],
    steering: Steering,
    opts: AttachOptions,
) -> io::Result<SteerInfo> {
    if fds.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the listener has no SO_REUSEPORT socket group",
        ));
    }
    if matches!(steering, Steering::Hash(_)) && fds.len() > SLOTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("hash steering supports at most {SLOTS} threads"),
        ));
    }
    imp::attach(fds, steering, opts)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::{cbpf, sys};

    pub(super) fn attach(
        fds: &[i32],
        steering: Steering,
        opts: AttachOptions,
    ) -> io::Result<SteerInfo> {
        let mut ebpf_unavailable = None;
        if opts.ebpf {
            if steering == Steering::Cpu {
                match crate::ebpf::attach_cpu_reuseport(fds) {
                    Ok(()) => {
                        return Ok(SteerInfo {
                            tier: Tier::Ebpf,
                            steering,
                            sockets: fds.len(),
                            ebpf_unavailable: None,
                        });
                    }
                    Err(e) => ebpf_unavailable = Some(e.to_string()),
                }
            } else {
                ebpf_unavailable = Some("hash steering uses classic BPF".into());
            }
        }
        sys::attach_reuseport_cbpf(fds[0], &cbpf::program(steering, fds.len()))?;
        Ok(SteerInfo {
            tier: Tier::Cbpf,
            steering,
            sockets: fds.len(),
            ebpf_unavailable,
        })
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub(super) fn attach(
        _fds: &[i32],
        _steering: Steering,
        _opts: AttachOptions,
    ) -> io::Result<SteerInfo> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_REUSEPORT steering programs are Linux-only",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_table_is_balanced_and_consistent() {
        for n in 1..=SLOTS {
            let t = slot_table(n);
            let mut count = vec![0usize; n];
            for &i in &t {
                count[i as usize] += 1;
            }
            let (lo, hi) = (SLOTS / n, SLOTS.div_ceil(n));
            assert!(count.iter().all(|&c| c >= lo && c <= hi), "n={n} {count:?}");
            if n < 32 {
                // Going from n to n + 1 threads: few slots move except to the new thread.
                let next = slot_table(n + 1);
                let stray = (0..SLOTS)
                    .filter(|&s| next[s] != t[s] && next[s] as usize != n)
                    .count();
                assert!(
                    stray <= SLOTS / 5,
                    "n={n}: {stray} slots moved between old threads"
                );
            }
        }
    }

    #[test]
    fn expected_index_is_none_for_cpu_steering() {
        let a: SocketAddr = "1.2.3.4:5".parse().unwrap();
        assert_eq!(expected_index(Steering::Cpu, 4, a, a), None);
        assert!(expected_index(Steering::Hash(HashKey::SrcIp), 4, a, a).unwrap() < 4);
    }
}
