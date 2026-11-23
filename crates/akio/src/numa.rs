//! NUMA placement of the engine's threads (ADR-088), off by default.
//!
//! On a machine with several NUMA nodes, memory and PCIe devices belong to one node each, and
//! a thread on another node reaches them across the interconnect. Every I/O thread of this
//! engine owns its connections, buffers (per-thread pools, first touched by the thread itself)
//! and timers, so keeping each thread on one node keeps its memory local; putting the threads
//! on the node of the network interface keeps the packets' path local too.
//!
//! [`EngineBuilder::numa`](crate::EngineBuilder::numa) (or `AKIO_NUMA`, see
//! [`NumaConfig::from_env`]) chooses the nodes: [`NumaPlacement::Spread`] puts thread `i` of
//! each group on node `i % nodes`, [`NumaPlacement::Nodes`] restricts every thread to the nodes
//! given, [`NumaPlacement::Interface`] to the node of a network interface. A thread is confined
//! to its node's CPUs (those the process may use), or with [`NumaConfig::per_cpu`] to one CPU;
//! [`NumaConfig::incoming_cpu`] also sets `SO_INCOMING_CPU` on each thread's listening socket,
//! so the kernel hands a connection to the thread on the CPU that received it. The logical pool
//! ([`Conn::spawn_blocking`](crate::Conn::spawn_blocking)) is confined to the chosen nodes.
//! [`Engine::numa_status`](crate::Engine::numa_status) reports what was done. Linux only:
//! elsewhere, and when the topology cannot be read, placement degrades to none (or fails the
//! build with [`NumaConfig::strict`]).

use std::io;

/// Which NUMA nodes the engine's threads go to ([`NumaConfig::placement`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NumaPlacement {
    /// No placement: threads run where the scheduler puts them (the default).
    #[default]
    Off,
    /// Thread `i` of each group on node `i % n` of the `n` nodes with CPUs this process may use.
    Spread,
    /// Every thread on one of these nodes (round robin in the order given).
    Nodes(Vec<usize>),
    /// Every thread on the node of this network interface (`eth0`), as its device reports
    /// it (`/sys/class/net/<name>/device/numa_node`).
    Interface(String),
}

/// NUMA placement of the engine's threads ([`EngineBuilder::numa`](crate::EngineBuilder::numa)).
/// `#[non_exhaustive]`: start from `NumaConfig::default()` (off) or a constructor and set fields.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NumaConfig {
    /// Which nodes the threads go to (default: [`NumaPlacement::Off`]).
    pub placement: NumaPlacement,
    /// Pin each I/O thread to one CPU of its node (round robin) instead of all of them
    /// (default: false).
    pub per_cpu: bool,
    /// Set `SO_INCOMING_CPU` on each I/O thread's listening socket to the first CPU of the
    /// thread's set (default: false): in the listener's `SO_REUSEPORT` group the kernel then
    /// prefers the socket of the thread on the CPU that received a connection (TCP since Linux
    /// 6.2) or datagram. Most useful with [`per_cpu`](Self::per_cpu) and the network
    /// interface's interrupts spread over those CPUs (RSS / `irqbalance`).
    pub incoming_cpu: bool,
    /// Confine the logical pool's threads to the chosen nodes' CPUs (default: true).
    pub pool: bool,
    /// Fail [`build`](crate::EngineBuilder::build) with an error instead of running without
    /// placement when it cannot be done (not Linux, no topology, an unknown node or interface)
    /// (default: false).
    pub strict: bool,
}

impl Default for NumaConfig {
    fn default() -> Self {
        NumaConfig {
            placement: NumaPlacement::Off,
            per_cpu: false,
            incoming_cpu: false,
            pool: true,
            strict: false,
        }
    }
}

impl NumaConfig {
    /// [`NumaPlacement::Spread`] with the other fields at their defaults.
    pub fn spread() -> Self {
        NumaConfig {
            placement: NumaPlacement::Spread,
            ..NumaConfig::default()
        }
    }

    /// [`NumaPlacement::Nodes`] with the other fields at their defaults.
    pub fn nodes(nodes: impl Into<Vec<usize>>) -> Self {
        NumaConfig {
            placement: NumaPlacement::Nodes(nodes.into()),
            ..NumaConfig::default()
        }
    }

    /// [`NumaPlacement::Interface`] with the other fields at their defaults.
    pub fn interface(name: impl Into<String>) -> Self {
        NumaConfig {
            placement: NumaPlacement::Interface(name.into()),
            ..NumaConfig::default()
        }
    }

    /// The configuration in `AKIO_NUMA`, which the builder uses when
    /// [`EngineBuilder::numa`](crate::EngineBuilder::numa) was not called: `spread`,
    /// `nodes:0,1`, `iface:eth0`, or `off`, optionally followed by `+cpu` ([`per_cpu`](Self::per_cpu)),
    /// `+incoming` ([`incoming_cpu`](Self::incoming_cpu)), `+nopool` (not [`pool`](Self::pool))
    /// and `+strict` (`nodes:0+cpu+incoming`). `None` when unset, empty or not understood (a
    /// warning is logged).
    pub fn from_env() -> Option<NumaConfig> {
        let v = std::env::var("AKIO_NUMA").ok()?;
        let c = parse_env(&v);
        if c.is_none() && !v.trim().is_empty() {
            crate::log_or_stderr(
                akio_log::Level::Warn,
                format_args!("AKIO_NUMA={v:?} is not understood; ignored"),
            );
        }
        c
    }
}

/// Parses an `AKIO_NUMA` value ([`NumaConfig::from_env`]).
pub(crate) fn parse_env(v: &str) -> Option<NumaConfig> {
    let mut parts = v.trim().split('+');
    let head = parts.next()?.trim();
    let placement = match head {
        "off" => NumaPlacement::Off,
        "spread" => NumaPlacement::Spread,
        _ => {
            if let Some(list) = head.strip_prefix("nodes:") {
                let nodes = list
                    .split(',')
                    .map(|n| n.trim().parse::<usize>().ok())
                    .collect::<Option<Vec<_>>>()?;
                if nodes.is_empty() {
                    return None;
                }
                NumaPlacement::Nodes(nodes)
            } else {
                let name = head.strip_prefix("iface:")?;
                if name.is_empty() {
                    return None;
                }
                NumaPlacement::Interface(name.to_owned())
            }
        }
    };
    let mut c = NumaConfig {
        placement,
        ..NumaConfig::default()
    };
    for flag in parts {
        match flag.trim() {
            "cpu" => c.per_cpu = true,
            "incoming" => c.incoming_cpu = true,
            "nopool" => c.pool = false,
            "strict" => c.strict = true,
            _ => return None,
        }
    }
    Some(c)
}

/// What NUMA placement the engine ended up with ([`Engine::numa_status`](crate::Engine::numa_status)).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NumaStatus {
    /// No placement was asked for.
    Off,
    /// Threads are placed.
    Placed(NumaReport),
    /// Placement was asked for but cannot be done (the reason); threads run unplaced.
    Degraded(String),
}

/// The placement done ([`NumaStatus::Placed`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NumaReport {
    /// The nodes the threads were spread over, in placement order.
    pub nodes: Vec<usize>,
    /// Per group (listeners in the order added, then client threads, then UDP client threads),
    /// the placement of each of its I/O threads at build time; empty for a group left alone
    /// (its threads pinned by eBPF CPU steering, or a backend that does not pin).
    pub groups: Vec<Vec<ThreadPlacement>>,
    /// The CPUs the logical pool is confined to (empty: not confined).
    pub pool_cpus: Vec<usize>,
}

/// Where one I/O thread runs ([`NumaReport::groups`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ThreadPlacement {
    /// Its node.
    pub node: usize,
    /// The CPUs it is pinned to.
    pub cpus: Vec<usize>,
    /// The `SO_INCOMING_CPU` set on its listening socket, if any.
    pub incoming_cpu: Option<usize>,
    /// io_uring with [`UringConfig::sqpoll`](crate::UringConfig::sqpoll): the CPU its ring's
    /// kernel SQ polling thread is pinned to (`IORING_SETUP_SQ_AFF`), one of [`cpus`](Self::cpus).
    /// The ring itself is created on a thread pinned to `cpus`, so its memory is on the node.
    pub sq_thread_cpu: Option<usize>,
}

/// A node with the CPUs of it this process may use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UsableNode {
    pub(crate) id: usize,
    pub(crate) cpus: Vec<usize>,
}

/// The nodes `placement` asks for, among `nodes` restricted to `allowed` CPUs (nodes left
/// without CPUs dropped); `interface` gives an interface's node. An error says why not.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn choose(
    placement: &NumaPlacement,
    nodes: &[akio_sys::numa::NumaNode],
    allowed: &[usize],
    interface: impl Fn(&str) -> io::Result<Option<usize>>,
) -> Result<Vec<UsableNode>, String> {
    let usable: Vec<UsableNode> = nodes
        .iter()
        .map(|n| UsableNode {
            id: n.id,
            cpus: n
                .cpus
                .iter()
                .copied()
                .filter(|c| allowed.contains(c))
                .collect(),
        })
        .filter(|n| !n.cpus.is_empty())
        .collect();
    let pick = |ids: &[usize]| -> Result<Vec<UsableNode>, String> {
        ids.iter()
            .map(|id| {
                usable
                    .iter()
                    .find(|n| n.id == *id)
                    .cloned()
                    .ok_or_else(|| format!("NUMA node {id} has no CPU this process may use"))
            })
            .collect()
    };
    match placement {
        NumaPlacement::Off => Ok(Vec::new()),
        NumaPlacement::Spread if usable.is_empty() => {
            Err("no NUMA node with a CPU this process may use".into())
        }
        NumaPlacement::Spread => Ok(usable),
        NumaPlacement::Nodes(ids) if ids.is_empty() => Err("NumaPlacement::Nodes is empty".into()),
        NumaPlacement::Nodes(ids) => pick(ids),
        NumaPlacement::Interface(name) => match interface(name) {
            Ok(Some(id)) => pick(&[id]),
            Ok(None) => Err(format!("interface {name} reports no NUMA node")),
            Err(e) => Err(format!("NUMA node of interface {name}: {e}")),
        },
    }
}

/// The CPU set of each of `count` threads over `nodes`: thread `i` on node `i % n`, all of its
/// CPUs, or with `per_cpu` CPU `(i / n) % len` of them.
pub(crate) fn thread_sets(
    nodes: &[UsableNode],
    per_cpu: bool,
    count: usize,
) -> Vec<(usize, Vec<usize>)> {
    if nodes.is_empty() {
        return Vec::new();
    }
    (0..count)
        .map(|i| {
            let n = &nodes[i % nodes.len()];
            let cpus = if per_cpu {
                vec![n.cpus[(i / nodes.len()) % n.cpus.len()]]
            } else {
                n.cpus.clone()
            };
            (n.id, cpus)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use akio_sys::numa::NumaNode;

    fn two_nodes() -> Vec<NumaNode> {
        vec![
            NumaNode {
                id: 0,
                cpus: vec![0, 1, 2, 3],
            },
            NumaNode {
                id: 1,
                cpus: vec![4, 5, 6, 7],
            },
        ]
    }

    fn no_iface(_: &str) -> io::Result<Option<usize>> {
        Err(io::ErrorKind::NotFound.into())
    }

    #[test]
    fn spread_alternates_nodes() {
        let all: Vec<usize> = (0..8).collect();
        let nodes = choose(&NumaPlacement::Spread, &two_nodes(), &all, no_iface).unwrap();
        let sets = thread_sets(&nodes, false, 4);
        assert_eq!(
            sets,
            [
                (0, vec![0, 1, 2, 3]),
                (1, vec![4, 5, 6, 7]),
                (0, vec![0, 1, 2, 3]),
                (1, vec![4, 5, 6, 7])
            ]
        );
        let per_cpu = thread_sets(&nodes, true, 10);
        let cpus: Vec<usize> = per_cpu.iter().map(|(_, c)| c[0]).collect();
        assert_eq!(cpus, [0, 4, 1, 5, 2, 6, 3, 7, 0, 4]);
        assert!(per_cpu.iter().all(|(n, c)| c[0] / 4 == *n));
    }

    #[test]
    fn allowed_cpus_and_nodes() {
        // The process may use CPUs 2, 3 only: node 1 drops out.
        let nodes = choose(&NumaPlacement::Spread, &two_nodes(), &[2, 3], no_iface).unwrap();
        assert_eq!(
            nodes,
            [UsableNode {
                id: 0,
                cpus: vec![2, 3]
            }]
        );
        assert!(
            choose(
                &NumaPlacement::Nodes(vec![1]),
                &two_nodes(),
                &[2, 3],
                no_iface
            )
            .is_err()
        );
        let all: Vec<usize> = (0..8).collect();
        let one = choose(&NumaPlacement::Nodes(vec![1]), &two_nodes(), &all, no_iface).unwrap();
        assert!(
            thread_sets(&one, true, 3)
                .iter()
                .all(|(n, c)| *n == 1 && c[0] >= 4)
        );
        assert!(choose(&NumaPlacement::Nodes(vec![]), &two_nodes(), &all, no_iface).is_err());
        assert!(choose(&NumaPlacement::Nodes(vec![7]), &two_nodes(), &all, no_iface).is_err());
        assert_eq!(
            choose(&NumaPlacement::Off, &two_nodes(), &all, no_iface).unwrap(),
            []
        );
        assert!(choose(&NumaPlacement::Spread, &two_nodes(), &[], no_iface).is_err());
    }

    #[test]
    fn interface_node() {
        let all: Vec<usize> = (0..8).collect();
        let on1 = |n: &str| Ok((n == "eth1").then_some(1));
        let nodes = choose(
            &NumaPlacement::Interface("eth1".into()),
            &two_nodes(),
            &all,
            on1,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, 1);
        let e = choose(
            &NumaPlacement::Interface("veth0".into()),
            &two_nodes(),
            &all,
            on1,
        )
        .unwrap_err();
        assert!(e.contains("reports no NUMA node"), "{e}");
        let e = choose(
            &NumaPlacement::Interface("nope".into()),
            &two_nodes(),
            &all,
            no_iface,
        )
        .unwrap_err();
        assert!(e.contains("nope"), "{e}");
    }

    #[test]
    fn env_values() {
        assert_eq!(parse_env("spread"), Some(NumaConfig::spread()));
        let c = parse_env("nodes:0,1+cpu+incoming+nopool+strict").unwrap();
        assert_eq!(c.placement, NumaPlacement::Nodes(vec![0, 1]));
        assert!(c.per_cpu && c.incoming_cpu && !c.pool && c.strict);
        assert_eq!(
            parse_env(" iface:eth0 ").unwrap().placement,
            NumaPlacement::Interface("eth0".into())
        );
        assert_eq!(parse_env("off"), Some(NumaConfig::default()));
        for bad in ["", "nodes:", "nodes:a", "iface:", "spread+fast", "on"] {
            assert_eq!(parse_env(bad), None, "{bad}");
        }
    }
}
