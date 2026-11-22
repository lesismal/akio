//! NUMA topology (Linux, from sysfs) and `SO_INCOMING_CPU`, for placing I/O threads near their
//! memory and their network interface (ADR-088).
//!
//! [`nodes`] lists the NUMA nodes with their CPUs (`/sys/devices/system/node/node<N>/cpulist`;
//! a kernel without NUMA support has no such directory and reads as one node holding every
//! online CPU), [`interface_node`] the node a network interface's device is attached to
//! (`/sys/class/net/<name>/device/numa_node`; `None` when the device does not say, as virtual
//! interfaces and single-node machines report `-1`). Nothing here changes any state but
//! [`set_incoming_cpu`]. Linux only: elsewhere these return `Unsupported`.

use std::io;
use std::path::Path;

/// One NUMA node: its id and the CPUs it holds, ascending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumaNode {
    /// The node id (`N` of `node<N>`).
    pub id: usize,
    /// Its CPUs, ascending (all of them, whether or not this process may use them).
    pub cpus: Vec<usize>,
}

/// Parses a kernel CPU list (`0-3,8,10-11`; empty: no CPU). `None` if malformed. Lists longer
/// than 65,536 CPUs are refused.
pub fn parse_cpulist(s: &str) -> Option<Vec<usize>> {
    const MAX: usize = 65_536;
    let s = s.trim();
    let mut out = Vec::new();
    if s.is_empty() {
        return Some(out);
    }
    for part in s.split(',') {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (
                a.trim().parse::<usize>().ok()?,
                b.trim().parse::<usize>().ok()?,
            ),
            None => {
                let c = part.trim().parse::<usize>().ok()?;
                (c, c)
            }
        };
        if b < a || b - a >= MAX || out.len() + (b - a) >= MAX {
            return None;
        }
        out.extend(a..=b);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// The NUMA nodes of this machine, by id ([`NumaNode`]). A kernel without NUMA support (no
/// `/sys/devices/system/node`) reads as node 0 with the online CPUs.
pub fn nodes() -> io::Result<Vec<NumaNode>> {
    if cfg!(target_os = "linux") {
        nodes_in(Path::new("/sys"))
    } else {
        Err(unsupported())
    }
}

/// [`nodes`] under another sysfs root (tests). `#[doc(hidden)]`.
#[doc(hidden)]
pub fn nodes_in(sys: &Path) -> io::Result<Vec<NumaNode>> {
    let dir = sys.join("devices/system/node");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let online = std::fs::read_to_string(sys.join("devices/system/cpu/online"))?;
            let cpus = parse_cpulist(&online).ok_or_else(|| bad("devices/system/cpu/online"))?;
            return Ok(vec![NumaNode { id: 0, cpus }]);
        }
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for e in entries {
        let e = e?;
        let name = e.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_prefix("node"))
            .and_then(|n| n.parse::<usize>().ok())
        else {
            continue;
        };
        let list = std::fs::read_to_string(e.path().join("cpulist"))?;
        let cpus = parse_cpulist(&list).ok_or_else(|| bad("cpulist"))?;
        out.push(NumaNode { id, cpus });
    }
    out.sort_by_key(|n| n.id);
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no NUMA node in /sys/devices/system/node",
        ));
    }
    Ok(out)
}

/// The NUMA node the device behind network interface `name` (`eth0`) is attached to, or `None`
/// when it reports none (`-1`: virtual interfaces, single-node machines). `NotFound` when there
/// is no such interface or it has no device (loopback), `InvalidInput` for a name that is not
/// an interface name.
pub fn interface_node(name: &str) -> io::Result<Option<usize>> {
    if cfg!(target_os = "linux") {
        interface_node_in(Path::new("/sys"), name)
    } else {
        Err(unsupported())
    }
}

/// [`interface_node`] under another sysfs root (tests). `#[doc(hidden)]`.
#[doc(hidden)]
pub fn interface_node_in(sys: &Path, name: &str) -> io::Result<Option<usize>> {
    // IFNAMSIZ is 16 with the terminating NUL; no path separators or dot names.
    if name.is_empty() || name.len() > 15 || name.contains('/') || name == "." || name == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a network interface name",
        ));
    }
    let s = std::fs::read_to_string(sys.join("class/net").join(name).join("device/numa_node"))?;
    let n: i64 = s.trim().parse().map_err(|_| bad("numa_node"))?;
    Ok(usize::try_from(n).ok())
}

/// Sets `SO_INCOMING_CPU` on socket `fd`: in a `SO_REUSEPORT` group, the kernel prefers the
/// socket whose value is the CPU that received the packet (TCP connections since Linux 6.2,
/// UDP for longer), so a thread pinned to that CPU accepts what arrives there. Linux only.
pub fn set_incoming_cpu(fd: std::os::fd::RawFd, cpu: usize) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let cpu = crate::ffi::c_int::try_from(cpu)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CPU number too large"))?;
        crate::net::setsockopt_int(fd, crate::ffi::SOL_SOCKET, crate::ffi::SO_INCOMING_CPU, cpu)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, cpu);
        Err(unsupported())
    }
}

/// The `SO_INCOMING_CPU` value of socket `fd` (-1 when unset and no packet arrived yet).
/// Linux only.
pub fn incoming_cpu(fd: std::os::fd::RawFd) -> io::Result<i32> {
    #[cfg(target_os = "linux")]
    {
        let mut v: crate::ffi::c_int = 0;
        let mut len = size_of::<crate::ffi::c_int>() as crate::ffi::socklen_t;
        // SAFETY: `v` is valid for `len` bytes of writes; the kernel writes at most `len`.
        let r = unsafe {
            crate::ffi::getsockopt(
                fd,
                crate::ffi::SOL_SOCKET,
                crate::ffi::SO_INCOMING_CPU,
                (&raw mut v).cast::<crate::ffi::c_void>(),
                &raw mut len,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(v)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Err(unsupported())
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "NUMA topology is Linux-only")
}

fn bad(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("malformed sysfs {what}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpulists() {
        assert_eq!(
            parse_cpulist("0-3,8,10-11\n"),
            Some(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(parse_cpulist(""), Some(vec![]));
        assert_eq!(parse_cpulist("5"), Some(vec![5]));
        assert_eq!(parse_cpulist("3,1-2,2"), Some(vec![1, 2, 3]));
        for bad in ["a", "1-", "-1", "3-1", "0-99999999", "1,,2"] {
            assert_eq!(parse_cpulist(bad), None, "{bad}");
        }
    }

    fn fake_sys(nodes: &[(&str, &str)], online: Option<&str>) -> std::path::PathBuf {
        let mut b = [0u8; 8];
        crate::fill_random(&mut b).unwrap();
        let root = std::env::temp_dir().join(format!("akio-numa-{}", u64::from_le_bytes(b)));
        for (name, list) in nodes {
            let d = root.join("devices/system/node").join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("cpulist"), list).unwrap();
        }
        if let Some(o) = online {
            let d = root.join("devices/system/cpu");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("online"), o).unwrap();
        }
        root
    }

    #[test]
    fn nodes_from_sysfs() {
        let root = fake_sys(
            &[
                ("node1", "4-7\n"),
                ("node0", "0-3\n"),
                ("possible", "0-1\n"),
            ],
            None,
        );
        // `possible` is a file in the real tree; here a directory without `node` prefix.
        let n = nodes_in(&root).unwrap();
        assert_eq!(
            n,
            [
                NumaNode {
                    id: 0,
                    cpus: vec![0, 1, 2, 3]
                },
                NumaNode {
                    id: 1,
                    cpus: vec![4, 5, 6, 7]
                }
            ]
        );
        std::fs::remove_dir_all(&root).ok();
        // No node directory: one node with the online CPUs.
        let root = fake_sys(&[], Some("0-5\n"));
        assert_eq!(
            nodes_in(&root).unwrap(),
            [NumaNode {
                id: 0,
                cpus: (0..6).collect()
            }]
        );
        std::fs::remove_dir_all(&root).ok();
        // A malformed list is an error.
        let root = fake_sys(&[("node0", "x\n")], None);
        assert_eq!(
            nodes_in(&root).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn interface_nodes() {
        let root = fake_sys(&[], None);
        for (name, v) in [("eth0", "1\n"), ("veth9", "-1\n")] {
            let d = root.join("class/net").join(name).join("device");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("numa_node"), v).unwrap();
        }
        assert_eq!(interface_node_in(&root, "eth0").unwrap(), Some(1));
        assert_eq!(interface_node_in(&root, "veth9").unwrap(), None);
        assert_eq!(
            interface_node_in(&root, "nope").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        for bad in ["", "../etc", ".", "..", "a/b", "sixteen-chars-xx"] {
            assert_eq!(
                interface_node_in(&root, bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad}"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_real_topology_and_incoming_cpu() {
        let n = nodes().unwrap();
        assert!(!n.is_empty() && n.iter().all(|n| !n.cpus.is_empty() || n.id > 0));
        let s = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&s);
        set_incoming_cpu(fd, 0).unwrap();
        assert_eq!(incoming_cpu(fd).unwrap(), 0);
        assert_eq!(
            interface_node("lo").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn elsewhere_unsupported() {
        assert_eq!(nodes().unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            interface_node("en0").unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
