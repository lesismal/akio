//! NUMA placement (ADR-088): off by default; on Linux the I/O threads run on the CPUs the
//! placement gives them (read back from `/proc/self/task/*/status`), listening sockets get
//! `SO_INCOMING_CPU`, the logical pool's threads are confined, traffic flows; impossible
//! placements degrade or, strict, fail the build. Elsewhere placement degrades. One test
//! function: the I/O threads are found by name, so no other engine may run meanwhile. Both
//! backends (`AKIO_TEST_BACKEND=uring`).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;

use akio::{Conn, Engine, Handler, Listener, NumaConfig, NumaStatus, fn_acceptor};

/// Echoes, except `pool`: answers with the CPUs a logical pool thread may run on
/// (`0,1,2,\n`; Linux).
struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        if d == b"pool" {
            let _ = c.spawn_blocking(
                || {
                    let cpus = akio_sys::process::allowed_cpus().unwrap_or_default();
                    let mut s: String = cpus.iter().map(|c| format!("{c},")).collect();
                    s.push('\n');
                    s
                },
                |_h: &mut Echo, c: &Conn<Echo>, s: String| {
                    let _ = c.send(s.as_bytes());
                },
            );
            return;
        }
        let _ = c.send(d);
    }
}

fn engine(numa: Option<NumaConfig>, threads: usize) -> std::io::Result<Engine> {
    let l = Listener::tcp("127.0.0.1:0".parse().unwrap())
        .backend(common::backend())
        .threads(threads)
        .serve(fn_acceptor(|_c: &Conn<Echo>| Echo));
    let mut b = Engine::builder().listen(l);
    if let Some(n) = numa {
        b = b.numa(n);
    }
    b.build()
}

fn echo(e: &Engine) {
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.write_all(b"numa").unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"numa");
}

/// The allowed-CPU list of each live thread named `name*`, by name.
#[cfg(target_os = "linux")]
fn thread_cpus(prefix: &str) -> Vec<(String, Vec<usize>)> {
    let mut out = Vec::new();
    for t in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let comm = std::fs::read_to_string(t.path().join("comm")).unwrap_or_default();
        let comm = comm.trim().to_owned();
        if !comm.starts_with(prefix) {
            continue;
        }
        let status = std::fs::read_to_string(t.path().join("status")).unwrap_or_default();
        let list = status
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .unwrap_or("")
            .trim()
            .to_owned();
        out.push((
            comm,
            akio_sys::numa::parse_cpulist(&list).expect("Cpus_allowed_list"),
        ));
    }
    out.sort();
    out
}

#[test]
fn numa_placement() {
    // Off unless asked (AKIO_NUMA is not set by the test runner).
    if std::env::var_os("AKIO_NUMA").is_none() {
        let e = engine(None, 2).unwrap();
        assert_eq!(e.numa_status(), &NumaStatus::Off);
        e.start().unwrap();
        echo(&e);
        e.shutdown();
        e.wait();
    }

    #[cfg(not(target_os = "linux"))]
    {
        let e = engine(Some(NumaConfig::spread()), 2).unwrap();
        assert!(
            matches!(e.numa_status(), NumaStatus::Degraded(w) if w.contains("Linux-only")),
            "{:?}",
            e.numa_status()
        );
        let mut strict = NumaConfig::spread();
        strict.strict = true;
        let err = engine(Some(strict), 2).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[cfg(target_os = "linux")]
    {
        let allowed = akio_sys::process::allowed_cpus().unwrap();
        let nodes = akio_sys::numa::nodes().unwrap();
        let usable: Vec<usize> = nodes
            .iter()
            .flat_map(|n| n.cpus.iter().copied())
            .filter(|c| allowed.contains(c))
            .collect();

        // Node-wide sets: each I/O thread on all CPUs of its node.
        let e = engine(Some(NumaConfig::spread()), 2).unwrap();
        let NumaStatus::Placed(r) = e.numa_status().clone() else {
            panic!("{:?}", e.numa_status());
        };
        assert_eq!(r.groups.len(), 1);
        assert_eq!(r.groups[0].len(), 2);
        let mut pool_cpus = r.pool_cpus.clone();
        pool_cpus.sort_unstable();
        let mut usable = usable;
        usable.sort_unstable();
        assert_eq!(pool_cpus, usable);
        e.start().unwrap();
        echo(&e);
        let got = thread_cpus("akio-io-");
        assert_eq!(got.len(), 2, "{got:?}");
        for (i, (name, cpus)) in got.iter().enumerate() {
            assert_eq!(name, &format!("akio-io-{i}"));
            assert_eq!(cpus, &r.groups[0][i].cpus, "{name}");
        }
        // The logical pool runs on the chosen nodes' CPUs.
        let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
        s.write_all(b"pool").unwrap();
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while b[0] != b'\n' {
            s.read_exact(&mut b).unwrap();
            line.push(b[0]);
        }
        let mut pool_seen: Vec<usize> = std::str::from_utf8(&line)
            .unwrap()
            .trim()
            .split(',')
            .filter(|c| !c.is_empty())
            .map(|c| c.parse().unwrap())
            .collect();
        pool_seen.sort_unstable();
        assert_eq!(pool_seen, pool_cpus);
        drop(s);
        e.shutdown();
        e.wait();

        // One CPU per thread, SO_INCOMING_CPU on the listening sockets.
        let mut c = NumaConfig::spread();
        c.per_cpu = true;
        c.incoming_cpu = true;
        let e = engine(Some(c), 3).unwrap();
        let NumaStatus::Placed(r) = e.numa_status().clone() else {
            panic!("{:?}", e.numa_status());
        };
        e.start().unwrap();
        echo(&e);
        let got = thread_cpus("akio-io-");
        assert_eq!(got.len(), 3, "{got:?}");
        for (i, (_, cpus)) in got.iter().enumerate() {
            let p = &r.groups[0][i];
            assert_eq!(cpus.len(), 1);
            assert_eq!(cpus, &p.cpus);
            // The listening sockets form a SO_REUSEPORT group on Linux (epoll and io_uring).
            assert_eq!(p.incoming_cpu, Some(cpus[0]), "thread {i}");
        }
        e.shutdown();
        e.wait();

        // Impossible placements: degraded, or an error when strict.
        let e = engine(Some(NumaConfig::nodes(vec![4096])), 1).unwrap();
        assert!(
            matches!(e.numa_status(), NumaStatus::Degraded(w) if w.contains("4096")),
            "{:?}",
            e.numa_status()
        );
        let e2 = engine(Some(NumaConfig::interface("lo")), 1).unwrap();
        assert!(
            matches!(e2.numa_status(), NumaStatus::Degraded(w) if w.contains("lo")),
            "{:?}",
            e2.numa_status()
        );
        let mut strict = NumaConfig::nodes(vec![4096]);
        strict.strict = true;
        assert_eq!(
            engine(Some(strict), 1).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        // A degraded engine still serves.
        e.start().unwrap();
        echo(&e);
        e.shutdown();
        e.wait();
    }
}
