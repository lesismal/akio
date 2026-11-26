//! NUMA placement (ADR-088): off by default; on Linux the I/O threads run on the CPUs the
//! placement gives them (read back from `/proc/self/task/*/status`), listening sockets get
//! `SO_INCOMING_CPU`, the logical pool's threads are confined, traffic flows; impossible
//! placements degrade or, strict, fail the build. Elsewhere placement degrades. One test
//! function: the I/O threads are found by name, so no other engine may run meanwhile. Both
//! backends (`AKIO_TEST_BACKEND=uring`); with io_uring also SQPOLL rings, whose kernel polling
//! threads (`iou-sqp-*`) run on the CPU the report gives.
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

/// The `akio-io-*` threads once they are those `want` describes (thread `i` on `want[i]`), or
/// what there is after 10 s: a thread names and pins itself when it first runs, which on a busy
/// host can be well after `start` returned.
#[cfg(target_os = "linux")]
fn io_threads(want: &[Vec<usize>]) -> Vec<(String, Vec<usize>)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = thread_cpus("akio-io-");
        let done = got.len() == want.len() && got.iter().zip(want).all(|((_, c), w)| c == w);
        if done || std::time::Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn numa_placement() {
    if common::work_stealing() {
        return; // work stealing: pollers and workers are placed differently (ADR-104)
    }
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
        let want: Vec<_> = r.groups[0].iter().map(|p| p.cpus.clone()).collect();
        let got = io_threads(&want);
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
        let want: Vec<_> = r.groups[0].iter().map(|p| p.cpus.clone()).collect();
        let got = io_threads(&want);
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
        drop((e, e2));

        if std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring") {
            sqpoll(&usable);
        }
    }
}

/// An io_uring engine with SQPOLL rings.
#[cfg(target_os = "linux")]
fn sqpoll_engine(numa: Option<NumaConfig>, threads: usize) -> Engine {
    let mut u = akio::UringConfig::default();
    u.strict = true;
    u.sqpoll = true;
    let l = Listener::tcp("127.0.0.1:0".parse().unwrap())
        .backend(akio::Backend::IoUring(u))
        .threads(threads)
        .serve(fn_acceptor(|_c: &Conn<Echo>| Echo));
    let mut b = Engine::builder().listen(l);
    if let Some(n) = numa {
        b = b.numa(n);
    }
    b.build().unwrap()
}

/// The allowed CPUs of the `iou-sqp-*` threads once there are `n` of them (rings of engines
/// shut down are torn down asynchronously), sorted.
#[cfg(target_os = "linux")]
fn sqp_threads(n: usize) -> Vec<Vec<usize>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut got: Vec<_> = thread_cpus("iou-sqp-")
            .into_iter()
            .map(|(_, c)| c)
            .collect();
        got.sort();
        if got.len() == n || std::time::Instant::now() > deadline {
            assert_eq!(got.len(), n, "iou-sqp threads: {got:?}");
            return got;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// SQPOLL rings: unplaced as before; placed, each ring's polling thread on one CPU of its loop's
/// set (loops sharing a set on different CPUs), as reported.
#[cfg(target_os = "linux")]
fn sqpoll(usable: &[usize]) {
    sqp_threads(0);
    let e = sqpoll_engine(None, 2);
    if std::env::var_os("AKIO_NUMA").is_none() {
        assert_eq!(e.numa_status(), &NumaStatus::Off);
    }
    e.start().unwrap();
    echo(&e);
    sqp_threads(2);
    e.shutdown();
    e.wait();
    drop(e);
    sqp_threads(0);

    for per_cpu in [false, true] {
        let mut c = NumaConfig::spread();
        c.per_cpu = per_cpu;
        let e = sqpoll_engine(Some(c), 2);
        let NumaStatus::Placed(r) = e.numa_status().clone() else {
            panic!("{:?}", e.numa_status());
        };
        let placed = &r.groups[0];
        let mut want = Vec::new();
        for (i, p) in placed.iter().enumerate() {
            let sq = p.sq_thread_cpu.expect("SQ CPU reported");
            assert!(p.cpus.contains(&sq), "thread {i}: {sq} not in {:?}", p.cpus);
            if per_cpu {
                assert_eq!(sq, p.cpus[0]);
            }
            want.push(vec![sq]);
        }
        if !per_cpu && placed[0].cpus == placed[1].cpus && usable.len() > 1 {
            assert_ne!(placed[0].sq_thread_cpu, placed[1].sq_thread_cpu);
        }
        want.sort();
        e.start().unwrap();
        echo(&e);
        assert_eq!(sqp_threads(2), want, "per_cpu {per_cpu}");
        // The I/O threads are placed as without SQPOLL.
        let want: Vec<_> = placed.iter().map(|p| p.cpus.clone()).collect();
        for (i, (_, cpus)) in io_threads(&want).iter().enumerate() {
            assert_eq!(cpus, &placed[i].cpus);
        }
        e.shutdown();
        e.wait();
        drop(e);
        sqp_threads(0);
    }
}
