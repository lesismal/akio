//! `EngineBuilder::pin_io_threads`: one CPU per I/O thread, in turn over the groups (shared
//! first, then the others in listener order), threads added by `set_threads` continuing the
//! round. Linux only (CPU affinity). One test: it reads the affinity of every `akio-io-*`
//! thread of the process, so no other engine may run meanwhile.
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

mod common;

use std::{net::SocketAddr, time::Duration};

use akio::{Config, Conn, Engine, Handler, Listener, fn_acceptor};

struct Nop;
impl Handler for Nop {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
}

fn listener() -> Listener {
    let a: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Listener::tcp(a)
        .backend(common::backend())
        .serve(fn_acceptor(|_c: &Conn<Nop>| Nop))
}

/// The CPU list of every I/O thread of this process, by thread id (ascending: spawn order).
fn io_affinity() -> Vec<String> {
    let mut v: Vec<(u64, String)> = std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|t| {
            let t = t.ok()?;
            let comm = std::fs::read_to_string(t.path().join("comm")).ok()?;
            if !comm.starts_with("akio-io-") {
                return None;
            }
            let status = std::fs::read_to_string(t.path().join("status")).ok()?;
            let cpus = status
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))?
                .trim()
                .to_owned();
            Some((t.file_name().to_str()?.parse().ok()?, cpus))
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, c)| c).collect()
}

/// [`io_affinity`] once `n` I/O threads exist (a thread takes its name when it starts).
fn io_affinity_of(n: usize) -> Vec<String> {
    let t0 = std::time::Instant::now();
    loop {
        let v = io_affinity();
        if v.len() >= n {
            return v;
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "{v:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Waits (5 s at most) until the I/O threads' CPU lists are `want` (a thread pins itself when
/// it starts, just after taking its name).
fn wait_affinity(want: &[String]) {
    let t0 = std::time::Instant::now();
    loop {
        let v = io_affinity();
        if v == want {
            return;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "{v:?}, want {want:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The CPUs this process may use.
fn allowed() -> Vec<usize> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let list = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .unwrap()
        .trim()
        .to_owned();
    let mut cpus = Vec::new();
    for part in list.split(',') {
        match part.split_once('-') {
            Some((a, b)) => cpus.extend(a.parse::<usize>().unwrap()..=b.parse().unwrap()),
            None => cpus.push(part.parse().unwrap()),
        }
    }
    cpus
}

fn quick() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

#[test]
fn io_threads_get_one_cpu_each_in_turn() {
    if common::rounds() || std::env::var("AKIO_DEFAULT_BACKEND").is_ok() {
        return; // rounds workers are not pinned; another default backend changes the groups
    }
    let cpus = allowed();
    if cpus.len() < 2 {
        eprintln!("skipped: one CPU allowed");
        return;
    }
    let n = cpus.len();
    // Off: the threads keep the process's CPUs.
    let e = Engine::builder()
        .config(quick())
        .io_threads(2)
        .listen(listener())
        .build()
        .unwrap();
    e.start().unwrap();
    let off = io_affinity_of(2);
    assert_eq!(off.len(), 2);
    assert!(
        off.iter().all(|c| c.contains('-') || c.contains(',')),
        "{off:?}"
    );
    e.shutdown();
    e.wait();

    // On: the shared group's 2 threads first, then the dedicated listener's thread.
    let e = Engine::builder()
        .config(quick())
        .pin_io_threads(true)
        .io_threads(2)
        .listen(listener())
        .listen(listener())
        .listen(listener().threads(1))
        .build()
        .unwrap();
    e.start().unwrap();
    let cpu = |i: usize| cpus[i % n].to_string();
    // The shared group's 2 threads, then the dedicated listener's.
    let mut want = vec![cpu(0), cpu(1), cpu(2)];
    wait_affinity(&want);
    // A thread added later continues the shared group's round (its sets reach one per CPU).
    e.set_threads(0, 3).unwrap();
    want.push(cpu(2));
    wait_affinity(&want);
    // A listener added at run time with threads of its own continues after the others.
    e.add_listener(listener().threads(1)).unwrap();
    want.push(cpu(3));
    wait_affinity(&want);
    e.shutdown();
    e.wait();
}
