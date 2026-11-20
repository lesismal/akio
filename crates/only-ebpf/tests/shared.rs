//! Shared (bpffs-pinned) steering and listener migration (ADR-063). Privileged: skipped without
//! `CAP_BPF` and a bpffs mount at /sys/fs/bpf, unless `ONLY_TEST_EXPECT_EBPF=1` (then a skip
//! fails). One process plays every "worker" here; the cross-process case is only-prefork's
//! `bpf` test.
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    path::PathBuf,
    time::{Duration, Instant},
};

use only_ebpf::{HashKey, SharedSteering, Steering};

fn expect_ebpf() -> bool {
    std::env::var("ONLY_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
}

fn privileged<T>(what: &str, r: std::io::Result<T>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) if !expect_ebpf() => {
            eprintln!("skipping {what}: {e}");
            None
        }
        Err(e) => panic!("{what}: {e}"),
    }
}

fn pin_dir(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/sys/fs/bpf/only-test-{}-{name}",
        std::process::id()
    ))
}

fn listen(addr: SocketAddr) -> TcpListener {
    let l = only_sys::listen(addr, true, 128).unwrap();
    l.set_nonblocking(true).unwrap();
    l
}

fn fds(g: &[TcpListener]) -> Vec<i32> {
    g.iter().map(AsRawFd::as_raw_fd).collect()
}

/// Index in `g` of the listener that accepted the connection from `peer`.
fn accepted_by(g: &[&TcpListener], peer: SocketAddr) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        for (i, l) in g.iter().enumerate() {
            if let Ok((_s, from)) = l.accept() {
                assert_eq!(from, peer, "connections are accepted one at a time");
                return i;
            }
        }
        assert!(
            Instant::now() < deadline,
            "connection from {peer} not accepted"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// `TcpExtTCPMigrateReqSuccess` of this network namespace.
fn migrated() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/net/netstat").ok()?;
    let mut lines = s.lines();
    while let (Some(h), Some(v)) = (lines.next(), lines.next()) {
        if !h.starts_with("TcpExt:") {
            continue;
        }
        let i = h
            .split_whitespace()
            .position(|k| k == "TCPMigrateReqSuccess")?;
        return v.split_whitespace().nth(i)?.parse().ok();
    }
    None
}

fn sysctl_migrate() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/tcp_migrate_req").is_ok_and(|v| v.trim() == "1")
}

#[test]
fn shared_slots_follow_their_owner() {
    let key = HashKey::SrcIpPort;
    let dir = pin_dir("slots");
    let Some(owner) = privileged(
        "shared steering",
        SharedSteering::create(&dir, 4, Steering::Hash(key)),
    ) else {
        return;
    };
    assert!(dir.join("meta").exists());
    // Two "workers" with two sockets each; B joins first, so the group's join order differs
    // from the slot order.
    let a0 = listen("127.0.0.1:0".parse().unwrap());
    let local = a0.local_addr().unwrap();
    let a = vec![a0, listen(local)];
    let b = vec![listen(local), listen(local)];
    let sb = SharedSteering::open(&dir).unwrap().at(2, 2).unwrap();
    let info = sb.join(&fds(&b)).unwrap();
    assert!(info.shared);
    assert_eq!(sb.sockets(), 4);
    assert_eq!(sb.steering(), Steering::Hash(key));
    SharedSteering::open(&dir)
        .unwrap()
        .at(0, 2)
        .unwrap()
        .join(&fds(&a))
        .unwrap();
    let check = |a: &[TcpListener], b: &[TcpListener], n: usize| {
        let all: Vec<&TcpListener> = a.iter().chain(b).collect();
        let mut seen = [0usize; 4];
        for _ in 0..n {
            let s = TcpStream::connect(local).unwrap();
            let peer = s.local_addr().unwrap();
            let want = only_ebpf::expected_index(Steering::Hash(key), 4, peer, local).unwrap();
            assert_eq!(accepted_by(&all, peer), want, "peer {peer}");
            seen[want] += 1;
        }
        assert!(seen.iter().all(|&c| c > 0), "{seen:?}");
    };
    check(&a, &b, 64);

    // "Worker" B restarts: its sockets close (and leave the array), the new ones take the
    // same slots.
    drop(b);
    let b2 = vec![listen(local), listen(local)];
    SharedSteering::open(&dir)
        .unwrap()
        .at(2, 2)
        .unwrap()
        .join(&fds(&b2))
        .unwrap();
    check(&a, &b2, 64);

    // The owner removes the pins; the attached program keeps steering.
    drop(owner);
    drop(sb);
    assert!(!dir.exists());
    check(&a, &b2, 32);
    assert!(SharedSteering::open(&dir).is_err());
}

#[test]
fn shared_slots_reject_a_bad_range() {
    let dir = pin_dir("range");
    let Some(s) = privileged(
        "shared steering",
        SharedSteering::create(&dir, 4, Steering::Cpu),
    ) else {
        return;
    };
    assert!(s.at(3, 2).is_err());
    assert!(s.at(0, 0).is_err());
    let l = listen("127.0.0.1:0".parse().unwrap());
    let addr = l.local_addr().unwrap();
    let three = vec![l, listen(addr), listen(addr)];
    // Three sockets do not fit two slots.
    assert!(s.at(0, 2).unwrap().join(&fds(&three)).is_err());
    // Fewer sockets than slots are fine (the rest of the handle's slots are emptied).
    s.at(0, 4).unwrap().join(&fds(&three[..1])).unwrap();
}

/// Connects `n` clients and returns them once the server side has queued them.
fn connect_many(addr: SocketAddr, n: usize) -> Vec<TcpStream> {
    let v: Vec<TcpStream> = (0..n)
        .map(|_| {
            let s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(100));
    v
}

/// Accepts `n` connections on `l` and echoes one 8-byte message on each.
fn accept_and_echo(l: &TcpListener, clients: &mut [TcpStream]) {
    let mut accepted = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while accepted.len() < clients.len() {
        match l.accept() {
            Ok((s, _)) => accepted.push(s),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "{} of {} connections reached the new listener",
                    accepted.len(),
                    clients.len()
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
    for (i, c) in clients.iter_mut().enumerate() {
        c.write_all(&(i as u64).to_be_bytes()).unwrap();
    }
    for s in &mut accepted {
        s.set_nonblocking(false).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut b = [0u8; 8];
        s.read_exact(&mut b).unwrap();
        s.write_all(&b).unwrap();
    }
    for (i, c) in clients.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        c.read_exact(&mut b).unwrap();
        assert_eq!(u64::from_be_bytes(b), i as u64);
    }
}

#[test]
fn closing_listener_migrates_its_accept_queue() {
    let dir = pin_dir("migrate");
    let Some(s) = privileged(
        "shared steering",
        SharedSteering::create(&dir, 1, Steering::Cpu),
    ) else {
        return;
    };
    if !s.migrates() {
        privileged::<()>(
            "SELECT_OR_MIGRATE",
            Err(std::io::Error::other("kernel without SELECT_OR_MIGRATE")),
        );
        return;
    }
    let old = listen("127.0.0.1:0".parse().unwrap());
    let addr = old.local_addr().unwrap();
    s.join(&[old.as_raw_fd()]).unwrap();
    let mut clients = connect_many(addr, 32);
    let before = migrated();
    // The replacement takes the slot, then the old listener closes with 32 queued
    // connections: the program moves them to the slot's socket.
    let new = listen(addr);
    s.join(&[new.as_raw_fd()]).unwrap();
    drop(old);
    accept_and_echo(&new, &mut clients);
    if let (Some(a), Some(b)) = (before, migrated()) {
        assert!(b - a >= 32, "TCPMigrateReqSuccess {a} -> {b}");
    }
}

#[test]
fn closing_listener_migrates_pending_handshakes() {
    // TCP_DEFER_ACCEPT keeps a connection as a request (half-open on the server) until data
    // arrives; it migrates when that data reaches the closed listener, with the packet, so
    // the program's migration branch runs on a real skb.
    let dir = pin_dir("migrate-req");
    let Some(s) = privileged(
        "shared steering",
        SharedSteering::create(&dir, 1, Steering::Cpu),
    ) else {
        return;
    };
    if !s.migrates() {
        privileged::<()>(
            "SELECT_OR_MIGRATE",
            Err(std::io::Error::other("kernel without SELECT_OR_MIGRATE")),
        );
        return;
    }
    let old = listen("127.0.0.1:0".parse().unwrap());
    let secs: libc::c_int = 30;
    // SAFETY: `secs` is a valid c_int option value of the length passed.
    let rc = unsafe {
        libc::setsockopt(
            old.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            (&raw const secs).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0);
    let addr = old.local_addr().unwrap();
    s.join(&[old.as_raw_fd()]).unwrap();
    let mut clients = connect_many(addr, 16);
    // Nothing is accepted yet: the requests wait for data.
    assert_eq!(
        old.accept().map(|_| ()).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::WouldBlock)
    );
    let new = listen(addr);
    s.join(&[new.as_raw_fd()]).unwrap();
    drop(old);
    accept_and_echo(&new, &mut clients);
}

#[test]
fn without_migration_the_accept_queue_is_reset() {
    // The behaviour the program avoids (only meaningful with the sysctl off).
    if sysctl_migrate() {
        eprintln!("skipping: net.ipv4.tcp_migrate_req=1 migrates without a program");
        return;
    }
    let old = listen("127.0.0.1:0".parse().unwrap());
    let addr = old.local_addr().unwrap();
    let clients = connect_many(addr, 8);
    let new = listen(addr);
    drop(old);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        new.accept().map(|_| ()).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::WouldBlock)
    );
    let mut reset = 0;
    for mut c in clients {
        let mut b = [0u8; 1];
        if matches!(c.read(&mut b), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset) {
            reset += 1;
        }
    }
    assert_eq!(reset, 8);
}
