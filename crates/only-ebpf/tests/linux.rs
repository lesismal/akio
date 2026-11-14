//! Kernel tests on plain sockets. Steering with classic BPF runs unprivileged; the eBPF tier and
//! the sockmap relay need privileges and are skipped without them, unless
//! `ONLY_TEST_EXPECT_EBPF=1` is set (privileged CI), which turns a skip into a failure.
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use only_ebpf::{AttachOptions, HashKey, Relay, Steering, Tier, attach_reuseport};

fn expect_ebpf() -> bool {
    std::env::var("ONLY_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
}

/// `Some(v)`, or `None` (skip) when the error says "not permitted / not supported" and
/// privileged results are not demanded.
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

/// `n` non-blocking `SO_REUSEPORT` listeners on one loopback port, in listen order.
fn group(n: usize) -> Vec<TcpListener> {
    let first = only_sys::listen("127.0.0.1:0".parse().unwrap(), true, 128).unwrap();
    let addr = first.local_addr().unwrap();
    let mut v = vec![first];
    for _ in 1..n {
        v.push(only_sys::listen(addr, true, 128).unwrap());
    }
    for l in &v {
        l.set_nonblocking(true).unwrap();
    }
    v
}

/// Index of the listener that accepted the connection from `peer`.
fn accepted_by(g: &[TcpListener], peer: SocketAddr) -> usize {
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

fn pin_to_cpu(cpu: usize) -> bool {
    // SAFETY: `set` is a plain bitmask initialized by CPU_ZERO/CPU_SET before use.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set) == 0
    }
}

fn cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// Connects from each CPU in turn (the loopback SYN is processed on the sending CPU) and
/// checks the connection lands on listener `cpu % n`.
fn check_cpu_steering(g: &[TcpListener]) {
    let addr = g[0].local_addr().unwrap();
    let n = g.len();
    for cpu in 0..cpus().min(8) {
        let peer = std::thread::spawn(move || {
            assert!(pin_to_cpu(cpu), "sched_setaffinity({cpu})");
            let s = TcpStream::connect(addr).unwrap();
            (s.local_addr().unwrap(), s)
        })
        .join()
        .unwrap();
        assert_eq!(accepted_by(g, peer.0), cpu % n, "connection from CPU {cpu}");
    }
}

#[test]
fn cbpf_cpu_steering_follows_the_receiving_cpu() {
    let g = group(3);
    let fds: Vec<i32> = g.iter().map(|l| l.as_raw_fd()).collect();
    let info = attach_reuseport(&fds, Steering::Cpu, {
        let mut o = AttachOptions::default();
        o.ebpf = false;
        o
    })
    .unwrap();
    assert_eq!(info.tier, Tier::Cbpf);
    check_cpu_steering(&g);
}

#[test]
fn cbpf_hash_steering_matches_expected_index() {
    for key in [HashKey::SrcIp, HashKey::SrcIpPort] {
        let g = group(4);
        let fds: Vec<i32> = g.iter().map(|l| l.as_raw_fd()).collect();
        let info = attach_reuseport(&fds, Steering::Hash(key), AttachOptions::default()).unwrap();
        assert_eq!(info.tier, Tier::Cbpf);
        let local = g[0].local_addr().unwrap();
        let mut seen = [0usize; 4];
        for _ in 0..64 {
            let s = TcpStream::connect(local).unwrap();
            let peer = s.local_addr().unwrap();
            let got = accepted_by(&g, peer);
            let want = only_ebpf::expected_index(Steering::Hash(key), 4, peer, local).unwrap();
            assert_eq!(got, want, "{key:?} peer {peer}");
            seen[got] += 1;
        }
        match key {
            // One source address: all on one thread.
            HashKey::SrcIp => assert_eq!(seen.iter().filter(|&&c| c > 0).count(), 1),
            // Different source ports spread.
            HashKey::SrcIpPort => assert!(seen.iter().filter(|&&c| c > 0).count() >= 3),
            _ => {}
        }
    }
}

#[test]
fn ebpf_cpu_steering_with_a_socket_array() {
    let g = group(3);
    let fds: Vec<i32> = g.iter().map(|l| l.as_raw_fd()).collect();
    let info = attach_reuseport(&fds, Steering::Cpu, {
        let mut o = AttachOptions::default();
        o.ebpf = true;
        o
    })
    .unwrap();
    if info.tier != Tier::Ebpf {
        let why = info.ebpf_unavailable.unwrap_or_default();
        privileged::<()>("eBPF reuseport", Err(std::io::Error::other(why)));
    }
    check_cpu_steering(&g);
}

fn read_exact_loop(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match s.read(&mut v[got..]) {
            Ok(0) => panic!("EOF after {got} of {n} bytes"),
            Ok(k) => got += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("read after {got} of {n} bytes: {e}"),
        }
    }
    v
}

/// Compares without printing megabytes.
fn assert_same(got: &[u8], want: &[u8]) {
    assert_eq!(got.len(), want.len());
    if let Some(i) = got.iter().zip(want).position(|(a, b)| a != b) {
        let near = |v: &[u8]| v[i..(i + 16).min(v.len())].to_vec();
        let bad = got.iter().zip(want).filter(|(a, b)| a != b).count();
        panic!(
            "first difference at byte {i} of {} ({bad} differ): got {:?} want {:?}",
            want.len(),
            near(got),
            near(want)
        );
    }
}

#[test]
fn sockmap_relay_splices_two_connections() {
    // On kernels below MIN_KERNEL only transfers that never fill a send buffer are safe.
    let Some(relay) = privileged("sockmap relay", Relay::new_any_kernel(4)) else {
        return;
    };
    let fixed = Relay::new(1).is_ok();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let mut c1 = TcpStream::connect(addr).unwrap();
    let (a, _) = l.accept().unwrap();
    let mut c2 = TcpStream::connect(addr).unwrap();
    let (b, _) = l.accept().unwrap();
    for s in [&c1, &c2, &a, &b] {
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    }
    let splice = relay.splice(a.as_raw_fd(), b.as_raw_fd()).unwrap();
    assert_ne!(splice.cookies()[0], splice.cookies()[1]);

    // Both directions, small and bulk; userspace never touches `a` or `b`.
    c1.write_all(b"ping").unwrap();
    assert_eq!(read_exact_loop(&mut c2, 4), b"ping");
    c2.write_all(b"pong").unwrap();
    assert_eq!(read_exact_loop(&mut c1, 4), b"pong");
    let size: u32 = if fixed { 16 << 20 } else { 128 << 10 };
    let bulk: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
    let mut w = c1.try_clone().unwrap();
    let data = bulk.clone();
    let writer = std::thread::spawn(move || w.write_all(&data).unwrap());
    let got = read_exact_loop(&mut c2, bulk.len());
    writer.join().unwrap();
    assert_same(&got, &bulk);

    // Nothing reached the spliced sockets' own receive queues.
    a.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(
        (&a).read(&mut buf).map_err(|e| e.kind()),
        Err(std::io::ErrorKind::WouldBlock)
    );
    a.set_nonblocking(false).unwrap();

    // Unsplice: data goes to userspace again.
    splice.unsplice().unwrap();
    c1.write_all(b"back").unwrap();
    let mut a = a;
    assert_eq!(read_exact_loop(&mut a, 4), b"back");

    // Splice again, then EOF on one side reaches the spliced socket as EOF.
    let _s = relay.splice(a.as_raw_fd(), b.as_raw_fd()).unwrap();
    drop(c1);
    let mut one = [0u8; 1];
    assert_eq!(a.read(&mut one).unwrap(), 0);
}

#[test]
fn relay_refuses_kernels_with_the_eagain_bug() {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut it = release.trim().split('.');
    let v: (u32, u32) = (
        it.next().unwrap().parse().unwrap(),
        it.next().unwrap().parse().unwrap(),
    );
    if v < only_ebpf::relay::MIN_KERNEL {
        let e = Relay::new(1).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported, "{e}");
    }
}
