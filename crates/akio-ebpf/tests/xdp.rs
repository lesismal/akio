//! The XDP rate limiter on the loopback interface (generic mode). Needs `CAP_NET_ADMIN` and
//! `CAP_BPF`: skipped without them unless `AKIO_TEST_EXPECT_EBPF=1`. Each test runs on a thread
//! of its own in a network namespace of its own (with `CAP_SYS_ADMIN`; see [`isolated`]), so
//! the `lo` it rate limits carries nothing but its own packets: the host's loopback traffic
//! (every other process's) is neither limited by it nor spends its buckets. Without
//! `CAP_SYS_ADMIN` they run on the current namespace's `lo`, one at a time: run them in a
//! network namespace of their own then (a container).
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{
    io,
    net::{TcpListener, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    sync::Mutex,
    time::{Duration, Instant},
};

use akio_ebpf::xdp::{Attachment, Count, RateLimiter, XdpLimit, XdpMode, XdpStats};

static LO: Mutex<()> = Mutex::new(());

/// How long a datagram or connection that passes may take on a loaded host.
const WAIT: Duration = Duration::from_secs(10);

fn expect_ebpf() -> bool {
    std::env::var("AKIO_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
}

/// Runs `f` on a thread of its own, in a network namespace of its own when we may make one
/// (`unshare(CLONE_NEWNET)`, its `lo` brought up), pinned to the CPU it starts on:
/// - the namespace's `lo` carries only the test's packets: the host's loopback traffic (on a
///   shared host, hundreds of connections a second from `127.0.0.1`) would take the credit of
///   the test's sources, and the test would rate limit every other process's loopback;
/// - the buckets are per receiving CPU, and a loopback packet is received on the CPU that sent
///   it: a thread that moved between CPUs would give each source a bucket on each of them.
fn isolated(f: impl FnOnce() + Send + 'static) {
    let _g = LO.lock().unwrap_or_else(|p| p.into_inner());
    let r = std::thread::spawn(move || {
        // SAFETY: plain syscall; it moves only this thread to a new network namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0 {
            lo_up();
        } else {
            let e = io::Error::last_os_error();
            eprintln!("no network namespace of our own ({e}): testing on this one's lo");
        }
        pin_to_this_cpu();
        f();
    })
    .join();
    if let Err(p) = r {
        std::panic::resume_unwind(p);
    }
}

/// Brings `lo` up (a new network namespace starts with it down).
fn lo_up() {
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    // SAFETY: `ifreq` is plain data, all zeroes a valid value.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (d, c) in ifr.ifr_name.iter_mut().zip(b"lo") {
        *d = *c as libc::c_char;
    }
    // SAFETY: `ifr` is a valid `ifreq` naming an interface, as both requests take.
    unsafe {
        assert_eq!(
            libc::ioctl(s.as_raw_fd(), libc::SIOCGIFFLAGS as _, &raw mut ifr),
            0,
            "SIOCGIFFLAGS lo: {}",
            io::Error::last_os_error()
        );
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        assert_eq!(
            libc::ioctl(s.as_raw_fd(), libc::SIOCSIFFLAGS as _, &raw const ifr),
            0,
            "SIOCSIFFLAGS lo: {}",
            io::Error::last_os_error()
        );
    }
}

fn pin_to_this_cpu() {
    // SAFETY: plain syscalls on this thread; `cpu_set_t` is plain data, zeroes the empty set.
    unsafe {
        let cpu = libc::sched_getcpu();
        assert!(cpu >= 0, "sched_getcpu: {}", io::Error::last_os_error());
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu as usize, &mut set);
        assert_eq!(
            libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set),
            0,
            "sched_setaffinity: {}",
            io::Error::last_os_error()
        );
    }
}

fn limit(count: Count, rate: u32, burst: u32) -> XdpLimit {
    let mut c = XdpLimit::default();
    c.count = count;
    c.rate = rate;
    c.burst = burst;
    c
}

fn attach(cfg: &XdpLimit) -> Option<RateLimiter> {
    match RateLimiter::attach("lo", cfg) {
        Ok(l) => Some(l),
        Err(e) if !expect_ebpf() => {
            eprintln!("skipping XDP test: {e}");
            None
        }
        Err(e) => panic!("XDP attach: {e}"),
    }
}

/// Sends `n` datagrams from `from` to a fresh socket and counts what arrives: with no limiter,
/// all `n` (each waited for); with `l`, what the program let pass, once it has judged every one.
fn udp_burst(l: Option<&RateLimiter>, from: &str, n: usize) -> usize {
    udp_burst_timed(l, from, n).0
}

/// [`udp_burst`], also returning how long the program took over them from the first send (the
/// buckets refill meanwhile).
fn udp_burst_timed(l: Option<&RateLimiter>, from: &str, n: usize) -> (usize, Duration) {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind(from).unwrap();
    let before = l.map(|l| l.stats().unwrap());
    let start = Instant::now();
    for _ in 0..n {
        tx.send_to(b"x", rx.local_addr().unwrap()).unwrap();
    }
    // The program counts each datagram before the socket gets it (if it passes).
    let passed = match (l, before) {
        (Some(l), Some(before)) => {
            let judged = |s: &XdpStats| s.passed + s.dropped - before.passed - before.dropped;
            let s = wait_stats(l, |s| judged(s) >= n as u64);
            assert_eq!(
                judged(&s),
                n as u64,
                "only our datagrams are counted: {s:?}"
            );
            (s.passed - before.passed) as usize
        }
        _ => n,
    };
    let took = start.elapsed();
    rx.set_read_timeout(Some(WAIT)).unwrap();
    let mut b = [0u8; 8];
    for i in 0..passed {
        rx.recv_from(&mut b)
            .unwrap_or_else(|e| panic!("datagram {i} of the {passed} that passed: {e}"));
    }
    rx.set_nonblocking(true).unwrap();
    let more = rx.recv_from(&mut b);
    assert!(
        more.as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock),
        "more than the {passed} that passed: {more:?}"
    );
    (passed, took)
}

/// Waits (bounded) for the limiter's counters to satisfy `done`, and returns them.
fn wait_stats(l: &RateLimiter, done: impl Fn(&XdpStats) -> bool) -> XdpStats {
    let deadline = Instant::now() + WAIT;
    loop {
        let s = l.stats().unwrap();
        if done(&s) {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "the program never saw them all: {s:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn udp_flood_is_cut_to_the_burst_per_source() {
    isolated(|| {
        let Some(l) = attach(&limit(Count::AllPackets, 1, 10)) else {
            return;
        };
        assert_eq!(l.mode(), XdpMode::Generic, "lo has no native XDP");
        assert_eq!(l.attachment(), Attachment::Link);
        // Each source has its own bucket; one second refills one packet (a loaded host may
        // take more than a second over them: one more packet per second it took).
        let (a, ta) = udp_burst_timed(Some(&l), "127.0.0.2:0", 200);
        let (b, tb) = udp_burst_timed(Some(&l), "127.0.0.3:0", 200);
        let max = |t: Duration| 11 + t.as_secs() as usize;
        assert!(
            (10..=max(ta)).contains(&a),
            "{a} datagrams from .2 passed in {ta:?}"
        );
        assert!(
            (10..=max(tb)).contains(&b),
            "{b} datagrams from .3 passed in {tb:?}"
        );
        let s = l.stats().unwrap();
        assert!(s.dropped >= 2 * 189, "{s:?}");
        assert!(s.new_sources >= 2, "{s:?}");
        // Forgetting a source refills it.
        assert!(l.forget("127.0.0.2".parse().unwrap()).unwrap());
        assert!(!l.forget("127.0.0.99".parse().unwrap()).unwrap());
        assert!(udp_burst(Some(&l), "127.0.0.2:0", 20) >= 10);
        // Detached: everything passes.
        l.detach().unwrap();
        assert_eq!(udp_burst(None, "127.0.0.2:0", 50), 50);
    });
}

#[test]
fn syn_flood_protection_leaves_established_connections_alone() {
    isolated(|| {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        // An established connection before the limiter.
        let mut old = TcpStream::connect(addr).unwrap();
        let (mut old_peer, _) = server.accept().unwrap();
        let Some(l) = attach(&limit(Count::TcpSyn, 1, 3)) else {
            return;
        };
        let start = Instant::now();
        let mut keep = Vec::new();
        for i in 0..3 {
            let c = TcpStream::connect_timeout(&addr, WAIT);
            keep.push(c.unwrap_or_else(|e| panic!("connection {i}: {e}")));
        }
        // The burst, not a SYN retransmitted after a refill.
        let s = l.stats().unwrap();
        assert!(s.passed == 3 && s.dropped == 0, "{s:?}");
        // The fourth SYN is dropped (its retransmission would come after the timeout), as long
        // as it comes within the second that refills one.
        let sent_after = start.elapsed();
        let r = TcpStream::connect_timeout(&addr, Duration::from_millis(400));
        assert!(
            sent_after < Duration::from_secs(1),
            "the first three took {sent_after:?}"
        );
        let e = r.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        // Established traffic is not counted.
        use io::{Read, Write};
        for _ in 0..100 {
            old.write_all(b"ping").unwrap();
            let mut b = [0u8; 4];
            old_peer.read_exact(&mut b).unwrap();
        }
        let s = l.stats().unwrap();
        assert!(s.dropped >= 1 && s.passed == 3, "{s:?}");
        assert_eq!(keep.len(), 3);
        drop(l);
        TcpStream::connect_timeout(&addr, WAIT).expect("connect after detach");
    });
}

#[test]
fn netlink_attachment_and_exclusivity() {
    isolated(|| {
        let mut cfg = limit(Count::AllPackets, 1, 5);
        cfg.force_netlink = true;
        let Some(l) = attach(&cfg) else {
            return;
        };
        assert_eq!(l.attachment(), Attachment::Netlink);
        let (n, took) = udp_burst_timed(Some(&l), "127.0.0.4:0", 50);
        assert!(
            (5..=6 + took.as_secs() as usize).contains(&n),
            "{n} in {took:?}"
        );
        // Someone else's program is never replaced.
        let e = RateLimiter::attach("lo", &limit(Count::AllPackets, 1, 5)).unwrap_err();
        assert!(
            matches!(e.raw_os_error(), Some(16 | 17)),
            "EBUSY/EEXIST expected: {e}"
        );
        l.detach().unwrap();
        assert_eq!(udp_burst(None, "127.0.0.4:0", 50), 50);
        // Dropping a link-attached limiter detaches too: a new one attaches.
        let l = attach(&limit(Count::AllPackets, 1, 5)).unwrap();
        assert_eq!(l.attachment(), Attachment::Link);
        drop(l);
        let l = attach(&limit(Count::AllPackets, 1, 5)).unwrap();
        drop(l);
        assert_eq!(udp_burst(None, "127.0.0.4:0", 50), 50);
    });
}

#[test]
fn native_mode_on_loopback_is_refused() {
    isolated(|| {
        let mut cfg = XdpLimit::default();
        cfg.mode = XdpMode::Native;
        match RateLimiter::attach("lo", &cfg) {
            Ok(_) => panic!("lo has no native XDP"),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !expect_ebpf() => {}
            Err(e) => assert!(
                matches!(e.raw_os_error(), Some(95 | 22)),
                "EOPNOTSUPP/EINVAL expected: {e}"
            ),
        }
        assert_eq!(
            RateLimiter::attach("no-such-if0", &XdpLimit::default())
                .unwrap_err()
                .raw_os_error(),
            Some(19) // ENODEV
        );
    });
}

#[test]
fn invalid_configurations() {
    let mut cfg = XdpLimit::default();
    cfg.rate = 0;
    assert_eq!(
        RateLimiter::attach_index(1, &cfg).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}
