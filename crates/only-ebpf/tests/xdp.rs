//! The XDP rate limiter on the loopback interface (generic mode). Needs `CAP_NET_ADMIN` and
//! `CAP_BPF`: skipped without them unless `ONLY_TEST_EXPECT_EBPF=1`. The tests attach to `lo`,
//! so they run one at a time, in this binary of their own (other tests' loopback traffic would
//! be rate limited too). Run them in a network namespace of their own (a container).
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
    time::Duration,
};

use only_ebpf::xdp::{Attachment, Count, RateLimiter, XdpLimit, XdpMode};

static LO: Mutex<()> = Mutex::new(());

fn expect_ebpf() -> bool {
    std::env::var("ONLY_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
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

/// Sends `n` datagrams from `from` to a fresh socket and counts what arrives.
fn udp_burst(from: &str, n: usize) -> usize {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let tx = UdpSocket::bind(from).unwrap();
    for _ in 0..n {
        tx.send_to(b"x", rx.local_addr().unwrap()).unwrap();
    }
    let mut got = 0;
    let mut b = [0u8; 8];
    while rx.recv_from(&mut b).is_ok() {
        got += 1;
    }
    got
}

#[test]
fn udp_flood_is_cut_to_the_burst_per_source() {
    let _g = LO.lock().unwrap_or_else(|p| p.into_inner());
    let Some(l) = attach(&limit(Count::AllPackets, 1, 10)) else {
        return;
    };
    assert_eq!(l.mode(), XdpMode::Generic, "lo has no native XDP");
    assert_eq!(l.attachment(), Attachment::Link);
    // Each source has its own bucket; one second refills one packet.
    let a = udp_burst("127.0.0.2:0", 200);
    let b = udp_burst("127.0.0.3:0", 200);
    assert!((10..=11).contains(&a), "{a} datagrams from .2 passed");
    assert!((10..=11).contains(&b), "{b} datagrams from .3 passed");
    let s = l.stats().unwrap();
    assert!(s.dropped >= 2 * 189, "{s:?}");
    assert!(s.new_sources >= 2, "{s:?}");
    // Forgetting a source refills it.
    assert!(l.forget("127.0.0.2".parse().unwrap()).unwrap());
    assert!(!l.forget("127.0.0.99".parse().unwrap()).unwrap());
    assert!(udp_burst("127.0.0.2:0", 20) >= 10);
    // Detached: everything passes.
    l.detach().unwrap();
    assert_eq!(udp_burst("127.0.0.2:0", 50), 50);
}

#[test]
fn syn_flood_protection_leaves_established_connections_alone() {
    let _g = LO.lock().unwrap_or_else(|p| p.into_inner());
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    // An established connection before the limiter.
    let mut old = TcpStream::connect(addr).unwrap();
    let (mut old_peer, _) = server.accept().unwrap();
    let Some(l) = attach(&limit(Count::TcpSyn, 1, 3)) else {
        return;
    };
    let connect = || TcpStream::connect_timeout(&addr, Duration::from_millis(400));
    let mut keep = Vec::new();
    for i in 0..3 {
        keep.push(connect().unwrap_or_else(|e| panic!("connection {i}: {e}")));
    }
    // The fourth SYN is dropped (its retransmission comes after the timeout).
    let e = connect().unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}");
    // Established traffic is not counted.
    use std::io::{Read, Write};
    for _ in 0..100 {
        old.write_all(b"ping").unwrap();
        let mut b = [0u8; 4];
        old_peer.read_exact(&mut b).unwrap();
    }
    let s = l.stats().unwrap();
    assert!(s.dropped >= 1 && s.passed == 3, "{s:?}");
    assert_eq!(keep.len(), 3);
    drop(l);
    connect().expect("connect after detach");
}

#[test]
fn netlink_attachment_and_exclusivity() {
    let _g = LO.lock().unwrap_or_else(|p| p.into_inner());
    let mut cfg = limit(Count::AllPackets, 1, 5);
    cfg.force_netlink = true;
    let Some(l) = attach(&cfg) else {
        return;
    };
    assert_eq!(l.attachment(), Attachment::Netlink);
    let n = udp_burst("127.0.0.4:0", 50);
    assert!((5..=6).contains(&n), "{n}");
    // Someone else's program is never replaced.
    let e = RateLimiter::attach("lo", &limit(Count::AllPackets, 1, 5)).unwrap_err();
    assert!(
        matches!(e.raw_os_error(), Some(16 | 17)),
        "EBUSY/EEXIST expected: {e}"
    );
    l.detach().unwrap();
    assert_eq!(udp_burst("127.0.0.4:0", 50), 50);
    // Dropping a link-attached limiter detaches too: a new one attaches.
    let l = attach(&limit(Count::AllPackets, 1, 5)).unwrap();
    assert_eq!(l.attachment(), Attachment::Link);
    drop(l);
    let l = attach(&limit(Count::AllPackets, 1, 5)).unwrap();
    drop(l);
    assert_eq!(udp_burst("127.0.0.4:0", 50), 50);
}

#[test]
fn native_mode_on_loopback_is_refused() {
    let _g = LO.lock().unwrap_or_else(|p| p.into_inner());
    let mut cfg = XdpLimit::default();
    cfg.mode = XdpMode::Native;
    match RateLimiter::attach("lo", &cfg) {
        Ok(_) => panic!("lo has no native XDP"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && !expect_ebpf() => {}
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
}

#[test]
fn invalid_configurations() {
    let mut cfg = XdpLimit::default();
    cfg.rate = 0;
    assert_eq!(
        RateLimiter::attach_index(1, &cfg).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
