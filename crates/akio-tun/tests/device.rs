//! TUN devices end to end: the kernel's IP stack on one side, a handler on the other.
//!
//! Creating a device needs `CAP_NET_ADMIN` and `/dev/net/tun` on Linux, root on macOS. Without
//! them every test that needs a device prints why it skipped and passes, unless
//! `AKIO_TEST_EXPECT_TUN=1` says this run is privileged (the Linux Docker and benchmark-host
//! runs: `docker run --cap-add NET_ADMIN --device /dev/net/tun`, IPv6 enabled with
//! `--sysctl net.ipv6.conf.all.disable_ipv6=0`), where a skip is a failure. The ping and
//! device-deletion tests also need `ping` and `ip` (iproute2), and skip without them.
//!
//! Each test has its own interface (`akt<N>`, N from 1 to 9) and subnets (`10.201.<N>.0/24`,
//! `fd00:201:<N>::/64`), so the tests run in parallel.
#![allow(missing_docs)]
// Most tests need a Linux kernel (macOS runs the device ones as root only, without routes).
#![cfg_attr(target_os = "macos", allow(unused_imports, dead_code))]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use akio::tun::{TunConfig, TunDevice, TunServer};
use akio::{Config, Conn, Error, Handler, fn_acceptor};

/// Whether this process may create TUN devices; prints why not (or fails, when the run is
/// meant to be privileged).
fn privileged() -> bool {
    static CHECK: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    let r = CHECK.get_or_init(|| {
        TunDevice::create(&TunConfig::new().up(false))
            .map(drop)
            .map_err(|e| e.to_string())
    });
    match r {
        Ok(()) => true,
        Err(e) => {
            assert!(
                std::env::var("AKIO_TEST_EXPECT_TUN").as_deref() != Ok("1"),
                "AKIO_TEST_EXPECT_TUN=1 but a TUN device cannot be created: {e}"
            );
            eprintln!(
                "skipped: cannot create a TUN device ({e}); needs CAP_NET_ADMIN and \
                 /dev/net/tun on Linux, root on macOS (AKIO_TEST_EXPECT_TUN=1 makes this a \
                 failure)"
            );
            false
        }
    }
}

fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    f()
}

// ---- packets -----------------------------------------------------------------------------

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let w = u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]);
        sum += u32::from(w);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 UDP packet (UDP checksum 0: none).
fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

/// The IP header length and protocol of an IPv4 or IPv6 packet (IPv6 without extension
/// headers).
fn l4(pkt: &[u8]) -> Option<(usize, u8)> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some((usize::from(pkt[0] & 0x0f) * 4, pkt[9])),
        6 if pkt.len() >= 40 => Some((40, pkt[6])),
        _ => None,
    }
}

/// Swaps the addresses of an IP packet (no checksum changes: both sums cover both addresses).
fn swap_addrs(p: &mut [u8]) {
    let (a, len) = if p[0] >> 4 == 4 { (12, 4) } else { (8, 16) };
    for i in 0..len {
        p.swap(a + i, a + len + i);
    }
}

/// A UDP packet sent back where it came from (addresses and ports swapped; checksums stay
/// valid).
fn udp_reflect(pkt: &[u8]) -> Option<Vec<u8>> {
    let (h, proto) = l4(pkt)?;
    if proto != 17 || pkt.len() < h + 8 {
        return None;
    }
    let mut p = pkt.to_vec();
    swap_addrs(&mut p);
    for i in 0..2 {
        p.swap(h + i, h + 2 + i);
    }
    Some(p)
}

/// The echo reply to an ICMP / ICMPv6 echo request.
fn echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    let (h, proto) = l4(pkt)?;
    let mut p = pkt.to_vec();
    match proto {
        1 if p.get(h) == Some(&8) => {
            p[h] = 0;
            p[h + 2..h + 4].fill(0);
            let c = checksum(&p[h..]);
            p[h + 2..h + 4].copy_from_slice(&c.to_be_bytes());
        }
        58 if p.get(h) == Some(&128) => {
            // Type 128 -> 129: the checksum drops by 0x0100 (RFC 1624 update).
            p[h] = 129;
            let old = u16::from_be_bytes([p[h + 2], p[h + 3]]);
            let mut sum = u32::from(!old) + u32::from(!0x8000u16) + 0x8100;
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            p[h + 2..h + 4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        }
        _ => return None,
    }
    swap_addrs(&mut p);
    Some(p)
}

/// Answers UDP and pings, counting packets.
struct Reflector {
    seen: Arc<AtomicUsize>,
}

impl Handler for Reflector {
    fn on_data(&mut self, c: &Conn<Self>, pkt: &[u8]) {
        self.seen.fetch_add(1, Ordering::Relaxed);
        if let Some(r) = udp_reflect(pkt).or_else(|| echo_reply(pkt)) {
            let _ = c.send(&r);
        }
    }
}

fn reflector(seen: &Arc<AtomicUsize>) -> impl akio::Acceptor<Handler = Reflector> {
    let seen = seen.clone();
    fn_acceptor(move |_c: &Conn<Reflector>| Reflector { seen: seen.clone() })
}

fn v4(n: u8, host: u8) -> IpAddr {
    IpAddr::from([10, 201, n, host])
}

fn v6(n: u8, host: u16) -> IpAddr {
    IpAddr::from([0xfd00, 0x201, u16::from(n), 0, 0, 0, 0, host])
}

/// A device `akt<n>` with both test subnets (macOS: a kernel-named utun).
fn device(n: u8, queues: usize) -> io::Result<TunDevice> {
    let cfg = TunConfig::new()
        .mtu(1280)
        .address(v4(n, 1), 24)
        .address(v6(n, 1), 64)
        .queues(queues);
    #[cfg(target_os = "linux")]
    let cfg = cfg.name(format!("akt{n}"));
    TunDevice::create(&cfg)
}

fn quick_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(500);
    cfg
}

fn has_tool(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
}

// ---- tests -------------------------------------------------------------------------------

#[test]
fn invalid_configurations() {
    #[cfg(target_os = "linux")]
    {
        let e = TunDevice::create(&TunConfig::new().name("a-name-far-too-long")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }
    #[cfg(target_os = "macos")]
    {
        let e = TunDevice::create(&TunConfig::new().name("tun0")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = TunDevice::create(&TunConfig::new().queues(2)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }
    if !privileged() {
        // The skip itself is what is tested: a clear error, not a panic or a hang.
        let e = TunDevice::create(&TunConfig::new()).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
            ) || e.raw_os_error().is_some(),
            "{e:?}"
        );
    }
}

#[test]
fn create_configure_destroy() {
    if !privileged() {
        return;
    }
    let dev = device(1, 1).unwrap();
    let ctl = dev.control();
    let name = dev.name().to_owned();
    assert_eq!(ctl.name(), name);
    #[cfg(target_os = "linux")]
    assert_eq!(name, "akt1");
    assert_eq!(dev.queues(), 1);
    assert_eq!(ctl.mtu().unwrap(), 1280);
    assert!(ctl.is_up().unwrap());
    let index = ctl.index().unwrap();
    assert!(index > 0);
    let find = || {
        akio_sys::interfaces()
            .unwrap()
            .into_iter()
            .find(|i| i.name == name)
    };
    let iface = find().expect("interface listed");
    assert!(iface.has_addr(v4(1, 1)), "{iface:?}");
    assert!(iface.has_addr(v6(1, 1)), "{iface:?}");
    ctl.set_mtu(1400).unwrap();
    assert_eq!(ctl.mtu().unwrap(), 1400);
    ctl.remove_address(v6(1, 1), 64).unwrap();
    assert!(!find().unwrap().has_addr(v6(1, 1)));
    ctl.add_address(v6(1, 7), 64).unwrap();
    assert!(find().unwrap().has_addr(v6(1, 7)));
    ctl.set_up(false).unwrap();
    assert!(!ctl.is_up().unwrap());
    ctl.set_up(true).unwrap();
    drop(dev);
    // The last queue closed: the interface is gone.
    assert!(wait_until(Duration::from_secs(2), || ctl.index().is_err()));
}

#[cfg(target_os = "linux")]
#[test]
fn udp_through_the_device_on_an_engine() {
    use std::net::{SocketAddr, UdpSocket};
    if !privileged() {
        return;
    }
    let engine = akio::Engine::builder().build().unwrap();
    engine.start().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let server = engine
        .serve_tun(device(2, 1).unwrap(), reflector(&seen))
        .unwrap();
    assert_eq!(server.queues(), 1);
    for (bind, peer) in [
        ("0.0.0.0:0", SocketAddr::new(v4(2, 2), 4000)),
        ("[::]:0", SocketAddr::new(v6(2, 2), 4000)),
    ] {
        let s = UdpSocket::bind(bind).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        for i in 0..3u8 {
            s.send_to(&[i; 100], peer).unwrap();
            let mut buf = [0u8; 2048];
            let (n, from) = s.recv_from(&mut buf).unwrap();
            assert_eq!(from, peer);
            assert_eq!(&buf[..n], &[i; 100]);
        }
    }
    // The engine's connection table and metrics see the queue.
    let conns = engine.connections(Duration::from_secs(2));
    assert!(conns.iter().any(|c| c.owner.backend == "tun"), "{conns:?}");
    server.shutdown();
    server.join();
    assert!(server.is_closed());
    engine.shutdown();
}

#[cfg(target_os = "linux")]
#[test]
fn ping_through_the_device() {
    if !privileged() {
        return;
    }
    if !has_tool("ping") {
        eprintln!("skipped: no `ping` binary (iputils-ping)");
        return;
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let _server = TunServer::start(device(3, 1).unwrap(), reflector(&seen), quick_cfg()).unwrap();
    for (flag, addr) in [("-4", v4(3, 2)), ("-6", v6(3, 2))] {
        let out = std::process::Command::new("ping")
            .args([flag, "-c", "3", "-i", "0.2", "-W", "2"])
            .arg(addr.to_string())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "ping {addr}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cross_thread_writes() {
    use std::net::UdpSocket;
    if !privileged() {
        return;
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let server = TunServer::start(device(4, 1).unwrap(), reflector(&seen), quick_cfg()).unwrap();
    let sock = UdpSocket::bind((v4(4, 1), 0)).unwrap();
    let port = sock.local_addr().unwrap().port();
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    const THREADS: u16 = 4;
    const PER: usize = 250;
    let writers: Vec<_> = (0..THREADS)
        .map(|t| {
            let w = server.writer();
            std::thread::spawn(move || {
                for i in 0..PER {
                    let payload = [(t as u8), (i % 251) as u8];
                    let pkt = ipv4_udp([10, 201, 4, 2], [10, 201, 4, 1], 1000 + t, port, &payload);
                    // Paced so the kernel's receive backlog never overflows: every 25 packets,
                    // let the queue drain into the device.
                    w.send(&pkt).unwrap();
                    if i % 25 == 24 {
                        assert!(wait_until(Duration::from_secs(2), || w.queued_bytes(0) == 0));
                    }
                }
            })
        })
        .collect();
    let mut per_thread = [0usize; THREADS as usize];
    let end = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 64];
    while per_thread.iter().sum::<usize>() < THREADS as usize * PER && Instant::now() < end {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            assert_eq!(n, 2);
            assert_eq!(from.ip(), v4(4, 2));
            per_thread[usize::from(from.port() - 1000)] += 1;
        }
    }
    for w in writers {
        w.join().unwrap();
    }
    assert_eq!(per_thread, [PER; THREADS as usize]);
}

#[cfg(target_os = "linux")]
#[test]
fn queue_limit_overloaded_then_drain() {
    use std::{net::UdpSocket, sync::mpsc};
    if !privileged() {
        return;
    }
    // Blocks its I/O thread on the first packet until told to go on (test only: a real handler
    // never blocks), so the queue of packets to write can only grow.
    struct Blocker {
        blocked: mpsc::Sender<()>,
        go: Arc<Mutex<mpsc::Receiver<()>>>,
        once: bool,
    }
    impl Handler for Blocker {
        fn on_data(&mut self, _c: &Conn<Self>, pkt: &[u8]) {
            // Only our UDP packet blocks (the kernel also sends its own IPv6 control packets).
            if self.once || udp_reflect(pkt).is_none() {
                return;
            }
            self.once = true;
            let _ = self.blocked.send(());
            let _ = self
                .go
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
        }
    }
    let (blocked_tx, blocked_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let go = Arc::new(Mutex::new(go_rx));
    let mut cfg = quick_cfg();
    cfg.max_queued_bytes = 4096;
    let blocked_tx = Mutex::new(blocked_tx);
    let server = TunServer::start(
        device(5, 1).unwrap(),
        fn_acceptor(move |_c: &Conn<Blocker>| Blocker {
            blocked: blocked_tx.lock().unwrap().clone(),
            go: go.clone(),
            once: false,
        }),
        cfg,
    )
    .unwrap();
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    s.send_to(b"wake", (v4(5, 2), 9)).unwrap();
    blocked_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let w = server.writer();
    let pkt = ipv4_udp([10, 201, 5, 2], [10, 201, 5, 1], 9, 9, &[0u8; 1000 - 28]);
    assert_eq!(pkt.len(), 1000);
    let mut accepted = 0;
    let err = loop {
        match w.send(&pkt) {
            Ok(()) => accepted += 1,
            Err(e) => break e,
        }
        assert!(accepted < 100, "never overloaded");
    };
    assert!(matches!(err, Error::Overloaded), "{err:?}");
    // 4 x 1000 bytes fit under 4096, a fifth does not.
    assert_eq!(accepted, 4);
    assert_eq!(w.queued_bytes(0), 4000);
    let (drained_tx, drained_rx) = mpsc::channel();
    w.on_drain(0, move || {
        let _ = drained_tx.send(());
    });
    go_tx.send(()).unwrap();
    drained_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(w.queued_bytes(0), 0);
    w.send(&pkt).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn hold_reads_pauses_the_device() {
    use std::net::UdpSocket;
    if !privileged() {
        return;
    }
    struct Held {
        seen: Arc<AtomicUsize>,
    }
    impl Handler for Held {
        fn on_data(&mut self, _c: &Conn<Self>, pkt: &[u8]) {
            if udp_reflect(pkt).is_some() {
                self.seen.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let conn: Arc<Mutex<Option<Conn<Held>>>> = Arc::default();
    let (s2, c2) = (seen.clone(), conn.clone());
    let _server = TunServer::start(
        device(6, 1).unwrap(),
        fn_acceptor(move |c: &Conn<Held>| {
            c.hold_reads(true);
            *c2.lock().unwrap() = Some(c.clone());
            Held { seen: s2.clone() }
        }),
        quick_cfg(),
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(2), || conn
        .lock()
        .unwrap()
        .is_some()));
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    for _ in 0..3 {
        s.send_to(b"held", (v4(6, 2), 9)).unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(seen.load(Ordering::Relaxed), 0, "read while held");
    conn.lock().unwrap().as_ref().unwrap().hold_reads(false);
    assert!(wait_until(Duration::from_secs(2), || seen
        .load(Ordering::Relaxed)
        >= 3));
}

#[cfg(target_os = "linux")]
#[test]
fn device_deleted_underneath() {
    if !privileged() {
        return;
    }
    if !has_tool("ip") {
        eprintln!("skipped: no `ip` binary (iproute2)");
        return;
    }
    struct Watch {
        closed: Arc<Mutex<Option<Option<String>>>>,
    }
    impl Handler for Watch {
        fn on_data(&mut self, _c: &Conn<Self>, _pkt: &[u8]) {}
        fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
            *self.closed.lock().unwrap() = Some(err.map(|e| e.to_string()));
        }
    }
    // Reading (the read fails), and with reads held (the loop's probe finds it).
    for (n, held) in [(7u8, false), (9, true)] {
        let closed: Arc<Mutex<Option<Option<String>>>> = Arc::default();
        let c2 = closed.clone();
        let opened = Arc::new(AtomicUsize::new(0));
        let o2 = opened.clone();
        let server = TunServer::start(
            device(n, 1).unwrap(),
            fn_acceptor(move |c: &Conn<Watch>| {
                c.hold_reads(held);
                o2.fetch_add(1, Ordering::Relaxed);
                Watch { closed: c2.clone() }
            }),
            quick_cfg(),
        )
        .unwrap();
        assert!(wait_until(Duration::from_secs(2), || opened
            .load(Ordering::Relaxed)
            == 1));
        let out = std::process::Command::new("ip")
            .args(["link", "del", &format!("akt{n}")])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            // Held: found by the once-a-second probe.
            wait_until(Duration::from_secs(5), || closed.lock().unwrap().is_some()),
            "held={held}: no on_close"
        );
        let err = closed.lock().unwrap().clone().unwrap();
        assert!(
            err.is_some(),
            "held={held}: a deleted device closes with an error"
        );
        assert!(wait_until(Duration::from_secs(1), || server.is_closed()));
        assert!(matches!(
            server.writer().send(&[0x45; 20]),
            Err(Error::Closed)
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn multi_queue_spreads_flows() {
    use std::net::UdpSocket;
    if !privileged() {
        return;
    }
    const QUEUES: usize = 4;
    struct Queue {
        index: usize,
        per_queue: Arc<[AtomicUsize; QUEUES]>,
    }
    impl Handler for Queue {
        fn on_data(&mut self, c: &Conn<Self>, pkt: &[u8]) {
            // Counts the test's UDP flows only (not the kernel's own IPv6 control packets).
            if let Some(r) = udp_reflect(pkt) {
                self.per_queue[self.index].fetch_add(1, Ordering::Relaxed);
                let _ = c.send(&r);
            }
        }
    }
    let per_queue: Arc<[AtomicUsize; QUEUES]> = Arc::new(Default::default());
    let opened = Arc::new(AtomicUsize::new(0));
    let (p2, o2) = (per_queue.clone(), opened.clone());
    let server = TunServer::start(
        device(8, QUEUES).unwrap(),
        fn_acceptor(move |_c: &Conn<Queue>| Queue {
            index: o2.fetch_add(1, Ordering::Relaxed),
            per_queue: p2.clone(),
        }),
        quick_cfg(),
    )
    .unwrap();
    assert_eq!(server.queues(), QUEUES);
    assert!(wait_until(Duration::from_secs(2), || opened
        .load(Ordering::Relaxed)
        == QUEUES));
    const FLOWS: usize = 64;
    let socks: Vec<UdpSocket> = (0..FLOWS)
        .map(|_| {
            let s = UdpSocket::bind("0.0.0.0:0").unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            s
        })
        .collect();
    for (i, s) in socks.iter().enumerate() {
        s.send_to(&[i as u8; 32], (v4(8, 2), 7)).unwrap();
    }
    for (i, s) in socks.iter().enumerate() {
        let mut buf = [0u8; 64];
        let (n, _) = s.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[i as u8; 32]);
    }
    let counts: Vec<usize> = per_queue
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    assert_eq!(counts.iter().sum::<usize>(), FLOWS, "{counts:?}");
    assert!(
        counts.iter().filter(|&&c| c > 0).count() >= 2,
        "flows were not spread over the queues: {counts:?}"
    );
    // The writer's flow hash keeps one flow on one queue.
    let w = server.writer();
    let a = ipv4_udp([10, 201, 8, 2], [10, 201, 8, 1], 1, 2, b"x");
    assert_eq!(w.queue_of(&a), w.queue_of(&a));
    assert!(w.queue_of(&a) < QUEUES);
}
