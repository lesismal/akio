//! The userspace stack against the Linux kernel's own TCP/IP stack as the peer: over a TAP
//! interface (`Device::Tap`), over a veth pair (`Device::AfPacket`), and over DPDK's `net_tap`
//! poll-mode driver (`Device::Dpdk`, feature `pmd` with libdpdk; one and two queues). A std
//! `UdpSocket` / `TcpStream` on the kernel side talks to a `only` UDP / TCP echo served by the
//! userspace stack, and the userspace stack dials the kernel's sockets.
//!
//! On the veth pair, `tc netem` adds loss, delay and reordering (both directions) for the TCP
//! recovery tests; `ss -tin` on the kernel side shows what was negotiated (SACK, window
//! scaling, timestamps) and that segments were retransmitted.
//!
//! The same runs over IPv6 (`*_ipv6`): the kernel side gets a `fd00:…/64` address (`nodad`), the
//! stack `DpdkConfig::address6`; neighbor discovery both ways, `ping -6`, UDP with fragments,
//! TCP both ways, and the netem loss run.
//!
//! Needs `CAP_NET_ADMIN`, `/dev/net/tun` and the `ip` / `tc` / `ss` tools, so the tests only run
//! when asked: `ONLY_TAP_TEST=1` (TAP, AF_PACKET) and `ONLY_DPDK_TEST=1` (DPDK).
//! `tools/dpdk/test.sh` runs them in Docker (`--cap-add NET_ADMIN --device /dev/net/tun`, IPv6
//! enabled with `--sysctl net.ipv6.conf.all.disable_ipv6=0`).
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::Command,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use only::{
    Backend, Config, Conn, Engine, Error, Handler, Listener,
    dpdk::{Device, DpdkConfig},
    fn_acceptor,
};

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

fn enabled(var: &str) -> bool {
    let on = std::env::var(var).is_ok_and(|v| v == "1");
    if !on {
        eprintln!("skipped: set {var}=1 (needs CAP_NET_ADMIN and /dev/net/tun)");
    }
    on
}

/// Retries `EINTR`: DPDK's TAP driver uses signals (SIGIO), which interrupt blocking calls on
/// other threads of the process.
fn retry<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    loop {
        match f() {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            r => return r,
        }
    }
}

fn run(cmd: &str, args: &str) -> String {
    let out = Command::new(cmd)
        .args(args.split_whitespace())
        .output()
        .unwrap_or_else(|e| panic!("run {cmd}: {e}"));
    assert!(
        out.status.success(),
        "{cmd} {args} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn ip(args: &str) {
    run("ip", args);
}

fn cfg() -> Config {
    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(500);
    cfg
}

/// Serves UDP echo on :7000 and TCP echo on :7001 at `local` over `dcfg`'s device (the IPv6
/// address when the configuration has one).
fn echo_engine(dcfg: DpdkConfig) -> Engine {
    let local: IpAddr = dcfg
        .address6
        .map_or_else(|| dcfg.address.into(), IpAddr::V6);
    let backend = Backend::Dpdk(dcfg);
    Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(SocketAddr::from((local, 7000)))
                .backend(backend.clone())
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(SocketAddr::from((local, 7001)))
                .backend(backend)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .expect("build")
}

/// Writes `data` and reads its echo concurrently; checks it.
fn tcp_echo(t: &mut TcpStream, data: &[u8]) {
    let mut w = t.try_clone().unwrap();
    let sent = data.to_vec();
    let writer = std::thread::spawn(move || {
        for chunk in sent.chunks(16 << 10) {
            retry(|| w.write_all(chunk)).unwrap();
        }
    });
    let mut got = vec![0u8; data.len()];
    let mut n = 0;
    while n < got.len() {
        let r = retry(|| t.read(&mut got[n..])).expect("tcp echo");
        assert!(r > 0, "EOF after {n} bytes");
        n += r;
    }
    writer.join().unwrap();
    assert!(got == data, "TCP echo differs");
}

fn pattern(n: usize, salt: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + salt) % 253) as u8).collect()
}

/// The kernel's SACK processing counters (TcpExt in /proc/net/netstat), summed: they only move
/// when SACK blocks from the peer were used.
fn kernel_sack_counters() -> u64 {
    let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    let mut lines = text.lines().filter(|l| l.starts_with("TcpExt:"));
    let (Some(names), Some(values)) = (lines.next(), lines.next()) else {
        return 0;
    };
    names
        .split_whitespace()
        .zip(values.split_whitespace())
        .filter(|(n, _)| {
            matches!(
                *n,
                "TCPSACKRecovery"
                    | "TCPSACKReorder"
                    | "TCPSackShifted"
                    | "TCPSackMerged"
                    | "TCPSackShiftFallback"
            )
        })
        .filter_map(|(_, v)| v.parse::<u64>().ok())
        .sum()
}

/// `ss -tin` lines for connections to `addr` (kernel's view of a connection with the stack).
fn ss_info(addr: SocketAddr) -> String {
    run("ss", &format!("-tin dst {addr}"))
}

/// A stack configuration with `local` as its address: an IPv4 one, or an IPv6 one (next to an
/// unused IPv4 address).
fn dcfg(dev: Device, local: IpAddr) -> DpdkConfig {
    match local {
        IpAddr::V4(a) => DpdkConfig::new(dev, a),
        IpAddr::V6(a) => {
            let o = a.octets();
            let mut d = DpdkConfig::new(dev, Ipv4Addr::new(10, 200, o[14], o[15]));
            d.address6 = Some(a);
            d
        }
    }
}

/// Gives the kernel `kernel` on `ifname` (IPv6 without duplicate address detection, so it is
/// usable at once).
fn kernel_addr(ifname: &str, kernel: IpAddr) {
    match kernel {
        IpAddr::V4(k) => ip(&format!("addr add {k}/24 dev {ifname}")),
        IpAddr::V6(k) => ip(&format!("-6 addr add {k}/64 dev {ifname} nodad")),
    }
}

/// The UDP and TCP echoes from the kernel's sockets, and dials from the userspace stack to the
/// kernel's sockets, over either family.
fn kernel_peer(dev: Device, ifname: &str, local: IpAddr, kernel: IpAddr) {
    let engine = echo_engine(dcfg(dev, local));
    // The TAP interface exists now (created when the stack opened its device).
    kernel_addr(ifname, kernel);
    ip(&format!("link set {ifname} up"));
    engine.start().unwrap();
    if kernel.is_ipv6() {
        // The kernel pings the stack (neighbor discovery both ways).
        let out = run("ping", &format!("-6 -c 3 -i 0.2 -W 2 {local}"));
        assert!(out.contains("3 received"), "{out}");
    }

    // UDP: datagrams keep their boundaries; the first one also resolves ARP / NDP both ways.
    let u = UdpSocket::bind((kernel, 0)).unwrap();
    u.connect((local, 7000)).unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut buf = vec![0u8; 65536];
    let start = Instant::now();
    let mut answered = false;
    while start.elapsed() < Duration::from_secs(10) && !answered {
        u.send(b"hello?").unwrap();
        answered = matches!(retry(|| u.recv(&mut buf)), Ok(6));
    }
    assert!(answered, "no UDP echo from the userspace stack");
    for i in 0..500usize {
        let msg = vec![(i % 256) as u8; 1 + (i * 7) % 1400];
        u.send(&msg).unwrap();
        let n = retry(|| u.recv(&mut buf)).expect("udp echo");
        assert_eq!(&buf[..n], &msg[..], "datagram {i}");
    }
    // Datagrams larger than the MTU: IP fragmentation both ways.
    for len in [2000usize, 8000, 30_000] {
        let msg = pattern(len, len);
        u.send(&msg).unwrap();
        let n = retry(|| u.recv(&mut buf)).expect("fragmented udp echo");
        assert!(buf[..n] == msg[..], "fragmented datagram of {len}");
    }

    // TCP: 2 MiB through the kernel's TCP and ours, written and read concurrently.
    let mut t =
        TcpStream::connect_timeout(&SocketAddr::from((local, 7001)), Duration::from_secs(5))
            .expect("tcp connect");
    t.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp_echo(&mut t, &pattern(2 << 20, 1));
    let info = ss_info(SocketAddr::from((local, 7001)));
    eprintln!("{ifname}: ss: {}", info.lines().last().unwrap_or("").trim());
    assert!(info.contains("wscale:"), "{info}");
    // Orderly close: our FIN, the server's FIN after it drained.
    t.shutdown(std::net::Shutdown::Write).unwrap();
    let eof = retry(|| t.read(&mut buf)).unwrap();
    assert_eq!(eof, 0, "EOF after the server closed");

    dial_kernel(&engine, kernel);

    let m = engine.metrics();
    eprintln!(
        "{ifname}: {}",
        m.to_prometheus()
            .lines()
            .filter(|l| l.contains("accepted_total{") || l.contains("dialed_total{"))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    engine.shutdown();
    engine.wait();
}

/// Collects a dialed connection's data and close.
struct Client(mpsc::Sender<Result<Vec<u8>, Option<String>>>);
impl Handler for Client {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        let _ = self.0.send(Ok(data.to_vec()));
    }
    fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
        let _ = self.0.send(Err(err.map(|e| e.to_string())));
    }
}

/// The userspace stack dials the kernel: several TCP connections to an echo listener (spread
/// over the queues on a multi-queue device), a UDP echo, and a UDP port nobody listens on
/// (ICMP / ICMPv6 port unreachable ends the dialed connection).
fn dial_kernel(engine: &Engine, kernel: IpAddr) {
    let l = TcpListener::bind((kernel, 9001)).unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                while let Ok(n) = retry(|| s.read(&mut b)) {
                    if n == 0 || retry(|| s.write_all(&b[..n])).is_err() {
                        break;
                    }
                }
            });
        }
    });
    let ku = UdpSocket::bind((kernel, 9002)).unwrap();
    std::thread::spawn(move || {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = retry(|| ku.recv_from(&mut b)) {
            let _ = ku.send_to(&b[..n], from);
        }
    });
    for i in 0..8usize {
        let (tx, rx) = mpsc::channel();
        let slot: Arc<Mutex<Option<Conn<Client>>>> = Arc::default();
        let s2 = slot.clone();
        let etx = tx.clone();
        engine.dial(
            SocketAddr::from((kernel, 9001)),
            fn_acceptor(move |c: &Conn<Client>| {
                *s2.lock().unwrap() = Some(c.clone());
                Client(tx.clone())
            }),
            move |e| {
                let _ = etx.send(Err(Some(format!("dial: {e}"))));
            },
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let c = loop {
            let opened = slot.lock().unwrap().clone();
            if let Some(c) = opened {
                break c;
            }
            if let Ok(Err(e)) = rx.try_recv() {
                panic!("dial {i}: {e:?}");
            }
            assert!(Instant::now() < deadline, "dial {i} timed out");
            std::thread::sleep(Duration::from_millis(1));
        };
        let msg = pattern(100_000, i);
        c.send(&msg).unwrap();
        let mut got = Vec::new();
        while got.len() < msg.len() {
            match rx.recv_timeout(Duration::from_secs(10)).expect("dial echo") {
                Ok(d) => got.extend(d),
                Err(e) => panic!("dialed connection closed: {e:?}"),
            }
        }
        assert!(got == msg, "dial {i}: echo differs");
        c.close();
    }
    // UDP dial: echo, then a closed port.
    for (port, refused) in [(9002u16, false), (9003, true)] {
        let (tx, rx) = mpsc::channel();
        let etx = tx.clone();
        let slot: Arc<Mutex<Option<Conn<Client>>>> = Arc::default();
        let s2 = slot.clone();
        engine.dial_udp(
            SocketAddr::from((kernel, port)),
            fn_acceptor(move |c: &Conn<Client>| {
                let _ = c.send(b"udp dial");
                *s2.lock().unwrap() = Some(c.clone());
                Client(tx.clone())
            }),
            move |e| {
                let _ = etx.send(Err(Some(format!("dial_udp: {e}"))));
            },
        );
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("udp dial result")
        {
            Ok(d) => {
                assert!(!refused);
                assert_eq!(d, b"udp dial");
                let opened = slot.lock().unwrap().take();
                if let Some(c) = opened {
                    c.close();
                }
            }
            Err(e) => {
                assert!(refused, "{e:?}");
                let e = e.unwrap_or_default();
                assert!(e.contains("unreachable") || e.contains("refused"), "{e}");
            }
        }
    }
}

#[test]
fn tap_kernel_peer() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    kernel_peer(
        Device::Tap("fltap0".to_owned()),
        "fltap0",
        Ipv4Addr::new(10, 77, 0, 2).into(),
        Ipv4Addr::new(10, 77, 0, 1).into(),
    );
}

fn v6(group: u16, host: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, group, 0, 0, 0, host))
}

#[test]
fn tap_kernel_peer_ipv6() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    kernel_peer(
        Device::Tap("fltap6".to_owned()),
        "fltap6",
        v6(77, 2),
        v6(77, 1),
    );
}

/// A veth pair `<name>0` (the userspace stack, through AF_PACKET; the kernel has no address
/// there) / `<name>1` (the kernel at `kernel`/24), with `netem` (if any) on both ends.
struct Veth {
    name: String,
}

impl Veth {
    fn new(name: &str, kernel: impl Into<IpAddr>, netem: Option<&str>) -> Veth {
        let _ = Command::new("ip")
            .args(["link", "del", &format!("{name}0")])
            .status();
        ip(&format!("link add {name}0 type veth peer name {name}1"));
        ip(&format!("link set {name}0 up"));
        kernel_addr(&format!("{name}1"), kernel.into());
        ip(&format!("link set {name}1 up"));
        if let Some(n) = netem {
            for end in ["0", "1"] {
                run("tc", &format!("qdisc add dev {name}{end} root netem {n}"));
            }
        }
        Veth {
            name: name.to_owned(),
        }
    }
}

impl Drop for Veth {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &format!("{}0", self.name)])
            .status();
    }
}

#[test]
fn af_packet_kernel_peer() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    // kernel_peer configures the kernel side itself.
    let _ = Command::new("ip").args(["link", "del", "flveth0"]).status();
    ip("link add flveth0 type veth peer name flveth1");
    ip("link set flveth0 up");
    kernel_peer(
        Device::AfPacket("flveth0".to_owned()),
        "flveth1",
        Ipv4Addr::new(10, 76, 0, 2).into(),
        Ipv4Addr::new(10, 76, 0, 1).into(),
    );
    ip("link del flveth0");
    // ICMP echo: the kernel pings the stack.
    let _v = Veth::new("flping", Ipv4Addr::new(10, 75, 0, 1), None);
    let engine = echo_engine(dcfg(
        Device::AfPacket("flping0".to_owned()),
        Ipv4Addr::new(10, 75, 0, 2).into(),
    ));
    engine.start().unwrap();
    if Command::new("ping").arg("-V").output().is_ok() {
        let out = run("ping", "-c 3 -i 0.2 -W 2 10.75.0.2");
        assert!(out.contains("3 received"), "{out}");
    } else {
        eprintln!("ping not installed: ICMP echo not checked");
    }
    engine.shutdown();
    engine.wait();
}

#[test]
fn af_packet_kernel_peer_ipv6() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    let _ = Command::new("ip")
        .args(["link", "del", "flv6eth0"])
        .status();
    ip("link add flv6eth0 type veth peer name flv6eth1");
    ip("link set flv6eth0 up");
    kernel_peer(
        Device::AfPacket("flv6eth0".to_owned()),
        "flv6eth1",
        v6(76, 2),
        v6(76, 1),
    );
    ip("link del flv6eth0");
}

/// Kernel -> stack -> kernel echo of `size` bytes on each of `conns` concurrent connections.
fn echo_many(local: IpAddr, conns: usize, size: usize) -> Duration {
    let t0 = Instant::now();
    let handles: Vec<_> = (0..conns)
        .map(|i| {
            std::thread::spawn(move || {
                let mut t = TcpStream::connect_timeout(
                    &SocketAddr::from((local, 7001)),
                    Duration::from_secs(10),
                )
                .expect("tcp connect");
                t.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
                tcp_echo(&mut t, &pattern(size, i));
            })
        })
        .collect();
    for h in handles {
        h.join().expect("echo thread");
    }
    t0.elapsed()
}

#[test]
fn af_packet_netem_loss_and_reordering() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    netem_loss(
        "flloss",
        Ipv4Addr::new(10, 74, 0, 2).into(),
        Ipv4Addr::new(10, 74, 0, 1).into(),
        false,
    );
}

#[test]
fn af_packet_netem_loss_ipv6_with_ecn_and_pacing() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    netem_loss("fl6loss", v6(74, 2), v6(74, 1), false);
    // ECN and pacing on (the kernel answers ECN-setup SYNs: tcp_ecn=2 by default).
    netem_loss("fl6ecn", v6(71, 2), v6(71, 1), true);
}

/// Kernel -> stack echo over a link with 2% loss, 2 ms delay and 10% reordering (both
/// directions): SACK recovery on both sides, then 16 connections at once.
fn netem_loss(name: &str, local: IpAddr, kernel: IpAddr, ecn_pacing: bool) {
    let _v = Veth::new(name, kernel, Some("loss 2% delay 2ms reorder 10% 50%"));
    let mut d = dcfg(Device::AfPacket(format!("{name}0")), local);
    d.tcp_buffer = 1 << 20;
    d.tcp_ecn = ecn_pacing;
    d.tcp_pacing = ecn_pacing;
    let engine = echo_engine(d);
    engine.start().unwrap();
    let mut t =
        TcpStream::connect_timeout(&SocketAddr::from((local, 7001)), Duration::from_secs(10))
            .expect("tcp connect over a lossy link");
    t.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let data = pattern(8 << 20, 3);
    let sack0 = kernel_sack_counters();
    let t0 = Instant::now();
    tcp_echo(&mut t, &data);
    let took = t0.elapsed();
    let info = ss_info(SocketAddr::from((local, 7001)));
    eprintln!(
        "netem {name}: 8 MiB echoed in {took:?} ({:.1} MB/s each way); ss: {}",
        data.len() as f64 / took.as_secs_f64() / 1e6,
        info.lines().last().unwrap_or("").trim()
    );
    if ecn_pacing {
        // With the default net.ipv4.tcp_ecn = 2 the kernel accepts ECN but does not ask for it
        // on its own connections: this one has ECN only when the sysctl is 1.
        let asks =
            std::fs::read_to_string("/proc/sys/net/ipv4/tcp_ecn").is_ok_and(|v| v.trim() == "1");
        eprintln!("netem {name}: kernel tcp_ecn asks: {asks}");
        if asks {
            assert!(info.contains("ecn"), "ECN not negotiated: {info}");
        }
        // The stack dials the kernel with an ECN-setup SYN: its data arrives ECT(0).
        ecn_dial(&engine, kernel);
    }
    let sacks = kernel_sack_counters() - sack0;
    eprintln!("netem: kernel SACK counters moved by {sacks}");
    assert!(sacks > 0, "the kernel used no SACK blocks from the stack");
    assert!(
        info.contains("retrans") || info.contains("lost"),
        "the kernel retransmitted: {info}"
    );
    drop(t);
    // Several connections at once over the same lossy link.
    let took = echo_many(local, 16, 256 << 10);
    eprintln!("netem: 16 x 256 KiB echoed in {took:?}");
    engine.shutdown();
    engine.wait();
}

/// The kernel's count of received IP packets with an ECT(0) codepoint (`IpExt: InECT0Pkts` /
/// `Ip6InECT0Pkts`).
fn kernel_ect0_received(v6: bool) -> u64 {
    if v6 {
        let text = std::fs::read_to_string("/proc/net/snmp6").unwrap_or_default();
        text.lines()
            .find_map(|l| l.strip_prefix("Ip6InECT0Pkts"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    } else {
        let text = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
        let mut lines = text.lines().filter(|l| l.starts_with("IpExt:"));
        let (Some(names), Some(values)) = (lines.next(), lines.next()) else {
            return 0;
        };
        names
            .split_whitespace()
            .zip(values.split_whitespace())
            .find(|(n, _)| *n == "InECT0Pkts")
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0)
    }
}

/// The stack (ECN on) dials a kernel echo over the lossy link and sends 1 MiB: the kernel
/// accepts the ECN-setup SYN, so the data reaches it ECN-capable.
fn ecn_dial(engine: &Engine, kernel: IpAddr) {
    let l = TcpListener::bind((kernel, 9101)).unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut b = [0u8; 4096];
            while let Ok(n) = retry(|| s.read(&mut b)) {
                if n == 0 || retry(|| s.write_all(&b[..n])).is_err() {
                    break;
                }
            }
        }
    });
    let ect0 = kernel_ect0_received(kernel.is_ipv6());
    let (tx, rx) = mpsc::channel();
    let slot: Arc<Mutex<Option<Conn<Client>>>> = Arc::default();
    let s2 = slot.clone();
    engine.dial(
        SocketAddr::new(kernel, 9101),
        fn_acceptor(move |c: &Conn<Client>| {
            *s2.lock().unwrap() = Some(c.clone());
            Client(tx.clone())
        }),
        |e| panic!("ecn dial: {e}"),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let c = loop {
        let opened = slot.lock().unwrap().clone();
        if let Some(c) = opened {
            break c;
        }
        assert!(Instant::now() < deadline, "ecn dial timed out");
        std::thread::sleep(Duration::from_millis(1));
    };
    let msg = pattern(1 << 20, 9);
    let mut got = Vec::new();
    let mut sent = 0;
    for chunk in msg.chunks(64 << 10) {
        c.send(chunk).unwrap();
        sent += chunk.len();
        // At most 256 KiB in flight.
        while got.len() + (256 << 10) < sent {
            match rx.recv_timeout(Duration::from_secs(30)).expect("ecn echo") {
                Ok(d) => got.extend(d),
                Err(e) => panic!("ecn dial closed: {e:?}"),
            }
        }
    }
    while got.len() < msg.len() {
        match rx.recv_timeout(Duration::from_secs(30)).expect("ecn echo") {
            Ok(d) => got.extend(d),
            Err(e) => panic!("ecn dial closed: {e:?}"),
        }
    }
    assert!(got == msg, "ecn dial: echo differs");
    let info = run("ss", &format!("-tin src {}", SocketAddr::new(kernel, 9101)));
    let marked = kernel_ect0_received(kernel.is_ipv6()) - ect0;
    eprintln!(
        "ecn dial: kernel received {marked} ECT(0) packets; ss: {}",
        info.lines().last().unwrap_or("").trim()
    );
    assert!(
        marked > 500,
        "the stack's data did not arrive ECN-capable ({marked})"
    );
    c.close();
}

#[test]
fn af_packet_window_scaling_large_transfer() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    // 20 ms RTT: without window scaling a 64 KiB window caps a connection at ~3 MB/s.
    let local: IpAddr = Ipv4Addr::new(10, 73, 0, 2).into();
    let _v = Veth::new(
        "flwin",
        Ipv4Addr::new(10, 73, 0, 1),
        Some("delay 10ms limit 10000"),
    );
    let mut d = dcfg(Device::AfPacket("flwin0".to_owned()), local);
    d.tcp_buffer = 4 << 20;
    let engine = echo_engine(d);
    engine.start().unwrap();
    let mut t =
        TcpStream::connect_timeout(&SocketAddr::from((local, 7001)), Duration::from_secs(10))
            .expect("tcp connect");
    t.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let data = pattern(32 << 20, 5);
    let t0 = Instant::now();
    tcp_echo(&mut t, &data);
    let took = t0.elapsed();
    let mbps = data.len() as f64 / took.as_secs_f64() / 1e6;
    let info = ss_info(SocketAddr::from((local, 7001)));
    eprintln!(
        "window scaling: 32 MiB echoed in {took:?} ({mbps:.1} MB/s each way); ss: {}",
        info.lines().last().unwrap_or("").trim()
    );
    // The kernel saw our window scale (4 MiB buffer: shift 7).
    assert!(info.contains("wscale:") && info.contains(",7"), "{info}");
    assert!(mbps > 4.0, "{mbps:.1} MB/s: window scaling not effective");
    engine.shutdown();
    engine.wait();
}

#[test]
fn af_packet_many_concurrent_connections() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    let local: IpAddr = Ipv4Addr::new(10, 72, 0, 2).into();
    let _v = Veth::new("flmany", Ipv4Addr::new(10, 72, 0, 1), None);
    let engine = echo_engine(dcfg(Device::AfPacket("flmany0".to_owned()), local));
    engine.start().unwrap();
    let took = echo_many(local, 500, 32 << 10);
    eprintln!("500 concurrent connections x 32 KiB echoed in {took:?}");
    let m = engine.metrics().to_prometheus();
    let accepted: u64 = m
        .lines()
        .filter(|l| l.starts_with("only_connections_accepted_total{") && l.contains(":7001"))
        .filter_map(|l| l.rsplit(" ").next()?.parse::<u64>().ok())
        .sum();
    assert_eq!(accepted, 500);
    engine.shutdown();
    engine.wait();
}

/// EAL settings for a net_tap port on interface `iface`. The EAL is initialised once per
/// process with the arguments of the first DPDK stack, so they list both test ports.
fn eal(iface: &str, queues: u16) -> only::dpdk::EalConfig {
    let mut eal = only::dpdk::EalConfig::default();
    // No hugepages, no shared runtime files, no PCI scan: runs in a container.
    eal.args = [
        "-l",
        "0",
        "--no-huge",
        "-m",
        "512",
        "--no-shconf",
        "--no-pci",
        "--vdev=net_tap0,iface=fldtap0",
        "--vdev=net_tap1,iface=fldtap1",
        "--vdev=net_tap2,iface=fldtap2",
    ]
    .map(str::to_owned)
    .to_vec();
    eal.port = match iface {
        "fldtap0" => "net_tap0",
        "fldtap1" => "net_tap1",
        _ => "net_tap2",
    }
    .to_owned();
    eal.queues = queues;
    eal
}

#[test]
fn dpdk_net_tap_kernel_peer() {
    if !enabled("ONLY_DPDK_TEST") {
        return;
    }
    // One queue, one I/O thread.
    kernel_peer(
        Device::Dpdk(eal("fldtap0", 1)),
        "fldtap0",
        Ipv4Addr::new(10, 78, 0, 2).into(),
        Ipv4Addr::new(10, 78, 0, 1).into(),
    );
    // Two queues: two I/O threads with a stack each; flows spread by the TAP's queue selection,
    // ARP fanned out between the queues, dialed connections on both queues (replies landing on
    // the other queue are handed over).
    kernel_peer(
        Device::Dpdk(eal("fldtap1", 2)),
        "fldtap1",
        Ipv4Addr::new(10, 79, 0, 2).into(),
        Ipv4Addr::new(10, 79, 0, 1).into(),
    );
    // IPv6 over two queues: neighbor discovery fanned out between them.
    kernel_peer(
        Device::Dpdk(eal("fldtap2", 2)),
        "fldtap2",
        v6(80, 2),
        v6(80, 1),
    );
}
