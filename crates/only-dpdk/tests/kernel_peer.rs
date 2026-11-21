//! The userspace stack against the Linux kernel's own TCP/IP stack as the peer: over a TAP
//! interface (`Device::Tap`), over a veth pair (`Device::AfPacket`, `Device::AfXdp`), and over
//! DPDK's `net_tap`
//! poll-mode driver (`Device::Dpdk`, feature `pmd` with libdpdk; one and two queues). A std
//! `UdpSocket` / `TcpStream` on the kernel side talks to a `only` UDP / TCP echo served by the
//! userspace stack, and the userspace stack dials the kernel's sockets.
//!
//! On the veth pair, `tc netem` adds loss, delay and reordering (both directions) for the TCP
//! recovery tests; `ss -tin` on the kernel side shows what was negotiated (SACK, window
//! scaling, timestamps) and that segments were retransmitted.
//!
//! UDP carries ECN codepoints both ways (the kernel sets and reads them with control messages,
//! an echo on :7002 answers with the codepoint it was given).
//!
//! The same runs over IPv6 (`*_ipv6`): the kernel side gets a `fd00:…/64` address (`nodad`), the
//! stack `DpdkConfig::address6`; neighbor discovery both ways, `ping -6`, UDP with fragments,
//! TCP both ways, and the netem loss run.
//!
//! Accurate ECN (`af_packet_accecn_kernel_peer`) runs against the kernel's own (Linux 6.18+,
//! `net.ipv4.tcp_ecn = 3`, read back from the kernel's `TCP_INFO`); SLAAC and duplicate address
//! detection (`af_packet_ipv6_slaac_and_dad_with_radvd`) against radvd and the kernel's DAD.
//! Both change sysctls of their network namespace only where `ONLY_TEST_NETNS_SYSCTL=1` says
//! it is a test container's, and skip otherwise. AF_XDP adds a shared UMEM over two queues and
//! jumbo frames with multi-buffer (`af_xdp_shared_umem_two_queues`,
//! `af_xdp_multi_buffer_jumbo_frames`).
//!
//! Needs `CAP_NET_ADMIN`, `/dev/net/tun` and the `ip` / `tc` / `ss` tools, so the tests only run
//! when asked: `ONLY_TAP_TEST=1` (TAP, AF_PACKET) and `ONLY_DPDK_TEST=1` (DPDK). The AF_XDP ones
//! (`af_xdp_*`, also `CAP_BPF` and `ethtool`) run with `ONLY_XDP_TEST=1` or
//! `ONLY_TEST_EXPECT_EBPF=1`; without privileges they skip, unless `ONLY_TEST_EXPECT_EBPF=1`.
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
    dpdk::{AfXdpConfig, Device, DpdkConfig, XdpMode, ZeroCopy},
    fn_acceptor,
};

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

/// UDP echo that answers with the ECN codepoint the datagram arrived with.
struct EcnEcho;
impl Handler for EcnEcho {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send_segments_ecn(data.to_vec(), 0, c.rx_ecn());
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
                .backend(backend.clone())
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::udp(SocketAddr::from((local, 7002)))
                .backend(backend)
                .serve(fn_acceptor(|_c: &Conn<EcnEcho>| EcnEcho)),
        )
        .build()
        .expect("build")
}

/// ECN through the userspace stack's UDP: the kernel sends each codepoint (`IP_TOS` /
/// `IPV6_TCLASS` control message), the stack reports it to the handler, which echoes it back
/// with the same codepoint, and the kernel reads it (`IP_RECVTOS` / `IPV6_RECVTCLASS`).
fn ecn_echo(local: IpAddr, kernel: IpAddr) {
    use std::os::fd::AsRawFd;
    let u = UdpSocket::bind((kernel, 0)).unwrap();
    u.set_nonblocking(true).unwrap();
    assert!(only_sys::enable_ecn(u.as_raw_fd()));
    let dest = SocketAddr::from((local, 7002));
    let mut rb = only_sys::RecvBatch::new(8, 2048);
    let mut sb = only_sys::SendBatch::new();
    for ecn in [2u8, 1, 3, 0] {
        let msg = [ecn + 10; 64];
        let deadline = Instant::now() + Duration::from_secs(10);
        let got = 'resend: loop {
            assert!(Instant::now() < deadline, "no ECN echo for codepoint {ecn}");
            {
                let mut b = sb.batch();
                assert!(b.push_ecn(Some(&dest), &[&msg], 0, ecn, kernel.is_ipv6()));
                let _ = b.send(u.as_raw_fd(), 0);
            }
            let wait = Instant::now() + Duration::from_millis(300);
            while Instant::now() < wait {
                let k = rb.recv(u.as_raw_fd()).unwrap_or(0);
                for i in 0..k {
                    if rb.get(i).is_some_and(|(d, _, _)| d == msg) {
                        break 'resend rb.ecn(i);
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        assert_eq!(
            got, ecn,
            "codepoint {ecn} through the userspace stack and back"
        );
    }
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
    ecn_echo(local, kernel);
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
        for attempt in 1.. {
            let limited = kernel_icmp_rate_limited();
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
            let r = rx.recv_timeout(Duration::from_secs(5));
            if r.is_err() && refused && attempt < 4 && kernel_icmp_rate_limited() > limited {
                // The kernel's per-host ICMP rate limit (`net.ipv4.icmp_ratelimit`) swallowed
                // its port unreachable: nothing reached the stack. Dial again.
                eprintln!("udp dial to port {port}: the kernel rate-limited its ICMP error");
                let taken = slot.lock().unwrap().take();
                if let Some(c) = taken {
                    c.close();
                }
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            match r.unwrap_or_else(|e| panic!("udp dial to port {port}: {e:?}")) {
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
            break;
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
    let ect0 = kernel_ect0_received(local.is_ipv6());
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
            // (`ss` does not show option flags on every kernel: count ECT(0) packets instead.)
            let marked = kernel_ect0_received(local.is_ipv6()) - ect0;
            eprintln!("netem {name}: kernel received {marked} ECT(0) packets from the stack");
            assert!(
                marked > 500,
                "ECN not negotiated with the kernel's SYN ({marked})"
            );
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
    // The kernel saw our window scale (4 MiB buffer: shift 7; `ss` prints ours first, then
    // the kernel's own, which depends on its buffers).
    assert!(info.contains("wscale:7,"), "{info}");
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

// ---- AF_XDP ----------------------------------------------------------------------------------

fn expect_ebpf() -> bool {
    std::env::var("ONLY_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
}

/// Whether to run the AF_XDP tests, and whether AF_XDP works here (privileges): a skip is a
/// failure under `ONLY_TEST_EXPECT_EBPF=1`.
fn xdp_enabled() -> bool {
    if !(expect_ebpf() || std::env::var("ONLY_XDP_TEST").is_ok_and(|v| v == "1")) {
        eprintln!("skipped: set ONLY_XDP_TEST=1 (needs CAP_NET_ADMIN, CAP_BPF and ethtool)");
        return false;
    }
    let probe = only::ebpf::probe();
    assert!(
        probe.af_xdp || !expect_ebpf(),
        "AF_XDP unavailable with ONLY_TEST_EXPECT_EBPF=1: {probe:?}"
    );
    if !probe.af_xdp {
        eprintln!("skipped: AF_XDP sockets cannot be created here ({probe:?})");
    }
    probe.af_xdp
}

fn xdp(ifname: &str, mode: XdpMode, zero_copy: ZeroCopy, queues: u16) -> Device {
    let mut c = AfXdpConfig::new(ifname);
    c.mode = mode;
    c.zero_copy = zero_copy;
    c.queues = queues;
    Device::AfXdp(c)
}

/// A veth pair `<name>0` (the stack, through AF_XDP) / `<name>1` (the kernel), `queues` queues
/// each way. The kernel side sends no GSO aggregates and no GRO merges frames on ours: an
/// AF_XDP chunk holds one frame of at most 3840 bytes (native XDP on a veth turns the peer's
/// GSO off by itself; generic XDP runs after GRO and needs it explicitly).
fn xdp_veth(name: &str, queues: u16) {
    let _ = Command::new("ip")
        .args(["link", "del", &format!("{name}0")])
        .status();
    ip(&format!(
        "link add {name}0 numtxqueues {queues} numrxqueues {queues} type veth peer name {name}1 \
         numtxqueues {queues} numrxqueues {queues}"
    ));
    run("ethtool", &format!("-K {name}1 tso off gso off gro off"));
    run("ethtool", &format!("-K {name}0 tso off gso off gro off"));
    ip(&format!("link set {name}0 up"));
}

/// The full kernel-peer run (UDP, ECN, fragments, 2 MiB TCP echo, dials) over AF_XDP.
fn af_xdp_peer(name: &str, mode: XdpMode, zero_copy: ZeroCopy, local: IpAddr, kernel: IpAddr) {
    xdp_veth(name, 1);
    let ifname = format!("{name}0");
    kernel_peer(
        xdp(&ifname, mode, zero_copy, 1),
        &format!("{name}1"),
        local,
        kernel,
    );
    let info = only::dpdk::af_xdp_info(&ifname).expect("AF_XDP info");
    eprintln!("{ifname}: {info:?}");
    match mode {
        XdpMode::Generic => assert!(!info.native),
        // A veth has native XDP (but no zero-copy AF_XDP).
        _ => assert!(info.native, "{info:?}"),
    }
    if zero_copy == ZeroCopy::Off {
        assert!(!info.zero_copy);
    }
    ip(&format!("link del {ifname}"));
}

#[test]
fn af_xdp_kernel_peer_native() {
    if !xdp_enabled() {
        return;
    }
    af_xdp_peer(
        "flxdp",
        XdpMode::Auto,
        ZeroCopy::Auto,
        Ipv4Addr::new(10, 70, 0, 2).into(),
        Ipv4Addr::new(10, 70, 0, 1).into(),
    );
}

#[test]
fn af_xdp_kernel_peer_generic_copy() {
    if !xdp_enabled() {
        return;
    }
    af_xdp_peer(
        "flxdg",
        XdpMode::Generic,
        ZeroCopy::Off,
        Ipv4Addr::new(10, 69, 0, 2).into(),
        Ipv4Addr::new(10, 69, 0, 1).into(),
    );
}

#[test]
fn af_xdp_kernel_peer_ipv6() {
    if !xdp_enabled() {
        return;
    }
    af_xdp_peer("flxd6", XdpMode::Auto, ZeroCopy::Auto, v6(70, 2), v6(70, 1));
}

#[test]
fn af_xdp_zero_copy_required_fails_on_a_veth() {
    if !xdp_enabled() {
        return;
    }
    xdp_veth("flxdz", 1);
    let r = Engine::builder()
        .listen(
            Listener::udp(SocketAddr::from(([10, 68, 0, 2], 7000)))
                .backend(Backend::Dpdk(DpdkConfig::new(
                    xdp("flxdz0", XdpMode::Auto, ZeroCopy::Required, 1),
                    Ipv4Addr::new(10, 68, 0, 2),
                )))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build();
    let e = r.expect_err("veth has no zero-copy AF_XDP");
    eprintln!("zero-copy required on a veth: {e}");
    // The failed open left no program behind: AF_PACKET-free copy mode works next.
    let engine = echo_engine(DpdkConfig::new(
        xdp("flxdz0", XdpMode::Auto, ZeroCopy::Off, 1),
        Ipv4Addr::new(10, 68, 0, 2),
    ));
    engine.shutdown();
    engine.wait();
    ip("link del flxdz0");
}

#[test]
fn af_xdp_two_queues_and_many_connections() {
    if !xdp_enabled() {
        return;
    }
    let local: IpAddr = Ipv4Addr::new(10, 67, 0, 2).into();
    let kernel: IpAddr = Ipv4Addr::new(10, 67, 0, 1).into();
    xdp_veth("flxdq", 2);
    let engine = echo_engine(dcfg(xdp("flxdq0", XdpMode::Auto, ZeroCopy::Auto, 2), local));
    kernel_addr("flxdq1", kernel);
    ip("link set flxdq1 up");
    engine.start().unwrap();
    let took = echo_many(local, 200, 32 << 10);
    eprintln!("AF_XDP, 2 queues: 200 concurrent connections x 32 KiB echoed in {took:?}");
    // Dialed connections use ports naming their queue; replies RSS puts on the other queue are
    // handed over.
    dial_kernel(&engine, kernel);
    let m = engine.metrics().to_prometheus();
    let accepted: u64 = m
        .lines()
        .filter(|l| l.starts_with("only_connections_accepted_total{") && l.contains(":7001"))
        .filter_map(|l| l.rsplit(" ").next()?.parse::<u64>().ok())
        .sum();
    assert_eq!(accepted, 200);
    // The veth spread the flows over both queues (one I/O thread each).
    let per_queue: Vec<u64> = m
        .lines()
        .filter(|l| l.starts_with("only_connections_accepted_total{") && l.contains(":7001"))
        .filter_map(|l| l.rsplit(" ").next()?.parse::<u64>().ok())
        .collect();
    eprintln!("AF_XDP, 2 queues: accepted per queue {per_queue:?}");
    assert!(
        per_queue.len() == 2 && per_queue.iter().all(|&n| n > 0),
        "{per_queue:?}"
    );
    let info = only::dpdk::af_xdp_info("flxdq0").unwrap();
    assert_eq!(info.queues, 2);
    engine.shutdown();
    engine.wait();
    ip("link del flxdq0");
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
}

#[test]
fn dpdk_net_tap_kernel_peer_ipv6() {
    if !enabled("ONLY_DPDK_TEST") {
        return;
    }
    // IPv6 over two queues: neighbor discovery fanned out between them.
    kernel_peer(
        Device::Dpdk(eal("fldtap2", 2)),
        "fldtap2",
        v6(80, 2),
        v6(80, 1),
    );
}

// ---- Accurate ECN, SLAAC / DAD and AF_XDP multi-buffer / shared UMEM -------------------------

/// What the kernel's `TCP_INFO` says about a connection (Linux 6.18+ fields; zeros before).
#[derive(Debug, Default)]
struct KernelTcpInfo {
    snd_mss: u32,
    /// `TCPI_ECN_MODE_*`: 0 disabled, 1 RFC 3168, 2 AccECN.
    ecn_mode: u32,
    /// `TCP_ACCECN_OPT_*`: 2 = options with counters seen.
    opt_seen: u32,
    /// `TCP_ACCECN_*_FAIL_*` bits.
    fail_mode: u32,
    received_ce: u32,
    delivered_e0_bytes: u32,
    delivered_ce_bytes: u32,
    received_ce_bytes: u32,
}

/// The kernel side's `TCP_INFO` of `fd`.
fn kernel_tcp_info(fd: std::os::fd::RawFd) -> KernelTcpInfo {
    let mut b = [0u8; 512];
    let mut len = b.len() as only_sys::ffi::socklen_t;
    // SAFETY: `b` is valid for `len` bytes of writes, `len` for one socklen_t; the kernel
    // writes at most `len` bytes.
    let r = unsafe {
        only_sys::ffi::getsockopt(
            fd,
            only_sys::ffi::IPPROTO_TCP,
            only_sys::ffi::TCP_INFO,
            b.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    assert_eq!(r, 0, "TCP_INFO");
    let u = |at: usize| u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let mut i = KernelTcpInfo {
        snd_mss: u(16),
        ..KernelTcpInfo::default()
    };
    if len as usize >= 280 {
        let bits = u(276);
        i.ecn_mode = bits & 3;
        i.opt_seen = (bits >> 2) & 3;
        i.fail_mode = (bits >> 4) & 0xf;
        i.received_ce = u(248);
        i.delivered_e0_bytes = u(256);
        i.delivered_ce_bytes = u(260);
        i.received_ce_bytes = u(272);
    }
    i
}

/// Reads sysctl `name` (`/proc/sys/...` path below `net/`).
fn sysctl(name: &str) -> String {
    std::fs::read_to_string(format!("/proc/sys/net/{name}"))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Sets sysctl `name` to `v` when this network namespace may be changed
/// (`ONLY_TEST_NETNS_SYSCTL=1`: a test container, never a shared host); returns whether `name`
/// now has that value.
fn netns_sysctl(name: &str, v: &str) -> bool {
    if sysctl(name) == v {
        return true;
    }
    if std::env::var("ONLY_TEST_NETNS_SYSCTL").is_ok_and(|x| x == "1") {
        let _ = std::fs::write(format!("/proc/sys/net/{name}"), v);
    }
    sysctl(name) == v
}

/// The stack dials `to` and echoes `size` bytes through it; returns the kernel side's
/// `TCP_INFO` once the echo is complete.
fn dial_echo(engine: &Engine, listener: TcpListener, to: SocketAddr, size: usize) -> KernelTcpInfo {
    use std::os::fd::AsRawFd;
    let (itx, irx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut b = [0u8; 16 << 10];
            let mut total = 0;
            while let Ok(n) = retry(|| s.read(&mut b)) {
                if n == 0 || retry(|| s.write_all(&b[..n])).is_err() {
                    break;
                }
                total += n;
                if total == size {
                    let _ = itx.send(kernel_tcp_info(s.as_raw_fd()));
                }
            }
        }
    });
    let (tx, rx) = mpsc::channel();
    let slot: Arc<Mutex<Option<Conn<Client>>>> = Arc::default();
    let s2 = slot.clone();
    let etx = tx.clone();
    engine.dial(
        to,
        fn_acceptor(move |c: &Conn<Client>| {
            *s2.lock().unwrap() = Some(c.clone());
            Client(tx.clone())
        }),
        move |e| {
            let _ = etx.send(Err(Some(format!("dial: {e}"))));
        },
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let c = loop {
        let opened = slot.lock().unwrap().clone();
        if let Some(c) = opened {
            break c;
        }
        if let Ok(Err(e)) = rx.try_recv() {
            panic!("dial {to}: {e:?}");
        }
        assert!(Instant::now() < deadline, "dial {to} timed out");
        std::thread::sleep(Duration::from_millis(1));
    };
    let msg = pattern(size, 3);
    let mut got = Vec::new();
    let mut sent = 0;
    for chunk in msg.chunks(64 << 10) {
        c.send(chunk).unwrap();
        sent += chunk.len();
        while got.len() + (256 << 10) < sent {
            match rx.recv_timeout(Duration::from_secs(30)).expect("dial echo") {
                Ok(d) => got.extend(d),
                Err(e) => panic!("dialed connection closed: {e:?}"),
            }
        }
    }
    while got.len() < msg.len() {
        match rx.recv_timeout(Duration::from_secs(30)).expect("dial echo") {
            Ok(d) => got.extend(d),
            Err(e) => panic!("dialed connection closed: {e:?}"),
        }
    }
    assert!(got == msg, "dial {to}: echo differs");
    let info = irx
        .recv_timeout(Duration::from_secs(10))
        .expect("kernel tcp_info");
    c.close();
    info
}

/// Accurate ECN against the kernel's (`net.ipv4.tcp_ecn = 3`, Linux 6.18+): over a veth with
/// netem marking CE instead of dropping (both ways), the kernel's echo client and the stack's
/// dial both end up in AccECN mode on both sides, each side's CE marks reach the other through
/// the ACE field and the AccECN option, and nobody detects a failure.
#[test]
fn af_packet_accecn_kernel_peer() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    let old = sysctl("ipv4/tcp_ecn");
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            if !self.0.is_empty() {
                netns_sysctl("ipv4/tcp_ecn", &self.0);
            }
        }
    }
    let _restore = Restore(old);
    if !netns_sysctl("ipv4/tcp_ecn", "3") {
        let need = std::env::var("ONLY_TEST_EXPECT_ACCECN").is_ok_and(|v| v == "1");
        assert!(!need, "net.ipv4.tcp_ecn is not 3 here");
        eprintln!("skipped: net.ipv4.tcp_ecn is not 3 in this namespace (and may not be set)");
        return;
    }
    let local: IpAddr = Ipv4Addr::new(10, 66, 0, 2).into();
    let kernel: IpAddr = Ipv4Addr::new(10, 66, 0, 1).into();
    let _v = Veth::new("flacc", kernel, Some("loss 1% ecn delay 1ms"));
    let mut d = dcfg(Device::AfPacket("flacc0".to_owned()), local);
    d.tcp_accecn = true;
    d.tcp_buffer = 1 << 20;
    let engine = echo_engine(d);
    engine.start().unwrap();
    let before = only::dpdk::tcp_ecn_stats();
    // The kernel connects (it asks for AccECN on its SYN) and echoes 4 MiB.
    let mut t =
        TcpStream::connect_timeout(&SocketAddr::from((local, 7001)), Duration::from_secs(10))
            .expect("tcp connect");
    t.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    tcp_echo(&mut t, &pattern(4 << 20, 11));
    let k = kernel_tcp_info(std::os::fd::AsRawFd::as_raw_fd(&t));
    eprintln!("accecn, kernel client: {k:?}");
    assert_eq!(k.ecn_mode, 2, "the kernel is in AccECN mode: {k:?}");
    assert_eq!(k.opt_seen, 2, "the kernel saw our AccECN options: {k:?}");
    assert_eq!(k.fail_mode, 0, "the kernel saw no AccECN failure: {k:?}");
    assert!(k.received_ce > 0, "netem marked our echo: {k:?}");
    assert!(
        k.delivered_e0_bytes > 1 << 20,
        "our option reported its ECT(0) bytes: {k:?}"
    );
    assert!(
        k.delivered_ce_bytes > 0,
        "our option reported its CE bytes: {k:?}"
    );
    drop(t);
    // The stack dials the kernel.
    let l = TcpListener::bind((kernel, 9201)).unwrap();
    let k = dial_echo(&engine, l, SocketAddr::new(kernel, 9201), 4 << 20);
    eprintln!("accecn, stack client: {k:?}");
    assert_eq!((k.ecn_mode, k.opt_seen, k.fail_mode), (2, 2, 0), "{k:?}");
    assert!(k.received_ce > 0 && k.delivered_ce_bytes > 0, "{k:?}");
    let after = only::dpdk::tcp_ecn_stats();
    eprintln!("accecn: stack stats {before:?} -> {after:?}");
    assert!(
        after.accecn >= before.accecn + 2,
        "both connections in AccECN mode"
    );
    assert!(after.ce_received > before.ce_received, "CE marks counted");
    assert!(
        after.ce_responses > before.ce_responses,
        "the kernel's feedback of our CE marks was answered"
    );
    engine.shutdown();
    engine.wait();
}

/// IPv6 autoconfiguration against Linux routers and hosts: radvd on the kernel side of a veth
/// advertises a /64 (MTU 1400, hop limit 32); the stack (`ipv6_slaac` + `ipv6_dad`) forms its
/// address after duplicate address detection, the kernel reaches it with an MSS for MTU 1400,
/// and the stack reaches an address of the kernel's off the /64 through the advertised default
/// router. Then duplicate address detection both ways: the kernel cannot take the stack's
/// address (we defend it), and the stack gives up a static address the kernel already has.
#[test]
fn af_packet_ipv6_slaac_and_dad_with_radvd() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    if Command::new("radvd").arg("--version").output().is_err() {
        let need = std::env::var("ONLY_TEST_EXPECT_RADVD").is_ok_and(|v| v == "1");
        assert!(!need, "radvd not installed");
        eprintln!("skipped: radvd not installed");
        return;
    }
    // radvd wants forwarding on (a router); only where this namespace may be changed.
    if !netns_sysctl("ipv6/conf/all/forwarding", "1") {
        eprintln!("skipped: net.ipv6.conf.all.forwarding is 0 and may not be set");
        return;
    }
    let _ = Command::new("ip").args(["link", "del", "flra0"]).status();
    ip("link add flra0 type veth peer name flra1");
    ip("link set flra0 up");
    ip("link set flra1 up");
    ip("-6 addr add fd00:77::1/64 dev flra1 nodad");
    ip("-6 addr add fd00:88::1/128 dev flra1 nodad");
    let conf = std::env::temp_dir().join("only-flra.conf");
    std::fs::write(
        &conf,
        "interface flra1 {\n  AdvSendAdvert on;\n  MinRtrAdvInterval 3;\n  MaxRtrAdvInterval 4;\n  \
         AdvLinkMTU 1400;\n  AdvCurHopLimit 32;\n  AdvDefaultLifetime 60;\n  \
         prefix fd00:77::/64 {\n    AdvOnLink on;\n    AdvAutonomous on;\n    \
         AdvValidLifetime 300;\n    AdvPreferredLifetime 120;\n  };\n};\n",
    )
    .unwrap();
    let pid = std::env::temp_dir().join("only-flra.pid");
    let mut radvd = Command::new("radvd")
        .args(["-n", "-m", "stderr", "-C"])
        .arg(&conf)
        .arg("-p")
        .arg(&pid)
        .spawn()
        .expect("radvd");
    struct Kill<'a>(&'a mut std::process::Child);
    impl Drop for Kill<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            let _ = Command::new("ip").args(["link", "del", "flra0"]).status();
        }
    }
    let _k = Kill(&mut radvd);
    let mac = [0x02, 0xf1, 0x77, 0, 0, 0x02];
    let mut d = DpdkConfig::new(
        Device::AfPacket("flra0".to_owned()),
        Ipv4Addr::new(10, 65, 0, 2),
    );
    d.mac = Some(mac);
    d.ipv6_slaac = true;
    d.ipv6_dad = true;
    let dev = d.device.clone();
    let engine = echo_engine(d);
    engine.start().unwrap();
    // fd00:77:: + the modified EUI-64 identifier of `mac`.
    let me = Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0xf1, 0x77ff, 0xfe00, 0x0002);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let a = only::dpdk::ipv6_addresses(&dev).unwrap_or_default();
        if a.contains(&me) {
            eprintln!("slaac: {a:?}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no SLAAC address after 20 s: {a:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = run("ping", &format!("-6 -c 3 -i 0.2 -W 2 {me}"));
    assert!(out.contains("3 received"), "{out}");
    // The kernel connects to the SLAAC address; our SYN-ACK's MSS follows the advertised MTU.
    let mut t = TcpStream::connect_timeout(&SocketAddr::from((me, 7001)), Duration::from_secs(10))
        .expect("tcp connect to the SLAAC address");
    t.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    tcp_echo(&mut t, &pattern(1 << 20, 4));
    let k = kernel_tcp_info(std::os::fd::AsRawFd::as_raw_fd(&t));
    eprintln!("slaac: kernel snd_mss {}", k.snd_mss);
    assert!(
        k.snd_mss <= 1400 - 60,
        "MSS for the advertised MTU: {}",
        k.snd_mss
    );
    drop(t);
    // Off the /64: through the default router (the kernel's link-local address).
    let l = TcpListener::bind("[fd00:88::1]:9301").unwrap();
    dial_echo(&engine, l, "[fd00:88::1]:9301".parse().unwrap(), 256 << 10);
    // The kernel's duplicate address detection of our address fails: we defend it.
    ip(&format!("-6 addr add {me}/128 dev flra1"));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let shown = run("ip", "-6 addr show dev flra1");
        if shown.contains("dadfailed") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "kernel DAD did not fail: {shown}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    ip(&format!("-6 addr del {me}/128 dev flra1"));
    engine.shutdown();
    engine.wait();
    // A static address the kernel already has fails our duplicate address detection.
    let mut d = DpdkConfig::new(
        Device::AfPacket("flra0".to_owned()),
        Ipv4Addr::new(10, 65, 0, 2),
    );
    d.mac = Some(mac);
    d.address6 = Some("fd00:77::1".parse().unwrap());
    d.ipv6_dad = true;
    // (Listening on the IPv4 address: listeners are dual-stack.)
    let engine = Engine::builder()
        .config(cfg())
        .listen(
            Listener::tcp(SocketAddr::from(([10, 65, 0, 2], 7001)))
                .backend(Backend::Dpdk(d))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .expect("build");
    engine.start().unwrap();
    let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xf1, 0x77ff, 0xfe00, 0x0002);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let a = only::dpdk::ipv6_addresses(&dev).unwrap_or_default();
        if a == vec![ll] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "DAD did not give up fd00:77::1: {a:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(only::dpdk::ipv6_addresses(&dev), Some(vec![ll]));
    engine.shutdown();
    engine.wait();
}

/// Two AF_XDP queues sharing one UMEM (`XDP_SHARED_UMEM`, copy mode on a veth): the same run
/// as `af_xdp_two_queues_and_many_connections`.
#[test]
fn af_xdp_shared_umem_two_queues() {
    if !xdp_enabled() {
        return;
    }
    let local: IpAddr = Ipv4Addr::new(10, 64, 0, 2).into();
    let kernel: IpAddr = Ipv4Addr::new(10, 64, 0, 1).into();
    xdp_veth("flxds", 2);
    let mut c = AfXdpConfig::new("flxds0");
    c.queues = 2;
    c.frames = 8192;
    c.shared_umem = true;
    let engine = echo_engine(dcfg(Device::AfXdp(c), local));
    kernel_addr("flxds1", kernel);
    ip("link set flxds1 up");
    engine.start().unwrap();
    let took = echo_many(local, 200, 32 << 10);
    eprintln!("AF_XDP, shared UMEM, 2 queues: 200 connections x 32 KiB echoed in {took:?}");
    dial_kernel(&engine, kernel);
    let m = engine.metrics().to_prometheus();
    let per_queue: Vec<u64> = m
        .lines()
        .filter(|l| l.starts_with("only_connections_accepted_total{") && l.contains(":7001"))
        .filter_map(|l| l.rsplit(" ").next()?.parse::<u64>().ok())
        .collect();
    eprintln!("AF_XDP, shared UMEM: accepted per queue {per_queue:?}");
    assert_eq!(per_queue.iter().sum::<u64>(), 200);
    assert!(
        per_queue.len() == 2 && per_queue.iter().all(|&n| n > 0),
        "{per_queue:?}"
    );
    let info = only::dpdk::af_xdp_info("flxds0").unwrap();
    eprintln!("flxds0: {info:?}");
    assert!(info.shared_umem && info.queues == 2, "{info:?}");
    engine.shutdown();
    engine.wait();
    ip("link del flxds0");
}

/// Jumbo frames over AF_XDP with multi-buffer (`XDP_USE_SG`): MTU 9000 on both ends of a veth,
/// in native and generic mode. Frames of up to 9014 bytes span three 4 KiB chunks each way;
/// UDP datagrams of 8000 bytes travel unfragmented, TCP uses an MSS of about 8960.
#[test]
fn af_xdp_multi_buffer_jumbo_frames() {
    if !xdp_enabled() {
        return;
    }
    for (name, mode, net) in [
        ("flxdj", XdpMode::Auto, 63u8),
        ("flxdk", XdpMode::Generic, 62),
    ] {
        let local: IpAddr = Ipv4Addr::new(10, net, 0, 2).into();
        let kernel: IpAddr = Ipv4Addr::new(10, net, 0, 1).into();
        xdp_veth(name, 1);
        ip(&format!("link set {name}0 mtu 9000"));
        ip(&format!("link set {name}1 mtu 9000"));
        let mut c = AfXdpConfig::new(format!("{name}0"));
        c.mode = mode;
        c.zero_copy = ZeroCopy::Off;
        c.multi_buffer = true;
        let mut d = dcfg(Device::AfXdp(c), local);
        d.mtu = 9000;
        d.tcp_buffer = 1 << 20;
        let engine = echo_engine(d);
        kernel_addr(&format!("{name}1"), kernel);
        ip(&format!("link set {name}1 up"));
        engine.start().unwrap();
        // UDP: 8000-byte datagrams in one frame each (the kernel does not fragment them).
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
        assert!(answered, "{name}: no UDP echo");
        let frag_before = kernel_reasm_ok();
        for i in 0..200usize {
            let msg = pattern(8000 + i % 900, i);
            u.send(&msg).unwrap();
            let n = retry(|| u.recv(&mut buf)).expect("jumbo udp echo");
            assert!(buf[..n] == msg[..], "{name}: datagram {i}");
        }
        assert_eq!(
            kernel_reasm_ok(),
            frag_before,
            "{name}: echoes came unfragmented"
        );
        // TCP: 8 MiB with jumbo segments.
        let mut t =
            TcpStream::connect_timeout(&SocketAddr::from((local, 7001)), Duration::from_secs(5))
                .expect("tcp connect");
        t.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let t0 = Instant::now();
        tcp_echo(&mut t, &pattern(8 << 20, 2));
        let k = kernel_tcp_info(std::os::fd::AsRawFd::as_raw_fd(&t));
        eprintln!(
            "{name} ({mode:?}): 8 MiB echoed in {:?}, kernel snd_mss {}; {:?}",
            t0.elapsed(),
            k.snd_mss,
            only::dpdk::af_xdp_info(&format!("{name}0"))
        );
        assert!(k.snd_mss > 8000, "jumbo MSS: {}", k.snd_mss);
        let info = only::dpdk::af_xdp_info(&format!("{name}0")).unwrap();
        assert!(info.multi_buffer, "{info:?}");
        drop(t);
        engine.shutdown();
        engine.wait();
        ip(&format!("link del {name}0"));
    }
}

/// The kernel's count of IPv4 datagrams reassembled (`Ip: ReasmOKs`).
fn kernel_reasm_ok() -> u64 {
    kernel_snmp("Ip:", "ReasmOKs")
}

/// A counter of `/proc/net/snmp` (the line pair starting with `group`).
fn kernel_snmp(group: &str, field: &str) -> u64 {
    let text = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    let mut lines = text.lines().filter(|l| l.starts_with(group));
    let (Some(names), Some(values)) = (lines.next(), lines.next()) else {
        return 0;
    };
    names
        .split_whitespace()
        .zip(values.split_whitespace())
        .find(|(n, _)| *n == field)
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0)
}

/// ICMP and ICMPv6 errors the kernel did not send because of its rate limits.
fn kernel_icmp_rate_limited() -> u64 {
    let v6: u64 = std::fs::read_to_string("/proc/net/snmp6")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (name, value) = l.split_once(char::is_whitespace)?;
            name.starts_with("Icmp6OutRateLimit")
                .then(|| value.trim().parse::<u64>().ok())
                .flatten()
        })
        .sum();
    kernel_snmp("Icmp:", "OutRateLimitGlobal") + kernel_snmp("Icmp:", "OutRateLimitHost") + v6
}
