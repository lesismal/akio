//! The userspace stack against the Linux kernel's own TCP/IP stack as the peer: over a TAP
//! interface (smoltcp's TAP device, `Device::Tap`), over a veth pair (`Device::AfPacket`), and
//! over DPDK's `net_tap` poll-mode driver (`Device::Dpdk`, feature `pmd` with libdpdk; one and
//! two queues). A std `UdpSocket` / `TcpStream` on the kernel side talks to a `only` UDP / TCP
//! echo served by the userspace stack.
//!
//! Needs `CAP_NET_ADMIN`, `/dev/net/tun` and the `ip` tool, so the tests only run when asked:
//! `ONLY_TAP_TEST=1` (TAP, AF_PACKET) and `ONLY_DPDK_TEST=1` (DPDK). `tools/dpdk/test.sh` runs
//! them in Docker (`--cap-add NET_ADMIN --device /dev/net/tun`).
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    process::Command,
    time::{Duration, Instant},
};

use only::{
    Backend, Config, Conn, Engine, Handler, Listener,
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

fn ip(args: &str) {
    let st = Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .expect("run ip");
    assert!(st.success(), "ip {args} failed");
}

/// Serves UDP echo on :7000 and TCP echo on :7001 at `local` over `dev`, configures the
/// kernel-side interface `ifname` as `kernel`/24, and checks both echoes from the
/// kernel's sockets.
fn kernel_peer(dev: Device, ifname: &str, local: Ipv4Addr, kernel: Ipv4Addr) {
    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(500);
    let backend = Backend::Dpdk(DpdkConfig::new(dev, local));
    let engine = Engine::builder()
        .config(cfg)
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
        .expect("build");
    // The TAP interface exists now (created when the stack opened its device).
    ip(&format!("addr add {kernel}/24 dev {ifname}"));
    ip(&format!("link set {ifname} up"));
    engine.start().unwrap();

    // UDP: datagrams keep their boundaries; the first one also resolves ARP both ways.
    let u = UdpSocket::bind((kernel, 0)).unwrap();
    u.connect((local, 7000)).unwrap();
    u.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut buf = vec![0u8; 2048];
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

    // TCP: 2 MiB through the kernel's TCP and smoltcp, written and read concurrently.
    let mut t =
        TcpStream::connect_timeout(&SocketAddr::from((local, 7001)), Duration::from_secs(5))
            .expect("tcp connect");
    t.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let data: Vec<u8> = (0..2u32 << 20).map(|i| (i % 253) as u8).collect();
    let mut w = t.try_clone().unwrap();
    let sent = data.clone();
    let writer = std::thread::spawn(move || {
        for chunk in sent.chunks(8 << 10) {
            w.write_all(chunk).unwrap();
        }
    });
    let mut got = vec![0u8; data.len()];
    t.read_exact(&mut got).expect("tcp echo");
    writer.join().unwrap();
    assert!(got == data, "TCP echo differs");
    // Orderly close: our FIN, the server's FIN after it drained.
    t.shutdown(std::net::Shutdown::Write).unwrap();
    let eof = retry(|| t.read(&mut buf)).unwrap();
    assert_eq!(eof, 0, "EOF after the server closed");

    let m = engine.metrics();
    eprintln!(
        "{ifname}: {}",
        m.to_prometheus()
            .lines()
            .filter(|l| l.contains("accepted"))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    engine.shutdown();
    engine.wait();
}

#[test]
fn tap_kernel_peer() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    kernel_peer(
        Device::Tap("fltap0".to_owned()),
        "fltap0",
        Ipv4Addr::new(10, 77, 0, 2),
        Ipv4Addr::new(10, 77, 0, 1),
    );
}

#[test]
fn af_packet_kernel_peer() {
    if !enabled("ONLY_TAP_TEST") {
        return;
    }
    // A veth pair: the userspace stack owns flveth0 through AF_PACKET (the kernel has no
    // address there), the kernel's sockets use flveth1.
    ip("link add flveth0 type veth peer name flveth1");
    ip("link set flveth0 up");
    kernel_peer(
        Device::AfPacket("flveth0".to_owned()),
        "flveth1",
        Ipv4Addr::new(10, 76, 0, 2),
        Ipv4Addr::new(10, 76, 0, 1),
    );
    ip("link del flveth0");
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
    ]
    .map(str::to_owned)
    .to_vec();
    eal.port = if iface == "fldtap0" {
        "net_tap0"
    } else {
        "net_tap1"
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
        Ipv4Addr::new(10, 78, 0, 2),
        Ipv4Addr::new(10, 78, 0, 1),
    );
    // Two queues: two I/O threads with a stack each; flows spread by the TAP's queue selection,
    // ARP fanned out between the queues.
    kernel_peer(
        Device::Dpdk(eal("fldtap1", 2)),
        "fldtap1",
        Ipv4Addr::new(10, 79, 0, 2),
        Ipv4Addr::new(10, 79, 0, 1),
    );
}
