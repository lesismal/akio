//! Companion of the book's "Kernel bypass (DPDK)" chapter: a UDP and a TCP echo served by the
//! userspace stack, and a client on a second stack dialing them. The two stacks are joined by an
//! in-process memory wire, so this runs anywhere without privileges; `--dpdk` and `--tap` show
//! the same server on a DPDK port or a TAP interface (Linux, see the chapter).
//!
//! `cargo run -p flash-dpdk --example guide-dpdk`

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::mpsc,
    time::Duration,
};

use flash::{
    Backend, Conn, Engine, Handler, Listener,
    dpdk::{Device, DpdkConfig, EalConfig, MemoryWire},
    fn_acceptor,
};

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

struct Print(mpsc::Sender<String>);
impl Handler for Print {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        let _ = self.0.send(String::from_utf8_lossy(data).into_owned());
    }
}

/// The device of the server's stack, chosen on the command line.
fn server_device(memory: Device) -> Device {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        // ANCHOR: dpdk
        "--dpdk" => {
            let mut eal = EalConfig::default();
            // EAL arguments: here a TAP-backed virtual port without hugepages; on a real NIC
            // bound to vfio-pci, e.g. ["-l", "2-3", "-a", "0000:03:00.0"] and port "0".
            eal.args = [
                "-l",
                "0",
                "--no-huge",
                "-m",
                "512",
                "--no-shconf",
                "--no-pci",
            ]
            .map(str::to_owned)
            .to_vec();
            eal.args.push("--vdev=net_tap0,iface=dtap0".to_owned());
            eal.port = "net_tap0".to_owned();
            eal.queues = 1; // one rx/tx queue pair = one I/O thread
            Device::Dpdk(eal)
        }
        // ANCHOR_END: dpdk
        "--tap" => Device::Tap("ftap0".to_owned()),
        _ => memory,
    }
}

fn main() -> std::io::Result<()> {
    let (wire_a, wire_b) = MemoryWire::new();
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);

    // ANCHOR: server
    let mut cfg = DpdkConfig::new(server_device(Device::Memory(wire_a)), server_ip);
    cfg.prefix_len = 24;
    cfg.gateway = None; // set for peers outside 10.0.0.0/24
    let backend = Backend::Dpdk(cfg);
    let server = Engine::builder()
        // Both listeners name the same device: they share its stack and I/O threads.
        .listen(
            Listener::udp(SocketAddr::from((server_ip, 7000)))
                .backend(backend.clone())
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(SocketAddr::from((server_ip, 7001)))
                .backend(backend)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()?;
    server.start()?;
    // ANCHOR_END: server

    if std::env::args().nth(1).is_some() {
        println!("serving UDP and TCP echo on {server_ip}:7000/7001; Ctrl-C to stop");
        server.wait();
        return Ok(());
    }

    // ANCHOR: client
    // A second stack on the other end of the wire. `dial` / `dial_udp` use the engine's last
    // (UDP) listener, so the client engine has one listener per protocol on its device.
    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let backend = Backend::Dpdk(DpdkConfig::new(Device::Memory(wire_b), client_ip));
    let client = Engine::builder()
        .listen(
            Listener::udp(SocketAddr::from((client_ip, 0)))
                .backend(backend.clone())
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(SocketAddr::from((client_ip, 0)))
                .backend(backend)
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()?;
    client.start()?;
    let (tx, rx) = mpsc::channel();
    let t = tx.clone();
    client.dial_udp(
        SocketAddr::from((server_ip, 7000)),
        fn_acceptor(move |c: &Conn<Print>| {
            let _ = c.send(b"hello over UDP");
            Print(t.clone())
        }),
        |e| eprintln!("dial_udp: {e}"),
    );
    client.dial(
        SocketAddr::from((server_ip, 7001)),
        fn_acceptor(move |c: &Conn<Print>| {
            let _ = c.send(b"hello over TCP");
            Print(tx.clone())
        }),
        |e| eprintln!("dial: {e}"),
    );
    // ANCHOR_END: client
    for _ in 0..2 {
        let msg = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(std::io::Error::other)?;
        println!("echoed: {msg}");
    }
    client.shutdown();
    client.wait();
    server.shutdown();
    server.wait();
    Ok(())
}
