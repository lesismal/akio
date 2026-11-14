//! Userspace-stack micro benchmarks over the in-process memory wire (any platform, no
//! privileges): TCP echo throughput, sequential connection rate, many concurrent connections and
//! UDP request/response rate. Uses only the public API, so the same file measures any version of
//! the stack (docs/BENCHMARKS.md has the A/B against the former smoltcp-based stack).
//!
//! ```text
//! cargo run --release -p only-dpdk --example stack-bench [-- quick]
//! ```
#![allow(missing_docs)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use only::{
    Backend, Config, Conn, Engine, Handler, Listener,
    dpdk::{Device, DpdkConfig, MemoryWire},
    fn_acceptor,
};

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

/// Forwards what a dialed connection receives.
struct Sink(mpsc::Sender<usize>);
impl Handler for Sink {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        let _ = self.0.send(data.len());
    }
}

fn cfg() -> Config {
    let mut c = Config::default();
    c.shutdown_timeout = Duration::from_millis(200);
    c
}

fn dcfg(dev: Device, ip: Ipv4Addr, tcp_buffer: usize) -> DpdkConfig {
    let mut d = DpdkConfig::new(dev, ip);
    d.tcp_buffer = tcp_buffer;
    d.tcp_backlog = 1024;
    d
}

/// A server engine (UDP and TCP echo) on end A, a client engine with a listener of each kind on
/// end B (dials run there).
fn pair(tcp_buffer: usize) -> (Engine, Engine) {
    let (a, b) = MemoryWire::new();
    let server = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(SocketAddr::from((A, 7000)))
                .backend(Backend::Dpdk(dcfg(
                    Device::Memory(a.clone()),
                    A,
                    tcp_buffer,
                )))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(SocketAddr::from((A, 7001)))
                .backend(Backend::Dpdk(dcfg(Device::Memory(a), A, tcp_buffer)))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .expect("server");
    let client = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp(SocketAddr::from((B, 0)))
                .backend(Backend::Dpdk(dcfg(
                    Device::Memory(b.clone()),
                    B,
                    tcp_buffer,
                )))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .listen(
            Listener::tcp(SocketAddr::from((B, 0)))
                .backend(Backend::Dpdk(dcfg(Device::Memory(b), B, tcp_buffer)))
                .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
        )
        .build()
        .expect("client");
    server.start().unwrap();
    client.start().unwrap();
    (server, client)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn dial(client: &Engine, tx: mpsc::Sender<usize>) -> Conn<Sink> {
    let (otx, orx) = mpsc::channel();
    client.dial(
        SocketAddr::from((A, 7001)),
        fn_acceptor(move |c: &Conn<Sink>| {
            let _ = otx.send(c.clone());
            Sink(tx.clone())
        }),
        |e| panic!("dial: {e}"),
    );
    orx.recv_timeout(Duration::from_secs(10))
        .expect("connected")
}

/// One connection echoes `total` bytes; returns MB/s of payload each way.
fn tcp_throughput(tcp_buffer: usize, total: usize) -> f64 {
    let (server, client) = pair(tcp_buffer);
    let (tx, rx) = mpsc::channel();
    let c = dial(&client, tx);
    let chunk = vec![0x5au8; 16 << 10];
    let t0 = Instant::now();
    let (mut sent, mut got) = (0usize, 0usize);
    while got < total {
        while sent < total && c.queued_bytes() < 256 << 10 {
            let n = chunk.len().min(total - sent);
            c.send(&chunk[..n]).unwrap();
            sent += n;
        }
        if let Ok(n) = rx.recv_timeout(Duration::from_millis(50)) {
            got += n;
        }
        assert!(t0.elapsed() < Duration::from_secs(120), "stalled at {got}");
    }
    let mbps = total as f64 / t0.elapsed().as_secs_f64() / 1e6;
    stop(&client);
    stop(&server);
    mbps
}

/// Sequential connections: dial, one request/response, close. Returns connections per second
/// and the median time to the first response.
fn connection_rate(n: usize) -> (f64, Duration) {
    let (server, client) = pair(64 << 10);
    let mut lat = Vec::with_capacity(n);
    let t0 = Instant::now();
    for _ in 0..n {
        let s = Instant::now();
        let (tx, rx) = mpsc::channel();
        let c = dial(&client, tx);
        c.send(b"ping").unwrap();
        let mut got = 0;
        while got < 4 {
            got += rx.recv_timeout(Duration::from_secs(10)).expect("echo");
        }
        lat.push(s.elapsed());
        c.close();
    }
    let rate = n as f64 / t0.elapsed().as_secs_f64();
    lat.sort();
    stop(&client);
    stop(&server);
    (rate, lat[lat.len() / 2])
}

/// `n` connections open at once, `rounds` request/response rounds on each (all in flight
/// together). Returns (setup time, request/responses per second).
fn concurrent(n: usize, rounds: usize) -> (Duration, f64) {
    let (server, client) = pair(16 << 10);
    let (tx, rx) = mpsc::channel();
    let conns: Arc<Mutex<Vec<Conn<Sink>>>> = Arc::default();
    let t0 = Instant::now();
    for _ in 0..n {
        let tx = tx.clone();
        let conns = conns.clone();
        client.dial(
            SocketAddr::from((A, 7001)),
            fn_acceptor(move |c: &Conn<Sink>| {
                conns.lock().unwrap().push(c.clone());
                Sink(tx.clone())
            }),
            |e| panic!("dial: {e}"),
        );
    }
    while conns.lock().unwrap().len() < n {
        assert!(t0.elapsed() < Duration::from_secs(60), "setup stalled");
        std::thread::sleep(Duration::from_micros(200));
    }
    let setup = t0.elapsed();
    let conns = conns.lock().unwrap().clone();
    let msg = [7u8; 64];
    let t1 = Instant::now();
    for _ in 0..rounds {
        for c in &conns {
            c.send(&msg).unwrap();
        }
        let mut got = 0;
        while got < n * msg.len() {
            got += rx.recv_timeout(Duration::from_secs(30)).expect("echo");
        }
    }
    let rps = (n * rounds) as f64 / t1.elapsed().as_secs_f64();
    for c in &conns {
        c.close();
    }
    stop(&client);
    stop(&server);
    (setup, rps)
}

/// UDP request/response round trips per second (one in flight).
fn udp_rate(n: usize) -> f64 {
    let (server, client) = pair(64 << 10);
    let (tx, rx) = mpsc::channel();
    let slot: Arc<Mutex<Option<Conn<Sink>>>> = Arc::default();
    let s2 = slot.clone();
    client.dial_udp(
        SocketAddr::from((A, 7000)),
        fn_acceptor(move |c: &Conn<Sink>| {
            *s2.lock().unwrap() = Some(c.clone());
            Sink(tx.clone())
        }),
        |e| panic!("dial_udp: {e}"),
    );
    let c = loop {
        let opened = slot.lock().unwrap().clone();
        if let Some(c) = opened {
            break c;
        }
        std::thread::sleep(Duration::from_micros(100));
    };
    let msg = [1u8; 100];
    // Warm up (ARP).
    c.send(&msg).unwrap();
    rx.recv_timeout(Duration::from_secs(5)).expect("udp echo");
    let t0 = Instant::now();
    for _ in 0..n {
        c.send(&msg).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).expect("udp echo");
    }
    let rate = n as f64 / t0.elapsed().as_secs_f64();
    stop(&client);
    stop(&server);
    rate
}

fn main() {
    let quick = std::env::args().any(|a| a == "quick");
    let scale = if quick { 1 } else { 4 };
    println!("userspace stack over the memory wire (release build recommended)");
    for (buf, label) in [(64 << 10, "64 KiB"), (1 << 20, "1 MiB")] {
        let mbps = tcp_throughput(buf, scale * (64 << 20));
        println!("tcp echo throughput, {label} buffers: {mbps:.0} MB/s each way");
    }
    let (rate, p50) = connection_rate(scale * 500);
    println!(
        "sequential connections (dial + 1 req/resp + close): {rate:.0}/s, median first response {p50:?}"
    );
    for n in [100, 1000] {
        let (setup, rps) = concurrent(n, 20 * scale);
        println!(
            "{n} concurrent connections: established in {setup:?}, {rps:.0} req/resp per second"
        );
    }
    let rate = udp_rate(scale * 10_000);
    println!("udp request/response: {rate:.0}/s");
}
