//! The eBPF benchmark's workloads (docs/BENCHMARKS.md, `tools/bench/ebpf.sh`). Linux; the
//! sockmap and XDP modes need root.
//!
//! * `socks <userspace|sockmap> <seconds> <conns> [epoll|uring]`: a SOCKS5 proxy (2 I/O
//!   threads) in front of a sink; `conns` clients upload through it as fast as they can. Prints
//!   the throughput and the CPU time the whole machine spent (from `/proc/stat`), per GB moved.
//! * `flood <addr> <seconds> <threads>`: sends 64-byte UDP datagrams to `addr` as fast as possible.
//! * `sink <addr> <seconds>`: receives UDP datagrams on `addr` and prints the rate.
//! * `xdp <interface> <seconds> <native|generic>`: attaches an XDP rate limiter (every packet,
//!   1 per second and source) and prints the rate it drops at.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{
    Backend, Engine, EngineRef, Listener,
    ebpf::{
        Relay,
        xdp::{Count, RateLimiter, XdpLimit, XdpMode},
    },
};
use akio_socks::{Destinations, ProxyConfig, Socks, spliced_tunnels};

/// Busy and total jiffies of the whole machine (`/proc/stat`, first line).
fn cpu_jiffies() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let v: Vec<u64> = s
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    let total: u64 = v.iter().sum();
    let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
    (total - idle, total)
}

fn socks(mode: &str, secs: u64, conns: usize, backend: &str) {
    // The sink: reads and discards, counting.
    let received = Arc::new(AtomicU64::new(0));
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = sink.local_addr().unwrap();
    let r2 = received.clone();
    thread::spawn(move || {
        for s in sink.incoming().flatten() {
            let r = r2.clone();
            thread::Builder::new()
                .name("sink".into())
                .spawn(move || {
                    let mut s = s;
                    let mut b = vec![0u8; 256 << 10];
                    while let Ok(n) = s.read(&mut b) {
                        if n == 0 {
                            return;
                        }
                        r.fetch_add(n as u64, Ordering::Relaxed);
                    }
                })
                .unwrap();
        }
    });
    let mut cfg = ProxyConfig::default();
    cfg.destinations = Destinations::Any;
    cfg.idle_timeout = None;
    if mode == "sockmap" {
        cfg.sockmap = Some(Relay::new(0).expect("sockmap relay (root, Linux 6.15+)"));
    }
    let er = EngineRef::new();
    let e = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(if backend == "uring" {
                        Backend::IoUring(Default::default())
                    } else {
                        Backend::Epoll
                    })
                    .threads(2)
                    .serve(Socks::new(er.clone()).config(cfg)),
            )
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    let proxy = e.local_addrs()[0];
    let SocketAddr::V4(t) = target else {
        unreachable!()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let mut clients = Vec::new();
    for _ in 0..conns {
        let mut s = TcpStream::connect(proxy).unwrap();
        s.write_all(&[5, 1, 0]).unwrap();
        let mut b = [0u8; 10];
        s.read_exact(&mut b[..2]).unwrap();
        let mut req = vec![5, 1, 0, 1];
        req.extend(t.ip().octets());
        req.extend(t.port().to_be_bytes());
        s.write_all(&req).unwrap();
        s.read_exact(&mut b).unwrap();
        assert_eq!(b[1], 0, "SOCKS reply");
        let stop = stop.clone();
        clients.push(
            thread::Builder::new()
                .name("client".into())
                .spawn(move || {
                    let chunk = vec![7u8; 256 << 10];
                    while !stop.load(Ordering::Relaxed) {
                        if s.write_all(&chunk).is_err() {
                            return;
                        }
                    }
                })
                .unwrap(),
        );
    }
    thread::sleep(Duration::from_secs(1)); // warm-up
    let (b0, t0, r0, w0) = (
        cpu_jiffies().0,
        cpu_jiffies().1,
        received.load(Ordering::Relaxed),
        Instant::now(),
    );
    thread::sleep(Duration::from_secs(secs));
    let (b1, t1) = cpu_jiffies();
    let bytes = received.load(Ordering::Relaxed) - r0;
    let wall = w0.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    let busy_s = (b1 - b0) as f64 / 100.0; // USER_HZ
    let cpus = (t1 - t0) as f64 / 100.0 / wall;
    let gb = bytes as f64 / 1e9;
    println!(
        "socks {mode} {backend}: {:.2} Gbit/s, {:.2} CPU-s per GB ({:.1} of {:.0} CPUs busy), {} spliced",
        gb * 8.0 / wall,
        busy_s / gb,
        busy_s / wall,
        cpus,
        spliced_tunnels()
    );
    drop(clients);
    std::process::exit(0);
}

fn flood(addr: SocketAddr, secs: u64, threads: usize) {
    let sent = Arc::new(AtomicU64::new(0));
    let until = Instant::now() + Duration::from_secs(secs);
    let hs: Vec<_> = (0..threads)
        .map(|_| {
            let sent = sent.clone();
            thread::spawn(move || {
                let s = UdpSocket::bind("0.0.0.0:0").unwrap();
                s.connect(addr).unwrap();
                let b = [0u8; 64];
                let mut n = 0u64;
                while Instant::now() < until {
                    for _ in 0..256 {
                        if s.send(&b).is_ok() {
                            n += 1;
                        }
                    }
                }
                sent.fetch_add(n, Ordering::Relaxed);
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    println!(
        "flood: {:.3} Mpps sent",
        sent.load(Ordering::Relaxed) as f64 / secs as f64 / 1e6
    );
}

fn sink(addr: SocketAddr, secs: u64) {
    let s = UdpSocket::bind(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut b = [0u8; 2048];
    let start = Instant::now();
    let mut n = 0u64;
    let mut first = None;
    while start.elapsed() < Duration::from_secs(secs) {
        if s.recv(&mut b).is_ok() {
            first.get_or_insert_with(Instant::now);
            n += 1;
        }
    }
    let t = first.map_or(1.0, |f| f.elapsed().as_secs_f64());
    println!("sink: {:.3} Mpps received", n as f64 / t / 1e6);
}

fn xdp(interface: &str, secs: u64, mode: &str) {
    let mut c = XdpLimit::default();
    c.count = Count::AllPackets;
    c.rate = 1;
    c.burst = 1;
    c.mode = if mode == "native" {
        XdpMode::Native
    } else {
        XdpMode::Generic
    };
    let l = RateLimiter::attach(interface, &c).expect("XDP attach (root)");
    eprintln!("attached {l:?}");
    let s0 = l.stats().unwrap();
    let t0 = Instant::now();
    thread::sleep(Duration::from_secs(secs));
    let s1 = l.stats().unwrap();
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "xdp {mode}: {:.3} Mpps dropped, {:.3} Mpps passed",
        (s1.dropped - s0.dropped) as f64 / dt / 1e6,
        (s1.passed - s0.passed) as f64 / dt / 1e6
    );
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| a.get(i).map(String::as_str).unwrap_or_default();
    let num = |i: usize, d: u64| arg(i).parse().unwrap_or(d);
    match arg(0) {
        "socks" => socks(arg(1), num(2, 5), num(3, 8) as usize, arg(4)),
        "flood" => flood(arg(1).parse().expect("addr"), num(2, 5), num(3, 4) as usize),
        "sink" => sink(arg(1).parse().expect("addr"), num(2, 5)),
        "xdp" => xdp(arg(1), num(2, 5), arg(3)),
        _ => {
            eprintln!(
                "usage: ebpf-bench socks <userspace|sockmap> <secs> <conns> [epoll|uring] | flood <addr> <secs> <threads> | sink <addr> <secs> | xdp <if> <secs> <native|generic>"
            );
            std::process::exit(2);
        }
    }
}
