//! Receive cost of a bound UDP socket (`Engine::bind_udp`), with or without the arrival
//! interface (`UdpBinding::set_recv_interface`, ADR-093):
//!
//! `cargo run --release -p akio --example udp-recv-bench [off|on] [secs=5] [senders=4] [peers=16] [size=64]`
//!
//! `senders` threads flood the socket on loopback with `size`-byte datagrams from `peers` source
//! sockets each (open loop: the receiver is saturated, the kernel drops what it cannot take).
//! The handler counts each datagram and reads `Conn::rx_interface`. It prints the datagrams the
//! I/O thread received per second and its CPU time per datagram (from `/proc`, Linux only; on
//! loopback the kernel's receive work runs on the senders' CPUs, so this is the copy out of
//! the socket and the engine's loop).

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio::{Conn, Engine, Handler, fn_acceptor};

/// CPU time of the calling thread in clock ticks (0 where unavailable).
fn thread_ticks() -> u64 {
    std::fs::read_to_string("/proc/thread-self/stat")
        .ok()
        .and_then(|s| {
            let rest = s.rsplit_once(')')?.1.to_string();
            let f: Vec<&str> = rest.split_whitespace().collect();
            Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
        })
        .unwrap_or(0)
}

struct Count {
    got: Arc<AtomicU64>,
    ifaces: Arc<AtomicU64>,
    cpu: Arc<Mutex<Option<u64>>>,
}

impl Handler for Count {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        if d == b"cpu" {
            *self.cpu.lock().unwrap() = Some(thread_ticks());
            return;
        }
        self.got.fetch_add(1, Ordering::Relaxed);
        if c.rx_interface() != 0 {
            self.ifaces.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn main() -> std::io::Result<()> {
    let mut a = std::env::args().skip(1);
    let on = a.next().is_some_and(|s| s == "on");
    let secs: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(5);
    let senders: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(4);
    let peers: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(16);
    let size: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(64);
    let engine = Engine::builder().udp_client_threads(1).build()?;
    engine.start()?;
    let (got, ifaces) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let cpu = Arc::new(Mutex::new(None));
    let (g, i, c) = (got.clone(), ifaces.clone(), cpu.clone());
    let b = engine.bind_udp(
        "127.0.0.1:0".parse().unwrap(),
        fn_acceptor(move |_c: &Conn<Count>| Count {
            got: g.clone(),
            ifaces: i.clone(),
            cpu: c.clone(),
        }),
    )?;
    if on {
        b.set_recv_interface(true)?;
    }
    let addr: SocketAddr = b.local_addr();
    let probe = UdpSocket::bind("127.0.0.1:0")?;
    let ticks = || {
        *cpu.lock().unwrap() = None;
        loop {
            probe.send_to(b"cpu", addr).unwrap();
            for _ in 0..100 {
                let taken = *cpu.lock().unwrap();
                if let Some(t) = taken {
                    return t;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let threads: Vec<_> = (0..senders)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let socks: Vec<UdpSocket> = (0..peers)
                    .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
                    .collect();
                let d = vec![0x5au8; size];
                while !stop.load(Ordering::Relaxed) {
                    for s in &socks {
                        let _ = s.send_to(&d, addr);
                    }
                }
            })
        })
        .collect();
    // Warm up (peers opened), then measure.
    std::thread::sleep(Duration::from_millis(500));
    let (n0, t0, start) = (got.load(Ordering::Relaxed), ticks(), Instant::now());
    std::thread::sleep(Duration::from_secs(secs));
    let t1 = ticks();
    let (n1, wall) = (got.load(Ordering::Relaxed), start.elapsed());
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    let n = (n1 - n0).max(1);
    // A clock tick is 10 ms.
    let ns = (t1 - t0) as f64 * 1e7 / n as f64;
    println!(
        "recv-interface {}: {:.0} datagrams/s, I/O thread CPU {ns:.1} ns/datagram, \
         {} of {} with an interface",
        if on { "on " } else { "off" },
        n as f64 / wall.as_secs_f64(),
        ifaces.load(Ordering::Relaxed),
        got.load(Ordering::Relaxed),
    );
    b.close();
    engine.shutdown();
    engine.wait();
    Ok(())
}
