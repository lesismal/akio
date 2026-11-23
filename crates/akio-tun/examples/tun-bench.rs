//! Packets per second through a TUN device: UDP sockets send to an address routed to the device,
//! the handler sends every packet back (addresses and ports swapped), the sockets count the
//! echoes. Each packet crosses the device twice (a read and a write on the I/O thread).
//!
//!   cargo run --release -p akio-tun --example tun-bench -- [queues] [flows] [seconds] [size]
//!
//! Linux, as root (or with `CAP_NET_ADMIN`). Defaults: 1 queue, 4 flows, 5 s, 64-byte payloads.
#![allow(missing_docs)]

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::{
        net::UdpSocket,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    use akio::tun::{TunConfig, TunDevice, TunServer};
    use akio::{Config, Conn, Handler, fn_acceptor};

    struct Echo;
    impl Handler for Echo {
        fn on_data(&mut self, c: &Conn<Self>, pkt: &[u8]) {
            // IPv4 UDP only: swap the addresses and the ports (checksums stay valid).
            if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
                return;
            }
            let h = usize::from(pkt[0] & 0x0f) * 4;
            let mut p = pkt.to_vec();
            for i in 0..4 {
                p.swap(12 + i, 16 + i);
            }
            for i in 0..2 {
                p.swap(h + i, h + 2 + i);
            }
            let _ = c.send_owned(p);
        }
    }

    let arg = |i: usize, d: u64| -> u64 {
        std::env::args()
            .nth(i)
            .and_then(|a| a.parse().ok())
            .unwrap_or(d)
    };
    let (queues, flows, secs, size) = (arg(1, 1), arg(2, 4), arg(3, 5), arg(4, 64));
    let dev = TunDevice::create(
        &TunConfig::new()
            .name("aktbench0")
            .address("10.250.0.1".parse().unwrap(), 24)
            .queues(queues as usize),
    )?;
    let server = TunServer::start(dev, fn_acceptor(|_c: &Conn<Echo>| Echo), Config::default())?;
    let stop = Arc::new(AtomicBool::new(false));
    let echoed = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));
    let mut threads = Vec::new();
    for f in 0..flows {
        let (stop, echoed, sent) = (stop.clone(), echoed.clone(), sent.clone());
        threads.push(std::thread::spawn(move || {
            let s = UdpSocket::bind("10.250.0.1:0").unwrap();
            s.set_nonblocking(true).unwrap();
            let payload = vec![f as u8; size as usize];
            let mut buf = vec![0u8; 2048];
            // Keep up to 64 packets in flight per flow.
            let mut inflight = 0u32;
            while !stop.load(Ordering::Relaxed) {
                while inflight < 64 && s.send_to(&payload, ("10.250.0.2", 9000)).is_ok() {
                    inflight += 1;
                    sent.fetch_add(1, Ordering::Relaxed);
                }
                let mut got = 0;
                while s.recv_from(&mut buf).is_ok() {
                    got += 1;
                }
                if got == 0 {
                    std::thread::sleep(Duration::from_micros(50));
                    // Losses (a full backlog) must not stall the window forever.
                    inflight = inflight.saturating_sub(1);
                } else {
                    inflight = inflight.saturating_sub(got);
                    echoed.fetch_add(u64::from(got), Ordering::Relaxed);
                }
            }
        }));
    }
    std::thread::sleep(Duration::from_secs(1)); // warm-up
    let (e0, s0, t0) = (
        echoed.load(Ordering::Relaxed),
        sent.load(Ordering::Relaxed),
        Instant::now(),
    );
    std::thread::sleep(Duration::from_secs(secs));
    let el = t0.elapsed().as_secs_f64();
    let (e1, s1) = (echoed.load(Ordering::Relaxed), sent.load(Ordering::Relaxed));
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    let pps = (e1 - e0) as f64 / el;
    println!(
        "queues={queues} flows={flows} payload={size}B: {pps:.0} echoes/s ({:.0} device packets/s, \
         {:.1} MB/s of payload each way), {:.1}% of sent echoed",
        pps * 2.0,
        pps * size as f64 / 1e6,
        100.0 * (e1 - e0) as f64 / (s1 - s0).max(1) as f64
    );
    drop(server);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tun-bench runs on Linux (as root)");
}
