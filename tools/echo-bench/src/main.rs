//! Minimal TCP echo load generator, std only, so the same tool drives flash, fib, tokio, monoio...
//!
//! usage: echo-bench <addr> [conns=64] [msg_bytes=64] [seconds=10]
//! Each connection is closed-loop: write a message, read it back, repeat.

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn main() {
    let mut a = std::env::args().skip(1);
    let addr = a.next().unwrap_or_else(|| {
        eprintln!("usage: echo-bench <addr> [conns=64] [msg_bytes=64] [seconds=10]");
        std::process::exit(2)
    });
    let conns: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(64);
    let size: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(64);
    let secs: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(10);

    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let handles: Vec<_> = (0..conns)
        .map(|_| {
            let (addr, stop, total) = (addr.clone(), stop.clone(), total.clone());
            thread::spawn(move || {
                let mut s = TcpStream::connect(&addr).expect("connect");
                s.set_nodelay(true).ok();
                let msg = vec![0xA5u8; size];
                let mut buf = vec![0u8; size];
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if s.write_all(&msg).is_err() || s.read_exact(&mut buf).is_err() {
                        break;
                    }
                    n += 1;
                }
                total.fetch_add(n, Ordering::Relaxed);
            })
        })
        .collect();

    let start = Instant::now();
    thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let el = start.elapsed().as_secs_f64();
    let n = total.load(Ordering::Relaxed) as f64;
    println!(
        "conns={conns} size={size}B  {:.0} req/s  {:.1} MiB/s (each way)",
        n / el,
        n * size as f64 / el / 1048576.0
    );
}
