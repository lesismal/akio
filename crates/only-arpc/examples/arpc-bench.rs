//! Loopback throughput of arpc calls: one process serves `/echo` and drives it from `conns`
//! client connections, each keeping `depth` calls in flight, for `secs` seconds.
//!
//! `cargo run --release -p only-arpc --example arpc-bench -- [conns] [depth] [secs] [payload] [timeout_ms]`
//! (defaults 8 64 5 64 0; `timeout_ms` 0 calls with `timeout: None`).
//!
//! Uses only the API that predates the hardening, so the same file measures both sides of an
//! A/B.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only::{Engine, Listener};
use only_arpc::{Peer, Routes, Server, dial_blocking};

fn arg(i: usize, default: u64) -> u64 {
    std::env::args()
        .nth(i)
        .and_then(|a| a.parse().ok())
        .unwrap_or(default)
}

struct Driver {
    peer: Peer,
    payload: Vec<u8>,
    timeout: Option<Duration>,
    done: AtomicU64,
    stop: Arc<AtomicBool>,
}

fn issue(d: &Arc<Driver>) {
    if d.stop.load(Ordering::Relaxed) {
        return;
    }
    let d2 = d.clone();
    d.peer.call_async("/echo", &d.payload, d.timeout, move |r| {
        if r.is_ok() {
            d2.done.fetch_add(1, Ordering::Relaxed);
        }
        issue(&d2);
    });
}

fn main() -> std::io::Result<()> {
    let conns = arg(1, 8) as usize;
    let depth = arg(2, 64) as usize;
    let secs = arg(3, 5);
    let payload = vec![b'x'; arg(4, 64) as usize];
    let timeout = match arg(5, 0) {
        0 => None,
        ms => Some(Duration::from_millis(ms)),
    };
    let routes = Routes::new().handle("/echo", |ctx| {
        let b = ctx.body().to_vec();
        ctx.write(&b);
    });
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let e = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().expect("addr"))
                    .threads((threads / 2).max(1))
                    .serve(Server::new(Arc::new(routes))),
            )
            .client_threads((threads / 2).max(1))
            .build()?,
    );
    e.start()?;
    let addr = e.local_addrs()[0];
    let stop = Arc::new(AtomicBool::new(false));
    let drivers: Vec<_> = (0..conns)
        .map(|_| {
            Ok(Arc::new(Driver {
                peer: dial_blocking(&e, addr, Arc::new(Routes::new()))?,
                payload: payload.clone(),
                timeout,
                done: AtomicU64::new(0),
                stop: stop.clone(),
            }))
        })
        .collect::<std::io::Result<_>>()?;
    for d in &drivers {
        for _ in 0..depth {
            issue(d);
        }
    }
    std::thread::sleep(Duration::from_secs(1)); // warm-up
    let count = || {
        drivers
            .iter()
            .map(|d| d.done.load(Ordering::Relaxed))
            .sum::<u64>()
    };
    let (c0, t0) = (count(), Instant::now());
    std::thread::sleep(Duration::from_secs(secs));
    let (c1, el) = (count(), t0.elapsed());
    stop.store(true, Ordering::Relaxed);
    println!(
        "arpc conns={conns} depth={depth} payload={} timeout={timeout:?}: {:.0} calls/s",
        payload.len(),
        (c1 - c0) as f64 / el.as_secs_f64()
    );
    std::thread::sleep(Duration::from_millis(200));
    for d in &drivers {
        d.peer.close();
    }
    e.shutdown();
    e.wait();
    Ok(())
}
