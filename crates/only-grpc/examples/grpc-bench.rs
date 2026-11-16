//! Loopback throughput of unary gRPC calls: one process serves an echo method and drives it
//! from `conns` HTTP/2 connections, each keeping `depth` calls in flight, for `secs` seconds.
//!
//! `cargo run --release -p only-grpc --example grpc-bench -- [conns] [depth] [secs] [payload] [timeout_ms]`
//! (defaults 4 64 5 64 0; `timeout_ms` 0 sends no `grpc-timeout`).
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
use only_grpc::{CallOptions, Code, GrpcClient, GrpcServer, Status};
use only_http::h2client::{H2Client, H2Options};

fn arg(i: usize, default: u64) -> u64 {
    std::env::args()
        .nth(i)
        .and_then(|a| a.parse().ok())
        .unwrap_or(default)
}

struct Driver {
    client: GrpcClient,
    payload: Vec<u8>,
    timeout: Option<Duration>,
    done: AtomicU64,
    stop: Arc<AtomicBool>,
}

fn issue(d: &Arc<Driver>) {
    if d.stop.load(Ordering::Relaxed) {
        return;
    }
    let mut opts = CallOptions::default();
    opts.timeout = d.timeout;
    let d2 = d.clone();
    let sink = d.client.bidi(
        "/bench.Echo/Unary",
        opts,
        |_m| {},
        move |st, _| {
            if st.code == Code::Ok {
                d2.done.fetch_add(1, Ordering::Relaxed);
            }
            issue(&d2);
        },
    );
    sink.send(&d.payload);
    sink.close_send();
}

fn main() -> std::io::Result<()> {
    let conns = arg(1, 4) as usize;
    let depth = arg(2, 64) as usize;
    let secs = arg(3, 5);
    let payload = vec![b'x'; arg(4, 64) as usize];
    let timeout = match arg(5, 0) {
        0 => None,
        ms => Some(Duration::from_millis(ms)),
    };
    let grpc = GrpcServer::new().unary("/bench.Echo/Unary", |_md, req, sink| {
        sink.send(&req);
        sink.finish(Status::ok());
    });
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let e = Arc::new(
        Engine::builder()
            .listen(
                Listener::tcp("127.0.0.1:0".parse().expect("addr"))
                    .threads((threads / 2).max(1))
                    .serve(only_http::serve(grpc)),
            )
            .client_threads((threads / 2).max(1))
            .build()?,
    );
    e.start()?;
    let addr = e.local_addrs()[0];
    let base = format!("http://{addr}");
    let stop = Arc::new(AtomicBool::new(false));
    let drivers: Vec<_> = (0..conns)
        .map(|_| {
            let h2 = H2Client::dial_blocking(&e, addr, None, H2Options::default())?;
            Ok(Arc::new(Driver {
                client: GrpcClient::new(h2, &base),
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
        "grpc conns={conns} depth={depth} payload={} timeout={timeout:?}: {:.0} calls/s",
        payload.len(),
        (c1 - c0) as f64 / el.as_secs_f64()
    );
    std::thread::sleep(Duration::from_millis(200));
    e.shutdown();
    e.wait();
    Ok(())
}
