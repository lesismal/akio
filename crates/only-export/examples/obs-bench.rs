//! The `http-bench` server (`GET /plaintext`, `GET /json`, HTTP/2 on the same port) with
//! observability switched on, to measure what it costs (docs/BENCHMARKS.md, "Observability
//! overhead"):
//!
//! `obs-bench <addr> <threads> <epoll|uring> <mode>[,<mode>...]`
//!
//! * `off`: nothing (the same server as `http-bench`);
//! * `metrics`: `HttpMetrics` middleware;
//! * `routes`: `HttpMetrics::with_routes(64)` middleware (per-route labels);
//! * `h2stats`: `H2Config::stats`;
//! * `spans`: request spans (`info`) through only-export's span queue, sent over OTLP/HTTP to a
//!   blackhole collector in this process every 100 ms;
//! * `spans1`: the same with 1% of the traces sampled;
//! * `push`: metrics pushed over OTLP/HTTP and StatsD every second (to the blackhole and a UDP
//!   socket nobody reads).

use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    sync::Arc,
    time::Duration,
};

use only::{Backend, Config, Engine, Listener, log::LevelFilter};
use only_export::{Exporter, Flavor};
use only_http::{
    Context, H2Config, HttpConfig, Router,
    observe::{H2Stats, HttpMetrics},
    serve_with,
};

/// Answers every HTTP/1.1 request on keep-alive connections with an empty 200.
fn blackhole() -> std::io::Result<String> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    let addr = l.local_addr()?;
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = vec![0u8; 1 << 16];
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < end + 4 + len {
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    buf.drain(..end + 4 + len);
                    if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Ok(format!("http://{addr}"))
}

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 4 {
        eprintln!(
            "usage: obs-bench <addr> <threads> <epoll|uring> <off|metrics|routes|h2stats|spans|push>[,...]"
        );
        std::process::exit(2);
    }
    let addr = a[0].parse().expect("address");
    let threads: usize = a[1].parse().expect("threads");
    let backend = match a[2].as_str() {
        "uring" => Backend::IoUring(Default::default()),
        _ => Backend::Epoll,
    };
    let modes: Vec<&str> = a[3].split(',').collect();
    let on = |m: &str| modes.contains(&m);

    let cfg = Config::default();
    let tel = cfg.telemetry.clone();
    let mut app = Router::new()
        .get("/plaintext", |ctx: &mut Context| {
            ctx.text(200, "Hello, World!");
        })
        .get("/json", |ctx: &mut Context| {
            ctx.bytes(
                200,
                "application/json",
                b"{\"message\":\"Hello, World!\"}".to_vec(),
            );
        });
    if on("metrics") || on("routes") {
        let m = if on("routes") {
            HttpMetrics::with_routes(64)
        } else {
            HttpMetrics::new()
        };
        tel.register_collector(Arc::new(m.clone()), &[]);
        app = app.layer(m.middleware());
    }
    let mut hc = HttpConfig::default();
    if on("h2stats") {
        let s = H2Stats::new();
        tel.register_collector(Arc::new(s.clone()), &[]);
        hc.h2 = Some({
            let mut h = H2Config::default();
            h.stats = Some(s);
            h
        });
    }
    let _exporter = if on("spans") || on("spans1") || on("push") {
        let sink = blackhole()?;
        let mut b = Exporter::builder()
            .service_name("obs-bench")
            .telemetry(tel)
            .interval(Duration::from_secs(1))
            .span_interval(Duration::from_millis(100))
            .span_queue(1 << 16, 2048)
            .otlp_http(&sink);
        if on("push") {
            let u = UdpSocket::bind("127.0.0.1:0")?;
            b = b.statsd(&u.local_addr()?.to_string(), Flavor::DogStatsd);
            std::mem::forget(u);
        } else {
            b = b.otlp_traces_only();
        }
        if on("spans") || on("spans1") {
            b = b.traces(LevelFilter::Info);
        }
        if on("spans1") {
            b = b.sample_ratio(0.01);
        }
        Some(b.start()?)
    } else {
        None
    };
    let l = Listener::tcp(addr)
        .backend(backend)
        .threads(threads)
        .serve(serve_with(hc, app));
    let engine = Engine::builder().config(cfg).listen(l).build()?;
    println!("listening on {:?} ({})", engine.local_addrs(), a[3]);
    engine.run()
}
