//! HTTP metrics, the Prometheus endpoint and the debug endpoint.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
    time::Duration,
};

use flash::{Backend, Config, Engine, Listener, UringConfig};
use flash_http::{
    Context, Router,
    observe::{self, HttpMetrics},
    serve,
};

fn backend() -> Backend {
    match std::env::var("FLASH_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

/// One request on a fresh connection; returns (status, body).
fn get(addr: SocketAddr, path: &str, extra: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text[9..12].parse().unwrap();
    let body = text.split_once("\r\n\r\n").map_or("", |x| x.1).to_owned();
    (status, body)
}

fn sample(text: &str, series: &str) -> f64 {
    text.lines()
        .find(|l| l.starts_with(series) && l[series.len()..].starts_with(' '))
        .unwrap_or_else(|| panic!("no {series} in\n{text}"))
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn metrics_endpoint_exposes_engine_and_http_metrics() {
    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(300);
    let tel = cfg.telemetry.clone();
    let http = HttpMetrics::new();
    let app = Router::new()
        .get("/ok", |ctx: &mut Context| ctx.text(200, "ok"))
        .get("/later", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                d.respond(flash_http::Response::text(201, "made"));
            });
        })
        .get(
            "/metrics",
            observe::metrics_handler(tel.clone(), Some(http.clone())),
        )
        .get(
            "/debug/flash/*view",
            observe::debug_handler(tel, Some("s3cret".into())),
        )
        .layer(http.middleware())
        .layer(observe::access_log());
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(serve(app)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];

    for _ in 0..3 {
        assert_eq!(get(addr, "/ok", "").0, 200);
    }
    assert_eq!(get(addr, "/missing", "").0, 404);
    assert_eq!(get(addr, "/later", "").0, 201);

    let snap = http.snapshot();
    assert_eq!(snap.by_class[1], 4, "{snap:?}"); // 3x 200 + 201
    assert_eq!(snap.by_class[3], 1);
    assert_eq!(snap.count(), 5);
    assert!(snap.sum >= Duration::from_millis(30));
    assert_eq!(snap.in_flight, 0);

    let (st, body) = get(addr, "/metrics", "");
    assert_eq!(st, 200);
    assert_eq!(
        sample(&body, "flash_http_requests_total{class=\"2xx\"}"),
        4.0
    );
    assert_eq!(
        sample(&body, "flash_http_requests_total{class=\"4xx\"}"),
        1.0
    );
    assert_eq!(
        sample(
            &body,
            "flash_http_request_duration_seconds_bucket{le=\"+Inf\"}"
        ),
        5.0
    );
    assert!(
        sample(
            &body,
            "flash_http_request_duration_seconds_bucket{le=\"0.01\"}"
        ) >= 4.0
    );
    // This request is in flight while it renders.
    assert_eq!(sample(&body, "flash_http_requests_in_flight"), 1.0);
    let accepted: f64 = body
        .lines()
        .filter(|l| l.starts_with("flash_connections_accepted_total{"))
        .map(|l| l.rsplit(' ').next().unwrap().parse::<f64>().unwrap())
        .sum();
    assert_eq!(accepted, 6.0);

    // Debug endpoint: guarded by the token.
    assert_eq!(get(addr, "/debug/flash/conns", "").0, 401);
    let auth = "Authorization: Bearer s3cret\r\n";
    let (st, conns) = get(addr, "/debug/flash/conns", auth);
    assert_eq!(st, 200);
    assert!(
        conns.starts_with('[') && conns.contains("\"peer\""),
        "{conns}"
    );
    let (_, loops) = get(addr, "/debug/flash/loops", auth);
    assert!(
        loops.contains("\"iterations\"") && loops.contains("\"pool\""),
        "{loops}"
    );
    let (_, live) = get(addr, "/debug/flash/live", auth);
    assert!(live.contains("\"max_queued_bytes\":67108864"), "{live}");
    let (_, slow) = get(addr, "/debug/flash/slow", auth);
    assert_eq!(slow, "[]");
    let (_, index) = get(addr, "/debug/flash/", auth);
    assert!(index.contains("views"));

    e.shutdown();
    e.wait();
}
