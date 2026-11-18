//! Per-route metrics, HTTP/2 connection and stream gauges, request and connection spans.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use only::{Backend, Config, Engine, Listener, UringConfig, metrics::Families};
use only_http::{
    Context, H2Config, HttpConfig, Router,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
    observe::{H2Stats, HttpMetrics},
    serve_with,
};
use only_log::{
    LevelFilter,
    span::{self, FieldValue, SpanContext, SpanData, SpanKind, SpanStatus, Tracer},
};

fn backend() -> Backend {
    match std::env::var("ONLY_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

struct Capture(Mutex<Vec<SpanData>>);

impl Tracer for Capture {
    fn on_end(&self, span: SpanData) {
        self.0.lock().unwrap().push(span);
    }
}

static CAP: Capture = Capture(Mutex::new(Vec::new()));
static SERIAL: Mutex<()> = Mutex::new(());

/// Tests in this file share the process-wide tracer: run them one at a time.
fn serial(spans: LevelFilter) -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _ = span::set_tracer(&CAP);
    span::set_max_span_level(spans);
    CAP.0.lock().unwrap().clear();
    g
}

fn spans_until(n: usize, f: impl Fn(&SpanData) -> bool) -> Vec<SpanData> {
    let t0 = Instant::now();
    loop {
        let v: Vec<SpanData> = CAP
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| f(s))
            .cloned()
            .collect();
        if v.len() >= n || t0.elapsed() > Duration::from_secs(10) {
            return v;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn get(addr: SocketAddr, path: &str, extra: &str) -> u16 {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
    String::from_utf8_lossy(&out)[9..12].parse().unwrap()
}

fn app() -> Router {
    Router::new()
        .get("/users/:id", |ctx: &mut Context| {
            let id = ctx.param("id").unwrap_or("?").to_owned();
            ctx.text(200, id);
        })
        .get("/fail", |ctx: &mut Context| ctx.text(503, "down"))
        .get("/a", |ctx: &mut Context| ctx.text(200, "a"))
        .get("/b", |ctx: &mut Context| ctx.text(200, "b"))
        .get("/child", |ctx: &mut Context| {
            // A span created by the handler is a child of the request span.
            let inner = only_log::info_span!(target: "app", "inner work");
            let parent = ctx.span_context();
            drop(inner);
            ctx.text(200, format!("{}", parent.is_some()));
        })
        .get("/later", |ctx: &mut Context| {
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                d.respond(only_http::Response::text(201, "later"));
            });
        })
}

fn start(cfg: HttpConfig, app: Router) -> Engine {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(serve_with(cfg, app)),
        )
        .client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

#[test]
fn per_route_metrics_use_patterns_and_bound_cardinality() {
    let _g = serial(LevelFilter::Off);
    let http = HttpMetrics::with_routes(2);
    let e = start(HttpConfig::default(), app().layer(http.middleware()));
    let addr = e.local_addrs()[0];
    for id in 0..5 {
        assert_eq!(get(addr, &format!("/users/{id}"), ""), 200);
    }
    assert_eq!(get(addr, "/fail", ""), 503);
    // Two slots: `/a` and `/b` come after them and share `other`.
    assert_eq!(get(addr, "/a", ""), 200);
    assert_eq!(get(addr, "/b", ""), 200);
    assert_eq!(get(addr, "/nope", ""), 404);
    assert_eq!(get(addr, "/nope/2", ""), 404);
    let rows = http.route_snapshot();
    let row = |m: &str, r: &str| {
        rows.iter()
            .find(|x| x.method == m && x.route == r)
            .unwrap_or_else(|| panic!("no {m} {r} in {rows:?}"))
    };
    assert_eq!(row("GET", "/users/:id").by_class[1], 5);
    assert_eq!(row("GET", "/users/:id").count(), 5);
    assert_eq!(row("GET", "/fail").by_class[4], 1);
    assert_eq!(row("*", "other").count(), 2);
    assert_eq!(row("*", "unmatched").by_class[3], 2);
    assert_eq!(rows.len(), 4, "{rows:?}");
    // The totals are unchanged by the per-route rows.
    assert_eq!(http.snapshot().count(), 10);

    let mut f = Families::new();
    only::metrics::Collector::collect(&http, &mut f);
    let text = f.to_prometheus();
    assert!(
        text.contains(
            "only_http_route_requests_total{method=\"GET\",route=\"/users/:id\",class=\"2xx\"} 5"
        ),
        "{text}"
    );
    assert!(text.contains(
        "only_http_route_request_duration_seconds_count{method=\"*\",route=\"unmatched\"} 2"
    ));
    assert!(!text.contains("/users/3"), "raw paths never become labels");
    assert_eq!(f.dropped(), 0);

    // Without `with_routes`, nothing per route.
    assert!(HttpMetrics::new().route_snapshot().is_empty());
    stop(&e);
}

#[test]
fn h2_connection_and_stream_gauges() {
    let _g = serial(LevelFilter::Off);
    let stats = H2Stats::new();
    let mut cfg = HttpConfig::default();
    cfg.h2 = Some({
        let mut h = H2Config::default();
        h.stats = Some(stats.clone());
        h
    });
    let e = start(cfg, app());
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let base = format!("http://{addr}");
    for i in 0..4 {
        let r = c
            .send(ClientRequest::get(&format!("{base}/users/{i}")))
            .wait()
            .unwrap();
        assert_eq!(r.status, 200);
    }
    // A response that is still being prepared keeps its stream open.
    let slow = c.send(ClientRequest::get(&format!("{base}/later")));
    let t0 = Instant::now();
    while stats.snapshot().streams_open != 1 && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(2));
    }
    let s = stats.snapshot();
    assert_eq!((s.connections_open, s.connections_total), (1, 1));
    assert_eq!((s.streams_open, s.streams_total), (1, 5));
    assert_eq!(slow.wait().unwrap().status, 201);
    c.close();
    let t0 = Instant::now();
    while stats.snapshot().connections_open != 0 && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    let s = stats.snapshot();
    assert_eq!((s.connections_open, s.streams_open), (0, 0), "{s:?}");
    assert_eq!(s.streams_total, 5);

    let mut f = Families::new();
    only::metrics::Collector::collect(&stats, &mut f);
    let text = f.to_prometheus();
    assert!(text.contains("only_http2_streams_total 5"), "{text}");
    assert!(text.contains("only_http2_connections_open 0"));
    assert!(text.contains("only_http2_resets_total{direction=\"sent\"}"));
    assert!(text.contains("only_http2_goaways_total{direction=\"received\"}"));
    stop(&e);
}

#[test]
fn request_spans_carry_route_status_and_remote_parent() {
    let _g = serial(LevelFilter::Info);
    let e = start(HttpConfig::default(), app());
    let addr = e.local_addrs()[0];
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    assert_eq!(
        get(addr, "/users/7", &format!("traceparent: {tp}\r\n")),
        200
    );
    assert_eq!(get(addr, "/fail", ""), 503);
    assert_eq!(get(addr, "/nope", ""), 404);
    assert_eq!(get(addr, "/child", ""), 200);
    assert_eq!(get(addr, "/later", ""), 201);
    let spans = spans_until(6, |s| s.target == "only_http::request" || s.target == "app");
    let by_name = |n: &str| {
        spans
            .iter()
            .find(|s| s.name == n)
            .unwrap_or_else(|| panic!("no span {n} in {spans:#?}"))
    };
    let user = by_name("GET /users/:id");
    assert_eq!(user.kind, SpanKind::Server);
    assert_eq!(
        user.field("http.route"),
        Some(&FieldValue::Str("/users/:id".into()))
    );
    assert_eq!(
        user.field("url.path"),
        Some(&FieldValue::Str("/users/7".into()))
    );
    assert_eq!(
        user.field("http.response.status_code"),
        Some(&FieldValue::U64(200))
    );
    assert_eq!(
        user.field("network.protocol.version"),
        Some(&FieldValue::Str("1.1".into()))
    );
    assert_eq!(
        user.field("client.address"),
        Some(&FieldValue::Str("127.0.0.1".into()))
    );
    assert_eq!(user.parent, SpanContext::from_traceparent(tp));
    assert_eq!(user.context.trace_id(), 0x4bf92f3577b34da6a3ce929d0e0e4736);

    let fail = by_name("GET /fail");
    assert!(matches!(fail.status, SpanStatus::Error(_)));
    assert_eq!(fail.parent, None);
    // Unmatched: named after the method only, no route.
    let nope = spans
        .iter()
        .find(|s| s.field("url.path") == Some(&FieldValue::Str("/nope".into())))
        .unwrap();
    assert_eq!(nope.name, "GET");
    assert!(nope.field("http.route").is_none());

    let inner = by_name("inner work");
    let child = by_name("GET /child");
    assert_eq!(inner.parent, Some(child.context));
    // A detached response ends the span when it is sent.
    let later = by_name("GET /later");
    assert_eq!(
        later.field("http.response.status_code"),
        Some(&FieldValue::U64(201))
    );
    assert!(later.duration() >= Duration::from_millis(25));
    // Connection spans are `debug`: off at `info`.
    assert!(!spans.iter().any(|s| s.target == "only_http::connection"));
    stop(&e);
}

#[test]
fn h2_request_and_connection_spans() {
    let _g = serial(LevelFilter::Debug);
    let e = start(HttpConfig::default(), app());
    let addr = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let r = c
        .send(ClientRequest::get(&format!("http://{addr}/users/9")))
        .wait()
        .unwrap();
    assert_eq!(r.status, 200);
    c.close();
    let spans = spans_until(2, |s| s.target.starts_with("only_http::"));
    let req = spans
        .iter()
        .find(|s| s.target == "only_http::request")
        .expect("request span");
    assert_eq!(req.name, "GET /users/:id");
    assert_eq!(
        req.field("network.protocol.version"),
        Some(&FieldValue::Str("2".into()))
    );
    let conn = spans
        .iter()
        .find(|s| s.target == "only_http::connection")
        .expect("connection span");
    assert_eq!(conn.name, "http.server.connection");
    assert_eq!(
        conn.field("network.protocol.version"),
        Some(&FieldValue::Str("2".into()))
    );
    assert!(conn.end >= req.end);
    stop(&e);
}

#[test]
fn spans_off_cost_nothing_observable() {
    let _g = serial(LevelFilter::Off);
    let e = start(HttpConfig::default(), app());
    let addr = e.local_addrs()[0];
    assert_eq!(get(addr, "/child", ""), 200);
    stop(&e);
    assert!(CAP.0.lock().unwrap().is_empty());
}
