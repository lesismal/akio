//! The exporter against in-process receivers: an OTLP/HTTP endpoint that decodes the protobuf
//! bodies, and a UDP socket standing in for StatsD. Runs everywhere (no collector needed); the
//! Docker test (`collector.rs`) does the same against the reference implementation.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Engine, Listener, log::LevelFilter};
use akio_export::{Encoding, Exporter, Flavor};
use akio_http::{Context, H2Config, HttpConfig, Router, observe, serve_with};
use akio_protobuf::encoding::{Reader, WireType};

/// One received OTLP request.
#[derive(Clone, Debug)]
struct Post {
    path: String,
    content_type: String,
    body: Vec<u8>,
}

/// A keep-alive HTTP/1.1 server recording POSTs and answering 200.
fn otlp_receiver() -> (SocketAddr, Arc<Mutex<Vec<Post>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let g = g.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = vec![0u8; 65536];
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    let header = |name: &str| {
                        head.lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
                            })
                            .unwrap_or_default()
                    };
                    let len: usize = header("content-length").parse().unwrap();
                    while buf.len() < end + 4 + len {
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let path = head.split(' ').nth(1).unwrap_or("").to_owned();
                    g.lock().unwrap().push(Post {
                        path,
                        content_type: header("content-type"),
                        body: buf[end + 4..end + 4 + len].to_vec(),
                    });
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
    (addr, got)
}

fn statsd_receiver() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = s.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while let Ok(n) = s.recv(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            g.lock().unwrap().extend(text.lines().map(str::to_owned));
        }
    });
    (addr, got)
}

/// Every length-delimited field `num` of the message `buf`.
fn fields(buf: &[u8], num: u32) -> Vec<&[u8]> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.is_empty() {
        let (f, wt) = r.read_tag().unwrap();
        if wt == WireType::Len {
            let b = r.read_bytes().unwrap();
            if f == num {
                out.push(b);
            }
        } else {
            r.skip_field(f, wt).unwrap();
        }
    }
    out
}

/// Follows a path of message fields, collecting the leaves.
fn path<'a>(buf: &'a [u8], nums: &[u32]) -> Vec<&'a [u8]> {
    match nums.split_first() {
        None => vec![buf],
        Some((n, rest)) => fields(buf, *n)
            .into_iter()
            .flat_map(|b| path(b, rest))
            .collect(),
    }
}

fn strs(v: Vec<&[u8]>) -> Vec<String> {
    v.into_iter()
        .map(|b| String::from_utf8(b.to_vec()).unwrap())
        .collect()
}

fn get(addr: SocketAddr, path: &str, extra: &str) {
    // A busy host may be short of ephemeral ports for a moment.
    let t0 = Instant::now();
    let mut s = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(e) if t0.elapsed() < Duration::from_secs(10) => {
                eprintln!("connect: {e}, retrying");
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("connect: {e}"),
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n"
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert!(out.starts_with(b"HTTP/1.1 "), "{out:?}");
}

#[test]
fn metrics_and_spans_reach_otlp_and_statsd() {
    let (otlp_addr, posts) = otlp_receiver();
    let (statsd_addr, lines) = statsd_receiver();

    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(300);
    let tel = cfg.telemetry.clone();
    let http = observe::HttpMetrics::with_routes(16);
    let h2 = observe::H2Stats::new();
    tel.register_collector(Arc::new(http.clone()), &[]);
    tel.register_collector(Arc::new(h2.clone()), &[]);
    let app = Router::new()
        .get("/users/:id", |ctx: &mut Context| ctx.text(200, "u"))
        .get("/boom", |ctx: &mut Context| ctx.text(500, "x"))
        .layer(http.middleware());
    let mut hc = HttpConfig::default();
    hc.h2 = Some({
        let mut h = H2Config::default();
        h.stats = Some(h2);
        h
    });
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(2)
                .serve(serve_with(hc, app)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];

    let exporter = Exporter::builder()
        .service_name("inprocess-test")
        .resource_attr("deployment.environment", "test")
        .telemetry(tel.clone())
        .interval(Duration::from_secs(3600)) // only explicit flushes
        .span_interval(Duration::from_secs(3600))
        .otlp_http(&format!("http://{otlp_addr}"))
        .statsd(&statsd_addr.to_string(), Flavor::DogStatsd)
        .statsd_options("t.", 512, 1000)
        .traces(LevelFilter::Info)
        .start()
        .unwrap();
    tel.register_collector(exporter.collector(), &[]);

    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    get(addr, "/users/1", &format!("traceparent: {tp}\r\n"));
    get(addr, "/users/2", "");
    get(addr, "/boom", "");
    exporter.flush();

    let p = posts.lock().unwrap().clone();
    let traces: Vec<&Post> = p.iter().filter(|p| p.path == "/v1/traces").collect();
    let metrics: Vec<&Post> = p.iter().filter(|p| p.path == "/v1/metrics").collect();
    assert_eq!(traces.len(), 1, "{p:?}");
    assert_eq!(metrics.len(), 1);
    assert_eq!(traces[0].content_type, "application/x-protobuf");

    // ExportTraceServiceRequest: resource_spans(1) / scope_spans(2) / spans(2).
    let body = &traces[0].body;
    let spans = path(body, &[1, 2, 2]);
    assert_eq!(spans.len(), 3);
    let mut names = strs(spans.iter().flat_map(|s| fields(s, 5)).collect());
    names.sort();
    assert_eq!(names, ["GET /boom", "GET /users/:id", "GET /users/:id"]);
    let scopes = strs(path(body, &[1, 2, 1, 1]));
    assert_eq!(scopes, ["akio_http::request"]);
    // The span with the remote parent carries its trace id and parent span id.
    let trace_ids: Vec<&[u8]> = spans.iter().flat_map(|s| fields(s, 1)).collect();
    let want = 0x4bf92f3577b34da6a3ce929d0e0e4736u128.to_be_bytes();
    assert!(trace_ids.contains(&&want[..]));
    let parents: Vec<&[u8]> = spans.iter().flat_map(|s| fields(s, 4)).collect();
    assert_eq!(parents, [&0x00f067aa0ba902b7u64.to_be_bytes()[..]]);
    // Resource attributes.
    let keys = strs(path(body, &[1, 1, 1, 1]));
    assert_eq!(keys, ["service.name", "deployment.environment"]);

    // ExportMetricsServiceRequest: resource_metrics(1) / scope_metrics(2) / metrics(2) / name(1).
    let names = strs(path(&metrics[0].body, &[1, 2, 2, 1]));
    for want in [
        "akio_connections_accepted_total",
        "akio_http_requests_total",
        "akio_http_route_requests_total",
        "akio_http_route_request_duration_seconds",
        "akio_http2_connections_open",
        "akio_export_pushes_total",
    ] {
        assert!(
            names.iter().any(|n| n == want),
            "{want} missing from {names:?}"
        );
    }

    // StatsD (DogStatsD tags, the prefix, counter deltas).
    let t0 = Instant::now();
    let has = |l: &str| lines.lock().unwrap().iter().any(|x| x == l);
    let route_line = "t.akio_http_route_requests_total:2|c|#method:GET,route:/users/:id,class:2xx";
    while !has(route_line) && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(has(route_line), "{:?}", lines.lock().unwrap());
    assert!(has("t.akio_http_requests_total:1|c|#class:5xx"));
    lines.lock().unwrap().clear();
    get(addr, "/users/3", "");
    exporter.flush();
    let t0 = Instant::now();
    let delta = "t.akio_http_route_requests_total:1|c|#method:GET,route:/users/:id,class:2xx";
    while !has(delta) && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        has(delta),
        "a delta, not the total: {:?}",
        lines.lock().unwrap()
    );

    let s = exporter.stats();
    assert_eq!(s.spans_exported, 4);
    assert_eq!(
        (s.otlp_metrics_ok, s.otlp_traces_ok, s.statsd_ok),
        (2, 2, 2)
    );
    assert_eq!(
        s.otlp_metrics_failed + s.otlp_traces_failed + s.statsd_failed,
        0
    );

    // A second exporter (metrics only) in OTLP/JSON.
    let json = Exporter::builder()
        .telemetry(tel)
        .otlp_http_with(
            &format!("http://{otlp_addr}/prefix"),
            Encoding::Json,
            &[("x-tenant", "t1")],
        )
        .start()
        .unwrap();
    json.flush();
    json.shutdown();
    let p = posts.lock().unwrap().clone();
    let j = p.iter().find(|p| p.path == "/prefix/v1/metrics").unwrap();
    assert_eq!(j.content_type, "application/json");
    let text = String::from_utf8(j.body.clone()).unwrap();
    assert!(
        text.starts_with("{\"resourceMetrics\":[{\"resource\":"),
        "{text}"
    );
    assert!(text.contains("\"name\":\"akio_http_route_requests_total\""));

    exporter.shutdown();
    e.shutdown();
    e.wait();
}
