//! End to end against the OpenTelemetry Collector over plain OTLP/HTTP and StatsD: run with
//! `tools/otel/e2e.sh`, which starts the collector in Docker and sets `AKIO_OTEL_COLLECTOR`
//! (OTLP/HTTP endpoint), `AKIO_OTEL_STATSD` (its statsd receiver) and `AKIO_OTEL_OUT` (where its
//! file exporters write OTLP/JSON). Without them the test returns at once. Traces carry events
//! and links, logs are correlated with the request spans, the latency histogram has exemplars.
//! `collector_tls.rs` covers gRPC and TLS.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use akio::{
    Config, Engine, Listener,
    log::{LevelFilter, info, span::FieldValue},
};
use akio_export::{Encoding, Exporter, Flavor};
use akio_http::{Context, Router, observe, serve};

fn get(addr: SocketAddr, path: &str, extra: &str) {
    // A busy host may be short of ephemeral ports for a moment.
    let t0 = Instant::now();
    let mut s = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(e) if t0.elapsed() < Duration::from_secs(10) => {
                eprintln!("connect: {e}, retrying");
                std::thread::sleep(Duration::from_millis(100));
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
}

/// Waits until the collector's output file `name` contains every needle.
fn wait_for(dir: &str, name: &str, needles: &[&str]) {
    let path = format!("{dir}/{name}");
    let t0 = Instant::now();
    loop {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let missing: Vec<&&str> = needles.iter().filter(|n| !text.contains(**n)).collect();
        if missing.is_empty() {
            return;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "{path} lacks {missing:?}; it has:\n{}",
            &text[text.len().saturating_sub(4000)..]
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn otlp_and_statsd_into_the_collector() {
    let (Ok(endpoint), Ok(statsd), Ok(out)) = (
        std::env::var("AKIO_OTEL_COLLECTOR"),
        std::env::var("AKIO_OTEL_STATSD"),
        std::env::var("AKIO_OTEL_OUT"),
    ) else {
        eprintln!("AKIO_OTEL_COLLECTOR / AKIO_OTEL_STATSD / AKIO_OTEL_OUT not set: skipped");
        return;
    };

    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(300);
    let tel = cfg.telemetry.clone();
    let http = observe::HttpMetrics::with_routes(16).with_exemplars();
    tel.register_collector(Arc::new(http.clone()), &[]);
    let app = Router::new()
        .get("/users/:id", |ctx: &mut Context| {
            // A child span of the request span, with an event and a link; a record in it.
            let mut child = akio::log::info_span!(target: "e2e", "load user");
            child.add_event("cache miss", &[("tier", FieldValue::from("l1"))]);
            let linked = akio::log::span::SpanContext::new(0xfeed, 0xbeef, true, true).unwrap();
            child.add_link(linked, &[("why", FieldValue::from("batch"))]);
            let id = ctx.param("id").unwrap_or("?").to_owned();
            child.in_scope(|| info!(target: "e2e", user = id.as_str(); "loading user {id}"));
            drop(child);
            ctx.text(200, "u");
        })
        .get("/boom", |ctx: &mut Context| ctx.text(500, "x"))
        .layer(http.middleware());
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(2)
                .serve(serve(app)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];

    let ex = Exporter::builder()
        .service_name("akio-e2e")
        .telemetry(tel)
        .interval(Duration::from_millis(500))
        .span_interval(Duration::from_millis(100))
        .otlp_http(&endpoint)
        .statsd(&statsd, Flavor::DogStatsd)
        .statsd_options("e2e.", 1432, 10_000)
        .traces(LevelFilter::Info)
        .logs(LevelFilter::Info)
        .start()
        .unwrap();
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    get(addr, "/users/1", &format!("traceparent: {tp}\r\n"));
    for i in 2..6 {
        get(addr, &format!("/users/{i}"), "");
    }
    get(addr, "/boom", "");
    ex.flush();

    // A second exporter, metrics only, in OTLP/JSON.
    let json = Exporter::builder()
        .service_name("akio-json-e2e")
        .collector(Arc::new(http))
        .otlp_http_with(&endpoint, Encoding::Json, &[])
        .start()
        .unwrap();
    json.flush();

    wait_for(
        &out,
        "traces.jsonl",
        &[
            "\"traceId\":\"4bf92f3577b34da6a3ce929d0e0e4736\"",
            "\"parentSpanId\":\"00f067aa0ba902b7\"",
            "\"name\":\"GET /users/:id\"",
            "\"name\":\"load user\"",
            "\"name\":\"GET /boom\"",
            "\"key\":\"http.route\"",
            "\"stringValue\":\"akio-e2e\"",
            // The event and the link of the child span.
            "\"events\":[{\"timeUnixNano\":",
            "\"name\":\"cache miss\"",
            "\"links\":[{\"traceId\":\"0000000000000000000000000000feed\",\"spanId\":\"000000000000beef\"",
        ],
    );
    wait_for(
        &out,
        "logs.jsonl",
        &[
            "\"body\":{\"stringValue\":\"loading user 1\"}",
            "\"key\":\"code.file.path\"",
            "\"severityText\":\"INFO\"",
            // The record logged in the request with a traceparent carries its trace id.
            "\"traceId\":\"4bf92f3577b34da6a3ce929d0e0e4736\"",
            "\"stringValue\":\"akio-e2e\"",
        ],
    );
    wait_for(
        &out,
        "metrics.jsonl",
        &[
            // OTLP (protobuf) from the first exporter.
            "\"name\":\"akio_http_route_requests_total\"",
            "\"name\":\"akio_http_route_request_duration_seconds\"",
            "\"name\":\"akio_connections_accepted_total\"",
            "\"stringValue\":\"/users/:id\"",
            // Exemplars of the latency histogram point at request spans.
            "\"exemplars\":[{\"timeUnixNano\":",
            // OTLP/JSON from the second.
            "\"stringValue\":\"akio-json-e2e\"",
            // DogStatsD through the collector's statsd receiver.
            "\"name\":\"e2e.akio_http_route_requests_total\"",
            "\"name\":\"e2e.akio_connections_open\"",
        ],
    );
    let s = ex.stats();
    assert_eq!(
        (
            s.otlp_metrics_failed,
            s.otlp_traces_failed,
            s.otlp_logs_failed,
            s.statsd_failed
        ),
        (0, 0, 0, 0),
        "the collector refused a request: {s:?}"
    );
    assert!(s.otlp_metrics_ok >= 1 && s.otlp_traces_ok >= 1 && s.statsd_ok >= 1);
    assert!(s.otlp_logs_ok >= 1 && s.logs_exported >= 5, "{s:?}");
    assert_eq!(s.spans_exported, 11, "6 requests + 5 children: {s:?}");
    assert_eq!((s.spans_rejected, s.logs_rejected), (0, 0));
    assert_eq!(json.stats().otlp_metrics_ok, 1);
    assert_eq!(json.stats().otlp_metrics_failed, 0);
    json.shutdown();
    ex.shutdown();
    e.shutdown();
    e.wait();
}
