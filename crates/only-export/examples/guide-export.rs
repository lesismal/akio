//! Companion of the book's "Observability" chapter, sections "Per-route metrics and HTTP/2",
//! "Spans" and "Push export": route-labelled HTTP metrics, HTTP/2 gauges, request spans with
//! W3C trace context, and pushing everything to an OpenTelemetry collector and StatsD (ADR-020).
//!
//! `cargo run -p only-export --example guide-export` (with a collector on 127.0.0.1:4318 and a
//! StatsD agent on 127.0.0.1:8125 to see the data arrive; without them the pushes fail and are
//! counted, nothing else changes).

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use only::{Config, Engine, Listener, log::LevelFilter};
use only_export::{Exporter, Flavor};
use only_http::{
    Context, H2Config, HttpConfig, Router,
    observe::{H2Stats, HttpMetrics},
    serve_with,
};

fn main() -> std::io::Result<()> {
    // ANCHOR: routes
    let cfg = Config::default();
    let tel = cfg.telemetry.clone();

    // Per-route labels: `route="/users/:id"` (the pattern, never the raw path), at most 64
    // routes; later ones share `route="other"`, unmatched requests are `route="unmatched"`.
    let http = HttpMetrics::with_routes(64);
    tel.register_collector(Arc::new(http.clone()), &[]);

    // HTTP/2 connections and streams open now, resets and GOAWAYs.
    let h2 = H2Stats::new();
    tel.register_collector(Arc::new(h2.clone()), &[]);
    let mut http_cfg = HttpConfig::default();
    http_cfg.h2 = Some({
        let mut h = H2Config::default();
        h.stats = Some(h2);
        h
    });
    // ANCHOR_END: routes

    // ANCHOR: spans
    let app = Router::new()
        .get("/users/:id", |ctx: &mut Context| {
            // The request span (`GET /users/:id`) is current while the handler runs: this one
            // is its child.
            let mut span = only::log::info_span!(target: "app", "load user");
            span.record("user.id", ctx.param("id").unwrap_or("").to_owned());
            // Propagate the trace to a downstream call.
            let traceparent = ctx.span_context().map(|c| c.to_traceparent());
            drop(span);
            ctx.text(200, format!("traceparent {traceparent:?}\n"));
        })
        // `layer` puts the middleware inside the router, where the route is known.
        .layer(http.middleware());
    // ANCHOR_END: spans

    // ANCHOR: export
    let exporter = Exporter::builder()
        .service_name("guide")
        .resource_attr("deployment.environment", "dev")
        .telemetry(tel.clone()) // engine series + every registered collector
        .interval(Duration::from_secs(10))
        .otlp_http("http://127.0.0.1:4318") // POST /v1/metrics and /v1/traces, protobuf
        .statsd("127.0.0.1:8125", Flavor::DogStatsd)
        .traces(LevelFilter::Info) // request spans on, exported in batches
        .sample_ratio(0.25) // a quarter of new traces; callers' sampled flags are followed
        .start()?;
    // The exporter's own counters (pushes, failures, spans dropped) on /metrics too.
    tel.register_collector(exporter.collector(), &[]);
    // ANCHOR_END: export

    let engine = Engine::builder()
        .config(cfg)
        .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve_with(http_cfg, app)))
        .build()?;
    engine.start()?;
    let addr = engine.local_addrs()[0];
    for id in 1..=3 {
        let mut s = TcpStream::connect(addr)?;
        write!(
            s,
            "GET /users/{id} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )?;
        let mut out = String::new();
        s.read_to_string(&mut out)?;
        print!("{}", out.lines().last().unwrap_or(""));
        println!();
    }
    exporter.flush();
    println!("{:?}", exporter.stats());
    println!("{:?}", http.route_snapshot());
    exporter.shutdown();
    engine.shutdown();
    engine.wait();
    Ok(())
}
